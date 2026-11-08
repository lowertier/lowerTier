use super::*;
use crate::tunnel::common::ensure_local_allowed_on_interface;
use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};

pub(super) const MIGRATION_COOLDOWN: Duration = Duration::from_secs(2);
const MIGRATIONS_PER_SECOND: u64 = 32;
const MIGRATION_BURST: u64 = 64;
const TOKEN_NS: u64 = 1_000_000_000 / MIGRATIONS_PER_SECOND;

struct MigrationBudget {
    credit_ns: u64,
    updated: Instant,
}

impl MigrationBudget {
    fn new(now: Instant) -> Self {
        Self {
            credit_ns: MIGRATION_BURST * TOKEN_NS,
            updated: now,
        }
    }

    fn admit(&mut self, now: Instant, count: u64) -> bool {
        let elapsed = now
            .saturating_duration_since(self.updated)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        self.credit_ns = self
            .credit_ns
            .saturating_add(elapsed)
            .min(MIGRATION_BURST * TOKEN_NS);
        self.updated = now;
        let charge = count.saturating_mul(TOKEN_NS);
        if self.credit_ns < charge {
            return false;
        }
        self.credit_ns -= charge;
        true
    }
}

fn migration_budget() -> &'static ParkingMutex<MigrationBudget> {
    static BUDGET: OnceLock<ParkingMutex<MigrationBudget>> = OnceLock::new();
    BUDGET.get_or_init(|| ParkingMutex::new(MigrationBudget::new(Instant::now())))
}

#[derive(Default)]
struct ValidationState {
    pending: bool,
    next_allowed: Option<Instant>,
    local: Option<SocketAddr>,
    source: Option<IpAddr>,
    bound_interface: Option<u32>,
    pending_interface: Option<u32>,
}

pub(super) struct QuicMigrationPolicy {
    global_ctx: Weak<crate::common::global_ctx::GlobalCtx>,
    pub(super) path_state: Arc<super::super::TunnelPathState>,
    validation: ParkingMutex<ValidationState>,
}

impl QuicMigrationPolicy {
    pub(super) fn new(
        global_ctx: &ArcGlobalCtx,
        path_state: Arc<super::super::TunnelPathState>,
    ) -> Self {
        Self {
            global_ctx: Arc::downgrade(global_ctx),
            path_state,
            validation: ParkingMutex::new(ValidationState::default()),
        }
    }

    fn admit(&self) -> bool {
        let now = Instant::now();
        let mut state = self.validation.lock();
        if state.pending
            || state.next_allowed.is_some_and(|deadline| now < deadline)
            || !migration_budget().lock().admit(now, 1)
        {
            return false;
        }
        state.pending = true;
        state.local = None;
        state.next_allowed = Some(now + MIGRATION_COOLDOWN);
        true
    }

    fn cancel(&self) {
        let mut state = self.validation.lock();
        state.pending = false;
        state.local = None;
        state.pending_interface = None;
    }

    pub(super) fn record_source_selection(&self, source: IpAddr) {
        self.validation.lock().source = Some(source);
    }

    pub(super) fn record_local_interface(&self, local: SocketAddr) {
        let interface = source_interface(local.ip());
        self.validation.lock().bound_interface = interface;
    }
}

impl quinn::PathPolicy for QuicMigrationPolicy {
    fn allow(&self, _current: SocketAddr, candidate: SocketAddr) -> bool {
        self.path_state.peer_authenticated.load(Ordering::Acquire)
            && self.global_ctx.upgrade().is_some_and(|ctx| {
                let policy = ctx.get_underlay_policy();
                let remote = SocketAddr::new(candidate.ip().to_canonical(), candidate.port());
                let local = self.validation.lock().local;
                ensure_remote_allowed(&policy, remote).is_ok()
                    && local.is_none_or(|local| {
                        // Quinn calls this from its connection task after the rebind request.
                        let _namespace = ctx.net_ns.guard();
                        ensure_local_allowed(&policy, local).is_ok()
                    })
            })
    }

    fn begin_validation(&self, current: SocketAddr, candidate: SocketAddr) -> bool {
        self.allow(current, candidate) && self.admit()
    }

    fn begin_local_validation(&self, remote: SocketAddr) -> bool {
        self.allow(remote, remote) && self.validation.lock().local.is_some()
    }

    fn validated(&self, remote: SocketAddr) {
        let local = {
            let mut state = self.validation.lock();
            state.pending = false;
            let local = state.local.take();
            if let Some(local) = local {
                state.source = Some(local.ip());
                state.bound_interface = state.pending_interface.take();
            }
            local
        };
        let mut info = self.path_state.info.write();
        if let Some(local) = local {
            info.local_addr =
                Some(super::super::build_url_from_socket_addr(&local.to_string(), "quic").into());
        } else {
            let url = super::super::build_url_from_socket_addr(&remote.to_string(), "quic");
            info.remote_addr = Some(url.clone().into());
            info.resolved_remote_addr = Some(url.into());
        }
    }

    fn validation_failed(&self, _remote: SocketAddr) {
        self.cancel();
    }
}

fn source_interface(address: IpAddr) -> Option<u32> {
    if address.is_unspecified() {
        return None;
    }
    find_source_interface(&NetworkInterface::show().ok()?, address).map(|interface| interface.index)
}

fn find_source_interface(
    interfaces: &[NetworkInterface],
    address: IpAddr,
) -> Option<&NetworkInterface> {
    let address = address.to_canonical();
    if address.is_unspecified() {
        return None;
    }
    interfaces
        .iter()
        .find(|interface| interface.addr.iter().any(|entry| entry.ip() == address))
}

fn local_allowed(
    policy: &UnderlayPolicy,
    local: SocketAddr,
    interfaces: &[NetworkInterface],
) -> Result<(), TunnelError> {
    let interface = find_source_interface(interfaces, local.ip());
    ensure_local_allowed_on_interface(
        policy,
        local,
        interface.map(|interface| interface.name.as_str()),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn selected_source(
    ctx: &ArcGlobalCtx,
    remote: SocketAddr,
) -> Result<IpAddr, TunnelError> {
    let _namespace = ctx.net_ns.guard();
    let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
    let source = probe_source(remote, ctx.flags_arc().socket_mark)?;
    ensure_local_allowed(&ctx.get_underlay_policy(), SocketAddr::new(source, 0))?;
    Ok(source)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn probe_source(remote: SocketAddr, socket_mark: Option<u32>) -> Result<IpAddr, TunnelError> {
    let bind_addr: SocketAddr = if remote.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = bind::<std::net::UdpSocket>()
        .addr(bind_addr)
        .maybe_socket_mark(socket_mark)
        .call()?;
    // This socket only reads route selection and never receives QUIC packets.
    socket.connect(remote)?;
    Ok(socket.local_addr()?.ip().to_canonical())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn admit_client_group(
    paths: &[Arc<ConnWrapper>],
    sources: &[IpAddr],
    port: u16,
    interface: Option<u32>,
) -> bool {
    let now = Instant::now();
    let mut states = paths
        .iter()
        .map(|path| path.migration_policy.validation.lock())
        .collect::<Vec<_>>();
    if states
        .iter()
        .any(|state| state.pending || state.next_allowed.is_some_and(|deadline| now < deadline))
        || !migration_budget().lock().admit(now, paths.len() as u64)
    {
        return false;
    }
    for (state, source) in states.iter_mut().zip(sources) {
        state.pending = true;
        state.local = Some(SocketAddr::new(*source, port));
        state.pending_interface = interface;
        state.next_allowed = Some(now + MIGRATION_COOLDOWN);
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) async fn migrate_client_paths(
    manager: &QuicEndpointManager,
    ctx: &ArcGlobalCtx,
) -> bool {
    let paths = {
        let mut paths = manager.client_paths.lock();
        paths.retain(|path| path.strong_count() != 0);
        paths.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
    };
    let mut complete = true;
    let mut groups: Vec<(SocketAddr, Endpoint, Vec<Arc<ConnWrapper>>)> = Vec::new();
    for path in paths {
        if !path
            .migration_policy
            .path_state
            .peer_authenticated
            .load(Ordering::Acquire)
            || path.conn.close_reason().is_some()
        {
            continue;
        }
        let Some(endpoint) = path._endpoint_owner.clone() else {
            continue;
        };
        let Ok(local) = endpoint.local_addr() else {
            complete = false;
            continue;
        };
        if let Some((_, _, paths)) = groups.iter_mut().find(|(other, _, _)| *other == local) {
            paths.push(path);
        } else {
            groups.push((local, endpoint, vec![path]));
        }
    }
    if groups.is_empty() {
        return complete;
    }
    let mut interface_snapshot = None;
    let policy = ctx.get_underlay_policy();
    let socket_mark = ctx.flags_arc().socket_mark;
    for (previous_local, endpoint, paths) in groups {
        // Listener sockets retain their discovery address. Pending handshakes keep their original socket.
        if endpoint.has_server_config() {
            continue;
        }
        if endpoint.open_connections() != paths.len() {
            complete = false;
            continue;
        }
        let now = Instant::now();
        if paths.iter().any(|path| {
            let state = path.migration_policy.validation.lock();
            state.pending || state.next_allowed.is_some_and(|deadline| now < deadline)
        }) {
            complete = false;
            continue;
        }
        let interfaces = if policy.has_interface_rules() || !previous_local.ip().is_unspecified() {
            interface_snapshot
                .get_or_insert_with(|| {
                    let _namespace = ctx.net_ns.guard();
                    NetworkInterface::show().unwrap_or_default()
                })
                .as_slice()
        } else {
            &[]
        };
        let mut sources = Vec::with_capacity(paths.len());
        for path in &paths {
            let address = path.conn.remote_address();
            let remote = SocketAddr::new(address.ip().to_canonical(), address.port());
            let source = if ensure_remote_allowed(&policy, remote).is_ok() {
                let selected = {
                    let _namespace = ctx.net_ns.guard();
                    probe_source(remote, socket_mark).and_then(|source| {
                        local_allowed(&policy, SocketAddr::new(source, 0), interfaces)?;
                        Ok(source)
                    })
                };
                match selected {
                    Ok(source) => Some(source),
                    Err(_) => {
                        let interfaces = ctx
                            .get_ip_collector()
                            .collect_current_interface_addrs()
                            .await;
                        if remote.is_ipv4() {
                            interfaces
                                .interface_ipv4s
                                .first()
                                .map(|source| IpAddr::V4((*source).into()))
                        } else {
                            interfaces
                                .interface_ipv6s
                                .first()
                                .map(|source| IpAddr::V6((*source).into()))
                        }
                    }
                }
            } else {
                None
            };
            sources.push(source);
        }
        let Some(sources) = sources.into_iter().collect::<Option<Vec<_>>>() else {
            for path in &paths {
                path.conn.record_migration_rejection();
            }
            complete = false;
            continue;
        };
        let source = sources[0];
        let wildcard = previous_local.ip().is_unspecified() && !policy.is_active();
        if !wildcard
            && (sources.iter().any(|other| *other != source)
                || previous_local.is_ipv4() != source.is_ipv4())
        {
            for path in &paths {
                path.conn.record_migration_rejection();
            }
            complete = false;
            continue;
        }
        let mut changed = local_allowed(&policy, previous_local, interfaces).is_err();
        let interface =
            find_source_interface(interfaces, previous_local.ip()).map(|interface| interface.index);
        for (path, source) in paths.iter().zip(&sources) {
            let mut state = path.migration_policy.validation.lock();
            changed |= state
                .bound_interface
                .is_some_and(|previous| Some(previous) != interface);
            if state.bound_interface.is_none() {
                state.bound_interface = interface;
            }
            match state.source {
                Some(previous) => changed |= previous != *source,
                None => {
                    state.source = Some(*source);
                }
            }
        }
        if !changed {
            // Overlay and neighbor route updates must preserve established NAT port mappings.
            continue;
        }
        let result = (|| -> Result<(), TunnelError> {
            let _namespace = ctx.net_ns.guard();
            let bind_addr = SocketAddr::new(
                if wildcard {
                    previous_local.ip()
                } else {
                    source
                },
                0,
            );
            let socket = bind::<std::net::UdpSocket>()
                .addr(bind_addr)
                .only_v6(false)
                .maybe_socket_mark(socket_mark)
                .call()?;
            configure_quic_socket_buffers(&socket2::SockRef::from(&socket));
            let local = socket.local_addr()?;
            for source in &sources {
                ensure_local_allowed(&policy, SocketAddr::new(*source, local.port()))?;
            }
            let socket = prepare_quic_udp_socket(socket)?;
            if !admit_client_group(
                &paths,
                &sources,
                local.port(),
                source_interface(bind_addr.ip()),
            ) {
                return Err(TunnelError::InternalError(
                    "QUIC migration limit reached".into(),
                ));
            }
            if let Err(error) = endpoint.rebind(socket) {
                for path in &paths {
                    path.migration_policy.cancel();
                }
                return Err(error.into());
            }
            Ok(())
        })();
        if let Err(error) = result {
            for path in &paths {
                path.conn.record_migration_rejection();
            }
            tracing::debug!(?error, "QUIC client socket migration deferred");
            complete = false;
        }
    }
    complete
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn observe_network_changes(manager: &Arc<QuicEndpointManager>, ctx: &ArcGlobalCtx) {
    let mut events = ctx.subscribe();
    let manager = Arc::downgrade(manager);
    let weak_ctx = Arc::downgrade(ctx);
    let notifications = {
        let _namespace = ctx.net_ns.guard();
        RouteNotifications::new()
    };
    tokio::spawn(async move {
        let mut notifications = notifications
            .map_err(|error| {
                tracing::debug!(
                    ?error,
                    "QUIC route notifications unavailable; monitor source addresses"
                );
            })
            .ok();
        let mut retry = tokio::time::interval(MIGRATION_COOLDOWN);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = async {
                    match &notifications {
                        Some(notifications) => notifications.changed().await,
                        None => futures::future::pending().await,
                    }
                } => {
                    if changed.is_err() { notifications = None; }
                }
                _ = retry.tick() => {}
                event = events.recv() => {
                    match event {
                        Ok(crate::common::global_ctx::GlobalCtxEvent::ConfigPatched(_))
                        | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
            let (Some(manager), Some(ctx)) = (manager.upgrade(), weak_ctx.upgrade()) else {
                break;
            };
            migrate_client_paths(&manager, &ctx).await;
        }
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn observe_network_changes(_manager: &Arc<QuicEndpointManager>, _ctx: &ArcGlobalCtx) {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RouteNotifications(tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RouteNotifications {
    fn new() -> std::io::Result<Self> {
        use nix::libc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        #[cfg(target_os = "linux")]
        let (family, protocol) = (libc::AF_NETLINK, libc::NETLINK_ROUTE);
        #[cfg(target_os = "macos")]
        let (family, protocol) = (libc::PF_ROUTE, 0);
        let raw = unsafe { libc::socket(family, libc::SOCK_RAW, protocol) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        {
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            address.nl_groups = 1 | 0x10 | 0x40 | 0x100 | 0x400;
            if unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self(tokio::io::unix::AsyncFd::new(fd)?))
    }

    async fn changed(&self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        loop {
            let mut ready = self.0.readable().await?;
            match ready.try_io(|fd| {
                let mut bytes = [0_u8; 8192];
                let count = unsafe {
                    nix::libc::read(
                        fd.get_ref().as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if count < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(Self::relevant(&bytes[..count as usize]))
                }
            }) {
                Ok(Ok(true)) => return Ok(()),
                Ok(Ok(false)) => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn relevant(_bytes: &[u8]) -> bool {
        true
    }

    #[cfg(target_os = "macos")]
    fn relevant(bytes: &[u8]) -> bool {
        use nix::libc;
        let Some(&kind) = bytes.get(3) else {
            return false;
        };
        match i32::from(kind) {
            libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO | libc::RTM_IFINFO2 => true,
            libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE => {
                if bytes.len() < std::mem::size_of::<libc::rt_msghdr>() {
                    return false;
                }
                // Kernel route queries and cloned neighbor routes do not change interface selection.
                let header =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::rt_msghdr>()) };
                header.rtm_flags & (libc::RTF_WASCLONED | libc::RTF_LLINFO) == 0
            }
            _ => false,
        }
    }
}

#[cfg(test)]
pub(super) fn check_budget() {
    let now = Instant::now();
    let mut budget = MigrationBudget::new(now);
    for _ in 0..MIGRATION_BURST {
        assert!(budget.admit(now, 1));
    }
    assert!(!budget.admit(now, 1));
    assert!(!budget.admit(now + Duration::from_nanos(TOKEN_NS), 2));
    assert!(budget.admit(now + Duration::from_nanos(TOKEN_NS), 1));
    assert!(!budget.admit(now + Duration::from_nanos(TOKEN_NS), 1));
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[test]
fn source_probes_work_without_a_runtime_and_preserve_local_policy() {
    use crate::common::{config::TomlConfigLoader, global_ctx::GlobalCtx};

    let context = Arc::new(GlobalCtx::new(TomlConfigLoader::default()));
    for remote in ["127.0.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443"] {
        let remote: SocketAddr = remote.parse().unwrap();
        assert_eq!(
            selected_source(&context, remote).unwrap(),
            remote.ip().to_canonical()
        );
    }
    let mut flags = context.get_flags();
    flags.underlay_deny_cidrs = vec!["127.0.0.0/8".to_owned()];
    context.set_flags(flags);
    assert!(matches!(
        selected_source(&context, "127.0.0.1:443".parse().unwrap()),
        Err(TunnelError::UnderlayPolicyDenied(_))
    ));
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires root and Linux network namespaces"]
fn local_migration_policy_checks_the_socket_namespace() {
    use crate::common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::GlobalCtx,
    };
    use quinn::PathPolicy;

    struct Namespace(String);
    impl Drop for Namespace {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.0])
                .status();
        }
    }
    let name = format!("lt-policy-{}", std::process::id());
    let run = |args: &[&str]| {
        assert!(
            std::process::Command::new("ip")
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    };
    run(&["netns", "add", &name]);
    let namespace = Namespace(name);
    run(&[
        "-n",
        &namespace.0,
        "link",
        "add",
        "lt-policy",
        "type",
        "dummy",
    ]);
    run(&[
        "-n",
        &namespace.0,
        "addr",
        "add",
        "192.0.2.7/32",
        "dev",
        "lt-policy",
    ]);
    run(&["-n", &namespace.0, "link", "set", "lt-policy", "up"]);
    let config = TomlConfigLoader::default();
    config.set_netns(Some(namespace.0.clone()));
    let mut flags = config.get_flags();
    flags.underlay_deny_interfaces = vec!["lo".to_owned()];
    config.set_flags(flags);
    let context = Arc::new(GlobalCtx::new(config));
    let state = Arc::new(crate::tunnel::TunnelPathState {
        peer_authenticated: std::sync::atomic::AtomicBool::new(true),
        info: RwLock::new(TunnelInfo::default()),
    });
    let policy = QuicMigrationPolicy::new(&context, state);
    let local = "192.0.2.7:12345".parse().unwrap();
    assert!(ensure_local_allowed(&context.get_underlay_policy(), local).is_err());
    policy.validation.lock().local = Some(local);
    assert!(policy.begin_local_validation("127.0.0.1:443".parse().unwrap()));
    let mut flags = context.get_flags();
    flags.underlay_deny_interfaces.push("lt-policy".to_owned());
    context.set_flags(flags);
    assert!(!policy.begin_local_validation("127.0.0.1:443".parse().unwrap()));
}
