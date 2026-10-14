// try connect peers directly, with either its public ip or lan ip

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use quanta::Instant;

use crate::{
    common::{
        PeerId, dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx,
        underlay_policy::UnderlayPolicy,
    },
    peers::{
        peer_manager::PeerManager,
        peer_rpc::PeerRpcManager,
        peer_rpc_service::DirectConnectorManagerRpcServer,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory, DirectConnectorRpcServer,
            GetIpListRequest, GetIpListResponse,
        },
        rpc_types::controller::BaseController,
    },
    tunnel::{IpVersion, matches_protocol},
    use_global_var,
};

use super::{
    BackOff, create_connector_by_url, should_background_p2p_with_peer, should_try_p2p_with_peer,
};

fn handle_rpc_result<T>(
    ret: Result<T, crate::proto::rpc_types::error::Error>,
    dst_peer_id: PeerId,
    blacklist: &timedmap::TimedMap<PeerId, ()>,
) -> Result<T, crate::proto::rpc_types::error::Error> {
    match ret {
        Ok(ret) => Ok(ret),
        Err(e) => {
            if matches!(
                e,
                crate::proto::rpc_types::error::Error::InvalidServiceKey(_, _)
            ) {
                blacklist.insert(
                    dst_peer_id,
                    (),
                    Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
            }
            Err(e)
        }
    }
}
use crate::tunnel::IpScheme;
use anyhow::Context;
use rand::Rng;
use socket2::Protocol;
use tokio::{sync::Mutex, task::JoinSet, time::timeout};
use url::Host;

pub const DIRECT_CONNECTOR_SERVICE_ID: u32 = 1;
pub const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC: u64 = 300;
const DIRECT_PROBE_GRACE_PERIOD: Duration = Duration::from_millis(1_500);

fn direct_protocol_priority(scheme: &str, configured_default: &str) -> u8 {
    if scheme == configured_default {
        return 4;
    }
    match scheme {
        "quic" => 3,
        "tcp" => 2,
        "wss" => 1,
        _ => 0,
    }
}

static TESTING: AtomicBool = AtomicBool::new(false);

async fn wait_for_probe_group<F>(
    tasks: &mut JoinSet<Result<(), Error>>,
    has_success: F,
    grace_period: Duration,
) -> Vec<Result<Result<(), Error>, tokio::task::JoinError>>
where
    F: Fn() -> bool,
{
    let mut results = Vec::new();
    let mut deadline = has_success().then(|| tokio::time::Instant::now() + grace_period);

    while !tasks.is_empty() {
        let next = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(next) => next,
                Err(_) => break,
            }
        } else {
            tasks.join_next().await
        };

        let Some(result) = next else {
            break;
        };
        results.push(result);

        if deadline.is_none() && has_success() {
            deadline = Some(tokio::time::Instant::now() + grace_period);
        }
    }

    if !tasks.is_empty() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    results
}

fn mapped_listener_port(url: &url::Url) -> Option<u16> {
    url.port()
        .or_else(|| IpScheme::try_from(url).ok().map(IpScheme::default_port))
}

async fn resolve_mapped_listener_addrs(listener: &url::Url) -> Result<Vec<SocketAddr>, Error> {
    socket_addrs(listener, || mapped_listener_port(listener)).await
}

fn direct_listener_allowed_before_resolution(policy: &UnderlayPolicy, listener: &url::Url) -> bool {
    !policy.is_active() || super::url_has_ip_literal_host(listener)
}

fn is_usable_public_ipv6_candidate(ip: &Ipv6Addr, global_ctx: &ArcGlobalCtx) -> bool {
    is_usable_public_ipv6_candidate_with_mode(ip, global_ctx, TESTING.load(Ordering::Relaxed))
}

fn is_usable_public_ipv6_candidate_with_mode(
    ip: &Ipv6Addr,
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> bool {
    !global_ctx.is_ip_lowertier_managed_ipv6(ip)
        && global_ctx.get_underlay_policy().allows_ip((*ip).into())
        && (testing
            || (!ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()))
}

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];
        let allow_public_server = use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER);
        let flags = self.get_global_ctx().get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let now = Instant::now();

        let routes = self.list_routes().await;
        for route in routes.iter() {
            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                lazy_p2p,
                flags.disable_p2p,
                flags.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                flags.disable_p2p,
                flags.need_p2p,
            ) && self.has_recent_traffic(route.peer_id, now);
            if static_allowed || dynamic_allowed {
                ret.push(route.peer_id);
            }
        }

        ret
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstListenerUrlBlackListItem(PeerId, String);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_listener_blacklist: timedmap::TimedMap<DstListenerUrlBlackListItem, ()>,
    peer_black_list: timedmap::TimedMap<PeerId, ()>,
    direct_handshake_locks: Mutex<HashMap<PeerId, Weak<Mutex<()>>>>,
}

impl DirectConnectorManagerData {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx,
            peer_manager,
            dst_listener_blacklist: timedmap::TimedMap::new(),
            peer_black_list: timedmap::TimedMap::new(),
            direct_handshake_locks: Mutex::new(HashMap::new()),
        }
    }

    async fn direct_handshake_lock(&self, dst_peer_id: PeerId) -> Arc<Mutex<()>> {
        let mut locks = self.direct_handshake_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(&dst_peer_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(dst_peer_id, Arc::downgrade(&lock));
        lock
    }

    async fn do_try_connect_to_ip(&self, dst_peer_id: PeerId, addr: String) -> Result<(), Error> {
        if self.peer_manager.has_live_peer_connection(dst_peer_id) {
            return Ok(());
        }
        let connector = create_connector_by_url(&addr, &self.global_ctx, IpVersion::Both).await?;
        let tunnel = timeout(
            std::time::Duration::from_secs(3),
            self.peer_manager.connect_tunnel(connector),
        )
        .await??;
        let handshake_lock = self.direct_handshake_lock(dst_peer_id).await;
        let _handshake_guard = handshake_lock.lock().await;
        if self.peer_manager.has_live_peer_connection(dst_peer_id) {
            return Ok(());
        }
        let (peer_id, conn_id) = timeout(
            std::time::Duration::from_secs(3),
            self.peer_manager
                .add_client_tunnel_with_peer_id_hint(tunnel, true, Some(dst_peer_id)),
        )
        .await??;

        if peer_id != dst_peer_id && !TESTING.load(Ordering::Relaxed) {
            tracing::info!(
                "connect to ip succ: {}, but peer id mismatch, expect: {}, actual: {}",
                addr,
                dst_peer_id,
                peer_id
            );
            self.peer_manager.close_peer_conn(peer_id, &conn_id).await?;
            return Err(Error::InvalidUrl(addr));
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn try_connect_to_ip(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        let mut rand_gen = rand::rngs::OsRng;
        let backoff_ms = [1000, 2000, 4000];
        let mut backoff_idx = 0;

        tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start");

        self.dst_listener_blacklist.cleanup();

        if self
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(dst_peer_id, addr.clone()))
        {
            return Err(Error::UrlInBlacklist);
        }

        loop {
            tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start one round");
            let ret = self.do_try_connect_to_ip(dst_peer_id, addr.clone()).await;
            tracing::debug!(?ret, ?dst_peer_id, ?addr, "try_connect_to_ip return");
            if ret.is_ok() {
                return Ok(());
            }

            if self.peer_manager.has_live_peer_connection(dst_peer_id) {
                return Ok(());
            }

            if backoff_idx < backoff_ms.len() {
                let delta = backoff_ms[backoff_idx] >> 1;
                assert!(delta > 0);
                assert!(delta < backoff_ms[backoff_idx]);

                tokio::time::sleep(Duration::from_millis(
                    (backoff_ms[backoff_idx] + rand_gen.gen_range(-delta..delta)) as u64,
                ))
                .await;

                backoff_idx += 1;
                continue;
            } else {
                self.dst_listener_blacklist.insert(
                    DstListenerUrlBlackListItem(dst_peer_id, addr),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
                return ret;
            }
        }
    }

    async fn spawn_direct_connect_task(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
        listener: &url::Url,
        tasks: &mut JoinSet<Result<(), Error>>,
        scheduled: &mut HashSet<String>,
    ) {
        let policy = self.global_ctx.get_underlay_policy();
        if !direct_listener_allowed_before_resolution(&policy, listener) {
            tracing::warn!(
                ?listener,
                "strict underlay policy skipped hostname listener before DNS resolution"
            );
            return;
        }
        let Ok(mut addrs) = resolve_mapped_listener_addrs(listener).await else {
            tracing::error!(?listener, "failed to parse socket address from listener");
            return;
        };
        let listener_host = addrs.pop();
        tracing::info!(?listener_host, ?listener, "try direct connect to peer");

        let is_udp = matches_protocol!(listener, Protocol::UDP);
        // Snapshot running listeners once; used for cheap port pre-checks before the
        // expensive should_deny_proxy call (which binds a socket per IP) in the
        // unspecified-address expansion loops below.
        let local_listeners = self.global_ctx.get_running_listeners();
        let port_has_local_listener = |port: u16| -> bool {
            local_listeners
                .iter()
                .any(|l| l.port() == Some(port) && matches_protocol!(l, Protocol::UDP) == is_udp)
        };

        match listener_host {
            Some(SocketAddr::V4(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // Only pay the should_deny_proxy cost (bind per IP) when a local
                    // listener actually uses this port+protocol; otherwise the check
                    // can never return true.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv4s
                        .iter()
                        .chain(ip_list.public_ipv4.iter())
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(
                                IpAddr::V4(std::net::Ipv4Addr::from(ip.addr)),
                                s_addr.port(),
                            );
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (0.0.0.0 expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(ip.to_string().as_str())).is_ok() {
                                if !scheduled.insert(addr.to_string()) {
                                    return;
                                }
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for interface ipv4"
                                );
                            }
                        });
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv4)");
                    } else {
                        if !scheduled.insert(listener.to_string()) {
                            return;
                        }
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            Some(SocketAddr::V6(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // for ipv6, only try public ip
                    // Same port pre-check as IPv4: avoid binding per IP when no local
                    // listener uses this port+protocol.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv6s
                        .iter()
                        .chain(ip_list.public_ipv6.iter())
                        .filter_map(|x| Ipv6Addr::from_str(&x.to_string()).ok())
                        .filter(|x| is_usable_public_ipv6_candidate(x, &self.global_ctx))
                        .collect::<HashSet<_>>()
                        .iter()
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(IpAddr::V6(*ip), s_addr.port());
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (:: expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(format!("[{}]", ip).as_str())).is_ok() {
                                if !scheduled.insert(addr.to_string()) {
                                    return;
                                }
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for public ipv6"
                                );
                            }
                        });
                } else if self.global_ctx.is_ip_lowertier_managed_ipv6(s_addr.ip()) {
                    tracing::debug!(
                        ?listener,
                        "skip LowTier-managed IPv6 as direct-connect target"
                    );
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv6)");
                    } else {
                        if !scheduled.insert(listener.to_string()) {
                            return;
                        }
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            p => {
                tracing::error!(?p, ?listener, "failed to parse ip version from listener");
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect_internal(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        let enable_ipv6 = self.global_ctx.get_flags().enable_ipv6;
        let available_listeners = ip_list
            .listeners
            .clone()
            .into_iter()
            .map(Into::<url::Url>::into)
            .filter_map(|l| if l.scheme() != "ring" { Some(l) } else { None })
            .filter(|l| mapped_listener_port(l).is_some() && l.host().is_some())
            .filter(|l| enable_ipv6 || !matches!(l.host().unwrap().to_owned(), Host::Ipv6(_)))
            .collect::<Vec<_>>();

        tracing::debug!(?available_listeners, "got available listeners");

        if available_listeners.is_empty() {
            return Err(anyhow::anyhow!("peer {} have no valid listener", dst_peer_id).into());
        }

        let default_protocol = self.global_ctx.get_flags().default_protocol;
        // Prefer the configured protocol. Default is QUIC/h3, then H2/TCP, then WSS.
        // highest priority is in the last
        let mut available_listeners = available_listeners;
        let flags = self.global_ctx.flags_arc();
        let mut unique_listeners = HashSet::new();
        available_listeners.retain(|listener| {
            crate::common::config::transport_protocol_enabled(&flags, listener.scheme())
                && unique_listeners.insert(listener.clone())
        });
        available_listeners
            .sort_by_key(|listener| direct_protocol_priority(listener.scheme(), &default_protocol));

        while !available_listeners.is_empty() {
            if self.peer_manager.has_live_peer_connection(dst_peer_id) {
                return Ok(());
            }
            let mut tasks = JoinSet::new();
            let mut listener_list = vec![];
            let mut scheduled = HashSet::new();

            let cur_scheme = available_listeners.last().unwrap().scheme().to_owned();
            while let Some(listener) = available_listeners.last() {
                if listener.scheme() != cur_scheme {
                    break;
                }

                tracing::debug!("try direct connect to peer with listener: {}", listener);
                self.spawn_direct_connect_task(
                    dst_peer_id,
                    &ip_list,
                    listener,
                    &mut tasks,
                    &mut scheduled,
                )
                .await;

                listener_list.push(listener.clone().to_string());
                available_listeners.pop();
            }

            let ret = wait_for_probe_group(
                &mut tasks,
                || self.peer_manager.has_live_peer_connection(dst_peer_id),
                DIRECT_PROBE_GRACE_PERIOD,
            )
            .await;
            tracing::debug!(
                ?ret,
                ?dst_peer_id,
                ?cur_scheme,
                ?listener_list,
                "all tasks finished for current scheme"
            );

            if self.peer_manager.has_live_peer_connection(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 2000, 2000, 5000, 5000, 10000, 30000, 60000]);
        let mut attempt = 0;
        loop {
            if self.peer_black_list.contains(&dst_peer_id) {
                return Err(anyhow::anyhow!("peer {} is blacklisted", dst_peer_id).into());
            }

            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(backoff.next_backoff())).await;
            }
            // A punched connection already supplies a direct path. Do not query or dial it again.
            if self.peer_manager.has_live_peer_connection(dst_peer_id) {
                return Ok(());
            }
            attempt += 1;

            let peer_manager = self.peer_manager.clone();
            tracing::debug!("try direct connect to peer: {}", dst_peer_id);

            let rpc_stub = peer_manager
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                peer_manager.my_peer_id(),
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

            let ip_list = rpc_stub
                .get_ip_list(BaseController::default(), GetIpListRequest {})
                .await;
            let ip_list = handle_rpc_result(ip_list, dst_peer_id, &self.peer_black_list)
                .with_context(|| format!("get ip list from peer {}", dst_peer_id))?;

            tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");

            let ret = self
                .do_try_direct_connect_internal(dst_peer_id, ip_list)
                .await;
            tracing::info!(?ret, ?dst_peer_id, "do_try_direct_connect return");

            if peer_manager.has_live_peer_connection(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }
    }
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,
    client: PeerTaskManager<DirectConnectorLauncher>,
}

#[derive(Clone)]
struct DirectConnectorLauncher(Arc<DirectConnectorManagerData>);

#[async_trait::async_trait]
impl PeerTaskLauncher for DirectConnectorLauncher {
    type Data = Arc<DirectConnectorManagerData>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_mgr: Arc<PeerManager>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        data.peer_black_list.cleanup();
        let my_peer_id = data.peer_manager.my_peer_id();
        data.peer_manager
            .list_peers()
            .await
            .into_iter()
            .filter(|peer_id| {
                *peer_id != my_peer_id
                    && !data.peer_manager.has_live_peer_connection(*peer_id)
                    && !data.peer_black_list.contains(peer_id)
            })
            .collect()
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        tokio::spawn(async move { data.do_try_direct_connect(item).await.map_err(Into::into) })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let data = Arc::new(DirectConnectorManagerData::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));
        let client = PeerTaskManager::new_with_external_signal(
            DirectConnectorLauncher(data.clone()),
            peer_manager.clone(),
            Some(peer_manager.p2p_demand_notify()),
        );
        Self {
            global_ctx,
            data,
            client,
        }
    }

    pub fn run(&mut self) {
        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                    self.global_ctx.clone(),
                )),
                &self.data.global_ctx.get_network_name(),
            );
    }

    pub fn run_as_client(&mut self) {
        self.client.start();
    }
}
