//! Authenticated TCP rendezvous with independent TCP and TLS roles.
use super::{
    should_try_p2p_with_peer,
    traversal::{
        MAX_CANDIDATES, authenticate_rendezvous_peer, hole_punch_peers, source_pair,
        validate_ipv4_candidates,
    },
};
use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx, join_joinset_background, stun::TcpPortMappings},
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        peer_rpc::{
            TcpHolePunchRequest, TcpHolePunchResponse, TcpHolePunchRpc,
            TcpHolePunchRpcClientFactory, TcpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{
        Tunnel,
        common::{bind, ensure_local_allowed, ensure_remote_allowed},
        http2,
        websocket::{WsTunnelConnector, WsTunnelListener},
    },
};
use anyhow::{Context, Result, bail, ensure};
use futures::{SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(40);
const STREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(30);
mod hard_nat;

struct Expansion {
    mode: hard_nat::Strategy,
    permit: tokio::sync::SemaphorePermit<'static>,
}

struct NominatedTunnel {
    inner: Box<dyn Tunnel>,
    parts: Mutex<Option<crate::tunnel::SplitTunnel>>,
}
impl Tunnel for NominatedTunnel {
    fn split(&self) -> crate::tunnel::SplitTunnel {
        self.parts
            .lock()
            .unwrap()
            .take()
            .expect("tunnel already split")
    }
    fn info(&self) -> Option<crate::proto::common::TunnelInfo> {
        self.inner.info()
    }
    fn transport_binding(&self) -> Option<crate::tunnel::TransportBinding> {
        self.inner.transport_binding()
    }
    fn is_transport_authenticated(&self) -> bool {
        self.inner.is_transport_authenticated()
    }
    fn receive_backpressure(&self) -> Option<crate::tunnel::ReceiveBackpressure> {
        self.inner.receive_backpressure()
    }
}

async fn nominate(
    tunnel: Box<dyn Tunnel>,
    token: [u8; 32],
    client: bool,
) -> Result<Box<dyn Tunnel>> {
    use crate::tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    };
    let (mut reader, mut writer) = tunnel.split();
    let packet = || {
        let mut packet = ZCPacket::new_with_payload(&token);
        packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        PacketBatch::singleton(packet)
    };
    // Only the initiator nominates a stream. The RPC token binds it to this rendezvous.
    if client {
        writer.send(packet()).await?;
    }
    let mut batch = reader.next().await.context("TCP nomination closed")??;
    ensure!(!batch.is_empty(), "empty TCP nomination");
    let remaining = batch.split_off(1);
    let received = batch
        .pop_singleton()
        .map_err(|_| anyhow::anyhow!("invalid TCP nomination"))?;
    ensure!(received.payload() == token, "TCP nomination token mismatch");
    if !client {
        writer.send(packet()).await?;
    }
    if !remaining.is_empty() {
        reader = Box::pin(futures::stream::once(async { Ok(remaining) }).chain(reader));
    }
    Ok(Box::new(NominatedTunnel {
        inner: tunnel,
        parts: Mutex::new(Some((reader, writer))),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    H2,
    Wss,
}
impl Protocol {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "tcp" => Ok(Self::H2),
            "wss" => Ok(Self::Wss),
            _ => bail!("unsupported TCP punch protocol"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::H2 => "tcp",
            Self::Wss => "wss",
        }
    }
}
struct Reservation {
    listener: TcpListener,
    mapped_listeners: Vec<Arc<TcpListener>>,
    mapping: TcpPortMappings,
    candidates: Vec<SocketAddr>,
}
fn local_allowed(ctx: &ArcGlobalCtx, local: SocketAddr) -> Result<()> {
    let _guard = ctx.net_ns.guard();
    Ok(ensure_local_allowed(&ctx.get_underlay_policy(), local)?)
}
fn listen(ctx: &ArcGlobalCtx, local: SocketAddr) -> Result<TcpListener> {
    local_allowed(ctx, local)?;
    Ok(bind::<TcpSocket>()
        .addr(local)
        .reuse_port(true)
        .net_ns(ctx.net_ns.clone())
        .maybe_socket_mark(ctx.get_flags().socket_mark)
        .call()?
        .listen(16)?)
}
async fn reserve(ctx: &ArcGlobalCtx, offset: usize) -> Result<Reservation> {
    let ips = ctx.get_ip_collector().collect_ip_addrs().await;
    let mut addresses: Vec<SocketAddr> = ips
        .interface_ipv4s
        .into_iter()
        .map(|ip| SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), 0))
        .filter(|local| {
            !ctx.is_ip_in_same_network(&local.ip()) && local_allowed(ctx, *local).is_ok()
        })
        .collect();
    addresses.sort_unstable();
    if !addresses.is_empty() {
        let n = addresses.len();
        addresses.rotate_left(offset % n);
    }
    reserve_addresses(ctx, addresses).await
}

async fn reserve_addresses(ctx: &ArcGlobalCtx, addresses: Vec<SocketAddr>) -> Result<Reservation> {
    for local in addresses {
        let Ok(listener) = listen(ctx, local) else {
            continue;
        };
        let local = listener.local_addr()?;
        let mapping = match ctx
            .get_stun_info_collector()
            .get_tcp_port_mappings_bound(local, ctx.get_flags().socket_mark, ctx.net_ns.clone())
            .await
        {
            Ok(mapping) => mapping,
            Err(error) => {
                tracing::debug!(?local, ?error, "TCP punch STUN failed");
                continue;
            }
        };
        let mut candidates = mapping.addresses.clone();
        candidates.retain(|a| {
            a.is_ipv4() && ensure_remote_allowed(&ctx.get_underlay_policy(), *a).is_ok()
        });
        candidates.truncate(MAX_CANDIDATES - 1);
        if !candidates.contains(&local) {
            candidates.push(local);
        }
        let mapped_listeners = reserve_mapped_listeners(ctx, local, &mapping.addresses, &[]);
        tracing::info!(?local, ?candidates, "TCP punch reserved source port");
        return Ok(Reservation {
            listener,
            mapped_listeners,
            mapping,
            candidates,
        });
    }
    bail!("no allowed source with a TCP STUN mapping")
}

fn reserve_mapped_listeners(
    ctx: &ArcGlobalCtx,
    local: SocketAddr,
    mapped: &[SocketAddr],
    previous: &[Arc<TcpListener>],
) -> Vec<Arc<TcpListener>> {
    if let Some(listener) = previous.iter().find(|listener| {
        listener
            .local_addr()
            .is_ok_and(|address| mapped.contains(&address))
    }) {
        return vec![listener.clone()];
    }
    for address in crate::common::network::local_mapped_addrs(local, mapped) {
        // A locally assigned public port needs its own exclusive listener.
        let bound = bind::<TcpSocket>()
            .addr(address)
            .reuse_address(false)
            .net_ns(ctx.net_ns.clone())
            .maybe_socket_mark(ctx.get_flags().socket_mark)
            .call()
            .and_then(|socket| {
                // Acquire the port exclusively before enabling source-port reuse for our connectors.
                let options = socket2::SockRef::from(&socket);
                options.set_reuse_address(true)?;
                #[cfg(unix)]
                options.set_reuse_port(true)?;
                Ok(socket.listen(16)?)
            });
        if let Ok(listener) = bound {
            tracing::info!(?address, "TCP punch reserved locally assigned mapped port");
            return vec![Arc::new(listener)];
        }
    }
    Vec::new()
}

pub(crate) struct TcpBootstrap {
    ctx: ArcGlobalCtx,
    protocol: Protocol,
    listener: TcpListener,
    mapping: tokio::sync::Mutex<TcpPortMappings>,
    mapped_listeners: tokio::sync::watch::Sender<Vec<Arc<TcpListener>>>,
    candidates: Mutex<HashMap<SocketAddr, tokio::time::Instant>>,
    advertised: Mutex<Option<SocketAddr>>,
}

impl TcpBootstrap {
    pub(crate) async fn new(
        ctx: ArcGlobalCtx,
        local: SocketAddr,
        advertised: Option<SocketAddr>,
    ) -> Result<Self> {
        let protocol = Protocol::parse(&ctx.get_flags().default_protocol)?;
        crate::common::config::ensure_transport_protocol_enabled(
            &ctx.flags_arc(),
            protocol.name(),
        )?;
        let reservation = if advertised.is_some() || local.is_ipv6() {
            let listener = listen(&ctx, local)?;
            let advertised = advertised.unwrap_or(listener.local_addr()?);
            ensure!(
                advertised.port() != 0 && advertised.is_ipv4() == local.is_ipv4(),
                "invalid discovery advertisement"
            );
            Reservation {
                listener,
                mapped_listeners: Vec::new(),
                mapping: TcpPortMappings {
                    addresses: vec![advertised],
                    connections: Vec::new(),
                },
                candidates: vec![advertised],
            }
        } else {
            reserve_addresses(&ctx, vec![local]).await?
        };
        let advertised = reservation
            .mapped_listeners
            .first()
            .and_then(|listener| listener.local_addr().ok())
            .or_else(|| reservation.mapping.addresses.first().copied())
            .context("no TCP bootstrap mapping")?;
        let (mapped_listeners, _) = tokio::sync::watch::channel(reservation.mapped_listeners);
        Ok(Self {
            ctx,
            protocol,
            listener: reservation.listener,
            mapping: tokio::sync::Mutex::new(reservation.mapping),
            mapped_listeners,
            candidates: Mutex::new(HashMap::new()),
            advertised: Mutex::new(Some(advertised)),
        })
    }

    pub(crate) async fn mapped(&self) -> Result<SocketAddr> {
        (*self.advertised.lock().unwrap()).context("TCP bootstrap mapping is unavailable")
    }

    pub(crate) async fn refresh_mapping(&self, previous: Option<SocketAddr>) -> Result<SocketAddr> {
        let result = self.refresh_mapping_inner(previous).await;
        *self.advertised.lock().unwrap() = result.as_ref().ok().copied();
        result
    }

    async fn refresh_mapping_inner(&self, previous: Option<SocketAddr>) -> Result<SocketAddr> {
        let local = self.listener.local_addr()?;
        local_allowed(&self.ctx, local)?;
        if local.is_ipv6() {
            return Ok(local);
        }
        let mut mapping = self.mapping.lock().await;
        mapping.connections.retain(|stream| {
            stream.peer_addr().is_ok_and(|remote| {
                ensure_remote_allowed(&self.ctx.get_underlay_policy(), remote).is_ok()
            })
        });
        if mapping.refresh().await.is_err() {
            *mapping = self
                .ctx
                .get_stun_info_collector()
                .get_tcp_port_mappings_bound(
                    local,
                    self.ctx.get_flags().socket_mark,
                    self.ctx.net_ns.clone(),
                )
                .await?;
        }
        mapping.addresses.retain(|address| {
            ensure_remote_allowed(&self.ctx.get_underlay_policy(), *address).is_ok()
        });
        let listeners = reserve_mapped_listeners(
            &self.ctx,
            local,
            &mapping.addresses,
            &self.mapped_listeners.borrow(),
        );
        // A local public mapping must advertise the port that owns its listener.
        let address = listeners
            .first()
            .and_then(|listener| listener.local_addr().ok())
            .or_else(|| previous.filter(|address| mapping.addresses.contains(address)))
            .or_else(|| mapping.addresses.first().copied())
            .context("no allowed TCP mapping")?;
        self.mapped_listeners.send_if_modified(|current| {
            if current.len() == listeners.len()
                && current
                    .iter()
                    .zip(&listeners)
                    .all(|(a, b)| Arc::ptr_eq(a, b))
            {
                false
            } else {
                *current = listeners;
                true
            }
        });
        Ok(address)
    }

    pub(crate) async fn accept_stream(&self) -> Result<TcpStream> {
        let mut changes = self.mapped_listeners.subscribe();
        loop {
            let mapped = changes.borrow_and_update().clone();
            let listeners = std::iter::once(&self.listener).chain(mapped.iter().map(AsRef::as_ref));
            let accepts = listeners
                .map(|listener| Box::pin(listener.accept()))
                .collect::<Vec<_>>();
            tokio::select! {
                (accepted, _, _) = futures::future::select_all(accepts) => return Ok(accepted?.0),
                changed = changes.changed() => { changed?; }
            }
        }
    }

    pub(crate) async fn accept(&self, stream: TcpStream) -> Result<Box<dyn Tunnel>> {
        establish(stream, self.ctx.clone(), self.protocol, false).await
    }

    pub(crate) fn register_candidate(&self, remote: SocketAddr) {
        let mut candidates = self.candidates.lock().unwrap();
        candidates.retain(|_, seen| seen.elapsed() < Duration::from_secs(120));
        if candidates.len() < 64 || candidates.contains_key(&remote) {
            candidates.insert(remote, tokio::time::Instant::now());
        }
    }

    async fn rendezvous_role(&self, remote: SocketAddr) -> Option<bool> {
        let local = self.mapped().await.ok()?;
        // Fresh source ports keep the conventional TLS client/server roles.
        let known = self
            .candidates
            .lock()
            .unwrap()
            .get(&remote)
            .is_some_and(|seen| seen.elapsed() < Duration::from_secs(120));
        known.then_some(local < remote)
    }

    fn connect_source(&self) -> Result<SocketAddr> {
        self.mapped_listeners
            .borrow()
            .first()
            .map(|listener| listener.local_addr())
            .unwrap_or_else(|| self.listener.local_addr())
            .map_err(Into::into)
    }

    pub(crate) async fn accept_candidate(
        &self,
        stream: TcpStream,
    ) -> Result<(Box<dyn Tunnel>, bool)> {
        let client = self
            .rendezvous_role(stream.peer_addr()?)
            .await
            .unwrap_or(false);
        Ok((
            establish(stream, self.ctx.clone(), self.protocol, client).await?,
            client,
        ))
    }

    pub(crate) async fn connect_candidate(
        &self,
        remote: SocketAddr,
    ) -> Result<(Box<dyn Tunnel>, bool)> {
        let client = self.rendezvous_role(remote).await.unwrap_or(true);
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            connect_bound(self.ctx.clone(), self.connect_source()?, remote),
        )
        .await??;
        Ok((
            establish(stream, self.ctx.clone(), self.protocol, client).await?,
            client,
        ))
    }

    pub(crate) async fn connect(
        &self,
        remote: SocketAddr,
        fresh_port: bool,
    ) -> Result<Box<dyn Tunnel>> {
        let mut local = self.connect_source()?;
        if fresh_port {
            local.set_port(0);
        }
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            connect_bound(self.ctx.clone(), local, remote),
        )
        .await??;
        establish(stream, self.ctx.clone(), self.protocol, true).await
    }
}
fn candidates(
    ctx: &ArcGlobalCtx,
    input: &[crate::proto::common::SocketAddr],
) -> Result<Vec<SocketAddr>> {
    validate_ipv4_candidates(ctx, input, "TCP")
}
async fn establish(
    stream: TcpStream,
    ctx: ArcGlobalCtx,
    protocol: Protocol,
    client: bool,
) -> Result<Box<dyn Tunnel>> {
    local_allowed(&ctx, stream.local_addr()?)?;
    ensure_remote_allowed(&ctx.get_underlay_policy(), stream.peer_addr()?)?;
    stream.set_nodelay(true)?;
    crate::tunnel::common::size_tcp_socket_buffers(&socket2::SockRef::from(&stream));
    let flags = ctx.get_flags();
    let local = crate::tunnel::build_url_from_socket_addr(
        &stream.local_addr()?.to_string(),
        protocol.name(),
    );
    let remote = crate::tunnel::build_url_from_socket_addr(
        &stream.peer_addr()?.to_string(),
        protocol.name(),
    );
    match (protocol, client) {
        (Protocol::H2, true) => Ok(http2::connect(stream, remote, &flags).await?),
        (Protocol::H2, false) => {
            http2::accept(stream, &http2::tls_acceptor(&flags)?, local, &flags)
                .await?
                .context("punched H2 connection was not admitted")
        }
        (Protocol::Wss, true) => Ok(WsTunnelConnector::connect_punched(
            stream,
            remote,
            ctx.get_underlay_policy(),
            Some(ctx.net_ns.clone()),
        )
        .await?),
        (Protocol::Wss, false) => Ok(WsTunnelListener::accept_punched(stream).await?),
    }
}
async fn connect_bound(
    ctx: ArcGlobalCtx,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<TcpStream> {
    local_allowed(&ctx, local)?;
    ensure_remote_allowed(&ctx.get_underlay_policy(), remote)?;
    let socket = bind::<TcpSocket>()
        .addr(local)
        .reuse_port(true)
        .net_ns(ctx.net_ns.clone())
        .maybe_socket_mark(ctx.get_flags().socket_mark)
        .call()?;
    // The caller owns the deadline. A pending SYN must survive simultaneous-open coordination.
    Ok(socket.connect(remote).await?)
}
async fn accept_once(
    listener: Arc<TcpListener>,
) -> (Arc<TcpListener>, std::io::Result<(TcpStream, SocketAddr)>) {
    let accepted = listener.accept().await;
    (listener, accepted)
}

fn spawn_handshake(
    handshakes: &mut JoinSet<Result<Box<dyn Tunnel>>>,
    stream: TcpStream,
    ctx: &ArcGlobalCtx,
    protocol: Protocol,
    client: bool,
    token: [u8; 32],
) {
    let ctx = ctx.clone();
    handshakes.spawn(async move {
        tokio::time::timeout(STREAM_HANDSHAKE_TIMEOUT, async {
            let tunnel = establish(stream, ctx, protocol, client).await?;
            if client {
                Ok(tunnel)
            } else {
                nominate(tunnel, token, false).await
            }
        })
        .await?
    });
}

async fn punch(
    reservation: Reservation,
    remote: Vec<SocketAddr>,
    ctx: ArcGlobalCtx,
    protocol: Protocol,
    client: bool,
    token: [u8; 32],
    expansion: Option<Expansion>,
) -> Result<Box<dyn Tunnel>> {
    let local = reservation.listener.local_addr()?;
    let (streams, mut expanded_streams) = tokio::sync::mpsc::channel(MAX_CANDIDATES);
    let expanded = if let Some(Expansion { mode, permit }) = expansion {
        match hard_nat::Prepared::new(&ctx, local, &remote, mode) {
            Ok(prepared) => {
                tracing::info!(?mode, ?local, "TCP expanded traversal started");
                Some(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                    prepared.with_permit(permit).run(ctx.clone(), streams),
                )))
            }
            Err(error) => {
                tracing::debug!(?mode, ?error, "TCP expanded traversal unavailable");
                None
            }
        }
    } else {
        None
    };
    let timeout = if expanded.is_some() {
        hard_nat::TIMEOUT
    } else {
        Duration::from_secs(20)
    };
    let mut accepts = JoinSet::new();
    for listener in
        std::iter::once(Arc::new(reservation.listener)).chain(reservation.mapped_listeners)
    {
        accepts.spawn(accept_once(listener));
    }
    let mut connects = JoinSet::new();
    let mut connecting = vec![false; remote.len()];
    let mut handshakes = JoinSet::new();
    let mut retry = tokio::time::interval(Duration::from_secs(4));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Keep STUN mappings and the listener alive until a peer TCP connection succeeds.
    let _mapping = reservation.mapping;
    tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                _ = retry.tick() => {
                    for (index, &destination) in remote.iter().enumerate() {
                        if connecting[index] { continue; }
                        connecting[index] = true;
                        let context = ctx.clone();
                        connects.spawn(async move {
                            (index, connect_bound(context, local, destination).await)
                        });
                    }
                }
                accepted = accepts.join_next(), if handshakes.len() < MAX_CANDIDATES => {
                    let (listener, accepted) = accepted.context("TCP punch listeners stopped")??;
                    let (stream, source) = accepted?;
                    accepts.spawn(accept_once(listener));
                    if !remote.iter().any(|candidate| candidate.ip() == source.ip()) { continue; }
                    spawn_handshake(&mut handshakes, stream, &ctx, protocol, client, token);
                }
                connected = connects.join_next(), if !connects.is_empty() => {
                    let (index, result) = connected.context("TCP punch connectors stopped")??;
                    connecting[index] = false;
                    if let Err(error) = &result {
                        tracing::debug!(?local, remote = ?remote[index], ?error, "TCP punch connection failed");
                    }
                    if let Ok(stream) = result {
                        if handshakes.len() >= MAX_CANDIDATES { continue; }
                        spawn_handshake(&mut handshakes, stream, &ctx, protocol, client, token);
                    }
                }
                Some(stream) = expanded_streams.recv(), if handshakes.len() < MAX_CANDIDATES => {
                    spawn_handshake(&mut handshakes, stream, &ctx, protocol, client, token);
                }
                result = handshakes.join_next(), if !handshakes.is_empty() => {
                    match result {
                        Some(Ok(Ok(tunnel))) => {
                            if !client { return Ok(tunnel); }
                            match tokio::time::timeout(STREAM_HANDSHAKE_TIMEOUT, nominate(tunnel, token, true)).await {
                                Ok(Ok(tunnel)) => return Ok(tunnel),
                                result => tracing::debug!(?result, "TCP nomination failed"),
                            }
                        },
                        Some(Ok(Err(error))) => tracing::debug!(?error, "TCP punch handshake failed"),
                        _ => {}
                    }
                }
            }
        }
    }).await.context("TCP simultaneous open timed out")?
}
#[derive(Default)]
struct State {
    active: Mutex<HashSet<PeerId>>,
    attempts: Mutex<HashMap<PeerId, (tokio::time::Instant, u32)>>,
}
struct Attempt {
    state: Arc<State>,
    peer: PeerId,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.state.active.lock().unwrap().remove(&self.peer);
        if let Some((time, _)) = self.state.attempts.lock().unwrap().get_mut(&self.peer) {
            *time = tokio::time::Instant::now();
        }
    }
}
struct Server {
    peer_mgr: Arc<PeerManager>,
    state: Arc<State>,
    permits: Arc<Semaphore>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}
impl Server {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "TCP rendezvous".into());
        Arc::new(Self {
            peer_mgr,
            state: Arc::default(),
            permits: Arc::new(Semaphore::new(4)),
            tasks,
        })
    }
    fn authenticate(ctrl: &BaseController) -> Result<PeerId> {
        authenticate_rendezvous_peer(ctrl, "TCP")
    }
    fn take(&self, peer: PeerId) -> Result<(Attempt, u32)> {
        let mut active = self.state.active.lock().unwrap();
        ensure!(!active.contains(&peer), "TCP punch already active");
        let mut attempts = self.state.attempts.lock().unwrap();
        let now = tokio::time::Instant::now();
        attempts.retain(|_, (time, _)| now.duration_since(*time) < Duration::from_secs(600));
        let index = if let Some((time, index)) = attempts.get_mut(&peer) {
            ensure!(
                now.duration_since(*time) >= RETRY,
                "TCP punch retry is rate limited"
            );
            *time = now;
            *index = index.wrapping_add(1);
            *index
        } else {
            ensure!(attempts.len() < 1024, "TCP punch peer limit reached");
            attempts.insert(peer, (now, 0));
            0
        };
        active.insert(peer);
        Ok((
            Attempt {
                state: self.state.clone(),
                peer,
            },
            index,
        ))
    }
    async fn allowed(&self, peer: PeerId) -> bool {
        let flags = self.peer_mgr.get_global_ctx().get_flags();
        let route = self
            .peer_mgr
            .list_routes()
            .await
            .into_iter()
            .find(|r| r.peer_id == peer);
        !flags.disable_tcp_hole_punching
            && should_try_p2p_with_peer(
                route.as_ref().and_then(|r| r.feature_flag.as_ref()),
                false,
                flags.disable_p2p,
                flags.need_p2p,
            )
    }
    async fn initiate(&self, peer: PeerId) -> Result<()> {
        ensure!(self.allowed(peer).await, "TCP punch denied by peer policy");
        let _permit = self.permits.clone().try_acquire_owned()?;
        let (_attempt, index) = self.take(peer)?;
        let (local_index, remote_index) = source_pair(index);
        let ctx = self.peer_mgr.get_global_ctx();
        let protocol = Protocol::parse(&ctx.get_flags().default_protocol)?;
        crate::common::config::ensure_transport_protocol_enabled(
            &ctx.flags_arc(),
            protocol.name(),
        )?;
        let reservation = reserve(&ctx, local_index as usize).await?;
        let variable_mapping = hard_nat::mapping_varies(&reservation.mapping);
        let hard_permit = if ctx.get_flags().disable_sym_hole_punching {
            None
        } else {
            hard_nat::PERMIT.try_acquire().ok()
        };
        let token = rand::random::<[u8; 32]>();
        let rpc = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                peer,
                ctx.get_network_name(),
            );
        let response = rpc
            .exchange_mapped_addr(
                BaseController {
                    timeout_ms: 12000,
                    ..Default::default()
                },
                TcpHolePunchRequest {
                    connector_mapped_addr: None,
                    candidates: reservation
                        .candidates
                        .iter()
                        .copied()
                        .map(Into::into)
                        .collect(),
                    protocol: protocol.name().into(),
                    source_index: remote_index,
                    version: 1,
                    nomination_token: token.to_vec(),
                    variable_mapping,
                    port_search: hard_permit.is_some(),
                },
            )
            .await?;
        ensure!(
            response.version == 1 && response.protocol == protocol.name(),
            "TCP rendezvous protocol mismatch"
        );
        let remote = candidates(&ctx, &response.candidates)?;
        let mode = hard_nat::strategy(variable_mapping, response.variable_mapping);
        let expansion = hard_permit
            .filter(|_| response.port_search && mode != hard_nat::Strategy::Candidates)
            .map(|permit| Expansion { mode, permit });
        let tunnel = punch(reservation, remote, ctx, protocol, true, token, expansion).await?;
        self.peer_mgr.add_punched_tunnel(tunnel, peer, true).await?;
        tracing::info!(peer, ?protocol, "TCP hole punch connected");
        Ok(())
    }
}
#[async_trait::async_trait]
impl TcpHolePunchRpc for Server {
    type Controller = BaseController;
    async fn exchange_mapped_addr(
        &self,
        ctrl: BaseController,
        request: TcpHolePunchRequest,
    ) -> rpc_types::error::Result<TcpHolePunchResponse> {
        let peer = Self::authenticate(&ctrl)?;
        let ctx = self.peer_mgr.get_global_ctx();
        let checked = async {
            ensure!(request.version == 1, "unsupported TCP rendezvous version");
            ensure!(self.allowed(peer).await, "TCP punch denied by peer policy");
            let protocol = Protocol::parse(&request.protocol)?;
            crate::common::config::ensure_transport_protocol_enabled(
                &ctx.flags_arc(),
                protocol.name(),
            )?;
            let token: [u8; 32] = request
                .nomination_token
                .as_slice()
                .try_into()
                .context("invalid TCP nomination token")?;
            let remote = candidates(&ctx, &request.candidates)?;
            let permit = self.permits.clone().try_acquire_owned()?;
            let (attempt, _) = self.take(peer)?;
            let reservation = tokio::time::timeout(
                Duration::from_secs(10),
                reserve(&ctx, request.source_index as usize),
            )
            .await??;
            let variable_mapping = hard_nat::mapping_varies(&reservation.mapping);
            let mode = hard_nat::strategy(variable_mapping, request.variable_mapping);
            let expansion = if request.port_search
                && !ctx.get_flags().disable_sym_hole_punching
                && mode != hard_nat::Strategy::Candidates
            {
                hard_nat::PERMIT
                    .try_acquire()
                    .ok()
                    .map(|permit| Expansion { mode, permit })
            } else {
                None
            };
            let response = TcpHolePunchResponse {
                listener_mapped_addr: None,
                candidates: reservation
                    .candidates
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect(),
                protocol: protocol.name().into(),
                version: 1,
                variable_mapping,
                port_search: expansion.is_some(),
            };
            let peer_mgr = self.peer_mgr.clone();
            self.tasks.lock().unwrap().spawn(async move {
                let (_attempt, _permit) = (attempt, permit);
                let result = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
                    let tunnel =
                        punch(reservation, remote, ctx, protocol, false, token, expansion).await?;
                    peer_mgr.add_punched_tunnel(tunnel, peer, false).await?;
                    tracing::info!(peer, ?protocol, "TCP hole punch accepted");
                    Ok::<_, anyhow::Error>(())
                })
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!(peer, ?result, "TCP punch attempt failed");
                }
            });
            Ok::<_, anyhow::Error>(response)
        }
        .await;
        checked.map_err(Into::into)
    }
}
#[derive(Clone)]
struct Launcher(Arc<Server>);
#[async_trait::async_trait]
impl PeerTaskLauncher for Launcher {
    type Data = Arc<Server>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();
    fn new_data(&self, _: Arc<PeerManager>) -> Self::Data {
        self.0.clone()
    }
    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<PeerId> {
        hole_punch_peers(&data.peer_mgr).await
    }
    async fn launch_task(
        &self,
        data: &Self::Data,
        peer: PeerId,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let data = data.clone();
        tokio::spawn(async move {
            let next = data
                .state
                .attempts
                .lock()
                .unwrap()
                .get(&peer)
                .map(|(time, _)| *time + RETRY);
            if let Some(next) = next {
                tokio::time::sleep_until(next).await;
            }
            tokio::time::timeout(ATTEMPT_TIMEOUT, data.initiate(peer)).await?
        })
    }
    async fn all_task_done(&self, _: &Self::Data) {}
    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}
pub struct TcpHolePunchConnector {
    server: Arc<Server>,
    client: PeerTaskManager<Launcher>,
}
impl TcpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let server = Server::new(peer_mgr.clone());
        let client = PeerTaskManager::new_with_external_signal(
            Launcher(server.clone()),
            peer_mgr.clone(),
            Some(peer_mgr.p2p_demand_notify()),
        );
        Self { server, client }
    }
    pub async fn run(&mut self) -> Result<()> {
        let ctx = self.server.peer_mgr.get_global_ctx();
        if ctx.get_flags().disable_tcp_hole_punching {
            return Ok(());
        }
        self.server
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                TcpHolePunchRpcServer::new_arc(self.server.clone()),
                &ctx.get_network_name(),
            );
        self.client.start();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{config::NetworkIdentity, global_ctx::tests::get_mock_global_ctx_with_network},
        proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
        tunnel::{
            TransportBindingKind,
            batch::PacketBatch,
            packet_def::{PacketType, ZCPacket},
        },
    };
    use futures::{SinkExt, StreamExt};
    pub(super) fn context() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "tcp-punch".into(),
            "test-secret".into(),
        )))
    }
    fn reservation(ctx: &ArcGlobalCtx) -> Reservation {
        let listener = listen(ctx, "127.0.0.1:0".parse().unwrap()).unwrap();
        let local = listener.local_addr().unwrap();
        Reservation {
            listener,
            mapped_listeners: vec![],
            mapping: TcpPortMappings {
                addresses: vec![local],
                connections: vec![],
            },
            candidates: vec![local],
        }
    }

    struct LocalStun(Option<SocketAddr>);
    #[async_trait::async_trait]
    impl crate::common::stun::StunInfoCollectorTrait for LocalStun {
        async fn get_udp_port_mapping_with_socket(
            &self,
            _: Arc<tokio::net::UdpSocket>,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            unreachable!()
        }
        fn get_stun_info(&self) -> crate::proto::common::StunInfo {
            Default::default()
        }
        async fn get_udp_port_mapping(
            &self,
            _: u16,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            unreachable!()
        }
        async fn get_tcp_port_mapping(
            &self,
            _: u16,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            unreachable!("TCP traversal must retain its bound source")
        }
        async fn get_tcp_port_mappings_bound(
            &self,
            local: SocketAddr,
            _: Option<u32>,
            _: crate::common::netns::NetNS,
        ) -> Result<TcpPortMappings, crate::common::error::Error> {
            Ok(TcpPortMappings {
                addresses: vec![self.0.unwrap_or(local)],
                connections: vec![],
            })
        }
    }

    #[tokio::test]
    #[serial_test::serial(traversal_expansion)]
    async fn authenticated_relay_rendezvous_establishes_direct_h2_and_wss() {
        use crate::peers::tests::{
            connect_peer_manager, create_mock_peer_manager_secure, wait_route_appear,
        };
        for protocol in [Protocol::H2, Protocol::Wss] {
            let a = create_mock_peer_manager_secure("tcp-rpc".into(), "rpc-secret".into()).await;
            let b = create_mock_peer_manager_secure("tcp-rpc".into(), "rpc-secret".into()).await;
            let relay =
                create_mock_peer_manager_secure("tcp-rpc".into(), "rpc-secret".into()).await;
            for peer in [&a, &b] {
                let ctx = peer.get_global_ctx();
                ctx.replace_stun_info_collector(Box::new(LocalStun(None)));
                let mut flags = ctx.get_flags();
                flags.default_protocol = protocol.name().into();
                ctx.set_flags(flags);
            }
            connect_peer_manager(a.clone(), relay.clone()).await;
            connect_peer_manager(b.clone(), relay.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            assert!(!a.get_peer_map().has_peer(b.my_peer_id()));
            let server = Server::new(b.clone());
            b.get_peer_rpc_mgr().rpc_server().registry().register(
                TcpHolePunchRpcServer::new_arc(server.clone()),
                &b.get_global_ctx().get_network_name(),
            );
            tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                Server::new(a.clone()).initiate(b.my_peer_id()),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(a.get_peer_map().has_peer(b.my_peer_id()));
            assert!(b.get_peer_map().has_peer(a.my_peer_id()));
        }
    }
    #[tokio::test]
    async fn locally_mapped_tcp_port_is_reserved_without_sharing_an_existing_listener() {
        let ctx = context();
        ctx.replace_stun_info_collector(Box::new(LocalStun(None)));
        let occupied = reserve(&ctx, 0).await.unwrap();
        let mapped = occupied.listener.local_addr().unwrap();
        ctx.replace_stun_info_collector(Box::new(LocalStun(Some(mapped))));
        let fallback = reserve(&ctx, 0).await.unwrap();
        assert_ne!(fallback.listener.local_addr().unwrap(), mapped);
        assert!(fallback.mapped_listeners.is_empty());
        drop(fallback);
        drop(occupied);
        let reserved = reserve(&ctx, 0).await.unwrap();
        assert_eq!(reserved.mapped_listeners[0].local_addr().unwrap(), mapped);
        assert!(reserved.candidates.contains(&mapped));
        assert!(
            reserved
                .candidates
                .contains(&reserved.listener.local_addr().unwrap())
        );
        drop(reserved);
        let mut flags = ctx.get_flags();
        flags.default_protocol = "tcp".into();
        ctx.set_flags(flags);
        let bootstrap = Arc::new(
            TcpBootstrap::new(ctx.clone(), "127.0.0.1:0".parse().unwrap(), None)
                .await
                .unwrap(),
        );
        assert_eq!(bootstrap.mapped().await.unwrap(), mapped);
        let accepting = bootstrap.clone();
        let accepted = tokio::spawn(async move { accepting.accept_stream().await });
        tokio::task::yield_now().await;
        let replacement = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let replacement_address = replacement.local_addr().unwrap();
        drop(replacement);
        ctx.replace_stun_info_collector(Box::new(LocalStun(Some(replacement_address))));
        assert_eq!(
            bootstrap.refresh_mapping(Some(mapped)).await.unwrap(),
            replacement_address
        );
        let _client = TcpStream::connect(replacement_address).await.unwrap();
        let stream = tokio::time::timeout(Duration::from_secs(1), accepted)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stream.local_addr().unwrap(), replacement_address);
    }

    #[tokio::test]
    async fn simultaneous_open_preserves_h2_and_wss_bindings_and_payload() {
        for protocol in [Protocol::H2, Protocol::Wss] {
            tokio::time::timeout(Duration::from_secs(8), async {
                let ctx = context();
                let a = reservation(&ctx);
                let b = reservation(&ctx);
                let local_a = a.candidates[0];
                let local_b = b.candidates[0];
                let token = rand::random::<[u8; 32]>();
                let (a, b) = tokio::join!(
                    punch(a, vec![local_b], ctx.clone(), protocol, true, token, None),
                    punch(b, vec![local_a], ctx, protocol, false, token, None)
                );
                let a = a.unwrap();
                let b = b.unwrap();
                let binding = a.transport_binding().unwrap();
                assert_eq!(
                    binding.kind,
                    if protocol == Protocol::H2 {
                        TransportBindingKind::Http2TlsExporterV1
                    } else {
                        TransportBindingKind::WssTlsExporterV1
                    }
                );
                assert_eq!(Some(binding), b.transport_binding());
                let url: url::Url = a.info().unwrap().local_addr.unwrap().into();
                assert_eq!(url.port(), Some(local_a.port()));
                let (mut ar, mut aw) = a.split();
                let (mut br, mut bw) = b.split();
                let mut packet = ZCPacket::new_with_payload(b"punched TCP payload");
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                aw.send(PacketBatch::singleton(packet)).await.unwrap();
                bw.send(br.next().await.unwrap().unwrap()).await.unwrap();
                assert_eq!(
                    ar.next()
                        .await
                        .unwrap()
                        .unwrap()
                        .pop_singleton()
                        .unwrap()
                        .payload(),
                    b"punched TCP payload"
                );
            })
            .await
            .unwrap();
        }
    }
    #[test]
    fn rendezvous_rejects_unverified_callers_and_invalid_protocols() {
        assert!(Server::authenticate(&BaseController::default()).is_err());
        let mut ctrl = BaseController {
            authenticated_peer_id: Some(1),
            authenticated_peer_identity_type: Some(PeerIdentityType::ForeignRelay),
            authenticated_peer_secure_auth_level: Some(SecureAuthLevel::PeerVerified),
            ..Default::default()
        };
        assert!(Server::authenticate(&ctrl).is_err());
        ctrl.authenticated_peer_identity_type = Some(PeerIdentityType::Admin);
        assert_eq!(Server::authenticate(&ctrl).unwrap(), 1);
        assert!(Protocol::parse("ws").is_err());
        assert!(Protocol::parse("quic").is_err());
    }

    #[tokio::test]
    async fn only_the_nominated_stream_survives_competing_connections() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let token = rand::random::<[u8; 32]>();
            let (_unused_client, first_server) = crate::tunnel::ring::create_ring_tunnel_pair();
            let (chosen_client, chosen_server) = crate::tunnel::ring::create_ring_tunnel_pair();
            let mut candidates = JoinSet::new();
            candidates.spawn(nominate(first_server, token, false));
            candidates.spawn(nominate(chosen_server, token, false));
            let (client, server) =
                tokio::join!(nominate(chosen_client, token, true), candidates.join_next());
            let client = client.unwrap();
            let server = server.unwrap().unwrap().unwrap();
            candidates.abort_all();
            let (_, mut writer) = client.split();
            let (mut reader, _) = server.split();
            writer
                .send(PacketBatch::singleton(ZCPacket::new_with_payload(
                    b"chosen",
                )))
                .await
                .unwrap();
            assert_eq!(
                reader
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap()
                    .payload(),
                b"chosen"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn nomination_rejects_another_attempt_token() {
        let (a, b) = crate::tunnel::ring::create_ring_tunnel_pair();
        let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(nominate(a, [1; 32], true), nominate(b, [2; 32], false))
        })
        .await
        .unwrap();
        assert!(a.is_err());
        assert!(b.is_err());
    }
}
