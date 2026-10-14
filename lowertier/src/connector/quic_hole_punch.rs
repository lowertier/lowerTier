//! Authenticated rendezvous for QUIC. STUN and QUIC retain the same UDP socket.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, oneshot},
    task::JoinSet,
};

use crate::{
    common::{
        PeerId, global_ctx::ArcGlobalCtx, join_joinset_background, stun::StunInfoCollectorTrait,
    },
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        common::Void,
        peer_rpc::{
            QuicHolePunchRpc, QuicHolePunchRpcClientFactory, QuicHolePunchRpcServer,
            QuicPunchRequest, QuicPunchResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{
        TunnelConnector, TunnelListener,
        common::{bind, ensure_local_allowed, ensure_remote_allowed},
        quic::{QuicTunnelConnector, QuicTunnelListener},
    },
};

use super::{
    should_try_p2p_with_peer,
    traversal::{
        MAX_CANDIDATES, authenticate_rendezvous_peer, hole_punch_peers, source_pair,
        validate_ipv4_candidates,
    },
};

mod hard_nat;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

struct Session {
    transaction: [u8; 12],
    activate: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
struct State {
    sessions: Mutex<HashMap<PeerId, Session>>,
    cooldown: Mutex<HashMap<PeerId, (tokio::time::Instant, u32)>>,
}

struct SessionGuard {
    state: Arc<State>,
    peer: PeerId,
}

struct RetryGuard {
    state: Arc<State>,
    peer: PeerId,
}

impl Drop for RetryGuard {
    fn drop(&mut self) {
        if let Some((finished, _)) = self.state.cooldown.lock().unwrap().get_mut(&self.peer) {
            *finished = tokio::time::Instant::now();
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.state.sessions.lock().unwrap().remove(&self.peer);
    }
}

fn validate_candidates(
    ctx: &ArcGlobalCtx,
    addresses: &[crate::proto::common::SocketAddr],
) -> Result<Vec<SocketAddr>> {
    validate_ipv4_candidates(ctx, addresses, "QUIC")
}

async fn mapped_socket(ctx: &ArcGlobalCtx, offset: usize) -> Result<(UdpSocket, Vec<SocketAddr>)> {
    let addresses = ctx.get_ip_collector().collect_ip_addrs().await;
    let mut addresses: Vec<_> = addresses
        .interface_ipv4s
        .into_iter()
        .map(|ip| SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), 0))
        .collect();
    addresses.sort_unstable();
    addresses.retain(|local| {
        !ctx.is_ip_in_same_network(&local.ip())
            && ensure_local_allowed(&ctx.get_underlay_policy(), *local).is_ok()
    });
    if !addresses.is_empty() {
        let count = addresses.len();
        addresses.rotate_left((offset / 2) % count);
    }
    // Try the original STUN socket on alternate source slots if a local mapped port is unreachable.
    mapped_socket_from(ctx, addresses, offset % 2 == 0).await
}

async fn mapped_socket_from(
    ctx: &ArcGlobalCtx,
    addresses: Vec<SocketAddr>,
    try_local_mapping: bool,
) -> Result<(UdpSocket, Vec<SocketAddr>)> {
    let policy = ctx.get_underlay_policy();
    for local in addresses {
        if ctx.is_ip_in_same_network(&local.ip()) || ensure_local_allowed(&policy, local).is_err() {
            continue;
        }
        let socket = match bind::<UdpSocket>()
            .addr(local)
            .net_ns(ctx.net_ns.clone())
            .maybe_socket_mark(ctx.get_flags().socket_mark)
            .call()
        {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                tracing::debug!(?local, ?error, "QUIC punch bind failed");
                continue;
            }
        };
        let local = socket.local_addr()?;
        let mut candidates = match ctx
            .get_stun_info_collector()
            .get_udp_port_mappings_with_socket(socket.clone())
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::debug!(?local, ?error, "QUIC punch STUN mapping failed");
                continue;
            }
        };
        candidates.retain(|address| address.is_ipv4() && policy.allows_ip(address.ip()));
        candidates.truncate(MAX_CANDIDATES - 1);
        if !candidates.contains(&local) {
            candidates.push(local);
        }
        let socket = Arc::try_unwrap(socket)
            .map_err(|_| anyhow::anyhow!("STUN still owns the punch socket"))?;
        for mapped in crate::common::network::local_mapped_addrs(local, &candidates)
            .filter(|_| try_local_mapping)
        {
            if let Ok(mapped_socket) = bind::<UdpSocket>()
                .addr(mapped)
                .reuse_address(false)
                .net_ns(ctx.net_ns.clone())
                .maybe_socket_mark(ctx.get_flags().socket_mark)
                .call()
            {
                tracing::info!(?mapped, "QUIC punch reserved locally assigned mapped port");
                return Ok((mapped_socket, vec![mapped]));
            }
        }
        tracing::debug!(?local, ?candidates, "QUIC punch mapped socket");
        return Ok((socket, candidates));
    }
    bail!("no allowed IPv4 source for QUIC hole punching")
}

// The transaction ID is a random rendezvous secret sent through the encrypted RPC.
fn binding_request(transaction: &[u8; 12]) -> [u8; 20] {
    lowertier_tracker::binding::request(transaction)
}

fn binding_response(transaction: &[u8; 12], source: SocketAddr) -> Vec<u8> {
    lowertier_tracker::binding::response(&binding_request(transaction), source, false)
        .expect("authenticated probe uses a valid Binding request")
        .0
}

async fn punch(
    socket: &UdpSocket,
    candidates: &[SocketAddr],
    transaction: &[u8; 12],
    ctx: &ArcGlobalCtx,
    mut activation: Option<oneshot::Receiver<()>>,
) -> Result<SocketAddr> {
    let request = binding_request(transaction);
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buffer = [0; 512];
    let mut observed = None;
    tokio::time::timeout(PUNCH_TIMEOUT, async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    for destination in candidates {
                        if let Err(error) = socket.send_to(&request, destination).await {
                            tracing::trace!(?destination, ?error, "QUIC punch candidate send failed");
                        }
                    }
                }
                activated = async { activation.as_mut().unwrap().await }, if activation.is_some() => {
                    activated.context("QUIC activation was cancelled")?;
                    return observed.context("QUIC activation has no verified endpoint");
                }
                received = socket.recv_from(&mut buffer) => {
                    let (length, source) = match received {
                        Ok(packet) => packet,
                        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::HostUnreachable) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    if !source.is_ipv4() || source.port() == 0 || ensure_remote_allowed(&ctx.get_underlay_policy(), source).is_err() {
                        continue;
                    }
                    if buffer[..length] == request {
                        observed = Some(source);
                        if let Err(error) = socket.send_to(&binding_response(transaction, source), source).await {
                            tracing::trace!(?source, ?error, "QUIC punch response send failed");
                        }
                    } else if length == 32 && buffer[..2] == [1, 1]
                        && buffer[2..8] == [0, 12, 0x21, 0x12, 0xa4, 0x42]
                        && buffer[8..20] == *transaction && buffer[20..26] == [0, 0x20, 0, 8, 0, 1] {
                        observed = Some(source);
                        if activation.is_none() { return Ok(source); }
                    }
                }
            }
        }
    }).await.context("QUIC hole punch timed out")?
}

struct PunchServer {
    peer_mgr: Arc<PeerManager>,
    state: Arc<State>,
    permits: Arc<Semaphore>,
    hard_permits: Arc<Semaphore>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl PunchServer {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "QUIC punch server".to_owned());
        Arc::new(Self {
            peer_mgr,
            state: Arc::default(),
            permits: Arc::new(Semaphore::new(4)),
            hard_permits: Arc::new(Semaphore::new(1)),
            tasks,
        })
    }

    fn authenticate(ctrl: &BaseController) -> Result<PeerId> {
        authenticate_rendezvous_peer(ctrl, "QUIC")
    }

    fn take_attempt(&self, peer: PeerId) -> Option<u32> {
        let mut cooldown = self.state.cooldown.lock().unwrap();
        let now = tokio::time::Instant::now();
        cooldown.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(600));
        if let Some((start, attempt)) = cooldown.get_mut(&peer) {
            if now.duration_since(*start) < RETRY_INTERVAL {
                return None;
            }
            *start = now;
            *attempt = attempt.wrapping_add(1);
            return Some(*attempt);
        }
        if cooldown.len() >= 1024 {
            return None;
        }
        cooldown.insert(peer, (now, 0));
        Some(0)
    }

    async fn initiate(&self, peer: PeerId) -> Result<()> {
        let _permit = self.permits.clone().try_acquire_owned()?;
        let attempt = self
            .take_attempt(peer)
            .context("QUIC punch retry is rate limited")?;
        let _retry = RetryGuard {
            state: self.state.clone(),
            peer,
        };
        let (local_source, remote_source) = source_pair(attempt);
        let ctx = self.peer_mgr.get_global_ctx();
        crate::common::config::ensure_transport_protocol_enabled(&ctx.flags_arc(), "quic")?;
        let (socket, candidates) = mapped_socket(&ctx, local_source as usize).await?;
        let variable_mapping = hard_nat::mapping_varies(socket.local_addr()?, &candidates);
        let transaction: [u8; 12] = rand::random();
        let stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<QuicHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                peer,
                ctx.get_network_name(),
            );
        let response = stub
            .prepare(
                BaseController {
                    timeout_ms: 8000,
                    ..Default::default()
                },
                QuicPunchRequest {
                    candidates: candidates.into_iter().map(Into::into).collect(),
                    transaction_id: transaction.to_vec(),
                    source_index: remote_source,
                    variable_mapping,
                },
            )
            .await?;
        let candidates = validate_candidates(&ctx, &response.candidates)?;
        let mode = hard_nat::strategy(variable_mapping, response.variable_mapping);
        let _hard_permit = if mode != hard_nat::Strategy::Candidates {
            Some(self.hard_permits.clone().try_acquire_owned()?)
        } else {
            None
        };
        let (socket, remote) =
            hard_nat::run(socket, &candidates, &transaction, &ctx, None, mode).await?;
        stub.activate(
            BaseController::default(),
            QuicPunchRequest {
                candidates: vec![],
                transaction_id: transaction.to_vec(),
                source_index: 0,
                variable_mapping: false,
            },
        )
        .await?;
        let local = socket.local_addr()?;
        let mut connector = QuicTunnelConnector::from_punched_socket(socket, remote, ctx.clone());
        let tunnel = connector.connect().await?;
        self.peer_mgr.add_punched_tunnel(tunnel, peer, true).await?;
        tracing::info!(peer, ?local, ?remote, "QUIC hole punch connected");
        Ok(())
    }
}

#[async_trait::async_trait]
impl QuicHolePunchRpc for PunchServer {
    type Controller = BaseController;

    async fn prepare(
        &self,
        ctrl: BaseController,
        input: QuicPunchRequest,
    ) -> rpc_types::error::Result<QuicPunchResponse> {
        let peer = Self::authenticate(&ctrl)?;
        let ctx = self.peer_mgr.get_global_ctx();
        let flags = ctx.get_flags();
        let route = self
            .peer_mgr
            .list_routes()
            .await
            .into_iter()
            .find(|route| route.peer_id == peer);
        ensure_rpc(
            !flags.disable_udp_hole_punching
                && crate::common::config::transport_protocol_enabled(&flags, "quic")
                && should_try_p2p_with_peer(
                    route.as_ref().and_then(|r| r.feature_flag.as_ref()),
                    false,
                    flags.disable_p2p,
                    flags.need_p2p,
                ),
            "peer policy denies QUIC punching",
        )?;
        let transaction: [u8; 12] = input
            .transaction_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid QUIC punch transaction"))?;
        let candidates = validate_candidates(&ctx, &input.candidates)?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(anyhow::Error::from)?;
        ensure_rpc(
            self.take_attempt(peer).is_some(),
            "QUIC punch retry is rate limited",
        )?;
        let (activate_tx, activate_rx) = oneshot::channel();
        {
            let mut sessions = self.state.sessions.lock().unwrap();
            ensure_rpc(
                !sessions.contains_key(&peer),
                "QUIC punch session already exists",
            )?;
            sessions.insert(
                peer,
                Session {
                    transaction,
                    activate: Some(activate_tx),
                },
            );
        }
        let guard = SessionGuard {
            state: self.state.clone(),
            peer,
        };
        let (socket, mapped) = tokio::time::timeout(
            Duration::from_secs(6),
            mapped_socket(&ctx, input.source_index as usize),
        )
        .await??;
        let variable_mapping =
            hard_nat::mapping_varies(socket.local_addr().map_err(anyhow::Error::from)?, &mapped);
        let mode = hard_nat::strategy(variable_mapping, input.variable_mapping);
        let hard_permit = if mode != hard_nat::Strategy::Candidates {
            Some(
                self.hard_permits
                    .clone()
                    .try_acquire_owned()
                    .map_err(anyhow::Error::from)?,
            )
        } else {
            None
        };
        let peer_mgr = self.peer_mgr.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let _guard = guard;
            let _permit = permit;
            let _hard_permit = hard_permit;
            let result = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
                let (socket, remote) = hard_nat::run(
                    socket,
                    &candidates,
                    &transaction,
                    &ctx,
                    Some(activate_rx),
                    mode,
                )
                .await?;
                let local = socket.local_addr()?;
                let mut listener = QuicTunnelListener::from_punched_socket(socket, ctx)?;
                let tunnel = listener.accept().await?;
                peer_mgr.add_punched_tunnel(tunnel, peer, false).await?;
                tracing::info!(peer, ?local, ?remote, "QUIC hole punch accepted");
                Ok::<_, anyhow::Error>(())
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                tracing::debug!(peer, ?result, "QUIC punch server attempt failed");
            }
        });
        Ok(QuicPunchResponse {
            candidates: mapped.into_iter().map(Into::into).collect(),
            variable_mapping,
        })
    }

    async fn activate(
        &self,
        ctrl: BaseController,
        input: QuicPunchRequest,
    ) -> rpc_types::error::Result<Void> {
        let peer = Self::authenticate(&ctrl)?;
        let mut sessions = self.state.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&peer)
            .context("QUIC punch session expired")?;
        ensure_rpc(
            input.transaction_id == session.transaction,
            "QUIC punch transaction does not match",
        )?;
        if let Some(activate) = session.activate.take() {
            activate
                .send(())
                .map_err(|_| anyhow::anyhow!("QUIC punch receiver stopped"))?;
        }
        Ok(Void {})
    }
}

fn ensure_rpc(condition: bool, message: &'static str) -> rpc_types::error::Result<()> {
    if !condition {
        return Err(anyhow::anyhow!(message).into());
    }
    Ok(())
}

#[derive(Clone)]
struct Launcher(Arc<PunchServer>);

#[async_trait::async_trait]
impl PeerTaskLauncher for Launcher {
    type Data = Arc<PunchServer>;
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
            let retry_at = data
                .state
                .cooldown
                .lock()
                .unwrap()
                .get(&peer)
                .map(|(finished, _)| *finished + RETRY_INTERVAL);
            if let Some(retry_at) = retry_at {
                tokio::time::sleep_until(retry_at).await;
            }
            if data.peer_mgr.has_live_peer_connection(peer) {
                return Ok(());
            }
            tokio::time::timeout(ATTEMPT_TIMEOUT, data.initiate(peer)).await?
        })
    }
    async fn all_task_done(&self, _: &Self::Data) {}
    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct QuicHolePunchConnector {
    server: Arc<PunchServer>,
    client: PeerTaskManager<Launcher>,
}

impl QuicHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let server = PunchServer::new(peer_mgr.clone());
        let client = PeerTaskManager::new_with_external_signal(
            Launcher(server.clone()),
            peer_mgr.clone(),
            Some(peer_mgr.p2p_demand_notify()),
        );
        Self { server, client }
    }
    pub fn run(&mut self) {
        let ctx = self.server.peer_mgr.get_global_ctx();
        if ctx.get_flags().disable_udp_hole_punching {
            return;
        }
        self.server
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                QuicHolePunchRpcServer::new_arc(self.server.clone()),
                &ctx.get_network_name(),
            );
        self.client.start();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{config::NetworkIdentity, global_ctx::tests::get_mock_global_ctx_with_network},
        proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
        tunnel::{
            batch::PacketBatch,
            packet_def::{PacketType, ZCPacket},
        },
    };
    use futures::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) fn context() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "quic-punch-test".to_owned(),
            "quic-punch-secret".to_owned(),
        )))
    }

    #[derive(Default)]
    struct LocalStun {
        failures: AtomicUsize,
        mapping_started: Option<Arc<tokio::sync::Notify>>,
        mapping: Option<SocketAddr>,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for LocalStun {
        fn get_stun_info(&self) -> crate::proto::common::StunInfo {
            Default::default()
        }
        async fn get_udp_port_mapping(
            &self,
            _: u16,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            unreachable!("the traversal must use its bound socket")
        }
        async fn get_udp_port_mapping_with_socket(
            &self,
            socket: Arc<UdpSocket>,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            if let Some(started) = &self.mapping_started {
                started.notify_one();
                std::future::pending::<()>().await;
            }
            if self
                .failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
            {
                return Err(crate::common::error::Error::NotFound);
            }
            Ok(self.mapping.unwrap_or(socket.local_addr()?))
        }
        async fn get_tcp_port_mapping(
            &self,
            _: u16,
        ) -> Result<SocketAddr, crate::common::error::Error> {
            unreachable!("QUIC traversal must not use TCP mappings")
        }
    }

    #[tokio::test]
    async fn locally_mapped_udp_port_is_reserved_without_sharing_an_existing_socket() {
        let ctx = context();
        let occupied = bind::<UdpSocket>()
            .addr("127.0.0.1:0".parse().unwrap())
            .call()
            .unwrap();
        let mapped = occupied.local_addr().unwrap();
        ctx.replace_stun_info_collector(Box::new(LocalStun {
            mapping: Some(mapped),
            ..Default::default()
        }));
        let (fallback, _) = mapped_socket_from(&ctx, vec!["127.0.0.1:0".parse().unwrap()], true)
            .await
            .unwrap();
        assert_ne!(fallback.local_addr().unwrap(), mapped);
        drop(fallback);
        drop(occupied);
        let (reserved, candidates) =
            mapped_socket_from(&ctx, vec!["127.0.0.1:0".parse().unwrap()], true)
                .await
                .unwrap();
        assert_eq!(reserved.local_addr().unwrap(), mapped);
        assert_eq!(candidates, vec![mapped]);
        let source = bind::<UdpSocket>()
            .addr("127.0.0.1:0".parse().unwrap())
            .call()
            .unwrap();
        let source_addr = source.local_addr().unwrap();
        drop(source);
        drop(reserved);
        let (original, candidates) = mapped_socket_from(&ctx, vec![source_addr], false)
            .await
            .unwrap();
        assert_eq!(original.local_addr().unwrap(), source_addr);
        assert!(candidates.contains(&source_addr));
        assert!(candidates.contains(&mapped));
    }

    #[tokio::test]
    async fn authenticated_rpc_through_relay_establishes_direct_quic() {
        relay_establishes_direct_quic(false).await;
        relay_establishes_direct_quic(true).await;
    }

    async fn relay_establishes_direct_quic(foreign: bool) {
        use crate::peers::tests::{
            connect_peer_manager, create_mock_peer_manager_secure, wait_route_appear,
        };
        let a =
            create_mock_peer_manager_secure("punch-rpc".into(), "punch-rpc-secret".into()).await;
        let b =
            create_mock_peer_manager_secure("punch-rpc".into(), "punch-rpc-secret".into()).await;
        let relay_network = if foreign {
            "punch-foreign"
        } else {
            "punch-rpc"
        };
        let relay_secret = if foreign {
            "foreign-secret"
        } else {
            "punch-rpc-secret"
        };
        let relay =
            create_mock_peer_manager_secure(relay_network.into(), relay_secret.into()).await;
        if foreign {
            let ctx = relay.get_global_ctx();
            let mut flags = ctx.get_flags();
            flags.relay_config_mut().transit_networks = vec!["punch-rpc".to_owned()];
            ctx.set_flags(flags);
        }
        for peer in [&a, &b] {
            peer.get_global_ctx()
                .replace_stun_info_collector(Box::new(LocalStun::default()));
        }
        connect_peer_manager(a.clone(), relay.clone()).await;
        connect_peer_manager(b.clone(), relay.clone()).await;
        wait_route_appear(a.clone(), b.clone()).await.unwrap();
        assert!(!a.get_peer_map().has_peer(b.my_peer_id()));
        let server = PunchServer::new(b.clone());
        b.get_peer_rpc_mgr().rpc_server().registry().register(
            QuicHolePunchRpcServer::new_arc(server.clone()),
            &b.get_global_ctx().get_network_name(),
        );
        let client = PunchServer::new(a.clone());
        tokio::time::timeout(ATTEMPT_TIMEOUT, client.initiate(b.my_peer_id()))
            .await
            .unwrap()
            .unwrap();
        assert!(a.get_peer_map().has_peer(b.my_peer_id()));
        assert!(b.get_peer_map().has_peer(a.my_peer_id()));
    }

    #[tokio::test]
    async fn punched_tunnel_rejects_another_authenticated_peer() {
        use crate::peers::tests::create_mock_peer_manager_secure;
        let a = create_mock_peer_manager_secure("punch-identity".into(), "identity-secret".into())
            .await;
        let b = create_mock_peer_manager_secure("punch-identity".into(), "identity-secret".into())
            .await;
        let (client, server) = crate::tunnel::ring::create_ring_tunnel_pair();
        let (a_result, b_result) = tokio::join!(
            a.add_punched_tunnel(client, b.my_peer_id().wrapping_add(1), true),
            b.add_punched_tunnel(server, a.my_peer_id(), false)
        );
        assert!(a_result.is_err());
        assert!(b_result.is_ok());
        assert!(!a.get_peer_map().has_peer(b.my_peer_id()));
    }

    #[tokio::test]
    async fn failed_stun_source_does_not_prevent_next_source() {
        let ctx = context();
        ctx.replace_stun_info_collector(Box::new(LocalStun {
            failures: AtomicUsize::new(1),
            ..Default::default()
        }));
        let source = "127.0.0.1:0".parse().unwrap();
        let (socket, candidates) = mapped_socket_from(&ctx, vec![source, source], true)
            .await
            .unwrap();
        assert_eq!(candidates, vec![socket.local_addr().unwrap()]);
    }

    #[tokio::test]
    async fn cancelling_punch_and_quic_accept_releases_server_resources() {
        use crate::peers::tests::create_mock_peer_manager_secure;
        for activate_quic in [false, true] {
            let peer =
                create_mock_peer_manager_secure("punch-cancel".into(), "cancel-secret".into())
                    .await;
            let ctx = peer.get_global_ctx();
            ctx.replace_stun_info_collector(Box::new(LocalStun::default()));
            let server = PunchServer::new(peer.clone());
            let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let token = rand::random::<[u8; 12]>();
            let controller = BaseController {
                authenticated_peer_id: Some(peer.my_peer_id().wrapping_add(1)),
                authenticated_peer_identity_type: Some(PeerIdentityType::Admin),
                authenticated_peer_secure_auth_level: Some(SecureAuthLevel::PeerVerified),
                ..Default::default()
            };
            let destination = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                client.local_addr().unwrap().port(),
            );
            let response = server
                .prepare(
                    controller.clone(),
                    QuicPunchRequest {
                        candidates: vec![destination.into()],
                        transaction_id: token.to_vec(),
                        source_index: 0,
                        variable_mapping: false,
                    },
                )
                .await
                .unwrap();
            let remote: SocketAddr = response.candidates[0].clone().into();
            assert_eq!(server.permits.available_permits(), 3);
            assert_eq!(server.state.sessions.lock().unwrap().len(), 1);
            if activate_quic {
                punch(&client, &[remote], &token, &ctx, None).await.unwrap();
                server
                    .activate(
                        controller,
                        QuicPunchRequest {
                            candidates: vec![],
                            transaction_id: token.to_vec(),
                            source_index: 0,
                            variable_mapping: false,
                        },
                    )
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            server.tasks.lock().unwrap().abort_all();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let released = server.permits.available_permits() == 4
                        && server.state.sessions.lock().unwrap().is_empty();
                    if released && std::net::UdpSocket::bind(remote).is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn cancelling_mapping_releases_server_resources() {
        use crate::peers::tests::create_mock_peer_manager_secure;
        let peer =
            create_mock_peer_manager_secure("cancel-map".into(), "cancel-secret".into()).await;
        let started = Arc::new(tokio::sync::Notify::new());
        peer.get_global_ctx()
            .replace_stun_info_collector(Box::new(LocalStun {
                mapping_started: Some(started.clone()),
                ..Default::default()
            }));
        let server = PunchServer::new(peer);
        let task_server = server.clone();
        let task = tokio::spawn(async move {
            task_server
                .prepare(
                    BaseController {
                        authenticated_peer_id: Some(7),
                        authenticated_peer_identity_type: Some(PeerIdentityType::Admin),
                        authenticated_peer_secure_auth_level: Some(SecureAuthLevel::PeerVerified),
                        ..Default::default()
                    },
                    QuicPunchRequest {
                        candidates: vec!["127.0.0.1:12345".parse::<SocketAddr>().unwrap().into()],
                        transaction_id: vec![1; 12],
                        source_index: 0,
                        variable_mapping: false,
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        assert_eq!(server.permits.available_permits(), 3);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(server.permits.available_permits(), 4);
        assert!(server.state.sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn destination_dependent_mapping_and_port_filter_do_not_report_success() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_stun_mapping = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_peer_mapping = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_mapping = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let client_stun_addr = client_stun_mapping.local_addr().unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_mapped = server_mapping.local_addr().unwrap();
        let sent = Arc::new(AtomicUsize::new(0));
        let blocked = Arc::new(AtomicUsize::new(0));
        let sent_count = sent.clone();
        let blocked_count = blocked.clone();
        let proxy = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let mut buffer = [0; 512];
            let mut peer_buffer = [0; 512];
            let mut stale_buffer = [0; 512];
            loop {
                tokio::select! {
                    packet = server_mapping.recv_from(&mut buffer) => {
                        let (n, source) = packet.unwrap();
                        if source == client_addr {
                            sent_count.fetch_add(1, Ordering::Relaxed);
                            client_peer_mapping.send_to(&buffer[..n], server_mapped).await.unwrap();
                        } else if source == client_stun_addr {
                            server_mapping.send_to(&buffer[..n], server_addr).await.unwrap();
                        } else {
                            // Hattori contacted the STUN port. Its filter rejects the new port.
                            blocked_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    packet = client_stun_mapping.recv_from(&mut stale_buffer) => {
                        // The mapping for the rendezvous server cannot admit Hattori packets.
                        assert_eq!(packet.unwrap().1, server_addr);
                    }
                    packet = client_peer_mapping.recv_from(&mut peer_buffer) => {
                        let (n, _) = packet.unwrap();
                        server_mapping.send_to(&peer_buffer[..n], client_addr).await.unwrap();
                    }
                }
            }
        }));
        let ctx = context();
        let token = rand::random();
        let (_activate, activation) = oneshot::channel();
        let result = tokio::time::timeout(Duration::from_millis(450), async {
            let server_candidates = [server_mapped];
            let client_candidates = [client_stun_addr];
            tokio::try_join!(
                punch(&client, &server_candidates, &token, &ctx, None),
                punch(&server, &client_candidates, &token, &ctx, Some(activation))
            )
        })
        .await;
        assert!(result.is_err());
        assert!(sent.load(Ordering::Relaxed) >= 2);
        assert!(blocked.load(Ordering::Relaxed) >= 2);
        drop(proxy);
    }

    #[tokio::test]
    async fn punched_socket_survives_loss_and_peer_reflexive_mapping() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let translated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let stale = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let server_addr = server.local_addr().unwrap();
            let front_addr = front.local_addr().unwrap();
            let translated_addr = translated.local_addr().unwrap();
            let stale_addr = stale.local_addr().unwrap();
            // This proxy changes the source mapping and loses the first STUN response.
            let proxy = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let mut incoming = [0; 65535];
                let mut outgoing = [0; 65535];
                let mut dropped = false;
                loop {
                    tokio::select! {
                        packet = front.recv_from(&mut incoming) => {
                            let (n, source) = packet.unwrap();
                            assert_eq!(source, client_addr);
                            translated.send_to(&incoming[..n], server_addr).await.unwrap();
                        }
                        packet = translated.recv_from(&mut outgoing) => {
                            let (n, source) = packet.unwrap();
                            assert_eq!(source, server_addr);
                            if !dropped && n == 32 && outgoing[..2] == [1, 1] {
                                dropped = true;
                                continue;
                            }
                            front.send_to(&outgoing[..n], client_addr).await.unwrap();
                        }
                    }
                }
            }));
            let token = rand::random();
            let (activate, activation) = oneshot::channel();
            let ctx = context();
            let server_ctx = ctx.clone();
            let accept = tokio::spawn(async move {
                let observed = punch(
                    &server,
                    &[stale_addr],
                    &token,
                    &server_ctx,
                    Some(activation),
                )
                .await
                .unwrap();
                assert_eq!(observed, translated_addr);
                assert_eq!(server.local_addr().unwrap(), server_addr);
                let mut listener =
                    QuicTunnelListener::from_punched_socket(server, server_ctx).unwrap();
                listener.accept().await.unwrap()
            });
            // Broadcast fails without SO_BROADCAST. The valid candidate must still work.
            let invalid = "255.255.255.255:9".parse().unwrap();
            let observed = punch(&client, &[invalid, front_addr], &token, &ctx, None)
                .await
                .unwrap();
            assert_eq!(observed, front_addr);
            assert_eq!(client.local_addr().unwrap(), client_addr);
            activate.send(()).unwrap();
            let mut connector = QuicTunnelConnector::from_punched_socket(client, observed, ctx);
            let client_tunnel = connector.connect().await.unwrap();
            let server_tunnel = accept.await.unwrap();
            assert!(client_tunnel.transport_binding().is_some());
            assert_eq!(
                client_tunnel.transport_binding(),
                server_tunnel.transport_binding()
            );
            let client_local: url::Url = client_tunnel.info().unwrap().local_addr.unwrap().into();
            let server_local: url::Url = server_tunnel.info().unwrap().local_addr.unwrap().into();
            assert_eq!(client_local.port(), Some(client_addr.port()));
            assert_eq!(server_local.port(), Some(server_addr.port()));
            let (mut client_rx, mut client_tx) = client_tunnel.split();
            let (mut server_rx, mut server_tx) = server_tunnel.split();
            let mut packet = ZCPacket::new_with_payload(b"punched QUIC payload");
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
            client_tx
                .send(PacketBatch::singleton(packet))
                .await
                .unwrap();
            let received = server_rx.next().await.unwrap().unwrap();
            server_tx.send(received).await.unwrap();
            let received = client_rx
                .next()
                .await
                .unwrap()
                .unwrap()
                .pop_singleton()
                .unwrap();
            assert_eq!(received.payload(), b"punched QUIC payload");
            drop(proxy);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn wrong_transaction_cannot_select_a_peer() {
        let ctx = context();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let attacker_addr = attacker.local_addr().unwrap();
        attacker
            .send_to(&binding_response(&[2; 12], local), local)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            punch(&socket, &[attacker_addr], &[1; 12], &ctx, None),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn rendezvous_rejects_unverified_and_foreign_peers() {
        assert!(PunchServer::authenticate(&BaseController::default()).is_err());
        let mut ctrl = BaseController {
            authenticated_peer_id: Some(7),
            authenticated_peer_identity_type: Some(PeerIdentityType::ForeignRelay),
            authenticated_peer_secure_auth_level: Some(SecureAuthLevel::PeerVerified),
            ..Default::default()
        };
        assert!(PunchServer::authenticate(&ctrl).is_err());
        ctrl.authenticated_peer_identity_type = Some(PeerIdentityType::Admin);
        assert_eq!(PunchServer::authenticate(&ctrl).unwrap(), 7);
        ctrl.authenticated_peer_secure_auth_level = Some(SecureAuthLevel::EncryptedUnauthenticated);
        assert!(PunchServer::authenticate(&ctrl).is_err());
    }

    #[tokio::test]
    async fn rendezvous_rejects_invalid_candidates_and_denied_underlay() {
        let ctx = context();
        for address in [
            "0.0.0.0:100",
            "224.0.0.1:100",
            "255.255.255.255:100",
            "127.0.0.1:0",
            "[::1]:100",
        ] {
            assert!(
                validate_candidates(&ctx, &[address.parse::<SocketAddr>().unwrap().into()])
                    .is_err()
            );
        }
        let address: crate::proto::common::SocketAddr =
            "127.0.0.1:100".parse::<SocketAddr>().unwrap().into();
        assert!(validate_candidates(&ctx, &vec![address.clone(); MAX_CANDIDATES + 1]).is_err());
        let mut flags = ctx.get_flags();
        flags.underlay_deny_cidrs = vec!["127.0.0.0/8".to_owned()];
        ctx.set_flags(flags);
        assert!(validate_candidates(&ctx, &[address]).is_err());
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(QuicTunnelListener::from_punched_socket(socket, ctx).is_err());
    }
}
