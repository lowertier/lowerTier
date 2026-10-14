use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use crossbeam::atomic::AtomicCell;
use futures::Future;
use std::sync::RwLock;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    common::{PeerId, global_ctx::GlobalCtx},
    peers::{
        peer_manager::PeerManager,
        peer_map::PeerMap,
        peer_rpc::PeerRpcManager,
        route_trait::{RouteCostCalculator, RouteCostCalculatorInterface},
    },
    proto::{
        api::instance::Route,
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, GlobalPeerMap, PeerCenterRpc,
            PeerCenterRpcClientFactory, PeerCenterRpcServer, PeerInfoForGlobalMap,
            ReportPeersRequest, ReportPeersResponse,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
};

use super::{Digest, Error, server::PeerCenterServer};

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait PeerCenterPeerManagerTrait: Send + Sync + 'static {
    async fn list_peers(&self) -> PeerInfoForGlobalMap;
    fn my_peer_id(&self) -> PeerId;
    fn get_global_ctx(&self) -> Arc<GlobalCtx>;
    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager>;
    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route>;

    fn local_center_route(&self) -> Option<Route> {
        let global_ctx = self.get_global_ctx();
        if global_ctx.get_network_identity().network_secret.is_none()
            || global_ctx.get_feature_flags().is_credential_peer
            || global_ctx
                .get_hostname()
                .starts_with(crate::peers::PUBLIC_SERVER_HOSTNAME_PREFIX)
        {
            return None;
        }
        Some(Route {
            peer_id: self.my_peer_id(),
            feature_flag: Some(global_ctx.get_feature_flags()),
            peer_identity_type: crate::proto::peer_rpc::PeerIdentityType::Admin as i32,
            secure_auth_level: crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed
                as i32,
            ..Default::default()
        })
    }
}

struct PeerCenterBase {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
    my_peer_id: PeerId,
    tasks: Mutex<JoinSet<()>>,
    lock: Arc<Mutex<()>>,
    local_server: std::sync::OnceLock<PeerCenterServer>,
}

/// Only locally constructed jobs can use this service. Remote calls use the RPC server.
struct LocalPeerCenterClient {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
    server: PeerCenterServer,
}

impl LocalPeerCenterClient {
    fn controller(&self) -> Result<BaseController, rpc_types::error::Error> {
        let route = self.peer_mgr.local_center_route().ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket(
                "local peer is not an eligible center".to_owned(),
            )
        })?;
        let mut ctrl = BaseController::default();
        ctrl.set_authenticated_peer_id(Some(route.peer_id));
        ctrl.set_authenticated_peer_identity_type(Some(
            crate::proto::peer_rpc::PeerIdentityType::try_from(route.peer_identity_type).map_err(
                |_| {
                    rpc_types::error::Error::MalformatRpcPacket("invalid local identity".to_owned())
                },
            )?,
        ));
        ctrl.set_authenticated_peer_secure_auth_level(Some(
            crate::proto::peer_rpc::SecureAuthLevel::try_from(route.secure_auth_level).map_err(
                |_| {
                    rpc_types::error::Error::MalformatRpcPacket(
                        "invalid local authentication level".to_owned(),
                    )
                },
            )?,
        ));
        Ok(ctrl)
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for LocalPeerCenterClient {
    type Controller = BaseController;

    async fn report_peers(
        &self,
        _: BaseController,
        req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        self.server.report_peers(self.controller()?, req).await
    }

    async fn get_global_peer_map(
        &self,
        _: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        self.server
            .get_global_peer_map(self.controller()?, req)
            .await
    }
}

struct PeridicJobCtx<T> {
    _peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
    my_peer_id: PeerId,
    center_peer: AtomicCell<PeerId>,
    job_ctx: T,
}

impl PeerCenterBase {
    pub async fn init(&self) -> Result<(), Error> {
        let Some(rpc_mgr) = self.peer_mgr.get_rpc_mgr().upgrade() else {
            return Err(Error::Shutdown);
        };
        rpc_mgr.rpc_server().registry().register(
            PeerCenterRpcServer::new(self.local_server.get_or_init(PeerCenterServer::new).clone()),
            &self.peer_mgr.get_global_ctx().get_network_name(),
        );
        Ok(())
    }

    fn select_center_peer_from_routes(
        peers: &[crate::proto::api::instance::Route],
    ) -> Option<PeerId> {
        let mut eligible_peers = peers
            .iter()
            .filter(|route| {
                route.peer_identity_type == crate::proto::peer_rpc::PeerIdentityType::Admin as i32
            })
            .filter(|route| {
                route.secure_auth_level
                    == crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed as i32
            })
            .filter(|route| {
                route
                    .feature_flag
                    .map(|flags| !flags.is_public_server)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();

        // All peers run this rule over the same authenticated route snapshot.
        // A speed-capable administrator wins only when one exists.
        if eligible_peers
            .iter()
            .any(|route| route.feature_flag.is_some_and(|flags| flags.speed_routing))
        {
            eligible_peers
                .retain(|route| route.feature_flag.is_some_and(|flags| flags.speed_routing));
        }
        eligible_peers
            .into_iter()
            .min_by_key(|route| route.peer_id)
            .map(|route| route.peer_id)
    }

    async fn select_center_peer(peer_mgr: &dyn PeerCenterPeerManagerTrait) -> Option<PeerId> {
        let mut peers = peer_mgr.list_routes().await;
        if let Some(local_route) = peer_mgr.local_center_route() {
            peers.push(local_route);
        }
        Self::select_center_peer_from_routes(&peers)
    }

    async fn init_periodic_job<
        T: Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<u32, rpc_types::error::Error>> + Send + 'static,
    >(
        &self,
        job_ctx: T,
        job_fn: impl Fn(
            Box<dyn PeerCenterRpc<Controller = BaseController> + Send>,
            Arc<PeridicJobCtx<T>>,
        ) -> Fut
        + Send
        + Sync
        + 'static,
    ) {
        let my_peer_id = self.my_peer_id;
        let peer_mgr = self.peer_mgr.clone();
        let lock = self.lock.clone();
        let local_server = self
            .local_server
            .get()
            .expect("peer center is initialized")
            .clone();
        self.tasks.lock().await.spawn(
            async move {
                let ctx = Arc::new(PeridicJobCtx {
                    _peer_mgr: peer_mgr.clone(),
                    my_peer_id,
                    center_peer: AtomicCell::new(PeerId::default()),
                    job_ctx,
                });
                loop {
                    let Some(center_peer) = Self::select_center_peer(&peer_mgr).await else {
                        tracing::trace!("no center peer found, sleep 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    let Some(rpc_mgr) = peer_mgr.get_rpc_mgr().upgrade() else {
                        tracing::error!("rpc manager is shutdown, exit periodic job");
                        return;
                    };

                    ctx.center_peer.store(center_peer);
                    tracing::trace!(?center_peer, "run periodic job");
                    let _g = lock.lock().await;
                    let stub: Box<dyn PeerCenterRpc<Controller = BaseController> + Send> =
                        if center_peer == my_peer_id {
                            Box::new(LocalPeerCenterClient {
                                peer_mgr: peer_mgr.clone(),
                                server: local_server.clone(),
                            })
                        } else {
                            rpc_mgr
                                .rpc_client()
                                .scoped_client::<PeerCenterRpcClientFactory<BaseController>>(
                                    my_peer_id,
                                    center_peer,
                                    peer_mgr.get_global_ctx().get_network_name(),
                                )
                        };
                    let ret = job_fn(stub, ctx.clone()).await;
                    drop(_g);

                    let Ok(sleep_time_ms) = ret else {
                        tracing::error!("periodic job to center server rpc failed: {:?}", ret);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    };

                    if sleep_time_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(sleep_time_ms as u64)).await;
                    }
                }
            }
            .instrument(tracing::info_span!("periodic_job", ?my_peer_id)),
        );
    }

    pub fn new(peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>) -> Self {
        let my_peer_id = peer_mgr.my_peer_id();
        PeerCenterBase {
            peer_mgr,
            my_peer_id,
            tasks: Mutex::new(JoinSet::new()),
            lock: Arc::new(Mutex::new(())),
            local_server: std::sync::OnceLock::new(),
        }
    }
}

#[derive(Clone)]
pub struct PeerCenterInstanceService {
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
}

fn apply_global_peer_map_response(
    global_peer_map: &RwLock<GlobalPeerMap>,
    global_peer_map_digest: &AtomicCell<Digest>,
    global_peer_map_update_time: &AtomicCell<Instant>,
    source_update_times: &RwLock<HashMap<PeerId, Instant>>,
    requested_digest: Digest,
    response: GetGlobalPeerMapResponse,
) -> bool {
    // A digest match must not replace a populated cache with an empty map.
    // Accept the legacy default response and the explicit digest-only form.
    if response == GetGlobalPeerMapResponse::default()
        || (requested_digest != 0
            && response.global_peer_map.is_empty()
            && response.digest == Some(requested_digest))
    {
        return false;
    }

    let received_at = Instant::now();
    let full_snapshot = response.full_snapshot
        || (!response.global_peer_map.is_empty() && response.deltas.is_empty());
    let snapshot_residence_age_ms = response.snapshot_residence_age_ms;
    let mut next_map = if full_snapshot {
        response.global_peer_map
    } else {
        global_peer_map.read().unwrap().map.clone()
    };
    let mut next_source_times = if full_snapshot {
        HashMap::with_capacity(next_map.len())
    } else {
        source_update_times.read().unwrap().clone()
    };
    if full_snapshot {
        for peer_info in next_map.values_mut() {
            for info in peer_info.direct_peers.values_mut() {
                info.speed_sample_age_ms = info
                    .speed_sample_age_ms
                    .saturating_add(snapshot_residence_age_ms);
            }
        }
        next_source_times.extend(next_map.keys().copied().map(|source| (source, received_at)));
    }
    if !response.deltas.is_empty() {
        for delta in response.deltas {
            if delta.removed {
                next_map.remove(&delta.source_peer_id);
                next_source_times.remove(&delta.source_peer_id);
            } else if let Some(peer_info) = delta.peer_info {
                let mut peer_info = peer_info;
                for info in peer_info.direct_peers.values_mut() {
                    info.speed_sample_age_ms = info
                        .speed_sample_age_ms
                        .saturating_add(delta.residence_age_ms);
                }
                next_map.insert(delta.source_peer_id, peer_info);
                next_source_times.insert(delta.source_peer_id, received_at);
            }
        }
    }

    *global_peer_map.write().unwrap() = GlobalPeerMap { map: next_map };
    *source_update_times.write().unwrap() = next_source_times;
    global_peer_map_digest.store(response.digest.unwrap_or_default());
    global_peer_map_update_time.store(received_at);
    true
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterInstanceService {
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        _: BaseController,
        _: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let global_peer_map = self.global_peer_map.read().unwrap();
        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map.clone(),
            digest: Some(self.global_peer_map_digest.load()),
            full_snapshot: true,
            ..Default::default()
        })
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        Err(anyhow::anyhow!("not implemented").into())
    }
}

pub struct PeerCenterInstance {
    peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,

    client: Arc<PeerCenterBase>,
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
    global_peer_map_update_time: Arc<AtomicCell<Instant>>,
    source_update_times: Arc<RwLock<HashMap<PeerId, Instant>>>,
}

impl PeerCenterInstance {
    pub fn new(peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>) -> Self {
        PeerCenterInstance {
            peer_mgr: peer_mgr.clone(),
            client: Arc::new(PeerCenterBase::new(peer_mgr.clone())),
            global_peer_map: Arc::new(RwLock::new(GlobalPeerMap::default())),
            global_peer_map_digest: Arc::new(AtomicCell::new(Digest::default())),
            global_peer_map_update_time: Arc::new(AtomicCell::new(Instant::now())),
            source_update_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn init(&self) {
        self.client.init().await.unwrap();
        self.init_get_global_info_job().await;
        self.init_report_peers_job().await;
    }

    async fn init_get_global_info_job(&self) {
        struct Ctx {
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,
            global_peer_map_digest: Arc<AtomicCell<Digest>>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
            source_update_times: Arc<RwLock<HashMap<PeerId, Instant>>>,
        }

        let ctx = Arc::new(Ctx {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
            source_update_times: self.source_update_times.clone(),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                if ctx
                    .job_ctx
                    .global_peer_map_update_time
                    .load()
                    .elapsed()
                    .as_secs()
                    > 120
                {
                    ctx.job_ctx.global_peer_map_digest.store(Digest::default());
                }

                let ret = client
                    .get_global_peer_map(
                        BaseController::default(),
                        GetGlobalPeerMapRequest {
                            digest: ctx.job_ctx.global_peer_map_digest.load(),
                        },
                    )
                    .await;

                let Ok(resp) = ret else {
                    tracing::error!(
                        "get global info from center server got error result: {:?}",
                        ret
                    );
                    return Ok(10000);
                };

                let source_count = resp.global_peer_map.len();
                let delta_count = resp.deltas.len();
                let edge_count = resp
                    .global_peer_map
                    .values()
                    .map(|peer_info| peer_info.direct_peers.len())
                    .sum::<usize>();
                tracing::debug!(
                    digest = ?resp.digest,
                    source_count,
                    edge_count,
                    delta_count,
                    full_snapshot = resp.full_snapshot,
                    "received peer center map update"
                );

                apply_global_peer_map_response(
                    &ctx.job_ctx.global_peer_map,
                    &ctx.job_ctx.global_peer_map_digest,
                    &ctx.job_ctx.global_peer_map_update_time,
                    &ctx.job_ctx.source_update_times,
                    ctx.job_ctx.global_peer_map_digest.load(),
                    resp,
                );

                Ok(15000)
            })
            .await;
    }

    async fn init_report_peers_job(&self) {
        struct Ctx {
            peer_mgr: Arc<dyn PeerCenterPeerManagerTrait>,
            last_report: Mutex<PeerInfoForGlobalMap>,

            last_center_peer: AtomicCell<PeerId>,
            last_report_time: AtomicCell<Instant>,
        }
        let ctx = Arc::new(Ctx {
            peer_mgr: self.peer_mgr.clone(),
            last_report: Mutex::new(PeerInfoForGlobalMap::default()),
            last_center_peer: AtomicCell::new(PeerId::default()),
            last_report_time: AtomicCell::new(Instant::now()),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                let my_node_id = ctx.my_peer_id;
                let peers = ctx.job_ctx.peer_mgr.list_peers().await;
                let job_ctx = &ctx.job_ctx;

                // only report when:
                // 1. center peer changed
                // 2. last report time is more than 60 seconds
                // 3. peers changed
                if ctx.center_peer.load() == ctx.job_ctx.last_center_peer.load()
                    && job_ctx.last_report_time.load().elapsed().as_secs() < 60
                    && *job_ctx.last_report.lock().await == peers
                {
                    return Ok(5000);
                }

                let ret = client
                    .report_peers(
                        BaseController::default(),
                        ReportPeersRequest {
                            my_peer_id: my_node_id,
                            peer_infos: Some(peers.clone()),
                        },
                    )
                    .await;

                if ret.is_ok() {
                    ctx.job_ctx.last_center_peer.store(ctx.center_peer.load());
                    *ctx.job_ctx.last_report.lock().await = peers;
                    ctx.job_ctx.last_report_time.store(Instant::now());
                } else {
                    tracing::error!("report peers to center server got error result: {:?}", ret);
                }

                Ok(5000)
            })
            .await;
    }

    pub fn get_rpc_service(&self) -> PeerCenterInstanceService {
        PeerCenterInstanceService {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
        }
    }

    pub fn get_cost_calculator(&self) -> RouteCostCalculator {
        struct RouteCostCalculatorImpl {
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,

            global_peer_map_clone: GlobalPeerMap,
            source_update_times: Arc<RwLock<HashMap<PeerId, Instant>>>,
            source_update_times_clone: HashMap<PeerId, Instant>,

            last_update_time: AtomicCell<Instant>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
        }

        impl RouteCostCalculatorImpl {
            fn directed_cost(&self, src: PeerId, dst: PeerId) -> Option<i32> {
                self.global_peer_map_clone
                    .map
                    .get(&src)
                    .and_then(|src_peer_info| src_peer_info.direct_peers.get(&dst))
                    .map(|info| info.latency_ms)
            }

            fn directed_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
                let info = self
                    .global_peer_map_clone
                    .map
                    .get(&src)?
                    .direct_peers
                    .get(&dst)?;
                if info.tx_delivery_bps == 0 || info.speed_sample_ttl_ms == 0 {
                    return None;
                }
                let local_residence_ms = self
                    .source_update_times_clone
                    .get(&src)
                    .or_else(|| self.source_update_times_clone.get(&dst))
                    .map(|updated| u64::try_from(updated.elapsed().as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or_else(|| {
                        u64::try_from(
                            self.global_peer_map_update_time
                                .load()
                                .elapsed()
                                .as_millis(),
                        )
                        .unwrap_or(u64::MAX)
                    });
                let total_age_ms = info.speed_sample_age_ms.saturating_add(local_residence_ms);
                (total_age_ms < info.speed_sample_ttl_ms).then_some(info.tx_delivery_bps)
            }
        }

        impl RouteCostCalculatorInterface for RouteCostCalculatorImpl {
            fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
                if let Some(cost) = self.directed_cost(src, dst) {
                    return cost;
                }
                self.directed_cost(dst, src).unwrap_or(500)
            }

            fn calculate_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
                self.directed_delivery_bps(src, dst)
            }

            fn begin_update(&mut self) {
                let global_peer_map = self.global_peer_map.read().unwrap();
                self.global_peer_map_clone = global_peer_map.clone();
                self.source_update_times_clone = self.source_update_times.read().unwrap().clone();
            }

            fn end_update(&mut self) {
                self.last_update_time
                    .store(self.global_peer_map_update_time.load());
            }

            fn need_update(&self) -> bool {
                self.last_update_time.load() < self.global_peer_map_update_time.load()
            }
        }

        Box::new(RouteCostCalculatorImpl {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_clone: GlobalPeerMap::default(),
            source_update_times: self.source_update_times.clone(),
            source_update_times_clone: HashMap::new(),
            last_update_time: AtomicCell::new(
                self.global_peer_map_update_time.load() - Duration::from_secs(1),
            ),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
        })
    }
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        crate::rpc_service::control::ControlInstance::list_peers(self)
            .await
            .into()
    }

    fn my_peer_id(&self) -> PeerId {
        self.get_peer_map().my_peer_id()
    }

    fn get_global_ctx(&self) -> Arc<GlobalCtx> {
        self.get_peer_map().get_global_ctx()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.get_peer_rpc_mgr())
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        self.list_routes().await
    }
}

pub struct PeerMapWithPeerRpcManager {
    pub peer_map: Arc<PeerMap>,
    pub rpc_mgr: Arc<PeerRpcManager>,
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerMapWithPeerRpcManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        // TODO: currently latency between public server cannot be calculated because one public-server pair
        // has no connection between them. (hard to get latency from peer manager because it's hard to transfrom the peer id)
        // but it's fine because we don't want to too much traffic between public servers.
        let peers = self.peer_map.list_peers();
        let mut ret = PeerInfoForGlobalMap::default();
        for peer in peers {
            if let Some(conns) = self.peer_map.list_peer_conns(peer).await {
                let Some(info) = super::direct_peer_info_from_connections(&conns) else {
                    continue;
                };

                ret.direct_peers.insert(peer, info);
            }
        }

        ret
    }

    fn my_peer_id(&self) -> PeerId {
        self.peer_map.my_peer_id()
    }

    fn get_global_ctx(&self) -> Arc<GlobalCtx> {
        self.peer_map.get_global_ctx()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.rpc_mgr)
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        self.peer_map.list_route_infos().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        proto::peer_rpc::DirectConnectedPeerInfo,
        proto::{api::instance::Route, common::PeerFeatureFlag},
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    #[tokio::test]
    async fn local_center_jobs_share_the_registered_server() {
        let peer_mgr = create_mock_peer_manager().await;
        let base = PeerCenterBase::new(peer_mgr.clone());
        base.init().await.unwrap();
        let local = LocalPeerCenterClient {
            peer_mgr: peer_mgr.clone(),
            server: base.local_server.get().unwrap().clone(),
        };
        let peer_id = peer_mgr.my_peer_id();
        local
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: peer_id,
                    peer_infos: Some(PeerInfoForGlobalMap::default()),
                },
            )
            .await
            .unwrap();
        let response = base
            .local_server
            .get()
            .unwrap()
            .get_global_peer_map(
                local.controller().unwrap(),
                GetGlobalPeerMapRequest::default(),
            )
            .await
            .unwrap();
        assert!(response.global_peer_map.contains_key(&peer_id));
        assert!(
            local
                .report_peers(
                    BaseController::default(),
                    ReportPeersRequest {
                        my_peer_id: peer_id.wrapping_add(1),
                        peer_infos: Some(PeerInfoForGlobalMap::default()),
                    }
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn local_center_jobs_require_current_admin_eligibility() {
        let peer_mgr = create_mock_peer_manager().await;
        let local = LocalPeerCenterClient {
            peer_mgr: peer_mgr.clone(),
            server: PeerCenterServer::new(),
        };
        assert!(local.controller().is_ok());
        peer_mgr.get_global_ctx().set_hostname(format!(
            "{}test",
            crate::peers::PUBLIC_SERVER_HOSTNAME_PREFIX
        ));
        assert!(
            local
                .get_global_peer_map(
                    BaseController::default(),
                    GetGlobalPeerMapRequest::default()
                )
                .await
                .is_err()
        );
        assert!(
            local
                .server
                .get_global_peer_map(
                    BaseController::default(),
                    GetGlobalPeerMapRequest::default()
                )
                .await
                .is_err()
        );
    }
}
