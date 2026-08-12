use std::{
    collections::BinaryHeap,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use tokio::task::JoinSet;

use crate::{
    common::PeerId,
    proto::{
        peer_rpc::{
            DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
            GlobalPeerMap, PeerCenterRpc, PeerInfoForGlobalMap, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::Digest;

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub(crate) struct SrcDstPeerPair {
    src: PeerId,
    dst: PeerId,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerCenterInfoEntry {
    info: DirectConnectedPeerInfo,
    update_time: std::time::Instant,
}

#[derive(Debug, Default)]
struct PeerCenterServerData {
    global_peer_map: DashMap<SrcDstPeerPair, PeerCenterInfoEntry>,
    peer_report_time: DashMap<PeerId, std::time::Instant>,
    digest: AtomicCell<Digest>,
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    data: Arc<PeerCenterServerData>,
    tasks: Arc<JoinSet<()>>,
}

impl PeerCenterServer {
    pub fn new() -> Self {
        let data = Arc::new(PeerCenterServerData::default());
        let weak_data = Arc::downgrade(&data);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let Some(data) = weak_data.upgrade() else {
                    break;
                };
                PeerCenterServer::clean_outdated_peer_data(&data).await;
            }
        });

        PeerCenterServer {
            data,
            tasks: Arc::new(tasks),
        }
    }

    async fn clean_outdated_peer_data(data: &PeerCenterServerData) {
        data.peer_report_time.retain(|_, v| {
            std::time::Instant::now().duration_since(*v) < std::time::Duration::from_secs(180)
        });
        data.global_peer_map.retain(|_, v| {
            std::time::Instant::now().duration_since(v.update_time)
                < std::time::Duration::from_secs(180)
        });
    }

    fn calc_global_digest_data(data: &PeerCenterServerData) -> Digest {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let entries = data
            .global_peer_map
            .iter()
            .map(|entry| {
                let pair = entry.key().clone();
                let info = entry.value().info;
                (
                    pair,
                    info.latency_ms,
                    info.tx_delivery_bps,
                    info.tx_loss_ppm,
                    info.speed_sample_age_ms,
                    info.speed_sample_ttl_ms,
                    info.speed_probe_generation,
                )
            })
            .collect::<BinaryHeap<_>>()
            .into_sorted_vec();
        entries.hash(&mut hasher);
        hasher.finish()
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterServer {
    type Controller = BaseController;

    #[tracing::instrument()]
    async fn report_peers(
        &self,
        _: BaseController,
        req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        let my_peer_id = req.my_peer_id;
        let peers = req.peer_infos.unwrap_or_default();

        tracing::debug!("receive report_peers");

        let data = &self.data;
        data.peer_report_time
            .insert(my_peer_id, std::time::Instant::now());

        for (peer_id, peer_info) in peers.direct_peers {
            let pair = SrcDstPeerPair {
                src: my_peer_id,
                dst: peer_id,
            };
            let entry = PeerCenterInfoEntry {
                info: peer_info,
                update_time: std::time::Instant::now(),
            };
            data.global_peer_map.insert(pair, entry);
        }

        data.digest
            .store(PeerCenterServer::calc_global_digest_data(data));

        Ok(ReportPeersResponse::default())
    }

    #[tracing::instrument()]
    async fn get_global_peer_map(
        &self,
        _: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let digest = req.digest;

        let data = &self.data;
        if digest == data.digest.load() && digest != 0 {
            return Ok(GetGlobalPeerMapResponse::default());
        }

        let mut global_peer_map = GlobalPeerMap::default();
        for item in data.global_peer_map.iter() {
            let (pair, entry) = item.pair();
            let residence_ms =
                u64::try_from(entry.update_time.elapsed().as_millis()).unwrap_or(u64::MAX);
            let mut info = entry.info;
            info.speed_sample_age_ms = info.speed_sample_age_ms.saturating_add(residence_ms);
            global_peer_map
                .map
                .entry(pair.src)
                .or_insert_with(|| PeerInfoForGlobalMap {
                    direct_peers: Default::default(),
                })
                .direct_peers
                .insert(pair.dst, info);
        }

        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map,
            digest: Some(data.digest.load()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_clones_share_instance_data() {
        let server = PeerCenterServer::new();
        let server_clone = server.clone();

        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            100,
            DirectConnectedPeerInfo {
                latency_ms: 3,
                ..Default::default()
            },
        );

        server
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 99,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp = server_clone
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert_eq!(1, resp.global_peer_map.len());
        assert!(resp.global_peer_map[&99].direct_peers.contains_key(&100));
    }

    #[tokio::test]
    async fn independent_server_instances_do_not_share_data() {
        let server_a = PeerCenterServer::new();
        let server_b = PeerCenterServer::new();

        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            101,
            DirectConnectedPeerInfo {
                latency_ms: 5,
                ..Default::default()
            },
        );

        server_a
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 100,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp_a = server_a
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert_eq!(1, resp_a.global_peer_map.len());

        let resp_b = server_b
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert!(resp_b.global_peer_map.is_empty());
    }

    #[tokio::test]
    async fn server_preserves_directed_speed_and_adds_residence_age() {
        let server = PeerCenterServer::new();
        let forward = DirectConnectedPeerInfo {
            latency_ms: 70,
            tx_delivery_bps: 20_000_000,
            tx_loss_ppm: 1_000,
            speed_sample_age_ms: 11,
            speed_sample_ttl_ms: 90_000,
            speed_probe_generation: 7,
        };
        let reverse = DirectConnectedPeerInfo {
            latency_ms: 160,
            tx_delivery_bps: 5_000_000,
            tx_loss_ppm: 2_000,
            speed_sample_age_ms: 13,
            speed_sample_ttl_ms: 90_000,
            speed_probe_generation: 8,
        };

        for (source, destination, info) in [(1, 2, forward), (2, 1, reverse)] {
            let mut peers = PeerInfoForGlobalMap::default();
            peers.direct_peers.insert(destination, info);
            server
                .report_peers(
                    BaseController::default(),
                    ReportPeersRequest {
                        my_peer_id: source,
                        peer_infos: Some(peers),
                    },
                )
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let response = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        let actual_forward = &response.global_peer_map[&1].direct_peers[&2];
        let actual_reverse = &response.global_peer_map[&2].direct_peers[&1];
        assert_eq!(actual_forward.tx_delivery_bps, 20_000_000);
        assert_eq!(actual_reverse.tx_delivery_bps, 5_000_000);
        assert!(actual_forward.speed_sample_age_ms >= 21);
        assert!(actual_reverse.speed_sample_age_ms >= 23);
    }

    #[tokio::test]
    async fn delivery_change_updates_digest_without_a_topology_change() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            2,
            DirectConnectedPeerInfo {
                tx_delivery_bps: 5_000_000,
                speed_sample_ttl_ms: 90_000,
                ..Default::default()
            },
        );
        server
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers.clone()),
                },
            )
            .await
            .unwrap();
        let first = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();

        peers.direct_peers.get_mut(&2).unwrap().tx_delivery_bps = 20_000_000;
        server
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();
        let second = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest {
                    digest: first.digest.unwrap(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            second.global_peer_map[&1].direct_peers[&2].tx_delivery_bps,
            20_000_000
        );
        assert_ne!(first.digest, second.digest);
    }
}
