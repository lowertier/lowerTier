// peer_center is used to collect peer info into one peer node.
// the center node is selected with the following rules:
// 1. has smallest peer id
// 2. TODO: has allow_to_be_center peer feature
// peer center is not guaranteed to be stable and can be changed when peer enter or leave.
// it's used to reduce the cost to exchange infos between peers.

use std::collections::BTreeMap;

use crate::proto::api::instance::PeerInfo;
use crate::proto::peer_rpc::{DirectConnectedPeerInfo, PeerInfoForGlobalMap};

pub mod instance;
mod server;

#[derive(thiserror::Error, Debug, serde::Deserialize, serde::Serialize)]
pub enum Error {
    #[error("Digest not match, need provide full peer info to center server.")]
    DigestMismatch,
    #[error("Not center server")]
    NotCenterServer,
    #[error("Instance shutdown")]
    Shutdown,
}

pub type Digest = u64;

fn direct_peer_info_from_connections(
    connections: &[crate::proto::api::instance::PeerConnInfo],
) -> Option<DirectConnectedPeerInfo> {
    let selected_speed = connections
        .iter()
        .filter(|connection| connection.tx_delivery_bps.unwrap_or_default() > 0)
        .filter(|connection| {
            connection.speed_sample_age_ms.unwrap_or(u64::MAX)
                < connection.speed_sample_ttl_ms.unwrap_or_default()
        })
        .max_by_key(|connection| {
            (
                connection.tx_delivery_bps.unwrap_or_default(),
                std::cmp::Reverse(
                    connection
                        .stats
                        .as_ref()
                        .map(|stats| stats.latency_us)
                        .unwrap_or(u64::MAX),
                ),
                std::cmp::Reverse(&connection.conn_id),
            )
        });
    let selected = selected_speed.or_else(|| {
        connections.iter().min_by_key(|connection| {
            connection
                .stats
                .as_ref()
                .map(|stats| stats.latency_us)
                .unwrap_or(u64::MAX)
        })
    })?;
    let latency_us = selected.stats.as_ref()?.latency_us;
    Some(DirectConnectedPeerInfo {
        latency_ms: std::cmp::max(1, (latency_us / 1_000).min(i32::MAX as u64) as i32),
        tx_delivery_bps: selected.tx_delivery_bps.unwrap_or_default(),
        tx_loss_ppm: selected.tx_loss_ppm.unwrap_or_default(),
        speed_sample_age_ms: selected.speed_sample_age_ms.unwrap_or_default(),
        speed_sample_ttl_ms: selected.speed_sample_ttl_ms.unwrap_or_default(),
        speed_probe_generation: selected.speed_probe_generation.unwrap_or_default(),
    })
}

impl From<Vec<PeerInfo>> for PeerInfoForGlobalMap {
    fn from(peers: Vec<PeerInfo>) -> Self {
        let mut peer_map = BTreeMap::new();
        for peer in peers {
            let Some(dp_info) = direct_peer_info_from_connections(&peer.conns) else {
                continue;
            };

            // sort conn info so hash result is stable
            peer_map.insert(peer.peer_id, dp_info);
        }
        PeerInfoForGlobalMap {
            direct_peers: peer_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::api::instance::{PeerConnInfo, PeerConnStats};

    use super::*;

    fn connection(id: &str, latency_us: u64, delivery_bps: Option<u64>) -> PeerConnInfo {
        PeerConnInfo {
            conn_id: id.to_string(),
            stats: Some(PeerConnStats {
                latency_us,
                ..Default::default()
            }),
            tx_delivery_bps: delivery_bps,
            tx_loss_ppm: delivery_bps.map(|_| 100),
            speed_sample_age_ms: delivery_bps.map(|_| 1_000),
            speed_sample_ttl_ms: delivery_bps.map(|_| 90_000),
            speed_probe_generation: delivery_bps.map(|_| 9),
            ..Default::default()
        }
    }

    #[test]
    fn global_map_reports_the_highest_fresh_directed_delivery_connection() {
        let peers = vec![PeerInfo {
            peer_id: 2,
            conns: vec![
                connection("low-latency", 5_000, Some(4_000_000)),
                connection("high-speed", 50_000, Some(20_000_000)),
                connection("expired", 1_000, Some(40_000_000)),
            ],
            ..Default::default()
        }];
        let mut expired = peers.clone();
        expired[0].conns[2].speed_sample_age_ms = Some(90_000);

        let global = PeerInfoForGlobalMap::from(expired);
        let info = &global.direct_peers[&2];

        assert_eq!(info.tx_delivery_bps, 20_000_000);
        assert_eq!(info.latency_ms, 50);
        assert_eq!(info.speed_probe_generation, 9);
    }
}
