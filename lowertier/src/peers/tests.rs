use std::sync::Arc;
use std::time::Duration;

use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{
            NetworkIdentity, TrustedKeySource,
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
        },
        stats_manager::{LabelSet, LabelType, MetricName},
    },
    proto::api::instance::TrustedKeySourcePb,
    tunnel::{
        common::tests::wait_for_condition,
        packet_def::{PacketType, ZCPacket},
        ring::create_ring_tunnel_pair,
    },
};

use super::{
    create_packet_recv_chan,
    peer_conn::tests::set_secure_mode_cfg,
    peer_manager::{PeerManager, RouteAlgoType},
    peer_map::PeerMap,
    peer_session::{PeerSession, PeerSessionStore, SessionKey},
    relay_peer_map::RelayPeerMap,
    route_trait::NextHopPolicy,
};

fn credential_private_key_from_secret(secret: &str) -> x25519_dalek::StaticSecret {
    crate::peers::credential_manager::CredentialManager::private_key_from_bundle(secret)
        .expect("credential bundle contains a valid private key")
}

pub fn replace_stun_info_collector(
    peer_mgr: Arc<PeerManager>,
    udp_nat_type: crate::proto::common::NatType,
) {
    let collector = Box::new(crate::common::stun::MockStunInfoCollector { udp_nat_type });
    peer_mgr
        .get_global_ctx()
        .replace_stun_info_collector(collector);
}

pub async fn create_mock_peer_manager_with_mock_stun(
    udp_nat_type: crate::proto::common::NatType,
) -> Arc<PeerManager> {
    let peer_mgr = create_mock_peer_manager().await;
    let mut flags = peer_mgr.get_global_ctx().get_flags();
    flags.disable_upnp = true;
    peer_mgr.get_global_ctx().set_flags(flags);
    replace_stun_info_collector(peer_mgr.clone(), udp_nat_type);
    peer_mgr
}

pub async fn create_mock_peer_manager() -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        get_mock_global_ctx(),
        s,
    ));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn create_mock_peer_manager_with_name(network_name: String) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let g =
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(network_name, "".to_string())));
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

pub async fn create_mock_peer_manager_secure(
    network_name: String,
    network_secret: String,
) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let g =
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(network_name, network_secret)));
    set_secure_mode_cfg(&g, true);
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

fn set_private_mode(peer_mgr: &PeerManager, enabled: bool) {
    let global_ctx = peer_mgr.get_global_ctx();
    let mut flags = global_ctx.get_flags();
    flags.private_mode = enabled;
    global_ctx.set_flags(flags);
}

async fn connect_client_and_server(
    client: Arc<PeerManager>,
    server: Arc<PeerManager>,
) -> (Result<(), Error>, Result<(), Error>) {
    let (client_ring, server_ring) = create_ring_tunnel_pair();
    tokio::join!(
        {
            let client = client.clone();
            async move {
                client.add_client_tunnel(client_ring, false).await?;
                Ok(())
            }
        },
        {
            let server = server.clone();
            async move { server.add_tunnel_as_server(server_ring, true).await }
        }
    )
}

async fn wait_for_foreign_network(server: Arc<PeerManager>, network_name: &'static str) {
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .contains_key(network_name)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

async fn wait_for_foreign_network_peer_count_at_least(
    server: Arc<PeerManager>,
    network_name: &'static str,
    min_peer_count: usize,
) {
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .get(network_name)
                    .map(|entry| entry.peers.len() >= min_peer_count)
                    .unwrap_or(false)
            }
        },
        Duration::from_secs(10),
    )
    .await;
}

async fn wait_for_public_peers_empty(client: Arc<PeerManager>) {
    wait_for_condition(
        || {
            let client = client.clone();
            async move {
                client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            }
        },
        Duration::from_secs(5),
    )
    .await;
}

pub async fn connect_peer_manager(client: Arc<PeerManager>, server: Arc<PeerManager>) {
    let (a_ring, b_ring) = create_ring_tunnel_pair();
    let a_mgr_copy = client;
    tokio::spawn(async move {
        a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
    });
    let b_mgr_copy = server;
    tokio::spawn(async move {
        b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
    });
}

pub async fn wait_route_appear_with_cost(
    peer_mgr: Arc<PeerManager>,
    node_id: PeerId,
    cost: Option<i32>,
) -> Result<(), Error> {
    let now = std::time::Instant::now();
    while now.elapsed().as_secs() < 5 {
        let route = peer_mgr.list_routes().await;
        if route
            .iter()
            .any(|r| r.peer_id == node_id && (cost.is_none() || r.cost == cost.unwrap()))
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(Error::NotFound)
}

pub async fn wait_route_appear(
    peer_mgr: Arc<PeerManager>,
    target_peer: Arc<PeerManager>,
) -> Result<(), Error> {
    wait_route_appear_with_cost(peer_mgr.clone(), target_peer.my_peer_id(), None).await?;
    wait_route_appear_with_cost(target_peer, peer_mgr.my_peer_id(), None).await
}

fn metric_value(peer_mgr: &PeerManager, metric: MetricName, network_name: &str) -> u64 {
    peer_mgr
        .get_global_ctx()
        .stats_manager()
        .get_metric(
            metric,
            &LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string())),
        )
        .map(|metric| metric.value)
        .unwrap_or(0)
}

/// Helper: create a secure peer manager for a credential node from a signed
/// credential bundle. A bare private key cannot authenticate; the signed
/// certificate is mandatory.
pub async fn create_mock_peer_manager_credential(
    network_name: String,
    encoded_bundle: &str,
) -> Arc<PeerManager> {
    use crate::common::config::NetworkIdentity;
    use crate::peers::credential_manager::CredentialManager;
    use crate::proto::common::SecureModeConfig;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    let bundle = CredentialManager::parse_credential_bundle(encoded_bundle)
        .expect("credential bundle must be valid");
    assert_eq!(bundle.network_name, network_name);
    let private_key = credential_private_key_from_secret(encoded_bundle);
    let public = x25519_dalek::PublicKey::from(&private_key);

    let (s, _r) = create_packet_recv_chan();
    let g = get_mock_global_ctx_with_network(Some(
        NetworkIdentity::new_credential_with_root_fingerprint(
            network_name,
            &bundle.root_fingerprint,
        )
        .expect("credential root fingerprint must be valid"),
    ));
    g.config.set_secure_mode(Some(SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        credential_bundle: Some(encoded_bundle.to_owned()),
        credential_root_fingerprint: bundle.root_fingerprint,
        credential_certificate: bundle
            .certificate
            .map(|certificate| prost::Message::encode_to_vec(&certificate))
            .unwrap_or_default(),
    }));

    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

/// Helper: create a credential node whose bundle is signed by an unknown root,
/// so no admin in the test network trusts it.
pub async fn create_mock_peer_manager_unknown_credential(network_name: String) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let g = crate::common::global_ctx::tests::get_mock_credential_global_ctx(network_name);
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, g, s));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

mod speed_first {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use crate::{
        common::PeerId,
        peers::{
            peer_manager::PeerManager,
            route_trait::{NextHopPolicy, Route, RouteCostCalculatorInterface},
            speed_probe::SpeedSample,
        },
        tunnel::packet_def::{PacketType, ZCPacket},
    };

    use super::{
        connect_peer_manager, create_mock_peer_manager, wait_for_condition, wait_route_appear,
    };

    #[derive(Clone, Default)]
    struct DirectedMeasurements {
        latency_ms: HashMap<(PeerId, PeerId), i32>,
        delivery_bps: HashMap<(PeerId, PeerId), u64>,
    }

    impl RouteCostCalculatorInterface for DirectedMeasurements {
        fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
            self.latency_ms.get(&(src, dst)).copied().unwrap_or(1)
        }

        fn calculate_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
            self.delivery_bps.get(&(src, dst)).copied()
        }
    }

    async fn fully_connected_peers() -> [Arc<PeerManager>; 3] {
        let a = create_mock_peer_manager().await;
        let b = create_mock_peer_manager().await;
        let c = create_mock_peer_manager().await;
        connect_peer_manager(a.clone(), b.clone()).await;
        connect_peer_manager(b.clone(), c.clone()).await;
        connect_peer_manager(a.clone(), c.clone()).await;
        wait_route_appear(a.clone(), b.clone()).await.unwrap();
        wait_route_appear(b.clone(), c.clone()).await.unwrap();
        wait_route_appear(a.clone(), c.clone()).await.unwrap();
        [a, b, c]
    }

    fn asymmetric_measurements(a: PeerId, b: PeerId, c: PeerId) -> DirectedMeasurements {
        DirectedMeasurements {
            latency_ms: HashMap::from([
                ((a, c), 100),
                ((a, b), 40),
                ((b, c), 40),
                ((c, a), 70),
                ((c, b), 30),
                ((b, a), 30),
            ]),
            delivery_bps: HashMap::from([
                ((a, c), 5_000_000),
                ((a, b), 20_000_000),
                ((b, c), 25_000_000),
                ((c, a), 30_000_000),
                ((c, b), 10_000_000),
                ((b, a), 10_000_000),
            ]),
        }
    }

    fn speed_packet(from: PeerId, to: PeerId, flow_shard: u16) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"speed-flow");
        packet.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_speed_first(true)
            .set_flow_shard(flow_shard);
        packet
    }
}
