use std::sync::Arc;

use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{
            NetworkIdentity,
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
        },
    },
    tunnel::ring::create_ring_tunnel_pair,
};

use super::{
    create_packet_recv_chan,
    peer_conn::tests::set_secure_mode_cfg,
    peer_manager::{PeerManager, RouteAlgoType},
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
    let flags = peer_mgr.get_global_ctx().get_flags();
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
