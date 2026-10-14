//! Credential system integration tests
//!
//! These tests verify the credential-based authentication system where:
//! - Admin nodes hold network_secret and can generate credentials
//! - Credential nodes use X25519 keypairs to authenticate without network_secret
//! - Credentials can be revoked and propagate across the network

use base64::{Engine as _, prelude::BASE64_STANDARD};
use rand::rngs::OsRng;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    common::{
        config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
        global_ctx::GlobalCtxEvent,
    },
    instance::instance::Instance,
    peers::credential_manager::CredentialManager,
    proto::common::SecureModeConfig,
    tunnel::{common::tests::wait_for_condition, tcp::TcpTunnelConnector},
};

use super::{add_ns_to_bridge, create_netns, del_netns, drop_insts, ping_test};

fn generate_secure_mode_config() -> SecureModeConfig {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        credential_bundle: None,
        credential_root_fingerprint: Vec::new(),
        credential_certificate: Vec::new(),
    }
}

/// Prepare network namespaces for credential tests
/// Topology:
///   br_a (10.1.1.0/24): ns_adm (10.1.1.1), ns_c1 (10.1.1.2), ns_c2 (10.1.1.3), ns_c3 (10.1.1.4), ns_c4 (10.1.1.5)
///   br_b (10.1.2.0/24): ns_adm2 (10.1.2.1) - for multi-admin tests
/// Note: Using short names (max 15 chars for veth interfaces)
pub fn prepare_credential_network() {
    // Clean up any existing namespaces
    for ns in ["ns_adm", "ns_c1", "ns_c2", "ns_c3", "ns_c4", "ns_adm2"] {
        del_netns(ns);
    }

    // Create bridge br_a for admin and credentials
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "br_a"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["delbr", "br_a"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["addbr", "br_a"])
        .output()
        .expect("Failed to create br_a");
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "br_a", "up"])
        .output();

    // Create namespaces and add to bridge
    create_netns("ns_adm", "10.1.1.1/24", "fd11::1/64");
    add_ns_to_bridge("br_a", "ns_adm");

    create_netns("ns_c1", "10.1.1.2/24", "fd11::2/64");
    add_ns_to_bridge("br_a", "ns_c1");

    create_netns("ns_c2", "10.1.1.3/24", "fd11::3/64");
    add_ns_to_bridge("br_a", "ns_c2");

    // Create ns_c3 for relay tests (needs 4 nodes)
    create_netns("ns_c3", "10.1.1.4/24", "fd11::4/64");
    add_ns_to_bridge("br_a", "ns_c3");

    // Create ns_c4 for multi-admin credential tests (needs 5 nodes)
    create_netns("ns_c4", "10.1.1.5/24", "fd11::5/64");
    add_ns_to_bridge("br_a", "ns_c4");

    // Create bridge br_b for second admin (multi-admin tests)
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "br_b"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["delbr", "br_b"])
        .output();
    let _ = std::process::Command::new("brctl")
        .args(["addbr", "br_b"])
        .output()
        .expect("Failed to create br_b");
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "br_b", "up"])
        .output();

    create_netns("ns_adm2", "10.1.2.1/24", "fd12::1/64");
    add_ns_to_bridge("br_b", "ns_adm2");
}

fn build_credential_config(
    network_name: String,
    credential_secret: &str,
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let bundle = CredentialManager::parse_credential_bundle(credential_secret)
        .expect("credential RPC returns a signed bundle");
    let root_fingerprint = bundle.root_fingerprint.clone();
    let certificate = bundle
        .certificate
        .as_ref()
        .map(prost::Message::encode_to_vec)
        .unwrap_or_default();
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![]);
    config.set_network_identity(
        NetworkIdentity::new_credential_with_root_fingerprint(network_name, &root_fingerprint)
            .expect("credential bundle root fingerprint is 32 bytes"),
    );
    config.set_secure_mode(Some(SecureModeConfig {
        enabled: true,
        local_private_key: None,
        local_public_key: None,
        credential_bundle: Some(credential_secret.to_owned()),
        credential_root_fingerprint: root_fingerprint,
        credential_certificate: certificate,
    }));

    config
}

/// Helper: Create credential node config with generated credential
async fn create_credential_config(
    admin_inst: &Instance,
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let (_cred_id, cred_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential(vec![], false, vec![], Duration::from_secs(3600))
        .unwrap();

    build_credential_config(
        admin_inst
            .get_global_ctx()
            .get_network_identity()
            .network_name
            .clone(),
        &cred_secret,
        inst_name,
        ns,
        ipv4,
        ipv6,
    )
}

fn create_credential_config_from_secret(
    network_name: String,
    credential_secret: &str,
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    build_credential_config(network_name, credential_secret, inst_name, ns, ipv4, ipv6)
}

/// Helper: Create admin node config
fn create_admin_config(
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "tcp://0.0.0.0:11010".parse().unwrap(),
    ]);
    config.set_network_identity(NetworkIdentity::new(
        "test_network".to_string(),
        "test_secret".to_string(),
    ));
    config.set_secure_mode(Some(generate_secure_mode_config()));

    config
}

fn create_shared_config(
    inst_name: &str,
    ns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(ns.map(|s| s.to_owned()));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec![
        "tcp://0.0.0.0:11010".parse().unwrap(),
        "tcp://0.0.0.0:11010".parse().unwrap(),
    ]);
    config.set_network_identity(NetworkIdentity::new(
        "shared_network".to_string(),
        "".to_string(),
    ));
    config.set_secure_mode(Some(generate_secure_mode_config()));
    config
}

async fn wait_ping_reachability(src_ns: &str, dst_ip: &str, reachable: bool, timeout: Duration) {
    wait_for_condition(
        || async {
            let ping_result = ping_test(src_ns, dst_ip, None).await;
            if reachable { ping_result } else { !ping_result }
        },
        timeout,
    )
    .await;
}

async fn assert_shared_visibility_stable(
    admin_a_inst: &Instance,
    admin_c_inst: &Instance,
    peer_id: u32,
    peer_ip: &str,
    should_exist: bool,
    label: &str,
) {
    for _ in 0..5 {
        let admin_a_routes = admin_a_inst.get_peer_manager().list_routes().await;
        let admin_c_routes = admin_c_inst.get_peer_manager().list_routes().await;
        let admin_a_has = admin_a_routes.iter().any(|r| r.peer_id == peer_id);
        let admin_c_has = admin_c_routes.iter().any(|r| r.peer_id == peer_id);
        if should_exist {
            assert!(
                admin_a_has || admin_c_has,
                "{} should exist via shared path but routes are admin_a={:?} admin_c={:?}",
                label,
                admin_a_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
                admin_c_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
            );
        } else {
            assert!(
                !admin_a_has && !admin_c_has,
                "{} should be absent via shared path but routes are admin_a={:?} admin_c={:?}",
                label,
                admin_a_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
                admin_c_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
            );
        }

        let ping_from_admin_a = ping_test("ns_adm", peer_ip, None).await;
        let ping_from_admin_c = ping_test("ns_c3", peer_ip, None).await;
        if should_exist {
            assert!(ping_from_admin_a, "admin_a should reach {}", label);
            assert!(ping_from_admin_c, "admin_c should reach {}", label);
        } else {
            assert!(!ping_from_admin_a, "admin_a should not reach {}", label);
            assert!(!ping_from_admin_c, "admin_c should not reach {}", label);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_stable_single_visible_peer_on_admins(
    admin_a_inst: &Instance,
    admin_c_inst: &Instance,
    peer_a_id: u32,
    peer_b_id: u32,
    timeout: Duration,
) -> u32 {
    let start = std::time::Instant::now();
    let mut stable_winner = None;
    let mut stable_samples = 0;

    loop {
        let admin_a_routes = admin_a_inst.get_peer_manager().list_routes().await;
        let admin_c_routes = admin_c_inst.get_peer_manager().list_routes().await;

        let admin_a_has_a = admin_a_routes.iter().any(|r| r.peer_id == peer_a_id);
        let admin_a_has_b = admin_a_routes.iter().any(|r| r.peer_id == peer_b_id);
        let admin_c_has_a = admin_c_routes.iter().any(|r| r.peer_id == peer_a_id);
        let admin_c_has_b = admin_c_routes.iter().any(|r| r.peer_id == peer_b_id);

        let current_winner = if admin_a_has_a && admin_c_has_a && !admin_a_has_b && !admin_c_has_b {
            Some(peer_a_id)
        } else if admin_a_has_b && admin_c_has_b && !admin_a_has_a && !admin_c_has_a {
            Some(peer_b_id)
        } else {
            None
        };

        println!(
            "single-visible routes: a={:?} c={:?} winner={:?}",
            admin_a_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
            admin_c_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
            current_winner
        );

        match current_winner {
            Some(winner) if stable_winner == Some(winner) => stable_samples += 1,
            Some(winner) => {
                stable_winner = Some(winner);
                stable_samples = 1;
            }
            None => {
                stable_winner = None;
                stable_samples = 0;
            }
        }

        if stable_samples >= 3 {
            return stable_winner.unwrap();
        }

        assert!(
            start.elapsed() < timeout,
            "timed out waiting for a stable single visible peer on both admins: a={:?} c={:?}",
            admin_a_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>(),
            admin_c_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Test 1: Basic credential node connectivity
/// Topology: Admin ← Credential
/// Verifies that a credential node can connect to an admin node and appears in routes
#[tokio::test]
#[serial_test::serial]
async fn credential_basic_connectivity() {
    prepare_credential_network();

    // Create admin node
    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    // Create credential node
    let cred_config = create_credential_config(
        &admin_inst,
        "cred",
        Some("ns_c1"),
        "10.144.144.2",
        "fd00::2/64",
    )
    .await;
    let mut cred_inst = Instance::new(cred_config);
    cred_inst.run().await.unwrap();

    // Credential connects to admin
    cred_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred_peer_id = cred_inst.peer_id();
    let admin_peer_id = admin_inst.peer_id();
    println!(
        "Admin peer_id: {}, Credential peer_id: {}",
        admin_peer_id, cred_peer_id
    );

    // Wait a bit for connection attempt
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check peers and connections
    let admin_peers = admin_inst.get_peer_manager().get_peer_map().list_peers();
    let cred_peers = cred_inst.get_peer_manager().get_peer_map().list_peers();
    println!("Admin peers: {:?}", admin_peers);
    println!("Credential peers: {:?}", cred_peers);

    // Wait for credential to appear in admin's route table
    wait_for_condition(
        || async {
            let routes = admin_inst.get_peer_manager().list_routes().await;
            let cred_routes = cred_inst.get_peer_manager().list_routes().await;
            let admin_peers = admin_inst.get_peer_manager().get_peer_map().list_peers();
            let cred_peers = cred_inst.get_peer_manager().get_peer_map().list_peers();
            println!(
                "Admin peers: {:?}, routes: {:?}",
                admin_peers,
                routes
                    .iter()
                    .map(|r| (r.peer_id, r.ipv4_addr))
                    .collect::<Vec<_>>()
            );
            println!(
                "Credential peers: {:?}, routes: {:?}",
                cred_peers,
                cred_routes
                    .iter()
                    .map(|r| (r.peer_id, r.ipv4_addr))
                    .collect::<Vec<_>>()
            );
            routes.iter().any(|r| r.peer_id == cred_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;

    // Verify connectivity
    wait_for_condition(
        || async { ping_test("ns_adm", "10.144.144.2", None).await },
        Duration::from_secs(10),
    )
    .await;

    wait_for_condition(
        || async { ping_test("ns_c1", "10.144.144.1", None).await },
        Duration::from_secs(10),
    )
    .await;

    drop_insts(vec![admin_inst, cred_inst]).await;
}

/// Test: A non-reusable credential only allows one peer at a time.
#[tokio::test]
#[serial_test::serial]
async fn credential_non_reusable_allows_only_one_peer() {
    prepare_credential_network();

    let admin_config = create_admin_config("admin", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_inst = Instance::new(admin_config);
    admin_inst.run().await.unwrap();

    let (_cred_id, cred_secret) = admin_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential_with_options(
            vec![],
            false,
            vec![],
            Duration::from_secs(3600),
            None,
            false,
        )
        .unwrap();

    let network_name = admin_inst
        .get_global_ctx()
        .get_network_identity()
        .network_name
        .clone();
    let cred1_config = create_credential_config_from_secret(
        network_name.clone(),
        &cred_secret,
        "cred1_single",
        Some("ns_c1"),
        "10.144.144.2",
        "fd00::2/64",
    );
    let cred2_config = create_credential_config_from_secret(
        network_name,
        &cred_secret,
        "cred2_single",
        Some("ns_c2"),
        "10.144.144.3",
        "fd00::3/64",
    );

    let mut cred1_inst = Some(Instance::new(cred1_config));
    cred1_inst.as_mut().unwrap().run().await.unwrap();
    cred1_inst
        .as_ref()
        .unwrap()
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred1_peer_id = cred1_inst.as_ref().unwrap().peer_id();
    wait_for_condition(
        || async {
            admin_inst
                .get_peer_manager()
                .list_routes()
                .await
                .iter()
                .any(|r| r.peer_id == cred1_peer_id)
        },
        Duration::from_secs(10),
    )
    .await;
    wait_ping_reachability("ns_adm", "10.144.144.2", true, Duration::from_secs(10)).await;

    let mut cred2_inst = Some(Instance::new(cred2_config));
    cred2_inst.as_mut().unwrap().run().await.unwrap();
    cred2_inst
        .as_ref()
        .unwrap()
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let cred2_peer_id = cred2_inst.as_ref().unwrap().peer_id();
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The non-reusable credential owner is elected by lowest peer_id, so either cred1 or cred2
    // may win. Determine the winner and loser dynamically.
    let admin_routes = admin_inst.get_peer_manager().list_routes().await;
    let (winner_peer_id, winner_ip, winner_inst, loser_peer_id, loser_ip, loser_inst) =
        if admin_routes.iter().any(|r| r.peer_id == cred1_peer_id) {
            (
                cred1_peer_id,
                "10.144.144.2",
                &mut cred1_inst,
                cred2_peer_id,
                "10.144.144.3",
                &mut cred2_inst,
            )
        } else if admin_routes.iter().any(|r| r.peer_id == cred2_peer_id) {
            (
                cred2_peer_id,
                "10.144.144.3",
                &mut cred2_inst,
                cred1_peer_id,
                "10.144.144.2",
                &mut cred1_inst,
            )
        } else {
            panic!(
                "neither credential peer is present in routes: {:?}",
                admin_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
            );
        };

    for _ in 0..5 {
        let admin_routes = admin_inst.get_peer_manager().list_routes().await;
        assert!(
            admin_routes.iter().any(|r| r.peer_id == winner_peer_id),
            "winning credential peer should remain present: {:?}",
            admin_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
        );
        assert!(
            ping_test("ns_adm", winner_ip, None).await,
            "admin should still reach the winning credential peer"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    for _ in 0..5 {
        let admin_routes = admin_inst.get_peer_manager().list_routes().await;
        assert!(
            !admin_routes.iter().any(|r| r.peer_id == loser_peer_id),
            "losing credential peer should not appear in routes: {:?}",
            admin_routes.iter().map(|r| r.peer_id).collect::<Vec<_>>()
        );
        assert!(
            !ping_test("ns_adm", loser_ip, None).await,
            "admin should not reach the losing credential peer"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    drop_insts(vec![winner_inst.take().unwrap()]).await;

    wait_for_condition(
        || async {
            let routes = admin_inst.get_peer_manager().list_routes().await;
            !routes.iter().any(|r| r.peer_id == winner_peer_id)
                && routes.iter().any(|r| r.peer_id == loser_peer_id)
        },
        Duration::from_secs(20),
    )
    .await;
    wait_ping_reachability("ns_adm", loser_ip, true, Duration::from_secs(20)).await;

    drop_insts(vec![admin_inst, loser_inst.take().unwrap()]).await;
}

#[tokio::test]
#[serial_test::serial]
async fn credential_non_reusable_across_two_admins_allows_only_one_peer() {
    prepare_credential_network();

    let admin_a_config =
        create_admin_config("admin_a", Some("ns_adm"), "10.144.144.1", "fd00::1/64");
    let mut admin_a_inst = Instance::new(admin_a_config);
    admin_a_inst.run().await.unwrap();

    let shared_b_config =
        create_shared_config("shared_b", Some("ns_c1"), "10.144.144.2", "fd00::2/64");
    let mut shared_b_inst = Instance::new(shared_b_config);
    shared_b_inst.run().await.unwrap();

    let admin_c_config =
        create_admin_config("admin_c", Some("ns_c3"), "10.144.144.4", "fd00::4/64");
    let mut admin_c_inst = Instance::new(admin_c_config);
    admin_c_inst.run().await.unwrap();

    admin_a_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.2:11010".parse().unwrap(),
        ));
    admin_c_inst
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.2:11010".parse().unwrap(),
        ));

    let admin_c_peer_id = admin_c_inst.peer_id();
    wait_for_condition(
        || async {
            let a_routes = admin_a_inst.get_peer_manager().list_routes().await;
            let c_routes = admin_c_inst.get_peer_manager().list_routes().await;
            a_routes.iter().any(|r| r.peer_id == admin_c_peer_id)
                || c_routes.iter().any(|r| r.peer_id == admin_a_inst.peer_id())
        },
        Duration::from_secs(10),
    )
    .await;

    let (_cred_id, cred_secret) = admin_a_inst
        .get_global_ctx()
        .get_credential_manager()
        .generate_credential_with_options(
            vec![],
            false,
            vec![],
            Duration::from_secs(3600),
            None,
            false,
        )
        .unwrap();
    admin_a_inst
        .get_global_ctx()
        .issue_event(GlobalCtxEvent::CredentialChanged);

    let network_name = admin_a_inst
        .get_global_ctx()
        .get_network_identity()
        .network_name
        .clone();
    let cred_left_config = create_credential_config_from_secret(
        network_name.clone(),
        &cred_secret,
        "cred_left",
        Some("ns_c2"),
        "10.144.144.5",
        "fd00::5/64",
    );
    let cred_right_config = create_credential_config_from_secret(
        network_name,
        &cred_secret,
        "cred_right",
        Some("ns_c4"),
        "10.144.144.6",
        "fd00::6/64",
    );

    let mut cred_left_inst = Some(Instance::new(cred_left_config));
    cred_left_inst.as_mut().unwrap().run().await.unwrap();
    cred_left_inst
        .as_ref()
        .unwrap()
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.1:11010".parse().unwrap(),
        ));

    let mut cred_right_inst = Some(Instance::new(cred_right_config));
    cred_right_inst.as_mut().unwrap().run().await.unwrap();
    cred_right_inst
        .as_ref()
        .unwrap()
        .get_conn_manager()
        .add_connector(TcpTunnelConnector::new(
            "tcp://10.1.1.4:11010".parse().unwrap(),
        ));

    let cred_left_peer_id = cred_left_inst.as_ref().unwrap().peer_id();
    let cred_right_peer_id = cred_right_inst.as_ref().unwrap().peer_id();
    let winner_peer_id = wait_stable_single_visible_peer_on_admins(
        &admin_a_inst,
        &admin_c_inst,
        cred_left_peer_id,
        cred_right_peer_id,
        Duration::from_secs(60),
    )
    .await;

    let (winner_peer_id, winner_ip, loser_peer_id, loser_ip) =
        if winner_peer_id == cred_left_peer_id {
            (
                cred_left_peer_id,
                "10.144.144.5",
                cred_right_peer_id,
                "10.144.144.6",
            )
        } else {
            (
                cred_right_peer_id,
                "10.144.144.6",
                cred_left_peer_id,
                "10.144.144.5",
            )
        };

    wait_ping_reachability("ns_adm", winner_ip, true, Duration::from_secs(20)).await;
    wait_ping_reachability("ns_c3", winner_ip, true, Duration::from_secs(20)).await;
    wait_ping_reachability("ns_adm", loser_ip, false, Duration::from_secs(5)).await;
    wait_ping_reachability("ns_c3", loser_ip, false, Duration::from_secs(5)).await;

    assert_shared_visibility_stable(
        &admin_a_inst,
        &admin_c_inst,
        winner_peer_id,
        winner_ip,
        true,
        "winning credential",
    )
    .await;
    assert_shared_visibility_stable(
        &admin_a_inst,
        &admin_c_inst,
        loser_peer_id,
        loser_ip,
        false,
        "losing credential",
    )
    .await;

    if winner_peer_id == cred_left_peer_id {
        drop_insts(vec![cred_left_inst.take().unwrap()]).await;
    } else {
        drop_insts(vec![cred_right_inst.take().unwrap()]).await;
    }

    wait_for_condition(
        || async {
            let admin_a_routes = admin_a_inst.get_peer_manager().list_routes().await;
            let admin_c_routes = admin_c_inst.get_peer_manager().list_routes().await;
            admin_a_routes.iter().any(|r| r.peer_id == loser_peer_id)
                && admin_c_routes.iter().any(|r| r.peer_id == loser_peer_id)
                && !admin_a_routes.iter().any(|r| r.peer_id == winner_peer_id)
                && !admin_c_routes.iter().any(|r| r.peer_id == winner_peer_id)
        },
        Duration::from_secs(60),
    )
    .await;

    wait_ping_reachability("ns_adm", loser_ip, true, Duration::from_secs(20)).await;
    wait_ping_reachability("ns_c3", loser_ip, true, Duration::from_secs(20)).await;
    wait_ping_reachability("ns_adm", winner_ip, false, Duration::from_secs(5)).await;
    wait_ping_reachability("ns_c3", winner_ip, false, Duration::from_secs(5)).await;

    assert_shared_visibility_stable(
        &admin_a_inst,
        &admin_c_inst,
        loser_peer_id,
        loser_ip,
        true,
        "failover credential",
    )
    .await;
    assert_shared_visibility_stable(
        &admin_a_inst,
        &admin_c_inst,
        winner_peer_id,
        winner_ip,
        false,
        "removed winning credential",
    )
    .await;

    if winner_peer_id == cred_left_peer_id {
        drop_insts(vec![
            admin_a_inst,
            shared_b_inst,
            admin_c_inst,
            cred_right_inst.take().unwrap(),
        ])
        .await;
    } else {
        drop_insts(vec![
            admin_a_inst,
            shared_b_inst,
            admin_c_inst,
            cred_left_inst.take().unwrap(),
        ])
        .await;
    }
}
