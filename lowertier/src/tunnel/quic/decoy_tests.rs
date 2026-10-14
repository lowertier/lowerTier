//! Local-only passthrough security and delivery tests. The DNS name is SNI,
//! never a network destination; every socket is explicitly loopback-bound.
use super::*;
use crate::common::{config::NetworkIdentity, global_ctx::tests::get_mock_global_ctx_with_network};
use tokio_util::task::AbortOnDropHandle;

const HOST: &str = "challenges.cloudflare.com";

async fn listener(upstream: SocketAddr) -> QuicTunnelListener {
    let context = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        "decoy-limits".to_owned(),
        "decoy-limits-test-network-secret".to_owned(),
    )));
    let mut flags = context.get_flags();
    flags.camouflage_config_mut().server_name = HOST.to_owned();
    flags
        .camouflage_config_mut()
        .set_decoy_upstream(upstream.to_string());
    flags.camouflage_config_mut().admission_secret =
        "decoy-limits-test-admission-secret".to_owned();
    context.set_flags(flags);
    let mut listener = QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), context);
    listener.listen().await.unwrap();
    listener
}

fn packet(kind: u8, dcid: &[u8], scid: &[u8], length: usize) -> Vec<u8> {
    let mut data = vec![0xc0 | (kind << 4), 0, 0, 0, 1, dcid.len() as u8];
    data.extend_from_slice(dcid);
    data.push(scid.len() as u8);
    data.extend_from_slice(scid);
    data.extend_from_slice(&[0, 0x40, 32]);
    data.resize(length, 0);
    data
}

#[tokio::test]
async fn unadmitted_decoy_routes_cannot_exhaust_authenticated_route_capacity() {
    let runtime = default_runtime().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let public = runtime.wrap_udp_socket(socket).unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let secret = b"decoy-route-capacity-test-secret";
    let decoy = QuicDecoySocket::new(
        public,
        upstream.local_addr().unwrap(),
        Arc::from(secret.as_slice()),
        None,
        None,
    );
    let initial = packet(0, b"original", b"clientid", 1200);
    for port in 10000..15000 {
        assert_eq!(
            decoy.route(SocketAddr::from(([127, 0, 0, 1], port)), &initial),
            Some(QuicSocketRoute::Decoy)
        );
    }
    // No relay admission took place. Dropping pending packets must leave no
    // cached route, even after more than MAX_QUIC_DECOY_FLOWS attempted tuples.
    assert!(decoy.routes.is_empty());
    let marked = packet(
        0,
        &quic_routing_cid(secret, SystemTime::now()),
        b"clientid",
        1200,
    );
    assert_eq!(
        decoy.route("127.0.0.1:16000".parse().unwrap(), &marked),
        Some(QuicSocketRoute::Local)
    );
    assert_eq!(decoy.routes.len(), 1);
    // A new tuple can reach Quinn's CID lookup without consuming a route slot.
    assert_eq!(
        decoy.route("127.0.0.1:16002".parse().unwrap(), &[0x40; 64]),
        Some(QuicSocketRoute::Local)
    );
    assert_eq!(decoy.routes.len(), 1);

    let mut mixed = vec![0x40; 1200];
    mixed.extend_from_slice(&initial);
    let local_len = decoy.route_received(
        quinn::udp::RecvMeta {
            addr: "127.0.0.1:16003".parse().unwrap(),
            len: mixed.len(),
            stride: 1200,
            ecn: None,
            dst_ip: None,
        },
        &mut mixed,
    );
    assert_eq!(local_len, 1200);
    assert!(mixed[..local_len].iter().all(|byte| *byte == 0x40));
    assert_eq!(decoy.decoy_tx.capacity(), 63);
    assert_eq!(decoy.routes.len(), 1);

    // A pending decoy packet may lose the race to a marked client. Even if
    // admission then fails, the pending packet must not erase that local route.
    let client: SocketAddr = "127.0.0.42:16001".parse().unwrap();
    decoy.routes.insert(
        client,
        QuicSocketRouteEntry {
            route: QuicSocketRoute::Local,
            last_seen_seconds: AtomicU64::new(QuicDecoySocket::now_seconds()),
        },
    );
    let limiter = crate::tunnel::decoy::process_limiter();
    let _permits: Vec<_> = (0..8)
        .map(|_| limiter.admit(client.ip()).unwrap())
        .collect();
    decoy
        .decoy_tx
        .send(QuicDecoyPacket {
            client,
            server_ip: None,
            bytes: Bytes::from(initial),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while decoy.decoy_tx.capacity() != 64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        decoy.routes.get(&client).unwrap().route,
        QuicSocketRoute::Local
    );
}

#[tokio::test]
async fn udp_decoy_drops_non_quic_and_cannot_amplify_without_cid_return() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = listener(upstream.local_addr().unwrap()).await;
        let public = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = vec![0; 65535];
        client.send_to(b"not QUIC", public).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buffer))
                .await
                .is_err()
        );

        let initial = packet(0, b"original", b"clientid", 1200);
        client.send_to(&initial, public).await.unwrap();
        let (length, relay) = upstream.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], initial);
        // Too large even though the byte-rate buckets still have ample burst.
        upstream.send_to(&vec![0xa5; 2400], relay).await.unwrap();
        let response = packet(0, b"clientid", b"serverid", 1200);
        upstream.send_to(&response, relay).await.unwrap();
        upstream.send_to(&response, relay).await.unwrap();
        let (length, source) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(source, public);
        assert_eq!(&buffer[..length], response);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buffer))
                .await
                .is_err()
        );

        // Wrong CID cannot lift the cap. Its bytes only earn equivalent credit.
        client
            .send_to(&packet(2, b"wrongcid", b"clientid", 100), public)
            .await
            .unwrap();
        upstream.recv_from(&mut buffer).await.unwrap();
        upstream.send_to(&vec![0xa5; 2400], relay).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buffer))
                .await
                .is_err()
        );

        // Echoing the CID actually delivered on this tuple provides return-path
        // evidence; subsequent larger responses remain subject to rate limits.
        client
            .send_to(&packet(2, b"serverid", b"clientid", 100), public)
            .await
            .unwrap();
        upstream.recv_from(&mut buffer).await.unwrap();
        let large = vec![0xa5; 2400];
        upstream.send_to(&large, relay).await.unwrap();
        let (length, _) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], large);

        // A new source port on the same IP cannot borrow this authorization.
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        other.send_to(&initial, public).await.unwrap();
        let (_, other_relay) = upstream.recv_from(&mut buffer).await.unwrap();
        assert_ne!(other_relay, relay);
        upstream.send_to(&large, other_relay).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), other.recv_from(&mut buffer))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_decoy_large_certificate_and_body_are_lossless_and_rate_limited() {
    for trial in 0..3 {
        tokio::time::timeout(Duration::from_secs(30), async {
            let directory = tempfile::tempdir().unwrap();
            let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
            std::fs::write(directory.path().join("index.html"), &payload).unwrap();
            // Exercise multiple server handshake datagrams under the 1x bound.
            // This is a test certificate, not a certificate for the public host.
            let cert = rcgen::generate_simple_self_signed(vec![HOST.to_owned(); 128]).unwrap();
            assert!(cert.serialize_der().unwrap().len() > 3000);
            let cert_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
            std::fs::write(&key_path, cert.serialize_private_key_pem()).unwrap();
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = HOST.to_owned();
            flags.camouflage_config_mut().tls_cert = cert_path.to_str().unwrap().to_owned();
            flags.camouflage_config_mut().tls_key = key_path.to_str().unwrap().to_owned();
            let upstream = Endpoint::server(server_config(&flags).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
            let listener = listener(upstream.local_addr().unwrap()).await;
            let public = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            let root = directory.path().to_path_buf();
            let (connection_tx, connection_rx) = oneshot::channel();
            let _server = AbortOnDropHandle::new(tokio::spawn(async move {
                let connection = upstream.accept().await.unwrap().await.unwrap();
                connection_tx.send(connection.clone()).unwrap();
                if let Ok(ConnectIpAccept::Website(website)) =
                    accept_connect_ip_request(&connection, None, Some(root.clone())).await
                {
                    serve_http3_requests(website.connection, Some(root), Some(website.first)).await;
                }
            }));

            // The test client explicitly uses the local ephemeral-identity mode.
            let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(client_config(&gen_default_flags()).unwrap());
            let start = Instant::now();
            let connection = client.connect(public, HOST).unwrap().await.unwrap();
            let handshake = start.elapsed();
            let observed = connection.clone();
            let (mut driver, mut requests) = h3::client::builder()
                .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(h3_quinn::Connection::new(connection))
                .await.unwrap();
            let _driver = AbortOnDropHandle::new(tokio::spawn(async move { let _ = driver.wait_idle().await; }));
            let mut stream = requests.send_request(http::Request::get(format!("https://{HOST}/")).body(()).unwrap()).await.unwrap();
            stream.finish().await.unwrap();
            assert_eq!(stream.recv_response().await.unwrap().status(), http::StatusCode::OK);
            let mut received = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let length = data.remaining();
                received.extend_from_slice(&data.copy_to_bytes(length));
            }
            assert_eq!(received, payload);
            let elapsed = start.elapsed();
            assert!(elapsed >= Duration::from_millis(3500), "per-IP rate/burst exceeded: {elapsed:?}");
            let server_stats = connection_rx.await.unwrap().stats();
            let client_stats = observed.stats();
            eprintln!(
                "decoy H3 trial={trial} delivered={}/{} elapsed_ms={} handshake_ms={} goodput_mbit={:.3} client_rtt_us={} server_lost_packets={} server_sent_packets={} server_udp_tx_bytes={} client_mtu={} server_mtu={}",
                received.len(), payload.len(), elapsed.as_millis(), handshake.as_millis(),
                received.len() as f64 * 8.0 / elapsed.as_secs_f64() / 1e6,
                client_stats.path.rtt.as_micros(), server_stats.path.lost_packets,
                server_stats.path.sent_packets, server_stats.udp_tx.bytes,
                client_stats.path.current_mtu, server_stats.path.current_mtu,
            );
            client.close(VarInt::from_u32(0), b"test complete");
        }).await.expect("rate-limited HTTP/3 download stalled");
    }
}
