use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    TransportBindingKind, TunnelConnector, TunnelListener,
    batch::PacketBatch,
    packet_def::{PacketType, ZCPacket},
    quic::{QuicTunnelConnector, QuicTunnelListener},
    tcp::{TcpTunnelConnector, TcpTunnelListener},
    websocket::{WsTunnelConnector, WsTunnelListener},
};
use crate::common::{
    config::{NetworkIdentity, gen_default_flags},
    global_ctx::tests::get_mock_global_ctx_with_network,
};

const HOST: &str = "challenges.cloudflare.com";

struct Caddy {
    child: Child,
    _directory: tempfile::TempDir,
}

impl Drop for Caddy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CADDY_BIN with the caddy-l4 module"]
async fn caddy_multiplexes_camouflaged_transports() {
    for sni_passthrough in [true, false] {
        tokio::time::timeout(Duration::from_secs(45), async {
            let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let public = reservation.local_addr().unwrap();
            let web_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let web = web_reservation.local_addr().unwrap();
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = HOST.to_owned();
            flags.camouflage_config_mut().set_decoy_upstream(web.to_string());
            flags.camouflage_config_mut().admission_secret = "caddy-routing-test-secret".to_owned();
            flags.camouflage_config_mut().sni_routing = sni_passthrough;
            let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(12);
            let mut servers = tokio::task::JoinSet::new();
            let mut upstreams = [Vec::new(), Vec::new(), Vec::new()];
            let mut contexts = Vec::new();
            for (protocol, upstreams) in upstreams.iter_mut().enumerate() {
                for backend in 0..2 {
                    let mut listener: Box<dyn TunnelListener> = match protocol {
                        0 => {
                            let context = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                                "caddy-test".to_owned(),
                                "caddy-network-test-secret".to_owned(),
                            )));
                            context.set_flags(flags.clone());
                            contexts.push(context.clone());
                            Box::new(QuicTunnelListener::new(
                                "quic://127.0.0.1:0".parse().unwrap(), context,
                            ))
                        }
                        1 => {
                            let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
                            listener.set_flags(flags.clone());
                            Box::new(listener)
                        }
                        _ => Box::new(WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap())),
                    };
                    listener.listen().await.unwrap();
                    upstreams.push(listener.local_url().port().unwrap());
                    let accepted_tx = accepted_tx.clone();
                    servers.spawn(async move {
                        for _ in 0..2 {
                            let tunnel = listener.accept().await.unwrap();
                            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                            accepted_tx.send((protocol, backend, tunnel.transport_binding(), done_tx)).await.unwrap();
                            let (mut receive, mut send) = tunnel.split();
                            let packet = receive.next().await.unwrap().unwrap();
                            send.send(packet).await.unwrap();
                            send.flush().await.unwrap();
                            done_rx.await.unwrap();
                        }
                    });
                }
            }

            let work_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../benchmark-results/.work");
            std::fs::create_dir_all(work_dir).unwrap();
            let directory = tempfile::Builder::new().prefix("caddy-").tempdir_in(work_dir).unwrap();
            let certificate = rcgen::generate_simple_self_signed(vec!["web.invalid".to_owned(), HOST.to_owned()]).unwrap();
            let certificate_path = directory.path().join("web.pem");
            let key_path = directory.path().join("web-key.pem");
            std::fs::write(&certificate_path, certificate.serialize_pem().unwrap()).unwrap();
            std::fs::write(&key_path, certificate.serialize_private_key_pem()).unwrap();
            let config = format!(r#"{{
    admin off
    auto_https disable_redirects
    skip_install_trust
    layer4 {{
        udp/{public} {{
            @vpn quic sni {HOST}
            route @vpn {{
                proxy udp/127.0.0.1:{q0} udp/127.0.0.1:{q1} {{
                    lb_policy round_robin
                }}
            }}
            route {{
                proxy udp/{web}
            }}
        }}
        tcp/{public} {{
            @marked regexp `^\x16\x03\x01\x00\x{routing_length:02x}` 5
            route @marked {{
                proxy 127.0.0.1:{h0} 127.0.0.1:{h1} {{
                    lb_policy round_robin
                }}
            }}
            @h2 tls {{
                sni {HOST}
                alpn h2
            }}
            route @h2 {{
                proxy 127.0.0.1:{h0} 127.0.0.1:{h1} {{
                    lb_policy round_robin
                }}
            }}
            @ws tls {{
                sni {HOST}
                alpn http/1.1
            }}
            route @ws {{
                proxy 127.0.0.1:{w0} 127.0.0.1:{w1} {{
                    lb_policy round_robin
                }}
            }}
            route {{
                proxy {web}
            }}
        }}
    }}
}}
https://web.invalid:{web_port}, https://{HOST}:{web_port} {{
    bind 127.0.0.1
    tls "{certificate_file}" "{key_file}"
    respond "ordinary website"
}}
"#, q0=upstreams[0][0], q1=upstreams[0][1], h0=upstreams[1][0], h1=upstreams[1][1],
                w0=upstreams[2][0], w1=upstreams[2][1], web_port=web.port(),
                certificate_file=certificate_path.display(), key_file=key_path.display(),
                routing_length=super::quic::QUIC_ROUTING_CID_BYTES);
            let config_path = directory.path().join("Caddyfile");
            std::fs::write(&config_path, config).unwrap();
            let binary = std::env::var_os("CADDY_BIN").expect("CADDY_BIN is required");
            let adapted = Command::new(&binary).args(["adapt", "--adapter", "caddyfile", "--config"])
                .arg(&config_path).output().unwrap();
            assert!(adapted.status.success(), "{}", String::from_utf8_lossy(&adapted.stderr));
            drop(reservation);
            drop(web_reservation);
            let child = Command::new(binary).args(["run", "--adapter", "caddyfile", "--config"])
                .arg(config_path)
                .env("XDG_DATA_HOME", directory.path().join("data"))
                .env("XDG_CONFIG_HOME", directory.path().join("config"))
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
                .spawn().unwrap();
            let mut caddy = Caddy { child, _directory: directory };
            let mut ready = false;
            for _ in 0..100 {
                assert!(caddy.child.try_wait().unwrap().is_none(), "Caddy exited during startup");
                if tokio::net::TcpStream::connect(public).await.is_ok() {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(ready, "Caddy did not start listening");

            let web_flags = gen_default_flags();
            let stream = tokio::net::TcpStream::connect(public).await.unwrap();
            let tls = super::stealth_tls::rustls_client_config(&web_flags, &[b"http/1.1"]).unwrap();
            let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                .connect("web.invalid".try_into().unwrap(), stream).await.unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\nHost: web.invalid\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.contains("ordinary website"));

            for host in ["web.invalid", HOST] {
                if sni_passthrough && host == HOST {
                    continue;
                }
                let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
                endpoint.set_default_client_config(super::quic::client_config(&web_flags).unwrap());
                let connection = endpoint.connect(public, host).unwrap().await.unwrap();
                let (mut driver, mut requests) = h3::client::builder()
                    .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(
                        h3_quinn::Connection::new(connection),
                    ).await.unwrap();
                let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    let _ = driver.wait_idle().await;
                }));
                let mut request = requests.send_request(http::Request::get(format!("https://{host}/")).body(()).unwrap()).await.unwrap();
                request.finish().await.unwrap();
                assert_eq!(request.recv_response().await.unwrap().status(), http::StatusCode::OK);
                drop(driver);
            }
            if !sni_passthrough {
                let stream = tokio::net::TcpStream::connect(public).await.unwrap();
                let tls = super::stealth_tls::rustls_client_config(&web_flags, &[b"h2"]).unwrap();
                let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                    .connect(HOST.try_into().unwrap(), stream).await.unwrap();
                let (mut requests, connection) = h2::client::handshake(stream).await.unwrap();
                let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    let _ = connection.await;
                }));
                let (response, _) = requests.send_request(
                    http::Request::get(format!("https://{HOST}/")).body(()).unwrap(), true,
                ).unwrap();
                assert_eq!(response.await.unwrap().status(), http::StatusCode::OK);
                drop(driver);
            }

            let mut counts = [[0; 2]; 3];
            for protocol in 0..3 {
                for _ in 0..4 {
                    let client = match protocol {
                        0 => QuicTunnelConnector::new(format!("quic://{public}").parse().unwrap(), contexts[0].clone())
                            .connect().await.unwrap(),
                        1 => {
                            let mut connector = TcpTunnelConnector::new(format!("tcp://{public}").parse().unwrap());
                            connector.set_flags(flags.clone());
                            connector.connect().await.unwrap()
                        }
                        _ => {
                            let mut connector = WsTunnelConnector::new(format!("wss://{HOST}:{}/ws", public.port()).parse().unwrap());
                            connector.set_resolved_addr(public);
                            connector.connect().await.unwrap()
                        }
                    };
                    let (accepted_protocol, backend, binding, done) = accepted_rx.recv().await.unwrap();
                    assert_eq!(accepted_protocol, protocol);
                    assert!(binding.is_some());
                    assert_eq!(client.transport_binding(), binding);
                    if protocol == 1 {
                        assert_eq!(binding.unwrap().kind, TransportBindingKind::Http2TlsExporterV1);
                    } else if protocol == 2 {
                        assert_eq!(binding.unwrap().kind, TransportBindingKind::WssTlsExporterV1);
                    }
                    counts[protocol][backend] += 1;
                    let (mut receive, mut send) = client.split();
                    let mut packet = ZCPacket::new_with_payload(b"caddy-shared-port");
                    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                    send.send(PacketBatch::singleton(packet)).await.unwrap();
                    let echoed = receive.next().await.unwrap().unwrap().pop_singleton().unwrap();
                    assert_eq!(echoed.payload(), b"caddy-shared-port");
                    done.send(()).unwrap();
                }
            }
            assert_eq!(counts, [[2, 2], [2, 2], [2, 2]]);
            while let Some(result) = servers.join_next().await { result.unwrap(); }
            eprintln!("Caddy H2/H3/WSS: two backends each, unchanged TLS bindings, website coexistence; SNI passthrough={sni_passthrough}");
        }).await.expect("shared-port Caddy integration timed out");
    }
}
