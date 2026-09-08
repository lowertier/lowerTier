use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    TransportBindingKind, TunnelConnector, TunnelListener,
    batch::PacketBatch,
    packet_def::{PacketType, ZCPacket},
    tcp::{TcpTunnelConnector, TcpTunnelListener},
    websocket::{WsTunnelConnector, WsTunnelListener},
};
use crate::common::config::gen_default_flags;

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
async fn caddy_multiplexes_tcp_transports() {
    for lane_count in [1, 4] {
        let policy = if lane_count == 1 {
            "round_robin"
        } else {
            "ip_hash"
        };
        tokio::time::timeout(Duration::from_secs(45), async {
            let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let public = reservation.local_addr().unwrap();
            let web_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let web = web_reservation.local_addr().unwrap();
            let mut flags = gen_default_flags();
            flags.quic_server_name = HOST.to_owned();
            flags.quic_decoy_upstream = web.to_string();
            flags.quic_admission_secret = "caddy-routing-test-secret".to_owned();
            flags.quic_sni_passthrough = true;
            let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(12);
            let mut servers = tokio::task::JoinSet::new();
            let mut upstreams = [Vec::new(), Vec::new()];
            for (protocol, upstreams) in upstreams.iter_mut().enumerate() {
                for backend in 0..2 {
                    let mut listener: Box<dyn TunnelListener> = match protocol {
                        0 => {
                            let mut listener = TcpTunnelListener::new(
                                format!("tcp://127.0.0.1:0?lanes={lane_count}")
                                    .parse()
                                    .unwrap(),
                            );
                            listener.set_flags(flags.clone());
                            Box::new(listener)
                        }
                        _ => Box::new(WsTunnelListener::new(
                            format!("wss://127.0.0.1:0?lanes={lane_count}")
                                .parse()
                                .unwrap(),
                        )),
                    };
                    listener.listen().await.unwrap();
                    upstreams.push(listener.local_url().port().unwrap());
                    let accepted_tx = accepted_tx.clone();
                    servers.spawn(async move {
                        loop {
                            let tunnel = listener.accept().await.unwrap();
                            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                            accepted_tx
                                .send((protocol, backend, tunnel.transport_binding(), done_tx))
                                .await
                                .unwrap();
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
            let directory = tempfile::Builder::new()
                .prefix("caddy-")
                .tempdir_in(work_dir)
                .unwrap();
            let certificate =
                rcgen::generate_simple_self_signed(vec!["web.invalid".to_owned(), HOST.to_owned()])
                    .unwrap();
            let certificate_path = directory.path().join("web.pem");
            let key_path = directory.path().join("web-key.pem");
            std::fs::write(&certificate_path, certificate.serialize_pem().unwrap()).unwrap();
            std::fs::write(&key_path, certificate.serialize_private_key_pem()).unwrap();
            let config = format!(
                r#"{{
    admin off
    auto_https disable_redirects
    skip_install_trust
    layer4 {{
        tcp/{public} {{
            @h2 tls {{
                sni {HOST}
                alpn h2
            }}
            route @h2 {{
                proxy 127.0.0.1:{h0} 127.0.0.1:{h1} {{
                    lb_policy {policy}
                }}
            }}
            @ws tls {{
                sni {HOST}
                alpn http/1.1
            }}
            route @ws {{
                proxy 127.0.0.1:{w0} 127.0.0.1:{w1} {{
                    lb_policy {policy}
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
"#,
                h0 = upstreams[0][0],
                h1 = upstreams[0][1],
                w0 = upstreams[1][0],
                w1 = upstreams[1][1],
                web_port = web.port(),
                certificate_file = certificate_path.display(),
                key_file = key_path.display()
            );
            let config_path = directory.path().join("Caddyfile");
            std::fs::write(&config_path, config).unwrap();
            let binary = std::env::var_os("CADDY_BIN").expect("CADDY_BIN is required");
            let adapted = Command::new(&binary)
                .args(["adapt", "--adapter", "caddyfile", "--config"])
                .arg(&config_path)
                .output()
                .unwrap();
            assert!(
                adapted.status.success(),
                "{}",
                String::from_utf8_lossy(&adapted.stderr)
            );
            drop(reservation);
            drop(web_reservation);
            let child = Command::new(binary)
                .args(["run", "--adapter", "caddyfile", "--config"])
                .arg(config_path)
                .env("XDG_DATA_HOME", directory.path().join("data"))
                .env("XDG_CONFIG_HOME", directory.path().join("config"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut caddy = Caddy {
                child,
                _directory: directory,
            };
            let mut ready = false;
            for _ in 0..100 {
                assert!(
                    caddy.child.try_wait().unwrap().is_none(),
                    "Caddy exited during startup"
                );
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
                .connect("web.invalid".try_into().unwrap(), stream)
                .await
                .unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: web.invalid\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.contains("ordinary website"));

            let mut counts = [[0; 2]; 2];
            for protocol in 0..2 {
                for _ in 0..4 {
                    let client = match protocol {
                        0 => {
                            let mut connector = TcpTunnelConnector::new(
                                format!("tcp://{public}?lanes={lane_count}")
                                    .parse()
                                    .unwrap(),
                            );
                            connector.set_flags(flags.clone());
                            connector.connect().await.unwrap()
                        }
                        _ => {
                            let mut connector = WsTunnelConnector::new(
                                format!("wss://{HOST}:{}/ws?lanes={lane_count}", public.port())
                                    .parse()
                                    .unwrap(),
                            );
                            connector.set_resolved_addr(public);
                            connector.connect().await.unwrap()
                        }
                    };
                    let (accepted_protocol, backend, binding, done) =
                        accepted_rx.recv().await.unwrap();
                    assert_eq!(accepted_protocol, protocol);
                    assert!(binding.is_some());
                    assert_eq!(client.transport_binding(), binding);
                    if lane_count > 1 {
                        assert_eq!(
                            binding.unwrap().kind,
                            TransportBindingKind::TlsExporterLanesV1
                        );
                    } else if protocol == 0 {
                        assert_eq!(
                            binding.unwrap().kind,
                            TransportBindingKind::Http2TlsExporterV1
                        );
                    } else if protocol == 1 {
                        assert_eq!(
                            binding.unwrap().kind,
                            TransportBindingKind::WssTlsExporterV1
                        );
                    }
                    counts[protocol][backend] += 1;
                    let (mut receive, mut send) = client.split();
                    let mut packet = ZCPacket::new_with_payload(b"caddy-shared-port");
                    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                    send.send(PacketBatch::singleton(packet)).await.unwrap();
                    let echoed = receive
                        .next()
                        .await
                        .unwrap()
                        .unwrap()
                        .pop_singleton()
                        .unwrap();
                    assert_eq!(echoed.payload(), b"caddy-shared-port");
                    done.send(()).unwrap();
                }
            }
            if lane_count == 1 {
                assert_eq!(counts, [[2, 2], [2, 2]]);
            } else {
                assert!(counts.iter().all(|count| count.iter().sum::<usize>() == 4));
            }
            servers.abort_all();
            while let Some(result) = servers.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled());
                }
            }
        })
        .await
        .expect("shared-port Caddy integration timed out");
    }
}
