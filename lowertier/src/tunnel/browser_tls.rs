//! Outbound TLS for H2 and WSS. Same rustls provider as QUIC/H2/WSS servers.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::{TunnelError, stealth_tls};

pub(super) async fn connect<S>(
    stream: S,
    server_name: &str,
    alpn: &[&[u8]],
    verify_certificate: bool,
) -> Result<TlsStream<S>, TunnelError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let config = stealth_tls::rustls_client_config_for(alpn, verify_certificate)?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_string()))?;
    connector
        .connect(name, stream)
        .await
        .map_err(|error| TunnelError::InternalError(format!("TLS handshake: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };

    async fn capture(alpn: &[&[u8]]) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let receive = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(length <= 16 * 1024);
                let mut hello = header.to_vec();
                hello.resize(5 + length, 0);
                stream.read_exact(&mut hello[5..]).await.unwrap();
                hello
            };
            let send = async {
                let stream = TcpStream::connect(addr).await.unwrap();
                assert!(
                    connect(stream, "challenges.cloudflare.com", alpn, false)
                        .await
                        .is_err()
                );
            };
            let (hello, _) = tokio::join!(receive, send);
            hello
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn client_hello_is_a_tls_handshake_with_fresh_randomness() {
        for alpn in [
            vec![b"h2".as_slice(), b"http/1.1"],
            vec![b"http/1.1".as_slice()],
        ] {
            let first = capture(&alpn).await;
            let second = capture(&alpn).await;
            assert_eq!(first[0], 22);
            assert_eq!(first[5], 1);
            assert_ne!(&first[11..43], &second[11..43]);
        }
    }

    #[tokio::test]
    async fn tls_exporter_matches_and_strict_verification_rejects_unknown_identity() {
        let (certs, key) = crate::tunnel::stealth_tls::shared_ephemeral_identity();
        let provider = crate::tunnel::stealth_tls::stealth_crypto_provider();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        for strict in [false, true] {
            timeout(Duration::from_secs(10), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let result = acceptor.accept(stream).await;
                    if strict {
                        assert!(result.is_err());
                        return;
                    }
                    let mut stream = result.unwrap();
                    let mut exported = [0; 32];
                    stream
                        .get_ref()
                        .1
                        .export_keying_material(
                            &mut exported,
                            b"EXPORTER-LowTier-Test",
                            Some(b"binding"),
                        )
                        .unwrap();
                    stream.write_all(&exported).await.unwrap();
                    stream.flush().await.unwrap();
                };
                let client = async {
                    let stream = TcpStream::connect(addr).await.unwrap();
                    let result =
                        connect(stream, "challenges.cloudflare.com", &[b"h2"], strict).await;
                    if strict {
                        assert!(result.is_err());
                        return;
                    }
                    let mut stream = result.unwrap();
                    let mut exported = [0; 32];
                    stream
                        .get_ref()
                        .1
                        .export_keying_material(
                            &mut exported,
                            b"EXPORTER-LowTier-Test",
                            Some(b"binding"),
                        )
                        .unwrap();
                    let mut remote = [0; 32];
                    stream.read_exact(&mut remote).await.unwrap();
                    assert_eq!(exported, remote);
                };
                tokio::join!(server, client);
            })
            .await
            .unwrap();
        }
    }
}
