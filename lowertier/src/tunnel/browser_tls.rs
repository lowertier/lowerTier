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

    /// The offered cipher suites, extension types in order, and ALPN of a ClientHello record.
    fn client_hello_shape(record: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<Vec<u8>>) {
        let hello = &record[9..];
        let take = |at: usize, len: usize| &hello[at..at + len];
        let mut at = 2 + 32;
        at += 1 + usize::from(hello[at]);
        let suites_len = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        let suites = take(at + 2, suites_len)
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        at += 2 + suites_len;
        at += 1 + usize::from(hello[at]);
        let extensions_len = usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        let mut extensions = take(at + 2, extensions_len);
        let (mut types, mut alpn) = (Vec::new(), Vec::new());
        while !extensions.is_empty() {
            let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
            let len = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
            types.push(kind);
            if kind == 16 {
                let mut list = &extensions[6..4 + len];
                while !list.is_empty() {
                    alpn.push(list[1..1 + usize::from(list[0])].to_vec());
                    list = &list[1 + usize::from(list[0])..];
                }
            }
            extensions = &extensions[4 + len..];
        }
        (suites, types, alpn)
    }

    /// Pins what the TLS client offers. Performance work must not change this by accident:
    /// a different cipher order, extension set, or ALPN list changes how the connection looks.
    #[tokio::test]
    async fn client_hello_offer_is_pinned() {
        let (suites, types, alpn) = client_hello_shape(&capture(&[b"h2", b"http/1.1"]).await);
        assert_eq!(
            suites,
            vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x00ff
            ],
            "{suites:04x?}"
        );
        assert_eq!(alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let mut sorted = types.clone();
        sorted.sort_unstable();
        // server_name, status_request, supported_groups, ec_point_formats, signature_algorithms,
        // ALPN, extended_master_secret, session_ticket, supported_versions,
        // psk_key_exchange_modes, key_share
        assert_eq!(
            sorted,
            vec![0, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51],
            "extension order as sent: {types:?}"
        );
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
