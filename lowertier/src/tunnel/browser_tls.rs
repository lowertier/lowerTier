use std::io::{self, Read, Write};

use anyhow::Context as _;
use foreign_types::ForeignTypeRef;

mod roots;
use boring::{
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
        SslMethod, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use tokio::{io::BufWriter, net::TcpStream};

use super::TunnelError;

struct BrotliCertificate;

impl CertificateCompressor for BrotliCertificate {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        // Certificate data is unauthenticated at decompression time.
        const LIMIT: u64 = 128 * 1024;
        let decoder = brotli_decompressor::Decompressor::new(input, 4096);
        let written = io::copy(&mut decoder.take(LIMIT + 1), output)?;
        if written > LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS certificate exceeds limit",
            ));
        }
        Ok(())
    }
}

fn client_config(alpn: &[&[u8]], verify_certificate: bool) -> anyhow::Result<ConnectConfiguration> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    // Chromium's cipher policy, with real implementations of every advertised suite.
    builder.set_strict_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES")?;
    builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;

    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliCertificate)?;
    let mut protocols = Vec::new();
    for protocol in alpn {
        let len = u8::try_from(protocol.len()).context("ALPN protocol length")?;
        anyhow::ensure!(len != 0, "empty ALPN protocol");
        protocols.push(len);
        protocols.extend_from_slice(protocol);
    }
    builder.set_alpn_protos(&protocols)?;
    let native = rustls_native_certs::load_native_certs();
    if verify_certificate {
        anyhow::ensure!(
            !native.certs.is_empty(),
            "no native TLS roots: {:?}",
            native.errors
        );
    } else {
        // Direct peer identity is authenticated by Noise using this TLS exporter.
        builder.set_verify(SslVerifyMode::NONE);
    }
    let mut anchors = Vec::new();
    for der in native.certs {
        let cert = X509::from_der(der.as_ref())?;
        let digest = cert.digest(boring::hash::MessageDigest::sha256())?;
        if let Some((_, id)) = roots::TRUST_ANCHORS
            .iter()
            .find(|(hash, _)| hash.as_slice() == digest.as_ref())
        {
            anchors.push(id.len() as u8);
            anchors.extend_from_slice(id);
        }
        if verify_certificate {
            builder.cert_store_mut().add_cert(cert)?;
        }
    }
    let mut config = builder.build().configure()?;
    config.set_verify_hostname(verify_certificate);
    config.set_enable_ech_grease(true);
    let signatures: [u16; 11] = [
        0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    // These settings are absent from the safe wrapper. SSL owns copies of both
    // borrowed arrays; the pointer remains exclusively borrowed for these calls.
    unsafe {
        let ssl = config.as_ptr();
        anyhow::ensure!(
            boring_sys::SSL_set_verify_algorithm_prefs(ssl, signatures.as_ptr(), signatures.len())
                == 1,
            "configure signature algorithms"
        );
        boring_sys::SSL_set_server_padding_request(ssl, 0);
        if !anchors.is_empty() {
            anyhow::ensure!(
                boring_sys::SSL_set1_requested_trust_anchors(ssl, anchors.as_ptr(), anchors.len())
                    == 1,
                "configure trust anchor hints"
            );
        }
    }
    Ok(config)
}

pub(super) async fn connect(
    stream: TcpStream,
    server_name: &str,
    alpn: &[&[u8]],
    verify_certificate: bool,
) -> Result<BufWriter<tokio_boring::SslStream<TcpStream>>, TunnelError> {
    let config = client_config(alpn, verify_certificate).context("configure browser TLS")?;
    let tls = tokio_boring::connect(config, server_name, stream)
        .await
        .map_err(|error| TunnelError::InternalError(format!("browser TLS handshake: {error}")))?;
    // BoringSSL's Tokio adapter writes scalar buffers. Coalesce frame headers and
    // payloads into TLS records while retaining explicit flush/backpressure semantics.
    Ok(BufWriter::with_capacity(64 * 1024, tls))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
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
    async fn browser_client_hello_uses_tls_records_and_fresh_randomness() {
        for (name, alpn) in [
            ("https", vec![b"h2".as_slice(), b"http/1.1"]),
            ("wss", vec![b"http/1.1".as_slice()]),
        ] {
            let first = capture(&alpn).await;
            let second = capture(&alpn).await;
            assert_eq!(&first[..3], &[22, 3, 1]);
            assert_eq!(first[5], 1);
            assert_eq!(&first[9..11], &[3, 3]);
            assert_ne!(&first[11..43], &second[11..43]);
            if let Ok(directory) = std::env::var("LOWTIER_TLS_CAPTURE_DIR") {
                let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap();
                let directory = root.join(directory);
                assert!(directory.starts_with(root));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join(format!("lowertier-{name}-0.bin")), first).unwrap();
                std::fs::write(directory.join(format!("lowertier-{name}-1.bin")), second).unwrap();
            }
        }
    }

    fn grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a
    }

    fn words(bytes: &[u8]) -> Vec<u16> {
        assert_eq!(bytes.len() % 2, 0);
        bytes
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect()
    }

    fn hello_profile(record: &[u8]) -> serde_json::Value {
        let body = &record[9..];
        let session_len = usize::from(body[34]);
        let mut cursor = 35 + session_len;
        let cipher_len = usize::from(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
        cursor += 2;
        let ciphers = words(&body[cursor..cursor + cipher_len]);
        cursor += cipher_len;
        cursor += 1 + usize::from(body[cursor]);
        let extension_len = usize::from(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
        cursor += 2;
        assert_eq!(cursor + extension_len, body.len());
        let mut extensions = std::collections::BTreeMap::new();
        let mut order = Vec::new();
        while cursor < body.len() {
            let kind = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            let length = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
            cursor += 4;
            assert!(
                extensions
                    .insert(kind, &body[cursor..cursor + length])
                    .is_none()
            );
            order.push(kind);
            cursor += length;
        }
        let mut shares = Vec::new();
        let mut key_data = &extensions[&51][2..];
        while !key_data.is_empty() {
            let group = u16::from_be_bytes([key_data[0], key_data[1]]);
            let length = usize::from(u16::from_be_bytes([key_data[2], key_data[3]]));
            if !grease(group) {
                shares.push((group, length));
            }
            key_data = &key_data[4 + length..];
        }
        let mut protocols = Vec::new();
        let mut alpn_data = &extensions[&16][2..];
        while !alpn_data.is_empty() {
            let length = usize::from(alpn_data[0]);
            protocols.push(std::str::from_utf8(&alpn_data[1..1 + length]).unwrap());
            alpn_data = &alpn_data[1 + length..];
        }
        let groups = words(&extensions[&10][2..]);
        serde_json::json!({
            "record_version": u16::from_be_bytes([record[1], record[2]]),
            "legacy_version": u16::from_be_bytes([body[0], body[1]]),
            "session_id_length": session_len,
            "ciphers": ciphers.iter().copied().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "extensions": extensions.keys().copied().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "extension_order": order.into_iter().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "groups": groups.iter().copied().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "signatures": words(&extensions[&13][2..]).into_iter().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "versions": words(&extensions[&43][1..]).into_iter().filter(|v| !grease(*v)).collect::<Vec<_>>(),
            "key_shares": shares,
            "alpn": protocols,
            "compression": extensions[&27],
            "grease_counts": [ciphers.iter().filter(|v| grease(**v)).count(), extensions.keys().filter(|v| grease(**v)).count(), groups.iter().filter(|v| grease(**v)).count()],
        })
    }

    #[tokio::test]
    async fn client_hello_matches_captured_chrome_core_fields() {
        let chrome: serde_json::Value =
            serde_json::from_str(include_str!("browser_tls/chrome-152.json")).unwrap();
        for (name, alpn) in [
            ("https", vec![b"h2".as_slice(), b"http/1.1"]),
            ("wss", vec![b"http/1.1".as_slice()]),
        ] {
            let first = hello_profile(&capture(&alpn).await);
            let second = hello_profile(&capture(&alpn).await);
            for field in [
                "record_version",
                "legacy_version",
                "session_id_length",
                "groups",
                "signatures",
                "versions",
                "key_shares",
                "alpn",
                "compression",
                "grease_counts",
            ] {
                assert_eq!(first[field], chrome[name][field], "{name}: {field}");
            }
            // Cipher preference follows AES availability, as it does in Chrome.
            let mut offered: Vec<u16> = serde_json::from_value(first["ciphers"].clone()).unwrap();
            let mut expected: Vec<u16> =
                serde_json::from_value(chrome[name]["ciphers"].clone()).unwrap();
            offered.sort_unstable();
            expected.sort_unstable();
            assert_eq!(offered, expected);
            assert_ne!(first["extension_order"], second["extension_order"]);
            let mut extensions: Vec<u16> =
                serde_json::from_value(first["extensions"].clone()).unwrap();
            let mut expected: Vec<u16> =
                serde_json::from_value(chrome[name]["extensions"].clone()).unwrap();
            // CA hints depend on the installed roots. ALPS is omitted because h2
            // does not consume TLS-delivered SETTINGS; advertising it would lie.
            extensions.retain(|v| *v != 51764);
            expected.retain(|v| !matches!(*v, 51764 | 17613));
            assert_eq!(extensions, expected, "{name}: extensions");
        }
    }

    #[tokio::test]
    async fn tls_exporter_matches_and_strict_verification_rejects_unknown_identity() {
        crate::tunnel::insecure_tls::init_crypto_provider();
        let (certs, key) = crate::tunnel::insecure_tls::get_insecure_tls_cert();
        let mut config = rustls::ServerConfig::builder()
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
                        .ssl()
                        .export_keying_material(
                            &mut exported,
                            "EXPORTER-LowTier-Test",
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
