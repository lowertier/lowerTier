//! Shared TLS identity for QUIC HTTP/3 and TCP HTTP/2 camouflage.
//!
//! Owned certificates follow `quic_tls_cert` / Let's Encrypt live paths.
//! Decoy pass-through skips a local certificate so probes can see the upstream
//! cert. Noise remains the peer identity layer.

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::Context as _;
use rustls::{
    DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

use crate::{common::config::Flags, tunnel::TunnelError};

/// Certificate and key files to serve, with the server name each one is for. An explicit
/// `tls_cert` serves every name. Otherwise each server name loads its Let's Encrypt files.
/// Decoy pass-through serves no local certificate: unmarked visitors reach the upstream.
pub fn server_identity_paths(flags: &Flags) -> Vec<(Option<String>, PathBuf, PathBuf)> {
    let camouflage = flags.camouflage_config();
    if !camouflage.tls_cert.is_empty() {
        return vec![(
            None,
            PathBuf::from(&camouflage.tls_cert),
            PathBuf::from(&camouflage.tls_key),
        )];
    }
    if camouflage.has_decoy() {
        return Vec::new();
    }
    camouflage
        .server_names
        .iter()
        .map(|name| {
            let live = Path::new("/etc/letsencrypt/live").join(name);
            (
                Some(name.clone()),
                live.join("fullchain.pem"),
                live.join("privkey.pem"),
            )
        })
        .collect()
}

/// rustls verifier that accepts any certificate. Noise authenticates the peer.
#[derive(Debug)]
pub struct NoiseAuthenticatedPeerVerifier(Arc<rustls::crypto::CryptoProvider>);

impl NoiseAuthenticatedPeerVerifier {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(stealth_crypto_provider()))
    }
}

impl ServerCertVerifier for NoiseAuthenticatedPeerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn load_identity(
    name: Option<&str>,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TunnelError> {
    {
        let cert_file = File::open(cert_path).with_context(|| {
            format!(
                "open stealth TLS certificate {}; configure explicit paths or install the certificate for {}",
                cert_path.display(),
                name.unwrap_or("the server names")
            )
        })?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .context("parse stealth TLS certificate chain")?;
        if certs.is_empty() {
            return Err(TunnelError::InternalError(
                "stealth TLS certificate chain is empty".to_owned(),
            ));
        }
        let key_file = File::open(key_path)
            .with_context(|| format!("open stealth TLS private key {}", key_path.display()))?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
            .context("parse stealth TLS private key")?
            .ok_or_else(|| {
                TunnelError::InternalError("stealth TLS private key is empty".to_owned())
            })?;
        Ok((certs, key))
    }
}

/// Picks the certificate for the server name a client sends. Connections without an allowed
/// server name are rejected before completing TLS.
#[derive(Debug)]
struct ServerNameCertificates {
    by_name: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    allowed_names: std::collections::HashSet<String>,
    default: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for ServerNameCertificates {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = hello.server_name()?.to_ascii_lowercase();
        if !self.allowed_names.contains(&sni) {
            return None;
        }
        Some(self.by_name.get(&sni).unwrap_or(&self.default).clone())
    }
}

/// The certificate resolver shared by the QUIC, HTTP/2, and WSS listeners.
pub fn server_cert_resolver(
    flags: &Flags,
) -> Result<Arc<dyn rustls::server::ResolvesServerCert>, TunnelError> {
    let provider = stealth_crypto_provider();
    let certified = |certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>| {
        rustls::sign::CertifiedKey::from_der(certs, key, &provider)
            .map(Arc::new)
            .context("load stealth TLS server identity")
    };
    let allowed_names: std::collections::HashSet<String> = flags
        .camouflage_config()
        .effective_server_names()
        .into_iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let mut by_name = std::collections::HashMap::new();
    let mut default = None;
    for (name, cert_path, key_path) in server_identity_paths(flags) {
        let (certs, key) = load_identity(name.as_deref(), &cert_path, &key_path)?;
        let key = certified(certs, key)?;
        if let Some(name) = name {
            by_name.insert(name.to_ascii_lowercase(), key.clone());
        }
        default.get_or_insert(key);
    }
    let default = match default {
        Some(key) => key,
        None => {
            let (certs, key) = shared_ephemeral_identity();
            certified(certs, key)?
        }
    };
    Ok(Arc::new(ServerNameCertificates {
        by_name,
        allowed_names,
        default,
    }))
}

/// One process-wide self-signed identity for QUIC/H2/WSS when no cert files
/// are configured. Listeners used to mint a new rcgen key each.
pub(crate) fn shared_ephemeral_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)
{
    static IDENTITY: OnceLock<(Vec<CertificateDer<'static>>, Vec<u8>)> = OnceLock::new();
    let (certs, key) = IDENTITY.get_or_init(|| {
        let certificate =
            rcgen::Certificate::from_params(rcgen::CertificateParams::new(Vec::new()))
                .expect("generate ephemeral stealth TLS certificate");
        let cert = CertificateDer::from(
            certificate
                .serialize_der()
                .expect("serialize ephemeral stealth TLS certificate"),
        );
        (vec![cert], certificate.serialize_private_key_der())
    });
    (certs.clone(), PrivatePkcs8KeyDer::from(key.clone()).into())
}

pub fn skip_server_verification(flags: &Flags) -> bool {
    !flags.camouflage_config().has_server_names() || flags.camouflage_config().has_decoy()
}

/// rustls defaults to AES-256-GCM first. Chrome and Safari offer AES-128-GCM,
/// then AES-256-GCM, then ChaCha20. Same for the TLS 1.2 ECDHE suites.
pub(crate) fn browser_like_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::ring::cipher_suite;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    provider
}

pub(crate) fn stealth_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let provider = browser_like_provider();
            let _ = rustls::crypto::CryptoProvider::install_default(browser_like_provider());
            Arc::new(provider)
        })
        .clone()
}

fn native_root_store() -> Result<&'static RootCertStore, TunnelError> {
    static ROOTS: OnceLock<RootCertStore> = OnceLock::new();
    if let Some(roots) = ROOTS.get() {
        return Ok(roots);
    }
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(TunnelError::InternalError(format!(
            "load native stealth TLS roots: {:?}",
            native.errors
        )));
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err(TunnelError::InternalError(format!(
            "no valid native stealth TLS roots; ignored {ignored} certificates"
        )));
    }
    Ok(ROOTS.get_or_init(|| roots))
}

#[cfg(test)]
pub fn rustls_client_config(
    flags: &Flags,
    alpn: &[&[u8]],
) -> Result<rustls::ClientConfig, TunnelError> {
    rustls_client_config_for(alpn, !skip_server_verification(flags))
}

pub(crate) fn rustls_client_config_for(
    alpn: &[&[u8]],
    verify_certificate: bool,
) -> Result<rustls::ClientConfig, TunnelError> {
    let provider = stealth_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("configure stealth TLS client")?;
    let mut config = if verify_certificate {
        builder
            .with_root_certificates(native_root_store()?.clone())
            .with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(NoiseAuthenticatedPeerVerifier::new())
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
    Ok(config)
}

pub fn rustls_server_config(
    flags: &Flags,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, TunnelError> {
    let resolver = server_cert_resolver(flags)?;
    let provider = stealth_crypto_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure stealth TLS server")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
    Ok(config)
}

/// Extract a DNS hostname from `url`, ignoring IPv4/IPv6 literals even on non-special schemes
/// (`h2://`, `quic://`, `tcp://`) where `url::Url::domain()` returns opaque IPv4 strings.
pub(crate) fn url_dns_host(url: &url::Url) -> Option<&str> {
    url.domain()
        .filter(|host| !host.is_empty() && host.parse::<std::net::IpAddr>().is_err())
}

/// The TLS server name for a connection to `remote`: one of the configured names, chosen per
/// destination, or the host of the peer URI.
pub fn client_server_name(
    flags: &Flags,
    url: &url::Url,
    remote: std::net::IpAddr,
) -> Result<ServerName<'static>, TunnelError> {
    let config = flags.camouflage_config();
    let name = match config.server_name_for(remote) {
        Some(name) => name.to_owned(),
        None => url_dns_host(url)
            .map(str::to_string)
            .unwrap_or_else(|| crate::common::control_config::DEFAULT_CAMOUFLAGE_SERVER_NAME.to_string()),
    };
    ServerName::try_from(name).map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_string()))
}

use crate::common::global_ctx::ArcGlobalCtx;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use hmac::Mac as _;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const QUIC_ROUTING_CID_BYTES: usize = 8;
const QUIC_ROUTING_NONCE_BYTES: usize = 4;
const QUIC_ROUTING_TAG_BYTES: usize = QUIC_ROUTING_CID_BYTES - QUIC_ROUTING_NONCE_BYTES;
const CONNECT_IP_ADMISSION_WINDOW_SECONDS: u64 = 300;

fn quic_routing_tag(secret: &[u8], window: u64, nonce: &[u8]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret)
        .expect("HMAC accepts all QUIC routing key lengths");
    mac.update(b"lowertier QUIC routing CID v1");
    mac.update(&window.to_be_bytes());
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

pub(crate) fn routing_cid_bytes(secret: &[u8], now: SystemTime) -> [u8; QUIC_ROUTING_CID_BYTES] {
    use ring::rand::SecureRandom as _;

    let mut bytes = [0_u8; QUIC_ROUTING_CID_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes[..QUIC_ROUTING_NONCE_BYTES])
        .expect("operating system random generator must be available");
    let window = ConnectIpAdmission::window(now);
    let tag = quic_routing_tag(secret, window, &bytes[..QUIC_ROUTING_NONCE_BYTES]);
    bytes[QUIC_ROUTING_NONCE_BYTES..].copy_from_slice(&tag[..QUIC_ROUTING_TAG_BYTES]);
    bytes
}

pub(crate) fn valid_routing_cid_bytes(cid: &[u8], secret: &[u8], now: SystemTime) -> bool {
    if cid.len() != QUIC_ROUTING_CID_BYTES {
        return false;
    }
    let nonce = &cid[..QUIC_ROUTING_NONCE_BYTES];
    let current = ConnectIpAdmission::window(now);
    [
        current.saturating_sub(1),
        current,
        current.saturating_add(1),
    ]
    .into_iter()
    .any(|window| {
        let tag = quic_routing_tag(secret, window, nonce);
        crate::common::verify_slices_are_equal(
            &cid[QUIC_ROUTING_NONCE_BYTES..],
            &tag[..QUIC_ROUTING_TAG_BYTES],
        )
        .is_ok()
    })
}

#[derive(Clone)]
pub(crate) struct ConnectIpAdmission {
    pub(super) key: Arc<[u8]>,
}

impl ConnectIpAdmission {
    pub(crate) fn stream_flags(global_ctx: &ArcGlobalCtx) -> Flags {
        let mut flags = global_ctx.get_flags();
        if flags.camouflage_config().admission_secret.is_empty()
            && let Some(secret) = global_ctx.get_network_identity().network_secret
        {
            flags.camouflage_config_mut().admission_secret = secret;
        }
        flags
    }

    pub(crate) fn from_global_ctx(global_ctx: &ArcGlobalCtx) -> Option<Self> {
        let flags = global_ctx.config.get_flags();
        let key = if flags.camouflage_config().admission_secret.is_empty() {
            global_ctx.get_network_identity().network_secret?
        } else {
            flags.camouflage_config().admission_secret.clone()
        };
        Self::from_secret(key)
    }

    pub(crate) fn from_flags(flags: &crate::common::config::Flags) -> Option<Self> {
        Self::from_secret(flags.camouflage_config().admission_secret.clone())
    }

    fn from_secret(key: String) -> Option<Self> {
        (!key.is_empty()).then(|| Self {
            key: Arc::from(key.into_bytes()),
        })
    }

    pub(super) fn window(now: SystemTime) -> u64 {
        now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            / CONNECT_IP_ADMISSION_WINDOW_SECONDS
    }

    pub(super) fn token_for_window(&self, window: u64) -> String {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts all admission key lengths");
        mac.update(b"lowertier HTTP/3 CONNECT-IP admission v2");
        mac.update(&window.to_be_bytes());
        format!(
            "v2.{window}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    pub(crate) fn current_token(&self) -> String {
        self.token_for_window(Self::window(SystemTime::now()))
    }

    pub(crate) fn verify_header(&self, value: &str) -> bool {
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        let mut fields = token.split('.');
        if fields.next() != Some("v2") {
            return false;
        }
        let Some(window) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            return false;
        };
        if fields.next().is_none() || fields.next().is_some() {
            return false;
        }
        let current = Self::window(SystemTime::now());
        if window.abs_diff(current) > 1 {
            return false;
        }
        crate::common::verify_slices_are_equal(
            token.as_bytes(),
            self.token_for_window(window).as_bytes(),
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::gen_default_flags;

    #[test]
    fn certificate_paths_follow_server_name_without_manual_paths() {
        let mut flags = gen_default_flags();
        flags.camouflage_config_mut().server_names = vec!["challenges.cloudflare.com".to_owned()];

        flags
            .camouflage_config_mut()
            .server_names
            .push("cdn.example.test".to_owned());

        let paths = server_identity_paths(&flags);

        assert_eq!(
            paths,
            vec![
                (
                    Some("challenges.cloudflare.com".to_owned()),
                    PathBuf::from("/etc/letsencrypt/live/challenges.cloudflare.com/fullchain.pem"),
                    PathBuf::from("/etc/letsencrypt/live/challenges.cloudflare.com/privkey.pem"),
                ),
                (
                    Some("cdn.example.test".to_owned()),
                    PathBuf::from("/etc/letsencrypt/live/cdn.example.test/fullchain.pem"),
                    PathBuf::from("/etc/letsencrypt/live/cdn.example.test/privkey.pem"),
                ),
            ]
        );
    }

    #[test]
    fn explicit_certificate_paths_take_priority() {
        let mut flags = gen_default_flags();
        flags.camouflage_config_mut().server_names = vec!["challenges.cloudflare.com".to_owned()];
        flags.camouflage_config_mut().tls_cert = "/run/cert.pem".to_owned();
        flags.camouflage_config_mut().tls_key = "/run/key.pem".to_owned();

        assert_eq!(
            server_identity_paths(&flags),
            vec![(
                None,
                PathBuf::from("/run/cert.pem"),
                PathBuf::from("/run/key.pem")
            )]
        );
    }

    #[test]
    fn decoy_pass_through_does_not_load_a_local_certificate() {
        let mut flags = gen_default_flags();
        flags.camouflage_config_mut().server_names = vec!["challenges.cloudflare.com".to_owned()];
        flags
            .camouflage_config_mut()
            .set_decoy_upstream("challenges.cloudflare.com:443".to_owned());
        assert!(server_identity_paths(&flags).is_empty());
        assert!(skip_server_verification(&flags));
    }

    #[test]
    fn stealth_crypto_provider_is_process_wide() {
        assert!(std::sync::Arc::ptr_eq(
            &stealth_crypto_provider(),
            &stealth_crypto_provider()
        ));
    }

    #[test]
    fn browser_like_ciphers_match_chrome_and_safari_order() {
        let ids: Vec<_> = browser_like_provider()
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect();
        let aes128 = ids
            .iter()
            .position(|suite| *suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
            .unwrap();
        let aes256 = ids
            .iter()
            .position(|suite| *suite == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
            .unwrap();
        let chacha = ids
            .iter()
            .position(|suite| *suite == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .unwrap();
        assert!(aes128 < aes256 && aes256 < chacha);
        assert_ne!(
            rustls::crypto::ring::default_provider()
                .cipher_suites
                .first()
                .map(|suite| suite.suite()),
            Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        );
    }

    #[test]
    fn client_server_name_defaults_to_cloudflare_for_ip_targets() {
        let mut flags = crate::common::config::gen_default_flags();
        let ip_url: url::Url = "https://127.0.0.1:443".parse().unwrap();
        let h2_ip_url: url::Url = "h2://127.0.0.1:443".parse().unwrap();
        let quic_ip_url: url::Url = "quic://127.0.0.1:443".parse().unwrap();
        let host_url: url::Url = "wss://edge.example.test:443".parse().unwrap();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        for target in [&ip_url, &h2_ip_url, &quic_ip_url] {
            assert_eq!(
                super::client_server_name(&flags, target, ip).unwrap(),
                rustls::pki_types::ServerName::try_from("challenges.cloudflare.com").unwrap()
            );
        }
        assert_eq!(
            super::client_server_name(&flags, &host_url, ip).unwrap(),
            rustls::pki_types::ServerName::try_from("edge.example.test").unwrap()
        );

        flags.camouflage_config_mut().server_names = vec!["custom.example.test".to_owned()];
        assert_eq!(
            super::client_server_name(&flags, &ip_url, ip).unwrap(),
            rustls::pki_types::ServerName::try_from("custom.example.test").unwrap()
        );
    }

    #[tokio::test]
    async fn server_cert_resolver_rejects_missing_or_unmatched_sni() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let flags = crate::common::config::gen_default_flags();
        let acceptor = TlsAcceptor::from(Arc::new(
            super::rustls_server_config(&flags, &[b"h2"]).unwrap(),
        ));
        let client_cfg = Arc::new(super::rustls_client_config_for(&[b"h2"], false).unwrap());
        let connector = TlsConnector::from(client_cfg);

        // No SNI (IP literal) and wrong SNI ("localhost") must both abort TLS before certificate exchange.
        for bad_sni in [
            rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        ] {
            let (client_io, server_io) = tokio::io::duplex(4096);
            let acceptor = acceptor.clone();
            let server_task = tokio::spawn(async move { acceptor.accept(server_io).await });
            let client_res = connector.connect(bad_sni, client_io).await;
            assert!(client_res.is_err(), "expected missing/wrong SNI to fail handshake");
            assert!(server_task.await.unwrap().is_err());
        }

        // Default SNI ("challenges.cloudflare.com") succeeds cleanly.
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let mut buf = [0_u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });
        let good_sni = rustls::pki_types::ServerName::try_from("challenges.cloudflare.com").unwrap();
        let mut tls = connector.connect(good_sni, client_io).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        server_task.await.unwrap();
    }
}
