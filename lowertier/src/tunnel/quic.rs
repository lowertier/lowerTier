//! QUIC stream control plus bounded DATAGRAM delivery for L2/L3 data.
//!
//! rustls/ring supplies standard TLS 1.3 QUIC packet protection. LowTier's
//! inner Noise session remains responsible for authenticated peer identity.

use super::{
    BatchStreamItem, FromUrl, IpVersion, SinkError, Tunnel, TunnelConnector, TunnelError,
    TunnelListener,
};
use crate::common::{
    config::{Flags, gen_default_flags},
    global_ctx::ArcGlobalCtx,
    underlay_policy::UnderlayPolicy,
};
use crate::tunnel::common::{
    bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
    wait_for_connect_futures,
};
use crate::tunnel::{
    TunnelInfo,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    common::{BatchTunnelWrapper, FramedReader, ZCPacketToBytes},
};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use futures::{Future, FutureExt, Sink, Stream, StreamExt};
use parking_lot::RwLock;
use quinn::{
    ClientConfig, ConnectError, Connection, Endpoint, EndpointConfig, RecvStream, SendStream,
    ServerConfig, TransportConfig, VarInt, congestion::BbrConfig, default_runtime,
};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{io::AsyncWriteExt as _, net::UdpSocket, sync::mpsc, task::JoinHandle};

use super::{
    common::TcpZCPacketToBytes,
    packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacket, ZCPacketType},
};

pub(crate) mod adaptive;
pub(crate) mod brutal;
pub(crate) mod quic_config;
pub(crate) mod wire_profile;

use self::adaptive::{AdaptiveConfig, AdaptiveFactory};

const QUIC_INITIAL_MTU: u16 = 1452;
const QUIC_DATAGRAM_SEND_BUFFER_BYTES: usize = MAX_PACKET_BATCH_SIZE * QUIC_INITIAL_MTU as usize;
const QUIC_RELIABLE_INITIAL_BUFFER_SIZE: usize = 4500;
const QUIC_RELIABLE_MAX_PACKET_SIZE: usize = u16::MAX as usize + PEER_MANAGER_HEADER_SIZE;
const QUIC_SOCKET_BUFFER_BYTES: usize = 7 * 1024 * 1024;

const fn quic_socket_buffer_bytes() -> usize {
    QUIC_SOCKET_BUFFER_BYTES
}

fn configure_quic_socket_buffers(socket: &UdpSocket) {
    let socket = socket2::SockRef::from(socket);
    let target = quic_socket_buffer_bytes();
    if let Err(error) = socket.set_recv_buffer_size(target) {
        tracing::warn!(
            ?error,
            target,
            "failed to increase the QUIC UDP receive buffer"
        );
    }
    if let Err(error) = socket.set_send_buffer_size(target) {
        tracing::warn!(
            ?error,
            target,
            "failed to increase the QUIC UDP send buffer"
        );
    }
}

async fn activate_reliable_lane(
    send: &mut SendStream,
    recv: &mut RecvStream,
    client: bool,
) -> Result<(), TunnelError> {
    if client {
        send.write_all(&[0])
            .await
            .context("activate reliable QUIC lane")?;
        send.flush().await.context("flush reliable QUIC lane")?;
    } else {
        let mut activation = [0_u8; 1];
        recv.read_exact(&mut activation)
            .await
            .context("receive reliable QUIC lane activation")?;
    }
    Ok(())
}

// region config
mod tls {
    use std::sync::Arc;

    use anyhow::Context as _;
    use hmac::{Hmac, Mac};
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::{
        CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
    };
    use sha2::Sha256;

    use crate::{common::config::NetworkIdentity, tunnel::TunnelError};

    const NETWORK_IDENTITY_LABEL: &[u8] = b"lowertier QUIC network identity v1";
    const ED25519_PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    pub(super) struct NetworkTlsIdentity {
        pub(super) certificate: CertificateDer<'static>,
        pub(super) private_key: PrivateKeyDer<'static>,
    }

    pub(super) fn network_identity(
        identity: &NetworkIdentity,
    ) -> Result<Option<NetworkTlsIdentity>, TunnelError> {
        let Some(secret) = identity.network_secret.as_deref() else {
            return Ok(None);
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .context("initialize QUIC network identity derivation")?;
        mac.update(NETWORK_IDENTITY_LABEL);
        mac.update(identity.network_name.as_bytes());
        let seed = mac.finalize().into_bytes();

        let mut key_der = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + seed.len());
        key_der.extend_from_slice(&ED25519_PKCS8_PREFIX);
        key_der.extend_from_slice(seed.as_slice());
        let key_pair = rcgen::KeyPair::from_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)
            .context("create QUIC network identity key")?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]);
        params.alg = &rcgen::PKCS_ED25519;
        params.key_pair = Some(key_pair);
        let certificate = rcgen::Certificate::from_params(params)
            .context("create QUIC network identity certificate")?;
        let certificate_der = CertificateDer::from(
            certificate
                .serialize_der()
                .context("serialize QUIC network identity certificate")?,
        );
        let private_key = PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der()).into();
        Ok(Some(NetworkTlsIdentity {
            certificate: certificate_der,
            private_key,
        }))
    }

    /// QUIC supplies standard TLS 1.3 AEAD, header protection, and key updates.
    /// LowTier's authenticated Noise session remains the peer identity layer,
    /// so the ephemeral self-signed transport certificate is intentionally not
    /// treated as an identity credential.
    #[derive(Debug)]
    struct NoiseAuthenticatedPeerVerifier(Arc<rustls::crypto::CryptoProvider>);

    impl NoiseAuthenticatedPeerVerifier {
        fn new() -> Arc<Self> {
            Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
        }
    }

    #[derive(Debug)]
    struct NetworkCertificateVerifier {
        certificate: CertificateDer<'static>,
        provider: Arc<rustls::crypto::CryptoProvider>,
        root_hints: Vec<DistinguishedName>,
    }

    impl NetworkCertificateVerifier {
        fn new(certificate: CertificateDer<'static>) -> Arc<Self> {
            Arc::new(Self {
                certificate,
                provider: Arc::new(rustls::crypto::ring::default_provider()),
                root_hints: Vec::new(),
            })
        }

        fn verify_certificate(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
        ) -> Result<(), rustls::Error> {
            if intermediates.is_empty() && end_entity.as_ref() == self.certificate.as_ref() {
                Ok(())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }

        fn verify_tls12(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                signature,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                signature,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    impl ServerCertVerifier for NetworkCertificateVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            self.verify_certificate(end_entity, intermediates)?;
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verify_tls12(message, cert, signature)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verify_tls13(message, cert, signature)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes()
        }
    }

    impl ClientCertVerifier for NetworkCertificateVerifier {
        fn client_auth_mandatory(&self) -> bool {
            false
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &self.root_hints
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            self.verify_certificate(end_entity, intermediates)?;
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verify_tls12(message, cert, signature)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.verify_tls13(message, cert, signature)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes()
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

    pub(super) fn server_crypto() -> Result<QuicServerConfig, TunnelError> {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .context("generate ephemeral QUIC certificate")?;
        let cert_der = CertificateDer::from(
            certificate
                .serialize_der()
                .context("serialize ephemeral QUIC certificate")?,
        );
        let key_der = PrivatePkcs8KeyDer::from(certificate.serialize_private_key_der());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure QUIC TLS 1.3 server")?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())
            .context("configure ephemeral QUIC server identity")?;
        QuicServerConfig::try_from(config)
            .context("convert rustls server config to Quinn")
            .map_err(Into::into)
    }

    pub(super) fn network_server_crypto(
        identity: &NetworkIdentity,
    ) -> Result<QuicServerConfig, TunnelError> {
        let Some(identity) = network_identity(identity)? else {
            return server_crypto();
        };
        let verifier = NetworkCertificateVerifier::new(identity.certificate.clone());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure network-authenticated QUIC TLS 1.3 server")?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![identity.certificate], identity.private_key)
            .context("configure QUIC network server identity")?;
        QuicServerConfig::try_from(config)
            .context("convert network rustls server config to Quinn")
            .map_err(Into::into)
    }

    pub(super) fn client_crypto() -> Result<QuicClientConfig, TunnelError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure QUIC TLS 1.3 client")?
            .dangerous()
            .with_custom_certificate_verifier(NoiseAuthenticatedPeerVerifier::new())
            .with_no_client_auth();
        QuicClientConfig::try_from(config)
            .context("convert rustls client config to Quinn")
            .map_err(Into::into)
    }

    pub(super) fn network_client_crypto(
        identity: &NetworkIdentity,
    ) -> Result<QuicClientConfig, TunnelError> {
        let Some(identity) = network_identity(identity)? else {
            return client_crypto();
        };
        let verifier = NetworkCertificateVerifier::new(identity.certificate.clone());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure network-authenticated QUIC TLS 1.3 client")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![identity.certificate], identity.private_key)
            .context("configure QUIC network client identity")?;
        QuicClientConfig::try_from(config)
            .context("convert network rustls client config to Quinn")
            .map_err(Into::into)
    }
}
pub fn transport_config(flags: &Flags) -> Result<Arc<TransportConfig>, TunnelError> {
    let mut config = TransportConfig::default();

    let stream_receive_window = VarInt::from_u64(flags.quic_initial_receive_window)
        .map_err(|error| TunnelError::InternalError(error.to_string()))?;
    let receive_window = VarInt::from_u64(flags.quic_receive_window)
        .map_err(|error| TunnelError::InternalError(error.to_string()))?;

    config
        .max_concurrent_bidi_streams(u8::MAX.into())
        .max_concurrent_uni_streams(0u8.into())
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .initial_mtu(QUIC_INITIAL_MTU)
        .min_mtu(1200)
        .enable_segmentation_offload(true)
        .datagram_receive_buffer_size(Some(16 * 1024 * 1024))
        .datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_BYTES)
        .stream_receive_window(stream_receive_window)
        .receive_window(receive_window);

    match flags.quic_congestion.as_str() {
        "adaptive" => {
            const MIB: u64 = 1024 * 1024;
            let adaptive = AdaptiveFactory::new(AdaptiveConfig {
                min_rate_bps: 128_000,
                initial_rate_bps: 1_000_000,
                max_rate_bps: 1_000_000_000,
                target_wire_bps: Some(750_000_000),
                max_cwnd_bytes: 128 * MIB,
                probe_seed: 0x4554_5155_4943_0001,
            })
            .map_err(|error| TunnelError::InternalError(error.to_string()))?;
            config.congestion_controller_factory(Arc::new(adaptive));
        }
        "bbr" => {
            config.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        "brutal" => {
            let brutal = brutal::BrutalConfig::new(
                flags.quic_brutal_send_bps,
                flags.quic_brutal_loss_compensation,
            )
            .map_err(|error| TunnelError::InternalError(error.into()))?;
            config.congestion_controller_factory(Arc::new(brutal));
        }
        controller => {
            return Err(TunnelError::InternalError(format!(
                "unsupported QUIC congestion controller {controller:?}"
            )));
        }
    }

    Ok(Arc::new(config))
}

pub fn server_config(flags: &Flags) -> Result<ServerConfig, TunnelError> {
    let mut config = ServerConfig::with_crypto(Arc::new(tls::server_crypto()?));
    config.transport_config(transport_config(flags)?);
    Ok(config)
}

pub fn client_config(flags: &Flags) -> Result<ClientConfig, TunnelError> {
    let mut config = ClientConfig::new(Arc::new(tls::client_crypto()?));
    config.transport_config(transport_config(flags)?);
    Ok(config)
}

fn server_config_for_network(
    flags: &Flags,
    identity: &crate::common::config::NetworkIdentity,
) -> Result<ServerConfig, TunnelError> {
    let mut config = ServerConfig::with_crypto(Arc::new(tls::network_server_crypto(identity)?));
    config.transport_config(transport_config(flags)?);
    Ok(config)
}

fn client_config_for_network(
    flags: &Flags,
    identity: &crate::common::config::NetworkIdentity,
) -> Result<ClientConfig, TunnelError> {
    let mut config = ClientConfig::new(Arc::new(tls::network_client_crypto(identity)?));
    config.transport_config(transport_config(flags)?);
    Ok(config)
}

fn connection_has_network_identity(
    connection: &Connection,
    identity: &crate::common::config::NetworkIdentity,
) -> bool {
    let Ok(Some(expected)) = tls::network_identity(identity) else {
        return false;
    };
    let Some(peer_identity) = connection.peer_identity() else {
        return false;
    };
    let Ok(certificates) =
        peer_identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
    else {
        return false;
    };
    certificates.len() == 1 && certificates[0].as_ref() == expected.certificate.as_ref()
}

pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    // QUIC starts at the conservative 1200-byte MTU configured above and may
    // probe upward. This ceiling lets local/Ethernet paths carry a normal VPN
    // frame in one DATAGRAM after PMTU discovery.
    config.max_udp_payload_size(1500).unwrap();
    config
}
//endregion

//region rw pool
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derive(Debug, Deref, DerefMut)]
struct RwPoolInner<Item> {
    #[deref]
    #[deref_mut]
    pool: Vec<Item>,
    enabled: bool,
}

#[derive(Debug)]
struct RwPool<Item> {
    ephemeral: RwLock<RwPoolInner<Item>>,
    persistent: RwLock<RwPoolInner<Item>>,
    capacity: usize,
}

impl<Item> RwPool<Item> {
    fn new(capacity: usize) -> Self {
        Self {
            ephemeral: RwLock::new(RwPoolInner::default()),
            persistent: RwLock::new(RwPoolInner::default()),
            capacity,
        }
    }

    /// return the capacity of the ephemeral pool;
    /// if `ephemeral` or `persistent` is None, read lock `self`'s pool
    fn capacity(
        &self,
        ephemeral: Option<&RwPoolInner<Item>>,
        persistent: Option<&RwPoolInner<Item>>,
    ) -> usize {
        let guard;
        let ephemeral = if let Some(ephemeral) = ephemeral {
            ephemeral
        } else {
            guard = self.ephemeral.read();
            &guard
        };

        let guard;
        let persistent = if let Some(persistent) = persistent {
            persistent
        } else {
            guard = self.persistent.read();
            &guard
        };

        (self.capacity * ephemeral.enabled as usize).saturating_sub(persistent.len())
    }

    fn is_full(&self) -> bool {
        let pool = self.ephemeral.read();
        pool.len() >= self.capacity(Some(&pool), None)
    }

    fn is_enabled(&self) -> bool {
        self.ephemeral.read().enabled
    }

    fn enable(&self) {
        self.ephemeral.write().enabled = true;
        self.resize();
    }

    fn disable(&self) {
        self.ephemeral.write().enabled = false;
        self.resize();
    }

    /// push an item to the persistent pool
    fn push(&self, item: Item) {
        self.persistent.write().push(item);
        self.resize();
    }

    fn len(&self) -> usize {
        let persistent_len = self.persistent.read().len();
        let ephemeral_len = self.ephemeral.read().len();
        persistent_len + ephemeral_len
    }

    /// try to push an item to the ephemeral pool, return the item if full
    fn try_push(&self, item: Item) -> Option<Item> {
        let mut pool = self.ephemeral.write();
        if pool.len() < self.capacity(Some(&pool), None) {
            pool.push(item);
            return None;
        }
        Some(item)
    }

    fn resize(&self) {
        let resize = {
            let pool = self.ephemeral.read();
            pool.capacity() != self.capacity(Some(&pool), None)
        };
        if resize {
            let mut pool = self.ephemeral.write();
            let capacity = self.capacity(Some(&pool), None);
            pool.reserve_exact(capacity);
            pool.truncate(capacity);
            pool.shrink_to(capacity);
        }
    }

    fn with_iter<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn Iterator<Item = &Item>) -> R,
    {
        let ephemeral = self.ephemeral.read();
        let persistent = self.persistent.read();
        f(&mut persistent.iter().chain(ephemeral.iter()))
    }
}

impl RwPool<Endpoint> {
    fn retain_endpoints<F>(&self, mut keep: F) -> usize
    where
        F: FnMut(&Endpoint) -> bool,
    {
        let persistent_removed = {
            let mut persistent = self.persistent.write();
            let before = persistent.len();
            persistent.retain(|endpoint| keep(endpoint));
            before - persistent.len()
        };

        let ephemeral_removed = {
            let mut ephemeral = self.ephemeral.write();
            let before = ephemeral.len();
            ephemeral.retain(|endpoint| keep(endpoint));
            before - ephemeral.len()
        };

        let removed = persistent_removed + ephemeral_removed;
        if removed > 0 {
            self.resize();
        }
        removed
    }

    fn remove_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        self.retain_endpoints(|endpoint| endpoint.local_addr().ok() != Some(local_addr))
    }

    fn contains_local_addr(&self, local_addr: SocketAddr) -> bool {
        self.persistent
            .read()
            .iter()
            .any(|endpoint| endpoint.local_addr().ok() == Some(local_addr))
            || self
                .ephemeral
                .read()
                .iter()
                .any(|endpoint| endpoint.local_addr().ok() == Some(local_addr))
    }
}
//endregion

//region endpoint manager
#[derive(Debug)]
pub struct QuicEndpointManager {
    ipv4: RwPool<Endpoint>,
    ipv6: RwPool<Endpoint>,
    both: RwPool<Endpoint>,
}

static QUIC_ENDPOINT_MANAGER: OnceLock<QuicEndpointManager> = OnceLock::new();

#[derive(Clone, Copy)]
struct QuicConnectSecurity<'a> {
    flags: &'a Flags,
    identity: &'a crate::common::config::NetworkIdentity,
    allow_noise_protected_transport: bool,
}

impl QuicEndpointManager {
    fn try_create(
        addr: SocketAddr,
        dual_stack: bool,
        socket_mark: Option<u32>,
    ) -> Result<Endpoint, TunnelError> {
        let socket = bind::<UdpSocket>()
            .addr(addr)
            .only_v6(addr.is_ipv6() && !dual_stack)
            .maybe_socket_mark(socket_mark)
            .call()?;
        configure_quic_socket_buffers(&socket);
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            runtime.wrap_udp_socket(socket.into_std()?)?,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config(&gen_default_flags())?);
        Ok(endpoint)
    }

    fn create<F>(
        &self,
        socket_mark: Option<u32>,
        mut selector: F,
    ) -> Result<(&RwPool<Endpoint>, Option<Endpoint>), TunnelError>
    where
        F: FnMut(&QuicEndpointManager) -> (&RwPool<Endpoint>, Option<(SocketAddr, bool)>),
    {
        loop {
            let (pool, r) = selector(self);
            let Some((addr, dual_stack)) = r else {
                return Ok((pool, None));
            };

            let endpoint = Self::try_create(addr, dual_stack, socket_mark);
            if let Err(error) = endpoint.as_ref()
                && dual_stack
            {
                tracing::warn!(?error, "create dual stack quic endpoint failed");
                self.both.disable();
                self.ipv4.enable();
                self.ipv6.enable();
                continue;
            }

            return Ok((pool, Some(endpoint?)));
        }
    }
}

impl QuicEndpointManager {
    fn new(capacity: usize) -> Self {
        let ipv4 = RwPool::new(capacity.div_ceil(2));
        let ipv6 = RwPool::new(capacity.div_ceil(2));
        let both = RwPool::new(capacity);
        both.enable();
        Self { ipv4, ipv6, both }
    }

    fn load(global_ctx: &ArcGlobalCtx) -> &Self {
        let capacity = global_ctx
            .config
            .get_flags()
            .multi_thread
            .then(std::thread::available_parallelism)
            .and_then(|r| r.ok())
            .map(|n| n.get())
            .unwrap_or(1);

        let mgr = QUIC_ENDPOINT_MANAGER.get();
        match mgr {
            Some(mgr) => {
                for pool in [&mgr.ipv4, &mgr.ipv6, &mgr.both] {
                    pool.resize();
                }
            }
            None => {
                let _ = QUIC_ENDPOINT_MANAGER.set(Self::new(capacity));
            }
        }

        QUIC_ENDPOINT_MANAGER.get().unwrap()
    }

    fn client_pool(&self, ip_version: IpVersion) -> &RwPool<Endpoint> {
        let dual_stack = self.both.is_enabled();
        match ip_version {
            IpVersion::V4 if !dual_stack => &self.ipv4,
            _ => {
                if dual_stack {
                    &self.both
                } else {
                    &self.ipv6
                }
            }
        }
    }

    /// Get a QUIC endpoint to be used as a server
    ///
    /// # Arguments
    /// * `addr`: listen address
    fn server(global_ctx: &ArcGlobalCtx, addr: SocketAddr) -> Result<Endpoint, TunnelError> {
        let mgr = Self::load(global_ctx);
        let socket_mark = global_ctx.config.get_flags().socket_mark;

        let (pool, endpoint) = mgr.create(socket_mark, |mgr| {
            let dual_stack = addr.ip() == Ipv6Addr::UNSPECIFIED && mgr.both.is_enabled();
            let pool = if addr.is_ipv4() {
                &mgr.ipv4
            } else if dual_stack {
                &mgr.both
            } else {
                &mgr.ipv6
            };
            (pool, Some((addr, dual_stack)))
        })?;

        let endpoint = endpoint.expect("server endpoint creation should not return None");
        endpoint.set_server_config(Some(server_config_for_network(
            &global_ctx.get_flags(),
            &global_ctx.get_network_identity(),
        )?));
        pool.push(endpoint.clone());

        Ok(endpoint)
    }

    fn client_endpoint(
        &self,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
    ) -> Result<Endpoint, TunnelError> {
        let (pool, endpoint) = self.create(socket_mark, |mgr| {
            let dual_stack = mgr.both.is_enabled();
            let (pool, addr) = match ip_version {
                IpVersion::V4 if !dual_stack => (&mgr.ipv4, (Ipv4Addr::UNSPECIFIED, 0).into()),
                _ => {
                    let pool = if dual_stack { &mgr.both } else { &mgr.ipv6 };
                    (pool, (Ipv6Addr::UNSPECIFIED, 0).into())
                }
            };
            if pool.is_full() {
                (pool, None)
            } else {
                (pool, Some((addr, dual_stack)))
            }
        })?;

        if let Some(endpoint) = endpoint {
            pool.try_push(endpoint);
        }

        Ok(pool.with_iter(|iter| iter.min_by_key(|e| e.open_connections()).unwrap().clone()))
    }

    fn client_endpoint_for_source(
        &self,
        source: SocketAddr,
        socket_mark: Option<u32>,
        policy: &UnderlayPolicy,
    ) -> Result<Endpoint, TunnelError> {
        ensure_local_allowed(policy, source)?;
        let pool = if source.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };

        if let Some(endpoint) = pool.with_iter(|iter| {
            iter.filter(|endpoint| {
                endpoint
                    .local_addr()
                    .is_ok_and(|local| local.ip() == source.ip())
            })
            .min_by_key(|endpoint| endpoint.open_connections())
            .cloned()
        }) {
            return Ok(endpoint);
        }

        let endpoint = Self::try_create(source, false, socket_mark)?;
        Ok(self.retain_source_endpoint(endpoint))
    }

    fn retain_source_endpoint(&self, endpoint: Endpoint) -> Endpoint {
        let pool = if endpoint
            .local_addr()
            .is_ok_and(|local_addr| local_addr.is_ipv4())
        {
            &self.ipv4
        } else {
            &self.ipv6
        };
        pool.enable();
        let connection_owner = endpoint.clone();
        pool.try_push(endpoint).unwrap_or(connection_owner)
    }

    fn remove_endpoint(&self, endpoint: &Endpoint) -> usize {
        let Ok(local_addr) = endpoint.local_addr() else {
            return 0;
        };
        self.remove_endpoint_by_local_addr(local_addr)
    }

    fn remove_endpoint_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        [&self.ipv4, &self.ipv6, &self.both]
            .into_iter()
            .map(|pool| pool.remove_by_local_addr(local_addr))
            .sum()
    }

    fn contains_local_addr(&self, local_addr: SocketAddr) -> bool {
        [&self.ipv4, &self.ipv6, &self.both]
            .into_iter()
            .any(|pool| pool.contains_local_addr(local_addr))
    }

    async fn connect(
        global_ctx: &ArcGlobalCtx,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
        policy: Arc<UnderlayPolicy>,
    ) -> Result<(Endpoint, Connection, bool), TunnelError> {
        let ip_version = if addr.ip().is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let flags = global_ctx.get_flags();
        let identity = global_ctx.get_network_identity();
        let allow_noise_protected_transport = global_ctx
            .config
            .get_secure_mode()
            .is_some_and(|config| config.enabled);
        let security = QuicConnectSecurity {
            flags: &flags,
            identity: &identity,
            allow_noise_protected_transport,
        };
        let socket_mark = flags.socket_mark;
        ensure_remote_allowed(&policy, addr)?;
        let bind_addrs = eligible_bind_addrs(&policy, bind_addrs, addr)?;
        let manager = Self::load(global_ctx);
        if bind_addrs.is_empty() {
            return manager
                .connect_with_ip_version(addr, ip_version, socket_mark, security)
                .await;
        }

        let futures = futures::stream::FuturesUnordered::new();
        for source in bind_addrs {
            futures.push(manager.connect_with_source(
                addr,
                source,
                socket_mark,
                policy.clone(),
                security,
            ));
        }
        wait_for_connect_futures(futures).await
    }

    async fn connect_with_source(
        &self,
        addr: SocketAddr,
        source: SocketAddr,
        socket_mark: Option<u32>,
        policy: Arc<UnderlayPolicy>,
        security: QuicConnectSecurity<'_>,
    ) -> Result<(Endpoint, Connection, bool), TunnelError> {
        let pool = if source.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };
        let max_endpoint_stopping_retries = pool.len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint_for_source(source, socket_mark, &policy)?;
            let server_name = addr.ip().to_string();
            let connecting = match endpoint.connect_with(
                client_config_for_network(security.flags, security.identity)?,
                addr,
                &server_name,
            ) {
                Ok(connecting) => connecting,
                Err(ConnectError::EndpointStopping) => {
                    self.remove_endpoint(&endpoint);
                    endpoint_stopping_retries += 1;
                    if endpoint_stopping_retries > max_endpoint_stopping_retries {
                        return Err(anyhow::Error::new(ConnectError::EndpointStopping)
                            .context(format!("failed to create connection to {}", addr))
                            .into());
                    }
                    continue;
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context(format!("failed to create connection to {}", addr))
                        .into());
                }
            };
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(authentication_error) if security.allow_noise_protected_transport => {
                    tracing::debug!(
                        ?authentication_error,
                        %addr,
                        "network identity unavailable; using Noise-protected QUIC"
                    );
                    endpoint
                        .connect_with(client_config(security.flags)?, addr, &server_name)
                        .with_context(|| format!("failed to start Noise-protected QUIC to {addr}"))?
                        .await
                        .with_context(|| {
                            format!("failed to connect Noise-protected QUIC to {addr}")
                        })?
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context(format!("failed to authenticate QUIC connection to {addr}"))
                        .into());
                }
            };
            ensure_local_allowed(&policy, endpoint.local_addr()?)?;
            ensure_remote_allowed(&policy, connection.remote_address())?;
            let authenticated = connection_has_network_identity(&connection, security.identity);
            return Ok((endpoint, connection, authenticated));
        }
    }

    async fn connect_with_ip_version(
        &self,
        addr: SocketAddr,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
        security: QuicConnectSecurity<'_>,
    ) -> Result<(Endpoint, Connection, bool), TunnelError> {
        let max_endpoint_stopping_retries = self.client_pool(ip_version).len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint(ip_version, socket_mark)?;
            let server_name = addr.ip().to_string();
            let connecting = match endpoint.connect_with(
                client_config_for_network(security.flags, security.identity)?,
                addr,
                &server_name,
            ) {
                Ok(connecting) => connecting,
                Err(ConnectError::EndpointStopping) => {
                    let local_addr = endpoint.local_addr().ok();
                    let removed = self.remove_endpoint(&endpoint);
                    endpoint_stopping_retries += 1;
                    tracing::warn!(
                        ?addr,
                        ?local_addr,
                        removed,
                        "removed stopped quic endpoint and retry connect"
                    );
                    if endpoint_stopping_retries > max_endpoint_stopping_retries {
                        return Err(anyhow::Error::new(ConnectError::EndpointStopping)
                            .context(format!("failed to create connection to {}", addr))
                            .into());
                    }
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("failed to create connection to {}", addr))
                        .into());
                }
            };
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(authentication_error) if security.allow_noise_protected_transport => {
                    tracing::debug!(
                        ?authentication_error,
                        %addr,
                        "network identity unavailable; using Noise-protected QUIC"
                    );
                    endpoint
                        .connect_with(client_config(security.flags)?, addr, &server_name)
                        .with_context(|| format!("failed to start Noise-protected QUIC to {addr}"))?
                        .await
                        .with_context(|| {
                            format!("failed to connect Noise-protected QUIC to {addr}")
                        })?
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context(format!("failed to authenticate QUIC connection to {addr}"))
                        .into());
                }
            };

            let authenticated = connection_has_network_identity(&connection, security.identity);
            return Ok((endpoint, connection, authenticated));
        }
    }
}
//endregion

struct ConnWrapper {
    conn: Connection,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

static QUIC_STATS_INTERVAL: OnceLock<Option<Duration>> = OnceLock::new();

fn quic_stats_interval_from(value: Option<&str>) -> Option<Duration> {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|milliseconds| *milliseconds > 0)
        .map(Duration::from_millis)
}

fn quic_stats_interval() -> Option<Duration> {
    *QUIC_STATS_INTERVAL.get_or_init(|| {
        let value = std::env::var("LOWTIER_QUIC_STATS_INTERVAL_MS").ok();
        quic_stats_interval_from(value.as_deref())
    })
}

fn observe_quic_path(connection: &Arc<ConnWrapper>) {
    let Some(period) = quic_stats_interval() else {
        return;
    };
    let connection = Arc::downgrade(connection);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(connection) = connection.upgrade() else {
                break;
            };
            let stats = connection.conn.stats();
            tracing::info!(
                target: "CORE::TUNNEL::QUIC_PATH",
                connection = connection.conn.stable_id(),
                remote = %connection.conn.remote_address(),
                tx_datagrams = stats.udp_tx.datagrams,
                tx_bytes = stats.udp_tx.bytes,
                tx_ios = stats.udp_tx.ios,
                rx_datagrams = stats.udp_rx.datagrams,
                rx_bytes = stats.udp_rx.bytes,
                rx_ios = stats.udp_rx.ios,
                tx_frames = stats.frame_tx.datagram,
                rx_frames = stats.frame_rx.datagram,
                rtt_us = stats.path.rtt.as_micros(),
                cwnd = stats.path.cwnd,
                congestion_events = stats.path.congestion_events,
                lost_packets = stats.path.lost_packets,
                lost_bytes = stats.path.lost_bytes,
                sent_packets = stats.path.sent_packets,
                mtu = stats.path.current_mtu,
                send_buffer_space = connection.conn.datagram_send_buffer_space(),
                "QUIC path statistics"
            );
        }
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuicDelivery {
    PlainDatagram,
    ReliableStream,
}

fn select_quic_delivery(packet: &ZCPacket, max_datagram_size: Option<usize>) -> QuicDelivery {
    let critical_l2 = packet
        .peer_manager_header()
        .is_some_and(|header| header.is_critical_l2_control());
    let fits_datagram =
        max_datagram_size.is_some_and(|maximum| packet.tunnel_payload().len() <= maximum);
    if packet.is_lossy() && !critical_l2 && fits_datagram {
        return QuicDelivery::PlainDatagram;
    }
    QuicDelivery::ReliableStream
}

fn encode_quic_datagram(packet: ZCPacket) -> Bytes {
    packet.convert_type(ZCPacketType::DummyTunnel).into_bytes()
}

fn decode_quic_datagram(bytes: Bytes) -> Result<ZCPacket, TunnelError> {
    if bytes.len() < PEER_MANAGER_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "QUIC DATAGRAM is too short: {} < {}",
            bytes.len(),
            PEER_MANAGER_HEADER_SIZE
        )));
    }

    // Quinn hands ownership of a Bytes allocation to the application. Reuse
    // it directly when unique and copy only if another reference exists.
    let bytes = bytes
        .try_into_mut()
        .unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
    Ok(ZCPacket::new_from_buf(bytes, ZCPacketType::DummyTunnel))
}

fn decode_received_quic_datagram(bytes: Bytes) -> Option<ZCPacket> {
    match decode_quic_datagram(bytes) {
        Ok(packet) => Some(packet),
        Err(error) => {
            tracing::debug!(?error, "dropping malformed QUIC DATAGRAM");
            None
        }
    }
}

/// Combines reliable QUIC control frames with the unordered DATAGRAM data
/// lane. Poll preference alternates so a saturated data lane cannot starve
/// control traffic and vice versa.
struct QuicHybridReader {
    reliable: mpsc::Receiver<BatchStreamItem>,
    connection: Arc<ConnWrapper>,
    datagrams: Pin<Box<quinn::ReadDatagrams>>,
    poll_datagram_first: bool,
}

impl QuicHybridReader {
    fn new(reliable: mpsc::Receiver<BatchStreamItem>, connection: Arc<ConnWrapper>) -> Self {
        let datagrams = Box::pin(connection.conn.read_datagrams(
            Vec::with_capacity(MAX_PACKET_BATCH_SIZE),
            MAX_PACKET_BATCH_SIZE,
        ));
        Self {
            reliable,
            connection,
            datagrams,
            poll_datagram_first: true,
        }
    }

    fn decode_datagram_batch(datagrams: &mut Vec<Bytes>) -> Option<PacketBatch> {
        let mut batch = PacketBatch::with_capacity(datagrams.len());
        for bytes in datagrams.drain(..) {
            if let Some(packet) = decode_received_quic_datagram(bytes) {
                batch
                    .try_push(packet)
                    .expect("the QUIC receive batch has a fixed bound");
            }
        }
        (!batch.is_empty()).then_some(batch)
    }

    fn poll_datagram(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<BatchStreamItem>> {
        const MAX_INVALID_BATCHES_PER_POLL: usize = 4;
        for _ in 0..MAX_INVALID_BATCHES_PER_POLL {
            match self.datagrams.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(mut datagrams)) => {
                    let batch = Self::decode_datagram_batch(&mut datagrams);
                    self.datagrams = Box::pin(
                        self.connection
                            .conn
                            .read_datagrams(datagrams, MAX_PACKET_BATCH_SIZE),
                    );
                    if let Some(batch) = batch {
                        return Poll::Ready(Some(Ok(batch)));
                    }
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Some(Err(TunnelError::Anyhow(
                        anyhow::Error::new(error).context("read QUIC DATAGRAM batch failed"),
                    ))));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_reliable(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<BatchStreamItem>> {
        self.reliable.poll_recv(cx)
    }
}

impl Stream for QuicHybridReader {
    type Item = BatchStreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let datagram_first = self.poll_datagram_first;
        self.poll_datagram_first = !datagram_first;

        if datagram_first {
            if let Poll::Ready(item) = self.poll_datagram(cx) {
                return Poll::Ready(item);
            }
            self.poll_reliable(cx)
        } else {
            if let Poll::Ready(item) = self.poll_reliable(cx) {
                return Poll::Ready(item);
            }
            self.poll_datagram(cx)
        }
    }
}

struct QuicHybridWriter {
    connection: Arc<ConnWrapper>,
    pending_datagrams: Option<VecDeque<Bytes>>,
    pending_datagram_send: Option<DatagramBatchSend>,
    reliable_tx: Option<mpsc::Sender<PacketBatch>>,
    pending_reliable: Option<PacketBatch>,
    reliable_reserve: Option<ReliableReserve>,
    reliable_task: Option<JoinHandle<Result<(), TunnelError>>>,
}

type ReliableReserve = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<PacketBatch>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;
type DatagramBatchSend =
    Pin<Box<dyn Future<Output = (Result<(), quinn::SendDatagramError>, VecDeque<Bytes>)> + Send>>;

const RELIABLE_LANE_QUEUE_BATCHES: usize = 1;

#[derive(Clone, Copy, Debug)]
enum ReliableLaneRole {
    Initiator,
    Acceptor,
}

fn poll_reliable_reservation(
    reservation: &mut Option<ReliableReserve>,
    cx: &mut TaskContext<'_>,
) -> Poll<Result<mpsc::OwnedPermit<PacketBatch>, SinkError>> {
    let reserve = reservation
        .as_mut()
        .expect("the reliable reservation exists before polling");
    match reserve.as_mut().poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
            *reservation = None;
            Poll::Ready(Ok(permit))
        }
        Poll::Ready(Err(_)) => {
            *reservation = None;
            Poll::Ready(Err(TunnelError::InternalError(
                "reliable QUIC lane stopped".to_owned(),
            )))
        }
    }
}

async fn run_reliable_writer(
    mut send: SendStream,
    receiver: &mut mpsc::Receiver<PacketBatch>,
    pending: &mut Option<Vec<Bytes>>,
) -> Result<(), TunnelError> {
    loop {
        if pending.is_none() {
            let Some(batch) = receiver.recv().await else {
                send.finish().context("finish reliable QUIC lane")?;
                return Ok(());
            };
            let converter = TcpZCPacketToBytes;
            let mut frames = Vec::with_capacity(batch.len());
            for packet in batch {
                frames.push(converter.zcpacket_into_bytes(packet)?);
            }
            *pending = Some(frames);
        }

        tokio::time::timeout(Duration::from_secs(7), async {
            for frame in pending.as_ref().unwrap() {
                send.write_all(frame).await?;
            }
            send.flush().await
        })
        .await
        .context("reliable QUIC lane timed out")??;
        pending.take();
    }
}

async fn run_reliable_reader(
    recv: RecvStream,
    max_packet_size: usize,
    sender: &mpsc::Sender<BatchStreamItem>,
) -> Result<(), TunnelError> {
    let mut reader = FramedReader::new_with_initial_capacity(
        recv,
        max_packet_size,
        QUIC_RELIABLE_INITIAL_BUFFER_SIZE,
    );
    loop {
        let Some(first) = reader.next().await else {
            return Ok(());
        };
        let first = first?;
        let mut batch = PacketBatch::new();
        batch
            .try_push(first)
            .expect("a new reliable QUIC batch accepts one packet");
        let mut reached_end = false;
        while batch.len() < MAX_PACKET_BATCH_SIZE {
            match reader.next().now_or_never() {
                Some(Some(Ok(packet))) => batch
                    .try_push(packet)
                    .expect("the reliable QUIC batch checks its bound"),
                Some(Some(Err(error))) => return Err(error),
                Some(None) => {
                    reached_end = true;
                    break;
                }
                None => break,
            }
        }
        sender
            .send(Ok(batch))
            .await
            .map_err(|_| TunnelError::InternalError("QUIC tunnel reader stopped".to_owned()))?;
        if reached_end {
            return Ok(());
        }
    }
}

async fn open_replacement_reliable_lane(
    connection: &Connection,
    role: ReliableLaneRole,
) -> Result<(SendStream, RecvStream), TunnelError> {
    let (mut send, mut recv) = match role {
        ReliableLaneRole::Initiator => connection
            .open_bi()
            .await
            .with_context(|| "open replacement reliable QUIC lane")?,
        ReliableLaneRole::Acceptor => connection
            .accept_bi()
            .await
            .with_context(|| "accept replacement reliable QUIC lane")?,
    };
    activate_reliable_lane(
        &mut send,
        &mut recv,
        matches!(role, ReliableLaneRole::Initiator),
    )
    .await?;
    Ok((send, recv))
}

async fn run_reliable_lane(
    connection: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    role: ReliableLaneRole,
    max_packet_size: usize,
    mut outgoing: mpsc::Receiver<PacketBatch>,
    incoming: mpsc::Sender<BatchStreamItem>,
) -> Result<(), TunnelError> {
    let mut pending = None;
    loop {
        let writer = run_reliable_writer(send, &mut outgoing, &mut pending);
        let reader = run_reliable_reader(recv, max_packet_size, &incoming);
        tokio::pin!(writer, reader);

        let lane_error = tokio::select! {
            result = &mut writer => match result {
                Ok(()) => return Ok(()),
                Err(error) => error,
            },
            result = &mut reader => match result {
                Ok(()) => return Ok(()),
                Err(_error) if incoming.is_closed() => return Ok(()),
                Err(error) => error,
            },
            error = connection.closed() => {
                return Err(anyhow::Error::new(error)
                    .context("QUIC connection closed during reliable lane operation")
                    .into());
            }
        };

        tracing::warn!(?lane_error, ?role, "recovering reliable QUIC lane");
        if connection.close_reason().is_some() {
            return Err(lane_error);
        }
        (send, recv) = open_replacement_reliable_lane(&connection, role).await?;
    }
}

impl QuicHybridWriter {
    fn new(
        reliable_tx: mpsc::Sender<PacketBatch>,
        reliable_task: JoinHandle<Result<(), TunnelError>>,
        connection: Arc<ConnWrapper>,
    ) -> Self {
        Self {
            connection,
            pending_datagrams: Some(VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE)),
            pending_datagram_send: None,
            reliable_tx: Some(reliable_tx),
            pending_reliable: None,
            reliable_reserve: None,
            reliable_task: Some(reliable_task),
        }
    }

    fn begin_datagram_flush(&mut self) {
        if self.pending_datagram_send.is_some()
            || self
                .pending_datagrams
                .as_ref()
                .is_none_or(VecDeque::is_empty)
        {
            return;
        }
        let datagrams = self
            .pending_datagrams
            .take()
            .expect("the pending QUIC batch is available before a flush");
        let connection = self.connection.conn.clone();
        self.pending_datagram_send = Some(Box::pin(async move {
            connection.send_datagrams_wait(datagrams).await
        }));
    }

    fn poll_datagram_queue(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        let Some(send) = self.pending_datagram_send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match send.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((result, mut datagrams)) => {
                datagrams.clear();
                self.pending_datagrams = Some(datagrams);
                self.pending_datagram_send = None;
                match result {
                    Ok(()) | Err(quinn::SendDatagramError::TooLarge) => Poll::Ready(Ok(())),
                    Err(error) => Poll::Ready(Err(TunnelError::Anyhow(
                        anyhow::Error::new(error).context("send QUIC DATAGRAM batch failed"),
                    ))),
                }
            }
        }
    }

    fn poll_ready_queues(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        if self
            .pending_datagrams
            .as_ref()
            .is_some_and(|datagrams| !datagrams.is_empty())
        {
            self.begin_datagram_flush();
        }
        match self.poll_datagram_queue(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => self.poll_reliable_queue(cx),
        }
    }

    fn poll_flush_queues(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        self.begin_datagram_flush();
        match self.poll_datagram_queue(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => self.poll_reliable_queue(cx),
        }
    }

    fn poll_reliable_queue(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        if self.pending_reliable.is_none() {
            return Poll::Ready(Ok(()));
        }
        if self.reliable_reserve.is_none() {
            let sender = self.reliable_tx.as_ref().ok_or_else(|| {
                TunnelError::InternalError("reliable QUIC lane is closed".to_owned())
            })?;
            self.reliable_reserve = Some(Box::pin(sender.clone().reserve_owned()));
        }

        match poll_reliable_reservation(&mut self.reliable_reserve, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                let packet = self.pending_reliable.take().unwrap();
                permit.send(packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}

impl Drop for QuicHybridWriter {
    fn drop(&mut self) {
        if let Some(task) = self.reliable_task.take() {
            task.abort();
        }
    }
}

impl Sink<PacketBatch> for QuicHybridWriter {
    type Error = SinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_ready_queues(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        let writer = self.as_mut().get_mut();
        let maximum = writer.connection.conn.max_datagram_size();
        let mut reliable = PacketBatch::with_capacity(batch.len());
        if writer.pending_reliable.is_some() {
            return Err(TunnelError::InternalError(
                "QUIC batch started without sink readiness".to_owned(),
            ));
        }
        let datagrams = writer.pending_datagrams.as_mut().ok_or_else(|| {
            TunnelError::InternalError(
                "QUIC DATAGRAM batch started while a flush is active".to_owned(),
            )
        })?;
        if !datagrams.is_empty() {
            return Err(TunnelError::InternalError(
                "QUIC batch started without sink readiness".to_owned(),
            ));
        }

        for packet in batch {
            match select_quic_delivery(&packet, maximum) {
                QuicDelivery::PlainDatagram => datagrams.push_back(encode_quic_datagram(packet)),
                QuicDelivery::ReliableStream => reliable
                    .try_push(packet)
                    .expect("the reliable subset cannot exceed its input batch"),
            }
        }

        if reliable.is_empty() {
            return Ok(());
        }
        let Some(sender) = writer.reliable_tx.as_ref() else {
            return Err(TunnelError::InternalError(
                "reliable QUIC lane is closed".to_owned(),
            ));
        };
        match sender.try_send(reliable) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(batch)) => {
                writer.pending_reliable = Some(batch);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TunnelError::InternalError(
                "reliable QUIC lane stopped".to_owned(),
            )),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_flush_queues(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().get_mut().poll_flush_queues(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        let writer = self.as_mut().get_mut();
        writer.reliable_tx.take();
        let Some(task) = writer.reliable_task.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                writer.reliable_task = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(error)) => {
                writer.reliable_task = None;
                Poll::Ready(Err(TunnelError::Anyhow(anyhow::Error::new(error))))
            }
        }
    }
}

fn build_quic_hybrid_tunnel(
    connection: Connection,
    reliable_send: SendStream,
    reliable_recv: RecvStream,
    reliable_role: ReliableLaneRole,
    max_packet_size: usize,
    info: TunnelInfo,
    _flags: &Flags,
    transport_authenticated: bool,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let connection = Arc::new(ConnWrapper { conn: connection });
    observe_quic_path(&connection);
    let (reliable_tx, reliable_outgoing) = mpsc::channel(RELIABLE_LANE_QUEUE_BATCHES);
    let (reliable_incoming, reliable_rx) = mpsc::channel(RELIABLE_LANE_QUEUE_BATCHES);
    let reliable_task = tokio::spawn(run_reliable_lane(
        connection.conn.clone(),
        reliable_send,
        reliable_recv,
        reliable_role,
        max_packet_size,
        reliable_outgoing,
        reliable_incoming,
    ));
    Ok(Box::new(
        BatchTunnelWrapper::new_with_transport_authentication(
            QuicHybridReader::new(reliable_rx, connection.clone()),
            QuicHybridWriter::new(reliable_tx, reliable_task, connection),
            Some(info),
            transport_authenticated,
        ),
    ))
}

pub struct QuicTunnelListener {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    endpoint: Option<Endpoint>,
}

impl QuicTunnelListener {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelListener {
            addr,
            global_ctx,
            endpoint: None,
        }
    }

    async fn do_accept(&self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // accept a single connection
        let conn = self
            .endpoint
            .as_ref()
            .unwrap()
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("accept failed, no incoming"))?;
        let conn = conn.await.with_context(|| "accept connection failed")?;
        let transport_authenticated =
            connection_has_network_identity(&conn, &self.global_ctx.get_network_identity());
        let remote_addr = conn.remote_address();
        let (mut w, mut r) = conn.accept_bi().await.with_context(|| "accept_bi failed")?;
        activate_reliable_lane(&mut w, &mut r, false).await?;

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
        };

        let flags = self.global_ctx.config.get_flags();
        build_quic_hybrid_tunnel(
            conn,
            w,
            r,
            ReliableLaneRole::Acceptor,
            QUIC_RELIABLE_MAX_PACKET_SIZE,
            info,
            &flags,
            transport_authenticated,
        )
    }
}

impl Drop for QuicTunnelListener {
    fn drop(&mut self) {
        let Some(endpoint) = &self.endpoint else {
            return;
        };
        let Ok(local_addr) = endpoint.local_addr() else {
            return;
        };
        QuicEndpointManager::load(&self.global_ctx).remove_endpoint_by_local_addr(local_addr);
    }
}

#[async_trait::async_trait]
impl TunnelListener for QuicTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let endpoint = QuicEndpointManager::server(&self.global_ctx, addr)?;
        self.addr
            .set_port(Some(endpoint.local_addr()?.port()))
            .unwrap();
        self.endpoint = Some(endpoint);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        loop {
            match self.do_accept().await {
                Ok(ret) => return Ok(ret),
                Err(e) => {
                    tracing::warn!(?e, "accept fail");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct QuicTunnelConnector {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    bind_addrs: Vec<SocketAddr>,
    underlay_policy: Arc<UnderlayPolicy>,
}

impl QuicTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelConnector {
            addr,
            global_ctx,
            ip_version: IpVersion::Both,
            resolved_addr: None,
            bind_addrs: Vec::new(),
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QuicTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        let (endpoint, connection, transport_authenticated) = QuicEndpointManager::connect(
            &self.global_ctx,
            addr,
            &self.bind_addrs,
            self.underlay_policy.clone(),
        )
        .await?;

        let local_addr = endpoint.local_addr()?;

        let (mut w, mut r) = connection
            .open_bi()
            .await
            .with_context(|| "open_bi failed")?;
        activate_reliable_lane(&mut w, &mut r, true).await?;

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&connection.remote_address().to_string(), "quic")
                    .into(),
            ),
        };

        let flags = self.global_ctx.config.get_flags();
        build_quic_hybrid_tunnel(
            connection,
            w,
            r,
            ReliableLaneRole::Initiator,
            QUIC_RELIABLE_MAX_PACKET_SIZE,
            info,
            &flags,
            transport_authenticated,
        )
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_underlay_policy(&mut self, policy: Arc<UnderlayPolicy>) {
        self.underlay_policy = policy;
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{
        global_ctx::tests::get_mock_global_ctx_with_network, underlay_policy::UnderlayPolicy,
    };
    use crate::tunnel::{
        TunnelConnector,
        common::tests::_tunnel_pingpong,
        packet_def::{PacketType, ZCPacket},
    };
    use futures::{SinkExt, StreamExt};
    use std::sync::LazyLock;
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    #[test]
    fn quic_data_plane_implements_owned_batch_interfaces() {
        fn assert_reader<T: crate::tunnel::PacketBatchStream>() {}
        fn assert_writer<T: crate::tunnel::PacketBatchSink>() {}

        assert_reader::<QuicHybridReader>();
        assert_writer::<QuicHybridWriter>();
    }

    // Shared runtime for all tests to avoid endpoint invalidation across runtimes
    static RUNTIME: LazyLock<Runtime> =
        LazyLock::new(|| Builder::new_multi_thread().enable_all().build().unwrap());

    fn global_ctx() -> ArcGlobalCtx {
        let identity = crate::common::config::NetworkIdentity::default();
        get_mock_global_ctx_with_network(Some(identity))
    }

    fn brutal_global_ctx() -> ArcGlobalCtx {
        let global_ctx = global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.quic_congestion = "brutal".into();
        flags.quic_brutal_send_bps = 100_000_000;
        flags.quic_initial_receive_window = 8 * 1024 * 1024;
        flags.quic_receive_window = 32 * 1024 * 1024;
        global_ctx.set_flags(flags);
        global_ctx
    }

    fn hybrid_writer_without_reliable_io(connection: Arc<ConnWrapper>) -> QuicHybridWriter {
        let (sender, mut receiver) = mpsc::channel::<PacketBatch>(RELIABLE_LANE_QUEUE_BATCHES);
        let task = tokio::spawn(async move {
            while receiver.recv().await.is_some() {}
            Ok(())
        });
        QuicHybridWriter::new(sender, task, connection)
    }

    #[test]
    fn adaptive_transport_config_builds() {
        let mut flags = gen_default_flags();
        flags.quic_congestion = "adaptive".to_owned();

        transport_config(&flags).unwrap();
    }

    #[test]
    fn quic_socket_buffer_matches_the_high_rate_datagram_path() {
        assert_eq!(quic_socket_buffer_bytes(), 7 * 1024 * 1024);
    }

    #[test]
    fn quic_path_observer_uses_an_explicit_positive_interval() {
        assert_eq!(quic_stats_interval_from(None), None);
        assert_eq!(quic_stats_interval_from(Some("0")), None);
        assert_eq!(quic_stats_interval_from(Some("invalid")), None);
        assert_eq!(
            quic_stats_interval_from(Some("250")),
            Some(Duration::from_millis(250))
        );
    }

    #[tokio::test]
    async fn failed_reliable_reservation_is_removed_before_another_poll() {
        let (sender, receiver) = mpsc::channel::<PacketBatch>(1);
        drop(receiver);
        let mut reservation: Option<ReliableReserve> = Some(Box::pin(sender.reserve_owned()));

        let result =
            futures::future::poll_fn(|cx| poll_reliable_reservation(&mut reservation, cx)).await;

        assert!(result.is_err());
        assert!(reservation.is_none());
    }

    fn stopped_client_endpoint() -> (Endpoint, SocketAddr) {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let endpoint = rt.block_on(async {
            QuicEndpointManager::try_create((Ipv4Addr::UNSPECIFIED, 0).into(), false, None).unwrap()
        });
        let local_addr = endpoint.local_addr().unwrap();
        drop(rt);
        assert!(matches!(
            endpoint.connect("127.0.0.1:1".parse().unwrap(), "localhost"),
            Err(ConnectError::EndpointStopping)
        ));
        (endpoint, local_addr)
    }

    #[test]
    fn client_endpoints_are_keyed_by_local_source_and_deny_policy() {
        RUNTIME.block_on(async {
            let mgr = QuicEndpointManager::new(4);
            let policy = UnderlayPolicy::default();
            let source_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let source_b: SocketAddr = "[::1]:0".parse().unwrap();

            let endpoint_a = mgr
                .client_endpoint_for_source(source_a, None, &policy)
                .unwrap();
            let endpoint_b = mgr
                .client_endpoint_for_source(source_b, None, &policy)
                .unwrap();

            assert_eq!(endpoint_a.local_addr().unwrap().ip(), source_a.ip());
            assert_eq!(endpoint_b.local_addr().unwrap().ip(), source_b.ip());
            assert_ne!(
                endpoint_a.local_addr().unwrap(),
                endpoint_b.local_addr().unwrap()
            );

            let denied = UnderlayPolicy::new(&[], &["127.0.0.0/8".into()]).unwrap();
            let result = mgr.client_endpoint_for_source(source_a, None, &denied);
            assert!(matches!(result, Err(TunnelError::UnderlayPolicyDenied(_))));
        });
    }

    #[test]
    fn source_bound_client_endpoints_remain_bounded() {
        RUNTIME.block_on(async {
            let mgr = QuicEndpointManager::new(1);

            for _ in 0..3 {
                let endpoint =
                    QuicEndpointManager::try_create("127.0.0.1:0".parse().unwrap(), false, None)
                        .unwrap();
                let _connection_owner = mgr.retain_source_endpoint(endpoint);
            }

            assert_eq!(mgr.ipv4.len(), 1);
        });
    }

    #[test]
    fn quic_pingpong() {
        RUNTIME.block_on(quic_pingpong_impl())
    }
    async fn quic_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::]:21011".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn quic_hybrid_lanes_cross_a_live_connection() {
        RUNTIME.block_on(async {
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
            listener.listen().await.unwrap();
            let remote = listener.local_url();
            let (received_tx, received_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, mut send) = tunnel.split();
                for _ in 0..3 {
                    let packet = recv.next().await.unwrap().unwrap();
                    send.send(packet).await.unwrap();
                    send.flush().await.unwrap();
                }
                received_rx.await.unwrap();
                send.close().await.unwrap();
            });

            let tunnel = QuicTunnelConnector::new(remote, global_ctx())
                .connect()
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();

            let mut normal = ZCPacket::new_with_payload(b"normal datagram");
            normal.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            let mut critical = ZCPacket::new_with_payload(&[0_u8; 42]);
            critical.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            critical
                .mut_peer_manager_header()
                .unwrap()
                .set_critical_l2_control(true);

            let mut oversized = ZCPacket::new_with_payload(&[0x5a; 9000]);
            oversized.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            for expected in [normal, critical, oversized] {
                send.send(PacketBatch::singleton(expected.clone()))
                    .await
                    .unwrap();
                send.flush().await.unwrap();
                let received = tokio::time::timeout(Duration::from_secs(2), recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap();
                assert_eq!(received.payload(), expected.payload());
                assert_eq!(
                    received
                        .peer_manager_header()
                        .unwrap()
                        .is_critical_l2_control(),
                    expected
                        .peer_manager_header()
                        .unwrap()
                        .is_critical_l2_control()
                );
            }

            received_tx.send(()).unwrap();
            send.close().await.unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn reliable_lane_recovers_without_reconnecting() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let (recovered_tx, recovered_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let connection = server_endpoint.accept().await.unwrap().await.unwrap();
                let stable_id = connection.stable_id();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                activate_reliable_lane(&mut send, &mut recv, false)
                    .await
                    .unwrap();
                send.reset(0_u32.into()).unwrap();
                recv.stop(0_u32.into()).unwrap();

                let (mut send, mut recv) =
                    tokio::time::timeout(Duration::from_secs(2), connection.accept_bi())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(connection.stable_id(), stable_id);
                activate_reliable_lane(&mut send, &mut recv, false)
                    .await
                    .unwrap();
                recovered_tx.send(()).unwrap();

                let mut reader = FramedReader::new_with_initial_capacity(
                    recv,
                    QUIC_RELIABLE_MAX_PACKET_SIZE,
                    QUIC_RELIABLE_INITIAL_BUFFER_SIZE,
                );
                for _ in 0..2 {
                    let packet = tokio::time::timeout(Duration::from_secs(2), reader.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    if packet.payload() == b"after recovery" {
                        return packet;
                    }
                }
                panic!("replacement reliable lane did not deliver the expected packet");
            });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let connection = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let stable_id = connection.stable_id();
            let (mut send_stream, mut recv_stream) = connection.open_bi().await.unwrap();
            activate_reliable_lane(&mut send_stream, &mut recv_stream, true)
                .await
                .unwrap();
            let tunnel = build_quic_hybrid_tunnel(
                connection.clone(),
                send_stream,
                recv_stream,
                ReliableLaneRole::Initiator,
                QUIC_RELIABLE_MAX_PACKET_SIZE,
                TunnelInfo::default(),
                &flags,
                false,
            )
            .unwrap();
            let (_recv, mut send) = tunnel.split();

            let mut trigger = ZCPacket::new_with_payload(b"trigger recovery");
            trigger.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
            let _ = send.send(PacketBatch::singleton(trigger)).await;
            let _ = send.flush().await;

            tokio::time::timeout(Duration::from_secs(2), recovered_rx)
                .await
                .unwrap()
                .unwrap();

            let mut expected = ZCPacket::new_with_payload(b"after recovery");
            expected.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
            send.send(PacketBatch::singleton(expected.clone()))
                .await
                .unwrap();
            send.flush().await.unwrap();

            let received = server.await.unwrap();
            assert_eq!(received.payload(), expected.payload());
            assert_eq!(connection.stable_id(), stable_id);
        });
    }

    #[test]
    fn quic_pingpong_with_strict_source_bind() {
        RUNTIME.block_on(async {
            let listener =
                QuicTunnelListener::new("quic://127.0.0.1:21013".parse().unwrap(), global_ctx());
            let mut connector =
                QuicTunnelConnector::new("quic://127.0.0.1:21013".parse().unwrap(), global_ctx());
            connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
            connector.set_underlay_policy(Arc::new(
                UnderlayPolicy::new(&[], &["100.64.0.0/10".into()]).unwrap(),
            ));
            _tunnel_pingpong(listener, connector).await;
        });
    }

    #[test]
    fn quic_pingpong_with_brutal_controller() {
        RUNTIME.block_on(async {
            let listener = QuicTunnelListener::new(
                "quic://127.0.0.1:21014".parse().unwrap(),
                brutal_global_ctx(),
            );
            let connector = QuicTunnelConnector::new(
                "quic://127.0.0.1:21014".parse().unwrap(),
                brutal_global_ctx(),
            );
            _tunnel_pingpong(listener, connector).await;
        });
    }

    #[test]
    fn ipv6_pingpong() {
        RUNTIME.block_on(ipv6_pingpong_impl())
    }
    async fn ipv6_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:32015".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://[::1]:32015".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn ipv6_domain_pingpong() {
        RUNTIME.block_on(ipv6_domain_pingpong_impl())
    }
    async fn ipv6_domain_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:32016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:32016".parse().unwrap(), global_ctx());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener =
            QuicTunnelListener::new("quic://127.0.0.1:32016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:32016".parse().unwrap(), global_ctx());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[test]
    fn alloc_port() {
        RUNTIME.block_on(alloc_port_impl())
    }
    async fn alloc_port_impl() {
        // v4
        let mut listener =
            QuicTunnelListener::new("quic://0.0.0.0:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = QuicTunnelListener::new("quic://[::]:0".parse().unwrap(), global_ctx());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn listener_drop_removes_persistent_endpoint() {
        RUNTIME.block_on(listener_drop_removes_persistent_endpoint_impl())
    }
    async fn listener_drop_removes_persistent_endpoint_impl() {
        let global_ctx = global_ctx();
        let endpoint_addr = {
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx.clone());
            listener.listen().await.unwrap();
            let endpoint_addr = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            assert!(QuicEndpointManager::load(&global_ctx).contains_local_addr(endpoint_addr));
            endpoint_addr
        };

        assert!(!QuicEndpointManager::load(&global_ctx).contains_local_addr(endpoint_addr));
    }

    #[test]
    fn connect_removes_stopped_endpoints_and_retries() {
        let (stopped_endpoint_a, stopped_addr_a) = stopped_client_endpoint();
        let (stopped_endpoint_b, stopped_addr_b) = stopped_client_endpoint();

        RUNTIME.block_on(async move {
            let mgr = QuicEndpointManager::new(2);
            mgr.both.push(stopped_endpoint_a);
            mgr.both.push(stopped_endpoint_b);
            assert!(mgr.contains_local_addr(stopped_addr_a));
            assert!(mgr.contains_local_addr(stopped_addr_b));
            let flags = gen_default_flags();
            let identity = crate::common::config::NetworkIdentity::default();

            let err = mgr
                .connect_with_ip_version(
                    "127.0.0.1:0".parse().unwrap(),
                    IpVersion::V4,
                    None,
                    QuicConnectSecurity {
                        flags: &flags,
                        identity: &identity,
                        allow_noise_protected_transport: false,
                    },
                )
                .await
                .unwrap_err();
            let err = format!("{:?}", err);
            assert!(
                err.contains("invalid remote address"),
                "unexpected error: {}",
                err
            );
            assert!(!mgr.contains_local_addr(stopped_addr_a));
            assert!(!mgr.contains_local_addr(stopped_addr_b));
        });
    }

    #[test]
    fn invalid_peer_addr() {
        RUNTIME.block_on(invalid_peer_addr_impl())
    }
    async fn invalid_peer_addr_impl() {
        let mut connector =
            QuicTunnelConnector::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
        let err = format!("{:?}", connector.connect().await.unwrap_err());
        assert!(
            err.contains("invalid remote address"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn normal_data_uses_plain_datagrams_and_critical_l2_uses_the_stream() {
        let mut data = ZCPacket::new_with_payload(b"data");
        data.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);
        assert_eq!(
            select_quic_delivery(&data, Some(data.tunnel_payload().len())),
            QuicDelivery::PlainDatagram
        );

        let mut ethernet = ZCPacket::new_with_payload(&[0x5a; 1000]);
        ethernet.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Ethernet as u8);
        assert_eq!(
            select_quic_delivery(&ethernet, Some(1200)),
            QuicDelivery::PlainDatagram
        );

        ethernet
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);
        assert_eq!(
            select_quic_delivery(&ethernet, Some(1200)),
            QuicDelivery::ReliableStream
        );

        let mut oversized = ZCPacket::new_with_payload(&[0x5a; 1500]);
        oversized.fill_peer_manager_hdr(
            1,
            2,
            crate::tunnel::packet_def::PacketType::Ethernet as u8,
        );
        assert_eq!(
            select_quic_delivery(&oversized, Some(1200)),
            QuicDelivery::ReliableStream
        );

        let mut control = ZCPacket::new_with_payload(b"rpc");
        control.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::RpcReq as u8);
        assert_eq!(
            select_quic_delivery(&control, Some(usize::MAX)),
            QuicDelivery::ReliableStream
        );
    }

    #[test]
    fn quic_datagram_round_trip_reuses_the_tunnel_payload() {
        let mut packet = ZCPacket::new_with_payload(b"datagram-payload");
        packet.fill_peer_manager_hdr(7, 9, crate::tunnel::packet_def::PacketType::Data as u8);
        let expected = packet.tunnel_payload().to_vec();

        let encoded = encode_quic_datagram(packet);
        assert_eq!(encoded.as_ref(), expected);

        let decoded = decode_quic_datagram(encoded).unwrap();
        assert_eq!(decoded.tunnel_payload(), expected);
        assert!(decoded.is_lossy());
    }

    #[test]
    fn datagram_queue_owns_at_most_one_packet_batch() {
        assert_eq!(
            QUIC_DATAGRAM_SEND_BUFFER_BYTES,
            crate::tunnel::batch::MAX_PACKET_BATCH_SIZE * 1452
        );
    }

    #[test]
    fn malformed_plain_datagram_is_dropped() {
        assert!(decode_received_quic_datagram(Bytes::from_static(b"short")).is_none());
    }

    #[test]
    fn quic_transport_uses_tls13_and_survives_a_key_update() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let server_name = server_addr.ip().to_string();
            let client = client_endpoint
                .connect(server_addr, &server_name)
                .unwrap()
                .await
                .unwrap();
            let server = server.await.unwrap();

            let handshake = client.handshake_data().unwrap();
            let client_handshake = handshake
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .expect("QUIC must use rustls TLS 1.3");
            assert_eq!(client_handshake.protocol, None);

            let server_handshake = server.handshake_data().unwrap();
            let server_handshake = server_handshake
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .expect("QUIC must use rustls TLS 1.3");
            assert_eq!(server_handshake.server_name, None);

            client.force_key_update();
            client
                .send_datagram(Bytes::from_static(b"after-key-update"))
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                Bytes::from_static(b"after-key-update")
            );
        });
    }

    #[test]
    fn quic_connection_drains_ready_datagrams_as_one_bounded_batch() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server.await.unwrap();

            for sequence in 0_u8..8 {
                client
                    .send_datagram(Bytes::from(vec![sequence; 32]))
                    .unwrap();
            }

            let first = tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first[0], 0);

            let ready = tokio::time::timeout(
                Duration::from_secs(2),
                server.read_datagrams(Vec::with_capacity(7), 7),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(ready.len(), 7);
            assert_eq!(
                ready.iter().map(|datagram| datagram[0]).collect::<Vec<_>>(),
                (1..8).collect::<Vec<_>>()
            );
        });
    }

    #[test]
    fn quic_writer_waits_for_full_datagram_queue_capacity() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server_task =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server_task.await.unwrap();
            let maximum = client.max_datagram_size().unwrap();
            let filler = Bytes::from(vec![0; maximum]);
            while client.datagram_send_buffer_space() >= filler.len() {
                client.send_datagram(filler.clone()).unwrap();
            }
            assert!(client.datagram_send_buffer_space() < filler.len());

            let connection = Arc::new(ConnWrapper {
                conn: client.clone(),
            });
            let mut writer = hybrid_writer_without_reliable_io(connection);
            let payload = vec![0x5a; maximum - PEER_MANAGER_HEADER_SIZE];
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            Pin::new(&mut writer)
                .start_send(PacketBatch::singleton(packet))
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(2),
                futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx)),
            )
            .await
            .unwrap()
            .unwrap();

            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let datagram = server.read_datagram().await.unwrap();
                    if datagram
                        .get(PEER_MANAGER_HEADER_SIZE)
                        .is_some_and(|byte| *byte == 0x5a)
                    {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn quic_writer_keeps_one_owned_datagram_batch_until_flush() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server_task =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server_task.await.unwrap();
            let connection = Arc::new(ConnWrapper {
                conn: client.clone(),
            });
            let mut writer = hybrid_writer_without_reliable_io(connection);
            let mut batch = PacketBatch::with_capacity(8);
            for sequence in 0..8_u8 {
                let mut packet = ZCPacket::new_with_payload(&[sequence; 64]);
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                batch.try_push(packet).unwrap();
            }
            Pin::new(&mut writer).start_send(batch).unwrap();

            assert_eq!(writer.pending_datagrams.as_ref().unwrap().len(), 8);
            assert!(writer.pending_datagram_send.is_none());

            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
                .await
                .unwrap();
            assert!(writer.pending_datagrams.as_ref().unwrap().is_empty());
            assert!(writer.pending_datagram_send.is_none());

            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), async {
                while received.len() != 8 {
                    received.push(server.read_datagram().await.unwrap());
                }
            })
            .await
            .unwrap();
            assert_eq!(
                received
                    .iter()
                    .map(|datagram| datagram[PEER_MANAGER_HEADER_SIZE])
                    .collect::<Vec<_>>(),
                (0..8_u8).collect::<Vec<_>>()
            );
        });
    }

    #[test]
    fn quic_network_identity_is_deterministic_and_secret_bound() {
        let first = crate::common::config::NetworkIdentity::new(
            "test-network".to_owned(),
            "first-secret".to_owned(),
        );
        let same = crate::common::config::NetworkIdentity::new(
            "test-network".to_owned(),
            "first-secret".to_owned(),
        );
        let different = crate::common::config::NetworkIdentity::new(
            "test-network".to_owned(),
            "different-secret".to_owned(),
        );

        let first = tls::network_identity(&first).unwrap().unwrap();
        let same = tls::network_identity(&same).unwrap().unwrap();
        let different = tls::network_identity(&different).unwrap().unwrap();

        assert_eq!(first.certificate, same.certificate);
        assert_eq!(
            first.private_key.secret_der(),
            same.private_key.secret_der()
        );
        assert_ne!(first.certificate, different.certificate);
    }

    #[test]
    fn quic_network_identity_authenticates_both_endpoints() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let identity = crate::common::config::NetworkIdentity::new(
                "test-network".to_owned(),
                "test-secret".to_owned(),
            );
            let server_endpoint = Endpoint::server(
                server_config_for_network(&flags, &identity).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint
                .set_default_client_config(client_config_for_network(&flags, &identity).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server.await.unwrap();

            assert!(connection_has_network_identity(&client, &identity));
            assert!(connection_has_network_identity(&server, &identity));
        });
    }

    #[test]
    fn quic_network_identity_rejects_a_different_secret() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_identity = crate::common::config::NetworkIdentity::new(
                "test-network".to_owned(),
                "server-secret".to_owned(),
            );
            let client_identity = crate::common::config::NetworkIdentity::new(
                "test-network".to_owned(),
                "client-secret".to_owned(),
            );
            let server_endpoint = Endpoint::server(
                server_config_for_network(&flags, &server_identity).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server = tokio::spawn(async move { server_endpoint.accept().await.unwrap().await });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(
                client_config_for_network(&flags, &client_identity).unwrap(),
            );
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await;
            let server = server.await.unwrap();

            assert!(client.is_err());
            assert!(server.is_err());
        });
    }

    #[test]
    fn direct_quic_tunnel_reports_network_authentication() {
        RUNTIME.block_on(async {
            let server_ctx = global_ctx();
            let client_ctx = global_ctx();
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), server_ctx);
            listener.listen().await.unwrap();
            let listener_addr = listener.local_url();
            let server = tokio::spawn(async move { listener.accept().await.unwrap() });

            let mut connector = QuicTunnelConnector::new(listener_addr, client_ctx);
            let client = connector.connect().await.unwrap();
            let server = server.await.unwrap();

            assert!(client.is_transport_authenticated());
            assert!(server.is_transport_authenticated());
        });
    }

    #[test]
    fn direct_quic_connection_rejects_an_unauthenticated_server() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let accept_endpoint = server_endpoint.clone();
            let server = tokio::spawn(async move {
                loop {
                    let incoming = accept_endpoint.accept().await.unwrap();
                    if let Ok(connection) = incoming.await {
                        return connection;
                    }
                }
            });

            let context = global_ctx();
            let result = QuicEndpointManager::connect(
                &context,
                server_addr,
                &[],
                Arc::new(UnderlayPolicy::default()),
            )
            .await;

            assert!(result.is_err());
            server.abort();
        });
    }

    #[test]
    fn secure_mode_allows_noise_protected_quic() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let accept_endpoint = server_endpoint.clone();
            let server = tokio::spawn(async move {
                loop {
                    let incoming = accept_endpoint.accept().await.unwrap();
                    if let Ok(connection) = incoming.await {
                        return connection;
                    }
                }
            });

            let context = global_ctx();
            context
                .config
                .set_secure_mode(Some(crate::proto::common::SecureModeConfig {
                    enabled: true,
                    local_private_key: None,
                    local_public_key: None,
                }));
            let (_endpoint, connection, authenticated) = QuicEndpointManager::connect(
                &context,
                server_addr,
                &[],
                Arc::new(UnderlayPolicy::default()),
            )
            .await
            .unwrap();
            let _server = server.await.unwrap();

            assert!(!authenticated);
            connection.close(0_u32.into(), b"test complete");
        });
    }

    #[test]
    fn different_network_secrets_are_rejected() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_identity = crate::common::config::NetworkIdentity::new(
                "test-network".to_owned(),
                "server-secret".to_owned(),
            );
            let server_endpoint = Endpoint::server(
                server_config_for_network(&flags, &server_identity).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let accept_endpoint = server_endpoint.clone();
            let server = tokio::spawn(async move {
                loop {
                    let incoming = accept_endpoint.accept().await.unwrap();
                    if let Ok(connection) = incoming.await {
                        return connection;
                    }
                }
            });

            let context = global_ctx();
            context
                .config
                .set_network_identity(crate::common::config::NetworkIdentity::new(
                    "test-network".to_owned(),
                    "client-secret".to_owned(),
                ));
            let result = QuicEndpointManager::connect(
                &context,
                server_addr,
                &[],
                Arc::new(UnderlayPolicy::default()),
            )
            .await;

            assert!(result.is_err());
            server.abort();
        });
    }
}
