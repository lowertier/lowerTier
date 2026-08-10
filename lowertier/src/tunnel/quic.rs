//! QUIC stream control plus bounded DATAGRAM delivery for L2/L3 data.
//!
//! rustls/ring supplies standard TLS 1.3 QUIC packet protection. LowTier's
//! inner Noise session remains responsible for authenticated peer identity.

use super::{
    FromUrl, IpVersion, SinkError, SinkItem, StreamItem, Tunnel, TunnelConnector, TunnelError,
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
    common::{FramedReader, FramedWriter, TunnelWrapper},
};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use futures::{Future, Sink, Stream};
use parking_lot::{Mutex, RwLock};
use quinn::{
    ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, EndpointConfig, RecvStream,
    SendStream, ServerConfig, TransportConfig, VarInt, congestion::BbrConfig, default_runtime,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt as _, net::UdpSocket};

use super::{
    common::TcpZCPacketToBytes,
    packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacket, ZCPacketType},
};
use datagram_metrics::QuicDatagramMetrics;
use fec::{EncodedFecBlock, FEC_FLUSH_DELAY, FecDecoderState, FecEncoderState};
use reliable_datagram::{
    DatagramMessage, ReceiveEvent, ReceiveState, SendState, decode_datagram, encode_ack_range,
    encode_fragment_nack,
};

pub(crate) mod adaptive;
pub(crate) mod brutal;
mod datagram_metrics;
pub(crate) mod fec;
pub(crate) mod quic_config;
mod reliable_datagram;
pub(crate) mod wire_profile;

use self::adaptive::{AdaptiveConfig, AdaptiveFactory};

const QUIC_DATAGRAM_PREFACE: &[u8; 4] = b"ETQ4";
const QUIC_DATAGRAM_SEND_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const QUIC_DATAGRAM_MIN_QUEUE_BUDGET: usize = 64 * 1024;
const QUIC_DATAGRAM_ACK_BATCH_FRAMES: usize = 16;
const QUIC_DATAGRAM_ACK_MAX_DELAY: Duration = Duration::from_millis(2);
const QUIC_DATAGRAM_RECOVERED_QUEUE_CAPACITY: usize = 4096;

fn extend_bounded_queue<T>(
    queue: &mut VecDeque<T>,
    values: impl IntoIterator<Item = T>,
    capacity: usize,
) -> usize {
    let mut dropped = 0;
    for value in values {
        if queue.len() < capacity {
            queue.push_back(value);
        } else {
            dropped += 1;
        }
    }
    dropped
}

async fn exchange_datagram_preface(
    send: &mut SendStream,
    recv: &mut RecvStream,
    client: bool,
) -> Result<(), TunnelError> {
    let mut peer = [0_u8; QUIC_DATAGRAM_PREFACE.len()];
    if client {
        send.write_all(QUIC_DATAGRAM_PREFACE)
            .await
            .context("write QUIC DATAGRAM preface")?;
        send.flush().await.context("flush QUIC DATAGRAM preface")?;
        recv.read_exact(&mut peer)
            .await
            .context("read QUIC DATAGRAM preface")?;
    } else {
        recv.read_exact(&mut peer)
            .await
            .context("read QUIC DATAGRAM preface")?;
        send.write_all(QUIC_DATAGRAM_PREFACE)
            .await
            .context("write QUIC DATAGRAM preface")?;
        send.flush().await.context("flush QUIC DATAGRAM preface")?;
    }
    if &peer != QUIC_DATAGRAM_PREFACE {
        return Err(TunnelError::InvalidPacket(format!(
            "unsupported QUIC packet transport preface: {peer:?}"
        )));
    }
    Ok(())
}

// region config
mod tls {
    use std::sync::Arc;

    use anyhow::Context as _;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    };

    use crate::tunnel::TunnelError;

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
        .initial_mtu(1200)
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
        endpoint.set_server_config(Some(server_config(&global_ctx.get_flags())?));
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
        pool.push(endpoint.clone());
        Ok(endpoint)
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
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let ip_version = if addr.ip().is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let flags = global_ctx.get_flags();
        let socket_mark = flags.socket_mark;
        ensure_remote_allowed(&policy, addr)?;
        let bind_addrs = eligible_bind_addrs(&policy, bind_addrs, addr)?;
        let manager = Self::load(global_ctx);
        if bind_addrs.is_empty() {
            return manager
                .connect_with_ip_version(addr, ip_version, socket_mark, &flags)
                .await;
        }

        let futures = futures::stream::FuturesUnordered::new();
        for source in bind_addrs {
            futures.push(manager.connect_with_source(
                addr,
                source,
                socket_mark,
                policy.clone(),
                &flags,
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
        flags: &Flags,
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let pool = if source.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };
        let max_endpoint_stopping_retries = pool.len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let mut endpoint = self.client_endpoint_for_source(source, socket_mark, &policy)?;
            endpoint.set_default_client_config(client_config(flags)?);
            let server_name = addr.ip().to_string();
            let connecting = match endpoint.connect(addr, &server_name) {
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
            let connection = connecting
                .await
                .with_context(|| format!("failed to connect to {}", addr))?;
            ensure_local_allowed(&policy, endpoint.local_addr()?)?;
            ensure_remote_allowed(&policy, connection.remote_address())?;
            return Ok((endpoint, connection));
        }
    }

    async fn connect_with_ip_version(
        &self,
        addr: SocketAddr,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
        flags: &Flags,
    ) -> Result<(Endpoint, Connection), TunnelError> {
        let max_endpoint_stopping_retries = self.client_pool(ip_version).len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let mut endpoint = self.client_endpoint(ip_version, socket_mark)?;
            endpoint.set_default_client_config(client_config(flags)?);
            let server_name = addr.ip().to_string();
            let connecting = match endpoint.connect(addr, &server_name) {
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
            let connection = connecting
                .await
                .with_context(|| format!("failed to connect to {}", addr))?;

            return Ok((endpoint, connection));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuicDelivery {
    Datagram,
    ReliableStream,
}

fn select_quic_delivery(packet: &ZCPacket, max_datagram_size: Option<usize>) -> QuicDelivery {
    if packet.is_lossy() && max_datagram_size.is_some() {
        QuicDelivery::Datagram
    } else {
        QuicDelivery::ReliableStream
    }
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

fn reliable_datagram_rto(connection: &Connection) -> Duration {
    connection
        .rtt()
        .saturating_mul(2)
        .clamp(Duration::from_millis(100), Duration::from_secs(1))
}

fn reliable_datagram_nack_grace(connection: &Connection) -> Duration {
    connection
        .rtt()
        .div_f32(4.0)
        .clamp(Duration::from_millis(10), Duration::from_millis(50))
}

trait QuicDatagramIo {
    fn max_datagram_size(&self) -> Option<usize>;
    fn send_datagram(&self, datagram: Bytes) -> Result<(), quinn::SendDatagramError>;

    fn has_send_buffer_space(&self, _bytes: usize) -> bool {
        true
    }
}

impl QuicDatagramIo for Connection {
    fn max_datagram_size(&self) -> Option<usize> {
        Connection::max_datagram_size(self)
    }

    fn send_datagram(&self, datagram: Bytes) -> Result<(), quinn::SendDatagramError> {
        Connection::send_datagram(self, datagram)
    }

    fn has_send_buffer_space(&self, bytes: usize) -> bool {
        let free = self.datagram_send_buffer_space();
        if bytes > free {
            return false;
        }
        let occupied = QUIC_DATAGRAM_SEND_BUFFER_BYTES.saturating_sub(free);
        let cwnd = usize::try_from(self.stats().path.cwnd).unwrap_or(usize::MAX);
        let queue_budget = cwnd.saturating_mul(2).clamp(
            QUIC_DATAGRAM_MIN_QUEUE_BUDGET,
            QUIC_DATAGRAM_SEND_BUFFER_BYTES,
        );
        occupied.saturating_add(bytes) <= queue_budget
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DatagramSendOutcome {
    Sent,
    Dropped,
}

fn send_frame_with_io(
    io: &impl QuicDatagramIo,
    send: &Mutex<SendState>,
    metrics: &QuicDatagramMetrics,
    fec_send: Option<&Mutex<FecEncoderState>>,
    frame: Bytes,
    immediate_duplicate: bool,
    now: Instant,
    rto: Duration,
) -> Result<DatagramSendOutcome, TunnelError> {
    const MAX_REFRAGMENT_ATTEMPTS: usize = 3;
    const MTU_RACE_SAFETY_MARGIN: usize = 32;

    let mut max_datagram_size = io.max_datagram_size().ok_or_else(|| {
        TunnelError::InvalidProtocol("peer does not support QUIC DATAGRAM".to_owned())
    })?;
    metrics.observe_path_mtu(max_datagram_size);
    'refragment: for attempt in 0..MAX_REFRAGMENT_ATTEMPTS {
        let source_datagram_size = if fec_send.is_some() {
            FecEncoderState::max_source_datagram_size(max_datagram_size)
                .map_err(|error| TunnelError::InternalError(error.to_string()))?
        } else {
            max_datagram_size
        };
        let queued = match send
            .lock()
            .queue(frame.clone(), source_datagram_size, now, rto)
        {
            Ok(queued) => queued,
            Err(TunnelError::BufferFull) => {
                metrics.record_queue_drop_pending();
                return Ok(DatagramSendOutcome::Dropped);
            }
            Err(error) => return Err(error),
        };
        metrics.observe_queue_bytes(send.lock().pending_bytes());
        let encoded_bytes = queued.datagrams.iter().map(Bytes::len).sum();
        if !io.has_send_buffer_space(encoded_bytes) {
            send.lock().acknowledge(queued.frame_id);
            metrics.record_queue_drop_quinn();
            return Ok(DatagramSendOutcome::Dropped);
        }

        let raw_fragment_count = queued.datagrams.len();
        let (source_datagrams, completed_blocks) = if let Some(fec_send) = fec_send {
            let mut fec_send = fec_send.lock();
            let mut sources = Vec::with_capacity(raw_fragment_count);
            let mut completed = Vec::new();
            for datagram in queued.datagrams {
                let output = match fec_send.push(datagram, now) {
                    Ok(output) => output,
                    Err(error) => {
                        fec_send.abort_block();
                        send.lock().acknowledge(queued.frame_id);
                        return Err(TunnelError::InternalError(error.to_string()));
                    }
                };
                sources.push(output.source);
                if let Some(block) = output.completed {
                    completed.push(block);
                }
            }
            (sources, completed)
        } else {
            (queued.datagrams, Vec::new())
        };
        let parity_bytes = completed_blocks
            .iter()
            .flat_map(|block| &block.parity)
            .map(Bytes::len)
            .sum::<usize>();
        let source_bytes = source_datagrams.iter().map(Bytes::len).sum::<usize>();
        let total_bytes = source_bytes.saturating_add(parity_bytes);
        if !io.has_send_buffer_space(total_bytes) {
            if let Some(fec_send) = fec_send {
                fec_send.lock().abort_block();
            }
            send.lock().acknowledge(queued.frame_id);
            metrics.record_queue_drop_quinn();
            return Ok(DatagramSendOutcome::Dropped);
        }
        let duplicate = immediate_duplicate
            && io.has_send_buffer_space(total_bytes.saturating_add(source_bytes));
        if immediate_duplicate && !duplicate {
            metrics.record_critical_duplicate_suppressed();
        }
        let fragmented = raw_fragment_count > 1;
        for datagram in source_datagrams {
            let datagram_len = datagram.len();
            let duplicate_datagram = duplicate.then(|| datagram.clone());
            match io.send_datagram(datagram) {
                Ok(()) => metrics.record_source_fragment(datagram_len, fragmented),
                Err(quinn::SendDatagramError::TooLarge)
                    if attempt + 1 < MAX_REFRAGMENT_ATTEMPTS =>
                {
                    if let Some(fec_send) = fec_send {
                        fec_send.lock().abort_block();
                    }
                    send.lock().acknowledge(queued.frame_id);
                    let refreshed = io.max_datagram_size().unwrap_or(max_datagram_size);
                    max_datagram_size = if refreshed < max_datagram_size {
                        refreshed
                    } else {
                        max_datagram_size.saturating_sub(MTU_RACE_SAFETY_MARGIN)
                    };
                    metrics.observe_path_mtu(max_datagram_size);
                    continue 'refragment;
                }
                Err(error) => {
                    send.lock().acknowledge(queued.frame_id);
                    return Err(TunnelError::Anyhow(
                        anyhow::Error::new(error).context("send reliable QUIC DATAGRAM failed"),
                    ));
                }
            }
            if let Some(duplicate_datagram) = duplicate_datagram {
                io.send_datagram(duplicate_datagram).map_err(|error| {
                    TunnelError::Anyhow(
                        anyhow::Error::new(error)
                            .context("send duplicate critical L2 QUIC DATAGRAM failed"),
                    )
                })?;
            }
        }
        if duplicate {
            metrics.record_critical_duplicate_sent();
        }
        for block in completed_blocks {
            let mut parity_sent = true;
            for parity in &block.parity {
                if let Err(error) = io.send_datagram(parity.clone()) {
                    parity_sent = false;
                    metrics.record_fec_unrecoverable();
                    if !matches!(error, quinn::SendDatagramError::TooLarge) {
                        send.lock().acknowledge(queued.frame_id);
                        return Err(TunnelError::Anyhow(
                            anyhow::Error::new(error)
                                .context("send ETD4 FEC parity DATAGRAM failed"),
                        ));
                    }
                    break;
                }
            }
            if parity_sent {
                metrics.record_fec_block(
                    block.source_count,
                    block.parity.len(),
                    block.source_bytes,
                    block.parity_bytes,
                );
            }
        }
        return Ok(DatagramSendOutcome::Sent);
    }
    unreachable!("refragmentation loop returns or propagates on every final attempt")
}

struct ReliableDatagramState {
    connection: Connection,
    send: Mutex<SendState>,
    receive: Mutex<ReceiveState>,
    fec_send: Option<Mutex<FecEncoderState>>,
    fec_receive: Mutex<FecDecoderState>,
    recovered_packets: Mutex<VecDeque<ZCPacket>>,
    critical_l2_duplication: bool,
    metrics: QuicDatagramMetrics,
}

impl ReliableDatagramState {
    fn new(connection: Connection, flags: &Flags) -> Result<Self, TunnelError> {
        let fec_send = match flags.quic_datagram_fec_parity {
            0 => None,
            parity_count => Some(Mutex::new(
                FecEncoderState::new(parity_count as usize, FEC_FLUSH_DELAY)
                    .map_err(|error| TunnelError::InternalError(error.to_string()))?,
            )),
        };
        Ok(Self {
            connection,
            send: Mutex::new(SendState::default()),
            receive: Mutex::new(ReceiveState::default()),
            fec_send,
            fec_receive: Mutex::new(FecDecoderState::default()),
            recovered_packets: Mutex::new(VecDeque::new()),
            critical_l2_duplication: flags.quic_critical_l2_duplication,
            metrics: QuicDatagramMetrics::default(),
        })
    }

    fn send_packet(&self, packet: ZCPacket) -> Result<(), TunnelError> {
        let immediate_duplicate = self.critical_l2_duplication
            && packet
                .peer_manager_header()
                .is_some_and(|header| header.is_critical_l2_duplicate());
        self.metrics.record_source_frame();
        let outcome = send_frame_with_io(
            &self.connection,
            &self.send,
            &self.metrics,
            self.fec_send.as_ref(),
            encode_quic_datagram(packet),
            immediate_duplicate,
            Instant::now(),
            reliable_datagram_rto(&self.connection),
        )?;
        if outcome == DatagramSendOutcome::Dropped {
            tracing::trace!("dropping L2 QUIC DATAGRAM because the bounded send queue is full");
        }
        Ok(())
    }

    fn send_ack_range(&self, largest_frame_id: u64, received: u128) -> Result<(), TunnelError> {
        self.connection
            .send_datagram(encode_ack_range(largest_frame_id, received))
            .map_err(|error| {
                TunnelError::Anyhow(
                    anyhow::Error::new(error)
                        .context("send reliable QUIC DATAGRAM ACK range failed"),
                )
            })?;
        self.metrics.record_ack_range_sent();
        Ok(())
    }

    fn send_fragment_nack(&self, frame_id: u64, missing_fragments: u64) -> Result<(), TunnelError> {
        self.connection
            .send_datagram(encode_fragment_nack(frame_id, missing_fragments))
            .map_err(|error| {
                TunnelError::Anyhow(
                    anyhow::Error::new(error)
                        .context("send reliable QUIC DATAGRAM fragment NACK failed"),
                )
            })?;
        self.metrics.record_nack_sent();
        Ok(())
    }

    fn send_fec_block(&self, block: EncodedFecBlock) -> Result<(), TunnelError> {
        if !self.connection.has_send_buffer_space(block.parity_bytes) {
            self.metrics.record_queue_drop_quinn();
            self.metrics.record_fec_unrecoverable();
            return Ok(());
        }
        for parity in &block.parity {
            if let Err(error) = self.connection.send_datagram(parity.clone()) {
                self.metrics.record_fec_unrecoverable();
                if matches!(error, quinn::SendDatagramError::TooLarge) {
                    tracing::trace!(
                        block_id = block.block_id,
                        "dropping ETD4 FEC parity after a path MTU change"
                    );
                    return Ok(());
                }
                return Err(TunnelError::Anyhow(
                    anyhow::Error::new(error).context("send partial ETD4 FEC block failed"),
                ));
            }
        }
        self.metrics.record_fec_block(
            block.source_count,
            block.parity.len(),
            block.source_bytes,
            block.parity_bytes,
        );
        Ok(())
    }

    fn receive_data_fragment(
        &self,
        fragment: reliable_datagram::DataFragment,
        now: Instant,
    ) -> Result<Option<ZCPacket>, TunnelError> {
        let (event, ack_range) = {
            let mut receive = self.receive.lock();
            let event = receive.ingest(fragment, now)?;
            let ack_range = match event {
                ReceiveEvent::Complete { .. } => receive.take_ack_range_if_due(
                    now,
                    QUIC_DATAGRAM_ACK_BATCH_FRAMES,
                    QUIC_DATAGRAM_ACK_MAX_DELAY,
                ),
                ReceiveEvent::Duplicate { .. } => receive.ack_range(),
                ReceiveEvent::Pending => None,
            };
            (event, ack_range)
        };
        if let Some((largest_frame_id, received)) = ack_range {
            self.send_ack_range(largest_frame_id, received)?;
        }
        match event {
            ReceiveEvent::Pending | ReceiveEvent::Duplicate { .. } => Ok(None),
            ReceiveEvent::Complete { frame, .. } => decode_quic_datagram(frame).map(Some),
        }
    }

    fn receive_inner_data(
        &self,
        datagram: Bytes,
        now: Instant,
    ) -> Result<Option<ZCPacket>, TunnelError> {
        let DatagramMessage::Data(fragment) = decode_datagram(datagram)? else {
            return Err(TunnelError::InvalidPacket(
                "ETD4 FEC source does not contain a data fragment".to_owned(),
            ));
        };
        self.receive_data_fragment(fragment, now)
    }

    fn deliver_fec_records(
        &self,
        original: Option<Bytes>,
        recovered: Vec<Bytes>,
        expired_blocks: usize,
        now: Instant,
    ) -> Result<Option<ZCPacket>, TunnelError> {
        for _ in 0..expired_blocks {
            self.metrics.record_fec_unrecoverable();
        }
        if !recovered.is_empty() {
            self.metrics.record_fec_recovered(recovered.len());
        }
        let mut packets = Vec::with_capacity(usize::from(original.is_some()) + recovered.len());
        if let Some(original) = original
            && let Some(packet) = self.receive_inner_data(original, now)?
        {
            packets.push(packet);
        }
        for datagram in recovered {
            if let Some(packet) = self.receive_inner_data(datagram, now)? {
                packets.push(packet);
            }
        }
        let mut packets = packets.into_iter();
        let first = packets.next();
        let dropped = extend_bounded_queue(
            &mut self.recovered_packets.lock(),
            packets,
            QUIC_DATAGRAM_RECOVERED_QUEUE_CAPACITY,
        );
        for _ in 0..dropped {
            self.metrics.record_queue_drop_pending();
        }
        Ok(first)
    }

    fn take_recovered_packet(&self) -> Option<ZCPacket> {
        self.recovered_packets.lock().pop_front()
    }

    fn log_metrics(&self, reason: &'static str) {
        let path = self.connection.stats().path;
        let queue_bytes = QUIC_DATAGRAM_SEND_BUFFER_BYTES
            .saturating_sub(self.connection.datagram_send_buffer_space());
        tracing::info!(
            target: "CORE::QUIC_DATAGRAM_METRICS",
            event = "ETQ4_METRICS",
            reason,
            atomic_header = QuicDatagramMetrics::tsv_header(),
            atomic_row = %self.metrics.tsv_row(),
            rtt_us = u64::try_from(path.rtt.as_micros()).unwrap_or(u64::MAX),
            cwnd_bytes = path.cwnd,
            lost_packets = path.lost_packets,
            lost_bytes = path.lost_bytes,
            sent_packets = path.sent_packets,
            current_mtu = path.current_mtu,
            datagram_queue_bytes = queue_bytes,
            "ETQ4_METRICS_TSV\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            reason,
            self.metrics.tsv_row(),
            u64::try_from(path.rtt.as_micros()).unwrap_or(u64::MAX),
            path.cwnd,
            path.lost_packets,
            path.lost_bytes,
            path.sent_packets,
            path.current_mtu,
            queue_bytes,
        );
    }

    fn receive_datagram(&self, bytes: Bytes) -> Result<Option<ZCPacket>, TunnelError> {
        match decode_datagram(bytes)? {
            DatagramMessage::AckRange {
                largest_frame_id,
                received,
            } => {
                self.send
                    .lock()
                    .acknowledge_range(largest_frame_id, received);
                self.metrics.record_ack_range_received();
                Ok(None)
            }
            DatagramMessage::FragmentNack {
                frame_id,
                missing_fragments,
            } => {
                self.metrics.record_nack_received();
                let Some(fragments) = self
                    .send
                    .lock()
                    .selective_fragments(frame_id, missing_fragments)
                else {
                    return Ok(None);
                };
                let encoded_bytes = fragments.iter().map(Bytes::len).sum();
                if !self.connection.has_send_buffer_space(encoded_bytes) {
                    self.metrics.record_queue_drop_quinn();
                    return Ok(None);
                }
                self.metrics.record_selective_retransmit(fragments.len());
                for fragment in fragments {
                    self.connection.send_datagram(fragment).map_err(|error| {
                        TunnelError::Anyhow(
                            anyhow::Error::new(error)
                                .context("selective QUIC DATAGRAM retransmission failed"),
                        )
                    })?;
                }
                Ok(None)
            }
            DatagramMessage::FecSource {
                block_id,
                source_index,
                datagram,
            } => {
                let now = Instant::now();
                let output = self
                    .fec_receive
                    .lock()
                    .ingest_source(block_id, source_index, datagram.clone(), now)
                    .map_err(|error| TunnelError::InvalidPacket(error.to_string()))?;
                self.deliver_fec_records(
                    Some(datagram),
                    output.datagrams,
                    output.expired_blocks,
                    now,
                )
            }
            DatagramMessage::FecParity {
                block_id,
                source_count,
                parity_count,
                parity_index,
                shard,
            } => {
                let now = Instant::now();
                let output = self
                    .fec_receive
                    .lock()
                    .ingest_parity(
                        block_id,
                        source_count,
                        parity_count,
                        parity_index,
                        shard,
                        now,
                    )
                    .map_err(|error| TunnelError::InvalidPacket(error.to_string()))?;
                self.deliver_fec_records(None, output.datagrams, output.expired_blocks, now)
            }
            DatagramMessage::Data(fragment) => self.receive_data_fragment(fragment, Instant::now()),
        }
    }

    fn service_due(&self) -> bool {
        let now = Instant::now();
        let (ack_range, nacks, expired_partial_frames) = {
            let mut receive = self.receive.lock();
            let ack_range = receive.take_ack_range_if_due(
                now,
                QUIC_DATAGRAM_ACK_BATCH_FRAMES,
                QUIC_DATAGRAM_ACK_MAX_DELAY,
            );
            let nacks = receive.nacks_due(now, reliable_datagram_nack_grace(&self.connection));
            let expired_partial_frames = receive.take_expired_partial_frames();
            (ack_range, nacks, expired_partial_frames)
        };
        for _ in 0..expired_partial_frames {
            self.metrics.record_partial_frame_expired();
        }
        if let Some((largest_frame_id, received)) = ack_range
            && let Err(error) = self.send_ack_range(largest_frame_id, received)
        {
            tracing::warn!(?error, "QUIC DATAGRAM ACK-range service failed");
            if self.connection.close_reason().is_some() {
                return false;
            }
        }
        for (frame_id, missing_fragments) in nacks {
            if let Err(error) = self.send_fragment_nack(frame_id, missing_fragments) {
                tracing::warn!(
                    ?error,
                    frame_id,
                    "QUIC DATAGRAM fragment-NACK service failed"
                );
                if self.connection.close_reason().is_some() {
                    return false;
                }
            }
        }

        if let Some(fec_send) = &self.fec_send {
            match fec_send.lock().flush_due(now) {
                Ok(Some(block)) => {
                    if let Err(error) = self.send_fec_block(block) {
                        tracing::warn!(?error, "partial ETD4 FEC flush failed");
                        if self.connection.close_reason().is_some() {
                            return false;
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.metrics.record_fec_unrecoverable();
                    tracing::warn!(?error, "partial ETD4 FEC encoding failed");
                }
            }
        }

        let sweep = self
            .send
            .lock()
            .retries_due(now, reliable_datagram_rto(&self.connection));
        if !sweep.exhausted.is_empty() {
            for _ in &sweep.exhausted {
                self.metrics.record_recovery_exhausted();
            }
            tracing::trace!(
                frames = sweep.exhausted.len(),
                first_frame_id = sweep.exhausted.first().copied(),
                "reliable QUIC DATAGRAM retry limit reached"
            );
        }
        for retry in sweep.retries {
            let encoded_bytes = retry.datagrams.iter().map(Bytes::len).sum();
            if !self.connection.has_send_buffer_space(encoded_bytes) {
                tracing::trace!(
                    frame_id = retry.frame_id,
                    "skipping L2 QUIC DATAGRAM retry because the bounded send queue is full"
                );
                // The queue is already carrying newer traffic. Retaining this
                // stale frame for another RTO cannot produce another retry,
                // and only consumes pending-memory budget until expiry.
                self.send.lock().acknowledge(retry.frame_id);
                continue;
            }
            for datagram in retry.datagrams {
                if let Err(error) = self.connection.send_datagram(datagram) {
                    tracing::warn!(
                        frame_id = retry.frame_id,
                        ?error,
                        "reliable QUIC DATAGRAM retransmission failed"
                    );
                    if matches!(error, quinn::SendDatagramError::ConnectionLost(_)) {
                        return false;
                    }
                    break;
                }
            }
        }
        true
    }
}

impl Drop for ReliableDatagramState {
    fn drop(&mut self) {
        self.log_metrics("connection_drop");
    }
}

async fn run_reliable_datagram_retransmissions(state: Weak<ReliableDatagramState>) {
    let mut interval = tokio::time::interval(QUIC_DATAGRAM_ACK_MAX_DELAY);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(state) = state.upgrade() else {
            return;
        };
        if !state.service_due() {
            return;
        }
    }
}

async fn run_reliable_datagram_metrics(state: Weak<ReliableDatagramState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let Some(state) = state.upgrade() else {
            return;
        };
        state.log_metrics("periodic");
    }
}

type DatagramRead = Pin<Box<dyn Future<Output = Result<Bytes, ConnectionError>> + Send + 'static>>;

fn next_datagram_read(connection: &Connection) -> DatagramRead {
    let connection = connection.clone();
    Box::pin(async move { connection.read_datagram().await })
}

/// Combines reliable QUIC control frames with the unordered DATAGRAM data
/// lane. Poll preference alternates so a saturated data lane cannot starve
/// control traffic and vice versa.
struct QuicHybridReader {
    reliable: FramedReader<RecvStream>,
    connection: Arc<ConnWrapper>,
    datagram: Arc<ReliableDatagramState>,
    datagram_read: Option<DatagramRead>,
    poll_datagram_first: bool,
}

impl QuicHybridReader {
    fn new(
        reliable: RecvStream,
        max_packet_size: usize,
        connection: Arc<ConnWrapper>,
        datagram: Arc<ReliableDatagramState>,
    ) -> Self {
        let datagram_read = Some(next_datagram_read(&connection.conn));
        Self {
            reliable: FramedReader::new(reliable, max_packet_size),
            connection,
            datagram,
            datagram_read,
            poll_datagram_first: true,
        }
    }

    fn poll_datagram(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<StreamItem>> {
        // Consume a bounded number of internal ACKs/fragments per poll. This
        // preserves control-stream fairness even when the DATAGRAM queue is hot.
        for _ in 0..64 {
            if let Some(packet) = self.datagram.take_recovered_packet() {
                return Poll::Ready(Some(Ok(packet)));
            }
            let Some(read) = self.datagram_read.as_mut() else {
                return Poll::Pending;
            };
            match read.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(bytes)) => {
                    self.datagram_read = Some(next_datagram_read(&self.connection.conn));
                    match self.datagram.receive_datagram(bytes) {
                        Ok(Some(packet)) => return Poll::Ready(Some(Ok(packet))),
                        Ok(None) => continue,
                        Err(error) => {
                            tracing::warn!(?error, "dropping invalid reliable QUIC DATAGRAM");
                            continue;
                        }
                    }
                }
                Poll::Ready(Err(error)) => {
                    self.datagram_read = None;
                    return Poll::Ready(Some(Err(TunnelError::Anyhow(
                        anyhow::Error::new(error).context("read QUIC DATAGRAM failed"),
                    ))));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_reliable(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<StreamItem>> {
        Pin::new(&mut self.reliable).poll_next(cx)
    }
}

impl Stream for QuicHybridReader {
    type Item = StreamItem;

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
    reliable: FramedWriter<SendStream, TcpZCPacketToBytes>,
    connection: Arc<ConnWrapper>,
    datagram: Arc<ReliableDatagramState>,
}

impl QuicHybridWriter {
    fn new(
        reliable: SendStream,
        connection: Arc<ConnWrapper>,
        datagram: Arc<ReliableDatagramState>,
    ) -> Self {
        Self {
            reliable: FramedWriter::new(reliable),
            connection,
            datagram,
        }
    }
}

impl Sink<SinkItem> for QuicHybridWriter {
    type Error = SinkError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.reliable).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        match select_quic_delivery(&item, self.connection.conn.max_datagram_size()) {
            QuicDelivery::Datagram => self.datagram.send_packet(item),
            QuicDelivery::ReliableStream => Pin::new(&mut self.reliable).start_send(item),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.reliable).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.reliable).poll_close(cx)
    }
}

fn build_quic_hybrid_tunnel(
    connection: Connection,
    reliable_send: SendStream,
    reliable_recv: RecvStream,
    max_packet_size: usize,
    info: TunnelInfo,
    flags: &Flags,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let connection = Arc::new(ConnWrapper { conn: connection });
    let datagram = Arc::new(ReliableDatagramState::new(connection.conn.clone(), flags)?);
    tokio::spawn(run_reliable_datagram_retransmissions(Arc::downgrade(
        &datagram,
    )));
    tokio::spawn(run_reliable_datagram_metrics(Arc::downgrade(&datagram)));
    Ok(Box::new(TunnelWrapper::new(
        QuicHybridReader::new(
            reliable_recv,
            max_packet_size,
            connection.clone(),
            datagram.clone(),
        ),
        QuicHybridWriter::new(reliable_send, connection, datagram),
        Some(info),
    )))
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
        let remote_addr = conn.remote_address();
        let (mut w, mut r) = conn.accept_bi().await.with_context(|| "accept_bi failed")?;
        exchange_datagram_preface(&mut w, &mut r, false).await?;

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
        build_quic_hybrid_tunnel(conn, w, r, 2000, info, &flags)
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
        let (endpoint, connection) = QuicEndpointManager::connect(
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
        exchange_datagram_preface(&mut w, &mut r, true).await?;

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
        build_quic_hybrid_tunnel(connection, w, r, 4500, info, &flags)
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
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };
    use futures::{SinkExt as _, StreamExt as _};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    #[test]
    fn recovered_queue_extension_is_hard_bounded() {
        let mut queue = VecDeque::from([1_u8, 2]);
        let dropped = extend_bounded_queue(&mut queue, [3_u8, 4, 5], 4);

        assert_eq!(queue, VecDeque::from([1, 2, 3, 4]));
        assert_eq!(dropped, 1);
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

    #[test]
    fn adaptive_transport_config_builds() {
        let mut flags = gen_default_flags();
        flags.quic_congestion = "adaptive".to_owned();

        transport_config(&flags).unwrap();
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
    fn quic_bench() {
        RUNTIME.block_on(quic_bench_impl())
    }
    async fn quic_bench_impl() {
        let listener = QuicTunnelListener::new("quic://[::]:21012".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap(), global_ctx());
        _tunnel_bench(listener, connector).await
    }

    #[test]
    fn ipv6_pingpong() {
        RUNTIME.block_on(ipv6_pingpong_impl())
    }
    async fn ipv6_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://[::1]:31015".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn ipv6_domain_pingpong() {
        RUNTIME.block_on(ipv6_domain_pingpong_impl())
    }
    async fn ipv6_domain_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:31016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:31016".parse().unwrap(), global_ctx());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener =
            QuicTunnelListener::new("quic://127.0.0.1:31016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:31016".parse().unwrap(), global_ctx());
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

            let err = mgr
                .connect_with_ip_version(
                    "127.0.0.1:0".parse().unwrap(),
                    IpVersion::V4,
                    None,
                    &gen_default_flags(),
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
    fn quic_datagram_carries_l2_and_l3_data_without_stream_fallback() {
        let mut data = ZCPacket::new_with_payload(b"data");
        data.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);
        assert_eq!(
            select_quic_delivery(&data, Some(data.tunnel_payload().len())),
            QuicDelivery::Datagram
        );

        let mut ethernet = ZCPacket::new_with_payload(&[0x5a; 1500]);
        ethernet.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Ethernet as u8);
        assert_eq!(
            select_quic_delivery(&ethernet, Some(1200)),
            QuicDelivery::Datagram,
            "large Ethernet frames must be fragmented, not sent through the ordered stream"
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

    struct ShrinkingDatagramIo {
        max_size: AtomicUsize,
        reject_first: AtomicBool,
        sent: Mutex<Vec<Bytes>>,
    }

    struct FullDatagramIo {
        sent: AtomicUsize,
    }

    impl QuicDatagramIo for FullDatagramIo {
        fn max_datagram_size(&self) -> Option<usize> {
            Some(1200)
        }

        fn send_datagram(&self, _datagram: Bytes) -> Result<(), quinn::SendDatagramError> {
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn has_send_buffer_space(&self, _bytes: usize) -> bool {
            false
        }
    }

    impl QuicDatagramIo for ShrinkingDatagramIo {
        fn max_datagram_size(&self) -> Option<usize> {
            Some(self.max_size.load(Ordering::Relaxed))
        }

        fn send_datagram(&self, datagram: Bytes) -> Result<(), quinn::SendDatagramError> {
            if self.reject_first.swap(false, Ordering::Relaxed) {
                self.max_size.store(600, Ordering::Relaxed);
                return Err(quinn::SendDatagramError::TooLarge);
            }
            self.sent.lock().push(datagram);
            Ok(())
        }
    }

    #[test]
    fn reliable_datagram_refragments_after_path_mtu_shrinks() {
        let io = ShrinkingDatagramIo {
            max_size: AtomicUsize::new(1200),
            reject_first: AtomicBool::new(true),
            sent: Mutex::new(Vec::new()),
        };
        let send = Mutex::new(SendState::default());
        let metrics = QuicDatagramMetrics::default();
        let expected = Bytes::from(vec![0x7d; 4096]);
        send_frame_with_io(
            &io,
            &send,
            &metrics,
            None,
            expected.clone(),
            false,
            Instant::now(),
            Duration::from_millis(100),
        )
        .unwrap();

        let sent = io.sent.lock().clone();
        assert!(sent.len() > 1);
        assert!(sent.iter().all(|datagram| datagram.len() <= 600));
        let mut receiver = ReceiveState::default();
        let mut completed = None;
        for datagram in sent {
            let DatagramMessage::Data(fragment) = decode_datagram(datagram).unwrap() else {
                unreachable!()
            };
            if let ReceiveEvent::Complete { frame, .. } =
                receiver.ingest(fragment, Instant::now()).unwrap()
            {
                completed = Some(frame);
            }
        }
        assert_eq!(completed, Some(expected));
    }

    #[test]
    fn reliable_datagram_applies_backpressure_before_quinn_evicts_old_frames() {
        let io = FullDatagramIo {
            sent: AtomicUsize::new(0),
        };
        let send = Mutex::new(SendState::default());
        let metrics = QuicDatagramMetrics::default();
        assert!(matches!(
            send_frame_with_io(
                &io,
                &send,
                &metrics,
                None,
                Bytes::from(vec![0x4a; 1500]),
                false,
                Instant::now(),
                Duration::from_millis(100),
            ),
            Ok(DatagramSendOutcome::Dropped)
        ));
        assert_eq!(io.sent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn critical_l2_frame_is_duplicated_immediately_with_the_same_frame_id() {
        let io = ShrinkingDatagramIo {
            max_size: AtomicUsize::new(1200),
            reject_first: AtomicBool::new(false),
            sent: Mutex::new(Vec::new()),
        };
        let send = Mutex::new(SendState::default());
        let metrics = QuicDatagramMetrics::default();
        send_frame_with_io(
            &io,
            &send,
            &metrics,
            None,
            Bytes::from_static(b"critical-arp"),
            true,
            Instant::now(),
            Duration::from_millis(100),
        )
        .unwrap();

        let sent = io.sent.lock();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
        assert_eq!(metrics.snapshot().critical_duplicates_sent, 1);
    }

    #[test]
    fn fragmented_ethernet_crosses_a_live_bbr_datagram_connection() {
        RUNTIME.block_on(async {
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
            listener.listen().await.unwrap();
            let remote = listener.local_url();
            let (verified_tx, verified_rx) = tokio::sync::oneshot::channel();

            let server = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, mut send) = tunnel.split();
                let packet = recv.next().await.unwrap().unwrap();
                assert!(packet.is_lossy());
                assert_eq!(
                    packet.peer_manager_header().unwrap().packet_type,
                    crate::tunnel::packet_def::PacketType::Ethernet as u8
                );
                send.send(packet).await.unwrap();
                send.flush().await.unwrap();
                let _ = verified_rx.await;
            });

            let mut connector = QuicTunnelConnector::new(remote, global_ctx());
            let tunnel = connector.connect().await.unwrap();
            let (mut recv, mut send) = tunnel.split();
            let payload = (0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(
                11,
                12,
                crate::tunnel::packet_def::PacketType::Ethernet as u8,
            );
            send.send(packet).await.unwrap();
            send.flush().await.unwrap();

            let echoed = tokio::time::timeout(Duration::from_secs(2), recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(echoed.payload(), payload);
            let _ = verified_tx.send(());
            server.await.unwrap();
        });
    }
}
