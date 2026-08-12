use arc_swap::ArcSwapOption;
use crossbeam::atomic::AtomicCell;
use futures::{StreamExt, TryFutureExt};
use std::{
    any::Any,
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use tokio::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::Mac;
use prost::Message;
use tokio::{
    sync::broadcast,
    task::JoinSet,
    time::{Duration, timeout},
};

use tracing::Instrument;
use zerocopy::AsBytes;

use snow::{HandshakeState, params::NoiseParams};

#[cfg(feature = "quic")]
use super::alternate_fec::{AlternateFecDecoder, decode_alternate_fec_packet};
use super::{
    PacketRecvChan,
    encrypt::Encryptor,
    link_envelope::{LinkEnvelopeSession, LinkEnvelopeTunnelFilter},
    peer_conn_ping::PeerConnPinger,
    peer_session::{PeerSession, PeerSessionAction},
    traffic_metrics::AggregateTrafficMetrics,
};
use crate::{
    common::{
        PeerId,
        config::{NetworkIdentity, NetworkSecretDigest},
        error::Error,
        global_ctx::ArcGlobalCtx,
    },
    peers::peer_session::{PeerSessionStore, SessionKey, UpsertResponderSessionReturn},
    proto::{
        api::instance::{PeerConnInfo, PeerConnStats},
        common::{LimiterConfig, SecureModeConfig, TunnelInfo},
        peer_rpc::{
            HandshakeRequest, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb, PeerIdentityType, SecureAuthLevel,
        },
    },
    tunnel::{
        BatchStreamItem, PacketBatchStream, Tunnel, TunnelError,
        batch::{
            MAX_PACKET_BATCH_SIZE, PacketBatch, RECEIVE_PREFETCH_BATCHES,
            ordered_parallel_try_for_each, parallel_crypto_enabled,
            wait_for_delivery_with_bounded_prefetch,
        },
        direct::{DirectTunnel, DirectTunnelSender},
        filter::{
            StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter,
            scalar_after_received_batch, scalar_before_send_batch,
        },
        packet_def::{PEER_MANAGER_HEADER_SIZE, PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
    },
    use_global_var,
};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;
const MAX_PENDING_HANDSHAKE_PACKETS: usize = MAX_PACKET_BATCH_SIZE;
const MAX_PENDING_HANDSHAKE_BYTES: usize =
    MAX_PENDING_HANDSHAKE_PACKETS * (4096 + PEER_MANAGER_HEADER_SIZE);

fn packet_batch_is_direct_peer_data(batch: &PacketBatch) -> bool {
    !batch.is_empty()
        && batch.iter().all(|packet| {
            if let Some(metadata) = packet.parsed_metadata() {
                return metadata.packet_type != PacketType::Ping as u8
                    && metadata.packet_type != PacketType::Pong as u8
                    && metadata.packet_type != PacketType::AlternateFecSource as u8
                    && metadata.packet_type != PacketType::AlternateFecParity as u8;
            }
            packet.peer_manager_header().is_some_and(|header| {
                header.packet_type != PacketType::Ping as u8
                    && header.packet_type != PacketType::Pong as u8
                    && header.packet_type != PacketType::AlternateFecSource as u8
                    && header.packet_type != PacketType::AlternateFecParity as u8
            })
        })
}

/// The proof of client secret.
#[derive(Debug)]
struct SecretProof {
    challenge: Vec<u8>,
    proof: Vec<u8>,
}

/// The result of noise handshake.
#[derive(Debug)]
struct NoiseHandshakeResult {
    peer_id: PeerId,
    session: Arc<PeerSession>,
    local_static_pubkey: Vec<u8>,
    remote_static_pubkey: Vec<u8>,
    handshake_hash: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
    peer_identity_type: PeerIdentityType,
    remote_network_name: String,

    secret_digest: Vec<u8>,

    // foreign network manager use this to verify peer.
    // the challenge will be sent to authorized peer and compare the proof against it.
    client_secret_proof: Option<SecretProof>,

    my_encrypt_algo: String,
    remote_encrypt_algo: String,
}

#[derive(Clone)]
struct PeerSessionTunnelFilter {
    enabled: bool,
    link_protection_active: Arc<AtomicBool>,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    session: Arc<ArcSwapOption<PeerSession>>,
}

#[derive(Clone)]
struct LegacyNetworkTunnelFilter {
    enabled: bool,
    transport_authenticated: bool,
    opaque_relay: Arc<AtomicBool>,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    encryptor: Arc<dyn Encryptor>,
}

impl LegacyNetworkTunnelFilter {
    fn new(
        my_peer_id: PeerId,
        enabled: bool,
        transport_authenticated: bool,
        encryptor: Arc<dyn Encryptor>,
    ) -> Self {
        Self {
            enabled,
            transport_authenticated,
            opaque_relay: Arc::new(AtomicBool::new(false)),
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            encryptor,
        }
    }

    fn set_my_peer_id(&self, my_peer_id: PeerId) {
        self.my_peer_id.store(my_peer_id);
    }

    fn set_peer_id(&self, peer_id: PeerId) {
        self.peer_id.store(Some(peer_id));
    }

    fn set_opaque_relay(&self, opaque_relay: bool) {
        self.opaque_relay.store(opaque_relay, Ordering::Release);
    }

    fn protects(packet_type: u8) -> bool {
        matches!(
            packet_type,
            value if value == PacketType::Data as u8
                || value == PacketType::Ethernet as u8
                || value == PacketType::KcpSrc as u8
                || value == PacketType::KcpDst as u8
                || value == PacketType::QuicSrc as u8
                || value == PacketType::QuicDst as u8
                || value == PacketType::AlternateFecSource as u8
                || value == PacketType::AlternateFecParity as u8
        )
    }

    fn direct_authenticated_packet(&self, from_peer_id: PeerId, to_peer_id: PeerId) -> bool {
        self.transport_authenticated
            && self.peer_id.load().is_some_and(|peer_id| {
                from_peer_id == self.my_peer_id.load() && to_peer_id == peer_id
            })
    }

    fn encrypt_packet_if_needed(&self, packet: &mut ZCPacket) -> Result<(), anyhow::Error> {
        if !self.enabled || self.opaque_relay.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(header) = packet.peer_manager_header() else {
            return Ok(());
        };
        if header.is_encrypted() || !Self::protects(header.packet_type) {
            return Ok(());
        }
        if self.direct_authenticated_packet(header.from_peer_id.get(), header.to_peer_id.get()) {
            return Ok(());
        }
        self.encryptor.encrypt(packet).map_err(Into::into)
    }

    fn decrypt_packet_if_needed(&self, packet: &mut ZCPacket) -> Result<bool, anyhow::Error> {
        if !self.enabled || self.opaque_relay.load(Ordering::Acquire) {
            return Ok(true);
        }
        let Some(header) = packet.peer_manager_header() else {
            return Ok(true);
        };
        if !Self::protects(header.packet_type) {
            return Ok(true);
        }
        let from_peer_id = header.from_peer_id.get();
        let to_peer_id = header.to_peer_id.get();
        if header.is_encrypted() {
            if to_peer_id == self.my_peer_id.load() {
                self.encryptor.decrypt(packet)?;
            }
            return Ok(true);
        }
        Ok(self.transport_authenticated
            && self.peer_id.load() == Some(from_peer_id)
            && to_peer_id == self.my_peer_id.load())
    }
}

impl LegacyNetworkTunnelFilter {
    fn direct_authenticated_batch(&self, batch: &PacketBatch) -> bool {
        if !self.transport_authenticated {
            return false;
        }
        let Some(peer_id) = self.peer_id.load() else {
            return false;
        };
        let my_peer_id = self.my_peer_id.load();
        batch.iter().all(|packet| {
            let Some(header) = packet.peer_manager_header() else {
                return true;
            };
            if !Self::protects(header.packet_type) || header.is_encrypted() {
                return true;
            }
            header.from_peer_id.get() == my_peer_id && header.to_peer_id.get() == peer_id
        })
    }

    fn direct_authenticated_receive_batch(&self, batch: &PacketBatch) -> bool {
        if !self.transport_authenticated {
            return false;
        }
        let Some(peer_id) = self.peer_id.load() else {
            return false;
        };
        let my_peer_id = self.my_peer_id.load();
        batch.iter().all(|packet| {
            let Some(header) = packet.peer_manager_header() else {
                return true;
            };
            if !Self::protects(header.packet_type) {
                return true;
            }
            if header.is_encrypted() {
                return false;
            }
            header.from_peer_id.get() == peer_id && header.to_peer_id.get() == my_peer_id
        })
    }
}

impl TunnelFilter for LegacyNetworkTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        if let Err(error) = self.encrypt_packet_if_needed(&mut data) {
            tracing::warn!(?error, "legacy network encryption failed");
            return None;
        }
        Some(data)
    }

    fn after_received(&self, data: crate::tunnel::StreamItem) -> Option<crate::tunnel::StreamItem> {
        let mut data = match data {
            Ok(packet) => packet,
            Err(error) => return Some(Err(error)),
        };
        match self.decrypt_packet_if_needed(&mut data) {
            Ok(true) => Some(Ok(data)),
            Ok(false) => {
                tracing::warn!("dropped unencrypted data from an unauthenticated transport");
                None
            }
            Err(error) => {
                tracing::warn!(?error, "legacy network decryption failed");
                None
            }
        }
    }

    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        if !self.enabled || self.opaque_relay.load(Ordering::Acquire) {
            return Some(data);
        }
        // Authenticated QUIC already protects the outer path. Direct data batches
        // skip the per-packet encrypt scan.
        if self.direct_authenticated_batch(&data) {
            return Some(data);
        }
        scalar_before_send_batch(self, data)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        if !self.enabled || self.opaque_relay.load(Ordering::Acquire) {
            return Some(data);
        }
        if let Ok(batch) = &data
            && self.direct_authenticated_receive_batch(batch)
        {
            return Some(data);
        }
        scalar_after_received_batch(self, data)
    }

    fn filter_output(&self) {}
}

impl PeerSessionTunnelFilter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            link_protection_active: Arc::new(AtomicBool::new(false)),
            my_peer_id: Arc::new(AtomicCell::new(PeerId::default())),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(ArcSwapOption::empty()),
        }
    }

    fn new_with_peer(my_peer_id: PeerId, enabled: bool) -> Self {
        Self::new_with_peer_and_link_active(my_peer_id, enabled, Arc::new(AtomicBool::new(false)))
    }

    fn new_with_peer_and_link_active(
        my_peer_id: PeerId,
        enabled: bool,
        link_protection_active: Arc<AtomicBool>,
    ) -> Self {
        Self {
            enabled,
            link_protection_active,
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(ArcSwapOption::empty()),
        }
    }

    fn set_my_peer_id(&self, my_peer_id: PeerId) {
        self.my_peer_id.store(my_peer_id);
    }

    fn set_peer_id(&self, peer_id: PeerId) {
        self.peer_id.store(Some(peer_id));
    }

    fn set_session(&self, session: Arc<PeerSession>) {
        self.session.store(Some(session));
    }

    fn should_skip_encrypt(&self, hdr: &crate::tunnel::packet_def::PeerManagerHeader) -> bool {
        hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg2 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg3 as u8
            || hdr.packet_type == PacketType::RelayHandshake as u8
            || hdr.packet_type == PacketType::RelayHandshakeAck as u8
            || hdr.packet_type == PacketType::Ping as u8
            || hdr.packet_type == PacketType::Pong as u8
    }

    fn encrypt_packet_with_session(
        &self,
        data: &mut ZCPacket,
        my_peer_id: PeerId,
        peer_id: PeerId,
        session: &PeerSession,
    ) -> Result<(), anyhow::Error> {
        let Some(hdr) = data.peer_manager_header() else {
            return Ok(());
        };
        if self.should_skip_encrypt(hdr) || hdr.is_encrypted() {
            return Ok(());
        }
        let from_peer_id = hdr.from_peer_id.get();
        let to_peer_id = hdr.to_peer_id.get();
        if my_peer_id != from_peer_id || to_peer_id != peer_id {
            return Ok(());
        }
        session.encrypt_payload(my_peer_id, peer_id, data)
    }

    fn encryption_context(&self) -> Option<(PeerId, PeerId, Arc<PeerSession>)> {
        if !self.enabled || self.link_protection_active.load(Ordering::Acquire) {
            return None;
        }
        Some((
            self.my_peer_id.load(),
            self.peer_id.load()?,
            self.session.load_full()?,
        ))
    }

    fn encrypt_packet_if_needed(&self, data: &mut ZCPacket) -> Result<(), anyhow::Error> {
        let Some((my_peer_id, peer_id, session)) = self.encryption_context() else {
            return Ok(());
        };
        self.encrypt_packet_with_session(data, my_peer_id, peer_id, &session)
    }

    fn encrypt_batch_sequential(&self, batch: &mut PacketBatch) -> Result<(), anyhow::Error> {
        let Some((my_peer_id, peer_id, session)) = self.encryption_context() else {
            return Ok(());
        };
        let direct_batch = batch.iter().all(|packet| {
            packet.peer_manager_header().is_some_and(|header| {
                !self.should_skip_encrypt(header)
                    && !header.is_encrypted()
                    && header.from_peer_id.get() == my_peer_id
                    && header.to_peer_id.get() == peer_id
            })
        });
        if direct_batch {
            return session.encrypt_payload_batch(my_peer_id, peer_id, batch);
        }
        batch.iter_mut().try_for_each(|packet| {
            self.encrypt_packet_with_session(packet, my_peer_id, peer_id, &session)
        })
    }

    fn encrypt_batch_parallel(&self, batch: &mut PacketBatch) -> Result<(), anyhow::Error> {
        let Some((my_peer_id, peer_id, session)) = self.encryption_context() else {
            return Ok(());
        };
        ordered_parallel_try_for_each(batch, |packet| {
            self.encrypt_packet_with_session(packet, my_peer_id, peer_id, &session)
        })
    }
}

impl TunnelFilter for PeerSessionTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        if let Err(e) = self.encrypt_packet_if_needed(&mut data) {
            tracing::warn!(
                ?e,
                "PeerSessionTunnelFilter: encrypt failed, dropping packet"
            );
            return None;
        }

        Some(data)
    }

    fn after_received(&self, data: crate::tunnel::StreamItem) -> Option<crate::tunnel::StreamItem> {
        if !self.enabled {
            return Some(data);
        }

        let mut data = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let Some(hdr) = data.peer_manager_header() else {
            return Some(Ok(data));
        };

        if self.should_skip_encrypt(hdr) {
            return Some(Ok(data));
        }

        let from_peer_id = hdr.from_peer_id.get();
        if from_peer_id == 0 {
            return Some(Ok(data));
        }

        let Some(peer_id) = self.peer_id.load() else {
            return Some(Ok(data));
        };

        if from_peer_id != peer_id {
            return Some(Ok(data));
        }

        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Some(Ok(data));
        };

        let my_peer_id = self.my_peer_id.load();
        if hdr.to_peer_id.get() != my_peer_id {
            return Some(Ok(data));
        }
        if self.link_protection_active.load(Ordering::Acquire) && !hdr.is_encrypted() {
            return Some(Ok(data));
        }

        if let Err(e) = session.decrypt_payload(from_peer_id, my_peer_id, &mut data) {
            if !session.is_valid() {
                // Session auto-invalidated after too many consecutive failures.
                // Close the connection to trigger reconnection with a fresh handshake.
                tracing::error!(?e, "session invalidated, closing connection");
                return Some(Err(TunnelError::InternalError(
                    "session invalidated due to consecutive decrypt failures".to_string(),
                )));
            }
            // Transient failure, drop this packet but keep the connection alive.
            return None;
        }

        Some(Ok(data))
    }

    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        if !self.enabled {
            return Some(data);
        }
        let mut data = data;
        let result = if parallel_crypto_enabled(data.len()) {
            self.encrypt_batch_parallel(&mut data)
        } else {
            self.encrypt_batch_sequential(&mut data)
        };
        if let Err(error) = result {
            tracing::warn!(?error, "peer session batch encryption failed");
            return None;
        }
        Some(data)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        if !self.enabled {
            return Some(data);
        }
        if self.link_protection_active.load(Ordering::Acquire) {
            return Some(data);
        }
        if let Ok(batch) = &data {
            let needs_decrypt = batch.iter().any(|packet| {
                packet.peer_manager_header().is_some_and(|header| {
                    header.is_encrypted() && !self.should_skip_encrypt(header)
                })
            });
            if !needs_decrypt {
                return Some(data);
            }
        }
        scalar_after_received_batch(self, data)
    }

    fn filter_output(&self) {}
}

pub struct PeerConnCloseNotify {
    conn_id: PeerConnId,
    sender: Arc<std::sync::Mutex<Option<broadcast::Sender<()>>>>,
}

impl PeerConnCloseNotify {
    fn new(conn_id: PeerConnId) -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            conn_id,
            sender: Arc::new(std::sync::Mutex::new(Some(sender))),
        }
    }

    fn notify_close(&self) {
        self.sender.lock().unwrap().take();
    }

    pub async fn get_waiter(&self) -> Option<broadcast::Receiver<()>> {
        if let Some(sender) = self.sender.lock().unwrap().as_mut() {
            let receiver = sender.subscribe();
            return Some(receiver);
        }
        None
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub fn is_closed(&self) -> bool {
        self.sender.lock().unwrap().is_none()
    }
}

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    peer_id_hint: Option<PeerId>,
    global_ctx: ArcGlobalCtx,

    secure_mode_cfg: Option<SecureModeConfig>,
    session_filter: PeerSessionTunnelFilter,
    legacy_filter: LegacyNetworkTunnelFilter,
    link_envelope_filter: LinkEnvelopeTunnelFilter,
    noise_handshake_result: Option<NoiseHandshakeResult>,

    tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: DirectTunnelSender,
    recv: Mutex<Option<Pin<Box<dyn PacketBatchStream>>>>,
    pending_recv: parking_lot::Mutex<VecDeque<ZCPacket>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,
    is_client: Option<bool>,

    // remote or local
    is_hole_punched: bool,

    close_event_notifier: Arc<PeerConnCloseNotify>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,

    peer_session_store: Arc<PeerSessionStore>,
    my_encrypt_algo: String,

    #[cfg(feature = "quic")]
    alternate_fec_decoder: Option<Arc<parking_lot::Mutex<AlternateFecDecoder>>>,
}

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

impl PeerConn {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        tunnel: Box<dyn Tunnel>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        Self::new_with_peer_id_hint(my_peer_id, global_ctx, tunnel, None, peer_session_store)
    }

    pub fn new_with_peer_id_hint(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        tunnel: Box<dyn Tunnel>,
        peer_id_hint: Option<PeerId>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        let flags = global_ctx.get_flags();
        let transport_authenticated = tunnel.is_transport_authenticated();
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let secure_mode_cfg = global_ctx.config.get_secure_mode();
        let secure_mode_enabled = secure_mode_cfg
            .as_ref()
            .is_some_and(|config| config.enabled);
        let link_protected = secure_mode_enabled
            && tunnel_info
                .as_ref()
                .is_some_and(|info| matches!(info.tunnel_type.as_str(), "udp" | "ring"));
        let link_envelope_filter = LinkEnvelopeTunnelFilter::new(link_protected);
        let session_filter = PeerSessionTunnelFilter::new_with_peer_and_link_active(
            my_peer_id,
            secure_mode_enabled,
            link_envelope_filter.active_flag(),
        );
        let legacy_filter = LegacyNetworkTunnelFilter::new(
            my_peer_id,
            !secure_mode_enabled && flags.enable_encryption,
            transport_authenticated,
            super::encrypt::create_encryptor(
                &flags.encryption_algorithm,
                global_ctx.get_128_key(),
                global_ctx.get_256_key(),
            ),
        );

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let filter_chain = TunnelFilterChain::new(session_filter.clone(), legacy_filter.clone())
            .chain(peer_conn_tunnel_filter)
            .chain(link_envelope_filter.clone());
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
        let mut direct_tunnel = DirectTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));

        let (recv, sink) = (direct_tunnel.get_stream(), direct_tunnel.get_sink());

        let conn_id = PeerConnId::new_v4();
        let my_encrypt_algo = flags.encryption_algorithm;

        PeerConn {
            conn_id,

            my_peer_id,
            peer_id_hint,
            global_ctx,

            secure_mode_cfg,
            session_filter,
            legacy_filter,
            link_envelope_filter,
            noise_handshake_result: None,

            tunnel: Arc::new(Mutex::new(
                Box::new(direct_tunnel) as Box<dyn Any + Send + 'static>
            )),
            sink,
            recv: Mutex::new(Some(recv)),
            pending_recv: parking_lot::Mutex::new(VecDeque::new()),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            is_hole_punched: true,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id)),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),

            peer_session_store,
            my_encrypt_algo,

            #[cfg(feature = "quic")]
            alternate_fec_decoder: None,
        }
    }

    fn get_peer_session_store(&self) -> &Arc<PeerSessionStore> {
        &self.peer_session_store
    }

    pub fn is_secure_mode_enabled(&self) -> bool {
        self.secure_mode_cfg
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
    }

    // pri, pub
    fn get_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let cfg = self
            .secure_mode_cfg
            .as_ref()
            .ok_or_else(|| Error::WaitRespError("secure mode config not set".to_owned()))?;
        Ok((
            cfg.private_key()?.as_bytes().to_vec(),
            cfg.public_key()?.as_bytes().to_vec(),
        ))
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub(crate) fn has_distinct_quic_surface(&self, other: &Self) -> bool {
        self.tunnel_info
            .as_ref()
            .zip(other.tunnel_info.as_ref())
            .is_some_and(|(left, right)| tunnel_infos_have_distinct_quic_surface(left, right))
    }

    pub(crate) fn alternate_parity_path_allowed(&self) -> bool {
        self.tunnel_info.as_ref().is_some_and(|info| {
            tunnel_info_allowed_for_alternate_parity(info, &self.global_ctx.get_underlay_policy())
        })
    }

    #[cfg(feature = "quic")]
    pub(crate) fn set_alternate_fec_decoder(
        &mut self,
        decoder: Option<Arc<parking_lot::Mutex<AlternateFecDecoder>>>,
    ) {
        self.alternate_fec_decoder = decoder;
    }

    pub fn set_is_hole_punched(&mut self, is_hole_punched: bool) {
        self.is_hole_punched = is_hole_punched;
    }

    pub fn is_hole_punched(&self) -> bool {
        self.is_hole_punched
    }

    pub fn is_closed(&self) -> bool {
        self.close_event_notifier.is_closed()
    }

    async fn wait_handshake(&self, need_retry: &mut bool) -> Result<HandshakeRequest, Error> {
        *need_retry = false;
        let rsp = self
            .recv_next_peer_manager_packet(Some(PacketType::HandShake))
            .await?;

        *need_retry = true;
        let rsp_len = rsp.buf_len() as u64;

        let Some(peer_mgr_hdr) = rsp.peer_manager_header() else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet: {:?}, cannot decode peer manager hdr",
                rsp
            )));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}, packet: {:?}",
                peer_mgr_hdr.packet_type, rsp
            )));
        }

        let rsp = HandshakeRequest::decode(rsp.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        self.record_control_rx(&rsp.network_name, rsp_len);

        Ok(rsp)
    }

    async fn wait_handshake_loop(&self) -> Result<HandshakeRequest, Error> {
        timeout(Duration::from_secs(5), async move {
            loop {
                let mut need_retry = true;
                match self.wait_handshake(&mut need_retry).await {
                    Ok(rsp) => return Ok(rsp),
                    Err(e) => {
                        tracing::warn!("wait handshake error: {:?}", e);
                        if !need_retry {
                            return Err(e);
                        }
                    }
                }
            }
        })
        .map_err(|e| Error::WaitRespError(format!("wait handshake timeout: {:?}", e)))
        .await?
    }

    async fn send_handshake(
        &self,
        send_secret_digest: bool,
        metric_network_name: &str,
    ) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let mut req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };

        // only send network secret digest if the network is the same
        if send_secret_digest {
            req.network_secret_digest
                .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        } else {
            // fill zero
            req.network_secret_digest
                .extend_from_slice(&[0u8; std::mem::size_of::<NetworkSecretDigest>()]);
        }

        let hs_req = req.encode_to_vec();
        let mut zc_packet = ZCPacket::new_with_payload(hs_req.as_bytes());
        zc_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::HandShake as u8,
        );
        let pkt_len = zc_packet.buf_len() as u64;

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;
        self.record_control_tx(metric_network_name, pkt_len);

        // yield to send the response packet
        tokio::task::yield_now().await;

        Ok(())
    }

    fn decode_handshake_packet(pkt: &ZCPacket) -> Result<HandshakeRequest, Error> {
        let Some(peer_mgr_hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "unexpected packet: cannot decode peer manager hdr".to_owned(),
            ));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}",
                peer_mgr_hdr.packet_type
            )));
        }

        let rsp = HandshakeRequest::decode(pkt.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        Ok(rsp)
    }

    async fn recv_next_peer_manager_packet(
        &self,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<ZCPacket, Error> {
        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();

        loop {
            if let Some(packet) = self.take_pending_packet(expected_pkt_type)? {
                return Ok(packet);
            }
            let Some(ret) = recv.next().await else {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ));
            };
            let batch = match ret {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::WaitRespError(format!(
                        "conn recv error during wait handshake response, err: {:?}",
                        e
                    )));
                }
            };

            let mut pending = self.pending_recv.lock();
            Self::append_pending_handshake_batch(&mut pending, batch)?;
        }
    }

    fn take_pending_packet(
        &self,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<Option<ZCPacket>, Error> {
        let mut pending = self.pending_recv.lock();
        Self::take_pending_handshake_packet(&mut pending, expected_pkt_type)
    }

    fn take_pending_handshake_packet(
        pending: &mut VecDeque<ZCPacket>,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<Option<ZCPacket>, Error> {
        let Some(expected_pkt_type) = expected_pkt_type else {
            return Ok(pending.pop_front());
        };
        let position = pending.iter().position(|packet| {
            packet
                .peer_manager_header()
                .is_some_and(|header| header.packet_type == expected_pkt_type as u8)
        });
        if let Some(position) = position {
            return Ok(pending.remove(position));
        }
        Ok(None)
    }

    fn append_pending_handshake_batch(
        pending: &mut VecDeque<ZCPacket>,
        batch: PacketBatch,
    ) -> Result<(), Error> {
        let packet_count = pending.len().saturating_add(batch.len());
        let byte_count = pending
            .iter()
            .map(ZCPacket::buf_len)
            .sum::<usize>()
            .saturating_add(batch.buffer_byte_len());
        if packet_count > MAX_PENDING_HANDSHAKE_PACKETS || byte_count > MAX_PENDING_HANDSHAKE_BYTES
        {
            return Err(Error::WaitRespError(
                "pending handshake packet limit exceeded".to_owned(),
            ));
        }
        pending.extend(batch);
        Ok(())
    }

    fn decode_b64_32(input: &str) -> Result<Vec<u8>, Error> {
        let decoded = BASE64_STANDARD
            .decode(input)
            .map_err(|e| Error::WaitRespError(format!("base64 decode failed: {e:?}")))?;
        if decoded.len() != 32 {
            return Err(Error::WaitRespError(format!(
                "invalid key length: {}",
                decoded.len()
            )));
        }
        Ok(decoded)
    }

    fn get_pinned_remote_static_pubkey_b64(&self) -> Option<String> {
        let remote_url_str = self
            .tunnel_info
            .as_ref()
            .and_then(|t| t.remote_addr.as_ref())
            .map(|u| u.url.as_str())?;
        let remote_url: url::Url = remote_url_str.parse().ok()?;

        self.global_ctx
            .config
            .get_peers()
            .into_iter()
            .find(|p| p.uri == remote_url)
            .and_then(|p| p.peer_public_key)
    }

    async fn send_noise_msg<Msg: prost::Message + Debug>(
        &self,
        pb: Msg,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        metric_network_name: &str,
        hs: &mut snow::HandshakeState,
    ) -> Result<(), Error> {
        tracing::info!(
            "send noise msg: {:?}, packet_type: {:?}, from: {:?}, to: {:?}",
            pb,
            packet_type,
            self.my_peer_id,
            remote_peer_id
        );
        let payload = pb.encode_to_vec();
        let mut msg = vec![0u8; 4096];
        let msg_len = hs
            .write_message(&payload, &mut msg)
            .map_err(|e| Error::WaitRespError(format!("noise write msg1 failed: {e:?}")))?;
        let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
        pkt.fill_peer_manager_hdr(self.my_peer_id, remote_peer_id, packet_type as u8);
        let pkt_len = pkt.buf_len() as u64;
        self.sink.send(pkt).await?;
        self.record_control_tx(metric_network_name, pkt_len);
        Ok(())
    }

    /// Unified remote peer authentication verification.
    ///
    /// Auth outcome matrix (current behavior):
    ///
    /// | Client role | Server role | Typical credential condition | Client auth level | Server auth level | Client sees server type | Server sees client type |
    /// | --- | --- | --- | --- | --- | --- | --- |
    /// | Admin | Admin | same network_secret, proof verified | NetworkSecretConfirmed | NetworkSecretConfirmed | Admin | Admin |
    /// | Credential | Admin | client pubkey is trusted by admin | EncryptedUnauthenticated | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is unknown | handshake may fail | handshake reject | unknown | unknown |
    /// | Admin | SharedNode | pinned key match | PeerVerified | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Admin | SharedNode | local has no pinned key requirement | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Credential | SharedNode | no pin and not trusted | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Credential |
    /// | Credential | Credential | should reject | handshake reject | handshake reject | unknown | unknown |
    ///
    /// Logic (in priority order):
    /// 1. **NetworkSecretConfirmed**: proof verification succeeds
    /// 2. **PeerVerified**: pinned_pubkey matches and is in trusted list
    ///    (if no network_secret, pinned_pubkey must be in trusted list)
    /// 3. **PeerVerified**: pubkey is in trusted list
    /// 4. **EncryptedUnauthenticated**: initiator without network_secret
    /// 5. **Reject**: none of the above
    #[allow(clippy::too_many_arguments)]
    fn verify_remote_auth(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_pubkey: &[u8],
        pinned_pubkey: Option<&[u8]>,
        has_network_secret: bool,
        is_initiator: bool,
        remote_network_name: &str,
    ) -> Result<SecureAuthLevel, Error> {
        // 1. Verify proof
        if let Some(proof) = proof
            && let Some(mac) = self.global_ctx.get_secret_proof(handshake_hash)
            && mac.verify_slice(proof).is_ok()
        {
            return Ok(SecureAuthLevel::NetworkSecretConfirmed);
        }

        // 2. Check pinned pubkey
        if let Some(pinned) = pinned_pubkey {
            if pinned != remote_pubkey {
                return Err(Error::WaitRespError(
                    "pinned remote static pubkey mismatch".to_owned(),
                ));
            }
            // If no network_secret, pinned key must be in trusted list
            if !has_network_secret
                && !self
                    .global_ctx
                    .is_pubkey_trusted(remote_pubkey, remote_network_name)
            {
                return Err(Error::WaitRespError(
                    "pinned pubkey not in trusted list".to_owned(),
                ));
            }
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 3. Check if pubkey is in trusted list
        if self
            .global_ctx
            .is_pubkey_trusted(remote_pubkey, remote_network_name)
        {
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 4. If we are the initiator without network_secret, keep encrypted channel only.
        if is_initiator && !has_network_secret {
            return Ok(SecureAuthLevel::EncryptedUnauthenticated);
        }

        // 5. Reject
        Err(Error::WaitRespError(
            "authentication failed: invalid proof and unknown credential".to_owned(),
        ))
    }

    fn classify_remote_identity(
        &self,
        remote_network_name: &str,
        secure_auth_level: SecureAuthLevel,
        remote_role_hint_is_same_network: bool,
        remote_sent_secret_proof: bool,
        is_client: bool,
    ) -> PeerIdentityType {
        if !remote_role_hint_is_same_network
            || remote_network_name != self.global_ctx.get_network_name()
        {
            if is_client {
                PeerIdentityType::SharedNode
            } else if remote_sent_secret_proof {
                PeerIdentityType::Admin
            } else {
                PeerIdentityType::Credential
            }
        } else {
            if matches!(secure_auth_level, SecureAuthLevel::NetworkSecretConfirmed)
                || remote_sent_secret_proof
            {
                return PeerIdentityType::Admin;
            }

            PeerIdentityType::Credential
        }
    }

    async fn do_noise_handshake_as_client(&self) -> Result<NoiseHandshakeResult, Error> {
        let prologue = b"lowertier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;

        let pinned_remote_pubkey = self
            .get_pinned_remote_static_pubkey_b64()
            .map(|v| Self::decode_b64_32(&v))
            .transpose()?;

        let builder = snow::Builder::new(params);
        let (local_private_key, local_static_pubkey) = self.get_keypair()?;

        let network = self.global_ctx.get_network_identity();
        let a_session_generation = self
            .peer_id_hint
            .and_then(|peer_id| {
                self.get_peer_session_store()
                    .get(&SessionKey::new(network.network_name.clone(), peer_id))
            })
            .map(|s| s.session_generation());

        let a_conn_id = uuid::Uuid::new_v4();
        let msg1_pb = PeerConnNoiseMsg1Pb {
            version: VERSION,
            a_network_name: network.network_name.clone(),
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.my_encrypt_algo.clone(),
        };

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_private_key)?
            .build_initiator()?;

        self.send_noise_msg(
            msg1_pb,
            PacketType::NoiseHandshakeMsg1,
            PeerId::default(),
            &network.network_name,
            &mut hs,
        )
        .await?;

        let server_handshake_hash = hs.get_handshake_hash().to_vec();

        let msg2 = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg2)),
        )
        .await??;
        self.record_control_rx(&network.network_name, msg2.buf_len() as u64);
        let remote_peer_id = msg2.get_src_peer_id().expect("missing src peer id");
        if let Some(hint) = self.peer_id_hint
            && hint != remote_peer_id
        {
            return Err(Error::WaitRespError("peer_id mismatch".to_owned()));
        }
        let msg2_pb = Self::decode_handshake_message::<PeerConnNoiseMsg2Pb>(
            PacketType::NoiseHandshakeMsg2,
            Some(&mut hs),
            msg2,
        )?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg2 conn_id_echo mismatch".to_owned(),
            ));
        }
        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::WaitRespError("invalid session action".to_owned()))?;
        let remote_network_name = msg2_pb.b_network_name.clone();
        let remote_sent_secret_proof = msg2_pb.secret_proof_32.is_some();

        if remote_network_name == network.network_name && msg2_pb.role_hint != 1 {
            return Err(Error::WaitRespError(
                "role_hint must be 1 when network_name is same".to_owned(),
            ));
        }

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();
        let secret_proof_32 = self
            .global_ctx
            .get_secret_proof(&handshake_hash_for_proof)
            .map(|mac| mac.finalize().into_bytes().to_vec());

        let secret_digest = if use_global_var!(HMAC_SECRET_DIGEST) {
            self.global_ctx
                .get_secret_proof("digest".as_bytes())
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network.network_secret_digest.unwrap_or_default().to_vec()
        };

        let msg3_pb = PeerConnNoiseMsg3Pb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: msg2_pb.b_conn_id,
            secret_proof_32,
            secret_digest: secret_digest.clone(),
        };
        self.send_noise_msg(
            msg3_pb,
            PacketType::NoiseHandshakeMsg3,
            remote_peer_id,
            &network.network_name,
            &mut hs,
        )
        .await?;

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };

        // Verify server authentication using unified logic
        let secure_auth_level = if msg2_pb.role_hint != 1 && pinned_remote_pubkey.is_none() {
            SecureAuthLevel::EncryptedUnauthenticated
        } else {
            self.verify_remote_auth(
                msg2_pb.secret_proof_32.as_deref(),
                &server_handshake_hash,
                &remote_static,
                pinned_remote_pubkey.as_deref(),
                network.network_secret.is_some(),
                true, // is_initiator
                &remote_network_name,
            )?
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            msg2_pb.role_hint == 1,
            remote_sent_secret_proof,
            true,
        );

        let handshake_hash = hs.get_handshake_hash().to_vec();

        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let root_key = msg2_pb
            .root_key_32
            .as_deref()
            .filter(|v| v.len() == 32)
            .map(|v| {
                let mut key = [0u8; 32];
                key.copy_from_slice(v);
                key
            });
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let session = self.get_peer_session_store().apply_initiator_action(
            &SessionKey::new(network.network_name.clone(), remote_peer_id),
            session_action,
            msg2_pb.b_session_generation,
            root_key,
            msg2_pb.initial_epoch,
            algo,
            msg2_pb.server_encryption_algorithm.clone(),
            remote_static_key,
        )?;

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            // we have authorized the peer with noise handshake, so just set secret digest same as us even remote is a shared node.
            secret_digest,
            client_secret_proof: None,

            my_encrypt_algo: self.my_encrypt_algo.clone(),
            remote_encrypt_algo: msg2_pb.server_encryption_algorithm.clone(),
        })
    }

    fn decode_handshake_message<MsgT>(
        expected_pkt_type: PacketType,
        hs: Option<&mut HandshakeState>,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error>
    where
        MsgT: prost::Message + Default,
    {
        tracing::info!(
            "decode_handshake_message: {:?}, expected_pkt_type: {:?}",
            pkt,
            expected_pkt_type
        );
        let Some(hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "packet without peer manager header".to_owned(),
            ));
        };

        if hdr.packet_type != expected_pkt_type as u8 {
            return Err(Error::WaitRespError(format!(
                "packet type not {:?}",
                expected_pkt_type
            )));
        }

        let msg = match hs {
            Some(hs) => {
                let mut out = vec![0u8; 4096];
                let out_len = hs
                    .read_message(pkt.payload(), &mut out)
                    .map_err(|e| Error::WaitRespError(format!("noise read msg failed: {e:?}")))?;
                MsgT::decode(&out[..out_len])
                    .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?
            }
            None => MsgT::decode(pkt.payload())
                .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?,
        };

        Ok(msg)
    }

    async fn read_next_message_with_timeout(
        &mut self,
        read_timeout: Duration,
    ) -> Result<ZCPacket, Error> {
        timeout(read_timeout, self.recv_next_peer_manager_packet(None))
            .await
            .map_err(|e| Error::WaitRespError(format!("read next message timeout: {e:?}")))?
    }

    async fn do_noise_handshake_as_server<Fn>(
        &mut self,
        first_msg1: ZCPacket,
        mut handshake_recved: Fn,
    ) -> Result<NoiseHandshakeResult, Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let prologue = b"lowertier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;
        let builder = snow::Builder::new(params);

        let (local_static_private_key, local_static_pubkey) = self.get_keypair()?;

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_static_private_key)?
            .build_responder()?;

        let remote_peer_id = first_msg1
            .get_src_peer_id()
            .expect("msg1 must have src peer id");
        let first_msg1_len = first_msg1.buf_len() as u64;

        let msg1_pb = Self::decode_handshake_message::<PeerConnNoiseMsg1Pb>(
            PacketType::NoiseHandshakeMsg1,
            Some(&mut hs),
            first_msg1,
        )?;
        let remote_network_name = msg1_pb.a_network_name.clone();
        self.record_control_rx(&remote_network_name, first_msg1_len);

        // this may update my peer id
        handshake_recved(self, &remote_network_name)?;

        let server_network_name = self.global_ctx.get_network_name();
        let (role_hint, secret_proof_32) = if msg1_pb.a_network_name == server_network_name {
            (
                1,
                self.global_ctx
                    .get_secret_proof(hs.get_handshake_hash())
                    .map(|m| m.finalize().into_bytes().to_vec()),
            )
        } else {
            (2, None)
        };

        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let UpsertResponderSessionReturn {
            session,
            action,
            session_generation: b_session_generation,
            root_key: root_key_32,
            initial_epoch,
        } = self.get_peer_session_store().upsert_responder_session(
            &SessionKey::new(remote_network_name.clone(), remote_peer_id),
            msg1_pb.a_session_generation,
            algo.clone(),
            msg1_pb.client_encryption_algorithm.clone(),
            None,
        )?;

        let b_conn_id = uuid::Uuid::new_v4();
        let msg2_pb = PeerConnNoiseMsg2Pb {
            b_network_name: server_network_name,
            role_hint,
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation,
            root_key_32: root_key_32.map(|k| k.to_vec()),
            initial_epoch,
            b_conn_id: Some(b_conn_id.into()),
            a_conn_id_echo: msg1_pb.a_conn_id,
            secret_proof_32,
            server_encryption_algorithm: algo,
        };
        self.send_noise_msg(
            msg2_pb,
            PacketType::NoiseHandshakeMsg2,
            remote_peer_id,
            &remote_network_name,
            &mut hs,
        )
        .await?;

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();

        let msg3_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg3)),
        )
        .await??;
        self.record_control_rx(&remote_network_name, msg3_pkt.buf_len() as u64);
        let msg3_pb = Self::decode_handshake_message::<PeerConnNoiseMsg3Pb>(
            PacketType::NoiseHandshakeMsg3,
            Some(&mut hs),
            msg3_pkt,
        )?;

        if msg3_pb.a_conn_id_echo != msg1_pb.a_conn_id {
            return Err(Error::WaitRespError(
                "noise msg3 a_conn_id mismatch".to_owned(),
            ));
        }
        if msg3_pb.b_conn_id_echo != Some(b_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg3 b_conn_id mismatch".to_owned(),
            ));
        }

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };
        session.check_or_set_peer_static_pubkey(remote_static_key)?;

        // Verify client authentication using unified logic
        // Note: Server doesn't use pinned_pubkey since it's the responder
        let secure_auth_level = if role_hint == 1 {
            self.verify_remote_auth(
                msg3_pb.secret_proof_32.as_deref(),
                &handshake_hash_for_proof,
                &remote_static,
                None, // Server doesn't have pinned_remote_pubkey
                self.global_ctx
                    .get_network_identity()
                    .network_secret
                    .is_some(),
                false, // is_initiator
                &remote_network_name,
            )?
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            role_hint == 1,
            msg3_pb.secret_proof_32.is_some(),
            false,
        );

        let handshake_hash = hs.get_handshake_hash().to_vec();

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
            client_secret_proof: msg3_pb.secret_proof_32.as_ref().map(|p| SecretProof {
                challenge: handshake_hash_for_proof,
                proof: p.clone(),
            }),

            my_encrypt_algo: self.my_encrypt_algo.clone(),
            remote_encrypt_algo: msg1_pb.client_encryption_algorithm.clone(),
        })
    }

    fn build_handshake_rsp(&self, noise: &NoiseHandshakeResult) -> HandshakeRequest {
        tracing::info!("build_handshake_rsp: {:?}", noise);
        HandshakeRequest {
            magic: MAGIC,
            my_peer_id: noise.peer_id,
            version: VERSION,
            network_name: noise.remote_network_name.clone(),

            features: Vec::new(),
            network_secret_digest: noise.secret_digest.clone(),
        }
    }

    #[tracing::instrument(skip(handshake_recved))]
    pub async fn do_handshake_as_server_ext<Fn>(
        &mut self,
        mut handshake_recved: Fn,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let first_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(None),
        )
        .await??;
        let Some(hdr) = first_pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "first packet must have peer manager header".to_owned(),
            ));
        };

        if self.is_secure_mode_enabled() && hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
        {
            let noise = self
                .do_noise_handshake_as_server(first_pkt, handshake_recved)
                .await?;
            // construct handshake rsp from noise result for compat.
            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);
            self.link_envelope_filter.install(LinkEnvelopeSession::new(
                noise.session.root_key(),
                &noise.handshake_hash,
                false,
            ));
            self.noise_handshake_result = Some(noise);

            self.info = Some(handshake_rsp);
            self.is_client = Some(false);
        } else if hdr.packet_type == PacketType::HandShake as u8 {
            let rsp = Self::decode_handshake_packet(&first_pkt)?;
            handshake_recved(self, &rsp.network_name)?;
            tracing::info!("handshake request: {:?}", rsp);
            self.record_control_rx(&rsp.network_name, first_pkt.buf_len() as u64);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest, &self.get_network_identity().network_name)
                .await?;
        } else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type during handshake: {}",
                hdr.packet_type
            )));
        }

        self.legacy_filter.set_peer_id(self.get_peer_id());
        self.legacy_filter.set_opaque_relay(
            self.get_network_identity().network_name
                != self.global_ctx.get_network_identity().network_name,
        );

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        if self.is_secure_mode_enabled() {
            let noise = self.do_noise_handshake_as_client().await?;
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);
            self.link_envelope_filter.install(LinkEnvelopeSession::new(
                noise.session.root_key(),
                &noise.handshake_hash,
                true,
            ));

            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.noise_handshake_result = Some(noise);
            self.info = Some(handshake_rsp);
            self.is_client = Some(true);
        } else {
            let network = self.global_ctx.get_network_identity();
            self.send_handshake(true, &network.network_name).await?;
            tracing::info!("waiting for handshake request from server");
            let rsp = self.wait_handshake_loop().await?;
            tracing::info!("handshake response: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(true);
        }

        self.legacy_filter.set_peer_id(self.get_peer_id());

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError(
                "peer id conflict, are you connecting to yourself?".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    fn control_metrics(&self, network_name: &str) -> AggregateTrafficMetrics {
        AggregateTrafficMetrics::control(
            self.global_ctx.stats_manager().clone(),
            network_name.to_string(),
        )
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.control_metrics(network_name).record_tx(bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.control_metrics(network_name).record_rx(bytes);
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let stream = self.recv.lock().await.take().unwrap();
        let mut pending = std::mem::take(&mut *self.pending_recv.lock());
        let mut pending_batches = Vec::new();
        while !pending.is_empty() {
            let mut batch = PacketBatch::new();
            while batch.len() < crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
                let Some(packet) = pending.pop_front() else {
                    break;
                };
                batch
                    .try_push(packet)
                    .expect("the pending receive batch checks its bound");
            }
            pending_batches.push(Ok(batch));
        }
        let mut stream: Pin<Box<dyn PacketBatchStream>> = if pending_batches.is_empty() {
            stream
        } else {
            Box::pin(futures::stream::iter(pending_batches).chain(stream))
        };
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();
        let control_metrics = self.control_metrics(&conn_info_for_instrument.network_name);
        #[cfg(feature = "quic")]
        let alternate_fec_decoder = self.alternate_fec_decoder.clone();

        let is_foreign_network = conn_info_for_instrument.network_name
            != self.global_ctx.get_network_identity().network_name;
        let recv_limiter = if is_foreign_network
            && self.global_ctx.get_flags().foreign_relay_bps_limit != u64::MAX
        {
            let relay_network_bps_limit = self.global_ctx.get_flags().foreign_relay_bps_limit;
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(relay_network_bps_limit),
                fill_duration_ms: None,
            };
            Some(self.global_ctx.token_bucket_manager().get_or_create(
                &format!("{}:recv", conn_info_for_instrument.network_name),
                limiter_config.into(),
            ))
        } else if self.global_ctx.get_flags().instance_recv_bps_limit != u64::MAX {
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(self.global_ctx.get_flags().instance_recv_bps_limit),
                fill_duration_ms: None,
            };
            Some(
                self.global_ctx
                    .token_bucket_manager()
                    .get_or_create("instance:recv", limiter_config.into()),
            )
        } else {
            None
        };

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                let mut next_result = stream.next().await;
                'receive: while let Some(result) = next_result.take() {
                    let mut incoming = match result {
                        Ok(batch) => batch,
                        Err(error) => {
                            tracing::error!(?error, "peer conn recv error");
                            task_ret = Err(error);
                            break;
                        }
                    };

                    // Parse headers only when missing. The QUIC decoder may already
                    // have filled metadata for a complete direct batch.
                    for packet in incoming.iter_mut() {
                        if packet.parsed_metadata().is_none() {
                            let _ = packet.refresh_parsed_metadata();
                        }
                    }

                    let received_bytes = incoming.buffer_byte_len() as u64;
                    if packet_batch_is_direct_peer_data(&incoming) {
                        let (delivery, mut prefetched, stream_ended) =
                            wait_for_delivery_with_bounded_prefetch(
                                &mut stream,
                                sender.send_batch(incoming),
                                RECEIVE_PREFETCH_BATCHES,
                            )
                            .await;
                        if delivery.is_err() {
                            break;
                        }
                        if received_bytes != 0
                            && let Some(limiter) = recv_limiter.as_ref()
                        {
                            limiter.consume(received_bytes).await;
                        }
                        next_result = if let Some(first) = prefetched.pop_front() {
                            if !prefetched.is_empty() {
                                stream = Box::pin(futures::stream::iter(prefetched).chain(stream));
                            }
                            Some(first)
                        } else if stream_ended {
                            None
                        } else {
                            stream.next().await
                        };
                        continue;
                    }

                    let mut data = PacketBatch::with_capacity(incoming.len());
                    for mut zc_packet in incoming {
                        let buf_len = zc_packet.buf_len() as u64;
                        let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                            tracing::error!(
                                "unexpected packet: {:?}, cannot decode peer manager hdr",
                                zc_packet
                            );
                            continue;
                        };

                        #[cfg(feature = "quic")]
                        if peer_mgr_hdr.packet_type == PacketType::AlternateFecSource as u8
                            || peer_mgr_hdr.packet_type == PacketType::AlternateFecParity as u8
                        {
                            if let Some(decoder) = alternate_fec_decoder.as_ref() {
                                let decoded = {
                                    let mut decoder = decoder.lock();
                                    decode_alternate_fec_packet(
                                        zc_packet,
                                        &mut decoder,
                                        std::time::Instant::now(),
                                    )
                                };
                                match decoded {
                                    Ok(recovered) => {
                                        for packet in recovered {
                                            if let Err(packet) = data.try_push(packet) {
                                                if sender
                                                    .send_batch(std::mem::take(&mut data))
                                                    .await
                                                    .is_err()
                                                {
                                                    break 'receive;
                                                }
                                                data.try_push(packet).expect(
                                                    "fresh alternate FEC receive batch has room",
                                                );
                                            }
                                        }
                                    }
                                    Err(error) => tracing::warn!(
                                        ?error,
                                        "dropping invalid alternate-path FEC packet"
                                    ),
                                }
                            }
                            continue;
                        }

                        if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                            control_metrics.record_rx(buf_len);
                            peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                            if let Err(e) = sink.send(zc_packet).await {
                                tracing::error!(?e, "peer conn send req error");
                            } else {
                                control_metrics.record_tx(buf_len);
                            }
                        } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                            control_metrics.record_rx(buf_len);
                            if let Err(e) = ctrl_sender.send(zc_packet) {
                                tracing::error!(?e, "peer conn send ctrl resp error");
                            }
                        } else {
                            data.try_push(zc_packet)
                                .expect("filtered peer receive vector remains bounded");
                        }
                    }

                    if !data.is_empty() && sender.send_batch(data).await.is_err() {
                        break;
                    }

                    if received_bytes != 0
                        && let Some(limiter) = recv_limiter.as_ref()
                    {
                        limiter.consume(received_bytes).await;
                    }
                    next_result = stream.next().await;
                }

                tracing::info!("end recving peer conn packet");

                drop(sink);
                close_event_notifier.notify_close();

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.sink.clone(),
            self.ctrl_resp_sender.clone(),
            self.latency_stats.clone(),
            self.loss_rate_stats.clone(),
            self.throughput.clone(),
            self.control_metrics(&self.get_conn_info().network_name),
        );

        let close_event_notifier = self.close_event_notifier.clone();

        self.tasks.spawn(async move {
            pingpong.pingpong().await;

            tracing::warn!(?pingpong, "pingpong task exit");

            close_event_notifier.notify_close();

            Ok(())
        });
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        Ok(self.sink.send(msg).await?)
    }

    pub async fn send_msg_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let batch = match batch.pop_singleton() {
            Ok(packet) => return Ok(self.sink.send(packet).await?),
            Err(batch) => batch,
        };
        Ok(self.sink.send_batch(batch).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        let mut ret = NetworkIdentity {
            network_name: info.network_name.clone(),
            network_secret: None,
            network_secret_digest: Some([0u8; 32]),
        };
        ret.network_secret_digest
            .as_mut()
            .unwrap()
            .copy_from_slice(&info.network_secret_digest);
        ret
    }

    fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
        network
            .network_secret_digest
            .as_ref()
            .is_none_or(|digest| digest.iter().all(|byte| *byte == 0))
    }

    fn matches_local_secret_proof(&self) -> bool {
        let Some(secret_proof) = self
            .noise_handshake_result
            .as_ref()
            .and_then(|noise| noise.client_secret_proof.as_ref())
        else {
            return false;
        };

        self.global_ctx
            .get_secret_proof(&secret_proof.challenge)
            .is_some_and(|mac| mac.verify_slice(&secret_proof.proof).is_ok())
    }

    pub(crate) fn matches_local_network_secret(&self) -> bool {
        if self.matches_local_secret_proof() {
            return true;
        }

        let my_identity = self.global_ctx.get_network_identity();
        let peer_identity = self.get_network_identity();

        !Self::network_secret_digest_is_empty(&my_identity)
            && !Self::network_secret_digest_is_empty(&peer_identity)
            && my_identity.network_secret_digest == peer_identity.network_secret_digest
    }

    pub fn get_close_notifier(&self) -> Arc<PeerConnCloseNotify> {
        self.close_event_notifier.clone()
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub(crate) fn tunnel_type(&self) -> Option<&str> {
        self.tunnel_info
            .as_ref()
            .map(|info| info.tunnel_type.as_str())
    }

    #[cfg(test)]
    pub(crate) fn record_latency_for_test(&self, latency_us: u32) {
        self.latency_stats.record_latency(latency_us);
    }

    #[cfg(test)]
    pub(crate) fn set_tunnel_info_for_test(&mut self, tunnel_info: TunnelInfo) {
        self.tunnel_info = Some(tunnel_info);
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        let info = self.info.as_ref().unwrap();
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: info.features.clone(),
            tunnel: self.tunnel_info.clone(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
            is_client: self.is_client.unwrap_or_default(),
            network_name: info.network_name.clone(),
            is_closed: self.close_event_notifier.is_closed(),
            noise_local_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.local_static_pubkey.clone())
                .unwrap_or_default(),
            noise_remote_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.remote_static_pubkey.clone())
                .unwrap_or_default(),
            secure_auth_level: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.secure_auth_level as i32)
                .unwrap_or_default(),
            peer_identity_type: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.peer_identity_type as i32)
                .unwrap_or(PeerIdentityType::Admin as i32),
            tx_delivery_bps: None,
            tx_loss_ppm: None,
            speed_sample_age_ms: None,
            speed_probe_generation: None,
        }
    }

    pub fn get_peer_identity_type(&self) -> PeerIdentityType {
        self.noise_handshake_result
            .as_ref()
            .map(|x| x.peer_identity_type)
            .unwrap_or(PeerIdentityType::Admin)
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        if self.info.is_some() {
            panic!("set_peer_id should only be called before handshake");
        }
        self.my_peer_id = peer_id;
        self.session_filter.set_my_peer_id(peer_id);
        self.legacy_filter.set_my_peer_id(peer_id);
    }

    pub fn get_my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }
}

fn tunnel_url_ip(url: Option<&crate::proto::common::Url>) -> Option<std::net::IpAddr> {
    let ip: std::net::IpAddr = url::Url::parse(&url?.url).ok()?.host_str()?.parse().ok()?;
    (!ip.is_unspecified()).then_some(ip)
}

fn tunnel_infos_have_distinct_quic_surface(left: &TunnelInfo, right: &TunnelInfo) -> bool {
    if left.tunnel_type != "quic" || right.tunnel_type != "quic" {
        return false;
    }
    let left_local = tunnel_url_ip(left.local_addr.as_ref());
    let right_local = tunnel_url_ip(right.local_addr.as_ref());
    let left_remote = tunnel_url_ip(
        left.resolved_remote_addr
            .as_ref()
            .or(left.remote_addr.as_ref()),
    );
    let right_remote = tunnel_url_ip(
        right
            .resolved_remote_addr
            .as_ref()
            .or(right.remote_addr.as_ref()),
    );
    left_local
        .zip(right_local)
        .is_some_and(|(left, right)| left != right)
        || left_remote
            .zip(right_remote)
            .is_some_and(|(left, right)| left != right)
}

fn tunnel_info_allowed_for_alternate_parity(
    info: &TunnelInfo,
    policy: &crate::common::underlay_policy::UnderlayPolicy,
) -> bool {
    if info.tunnel_type != "quic" {
        return false;
    }
    if !policy.is_active() {
        return true;
    }
    // TunnelInfo carries IP endpoints but not a stable interface name. When
    // an interface deny rule is active, do not add alternate-path traffic to
    // a connection whose interface cannot be re-proven at selection time.
    if policy.has_interface_rules() {
        return false;
    }
    let Some(local) = tunnel_url_ip(info.local_addr.as_ref()) else {
        return false;
    };
    let Some(remote) = tunnel_url_ip(
        info.resolved_remote_addr
            .as_ref()
            .or(info.remote_addr.as_ref()),
    ) else {
        return false;
    };
    policy.allows_ip(local) && policy.allows_remote(remote)
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        // if someone drop a conn manually, the notifier is not called.
        self.close_event_notifier.notify_close();
    }
}

#[cfg(test)]
pub mod tests {
    use std::{sync::Arc, time::Duration};

    use rand::rngs::OsRng;

    use super::*;
    use crate::common::config::PeerConfig;
    use crate::common::global_ctx::GlobalCtx;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::common::stats_manager::{LabelSet, LabelType, MetricName};

    #[tokio::test]
    async fn direct_delivery_prefetches_exactly_one_batch() {
        let mut stream = futures::stream::iter([1_u8, 2_u8]);
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            release.send(()).unwrap();
        });

        let (delivery, prefetched) =
            crate::tunnel::batch::wait_for_delivery_with_one_prefetch(&mut stream, async {
                wait.await.map_err(|_| ())
            })
            .await;

        assert!(delivery.is_ok());
        assert_eq!(prefetched, Some(Some(1)));
        assert_eq!(stream.next().await, Some(2));
    }

    #[tokio::test]
    async fn direct_delivery_prefetches_configured_ready_batches() {
        let mut stream = futures::stream::iter([1_u8, 2_u8, 3_u8, 4_u8]);
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            release.send(()).unwrap();
        });

        let (delivery, prefetched, stream_ended) = wait_for_delivery_with_bounded_prefetch(
            &mut stream,
            async { wait.await.map_err(|_| ()) },
            RECEIVE_PREFETCH_BATCHES,
        )
        .await;

        assert!(delivery.is_ok());
        assert!(!stream_ended);
        assert_eq!(prefetched.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(stream.next().await, Some(4));
    }
    use crate::peers::create_packet_recv_chan;
    use crate::peers::recv_packet_from_chan;
    use crate::tunnel::common::tests::wait_for_condition;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;
    use tokio_util::task::AbortOnDropHandle;

    #[test]
    fn normal_data_batch_keeps_transport_owned_storage() {
        let mut batch = PacketBatch::new();
        for value in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[value; 64]);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }
        assert!(packet_batch_is_direct_peer_data(&batch));

        let mut ping = ZCPacket::new_with_payload(b"ping");
        ping.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
        batch.try_push(ping).unwrap();
        assert!(!packet_batch_is_direct_peer_data(&batch));
    }

    #[test]
    fn handshake_preserves_a_bounded_nonmatching_pending_batch() {
        let mut pending = VecDeque::new();
        let mut packet = ZCPacket::new_with_payload(b"early data");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        pending.push_back(packet);

        let result =
            PeerConn::take_pending_handshake_packet(&mut pending, Some(PacketType::HandShake));

        assert!(result.unwrap().is_none());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn handshake_rejects_a_pending_packet_count_overflow() {
        let mut pending = VecDeque::new();
        for _ in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
            pending.push_back(ZCPacket::new_with_payload(b"early data"));
        }
        let batch = PacketBatch::singleton(ZCPacket::new_with_payload(b"overflow"));

        let result = PeerConn::append_pending_handshake_batch(&mut pending, batch);

        assert!(matches!(result, Err(Error::WaitRespError(_))));
        assert_eq!(pending.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
    }

    #[test]
    fn handshake_rejects_a_pending_byte_overflow() {
        let mut pending = VecDeque::new();
        let packet = ZCPacket::new_with_payload(&vec![0_u8; MAX_PENDING_HANDSHAKE_BYTES]);
        let batch = PacketBatch::singleton(packet);

        let result = PeerConn::append_pending_handshake_batch(&mut pending, batch);

        assert!(matches!(result, Err(Error::WaitRespError(_))));
        assert!(pending.is_empty());
    }

    #[test]
    fn alternate_parity_requires_two_distinct_quic_ip_surfaces() {
        let url = |value: &str| Some(url::Url::parse(value).unwrap().into());
        let path_a = TunnelInfo {
            tunnel_type: "quic".into(),
            local_addr: url("quic://192.0.2.10:31000"),
            remote_addr: url("quic://198.51.100.20:11010"),
            resolved_remote_addr: url("quic://198.51.100.20:11010"),
        };
        let same_ips_new_ports = TunnelInfo {
            tunnel_type: "quic".into(),
            local_addr: url("quic://192.0.2.10:32000"),
            remote_addr: url("quic://198.51.100.20:12000"),
            resolved_remote_addr: url("quic://198.51.100.20:12000"),
        };
        let alternate_remote = TunnelInfo {
            tunnel_type: "quic".into(),
            local_addr: url("quic://192.0.2.10:33000"),
            remote_addr: url("quic://203.0.113.50:11010"),
            resolved_remote_addr: url("quic://203.0.113.50:11010"),
        };
        let udp_path = TunnelInfo {
            tunnel_type: "udp".into(),
            ..alternate_remote.clone()
        };

        assert!(!tunnel_infos_have_distinct_quic_surface(
            &path_a,
            &same_ips_new_ports
        ));
        assert!(tunnel_infos_have_distinct_quic_surface(
            &path_a,
            &alternate_remote
        ));
        assert!(!tunnel_infos_have_distinct_quic_surface(&path_a, &udp_path));
    }

    #[test]
    fn alternate_parity_rechecks_strict_deny_policy() {
        let denied_cidr =
            crate::common::underlay_policy::UnderlayPolicy::new(&[], &["100.64.0.0/10".into()])
                .unwrap();
        let denied_interface =
            crate::common::underlay_policy::UnderlayPolicy::new(&["tailscale0".into()], &[])
                .unwrap();
        let tailscale = TunnelInfo {
            tunnel_type: "quic".into(),
            local_addr: Some(url::Url::parse("quic://192.0.2.10:31000").unwrap().into()),
            remote_addr: Some(
                url::Url::parse("quic://100.100.20.30:11010")
                    .unwrap()
                    .into(),
            ),
            resolved_remote_addr: Some(
                url::Url::parse("quic://100.100.20.30:11010")
                    .unwrap()
                    .into(),
            ),
        };

        assert!(!tunnel_info_allowed_for_alternate_parity(
            &tailscale,
            &denied_cidr
        ));
        assert!(!tunnel_info_allowed_for_alternate_parity(
            &tailscale,
            &denied_interface
        ));
    }

    pub fn set_secure_mode_cfg(global_ctx: &GlobalCtx, enabled: bool) {
        if !enabled {
            global_ctx.config.set_secure_mode(None);
        } else {
            // generate x25519 key pair
            let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&private);

            global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }));
        }
    }

    fn metric_value(global_ctx: &GlobalCtx, metric: MetricName, network_name: &str) -> u64 {
        global_ctx
            .stats_manager()
            .get_metric(
                metric,
                &LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string())),
            )
            .map(|metric| metric.value)
            .unwrap_or(0)
    }

    #[test]
    fn peer_session_filter_skips_relay_packet_for_next_hop() {
        let my_peer_id = 10;
        let next_hop_peer_id = 20;
        let dst_peer_id = 30;
        let filter = PeerSessionTunnelFilter::new_with_peer(my_peer_id, true);
        filter.set_peer_id(next_hop_peer_id);

        let session = Arc::new(PeerSession::new(
            next_hop_peer_id,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_string(),
            "aes-gcm".to_string(),
            None,
        ));
        session.invalidate();
        filter.set_session(session);

        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(my_peer_id, dst_peer_id, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        let original_len = packet.buf_len();

        let packet = filter
            .before_send(packet)
            .expect("relay packet should bypass next-hop session");

        let hdr = packet.peer_manager_header().unwrap();
        assert_eq!(hdr.from_peer_id.get(), my_peer_id);
        assert_eq!(hdr.to_peer_id.get(), dst_peer_id);
        assert!(hdr.is_encrypted());
        assert_eq!(packet.buf_len(), original_len);
    }

    #[test]
    fn peer_session_filter_batch_encrypts_once_and_preserves_order() {
        let my_peer_id = 10;
        let peer_id = 20;
        let filter = PeerSessionTunnelFilter::new_with_peer(my_peer_id, true);
        filter.set_peer_id(peer_id);
        filter.set_session(Arc::new(PeerSession::new(
            peer_id,
            PeerSession::new_root_key(),
            1,
            0,
            "chacha20-poly1305".to_string(),
            "chacha20-poly1305".to_string(),
            None,
        )));

        let mut batch = crate::tunnel::batch::PacketBatch::new();
        for value in 1..=8_u8 {
            let mut packet = ZCPacket::new_with_payload(&[value]);
            packet.fill_peer_manager_hdr(my_peer_id, peer_id, PacketType::Data as u8);
            batch.try_push(packet).unwrap();
        }

        filter.encrypt_batch_parallel(&mut batch).unwrap();
        let encrypted_payloads = batch
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>();
        assert!(
            batch
                .iter()
                .all(|packet| { packet.peer_manager_header().unwrap().is_encrypted() })
        );

        let passed = batch
            .into_iter()
            .map(|packet| filter.before_send(packet).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            passed
                .iter()
                .map(|packet| packet.payload().to_vec())
                .collect::<Vec<_>>(),
            encrypted_payloads
        );
        assert_eq!(
            passed
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>()
                .len(),
            8
        );
    }

    #[test]
    fn peer_session_filter_uses_the_link_envelope_for_a_direct_packet() {
        let my_peer_id = 10;
        let peer_id = 20;
        let sender = PeerSessionTunnelFilter::new_with_peer_and_link_active(
            my_peer_id,
            true,
            Arc::new(AtomicBool::new(true)),
        );
        let receiver = PeerSessionTunnelFilter::new_with_peer_and_link_active(
            peer_id,
            true,
            Arc::new(AtomicBool::new(true)),
        );
        sender.set_peer_id(peer_id);
        receiver.set_peer_id(my_peer_id);

        let mut packet = ZCPacket::new_with_payload(b"direct payload");
        packet.fill_peer_manager_hdr(my_peer_id, peer_id, PacketType::Data as u8);

        let packet = sender.before_send(packet).unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
        let packet = receiver.after_received(Ok(packet)).unwrap().unwrap();
        assert_eq!(packet.payload(), b"direct payload");
    }

    fn legacy_filter(
        my_peer_id: PeerId,
        peer_id: PeerId,
        transport_authenticated: bool,
    ) -> LegacyNetworkTunnelFilter {
        let cipher = crate::peers::encrypt::create_encryptor("aes-gcm", [7_u8; 16], [9_u8; 32]);
        let filter =
            LegacyNetworkTunnelFilter::new(my_peer_id, true, transport_authenticated, cipher);
        filter.set_peer_id(peer_id);
        filter
    }

    #[test]
    fn authenticated_quic_skips_inner_encryption_for_direct_data() {
        let sender = legacy_filter(10, 20, true);
        let mut packet = ZCPacket::new_with_payload(b"direct data");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        let packet = sender.before_send(packet).unwrap();

        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(packet.payload(), b"direct data");
    }

    #[test]
    fn fallback_transport_keeps_inner_encryption() {
        let sender = legacy_filter(10, 20, false);
        let receiver = legacy_filter(20, 10, false);
        let mut packet = ZCPacket::new_with_payload(b"fallback data");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        let packet = sender.before_send(packet).unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        let packet = receiver.after_received(Ok(packet)).unwrap().unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(packet.payload(), b"fallback data");
    }

    #[test]
    fn authenticated_quic_keeps_relay_data_encrypted_until_destination() {
        let origin = legacy_filter(10, 20, true);
        let relay_receive = legacy_filter(20, 10, true);
        let relay_send = legacy_filter(20, 30, true);
        let destination = legacy_filter(30, 20, true);
        let mut packet = ZCPacket::new_with_payload(b"relay data");
        packet.fill_peer_manager_hdr(10, 30, PacketType::Data as u8);

        let packet = origin.before_send(packet).unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        let packet = relay_receive.after_received(Ok(packet)).unwrap().unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        let packet = relay_send.before_send(packet).unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());

        let packet = destination.after_received(Ok(packet)).unwrap().unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(packet.payload(), b"relay data");
    }

    #[test]
    fn foreign_relay_preserves_opaque_legacy_data() {
        let origin = legacy_filter(10, 20, false);
        let relay = legacy_filter(20, 10, false);
        relay.set_opaque_relay(true);
        let mut packet = ZCPacket::new_with_payload(b"foreign relay data");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        let packet = origin.before_send(packet).unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());
        let encrypted_payload = packet.payload().to_vec();

        let packet = relay.after_received(Ok(packet)).unwrap().unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(packet.payload(), encrypted_payload);
    }

    #[test]
    fn foreign_network_wrapper_stays_parseable_for_routing() {
        let sender = legacy_filter(10, 20, false);
        let inner = ZCPacket::new_with_payload(b"encrypted inner packet");
        let network_name = "foreign".to_string();
        let mut packet = ZCPacket::new_for_foreign_network(&network_name, 30, &inner);
        packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        let packet = sender.before_send(packet).unwrap();

        assert!(!packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(
            packet
                .foreign_network_hdr()
                .unwrap()
                .get_network_name(packet.payload()),
            "foreign"
        );
    }

    #[tokio::test]
    async fn peer_conn_handshake_same_id() {
        let ps = Arc::new(PeerSessionStore::new());
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = c_peer_id;

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        assert!(c_ret.is_err());
        assert!(s_ret.is_err());
    }

    #[tokio::test]
    async fn peer_conn_handshake() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let ps = Arc::new(PeerSessionStore::new());
        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());

        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(c_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(c_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(s_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(s_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default"),
            c_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default"),
            c_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default"),
            s_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default"),
            s_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );

        assert_eq!(c_peer.get_peer_id(), s_peer_id);
        assert_eq!(s_peer.get_peer_id(), c_peer_id);
        assert_eq!(c_peer.get_network_identity(), s_peer.get_network_identity());
        assert_eq!(
            c_peer.get_network_identity().network_name,
            NetworkIdentity::default().network_name
        );
        assert_eq!(c_peer.get_network_identity().network_secret, None);
        assert_eq!(
            c_peer.get_network_identity().network_secret_digest,
            NetworkIdentity::default().network_secret_digest
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_pubkey_and_encryption() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default"),
            c_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default"),
            c_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default"),
            s_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default"),
            s_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );

        let c_info = c_peer.get_conn_info();
        let s_info = s_peer.get_conn_info();

        assert_eq!(c_info.noise_local_static_pubkey.len(), 32);
        assert_eq!(c_info.noise_remote_static_pubkey.len(), 32);
        assert_eq!(s_info.noise_local_static_pubkey.len(), 32);
        assert_eq!(s_info.noise_remote_static_pubkey.len(), 32);

        assert_eq!(
            c_info.noise_remote_static_pubkey,
            s_info.noise_local_static_pubkey
        );
        assert_eq!(
            s_info.noise_remote_static_pubkey,
            c_info.noise_local_static_pubkey
        );

        let network = s_ctx.get_network_identity();
        let mut expected = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: s_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };
        expected
            .network_secret_digest
            .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        let expected_payload = expected.encode_to_vec();

        println!("sent: {:?}", c_recorder.sent.lock().unwrap());

        let wire_hs = c_recorder
            .sent
            .lock()
            .unwrap()
            .iter()
            .find(|p| {
                p.peer_manager_header()
                    .is_some_and(|h| h.packet_type == PacketType::NoiseHandshakeMsg3 as u8)
            })
            .unwrap()
            .clone();
        assert_ne!(wire_hs.payload(), expected_payload.as_slice());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_server_accept_legacy_client() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "shared".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None as i32,
        );

        assert_eq!(c_peer.get_conn_info().network_name, "shared".to_string());
        assert_eq!(s_peer.get_conn_info().network_name, "user".to_string());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_different_network_name_ok() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "shared".to_string(),
            "sec2".to_string(),
        ));

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );

        assert_eq!(c_peer.get_conn_info().network_name, "shared".to_string());
        assert_eq!(s_peer.get_conn_info().network_name, "user".to_string());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_data_roundtrip() {
        let (c, s) = create_ring_tunnel_pair();
        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let c = TunnelWithFilter::new(c, c_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();
        assert_eq!(
            c_peer
                .noise_handshake_result
                .as_ref()
                .unwrap()
                .handshake_hash,
            s_peer
                .noise_handshake_result
                .as_ref()
                .unwrap()
                .handshake_hash
        );
        assert_eq!(
            c_peer
                .noise_handshake_result
                .as_ref()
                .unwrap()
                .session
                .root_key(),
            s_peer
                .noise_handshake_result
                .as_ref()
                .unwrap()
                .session
                .root_key()
        );

        let mut link_probe = ZCPacket::new_with_payload(b"link-probe");
        link_probe.fill_peer_manager_hdr(c_peer_id, s_peer_id, PacketType::Data as u8);
        let link_probe = c_peer.link_envelope_filter.before_send(link_probe).unwrap();
        let link_probe = s_peer
            .link_envelope_filter
            .after_received(Ok(link_probe))
            .unwrap()
            .unwrap();
        assert_eq!(link_probe.payload(), b"link-probe");

        let (packet_send, mut packet_recv) = create_packet_recv_chan();
        s_peer.start_recv_loop(packet_send).await;

        let payload = b"secure-data-123";
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(c_peer_id, s_peer_id, PacketType::Data as u8);
        c_peer.send_msg(pkt).await.unwrap();

        let got = timeout(Duration::from_secs(2), async move {
            recv_packet_from_chan(&mut packet_recv).await
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(got.payload(), payload);
        assert_eq!(
            got.peer_manager_header().unwrap().packet_type,
            PacketType::Data as u8
        );

        let sent = c_recorder.sent.lock().unwrap();
        let wire_packet = sent.last().expect("the data packet must be recorded");
        let wire_bytes = wire_packet.tunnel_payload();
        assert!(
            !wire_bytes
                .windows(4)
                .any(|bytes| bytes == c_peer_id.to_le_bytes())
        );
        assert!(
            !wire_bytes
                .windows(4)
                .any(|bytes| bytes == s_peer_id.to_le_bytes())
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_batch_roundtrip_preserves_order() {
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();
        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());
        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        let (packet_send, mut packet_recv) = create_packet_recv_chan();
        s_peer.start_recv_loop(packet_send).await;
        let mut batch = crate::tunnel::batch::PacketBatch::new();
        for value in 1..=4_u8 {
            let mut packet = ZCPacket::new_with_payload(&[value]);
            packet.fill_peer_manager_hdr(c_peer_id, s_peer_id, PacketType::Data as u8);
            batch.try_push(packet).unwrap();
        }

        c_peer.send_msg_batch(batch).await.unwrap();

        let received = timeout(Duration::from_secs(2), async move {
            let mut values = Vec::new();
            for _ in 0..4 {
                values.push(
                    recv_packet_from_chan(&mut packet_recv)
                        .await
                        .unwrap()
                        .payload()[0],
                );
            }
            values
        })
        .await
        .unwrap();
        assert_eq!(received, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_network_secret_confirmed() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        s_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_shared_node_pubkey_verified() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "net2".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });

        let remote_url: url::Url = c.info().unwrap().remote_addr.unwrap().url.parse().unwrap();

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        c_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_public_key: Some(
                s_ctx
                    .config
                    .get_secure_mode()
                    .unwrap()
                    .local_public_key
                    .unwrap(),
            ),
        }]);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::PeerVerified as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::SharedNode as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_shared_node_without_pin_is_unauthenticated() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "net2".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::SharedNode as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
    }

    async fn peer_conn_pingpong_test_common(
        drop_start: u32,
        drop_end: u32,
        conn_closed: bool,
        drop_both: bool,
    ) {
        let (c, s) = create_ring_tunnel_pair();

        // drop 1-3 packets should not affect pingpong
        let c_recorder = Arc::new(DropSendTunnelFilter::new(drop_start, drop_end));
        let c = TunnelWithFilter::new(c, c_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        s_peer.start_recv_loop(create_packet_recv_chan().0).await;
        // do not start ping for s, s only reponde to ping from c

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        let close_notifier = c_peer.get_close_notifier();
        c_peer.start_pingpong();
        c_peer.start_recv_loop(create_packet_recv_chan().0).await;

        let throughput = c_peer.throughput.clone();
        let _t = AbortOnDropHandle::new(tokio::spawn(async move {
            // if not drop both, we mock some rx traffic for client peer to test pinger
            if drop_both {
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(3);
            }
        }));

        tokio::time::sleep(Duration::from_secs(15)).await;

        if conn_closed {
            assert!(close_notifier.is_closed());
        } else {
            assert!(!close_notifier.is_closed());
        }
    }

    #[tokio::test]
    async fn peer_conn_pingpong_records_control_metrics() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        s_peer.start_recv_loop(create_packet_recv_chan().0).await;
        c_peer.start_pingpong();
        c_peer.start_recv_loop(create_packet_recv_chan().0).await;

        wait_for_condition(
            || {
                let c_ctx = c_ctx.clone();
                let s_ctx = s_ctx.clone();
                async move {
                    metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default") > 0
                        && metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default") > 0
                        && metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default") > 0
                        && metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default") > 0
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_timeout_not_close() {
        peer_conn_pingpong_test_common(3, 5, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_oneside_timeout() {
        peer_conn_pingpong_test_common(4, 12, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_bothside_timeout() {
        peer_conn_pingpong_test_common(3, 14, true, true).await;
    }

    #[tokio::test]
    async fn close_tunnel_during_handshake() {
        let ps = Arc::new(PeerSessionStore::new());
        let (c, s) = create_ring_tunnel_pair();
        let mut c_peer = PeerConn::new(
            new_peer_id(),
            get_mock_global_ctx(),
            Box::new(c),
            ps.clone(),
        );
        let j = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(s);
        });
        timeout(Duration::from_millis(1500), c_peer.do_handshake_as_client())
            .await
            .unwrap()
            .unwrap_err();
        let _ = tokio::join!(j);
    }

    /// Helper: set up a credential node's GlobalCtx with a specific private key
    /// (no network_secret, secure mode enabled with the given keypair)
    fn set_credential_mode_cfg(
        global_ctx: &GlobalCtx,
        network_name: &str,
        private_key: &x25519_dalek::StaticSecret,
    ) {
        use crate::common::config::NetworkIdentity;
        let public = x25519_dalek::PublicKey::from(private_key);
        global_ctx
            .config
            .set_network_identity(NetworkIdentity::new_credential(network_name.to_string()));
        global_ctx.config.set_secure_mode(Some(SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        }));
    }

    /// Test: credential node connects to admin node, admin has credential in trusted list.
    /// Handshake should succeed with PeerVerified auth level on server side.
    #[tokio::test]
    async fn peer_conn_credential_node_connects_to_admin() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        // Admin node (server) has network_secret
        let s_ctx = get_mock_global_ctx();
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&s_ctx, true);

        // Generate a credential on admin and get the private key for the client
        let (cred_id, cred_secret) = s_ctx.get_credential_manager().generate_credential(
            vec!["guest".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

        // Credential node (client) uses credential private key
        let c_ctx = get_mock_global_ctx();
        let privkey_bytes: [u8; 32] = BASE64_STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        set_credential_mode_cfg(&c_ctx, "net1", &private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        // Server should see credential node as PeerVerified
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::PeerVerified as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Credential as i32,
        );

        // Client (credential node) keeps encrypted unauthenticated level
        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );

        // Verify credential ID matches
        let _ = cred_id; // just to use it
    }

    /// Test: unknown credential node (not in trusted list) is rejected by admin.
    #[tokio::test]
    async fn peer_conn_unknown_credential_rejected() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        // Admin node (server) with no credentials generated
        let s_ctx = get_mock_global_ctx();
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&s_ctx, true);

        // Unknown credential node (client) with random key, not in admin's trusted list
        let c_ctx = get_mock_global_ctx();
        let random_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        set_credential_mode_cfg(&c_ctx, "net1", &random_private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        // Server should reject the unknown credential
        assert!(s_ret.is_err(), "server should reject unknown credential");
        // Client may also fail due to connection being closed
        let _ = c_ret;
    }

    /// Test: two admin nodes with same network_secret still get NetworkSecretConfirmed.
    /// (Regression test: credential system should not break normal admin-to-admin auth)
    #[tokio::test]
    async fn peer_conn_admin_to_admin_still_works() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
    }

    /// Test: revoked credential is rejected on new connection attempt.
    #[tokio::test]
    async fn peer_conn_revoked_credential_rejected() {
        // Admin generates credential, then revokes it
        let admin_ctx = get_mock_global_ctx();
        admin_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&admin_ctx, true);

        let (cred_id, cred_secret) = admin_ctx.get_credential_manager().generate_credential(
            vec![],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

        // Revoke the credential
        assert!(
            admin_ctx
                .get_credential_manager()
                .revoke_credential(&cred_id)
        );

        // Now try to connect with the revoked credential
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let privkey_bytes: [u8; 32] = BASE64_STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        set_credential_mode_cfg(&c_ctx, "net1", &private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, admin_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        // Server should reject the revoked credential
        assert!(s_ret.is_err(), "server should reject revoked credential");
        let _ = c_ret;
    }
}
