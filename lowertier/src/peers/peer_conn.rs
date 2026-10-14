use arc_swap::ArcSwapOption;
use crossbeam::atomic::AtomicCell;
use futures::StreamExt;
use std::{
    any::Any,
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
};

use tokio::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::Mac;
use prost::Message;
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use tokio::{
    sync::broadcast,
    task::JoinSet,
    time::{Duration, timeout},
};

use tracing::Instrument;

use snow::{HandshakeState, TransportState, params::NoiseParams};

use super::{
    PacketRecvChan,
    peer_conn_ping::PeerConnPinger,
    peer_session::{
        INITIATOR_RECOVERY_LIFETIME, InitiatorTransitionIdentity, PeerSession, PeerSessionAction,
    },
    receiver_pacing::{
        RECEIVER_PACING_FEATURE, RECEIVER_PRESSURE_REPORT_INTERVAL, ReceiverPacer,
        ReceiverPressureReport, paced_batch_bytes, paced_packet_bytes, receiver_pacing_enabled,
        shared_receiver_pacer,
    },
    speed_probe::{
        ProbeAck, ProbeData, ProbeReceiver, ProbeReservation, SpeedSample,
        generate_receipt_challenge, probe_train_metadata, speed_sample_ttl,
    },
    traffic_metrics::{AggregateTrafficMetrics, SpeedProbeMetrics},
};
use crate::{
    common::{
        PeerId,
        config::{EncryptionAlgorithm, NetworkIdentity},
        dataplane_telemetry::DataplaneStage,
        error::Error,
        global_ctx::ArcGlobalCtx,
        verify_slices_are_equal,
    },
    peers::credential_manager::CredentialManager,
    peers::peer_session::{
        InitiatorSessionReservation, PeerSessionStore, SessionKey, UpsertResponderSessionReturn,
    },
    proto::{
        api::instance::{PeerConnInfo, PeerConnStats},
        common::{SecureModeConfig, TunnelInfo},
        peer_rpc::{
            CredentialCertificate, CredentialCertificateStatus, HandshakeRequest,
            PeerConnDataProtectionPb, PeerConnNoiseCommitAckPb, PeerConnNoiseCommitDonePb,
            PeerConnNoiseCommitPb, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnNoiseReadyAckPb, PeerConnNoiseReadyPb, PeerConnNoiseReadyReceiptAckPb,
            PeerConnNoiseReadyReceiptPb, PeerConnNoiseRecoveryPb, PeerConnSessionActionPb,
            PeerIdentityType, SecureAuthLevel,
        },
    },
    tunnel::{
        BatchStreamItem, PacketBatchStream, TransportBinding, TransportBindingKind, Tunnel,
        TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, RECEIVE_PREFETCH_BATCHES},
        direct::{DirectTunnel, DirectTunnelSender},
        filter::{
            StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter,
            scalar_after_received_batch,
        },
        packet_def::{PEER_MANAGER_HEADER_SIZE, PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
    },
    use_global_var,
};

pub type PeerConnId = uuid::Uuid;

fn is_noise_handshake_packet_type(packet_type: u8) -> bool {
    matches!(
        packet_type,
        value if value == PacketType::NoiseHandshakeMsg1 as u8
            || value == PacketType::NoiseHandshakeMsg2 as u8
            || value == PacketType::NoiseHandshakeMsg3 as u8
            || value == PacketType::NoiseHandshakeCommit as u8
            || value == PacketType::NoiseHandshakeCommitAck as u8
            || value == PacketType::NoiseHandshakeCommitDone as u8
            || value == PacketType::NoiseHandshakeReady as u8
            || value == PacketType::NoiseHandshakeReadyAck as u8
            || value == PacketType::NoiseHandshakeReadyReceipt as u8
            || value == PacketType::NoiseHandshakeReadyReceiptAck as u8
    )
}

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 4;
const MAX_ADMISSION_CERT_BYTES: usize = 4096;
const MAX_ADMISSION_STATUS_BYTES: usize = 2048;
const ADMISSION_CONTEXT_DOMAIN: &[u8] = b"lowertier peer admission context v1\0";
const CERTIFICATE_DIGEST_DOMAIN: &[u8] = b"lowertier certificate digest v1\0";
const STATUS_DIGEST_DOMAIN: &[u8] = b"lowertier credential status digest v1\0";
const NOISE_PROLOGUE_DOMAIN: &[u8] = b"lowertier peerconn noise prologue v1\0";
const MAX_PENDING_HANDSHAKE_PACKETS: usize = MAX_PACKET_BATCH_SIZE;
const MAX_PENDING_HANDSHAKE_BYTES: usize =
    MAX_PENDING_HANDSHAKE_PACKETS * (4096 + PEER_MANAGER_HEADER_SIZE);
pub(crate) const SPEED_ROUTING_FEATURE: &str = "speed-routing-v2";

fn handshake_features() -> Vec<String> {
    vec![
        SPEED_ROUTING_FEATURE.to_string(),
        RECEIVER_PACING_FEATURE.to_string(),
    ]
}

fn validate_protocol_version(version: u32) -> Result<(), Error> {
    if version == VERSION {
        return Ok(());
    }
    Err(Error::WaitRespError(format!(
        "peer protocol version {version} does not match local version {VERSION}"
    )))
}

fn recovery_pb_from_identity(identity: &InitiatorTransitionIdentity) -> PeerConnNoiseRecoveryPb {
    PeerConnNoiseRecoveryPb {
        session_metadata_id: Some(identity.session_metadata_id.into()),
        action: match identity.action {
            PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
            PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
            PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
        },
        session_generation: identity.session_generation,
        initial_epoch: identity.initial_epoch,
        root_key_digest: identity.root_key_digest.to_vec(),
        transition_id: identity.transition_id.to_vec(),
    }
}

fn recovery_identity_from_pb(
    pb: PeerConnNoiseRecoveryPb,
    session_key: SessionKey,
) -> Result<InitiatorTransitionIdentity, Error> {
    let action = PeerConnSessionActionPb::try_from(pb.action)
        .map_err(|_| Error::WaitRespError("invalid recovery action".to_owned()))?;
    let action = match action {
        PeerConnSessionActionPb::Join => PeerSessionAction::Join,
        PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
        PeerConnSessionActionPb::Create => PeerSessionAction::Create,
    };
    let session_metadata_id = pb
        .session_metadata_id
        .ok_or_else(|| Error::WaitRespError("recovery metadata id is missing".to_owned()))?;
    let session_metadata_id = uuid::Uuid::from(session_metadata_id);
    if pb.root_key_digest.len() != 32 || pb.transition_id.len() != 16 {
        return Err(Error::WaitRespError("invalid recovery identity".to_owned()));
    }
    let mut root_key_digest = [0_u8; 32];
    root_key_digest.copy_from_slice(&pb.root_key_digest);
    let mut transition_id = [0_u8; 16];
    transition_id.copy_from_slice(&pb.transition_id);
    if transition_id == [0; 16] {
        return Err(Error::WaitRespError(
            "recovery transition id must not be zero".to_owned(),
        ));
    }
    Ok(InitiatorTransitionIdentity::new(
        session_key,
        session_metadata_id,
        action,
        pb.session_generation,
        pb.initial_epoch,
        transition_id,
        root_key_digest,
    ))
}

fn transition_id_from_wire(bytes: &[u8]) -> Result<[u8; 16], Error> {
    if bytes.len() != 16 {
        return Err(Error::WaitRespError(
            "invalid session transition id".to_owned(),
        ));
    }
    let mut transition_id = [0_u8; 16];
    transition_id.copy_from_slice(bytes);
    if transition_id == [0; 16] {
        return Err(Error::WaitRespError(
            "session transition id must not be zero".to_owned(),
        ));
    }
    Ok(transition_id)
}

fn optional_transition_id_from_wire(bytes: &[u8]) -> Result<Option<[u8; 16]>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    transition_id_from_wire(bytes).map(Some)
}

fn recovery_identity_matches_wire(
    local: Option<&InitiatorTransitionIdentity>,
    remote: Option<&InitiatorTransitionIdentity>,
) -> bool {
    match (local, remote) {
        (None, None) => true,
        (Some(local), Some(remote)) => {
            local.session_key == remote.session_key
                && local.session_metadata_id == remote.session_metadata_id
                && local.action == remote.action
                && local.session_generation == remote.session_generation
                && local.initial_epoch == remote.initial_epoch
                && verify_slices_are_equal(&local.transition_id, &remote.transition_id).is_ok()
                && verify_slices_are_equal(&local.root_key_digest, &remote.root_key_digest).is_ok()
        }
        _ => false,
    }
}

fn packet_batch_is_direct_control(packet_type: u8) -> bool {
    packet_type == PacketType::Ping as u8
        || packet_type == PacketType::Pong as u8
        || packet_type == PacketType::SpeedProbe as u8
        || packet_type == PacketType::SpeedProbeAck as u8
        || packet_type == PacketType::ReceiverPressure as u8
        || is_noise_handshake_packet_type(packet_type)
}

fn packet_batch_is_direct_peer_data(batch: &PacketBatch) -> bool {
    !batch.is_empty()
        && batch.iter().all(|packet| {
            if let Some(metadata) = packet.parsed_metadata() {
                return !packet_batch_is_direct_control(metadata.packet_type);
            }
            packet
                .peer_manager_header()
                .is_some_and(|header| !packet_batch_is_direct_control(header.packet_type))
        })
}

fn batch_packet_type_is_direct_ping_pong(packet_type: u8) -> bool {
    packet_type == PacketType::Ping as u8 || packet_type == PacketType::Pong as u8
}

fn stamp_and_validate_incoming_identity(
    batch: &mut PacketBatch,
    probe_peer_id: PeerId,
    identity_type: PeerIdentityType,
    secure_auth_level: SecureAuthLevel,
    session_id: uuid::Uuid,
) -> bool {
    let mut identity_valid = true;
    for packet in batch.iter_mut() {
        identity_valid &= packet.set_authenticated_peer_id(probe_peer_id);
        identity_valid &= packet.set_authenticated_peer_identity_type(identity_type);
        identity_valid &= packet.set_authenticated_peer_secure_auth_level(secure_auth_level);
        identity_valid &= packet.set_authenticated_session_id(session_id);
    }
    identity_valid
}

fn packet_batch_is_direct_ping_pong(batch: &PacketBatch) -> bool {
    !batch.is_empty()
        && batch.iter().all(|packet| {
            let packet_type = packet
                .parsed_metadata()
                .map(|metadata| metadata.packet_type)
                .or_else(|| {
                    packet
                        .peer_manager_header()
                        .map(|header| header.packet_type)
                });
            packet_type.is_some_and(batch_packet_type_is_direct_ping_pong)
        })
}

// Liveness probes must not queue behind bulk delivery. When the receive loop is
// parked waiting for the TUN-bound byte budget, ping and pong batches are still
// answered from this helper; everything else keeps its existing order.
async fn respond_to_direct_ping_pong_batch(
    incoming: PacketBatch,
    sink: &DirectTunnelSender,
    ctrl_sender: &broadcast::Sender<ZCPacket>,
    control_metrics: &AggregateTrafficMetrics,
) {
    for mut zc_packet in incoming {
        let buf_len = zc_packet.buf_len() as u64;
        let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
            tracing::error!(
                "unexpected packet: {:?}, cannot decode peer manager hdr",
                zc_packet
            );
            continue;
        };
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
        }
    }
}

fn speed_probe_ack_packet(my_peer_id: PeerId, peer_id: PeerId, ack: ProbeAck) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(&ack.encode());
    packet.fill_peer_manager_hdr(my_peer_id, peer_id, PacketType::SpeedProbeAck as u8);
    packet
}

fn receiver_pressure_packet(
    my_peer_id: PeerId,
    peer_id: PeerId,
    report: ReceiverPressureReport,
) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(&report.encode());
    packet.fill_peer_manager_hdr(my_peer_id, peer_id, PacketType::ReceiverPressure as u8);
    let header = packet
        .mut_peer_manager_header()
        .expect("the receiver-pressure packet owns a peer header");
    header.set_critical_l2_control(true);
    header.set_latency_first(true);
    packet
}

struct ActiveSpeedProbeGuard<'a>(&'a AtomicBool);

impl Drop for ActiveSpeedProbeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct PreparedSessionGuard {
    store: PeerSessionStore,
    key: SessionKey,
    session: Arc<PeerSession>,
    action: PeerSessionAction,
    revision: Option<u64>,
    initial_epoch: u32,
    armed: bool,
}

enum ResponderTransitionPlan {
    Prepared {
        prepared: UpsertResponderSessionReturn,
        recovery_active: bool,
    },
    Reset(InitiatorTransitionIdentity),
}

impl PreparedSessionGuard {
    fn new(
        store: PeerSessionStore,
        key: SessionKey,
        session: Arc<PeerSession>,
        action: PeerSessionAction,
        revision: Option<u64>,
        initial_epoch: u32,
    ) -> Self {
        Self {
            store,
            key,
            session,
            action,
            revision,
            initial_epoch,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedSessionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.store.cancel_prepared_session(
                &self.key,
                &self.session,
                self.action,
                self.revision,
                self.initial_epoch,
            );
        }
    }
}

fn admission_len_u32(value: usize) -> Result<[u8; 4], Error> {
    u32::try_from(value)
        .map(|value| value.to_be_bytes())
        .map_err(|_| Error::WaitRespError("admission field is too large".to_owned()))
}

fn admission_field(hasher: &mut Sha256, tag: u8, value: &[u8]) -> Result<(), Error> {
    hasher.update([tag]);
    hasher.update(admission_len_u32(value.len())?);
    hasher.update(value);
    Ok(())
}

fn admission_u32(hasher: &mut Sha256, tag: u8, value: u32) -> Result<(), Error> {
    admission_field(hasher, tag, &value.to_be_bytes())
}

fn admission_u64(hasher: &mut Sha256, tag: u8, value: u64) -> Result<(), Error> {
    admission_field(hasher, tag, &value.to_be_bytes())
}

fn admission_uuid(hasher: &mut Sha256, tag: u8, value: &uuid::Uuid) -> Result<(), Error> {
    admission_field(hasher, tag, value.as_bytes())
}

fn admission_fixed<const N: usize>(
    hasher: &mut Sha256,
    tag: u8,
    value: &[u8],
) -> Result<(), Error> {
    if value.len() != N {
        return Err(Error::WaitRespError(format!(
            "admission field {tag} must be {N} bytes"
        )));
    }
    admission_field(hasher, tag, value)
}

fn canonical_certificate_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.is_empty() {
        return Ok([0; 32]);
    }
    if bytes.len() > MAX_ADMISSION_CERT_BYTES {
        return Err(Error::WaitRespError(
            "credential certificate is too large".to_owned(),
        ));
    }
    let certificate = CredentialCertificate::decode(bytes)
        .map_err(|_| Error::WaitRespError("invalid credential certificate".to_owned()))?;
    let canonical = certificate.encode_to_vec();
    if canonical != bytes {
        return Err(Error::WaitRespError(
            "credential certificate is not canonical".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(CERTIFICATE_DIGEST_DOMAIN);
    hasher.update(admission_len_u32(canonical.len())?);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

fn canonical_certificate_id(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_ADMISSION_CERT_BYTES {
        return Err(Error::WaitRespError(
            "credential certificate is too large".to_owned(),
        ));
    }
    let certificate = CredentialCertificate::decode(bytes)
        .map_err(|_| Error::WaitRespError("invalid credential certificate".to_owned()))?;
    if certificate.encode_to_vec() != bytes
        || certificate.certificate_id.len() != 16
        || certificate.certificate_id.iter().all(|byte| *byte == 0)
    {
        return Err(Error::WaitRespError(
            "credential certificate has an invalid certificate id".to_owned(),
        ));
    }
    Ok(certificate.certificate_id)
}

fn canonical_status_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.is_empty() {
        return Ok([0; 32]);
    }
    if bytes.len() > MAX_ADMISSION_STATUS_BYTES {
        return Err(Error::WaitRespError(
            "credential status is too large".to_owned(),
        ));
    }
    let status = CredentialCertificateStatus::decode(bytes)
        .map_err(|_| Error::WaitRespError("invalid credential status".to_owned()))?;
    let canonical = status.encode_to_vec();
    if canonical != bytes {
        return Err(Error::WaitRespError(
            "credential status is not canonical".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(STATUS_DIGEST_DOMAIN);
    hasher.update(admission_len_u32(canonical.len())?);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn admission_context_hash(
    network_name: &str,
    initiator_peer_id: PeerId,
    responder_peer_id: PeerId,
    initiator_conn_id: &uuid::Uuid,
    responder_conn_id: &uuid::Uuid,
    initiator_noise_static: &[u8],
    responder_noise_static: &[u8],
    pinned_root_fingerprint: &[u8],
    initiator_certificate_digest: &[u8],
    responder_certificate_digest: &[u8],
    initiator_certificate_id: &[u8],
    responder_certificate_id: &[u8],
    initiator_identity_type: PeerIdentityType,
    responder_identity_type: PeerIdentityType,
    initiator_auth_level: SecureAuthLevel,
    responder_auth_level: SecureAuthLevel,
    initiator_receive_capabilities: u64,
    responder_receive_capabilities: u64,
    initiator_transmit_capabilities: u64,
    responder_transmit_capabilities: u64,
    initiator_status_digest: &[u8],
    responder_status_digest: &[u8],
    initiator_status_sequence: u64,
    responder_status_sequence: u64,
    session_metadata_id: &uuid::Uuid,
    transition_id: &[u8],
    session_action: i32,
    session_generation: u32,
    initial_epoch: u32,
    handshake_hash: &[u8],
    selected_protection: i32,
    transport_binding_kind: u32,
    transport_binding_digest: &[u8],
) -> Result<[u8; 32], Error> {
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_CONTEXT_DOMAIN);
    admission_u32(&mut hasher, 1, VERSION)?;
    admission_field(&mut hasher, 2, network_name.as_bytes())?;
    admission_u32(&mut hasher, 3, initiator_peer_id)?;
    admission_u32(&mut hasher, 4, responder_peer_id)?;
    admission_uuid(&mut hasher, 5, initiator_conn_id)?;
    admission_uuid(&mut hasher, 6, responder_conn_id)?;
    admission_fixed::<32>(&mut hasher, 7, initiator_noise_static)?;
    admission_fixed::<32>(&mut hasher, 8, responder_noise_static)?;
    admission_fixed::<32>(&mut hasher, 9, pinned_root_fingerprint)?;
    admission_fixed::<32>(&mut hasher, 10, initiator_certificate_digest)?;
    admission_fixed::<32>(&mut hasher, 11, responder_certificate_digest)?;
    admission_field(&mut hasher, 12, initiator_certificate_id)?;
    admission_field(&mut hasher, 13, responder_certificate_id)?;
    admission_u32(&mut hasher, 14, initiator_identity_type as u32)?;
    admission_u32(&mut hasher, 15, responder_identity_type as u32)?;
    admission_u32(&mut hasher, 16, initiator_auth_level as u32)?;
    admission_u32(&mut hasher, 17, responder_auth_level as u32)?;
    admission_u64(&mut hasher, 18, initiator_receive_capabilities)?;
    admission_u64(&mut hasher, 19, responder_receive_capabilities)?;
    admission_fixed::<32>(&mut hasher, 20, initiator_status_digest)?;
    admission_fixed::<32>(&mut hasher, 21, responder_status_digest)?;
    admission_u64(&mut hasher, 22, initiator_status_sequence)?;
    admission_u64(&mut hasher, 23, responder_status_sequence)?;
    admission_uuid(&mut hasher, 24, session_metadata_id)?;
    admission_fixed::<16>(&mut hasher, 25, transition_id)?;
    let session_action = u32::try_from(session_action)
        .map_err(|_| Error::WaitRespError("invalid session action".to_owned()))?;
    if session_action > PeerConnSessionActionPb::Create as u32 {
        return Err(Error::WaitRespError("invalid session action".to_owned()));
    }
    admission_u32(&mut hasher, 26, session_action)?;
    admission_u32(&mut hasher, 27, session_generation)?;
    admission_u32(&mut hasher, 28, initial_epoch)?;
    admission_fixed::<32>(&mut hasher, 29, handshake_hash)?;
    let selected_protection = u32::try_from(selected_protection)
        .map_err(|_| Error::WaitRespError("invalid data protection mode".to_owned()))?;
    admission_u32(&mut hasher, 30, selected_protection)?;
    admission_u32(&mut hasher, 31, transport_binding_kind)?;
    admission_fixed::<32>(&mut hasher, 32, transport_binding_digest)?;
    admission_u64(&mut hasher, 33, initiator_transmit_capabilities)?;
    admission_u64(&mut hasher, 34, responder_transmit_capabilities)?;
    Ok(hasher.finalize().into())
}

fn tls_exporter_tunnel(tunnel_type: Option<&str>) -> bool {
    let Some(value) = tunnel_type else {
        return false;
    };
    if value.eq_ignore_ascii_case("quic") || value.eq_ignore_ascii_case("wss") {
        return true;
    }
    if value.eq_ignore_ascii_case("tcp") {
        return true;
    }
    false
}

fn validate_transport_binding(
    tunnel_type: Option<&str>,
    binding: Option<TransportBinding>,
) -> Result<Option<TransportBinding>, Error> {
    match (tls_exporter_tunnel(tunnel_type), binding) {
        (true, None) => Err(Error::WaitRespError(
            "TLS exporter tunnel is missing a transport binding".to_owned(),
        )),
        (false, Some(_)) => Err(Error::WaitRespError(
            "non-exporter tunnel has a transport binding".to_owned(),
        )),
        (_, binding) => Ok(binding),
    }
}

fn transport_binding_context(binding: Option<TransportBinding>) -> (u32, [u8; 32]) {
    match binding {
        Some(TransportBinding {
            kind: TransportBindingKind::QuicTlsExporterV1,
            bytes,
        }) => (1, bytes),
        Some(TransportBinding {
            kind: TransportBindingKind::WssTlsExporterV1,
            bytes,
        }) => (2, bytes),
        Some(TransportBinding {
            kind: TransportBindingKind::Http2TlsExporterV1,
            bytes,
        }) => (3, bytes),
        Some(TransportBinding {
            kind: TransportBindingKind::TlsExporterLanesV1,
            bytes,
        }) => (4, bytes),
        None => (0, [0; 32]),
    }
}

fn noise_prologue_for_binding(
    tunnel_type: Option<&str>,
    binding: Option<TransportBinding>,
) -> Result<Vec<u8>, Error> {
    let binding = validate_transport_binding(tunnel_type, binding)?;
    let (kind, bytes) = transport_binding_context(binding);
    let binding_len = if kind == 0 { 0_u32 } else { 32_u32 };
    let mut hasher = Sha256::new();
    hasher.update(NOISE_PROLOGUE_DOMAIN);
    hasher.update([kind as u8]);
    hasher.update(binding_len.to_be_bytes());
    if kind != 0 {
        hasher.update(bytes);
    }
    Ok(hasher.finalize().to_vec())
}

fn validate_data_protection_mode(
    local: PeerConnDataProtectionPb,
    selected: PeerConnDataProtectionPb,
) -> Result<(), Error> {
    if local == selected {
        return Ok(());
    }
    Err(Error::WaitRespError(
        "peer selected a data protection mode that does not match the tunnel binding".to_owned(),
    ))
}

fn validate_encryption_algorithm(algorithm: &str) -> Result<(), Error> {
    algorithm
        .parse::<EncryptionAlgorithm>()
        .map(|_| ())
        .map_err(|_| {
            Error::WaitRespError(format!(
                "peer selected an unsupported encryption algorithm: {algorithm:?}"
            ))
        })
}

/// The authorization that permits private-network admission.
///
/// A network digest identifies a network. It does not prove secret possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivateAdmission {
    #[default]
    None,
    TranscriptSecretProof,
    TrustedStaticCredential,
    RootSignedCredential,
}

impl PrivateAdmission {
    pub fn is_authorized(self) -> bool {
        !matches!(self, Self::None)
    }
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
    private_admission: PrivateAdmission,
    peer_identity_type: PeerIdentityType,
    remote_network_name: String,

    secret_digest: Vec<u8>,
    // foreign network manager use this to verify peer.
    // the challenge will be sent to authorized peer and compare the proof against it.
}

#[derive(Clone)]
struct PeerSessionTunnelFilter {
    enabled: bool,
    data_protection_mode: Arc<AtomicU8>,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    session: Arc<ArcSwapOption<PeerSession>>,
    #[cfg(test)]
    batch_encrypt_calls: Arc<AtomicU32>,
    #[cfg(test)]
    batch_decrypt_calls: Arc<AtomicU32>,
}

impl PeerSessionTunnelFilter {
    fn new_with_peer(my_peer_id: PeerId, enabled: bool) -> Self {
        Self {
            enabled,
            data_protection_mode: Arc::new(AtomicU8::new(
                PeerConnDataProtectionPb::SessionAead as u8,
            )),
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(ArcSwapOption::empty()),
            #[cfg(test)]
            batch_encrypt_calls: Arc::new(AtomicU32::new(0)),
            #[cfg(test)]
            batch_decrypt_calls: Arc::new(AtomicU32::new(0)),
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

    fn set_data_protection_mode(&self, mode: PeerConnDataProtectionPb) {
        self.data_protection_mode
            .store(mode as u8, Ordering::Release);
    }

    fn uses_quic_exporter(&self) -> bool {
        // QUIC, WSS, and HTTP/2 TCP select QuicExporter after a TLS binding.
        // Direct hops then skip inner session AEAD.
        self.data_protection_mode.load(Ordering::Acquire)
            == PeerConnDataProtectionPb::QuicExporter as u8
    }

    fn is_immediate_direct_packet(
        &self,
        data: &ZCPacket,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
    ) -> bool {
        data.peer_manager_header().is_some_and(|header| {
            header.from_peer_id.get() == from_peer_id
                && header.to_peer_id.get() == to_peer_id
                && header.forward_counter == 1
        })
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
        // A session is installed only after the Noise handshake completes.
        // Encrypt every matching packet after that point.
        if hdr.is_encrypted() {
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
        if !self.enabled {
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
        if self.uses_quic_exporter() && self.is_immediate_direct_packet(data, my_peer_id, peer_id) {
            if data
                .peer_manager_header()
                .is_some_and(|header| header.is_encrypted())
            {
                return Err(anyhow::anyhow!(
                    "QUIC exporter direct packet has unexpected inner encryption"
                ));
            }
            return Ok(());
        }
        self.encrypt_packet_with_session(data, my_peer_id, peer_id, &session)
    }

    fn encrypt_batch_sequential(&self, batch: &mut PacketBatch) -> Result<(), anyhow::Error> {
        let Some((my_peer_id, peer_id, session)) = self.encryption_context() else {
            return Ok(());
        };
        self.encrypt_batch_grouped(batch, my_peer_id, peer_id, session)
    }

    fn encrypt_batch_grouped(
        &self,
        batch: &mut PacketBatch,
        my_peer_id: PeerId,
        peer_id: PeerId,
        session: Arc<PeerSession>,
    ) -> Result<(), anyhow::Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let batch_len = batch.len();
        let mut selected = [false; MAX_PACKET_BATCH_SIZE];
        let mut keep_unselected = [true; MAX_PACKET_BATCH_SIZE];
        let selected = &mut selected[..batch_len];
        let keep_unselected = &mut keep_unselected[..batch_len];
        let mut selected_count = 0;
        for (index, packet) in batch.iter().enumerate() {
            let Some(header) = packet.peer_manager_header() else {
                continue;
            };
            let eligible = !header.is_encrypted()
                && header.from_peer_id.get() == my_peer_id
                && header.to_peer_id.get() == peer_id;
            if self.uses_quic_exporter()
                && self.is_immediate_direct_packet(packet, my_peer_id, peer_id)
            {
                if header.is_encrypted() {
                    keep_unselected[index] = false;
                }
                continue;
            }
            selected[index] = eligible;
            selected_count += usize::from(eligible);
        }
        if selected_count == 0 {
            if keep_unselected.iter().any(|keep| !keep) {
                batch.retain_flags(&keep_unselected);
            }
            return Ok(());
        }
        if selected_count == batch.len() {
            #[cfg(test)]
            self.batch_encrypt_calls.fetch_add(1, Ordering::Relaxed);
            return session.encrypt_payload_batch(my_peer_id, peer_id, batch);
        }

        batch.process_selected_with_keep_flags(&selected, &keep_unselected, |packets| {
            #[cfg(test)]
            self.batch_encrypt_calls.fetch_add(1, Ordering::Relaxed);
            session
                .encrypt_payload_batch(my_peer_id, peer_id, packets)
                .map(|()| SmallVec::from_elem(true, packets.len()))
        })
    }

    fn decrypt_direct_batch(&self, mut batch: PacketBatch) -> BatchStreamItem {
        let peer_id = self.peer_id.load().expect("batch decrypt has a peer id");
        let session_guard = self.session.load();
        let session = session_guard
            .as_deref()
            .expect("batch decrypt has an active session");
        let my_peer_id = self.my_peer_id.load();

        #[cfg(test)]
        self.batch_decrypt_calls.fetch_add(1, Ordering::Relaxed);
        let outcomes = session.decrypt_payload_batch(peer_id, my_peer_id, &mut batch);
        let keep = outcomes
            .into_iter()
            .map(|outcome| outcome.is_ok())
            .collect::<SmallVec<[bool; MAX_PACKET_BATCH_SIZE]>>();
        if !session.is_valid() {
            tracing::error!("session invalidated, closing connection");
            return Err(TunnelError::InternalError(
                "session invalidated due to consecutive decrypt failures".to_string(),
            ));
        }
        batch.retain_flags(&keep);
        Ok(batch)
    }

    fn decrypt_mixed_batch(&self, mut batch: PacketBatch) -> BatchStreamItem {
        let Some(peer_id) = self.peer_id.load() else {
            return Ok(batch);
        };
        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Ok(batch);
        };
        let my_peer_id = self.my_peer_id.load();
        let batch_len = batch.len();
        let mut selected = [false; MAX_PACKET_BATCH_SIZE];
        let mut keep_unselected = [true; MAX_PACKET_BATCH_SIZE];
        let selected = &mut selected[..batch_len];
        let keep_unselected = &mut keep_unselected[..batch_len];
        let mut selected_count = 0;
        for (index, packet) in batch.iter().enumerate() {
            let Some(header) = packet.peer_manager_header() else {
                continue;
            };
            if header.from_peer_id.get() != peer_id || header.to_peer_id.get() != my_peer_id {
                continue;
            }
            if header.is_encrypted() {
                selected[index] = true;
                selected_count += 1;
            } else {
                // Raw protected streams have no plaintext exception.
                keep_unselected[index] = false;
            }
        }
        if selected_count == 0 {
            batch.retain_flags(&keep_unselected);
            return Ok(batch);
        }

        let result =
            batch.process_selected_with_keep_flags(&selected, &keep_unselected, |packets| {
                #[cfg(test)]
                self.batch_decrypt_calls.fetch_add(1, Ordering::Relaxed);
                let outcomes = session.decrypt_payload_batch(peer_id, my_peer_id, packets);
                Ok::<SmallVec<[bool; MAX_PACKET_BATCH_SIZE]>, anyhow::Error>(
                    outcomes
                        .into_iter()
                        .map(|outcome| outcome.is_ok())
                        .collect(),
                )
            });
        if result.is_err() || !session.is_valid() {
            tracing::error!("session invalidated, closing connection");
            return Err(TunnelError::InternalError(
                "session invalidated due to consecutive decrypt failures".to_string(),
            ));
        }
        Ok(batch)
    }

    fn decrypt_quic_exporter_batch(&self, mut batch: PacketBatch) -> BatchStreamItem {
        let Some(peer_id) = self.peer_id.load() else {
            return Ok(batch);
        };
        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Ok(batch);
        };
        let my_peer_id = self.my_peer_id.load();
        let batch_len = batch.len();
        let mut selected = [false; MAX_PACKET_BATCH_SIZE];
        let mut keep = [true; MAX_PACKET_BATCH_SIZE];
        let selected = &mut selected[..batch_len];
        let keep = &mut keep[..batch_len];
        let mut selected_count = 0;
        for (index, packet) in batch.iter().enumerate() {
            let Some(header) = packet.peer_manager_header() else {
                continue;
            };
            if header.from_peer_id.get() != peer_id || header.to_peer_id.get() != my_peer_id {
                continue;
            }
            if header.forward_counter == 1 {
                if header.is_encrypted() {
                    keep[index] = false;
                }
                continue;
            }
            if header.is_encrypted() {
                selected[index] = true;
                selected_count += 1;
            } else {
                // A forwarded packet must retain the per-hop session AEAD.
                keep[index] = false;
            }
        }
        if selected_count == 0 {
            batch.retain_flags(&keep);
            return Ok(batch);
        }

        let result = batch.process_selected_with_keep_flags(&selected, &keep, |packets| {
            #[cfg(test)]
            self.batch_decrypt_calls.fetch_add(1, Ordering::Relaxed);
            let outcomes = session.decrypt_payload_batch(peer_id, my_peer_id, packets);
            Ok::<SmallVec<[bool; MAX_PACKET_BATCH_SIZE]>, anyhow::Error>(
                outcomes
                    .into_iter()
                    .map(|outcome| outcome.is_ok())
                    .collect(),
            )
        });
        if result.is_err() || !session.is_valid() {
            tracing::error!("session invalidated, closing connection");
            return Err(TunnelError::InternalError(
                "session invalidated due to consecutive decrypt failures".to_string(),
            ));
        }
        Ok(batch)
    }
}

impl TunnelFilter for PeerSessionTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        // Authentication metadata belongs to the receiving connection, including on ring transports.
        data.clear_authenticated_peer_id();
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
        if self.uses_quic_exporter() && self.is_immediate_direct_packet(&data, peer_id, my_peer_id)
        {
            if hdr.is_encrypted() {
                tracing::debug!(
                    from_peer_id = peer_id,
                    to_peer_id = my_peer_id,
                    "dropping inner-encrypted direct packet on QUIC exporter stream"
                );
                return None;
            }
            return Some(Ok(data));
        }
        // Established raw streams require session authentication before packet classification.
        if !hdr.is_encrypted() {
            tracing::debug!(
                from_peer_id,
                to_peer_id = my_peer_id,
                packet_type = hdr.packet_type,
                "dropping plaintext packet on protected raw peer stream"
            );
            return None;
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

    fn before_send_batch(&self, mut data: PacketBatch) -> Option<PacketBatch> {
        for packet in data.iter_mut() {
            packet.clear_authenticated_peer_id();
        }
        if !self.enabled {
            return Some(data);
        }
        let result = self.encrypt_batch_sequential(&mut data);
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
        if self.uses_quic_exporter() {
            if data.is_err() {
                return scalar_after_received_batch(self, data);
            }
            let batch = match data {
                Ok(batch) => batch,
                Err(_) => unreachable!("error batch was handled above"),
            };
            return Some(self.decrypt_quic_exporter_batch(batch));
        }
        let can_batch_decrypt = data.as_ref().is_ok_and(|batch| {
            let Some(peer_id) = self.peer_id.load() else {
                return false;
            };
            if self.session.load().is_none() {
                return false;
            }
            let my_peer_id = self.my_peer_id.load();
            batch.iter().all(|packet| {
                packet.peer_manager_header().is_some_and(|header| {
                    header.is_encrypted()
                        && header.from_peer_id.get() == peer_id
                        && header.to_peer_id.get() == my_peer_id
                })
            })
        });
        if can_batch_decrypt {
            let batch = match data {
                Ok(batch) => batch,
                Err(_) => unreachable!("batch decrypt check accepted an error item"),
            };
            return Some(self.decrypt_direct_batch(batch));
        }
        if data.is_ok() {
            let batch = match data {
                Ok(batch) => batch,
                Err(_) => unreachable!("mixed batch decrypt check accepted an error item"),
            };
            return Some(self.decrypt_mixed_batch(batch));
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

#[derive(Default)]
pub(crate) struct DiscoveryPeerHint {
    identity: AtomicCell<Option<(PeerId, std::time::Instant)>>,
}

impl DiscoveryPeerHint {
    pub(crate) fn observe(&self, peer: PeerId) {
        self.identity.store(Some((peer, std::time::Instant::now())));
    }

    pub(crate) fn peer_id(&self) -> Option<PeerId> {
        self.identity.load().map(|(peer, _)| peer)
    }

    pub(crate) fn recent_peer_id(&self, age: Duration) -> Option<PeerId> {
        self.identity
            .load()
            .filter(|(_, seen)| seen.elapsed() < age)
            .map(|(peer, _)| peer)
    }
}

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    peer_id_hint: Option<PeerId>,
    discovery_peer_hint: Option<Arc<DiscoveryPeerHint>>,
    global_ctx: ArcGlobalCtx,
    transit_network: std::sync::OnceLock<Arc<str>>,

    my_encrypt_algo: String,
    secure_mode_cfg: SecureModeConfig,
    session_filter: PeerSessionTunnelFilter,
    noise_handshake_result: Option<NoiseHandshakeResult>,
    private_admission: PrivateAdmission,
    connection_permit: Option<super::peer_map::PeerConnectionPermit>,

    _tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: DirectTunnelSender,
    recv: Mutex<Option<Pin<Box<dyn PacketBatchStream>>>>,
    pending_recv: parking_lot::Mutex<VecDeque<ZCPacket>>,
    tunnel_info: Option<TunnelInfo>,
    tunnel_path_state: Option<Arc<crate::tunnel::TunnelPathState>>,
    transport_binding: Option<TransportBinding>,
    receive_backpressure: Option<crate::tunnel::ReceiveBackpressure>,

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
    speed_sample: Arc<parking_lot::RwLock<Option<SpeedSample>>>,
    speed_probe_receiver: Arc<parking_lot::Mutex<ProbeReceiver>>,
    speed_ack_sender: broadcast::Sender<ProbeAck>,
    speed_probe_active: AtomicBool,
    receiver_pacer: Option<Arc<ReceiverPacer>>,

    peer_session_store: Arc<PeerSessionStore>,
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
    const HANDSHAKE_METRIC_NETWORK: &'static str = "__handshake__";

    pub fn secure_auth_level(&self) -> Option<SecureAuthLevel> {
        self.noise_handshake_result
            .as_ref()
            .map(|result| result.secure_auth_level)
    }

    pub(crate) fn private_admission(&self) -> PrivateAdmission {
        self.private_admission
    }

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
        let tunnel_info = tunnel.info();
        let tunnel_path_state = tunnel.path_state();
        let transport_binding = tunnel.transport_binding();
        let receive_backpressure = tunnel.receive_backpressure();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);
        let (speed_ack_sender, _speed_ack_receiver) = broadcast::channel(8);

        let secure_mode_cfg = global_ctx
            .config
            .get_secure_mode()
            .filter(|config| config.enabled)
            .expect("the current protocol requires automatic secure mode");
        let session_filter = PeerSessionTunnelFilter::new_with_peer(my_peer_id, true);

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let filter_chain = TunnelFilterChain::new(session_filter.clone(), peer_conn_tunnel_filter);
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
        let mut direct_tunnel = DirectTunnel::new_with_process_memory(
            peer_conn_tunnel,
            Some(Duration::from_secs(30)),
            Some(global_ctx.process_memory_governor()),
        );

        let (recv, sink) = (direct_tunnel.get_stream(), direct_tunnel.get_sink());
        sink.set_transit_context(&global_ctx);

        let conn_id = PeerConnId::new_v4();
        let my_encrypt_algo = flags.encryption_algorithm;

        PeerConn {
            conn_id,

            my_peer_id,
            peer_id_hint,
            discovery_peer_hint: None,
            global_ctx,
            transit_network: std::sync::OnceLock::new(),

            secure_mode_cfg,
            session_filter,
            noise_handshake_result: None,
            private_admission: PrivateAdmission::None,
            connection_permit: None,

            _tunnel: Arc::new(Mutex::new(
                Box::new(direct_tunnel) as Box<dyn Any + Send + 'static>
            )),
            sink,
            recv: Mutex::new(Some(recv)),
            pending_recv: parking_lot::Mutex::new(VecDeque::new()),
            tunnel_info,
            tunnel_path_state,
            transport_binding,
            receive_backpressure,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            is_hole_punched: true,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id)),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
            speed_sample: Arc::new(parking_lot::RwLock::new(None)),
            speed_probe_receiver: Arc::new(parking_lot::Mutex::new(ProbeReceiver::default())),
            speed_ack_sender,
            speed_probe_active: AtomicBool::new(false),
            receiver_pacer: None,

            peer_session_store,
            my_encrypt_algo,
        }
    }

    fn get_peer_session_store(&self) -> &Arc<PeerSessionStore> {
        &self.peer_session_store
    }

    pub(crate) fn attach_connection_permit(
        &mut self,
        permit: super::peer_map::PeerConnectionPermit,
    ) {
        self.connection_permit = Some(permit);
    }

    // pri, pub
    fn get_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Ok((
            self.secure_mode_cfg.private_key()?.as_bytes().to_vec(),
            self.secure_mode_cfg.public_key()?.as_bytes().to_vec(),
        ))
    }

    fn local_root_fingerprint(&self) -> [u8; 32] {
        let manager = self.global_ctx.get_credential_manager();
        *manager.root_fingerprint()
    }

    fn tunnel_transport_binding(&self) -> Result<Option<TransportBinding>, Error> {
        validate_transport_binding(
            self.tunnel_info
                .as_ref()
                .map(|info| info.tunnel_type.as_str()),
            self.transport_binding,
        )
    }

    fn noise_prologue(&self) -> Result<Vec<u8>, Error> {
        noise_prologue_for_binding(
            self.tunnel_info
                .as_ref()
                .map(|info| info.tunnel_type.as_str()),
            self.transport_binding,
        )
    }

    fn local_data_protection(&self) -> Result<PeerConnDataProtectionPb, Error> {
        if self.tunnel_transport_binding()?.is_some() {
            Ok(PeerConnDataProtectionPb::QuicExporter)
        } else {
            Ok(PeerConnDataProtectionPb::SessionAead)
        }
    }

    fn local_transport_binding_context(&self) -> Result<(u32, [u8; 32]), Error> {
        Ok(transport_binding_context(self.tunnel_transport_binding()?))
    }

    fn admission_root_fingerprint(&self) -> [u8; 32] {
        self.local_credential_root_fingerprint()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or_else(|| self.local_root_fingerprint())
    }

    fn locally_pinned_root_fingerprint(&self, network_name: &str) -> Option<[u8; 32]> {
        if network_name != self.global_ctx.get_network_name() {
            return None;
        }
        if let Some(root) = self
            .local_credential_root_fingerprint()
            .and_then(|bytes| bytes.try_into().ok())
        {
            return Some(root);
        }
        if let Some(root) = self
            .global_ctx
            .get_network_identity()
            .credential_root_fingerprint()
        {
            return Some(*root);
        }
        self.global_ctx
            .get_network_identity()
            .network_secret
            .is_some()
            .then(|| self.local_root_fingerprint())
    }

    fn local_credential_certificate(&self) -> Option<Vec<u8>> {
        (!self.secure_mode_cfg.credential_certificate.is_empty())
            .then(|| self.secure_mode_cfg.credential_certificate.clone())
    }

    fn local_credential_root_fingerprint(&self) -> Option<Vec<u8>> {
        (!self.secure_mode_cfg.credential_root_fingerprint.is_empty())
            .then(|| self.secure_mode_cfg.credential_root_fingerprint.clone())
    }

    fn build_local_admin_credentials(
        &self,
        static_pubkey: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, [u8; 32]), Error> {
        let static_pubkey: [u8; 32] = static_pubkey.try_into().map_err(|_| {
            Error::WaitRespError("local Noise static key must be 32 bytes".to_owned())
        })?;
        let manager = self.global_ctx.get_credential_manager();
        let certificate = manager
            .new_admin_certificate(&static_pubkey, Duration::from_secs(60))
            .map_err(|error| {
                Error::WaitRespError(format!("create Admin certificate failed: {error}"))
            })?;
        let certificate_bytes = certificate.encode_to_vec();
        if certificate_bytes.len() > MAX_ADMISSION_CERT_BYTES {
            return Err(Error::WaitRespError(
                "Admin certificate is too large".to_owned(),
            ));
        }
        // The certificate is short-lived. An empty status means no negative
        // revocation assertion. The local administrator checks its own set.
        Ok((certificate_bytes, Vec::new(), *manager.root_fingerprint()))
    }

    fn verify_remote_certificate(
        &self,
        certificate_bytes: &[u8],
        network_name: &str,
        root_fingerprint: &[u8],
        remote_static: &[u8],
        expected_role: &str,
    ) -> Result<CredentialCertificate, Error> {
        if certificate_bytes.len() > MAX_ADMISSION_CERT_BYTES {
            return Err(Error::WaitRespError(
                "credential certificate is too large".to_owned(),
            ));
        }
        CredentialManager::verify_certificate_bytes(
            certificate_bytes,
            network_name,
            root_fingerprint,
            remote_static,
            expected_role,
            crate::peers::credential_manager::current_unix_timestamp(),
        )
        .map_err(|error| {
            Error::WaitRespError(format!("invalid {expected_role} certificate: {error}"))
        })
    }

    fn verify_remote_status(
        &self,
        status_bytes: &[u8],
        network_name: &str,
        root_fingerprint: &[u8],
        certificate_id: &[u8],
    ) -> Result<CredentialCertificateStatus, Error> {
        if status_bytes.len() > MAX_ADMISSION_STATUS_BYTES {
            return Err(Error::WaitRespError(
                "credential status is too large".to_owned(),
            ));
        }
        CredentialManager::verify_status_evidence_bytes(
            status_bytes,
            network_name,
            root_fingerprint,
            certificate_id,
            crate::peers::credential_manager::current_unix_timestamp(),
            Duration::from_secs(60),
            0,
        )
        .map_err(|error| Error::WaitRespError(format!("invalid credential status: {error}")))
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub(crate) fn set_discovery_peer_hint(&mut self, hint: Arc<DiscoveryPeerHint>) {
        self.discovery_peer_hint = Some(hint);
    }

    pub(crate) fn discovery_order(&self) -> Option<(bool, [u8; 32])> {
        // The Noise transcript gives both endpoints the same order for simultaneous flows.
        let hash = self
            .noise_handshake_result
            .as_ref()?
            .handshake_hash
            .as_slice()
            .try_into()
            .ok()?;
        Some((
            self.is_client? == (self.my_peer_id < self.get_peer_id()),
            hash,
        ))
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

    fn keep_packet_during_handshake(packet_type: u8) -> bool {
        is_noise_handshake_packet_type(packet_type)
            || packet_type == PacketType::Ping as u8
            || packet_type == PacketType::Pong as u8
    }

    fn take_pending_handshake_packet(
        pending: &mut VecDeque<ZCPacket>,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<Option<ZCPacket>, Error> {
        let Some(expected_pkt_type) = expected_pkt_type else {
            return Ok(pending.pop_front());
        };
        let expected = expected_pkt_type as u8;
        let mut found = None;
        let mut keep = VecDeque::with_capacity(pending.len());
        for packet in pending.drain(..) {
            let packet_type = packet
                .peer_manager_header()
                .map(|header| header.packet_type);
            if packet_type == Some(expected) && found.is_none() {
                found = Some(packet);
                continue;
            }
            if packet_type.is_some_and(Self::keep_packet_during_handshake) {
                keep.push_back(packet);
            }
        }
        *pending = keep;
        Ok(found)
    }

    fn append_pending_handshake_batch(
        pending: &mut VecDeque<ZCPacket>,
        batch: PacketBatch,
    ) -> Result<(), Error> {
        for packet in batch {
            let keep = packet
                .peer_manager_header()
                .is_some_and(|header| Self::keep_packet_during_handshake(header.packet_type));
            if !keep {
                continue;
            }
            let packet_count = pending.len().saturating_add(1);
            let byte_count = pending
                .iter()
                .map(ZCPacket::buf_len)
                .sum::<usize>()
                .saturating_add(packet.buf_len());
            if packet_count > MAX_PENDING_HANDSHAKE_PACKETS
                || byte_count > MAX_PENDING_HANDSHAKE_BYTES
            {
                return Err(Error::WaitRespError(
                    "pending handshake packet limit exceeded".to_owned(),
                ));
            }
            pending.push_back(packet);
        }
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
        let payload = pb.encode_to_vec();
        tracing::info!(
            ?packet_type,
            from_peer_id = self.my_peer_id,
            to_peer_id = remote_peer_id,
            payload_len = payload.len(),
            "send Noise handshake message"
        );
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

    fn build_noise_transport_msg<Msg: prost::Message + Debug>(
        &self,
        pb: Msg,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        transport: &mut TransportState,
    ) -> Result<ZCPacket, Error> {
        let payload = pb.encode_to_vec();
        tracing::info!(
            ?packet_type,
            from_peer_id = self.my_peer_id,
            to_peer_id = remote_peer_id,
            payload_len = payload.len(),
            "send Noise transport message"
        );
        let mut msg = vec![0u8; 4096];
        let msg_len = transport
            .write_message(&payload, &mut msg)
            .map_err(|e| Error::WaitRespError(format!("noise transport write failed: {e:?}")))?;
        let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
        pkt.fill_peer_manager_hdr(self.my_peer_id, remote_peer_id, packet_type as u8);
        Ok(pkt)
    }

    async fn send_noise_transport_msg<Msg: prost::Message + Debug>(
        &self,
        pb: Msg,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        metric_network_name: &str,
        transport: &mut TransportState,
    ) -> Result<(), Error> {
        let pkt = self.build_noise_transport_msg(pb, packet_type, remote_peer_id, transport)?;
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
    /// | Credential | Admin | valid root-signed certificate | PeerVerified | PeerVerified | Admin | Credential |
    /// | Credential | Admin | certificate missing or invalid | handshake reject | handshake reject | unknown | unknown |
    /// | Admin | SharedNode | pinned key match | PeerVerified | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Admin | SharedNode | local has no pinned key requirement | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Credential | SharedNode | no pin and not trusted | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Credential |
    /// | Credential | Credential | matching root-signed certificates | PeerVerified | PeerVerified | Credential | Credential |
    ///
    /// Logic uses transcript proof first, then an explicit local peer pin.
    /// Certificate authority admission is checked in the signed certificate flow.
    fn verify_secret_proof(&self, proof: Option<&[u8]>, handshake_hash: &[u8]) -> bool {
        proof.is_some_and(|proof| {
            self.global_ctx
                .get_secret_proof(handshake_hash)
                .is_some_and(|mac| mac.verify_slice(proof).is_ok())
        })
    }

    fn classify_private_admission(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_static: &[u8],
        _remote_network_name: &str,
        pinned_pubkey: Option<&[u8]>,
    ) -> PrivateAdmission {
        if self.verify_secret_proof(proof, handshake_hash) {
            return PrivateAdmission::TranscriptSecretProof;
        }
        if remote_static.len() == 32 && pinned_pubkey == Some(remote_static) {
            return PrivateAdmission::TrustedStaticCredential;
        }
        PrivateAdmission::None
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_remote_auth(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_pubkey: &[u8],
        pinned_pubkey: Option<&[u8]>,
        has_network_secret: bool,
        is_initiator: bool,
        _remote_network_name: &str,
    ) -> Result<SecureAuthLevel, Error> {
        // 1. Verify proof
        if self.verify_secret_proof(proof, handshake_hash) {
            return Ok(SecureAuthLevel::NetworkSecretConfirmed);
        }

        // 2. Check pinned pubkey
        if let Some(pinned) = pinned_pubkey {
            if pinned != remote_pubkey {
                return Err(Error::WaitRespError(
                    "pinned remote static pubkey mismatch".to_owned(),
                ));
            }
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // An initiator without a shared secret remains encrypted but unauthenticated.
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
        _remote_sent_secret_proof: bool,
        _is_client: bool,
    ) -> PeerIdentityType {
        if matches!(secure_auth_level, SecureAuthLevel::EncryptedUnauthenticated) {
            return PeerIdentityType::SharedNode;
        }
        if !remote_role_hint_is_same_network
            || remote_network_name != self.global_ctx.get_network_name()
        {
            // A foreign or role-mismatched peer cannot assert local authority.
            return PeerIdentityType::SharedNode;
        }

        if matches!(secure_auth_level, SecureAuthLevel::NetworkSecretConfirmed) {
            PeerIdentityType::Admin
        } else {
            PeerIdentityType::Credential
        }
    }

    async fn do_noise_handshake_as_client(&self) -> Result<NoiseHandshakeResult, Error> {
        let prologue = self.noise_prologue()?;

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
        let recovery_key = self
            .peer_id_hint
            .map(|peer_id| SessionKey::new(network.network_name.clone(), peer_id));
        let recovery_identity = recovery_key
            .as_ref()
            .and_then(|key| self.get_peer_session_store().in_doubt_identity(key));
        // Capture the exact prior receipt before Msg1 is sent. The receipt
        // remains retained until the next authenticated Commit succeeds.
        let prior_receipt_identity = recovery_key.as_ref().and_then(|key| {
            self.get_peer_session_store()
                .initiator_receipt_identity(key)
        });
        let acknowledged_transition_id = if recovery_identity.is_none() {
            prior_receipt_identity
                .as_ref()
                .map(|identity| identity.transition_id)
        } else {
            None
        };
        let a_session_generation = self
            .peer_id_hint
            .and_then(|peer_id| {
                self.get_peer_session_store()
                    .get(&SessionKey::new(network.network_name.clone(), peer_id))
            })
            .map(|s| s.session_generation());

        let a_conn_id = uuid::Uuid::new_v4();
        let mut local_certificate = self.local_credential_certificate().unwrap_or_default();
        if local_certificate.is_empty() && network.network_secret.is_some() {
            local_certificate = self.build_local_admin_credentials(&local_static_pubkey)?.0;
        }
        let local_certificate_digest = canonical_certificate_digest(&local_certificate)?;
        let local_certificate_id = canonical_certificate_id(&local_certificate)?;
        let local_certificate_identity_type = if local_certificate.is_empty() {
            PeerIdentityType::SharedNode
        } else {
            let certificate =
                CredentialCertificate::decode(local_certificate.as_slice()).map_err(|_| {
                    Error::WaitRespError("invalid local credential certificate".to_owned())
                })?;
            match certificate.role.as_str() {
                "Admin" => PeerIdentityType::Admin,
                "Credential" => PeerIdentityType::Credential,
                _ => {
                    return Err(Error::WaitRespError(
                        "unsupported local credential certificate role".to_owned(),
                    ));
                }
            }
        };
        let local_root_fingerprint = self.admission_root_fingerprint();
        let msg1_pb = PeerConnNoiseMsg1Pb {
            version: VERSION,
            a_network_name: network.network_name.clone(),
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.my_encrypt_algo.clone(),
            recovery: recovery_identity.as_ref().map(recovery_pb_from_identity),
            acknowledged_transition_id: acknowledged_transition_id
                .map(|id| id.to_vec())
                .unwrap_or_default(),
            receive_capabilities: 0,
            transmit_capabilities: 0,
            credential_root_fingerprint: local_root_fingerprint.to_vec(),
            initiator_certificate_digest: local_certificate_digest.to_vec(),
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
        // The direct connector performs the authoritative destination check.
        // A mapped listener can intentionally resolve to a different peer.
        let msg2_pb = Self::decode_handshake_message::<PeerConnNoiseMsg2Pb>(
            PacketType::NoiseHandshakeMsg2,
            Some(&mut hs),
            msg2,
        )?;
        validate_protocol_version(msg2_pb.version)?;
        validate_encryption_algorithm(&msg2_pb.server_encryption_algorithm)?;
        let local_data_protection = self.local_data_protection()?;
        let selected_protection = PeerConnDataProtectionPb::try_from(msg2_pb.data_protection)
            .map_err(|_| Error::WaitRespError("invalid data protection mode".to_owned()))?;
        validate_data_protection_mode(local_data_protection, selected_protection)?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg2 conn_id_echo mismatch".to_owned(),
            ));
        }
        if msg2_pb.b_conn_id.is_none()
            || msg2_pb.session_metadata_id.is_none()
            || msg2_pb.transition_id.len() != 16
        {
            return Err(Error::WaitRespError(
                "noise msg2 has incomplete session transition".to_owned(),
            ));
        }
        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::WaitRespError("invalid session action".to_owned()))?;
        let remote_network_name = msg2_pb.b_network_name.clone();
        let remote_static_after_msg2 = hs
            .get_remote_static()
            .map(|static_key: &[u8]| static_key.to_vec())
            .unwrap_or_default();
        let local_root_fingerprint = self.admission_root_fingerprint();
        let locally_pinned_remote_root = self.locally_pinned_root_fingerprint(&remote_network_name);
        let same_network_credential_server =
            remote_network_name == network.network_name && network.network_secret.is_none();
        let responder_certificate_digest =
            canonical_certificate_digest(&msg2_pb.responder_certificate)?;
        let responder_certificate_id = canonical_certificate_id(&msg2_pb.responder_certificate)?;
        let mut responder_certificate_identity_type = None;
        let mut responder_status_digest = [0_u8; 32];
        let mut responder_status_sequence = 0_u64;
        let mut responder_certificate_trusted = false;
        if same_network_credential_server {
            let Some(trusted_root) = locally_pinned_remote_root else {
                return Err(Error::WaitRespError(
                    "credential client has no pinned root for the network".to_owned(),
                ));
            };
            if verify_slices_are_equal(&trusted_root, &msg2_pb.credential_root_fingerprint).is_err()
            {
                return Err(Error::WaitRespError(
                    "server credential root fingerprint mismatch".to_owned(),
                ));
            }
            if msg2_pb.responder_certificate.is_empty() {
                return Err(Error::WaitRespError(
                    "credential client requires an Admin certificate".to_owned(),
                ));
            }
            let certificate = CredentialCertificate::decode(
                msg2_pb.responder_certificate.as_slice(),
            )
            .map_err(|_| Error::WaitRespError("invalid responder certificate".to_owned()))?;
            let expected_role = match certificate.role.as_str() {
                "Admin" => {
                    responder_certificate_identity_type = Some(PeerIdentityType::Admin);
                    "Admin"
                }
                "Credential" => {
                    responder_certificate_identity_type = Some(PeerIdentityType::Credential);
                    "Credential"
                }
                _ => {
                    return Err(Error::WaitRespError(
                        "unsupported responder certificate role".to_owned(),
                    ));
                }
            };
            let certificate = self.verify_remote_certificate(
                &msg2_pb.responder_certificate,
                &remote_network_name,
                &trusted_root,
                &remote_static_after_msg2,
                expected_role,
            )?;
            if certificate.certificate_id != responder_certificate_id {
                return Err(Error::WaitRespError(
                    "Admin certificate id changed during verification".to_owned(),
                ));
            }
            if self
                .global_ctx
                .get_credential_manager()
                .is_certificate_id_revoked(&responder_certificate_id)
            {
                return Err(Error::WaitRespError(
                    "responder credential certificate is revoked".to_owned(),
                ));
            }
            responder_certificate_trusted = true;
            if !msg2_pb.responder_certificate_status.is_empty() {
                let status = self.verify_remote_status(
                    &msg2_pb.responder_certificate_status,
                    &remote_network_name,
                    &trusted_root,
                    &responder_certificate_id,
                )?;
                responder_status_digest =
                    canonical_status_digest(&msg2_pb.responder_certificate_status)?;
                responder_status_sequence = status.sequence;
            }
        } else if remote_network_name == network.network_name
            && !msg2_pb.responder_certificate.is_empty()
            && let Some(trusted_root) = locally_pinned_remote_root
        {
            if verify_slices_are_equal(&trusted_root, &msg2_pb.credential_root_fingerprint).is_err()
            {
                return Err(Error::WaitRespError(
                    "server credential root fingerprint mismatch".to_owned(),
                ));
            }
            let certificate = CredentialCertificate::decode(
                msg2_pb.responder_certificate.as_slice(),
            )
            .map_err(|_| Error::WaitRespError("invalid responder certificate".to_owned()))?;
            let expected_role = match certificate.role.as_str() {
                "Admin" => {
                    responder_certificate_identity_type = Some(PeerIdentityType::Admin);
                    "Admin"
                }
                "Credential" => {
                    responder_certificate_identity_type = Some(PeerIdentityType::Credential);
                    "Credential"
                }
                _ => {
                    return Err(Error::WaitRespError(
                        "unsupported responder certificate role".to_owned(),
                    ));
                }
            };
            let certificate = self.verify_remote_certificate(
                &msg2_pb.responder_certificate,
                &remote_network_name,
                &trusted_root,
                &remote_static_after_msg2,
                expected_role,
            )?;
            if certificate.certificate_id != responder_certificate_id {
                return Err(Error::WaitRespError(
                    "Admin certificate id changed during verification".to_owned(),
                ));
            }
            if self
                .global_ctx
                .get_credential_manager()
                .is_certificate_id_revoked(&responder_certificate_id)
            {
                return Err(Error::WaitRespError(
                    "responder credential certificate is revoked".to_owned(),
                ));
            }
            responder_certificate_trusted = true;
        }
        let remote_sent_secret_proof = msg2_pb.secret_proof_32.is_some();
        let session_key = SessionKey::new(network.network_name.clone(), remote_peer_id);
        let server_recovery_identity = msg2_pb
            .recovery
            .clone()
            .map(|recovery| recovery_identity_from_pb(recovery, session_key.clone()))
            .transpose()?;
        let recovery_reset = recovery_identity.is_some() && server_recovery_identity.is_none();
        let recovering = recovery_identity.is_some() && !recovery_reset;

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

        let initiator_proof_valid = secret_proof_32
            .as_deref()
            .is_some_and(|proof| self.verify_secret_proof(Some(proof), &handshake_hash_for_proof));
        let responder_proof_valid =
            self.verify_secret_proof(msg2_pb.secret_proof_32.as_deref(), &server_handshake_hash);
        let responder_auth_level_for_msg3 = if responder_proof_valid {
            SecureAuthLevel::NetworkSecretConfirmed
        } else if responder_certificate_trusted {
            SecureAuthLevel::PeerVerified
        } else if pinned_remote_pubkey
            .as_deref()
            .is_some_and(|pinned| pinned == remote_static_after_msg2.as_slice())
        {
            SecureAuthLevel::PeerVerified
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        let responder_identity_type_for_msg3 = if responder_certificate_trusted {
            responder_certificate_identity_type.unwrap_or(PeerIdentityType::SharedNode)
        } else {
            self.classify_remote_identity(
                &remote_network_name,
                responder_auth_level_for_msg3,
                msg2_pb.role_hint == 1,
                msg2_pb.secret_proof_32.is_some(),
                true,
            )
        };
        if remote_network_name == network.network_name
            && matches!(
                responder_auth_level_for_msg3,
                SecureAuthLevel::NetworkSecretConfirmed | SecureAuthLevel::PeerVerified
            )
            && let Some(hint) = &self.discovery_peer_hint
        {
            // Persist identity before session commit. Cancellation can retain a receipt that needs this identity on retry.
            hint.observe(remote_peer_id);
        }
        if !recovery_reset
            && !recovery_identity_matches_wire(
                recovery_identity.as_ref(),
                server_recovery_identity.as_ref(),
            )
        {
            return Err(Error::WaitRespError(
                "noise recovery identity mismatch".to_owned(),
            ));
        }
        let b_conn_id = msg2_pb.b_conn_id.clone();
        let msg3_pb = PeerConnNoiseMsg3Pb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: b_conn_id.clone(),
            secret_proof_32,
            secret_digest: secret_digest.clone(),
            initiator_certificate: local_certificate.clone(),
            initiator_certificate_digest: local_certificate_digest.to_vec(),
            responder_identity_type: responder_identity_type_for_msg3 as i32,
            responder_auth_level: responder_auth_level_for_msg3 as i32,
            data_protection: selected_protection as i32,
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
        let mut secure_auth_level = if msg2_pb.role_hint != 1 && pinned_remote_pubkey.is_none() {
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
        if responder_certificate_trusted
            && secure_auth_level == SecureAuthLevel::EncryptedUnauthenticated
        {
            secure_auth_level = SecureAuthLevel::PeerVerified;
        }
        let private_admission = if self
            .verify_secret_proof(msg2_pb.secret_proof_32.as_deref(), &server_handshake_hash)
        {
            PrivateAdmission::TranscriptSecretProof
        } else if responder_certificate_trusted {
            PrivateAdmission::RootSignedCredential
        } else {
            self.classify_private_admission(
                msg2_pb.secret_proof_32.as_deref(),
                &server_handshake_hash,
                &remote_static,
                &remote_network_name,
                pinned_remote_pubkey.as_deref(),
            )
        };
        let mut peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            msg2_pb.role_hint == 1,
            remote_sent_secret_proof,
            true,
        );
        if responder_certificate_trusted {
            if let Some(identity_type) = responder_certificate_identity_type {
                peer_identity_type = identity_type;
            }
        }

        let responder_auth_level_for_context = if responder_proof_valid {
            SecureAuthLevel::NetworkSecretConfirmed
        } else {
            responder_auth_level_for_msg3
        };
        let initiator_auth_level_for_context = if remote_network_name != network.network_name {
            SecureAuthLevel::EncryptedUnauthenticated
        } else if initiator_proof_valid
            && responder_certificate_identity_type
                .is_some_and(|identity| identity == PeerIdentityType::Admin)
        {
            SecureAuthLevel::NetworkSecretConfirmed
        } else if !local_certificate_id.is_empty() {
            SecureAuthLevel::PeerVerified
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        let initiator_identity_type_for_context = if remote_network_name != network.network_name {
            PeerIdentityType::SharedNode
        } else if initiator_proof_valid {
            PeerIdentityType::Admin
        } else if !local_certificate_id.is_empty() {
            local_certificate_identity_type
        } else {
            PeerIdentityType::SharedNode
        };

        if recovery_reset {
            let identity = recovery_identity.as_ref().expect("reset identity exists");
            let retained_peer_key = self
                .get_peer_session_store()
                .in_doubt_peer_static_pubkey(&identity.session_key);
            if let Some(retained_peer_key) = retained_peer_key {
                if remote_static_key != Some(retained_peer_key) {
                    return Err(Error::WaitRespError(
                        "recovery reset Noise static key does not match retained key".to_owned(),
                    ));
                }
            } else if !matches!(
                secure_auth_level,
                SecureAuthLevel::NetworkSecretConfirmed | SecureAuthLevel::PeerVerified
            ) {
                return Err(Error::WaitRespError(
                    "recovery reset requires a retained static key or authenticated proof"
                        .to_owned(),
                ));
            }
        }

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let session_metadata_id = msg2_pb
            .session_metadata_id
            .clone()
            .map(uuid::Uuid::from)
            .ok_or_else(|| Error::WaitRespError("missing responder session metadata".to_owned()))?;
        let transition_id = transition_id_from_wire(&msg2_pb.transition_id)?;
        let (transport_binding_kind, transport_binding_digest) =
            self.local_transport_binding_context()?;
        let context_hash = admission_context_hash(
            &network.network_name,
            self.my_peer_id,
            remote_peer_id,
            &a_conn_id,
            &uuid::Uuid::from(msg2_pb.b_conn_id.clone().ok_or_else(|| {
                Error::WaitRespError("missing responder connection id".to_owned())
            })?),
            &local_static_pubkey,
            &remote_static,
            &local_root_fingerprint,
            &local_certificate_digest,
            &responder_certificate_digest,
            &local_certificate_id,
            &responder_certificate_id,
            initiator_identity_type_for_context,
            responder_identity_type_for_msg3,
            initiator_auth_level_for_context,
            responder_auth_level_for_context,
            0,
            msg2_pb.receive_capabilities,
            0,
            msg2_pb.transmit_capabilities,
            &[0; 32],
            &responder_status_digest,
            0,
            responder_status_sequence,
            &session_metadata_id,
            &transition_id,
            msg2_pb.action,
            msg2_pb.b_session_generation,
            msg2_pb.initial_epoch,
            &handshake_hash,
            selected_protection as i32,
            transport_binding_kind,
            &transport_binding_digest,
        )?;

        let mut transport = hs
            .into_transport_mode()
            .map_err(|e| Error::WaitRespError(format!("noise transport mode failed: {e:?}")))?;
        let commit_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeCommit)),
        )
        .await??;
        self.record_control_rx(&network.network_name, commit_pkt.buf_len() as u64);
        let commit_pb = Self::decode_noise_transport_message::<PeerConnNoiseCommitPb>(
            PacketType::NoiseHandshakeCommit,
            &mut transport,
            commit_pkt,
        )?;
        if commit_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise commit a_conn_id mismatch".to_owned(),
            ));
        }
        if commit_pb.b_conn_id_echo != b_conn_id {
            return Err(Error::WaitRespError(
                "noise commit b_conn_id mismatch".to_owned(),
            ));
        }
        if commit_pb.session_metadata_id != msg2_pb.session_metadata_id {
            return Err(Error::WaitRespError(
                "noise commit session metadata mismatch".to_owned(),
            ));
        }
        if commit_pb.transition_id != msg2_pb.transition_id {
            return Err(Error::WaitRespError(
                "noise commit transition id mismatch".to_owned(),
            ));
        }
        if commit_pb.action != msg2_pb.action
            || commit_pb.session_generation != msg2_pb.b_session_generation
            || commit_pb.initial_epoch != msg2_pb.initial_epoch
        {
            return Err(Error::WaitRespError(
                "noise commit session transition mismatch".to_owned(),
            ));
        }
        if verify_slices_are_equal(&commit_pb.admission_context_hash, &context_hash).is_err() {
            return Err(Error::WaitRespError(
                "noise commit admission context mismatch".to_owned(),
            ));
        }
        let commit_root_key = match commit_pb.root_key_32.as_deref() {
            None => None,
            Some(bytes) if bytes.len() == 32 => {
                let mut root_key = [0_u8; 32];
                root_key.copy_from_slice(bytes);
                Some(root_key)
            }
            Some(_) => {
                return Err(Error::WaitRespError(
                    "noise commit has invalid root key".to_owned(),
                ));
            }
        };
        if recovery_reset {
            if commit_root_key.is_some() {
                return Err(Error::WaitRespError(
                    "noise recovery reset commit must not carry a root key".to_owned(),
                ));
            }
            let identity = recovery_identity
                .as_ref()
                .expect("recovery reset has an identity");
            let expected_action = match identity.action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            };
            if msg2_pb.session_metadata_id != Some(identity.session_metadata_id.into())
                || msg2_pb.transition_id != identity.transition_id.to_vec()
                || msg2_pb.action != expected_action
                || msg2_pb.b_session_generation != identity.session_generation
                || msg2_pb.initial_epoch != identity.initial_epoch
            {
                return Err(Error::WaitRespError(
                    "noise recovery reset identity mismatch".to_owned(),
                ));
            }
            let reset_ack = PeerConnNoiseCommitAckPb {
                a_conn_id_echo: Some(a_conn_id.into()),
                b_conn_id_echo: b_conn_id.clone(),
                session_metadata_id: msg2_pb.session_metadata_id.clone(),
                transition_id: msg2_pb.transition_id.clone(),
                action: expected_action,
                session_generation: msg2_pb.b_session_generation,
                initial_epoch: msg2_pb.initial_epoch,
                admission_context_hash: context_hash.to_vec(),
            };
            self.send_noise_transport_msg(
                reset_ack,
                PacketType::NoiseHandshakeCommitAck,
                remote_peer_id,
                &network.network_name,
                &mut transport,
            )
            .await?;
            if !self
                .get_peer_session_store()
                .cancel_initiator_reservation_exact(identity)
            {
                return Err(Error::WaitRespError(
                    "recovery reset identity was not retained".to_owned(),
                ));
            }
            return Err(Error::WaitRespError(
                "authenticated recovery reset completed".to_owned(),
            ));
        }
        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let root_key = if recovering {
            let root_key = commit_root_key.ok_or_else(|| {
                Error::WaitRespError("recovery commit is missing its root key".to_owned())
            })?;
            let identity = recovery_identity
                .as_ref()
                .expect("recovering handshake has an identity");
            if InitiatorTransitionIdentity::digest_root_key(&root_key) != identity.root_key_digest {
                return Err(Error::WaitRespError(
                    "recovery commit root key does not match its transition identity".to_owned(),
                ));
            }
            Some(root_key)
        } else {
            match action {
                PeerConnSessionActionPb::Create | PeerConnSessionActionPb::Sync => {
                    Some(commit_root_key.ok_or_else(|| {
                        Error::WaitRespError(
                            "fresh session commit is missing its root key".to_owned(),
                        )
                    })?)
                }
                PeerConnSessionActionPb::Join => {
                    if commit_root_key.is_some() {
                        return Err(Error::WaitRespError(
                            "JOIN commit must not carry a root key".to_owned(),
                        ));
                    }
                    None
                }
            }
        };
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let transition_id = transition_id_from_wire(&msg2_pb.transition_id)?;
        let reservation: InitiatorSessionReservation = if let Some(identity) = recovery_identity {
            self.get_peer_session_store()
                .resume_initiator_reservation(&identity)
                .map_err(|error| {
                    Error::WaitRespError(format!("resume recovery reservation failed: {error}"))
                })?
        } else {
            self.get_peer_session_store()
                .prepare_initiator_action_with_transition_id(
                    &session_key,
                    session_action,
                    msg2_pb.b_session_generation,
                    root_key,
                    msg2_pb.initial_epoch,
                    algo,
                    msg2_pb.server_encryption_algorithm.clone(),
                    remote_static_key,
                    transition_id,
                )?
        };
        if recovering && reservation.transition_id() != transition_id {
            return Err(Error::WaitRespError(
                "recovered session transition id mismatch".to_owned(),
            ));
        }

        let commit_ack = PeerConnNoiseCommitAckPb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: b_conn_id.clone(),
            session_metadata_id: msg2_pb.session_metadata_id.clone(),
            transition_id: msg2_pb.transition_id.clone(),
            action: msg2_pb.action,
            session_generation: msg2_pb.b_session_generation,
            initial_epoch: msg2_pb.initial_epoch,
            admission_context_hash: context_hash.to_vec(),
        };
        self.send_noise_transport_msg(
            commit_ack,
            PacketType::NoiseHandshakeCommitAck,
            remote_peer_id,
            &network.network_name,
            &mut transport,
        )
        .await?;

        let done_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeCommitDone)),
        )
        .await??;
        self.record_control_rx(&network.network_name, done_pkt.buf_len() as u64);
        let done_pb = Self::decode_noise_transport_message::<PeerConnNoiseCommitDonePb>(
            PacketType::NoiseHandshakeCommitDone,
            &mut transport,
            done_pkt,
        )?;
        if done_pb.a_conn_id_echo != Some(a_conn_id.into())
            || done_pb.b_conn_id_echo != b_conn_id
            || done_pb.session_metadata_id != msg2_pb.session_metadata_id
            || done_pb.transition_id != msg2_pb.transition_id
            || done_pb.action != msg2_pb.action
            || done_pb.session_generation != msg2_pb.b_session_generation
            || done_pb.initial_epoch != msg2_pb.initial_epoch
            || verify_slices_are_equal(&done_pb.admission_context_hash, &context_hash).is_err()
        {
            return Err(Error::WaitRespError(
                "noise commit done mismatch".to_owned(),
            ));
        }
        let ready_pb = PeerConnNoiseReadyPb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: b_conn_id.clone(),
            session_metadata_id: msg2_pb.session_metadata_id.clone(),
            transition_id: msg2_pb.transition_id.clone(),
            action: msg2_pb.action,
            session_generation: msg2_pb.b_session_generation,
            initial_epoch: msg2_pb.initial_epoch,
            admission_context_hash: context_hash.to_vec(),
        };
        let ready_packet = self.build_noise_transport_msg(
            ready_pb,
            PacketType::NoiseHandshakeReady,
            remote_peer_id,
            &mut transport,
        )?;
        let ready_packet_len = ready_packet.buf_len() as u64;
        let mut ready_ack = None;
        for _ in 0..3 {
            self.sink.send(ready_packet.clone()).await?;
            self.record_control_tx(&network.network_name, ready_packet_len);
            let ack = timeout(
                Duration::from_millis(500),
                self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeReadyAck)),
            )
            .await;
            if let Ok(Ok(packet)) = ack {
                ready_ack = Some(packet);
                break;
            }
        }
        let ready_ack = match ready_ack {
            Some(ready_ack) => ready_ack,
            None => {
                let responder_metadata = msg2_pb
                    .session_metadata_id
                    .map(uuid::Uuid::from)
                    .ok_or_else(|| {
                        Error::WaitRespError("missing responder session metadata".to_owned())
                    })?;
                reservation
                    .suspend_with_session_metadata(responder_metadata, INITIATOR_RECOVERY_LIFETIME)
                    .map_err(|error| {
                        Error::WaitRespError(format!("retain recovery reservation failed: {error}"))
                    })?;
                return Err(Error::WaitRespError(
                    "noise ready acknowledgement timed out".to_owned(),
                ));
            }
        };
        self.record_control_rx(&network.network_name, ready_ack.buf_len() as u64);
        let ready_ack_pb = Self::decode_noise_transport_message::<PeerConnNoiseReadyAckPb>(
            PacketType::NoiseHandshakeReadyAck,
            &mut transport,
            ready_ack,
        )?;
        if ready_ack_pb.a_conn_id_echo != Some(a_conn_id.into())
            || ready_ack_pb.b_conn_id_echo != b_conn_id
            || ready_ack_pb.session_metadata_id != msg2_pb.session_metadata_id
            || ready_ack_pb.transition_id != msg2_pb.transition_id
            || ready_ack_pb.action != msg2_pb.action
            || ready_ack_pb.session_generation != msg2_pb.b_session_generation
            || ready_ack_pb.initial_epoch != msg2_pb.initial_epoch
            || verify_slices_are_equal(&ready_ack_pb.admission_context_hash, &context_hash).is_err()
        {
            return Err(Error::WaitRespError(
                "noise ready acknowledgement mismatch".to_owned(),
            ));
        }
        let responder_metadata_id = msg2_pb
            .session_metadata_id
            .clone()
            .map(uuid::Uuid::from)
            .ok_or_else(|| Error::WaitRespError("missing responder session metadata".to_owned()))?;
        let receipt_identity =
            reservation.transition_identity_with_session_metadata(responder_metadata_id);
        let previous_receipt_identity =
            prior_receipt_identity.filter(|identity| identity.session_key == session_key);
        let session = match reservation
            .commit_with_receipt_replacing(receipt_identity.clone(), previous_receipt_identity)
        {
            Ok(session) => session,
            Err(error) => return Err(error.into()),
        };
        let receipt_pb = PeerConnNoiseReadyReceiptPb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: b_conn_id.clone(),
            session_metadata_id: msg2_pb.session_metadata_id.clone(),
            transition_id: msg2_pb.transition_id.clone(),
            action: msg2_pb.action,
            session_generation: msg2_pb.b_session_generation,
            initial_epoch: msg2_pb.initial_epoch,
            admission_context_hash: context_hash.to_vec(),
        };
        let receipt_packet = self.build_noise_transport_msg(
            receipt_pb,
            PacketType::NoiseHandshakeReadyReceipt,
            remote_peer_id,
            &mut transport,
        )?;
        let receipt_packet_len = receipt_packet.buf_len() as u64;
        let mut receipt_ack = None;
        for _ in 0..3 {
            self.sink.send(receipt_packet.clone()).await?;
            self.record_control_tx(&network.network_name, receipt_packet_len);
            if let Ok(Ok(packet)) = timeout(
                Duration::from_millis(500),
                self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeReadyReceiptAck)),
            )
            .await
            {
                receipt_ack = Some(packet);
                break;
            }
        }
        let Some(receipt_ack) = receipt_ack else {
            return Err(Error::WaitRespError(
                "noise ready receipt acknowledgement timed out".to_owned(),
            ));
        };
        self.record_control_rx(&network.network_name, receipt_ack.buf_len() as u64);
        let receipt_ack_pb = Self::decode_noise_transport_message::<PeerConnNoiseReadyReceiptAckPb>(
            PacketType::NoiseHandshakeReadyReceiptAck,
            &mut transport,
            receipt_ack,
        )?;
        if receipt_ack_pb.a_conn_id_echo != Some(a_conn_id.into())
            || receipt_ack_pb.b_conn_id_echo != b_conn_id
            || receipt_ack_pb.session_metadata_id != msg2_pb.session_metadata_id
            || receipt_ack_pb.transition_id != msg2_pb.transition_id
            || receipt_ack_pb.action != msg2_pb.action
            || receipt_ack_pb.session_generation != msg2_pb.b_session_generation
            || receipt_ack_pb.initial_epoch != msg2_pb.initial_epoch
            || verify_slices_are_equal(&receipt_ack_pb.admission_context_hash, &context_hash)
                .is_err()
        {
            return Err(Error::WaitRespError(
                "noise ready receipt acknowledgement mismatch".to_owned(),
            ));
        }
        if !self
            .get_peer_session_store()
            .acknowledge_initiator_receipt_exact(&receipt_identity)
        {
            return Err(Error::WaitRespError(
                "initiator receipt was not retained".to_owned(),
            ));
        }
        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            private_admission,
            peer_identity_type,
            remote_network_name,
            // we have authorized the peer with noise handshake, so just set secret digest same as us even remote is a shared node.
            secret_digest,
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

    fn decode_noise_transport_message<MsgT>(
        expected_pkt_type: PacketType,
        transport: &mut TransportState,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error>
    where
        MsgT: prost::Message + Default,
    {
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
        let mut out = vec![0u8; 4096];
        let out_len = transport
            .read_message(pkt.payload(), &mut out)
            .map_err(|e| Error::WaitRespError(format!("noise transport read failed: {e:?}")))?;
        MsgT::decode(&out[..out_len])
            .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))
    }

    async fn do_noise_handshake_as_server<Fn, Admit>(
        &mut self,
        first_msg1: ZCPacket,
        mut handshake_recved: Fn,
        mut admission_check: Admit,
    ) -> Result<NoiseHandshakeResult, Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
        Admit: FnMut(&str, SecureAuthLevel, PrivateAdmission, &[u8]) -> Result<(), Error> + Send,
    {
        let prologue = self.noise_prologue()?;

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
        validate_protocol_version(msg1_pb.version)?;
        validate_encryption_algorithm(&msg1_pb.client_encryption_algorithm)?;
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
        let session_key = SessionKey::new(remote_network_name.clone(), remote_peer_id);
        let recovery_identity = msg1_pb
            .recovery
            .clone()
            .map(|recovery| recovery_identity_from_pb(recovery, session_key.clone()))
            .transpose()?;
        let store = self.get_peer_session_store();
        let pending_responder_proof = if recovery_identity.is_none() {
            store.responder_recovery_id(&session_key)
        } else {
            None
        };
        let transition_plan = if let Some(identity) = recovery_identity {
            match self
                .get_peer_session_store()
                .reconcile_active_responder_transition(&identity)?
            {
                Some(recovered) => {
                    if recovered.action != identity.action
                        || recovered.session_generation != identity.session_generation
                        || recovered.initial_epoch != identity.initial_epoch
                        || recovered.transition_id != identity.transition_id
                        || recovered.session.metadata_session_id() != identity.session_metadata_id
                    {
                        return Err(Error::WaitRespError(
                            "responder recovery identity mismatch".to_owned(),
                        ));
                    }
                    ResponderTransitionPlan::Prepared {
                        prepared: UpsertResponderSessionReturn::for_recovery(
                            recovered.session,
                            recovered.action,
                            recovered.session_generation,
                            recovered.root_key,
                            recovered.initial_epoch,
                            recovered.transition_id,
                            (!matches!(recovered.action, PeerSessionAction::Create))
                                .then_some(recovered.transition_revision),
                            self.get_peer_session_store().as_ref().clone(),
                            session_key.clone(),
                        ),
                        recovery_active: true,
                    }
                }
                None => {
                    // The authenticated peer has no record of this exact
                    // transition. Start an explicit reset confirmation.
                    if store.has_responder_recovery(&session_key)
                        || store.has_pending_create(&session_key)
                        || store.peek(&session_key).is_some()
                    {
                        return Err(Error::WaitRespError(
                            "responder recovery identity does not match local state".to_owned(),
                        ));
                    }
                    ResponderTransitionPlan::Reset(identity)
                }
            }
        } else if let Some(expected_transition_id) = pending_responder_proof {
            match optional_transition_id_from_wire(&msg1_pb.acknowledged_transition_id)? {
                Some(supplied_transition_id)
                    if supplied_transition_id == expected_transition_id =>
                {
                    ResponderTransitionPlan::Prepared {
                        prepared: store.prepare_responder_session_with_recovery_proof(
                            &session_key,
                            supplied_transition_id,
                            algo.clone(),
                            msg1_pb.client_encryption_algorithm.clone(),
                            None,
                        )?,
                        recovery_active: false,
                    }
                }
                Some(_) => {
                    return Err(Error::WaitRespError(
                        "responder transition acknowledgement mismatch".to_owned(),
                    ));
                }
                None => {
                    store.abandon_unacknowledged_responder_recovery(&session_key);
                    ResponderTransitionPlan::Prepared {
                        prepared: store.prepare_responder_session(
                            &session_key,
                            algo.clone(),
                            msg1_pb.client_encryption_algorithm.clone(),
                            None,
                        )?,
                        recovery_active: false,
                    }
                }
            }
        } else {
            // A stale acknowledgement is harmless after its shape is valid.
            optional_transition_id_from_wire(&msg1_pb.acknowledged_transition_id)?;
            ResponderTransitionPlan::Prepared {
                prepared: store.prepare_responder_session(
                    &session_key,
                    algo.clone(),
                    msg1_pb.client_encryption_algorithm.clone(),
                    None,
                )?,
                recovery_active: false,
            }
        };
        let (
            transition_id,
            action,
            b_session_generation,
            root_key_32,
            initial_epoch,
            session_metadata_id,
            recovery_active,
            reset_identity,
        ) = match &transition_plan {
            ResponderTransitionPlan::Prepared {
                prepared,
                recovery_active,
            } => (
                prepared.transition_id(),
                prepared.action,
                prepared.session_generation,
                prepared.root_key,
                prepared.initial_epoch,
                prepared.session.metadata_session_id(),
                *recovery_active,
                None,
            ),
            ResponderTransitionPlan::Reset(identity) => (
                identity.transition_id,
                identity.action,
                identity.session_generation,
                None,
                identity.initial_epoch,
                identity.session_metadata_id,
                false,
                Some(identity),
            ),
        };
        let session = match &transition_plan {
            ResponderTransitionPlan::Prepared { prepared, .. } => Some(prepared.session.clone()),
            ResponderTransitionPlan::Reset(_) => None,
        };
        let transition_revision = match &transition_plan {
            ResponderTransitionPlan::Prepared { prepared, .. } => prepared.transition_revision,
            ResponderTransitionPlan::Reset(_) => None,
        };
        let mut reservation_guard = session.as_ref().and_then(|session| {
            (!recovery_active).then(|| {
                PreparedSessionGuard::new(
                    self.get_peer_session_store().as_ref().clone(),
                    session_key.clone(),
                    session.clone(),
                    action,
                    transition_revision,
                    initial_epoch,
                )
            })
        });

        let b_conn_id = uuid::Uuid::new_v4();
        let (responder_certificate, responder_certificate_status, server_root_fingerprint) =
            if role_hint == 1 {
                if self
                    .global_ctx
                    .get_network_identity()
                    .network_secret
                    .is_some()
                {
                    self.build_local_admin_credentials(&local_static_pubkey)?
                } else {
                    let certificate = self.local_credential_certificate().unwrap_or_default();
                    if certificate.is_empty() {
                        return Err(Error::WaitRespError(
                            "credential listener has no responder certificate".to_owned(),
                        ));
                    }
                    let root = self
                        .locally_pinned_root_fingerprint(&server_network_name)
                        .ok_or_else(|| {
                            Error::WaitRespError(
                                "credential listener has no pinned certificate root".to_owned(),
                            )
                        })?;
                    self.verify_remote_certificate(
                        &certificate,
                        &server_network_name,
                        &root,
                        &local_static_pubkey,
                        "Credential",
                    )?;
                    (certificate, Vec::new(), root)
                }
            } else {
                (Vec::new(), Vec::new(), self.admission_root_fingerprint())
            };
        let responder_certificate_digest = canonical_certificate_digest(&responder_certificate)?;
        let responder_certificate_id = canonical_certificate_id(&responder_certificate)?;
        if !responder_certificate_id.is_empty()
            && self
                .global_ctx
                .get_credential_manager()
                .is_certificate_id_revoked(&responder_certificate_id)
        {
            return Err(Error::WaitRespError(
                "local responder credential certificate is revoked".to_owned(),
            ));
        }
        let responder_certificate_identity_type = if responder_certificate.is_empty() {
            PeerIdentityType::SharedNode
        } else {
            let certificate = CredentialCertificate::decode(responder_certificate.as_slice())
                .map_err(|_| {
                    Error::WaitRespError("invalid local responder certificate".to_owned())
                })?;
            match certificate.role.as_str() {
                "Admin" => PeerIdentityType::Admin,
                "Credential" => PeerIdentityType::Credential,
                _ => {
                    return Err(Error::WaitRespError(
                        "unsupported local responder certificate role".to_owned(),
                    ));
                }
            }
        };
        let responder_status_digest = canonical_status_digest(&responder_certificate_status)?;
        let responder_status_sequence = if responder_certificate_status.is_empty() {
            0
        } else {
            CredentialCertificateStatus::decode(responder_certificate_status.as_slice())
                .map_err(|_| Error::WaitRespError("invalid Admin certificate status".to_owned()))?
                .sequence
        };
        let responder_receive_capabilities = 0;
        let responder_transmit_capabilities = 0;
        let local_data_protection = self.local_data_protection()?;
        let (transport_binding_kind, transport_binding_digest) =
            self.local_transport_binding_context()?;
        if msg1_pb.a_network_name == server_network_name
            && verify_slices_are_equal(
                &server_root_fingerprint,
                &msg1_pb.credential_root_fingerprint,
            )
            .is_err()
        {
            return Err(Error::WaitRespError(
                "initiator credential root fingerprint mismatch".to_owned(),
            ));
        }
        let msg2_pb = PeerConnNoiseMsg2Pb {
            b_network_name: server_network_name,
            role_hint,
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation,
            initial_epoch,
            b_conn_id: Some(b_conn_id.clone().into()),
            a_conn_id_echo: msg1_pb.a_conn_id.clone(),
            secret_proof_32,
            server_encryption_algorithm: algo,
            version: VERSION,
            session_metadata_id: Some(session_metadata_id.clone().into()),
            transition_id: transition_id.to_vec(),
            recovery: recovery_active.then(|| msg1_pb.recovery.clone()).flatten(),
            receive_capabilities: responder_receive_capabilities,
            transmit_capabilities: responder_transmit_capabilities,
            responder_certificate,
            credential_root_fingerprint: server_root_fingerprint.to_vec(),
            responder_certificate_status,
            data_protection: local_data_protection as i32,
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
        if msg3_pb.b_conn_id_echo != Some(b_conn_id.clone().into()) {
            return Err(Error::WaitRespError(
                "noise msg3 b_conn_id mismatch".to_owned(),
            ));
        }
        let echoed_responder_identity = PeerIdentityType::try_from(msg3_pb.responder_identity_type)
            .map_err(|_| Error::WaitRespError("invalid echoed responder identity".to_owned()))?;
        let echoed_responder_auth = SecureAuthLevel::try_from(msg3_pb.responder_auth_level)
            .map_err(|_| Error::WaitRespError("invalid echoed responder auth level".to_owned()))?;
        let selected_protection = PeerConnDataProtectionPb::try_from(msg3_pb.data_protection)
            .map_err(|_| Error::WaitRespError("invalid data protection mode".to_owned()))?;
        validate_data_protection_mode(local_data_protection, selected_protection)?;
        if msg3_pb.data_protection != local_data_protection as i32 {
            return Err(Error::WaitRespError(
                "peer data protection mode does not match the Msg2 selection".to_owned(),
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
        let initiator_certificate_digest =
            canonical_certificate_digest(&msg3_pb.initiator_certificate)?;
        if verify_slices_are_equal(
            &initiator_certificate_digest,
            &msg1_pb.initiator_certificate_digest,
        )
        .is_err()
        {
            return Err(Error::WaitRespError(
                "initiator certificate digest mismatch".to_owned(),
            ));
        }
        let initiator_certificate_id = canonical_certificate_id(&msg3_pb.initiator_certificate)?;
        let mut initiator_has_valid_certificate = false;
        let mut initiator_certificate_identity_type = None;
        let locally_pinned_initiator_root =
            self.locally_pinned_root_fingerprint(&remote_network_name);
        if !msg3_pb.initiator_certificate.is_empty()
            && remote_network_name == self.global_ctx.get_network_name()
        {
            let Some(trusted_root) = locally_pinned_initiator_root else {
                return Err(Error::WaitRespError(
                    "administrator has no pinned root for the network".to_owned(),
                ));
            };
            if verify_slices_are_equal(&trusted_root, &msg1_pb.credential_root_fingerprint).is_err()
            {
                return Err(Error::WaitRespError(
                    "initiator credential root fingerprint mismatch".to_owned(),
                ));
            }
            let certificate_metadata = CredentialCertificate::decode(
                msg3_pb.initiator_certificate.as_slice(),
            )
            .map_err(|_| Error::WaitRespError("invalid initiator certificate".to_owned()))?;
            let expected_role = match certificate_metadata.role.as_str() {
                "Admin" => {
                    initiator_certificate_identity_type = Some(PeerIdentityType::Admin);
                    "Admin"
                }
                "Credential" => {
                    initiator_certificate_identity_type = Some(PeerIdentityType::Credential);
                    "Credential"
                }
                _ => {
                    return Err(Error::WaitRespError(
                        "unsupported initiator certificate role".to_owned(),
                    ));
                }
            };
            let certificate = self.verify_remote_certificate(
                &msg3_pb.initiator_certificate,
                &remote_network_name,
                &trusted_root,
                &remote_static,
                expected_role,
            )?;
            if certificate.certificate_id != initiator_certificate_id {
                return Err(Error::WaitRespError(
                    "initiator certificate id changed during verification".to_owned(),
                ));
            }
            initiator_has_valid_certificate = true;
            if self
                .global_ctx
                .get_credential_manager()
                .is_certificate_id_revoked(&initiator_certificate_id)
            {
                return Err(Error::WaitRespError(
                    "initiator credential certificate is revoked".to_owned(),
                ));
            }
        }
        let transcript_secret_proof_valid = self.verify_secret_proof(
            msg3_pb.secret_proof_32.as_deref(),
            &handshake_hash_for_proof,
        );
        let max_responder_auth = if transcript_secret_proof_valid {
            SecureAuthLevel::NetworkSecretConfirmed
        } else {
            // PeerVerified only asserts that the initiator checked the
            // responder static key. Pinning or a trusted certificate is
            // initiator-side evidence the responder cannot observe, so it
            // must not be rejected here. Only NetworkSecretConfirmed claims
            // secret possession, which the responder can verify itself.
            SecureAuthLevel::PeerVerified
        };
        if echoed_responder_auth as i32 > max_responder_auth as i32 {
            return Err(Error::WaitRespError(
                "echoed responder auth exceeds verified evidence".to_owned(),
            ));
        }
        let expected_responder_identity = responder_certificate_identity_type;
        if echoed_responder_identity != expected_responder_identity {
            return Err(Error::WaitRespError(
                "echoed responder identity does not match role".to_owned(),
            ));
        }
        if role_hint == 1 && !transcript_secret_proof_valid && !initiator_has_valid_certificate {
            return Err(Error::WaitRespError(
                "administrator requires a valid signed initiator certificate".to_owned(),
            ));
        }
        if let Some(reset_identity) = reset_identity {
            // Reset is destructive. Require shared-secret or trusted-key
            // authentication when the responder has no retained key.
            let secure_auth_level = if transcript_secret_proof_valid {
                SecureAuthLevel::NetworkSecretConfirmed
            } else if initiator_has_valid_certificate {
                SecureAuthLevel::PeerVerified
            } else {
                return Err(Error::WaitRespError(
                    "recovery reset requires transcript proof or a valid Credential certificate"
                        .to_owned(),
                ));
            };
            if !matches!(
                secure_auth_level,
                SecureAuthLevel::NetworkSecretConfirmed | SecureAuthLevel::PeerVerified
            ) {
                return Err(Error::WaitRespError(
                    "recovery reset requires authenticated proof".to_owned(),
                ));
            }
            let handshake_hash = hs.get_handshake_hash().to_vec();
            let initiator_conn_id = msg1_pb
                .a_conn_id
                .clone()
                .ok_or_else(|| Error::WaitRespError("missing initiator connection id".to_owned()))
                .map(uuid::Uuid::from)?;
            let initiator_identity_type =
                if remote_network_name != self.global_ctx.get_network_name() {
                    PeerIdentityType::SharedNode
                } else if secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed {
                    PeerIdentityType::Admin
                } else {
                    PeerIdentityType::Credential
                };
            let reset_context_hash = admission_context_hash(
                &remote_network_name,
                remote_peer_id,
                self.my_peer_id,
                &initiator_conn_id,
                &b_conn_id,
                &remote_static,
                &local_static_pubkey,
                &msg1_pb.credential_root_fingerprint,
                &initiator_certificate_digest,
                &responder_certificate_digest,
                &initiator_certificate_id,
                &responder_certificate_id,
                initiator_identity_type,
                echoed_responder_identity,
                secure_auth_level,
                echoed_responder_auth,
                msg1_pb.receive_capabilities,
                responder_receive_capabilities,
                msg1_pb.transmit_capabilities,
                responder_transmit_capabilities,
                &[0; 32],
                &responder_status_digest,
                0,
                responder_status_sequence,
                &reset_identity.session_metadata_id,
                &reset_identity.transition_id,
                match reset_identity.action {
                    PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                    PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                    PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                },
                reset_identity.session_generation,
                reset_identity.initial_epoch,
                &handshake_hash,
                selected_protection as i32,
                transport_binding_kind,
                &transport_binding_digest,
            )?;
            let mut reset_transport = hs
                .into_transport_mode()
                .map_err(|e| Error::WaitRespError(format!("noise transport mode failed: {e:?}")))?;
            let reset_commit = PeerConnNoiseCommitPb {
                a_conn_id_echo: msg1_pb.a_conn_id.clone(),
                b_conn_id_echo: Some(b_conn_id.clone().into()),
                session_metadata_id: Some(reset_identity.session_metadata_id.into()),
                transition_id: reset_identity.transition_id.to_vec(),
                action: match reset_identity.action {
                    PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                    PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                    PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                },
                session_generation: reset_identity.session_generation,
                initial_epoch: reset_identity.initial_epoch,
                root_key_32: None,
                admission_context_hash: reset_context_hash.to_vec(),
            };
            self.send_noise_transport_msg(
                reset_commit,
                PacketType::NoiseHandshakeCommit,
                remote_peer_id,
                &remote_network_name,
                &mut reset_transport,
            )
            .await?;
            let reset_ack_pkt = timeout(
                Duration::from_secs(5),
                self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeCommitAck)),
            )
            .await??;
            let reset_ack = Self::decode_noise_transport_message::<PeerConnNoiseCommitAckPb>(
                PacketType::NoiseHandshakeCommitAck,
                &mut reset_transport,
                reset_ack_pkt,
            )?;
            if reset_ack.a_conn_id_echo != msg1_pb.a_conn_id
                || reset_ack.b_conn_id_echo != Some(b_conn_id.into())
                || reset_ack.session_metadata_id != Some(reset_identity.session_metadata_id.into())
                || reset_ack.transition_id != reset_identity.transition_id.to_vec()
                || reset_ack.session_generation != reset_identity.session_generation
                || reset_ack.initial_epoch != reset_identity.initial_epoch
                || reset_ack.action
                    != match reset_identity.action {
                        PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                        PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                        PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                    }
                || verify_slices_are_equal(&reset_ack.admission_context_hash, &reset_context_hash)
                    .is_err()
            {
                return Err(Error::WaitRespError(
                    "noise recovery reset acknowledgement mismatch".to_owned(),
                ));
            }
            return Err(Error::WaitRespError(
                "authenticated recovery reset completed".to_owned(),
            ));
        }
        let session = session.expect("prepared responder transition has a session");
        let prepared = match transition_plan {
            ResponderTransitionPlan::Prepared { prepared, .. } => prepared,
            ResponderTransitionPlan::Reset(_) => unreachable!("reset plan returned above"),
        };
        if recovery_active {
            // Recovery uses a committed session. Check the key without creating a pending state.
            session
                .check_peer_static_pubkey(remote_static_key)
                .map_err(|error| {
                    Error::WaitRespError(format!("check remote static key failed: {error}"))
                })?;
        } else {
            // Reserve the authenticated static key until the responder commits.
            // The direct handshake must not publish peer identity before CommitAck.
            session
                .reserve_peer_static_pubkey(remote_static_key)
                .map_err(|error| {
                    Error::WaitRespError(format!("reserve remote static key failed: {error}"))
                })?;
        }

        // A digest identifies a network. It never proves secret possession.
        let private_admission = if transcript_secret_proof_valid {
            PrivateAdmission::TranscriptSecretProof
        } else if initiator_has_valid_certificate {
            PrivateAdmission::RootSignedCredential
        } else {
            PrivateAdmission::None
        };
        let transcript_secret_proof =
            matches!(private_admission, PrivateAdmission::TranscriptSecretProof);
        let trusted_static_credential = matches!(
            private_admission,
            PrivateAdmission::TrustedStaticCredential | PrivateAdmission::RootSignedCredential
        );

        // Same-network peers must prove the network secret or a trusted
        // credential. Foreign peers can use the same proof or a trusted key.
        // A role hint never grants authority.
        let secure_auth_level = if transcript_secret_proof {
            SecureAuthLevel::NetworkSecretConfirmed
        } else if trusted_static_credential {
            SecureAuthLevel::PeerVerified
        } else if role_hint == 1 {
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
        let peer_identity_type = initiator_certificate_identity_type.unwrap_or(peer_identity_type);
        self.private_admission = private_admission;
        admission_check(
            &remote_network_name,
            secure_auth_level,
            private_admission,
            &remote_static,
        )?;
        // Noise XX authenticates the initiator static key in Msg3.
        // Clear any previous responder proof only after this authentication.
        if !recovery_active {
            prepared.authenticate_recovery().map_err(|error| {
                Error::WaitRespError(format!("authenticate responder recovery failed: {error}"))
            })?;
        }

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let initiator_conn_id = msg1_pb
            .a_conn_id
            .clone()
            .map(uuid::Uuid::from)
            .ok_or_else(|| Error::WaitRespError("missing initiator connection id".to_owned()))?;
        let context_hash = admission_context_hash(
            &remote_network_name,
            remote_peer_id,
            self.my_peer_id,
            &initiator_conn_id,
            &b_conn_id,
            &remote_static,
            &local_static_pubkey,
            &msg1_pb.credential_root_fingerprint,
            &initiator_certificate_digest,
            &responder_certificate_digest,
            &initiator_certificate_id,
            &responder_certificate_id,
            peer_identity_type,
            echoed_responder_identity,
            secure_auth_level,
            echoed_responder_auth,
            msg1_pb.receive_capabilities,
            responder_receive_capabilities,
            msg1_pb.transmit_capabilities,
            responder_transmit_capabilities,
            &[0; 32],
            &responder_status_digest,
            0,
            responder_status_sequence,
            &session_metadata_id,
            &transition_id,
            match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation,
            initial_epoch,
            &handshake_hash,
            selected_protection as i32,
            transport_binding_kind,
            &transport_binding_digest,
        )?;
        let mut transport = hs
            .into_transport_mode()
            .map_err(|e| Error::WaitRespError(format!("noise transport mode failed: {e:?}")))?;
        let commit_pb = PeerConnNoiseCommitPb {
            a_conn_id_echo: msg1_pb.a_conn_id.clone(),
            b_conn_id_echo: Some(b_conn_id.clone().into()),
            session_metadata_id: Some(session_metadata_id.into()),
            transition_id: transition_id.to_vec(),
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            session_generation: b_session_generation,
            initial_epoch,
            root_key_32: (recovery_active || !matches!(action, PeerSessionAction::Join))
                .then(|| root_key_32.map(|key| key.to_vec()))
                .flatten(),
            admission_context_hash: context_hash.to_vec(),
        };
        self.send_noise_transport_msg(
            commit_pb,
            PacketType::NoiseHandshakeCommit,
            remote_peer_id,
            &remote_network_name,
            &mut transport,
        )
        .await?;

        let ack_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeCommitAck)),
        )
        .await??;
        self.record_control_rx(&remote_network_name, ack_pkt.buf_len() as u64);
        let ack_pb = Self::decode_noise_transport_message::<PeerConnNoiseCommitAckPb>(
            PacketType::NoiseHandshakeCommitAck,
            &mut transport,
            ack_pkt,
        )?;
        if ack_pb.a_conn_id_echo != msg1_pb.a_conn_id
            || ack_pb.b_conn_id_echo != Some(b_conn_id.clone().into())
            || ack_pb.session_metadata_id != Some(session_metadata_id.clone().into())
            || ack_pb.transition_id != transition_id.to_vec()
            || ack_pb.session_generation != b_session_generation
            || ack_pb.initial_epoch != initial_epoch
            || ack_pb.action
                != match action {
                    PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                    PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                    PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                }
            || verify_slices_are_equal(&ack_pb.admission_context_hash, &context_hash).is_err()
        {
            return Err(Error::WaitRespError(
                "noise commit acknowledgement mismatch".to_owned(),
            ));
        }

        let done_pb = PeerConnNoiseCommitDonePb {
            a_conn_id_echo: msg1_pb.a_conn_id,
            b_conn_id_echo: Some(b_conn_id.into()),
            session_metadata_id: Some(session_metadata_id.into()),
            transition_id: transition_id.to_vec(),
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            session_generation: b_session_generation,
            initial_epoch,
            admission_context_hash: context_hash.to_vec(),
        };
        self.send_noise_transport_msg(
            done_pb,
            PacketType::NoiseHandshakeCommitDone,
            remote_peer_id,
            &remote_network_name,
            &mut transport,
        )
        .await?;

        let ready_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeReady)),
        )
        .await??;
        self.record_control_rx(&remote_network_name, ready_pkt.buf_len() as u64);
        let ready_pb = Self::decode_noise_transport_message::<PeerConnNoiseReadyPb>(
            PacketType::NoiseHandshakeReady,
            &mut transport,
            ready_pkt,
        )?;
        if ready_pb.a_conn_id_echo != msg1_pb.a_conn_id
            || ready_pb.b_conn_id_echo != Some(b_conn_id.into())
            || ready_pb.session_metadata_id != Some(session_metadata_id.into())
            || ready_pb.transition_id != transition_id.to_vec()
            || ready_pb.session_generation != b_session_generation
            || ready_pb.initial_epoch != initial_epoch
            || verify_slices_are_equal(&ready_pb.admission_context_hash, &context_hash).is_err()
            || ready_pb.action
                != match action {
                    PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                    PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                    PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                }
        {
            return Err(Error::WaitRespError("noise ready mismatch".to_owned()));
        }
        let ready_ack_pb = PeerConnNoiseReadyAckPb {
            a_conn_id_echo: msg1_pb.a_conn_id,
            b_conn_id_echo: Some(b_conn_id.into()),
            session_metadata_id: Some(session_metadata_id.into()),
            transition_id: transition_id.to_vec(),
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            session_generation: b_session_generation,
            initial_epoch,
            admission_context_hash: context_hash.to_vec(),
        };
        let ready_ack_packet = self.build_noise_transport_msg(
            ready_ack_pb,
            PacketType::NoiseHandshakeReadyAck,
            remote_peer_id,
            &mut transport,
        )?;
        let ready_ack_len = ready_ack_packet.buf_len() as u64;
        // Publish before the first acknowledgement. The acknowledgement
        // promises that this exact transition is active on the responder.
        if !recovery_active {
            self.get_peer_session_store()
                .commit_prepared_responder_transition(&session_key, &prepared)?;
            if let Some(guard) = reservation_guard.as_mut() {
                guard.disarm();
            }
        }
        // Send a short acknowledgement burst. This bounds one lost ACK
        // without adding a timer delay to the successful handshake path.
        // A failed copy is tolerated here: the transition is already
        // committed, and the initiator can finish from any single copy.
        // The failure is reported after the receipt exchange completes.
        let mut ready_ack_send_error = None;
        for _ in 0..3 {
            match self.sink.send(ready_ack_packet.clone()).await {
                Ok(()) => self.record_control_tx(&remote_network_name, ready_ack_len),
                Err(error) => {
                    ready_ack_send_error.get_or_insert(error);
                }
            }
        }
        let receipt_pkt = match timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeReadyReceipt)),
        )
        .await
        {
            Ok(Ok(packet)) => Some(packet),
            Ok(Err(error)) => return Err(error),
            Err(_) => None,
        };
        if let Some(receipt_pkt) = receipt_pkt {
            self.record_control_rx(&remote_network_name, receipt_pkt.buf_len() as u64);
            let receipt_pb = Self::decode_noise_transport_message::<PeerConnNoiseReadyReceiptPb>(
                PacketType::NoiseHandshakeReadyReceipt,
                &mut transport,
                receipt_pkt,
            )?;
            if receipt_pb.a_conn_id_echo != msg1_pb.a_conn_id
                || receipt_pb.b_conn_id_echo != Some(b_conn_id.into())
                || receipt_pb.session_metadata_id != Some(session_metadata_id.into())
                || receipt_pb.transition_id != transition_id.to_vec()
                || receipt_pb.session_generation != b_session_generation
                || receipt_pb.initial_epoch != initial_epoch
                || verify_slices_are_equal(&receipt_pb.admission_context_hash, &context_hash)
                    .is_err()
                || receipt_pb.action
                    != match action {
                        PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                        PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                        PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                    }
            {
                return Err(Error::WaitRespError(
                    "noise ready receipt mismatch".to_owned(),
                ));
            }
            let receipt_ack_pb = PeerConnNoiseReadyReceiptAckPb {
                a_conn_id_echo: msg1_pb.a_conn_id,
                b_conn_id_echo: Some(b_conn_id.into()),
                session_metadata_id: Some(session_metadata_id.into()),
                transition_id: transition_id.to_vec(),
                action: match action {
                    PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                    PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                    PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                },
                session_generation: b_session_generation,
                initial_epoch,
                admission_context_hash: context_hash.to_vec(),
            };
            let receipt_ack_packet = self.build_noise_transport_msg(
                receipt_ack_pb,
                PacketType::NoiseHandshakeReadyReceiptAck,
                remote_peer_id,
                &mut transport,
            )?;
            let receipt_ack_len = receipt_ack_packet.buf_len() as u64;
            for _ in 0..3 {
                self.sink.send(receipt_ack_packet.clone()).await?;
                self.record_control_tx(&remote_network_name, receipt_ack_len);
            }
            // Remove only this exact responder proof after the authenticated receipt.
            self.get_peer_session_store()
                .acknowledge_responder_recovery(&session_key, transition_id);
        }

        if let Some(error) = ready_ack_send_error {
            return Err(error.into());
        }

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            private_admission,
            peer_identity_type,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
        })
    }

    fn build_handshake_rsp(&self, noise: &NoiseHandshakeResult) -> HandshakeRequest {
        tracing::debug!(
            peer_id = noise.peer_id,
            identity_type = ?noise.peer_identity_type,
            secure_auth_level = ?noise.secure_auth_level,
            "build authenticated handshake response"
        );
        HandshakeRequest {
            magic: MAGIC,
            my_peer_id: noise.peer_id,
            version: VERSION,
            network_name: noise.remote_network_name.clone(),

            features: handshake_features(),
            network_secret_digest: noise.secret_digest.clone(),
        }
    }

    #[tracing::instrument(skip(handshake_recved))]
    pub async fn do_handshake_as_server_ext<Fn>(
        &mut self,
        handshake_recved: Fn,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        self.do_handshake_as_server_ext_with_admission(handshake_recved, |_, _, _, _| Ok(()))
            .await
    }

    #[tracing::instrument(skip(handshake_recved, admission_check))]
    pub async fn do_handshake_as_server_ext_with_admission<Fn, Admit>(
        &mut self,
        handshake_recved: Fn,
        admission_check: Admit,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
        Admit: FnMut(&str, SecureAuthLevel, PrivateAdmission, &[u8]) -> Result<(), Error> + Send,
    {
        let first_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg1)),
        )
        .await??;
        let Some(hdr) = first_pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "first packet must have peer manager header".to_owned(),
            ));
        };
        if hdr.packet_type != PacketType::NoiseHandshakeMsg1 as u8 {
            return Err(Error::WaitRespError(
                "first handshake packet was not NoiseHandshakeMsg1".to_owned(),
            ));
        }
        let noise = self
            .do_noise_handshake_as_server(first_pkt, handshake_recved, admission_check)
            .await?;
        let data_protection_mode = self.local_data_protection()?;
        let handshake_rsp = self.build_handshake_rsp(&noise);
        self.private_admission = noise.private_admission;
        self.session_filter.set_session(noise.session.clone());
        self.session_filter.set_peer_id(noise.peer_id);
        self.session_filter
            .set_data_protection_mode(data_protection_mode);
        self.noise_handshake_result = Some(noise);
        self.info = Some(handshake_rsp);
        self.is_client = Some(false);

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            self.enable_authenticated_path();
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        let noise = self.do_noise_handshake_as_client().await?;
        let data_protection_mode = self.local_data_protection()?;
        self.private_admission = noise.private_admission;
        self.session_filter.set_session(noise.session.clone());
        self.session_filter.set_peer_id(noise.peer_id);
        self.session_filter
            .set_data_protection_mode(data_protection_mode);

        let handshake_rsp = self.build_handshake_rsp(&noise);
        self.noise_handshake_result = Some(noise);
        self.info = Some(handshake_rsp);
        self.is_client = Some(true);

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError(
                "peer id conflict, are you connecting to yourself?".to_owned(),
            ))
        } else {
            self.enable_authenticated_path();
            Ok(())
        }
    }

    fn enable_authenticated_path(&self) {
        if let Some(state) = &self.tunnel_path_state {
            state.peer_authenticated.store(true, Ordering::Release);
        }
    }

    pub(crate) fn current_tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel_path_state
            .as_ref()
            .map(|state| state.info.read().clone())
            .or_else(|| self.tunnel_info.clone())
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
        let network_name = if self.handshake_done() {
            network_name
        } else {
            Self::HANDSHAKE_METRIC_NETWORK
        };
        self.control_metrics(network_name).record_tx(bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        let network_name = if self.handshake_done() {
            network_name
        } else {
            Self::HANDSHAKE_METRIC_NETWORK
        };
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
        let speed_ack_sender = self.speed_ack_sender.clone();
        let speed_probe_receiver = self.speed_probe_receiver.clone();
        let probe_my_peer_id = self.my_peer_id;
        let probe_peer_id = self.get_peer_id();
        let receiver_pacing_supported = self.supports_receiver_pacing();
        let receiver_pacer = shared_receiver_pacer(probe_my_peer_id, probe_peer_id);
        self.receiver_pacer = Some(receiver_pacer.clone());
        let receiver_pressure_reports_enabled =
            receiver_pacing_enabled() && receiver_pacing_supported;
        let receiver_pressure_telemetry = self.global_ctx.dataplane_telemetry().clone();
        let authenticated_session_id = self.conn_id;
        let authenticated_peer_identity_type = self
            .noise_handshake_result
            .as_ref()
            .map(|result| result.peer_identity_type)
            .unwrap_or(PeerIdentityType::SharedNode);
        let authenticated_peer_secure_auth_level = self
            .noise_handshake_result
            .as_ref()
            .map(|result| result.secure_auth_level)
            .unwrap_or(SecureAuthLevel::EncryptedUnauthenticated);
        let conn_info_for_instrument = self.get_conn_info();
        let control_metrics = self.control_metrics(&conn_info_for_instrument.network_name);
        let speed_metrics = SpeedProbeMetrics::new(
            self.global_ctx.stats_manager().clone(),
            conn_info_for_instrument.network_name.clone(),
            probe_peer_id,
        );

        let poll_receiver = speed_probe_receiver.clone();
        let poll_sink = sink.clone();
        let poll_close_notifier = self.close_event_notifier.clone();
        let poll_metrics = control_metrics.clone();
        let poll_pressure_telemetry = receiver_pressure_telemetry.clone();
        self.tasks.spawn(async move {
            let mut interval = tokio::time::interval(RECEIVER_PRESSURE_REPORT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut close_waiter = poll_close_notifier.get_waiter().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let ack = poll_receiver.lock().poll(std::time::Instant::now());
                        if let Some(ack) = ack {
                            let packet = speed_probe_ack_packet(probe_my_peer_id, probe_peer_id, ack);
                            let packet_len = packet.buf_len() as u64;
                            if poll_sink.send(packet).await.is_err() {
                                break;
                            }
                            poll_metrics.record_tx(packet_len);
                        }
                        if receiver_pressure_reports_enabled {
                            let snapshot = poll_pressure_telemetry.receiver_pressure_snapshot();
                            let report = ReceiverPressureReport {
                                sample_micros: snapshot.sample_micros,
                                delivered_bytes: snapshot.delivered_bytes,
                                occupancy_packets: snapshot
                                    .occupancy_packets
                                    .min(u64::from(u32::MAX)) as u32,
                                capacity_packets: super::direct_nic::DIRECT_NIC_QUEUE_PACKET_CAPACITY
                                    .min(u32::MAX as usize) as u32,
                                stall_ns: snapshot.stall_ns,
                            };
                            let packet = receiver_pressure_packet(
                                probe_my_peer_id,
                                probe_peer_id,
                                report,
                            );
                            let packet_len = packet.buf_len() as u64;
                            if poll_sink.send(packet).await.is_err() {
                                break;
                            }
                            poll_metrics.record_tx(packet_len);
                        }
                    }
                    _ = async {
                        if let Some(waiter) = close_waiter.as_mut() {
                            let _ = waiter.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => break,
                }
            }
            Ok(())
        });

        let receiver_pacer_for_recv = receiver_pacer.clone();
        let global_ctx = self.global_ctx.clone();
        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                let mut receive_queue = VecDeque::with_capacity(RECEIVE_PREFETCH_BATCHES);
                let mut stream_ended = false;
                let mut next_result = stream.next().await;
                while let Some(result) = next_result.take() {
                    let mut incoming = match result {
                        Ok(batch) => batch,
                        Err(error) => {
                            tracing::error!(?error, "peer conn recv error");
                            task_ret = Err(error);
                            break;
                        }
                    };
                    let identity_valid = stamp_and_validate_incoming_identity(
                        &mut incoming,
                        probe_peer_id,
                        authenticated_peer_identity_type,
                        authenticated_peer_secure_auth_level,
                        authenticated_session_id,
                    );
                    if !identity_valid {
                        tracing::error!(
                            authenticated_peer_id = probe_peer_id,
                            "peer packet contains conflicting authenticated identity"
                        );
                        task_ret = Err(TunnelError::InvalidPacket(
                            "peer packet contains conflicting authenticated identity".to_string(),
                        ));
                        break;
                    }

                    // Parse headers only when missing. The QUIC decoder may already
                    // have filled metadata for a complete direct batch.
                    for packet in incoming.iter_mut() {
                        if packet.parsed_metadata().is_none() {
                            let _ = packet.refresh_parsed_metadata();
                        }
                    }

                    let received_bytes = incoming.buffer_byte_len() as u64;
                    if packet_batch_is_direct_peer_data(&incoming) {
                        // Deliver the bulk batch while still answering liveness
                        // traffic: ping/pong-only batches are handled inline
                        // instead of waiting behind the parked delivery.
                        let delivery = sender.send_batch(incoming);
                        tokio::pin!(delivery);
                        let mut prefetch_stream_open = true;
                        let mut prefetch_reached_end = false;
                        let mut delivery_failed = false;
                        let mut identity_invalid = false;
                        loop {
                            tokio::select! {
                                biased;
                                delivery_result = &mut delivery => {
                                    if delivery_result.is_err() {
                                        delivery_failed = true;
                                    }
                                    break;
                                }
                                next = stream.next(), if prefetch_stream_open && receive_queue.len() < RECEIVE_PREFETCH_BATCHES => {
                                    match next {
                                        Some(result) => match result {
                                            Ok(mut batch) => {
                                                if !stamp_and_validate_incoming_identity(
                                                    &mut batch,
                                                    probe_peer_id,
                                                    authenticated_peer_identity_type,
                                                    authenticated_peer_secure_auth_level,
                                                    authenticated_session_id,
                                                ) {
                                                    tracing::error!(
                                                        authenticated_peer_id = probe_peer_id,
                                                        "peer packet contains conflicting authenticated identity"
                                                    );
                                                    task_ret = Err(TunnelError::InvalidPacket(
                                                        "peer packet contains conflicting authenticated identity"
                                                            .to_string(),
                                                    ));
                                                    identity_invalid = true;
                                                    break;
                                                }
                                                if packet_batch_is_direct_ping_pong(&batch) {
                                                    respond_to_direct_ping_pong_batch(
                                                        batch,
                                                        &sink,
                                                        &ctrl_sender,
                                                        &control_metrics,
                                                    )
                                                    .await;
                                                } else {
                                                    receive_queue.push_back(Ok(batch));
                                                }
                                            }
                                            Err(_) => receive_queue.push_back(result),
                                        },
                                        None => {
                                            prefetch_stream_open = false;
                                            prefetch_reached_end = true;
                                        }
                                    }
                                }
                            }
                        }
                        if delivery_failed {
                            tracing::warn!(
                                "peer receive loop could not admit a direct data batch"
                            );
                        }
                        if delivery_failed || identity_invalid {
                            break;
                        }
                        global_ctx.pace_receive(received_bytes as usize).await;
                        stream_ended |= prefetch_reached_end;
                        next_result = if let Some(first) = receive_queue.pop_front() {
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

                        // Old peers must not deliver retired FEC records as ordinary data.
                        if matches!(peer_mgr_hdr.packet_type, 23 | 24) {
                            continue;
                        }
                        if peer_mgr_hdr.packet_type == PacketType::ReceiverPressure as u8 {
                            control_metrics.record_rx(buf_len);
                            match ReceiverPressureReport::decode(zc_packet.payload()) {
                                Ok(report) => {
                                    let update = receiver_pacer_for_recv
                                        .update_report(report, std::time::Instant::now());
                                    if update.active_changed {
                                        tracing::info!(
                                            active = update.active,
                                            pressured = update.pressured,
                                            service_bytes_per_second =
                                                update.service_bytes_per_second,
                                            target_bytes_per_second =
                                                update.target_bytes_per_second,
                                            remote_peer_id = probe_peer_id,
                                            "receiver-clocked pacing state changed"
                                        );
                                    } else if update.active {
                                        tracing::trace!(
                                            pressured = update.pressured,
                                            service_bytes_per_second =
                                                update.service_bytes_per_second,
                                            target_bytes_per_second =
                                                update.target_bytes_per_second,
                                            remote_peer_id = probe_peer_id,
                                            "receiver-clocked pacing updated"
                                        );
                                    }
                                }
                                Err(error) => tracing::warn!(
                                    error,
                                    remote_peer_id = probe_peer_id,
                                    "invalid authenticated receiver-pressure report"
                                ),
                            }
                        } else if peer_mgr_hdr.packet_type == PacketType::SpeedProbe as u8 {
                            control_metrics.record_rx(buf_len);
                            speed_metrics.record_rx(buf_len);
                            let probe_result = {
                                speed_probe_receiver.lock().receive_wire(
                                    zc_packet.payload(),
                                    zc_packet.tunnel_payload().len(),
                                    std::time::Instant::now(),
                                )
                            };
                            match probe_result {
                                Ok(Some(ack)) => {
                                    let packet = speed_probe_ack_packet(
                                        probe_my_peer_id,
                                        probe_peer_id,
                                        ack,
                                    );
                                    let packet_len = packet.buf_len() as u64;
                                    if let Err(error) = sink.send(packet).await {
                                        tracing::warn!(
                                            ?error,
                                            "speed probe acknowledgement failed"
                                        );
                                    } else {
                                        control_metrics.record_tx(packet_len);
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    speed_metrics.record_failure("malformed");
                                    tracing::warn!(?error, "invalid speed probe packet");
                                }
                            }
                        } else if peer_mgr_hdr.packet_type == PacketType::SpeedProbeAck as u8 {
                            control_metrics.record_rx(buf_len);
                            match ProbeAck::decode(zc_packet.payload()) {
                                Ok(ack) => {
                                    let _ = speed_ack_sender.send(ack);
                                }
                                Err(error) => {
                                    speed_metrics.record_failure("malformed");
                                    tracing::warn!(?error, "invalid speed probe acknowledgement");
                                }
                            }
                        } else if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
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
                        } else if matches!(
                            peer_mgr_hdr.packet_type,
                            value if value == PacketType::NoiseHandshakeMsg1 as u8
                                || value == PacketType::NoiseHandshakeMsg2 as u8
                                || value == PacketType::NoiseHandshakeMsg3 as u8
                                || value == PacketType::NoiseHandshakeCommit as u8
                                || value == PacketType::NoiseHandshakeCommitAck as u8
                                || value == PacketType::NoiseHandshakeCommitDone as u8
                                || value == PacketType::NoiseHandshakeReady as u8
                                || value == PacketType::NoiseHandshakeReadyAck as u8
                                || value == PacketType::NoiseHandshakeReadyReceipt as u8
                                || value == PacketType::NoiseHandshakeReadyReceiptAck as u8
                        ) {
                            control_metrics.record_rx(buf_len);
                            tracing::debug!(
                                packet_type = peer_mgr_hdr.packet_type,
                                "drop duplicate direct handshake control packet"
                            );
                        } else {
                            data.try_push(zc_packet)
                                .expect("filtered peer receive vector remains bounded");
                        }
                    }

                    if !data.is_empty() {
                        let packets = data.len();
                        let bytes = data.buffer_byte_len();
                        let retained_bytes = data.retained_buffer_capacity();
                        if sender.send_batch(data).await.is_err() {
                            tracing::warn!(
                                packets,
                                bytes,
                                retained_bytes,
                                "peer receive loop could not admit a filtered batch"
                            );
                            break;
                        }
                    }

                    global_ctx.pace_receive(received_bytes as usize).await;
                    next_result = if let Some(first) = receive_queue.pop_front() {
                        Some(first)
                    } else if stream_ended {
                        None
                    } else {
                        stream.next().await
                    };
                }

                tracing::info!(
                    target: "CORE",
                    ?task_ret,
                    stream_ended,
                    "end recving peer conn packet"
                );

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
            self.receive_backpressure.clone(),
        );

        let close_event_notifier = self.close_event_notifier.clone();
        self.tasks.spawn(async move {
            pingpong.pingpong().await;
            // A silent transport can outlive the liveness task without ending its receive stream.
            close_event_notifier.notify_close();
            tracing::warn!(target: "CORE", ?pingpong, "pingpong task exit");
            Ok(())
        });
    }

    async fn pace_outbound_bulk(&self, packets: usize, bytes: usize) {
        let Some(pacer) = self.receiver_pacer.as_ref() else {
            return;
        };
        let started = crate::common::dataplane_telemetry::DataplaneTelemetry::sample_start();
        pacer.pace_bytes(bytes).await;
        self.global_ctx.dataplane_telemetry().record_stage_sample(
            DataplaneStage::ReceiverPacing,
            started,
            packets,
            bytes,
        );
    }

    fn prepare_outbound_transit(&self, msg: &mut ZCPacket) {
        let Some(header) = msg.peer_manager_header() else {
            return;
        };
        if !msg.transit_data && header.from_peer_id.get() == self.my_peer_id {
            return;
        }
        let is_data = if header.packet_type == PacketType::ForeignNetworkPacket as u8 {
            !header.is_foreign_control()
                && msg.foreign_network_inner_is_data().is_none_or(|data| data)
        } else {
            super::traffic_metrics::is_relay_data_packet_type(header.packet_type)
        };
        if !is_data {
            return;
        }
        let destination = header.to_peer_id.get();
        if msg.transit_network.is_none() {
            msg.transit_network = Some(
                self.transit_network
                    .get_or_init(|| Arc::from(self.get_network_identity().network_name))
                    .clone(),
            );
        }
        msg.transit_destination.get_or_insert(destination);
        msg.transit_data = true;
    }

    pub async fn send_msg(&self, mut msg: ZCPacket) -> Result<(), Error> {
        let paced_bytes = paced_packet_bytes(&msg);
        self.pace_outbound_bulk(usize::from(paced_bytes != 0), paced_bytes)
            .await;
        self.prepare_outbound_transit(&mut msg);
        Ok(self.sink.send(msg).await?)
    }

    pub(crate) fn supports_receiver_pacing(&self) -> bool {
        self.info.as_ref().is_some_and(|info| {
            info.features
                .iter()
                .any(|feature| feature == RECEIVER_PACING_FEATURE)
        })
    }

    pub(crate) fn supports_speed_routing(&self) -> bool {
        self.info.as_ref().is_some_and(|info| {
            info.features
                .iter()
                .any(|feature| feature == SPEED_ROUTING_FEATURE)
        })
    }

    pub(crate) fn fresh_speed_sample(&self, now: std::time::Instant) -> Option<SpeedSample> {
        self.speed_sample
            .read()
            .filter(|sample| sample.is_fresh(now))
            .as_ref()
            .copied()
    }

    fn store_speed_sample(&self, sample: SpeedSample) {
        let mut current = self.speed_sample.write();
        if current
            .as_ref()
            .is_none_or(|existing| sample.generation > existing.generation)
        {
            *current = Some(sample);
        }
    }

    pub(crate) async fn run_speed_probe(
        &self,
        generation: u64,
        reserved_bytes: u64,
        wire_packet_size: usize,
        interval: Duration,
    ) -> u64 {
        if self.is_closed() {
            return reserved_bytes;
        }
        let connection_info = self.get_conn_info();
        let speed_metrics = SpeedProbeMetrics::new(
            self.global_ctx.stats_manager().clone(),
            connection_info.network_name.clone(),
            self.get_peer_id(),
        );
        if let Some(sample) = self.fresh_speed_sample(std::time::Instant::now()) {
            speed_metrics.set_sample_age_ms(
                sample
                    .age(std::time::Instant::now())
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            );
        }
        if !self.supports_speed_routing() {
            speed_metrics.record_failure("unsupported_peer");
            return reserved_bytes;
        }
        if self
            .speed_probe_active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            speed_metrics.record_failure("busy");
            return reserved_bytes;
        }
        let _active_guard = ActiveSpeedProbeGuard(&self.speed_probe_active);
        let Ok((encoded_size, expected_packets, expected_bytes)) =
            probe_train_metadata(reserved_bytes, wire_packet_size, PEER_MANAGER_HEADER_SIZE)
        else {
            speed_metrics.record_failure("budget");
            return reserved_bytes;
        };
        if expected_packets == 0 {
            speed_metrics.record_failure("budget");
            return reserved_bytes;
        }

        let mut acknowledgements = self.speed_ack_sender.subscribe();
        let started_at = std::time::Instant::now();
        let send_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let receipt_challenge = match generate_receipt_challenge() {
            Ok(challenge) => challenge,
            Err(_) => {
                speed_metrics.record_failure("entropy");
                return reserved_bytes;
            }
        };
        let mut reservation = ProbeReservation::new(reserved_bytes, receipt_challenge, started_at);
        let network_name = self.get_conn_info().network_name;
        for sequence in 0..expected_packets {
            let final_marker = sequence + 1 == expected_packets;
            let payload = match (ProbeData {
                generation,
                sequence,
                expected_packets,
                expected_bytes,
                final_marker,
                receipt_challenge: if final_marker {
                    receipt_challenge
                } else {
                    [0_u8; 16]
                },
            })
            .encode_with_size(encoded_size)
            {
                Ok(payload) => payload,
                Err(_) => {
                    speed_metrics.record_failure("budget");
                    break;
                }
            };
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(
                self.my_peer_id,
                self.get_peer_id(),
                PacketType::SpeedProbe as u8,
            );
            packet
                .mut_peer_manager_header()
                .unwrap()
                .set_latency_first(true);
            let packet_len = packet.tunnel_payload().len() as u64;
            let metric_len = packet.buf_len() as u64;
            if !reservation.reserve_send(packet_len, std::time::Instant::now()) {
                speed_metrics.record_failure("budget");
                break;
            }
            let send = tokio::time::timeout_at(send_deadline, self.sink.send(packet)).await;
            match send {
                Ok(Ok(())) => {
                    reservation.commit_send(std::time::Instant::now());
                }
                Ok(Err(_)) => {
                    reservation.cancel_send();
                    speed_metrics.record_failure("send");
                    break;
                }
                Err(_) => {
                    reservation.cancel_send();
                    speed_metrics.record_failure("timeout");
                    break;
                }
            }
            if final_marker {
                reservation.mark_challenge_sent();
            }
            self.record_control_tx(&network_name, metric_len);
            speed_metrics.record_tx(metric_len);
        }

        if reservation.sent_bytes() >= (wire_packet_size as u64).saturating_mul(2) {
            let acknowledgement = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match acknowledgements.recv().await {
                        Ok(ack) if ack.generation == generation => {
                            return Some((ack, std::time::Instant::now()));
                        }
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            })
            .await
            .ok()
            .flatten();
            if let Some((ack, _completed_at)) = acknowledgement {
                if reservation.matches_ack(&ack) {
                    let ttl = speed_sample_ttl(interval);
                    self.store_speed_sample(SpeedSample::from_ack(
                        ack,
                        reservation.send_duration(),
                        std::time::Instant::now(),
                        ttl,
                    ));
                    speed_metrics.set_sample_age_ms(0);
                } else {
                    speed_metrics.record_failure("invalid_ack");
                }
            } else {
                speed_metrics.record_failure("timeout");
            }
        } else if reservation.sent_bytes() > 0 {
            speed_metrics.record_failure("incomplete");
        }

        reservation.unused_bytes()
    }

    pub async fn send_msg_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let mut batch = match batch.pop_singleton() {
            Ok(packet) => return self.send_msg(packet).await,
            Err(batch) => batch,
        };
        let paced_bytes = paced_batch_bytes(&batch);
        self.pace_outbound_bulk(batch.len(), paced_bytes).await;
        for packet in batch.iter_mut() {
            self.prepare_outbound_transit(packet);
        }
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
    pub(crate) fn inject_pending_recv_for_test(&self, packet: ZCPacket) {
        self.pending_recv.lock().push_back(packet);
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        let info = self.info.as_ref().unwrap();
        let now = std::time::Instant::now();
        let speed_sample = self.fresh_speed_sample(now);
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: info.features.clone(),
            tunnel: self.current_tunnel_info(),
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
            tx_delivery_bps: speed_sample.map(|sample| sample.delivery_bps),
            tx_loss_ppm: speed_sample.map(|sample| sample.loss_ppm),
            speed_sample_age_ms: speed_sample
                .map(|sample| u64::try_from(sample.age(now).as_millis()).unwrap_or(u64::MAX)),
            speed_probe_generation: speed_sample.map(|sample| sample.generation),
            speed_sample_ttl_ms: speed_sample
                .map(|sample| u64::try_from(sample.ttl.as_millis()).unwrap_or(u64::MAX)),
        }
    }

    pub fn get_peer_identity_type(&self) -> PeerIdentityType {
        self.noise_handshake_result
            .as_ref()
            .map(|x| x.peer_identity_type)
            .unwrap_or(PeerIdentityType::Admin)
    }

    pub(crate) fn origin_auth_tuple(&self) -> Option<(PeerIdentityType, Vec<u8>, SecureAuthLevel)> {
        let result = self.noise_handshake_result.as_ref()?;
        Some((
            result.peer_identity_type,
            result.remote_static_pubkey.clone(),
            result.secure_auth_level,
        ))
    }

    pub(crate) fn set_peer_identity_type(&mut self, identity_type: PeerIdentityType) {
        if let Some(result) = self.noise_handshake_result.as_mut() {
            result.peer_identity_type = identity_type;
        }
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        if self.info.is_some() {
            panic!("set_peer_id should only be called before handshake");
        }
        self.my_peer_id = peer_id;
        self.session_filter.set_my_peer_id(peer_id);
    }

    pub fn get_my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }
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

    use crate::common::global_ctx::GlobalCtx;
    use crate::common::global_ctx::tests::{get_mock_global_ctx, get_mock_global_ctx_with_network};
    use crate::common::new_peer_id;

    use crate::peers::create_packet_recv_chan;
    use crate::peers::recv_packet_from_chan;

    use crate::tunnel::ring::create_ring_tunnel_pair;

    async fn asymmetric_session_expiry_handshake(retained_by_client: bool) {
        let client_id = 1001;
        let server_id = 2002;
        let network = "asymmetric-session-expiry";
        let client_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network.into(),
            "test-only-secret".into(),
        )));
        let server_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network.into(),
            "test-only-secret".into(),
        )));
        set_secure_mode_cfg(&client_ctx, true);
        set_secure_mode_cfg(&server_ctx, true);
        let client_store = Arc::new(PeerSessionStore::new());
        let server_store = Arc::new(PeerSessionStore::new());
        let (ct, st) = create_ring_tunnel_pair();
        let mut client = PeerConn::new_with_peer_id_hint(
            client_id,
            client_ctx,
            ct,
            Some(server_id),
            client_store.clone(),
        );
        let mut server = PeerConn::new_with_peer_id_hint(
            server_id,
            server_ctx,
            st,
            Some(client_id),
            server_store.clone(),
        );
        let (store, remote, public_key) = if retained_by_client {
            (&client_store, server_id, server.get_keypair().unwrap().1)
        } else {
            (&server_store, client_id, client.get_keypair().unwrap().1)
        };
        // A closed connection can leave a cached session on one endpoint after
        // the other endpoint's idle eviction. No transition remains in doubt.
        let retained = Arc::new(crate::peers::peer_session::PeerSession::new(
            remote,
            crate::peers::peer_session::PeerSession::new_root_key(),
            1,
            0,
            "chacha20-poly1305".into(),
            "chacha20-poly1305".into(),
            Some(public_key.try_into().unwrap()),
        ));
        store.insert_session(SessionKey::new(network.into(), remote), retained.clone());
        let (c, s) = tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server()
        );
        assert!(
            c.is_ok() && s.is_ok(),
            "asymmetric idle eviction failed: client={c:?}, server={s:?}"
        );
        let a = client_store
            .get(&SessionKey::new(network.into(), server_id))
            .unwrap();
        let b = server_store
            .get(&SessionKey::new(network.into(), client_id))
            .unwrap();
        assert_eq!(a.root_key(), b.root_key());
        assert_eq!(a.session_generation(), b.session_generation());
        assert!(a.is_valid() && b.is_valid());
    }

    #[tokio::test]
    async fn asymmetric_session_expiry_recovers_when_responder_forgot() {
        asymmetric_session_expiry_handshake(true).await;
    }

    #[tokio::test]
    async fn asymmetric_session_expiry_recovers_when_initiator_forgot() {
        asymmetric_session_expiry_handshake(false).await;
    }

    #[tokio::test]
    async fn asymmetric_session_expiry_reconnects_after_real_handshake_and_delivers_data() {
        for retained_by_client in [false, true] {
            for known_peer in [false, true] {
                let client_id = 901;
                let server_id = 902;
                let network = "real-session-cache-expiry";
                let client_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                    network.into(),
                    "test-cache-secret".into(),
                )));
                let server_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                    network.into(),
                    "test-cache-secret".into(),
                )));
                set_secure_mode_cfg(&client_ctx, true);
                set_secure_mode_cfg(&server_ctx, true);
                let client_store = Arc::new(PeerSessionStore::new());
                let server_store = Arc::new(PeerSessionStore::new());
                let (ct, st) = create_ring_tunnel_pair();
                let mut client = PeerConn::new_with_peer_id_hint(
                    client_id,
                    client_ctx.clone(),
                    ct,
                    None,
                    client_store.clone(),
                );
                let mut server = PeerConn::new_with_peer_id_hint(
                    server_id,
                    server_ctx.clone(),
                    st,
                    None,
                    server_store.clone(),
                );
                let client_key: [u8; 32] = client.get_keypair().unwrap().1.try_into().unwrap();
                let server_key: [u8; 32] = server.get_keypair().unwrap().1.try_into().unwrap();
                let (c, s) = tokio::join!(
                    client.do_handshake_as_client(),
                    server.do_handshake_as_server()
                );
                assert!(c.is_ok() && s.is_ok(), "initial handshake: {c:?} {s:?}");
                drop((client, server));
                let ck = SessionKey::new(network.into(), server_id);
                let sk = SessionKey::new(network.into(), client_id);
                if retained_by_client {
                    assert!(server_store.clear_peer_records_if_static_key_matches(&sk, client_key));
                    assert!(server_store.peek(&sk).is_none());
                    assert!(client_store.peek(&ck).is_some());
                } else {
                    assert!(client_store.clear_peer_records_if_static_key_matches(&ck, server_key));
                    assert!(client_store.peek(&ck).is_none());
                    assert!(server_store.peek(&sk).is_some());
                }
                let (ct, st) = create_ring_tunnel_pair();
                let mut client = PeerConn::new_with_peer_id_hint(
                    client_id,
                    client_ctx,
                    ct,
                    known_peer.then_some(server_id),
                    client_store.clone(),
                );
                let mut server = PeerConn::new_with_peer_id_hint(
                    server_id,
                    server_ctx,
                    st,
                    None,
                    server_store.clone(),
                );
                let (c, s) = tokio::join!(
                    client.do_handshake_as_client(),
                    server.do_handshake_as_server()
                );
                assert!(
                    c.is_ok() && s.is_ok(),
                    "reconnect retained_client={retained_by_client} hinted={known_peer}: {c:?} {s:?}"
                );
                let (client_tx, mut client_rx) = create_packet_recv_chan();
                let (server_tx, mut server_rx) = create_packet_recv_chan();
                client.start_recv_loop(client_tx).await;
                server.start_recv_loop(server_tx).await;
                for (sender, receiver, from, to) in [
                    (&client, &mut server_rx, client_id, server_id),
                    (&server, &mut client_rx, server_id, client_id),
                ] {
                    let mut packet =
                        ZCPacket::new_with_payload(b"authenticated post-expiry payload");
                    packet.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
                    sender.send_msg(packet).await.unwrap();
                    let received = tokio::time::timeout(
                        Duration::from_secs(2),
                        recv_packet_from_chan(receiver),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!(received.payload(), b"authenticated post-expiry payload");
                }
                let a = client_store.get(&ck).unwrap();
                let b = server_store.get(&sk).unwrap();
                assert_eq!(a.root_key(), b.root_key());
                assert!(a.is_valid() && b.is_valid());
            }
        }
    }

    #[test]
    fn rejects_an_unknown_peer_encryption_algorithm() {
        assert!(validate_encryption_algorithm("chacha20-poly1305").is_ok());
        assert!(validate_encryption_algorithm("unknown-cipher").is_err());
    }

    #[test]
    fn wss_uses_the_quic_tls_exporter_data_protection_path() {
        let binding = TransportBinding {
            kind: TransportBindingKind::WssTlsExporterV1,
            bytes: [7; 32],
        };
        assert!(validate_transport_binding(Some("wss"), None).is_err());
        assert!(validate_transport_binding(Some("wss"), Some(binding)).is_ok());
        assert!(validate_transport_binding(Some("ws"), Some(binding)).is_err());
        assert!(validate_transport_binding(Some("ws"), None).is_ok());
        assert_eq!(transport_binding_context(Some(binding)).0, 2);
        assert_eq!(
            transport_binding_context(Some(TransportBinding {
                kind: TransportBindingKind::QuicTlsExporterV1,
                bytes: [7; 32],
            }))
            .0,
            1
        );
        {
            let tcp_binding = TransportBinding {
                kind: TransportBindingKind::Http2TlsExporterV1,
                bytes: [9; 32],
            };
            assert!(validate_transport_binding(Some("tcp"), Some(tcp_binding)).is_ok());
            assert_eq!(transport_binding_context(Some(tcp_binding)).0, 3);
        }
        for enabled in [false, true] {
            let filter = PeerSessionTunnelFilter::new_with_peer(1, enabled);
            let mut packet = test_packet(PacketType::Pong as u8);
            let session = uuid::Uuid::new_v4();
            assert!(packet.set_authenticated_peer_id(2));
            assert!(packet.set_authenticated_peer_identity_type(PeerIdentityType::Admin));
            assert!(
                packet.set_authenticated_peer_secure_auth_level(
                    SecureAuthLevel::NetworkSecretConfirmed
                )
            );
            assert!(packet.set_authenticated_session_id(session));
            assert!(packet.set_verified_origin(
                2,
                PeerIdentityType::Admin,
                SecureAuthLevel::NetworkSecretConfirmed,
                session,
            ));
            let scalar = filter.before_send(packet.clone()).unwrap();
            let batch = filter
                .before_send_batch(PacketBatch::singleton(packet))
                .unwrap();
            for outbound in [&scalar, &batch[0]] {
                assert_eq!(outbound.authenticated_peer_id(), None);
                assert_eq!(outbound.authenticated_peer_identity_type(), None);
                assert_eq!(outbound.authenticated_peer_secure_auth_level(), None);
                assert_eq!(outbound.authenticated_session_id(), None);
                assert_eq!(outbound.verified_origin_peer_id(), None);
                assert_eq!(outbound.verified_origin_peer_identity_type(), None);
                assert_eq!(outbound.verified_origin_peer_secure_auth_level(), None);
                assert_eq!(outbound.verified_origin_session_id(), None);
                assert_eq!(
                    outbound.payload(),
                    test_packet(PacketType::Pong as u8).payload()
                );
            }
        }
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
                ..Default::default()
            }));
        }
    }

    fn test_packet(packet_type: u8) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&[0u8; 32]);
        packet.fill_peer_manager_hdr(1, 2, packet_type);
        packet
    }

    #[tokio::test]
    async fn server_handshake_ignores_a_leading_non_handshake_packet() {
        let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
        let sessions = Arc::new(PeerSessionStore::new());
        let mut client = PeerConn::new(
            new_peer_id(),
            get_mock_global_ctx(),
            client_tunnel,
            sessions.clone(),
        );
        let mut server = PeerConn::new(
            new_peer_id(),
            get_mock_global_ctx(),
            server_tunnel,
            sessions,
        );
        server.inject_pending_recv_for_test(test_packet(PacketType::Data as u8));
        server.inject_pending_recv_for_test(test_packet(83));
        let (client_result, server_result) = tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server()
        );
        assert!(
            client_result.is_ok(),
            "client handshake failed: {client_result:?}"
        );
        match server_result {
            Ok(()) => {}
            Err(Error::WaitRespError(message)) => {
                assert!(
                    !message.contains("unexpected packet type during handshake"),
                    "server handshake failed on a leading non-handshake packet: {message}"
                );
                panic!("server handshake failed: {message}");
            }
            Err(error) => panic!("server handshake failed: {error:?}"),
        }
    }
}
