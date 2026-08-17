use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;
use prost::Message;
use quanta::Instant;
use rayon::prelude::*;
use snow::{TransportState, params::NoiseParams};
use smallvec::SmallVec;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, oneshot};
use tokio::time::{Duration, timeout};

use crate::peers::{PacketRecvChan, foreign_network_client::ForeignNetworkClient};
use crate::{
    common::error::Error,
    common::{PeerId, global_ctx::ArcGlobalCtx, shrink_dashmap},
    peers::flow::{classify_packet_flow, stamp_critical_l2_control, stamp_packet_flow},
    peers::peer_manager::PeerManager,
    peers::peer_map::{
        OriginAuthCapability, OriginAuthEntry, OriginAuthGrant, OriginAuthSnapshot, PeerMap,
        PeerMapDataPlaneDescriptor,
    },
    peers::peer_session::{
        INITIATOR_RECOVERY_LIFETIME, InitiatorSessionReservation, InitiatorTransitionIdentity,
        PeerSession, PeerSessionAction, PeerSessionStore, SessionKey,
    },
    peers::route_trait::NextHopPolicy,
    peers::traffic_metrics::AggregateTrafficMetrics,
    proto::peer_rpc::{
        PeerConnNoiseRecoveryPb, PeerConnSessionActionPb, PeerIdentityType, RelayNoiseMsg1Pb,
        RelayNoiseMsg2Pb, SecureAuthLevel,
    },
    tunnel::{
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, parallel_crypto_enabled},
        packet_def::{PEER_MANAGER_STABLE_AUTH_DATA_SIZE, PacketType, ZCPacket},
    },
};

const RELAY_NOISE_VERSION: u32 = 2;
const RELAY_NOISE_PROLOGUE: &[u8] = b"lowertier-relay-noise";

fn validate_relay_protocol_version(version: u32) -> Result<(), Error> {
    if version == RELAY_NOISE_VERSION {
        return Ok(());
    }
    Err(Error::RouteError(Some(format!(
        "unsupported relay protocol version: {version}"
    ))))
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
        .map_err(|_| Error::RouteError(Some("invalid relay recovery action".to_string())))?;
    let action = match action {
        PeerConnSessionActionPb::Join => PeerSessionAction::Join,
        PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
        PeerConnSessionActionPb::Create => PeerSessionAction::Create,
    };
    let session_metadata_id = pb.session_metadata_id.ok_or_else(|| {
        Error::RouteError(Some("relay recovery metadata id is missing".to_string()))
    })?;
    if pb.root_key_digest.len() != 32
        || pb.transition_id.len() != RELAY_TRANSITION_ID_SIZE
        || pb.transition_id.iter().all(|byte| *byte == 0)
    {
        return Err(Error::RouteError(Some(
            "invalid relay recovery identity".to_string(),
        )));
    }
    let mut root_key_digest = [0_u8; 32];
    root_key_digest.copy_from_slice(&pb.root_key_digest);
    let mut transition_id = [0_u8; 16];
    transition_id.copy_from_slice(&pb.transition_id);
    Ok(InitiatorTransitionIdentity::new(
        session_key,
        uuid::Uuid::from(session_metadata_id),
        action,
        pb.session_generation,
        pb.initial_epoch,
        transition_id,
        root_key_digest,
    ))
}

fn transition_id_from_wire(bytes: &[u8]) -> Result<[u8; RELAY_TRANSITION_ID_SIZE], Error> {
    if bytes.len() != RELAY_TRANSITION_ID_SIZE || bytes.iter().all(|byte| *byte == 0) {
        return Err(Error::RouteError(Some(
            "invalid relay transition id".to_string(),
        )));
    }
    let mut transition_id = [0_u8; RELAY_TRANSITION_ID_SIZE];
    transition_id.copy_from_slice(bytes);
    Ok(transition_id)
}

fn recovery_identity_matches_wire(
    local: &InitiatorTransitionIdentity,
    wire: &InitiatorTransitionIdentity,
) -> bool {
    local.session_key == wire.session_key
        && local.session_metadata_id == wire.session_metadata_id
        && local.action == wire.action
        && local.session_generation == wire.session_generation
        && local.initial_epoch == wire.initial_epoch
        && local.transition_id == wire.transition_id
        && local.root_key_digest == wire.root_key_digest
}

fn encode_reset_identity(identity: &InitiatorTransitionIdentity) -> Vec<u8> {
    recovery_pb_from_identity(identity).encode_to_vec()
}

fn decode_reset_identity(
    payload: &[u8],
    session_key: SessionKey,
) -> Result<InitiatorTransitionIdentity, Error> {
    let recovery = PeerConnNoiseRecoveryPb::decode(payload).map_err(|error| {
        Error::RouteError(Some(format!("decode relay reset identity failed: {error}")))
    })?;
    recovery_identity_from_pb(recovery, session_key)
}

const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const HANDSHAKE_RETRY_BASE_MS: u64 = 200;
const HANDSHAKE_MAX_ATTEMPTS: u32 = 3;
const HANDSHAKE_CONFIRM_RETRY_MS: u64 = 200;
const HANDSHAKE_CONFIRM_RETRY_MAX_MS: u64 = 5_000;
const HANDSHAKE_CONFIRM_MAX_ATTEMPTS: u32 = 8;
const MAX_PENDING_PACKETS_PER_PEER: usize = 32;
const RELAY_QUEUE_PACKET_OVERHEAD: usize = 128;
const RELAY_QUEUE_MAX_BYTES_PER_PEER: usize = 256 * 1024;
const RELAY_QUEUE_MAX_BYTES_GLOBAL: usize = 1024 * 1024;
const RELAY_QUEUE_MAX_PACKETS_GLOBAL: usize = 4096;
static RELAY_QUEUE_GLOBAL_BYTES: AtomicUsize = AtomicUsize::new(0);
static RELAY_QUEUE_GLOBAL_PACKETS: AtomicUsize = AtomicUsize::new(0);
const MAX_COMPLETED_HANDSHAKES_PER_PEER: usize = 64;
const RESPONDER_CONFIRM_DEADLINE_MS: u64 = HANDSHAKE_TIMEOUT_SECS * 1_000;
const RELAY_CONFIRM_WINDOW_MS: u64 = 21_200;
const RELAY_FLUSH_RETRY_MAX_ATTEMPTS: u32 = 8;
const RELAY_HANDSHAKE_ID_SIZE: usize = 16;
const RELAY_TRANSITION_ID_SIZE: usize = 16;
const RELAY_CONFIRMATION_PAYLOAD_SIZE: usize = RELAY_HANDSHAKE_ID_SIZE + RELAY_TRANSITION_ID_SIZE;
const RELAY_READY_RECEIPT_PAYLOAD_SIZE: usize =
    RELAY_HANDSHAKE_ID_SIZE + RELAY_HANDSHAKE_ID_SIZE + RELAY_TRANSITION_ID_SIZE + 1 + 4 + 4;
const RELAY_ORIGIN_PROOF_MAGIC: [u8; 4] = *b"LRP1";
const RELAY_ORIGIN_PROOF_AUTH_DATA_SIZE: usize = PEER_MANAGER_STABLE_AUTH_DATA_SIZE - 4;
const RELAY_ORIGIN_PROOF_SIZE: usize =
    RELAY_ORIGIN_PROOF_MAGIC.len() + RELAY_ORIGIN_PROOF_AUTH_DATA_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayReadyReceiptIdentity {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    session_metadata_id: uuid::Uuid,
    transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
    action: PeerSessionAction,
    session_generation: u32,
    initial_epoch: u32,
}

fn relay_action_to_wire(action: PeerSessionAction) -> u8 {
    match action {
        PeerSessionAction::Join => 0,
        PeerSessionAction::Sync => 1,
        PeerSessionAction::Create => 2,
    }
}

fn relay_action_from_wire(value: u8) -> Result<PeerSessionAction, Error> {
    match value {
        0 => Ok(PeerSessionAction::Join),
        1 => Ok(PeerSessionAction::Sync),
        2 => Ok(PeerSessionAction::Create),
        _ => Err(Error::RouteError(Some(
            "invalid relay receipt session action".to_string(),
        ))),
    }
}

fn encode_relay_ready_receipt(
    identity: RelayReadyReceiptIdentity,
) -> [u8; RELAY_READY_RECEIPT_PAYLOAD_SIZE] {
    let mut payload = [0_u8; RELAY_READY_RECEIPT_PAYLOAD_SIZE];
    let mut offset = 0;
    payload[offset..offset + RELAY_HANDSHAKE_ID_SIZE].copy_from_slice(&identity.handshake_id);
    offset += RELAY_HANDSHAKE_ID_SIZE;
    payload[offset..offset + RELAY_HANDSHAKE_ID_SIZE]
        .copy_from_slice(identity.session_metadata_id.as_bytes());
    offset += RELAY_HANDSHAKE_ID_SIZE;
    payload[offset..offset + RELAY_TRANSITION_ID_SIZE].copy_from_slice(&identity.transition_id);
    offset += RELAY_TRANSITION_ID_SIZE;
    payload[offset] = relay_action_to_wire(identity.action);
    offset += 1;
    payload[offset..offset + 4].copy_from_slice(&identity.session_generation.to_be_bytes());
    offset += 4;
    payload[offset..offset + 4].copy_from_slice(&identity.initial_epoch.to_be_bytes());
    payload
}

fn decode_relay_ready_receipt(payload: &[u8]) -> Result<RelayReadyReceiptIdentity, Error> {
    if payload.len() != RELAY_READY_RECEIPT_PAYLOAD_SIZE {
        return Err(Error::RouteError(Some(
            "invalid relay ready receipt payload".to_string(),
        )));
    }
    let mut offset = 0;
    let handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE] = payload
        [offset..offset + RELAY_HANDSHAKE_ID_SIZE]
        .try_into()
        .expect("the receipt payload length was checked");
    offset += RELAY_HANDSHAKE_ID_SIZE;
    let session_metadata_id = uuid::Uuid::from_bytes(
        payload[offset..offset + RELAY_HANDSHAKE_ID_SIZE]
            .try_into()
            .expect("the receipt payload length was checked"),
    );
    offset += RELAY_HANDSHAKE_ID_SIZE;
    let transition_id: [u8; RELAY_TRANSITION_ID_SIZE] = payload
        [offset..offset + RELAY_TRANSITION_ID_SIZE]
        .try_into()
        .expect("the receipt payload length was checked");
    if transition_id.iter().all(|byte| *byte == 0) {
        return Err(Error::RouteError(Some(
            "invalid relay ready receipt transition id".to_string(),
        )));
    }
    offset += RELAY_TRANSITION_ID_SIZE;
    let action = relay_action_from_wire(payload[offset])?;
    offset += 1;
    let session_generation = u32::from_be_bytes(
        payload[offset..offset + 4]
            .try_into()
            .expect("the receipt payload length was checked"),
    );
    offset += 4;
    let initial_epoch = u32::from_be_bytes(
        payload[offset..offset + 4]
            .try_into()
            .expect("the receipt payload length was checked"),
    );
    Ok(RelayReadyReceiptIdentity {
        handshake_id,
        session_metadata_id,
        transition_id,
        action,
        session_generation,
        initial_epoch,
    })
}

pub(crate) fn attach_relay_origin_proof(packet: &mut ZCPacket) -> anyhow::Result<()> {
    stamp_critical_l2_control(packet);
    stamp_packet_flow(packet);
    let header = packet
        .peer_manager_header()
        .ok_or_else(|| anyhow::anyhow!("relay packet has no peer header"))?;
    let stable_auth_data = header.stable_auth_data();
    let mut proof = [0_u8; RELAY_ORIGIN_PROOF_SIZE];
    proof[..4].copy_from_slice(&RELAY_ORIGIN_PROOF_MAGIC);
    proof[4..].copy_from_slice(&stable_auth_data[4..]);
    packet
        .append_payload_preserving_flow_hash(&proof)
        .map_err(|error| anyhow::anyhow!(error))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayBatchDecryptOutcome {
    NotAttempted,
    Decrypted,
    Failed,
}

fn verify_and_remove_relay_origin_proof(packet: &mut ZCPacket) -> anyhow::Result<()> {
    let payload = packet.payload();
    anyhow::ensure!(
        payload.len() >= RELAY_ORIGIN_PROOF_SIZE,
        "relay origin proof is missing"
    );
    let proof: [u8; RELAY_ORIGIN_PROOF_SIZE] = payload[payload.len() - RELAY_ORIGIN_PROOF_SIZE..]
        .try_into()
        .expect("the relay proof length was checked");
    anyhow::ensure!(
        proof[..4] == RELAY_ORIGIN_PROOF_MAGIC,
        "invalid relay proof"
    );
    let header = packet
        .peer_manager_header()
        .ok_or_else(|| anyhow::anyhow!("relay packet has no peer header"))?
        .clone();
    let stable_auth_data = header.stable_auth_data();
    anyhow::ensure!(
        proof[4..] == stable_auth_data[4..],
        "relay origin proof does not match the packet header"
    );
    packet
        .remove_payload_suffix_preserving_flow_hash(RELAY_ORIGIN_PROOF_SIZE)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(())
}

#[derive(Clone)]
pub struct RelayPeerState {
    pub last_active_at: Instant,
    pub failure_count: u32,
    pub next_retry_at: Option<Instant>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelaySendPhase {
    AwaitingSession = 0,
    Confirming = 1,
    Draining = 2,
    Ready = 3,
}

impl RelaySendPhase {
    fn from_atomic(value: u8) -> Self {
        match value {
            1 => Self::Confirming,
            2 => Self::Draining,
            3 => Self::Ready,
            _ => Self::AwaitingSession,
        }
    }
}

struct RelayQueue {
    packets: VecDeque<RelayQueuedPacket>,
    in_flight: usize,
    in_flight_bytes: usize,
}

/// Immutable authority captured before a complete Ethernet packet enters a relay path.
///
/// The descriptor carries the source token, authentication generation, route trust
/// generation, forwarding generation, exact origin entry, and exact bridge grant.
/// The destination is part of the token and cannot change while the packet waits.
#[derive(Clone)]
pub(crate) struct FullEthernetAuthorizationToken {
    descriptor: Arc<PeerMapDataPlaneDescriptor>,
    destination_peer_id: PeerId,
}

impl FullEthernetAuthorizationToken {
    pub(crate) fn from_descriptor(
        descriptor: &PeerMapDataPlaneDescriptor,
        destination_peer_id: PeerId,
    ) -> Self {
        Self {
            descriptor: Arc::new(descriptor.clone()),
            destination_peer_id,
        }
    }

    pub(crate) fn destination_peer_id(&self) -> PeerId {
        self.destination_peer_id
    }

    pub(crate) fn is_current(&self, peer_map: &PeerMap, global_ctx: &ArcGlobalCtx) -> bool {
        let current = peer_map.dataplane_descriptor();
        PeerManager::full_ethernet_descriptor_is_current_for_destination(
            self.descriptor.as_ref(),
            current.as_ref(),
            self.destination_peer_id,
            peer_map.my_peer_id(),
            global_ctx,
        )
    }
}

type RelayQueuedPacket = (
    ZCPacket,
    NextHopPolicy,
    usize,
    Option<FullEthernetAuthorizationToken>,
);
type RelayReadyPacket = (
    ZCPacket,
    NextHopPolicy,
    Option<FullEthernetAuthorizationToken>,
);

struct RelaySendState {
    phase: AtomicU8,
    closed: AtomicBool,
    queue: StdMutex<RelayQueue>,
    draining: Mutex<()>,
    retry_scheduled: AtomicBool,
    retry_attempt: AtomicU32,
    confirmation: StdMutex<Option<RelayConfirmationIdentity>>,
    queued_bytes: AtomicUsize,
    process_memory: Arc<crate::common::global_ctx::ProcessMemoryGovernor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayConfirmationIdentity {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    session_id: uuid::Uuid,
    transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
}

enum EnqueueResult {
    Queued,
    Ready,
}

enum EnqueueBatchResult {
    Queued,
    Ready(Vec<RelayReadyPacket>),
}

impl RelaySendState {
    fn new(phase: RelaySendPhase) -> Self {
        Self::new_with_governor(
            phase,
            Arc::new(
                crate::common::global_ctx::ProcessMemoryGovernor::with_limit(
                    RELAY_QUEUE_MAX_BYTES_GLOBAL,
                ),
            ),
        )
    }

    fn new_with_governor(
        phase: RelaySendPhase,
        process_memory: Arc<crate::common::global_ctx::ProcessMemoryGovernor>,
    ) -> Self {
        Self {
            phase: AtomicU8::new(phase as u8),
            closed: AtomicBool::new(false),
            queue: StdMutex::new(RelayQueue {
                packets: VecDeque::new(),
                in_flight: 0,
                in_flight_bytes: 0,
            }),
            draining: Mutex::new(()),
            retry_scheduled: AtomicBool::new(false),
            retry_attempt: AtomicU32::new(0),
            confirmation: StdMutex::new(None),
            queued_bytes: AtomicUsize::new(0),
            process_memory,
        }
    }

    fn charge(&self, bytes: usize, packets: usize) -> bool {
        let Some(_) = self
            .queued_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= RELAY_QUEUE_MAX_BYTES_PER_PEER)
            })
            .ok()
        else {
            return false;
        };
        if !self.process_memory.reserve(bytes) {
            self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        }
        let global_bytes =
            RELAY_QUEUE_GLOBAL_BYTES.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= RELAY_QUEUE_MAX_BYTES_GLOBAL)
            });
        if global_bytes.is_err() {
            self.process_memory.release(bytes);
            self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        }
        let global_packets =
            RELAY_QUEUE_GLOBAL_PACKETS.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(packets)
                    .filter(|next| *next <= RELAY_QUEUE_MAX_PACKETS_GLOBAL)
            });
        if global_packets.is_err() {
            self.process_memory.release(bytes);
            RELAY_QUEUE_GLOBAL_BYTES.fetch_sub(bytes, Ordering::AcqRel);
            self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        }
        true
    }

    fn release(&self, bytes: usize, packets: usize) {
        self.process_memory.release(bytes);
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
        RELAY_QUEUE_GLOBAL_BYTES.fetch_sub(bytes, Ordering::AcqRel);
        RELAY_QUEUE_GLOBAL_PACKETS.fetch_sub(packets, Ordering::AcqRel);
    }

    fn phase(&self) -> RelaySendPhase {
        RelaySendPhase::from_atomic(self.phase.load(Ordering::Acquire))
    }

    fn set_phase(&self, phase: RelaySendPhase) {
        let _queue = self.queue.lock().unwrap();
        self.phase.store(phase as u8, Ordering::Release);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.phase
            .store(RelaySendPhase::AwaitingSession as u8, Ordering::Release);
        let mut queue = self.queue.lock().unwrap();
        let released_bytes = queue
            .packets
            .iter()
            .map(|(_, _, bytes, _)| *bytes)
            .sum::<usize>()
            .saturating_add(queue.in_flight_bytes);
        let released_packets = queue.packets.len().saturating_add(queue.in_flight);
        queue.packets.clear();
        queue.in_flight = 0;
        queue.in_flight_bytes = 0;
        drop(queue);
        self.release(released_bytes, released_packets);
    }

    fn set_confirmation(&self, identity: RelayConfirmationIdentity) {
        *self.confirmation.lock().unwrap() = Some(identity);
        self.set_phase(RelaySendPhase::Confirming);
    }

    fn clear_confirmation(&self, identity: RelayConfirmationIdentity) -> bool {
        let mut confirmation = self.confirmation.lock().unwrap();
        if confirmation.as_ref() != Some(&identity) {
            return false;
        }
        *confirmation = None;
        true
    }

    fn enqueue(
        &self,
        packet: ZCPacket,
        policy: NextHopPolicy,
        authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<EnqueueResult, Error> {
        let mut queue = self.queue.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::RouteError(Some(
                "relay peer state is closed".to_string(),
            )));
        }
        if self.phase() == RelaySendPhase::Ready {
            return Ok(EnqueueResult::Ready);
        }
        if queue.packets.len() + queue.in_flight >= MAX_PENDING_PACKETS_PER_PEER {
            return Err(Error::RouteError(Some(
                "secure relay queue is full for peer".to_string(),
            )));
        }
        let charge = packet.buf_len().saturating_add(RELAY_QUEUE_PACKET_OVERHEAD);
        if !self.charge(charge, 1) {
            return Err(Error::RouteError(Some(
                "secure relay queue byte budget is full".to_string(),
            )));
        }
        queue
            .packets
            .push_back((packet, policy, charge, authorization));
        Ok(EnqueueResult::Queued)
    }

    fn enqueue_batch(
        &self,
        packets: impl IntoIterator<Item = RelayReadyPacket>,
    ) -> Result<EnqueueBatchResult, Error> {
        let packets = packets.into_iter().collect::<Vec<_>>();
        let mut queue = self.queue.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::RouteError(Some(
                "relay peer state is closed".to_string(),
            )));
        }
        if self.phase() == RelaySendPhase::Ready {
            return Ok(EnqueueBatchResult::Ready(packets));
        }
        if queue.packets.len() + queue.in_flight + packets.len() > MAX_PENDING_PACKETS_PER_PEER {
            return Err(Error::RouteError(Some(
                "secure relay queue is full for peer".to_string(),
            )));
        }
        let packets = packets
            .into_iter()
            .map(|(packet, policy, authorization)| {
                let charge = packet.buf_len().saturating_add(RELAY_QUEUE_PACKET_OVERHEAD);
                (packet, policy, charge, authorization)
            })
            .collect::<Vec<_>>();
        let bytes = packets.iter().map(|(_, _, bytes, _)| *bytes).sum::<usize>();
        if !self.charge(bytes, packets.len()) {
            return Err(Error::RouteError(Some(
                "secure relay queue byte budget is full".to_string(),
            )));
        }
        queue.packets.extend(packets);
        Ok(EnqueueBatchResult::Queued)
    }

    fn pop_batch_for_send(&self, max_packets: usize) -> Option<Vec<RelayQueuedPacket>> {
        let mut queue = self.queue.lock().unwrap();
        let first_policy = queue.packets.front()?.1.clone();
        let mut packets = Vec::with_capacity(max_packets);
        while packets.len() < max_packets {
            let Some((_, policy, _, _)) = queue.packets.front() else {
                break;
            };
            if *policy != first_policy {
                break;
            }
            let packet = queue
                .packets
                .pop_front()
                .expect("the queue front was checked");
            queue.in_flight_bytes = queue.in_flight_bytes.saturating_add(packet.2);
            queue.in_flight = queue.in_flight.saturating_add(1);
            packets.push(packet);
        }
        Some(packets)
    }

    fn complete_send_batch(&self, bytes: usize, packets: usize) {
        let mut queue = self.queue.lock().unwrap();
        let completed = packets.min(queue.in_flight);
        queue.in_flight = queue.in_flight.saturating_sub(completed);
        queue.in_flight_bytes = queue.in_flight_bytes.saturating_sub(bytes);
        drop(queue);
        self.release(bytes, completed);
    }

    fn requeue_failed_batch(&self, packets: Vec<RelayQueuedPacket>) {
        let mut queue = self.queue.lock().unwrap();
        let count = packets.len().min(queue.in_flight);
        let bytes = packets
            .iter()
            .take(count)
            .map(|(_, _, bytes, _)| *bytes)
            .sum::<usize>();
        queue.in_flight = queue.in_flight.saturating_sub(count);
        queue.in_flight_bytes = queue.in_flight_bytes.saturating_sub(bytes);
        let mut released_bytes: usize = 0;
        let mut released_packets = 0;
        for packet in packets.into_iter().rev() {
            if queue.packets.len() < MAX_PENDING_PACKETS_PER_PEER {
                queue.packets.push_front(packet);
            } else {
                released_bytes = released_bytes.saturating_add(packet.2);
                released_packets += 1;
            }
        }
        drop(queue);
        if released_packets != 0 {
            self.release(released_bytes, released_packets);
        }
    }

    fn is_empty(&self) -> bool {
        let queue = self.queue.lock().unwrap();
        queue.packets.is_empty() && queue.in_flight == 0
    }

    fn finish_draining(&self) -> bool {
        let queue = self.queue.lock().unwrap();
        if !queue.packets.is_empty() || queue.in_flight != 0 {
            return false;
        }
        self.phase
            .store(RelaySendPhase::Ready as u8, Ordering::Release);
        true
    }

    fn packet_count(&self) -> usize {
        let queue = self.queue.lock().unwrap();
        queue.packets.len() + queue.in_flight
    }

    fn set_in_flight_for_test(&self, value: bool) {
        let mut queue = self.queue.lock().unwrap();
        queue.in_flight = usize::from(value);
    }
}

impl Drop for RelaySendState {
    fn drop(&mut self) {
        self.close();
    }
}

impl Default for RelayPeerState {
    fn default() -> Self {
        Self {
            last_active_at: Instant::now(),
            failure_count: 0,
            next_retry_at: None,
        }
    }
}

pub struct RelayPeerMap {
    peer_map: Arc<PeerMap>,
    foreign_network_client: Option<Arc<ForeignNetworkClient>>,
    foreign_relay_transport: Option<ForeignRelayTransport>,
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_session_store: Arc<PeerSessionStore>,
    states: DashMap<PeerId, RelayPeerState>,
    pending_handshakes: DashMap<PeerId, PendingHandshake>,
    deferred_handshakes: DashMap<PeerId, (ZCPacket, [u8; RELAY_HANDSHAKE_ID_SIZE])>,
    handshake_locks: DashMap<PeerId, Arc<Mutex<()>>>,
    responder_handshake_locks: DashMap<PeerId, Arc<Mutex<()>>>,
    send_states: DashMap<PeerId, Arc<RelaySendState>>,
    pending_responder_handshake_acks: DashMap<PeerId, PendingResponderHandshake>,
    pending_responder_resets: DashMap<PeerId, PendingResponderReset>,
    pending_reset_acks: DashMap<PeerId, PendingResetAck>,
    completed_responder_handshakes: DashMap<PeerId, VecDeque<CompletedRelayHandshake>>,
    pending_confirmation_acks: DashMap<PeerId, PendingConfirmationAck>,
    pending_ready_receipts: DashMap<PeerId, PendingReadyReceipt>,
    completed_ready_receipts: DashMap<PeerId, VecDeque<CompletedReadyReceipt>>,
    relay_session_auth: DashMap<PeerId, RelaySessionAuthBinding>,

    control_metrics: AggregateTrafficMetrics,
}

struct PendingHandshake {
    response_tx: std::sync::Mutex<Option<oneshot::Sender<ZCPacket>>>,
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    payload: Vec<u8>,
    policy: NextHopPolicy,
}

struct PendingConfirmationAck {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    session_id: uuid::Uuid,
    transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
    expected_packet_type: u8,
    transition_identity: InitiatorTransitionIdentity,
    previous_receipt_identity: Option<InitiatorTransitionIdentity>,
    expires_at: Instant,
    /// The staged initiator session remains private until READY-ACK.
    ///
    /// It is used only to decrypt matching confirmation control packets.
    session: Arc<PeerSession>,
    notify: Arc<Notify>,
    outcome: Arc<AtomicU8>,
}

#[derive(Clone)]
struct PendingReadyReceipt {
    identity: RelayReadyReceiptIdentity,
    session: Arc<PeerSession>,
    expires_at: Instant,
    notify: Arc<Notify>,
    outcome: Arc<AtomicU8>,
    owner_running: Arc<AtomicBool>,
}

struct PendingResponderHandshake {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    response: Vec<u8>,
    prepared: crate::peers::peer_session::UpsertResponderSessionReturn,
    recovery_active: bool,
    transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
    deadline: Instant,
}

#[derive(Clone)]
struct PendingResponderReset {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    identity: InitiatorTransitionIdentity,
    response: Vec<u8>,
    transport: Arc<StdMutex<TransportState>>,
    deadline: Instant,
}

struct PendingResetAck {
    handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    identity: InitiatorTransitionIdentity,
    response_tx: std::sync::Mutex<Option<oneshot::Sender<ZCPacket>>>,
}

struct CompletedRelayHandshake {
    identity: RelayConfirmationIdentity,
    expires_at: Instant,
}

struct CompletedReadyReceipt {
    identity: RelayReadyReceiptIdentity,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelaySessionAuthBinding {
    peer_id: PeerId,
    metadata_session_id: uuid::Uuid,
    noise_static_pubkey: [u8; 32],
    generic_revision: Option<u64>,
    bridge_revision: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct ForeignRelayTransport {
    pub network_name: String,
    pub packet_sender: PacketRecvChan,
}

impl RelayPeerMap {
    pub(crate) fn new(
        peer_map: Arc<PeerMap>,
        foreign_network_client: Option<Arc<ForeignNetworkClient>>,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
        peer_session_store: Arc<PeerSessionStore>,
        foreign_relay_transport: Option<ForeignRelayTransport>,
    ) -> Arc<Self> {
        Arc::new(Self {
            control_metrics: AggregateTrafficMetrics::control(
                global_ctx.stats_manager().clone(),
                global_ctx.get_network_name(),
            ),
            peer_map,
            foreign_network_client,
            foreign_relay_transport,
            global_ctx,
            my_peer_id,
            peer_session_store,
            states: DashMap::new(),
            pending_handshakes: DashMap::new(),
            deferred_handshakes: DashMap::new(),
            handshake_locks: DashMap::new(),
            responder_handshake_locks: DashMap::new(),
            send_states: DashMap::new(),
            pending_responder_handshake_acks: DashMap::new(),
            pending_responder_resets: DashMap::new(),
            pending_reset_acks: DashMap::new(),
            completed_responder_handshakes: DashMap::new(),
            pending_confirmation_acks: DashMap::new(),
            pending_ready_receipts: DashMap::new(),
            completed_ready_receipts: DashMap::new(),
            relay_session_auth: DashMap::new(),
        })
    }

    fn send_state(&self, peer_id: PeerId) -> Option<Arc<RelaySendState>> {
        self.send_states.get(&peer_id).map(|entry| entry.clone())
    }

    fn ensure_send_state(&self, peer_id: PeerId, phase: RelaySendPhase) -> Arc<RelaySendState> {
        self.send_states
            .entry(peer_id)
            .or_insert_with(|| {
                Arc::new(RelaySendState::new_with_governor(
                    phase,
                    self.global_ctx.process_memory_governor(),
                ))
            })
            .clone()
    }

    fn set_send_phase(&self, peer_id: PeerId, phase: RelaySendPhase) {
        self.ensure_send_state(peer_id, phase).set_phase(phase);
    }

    fn set_confirmation_identity(
        &self,
        peer_id: PeerId,
        identity: RelayConfirmationIdentity,
    ) -> Arc<RelaySendState> {
        let state = self.ensure_send_state(peer_id, RelaySendPhase::Confirming);
        state.set_confirmation(identity);
        state
    }

    fn reset_confirmation_state(&self, peer_id: PeerId, identity: RelayConfirmationIdentity) {
        if let Some(state) = self.send_state(peer_id) {
            state.clear_confirmation(identity);
            state.set_phase(RelaySendPhase::AwaitingSession);
        }
    }

    /// Finish a local cancellation after the initiator reservation is in doubt.
    ///
    /// The hidden reservation stays in the session store. Only an authenticated
    /// recovery or reset may remove that reservation.
    fn reject_canceled_suspended_ready_confirmation(
        &self,
        peer_id: PeerId,
        identity: RelayConfirmationIdentity,
    ) -> Error {
        self.pending_confirmation_acks
            .remove_if(&peer_id, |_, pending| {
                pending.handshake_id == identity.handshake_id
                    && pending.session_id == identity.session_id
                    && pending.transition_id == identity.transition_id
            });
        self.reset_confirmation_state(peer_id, identity);
        Error::RouteError(Some(
            "relay ready confirmation was canceled; recovery is pending".to_string(),
        ))
    }

    fn get_local_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let cfg = self
            .global_ctx
            .config
            .get_secure_mode()
            .filter(|config| config.enabled)
            .ok_or_else(|| Error::RouteError(Some("secure mode is required".to_string())))?;
        let private = cfg
            .private_key()
            .map_err(|e| Error::RouteError(Some(format!("invalid private key: {e:?}"))))?;
        let public = cfg
            .public_key()
            .map_err(|e| Error::RouteError(Some(format!("invalid public key: {e:?}"))))?;
        Ok((private.as_bytes().to_vec(), public.as_bytes().to_vec()))
    }

    fn find_remote_static_pubkey(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let snapshot = self.peer_map.origin_auth_snapshot();
        snapshot
            .lookup(peer_id)
            .map(|entry| entry.noise_static_pubkey.to_vec())
    }

    fn bind_relay_session_auth(
        &self,
        peer_id: PeerId,
        session: &PeerSession,
    ) -> Result<RelaySessionAuthBinding, Error> {
        let snapshot = self.peer_map.origin_auth_snapshot();
        let generic = snapshot.lookup(peer_id);
        let bridge = snapshot
            .lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
            .filter(|grant| grant.is_live(Instant::now()));
        let static_key = session.peer_static_pubkey().ok_or_else(|| {
            Error::RouteError(Some(
                "relay session has no authenticated peer key".to_string(),
            ))
        })?;
        if generic.is_none_or(|entry| entry.noise_static_pubkey != static_key) {
            return Err(Error::RouteError(Some(
                "relay session key does not match origin authority".to_string(),
            )));
        }
        let binding = RelaySessionAuthBinding {
            peer_id,
            metadata_session_id: session.metadata_session_id(),
            noise_static_pubkey: static_key,
            generic_revision: generic.map(|entry| entry.revision),
            bridge_revision: bridge.map(|grant| grant.revision),
        };
        self.relay_session_auth.insert(peer_id, binding);
        Ok(binding)
    }

    fn bind_existing_relay_session_auth_if_missing(
        &self,
        peer_id: PeerId,
        session: &PeerSession,
    ) -> Result<(), Error> {
        if self.relay_session_auth.contains_key(&peer_id) {
            return Ok(());
        }
        self.bind_relay_session_auth(peer_id, session).map(|_| ())
    }

    fn validate_relay_session_auth(
        &self,
        peer_id: PeerId,
        session: &PeerSession,
        requires_bridge_grant: bool,
    ) -> Result<(OriginAuthEntry, Option<OriginAuthGrant>), Error> {
        let snapshot = self.peer_map.origin_auth_snapshot();
        self.validate_relay_session_auth_from_snapshot(
            peer_id,
            session,
            requires_bridge_grant,
            &snapshot,
        )
    }

    fn validate_relay_session_identity_from_snapshot(
        &self,
        peer_id: PeerId,
        session: &PeerSession,
        requires_bridge_grant: bool,
        snapshot: &OriginAuthSnapshot,
    ) -> Result<(OriginAuthEntry, Option<OriginAuthGrant>), Error> {
        let Some(generic) = snapshot.lookup(peer_id) else {
            return Err(Error::RouteError(Some(
                "relay origin has no generic authenticated identity".to_string(),
            )));
        };
        let static_key = session.peer_static_pubkey().ok_or_else(|| {
            Error::RouteError(Some(
                "relay session has no authenticated peer key".to_string(),
            ))
        })?;
        if generic.noise_static_pubkey != static_key {
            return Err(Error::RouteError(Some(
                "relay session key does not match origin authority".to_string(),
            )));
        }
        let bridge = snapshot
            .lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
            .filter(|grant| grant.is_live(Instant::now()));
        if requires_bridge_grant {
            let Some(grant) = bridge else {
                return Err(Error::RouteError(Some(
                    "complete Ethernet requires a live bridge grant".to_string(),
                )));
            };
            if grant.noise_static_pubkey != static_key {
                return Err(Error::RouteError(Some(
                    "bridge grant does not match relay session key".to_string(),
                )));
            }
            return Ok((generic, Some(grant)));
        }
        Ok((generic, bridge))
    }

    fn validate_relay_session_auth_from_snapshot(
        &self,
        peer_id: PeerId,
        session: &PeerSession,
        requires_bridge_grant: bool,
        snapshot: &OriginAuthSnapshot,
    ) -> Result<(OriginAuthEntry, Option<OriginAuthGrant>), Error> {
        let (generic, bridge) = self.validate_relay_session_identity_from_snapshot(
            peer_id,
            session,
            requires_bridge_grant,
            snapshot,
        )?;
        let binding = self.relay_session_auth.get(&peer_id).ok_or_else(|| {
            Error::RouteError(Some(
                "relay session authority binding is missing".to_string(),
            ))
        })?;
        let static_key = session.peer_static_pubkey().ok_or_else(|| {
            Error::RouteError(Some(
                "relay session has no authenticated peer key".to_string(),
            ))
        })?;
        if binding.peer_id != peer_id
            || binding.metadata_session_id != session.metadata_session_id()
            || binding.noise_static_pubkey != static_key
            || binding.generic_revision != Some(generic.revision)
        {
            return Err(Error::RouteError(Some(
                "relay session authority binding changed".to_string(),
            )));
        }
        if requires_bridge_grant {
            let grant = bridge.as_ref().expect("bridge grant was validated above");
            if binding.bridge_revision != Some(grant.revision) {
                return Err(Error::RouteError(Some(
                    "bridge grant does not match relay session authority".to_string(),
                )));
            }
        }
        Ok((generic, bridge))
    }

    fn full_ethernet_authorization_token(
        &self,
        destination_peer_id: PeerId,
        provided: Option<FullEthernetAuthorizationToken>,
    ) -> FullEthernetAuthorizationToken {
        provided.unwrap_or_else(|| {
            let descriptor = self.peer_map.dataplane_descriptor();
            FullEthernetAuthorizationToken::from_descriptor(
                descriptor.as_ref(),
                destination_peer_id,
            )
        })
    }

    fn full_ethernet_authorization_is_current(
        &self,
        destination_peer_id: PeerId,
        authorization: Option<&FullEthernetAuthorizationToken>,
    ) -> bool {
        authorization.is_some_and(|authorization| {
            authorization.destination_peer_id() == destination_peer_id
                && authorization.is_current(&self.peer_map, &self.global_ctx)
        })
    }

    fn packet_authorization_token(
        &self,
        packet: &ZCPacket,
        destination_peer_id: PeerId,
        provided: Option<FullEthernetAuthorizationToken>,
    ) -> Option<FullEthernetAuthorizationToken> {
        packet.peer_manager_header().and_then(|header| {
            (header.packet_type == PacketType::Ethernet as u8)
                .then(|| self.full_ethernet_authorization_token(destination_peer_id, provided))
        })
    }

    pub(crate) fn ethernet_origin_is_authorized(&self, packet: &ZCPacket, peer_id: PeerId) -> bool {
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        if header.from_peer_id.get() != peer_id || header.packet_type != PacketType::Ethernet as u8
        {
            return false;
        }
        let Some(binding) = self.relay_session_auth.get(&peer_id) else {
            return false;
        };
        let Some(origin_id) = packet.verified_origin_peer_id() else {
            return false;
        };
        if origin_id != peer_id
            || packet.verified_origin_peer_identity_type() != Some(PeerIdentityType::Admin)
            || packet.verified_origin_peer_secure_auth_level()
                != Some(SecureAuthLevel::PeerVerified)
            || packet.verified_origin_session_id() != Some(binding.metadata_session_id)
        {
            return false;
        }
        let snapshot = self.peer_map.origin_auth_snapshot();
        let Some(generic) = snapshot.lookup(peer_id) else {
            return false;
        };
        let generic_is_valid = generic.identity_type == PeerIdentityType::Admin
            && matches!(
                generic.secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
            && binding.noise_static_pubkey == generic.noise_static_pubkey
            && binding.generic_revision == Some(generic.revision);
        if !generic_is_valid {
            return false;
        }
        if header.is_hybrid_ip_ethernet() {
            return true;
        }
        let Some(grant) = snapshot.lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
        else {
            return false;
        };
        grant.is_live(Instant::now())
            && generic.noise_static_pubkey == grant.noise_static_pubkey
            && binding.bridge_revision == Some(grant.revision)
    }

    fn get_handshake_lock(&self, peer_id: PeerId) -> Arc<Mutex<()>> {
        self.handshake_locks
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn send_handshake_packet(
        &self,
        noise_payload: Vec<u8>,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
        packet_type: PacketType,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let mut payload = Vec::with_capacity(RELAY_HANDSHAKE_ID_SIZE + noise_payload.len());
        payload.extend_from_slice(&handshake_id);
        payload.extend_from_slice(&noise_payload);
        let mut pkt = ZCPacket::new_with_payload(&payload);
        pkt.fill_peer_manager_hdr(self.my_peer_id, dst_peer_id, packet_type as u8);
        let pkt_len = pkt.buf_len() as u64;
        self.send_via_next_hop(pkt, dst_peer_id, policy).await?;
        self.control_metrics.record_tx(pkt_len);
        Ok(())
    }

    async fn send_reset_transport_packet(
        &self,
        transport: &Arc<StdMutex<TransportState>>,
        identity: &InitiatorTransitionIdentity,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
        packet_type: PacketType,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let payload = encode_reset_identity(identity);
        let mut out = vec![0_u8; 4096];
        let out_len = transport
            .lock()
            .unwrap()
            .write_message(&payload, &mut out)
            .map_err(|error| {
                Error::RouteError(Some(format!("write relay reset message failed: {error:?}")))
            })?;
        let mut packet_payload = Vec::with_capacity(RELAY_HANDSHAKE_ID_SIZE + out_len);
        packet_payload.extend_from_slice(&handshake_id);
        packet_payload.extend_from_slice(&out[..out_len]);
        let mut packet = ZCPacket::new_with_payload(&packet_payload);
        packet.fill_peer_manager_hdr(self.my_peer_id, dst_peer_id, packet_type as u8);
        let packet_len = packet.buf_len() as u64;
        self.send_via_next_hop(packet, dst_peer_id, NextHopPolicy::LeastHop)
            .await?;
        self.control_metrics.record_tx(packet_len);
        Ok(())
    }

    fn decode_reset_transport_message(
        &self,
        transport: &Arc<StdMutex<TransportState>>,
        packet: &ZCPacket,
        expected_packet_type: PacketType,
        remote_peer_id: PeerId,
    ) -> Result<InitiatorTransitionIdentity, Error> {
        let header = packet.peer_manager_header().ok_or_else(|| {
            Error::RouteError(Some("relay reset packet has no header".to_string()))
        })?;
        if header.packet_type != expected_packet_type as u8 {
            return Err(Error::RouteError(Some(
                "relay reset packet type mismatch".to_string(),
            )));
        }
        let payload = packet
            .payload()
            .get(RELAY_HANDSHAKE_ID_SIZE..)
            .ok_or_else(|| {
                Error::RouteError(Some("relay reset handshake id is missing".to_string()))
            })?;
        let mut out = vec![0_u8; 4096];
        let out_len = transport
            .lock()
            .unwrap()
            .read_message(payload, &mut out)
            .map_err(|error| {
                Error::RouteError(Some(format!("read relay reset message failed: {error:?}")))
            })?;
        let session_key = SessionKey::new(self.global_ctx.get_network_name(), remote_peer_id);
        decode_reset_identity(&out[..out_len], session_key)
    }

    pub(crate) fn is_handshake_confirmation_packet_type(packet_type: u8) -> bool {
        packet_type == PacketType::RelayHandshakeConfirm as u8
            || packet_type == PacketType::RelayHandshakeConfirmAck as u8
            || packet_type == PacketType::RelayHandshakeReady as u8
            || packet_type == PacketType::RelayHandshakeReadyAck as u8
            || packet_type == PacketType::RelayHandshakeReadyReceipt as u8
            || packet_type == PacketType::RelayHandshakeReadyReceiptAck as u8
    }

    pub(crate) fn is_handshake_packet_type(packet_type: u8) -> bool {
        packet_type == PacketType::RelayHandshake as u8
            || packet_type == PacketType::RelayHandshakeAck as u8
            || packet_type == PacketType::RelayHandshakeReset as u8
            || packet_type == PacketType::RelayHandshakeResetAck as u8
    }

    async fn send_handshake_confirmation_packet(
        &self,
        session: &PeerSession,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
        transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
        packet_type: PacketType,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let mut payload = [0_u8; RELAY_CONFIRMATION_PAYLOAD_SIZE];
        payload[..RELAY_HANDSHAKE_ID_SIZE].copy_from_slice(&handshake_id);
        payload[RELAY_HANDSHAKE_ID_SIZE..].copy_from_slice(&transition_id);
        let mut packet = ZCPacket::new_with_payload(&payload);
        packet.fill_peer_manager_hdr(self.my_peer_id, dst_peer_id, packet_type as u8);
        attach_relay_origin_proof(&mut packet)
            .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        session
            .encrypt_payload(self.my_peer_id, dst_peer_id, &mut packet)
            .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        let packet_len = packet.buf_len() as u64;
        self.send_via_next_hop(packet, dst_peer_id, NextHopPolicy::LeastHop)
            .await?;
        self.control_metrics.record_tx(packet_len);
        Ok(())
    }

    async fn send_handshake_ready_packet(
        &self,
        session: &PeerSession,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
        transition_id: [u8; RELAY_TRANSITION_ID_SIZE],
        packet_type: PacketType,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.send_handshake_confirmation_packet(
            session,
            handshake_id,
            transition_id,
            packet_type,
            dst_peer_id,
        )
        .await
    }

    async fn send_ready_receipt_packet(
        &self,
        session: &PeerSession,
        identity: RelayReadyReceiptIdentity,
        packet_type: PacketType,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let payload = encode_relay_ready_receipt(identity);
        let mut packet = ZCPacket::new_with_payload(&payload);
        packet.fill_peer_manager_hdr(self.my_peer_id, dst_peer_id, packet_type as u8);
        attach_relay_origin_proof(&mut packet)
            .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        session
            .encrypt_payload(self.my_peer_id, dst_peer_id, &mut packet)
            .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        let packet_len = packet.buf_len() as u64;
        self.send_via_next_hop(packet, dst_peer_id, NextHopPolicy::LeastHop)
            .await?;
        self.control_metrics.record_tx(packet_len);
        Ok(())
    }

    async fn drive_ready_receipt(
        &self,
        dst_peer_id: PeerId,
        identity: RelayReadyReceiptIdentity,
        owner_running: Arc<AtomicBool>,
    ) {
        let mut retry_delay = Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MS);
        loop {
            for _ in 0..HANDSHAKE_CONFIRM_MAX_ATTEMPTS {
                let Some(pending) = self
                    .pending_ready_receipts
                    .get(&dst_peer_id)
                    .filter(|current| current.identity == identity)
                    .map(|current| current.clone())
                else {
                    owner_running.store(false, Ordering::Release);
                    return;
                };
                if pending.outcome.load(Ordering::Acquire) == 1 {
                    self.pending_ready_receipts
                        .remove_if(&dst_peer_id, |_, current| current.identity == identity);
                    owner_running.store(false, Ordering::Release);
                    return;
                }
                if let Err(error) = self
                    .send_ready_receipt_packet(
                        &pending.session,
                        identity,
                        PacketType::RelayHandshakeReadyReceipt,
                        dst_peer_id,
                    )
                    .await
                {
                    tracing::debug!(?error, ?dst_peer_id, "relay ready receipt send failed");
                }
                if pending.outcome.load(Ordering::Acquire) == 1 {
                    self.pending_ready_receipts
                        .remove_if(&dst_peer_id, |_, current| current.identity == identity);
                    owner_running.store(false, Ordering::Release);
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep(retry_delay) => {}
                    _ = pending.notify.notified() => {}
                }
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MAX_MS));
            }

            // Keep one owner task for the durable receipt. A later ensure_session
            // call wakes this owner and starts one new retry schedule.
            let Some(pending) = self
                .pending_ready_receipts
                .get(&dst_peer_id)
                .filter(|current| current.identity == identity)
                .map(|current| current.clone())
            else {
                owner_running.store(false, Ordering::Release);
                return;
            };
            pending.notify.notified().await;
            retry_delay = Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MS);
        }
    }

    fn ensure_ready_receipt_owner(self: &Arc<Self>, dst_peer_id: PeerId) {
        let Some(pending) = self
            .pending_ready_receipts
            .get(&dst_peer_id)
            .map(|entry| entry.clone())
        else {
            return;
        };
        if pending
            .owner_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let relay_map = self.clone();
        tokio::spawn(async move {
            relay_map
                .drive_ready_receipt(dst_peer_id, pending.identity, pending.owner_running.clone())
                .await;
        });
    }

    fn start_ready_receipt(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        identity: RelayReadyReceiptIdentity,
        session: Arc<PeerSession>,
    ) {
        let pending = PendingReadyReceipt {
            identity,
            session,
            expires_at: Instant::now() + INITIATOR_RECOVERY_LIFETIME,
            notify: Arc::new(Notify::new()),
            outcome: Arc::new(AtomicU8::new(0)),
            owner_running: Arc::new(AtomicBool::new(false)),
        };
        match self.pending_ready_receipts.entry(dst_peer_id) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(pending);
            }
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().identity == identity {
                    entry.get().notify.notify_one();
                    return;
                }
                entry.get().notify.notify_one();
                entry.insert(pending);
            }
        }
        self.ensure_ready_receipt_owner(dst_peer_id);
    }

    fn retry_pending_ready_receipt(&self, dst_peer_id: PeerId, session: Arc<PeerSession>) {
        if let Some(mut pending) = self.pending_ready_receipts.get_mut(&dst_peer_id) {
            pending.session = session;
            pending.notify.notify_one();
        }
    }

    async fn commit_initiator_after_ready(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        identity: RelayConfirmationIdentity,
        reservation: InitiatorSessionReservation,
        receipt_session_metadata_id: uuid::Uuid,
        previous_receipt_identity: Option<InitiatorTransitionIdentity>,
    ) -> Result<(), Error> {
        let receipt_identity = RelayReadyReceiptIdentity {
            handshake_id: identity.handshake_id,
            session_metadata_id: receipt_session_metadata_id,
            transition_id: identity.transition_id,
            action: reservation.action(),
            session_generation: reservation.session_generation(),
            initial_epoch: reservation.initial_epoch(),
        };
        let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::Confirming);
        state.clear_confirmation(identity);
        state.set_phase(RelaySendPhase::Draining);
        let receipt_store_identity =
            reservation.transition_identity_with_session_metadata(receipt_session_metadata_id);
        let committed = match reservation
            .commit_with_receipt_replacing(receipt_store_identity, previous_receipt_identity)
        {
            Ok(session) => session,
            Err(error) => {
                state.set_phase(RelaySendPhase::AwaitingSession);
                return Err(Error::RouteError(Some(error.to_string())));
            }
        };
        let session_key = SessionKey::new(
            self.global_ctx.get_network_identity().network_name,
            dst_peer_id,
        );
        if let Err(error) = self.bind_relay_session_auth(dst_peer_id, &committed) {
            self.peer_session_store
                .remove_if_same(&session_key, &committed);
            state.set_phase(RelaySendPhase::AwaitingSession);
            return Err(error);
        }
        self.pending_confirmation_acks
            .remove_if(&dst_peer_id, |_, pending| {
                pending.handshake_id == identity.handshake_id
                    && pending.session_id == identity.session_id
                    && pending.transition_id == identity.transition_id
            });
        if let Err(error) = self
            .flush_pending_packets(dst_peer_id, committed.clone())
            .await
        {
            tracing::debug!(
                ?error,
                ?dst_peer_id,
                "relay queue drain failed after initiator confirmation"
            );
            self.schedule_flush_retry(dst_peer_id, committed.clone());
        }
        self.start_ready_receipt(dst_peer_id, receipt_identity, committed);
        Ok(())
    }

    async fn start_handshake_confirmation(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
        reservation: InitiatorSessionReservation,
        responder_session_metadata_id: uuid::Uuid,
        previous_receipt_identity: Option<InitiatorTransitionIdentity>,
    ) -> Result<(), Error> {
        let session = reservation.session();
        let notify = Arc::new(Notify::new());
        let session_id = session.metadata_session_id();
        let transition_id = reservation.transition_id();
        let identity = RelayConfirmationIdentity {
            handshake_id,
            session_id,
            transition_id,
        };
        let transition_identity =
            reservation.transition_identity_with_session_metadata(responder_session_metadata_id);
        let expires_at = Instant::now() + INITIATOR_RECOVERY_LIFETIME;
        let state = self.set_confirmation_identity(dst_peer_id, identity);
        let outcome = Arc::new(AtomicU8::new(0));
        self.pending_confirmation_acks.insert(
            dst_peer_id,
            PendingConfirmationAck {
                handshake_id,
                session_id,
                transition_id,
                expected_packet_type: PacketType::RelayHandshakeConfirmAck as u8,
                transition_identity: transition_identity.clone(),
                previous_receipt_identity: previous_receipt_identity.clone(),
                expires_at,
                session: session.clone(),
                notify: notify.clone(),
                outcome: outcome.clone(),
            },
        );

        let mut retry_delay = Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MS);
        for _ in 0..HANDSHAKE_CONFIRM_MAX_ATTEMPTS {
            if let Err(error) = self
                .send_handshake_confirmation_packet(
                    &session,
                    handshake_id,
                    transition_id,
                    PacketType::RelayHandshakeConfirm,
                    dst_peer_id,
                )
                .await
            {
                tracing::debug!(?error, dst_peer_id, "relay confirmation send failed");
            }
            if outcome.load(Ordering::Acquire) == 1 {
                self.pending_confirmation_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.session_id == session_id
                            && pending.transition_id == transition_id
                    });
                break;
            }
            if timeout(retry_delay, notify.notified()).await.is_ok()
                && outcome.load(Ordering::Acquire) == 1
            {
                self.pending_confirmation_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.session_id == session_id
                            && pending.transition_id == transition_id
                    });
                break;
            }
            if outcome.load(Ordering::Acquire) == 2 {
                self.pending_confirmation_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.session_id == session_id
                            && pending.transition_id == transition_id
                    });
                state.clear_confirmation(identity);
                state.set_phase(RelaySendPhase::AwaitingSession);
                return Err(Error::RouteError(Some(
                    "relay confirmation was canceled".to_string(),
                )));
            }
            retry_delay = retry_delay
                .saturating_mul(2)
                .min(Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MAX_MS));
        }
        let confirm_accepted = match outcome.load(Ordering::Acquire) {
            1 => true,
            0 => outcome
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_err(),
            _ => false,
        };
        if confirm_accepted {
            if let Err(error) = reservation.suspend_with_session_metadata(
                responder_session_metadata_id,
                INITIATOR_RECOVERY_LIFETIME,
            ) {
                self.pending_confirmation_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.session_id == session_id
                            && pending.transition_id == transition_id
                    });
                self.reset_confirmation_state(dst_peer_id, identity);
                return Err(Error::RouteError(Some(format!(
                    "retain relay recovery reservation failed: {error}"
                ))));
            }

            let ready_notify = Arc::new(Notify::new());
            let ready_outcome = Arc::new(AtomicU8::new(0));
            self.pending_confirmation_acks.insert(
                dst_peer_id,
                PendingConfirmationAck {
                    handshake_id,
                    session_id,
                    transition_id,
                    expected_packet_type: PacketType::RelayHandshakeReadyAck as u8,
                    transition_identity: transition_identity.clone(),
                    previous_receipt_identity: previous_receipt_identity.clone(),
                    expires_at,
                    session: session.clone(),
                    notify: ready_notify.clone(),
                    outcome: ready_outcome.clone(),
                },
            );
            let mut ready_delay = Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MS);
            for _ in 0..HANDSHAKE_CONFIRM_MAX_ATTEMPTS {
                if let Err(error) = self
                    .send_handshake_ready_packet(
                        &session,
                        handshake_id,
                        transition_id,
                        PacketType::RelayHandshakeReady,
                        dst_peer_id,
                    )
                    .await
                {
                    tracing::debug!(?error, ?dst_peer_id, "relay ready send failed");
                }
                if ready_outcome.load(Ordering::Acquire) == 1 {
                    return Ok(());
                }
                if timeout(ready_delay, ready_notify.notified()).await.is_ok()
                    && ready_outcome.load(Ordering::Acquire) == 1
                {
                    return Ok(());
                }
                if ready_outcome.load(Ordering::Acquire) == 2 {
                    self.pending_confirmation_acks
                        .remove_if(&dst_peer_id, |_, pending| {
                            pending.handshake_id == handshake_id
                                && pending.session_id == session_id
                                && pending.transition_id == transition_id
                        });
                    self.reset_confirmation_state(dst_peer_id, identity);
                    return Err(Error::RouteError(Some(
                        "relay ready confirmation was canceled".to_string(),
                    )));
                }
                ready_delay = ready_delay
                    .saturating_mul(2)
                    .min(Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MAX_MS));
            }
            if ready_outcome.load(Ordering::Acquire) == 2 {
                self.pending_confirmation_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.session_id == session_id
                            && pending.transition_id == transition_id
                    });
                self.reset_confirmation_state(dst_peer_id, identity);
                return Err(Error::RouteError(Some(
                    "relay ready confirmation was canceled".to_string(),
                )));
            }
            if ready_outcome.load(Ordering::Acquire) == 1 {
                return Ok(());
            }
            if ready_outcome.load(Ordering::Acquire) == 2 {
                return Err(
                    self.reject_canceled_suspended_ready_confirmation(dst_peer_id, identity)
                );
            }
            return Err(Error::RouteError(Some(
                "relay ready acknowledgement timed out; recovery is pending".to_string(),
            )));
        }
        self.pending_confirmation_acks
            .remove_if(&dst_peer_id, |_, pending| {
                pending.handshake_id == handshake_id
                    && pending.session_id == session_id
                    && pending.transition_id == transition_id
            });
        state.clear_confirmation(identity);
        state.set_phase(RelaySendPhase::AwaitingSession);
        Err(Error::RouteError(Some(
            "relay confirmation timed out".to_string(),
        )))
    }

    fn responder_handshake_completed(
        &self,
        peer_id: PeerId,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    ) -> bool {
        self.completed_responder_handshakes
            .get(&peer_id)
            .is_some_and(|completed| {
                completed.iter().any(|entry| {
                    entry.identity.handshake_id == handshake_id && entry.expires_at > Instant::now()
                })
            })
    }

    fn responder_handshake_completed_identity(
        &self,
        peer_id: PeerId,
        identity: RelayConfirmationIdentity,
    ) -> bool {
        self.completed_responder_handshakes
            .get(&peer_id)
            .is_some_and(|completed| {
                completed
                    .iter()
                    .any(|entry| entry.identity == identity && entry.expires_at > Instant::now())
            })
    }

    fn record_completed_ready_receipt(&self, peer_id: PeerId, identity: RelayReadyReceiptIdentity) {
        let mut completed = self.completed_ready_receipts.entry(peer_id).or_default();
        if completed.iter().any(|entry| entry.identity == identity) {
            return;
        }
        if completed.len() >= MAX_COMPLETED_HANDSHAKES_PER_PEER {
            completed.pop_front();
        }
        completed.push_back(CompletedReadyReceipt {
            identity,
            expires_at: Instant::now() + Duration::from_secs(60),
        });
    }

    fn completed_ready_receipt(
        &self,
        peer_id: PeerId,
        identity: RelayReadyReceiptIdentity,
    ) -> bool {
        self.completed_ready_receipts
            .get(&peer_id)
            .is_some_and(|completed| {
                completed
                    .iter()
                    .any(|entry| entry.identity == identity && entry.expires_at > Instant::now())
            })
    }

    fn record_completed_responder_handshake(
        &self,
        peer_id: PeerId,
        identity: RelayConfirmationIdentity,
    ) {
        let mut completed = self
            .completed_responder_handshakes
            .entry(peer_id)
            .or_default();
        if completed.iter().any(|entry| entry.identity == identity) {
            return;
        }
        if completed.len() >= MAX_COMPLETED_HANDSHAKES_PER_PEER {
            completed.pop_front();
        }
        completed.push_back(CompletedRelayHandshake {
            identity,
            expires_at: Instant::now() + Duration::from_secs(60),
        });
    }

    fn cancel_pending_responder_handshake(
        &self,
        peer_id: PeerId,
        expected_handshake_id: Option<[u8; RELAY_HANDSHAKE_ID_SIZE]>,
    ) {
        let removed = if let Some(handshake_id) = expected_handshake_id {
            self.pending_responder_handshake_acks
                .remove_if(&peer_id, |_, pending| pending.handshake_id == handshake_id)
        } else {
            self.pending_responder_handshake_acks.remove(&peer_id)
        };
        let Some((_, pending)) = removed else {
            return;
        };
        if !pending.recovery_active {
            pending.prepared.cancel();
        }
        if let Some(state) = self.send_state(peer_id) {
            state.set_phase(RelaySendPhase::AwaitingSession);
            *state.confirmation.lock().unwrap() = None;
        }
    }

    fn cancel_pending_responder_reset(
        &self,
        peer_id: PeerId,
        expected_handshake_id: Option<[u8; RELAY_HANDSHAKE_ID_SIZE]>,
    ) {
        if let Some(handshake_id) = expected_handshake_id {
            self.pending_responder_resets
                .remove_if(&peer_id, |_, pending| pending.handshake_id == handshake_id);
        } else {
            self.pending_responder_resets.remove(&peer_id);
        }
    }

    fn extend_pending_responder_deadline(
        &self,
        peer_id: PeerId,
        identity: RelayConfirmationIdentity,
    ) {
        if let Some(mut pending) = self.pending_responder_handshake_acks.get_mut(&peer_id)
            && pending.handshake_id == identity.handshake_id
            && pending.transition_id == identity.transition_id
            && pending.prepared.session.metadata_session_id() == identity.session_id
        {
            pending.deadline = Instant::now()
                + Duration::from_millis(RESPONDER_CONFIRM_DEADLINE_MS + RELAY_CONFIRM_WINDOW_MS);
        }
    }

    fn remove_pending_handshake_if_matching(
        &self,
        peer_id: PeerId,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    ) {
        self.pending_handshakes
            .remove_if(&peer_id, |_, pending| pending.handshake_id == handshake_id);
    }

    fn cancel_pending_confirmation(&self, peer_id: PeerId) {
        if let Some((_, pending)) = self.pending_confirmation_acks.remove(&peer_id) {
            pending.outcome.store(2, Ordering::Release);
            pending.notify.notify_one();
        }
    }

    fn get_live_staged_confirmation(
        &self,
        peer_id: PeerId,
    ) -> Option<(
        Arc<PeerSession>,
        [u8; RELAY_HANDSHAKE_ID_SIZE],
        uuid::Uuid,
        [u8; RELAY_TRANSITION_ID_SIZE],
    )> {
        let pending = self.pending_confirmation_acks.get(&peer_id)?;
        if pending.expires_at <= Instant::now() {
            drop(pending);
            self.cancel_pending_confirmation(peer_id);
            return None;
        }
        Some((
            pending.session.clone(),
            pending.handshake_id,
            pending.session_id,
            pending.transition_id,
        ))
    }

    async fn send_via_next_hop(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.send_via_next_hop_at(msg, dst_peer_id, policy, None)
            .await
    }

    async fn send_via_next_hop_at(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
    ) -> Result<(), Error> {
        if let Some(transport) = &self.foreign_relay_transport
            && !self.peer_map.has_peer(dst_peer_id)
        {
            let mut foreign_packet =
                ZCPacket::new_for_foreign_network(&transport.network_name, dst_peer_id, &msg);
            foreign_packet.fill_peer_manager_hdr(
                self.my_peer_id,
                dst_peer_id,
                PacketType::ForeignNetworkPacket as u8,
            );
            return transport
                .packet_sender
                .send(foreign_packet)
                .await
                .map_err(|error| Error::RouteError(Some(error.to_string())));
        }

        let next_hop = if let Some(next_hop) = selected_next_hop {
            Some(next_hop)
        } else {
            self.peer_map
                .get_gateway_peer_id_for_packet(dst_peer_id, policy, &msg)
                .await
                .or_else(|| {
                    (self.peer_map.has_peer(dst_peer_id)
                        || self
                            .foreign_network_client
                            .as_ref()
                            .is_some_and(|client| client.has_next_hop(dst_peer_id))
                        || self.foreign_relay_transport.is_some())
                    .then_some(dst_peer_id)
                })
        };
        let Some(next_hop) = next_hop else {
            return Err(Error::RouteError(Some(format!(
                "next hop not found in route for peer {dst_peer_id:?}"
            ))));
        };
        if self.peer_map.has_peer(next_hop) {
            self.peer_map.send_msg_directly(msg, next_hop).await
        } else if let Some(foreign_network_client) = &self.foreign_network_client {
            foreign_network_client.send_msg(msg, next_hop).await
        } else if let Some(transport) = &self.foreign_relay_transport {
            let mut foreign_packet =
                ZCPacket::new_for_foreign_network(&transport.network_name, dst_peer_id, &msg);
            foreign_packet.fill_peer_manager_hdr(
                self.my_peer_id,
                next_hop,
                PacketType::ForeignNetworkPacket as u8,
            );
            transport
                .packet_sender
                .send(foreign_packet)
                .await
                .map_err(|error| Error::RouteError(Some(error.to_string())))
        } else {
            Err(Error::RouteError(Some(format!(
                "next hop not found in direct peer map: {next_hop:?}"
            ))))
        }
    }

    async fn send_via_next_hop_batch(
        &self,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.send_via_next_hop_batch_at(batch, dst_peer_id, policy, None)
            .await
    }

    async fn send_via_next_hop_batch_at(
        &self,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
    ) -> Result<(), Error> {
        if let Some(transport) = &self.foreign_relay_transport
            && !self.peer_map.has_peer(dst_peer_id)
        {
            let mut foreign_batch = PacketBatch::new();
            for packet in batch {
                let mut foreign_packet = ZCPacket::new_for_foreign_network(
                    &transport.network_name,
                    dst_peer_id,
                    &packet,
                );
                foreign_packet.fill_peer_manager_hdr(
                    self.my_peer_id,
                    dst_peer_id,
                    PacketType::ForeignNetworkPacket as u8,
                );
                foreign_batch
                    .try_push(foreign_packet)
                    .expect("the foreign batch cannot exceed its source batch");
            }
            return transport
                .packet_sender
                .send_batch(foreign_batch)
                .await
                .map_err(|error| Error::RouteError(Some(error.to_string())));
        }

        let Some(first) = batch.first() else {
            return Ok(());
        };
        let flow_hash = classify_packet_flow(first).hash;
        let next_hop = if let Some(next_hop) = selected_next_hop {
            Some(next_hop)
        } else {
            self.peer_map
                .get_gateway_peer_id_for_flow(dst_peer_id, policy, flow_hash)
                .await
                .or_else(|| {
                    (self.peer_map.has_peer(dst_peer_id)
                        || self
                            .foreign_network_client
                            .as_ref()
                            .is_some_and(|client| client.has_next_hop(dst_peer_id))
                        || self.foreign_relay_transport.is_some())
                    .then_some(dst_peer_id)
                })
        };
        let Some(next_hop) = next_hop else {
            return Err(Error::RouteError(Some(format!(
                "next hop not found in route for peer {dst_peer_id:?}"
            ))));
        };
        if self.peer_map.has_peer(next_hop) {
            self.peer_map.send_msg_batch_directly(batch, next_hop).await
        } else if let Some(foreign_network_client) = &self.foreign_network_client {
            for packet in batch {
                foreign_network_client.send_msg(packet, next_hop).await?;
            }
            Ok(())
        } else if let Some(transport) = &self.foreign_relay_transport {
            let mut foreign_batch = PacketBatch::new();
            for packet in batch {
                let mut foreign_packet = ZCPacket::new_for_foreign_network(
                    &transport.network_name,
                    dst_peer_id,
                    &packet,
                );
                foreign_packet.fill_peer_manager_hdr(
                    self.my_peer_id,
                    next_hop,
                    PacketType::ForeignNetworkPacket as u8,
                );
                foreign_batch
                    .try_push(foreign_packet)
                    .expect("the foreign batch cannot exceed its source batch");
            }
            transport
                .packet_sender
                .send_batch(foreign_batch)
                .await
                .map_err(|error| Error::RouteError(Some(error.to_string())))
        } else {
            Err(Error::RouteError(Some(format!(
                "next hop not found in direct peer map: {next_hop:?}"
            ))))
        }
    }

    pub async fn send_msg(
        self: &Arc<Self>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.send_msg_with_next_hop(msg, dst_peer_id, policy, None)
            .await
    }

    pub async fn send_msg_with_next_hop(
        self: &Arc<Self>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
    ) -> Result<(), Error> {
        self.send_msg_with_next_hop_authorized(msg, dst_peer_id, policy, selected_next_hop, None)
            .await
    }

    pub(crate) async fn send_msg_with_next_hop_authorized(
        self: &Arc<Self>,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
        provided_authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<(), Error> {
        let packet_type = msg
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?
            .packet_type;
        let is_encrypted = msg
            .peer_manager_header()
            .is_some_and(|header| header.is_encrypted());
        if is_encrypted || Self::is_handshake_packet_type(packet_type) {
            return self
                .send_via_next_hop_at(msg, dst_peer_id, policy, selected_next_hop)
                .await;
        }

        let now = Instant::now();

        self.states.entry(dst_peer_id).or_default().last_active_at = now;

        attach_relay_origin_proof(&mut msg)
            .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        let authorization =
            self.packet_authorization_token(&msg, dst_peer_id, provided_authorization);
        if msg
            .peer_manager_header()
            .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay encryption".to_string(),
            )));
        }

        if let Some(state) = self.send_state(dst_peer_id)
            && state.phase() != RelaySendPhase::Ready
        {
            if matches!(
                state.enqueue(msg.clone(), policy.clone(), authorization.clone())?,
                EnqueueResult::Queued
            ) {
                self.flush_pending_if_ready(dst_peer_id).await;
                return Ok(());
            }
        }

        let session = match self.ensure_session(dst_peer_id, policy.clone()).await {
            Ok(session) => session,
            Err(_) => {
                let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession);
                match state.enqueue(msg, policy, authorization.clone())? {
                    EnqueueResult::Queued => {
                        self.flush_pending_if_ready(dst_peer_id).await;
                        return Ok(());
                    }
                    EnqueueResult::Ready => {
                        return Err(Error::RouteError(Some(
                            "relay state became ready without a session".to_string(),
                        )));
                    }
                }
            }
        };

        if let Some(state) = self.send_state(dst_peer_id)
            && state.phase() != RelaySendPhase::Ready
        {
            match state.enqueue(msg.clone(), policy.clone(), authorization.clone())? {
                EnqueueResult::Queued => return Ok(()),
                EnqueueResult::Ready => {}
            }
        }

        let my_peer_id = self.my_peer_id;
        if msg
            .peer_manager_header()
            .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay encryption".to_string(),
            )));
        }
        session
            .encrypt_payload(my_peer_id, dst_peer_id, &mut msg)
            .map_err(|e| Error::RouteError(Some(format!("{e:?}"))))?;

        if msg
            .peer_manager_header()
            .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay send".to_string(),
            )));
        }

        self.send_via_next_hop_at(msg, dst_peer_id, policy, selected_next_hop)
            .await
    }

    pub async fn send_msg_batch(
        self: &Arc<Self>,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.send_msg_batch_with_next_hop(batch, dst_peer_id, policy, None)
            .await
    }

    pub async fn send_msg_batch_with_next_hop(
        self: &Arc<Self>,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
    ) -> Result<(), Error> {
        self.send_msg_batch_with_next_hop_authorized(
            batch,
            dst_peer_id,
            policy,
            selected_next_hop,
            None,
        )
        .await
    }

    pub(crate) async fn send_msg_batch_with_next_hop_authorized(
        self: &Arc<Self>,
        mut batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        selected_next_hop: Option<PeerId>,
        provided_authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let first_header = batch
            .first()
            .and_then(ZCPacket::peer_manager_header)
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let first_is_encrypted = first_header.is_encrypted();
        let first_is_handshake = Self::is_handshake_packet_type(first_header.packet_type);
        let compatible = batch.iter().all(|packet| {
            packet.peer_manager_header().is_some_and(|header| {
                header.is_encrypted() == first_is_encrypted
                    && Self::is_handshake_packet_type(header.packet_type) == first_is_handshake
            })
        });
        if !compatible {
            return Err(Error::RouteError(Some(
                "mixed secure relay batch".to_string(),
            )));
        }
        if first_is_encrypted || first_is_handshake {
            return self
                .send_via_next_hop_batch_at(batch, dst_peer_id, policy, selected_next_hop)
                .await;
        }
        self.states.entry(dst_peer_id).or_default().last_active_at = Instant::now();

        for packet in batch.iter_mut() {
            attach_relay_origin_proof(packet)
                .map_err(|error| Error::RouteError(Some(error.to_string())))?;
        }

        let has_ethernet = batch.iter().any(|packet| {
            packet
                .peer_manager_header()
                .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
        });
        let authorization = has_ethernet
            .then(|| self.full_ethernet_authorization_token(dst_peer_id, provided_authorization));
        if has_ethernet
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay encryption".to_string(),
            )));
        }
        if let Some(state) = self.send_state(dst_peer_id)
            && state.phase() != RelaySendPhase::Ready
        {
            let items = batch.into_iter().map(|packet| {
                let token = packet
                    .peer_manager_header()
                    .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
                    .then(|| authorization.clone())
                    .flatten();
                (packet, policy.clone(), token)
            });
            match state.enqueue_batch(items)? {
                EnqueueBatchResult::Queued => {
                    self.flush_pending_if_ready(dst_peer_id).await;
                    return Ok(());
                }
                EnqueueBatchResult::Ready(items) => {
                    let mut ready_batch = PacketBatch::new();
                    for (packet, _, _) in items {
                        ready_batch
                            .try_push(packet)
                            .expect("a relay batch cannot exceed the batch limit");
                    }
                    batch = ready_batch;
                }
            }
        }

        let session = match self.ensure_session(dst_peer_id, policy.clone()).await {
            Ok(session) => session,
            Err(_) => {
                let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession);
                state.set_phase(RelaySendPhase::AwaitingSession);
                let items = batch.into_iter().map(|packet| {
                    let token = packet
                        .peer_manager_header()
                        .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
                        .then(|| authorization.clone())
                        .flatten();
                    (packet, policy.clone(), token)
                });
                match state.enqueue_batch(items)? {
                    EnqueueBatchResult::Queued => {
                        self.flush_pending_if_ready(dst_peer_id).await;
                        return Ok(());
                    }
                    EnqueueBatchResult::Ready(_) => {
                        return Err(Error::RouteError(Some(
                            "relay state became ready without a session".to_string(),
                        )));
                    }
                }
            }
        };

        if let Some(state) = self.send_state(dst_peer_id)
            && state.phase() != RelaySendPhase::Ready
        {
            let items = batch.into_iter().map(|packet| {
                let token = packet
                    .peer_manager_header()
                    .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
                    .then(|| authorization.clone())
                    .flatten();
                (packet, policy.clone(), token)
            });
            match state.enqueue_batch(items)? {
                EnqueueBatchResult::Queued => return Ok(()),
                EnqueueBatchResult::Ready(items) => {
                    let mut ready_batch = PacketBatch::new();
                    for (packet, _, _) in items {
                        ready_batch
                            .try_push(packet)
                            .expect("a relay batch cannot exceed the batch limit");
                    }
                    batch = ready_batch;
                }
            }
        }

        let my_peer_id = self.my_peer_id;
        if has_ethernet
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay encryption".to_string(),
            )));
        }
        if parallel_crypto_enabled(batch.len()) {
            let (encrypted, result) = tokio::task::spawn_blocking(move || {
                let result = batch.par_iter_mut().try_for_each(|packet| {
                    session.encrypt_payload(my_peer_id, dst_peer_id, packet)
                });
                (batch, result)
            })
            .await
            .map_err(|error| {
                Error::RouteError(Some(format!(
                    "relay batch encryption worker failed: {error}"
                )))
            })?;
            result.map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?;
            batch = encrypted;
        } else {
            session
                .encrypt_payload_batch(my_peer_id, dst_peer_id, &mut batch)
                .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?;
        }

        if has_ethernet
            && !self.full_ethernet_authorization_is_current(dst_peer_id, authorization.as_ref())
        {
            return Err(Error::RouteError(Some(
                "complete Ethernet authority changed before relay send".to_string(),
            )));
        }

        self.send_via_next_hop_batch_at(batch, dst_peer_id, policy, selected_next_hop)
            .await
    }

    pub(crate) fn buffer_pending_packet(
        &self,
        dst_peer_id: PeerId,
        pkt: ZCPacket,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession);
        if state.closed.load(Ordering::Acquire) {
            return Err(Error::RouteError(Some(
                "relay peer state is closed".to_string(),
            )));
        }
        let authorization = self.packet_authorization_token(&pkt, dst_peer_id, None);
        state.enqueue(pkt, policy, authorization).map(|_| ())
    }

    fn buffer_pending_batch(
        &self,
        dst_peer_id: PeerId,
        batch: PacketBatch,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession);
        let authorization = batch.iter().any(|packet| {
            packet
                .peer_manager_header()
                .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
        });
        let authorization =
            authorization.then(|| self.full_ethernet_authorization_token(dst_peer_id, None));
        state
            .enqueue_batch(batch.into_iter().map(|packet| {
                let token = packet
                    .peer_manager_header()
                    .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
                    .then(|| authorization.clone())
                    .flatten();
                (packet, policy.clone(), token)
            }))
            .map(|_| ())
    }

    pub(crate) async fn flush_pending_packets(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        session: Arc<PeerSession>,
    ) -> Result<(), Error> {
        let state = self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession);
        if state.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if matches!(
            state.phase(),
            RelaySendPhase::AwaitingSession | RelaySendPhase::Confirming
        ) {
            return Ok(());
        }
        let _drain_guard = state.draining.lock().await;
        state.set_phase(RelaySendPhase::Draining);
        if state.finish_draining() {
            return Ok(());
        }

        tracing::debug!(
            ?dst_peer_id,
            count = state.packet_count(),
            "flushing pending packets after relay handshake"
        );

        loop {
            let Some(pending) =
                state.pop_batch_for_send(crate::tunnel::batch::MAX_PACKET_BATCH_SIZE)
            else {
                if state.finish_draining() {
                    break;
                }
                continue;
            };
            let policy = pending[0].1.clone();
            let ethernet_authority_valid = pending.iter().all(|(packet, _, _, authorization)| {
                packet.peer_manager_header().is_none_or(|header| {
                    header.packet_type != PacketType::Ethernet as u8
                        || self.full_ethernet_authorization_is_current(
                            dst_peer_id,
                            authorization.as_ref(),
                        )
                })
            });
            if !ethernet_authority_valid {
                let bytes = pending.iter().map(|(_, _, bytes, _)| *bytes).sum::<usize>();
                state.complete_send_batch(bytes, pending.len());
                tracing::debug!(
                    ?dst_peer_id,
                    "drop queued Ethernet after relay authority revocation"
                );
                continue;
            }
            let mut encrypted = PacketBatch::new();
            for (packet, _, _, _) in &pending {
                encrypted
                    .try_push(packet.clone())
                    .expect("the pending relay group is bounded");
            }
            // Revalidate after packet cloning and immediately before encryption.
            let ethernet_authority_valid = pending.iter().all(|(packet, _, _, authorization)| {
                packet.peer_manager_header().is_none_or(|header| {
                    header.packet_type != PacketType::Ethernet as u8
                        || self.full_ethernet_authorization_is_current(
                            dst_peer_id,
                            authorization.as_ref(),
                        )
                })
            });
            if !ethernet_authority_valid {
                let bytes = pending.iter().map(|(_, _, bytes, _)| *bytes).sum::<usize>();
                state.complete_send_batch(bytes, pending.len());
                continue;
            }
            if let Err(error) =
                session.encrypt_payload_batch(self.my_peer_id, dst_peer_id, &mut encrypted)
            {
                tracing::debug!(?error, ?dst_peer_id, "pending relay encryption failed");
                state.requeue_failed_batch(pending);
                if !session.is_valid() {
                    state.set_phase(RelaySendPhase::AwaitingSession);
                }
                self.schedule_flush_retry(dst_peer_id, session.clone());
                return Ok(());
            }
            // Revalidate after encryption and immediately before the actual send.
            let ethernet_authority_valid = pending.iter().all(|(packet, _, _, authorization)| {
                packet.peer_manager_header().is_none_or(|header| {
                    header.packet_type != PacketType::Ethernet as u8
                        || self.full_ethernet_authorization_is_current(
                            dst_peer_id,
                            authorization.as_ref(),
                        )
                })
            });
            if !ethernet_authority_valid {
                let bytes = pending.iter().map(|(_, _, bytes, _)| *bytes).sum::<usize>();
                state.complete_send_batch(bytes, pending.len());
                continue;
            }
            if let Err(error) = self
                .send_via_next_hop_batch_at(encrypted, dst_peer_id, policy, None)
                .await
            {
                tracing::debug!(?error, ?dst_peer_id, "pending relay send failed");
                state.requeue_failed_batch(pending);
                self.schedule_flush_retry(dst_peer_id, session.clone());
                return Ok(());
            }
            let bytes = pending.iter().map(|(_, _, bytes, _)| *bytes).sum::<usize>();
            state.complete_send_batch(bytes, pending.len());
        }
        state.retry_attempt.store(0, Ordering::Release);
        Ok(())
    }

    async fn flush_pending_if_ready(self: &Arc<Self>, dst_peer_id: PeerId) {
        let session_key = SessionKey::new(
            self.global_ctx.get_network_identity().network_name,
            dst_peer_id,
        );
        if let Some(session) = self.peer_session_store.get(&session_key)
            && let Some(state) = self.send_state(dst_peer_id)
            && state.phase() == RelaySendPhase::Draining
        {
            if let Err(error) = self
                .flush_pending_packets(dst_peer_id, session.clone())
                .await
            {
                tracing::debug!(?error, ?dst_peer_id, "relay queue drain failed");
                self.schedule_flush_retry(dst_peer_id, session);
            }
        }
    }

    fn schedule_flush_retry(self: &Arc<Self>, dst_peer_id: PeerId, session: Arc<PeerSession>) {
        let Some(state) = self.send_state(dst_peer_id) else {
            return;
        };
        if state.closed.load(Ordering::Acquire) {
            return;
        }
        if state
            .retry_scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let attempt = state.retry_attempt.fetch_add(1, Ordering::AcqRel);
        if attempt >= RELAY_FLUSH_RETRY_MAX_ATTEMPTS {
            state.retry_scheduled.store(false, Ordering::Release);
            state.set_phase(RelaySendPhase::AwaitingSession);
            return;
        }
        let delay_ms = HANDSHAKE_CONFIRM_RETRY_MS
            .saturating_mul(1_u64 << attempt.min(4))
            .min(HANDSHAKE_CONFIRM_RETRY_MAX_MS);
        let relay_map = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            state.retry_scheduled.store(false, Ordering::Release);
            if state.phase() == RelaySendPhase::AwaitingSession {
                let _ = relay_map
                    .ensure_session(dst_peer_id, NextHopPolicy::LeastHop)
                    .await;
            } else if state.phase() == RelaySendPhase::Draining {
                if let Err(error) = relay_map
                    .flush_pending_packets(dst_peer_id, session.clone())
                    .await
                {
                    tracing::debug!(?error, ?dst_peer_id, "relay queue retry drain failed");
                    relay_map.schedule_flush_retry(dst_peer_id, session);
                }
            }
        });
    }

    pub(crate) fn pending_packet_count(&self, dst_peer_id: PeerId) -> usize {
        self.send_state(dst_peer_id)
            .map(|state| state.packet_count())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn set_pending_packet_in_flight_for_test(&self, dst_peer_id: PeerId, value: bool) {
        self.ensure_send_state(dst_peer_id, RelaySendPhase::AwaitingSession)
            .set_in_flight_for_test(value);
    }

    pub fn has_session(&self, dst_peer_id: PeerId) -> bool {
        self.peer_session_store
            .get(&SessionKey::new(
                self.global_ctx.get_network_identity().network_name.clone(),
                dst_peer_id,
            ))
            .is_some()
    }

    pub async fn ensure_session(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<Arc<PeerSession>, Error> {
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        if let Some(session) = self.peer_session_store.get(&key) {
            let awaiting = self
                .send_state(dst_peer_id)
                .is_some_and(|state| state.phase() == RelaySendPhase::AwaitingSession);
            self.retry_pending_ready_receipt(dst_peer_id, session.clone());
            if !awaiting {
                self.bind_existing_relay_session_auth_if_missing(dst_peer_id, &session)?;
                return Ok(session);
            }
        }
        if self
            .pending_responder_handshake_acks
            .contains_key(&dst_peer_id)
        {
            return Err(Error::RouteError(Some(
                "relay responder confirmation is pending".to_string(),
            )));
        }

        let lock = self.get_handshake_lock(dst_peer_id);
        if let Ok(guard) = lock.try_lock_owned() {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone
                    .handshake_session(dst_peer_id, policy, Some(guard))
                    .await
            });
        };
        Err(Error::RouteError(Some(
            "relay handshake in progress".to_string(),
        )))
    }

    #[tracing::instrument(skip(self, _lock_guard), level = "debug", ret)]
    pub async fn handshake_session(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        _lock_guard: Option<OwnedMutexGuard<()>>,
    ) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        if let Some(session) = self.peer_session_store.get(&key)
            && self
                .send_state(dst_peer_id)
                .is_none_or(|state| state.phase() == RelaySendPhase::Ready)
        {
            self.bind_existing_relay_session_auth_if_missing(dst_peer_id, &session)?;
            self.retry_pending_ready_receipt(dst_peer_id, session.clone());
            self.flush_pending_packets(dst_peer_id, session).await?;
            return Ok(());
        }

        if let Some(next_retry_at) = self.states.get(&dst_peer_id).and_then(|v| v.next_retry_at)
            && Instant::now() < next_retry_at
        {
            return Err(Error::RouteError(Some(
                "relay handshake backoff".to_string(),
            )));
        }

        let mut last_err = None;
        for attempt in 0..HANDSHAKE_MAX_ATTEMPTS {
            if let Some(session) = self.peer_session_store.get(&key) {
                self.bind_existing_relay_session_auth_if_missing(dst_peer_id, &session)?;
                if let Some(state) = self.send_state(dst_peer_id)
                    && state.phase() == RelaySendPhase::AwaitingSession
                {
                    state.set_phase(RelaySendPhase::Draining);
                }
                self.register_handshake_success(dst_peer_id);
                self.retry_pending_ready_receipt(dst_peer_id, session.clone());
                self.flush_pending_packets(dst_peer_id, session).await?;
                return Ok(());
            }
            let ret = self
                .handshake_session_once(dst_peer_id, policy.clone())
                .await;
            match ret {
                Ok(session) => {
                    self.register_handshake_success(dst_peer_id);
                    self.retry_pending_ready_receipt(dst_peer_id, session.clone());
                    self.flush_pending_packets(dst_peer_id, session).await?;
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                    self.register_handshake_failure(dst_peer_id, attempt);
                    if attempt + 1 < HANDSHAKE_MAX_ATTEMPTS {
                        let backoff = HANDSHAKE_RETRY_BASE_MS.saturating_mul(1 << attempt);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                    }
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| Error::RouteError(Some("relay handshake failed".to_string()))))
    }

    #[tracing::instrument(skip(self), level = "debug", ret)]
    async fn handshake_session_once(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<Arc<PeerSession>, Error> {
        let network = self.global_ctx.get_network_identity();
        let session_key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        let (local_private_key, _local_public_key) = self.get_local_keypair()?;
        let remote_static = self
            .find_remote_static_pubkey(dst_peer_id)
            .ok_or_else(|| Error::RouteError(Some("remote static pubkey not found".to_string())))?;
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::RouteError(Some(format!("parse noise params failed: {e:?}"))))?;

        let builder = snow::Builder::new(params);
        let mut hs = builder
            .prologue(RELAY_NOISE_PROLOGUE)
            .map_err(|e| Error::RouteError(Some(format!("set prologue failed: {e:?}"))))?
            .local_private_key(&local_private_key)
            .map_err(|e| Error::RouteError(Some(format!("set local key failed: {e:?}"))))?
            .remote_public_key(&remote_static)
            .map_err(|e| Error::RouteError(Some(format!("set remote key failed: {e:?}"))))?
            .build_initiator()
            .map_err(|e| Error::RouteError(Some(format!("build initiator failed: {e:?}"))))?;

        let a_session_generation = self
            .peer_session_store
            .get(&session_key)
            .map(|s| s.session_generation());
        let recovery_identity = self.peer_session_store.in_doubt_identity(&session_key);
        if recovery_identity.is_some() {
            let retained_peer_key = self
                .peer_session_store
                .in_doubt_peer_static_pubkey(&session_key)
                .ok_or_else(|| {
                    Error::RouteError(Some(
                        "relay recovery reset requires a retained peer static key".to_string(),
                    ))
                })?;
            if remote_static.as_slice() != retained_peer_key.as_slice() {
                return Err(Error::RouteError(Some(
                    "relay recovery peer static key mismatch".to_string(),
                )));
            }
        }
        // Keep the exact prior receipt for atomic rotation after this transition.
        // Send its token only when this handshake is not recovering another one.
        let previous_receipt_identity = self
            .peer_session_store
            .initiator_receipt_identity(&session_key);
        let fallback_receipt_identity = recovery_identity
            .is_none()
            .then(|| previous_receipt_identity.clone())
            .flatten();
        let fallback_receipt_id = fallback_receipt_identity
            .as_ref()
            .map(|identity| identity.transition_id);
        let acknowledged_transition_id = if recovery_identity.is_none() {
            fallback_receipt_id
                .map(|transition_id| transition_id.to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let a_conn_id = uuid::Uuid::new_v4();
        let handshake_id = *a_conn_id.as_bytes();
        let msg1_pb = RelayNoiseMsg1Pb {
            version: RELAY_NOISE_VERSION,
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.global_ctx.get_flags().encryption_algorithm.clone(),
            recovery: recovery_identity.as_ref().map(recovery_pb_from_identity),
            acknowledged_transition_id: acknowledged_transition_id.clone(),
        };
        let payload = msg1_pb.encode_to_vec();
        let mut out = vec![0u8; 4096];
        let out_len = hs
            .write_message(&payload, &mut out)
            .map_err(|e| Error::RouteError(Some(format!("noise write msg1 failed: {e:?}"))))?;
        let (tx, rx) = oneshot::channel();
        self.pending_handshakes.insert(
            dst_peer_id,
            PendingHandshake {
                response_tx: std::sync::Mutex::new(Some(tx)),
                handshake_id,
                payload: out[..out_len].to_vec(),
                policy: policy.clone(),
            },
        );

        let send_res = self
            .send_handshake_packet(
                out[..out_len].to_vec(),
                handshake_id,
                PacketType::RelayHandshake,
                dst_peer_id,
                policy,
            )
            .await;

        if send_res.is_err() {
            self.remove_pending_handshake_if_matching(dst_peer_id, handshake_id);
        }
        send_res?;
        let msg2_pkt = match timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), rx).await {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(_)) => {
                self.remove_pending_handshake_if_matching(dst_peer_id, handshake_id);
                return Err(Error::RouteError(Some(
                    "relay handshake canceled".to_string(),
                )));
            }
            Err(_) => {
                self.remove_pending_handshake_if_matching(dst_peer_id, handshake_id);
                return Err(Error::RouteError(Some(
                    "relay handshake timeout".to_string(),
                )));
            }
        };

        let msg2_pb = self.decode_handshake_message::<RelayNoiseMsg2Pb>(
            PacketType::RelayHandshakeAck,
            &mut hs,
            msg2_pkt,
        );
        self.remove_pending_handshake_if_matching(dst_peer_id, handshake_id);
        let msg2_pb = msg2_pb?;
        validate_relay_protocol_version(msg2_pb.version)?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::RouteError(Some(
                "relay msg2 conn_id_echo mismatch".to_string(),
            )));
        }
        if !msg2_pb.accepted {
            if !msg2_pb.acknowledged_transition_id.is_empty() {
                return Err(Error::RouteError(Some(
                    "relay rejected msg2 has an acknowledgement".to_string(),
                )));
            }
            if let Some((_, (deferred, deferred_handshake_id))) =
                self.deferred_handshakes.remove(&dst_peer_id)
            {
                self.handle_relay_msg1(deferred, dst_peer_id, deferred_handshake_id)
                    .await?;
                if let Some(session) = self.peer_session_store.get(&session_key) {
                    return Ok(session);
                }
            }
            return Err(Error::RouteError(Some(
                "relay peer key is not ready".to_string(),
            )));
        }
        let echoed_acknowledgement = match msg2_pb.acknowledged_transition_id.len() {
            0 => None,
            RELAY_TRANSITION_ID_SIZE => Some(transition_id_from_wire(
                &msg2_pb.acknowledged_transition_id,
            )?),
            _ => {
                return Err(Error::RouteError(Some(
                    "invalid relay acknowledged transition id in msg2".to_string(),
                )));
            }
        };
        if let Some(expected_id) = fallback_receipt_id {
            if echoed_acknowledgement != Some(expected_id) {
                return Err(Error::RouteError(Some(
                    "relay acknowledged transition id mismatch".to_string(),
                )));
            }
        } else if echoed_acknowledgement.is_some() {
            return Err(Error::RouteError(Some(
                "unexpected relay acknowledgement echo".to_string(),
            )));
        }
        self.deferred_handshakes.remove(&dst_peer_id);

        let responder_session_metadata_id = msg2_pb
            .b_session_metadata_id
            .ok_or_else(|| {
                Error::RouteError(Some("relay msg2 session metadata is missing".to_string()))
            })
            .and_then(|metadata| Ok(uuid::Uuid::from(metadata)))?;
        let responder_transition_id = transition_id_from_wire(&msg2_pb.transition_id)?;
        let responder_recovery_identity = msg2_pb
            .recovery
            .clone()
            .map(|recovery| recovery_identity_from_pb(recovery, session_key.clone()))
            .transpose()?;
        if msg2_pb.recovery_reset {
            let local = recovery_identity.as_ref().ok_or_else(|| {
                Error::RouteError(Some(
                    "relay recovery reset has no local recovery identity".to_string(),
                ))
            })?;
            let wire = responder_recovery_identity.as_ref().ok_or_else(|| {
                Error::RouteError(Some("relay recovery reset identity is missing".to_string()))
            })?;
            if !recovery_identity_matches_wire(local, wire) {
                return Err(Error::RouteError(Some(
                    "relay recovery reset identity mismatch".to_string(),
                )));
            }
        } else if match (&recovery_identity, &responder_recovery_identity) {
            (Some(local), Some(wire)) => !recovery_identity_matches_wire(local, wire),
            (None, None) => false,
            _ => true,
        } {
            return Err(Error::RouteError(Some(
                "relay recovery identity mismatch".to_string(),
            )));
        }
        if let Some(identity) = &recovery_identity
            && responder_transition_id != identity.transition_id
        {
            return Err(Error::RouteError(Some(
                "relay transition id does not match recovery identity".to_string(),
            )));
        }
        if msg2_pb.recovery_reset {
            let identity = recovery_identity
                .as_ref()
                .expect("reset identity was checked");
            let expected_action = match identity.action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            };
            let metadata = uuid::Uuid::from(msg2_pb.b_session_metadata_id.ok_or_else(|| {
                Error::RouteError(Some("relay reset metadata is missing".to_string()))
            })?);
            if metadata != identity.session_metadata_id
                || msg2_pb.action != expected_action
                || msg2_pb.b_session_generation != identity.session_generation
                || msg2_pb.initial_epoch != identity.initial_epoch
                || msg2_pb.root_key_32.is_some()
                || !msg2_pb.acknowledged_transition_id.is_empty()
            {
                return Err(Error::RouteError(Some(
                    "relay recovery reset transition mismatch".to_string(),
                )));
            }
            self.deferred_handshakes.remove(&dst_peer_id);
            let transport = Arc::new(StdMutex::new(hs.into_transport_mode().map_err(
                |error| Error::RouteError(Some(format!("relay reset transport failed: {error:?}"))),
            )?));
            let (tx, rx) = oneshot::channel();
            self.pending_reset_acks.insert(
                dst_peer_id,
                PendingResetAck {
                    handshake_id,
                    identity: identity.clone(),
                    response_tx: std::sync::Mutex::new(Some(tx)),
                },
            );
            if let Err(error) = self
                .send_reset_transport_packet(
                    &transport,
                    identity,
                    handshake_id,
                    PacketType::RelayHandshakeReset,
                    dst_peer_id,
                )
                .await
            {
                self.pending_reset_acks
                    .remove_if(&dst_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                    });
                return Err(error);
            }
            let reset_ack = match timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), rx).await {
                Ok(Ok(packet)) => packet,
                Ok(Err(_)) => {
                    self.pending_reset_acks
                        .remove_if(&dst_peer_id, |_, pending| {
                            pending.handshake_id == handshake_id
                        });
                    return Err(Error::RouteError(Some(
                        "relay recovery reset acknowledgement canceled".to_string(),
                    )));
                }
                Err(_) => {
                    self.pending_reset_acks
                        .remove_if(&dst_peer_id, |_, pending| {
                            pending.handshake_id == handshake_id
                        });
                    return Err(Error::RouteError(Some(
                        "relay recovery reset acknowledgement timed out".to_string(),
                    )));
                }
            };
            self.pending_reset_acks
                .remove_if(&dst_peer_id, |_, pending| {
                    pending.handshake_id == handshake_id
                });
            let ack_identity = self.decode_reset_transport_message(
                &transport,
                &reset_ack,
                PacketType::RelayHandshakeResetAck,
                dst_peer_id,
            )?;
            let ack_handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE] = reset_ack
                .payload()
                .get(..RELAY_HANDSHAKE_ID_SIZE)
                .ok_or_else(|| {
                    Error::RouteError(Some("relay reset ack handshake id is missing".to_string()))
                })?
                .try_into()
                .expect("the reset handshake id length was checked");
            if ack_handshake_id != handshake_id
                || !recovery_identity_matches_wire(identity, &ack_identity)
            {
                return Err(Error::RouteError(Some(
                    "relay recovery reset acknowledgement mismatch".to_string(),
                )));
            }
            if !self
                .peer_session_store
                .cancel_initiator_reservation_exact(identity)
            {
                return Err(Error::RouteError(Some(
                    "relay recovery reset identity was not retained".to_string(),
                )));
            }
            if let Some((_, pending)) = self
                .pending_ready_receipts
                .remove_if(&dst_peer_id, |_, pending| {
                    pending.identity.transition_id == identity.transition_id
                })
            {
                pending.notify.notify_one();
            }
            return Err(Error::RouteError(Some(
                "authenticated relay recovery reset completed".to_string(),
            )));
        }

        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::RouteError(Some("invalid session action".to_string())))?;
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };
        let root_key_bytes = msg2_pb
            .root_key_32
            .as_deref()
            .filter(|v| v.len() == 32)
            .map(|v| {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(v);
                key_bytes
            });
        // Block data before the initiator publishes the session.
        let send_state = self.ensure_send_state(dst_peer_id, RelaySendPhase::Confirming);
        send_state.set_phase(RelaySendPhase::Confirming);
        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let recovery_active = recovery_identity.is_some();
        let reservation = if recovery_active {
            let identity = recovery_identity
                .as_ref()
                .expect("recovery identity is present when recovery is active");
            self.peer_session_store
                .resume_initiator_reservation(identity)
                .map_err(|error| {
                    send_state.set_phase(RelaySendPhase::AwaitingSession);
                    Error::RouteError(Some(format!("resume relay recovery failed: {error}")))
                })?
        } else {
            self.peer_session_store
                .prepare_initiator_action_with_transition_id(
                    &session_key,
                    session_action,
                    msg2_pb.b_session_generation,
                    root_key_bytes,
                    msg2_pb.initial_epoch,
                    algo,
                    msg2_pb.server_encryption_algorithm.clone(),
                    remote_static_key,
                    responder_transition_id,
                )
                .map_err(|e| {
                    send_state.set_phase(RelaySendPhase::AwaitingSession);
                    Error::RouteError(Some(format!("{e:?}")))
                })?
        };
        self.start_handshake_confirmation(
            dst_peer_id,
            handshake_id,
            reservation,
            responder_session_metadata_id,
            previous_receipt_identity,
        )
        .await?;
        self.peer_session_store.get(&session_key).ok_or_else(|| {
            Error::RouteError(Some("initiator session was not published".to_string()))
        })
    }

    fn register_handshake_success(&self, dst_peer_id: PeerId) {
        let mut entry = self.states.entry(dst_peer_id).or_default();
        entry.last_active_at = Instant::now();
        entry.failure_count = 0;
        entry.next_retry_at = None;
    }

    fn register_handshake_failure(&self, dst_peer_id: PeerId, attempt: u32) {
        let mut entry = self.states.entry(dst_peer_id).or_default();
        entry.failure_count = entry.failure_count.saturating_add(1);
        let backoff = HANDSHAKE_RETRY_BASE_MS.saturating_mul(1 << attempt);
        entry.next_retry_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    fn decode_handshake_message<MsgT: Message + Default>(
        &self,
        expected_type: PacketType,
        hs: &mut snow::HandshakeState,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error> {
        let hdr = pkt.peer_manager_header().ok_or_else(|| {
            Error::RouteError(Some("packet without peer manager header".to_string()))
        })?;
        if hdr.packet_type != expected_type as u8 {
            return Err(Error::RouteError(Some("packet type mismatch".to_string())));
        }
        let noise_payload = pkt
            .payload()
            .get(RELAY_HANDSHAKE_ID_SIZE..)
            .ok_or_else(|| Error::RouteError(Some("handshake id is missing".to_string())))?;
        let mut out = vec![0u8; 4096];
        let out_len = hs.read_message(noise_payload, &mut out).map_err(|error| {
            Error::RouteError(Some(format!(
                "noise read {expected_type:?} from {} to {} failed with encrypted={} and payload_len={}: {error:?}",
                hdr.from_peer_id.get(),
                hdr.to_peer_id.get(),
                hdr.is_encrypted(),
                pkt.payload().len(),
            )))
        })?;
        let msg = MsgT::decode(&out[..out_len])
            .map_err(|e| Error::RouteError(Some(format!("decode message failed: {e:?}"))))?;
        Ok(msg)
    }

    async fn handle_relay_reset_packet(
        self: &Arc<Self>,
        packet: ZCPacket,
        remote_peer_id: PeerId,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    ) -> Result<(), Error> {
        let Some(pending) = self
            .pending_responder_resets
            .get(&remote_peer_id)
            .map(|pending| pending.clone())
        else {
            return Err(Error::RouteError(Some(
                "relay reset is not pending".to_string(),
            )));
        };
        if pending.handshake_id != handshake_id {
            return Err(Error::RouteError(Some(
                "relay reset handshake id mismatch".to_string(),
            )));
        }
        let identity = self.decode_reset_transport_message(
            &pending.transport,
            &packet,
            PacketType::RelayHandshakeReset,
            remote_peer_id,
        )?;
        if !recovery_identity_matches_wire(&pending.identity, &identity) {
            return Err(Error::RouteError(Some(
                "relay reset identity mismatch".to_string(),
            )));
        }
        let mut out = vec![0_u8; 4096];
        let payload = encode_reset_identity(&pending.identity);
        let out_len = pending
            .transport
            .lock()
            .unwrap()
            .write_message(&payload, &mut out)
            .map_err(|error| {
                Error::RouteError(Some(format!("write relay reset ack failed: {error:?}")))
            })?;
        let mut ack_payload = Vec::with_capacity(RELAY_HANDSHAKE_ID_SIZE + out_len);
        ack_payload.extend_from_slice(&handshake_id);
        ack_payload.extend_from_slice(&out[..out_len]);
        let mut ack = ZCPacket::new_with_payload(&ack_payload);
        ack.fill_peer_manager_hdr(
            self.my_peer_id,
            remote_peer_id,
            PacketType::RelayHandshakeResetAck as u8,
        );
        let packet_len = ack.buf_len() as u64;
        self.send_via_next_hop(ack, remote_peer_id, NextHopPolicy::LeastHop)
            .await?;
        self.control_metrics.record_tx(packet_len);
        Ok(())
    }

    pub async fn handle_handshake_packet(self: &Arc<Self>, packet: ZCPacket) -> Result<(), Error> {
        let hdr = packet
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let src_peer_id = hdr.from_peer_id.get();
        let handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE] = packet
            .payload()
            .get(..RELAY_HANDSHAKE_ID_SIZE)
            .ok_or_else(|| Error::RouteError(Some("handshake id is missing".to_string())))?
            .try_into()
            .expect("the handshake id length was checked");
        self.control_metrics.record_rx(packet.buf_len() as u64);
        if hdr.packet_type == PacketType::RelayHandshakeReset as u8 {
            return self
                .handle_relay_reset_packet(packet, src_peer_id, handshake_id)
                .await;
        }
        if hdr.packet_type == PacketType::RelayHandshakeResetAck as u8 {
            if let Some(pending) = self.pending_reset_acks.get(&src_peer_id)
                && pending.handshake_id == handshake_id
            {
                let response_tx = pending.response_tx.lock().unwrap().take();
                drop(pending);
                if let Some(response_tx) = response_tx {
                    let _ = response_tx.send(packet);
                }
            }
            return Ok(());
        }
        match hdr.packet_type {
            x if x == PacketType::RelayHandshake as u8 => {
                tracing::debug!("handle_relay_msg1 from {:?}", src_peer_id);
                self.handle_relay_msg1(packet, src_peer_id, handshake_id)
                    .await
            }
            x if x == PacketType::RelayHandshakeAck as u8 => {
                if let Some(pending) = self.pending_handshakes.get(&src_peer_id)
                    && pending.handshake_id == handshake_id
                {
                    let response_tx = pending.response_tx.lock().unwrap().take();
                    drop(pending);
                    if let Some(response_tx) = response_tx {
                        let _ = response_tx.send(packet);
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_ready_receipt(
        self: &Arc<Self>,
        remote_peer_id: PeerId,
        identity: RelayReadyReceiptIdentity,
    ) -> Result<(), Error> {
        let session_key = SessionKey::new(
            self.global_ctx.get_network_identity().network_name,
            remote_peer_id,
        );
        let session = self.peer_session_store.get(&session_key).ok_or_else(|| {
            Error::RouteError(Some(
                "relay ready receipt has no active session".to_string(),
            ))
        })?;
        if session.metadata_session_id() != identity.session_metadata_id {
            return Err(Error::RouteError(Some(
                "relay ready receipt session metadata does not match".to_string(),
            )));
        }
        // A duplicate receipt can arrive after a later transition changes the
        // active root key. The completed identity is already authenticated by
        // the current session, so replay the ACK without reconciling old keys.
        if self.completed_ready_receipt(remote_peer_id, identity) {
            return self
                .send_ready_receipt_packet(
                    &session,
                    identity,
                    PacketType::RelayHandshakeReadyReceiptAck,
                    remote_peer_id,
                )
                .await;
        }
        let transition_identity = InitiatorTransitionIdentity::new(
            session_key.clone(),
            identity.session_metadata_id,
            identity.action,
            identity.session_generation,
            identity.initial_epoch,
            identity.transition_id,
            session.root_key_digest(),
        );
        let committed = self
            .peer_session_store
            .reconcile_active_responder_transition(&transition_identity)
            .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?
            .ok_or_else(|| {
                Error::RouteError(Some(
                    "relay ready receipt does not match a committed transition".to_string(),
                ))
            })?;
        if committed.action != identity.action
            || committed.session_generation != identity.session_generation
            || committed.initial_epoch != identity.initial_epoch
            || committed.transition_id != identity.transition_id
        {
            return Err(Error::RouteError(Some(
                "relay ready receipt transition does not match".to_string(),
            )));
        }

        let responder_lock = self
            .responder_handshake_locks
            .entry(remote_peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _responder_guard = responder_lock.lock().await;
        if self.peer_session_store.responder_recovery_id(&session_key)
            != Some(identity.transition_id)
        {
            if !self.completed_ready_receipt(remote_peer_id, identity) {
                return Err(Error::RouteError(Some(
                    "relay ready receipt proof is not pending".to_string(),
                )));
            }
        } else {
            let pending_next = self
                .pending_responder_handshake_acks
                .remove_if(&remote_peer_id, |_, pending| {
                    pending.prepared.proof_dependency() == Some(identity.transition_id)
                })
                .map(|(_, pending)| pending);
            if let Some(pending) = pending_next {
                if let Err(error) = pending.prepared.authenticate_recovery() {
                    self.pending_responder_handshake_acks
                        .insert(remote_peer_id, pending);
                    return Err(Error::RouteError(Some(format!(
                        "authenticate relay ready receipt failed: {error}"
                    ))));
                }
                self.pending_responder_handshake_acks
                    .insert(remote_peer_id, pending);
            } else if !self
                .peer_session_store
                .acknowledge_responder_recovery(&session_key, identity.transition_id)
            {
                return Err(Error::RouteError(Some(
                    "relay ready receipt proof changed".to_string(),
                )));
            }
        }
        self.record_completed_ready_receipt(remote_peer_id, identity);
        drop(_responder_guard);
        self.send_ready_receipt_packet(
            &session,
            identity,
            PacketType::RelayHandshakeReadyReceiptAck,
            remote_peer_id,
        )
        .await
    }

    async fn handle_ready_receipt_ack(
        &self,
        remote_peer_id: PeerId,
        identity: RelayReadyReceiptIdentity,
        verified_session_id: uuid::Uuid,
    ) -> Result<(), Error> {
        let session_key = SessionKey::new(
            self.global_ctx.get_network_identity().network_name,
            remote_peer_id,
        );
        let session = self.peer_session_store.get(&session_key).ok_or_else(|| {
            Error::RouteError(Some(
                "relay ready receipt ack has no active session".to_string(),
            ))
        })?;
        if session.metadata_session_id() != verified_session_id {
            return Err(Error::RouteError(Some(
                "relay ready receipt ack used an unexpected session".to_string(),
            )));
        }
        let receipt_identity = InitiatorTransitionIdentity::new(
            session_key.clone(),
            identity.session_metadata_id,
            identity.action,
            identity.session_generation,
            identity.initial_epoch,
            identity.transition_id,
            session.root_key_digest(),
        );
        let completed_ack = || {
            self.peer_session_store
                .initiator_receipt_identity(&session_key)
                .is_none()
                && self
                    .peer_session_store
                    .active_transition_matches(&receipt_identity)
        };
        let Some(pending) = self
            .pending_ready_receipts
            .get(&remote_peer_id)
            .map(|pending| pending.clone())
        else {
            if completed_ack() {
                return Ok(());
            }
            return Err(Error::RouteError(Some(
                "relay ready receipt acknowledgement owner is missing".to_string(),
            )));
        };
        if pending.identity != identity {
            return Err(Error::RouteError(Some(
                "relay ready receipt acknowledgement mismatch".to_string(),
            )));
        }
        if !self
            .peer_session_store
            .acknowledge_initiator_receipt_exact(&receipt_identity)
            && !completed_ack()
        {
            return Err(Error::RouteError(Some(
                "relay ready receipt was not pending".to_string(),
            )));
        }
        pending.outcome.store(1, Ordering::Release);
        pending.notify.notify_one();
        Ok(())
    }

    pub(crate) async fn handle_handshake_confirmation(
        self: &Arc<Self>,
        packet: ZCPacket,
    ) -> Result<(), Error> {
        let header = packet
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let remote_peer_id = header.from_peer_id.get();
        let packet_type = header.packet_type;
        let staged_ack = packet_type == PacketType::RelayHandshakeConfirmAck as u8
            || packet_type == PacketType::RelayHandshakeReadyAck as u8;
        if staged_ack
            && self
                .pending_confirmation_acks
                .get(&remote_peer_id)
                .is_some_and(|pending| pending.expires_at <= Instant::now())
        {
            self.cancel_pending_confirmation(remote_peer_id);
            return Err(Error::RouteError(Some(
                "relay confirmation transition expired".to_string(),
            )));
        }
        let verified_session_id = packet.verified_origin_session_id();
        if packet.verified_origin_peer_id() != Some(remote_peer_id) || verified_session_id.is_none()
        {
            return Err(Error::RouteError(Some(
                "relay confirmation is not session authenticated".to_string(),
            )));
        }
        let payload = packet.payload();
        if packet_type == PacketType::RelayHandshakeReadyReceipt as u8 {
            let identity = decode_relay_ready_receipt(payload)?;
            return self.handle_ready_receipt(remote_peer_id, identity).await;
        }
        if packet_type == PacketType::RelayHandshakeReadyReceiptAck as u8 {
            let identity = decode_relay_ready_receipt(payload)?;
            return self
                .handle_ready_receipt_ack(
                    remote_peer_id,
                    identity,
                    verified_session_id.expect("session authentication was checked"),
                )
                .await;
        }
        if payload.len() != RELAY_CONFIRMATION_PAYLOAD_SIZE {
            return Err(Error::RouteError(Some(
                "invalid confirmation payload".to_string(),
            )));
        }
        let handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE] = payload[..RELAY_HANDSHAKE_ID_SIZE]
            .try_into()
            .expect("the confirmation payload length was checked");
        let transition_id: [u8; RELAY_TRANSITION_ID_SIZE] = payload[RELAY_HANDSHAKE_ID_SIZE..]
            .try_into()
            .expect("the confirmation transition id length was checked");
        if packet_type == PacketType::RelayHandshakeConfirmAck as u8
            || packet_type == PacketType::RelayHandshakeReadyAck as u8
        {
            let Some(pending) = self.pending_confirmation_acks.get(&remote_peer_id) else {
                return Ok(());
            };
            if pending.handshake_id != handshake_id
                || Some(pending.session_id) != verified_session_id
                || pending.transition_id != transition_id
                || pending.expected_packet_type != packet_type
            {
                return Ok(());
            }
            if pending.outcome.load(Ordering::Acquire) == 1 {
                return Ok(());
            }
            if packet_type == PacketType::RelayHandshakeReadyAck as u8 {
                let identity = pending.transition_identity.clone();
                let receipt_session_metadata_id = pending.transition_identity.session_metadata_id;
                let previous_receipt_identity = pending.previous_receipt_identity.clone();
                let outcome = pending.outcome.clone();
                let notify = pending.notify.clone();
                drop(pending);
                let reservation = self
                    .peer_session_store
                    .resume_initiator_reservation(&identity)
                    .map_err(|error| {
                        Error::RouteError(Some(format!(
                            "resume relay initiator reservation failed: {error}"
                        )))
                    })?;
                let relay_identity = RelayConfirmationIdentity {
                    handshake_id,
                    session_id: verified_session_id.expect("session id was checked"),
                    transition_id,
                };
                self.commit_initiator_after_ready(
                    remote_peer_id,
                    relay_identity,
                    reservation,
                    receipt_session_metadata_id,
                    previous_receipt_identity,
                )
                .await?;
                outcome.store(1, Ordering::Release);
                notify.notify_one();
                return Ok(());
            }
            let Some(pending) = self.pending_confirmation_acks.get(&remote_peer_id) else {
                return Ok(());
            };
            if pending.handshake_id == handshake_id
                && pending.transition_id == transition_id
                && pending
                    .outcome
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                pending.notify.notify_one();
            }
            return Ok(());
        }
        if packet_type == PacketType::RelayHandshakeReady as u8 {
            let identity = RelayConfirmationIdentity {
                handshake_id,
                session_id: verified_session_id.expect("the session id was checked"),
                transition_id,
            };
            let state = self.send_state(remote_peer_id).ok_or_else(|| {
                Error::RouteError(Some("relay ready has no confirmation state".to_string()))
            })?;
            let current_confirmation =
                state.confirmation.lock().unwrap().as_ref() == Some(&identity);
            if !current_confirmation
                && !self.responder_handshake_completed_identity(remote_peer_id, identity)
            {
                return Err(Error::RouteError(Some(
                    "relay ready does not match the pending handshake".to_string(),
                )));
            }
            let responder_lock = self
                .responder_handshake_locks
                .entry(remote_peer_id)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone();
            let responder_guard = responder_lock.lock().await;
            let session_key = SessionKey::new(
                self.global_ctx.get_network_identity().network_name,
                remote_peer_id,
            );
            let session = if current_confirmation {
                let pending = self
                    .pending_responder_handshake_acks
                    .remove_if(&remote_peer_id, |_, pending| {
                        pending.handshake_id == handshake_id
                            && pending.transition_id == transition_id
                            && pending.prepared.session.metadata_session_id() == identity.session_id
                            && pending.deadline > Instant::now()
                    })
                    .map(|(_, pending)| pending);
                match pending {
                    Some(pending) => {
                        if !pending.recovery_active {
                            if let Err(error) = self
                                .peer_session_store
                                .commit_prepared_responder_transition(
                                    &session_key,
                                    &pending.prepared,
                                )
                            {
                                pending.prepared.cancel();
                                self.reset_confirmation_state(remote_peer_id, identity);
                                return Err(Error::RouteError(Some(error.to_string())));
                            }
                        }
                        let session = pending.prepared.session.clone();
                        if let Err(error) = self.bind_relay_session_auth(remote_peer_id, &session) {
                            self.peer_session_store
                                .remove_if_same(&session_key, &session);
                            self.reset_confirmation_state(remote_peer_id, identity);
                            return Err(error);
                        }
                        self.record_completed_responder_handshake(remote_peer_id, identity);
                        session
                    }
                    None => {
                        if !self.responder_handshake_completed_identity(remote_peer_id, identity) {
                            return Err(Error::RouteError(Some(
                                "relay ready has no pending responder transition".to_string(),
                            )));
                        }
                        let session =
                            self.peer_session_store.get(&session_key).ok_or_else(|| {
                                Error::RouteError(Some("relay ready has no session".to_string()))
                            })?;
                        if let Err(error) = self.bind_relay_session_auth(remote_peer_id, &session) {
                            self.peer_session_store
                                .remove_if_same(&session_key, &session);
                            return Err(error);
                        }
                        session
                    }
                }
            } else {
                let session = self.peer_session_store.get(&session_key).ok_or_else(|| {
                    Error::RouteError(Some("relay ready has no session".to_string()))
                })?;
                if let Err(error) = self.bind_relay_session_auth(remote_peer_id, &session) {
                    self.peer_session_store
                        .remove_if_same(&session_key, &session);
                    return Err(error);
                }
                session
            };
            if session.metadata_session_id() != identity.session_id {
                drop(responder_guard);
                return Err(Error::RouteError(Some(
                    "relay ready session does not match".to_string(),
                )));
            }
            drop(responder_guard);
            self.send_handshake_ready_packet(
                &session,
                handshake_id,
                transition_id,
                PacketType::RelayHandshakeReadyAck,
                remote_peer_id,
            )
            .await?;
            if current_confirmation {
                state.clear_confirmation(identity);
                state.set_phase(RelaySendPhase::Draining);
                self.flush_pending_packets(remote_peer_id, session).await?;
            }
            return Ok(());
        }
        if packet_type != PacketType::RelayHandshakeConfirm as u8 {
            return Err(Error::RouteError(Some(
                "invalid handshake confirmation type".to_string(),
            )));
        }

        let responder_lock = self
            .responder_handshake_locks
            .entry(remote_peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let responder_guard = responder_lock.lock().await;
        if self
            .pending_responder_handshake_acks
            .get(&remote_peer_id)
            .is_some_and(|pending| pending.deadline <= Instant::now())
        {
            self.cancel_pending_responder_handshake(remote_peer_id, Some(handshake_id));
        }
        let confirmation_identity = RelayConfirmationIdentity {
            handshake_id,
            session_id: verified_session_id.expect("the session id was checked"),
            transition_id,
        };
        let session = if let Some(pending) = self
            .pending_responder_handshake_acks
            .get(&remote_peer_id)
            .filter(|pending| {
                pending.handshake_id == handshake_id
                    && Some(pending.prepared.session.metadata_session_id()) == verified_session_id
                    && pending.transition_id == transition_id
                    && pending.deadline > Instant::now()
            })
            .map(|pending| pending.prepared.session.clone())
        {
            pending
        } else if self.responder_handshake_completed_identity(remote_peer_id, confirmation_identity)
        {
            let session_key = SessionKey::new(
                self.global_ctx.get_network_identity().network_name,
                remote_peer_id,
            );
            let session = self.peer_session_store.get(&session_key).ok_or_else(|| {
                Error::RouteError(Some("relay confirmation has no session".to_string()))
            })?;
            if Some(session.metadata_session_id()) != verified_session_id {
                return Err(Error::RouteError(Some(
                    "relay confirmation session does not match".to_string(),
                )));
            }
            session
        } else {
            return Err(Error::RouteError(Some(
                "relay confirmation does not match the pending handshake".to_string(),
            )));
        };
        self.extend_pending_responder_deadline(remote_peer_id, confirmation_identity);
        drop(responder_guard);
        self.send_handshake_confirmation_packet(
            &session,
            handshake_id,
            transition_id,
            PacketType::RelayHandshakeConfirmAck,
            remote_peer_id,
        )
        .await?;
        // Keep the responder barrier until the authenticated READY packet.
        Ok(())
    }

    async fn handle_relay_msg1(
        self: &Arc<Self>,
        msg1: ZCPacket,
        remote_peer_id: PeerId,
        handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE],
    ) -> Result<(), Error> {
        let expected_pubkey = self
            .find_remote_static_pubkey(remote_peer_id)
            .ok_or_else(|| Error::RouteError(Some("relay peer key is not ready".to_string())))?;
        let responder_lock = self
            .responder_handshake_locks
            .entry(remote_peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _responder_guard = responder_lock.lock().await;
        // Check for bidirectional handshake race condition.
        // If we are also waiting for a RelayHandshakeAck from this peer,
        // use deterministic rule: the peer with smaller peer_id becomes initiator.
        let (local_private_key, _local_public_key) = self.get_local_keypair()?;
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::RouteError(Some(format!("parse noise params failed: {e:?}"))))?;
        let builder = snow::Builder::new(params);
        let mut hs = builder
            .prologue(RELAY_NOISE_PROLOGUE)
            .map_err(|e| Error::RouteError(Some(format!("set prologue failed: {e:?}"))))?
            .local_private_key(&local_private_key)
            .map_err(|e| Error::RouteError(Some(format!("set local key failed: {e:?}"))))?
            .build_responder()
            .map_err(|e| Error::RouteError(Some(format!("build responder failed: {e:?}"))))?;

        let msg1_pb = self.decode_handshake_message::<RelayNoiseMsg1Pb>(
            PacketType::RelayHandshake,
            &mut hs,
            msg1.clone(),
        )?;
        validate_relay_protocol_version(msg1_pb.version)?;
        let message_conn_id = msg1_pb
            .a_conn_id
            .ok_or_else(|| Error::RouteError(Some("relay msg1 conn_id is missing".to_string())))?;
        let message_conn_id = uuid::Uuid::try_from(message_conn_id)
            .map_err(|error| Error::RouteError(Some(format!("invalid relay conn_id: {error}"))))?;
        if message_conn_id.as_bytes() != &handshake_id {
            return Err(Error::RouteError(Some(
                "relay msg1 clear handshake id mismatch".to_string(),
            )));
        }
        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        if remote_static != expected_pubkey {
            return Err(Error::RouteError(Some(format!(
                "responder: initiator static pubkey mismatch for peer {}, expected {} bytes, got {} bytes",
                remote_peer_id,
                expected_pubkey.len(),
                remote_static.len()
            ))));
        }

        if self.pending_handshakes.contains_key(&remote_peer_id) {
            // We have a pending handshake as initiator.
            // If remote_peer_id < my_peer_id, remote should be initiator, we should be responder.
            // Cancel our pending handshake and proceed as responder.
            if remote_peer_id < self.my_peer_id {
                tracing::debug!(
                    ?remote_peer_id,
                    my_peer_id = ?self.my_peer_id,
                    "bidirectional handshake race: yielding initiator role to smaller peer_id"
                );
                // Remove our pending handshake
                self.pending_handshakes.remove(&remote_peer_id);
            } else {
                let retransmit = self.pending_handshakes.get(&remote_peer_id).map(|pending| {
                    (
                        pending.payload.clone(),
                        pending.handshake_id,
                        pending.policy.clone(),
                    )
                });
                tracing::debug!(
                    ?remote_peer_id,
                    my_peer_id = ?self.my_peer_id,
                    "bidirectional handshake race: keeping initiator role due to smaller peer_id"
                );
                self.deferred_handshakes
                    .insert(remote_peer_id, (msg1, handshake_id));
                if let Some((payload, pending_handshake_id, policy)) = retransmit {
                    self.send_handshake_packet(
                        payload,
                        pending_handshake_id,
                        PacketType::RelayHandshake,
                        remote_peer_id,
                        policy,
                    )
                    .await?;
                }
                return Ok(());
            }
        }

        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };

        if self.responder_handshake_completed(remote_peer_id, handshake_id) {
            return Ok(());
        }
        if self
            .pending_responder_handshake_acks
            .get(&remote_peer_id)
            .is_some_and(|pending| pending.deadline <= Instant::now())
        {
            self.cancel_pending_responder_handshake(remote_peer_id, None);
        }
        if self
            .pending_responder_resets
            .get(&remote_peer_id)
            .is_some_and(|pending| pending.deadline <= Instant::now())
        {
            self.cancel_pending_responder_reset(remote_peer_id, None);
        }
        if self
            .pending_responder_handshake_acks
            .get(&remote_peer_id)
            .is_some_and(|pending| pending.handshake_id != handshake_id)
        {
            return Err(Error::RouteError(Some(
                "relay responder handshake is busy".to_string(),
            )));
        }
        if let Some(response) = self
            .pending_responder_handshake_acks
            .get(&remote_peer_id)
            .filter(|response| response.handshake_id == handshake_id)
            .map(|response| response.response.clone())
        {
            return self
                .send_handshake_packet(
                    response,
                    handshake_id,
                    PacketType::RelayHandshakeAck,
                    remote_peer_id,
                    NextHopPolicy::LeastHop,
                )
                .await;
        }
        if self
            .pending_responder_resets
            .get(&remote_peer_id)
            .is_some_and(|pending| pending.handshake_id != handshake_id)
        {
            return Err(Error::RouteError(Some(
                "relay responder reset is busy".to_string(),
            )));
        }
        if let Some(response) = self
            .pending_responder_resets
            .get(&remote_peer_id)
            .filter(|pending| pending.handshake_id == handshake_id)
            .map(|pending| pending.response.clone())
        {
            return self
                .send_handshake_packet(
                    response,
                    handshake_id,
                    PacketType::RelayHandshakeAck,
                    remote_peer_id,
                    NextHopPolicy::LeastHop,
                )
                .await;
        }

        let server_network_name = self.global_ctx.get_network_name();
        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let key = SessionKey::new(server_network_name.clone(), remote_peer_id);
        let recovery_identity = msg1_pb
            .recovery
            .clone()
            .map(|recovery| recovery_identity_from_pb(recovery, key.clone()))
            .transpose()?;
        if recovery_identity.is_some() && !msg1_pb.acknowledged_transition_id.is_empty() {
            return Err(Error::RouteError(Some(
                "relay recovery and acknowledgement cannot share one handshake".to_string(),
            )));
        }
        let responder_proof_pending =
            recovery_identity.is_none() && self.peer_session_store.has_responder_recovery(&key);
        let acknowledged_transition_id = if recovery_identity.is_none() {
            let acknowledged_transition_id = match msg1_pb.acknowledged_transition_id.len() {
                0 => None,
                RELAY_TRANSITION_ID_SIZE => Some(transition_id_from_wire(
                    &msg1_pb.acknowledged_transition_id,
                )?),
                _ => {
                    return Err(Error::RouteError(Some(
                        "invalid relay acknowledged transition id".to_string(),
                    )));
                }
            };
            if responder_proof_pending {
                let Some(acknowledged_transition_id) = acknowledged_transition_id else {
                    return Err(Error::RouteError(Some(
                        "relay responder recovery acknowledgement is missing".to_string(),
                    )));
                };
                Some(acknowledged_transition_id)
            } else {
                acknowledged_transition_id
            }
        } else {
            None
        };
        // Echo the exact durable initiator receipt when the authenticated
        // handshake carries one. A responder proof may be absent because a
        // previous ReadyReceipt already released it.
        let mut acknowledged_transition_id_echo = acknowledged_transition_id;
        let (upsert, recovery_active) = if let Some(identity) = recovery_identity {
            let Some(recovered) = self
                .peer_session_store
                .reconcile_active_responder_transition(&identity)
                .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?
            else {
                if self.peer_session_store.has_responder_recovery(&key)
                    || self.peer_session_store.has_pending_create(&key)
                    || self.peer_session_store.peek(&key).is_some()
                {
                    return Err(Error::RouteError(Some(
                        "relay recovery reset conflicts with local session state".to_string(),
                    )));
                }
                let msg2_pb = RelayNoiseMsg2Pb {
                    action: match identity.action {
                        PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                        PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                        PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
                    },
                    b_session_generation: identity.session_generation,
                    root_key_32: None,
                    initial_epoch: identity.initial_epoch,
                    b_conn_id: Some(uuid::Uuid::new_v4().into()),
                    a_conn_id_echo: msg1_pb.a_conn_id,
                    server_encryption_algorithm: algo,
                    version: RELAY_NOISE_VERSION,
                    accepted: true,
                    b_session_metadata_id: Some(identity.session_metadata_id.into()),
                    recovery: Some(recovery_pb_from_identity(&identity)),
                    transition_id: identity.transition_id.to_vec(),
                    acknowledged_transition_id: Vec::new(),
                    recovery_reset: true,
                };
                let payload = msg2_pb.encode_to_vec();
                let mut out = vec![0_u8; 4096];
                let out_len = hs.write_message(&payload, &mut out).map_err(|error| {
                    Error::RouteError(Some(format!(
                        "noise write relay reset msg2 failed: {error:?}"
                    )))
                })?;
                let response = out[..out_len].to_vec();
                let transport = Arc::new(StdMutex::new(hs.into_transport_mode().map_err(
                    |error| {
                        Error::RouteError(Some(format!("relay reset transport failed: {error:?}")))
                    },
                )?));
                let deadline = Instant::now()
                    + Duration::from_millis(
                        RESPONDER_CONFIRM_DEADLINE_MS + RELAY_CONFIRM_WINDOW_MS * 2,
                    );
                self.pending_responder_resets.insert(
                    remote_peer_id,
                    PendingResponderReset {
                        handshake_id,
                        identity: identity.clone(),
                        response: response.clone(),
                        transport,
                        deadline,
                    },
                );
                self.register_handshake_success(remote_peer_id);
                if let Err(error) = self
                    .send_handshake_packet(
                        response,
                        handshake_id,
                        PacketType::RelayHandshakeAck,
                        remote_peer_id,
                        NextHopPolicy::LeastHop,
                    )
                    .await
                {
                    self.cancel_pending_responder_reset(remote_peer_id, Some(handshake_id));
                    return Err(error);
                }
                let weak_self = Arc::downgrade(self);
                tokio::spawn(async move {
                    loop {
                        let Some(relay_map) = weak_self.upgrade() else {
                            break;
                        };
                        let Some(current_deadline) = relay_map
                            .pending_responder_resets
                            .get(&remote_peer_id)
                            .filter(|pending| pending.handshake_id == handshake_id)
                            .map(|pending| pending.deadline)
                        else {
                            break;
                        };
                        let remaining = current_deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            relay_map
                                .cancel_pending_responder_reset(remote_peer_id, Some(handshake_id));
                            break;
                        }
                        tokio::time::sleep(remaining).await;
                    }
                });
                return Ok(());
            };
            if recovered.action != identity.action
                || recovered.session_generation != identity.session_generation
                || recovered.initial_epoch != identity.initial_epoch
                || recovered.transition_id != identity.transition_id
                || recovered.session.metadata_session_id() != identity.session_metadata_id
            {
                return Err(Error::RouteError(Some(
                    "relay responder recovery identity mismatch".to_string(),
                )));
            }
            (
                crate::peers::peer_session::UpsertResponderSessionReturn::for_recovery(
                    recovered.session,
                    recovered.action,
                    recovered.session_generation,
                    recovered.root_key,
                    recovered.initial_epoch,
                    recovered.transition_id,
                    (!matches!(recovered.action, PeerSessionAction::Create))
                        .then_some(recovered.transition_revision),
                    self.peer_session_store.as_ref().clone(),
                    key.clone(),
                ),
                true,
            )
        } else if let Some(acknowledged_transition_id) = acknowledged_transition_id {
            if responder_proof_pending {
                (
                    self.peer_session_store
                        .acknowledge_and_prepare_responder_session(
                            &key,
                            acknowledged_transition_id,
                            algo.clone(),
                            msg1_pb.client_encryption_algorithm.clone(),
                            remote_static_key,
                        )
                        .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?,
                    false,
                )
            } else {
                (
                    self.peer_session_store
                        .prepare_responder_session(
                            &key,
                            algo.clone(),
                            msg1_pb.client_encryption_algorithm.clone(),
                            remote_static_key,
                        )
                        .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?,
                    false,
                )
            }
        } else {
            (
                self.peer_session_store
                    .prepare_responder_session(
                        &key,
                        algo.clone(),
                        msg1_pb.client_encryption_algorithm.clone(),
                        remote_static_key,
                    )
                    .map_err(|error| Error::RouteError(Some(format!("{error:?}"))))?,
                false,
            )
        };
        if let Some(proof_id) = upsert.proof_dependency() {
            if let Err(error) = upsert.authenticate_recovery() {
                upsert.cancel();
                return Err(Error::RouteError(Some(format!(
                    "authenticate relay responder recovery failed: {error}"
                ))));
            }
            acknowledged_transition_id_echo = Some(proof_id);
        }
        let transition_id = upsert.transition_id();
        let msg2_pb = RelayNoiseMsg2Pb {
            action: match upsert.action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation: upsert.session_generation,
            root_key_32: upsert.root_key.map(|k| k.to_vec()),
            initial_epoch: upsert.initial_epoch,
            b_conn_id: Some(uuid::Uuid::new_v4().into()),
            a_conn_id_echo: msg1_pb.a_conn_id,
            server_encryption_algorithm: algo,
            version: RELAY_NOISE_VERSION,
            accepted: true,
            b_session_metadata_id: Some(upsert.session.metadata_session_id().into()),
            recovery: recovery_active.then(|| msg1_pb.recovery.clone()).flatten(),
            transition_id: transition_id.to_vec(),
            acknowledged_transition_id: acknowledged_transition_id_echo
                .map(|transition_id| transition_id.to_vec())
                .unwrap_or_default(),
            recovery_reset: false,
        };
        let payload = msg2_pb.encode_to_vec();
        let mut out = vec![0u8; 4096];
        let out_len = match hs.write_message(&payload, &mut out) {
            Ok(out_len) => out_len,
            Err(error) => {
                if !recovery_active {
                    upsert.cancel();
                }
                return Err(Error::RouteError(Some(format!(
                    "noise write msg2 failed: {error:?}"
                ))));
            }
        };
        let response = out[..out_len].to_vec();
        let deadline = Instant::now()
            + Duration::from_millis(RESPONDER_CONFIRM_DEADLINE_MS + RELAY_CONFIRM_WINDOW_MS * 2);
        let session_id = upsert.session.metadata_session_id();
        self.set_confirmation_identity(
            remote_peer_id,
            RelayConfirmationIdentity {
                handshake_id,
                session_id,
                transition_id,
            },
        );
        self.pending_responder_handshake_acks.insert(
            remote_peer_id,
            PendingResponderHandshake {
                handshake_id,
                response: response.clone(),
                prepared: upsert,
                recovery_active,
                transition_id,
                deadline,
            },
        );

        let weak_self = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(relay_map) = weak_self.upgrade() else {
                    break;
                };
                let Some(current_deadline) = relay_map
                    .pending_responder_handshake_acks
                    .get(&remote_peer_id)
                    .filter(|pending| pending.handshake_id == handshake_id)
                    .map(|pending| pending.deadline)
                else {
                    break;
                };
                let remaining = current_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    relay_map
                        .cancel_pending_responder_handshake(remote_peer_id, Some(handshake_id));
                    break;
                }
                tokio::time::sleep(remaining).await;
            }
        });

        self.register_handshake_success(remote_peer_id);

        if let Err(error) = self
            .send_handshake_packet(
                response,
                handshake_id,
                PacketType::RelayHandshakeAck,
                remote_peer_id,
                NextHopPolicy::LeastHop,
            )
            .await
        {
            self.cancel_pending_responder_handshake(remote_peer_id, Some(handshake_id));
            return Err(error);
        }

        Ok(())
    }

    /// Decrypt ordinary relay data in session-homogeneous groups.
    ///
    /// Handshake and confirmation packets remain on the scalar path.
    /// A forged member cannot invalidate the shared session.
    pub(crate) fn decrypt_batch_if_needed(
        &self,
        batch: &mut PacketBatch,
    ) -> Vec<RelayBatchDecryptOutcome> {
        let mut outcomes = vec![RelayBatchDecryptOutcome::NotAttempted; batch.len()];
        let mut requires_bridge_grant = vec![false; batch.len()];
        let mut groups = HashMap::<(PeerId, uuid::Uuid), (Arc<PeerSession>, Vec<usize>)>::new();
        let network = self.global_ctx.get_network_identity();
        for (index, packet) in batch.iter().enumerate() {
            let Some(header) = packet.peer_manager_header() else {
                continue;
            };
            if !header.is_encrypted()
                || Self::is_handshake_packet_type(header.packet_type)
                || Self::is_handshake_confirmation_packet_type(header.packet_type)
            {
                continue;
            }
            requires_bridge_grant[index] =
                header.packet_type == PacketType::Ethernet as u8 && !header.is_hybrid_ip_ethernet();
            let from_peer_id = header.from_peer_id.get();
            let key = SessionKey::new(network.network_name.clone(), from_peer_id);
            let Some(session) = self.peer_session_store.peek(&key) else {
                outcomes[index] = RelayBatchDecryptOutcome::Failed;
                continue;
            };
            groups
                .entry((from_peer_id, session.metadata_session_id()))
                .or_insert_with(|| (session.clone(), Vec::new()))
                .1
                .push(index);
        }

        for ((from_peer_id, _session_id), (session, indexes)) in groups {
            let key = SessionKey::new(network.network_name.clone(), from_peer_id);
            let auth_snapshot = self.peer_map.origin_auth_snapshot();
            let group_requires_bridge_grant =
                indexes.iter().any(|index| requires_bridge_grant[*index]);
            let Ok((origin_entry, _bridge_grant)) = self.validate_relay_session_auth_from_snapshot(
                from_peer_id,
                &session,
                group_requires_bridge_grant,
                &auth_snapshot,
            ) else {
                for index in indexes {
                    outcomes[index] = RelayBatchDecryptOutcome::Failed;
                }
                continue;
            };
            let Some(session_public_key) = session.peer_static_pubkey() else {
                for index in indexes {
                    outcomes[index] = RelayBatchDecryptOutcome::Failed;
                }
                continue;
            };
            if session_public_key != origin_entry.noise_static_pubkey {
                for index in indexes {
                    outcomes[index] = RelayBatchDecryptOutcome::Failed;
                }
                continue;
            }
            let bridge_valid = auth_snapshot
                .lookup_grant(from_peer_id, OriginAuthCapability::FullEthernetBridge)
                .filter(|grant| grant.is_live(Instant::now()))
                .is_some_and(|grant| {
                    grant.noise_static_pubkey == session_public_key
                        && self
                            .relay_session_auth
                            .get(&from_peer_id)
                            .is_some_and(|binding| binding.bridge_revision == Some(grant.revision))
                });
            let batch_len = batch.len();
            let mut selected = [false; MAX_PACKET_BATCH_SIZE];
            let selected = &mut selected[..batch_len];
            for index in &indexes {
                selected[*index] = true;
            }
            let keep = [true; MAX_PACKET_BATCH_SIZE];
            let keep = &keep[..batch_len];
            let process_result =
                batch.process_selected_with_keep_flags(&selected, &keep, |packets| {
                    let decrypt_results =
                        session.decrypt_payload_batch(from_peer_id, self.my_peer_id, packets);
                    for (index, (packet, decrypt_result)) in indexes
                        .iter()
                        .copied()
                        .zip(packets.iter_mut().zip(decrypt_results))
                    {
                        if decrypt_result.is_err()
                            || verify_and_remove_relay_origin_proof(packet).is_err()
                        {
                            outcomes[index] = RelayBatchDecryptOutcome::Failed;
                            continue;
                        }
                        let packet_type = packet
                            .peer_manager_header()
                            .map(|header| header.packet_type)
                            .unwrap_or_default();
                        if packet_type == PacketType::Ethernet as u8 && !bridge_valid {
                            outcomes[index] = RelayBatchDecryptOutcome::Failed;
                            continue;
                        }
                        if !packet.set_verified_origin(
                            from_peer_id,
                            origin_entry.identity_type,
                            SecureAuthLevel::PeerVerified,
                            session.metadata_session_id(),
                        ) {
                            outcomes[index] = RelayBatchDecryptOutcome::Failed;
                            continue;
                        }
                        outcomes[index] = RelayBatchDecryptOutcome::Decrypted;
                    }
                    Ok::<SmallVec<[bool; MAX_PACKET_BATCH_SIZE]>, Error>(
                        SmallVec::from_elem(true, packets.len()),
                    )
                });
            if process_result.is_err() {
                for index in indexes {
                    outcomes[index] = RelayBatchDecryptOutcome::Failed;
                }
            } else {
                self.peer_session_store.touch_if_same(&key, &session);
                self.states.entry(from_peer_id).or_default().last_active_at = Instant::now();
            }
        }
        outcomes
    }

    pub async fn decrypt_if_needed(self: &Arc<Self>, packet: &mut ZCPacket) -> Result<bool, Error> {
        let hdr = packet
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let from_peer_id = hdr.from_peer_id.get();
        let packet_type = hdr.packet_type;
        let is_confirmation = Self::is_handshake_confirmation_packet_type(packet_type);
        if is_confirmation {
            self.control_metrics.record_rx(packet.buf_len() as u64);
        }
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), from_peer_id);
        let active_session = self.peer_session_store.peek(&key);
        let staged_confirmation = if is_confirmation
            && (packet_type == PacketType::RelayHandshakeConfirmAck as u8
                || packet_type == PacketType::RelayHandshakeReadyAck as u8)
        {
            self.get_live_staged_confirmation(from_peer_id)
        } else {
            None
        };
        let pending_responder_session = if is_confirmation
            && (packet_type == PacketType::RelayHandshakeConfirm as u8
                || packet_type == PacketType::RelayHandshakeReady as u8)
        {
            self.pending_responder_handshake_acks
                .get(&from_peer_id)
                .map(|pending| pending.prepared.session.clone())
        } else {
            None
        };
        let session = pending_responder_session
            .clone()
            .or_else(|| {
                staged_confirmation
                    .as_ref()
                    .map(|(session, _, _, _)| session.clone())
            })
            .or_else(|| active_session.clone());
        let Some(session) = session else {
            tracing::debug!(
                "relay session not found for peer {}, try handshake",
                from_peer_id
            );
            if !is_confirmation && !Self::is_handshake_packet_type(packet_type) {
                // Ordinary encrypted data cannot create a session. Only the
                // explicit handshake path may reserve session state.
                return Ok(false);
            }
            self.ensure_session(from_peer_id, NextHopPolicy::LeastHop)
                .await?;
            return Ok(false);
        };
        session.decrypt_payload(from_peer_id, self.my_peer_id, packet)?;
        verify_and_remove_relay_origin_proof(packet)?;
        if let Some((
            expected_session,
            expected_handshake_id,
            expected_session_id,
            expected_transition_id,
        )) = staged_confirmation.as_ref()
        {
            if !Arc::ptr_eq(&session, expected_session)
                || expected_session.metadata_session_id() != *expected_session_id
            {
                return Err(Error::RouteError(Some(
                    "relay confirmation used an unexpected staged session".to_string(),
                )));
            }
            let payload = packet.payload();
            if payload.len() != RELAY_CONFIRMATION_PAYLOAD_SIZE {
                return Err(Error::RouteError(Some(
                    "invalid staged relay confirmation payload".to_string(),
                )));
            }
            let received_handshake_id: [u8; RELAY_HANDSHAKE_ID_SIZE] = payload
                [..RELAY_HANDSHAKE_ID_SIZE]
                .try_into()
                .expect("the staged confirmation payload length was checked");
            let received_transition_id: [u8; RELAY_TRANSITION_ID_SIZE] = payload
                [RELAY_HANDSHAKE_ID_SIZE..]
                .try_into()
                .expect("the staged confirmation transition id length was checked");
            if received_handshake_id != *expected_handshake_id
                || received_transition_id != *expected_transition_id
            {
                return Err(Error::RouteError(Some(
                    "relay confirmation does not match the staged transition".to_string(),
                )));
            }
        }
        let requires_bridge_grant = packet_type == PacketType::Ethernet as u8
            && packet
                .peer_manager_header()
                .is_none_or(|header| !header.is_hybrid_ip_ethernet());
        let transitional_session = pending_responder_session
            .as_ref()
            .is_some_and(|pending| Arc::ptr_eq(&session, pending))
            || staged_confirmation
                .as_ref()
                .is_some_and(|(staged, _, _, _)| Arc::ptr_eq(&session, staged));
        if !transitional_session {
            self.bind_existing_relay_session_auth_if_missing(from_peer_id, &session)?;
        }
        let auth_snapshot = self.peer_map.origin_auth_snapshot();
        let authority = if transitional_session {
            self.validate_relay_session_identity_from_snapshot(
                from_peer_id,
                &session,
                requires_bridge_grant,
                &auth_snapshot,
            )
        } else {
            self.validate_relay_session_auth_from_snapshot(
                from_peer_id,
                &session,
                requires_bridge_grant,
                &auth_snapshot,
            )
        };
        let (origin_entry, bridge_grant) = match authority {
            Ok(authority) => authority,
            Err(error) => {
                session.invalidate();
                self.peer_session_store.remove_if_same(&key, &session);
                if let Some(state) = self.send_state(from_peer_id) {
                    state.set_phase(RelaySendPhase::AwaitingSession);
                }
                return Err(error);
            }
        };
        let identity_type = origin_entry.identity_type;
        let session_public_key = session.peer_static_pubkey().ok_or_else(|| {
            Error::RouteError(Some(
                "relay session has no authenticated peer key".to_string(),
            ))
        })?;
        if session_public_key != origin_entry.noise_static_pubkey {
            session.invalidate();
            self.peer_session_store.remove_if_same(&key, &session);
            if let Some(state) = self.send_state(from_peer_id) {
                state.set_phase(RelaySendPhase::AwaitingSession);
            }
            return Err(Error::RouteError(Some(
                "relay session key does not match the authenticated route".to_string(),
            )));
        }
        let origin_secure_auth_level = if bridge_grant.is_some() {
            // A bridge grant is scoped to complete Ethernet and never creates
            // generic authority. The generic identity above still supplies the
            // origin role for all packet types.
            SecureAuthLevel::PeerVerified
        } else if matches!(
            origin_entry.secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed | SecureAuthLevel::PeerVerified
        ) {
            // Relay origin assurance is local evidence. Network-secret proof on a
            // different hop does not transfer administrative authority.
            SecureAuthLevel::PeerVerified
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        if !packet.set_verified_origin(
            from_peer_id,
            identity_type,
            origin_secure_auth_level,
            session.metadata_session_id(),
        ) {
            return Err(Error::RouteError(Some(
                "relay origin metadata conflicts with the verified session".to_string(),
            )));
        }
        self.peer_session_store.touch_if_same(&key, &session);
        self.states.entry(from_peer_id).or_default().last_active_at = Instant::now();
        Ok(true)
    }

    pub fn evict_idle_sessions(&self, idle: Duration) {
        let now = Instant::now();
        let expired = self
            .pending_responder_handshake_acks
            .iter()
            .filter_map(|entry| (entry.deadline <= now).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for peer_id in expired {
            self.cancel_pending_responder_handshake(peer_id, None);
            self.cancel_pending_responder_reset(peer_id, None);
        }
        let mut to_remove = Vec::new();
        for entry in self.states.iter() {
            if now.duration_since(entry.last_active_at) > idle {
                to_remove.push(*entry.key());
            }
        }
        for peer_id in to_remove {
            self.cancel_pending_responder_handshake(peer_id, None);
            self.cancel_pending_responder_reset(peer_id, None);
            self.states.remove(&peer_id);
            self.relay_session_auth.remove(&peer_id);
            self.pending_handshakes.remove(&peer_id);
            self.deferred_handshakes.remove(&peer_id);
            self.handshake_locks.remove(&peer_id);
            self.responder_handshake_locks.remove(&peer_id);
            if let Some((_, state)) = self.send_states.remove(&peer_id) {
                state.close();
            }
            self.completed_responder_handshakes.remove(&peer_id);
            self.cancel_pending_confirmation(peer_id);
            self.completed_ready_receipts.remove(&peer_id);
        }
        shrink_dashmap(&self.states, None);
        shrink_dashmap(&self.pending_handshakes, None);
        shrink_dashmap(&self.deferred_handshakes, None);
        shrink_dashmap(&self.handshake_locks, None);
        shrink_dashmap(&self.responder_handshake_locks, None);
        shrink_dashmap(&self.send_states, None);
        shrink_dashmap(&self.pending_responder_handshake_acks, None);
        shrink_dashmap(&self.pending_responder_resets, None);
        shrink_dashmap(&self.pending_reset_acks, None);
        shrink_dashmap(&self.completed_responder_handshakes, None);
        shrink_dashmap(&self.pending_confirmation_acks, None);
        shrink_dashmap(&self.pending_ready_receipts, None);
        shrink_dashmap(&self.completed_ready_receipts, None);
    }

    pub fn has_state(&self, peer_id: PeerId) -> bool {
        self.states.contains_key(&peer_id)
    }

    /// Clear durable session recovery records after verified peer removal.
    ///
    /// The static key must come from the authenticated peer record. A mismatch
    /// leaves recovery state unchanged and returns false.
    pub fn clear_peer_session_records_if_static_key_matches(
        &self,
        peer_id: PeerId,
        peer_static_pubkey: [u8; 32],
    ) -> bool {
        let key = SessionKey::new(self.global_ctx.get_network_name(), peer_id);
        self.peer_session_store
            .clear_peer_records_if_static_key_matches(&key, peer_static_pubkey)
    }

    pub fn failure_count(&self, peer_id: PeerId) -> Option<u32> {
        self.states.get(&peer_id).map(|v| v.failure_count)
    }

    pub fn is_backoff_active(&self, peer_id: PeerId) -> bool {
        self.states
            .get(&peer_id)
            .and_then(|v| v.next_retry_at)
            .is_some_and(|ts| Instant::now() < ts)
    }

    /// Remove relay-specific state for a specific peer.
    /// This does NOT remove the session from PeerSessionStore, because the
    /// session lifecycle is independent of any particular connection type
    /// (relay or direct). The session may still be used by direct connections
    /// or for fast reconnection (Join instead of Create).
    pub fn remove_peer(&self, peer_id: PeerId) {
        self.cancel_pending_responder_handshake(peer_id, None);
        self.cancel_pending_responder_reset(peer_id, None);
        self.states.remove(&peer_id);
        self.relay_session_auth.remove(&peer_id);
        self.pending_handshakes.remove(&peer_id);
        self.deferred_handshakes.remove(&peer_id);
        self.handshake_locks.remove(&peer_id);
        self.responder_handshake_locks.remove(&peer_id);
        if let Some((_, state)) = self.send_states.remove(&peer_id) {
            state.close();
        }
        self.completed_responder_handshakes.remove(&peer_id);
        self.cancel_pending_confirmation(peer_id);
        if let Some((_, pending)) = self.pending_ready_receipts.remove(&peer_id) {
            pending.notify.notify_one();
        }
        self.completed_ready_receipts.remove(&peer_id);
        shrink_dashmap(&self.states, None);
        shrink_dashmap(&self.pending_handshakes, None);
        shrink_dashmap(&self.deferred_handshakes, None);
        shrink_dashmap(&self.handshake_locks, None);
        shrink_dashmap(&self.responder_handshake_locks, None);
        shrink_dashmap(&self.send_states, None);
        shrink_dashmap(&self.pending_responder_handshake_acks, None);
        shrink_dashmap(&self.completed_responder_handshakes, None);
        shrink_dashmap(&self.pending_confirmation_acks, None);
        shrink_dashmap(&self.pending_ready_receipts, None);
        shrink_dashmap(&self.completed_ready_receipts, None);

        tracing::debug!(?peer_id, "RelayPeerMap removed peer relay state");
    }
}

#[cfg(test)]
mod relay_origin_proof_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };

    use quanta::Instant;
    use tokio::sync::Notify;
    use tokio::time::Duration;

    use super::{
        HANDSHAKE_CONFIRM_RETRY_MS, PendingConfirmationAck, RELAY_HANDSHAKE_ID_SIZE,
        RELAY_NOISE_VERSION, RELAY_QUEUE_MAX_BYTES_PER_PEER, RELAY_TRANSITION_ID_SIZE,
        RelayConfirmationIdentity, RelayPeerMap, RelaySendPhase, RelaySendState,
        attach_relay_origin_proof, recovery_identity_from_pb, recovery_identity_matches_wire,
        recovery_pb_from_identity, transition_id_from_wire, validate_relay_protocol_version,
        verify_and_remove_relay_origin_proof,
    };
    use crate::common::{
        PeerId,
        global_ctx::{NetworkIdentity, tests::get_mock_global_ctx_with_network},
    };
    use crate::peers::{
        create_packet_recv_chan,
        peer_map::PeerMap,
        peer_session::{
            INITIATOR_RECOVERY_LIFETIME, InitiatorTransitionIdentity, PeerSession,
            PeerSessionAction, PeerSessionStore, SessionKey,
        },
        route_trait::NextHopPolicy,
    };
    use crate::tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    };

    fn queue_packet(payload_len: usize) -> ZCPacket {
        let payload = vec![0_u8; payload_len];
        let mut packet = ZCPacket::new_with_payload(&payload);
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        packet
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_relay_handshake_does_not_retain_a_responder_lock() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "relay-admission".to_string(),
            "relay-secret".to_string(),
        )));
        let peer_map = Arc::new(PeerMap::new(packet_send, ctx.clone(), 10));
        let store = Arc::new(PeerSessionStore::new());
        let relay_map = RelayPeerMap::new(peer_map, None, ctx, 10, store, None);
        let mut packet = ZCPacket::new_with_payload(&[0; RELAY_HANDSHAKE_ID_SIZE + 1]);
        packet.fill_peer_manager_hdr(999, 10, PacketType::RelayHandshake as u8);

        assert!(relay_map.handle_handshake_packet(packet).await.is_err());
        assert!(relay_map.responder_handshake_locks.is_empty());
    }

    #[test]
    fn relay_queue_rejects_large_packet_without_retaining_it() {
        let state = RelaySendState::new(RelaySendPhase::AwaitingSession);
        let error = state.enqueue(
            queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER),
            NextHopPolicy::LeastHop,
            None,
        );
        assert!(error.is_err());
        assert_eq!(state.packet_count(), 0);
        state.close();
    }

    #[test]
    fn relay_queue_batch_admission_is_atomic_and_close_releases_budget() {
        let state = RelaySendState::new(RelaySendPhase::AwaitingSession);
        let packets = [
            queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER / 2),
            queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER / 2),
            queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER / 2),
        ];
        assert!(
            state
                .enqueue_batch(packets.into_iter().map(|packet| (
                    packet,
                    NextHopPolicy::LeastHop,
                    None
                )),)
                .is_err()
        );
        assert_eq!(state.packet_count(), 0);
        state.close();

        let next = RelaySendState::new(RelaySendPhase::AwaitingSession);
        assert!(
            next.enqueue(
                queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER - 256),
                NextHopPolicy::LeastHop,
                None
            )
            .is_ok()
        );
        next.close();
        let after_close = RelaySendState::new(RelaySendPhase::AwaitingSession);
        assert!(
            after_close
                .enqueue(
                    queue_packet(RELAY_QUEUE_MAX_BYTES_PER_PEER - 256),
                    NextHopPolicy::LeastHop,
                    None
                )
                .is_ok()
        );
        after_close.close();
    }

    #[test]
    fn current_relay_protocol_rejects_old_versions() {
        assert!(validate_relay_protocol_version(RELAY_NOISE_VERSION).is_ok());
        assert!(validate_relay_protocol_version(RELAY_NOISE_VERSION - 1).is_err());
    }

    #[test]
    fn relay_origin_proof_round_trips_the_original_payload() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_exit_node(true);

        attach_relay_origin_proof(&mut packet).unwrap();
        verify_and_remove_relay_origin_proof(&mut packet).unwrap();

        assert_eq!(packet.payload(), b"relay payload");
        let header = packet.peer_manager_header().unwrap();
        assert_eq!(header.from_peer_id.get(), 7);
        assert_eq!(header.to_peer_id.get(), 9);
        assert_eq!(header.packet_type, PacketType::Data as u8);
    }

    #[test]
    fn relay_origin_proof_rejects_a_changed_packet_type() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet.mut_peer_manager_header().unwrap().packet_type = PacketType::RpcReq as u8;

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_origin_proof_rejects_a_changed_origin() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet
            .mut_peer_manager_header()
            .unwrap()
            .from_peer_id
            .set(8);

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_origin_proof_binds_the_complete_flow_shard() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        packet.mut_peer_manager_header().unwrap().set_flow_shard(1);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet.mut_peer_manager_header().unwrap().set_flow_shard(2);

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_origin_proof_survives_route_policy_changes_across_three_relays() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_latency_first(true)
            .set_speed_first(true);

        for hop in 0..4 {
            attach_relay_origin_proof(&mut packet).unwrap();
            if hop >= 2 {
                // Relays may clear route policy after the third hop.
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_latency_first(false)
                    .set_speed_first(false);
            }
            verify_and_remove_relay_origin_proof(&mut packet).unwrap();
            packet.mut_peer_manager_header().unwrap().forward_counter += 1;
        }
    }

    #[test]
    fn relay_origin_proof_rejects_a_changed_stable_flag() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet.mut_peer_manager_header().unwrap().set_no_proxy(true);

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_origin_proof_rejects_a_changed_reserved_flag() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet.mut_peer_manager_header().unwrap().flags ^= 0x80;

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_origin_proof_rejects_changed_critical_control_state() {
        let mut packet = ZCPacket::new_with_payload(b"relay payload");
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);
        attach_relay_origin_proof(&mut packet).unwrap();
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);

        assert!(verify_and_remove_relay_origin_proof(&mut packet).is_err());
    }

    #[test]
    fn relay_recovery_identity_round_trips_without_key_material() {
        let identity = InitiatorTransitionIdentity::new(
            SessionKey::new("relay-test".to_string(), 19),
            uuid::Uuid::new_v4(),
            PeerSessionAction::Sync,
            4,
            8,
            [0x12; 16],
            [0x5a; 32],
        );
        let wire = recovery_pb_from_identity(&identity);
        let decoded = recovery_identity_from_pb(wire, identity.session_key.clone()).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn relay_recovery_identity_rejects_invalid_digest() {
        let identity = InitiatorTransitionIdentity::new(
            SessionKey::new("relay-test".to_string(), 20),
            uuid::Uuid::new_v4(),
            PeerSessionAction::Create,
            1,
            0,
            [0x13; 16],
            [0x33; 32],
        );
        let mut wire = recovery_pb_from_identity(&identity);
        wire.root_key_digest.pop();
        assert!(recovery_identity_from_pb(wire, identity.session_key).is_err());
    }

    #[test]
    fn relay_recovery_identity_rejects_zero_transition_id() {
        let identity = InitiatorTransitionIdentity::new(
            SessionKey::new("relay-test".to_string(), 22),
            uuid::Uuid::new_v4(),
            PeerSessionAction::Create,
            1,
            0,
            [0x22; 16],
            [0x44; 32],
        );
        let mut wire = recovery_pb_from_identity(&identity);
        wire.transition_id.fill(0);
        assert!(recovery_identity_from_pb(wire, identity.session_key).is_err());
        assert!(transition_id_from_wire(&[0; RELAY_TRANSITION_ID_SIZE]).is_err());
    }

    #[test]
    fn relay_recovery_ignores_private_local_revision() {
        let mut local = InitiatorTransitionIdentity::new(
            SessionKey::new("relay-test".to_string(), 21),
            uuid::Uuid::new_v4(),
            PeerSessionAction::Sync,
            7,
            11,
            [0x21; 16],
            [0x42; 32],
        );
        let mut wire = local.clone();
        local.transition_revision = 19;
        wire.transition_revision = 0;
        assert!(recovery_identity_matches_wire(&local, &wire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_recovery_suspension_keeps_initiator_reservation() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "relay-race".to_string(),
            "relay-secret".to_string(),
        )));
        let peer_map = Arc::new(PeerMap::new(packet_send, ctx.clone(), 10));
        let store = Arc::new(PeerSessionStore::new());
        let relay_map = RelayPeerMap::new(peer_map, None, ctx.clone(), 10, store.clone(), None);
        let peer_id: PeerId = 20;
        let key = SessionKey::new(ctx.get_network_name(), peer_id);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some([7; 32]),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let session = reservation.session();
        let session_id = session.metadata_session_id();
        let transition_id = reservation.transition_id();
        let responder_metadata_id = uuid::Uuid::new_v4();
        let transition_identity =
            reservation.transition_identity_with_session_metadata(responder_metadata_id);
        let confirmation_identity = RelayConfirmationIdentity {
            handshake_id: [3; RELAY_HANDSHAKE_ID_SIZE],
            session_id,
            transition_id,
        };
        relay_map.set_confirmation_identity(peer_id, confirmation_identity);
        let outcome = Arc::new(AtomicU8::new(0));
        relay_map.pending_confirmation_acks.insert(
            peer_id,
            PendingConfirmationAck {
                handshake_id: confirmation_identity.handshake_id,
                session_id,
                transition_id,
                expected_packet_type: PacketType::RelayHandshakeReadyAck as u8,
                transition_identity: transition_identity.clone(),
                previous_receipt_identity: None,
                expires_at: Instant::now() + Duration::from_millis(HANDSHAKE_CONFIRM_RETRY_MS),
                session,
                notify: Arc::new(Notify::new()),
                outcome: outcome.clone(),
            },
        );

        reservation
            .suspend_with_session_metadata(responder_metadata_id, INITIATOR_RECOVERY_LIFETIME)
            .unwrap();
        relay_map.cancel_pending_confirmation(peer_id);
        assert_eq!(outcome.load(Ordering::Acquire), 2);

        let error =
            relay_map.reject_canceled_suspended_ready_confirmation(peer_id, confirmation_identity);
        assert!(format!("{error:?}").contains("recovery is pending"));
        assert_eq!(store.in_doubt_reservation_count(), 1);
        assert_eq!(store.in_doubt_identity(&key), Some(transition_identity));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_receipt_has_one_nonblocking_owner_until_exact_ack() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "receipt-owner".to_string(),
            "receipt-secret".to_string(),
        )));
        let peer_map = Arc::new(PeerMap::new(packet_send, ctx.clone(), 10));
        let store = Arc::new(PeerSessionStore::new());
        let relay_map = RelayPeerMap::new(peer_map, None, ctx.clone(), 10, store.clone(), None);
        let peer_id: PeerId = 20;
        let key = SessionKey::new(ctx.get_network_name(), peer_id);
        let session = Arc::new(PeerSession::new(
            peer_id,
            [7; 32],
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        store.insert_session(key, session.clone());
        let identity = super::RelayReadyReceiptIdentity {
            handshake_id: [1; RELAY_HANDSHAKE_ID_SIZE],
            session_metadata_id: session.metadata_session_id(),
            transition_id: [2; RELAY_TRANSITION_ID_SIZE],
            action: PeerSessionAction::Create,
            session_generation: 1,
            initial_epoch: 0,
        };
        relay_map.start_ready_receipt(peer_id, identity, session.clone());

        for _ in 0..32 {
            let mut batch = PacketBatch::new();
            for _ in 0..4 {
                batch
                    .try_push(queue_packet(8))
                    .expect("small receipt-owner test batch");
            }
            let _ = relay_map
                .send_msg_batch(batch, peer_id, NextHopPolicy::LeastHop)
                .await;
        }

        let pending = relay_map
            .pending_ready_receipts
            .get(&peer_id)
            .map(|entry| entry.clone())
            .expect("durable receipt remains after dropped ACKs");
        assert!(pending.owner_running.load(Ordering::Acquire));
        pending.outcome.store(1, Ordering::Release);
        pending.notify.notify_one();
        for _ in 0..32 {
            if !relay_map.pending_ready_receipts.contains_key(&peer_id) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!relay_map.pending_ready_receipts.contains_key(&peer_id));
    }

    #[test]
    fn recovered_responder_ready_ack_allows_the_next_normal_transition() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("relay-recovery".to_string(), 23);
        let peer_static_pubkey = [0x17_u8; 32];
        let prepared = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                Some(peer_static_pubkey),
            )
            .unwrap();
        let transition_id = prepared.transition_id();
        store
            .commit_prepared_responder_transition(&key, &prepared)
            .unwrap();
        assert!(store.has_responder_recovery(&key));
        assert!(store.acknowledge_responder_recovery(&key, transition_id));
        assert!(!store.has_responder_recovery(&key));

        let next = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                Some(peer_static_pubkey),
            )
            .expect("a recovered relay transition must permit the next normal transition");
        next.cancel();
    }
}
