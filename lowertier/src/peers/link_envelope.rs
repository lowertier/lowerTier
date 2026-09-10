use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use arc_swap::ArcSwapOption;
use atomic_shim::AtomicU64;
use hmac::{Hmac, Mac as _};
use ring::aead;
use sha2::Sha256;

use super::replay_window::ReplayWindow;
use crate::common::dataplane_telemetry::{DataplaneStage, DataplaneTelemetry};
use crate::tunnel::packet_def::{PacketType, ZCPacket, ZCPacketType};
use crate::tunnel::{
    BatchStreamItem, StreamItem,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    filter::TunnelFilter,
};

const PUBLIC_HEADER_SIZE: usize = 8;
const AEAD_TAG_SIZE: usize = 16;
pub(crate) const LINK_ENVELOPE_OVERHEAD: usize = PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE;
const PROTOCOL_AAD: &[u8; 4] = b"ETL1";

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct LinkEnvelopeSession {
    send_key: aead::LessSafeKey,
    receive_key: aead::LessSafeKey,
    local_peer_id: u32,
    remote_peer_id: u32,
    send_sequence: AtomicU64,
    send_exhausted: AtomicBool,
    receive_replay: Mutex<ReplayWindow>,
    #[cfg(test)]
    replay_lock_acquisitions: AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct LinkEnvelopeTunnelFilter {
    enabled: bool,
    active: std::sync::Arc<AtomicBool>,
    session: std::sync::Arc<ArcSwapOption<LinkEnvelopeSession>>,
    telemetry: Option<Arc<DataplaneTelemetry>>,
    #[cfg(test)]
    session_loads: std::sync::Arc<AtomicUsize>,
}

impl LinkEnvelopeTunnelFilter {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active: std::sync::Arc::new(AtomicBool::new(false)),
            session: std::sync::Arc::new(ArcSwapOption::empty()),
            telemetry: None,
            #[cfg(test)]
            session_loads: std::sync::Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn with_telemetry(enabled: bool, telemetry: Arc<DataplaneTelemetry>) -> Self {
        let mut filter = Self::new(enabled);
        filter.telemetry = Some(telemetry);
        filter
    }

    pub(crate) fn active_flag(&self) -> std::sync::Arc<AtomicBool> {
        self.active.clone()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn install(&self, session: LinkEnvelopeSession) {
        if !self.enabled {
            return;
        }
        self.session.store(Some(std::sync::Arc::new(session)));
        self.active.store(true, Ordering::Release);
    }

    fn load_session(&self) -> Option<std::sync::Arc<LinkEnvelopeSession>> {
        #[cfg(test)]
        self.session_loads.fetch_add(1, Ordering::Relaxed);
        self.session.load_full()
    }

    #[cfg(test)]
    fn reset_work_counters(&self) {
        self.session_loads.store(0, Ordering::Relaxed);
        if let Some(session) = self.session.load_full() {
            session.replay_lock_acquisitions.store(0, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn session_load_count(&self) -> usize {
        self.session_loads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn replay_lock_count(&self) -> usize {
        self.session
            .load_full()
            .map(|session| session.replay_lock_acquisitions.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

impl TunnelFilter for LinkEnvelopeTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: ZCPacket) -> Option<ZCPacket> {
        data.clear_authenticated_peer_id();
        if !self.enabled {
            return Some(data);
        }
        let Some(session) = self.load_session() else {
            return Some(data);
        };
        match session.seal(data) {
            Ok(packet) => Some(packet),
            Err(error) => {
                tracing::warn!(?error, "link envelope encryption failed");
                None
            }
        }
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        if !self.enabled {
            return Some(data);
        }
        let data = match data {
            Ok(packet) => packet,
            Err(error) => return Some(Err(error)),
        };
        let Some(session) = self.load_session() else {
            return Some(Ok(data));
        };
        if session.is_late_plaintext_noise_control(&data) {
            return Some(Ok(data));
        }
        match session.open(data) {
            Ok(packet) => Some(Ok(packet)),
            Err(error) => {
                tracing::debug!(?error, "dropping protected link packet");
                None
            }
        }
    }

    fn before_send_batch(&self, mut data: PacketBatch) -> Option<PacketBatch> {
        if !self.enabled {
            for packet in data.iter_mut() {
                packet.clear_authenticated_peer_id();
            }
            return Some(data);
        }
        let Some(session) = self.load_session() else {
            for packet in data.iter_mut() {
                packet.clear_authenticated_peer_id();
            }
            return Some(data);
        };
        let _stage = self.telemetry.as_ref().and_then(|telemetry| {
            telemetry.sample_stage(
                DataplaneStage::LinkEncrypt,
                data.len(),
                data.buffer_byte_len(),
            )
        });
        let sealed = session.seal_batch(data);
        (!sealed.is_empty()).then_some(sealed)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        if !self.enabled {
            return Some(data);
        }
        let Some(session) = self.load_session() else {
            return Some(data);
        };
        let batch = match data {
            Ok(batch) => batch,
            Err(error) => return Some(Err(error)),
        };
        let _stage = self.telemetry.as_ref().and_then(|telemetry| {
            telemetry.sample_stage(
                DataplaneStage::LinkDecrypt,
                batch.len(),
                batch.buffer_byte_len(),
            )
        });
        match session.open_batch_with_late_noise_controls(batch) {
            Ok(batch) if batch.is_empty() => None,
            Ok(batch) => Some(Ok(batch)),
            Err(error) => {
                tracing::debug!(?error, "dropping protected link batch");
                None
            }
        }
    }

    fn filter_output(&self) {}
}

impl LinkEnvelopeSession {
    pub(crate) fn new(
        root_key: [u8; 32],
        handshake_hash: &[u8],
        is_client: bool,
        local_peer_id: u32,
        remote_peer_id: u32,
    ) -> Self {
        let a_to_b_key = derive(&root_key, handshake_hash, b"a-to-b-key");
        let b_to_a_key = derive(&root_key, handshake_hash, b"b-to-a-key");
        let (send_key, receive_key) = if is_client {
            (a_to_b_key, b_to_a_key)
        } else {
            (b_to_a_key, a_to_b_key)
        };

        Self {
            send_key: less_safe_key(send_key),
            receive_key: less_safe_key(receive_key),
            local_peer_id,
            remote_peer_id,
            send_sequence: AtomicU64::new(0),
            send_exhausted: AtomicBool::new(false),
            receive_replay: Mutex::new(ReplayWindow::default()),
            #[cfg(test)]
            replay_lock_acquisitions: AtomicUsize::new(0),
        }
    }

    pub(crate) fn seal(&self, mut packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        let sequence = self.reserve_send_sequences(1)?;
        self.seal_with_sequence(&mut packet, sequence)?;
        Ok(packet)
    }

    fn reserve_send_sequences(&self, count: usize) -> Result<u64, anyhow::Error> {
        if count == 0 {
            return Ok(0);
        }
        let count =
            u64::try_from(count).map_err(|_| anyhow::anyhow!("the link batch is too large"))?;
        loop {
            if self.send_exhausted.load(Ordering::Acquire) {
                return Err(anyhow::anyhow!("the link sequence is exhausted"));
            }
            let current = self.send_sequence.load(Ordering::Acquire);
            let last_offset = count - 1;
            if current > u64::MAX - last_offset {
                return Err(anyhow::anyhow!("the link sequence is exhausted"));
            }
            let next = if current == u64::MAX - last_offset {
                0
            } else {
                current + count
            };
            if self
                .send_sequence
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if next == 0 {
                    self.send_exhausted.store(true, Ordering::Release);
                }
                return Ok(current);
            }
        }
    }

    fn seal_with_sequence(
        &self,
        packet: &mut ZCPacket,
        sequence: u64,
    ) -> Result<(), anyhow::Error> {
        if sequence == u64::MAX {
            self.send_exhausted.store(true, Ordering::Release);
        }

        let public_header = sequence.to_be_bytes();
        let lossy = packet.is_lossy();
        packet
            .convert_type_in_place(ZCPacketType::DummyTunnel)
            .map_err(anyhow::Error::msg)?;
        let envelope = packet.mut_inner_preserving_flow_hash();
        envelope.reserve(AEAD_TAG_SIZE + PUBLIC_HEADER_SIZE);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(
                nonce(sequence),
                aead::Aad::from(associated_data(public_header)),
                envelope,
            )
            .map_err(|_| anyhow::anyhow!("link envelope encryption failed"))?;
        envelope.extend_from_slice(tag.as_ref());
        envelope.extend_from_slice(&public_header);
        packet.set_lossy_hint(lossy);
        Ok(())
    }

    fn seal_batch(self: &Arc<Self>, mut data: PacketBatch) -> PacketBatch {
        for packet in data.iter_mut() {
            packet.clear_authenticated_peer_id();
        }
        let candidate_count = data.len();
        let first_sequence = match self.reserve_send_sequences(candidate_count) {
            Ok(first_sequence) => first_sequence,
            Err(error) => {
                tracing::warn!(?error, "link envelope batch sequence reservation failed");
                return PacketBatch::new();
            }
        };
        let result = data.iter_mut().enumerate().try_for_each(|(index, packet)| {
            self.seal_with_sequence(packet, first_sequence + index as u64)
        });
        if let Err(error) = result {
            tracing::warn!(?error, "link envelope batch encryption failed");
            return PacketBatch::new();
        }
        data
    }

    pub(crate) fn open(&self, mut packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        packet
            .convert_type_in_place(ZCPacketType::DummyTunnel)
            .map_err(anyhow::Error::msg)?;
        let envelope = packet.mut_inner_preserving_flow_hash();
        if envelope.len() < PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE {
            return Err(anyhow::anyhow!("the link envelope is too short"));
        }

        let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
        let public_header: [u8; PUBLIC_HEADER_SIZE] = envelope[public_header_offset..]
            .try_into()
            .expect("the public header length was checked");
        let sequence = u64::from_be_bytes(public_header);

        #[cfg(test)]
        self.replay_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        let mut replay = self.receive_replay.lock().unwrap();
        if !replay.can_accept(sequence) {
            return Err(anyhow::anyhow!("the link sequence is a replay"));
        }

        let plaintext_length = self
            .receive_key
            .open_in_place(
                nonce(sequence),
                aead::Aad::from(associated_data(public_header)),
                &mut envelope[..public_header_offset],
            )
            .map_err(|_| anyhow::anyhow!("link envelope authentication failed"))?
            .len();
        if !replay.accept(sequence) {
            return Err(anyhow::anyhow!("the link sequence is a replay"));
        }
        envelope.truncate(plaintext_length);

        Ok(packet)
    }

    fn open_batch_with_late_noise_controls(
        &self,
        mut data: PacketBatch,
    ) -> Result<PacketBatch, anyhow::Error> {
        if data.is_empty() {
            return Ok(data);
        }

        let mut protected = [false; MAX_PACKET_BATCH_SIZE];
        let mut sequences = [0_u64; MAX_PACKET_BATCH_SIZE];
        let mut drop_packet = [false; MAX_PACKET_BATCH_SIZE];
        for (index, packet) in data.iter_mut().enumerate() {
            if self.is_late_plaintext_noise_control(packet) {
                continue;
            }
            if packet
                .convert_type_in_place(ZCPacketType::DummyTunnel)
                .is_err()
            {
                drop_packet[index] = true;
                continue;
            }
            let envelope = packet.mut_inner_preserving_flow_hash();
            if envelope.len() < PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE {
                drop_packet[index] = true;
                continue;
            }
            let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
            let public_header: [u8; PUBLIC_HEADER_SIZE] = envelope[public_header_offset..]
                .try_into()
                .expect("the public header length was checked");
            protected[index] = true;
            sequences[index] = u64::from_be_bytes(public_header);
        }

        {
            #[cfg(test)]
            self.replay_lock_acquisitions
                .fetch_add(1, Ordering::Relaxed);
            let mut replay_work = *self.receive_replay.lock().unwrap();
            for index in 0..data.len() {
                if drop_packet[index] || !protected[index] {
                    continue;
                }
                if !replay_work.accept(sequences[index]) {
                    drop_packet[index] = true;
                }
            }
        }

        let decrypt_failed: [AtomicBool; MAX_PACKET_BATCH_SIZE] =
            std::array::from_fn(|_| AtomicBool::new(false));
        let decrypt_result = data.iter_mut().enumerate().try_for_each(|(index, packet)| {
            if drop_packet[index] || !protected[index] {
                return Ok::<(), anyhow::Error>(());
            }
            let sequence = sequences[index];
            let public_header = sequence.to_be_bytes();
            let envelope = packet.mut_inner_preserving_flow_hash();
            let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
            match self.receive_key.open_in_place(
                nonce(sequence),
                aead::Aad::from(associated_data(public_header)),
                &mut envelope[..public_header_offset],
            ) {
                Ok(plaintext) => {
                    let plaintext_length = plaintext.len();
                    envelope.truncate(plaintext_length);
                    Ok(())
                }
                Err(_) => {
                    decrypt_failed[index].store(true, Ordering::Relaxed);
                    Ok(())
                }
            }
        });
        if let Err(error) = decrypt_result {
            tracing::warn!(?error, "link envelope batch decryption failed");
            return Ok(PacketBatch::new());
        }
        for (index, failed) in decrypt_failed.iter().enumerate().take(data.len()) {
            if failed.load(Ordering::Relaxed) {
                drop_packet[index] = true;
            }
        }

        #[cfg(test)]
        self.replay_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut replay = self.receive_replay.lock().unwrap();
            for index in 0..data.len() {
                if drop_packet[index] || !protected[index] {
                    continue;
                }
                if !replay.accept(sequences[index]) {
                    drop_packet[index] = true;
                }
            }
        }

        if !drop_packet.iter().take(data.len()).any(|dropped| *dropped) {
            return Ok(data);
        }
        let mut kept = PacketBatch::with_capacity(data.len());
        for (index, packet) in data.into_iter().enumerate() {
            if drop_packet[index] {
                continue;
            }
            kept.try_push(packet)
                .expect("kept packets cannot exceed the input batch");
        }
        Ok(kept)
    }

    fn is_late_plaintext_noise_control(&self, packet: &ZCPacket) -> bool {
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        header.from_peer_id.get() == self.remote_peer_id
            && header.to_peer_id.get() == self.local_peer_id
            && header.flags == 0
            && header.forward_counter == 1
            && header.flow_shard().is_none()
            && !header.is_critical_l2_control()
            && usize::try_from(header.len.get()).ok() == Some(packet.payload_len())
            && is_noise_handshake_packet_type(header.packet_type)
    }
}

pub(crate) fn is_noise_handshake_packet_type(packet_type: u8) -> bool {
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

fn derive(root_key: &[u8; 32], handshake_hash: &[u8], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(root_key).expect("HMAC accepts a 32-byte key");
    mac.update(b"lowertier-link-envelope-v1");
    mac.update(handshake_hash);
    mac.update(label);
    let output = mac.finalize().into_bytes();
    output.into()
}

fn less_safe_key(key: [u8; 32]) -> aead::LessSafeKey {
    let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key)
        .expect("ChaCha20-Poly1305 accepts a 32-byte key");
    aead::LessSafeKey::new(key)
}

fn associated_data(public_header: [u8; PUBLIC_HEADER_SIZE]) -> [u8; 12] {
    let mut data = [0_u8; 12];
    data[..PROTOCOL_AAD.len()].copy_from_slice(PROTOCOL_AAD);
    data[PROTOCOL_AAD.len()..].copy_from_slice(&public_header);
    data
}

fn nonce(sequence: u64) -> aead::Nonce {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&1_u32.to_be_bytes());
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    aead::Nonce::assume_unique_for_key(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::filter::TunnelFilter;
    use crate::tunnel::packet_def::{PacketType, ReusableBufferPool, ZCPacketType};

    fn packet() -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"private ethernet payload");
        packet.fill_peer_manager_hdr(0x1122_3344, 0x5566_7788, PacketType::Ethernet as u8);
        packet
    }

    fn noise_control(packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"noise transport payload");
        packet.fill_peer_manager_hdr(0x1122_3344, 0x5566_7788, packet_type as u8);
        packet
    }

    fn sessions() -> (LinkEnvelopeSession, LinkEnvelopeSession) {
        let root_key = [0x5a; 32];
        let handshake_hash = [0xa5; 32];
        (
            LinkEnvelopeSession::new(root_key, &handshake_hash, true, 0x1122_3344, 0x5566_7788),
            LinkEnvelopeSession::new(root_key, &handshake_hash, false, 0x5566_7788, 0x1122_3344),
        )
    }

    #[test]
    fn replayed_packet_is_dropped_without_failing_the_batch() {
        let filter = LinkEnvelopeTunnelFilter::new(true);
        let (client, server) = sessions();
        filter.install(server);
        let client = std::sync::Arc::new(client);

        let mut live = PacketBatch::with_capacity(2);
        live.try_push(packet()).unwrap();
        live.try_push(packet()).unwrap();
        let sealed_live = client.seal_batch(live);
        let replay_one = sealed_live[0].clone();
        let opened = filter
            .after_received_batch(Ok(sealed_live))
            .expect("the first batch is admitted")
            .expect("the first batch decrypts");
        assert_eq!(opened.len(), 2);

        let mut fresh = PacketBatch::with_capacity(1);
        fresh.try_push(packet()).unwrap();
        let mut mixed = PacketBatch::with_capacity(2);
        mixed.try_push(replay_one).unwrap();
        mixed
            .try_push(client.seal_batch(fresh).pop_singleton().unwrap())
            .unwrap();
        let opened = filter
            .after_received_batch(Ok(mixed))
            .expect("a mixed batch stays on the stream")
            .expect("a mixed batch decrypts");
        assert_eq!(opened.len(), 1);
    }
}
