use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use arc_swap::ArcSwapOption;
use atomic_shim::AtomicU64;
use hmac::{Hmac, Mac as _};
use ring::{aead, hmac as ring_hmac};
use sha2::Sha256;

use crate::tunnel::packet_def::{PacketType, ZCPacket, ZCPacketType};
use crate::tunnel::{
    BatchStreamItem, StreamItem, TunnelError, batch::PacketBatch, filter::TunnelFilter,
};

const PUBLIC_HEADER_SIZE: usize = 8;
const AEAD_TAG_SIZE: usize = 16;
pub(crate) const LINK_ENVELOPE_OVERHEAD: usize = PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE;
const PROTOCOL_AAD: &[u8; 4] = b"ETL1";
const HEADER_PROTECTION_DOMAIN: &[u8; 4] = b"ETHP";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Default)]
struct ReplayWindow256 {
    max_sequence: u64,
    bitmap: [u64; 4],
    valid: bool,
}

fn shift_replay_bitmap(bitmap: &mut [u64; 4], distance: usize) {
    if distance >= 256 {
        bitmap.fill(0);
        return;
    }
    if distance == 0 {
        return;
    }

    let original = *bitmap;
    let word_shift = distance / 64;
    let bit_shift = distance % 64;

    for destination_word in (0..bitmap.len()).rev() {
        let Some(source_word) = destination_word.checked_sub(word_shift) else {
            bitmap[destination_word] = 0;
            continue;
        };

        let mut value = original[source_word] << bit_shift;
        if bit_shift != 0 && source_word != 0 {
            value |= original[source_word - 1] >> (64 - bit_shift);
        }
        bitmap[destination_word] = value;
    }
}

impl ReplayWindow256 {
    fn test_bit(&self, index: usize) -> bool {
        self.bitmap[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn set_bit(&mut self, index: usize) {
        self.bitmap[index / 64] |= 1_u64 << (index % 64);
    }

    fn shift(&mut self, distance: usize) {
        shift_replay_bitmap(&mut self.bitmap, distance);
    }

    fn can_accept(&self, sequence: u64) -> bool {
        if !self.valid || sequence > self.max_sequence {
            return true;
        }
        let distance = (self.max_sequence - sequence) as usize;
        distance < 256 && !self.test_bit(distance)
    }

    fn accept(&mut self, sequence: u64) -> bool {
        if !self.can_accept(sequence) {
            return false;
        }
        if !self.valid {
            self.valid = true;
            self.max_sequence = sequence;
            self.set_bit(0);
            return true;
        }
        if sequence > self.max_sequence {
            self.shift((sequence - self.max_sequence) as usize);
            self.max_sequence = sequence;
            self.set_bit(0);
            return true;
        }
        self.set_bit((self.max_sequence - sequence) as usize);
        true
    }
}

pub(crate) struct LinkEnvelopeSession {
    send_key: aead::LessSafeKey,
    receive_key: aead::LessSafeKey,
    send_header_key: ring_hmac::Key,
    receive_header_key: ring_hmac::Key,
    local_peer_id: u32,
    remote_peer_id: u32,
    send_sequence: AtomicU64,
    send_exhausted: AtomicBool,
    receive_replay: Mutex<ReplayWindow256>,
    #[cfg(test)]
    replay_lock_acquisitions: AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct LinkEnvelopeTunnelFilter {
    enabled: bool,
    active: std::sync::Arc<AtomicBool>,
    session: std::sync::Arc<ArcSwapOption<LinkEnvelopeSession>>,
    #[cfg(test)]
    session_loads: std::sync::Arc<AtomicUsize>,
}

impl LinkEnvelopeTunnelFilter {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active: std::sync::Arc::new(AtomicBool::new(false)),
            session: std::sync::Arc::new(ArcSwapOption::empty()),
            #[cfg(test)]
            session_loads: std::sync::Arc::new(AtomicUsize::new(0)),
        }
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
        Some(session.open(data).map_err(|error| {
            TunnelError::InvalidPacket(format!("protected link packet failed: {error}"))
        }))
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
        Some(
            session
                .open_batch_with_late_noise_controls(batch)
                .map_err(|error| {
                    TunnelError::InvalidPacket(format!("protected link batch failed: {error}"))
                }),
        )
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
        let a_to_b_header = derive(&root_key, handshake_hash, b"a-to-b-header");
        let b_to_a_header = derive(&root_key, handshake_hash, b"b-to-a-header");
        let (send_key, receive_key, send_header_key, receive_header_key) = if is_client {
            (a_to_b_key, b_to_a_key, a_to_b_header, b_to_a_header)
        } else {
            (b_to_a_key, a_to_b_key, b_to_a_header, a_to_b_header)
        };

        Self {
            send_key: less_safe_key(send_key),
            receive_key: less_safe_key(receive_key),
            send_header_key: header_key(send_header_key),
            receive_header_key: header_key(receive_header_key),
            local_peer_id,
            remote_peer_id,
            send_sequence: AtomicU64::new(0),
            send_exhausted: AtomicBool::new(false),
            receive_replay: Mutex::new(ReplayWindow256::default()),
            #[cfg(test)]
            replay_lock_acquisitions: AtomicUsize::new(0),
        }
    }

    pub(crate) fn seal(&self, packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        let sequence = self.reserve_send_sequences(1)?;
        self.seal_with_sequence(packet, sequence)
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
        packet: ZCPacket,
        sequence: u64,
    ) -> Result<ZCPacket, anyhow::Error> {
        if sequence == u64::MAX {
            self.send_exhausted.store(true, Ordering::Release);
        }

        let public_header = sequence.to_be_bytes();
        let lossy = packet.is_lossy();
        let mut packet = packet.convert_type(ZCPacketType::DummyTunnel);
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
        envelope.extend_from_slice(&protect_header(
            public_header,
            &envelope,
            &self.send_header_key,
        ));
        packet.set_lossy_hint(lossy);
        Ok(packet)
    }

    fn seal_batch(&self, data: PacketBatch) -> PacketBatch {
        let mut items = Vec::with_capacity(data.len());
        let mut candidate_count = 0;
        for mut packet in data {
            packet.clear_authenticated_peer_id();
            items.push((Some(candidate_count), packet));
            candidate_count += 1;
        }

        let first_sequence = match self.reserve_send_sequences(candidate_count) {
            Ok(first_sequence) => first_sequence,
            Err(error) => {
                tracing::warn!(?error, "link envelope batch sequence reservation failed");
                return PacketBatch::new();
            }
        };
        let mut sealed = PacketBatch::with_capacity(items.len());
        for (candidate_index, packet) in items {
            let result = match candidate_index {
                Some(index) => self.seal_with_sequence(packet, first_sequence + index as u64),
                None => Ok(packet),
            };
            match result {
                Ok(packet) => sealed
                    .try_push(packet)
                    .expect("sealed batch remains within its input bound"),
                Err(error) => tracing::warn!(?error, "link envelope batch encryption failed"),
            }
        }
        sealed
    }

    pub(crate) fn open(&self, packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        let mut packet = packet.convert_type(ZCPacketType::DummyTunnel);
        let envelope = packet.mut_inner_preserving_flow_hash();
        if envelope.len() < PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE {
            return Err(anyhow::anyhow!("the link envelope is too short"));
        }

        let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
        let protected_header: [u8; PUBLIC_HEADER_SIZE] = envelope[public_header_offset..]
            .try_into()
            .expect("the public header length was checked");
        let public_header = protect_header(
            protected_header,
            &envelope[..public_header_offset],
            &self.receive_header_key,
        );
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

    fn open_batch(&self, data: PacketBatch) -> Result<PacketBatch, anyhow::Error> {
        if data.is_empty() {
            return Ok(data);
        }

        let replay_snapshot = {
            #[cfg(test)]
            self.replay_lock_acquisitions
                .fetch_add(1, Ordering::Relaxed);
            *self.receive_replay.lock().unwrap()
        };
        let mut candidates = Vec::with_capacity(data.len());
        let mut seen = std::collections::HashSet::with_capacity(data.len());

        for packet in data {
            let mut packet = packet.convert_type(ZCPacketType::DummyTunnel);
            let envelope = packet.mut_inner_preserving_flow_hash();
            if envelope.len() < PUBLIC_HEADER_SIZE + AEAD_TAG_SIZE {
                return Err(anyhow::anyhow!("the link envelope is too short"));
            }
            let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
            let protected_header: [u8; PUBLIC_HEADER_SIZE] = envelope[public_header_offset..]
                .try_into()
                .expect("the public header length was checked");
            let public_header = protect_header(
                protected_header,
                &envelope[..public_header_offset],
                &self.receive_header_key,
            );
            let sequence = u64::from_be_bytes(public_header);
            if !seen.insert(sequence) || !replay_snapshot.can_accept(sequence) {
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
            envelope.truncate(plaintext_length);
            candidates.push((packet, sequence));
        }

        #[cfg(test)]
        self.replay_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        let mut replay = self.receive_replay.lock().unwrap();
        let mut replay_work = *replay;
        for (_, sequence) in &candidates {
            if !replay_work.accept(*sequence) {
                return Err(anyhow::anyhow!("the link sequence is a replay"));
            }
        }
        *replay = replay_work;
        let mut opened = PacketBatch::with_capacity(candidates.len());
        for (packet, _) in candidates {
            opened
                .try_push(packet)
                .expect("opened batch remains within its input bound");
        }
        Ok(opened)
    }

    fn open_batch_with_late_noise_controls(
        &self,
        data: PacketBatch,
    ) -> Result<PacketBatch, anyhow::Error> {
        enum BatchSlot {
            LateNoiseControl(ZCPacket),
            Protected,
        }

        let mut slots = Vec::with_capacity(data.len());
        let mut protected = PacketBatch::with_capacity(data.len());
        for packet in data {
            if self.is_late_plaintext_noise_control(&packet) {
                slots.push(BatchSlot::LateNoiseControl(packet));
            } else {
                protected
                    .try_push(packet)
                    .expect("the protected subset remains within its input bound");
                slots.push(BatchSlot::Protected);
            }
        }

        let mut opened = self.open_batch(protected)?.into_iter();
        let mut output = PacketBatch::with_capacity(slots.len());
        for slot in slots {
            let packet = match slot {
                BatchSlot::LateNoiseControl(packet) => packet,
                BatchSlot::Protected => opened
                    .next()
                    .expect("each protected input produces one opened packet"),
            };
            output
                .try_push(packet)
                .expect("the reconstructed batch keeps its input bound");
        }
        debug_assert!(opened.next().is_none());
        Ok(output)
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

fn header_key(key: [u8; 32]) -> ring_hmac::Key {
    ring_hmac::Key::new(ring_hmac::HMAC_SHA256, &key)
}

fn protect_header(
    mut header: [u8; PUBLIC_HEADER_SIZE],
    ciphertext: &[u8],
    key: &ring_hmac::Key,
) -> [u8; PUBLIC_HEADER_SIZE] {
    let mut input = [0_u8; 20];
    input[..HEADER_PROTECTION_DOMAIN.len()].copy_from_slice(HEADER_PROTECTION_DOMAIN);
    input[HEADER_PROTECTION_DOMAIN.len()..].copy_from_slice(&ciphertext[..16]);
    let mask = ring_hmac::sign(key, &input);
    for (byte, mask_byte) in header.iter_mut().zip(mask.as_ref()) {
        *byte ^= mask_byte;
    }
    header
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

    fn reference_replay_shift(bitmap: [u64; 4], distance: usize) -> [u64; 4] {
        let mut shifted = [0_u64; 4];
        for source in 0..256 {
            if bitmap[source / 64] & (1_u64 << (source % 64)) == 0 {
                continue;
            }
            let destination = source + distance;
            if destination < 256 {
                shifted[destination / 64] |= 1_u64 << (destination % 64);
            }
        }
        shifted
    }

    #[test]
    fn replay_word_shift_matches_the_reference_at_boundaries() {
        let original = [
            0x8000_0000_0000_0001,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x4000_0000_0000_0002,
        ];

        for distance in [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 300] {
            let mut actual = original;
            shift_replay_bitmap(&mut actual, distance);
            assert_eq!(actual, reference_replay_shift(original, distance));
        }
    }

    #[test]
    #[ignore = "performance measurement"]
    fn benchmark_replay_word_shift() {
        use std::hint::black_box;
        use std::time::Instant;

        fn shift_each_bit(bitmap: &mut [u8; 32], distance: usize) {
            for index in (0..256).rev() {
                let set = index >= distance
                    && bitmap[(index - distance) / 8] & (1 << ((index - distance) % 8)) != 0;
                let byte = &mut bitmap[index / 8];
                let mask = 1 << (index % 8);
                if set {
                    *byte |= mask;
                } else {
                    *byte &= !mask;
                }
            }
        }

        const ITERATIONS: usize = 2_000_000;
        let original = [
            0x8000_0000_0000_0001,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x4000_0000_0000_0002,
        ];

        let reference_start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut bitmap = black_box([0x5a_u8; 32]);
            shift_each_bit(&mut bitmap, black_box(1));
            black_box(bitmap);
        }
        let reference_elapsed = reference_start.elapsed();

        let word_start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut bitmap = black_box(original);
            shift_replay_bitmap(&mut bitmap, black_box(1));
            black_box(bitmap);
        }
        let word_elapsed = word_start.elapsed();

        eprintln!(
            "replay_shift iterations={ITERATIONS} reference_ns={} word_ns={} speedup={:.3}",
            reference_elapsed.as_nanos(),
            word_elapsed.as_nanos(),
            reference_elapsed.as_secs_f64() / word_elapsed.as_secs_f64()
        );
    }

    #[test]
    fn envelope_round_trip_restores_the_complete_packet() {
        let (client, server) = sessions();
        let original = packet().tunnel_payload().to_vec();

        let sealed = client.seal(packet()).unwrap();
        assert_eq!(sealed.packet_type(), ZCPacketType::DummyTunnel);
        assert_ne!(sealed.tunnel_payload(), original);

        let opened = server.open(sealed).unwrap();
        assert_eq!(opened.packet_type(), ZCPacketType::DummyTunnel);
        assert_eq!(opened.tunnel_payload(), original);
    }

    #[test]
    fn envelope_round_trip_preserves_local_flow_hash() {
        let (client, server) = sessions();
        let mut source = packet();
        let flow_hash = 0x0123_4567_89ab_cdef;
        source.set_flow_hash(flow_hash);

        let sealed = client.seal(source).unwrap();
        assert_eq!(sealed.flow_hash(), Some(flow_hash));

        let opened = server.open(sealed).unwrap();
        assert_eq!(opened.flow_hash(), Some(flow_hash));
    }

    #[test]
    fn protected_send_returns_the_original_reusable_slab() {
        let (client, _) = sessions();
        let pool = ReusableBufferPool::new(512, 1);
        let mut buffer = pool.try_take().unwrap();
        let original_pointer = buffer.as_ptr();
        let payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        buffer.truncate(payload_offset + 32);
        let mut packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());
        packet.mut_payload().fill(0x5a);
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);

        let sealed = client.seal(packet).unwrap();
        assert_eq!(pool.available(), 0);
        drop(sealed);

        let recycled = pool.try_take().unwrap();
        assert_eq!(recycled.as_ptr(), original_pointer);
    }

    #[test]
    fn repeated_plaintext_has_different_visible_bytes() {
        let (client, _) = sessions();
        let first = client.seal(packet()).unwrap();
        let second = client.seal(packet()).unwrap();

        assert_ne!(first.tunnel_payload(), second.tunnel_payload());
    }

    #[test]
    fn visible_headers_do_not_expose_a_counter() {
        let (client, _) = sessions();
        let values = (0..4)
            .map(|_| {
                let sealed = client.seal(packet()).unwrap();
                let visible = sealed.tunnel_payload();
                u64::from_be_bytes(
                    visible[visible.len() - 8..]
                        .try_into()
                        .expect("the visible header has eight bytes"),
                )
            })
            .collect::<Vec<_>>();

        assert!(
            values
                .windows(2)
                .any(|pair| pair[1].wrapping_sub(pair[0]) != 1)
        );
    }

    #[test]
    fn envelope_reuses_packet_storage_when_capacity_is_available() {
        let (client, server) = sessions();
        let mut source = packet();
        source.mut_inner().reserve(64);
        let source_pointer = source.tunnel_payload().as_ptr();

        let sealed = client.seal(source).unwrap();
        assert_eq!(sealed.tunnel_payload().as_ptr(), source_pointer);
        let sealed_pointer = sealed.tunnel_payload().as_ptr();

        let opened = server.open(sealed).unwrap();
        assert_eq!(opened.tunnel_payload().as_ptr(), sealed_pointer);
    }

    #[test]
    fn envelope_hides_peer_identifiers_and_packet_type() {
        let (client, _) = sessions();
        let sealed = client.seal(packet()).unwrap();
        let visible = sealed.tunnel_payload();

        assert!(
            !visible
                .windows(4)
                .any(|bytes| bytes == 0x1122_3344_u32.to_le_bytes())
        );
        assert!(
            !visible
                .windows(4)
                .any(|bytes| bytes == 0x5566_7788_u32.to_le_bytes())
        );
        assert_ne!(visible[8], PacketType::Ethernet as u8);
    }

    #[test]
    fn envelope_rejects_ciphertext_tampering() {
        let (client, server) = sessions();
        let mut sealed = client.seal(packet()).unwrap();
        let last = sealed.mut_inner().len() - 1;
        sealed.mut_inner()[last] ^= 0x80;

        assert!(server.open(sealed).is_err());
    }

    #[test]
    fn envelope_rejects_visible_header_tampering() {
        let (client, server) = sessions();
        let mut sealed = client.seal(packet()).unwrap();
        let last = sealed.mut_inner().len() - 1;
        sealed.mut_inner()[last] ^= 0x01;

        assert!(server.open(sealed).is_err());
    }

    #[test]
    fn envelope_rejects_replay() {
        let (client, server) = sessions();
        let sealed = client.seal(packet()).unwrap();

        server.open(sealed.clone()).unwrap();
        assert!(server.open(sealed).is_err());
    }

    #[test]
    fn envelope_separates_directions() {
        let (client, server) = sessions();
        let sealed = client.seal(packet()).unwrap();

        assert!(client.open(sealed.clone()).is_err());
        assert!(server.open(sealed).is_ok());
    }

    #[test]
    fn envelope_rejects_plaintext_after_installation() {
        let (_, server) = sessions();

        assert!(server.open(packet()).is_err());
    }

    #[test]
    fn tunnel_filter_changes_from_plaintext_to_protected_mode() {
        let root_key = [0x5a; 32];
        let handshake_hash = [0xa5; 32];
        let client = LinkEnvelopeTunnelFilter::new(true);
        let server = LinkEnvelopeTunnelFilter::new(true);
        let original = packet().tunnel_payload().to_vec();

        assert!(!client.active_flag().load(Ordering::Acquire));
        let handshake = client.before_send(packet()).unwrap();
        assert_eq!(handshake.tunnel_payload(), original);

        client.install(LinkEnvelopeSession::new(
            root_key,
            &handshake_hash,
            true,
            0x1122_3344,
            0x5566_7788,
        ));
        server.install(LinkEnvelopeSession::new(
            root_key,
            &handshake_hash,
            false,
            0x5566_7788,
            0x1122_3344,
        ));
        assert!(client.active_flag().load(Ordering::Acquire));
        let sealed = client.before_send(packet()).unwrap();
        assert_ne!(sealed.tunnel_payload(), original);
        let opened = server.after_received(Ok(sealed)).unwrap().unwrap();
        assert_eq!(opened.tunnel_payload(), original);

        let rejected = server.after_received(Ok(packet())).unwrap();
        assert!(rejected.is_err());
    }

    #[test]
    fn disabled_filter_does_not_advertise_link_protection() {
        let filter = LinkEnvelopeTunnelFilter::new(false);
        let (session, _) = sessions();

        filter.install(session);

        assert!(!filter.is_active());
        assert!(filter.load_session().is_none());
    }

    #[test]
    fn installed_filter_accepts_only_canonical_late_noise_controls() {
        let (_, server_session) = sessions();
        let server = LinkEnvelopeTunnelFilter::new(true);
        server.install(server_session);

        let accepted = server
            .after_received(Ok(noise_control(PacketType::NoiseHandshakeReadyReceipt)))
            .unwrap();
        assert!(accepted.is_ok());

        let mut wrong_peer = noise_control(PacketType::NoiseHandshakeReadyReceipt);
        wrong_peer
            .mut_peer_manager_header()
            .unwrap()
            .from_peer_id
            .set(7);
        assert!(server.after_received(Ok(wrong_peer)).unwrap().is_err());
        assert!(server.after_received(Ok(packet())).unwrap().is_err());
    }

    #[test]
    fn protected_batch_keeps_late_noise_control_order() {
        let (client_session, server_session) = sessions();
        let client = LinkEnvelopeTunnelFilter::new(true);
        let server = LinkEnvelopeTunnelFilter::new(true);
        client.install(client_session);
        server.install(server_session);

        let protected = client.before_send(packet()).unwrap();
        let late = noise_control(PacketType::NoiseHandshakeReadyReceipt);
        let mut batch = PacketBatch::with_capacity(2);
        batch.try_push(late).unwrap();
        batch.try_push(protected).unwrap();

        let opened = server
            .after_received_batch(Ok(batch))
            .unwrap()
            .expect("the mixed transition batch must authenticate");
        assert_eq!(opened.len(), 2);
        assert_eq!(
            opened[0].peer_manager_header().unwrap().packet_type,
            PacketType::NoiseHandshakeReadyReceipt as u8
        );
        assert_eq!(
            opened[1].peer_manager_header().unwrap().packet_type,
            PacketType::Ethernet as u8
        );
    }

    #[test]
    fn protected_batch_uses_one_session_load_and_two_replay_locks() {
        let root_key = [0x5a; 32];
        let handshake_hash = [0xa5; 32];
        let client = LinkEnvelopeTunnelFilter::new(true);
        let server = LinkEnvelopeTunnelFilter::new(true);
        client.install(LinkEnvelopeSession::new(
            root_key,
            &handshake_hash,
            true,
            0x1122_3344,
            0x5566_7788,
        ));
        server.install(LinkEnvelopeSession::new(
            root_key,
            &handshake_hash,
            false,
            0x5566_7788,
            0x1122_3344,
        ));

        for count in [1_usize, 16, 64] {
            client.reset_work_counters();
            server.reset_work_counters();
            let mut batch = PacketBatch::with_capacity(count);
            for index in 0..count {
                let mut packet = packet();
                packet.set_flow_hash(index as u64);
                batch.try_push(packet).unwrap();
            }

            let sealed = client
                .before_send_batch(batch)
                .expect("protected batch should remain non-empty");
            assert_eq!(sealed.len(), count);
            assert_eq!(client.session_load_count(), 1);

            let opened = server
                .after_received_batch(Ok(sealed))
                .expect("protected batch should remain non-empty")
                .expect("protected batch should authenticate");
            assert_eq!(opened.len(), count);
            assert_eq!(server.session_load_count(), 1);
            assert_eq!(server.replay_lock_count(), 2);
        }
    }
}
