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
    BatchStreamItem, StreamItem, TunnelError,
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
        Some(
            session
                .open_batch_with_late_noise_controls(batch)
                .map_err(|error| {
                    TunnelError::InvalidPacket(format!("protected link batch failed: {error}"))
                }),
        )
    }

    fn uses_async_crypto_pipeline(&self) -> bool {
        self.enabled
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
        let result =
            super::crypto_workers::ordered_in_place_transform(&mut data, |index, packet| {
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
        let mut ordered_sequences = [0_u64; MAX_PACKET_BATCH_SIZE];
        let mut protected_count = 0_usize;
        for (index, packet) in data.iter_mut().enumerate() {
            if self.is_late_plaintext_noise_control(packet) {
                continue;
            }
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
            protected[index] = true;
            sequences[index] = sequence;
            ordered_sequences[protected_count] = sequence;
            protected_count += 1;
        }
        if protected_count == 0 {
            return Ok(data);
        }
        ordered_sequences[..protected_count].sort_unstable();

        let replay_snapshot = {
            #[cfg(test)]
            self.replay_lock_acquisitions
                .fetch_add(1, Ordering::Relaxed);
            *self.receive_replay.lock().unwrap()
        };
        for index in 0..protected_count {
            let sequence = ordered_sequences[index];
            if (index != 0 && sequence == ordered_sequences[index - 1])
                || !replay_snapshot.can_accept(sequence)
            {
                return Err(anyhow::anyhow!("the link sequence is a replay"));
            }
        }

        super::crypto_workers::ordered_in_place_transform(&mut data, |index, packet| {
            if !protected[index] {
                return Ok::<(), anyhow::Error>(());
            }
            let sequence = sequences[index];
            let public_header = sequence.to_be_bytes();
            let envelope = packet.mut_inner_preserving_flow_hash();
            let public_header_offset = envelope.len() - PUBLIC_HEADER_SIZE;
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
            Ok(())
        })?;

        #[cfg(test)]
        self.replay_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        let mut replay = self.receive_replay.lock().unwrap();
        let mut replay_work = *replay;
        for sequence in &ordered_sequences[..protected_count] {
            if !replay_work.accept(*sequence) {
                return Err(anyhow::anyhow!("the link sequence is a replay"));
            }
        }
        *replay = replay_work;
        Ok(data)
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
    fn visible_header_contains_the_authenticated_counter() {
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

        assert_eq!(values, vec![0, 1, 2, 3]);
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

    #[test]
    fn protected_batch_reuses_the_input_batch_container() {
        let (client_session, server_session) = sessions();
        let client = LinkEnvelopeTunnelFilter::new(true);
        let server = LinkEnvelopeTunnelFilter::new(true);
        client.install(client_session);
        server.install(server_session);
        let mut batch = PacketBatch::new();
        for index in 0_u64..16 {
            let mut packet = packet();
            packet.set_flow_hash(index);
            batch.try_push(packet).unwrap();
        }
        let pointer = batch.as_ptr();

        let sealed = client.before_send_batch(batch).unwrap();

        assert_eq!(sealed.as_ptr(), pointer);
        assert_eq!(sealed.len(), 16);

        let opened = server.after_received_batch(Ok(sealed)).unwrap().unwrap();
        assert_eq!(opened.as_ptr(), pointer);
        assert_eq!(opened.len(), 16);
    }
}
