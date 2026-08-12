use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use arc_swap::ArcSwapOption;
use atomic_shim::AtomicU64;
use hmac::{Hmac, Mac as _};
use ring::{aead, hmac as ring_hmac};
use sha2::Sha256;

use crate::tunnel::packet_def::{PacketType, ZCPacket, ZCPacketType};
use crate::tunnel::{
    BatchStreamItem, StreamItem, TunnelError,
    batch::PacketBatch,
    filter::{TunnelFilter, scalar_after_received_batch, scalar_before_send_batch},
};

const PUBLIC_HEADER_SIZE: usize = 8;
const AEAD_TAG_SIZE: usize = 16;
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
    send_sequence: AtomicU64,
    send_exhausted: AtomicBool,
    receive_replay: Mutex<ReplayWindow256>,
}

#[derive(Clone)]
pub(crate) struct LinkEnvelopeTunnelFilter {
    enabled: bool,
    active: std::sync::Arc<AtomicBool>,
    session: std::sync::Arc<ArcSwapOption<LinkEnvelopeSession>>,
}

impl LinkEnvelopeTunnelFilter {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active: std::sync::Arc::new(AtomicBool::new(false)),
            session: std::sync::Arc::new(ArcSwapOption::empty()),
        }
    }

    pub(crate) fn active_flag(&self) -> std::sync::Arc<AtomicBool> {
        self.active.clone()
    }

    pub(crate) fn install(&self, session: LinkEnvelopeSession) {
        self.session.store(Some(std::sync::Arc::new(session)));
        self.active.store(true, Ordering::Release);
    }
}

impl TunnelFilter for LinkEnvelopeTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, data: ZCPacket) -> Option<ZCPacket> {
        if !self.enabled {
            return Some(data);
        }
        let session = self.session.load();
        let Some(session) = session.as_deref() else {
            return Some(data);
        };
        if data.peer_manager_header().is_some_and(|header| {
            matches!(
                header.packet_type,
                value if value == PacketType::NoiseHandshakeMsg1 as u8
                    || value == PacketType::NoiseHandshakeMsg2 as u8
                    || value == PacketType::NoiseHandshakeMsg3 as u8
            )
        }) {
            return Some(data);
        }
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
        let session = self.session.load();
        let Some(session) = session.as_deref() else {
            return Some(Ok(data));
        };
        Some(session.open(data).map_err(|error| {
            TunnelError::InvalidPacket(format!("protected link packet failed: {error}"))
        }))
    }

    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        if !self.enabled || self.session.load().is_none() {
            return Some(data);
        }
        scalar_before_send_batch(self, data)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        if !self.enabled || self.session.load().is_none() {
            return Some(data);
        }
        scalar_after_received_batch(self, data)
    }

    fn filter_output(&self) {}
}

impl LinkEnvelopeSession {
    pub(crate) fn new(root_key: [u8; 32], handshake_hash: &[u8], is_client: bool) -> Self {
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
            send_sequence: AtomicU64::new(0),
            send_exhausted: AtomicBool::new(false),
            receive_replay: Mutex::new(ReplayWindow256::default()),
        }
    }

    pub(crate) fn seal(&self, packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        if self.send_exhausted.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("the link sequence is exhausted"));
        }
        let sequence = self.send_sequence.fetch_add(1, Ordering::Relaxed);
        if sequence == u64::MAX {
            self.send_exhausted.store(true, Ordering::Relaxed);
        }

        let public_header = sequence.to_be_bytes();
        let lossy = packet.is_lossy();
        let mut envelope = packet.tunnel_payload_bytes();
        envelope.reserve(AEAD_TAG_SIZE + PUBLIC_HEADER_SIZE);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(
                nonce(sequence),
                aead::Aad::from(associated_data(public_header)),
                &mut envelope,
            )
            .map_err(|_| anyhow::anyhow!("link envelope encryption failed"))?;
        envelope.extend_from_slice(tag.as_ref());
        envelope.extend_from_slice(&protect_header(
            public_header,
            &envelope,
            &self.send_header_key,
        ));
        let mut packet = ZCPacket::new_from_buf(envelope, ZCPacketType::DummyTunnel);
        packet.set_lossy_hint(lossy);
        Ok(packet)
    }

    pub(crate) fn open(&self, packet: ZCPacket) -> Result<ZCPacket, anyhow::Error> {
        let mut envelope = packet.tunnel_payload_bytes();
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

        Ok(ZCPacket::new_from_buf(envelope, ZCPacketType::DummyTunnel))
    }
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
    use crate::tunnel::packet_def::{PacketType, ZCPacketType};

    fn packet() -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"private ethernet payload");
        packet.fill_peer_manager_hdr(0x1122_3344, 0x5566_7788, PacketType::Ethernet as u8);
        packet
    }

    fn sessions() -> (LinkEnvelopeSession, LinkEnvelopeSession) {
        let root_key = [0x5a; 32];
        let handshake_hash = [0xa5; 32];
        (
            LinkEnvelopeSession::new(root_key, &handshake_hash, true),
            LinkEnvelopeSession::new(root_key, &handshake_hash, false),
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

        client.install(LinkEnvelopeSession::new(root_key, &handshake_hash, true));
        server.install(LinkEnvelopeSession::new(root_key, &handshake_hash, false));
        assert!(client.active_flag().load(Ordering::Acquire));
        let sealed = client.before_send(packet()).unwrap();
        assert_ne!(sealed.tunnel_payload(), original);
        let opened = server.after_received(Ok(sealed)).unwrap().unwrap();
        assert_eq!(opened.tunnel_payload(), original);

        let rejected = server.after_received(Ok(packet())).unwrap();
        assert!(rejected.is_err());
    }
}
