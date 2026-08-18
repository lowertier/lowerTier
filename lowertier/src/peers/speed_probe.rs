use std::time::{Duration, Instant};

use rand::RngCore;

pub(crate) const PROBE_HEADER_SIZE: usize = 48;
pub(crate) const MAX_SPEED_SAMPLE_TTL: Duration = Duration::from_secs(15 * 60);
const PROBE_ACK_SIZE: usize = 56;
const MAX_PROBE_PACKETS: u32 = 65_536;
const PROBE_SEND_TIMEOUT: Duration = Duration::from_secs(1);
const PROBE_MARKER_TIMEOUT: Duration = Duration::from_secs(1);
const PROBE_INCOMPLETE_TIMEOUT: Duration = Duration::from_secs(2);
const BITS_PER_BYTE: u128 = 8;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub(crate) fn speed_sample_ttl(interval: Duration) -> Duration {
    interval
        .checked_mul(3)
        .unwrap_or(MAX_SPEED_SAMPLE_TTL)
        .min(MAX_SPEED_SAMPLE_TTL)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProbeError {
    #[error("probe payload is too short")]
    PayloadTooShort,
    #[error("probe acknowledgement has an invalid size")]
    InvalidAckSize,
    #[error("probe packet metadata is invalid")]
    InvalidMetadata,
    #[error("probe arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("probe generation metadata changed")]
    MetadataChanged,
    #[error("probe interval must be positive")]
    InvalidInterval,
    #[error("secure random data is unavailable")]
    EntropyUnavailable,
}

pub(crate) fn generate_receipt_challenge() -> Result<[u8; 16], ProbeError> {
    loop {
        let mut challenge = [0_u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| ProbeError::EntropyUnavailable)?;
        if challenge != [0_u8; 16] {
            return Ok(challenge);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbeData {
    pub generation: u64,
    pub sequence: u32,
    pub expected_packets: u32,
    pub expected_bytes: u64,
    pub final_marker: bool,
    pub receipt_challenge: [u8; 16],
}

impl ProbeData {
    pub(crate) fn encode_with_size(self, encoded_size: usize) -> Result<Vec<u8>, ProbeError> {
        self.validate(encoded_size)?;
        let mut encoded = vec![0_u8; encoded_size];
        encoded[0..8].copy_from_slice(&self.generation.to_le_bytes());
        encoded[8..12].copy_from_slice(&self.sequence.to_le_bytes());
        encoded[12..16].copy_from_slice(&self.expected_packets.to_le_bytes());
        encoded[16..24].copy_from_slice(&self.expected_bytes.to_le_bytes());
        encoded[24] = u8::from(self.final_marker);
        encoded[32..48].copy_from_slice(&self.receipt_challenge);
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProbeError> {
        if encoded.len() < PROBE_HEADER_SIZE {
            return Err(ProbeError::PayloadTooShort);
        }
        let data = Self {
            generation: u64::from_le_bytes(encoded[0..8].try_into().unwrap()),
            sequence: u32::from_le_bytes(encoded[8..12].try_into().unwrap()),
            expected_packets: u32::from_le_bytes(encoded[12..16].try_into().unwrap()),
            expected_bytes: u64::from_le_bytes(encoded[16..24].try_into().unwrap()),
            final_marker: match encoded[24] {
                0 => false,
                1 => true,
                _ => return Err(ProbeError::InvalidMetadata),
            },
            receipt_challenge: encoded[32..48].try_into().unwrap(),
        };
        if encoded[25..32].iter().any(|byte| *byte != 0) {
            return Err(ProbeError::InvalidMetadata);
        }
        data.validate(encoded.len())?;
        Ok(data)
    }

    fn validate(self, encoded_size: usize) -> Result<(), ProbeError> {
        if encoded_size < PROBE_HEADER_SIZE {
            return Err(ProbeError::PayloadTooShort);
        }
        if !(2..=MAX_PROBE_PACKETS).contains(&self.expected_packets)
            || self.sequence >= self.expected_packets
            || self.expected_bytes == 0
            || self.final_marker && self.sequence + 1 != self.expected_packets
            || self.final_marker && self.receipt_challenge == [0_u8; 16]
            || !self.final_marker && self.receipt_challenge != [0_u8; 16]
        {
            return Err(ProbeError::InvalidMetadata);
        }
        let minimum_bytes = u64::from(self.expected_packets)
            .checked_mul(PROBE_HEADER_SIZE as u64)
            .ok_or(ProbeError::ArithmeticOverflow)?;
        if self.expected_bytes < minimum_bytes || encoded_size as u64 > self.expected_bytes {
            return Err(ProbeError::InvalidMetadata);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProbeAck {
    pub generation: u64,
    pub received_packets: u32,
    pub expected_packets: u32,
    pub received_bytes: u64,
    pub expected_bytes: u64,
    pub duration_ns: u64,
    pub receipt_challenge: [u8; 16],
}

impl ProbeAck {
    pub(crate) fn encode(self) -> [u8; PROBE_ACK_SIZE] {
        let mut encoded = [0_u8; PROBE_ACK_SIZE];
        encoded[0..8].copy_from_slice(&self.generation.to_le_bytes());
        encoded[8..12].copy_from_slice(&self.received_packets.to_le_bytes());
        encoded[12..16].copy_from_slice(&self.expected_packets.to_le_bytes());
        encoded[16..24].copy_from_slice(&self.received_bytes.to_le_bytes());
        encoded[24..32].copy_from_slice(&self.expected_bytes.to_le_bytes());
        encoded[32..40].copy_from_slice(&self.duration_ns.to_le_bytes());
        encoded[40..56].copy_from_slice(&self.receipt_challenge);
        encoded
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProbeError> {
        if encoded.len() != PROBE_ACK_SIZE {
            return Err(ProbeError::InvalidAckSize);
        }
        let ack = Self {
            generation: u64::from_le_bytes(encoded[0..8].try_into().unwrap()),
            received_packets: u32::from_le_bytes(encoded[8..12].try_into().unwrap()),
            expected_packets: u32::from_le_bytes(encoded[12..16].try_into().unwrap()),
            received_bytes: u64::from_le_bytes(encoded[16..24].try_into().unwrap()),
            expected_bytes: u64::from_le_bytes(encoded[24..32].try_into().unwrap()),
            duration_ns: u64::from_le_bytes(encoded[32..40].try_into().unwrap()),
            receipt_challenge: encoded[40..56].try_into().unwrap(),
        };
        if !(2..=MAX_PROBE_PACKETS).contains(&ack.expected_packets)
            || ack.received_packets > ack.expected_packets
            || ack.received_bytes > ack.expected_bytes
            || ack.receipt_challenge == [0_u8; 16]
        {
            return Err(ProbeError::InvalidMetadata);
        }
        Ok(ack)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SpeedSample {
    pub delivery_bps: u64,
    pub loss_ppm: u32,
    pub generation: u64,
    pub measured_at: Instant,
    pub ttl: Duration,
}

impl SpeedSample {
    pub(crate) fn from_ack(
        ack: ProbeAck,
        local_send_duration: Duration,
        measured_at: Instant,
        ttl: Duration,
    ) -> Self {
        let trusted_duration_ns = ack
            .duration_ns
            .max(u64::try_from(local_send_duration.as_nanos()).unwrap_or(u64::MAX));
        let delivery_bps = if ack.received_packets < 2 || trusted_duration_ns == 0 {
            0
        } else {
            let bits = u128::from(ack.received_bytes).saturating_mul(BITS_PER_BYTE);
            let rate = bits
                .saturating_mul(NANOS_PER_SECOND)
                .checked_div(u128::from(trusted_duration_ns))
                .unwrap_or_default();
            u64::try_from(rate).unwrap_or(u64::MAX)
        };
        let missing_packets = ack.expected_packets.saturating_sub(ack.received_packets);
        let loss_ppm = u64::from(missing_packets)
            .saturating_mul(1_000_000)
            .checked_div(u64::from(ack.expected_packets))
            .unwrap_or_default() as u32;
        Self {
            delivery_bps,
            loss_ppm,
            generation: ack.generation,
            measured_at,
            ttl,
        }
    }

    pub(crate) fn is_fresh(&self, now: Instant) -> bool {
        now.checked_duration_since(self.measured_at)
            .is_some_and(|age| age < self.ttl)
    }

    pub(crate) fn age(&self, now: Instant) -> Duration {
        now.checked_duration_since(self.measured_at)
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct ReceivedGeneration {
    metadata: ProbeData,
    received: Vec<u64>,
    received_packets: u32,
    received_bytes: u64,
    first_arrival: Instant,
    last_arrival: Instant,
    marker_arrival: Option<Instant>,
    receipt_challenge: Option<[u8; 16]>,
}

impl ReceivedGeneration {
    fn new(data: ProbeData, now: Instant) -> Self {
        let bitmap_words = (data.expected_packets as usize).div_ceil(u64::BITS as usize);
        Self {
            metadata: data,
            received: vec![0; bitmap_words],
            received_packets: 0,
            received_bytes: 0,
            first_arrival: now,
            last_arrival: now,
            marker_arrival: None,
            receipt_challenge: None,
        }
    }

    fn metadata_matches(&self, data: ProbeData) -> bool {
        self.metadata.generation == data.generation
            && self.metadata.expected_packets == data.expected_packets
            && self.metadata.expected_bytes == data.expected_bytes
    }

    fn mark_received(&mut self, sequence: u32) -> bool {
        let sequence = sequence as usize;
        let word = sequence / u64::BITS as usize;
        let mask = 1_u64 << (sequence % u64::BITS as usize);
        if self.received[word] & mask != 0 {
            return false;
        }
        self.received[word] |= mask;
        true
    }

    fn can_replace(&self, now: Instant) -> bool {
        self.marker_arrival.is_none()
            && now
                .checked_duration_since(self.first_arrival)
                .is_some_and(|age| age >= PROBE_INCOMPLETE_TIMEOUT)
    }

    fn acknowledgement(&self) -> ProbeAck {
        let duration_ns = self
            .last_arrival
            .checked_duration_since(self.first_arrival)
            .unwrap_or_default()
            .as_nanos();
        ProbeAck {
            generation: self.metadata.generation,
            received_packets: self.received_packets,
            expected_packets: self.metadata.expected_packets,
            received_bytes: self.received_bytes,
            expected_bytes: self.metadata.expected_bytes,
            duration_ns: u64::try_from(duration_ns).unwrap_or(u64::MAX),
            receipt_challenge: self
                .receipt_challenge
                .expect("a completed probe has a receipt challenge"),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ProbeReceiver {
    active: Option<ReceivedGeneration>,
}

impl ProbeReceiver {
    pub(crate) fn receive(
        &mut self,
        encoded: &[u8],
        now: Instant,
    ) -> Result<Option<ProbeAck>, ProbeError> {
        self.receive_wire(encoded, encoded.len(), now)
    }

    pub(crate) fn receive_wire(
        &mut self,
        encoded: &[u8],
        wire_size: usize,
        now: Instant,
    ) -> Result<Option<ProbeAck>, ProbeError> {
        let data = ProbeData::decode(encoded)?;
        match self.active.as_ref() {
            Some(active) if data.generation < active.metadata.generation => return Ok(None),
            Some(active) if data.generation == active.metadata.generation => {
                if !active.metadata_matches(data) {
                    return Err(ProbeError::MetadataChanged);
                }
            }
            Some(active) if !active.can_replace(now) => return Ok(None),
            _ => self.active = Some(ReceivedGeneration::new(data, now)),
        }

        let active = self.active.as_mut().unwrap();
        if !active.mark_received(data.sequence) {
            return Ok(None);
        }
        let received_bytes = active
            .received_bytes
            .checked_add(wire_size as u64)
            .ok_or(ProbeError::ArithmeticOverflow)?;
        if received_bytes > active.metadata.expected_bytes {
            return Err(ProbeError::InvalidMetadata);
        }
        active.received_packets += 1;
        active.received_bytes = received_bytes;
        if active.received_packets == 1 {
            active.first_arrival = now;
        }
        active.last_arrival = now;
        if data.final_marker {
            active.marker_arrival = Some(now);
            active.receipt_challenge = Some(data.receipt_challenge);
        }
        if active.received_packets == active.metadata.expected_packets {
            return Ok(self.finish());
        }
        Ok(None)
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Option<ProbeAck> {
        let active = self.active.as_ref()?;
        if active.marker_arrival.is_some_and(|marker| {
            now.checked_duration_since(marker)
                .is_some_and(|age| age >= PROBE_MARKER_TIMEOUT)
        }) {
            return self.finish();
        }
        if active.marker_arrival.is_none()
            && now
                .checked_duration_since(active.first_arrival)
                .is_some_and(|age| age >= PROBE_INCOMPLETE_TIMEOUT)
        {
            self.active = None;
        }
        None
    }

    fn finish(&mut self) -> Option<ProbeAck> {
        self.active
            .take()
            .filter(|active| active.receipt_challenge.is_some())
            .map(|active| active.acknowledgement())
    }

    pub(crate) fn has_active_generation(&self) -> bool {
        self.active.is_some()
    }

    pub(crate) fn active_generation(&self) -> Option<u64> {
        self.active
            .as_ref()
            .map(|active| active.metadata.generation)
    }
}

pub(crate) fn build_probe_train(
    generation: u64,
    reserved_bytes: u64,
    packet_size: usize,
    receipt_challenge: [u8; 16],
) -> Result<Vec<Vec<u8>>, ProbeError> {
    build_probe_train_with_overhead(
        generation,
        reserved_bytes,
        packet_size,
        0,
        receipt_challenge,
    )
}

pub(crate) fn build_probe_train_with_overhead(
    generation: u64,
    reserved_bytes: u64,
    wire_packet_size: usize,
    per_packet_overhead: usize,
    receipt_challenge: [u8; 16],
) -> Result<Vec<Vec<u8>>, ProbeError> {
    let encoded_size = wire_packet_size
        .checked_sub(per_packet_overhead)
        .ok_or(ProbeError::PayloadTooShort)?;
    if encoded_size < PROBE_HEADER_SIZE {
        return Err(ProbeError::PayloadTooShort);
    }
    let packet_size_u64 = wire_packet_size as u64;
    let packet_count = (reserved_bytes / packet_size_u64).min(u64::from(MAX_PROBE_PACKETS));
    if packet_count < 2 {
        return Ok(Vec::new());
    }
    let expected_packets =
        u32::try_from(packet_count).map_err(|_| ProbeError::ArithmeticOverflow)?;
    let expected_bytes = packet_count
        .checked_mul(packet_size_u64)
        .ok_or(ProbeError::ArithmeticOverflow)?;
    let mut train = Vec::with_capacity(expected_packets as usize);
    for sequence in 0..expected_packets {
        train.push(
            ProbeData {
                generation,
                sequence,
                expected_packets,
                expected_bytes,
                final_marker: sequence + 1 == expected_packets,
                receipt_challenge: if sequence + 1 == expected_packets {
                    receipt_challenge
                } else {
                    [0_u8; 16]
                },
            }
            .encode_with_size(encoded_size)?,
        );
    }
    Ok(train)
}

pub(crate) fn probe_train_metadata(
    reserved_bytes: u64,
    wire_packet_size: usize,
    per_packet_overhead: usize,
) -> Result<(usize, u32, u64), ProbeError> {
    let encoded_size = wire_packet_size
        .checked_sub(per_packet_overhead)
        .ok_or(ProbeError::PayloadTooShort)?;
    if encoded_size < PROBE_HEADER_SIZE {
        return Err(ProbeError::PayloadTooShort);
    }
    let packet_count = (reserved_bytes / wire_packet_size as u64).min(u64::from(MAX_PROBE_PACKETS));
    if packet_count < 2 {
        return Ok((encoded_size, 0, 0));
    }
    let expected_packets =
        u32::try_from(packet_count).map_err(|_| ProbeError::ArithmeticOverflow)?;
    let expected_bytes = packet_count
        .checked_mul(wire_packet_size as u64)
        .ok_or(ProbeError::ArithmeticOverflow)?;
    Ok((encoded_size, expected_packets, expected_bytes))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProbeAllocation {
    pub shares: Vec<u64>,
    pub unused_bytes: u64,
}

pub(crate) fn split_cycle_budget(
    snapshot_bytes: u64,
    connection_count: usize,
    packet_size: usize,
) -> ProbeAllocation {
    if connection_count == 0 || packet_size == 0 {
        return ProbeAllocation {
            shares: Vec::new(),
            unused_bytes: snapshot_bytes,
        };
    }
    let Ok(connection_count_u64) = u64::try_from(connection_count) else {
        return ProbeAllocation {
            shares: Vec::new(),
            unused_bytes: snapshot_bytes,
        };
    };
    let share = snapshot_bytes / connection_count_u64;
    let minimum_share = (packet_size as u64).saturating_mul(2);
    if share < minimum_share {
        return ProbeAllocation {
            shares: Vec::new(),
            unused_bytes: snapshot_bytes,
        };
    }
    let allocated = share.saturating_mul(connection_count_u64);
    ProbeAllocation {
        shares: vec![share; connection_count],
        unused_bytes: snapshot_bytes.saturating_sub(allocated),
    }
}

#[derive(Debug)]
pub(crate) struct ProbeBudget {
    rate_bps: u64,
    capacity_bytes: u64,
    available_bytes: u64,
    last_refill: Instant,
    refill_remainder: u128,
}

impl ProbeBudget {
    pub(crate) fn new(rate_bps: u64, interval: Duration, now: Instant) -> Result<Self, ProbeError> {
        if interval.is_zero() {
            return Err(ProbeError::InvalidInterval);
        }
        let capacity = u128::from(rate_bps)
            .checked_mul(interval.as_nanos())
            .ok_or(ProbeError::ArithmeticOverflow)?
            .checked_div(BITS_PER_BYTE * NANOS_PER_SECOND)
            .ok_or(ProbeError::ArithmeticOverflow)?;
        let capacity_bytes = u64::try_from(capacity).map_err(|_| ProbeError::ArithmeticOverflow)?;
        Ok(Self {
            rate_bps,
            capacity_bytes,
            available_bytes: capacity_bytes,
            last_refill: now,
            refill_remainder: 0,
        })
    }

    fn refill(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };
        self.last_refill = now;
        if self.available_bytes >= self.capacity_bytes {
            self.refill_remainder = 0;
            return;
        }
        let numerator = u128::from(self.rate_bps)
            .saturating_mul(elapsed.as_nanos())
            .saturating_add(self.refill_remainder);
        let denominator = BITS_PER_BYTE * NANOS_PER_SECOND;
        let refill_bytes = numerator / denominator;
        self.refill_remainder = numerator % denominator;
        self.available_bytes = self
            .available_bytes
            .saturating_add(u64::try_from(refill_bytes).unwrap_or(u64::MAX))
            .min(self.capacity_bytes);
        if self.available_bytes == self.capacity_bytes {
            self.refill_remainder = 0;
        }
    }

    pub(crate) fn take_cycle_snapshot(&mut self, now: Instant) -> u64 {
        self.refill(now);
        std::mem::take(&mut self.available_bytes)
    }

    pub(crate) fn return_unused(&mut self, bytes: u64) {
        self.available_bytes = self
            .available_bytes
            .saturating_add(bytes)
            .min(self.capacity_bytes);
    }

    pub(crate) fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    pub(crate) fn available_bytes(&self) -> u64 {
        self.available_bytes
    }
}

#[derive(Debug)]
pub(crate) struct ProbeReservation {
    reserved_bytes: u64,
    sent_bytes: u64,
    sent_packets: u32,
    pending_bytes: Option<u64>,
    first_sent_at: Option<Instant>,
    last_sent_at: Option<Instant>,
    receipt_challenge: [u8; 16],
    challenge_sent: bool,
    deadline: Instant,
}

impl ProbeReservation {
    pub(crate) fn new(reserved_bytes: u64, receipt_challenge: [u8; 16], now: Instant) -> Self {
        Self {
            reserved_bytes,
            sent_bytes: 0,
            sent_packets: 0,
            pending_bytes: None,
            first_sent_at: None,
            last_sent_at: None,
            receipt_challenge,
            challenge_sent: false,
            deadline: now + PROBE_SEND_TIMEOUT,
        }
    }

    pub(crate) fn reserve_send(&mut self, bytes: u64, now: Instant) -> bool {
        if now >= self.deadline
            || self.pending_bytes.is_some()
            || self
                .sent_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.reserved_bytes)
        {
            return false;
        }
        self.pending_bytes = Some(bytes);
        true
    }

    pub(crate) fn commit_send(&mut self, now: Instant) {
        let bytes = self
            .pending_bytes
            .take()
            .expect("a probe send must reserve bytes before commit");
        self.sent_bytes += bytes;
        self.sent_packets = self.sent_packets.saturating_add(1);
        self.first_sent_at.get_or_insert(now);
        self.last_sent_at = Some(now);
    }

    pub(crate) fn cancel_send(&mut self) {
        self.pending_bytes = None;
    }

    pub(crate) fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    pub(crate) fn mark_challenge_sent(&mut self) {
        self.challenge_sent = true;
    }

    pub(crate) fn unused_bytes(&self) -> u64 {
        self.reserved_bytes
            .saturating_sub(self.sent_bytes)
            .saturating_sub(self.pending_bytes.unwrap_or_default())
    }

    pub(crate) fn send_duration(&self) -> Duration {
        self.first_sent_at
            .zip(self.last_sent_at)
            .and_then(|(first, last)| last.checked_duration_since(first))
            .unwrap_or_default()
    }

    pub(crate) fn matches_ack(&self, ack: &ProbeAck) -> bool {
        self.challenge_sent
            && ack.receipt_challenge == self.receipt_challenge
            && u64::from(ack.expected_packets) == u64::from(self.sent_packets)
            && ack.expected_bytes == self.sent_bytes
            && ack.received_bytes <= self.sent_bytes
            && ack.received_packets <= self.sent_packets
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        MAX_SPEED_SAMPLE_TTL, ProbeAck, ProbeBudget, ProbeData, ProbeReceiver, ProbeReservation,
        SpeedSample, build_probe_train, speed_sample_ttl, split_cycle_budget,
    };

    const RECEIPT_CHALLENGE: [u8; 16] = [0x5a; 16];

    #[test]
    fn probe_payloads_round_trip_and_reject_invalid_sizes() {
        let data = ProbeData {
            generation: 7,
            sequence: 2,
            expected_packets: 3,
            expected_bytes: 300,
            final_marker: true,
            receipt_challenge: RECEIPT_CHALLENGE,
        };
        let encoded = data.encode_with_size(100).unwrap();
        assert_eq!(encoded.len(), 100);
        assert_eq!(ProbeData::decode(&encoded).unwrap(), data);
        assert!(ProbeData::decode(&encoded[..47]).is_err());

        let ack = ProbeAck {
            generation: 7,
            received_packets: 2,
            expected_packets: 3,
            received_bytes: 200,
            expected_bytes: 300,
            duration_ns: 100_000_000,
            receipt_challenge: RECEIPT_CHALLENGE,
        };
        let encoded = ack.encode();
        assert_eq!(ProbeAck::decode(&encoded).unwrap(), ack);
        assert!(ProbeAck::decode(&encoded[..55]).is_err());
    }

    #[test]
    fn train_uses_complete_packets_and_marks_only_the_last_packet() {
        let train = build_probe_train(9, 350, 100, RECEIPT_CHALLENGE).unwrap();
        assert_eq!(train.len(), 3);
        assert!(train.iter().all(|packet| packet.len() == 100));

        for (index, packet) in train.iter().enumerate() {
            let data = ProbeData::decode(packet).unwrap();
            assert_eq!(data.sequence, index as u32);
            assert_eq!(data.expected_packets, 3);
            assert_eq!(data.expected_bytes, 300);
            assert_eq!(data.final_marker, index == 2);
            assert_eq!(
                data.receipt_challenge,
                if index == 2 {
                    RECEIPT_CHALLENGE
                } else {
                    [0_u8; 16]
                }
            );
        }

        assert!(
            build_probe_train(9, 199, 100, RECEIPT_CHALLENGE)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn receiver_waits_for_reordered_packets_and_ignores_duplicates() {
        let start = Instant::now();
        let train = build_probe_train(11, 300, 100, RECEIPT_CHALLENGE).unwrap();
        let mut receiver = ProbeReceiver::default();

        assert!(receiver.receive(&train[2], start).unwrap().is_none());
        assert!(
            receiver
                .receive(&train[0], start + Duration::from_millis(20))
                .unwrap()
                .is_none()
        );
        assert!(
            receiver
                .receive(&train[0], start + Duration::from_millis(40))
                .unwrap()
                .is_none()
        );
        let ack = receiver
            .receive(&train[1], start + Duration::from_millis(100))
            .unwrap()
            .unwrap();

        assert_eq!(ack.received_packets, 3);
        assert_eq!(ack.received_bytes, 300);
        assert_eq!(ack.duration_ns, 100_000_000);
        assert_eq!(ack.receipt_challenge, RECEIPT_CHALLENGE);
    }

    #[test]
    fn receiver_times_out_after_marker_and_expires_missing_marker() {
        let start = Instant::now();
        let train = build_probe_train(12, 300, 100, RECEIPT_CHALLENGE).unwrap();
        let mut receiver = ProbeReceiver::default();

        assert!(receiver.receive(&train[2], start).unwrap().is_none());
        assert!(
            receiver
                .receive(&train[0], start + Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        assert!(receiver.poll(start + Duration::from_millis(999)).is_none());
        let ack = receiver.poll(start + Duration::from_secs(1)).unwrap();
        assert_eq!(ack.received_packets, 2);

        let next = build_probe_train(13, 300, 100, RECEIPT_CHALLENGE).unwrap();
        assert!(
            receiver
                .receive(&next[0], start + Duration::from_secs(2))
                .unwrap()
                .is_none()
        );
        assert!(receiver.poll(start + Duration::from_millis(3999)).is_none());
        assert!(receiver.has_active_generation());
        assert!(receiver.poll(start + Duration::from_secs(4)).is_none());
        assert!(!receiver.has_active_generation());
    }

    #[test]
    fn newer_generation_waits_for_the_active_generation_timeout() {
        let start = Instant::now();
        let old = build_probe_train(20, 300, 100, RECEIPT_CHALLENGE).unwrap();
        let new = build_probe_train(21, 300, 100, RECEIPT_CHALLENGE).unwrap();
        let mut receiver = ProbeReceiver::default();

        receiver.receive(&old[0], start).unwrap();
        receiver
            .receive(&new[0], start + Duration::from_millis(1))
            .unwrap();
        receiver
            .receive(&old[1], start + Duration::from_millis(2))
            .unwrap();

        assert_eq!(receiver.active_generation(), Some(20));
        receiver
            .receive(&new[0], start + Duration::from_secs(2))
            .unwrap();
        assert_eq!(receiver.active_generation(), Some(21));
    }

    #[test]
    fn receiver_uses_one_bit_for_each_expected_packet() {
        let start = Instant::now();
        let packet = ProbeData {
            generation: 30,
            sequence: 0,
            expected_packets: 65_536,
            expected_bytes: 65_536 * 48,
            final_marker: false,
            receipt_challenge: [0; 16],
        }
        .encode_with_size(48)
        .unwrap();
        let mut receiver = ProbeReceiver::default();

        receiver.receive(&packet, start).unwrap();

        assert_eq!(receiver.active.as_ref().unwrap().received.len(), 1024);
    }

    #[test]
    fn sample_calculates_delivery_loss_and_freshness() {
        let measured_at = Instant::now();
        let ack = ProbeAck {
            generation: 31,
            received_packets: 2,
            expected_packets: 3,
            received_bytes: 200,
            expected_bytes: 300,
            duration_ns: 100_000_000,
            receipt_challenge: RECEIPT_CHALLENGE,
        };
        let sample = SpeedSample::from_ack(
            ack,
            Duration::from_millis(200),
            measured_at,
            Duration::from_secs(90),
        );

        assert_eq!(sample.delivery_bps, 8_000);
        assert_eq!(sample.loss_ppm, 333_333);
        assert_eq!(sample.generation, 31);
        assert!(sample.is_fresh(measured_at + Duration::from_millis(89_999)));
        assert!(!sample.is_fresh(measured_at + Duration::from_secs(90)));

        let one_packet = SpeedSample::from_ack(
            ProbeAck {
                received_packets: 1,
                duration_ns: 1,
                ..ack
            },
            Duration::from_nanos(1),
            measured_at,
            Duration::from_secs(90),
        );
        assert_eq!(one_packet.delivery_bps, 0);
    }

    #[test]
    fn sample_ttl_is_three_intervals_and_never_exceeds_protocol_bound() {
        assert_eq!(
            speed_sample_ttl(Duration::from_secs(30)),
            Duration::from_secs(90)
        );
        assert_eq!(
            speed_sample_ttl(Duration::from_secs(300)),
            MAX_SPEED_SAMPLE_TTL
        );
        assert_eq!(
            speed_sample_ttl(Duration::from_secs(301)),
            MAX_SPEED_SAMPLE_TTL
        );
    }

    #[test]
    fn budget_refills_to_one_interval_and_splits_equal_shares() {
        let start = Instant::now();
        let mut budget = ProbeBudget::new(8_000, Duration::from_secs(2), start).unwrap();
        assert_eq!(budget.capacity_bytes(), 2_000);
        assert_eq!(budget.take_cycle_snapshot(start), 2_000);
        assert_eq!(budget.take_cycle_snapshot(start), 0);
        assert_eq!(
            budget.take_cycle_snapshot(start + Duration::from_secs(1)),
            1_000
        );
        assert_eq!(
            budget.take_cycle_snapshot(start + Duration::from_secs(3)),
            2_000
        );

        let allocation = split_cycle_budget(2_000, 3, 300);
        assert_eq!(allocation.shares, vec![666, 666, 666]);
        assert_eq!(allocation.unused_bytes, 2);

        let skipped = split_cycle_budget(1_000, 2, 200);
        assert_eq!(skipped.shares, vec![500, 500]);
        assert_eq!(skipped.unused_bytes, 0);

        let skipped = split_cycle_budget(500, 2, 300);
        assert!(skipped.shares.is_empty());
        assert_eq!(skipped.unused_bytes, 500);
    }

    #[test]
    fn reservation_stops_after_one_second_and_returns_unused_bytes() {
        let start = Instant::now();
        let mut reservation = ProbeReservation::new(1_000, RECEIPT_CHALLENGE, start);

        assert!(reservation.reserve_send(300, start + Duration::from_millis(999)));
        reservation.commit_send(start + Duration::from_millis(999));
        assert!(!reservation.reserve_send(300, start + Duration::from_secs(1)));
        assert_eq!(reservation.sent_bytes(), 300);
        assert_eq!(reservation.unused_bytes(), 700);
        assert_eq!(reservation.send_duration(), Duration::ZERO);
        let valid_ack = ProbeAck {
            generation: 1,
            received_packets: 1,
            expected_packets: 1,
            received_bytes: 300,
            expected_bytes: 300,
            duration_ns: 1,
            receipt_challenge: RECEIPT_CHALLENGE,
        };
        assert!(!reservation.matches_ack(&valid_ack));
        reservation.mark_challenge_sent();
        assert!(reservation.matches_ack(&valid_ack));
        assert!(!reservation.matches_ack(&ProbeAck {
            generation: 1,
            received_packets: 2,
            expected_packets: 2,
            received_bytes: 600,
            expected_bytes: 600,
            duration_ns: 1,
            receipt_challenge: RECEIPT_CHALLENGE,
        }));

        assert!(!reservation.matches_ack(&ProbeAck {
            generation: 1,
            received_packets: 1,
            expected_packets: 1,
            received_bytes: 300,
            expected_bytes: 300,
            duration_ns: 1,
            receipt_challenge: [0x6b; 16],
        }));

        let mut budget = ProbeBudget::new(8_000, Duration::from_secs(1), start).unwrap();
        assert_eq!(budget.take_cycle_snapshot(start), 1_000);
        budget.return_unused(reservation.unused_bytes());
        assert_eq!(budget.available_bytes(), 700);
    }

    #[test]
    fn delayed_ack_does_not_reduce_the_measured_send_rate() {
        let start = Instant::now();
        let mut reservation = ProbeReservation::new(1_000, RECEIPT_CHALLENGE, start);
        assert!(reservation.reserve_send(100, start + Duration::from_millis(10)));
        reservation.commit_send(start + Duration::from_millis(10));
        assert!(reservation.reserve_send(100, start + Duration::from_millis(20)));
        reservation.commit_send(start + Duration::from_millis(20));
        reservation.mark_challenge_sent();
        let ack = ProbeAck {
            generation: 4,
            received_packets: 2,
            expected_packets: 2,
            received_bytes: 200,
            expected_bytes: 200,
            duration_ns: 5_000_000,
            receipt_challenge: RECEIPT_CHALLENGE,
        };

        let sample = SpeedSample::from_ack(
            ack,
            reservation.send_duration(),
            start + Duration::from_secs(2),
            Duration::from_secs(30),
        );

        assert_eq!(sample.delivery_bps, 160_000);
    }
}
