use bytes::{BufMut, Bytes, BytesMut};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use crate::tunnel::TunnelError;

const DATAGRAM_MAGIC: &[u8; 4] = b"ETD4";
const DATAGRAM_KIND_DATA: u8 = 1;
const DATAGRAM_KIND_ACK_RANGE: u8 = 3;
const DATAGRAM_KIND_FRAGMENT_NACK: u8 = 4;
const DATAGRAM_KIND_FEC_SOURCE: u8 = 5;
const DATAGRAM_KIND_FEC_PARITY: u8 = 6;
pub(super) const DATAGRAM_HEADER_LEN: usize = 21;
pub(super) const FEC_SOURCE_HEADER_LEN: usize = 14;
pub(super) const FEC_PARITY_HEADER_LEN: usize = 18;
pub(super) const MAX_DATAGRAM_FRAME_LEN: usize = 65_536;
const MAX_FRAGMENTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DataFragment {
    pub frame_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: usize,
    pub payload: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DatagramMessage {
    Data(DataFragment),
    AckRange {
        largest_frame_id: u64,
        received: u128,
    },
    FragmentNack {
        frame_id: u64,
        missing_fragments: u64,
    },
    FecSource {
        block_id: u64,
        source_index: u8,
        datagram: Bytes,
    },
    FecParity {
        block_id: u64,
        source_count: u8,
        parity_count: u8,
        parity_index: u8,
        shard: Bytes,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReceiveLimits {
    pub max_partial_frames: usize,
    pub max_partial_bytes: usize,
    pub partial_ttl: Duration,
    pub max_delivered_ids: usize,
    pub delivered_ttl: Duration,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            max_partial_frames: 4_096,
            max_partial_bytes: 64 * 1024 * 1024,
            partial_ttl: Duration::from_secs(5),
            max_delivered_ids: 65_536,
            delivered_ttl: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReceiveEvent {
    Pending,
    Complete { frame_id: u64, frame: Bytes },
    Duplicate { frame_id: u64 },
}

struct PartialFrame {
    fragment_count: u16,
    total_len: usize,
    fragments: Vec<Option<Bytes>>,
    received_fragments: usize,
    received_bytes: usize,
    created_at: Instant,
    nack_sent: bool,
}

pub(super) struct ReceiveState {
    limits: ReceiveLimits,
    partial: HashMap<u64, PartialFrame>,
    partial_bytes: usize,
    delivered_ids: HashSet<u64>,
    delivered_order: VecDeque<(u64, Instant)>,
    largest_delivered_id: Option<u64>,
    delivered_bitmap: u128,
    completed_since_feedback: usize,
    feedback_started_at: Option<Instant>,
    expired_partial_frames: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SendLimits {
    pub max_pending_frames: usize,
    pub max_pending_bytes: usize,
    pub max_retries: u8,
}

impl Default for SendLimits {
    fn default() -> Self {
        Self {
            max_pending_frames: 131_072,
            max_pending_bytes: 256 * 1024 * 1024,
            max_retries: 1,
        }
    }
}

struct PendingFrame {
    datagrams: Vec<Bytes>,
    encoded_bytes: usize,
    retries: u8,
}

#[derive(Clone, Debug)]
pub(super) struct QueuedFrame {
    pub frame_id: u64,
    pub datagrams: Vec<Bytes>,
    pub pending_bytes: usize,
}

#[derive(Clone, Debug)]
pub(super) struct RetryFrame {
    pub frame_id: u64,
    pub datagrams: Vec<Bytes>,
}

#[derive(Default, Debug)]
pub(super) struct RetrySweep {
    pub retries: Vec<RetryFrame>,
    pub exhausted: Vec<u64>,
}

pub(super) struct SendState {
    limits: SendLimits,
    next_frame_id: u64,
    pending: HashMap<u64, PendingFrame>,
    pending_bytes: usize,
    deadlines: BinaryHeap<Reverse<(Instant, u64, u8)>>,
}

impl Default for SendState {
    fn default() -> Self {
        Self::new(SendLimits::default())
    }
}

impl SendState {
    pub fn new(limits: SendLimits) -> Self {
        Self {
            limits,
            next_frame_id: 1,
            pending: HashMap::new(),
            pending_bytes: 0,
            deadlines: BinaryHeap::new(),
        }
    }

    pub fn queue(
        &mut self,
        frame: Bytes,
        max_datagram_size: usize,
        now: Instant,
        rto: Duration,
    ) -> Result<QueuedFrame, TunnelError> {
        if rto.is_zero() {
            return Err(invalid("retransmission timeout is zero"));
        }
        let frame_id = self.next_frame_id;
        let datagrams = encode_frame(frame_id, frame, max_datagram_size)?;
        let encoded_bytes = datagrams.iter().map(Bytes::len).sum::<usize>();
        if self.pending.len() >= self.limits.max_pending_frames
            || self.pending_bytes + encoded_bytes > self.limits.max_pending_bytes
        {
            return Err(TunnelError::BufferFull);
        }

        self.next_frame_id = self.next_frame_id.wrapping_add(1).max(1);
        self.pending_bytes += encoded_bytes;
        self.pending.insert(
            frame_id,
            PendingFrame {
                datagrams: datagrams.clone(),
                encoded_bytes,
                retries: 0,
            },
        );
        self.deadlines.push(Reverse((now + rto, frame_id, 0)));
        Ok(QueuedFrame {
            frame_id,
            datagrams,
            pending_bytes: self.pending_bytes,
        })
    }

    pub fn acknowledge(&mut self, frame_id: u64) -> bool {
        let Some(pending) = self.pending.remove(&frame_id) else {
            return false;
        };
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.encoded_bytes);
        true
    }

    pub fn acknowledge_range(&mut self, largest_frame_id: u64, mut received: u128) -> usize {
        let mut acknowledged = 0;
        while received != 0 {
            let offset = received.trailing_zeros() as u64;
            received &= received - 1;
            let Some(frame_id) = largest_frame_id.checked_sub(offset) else {
                continue;
            };
            acknowledged += usize::from(self.acknowledge(frame_id));
        }
        acknowledged
    }

    pub fn selective_fragments(&self, frame_id: u64, missing_fragments: u64) -> Option<Vec<Bytes>> {
        let pending = self.pending.get(&frame_id)?;
        Some(
            pending
                .datagrams
                .iter()
                .enumerate()
                .filter(|(index, _)| missing_fragments & (1_u64 << index) != 0)
                .map(|(_, datagram)| datagram.clone())
                .collect(),
        )
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn has_service_work(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn retries_due(&mut self, now: Instant, rto: Duration) -> RetrySweep {
        let mut sweep = RetrySweep::default();
        while let Some(Reverse((deadline, frame_id, generation))) = self.deadlines.peek().copied() {
            if deadline > now {
                break;
            }
            self.deadlines.pop();
            let Some(pending) = self.pending.get_mut(&frame_id) else {
                continue;
            };
            if pending.retries != generation {
                continue;
            }
            if pending.retries >= self.limits.max_retries {
                sweep.exhausted.push(frame_id);
                continue;
            }
            pending.retries += 1;
            sweep.retries.push(RetryFrame {
                frame_id,
                datagrams: pending.datagrams.clone(),
            });
            self.deadlines
                .push(Reverse((now + rto, frame_id, pending.retries)));
        }

        sweep.exhausted.sort_unstable();
        sweep.retries.sort_by_key(|retry| retry.frame_id);
        for frame_id in &sweep.exhausted {
            let pending = self.pending.remove(frame_id).unwrap();
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.encoded_bytes);
        }
        sweep
    }

    #[cfg(test)]
    fn pending_frame_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for ReceiveState {
    fn default() -> Self {
        Self::new(ReceiveLimits::default())
    }
}

impl ReceiveState {
    pub fn new(limits: ReceiveLimits) -> Self {
        Self {
            limits,
            partial: HashMap::new(),
            partial_bytes: 0,
            delivered_ids: HashSet::new(),
            delivered_order: VecDeque::new(),
            largest_delivered_id: None,
            delivered_bitmap: 0,
            completed_since_feedback: 0,
            feedback_started_at: None,
            expired_partial_frames: 0,
        }
    }

    fn expire(&mut self, now: Instant) {
        let partial_ttl = self.limits.partial_ttl;
        let mut expired_bytes = 0;
        let mut expired_frames = 0;
        self.partial.retain(|_, partial| {
            let retain = now.saturating_duration_since(partial.created_at) <= partial_ttl;
            if !retain {
                expired_bytes += partial.received_bytes;
                expired_frames += 1;
            }
            retain
        });
        self.partial_bytes = self.partial_bytes.saturating_sub(expired_bytes);
        self.expired_partial_frames = self.expired_partial_frames.saturating_add(expired_frames);

        while let Some(&(frame_id, delivered_at)) = self.delivered_order.front() {
            if self.delivered_order.len() <= self.limits.max_delivered_ids
                && now.saturating_duration_since(delivered_at) <= self.limits.delivered_ttl
            {
                break;
            }
            self.delivered_order.pop_front();
            self.delivered_ids.remove(&frame_id);
        }
    }

    fn record_delivered(&mut self, frame_id: u64, now: Instant) {
        if self.completed_since_feedback == 0 {
            self.feedback_started_at = Some(now);
        }
        self.completed_since_feedback = self.completed_since_feedback.saturating_add(1);
        match self.largest_delivered_id {
            None => {
                self.largest_delivered_id = Some(frame_id);
                self.delivered_bitmap = 1;
            }
            Some(largest) if frame_id > largest => {
                let shift = frame_id - largest;
                self.delivered_bitmap = if shift < u128::BITS as u64 {
                    self.delivered_bitmap << shift
                } else {
                    0
                };
                self.delivered_bitmap |= 1;
                self.largest_delivered_id = Some(frame_id);
            }
            Some(largest) => {
                let offset = largest - frame_id;
                if offset < u128::BITS as u64 {
                    self.delivered_bitmap |= 1_u128 << offset;
                }
            }
        }
        self.delivered_ids.insert(frame_id);
        self.delivered_order.push_back((frame_id, now));
        self.expire(now);
    }

    pub fn ingest(
        &mut self,
        fragment: DataFragment,
        now: Instant,
    ) -> Result<ReceiveEvent, TunnelError> {
        self.expire(now);
        if self.delivered_ids.contains(&fragment.frame_id) {
            return Ok(ReceiveEvent::Duplicate {
                frame_id: fragment.frame_id,
            });
        }
        if fragment.fragment_count == 1 {
            if fragment.fragment_index != 0 || fragment.payload.len() != fragment.total_len {
                return Err(invalid("single-fragment frame geometry is inconsistent"));
            }
            let frame_id = fragment.frame_id;
            self.record_delivered(frame_id, now);
            return Ok(ReceiveEvent::Complete {
                frame_id,
                frame: fragment.payload,
            });
        }

        if !self.partial.contains_key(&fragment.frame_id) {
            if self.partial.len() >= self.limits.max_partial_frames
                || self.partial_bytes + fragment.payload.len() > self.limits.max_partial_bytes
            {
                return Err(TunnelError::BufferFull);
            }
            self.partial.insert(
                fragment.frame_id,
                PartialFrame {
                    fragment_count: fragment.fragment_count,
                    total_len: fragment.total_len,
                    fragments: vec![None; fragment.fragment_count as usize],
                    received_fragments: 0,
                    received_bytes: 0,
                    created_at: now,
                    nack_sent: false,
                },
            );
        }

        let partial = self.partial.get_mut(&fragment.frame_id).unwrap();
        if partial.fragment_count != fragment.fragment_count
            || partial.total_len != fragment.total_len
        {
            return Err(invalid("fragment metadata changed within a frame"));
        }
        let slot = &mut partial.fragments[fragment.fragment_index as usize];
        if let Some(previous) = slot {
            if previous != &fragment.payload {
                return Err(invalid("fragment payload changed within a frame"));
            }
            return Ok(ReceiveEvent::Pending);
        }
        if self.partial_bytes + fragment.payload.len() > self.limits.max_partial_bytes {
            return Err(TunnelError::BufferFull);
        }
        partial.received_fragments += 1;
        partial.received_bytes += fragment.payload.len();
        self.partial_bytes += fragment.payload.len();
        *slot = Some(fragment.payload);

        if partial.received_fragments != partial.fragment_count as usize {
            return Ok(ReceiveEvent::Pending);
        }

        let partial = self.partial.remove(&fragment.frame_id).unwrap();
        self.partial_bytes = self.partial_bytes.saturating_sub(partial.received_bytes);
        if partial.received_bytes != partial.total_len {
            return Err(invalid(format!(
                "reassembled length {} differs from declared length {}",
                partial.received_bytes, partial.total_len
            )));
        }

        let frame = if partial.fragment_count == 1 {
            partial.fragments.into_iter().next().unwrap().unwrap()
        } else {
            let mut frame = BytesMut::with_capacity(partial.total_len);
            for payload in partial.fragments {
                frame.put_slice(&payload.unwrap());
            }
            frame.freeze()
        };
        self.record_delivered(fragment.frame_id, now);
        Ok(ReceiveEvent::Complete {
            frame_id: fragment.frame_id,
            frame,
        })
    }

    pub fn ack_range(&self) -> Option<(u64, u128)> {
        self.largest_delivered_id
            .map(|largest| (largest, self.delivered_bitmap))
    }

    pub fn take_ack_range_if_due(
        &mut self,
        now: Instant,
        max_completed: usize,
        max_delay: Duration,
    ) -> Option<(u64, u128)> {
        if self.completed_since_feedback == 0 {
            return None;
        }
        let due_by_count = self.completed_since_feedback >= max_completed.max(1);
        let due_by_time = self
            .feedback_started_at
            .is_some_and(|started_at| now.saturating_duration_since(started_at) >= max_delay);
        if !due_by_count && !due_by_time {
            return None;
        }

        self.completed_since_feedback = 0;
        self.feedback_started_at = None;
        self.ack_range()
    }

    pub fn nacks_due(&mut self, now: Instant, grace: Duration) -> Vec<(u64, u64)> {
        self.expire(now);
        let mut due = Vec::new();
        for (&frame_id, partial) in &mut self.partial {
            if partial.nack_sent || now.saturating_duration_since(partial.created_at) < grace {
                continue;
            }
            let count = usize::from(partial.fragment_count);
            let all_fragments = if count == u64::BITS as usize {
                u64::MAX
            } else {
                (1_u64 << count) - 1
            };
            let received = partial
                .fragments
                .iter()
                .enumerate()
                .fold(0_u64, |bitmap, (index, fragment)| {
                    bitmap | (u64::from(fragment.is_some()) << index)
                });
            let missing = all_fragments & !received;
            if missing != 0 {
                partial.nack_sent = true;
                due.push((frame_id, missing));
            }
        }
        due.sort_unstable_by_key(|(frame_id, _)| *frame_id);
        due
    }

    pub fn take_expired_partial_frames(&mut self) -> usize {
        std::mem::take(&mut self.expired_partial_frames)
    }

    pub fn has_service_work(&self) -> bool {
        self.completed_since_feedback != 0 || !self.partial.is_empty()
    }

    #[cfg(test)]
    fn partial_frame_count(&self) -> usize {
        self.partial.len()
    }
}

fn invalid(message: impl Into<String>) -> TunnelError {
    TunnelError::InvalidPacket(format!(
        "invalid reliable QUIC DATAGRAM: {}",
        message.into()
    ))
}

fn encode_header(
    output: &mut BytesMut,
    kind: u8,
    frame_id: u64,
    fragment_index: u16,
    fragment_count: u16,
    total_len: u32,
) {
    output.put_slice(DATAGRAM_MAGIC);
    output.put_u8(kind);
    output.put_u64(frame_id);
    output.put_u16(fragment_index);
    output.put_u16(fragment_count);
    output.put_u32(total_len);
}

pub(super) fn encode_frame(
    frame_id: u64,
    frame: Bytes,
    max_datagram_size: usize,
) -> Result<Vec<Bytes>, TunnelError> {
    if frame.is_empty() || frame.len() > MAX_DATAGRAM_FRAME_LEN {
        return Err(invalid(format!(
            "frame length {} is outside 1..={MAX_DATAGRAM_FRAME_LEN}",
            frame.len()
        )));
    }
    let fragment_payload_len = max_datagram_size
        .checked_sub(DATAGRAM_HEADER_LEN)
        .filter(|len| *len > 0)
        .ok_or_else(|| {
            invalid(format!(
                "maximum datagram size {max_datagram_size} is too small"
            ))
        })?;
    let fragment_count = frame.len().div_ceil(fragment_payload_len);
    if fragment_count > MAX_FRAGMENTS {
        return Err(invalid(format!(
            "frame needs {fragment_count} fragments, maximum is {MAX_FRAGMENTS}"
        )));
    }

    let fragment_count_u16 = fragment_count as u16;
    let total_len = frame.len() as u32;
    let mut datagrams = Vec::with_capacity(fragment_count);
    for fragment_index in 0..fragment_count {
        let start = fragment_index * fragment_payload_len;
        let end = (start + fragment_payload_len).min(frame.len());
        let payload = &frame[start..end];
        let mut output = BytesMut::with_capacity(DATAGRAM_HEADER_LEN + payload.len());
        encode_header(
            &mut output,
            DATAGRAM_KIND_DATA,
            frame_id,
            fragment_index as u16,
            fragment_count_u16,
            total_len,
        );
        output.put_slice(payload);
        datagrams.push(output.freeze());
    }
    Ok(datagrams)
}

pub(super) fn encode_ack_range(largest_frame_id: u64, received: u128) -> Bytes {
    let mut output = BytesMut::with_capacity(29);
    output.put_slice(DATAGRAM_MAGIC);
    output.put_u8(DATAGRAM_KIND_ACK_RANGE);
    output.put_u64(largest_frame_id);
    output.put_u128(received);
    output.freeze()
}

pub(super) fn encode_fragment_nack(frame_id: u64, missing_fragments: u64) -> Bytes {
    let mut output = BytesMut::with_capacity(DATAGRAM_HEADER_LEN);
    output.put_slice(DATAGRAM_MAGIC);
    output.put_u8(DATAGRAM_KIND_FRAGMENT_NACK);
    output.put_u64(frame_id);
    output.put_u64(missing_fragments);
    output.freeze()
}

pub(super) fn encode_fec_source(
    block_id: u64,
    source_index: u8,
    datagram: Bytes,
) -> Result<Bytes, TunnelError> {
    if block_id == 0 || source_index >= 16 || datagram.is_empty() {
        return Err(invalid("invalid FEC source metadata"));
    }
    let mut output = BytesMut::with_capacity(FEC_SOURCE_HEADER_LEN + datagram.len());
    output.put_slice(DATAGRAM_MAGIC);
    output.put_u8(DATAGRAM_KIND_FEC_SOURCE);
    output.put_u64(block_id);
    output.put_u8(source_index);
    output.put_slice(&datagram);
    Ok(output.freeze())
}

pub(super) fn encode_fec_parity(
    block_id: u64,
    source_count: u8,
    parity_count: u8,
    parity_index: u8,
    shard: Bytes,
) -> Result<Bytes, TunnelError> {
    if block_id == 0
        || !(1..=16).contains(&source_count)
        || !(1..=3).contains(&parity_count)
        || parity_index >= parity_count
        || shard.is_empty()
        || shard.len() > u16::MAX as usize
        || !shard.len().is_multiple_of(2)
    {
        return Err(invalid("invalid FEC parity metadata"));
    }
    let mut output = BytesMut::with_capacity(FEC_PARITY_HEADER_LEN + shard.len());
    output.put_slice(DATAGRAM_MAGIC);
    output.put_u8(DATAGRAM_KIND_FEC_PARITY);
    output.put_u64(block_id);
    output.put_u8(source_count);
    output.put_u8(parity_count);
    output.put_u8(parity_index);
    output.put_u16(shard.len() as u16);
    output.put_slice(&shard);
    Ok(output.freeze())
}

pub(super) fn decode_datagram(bytes: Bytes) -> Result<DatagramMessage, TunnelError> {
    if bytes.len() < 5 {
        return Err(invalid(format!(
            "message length {} is below 5",
            bytes.len()
        )));
    }
    if &bytes[..4] != DATAGRAM_MAGIC {
        return Err(invalid("bad magic"));
    }

    let kind = bytes[4];

    match kind {
        DATAGRAM_KIND_ACK_RANGE => {
            if bytes.len() != 29 {
                return Err(invalid("ACK range has an invalid length"));
            }
            let largest_frame_id = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
            let received = u128::from_be_bytes(bytes[13..29].try_into().unwrap());
            if largest_frame_id == 0 || received & 1 == 0 {
                return Err(invalid(
                    "ACK range must include a non-zero largest frame ID",
                ));
            }
            Ok(DatagramMessage::AckRange {
                largest_frame_id,
                received,
            })
        }
        DATAGRAM_KIND_FRAGMENT_NACK => {
            if bytes.len() != DATAGRAM_HEADER_LEN {
                return Err(invalid("fragment NACK has an invalid length"));
            }
            let frame_id = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
            let missing_fragments = u64::from_be_bytes(bytes[13..21].try_into().unwrap());
            if frame_id == 0 || missing_fragments == 0 {
                return Err(invalid(
                    "fragment NACK must identify a frame and missing fragment",
                ));
            }
            Ok(DatagramMessage::FragmentNack {
                frame_id,
                missing_fragments,
            })
        }
        DATAGRAM_KIND_FEC_SOURCE => {
            if bytes.len() <= FEC_SOURCE_HEADER_LEN {
                return Err(invalid("FEC source has an invalid length"));
            }
            let block_id = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
            let source_index = bytes[13];
            if block_id == 0 || source_index >= 16 {
                return Err(invalid("invalid FEC source metadata"));
            }
            Ok(DatagramMessage::FecSource {
                block_id,
                source_index,
                datagram: bytes.slice(FEC_SOURCE_HEADER_LEN..),
            })
        }
        DATAGRAM_KIND_FEC_PARITY => {
            if bytes.len() < FEC_PARITY_HEADER_LEN {
                return Err(invalid("FEC parity has an invalid length"));
            }
            let block_id = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
            let source_count = bytes[13];
            let parity_count = bytes[14];
            let parity_index = bytes[15];
            let shard_len = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
            if block_id == 0
                || !(1..=16).contains(&source_count)
                || !(1..=3).contains(&parity_count)
                || parity_index >= parity_count
                || shard_len == 0
                || shard_len % 2 != 0
                || bytes.len() != FEC_PARITY_HEADER_LEN + shard_len
            {
                return Err(invalid("invalid FEC parity metadata"));
            }
            Ok(DatagramMessage::FecParity {
                block_id,
                source_count,
                parity_count,
                parity_index,
                shard: bytes.slice(FEC_PARITY_HEADER_LEN..),
            })
        }
        DATAGRAM_KIND_DATA => {
            if bytes.len() < DATAGRAM_HEADER_LEN {
                return Err(invalid("data message is shorter than its header"));
            }
            let frame_id = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
            let fragment_index = u16::from_be_bytes(bytes[13..15].try_into().unwrap());
            let fragment_count = u16::from_be_bytes(bytes[15..17].try_into().unwrap());
            let total_len = u32::from_be_bytes(bytes[17..21].try_into().unwrap()) as usize;
            let fragment_count_usize = fragment_count as usize;
            if fragment_count_usize == 0 || fragment_count_usize > MAX_FRAGMENTS {
                return Err(invalid(format!(
                    "fragment count {fragment_count_usize} is outside 1..={MAX_FRAGMENTS}"
                )));
            }
            if fragment_index >= fragment_count {
                return Err(invalid(format!(
                    "fragment index {fragment_index} is not below count {fragment_count}"
                )));
            }
            let payload = bytes.slice(DATAGRAM_HEADER_LEN..);
            if payload.is_empty() {
                return Err(invalid("data fragment payload is empty"));
            }
            if total_len == 0 || total_len > MAX_DATAGRAM_FRAME_LEN || payload.len() > total_len {
                return Err(invalid(format!(
                    "declared frame length {total_len} is inconsistent with fragment length {}",
                    payload.len()
                )));
            }
            if fragment_count == 1 && (fragment_index != 0 || payload.len() != total_len) {
                return Err(invalid("single-fragment frame geometry is inconsistent"));
            }
            if fragment_count_usize > total_len {
                return Err(invalid("fragment count exceeds declared frame length"));
            }

            Ok(DatagramMessage::Data(DataFragment {
                frame_id,
                fragment_index,
                fragment_count,
                total_len,
                payload,
            }))
        }
        _ => Err(invalid(format!("unknown message kind {kind}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn codec_round_trips_single_and_fragmented_frames() {
        for (frame_len, datagram_size) in [(64, 1200), (4096, 1200), (65_536, 1200)] {
            let frame = Bytes::from(vec![0x5a; frame_len]);
            let encoded = encode_frame(41, frame.clone(), datagram_size).unwrap();
            assert_eq!(
                encoded.len(),
                frame_len.div_ceil(datagram_size - DATAGRAM_HEADER_LEN)
            );

            let mut decoded = encoded
                .into_iter()
                .map(decode_datagram)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            decoded.sort_by_key(|message| match message {
                DatagramMessage::Data(fragment) => fragment.fragment_index,
                _ => unreachable!(),
            });

            let mut rebuilt = Vec::with_capacity(frame_len);
            for message in decoded {
                let DatagramMessage::Data(fragment) = message else {
                    unreachable!()
                };
                assert_eq!(fragment.frame_id, 41);
                assert_eq!(fragment.total_len, frame_len);
                rebuilt.extend_from_slice(&fragment.payload);
            }
            assert_eq!(rebuilt, frame);
        }
    }

    #[test]
    fn codec_rejects_legacy_acks_and_malformed_envelopes() {
        let mut legacy_ack = BytesMut::with_capacity(DATAGRAM_HEADER_LEN);
        encode_header(&mut legacy_ack, 2, 99, 0, 0, 0);
        assert!(decode_datagram(legacy_ack.freeze()).is_err());

        let mut bad_magic = encode_ack_range(1, 1).to_vec();
        bad_magic[0] ^= 0xff;
        assert!(decode_datagram(Bytes::from(bad_magic)).is_err());

        let mut bad_geometry = encode_frame(1, Bytes::from_static(b"frame"), 1200)
            .unwrap()
            .remove(0)
            .to_vec();
        bad_geometry[13..15].copy_from_slice(&1_u16.to_be_bytes());
        bad_geometry[15..17].copy_from_slice(&1_u16.to_be_bytes());
        assert!(decode_datagram(Bytes::from(bad_geometry)).is_err());

        assert!(encode_frame(1, Bytes::from_static(b"frame"), DATAGRAM_HEADER_LEN).is_err());
        assert!(encode_frame(1, Bytes::from(vec![0; 65_537]), 1200).is_err());
    }

    #[test]
    fn etd4_codec_round_trips_ack_ranges_and_fragment_nacks() {
        let received = (1_u128 << 0) | (1_u128 << 1) | (1_u128 << 17) | (1_u128 << 127);
        assert_eq!(
            decode_datagram(encode_ack_range(500, received)).unwrap(),
            DatagramMessage::AckRange {
                largest_frame_id: 500,
                received,
            }
        );

        let missing_fragments = (1_u64 << 2) | (1_u64 << 9) | (1_u64 << 63);
        assert_eq!(
            decode_datagram(encode_fragment_nack(77, missing_fragments)).unwrap(),
            DatagramMessage::FragmentNack {
                frame_id: 77,
                missing_fragments,
            }
        );
    }

    #[test]
    fn etd4_codec_round_trips_systematic_fec_source_and_parity() {
        let source = Bytes::from_static(b"encoded-etd4-source");
        assert_eq!(
            decode_datagram(encode_fec_source(91, 15, source.clone()).unwrap()).unwrap(),
            DatagramMessage::FecSource {
                block_id: 91,
                source_index: 15,
                datagram: source,
            }
        );

        let parity = Bytes::from(vec![0x5a; 1182]);
        assert_eq!(
            decode_datagram(encode_fec_parity(91, 16, 2, 1, parity.clone()).unwrap()).unwrap(),
            DatagramMessage::FecParity {
                block_id: 91,
                source_count: 16,
                parity_count: 2,
                parity_index: 1,
                shard: parity,
            }
        );
        assert!(encode_fec_source(0, 0, Bytes::from_static(b"x")).is_err());
        assert!(encode_fec_parity(1, 16, 2, 2, Bytes::from_static(b"xx")).is_err());
    }

    #[test]
    fn receiver_reassembles_out_of_order_once_and_reacks_duplicates() {
        let expected = Bytes::from(vec![0xa5; 4096]);
        let mut fragments = encode_frame(7, expected.clone(), 600)
            .unwrap()
            .into_iter()
            .map(|bytes| match decode_datagram(bytes).unwrap() {
                DatagramMessage::Data(fragment) => fragment,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        fragments.reverse();
        let duplicate = fragments[0].clone();

        let now = Instant::now();
        let mut receiver = ReceiveState::default();
        for fragment in fragments.iter().take(fragments.len() - 1).cloned() {
            assert_eq!(
                receiver.ingest(fragment, now).unwrap(),
                ReceiveEvent::Pending
            );
        }
        assert_eq!(
            receiver
                .ingest(fragments.last().unwrap().clone(), now)
                .unwrap(),
            ReceiveEvent::Complete {
                frame_id: 7,
                frame: expected,
            }
        );
        assert_eq!(
            receiver.ingest(duplicate, now).unwrap(),
            ReceiveEvent::Duplicate { frame_id: 7 },
            "a retransmission must be acknowledged again without redelivery"
        );
    }

    #[test]
    fn receiver_completes_single_fragment_without_partial_storage() {
        let limits = ReceiveLimits {
            max_partial_frames: 0,
            max_partial_bytes: 0,
            ..ReceiveLimits::default()
        };
        let fragment = match decode_datagram(
            encode_frame(8, Bytes::from_static(b"complete"), 1200)
                .unwrap()
                .remove(0),
        )
        .unwrap()
        {
            DatagramMessage::Data(fragment) => fragment,
            _ => unreachable!(),
        };
        let mut receiver = ReceiveState::new(limits);

        assert_eq!(
            receiver.ingest(fragment, Instant::now()).unwrap(),
            ReceiveEvent::Complete {
                frame_id: 8,
                frame: Bytes::from_static(b"complete"),
            }
        );
        assert_eq!(receiver.partial_frame_count(), 0);
    }

    #[test]
    fn receiver_expires_partial_frames_and_enforces_bounds() {
        let limits = ReceiveLimits {
            max_partial_frames: 1,
            max_partial_bytes: 1024,
            partial_ttl: Duration::from_millis(10),
            ..ReceiveLimits::default()
        };
        let now = Instant::now();
        let first = match decode_datagram(
            encode_frame(1, Bytes::from(vec![1; 900]), 600)
                .unwrap()
                .remove(0),
        )
        .unwrap()
        {
            DatagramMessage::Data(fragment) => fragment,
            _ => unreachable!(),
        };
        let second = match decode_datagram(
            encode_frame(2, Bytes::from(vec![2; 900]), 600)
                .unwrap()
                .remove(0),
        )
        .unwrap()
        {
            DatagramMessage::Data(fragment) => fragment,
            _ => unreachable!(),
        };

        let mut receiver = ReceiveState::new(limits);
        assert_eq!(
            receiver.ingest(first.clone(), now).unwrap(),
            ReceiveEvent::Pending
        );
        assert!(matches!(
            receiver.ingest(second.clone(), now),
            Err(TunnelError::BufferFull)
        ));
        assert_eq!(receiver.partial_frame_count(), 1);

        assert_eq!(
            receiver
                .ingest(second, now + Duration::from_millis(11))
                .unwrap(),
            ReceiveEvent::Pending
        );
        assert_eq!(receiver.partial_frame_count(), 1);
        assert_eq!(receiver.take_expired_partial_frames(), 1);
    }

    #[test]
    fn sender_retries_a_dropped_frame_and_ack_releases_it() {
        let now = Instant::now();
        let rto = Duration::from_millis(100);
        let mut sender = SendState::new(SendLimits {
            max_retries: 2,
            ..SendLimits::default()
        });
        let queued = sender
            .queue(Bytes::from(vec![0x33; 1500]), 1200, now, rto)
            .unwrap();
        assert_eq!(
            queued.pending_bytes,
            queued.datagrams.iter().map(Bytes::len).sum::<usize>()
        );
        assert_eq!(sender.pending_frame_count(), 1);
        assert!(
            sender
                .retries_due(now + Duration::from_millis(99), rto)
                .retries
                .is_empty()
        );

        let retry = sender.retries_due(now + rto, rto);
        assert_eq!(retry.retries.len(), 1);
        assert_eq!(retry.retries[0].frame_id, queued.frame_id);
        assert_eq!(retry.retries[0].datagrams, queued.datagrams);
        assert!(retry.exhausted.is_empty());

        assert!(sender.acknowledge(queued.frame_id));
        assert_eq!(sender.pending_frame_count(), 0);
        assert!(!sender.has_service_work());
        assert!(
            sender
                .retries_due(now + Duration::from_secs(1), rto)
                .retries
                .is_empty()
        );
    }

    #[test]
    fn sender_and_receiver_report_only_pending_service_work() {
        let now = Instant::now();
        let mut sender = SendState::default();
        let queued = sender
            .queue(
                Bytes::from_static(b"frame"),
                1200,
                now,
                Duration::from_millis(100),
            )
            .unwrap();
        assert!(sender.has_service_work());
        assert!(sender.acknowledge(queued.frame_id));
        assert!(!sender.has_service_work());

        let fragment = match decode_datagram(queued.datagrams[0].clone()).unwrap() {
            DatagramMessage::Data(fragment) => fragment,
            _ => unreachable!(),
        };
        let mut receiver = ReceiveState::default();
        receiver.ingest(fragment, now).unwrap();
        assert!(receiver.has_service_work());
        assert!(
            receiver
                .take_ack_range_if_due(now, 1, Duration::from_secs(1))
                .is_some()
        );
        assert!(!receiver.has_service_work());
    }

    #[test]
    fn sender_caps_retries_without_blocking_independent_frames() {
        let now = Instant::now();
        let rto = Duration::from_millis(100);
        let mut sender = SendState::new(SendLimits {
            max_retries: 1,
            max_pending_frames: 2,
            ..SendLimits::default()
        });
        let first = sender
            .queue(Bytes::from_static(b"first"), 1200, now, rto)
            .unwrap();
        let second = sender
            .queue(Bytes::from_static(b"second"), 1200, now, rto)
            .unwrap();
        let due = sender.retries_due(now + rto, rto);
        let mut retried_ids = due
            .retries
            .iter()
            .map(|retry| retry.frame_id)
            .collect::<Vec<_>>();
        retried_ids.sort_unstable();
        assert_eq!(retried_ids, vec![first.frame_id, second.frame_id]);

        assert!(sender.acknowledge(second.frame_id));
        let exhausted = sender.retries_due(now + rto + rto, rto);
        assert_eq!(exhausted.exhausted, vec![first.frame_id]);
        assert!(exhausted.retries.is_empty());
        assert_eq!(sender.pending_frame_count(), 0);

        assert!(
            sender
                .queue(Bytes::from_static(b"later"), 1200, now + rto + rto, rto)
                .is_ok()
        );
    }

    #[test]
    fn ack_range_releases_multiple_frames_without_per_frame_feedback() {
        let now = Instant::now();
        let rto = Duration::from_millis(100);
        let mut sender = SendState::default();
        let first = sender
            .queue(Bytes::from_static(b"first"), 1200, now, rto)
            .unwrap();
        let second = sender
            .queue(Bytes::from_static(b"second"), 1200, now, rto)
            .unwrap();
        let third = sender
            .queue(Bytes::from_static(b"third"), 1200, now, rto)
            .unwrap();

        assert_eq!(
            sender.acknowledge_range(third.frame_id, 0b101),
            2,
            "bits zero and two acknowledge the largest and largest-minus-two"
        );
        assert_eq!(sender.pending_frame_count(), 1);
        assert!(!sender.acknowledge(first.frame_id));
        assert!(sender.acknowledge(second.frame_id));
    }

    #[test]
    fn fragment_nack_selects_only_missing_fragments() {
        let now = Instant::now();
        let mut sender = SendState::default();
        let queued = sender
            .queue(
                Bytes::from(vec![0x5a; 3_000]),
                600,
                now,
                Duration::from_millis(100),
            )
            .unwrap();
        assert!(queued.datagrams.len() >= 5);

        let selected = sender
            .selective_fragments(queued.frame_id, (1 << 1) | (1 << 4))
            .unwrap();
        assert_eq!(
            selected,
            vec![queued.datagrams[1].clone(), queued.datagrams[4].clone()]
        );
        assert_eq!(sender.pending_frame_count(), 1);
    }

    #[test]
    fn receiver_builds_ack_window_and_nacks_only_missing_fragments_after_grace() {
        let now = Instant::now();
        let grace = Duration::from_millis(20);
        let mut receiver = ReceiveState::default();

        for frame_id in [130_u64, 128] {
            let fragment = match decode_datagram(
                encode_frame(frame_id, Bytes::from_static(b"frame"), 1200)
                    .unwrap()
                    .remove(0),
            )
            .unwrap()
            {
                DatagramMessage::Data(fragment) => fragment,
                _ => unreachable!(),
            };
            assert!(matches!(
                receiver.ingest(fragment, now),
                Ok(ReceiveEvent::Complete { .. })
            ));
        }
        assert_eq!(receiver.ack_range(), Some((130, 0b101)));

        let fragments = encode_frame(200, Bytes::from(vec![0x33; 1_500]), 600)
            .unwrap()
            .into_iter()
            .map(|bytes| match decode_datagram(bytes).unwrap() {
                DatagramMessage::Data(fragment) => fragment,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        receiver.ingest(fragments[0].clone(), now).unwrap();
        assert!(
            receiver
                .nacks_due(now + grace - Duration::from_millis(1), grace)
                .is_empty()
        );
        assert_eq!(receiver.nacks_due(now + grace, grace), vec![(200, 0b110)]);
        assert!(receiver.nacks_due(now + grace + grace, grace).is_empty());
    }

    #[test]
    fn ack_feedback_batches_by_count_or_deadline() {
        let now = Instant::now();
        let delay = Duration::from_millis(2);
        let mut receiver = ReceiveState::default();

        for frame_id in 1..=15 {
            let fragment = match decode_datagram(
                encode_frame(frame_id, Bytes::from_static(b"x"), 1200)
                    .unwrap()
                    .remove(0),
            )
            .unwrap()
            {
                DatagramMessage::Data(fragment) => fragment,
                _ => unreachable!(),
            };
            receiver.ingest(fragment, now).unwrap();
        }
        assert_eq!(receiver.take_ack_range_if_due(now, 16, delay), None);
        assert!(
            receiver
                .take_ack_range_if_due(now + delay, 16, delay)
                .is_some()
        );

        for frame_id in 16..=31 {
            let fragment = match decode_datagram(
                encode_frame(frame_id, Bytes::from_static(b"x"), 1200)
                    .unwrap()
                    .remove(0),
            )
            .unwrap()
            {
                DatagramMessage::Data(fragment) => fragment,
                _ => unreachable!(),
            };
            receiver.ingest(fragment, now + delay).unwrap();
        }
        assert!(
            receiver
                .take_ack_range_if_due(now + delay, 16, delay)
                .is_some()
        );
        assert_eq!(receiver.take_ack_range_if_due(now + delay, 16, delay), None);
    }

    #[test]
    fn default_retry_budget_is_one_round_trip() {
        assert_eq!(
            SendLimits::default().max_retries,
            1,
            "L2 data must not accumulate a multi-second application retry tail"
        );
    }
}
