//! Bounded NIC admission. A blocked flow retains its ordering independently of
//! other flows; queued overload is charged to the largest queued flow.
use crate::tunnel::queue_feedback::FlowQueueFeedback;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::stats_manager::{CounterHandle, MetricName, StatsManager};

use crate::tunnel::{
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    packet_def::{ZCPacket, ethernet_network_metadata},
};

const FLOW_LIMIT: usize = 128;
const PACKET_LIMIT: usize = 2048;
const QUEUED_BYTE_LIMIT: usize = 4 * 1024 * 1024;
const ACTIVE_BYTE_LIMIT: usize = 2 * 1024 * 1024;
const ACTIVE_QUEUE_BYTE_LIMIT: usize = 3 * 128 * 1024;
pub(super) const ACTIVE_FLOW_LIMIT: usize = 16;
const CODEL_TARGET: Duration = Duration::from_millis(5);
const CODEL_INTERVAL: Duration = Duration::from_millis(100);

struct QueuedPacket {
    packet: ZCPacket,
    enqueued: Instant,
}

#[derive(Default)]
struct Codel {
    first_above: Option<Instant>,
    next_drop: Option<Instant>,
    dropping: bool,
    count: u32,
    last_count: u32,
}

impl Codel {
    fn signal_with_downstream(
        &mut self,
        now: Instant,
        sojourn: Duration,
        downstream: (Duration, bool),
        backlog: usize,
        max_packet: usize,
    ) -> bool {
        if downstream.1 {
            // The transport already observed the full interval. Do not wait for a second interval here.
            self.first_above = Some(self.first_above.map_or(now, |deadline| deadline.min(now)));
        }
        self.signal(now, sojourn.max(downstream.0), backlog, max_packet)
    }

    fn control_law(time: Instant, count: u32) -> Instant {
        time + CODEL_INTERVAL.div_f64(f64::from(count.max(1)).sqrt())
    }

    fn signal(
        &mut self,
        now: Instant,
        sojourn: Duration,
        backlog: usize,
        max_packet: usize,
    ) -> bool {
        // Keep one maximum-sized packet to avoid starving a slow link.
        let above = if sojourn < CODEL_TARGET || backlog <= max_packet {
            self.first_above = None;
            false
        } else if let Some(first_above) = self.first_above {
            now >= first_above
        } else {
            self.first_above = Some(now + CODEL_INTERVAL);
            false
        };
        if self.dropping {
            if !above {
                self.dropping = false;
            } else if self.next_drop.is_some_and(|next| now >= next) {
                self.count = self.count.saturating_add(1);
                self.next_drop = Some(Self::control_law(self.next_drop.unwrap(), self.count));
                return true;
            }
        } else if above {
            let delta = self.count.saturating_sub(self.last_count);
            self.count = if delta > 1
                && self
                    .next_drop
                    .is_some_and(|next| now.saturating_duration_since(next) < CODEL_INTERVAL * 16)
            {
                delta
            } else {
                1
            };
            self.last_count = self.count;
            self.dropping = true;
            self.next_drop = Some(Self::control_law(now, self.count));
            return true;
        }
        false
    }
}

struct IngressMetrics {
    drops: CounterHandle,
    marks: CounterHandle,
    sojourn_us: CounterHandle,
    dequeued: CounterHandle,
}

#[derive(Default)]
struct Flow {
    feedback: Arc<FlowQueueFeedback>,
    packets: VecDeque<QueuedPacket>,
    bytes: usize,
    active_bytes: Option<usize>,
    max_packet: usize,
    codel: Codel,
}

pub(super) struct NicIngressQueue {
    flows: HashMap<u64, Flow>,
    ready: VecDeque<u64>,
    packets: usize,
    bytes: usize,
    active_flows: usize,
    active_bytes: usize,
    enqueued: u64,
    evicted: u64,
    rejected: u64,
    peak_queued_bytes: usize,
    peak_active_bytes: usize,
    aqm_drops: u64,
    aqm_marks: u64,
    native_ethernet: bool,
    metrics: Option<IngressMetrics>,
}

impl Default for NicIngressQueue {
    fn default() -> Self {
        Self {
            flows: HashMap::with_capacity(FLOW_LIMIT),
            ready: VecDeque::with_capacity(FLOW_LIMIT),
            packets: 0,
            bytes: 0,
            active_flows: 0,
            active_bytes: 0,
            enqueued: 0,
            evicted: 0,
            rejected: 0,
            peak_queued_bytes: 0,
            peak_active_bytes: 0,
            aqm_drops: 0,
            aqm_marks: 0,
            native_ethernet: false,
            metrics: None,
        }
    }
}

impl NicIngressQueue {
    pub(super) fn new(stats: &StatsManager, native_ethernet: bool) -> Self {
        let mut queue = Self::default();
        queue.native_ethernet = native_ethernet;
        queue.metrics = Some(IngressMetrics {
            drops: stats.get_simple_counter(MetricName::NicAqmDrops),
            marks: stats.get_simple_counter(MetricName::NicAqmMarks),
            sojourn_us: stats.get_simple_counter(MetricName::NicQueueSojournUs),
            dequeued: stats.get_simple_counter(MetricName::NicQueueDequeued),
        });
        queue
    }

    pub(super) fn is_empty(&self) -> bool {
        self.packets == 0
    }

    #[cfg(test)]
    pub(super) fn push(&mut self, hash: u64, packet: ZCPacket) {
        self.push_at(hash, packet, Instant::now());
    }

    pub(super) fn push_at(&mut self, hash: u64, mut packet: ZCPacket, enqueued: Instant) {
        let mut bytes = packet.retained_buffer_capacity();
        // Every admitted packet must fit an otherwise empty active budget.
        // A short slice can retain a larger receive slab; compact that slab
        // before admission so it cannot remain permanently undispatchable.
        let packet_limit = QUEUED_BYTE_LIMIT.min(ACTIVE_BYTE_LIMIT);
        if bytes > packet_limit {
            packet.compact_retained_buffer();
            bytes = packet.retained_buffer_capacity();
        }
        if bytes > packet_limit
            || (self.flows.len() >= FLOW_LIMIT && !self.flows.contains_key(&hash))
        {
            self.rejected += 1;
            if let Some(metrics) = &self.metrics {
                metrics.drops.inc();
            }
            return;
        }
        while self.packets >= PACKET_LIMIT || self.bytes + bytes > QUEUED_BYTE_LIMIT {
            let Some((&largest, _)) = self
                .flows
                .iter()
                .filter(|(_, flow)| !flow.packets.is_empty())
                .max_by_key(|(_, flow)| flow.bytes)
            else {
                self.rejected += 1;
                if let Some(metrics) = &self.metrics {
                    metrics.drops.inc();
                }
                return;
            };
            let flow = self.flows.get_mut(&largest).expect("selected queued flow");
            let dropped = flow.packets.pop_front().expect("nonempty queued flow");
            let retained = dropped.packet.retained_buffer_capacity();
            flow.bytes -= retained;
            self.bytes -= retained;
            self.packets -= 1;
            self.evicted += 1;
            if let Some(metrics) = &self.metrics {
                metrics.drops.inc();
            }
        }
        let flow = self.flows.entry(hash).or_insert_with(|| {
            // FIFO rotation also bounds the wait of existing ready flows when
            // new flows arrive continuously.
            self.ready.push_back(hash);
            Flow::default()
        });
        flow.max_packet = flow.max_packet.max(bytes);
        flow.packets.push_back(QueuedPacket { packet, enqueued });
        flow.bytes += bytes;
        self.bytes += bytes;
        self.packets += 1;
        self.enqueued += 1;
        self.peak_queued_bytes = self.peak_queued_bytes.max(self.bytes);
    }

    pub(super) fn pop(&mut self) -> Option<(u64, PacketBatch)> {
        if self.active_flows >= ACTIVE_FLOW_LIMIT {
            return None;
        }
        let hard_available = ACTIVE_BYTE_LIMIT - self.active_bytes;
        let available = ACTIVE_QUEUE_BYTE_LIMIT.saturating_sub(self.active_bytes);
        let now = Instant::now();
        let mut drops = 0;
        let mut marks = 0;
        let mut sojourn_us = 0;
        let mut dequeued = 0;
        for _ in 0..self.ready.len() {
            let hash = self.ready.pop_front().expect("ready length is bounded");
            let flow = self.flows.get_mut(&hash).expect("ready flow exists");
            debug_assert!(flow.active_bytes.is_none());
            if flow.packets.is_empty() {
                self.flows.remove(&hash);
                continue;
            }
            let mut downstream = None;
            let mut batch = PacketBatch::new();
            let mut retained = 0;
            while batch.len() < MAX_PACKET_BATCH_SIZE {
                let Some(packet) = flow.packets.front() else {
                    break;
                };
                let bytes = packet.packet.retained_buffer_capacity();
                // One legal packet can exceed the handoff floor on an empty active budget.
                let packet_available = if self.active_bytes == 0 && retained == 0 {
                    available.max(bytes).min(hard_available)
                } else {
                    available
                };
                if retained + bytes > packet_available {
                    break;
                }
                let downstream = *downstream.get_or_insert_with(|| flow.feedback.snapshot());
                let mut packet = flow.packets.pop_front().expect("front packet exists");
                flow.bytes -= bytes;
                self.bytes -= bytes;
                self.packets -= 1;
                let sojourn = now.saturating_duration_since(packet.enqueued);
                sojourn_us += sojourn.as_micros().min(u64::MAX as u128) as u64;
                dequeued += 1;
                if flow.codel.signal_with_downstream(
                    now,
                    sojourn,
                    downstream,
                    flow.bytes,
                    flow.max_packet,
                ) {
                    if mark_inner_ce(&mut packet.packet, self.native_ethernet) {
                        marks += 1;
                    } else {
                        drops += 1;
                        continue;
                    }
                }
                retained += bytes;
                batch.try_push(packet.packet).expect("batch length checked");
            }
            if batch.is_empty() {
                if flow.packets.is_empty() {
                    self.flows.remove(&hash);
                } else {
                    self.ready.push_back(hash);
                }
                continue;
            }
            flow.active_bytes = Some(retained);
            // One tag per flow batch binds downstream feedback without one Arc clone per packet.
            batch
                .iter_mut()
                .next()
                .expect("nonempty delivery")
                .queue_feedback = Some(flow.feedback.clone());
            self.active_bytes += retained;
            self.active_flows += 1;
            self.peak_active_bytes = self.peak_active_bytes.max(self.active_bytes);
            self.record_dequeue(drops, marks, sojourn_us, dequeued);
            return Some((hash, batch));
        }
        self.record_dequeue(drops, marks, sojourn_us, dequeued);
        None
    }

    fn record_dequeue(&mut self, drops: u64, marks: u64, sojourn_us: u64, dequeued: u64) {
        self.aqm_drops += drops;
        self.aqm_marks += marks;
        if let Some(metrics) = &self.metrics {
            metrics.drops.add(drops);
            metrics.marks.add(marks);
            metrics.sojourn_us.add(sojourn_us);
            metrics.dequeued.add(dequeued);
        }
    }

    pub(super) fn complete(&mut self, hash: u64) {
        let flow = self
            .flows
            .get_mut(&hash)
            .expect("active flow remains pinned");
        let retained = flow
            .active_bytes
            .take()
            .expect("one completion per delivery");
        self.active_bytes -= retained;
        self.active_flows -= 1;
        if flow.packets.is_empty() {
            self.flows.remove(&hash);
        } else {
            self.ready.push_back(hash);
        }
    }

    pub(super) fn report(&self) {
        tracing::info!(target: "CORE",
            enqueued = self.enqueued,
            evicted = self.evicted,
            rejected = self.rejected,
            aqm_drops = self.aqm_drops,
            aqm_marks = self.aqm_marks,
            queued_packets = self.packets,
            queued_bytes = self.bytes,
            active_flows = self.active_flows,
            active_bytes = self.active_bytes,
            peak_queued_bytes = self.peak_queued_bytes,
            peak_active_bytes = self.peak_active_bytes,
            "NIC ingress queue counters"
        );
    }
}

fn mark_inner_ce(packet: &mut ZCPacket, native_ethernet: bool) -> bool {
    let offset = if native_ethernet {
        let Some(metadata) = ethernet_network_metadata(packet.payload()) else {
            return false;
        };
        if !matches!(metadata.ether_type, 0x0800 | 0x86dd) {
            return false;
        }
        metadata.payload_offset
    } else {
        0
    };
    let Some(ip) = packet.payload().get(offset..) else {
        return false;
    };
    match ip.first().map(|byte| byte >> 4) {
        Some(4) => {
            if ip.len() < 20 {
                return false;
            }
            let header_len = usize::from(ip[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            if header_len < 20
                || header_len > ip.len()
                || total_len < header_len
                || total_len > ip.len()
                || ip[1] & 3 == 0
            {
                return false;
            }
            let ip = &mut packet.mut_payload_preserving_flow_hash()[offset..];
            ip[1] |= 3;
            ip[10] = 0;
            ip[11] = 0;
            // Recompute the complete header, including IPv4 options.
            let sum = ip[..header_len]
                .chunks_exact(2)
                .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
                .sum::<u32>();
            let sum = (sum & 0xffff) + (sum >> 16);
            let checksum = !((sum & 0xffff) + (sum >> 16)) as u16;
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            true
        }
        Some(6) => {
            if ip.len() < 40 || ip[1] & 0x30 == 0 {
                return false;
            }
            let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            if payload_len != 0 && payload_len + 40 > ip.len() {
                return false;
            }
            packet.mut_payload_preserving_flow_hash()[offset + 1] |= 0x30;
            true
        }
        _ => false,
    }
}

impl Drop for NicIngressQueue {
    fn drop(&mut self) {
        if self.evicted != 0 || self.rejected != 0 {
            tracing::warn!(
                enqueued = self.enqueued,
                evicted = self.evicted,
                rejected = self.rejected,
                queued_at_shutdown = self.packets,
                active_at_shutdown = self.active_flows,
                "NIC ingress overload totals"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(sequence: u8) -> ZCPacket {
        ZCPacket::new_with_payload(&[sequence; 1200])
    }

    #[test]
    fn ecn_marks_preserve_ipv4_checksum_and_ipv6_flow_label() {
        let mut ip = [0_u8; 24];
        ip[0] = 0x46;
        ip[1] = 0xb9;
        ip[2..4].copy_from_slice(&24_u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip[20..24].copy_from_slice(&[1, 1, 0, 0]);
        for ethernet in [false, true] {
            let mut payload = Vec::new();
            if ethernet {
                payload.extend_from_slice(&[0; 12]);
                payload.extend_from_slice(&[0x81, 0, 0, 1, 8, 0]);
            }
            payload.extend_from_slice(&ip);
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.set_flow_hash(7);
            assert!(mark_inner_ce(&mut packet, ethernet));
            assert_eq!(packet.flow_hash(), Some(7));
            let offset = if ethernet { 18 } else { 0 };
            let marked = &packet.payload()[offset..];
            assert_eq!(marked[1], 0xbb);
            let sum: u32 = marked
                .chunks_exact(2)
                .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
                .sum();
            let sum = (sum & 0xffff) + (sum >> 16);
            assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
            packet.mut_payload_preserving_flow_hash()[offset + 1] &= !3;
            let original = packet.payload().to_vec();
            assert!(!mark_inner_ce(&mut packet, ethernet));
            assert_eq!(packet.payload(), original);
        }
        let mut ipv6 = [0_u8; 40];
        ipv6[..4].copy_from_slice(&[0x6a, 0x2b, 0xcd, 0xef]);
        let mut packet = ZCPacket::new_with_payload(&ipv6);
        assert!(mark_inner_ce(&mut packet, false));
        assert_eq!(&packet.payload()[..4], &[0x6a, 0x3b, 0xcd, 0xef]);
        assert!(!mark_inner_ce(
            &mut ZCPacket::new_with_payload(&[0x45; 10]),
            false
        ));
    }

    #[test]
    fn codel_persistent_delay_uses_inverse_square_root_control_law() {
        let start = Instant::now();
        let mut codel = Codel::default();
        assert!(!codel.signal(start, CODEL_TARGET, 4000, 1500));
        assert!(!codel.signal(
            start + CODEL_INTERVAL - Duration::from_nanos(1),
            CODEL_TARGET,
            4000,
            1500
        ));
        assert!(codel.signal(start + CODEL_INTERVAL, CODEL_TARGET, 4000, 1500));
        assert_eq!(codel.count, 1);
        let next = codel.next_drop.unwrap();
        assert!(codel.signal(next, CODEL_TARGET, 4000, 1500));
        assert_eq!(codel.count, 2);
        assert_eq!(
            Codel::control_law(start, 4) - start,
            Duration::from_millis(50)
        );
        assert!(!codel.signal(next, CODEL_TARGET, 1500, 1500));
        assert!(!codel.dropping);
        assert!(codel.first_above.is_none());
        let mut downstream = Codel::default();
        assert!(downstream.signal_with_downstream(
            start,
            Duration::ZERO,
            (CODEL_TARGET, true),
            4000,
            1500
        ));
        assert_eq!(downstream.count, 1);
        assert!(!downstream.signal_with_downstream(
            start,
            Duration::ZERO,
            (Duration::ZERO, false),
            4000,
            1500
        ));
        assert!(!downstream.dropping);
        assert!(!downstream.signal_with_downstream(
            start,
            Duration::ZERO,
            (CODEL_TARGET, true),
            1500,
            1500
        ));
    }

    #[test]
    fn sparse_flow_progresses_while_bulk_is_in_flight() {
        let mut queue = NicIngressQueue::default();
        queue.push(1, packet(0));
        let bulk = queue.pop().unwrap();
        for n in 1..=128 {
            queue.push(1, packet(n));
        }
        queue.push(2, packet(9));
        let (hash, batch) = queue.pop().unwrap();
        assert_eq!(hash, 2);
        assert_eq!(batch.len(), 1);
        assert!(queue.pop().is_none());
        queue.complete(2);
        drop(bulk);
        queue.complete(1);
        let (_, batch) = queue.pop().unwrap();
        assert_eq!(
            batch.iter().map(|p| p.payload()[0]).collect::<Vec<_>>(),
            (1..=64).collect::<Vec<_>>()
        );
    }

    #[test]
    fn overload_is_accounted_and_preserves_sparse_delivery() {
        let mut queue = NicIngressQueue::default();
        for _ in 0..PACKET_LIMIT + 64 {
            queue.push(1, packet(0));
        }
        queue.push(2, packet(7));
        assert!(queue.packets <= PACKET_LIMIT);
        assert!(queue.bytes <= QUEUED_BYTE_LIMIT);
        assert!(queue.evicted > 0);
        let (bulk, batch) = queue.pop().unwrap();
        assert_eq!(bulk, 1);
        drop(batch);
        let (hash, batch) = queue.pop().unwrap();
        assert_eq!(hash, 2);
        assert_eq!(batch.iter().next().unwrap().payload()[0], 7);
    }

    #[test]
    fn ready_rotation_does_not_let_new_flows_starve_old_flows() {
        let mut queue = NicIngressQueue::default();
        for hash in 0..16 {
            queue.push(hash, packet(0));
        }
        for hash in 0..16 {
            queue.push(100 + hash, packet(1));
            let (next, batch) = queue.pop().unwrap();
            assert_eq!(next, hash);
            drop(batch);
            queue.complete(next);
        }
    }

    #[test]
    fn active_memory_and_parallelism_remain_bounded() {
        oversized_receive_slab_is_compacted_before_active_admission();
        unserviceable_payload_is_rejected_without_poisoning_flow();
        exhausted_flow_slots_are_reported_and_reclaimed();
        let mut queue = NicIngressQueue::default();
        let mut active = Vec::new();
        for hash in 0..FLOW_LIMIT as u64 {
            queue.push(hash, packet(0));
            if let Some(delivery) = queue.pop() {
                active.push(delivery);
            }
            assert!(queue.active_flows <= ACTIVE_FLOW_LIMIT);
            assert!(queue.active_bytes <= ACTIVE_BYTE_LIMIT);
            assert!(queue.bytes <= QUEUED_BYTE_LIMIT);
        }
        assert_eq!(active.len(), ACTIVE_FLOW_LIMIT);
        for (hash, batch) in active {
            drop(batch);
            queue.complete(hash);
        }
        while let Some((hash, batch)) = queue.pop() {
            drop(batch);
            queue.complete(hash);
        }
        assert!(queue.flows.is_empty());
        assert_eq!((queue.bytes, queue.active_bytes, queue.packets), (0, 0, 0));
        for hash in 0..8 {
            for _ in 0..MAX_PACKET_BATCH_SIZE {
                queue.push(hash, packet(0));
            }
        }
        let mut active = Vec::new();
        while let Some(delivery) = queue.pop() {
            active.push(delivery);
            assert!(queue.active_bytes <= ACTIVE_QUEUE_BYTE_LIMIT);
        }
        assert!(!queue.is_empty());
        assert!(active.len() < ACTIVE_FLOW_LIMIT);
        for (hash, batch) in active {
            drop(batch);
            queue.complete(hash);
        }
        while let Some((hash, batch)) = queue.pop() {
            drop(batch);
            queue.complete(hash);
        }
        assert_eq!((queue.bytes, queue.active_bytes, queue.packets), (0, 0, 0));
    }

    fn oversized_receive_slab_is_compacted_before_active_admission() {
        let mut queue = NicIngressQueue::default();
        let mut short = ZCPacket::new_for_tun(ACTIVE_BYTE_LIMIT + 65536, 0);
        short.set_flow_hash(7);
        assert!(short.retained_buffer_capacity() > ACTIVE_BYTE_LIMIT);
        queue.push(7, short);
        let (hash, batch) = queue.pop().expect("admitted packet must be dispatchable");
        assert_eq!(hash, 7);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.iter().next().unwrap().flow_hash(), Some(7));
        assert!(queue.active_bytes <= ACTIVE_BYTE_LIMIT);
        drop(batch);
        queue.complete(hash);
        assert!(queue.flows.is_empty());
    }

    fn unserviceable_payload_is_rejected_without_poisoning_flow() {
        let mut queue = NicIngressQueue::default();
        queue.push(9, ZCPacket::new_with_payload_len(ACTIVE_BYTE_LIMIT + 1));
        assert_eq!(queue.rejected, 1);
        assert!(queue.flows.is_empty());
        queue.push(9, packet(3));
        let (hash, batch) = queue.pop().expect("next valid packet must progress");
        assert_eq!(hash, 9);
        assert_eq!(batch.iter().next().unwrap().payload()[0], 3);
    }

    fn exhausted_flow_slots_are_reported_and_reclaimed() {
        let mut queue = NicIngressQueue::default();
        for hash in 0..FLOW_LIMIT as u64 {
            queue.push(hash, packet(0));
        }
        queue.push(u64::MAX, packet(1));
        assert_eq!(queue.rejected, 1);
        while let Some((hash, batch)) = queue.pop() {
            drop(batch);
            queue.complete(hash);
        }
        assert!(queue.flows.is_empty());
        queue.push(u64::MAX, packet(2));
        assert_eq!(queue.pop().unwrap().0, u64::MAX);
    }
}
