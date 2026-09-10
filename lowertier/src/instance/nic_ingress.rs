//! Bounded NIC admission. A blocked flow retains its ordering independently of
//! other flows; queued overload is charged to the largest queued flow.
use std::collections::{HashMap, VecDeque};

use crate::tunnel::{
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    packet_def::ZCPacket,
};

const FLOW_LIMIT: usize = 128;
const PACKET_LIMIT: usize = 2048;
const QUEUED_BYTE_LIMIT: usize = 4 * 1024 * 1024;
const ACTIVE_BYTE_LIMIT: usize = 2 * 1024 * 1024;
pub(super) const ACTIVE_FLOW_LIMIT: usize = 16;

#[derive(Default)]
struct Flow {
    packets: VecDeque<ZCPacket>,
    bytes: usize,
    active_bytes: Option<usize>,
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
        }
    }
}

impl NicIngressQueue {
    pub(super) fn is_empty(&self) -> bool {
        self.packets == 0
    }

    pub(super) fn push(&mut self, hash: u64, mut packet: ZCPacket) {
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
                return;
            };
            let flow = self.flows.get_mut(&largest).expect("selected queued flow");
            let dropped = flow.packets.pop_front().expect("nonempty queued flow");
            let retained = dropped.retained_buffer_capacity();
            flow.bytes -= retained;
            self.bytes -= retained;
            self.packets -= 1;
            self.evicted += 1;
        }
        let flow = self.flows.entry(hash).or_insert_with(|| {
            // FIFO rotation also bounds the wait of existing ready flows when
            // new flows arrive continuously.
            self.ready.push_back(hash);
            Flow::default()
        });
        flow.packets.push_back(packet);
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
        let available = ACTIVE_BYTE_LIMIT - self.active_bytes;
        for _ in 0..self.ready.len() {
            let hash = self.ready.pop_front().expect("ready length is bounded");
            let flow = self.flows.get_mut(&hash).expect("ready flow exists");
            debug_assert!(flow.active_bytes.is_none());
            if flow.packets.is_empty() {
                self.flows.remove(&hash);
                continue;
            }
            let mut batch = PacketBatch::new();
            let mut retained = 0;
            while batch.len() < MAX_PACKET_BATCH_SIZE {
                let Some(packet) = flow.packets.front() else {
                    break;
                };
                let bytes = packet.retained_buffer_capacity();
                if retained + bytes > available {
                    break;
                }
                let packet = flow.packets.pop_front().expect("front packet exists");
                retained += bytes;
                flow.bytes -= bytes;
                self.bytes -= bytes;
                self.packets -= 1;
                batch.try_push(packet).expect("batch length checked");
            }
            if batch.is_empty() {
                self.ready.push_back(hash);
                continue;
            }
            flow.active_bytes = Some(retained);
            self.active_bytes += retained;
            self.active_flows += 1;
            self.peak_active_bytes = self.peak_active_bytes.max(self.active_bytes);
            return Some((hash, batch));
        }
        None
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
    }

    #[test]
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

    #[test]
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

    #[test]
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
