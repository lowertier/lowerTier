use std::{array, collections::VecDeque};

pub(crate) const FLOW_SHARD_COUNT: usize = 64;
pub(crate) const TUN_SCHEDULER_PACKET_CAPACITY: usize = 128;
pub(crate) const TUN_SCHEDULER_BYTE_CAPACITY: usize = 512 * 1024;
const DEFAULT_CONTROL_BURST_PACKETS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DrainStats {
    pub(crate) packets: usize,
    pub(crate) bytes: usize,
}

#[derive(Debug)]
pub(crate) struct ScheduledPacket<T> {
    pub(crate) value: T,
    pub(crate) bytes: usize,
    pub(crate) control: bool,
}

#[derive(Debug)]
pub(crate) struct FlowDrrScheduler<T> {
    flows: [VecDeque<ScheduledPacket<T>>; FLOW_SHARD_COUNT],
    deficits: [usize; FLOW_SHARD_COUNT],
    active: u64,
    control_heads: u64,
    cursor: usize,
    len: usize,
    bytes: usize,
    packet_capacity: usize,
    byte_capacity: usize,
    quantum_bytes: usize,
    control_burst_packets: usize,
    control_budget: usize,
}

impl<T> FlowDrrScheduler<T> {
    pub(crate) fn new(packet_capacity: usize, byte_capacity: usize, quantum_bytes: usize) -> Self {
        assert!(packet_capacity > 0);
        assert!(byte_capacity > 0);
        assert!(quantum_bytes > 0);
        Self {
            flows: array::from_fn(|_| VecDeque::new()),
            deficits: [0; FLOW_SHARD_COUNT],
            active: 0,
            control_heads: 0,
            cursor: 0,
            len: 0,
            bytes: 0,
            packet_capacity,
            byte_capacity,
            quantum_bytes,
            control_burst_packets: DEFAULT_CONTROL_BURST_PACKETS,
            control_budget: DEFAULT_CONTROL_BURST_PACKETS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_control_burst(mut self, packets: usize) -> Self {
        assert!(packets > 0);
        self.control_burst_packets = packets;
        self.control_budget = packets;
        self
    }

    #[inline]
    pub(crate) fn queue_index(shard: u16, queue_count: usize) -> usize {
        debug_assert!(queue_count > 0);
        usize::from(shard) % queue_count
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn queued_packets(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn byte_len(&self) -> usize {
        self.bytes
    }

    #[inline]
    pub(crate) fn queued_bytes(&self) -> usize {
        self.bytes
    }

    #[inline]
    pub(crate) fn can_accept(&self, packets: usize, bytes: usize) -> bool {
        packets <= self.packet_capacity.saturating_sub(self.len)
            && bytes <= self.byte_capacity.saturating_sub(self.bytes)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn push(
        &mut self,
        shard: u16,
        value: T,
        bytes: usize,
        control: bool,
    ) -> Result<(), T> {
        if self.len == self.packet_capacity || bytes > self.byte_capacity.saturating_sub(self.bytes)
        {
            return Err(value);
        }
        let index = usize::from(shard) & (FLOW_SHARD_COUNT - 1);
        let flow = &mut self.flows[index];
        let was_empty = flow.is_empty();
        flow.push_back(ScheduledPacket {
            value,
            bytes,
            control,
        });
        self.len += 1;
        self.bytes += bytes;
        if was_empty {
            self.active |= 1_u64 << index;
            if control {
                self.control_heads |= 1_u64 << index;
            }
        }
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<ScheduledPacket<T>> {
        if self.active == 0 {
            return None;
        }
        if self.control_budget != 0 && self.control_heads != 0 {
            if let Some(index) = self.next_set(self.control_heads) {
                self.control_budget -= 1;
                return self.pop_index(index, true);
            }
        }

        let bulk_heads = self.active & !self.control_heads;
        if bulk_heads != 0 {
            let packet = self.pop_drr_from(bulk_heads);
            if packet.is_some() {
                self.control_budget = self.control_burst_packets;
            }
            return packet;
        }

        // Do not idle when every active head is control. Start a new bounded
        // control burst; same-flow FIFO still prevents a tail control packet
        // from overtaking an earlier bulk head in its own shard.
        if self.control_heads != 0 {
            self.control_budget = self.control_burst_packets - 1;
            let index = self.next_set(self.control_heads)?;
            return self.pop_index(index, true);
        }

        self.control_budget = self.control_burst_packets;
        self.pop_drr()
    }

    pub(crate) fn drain_into(&mut self, output: &mut Vec<T>, limit: usize) -> DrainStats {
        debug_assert!(output.is_empty());
        let mut stats = DrainStats::default();
        while stats.packets < limit {
            let Some(packet) = self.pop() else {
                break;
            };
            stats.packets += 1;
            stats.bytes = stats.bytes.saturating_add(packet.bytes);
            output.push(packet.value);
        }
        stats
    }

    fn pop_drr(&mut self) -> Option<ScheduledPacket<T>> {
        self.pop_drr_from(self.active)
    }

    fn pop_drr_from(&mut self, mut eligible: u64) -> Option<ScheduledPacket<T>> {
        let mut remaining_rounds = FLOW_SHARD_COUNT.saturating_mul(2);
        while remaining_rounds != 0 {
            eligible &= self.active;
            if eligible == 0 {
                return None;
            }
            remaining_rounds -= 1;
            let index = self.next_set(eligible)?;
            let head_bytes = self.flows[index]
                .front()
                .expect("an active flow has a head packet")
                .bytes;
            if self.deficits[index] < head_bytes {
                self.deficits[index] = self.deficits[index].saturating_add(self.quantum_bytes);
                continue;
            }
            self.deficits[index] -= head_bytes;
            return self.pop_index(index, false);
        }

        // A packet can exceed one quantum. Continue bounded rounds until one
        // active flow accumulates enough deficit; capacity bounds make this
        // loop finite and keep the common MTU-sized case above fast.
        loop {
            eligible &= self.active;
            if eligible == 0 {
                return None;
            }
            let index = self.next_set(eligible)?;
            let head_bytes = self.flows[index]
                .front()
                .expect("an active flow has a head packet")
                .bytes;
            self.deficits[index] = self.deficits[index].saturating_add(self.quantum_bytes);
            if self.deficits[index] >= head_bytes {
                self.deficits[index] -= head_bytes;
                return self.pop_index(index, false);
            }
        }
    }

    #[inline]
    fn next_set(&mut self, bits: u64) -> Option<usize> {
        if bits == 0 {
            return None;
        }
        let shift = self.cursor & (FLOW_SHARD_COUNT - 1);
        let rotated = bits.rotate_right(shift as u32);
        let relative = rotated.trailing_zeros() as usize;
        let index = (relative + shift) & (FLOW_SHARD_COUNT - 1);
        self.cursor = (index + 1) & (FLOW_SHARD_COUNT - 1);
        Some(index)
    }

    fn pop_index(&mut self, index: usize, control_selection: bool) -> Option<ScheduledPacket<T>> {
        let packet = self.flows[index].pop_front()?;
        debug_assert!(!control_selection || packet.control);
        self.len -= 1;
        self.bytes -= packet.bytes;
        let bit = 1_u64 << index;
        if let Some(next) = self.flows[index].front() {
            if next.control {
                self.control_heads |= bit;
            } else {
                self.control_heads &= !bit;
            }
        } else {
            self.active &= !bit;
            self.control_heads &= !bit;
            self.deficits[index] = 0;
        }
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::{FlowDrrScheduler, TUN_SCHEDULER_BYTE_CAPACITY, TUN_SCHEDULER_PACKET_CAPACITY};

    #[test]
    fn queue_mapping_is_flow_stable() {
        for queue_count in 1..=8 {
            for shard in 0_u16..64 {
                let first = FlowDrrScheduler::<u8>::queue_index(shard, queue_count);
                assert_eq!(
                    first,
                    FlowDrrScheduler::<u8>::queue_index(shard, queue_count)
                );
                assert!(first < queue_count);
            }
        }
    }

    #[test]
    fn fifo_is_preserved_inside_one_flow() {
        let mut scheduler = FlowDrrScheduler::new(16, 16_000, 1500);
        for value in 0_u8..8 {
            scheduler.push(7, value, 1000, false).unwrap();
        }
        let output =
            std::iter::from_fn(|| scheduler.pop().map(|packet| packet.value)).collect::<Vec<_>>();
        assert_eq!(output, (0_u8..8).collect::<Vec<_>>());
    }

    #[test]
    fn a_later_control_packet_cannot_overtake_its_flow_head() {
        let mut scheduler = FlowDrrScheduler::new(8, 8_000, 1500);
        scheduler.push(3, "data-head", 1000, false).unwrap();
        scheduler.push(3, "control-tail", 100, true).unwrap();
        scheduler.push(4, "other-control", 100, true).unwrap();

        assert_eq!(scheduler.pop().unwrap().value, "other-control");
        assert_eq!(scheduler.pop().unwrap().value, "data-head");
        assert_eq!(scheduler.pop().unwrap().value, "control-tail");
    }

    #[test]
    fn control_priority_has_a_bounded_burst() {
        let mut scheduler = FlowDrrScheduler::new(16, 16_000, 1500).with_control_burst(2);
        for shard in 0_u16..4 {
            scheduler.push(shard, shard, 100, true).unwrap();
        }
        scheduler.push(10, 99, 100, false).unwrap();

        let first = scheduler.pop().unwrap();
        let second = scheduler.pop().unwrap();
        let third = scheduler.pop().unwrap();
        assert!(first.control && second.control);
        assert!(!third.control);
        assert_eq!(third.value, 99);
    }

    #[test]
    fn drr_accounts_bytes_across_active_flows() {
        let mut scheduler = FlowDrrScheduler::new(32, 64_000, 1000);
        for value in 0_u8..4 {
            scheduler.push(1, (1, value), 1000, false).unwrap();
            scheduler.push(2, (2, value), 2000, false).unwrap();
        }
        let first_six = (0..6)
            .map(|_| scheduler.pop().unwrap().value.0)
            .collect::<Vec<_>>();
        let flow_one = first_six.iter().filter(|flow| **flow == 1).count();
        let flow_two = first_six.iter().filter(|flow| **flow == 2).count();
        assert!(flow_one >= flow_two);
        assert!(flow_two > 0);
    }

    #[test]
    fn scheduler_enforces_packet_and_byte_bounds() {
        let mut scheduler = FlowDrrScheduler::new(2, 1500, 1500);
        scheduler.push(1, 1, 700, false).unwrap();
        scheduler.push(2, 2, 700, false).unwrap();
        assert_eq!(scheduler.push(3, 3, 1, false), Err(3));
        assert_eq!(scheduler.len(), 2);
        assert_eq!(scheduler.byte_len(), 1400);
        assert!(scheduler.can_accept(0, 100));
        assert!(!scheduler.can_accept(1, 100));
        assert!(!scheduler.can_accept(0, 101));
    }

    #[test]
    fn production_capacity_drains_one_ready_vector_without_reordering() {
        let mut scheduler = FlowDrrScheduler::new(
            TUN_SCHEDULER_PACKET_CAPACITY,
            TUN_SCHEDULER_BYTE_CAPACITY,
            1500,
        );
        for value in 0_u8..64 {
            scheduler.push(7, value, 1400, false).unwrap();
        }
        let mut output = Vec::with_capacity(64);
        let stats = scheduler.drain_into(&mut output, 64);

        assert_eq!(stats.packets, 64);
        assert_eq!(stats.bytes, 64 * 1400);
        assert_eq!(output, (0_u8..64).collect::<Vec<_>>());
        assert!(scheduler.is_empty());
    }
}
