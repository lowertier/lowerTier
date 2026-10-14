use crate::tunnel::batch::{MAX_PACKET_BATCH_SIZE, SEND_PIPELINE_SLOT_COUNT};

/// Retain enough authenticated sequence history for every bounded send-pipeline
/// slot plus the network-reordering allowance supported before the dual queue.
pub(crate) const REPLAY_WINDOW_BITS: usize = 1024;
pub(crate) const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

const NETWORK_REORDER_HEADROOM: usize = 256;
const REQUIRED_REPLAY_WINDOW_BITS: usize =
    SEND_PIPELINE_SLOT_COUNT * MAX_PACKET_BATCH_SIZE + NETWORK_REORDER_HEADROOM;
const REPLAY_WINDOW_INDEX_MASK: u64 = REPLAY_WINDOW_BITS as u64 - 1;
const _: () = assert!(REPLAY_WINDOW_BITS.is_power_of_two());
const _: () = assert!(REPLAY_WINDOW_BITS % u64::BITS as usize == 0);
const _: () = assert!(REPLAY_WINDOW_BITS >= REQUIRED_REPLAY_WINDOW_BITS);

/// A circular authenticated-sequence bitmap.
///
/// Bit position `sequence mod REPLAY_WINDOW_BITS` belongs to exactly one
/// sequence in the current history interval. Advancing the high-water mark
/// clears only positions that are entering the interval, which is one bit for
/// contiguous traffic instead of shifting the entire bitmap for every packet.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplayWindow {
    max_sequence: u64,
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    valid: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            max_sequence: 0,
            bitmap: [0; REPLAY_WINDOW_WORDS],
            valid: false,
        }
    }
}

impl ReplayWindow {
    #[inline]
    pub(crate) fn clear(&mut self) {
        self.max_sequence = 0;
        self.bitmap.fill(0);
        self.valid = false;
    }

    #[inline]
    fn bit_index(sequence: u64) -> usize {
        (sequence & REPLAY_WINDOW_INDEX_MASK) as usize
    }

    #[inline]
    fn test_sequence(&self, sequence: u64) -> bool {
        let index = Self::bit_index(sequence);
        self.bitmap[index / u64::BITS as usize] & (1_u64 << (index % u64::BITS as usize)) != 0
    }

    #[inline]
    fn set_sequence(&mut self, sequence: u64) {
        let index = Self::bit_index(sequence);
        self.bitmap[index / u64::BITS as usize] |= 1_u64 << (index % u64::BITS as usize);
    }

    #[inline]
    fn clear_sequence(&mut self, sequence: u64) {
        let index = Self::bit_index(sequence);
        self.bitmap[index / u64::BITS as usize] &= !(1_u64 << (index % u64::BITS as usize));
    }

    #[inline]
    fn clear_advanced_positions(&mut self, new_max_sequence: u64) {
        let distance = new_max_sequence - self.max_sequence;
        if distance >= REPLAY_WINDOW_BITS as u64 {
            self.bitmap.fill(0);
            return;
        }

        let distance = distance as usize;
        for offset in 1..=distance {
            self.clear_sequence(self.max_sequence + offset as u64);
        }
    }

    #[inline]
    pub(crate) fn can_accept(&self, sequence: u64) -> bool {
        if !self.valid || sequence > self.max_sequence {
            return true;
        }
        let distance = self.max_sequence - sequence;
        distance < REPLAY_WINDOW_BITS as u64 && !self.test_sequence(sequence)
    }

    #[inline]
    pub(crate) fn accept(&mut self, sequence: u64) -> bool {
        if !self.can_accept(sequence) {
            return false;
        }
        if !self.valid {
            self.valid = true;
            self.max_sequence = sequence;
            self.set_sequence(sequence);
            return true;
        }
        if sequence > self.max_sequence {
            self.clear_advanced_positions(sequence);
            self.max_sequence = sequence;
        }
        self.set_sequence(sequence);
        true
    }

    #[cfg(test)]
    pub(crate) fn max_sequence(&self) -> u64 {
        self.max_sequence
    }
}
