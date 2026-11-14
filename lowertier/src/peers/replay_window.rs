use crate::tunnel::batch::{MAX_PACKET_BATCH_SIZE, SEND_PIPELINE_SLOT_COUNT};

/// Retain enough authenticated sequence history for every bounded send-pipeline
/// slot plus multipath RTT-skew reordering allowance across heterogeneous relays.
pub(crate) const REPLAY_WINDOW_BITS: usize = 16_384;
pub(crate) const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

const NETWORK_REORDER_HEADROOM: usize = 256;
const REQUIRED_REPLAY_WINDOW_BITS: usize =
    SEND_PIPELINE_SLOT_COUNT * MAX_PACKET_BATCH_SIZE + NETWORK_REORDER_HEADROOM;
const REPLAY_WINDOW_INDEX_MASK: u64 = REPLAY_WINDOW_BITS as u64 - 1;
const _: () = assert!(REPLAY_WINDOW_BITS.is_power_of_two());
const _: () = assert!(REPLAY_WINDOW_BITS.is_multiple_of(u64::BITS as usize));
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
    fn clear_advanced_positions(&mut self, new_max_sequence: u64) {
        let distance = new_max_sequence - self.max_sequence;
        if distance >= REPLAY_WINDOW_BITS as u64 {
            self.bitmap.fill(0);
            return;
        }

        let start_bit = ((self.max_sequence + 1) & REPLAY_WINDOW_INDEX_MASK) as usize;
        let end_bit = (new_max_sequence & REPLAY_WINDOW_INDEX_MASK) as usize;
        let start_word = start_bit / u64::BITS as usize;
        let start_off = start_bit % u64::BITS as usize;
        let end_word = end_bit / u64::BITS as usize;
        let end_off = end_bit % u64::BITS as usize;

        let start_mask = !0_u64 << start_off;
        let end_mask = !0_u64 >> (63 - end_off);

        if start_word == end_word {
            if start_off <= end_off {
                self.bitmap[start_word] &= !(start_mask & end_mask);
            } else {
                self.bitmap[start_word] &= !(start_mask | end_mask);
                self.bitmap[..start_word].fill(0);
                self.bitmap[start_word + 1..].fill(0);
            }
            return;
        }

        self.bitmap[start_word] &= !start_mask;
        self.bitmap[end_word] &= !end_mask;
        if start_word < end_word {
            self.bitmap[start_word + 1..end_word].fill(0);
        } else {
            self.bitmap[start_word + 1..].fill(0);
            self.bitmap[..end_word].fill(0);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_wise_advance_matches_expected_window_bounds() {
        for jump in [1_u64, 63, 64, 65, 1_500, 16_383, 16_384, 50_000] {
            let mut window = ReplayWindow::default();
            for seq in 0..128 {
                assert!(window.accept(seq));
            }
            let target = 127 + jump;
            assert!(window.accept(target), "jump {jump}");
            assert!(!window.accept(target), "duplicate {target} at jump {jump}");

            if jump < REPLAY_WINDOW_BITS as u64 {
                // Sequence 127 was already seen and stays within window if jump < 16384.
                assert!(!window.accept(127), "old seen seq 127 at jump {jump}");
                if let Some(oldest_unseen_in_window) =
                    target.checked_sub(REPLAY_WINDOW_BITS as u64 - 1)
                    && oldest_unseen_in_window > 127
                {
                    assert!(
                        window.accept(oldest_unseen_in_window),
                        "oldest unseen seq at jump {jump}"
                    );
                }
            }
            if target >= REPLAY_WINDOW_BITS as u64 {
                assert!(!window.accept(target - REPLAY_WINDOW_BITS as u64));
            }
        }
    }

    #[test]
    fn accepts_multipath_out_of_order_beyond_1024() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(0));
        assert!(window.accept(12_000));
        assert!(window.accept(1));
        assert!(window.accept(5_000));
        assert!(window.accept(11_999));
        assert!(!window.accept(5_000));
        // Wrap-around clear across end of ring
        assert!(window.accept(28_383));
        assert!(window.accept(12_001));
        assert!(!window.accept(11_999));
    }
}
