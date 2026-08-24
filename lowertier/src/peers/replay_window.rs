use crate::{peers::crypto_workers::SEND_CRYPTO_SLOT_COUNT, tunnel::batch::MAX_PACKET_BATCH_SIZE};

/// Retain enough authenticated sequence history for every stable crypto slot
/// plus the network-reordering allowance supported before the dual queue.
pub(crate) const REPLAY_WINDOW_BITS: usize = 1024;
pub(crate) const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

const NETWORK_REORDER_HEADROOM: usize = 256;
const REQUIRED_REPLAY_WINDOW_BITS: usize =
    SEND_CRYPTO_SLOT_COUNT * MAX_PACKET_BATCH_SIZE + NETWORK_REORDER_HEADROOM;
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn reference_accept(
        accepted: &mut HashSet<u64>,
        max_sequence: &mut Option<u64>,
        sequence: u64,
    ) -> bool {
        if let Some(current_max) = *max_sequence {
            if sequence <= current_max
                && (current_max - sequence >= REPLAY_WINDOW_BITS as u64
                    || accepted.contains(&sequence))
            {
                return false;
            }
        }

        accepted.insert(sequence);
        if max_sequence.is_none_or(|current_max| sequence > current_max) {
            *max_sequence = Some(sequence);
            accepted.retain(|accepted_sequence| {
                sequence - *accepted_sequence < REPLAY_WINDOW_BITS as u64
            });
        }
        true
    }

    #[test]
    fn circular_window_matches_reference_across_wraps_and_jumps() {
        let mut window = ReplayWindow::default();
        let mut accepted = HashSet::new();
        let mut reference_max = None;
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;

        for iteration in 0..20_000_u64 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let current_max = reference_max.unwrap_or(0);
            let sequence = match iteration % 5 {
                0 => current_max + 1 + seed % 7,
                1 => current_max.saturating_sub(seed % 1_200),
                2 => current_max + 1 + seed % 1_300,
                3 => current_max.saturating_sub(seed % 128),
                _ => current_max,
            };

            assert_eq!(
                window.accept(sequence),
                reference_accept(&mut accepted, &mut reference_max, sequence),
                "mismatch for sequence {sequence} at iteration {iteration}"
            );
        }
    }

    #[test]
    fn window_accepts_the_full_bounded_crypto_and_network_reorder() {
        let highest = (REQUIRED_REPLAY_WINDOW_BITS - 1) as u64;
        let mut window = ReplayWindow::default();

        assert!(window.accept(highest));
        assert!(window.accept(0));
        assert!(!window.accept(0));
    }

    #[test]
    fn window_rejects_the_exact_history_boundary_and_recycles_its_bit() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(0));
        assert!(window.accept(REPLAY_WINDOW_BITS as u64));
        assert!(!window.accept(0));
        assert!(!window.accept(REPLAY_WINDOW_BITS as u64));
        assert!(window.accept(1));
    }

    #[test]
    fn window_handles_the_u64_sequence_limit_without_overflow() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(u64::MAX - 2));
        assert!(window.accept(u64::MAX));
        assert!(window.accept(u64::MAX - 1));
        assert!(!window.accept(u64::MAX));
        assert!(!window.accept(u64::MAX - 1));
    }
}
