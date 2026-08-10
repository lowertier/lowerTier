use std::sync::atomic::{AtomicU64, Ordering};

const RELAXED: Ordering = Ordering::Relaxed;

#[derive(Default)]
pub(super) struct QuicDatagramMetrics {
    source_frames: AtomicU64,
    source_fragments: AtomicU64,
    source_bytes: AtomicU64,
    fragmented_source_fragments: AtomicU64,
    queue_drops_pending: AtomicU64,
    queue_drops_quinn: AtomicU64,
    ack_ranges_sent: AtomicU64,
    ack_ranges_received: AtomicU64,
    nacks_sent: AtomicU64,
    nacks_received: AtomicU64,
    selective_fragments_retransmitted: AtomicU64,
    recovery_exhausted: AtomicU64,
    critical_duplicates_sent: AtomicU64,
    critical_duplicates_suppressed: AtomicU64,
    fec_blocks: AtomicU64,
    fec_source_symbols: AtomicU64,
    fec_parity_symbols: AtomicU64,
    fec_source_bytes: AtomicU64,
    fec_parity_bytes: AtomicU64,
    fec_recovered_symbols: AtomicU64,
    fec_unrecoverable_blocks: AtomicU64,
    partial_frames_expired: AtomicU64,
    path_mtu: AtomicU64,
    queue_high_water_bytes: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct QuicDatagramMetricsSnapshot {
    pub source_frames: u64,
    pub source_fragments: u64,
    pub source_bytes: u64,
    pub fragmented_source_fragments: u64,
    pub queue_drops_pending: u64,
    pub queue_drops_quinn: u64,
    pub ack_ranges_sent: u64,
    pub ack_ranges_received: u64,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    pub selective_fragments_retransmitted: u64,
    pub recovery_exhausted: u64,
    pub critical_duplicates_sent: u64,
    pub critical_duplicates_suppressed: u64,
    pub fec_blocks: u64,
    pub fec_source_symbols: u64,
    pub fec_parity_symbols: u64,
    pub fec_source_bytes: u64,
    pub fec_parity_bytes: u64,
    pub fec_recovered_symbols: u64,
    pub fec_unrecoverable_blocks: u64,
    pub partial_frames_expired: u64,
    pub path_mtu: u64,
    pub queue_high_water_bytes: u64,
}

macro_rules! counter_method {
    ($name:ident, $field:ident) => {
        pub fn $name(&self) {
            self.$field.fetch_add(1, RELAXED);
        }
    };
}

impl QuicDatagramMetrics {
    pub const fn tsv_header() -> &'static str {
        "source_frames\tsource_fragments\tsource_bytes\tfragmented_source_fragments\tqueue_drops_pending\tqueue_drops_quinn\tack_ranges_sent\tack_ranges_received\tnacks_sent\tnacks_received\tselective_fragments_retransmitted\trecovery_exhausted\tcritical_duplicates_sent\tcritical_duplicates_suppressed\tfec_blocks\tfec_source_symbols\tfec_parity_symbols\tfec_source_bytes\tfec_parity_bytes\tfec_recovered_symbols\tfec_unrecoverable_blocks\tpartial_frames_expired\tpath_mtu\tqueue_high_water_bytes"
    }

    counter_method!(record_source_frame, source_frames);
    counter_method!(record_queue_drop_pending, queue_drops_pending);
    counter_method!(record_queue_drop_quinn, queue_drops_quinn);
    counter_method!(record_ack_range_sent, ack_ranges_sent);
    counter_method!(record_ack_range_received, ack_ranges_received);
    counter_method!(record_nack_sent, nacks_sent);
    counter_method!(record_nack_received, nacks_received);
    counter_method!(record_recovery_exhausted, recovery_exhausted);
    counter_method!(record_critical_duplicate_sent, critical_duplicates_sent);
    counter_method!(
        record_critical_duplicate_suppressed,
        critical_duplicates_suppressed
    );
    counter_method!(record_fec_unrecoverable, fec_unrecoverable_blocks);
    counter_method!(record_partial_frame_expired, partial_frames_expired);

    pub fn record_source_fragment(&self, bytes: usize, fragmented: bool) {
        self.source_fragments.fetch_add(1, RELAXED);
        self.source_bytes.fetch_add(bytes as u64, RELAXED);
        if fragmented {
            self.fragmented_source_fragments.fetch_add(1, RELAXED);
        }
    }

    pub fn record_selective_retransmit(&self, fragments: usize) {
        self.selective_fragments_retransmitted
            .fetch_add(fragments as u64, RELAXED);
    }

    pub fn record_fec_block(
        &self,
        source_symbols: usize,
        parity_symbols: usize,
        source_bytes: usize,
        parity_bytes: usize,
    ) {
        self.fec_blocks.fetch_add(1, RELAXED);
        self.fec_source_symbols
            .fetch_add(source_symbols as u64, RELAXED);
        self.fec_parity_symbols
            .fetch_add(parity_symbols as u64, RELAXED);
        self.fec_source_bytes
            .fetch_add(source_bytes as u64, RELAXED);
        self.fec_parity_bytes
            .fetch_add(parity_bytes as u64, RELAXED);
    }

    pub fn record_fec_recovered(&self, symbols: usize) {
        self.fec_recovered_symbols
            .fetch_add(symbols as u64, RELAXED);
    }

    pub fn observe_path_mtu(&self, mtu: usize) {
        self.path_mtu.fetch_max(mtu as u64, RELAXED);
    }

    pub fn observe_queue_bytes(&self, bytes: usize) {
        self.queue_high_water_bytes.fetch_max(bytes as u64, RELAXED);
    }

    pub fn snapshot(&self) -> QuicDatagramMetricsSnapshot {
        QuicDatagramMetricsSnapshot {
            source_frames: self.source_frames.load(RELAXED),
            source_fragments: self.source_fragments.load(RELAXED),
            source_bytes: self.source_bytes.load(RELAXED),
            fragmented_source_fragments: self.fragmented_source_fragments.load(RELAXED),
            queue_drops_pending: self.queue_drops_pending.load(RELAXED),
            queue_drops_quinn: self.queue_drops_quinn.load(RELAXED),
            ack_ranges_sent: self.ack_ranges_sent.load(RELAXED),
            ack_ranges_received: self.ack_ranges_received.load(RELAXED),
            nacks_sent: self.nacks_sent.load(RELAXED),
            nacks_received: self.nacks_received.load(RELAXED),
            selective_fragments_retransmitted: self.selective_fragments_retransmitted.load(RELAXED),
            recovery_exhausted: self.recovery_exhausted.load(RELAXED),
            critical_duplicates_sent: self.critical_duplicates_sent.load(RELAXED),
            critical_duplicates_suppressed: self.critical_duplicates_suppressed.load(RELAXED),
            fec_blocks: self.fec_blocks.load(RELAXED),
            fec_source_symbols: self.fec_source_symbols.load(RELAXED),
            fec_parity_symbols: self.fec_parity_symbols.load(RELAXED),
            fec_source_bytes: self.fec_source_bytes.load(RELAXED),
            fec_parity_bytes: self.fec_parity_bytes.load(RELAXED),
            fec_recovered_symbols: self.fec_recovered_symbols.load(RELAXED),
            fec_unrecoverable_blocks: self.fec_unrecoverable_blocks.load(RELAXED),
            partial_frames_expired: self.partial_frames_expired.load(RELAXED),
            path_mtu: self.path_mtu.load(RELAXED),
            queue_high_water_bytes: self.queue_high_water_bytes.load(RELAXED),
        }
    }

    pub fn tsv_row(&self) -> String {
        let s = self.snapshot();
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.source_frames,
            s.source_fragments,
            s.source_bytes,
            s.fragmented_source_fragments,
            s.queue_drops_pending,
            s.queue_drops_quinn,
            s.ack_ranges_sent,
            s.ack_ranges_received,
            s.nacks_sent,
            s.nacks_received,
            s.selective_fragments_retransmitted,
            s.recovery_exhausted,
            s.critical_duplicates_sent,
            s.critical_duplicates_suppressed,
            s.fec_blocks,
            s.fec_source_symbols,
            s.fec_parity_symbols,
            s.fec_source_bytes,
            s.fec_parity_bytes,
            s.fec_recovered_symbols,
            s.fec_unrecoverable_blocks,
            s.partial_frames_expired,
            s.path_mtu,
            s.queue_high_water_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::QuicDatagramMetrics;

    #[test]
    fn relaxed_atomic_metrics_reconcile_concurrent_packet_updates() {
        let metrics = Arc::new(QuicDatagramMetrics::default());
        let workers = (0..4)
            .map(|_| {
                let metrics = metrics.clone();
                thread::spawn(move || {
                    for _ in 0..1_000 {
                        metrics.record_source_fragment(1200, true);
                        metrics.record_ack_range_sent();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        metrics.observe_path_mtu(1200);
        metrics.observe_path_mtu(1420);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.source_fragments, 4_000);
        assert_eq!(snapshot.source_bytes, 4_800_000);
        assert_eq!(snapshot.fragmented_source_fragments, 4_000);
        assert_eq!(snapshot.ack_ranges_sent, 4_000);
        assert_eq!(snapshot.path_mtu, 1420);
    }

    #[test]
    fn benchmark_export_has_stable_header_and_field_order() {
        let metrics = QuicDatagramMetrics::default();
        metrics.record_fec_block(16, 2, 19_200, 2_400);
        metrics.record_fec_recovered(2);
        metrics.record_queue_drop_pending();

        assert_eq!(
            QuicDatagramMetrics::tsv_header(),
            "source_frames\tsource_fragments\tsource_bytes\tfragmented_source_fragments\tqueue_drops_pending\tqueue_drops_quinn\tack_ranges_sent\tack_ranges_received\tnacks_sent\tnacks_received\tselective_fragments_retransmitted\trecovery_exhausted\tcritical_duplicates_sent\tcritical_duplicates_suppressed\tfec_blocks\tfec_source_symbols\tfec_parity_symbols\tfec_source_bytes\tfec_parity_bytes\tfec_recovered_symbols\tfec_unrecoverable_blocks\tpartial_frames_expired\tpath_mtu\tqueue_high_water_bytes"
        );
        assert_eq!(
            metrics.tsv_row(),
            "0\t0\t0\t0\t1\t0\t0\t0\t0\t0\t0\t0\t0\t0\t1\t16\t2\t19200\t2400\t2\t0\t0\t0\t0"
        );
    }
}
