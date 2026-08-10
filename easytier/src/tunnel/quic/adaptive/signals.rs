use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// EasyTier-local signals that Quinn's congestion-controller callbacks cannot
/// observe directly.
///
/// Updates are deliberately lock-free. The QUIC controller reads counters at
/// packet-round boundaries.
#[derive(Debug, Default)]
pub struct AdaptiveSignals {
    local_reliable_drops: AtomicU64,
    queue_sojourn_us: AtomicU64,
    path_epoch: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdaptiveSignalSnapshot {
    pub local_reliable_drops: u64,
    pub queue_sojourn: Duration,
    pub path_epoch: u64,
}

impl AdaptiveSignals {
    pub fn record_local_reliable_drop(&self) {
        self.local_reliable_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_queue_sojourn(&self, duration: Duration) {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.queue_sojourn_us.store(micros, Ordering::Relaxed);
    }

    pub fn set_path_epoch(&self, epoch: u64) {
        self.path_epoch.store(epoch, Ordering::Release);
    }

    pub fn snapshot(&self) -> AdaptiveSignalSnapshot {
        AdaptiveSignalSnapshot {
            local_reliable_drops: self.local_reliable_drops.load(Ordering::Relaxed),
            queue_sojourn: Duration::from_micros(self.queue_sojourn_us.load(Ordering::Relaxed)),
            path_epoch: self.path_epoch.load(Ordering::Acquire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips_atomic_signals() {
        let signals = AdaptiveSignals::default();
        signals.record_local_reliable_drop();
        signals.set_queue_sojourn(Duration::from_millis(17));
        signals.set_path_epoch(9);

        assert_eq!(
            signals.snapshot(),
            AdaptiveSignalSnapshot {
                local_reliable_drops: 1,
                queue_sojourn: Duration::from_millis(17),
                path_epoch: 9,
            }
        );
    }
}
