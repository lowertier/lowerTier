use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    min_cwnd: usize,
    ssthresh: usize,
    rwnd: usize,
    acked_bytes: usize,
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            ssthresh: usize::MAX,
            rwnd: 64 * 1024,
            acked_bytes: 0,
        }
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _rtt: &RttEstimator) {
        if len == 0 {
            return;
        }
        let len = if self.cwnd < self.ssthresh {
            // Each ACK grows slow start by at most one MSS (RFC 5681).
            self.acked_bytes = 0;
            len.min(self.min_cwnd)
        } else {
            // Add one MSS after a window of new bytes has been acknowledged.
            // A delayed ACK from an older, larger flight earns at most one
            // window of credit. This needs no division or floating point.
            self.acked_bytes = self.acked_bytes.saturating_add(len.min(self.cwnd));
            if self.acked_bytes >= self.cwnd {
                self.acked_bytes -= self.cwnd;
                self.min_cwnd
            } else {
                0
            }
        };

        self.cwnd = self
            .cwnd
            .saturating_add(len)
            .min(self.rwnd)
            .max(self.min_cwnd);
    }

    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.ssthresh = (self.cwnd >> 1).max(self.min_cwnd);
    }

    fn on_retransmit(&mut self, _now: Instant) {
        self.acked_bytes = 0;
        self.cwnd = (self.cwnd >> 1).max(self.min_cwnd);
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time::Instant;

    use super::*;

    #[test]
    fn congestion_avoidance_requires_one_window_of_newly_acked_bytes() {
        let now = Instant::from_millis(0);
        let mut reno = Reno::new();
        reno.set_mss(1000);
        reno.cwnd = 10_000;
        reno.ssthresh = 5000;
        for _ in 0..9 {
            reno.on_ack(now, 1000, &RttEstimator::default());
            assert_eq!(reno.window(), 10_000);
        }
        reno.on_ack(now, 1000, &RttEstimator::default());
        assert_eq!(reno.window(), 11_000);
    }

    #[test]
    fn duplicate_acks_do_not_grow_congestion_avoidance_window() {
        let now = Instant::from_millis(0);
        let mut reno = Reno::new();
        reno.set_mss(1000);
        reno.cwnd = 10_000;
        reno.ssthresh = 5000;
        for _ in 0..100 {
            reno.on_ack(now, 0, &RttEstimator::default());
            assert_eq!(reno.window(), 10_000);
        }
    }

    #[test]
    fn slow_start_limits_growth_to_one_mss_per_new_ack() {
        let now = Instant::from_millis(0);
        let mut reno = Reno::new();
        reno.set_mss(1000);
        let initial = reno.window();
        reno.on_ack(now, 8000, &RttEstimator::default());
        assert_eq!(reno.window(), initial + 1000);
        reno.on_ack(now, 0, &RttEstimator::default());
        assert_eq!(reno.window(), initial + 1000);
    }

    #[test]
    fn congestion_avoidance_discards_credit_after_loss() {
        let now = Instant::from_millis(0);
        let mut reno = Reno::new();
        reno.set_mss(1000);
        reno.cwnd = 10_000;
        reno.ssthresh = 5000;
        reno.on_ack(now, 9000, &RttEstimator::default());
        assert_eq!(reno.window(), 10_000);
        assert_eq!(reno.ssthresh, 5000);
        reno.on_retransmit(now);
        reno.on_ack(now, 1000, &RttEstimator::default());
        assert_eq!(reno.window(), 5000);
        reno.on_ack(now, 4000, &RttEstimator::default());
        assert_eq!(reno.window(), 6000);
    }

    #[test]
    fn test_reno() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut reno = Reno::new();
                reno.set_mss(1480);

                // Set remote window.
                reno.set_remote_window(remote_window);

                reno.on_ack(now, 4096, &RttEstimator::default());

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                if i & 1 == 0 {
                    reno.on_retransmit(now);
                } else {
                    reno.on_duplicate_ack(now);
                }

                let elapsed = Instant::from_millis(1000);
                reno.on_ack(elapsed, n, &RttEstimator::default());

                let cwnd = reno.window();
                println!("Reno: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= reno.min_cwnd);
                assert!(reno.window() <= remote_window);
            }
        }
    }

    #[test]
    fn reno_min_cwnd() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        let mut reno = Reno::new();
        reno.set_remote_window(remote_window);

        for _ in 0..100 {
            reno.on_retransmit(now);
            assert!(reno.window() >= reno.min_cwnd);
        }
    }

    #[test]
    fn reno_set_rwnd() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 * 1024 * 1024);

        println!("{reno:?}");
    }
}
