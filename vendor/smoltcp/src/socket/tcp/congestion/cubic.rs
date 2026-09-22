use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

// RFC 9438: the cubic function uses segments and seconds. Socket credit uses bytes.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;
const ALPHA_RENO: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cubic {
    cwnd: usize,
    min_cwnd: usize,
    w_max: usize,
    recovery_start: Option<Instant>,
    rwnd: usize,
    last_update: Instant,
    ssthresh: usize,
    k: f64,
    target: f64,
    ack_credit: f64,
    reno_window: f64,
}

impl Cubic {
    pub fn new() -> Self {
        Self {
            cwnd: 2048,
            min_cwnd: 2048,
            w_max: 2048,
            recovery_start: None,
            rwnd: 64 * 1024,
            last_update: Instant::from_millis(0),
            ssthresh: usize::MAX,
            k: 0.0,
            target: 2048.0,
            ack_credit: 0.0,
            reno_window: 2048.0,
        }
    }

    fn begin_epoch(&mut self, now: Instant) {
        self.w_max = self.w_max.max(self.cwnd);
        let gap = self.w_max.saturating_sub(self.cwnd) as f64 / self.min_cwnd as f64;
        // Cube root is computed once per recovery epoch, never per packet.
        self.k = cube_root(gap / C).unwrap_or(0.0);
        self.recovery_start = Some(now);
        self.last_update = now;
        self.target = self.cwnd as f64;
        self.ack_credit = 0.0;
        self.reno_window = self.cwnd as f64;
    }
}

impl Controller for Cubic {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_retransmit(&mut self, now: Instant) {
        let old_window = self.cwnd as f64;
        // Fast convergence changes W_max, independently of the 0.7 loss cut.
        self.w_max = if self.cwnd < self.w_max {
            (old_window * (1.0 + BETA_CUBIC) / 2.0) as usize
        } else {
            self.cwnd
        };
        self.ssthresh = ((old_window * BETA_CUBIC) as usize).max(self.min_cwnd.saturating_mul(2));
        self.cwnd = self
            .cwnd
            .min(self.ssthresh)
            .min(self.rwnd)
            .max(self.min_cwnd);
        self.begin_epoch(now);
    }

    fn on_timeout(&mut self, now: Instant) {
        self.on_retransmit(now);
        self.cwnd = self.min_cwnd;
        self.recovery_start = None;
        self.ack_credit = 0.0;
        self.reno_window = self.cwnd as f64;
    }

    // The TCP socket reports every duplicate ACK. Its fast-retransmit decision
    // calls on_retransmit once; duplicates alone must not restart the epoch.
    fn on_duplicate_ack(&mut self, _now: Instant) {}

    fn set_remote_window(&mut self, remote_window: usize) {
        self.rwnd = self.rwnd.max(remote_window);
    }

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {
        if len == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            // Keep the RFC 5681 slow-start bound of one MSS per new ACK.
            self.cwnd = self
                .cwnd
                .saturating_add(len.min(self.min_cwnd))
                .min(self.rwnd)
                .max(self.min_cwnd);
            self.reno_window = self.cwnd as f64;
            return;
        }
        if self.recovery_start.is_none() {
            self.begin_epoch(now);
        }
        let elapsed = now.total_millis() - self.recovery_start.unwrap().total_millis();
        if elapsed < 0 {
            return;
        }
        let mss = self.min_cwnd as f64;
        // Cache the time-dependent target for this millisecond. Growth remains
        // proportional to newly acknowledged bytes, including cumulative ACKs.
        if now.total_millis() > self.last_update.total_millis() {
            let t = (elapsed as f64 + f64::from(rtt.srtt.max(1))) / 1000.0 - self.k;
            self.target = (C * t * t * t + self.w_max as f64 / mss) * mss;
            self.target = self
                .target
                .max(self.cwnd as f64)
                .min(self.cwnd as f64 * 1.5);
            self.last_update = now;
        }
        let acked = len.min(self.cwnd) as f64;
        self.reno_window += ALPHA_RENO * acked * mss / self.reno_window.max(mss);
        if self.reno_window > self.target {
            self.cwnd = self.cwnd.max(self.reno_window as usize).min(self.rwnd);
        } else {
            self.ack_credit += (self.target - self.cwnd as f64).max(0.0) * acked / self.cwnd as f64;
            let increment = (self.ack_credit as usize).min(len).min(self.min_cwnd);
            self.ack_credit -= increment as f64;
            self.cwnd = self.cwnd.saturating_add(increment).min(self.rwnd);
        }
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    // Sending or waiting without fresh ACK feedback cannot increase cwnd.
    fn pre_transmit(&mut self, _now: Instant) {}

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss.max(1);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }
}

#[inline]
fn abs(a: f64) -> f64 {
    if a < 0.0 { -a } else { a }
}

/// Calculate cube root by using the Newton-Raphson method.
fn cube_root(a: f64) -> Option<f64> {
    if a <= 0.0 {
        return None;
    }

    let (_, init) = if a < 1_000.0 {
        (1.0, 8.879040017426005) // cube_root(700.0)
    } else if a < 1_000_000.0 {
        (5.0, 88.79040017426004) // cube_root(700_000.0)
    } else if a < 1_000_000_000.0 {
        (50.0, 887.9040017426004) // cube_root(700_000_000.0)
    } else if a < 1_000_000_000_000.0 {
        (500.0, 8879.040017426003) // cube_root(700_000_000_000.0)
    } else if a < 1_000_000_000_000_000.0 {
        (5000.0, 88790.40017426001) // cube_root(700_000_000_000.0)
    } else {
        (50000.0, 887904.0017426) // cube_root(700_000_000_000_000.0)
    };

    let mut x = init; // initial value
    let mut n = 20; // The maximum iteration
    loop {
        let next_x = (2.0 * x + a / (x * x)) / 3.0;
        if abs(next_x - x) <= 1e-10 * next_x.max(1.0) {
            return Some(next_x);
        }
        x = next_x;

        if n == 0 {
            return Some(next_x);
        }

        n -= 1;
    }
}

#[cfg(test)]
mod test {
    use crate::{socket::tcp::RttEstimator, time::Instant};

    use super::*;

    #[test]
    fn early_loss_never_increases_the_flight_allowance() {
        let mut cubic = Cubic::new();
        let before = cubic.window();
        cubic.on_retransmit(Instant::from_millis(0));
        assert!(cubic.window() <= before);
        assert!(cubic.ssthresh >= 2 * cubic.min_cwnd);
    }

    #[test]
    fn transmission_does_not_overwrite_slow_start() {
        let mut cubic = Cubic::new();
        cubic.set_mss(1200);
        cubic.set_remote_window(4 * 1024 * 1024);
        for i in 0..100 {
            let now = Instant::from_millis(i * 20);
            cubic.on_ack(now, 1200, &RttEstimator::default());
            let acknowledged_window = cubic.window();
            cubic.pre_transmit(now);
            assert_eq!(cubic.window(), acknowledged_window);
        }
        assert_eq!(cubic.window(), 2048 + 1200 * 100);
    }

    #[test]
    fn recovery_uses_segment_units_and_new_ack_credit() {
        let mut cubic = Cubic::new();
        cubic.set_mss(1000);
        cubic.set_remote_window(4_000_000);
        cubic.cwnd = 1_000_000;
        cubic.on_retransmit(Instant::from_millis(0));
        assert_eq!(cubic.window(), 700_000);
        // K = cube_root(300 segments / 0.4), not cube_root(300000 bytes / 0.4).
        assert!(abs(cubic.k - 9.085602964) < 1e-7);
        let epoch = cubic.recovery_start;
        for i in 1..100 {
            let now = Instant::from_millis(i * 20);
            cubic.on_duplicate_ack(now);
            cubic.on_ack(now, 0, &RttEstimator::default());
            cubic.pre_transmit(now);
        }
        assert_eq!(cubic.window(), 700_000);
        assert_eq!(cubic.recovery_start, epoch);
        let rtt = RttEstimator {
            srtt: 20,
            ..RttEstimator::default()
        };
        for round in 1..=100 {
            let now = Instant::from_millis(round * 20);
            for _ in 0..cubic.window() / 1000 {
                let before = cubic.window();
                cubic.on_ack(now, 1000, &rtt);
                assert!(cubic.window() <= before + 1000);
            }
        }
        assert!(
            cubic.window() > 800_000,
            "high-BDP recovery stalled: {}",
            cubic.window()
        );
        assert!(cubic.window() < 1_100_000);
        cubic.on_timeout(Instant::from_millis(2100));
        assert_eq!(cubic.window(), 1000);
        assert!(cubic.ssthresh >= 2_000);
        assert!(cubic.recovery_start.is_none());
    }

    #[test]
    fn fast_convergence_does_not_apply_the_loss_reduction_twice() {
        let mut cubic = Cubic::new();
        cubic.set_mss(1000);
        cubic.set_remote_window(4_000_000);
        cubic.w_max = 1_000_000;
        cubic.cwnd = 800_000;
        cubic.on_retransmit(Instant::from_millis(0));
        assert_eq!(cubic.w_max, 680_000);
        assert_eq!(cubic.window(), 560_000);
    }

    #[test]
    fn test_cubic() {
        let remote_window = 64 * 1024 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut cubic = Cubic::new();
                // Set remote window.
                cubic.set_remote_window(remote_window);

                cubic.set_mss(1480);

                if i & 1 == 0 {
                    cubic.on_retransmit(now);
                } else {
                    cubic.on_duplicate_ack(now);
                }

                cubic.pre_transmit(now);

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                let elapsed = Instant::from_millis(n);
                cubic.pre_transmit(elapsed);

                let cwnd = cubic.window();
                println!("Cubic: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= cubic.min_cwnd);
                assert!(cubic.window() <= remote_window);
            }
        }
    }

    #[test]
    fn cubic_time_inversion() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_retransmit(t2);
        cubic.pre_transmit(t1);

        let cwnd = cubic.window();
        println!("Cubic:time_inversion: cwnd: {}, cubic: {cubic:?}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_long_elapsed_time() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_retransmit(t1);
        cubic.pre_transmit(t2);

        let cwnd = cubic.window();
        println!("Cubic:long_elapsed_time: cwnd: {}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_last_update() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_millis(100);
        let t3 = Instant::from_millis(199);
        let t4 = Instant::from_millis(20000);

        cubic.on_retransmit(t1);

        cubic.pre_transmit(t2);
        let cwnd2 = cubic.window();

        cubic.pre_transmit(t3);
        let cwnd3 = cubic.window();

        cubic.pre_transmit(t4);
        let cwnd4 = cubic.window();

        println!(
            "Cubic:last_update: cwnd2: {}, cwnd3: {}, cwnd4: {}",
            cwnd2, cwnd3, cwnd4
        );

        assert_eq!(cwnd2, cwnd3);
        // Elapsed time without new ACK feedback cannot grant flight credit.
        assert_eq!(cwnd2, cwnd4);
        cubic.on_ack(t4, 1024, &RttEstimator::default());
        assert!(cubic.window() > cwnd4);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);

        let cwnd = cubic.window();
        let ack_len = 1024;

        cubic.on_ack(t1, ack_len, &RttEstimator::default());

        assert!(cubic.window() > cwnd);

        for i in 1..1000 {
            let t2 = Instant::from_micros(i);
            cubic.on_ack(t2, ack_len * 100, &RttEstimator::default());
            assert!(cubic.window() <= cubic.rwnd);
        }

        let t3 = Instant::from_micros(2000);

        let cwnd = cubic.window();
        cubic.on_retransmit(t3);
        assert_eq!(
            ((cwnd as f64 * BETA_CUBIC) as usize).max(2 * cubic.min_cwnd),
            cubic.ssthresh
        );
        assert_eq!(cubic.window(), cubic.ssthresh);
    }

    #[test]
    fn cubic_pre_transmit() {
        let mut cubic = Cubic::new();
        cubic.pre_transmit(Instant::from_micros(2000));
    }

    #[test]
    fn test_cube_root() {
        for n in (1..1000000).step_by(99) {
            let a = n as f64;
            let a = a * a * a;
            let result = cube_root(a);
            println!("cube_root({a}) = {}", result.unwrap());
        }
    }

    #[test]
    #[should_panic]
    fn cube_root_zero() {
        cube_root(0.0).unwrap();
    }
}
