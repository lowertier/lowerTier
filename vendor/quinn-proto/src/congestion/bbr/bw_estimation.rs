use std::{
    collections::VecDeque,
    fmt::{Debug, Display, Formatter},
};

use super::min_max::MinMax;
use crate::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct SendState {
    sent: Instant,
    first_sent: Instant,
    delivered: u64,
    delivered_time: Instant,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    acked_at_last_window: u64,
    delivered_time: Option<Instant>,
    first_sent_time: Option<Instant>,
    in_flight: u64,
    sent: VecDeque<SendState>,
    sample: Option<SendState>,
    acked_time: Option<Instant>,
    max_filter: MinMax,
}

impl BandwidthEstimation {
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64) {
        if self.in_flight == 0 {
            self.first_sent_time = Some(now);
            self.delivered_time = Some(now);
            self.sent.clear();
        }
        self.in_flight = self.in_flight.saturating_add(bytes);
        // Packets sealed together share a send timestamp and delivery snapshot.
        if self.sent.back().is_none_or(|state| state.sent != now) {
            self.sent.push_back(SendState {
                sent: now,
                first_sent: self.first_sent_time.unwrap_or(now),
                delivered: self.total_acked,
                delivered_time: self.delivered_time.unwrap_or(now),
            });
        }
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        _round: u64,
        _app_limited: bool,
    ) {
        self.total_acked += bytes;
        self.acked_time = Some(now);
        while self.sent.get(1).is_some_and(|state| state.sent <= sent) {
            self.sent.pop_front();
        }
        let Some(&state) = self.sent.front().filter(|state| state.sent == sent) else {
            // A reordered ACK can refer to a snapshot retired by a newer ACK.
            return;
        };
        if self
            .sample
            .is_none_or(|sample| (state.delivered, state.sent) > (sample.delivered, sample.sent))
        {
            self.sample = Some(state);
        }
    }

    pub(crate) fn on_loss(&mut self, bytes: u64) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(
        &mut self,
        current_round: u64,
        app_limited: bool,
        in_flight: u64,
        min_rtt: Duration,
    ) {
        self.acked_at_last_window = self.total_acked;
        self.in_flight = in_flight;
        let Some(now) = self.acked_time.take() else {
            return;
        };
        self.delivered_time = Some(now);
        let Some(sample) = self.sample.take() else {
            return;
        };
        self.first_sent_time = Some(sample.sent);

        // Measure the corresponding flight, not the gap between adjacent ACKs.
        // The send interval bounds samples when the return path compresses ACKs.
        // A delayed ACK (scheduler steal, delayed-ACK timer) must not look like
        // a low-bandwidth path: that freezes BBR startup at the initial window.
        let ack_wait = now.saturating_duration_since(sample.delivered_time);
        let send_wait = sample.sent.saturating_duration_since(sample.first_sent);
        let interval = delivery_interval(ack_wait, send_wait, min_rtt);
        let Some(bandwidth) = Self::bw_from_delta(self.total_acked - sample.delivered, interval)
        else {
            return;
        };
        if !app_limited || self.max_filter.get() < bandwidth {
            self.max_filter.update_max(current_round, bandwidth);
        }
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let bytes_per_second = bytes as u128 * 1_000_000_000 / window_duration_ns;
        Some(if bytes_per_second > u64::MAX as u128 {
            u64::MAX
        } else {
            bytes_per_second as u64
        })
    }
}

fn delivery_interval(ack_wait: Duration, send_wait: Duration, min_rtt: Duration) -> Duration {
    let interval = ack_wait.max(send_wait);
    if min_rtt.is_zero() || min_rtt == Duration::MAX {
        return interval;
    }
    // ACK wait longer than a few min_rtt is scheduling delay, not send spacing.
    if ack_wait > min_rtt.saturating_mul(4) {
        return send_wait.max(min_rtt);
    }
    interval
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_all_packets_in_an_ack_batch() {
        let mut bandwidth = BandwidthEstimation::default();
        let now = Instant::now();
        for flight in 0..2 {
            let sent = now + Duration::from_millis(flight);
            for _ in 0..20 {
                bandwidth.on_sent(sent, 1200);
            }
            assert_eq!(bandwidth.sent.len(), 1);
            for _ in 0..20 {
                bandwidth.on_ack(sent + Duration::from_millis(1), sent, 1200, flight, false);
            }
            assert_eq!(bandwidth.bytes_acked_this_window(), 24_000);
            bandwidth.end_acks(flight, false, 0, Duration::MAX);
        }
        assert_eq!(bandwidth.get_estimate(), 24_000_000);
    }

    #[test]
    fn expires_bandwidth_from_a_faster_path() {
        let mut bandwidth = BandwidthEstimation::default();
        let mut now = Instant::now();
        for round in 0..24 {
            let sent = now;
            bandwidth.on_sent(sent, 24_000);
            now += Duration::from_millis(if round < 3 { 1 } else { 10 });
            bandwidth.on_ack(now, sent, 24_000, round, false);
            bandwidth.end_acks(round, false, 0, Duration::MAX);
        }
        assert_eq!(bandwidth.get_estimate(), 2_400_000);
    }

    #[test]
    fn send_rate_bounds_compressed_acks() {
        let mut bandwidth = BandwidthEstimation::default();
        let now = Instant::now();
        for packet in 0..8 {
            bandwidth.on_sent(now + Duration::from_millis(packet * 10), 1200);
        }
        bandwidth.on_ack(now + Duration::from_millis(80), now, 1200, 0, false);
        bandwidth.end_acks(0, false, 8400, Duration::MAX);
        for packet in 1..8 {
            bandwidth.on_ack(
                now + Duration::from_micros(80_100),
                now + Duration::from_millis(packet * 10),
                1200,
                1,
                false,
            );
        }
        bandwidth.end_acks(1, false, 0, Duration::MAX);
        assert!(bandwidth.get_estimate() > 0);
        assert!(bandwidth.get_estimate() <= 120_000);
    }

    #[test]
    fn reordered_ack_counts_delivery_without_reusing_retired_state() {
        let mut bandwidth = BandwidthEstimation::default();
        let now = Instant::now();
        bandwidth.on_sent(now, 1200);
        bandwidth.on_sent(now + Duration::from_millis(1), 1200);
        bandwidth.on_ack(
            now + Duration::from_millis(80),
            now + Duration::from_millis(1),
            1200,
            0,
            false,
        );
        bandwidth.end_acks(0, false, 1200, Duration::MAX);
        bandwidth.on_ack(now + Duration::from_millis(81), now, 1200, 1, false);
        assert_eq!(bandwidth.bytes_acked_this_window(), 1200);
        bandwidth.end_acks(1, false, 0, Duration::MAX);
        assert_eq!(bandwidth.total_acked, 2400);
        assert_eq!(bandwidth.get_estimate(), 15_000);
    }

    #[test]
    fn idle_after_loss_does_not_enter_the_delivery_interval() {
        let mut bandwidth = BandwidthEstimation::default();
        let now = Instant::now();
        bandwidth.on_sent(now, 1200);
        bandwidth.on_loss(1200);
        let sent = now + Duration::from_secs(5);
        bandwidth.on_sent(sent, 1200);
        bandwidth.on_ack(sent + Duration::from_millis(1), sent, 1200, 0, false);
        bandwidth.end_acks(0, false, 0, Duration::MAX);
        assert_eq!(bandwidth.get_estimate(), 1_200_000);
    }

    #[test]
    fn delayed_ack_does_not_look_like_a_narrow_path() {
        let mut bandwidth = BandwidthEstimation::default();
        let now = Instant::now();
        bandwidth.on_sent(now, 12_000);
        bandwidth.on_ack(now + Duration::from_millis(600), now, 12_000, 0, false);
        bandwidth.end_acks(0, false, 0, Duration::from_millis(80));
        assert_eq!(bandwidth.get_estimate(), 150_000);
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}
