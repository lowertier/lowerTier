//! Pacing of packet transmissions.

use crate::{Duration, Instant};
use std::num::NonZeroU16;

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    max_burst_size: NonZeroU16,
    last_window: u64,
    last_rtt: Duration,
    last_mtu: u16,
    rate: Option<u64>,
    last_rate: Option<u64>,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(
        smoothed_rtt: Duration,
        window: u64,
        mtu: u16,
        now: Instant,
        max_burst_size: NonZeroU16,
    ) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu, None, max_burst_size);
        Self {
            capacity,
            max_burst_size,
            last_window: window,
            last_rtt: smoothed_rtt,
            last_mtu: mtu,
            rate: None,
            last_rate: None,
            tokens: capacity,
            prev: now,
        }
    }

    /// Preserve the per-path burst bound across connection migration.
    pub(super) fn max_burst_size(&self) -> NonZeroU16 {
        self.max_burst_size
    }

    /// Set the controller's pacing rate in bits per second, when available.
    pub(super) fn set_rate(&mut self, bits_per_second: Option<u64>) {
        self.rate = bits_per_second
            .filter(|&rate| rate != 0)
            .map(|rate| (rate / 8).max(1));
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window
            || smoothed_rtt != self.last_rtt
            || mtu != self.last_mtu
            || self.rate != self.last_rate
        {
            self.capacity =
                optimal_capacity(smoothed_rtt, window, mtu, self.rate, self.max_burst_size);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_rtt = smoothed_rtt;
            self.last_mtu = mtu;
            self.last_rate = self.rate;
        }

        // Credit elapsed time before spending existing tokens. Deferring this
        // until the bucket is empty lets an idle sender spend a full bucket
        // and immediately refill another one at the same timestamp.
        // A batch sharing `now` takes only the comparison on later packets.
        if now > self.prev && !smoothed_rtt.is_zero() {
            let elapsed = now.duration_since(self.prev).as_secs_f64();
            let new_tokens = match self.rate {
                Some(rate) => rate as f64 * elapsed,
                None => window as f64 * 1.25 * elapsed / smoothed_rtt.as_secs_f64(),
            };
            self.tokens = self
                .tokens
                .saturating_add(new_tokens as u64)
                .min(self.capacity);
            self.prev = now;
        }

        if self.tokens >= bytes_to_send {
            return None;
        }

        // We disable window-derived pacing for extremely large windows.
        if self.rate.is_none() && window > u64::from(u32::MAX) {
            return None;
        }
        if smoothed_rtt.is_zero() {
            return None;
        }
        if now < self.prev {
            warn!("received a timestamp early than a previous recorded time, ignoring");
        }

        if let Some(rate) = self.rate {
            let missing = bytes_to_send.max(self.capacity) - self.tokens;
            let nanos = missing.saturating_mul(1_000_000_000).div_ceil(rate);
            return Some(self.prev + Duration::from_nanos(nanos));
        }

        let window = window as u32;
        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(
    smoothed_rtt: Duration,
    window: u64,
    mtu: u16,
    rate: Option<u64>,
    max_burst_size: NonZeroU16,
) -> u64 {
    let capacity = match rate {
        Some(rate) => rate as u128 * BURST_INTERVAL_NANOS / 1_000_000_000,
        None => {
            let rtt = smoothed_rtt.as_nanos().max(1);
            window as u128 * BURST_INTERVAL_NANOS / rtt
        }
    };

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    let max_packets = u64::from(max_burst_size.get());
    capacity.clamp(
        u128::from(MIN_BURST_SIZE.min(max_packets)) * u128::from(mtu),
        u128::from(max_packets) * u128::from(mtu),
    ) as u64
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Allow the rate-derived 2 ms budget to survive millisecond timer rounding.
/// At 1 Gbit/s this is 250 kB (177 packets at MTU 1420). A 64-packet cap
/// discards elapsed credit and limits 1/2 ms wakeups to 727/364 Mbit/s.
/// Capacity still follows the current window/rate; this is only an upper bound.
/// The I/O driver separately limits each GSO submission and scheduling turn.
#[cfg(test)]
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    fn default_pacer(rtt: Duration, window: u64, mtu: u16, now: Instant) -> Pacer {
        Pacer::new(
            rtt,
            window,
            mtu,
            now,
            NonZeroU16::new(MAX_BURST_SIZE as u16).unwrap(),
        )
    }

    #[test]
    fn configured_burst_bound_survives_refill_and_path_estimate_changes() {
        for limit in [1, 8, 64, 256] {
            for explicit_rate in [None, Some(1_000_000_000)] {
                let start = Instant::now();
                let limit = NonZeroU16::new(limit).unwrap();
                let mut p = Pacer::new(Duration::from_millis(20), 2_500_000, 1420, start, limit);
                p.set_rate(explicit_rate);
                for (i, mtu) in [1200_u16, 1420, 1500].into_iter().enumerate() {
                    let now = start + Duration::from_secs(i as u64 + 1);
                    let rtt = Duration::from_millis(1);
                    assert_eq!(p.delay(rtt, mtu.into(), mtu, 2_500_000, now), None);
                    let maximum = u64::from(limit.get()) * u64::from(mtu);
                    let expected = if explicit_rate.is_some() {
                        maximum.min(250_000)
                    } else {
                        maximum
                    };
                    assert_eq!(p.capacity, expected);
                    for _ in 0..p.capacity / u64::from(mtu) {
                        assert_eq!(p.delay(rtt, mtu.into(), mtu, 2_500_000, now), None);
                        p.on_transmit(mtu);
                    }
                    assert!(p.delay(rtt, mtu.into(), mtu, 2_500_000, now).is_some());
                    assert!(p.tokens < u64::from(mtu));
                    assert_eq!(p.max_burst_size(), limit);
                }
            }
        }
    }

    #[test]
    fn rate_survives_millisecond_timer_quantization() {
        for explicit_rate in [false, true] {
            for tick_ns in [1_000_000, 2_000_000] {
                let start = Instant::now();
                let rtt = Duration::from_millis(20);
                let mtu = 1420;
                let window = 2_500_000;
                let mut pacer = default_pacer(rtt, window, mtu, start);
                if explicit_rate {
                    pacer.set_rate(Some(1_000_000_000));
                }
                let mut now = start;
                let mut bytes = 0_u64;
                while now < start + Duration::from_secs(2) {
                    if let Some(deadline) = pacer.delay(rtt, mtu.into(), mtu, window, now) {
                        let elapsed = deadline.duration_since(start).as_nanos() as u64;
                        now = start + Duration::from_nanos(elapsed.div_ceil(tick_ns) * tick_ns);
                    } else {
                        pacer.on_transmit(mtu);
                        bytes += u64::from(mtu);
                    }
                }
                let bps = bytes * 8 / 2;
                assert!(
                    bps >= 950_000_000,
                    "rate={explicit_rate}, tick={tick_ns}: {bps}"
                );
                assert!(
                    bps <= 1_251_500_000,
                    "credit exceeded the pacing budget: {bps}"
                );
            }
        }
    }

    #[test]
    fn capacity_tracks_rtt_without_a_window_change() {
        let now = Instant::now();
        let mut pacer = default_pacer(Duration::from_millis(100), 500_000, 1420, now);
        let initial = pacer.tokens;
        pacer.delay(Duration::from_millis(10), 1420, 1420, 500_000, now);
        assert_eq!(pacer.capacity, 100_000);
        assert_eq!(
            pacer.tokens, initial,
            "a capacity update cannot mint credit"
        );
        pacer.delay(Duration::from_millis(200), 1420, 1420, 500_000, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * 1420);
        assert!(pacer.tokens <= pacer.capacity);
    }

    #[test]
    fn capacity_clamps_before_narrowing_extreme_inputs() {
        assert_eq!(
            optimal_capacity(
                Duration::from_nanos(1),
                u64::MAX,
                1420,
                None,
                NonZeroU16::new(MAX_BURST_SIZE as u16).unwrap()
            ),
            MAX_BURST_SIZE * 1420
        );
    }

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            default_pacer(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            default_pacer(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            default_pacer(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn controller_rate_is_independent_of_the_flight_window() {
        let now = Instant::now();
        let rtt = Duration::from_millis(80);
        let mut pacer = default_pacer(rtt, 16 * 1024 * 1024, 1200, now);
        pacer.set_rate(Some(80_000_000));
        pacer.delay(rtt, 1200, 1200, 16 * 1024 * 1024, now);
        assert_eq!(pacer.capacity, 20_000);
        pacer.tokens = 0;
        assert_eq!(
            pacer.delay(rtt, 1200, 1200, 16 * 1024 * 1024, now),
            Some(now + Duration::from_millis(2))
        );
        pacer.set_rate(Some(40_000_000));
        pacer.delay(rtt, 1200, 1200, 16 * 1024 * 1024, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * 1200);
    }

    #[test]
    fn idle_refill_allows_only_one_burst_at_one_timestamp() {
        let start = Instant::now();
        let resumed = start + Duration::from_secs(1);
        let rtt = Duration::from_millis(50);
        let mtu = 1200;
        let window = 48_000;
        for rate in [None, Some(8_000_000)] {
            let mut pacer = default_pacer(rtt, window, mtu, start);
            pacer.set_rate(rate);
            assert_eq!(pacer.delay(rtt, mtu.into(), mtu, window, resumed), None);
            let capacity = pacer.capacity;
            let packets = capacity / u64::from(mtu);
            for _ in 0..packets {
                assert_eq!(pacer.delay(rtt, mtu.into(), mtu, window, resumed), None);
                pacer.on_transmit(mtu);
            }
            assert!(
                pacer.delay(rtt, mtu.into(), mtu, window, resumed).is_some(),
                "idle credit must be clamped before spending the first burst; rate={rate:?}"
            );
            assert!(pacer.tokens < u64::from(mtu));
        }
    }

    #[test]
    fn partial_bucket_refills_before_spending_after_idle() {
        let start = Instant::now();
        let resumed = start + Duration::from_secs(1);
        let rtt = Duration::from_millis(50);
        let mtu = 1200;
        let window = 48_000;
        let mut pacer = default_pacer(rtt, window, mtu, start);
        pacer.on_transmit(mtu);
        assert_eq!(pacer.delay(rtt, mtu.into(), mtu, window, resumed), None);
        assert_eq!(pacer.tokens, pacer.capacity);
        assert_eq!(pacer.prev, resumed);
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 750_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = default_pacer(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = default_pacer(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = default_pacer(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 750_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = default_pacer(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 1_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = default_pacer(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
}
