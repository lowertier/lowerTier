use std::{any::Any, sync::Arc, time::Duration};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory},
};

const PACER_NUMERATOR: u128 = 5;
const PACER_DENOMINATOR: u128 = 4;
const MIN_DATAGRAMS_IN_FLIGHT: u64 = 10;
const MAX_PACED_WINDOW: u64 = u32::MAX as u64;
const MAX_LOSS_COMPENSATION: u64 = 4;
const INITIAL_RTT: Duration = Duration::from_millis(333);
const DELIVERY_SCALE: u64 = 1_000_000;

/// Fixed-rate QUIC congestion controller configuration.
///
/// Quinn's userspace pacer emits approximately 1.25 congestion windows per
/// RTT. The calculated window compensates for that factor so the configured
/// bit rate is the target wire rate rather than 1.25 times the target.
#[derive(Clone, Debug)]
pub struct BrutalConfig {
    send_bps: u64,
    loss_compensation: bool,
}

impl BrutalConfig {
    pub fn new(send_bps: u64, loss_compensation: bool) -> Result<Self, &'static str> {
        if send_bps == 0 {
            return Err("Brutal send rate must be greater than zero");
        }
        Ok(Self {
            send_bps,
            loss_compensation,
        })
    }

    pub fn send_bps(&self) -> u64 {
        self.send_bps
    }

    fn window_for_rate(&self, send_bps: u64, rtt: Duration, mtu: u16) -> u64 {
        let bytes_per_second = u128::from(send_bps).div_ceil(8);
        let window = bytes_per_second
            .saturating_mul(rtt.as_nanos())
            .saturating_mul(PACER_DENOMINATOR)
            / (1_000_000_000_u128 * PACER_NUMERATOR);
        let minimum = MIN_DATAGRAMS_IN_FLIGHT * u64::from(mtu);
        u64::try_from(window)
            .unwrap_or(u64::MAX)
            .clamp(minimum, MAX_PACED_WINDOW)
    }

    pub(crate) fn window_for_rtt(&self, rtt: Duration, mtu: u16) -> u64 {
        self.window_for_rate(self.send_bps, rtt, mtu)
    }

    fn compensated_rate_bps(&self, acknowledged: u64, lost: u64) -> u64 {
        if !self.loss_compensation || lost == 0 {
            return self.send_bps;
        }

        let total = acknowledged.saturating_add(lost);
        if total == 0 {
            return self.send_bps;
        }
        if acknowledged == 0 {
            return self.send_bps.saturating_mul(MAX_LOSS_COMPENSATION);
        }

        let compensated = u128::from(self.send_bps)
            .saturating_mul(u128::from(total))
            .div_ceil(u128::from(acknowledged));
        u64::try_from(compensated)
            .unwrap_or(u64::MAX)
            .min(self.send_bps.saturating_mul(MAX_LOSS_COMPENSATION))
    }

    fn compensated_rate_for_delivery(&self, delivery_ratio: u64) -> u64 {
        if !self.loss_compensation || delivery_ratio >= DELIVERY_SCALE {
            return self.send_bps;
        }
        let minimum_ratio = DELIVERY_SCALE / MAX_LOSS_COMPENSATION;
        let ratio = delivery_ratio.max(minimum_ratio);
        let compensated = u128::from(self.send_bps)
            .saturating_mul(u128::from(DELIVERY_SCALE))
            .div_ceil(u128::from(ratio));
        u64::try_from(compensated)
            .unwrap_or(u64::MAX)
            .min(self.send_bps.saturating_mul(MAX_LOSS_COMPENSATION))
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: std::time::Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu))
    }
}

#[derive(Clone, Debug)]
struct Brutal {
    config: Arc<BrutalConfig>,
    current_mtu: u16,
    last_rtt: Duration,
    current_window: u64,
    effective_send_bps: u64,
    sent_bytes: u64,
    acknowledged_bytes: u64,
    lost_bytes: u64,
    delivery_ratio: Option<u64>,
}

impl Brutal {
    fn new(config: Arc<BrutalConfig>, current_mtu: u16) -> Self {
        let current_window = config.window_for_rtt(INITIAL_RTT, current_mtu);
        let effective_send_bps = config.send_bps();
        Self {
            config,
            current_mtu,
            last_rtt: INITIAL_RTT,
            current_window,
            effective_send_bps,
            sent_bytes: 0,
            acknowledged_bytes: 0,
            lost_bytes: 0,
            delivery_ratio: None,
        }
    }

    fn update_window(&mut self) {
        self.current_window =
            self.config
                .window_for_rate(self.effective_send_bps, self.last_rtt, self.current_mtu);
    }

    fn reset_delivery_estimator(&mut self) {
        self.acknowledged_bytes = 0;
        self.lost_bytes = 0;
        self.delivery_ratio = None;
        self.effective_send_bps = self.config.send_bps();
        self.update_window();
    }
}

impl Controller for Brutal {
    fn on_sent(&mut self, _now: std::time::Instant, bytes: u64, _last_packet_number: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes);
    }

    fn on_ack(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.acknowledged_bytes = self.acknowledged_bytes.saturating_add(bytes);
        self.last_rtt = rtt.get();
        self.update_window();
    }

    fn on_end_acks(
        &mut self,
        _now: std::time::Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        if self.acknowledged_bytes == 0 && self.lost_bytes == 0 {
            return;
        }
        let total = self.acknowledged_bytes.saturating_add(self.lost_bytes);
        let sample = self.acknowledged_bytes.saturating_mul(DELIVERY_SCALE) / total;
        let delivery_ratio = self
            .delivery_ratio
            .map(|previous| previous.saturating_mul(7).saturating_add(sample) / 8)
            .unwrap_or(sample);
        self.delivery_ratio = Some(delivery_ratio);
        self.effective_send_bps = self.config.compensated_rate_for_delivery(delivery_ratio);
        self.sent_bytes = 0;
        self.acknowledged_bytes = 0;
        self.lost_bytes = 0;
        self.update_window();
    }

    fn on_congestion_event(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if is_persistent_congestion {
            self.reset_delivery_estimator();
            return;
        }
        self.lost_bytes = self.lost_bytes.saturating_add(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu;
        self.update_window();
    }

    fn window(&self) -> u64 {
        self.current_window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.window_for_rtt(INITIAL_RTT, self.current_mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_tracks_rate_and_rtt() {
        let config = BrutalConfig::new(100_000_000, true).unwrap();
        assert_eq!(
            config.window_for_rtt(Duration::from_millis(50), 1200),
            500_000
        );
    }

    #[test]
    fn window_has_ten_datagram_floor_and_pacer_ceiling() {
        let slow = BrutalConfig::new(1, false).unwrap();
        assert_eq!(slow.window_for_rtt(Duration::from_micros(1), 1400), 14_000);

        let fast = BrutalConfig::new(u64::MAX, false).unwrap();
        assert_eq!(
            fast.window_for_rtt(Duration::from_secs(60), 1200),
            MAX_PACED_WINDOW
        );
    }

    #[test]
    fn inverse_delivery_compensation_is_bounded() {
        let config = BrutalConfig::new(100_000_000, true).unwrap();
        assert_eq!(config.compensated_rate_bps(75, 25), 133_333_334);
        assert_eq!(config.compensated_rate_bps(1, 99), 400_000_000);

        let disabled = BrutalConfig::new(100_000_000, false).unwrap();
        assert_eq!(disabled.compensated_rate_bps(1, 99), 100_000_000);
    }

    #[test]
    fn persistent_congestion_resets_to_base_rate() {
        let config = Arc::new(BrutalConfig::new(100_000_000, true).unwrap());
        let mut controller = Brutal::new(config, 1200);
        controller.effective_send_bps = 400_000_000;
        controller.acknowledged_bytes = 10;
        controller.lost_bytes = 90;
        controller.update_window();

        let now = std::time::Instant::now();
        controller.on_congestion_event(now, now, true, 1200);

        assert_eq!(controller.effective_send_bps, 100_000_000);
        assert_eq!(controller.acknowledged_bytes, 0);
        assert_eq!(controller.lost_bytes, 0);
        assert_eq!(controller.delivery_ratio, None);
        assert_eq!(
            controller.window(),
            controller.config.window_for_rtt(INITIAL_RTT, 1200)
        );
    }
}
