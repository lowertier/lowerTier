use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory},
};

use super::core::{
    AdaptiveConfig, AdaptiveCore, AdaptiveDecision, ConfigError, RoundSample, rate_to_cwnd,
};
use super::signals::AdaptiveSignals;

#[derive(Clone, Debug)]
pub struct AdaptiveFactory {
    config: AdaptiveConfig,
    signals: Arc<AdaptiveSignals>,
}

impl AdaptiveFactory {
    pub fn new(config: AdaptiveConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            signals: Arc::new(AdaptiveSignals::default()),
        })
    }

    pub fn with_signals(
        config: AdaptiveConfig,
        signals: Arc<AdaptiveSignals>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self { config, signals })
    }

    pub fn signals(&self) -> Arc<AdaptiveSignals> {
        self.signals.clone()
    }
}

impl ControllerFactory for AdaptiveFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let core = AdaptiveCore::new(self.config.clone(), current_mtu)
            .expect("AdaptiveFactory validates its configuration before use");
        Box::new(AdaptiveController::new(
            core,
            self.config.clone(),
            self.signals.clone(),
            current_mtu,
        ))
    }
}

#[derive(Clone, Debug, Default)]
struct RoundAccumulator {
    acked_bytes: u64,
    lost_bytes: u64,
    sent_bytes: u64,
    first_sent: Option<Instant>,
    last_sent: Option<Instant>,
    first_ack: Option<Instant>,
    last_ack: Option<Instant>,
    smoothed_rtt: Duration,
    min_rtt: Duration,
    conservative_rtt: Duration,
    ecn: bool,
    persistent_congestion: bool,
}

impl RoundAccumulator {
    fn record_sent(&mut self, now: Instant, bytes: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes);
        self.first_sent = Some(self.first_sent.map_or(now, |value| value.min(now)));
        self.last_sent = Some(self.last_sent.map_or(now, |value| value.max(now)));
    }

    fn record_ack(&mut self, now: Instant, sent: Instant, bytes: u64, rtt: &RttEstimator) {
        self.acked_bytes = self.acked_bytes.saturating_add(bytes);
        self.first_sent = Some(self.first_sent.map_or(sent, |value| value.min(sent)));
        self.last_sent = Some(self.last_sent.map_or(sent, |value| value.max(sent)));
        self.first_ack = Some(self.first_ack.map_or(now, |value| value.min(now)));
        self.last_ack = Some(self.last_ack.map_or(now, |value| value.max(now)));
        self.smoothed_rtt = rtt.get();
        self.min_rtt = rtt.min();
        self.conservative_rtt = rtt.conservative();
    }

    fn interval(&self) -> Duration {
        let send_span = self
            .first_sent
            .zip(self.last_sent)
            .map_or(Duration::ZERO, |(first, last)| {
                last.saturating_duration_since(first)
            });
        let ack_span = self
            .first_ack
            .zip(self.last_ack)
            .map_or(Duration::ZERO, |(first, last)| {
                last.saturating_duration_since(first)
            });
        send_span.max(ack_span).max(Duration::from_millis(1))
    }

    fn delivered_bps(&self) -> u64 {
        bytes_per_interval_to_bps(self.acked_bytes, self.interval())
    }

    fn sent_bps(&self) -> u64 {
        bytes_per_interval_to_bps(self.sent_bytes, self.interval())
    }
}

fn bytes_per_interval_to_bps(bytes: u64, interval: Duration) -> u64 {
    let bits = u128::from(bytes).saturating_mul(8);
    let bps = bits.saturating_mul(1_000_000_000) / interval.as_nanos().max(1);
    u64::try_from(bps).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug)]
pub struct AdaptiveController {
    core: AdaptiveCore,
    config: AdaptiveConfig,
    signals: Arc<AdaptiveSignals>,
    current_mtu: u16,
    current_window: u64,
    accumulator: RoundAccumulator,
    last_sent_packet: u64,
    round_end_packet: u64,
    last_reliable_drop_count: u64,
    last_decision: Option<AdaptiveDecision>,
}

impl AdaptiveController {
    fn new(
        core: AdaptiveCore,
        config: AdaptiveConfig,
        signals: Arc<AdaptiveSignals>,
        current_mtu: u16,
    ) -> Self {
        let current_mtu = current_mtu.max(1200);
        let current_window = rate_to_cwnd(
            core.pacing_bps(),
            Duration::from_millis(333),
            current_mtu,
            config.max_cwnd_bytes,
        );
        Self {
            core,
            config,
            signals,
            current_mtu,
            current_window,
            accumulator: RoundAccumulator::default(),
            last_sent_packet: 0,
            round_end_packet: 0,
            last_reliable_drop_count: 0,
            last_decision: None,
        }
    }

    pub fn pacing_bps(&self) -> u64 {
        self.core.pacing_bps()
    }

    pub fn last_decision(&self) -> Option<AdaptiveDecision> {
        self.last_decision
    }

    pub fn signals(&self) -> Arc<AdaptiveSignals> {
        self.signals.clone()
    }

    fn finish_round(&mut self, in_flight: u64, app_limited: bool) {
        let signals = self.signals.snapshot();
        let local_reliable_drop = signals.local_reliable_drops != self.last_reliable_drop_count;
        self.last_reliable_drop_count = signals.local_reliable_drops;

        let sent_bps = self.accumulator.sent_bps();
        let delivered_bps = if sent_bps == 0 {
            self.accumulator.delivered_bps()
        } else {
            self.accumulator
                .delivered_bps()
                .min(sent_bps.saturating_mul(125) / 100)
        };
        let sample = RoundSample {
            delivered_bps,
            sent_bps,
            acked_bytes: self.accumulator.acked_bytes,
            lost_bytes: self.accumulator.lost_bytes,
            inflight_bytes: in_flight,
            smoothed_rtt: self.accumulator.smoothed_rtt.max(Duration::from_millis(1)),
            min_rtt: self.accumulator.min_rtt.max(Duration::from_millis(1)),
            conservative_rtt: self
                .accumulator
                .conservative_rtt
                .max(Duration::from_millis(1)),
            app_limited,
            ecn: self.accumulator.ecn,
            persistent_congestion: self.accumulator.persistent_congestion,
            local_reliable_drop,
            local_queue_sojourn: signals.queue_sojourn,
            path_epoch: signals.path_epoch,
        };
        let decision = self.core.on_round(sample);
        self.current_window = decision.cwnd_bytes;
        self.last_decision = Some(decision);
        self.accumulator = RoundAccumulator::default();
    }
}

impl Controller for AdaptiveController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.last_sent_packet = last_packet_number;
        if self.last_decision.is_none() || self.round_end_packet == 0 {
            // Before the first acknowledgement, keep extending the initial
            // round to the latest packet already emitted.
            self.round_end_packet = last_packet_number;
        }
        self.accumulator.record_sent(now, bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.accumulator.record_ack(now, sent, bytes, rtt);
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let round_complete =
            largest_packet_num_acked.is_some_and(|packet| packet >= self.round_end_packet);
        if !round_complete || self.accumulator.acked_bytes == 0 {
            return;
        }
        self.finish_round(in_flight, app_limited);
        self.round_end_packet = self.last_sent_packet;
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.accumulator.lost_bytes = self.accumulator.lost_bytes.saturating_add(lost_bytes);
        self.accumulator.ecn |= lost_bytes == 0;
        self.accumulator.persistent_congestion |= is_persistent_congestion;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu.max(1200);
        self.core.on_mtu_update(self.current_mtu);
        let rtt = self
            .accumulator
            .smoothed_rtt
            .max(Duration::from_millis(333));
        self.current_window = rate_to_cwnd(
            self.core.pacing_bps(),
            rtt,
            self.current_mtu,
            self.config.max_cwnd_bytes,
        );
    }

    fn window(&self) -> u64 {
        self.current_window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        u64::from(self.current_mtu).saturating_mul(10)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Retrieve the lock-free EasyTier signal channel from a live Quinn connection
/// using this controller. Returns `None` for BBR, CUBIC, or another controller.
pub fn signals_from_connection(connection: &quinn::Connection) -> Option<Arc<AdaptiveSignals>> {
    connection
        .congestion_state()
        .into_any()
        .downcast::<AdaptiveController>()
        .ok()
        .map(|controller| controller.signals())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_builds_a_bounded_controller() {
        let factory = Arc::new(
            AdaptiveFactory::new(AdaptiveConfig {
                initial_rate_bps: 10_000_000,
                max_rate_bps: 1_000_000_000,
                max_cwnd_bytes: 64 * 1024 * 1024,
                ..AdaptiveConfig::default()
            })
            .unwrap(),
        );

        let controller = factory.build(Instant::now(), 1200);
        assert_eq!(controller.initial_window(), 12_000);
        assert!(controller.window() >= 12_000);
        assert!(controller.window() <= 64 * 1024 * 1024);
    }

    #[test]
    fn bytes_per_interval_uses_wide_arithmetic() {
        assert_eq!(
            bytes_per_interval_to_bps(125_000_000, Duration::from_secs(1)),
            1_000_000_000
        );
        assert_eq!(
            bytes_per_interval_to_bps(u64::MAX, Duration::from_nanos(1)),
            u64::MAX
        );
    }
}
