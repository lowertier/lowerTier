use std::fmt;
use std::time::Duration;

const BANDWIDTH_FILTER_ROUNDS: usize = 10;
const LOSS_FLOOR_SAMPLES: usize = 3;
const LOSS_SCALE_PPM: u64 = 1_000_000;
const EXCESS_LOSS_MARGIN_PPM: u32 = 5_000;
const GAIN_SCALE: u64 = 10_000;

const DRAIN_GAIN: u64 = 7_000;
const CRUISE_GAIN: u64 = 9_000;
const PROBE_UP_GAIN: u64 = 11_000;
const PROBE_DOWN_GAIN: u64 = 8_500;
const REPROBE_GAIN: u64 = 12_500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveMode {
    Startup,
    Drain,
    Cruise,
    ProbeUp,
    Reprobe,
    ProbeDown,
    Recovery,
}

#[derive(Clone, Debug)]
pub struct AdaptiveConfig {
    /// Lower bound used after severe congestion or path restart.
    pub min_rate_bps: u64,
    /// Initial encoded-wire pacing estimate.
    pub initial_rate_bps: u64,
    /// Hard operator safety ceiling. This is encoded wire rate.
    pub max_rate_bps: u64,
    /// Optional encoded-wire rate sufficient for the application's goodput goal.
    /// Capacity probing stops after this rate is demonstrated.
    pub target_wire_bps: Option<u64>,
    /// Per-connection congestion-window memory bound.
    pub max_cwnd_bytes: u64,
    /// Seed used only to desynchronise capacity probes.
    pub probe_seed: u64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            min_rate_bps: 128_000,
            initial_rate_bps: 1_000_000,
            max_rate_bps: 1_000_000_000,
            target_wire_bps: None,
            max_cwnd_bytes: 128 * 1024 * 1024,
            probe_seed: 0x9e37_79b9_7f4a_7c15,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    ZeroRate,
    InvalidRateOrder,
    TargetExceedsMaximum,
    CongestionWindowTooSmall,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRate => write!(f, "adaptive rates must be greater than zero"),
            Self::InvalidRateOrder => {
                write!(f, "adaptive rates must satisfy min <= initial <= max")
            }
            Self::TargetExceedsMaximum => {
                write!(f, "target wire rate exceeds the maximum wire rate")
            }
            Self::CongestionWindowTooSmall => {
                write!(
                    f,
                    "maximum congestion window is below ten 1200-byte packets"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl AdaptiveConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.min_rate_bps == 0 || self.initial_rate_bps == 0 || self.max_rate_bps == 0 {
            return Err(ConfigError::ZeroRate);
        }
        if self.min_rate_bps > self.initial_rate_bps || self.initial_rate_bps > self.max_rate_bps {
            return Err(ConfigError::InvalidRateOrder);
        }
        if self
            .target_wire_bps
            .is_some_and(|target| target == 0 || target > self.max_rate_bps)
        {
            return Err(ConfigError::TargetExceedsMaximum);
        }
        if self.max_cwnd_bytes < 12_000 {
            return Err(ConfigError::CongestionWindowTooSmall);
        }
        Ok(())
    }

    fn rate_cap(&self) -> u64 {
        self.target_wire_bps
            .unwrap_or(self.max_rate_bps)
            .min(self.max_rate_bps)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RoundSample {
    pub delivered_bps: u64,
    pub sent_bps: u64,
    pub acked_bytes: u64,
    pub lost_bytes: u64,
    pub inflight_bytes: u64,
    pub smoothed_rtt: Duration,
    pub min_rtt: Duration,
    pub conservative_rtt: Duration,
    pub app_limited: bool,
    pub ecn: bool,
    pub persistent_congestion: bool,
    pub local_reliable_drop: bool,
    pub local_queue_sojourn: Duration,
    pub path_epoch: u64,
}

impl RoundSample {
    pub fn loss_ppm(&self) -> u32 {
        let total = self.acked_bytes.saturating_add(self.lost_bytes);
        if total == 0 {
            return 0;
        }
        let ppm = u128::from(self.lost_bytes).saturating_mul(u128::from(LOSS_SCALE_PPM))
            / u128::from(total);
        u32::try_from(ppm).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveDecision {
    pub mode: AdaptiveMode,
    pub pacing_bps: u64,
    pub cwnd_bytes: u64,
    pub bandwidth_estimate_bps: u64,
    pub short_bandwidth_bps: u64,
    pub loss_floor_ppm: Option<u32>,
    pub queue_guard: Duration,
}

#[derive(Clone, Debug)]
struct BandwidthModel {
    samples: [u64; BANDWIDTH_FILTER_ROUNDS],
    sample_count: usize,
    next_sample: usize,
    long_bps: u64,
    short_bps: u64,
    full_bw_bps: u64,
    plateau_rounds: u8,
}

impl BandwidthModel {
    fn new(initial_bps: u64) -> Self {
        Self {
            samples: [0; BANDWIDTH_FILTER_ROUNDS],
            sample_count: 0,
            next_sample: 0,
            long_bps: initial_bps,
            short_bps: initial_bps,
            full_bw_bps: 0,
            plateau_rounds: 0,
        }
    }

    fn observe(&mut self, delivered_bps: u64, app_limited: bool) {
        if delivered_bps == 0 {
            return;
        }

        if !app_limited || delivered_bps > self.short_bps {
            self.short_bps = if self.short_bps == 0 {
                delivered_bps
            } else {
                self.short_bps
                    .saturating_mul(3)
                    .saturating_add(delivered_bps)
                    / 4
            };
        }

        if !app_limited || delivered_bps > self.long_bps {
            self.samples[self.next_sample] = delivered_bps;
            self.next_sample = (self.next_sample + 1) % BANDWIDTH_FILTER_ROUNDS;
            self.sample_count = (self.sample_count + 1).min(BANDWIDTH_FILTER_ROUNDS);
            self.long_bps = self.samples[..self.sample_count]
                .iter()
                .copied()
                .max()
                .unwrap_or(delivered_bps);
        }
    }

    fn startup_plateau(&mut self, delivered_bps: u64, app_limited: bool) -> bool {
        if delivered_bps == 0 || app_limited {
            return false;
        }

        if self.full_bw_bps == 0
            || delivered_bps >= self.full_bw_bps.saturating_mul(120).saturating_div(100)
        {
            self.full_bw_bps = delivered_bps;
            self.plateau_rounds = 0;
        } else {
            self.plateau_rounds = self.plateau_rounds.saturating_add(1);
        }
        self.plateau_rounds >= 3
    }

    fn reset_to(&mut self, bps: u64) {
        *self = Self::new(bps.max(1));
    }
}

#[derive(Clone, Debug)]
struct LossModel {
    floor_ppm: u32,
    initialised: bool,
    initial_samples: [u32; LOSS_FLOOR_SAMPLES],
    initial_count: usize,
}

impl LossModel {
    fn new() -> Self {
        Self {
            floor_ppm: 0,
            initialised: false,
            initial_samples: [0; LOSS_FLOOR_SAMPLES],
            initial_count: 0,
        }
    }

    fn observe_healthy(&mut self, loss_ppm: u32) {
        if !self.initialised {
            self.initial_samples[self.initial_count] = loss_ppm;
            self.initial_count += 1;
            if self.initial_count == LOSS_FLOOR_SAMPLES {
                self.initial_samples.sort_unstable();
                self.floor_ppm = self.initial_samples[LOSS_FLOOR_SAMPLES / 2];
                self.initialised = true;
            }
            return;
        }

        self.floor_ppm = if loss_ppm < self.floor_ppm {
            self.floor_ppm.saturating_add(loss_ppm.saturating_mul(3)) / 4
        } else {
            self.floor_ppm.saturating_mul(63).saturating_add(loss_ppm) / 64
        };
    }

    fn has_excess_loss(&self, loss_ppm: u32) -> bool {
        self.initialised && loss_ppm > self.floor_ppm.saturating_add(EXCESS_LOSS_MARGIN_PPM)
    }

    fn value(&self) -> Option<u32> {
        self.initialised.then_some(self.floor_ppm)
    }
}

#[derive(Clone, Debug)]
struct LatencyModel {
    jitter: Duration,
}

impl LatencyModel {
    fn new() -> Self {
        Self {
            jitter: Duration::ZERO,
        }
    }

    fn observe(&mut self, sample: &RoundSample) {
        let jitter_sample = sample.conservative_rtt.abs_diff(sample.smoothed_rtt);
        self.jitter = duration_weighted_average(self.jitter, 7, jitter_sample, 1, 8);
    }

    fn queue_guard(&self, min_rtt: Duration) -> Duration {
        let five_percent = min_rtt / 20;
        let four_jitter = self.jitter.saturating_mul(4);
        Duration::from_millis(10)
            .max(five_percent)
            .max(four_jitter)
            .clamp(Duration::from_millis(10), Duration::from_millis(80))
    }

    fn queue_delay(sample: &RoundSample) -> Duration {
        sample.conservative_rtt.saturating_sub(sample.min_rtt)
    }
}

fn duration_weighted_average(
    left: Duration,
    left_weight: u32,
    right: Duration,
    right_weight: u32,
    divisor: u32,
) -> Duration {
    let nanos = left
        .as_nanos()
        .saturating_mul(u128::from(left_weight))
        .saturating_add(right.as_nanos().saturating_mul(u128::from(right_weight)))
        / u128::from(divisor);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[derive(Clone, Debug)]
pub struct AdaptiveCore {
    config: AdaptiveConfig,
    mode: AdaptiveMode,
    pacing_bps: u64,
    current_mtu: u16,
    bandwidth: BandwidthModel,
    latency: LatencyModel,
    loss: LossModel,
    path_epoch: Option<u64>,
    rounds_in_mode: u8,
    pressure_rounds: u8,
    capacity_drop_rounds: u8,
    clean_recovery_rounds: u8,
    rounds_since_probe: u8,
    next_probe_rounds: u8,
    probe_baseline_bps: u64,
    previous_delivered_bps: u64,
    target_confirmed: bool,
    rng_state: u64,
}

impl AdaptiveCore {
    pub fn new(config: AdaptiveConfig, current_mtu: u16) -> Result<Self, ConfigError> {
        config.validate()?;
        let current_mtu = current_mtu.max(1200);
        let initial_rate = config
            .initial_rate_bps
            .clamp(config.min_rate_bps, config.rate_cap());
        let seed = if config.probe_seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            config.probe_seed
        };
        let mut core = Self {
            config,
            mode: AdaptiveMode::Startup,
            pacing_bps: initial_rate,
            current_mtu,
            bandwidth: BandwidthModel::new(initial_rate),
            latency: LatencyModel::new(),
            loss: LossModel::new(),
            path_epoch: None,
            rounds_in_mode: 0,
            pressure_rounds: 0,
            capacity_drop_rounds: 0,
            clean_recovery_rounds: 0,
            rounds_since_probe: 0,
            next_probe_rounds: 10,
            probe_baseline_bps: 0,
            previous_delivered_bps: 0,
            target_confirmed: false,
            rng_state: seed,
        };
        core.next_probe_rounds = core.draw_probe_rounds();
        Ok(core)
    }

    pub fn mode(&self) -> AdaptiveMode {
        self.mode
    }

    pub fn pacing_bps(&self) -> u64 {
        self.pacing_bps
    }

    pub fn bandwidth_estimate_bps(&self) -> u64 {
        self.bandwidth.long_bps
    }

    pub fn short_bandwidth_bps(&self) -> u64 {
        self.bandwidth.short_bps
    }

    pub fn loss_floor_ppm(&self) -> Option<u32> {
        self.loss.value()
    }

    pub fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu.max(1200);
    }

    pub fn on_round(&mut self, sample: RoundSample) -> AdaptiveDecision {
        if self.path_epoch != Some(sample.path_epoch) {
            self.reset_path(sample.path_epoch);
        }

        let previous_long = self.bandwidth.long_bps;
        self.bandwidth
            .observe(sample.delivered_bps, sample.app_limited);
        self.latency.observe(&sample);

        let guard = self.latency.queue_guard(sample.min_rtt);
        let queue_delay = LatencyModel::queue_delay(&sample);
        let queue_soft = queue_delay > guard;
        let queue_hard = queue_delay > guard.saturating_mul(2)
            || sample.local_queue_sojourn > Duration::from_millis(50);
        let loss_ppm = sample.loss_ppm();
        let delivery_growth = percent_growth(sample.delivered_bps, self.previous_delivered_bps);

        // During Startup, learn a medium-loss floor only while delivered rate
        // is still growing. This prevents a queue-less policer from teaching
        // its congestion drops to the non-congestive loss model.
        let loss_floor_learning_allowed =
            self.mode != AdaptiveMode::Startup || delivery_growth >= 5;
        let healthy_for_loss_floor = loss_floor_learning_allowed
            && !queue_soft
            && !sample.ecn
            && !sample.persistent_congestion
            && !sample.local_reliable_drop
            && sample.delivered_bps > 0;
        if healthy_for_loss_floor {
            self.loss.observe_healthy(loss_ppm);
        }
        let excess_loss = self.loss.has_excess_loss(loss_ppm);

        if self.target_demonstrated(sample.delivered_bps) {
            self.target_confirmed = true;
        }

        let hard_pressure =
            sample.ecn || sample.persistent_congestion || sample.local_reliable_drop || queue_hard;
        let soft_pressure = (queue_soft || excess_loss) && delivery_growth < 5;

        self.pressure_rounds = if soft_pressure {
            self.pressure_rounds.saturating_add(1)
        } else {
            0
        };

        if hard_pressure {
            self.enter_recovery();
        } else {
            self.observe_capacity_drop(&sample, queue_soft || excess_loss);
            self.advance_mode(&sample, previous_long);
        }

        self.previous_delivered_bps = sample.delivered_bps;
        self.rounds_in_mode = self.rounds_in_mode.saturating_add(1);

        AdaptiveDecision {
            mode: self.mode,
            pacing_bps: self.pacing_bps,
            cwnd_bytes: rate_to_cwnd(
                self.pacing_bps,
                sample.smoothed_rtt,
                self.current_mtu,
                self.config.max_cwnd_bytes,
            ),
            bandwidth_estimate_bps: self.bandwidth.long_bps,
            short_bandwidth_bps: self.bandwidth.short_bps,
            loss_floor_ppm: self.loss.value(),
            queue_guard: guard,
        }
    }

    fn observe_capacity_drop(&mut self, sample: &RoundSample, pressure: bool) {
        let short_is_low = self.bandwidth.short_bps.saturating_mul(100)
            < self.bandwidth.long_bps.saturating_mul(80);
        if !sample.app_limited && pressure && short_is_low {
            self.capacity_drop_rounds = self.capacity_drop_rounds.saturating_add(1);
        } else {
            self.capacity_drop_rounds = 0;
        }

        if self.capacity_drop_rounds >= 2 {
            let reduced = self
                .bandwidth
                .short_bps
                .max(self.bandwidth.long_bps / 2)
                .max(self.config.min_rate_bps);
            self.bandwidth.reset_to(reduced);
            self.target_confirmed = false;
            self.enter_mode(AdaptiveMode::Drain);
            self.pacing_bps = apply_gain(reduced, DRAIN_GAIN)
                .clamp(self.config.min_rate_bps, self.config.rate_cap());
            self.capacity_drop_rounds = 0;
        }
    }

    fn advance_mode(&mut self, sample: &RoundSample, previous_long: u64) {
        match self.mode {
            AdaptiveMode::Startup => {
                let plateau = self
                    .bandwidth
                    .startup_plateau(sample.delivered_bps, sample.app_limited);
                let target_reached = self.target_demonstrated(sample.delivered_bps);
                if plateau || self.pressure_rounds >= 2 || target_reached {
                    self.enter_mode(AdaptiveMode::Drain);
                    self.pacing_bps = apply_gain(
                        self.bandwidth.long_bps.max(self.config.min_rate_bps),
                        DRAIN_GAIN,
                    )
                    .clamp(self.config.min_rate_bps, self.config.rate_cap());
                } else {
                    self.pacing_bps = self
                        .pacing_bps
                        .saturating_mul(2)
                        .clamp(self.config.min_rate_bps, self.config.rate_cap());
                }
            }
            AdaptiveMode::Drain => {
                let bdp = bdp_bytes(self.bandwidth.long_bps, sample.min_rtt);
                self.pacing_bps = apply_gain(
                    self.bandwidth.long_bps.max(self.config.min_rate_bps),
                    DRAIN_GAIN,
                )
                .clamp(self.config.min_rate_bps, self.config.rate_cap());

                if sample.inflight_bytes <= bdp.saturating_mul(105) / 100
                    || self.rounds_in_mode >= 1
                {
                    self.enter_mode(AdaptiveMode::Cruise);
                    self.set_cruise_rate();
                }
            }
            AdaptiveMode::Cruise => {
                self.set_cruise_rate();
                self.rounds_since_probe = self.rounds_since_probe.saturating_add(1);
                if self.rounds_since_probe >= self.next_probe_rounds
                    && !self.target_demonstrated(sample.delivered_bps)
                {
                    self.probe_baseline_bps = self.bandwidth.long_bps;
                    self.enter_mode(AdaptiveMode::ProbeUp);
                    self.pacing_bps = apply_gain(
                        self.bandwidth.long_bps.max(self.config.min_rate_bps),
                        PROBE_UP_GAIN,
                    )
                    .clamp(self.config.min_rate_bps, self.config.rate_cap());
                }
            }
            AdaptiveMode::ProbeUp => {
                let growth = percent_growth(sample.delivered_bps, self.probe_baseline_bps);
                if growth >= 8 && self.pressure_rounds == 0 {
                    self.enter_mode(AdaptiveMode::Reprobe);
                    self.pacing_bps = apply_gain(self.pacing_bps, REPROBE_GAIN)
                        .clamp(self.config.min_rate_bps, self.config.rate_cap());
                } else {
                    self.enter_mode(AdaptiveMode::ProbeDown);
                    self.pacing_bps = apply_gain(
                        self.bandwidth.long_bps.max(self.config.min_rate_bps),
                        PROBE_DOWN_GAIN,
                    )
                    .clamp(self.config.min_rate_bps, self.config.rate_cap());
                }
            }
            AdaptiveMode::Reprobe => {
                let growth = percent_growth(sample.delivered_bps, previous_long);
                if growth >= 5
                    && self.pressure_rounds == 0
                    && self.rounds_in_mode < 3
                    && !self.target_demonstrated(sample.delivered_bps)
                {
                    self.pacing_bps = apply_gain(self.pacing_bps, REPROBE_GAIN)
                        .clamp(self.config.min_rate_bps, self.config.rate_cap());
                } else {
                    self.enter_mode(AdaptiveMode::ProbeDown);
                    self.pacing_bps = apply_gain(
                        self.bandwidth.long_bps.max(self.config.min_rate_bps),
                        PROBE_DOWN_GAIN,
                    )
                    .clamp(self.config.min_rate_bps, self.config.rate_cap());
                }
            }
            AdaptiveMode::ProbeDown => {
                self.enter_mode(AdaptiveMode::Cruise);
                self.set_cruise_rate();
            }
            AdaptiveMode::Recovery => {
                let clean = !sample.ecn
                    && !sample.persistent_congestion
                    && !sample.local_reliable_drop
                    && self.pressure_rounds == 0;
                self.clean_recovery_rounds = if clean {
                    self.clean_recovery_rounds.saturating_add(1)
                } else {
                    0
                };
                if self.clean_recovery_rounds >= 2 {
                    self.enter_mode(AdaptiveMode::Drain);
                    self.pacing_bps = apply_gain(
                        self.bandwidth.short_bps.max(self.config.min_rate_bps),
                        DRAIN_GAIN,
                    )
                    .clamp(self.config.min_rate_bps, self.config.rate_cap());
                }
            }
        }
    }

    fn enter_recovery(&mut self) {
        let reduced = self
            .pacing_bps
            .saturating_mul(75)
            .saturating_div(100)
            .min(
                self.bandwidth
                    .short_bps
                    .saturating_mul(90)
                    .saturating_div(100),
            )
            .max(self.config.min_rate_bps);
        self.target_confirmed = false;
        self.enter_mode(AdaptiveMode::Recovery);
        self.pacing_bps = reduced.min(self.config.rate_cap());
        self.clean_recovery_rounds = 0;
    }

    fn set_cruise_rate(&mut self) {
        let headroom_rate = apply_gain(
            self.bandwidth.long_bps.max(self.config.min_rate_bps),
            CRUISE_GAIN,
        );
        let target_floor = if self.target_confirmed {
            self.config.target_wire_bps.unwrap_or(0)
        } else {
            0
        };
        self.pacing_bps = headroom_rate
            .max(target_floor)
            .clamp(self.config.min_rate_bps, self.config.rate_cap());
    }

    fn target_demonstrated(&self, delivered_bps: u64) -> bool {
        self.config
            .target_wire_bps
            .is_some_and(|target| delivered_bps >= target.saturating_mul(95) / 100)
    }

    fn enter_mode(&mut self, mode: AdaptiveMode) {
        self.mode = mode;
        self.rounds_in_mode = 0;
        if mode == AdaptiveMode::Cruise {
            self.rounds_since_probe = 0;
            self.next_probe_rounds = self.draw_probe_rounds();
        }
    }

    fn reset_path(&mut self, epoch: u64) {
        self.path_epoch = Some(epoch);
        self.mode = AdaptiveMode::Startup;
        self.pacing_bps = self
            .config
            .initial_rate_bps
            .clamp(self.config.min_rate_bps, self.config.rate_cap());
        self.bandwidth = BandwidthModel::new(self.pacing_bps);
        self.latency = LatencyModel::new();
        self.loss = LossModel::new();
        self.rounds_in_mode = 0;
        self.pressure_rounds = 0;
        self.capacity_drop_rounds = 0;
        self.clean_recovery_rounds = 0;
        self.rounds_since_probe = 0;
        self.next_probe_rounds = self.draw_probe_rounds();
        self.probe_baseline_bps = 0;
        self.previous_delivered_bps = 0;
        self.target_confirmed = false;
    }

    fn draw_probe_rounds(&mut self) -> u8 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        8 + u8::try_from(x % 5).expect("x modulo 5 fits in u8")
    }
}

fn apply_gain(rate_bps: u64, gain: u64) -> u64 {
    let scaled = u128::from(rate_bps).saturating_mul(u128::from(gain)) / u128::from(GAIN_SCALE);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

fn percent_growth(current: u64, baseline: u64) -> u64 {
    if baseline == 0 {
        return u64::MAX;
    }
    if current <= baseline {
        return 0;
    }
    current.saturating_sub(baseline).saturating_mul(100) / baseline
}

pub fn bdp_bytes(rate_bps: u64, rtt: Duration) -> u64 {
    let bytes = u128::from(rate_bps).saturating_mul(rtt.as_nanos()) / 8_000_000_000_u128;
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Convert a pacing target into Quinn's congestion window.
///
/// Quinn's userspace pacer emits approximately 1.25 windows per RTT. The 4/5
/// factor mirrors LowTier's existing fixed-rate controller and keeps the
/// requested encoded-wire rate close to the resulting paced rate.
pub fn rate_to_cwnd(rate_bps: u64, rtt: Duration, mtu: u16, max_cwnd_bytes: u64) -> u64 {
    let window = u128::from(rate_bps)
        .saturating_mul(rtt.as_nanos())
        .saturating_mul(4)
        / (8_000_000_000_u128 * 5);
    let minimum = u64::from(mtu.max(1200)).saturating_mul(10);
    u64::try_from(window)
        .unwrap_or(u64::MAX)
        .clamp(minimum, max_cwnd_bytes.max(minimum))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(delivered_bps: u64, sent_bps: u64, loss_ppm: u32, rtt_ms: u64) -> RoundSample {
        let total = 100_000_000_u64;
        let lost = total.saturating_mul(u64::from(loss_ppm)) / LOSS_SCALE_PPM;
        RoundSample {
            delivered_bps,
            sent_bps,
            acked_bytes: total.saturating_sub(lost),
            lost_bytes: lost,
            inflight_bytes: bdp_bytes(sent_bps, Duration::from_millis(rtt_ms)),
            smoothed_rtt: Duration::from_millis(rtt_ms),
            min_rtt: Duration::from_millis(rtt_ms),
            conservative_rtt: Duration::from_millis(rtt_ms),
            app_limited: false,
            ecn: false,
            persistent_congestion: false,
            local_reliable_drop: false,
            local_queue_sojourn: Duration::ZERO,
            path_epoch: 1,
        }
    }

    #[test]
    fn configuration_validation_rejects_inconsistent_limits() {
        let config = AdaptiveConfig {
            min_rate_bps: 2,
            initial_rate_bps: 1,
            max_rate_bps: 3,
            ..AdaptiveConfig::default()
        };
        assert_eq!(config.validate(), Err(ConfigError::InvalidRateOrder));
    }

    #[test]
    fn rate_to_window_is_bounded_and_uses_wide_arithmetic() {
        assert_eq!(
            rate_to_cwnd(1, Duration::from_micros(1), 1200, 128 * 1024 * 1024),
            12_000
        );
        assert_eq!(
            rate_to_cwnd(u64::MAX, Duration::from_secs(60), 1500, 128 * 1024 * 1024),
            128 * 1024 * 1024
        );
    }

    #[test]
    fn stable_three_percent_loss_does_not_trigger_recovery() {
        let mut core = AdaptiveCore::new(
            AdaptiveConfig {
                initial_rate_bps: 10_000_000,
                max_rate_bps: 1_000_000_000,
                target_wire_bps: Some(750_000_000),
                ..AdaptiveConfig::default()
            },
            1200,
        )
        .unwrap();

        let rates = [
            9_700_000,
            19_400_000,
            38_800_000,
            77_600_000,
            155_200_000,
            310_400_000,
            620_800_000,
            735_000_000,
        ];
        for delivered in rates {
            let decision = core.on_round(sample(
                delivered,
                delivered.saturating_mul(103) / 100,
                30_000,
                150,
            ));
            assert_ne!(decision.mode, AdaptiveMode::Recovery);
        }

        // One Drain round removes the Startup probe queue, then the confirmed
        // target becomes the Cruise floor.
        let decision = core.on_round(sample(735_000_000, 750_000_000, 30_000, 150));
        assert_ne!(decision.mode, AdaptiveMode::Recovery);
        assert!(core.pacing_bps() >= 700_000_000);
        assert!(core.loss_floor_ppm().is_some());
    }

    #[test]
    fn ecn_and_local_drop_enter_recovery() {
        let mut core = AdaptiveCore::new(AdaptiveConfig::default(), 1200).unwrap();
        let mut first = sample(10_000_000, 11_000_000, 30_000, 100);
        first.ecn = true;
        assert_eq!(core.on_round(first).mode, AdaptiveMode::Recovery);

        let mut core = AdaptiveCore::new(AdaptiveConfig::default(), 1200).unwrap();
        let mut second = sample(10_000_000, 11_000_000, 30_000, 100);
        second.local_reliable_drop = true;
        assert_eq!(core.on_round(second).mode, AdaptiveMode::Recovery);
    }

    #[test]
    fn path_epoch_resets_capacity_model() {
        let mut core = AdaptiveCore::new(
            AdaptiveConfig {
                initial_rate_bps: 5_000_000,
                max_rate_bps: 1_000_000_000,
                ..AdaptiveConfig::default()
            },
            1200,
        )
        .unwrap();

        for delivered in [5_000_000, 10_000_000, 20_000_000, 40_000_000] {
            core.on_round(sample(delivered, delivered, 0, 100));
        }
        assert!(core.bandwidth_estimate_bps() >= 40_000_000);

        let mut changed = sample(1_000_000, 1_000_000, 0, 200);
        changed.path_epoch = 2;
        core.on_round(changed);
        assert!(core.bandwidth_estimate_bps() <= 5_000_000);
        assert_eq!(core.mode(), AdaptiveMode::Startup);
    }
}
