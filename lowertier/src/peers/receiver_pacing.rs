use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};

use crate::{
    common::PeerId,
    tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    },
};

pub(crate) const RECEIVER_PACING_FEATURE: &str = "receiver-pacing-v1";
pub(crate) const RECEIVER_PRESSURE_REPORT_INTERVAL: Duration = Duration::from_millis(100);

const REPORT_VERSION: u8 = 1;
const REPORT_WIRE_SIZE: usize = 40;
const PRESSURE_OCCUPANCY_NUMERATOR: u64 = 1;
const PRESSURE_OCCUPANCY_DENOMINATOR: u64 = 4;
const PRESSURE_STALL_NS: u64 = 1_000_000;
const ACTIVATE_AFTER_REPORTS: u8 = 2;
const CLEAR_AFTER_REPORTS: u8 = 3;
const TARGET_HEADROOM_NUMERATOR: u64 = 95;
const TARGET_HEADROOM_DENOMINATOR: u64 = 100;
const MIN_TARGET_BYTES_PER_SECOND: u64 = 1024 * 1024;
const MAX_TARGET_BYTES_PER_SECOND: u64 = 100 * 1024 * 1024 * 1024;
const TOKEN_BURST_BYTES: u64 = 256 * 1024;
const REPORT_STALE_AFTER: Duration = Duration::from_secs(2);
const MAX_PACING_SLEEP: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReceiverPressureReport {
    pub(crate) sample_micros: u64,
    pub(crate) delivered_bytes: u64,
    pub(crate) occupancy_packets: u32,
    pub(crate) capacity_packets: u32,
    pub(crate) stall_ns: u64,
}

impl ReceiverPressureReport {
    pub(crate) fn encode(self) -> [u8; REPORT_WIRE_SIZE] {
        let mut output = [0_u8; REPORT_WIRE_SIZE];
        output[0] = REPORT_VERSION;
        output[8..16].copy_from_slice(&self.sample_micros.to_be_bytes());
        output[16..24].copy_from_slice(&self.delivered_bytes.to_be_bytes());
        output[24..28].copy_from_slice(&self.occupancy_packets.to_be_bytes());
        output[28..32].copy_from_slice(&self.capacity_packets.to_be_bytes());
        output[32..40].copy_from_slice(&self.stall_ns.to_be_bytes());
        output
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, &'static str> {
        if input.len() != REPORT_WIRE_SIZE {
            return Err("receiver-pressure report has an invalid length");
        }
        if input[0] != REPORT_VERSION || input[1..8].iter().any(|byte| *byte != 0) {
            return Err("receiver-pressure report has an unsupported version");
        }
        let report = Self {
            sample_micros: u64::from_be_bytes(input[8..16].try_into().unwrap()),
            delivered_bytes: u64::from_be_bytes(input[16..24].try_into().unwrap()),
            occupancy_packets: u32::from_be_bytes(input[24..28].try_into().unwrap()),
            capacity_packets: u32::from_be_bytes(input[28..32].try_into().unwrap()),
            stall_ns: u64::from_be_bytes(input[32..40].try_into().unwrap()),
        };
        if report.capacity_packets == 0
            || u64::from(report.occupancy_packets)
                > u64::from(report.capacity_packets).saturating_mul(4)
        {
            return Err("receiver-pressure report has an invalid queue shape");
        }
        Ok(report)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacerUpdate {
    pub(crate) active: bool,
    pub(crate) active_changed: bool,
    pub(crate) pressured: bool,
    pub(crate) service_bytes_per_second: u64,
    pub(crate) target_bytes_per_second: u64,
}

struct PacerState {
    previous_report: Option<ReceiverPressureReport>,
    last_report_received: Option<Instant>,
    smoothed_service_bytes_per_second: u64,
    target_bytes_per_second: u64,
    pressure_streak: u8,
    clear_streak: u8,
    active: bool,
    tokens: u64,
    last_refill: Instant,
}

impl PacerState {
    fn new(now: Instant) -> Self {
        Self {
            previous_report: None,
            last_report_received: None,
            smoothed_service_bytes_per_second: 0,
            target_bytes_per_second: 0,
            pressure_streak: 0,
            clear_streak: 0,
            active: false,
            tokens: TOKEN_BURST_BYTES,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant, capacity: u64) {
        if self.target_bytes_per_second == 0 {
            self.last_refill = now;
            return;
        }
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        let added = u128::from(self.target_bytes_per_second).saturating_mul(elapsed_ns)
            / 1_000_000_000_u128;
        self.tokens = self
            .tokens
            .saturating_add(added.min(u128::from(u64::MAX)) as u64)
            .min(capacity);
        self.last_refill = now;
    }

    fn deactivate(&mut self, now: Instant) {
        self.active = false;
        self.target_bytes_per_second = 0;
        self.tokens = TOKEN_BURST_BYTES;
        self.last_refill = now;
    }
}

pub(crate) struct ReceiverPacer {
    enabled: bool,
    state: parking_lot::Mutex<PacerState>,
}

impl ReceiverPacer {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            state: parking_lot::Mutex::new(PacerState::new(Instant::now())),
        }
    }

    pub(crate) fn update_report(
        &self,
        report: ReceiverPressureReport,
        received_at: Instant,
    ) -> PacerUpdate {
        if !self.enabled {
            return PacerUpdate {
                active: false,
                active_changed: false,
                pressured: false,
                service_bytes_per_second: 0,
                target_bytes_per_second: 0,
            };
        }

        let mut state = self.state.lock();
        let old_active = state.active;
        let Some(previous) = state.previous_report else {
            state.previous_report = Some(report);
            state.last_report_received = Some(received_at);
            state.last_refill = received_at;
            return PacerUpdate {
                active: false,
                active_changed: false,
                pressured: false,
                service_bytes_per_second: 0,
                target_bytes_per_second: 0,
            };
        };
        if report.sample_micros <= previous.sample_micros
            || report.delivered_bytes < previous.delivered_bytes
            || report.stall_ns < previous.stall_ns
        {
            return PacerUpdate {
                active: state.active,
                active_changed: false,
                pressured: false,
                service_bytes_per_second: state.smoothed_service_bytes_per_second,
                target_bytes_per_second: state.target_bytes_per_second,
            };
        }

        let delta_micros = report.sample_micros - previous.sample_micros;
        let delta_bytes = report.delivered_bytes - previous.delivered_bytes;
        let delta_stall_ns = report.stall_ns - previous.stall_ns;
        let sample_service = if delta_micros == 0 {
            0
        } else {
            (u128::from(delta_bytes).saturating_mul(1_000_000) / u128::from(delta_micros))
                .min(u128::from(MAX_TARGET_BYTES_PER_SECOND)) as u64
        };
        if sample_service != 0 {
            state.smoothed_service_bytes_per_second =
                if state.smoothed_service_bytes_per_second == 0 {
                    sample_service
                } else {
                    state
                        .smoothed_service_bytes_per_second
                        .saturating_mul(3)
                        .saturating_add(sample_service)
                        / 4
                };
        }

        let occupancy_pressure = u64::from(report.occupancy_packets)
            .saturating_mul(PRESSURE_OCCUPANCY_DENOMINATOR)
            >= u64::from(report.capacity_packets).saturating_mul(PRESSURE_OCCUPANCY_NUMERATOR);
        let pressured = occupancy_pressure || delta_stall_ns >= PRESSURE_STALL_NS;
        if pressured {
            state.pressure_streak = state
                .pressure_streak
                .saturating_add(1)
                .min(ACTIVATE_AFTER_REPORTS);
            state.clear_streak = 0;
        } else {
            state.clear_streak = state
                .clear_streak
                .saturating_add(1)
                .min(CLEAR_AFTER_REPORTS);
            state.pressure_streak = 0;
        }

        if state.clear_streak >= CLEAR_AFTER_REPORTS {
            state.deactivate(received_at);
        } else if state.pressure_streak >= ACTIVATE_AFTER_REPORTS {
            if state.active {
                state.refill(received_at, TOKEN_BURST_BYTES);
            }
            if sample_service == 0 && state.active {
                state.target_bytes_per_second =
                    state.target_bytes_per_second.saturating_mul(9) / 10;
                state.target_bytes_per_second = state
                    .target_bytes_per_second
                    .max(MIN_TARGET_BYTES_PER_SECOND);
            } else if state.smoothed_service_bytes_per_second != 0 {
                let target = state
                    .smoothed_service_bytes_per_second
                    .saturating_mul(TARGET_HEADROOM_NUMERATOR)
                    / TARGET_HEADROOM_DENOMINATOR;
                state.target_bytes_per_second =
                    target.clamp(MIN_TARGET_BYTES_PER_SECOND, MAX_TARGET_BYTES_PER_SECOND);
                if !state.active {
                    state.tokens = 0;
                }
                state.active = true;
            }
            state.last_refill = received_at;
        }

        state.previous_report = Some(report);
        state.last_report_received = Some(received_at);
        PacerUpdate {
            active: state.active,
            active_changed: old_active != state.active,
            pressured,
            service_bytes_per_second: state.smoothed_service_bytes_per_second,
            target_bytes_per_second: state.target_bytes_per_second,
        }
    }

    pub(crate) async fn pace_bytes(&self, bytes: usize) {
        if !self.enabled || bytes == 0 {
            return;
        }
        let bytes = bytes as u64;
        loop {
            let wait = {
                let now = Instant::now();
                let mut state = self.state.lock();
                if !state.active
                    || state.last_report_received.is_none_or(|received| {
                        now.saturating_duration_since(received) > REPORT_STALE_AFTER
                    })
                {
                    if state.active {
                        state.deactivate(now);
                    }
                    return;
                }
                let capacity = TOKEN_BURST_BYTES.max(bytes);
                state.refill(now, capacity);
                if state.tokens >= bytes {
                    state.tokens -= bytes;
                    return;
                }
                let deficit = bytes - state.tokens;
                let wait_ns = u128::from(deficit)
                    .saturating_mul(1_000_000_000)
                    .div_ceil(u128::from(state.target_bytes_per_second.max(1)));
                Duration::from_nanos(wait_ns.min(u128::from(u64::MAX)) as u64).min(MAX_PACING_SLEEP)
            };
            tokio::time::sleep(wait).await;
        }
    }

    #[cfg(test)]
    fn state_for_test(&self) -> (bool, u64, u64) {
        let state = self.state.lock();
        (
            state.active,
            state.smoothed_service_bytes_per_second,
            state.target_bytes_per_second,
        )
    }
}

fn env_flag_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
    })
}

fn receiver_pacing_enabled_from_env(enable: Option<&str>, disable: Option<&str>) -> bool {
    env_flag_enabled(enable) && !env_flag_enabled(disable)
}

pub(crate) fn receiver_pacing_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let enable = std::env::var("LOWTIER_ENABLE_RECEIVER_PACING").ok();
        let disable = std::env::var("LOWTIER_DISABLE_RECEIVER_PACING").ok();
        receiver_pacing_enabled_from_env(enable.as_deref(), disable.as_deref())
    })
}

pub(crate) fn shared_receiver_pacer(
    my_peer_id: PeerId,
    remote_peer_id: PeerId,
) -> Arc<ReceiverPacer> {
    type Registry = HashMap<(PeerId, PeerId), Weak<ReceiverPacer>>;
    static REGISTRY: OnceLock<parking_lot::Mutex<Registry>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));
    let mut registry = registry.lock();
    registry.retain(|_, pacer| pacer.strong_count() != 0);
    let key = (my_peer_id, remote_peer_id);
    if let Some(pacer) = registry.get(&key).and_then(Weak::upgrade) {
        return pacer;
    }
    let pacer = Arc::new(ReceiverPacer::new(receiver_pacing_enabled()));
    registry.insert(key, Arc::downgrade(&pacer));
    pacer
}

pub(crate) fn paced_packet_bytes(packet: &ZCPacket) -> usize {
    let Some(header) = packet.peer_manager_header() else {
        return 0;
    };
    if header.is_critical_l2_control() {
        return 0;
    }
    let paced = matches!(
        header.packet_type,
        packet_type
            if packet_type == PacketType::Data as u8
                || packet_type == PacketType::ForeignNetworkPacket as u8
                || packet_type == PacketType::KcpSrc as u8
                || packet_type == PacketType::KcpDst as u8
                || packet_type == PacketType::QuicSrc as u8
                || packet_type == PacketType::QuicDst as u8
                || packet_type == PacketType::DataWithKcpSrcModified as u8
                || packet_type == PacketType::DataWithQuicSrcModified as u8
                || packet_type == PacketType::Ethernet as u8
                || packet_type == PacketType::AlternateFecSource as u8
                || packet_type == PacketType::AlternateFecParity as u8
    );
    paced.then(|| packet.payload().len()).unwrap_or(0)
}

pub(crate) fn paced_batch_bytes(batch: &PacketBatch) -> usize {
    batch.iter().map(paced_packet_bytes).sum()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    };

    use super::{
        ReceiverPacer, ReceiverPressureReport, paced_batch_bytes, paced_packet_bytes,
        receiver_pacing_enabled_from_env,
    };

    fn report(
        sample_micros: u64,
        delivered_bytes: u64,
        occupancy_packets: u32,
        stall_ns: u64,
    ) -> ReceiverPressureReport {
        ReceiverPressureReport {
            sample_micros,
            delivered_bytes,
            occupancy_packets,
            capacity_packets: 192,
            stall_ns,
        }
    }

    #[test]
    fn receiver_pacing_requires_explicit_enable_and_disable_wins() {
        assert!(!receiver_pacing_enabled_from_env(None, None));
        assert!(!receiver_pacing_enabled_from_env(Some("0"), None));
        assert!(receiver_pacing_enabled_from_env(Some("1"), None));
        assert!(receiver_pacing_enabled_from_env(Some("TRUE"), None));
        assert!(!receiver_pacing_enabled_from_env(Some("yes"), Some("on")));
    }

    #[test]
    fn receiver_pressure_report_round_trips_and_rejects_invalid_shape() {
        let report = report(100_000, 2_000_000, 48, 10_000_000);
        assert_eq!(ReceiverPressureReport::decode(&report.encode()), Ok(report));
        let mut invalid = report.encode();
        invalid[28..32].fill(0);
        assert!(ReceiverPressureReport::decode(&invalid).is_err());
    }

    #[test]
    fn pacer_activates_from_receiver_service_and_clears_after_pressure() {
        let pacer = ReceiverPacer::new(true);
        let started = Instant::now();
        pacer.update_report(report(100_000, 0, 0, 0), started);
        pacer.update_report(
            report(200_000, 1_000_000, 64, 2_000_000),
            started + Duration::from_millis(100),
        );
        let update = pacer.update_report(
            report(300_000, 2_000_000, 64, 4_000_000),
            started + Duration::from_millis(200),
        );
        assert!(update.active);
        assert!(update.target_bytes_per_second > 0);
        let (active, service, target) = pacer.state_for_test();
        assert!(active);
        assert_eq!(service, 10_000_000);
        assert_eq!(target, 9_500_000);

        for index in 4..=6 {
            pacer.update_report(
                report(index * 100_000, index * 1_000_000, 0, 4_000_000),
                started + Duration::from_millis(index * 100),
            );
        }
        assert!(!pacer.state_for_test().0);
    }

    #[test]
    fn zero_delivery_under_pressure_reduces_an_active_target() {
        let pacer = ReceiverPacer::new(true);
        let started = Instant::now();
        pacer.update_report(report(100_000, 0, 0, 0), started);
        pacer.update_report(
            report(200_000, 1_000_000, 64, 2_000_000),
            started + Duration::from_millis(100),
        );
        pacer.update_report(
            report(300_000, 2_000_000, 64, 4_000_000),
            started + Duration::from_millis(200),
        );
        assert_eq!(pacer.state_for_test().2, 9_500_000);

        let update = pacer.update_report(
            report(400_000, 2_000_000, 64, 6_000_000),
            started + Duration::from_millis(300),
        );
        assert!(update.active);
        assert_eq!(update.target_bytes_per_second, 8_550_000);
    }

    #[test]
    fn only_noncritical_data_contributes_to_pacing() {
        let mut data = ZCPacket::new_with_payload(&[1_u8; 100]);
        data.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        assert_eq!(paced_packet_bytes(&data), 100);

        let mut control = ZCPacket::new_with_payload(&[2_u8; 20]);
        control.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        control
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);
        assert_eq!(paced_packet_bytes(&control), 0);

        let mut ping = ZCPacket::new_with_payload(&[3_u8; 20]);
        ping.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
        assert_eq!(paced_packet_bytes(&ping), 0);

        let mut batch = PacketBatch::new();
        batch.try_push(data).unwrap();
        batch.try_push(control).unwrap();
        batch.try_push(ping).unwrap();
        assert_eq!(paced_batch_bytes(&batch), 100);
    }
}
