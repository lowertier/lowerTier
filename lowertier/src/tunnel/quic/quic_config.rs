use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use quinn::{TransportConfig, VarInt, congestion::BbrConfig};

use super::adaptive::{AdaptiveConfig, AdaptiveFactory, ConfigError};
use super::wire_profile::WireProfile;

const MIB: u64 = 1024 * 1024;
const MIN_MEMORY_BYTES: u64 = 2 * MIB;
const MAX_STREAM_WINDOW_BYTES: u64 = 64 * MIB;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTuning {
    pub target_wire_bps: u64,
    pub maximum_expected_rtt: Duration,
    pub memory_cap_bytes: u64,
    pub stream_receive_window_bytes: u64,
    pub connection_receive_window_bytes: u64,
    pub connection_send_window_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicConfigError {
    ZeroTargetRate,
    ZeroRtt,
    MemoryCapTooSmall,
    VarIntWindow,
    Adaptive(ConfigError),
}

impl fmt::Display for QuicConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTargetRate => write!(f, "target wire rate must be greater than zero"),
            Self::ZeroRtt => write!(f, "maximum expected RTT must be greater than zero"),
            Self::MemoryCapTooSmall => {
                write!(f, "QUIC memory cap must be at least 2 MiB")
            }
            Self::VarIntWindow => write!(f, "QUIC flow-control window exceeds VarInt"),
            Self::Adaptive(error) => write!(f, "invalid adaptive configuration: {error}"),
        }
    }
}

impl std::error::Error for QuicConfigError {}

impl From<ConfigError> for QuicConfigError {
    fn from(value: ConfigError) -> Self {
        Self::Adaptive(value)
    }
}

impl QuicTuning {
    /// Size windows from encoded wire rate and maximum expected RTT.
    ///
    /// A safety factor of two is used for the hot stream. Aggregate send and
    /// receive windows are bounded to half of the configured per-connection
    /// memory cap each.
    pub fn for_target_wire_rate(
        target_wire_bps: u64,
        maximum_expected_rtt: Duration,
        memory_cap_bytes: u64,
    ) -> Result<Self, QuicConfigError> {
        if target_wire_bps == 0 {
            return Err(QuicConfigError::ZeroTargetRate);
        }
        if maximum_expected_rtt.is_zero() {
            return Err(QuicConfigError::ZeroRtt);
        }
        if memory_cap_bytes < MIN_MEMORY_BYTES {
            return Err(QuicConfigError::MemoryCapTooSmall);
        }

        let bdp = bytes_for_rate_and_duration(target_wire_bps, maximum_expected_rtt);
        let desired_stream =
            next_power_of_two_saturating(bdp.saturating_mul(2)).clamp(MIB, MAX_STREAM_WINDOW_BYTES);
        let per_direction_cap = memory_cap_bytes / 2;
        let stream = desired_stream.min(per_direction_cap).max(MIB);
        let aggregate = stream
            .saturating_add(stream / 2)
            .min(per_direction_cap)
            .max(stream);

        Ok(Self {
            target_wire_bps,
            maximum_expected_rtt,
            memory_cap_bytes,
            stream_receive_window_bytes: stream,
            connection_receive_window_bytes: aggregate,
            connection_send_window_bytes: aggregate,
        })
    }
}

pub enum CongestionChoice {
    Bbr,
    Adaptive(AdaptiveConfig),
}

/// Build a `TransportConfig` that can replace LowTier's current
/// `transport_config()` body without introducing a new wire protocol.
///
/// The existing single bidirectional stream remains intact. Incoming
/// unidirectional streams and QUIC DATAGRAM remain disabled.
pub fn build_transport_config(
    tuning: &QuicTuning,
    profile: WireProfile,
    congestion: CongestionChoice,
) -> Result<Arc<TransportConfig>, QuicConfigError> {
    let stream_receive_window = VarInt::from_u64(tuning.stream_receive_window_bytes)
        .map_err(|_| QuicConfigError::VarIntWindow)?;
    let receive_window = VarInt::from_u64(tuning.connection_receive_window_bytes)
        .map_err(|_| QuicConfigError::VarIntWindow)?;

    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(8_u8.into())
        .max_concurrent_uni_streams(0_u8.into())
        // Remove the current deterministic five-second QUIC keepalive. The
        // application pinger can use WireProfile's bounded idle-only interval.
        .keep_alive_interval(None)
        .initial_rtt(tuning.maximum_expected_rtt)
        .initial_mtu(1200)
        .min_mtu(1200)
        .enable_segmentation_offload(true)
        .allow_spin(profile.allow_spin)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .stream_receive_window(stream_receive_window)
        .receive_window(receive_window)
        .send_window(tuning.connection_send_window_bytes)
        .send_fairness(true);

    match congestion {
        CongestionChoice::Bbr => {
            config.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        CongestionChoice::Adaptive(adaptive) => {
            let factory = AdaptiveFactory::new(adaptive)?;
            config.congestion_controller_factory(Arc::new(factory));
        }
    }

    Ok(Arc::new(config))
}

fn bytes_for_rate_and_duration(rate_bps: u64, duration: Duration) -> u64 {
    let bytes = u128::from(rate_bps).saturating_mul(duration.as_nanos()) / 8_000_000_000_u128;
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn next_power_of_two_saturating(value: u64) -> u64 {
    value.checked_next_power_of_two().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_hundred_megabit_goodput_budget_gets_bdp_sized_windows() {
        // 750 Mbit/s encoded wire budget for a 500 Mbit/s application goal.
        let tuning =
            QuicTuning::for_target_wire_rate(750_000_000, Duration::from_millis(300), 256 * MIB)
                .unwrap();

        assert_eq!(tuning.stream_receive_window_bytes, 64 * MIB);
        assert_eq!(tuning.connection_receive_window_bytes, 96 * MIB);
        assert_eq!(tuning.connection_send_window_bytes, 96 * MIB);
    }

    #[test]
    fn transport_configs_build_for_both_controller_choices() {
        let tuning =
            QuicTuning::for_target_wire_rate(750_000_000, Duration::from_millis(300), 256 * MIB)
                .unwrap();

        build_transport_config(&tuning, WireProfile::BULK, CongestionChoice::Bbr).unwrap();

        build_transport_config(
            &tuning,
            WireProfile::BULK,
            CongestionChoice::Adaptive(AdaptiveConfig {
                initial_rate_bps: 1_000_000,
                max_rate_bps: 1_000_000_000,
                target_wire_bps: Some(750_000_000),
                max_cwnd_bytes: 128 * MIB,
                ..AdaptiveConfig::default()
            }),
        )
        .unwrap();
    }

    #[test]
    fn low_memory_budget_is_rejected() {
        assert_eq!(
            QuicTuning::for_target_wire_rate(500_000_000, Duration::from_millis(300), MIB),
            Err(QuicConfigError::MemoryCapTooSmall)
        );
    }
}
