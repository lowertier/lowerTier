//! Select the aggregate QUIC controller once during connection setup.
//!
//! Inner TCP still controls each flow. The aggregate tunnel keeps its own
//! delivery feedback and bounded pacing, including for non-TCP datagrams.
use std::sync::Arc;

use quinn_proto::congestion::{BbrConfig, ControllerFactory, CubicConfig};

use crate::tunnel::TunnelError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Bbr,
    Cubic,
}

impl Algorithm {
    fn parse(value: Option<&str>) -> Result<Self, TunnelError> {
        match value {
            None | Some("bbr") => Ok(Self::Bbr),
            Some("cubic") => Ok(Self::Cubic),
            Some(_) => Err(TunnelError::InvalidPacket(
                "LOWTIER_QUIC_CONGESTION must be bbr or cubic".into(),
            )),
        }
    }

    fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            Self::Bbr => {
                // Preserve the standard ten-datagram startup budget.
                let mut config = BbrConfig::default();
                config.initial_window(12_000);
                Arc::new(config)
            }
            Self::Cubic => Arc::new(CubicConfig::default()),
        }
    }
}

pub(super) fn controller_factory() -> Result<Arc<dyn ControllerFactory + Send + Sync>, TunnelError>
{
    let value = match std::env::var("LOWTIER_QUIC_CONGESTION") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => {
            return Err(TunnelError::InvalidPacket(
                "invalid congestion selector encoding".into(),
            ));
        }
    };
    let algorithm = Algorithm::parse(value.as_deref())?;
    tracing::info!(?algorithm, "QUIC congestion controller selected");
    Ok(algorithm.factory())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selector_accepts_only_delivery_responsive_controllers() {
        assert_eq!(Algorithm::parse(None).unwrap(), Algorithm::Bbr);
        assert_eq!(Algorithm::parse(Some("bbr")).unwrap(), Algorithm::Bbr);
        assert_eq!(Algorithm::parse(Some("cubic")).unwrap(), Algorithm::Cubic);
        for value in ["", "none", "unlimited", "BBR", "cubic "] {
            assert!(Algorithm::parse(Some(value)).is_err());
        }
    }
    #[test]
    fn both_algorithms_keep_a_bounded_initial_flight_window() {
        for algorithm in [Algorithm::Bbr, Algorithm::Cubic] {
            let controller = algorithm.factory().build(std::time::Instant::now(), 1200);
            assert_eq!(controller.initial_window(), 12_000);
            assert_eq!(controller.window(), 12_000);
            assert_eq!(controller.clone_box().window(), controller.window());
        }
    }
}
