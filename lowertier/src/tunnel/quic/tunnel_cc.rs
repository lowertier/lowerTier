//! Create the aggregate QUIC controller during connection setup.
//!
//! Inner TCP still controls each flow. The aggregate tunnel keeps its own
//! delivery feedback and bounded pacing, including for non-TCP datagrams.
use std::sync::Arc;

use quinn_proto::congestion::{BbrConfig, ControllerFactory};

pub(super) fn controller_factory() -> Arc<dyn ControllerFactory + Send + Sync> {
    // Preserve the standard ten-datagram startup budget.
    let mut config = BbrConfig::default();
    config.initial_window(12_000);
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controller_keeps_a_bounded_initial_flight_window() {
        let controller = controller_factory().build(std::time::Instant::now(), 1200);
        assert_eq!(controller.initial_window(), 12_000);
        assert_eq!(controller.window(), 12_000);
        assert_eq!(controller.clone_box().window(), controller.window());
    }
}
