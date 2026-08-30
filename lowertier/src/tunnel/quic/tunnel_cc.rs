use std::{any::Any, sync::Arc, time::Instant};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory},
};

/// Quinn disables its userspace pacer above this congestion window.
///
/// Tunnel packets already contain transports with their own congestion rules.
/// This controller keeps QUIC packet protection and removes the second controller.
const UNPACED_TUNNEL_WINDOW_BYTES: u64 = u32::MAX as u64 + 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct TunnelConfig;

impl ControllerFactory for TunnelConfig {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(TunnelController)
    }
}

#[derive(Clone, Copy, Debug)]
struct TunnelController;

impl Controller for TunnelController {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {}

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
    ) {
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        UNPACED_TUNNEL_WINDOW_BYTES
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(*self)
    }

    fn initial_window(&self) -> u64 {
        UNPACED_TUNNEL_WINDOW_BYTES
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_window_disables_quinn_pacing() {
        let controller = TunnelController;

        assert_eq!(controller.window(), u32::MAX as u64 + 1);
    }
}
