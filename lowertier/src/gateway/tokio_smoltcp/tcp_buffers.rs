use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use smoltcp::socket::tcp;

use crate::common::global_ctx::{
    PROCESS_RETAINED_MEMORY_LIMIT_BYTES, ProcessMemoryGovernor, ProcessMemoryPermit,
};

// One full-duplex socket can retain at most one quarter of the process budget.
const MAX_BUFFER_BYTES: usize = PROCESS_RETAINED_MEMORY_LIMIT_BYTES / 8;

struct DeliverySample {
    start: Instant,
    bytes: usize,
}

impl DeliverySample {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            bytes: 0,
        }
    }

    fn target(&mut self, bytes: usize, now: Instant, rtt: Duration, capacity: usize) -> usize {
        self.bytes = self.bytes.saturating_add(bytes);
        let elapsed = now.saturating_duration_since(self.start);
        if elapsed < rtt || rtt.is_zero() {
            return capacity;
        }
        // Two measured bandwidth-delay products allow ACK and application work
        // to overlap. Geometric growth bounds total copying by the final size.
        let target = (self.bytes as u128 * 2 * rtt.as_nanos())
            .div_ceil(elapsed.as_nanos().max(1))
            .min(MAX_BUFFER_BYTES as u128) as usize;
        self.start = now;
        self.bytes = 0;
        if target <= capacity {
            capacity
        } else {
            target
                .next_power_of_two()
                .min(capacity.saturating_mul(2))
                .min(MAX_BUFFER_BYTES)
        }
    }
}

pub(super) struct TcpBuffers {
    governor: Arc<ProcessMemoryGovernor>,
    rx_memory: ProcessMemoryPermit,
    tx_memory: ProcessMemoryPermit,
    rx_sample: DeliverySample,
    tx_sample: DeliverySample,
}

impl TcpBuffers {
    pub(super) fn new(
        rx: usize,
        tx: usize,
        governor: Arc<ProcessMemoryGovernor>,
    ) -> io::Result<Self> {
        let reserve = |bytes| {
            governor
                .try_reserve_owned(bytes)
                .ok_or_else(|| io::Error::other("userspace TCP memory budget exhausted"))
        };
        let rx_memory = reserve(rx)?;
        let tx_memory = reserve(tx)?;
        let now = Instant::now();
        Ok(Self {
            governor,
            rx_memory,
            tx_memory,
            rx_sample: DeliverySample::new(now),
            tx_sample: DeliverySample::new(now),
        })
    }

    pub(super) fn recv_limit(initial: usize) -> usize {
        initial.max(MAX_BUFFER_BYTES)
    }

    pub(super) fn received(&mut self, socket: &mut tcp::Socket<'_>, bytes: usize) {
        let Some(rtt) = socket.smoothed_rtt() else {
            return;
        };
        // smoltcp measures RTT in milliseconds. A zero sample represents a
        // sub-millisecond path, so use one measurement tick for its estimate.
        let rtt = Duration::from(rtt).max(Duration::from_millis(1));
        let target = self
            .rx_sample
            .target(bytes, Instant::now(), rtt, socket.recv_capacity())
            .min(socket.recv_capacity_limit());
        if target <= socket.recv_capacity() {
            return;
        }
        // Reserve the complete replacement before allocation. The old buffer
        // and its permit remain live until the copy finishes.
        let Some(permit) = self.governor.try_reserve_owned(target) else {
            return;
        };
        tracing::debug!(target: "CORE::TCP_BUFFER", direction = "receive", old_bytes = socket.recv_capacity(), new_bytes = target, rtt_us = rtt.as_micros(), "TCP buffer growth");
        socket.grow_recv_buffer(vec![0; target]);
        self.rx_memory = permit;
    }

    pub(super) fn sent(&mut self, socket: &mut tcp::Socket<'_>, bytes: usize) {
        let Some(rtt) = socket.smoothed_rtt() else {
            return;
        };
        let rtt = Duration::from(rtt).max(Duration::from_millis(1));
        let target = self
            .tx_sample
            .target(bytes, Instant::now(), rtt, socket.send_capacity());
        if target <= socket.send_capacity() {
            return;
        }
        let Some(permit) = self.governor.try_reserve_owned(target) else {
            return;
        };
        tracing::debug!(target: "CORE::TCP_BUFFER", direction = "send", old_bytes = socket.send_capacity(), new_bytes = target, rtt_us = rtt.as_micros(), "TCP buffer growth");
        socket.grow_send_buffer(vec![0; target]);
        self.tx_memory = permit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userspace_tcp_keeps_congestion_control_with_growing_buffers() {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 8192]),
            tcp::SocketBuffer::new(vec![0; 8192]),
        );
        assert_ne!(socket.congestion_control(), tcp::CongestionControl::None);
        socket.grow_send_buffer(vec![0; 65536]);
        assert_ne!(socket.congestion_control(), tcp::CongestionControl::None);
    }

    #[test]
    fn demand_controls_growth_and_idle_samples_do_not_allocate() {
        let now = Instant::now();
        let rtt = Duration::from_millis(20);
        let mut sample = DeliverySample::new(now);
        assert_eq!(sample.target(8192, now + rtt / 2, rtt, 8192), 8192);
        assert_eq!(sample.target(0, now + rtt, rtt, 8192), 16384);
        assert_eq!(sample.target(0, now + rtt * 2, rtt, 16384), 16384);
        assert_eq!(sample.target(100, now + rtt * 3, rtt, 16384), 16384);
        assert_eq!(
            sample.target(usize::MAX, now + rtt * 4, rtt, MAX_BUFFER_BYTES),
            MAX_BUFFER_BYTES
        );
    }

    #[test]
    fn admission_failure_releases_partial_reservations() {
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(24));
        let first = TcpBuffers::new(8, 8, governor.clone()).unwrap();
        assert!(TcpBuffers::new(8, 8, governor.clone()).is_err());
        assert!(governor.try_reserve_owned(8).is_some());
        drop(first);
        assert!(governor.try_reserve_owned(24).is_some());
    }
}
