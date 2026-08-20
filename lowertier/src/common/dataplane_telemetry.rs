use std::{
    cell::Cell,
    fmt::Write as _,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_DATAPLANE_QUEUES: usize = 64;
const DEFAULT_SAMPLE_EVERY: u64 = 256;

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataplaneStage {
    RoutePolicy,
    RoutedClassify,
    RoutedEnqueue,
    QuicReceive,
    QuicSend,
    DirectNicIngress,
    DirectNicAdmission,
    TunRead,
    TunSchedule,
    TunWrite,
    ReceiverPacing,
}

const DATAPLANE_STAGES: [DataplaneStage; 11] = [
    DataplaneStage::RoutePolicy,
    DataplaneStage::RoutedClassify,
    DataplaneStage::RoutedEnqueue,
    DataplaneStage::QuicReceive,
    DataplaneStage::QuicSend,
    DataplaneStage::DirectNicIngress,
    DataplaneStage::DirectNicAdmission,
    DataplaneStage::TunRead,
    DataplaneStage::TunSchedule,
    DataplaneStage::TunWrite,
    DataplaneStage::ReceiverPacing,
];

impl DataplaneStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RoutePolicy => "route_policy",
            Self::RoutedClassify => "routed_classify",
            Self::RoutedEnqueue => "routed_enqueue",
            Self::QuicReceive => "quic_receive",
            Self::QuicSend => "quic_send",
            Self::DirectNicIngress => "direct_nic_ingress",
            Self::DirectNicAdmission => "direct_nic_admission",
            Self::TunRead => "tun_read",
            Self::TunSchedule => "tun_schedule",
            Self::TunWrite => "tun_write",
            Self::ReceiverPacing => "receiver_pacing",
        }
    }
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataplaneQueueClass {
    DirectNic,
    Tun,
}

const DATAPLANE_QUEUE_CLASSES: [DataplaneQueueClass; 2] =
    [DataplaneQueueClass::DirectNic, DataplaneQueueClass::Tun];
const DATAPLANE_QUEUE_SLOTS: usize = DATAPLANE_QUEUE_CLASSES.len() * MAX_DATAPLANE_QUEUES;

impl DataplaneQueueClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectNic => "direct_nic",
            Self::Tun => "tun",
        }
    }
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataplaneIo {
    QuicUdpReceive,
    QuicUdpSend,
    TunRead,
    TunWrite,
    IoUringSubmit,
}

const DATAPLANE_IO: [DataplaneIo; 5] = [
    DataplaneIo::QuicUdpReceive,
    DataplaneIo::QuicUdpSend,
    DataplaneIo::TunRead,
    DataplaneIo::TunWrite,
    DataplaneIo::IoUringSubmit,
];

impl DataplaneIo {
    const fn as_str(self) -> &'static str {
        match self {
            Self::QuicUdpReceive => "quic_udp_receive",
            Self::QuicUdpSend => "quic_udp_send",
            Self::TunRead => "tun_read",
            Self::TunWrite => "tun_write",
            Self::IoUringSubmit => "io_uring_submit",
        }
    }
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataplaneFec {
    SourceTx,
    ParityTx,
    SourceRx,
    ParityRx,
    Recovered,
}

const DATAPLANE_FEC: [DataplaneFec; 5] = [
    DataplaneFec::SourceTx,
    DataplaneFec::ParityTx,
    DataplaneFec::SourceRx,
    DataplaneFec::ParityRx,
    DataplaneFec::Recovered,
];

impl DataplaneFec {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SourceTx => "source_tx",
            Self::ParityTx => "parity_tx",
            Self::SourceRx => "source_rx",
            Self::ParityRx => "parity_rx",
            Self::Recovered => "recovered",
        }
    }
}

#[derive(Default)]
struct StageStats {
    samples: AtomicU64,
    sampled_ns: AtomicU64,
    max_ns: AtomicU64,
    sampled_batches: AtomicU64,
    sampled_packets: AtomicU64,
    sampled_bytes: AtomicU64,
}

#[derive(Default)]
struct QueueStats {
    occupancy_packets: AtomicU64,
    occupancy_bytes: AtomicU64,
    max_occupancy_packets: AtomicU64,
    max_occupancy_bytes: AtomicU64,
    stall_events: AtomicU64,
    stall_ns: AtomicU64,
}

#[derive(Default)]
struct IoStats {
    syscalls: AtomicU64,
    packets: AtomicU64,
    bytes: AtomicU64,
}

#[derive(Default)]
struct FecStats {
    packets: AtomicU64,
    bytes: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverPressureSnapshot {
    pub sample_micros: u64,
    pub delivered_bytes: u64,
    pub occupancy_packets: u64,
    pub stall_ns: u64,
}

pub struct DataplaneStageGuard {
    telemetry: std::sync::Arc<DataplaneTelemetry>,
    stage: DataplaneStage,
    started: Instant,
    packets: usize,
    bytes: usize,
}

impl DataplaneStageGuard {
    pub fn set_shape(&mut self, packets: usize, bytes: usize) {
        self.packets = packets;
        self.bytes = bytes;
    }
}

impl Drop for DataplaneStageGuard {
    fn drop(&mut self) {
        self.telemetry.record_stage_sample(
            self.stage,
            Some(self.started),
            self.packets,
            self.bytes,
        );
    }
}

pub struct DataplaneTelemetry {
    started: Instant,
    stages: [StageStats; DATAPLANE_STAGES.len()],
    queues: [QueueStats; DATAPLANE_QUEUE_SLOTS],
    io: [IoStats; DATAPLANE_IO.len()],
    fec: [FecStats; DATAPLANE_FEC.len()],
}

impl Default for DataplaneTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl DataplaneTelemetry {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            stages: std::array::from_fn(|_| StageStats::default()),
            queues: std::array::from_fn(|_| QueueStats::default()),
            io: std::array::from_fn(|_| IoStats::default()),
            fec: std::array::from_fn(|_| FecStats::default()),
        }
    }

    pub fn sample_stage(
        self: &std::sync::Arc<Self>,
        stage: DataplaneStage,
        packets: usize,
        bytes: usize,
    ) -> Option<DataplaneStageGuard> {
        Self::sample_start().map(|started| DataplaneStageGuard {
            telemetry: self.clone(),
            stage,
            started,
            packets,
            bytes,
        })
    }

    pub fn sample_stage_with_shape<F>(
        self: &std::sync::Arc<Self>,
        stage: DataplaneStage,
        shape: F,
    ) -> Option<DataplaneStageGuard>
    where
        F: FnOnce() -> (usize, usize),
    {
        let started = Self::sample_start()?;
        let (packets, bytes) = shape();
        Some(DataplaneStageGuard {
            telemetry: self.clone(),
            stage,
            started,
            packets,
            bytes,
        })
    }

    pub fn sample_start() -> Option<Instant> {
        let every = sample_every();
        if every == 0 {
            return None;
        }
        SAMPLE_SEQUENCE.with(|sequence| {
            let next = sequence.get().wrapping_add(1);
            sequence.set(next);
            let selected = if every.is_power_of_two() {
                next & (every - 1) == 0
            } else {
                next % every == 0
            };
            selected.then(Instant::now)
        })
    }

    pub fn record_stage_sample(
        &self,
        stage: DataplaneStage,
        started: Option<Instant>,
        packets: usize,
        bytes: usize,
    ) {
        let Some(started) = started else {
            return;
        };
        let elapsed_ns = duration_ns(started.elapsed());
        let stats = &self.stages[stage as usize];
        stats.samples.fetch_add(1, Ordering::Relaxed);
        stats.sampled_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
        atomic_max(&stats.max_ns, elapsed_ns);
        stats.sampled_batches.fetch_add(1, Ordering::Relaxed);
        stats
            .sampled_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        stats
            .sampled_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn set_queue_occupancy(
        &self,
        class: DataplaneQueueClass,
        queue: usize,
        packets: usize,
        bytes: usize,
    ) {
        let stats = &self.queues[queue_slot(class, queue)];
        let packets = packets as u64;
        let bytes = bytes as u64;
        stats.occupancy_packets.store(packets, Ordering::Relaxed);
        stats.occupancy_bytes.store(bytes, Ordering::Relaxed);
        atomic_max(&stats.max_occupancy_packets, packets);
        atomic_max(&stats.max_occupancy_bytes, bytes);
    }

    pub fn record_queue_stall(&self, class: DataplaneQueueClass, queue: usize, duration: Duration) {
        let stats = &self.queues[queue_slot(class, queue)];
        stats.stall_events.fetch_add(1, Ordering::Relaxed);
        stats
            .stall_ns
            .fetch_add(duration_ns(duration), Ordering::Relaxed);
    }

    pub fn record_io(&self, operation: DataplaneIo, syscalls: usize, packets: usize, bytes: usize) {
        let stats = &self.io[operation as usize];
        stats.syscalls.fetch_add(syscalls as u64, Ordering::Relaxed);
        stats.packets.fetch_add(packets as u64, Ordering::Relaxed);
        stats.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_fec(&self, operation: DataplaneFec, packets: usize, bytes: usize) {
        let stats = &self.fec[operation as usize];
        stats.packets.fetch_add(packets as u64, Ordering::Relaxed);
        stats.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn receiver_pressure_snapshot(&self) -> ReceiverPressureSnapshot {
        let queue = &self.queues[queue_slot(DataplaneQueueClass::DirectNic, 0)];
        let tun_write = &self.io[DataplaneIo::TunWrite as usize];
        ReceiverPressureSnapshot {
            sample_micros: self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            delivered_bytes: tun_write.bytes.load(Ordering::Relaxed),
            occupancy_packets: queue.occupancy_packets.load(Ordering::Relaxed),
            stall_ns: queue.stall_ns.load(Ordering::Relaxed),
        }
    }

    pub fn export_prometheus(&self) -> String {
        let mut output = String::with_capacity(16 * 1024);
        output.push_str(
            "# HELP lowertier_dataplane_stage_samples_total Sampled dataplane stage executions.\n\
# TYPE lowertier_dataplane_stage_samples_total counter\n\
# HELP lowertier_dataplane_stage_sampled_ns_total Nanoseconds accumulated by sampled dataplane stage executions.\n\
# TYPE lowertier_dataplane_stage_sampled_ns_total counter\n\
# HELP lowertier_dataplane_stage_sampled_ns_max Maximum sampled dataplane stage duration in nanoseconds.\n\
# TYPE lowertier_dataplane_stage_sampled_ns_max gauge\n\
# HELP lowertier_dataplane_stage_sampled_batches_total Batches represented by stage samples.\n\
# TYPE lowertier_dataplane_stage_sampled_batches_total counter\n\
# HELP lowertier_dataplane_stage_sampled_packets_total Packets represented by stage samples.\n\
# TYPE lowertier_dataplane_stage_sampled_packets_total counter\n\
# HELP lowertier_dataplane_stage_sampled_bytes_total Bytes represented by stage samples.\n\
# TYPE lowertier_dataplane_stage_sampled_bytes_total counter\n",
        );
        for stage in DATAPLANE_STAGES {
            let stats = &self.stages[stage as usize];
            let name = stage.as_str();
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_samples_total{{stage=\"{name}\"}} {}",
                stats.samples.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_sampled_ns_total{{stage=\"{name}\"}} {}",
                stats.sampled_ns.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_sampled_ns_max{{stage=\"{name}\"}} {}",
                stats.max_ns.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_sampled_batches_total{{stage=\"{name}\"}} {}",
                stats.sampled_batches.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_sampled_packets_total{{stage=\"{name}\"}} {}",
                stats.sampled_packets.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_stage_sampled_bytes_total{{stage=\"{name}\"}} {}",
                stats.sampled_bytes.load(Ordering::Relaxed)
            );
        }

        output.push_str(
            "# HELP lowertier_dataplane_queue_occupancy_packets Current queue occupancy in packets.\n\
# TYPE lowertier_dataplane_queue_occupancy_packets gauge\n\
# HELP lowertier_dataplane_queue_occupancy_bytes Current queue occupancy in retained bytes.\n\
# TYPE lowertier_dataplane_queue_occupancy_bytes gauge\n\
# HELP lowertier_dataplane_queue_occupancy_packets_max Maximum observed queue occupancy in packets.\n\
# TYPE lowertier_dataplane_queue_occupancy_packets_max gauge\n\
# HELP lowertier_dataplane_queue_occupancy_bytes_max Maximum observed queue occupancy in retained bytes.\n\
# TYPE lowertier_dataplane_queue_occupancy_bytes_max gauge\n\
# HELP lowertier_dataplane_queue_stall_events_total Queue backpressure stall events.\n\
# TYPE lowertier_dataplane_queue_stall_events_total counter\n\
# HELP lowertier_dataplane_queue_stall_ns_total Queue backpressure time in nanoseconds.\n\
# TYPE lowertier_dataplane_queue_stall_ns_total counter\n",
        );
        for class in DATAPLANE_QUEUE_CLASSES {
            for queue in 0..MAX_DATAPLANE_QUEUES {
                let stats = &self.queues[queue_slot(class, queue)];
                let occupancy_packets = stats.occupancy_packets.load(Ordering::Relaxed);
                let occupancy_bytes = stats.occupancy_bytes.load(Ordering::Relaxed);
                let max_packets = stats.max_occupancy_packets.load(Ordering::Relaxed);
                let max_bytes = stats.max_occupancy_bytes.load(Ordering::Relaxed);
                let stall_events = stats.stall_events.load(Ordering::Relaxed);
                let stall_ns = stats.stall_ns.load(Ordering::Relaxed);
                if occupancy_packets == 0
                    && occupancy_bytes == 0
                    && max_packets == 0
                    && max_bytes == 0
                    && stall_events == 0
                    && stall_ns == 0
                {
                    continue;
                }
                let class = class.as_str();
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_occupancy_packets{{class=\"{class}\",queue=\"{queue}\"}} {occupancy_packets}"
                );
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_occupancy_bytes{{class=\"{class}\",queue=\"{queue}\"}} {occupancy_bytes}"
                );
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_occupancy_packets_max{{class=\"{class}\",queue=\"{queue}\"}} {max_packets}"
                );
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_occupancy_bytes_max{{class=\"{class}\",queue=\"{queue}\"}} {max_bytes}"
                );
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_stall_events_total{{class=\"{class}\",queue=\"{queue}\"}} {stall_events}"
                );
                let _ = writeln!(
                    output,
                    "lowertier_dataplane_queue_stall_ns_total{{class=\"{class}\",queue=\"{queue}\"}} {stall_ns}"
                );
            }
        }

        output.push_str(
            "# HELP lowertier_dataplane_io_syscalls_total Dataplane kernel I/O calls.\n\
# TYPE lowertier_dataplane_io_syscalls_total counter\n\
# HELP lowertier_dataplane_io_packets_total Packets represented by dataplane kernel I/O calls.\n\
# TYPE lowertier_dataplane_io_packets_total counter\n\
# HELP lowertier_dataplane_io_bytes_total Bytes represented by dataplane kernel I/O calls.\n\
# TYPE lowertier_dataplane_io_bytes_total counter\n",
        );
        for operation in DATAPLANE_IO {
            let stats = &self.io[operation as usize];
            let name = operation.as_str();
            let _ = writeln!(
                output,
                "lowertier_dataplane_io_syscalls_total{{operation=\"{name}\"}} {}",
                stats.syscalls.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_io_packets_total{{operation=\"{name}\"}} {}",
                stats.packets.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_io_bytes_total{{operation=\"{name}\"}} {}",
                stats.bytes.load(Ordering::Relaxed)
            );
        }

        output.push_str(
            "# HELP lowertier_dataplane_fec_packets_total Alternate-path FEC packets by operation.\n\
# TYPE lowertier_dataplane_fec_packets_total counter\n\
# HELP lowertier_dataplane_fec_bytes_total Alternate-path FEC bytes by operation.\n\
# TYPE lowertier_dataplane_fec_bytes_total counter\n",
        );
        for operation in DATAPLANE_FEC {
            let stats = &self.fec[operation as usize];
            let name = operation.as_str();
            let _ = writeln!(
                output,
                "lowertier_dataplane_fec_packets_total{{operation=\"{name}\"}} {}",
                stats.packets.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                output,
                "lowertier_dataplane_fec_bytes_total{{operation=\"{name}\"}} {}",
                stats.bytes.load(Ordering::Relaxed)
            );
        }
        output
    }
}

thread_local! {
    static SAMPLE_SEQUENCE: Cell<u64> = const { Cell::new(0) };
}

fn sample_every() -> u64 {
    static SAMPLE_EVERY: OnceLock<u64> = OnceLock::new();
    *SAMPLE_EVERY.get_or_init(|| {
        std::env::var("LOWTIER_DATAPLANE_SAMPLE_EVERY")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_SAMPLE_EVERY)
    })
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn queue_slot(class: DataplaneQueueClass, queue: usize) -> usize {
    usize::from(class as u8) * MAX_DATAPLANE_QUEUES
        + queue.min(MAX_DATAPLANE_QUEUES.saturating_sub(1))
}

fn atomic_max(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while current < value {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        DataplaneFec, DataplaneIo, DataplaneQueueClass, DataplaneStage, DataplaneTelemetry,
    };

    #[test]
    fn telemetry_exports_sampled_stage_queue_and_io_metrics() {
        let telemetry = DataplaneTelemetry::new();
        telemetry.record_stage_sample(
            DataplaneStage::TunWrite,
            Some(Instant::now() - Duration::from_micros(10)),
            8,
            8192,
        );
        telemetry.set_queue_occupancy(DataplaneQueueClass::DirectNic, 0, 7, 7000);
        telemetry.record_queue_stall(DataplaneQueueClass::DirectNic, 0, Duration::from_micros(12));
        telemetry.record_io(DataplaneIo::TunWrite, 4, 8, 8192);
        telemetry.record_fec(DataplaneFec::SourceTx, 8, 9000);
        telemetry.record_fec(DataplaneFec::Recovered, 2, 2048);

        let pressure = telemetry.receiver_pressure_snapshot();
        assert_eq!(pressure.delivered_bytes, 8192);
        assert_eq!(pressure.occupancy_packets, 7);
        assert!(pressure.stall_ns >= 12_000);

        let output = telemetry.export_prometheus();
        assert!(output.contains("stage=\"tun_write\""));
        assert!(output.contains("class=\"direct_nic\",queue=\"0\""));
        assert!(output.contains("operation=\"tun_write\""));
        assert!(output.contains("operation=\"source_tx\""));
        assert!(output.contains("operation=\"recovered\""));
        assert!(output.contains(" 8192\n"));
        assert!(output.contains(" 9000\n"));
    }
}
