use std::{
    future::Future,
    io,
    os::fd::AsRawFd,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{Sink, Stream, ready, stream::FuturesUnordered};
use quincy_tun::{AsyncDevice, GROTable, VIRTIO_NET_HDR_LEN};
use smallvec::SmallVec;

use crate::{
    common::dataplane_telemetry::{
        DataplaneIo, DataplaneQueueClass, DataplaneStage, DataplaneTelemetry,
    },
    instance::{
        linux_tun_uring::{self, IoUringTunWriter},
        tun_scheduler::{
            FlowDrrScheduler, TUN_SCHEDULER_BYTE_CAPACITY, TUN_SCHEDULER_PACKET_CAPACITY,
        },
    },
    tunnel::{
        BatchStreamItem, PacketBatchSink, PacketBatchStream, SplitIngressTunnel, SplitTunnel,
        Tunnel, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, packet_batch_limit},
        packet_def::{ReusableBufferPool, TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
    },
};

const MAX_TUN_PACKET_SIZE: usize = u16::MAX as usize;
const TUN_BUFFER_BATCHES_PER_QUEUE: usize = 2;

fn tun_segment_capacity(mtu: usize) -> (usize, usize) {
    let payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
    let segment_capacity = payload_offset + mtu.max(1500) + 256 + TAIL_RESERVED_SIZE;
    (payload_offset, segment_capacity)
}

fn received_batch_partition(
    current_len: usize,
    received: usize,
    batch_limit: usize,
) -> Result<(usize, usize), TunnelError> {
    if received == 0
        || received > MAX_PACKET_BATCH_SIZE
        || current_len > batch_limit
        || !(1..=MAX_PACKET_BATCH_SIZE).contains(&batch_limit)
    {
        return Err(TunnelError::InvalidPacket(format!(
            "TUN read returned invalid segment count {received}"
        )));
    }
    let appended = received.min(batch_limit - current_len);
    Ok((appended, received - appended))
}

struct ReadState {
    device: Arc<AsyncDevice>,
    original: Vec<u8>,
    segments: Vec<BytesMut>,
    sizes: Vec<usize>,
    payload_offset: usize,
    segment_capacity: usize,
    reusable_pool: ReusableBufferPool,
    telemetry: Arc<DataplaneTelemetry>,
    pending_batch: Option<PacketBatch>,
    pending_error: Option<TunnelError>,
    failed: bool,
}

/// Preserve one complete configured TUN batch through crypto and output.
fn tun_batch_limit() -> usize {
    bounded_tun_batch_limit(packet_batch_limit())
}

fn bounded_tun_batch_limit(configured: usize) -> usize {
    configured.min(MAX_PACKET_BATCH_SIZE)
}

impl ReadState {
    fn new(
        device: Arc<AsyncDevice>,
        payload_offset: usize,
        segment_capacity: usize,
        reusable_pool: ReusableBufferPool,
        telemetry: Arc<DataplaneTelemetry>,
    ) -> Self {
        Self {
            device,
            original: vec![0; VIRTIO_NET_HDR_LEN + MAX_TUN_PACKET_SIZE],
            segments: (0..MAX_PACKET_BATCH_SIZE)
                .map(|_| {
                    reusable_pool
                        .try_take()
                        .expect("the reusable TAP pool contains the first read batch")
                })
                .collect(),
            sizes: vec![0; MAX_PACKET_BATCH_SIZE],
            payload_offset,
            segment_capacity,
            reusable_pool,
            telemetry,
            pending_batch: None,
            pending_error: None,
            failed: false,
        }
    }

    fn append_received(
        &mut self,
        count: usize,
        batch: &mut PacketBatch,
    ) -> Result<(), TunnelError> {
        let (appended, overflow_count) =
            received_batch_partition(batch.len(), count, tun_batch_limit())?;
        for index in 0..count {
            let packet_len = self.payload_offset + self.sizes[index];
            if packet_len > self.segment_capacity {
                return Err(TunnelError::InvalidPacket(format!(
                    "TUN offload segment length {packet_len} exceeds {}",
                    self.segment_capacity
                )));
            }
        }

        for index in 0..appended {
            let packet_len = self.payload_offset + self.sizes[index];
            let replacement = self.reusable_pool.take_or_allocate();
            let mut segment = std::mem::replace(&mut self.segments[index], replacement);
            segment.truncate(packet_len);
            batch
                .try_push(ZCPacket::new_from_reusable_buf(
                    segment,
                    ZCPacketType::NIC,
                    self.reusable_pool.clone(),
                ))
                .expect("the TUN output batch checks its fixed bound");
        }

        if overflow_count != 0 {
            let mut overflow = PacketBatch::with_capacity(overflow_count);
            for index in appended..count {
                let packet_len = self.payload_offset + self.sizes[index];
                let replacement = self.reusable_pool.take_or_allocate();
                let mut segment = std::mem::replace(&mut self.segments[index], replacement);
                segment.truncate(packet_len);
                overflow
                    .try_push(ZCPacket::new_from_reusable_buf(
                        segment,
                        ZCPacketType::NIC,
                        self.reusable_pool.clone(),
                    ))
                    .expect("one TUN GSO packet cannot exceed one fixed batch");
            }
            debug_assert!(self.pending_batch.is_none());
            self.pending_batch = Some(overflow);
        }
        Ok(())
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<BatchStreamItem>> {
        if self.failed {
            return Poll::Ready(None);
        }

        if let Some(mut batch) = self.pending_batch.take() {
            let batch_limit = tun_batch_limit();
            if batch.len() > batch_limit {
                self.pending_batch = Some(batch.split_off(batch_limit));
            }
            return Poll::Ready(Some(Ok(batch)));
        }

        if let Some(error) = self.pending_error.take() {
            self.failed = true;
            return Poll::Ready(Some(Err(error)));
        }

        let stage_started = DataplaneTelemetry::sample_start();
        let mut io_calls = 0_usize;
        let mut io_packets = 0_usize;
        let mut io_bytes = 0_usize;
        let count = loop {
            match self.device.poll_readable(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    return Poll::Ready(Some(Err(TunnelError::IOError(error))));
                }
                Poll::Ready(Ok(())) => {}
            }
            io_calls += 1;
            match self.device.try_recv_multiple(
                &mut self.original,
                &mut self.segments,
                &mut self.sizes,
                self.payload_offset,
            ) {
                Ok(count) => {
                    io_packets += count;
                    io_bytes =
                        io_bytes.saturating_add(self.sizes[..count].iter().copied().sum::<usize>());
                    break count;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    self.failed = true;
                    return Poll::Ready(Some(Err(TunnelError::IOError(error))));
                }
            }
        };

        let batch_limit = tun_batch_limit();
        let mut batch = PacketBatch::with_capacity(count.min(batch_limit));
        if let Err(error) = self.append_received(count, &mut batch) {
            self.failed = true;
            return Poll::Ready(Some(Err(error)));
        }

        while batch.len() < batch_limit && self.pending_batch.is_none() {
            io_calls += 1;
            match self.device.try_recv_multiple(
                &mut self.original,
                &mut self.segments,
                &mut self.sizes,
                self.payload_offset,
            ) {
                Ok(count) => {
                    io_packets += count;
                    io_bytes =
                        io_bytes.saturating_add(self.sizes[..count].iter().copied().sum::<usize>());
                    if let Err(error) = self.append_received(count, &mut batch) {
                        self.pending_error = Some(error);
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.pending_error = Some(TunnelError::IOError(error));
                    break;
                }
            }
        }

        self.telemetry
            .record_io(DataplaneIo::TunRead, io_calls, io_packets, io_bytes);
        self.telemetry.record_stage_sample(
            DataplaneStage::TunRead,
            stage_started,
            io_packets,
            io_bytes,
        );
        Poll::Ready(Some(Ok(batch)))
    }
}

struct LinuxTunStream {
    state: ReadState,
}

impl Stream for LinuxTunStream {
    type Item = BatchStreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.state.poll_next(cx)
    }
}

fn packet_into_tun_buffer(packet: ZCPacket) -> Result<BytesMut, TunnelError> {
    let payload_offset = packet.payload_offset();
    let mut inner = packet.inner();
    let packet_start = payload_offset;
    if packet_start < VIRTIO_NET_HDR_LEN {
        return Err(TunnelError::InvalidPacket(
            "packet does not have enough headroom for Linux TUN metadata".into(),
        ));
    }
    inner.advance(packet_start - VIRTIO_NET_HDR_LEN);
    inner[..VIRTIO_NET_HDR_LEN].fill(0);
    Ok(inner)
}

type SendFuture = Pin<
    Box<
        dyn Future<
                Output = (
                    usize,
                    io::Result<(usize, usize)>,
                    Vec<BytesMut>,
                    GROTable,
                    usize,
                    Option<std::time::Instant>,
                    bool,
                ),
            > + Send,
    >,
>;

struct QueueSink {
    scheduler: FlowDrrScheduler<BytesMut>,
    max_batch_bytes: usize,
    spare: Option<Vec<BytesMut>>,
    gro_spare: Option<GROTable>,
    write_active: bool,
    in_flight_packets: usize,
    in_flight_bytes: usize,
    stall_started: Option<std::time::Instant>,
}

impl QueueSink {
    fn new(mtu: usize) -> Self {
        let max_packet_bytes = mtu
            .max(1)
            .saturating_add(crate::instance::l2_tun::ETHERNET_HEADER_LEN)
            .saturating_add(VIRTIO_NET_HDR_LEN);
        let max_batch_bytes = max_packet_bytes.saturating_mul(MAX_PACKET_BATCH_SIZE);
        let byte_capacity = TUN_SCHEDULER_BYTE_CAPACITY
            .max(max_packet_bytes.saturating_mul(TUN_SCHEDULER_PACKET_CAPACITY));
        Self {
            scheduler: FlowDrrScheduler::new(
                TUN_SCHEDULER_PACKET_CAPACITY,
                byte_capacity,
                mtu.max(1),
            ),
            max_batch_bytes,
            spare: Some(Vec::with_capacity(MAX_PACKET_BATCH_SIZE)),
            gro_spare: Some(GROTable::default()),
            write_active: false,
            in_flight_packets: 0,
            in_flight_bytes: 0,
            stall_started: None,
        }
    }

    fn can_accept_batch(&self) -> bool {
        self.scheduler
            .can_accept(MAX_PACKET_BATCH_SIZE, self.max_batch_bytes)
    }

    fn take_flush_resources(
        &mut self,
    ) -> (
        Vec<BytesMut>,
        GROTable,
        crate::instance::tun_scheduler::DrainStats,
    ) {
        let mut buffers = self
            .spare
            .take()
            .expect("an idle TUN queue owns one write vector");
        let gro_table = self
            .gro_spare
            .take()
            .expect("an idle TUN queue owns one GRO table");
        let stats = self.scheduler.drain_into(&mut buffers, tun_batch_limit());
        debug_assert!(stats.packets != 0);
        self.write_active = true;
        self.in_flight_packets = stats.packets;
        self.in_flight_bytes = stats.bytes;
        (buffers, gro_table, stats)
    }

    fn restore_flush_resources(&mut self, mut buffers: Vec<BytesMut>, gro_table: GROTable) {
        buffers.clear();
        debug_assert!(self.write_active);
        debug_assert!(self.spare.is_none());
        self.spare = Some(buffers);
        self.gro_spare = Some(gro_table);
        self.write_active = false;
        self.in_flight_packets = 0;
        self.in_flight_bytes = 0;
    }

    fn occupancy_packets(&self) -> usize {
        self.scheduler
            .queued_packets()
            .saturating_add(self.in_flight_packets)
    }

    fn occupancy_bytes(&self) -> usize {
        self.scheduler
            .queued_bytes()
            .saturating_add(self.in_flight_bytes)
    }
}

struct LinuxTunSink {
    devices: Vec<Arc<AsyncDevice>>,
    queues: Vec<QueueSink>,
    io_uring_writers: Vec<Option<IoUringTunWriter>>,
    in_flight: FuturesUnordered<SendFuture>,
    telemetry: Arc<DataplaneTelemetry>,
}

impl LinuxTunSink {
    fn new(
        devices: Vec<Arc<AsyncDevice>>,
        mtu: usize,
        telemetry: Arc<DataplaneTelemetry>,
        offload: bool,
    ) -> Self {
        let queues = devices.iter().map(|_| QueueSink::new(mtu)).collect();
        let mut io_uring_writers = vec![None; devices.len()];
        if !offload && linux_tun_uring::enabled() {
            let mut writers = Vec::with_capacity(devices.len());
            for (index, device) in devices.iter().enumerate() {
                match IoUringTunWriter::new(device.as_raw_fd(), index, VIRTIO_NET_HDR_LEN) {
                    Ok(writer) => writers.push(Some(writer)),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            queue = index,
                            "io_uring TUN writer is unavailable; using the portable async writer"
                        );
                        writers.clear();
                        break;
                    }
                }
            }
            if writers.len() == devices.len() {
                tracing::info!(
                    queue_count = writers.len(),
                    "portable Linux TUN uses one io_uring writer per queue"
                );
                io_uring_writers = writers;
            }
        }
        Self {
            devices,
            queues,
            io_uring_writers,
            in_flight: FuturesUnordered::new(),
            telemetry,
        }
    }

    fn record_queue_occupancy(&self, index: usize) {
        let queue = &self.queues[index];
        self.telemetry.set_queue_occupancy(
            DataplaneQueueClass::Tun,
            index,
            queue.occupancy_packets(),
            queue.occupancy_bytes(),
        );
    }

    fn update_stall_state(&mut self) -> bool {
        let now = std::time::Instant::now();
        let mut ready = true;
        for (index, queue) in self.queues.iter_mut().enumerate() {
            if queue.can_accept_batch() {
                if let Some(started) = queue.stall_started.take() {
                    self.telemetry.record_queue_stall(
                        DataplaneQueueClass::Tun,
                        index,
                        now.saturating_duration_since(started),
                    );
                }
            } else {
                ready = false;
                queue.stall_started.get_or_insert(now);
            }
        }
        ready
    }

    fn begin_flush(&mut self) {
        for index in 0..self.queues.len() {
            let queue = &mut self.queues[index];
            if queue.write_active || queue.scheduler.is_empty() {
                continue;
            }
            let schedule_started = DataplaneTelemetry::sample_start();
            let (mut buffers, mut gro_table, stats) = queue.take_flush_resources();
            self.telemetry.record_stage_sample(
                DataplaneStage::TunSchedule,
                schedule_started,
                stats.packets,
                stats.bytes,
            );
            self.record_queue_occupancy(index);
            let write_started = DataplaneTelemetry::sample_start();
            if let Some(writer) = self.io_uring_writers[index].clone() {
                self.in_flight.push(Box::pin(async move {
                    let (result, buffers) = writer.submit(buffers).await;
                    (
                        index,
                        result,
                        buffers,
                        gro_table,
                        stats.packets,
                        write_started,
                        true,
                    )
                }));
            } else {
                let device = self.devices[index].clone();
                self.in_flight.push(Box::pin(async move {
                    let result = device
                        .send_multiple_with_stats(&mut gro_table, &mut buffers, VIRTIO_NET_HDR_LEN)
                        .await;
                    (
                        index,
                        result,
                        buffers,
                        gro_table,
                        stats.packets,
                        write_started,
                        false,
                    )
                }));
            }
        }
    }

    fn poll_complete_in_flight(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        while !self.in_flight.is_empty() {
            match Pin::new(&mut self.in_flight).poll_next(cx) {
                Poll::Ready(Some((
                    index,
                    result,
                    buffers,
                    gro_table,
                    packets,
                    started,
                    used_io_uring,
                ))) => {
                    let (bytes, writes) = result.map_err(TunnelError::IOError)?;
                    if used_io_uring {
                        self.telemetry
                            .record_io(DataplaneIo::IoUringSubmit, 1, packets, bytes);
                    }
                    self.telemetry
                        .record_io(DataplaneIo::TunWrite, writes, packets, bytes);
                    self.telemetry.record_stage_sample(
                        DataplaneStage::TunWrite,
                        started,
                        packets,
                        bytes,
                    );
                    self.queues[index].restore_flush_resources(buffers, gro_table);
                    self.record_queue_occupancy(index);
                }
                Poll::Ready(None) => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn packet_queue_index(packet: &ZCPacket, queue_count: usize) -> usize {
    packet
        .peer_manager_header()
        .and_then(|header| header.flow_shard())
        .map_or(0, |shard| {
            FlowDrrScheduler::<BytesMut>::queue_index(shard, queue_count)
        })
}

struct PlannedTunPacket {
    queue_index: usize,
    shard: u16,
    critical: bool,
    bytes: usize,
    buffer: BytesMut,
}

#[derive(Clone, Copy, Default)]
struct QueueAdmission {
    packets: usize,
    bytes: usize,
}

fn plan_tun_batch(
    batch: PacketBatch,
    queue_count: usize,
) -> Result<SmallVec<[PlannedTunPacket; MAX_PACKET_BATCH_SIZE]>, TunnelError> {
    debug_assert!(queue_count > 0);
    let mut planned: SmallVec<[PlannedTunPacket; MAX_PACKET_BATCH_SIZE]> =
        SmallVec::with_capacity(batch.len());
    for packet in batch {
        let header = packet.peer_manager_header();
        let shard = header.and_then(|header| header.flow_shard()).unwrap_or(0);
        let critical = header.is_some_and(|header| header.is_critical_l2_control());
        let queue_index = packet_queue_index(&packet, queue_count);
        let buffer = packet_into_tun_buffer(packet)?;
        planned.push(PlannedTunPacket {
            queue_index,
            shard,
            critical,
            bytes: buffer.len(),
            buffer,
        });
    }
    Ok(planned)
}

impl Sink<PacketBatch> for LinuxTunSink {
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.as_mut().get_mut();
        this.begin_flush();
        match this.poll_complete_in_flight(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }
        // A completion can make a previously full queue writable. Start its
        // next ready vector before checking admission; otherwise a full
        // scheduler can return Pending with no in-flight future left to wake
        // this sink.
        this.begin_flush();
        if this.update_stall_state() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        let this = self.as_mut().get_mut();
        let planned = plan_tun_batch(batch, this.queues.len())?;
        let mut admissions = SmallVec::<[QueueAdmission; 4]>::new();
        admissions.resize(this.queues.len(), QueueAdmission::default());
        for packet in &planned {
            let admission = &mut admissions[packet.queue_index];
            admission.packets += 1;
            admission.bytes = admission.bytes.saturating_add(packet.bytes);
        }
        for (index, admission) in admissions.iter().enumerate() {
            if !this.queues[index]
                .scheduler
                .can_accept(admission.packets, admission.bytes)
            {
                return Err(TunnelError::BufferFull);
            }
        }
        for packet in planned {
            this.queues[packet.queue_index]
                .scheduler
                .push(packet.shard, packet.buffer, packet.bytes, packet.critical)
                .expect("TUN batch admission was preflighted");
        }
        for (index, admission) in admissions.iter().enumerate() {
            if admission.packets != 0 {
                this.record_queue_occupancy(index);
            }
        }
        this.begin_flush();
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.as_mut().get_mut();
        loop {
            this.begin_flush();
            let schedulers_empty = this.queues.iter().all(|queue| queue.scheduler.is_empty());
            if schedulers_empty && this.in_flight.is_empty() {
                return Poll::Ready(Ok(()));
            }
            ready!(this.poll_complete_in_flight(cx))?;
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().poll_flush(cx)
    }
}
/// Owns the Linux TUN ingress queues and one shared egress sink.
///
/// The owner keeps each kernel queue as an independent stream. Generic tunnel
/// users can still request one merged stream through `split`.
struct LinuxTunTunnel {
    parts: Mutex<Option<SplitIngressTunnel>>,
}

impl LinuxTunTunnel {
    fn new(
        streams: Vec<Pin<Box<dyn PacketBatchStream>>>,
        sink: Pin<Box<dyn PacketBatchSink>>,
    ) -> Self {
        assert!(!streams.is_empty(), "Linux virtual NIC needs one queue");
        Self {
            parts: Mutex::new(Some((streams, sink))),
        }
    }

    fn take_parts(&self) -> SplitIngressTunnel {
        self.parts
            .lock()
            .expect("Linux TUN tunnel owner lock is not poisoned")
            .take()
            .expect("a Linux TUN tunnel can only be split once")
    }
}

impl Tunnel for LinuxTunTunnel {
    fn split(&self) -> SplitTunnel {
        let (streams, sink) = self.take_parts();
        (Box::pin(futures::stream::select_all(streams)), sink)
    }

    fn split_ingress_queues(&self) -> SplitIngressTunnel {
        self.take_parts()
    }

    fn info(&self) -> Option<crate::proto::common::TunnelInfo> {
        None
    }
}

pub(crate) fn wrap_devices(
    devices: Vec<AsyncDevice>,
    mtu: usize,
    telemetry: Arc<DataplaneTelemetry>,
    offload: bool,
) -> Box<dyn Tunnel> {
    assert!(!devices.is_empty(), "Linux virtual NIC needs one queue");
    let devices = devices.into_iter().map(Arc::new).collect::<Vec<_>>();
    let (payload_offset, segment_capacity) = tun_segment_capacity(mtu);
    let reusable_pool = ReusableBufferPool::new(
        segment_capacity,
        devices
            .len()
            .checked_mul(MAX_PACKET_BATCH_SIZE)
            .and_then(|count| count.checked_mul(TUN_BUFFER_BATCHES_PER_QUEUE))
            .expect("the TUN queue buffer count fits usize"),
    );
    let streams = devices
        .iter()
        .map(|device| {
            Box::pin(LinuxTunStream {
                state: ReadState::new(
                    device.clone(),
                    payload_offset,
                    segment_capacity,
                    reusable_pool.clone(),
                    telemetry.clone(),
                ),
            }) as Pin<Box<dyn PacketBatchStream>>
        })
        .collect::<Vec<_>>();
    let sink: Pin<Box<dyn PacketBatchSink>> =
        Box::pin(LinuxTunSink::new(devices, mtu, telemetry, offload));
    Box::new(LinuxTunTunnel::new(streams, sink))
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{Sink, StreamExt, stream};

    use crate::tunnel::{
        BatchStreamItem, PacketBatchSink, PacketBatchStream, Tunnel,
        batch::PacketBatch,
        packet_def::{ZCPacket, ZCPacketType},
    };

    struct TestSink;

    impl Sink<crate::tunnel::batch::PacketBatch> for TestSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(
            self: Pin<&mut Self>,
            _item: crate::tunnel::batch::PacketBatch,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn linux_tap_writer_accepts_owned_packet_batches() {
        fn assert_batch_sink<T: PacketBatchSink>() {}

        assert_batch_sink::<super::LinuxTunSink>();
    }

    #[test]
    fn linux_tunnel_exposes_one_ingress_stream_per_queue() {
        let streams = (0..3)
            .map(|_| {
                Box::pin(stream::empty::<BatchStreamItem>()) as Pin<Box<dyn PacketBatchStream>>
            })
            .collect();
        let sink: Pin<Box<dyn PacketBatchSink>> = Box::pin(TestSink);
        let tunnel = super::LinuxTunTunnel::new(streams, sink);

        let (streams, _sink) = tunnel.split_ingress_queues();
        assert_eq!(streams.len(), 3);
    }

    #[test]
    fn generic_split_merges_linux_ingress_streams() {
        let streams = (0..2)
            .map(|_| {
                Box::pin(stream::empty::<BatchStreamItem>()) as Pin<Box<dyn PacketBatchStream>>
            })
            .collect();
        let sink: Pin<Box<dyn PacketBatchSink>> = Box::pin(TestSink);
        let tunnel = super::LinuxTunTunnel::new(streams, sink);

        let (_stream, _sink) = tunnel.split();
    }

    #[test]
    fn default_ingress_split_keeps_one_stream() {
        let tunnel = crate::tunnel::common::BatchTunnelWrapper::new(
            stream::empty::<BatchStreamItem>(),
            TestSink,
            None,
        );
        let (streams, _sink) = tunnel.split_ingress_queues();
        assert_eq!(streams.len(), 1);
    }

    #[tokio::test]
    async fn ingress_queue_order_is_preserved() {
        let streams = (0..2)
            .map(|queue| {
                let batches = (0..3)
                    .map(|sequence| {
                        Ok(PacketBatch::singleton(ZCPacket::new_with_payload(&[
                            queue as u8,
                            sequence as u8,
                        ])))
                    })
                    .collect::<Vec<_>>();
                Box::pin(stream::iter(batches)) as Pin<Box<dyn PacketBatchStream>>
            })
            .collect();
        let sink: Pin<Box<dyn PacketBatchSink>> = Box::pin(TestSink);
        let tunnel = super::LinuxTunTunnel::new(streams, sink);
        let (mut streams, _sink) = tunnel.split_ingress_queues();

        for (queue, stream) in streams.iter_mut().enumerate() {
            for sequence in 0..3 {
                let batch = stream.next().await.unwrap().unwrap();
                assert_eq!(
                    batch.iter().next().unwrap().payload(),
                    &[queue as u8, sequence]
                );
            }
            assert!(stream.next().await.is_none());
        }
    }

    #[test]
    fn consecutive_gso_reads_carry_overflow_to_the_next_batch() {
        assert_eq!(super::received_batch_partition(0, 54, 64).unwrap(), (54, 0));
        assert_eq!(
            super::received_batch_partition(54, 54, 64).unwrap(),
            (10, 44)
        );
        assert_eq!(
            super::received_batch_partition(0, 54, 16).unwrap(),
            (16, 38)
        );
    }

    #[test]
    fn offload_egress_reuses_packet_headroom_for_virtio_metadata() {
        let mut packet = ZCPacket::new_with_payload(&[0x45, 0, 0, 20]);
        packet = packet.convert_type(ZCPacketType::NIC);

        let buffer = super::packet_into_tun_buffer(packet).unwrap();

        assert_eq!(
            &buffer[..quincy_tun::VIRTIO_NET_HDR_LEN],
            vec![0; quincy_tun::VIRTIO_NET_HDR_LEN]
        );
        assert_eq!(&buffer[quincy_tun::VIRTIO_NET_HDR_LEN..], &[0x45, 0, 0, 20]);
    }

    #[test]
    fn queue_selection_preserves_flow_affinity() {
        let mut first = ZCPacket::new_with_payload(b"first");
        first.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Ethernet as u8);
        first.mut_peer_manager_header().unwrap().set_flow_shard(5);
        let mut second = ZCPacket::new_with_payload(b"second");
        second.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Ethernet as u8);
        second.mut_peer_manager_header().unwrap().set_flow_shard(5);

        assert_eq!(super::packet_queue_index(&first, 2), 1);
        assert_eq!(
            super::packet_queue_index(&first, 2),
            super::packet_queue_index(&second, 2)
        );
    }

    #[test]
    fn queue_sink_reuses_flush_resources() {
        let mut queue = super::QueueSink::new(1380);
        let packet = bytes::BytesMut::from(&[0x45, 0, 0, 20][..]);
        let packet_bytes = packet.len();
        queue
            .scheduler
            .push(1, packet, packet_bytes, false)
            .unwrap();

        let (buffers, gro_table, stats) = queue.take_flush_resources();
        assert_eq!(stats.packets, 1);
        assert!(queue.scheduler.is_empty());
        assert!(queue.write_active);
        assert!(queue.spare.is_none());
        assert!(queue.gro_spare.is_none());

        queue.restore_flush_resources(buffers, gro_table);
        assert_eq!(
            queue.spare.as_ref().unwrap().capacity(),
            super::MAX_PACKET_BATCH_SIZE
        );
        assert!(queue.gro_spare.is_some());
        assert!(!queue.write_active);
    }

    #[test]
    fn queue_sink_drains_one_complete_configured_output_batch() {
        let mut queue = super::QueueSink::new(1380);
        for sequence in 0..super::MAX_PACKET_BATCH_SIZE {
            let packet = bytes::BytesMut::from(&[sequence as u8; 64][..]);
            queue.scheduler.push(1, packet, 64, false).unwrap();
        }

        let (buffers, gro_table, stats) = queue.take_flush_resources();
        let configured = super::tun_batch_limit();

        assert_eq!(stats.packets, configured);
        assert_eq!(
            queue.scheduler.queued_packets(),
            super::MAX_PACKET_BATCH_SIZE - configured
        );
        assert_eq!(
            buffers.iter().map(|buffer| buffer[0]).collect::<Vec<_>>(),
            (0..configured)
                .map(|sequence| sequence as u8)
                .collect::<Vec<_>>()
        );
        queue.restore_flush_resources(buffers, gro_table);
    }

    #[test]
    fn tun_batch_limit_preserves_configured_value_above_old_flush_budget() {
        let old_flush_budget = crate::tunnel::batch::IO_FLUSH_PACKET_BUDGET;
        assert!(old_flush_budget < super::MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            super::bounded_tun_batch_limit(super::MAX_PACKET_BATCH_SIZE),
            super::MAX_PACKET_BATCH_SIZE
        );
        let above_flush_budget = old_flush_budget + 1;
        assert_eq!(
            super::bounded_tun_batch_limit(above_flush_budget),
            above_flush_budget
        );
        assert_eq!(super::bounded_tun_batch_limit(4), 4);
    }
}
