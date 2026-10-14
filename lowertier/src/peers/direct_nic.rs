use std::sync::{Arc, OnceLock, Weak};

use futures::SinkExt;
use parking_lot::RwLock as SyncRwLock;
use smallvec::SmallVec;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, mpsc};

use crate::{
    common::{
        PeerId,
        dataplane_telemetry::{DataplaneQueueClass, DataplaneStage, DataplaneTelemetry},
        global_ctx::ArcGlobalCtx,
        stats_manager::CounterHandle,
    },
    tunnel::{
        PacketBatchSink, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::PacketType,
    },
};

use super::{
    BoxPeerPacketFilter,
    flow::stamp_packet_flow,
    l2_fabric::{L2Fabric, L2IngressBatch},
    peer_manager::{PeerManager, inspect_direct_nic_batch},
    peer_map::PeerMap,
    route_trait::ArcRoute,
    traffic_metrics::TrafficMetricRecorder,
};

const DIRECT_NIC_QUEUE_BATCH_CAPACITY: usize = 3;
pub(super) const DIRECT_NIC_QUEUE_PACKET_CAPACITY: usize =
    MAX_PACKET_BATCH_SIZE * DIRECT_NIC_QUEUE_BATCH_CAPACITY;
const DIRECT_NIC_QUEUE_SLOT_BYTES: usize = 4 * 1024;
const DIRECT_NIC_QUEUE_CREDIT_BYTES: usize =
    DIRECT_NIC_QUEUE_PACKET_CAPACITY * DIRECT_NIC_QUEUE_SLOT_BYTES;
// Preserve the previous data-lane per-batch retained-memory ceiling while
// sharing the aggregate control/data budget in one ordered queue.
const DIRECT_NIC_BATCH_CREDIT_BYTES: usize =
    MAX_PACKET_BATCH_SIZE * 2 * DIRECT_NIC_QUEUE_SLOT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectNicBatchPlan {
    byte_count: u64,
    packet_count: u64,
    queue_credits: u32,
}

pub(super) struct DirectNicDelivery {
    batch: PacketBatch,
    plan: DirectNicBatchPlan,
    byte_count: u64,
    packet_count: u64,
}

struct DirectNicQueueState {
    packets: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicUsize,
    telemetry: Arc<DataplaneTelemetry>,
}

impl DirectNicQueueState {
    fn new(telemetry: Arc<DataplaneTelemetry>) -> Self {
        Self {
            packets: std::sync::atomic::AtomicUsize::new(0),
            bytes: std::sync::atomic::AtomicUsize::new(0),
            telemetry,
        }
    }

    fn acquire(self: &Arc<Self>, plan: DirectNicBatchPlan) -> DirectNicQueueGuard {
        self.packets.fetch_add(
            plan.packet_count as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.bytes.fetch_add(
            plan.queue_credits as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.publish();
        DirectNicQueueGuard {
            state: self.clone(),
            plan,
        }
    }

    fn release(&self, plan: DirectNicBatchPlan) {
        self.packets.fetch_sub(
            plan.packet_count as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.bytes.fetch_sub(
            plan.queue_credits as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.publish();
    }

    fn publish(&self) {
        self.telemetry.set_queue_occupancy(
            DataplaneQueueClass::DirectNic,
            0,
            self.packets.load(std::sync::atomic::Ordering::Relaxed),
            self.bytes.load(std::sync::atomic::Ordering::Relaxed),
        );
    }
}

struct DirectNicQueueGuard {
    state: Arc<DirectNicQueueState>,
    plan: DirectNicBatchPlan,
}

impl Drop for DirectNicQueueGuard {
    fn drop(&mut self) {
        self.state.release(self.plan);
    }
}

struct DirectNicWork {
    batch: PacketBatch,
    queue_guard: DirectNicQueueGuard,
    queue_credits: OwnedSemaphorePermit,
}

struct DirectNicWriteBatch {
    batch: PacketBatch,
    ownership:
        SmallVec<[(DirectNicQueueGuard, OwnedSemaphorePermit); DIRECT_NIC_QUEUE_BATCH_CAPACITY]>,
}

impl DirectNicWriteBatch {
    fn new(work: DirectNicWork) -> Self {
        let DirectNicWork {
            batch,
            queue_guard,
            queue_credits,
        } = work;
        let mut ownership = SmallVec::new();
        ownership.push((queue_guard, queue_credits));
        Self { batch, ownership }
    }

    fn try_append(&mut self, work: DirectNicWork) -> Result<(), DirectNicWork> {
        if self.batch.len().saturating_add(work.batch.len()) > MAX_PACKET_BATCH_SIZE {
            return Err(work);
        }
        let DirectNicWork {
            batch,
            queue_guard,
            queue_credits,
        } = work;
        self.batch
            .try_append(batch)
            .expect("the direct NIC write batch checks its packet bound");
        self.ownership.push((queue_guard, queue_credits));
        Ok(())
    }
}

pub(crate) struct DirectNicEndpoint {
    sender: mpsc::Sender<DirectNicWork>,
    queue_credits: Arc<Semaphore>,
    queue_state: Arc<DirectNicQueueState>,
    terminal_error: Arc<OnceLock<String>>,
}

impl DirectNicEndpoint {
    fn terminal_error(&self) -> TunnelError {
        self.terminal_error
            .get()
            .map_or(TunnelError::Shutdown, |error| {
                TunnelError::InternalError(format!("direct NIC writer failed: {error}"))
            })
    }

    async fn enqueue(
        &self,
        batch: PacketBatch,
        plan: DirectNicBatchPlan,
    ) -> Result<(), TunnelError> {
        if self.terminal_error.get().is_some() {
            return Err(self.terminal_error());
        }
        let _stage = self.queue_state.telemetry.sample_stage(
            DataplaneStage::DirectNicAdmission,
            plan.packet_count as usize,
            plan.byte_count as usize,
        );
        let permit = match self
            .queue_credits
            .clone()
            .try_acquire_many_owned(plan.queue_credits)
        {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                let started = std::time::Instant::now();
                let result = self
                    .queue_credits
                    .clone()
                    .acquire_many_owned(plan.queue_credits)
                    .await
                    .map_err(|_| self.terminal_error());
                self.queue_state.telemetry.record_queue_stall(
                    DataplaneQueueClass::DirectNic,
                    0,
                    started.elapsed(),
                );
                result?
            }
            Err(tokio::sync::TryAcquireError::Closed) => return Err(self.terminal_error()),
        };
        let work = DirectNicWork {
            batch,
            queue_guard: self.queue_state.acquire(plan),
            queue_credits: permit,
        };
        match self.sender.try_send(work) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(work)) => {
                let started = std::time::Instant::now();
                let result = self
                    .sender
                    .send(work)
                    .await
                    .map_err(|_| self.terminal_error());
                self.queue_state.telemetry.record_queue_stall(
                    DataplaneQueueClass::DirectNic,
                    0,
                    started.elapsed(),
                );
                result
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self.terminal_error()),
        }
    }
}

fn finish_direct_nic_batch(
    mut batch: PacketBatch,
    byte_count: usize,
    mut retained_bytes: usize,
) -> Result<DirectNicDelivery, TunnelError> {
    if batch.len() > MAX_PACKET_BATCH_SIZE {
        return Err(TunnelError::ExceedMaxPacketSize(
            MAX_PACKET_BATCH_SIZE,
            batch.len(),
        ));
    }
    let packet_credits = batch
        .len()
        .checked_mul(DIRECT_NIC_QUEUE_SLOT_BYTES)
        .ok_or_else(|| TunnelError::InternalError("direct NIC packet credits overflow".into()))?;
    let mut queue_credits = retained_bytes.max(packet_credits);
    if queue_credits > DIRECT_NIC_BATCH_CREDIT_BYTES
        && byte_count.max(packet_credits) <= DIRECT_NIC_BATCH_CREDIT_BYTES
    {
        retained_bytes = 0;
        for packet in batch.iter_mut() {
            packet.compact_retained_buffer();
            retained_bytes = retained_bytes.saturating_add(packet.retained_buffer_capacity());
        }
        queue_credits = retained_bytes.max(packet_credits);
    }
    if queue_credits > DIRECT_NIC_BATCH_CREDIT_BYTES {
        return Err(TunnelError::ExceedMaxPacketSize(
            DIRECT_NIC_BATCH_CREDIT_BYTES,
            queue_credits,
        ));
    }
    let plan = DirectNicBatchPlan {
        byte_count: byte_count as u64,
        packet_count: batch.len() as u64,
        queue_credits: u32::try_from(queue_credits).expect("direct NIC credits fit u32"),
    };
    Ok(DirectNicDelivery {
        batch,
        plan,
        byte_count: byte_count as u64,
        packet_count: plan.packet_count,
    })
}

pub(super) fn plan_direct_nic_delivery(
    mut batch: PacketBatch,
) -> Result<DirectNicDelivery, TunnelError> {
    debug_assert!(!batch.is_empty());
    let mut byte_count = 0_usize;
    let mut retained_bytes = 0_usize;
    for packet in batch.iter_mut() {
        stamp_packet_flow(packet);
        byte_count = byte_count.saturating_add(packet.buf_len());
        retained_bytes = retained_bytes.saturating_add(packet.retained_buffer_capacity());
    }
    finish_direct_nic_batch(batch, byte_count, retained_bytes)
}

fn collect_direct_nic_write_batch(
    first: DirectNicWork,
    receiver: &mut mpsc::Receiver<DirectNicWork>,
    pending: &mut Option<DirectNicWork>,
) -> DirectNicWriteBatch {
    let mut write = DirectNicWriteBatch::new(first);
    while write.batch.len() < MAX_PACKET_BATCH_SIZE {
        let work = match receiver.try_recv() {
            Ok(work) => work,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        if let Err(work) = write.try_append(work) {
            *pending = Some(work);
            break;
        }
    }
    write
}

async fn feed_direct_nic_write_batch(
    sink: &mut std::pin::Pin<Box<dyn PacketBatchSink>>,
    write: DirectNicWriteBatch,
) -> Result<(), TunnelError> {
    let DirectNicWriteBatch {
        batch,
        ownership: _ownership,
    } = write;
    sink.feed(batch).await?;
    Ok(())
}

fn record_direct_nic_writer_failure(
    terminal_error: &OnceLock<String>,
    global_ctx: &ArcGlobalCtx,
    error: TunnelError,
) {
    let error = error.to_string();
    let _ = terminal_error.set(error.clone());
    global_ctx.set_tun_device_error(format!("TUN write failed: {error}"));
    tracing::error!(%error, "direct NIC writer failed");
}

async fn run_direct_nic_writer(
    mut sink: std::pin::Pin<Box<dyn PacketBatchSink>>,
    mut receiver: mpsc::Receiver<DirectNicWork>,
    terminal_error: Arc<OnceLock<String>>,
    global_ctx: ArcGlobalCtx,
) {
    let mut pending = None;
    while let Some(work) = match pending.take() {
        Some(work) => Some(work),
        None => receiver.recv().await,
    } {
        let write = collect_direct_nic_write_batch(work, &mut receiver, &mut pending);
        if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
            record_direct_nic_writer_failure(&terminal_error, &global_ctx, error);
            return;
        }

        loop {
            if let Some(work) = pending.take() {
                let write = collect_direct_nic_write_batch(work, &mut receiver, &mut pending);
                if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
                    record_direct_nic_writer_failure(&terminal_error, &global_ctx, error);
                    return;
                }
                continue;
            }
            tokio::select! {
                biased;
                next = receiver.recv() => {
                    match next {
                        Some(work) => {
                            let write = collect_direct_nic_write_batch(
                                work,
                                &mut receiver,
                                &mut pending,
                            );
                            if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
                                record_direct_nic_writer_failure(
                                    &terminal_error,
                                    &global_ctx,
                                    error,
                                );
                                return;
                            }
                        }
                        None => {
                            if let Err(error) = sink.flush().await {
                                record_direct_nic_writer_failure(
                                    &terminal_error,
                                    &global_ctx,
                                    error,
                                );
                            }
                            return;
                        }
                    }
                }
                result = sink.flush() => {
                    match result {
                        Ok(()) => {
                            break;
                        }
                        Err(error) => {
                            record_direct_nic_writer_failure(
                                &terminal_error,
                                &global_ctx,
                                error,
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct DirectNicBatchWriter {
    endpoint: SyncRwLock<Weak<DirectNicEndpoint>>,
}

impl DirectNicBatchWriter {
    pub(super) fn install(
        &self,
        sink: std::pin::Pin<Box<dyn PacketBatchSink>>,
        global_ctx: ArcGlobalCtx,
    ) -> Arc<DirectNicEndpoint> {
        let (sender, receiver) = mpsc::channel(DIRECT_NIC_QUEUE_BATCH_CAPACITY);
        let terminal_error = Arc::new(OnceLock::new());
        let queue_state = Arc::new(DirectNicQueueState::new(
            global_ctx.dataplane_telemetry().clone(),
        ));
        let endpoint = Arc::new(DirectNicEndpoint {
            sender,
            queue_credits: Arc::new(Semaphore::new(DIRECT_NIC_QUEUE_CREDIT_BYTES)),
            queue_state,
            terminal_error: terminal_error.clone(),
        });
        *self.endpoint.write() = Arc::downgrade(&endpoint);
        tokio::spawn(run_direct_nic_writer(
            sink,
            receiver,
            terminal_error,
            global_ctx,
        ));
        endpoint
    }

    pub(super) fn current_endpoint(&self) -> Option<Arc<DirectNicEndpoint>> {
        self.endpoint.read().upgrade()
    }

    pub(super) async fn send_to(
        endpoint: Arc<DirectNicEndpoint>,
        delivery: DirectNicDelivery,
    ) -> Result<(), TunnelError> {
        endpoint.enqueue(delivery.batch, delivery.plan).await
    }
}

pub(super) struct DirectNicIngress {
    pub(super) my_peer_id: PeerId,
    pub(super) peers: Weak<PeerMap>,
    pub(super) global_ctx: ArcGlobalCtx,
    pub(super) route: ArcRoute,
    pub(super) l2_fabric: Arc<L2Fabric>,
    pub(super) traffic_metrics: Arc<TrafficMetricRecorder>,
    pub(super) peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    pub(super) ethernet_input: bool,
    pub(super) nic: Arc<DirectNicBatchWriter>,
    pub(super) self_rx_bytes: CounterHandle,
    pub(super) self_rx_packets: CounterHandle,
}

impl DirectNicIngress {
    pub(crate) async fn try_process(&self, mut batch: PacketBatch) -> Result<(), PacketBatch> {
        let _stage = self
            .global_ctx
            .dataplane_telemetry()
            .sample_stage_with_shape(DataplaneStage::DirectNicIngress, || {
                (batch.len(), batch.buffer_byte_len())
            });
        let Some(peers) = self.peers.upgrade() else {
            return Err(batch);
        };
        let Some(endpoint) = self.nic.current_endpoint() else {
            return Err(batch);
        };
        for packet in batch.iter_mut() {
            if packet.parsed_metadata().is_none() && packet.refresh_parsed_metadata().is_none() {
                return Err(batch);
            }
        }

        let Some((from_peer_id, packet_type)) =
            inspect_direct_nic_batch(&batch, self.my_peer_id, self.ethernet_input, &mut |_, _| {})
        else {
            return Err(batch);
        };

        if packet_type == PacketType::Ethernet as u8
            && !PeerManager::credential_ethernet_peer_is_allowed(&peers, packet_type, from_peer_id)
                .await
        {
            tracing::warn!(
                from_peer_id,
                "drop ethernet batch from suppressed credential peer"
            );
            return Ok(());
        }
        if packet_type == PacketType::Ethernet as u8 {
            let mut authorized = true;
            for packet in &batch {
                if !PeerManager::full_ethernet_receive_is_authorized(
                    &peers,
                    None,
                    &self.global_ctx,
                    self.my_peer_id,
                    packet,
                ) {
                    authorized = false;
                    break;
                }
            }
            if !authorized {
                tracing::debug!(from_peer_id, "drop complete Ethernet from a hybrid peer");
                return Ok(());
            }
        }

        let local_ipv4 = self.global_ctx.get_ipv4();
        let batch = self
            .global_ctx
            .get_acl_filter()
            .process_packet_batch_with_acl(
                batch,
                true,
                local_ipv4.map(|address| address.address()),
                |destination| self.global_ctx.is_ip_local_ipv6(&destination),
                self.route.as_ref(),
            );
        if batch.is_empty() {
            return Ok(());
        }

        let mut batch = batch;
        {
            let pipelines = self.peer_packet_process_pipeline.read().await;
            for pipeline in pipelines.iter().rev() {
                if pipeline.is_direct_nic_terminal()
                    || !pipeline.is_interested_in_direct_nic_batch(&batch)
                {
                    continue;
                }
                batch = pipeline.try_process_batch_from_peer(batch).await;
                if batch.is_empty() {
                    return Ok(());
                }
            }
        }

        if self.ethernet_input
            && (packet_type == PacketType::Ethernet as u8 || self.l2_fabric.needs_tap_admission())
        {
            let now = std::time::Instant::now();
            let local_broadcast = local_ipv4.map(|network| network.last_address());
            let mut ingress_batch = L2IngressBatch::default();
            let keep: SmallVec<[bool; 64]> = batch
                .iter()
                .map(|packet| {
                    if packet_type == PacketType::Ethernet as u8 {
                        self.l2_fabric.admit_ingress_batch_at(
                            packet.payload(),
                            from_peer_id,
                            self.my_peer_id,
                            now,
                            &mut ingress_batch,
                        )
                    } else {
                        PeerManager::admit_compact_to_tap(
                            &self.l2_fabric,
                            packet.payload(),
                            from_peer_id,
                            local_broadcast,
                            now,
                        )
                    }
                })
                .collect();
            batch.retain_flags(&keep);
            if batch.is_empty() {
                return Ok(());
            }
        }
        // Stamp flow shards, account bytes and size the bounded TUN admission
        // in one pass while the cleartext tuple is still available.
        let delivery = match plan_direct_nic_delivery(batch) {
            Ok(delivery) => delivery,
            Err(error) => {
                tracing::error!(?error, "prepare direct packet batch for NIC failed");
                return Ok(());
            }
        };
        self.self_rx_bytes.add(delivery.byte_count);
        self.self_rx_packets.add(delivery.packet_count);
        if !self.traffic_metrics.try_record_rx_batch(
            from_peer_id,
            packet_type,
            delivery.byte_count,
            delivery.packet_count,
        ) {
            self.traffic_metrics
                .record_rx_batch(
                    from_peer_id,
                    packet_type,
                    delivery.byte_count,
                    delivery.packet_count,
                )
                .await;
        }

        if let Err(error) = DirectNicBatchWriter::send_to(endpoint, delivery).await {
            tracing::error!(?error, "send direct packet batch to NIC failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{batch::PacketBatch, packet_def::ZCPacket},
    };
    use futures::StreamExt;
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    #[derive(Debug, PartialEq, Eq)]
    enum DirectNicWriterEvent {
        Start(Vec<u8>),
        Flush,
    }

    struct ImmediateFlushDirectNicSink {
        events: futures::channel::mpsc::UnboundedSender<DirectNicWriterEvent>,
    }

    impl futures::Sink<PacketBatch> for ImmediateFlushDirectNicSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            self.get_mut()
                .events
                .unbounded_send(DirectNicWriterEvent::Start(
                    batch.iter().map(|packet| packet.payload()[0]).collect(),
                ))
                .map_err(|_| crate::tunnel::TunnelError::Shutdown)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.get_mut()
                .events
                .unbounded_send(DirectNicWriterEvent::Flush)
                .map_err(|_| crate::tunnel::TunnelError::Shutdown)?;
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    fn direct_nic_writer_batch(marker: u8, packet_count: usize) -> DirectNicDelivery {
        let mut batch = PacketBatch::new();
        for sequence in 0..packet_count {
            batch
                .try_push(ZCPacket::new_with_payload(&[marker, sequence as u8]))
                .unwrap();
        }
        plan_direct_nic_delivery(batch).unwrap()
    }

    #[tokio::test]
    async fn direct_nic_writer_coalesces_ready_batches_in_order() {
        let global_ctx = get_mock_global_ctx();
        let (sender, receiver) = tokio::sync::mpsc::channel(3);
        let terminal_error = Arc::new(std::sync::OnceLock::new());
        let queue_state = Arc::new(DirectNicQueueState::new(
            global_ctx.dataplane_telemetry().clone(),
        ));
        let endpoint = Arc::new(DirectNicEndpoint {
            sender,
            queue_credits: Arc::new(tokio::sync::Semaphore::new(DIRECT_NIC_QUEUE_CREDIT_BYTES)),
            queue_state,
            terminal_error: terminal_error.clone(),
        });
        let first = direct_nic_writer_batch(1, 2);
        endpoint.enqueue(first.batch, first.plan).await.unwrap();
        let second = direct_nic_writer_batch(2, 2);
        endpoint.enqueue(second.batch, second.plan).await.unwrap();
        drop(endpoint);

        let (events_tx, mut events_rx) = futures::channel::mpsc::unbounded();
        run_direct_nic_writer(
            Box::pin(ImmediateFlushDirectNicSink { events: events_tx }),
            receiver,
            terminal_error,
            global_ctx,
        )
        .await;

        assert_eq!(
            events_rx.next().await,
            Some(DirectNicWriterEvent::Start(vec![1, 1, 2, 2]))
        );
        assert_eq!(events_rx.next().await, Some(DirectNicWriterEvent::Flush));
        assert_eq!(events_rx.next().await, None);
    }
}
