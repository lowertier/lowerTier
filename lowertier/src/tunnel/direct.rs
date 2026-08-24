use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::future::poll_fn;
use tokio::{
    sync::{Notify, mpsc, watch},
    time::{Instant, timeout_at},
};

use super::{
    PacketBatchSink, PacketBatchStream, Tunnel, TunnelError,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, SEND_PIPELINE_SLOT_COUNT},
    packet_def::{PacketType, ZCPacket},
};
use crate::common::global_ctx::{ProcessMemoryGovernor, ProcessMemoryPermit};

const DIRECT_CONTROL_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE;
const DIRECT_DATA_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE * SEND_PIPELINE_SLOT_COUNT;
const DIRECT_CONTROL_BYTE_BUDGET: usize = 16 * 1024;
const DIRECT_DATA_BYTE_BUDGET: usize = 128 * 1024 * SEND_PIPELINE_SLOT_COUNT;
const DIRECT_PACKET_OVERHEAD: usize = std::mem::size_of::<ZCPacket>();
const MAX_CONSECUTIVE_CONTROL_SENDS: usize = 8;
// A scalar producer can fill every packet position in the stable job window.
const DIRECT_INFLIGHT_RUN_CAPACITY: usize = DIRECT_DATA_PACKET_BUDGET;

type BoxedPacketBatchSink = Pin<Box<dyn PacketBatchSink>>;

struct DirectSinkState {
    ownership_budget: Arc<AdmissionBudget>,
    control_budget: Arc<AdmissionBudget>,
    terminal_error: OnceLock<String>,
    terminal_tx: watch::Sender<()>,
    control_tx: mpsc::Sender<DirectSendWork>,
    data_tx: mpsc::Sender<DirectSendWork>,
}

struct DirectSendWork {
    batch: PacketBatch,
    ownership: AdmissionPermit,
    deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectBatchPlan {
    control: bool,
    packet_count: usize,
    byte_count: usize,
}

struct AdmissionBudget {
    packet_capacity: usize,
    byte_capacity: usize,
    run_capacity: Option<usize>,
    packets_in_use: AtomicUsize,
    bytes_in_use: AtomicUsize,
    runs_in_use: AtomicUsize,
    wake: Notify,
    process_memory: Option<Arc<ProcessMemoryGovernor>>,
}

struct AdmissionPermit {
    budget: Arc<AdmissionBudget>,
    packet_count: usize,
    byte_count: usize,
    run_count: usize,
    _process_memory: Option<ProcessMemoryPermit>,
}

impl DirectSinkState {
    fn new(
        sink: BoxedPacketBatchSink,
        close_timeout: Option<Duration>,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Arc<Self> {
        let data_run_capacity = DIRECT_INFLIGHT_RUN_CAPACITY;
        let (terminal_tx, _) = watch::channel(());
        let (control_tx, control_rx) = mpsc::channel(2);
        let (data_tx, data_rx) = mpsc::channel(data_run_capacity);
        let state = Arc::new(Self {
            ownership_budget: Arc::new(AdmissionBudget::with_process_and_runs(
                DIRECT_DATA_PACKET_BUDGET,
                DIRECT_DATA_BYTE_BUDGET,
                data_run_capacity,
                process_memory.clone(),
            )),
            control_budget: Arc::new(AdmissionBudget::with_process(
                DIRECT_CONTROL_PACKET_BUDGET,
                DIRECT_CONTROL_BYTE_BUDGET,
                process_memory,
            )),
            terminal_error: OnceLock::new(),
            terminal_tx,
            control_tx,
            data_tx,
        });
        tokio::spawn(run_direct_sink_owner(
            Arc::downgrade(&state),
            sink,
            control_rx,
            data_rx,
            close_timeout,
        ));
        state
    }
}

impl AdmissionBudget {
    fn with_process(
        packet_capacity: usize,
        byte_capacity: usize,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Self {
        Self::with_optional_runs(packet_capacity, byte_capacity, None, process_memory)
    }

    fn with_process_and_runs(
        packet_capacity: usize,
        byte_capacity: usize,
        run_capacity: usize,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Self {
        Self::with_optional_runs(
            packet_capacity,
            byte_capacity,
            Some(run_capacity),
            process_memory,
        )
    }

    fn with_optional_runs(
        packet_capacity: usize,
        byte_capacity: usize,
        run_capacity: Option<usize>,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Self {
        Self {
            packet_capacity,
            byte_capacity,
            run_capacity,
            packets_in_use: AtomicUsize::new(0),
            bytes_in_use: AtomicUsize::new(0),
            runs_in_use: AtomicUsize::new(0),
            wake: Notify::new(),
            process_memory,
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        packet_count: usize,
        byte_count: usize,
    ) -> Option<AdmissionPermit> {
        if packet_count > self.packet_capacity || byte_count > self.byte_capacity {
            return None;
        }

        let process_memory = if byte_count == 0 {
            None
        } else if let Some(governor) = self.process_memory.as_ref() {
            Some(governor.try_reserve_owned(byte_count)?)
        } else {
            None
        };

        loop {
            let current_packets = self.packets_in_use.load(Ordering::Acquire);
            let next_packets = current_packets.checked_add(packet_count)?;
            if next_packets > self.packet_capacity {
                return None;
            }
            if self
                .packets_in_use
                .compare_exchange(
                    current_packets,
                    next_packets,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            let current_bytes = self.bytes_in_use.load(Ordering::Acquire);
            let Some(next_bytes) = current_bytes.checked_add(byte_count) else {
                self.packets_in_use
                    .fetch_sub(packet_count, Ordering::AcqRel);
                self.wake.notify_one();
                return None;
            };
            if next_bytes > self.byte_capacity {
                self.packets_in_use
                    .fetch_sub(packet_count, Ordering::AcqRel);
                self.wake.notify_one();
                return None;
            }
            if self
                .bytes_in_use
                .compare_exchange(
                    current_bytes,
                    next_bytes,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let run_count = if let Some(run_capacity) = self.run_capacity {
                    loop {
                        let current_runs = self.runs_in_use.load(Ordering::Acquire);
                        let Some(next_runs) = current_runs.checked_add(1) else {
                            self.packets_in_use
                                .fetch_sub(packet_count, Ordering::AcqRel);
                            self.bytes_in_use.fetch_sub(byte_count, Ordering::AcqRel);
                            return None;
                        };
                        if next_runs > run_capacity {
                            self.packets_in_use
                                .fetch_sub(packet_count, Ordering::AcqRel);
                            self.bytes_in_use.fetch_sub(byte_count, Ordering::AcqRel);
                            return None;
                        }
                        if self
                            .runs_in_use
                            .compare_exchange(
                                current_runs,
                                next_runs,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            break 1;
                        }
                    }
                } else {
                    0
                };
                return Some(AdmissionPermit {
                    budget: self.clone(),
                    packet_count,
                    byte_count,
                    run_count,
                    _process_memory: process_memory,
                });
            }

            self.packets_in_use
                .fetch_sub(packet_count, Ordering::AcqRel);
            self.wake.notify_one();
        }
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.budget
            .packets_in_use
            .fetch_sub(self.packet_count, Ordering::AcqRel);
        self.budget
            .bytes_in_use
            .fetch_sub(self.byte_count, Ordering::AcqRel);
        if self.run_count != 0 {
            self.budget
                .runs_in_use
                .fetch_sub(self.run_count, Ordering::AcqRel);
        }
        self.budget.wake.notify_one();
    }
}

#[derive(Clone)]
pub struct DirectTunnelSender {
    state: Arc<DirectSinkState>,
    send_timeout: Option<Duration>,
}

impl DirectTunnelSender {
    pub fn send(&self, packet: ZCPacket) -> impl Future<Output = Result<(), TunnelError>> + '_ {
        self.send_batch(PacketBatch::singleton(packet))
    }

    pub fn send_batch(
        &self,
        mut batch: PacketBatch,
    ) -> impl Future<Output = Result<(), TunnelError>> + '_ {
        async move {
            if batch.is_empty() {
                return Ok(());
            }
            let plan = plan_direct_batch(&mut batch)?;
            let deadline = self.send_timeout.map(|duration| Instant::now() + duration);
            let ownership = run_until(acquire_batch_ownership(&self.state, plan), deadline).await?;
            self.enqueue_run(batch, ownership, plan.control, deadline)
                .await
        }
    }

    async fn enqueue_run(
        &self,
        batch: PacketBatch,
        ownership: AdmissionPermit,
        control: bool,
        deadline: Option<Instant>,
    ) -> Result<(), TunnelError> {
        debug_assert!(!batch.is_empty());

        let mut terminal = self.state.terminal_tx.subscribe();
        if self.state.terminal_error.get().is_some() {
            return Err(self.terminal_error());
        }
        let work = DirectSendWork {
            batch,
            ownership,
            deadline,
        };
        let sender = if control {
            &self.state.control_tx
        } else {
            &self.state.data_tx
        };
        tokio::select! {
            biased;
            _ = terminal.changed() => return Err(self.terminal_error()),
            result = sender.send(work) => {
                if result.is_err() {
                    return Err(self.terminal_error());
                }
            }
        }
        Ok(())
    }

    fn terminal_error(&self) -> TunnelError {
        TunnelError::InternalError(
            self.state
                .terminal_error
                .get()
                .cloned()
                .unwrap_or_else(|| "direct tunnel sink owner stopped".to_owned()),
        )
    }
}

fn earliest_deadline(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

async fn start_direct_batch(
    sink: &mut BoxedPacketBatchSink,
    batch: PacketBatch,
    deadline: Option<Instant>,
) -> Result<(), String> {
    run_until(poll_fn(|cx| sink.as_mut().poll_ready(cx)), deadline)
        .await
        .map_err(|error| format!("direct tunnel sink failed: {error}"))?;
    sink.as_mut()
        .start_send(batch)
        .map_err(|error| format!("direct tunnel sink failed: {error}"))
}

async fn start_pending_direct_batch(
    sink: &mut BoxedPacketBatchSink,
    pending_batch: &mut Option<PacketBatch>,
    pending_deadline: &mut Option<Instant>,
) -> Result<(), String> {
    let Some(batch) = pending_batch.take() else {
        return Ok(());
    };
    let deadline = pending_deadline.take();
    start_direct_batch(sink, batch, deadline).await
}

async fn accumulate_direct_data_batch(
    sink: &mut BoxedPacketBatchSink,
    pending_batch: &mut Option<PacketBatch>,
    pending_deadline: &mut Option<Instant>,
    batch: PacketBatch,
    deadline: Option<Instant>,
) -> Result<(), String> {
    if pending_batch
        .as_ref()
        .is_some_and(|pending| pending.len() + batch.len() > MAX_PACKET_BATCH_SIZE)
    {
        start_pending_direct_batch(sink, pending_batch, pending_deadline).await?;
    }

    if pending_batch.is_none() && batch.len() == MAX_PACKET_BATCH_SIZE {
        return start_direct_batch(sink, batch, deadline).await;
    }

    if pending_batch.is_none() {
        let mut pooled_batch = PacketBatch::new();
        pooled_batch.mark_inline_crypto();
        *pending_batch = Some(pooled_batch);
        *pending_deadline = deadline;
    } else {
        *pending_deadline = earliest_deadline(*pending_deadline, deadline);
    }
    pending_batch
        .as_mut()
        .expect("the pooled direct batch was installed")
        .try_append(batch)
        .expect("coalesced direct batches remain bounded");

    if pending_batch
        .as_ref()
        .is_some_and(|pending| pending.len() == MAX_PACKET_BATCH_SIZE)
    {
        start_pending_direct_batch(sink, pending_batch, pending_deadline).await?;
    }
    Ok(())
}

async fn run_direct_sink_owner(
    state: std::sync::Weak<DirectSinkState>,
    mut sink: BoxedPacketBatchSink,
    mut control_rx: mpsc::Receiver<DirectSendWork>,
    mut data_rx: mpsc::Receiver<DirectSendWork>,
    close_timeout: Option<Duration>,
) {
    let mut consecutive_control = 0_usize;
    let mut pending_work: Option<(DirectSendWork, bool)> = None;
    let mut started_ownerships = Vec::with_capacity(DIRECT_INFLIGHT_RUN_CAPACITY);

    loop {
        debug_assert!(started_ownerships.is_empty());
        if pending_work.is_none() && control_rx.is_closed() && data_rx.is_closed() {
            close_sink(&mut sink, close_timeout).await;
            break;
        }

        let next = if let Some((work, control_lane)) = pending_work.take() {
            if !control_lane && consecutive_control < MAX_CONSECUTIVE_CONTROL_SENDS {
                match control_rx.try_recv() {
                    Ok(control_work) => {
                        pending_work = Some((work, false));
                        Some((control_work, true))
                    }
                    Err(mpsc::error::TryRecvError::Empty)
                    | Err(mpsc::error::TryRecvError::Disconnected) => Some((work, false)),
                }
            } else {
                Some((work, control_lane))
            }
        } else if consecutive_control >= MAX_CONSECUTIVE_CONTROL_SENDS {
            tokio::select! {
                biased;
                work = data_rx.recv(), if !data_rx.is_closed() => work.map(|work| (work, false)),
                work = control_rx.recv(), if !control_rx.is_closed() => work.map(|work| (work, true)),
            }
        } else {
            tokio::select! {
                biased;
                work = control_rx.recv(), if !control_rx.is_closed() => work.map(|work| (work, true)),
                work = data_rx.recv(), if !data_rx.is_closed() => work.map(|work| (work, false)),
            }
        };

        let Some((work, control_lane)) = next else {
            if control_rx.is_closed() && data_rx.is_closed() {
                close_sink(&mut sink, close_timeout).await;
                break;
            }
            continue;
        };
        if control_lane {
            consecutive_control = consecutive_control.saturating_add(1);
        } else {
            consecutive_control = 0;
        }

        let mut flush_deadline = None;

        let start_result = if control_lane {
            let DirectSendWork {
                batch,
                ownership,
                deadline,
            } = work;
            flush_deadline = deadline;
            started_ownerships.push(ownership);
            start_direct_batch(&mut sink, batch, deadline).await
        } else {
            let mut started_packets = 0_usize;
            let mut current = Some(work);
            let mut pending_batch = None;
            let mut pending_batch_deadline = None;
            let mut yielded_for_fill = false;
            let mut result = Ok(());

            loop {
                if let Some(work) = current.take() {
                    let packet_count = work.batch.len();
                    if started_packets.saturating_add(packet_count) > DIRECT_DATA_PACKET_BUDGET {
                        pending_work = Some((work, false));
                        break;
                    }
                    let DirectSendWork {
                        batch,
                        ownership,
                        deadline,
                    } = work;
                    started_packets = started_packets.saturating_add(packet_count);
                    flush_deadline = earliest_deadline(flush_deadline, deadline);
                    started_ownerships.push(ownership);
                    if let Err(message) = accumulate_direct_data_batch(
                        &mut sink,
                        &mut pending_batch,
                        &mut pending_batch_deadline,
                        batch,
                        deadline,
                    )
                    .await
                    {
                        result = Err(message);
                        break;
                    }
                }

                match control_rx.try_recv() {
                    Ok(work) => {
                        pending_work = Some((work, true));
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => {}
                }

                if started_packets >= DIRECT_DATA_PACKET_BUDGET {
                    break;
                }

                match data_rx.try_recv() {
                    Ok(work) => current = Some(work),
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                    Err(mpsc::error::TryRecvError::Empty) if !yielded_for_fill => {
                        yielded_for_fill = true;
                        tokio::task::yield_now().await;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }

            if result.is_ok()
                && let Err(message) = start_pending_direct_batch(
                    &mut sink,
                    &mut pending_batch,
                    &mut pending_batch_deadline,
                )
                .await
            {
                result = Err(message);
            }
            result
        };

        if let Err(message) = start_result {
            started_ownerships.clear();
            if let Some(state) = state.upgrade() {
                set_terminal_error(&state, message);
            }
            close_sink(&mut sink, close_timeout).await;
            return;
        }

        if started_ownerships.is_empty() {
            continue;
        }

        match run_until(poll_fn(|cx| sink.as_mut().poll_flush(cx)), flush_deadline).await {
            Ok(()) => started_ownerships.clear(),
            Err(error) => {
                let message = format!("direct tunnel sink failed: {error}");
                started_ownerships.clear();
                if let Some(state) = state.upgrade() {
                    set_terminal_error(&state, message);
                }
                close_sink(&mut sink, close_timeout).await;
                break;
            }
        }
    }
}

async fn acquire_batch_ownership(
    state: &DirectSinkState,
    plan: DirectBatchPlan,
) -> Result<AdmissionPermit, TunnelError> {
    if state.terminal_error.get().is_some() {
        return Err(state.terminal_error_value());
    }
    let budget = if plan.control {
        &state.control_budget
    } else {
        &state.ownership_budget
    };
    acquire_budget_or_terminal(state, budget.clone(), plan.packet_count, plan.byte_count).await
}

pub struct DirectTunnel<T> {
    _tunnel: T,
    stream: Option<Pin<Box<dyn PacketBatchStream>>>,
    sender: DirectTunnelSender,
}

impl<T: Tunnel> DirectTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        Self::new_with_process_memory(tunnel, send_timeout, None)
    }

    pub(crate) fn new_with_process_memory(
        tunnel: T,
        send_timeout: Option<Duration>,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Self {
        let (stream, sink) = tunnel.split();
        let state = DirectSinkState::new(sink, send_timeout, process_memory);

        Self {
            _tunnel: tunnel,
            stream: Some(stream),
            sender: DirectTunnelSender {
                state,
                send_timeout,
            },
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn PacketBatchStream>> {
        self.stream.take().expect("the direct stream is taken once")
    }

    pub fn get_sink(&self) -> DirectTunnelSender {
        self.sender.clone()
    }
}

pub(crate) fn is_data_packet(packet: &ZCPacket) -> bool {
    let Some(header) = packet.peer_manager_header() else {
        return false;
    };

    if header.is_critical_l2_control() {
        return false;
    }

    let packet_type = if header.packet_type == PacketType::ForeignNetworkPacket as u8 {
        let Some(inner_packet_type) = packet.foreign_network_inner_packet_type() else {
            return false;
        };
        inner_packet_type
    } else {
        header.packet_type
    };

    matches!(
        packet_type,
        x if x == PacketType::Data as u8
            || x == PacketType::DataWithKcpSrcModified as u8
            || x == PacketType::DataWithQuicSrcModified as u8
            || x == PacketType::KcpSrc as u8
            || x == PacketType::KcpDst as u8
            || x == PacketType::QuicSrc as u8
            || x == PacketType::QuicDst as u8
            || x == PacketType::Ethernet as u8
            || x == PacketType::AlternateFecSource as u8
            || x == PacketType::AlternateFecParity as u8
    )
}

pub(crate) fn batch_has_uniform_priority(batch: &PacketBatch) -> bool {
    let Some(first) = batch.first() else {
        return true;
    };
    let first_is_data = is_data_packet(first);
    batch
        .iter()
        .all(|packet| is_data_packet(packet) == first_is_data)
}

fn batch_budget_bytes(batch: &PacketBatch) -> usize {
    batch
        .retained_buffer_capacity()
        .saturating_add(batch.len().saturating_mul(DIRECT_PACKET_OVERHEAD))
        .max(1)
}

fn batch_compacted_budget_bytes(batch: &PacketBatch) -> usize {
    batch
        .buffer_byte_len()
        .saturating_add(batch.len().saturating_mul(DIRECT_PACKET_OVERHEAD))
        .max(1)
}

fn plan_direct_batch(batch: &mut PacketBatch) -> Result<DirectBatchPlan, TunnelError> {
    debug_assert!(!batch.is_empty());
    let packet_count = batch.len();
    let mut control = true;
    let mut byte_count = packet_count.saturating_mul(DIRECT_PACKET_OVERHEAD);
    for packet in batch.iter() {
        control &= !is_data_packet(packet);
        byte_count = byte_count.saturating_add(packet.retained_buffer_capacity());
    }
    byte_count = byte_count.max(1);

    let (packet_limit, byte_limit) = if control {
        (DIRECT_CONTROL_PACKET_BUDGET, DIRECT_CONTROL_BYTE_BUDGET)
    } else {
        (DIRECT_DATA_PACKET_BUDGET, DIRECT_DATA_BYTE_BUDGET)
    };
    if packet_count > packet_limit {
        return Err(TunnelError::ExceedMaxPacketSize(packet_limit, packet_count));
    }

    if byte_count > byte_limit && batch_compacted_budget_bytes(batch) <= byte_limit {
        byte_count = packet_count.saturating_mul(DIRECT_PACKET_OVERHEAD);
        for packet in batch.iter_mut() {
            packet.compact_retained_buffer();
            byte_count = byte_count.saturating_add(packet.retained_buffer_capacity());
        }
        byte_count = byte_count.max(1);
    }
    if byte_count > byte_limit {
        return Err(TunnelError::ExceedMaxPacketSize(byte_limit, byte_count));
    }

    Ok(DirectBatchPlan {
        control,
        packet_count,
        byte_count,
    })
}

async fn acquire_budget_or_terminal(
    state: &DirectSinkState,
    budget: Arc<AdmissionBudget>,
    packet_count: usize,
    byte_count: usize,
) -> Result<AdmissionPermit, TunnelError> {
    let mut terminal = state.terminal_tx.subscribe();
    loop {
        if state.terminal_error.get().is_some() {
            return Err(state.terminal_error_value());
        }

        let wake = budget.wake.notified();
        tokio::pin!(wake);
        if let Some(permit) = budget.try_acquire(packet_count, byte_count) {
            return Ok(permit);
        }

        tokio::select! {
            biased;
            _ = terminal.changed() => return Err(state.terminal_error_value()),
            _ = &mut wake => {}
        }
    }
}

impl DirectSinkState {
    fn terminal_error_value(&self) -> TunnelError {
        TunnelError::InternalError(
            self.terminal_error
                .get()
                .cloned()
                .unwrap_or_else(|| "direct tunnel sink owner stopped".to_owned()),
        )
    }
}

async fn run_until<F, T>(operation: F, deadline: Option<Instant>) -> Result<T, TunnelError>
where
    F: Future<Output = Result<T, TunnelError>>,
{
    match deadline {
        Some(deadline) => timeout_at(deadline, operation)
            .await
            .map_err(TunnelError::Timeout)?,
        None => operation.await,
    }
}

fn set_terminal_error(state: &DirectSinkState, terminal: String) {
    if state.terminal_error.set(terminal).is_ok() {
        state.terminal_tx.send_replace(());
    }
}

async fn close_sink(sink: &mut BoxedPacketBatchSink, send_timeout: Option<Duration>) {
    let close = poll_fn(|cx| sink.as_mut().poll_close(cx));
    if let Some(duration) = send_timeout {
        let _ = tokio::time::timeout(duration, close).await;
    } else {
        let _ = close.await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use futures::{Sink, StreamExt};
    use tokio::sync::{mpsc::UnboundedSender, oneshot};

    use crate::tunnel::{
        PacketBatchSink,
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
        ring::create_ring_tunnel_pair,
    };

    use super::{DirectTunnel, MAX_PACKET_BATCH_SIZE, is_data_packet};

    #[test]
    fn direct_batch_plan_preserves_lane_and_exact_accounting() {
        let mut data = sized_batch(PacketType::Data, 4, 128);
        let expected_data_bytes = super::batch_budget_bytes(&data);
        let data_plan = super::plan_direct_batch(&mut data).unwrap();
        assert!(!data_plan.control);
        assert_eq!(data_plan.packet_count, 4);
        assert_eq!(data_plan.byte_count, expected_data_bytes);

        let mut control = sized_batch(PacketType::Ping, 2, 128);
        let expected_control_bytes = super::batch_budget_bytes(&control);
        let control_plan = super::plan_direct_batch(&mut control).unwrap();
        assert!(control_plan.control);
        assert_eq!(control_plan.packet_count, 2);
        assert_eq!(control_plan.byte_count, expected_control_bytes);

        let mut mixed = PacketBatch::new();
        mixed.try_push(control_packet(1)).unwrap();
        mixed
            .try_push(sized_batch(PacketType::Data, 1, 1).pop_singleton().unwrap())
            .unwrap();
        assert!(!super::plan_direct_batch(&mut mixed).unwrap().control);
    }

    #[tokio::test]
    async fn direct_batch_send_preserves_order() {
        let (tunnel, peer) = create_ring_tunnel_pair();
        let mut direct = DirectTunnel::new(tunnel, None);
        let sender = direct.get_sink();
        let mut receiver = peer.split().0;
        let mut batch = PacketBatch::new();
        for value in 1..=4_u8 {
            batch
                .try_push(ZCPacket::new_with_payload(&[value]))
                .unwrap();
        }

        sender.send_batch(batch).await.unwrap();

        let received = receiver
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|packet| packet.payload()[0])
            .collect::<Vec<_>>();
        assert_eq!(received, vec![1, 2, 3, 4]);
        let _stream = direct.get_stream();
    }

    #[tokio::test]
    async fn direct_control_send_compacts_oversized_receive_slab() {
        let (tunnel, peer) = create_ring_tunnel_pair();
        let mut direct = DirectTunnel::new(tunnel, None);
        let sender = direct.get_sink();
        let mut receiver = peer.split().0;
        let mut packet = control_packet(7);
        packet.mut_inner().reserve(64 * 1024);
        assert!(
            packet.retained_buffer_capacity() + super::DIRECT_PACKET_OVERHEAD
                > super::DIRECT_CONTROL_BYTE_BUDGET
        );
        assert!(
            packet.buf_len() + super::DIRECT_PACKET_OVERHEAD <= super::DIRECT_CONTROL_BYTE_BUDGET
        );

        sender.send(packet).await.unwrap();

        let received = receiver
            .next()
            .await
            .unwrap()
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(received.payload(), &[7]);
        assert!(
            received.retained_buffer_capacity() + super::DIRECT_PACKET_OVERHEAD
                <= super::DIRECT_CONTROL_BYTE_BUDGET
        );
        let _stream = direct.get_stream();
    }

    #[tokio::test]
    async fn direct_control_send_still_rejects_genuinely_oversized_packet() {
        let (tunnel, _peer) = create_ring_tunnel_pair();
        let direct = DirectTunnel::new(tunnel, None);
        let sender = direct.get_sink();
        let payload_len = super::DIRECT_CONTROL_BYTE_BUDGET;
        let error = sender
            .send_batch(sized_batch(PacketType::Ping, 1, payload_len))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            crate::tunnel::TunnelError::ExceedMaxPacketSize(limit, actual)
                if limit == super::DIRECT_CONTROL_BYTE_BUDGET && actual > limit
        ));
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum WriteKind {
        Data,
        Control,
    }

    struct BlockedDataSink {
        events: UnboundedSender<WriteKind>,
        pending: Option<WriteKind>,
        release_data: Option<oneshot::Receiver<()>>,
    }

    struct FailingSink {
        close_count: Arc<AtomicUsize>,
    }

    struct CountingSink {
        start_send_count: Arc<AtomicUsize>,
        flush_count: Arc<AtomicUsize>,
    }

    struct CoalescingSink {
        batches: UnboundedSender<Vec<u16>>,
        release_ready: Option<oneshot::Receiver<()>>,
        release_flush: Option<oneshot::Receiver<()>>,
    }

    impl Sink<PacketBatch> for CoalescingSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if let Some(release_ready) = self.release_ready.as_mut() {
                match Pin::new(release_ready).poll(cx) {
                    Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => self.release_ready = None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            let markers = batch
                .into_iter()
                .map(|packet| {
                    let payload = packet.payload();
                    u16::from_le_bytes([payload[0], payload[1]])
                })
                .collect();
            self.get_mut().batches.send(markers).unwrap();
            Ok(())
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if let Some(release_flush) = self.release_flush.as_mut() {
                match Pin::new(release_flush).poll(cx) {
                    Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => self.release_flush = None,
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<PacketBatch> for CountingSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            assert_eq!(batch.len(), super::MAX_PACKET_BATCH_SIZE);
            self.start_send_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.flush_count.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<PacketBatch> for FailingSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _batch: PacketBatch) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(crate::tunnel::TunnelError::InternalError(
                "writer failed".to_owned(),
            )))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.close_count.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<PacketBatch> for BlockedDataSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            if batch.iter().all(is_data_packet) {
                self.events.send(WriteKind::Data).unwrap();
                self.pending = Some(WriteKind::Data);
            } else {
                self.events.send(WriteKind::Control).unwrap();
                self.pending = Some(WriteKind::Control);
            }
            Ok(())
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if self.pending == Some(WriteKind::Data) {
                if let Some(release_data) = self.release_data.as_mut() {
                    match Pin::new(release_data).poll(cx) {
                        Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                            self.pending = None;
                            self.release_data = None;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            self.pending = None;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn data_packet(value: u8) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&[value]);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn control_packet(value: u8) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&[value]);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
        packet
    }

    fn indexed_data_packet(value: u16) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&value.to_le_bytes());
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn sized_batch(
        packet_type: PacketType,
        packet_count: usize,
        payload_len: usize,
    ) -> PacketBatch {
        let mut batch = PacketBatch::new();
        for _ in 0..packet_count {
            let mut packet = ZCPacket::new_with_payload(&vec![0_u8; payload_len]);
            packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
            batch.try_push(packet).unwrap();
        }
        batch
    }

    #[tokio::test]
    async fn full_data_batch_is_one_complete_sink_run() {
        let start_send_count = Arc::new(AtomicUsize::new(0));
        let flush_count = Arc::new(AtomicUsize::new(0));
        let sink = Box::pin(CountingSink {
            start_send_count: start_send_count.clone(),
            flush_count: flush_count.clone(),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        sender
            .send_batch(sized_batch(PacketType::Data, MAX_PACKET_BATCH_SIZE, 1))
            .await
            .unwrap();

        crate::tunnel::common::tests::wait_for_condition(
            || async {
                start_send_count.load(Ordering::Acquire) == 1
                    && flush_count.load(Ordering::Acquire) == 1
            },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert_eq!(start_send_count.load(Ordering::Acquire), 1);
        assert_eq!(flush_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn control_run_precedes_a_waiting_data_run() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        sender.send(data_packet(1)).await.unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));

        sender.send(data_packet(3)).await.unwrap();
        sender.send(control_packet(2)).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events_rx.recv())
                .await
                .is_err()
        );
        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Control));
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
    }

    #[tokio::test]
    async fn control_reserve_admits_when_data_run_window_is_full() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        sender.send(data_packet(1)).await.unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        for _ in 1..super::DIRECT_INFLIGHT_RUN_CAPACITY {
            sender.send(data_packet(2)).await.unwrap();
        }

        let mut waiter = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(3)).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sender.send(control_packet(4)),
        )
        .await
        .expect("the control reserve must admit while data runs are saturated")
        .unwrap();

        release_data.send(()).unwrap();
        assert!(waiter.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn admitted_data_runs_have_bounded_batch_ownership() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        let run_capacity = super::DIRECT_INFLIGHT_RUN_CAPACITY;
        sender.send(data_packet(1)).await.unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        for _ in 1..run_capacity {
            sender.send(data_packet(2)).await.unwrap();
        }

        // A further complete run waits for released ownership.
        let mut second = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(3)).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut second)
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert!(second.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn data_runs_share_one_total_packet_budget() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        sender
            .send_batch(sized_batch(
                PacketType::Data,
                super::MAX_PACKET_BATCH_SIZE,
                1,
            ))
            .await
            .unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        for _ in 1..super::SEND_PIPELINE_SLOT_COUNT {
            sender
                .send_batch(sized_batch(
                    PacketType::Data,
                    super::MAX_PACKET_BATCH_SIZE,
                    1,
                ))
                .await
                .unwrap();
        }

        let mut excess = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(3)).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut excess)
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert!(excess.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn scalar_window_coalesces_into_eight_ordered_batches_until_flush() {
        let (batches_tx, mut batches_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_ready, release_ready_rx) = oneshot::channel();
        let (release_flush, release_flush_rx) = oneshot::channel();
        let sink = Box::pin(CoalescingSink {
            batches: batches_tx,
            release_ready: Some(release_ready_rx),
            release_flush: Some(release_flush_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state: state.clone(),
            send_timeout: None,
        };

        for value in 0..super::DIRECT_DATA_PACKET_BUDGET as u16 {
            sender.send(indexed_data_packet(value)).await.unwrap();
        }
        assert_eq!(
            state.ownership_budget.runs_in_use.load(Ordering::Acquire),
            super::DIRECT_INFLIGHT_RUN_CAPACITY
        );

        let mut excess = tokio::spawn({
            let sender = sender.clone();
            async move {
                sender
                    .send(indexed_data_packet(super::DIRECT_DATA_PACKET_BUDGET as u16))
                    .await
            }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut excess)
                .await
                .is_err()
        );

        release_ready.send(()).unwrap();
        let mut observed = Vec::with_capacity(super::DIRECT_DATA_PACKET_BUDGET);
        for _ in 0..super::SEND_PIPELINE_SLOT_COUNT {
            let batch = tokio::time::timeout(std::time::Duration::from_secs(1), batches_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(batch.len(), super::MAX_PACKET_BATCH_SIZE);
            observed.extend(batch);
        }
        assert_eq!(
            observed,
            (0..super::DIRECT_DATA_PACKET_BUDGET as u16).collect::<Vec<_>>()
        );
        assert_eq!(
            state.ownership_budget.runs_in_use.load(Ordering::Acquire),
            super::DIRECT_INFLIGHT_RUN_CAPACITY
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut excess)
                .await
                .is_err()
        );

        release_flush.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut excess)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let final_batch =
            tokio::time::timeout(std::time::Duration::from_secs(1), batches_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(final_batch, vec![super::DIRECT_DATA_PACKET_BUDGET as u16]);
    }

    #[tokio::test]
    async fn queued_batch_admission_does_not_wait_for_previous_flush() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };
        let half_batch = MAX_PACKET_BATCH_SIZE / 2;

        sender
            .send_batch(sized_batch(PacketType::Data, half_batch, 1))
            .await
            .unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));

        let mut second = tokio::spawn({
            let sender = sender.clone();
            async move {
                sender
                    .send_batch(sized_batch(PacketType::Data, half_batch, 1))
                    .await
            }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut second)
                .await
                .expect("the second run should enter the fixed window")
                .unwrap()
                .is_ok()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events_rx.recv())
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
    }

    #[tokio::test]
    async fn terminal_write_failure_rejects_later_admission_and_closes_once() {
        let close_count = Arc::new(AtomicUsize::new(0));
        let sink = Box::pin(FailingSink {
            close_count: close_count.clone(),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let state = super::DirectSinkState::new(sink, None, None);
        let sender = super::DirectTunnelSender {
            state,
            send_timeout: None,
        };

        // A batch accepted by the sink is acknowledged before the failing
        // flush makes the tunnel terminal.
        assert!(sender.send(data_packet(1)).await.is_ok());
        crate::tunnel::common::tests::wait_for_condition(
            || async { close_count.load(Ordering::Acquire) == 1 },
            std::time::Duration::from_secs(1),
        )
        .await;

        assert!(sender.send(control_packet(2)).await.is_err());
        assert!(sender.send(data_packet(3)).await.is_err());
        assert_eq!(close_count.load(Ordering::Acquire), 1);
    }
}
