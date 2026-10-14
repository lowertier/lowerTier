use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
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

#[cfg(test)]
mod admission_tests;

type BoxedPacketBatchSink = Pin<Box<dyn PacketBatchSink>>;

struct TransitSink {
    inner: BoxedPacketBatchSink,
    state: std::sync::Weak<DirectSinkState>,
}

impl futures::Sink<PacketBatch> for TransitSink {
    type Error = TunnelError;
    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, mut batch: PacketBatch) -> Result<(), Self::Error> {
        // Check after poll_ready. Queued data cannot retain old permission or credit.
        if let Some(context) = self.state.upgrade().and_then(|state| {
            state
                .transit_context
                .get()
                .and_then(std::sync::Weak::upgrade)
        }) {
            batch.retain_mut(|packet| {
                if !packet.transit_data {
                    return true;
                }
                let network = packet.transit_network.clone();
                context.admit_transit(
                    packet,
                    network
                        .as_deref()
                        .unwrap_or(&context.get_network_identity().network_name),
                    packet
                        .transit_destination
                        .or_else(|| packet.get_dst_peer_id())
                        .unwrap_or(0),
                )
            });
        }
        if batch.is_empty() {
            return Ok(());
        }
        self.inner.as_mut().start_send(batch)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_flush(cx)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_close(cx)
    }
}

struct DirectSinkState {
    transit_context: OnceLock<std::sync::Weak<crate::common::global_ctx::GlobalCtx>>,
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
    usage: parking_lot::Mutex<AdmissionUsage>,
    wake: Notify,
    process_memory: Option<Arc<ProcessMemoryGovernor>>,
}

#[derive(Default)]
struct AdmissionUsage {
    packets: usize,
    bytes: usize,
    runs: usize,
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
            transit_context: OnceLock::new(),
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
            Box::pin(TransitSink {
                inner: sink,
                state: Arc::downgrade(&state),
            }),
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
            usage: parking_lot::Mutex::new(AdmissionUsage::default()),
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

        // Reserve all local dimensions together. A failed reservation must
        // neither expose partial ownership nor wake its own parked retry.
        let mut usage = self.usage.lock();
        let packets = usage.packets.checked_add(packet_count)?;
        let bytes = usage.bytes.checked_add(byte_count)?;
        let run_count = usize::from(self.run_capacity.is_some());
        let runs = usage.runs.checked_add(run_count)?;
        if packets > self.packet_capacity
            || bytes > self.byte_capacity
            || self.run_capacity.is_some_and(|limit| runs > limit)
        {
            return None;
        }
        let process_memory = if byte_count == 0 {
            None
        } else if let Some(governor) = &self.process_memory {
            Some(governor.try_reserve_owned(byte_count)?)
        } else {
            None
        };
        *usage = AdmissionUsage {
            packets,
            bytes,
            runs,
        };
        Some(AdmissionPermit {
            budget: self.clone(),
            packet_count,
            byte_count,
            run_count,
            _process_memory: process_memory,
        })
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        {
            let mut usage = self.budget.usage.lock();
            usage.packets -= self.packet_count;
            usage.bytes -= self.byte_count;
            usage.runs -= self.run_count;
        }
        drop(self._process_memory.take());
        // Different-sized requests can become eligible on the same release.
        self.budget.wake.notify_waiters();
    }
}

#[derive(Clone)]
pub struct DirectTunnelSender {
    state: Arc<DirectSinkState>,
    send_timeout: Option<Duration>,
}

impl DirectTunnelSender {
    pub(crate) fn set_transit_context(&self, context: &crate::common::global_ctx::ArcGlobalCtx) {
        let _ = self.state.transit_context.set(Arc::downgrade(context));
    }
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
        *pending_batch = Some(PacketBatch::new());
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

    if header.packet_type == PacketType::ForeignNetworkPacket as u8 {
        return !header.is_foreign_control();
    }

    let packet_type = header.packet_type;

    matches!(
        packet_type,
        x if x == PacketType::Data as u8
            || x == PacketType::OverlayStream as u8
            || x == PacketType::Ethernet as u8
    )
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

        // Construct both notifications before observing capacity. The shared
        // governor can be released by a different lane with no local permit.
        let memory_wake = budget
            .process_memory
            .as_ref()
            .map(|governor| governor.release_notified());
        let wake = budget.wake.notified();
        tokio::pin!(wake);
        enable_admission_waiter(wake.as_mut());
        if let Some(permit) = budget.try_acquire(packet_count, byte_count) {
            return Ok(permit);
        }

        tokio::select! {
            biased;
            _ = terminal.changed() => return Err(state.terminal_error_value()),
            _ = &mut wake => {},
            _ = async {
                match memory_wake {
                    Some(wake) => wake.await,
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

fn enable_admission_waiter(waiter: Pin<&mut tokio::sync::futures::Notified<'_>>) {
    waiter.enable();
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
    if state.terminal_error.set(terminal.clone()).is_ok() {
        tracing::warn!(
            target: "CORE",
            error = %terminal,
            "direct tunnel entered a terminal state"
        );
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
