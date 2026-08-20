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
    sync::{Mutex, Notify, mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};

use super::{
    PacketBatchSink, PacketBatchStream, Tunnel, TunnelError,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    packet_def::{PacketType, ZCPacket},
};
use crate::common::global_ctx::{ProcessMemoryGovernor, ProcessMemoryPermit};

const DIRECT_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE * 2;
const DIRECT_BYTE_BUDGET: usize = 128 * 1024;
const DIRECT_CONTROL_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE;
const DIRECT_DATA_PACKET_BUDGET: usize = DIRECT_PACKET_BUDGET - DIRECT_CONTROL_PACKET_BUDGET;
const DIRECT_CONTROL_BYTE_BUDGET: usize = DIRECT_BYTE_BUDGET / 8;
const DIRECT_DATA_BYTE_BUDGET: usize = DIRECT_BYTE_BUDGET - DIRECT_CONTROL_BYTE_BUDGET;
const DIRECT_PACKET_OVERHEAD: usize = std::mem::size_of::<ZCPacket>();
const MAX_CONSECUTIVE_CONTROL_SENDS: usize = 8;
const DIRECT_UNFLUSHED_PACKET_BUDGET: usize = 8;

type BoxedPacketBatchSink = Pin<Box<dyn PacketBatchSink>>;

struct DirectSinkState {
    sink: Arc<Mutex<BoxedPacketBatchSink>>,
    sink_gate: Arc<PrioritySinkGate>,
    ownership_budget: Arc<AdmissionBudget>,
    control_budget: Arc<AdmissionBudget>,
    data_budget: Arc<AdmissionBudget>,
    terminal_error: OnceLock<String>,
    terminal_tx: watch::Sender<()>,
    control_tx: mpsc::Sender<DirectSendWork>,
    data_tx: mpsc::Sender<DirectSendWork>,
}

struct DirectSendWork {
    batch: PacketBatch,
    ownership: AdmissionPermit,
    completion: oneshot::Sender<Result<(), String>>,
    deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectBatchPlan {
    control: bool,
    packet_count: usize,
    byte_count: usize,
}

struct SendBudget {
    _permit: AdmissionPermit,
}

struct AdmissionBudget {
    packet_capacity: usize,
    byte_capacity: usize,
    packets_in_use: AtomicUsize,
    bytes_in_use: AtomicUsize,
    wake: Notify,
    process_memory: Option<Arc<ProcessMemoryGovernor>>,
}

struct AdmissionPermit {
    budget: Arc<AdmissionBudget>,
    packet_count: usize,
    byte_count: usize,
    _process_memory: Option<ProcessMemoryPermit>,
}

#[derive(Default)]
struct PrioritySinkGateState {
    locked: bool,
    waiting_control: usize,
    waiting_data: usize,
    consecutive_control: usize,
}

struct PrioritySinkGate {
    state: std::sync::Mutex<PrioritySinkGateState>,
    control_wake: Notify,
    data_wake: Notify,
}

struct PrioritySinkPermit {
    gate: Arc<PrioritySinkGate>,
}

struct PriorityWaiter {
    gate: Arc<PrioritySinkGate>,
    control: bool,
    counted: bool,
}

impl DirectSinkState {
    fn new(
        sink: BoxedPacketBatchSink,
        close_timeout: Option<Duration>,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Arc<Self> {
        let (terminal_tx, _) = watch::channel(());
        let (control_tx, control_rx) = mpsc::channel(2);
        let (data_tx, data_rx) = mpsc::channel(DIRECT_UNFLUSHED_PACKET_BUDGET);
        let state = Arc::new(Self {
            sink: Arc::new(Mutex::new(sink)),
            sink_gate: Arc::new(PrioritySinkGate::new()),
            ownership_budget: Arc::new(AdmissionBudget::with_process(
                DIRECT_DATA_PACKET_BUDGET,
                DIRECT_DATA_BYTE_BUDGET,
                process_memory.clone(),
            )),
            control_budget: Arc::new(AdmissionBudget::with_process(
                DIRECT_CONTROL_PACKET_BUDGET,
                DIRECT_CONTROL_BYTE_BUDGET,
                process_memory,
            )),
            data_budget: Arc::new(AdmissionBudget::new(
                DIRECT_DATA_PACKET_BUDGET,
                DIRECT_DATA_BYTE_BUDGET,
            )),
            terminal_error: OnceLock::new(),
            terminal_tx,
            control_tx,
            data_tx,
        });
        tokio::spawn(run_direct_sink_owner(
            Arc::downgrade(&state),
            control_rx,
            data_rx,
            close_timeout,
        ));
        state
    }
}

impl PrioritySinkGate {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(PrioritySinkGateState::default()),
            control_wake: Notify::new(),
            data_wake: Notify::new(),
        }
    }

    async fn acquire(self: &Arc<Self>, control: bool) -> PrioritySinkPermit {
        let mut waiter = PriorityWaiter::new(self.clone(), control);
        loop {
            let wake = if control {
                self.control_wake.notified()
            } else {
                self.data_wake.notified()
            };
            tokio::pin!(wake);
            {
                let mut state = self.state.lock().unwrap();
                let can_acquire = if control {
                    state.waiting_data == 0
                        || state.consecutive_control < MAX_CONSECUTIVE_CONTROL_SENDS
                } else {
                    state.waiting_control == 0
                        || state.consecutive_control >= MAX_CONSECUTIVE_CONTROL_SENDS
                };
                if !state.locked && can_acquire {
                    state.locked = true;
                    if control {
                        state.waiting_control = state.waiting_control.saturating_sub(1);
                        if state.waiting_data == 0 {
                            state.consecutive_control = 0;
                        } else {
                            state.consecutive_control = state.consecutive_control.saturating_add(1);
                        }
                    } else {
                        state.waiting_data = state.waiting_data.saturating_sub(1);
                        state.consecutive_control = 0;
                    }
                    waiter.counted = false;
                    return PrioritySinkPermit { gate: self.clone() };
                }
            }
            wake.await;
        }
    }

    fn release(&self) {
        let wake_control = {
            let mut state = self.state.lock().unwrap();
            state.locked = false;
            state.waiting_control > 0
                && (state.waiting_data == 0
                    || state.consecutive_control < MAX_CONSECUTIVE_CONTROL_SENDS)
        };
        if wake_control {
            self.control_wake.notify_one();
        } else {
            self.data_wake.notify_one();
        }
    }
}

impl PriorityWaiter {
    fn new(gate: Arc<PrioritySinkGate>, control: bool) -> Self {
        let mut state = gate.state.lock().unwrap();
        if control {
            state.waiting_control += 1;
        } else {
            state.waiting_data += 1;
        }
        drop(state);
        Self {
            gate,
            control,
            counted: true,
        }
    }
}

impl Drop for PriorityWaiter {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let wake_control = {
            let mut state = self.gate.state.lock().unwrap();
            if self.control {
                state.waiting_control = state.waiting_control.saturating_sub(1);
            } else {
                state.waiting_data = state.waiting_data.saturating_sub(1);
            }
            !state.locked
                && state.waiting_control > 0
                && (state.waiting_data == 0
                    || state.consecutive_control < MAX_CONSECUTIVE_CONTROL_SENDS)
        };
        if wake_control {
            self.gate.control_wake.notify_one();
        } else {
            self.gate.data_wake.notify_one();
        }
    }
}

impl Drop for PrioritySinkPermit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

impl AdmissionBudget {
    fn new(packet_capacity: usize, byte_capacity: usize) -> Self {
        Self::with_process(packet_capacity, byte_capacity, None)
    }

    fn with_process(
        packet_capacity: usize,
        byte_capacity: usize,
        process_memory: Option<Arc<ProcessMemoryGovernor>>,
    ) -> Self {
        Self {
            packet_capacity,
            byte_capacity,
            packets_in_use: AtomicUsize::new(0),
            bytes_in_use: AtomicUsize::new(0),
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
                return Some(AdmissionPermit {
                    budget: self.clone(),
                    packet_count,
                    byte_count,
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
            self.send_segment(batch, ownership, plan.control).await
        }
    }

    async fn send_segment(
        &self,
        batch: PacketBatch,
        ownership: AdmissionPermit,
        control: bool,
    ) -> Result<(), TunnelError> {
        debug_assert!(!batch.is_empty());

        let mut terminal = self.state.terminal_tx.subscribe();
        if self.state.terminal_error.get().is_some() {
            return Err(self.terminal_error());
        }
        let (completion, result) = oneshot::channel();
        let work = DirectSendWork {
            batch,
            ownership,
            completion,
            deadline: self.send_timeout.map(|duration| Instant::now() + duration),
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
        tokio::select! {
            biased;
            result = result => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(message)) => Err(TunnelError::InternalError(message)),
                Err(_) => Err(self.terminal_error()),
            },
            _ = terminal.changed() => Err(self.terminal_error()),
        }
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

async fn start_direct_send_work(
    sink: &mut BoxedPacketBatchSink,
    work: DirectSendWork,
) -> Option<(usize, AdmissionPermit, Option<Instant>)> {
    let DirectSendWork {
        batch,
        ownership,
        completion,
        deadline,
    } = work;
    let packet_count = batch.len();

    if let Err(error) = run_until(poll_fn(|cx| sink.as_mut().poll_ready(cx)), deadline).await {
        let _ = completion.send(Err(format!("direct tunnel sink failed: {error}")));
        return None;
    }
    if let Err(error) = sink.as_mut().start_send(batch) {
        let _ = completion.send(Err(format!("direct tunnel sink failed: {error}")));
        return None;
    }

    // start_send transfers ownership of the batch to the sink. Preserve the
    // sender contract by acknowledging now while the admission permit stays
    // held until the shared flush completes.
    let _ = completion.send(Ok(()));
    Some((packet_count, ownership, deadline))
}

async fn run_direct_sink_owner(
    state: std::sync::Weak<DirectSinkState>,
    mut control_rx: mpsc::Receiver<DirectSendWork>,
    mut data_rx: mpsc::Receiver<DirectSendWork>,
    close_timeout: Option<Duration>,
) {
    let Some(owner) = state.upgrade() else {
        return;
    };
    let sink_owner = owner.sink.clone();
    drop(owner);
    let mut sink = sink_owner.lock().await;
    let mut consecutive_control = 0_usize;
    let mut pending_work: Option<(DirectSendWork, bool)> = None;

    loop {
        if pending_work.is_none() && control_rx.is_closed() && data_rx.is_closed() {
            close_sink(&mut sink, close_timeout).await;
            break;
        }

        let next = if let Some(work) = pending_work.take() {
            Some(work)
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

        let mut started_ownerships = Vec::with_capacity(DIRECT_UNFLUSHED_PACKET_BUDGET);
        let mut started_packets = 0_usize;
        let mut flush_deadline = None;
        let mut current = Some((work, control_lane));

        while let Some((work, lane_is_control)) = current.take() {
            let Some((packet_count, ownership, deadline)) =
                start_direct_send_work(&mut sink, work).await
            else {
                break;
            };
            started_packets = started_packets.saturating_add(packet_count);
            flush_deadline = earliest_deadline(flush_deadline, deadline);
            started_ownerships.push(ownership);

            // Control traffic is latency-sensitive. A data batch that already
            // reaches the packet budget also flushes immediately, so a large
            // batch cannot be multiplied into a much larger unflushed burst.
            if lane_is_control || started_packets >= DIRECT_UNFLUSHED_PACKET_BUDGET {
                break;
            }

            // One scheduling turn gives saturated scalar TUN producers a
            // chance to fill the bounded queue. Only already-ready work is
            // coalesced, so idle traffic does not wait for a batching timer.
            tokio::task::yield_now().await;

            match control_rx.try_recv() {
                Ok(work) => {
                    pending_work = Some((work, true));
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {}
            }

            match data_rx.try_recv() {
                Ok(work) => {
                    if started_packets.saturating_add(work.batch.len())
                        > DIRECT_UNFLUSHED_PACKET_BUDGET
                    {
                        pending_work = Some((work, false));
                        break;
                    }
                    current = Some((work, false));
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if started_ownerships.is_empty() {
            continue;
        }

        match run_until(poll_fn(|cx| sink.as_mut().poll_flush(cx)), flush_deadline).await {
            Ok(()) => drop(started_ownerships),
            Err(error) => {
                let message = format!("direct tunnel sink failed: {error}");
                drop(started_ownerships);
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

fn is_data_packet(packet: &ZCPacket) -> bool {
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

fn is_control_batch(batch: &PacketBatch) -> bool {
    // Mixed batches stay on the data lane to preserve packet ordering.
    // A segment uses the control lane only when every packet is control.
    batch.iter().all(|packet| !is_data_packet(packet))
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

async fn acquire_send_budget(
    state: &DirectSinkState,
    batch: &PacketBatch,
) -> Result<SendBudget, TunnelError> {
    if state.terminal_error.get().is_some() {
        return Err(TunnelError::InternalError(
            state
                .terminal_error
                .get()
                .cloned()
                .unwrap_or_else(|| "direct tunnel sink owner stopped".to_owned()),
        ));
    }

    let packet_count = batch.len();
    let byte_count = batch_budget_bytes(batch);
    if packet_count > DIRECT_PACKET_BUDGET {
        return Err(TunnelError::ExceedMaxPacketSize(
            DIRECT_PACKET_BUDGET,
            packet_count,
        ));
    }
    if byte_count > DIRECT_BYTE_BUDGET {
        return Err(TunnelError::ExceedMaxPacketSize(
            DIRECT_BYTE_BUDGET,
            byte_count,
        ));
    }

    let budget = if is_control_batch(batch) {
        state.control_budget.clone()
    } else {
        state.data_budget.clone()
    };
    if packet_count > budget.packet_capacity {
        return Err(TunnelError::ExceedMaxPacketSize(
            budget.packet_capacity,
            packet_count,
        ));
    }
    if byte_count > budget.byte_capacity {
        return Err(TunnelError::ExceedMaxPacketSize(
            budget.byte_capacity,
            byte_count,
        ));
    }
    let permit = acquire_budget_or_terminal(state, budget, packet_count, byte_count).await?;
    Ok(SendBudget { _permit: permit })
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

async fn send_sink_batch(
    sink: &mut BoxedPacketBatchSink,
    batch: PacketBatch,
    deadline: Option<Instant>,
) -> Result<(), TunnelError> {
    let operation = async {
        poll_fn(|cx| sink.as_mut().poll_ready(cx)).await?;
        sink.as_mut().start_send(batch)?;
        poll_fn(|cx| sink.as_mut().poll_flush(cx)).await
    };
    run_until(operation, deadline).await
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

    impl Sink<PacketBatch> for CountingSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            assert_eq!(batch.len(), MAX_PACKET_BATCH_SIZE);
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
    async fn full_data_batch_has_one_start_send_and_flush() {
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

        assert_eq!(start_send_count.load(Ordering::Acquire), 1);
        // The sink owner acknowledges a started batch before flushing it.
        crate::tunnel::common::tests::wait_for_condition(
            || async { flush_count.load(Ordering::Acquire) == 1 },
            std::time::Duration::from_secs(1),
        )
        .await;
        assert_eq!(flush_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn control_send_precedes_waiting_data_without_an_extra_queue() {
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

        let data_send = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(1)).await }
        });
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));

        let second_data_send = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(3)).await }
        });
        tokio::task::yield_now().await;
        let control_send = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(control_packet(2)).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events_rx.recv())
                .await
                .is_err()
        );
        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Control));
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        assert!(control_send.await.unwrap().is_ok());
        assert!(second_data_send.await.unwrap().is_ok());
        assert!(data_send.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn control_reserve_admits_when_data_budget_is_full() {
        let (tunnel, _peer) = create_ring_tunnel_pair();
        let state = super::DirectSinkState::new(tunnel.split().1, None, None);

        let mut data_permits = Vec::new();
        for _ in 0..(super::DIRECT_DATA_PACKET_BUDGET / super::MAX_PACKET_BATCH_SIZE) {
            let data = sized_batch(PacketType::Data, super::MAX_PACKET_BATCH_SIZE, 1);
            data_permits.push(super::acquire_send_budget(&state, &data).await.unwrap());
        }

        let data = sized_batch(PacketType::Data, 1, 1);
        let waiting_state = state.clone();
        let mut waiter =
            tokio::spawn(async move { super::acquire_send_budget(&waiting_state, &data).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );

        waiter.abort();
        let _ = waiter.await;

        let control = sized_batch(PacketType::Ping, 1, 1_024);
        let released = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            super::acquire_send_budget(&state, &control),
        )
        .await
        .expect("the control reserve must admit while data is saturated")
        .unwrap();
        drop(released);
        drop(data_permits);
    }

    #[tokio::test]
    async fn in_flight_sends_have_bounded_batch_ownership() {
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

        // One full in-flight data batch saturates the data packet budget.
        let first = tokio::spawn({
            let sender = sender.clone();
            async move {
                sender
                    .send_batch(sized_batch(PacketType::Data, MAX_PACKET_BATCH_SIZE, 1))
                    .await
            }
        });
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));

        // A further data send waits for released budget instead of growing
        // an unbounded queue.
        let mut second = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send_batch(sized_batch(PacketType::Data, 1, 1)).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut second)
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert!(second.await.unwrap().is_ok());
        assert!(first.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn small_data_requests_coalesce_to_packet_budget() {
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

        let sends = (0..(super::DIRECT_UNFLUSHED_PACKET_BUDGET + 1))
            .map(|value| {
                let sender = sender.clone();
                tokio::spawn(async move { sender.send(data_packet(value as u8)).await })
            })
            .collect::<Vec<_>>();

        for _ in 0..super::DIRECT_UNFLUSHED_PACKET_BUDGET {
            assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events_rx.recv())
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        for send in sends {
            assert!(send.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn next_batch_waits_for_previous_flush() {
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

        let first = tokio::spawn({
            let sender = sender.clone();
            async move {
                sender
                    .send_batch(sized_batch(PacketType::Data, half_batch, 1))
                    .await
            }
        });
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        assert!(first.await.unwrap().is_ok());

        let second = tokio::spawn({
            let sender = sender.clone();
            async move {
                sender
                    .send_batch(sized_batch(PacketType::Data, half_batch, 1))
                    .await
            }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), events_rx.recv())
                .await
                .is_err()
        );

        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));
        assert!(second.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn terminal_write_failure_reaches_queued_callers_and_closes_once() {
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
