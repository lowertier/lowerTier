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
    sync::{Notify, mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};

use super::{
    PacketBatchSink, PacketBatchStream, Tunnel, TunnelError,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    packet_def::{PacketType, ZCPacket},
};

const CONTROL_QUEUE_CAPACITY: usize = 64;
const DATA_QUEUE_CAPACITY: usize = 64;
const CONTROL_BURST_LIMIT: usize = 8;
const DIRECT_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE * 8;
const DIRECT_BYTE_BUDGET: usize = 8 * 1024 * 1024;
const DIRECT_CONTROL_PACKET_BUDGET: usize = MAX_PACKET_BATCH_SIZE;
const DIRECT_DATA_PACKET_BUDGET: usize = DIRECT_PACKET_BUDGET - DIRECT_CONTROL_PACKET_BUDGET;
const DIRECT_CONTROL_BYTE_BUDGET: usize = DIRECT_BYTE_BUDGET / 8;
const DIRECT_DATA_BYTE_BUDGET: usize = DIRECT_BYTE_BUDGET - DIRECT_CONTROL_BYTE_BUDGET;
const DIRECT_PACKET_OVERHEAD: usize = std::mem::size_of::<ZCPacket>();

type BoxedPacketBatchSink = Pin<Box<dyn PacketBatchSink>>;

struct SendRequest {
    batch: PacketBatch,
    _budget: SendBudget,
    completed: oneshot::Sender<Result<(), TunnelError>>,
}

struct DirectSinkState {
    control_tx: mpsc::Sender<SendRequest>,
    data_tx: mpsc::Sender<SendRequest>,
    control_budget: Arc<AdmissionBudget>,
    data_budget: Arc<AdmissionBudget>,
    terminal_error: OnceLock<String>,
    terminal_tx: watch::Sender<()>,
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
}

struct AdmissionPermit {
    budget: Arc<AdmissionBudget>,
    packet_count: usize,
    byte_count: usize,
}

impl DirectSinkState {
    fn new(control_tx: mpsc::Sender<SendRequest>, data_tx: mpsc::Sender<SendRequest>) -> Self {
        let (terminal_tx, _) = watch::channel(());
        Self {
            control_tx,
            data_tx,
            control_budget: Arc::new(AdmissionBudget::new(
                DIRECT_CONTROL_PACKET_BUDGET,
                DIRECT_CONTROL_BYTE_BUDGET,
            )),
            data_budget: Arc::new(AdmissionBudget::new(
                DIRECT_DATA_PACKET_BUDGET,
                DIRECT_DATA_BYTE_BUDGET,
            )),
            terminal_error: OnceLock::new(),
            terminal_tx,
        }
    }
}

impl AdmissionBudget {
    fn new(packet_capacity: usize, byte_capacity: usize) -> Self {
        Self {
            packet_capacity,
            byte_capacity,
            packets_in_use: AtomicUsize::new(0),
            bytes_in_use: AtomicUsize::new(0),
            wake: Notify::new(),
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
}

impl DirectTunnelSender {
    pub async fn send(&self, packet: ZCPacket) -> Result<(), TunnelError> {
        self.send_batch(PacketBatch::singleton(packet)).await
    }

    pub async fn send_batch(&self, batch: PacketBatch) -> Result<(), TunnelError> {
        if batch.is_empty() {
            return Ok(());
        }

        // PacketBatch is already bounded to MAX_PACKET_BATCH_SIZE. Submit the
        // complete batch as one request so one full batch has one flush.
        self.send_segment(batch).await
    }

    async fn send_segment(&self, batch: PacketBatch) -> Result<(), TunnelError> {
        debug_assert!(!batch.is_empty());

        let is_control = is_control_batch(&batch);
        let queue = if is_control {
            &self.state.control_tx
        } else {
            &self.state.data_tx
        };
        let budget = acquire_send_budget(&self.state, &batch).await?;
        let (completed, result) = oneshot::channel();
        queue
            .send(SendRequest {
                batch,
                _budget: budget,
                completed,
            })
            .await
            .map_err(|_| self.terminal_error())?;

        result.await.unwrap_or_else(|_| Err(self.terminal_error()))
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

pub struct DirectTunnel<T> {
    _tunnel: T,
    stream: Option<Pin<Box<dyn PacketBatchStream>>>,
    sender: DirectTunnelSender,
}

impl<T: Tunnel> DirectTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        let (stream, sink) = tunnel.split();
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
        let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE_CAPACITY);
        let state = Arc::new(DirectSinkState::new(control_tx, data_tx));

        let owner_state = state.clone();
        tokio::spawn(async move {
            run_sink_owner(sink, control_rx, data_rx, owner_state, send_timeout).await;
        });

        Self {
            _tunnel: tunnel,
            stream: Some(stream),
            sender: DirectTunnelSender { state },
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn PacketBatchStream>> {
        self.stream.take().expect("the direct stream is taken once")
    }

    pub fn get_sink(&self) -> DirectTunnelSender {
        self.sender.clone()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendLane {
    Control,
    Data,
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

fn batch_budget_bytes(batch: &PacketBatch) -> usize {
    batch
        .buffer_byte_len()
        .saturating_add(batch.len().saturating_mul(DIRECT_PACKET_OVERHEAD))
        .max(1)
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

async fn run_sink_owner(
    mut sink: BoxedPacketBatchSink,
    mut control_rx: mpsc::Receiver<SendRequest>,
    mut data_rx: mpsc::Receiver<SendRequest>,
    state: Arc<DirectSinkState>,
    send_timeout: Option<Duration>,
) {
    let mut control_open = true;
    let mut data_open = true;
    let mut control_burst = 0;

    loop {
        let Some((lane, request)) = receive_next_request(
            &mut control_rx,
            &mut data_rx,
            &mut control_open,
            &mut data_open,
            control_burst,
        )
        .await
        else {
            close_sink(&mut sink, send_timeout).await;
            return;
        };

        if request.completed.is_closed() {
            continue;
        }

        let deadline = send_timeout.map(|duration| Instant::now() + duration);
        match send_sink_batch(&mut sink, request.batch, deadline).await {
            Ok(()) => {
                let _ = request.completed.send(Ok(()));
                match lane {
                    SendLane::Control => control_burst += 1,
                    SendLane::Data => control_burst = 0,
                }
            }
            Err(error) => {
                let terminal = format!("direct tunnel sink failed: {error}");
                set_terminal_error(&state, terminal);
                let _ = request.completed.send(Err(error));
                fail_sink_owner(&mut sink, &mut control_rx, &mut data_rx, send_timeout).await;
                return;
            }
        }
    }
}

async fn receive_next_request(
    control_rx: &mut mpsc::Receiver<SendRequest>,
    data_rx: &mut mpsc::Receiver<SendRequest>,
    control_open: &mut bool,
    data_open: &mut bool,
    control_burst: usize,
) -> Option<(SendLane, SendRequest)> {
    loop {
        if control_burst < CONTROL_BURST_LIMIT && *control_open {
            match control_rx.try_recv() {
                Ok(request) => return Some((SendLane::Control, request)),
                Err(mpsc::error::TryRecvError::Disconnected) => *control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if *data_open {
            match data_rx.try_recv() {
                Ok(request) => return Some((SendLane::Data, request)),
                Err(mpsc::error::TryRecvError::Disconnected) => *data_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if control_burst >= CONTROL_BURST_LIMIT && *control_open {
            match control_rx.try_recv() {
                Ok(request) => return Some((SendLane::Control, request)),
                Err(mpsc::error::TryRecvError::Disconnected) => *control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if !*control_open && !*data_open {
            return None;
        }

        if *control_open && *data_open {
            tokio::select! {
                biased;
                request = control_rx.recv() => match request {
                    Some(request) => return Some((SendLane::Control, request)),
                    None => *control_open = false,
                },
                request = data_rx.recv() => match request {
                    Some(request) => return Some((SendLane::Data, request)),
                    None => *data_open = false,
                },
            }
        } else if *control_open {
            match control_rx.recv().await {
                Some(request) => return Some((SendLane::Control, request)),
                None => *control_open = false,
            }
        } else {
            match data_rx.recv().await {
                Some(request) => return Some((SendLane::Data, request)),
                None => *data_open = false,
            }
        }
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

async fn fail_sink_owner(
    sink: &mut BoxedPacketBatchSink,
    control_rx: &mut mpsc::Receiver<SendRequest>,
    data_rx: &mut mpsc::Receiver<SendRequest>,
    send_timeout: Option<Duration>,
) {
    control_rx.close();
    data_rx.close();
    while control_rx.try_recv().is_ok() {}
    while data_rx.try_recv().is_ok() {}
    close_sink(sink, send_timeout).await;
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
                let release_data = self
                    .release_data
                    .as_mut()
                    .expect("a blocked data write keeps its release signal");
                match Pin::new(release_data).poll(cx) {
                    Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                        self.pending = None;
                        self.release_data = None;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
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
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(super::CONTROL_QUEUE_CAPACITY);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel(super::DATA_QUEUE_CAPACITY);
        let state = Arc::new(super::DirectSinkState::new(control_tx, data_tx));
        let owner_state = state.clone();
        let owner = tokio::spawn(super::run_sink_owner(
            sink,
            control_rx,
            data_rx,
            owner_state,
            None,
        ));
        let sender = super::DirectTunnelSender { state };

        sender
            .send_batch(sized_batch(PacketType::Data, MAX_PACKET_BATCH_SIZE, 1))
            .await
            .unwrap();

        assert_eq!(start_send_count.load(Ordering::Acquire), 1);
        assert_eq!(flush_count.load(Ordering::Acquire), 1);
        owner.abort();
        let _ = owner.await;
    }

    #[tokio::test]
    async fn control_send_reaches_writer_while_data_flush_is_blocked() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_data, release_data_rx) = oneshot::channel();
        let sink = Box::pin(BlockedDataSink {
            events: events_tx,
            pending: None,
            release_data: Some(release_data_rx),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(super::CONTROL_QUEUE_CAPACITY);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel(super::DATA_QUEUE_CAPACITY);
        let state = std::sync::Arc::new(super::DirectSinkState::new(control_tx, data_tx));
        let owner_state = state.clone();
        tokio::spawn(super::run_sink_owner(
            sink,
            control_rx,
            data_rx,
            owner_state,
            None,
        ));
        let sender = super::DirectTunnelSender { state };

        let data_send = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(1)).await }
        });
        assert_eq!(events_rx.recv().await, Some(WriteKind::Data));

        let control_send = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(control_packet(2)).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if sender.state.control_tx.capacity() < super::CONTROL_QUEUE_CAPACITY {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("control request must enqueue while data flush is blocked");
        release_data.send(()).unwrap();
        assert_eq!(events_rx.recv().await, Some(WriteKind::Control));
        assert!(control_send.await.unwrap().is_ok());
        assert!(data_send.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn control_reserve_admits_when_data_budget_is_full() {
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(super::CONTROL_QUEUE_CAPACITY);
        let (data_tx, _data_rx) = tokio::sync::mpsc::channel(super::DATA_QUEUE_CAPACITY);
        let state = std::sync::Arc::new(super::DirectSinkState::new(control_tx, data_tx));

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

        let control = sized_batch(PacketType::Ping, 1, 500_000);
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
    async fn terminal_write_failure_reaches_queued_callers_and_closes_once() {
        let close_count = Arc::new(AtomicUsize::new(0));
        let sink = Box::pin(FailingSink {
            close_count: close_count.clone(),
        }) as Pin<Box<dyn PacketBatchSink>>;
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(super::CONTROL_QUEUE_CAPACITY);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel(super::DATA_QUEUE_CAPACITY);
        let state = Arc::new(super::DirectSinkState::new(control_tx, data_tx));
        let owner_state = state.clone();
        tokio::spawn(super::run_sink_owner(
            sink,
            control_rx,
            data_rx,
            owner_state,
            None,
        ));
        let sender = super::DirectTunnelSender { state };

        let data = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(data_packet(1)).await }
        });
        let control = tokio::spawn({
            let sender = sender.clone();
            async move { sender.send(control_packet(2)).await }
        });

        assert!(data.await.unwrap().is_err());
        assert!(control.await.unwrap().is_err());
        assert_eq!(close_count.load(Ordering::Acquire), 1);
    }
}
