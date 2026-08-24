use std::{
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use auto_impl::auto_impl;
use futures::{Sink, SinkExt, Stream, StreamExt, task::AtomicWaker};
use parking_lot::Mutex;
use smallvec::SmallVec;

use crate::tunnel::batch::{PARALLEL_CRYPTO_MIN_BATCH_SIZE, PacketBatch};
use crate::{
    peers::crypto_workers::{self, IndexedCryptoJob, SEND_CRYPTO_SLOT_COUNT},
    proto::common::TunnelInfo,
};

use self::stats::Throughput;

use super::*;

pub(crate) fn scalar_before_send_batch<F: TunnelFilter + ?Sized>(
    filter: &F,
    data: PacketBatch,
) -> Option<PacketBatch> {
    let mut filtered = PacketBatch::with_capacity(data.len());
    for packet in data {
        if let Some(packet) = filter.before_send(packet) {
            filtered
                .try_push(packet)
                .expect("a filtered tunnel batch cannot exceed its input");
        }
    }
    (!filtered.is_empty()).then_some(filtered)
}

pub(crate) fn scalar_after_received_batch<F: TunnelFilter + ?Sized>(
    filter: &F,
    data: BatchStreamItem,
) -> Option<BatchStreamItem> {
    let batch = match data {
        Ok(batch) => batch,
        Err(error) => {
            return filter
                .after_received(Err(error))
                .map(|result| result.map(PacketBatch::singleton));
        }
    };
    let mut filtered = PacketBatch::with_capacity(batch.len());
    for packet in batch {
        if let Some(result) = filter.after_received(Ok(packet)) {
            match result {
                Ok(packet) => filtered
                    .try_push(packet)
                    .expect("a filtered tunnel batch cannot exceed its input"),
                Err(error) => return Some(Err(error)),
            }
        }
    }
    (!filtered.is_empty()).then_some(Ok(filtered))
}

#[auto_impl(Arc, Box)]
pub trait TunnelFilter: Send + Sync {
    type FilterOutput;

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => Some(Ok(v)),
            Err(e) => Some(Err(e)),
        }
    }

    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        scalar_before_send_batch(self, data)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        scalar_after_received_batch(self, data)
    }

    /// Enable the bounded indexed send pipeline for filter chains that perform
    /// packet cryptography. Cheap recorder and statistics filters remain inline.
    fn uses_async_crypto_pipeline(&self) -> bool {
        false
    }

    fn filter_output(&self) -> Self::FilterOutput;
}

pub struct TunnelFilterChain<A, B> {
    a: A,
    b: B,
}

impl<A, B, OA, OB> TunnelFilter for TunnelFilterChain<A, B>
where
    A: TunnelFilter<FilterOutput = OA>,
    B: TunnelFilter<FilterOutput = OB>,
{
    type FilterOutput = (OA, OB);
    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        let data = self.a.before_send(data)?;
        self.b.before_send(data)
    }
    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let data = self.b.after_received(data)?;
        self.a.after_received(data)
    }
    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        let data = self.a.before_send_batch(data)?;
        self.b.before_send_batch(data)
    }
    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        let data = self.b.after_received_batch(data)?;
        self.a.after_received_batch(data)
    }
    fn uses_async_crypto_pipeline(&self) -> bool {
        self.a.uses_async_crypto_pipeline() || self.b.uses_async_crypto_pipeline()
    }
    fn filter_output(&self) -> Self::FilterOutput {
        (self.a.filter_output(), self.b.filter_output())
    }
}

impl<A, B> TunnelFilterChain<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }

    pub fn chain<T: TunnelFilter>(self, c: T) -> TunnelFilterChain<Self, T> {
        TunnelFilterChain::new(self, c)
    }
}

pub struct EmptyFilter;
impl TunnelFilter for EmptyFilter {
    type FilterOutput = ();
    fn filter_output(&self) {}
}

pub trait ToTunnelChain {
    fn to_chain(self) -> TunnelFilterChain<EmptyFilter, Self>
    where
        Self: Sized,
    {
        TunnelFilterChain::new(EmptyFilter, self)
    }
}

impl<O, T: TunnelFilter<FilterOutput = O>> ToTunnelChain for T {}

const CRYPTO_SLOT_FREE: u8 = 0;
const CRYPTO_SLOT_QUEUED: u8 = 1;
const CRYPTO_SLOT_CRYPTED: u8 = 2;
const CRYPTO_SLOT_DEAD: u8 = 3;
const CRYPTO_SLOT_IN_IO: u8 = 4;

struct SendCryptoSlot {
    state: AtomicU8,
    batch: Mutex<Option<PacketBatch>>,
}

impl SendCryptoSlot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(CRYPTO_SLOT_FREE),
            batch: Mutex::new(None),
        }
    }
}

struct SendCryptoSlots<F> {
    filter: Arc<F>,
    slots: Box<[SendCryptoSlot]>,
    owner_waker: AtomicWaker,
}

impl<F> SendCryptoSlots<F>
where
    F: TunnelFilter + 'static,
{
    fn new(filter: Arc<F>) -> Self {
        let slots = (0..SEND_CRYPTO_SLOT_COUNT)
            .map(|_| SendCryptoSlot::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            filter,
            slots,
            owner_waker: AtomicWaker::new(),
        }
    }

    fn state(&self, slot_index: usize) -> u8 {
        self.slots[slot_index].state.load(Ordering::Acquire)
    }

    fn register_owner(&self, cx: &Context<'_>) {
        self.owner_waker.register(cx.waker());
    }

    fn queue_batch(&self, slot_index: usize, batch: PacketBatch) {
        let slot = &self.slots[slot_index];
        debug_assert_eq!(slot.state.load(Ordering::Acquire), CRYPTO_SLOT_FREE);
        let previous = slot.batch.lock().replace(batch);
        debug_assert!(previous.is_none());
        slot.state.store(CRYPTO_SLOT_QUEUED, Ordering::Release);
    }

    fn take_crypted_batch(&self, slot_index: usize) -> PacketBatch {
        let slot = &self.slots[slot_index];
        debug_assert_eq!(slot.state.load(Ordering::Acquire), CRYPTO_SLOT_CRYPTED);
        let batch = slot
            .batch
            .lock()
            .take()
            .expect("a CRYPTED slot must retain its packet batch");
        slot.state.store(CRYPTO_SLOT_IN_IO, Ordering::Release);
        batch
    }

    fn release_slot(&self, slot_index: usize) {
        let slot = &self.slots[slot_index];
        slot.batch.lock().take();
        slot.state.store(CRYPTO_SLOT_FREE, Ordering::Release);
    }
}

impl<F> IndexedCryptoJob for SendCryptoSlots<F>
where
    F: TunnelFilter + 'static,
{
    fn process_crypto_slot(&self, slot_index: usize) {
        let slot = &self.slots[slot_index];
        if slot.state.load(Ordering::Acquire) != CRYPTO_SLOT_QUEUED {
            return;
        }
        let Some(batch) = slot.batch.lock().take() else {
            self.mark_crypto_slot_dead(slot_index);
            return;
        };

        match catch_unwind(AssertUnwindSafe(|| self.filter.before_send_batch(batch))) {
            Ok(Some(batch)) => {
                *slot.batch.lock() = Some(batch);
                slot.state.store(CRYPTO_SLOT_CRYPTED, Ordering::Release);
            }
            Ok(None) => {
                slot.state.store(CRYPTO_SLOT_DEAD, Ordering::Release);
            }
            Err(_) => {
                slot.state.store(CRYPTO_SLOT_DEAD, Ordering::Release);
                tracing::error!(slot_index, "send filter panicked; crypto slot marked DEAD");
            }
        }
        self.owner_waker.wake();
    }

    fn mark_crypto_slot_dead(&self, slot_index: usize) {
        let slot = &self.slots[slot_index];
        slot.batch.lock().take();
        slot.state.store(CRYPTO_SLOT_DEAD, Ordering::Release);
        self.owner_waker.wake();
    }
}

struct FilteredBatchSink<F, S> {
    sink: S,
    filter: Arc<F>,
    crypto: Option<Arc<SendCryptoSlots<F>>>,
    free_slots: SmallVec<[u16; SEND_CRYPTO_SLOT_COUNT]>,
    completion_fifo: VecDeque<u16>,
    in_io: SmallVec<[u16; SEND_CRYPTO_SLOT_COUNT]>,
}

impl<F, S> FilteredBatchSink<F, S>
where
    F: TunnelFilter + 'static,
    S: PacketBatchSink + Unpin + 'static,
{
    fn new(filter: Arc<F>, sink: S) -> Self {
        let crypto = (filter.uses_async_crypto_pipeline()
            && crypto_workers::send_crypto_pipeline_enabled())
        .then(|| Arc::new(SendCryptoSlots::new(filter.clone())));
        let mut free_slots = SmallVec::new();
        if crypto.is_some() {
            free_slots.extend((0..SEND_CRYPTO_SLOT_COUNT as u16).rev());
        }
        Self {
            sink,
            filter,
            crypto,
            free_slots,
            completion_fifo: VecDeque::with_capacity(SEND_CRYPTO_SLOT_COUNT),
            in_io: SmallVec::new(),
        }
    }

    fn poll_completed_prefix(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let crypto = self
            .crypto
            .as_ref()
            .expect("the async completion path has crypto slots")
            .clone();

        loop {
            let Some(&slot_index) = self.completion_fifo.front() else {
                return Poll::Ready(Ok(()));
            };
            let slot_index_usize = usize::from(slot_index);
            match crypto.state(slot_index_usize) {
                CRYPTO_SLOT_QUEUED => {
                    crypto.register_owner(cx);
                    if crypto.state(slot_index_usize) == CRYPTO_SLOT_QUEUED {
                        return Poll::Pending;
                    }
                }
                CRYPTO_SLOT_CRYPTED => match self.sink.poll_ready_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        let batch = crypto.take_crypted_batch(slot_index_usize);
                        self.completion_fifo.pop_front();
                        if let Err(error) = self.sink.start_send_unpin(batch) {
                            crypto.release_slot(slot_index_usize);
                            self.free_slots.push(slot_index);
                            return Poll::Ready(Err(error));
                        }
                        self.in_io.push(slot_index);
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                },
                CRYPTO_SLOT_DEAD => {
                    self.completion_fifo.pop_front();
                    crypto.release_slot(slot_index_usize);
                    self.free_slots.push(slot_index);
                }
                state => {
                    return Poll::Ready(Err(TunnelError::InternalError(format!(
                        "invalid crypto completion state {state} for slot {slot_index}"
                    ))));
                }
            }
        }
    }

    fn release_io_slots(&mut self) {
        let crypto = self
            .crypto
            .as_ref()
            .expect("I/O slots require an async crypto pipeline")
            .clone();
        for slot_index in self.in_io.drain(..) {
            crypto.release_slot(usize::from(slot_index));
            self.free_slots.push(slot_index);
        }
    }

    fn poll_ready_async(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        loop {
            if let Poll::Ready(Err(error)) = self.poll_completed_prefix(cx) {
                return Poll::Ready(Err(error));
            }
            if !self.free_slots.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if !self.in_io.is_empty() {
                match self.sink.poll_flush_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        self.release_io_slots();
                        continue;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }

            let crypto = self
                .crypto
                .as_ref()
                .expect("the async readiness path has crypto slots")
                .clone();
            crypto.register_owner(cx);
            match self.poll_completed_prefix(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if !self.free_slots.is_empty() => continue,
                Poll::Ready(Ok(())) | Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush_async(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        match self.poll_completed_prefix(cx) {
            Poll::Ready(Ok(())) => match self.sink.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    self.release_io_slots();
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close_async(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        match self.poll_completed_prefix(cx) {
            Poll::Ready(Ok(())) => match self.sink.poll_close_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    self.release_io_slots();
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, S> Sink<PacketBatch> for FilteredBatchSink<F, S>
where
    F: TunnelFilter + 'static,
    S: PacketBatchSink + Unpin + 'static,
{
    type Error = SinkError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let self_mut = self.as_mut().get_mut();
        if self_mut.crypto.is_some() {
            self_mut.poll_ready_async(cx)
        } else {
            self_mut.sink.poll_ready_unpin(cx)
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: PacketBatch) -> Result<(), Self::Error> {
        let self_mut = self.get_mut();
        let Some(crypto) = self_mut.crypto.clone() else {
            let Some(item) = self_mut.filter.before_send_batch(item) else {
                return Ok(());
            };
            return self_mut.sink.start_send_unpin(item);
        };

        if item.is_empty() {
            return Ok(());
        }
        let process_inline =
            item.len() < PARALLEL_CRYPTO_MIN_BATCH_SIZE || item.prefers_inline_crypto();
        let slot_index = self_mut.free_slots.pop().ok_or_else(|| {
            TunnelError::InternalError("crypto pipeline received data before readiness".to_owned())
        })?;
        let slot_index_usize = usize::from(slot_index);
        crypto.queue_batch(slot_index_usize, item);
        self_mut.completion_fifo.push_back(slot_index);

        if process_inline {
            crypto.process_crypto_slot(slot_index_usize);
        } else {
            let job_owner: Arc<dyn IndexedCryptoJob> = crypto.clone();
            if !crypto_workers::try_submit_indexed_crypto_job(job_owner, slot_index_usize) {
                crypto.process_crypto_slot(slot_index_usize);
            }
        }
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let self_mut = self.as_mut().get_mut();
        if self_mut.crypto.is_some() {
            self_mut.poll_flush_async(cx)
        } else {
            self_mut.sink.poll_flush_unpin(cx)
        }
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let self_mut = self.as_mut().get_mut();
        if self_mut.crypto.is_some() {
            self_mut.poll_close_async(cx)
        } else {
            self_mut.sink.poll_close_unpin(cx)
        }
    }
}

pub struct TunnelWithFilter<T, F> {
    inner: T,
    filter: Arc<F>,
}

impl<T, F> TunnelWithFilter<T, F>
where
    T: Tunnel + Send + 'static,
    F: TunnelFilter + Send + 'static,
{
    pub fn new(inner: T, filter: F) -> Self {
        Self {
            inner,
            filter: Arc::new(filter),
        }
    }

    fn wrap_sink<S: PacketBatchSink + Unpin + 'static>(
        filter: Arc<F>,
        sink: S,
    ) -> impl PacketBatchSink {
        FilteredBatchSink::new(filter, sink)
    }

    fn wrap_stream<S: PacketBatchStream + Unpin + 'static>(
        filter: Arc<F>,
        stream: S,
    ) -> impl PacketBatchStream {
        struct StreamWrapper<F, S> {
            stream: S,
            filter: Arc<F>,
        }

        impl<F, S> Stream for StreamWrapper<F, S>
        where
            F: TunnelFilter + 'static,
            S: PacketBatchStream + 'static + Unpin,
        {
            type Item = BatchStreamItem;

            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let self_mut = self.get_mut();
                loop {
                    match self_mut.stream.poll_next_unpin(cx) {
                        Poll::Ready(Some(ret)) => {
                            let Some(ret) = self_mut.filter.after_received_batch(ret) else {
                                continue;
                            };
                            return Poll::Ready(Some(ret));
                        }
                        Poll::Ready(None) => {
                            return Poll::Ready(None);
                        }
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                    }
                }
            }
        }

        StreamWrapper { stream, filter }
    }
}

impl<T, F> Tunnel for TunnelWithFilter<T, F>
where
    T: Tunnel + Send + 'static,
    F: TunnelFilter + Send + 'static,
{
    fn info(&self) -> Option<TunnelInfo> {
        self.inner.info()
    }

    fn datagram_size_budget(&self) -> Option<DatagramSizeBudget> {
        self.inner.datagram_size_budget()
    }

    fn transport_binding(&self) -> Option<TransportBinding> {
        self.inner.transport_binding()
    }

    fn is_transport_authenticated(&self) -> bool {
        self.inner.is_transport_authenticated()
    }

    fn split(&self) -> SplitTunnel {
        let (stream, sink) = self.inner.split();
        let filter = self.filter.clone();
        (
            Box::pin(Self::wrap_stream(filter.clone(), stream)),
            Box::pin(Self::wrap_sink(filter, sink)),
        )
    }
}

pub struct PacketRecorderTunnelFilter {
    pub received: Arc<std::sync::Mutex<Vec<ZCPacket>>>,
    pub sent: Arc<std::sync::Mutex<Vec<ZCPacket>>>,
}

impl TunnelFilter for PacketRecorderTunnelFilter {
    type FilterOutput = (Vec<ZCPacket>, Vec<ZCPacket>);

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        self.sent.lock().unwrap().push(data.clone());
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => {
                self.received.lock().unwrap().push(v.clone());
                Some(Ok(v))
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn filter_output(&self) -> Self::FilterOutput {
        (
            self.sent.lock().unwrap().clone(),
            self.received.lock().unwrap().clone(),
        )
    }
}

impl Default for PacketRecorderTunnelFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketRecorderTunnelFilter {
    pub fn new() -> Self {
        Self {
            received: Arc::new(std::sync::Mutex::new(Vec::new())),
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

pub struct StatsRecorderTunnelFilter {
    throughput: Arc<Throughput>,
}

impl TunnelFilter for StatsRecorderTunnelFilter {
    type FilterOutput = Arc<Throughput>;

    fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
        self.throughput.record_tx_bytes(data.buf_len() as u64);
        Some(data)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        match data {
            Ok(v) => {
                self.throughput.record_rx_bytes(v.buf_len() as u64);
                Some(Ok(v))
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
        self.throughput
            .record_tx_batch(data.buffer_byte_len() as u64, data.len() as u64);
        Some(data)
    }

    fn after_received_batch(&self, data: BatchStreamItem) -> Option<BatchStreamItem> {
        if let Ok(batch) = &data {
            self.throughput
                .record_rx_batch(batch.buffer_byte_len() as u64, batch.len() as u64);
        }
        Some(data)
    }

    fn filter_output(&self) -> Self::FilterOutput {
        self.throughput.clone()
    }
}

impl Default for StatsRecorderTunnelFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsRecorderTunnelFilter {
    pub fn new() -> Self {
        Self {
            throughput: Arc::new(Throughput::new()),
        }
    }

    pub fn get_throughput(&self) -> Arc<Throughput> {
        self.throughput.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        task::{Context, Poll},
        time::Duration,
    };

    use filter::ring::create_ring_tunnel_pair;
    use futures::{Sink, SinkExt, task::AtomicWaker};
    use tokio::{sync::Notify, time::timeout};

    use super::*;

    pub struct DropSendTunnelFilter {
        start: AtomicU32,
        end: AtomicU32,
        cur: AtomicU32,
    }

    impl TunnelFilter for DropSendTunnelFilter {
        type FilterOutput = ();

        fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
            self.cur.fetch_add(1, Ordering::SeqCst);
            if self.cur.load(Ordering::SeqCst) >= self.start.load(Ordering::SeqCst)
                && self.cur.load(std::sync::atomic::Ordering::SeqCst)
                    < self.end.load(Ordering::SeqCst)
            {
                tracing::trace!("drop packet: {:?}", data);
                return None;
            }
            Some(data)
        }

        fn filter_output(&self) {}
    }

    impl DropSendTunnelFilter {
        pub fn new(start: u32, end: u32) -> Self {
            Self {
                start: AtomicU32::new(start),
                end: AtomicU32::new(end),
                cur: AtomicU32::new(0),
            }
        }
    }

    #[tokio::test]
    async fn test_nested_filter() {
        let filter = Arc::new(
            PacketRecorderTunnelFilter::new()
                .to_chain()
                .chain(PacketRecorderTunnelFilter::new())
                .chain(PacketRecorderTunnelFilter::new())
                .chain(PacketRecorderTunnelFilter::new()),
        );
        let (s, _b) = create_ring_tunnel_pair();
        let tunnel = TunnelWithFilter::new(s, filter.clone());

        let (_r, mut s) = tunnel.split();
        s.send(PacketBatch::singleton(ZCPacket::new_with_payload(
            "ab".as_bytes(),
        )))
        .await
        .unwrap();

        let out = filter.filter_output();

        let a = out.0.0.0.1;
        let b = out.0.0.1;
        let c = out.0.1;
        let _d = out.1;

        assert_eq!(1, a.0.len());
        assert_eq!(1, b.0.len());
        assert_eq!(1, c.0.len());
    }

    struct AsyncMarkerFilter {
        dead_marker: Option<u8>,
    }

    struct ThreadRecordingFilter {
        observed: Arc<Mutex<Option<std::thread::ThreadId>>>,
    }

    impl TunnelFilter for ThreadRecordingFilter {
        type FilterOutput = ();

        fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
            *self.observed.lock() = Some(std::thread::current().id());
            Some(data)
        }

        fn uses_async_crypto_pipeline(&self) -> bool {
            true
        }

        fn filter_output(&self) {}
    }

    impl TunnelFilter for AsyncMarkerFilter {
        type FilterOutput = ();

        fn before_send_batch(&self, data: PacketBatch) -> Option<PacketBatch> {
            let marker = data[0].payload()[0];
            (self.dead_marker != Some(marker)).then_some(data)
        }

        fn uses_async_crypto_pipeline(&self) -> bool {
            true
        }

        fn filter_output(&self) {}
    }

    struct RecordingBatchSink {
        markers: Arc<Mutex<Vec<u8>>>,
    }

    impl Sink<PacketBatch> for RecordingBatchSink {
        type Error = SinkError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            self.get_mut()
                .markers
                .lock()
                .extend(batch.iter().map(|packet| packet.payload()[0]));
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

    struct FlushGate {
        io_complete: AtomicBool,
        started: AtomicUsize,
        owner_waker: AtomicWaker,
        all_slots_started: Notify,
    }

    impl FlushGate {
        fn new() -> Self {
            Self {
                io_complete: AtomicBool::new(false),
                started: AtomicUsize::new(0),
                owner_waker: AtomicWaker::new(),
                all_slots_started: Notify::new(),
            }
        }

        fn complete_io(&self) {
            self.io_complete.store(true, Ordering::Release);
            self.owner_waker.wake();
        }

        fn poll_io_complete(&self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            if self.io_complete.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            self.owner_waker.register(cx.waker());
            if self.io_complete.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    struct FlushGatedBatchSink {
        gate: Arc<FlushGate>,
    }

    impl Sink<PacketBatch> for FlushGatedBatchSink {
        type Error = SinkError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            assert!(!batch.is_empty());
            let gate = &self.get_mut().gate;
            let started = gate.started.fetch_add(1, Ordering::AcqRel) + 1;
            if started == SEND_CRYPTO_SLOT_COUNT {
                gate.all_slots_started.notify_one();
            }
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().gate.poll_io_complete(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().gate.poll_io_complete(cx)
        }
    }

    fn marker_batch(marker: u8) -> PacketBatch {
        PacketBatch::singleton(ZCPacket::new_with_payload(&[marker]))
    }

    fn inline_large_marker_batch(marker: u8) -> PacketBatch {
        let mut batch = PacketBatch::with_capacity(PARALLEL_CRYPTO_MIN_BATCH_SIZE);
        for _ in 0..PARALLEL_CRYPTO_MIN_BATCH_SIZE {
            batch
                .try_push(ZCPacket::new_with_payload(&[marker]))
                .unwrap();
        }
        batch.mark_inline_crypto();
        batch
    }

    #[tokio::test]
    async fn sparse_crypto_job_runs_on_the_peer_owner_thread() {
        let caller = std::thread::current().id();
        let observed = Arc::new(Mutex::new(None));
        let markers = Arc::new(Mutex::new(Vec::new()));
        let filter = Arc::new(ThreadRecordingFilter {
            observed: observed.clone(),
        });
        let mut sink = FilteredBatchSink::new(
            filter,
            RecordingBatchSink {
                markers: markers.clone(),
            },
        );

        sink.feed(marker_batch(7)).await.unwrap();
        sink.flush().await.unwrap();

        assert_eq!(observed.lock().as_ref(), Some(&caller));
        assert_eq!(*markers.lock(), vec![7]);
    }

    #[tokio::test]
    async fn hinted_large_crypto_job_runs_on_the_peer_owner_thread() {
        let caller = std::thread::current().id();
        let observed = Arc::new(Mutex::new(None));
        let markers = Arc::new(Mutex::new(Vec::new()));
        let filter = Arc::new(ThreadRecordingFilter {
            observed: observed.clone(),
        });
        let mut sink = FilteredBatchSink::new(
            filter,
            RecordingBatchSink {
                markers: markers.clone(),
            },
        );

        sink.feed(inline_large_marker_batch(9)).await.unwrap();
        sink.flush().await.unwrap();

        assert_eq!(observed.lock().as_ref(), Some(&caller));
        assert_eq!(markers.lock().len(), PARALLEL_CRYPTO_MIN_BATCH_SIZE);
    }

    #[tokio::test]
    async fn completed_prefix_drains_crypted_and_dead_slots_in_submission_order() {
        let markers = Arc::new(Mutex::new(Vec::new()));
        let filter = Arc::new(AsyncMarkerFilter {
            dead_marker: Some(3),
        });
        let mut sink = FilteredBatchSink::new(
            filter,
            RecordingBatchSink {
                markers: markers.clone(),
            },
        );
        let crypto = sink.crypto.as_ref().unwrap().clone();
        let mut submitted_slots = Vec::with_capacity(SEND_CRYPTO_SLOT_COUNT);

        for marker in 0..SEND_CRYPTO_SLOT_COUNT as u8 {
            let slot_index = sink.free_slots.pop().unwrap();
            crypto.queue_batch(usize::from(slot_index), marker_batch(marker));
            sink.completion_fifo.push_back(slot_index);
            submitted_slots.push(slot_index);
        }
        for slot_index in submitted_slots.iter().rev().copied() {
            crypto.process_crypto_slot(usize::from(slot_index));
        }

        assert_eq!(crypto.state(3), CRYPTO_SLOT_DEAD);
        sink.flush().await.unwrap();

        assert_eq!(*markers.lock(), vec![0, 1, 2, 4, 5, 6, 7]);
        assert!(sink.completion_fifo.is_empty());
        assert!(sink.in_io.is_empty());
        assert_eq!(sink.free_slots.len(), SEND_CRYPTO_SLOT_COUNT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stable_slots_release_only_after_transport_flush_completion() {
        let gate = Arc::new(FlushGate::new());
        let filter = Arc::new(AsyncMarkerFilter { dead_marker: None });
        let mut sink = FilteredBatchSink::new(filter, FlushGatedBatchSink { gate: gate.clone() });

        for marker in 0..SEND_CRYPTO_SLOT_COUNT as u8 {
            sink.feed(marker_batch(marker)).await.unwrap();
        }

        {
            let ninth = sink.feed(marker_batch(SEND_CRYPTO_SLOT_COUNT as u8));
            tokio::pin!(ninth);
            tokio::select! {
                biased;
                result = &mut ninth => panic!("ninth slot bypassed I/O completion: {result:?}"),
                _ = gate.all_slots_started.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    panic!("crypto workers did not deliver all stable slots")
                }
            }
        }

        assert_eq!(gate.started.load(Ordering::Acquire), SEND_CRYPTO_SLOT_COUNT);
        assert!(sink.free_slots.is_empty());
        assert!(sink.completion_fifo.is_empty());
        assert_eq!(sink.in_io.len(), SEND_CRYPTO_SLOT_COUNT);

        gate.complete_io();
        timeout(
            Duration::from_secs(2),
            sink.feed(marker_batch(SEND_CRYPTO_SLOT_COUNT as u8)),
        )
        .await
        .unwrap()
        .unwrap();
        timeout(Duration::from_secs(2), sink.flush())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            gate.started.load(Ordering::Acquire),
            SEND_CRYPTO_SLOT_COUNT + 1
        );
        assert!(sink.completion_fifo.is_empty());
        assert!(sink.in_io.is_empty());
        assert_eq!(sink.free_slots.len(), SEND_CRYPTO_SLOT_COUNT);
    }
}
