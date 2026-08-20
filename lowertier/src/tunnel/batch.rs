use std::{
    collections::VecDeque,
    future::Future,
    io, mem,
    ops::{Deref, DerefMut},
    pin::Pin,
    ptr, slice,
    sync::OnceLock,
    task::{Context, Poll},
};

use crossbeam::queue::ArrayQueue;
use futures::{Sink, Stream, StreamExt, ready};
use pin_project_lite::pin_project;
use rayon::prelude::*;
use smallvec::SmallVec;

use super::{TunnelError, packet_def::ZCPacket};

/// Maximum number of packets carried by one scheduling and I/O batch.
///
/// This matches the existing Darwin utun vector width. A batch never waits to
/// reach this size; producers append only packets that are already available.
pub const MAX_PACKET_BATCH_SIZE: usize = 64;

pub const PARALLEL_CRYPTO_MIN_BATCH_SIZE: usize = 32;
const RETAINED_PACKET_BATCH_CONTAINERS: usize = 32;

static PARALLEL_CRYPTO_ENABLED: OnceLock<bool> = OnceLock::new();
static PACKET_BATCH_LIMIT: OnceLock<usize> = OnceLock::new();

fn packet_batch_limit_from(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| (1..=MAX_PACKET_BATCH_SIZE).contains(limit))
        .unwrap_or(MAX_PACKET_BATCH_SIZE)
}

/// Runtime batch cap used by controlled performance-model sweeps.
///
/// Production defaults to the compile-time maximum. Producers never wait to
/// reach this cap; it only limits how many already-ready packets are grouped.
pub(crate) fn packet_batch_limit() -> usize {
    *PACKET_BATCH_LIMIT.get_or_init(|| {
        let value = std::env::var("LOWTIER_PACKET_BATCH_LIMIT").ok();
        packet_batch_limit_from(value.as_deref())
    })
}

pub(crate) fn drain_ready_count<F>(
    mut count: usize,
    capacity: usize,
    mut receive: F,
) -> (usize, Option<io::Error>)
where
    F: FnMut(usize) -> io::Result<usize>,
{
    while count < capacity {
        match receive(count) {
            Ok(0) => {
                return (
                    count,
                    Some(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "a ready packet read returned no packets",
                    )),
                );
            }
            Ok(received) if received <= capacity - count => count += received,
            Ok(_) => {
                return (
                    count,
                    Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a ready packet read exceeded the batch capacity",
                    )),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return (count, Some(error)),
        }
    }
    (count, None)
}

/// Maximum number of owned receive batches held while one delivery runs.
///
/// Slot 0 is the batch currently writing to TUN. The remaining slots keep QUIC
/// application drain moving without an unbounded queue.
pub const RECEIVE_PREFETCH_BATCHES: usize = 3;

/// Deliver one batch while continuously prefetching ready stream items.
///
/// `max_prefetch` bounds the number of fully received items held beside the
/// in-flight delivery. When the stream ends, the function stops polling it and
/// waits only for delivery. The third return value is true when the stream
/// ended during this wait.
pub(crate) async fn wait_for_delivery_with_bounded_prefetch<S, F, T, E>(
    stream: &mut S,
    delivery: F,
    max_prefetch: usize,
) -> (Result<(), E>, VecDeque<T>, bool)
where
    S: Stream<Item = T> + Unpin,
    F: Future<Output = Result<(), E>>,
{
    tokio::pin!(delivery);
    let mut prefetched = VecDeque::with_capacity(max_prefetch.min(8));
    let mut stream_open = true;
    let mut stream_ended = false;
    loop {
        tokio::select! {
            biased;
            result = &mut delivery => return (result, prefetched, stream_ended),
            next = stream.next(), if stream_open && prefetched.len() < max_prefetch => {
                match next {
                    Some(item) => prefetched.push_back(item),
                    None => {
                        stream_open = false;
                        stream_ended = true;
                    }
                }
            }
        }
    }
}

pub(crate) async fn wait_for_delivery_with_one_prefetch<S, F, T, E>(
    stream: &mut S,
    delivery: F,
) -> (Result<(), E>, Option<Option<T>>)
where
    S: Stream<Item = T> + Unpin,
    F: Future<Output = Result<(), E>>,
{
    let (result, mut prefetched, stream_ended) =
        wait_for_delivery_with_bounded_prefetch(stream, delivery, 1).await;
    let prefetched = if let Some(item) = prefetched.pop_front() {
        Some(Some(item))
    } else if stream_ended {
        Some(None)
    } else {
        None
    };
    (result, prefetched)
}

fn parallel_crypto_configured(
    batch_size: usize,
    explicitly_enabled: bool,
    explicitly_disabled: bool,
) -> bool {
    explicitly_enabled && batch_size >= PARALLEL_CRYPTO_MIN_BATCH_SIZE && !explicitly_disabled
}

pub fn parallel_crypto_enabled(batch_size: usize) -> bool {
    let enabled = *PARALLEL_CRYPTO_ENABLED.get_or_init(|| {
        std::env::var_os("LOWTIER_ENABLE_PARALLEL_CRYPTO").is_some()
            && std::env::var_os("LOWTIER_DEBUG_DISABLE_PARALLEL_CRYPTO").is_none()
    });
    parallel_crypto_configured(batch_size, enabled, false)
}

/// Runs independent packet work in parallel while retaining the owning
/// vector and its original packet order. Rayon may finish entries in any
/// order, but each worker mutates only its existing indexed slot.
pub fn ordered_parallel_try_for_each<T, E, F>(items: &mut [T], operation: F) -> Result<(), E>
where
    T: Send,
    E: Send,
    F: Fn(&mut T) -> Result<(), E> + Sync + Send,
{
    items.par_iter_mut().try_for_each(operation)
}

struct PacketBatchPool {
    containers: ArrayQueue<Vec<ZCPacket>>,
}

impl PacketBatchPool {
    fn new(capacity: usize) -> Self {
        Self {
            containers: ArrayQueue::new(capacity),
        }
    }

    fn take(&self) -> Vec<ZCPacket> {
        self.containers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(MAX_PACKET_BATCH_SIZE))
    }

    fn recycle(&self, mut packets: Vec<ZCPacket>) {
        packets.clear();
        if packets.capacity() < MAX_PACKET_BATCH_SIZE {
            return;
        }
        let _ = self.containers.push(packets);
    }
}

static PACKET_BATCH_POOL: OnceLock<PacketBatchPool> = OnceLock::new();

fn packet_batch_pool() -> &'static PacketBatchPool {
    PACKET_BATCH_POOL.get_or_init(|| PacketBatchPool::new(RETAINED_PACKET_BATCH_CONTAINERS))
}

/// A bounded, owning packet vector from a bounded container pool.
///
/// Packets keep their existing `BytesMut` storage when moved into and out of a
/// batch. The type intentionally exposes no unbounded `push` operation.
#[derive(Debug)]
pub struct PacketBatch {
    packets: Vec<ZCPacket>,
}

impl PacketBatch {
    pub fn new() -> Self {
        Self {
            packets: packet_batch_pool().take(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity <= MAX_PACKET_BATCH_SIZE);
        if capacity >= MAX_PACKET_BATCH_SIZE {
            return Self::new();
        }
        Self {
            packets: Vec::with_capacity(capacity),
        }
    }

    pub fn singleton(packet: ZCPacket) -> Self {
        let mut batch = Self::with_capacity(1);
        batch
            .try_push(packet)
            .expect("a new packet batch accepts one packet");
        batch
    }

    #[allow(clippy::result_large_err)]
    pub fn pop_singleton(mut self) -> Result<ZCPacket, Self> {
        if self.packets.len() != 1 {
            return Err(self);
        }
        Ok(self.packets.pop().expect("the packet batch has one entry"))
    }

    pub fn try_push(&mut self, packet: ZCPacket) -> Result<(), ZCPacket> {
        if self.packets.len() == MAX_PACKET_BATCH_SIZE {
            return Err(packet);
        }
        self.packets.push(packet);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        debug_assert!(at <= self.packets.len());
        Self {
            packets: self.packets.split_off(at),
        }
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.packets.truncate(len);
    }

    /// Logical payload bytes in this batch, excluding reserved headroom.
    pub fn byte_len(&self) -> usize {
        self.packets.iter().map(ZCPacket::payload_len).sum()
    }

    /// Backing-buffer bytes, including headers and reserved prefix space.
    pub fn buffer_byte_len(&self) -> usize {
        self.packets.iter().map(ZCPacket::buf_len).sum()
    }

    pub(crate) fn retained_buffer_capacity(&self) -> usize {
        self.packets
            .iter()
            .map(ZCPacket::retained_buffer_capacity)
            .sum()
    }

    pub fn iter(&self) -> slice::Iter<'_, ZCPacket> {
        self.packets.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, ZCPacket> {
        self.packets.iter_mut()
    }

    /// Keep packets in their original order and reuse this batch allocation.
    pub(crate) fn retain_flags(&mut self, keep: &[bool]) {
        assert_eq!(keep.len(), self.packets.len());
        let len = self.packets.len();
        let ptr = self.packets.as_mut_ptr();
        let mut write = 0;
        for (read, should_keep) in keep.iter().copied().enumerate() {
            unsafe {
                if should_keep {
                    let packet = ptr::read(ptr.add(read));
                    ptr::write(ptr.add(write), packet);
                    write += 1;
                } else {
                    ptr::drop_in_place(ptr.add(read));
                }
            }
        }
        debug_assert!(write <= len);
        unsafe { self.packets.set_len(write) };
    }

    /// Process one selected packet group and merge it back into this batch.
    ///
    /// The selected packets keep their original order. The batch keeps its
    /// original allocation. The closure returns one keep flag per selection.
    pub(crate) fn process_selected_with_keep_flags<F, E>(
        &mut self,
        selected: &[bool],
        keep_unselected: &[bool],
        process: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&mut [ZCPacket]) -> Result<SmallVec<[bool; MAX_PACKET_BATCH_SIZE]>, E>,
    {
        assert_eq!(selected.len(), self.packets.len());
        assert_eq!(keep_unselected.len(), self.packets.len());

        let len = self.packets.len();
        let selected_len = selected.iter().filter(|selected| **selected).count();
        let ptr = self.packets.as_mut_ptr();
        let mut selected_packets = SmallVec::<[ZCPacket; MAX_PACKET_BATCH_SIZE]>::new();
        for (index, is_selected) in selected.iter().copied().enumerate() {
            if is_selected {
                unsafe { selected_packets.push(ptr::read(ptr.add(index))) };
            }
        }

        // Restore moved packets before unwinding. This keeps PacketBatch safe
        // when a crypto implementation reports an unexpected panic.
        let process_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process(selected_packets.as_mut_slice())
        }));
        let selected_keep = match process_result {
            Ok(Ok(flags)) => {
                assert_eq!(flags.len(), selected_len);
                flags
            }
            Ok(Err(error)) => {
                unsafe { restore_selected_packets(ptr, selected, selected_packets) };
                return Err(error);
            }
            Err(payload) => {
                unsafe { restore_selected_packets(ptr, selected, selected_packets) };
                std::panic::resume_unwind(payload);
            }
        };

        let mut selected_index = 0;
        let mut selected_packets = selected_packets.into_iter();
        let mut write = 0;
        for (index, is_selected) in selected.iter().copied().enumerate() {
            unsafe {
                if is_selected {
                    let packet = selected_packets
                        .next()
                        .expect("selected packet count stays stable");
                    selected_index += 1;
                    if selected_keep[selected_index - 1] {
                        ptr::write(ptr.add(write), packet);
                        write += 1;
                    } else {
                        drop(packet);
                    }
                } else if keep_unselected[index] {
                    let packet = ptr::read(ptr.add(index));
                    ptr::write(ptr.add(write), packet);
                    write += 1;
                } else {
                    ptr::drop_in_place(ptr.add(index));
                }
            }
        }
        debug_assert_eq!(selected_index, selected_len);
        debug_assert!(selected_packets.next().is_none());
        debug_assert!(write <= len);
        unsafe { self.packets.set_len(write) };
        Ok(())
    }
}

unsafe fn restore_selected_packets(
    ptr: *mut ZCPacket,
    selected: &[bool],
    selected_packets: SmallVec<[ZCPacket; MAX_PACKET_BATCH_SIZE]>,
) {
    let mut selected_packets = selected_packets.into_iter();
    for (index, is_selected) in selected.iter().copied().enumerate() {
        if is_selected {
            let packet = selected_packets
                .next()
                .expect("selected packet count stays stable");
            // The caller moved each selected slot out before this restore.
            unsafe {
                ptr::write(ptr.add(index), packet);
            }
        }
    }
    debug_assert!(selected_packets.next().is_none());
}

impl Drop for PacketBatch {
    fn drop(&mut self) {
        let packets = mem::take(&mut self.packets);
        packet_batch_pool().recycle(packets);
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PacketBatch {
    type Target = [ZCPacket];

    fn deref(&self) -> &Self::Target {
        &self.packets
    }
}

impl DerefMut for PacketBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packets
    }
}

impl IntoIterator for PacketBatch {
    type Item = ZCPacket;
    type IntoIter = PacketBatchIntoIter;

    fn into_iter(mut self) -> Self::IntoIter {
        let mut packets = mem::take(&mut self.packets);
        let len = packets.len();
        // The iterator moves each initialized packet with `ptr::read`.
        // A zero length prevents `Vec` from dropping moved packets twice.
        unsafe { packets.set_len(0) };
        PacketBatchIntoIter {
            packets: Some(packets),
            next: 0,
            len,
        }
    }
}

pub struct PacketBatchIntoIter {
    packets: Option<Vec<ZCPacket>>,
    next: usize,
    len: usize,
}

impl Iterator for PacketBatchIntoIter {
    type Item = ZCPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.len {
            return None;
        }
        let packets = self.packets.as_ref().expect("the batch storage exists");
        // The index identifies one initialized and unread packet.
        let packet = unsafe { ptr::read(packets.as_ptr().add(self.next)) };
        self.next += 1;
        Some(packet)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PacketBatchIntoIter {}

impl Drop for PacketBatchIntoIter {
    fn drop(&mut self) {
        let Some(packets) = self.packets.take() else {
            return;
        };
        for index in self.next..self.len {
            // These packets remain initialized because iteration did not read them.
            unsafe { ptr::drop_in_place(packets.as_ptr().add(index) as *mut ZCPacket) };
        }
        packet_batch_pool().recycle(packets);
    }
}

impl<'a> IntoIterator for &'a PacketBatch {
    type Item = &'a ZCPacket;
    type IntoIter = slice::Iter<'a, ZCPacket>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.iter()
    }
}

pin_project! {
    /// Converts a scalar transport reader into the batch-first tunnel interface.
    ///
    /// This adapter is for control and compatibility transports. Native data
    /// transports must produce `PacketBatch` directly.
    pub struct ScalarToBatchStream<S> {
        #[pin]
        inner: S,
        pending_error: Option<TunnelError>,
    }
}

impl<S> ScalarToBatchStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending_error: None,
        }
    }
}

impl<S> Stream for ScalarToBatchStream<S>
where
    S: Stream<Item = Result<ZCPacket, TunnelError>>,
{
    type Item = Result<PacketBatch, TunnelError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if let Some(error) = this.pending_error.take() {
            return Poll::Ready(Some(Err(error)));
        }

        let first = match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(packet))) => packet,
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };

        let mut batch = PacketBatch::new();
        batch
            .try_push(first)
            .expect("a new packet batch accepts its first packet");
        while batch.len() < packet_batch_limit() {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(packet))) => batch
                    .try_push(packet)
                    .expect("the scalar adapter checks the batch bound"),
                Poll::Ready(Some(Err(error))) => {
                    *this.pending_error = Some(error);
                    break;
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
        Poll::Ready(Some(Ok(batch)))
    }
}

pin_project! {
    /// Exposes a batch stream to scalar control consumers.
    pub struct BatchToScalarStream<S> {
        #[pin]
        inner: S,
        pending: VecDeque<ZCPacket>,
    }
}

impl<S> BatchToScalarStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE),
        }
    }
}

impl<S> Stream for BatchToScalarStream<S>
where
    S: Stream<Item = Result<PacketBatch, TunnelError>>,
{
    type Item = Result<ZCPacket, TunnelError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if let Some(packet) = this.pending.pop_front() {
            return Poll::Ready(Some(Ok(packet)));
        }

        loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) if batch.is_empty() => continue,
                Poll::Ready(Some(Ok(batch))) => {
                    this.pending.extend(batch);
                    return Poll::Ready(this.pending.pop_front().map(Ok));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Converts a scalar transport writer into the batch-first tunnel interface.
///
/// It preserves downstream readiness for every packet. It flushes only after
/// the complete owned batch enters the scalar writer.
pub struct ScalarToBatchSink<S> {
    inner: S,
    pending: Option<PacketBatchIntoIter>,
    current: Option<ZCPacket>,
}

impl<S> ScalarToBatchSink<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: None,
            current: None,
        }
    }
}

impl<S> ScalarToBatchSink<S>
where
    S: Sink<ZCPacket, Error = TunnelError> + Unpin,
{
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        loop {
            if self.current.is_none() {
                self.current = self.pending.as_mut().and_then(Iterator::next);
                if self.current.is_none() {
                    self.pending = None;
                    return Poll::Ready(Ok(()));
                }
            }

            ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
            let packet = self.current.take().expect("a ready scalar packet exists");
            Pin::new(&mut self.inner).start_send(packet)?;
        }
    }
}

impl<S> Sink<PacketBatch> for ScalarToBatchSink<S>
where
    S: Sink<ZCPacket, Error = TunnelError> + Unpin,
{
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_pending(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        if self.pending.is_some() || self.current.is_some() {
            return Err(TunnelError::InternalError(
                "batch sink received data without readiness".to_owned(),
            ));
        }
        self.pending = Some(batch.into_iter());
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_pending(cx))?;
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod batch_interface_tests {
    use futures::{SinkExt, StreamExt, channel::mpsc, stream};

    use super::{BatchToScalarStream, PacketBatch, ScalarToBatchSink, ScalarToBatchStream};
    use crate::tunnel::{Tunnel, packet_def::ZCPacket, ring::create_ring_tunnel_pair};

    fn packet(value: u8) -> ZCPacket {
        ZCPacket::new_with_payload(&[value])
    }

    #[tokio::test]
    async fn scalar_stream_returns_all_ready_packets_in_one_owned_batch() {
        let source = stream::iter([Ok(packet(1)), Ok(packet(2)), Ok(packet(3))]);
        let mut stream = ScalarToBatchStream::new(source);

        let batch = stream.next().await.unwrap().unwrap();

        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].payload(), &[1]);
        assert_eq!(batch[1].payload(), &[2]);
        assert_eq!(batch[2].payload(), &[3]);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn batch_stream_scalar_adapter_preserves_packet_order() {
        let mut batch = PacketBatch::new();
        batch.try_push(packet(4)).unwrap();
        batch.try_push(packet(5)).unwrap();
        let source = stream::iter([Ok(batch)]);
        let mut stream = BatchToScalarStream::new(source);

        assert_eq!(stream.next().await.unwrap().unwrap().payload(), &[4]);
        assert_eq!(stream.next().await.unwrap().unwrap().payload(), &[5]);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn scalar_sink_adapter_delivers_each_packet_from_one_batch() {
        let (sink, mut receiver) = mpsc::unbounded();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let mut sink = ScalarToBatchSink::new(sink);
        let mut batch = PacketBatch::new();
        batch.try_push(packet(6)).unwrap();
        batch.try_push(packet(7)).unwrap();

        sink.send(batch).await.unwrap();
        sink.close().await.unwrap();

        assert_eq!(receiver.next().await.unwrap().payload(), &[6]);
        assert_eq!(receiver.next().await.unwrap().payload(), &[7]);
        assert!(receiver.next().await.is_none());
    }

    #[tokio::test]
    async fn tunnel_split_transfers_one_owned_batch_without_scalar_calls() {
        let (left, right) = create_ring_tunnel_pair();
        let (_left_reader, mut left_writer) = left.split();
        let (mut right_reader, _right_writer) = right.split();
        let mut sent = PacketBatch::new();
        sent.try_push(packet(8)).unwrap();
        sent.try_push(packet(9)).unwrap();

        left_writer.send(sent).await.unwrap();
        let received = right_reader.next().await.unwrap().unwrap();

        assert_eq!(received.len(), 2);
        assert_eq!(received[0].payload(), &[8]);
        assert_eq!(received[1].payload(), &[9]);
    }
}

impl<'a> IntoIterator for &'a mut PacketBatch {
    type Item = &'a mut ZCPacket;
    type IntoIter = slice::IterMut<'a, ZCPacket>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;

    use super::{
        MAX_PACKET_BATCH_SIZE, PARALLEL_CRYPTO_MIN_BATCH_SIZE, PacketBatchPool,
        ordered_parallel_try_for_each, packet_batch_limit_from, parallel_crypto_configured,
    };

    #[test]
    fn packet_batch_limit_is_strict_and_fails_safe() {
        assert_eq!(packet_batch_limit_from(None), MAX_PACKET_BATCH_SIZE);
        assert_eq!(packet_batch_limit_from(Some("1")), 1);
        assert_eq!(packet_batch_limit_from(Some("16")), 16);
        assert_eq!(packet_batch_limit_from(Some("64")), 64);
        assert_eq!(packet_batch_limit_from(Some("0")), MAX_PACKET_BATCH_SIZE);
        assert_eq!(packet_batch_limit_from(Some("65")), MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            packet_batch_limit_from(Some("invalid")),
            MAX_PACKET_BATCH_SIZE
        );
    }

    #[test]
    fn packet_batch_split_preserves_order() {
        let mut batch = super::PacketBatch::new();
        for value in 0_u8..6 {
            batch
                .try_push(crate::tunnel::packet_def::ZCPacket::new_with_payload(&[
                    value,
                ]))
                .unwrap();
        }

        let tail = batch.split_off(2);

        assert_eq!(
            batch
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(
            tail.iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
    }

    #[test]
    fn ready_drain_fills_one_bounded_batch() {
        let mut ready_counts = [1_usize, 2, 60].into_iter();
        let (count, error) = super::drain_ready_count(1, 64, |_| {
            ready_counts
                .next()
                .map(Ok)
                .unwrap_or_else(|| Err(std::io::ErrorKind::WouldBlock.into()))
        });

        assert_eq!(count, 64);
        assert!(error.is_none());
    }

    #[test]
    fn ready_drain_stops_cleanly_on_would_block() {
        let (count, error) =
            super::drain_ready_count(3, 64, |_| Err(std::io::ErrorKind::WouldBlock.into()));

        assert_eq!(count, 3);
        assert!(error.is_none());
    }

    #[tokio::test]
    async fn bounded_prefetch_stops_at_the_configured_limit() {
        let mut stream = futures::stream::iter([10_u8, 11, 12, 13]);
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            release.send(()).unwrap();
        });

        let (delivery, prefetched, stream_ended) = super::wait_for_delivery_with_bounded_prefetch(
            &mut stream,
            async { wait.await.map_err(|_| ()) },
            2,
        )
        .await;

        assert!(delivery.is_ok());
        assert!(!stream_ended);
        assert_eq!(prefetched.len(), 2);
        assert_eq!(prefetched.front().copied(), Some(10));
        assert_eq!(stream.next().await, Some(12));
    }

    #[test]
    fn batch_container_pool_reuses_one_fixed_vector() {
        let pool = PacketBatchPool::new(1);
        let first = pool.take();
        let first_pointer = first.as_ptr();
        assert_eq!(first.capacity(), MAX_PACKET_BATCH_SIZE);

        pool.recycle(first);
        let second = pool.take();

        assert_eq!(second.as_ptr(), first_pointer);
        assert_eq!(second.capacity(), MAX_PACKET_BATCH_SIZE);
    }

    #[test]
    fn parallel_crypto_is_opt_in_for_large_vectors_and_can_be_disabled() {
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            false,
            false
        ));
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE - 1,
            true,
            false
        ));
        assert!(parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            true,
            false
        ));
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            true,
            true
        ));
    }

    #[test]
    fn ordered_parallel_work_keeps_vector_order_when_completion_reverses() {
        let mut values = (0_u8..8).collect::<Vec<_>>();

        ordered_parallel_try_for_each(&mut values, |value| {
            std::thread::sleep(Duration::from_millis((7 - *value) as u64));
            *value += 10;
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(values, (10_u8..18).collect::<Vec<_>>());
    }
}
