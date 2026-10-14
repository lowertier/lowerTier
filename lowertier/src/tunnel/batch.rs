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
use smallvec::SmallVec;

use super::{TunnelError, packet_def::ZCPacket};

/// Maximum number of packets carried by one scheduling and I/O batch.
///
/// This matches the existing Darwin utun vector width. A batch never waits to
/// reach this size; producers append only packets that are already available.
pub const MAX_PACKET_BATCH_SIZE: usize = 64;

/// Number of stable packet jobs one peer owner may have in the send pipeline.
pub(crate) const SEND_PIPELINE_SLOT_COUNT: usize = 8;

/// Maximum packet count for one unflushed kernel I/O operation.
#[cfg(all(test, target_os = "linux"))]
pub(crate) const IO_FLUSH_PACKET_BUDGET: usize = 8;

const RETAINED_PACKET_BATCH_CONTAINERS: usize = 32;
#[inline]
pub(crate) const fn packet_batch_limit() -> usize {
    MAX_PACKET_BATCH_SIZE
}

/// Maximum number of owned receive batches held while one delivery runs.
///
/// Slot 0 is the batch currently writing to TUN. The remaining slots keep QUIC
/// application drain moving without an unbounded queue.
pub const RECEIVE_PREFETCH_BATCHES: usize = 3;

struct PacketBatchPool {
    containers: ArrayQueue<Vec<ZCPacket>>,
}

impl PacketBatchPool {
    fn new(capacity: usize) -> Self {
        Self {
            containers: ArrayQueue::new(capacity),
        }
    }

    fn take(&self, capacity: usize) -> Vec<ZCPacket> {
        let mut packets = self.containers.pop().unwrap_or_default();
        if packets.capacity() < capacity {
            packets.reserve_exact(capacity);
        }
        packets
    }

    fn recycle(&self, mut packets: Vec<ZCPacket>) {
        packets.clear();
        if packets.capacity() == 0 || packets.capacity() > MAX_PACKET_BATCH_SIZE {
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
        Self::with_capacity(MAX_PACKET_BATCH_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity <= MAX_PACKET_BATCH_SIZE);
        Self {
            packets: packet_batch_pool().take(capacity.min(MAX_PACKET_BATCH_SIZE)),
        }
    }

    pub fn singleton(packet: ZCPacket) -> Self {
        let mut batch = Self::with_capacity(1);
        batch
            .try_push(packet)
            .expect("a new packet batch accepts one packet");
        batch
    }

    #[cfg(test)]
    pub(crate) fn into_vec(mut self) -> Vec<ZCPacket> {
        mem::take(&mut self.packets)
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

    #[allow(clippy::result_large_err)]
    pub(crate) fn try_append(&mut self, mut other: Self) -> Result<(), Self> {
        if self.packets.len() + other.packets.len() > MAX_PACKET_BATCH_SIZE {
            return Err(other);
        }
        self.packets.append(&mut other.packets);
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
        max_batch_size: usize,
    }
}

impl<S> ScalarToBatchStream<S> {
    pub fn new(inner: S) -> Self {
        Self::new_with_max_batch_size(inner, MAX_PACKET_BATCH_SIZE)
    }

    pub fn new_with_max_batch_size(inner: S, max_batch_size: usize) -> Self {
        assert!(max_batch_size > 0);
        Self {
            inner,
            pending_error: None,
            max_batch_size: max_batch_size.min(MAX_PACKET_BATCH_SIZE),
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
        let batch_limit = packet_batch_limit().min(*this.max_batch_size);
        while batch.len() < batch_limit {
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

    use super::{MAX_PACKET_BATCH_SIZE, PacketBatch, PacketBatchPool};

    #[test]
    fn pool_exhaustion_preserves_the_requested_allocation_size() {
        let pool = PacketBatchPool::new(2);
        let first = pool.take(MAX_PACKET_BATCH_SIZE);
        let second = pool.take(MAX_PACKET_BATCH_SIZE);
        let mut small = pool.take(1);
        assert_eq!(small.capacity(), 1);
        small.push(super::ZCPacket::new_with_payload(b"owned payload"));
        let allocation = small.as_ptr();
        pool.recycle(small);
        let reused = pool.take(1);
        assert!(reused.is_empty());
        assert_eq!(reused.as_ptr(), allocation);
        pool.recycle(reused);
        pool.recycle(first);
        pool.recycle(second);
        assert_eq!(pool.containers.len(), 2);
        assert!(pool.take(MAX_PACKET_BATCH_SIZE).capacity() >= MAX_PACKET_BATCH_SIZE);
    }

    #[test]
    fn pool_does_not_retain_oversized_containers() {
        let pool = PacketBatchPool::new(2);
        pool.recycle(Vec::with_capacity(MAX_PACKET_BATCH_SIZE * 2));
        assert!(pool.containers.is_empty());
    }
}
