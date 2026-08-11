use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{Sink, Stream, ready, stream::FuturesUnordered};
use quincy_tun::{AsyncDevice, GROTable, VIRTIO_NET_HDR_LEN};

use crate::tunnel::{
    BatchStreamItem, Tunnel, TunnelError,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    common::BatchTunnelWrapper,
    packet_def::{ReusableBufferPool, TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
};

const MAX_TUN_PACKET_SIZE: usize = u16::MAX as usize;
const REUSABLE_TUN_BATCH_COUNT: usize = 2;

struct ReadState {
    device: Arc<AsyncDevice>,
    original: Vec<u8>,
    segments: Vec<BytesMut>,
    sizes: Vec<usize>,
    payload_offset: usize,
    segment_capacity: usize,
    reusable_pool: ReusableBufferPool,
    failed: bool,
}

impl ReadState {
    fn new(device: Arc<AsyncDevice>, l2_tun: bool, mtu: usize) -> Self {
        let payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset
            + if l2_tun {
                crate::instance::l2_tun::ETHERNET_HEADER_LEN
            } else {
                0
            };
        let segment_capacity = payload_offset + mtu.max(1500) + 256 + TAIL_RESERVED_SIZE;
        let reusable_pool = ReusableBufferPool::new(
            segment_capacity,
            MAX_PACKET_BATCH_SIZE * REUSABLE_TUN_BATCH_COUNT,
        );
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
            failed: false,
        }
    }

    async fn next(mut self) -> Option<(BatchStreamItem, Self)> {
        if self.failed {
            return None;
        }

        let result = self
            .device
            .recv_multiple(
                &mut self.original,
                &mut self.segments,
                &mut self.sizes,
                self.payload_offset,
            )
            .await;
        let count = match result {
            Ok(count) => count,
            Err(error) => {
                self.failed = true;
                return Some((Err(TunnelError::IOError(error)), self));
            }
        };

        for index in 0..count {
            let packet_len = self.payload_offset + self.sizes[index];
            if packet_len > self.segment_capacity {
                self.failed = true;
                return Some((
                    Err(TunnelError::InvalidPacket(format!(
                        "TUN offload segment length {packet_len} exceeds {}",
                        self.segment_capacity
                    ))),
                    self,
                ));
            }
        }

        let mut batch = PacketBatch::with_capacity(count);
        for index in 0..count {
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
                .expect("the TAP read batch has a fixed bound");
        }

        Some((Ok(batch), self))
    }
}

fn packet_into_offload_buffer(packet: ZCPacket, l2_tun: bool) -> Result<BytesMut, TunnelError> {
    let payload_offset = packet.payload_offset();
    let mut inner = packet.inner();
    let l2_prefix_len = if l2_tun {
        crate::instance::l2_tun::decapsulate_ip(&inner[payload_offset..])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        crate::instance::l2_tun::ETHERNET_HEADER_LEN
    } else {
        0
    };
    let packet_start = payload_offset + l2_prefix_len;
    if packet_start < VIRTIO_NET_HDR_LEN {
        return Err(TunnelError::InvalidPacket(
            "packet does not have enough headroom for virtio metadata".into(),
        ));
    }
    inner.advance(packet_start - VIRTIO_NET_HDR_LEN);
    inner[..VIRTIO_NET_HDR_LEN].fill(0);
    Ok(inner)
}

type SendFuture =
    Pin<Box<dyn Future<Output = (usize, io::Result<usize>, Vec<BytesMut>, GROTable)> + Send>>;

struct QueueSink {
    pending: Option<Vec<BytesMut>>,
    gro_table: Option<GROTable>,
}

impl QueueSink {
    fn new() -> Self {
        Self {
            pending: Some(Vec::with_capacity(MAX_PACKET_BATCH_SIZE)),
            gro_table: Some(GROTable::default()),
        }
    }

    fn take_flush_resources(&mut self) -> (Vec<BytesMut>, GROTable) {
        let buffers = self
            .pending
            .take()
            .expect("a queue has one buffer vector when no flush is active");
        let gro_table = self
            .gro_table
            .take()
            .expect("a queue has one GRO table when no flush is active");
        (buffers, gro_table)
    }

    fn restore_flush_resources(&mut self, mut buffers: Vec<BytesMut>, gro_table: GROTable) {
        buffers.clear();
        self.pending = Some(buffers);
        self.gro_table = Some(gro_table);
    }
}

struct LinuxTunSink {
    devices: Vec<Arc<AsyncDevice>>,
    l2_tun: bool,
    queues: Vec<QueueSink>,
    in_flight: FuturesUnordered<SendFuture>,
}

impl LinuxTunSink {
    fn new(devices: Vec<Arc<AsyncDevice>>, l2_tun: bool) -> Self {
        let queues = devices.iter().map(|_| QueueSink::new()).collect();
        Self {
            devices,
            l2_tun,
            queues,
            in_flight: FuturesUnordered::new(),
        }
    }

    fn begin_flush(&mut self) {
        if !self.in_flight.is_empty() {
            return;
        }
        for (index, queue) in self.queues.iter_mut().enumerate() {
            if queue.pending.as_ref().is_none_or(Vec::is_empty) {
                continue;
            }
            let device = self.devices[index].clone();
            let (mut buffers, mut gro_table) = queue.take_flush_resources();
            self.in_flight.push(Box::pin(async move {
                let result = device
                    .send_multiple(&mut gro_table, &mut buffers, VIRTIO_NET_HDR_LEN)
                    .await;
                (index, result, buffers, gro_table)
            }));
        }
    }
}

fn packet_queue_index(packet: &ZCPacket, queue_count: usize) -> usize {
    packet
        .peer_manager_header()
        .and_then(|header| header.flow_shard())
        .map_or(0, |shard| usize::from(shard) % queue_count)
}

impl Sink<PacketBatch> for LinuxTunSink {
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.in_flight.is_empty()
            || self.queues.iter().any(|queue| {
                queue
                    .pending
                    .as_ref()
                    .is_some_and(|packets| !packets.is_empty())
            })
        {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        let l2_tun = self.l2_tun;
        let queue_count = self.queues.len();
        for packet in batch {
            let queue_index = packet_queue_index(&packet, queue_count);
            self.queues[queue_index]
                .pending
                .as_mut()
                .expect("poll_ready restores the queue buffer vector")
                .push(packet_into_offload_buffer(packet, l2_tun)?);
        }
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            self.begin_flush();
            if self.in_flight.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let Some((index, result, buffers, gro_table)) =
                ready!(Pin::new(&mut self.in_flight).poll_next(cx))
            else {
                return Poll::Ready(Ok(()));
            };
            self.queues[index].restore_flush_resources(buffers, gro_table);
            result.map_err(TunnelError::IOError)?;
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().poll_flush(cx)
    }
}

pub(crate) fn wrap_devices(devices: Vec<AsyncDevice>, l2_tun: bool, mtu: usize) -> Box<dyn Tunnel> {
    assert!(!devices.is_empty(), "Linux virtual NIC needs one queue");
    let devices = devices.into_iter().map(Arc::new).collect::<Vec<_>>();
    let streams = devices
        .iter()
        .map(|device| {
            Box::pin(futures::stream::unfold(
                ReadState::new(device.clone(), l2_tun, mtu),
                |state| state.next(),
            )) as Pin<Box<dyn Stream<Item = BatchStreamItem> + Send>>
        })
        .collect::<Vec<_>>();
    let stream = futures::stream::select_all(streams);
    let sink = LinuxTunSink::new(devices, l2_tun);
    Box::new(BatchTunnelWrapper::new(stream, sink, None))
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{
        PacketBatchSink,
        packet_def::{ZCPacket, ZCPacketType},
    };

    #[test]
    fn linux_tap_writer_accepts_owned_packet_batches() {
        fn assert_batch_sink<T: PacketBatchSink>() {}

        assert_batch_sink::<super::LinuxTunSink>();
    }

    #[test]
    fn offload_egress_reuses_packet_headroom_for_virtio_metadata() {
        let mut packet = ZCPacket::new_with_payload(&[0x45, 0, 0, 20]);
        packet = packet.convert_type(ZCPacketType::NIC);

        let buffer = super::packet_into_offload_buffer(packet, false).unwrap();

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
        let mut queue = super::QueueSink::new();

        let (buffers, gro_table) = queue.take_flush_resources();
        assert!(queue.pending.is_none());
        assert!(queue.gro_table.is_none());

        queue.restore_flush_resources(buffers, gro_table);
        assert_eq!(
            queue.pending.as_ref().unwrap().capacity(),
            super::MAX_PACKET_BATCH_SIZE
        );
        assert!(queue.gro_table.is_some());
    }
}
