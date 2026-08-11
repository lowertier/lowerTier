use std::{
    collections::VecDeque,
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
    SinkItem, StreamItem, Tunnel, TunnelError,
    batch::MAX_PACKET_BATCH_SIZE,
    common::TunnelWrapper,
    packet_def::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
};

const MAX_TUN_PACKET_SIZE: usize = u16::MAX as usize;

struct ReadState {
    device: Arc<AsyncDevice>,
    original: Vec<u8>,
    segments: Vec<BytesMut>,
    sizes: Vec<usize>,
    ready: VecDeque<ZCPacket>,
    payload_offset: usize,
    segment_capacity: usize,
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
        Self {
            device,
            original: vec![0; VIRTIO_NET_HDR_LEN + MAX_TUN_PACKET_SIZE],
            segments: (0..MAX_PACKET_BATCH_SIZE)
                .map(|_| zeroed_buffer(segment_capacity))
                .collect(),
            sizes: vec![0; MAX_PACKET_BATCH_SIZE],
            ready: VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE),
            payload_offset,
            segment_capacity,
            failed: false,
        }
    }

    async fn next(mut self) -> Option<(StreamItem, Self)> {
        if self.failed {
            return None;
        }
        if let Some(packet) = self.ready.pop_front() {
            return Some((Ok(packet), self));
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
            let mut segment = std::mem::replace(
                &mut self.segments[index],
                zeroed_buffer(self.segment_capacity),
            );
            segment.truncate(packet_len);
            self.ready
                .push_back(ZCPacket::new_from_buf(segment, ZCPacketType::NIC));
        }

        self.ready.pop_front().map(|packet| (Ok(packet), self))
    }
}

fn zeroed_buffer(length: usize) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(length);
    buffer.resize(length, 0);
    buffer
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
    Pin<Box<dyn Future<Output = (usize, io::Result<usize>, GROTable)> + Send + 'static>>;

struct QueueSink {
    pending: Vec<BytesMut>,
    gro_table: GROTable,
}

struct LinuxTunSink {
    devices: Vec<Arc<AsyncDevice>>,
    l2_tun: bool,
    queues: Vec<QueueSink>,
    in_flight: FuturesUnordered<SendFuture>,
}

impl LinuxTunSink {
    fn new(devices: Vec<Arc<AsyncDevice>>, l2_tun: bool) -> Self {
        let queues = devices
            .iter()
            .map(|_| QueueSink {
                pending: Vec::with_capacity(MAX_PACKET_BATCH_SIZE),
                gro_table: GROTable::default(),
            })
            .collect();
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
            if queue.pending.is_empty() {
                continue;
            }
            let device = self.devices[index].clone();
            let mut buffers = std::mem::take(&mut queue.pending);
            let mut gro_table = std::mem::take(&mut queue.gro_table);
            self.in_flight.push(Box::pin(async move {
                let result = device
                    .send_multiple(&mut gro_table, &mut buffers, VIRTIO_NET_HDR_LEN)
                    .await;
                (index, result, gro_table)
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

impl Sink<SinkItem> for LinuxTunSink {
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.in_flight.is_empty()
            || self
                .queues
                .iter()
                .any(|queue| queue.pending.len() >= MAX_PACKET_BATCH_SIZE)
        {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, packet: SinkItem) -> Result<(), Self::Error> {
        let l2_tun = self.l2_tun;
        let queue_index = packet_queue_index(&packet, self.queues.len());
        self.queues[queue_index]
            .pending
            .push(packet_into_offload_buffer(packet, l2_tun)?);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            self.begin_flush();
            if self.in_flight.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let Some((index, result, gro_table)) =
                ready!(Pin::new(&mut self.in_flight).poll_next(cx))
            else {
                return Poll::Ready(Ok(()));
            };
            self.queues[index].gro_table = gro_table;
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
            )) as Pin<Box<dyn Stream<Item = StreamItem> + Send>>
        })
        .collect::<Vec<_>>();
    let stream = futures::stream::select_all(streams);
    let sink = LinuxTunSink::new(devices, l2_tun);
    Box::new(TunnelWrapper::new(stream, sink, None))
}

#[cfg(test)]
mod tests {
    use crate::tunnel::packet_def::{ZCPacket, ZCPacketType};

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
}
