use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{Sink, ready};
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

type SendFuture = Pin<Box<dyn Future<Output = (io::Result<usize>, GROTable)> + Send + 'static>>;

struct LinuxTunSink {
    device: Arc<AsyncDevice>,
    l2_tun: bool,
    pending: Vec<BytesMut>,
    gro_table: GROTable,
    in_flight: Option<SendFuture>,
}

impl LinuxTunSink {
    fn new(device: Arc<AsyncDevice>, l2_tun: bool) -> Self {
        Self {
            device,
            l2_tun,
            pending: Vec::with_capacity(MAX_PACKET_BATCH_SIZE),
            gro_table: GROTable::default(),
            in_flight: None,
        }
    }

    fn begin_flush(&mut self) {
        if self.in_flight.is_some() || self.pending.is_empty() {
            return;
        }
        let device = self.device.clone();
        let mut buffers = std::mem::take(&mut self.pending);
        let mut gro_table = std::mem::take(&mut self.gro_table);
        self.in_flight = Some(Box::pin(async move {
            let result = device
                .send_multiple(&mut gro_table, &mut buffers, VIRTIO_NET_HDR_LEN)
                .await;
            (result, gro_table)
        }));
    }
}

impl Sink<SinkItem> for LinuxTunSink {
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.in_flight.is_some() || self.pending.len() >= MAX_PACKET_BATCH_SIZE {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, packet: SinkItem) -> Result<(), Self::Error> {
        let l2_tun = self.l2_tun;
        self.pending
            .push(packet_into_offload_buffer(packet, l2_tun)?);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            self.begin_flush();
            let Some(future) = self.in_flight.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            let (result, gro_table) = ready!(future.as_mut().poll(cx));
            self.gro_table = gro_table;
            self.in_flight = None;
            result.map_err(TunnelError::IOError)?;
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().poll_flush(cx)
    }
}

pub(crate) fn wrap_device(device: AsyncDevice, l2_tun: bool, mtu: usize) -> Box<dyn Tunnel> {
    let device = Arc::new(device);
    let stream = futures::stream::unfold(ReadState::new(device.clone(), l2_tun, mtu), |state| {
        state.next()
    });
    let sink = LinuxTunSink::new(device, l2_tun);
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
}
