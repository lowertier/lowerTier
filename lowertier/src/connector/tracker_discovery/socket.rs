//! Quinn owns receive polling. Control packets leave through a bounded side channel.
use crate::common::stun::StunPacket;
use quinn::{AsyncUdpSocket, UdpPoller};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::broadcast;

#[derive(Debug)]
pub struct DiscoverySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    packets: broadcast::Sender<StunPacket>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Batch;
    impl AsyncUdpSocket for Batch {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unreachable!()
        }
        fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            unreachable!()
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1234".parse().unwrap())
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let punch =
                crate::connector::tracker_discovery::wire::punch(b"test", 1, [2; 16], 10, false);
            bufs[0][..65].copy_from_slice(&punch);
            bufs[0][65..130].fill(0x40);
            bufs[1][..65].fill(0);
            bufs[1][4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
            bufs[1][65..130].fill(0x20);
            bufs[1][130..137].fill(0xc0);
            for (index, length) in [130, 137].into_iter().enumerate() {
                meta[index] = quinn::udp::RecvMeta {
                    addr: self.local_addr().unwrap(),
                    len: length,
                    stride: 65,
                    ecn: None,
                    dst_ip: None,
                };
            }
            Poll::Ready(Ok(2))
        }
    }

    #[tokio::test]
    async fn mixed_gro_preserves_quic_and_only_extracts_control_packets() {
        let (packets, mut receiver) = broadcast::channel(8);
        let socket = DiscoverySocket::new(Arc::new(Batch), packets);
        let (mut a, mut b) = ([0; 256], [0; 256]);
        let mut buffers = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
        let mut metadata = [quinn::udp::RecvMeta::default(); 2];
        let count =
            futures::future::poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata))
                .await
                .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            (metadata[0].len, metadata[1].len, metadata[1].stride),
            (65, 72, 65)
        );
        assert_eq!(&buffers[0][..65], &[0x40; 65]);
        assert_eq!(&buffers[1][..65], &[0x20; 65]);
        assert_eq!(&buffers[1][65..72], &[0xc0; 7]);
        assert_eq!(receiver.recv().await.unwrap().data.len(), 65);
        assert_eq!(
            receiver.recv().await.unwrap().data[4..8],
            [0x21, 0x12, 0xa4, 0x42]
        );
        assert!(receiver.try_recv().is_err());
    }
}

impl DiscoverySocket {
    pub fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        packets: broadcast::Sender<StunPacket>,
    ) -> Arc<Self> {
        Arc::new(Self { inner, packets })
    }

    fn control(&self, bytes: &[u8], source: SocketAddr) -> bool {
        // Discovery endpoints do not negotiate fixed-bit greasing. Unknown packets still reach Quinn.
        let stun =
            bytes.len() >= 20 && bytes[0] & 0xc0 == 0 && bytes[4..8] == [0x21, 0x12, 0xa4, 0x42];
        let tracker = bytes.len() >= 8
            && match &bytes[..4] {
                [0, 0, 0, 0] => bytes.len() >= 16,
                [0, 0, 0, 1] => bytes.len() >= 20,
                [0, 0, 0, 3] => true,
                _ => false,
            };
        let punch = bytes.len() == super::wire::PUNCH_BYTES && bytes[..4] == [0, b'L', b'T', 1];
        if !stun && !tracker && !punch {
            return false;
        }
        if bytes.len() <= super::wire::MAX_RESPONSE {
            let _ = self.packets.send(StunPacket {
                data: bytes.to_vec(),
                addr: source,
            });
        }
        true
    }
}

impl AsyncUdpSocket for DiscoverySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..8 {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => count,
                other => return other,
            };
            let mut kept = 0;
            for index in 0..count {
                let mut received = meta[index];
                let mut write = 0;
                for offset in (0..received.len).step_by(received.stride.max(1)) {
                    let end = (offset + received.stride.max(1)).min(received.len);
                    if self.control(&bufs[index][offset..end], received.addr) {
                        continue;
                    }
                    if write != offset {
                        bufs[index].copy_within(offset..end, write);
                    }
                    write += end - offset;
                }
                if write == 0 {
                    continue;
                }
                received.len = write;
                if kept != index {
                    let (before, after) = bufs.split_at_mut(index);
                    before[kept][..write].copy_from_slice(&after[0][..write]);
                }
                meta[kept] = received;
                kept += 1;
            }
            if kept != 0 {
                return Poll::Ready(Ok(kept));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
