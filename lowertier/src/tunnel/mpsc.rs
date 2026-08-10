// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::proto::common::TunnelInfo;

use super::{
    Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, batch::PacketBatch, packet_def::ZCPacket,
};

use tokio::sync::{
    OwnedSemaphorePermit, Semaphore, TryAcquireError,
    mpsc::{Receiver, Sender, channel, error::TrySendError},
};
use tokio_util::task::AbortOnDropHandle;
// use tachyonix::{channel, Receiver, Sender, TrySendError};

use futures::SinkExt;

const MPSC_BATCH_QUEUE_CAPACITY: usize = 32;
const MPSC_PACKET_QUEUE_CAPACITY: usize = 128;

enum QueuedPackets {
    One {
        packet: ZCPacket,
        _packet_permit: OwnedSemaphorePermit,
    },
    Batch {
        batch: PacketBatch,
        _packet_permits: OwnedSemaphorePermit,
    },
}

#[derive(Clone)]
pub struct MpscTunnelSender {
    tx: Sender<QueuedPackets>,
    packet_permits: Arc<Semaphore>,
}

impl MpscTunnelSender {
    pub async fn send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let permit = self
            .packet_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TunnelError::Shutdown)?;
        self.tx
            .send(QueuedPackets::One {
                packet: item,
                _packet_permit: permit,
            })
            .await
            .map_err(|_| TunnelError::Shutdown)
    }

    pub fn try_send(&self, item: ZCPacket) -> Result<(), TunnelError> {
        let permit =
            self.packet_permits
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    TryAcquireError::NoPermits => TunnelError::BufferFull,
                    TryAcquireError::Closed => TunnelError::Shutdown,
                })?;
        self.tx
            .try_send(QueuedPackets::One {
                packet: item,
                _packet_permit: permit,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => TunnelError::BufferFull,
                TrySendError::Closed(_) => TunnelError::Shutdown,
            })
    }

    pub async fn send_batch(&self, batch: PacketBatch) -> Result<(), TunnelError> {
        if batch.is_empty() {
            return Ok(());
        }
        let batch = match batch.pop_singleton() {
            Ok(packet) => return self.send(packet).await,
            Err(batch) => batch,
        };
        let permit_count = u32::try_from(batch.len())
            .map_err(|_| TunnelError::InternalError("packet batch is too large".to_owned()))?;
        let permit = self
            .packet_permits
            .clone()
            .acquire_many_owned(permit_count)
            .await
            .map_err(|_| TunnelError::Shutdown)?;
        self.tx
            .send(QueuedPackets::Batch {
                batch,
                _packet_permits: permit,
            })
            .await
            .map_err(|_| TunnelError::Shutdown)
    }

    pub fn try_send_batch(&self, batch: PacketBatch) -> Result<(), TunnelError> {
        if batch.is_empty() {
            return Ok(());
        }
        let batch = match batch.pop_singleton() {
            Ok(packet) => return self.try_send(packet),
            Err(batch) => batch,
        };
        let permit_count = u32::try_from(batch.len())
            .map_err(|_| TunnelError::InternalError("packet batch is too large".to_owned()))?;
        let permit = self
            .packet_permits
            .clone()
            .try_acquire_many_owned(permit_count)
            .map_err(|error| match error {
                TryAcquireError::NoPermits => TunnelError::BufferFull,
                TryAcquireError::Closed => TunnelError::Shutdown,
            })?;
        self.tx
            .try_send(QueuedPackets::Batch {
                batch,
                _packet_permits: permit,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => TunnelError::BufferFull,
                TrySendError::Closed(_) => TunnelError::Shutdown,
            })
    }
}

pub struct MpscTunnel<T> {
    tx: Option<Sender<QueuedPackets>>,
    packet_permits: Arc<Semaphore>,

    tunnel: T,
    stream: Option<Pin<Box<dyn ZCPacketStream>>>,

    task: AbortOnDropHandle<()>,
}

impl<T: Tunnel> MpscTunnel<T> {
    pub fn new(tunnel: T, send_timeout: Option<Duration>) -> Self {
        let (tx, mut rx) = channel(MPSC_BATCH_QUEUE_CAPACITY);
        let packet_permits = Arc::new(Semaphore::new(MPSC_PACKET_QUEUE_CAPACITY));
        let (stream, mut sink) = tunnel.split();

        let task = tokio::spawn(async move {
            loop {
                if let Err(e) = Self::forward_one_round(&mut rx, &mut sink, send_timeout).await {
                    tracing::error!(?e, "forward error");
                    break;
                }
            }
            rx.close();
            let close_ret = timeout(Duration::from_secs(5), sink.close()).await;
            tracing::warn!(?close_ret, "mpsc close sink");
        });

        Self {
            tx: Some(tx),
            packet_permits,
            tunnel,
            stream: Some(stream),
            task: AbortOnDropHandle::new(task),
        }
    }

    async fn forward_one_round(
        rx: &mut Receiver<QueuedPackets>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        send_timeout_ms: Option<Duration>,
    ) -> Result<(), TunnelError> {
        let item = rx.recv().await.with_context(|| "recv error")?;
        if let Some(timeout_ms) = send_timeout_ms {
            Self::forward_one_round_with_timeout(rx, sink, item, timeout_ms).await
        } else {
            Self::forward_one_round_no_timeout(rx, sink, item).await
        }
    }

    async fn forward_one_round_no_timeout(
        rx: &mut Receiver<QueuedPackets>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        initial_item: QueuedPackets,
    ) -> Result<(), TunnelError> {
        let mut permits = Vec::new();
        let drain_scalar_tail = match initial_item {
            QueuedPackets::One {
                packet,
                _packet_permit,
            } => {
                sink.feed(packet).await?;
                permits.push(_packet_permit);
                true
            }
            QueuedPackets::Batch {
                batch,
                _packet_permits,
            } => {
                for packet in batch {
                    sink.feed(packet).await?;
                }
                permits.push(_packet_permits);
                false
            }
        };

        // A batch is already a complete flush round. Draining a second batch
        // here used to hold up to 128 packet permits while filling the
        // downstream ring, which produced stop-and-go bursts. Preserve the
        // original scalar coalescing behavior, but stop after the first batch.
        while drain_scalar_tail && let Ok(item) = rx.try_recv() {
            match item {
                QueuedPackets::One {
                    packet,
                    _packet_permit,
                } => {
                    if let Err(e) = sink.feed(packet).await {
                        tracing::error!(?e, "feed error");
                        return Err(e);
                    }
                    permits.push(_packet_permit);
                }
                QueuedPackets::Batch {
                    batch,
                    _packet_permits,
                } => {
                    for packet in batch {
                        if let Err(e) = sink.feed(packet).await {
                            tracing::error!(?e, "feed error");
                            return Err(e);
                        }
                    }
                    permits.push(_packet_permits);
                    break;
                }
            }
        }

        let result = sink.flush().await;
        drop(permits);
        result
    }

    async fn forward_one_round_with_timeout(
        rx: &mut Receiver<QueuedPackets>,
        sink: &mut Pin<Box<dyn ZCPacketSink>>,
        initial_item: QueuedPackets,
        timeout_ms: Duration,
    ) -> Result<(), TunnelError> {
        match timeout(timeout_ms, async move {
            Self::forward_one_round_no_timeout(rx, sink, initial_item).await
        })
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                tracing::error!(?e, "forward error");
                Err(e)
            }
            Err(e) => {
                tracing::error!(?e, "forward timeout");
                Err(e.into())
            }
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn ZCPacketStream>> {
        self.stream.take().unwrap()
    }

    pub fn get_sink(&self) -> MpscTunnelSender {
        MpscTunnelSender {
            tx: self.tx.as_ref().unwrap().clone(),
            packet_permits: self.packet_permits.clone(),
        }
    }

    pub fn close(&mut self) {
        self.packet_permits.close();
        self.tx.take();
        self.task.abort();
    }

    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel.info()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        batch::PacketBatch,
        ring::{RING_TUNNEL_CAP, create_ring_tunnel_pair},
        tcp::{TcpTunnelConnector, TcpTunnelListener},
    };

    use super::*;
    // test slow send lock in framed tunnel
    #[tokio::test]
    async fn mpsc_slow_receiver() {
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());

        listener.listen().await.unwrap();
        let t1 = tokio::spawn(async move {
            let t = listener.accept().await.unwrap();
            let (mut stream, _sink) = t.split();
            let now = tokio::time::Instant::now();

            let mut a_counter = 0;
            let mut b_counter = 0;

            while let Some(Ok(msg)) = stream.next().await {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if now.elapsed().as_secs() > 5 {
                    break;
                }

                if msg.payload() == "hello".as_bytes() {
                    a_counter += 1;
                } else if msg.payload() == "hello2".as_bytes() {
                    b_counter += 1;
                }
            }

            tracing::info!("t1 exit");
            assert_ne!(a_counter, 0);
            assert_ne!(b_counter, 0);
        });

        let tunnel = connector.connect().await.unwrap();
        let mpsc_tunnel = MpscTunnel::new(tunnel, None);

        let sink1 = mpsc_tunnel.get_sink();
        let t2 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                let a = sink1
                    .send(ZCPacket::new_with_payload("hello".as_bytes()))
                    .await;
                if a.is_err() {
                    tracing::info!(?a, "t2 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t2 exit");
        });

        let sink2 = mpsc_tunnel.get_sink();
        let t3 = tokio::spawn(async move {
            for i in 0..1000000 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let a = sink2
                    .send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await;
                if a.is_err() {
                    tracing::info!(?a, "t3 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t3 exit");
        });

        let t4 = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("closing");
            drop(mpsc_tunnel);
            tracing::info!("closed");
        });

        let _ = tokio::join!(t1, t2, t3, t4);
    }

    #[tokio::test]
    async fn mpsc_slow_receiver_with_send_timeout() {
        let (a, _b) = create_ring_tunnel_pair();
        let mpsc_tunnel = MpscTunnel::new(a, Some(Duration::from_secs(1)));
        let s = mpsc_tunnel.get_sink();
        for _ in 0..RING_TUNNEL_CAP {
            s.send(ZCPacket::new_with_payload(&[0; 1024]))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_ok());

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let e = s.send(ZCPacket::new_with_payload(&[0; 1024])).await;
        assert!(e.is_err());
    }

    #[tokio::test]
    async fn mpsc_batch_preserves_packet_order() {
        let (a, b) = create_ring_tunnel_pair();
        let mpsc_tunnel = MpscTunnel::new(a, None);
        let mut receiver = b.split().0;
        let mut batch = PacketBatch::new();
        for value in 1..=4_u8 {
            batch
                .try_push(ZCPacket::new_with_payload(&[value]))
                .unwrap();
        }

        mpsc_tunnel.get_sink().send_batch(batch).await.unwrap();

        let mut received = Vec::new();
        for _ in 0..4 {
            received.push(receiver.next().await.unwrap().unwrap().payload()[0]);
        }
        assert_eq!(received, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn mpsc_batch_send_reports_closed_queue() {
        let (a, _b) = create_ring_tunnel_pair();
        let mut mpsc_tunnel = MpscTunnel::new(a, None);
        let sender = mpsc_tunnel.get_sink();
        mpsc_tunnel.close();
        let mut batch = PacketBatch::new();
        batch
            .try_push(ZCPacket::new_with_payload(b"closed-1"))
            .unwrap();
        batch
            .try_push(ZCPacket::new_with_payload(b"closed-2"))
            .unwrap();

        let error = sender.send_batch(batch).await.unwrap_err();

        assert!(matches!(error, TunnelError::Shutdown));
    }
}
