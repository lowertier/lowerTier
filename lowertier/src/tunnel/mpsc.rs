// this mod wrap tunnel to a mpsc tunnel, based on crossbeam_channel

use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::proto::common::TunnelInfo;

use super::{
    PacketBatchSink, PacketBatchStream, Tunnel, TunnelError, batch::PacketBatch,
    packet_def::ZCPacket,
};

use tokio::sync::{
    OwnedSemaphorePermit, Semaphore, TryAcquireError,
    mpsc::{Receiver, Sender, channel, error::TrySendError},
};
use tokio_util::task::AbortOnDropHandle;

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
    stream: Option<Pin<Box<dyn PacketBatchStream>>>,

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
        sink: &mut Pin<Box<dyn PacketBatchSink>>,
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
        sink: &mut Pin<Box<dyn PacketBatchSink>>,
        initial_item: QueuedPackets,
    ) -> Result<(), TunnelError> {
        let mut permits = Vec::new();
        let drain_scalar_tail = match initial_item {
            QueuedPackets::One {
                packet,
                _packet_permit,
            } => {
                sink.feed(PacketBatch::singleton(packet)).await?;
                permits.push(_packet_permit);
                true
            }
            QueuedPackets::Batch {
                batch,
                _packet_permits,
            } => {
                sink.feed(batch).await?;
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
                    if let Err(e) = sink.feed(PacketBatch::singleton(packet)).await {
                        tracing::error!(?e, "feed error");
                        return Err(e);
                    }
                    permits.push(_packet_permit);
                }
                QueuedPackets::Batch {
                    batch,
                    _packet_permits,
                } => {
                    if let Err(e) = sink.feed(batch).await {
                        tracing::error!(?e, "feed error");
                        return Err(e);
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
        sink: &mut Pin<Box<dyn PacketBatchSink>>,
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

    pub fn get_stream(&mut self) -> Pin<Box<dyn PacketBatchStream>> {
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
}
