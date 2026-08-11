use std::{pin::Pin, sync::Arc, time::Duration};

use futures::SinkExt;
use tokio::{sync::Mutex, time::timeout};

use super::{
    PacketBatchSink, PacketBatchStream, Tunnel, TunnelError, batch::PacketBatch,
    packet_def::ZCPacket,
};

#[derive(Clone)]
pub struct DirectTunnelSender {
    sink: Arc<Mutex<Pin<Box<dyn PacketBatchSink>>>>,
    send_timeout: Option<Duration>,
}

impl DirectTunnelSender {
    pub async fn send(&self, packet: ZCPacket) -> Result<(), TunnelError> {
        self.send_batch(PacketBatch::singleton(packet)).await
    }

    pub async fn send_batch(&self, batch: PacketBatch) -> Result<(), TunnelError> {
        if batch.is_empty() {
            return Ok(());
        }

        let mut sink = self.sink.lock().await;
        let operation = sink.send(batch);
        if let Some(duration) = self.send_timeout {
            timeout(duration, operation).await??;
        } else {
            operation.await?;
        }
        Ok(())
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
        Self {
            _tunnel: tunnel,
            stream: Some(stream),
            sender: DirectTunnelSender {
                sink: Arc::new(Mutex::new(sink)),
                send_timeout,
            },
        }
    }

    pub fn get_stream(&mut self) -> Pin<Box<dyn PacketBatchStream>> {
        self.stream.take().expect("the direct stream is taken once")
    }

    pub fn get_sink(&self) -> DirectTunnelSender {
        self.sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket, ring::create_ring_tunnel_pair};

    use super::DirectTunnel;

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
}
