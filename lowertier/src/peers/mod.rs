pub(crate) mod direct_nic;
mod graph_algo;

pub mod l2_fabric;

pub mod acl_filter;
pub mod credential_manager;
pub mod peer;
pub mod peer_conn;
pub mod peer_conn_ping;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_rpc_service;
pub mod peer_session;
pub(crate) mod public_ipv6;
pub(crate) mod receiver_pacing;
pub mod relay_peer_map;
pub(crate) mod replay_window;
pub mod route_trait;
pub mod service_route;
pub(crate) mod speed_probe;
pub(crate) mod traffic_metrics;

use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

pub(crate) mod flow;
pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;
pub mod fabric;
pub(crate) mod secure_datagram;

pub mod peer_task;

#[cfg(test)]
pub mod tests;

use crate::tunnel::{
    batch::{PacketBatch, PacketBatchIntoIter},
    packet_def::ZCPacket,
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    fn is_direct_nic_terminal(&self) -> bool {
        false
    }

    fn is_interested_in_packet_from_peer(&self, _packet: &ZCPacket) -> bool {
        true
    }

    fn is_interested_in_batch_from_peer(&self, batch: &PacketBatch) -> bool {
        batch
            .iter()
            .any(|packet| self.is_interested_in_packet_from_peer(packet))
    }

    fn is_interested_in_direct_nic_batch(&self, batch: &PacketBatch) -> bool {
        self.is_interested_in_batch_from_peer(batch)
    }

    async fn try_process_packet_from_peer(&self, _zc_packet: ZCPacket) -> Option<ZCPacket> {
        Some(_zc_packet)
    }

    async fn try_process_batch_from_peer(&self, batch: PacketBatch) -> PacketBatch {
        let mut remaining = PacketBatch::new();
        for packet in batch {
            if let Some(packet) = self.try_process_packet_from_peer(packet).await {
                remaining
                    .try_push(packet)
                    .expect("a filtered batch cannot exceed its input batch");
            }
        }
        remaining
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool;

    async fn try_process_batch_from_nic(&self, mut batch: PacketBatch) -> PacketBatch {
        for packet in batch.iter_mut() {
            let _ = self.try_process_packet_from_nic(packet).await;
        }
        batch
    }

    fn id(&self) -> String {
        format!("{:p}", self)
    }
}

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

#[derive(Clone)]
pub struct PacketRecvChan {
    sender: tokio::sync::mpsc::Sender<QueuedPacketBatch>,
    queue_credits: Arc<Semaphore>,
    direct_nic: Arc<OnceLock<Arc<direct_nic::DirectNicIngress>>>,
}

const PACKET_QUEUE_BATCH_CAPACITY: usize = 32;
const PACKET_QUEUE_PACKET_CAPACITY: usize = 128;
const PACKET_QUEUE_SLOT_BYTES: usize = 4 * 1024;
const PACKET_QUEUE_CREDIT_BYTES: usize = PACKET_QUEUE_PACKET_CAPACITY * PACKET_QUEUE_SLOT_BYTES;

struct QueuedPacketBatch {
    batch: PacketBatch,
    _queue_credits: OwnedSemaphorePermit,
}

fn queue_credit_count(batch: &mut PacketBatch) -> Option<u32> {
    let packet_credits = batch.len().checked_mul(PACKET_QUEUE_SLOT_BYTES)?;
    let mut retained_bytes = batch.retained_buffer_capacity();
    if retained_bytes > PACKET_QUEUE_CREDIT_BYTES
        && batch.buffer_byte_len().max(packet_credits) <= PACKET_QUEUE_CREDIT_BYTES
    {
        for packet in batch.iter_mut() {
            packet.compact_retained_buffer();
        }
        retained_bytes = batch.retained_buffer_capacity();
    }
    if retained_bytes > PACKET_QUEUE_CREDIT_BYTES {
        return None;
    }
    u32::try_from(retained_bytes.max(packet_credits)).ok()
}

impl PacketRecvChan {
    pub(crate) fn create_sibling_channel(&self) -> (Self, PacketRecvChanReceiver) {
        // Each queue needs independent credits. Its consumer can await delivery
        // to the sibling while producers refill the source queue.
        create_packet_recv_chan()
    }

    pub async fn send(
        &self,
        packet: ZCPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ZCPacket>> {
        self.send_batch(PacketBatch::singleton(packet))
            .await
            .map_err(|error| {
                tokio::sync::mpsc::error::SendError(
                    error.0.pop_singleton().expect("scalar packet channel job"),
                )
            })
    }

    pub async fn send_batch(
        &self,
        batch: PacketBatch,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<PacketBatch>> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut batch = if let Some(direct_nic) = self.direct_nic.get() {
            match direct_nic.try_process(batch).await {
                Ok(()) => return Ok(()),
                Err(batch) => batch,
            }
        } else {
            batch
        };
        let Some(credit_count) = queue_credit_count(&mut batch) else {
            tracing::warn!(
                packets = batch.len(),
                bytes = batch.buffer_byte_len(),
                retained_bytes = batch.retained_buffer_capacity(),
                "peer packet batch exceeds the fallback queue credit limit"
            );
            return Err(tokio::sync::mpsc::error::SendError(batch));
        };
        let permit = match self
            .queue_credits
            .clone()
            .acquire_many_owned(credit_count)
            .await
        {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("peer packet fallback queue credits are closed");
                return Err(tokio::sync::mpsc::error::SendError(batch));
            }
        };
        self.sender
            .send(QueuedPacketBatch {
                batch,
                _queue_credits: permit,
            })
            .await
            .map_err(|error| {
                tracing::warn!("peer packet fallback queue receiver is closed");
                tokio::sync::mpsc::error::SendError(error.0.batch)
            })
    }

    fn install_direct_nic(&self, ingress: Arc<direct_nic::DirectNicIngress>) {
        let _ = self.direct_nic.set(ingress);
    }

    pub fn try_send(
        &self,
        packet: ZCPacket,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<ZCPacket>> {
        let mut batch = PacketBatch::singleton(packet);
        let Some(credit_count) = queue_credit_count(&mut batch) else {
            return Err(tokio::sync::mpsc::error::TrySendError::Full(
                batch.pop_singleton().expect("scalar packet channel job"),
            ));
        };
        let permit = match self
            .queue_credits
            .clone()
            .try_acquire_many_owned(credit_count)
        {
            Ok(permit) => permit,
            Err(error) => {
                let packet = batch.pop_singleton().expect("scalar packet channel job");
                return Err(match error {
                    TryAcquireError::NoPermits => {
                        tokio::sync::mpsc::error::TrySendError::Full(packet)
                    }
                    TryAcquireError::Closed => {
                        tokio::sync::mpsc::error::TrySendError::Closed(packet)
                    }
                });
            }
        };
        self.sender
            .try_send(QueuedPacketBatch {
                batch,
                _queue_credits: permit,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(queued) => {
                    tokio::sync::mpsc::error::TrySendError::Full(
                        queued
                            .batch
                            .pop_singleton()
                            .expect("scalar packet channel job"),
                    )
                }
                tokio::sync::mpsc::error::TrySendError::Closed(queued) => {
                    tokio::sync::mpsc::error::TrySendError::Closed(
                        queued
                            .batch
                            .pop_singleton()
                            .expect("scalar packet channel job"),
                    )
                }
            })
    }
}

pub struct PacketRecvChanReceiver {
    receiver: tokio::sync::mpsc::Receiver<QueuedPacketBatch>,
    pending: Option<(PacketBatchIntoIter, OwnedSemaphorePermit)>,
}

impl PacketRecvChanReceiver {
    pub async fn recv(&mut self) -> Option<ZCPacket> {
        if let Some(packet) = self.pending.as_mut().and_then(|pending| pending.0.next()) {
            return Some(packet);
        }
        self.pending = None;
        let queued = self.receiver.recv().await?;
        let mut packets = queued.batch.into_iter();
        let packet = packets.next();
        self.pending = Some((packets, queued._queue_credits));
        packet
    }

    pub async fn recv_batch(&mut self) -> Option<PacketBatch> {
        if let Some((mut pending, _queue_credits)) = self.pending.take() {
            let mut batch = PacketBatch::new();
            for packet in pending.by_ref() {
                batch
                    .try_push(packet)
                    .expect("pending peer vector remains bounded");
            }
            if !batch.is_empty() {
                return Some(batch);
            }
        }
        self.receiver.recv().await.map(|queued| queued.batch)
    }

    pub fn try_recv(&mut self) -> Result<ZCPacket, tokio::sync::mpsc::error::TryRecvError> {
        if let Some(packet) = self.pending.as_mut().and_then(|pending| pending.0.next()) {
            return Ok(packet);
        }
        self.pending = None;
        let queued = self.receiver.try_recv()?;
        let mut packets = queued.batch.into_iter();
        let packet = packets.next().expect("empty peer vectors are never queued");
        self.pending = Some((packets, queued._queue_credits));
        Ok(packet)
    }
}

pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(PACKET_QUEUE_BATCH_CAPACITY);
    let queue_credits = Arc::new(Semaphore::new(PACKET_QUEUE_CREDIT_BYTES));
    let direct_nic = Arc::new(OnceLock::new());
    (
        PacketRecvChan {
            sender,
            queue_credits,
            direct_nic,
        },
        PacketRecvChanReceiver {
            receiver,
            pending: None,
        },
    )
}
pub async fn recv_packet_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<ZCPacket, anyhow::Error> {
    packet_recv_chan_receiver
        .recv()
        .await
        .ok_or(anyhow::anyhow!("recv_packet_from_chan failed"))
}

pub async fn recv_packet_batch_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<PacketBatch, anyhow::Error> {
    packet_recv_chan_receiver
        .recv_batch()
        .await
        .ok_or(anyhow::anyhow!("recv_packet_batch_from_chan failed"))
}

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

#[cfg(test)]
mod vector_channel_tests {
    use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};

    use super::create_packet_recv_chan;

    #[tokio::test]
    async fn full_ingress_cannot_block_nic_delivery() {
        use std::task::Poll;

        fn batch(value: u8) -> PacketBatch {
            let mut batch = PacketBatch::new();
            for _ in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
                batch
                    .try_push(ZCPacket::new_with_payload(&[value; 128]))
                    .unwrap();
            }
            batch
        }

        let (nic, mut nic_rx) = create_packet_recv_chan();
        let (ingress, mut ingress_rx) = nic.create_sibling_channel();
        ingress.send_batch(batch(1)).await.unwrap();
        ingress.send_batch(batch(2)).await.unwrap();
        let current = ingress_rx.recv_batch().await.unwrap();
        ingress.send_batch(batch(3)).await.unwrap();
        assert_eq!(ingress.queue_credits.available_permits(), 0);

        // Production awaits NIC delivery before it can dequeue more ingress.
        let delivery = nic.send_batch(current);
        tokio::pin!(delivery);
        assert!(matches!(futures::poll!(&mut delivery), Poll::Ready(Ok(()))));
        nic.send_batch(batch(4)).await.unwrap();
        assert_eq!(nic.queue_credits.available_permits(), 0);

        // Both stages must retain their own bound and resume after a dequeue.
        let blocked_ingress = ingress.send_batch(batch(5));
        let blocked_nic = nic.send_batch(batch(6));
        tokio::pin!(blocked_ingress, blocked_nic);
        assert!(matches!(
            futures::poll!(&mut blocked_ingress),
            Poll::Pending
        ));
        assert!(matches!(futures::poll!(&mut blocked_nic), Poll::Pending));
        let received = nic_rx.recv_batch().await.unwrap();
        assert_eq!(received.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
        assert!(received.iter().all(|packet| packet.payload()[0] == 1));
        assert!(matches!(
            futures::poll!(&mut blocked_nic),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            futures::poll!(&mut blocked_ingress),
            Poll::Pending
        ));
        let received = ingress_rx.recv_batch().await.unwrap();
        assert!(received.iter().all(|packet| packet.payload()[0] == 2));
        assert!(matches!(
            futures::poll!(&mut blocked_ingress),
            Poll::Ready(Ok(()))
        ));
    }
}
