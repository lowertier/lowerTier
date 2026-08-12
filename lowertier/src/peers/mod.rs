mod graph_algo;

pub mod l2_fabric;

pub mod acl_filter;
#[cfg(feature = "quic")]
mod alternate_fec;
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
pub mod relay_peer_map;
pub mod route_trait;
pub mod rpc_service;
mod traffic_metrics;

use std::sync::{Arc, OnceLock};

pub(crate) mod flow;
pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;
pub(crate) mod link_envelope;
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

// pub type PacketRecvChan = tachyonix::Sender<ZCPacket>;
// pub type PacketRecvChanReceiver = tachyonix::Receiver<ZCPacket>;
// pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
//     tachyonix::channel(128)
// }
#[derive(Clone)]
pub struct PacketRecvChan {
    sender: tokio::sync::mpsc::Sender<PacketBatch>,
    direct_nic: Arc<OnceLock<Arc<peer_manager::DirectNicIngress>>>,
}

impl PacketRecvChan {
    pub async fn send(
        &self,
        packet: ZCPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ZCPacket>> {
        self.sender
            .send(PacketBatch::singleton(packet))
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
        let batch = if let Some(direct_nic) = self.direct_nic.get() {
            match direct_nic.try_process(batch).await {
                Ok(()) => return Ok(()),
                Err(batch) => batch,
            }
        } else {
            batch
        };
        self.sender.send(batch).await
    }

    pub(crate) fn install_direct_nic(&self, ingress: Arc<peer_manager::DirectNicIngress>) {
        let _ = self.direct_nic.set(ingress);
    }

    pub fn try_send(
        &self,
        packet: ZCPacket,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<ZCPacket>> {
        self.sender
            .try_send(PacketBatch::singleton(packet))
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(batch) => {
                    tokio::sync::mpsc::error::TrySendError::Full(
                        batch.pop_singleton().expect("scalar packet channel job"),
                    )
                }
                tokio::sync::mpsc::error::TrySendError::Closed(batch) => {
                    tokio::sync::mpsc::error::TrySendError::Closed(
                        batch.pop_singleton().expect("scalar packet channel job"),
                    )
                }
            })
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

pub struct PacketRecvChanReceiver {
    receiver: tokio::sync::mpsc::Receiver<PacketBatch>,
    pending: Option<PacketBatchIntoIter>,
}

impl PacketRecvChanReceiver {
    pub async fn recv(&mut self) -> Option<ZCPacket> {
        if let Some(packet) = self.pending.as_mut().and_then(Iterator::next) {
            return Some(packet);
        }
        self.pending = None;
        let batch = self.receiver.recv().await?;
        let mut packets = batch.into_iter();
        let packet = packets.next();
        self.pending = Some(packets);
        packet
    }

    pub async fn recv_batch(&mut self) -> Option<PacketBatch> {
        if let Some(mut pending) = self.pending.take() {
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
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<ZCPacket, tokio::sync::mpsc::error::TryRecvError> {
        if let Some(packet) = self.pending.as_mut().and_then(Iterator::next) {
            return Ok(packet);
        }
        self.pending = None;
        let batch = self.receiver.try_recv()?;
        let mut packets = batch.into_iter();
        let packet = packets.next().expect("empty peer vectors are never queued");
        self.pending = Some(packets);
        Ok(packet)
    }
}

pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(128);
    let direct_nic = Arc::new(OnceLock::new());
    (
        PacketRecvChan { sender, direct_nic },
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

    use super::{PeerPacketFilter, create_packet_recv_chan, recv_packet_batch_from_chan};

    struct KeepOddPackets;

    #[async_trait::async_trait]
    impl PeerPacketFilter for KeepOddPackets {
        async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
            (packet.payload()[0] % 2 == 1).then_some(packet)
        }
    }

    #[tokio::test]
    async fn peer_channel_queues_a_vector_as_one_ordered_job() {
        let (sender, mut receiver) = create_packet_recv_chan();
        let mut batch = PacketBatch::new();
        for value in 0_u8..4 {
            batch
                .try_push(ZCPacket::new_with_payload(&[value]))
                .unwrap();
        }

        sender.send_batch(batch).await.unwrap();
        let received = recv_packet_batch_from_chan(&mut receiver).await.unwrap();

        assert_eq!(received.len(), 4);
        assert_eq!(
            received
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[tokio::test]
    async fn default_peer_filter_batch_preserves_order_and_consumption() {
        let mut batch = PacketBatch::new();
        for value in 0_u8..6 {
            batch
                .try_push(ZCPacket::new_with_payload(&[value]))
                .unwrap();
        }

        let filtered = KeepOddPackets.try_process_batch_from_peer(batch).await;

        assert_eq!(
            filtered
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn peer_filter_is_interested_by_default() {
        let packet = ZCPacket::new_with_payload(b"data");

        assert!(KeepOddPackets.is_interested_in_packet_from_peer(&packet));
    }
}
