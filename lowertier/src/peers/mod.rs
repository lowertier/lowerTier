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

pub(crate) mod flow;
pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;
pub(crate) mod link_envelope;
pub(crate) mod secure_datagram;

pub mod peer_task;

#[cfg(test)]
pub mod tests;

use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(&self, _zc_packet: ZCPacket) -> Option<ZCPacket> {
        Some(_zc_packet)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool;

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
        self.sender.send(batch).await
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
    pending: Option<smallvec::IntoIter<[ZCPacket; 4]>>,
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
    (
        PacketRecvChan { sender },
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

    use super::{create_packet_recv_chan, recv_packet_batch_from_chan};

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
}
