use std::sync::{Arc, Mutex};

use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::{
    common::{PeerId, error::Error, stats_manager::StatsManager},
    proto::rpc_impl::{self, bidirect::BidirectRpcManager},
    tunnel::{batch::PacketBatch, packet_def::ZCPacket},
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerRpcManagerTransport: Send + Sync + 'static {
    fn my_peer_id(&self) -> PeerId;
    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error>;
    async fn recv(&self) -> Result<ZCPacket, Error>;
}

// handle rpc request from one peer
pub struct PeerRpcManager {
    tspt: Arc<Box<dyn PeerRpcManagerTransport>>,
    bidirect_rpc: BidirectRpcManager,
    tasks: Mutex<JoinSet<()>>,
}

impl std::fmt::Debug for PeerRpcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRpcManager")
            .field("node_id", &self.tspt.my_peer_id())
            .finish()
    }
}

impl PeerRpcManager {
    pub fn new(tspt: impl PeerRpcManagerTransport) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new(),

            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn new_with_stats_manager(
        tspt: impl PeerRpcManagerTransport,
        stats_manager: Arc<StatsManager>,
    ) -> Self {
        Self {
            tspt: Arc::new(Box::new(tspt)),
            bidirect_rpc: BidirectRpcManager::new_with_stats_manager(stats_manager),

            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub fn run(&self) {
        let ret = self.bidirect_rpc.run_and_create_tunnel();
        let (mut rx, mut tx) = ret.split();
        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Some(Ok(batch)) = rx.next().await {
                for packet in batch {
                    let dst_peer_id = packet.peer_manager_header().unwrap().to_peer_id.into();
                    if let Err(e) = tspt.send(packet, dst_peer_id).await {
                        tracing::error!("send to rpc tspt error: {:?}", e);
                    }
                }
            }
        });

        let tspt = self.tspt.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(packet) = tspt.recv().await {
                if let Err(e) = tx.send(PacketBatch::singleton(packet)).await {
                    tracing::error!("send to rpc tspt error: {:?}", e);
                }
            }
        });
    }

    pub fn rpc_client(&self) -> &rpc_impl::client::Client {
        self.bidirect_rpc.rpc_client()
    }

    pub fn rpc_server(&self) -> &rpc_impl::server::Server {
        self.bidirect_rpc.rpc_server()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.tspt.my_peer_id()
    }
}

impl Drop for PeerRpcManager {
    fn drop(&mut self) {
        tracing::debug!("PeerRpcManager drop, my_peer_id: {:?}", self.my_peer_id());
    }
}
