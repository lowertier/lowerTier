use std::sync::{Arc, Weak};

use crate::{
    common::global_ctx::GlobalCtx, instance::instance::InstanceConfigPatcher,
    peers::peer_manager::PeerManager, proto::api::instance::PeerInfo,
};

#[derive(Clone)]
pub struct ControlInstance {
    pub peer_manager: Weak<PeerManager>,
    pub global_ctx: Weak<GlobalCtx>,
    pub patcher: InstanceConfigPatcher,
}

impl ControlInstance {
    pub async fn list_peers(peer_manager: &PeerManager) -> Vec<PeerInfo> {
        let mut peers = peer_manager.get_peer_map().list_peers();
        peers.extend(
            peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .iter(),
        );
        let peer_map = peer_manager.get_peer_map();
        let mut peer_infos = Vec::new();
        for peer in peers {
            let mut peer_info = PeerInfo {
                peer_id: peer,
                default_conn_id: peer_map
                    .get_peer_default_conn_id(peer)
                    .await
                    .map(Into::into),
                directly_connected_conns: peer_map
                    .get_directly_connections_by_peer_id(peer)
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                ..Default::default()
            };

            if let Some(conns) = peer_map.list_peer_conns(peer).await {
                peer_info.conns = conns;
            } else if let Some(conns) = peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peer_conns(peer)
                .await
            {
                peer_info.conns = conns;
            }

            peer_infos.push(peer_info);
        }

        peer_infos
    }

    pub fn peers(&self) -> anyhow::Result<Arc<PeerManager>> {
        crate::utils::weak_upgrade(&self.peer_manager)
    }

    pub fn context(&self) -> anyhow::Result<Arc<GlobalCtx>> {
        crate::utils::weak_upgrade(&self.global_ctx)
    }
}
