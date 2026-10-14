use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct PeerCenterManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl PeerCenterManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterManageRpcService {
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        ctrl: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> crate::proto::rpc_types::error::Result<GetGlobalPeerMapResponse> {
        let instance_service =
            super::get_instance_service(&self.instance_manager, &None).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("please specify the instance ID") {
                    anyhow::anyhow!(
                        "PeerCenter management RPC cannot select an instance automatically \
                         when multiple instances are running; please use an API that allows \
                         specifying an instance identifier."
                    )
                } else {
                    e
                }
            })?;

        instance_service
            .get_peer_center_service()
            .get_global_peer_map(ctrl, req)
            .await
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _: ReportPeersRequest,
    ) -> crate::proto::rpc_types::error::Result<ReportPeersResponse> {
        Err(anyhow::anyhow!("not implemented for management API").into())
    }
}
