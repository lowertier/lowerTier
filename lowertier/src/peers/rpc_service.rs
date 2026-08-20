use std::{
    ops::Deref,
    sync::{Arc, Weak},
    time::Duration,
};

use crate::{
    proto::{
        api::instance::{
            AclManageRpc, CredentialManageRpc, DumpRouteRequest, DumpRouteResponse,
            GenerateCredentialRequest, GenerateCredentialResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetForeignNetworkSummaryRequest, GetForeignNetworkSummaryResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListCredentialsRequest,
            ListCredentialsResponse, ListForeignNetworkRequest, ListForeignNetworkResponse,
            ListGlobalForeignNetworkRequest, ListGlobalForeignNetworkResponse, ListPeerRequest,
            ListPeerResponse, ListPublicIpv6InfoRequest, ListPublicIpv6InfoResponse,
            ListRouteRequest, ListRouteResponse, PeerInfo, PeerManageRpc, RevokeCredentialRequest,
            RevokeCredentialResponse, ShowNodeInfoRequest, ShowNodeInfoResponse,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
    utils::weak_upgrade,
};

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    peer_manager: Weak<PeerManager>,
}

impl PeerManagerRpcService {
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        PeerManagerRpcService {
            peer_manager: Arc::downgrade(&peer_manager),
        }
    }

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

    fn authorize_credential_management(
        controller: &BaseController,
        global_ctx: &crate::common::global_ctx::GlobalCtx,
        admin_token: Option<&str>,
    ) -> Result<(), rpc_types::error::Error> {
        let remote_is_loopback = controller
            .get_tunnel_info()
            .and_then(|info| info.remote_addr.as_ref())
            .and_then(|address| url::Url::parse(&address.url).ok())
            .and_then(|address| address.host_str()?.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        let expected = global_ctx
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        let token_valid = admin_token.is_some_and(|token| {
            crate::common::verify_slices_are_equal(token.as_bytes(), expected.as_bytes()).is_ok()
        });
        if remote_is_loopback && !expected.is_empty() && token_valid {
            return Ok(());
        }
        Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
            "credential management requires a loopback channel and a valid administrator token"
        )))
    }
}

#[async_trait::async_trait]
impl PeerManageRpc for PeerManagerRpcService {
    type Controller = BaseController;
    async fn list_peer(
        &self,
        _: BaseController,
        _request: ListPeerRequest, // Accept request of type HelloRequest
    ) -> Result<ListPeerResponse, rpc_types::error::Error> {
        let mut reply = ListPeerResponse::default();

        let peers =
            PeerManagerRpcService::list_peers(weak_upgrade(&self.peer_manager)?.deref()).await;
        for peer in peers {
            reply.peer_infos.push(peer);
        }

        Ok(reply)
    }

    async fn list_public_ipv6_info(
        &self,
        _: BaseController,
        _request: ListPublicIpv6InfoRequest,
    ) -> Result<ListPublicIpv6InfoResponse, rpc_types::error::Error> {
        Ok(weak_upgrade(&self.peer_manager)?
            .get_local_public_ipv6_info()
            .await)
    }

    async fn list_route(
        &self,
        _: BaseController,
        _request: ListRouteRequest, // Accept request of type HelloRequest
    ) -> Result<ListRouteResponse, rpc_types::error::Error> {
        let reply = ListRouteResponse {
            routes: weak_upgrade(&self.peer_manager)?.list_routes().await,
        };
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest, // Accept request of type HelloRequest
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let reply = DumpRouteResponse {
            result: weak_upgrade(&self.peer_manager)?.dump_route().await,
        };
        Ok(reply)
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        request: ListForeignNetworkRequest,
    ) -> Result<ListForeignNetworkResponse, rpc_types::error::Error> {
        let reply = weak_upgrade(&self.peer_manager)?
            .get_foreign_network_manager()
            .list_foreign_networks_with_options(request.include_trusted_keys)
            .await;
        Ok(reply)
    }

    async fn list_global_foreign_network(
        &self,
        _: BaseController,
        _request: ListGlobalForeignNetworkRequest,
    ) -> Result<ListGlobalForeignNetworkResponse, rpc_types::error::Error> {
        Ok(weak_upgrade(&self.peer_manager)?
            .list_global_foreign_network()
            .await)
    }

    async fn get_foreign_network_summary(
        &self,
        _: BaseController,
        _request: GetForeignNetworkSummaryRequest,
    ) -> Result<GetForeignNetworkSummaryResponse, rpc_types::error::Error> {
        Ok(GetForeignNetworkSummaryResponse {
            summary: Some(
                weak_upgrade(&self.peer_manager)?
                    .get_foreign_network_summary()
                    .await,
            ),
        })
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        _request: ShowNodeInfoRequest, // Accept request of type HelloRequest
    ) -> Result<ShowNodeInfoResponse, rpc_types::error::Error> {
        Ok(ShowNodeInfoResponse {
            node_info: Some(weak_upgrade(&self.peer_manager)?.get_my_info().await),
        })
    }
}

#[async_trait::async_trait]
impl AclManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        _: BaseController,
        _request: GetAclStatsRequest,
    ) -> Result<GetAclStatsResponse, rpc_types::error::Error> {
        let acl_stats = weak_upgrade(&self.peer_manager)?
            .get_global_ctx()
            .get_acl_filter()
            .get_stats();
        Ok(GetAclStatsResponse {
            acl_stats: Some(acl_stats),
        })
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        _request: GetWhitelistRequest,
    ) -> Result<GetWhitelistResponse, rpc_types::error::Error> {
        let global_ctx = weak_upgrade(&self.peer_manager)?.get_global_ctx();
        let tcp_ports = global_ctx.config.get_tcp_whitelist();
        let udp_ports = global_ctx.config.get_udp_whitelist();
        tracing::info!(
            "Getting whitelist - TCP: {:?}, UDP: {:?}",
            tcp_ports,
            udp_ports
        );
        Ok(GetWhitelistResponse {
            tcp_ports,
            udp_ports,
        })
    }
}

#[async_trait::async_trait]
impl CredentialManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn generate_credential(
        &self,
        controller: BaseController,
        request: GenerateCredentialRequest,
    ) -> Result<GenerateCredentialResponse, rpc_types::error::Error> {
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();
        Self::authorize_credential_management(
            &controller,
            &global_ctx,
            request.admin_token.as_deref(),
        )?;

        if global_ctx
            .get_network_identity()
            .network_secret
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "only admin nodes (with network_secret) can generate credentials"
            )));
        }

        let ttl = if request.ttl_seconds > 0 {
            Duration::from_secs(request.ttl_seconds as u64)
        } else {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "ttl_seconds must be positive"
            )));
        };

        let (id, secret) = global_ctx
            .get_credential_manager()
            .generate_credential_bundle(
                request.groups,
                request.allow_relay,
                request.allowed_proxy_cidrs,
                ttl,
                request.credential_id,
                request.reusable.unwrap_or(true),
            )
            .map_err(|error| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "failed to issue credential: {error}"
                ))
            })?;

        global_ctx.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);

        let bundle =
            crate::peers::credential_manager::CredentialManager::parse_credential_bundle(&secret)
                .ok();
        Ok(GenerateCredentialResponse {
            credential_id: id,
            credential_secret: secret,
            bundle,
        })
    }

    async fn revoke_credential(
        &self,
        controller: BaseController,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, rpc_types::error::Error> {
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();
        Self::authorize_credential_management(
            &controller,
            &global_ctx,
            request.admin_token.as_deref(),
        )?;
        if global_ctx
            .get_network_identity()
            .network_secret
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "only admin nodes (with network_secret) can revoke credentials"
            )));
        }

        let success = global_ctx
            .get_credential_manager()
            .try_revoke_credential(&request.credential_id)
            .map_err(|error| {
                rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "failed to revoke credential: {error}"
                ))
            })?;

        if success {
            global_ctx.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);
        }

        Ok(RevokeCredentialResponse { success })
    }

    async fn list_credentials(
        &self,
        controller: BaseController,
        request: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, rpc_types::error::Error> {
        let pm = weak_upgrade(&self.peer_manager)?;
        let global_ctx = pm.get_global_ctx();
        Self::authorize_credential_management(
            &controller,
            &global_ctx,
            request.admin_token.as_deref(),
        )?;

        Ok(ListCredentialsResponse {
            credentials: global_ctx.get_credential_manager().list_credentials(),
        })
    }
}
