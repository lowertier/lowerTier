use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::control::v1::*,
        rpc_types::{controller::BaseController, error::Result},
    },
};

mod instance;
pub(crate) mod logs;
mod read;
mod token;
mod watch;
pub use instance::ControlInstance;
pub use token::ControlToken;

#[derive(Clone)]
pub struct ControlPlaneService {
    manager: Arc<NetworkInstanceManager>,
    token: Arc<ControlToken>,
    epoch: uuid::Uuid,
}

#[derive(Debug, thiserror::Error)]
#[error("{0:?}")]
struct Failure(ApiError);

fn failure(code: &str, message: &str, field_path: &str) -> anyhow::Error {
    Failure(ApiError {
        code: code.into(),
        message: message.into(),
        field_path: field_path.into(),
        retryable: false,
    })
    .into()
}

fn api_error(error: anyhow::Error) -> ApiError {
    match error.downcast::<Failure>() {
        Ok(failure) => failure.0,
        Err(_) => ApiError {
            code: "INTERNAL".into(),
            message: "The control operation failed.".into(),
            ..Default::default()
        },
    }
}

impl ControlPlaneService {
    pub fn new(manager: Arc<NetworkInstanceManager>, token: ControlToken) -> Self {
        Self {
            manager,
            token: Arc::new(token),
            epoch: *std::sync::LazyLock::force(&watch::PROCESS_EPOCH),
        }
    }

    fn authorize(&self, meta: Option<&RequestMeta>) -> std::result::Result<(), ApiError> {
        if meta.is_some_and(|meta| self.token.matches(&meta.control_token)) {
            return Ok(());
        }
        Err(ApiError {
            code: "UNAUTHENTICATED".into(),
            message: "A valid control token is required.".into(),
            field_path: "meta.control_token".into(),
            retryable: false,
        })
    }
}

macro_rules! control_service {
    ($($method:ident, $request:ident, $response:ident, $inner:ident;)*) => {
        #[async_trait::async_trait]
        impl ControlPlaneV1Rpc for ControlPlaneService {
            type Controller = BaseController;
            $(
                async fn $method(&self, controller: BaseController, request: $request) -> Result<$response> {
                    if let Err(error) = self.authorize(request.meta.as_ref()) {
                        return Ok($response { error: Some(error), ..Default::default() });
                    }
                    match self.$inner(controller, request).await {
                        Ok(response) => Ok(response),
                        Err(error) => Ok($response { error: Some(api_error(error)), ..Default::default() }),
                    }
                }
            )*
            async fn get_capabilities(&self, _: BaseController, request: GetCapabilitiesRequest) -> Result<GetCapabilitiesResponse> {
                if let Err(error) = self.authorize(request.meta.as_ref()) {
                    return Ok(GetCapabilitiesResponse { error: Some(error), ..Default::default() });
                }
                Ok(GetCapabilitiesResponse {
                    api_version: "1".into(),
                    methods: read::METHODS.iter().map(|method| (*method).into()).collect(),
                    max_page_size: 256,
                    max_watch_wait_ms: 20_000,
                    ..Default::default()
                })
            }
        }
    };
}

control_service! {
    list_instances, ListInstancesRequest, ListInstancesResponse, list_instances_inner;
    get_node, GetNodeRequest, GetNodeResponse, get_node_inner;
    list_peers, ListPeersRequest, ListPeersResponse, list_peers_inner;
    list_routes, ListRoutesRequest, ListRoutesResponse, list_routes_inner;
    get_l2, GetL2Request, GetL2Response, get_l2_inner;
    get_discovery, GetDiscoveryRequest, GetDiscoveryResponse, get_discovery_inner;
    list_listeners, ListListenersRequest, ListListenersResponse, list_listeners_inner;
    get_stats, GetStatsRequest, GetStatsResponse, get_stats_inner;
    get_prometheus, GetPrometheusRequest, GetPrometheusResponse, get_prometheus_inner;
    read_logs, ReadLogsRequest, ReadLogsResponse, read_logs_inner;
    get_log_config, GetLogConfigRequest, GetLogConfigResponse, get_log_config_inner;
    set_log_config, SetLogConfigRequest, SetLogConfigResponse, set_log_config_inner;
    get_acl, GetAclRequest, GetAclResponse, get_acl_inner;
    get_acl_stats, GetAclStatsRequest, GetAclStatsResponse, get_acl_stats_inner;
    list_credentials, ListCredentialsRequest, ListCredentialsResponse, list_credentials_inner;
    issue_credential, IssueCredentialRequest, IssueCredentialResponse, issue_credential_inner;
    revoke_credential, RevokeCredentialRequest, RevokeCredentialResponse, revoke_credential_inner;
    list_port_forwards, ListPortForwardsRequest, ListPortForwardsResponse, list_port_forwards_inner;
    watch_changes, WatchChangesRequest, WatchChangesResponse, watch_changes_inner;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_token_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let service = ControlPlaneService::new(
            Arc::new(NetworkInstanceManager::new()),
            ControlToken::load_or_create(&dir.path().join("control.token")).unwrap(),
        );
        let response = service
            .get_capabilities(BaseController::default(), GetCapabilitiesRequest::default())
            .await
            .unwrap();
        assert_eq!(response.error.unwrap().code, "UNAUTHENTICATED");
    }
}
