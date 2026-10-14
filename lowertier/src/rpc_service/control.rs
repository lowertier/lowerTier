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
    token: Option<Arc<ControlToken>>,
    epoch: uuid::Uuid,
    stats: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<
                uuid::Uuid,
                (i64, Vec<crate::proto::api::instance::MetricSnapshot>),
            >,
        >,
    >,
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
            token: Some(Arc::new(token)),
            epoch: *std::sync::LazyLock::force(&watch::PROCESS_EPOCH),
            stats: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    pub fn for_owned_instances(manager: Arc<NetworkInstanceManager>) -> Self {
        Self {
            manager,
            token: None,
            epoch: *std::sync::LazyLock::force(&watch::PROCESS_EPOCH),
            stats: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    fn authorize(&self, meta: Option<&RequestMeta>) -> std::result::Result<(), ApiError> {
        if self
            .token
            .as_ref()
            .is_none_or(|token| meta.is_some_and(|meta| token.matches(&meta.control_token)))
        {
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

pub async fn call_owned_json(
    manager: &Arc<NetworkInstanceManager>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> Result<serde_json::Value> {
    let error = if service_name != "api.control.v1.ControlPlaneV1Rpc" {
        Some(failure(
            "UNSUPPORTED_SERVICE",
            "The control service name is invalid.",
            "service_name",
        ))
    } else if !read::METHODS.contains(&method_name) {
        Some(failure(
            "UNSUPPORTED_METHOD",
            "The control method name is invalid.",
            "method_name",
        ))
    } else if domain_name.is_some_and(|domain| !domain.is_empty()) {
        Some(failure(
            "INVALID_ARGUMENT",
            "The control service has no domain.",
            "domain_name",
        ))
    } else {
        None
    };
    if let Some(error) = error {
        return Ok(serde_json::json!({"error": api_error(error)}));
    }
    match ControlPlaneService::for_owned_instances(manager.clone())
        .json_call_method(BaseController::default(), method_name, payload)
        .await
    {
        Ok(response) => Ok(response),
        Err(_) => Ok(serde_json::json!({"error": ApiError {
            code: "INVALID_ARGUMENT".into(),
            message: "The control request is invalid.".into(),
            ..Default::default()
        }})),
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
    async fn portal_requires_token_and_lists_two_node_resources() {
        use crate::{
            common::config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
            instance::instance::InstanceRpcServerHook,
            peers::tests::{connect_peer_manager, wait_route_appear},
            proto::rpc_impl::standalone::{StandAloneClient, StandAloneServer},
            tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener},
        };

        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("control.token");
        let token = ControlToken::load_or_create(&token_path).unwrap();
        let control_token = std::fs::read_to_string(&token_path)
            .unwrap()
            .trim()
            .to_owned();
        let manager = Arc::new(NetworkInstanceManager::new());
        let mut ids = Vec::new();
        for name in ["rpc-a", "rpc-b"] {
            let config = TomlConfigLoader::new_from_str(
                r#"
listeners = []
stun_servers = []
stun_servers_v6 = []
tcp_stun_servers = []
[network_identity]
network_name = "rpc-test"
network_secret = "rpc-test-secret"
[flags]
no_tun = true
multi_thread = false
enable_ipv6 = false
disable_p2p = true
disable_udp_hole_punching = true
disable_tcp_hole_punching = true
"#,
            )
            .unwrap();
            config.set_id(uuid::Uuid::new_v4());
            config.set_inst_name(name.into());
            ids.push(
                manager
                    .run_network_instance(config, false, ConfigFileControl::STATIC_CONFIG)
                    .unwrap(),
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            while ids
                .iter()
                .any(|id| manager.get_instance_service(id).is_none())
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let a = manager
            .get_instance_service(&ids[0])
            .unwrap()
            .peers()
            .unwrap();
        let b = manager
            .get_instance_service(&ids[1])
            .unwrap()
            .peers()
            .unwrap();
        connect_peer_manager(a.clone(), b.clone()).await;
        wait_route_appear(a.clone(), b.clone()).await.unwrap();

        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let uri: url::Url = format!("tcp://{address}").parse().unwrap();
        let mut server = StandAloneServer::new(TcpTunnelListener::new(uri.clone()));
        server.set_hook(Arc::new(InstanceRpcServerHook::new(None)));
        crate::rpc_service::api::register_api_rpc_service(&manager, server.registry(), token);
        server.serve().await.unwrap();
        let mut client = StandAloneClient::new(TcpTunnelConnector::new(uri));
        let service = client
            .scoped_client::<ControlPlaneV1RpcClientFactory<BaseController>>(String::new())
            .await
            .unwrap();
        let response = service
            .get_capabilities(BaseController::default(), GetCapabilitiesRequest::default())
            .await
            .unwrap();
        assert_eq!(response.error.unwrap().code, "UNAUTHENTICATED");
        let meta = Some(RequestMeta {
            instance_id: ids[0].to_string(),
            control_token,
            ..Default::default()
        });
        let peers = service
            .list_peers(
                BaseController::default(),
                ListPeersRequest {
                    meta: meta.clone(),
                    page: None,
                },
            )
            .await
            .unwrap();
        assert!(peers.error.is_none(), "{:?}", peers.error);
        assert!(
            peers
                .peers
                .iter()
                .any(|peer| peer.peer_id == b.my_peer_id())
        );
        let routes = service
            .list_routes(
                BaseController::default(),
                ListRoutesRequest {
                    meta: meta.clone(),
                    page: None,
                    include_paths: false,
                },
            )
            .await
            .unwrap();
        assert!(routes.error.is_none(), "{:?}", routes.error);
        assert!(routes.routes.iter().any(|route| {
            route
                .route
                .as_ref()
                .is_some_and(|route| route.peer_id == b.my_peer_id())
        }));
        use crate::proto::{common::TunnelInfo, rpc_impl::standalone::RpcServerHook};
        let hook = InstanceRpcServerHook::new(None);
        let ipv6_channel = TunnelInfo {
            remote_addr: Some("tcp://[::1]:15888".parse::<url::Url>().unwrap().into()),
            ..Default::default()
        };
        assert!(hook.on_new_client(Some(ipv6_channel.clone())).await.is_ok());
        let mut admin_meta = meta.unwrap();
        let admin_service = ControlPlaneService::new(
            manager.clone(),
            ControlToken::load_or_create(&token_path).unwrap(),
        );
        let controller = BaseController {
            tunnel_info: Some(ipv6_channel),
            ..Default::default()
        };
        let rejected = admin_service
            .list_credentials(
                controller.clone(),
                ListCredentialsRequest {
                    meta: Some(admin_meta.clone()),
                    page: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(rejected.error.unwrap().code, "PERMISSION_DENIED");
        admin_meta.admin_token = "rpc-test-secret".into();
        let accepted = admin_service
            .list_credentials(
                controller,
                ListCredentialsRequest {
                    meta: Some(admin_meta),
                    page: None,
                },
            )
            .await
            .unwrap();
        assert!(accepted.error.is_none(), "{:?}", accepted.error);
        for id in ids {
            manager.stop_network_instance(id).await.unwrap();
        }
    }
}
