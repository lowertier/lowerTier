use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::control::v1::*,
        rpc_types::{controller::BaseController, error::Result},
    },
};

pub(crate) mod config;
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
    externally_locked: bool,
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
        code: code.to_ascii_lowercase(),
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
            code: "internal".into(),
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
            externally_locked: false,
            stats: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    pub fn for_owned_instances(manager: Arc<NetworkInstanceManager>) -> Self {
        Self {
            manager,
            token: None,
            epoch: *std::sync::LazyLock::force(&watch::PROCESS_EPOCH),
            externally_locked: false,
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
            code: "permission_denied".into(),
            message: "A valid control token is required.".into(),
            field_path: "meta.control_token".into(),
            retryable: false,
        })
    }

    async fn mutation_guard(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        if self.externally_locked {
            None
        } else {
            Some(self.manager.remote_mutation_lock().lock_owned().await)
        }
    }
}

pub async fn call_owned_json(
    manager: &Arc<NetworkInstanceManager>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> Result<serde_json::Value> {
    Ok(
        call_owned_json_locked(manager, service_name, method_name, domain_name, payload)
            .await?
            .0,
    )
}

/// Keep the manager lock until the owned adapter completes lifecycle cleanup.
pub async fn call_owned_json_locked(
    manager: &Arc<NetworkInstanceManager>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> Result<(serde_json::Value, Option<tokio::sync::OwnedMutexGuard<()>>)> {
    let error = if service_name != "api.control.v1.ControlPlaneV1Rpc" {
        Some(failure(
            "INVALID_ARGUMENT",
            "The control service name is invalid.",
            "service_name",
        ))
    } else if !read::METHODS.contains(&method_name) {
        Some(failure(
            "INVALID_ARGUMENT",
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
        return Ok((serde_json::json!({"error": api_error(error)}), None));
    }
    let guard = if method_name == "WatchChanges" {
        None
    } else {
        Some(manager.remote_mutation_lock().lock_owned().await)
    };
    let mut service = ControlPlaneService::for_owned_instances(manager.clone());
    service.externally_locked = guard.is_some();
    let response = match service
        .json_call_method(BaseController::default(), method_name, payload)
        .await
    {
        Ok(response) => response,
        Err(_) => serde_json::json!({"error": ApiError {
            code: "invalid_argument".into(),
            message: "The control request is invalid.".into(),
            ..Default::default()
        }}),
    };
    Ok((response, guard))
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
                    apply_classes: vec!["live".into(), "new_connection".into(), "restart".into()],
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
    get_config, GetConfigRequest, GetConfigResponse, get_config_inner;
    validate_config, ValidateConfigRequest, ValidateConfigResponse, validate_config_inner;
    patch_config, PatchConfigRequest, PatchConfigResponse, patch_config_inner;
    get_relay, GetRelayRequest, GetRelayResponse, get_relay_inner;
    get_camouflage, GetCamouflageRequest, GetCamouflageResponse, get_camouflage_inner;
    create_instance, CreateInstanceRequest, CreateInstanceResponse, create_instance_inner;
    start_instance, StartInstanceRequest, StartInstanceResponse, start_instance_inner;
    stop_instance, StopInstanceRequest, StopInstanceResponse, stop_instance_inner;
    delete_instance, DeleteInstanceRequest, DeleteInstanceResponse, delete_instance_inner;
    set_acl, SetAclRequest, SetAclResponse, set_acl_inner;
    put_port_forward, PutPortForwardRequest, PutPortForwardResponse, put_port_forward_inner;
    delete_port_forward, DeletePortForwardRequest, DeletePortForwardResponse, delete_port_forward_inner;
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
[acl.acl_v1.group]
declares = [{ group_name = "admin", group_secret = "rpc-group-secret" }]
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
        assert_eq!(response.error.unwrap().code, "permission_denied");
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
                    include_paths: true,
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
        let selected = routes
            .routes
            .iter()
            .find(|route| route.route.as_ref().unwrap().peer_id == b.my_peer_id())
            .unwrap();
        assert_eq!(selected.path_peer_ids, vec![a.my_peer_id(), b.my_peer_id()]);
        let config = service
            .get_config(
                BaseController::default(),
                GetConfigRequest { meta: meta.clone() },
            )
            .await
            .unwrap();
        assert!(config.error.is_none(), "{:?}", config.error);
        assert_eq!(config.snapshot.unwrap().revision, 1);
        let active = config.active.unwrap();
        assert!(active.network_identity.unwrap().network_secret.is_none());
        assert_eq!(
            active.acl.unwrap().acl_v1.unwrap().group.unwrap().declares[0].group_secret,
            "[REDACTED]"
        );
        let patch = ConfigPatch {
            expected_revision: 1,
            field_mask: vec!["relay.use_relays".into()],
            values: Some(NodeConfig {
                relay: Some(crate::proto::common::RelayConfig {
                    use_relays: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let applied = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(patch.clone()),
                },
            )
            .await
            .unwrap();
        assert!(applied.error.is_none(), "{:?}", applied.error);
        assert_eq!(applied.result.unwrap().revision, 2);
        let stale = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(patch),
                },
            )
            .await
            .unwrap();
        assert_eq!(stale.error.unwrap().code, "conflict");
        let patch = ConfigPatch {
            expected_revision: 2,
            field_mask: vec!["hostname".into()],
            values: Some(NodeConfig {
                hostname: Some("unpublished".into()),
                ..Default::default()
            }),
            persist: true,
            ..Default::default()
        };
        let failed = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(patch),
                },
            )
            .await
            .unwrap();
        assert!(failed.error.is_some());
        let patch = ConfigPatch {
            expected_revision: 2,
            field_mask: vec!["listeners".into()],
            values: Some(NodeConfig {
                listeners: vec!["quic://127.0.0.1:0".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let rejected = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(patch.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(rejected.error.unwrap().code, "restart_required");
        let staged = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(ConfigPatch {
                        stage: true,
                        ..patch
                    }),
                },
            )
            .await
            .unwrap();
        assert!(staged.error.is_none(), "{:?}", staged.error);
        assert_eq!(staged.result.unwrap().restart_fields, vec!["listeners"]);
        let config = service
            .get_config(
                BaseController::default(),
                GetConfigRequest { meta: meta.clone() },
            )
            .await
            .unwrap();
        assert!(config.error.is_none(), "{:?}", config.error);
        assert_eq!(config.snapshot.unwrap().revision, 3);
        assert!(config.active.as_ref().unwrap().listeners.is_empty());
        assert_eq!(config.active.unwrap().hostname.as_deref(), None);
        assert_eq!(config.desired.unwrap().listeners.len(), 1);
        let validation = service
            .validate_config(
                BaseController::default(),
                ValidateConfigRequest {
                    meta: meta.clone(),
                    patch: Some(ConfigPatch {
                        expected_revision: 3,
                        field_mask: vec!["hostname".into()],
                        values: Some(NodeConfig {
                            hostname: Some("rpc-host".into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                },
            )
            .await
            .unwrap();
        assert!(validation.error.is_none(), "{:?}", validation.error);
        assert_eq!(validation.result.unwrap().restart_fields, vec!["listeners"]);
        let camouflage = service
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: meta.clone(),
                    patch: Some(ConfigPatch {
                        expected_revision: 3,
                        field_mask: vec!["camouflage.http_host".into()],
                        values: Some(NodeConfig {
                            camouflage: Some(crate::proto::common::CamouflageConfig {
                                http_host: "example.test".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        stage: true,
                        ..Default::default()
                    }),
                },
            )
            .await
            .unwrap();
        assert!(camouflage.error.is_none(), "{:?}", camouflage.error);
        assert_eq!(
            camouflage.result.unwrap().new_connection_fields,
            vec!["camouflage.http_host"]
        );
        let camouflage = service
            .get_camouflage(
                BaseController::default(),
                GetCamouflageRequest { meta: meta.clone() },
            )
            .await
            .unwrap();
        assert!(camouflage.error.is_none(), "{:?}", camouflage.error);
        assert_eq!(camouflage.config.unwrap().http_host, "example.test");
        let invalid = service
            .validate_config(
                BaseController::default(),
                ValidateConfigRequest {
                    meta: meta.clone(),
                    patch: Some(ConfigPatch {
                        expected_revision: 4,
                        field_mask: vec![
                            "camouflage.tls_cert".into(),
                            "camouflage.tls_key".into(),
                            "camouflage.server_name".into(),
                            "camouflage.website_root".into(),
                        ],
                        values: Some(NodeConfig {
                            camouflage: Some(crate::proto::common::CamouflageConfig {
                                tls_cert: dir.path().join("missing.crt").display().to_string(),
                                tls_key: dir.path().join("missing.key").display().to_string(),
                                server_name: "example.test".into(),
                                website_root: dir.path().display().to_string(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        stage: true,
                        ..Default::default()
                    }),
                },
            )
            .await
            .unwrap();
        assert_eq!(invalid.error.unwrap().code, "invalid_argument");
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
        assert_eq!(rejected.error.unwrap().code, "permission_denied");
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
        let stored = TomlConfigLoader::default();
        let stored_id = stored.get_id();
        let stored_path = dir.path().join("stored.toml");
        manager
            .create_network_instance(
                stored,
                ConfigFileControl::new(Some(stored_path.clone()), 0u8.into()),
            )
            .unwrap();
        let stored_meta = Some(RequestMeta {
            instance_id: stored_id.to_string(),
            ..Default::default()
        });
        let owned = ControlPlaneService::for_owned_instances(manager.clone());
        let patch = ConfigPatch {
            expected_revision: 1,
            field_mask: vec!["hostname".into()],
            values: Some(NodeConfig {
                hostname: Some("persisted-host".into()),
                ..Default::default()
            }),
            persist: true,
            ..Default::default()
        };
        let persisted = owned
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: stored_meta.clone(),
                    patch: Some(patch.clone()),
                },
            )
            .await
            .unwrap();
        assert!(persisted.error.is_none(), "{:?}", persisted.error);
        assert_eq!(
            TomlConfigLoader::new(&stored_path).unwrap().get_hostname(),
            "persisted-host"
        );
        std::fs::remove_file(&stored_path).unwrap();
        std::fs::create_dir(&stored_path).unwrap();
        std::fs::write(stored_path.join("entry"), "occupied").unwrap();
        let failed = owned
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    meta: stored_meta.clone(),
                    patch: Some(ConfigPatch {
                        expected_revision: 2,
                        values: Some(NodeConfig {
                            hostname: Some("failed-host".into()),
                            ..Default::default()
                        }),
                        ..patch
                    }),
                },
            )
            .await
            .unwrap();
        assert_eq!(failed.error.unwrap().code, "unavailable");
        let unchanged = owned
            .get_config(
                BaseController::default(),
                GetConfigRequest { meta: stored_meta },
            )
            .await
            .unwrap();
        assert_eq!(unchanged.snapshot.unwrap().revision, 2);
        assert_eq!(
            unchanged.active.unwrap().hostname.as_deref(),
            Some("persisted-host")
        );
        for id in ids {
            manager.stop_network_instance(id).await.unwrap();
        }
    }
}
