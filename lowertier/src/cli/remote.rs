use super::{
    args::Arguments,
    client::{Client, Rpc},
    error::{CliError, Result},
};
use crate::proto::{
    api::control::v1::*,
    rpc_types::{
        controller::BaseController,
        error::{Error as RpcError, Result as RpcResult},
    },
};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
mod terminal;

#[derive(Clone)]
pub(super) struct Options {
    pub target: String,
    pub secret: String,
    pub meta: RequestMeta,
}

pub(super) fn read_secret(args: &Arguments) -> Result<String> {
    args.remote_secret_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|text| text.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(|_| {
                    CliError::new(
                        "permission_denied",
                        "Cannot read --remote-secret-file.",
                        "remote_secret_file",
                    )
                })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

struct Proxy {
    local: Rpc,
    options: Options,
}
pub(super) fn wrap(local: Rpc, options: Options) -> Rpc {
    Box::new(Proxy { local, options })
}

impl Proxy {
    async fn forward<I: Serialize, O: DeserializeOwned>(
        &self,
        controller: BaseController,
        method: &str,
        input: I,
    ) -> RpcResult<O> {
        let payload = serde_json::to_vec(&input)
            .map_err(|_| RpcError::MalformatRpcPacket("Invalid remote request".into()))?;
        let response = self
            .local
            .call_remote(
                controller,
                CallRemoteRequest {
                    meta: Some(self.options.meta.clone()),
                    target: self.options.target.clone(),
                    method: method.into(),
                    payload,
                    secret: self.options.secret.clone(),
                    ..Default::default()
                },
            )
            .await?;
        let value = if let Some(error) = response.error {
            json!({"error": error})
        } else {
            serde_json::from_slice::<Value>(&response.payload)
                .map_err(|_| RpcError::MalformatRpcPacket("Invalid remote response".into()))?
        };
        serde_json::from_value(value)
            .map_err(|_| RpcError::MalformatRpcPacket("Invalid remote response type".into()))
    }
}

macro_rules! proxy_methods {
    ($($method:ident, $name:literal, $input:ident, $output:ident;)*) => {
        #[async_trait::async_trait]
        impl ControlPlaneV1Rpc for Proxy {
            type Controller = BaseController;
            $(async fn $method(&self, controller: BaseController, request: $input) -> RpcResult<$output> {
                self.forward(controller, $name, request).await
            })*
        }
    };
}
proxy_methods! {
    get_capabilities, "GetCapabilities", GetCapabilitiesRequest, GetCapabilitiesResponse;
    list_instances, "ListInstances", ListInstancesRequest, ListInstancesResponse;
    get_node, "GetNode", GetNodeRequest, GetNodeResponse;
    list_peers, "ListPeers", ListPeersRequest, ListPeersResponse;
    list_routes, "ListRoutes", ListRoutesRequest, ListRoutesResponse;
    list_paths, "ListPaths", ListPathsRequest, ListPathsResponse;
    get_l2, "GetL2", GetL2Request, GetL2Response;
    get_discovery, "GetDiscovery", GetDiscoveryRequest, GetDiscoveryResponse;
    list_listeners, "ListListeners", ListListenersRequest, ListListenersResponse;
    get_stats, "GetStats", GetStatsRequest, GetStatsResponse;
    get_prometheus, "GetPrometheus", GetPrometheusRequest, GetPrometheusResponse;
    read_logs, "ReadLogs", ReadLogsRequest, ReadLogsResponse;
    get_log_config, "GetLogConfig", GetLogConfigRequest, GetLogConfigResponse;
    set_log_config, "SetLogConfig", SetLogConfigRequest, SetLogConfigResponse;
    get_acl, "GetAcl", GetAclRequest, GetAclResponse;
    get_acl_stats, "GetAclStats", GetAclStatsRequest, GetAclStatsResponse;
    list_credentials, "ListCredentials", ListCredentialsRequest, ListCredentialsResponse;
    issue_credential, "IssueCredential", IssueCredentialRequest, IssueCredentialResponse;
    revoke_credential, "RevokeCredential", RevokeCredentialRequest, RevokeCredentialResponse;
    create_join_code, "CreateJoinCode", CreateJoinCodeRequest, CreateJoinCodeResponse;
    list_port_forwards, "ListPortForwards", ListPortForwardsRequest, ListPortForwardsResponse;
    watch_changes, "WatchChanges", WatchChangesRequest, WatchChangesResponse;
    get_config, "GetConfig", GetConfigRequest, GetConfigResponse;
    validate_config, "ValidateConfig", ValidateConfigRequest, ValidateConfigResponse;
    patch_config, "PatchConfig", PatchConfigRequest, PatchConfigResponse;
    get_relay, "GetRelay", GetRelayRequest, GetRelayResponse;
    get_camouflage, "GetCamouflage", GetCamouflageRequest, GetCamouflageResponse;
    create_instance, "CreateInstance", CreateInstanceRequest, CreateInstanceResponse;
    start_instance, "StartInstance", StartInstanceRequest, StartInstanceResponse;
    stop_instance, "StopInstance", StopInstanceRequest, StopInstanceResponse;
    delete_instance, "DeleteInstance", DeleteInstanceRequest, DeleteInstanceResponse;
    set_acl, "SetAcl", SetAclRequest, SetAclResponse;
    put_port_forward, "PutPortForward", PutPortForwardRequest, PutPortForwardResponse;
    delete_port_forward, "DeletePortForward", DeletePortForwardRequest, DeletePortForwardResponse;
    call_remote, "CallRemote", CallRemoteRequest, CallRemoteResponse;
}

async fn ssh_call(
    client: &Client,
    target: &str,
    secret: &str,
    session: &str,
    method: &str,
    payload: Value,
    keep: bool,
) -> Result<(Value, String)> {
    let response = client
        .rpc
        .call_remote(
            client.controller(),
            CallRemoteRequest {
                meta: client.meta(),
                target: target.into(),
                secret: secret.into(),
                session_id: session.into(),
                method: method.into(),
                payload: serde_json::to_vec(&payload).unwrap(),
                keep_session: keep,
            },
        )
        .await?;
    if let Some(error) = response.error {
        return Err(error.into());
    }
    let value: Value = serde_json::from_slice(&response.payload)
        .map_err(|_| CliError::new("internal", "Invalid SSH response.", ""))?;
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let error: ApiError = serde_json::from_value(error.clone())
            .map_err(|_| CliError::new("internal", "Invalid SSH error.", ""))?;
        return Err(error.into());
    }
    Ok((value, response.session_id))
}

pub(super) async fn ssh(
    args: &Arguments,
    request_id: &str,
    target: &str,
    tty: bool,
    command: &[String],
) -> Result<u8> {
    let tty = tty || (command.is_empty() && std::io::IsTerminal::is_terminal(&std::io::stdin()));
    if args.remote.is_some() {
        return Err(CliError::new(
            "invalid_argument",
            "Use user@node as the SSH target instead of --remote.",
            "remote",
        ));
    }
    let (user, target) = target.split_once('@').ok_or_else(|| {
        CliError::new(
            "invalid_argument",
            "Use an existing account and node: user@node.",
            "target",
        )
    })?;
    let client = Client::connect(args, request_id.into()).await?;
    let secret = read_secret(args)?;
    let (opened, session) = ssh_call(
        &client,
        target,
        &secret,
        "",
        "SshOpen",
        json!({"user": user}),
        true,
    )
    .await?;
    let host_key = opened["host_key"]
        .as_str()
        .ok_or_else(|| CliError::new("internal", "The SSH host key is absent.", ""))?;
    let (stream, bridge) = tokio::io::duplex(128 * 1024);
    let io = async {
        let (mut input, mut output) = tokio::io::split(bridge);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let _reader = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let mut bytes = vec![0; 16384];
                let count = match input.read(&mut bytes).await {
                    Ok(count) => count,
                    Err(_) => 0,
                };
                bytes.truncate(count);
                if sender.send(bytes).await.is_err() || count == 0 {
                    return;
                }
            }
        }));
        let mut eof = false;
        loop {
            let bytes = match receiver.try_recv() {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        eof = true;
                    }
                    bytes
                }
                Err(_) => Vec::new(),
            };
            let (value, _) = ssh_call(
                &client,
                target,
                "",
                &session,
                "SshIo",
                json!({"data": BASE64_STANDARD.encode(bytes), "eof": eof}),
                true,
            )
            .await?;
            let bytes = BASE64_STANDARD
                .decode(value["data"].as_str().unwrap_or(""))
                .map_err(|_| CliError::new("internal", "Invalid SSH data.", ""))?;
            output.write_all(&bytes).await.map_err(|_| {
                CliError::new("unavailable", "The local SSH connection closed.", "")
            })?;
            if value["eof"] == true {
                output.shutdown().await.ok();
                break;
            }
        }
        Ok::<(), CliError>(())
    };
    let run = async {
        #[cfg(unix)]
        {
            terminal::run(stream, host_key, user, tty, command)
                .await
                .map_err(|_| {
                    CliError::new("unavailable", "The authenticated SSH stream failed.", "ssh")
                })
        }
        #[cfg(not(unix))]
        {
            let _ = (stream, host_key, user, tty, command);
            Err(CliError::new(
                "unavailable",
                "SSH requires a Unix client.",
                "ssh",
            ))
        }
    };
    tokio::pin!(io, run);
    let result = tokio::select! {
        result = &mut run => {
            // Finish the current exchange before closing its serialized control session.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut io).await;
            result
        },
        result = &mut io => match result { Err(error) => Err(error), Ok(()) => run.await },
    };
    let _ = ssh_call(&client, target, "", &session, "SshClose", json!({}), false).await;
    result
}
