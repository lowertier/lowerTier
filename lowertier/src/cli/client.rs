use super::{
    args::Arguments,
    error::{CliError, Result},
};
use crate::{
    proto::{
        api::control::v1::*, rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    rpc_service::control::ControlToken,
    tunnel::tcp::TcpTunnelConnector,
};
use std::time::Duration;

macro_rules! responses {
    ($($name:ident),+ $(,)?) => {
        #[derive(serde::Serialize)] #[serde(untagged)]
        pub enum Response { $($name($name),)+ Peers(PeerView), Service { name: String, status: String } }
        impl Response {
            pub fn api_error(&self) -> Option<&ApiError> {
                match self { $(Self::$name(value) => value.error.as_ref(),)+ Self::Peers(_) | Self::Service { .. } => None }
            }
        }
        $(impl From<$name> for Response { fn from(value: $name) -> Self { Self::$name(value) } })+
    };
}
#[derive(serde::Serialize)]
pub struct PeerView {
    pub snapshot: Option<SnapshotMeta>,
    pub peers: Vec<PeerSnapshot>,
    pub route_summaries: Vec<RouteSnapshot>,
    pub active_policy: String,
    pub next_page_token: String,
}
responses!(
    ListInstancesResponse,
    GetNodeResponse,
    ListRoutesResponse,
    GetRelayResponse,
    GetL2Response,
    GetDiscoveryResponse,
    ListListenersResponse,
    GetCamouflageResponse,
    GetConfigResponse,
    ValidateConfigResponse,
    PatchConfigResponse,
    GetStatsResponse,
    GetPrometheusResponse,
    ReadLogsResponse,
    GetLogConfigResponse,
    SetLogConfigResponse,
    GetAclResponse,
    SetAclResponse,
    GetAclStatsResponse,
    ListCredentialsResponse,
    IssueCredentialResponse,
    RevokeCredentialResponse,
    ListPortForwardsResponse,
    PutPortForwardResponse,
    DeletePortForwardResponse,
    CreateInstanceResponse,
    StartInstanceResponse,
    StopInstanceResponse,
    DeleteInstanceResponse
);

pub fn checked<T: Into<Response>>(response: T) -> Result<Response> {
    let response = response.into();
    if let Some(error) = response.api_error() {
        return Err(error.clone().into());
    }
    let apply = match &response {
        Response::PatchConfigResponse(value) => value.result.as_ref(),
        Response::ValidateConfigResponse(value) => value.result.as_ref(),
        Response::SetAclResponse(value) => value.result.as_ref(),
        Response::PutPortForwardResponse(value) => value.result.as_ref(),
        Response::DeletePortForwardResponse(value) => value.result.as_ref(),
        Response::CreateInstanceResponse(value) => value.result.as_ref(),
        Response::StartInstanceResponse(value) => value.result.as_ref(),
        _ => None,
    };
    if let Some(result) = apply.filter(|result| !result.errors.is_empty()) {
        return Err(CliError::new(
            "partial_failure",
            result
                .errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            "result.errors",
        ));
    }
    Ok(response)
}
pub struct Client {
    pub rpc: Box<dyn ControlPlaneV1Rpc<Controller = BaseController> + Send + Sync>,
    pub meta: RequestMeta,
    // Keep the RPC manager alive for all requests and long polls.
    _transport: StandAloneClient<TcpTunnelConnector>,
}
impl Client {
    pub async fn connect(args: &Arguments, request_id: String) -> Result<Self> {
        let token = match &args.control_token {
            Some(token) => token.clone(),
            None => {
                let path = match &args.control_token_file {
                    Some(path) => path.clone(),
                    None => ControlToken::default_path(None).map_err(|_| {
                        CliError::new(
                            "permission_denied",
                            "Cannot find the control token file.",
                            "control_token_file",
                        )
                    })?,
                };
                std::fs::read_to_string(path)
                    .map_err(|_| {
                        CliError::new(
                            "permission_denied",
                            "Cannot read the control token file.",
                            "control_token_file",
                        )
                    })?
                    .trim()
                    .to_owned()
            }
        };
        if token.is_empty() {
            return Err(CliError::new(
                "permission_denied",
                "The control token is empty.",
                "control_token",
            ));
        }
        let connector = TcpTunnelConnector::new(
            format!("tcp://{}", args.rpc_portal).parse().map_err(|_| {
                CliError::new(
                    "invalid_argument",
                    "The RPC portal address is invalid.",
                    "rpc_portal",
                )
            })?,
        );
        let mut transport = StandAloneClient::new(connector);
        let rpc = tokio::time::timeout(
            Duration::from_secs(30),
            transport
                .scoped_client::<ControlPlaneV1RpcClientFactory<BaseController>>(String::new()),
        )
        .await
        .map_err(|_| {
            CliError::new(
                "deadline_exceeded",
                "The control connection exceeded its deadline.",
                "rpc_portal",
            )
        })?
        .map_err(|_| {
            CliError::new(
                "unavailable",
                "Cannot connect to the control portal.",
                "rpc_portal",
            )
        })?;
        let mut client = Self {
            rpc,
            meta: RequestMeta {
                instance_id: args.instance.clone().unwrap_or_default(),
                control_token: token,
                admin_token: args.admin_token.clone().unwrap_or_default(),
                request_id,
            },
            _transport: transport,
        };
        if !args.command.process_resource() {
            let list = client
                .rpc
                .list_instances(
                    client.controller(),
                    ListInstancesRequest {
                        meta: client.meta(),
                    },
                )
                .await?;
            if let Some(error) = list.error {
                return Err(error.into());
            }
            if client.meta.instance_id.is_empty() {
                client.meta.instance_id = match list.instances.as_slice() {
                    [instance] => instance.instance_id.clone(),
                    [] => {
                        return Err(CliError::new(
                            "not_found",
                            "No instance exists.",
                            "instance",
                        ));
                    }
                    _ => {
                        return Err(CliError::new(
                            "ambiguous",
                            "Specify --instance when more than one instance exists.",
                            "instance",
                        ));
                    }
                };
            } else if !list
                .instances
                .iter()
                .any(|instance| instance.instance_id == client.meta.instance_id)
            {
                return Err(CliError::new(
                    "not_found",
                    "The selected instance does not exist.",
                    "instance",
                ));
            }
        } else {
            client.meta.instance_id.clear();
        }
        Ok(client)
    }
    pub fn controller(&self) -> BaseController {
        BaseController {
            timeout_ms: 30_000,
            ..Default::default()
        }
    }
    pub fn meta(&self) -> Option<RequestMeta> {
        Some(self.meta.clone())
    }
    pub async fn config(&self) -> Result<GetConfigResponse> {
        let value = self
            .rpc
            .get_config(self.controller(), GetConfigRequest { meta: self.meta() })
            .await?;
        if let Some(error) = &value.error {
            return Err(error.clone().into());
        }
        Ok(value)
    }
    pub async fn revision(&self, expected: Option<u64>) -> Result<u64> {
        if let Some(revision) = expected {
            return Ok(revision);
        }
        self.config()
            .await?
            .snapshot
            .map(|snapshot| snapshot.revision)
            .ok_or_else(|| {
                CliError::new(
                    "internal",
                    "The configuration revision is absent.",
                    "snapshot",
                )
            })
    }
}
