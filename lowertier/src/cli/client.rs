use super::{
    args::Arguments,
    error::{CliError, Result},
};
use crate::{
    common::runtime_registry::{self, Selection},
    proto::{
        api::control::v1::*, rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    rpc_service::control::ControlToken,
    tunnel::tcp::TcpTunnelConnector,
};
use std::{path::PathBuf, time::Duration};

macro_rules! responses {
    ($($name:ident),+ $(,)?) => {
        #[derive(serde::Serialize)] #[serde(untagged)]
        pub enum Response {
            $($name($name),)+
            Peers(PeerView),
            Status(Box<super::commands::status::StatusView>),
            Doctor(super::commands::doctor::Report),
            Config(super::commands::config::ConfigView),
            Trace(super::commands::route::Trace),
            Nodes { nodes: Vec<runtime_registry::Record> },
            Service { name: String, status: String },
            Text { text: String },
        }
        impl Response {
            pub fn api_error(&self) -> Option<&ApiError> {
                match self {
                    $(Self::$name(value) => value.error.as_ref(),)+
                    _ => None,
                }
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
    /// Render one peer as a detail block (`peers show`).
    #[serde(skip)]
    pub detail: bool,
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

/// The daemon a command talks to.
pub struct Target {
    pub portal: String,
    pub token_file: PathBuf,
    pub name: Option<String>,
}

fn names(records: &[runtime_registry::Record]) -> String {
    records
        .iter()
        .map(|record| format!("{} (pid {}, {})", record.name, record.pid, record.portal))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Choose the portal and token file: --portal, then --node, then the only running daemon.
pub fn target(args: &Arguments) -> Result<Target> {
    let records = runtime_registry::live_records();
    let default_token = || {
        ControlToken::default_path(None).map_err(|_| {
            CliError::new(
                "permission_denied",
                "Cannot find the control token file. Pass --token-file.",
                "token_file",
            )
        })
    };
    if let Some(portal) = &args.portal {
        let record = records.iter().find(|record| record.portal == *portal);
        return Ok(Target {
            portal: portal.clone(),
            token_file: match (&args.token_file, record) {
                (Some(path), _) => path.clone(),
                (None, Some(record)) => record.token_file.clone(),
                (None, None) => default_token()?,
            },
            name: record.map(|record| record.name.clone()),
        });
    }
    match runtime_registry::select(records.clone(), args.node.as_deref()) {
        Selection::Found(record) => Ok(Target {
            portal: record.portal,
            token_file: args.token_file.clone().unwrap_or(record.token_file),
            name: Some(record.name),
        }),
        Selection::None => Ok(Target {
            portal: "127.0.0.1:15888".into(),
            token_file: match &args.token_file {
                Some(path) => path.clone(),
                None => default_token()?,
            },
            name: None,
        }),
        Selection::Ambiguous(records) => Err(CliError::new(
            "ambiguous",
            format!(
                "Several daemons are running: {}. Choose one with --node.",
                names(&records)
            ),
            "node",
        )),
        Selection::Missing(name) => Err(CliError::new(
            "not_found",
            if records.is_empty() {
                format!("No daemon named {name:?} is running, and no other daemon is running.")
            } else {
                format!(
                    "No daemon named {name:?} is running. Running: {}.",
                    names(&records)
                )
            },
            "node",
        )),
    }
}

#[cfg(unix)]
fn owner(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(path).ok()?.uid();
    nix::unistd::User::from_uid(uid.into())
        .ok()
        .flatten()
        .map(|user| user.name)
}

#[cfg(not(unix))]
fn owner(_: &std::path::Path) -> Option<String> {
    None
}

/// Read the control token and explain how to fix the common failures.
pub fn read_token(path: &std::path::Path) -> Result<String> {
    let token = std::fs::read_to_string(path).map_err(|error| {
        let shown = path.display();
        let message = match error.kind() {
            std::io::ErrorKind::NotFound => format!(
                "The control token {shown} does not exist. Start the daemon with `lowertier run`, \
                 or pass --token-file."
            ),
            std::io::ErrorKind::PermissionDenied => {
                let by = owner(path).map_or(String::new(), |user| format!(" (owned by {user})"));
                format!(
                    "Cannot read the control token {shown}{by}. Run the command with sudo, or set \
                     control.token_group to a group you belong to and restart the daemon."
                )
            }
            _ => format!("Cannot read the control token {shown}: {error}."),
        };
        CliError::new("permission_denied", message, "token_file")
    })?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(CliError::new(
            "permission_denied",
            format!("The control token {} is empty.", path.display()),
            "token_file",
        ));
    }
    Ok(token)
}

type Rpc = Box<dyn ControlPlaneV1Rpc<Controller = BaseController> + Send + Sync>;

async fn dial(portal: &str) -> Result<(StandAloneClient<TcpTunnelConnector>, Rpc)> {
    let unreachable = || {
        CliError::new(
            "unavailable",
            format!(
                "Cannot reach the daemon at {portal}. Is it running? `lowertier nodes` lists running daemons."
            ),
            "portal",
        )
    };
    let connector = TcpTunnelConnector::new(format!("tcp://{portal}").parse().map_err(|_| {
        CliError::new(
            "invalid_argument",
            format!("The portal address {portal:?} is invalid."),
            "portal",
        )
    })?);
    let mut transport = StandAloneClient::new(connector);
    let rpc = tokio::time::timeout(
        Duration::from_secs(10),
        transport.scoped_client::<ControlPlaneV1RpcClientFactory<BaseController>>(String::new()),
    )
    .await
    .map_err(|_| unreachable())?
    .map_err(|_| unreachable())?;
    Ok((transport, rpc))
}

pub struct Client {
    pub rpc: Rpc,
    pub meta: RequestMeta,
    pub target: Target,
    /// Name of the selected instance. A restarted daemon may give it a new ID.
    pub instance_name: Option<String>,
    // Keep the RPC manager alive for all requests and long polls.
    _transport: StandAloneClient<TcpTunnelConnector>,
}

impl Client {
    pub async fn connect(args: &Arguments, request_id: String) -> Result<Self> {
        let mut client = Self::open(args, target(args)?, request_id).await?;
        if !args.command.process_resource() {
            let (id, name) = client.select_instance(args.instance.as_deref()).await?;
            client.meta.instance_id = id;
            client.instance_name = Some(name);
        }
        Ok(client)
    }

    /// Connect to a daemon without selecting an instance.
    pub async fn open(args: &Arguments, target: Target, request_id: String) -> Result<Self> {
        let token = match &args.token {
            Some(token) => token.clone(),
            None => read_token(&target.token_file)?,
        };
        let (transport, rpc) = dial(&target.portal).await?;
        Ok(Self {
            rpc,
            meta: RequestMeta {
                instance_id: String::new(),
                control_token: token,
                admin_token: args.admin_token.clone().unwrap_or_default(),
                request_id,
            },
            target,
            instance_name: None,
            _transport: transport,
        })
    }

    /// Open a new connection to the same daemon and instance.
    pub async fn reconnect(&self) -> Result<Self> {
        let (transport, rpc) = dial(&self.target.portal).await?;
        let mut client = Self {
            rpc,
            meta: self.meta.clone(),
            target: Target {
                portal: self.target.portal.clone(),
                token_file: self.target.token_file.clone(),
                name: self.target.name.clone(),
            },
            instance_name: self.instance_name.clone(),
            _transport: transport,
        };
        if let Some(name) = &self.instance_name {
            client.meta.instance_id = client.select_instance(Some(name)).await?.0;
        }
        Ok(client)
    }

    /// Resolve an instance by ID or name, or pick the only one. Returns its ID and name.
    pub async fn select_instance(&self, wanted: Option<&str>) -> Result<(String, String)> {
        let list = self
            .rpc
            .list_instances(
                self.controller(),
                ListInstancesRequest { meta: self.meta() },
            )
            .await
            .map_err(|error| match CliError::from(error) {
                error if error.0.code == "unavailable" => CliError::new(
                    "unavailable",
                    format!(
                        "The daemon at {} closed the connection.",
                        self.target.portal
                    ),
                    "portal",
                ),
                error => error,
            })?;
        if let Some(error) = list.error {
            return Err(error.into());
        }
        let all = || {
            list.instances
                .iter()
                .map(|instance| instance.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match wanted {
            Some(wanted) => list
                .instances
                .iter()
                .find(|instance| instance.instance_id == wanted || instance.name == wanted)
                .map(|instance| (instance.instance_id.clone(), instance.name.clone()))
                .ok_or_else(|| {
                    CliError::new(
                        "not_found",
                        format!("No instance {wanted:?}. Instances: {}.", all()),
                        "instance",
                    )
                }),
            None => match list.instances.as_slice() {
                [instance] => Ok((instance.instance_id.clone(), instance.name.clone())),
                [] => Err(CliError::new(
                    "not_found",
                    "The daemon runs no instance. Create one with `lowertier instance create FILE`.",
                    "instance",
                )),
                _ => Err(CliError::new(
                    "ambiguous",
                    format!(
                        "Several instances run: {}. Choose one with --instance.",
                        all()
                    ),
                    "instance",
                )),
            },
        }
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
