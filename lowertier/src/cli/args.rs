use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{ffi::OsString, net::SocketAddr, path::PathBuf};

#[derive(Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Output {
    #[default]
    Table,
    Json,
}

#[derive(Parser)]
#[command(name = "lowertier-cli", version = crate::VERSION, about = "Manage LowTier through Control API v1")]
pub struct Arguments {
    #[arg(short = 'p', long, global = true, default_value = "127.0.0.1:15888")]
    pub rpc_portal: SocketAddr,
    /// Select one instance ID. A sole instance is selected automatically.
    #[arg(short = 'i', long, global = true)]
    pub instance: Option<String>,
    #[arg(
        long,
        global = true,
        env = "LOWTIER_CONTROL_TOKEN",
        hide_env_values = true
    )]
    pub control_token: Option<String>,
    #[arg(long, global = true, env = "LOWTIER_CONTROL_TOKEN_FILE")]
    pub control_token_file: Option<PathBuf>,
    /// Supply the network administrator token for credential commands.
    #[arg(
        long,
        global = true,
        env = "LOWTIER_ADMIN_TOKEN",
        hide_env_values = true
    )]
    pub admin_token: Option<String>,
    #[arg(short = 'o', long, global = true, value_enum, default_value = "table")]
    pub output: Output,
    /// Increase diagnostics on stderr.
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    Relay {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    L2 {
        #[command(subcommand)]
        command: L2Command,
    },
    Discovery {
        #[command(subcommand)]
        command: DiscoveryCommand,
    },
    Listener {
        #[command(subcommand)]
        command: ListenerCommand,
    },
    Camouflage {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Stats {
        #[command(subcommand)]
        command: StatsCommand,
    },
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    Acl {
        #[command(subcommand)]
        command: AclCommand,
    },
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    PortForward {
        #[command(subcommand)]
        command: PortForwardCommand,
    },
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    Service(ServiceArgs),
    /// Generate local shell completion scripts.
    Completion {
        #[arg(value_enum)]
        shell: crate::ShellType,
    },
}
impl Command {
    pub fn process_resource(&self) -> bool {
        matches!(
            self,
            Self::Instance {
                command: InstanceCommand::List | InstanceCommand::Create { .. }
            } | Self::Log { .. }
        )
    }
}

#[derive(Subcommand)]
pub enum NodeCommand {
    Show,
}
#[derive(Subcommand)]
pub enum PeerCommand {
    List(PageArgs),
    /// Find a peer by numeric ID or base64 public key.
    Show {
        peer: String,
    },
    Add {
        uri: String,
        #[arg(long)]
        public_key: Option<String>,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Remove a configured peer URI.
    Remove {
        uri: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}
#[derive(Subcommand)]
pub enum RouteCommand {
    List {
        #[arg(long)]
        path: bool,
        #[command(flatten)]
        page: PageArgs,
    },
    Show {
        destination: String,
        #[arg(long)]
        path: bool,
    },
}
#[derive(Subcommand)]
pub enum SettingsCommand {
    Show,
    Set(PatchArgs),
}
#[derive(Subcommand)]
pub enum L2Command {
    Fdb(PageArgs),
    Stats,
}
#[derive(Subcommand)]
pub enum DiscoveryCommand {
    Status,
}
#[derive(Subcommand)]
pub enum ListenerCommand {
    List,
    Add {
        uri: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Remove a configured listener URI or reported listener ID.
    Remove {
        listener: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}
#[derive(Subcommand)]
pub enum ConfigCommand {
    Get,
    Set(PatchArgs),
    Validate(PatchArgs),
}
#[derive(Subcommand)]
pub enum StatsCommand {
    Show {
        #[arg(long)]
        prometheus: bool,
    },
    Watch {
        #[arg(long)]
        prometheus: bool,
    },
}
#[derive(Subcommand)]
pub enum LogCommand {
    Read(PageArgs),
    Follow(PageArgs),
    /// Show or set the log level.
    Level {
        #[arg(value_parser = ["off", "error", "warn", "info", "debug", "trace"])]
        level: Option<String>,
    },
}
#[derive(Subcommand)]
pub enum AclCommand {
    Get,
    /// Read JSON with acl, tcp_whitelist, and udp_whitelist fields.
    Set {
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    Stats,
}
#[derive(Subcommand)]
pub enum CredentialCommand {
    List(PageArgs),
    Issue {
        #[arg(long, default_value_t = 3600)]
        ttl: i64,
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        #[arg(long)]
        allow_relay: bool,
        #[arg(long, value_delimiter = ',')]
        allowed_proxy_cidrs: Vec<String>,
        #[arg(long)]
        credential_id: Option<String>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        reusable: bool,
    },
    Revoke {
        credential_id: String,
    },
}
#[derive(Subcommand)]
pub enum PortForwardCommand {
    List,
    Add {
        #[arg(value_parser = ["tcp", "udp"])]
        protocol: String,
        bind_addr: String,
        dst_addr: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    Remove {
        #[arg(value_parser = ["tcp", "udp"])]
        protocol: String,
        bind_addr: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}
#[derive(Subcommand)]
pub enum InstanceCommand {
    List,
    /// Create a stopped instance from NodeConfig JSON.
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    Start,
    Stop,
    /// Delete a stopped instance.
    Delete,
}

#[derive(Args, Default)]
pub struct PageArgs {
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub limit: u32,
    #[arg(long, default_value = "")]
    pub page_token: String,
}
impl PageArgs {
    pub fn page(&self) -> Option<crate::proto::api::control::v1::Page> {
        Some(crate::proto::api::control::v1::Page {
            limit: self.limit,
            page_token: self.page_token.clone(),
        })
    }
}
#[derive(Args, Default)]
pub struct ApplyArgs {
    /// Require this revision. Otherwise use the revision read before the change.
    #[arg(long)]
    pub expected_revision: Option<u64>,
    /// Write the desired configuration to its existing file.
    #[arg(long)]
    pub persist: bool,
    /// Store restart fields without changing their active values.
    #[arg(long)]
    pub stage: bool,
}
#[derive(Args)]
pub struct PatchArgs {
    /// Set PATH=JSON. Unquoted string values are accepted.
    #[arg(value_name = "PATH=JSON")]
    pub assignments: Vec<String>,
    /// Read NodeConfig JSON values from a file.
    #[arg(long)]
    pub values: Option<PathBuf>,
    /// Select fields from --values. Arrays replace completely.
    #[arg(long, value_delimiter = ',')]
    pub field: Vec<String>,
    /// Remove optional fields.
    #[arg(long, value_delimiter = ',')]
    pub clear: Vec<String>,
    #[command(flatten)]
    pub apply: ApplyArgs,
}
#[derive(Args)]
pub struct ServiceArgs {
    #[arg(short, long, default_value = "lowertier")]
    pub name: String,
    #[command(subcommand)]
    pub command: ServiceCommand,
}
#[derive(Subcommand)]
pub enum ServiceCommand {
    Install(InstallArgs),
    Uninstall,
    Status,
    Start,
    Stop,
}
#[derive(Args)]
pub struct InstallArgs {
    #[arg(long, default_value = env!("CARGO_PKG_DESCRIPTION"))]
    pub description: String,
    #[arg(long)]
    pub display_name: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub disable_autostart: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub disable_restart_on_failure: Option<bool>,
    #[arg(long)]
    pub core_path: Option<PathBuf>,
    #[arg(long)]
    pub service_work_dir: Option<PathBuf>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub core_args: Vec<OsString>,
}
