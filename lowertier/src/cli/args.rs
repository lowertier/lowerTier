use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Output {
    #[default]
    Table,
    Json,
}

const GLOBAL: &str = "Global options";

#[derive(Parser)]
#[command(
    name = "lowertier",
    version = crate::VERSION,
    about = "LowTier: a peer-to-peer VPN through layers of unknown NAT.",
    after_help = "Start with `lowertier init`, then `lowertier run -c lowertier.toml`.\n\
                  `lowertier config explain` lists every configuration option."
)]
pub struct Arguments {
    /// Daemon to manage, by name or PID (see `lowertier nodes`).
    #[arg(short = 'n', long, global = true, help_heading = GLOBAL)]
    pub node: Option<String>,
    /// Management portal address. Overrides --node.
    #[arg(short = 'p', long, global = true, help_heading = GLOBAL)]
    pub portal: Option<String>,
    /// Instance ID or name when a daemon runs more than one.
    #[arg(short = 'i', long, global = true, help_heading = GLOBAL)]
    pub instance: Option<String>,
    /// Control token file. Defaults to the daemon's token file.
    #[arg(long, global = true, env = "LOWTIER_CONTROL_TOKEN_FILE", help_heading = GLOBAL)]
    pub token_file: Option<PathBuf>,
    #[arg(long, global = true, env = "LOWTIER_CONTROL_TOKEN", hide = true)]
    pub token: Option<String>,
    /// Network administrator token for credential commands.
    #[arg(
        long,
        global = true,
        env = "LOWTIER_ADMIN_TOKEN",
        hide_env_values = true,
        help_heading = GLOBAL
    )]
    pub admin_token: Option<String>,
    /// Output format.
    #[arg(short = 'o', long, global = true, value_enum, default_value = "table", help_heading = GLOBAL)]
    pub output: Output,
    /// Print diagnostics on stderr.
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count, help_heading = GLOBAL)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Write a new node configuration with a generated secret and key.
    Init(InitArgs),
    /// Run a node in the foreground.
    Run(RunArgs),
    /// Validate configuration files without starting a node.
    Check(CheckArgs),
    /// List daemons running on this machine.
    Nodes,

    /// Show node, addresses, NAT, listeners, and peers on one screen.
    Status,
    /// Diagnose common problems and print a fix for each.
    Doctor,
    /// Live terminal dashboard.
    Top(TopArgs),

    /// Show configuration values: active, and desired when they differ.
    Get {
        /// Option path or section, for example relay or tun.mtu.
        path: Option<String>,
    },
    /// Change configuration values in one transaction.
    Set(SetArgs),
    /// Remove configuration values so defaults apply.
    Unset {
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<String>,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Edit the configuration in $EDITOR and apply the changes.
    Edit {
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Configuration reference.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// List peers, or show, add, or remove one.
    Peers {
        #[command(subcommand)]
        command: Option<PeerCommand>,
    },
    /// List routes, or trace the path to one destination.
    Routes {
        #[command(subcommand)]
        command: Option<RouteCommand>,
    },
    /// Relay policy, transit permission, traffic, and drops.
    Relay,
    /// TLS camouflage settings and certificate verification.
    Camouflage,
    /// Tracker discovery and NAT mapping observations.
    Discovery,
    /// List listeners, or add or remove one.
    Listeners {
        #[command(subcommand)]
        command: Option<ListenerCommand>,
    },
    /// Layer 2 forwarding database and counters.
    L2 {
        #[command(subcommand)]
        command: Option<L2Command>,
    },
    /// Show or replace access control rules.
    Acl {
        #[command(subcommand)]
        command: Option<AclCommand>,
    },
    /// Issue, list, and revoke network credentials.
    Creds {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// List port forwards, or add or remove one.
    Forward {
        #[command(subcommand)]
        command: Option<ForwardCommand>,
    },
    /// Manage instances inside one daemon.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    /// Show metrics.
    Stats {
        /// Print Prometheus text.
        #[arg(long)]
        prometheus: bool,
        /// Print again whenever metrics change.
        #[arg(short, long)]
        watch: bool,
    },
    /// Show recent log lines.
    Logs {
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show or change the daemon log level.
    LogLevel {
        #[arg(value_parser = ["off", "error", "warn", "info", "debug", "trace"])]
        level: Option<String>,
    },
    /// Install and control the system service.
    Service(ServiceArgs),
    /// Print a shell completion script.
    Completion {
        #[arg(value_enum)]
        shell: crate::ShellType,
    },
}

impl Command {
    /// Commands that run without a daemon connection.
    pub fn local(&self) -> bool {
        matches!(
            self,
            Self::Init(_)
                | Self::Run(_)
                | Self::Check(_)
                | Self::Nodes
                | Self::Config { .. }
                | Self::Service(_)
                | Self::Completion { .. }
        )
    }

    /// Commands that address the daemon process instead of one instance.
    pub fn process_resource(&self) -> bool {
        matches!(
            self,
            Self::Instance {
                command: InstanceCommand::List | InstanceCommand::Create { .. }
            } | Self::Logs { .. }
                | Self::LogLevel { .. }
        )
    }
}

#[derive(Args)]
pub struct InitArgs {
    /// Configuration file to write. The secret and key files go next to it.
    #[arg(default_value = "lowertier.toml")]
    pub file: PathBuf,
    /// Network name.
    #[arg(long, default_value = "default")]
    pub network: String,
    /// Base listener port: H2 on TCP PORT, QUIC on UDP PORT+2, WSS on TCP PORT+2.
    #[arg(long)]
    pub listen: Option<u16>,
    /// Peer URI to connect to, for example quic://203.0.113.7:11012.
    #[arg(long = "peer")]
    pub peers: Vec<String>,
    /// Interface mode.
    #[arg(long, value_parser = ["kernel", "userspace", "none"])]
    pub tun: Option<String>,
    /// Static virtual IPv4 address with prefix. DHCP is used otherwise.
    #[arg(long)]
    pub ipv4: Option<String>,
    /// Replace existing files.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RunArgs {
    /// Configuration file. Repeat for several instances. Env: LOWTIER_CONFIG.
    #[arg(short = 'c', long = "config")]
    pub config: Vec<PathBuf>,
    /// Run every *.toml file in this directory.
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Override an option, for example --set relay.policy=latency.
    #[arg(long = "set", value_name = "PATH=VALUE")]
    pub sets: Vec<String>,
    /// Keep running without instances, for management through the portal.
    #[arg(long)]
    pub daemon: bool,
    /// Console log level. Overrides log.console.
    #[arg(long, value_parser = ["off", "error", "warn", "info", "debug", "trace"])]
    pub log_level: Option<String>,
}

#[derive(Args)]
pub struct CheckArgs {
    /// Configuration file. Use - for stdin. Env: LOWTIER_CONFIG.
    #[arg(short = 'c', long = "config")]
    pub config: Vec<PathBuf>,
    /// Override an option before validation.
    #[arg(long = "set", value_name = "PATH=VALUE")]
    pub sets: Vec<String>,
}

#[derive(Args)]
pub struct TopArgs {
    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(200..=60_000))]
    pub interval: u64,
}

#[derive(Args)]
pub struct SetArgs {
    /// PATH=VALUE pairs, for example relay.policy=latency tun.mtu=1280.
    #[arg(required = true, value_name = "PATH=VALUE")]
    pub assignments: Vec<String>,
    #[command(flatten)]
    pub apply: ApplyArgs,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Describe options: type, default, units, and when changes apply.
    Explain {
        /// Option path or section prefix. Lists every option when omitted.
        path: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PeerCommand {
    /// List peers with connection quality.
    List(PageArgs),
    /// Show one peer by ID, public key, or host name.
    Show { peer: String },
    /// Add a configured peer URI.
    Add {
        uri: String,
        /// Pin the peer's base64 public key.
        #[arg(long)]
        public_key: Option<String>,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Remove a configured peer URI.
    Rm {
        uri: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}

#[derive(Subcommand)]
pub enum RouteCommand {
    /// List routes.
    List {
        /// Include complete paths.
        #[arg(long)]
        path: bool,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show the selected path to a destination hop by hop.
    Trace {
        /// Destination prefix, address, peer ID, or host name.
        destination: String,
    },
}

#[derive(Subcommand)]
pub enum L2Command {
    /// Forwarding database entries.
    Fdb(PageArgs),
    /// Flood, loop, and policy drop counters.
    Stats,
}

#[derive(Subcommand)]
pub enum ListenerCommand {
    /// List active listeners.
    List,
    /// Add a listener URI, for example quic://0.0.0.0:11012.
    Add {
        uri: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Remove a configured listener URI or listener ID.
    Rm {
        listener: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}

#[derive(Subcommand)]
pub enum AclCommand {
    /// Show rules.
    Show,
    /// Show rule hit counters.
    Stats,
    /// Replace rules from a JSON file with acl, tcp_whitelist, and udp_whitelist fields.
    Set {
        file: PathBuf,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}

#[derive(Subcommand)]
pub enum CredentialCommand {
    /// List issued credentials.
    List(PageArgs),
    /// Issue a credential.
    Issue {
        /// Lifetime in seconds.
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
    /// Revoke a credential.
    Revoke { credential_id: String },
}

#[derive(Subcommand)]
pub enum ForwardCommand {
    /// List port forwards.
    List,
    /// Forward a local port to an address inside the network.
    Add {
        #[arg(value_parser = ["tcp", "udp"])]
        proto: String,
        /// Local address, for example 127.0.0.1:8080.
        bind: String,
        /// Destination, for example 10.126.126.2:80.
        dest: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
    /// Remove a port forward.
    Rm {
        #[arg(value_parser = ["tcp", "udp"])]
        proto: String,
        bind: String,
        #[command(flatten)]
        apply: ApplyArgs,
    },
}

#[derive(Subcommand)]
pub enum InstanceCommand {
    /// List instances in the daemon.
    List,
    /// Create a stopped instance from a configuration file.
    Create { file: PathBuf },
    /// Start the selected instance.
    Start,
    /// Stop the selected instance.
    Stop,
    /// Delete a stopped instance.
    Delete,
}

#[derive(Args, Default)]
pub struct PageArgs {
    /// Entries per page.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub limit: u32,
    /// Continue from a previous page.
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
    /// Fail unless the configuration is at this revision.
    #[arg(long)]
    pub expected_revision: Option<u64>,
    /// Change the running node only; leave the configuration file unchanged.
    #[arg(long)]
    pub no_persist: bool,
    /// Store changes that need a restart without applying them now.
    #[arg(long)]
    pub stage: bool,
}

#[derive(Args)]
pub struct ServiceArgs {
    /// Service name.
    #[arg(long, default_value = "lowertier")]
    pub name: String,
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install a service that runs `lowertier run` with the given arguments.
    Install(InstallArgs),
    /// Remove the service.
    Uninstall,
    /// Show whether the service is installed and running.
    Status,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
}

#[derive(Args)]
pub struct InstallArgs {
    #[arg(long, default_value = env!("CARGO_PKG_DESCRIPTION"))]
    pub description: String,
    #[arg(long)]
    pub display_name: Option<String>,
    #[arg(long)]
    pub disable_autostart: bool,
    #[arg(long)]
    pub disable_restart_on_failure: bool,
    /// lowertier binary to run. Defaults to this binary.
    #[arg(long)]
    pub binary: Option<PathBuf>,
    #[arg(long)]
    pub work_dir: Option<PathBuf>,
    /// Arguments after `lowertier run`, for example -- -c /etc/lowertier/node.toml.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub run_args: Vec<OsString>,
}
