use clap::{Parser, Subcommand};
use lowertier::{
    proto::{
        api::control::v1::*, rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    rpc_service::control::ControlToken,
    tunnel::tcp::TcpTunnelConnector,
};

#[derive(Parser)]
struct Arguments {
    #[arg(long, default_value = "127.0.0.1:15888")]
    rpc_portal: std::net::SocketAddr,
    #[arg(long)]
    instance: Option<String>,
    #[arg(long, env = "LOWTIER_CONTROL_TOKEN")]
    control_token: Option<String>,
    #[arg(long, env = "LOWTIER_CONTROL_TOKEN_FILE")]
    control_token_file: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    Show,
}
#[derive(Subcommand)]
enum PeerCommand {
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let control_token = match arguments.control_token {
        Some(token) => token,
        None => std::fs::read_to_string(
            arguments
                .control_token_file
                .unwrap_or(ControlToken::default_path(None)?),
        )?
        .trim()
        .to_owned(),
    };
    let meta = Some(RequestMeta {
        instance_id: arguments.instance.unwrap_or_default(),
        control_token,
        ..Default::default()
    });
    let connector = TcpTunnelConnector::new(format!("tcp://{}", arguments.rpc_portal).parse()?);
    let mut client = StandAloneClient::new(connector);
    let service = client
        .scoped_client::<ControlPlaneV1RpcClientFactory<BaseController>>(String::new())
        .await?;
    let value = match arguments.command {
        Command::Node {
            command: NodeCommand::Show,
        } => serde_json::to_value(
            service
                .get_node(BaseController::default(), GetNodeRequest { meta })
                .await?,
        )?,
        Command::Peer {
            command: PeerCommand::List,
        } => serde_json::to_value(
            service
                .list_peers(
                    BaseController::default(),
                    ListPeersRequest { meta, page: None },
                )
                .await?,
        )?,
    };
    if let Some(error) = value.get("error") {
        anyhow::bail!("{}", serde_json::to_string(error)?);
    }
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
