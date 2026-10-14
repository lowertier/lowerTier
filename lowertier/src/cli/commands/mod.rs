use super::{
    args::*,
    client::{Client, Response},
    error::Result,
};

mod acl;
mod camouflage;
pub(super) mod config;
mod credential;
mod discovery;
mod instance;
mod l2;
mod listener;
pub(super) mod log;
mod node;
mod peer;
mod port_forward;
mod relay;
mod route;
pub(super) mod service;
pub(super) mod stats;

pub async fn execute(client: &Client, command: &Command) -> Result<Response> {
    match command {
        Command::Node { command } => node::execute(client, command).await,
        Command::Peer { command } => peer::execute(client, command).await,
        Command::Route { command } => route::execute(client, command).await,
        Command::Relay { command } => relay::execute(client, command).await,
        Command::L2 { command } => l2::execute(client, command).await,
        Command::Discovery { command } => discovery::execute(client, command).await,
        Command::Listener { command } => listener::execute(client, command).await,
        Command::Camouflage { command } => camouflage::execute(client, command).await,
        Command::Config { command } => config::execute(client, command).await,
        Command::Stats { command } => stats::execute(client, command).await,
        Command::Log { command } => log::execute(client, command).await,
        Command::Acl { command } => acl::execute(client, command).await,
        Command::Credential { command } => credential::execute(client, command).await,
        Command::PortForward { command } => port_forward::execute(client, command).await,
        Command::Instance { command } => instance::execute(client, command).await,
        Command::Service(args) => service::execute(args),
        Command::Completion { .. } => unreachable!("Completion is local."),
    }
}
