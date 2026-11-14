use super::{
    args::*,
    client::{Client, Response},
    error::Result,
};

use crate::proto::api::control::v1::ListPathsRequest;

mod acl;
mod camouflage;
pub(crate) mod config;
mod credential;
mod discovery;
pub(super) mod doctor;
mod forward;
mod instance;
mod l2;
mod listener;
pub(super) mod log;
pub(crate) mod peer;
mod relay;
pub(super) mod route;
pub(super) mod service;
pub(super) mod stats;
pub(crate) mod status;

pub async fn execute(client: &Client, command: &Command) -> Result<Response> {
    match command {
        Command::Status => status::execute(client).await,
        Command::Get { path } => config::get(client, path.as_deref()).await,
        Command::Set(args) => config::set(client, &args.assignments, &args.apply).await,
        Command::Unset { paths, apply } => config::unset(client, paths, apply).await,
        Command::Edit { apply } => config::edit(client, apply).await,
        Command::Peers { command } => peer::execute(client, command.as_ref()).await,
        Command::Routes { command } => route::execute(client, command.as_ref()).await,
        Command::Relay => relay::execute(client).await,
        Command::Paths => super::client::checked(
            client
                .rpc
                .list_paths(
                    client.controller(),
                    ListPathsRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        Command::Camouflage => camouflage::execute(client).await,
        Command::Discovery => discovery::execute(client).await,
        Command::Listeners { command } => listener::execute(client, command.as_ref()).await,
        Command::L2 { command } => l2::execute(client, command.as_ref()).await,
        Command::Acl { command } => acl::execute(client, command.as_ref()).await,
        Command::Creds { command } => credential::execute(client, command).await,
        Command::Forward { command } => forward::execute(client, command.as_ref()).await,
        Command::Instance { command } => instance::execute(client, command).await,
        Command::Stats { prometheus, .. } => stats::execute(client, *prometheus).await,
        Command::Logs { clear: true, .. } => log::clear(client).await,
        Command::Logs { page, .. } if page.page_token.is_empty() => {
            super::client::checked(log::tail(client, page.limit).await?)
        }
        Command::Logs { page, .. } => super::client::checked(log::read(client, page).await?),
        Command::LogLevel { level } => log::level(client, level.as_deref()).await,
        Command::Init(_)
        | Command::Run(_)
        | Command::Check(_)
        | Command::Nodes
        | Command::Config { .. }
        | Command::Doctor
        | Command::Top(_)
        | Command::Gui(_)
        | Command::Service(_)
        | Command::Completion { .. }
        | Command::Ssh { .. } => unreachable!("handled before connecting"),
    }
}
