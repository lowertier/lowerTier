use super::super::{
    args::SettingsCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &SettingsCommand) -> Result<Response> {
    match command {
        SettingsCommand::Show => checked(
            client
                .rpc
                .get_relay(
                    client.controller(),
                    GetRelayRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        SettingsCommand::Set(args) => super::config::patch(client, args, "relay", false).await,
    }
}
