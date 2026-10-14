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
                .get_camouflage(
                    client.controller(),
                    GetCamouflageRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        SettingsCommand::Set(args) => super::config::patch(client, args, "camouflage", false).await,
    }
}
