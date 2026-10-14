use super::super::{
    args::{LogCommand, PageArgs},
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn read(client: &Client, page: &PageArgs) -> Result<ReadLogsResponse> {
    let value = client
        .rpc
        .read_logs(
            client.controller(),
            ReadLogsRequest {
                meta: client.meta(),
                page: page.page(),
            },
        )
        .await?;
    if let Some(error) = &value.error {
        return Err(error.clone().into());
    }
    Ok(value)
}
pub async fn execute(client: &Client, command: &LogCommand) -> Result<Response> {
    match command {
        LogCommand::Read(page) | LogCommand::Follow(page) => checked(read(client, page).await?),
        LogCommand::Level { level: Some(level) } => checked(
            client
                .rpc
                .set_log_config(
                    client.controller(),
                    SetLogConfigRequest {
                        meta: client.meta(),
                        level: level.clone(),
                    },
                )
                .await?,
        ),
        LogCommand::Level { level: None } => checked(
            client
                .rpc
                .get_log_config(
                    client.controller(),
                    GetLogConfigRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
    }
}
