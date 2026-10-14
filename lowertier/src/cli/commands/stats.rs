use super::super::{
    args::StatsCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &StatsCommand) -> Result<Response> {
    let (StatsCommand::Show { prometheus } | StatsCommand::Watch { prometheus }) = command;
    if *prometheus {
        checked(
            client
                .rpc
                .get_prometheus(
                    client.controller(),
                    GetPrometheusRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        )
    } else {
        checked(
            client
                .rpc
                .get_stats(
                    client.controller(),
                    GetStatsRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        )
    }
}
pub async fn wait(client: &Client, resource: &str, cursor: String) -> Result<WatchChangesResponse> {
    let value = client
        .rpc
        .watch_changes(
            client.controller(),
            WatchChangesRequest {
                meta: client.meta(),
                resources: vec![resource.into()],
                cursor,
                max_wait_ms: 20_000,
            },
        )
        .await?;
    if let Some(error) = &value.error {
        return Err(error.clone().into());
    }
    Ok(value)
}
