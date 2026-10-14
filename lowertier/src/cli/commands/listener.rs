use super::super::{
    args::ListenerCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use super::config;
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &ListenerCommand) -> Result<Response> {
    match command {
        ListenerCommand::List => checked(
            client
                .rpc
                .list_listeners(
                    client.controller(),
                    ListListenersRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        ListenerCommand::Add { uri, apply } => {
            let (mut desired, revision) = config::desired(client, apply).await?;
            if desired.listeners.contains(uri) {
                return Err(CliError::new(
                    "invalid_argument",
                    "The listener URI already exists.",
                    "listeners",
                ));
            }
            desired.listeners.push(uri.clone());
            config::replace(
                client,
                apply,
                revision,
                "listeners",
                NodeConfig {
                    listeners: desired.listeners,
                    ..Default::default()
                },
            )
            .await
        }
        ListenerCommand::Remove { listener, apply } => {
            let (mut desired, revision) = config::desired(client, apply).await?;
            let uri = if desired.listeners.contains(listener) {
                listener.clone()
            } else {
                let response = client
                    .rpc
                    .list_listeners(
                        client.controller(),
                        ListListenersRequest {
                            meta: client.meta(),
                        },
                    )
                    .await?;
                if let Some(error) = response.error {
                    return Err(error.into());
                }
                response
                    .listeners
                    .into_iter()
                    .find(|item| item.id == *listener)
                    .map(|item| item.uri)
                    .ok_or_else(|| {
                        CliError::new("not_found", "The listener does not exist.", "listener")
                    })?
            };
            let count = desired.listeners.len();
            desired.listeners.retain(|item| *item != uri);
            if count == desired.listeners.len() {
                return Err(CliError::new(
                    "not_found",
                    "The configured listener does not exist.",
                    "listener",
                ));
            }
            config::replace(
                client,
                apply,
                revision,
                "listeners",
                NodeConfig {
                    listeners: desired.listeners,
                    ..Default::default()
                },
            )
            .await
        }
    }
}
