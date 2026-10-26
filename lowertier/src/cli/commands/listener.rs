use super::super::{
    args::{ApplyArgs, ListenerCommand},
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use super::config;
use crate::proto::api::control::v1::*;
use toml::{Table, Value};

async fn list(client: &Client) -> Result<ListListenersResponse> {
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
    Ok(response)
}

fn configured(desired: &Table) -> Vec<Value> {
    config::lookup(desired, "transport.listen")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

async fn replace(
    client: &Client,
    listeners: Vec<Value>,
    apply: &ApplyArgs,
    revision: u64,
) -> Result<Response> {
    let mut values = Table::new();
    crate::common::config_schema::set(&mut values, "transport.listen", Value::Array(listeners));
    config::patch(
        client,
        values,
        vec!["transport.listen".into()],
        Vec::new(),
        apply,
        Some(revision),
    )
    .await
}

pub async fn execute(client: &Client, command: Option<&ListenerCommand>) -> Result<Response> {
    match command {
        None | Some(ListenerCommand::List) => checked(list(client).await?),
        Some(ListenerCommand::Add { uri, apply }) => {
            let (desired, revision) = config::desired(client, apply).await?;
            let mut listeners = configured(&desired);
            if listeners.iter().any(|item| item.as_str() == Some(uri)) {
                return Err(CliError::new(
                    "invalid_argument",
                    format!("The listener {uri} is already configured."),
                    "uri",
                ));
            }
            listeners.push(Value::String(uri.clone()));
            replace(client, listeners, apply, revision).await
        }
        Some(ListenerCommand::Rm { listener, apply }) => {
            let (desired, revision) = config::desired(client, apply).await?;
            let mut listeners = configured(&desired);
            let uri = if listeners.iter().any(|item| item.as_str() == Some(listener)) {
                listener.clone()
            } else {
                list(client)
                    .await?
                    .listeners
                    .into_iter()
                    .find(|item| item.id == *listener)
                    .map(|item| item.uri)
                    .ok_or_else(|| {
                        CliError::new(
                            "not_found",
                            format!("No listener {listener:?}. `lowertier listeners` lists them."),
                            "listener",
                        )
                    })?
            };
            let count = listeners.len();
            listeners.retain(|item| item.as_str() != Some(&uri));
            if count == listeners.len() {
                return Err(CliError::new(
                    "not_found",
                    format!("{uri} is active but not in transport.listen."),
                    "listener",
                ));
            }
            replace(client, listeners, apply, revision).await
        }
    }
}
