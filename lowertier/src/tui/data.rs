//! Polls the daemon and sends snapshots and new log lines to the UI.

use std::time::Duration;

use tokio::sync::mpsc;

use super::state::{Event, Snapshot};
use crate::{
    cli::{client::Client, commands::status},
    proto::api::control::v1::*,
};

const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// Pages read at startup to fill the log tail.
const INITIAL_LOG_PAGES: usize = 16;

async fn routes(client: &Client) -> crate::cli::error::Result<Vec<RouteSnapshot>> {
    let response = client
        .rpc
        .list_routes(
            client.controller(),
            ListRoutesRequest {
                meta: client.meta(),
                page: Some(Page {
                    limit: 256,
                    page_token: String::new(),
                }),
                include_paths: true,
            },
        )
        .await?;
    match response.error {
        Some(error) => Err(error.into()),
        None => Ok(response.routes),
    }
}

/// Read log pages after `cursor`. Returns the new lines and the next cursor.
async fn logs(
    client: &Client,
    mut cursor: String,
    pages: usize,
) -> crate::cli::error::Result<(Vec<LogEntry>, String)> {
    let mut entries = Vec::new();
    for _ in 0..pages {
        let response = client
            .rpc
            .read_logs(
                client.controller(),
                ReadLogsRequest {
                    meta: client.meta(),
                    page: Some(Page {
                        limit: 256,
                        page_token: cursor.clone(),
                    }),
                },
            )
            .await?;
        if let Some(error) = response.error {
            return Err(error.into());
        }
        let full = response.logs.len() == 256;
        entries.extend(response.logs);
        if !response.next_page_token.is_empty() {
            cursor = response.next_page_token;
        }
        if !full {
            break;
        }
    }
    Ok((entries, cursor))
}

pub async fn poll(mut client: Client, interval: Duration, events: mpsc::Sender<Event>) {
    let mut cursor = String::new();
    let mut first_logs = true;
    let mut backoff = Duration::from_secs(1);
    // A daemon that stops answering should show up within a few refreshes.
    let deadline = (interval * 3).max(Duration::from_secs(2));
    loop {
        let poll = async {
            let (status, routes) = tokio::join!(status::fetch(&client), routes(&client));
            let snapshot = Snapshot {
                status: status?,
                routes: routes?,
            };
            let pages = if first_logs { INITIAL_LOG_PAGES } else { 4 };
            let (entries, next) = logs(&client, cursor.clone(), pages).await?;
            Ok::<_, crate::cli::error::CliError>((snapshot, entries, next))
        };
        let result = tokio::time::timeout(deadline, poll)
            .await
            .unwrap_or_else(|_| {
                Err(crate::cli::error::CliError::new(
                    "deadline_exceeded",
                    format!(
                        "No answer from {} for {}s.",
                        client.target.portal,
                        deadline.as_secs()
                    ),
                    "",
                ))
            });
        let delay = match result {
            Ok((snapshot, entries, next)) => {
                cursor = next;
                first_logs = false;
                backoff = Duration::from_secs(1);
                if events
                    .send(Event::Snapshot(Box::new(snapshot)))
                    .await
                    .is_err()
                    || (!entries.is_empty() && events.send(Event::Logs(entries)).await.is_err())
                {
                    return;
                }
                interval
            }
            Err(error) => {
                // A restarted daemon rejects the old log cursor; read its log from the start.
                if error.0.field_path == "page.page_token" {
                    cursor.clear();
                    first_logs = true;
                }
                let message = format!("{} Retrying in {}s.", error.0.message, backoff.as_secs());
                if events.send(Event::Failed(message)).await.is_err() {
                    return;
                }
                if let Ok(fresh) = client.reconnect().await {
                    client = fresh;
                }
                let delay = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                delay
            }
        };
        tokio::time::sleep(delay).await;
    }
}
