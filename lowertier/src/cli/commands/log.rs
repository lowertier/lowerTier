use super::super::{
    args::PageArgs,
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

/// The newest `limit` lines and a cursor after them. The daemon keeps a bounded ring.
pub async fn tail(client: &Client, limit: u32) -> Result<ReadLogsResponse> {
    let mut page = PageArgs {
        limit: 256,
        page_token: String::new(),
    };
    let mut tail = std::collections::VecDeque::with_capacity(limit as usize);
    loop {
        let response = read(client, &page).await?;
        let full = response.logs.len() == 256;
        for entry in response.logs {
            if tail.len() == limit as usize {
                tail.pop_front();
            }
            tail.push_back(entry);
        }
        if !response.next_page_token.is_empty() {
            page.page_token = response.next_page_token;
        }
        if !full {
            return Ok(ReadLogsResponse {
                logs: tail.into(),
                next_page_token: page.page_token,
                truncated: response.truncated,
                ..Default::default()
            });
        }
    }
}

pub async fn level(client: &Client, level: Option<&str>) -> Result<Response> {
    match level {
        Some(level) => checked(
            client
                .rpc
                .set_log_config(
                    client.controller(),
                    SetLogConfigRequest {
                        meta: client.meta(),
                        level: level.into(),
                    },
                )
                .await?,
        ),
        None => checked(
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
