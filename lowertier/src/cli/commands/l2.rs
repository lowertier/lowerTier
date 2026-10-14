use super::super::{
    args::L2Command,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &L2Command) -> Result<Response> {
    let page = match command {
        L2Command::Fdb(page) => page.page(),
        L2Command::Stats => Some(Page {
            limit: 1,
            page_token: String::new(),
        }),
    };
    let mut response = client
        .rpc
        .get_l2(
            client.controller(),
            GetL2Request {
                meta: client.meta(),
                page,
            },
        )
        .await?;
    if matches!(command, L2Command::Stats) {
        response.fdb.clear();
        response.next_page_token.clear();
    }
    checked(response)
}
