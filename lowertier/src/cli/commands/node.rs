use super::super::{
    args::NodeCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, _: &NodeCommand) -> Result<Response> {
    checked(
        client
            .rpc
            .get_node(
                client.controller(),
                GetNodeRequest {
                    meta: client.meta(),
                },
            )
            .await?,
    )
}
