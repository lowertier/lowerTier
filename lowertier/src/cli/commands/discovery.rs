use super::super::{
    args::DiscoveryCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, _: &DiscoveryCommand) -> Result<Response> {
    checked(
        client
            .rpc
            .get_discovery(
                client.controller(),
                GetDiscoveryRequest {
                    meta: client.meta(),
                },
            )
            .await?,
    )
}
