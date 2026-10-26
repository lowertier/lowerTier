use super::super::{
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client) -> Result<Response> {
    checked(
        client
            .rpc
            .get_relay(
                client.controller(),
                GetRelayRequest {
                    meta: client.meta(),
                },
            )
            .await?,
    )
}
