use super::super::{
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client) -> Result<Response> {
    checked(
        client
            .rpc
            .get_camouflage(
                client.controller(),
                GetCamouflageRequest {
                    meta: client.meta(),
                },
            )
            .await?,
    )
}
