use super::super::{
    args::ForwardCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;

pub async fn execute(client: &Client, command: Option<&ForwardCommand>) -> Result<Response> {
    match command {
        None | Some(ForwardCommand::List) => checked(
            client
                .rpc
                .list_port_forwards(
                    client.controller(),
                    ListPortForwardsRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        Some(ForwardCommand::Add {
            proto,
            bind,
            dest,
            apply,
        }) => checked(
            client
                .rpc
                .put_port_forward(
                    client.controller(),
                    PutPortForwardRequest {
                        meta: client.meta(),
                        expected_revision: client.revision(apply.expected_revision).await?,
                        port_forward: Some(ForwardConfig {
                            bind: bind.clone(),
                            dest: dest.clone(),
                            proto: proto.clone(),
                        }),
                        persist: !apply.no_persist,
                        stage: apply.stage,
                    },
                )
                .await?,
        ),
        Some(ForwardCommand::Rm { proto, bind, apply }) => checked(
            client
                .rpc
                .delete_port_forward(
                    client.controller(),
                    DeletePortForwardRequest {
                        meta: client.meta(),
                        expected_revision: client.revision(apply.expected_revision).await?,
                        bind: bind.clone(),
                        proto: proto.clone(),
                        persist: !apply.no_persist,
                        stage: apply.stage,
                    },
                )
                .await?,
        ),
    }
}
