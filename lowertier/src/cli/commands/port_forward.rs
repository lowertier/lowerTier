use super::super::{
    args::PortForwardCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &PortForwardCommand) -> Result<Response> {
    match command {
        PortForwardCommand::List => checked(
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
        PortForwardCommand::Add {
            protocol,
            bind_addr,
            dst_addr,
            apply,
        } => checked(
            client
                .rpc
                .put_port_forward(
                    client.controller(),
                    PutPortForwardRequest {
                        meta: client.meta(),
                        expected_revision: client.revision(apply.expected_revision).await?,
                        port_forward: Some(ForwardConfig {
                            bind_addr: bind_addr.clone(),
                            dst_addr: dst_addr.clone(),
                            proto: protocol.clone(),
                        }),
                        persist: apply.persist,
                        stage: apply.stage,
                    },
                )
                .await?,
        ),
        PortForwardCommand::Remove {
            protocol,
            bind_addr,
            apply,
        } => checked(
            client
                .rpc
                .delete_port_forward(
                    client.controller(),
                    DeletePortForwardRequest {
                        meta: client.meta(),
                        expected_revision: client.revision(apply.expected_revision).await?,
                        bind_addr: bind_addr.clone(),
                        proto: protocol.clone(),
                        persist: apply.persist,
                        stage: apply.stage,
                    },
                )
                .await?,
        ),
    }
}
