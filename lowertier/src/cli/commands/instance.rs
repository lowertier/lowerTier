use super::super::{
    args::InstanceCommand,
    client::{Client, Response, checked},
    error::Result,
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &InstanceCommand) -> Result<Response> {
    match command {
        InstanceCommand::List => checked(
            client
                .rpc
                .list_instances(
                    client.controller(),
                    ListInstancesRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        InstanceCommand::Create { file } => checked(
            client
                .rpc
                .create_instance(
                    client.controller(),
                    CreateInstanceRequest {
                        meta: client.meta(),
                        config: Some(NodeConfig {
                            toml: std::fs::read_to_string(file).map_err(|error| {
                                super::super::error::CliError::new(
                                    "invalid_argument",
                                    format!("Cannot read {}: {error}", file.display()),
                                    "file",
                                )
                            })?,
                        }),
                    },
                )
                .await?,
        ),
        InstanceCommand::Start => checked(
            client
                .rpc
                .start_instance(
                    client.controller(),
                    StartInstanceRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        InstanceCommand::Stop => checked(
            client
                .rpc
                .stop_instance(
                    client.controller(),
                    StopInstanceRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        InstanceCommand::Delete => checked(
            client
                .rpc
                .delete_instance(
                    client.controller(),
                    DeleteInstanceRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
    }
}
