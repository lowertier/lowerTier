use super::super::{
    args::AclCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &AclCommand) -> Result<Response> {
    match command {
        AclCommand::Get => checked(
            client
                .rpc
                .get_acl(
                    client.controller(),
                    GetAclRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        AclCommand::Stats => checked(
            client
                .rpc
                .get_acl_stats(
                    client.controller(),
                    GetAclStatsRequest {
                        meta: client.meta(),
                    },
                )
                .await?,
        ),
        AclCommand::Set { file, apply } => {
            if apply.stage {
                return Err(CliError::new(
                    "invalid_argument",
                    "ACL changes apply live. Remove --stage.",
                    "stage",
                ));
            }
            let mut request: SetAclRequest = super::config::read_json(file)?;
            request.meta = client.meta();
            request.expected_revision = client.revision(apply.expected_revision).await?;
            request.persist = apply.persist;
            checked(client.rpc.set_acl(client.controller(), request).await?)
        }
    }
}
