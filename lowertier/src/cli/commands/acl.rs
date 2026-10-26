use super::super::{
    args::AclCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: Option<&AclCommand>) -> Result<Response> {
    match command.unwrap_or(&AclCommand::Show) {
        AclCommand::Show => checked(
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
            let text = std::fs::read_to_string(file).map_err(|error| {
                CliError::new(
                    "invalid_argument",
                    format!("Cannot read {}: {error}", file.display()),
                    "file",
                )
            })?;
            let mut request: SetAclRequest = serde_json::from_str(&text)?;
            request.meta = client.meta();
            request.expected_revision = client.revision(apply.expected_revision).await?;
            request.persist = !apply.no_persist;
            checked(client.rpc.set_acl(client.controller(), request).await?)
        }
    }
}
