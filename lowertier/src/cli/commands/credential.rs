use super::super::{
    args::CredentialCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &CredentialCommand) -> Result<Response> {
    if client.meta.admin_token.is_empty() {
        return Err(CliError::new(
            "permission_denied",
            "Credential commands require --admin-token or LOWTIER_ADMIN_TOKEN.",
            "admin_token",
        ));
    }
    match command {
        CredentialCommand::List(page) => checked(
            client
                .rpc
                .list_credentials(
                    client.controller(),
                    ListCredentialsRequest {
                        meta: client.meta(),
                        page: page.page(),
                    },
                )
                .await?,
        ),
        CredentialCommand::Issue {
            ttl,
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            credential_id,
            reusable,
        } => checked(
            client
                .rpc
                .issue_credential(
                    client.controller(),
                    IssueCredentialRequest {
                        meta: client.meta(),
                        groups: groups.clone(),
                        allow_relay: *allow_relay,
                        allowed_proxy_cidrs: allowed_proxy_cidrs.clone(),
                        ttl_seconds: *ttl,
                        credential_id: credential_id.clone(),
                        reusable: Some(*reusable),
                    },
                )
                .await?,
        ),
        CredentialCommand::Revoke { credential_id } => checked(
            client
                .rpc
                .revoke_credential(
                    client.controller(),
                    RevokeCredentialRequest {
                        meta: client.meta(),
                        credential_id: credential_id.clone(),
                    },
                )
                .await?,
        ),
    }
}
