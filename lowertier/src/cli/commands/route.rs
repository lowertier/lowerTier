use super::super::{
    args::RouteCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::proto::api::control::v1::*;
pub async fn execute(client: &Client, command: &RouteCommand) -> Result<Response> {
    match command {
        RouteCommand::List { path, page } => checked(
            client
                .rpc
                .list_routes(
                    client.controller(),
                    ListRoutesRequest {
                        meta: client.meta(),
                        page: page.page(),
                        include_paths: *path,
                    },
                )
                .await?,
        ),
        RouteCommand::Show { destination, path } => {
            let mut page_token = String::new();
            loop {
                let mut response = client
                    .rpc
                    .list_routes(
                        client.controller(),
                        ListRoutesRequest {
                            meta: client.meta(),
                            page: Some(Page {
                                limit: 256,
                                page_token,
                            }),
                            include_paths: *path,
                        },
                    )
                    .await?;
                if let Some(error) = response.error {
                    return Err(error.into());
                }
                response
                    .routes
                    .retain(|route| route.destination == *destination);
                if !response.routes.is_empty() {
                    response.next_page_token.clear();
                    return checked(response);
                }
                if response.next_page_token.is_empty() {
                    return Err(CliError::new(
                        "not_found",
                        "The route does not exist.",
                        "destination",
                    ));
                }
                page_token = response.next_page_token;
            }
        }
    }
}
