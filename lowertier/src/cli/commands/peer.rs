use super::super::{
    args::PeerCommand,
    client::{Client, PeerView, Response},
    error::{CliError, Result},
};
use super::config;
use crate::proto::api::control::v1::*;
use base64::{Engine, engine::general_purpose::STANDARD};

async fn view(client: &Client, response: ListPeersResponse) -> Result<Response> {
    if let Some(error) = response.error {
        return Err(error.into());
    }
    let relay = client
        .rpc
        .get_relay(
            client.controller(),
            GetRelayRequest {
                meta: client.meta(),
            },
        )
        .await?;
    if let Some(error) = relay.error {
        return Err(error.into());
    }
    if response
        .snapshot
        .as_ref()
        .zip(relay.snapshot.as_ref())
        .is_none_or(|(peers, relay)| {
            peers.revision != relay.revision
                || peers.topology_generation != relay.topology_generation
        })
    {
        return Err(CliError::new(
            "conflict",
            "The peer and route snapshots changed. Retry the request.",
            "snapshot",
        ));
    }
    let active_policy = relay
        .config
        .as_ref()
        .and_then(|config| crate::proto::common::RelayPolicy::try_from(config.policy).ok())
        .map(|policy| policy.as_str_name())
        .unwrap_or("unknown")
        .into();
    let route_summaries = relay
        .paths
        .into_iter()
        .filter(|route| {
            route.route.as_ref().is_some_and(|route| {
                response
                    .peers
                    .iter()
                    .any(|peer| peer.peer_id == route.peer_id)
            })
        })
        .collect();
    Ok(Response::Peers(PeerView {
        snapshot: response.snapshot,
        peers: response.peers,
        route_summaries,
        active_policy,
        next_page_token: response.next_page_token,
    }))
}

pub async fn execute(client: &Client, command: &PeerCommand) -> Result<Response> {
    match command {
        PeerCommand::List(page) => {
            view(
                client,
                client
                    .rpc
                    .list_peers(
                        client.controller(),
                        ListPeersRequest {
                            meta: client.meta(),
                            page: page.page(),
                        },
                    )
                    .await?,
            )
            .await
        }
        PeerCommand::Show { peer } => {
            let mut page_token = String::new();
            loop {
                let mut response = client
                    .rpc
                    .list_peers(
                        client.controller(),
                        ListPeersRequest {
                            meta: client.meta(),
                            page: Some(Page {
                                limit: 256,
                                page_token,
                            }),
                        },
                    )
                    .await?;
                if let Some(error) = response.error {
                    return Err(error.into());
                }
                response.peers.retain(|value| {
                    value.peer_id.to_string() == *peer || STANDARD.encode(&value.peer_key) == *peer
                });
                if !response.peers.is_empty() {
                    response.next_page_token.clear();
                    return view(client, response).await;
                }
                if response.next_page_token.is_empty() {
                    return Err(CliError::new(
                        "not_found",
                        "The peer does not exist.",
                        "peer",
                    ));
                }
                page_token = response.next_page_token;
            }
        }
        PeerCommand::Add {
            uri,
            public_key,
            apply,
        } => {
            let (mut desired, revision) = config::desired(client, apply).await?;
            if desired.peer.iter().any(|peer| peer.uri == *uri) {
                return Err(CliError::new(
                    "invalid_argument",
                    "The peer URI already exists.",
                    "peer",
                ));
            }
            desired.peer.push(PeerConfig {
                uri: uri.clone(),
                peer_public_key: public_key.clone(),
            });
            config::replace(
                client,
                apply,
                revision,
                "peer",
                NodeConfig {
                    peer: desired.peer,
                    ..Default::default()
                },
            )
            .await
        }
        PeerCommand::Remove { uri, apply } => {
            let (mut desired, revision) = config::desired(client, apply).await?;
            let count = desired.peer.len();
            desired.peer.retain(|peer| peer.uri != *uri);
            if count == desired.peer.len() {
                return Err(CliError::new(
                    "not_found",
                    "The configured peer URI does not exist.",
                    "peer",
                ));
            }
            config::replace(
                client,
                apply,
                revision,
                "peer",
                NodeConfig {
                    peer: desired.peer,
                    ..Default::default()
                },
            )
            .await
        }
    }
}
