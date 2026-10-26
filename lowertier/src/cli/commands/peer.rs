use super::super::{
    args::PeerCommand,
    client::{Client, PeerView, Response},
    error::{CliError, Result},
};
use super::config;
use crate::proto::api::control::v1::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use toml::{Table, Value};

pub async fn relay(client: &Client) -> Result<GetRelayResponse> {
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
    Ok(relay)
}

pub async fn list(client: &Client, page: Option<Page>) -> Result<ListPeersResponse> {
    let response = client
        .rpc
        .list_peers(
            client.controller(),
            ListPeersRequest {
                meta: client.meta(),
                page,
            },
        )
        .await?;
    if let Some(error) = response.error {
        return Err(error.into());
    }
    Ok(response)
}

/// Combine peers with their route summaries from the relay snapshot.
pub fn build(response: ListPeersResponse, relay: &GetRelayResponse) -> PeerView {
    let active_policy = relay
        .config
        .as_ref()
        .and_then(|config| crate::proto::common::RelayPolicy::try_from(config.policy).ok())
        .map(|policy| policy.as_str_name())
        .unwrap_or("unknown")
        .into();
    let route_summaries = relay
        .paths
        .iter()
        .filter(|route| {
            route.route.as_ref().is_some_and(|route| {
                response
                    .peers
                    .iter()
                    .any(|peer| peer.peer_id == route.peer_id)
            })
        })
        .cloned()
        .collect();
    PeerView {
        snapshot: response.snapshot,
        peers: response.peers,
        route_summaries,
        active_policy,
        next_page_token: response.next_page_token,
        detail: false,
    }
}

async fn view(client: &Client, response: ListPeersResponse, detail: bool) -> Result<Response> {
    let relay = relay(client).await?;
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
    let mut view = build(response, &relay);
    view.detail = detail;
    Ok(Response::Peers(view))
}

pub fn matches(peer: &PeerSnapshot, wanted: &str) -> bool {
    peer.peer_id.to_string() == wanted
        || STANDARD.encode(&peer.peer_key) == wanted
        || peer.route.as_ref().is_some_and(|route| {
            route.hostname == wanted
                || route.ipv4_addr.as_ref().is_some_and(|address| {
                    address.address.map(|ip| ip.to_string()).as_deref() == Some(wanted)
                })
        })
}

fn peers_of(desired: &Table) -> Vec<Value> {
    desired
        .get("peer")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

async fn replace(
    client: &Client,
    peers: Vec<Value>,
    apply: &super::super::args::ApplyArgs,
    revision: u64,
) -> Result<Response> {
    let mut values = Table::new();
    values.insert("peer".into(), Value::Array(peers));
    config::patch(
        client,
        values,
        vec!["peer".into()],
        Vec::new(),
        apply,
        Some(revision),
    )
    .await
}

pub async fn execute(client: &Client, command: Option<&PeerCommand>) -> Result<Response> {
    let Some(command) = command else {
        return view(client, list(client, None).await?, false).await;
    };
    match command {
        PeerCommand::List(page) => view(client, list(client, page.page()).await?, false).await,
        PeerCommand::Show { peer } => {
            let mut page_token = String::new();
            loop {
                let mut response = list(
                    client,
                    Some(Page {
                        limit: 256,
                        page_token,
                    }),
                )
                .await?;
                response.peers.retain(|value| matches(value, peer));
                if !response.peers.is_empty() {
                    response.next_page_token.clear();
                    return view(client, response, true).await;
                }
                if response.next_page_token.is_empty() {
                    return Err(CliError::new(
                        "not_found",
                        format!("No peer {peer:?}. `lowertier peers` lists peers."),
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
            let (desired, revision) = config::desired(client, apply).await?;
            let mut peers = peers_of(&desired);
            if peers
                .iter()
                .any(|peer| peer.get("uri").and_then(Value::as_str) == Some(uri))
            {
                return Err(CliError::new(
                    "invalid_argument",
                    format!("The peer {uri} is already configured."),
                    "uri",
                ));
            }
            let mut peer = Table::new();
            peer.insert("uri".into(), Value::String(uri.clone()));
            if let Some(key) = public_key {
                peer.insert("public_key".into(), Value::String(key.clone()));
            }
            peers.push(Value::Table(peer));
            replace(client, peers, apply, revision).await
        }
        PeerCommand::Rm { uri, apply } => {
            let (desired, revision) = config::desired(client, apply).await?;
            let mut peers = peers_of(&desired);
            let count = peers.len();
            peers.retain(|peer| peer.get("uri").and_then(Value::as_str) != Some(uri));
            if count == peers.len() {
                return Err(CliError::new(
                    "not_found",
                    format!("No configured peer {uri}. `lowertier get peer` lists them."),
                    "uri",
                ));
            }
            replace(client, peers, apply, revision).await
        }
    }
}
