use super::super::{
    args::RouteCommand,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use super::peer;
use crate::proto::api::control::v1::*;
use serde::Serialize;

#[derive(Serialize)]
pub struct Hop {
    pub peer_id: u32,
    pub name: String,
    pub address: String,
    /// Measured from this node; known for direct neighbors.
    pub rtt_us: Option<u64>,
    pub loss_ppm: Option<u32>,
    pub transport: String,
}

#[derive(Serialize)]
pub struct Trace {
    pub destination: String,
    pub policy: String,
    pub effective_policy: String,
    pub fallback_reason: String,
    pub path_error: String,
    pub cost_ms: Option<u64>,
    pub measured_rtt_us: Option<u64>,
    pub delivery_bps: Option<u64>,
    pub hops: Vec<Hop>,
}

async fn routes(
    client: &Client,
    page_token: String,
    include_paths: bool,
) -> Result<ListRoutesResponse> {
    let response = client
        .rpc
        .list_routes(
            client.controller(),
            ListRoutesRequest {
                meta: client.meta(),
                page: Some(Page {
                    limit: 256,
                    page_token,
                }),
                include_paths,
            },
        )
        .await?;
    if let Some(error) = response.error {
        return Err(error.into());
    }
    Ok(response)
}

fn route_matches(route: &RouteSnapshot, wanted: &str) -> bool {
    if route.destination == wanted {
        return true;
    }
    if let Some(info) = &route.route {
        if info.peer_id.to_string() == wanted || info.hostname == wanted {
            return true;
        }
        let address = info
            .ipv4_addr
            .as_ref()
            .and_then(|inet| inet.address)
            .map(std::net::Ipv4Addr::from);
        if address.is_some_and(|address| address.to_string() == wanted) {
            return true;
        }
    }
    match (
        wanted.parse::<std::net::IpAddr>(),
        route.destination.parse::<cidr::IpCidr>(),
    ) {
        (Ok(address), Ok(prefix)) => prefix.contains(&address),
        _ => false,
    }
}

async fn trace(client: &Client, destination: &str) -> Result<Response> {
    let mut page_token = String::new();
    let route = loop {
        let response = routes(client, page_token, true).await?;
        // Prefer the most specific matching prefix.
        if let Some(route) = response
            .routes
            .into_iter()
            .filter(|route| route_matches(route, destination))
            .max_by_key(|route| {
                route
                    .destination
                    .parse::<cidr::IpCidr>()
                    .map_or(u8::MAX, |prefix| prefix.network_length())
            })
        {
            break route;
        }
        if response.next_page_token.is_empty() {
            return Err(CliError::new(
                "not_found",
                format!("No route to {destination:?}. `lowertier routes` lists routes."),
                "destination",
            ));
        }
        page_token = response.next_page_token;
    };
    let peers = peer::list(
        client,
        Some(Page {
            limit: 256,
            page_token: String::new(),
        }),
    )
    .await?;
    let node = client
        .rpc
        .get_node(
            client.controller(),
            GetNodeRequest {
                meta: client.meta(),
            },
        )
        .await?;
    let local = node.node.unwrap_or_default();
    let hops = route
        .path_peer_ids
        .iter()
        .map(|id| {
            let peer = peers.peers.iter().find(|peer| peer.peer_id == *id);
            let info = peer.and_then(|peer| peer.route.as_ref());
            let (name, address) = if *id == local.peer_id {
                (
                    format!("{} (this node)", local.hostname),
                    local.ipv4_addr.clone(),
                )
            } else {
                (
                    info.map_or_else(|| "unknown".into(), |info| info.hostname.clone()),
                    info.and_then(|info| info.ipv4_addr.as_ref())
                        .map_or_else(String::new, |address| address.to_string()),
                )
            };
            let direct = peer.filter(|peer| !peer.conns.is_empty());
            Hop {
                peer_id: *id,
                name,
                address,
                rtt_us: direct.and_then(|peer| peer.rtt_us),
                loss_ppm: direct.and_then(|peer| peer.loss_ppm),
                transport: direct
                    .and_then(|peer| peer.conns.first())
                    .and_then(|conn| conn.tunnel.as_ref())
                    .map_or_else(String::new, |tunnel| tunnel.tunnel_type.clone()),
            }
        })
        .collect();
    Ok(Response::Trace(Trace {
        destination: route.destination,
        policy: route.policy,
        effective_policy: route.effective_policy,
        fallback_reason: route.fallback_reason,
        path_error: route.path_error,
        cost_ms: route.cost_ms,
        measured_rtt_us: route.measured_rtt_us,
        delivery_bps: route.delivery_bps,
        hops,
    }))
}

pub async fn execute(client: &Client, command: Option<&RouteCommand>) -> Result<Response> {
    match command {
        None => checked(routes(client, String::new(), false).await?),
        Some(RouteCommand::List { path, page }) => checked(
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
        Some(RouteCommand::Trace { destination }) => trace(client, destination).await,
    }
}
