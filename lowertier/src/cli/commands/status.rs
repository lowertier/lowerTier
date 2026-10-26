use super::super::{
    client::{Client, PeerView, Response},
    error::Result,
};
use super::peer;
use crate::proto::api::control::v1::*;
use serde::Serialize;

/// Everything `lowertier status` and `lowertier top` show, sampled together.
#[derive(Serialize)]
pub struct StatusView {
    pub daemon: Option<String>,
    pub portal: String,
    pub node: GetNodeResponse,
    pub peers: PeerView,
    pub relay: GetRelayResponse,
    pub discovery: GetDiscoveryResponse,
    pub listeners: ListListenersResponse,
}

fn checked<T>(response: T, error: Option<&ApiError>) -> Result<T> {
    match error {
        Some(error) => Err(error.clone().into()),
        None => Ok(response),
    }
}

pub async fn fetch(client: &Client) -> Result<StatusView> {
    let meta = client.meta();
    let (node, peers, relay, discovery, listeners) = tokio::join!(
        client
            .rpc
            .get_node(client.controller(), GetNodeRequest { meta: meta.clone() }),
        peer::list(
            client,
            Some(Page {
                limit: 256,
                page_token: String::new()
            })
        ),
        peer::relay(client),
        client.rpc.get_discovery(
            client.controller(),
            GetDiscoveryRequest { meta: meta.clone() }
        ),
        client
            .rpc
            .list_listeners(client.controller(), ListListenersRequest { meta }),
    );
    let node = node?;
    let node = checked(node.clone(), node.error.as_ref())?;
    let relay = relay?;
    let discovery = discovery?;
    let discovery = checked(discovery.clone(), discovery.error.as_ref())?;
    let listeners = listeners?;
    let listeners = checked(listeners.clone(), listeners.error.as_ref())?;
    Ok(StatusView {
        daemon: client.target.name.clone(),
        portal: client.target.portal.clone(),
        peers: peer::build(peers?, &relay),
        node,
        relay,
        discovery,
        listeners,
    })
}

pub async fn execute(client: &Client) -> Result<Response> {
    Ok(Response::Status(Box::new(fetch(client).await?)))
}
