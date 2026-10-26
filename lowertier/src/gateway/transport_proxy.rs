//! Direct proxy admission. All other targets retain packet routing and ACLs.
use super::tcp_proxy::TcpProxy;
use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx},
    peers::{peer_conn::PeerConnCloseNotify, peer_map::PeerMap},
    tunnel::quic::proxy::{IncomingProxy, ProxyEndpoint},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet};

pub(crate) async fn serve(
    endpoint: Arc<ProxyEndpoint>,
    mut incoming: mpsc::Receiver<IncomingProxy>,
    peers: Arc<PeerMap>,
    context: ArcGlobalCtx,
    peer_id: PeerId,
    close: Arc<PeerConnCloseNotify>,
) {
    let Some(mut closed) = close.get_waiter().await else {
        endpoint.authenticated(false);
        return;
    };
    let mut transfers = JoinSet::new();
    loop {
        tokio::select! {
            _ = closed.recv() => break,
            result = transfers.join_next(), if !transfers.is_empty() => {
                if let Some(Err(error)) = result { tracing::debug!(?error, "TCP transport proxy task stopped"); }
            }
            request = incoming.recv() => {
                let Some(request) = request else { break; };
                let peers = peers.clone(); let context = context.clone();
                transfers.spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(15), admit(&request, &peers, &context, peer_id)).await {
                        Ok(Ok(mut destination)) => {
                            match request.accept().await {
                                Ok(stream) => { let _ = stream.copy_owned(&mut destination).await; }
                                Err(error) => tracing::debug!(?error, "TCP transport proxy open failed"),
                            }
                        }
                        Ok(Err(status)) => { let _ = request.reject(status).await; }
                        Err(_) => { let _ = request.reject(http::StatusCode::GATEWAY_TIMEOUT).await; }
                    }
                });
            }
        }
    }
    endpoint.authenticated(false);
    transfers.abort_all();
}
async fn admit(
    request: &IncomingProxy,
    peers: &PeerMap,
    context: &ArcGlobalCtx,
    peer_id: PeerId,
) -> Result<tokio::net::TcpStream, http::StatusCode> {
    if context.get_acl_filter().is_enabled()
        || !context.no_tun()
        || !context.is_ip_local_virtual_ip(&request.destination.ip())
    {
        return Err(http::StatusCode::NOT_IMPLEMENTED);
    }
    let IpAddr::V4(source) = request.source.ip() else {
        return Err(http::StatusCode::FORBIDDEN);
    };
    if peers.get_peer_id_by_ipv4(&source).await != Some(peer_id)
        || context.should_deny_proxy(&request.destination, false)
    {
        return Err(http::StatusCode::FORBIDDEN);
    }
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), request.destination.port());
    TcpProxy::connect_nat_dst(destination)
        .await
        .map_err(|_| http::StatusCode::BAD_GATEWAY)
}
