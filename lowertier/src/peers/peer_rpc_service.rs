use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;

use crate::{
    common::{
        PeerId, global_ctx::ArcGlobalCtx, network::IPCollector, token_bucket::TokenBucket,
        underlay_policy::UnderlayPolicy,
    },
    proto::{
        common::Void,
        peer_rpc::{
            DirectConnectorRpc, GetIpListRequest, GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::{self, controller::BaseController},
    },
};

const MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 16;
const MAX_FOREIGN_RELAY_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 4;
const FOREIGN_RELAY_HOLE_PUNCH_BUCKET_CAPACITY: u64 = 4;
const FOREIGN_RELAY_HOLE_PUNCH_BUCKET_RATE: u64 = 4;

fn filter_denied_advertisements(ret: &mut GetIpListResponse, policy: &UnderlayPolicy) {
    ret.interface_ipv4s
        .retain(|ip| policy.allows_ip(std::net::Ipv4Addr::from(*ip).into()));
    ret.interface_ipv6s
        .retain(|ip| policy.allows_ip(std::net::Ipv6Addr::from(*ip).into()));

    if ret
        .public_ipv4
        .as_ref()
        .map(|ip| std::net::Ipv4Addr::from(*ip))
        .is_some_and(|ip| !policy.allows_ip(ip.into()))
    {
        ret.public_ipv4 = None;
    }
    if ret
        .public_ipv6
        .as_ref()
        .map(|ip| std::net::Ipv6Addr::from(*ip))
        .is_some_and(|ip| !policy.allows_ip(ip.into()))
    {
        ret.public_ipv6 = None;
    }

    ret.listeners.retain(|listener| {
        let Ok(listener) = url::Url::try_from(listener) else {
            return false;
        };
        listener
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_none_or(|ip| policy.allows_ip(ip))
    });
}

fn remove_lowertier_managed_ipv6s(ret: &mut GetIpListResponse, global_ctx: &ArcGlobalCtx) {
    ret.interface_ipv6s.retain(|ip| {
        let ip = std::net::Ipv6Addr::from(*ip);
        !global_ctx.is_ip_lowertier_managed_ipv6(&ip)
    });

    if ret
        .public_ipv6
        .as_ref()
        .map(|ip| std::net::Ipv6Addr::from(*ip))
        .is_some_and(|ip| global_ctx.is_ip_lowertier_managed_ipv6(&ip))
    {
        ret.public_ipv6 = None;
    }
}

fn connector_addrs_from_request_with_limit(
    req: SendUdpHolePunchPacketRequest,
    underlay_policy: &UnderlayPolicy,
    max_connector_addrs: usize,
    global_ctx: Option<&ArcGlobalCtx>,
) -> rpc_types::error::Result<(u16, Vec<SocketAddr>, Option<crate::proto::common::Ipv6Addr>)> {
    let listener_port = u16::try_from(req.listener_port)
        .map_err(|_| anyhow::anyhow!("listener_port is out of range: {}", req.listener_port))?;
    let mut connector_addrs = req
        .connector_addrs
        .into_iter()
        .map(SocketAddr::from)
        .collect::<Vec<_>>();

    if connector_addrs.is_empty() {
        connector_addrs.push(
            req.connector_addr
                .ok_or(anyhow::anyhow!("connector_addr is required"))?
                .into(),
        );
    }

    let mut deduped = Vec::with_capacity(connector_addrs.len());
    for addr in connector_addrs {
        if !underlay_policy.allows_remote(addr.ip()) {
            tracing::debug!(?addr, "underlay policy removed UDP hole-punch destination");
            continue;
        }
        if global_ctx.is_some_and(|global_ctx| !is_safe_foreign_relay_destination(addr, global_ctx))
        {
            tracing::debug!(
                ?addr,
                "foreign relay rejected unsafe UDP hole-punch destination"
            );
            continue;
        }
        if !deduped.contains(&addr) {
            deduped.push(addr);
        }
        if deduped.len() >= max_connector_addrs {
            break;
        }
    }

    if deduped.is_empty() {
        return Err(
            anyhow::anyhow!("underlay policy denied every UDP hole-punch destination").into(),
        );
    }

    Ok((listener_port, deduped, req.preferred_src_ipv6))
}

fn connector_addrs_from_request(
    req: SendUdpHolePunchPacketRequest,
    underlay_policy: &UnderlayPolicy,
) -> rpc_types::error::Result<(u16, Vec<SocketAddr>, Option<crate::proto::common::Ipv6Addr>)> {
    connector_addrs_from_request_with_limit(
        req,
        underlay_policy,
        MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS,
        None,
    )
}

fn is_safe_foreign_relay_destination(addr: SocketAddr, global_ctx: &ArcGlobalCtx) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !global_ctx.is_ip_lowertier_managed_ipv6(&ip)
        }
    }
}

#[derive(Clone)]
pub struct DirectConnectorManagerRpcServer {
    global_ctx: ArcGlobalCtx,
    foreign_relay_rate_limiters: Arc<DashMap<PeerId, Arc<TokenBucket>>>,
}

#[async_trait::async_trait]
impl DirectConnectorRpc for DirectConnectorManagerRpcServer {
    type Controller = BaseController;

    async fn get_ip_list(
        &self,
        _: BaseController,
        _: GetIpListRequest,
    ) -> rpc_types::error::Result<GetIpListResponse> {
        let mut ret = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
        ret.listeners = self
            .global_ctx
            .config
            .get_mapped_listeners()
            .into_iter()
            .chain(self.global_ctx.get_running_listeners())
            .chain(self.global_ctx.get_discovery_listeners())
            .map(Into::into)
            .collect();
        remove_lowertier_managed_ipv6s(&mut ret, &self.global_ctx);
        filter_denied_advertisements(&mut ret, &self.global_ctx.get_underlay_policy());
        tracing::trace!(
            "get_ip_list: public_ipv4: {:?}, public_ipv6: {:?}, listeners: {:?}",
            ret.public_ipv4,
            ret.public_ipv6,
            ret.listeners
        );
        Ok(ret)
    }

    async fn send_udp_hole_punch_packet(
        &self,
        ctrl: BaseController,
        req: SendUdpHolePunchPacketRequest,
    ) -> rpc_types::error::Result<Void> {
        let foreign_relay_peer_id = if ctrl.authenticated_peer_identity_type
            == Some(crate::proto::peer_rpc::PeerIdentityType::ForeignRelay)
        {
            match ctrl.authenticated_peer_id.filter(|peer_id| *peer_id != 0) {
                Some(peer_id) => Some(peer_id),
                None => {
                    return Err(anyhow::anyhow!(
                        "foreign relay hole-punch request has no authenticated peer"
                    )
                    .into());
                }
            }
        } else {
            None
        };

        let (listener_port, connector_addrs, preferred_src_ipv6) =
            connector_addrs_from_request_with_limit(
                req,
                &self.global_ctx.get_underlay_policy(),
                if foreign_relay_peer_id.is_some() {
                    MAX_FOREIGN_RELAY_HOLE_PUNCH_CONNECTOR_ADDRS
                } else {
                    MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS
                },
                foreign_relay_peer_id.map(|_| &self.global_ctx),
            )?;

        if let Some(peer_id) = foreign_relay_peer_id {
            if !self.try_consume_foreign_relay_hole_punch(peer_id) {
                return Err(anyhow::anyhow!(
                    "foreign relay hole-punch request rate limit exceeded"
                )
                .into());
            }
        }
        let _ = (connector_addrs, preferred_src_ipv6, listener_port);
        Ok(Default::default())
    }
}

impl DirectConnectorManagerRpcServer {
    fn try_consume_foreign_relay_hole_punch(&self, peer_id: PeerId) -> bool {
        let limiter = self
            .foreign_relay_rate_limiters
            .entry(peer_id)
            .or_insert_with(|| {
                TokenBucket::new(
                    FOREIGN_RELAY_HOLE_PUNCH_BUCKET_CAPACITY,
                    FOREIGN_RELAY_HOLE_PUNCH_BUCKET_RATE,
                    Duration::from_secs(1),
                )
            })
            .clone();
        limiter.try_consume(1)
    }

    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            foreign_relay_rate_limiters: Arc::new(DashMap::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr};

    use super::{
        DirectConnectorManagerRpcServer, FOREIGN_RELAY_HOLE_PUNCH_BUCKET_CAPACITY,
        MAX_FOREIGN_RELAY_HOLE_PUNCH_CONNECTOR_ADDRS, connector_addrs_from_request,
        connector_addrs_from_request_with_limit, filter_denied_advertisements,
        remove_lowertier_managed_ipv6s,
    };

    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, underlay_policy::UnderlayPolicy},
        proto::peer_rpc::{GetIpListResponse, SendUdpHolePunchPacketRequest},
    };
}
