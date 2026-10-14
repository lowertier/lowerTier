use std::net::IpAddr;

use crate::{
    common::{global_ctx::ArcGlobalCtx, underlay_policy::UnderlayPolicy},
    proto::{
        peer_rpc::{DirectConnectorRpc, GetIpListRequest, GetIpListResponse},
        rpc_types::{self, controller::BaseController},
    },
};

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

#[derive(Clone)]
pub struct DirectConnectorManagerRpcServer {
    global_ctx: ArcGlobalCtx,
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
}

impl DirectConnectorManagerRpcServer {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}
