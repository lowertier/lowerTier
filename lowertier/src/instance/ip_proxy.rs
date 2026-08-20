use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Context;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    gateway::{
        icmp_proxy::IcmpProxy,
        tcp_proxy::{NatDstTcpConnector, TcpProxy},
        udp_proxy::UdpProxy,
    },
    peers::peer_manager::PeerManager,
};

#[derive(Clone)]
pub(super) struct IpProxy {
    tcp_proxy: Arc<TcpProxy<NatDstTcpConnector>>,
    icmp_proxy: Arc<IcmpProxy>,
    udp_proxy: Arc<UdpProxy>,
    global_ctx: ArcGlobalCtx,
    started: Arc<AtomicBool>,
}

impl IpProxy {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Self, Error> {
        let tcp_proxy = TcpProxy::new(peer_manager.clone(), NatDstTcpConnector {});
        let icmp_proxy = IcmpProxy::new(global_ctx.clone(), peer_manager.clone())
            .with_context(|| "create icmp proxy failed")?;
        let udp_proxy = UdpProxy::new(global_ctx.clone(), peer_manager)
            .with_context(|| "create udp proxy failed")?;
        Ok(Self {
            tcp_proxy,
            icmp_proxy,
            udp_proxy,
            global_ctx,
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(super) fn tcp_proxy(&self) -> Arc<TcpProxy<NatDstTcpConnector>> {
        self.tcp_proxy.clone()
    }

    pub(super) async fn start(&self) -> Result<(), Error> {
        if (self.global_ctx.config.get_proxy_cidrs().is_empty()
            || self.started.load(Ordering::Relaxed))
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return Ok(());
        }

        // An exit node can still use the system network stack for forwarding.
        if self.global_ctx.proxy_forward_by_system() && !self.global_ctx.no_tun() {
            return Ok(());
        }

        self.started.store(true, Ordering::Relaxed);
        self.tcp_proxy.start(true).await?;
        if let Err(error) = self.icmp_proxy.start().await {
            tracing::error!(?error, "start icmp proxy failed");
            if cfg!(not(any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            ))) {
                return Err(error);
            }
        }
        self.udp_proxy.start().await?;
        Ok(())
    }
}
