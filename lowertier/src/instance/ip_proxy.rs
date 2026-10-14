use std::sync::{
    Arc, OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Context;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    gateway::{icmp_proxy::IcmpProxy, tcp_proxy::TcpProxy, udp_proxy::UdpProxy},
    peers::peer_manager::PeerManager,
};

#[derive(Clone)]
pub(super) struct IpProxy {
    tcp_proxy: Arc<OnceLock<Arc<TcpProxy>>>,
    icmp_proxy: Arc<OnceLock<Arc<IcmpProxy>>>,
    udp_proxy: Arc<OnceLock<Arc<UdpProxy>>>,
    global_ctx: ArcGlobalCtx,
    started: Arc<AtomicBool>,
    start_lock: Arc<tokio::sync::Mutex<()>>,
    peer_manager: Weak<PeerManager>,
}

impl IpProxy {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Self, Error> {
        Ok(Self {
            tcp_proxy: Arc::new(OnceLock::new()),
            icmp_proxy: Arc::new(OnceLock::new()),
            udp_proxy: Arc::new(OnceLock::new()),
            global_ctx,
            started: Arc::new(AtomicBool::new(false)),
            start_lock: Arc::new(tokio::sync::Mutex::new(())),
            peer_manager: Arc::downgrade(&peer_manager),
        })
    }

    pub(super) fn tcp_proxy(&self) -> Arc<OnceLock<Arc<TcpProxy>>> {
        self.tcp_proxy.clone()
    }

    pub(super) async fn start(&self) -> Result<(), Error> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.global_ctx.config.get_proxy_cidrs().is_empty()
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return Ok(());
        }

        // An exit node can still use the system network stack for forwarding.
        if self.global_ctx.proxy_forward_by_system() && !self.global_ctx.no_tun() {
            return Ok(());
        }

        let _guard = self.start_lock.lock().await;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let peer = self
            .peer_manager
            .upgrade()
            .context("IP proxy peer manager is gone")?;
        let tcp = self.tcp_proxy.get_or_init(|| TcpProxy::new(peer.clone()));
        if self.icmp_proxy.get().is_none() {
            let proxy = IcmpProxy::new(self.global_ctx.clone(), peer.clone())
                .context("create icmp proxy failed")?;
            let _ = self.icmp_proxy.set(proxy);
        }
        if self.udp_proxy.get().is_none() {
            let proxy =
                UdpProxy::new(self.global_ctx.clone(), peer).context("create udp proxy failed")?;
            let _ = self.udp_proxy.set(proxy);
        }
        tcp.start(true).await?;
        if let Err(error) = self.icmp_proxy.get().unwrap().start().await {
            tracing::error!(?error, "start icmp proxy failed");
            if cfg!(not(any(
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne")
            ))) {
                return Err(error);
            }
        }
        self.udp_proxy.get().unwrap().start().await?;
        self.started.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod protocol_memory_tests {
    use super::*;
    use crate::common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::GlobalCtx,
    };
    use crate::peers::{create_packet_recv_chan, peer_manager::RouteAlgoType};
    fn fixture(no_tun: bool) -> (Arc<PeerManager>, IpProxy) {
        let config = TomlConfigLoader::default();
        let mut flags = config.get_flags();
        flags.no_tun = no_tun;
        config.set_flags(flags);
        let ctx = Arc::new(GlobalCtx::new(config));
        let (sender, _receiver) = create_packet_recv_chan();
        let peer = Arc::new(PeerManager::new(RouteAlgoType::None, ctx.clone(), sender));
        let proxy = IpProxy::new(ctx, peer.clone()).unwrap();
        (peer, proxy)
    }
    #[tokio::test]
    async fn inactive_proxy_and_status_query_allocate_no_protocol_state() {
        let (_peer, proxy) = fixture(false);
        proxy.start().await.unwrap();
        let entries = proxy
            .tcp_proxy()
            .get()
            .map(|proxy| proxy.list_proxy_entries())
            .unwrap_or_default();
        assert!(entries.is_empty());
        assert!(proxy.tcp_proxy.get().is_none());
        assert!(proxy.icmp_proxy.get().is_none());
        assert!(proxy.udp_proxy.get().is_none());
        assert!(!proxy.started.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn concurrent_proxy_start_reuses_one_set_of_protocol_state() {
        let (_peer, proxy) = fixture(true);
        let (a, b) = tokio::join!(proxy.start(), proxy.start());
        a.unwrap();
        b.unwrap();
        let tcp = Arc::as_ptr(proxy.tcp_proxy.get().unwrap());
        proxy.start().await.unwrap();
        assert_eq!(tcp, Arc::as_ptr(proxy.tcp_proxy.get().unwrap()));
        assert!(proxy.icmp_proxy.get().is_some());
        assert!(proxy.udp_proxy.get().is_some());
        assert!(proxy.started.load(Ordering::Acquire));
    }
}
