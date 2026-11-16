use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(not(mobile), feature = "tun"))]
use std::time::Duration;

#[cfg(mobile)]
use anyhow::Context as _;
use cidr::{IpCidr, Ipv4Inet};
use futures::FutureExt;
#[cfg(all(not(mobile), feature = "tun"))]
use tokio::sync::oneshot;
use tokio::sync::{Mutex, Notify};
#[cfg(feature = "magic-dns")]
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::common::PeerId;
use crate::common::acl_processor::AclRuleBuilder;
use crate::common::config::ConfigLoader;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent};
use crate::connector::direct::DirectConnectorManager;
use crate::connector::manual::ManualConnectorManager;
use crate::connector::quic_hole_punch::QuicHolePunchConnector;
use crate::connector::tcp_hole_punch::TcpHolePunchConnector;

use crate::peer_center::instance::PeerCenterInstance;
use crate::peers::peer_conn::PeerConnId;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::proto::common::TunnelInfo;
use crate::proto::rpc_impl::standalone::RpcServerHook;
use crate::rpc_service::control::ControlInstance;

#[cfg(feature = "magic-dns")]
use super::dns_server::{MAGIC_DNS_FAKE_IP, runner::DnsRunner};
use super::ip_proxy::IpProxy;
use super::listeners::ListenerManager;
use super::public_ipv6_provider::{
    PublicIpv6ProviderReconcileTask, reconcile_public_ipv6_provider_runtime,
    run_public_ipv6_provider_reconcile_task, validate_public_ipv6_config,
};

#[cfg(feature = "socks5")]
use crate::gateway::socks5::Socks5Server;

#[cfg(feature = "tun")]
type NicCtx = super::virtual_nic::NicCtx;

#[cfg(feature = "magic-dns")]
struct MagicDnsContainer {
    dns_runner_task: AbortOnDropHandle<()>,
    dns_runner_cancel_token: CancellationToken,
}

// nic container will be cleared when dhcp ip changed
#[cfg(feature = "tun")]
pub struct NicCtxContainer {
    _nic_ctx: NicCtx,
    #[cfg(feature = "magic-dns")]
    magic_dns: Option<MagicDnsContainer>,
}

#[cfg(feature = "tun")]
impl NicCtxContainer {
    #[cfg(not(feature = "magic-dns"))]
    fn new(nic_ctx: NicCtx) -> Self {
        Self { _nic_ctx: nic_ctx }
    }

    #[cfg(feature = "magic-dns")]
    fn new(nic_ctx: NicCtx, dns_runner: Option<DnsRunner>) -> Self {
        if let Some(mut dns_runner) = dns_runner {
            let token = CancellationToken::new();
            let token_clone = token.clone();
            let task = tokio::spawn(async move {
                let _ = dns_runner.run(token_clone).await;
            });
            Self {
                _nic_ctx: nic_ctx,
                magic_dns: Some(MagicDnsContainer {
                    dns_runner_task: AbortOnDropHandle::new(task),
                    dns_runner_cancel_token: token,
                }),
            }
        } else {
            Self {
                _nic_ctx: nic_ctx,
                magic_dns: None,
            }
        }
    }
}

#[cfg(feature = "tun")]
type ArcNicCtx = Arc<Mutex<Option<NicCtxContainer>>>;
type ArcPublicIpv6ProviderTaskSlot = Arc<PublicIpv6ProviderTaskSlot>;

struct PublicIpv6ProviderTaskSlot {
    task: Mutex<Option<PublicIpv6ProviderReconcileTask>>,
    closing: AtomicBool,
}

impl PublicIpv6ProviderTaskSlot {
    fn new() -> Self {
        Self {
            task: Mutex::new(None),
            closing: AtomicBool::new(false),
        }
    }

    async fn ensure_started(&self, global_ctx: &ArcGlobalCtx) {
        let mut task = self.task.lock().await;
        if self.closing.load(Ordering::Acquire) || task.is_some() {
            return;
        }
        *task = run_public_ipv6_provider_reconcile_task(global_ctx);
    }

    async fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let task = self.task.lock().await.take();
        if let Some(task) = task {
            task.shutdown().await;
        }
    }
}

async fn ensure_public_ipv6_provider_reconcile_task(
    global_ctx: &ArcGlobalCtx,
    task_slot: &ArcPublicIpv6ProviderTaskSlot,
) {
    task_slot.ensure_started(global_ctx).await;
}

pub struct InstanceRpcServerHook {
    rpc_portal_whitelist: Vec<IpCidr>,
}

impl InstanceRpcServerHook {
    pub fn new(rpc_portal_whitelist: Option<Vec<IpCidr>>) -> Self {
        let rpc_portal_whitelist = rpc_portal_whitelist
            .unwrap_or_else(|| vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()]);
        InstanceRpcServerHook {
            rpc_portal_whitelist,
        }
    }
}

#[async_trait::async_trait]
impl RpcServerHook for InstanceRpcServerHook {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        let tunnel_info = tunnel_info.ok_or_else(|| anyhow::anyhow!("tunnel info is None"))?;

        let remote_url = tunnel_info
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow::anyhow!("remote_addr is None"))?;

        let url_str = &remote_url.url;
        let url = url::Url::parse(url_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse remote URL '{}': {}", url_str, e))?;

        let ip_addr = match url.host() {
            Some(url::Host::Ipv4(address)) => IpAddr::V4(address),
            Some(url::Host::Ipv6(address)) => IpAddr::V6(address),
            Some(url::Host::Domain(address)) => address
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("The RPC client address must be an IP address."))?,
            _ => anyhow::bail!("The RPC client address must be an IP address."),
        };

        for cidr in &self.rpc_portal_whitelist {
            if ip_addr.is_loopback() && cidr.contains(&ip_addr) {
                return Ok(Some(tunnel_info));
            }
        }
        return Err(anyhow::anyhow!(
            "Rpc portal client IP {} not in whitelist: {:?}, ignoring client.",
            ip_addr,
            self.rpc_portal_whitelist
        ));
    }
}

pub struct Instance {
    id: uuid::Uuid,

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx,

    peer_manager: Arc<PeerManager>,
    listener_manager: Arc<Mutex<ListenerManager<PeerManager>>>,
    conn_manager: Arc<ManualConnectorManager>,
    _direct_conn_manager: Arc<DirectConnectorManager>,
    tcp_hole_puncher: Option<Arc<Mutex<TcpHolePunchConnector>>>,
    quic_hole_puncher: Option<Arc<Mutex<QuicHolePunchConnector>>>,
    tracker_discovery: Option<AbortOnDropHandle<()>>,

    ip_proxy: Option<IpProxy>,

    peer_center: Arc<PeerCenterInstance>,

    #[cfg(feature = "socks5")]
    socks5_server: Arc<Socks5Server>,

    proxy_cidrs_monitor: Option<AbortOnDropHandle<()>>,
    public_ipv6_provider_task: ArcPublicIpv6ProviderTaskSlot,

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(config: impl ConfigLoader + 'static) -> Self {
        let global_ctx = Arc::new(GlobalCtx::new(config));

        tracing::info!(
            instance = %global_ctx.get_id(),
            name = %global_ctx.config.get_inst_name(),
            "Creating the network instance"
        );

        let id = global_ctx.get_id();

        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::LinkState,
            global_ctx.clone(),
        ));

        peer_manager.set_allow_loopback_tunnel(false);

        let listener_manager = Arc::new(Mutex::new(ListenerManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        )));

        let conn_manager = Arc::new(ManualConnectorManager::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));

        let mut direct_conn_manager =
            DirectConnectorManager::new(global_ctx.clone(), peer_manager.clone());
        direct_conn_manager.run();
        let direct_conn_manager = Arc::new(direct_conn_manager);

        // No servers, maps or task reapers for disabled transports.
        let flags = global_ctx.flags_arc();
        let enabled = |name| crate::common::config::transport_protocol_enabled(&flags, name);
        let tcp_hole_puncher = (!flags.disable_tcp_hole_punching
            && (enabled("h2") || enabled("wss")))
        .then(|| Arc::new(Mutex::new(TcpHolePunchConnector::new(peer_manager.clone()))));
        let quic_hole_puncher = (!flags.disable_udp_hole_punching && enabled("quic")).then(|| {
            Arc::new(Mutex::new(QuicHolePunchConnector::new(
                peer_manager.clone(),
            )))
        });
        drop(flags);

        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));

        #[cfg(feature = "socks5")]
        let socks5_server = Socks5Server::new(global_ctx.clone(), peer_manager.clone());

        Instance {
            id,

            #[cfg(feature = "tun")]
            nic_ctx: Arc::new(Mutex::new(None)),

            peer_manager,
            listener_manager,
            conn_manager,
            _direct_conn_manager: direct_conn_manager,
            tcp_hole_puncher,
            quic_hole_puncher,
            tracker_discovery: None,

            ip_proxy: None,

            peer_center,

            #[cfg(feature = "socks5")]
            socks5_server,

            proxy_cidrs_monitor: None,
            public_ipv6_provider_task: Arc::new(PublicIpv6ProviderTaskSlot::new()),

            global_ctx,
        }
    }

    pub fn get_conn_manager(&self) -> Arc<ManualConnectorManager> {
        self.conn_manager.clone()
    }

    /// Register configured peers. Reconnect tasks perform dialing and authentication.
    fn add_initial_peers(&self) {
        for peer in self.global_ctx.config.get_peers().iter() {
            self.conn_manager.add_connector_by_url(peer.uri.clone());
        }
    }

    async fn prepare_public_ipv6_config(&self) -> Result<(), Error> {
        validate_public_ipv6_config(&self.global_ctx)?;
        reconcile_public_ipv6_provider_runtime(&self.global_ctx).await;
        Ok(())
    }

    /// Stop the NIC and its DNS runner before replacing the interface.
    ///
    /// Dropping the NIC context removes the direct writer endpoint.
    /// Packets received without an endpoint are dropped.
    #[cfg(feature = "tun")]
    async fn clear_nic_ctx(arc_nic_ctx: ArcNicCtx) {
        #[cfg(feature = "magic-dns")]
        if let Some(old_ctx) = arc_nic_ctx.lock().await.take()
            && let Some(dns_runner) = old_ctx.magic_dns
        {
            dns_runner.dns_runner_cancel_token.cancel();
            tracing::debug!("cancelling dns runner task");
            let ret = dns_runner.dns_runner_task.await;
            tracing::debug!("dns runner task cancelled, ret: {:?}", ret);
        };

        arc_nic_ctx.lock().await.take();

        tracing::debug!("nic ctx cleared.");
    }

    #[cfg(feature = "magic-dns")]
    fn create_magic_dns_runner(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
    ) -> Option<DnsRunner> {
        let ctx = peer_mgr.get_global_ctx();
        if !ctx.config.get_flags().accept_dns {
            return None;
        }

        let runner = DnsRunner::new(
            peer_mgr,
            tun_dev,
            tun_ip,
            MAGIC_DNS_FAKE_IP.parse().unwrap(),
        );
        Some(runner)
    }

    #[cfg(feature = "tun")]
    async fn use_new_nic_ctx(
        arc_nic_ctx: ArcNicCtx,
        nic_ctx: NicCtx,
        #[cfg(feature = "magic-dns")] magic_dns: Option<DnsRunner>,
    ) {
        let mut g = arc_nic_ctx.lock().await;
        *g = Some(NicCtxContainer::new(
            nic_ctx,
            #[cfg(feature = "magic-dns")]
            magic_dns,
        ));
        tracing::debug!("nic ctx updated.");
    }

    // Warning, if there is an IP conflict in the network when using DHCP, the IP will be automatically changed.
    fn check_dhcp_ip_conflict(&self) {
        use rand::Rng;
        let peer_manager_c = Arc::downgrade(&self.peer_manager.clone());
        let global_ctx_c = self.get_global_ctx();
        #[cfg(feature = "tun")]
        let nic_ctx = self.nic_ctx.clone();
        tokio::spawn(async move {
            let default_ipv4_addr = Ipv4Inet::new(Ipv4Addr::new(10, 126, 126, 0), 24).unwrap();
            let mut current_dhcp_ip: Option<Ipv4Inet> = None;
            let mut next_sleep_time = 0;
            let nic_closed_notifier = Arc::new(Notify::new());
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(next_sleep_time)).await;

                let Some(peer_manager_c) = peer_manager_c.upgrade() else {
                    tracing::warn!("peer manager is dropped, stop dhcp check.");
                    return;
                };

                if nic_closed_notifier.notified().now_or_never().is_some() {
                    tracing::debug!("nic ctx is closed, try recreate it");
                    current_dhcp_ip = None;
                }

                // do not allocate ip if no peer connected
                let routes = peer_manager_c.list_routes().await;
                if routes.is_empty() {
                    next_sleep_time = 1;
                    continue;
                } else {
                    next_sleep_time = rand::thread_rng().gen_range(5..10);
                }

                let mut used_ipv4 = HashSet::new();
                for route in routes {
                    let Some(peer_ipv4_addr) = route.ipv4_addr else {
                        continue;
                    };

                    used_ipv4.insert(peer_ipv4_addr.into());
                }

                let dhcp_inet = used_ipv4.iter().next().unwrap_or(&default_ipv4_addr);
                // if old ip is already in this subnet and not conflicted, use it
                if let Some(ip) = current_dhcp_ip
                    && ip.network() == dhcp_inet.network()
                    && !used_ipv4.contains(&ip)
                {
                    continue;
                }

                // find an available ip in the subnet
                let candidate_ipv4_addr = dhcp_inet.network().iter().find(|ip| {
                    ip.address() != dhcp_inet.first_address()
                        && ip.address() != dhcp_inet.last_address()
                        && !used_ipv4.contains(ip)
                });

                if current_dhcp_ip == candidate_ipv4_addr {
                    continue;
                }

                let last_ip = current_dhcp_ip;
                tracing::debug!(
                    ?current_dhcp_ip,
                    ?candidate_ipv4_addr,
                    "dhcp start changing ip"
                );

                #[cfg(feature = "tun")]
                Self::clear_nic_ctx(nic_ctx.clone()).await;

                if let Some(ip) = candidate_ipv4_addr {
                    if global_ctx_c.no_tun() {
                        current_dhcp_ip = Some(ip);
                        global_ctx_c.set_ipv4(Some(ip));
                        global_ctx_c
                            .issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                        continue;
                    }

                    #[cfg(all(not(mobile), feature = "tun"))]
                    {
                        let mut new_nic_ctx = NicCtx::new(
                            global_ctx_c.clone(),
                            &peer_manager_c,
                            nic_closed_notifier.clone(),
                        );
                        if let Err(e) = new_nic_ctx.run(Some(ip), global_ctx_c.get_ipv6()).await {
                            tracing::error!(
                                ?current_dhcp_ip,
                                ?candidate_ipv4_addr,
                                ?e,
                                "add ip failed"
                            );
                            global_ctx_c.set_ipv4(None);
                            continue;
                        }
                        #[cfg(feature = "magic-dns")]
                        let ifname = new_nic_ctx.ifname().await;
                        Self::use_new_nic_ctx(
                            nic_ctx.clone(),
                            new_nic_ctx,
                            #[cfg(feature = "magic-dns")]
                            Self::create_magic_dns_runner(peer_manager_c.clone(), ifname, ip),
                        )
                        .await;
                    }

                    current_dhcp_ip = Some(ip);
                    global_ctx_c.set_ipv4(Some(ip));
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Changed(last_ip, Some(ip)));
                } else {
                    current_dhcp_ip = None;
                    global_ctx_c.set_ipv4(None);
                    global_ctx_c.issue_event(GlobalCtxEvent::DhcpIpv4Conflicted(last_ip));
                }
            }
        });
    }

    #[cfg(all(not(mobile), feature = "tun"))]
    fn check_for_static_ip(&self, first_round_output: oneshot::Sender<Result<(), Error>>) {
        let ipv4_addr = self.global_ctx.get_ipv4();
        let ipv6_addr = self.global_ctx.get_ipv6();

        // Only run if we have at least one IP address (IPv4 or IPv6)
        if ipv4_addr.is_none() && ipv6_addr.is_none() {
            let _ = first_round_output.send(Ok(()));
            return;
        }

        let nic_ctx = self.nic_ctx.clone();
        let peer_mgr = Arc::downgrade(&self.peer_manager);

        tokio::spawn(async move {
            let mut output_tx = Some(first_round_output);
            loop {
                let close_notifier = Arc::new(Notify::new());
                {
                    let Some(peer_mgr) = peer_mgr.upgrade() else {
                        tracing::warn!("peer manager is dropped, stop static ip check.");
                        if let Some(output_tx) = output_tx.take() {
                            let _ = output_tx.send(Err(Error::Unknown));
                            return;
                        }
                        return;
                    };

                    let mut new_nic_ctx =
                        NicCtx::new(peer_mgr.get_global_ctx(), &peer_mgr, close_notifier.clone());

                    if let Err(e) = new_nic_ctx.run(ipv4_addr, ipv6_addr).await {
                        if let Some(output_tx) = output_tx.take() {
                            let _ = output_tx.send(Err(e));
                            return;
                        }
                        tracing::error!("failed to create new nic ctx, err: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }

                    // Create Magic DNS runner only if we have IPv4
                    #[cfg(feature = "magic-dns")]
                    {
                        let ifname = new_nic_ctx.ifname().await;
                        let dns_runner = if let Some(ipv4) = ipv4_addr {
                            Self::create_magic_dns_runner(peer_mgr, ifname, ipv4)
                        } else {
                            None
                        };
                        Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx, dns_runner).await;
                    }
                    #[cfg(not(feature = "magic-dns"))]
                    Self::use_new_nic_ctx(nic_ctx.clone(), new_nic_ctx).await;
                }

                if let Some(output_tx) = output_tx.take() {
                    let _ = output_tx.send(Ok(()));
                }

                // NOTICE: make sure we do not hold the peer manager here,
                while close_notifier.notified().now_or_never().is_none() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if peer_mgr.strong_count() == 0 {
                        tracing::warn!("peer manager is dropped, stop static ip check.");
                        return;
                    }
                }
            }
        });
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.prepare_public_ipv6_config().await?;
        self.listener_manager
            .lock()
            .await
            .prepare_listeners()
            .await?;
        self.listener_manager.lock().await.run().await?;
        self.peer_manager.run().await?;
        ensure_public_ipv6_provider_reconcile_task(
            &self.global_ctx,
            &self.public_ipv6_provider_task,
        )
        .await;

        #[cfg(feature = "tun")]
        {
            Self::clear_nic_ctx(self.nic_ctx.clone()).await;

            #[cfg(not(mobile))]
            if self.global_ctx.config.get_flags().tun_mode()
                == crate::common::config::TunMode::Kernel
            {
                let (output_tx, output_rx) = oneshot::channel();
                self.check_for_static_ip(output_tx);
                output_rx.await.unwrap()?;
            }
        }

        if self.global_ctx.config.get_dhcp() {
            self.check_dhcp_ip_conflict();
        }

        self.global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&self.global_ctx)?.as_ref());

        // run after tun device created, so listener can bind to tun device, which may be required by win 10
        self.ip_proxy = Some(IpProxy::new(
            self.get_global_ctx(),
            self.get_peer_manager(),
        )?);
        self.run_ip_proxy().await?;

        if let Some(puncher) = &self.tcp_hole_puncher {
            puncher.lock().await.run().await?;
        }
        if let Some(puncher) = &self.quic_hole_puncher {
            puncher.lock().await.run();
        }

        self.peer_center.init().await;
        let route_calc = self.peer_center.get_cost_calculator();
        self.peer_manager
            .get_route()
            .set_route_cost_fn(route_calc)
            .await;

        self.add_initial_peers();
        if let Some(config) = self.global_ctx.config.get_tracker_discovery() {
            self.tracker_discovery = Some(crate::connector::tracker_discovery::start(
                self.peer_manager.clone(),
                config,
            )?);
        }

        let monitor = super::proxy_cidrs_monitor::ProxyCidrsMonitor::new(
            self.peer_manager.clone(),
            self.global_ctx.clone(),
        );
        self.proxy_cidrs_monitor = Some(monitor.start());

        #[cfg(feature = "socks5")]
        self.socks5_server.run().await?;

        Ok(())
    }

    pub async fn run_ip_proxy(&mut self) -> Result<(), Error> {
        if self.ip_proxy.is_none() {
            return Err(anyhow::anyhow!("ip proxy not enabled.").into());
        }
        self.ip_proxy.as_ref().unwrap().start().await?;
        Ok(())
    }

    pub fn get_peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn get_socks5_server(&self) -> Arc<Socks5Server> {
        self.socks5_server.clone()
    }

    pub async fn close_peer_conn(
        &mut self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        self.peer_manager
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await?;
        Ok(())
    }

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }

    /// Return management handles that cannot keep a stopped instance alive.
    pub fn control_instance(&self) -> ControlInstance {
        ControlInstance {
            peer_manager: Arc::downgrade(&self.peer_manager),
            global_ctx: Arc::downgrade(&self.global_ctx),
            conn_manager: Arc::downgrade(&self.conn_manager),
        }
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    #[cfg(feature = "tun")]
    pub fn get_nic_ctx(&self) -> ArcNicCtx {
        self.nic_ctx.clone()
    }

    #[cfg(mobile)]
    pub async fn setup_nic_ctx_for_mobile(
        nic_ctx: ArcNicCtx,
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        fd: i32,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("setup_nic_ctx_for_mobile, fd: {}", fd);
        Self::clear_nic_ctx(nic_ctx.clone()).await;
        if fd <= 0 {
            return Ok(());
        }
        let close_notifier = Arc::new(Notify::new());
        let mut new_nic_ctx =
            NicCtx::new(global_ctx.clone(), &peer_manager, close_notifier.clone());
        new_nic_ctx
            .run_for_mobile(fd)
            .await
            .with_context(|| "attach mobile NIC failed")?;

        #[cfg(feature = "magic-dns")]
        let magic_dns_runner = global_ctx
            .get_ipv4()
            .and_then(|ipv4| Self::create_magic_dns_runner(peer_manager.clone(), None, ipv4));
        Self::use_new_nic_ctx(
            nic_ctx.clone(),
            new_nic_ctx,
            #[cfg(feature = "magic-dns")]
            magic_dns_runner,
        )
        .await;
        Ok(())
    }

    pub async fn clear_resources(&mut self) {
        self.public_ipv6_provider_task.shutdown().await;
        self.peer_manager.clear_resources().await;
        #[cfg(feature = "tun")]
        let _ = self.nic_ctx.lock().await.take();
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let my_peer_id = self.peer_manager.my_peer_id();
        let pm = Arc::downgrade(&self.peer_manager);
        #[cfg(feature = "tun")]
        let nic_ctx = self.nic_ctx.clone();
        tokio::spawn(async move {
            #[cfg(feature = "tun")]
            nic_ctx.lock().await.take();
            if let Some(pm) = pm.upgrade() {
                pm.clear_resources().await;
            };

            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 10 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if pm.strong_count() == 0 {
                    tracing::info!(
                        "Instance for peer {} dropped, all resources cleared.",
                        my_peer_id
                    );
                    return;
                }
            }

            debug_assert!(
                false,
                "Instance for peer {} dropped, but resources not cleared in 1 seconds.",
                my_peer_id
            );
        });
    }
}

#[cfg(test)]
mod protocol_memory_tests {
    use super::*;
    use crate::common::config::TomlConfigLoader;
    #[tokio::test]
    async fn disabled_punchers_are_never_constructed() {
        for protocol in ["quic", "h2", "wss"] {
            let config = TomlConfigLoader::default();
            let mut flags = config.get_flags();
            flags.default_protocol = protocol.into();
            flags.enabled_protocols = vec![protocol.into()];
            config.set_flags(flags);
            let instance = Instance::new(config);
            assert_eq!(instance.quic_hole_puncher.is_some(), protocol == "quic");
            assert_eq!(instance.tcp_hole_puncher.is_some(), protocol != "quic");
        }
    }
    #[tokio::test]
    async fn disabled_factories_fail_before_dns_and_socket_allocation() {
        use crate::common::global_ctx::tests::get_mock_global_ctx;
        for protocol in ["quic", "h2", "wss"] {
            let ctx = get_mock_global_ctx();
            let mut flags = ctx.get_flags();
            flags.default_protocol = protocol.into();
            flags.enabled_protocols = vec![protocol.into()];
            ctx.set_flags(flags);
            for other in ["quic", "h2", "wss"] {
                if protocol == other {
                    continue;
                }
                let url =
                    url::Url::parse(&format!("{other}://must-not-resolve.invalid:12345")).unwrap();
                let err = crate::connector::create_connector_by_url(
                    url.as_str(),
                    &ctx,
                    crate::tunnel::IpVersion::Both,
                )
                .await
                .err()
                .unwrap();
                assert!(err.to_string().contains("disabled by transport.protocols"));
                let err = super::super::listeners::create_listener_by_url(&url, ctx.clone())
                    .err()
                    .unwrap();
                assert!(err.to_string().contains("disabled by transport.protocols"));
            }
        }
    }
}
