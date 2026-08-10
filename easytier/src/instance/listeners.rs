use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use tokio::task::JoinSet;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
        underlay_policy::UnderlayPolicy,
    },
    peers::peer_manager::PeerManager,
    tunnel::{
        self, IpScheme, Tunnel, TunnelListener, TunnelScheme, ring::RingTunnelListener,
        tcp::TcpTunnelListener, udp::UdpTunnelListener,
    },
    utils::BoxExt,
};

fn expand_strict_listener_urls(
    listener: &url::Url,
    allowed_ipv4s: &[Ipv4Addr],
    allowed_ipv6s: &[Ipv6Addr],
    enable_ipv6: bool,
    policy: &UnderlayPolicy,
) -> Result<Vec<url::Url>, Error> {
    if !policy.is_active() {
        return Ok(vec![listener.clone()]);
    }

    let host = listener
        .host_str()
        .and_then(|host| IpAddr::from_str(host).ok())
        .ok_or_else(|| {
            tunnel::TunnelError::UnderlayPolicyDenied(format!(
                "strict underlay policy requires an IP listener host: {listener}"
            ))
        })?;

    if !host.is_unspecified() {
        let address_is_allowed = match host {
            IpAddr::V4(addr) => {
                policy.allows_ip(host)
                    && (!policy.has_interface_rules() || allowed_ipv4s.contains(&addr))
            }
            IpAddr::V6(addr) => {
                policy.allows_ip(host)
                    && (!policy.has_interface_rules() || allowed_ipv6s.contains(&addr))
            }
        };
        if address_is_allowed {
            return Ok(vec![listener.clone()]);
        }
        return Err(tunnel::TunnelError::UnderlayPolicyDenied(format!(
            "listener address {host} is denied or is not on a proven allowed interface"
        ))
        .into());
    }

    let mut addresses = Vec::new();
    match host {
        IpAddr::V4(_) => {
            addresses.extend(allowed_ipv4s.iter().copied().map(IpAddr::V4));
            if enable_ipv6 && listener.scheme() != "faketcp" {
                addresses.extend(allowed_ipv6s.iter().copied().map(IpAddr::V6));
            }
        }
        IpAddr::V6(_) => addresses.extend(allowed_ipv6s.iter().copied().map(IpAddr::V6)),
    }

    let urls = addresses
        .into_iter()
        .map(|address| {
            let mut expanded = listener.clone();
            expanded.set_ip_host(address).map_err(|_| {
                Error::InvalidUrl(format!(
                    "failed to bind strict listener {listener} to {address}"
                ))
            })?;
            Ok(expanded)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    if urls.is_empty() {
        return Err(tunnel::TunnelError::UnderlayPolicyDenied(format!(
            "no allowed local source address is available for listener {listener}"
        ))
        .into());
    }

    Ok(urls)
}

pub fn create_listener_by_url(
    l: &url::Url,
    global_ctx: ArcGlobalCtx,
) -> Result<Box<dyn TunnelListener>, Error> {
    use crate::common::config::ConfigLoader;
    let socket_mark = global_ctx.config.get_flags().socket_mark;
    Ok(match l.try_into()? {
        TunnelScheme::Ip(scheme) => match scheme {
            IpScheme::Tcp => {
                let mut l = TcpTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            IpScheme::Udp => {
                let mut l = UdpTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.set_underlay_policy(global_ctx.get_underlay_policy());
                l.boxed()
            }
            #[cfg(feature = "wireguard")]
            IpScheme::Wg => {
                use crate::tunnel::wireguard::{WgConfig, WgTunnelListener};
                let nid = global_ctx.get_network_identity();
                let wg_config = WgConfig::new_from_network_identity(
                    &nid.network_name,
                    &nid.network_secret.unwrap_or_default(),
                );
                let mut l = WgTunnelListener::new(l.clone(), wg_config);
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            #[cfg(feature = "quic")]
            IpScheme::Quic => {
                // QUIC reads socket_mark from global_ctx in QuicEndpointManager
                tunnel::quic::QuicTunnelListener::new(l.clone(), global_ctx.clone()).boxed()
            }
            #[cfg(feature = "websocket")]
            IpScheme::Ws | IpScheme::Wss => {
                let mut l = tunnel::websocket::WsTunnelListener::new(l.clone());
                l.set_socket_mark(socket_mark);
                l.boxed()
            }
            #[cfg(feature = "faketcp")]
            IpScheme::FakeTcp => tunnel::fake_tcp::FakeTcpTunnelListener::new(l.clone()).boxed(),
        },
        #[cfg(unix)]
        TunnelScheme::Unix => tunnel::unix::UnixSocketTunnelListener::new(l.clone()).boxed(),
        _ => return Err(Error::InvalidUrl(l.to_string())),
    })
}

pub fn is_url_host_ipv6(l: &url::Url) -> bool {
    l.host_str().is_some_and(|h| h.contains(':'))
}

pub fn is_url_host_unspecified(l: &url::Url) -> bool {
    if let Ok(ip) = IpAddr::from_str(l.host_str().unwrap_or_default()) {
        ip.is_unspecified()
    } else {
        false
    }
}

#[async_trait]
pub trait TunnelHandlerForListener {
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error>;
}

#[async_trait]
impl TunnelHandlerForListener for PeerManager {
    #[tracing::instrument]
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
        self.add_tunnel_as_server(tunnel, true).await
    }
}

pub trait ListenerCreatorTrait: Fn() -> Box<dyn TunnelListener> + Send + Sync {}
impl<T: Send + Sync> ListenerCreatorTrait for T where T: Fn() -> Box<dyn TunnelListener> + Send {}
pub type ListenerCreator = Box<dyn ListenerCreatorTrait>;

#[derive(Clone)]
struct ListenerFactory {
    creator_fn: Arc<ListenerCreator>,
    must_succ: bool,
}

pub struct ListenerManager<H> {
    global_ctx: ArcGlobalCtx,
    net_ns: NetNS,
    listeners: Vec<ListenerFactory>,
    peer_manager: Weak<H>,

    tasks: JoinSet<()>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
            listeners: Vec::new(),
            peer_manager: Arc::downgrade(&peer_manager),
            tasks: JoinSet::new(),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
        let self_id = self.global_ctx.get_id();
        self.add_listener(
            move || {
                Box::new(RingTunnelListener::new(
                    format!("ring://{}", self_id).parse().unwrap(),
                ))
            },
            true,
        )
        .await?;

        let policy = self.global_ctx.get_underlay_policy();
        let flags = self.global_ctx.get_flags();
        let (allowed_ipv4s, allowed_ipv6s) = if policy.is_active() {
            let addresses = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
            (
                addresses
                    .interface_ipv4s
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<Ipv4Addr>>(),
                addresses
                    .interface_ipv6s
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<Ipv6Addr>>(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        for l in self.global_ctx.config.get_listener_uris().iter() {
            let l = l.clone();

            if policy.is_active() {
                let strict_listeners = expand_strict_listener_urls(
                    &l,
                    &allowed_ipv4s,
                    &allowed_ipv6s,
                    flags.enable_ipv6,
                    &policy,
                )?;
                for strict_listener in strict_listeners {
                    create_listener_by_url(&strict_listener, self.global_ctx.clone())?;
                    let ctx = self.global_ctx.clone();
                    self.add_listener(
                        move || create_listener_by_url(&strict_listener, ctx.clone()).unwrap(),
                        true,
                    )
                    .await?;
                }
                continue;
            }

            let Ok(_) = create_listener_by_url(&l, self.global_ctx.clone()) else {
                let msg = format!("failed to get listener by url: {}, maybe not supported", l);
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(l.clone(), msg));
                continue;
            };
            let ctx = self.global_ctx.clone();

            let listener = l.clone();
            self.add_listener(
                move || create_listener_by_url(&listener, ctx.clone()).unwrap(),
                true,
            )
            .await?;

            if self.global_ctx.config.get_flags().enable_ipv6
                && !is_url_host_ipv6(&l)
                && is_url_host_unspecified(&l)
                // quic enables dual-stack by default, may conflict with v4 listener
                && l.scheme() != "quic" && l.scheme() != "faketcp"
            {
                let mut ipv6_listener = l.clone();
                ipv6_listener
                    .set_host(Some("[::]".to_string().as_str()))
                    .with_context(|| format!("failed to set ipv6 host for listener: {}", l))?;
                let ctx = self.global_ctx.clone();
                self.add_listener(
                    move || create_listener_by_url(&ipv6_listener, ctx.clone()).unwrap(),
                    false,
                )
                .await?;
            }
        }

        Ok(())
    }

    pub async fn add_listener<C: ListenerCreatorTrait + 'static>(
        &mut self,
        creator: C,
        must_succ: bool,
    ) -> Result<(), Error> {
        self.listeners.push(ListenerFactory {
            creator_fn: Arc::new(Box::new(creator)),
            must_succ,
        });
        Ok(())
    }

    #[tracing::instrument(skip(creator))]
    async fn run_listener(
        creator: Arc<ListenerCreator>,
        peer_manager: Weak<H>,
        global_ctx: ArcGlobalCtx,
    ) {
        let mut err_count = 0;
        loop {
            let mut l = (creator)();
            let _g = global_ctx.net_ns.guard();
            match l.listen().await {
                Ok(_) => {
                    err_count = 0;
                    global_ctx.add_running_listener(l.local_url());
                    global_ctx.issue_event(GlobalCtxEvent::ListenerAdded(l.local_url()));
                }
                Err(e) => {
                    tracing::error!(?e, ?l, "listener listen error");
                    global_ctx.issue_event(GlobalCtxEvent::ListenerAddFailed(
                        l.local_url(),
                        format!("error: {:?}, retry listen later...", e),
                    ));
                    err_count += 1;
                    if err_count > 5 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
            loop {
                let ret = match l.accept().await {
                    Ok(ret) => ret,
                    Err(e) => {
                        global_ctx.issue_event(GlobalCtxEvent::ListenerAcceptFailed(
                            l.local_url(),
                            format!("error: {:?}, retry listen later...", e),
                        ));
                        tracing::error!(?e, ?l, "listener accept error");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                };

                let tunnel_info = ret.info().unwrap();
                global_ctx.issue_event(GlobalCtxEvent::ConnectionAccepted(
                    tunnel_info
                        .local_addr
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                    tunnel_info
                        .remote_addr
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                ));
                tracing::info!(ret = ?ret, "conn accepted");
                let peer_manager = peer_manager.clone();
                let global_ctx = global_ctx.clone();
                tokio::spawn(async move {
                    let Some(peer_manager) = peer_manager.upgrade() else {
                        tracing::error!("peer manager is gone, cannot handle tunnel");
                        return;
                    };
                    let server_ret = peer_manager.handle_tunnel(ret).await;
                    if let Err(e) = &server_ret {
                        global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                            tunnel_info.local_addr.unwrap_or_default().to_string(),
                            tunnel_info.remote_addr.unwrap_or_default().to_string(),
                            e.to_string(),
                        ));
                        tracing::error!(error = ?e, "handle conn error");
                    }
                });
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        for listener in &self.listeners {
            if listener.must_succ {
                // try listen once
                let mut l = (listener.creator_fn)();
                let _g = self.net_ns.guard();
                l.listen()
                    .await
                    .with_context(|| format!("failed to listen on {}", l.local_url()))?;
            }

            self.tasks.spawn(Self::run_listener(
                listener.creator_fn.clone(),
                self.peer_manager.clone(),
                self.global_ctx.clone(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI32, Ordering};

    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{TunnelConnector, TunnelError, packet_def::ZCPacket, ring::RingTunnelConnector},
    };

    use super::*;

    #[test]
    fn strict_policy_expands_wildcard_listener_to_allowed_sources() {
        let policy = UnderlayPolicy::new(
            &["utun5".into()],
            &["100.64.0.0/10".into(), "fd7a:115c:a1e0::/48".into()],
        )
        .unwrap();
        let listener = url::Url::parse("quic://0.0.0.0:11010").unwrap();

        let expanded = expand_strict_listener_urls(
            &listener,
            &["192.168.50.4".parse().unwrap()],
            &["2001:db8::4".parse().unwrap()],
            true,
            &policy,
        )
        .unwrap();

        assert_eq!(
            expanded,
            vec![
                url::Url::parse("quic://192.168.50.4:11010").unwrap(),
                url::Url::parse("quic://[2001:db8::4]:11010").unwrap(),
            ]
        );
    }

    #[test]
    fn strict_policy_rejects_denied_or_unproven_listener_sources() {
        let policy = UnderlayPolicy::new(&["utun5".into()], &["100.64.0.0/10".into()]).unwrap();

        let denied = expand_strict_listener_urls(
            &url::Url::parse("tcp://100.108.1.2:11010").unwrap(),
            &["192.168.50.4".parse().unwrap()],
            &[],
            false,
            &policy,
        );
        assert!(matches!(
            denied,
            Err(Error::TunnelError(
                tunnel::TunnelError::UnderlayPolicyDenied(_)
            ))
        ));

        let empty = expand_strict_listener_urls(
            &url::Url::parse("udp://0.0.0.0:11010").unwrap(),
            &[],
            &[],
            false,
            &policy,
        );
        assert!(matches!(
            empty,
            Err(Error::TunnelError(
                tunnel::TunnelError::UnderlayPolicyDenied(_)
            ))
        ));
    }

    #[derive(Debug)]
    struct MockListenerHandler {}

    #[async_trait]
    impl TunnelHandlerForListener for MockListenerHandler {
        async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
            let data = "abc";
            let (_recv, mut send) = tunnel.split();

            let zc_packet = ZCPacket::new_with_payload(data.as_bytes());
            send.send(zc_packet).await.unwrap();
            Err(Error::Unknown)
        }
    }

    #[tokio::test]
    async fn handle_error_in_accept() {
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(get_mock_global_ctx(), handler.clone());

        let ring_id = format!("ring://{}", uuid::Uuid::new_v4());

        let ring_id_clone = ring_id.clone();
        listener_mgr
            .add_listener(
                move || Box::new(RingTunnelListener::new(ring_id_clone.parse().unwrap())),
                true,
            )
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let connect_once = |ring_id| async move {
            let tunnel = RingTunnelConnector::new(ring_id).connect().await.unwrap();
            let (mut recv, _send) = tunnel.split();
            assert_eq!(
                recv.next().await.unwrap().unwrap().payload(),
                "abc".as_bytes()
            );
            tunnel
        };

        timeout(std::time::Duration::from_secs(1), async move {
            connect_once(ring_id.parse().unwrap()).await;
            // handle tunnel fail should not impact the second connect
            connect_once(ring_id.parse().unwrap()).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retry_listen() {
        let counter = Arc::new(AtomicI32::new(0));
        let drop_counter = Arc::new(AtomicI32::new(0));
        struct MockListener {
            counter: Arc<AtomicI32>,
            drop_counter: Arc<AtomicI32>,
        }

        #[async_trait::async_trait]
        impl TunnelListener for MockListener {
            async fn listen(&mut self) -> Result<(), TunnelError> {
                self.counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }

            async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Err(TunnelError::BufferFull)
            }

            fn local_url(&self) -> url::Url {
                "mock://".parse().unwrap()
            }
        }

        impl Drop for MockListener {
            fn drop(&mut self) {
                self.drop_counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(get_mock_global_ctx(), handler.clone());
        let counter_clone = counter.clone();
        let drop_counter_clone = drop_counter.clone();
        listener_mgr
            .add_listener(
                move || {
                    Box::new(MockListener {
                        counter: counter_clone.clone(),
                        drop_counter: drop_counter_clone.clone(),
                    })
                },
                true,
            )
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        assert!(counter.load(Ordering::Relaxed) >= 2);
        assert!(drop_counter.load(Ordering::Relaxed) >= 1);
    }
}
