use std::{
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
        underlay_policy::UnderlayPolicy,
    },
    peers::peer_manager::PeerManager,
    tunnel::{self, IpScheme, Tunnel, TunnelListener, tcp::TcpTunnelListener},
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
            if enable_ipv6 {
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
    crate::common::config::ensure_transport_protocol_enabled(&global_ctx.flags_arc(), l.scheme())?;
    let socket_mark = global_ctx.config.get_flags().socket_mark;
    let scheme = IpScheme::try_from(l)?;
    Ok(match scheme {
        IpScheme::Tcp => {
            let mut l = TcpTunnelListener::new(l.clone());
            l.set_socket_mark(socket_mark);
            l.set_underlay_policy(global_ctx.get_underlay_policy());
            l.set_global_ctx(&global_ctx);
            l.boxed()
        }
        IpScheme::Quic => {
            // QUIC reads socket_mark from global_ctx in QuicEndpointManager
            tunnel::quic::QuicTunnelListener::new(l.clone(), global_ctx.clone()).boxed()
        }
        IpScheme::Wss => {
            let mut l = tunnel::websocket::WsTunnelListener::new(l.clone());
            l.set_global_ctx(&global_ctx);
            l.set_socket_mark(socket_mark);
            l.boxed()
        }
    })
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

const MAX_CONCURRENT_EXTERNAL_HANDSHAKES: usize = 32;
const MAX_CONCURRENT_HANDSHAKES_PER_LISTENER: usize = 16;
const MAX_CONCURRENT_HANDSHAKES_PER_SOURCE: usize = 4;

#[derive(Debug)]
struct HandshakeAdmission {
    global: Arc<Semaphore>,
    sources: std::sync::Mutex<HashMap<String, usize>>,
}

impl HandshakeAdmission {
    fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(MAX_CONCURRENT_EXTERNAL_HANDSHAKES)),
            sources: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn try_reserve(
        self: &Arc<Self>,
        listener: &Arc<Semaphore>,
        source: String,
    ) -> Option<HandshakePermit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let listener = listener.clone().try_acquire_owned().ok()?;
        let mut sources = self.sources.lock().unwrap();
        let count = sources.entry(source.clone()).or_default();
        if *count >= MAX_CONCURRENT_HANDSHAKES_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(HandshakePermit {
            source,
            admission: self.clone(),
            _global: global,
            _listener: listener,
        })
    }

    fn release(&self, source: &str) {
        let mut sources = self.sources.lock().unwrap();
        let remove = if let Some(count) = sources.get_mut(source) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            sources.remove(source);
        }
    }
}

#[derive(Debug)]
struct HandshakePermit {
    source: String,
    admission: Arc<HandshakeAdmission>,
    _global: OwnedSemaphorePermit,
    _listener: OwnedSemaphorePermit,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.admission.release(&self.source);
    }
}

fn handshake_source(info: &crate::proto::common::TunnelInfo) -> String {
    let Some(remote) = info.remote_addr.as_ref() else {
        return "unknown".to_string();
    };
    url::Url::try_from(remote.clone())
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| remote.to_string())
}

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
    handshake_admission: Arc<HandshakeAdmission>,

    tasks: JoinSet<()>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
            listeners: Vec::new(),
            peer_manager: Arc::downgrade(&peer_manager),
            handshake_admission: Arc::new(HandshakeAdmission::new()),
            tasks: JoinSet::new(),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
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
        handshake_admission: Arc<HandshakeAdmission>,
    ) {
        let listener_admission = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES_PER_LISTENER));
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
                let admission = if l.local_url().scheme() == "ring" {
                    None
                } else {
                    match handshake_admission
                        .try_reserve(&listener_admission, handshake_source(&tunnel_info))
                    {
                        Some(permit) => Some(permit),
                        None => {
                            tracing::warn!(
                                ?l,
                                "drop accepted tunnel because handshake admission is full"
                            );
                            continue;
                        }
                    }
                };

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
                    let _admission = admission;
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
                self.handshake_admission.clone(),
            ));
        }

        Ok(())
    }
}
