// try connect peers directly, with either its public ip or lan ip

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use quanta::Instant;

use crate::{
    common::{
        PeerId, dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx,
        stun::StunInfoCollectorTrait, underlay_policy::UnderlayPolicy,
    },
    connector::udp_hole_punch::handle_rpc_result,
    peers::{
        peer_conn::PeerConnId,
        peer_manager::PeerManager,
        peer_rpc::PeerRpcManager,
        peer_rpc_service::DirectConnectorManagerRpcServer,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory, DirectConnectorRpcServer,
            GetIpListRequest, GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::controller::BaseController,
    },
    tunnel::{IpVersion, TunnelConnector, TunnelError, matches_protocol, udp::UdpTunnelConnector},
    use_global_var,
};

use super::{
    create_connector_by_url, should_background_p2p_with_peer, should_try_p2p_with_peer,
    udp_hole_punch,
};
use crate::tunnel::{FromUrl, IpScheme, TunnelScheme, matches_scheme};
use anyhow::Context;
use rand::Rng;
use socket2::Protocol;
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};
use url::Host;

pub const DIRECT_CONNECTOR_SERVICE_ID: u32 = 1;
pub const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC: u64 = 300;
const MAX_IPV6_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 16;
const DIRECT_PROBE_GRACE_PERIOD: Duration = Duration::from_millis(1_500);

fn direct_protocol_priority(scheme: &str, configured_default: &str) -> u8 {
    if scheme == configured_default {
        return 4;
    }
    match scheme {
        "udp" => 3,
        "quic" => 2,
        "tcp" => 1,
        _ => 0,
    }
}

static TESTING: AtomicBool = AtomicBool::new(false);

async fn wait_for_probe_group<F>(
    tasks: &mut JoinSet<Result<(), Error>>,
    has_success: F,
    grace_period: Duration,
) -> Vec<Result<Result<(), Error>, tokio::task::JoinError>>
where
    F: Fn() -> bool,
{
    let mut results = Vec::new();
    let mut deadline = has_success().then(|| tokio::time::Instant::now() + grace_period);

    while !tasks.is_empty() {
        let next = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(next) => next,
                Err(_) => break,
            }
        } else {
            tasks.join_next().await
        };

        let Some(result) = next else {
            break;
        };
        results.push(result);

        if deadline.is_none() && has_success() {
            deadline = Some(tokio::time::Instant::now() + grace_period);
        }
    }

    if !tasks.is_empty() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    results
}

async fn bind_direct_udp_socket(
    global_ctx: &ArcGlobalCtx,
    ipv4: bool,
) -> Result<Arc<UdpSocket>, Error> {
    let policy = global_ctx.get_underlay_policy();
    if !policy.is_active() {
        let bind_addr = if ipv4 { "0.0.0.0:0" } else { "[::]:0" };
        return Ok(Arc::new(
            crate::tunnel::common::bind::<UdpSocket>()
                .addr(bind_addr.parse().unwrap())
                .net_ns(global_ctx.net_ns.clone())
                .only_v6(!ipv4)
                .maybe_socket_mark(global_ctx.get_flags().socket_mark)
                .call()?,
        ));
    }

    let ip_list = global_ctx.get_ip_collector().collect_ip_addrs().await;
    let sources = if ipv4 {
        ip_list
            .interface_ipv4s
            .into_iter()
            .map(|ip| SocketAddr::new(Ipv4Addr::from(ip).into(), 0))
            .collect::<Vec<_>>()
    } else {
        ip_list
            .interface_ipv6s
            .into_iter()
            .map(|ip| SocketAddr::new(Ipv6Addr::from(ip).into(), 0))
            .collect::<Vec<_>>()
    };

    for source in sources {
        match crate::tunnel::common::bind::<UdpSocket>()
            .addr(source)
            .net_ns(global_ctx.net_ns.clone())
            .only_v6(source.is_ipv6())
            .maybe_socket_mark(global_ctx.get_flags().socket_mark)
            .call()
        {
            Ok(socket) => return Ok(Arc::new(socket)),
            Err(error) => tracing::debug!(?source, ?error, "direct UDP source bind failed"),
        }
    }

    Err(TunnelError::UnderlayPolicyDenied(format!(
        "no allowed local {} source is available for direct UDP hole punching",
        if ipv4 { "IPv4" } else { "IPv6" }
    ))
    .into())
}

fn mapped_listener_port(url: &url::Url) -> Option<u16> {
    url.port().or_else(|| {
        TunnelScheme::try_from(url)
            .ok()
            .and_then(|scheme| IpScheme::try_from(scheme).ok())
            .map(IpScheme::default_port)
    })
}

async fn resolve_mapped_listener_addrs(listener: &url::Url) -> Result<Vec<SocketAddr>, Error> {
    socket_addrs(listener, || mapped_listener_port(listener)).await
}

fn direct_listener_allowed_before_resolution(policy: &UnderlayPolicy, listener: &url::Url) -> bool {
    !policy.is_active()
        || listener
            .host_str()
            .is_some_and(|host| host.parse::<IpAddr>().is_ok())
}

fn is_usable_public_ipv6_candidate(ip: &Ipv6Addr, global_ctx: &ArcGlobalCtx) -> bool {
    is_usable_public_ipv6_candidate_with_mode(ip, global_ctx, TESTING.load(Ordering::Relaxed))
}

fn is_usable_public_ipv6_candidate_with_mode(
    ip: &Ipv6Addr,
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> bool {
    !global_ctx.is_ip_easytier_managed_ipv6(ip)
        && global_ctx.get_underlay_policy().allows_ip((*ip).into())
        && (testing
            || (!ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()))
}

fn push_ipv6_hole_punch_candidate(
    candidates: &mut Vec<Ipv6Addr>,
    ip: Ipv6Addr,
    global_ctx: &ArcGlobalCtx,
    limit: usize,
) {
    if candidates.len() >= limit
        || !is_usable_public_ipv6_candidate(&ip, global_ctx)
        || candidates.contains(&ip)
    {
        return;
    }
    candidates.push(ip);
}

async fn collect_ipv6_hole_punch_candidates(global_ctx: &ArcGlobalCtx) -> Vec<Ipv6Addr> {
    let mut candidates = Vec::new();
    for ip in global_ctx
        .get_stun_info_collector()
        .get_stun_info()
        .public_ip
        .iter()
        .filter_map(|ip| ip.parse::<Ipv6Addr>().ok())
    {
        push_ipv6_hole_punch_candidate(
            &mut candidates,
            ip,
            global_ctx,
            MAX_IPV6_HOLE_PUNCH_CONNECTOR_ADDRS,
        );
    }

    let ip_list = global_ctx.get_ip_collector().collect_ip_addrs().await;
    for ip in ip_list
        .interface_ipv6s
        .iter()
        .chain(ip_list.public_ipv6.iter())
        .map(|ip| Ipv6Addr::from(*ip))
    {
        push_ipv6_hole_punch_candidate(
            &mut candidates,
            ip,
            global_ctx,
            MAX_IPV6_HOLE_PUNCH_CONNECTOR_ADDRS,
        );
    }

    candidates
}

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];
        let allow_public_server = use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER);
        let flags = self.get_global_ctx().get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let now = Instant::now();

        let routes = self.list_routes().await;
        for route in routes.iter() {
            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                lazy_p2p,
                flags.disable_p2p,
                flags.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                allow_public_server,
                flags.disable_p2p,
                flags.need_p2p,
            ) && self.has_recent_traffic(route.peer_id, now);
            if static_allowed || dynamic_allowed {
                ret.push(route.peer_id);
            }
        }

        ret
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstBlackListItem(PeerId, String);

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstListenerUrlBlackListItem(PeerId, String);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_listener_blacklist: timedmap::TimedMap<DstListenerUrlBlackListItem, ()>,
    peer_black_list: timedmap::TimedMap<PeerId, ()>,
}

impl DirectConnectorManagerData {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx,
            peer_manager,
            dst_listener_blacklist: timedmap::TimedMap::new(),
            peer_black_list: timedmap::TimedMap::new(),
        }
    }

    async fn remote_send_udp_hole_punch_packet(
        &self,
        dst_peer_id: PeerId,
        connector_addrs: Vec<SocketAddr>,
        preferred_src_ipv6: Option<Ipv6Addr>,
        remote_url: &url::Url,
    ) -> Result<(), Error> {
        if !matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp)) {
            return Err(anyhow::anyhow!(
                "udp hole punch packet only applies to udp listener: {}",
                remote_url
            )
            .into());
        }

        let policy = self.global_ctx.get_underlay_policy();
        let connector_addrs = connector_addrs
            .into_iter()
            .filter(|addr| policy.allows_ip(addr.ip()))
            .collect::<Vec<_>>();
        if connector_addrs.is_empty() {
            return Err(TunnelError::UnderlayPolicyDenied(
                "no allowed UDP hole-punch address remains for RPC".into(),
            )
            .into());
        }

        let global_ctx = self.peer_manager.get_global_ctx();
        let listener_port = mapped_listener_port(remote_url).ok_or(anyhow::anyhow!(
            "failed to parse port from remote url: {}",
            remote_url
        ))?;

        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            global_ctx.get_network_name(),
        );

        rpc_stub
            .send_udp_hole_punch_packet(
                BaseController::default(),
                SendUdpHolePunchPacketRequest {
                    connector_addr: connector_addrs.first().copied().map(Into::into),
                    listener_port: listener_port as u32,
                    preferred_src_ipv6: preferred_src_ipv6.map(Into::into),
                    connector_addrs: connector_addrs.into_iter().map(Into::into).collect(),
                },
            )
            .await
            .with_context(|| {
                format!(
                    "do rpc, send udp hole punch packet to peer {} at {} with preferred source {:?}",
                    dst_peer_id, remote_url, preferred_src_ipv6
                )
            })?;

        Ok(())
    }

    async fn connect_to_public_ipv6(
        &self,
        dst_peer_id: PeerId,
        remote_url: &url::Url,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let local_socket = bind_direct_udp_socket(&self.global_ctx, false)
            .await
            .with_context(|| format!("failed to bind local socket for {}", remote_url))?;
        let connector_ips = collect_ipv6_hole_punch_candidates(&self.global_ctx).await;

        // ask remote to send v6 hole punch packet
        // and no matter what the result is, continue to connect
        if !connector_ips.is_empty() {
            let local_port = local_socket.local_addr()?.port();
            let connector_addrs = connector_ips
                .into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), local_port))
                .collect::<Vec<_>>();
            let preferred_src_ipv6 = match remote_url.host() {
                Some(Host::Ipv6(ip)) => Some(ip),
                _ => None,
            };
            tracing::debug!(
                ?connector_addrs,
                ?preferred_src_ipv6,
                ?remote_url,
                "request remote IPv6 hole-punch packets"
            );
            if let Err(err) = self
                .remote_send_udp_hole_punch_packet(
                    dst_peer_id,
                    connector_addrs,
                    preferred_src_ipv6,
                    remote_url,
                )
                .await
            {
                tracing::debug!(
                    ?err,
                    ?remote_url,
                    "remote IPv6 hole-punch packet request failed"
                );
            }
        } else {
            tracing::debug!(
                ?remote_url,
                "skip remote IPv6 hole-punch packet; no non-EasyTier public IPv6 in STUN info"
            );
        }

        let mut udp_connector = UdpTunnelConnector::new(remote_url.clone());
        udp_connector.set_underlay_policy(self.global_ctx.get_underlay_policy());
        let remote_addr = SocketAddr::from_url(remote_url.clone(), IpVersion::V6).await?;
        let ret = udp_connector
            .try_connect_with_socket(local_socket, remote_addr)
            .await?;

        // NOTICE: must add as directly connected tunnel
        self.peer_manager
            .add_client_tunnel_with_peer_id_hint(ret, true, Some(dst_peer_id))
            .await
    }

    async fn connect_to_public_ipv4(
        &self,
        dst_peer_id: PeerId,
        remote_url: &url::Url,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let local_socket = bind_direct_udp_socket(&self.global_ctx, true)
            .await
            .with_context(|| format!("failed to bind local socket for {}", remote_url))?;
        let connector_addr = self
            .peer_manager
            .get_global_ctx()
            .get_stun_info_collector()
            .get_udp_port_mapping_with_socket(local_socket.clone())
            .await
            .with_context(|| format!("failed to get udp port mapping for {}", remote_url))?;

        let _ = self
            .remote_send_udp_hole_punch_packet(dst_peer_id, vec![connector_addr], None, remote_url)
            .await;

        let mut udp_connector = UdpTunnelConnector::new(remote_url.clone());
        udp_connector.set_underlay_policy(self.global_ctx.get_underlay_policy());
        let remote_addr = SocketAddr::from_url(remote_url.clone(), IpVersion::V4).await?;
        let ret = udp_connector
            .try_connect_with_socket(local_socket, remote_addr)
            .await?;

        self.peer_manager
            .add_client_tunnel_with_peer_id_hint(ret, true, Some(dst_peer_id))
            .await
    }

    async fn do_try_connect_to_ip(&self, dst_peer_id: PeerId, addr: String) -> Result<(), Error> {
        let connector = create_connector_by_url(&addr, &self.global_ctx, IpVersion::Both).await?;
        let remote_url = connector.remote_url();
        let (peer_id, conn_id) = if matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp)) {
            match remote_url.host() {
                Some(Host::Ipv6(_)) => {
                    self.connect_to_public_ipv6(dst_peer_id, &remote_url)
                        .await?
                }
                Some(Host::Ipv4(ip)) if is_public_ipv4(ip) => {
                    match self.connect_to_public_ipv4(dst_peer_id, &remote_url).await {
                        Ok(ret) => ret,
                        Err(err) => {
                            tracing::debug!(
                                ?err,
                                %remote_url,
                                "udp public ipv4 listener punch failed, falling back to direct connect"
                            );
                            timeout(
                                std::time::Duration::from_secs(3),
                                self.peer_manager.try_direct_connect_with_peer_id_hint(
                                    connector,
                                    Some(dst_peer_id),
                                ),
                            )
                            .await??
                        }
                    }
                }
                _ => {
                    timeout(
                        std::time::Duration::from_secs(3),
                        self.peer_manager
                            .try_direct_connect_with_peer_id_hint(connector, Some(dst_peer_id)),
                    )
                    .await??
                }
            }
        } else {
            timeout(
                std::time::Duration::from_secs(3),
                self.peer_manager
                    .try_direct_connect_with_peer_id_hint(connector, Some(dst_peer_id)),
            )
            .await??
        };

        if peer_id != dst_peer_id && !TESTING.load(Ordering::Relaxed) {
            tracing::info!(
                "connect to ip succ: {}, but peer id mismatch, expect: {}, actual: {}",
                addr,
                dst_peer_id,
                peer_id
            );
            self.peer_manager.close_peer_conn(peer_id, &conn_id).await?;
            return Err(Error::InvalidUrl(addr));
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn try_connect_to_ip(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        let mut rand_gen = rand::rngs::OsRng;
        let backoff_ms = [1000, 2000, 4000];
        let mut backoff_idx = 0;

        tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start");

        self.dst_listener_blacklist.cleanup();

        if self
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(dst_peer_id, addr.clone()))
        {
            return Err(Error::UrlInBlacklist);
        }

        loop {
            tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start one round");
            let ret = self.do_try_connect_to_ip(dst_peer_id, addr.clone()).await;
            tracing::debug!(?ret, ?dst_peer_id, ?addr, "try_connect_to_ip return");
            if ret.is_ok() {
                return Ok(());
            }

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }

            if backoff_idx < backoff_ms.len() {
                let delta = backoff_ms[backoff_idx] >> 1;
                assert!(delta > 0);
                assert!(delta < backoff_ms[backoff_idx]);

                tokio::time::sleep(Duration::from_millis(
                    (backoff_ms[backoff_idx] + rand_gen.gen_range(-delta..delta)) as u64,
                ))
                .await;

                backoff_idx += 1;
                continue;
            } else {
                self.dst_listener_blacklist.insert(
                    DstListenerUrlBlackListItem(dst_peer_id, addr),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
                return ret;
            }
        }
    }

    async fn spawn_direct_connect_task(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
        listener: &url::Url,
        tasks: &mut JoinSet<Result<(), Error>>,
    ) {
        let policy = self.global_ctx.get_underlay_policy();
        if !direct_listener_allowed_before_resolution(&policy, listener) {
            tracing::warn!(
                ?listener,
                "strict underlay policy skipped hostname listener before DNS resolution"
            );
            return;
        }
        let Ok(mut addrs) = resolve_mapped_listener_addrs(listener).await else {
            tracing::error!(?listener, "failed to parse socket address from listener");
            return;
        };
        let listener_host = addrs.pop();
        tracing::info!(?listener_host, ?listener, "try direct connect to peer");

        let is_udp = matches_protocol!(listener, Protocol::UDP);
        // Snapshot running listeners once; used for cheap port pre-checks before the
        // expensive should_deny_proxy call (which binds a socket per IP) in the
        // unspecified-address expansion loops below.
        let local_listeners = self.global_ctx.get_running_listeners();
        let port_has_local_listener = |port: u16| -> bool {
            local_listeners
                .iter()
                .any(|l| l.port() == Some(port) && matches_protocol!(l, Protocol::UDP) == is_udp)
        };

        match listener_host {
            Some(SocketAddr::V4(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // Only pay the should_deny_proxy cost (bind per IP) when a local
                    // listener actually uses this port+protocol; otherwise the check
                    // can never return true.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv4s
                        .iter()
                        .chain(ip_list.public_ipv4.iter())
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(
                                IpAddr::V4(std::net::Ipv4Addr::from(ip.addr)),
                                s_addr.port(),
                            );
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (0.0.0.0 expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(ip.to_string().as_str())).is_ok() {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for interface ipv4"
                                );
                            }
                        });
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv4)");
                    } else {
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            Some(SocketAddr::V6(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // for ipv6, only try public ip
                    // Same port pre-check as IPv4: avoid binding per IP when no local
                    // listener uses this port+protocol.
                    let check_self = port_has_local_listener(s_addr.port());
                    ip_list
                        .interface_ipv6s
                        .iter()
                        .chain(ip_list.public_ipv6.iter())
                        .filter_map(|x| Ipv6Addr::from_str(&x.to_string()).ok())
                        .filter(|x| is_usable_public_ipv6_candidate(x, &self.global_ctx))
                        .collect::<HashSet<_>>()
                        .iter()
                        .for_each(|ip| {
                            let sock_addr = SocketAddr::new(IpAddr::V6(*ip), s_addr.port());
                            if check_self && self.global_ctx.should_deny_proxy(&sock_addr, is_udp) {
                                tracing::debug!(
                                    ?ip,
                                    ?listener,
                                    "skip self-connection (:: expansion)"
                                );
                                return;
                            }
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(format!("[{}]", ip).as_str())).is_ok() {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id,
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for public ipv6"
                                );
                            }
                        });
                } else if self.global_ctx.is_ip_easytier_managed_ipv6(s_addr.ip()) {
                    tracing::debug!(
                        ?listener,
                        "skip EasyTier-managed IPv6 as direct-connect target"
                    );
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    if self
                        .global_ctx
                        .should_deny_proxy(&SocketAddr::from(s_addr), is_udp)
                    {
                        tracing::debug!(?listener, "skip self-connection (specific IPv6)");
                    } else {
                        tasks.spawn(Self::try_connect_to_ip(
                            self.clone(),
                            dst_peer_id,
                            listener.to_string(),
                        ));
                    }
                }
            }
            p => {
                tracing::error!(?p, ?listener, "failed to parse ip version from listener");
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect_internal(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        let enable_ipv6 = self.global_ctx.get_flags().enable_ipv6;
        let available_listeners = ip_list
            .listeners
            .clone()
            .into_iter()
            .map(Into::<url::Url>::into)
            .filter_map(|l| if l.scheme() != "ring" { Some(l) } else { None })
            .filter(|l| mapped_listener_port(l).is_some() && l.host().is_some())
            .filter(|l| enable_ipv6 || !matches!(l.host().unwrap().to_owned(), Host::Ipv6(_)))
            .collect::<Vec<_>>();

        tracing::debug!(?available_listeners, "got available listeners");

        if available_listeners.is_empty() {
            return Err(anyhow::anyhow!("peer {} have no valid listener", dst_peer_id).into());
        }

        let default_protocol = self.global_ctx.get_flags().default_protocol;
        // Prefer the configured protocol. The default is raw UDP, followed by QUIC and then
        // TCP, keeping stream head-of-line blocking off the normal data path.
        // highest priority is in the last
        let mut available_listeners = available_listeners;
        available_listeners
            .sort_by_key(|listener| direct_protocol_priority(listener.scheme(), &default_protocol));

        while !available_listeners.is_empty() {
            let mut tasks = JoinSet::new();
            let mut listener_list = vec![];

            let cur_scheme = available_listeners.last().unwrap().scheme().to_owned();
            while let Some(listener) = available_listeners.last() {
                if listener.scheme() != cur_scheme {
                    break;
                }

                tracing::debug!("try direct connect to peer with listener: {}", listener);
                self.spawn_direct_connect_task(dst_peer_id, &ip_list, listener, &mut tasks)
                    .await;

                listener_list.push(listener.clone().to_string());
                available_listeners.pop();
            }

            let ret = wait_for_probe_group(
                &mut tasks,
                || self.peer_manager.has_directly_connected_conn(dst_peer_id),
                DIRECT_PROBE_GRACE_PERIOD,
            )
            .await;
            tracing::debug!(
                ?ret,
                ?dst_peer_id,
                ?cur_scheme,
                ?listener_list,
                "all tasks finished for current scheme"
            );

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let mut backoff =
            udp_hole_punch::BackOff::new(vec![1000, 2000, 2000, 5000, 5000, 10000, 30000, 60000]);
        let mut attempt = 0;
        loop {
            if self.peer_black_list.contains(&dst_peer_id) {
                return Err(anyhow::anyhow!("peer {} is blacklisted", dst_peer_id).into());
            }

            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(backoff.next_backoff())).await;
            }
            attempt += 1;

            let peer_manager = self.peer_manager.clone();
            tracing::debug!("try direct connect to peer: {}", dst_peer_id);

            let rpc_stub = peer_manager
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                peer_manager.my_peer_id(),
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

            let ip_list = rpc_stub
                .get_ip_list(BaseController::default(), GetIpListRequest {})
                .await;
            let ip_list = handle_rpc_result(ip_list, dst_peer_id, &self.peer_black_list)
                .with_context(|| format!("get ip list from peer {}", dst_peer_id))?;

            tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");

            let ret = self
                .do_try_direct_connect_internal(dst_peer_id, ip_list)
                .await;
            tracing::info!(?ret, ?dst_peer_id, "do_try_direct_connect return");

            if peer_manager.has_directly_connected_conn(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,
    client: PeerTaskManager<DirectConnectorLauncher>,
    tasks: JoinSet<()>,
}

#[derive(Clone)]
struct DirectConnectorLauncher(Arc<DirectConnectorManagerData>);

#[async_trait::async_trait]
impl PeerTaskLauncher for DirectConnectorLauncher {
    type Data = Arc<DirectConnectorManagerData>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_mgr: Arc<PeerManager>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        data.peer_black_list.cleanup();
        let my_peer_id = data.peer_manager.my_peer_id();
        data.peer_manager
            .list_peers()
            .await
            .into_iter()
            .filter(|peer_id| {
                *peer_id != my_peer_id
                    && !data.peer_manager.has_directly_connected_conn(*peer_id)
                    && !data.peer_black_list.contains(peer_id)
            })
            .collect()
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        tokio::spawn(async move { data.do_try_direct_connect(item).await.map_err(Into::into) })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let data = Arc::new(DirectConnectorManagerData::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));
        let client = PeerTaskManager::new_with_external_signal(
            DirectConnectorLauncher(data.clone()),
            peer_manager.clone(),
            Some(peer_manager.p2p_demand_notify()),
        );
        Self {
            global_ctx,
            data,
            client,
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self) {
        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                    self.global_ctx.clone(),
                )),
                &self.data.global_ctx.get_network_name(),
            );
    }

    pub fn run_as_client(&mut self) {
        self.client.start();
    }

    #[cfg(test)]
    pub(crate) async fn try_direct_connect_with_ip_list(
        &self,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        self.data
            .do_try_direct_connect_internal(dst_peer_id, ip_list)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        connector::direct::{
            DirectConnectorManager, DirectConnectorManagerData, DstListenerUrlBlackListItem,
        },
        instance::listeners::ListenerManager,
        peers::tests::{
            connect_peer_manager, create_mock_peer_manager, wait_route_appear,
            wait_route_appear_with_cost,
        },
        proto::peer_rpc::GetIpListResponse,
        tunnel::{IpScheme, TunnelScheme, matches_scheme},
    };

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        TESTING, direct_protocol_priority, mapped_listener_port, resolve_mapped_listener_addrs,
    };

    #[test]
    fn datagram_transport_order_prefers_udp_then_quic_then_tcp() {
        assert!(direct_protocol_priority("udp", "udp") > direct_protocol_priority("quic", "udp"));
        assert!(direct_protocol_priority("quic", "udp") > direct_protocol_priority("tcp", "udp"));
        assert!(direct_protocol_priority("tcp", "tcp") > direct_protocol_priority("udp", "tcp"));
    }

    #[tokio::test]
    async fn probe_group_allows_competitors_then_aborts_stragglers() {
        let success = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        let first_success = success.clone();
        let first_completed = completed.clone();
        tasks.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            first_success.store(true, Ordering::Relaxed);
            first_completed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let competitor_completed = completed.clone();
        tasks.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            competitor_completed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let straggler_completed = completed.clone();
        tasks.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            straggler_completed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let started = tokio::time::Instant::now();
        let results = super::wait_for_probe_group(
            &mut tasks,
            || success.load(Ordering::Relaxed),
            std::time::Duration::from_millis(200),
        )
        .await;

        assert_eq!(results.len(), 2);
        assert_eq!(completed.load(Ordering::Relaxed), 2);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn public_ipv6_candidate_rejects_easytier_managed_addr_even_in_tests() {
        let global_ctx = get_mock_global_ctx();
        let managed_ipv6: cidr::Ipv6Inet = "2001:db8::2/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([managed_ipv6]));

        assert!(!super::is_usable_public_ipv6_candidate_with_mode(
            &"2001:db8::2".parse().unwrap(),
            &global_ctx,
            true,
        ));
        assert!(super::is_usable_public_ipv6_candidate_with_mode(
            &"::1".parse().unwrap(),
            &global_ctx,
            true,
        ));
    }

    #[tokio::test]
    async fn ipv6_hole_punch_candidates_are_deduped_filtered_and_capped() {
        let global_ctx = get_mock_global_ctx();
        let managed_ipv6: cidr::Ipv6Inet = "2001:db8::2/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([managed_ipv6]));

        let first: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let managed = managed_ipv6.address();
        let second: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let third: Ipv6Addr = "2001:db8::4".parse().unwrap();
        let mut candidates = Vec::new();

        super::push_ipv6_hole_punch_candidate(&mut candidates, first, &global_ctx, 2);
        super::push_ipv6_hole_punch_candidate(&mut candidates, first, &global_ctx, 2);
        super::push_ipv6_hole_punch_candidate(&mut candidates, managed, &global_ctx, 2);
        super::push_ipv6_hole_punch_candidate(&mut candidates, second, &global_ctx, 2);
        super::push_ipv6_hole_punch_candidate(&mut candidates, third, &global_ctx, 2);

        assert_eq!(candidates, vec![first, second]);
    }

    #[test]
    fn udp_ipv6_url_matches_hole_punch_branch_condition() {
        let remote_url: url::Url = "udp://[2001:db8::1]:11010".parse().unwrap();
        let takes_udp_ipv6_hole_punch_branch =
            matches_scheme!(remote_url, TunnelScheme::Ip(IpScheme::Udp))
                && matches!(remote_url.host(), Some(url::Host::Ipv6(_)));

        assert!(takes_udp_ipv6_hole_punch_branch);
    }

    #[test]
    fn mapped_listener_port_uses_ip_scheme_defaults() {
        assert_eq!(
            mapped_listener_port(&"ws://example.com".parse().unwrap()),
            Some(80)
        );
        assert_eq!(
            mapped_listener_port(&"wss://example.com".parse().unwrap()),
            Some(443)
        );
        assert_eq!(
            mapped_listener_port(&"tcp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
        assert_eq!(
            mapped_listener_port(&"udp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
    }

    #[tokio::test]
    async fn resolve_mapped_listener_addrs_uses_default_ports() {
        let wss_addrs = resolve_mapped_listener_addrs(&"wss://127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            wss_addrs,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)]
        );

        let tcp_addrs = resolve_mapped_listener_addrs(&"tcp://127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            tcp_addrs,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11010)]
        );
    }

    #[test]
    fn strict_direct_listener_filter_rejects_hostname() {
        let policy =
            crate::common::underlay_policy::UnderlayPolicy::new(&["tailscale0".into()], &[])
                .unwrap();

        assert!(!super::direct_listener_allowed_before_resolution(
            &policy,
            &"quic://peer.example:11010".parse().unwrap(),
        ));
        assert!(super::direct_listener_allowed_before_resolution(
            &policy,
            &"quic://192.0.2.20:11010".parse().unwrap(),
        ));
    }

    async fn run_direct_connector_mapped_listener_test(
        mapped_listener: &str,
        target_listener: &str,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        let p_x = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        connect_peer_manager(p_c.clone(), p_x.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        wait_route_appear(p_a.clone(), p_x.clone()).await.unwrap();

        let mut f = p_a.get_global_ctx().get_flags();
        f.bind_device = false;
        p_a.get_global_ctx().set_flags(f);

        p_c.get_global_ctx()
            .config
            .set_mapped_listeners(Some(vec![mapped_listener.parse().unwrap()]));

        p_x.get_global_ctx()
            .config
            .set_listeners(vec![target_listener.parse().unwrap()]);
        let mut lis_x = ListenerManager::new(p_x.get_global_ctx(), p_x.clone());
        lis_x.prepare_listeners().await.unwrap();
        lis_x.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());
        dm_a.run_as_client();
        dm_c.run_as_server();
        // p_c's mapped listener is p_x's listener, so p_a should connect to p_x directly

        wait_route_appear_with_cost(p_a.clone(), p_x.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_mapped_listener() {
        run_direct_connector_mapped_listener_test("tcp://127.0.0.1:11334", "tcp://0.0.0.0:11334")
            .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn direct_connector_basic_test(
        #[values("tcp", "udp", "wg")] proto: &str,
        #[values("true", "false")] ipv6: bool,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        p_c.get_global_ctx()
            .get_ip_collector()
            .collect_ip_addrs()
            .await;

        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());

        dm_a.run_as_client();
        dm_c.run_as_server();

        let port = if proto == "wg" { 11040 } else { 11041 };
        if !ipv6 {
            p_c.get_global_ctx().config.set_listeners(vec![
                format!("{}://0.0.0.0:{}", proto, port).parse().unwrap(),
            ]);
        } else {
            p_c.get_global_ctx()
                .config
                .set_listeners(vec![format!("{}://[::]:{}", proto, port).parse().unwrap()]);
        }
        let mut f = p_c.get_global_ctx().config.get_flags();
        f.enable_ipv6 = ipv6;
        p_c.get_global_ctx().set_flags(f);
        let mut lis_c = ListenerManager::new(p_c.get_global_ctx(), p_c.clone());
        lis_c.prepare_listeners().await.unwrap();

        lis_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_scheme_blacklist() {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let data = Arc::new(DirectConnectorManagerData::new(
            p_a.get_global_ctx(),
            p_a.clone(),
        ));
        let mut ip_list = GetIpListResponse::default();
        ip_list
            .listeners
            .push("tcp://127.0.0.1:10222".parse().unwrap());

        ip_list
            .interface_ipv4s
            .push("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().into());

        data.do_try_direct_connect_internal(1, ip_list.clone())
            .await
            .unwrap();

        assert!(
            data.dst_listener_blacklist
                .contains(&DstListenerUrlBlackListItem(
                    1,
                    "tcp://127.0.0.1:10222".parse().unwrap()
                ))
        );
    }
}
