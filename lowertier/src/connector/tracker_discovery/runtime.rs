use super::{
    client::{self, UdpTracker},
    server::unix_seconds,
    wire::{self, Announce},
};
use crate::connector::tcp_hole_punch::TcpBootstrap;
use crate::{
    common::{config::TrackerDiscoveryConfig, global_ctx::ArcGlobalCtx, stun::StunPacket},
    peers::peer_manager::PeerManager,
    tunnel::{
        TunnelConnector, TunnelListener,
        common::{bind, ensure_local_allowed, ensure_remote_allowed},
        quic::{self, QuicTunnelConnector, QuicTunnelListener},
    },
};
use anyhow::{Context, Result, ensure};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::task::AbortOnDropHandle;

// Speculative QUIC handshakes share one quarter of the process memory budget.
// A per-interface limit can otherwise consume all credit before Noise can send.
static QUIC_DISCOVERY_HANDSHAKES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(
    crate::common::global_ctx::PROCESS_RETAINED_MEMORY_LIMIT_BYTES
        / quic::QUIC_CONNECTION_MEMORY_CHARGE_BYTES
        / 4,
);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);

/// Withdraw expired observations without disturbing established QUIC sessions.
/// A restored mapping (including the same address) must wake tracker watchers.
fn publish_udp_mapping(
    sender: &watch::Sender<Option<SocketAddr>>,
    mapped: Option<SocketAddr>,
) -> Duration {
    sender.send_if_modified(|current| {
        if *current == mapped {
            return false;
        }
        *current = mapped;
        true
    });
    if mapped.is_some() {
        Duration::from_secs(30)
    } else {
        // Mapping recovery is independent of the tracker's announce interval.
        Duration::from_secs(5)
    }
}

async fn acquire_quic_discovery_slot<'a>(
    slots: &'a tokio::sync::Semaphore,
    upgrade: &mut Option<oneshot::Receiver<u32>>,
    expected: &mut Option<u32>,
) -> Result<tokio::sync::SemaphorePermit<'a>, tokio::sync::AcquireError> {
    let permit = slots.acquire().await?;
    if let Some(receiver) = upgrade.as_mut() {
        // try_recv consumes ready and closed channels. Neither can be polled again.
        match receiver.try_recv() {
            Ok(peer) => {
                *expected = Some(peer);
                *upgrade = None;
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                *upgrade = None;
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }
    Ok(permit)
}

pub(crate) fn start(
    peers: Arc<PeerManager>,
    config: TrackerDiscoveryConfig,
) -> Result<AbortOnDropHandle<()>> {
    let ctx = peers.get_global_ctx();
    ensure!(
        !config.trackers.is_empty() && config.trackers.len() <= 8,
        "discovery needs 1–8 trackers"
    );
    let identity = ctx.get_network_identity();
    ensure!(
        identity
            .network_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_empty()),
        "tracker discovery requires a nonempty network secret"
    );
    let key = identity
        .network_secret_digest
        .context("tracker discovery requires a network secret digest")?;
    ensure!(
        matches!(
            ctx.get_flags().default_protocol.as_str(),
            "quic" | "tcp" | "wss"
        ),
        "unsupported discovery protocol"
    );
    for url in &config.trackers {
        ensure!(
            matches!(url.scheme(), "udp" | "http" | "https")
                && url.host_str().is_some()
                && url.port_or_known_default().is_some()
                && url.username().is_empty()
                && url.password().is_none(),
            "invalid tracker URL"
        );
    }
    if let Some(local) = config.bind {
        ensure!(
            !local.ip().is_unspecified(),
            "discovery bind needs a concrete local address"
        );
        let _guard = ctx.net_ns.guard();
        ensure_local_allowed(&ctx.get_underlay_policy(), local)?;
    }
    if let Some(advertise) = config.advertise {
        ensure!(
            config.bind.is_some()
                && advertise.port() != 0
                && !advertise.ip().is_unspecified()
                && !advertise.ip().is_multicast(),
            "discovery advertise requires bind and a valid endpoint"
        );
    }
    Ok(AbortOnDropHandle::new(tokio::spawn(async move {
        let mut paths = HashMap::new();
        loop {
            let mut addresses = if let Some(local) = config.bind {
                vec![local]
            } else {
                ctx.get_ip_collector()
                    .collect_ip_addrs()
                    .await
                    .interface_ipv4s
                    .into_iter()
                    .map(|ip| SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), 0))
                    .filter(|local| {
                        !ctx.is_ip_in_same_network(&local.ip()) && {
                            let _guard = ctx.net_ns.guard();
                            ensure_local_allowed(&ctx.get_underlay_policy(), *local).is_ok()
                        }
                    })
                    .collect::<Vec<_>>()
            };
            addresses.sort_unstable();
            addresses.dedup();
            addresses.truncate(16);
            paths.retain(|address, _: &mut AbortOnDropHandle<()>| addresses.contains(address));
            for local in addresses {
                if paths.contains_key(&local) {
                    continue;
                }
                let (ctx, peers, config) = (ctx.clone(), peers.clone(), config.clone());
                paths.insert(
                    local,
                    AbortOnDropHandle::new(tokio::spawn(async move {
                        loop {
                            if let Err(error) =
                                run_path(ctx.clone(), peers.clone(), config.clone(), local, key)
                                    .await
                            {
                                tracing::warn!(?local, %error, "tracker discovery path failed");
                            }
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    })),
                );
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })))
}

async fn run_path(
    ctx: ArcGlobalCtx,
    peers: Arc<PeerManager>,
    config: TrackerDiscoveryConfig,
    local: SocketAddr,
    key: [u8; 32],
) -> Result<()> {
    let protocol = ctx.get_flags().default_protocol;
    let udp_local = if protocol == "quic" {
        local
    } else {
        SocketAddr::new(local.ip(), 0)
    };
    let udp = bind::<UdpSocket>()
        .addr(udp_local)
        .net_ns(ctx.net_ns.clone())
        .maybe_socket_mark(ctx.get_flags().socket_mark)
        .call()?;
    let (packets, _) = broadcast::channel::<StunPacket>(128);
    let mut tasks = JoinSet::new();
    let (endpoint, udp) = if protocol == "quic" {
        let (endpoint, udp) = quic::discovery_endpoint(udp, &ctx, packets.clone())?;
        (Some(endpoint), udp)
    } else {
        let udp = Arc::new(udp);
        let (socket, packets) = (udp.clone(), packets.clone());
        tasks.spawn(async move {
            let mut bytes = [0; wire::MAX_RESPONSE];
            loop {
                let (length, addr) = socket.recv_from(&mut bytes).await?;
                let _ = packets.send(StunPacket {
                    data: bytes[..length].to_vec(),
                    addr,
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        (None, udp)
    };
    let (mapped_tx, mapped_rx) = watch::channel(config.advertise);
    let (candidate_tx, candidate_rx) = mpsc::channel(64);
    let peer_session = rand::random();
    let hash = wire::rendezvous_id(&key, &protocol);
    // CONNECT requests start while STUN is still in flight.
    for url in config.trackers.clone() {
        let (ctx, udp, packets, mapped, candidates) = (
            ctx.clone(),
            udp.clone(),
            packets.clone(),
            mapped_rx.clone(),
            candidate_tx.clone(),
        );
        tasks.spawn(async move {
            tracker_loop(
                url,
                ctx,
                udp,
                packets,
                mapped,
                candidates,
                hash,
                peer_session,
            )
            .await
        });
    }
    let tcp = if protocol != "quic" {
        let tcp = Arc::new(TcpBootstrap::new(ctx.clone(), local, config.advertise).await?);
        mapped_tx.send_replace(Some(tcp.mapped().await));
        if config.advertise.is_none() {
            let tcp = tcp.clone();
            tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let previous = *mapped_tx.borrow();
                    let mapped = match tcp.refresh_mapping(previous).await {
                        Ok(address) => Some(address),
                        Err(error) => {
                            tracing::debug!(%error, "tracker TCP mapping refresh failed");
                            None
                        }
                    };
                    mapped_tx.send_if_modified(|current| {
                        if *current == mapped {
                            false
                        } else {
                            *current = mapped;
                            true
                        }
                    });
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
        }
        Some(tcp)
    } else {
        if config.advertise.is_none() {
            let (ctx, udp, packets) = (ctx.clone(), udp.clone(), packets.clone());
            tasks.spawn(async move {
                loop {
                    let current = *mapped_tx.borrow();
                    let mapping = if let Some(current) = current {
                        ctx.get_stun_info_collector()
                            .get_udp_port_mappings_with_socket_receiver(
                                udp.clone(),
                                packets.subscribe(),
                            )
                            .await
                            .and_then(|addresses| {
                                addresses
                                    .iter()
                                    .copied()
                                    .find(|address| *address == current)
                                    .or_else(|| addresses.first().copied())
                                    .ok_or(crate::common::error::Error::NotFound)
                            })
                    } else {
                        ctx.get_stun_info_collector()
                            .get_first_udp_mapping_with_receiver(udp.clone(), packets.subscribe())
                            .await
                    };
                    let mapped = match mapping {
                        Ok(mapped) => Some(mapped),
                        Err(error) => {
                            tracing::debug!(%error, "tracker discovery STUN failed; mapping withdrawn");
                            None
                        }
                    };
                    let delay = publish_udp_mapping(&mapped_tx, mapped);
                    tokio::time::sleep(delay).await;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
        }
        None
    };
    let (listener_peers, listener_ctx, listener_tcp) = (peers.clone(), ctx.clone(), tcp.clone());
    let listener_endpoint = endpoint.clone();
    tasks.spawn(async move {
        let mut quic = listener_endpoint.map(|endpoint| QuicTunnelListener::from_discovery_endpoint(endpoint, listener_ctx)).transpose()?;
        let mut handshakes = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
                accepted = async {
                    if let Some(listener) = quic.as_mut() { Ok(futures::future::Either::Left(listener.accept().await?)) }
                    else { Ok::<_, anyhow::Error>(futures::future::Either::Right(listener_tcp.as_ref().unwrap().accept_stream().await?)) }
                }, if handshakes.len() < 16 => {
                    let Ok(accepted) = accepted else { continue; };
                    let peers = listener_peers.clone();
                    let tcp = listener_tcp.clone();
                    handshakes.spawn(async move {
                        let result = tokio::time::timeout(Duration::from_secs(15), async {
                            let tunnel = match accepted { futures::future::Either::Left(tunnel) => tunnel,
                                futures::future::Either::Right(stream) => tcp.unwrap().accept(stream).await? };
                            peers.add_discovered_tunnel(tunnel, None, false).await?;
                            Ok::<(), anyhow::Error>(())
                        }).await;
                        match result {
                            Ok(Ok(())) => tracing::info!("tracker bootstrap accepted authenticated peer"),
                            error => tracing::debug!(?error, "tracker bootstrap admission failed"),
                        }
                    });
                }
            }
        }
        #[allow(unreachable_code)] Ok::<(), anyhow::Error>(())
    });
    tasks.spawn(candidate_loop(
        ctx,
        peers,
        udp,
        packets,
        endpoint,
        tcp,
        candidate_rx,
        candidate_tx,
        key,
    ));
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn tracker_loop(
    url: url::Url,
    ctx: ArcGlobalCtx,
    udp: Arc<UdpSocket>,
    packets: broadcast::Sender<StunPacket>,
    mut mapped: watch::Receiver<Option<SocketAddr>>,
    candidates: mpsc::Sender<SocketAddr>,
    hash: wire::Id,
    peer: wire::Id,
) -> Result<()> {
    let local = udp.local_addr()?;
    let tracker_name = url.host_str().unwrap().to_owned();
    let mut started = true;
    let mut cached_tracker = None;
    let mut address_index = 0usize;
    loop {
        let result = async {
            if url.scheme() == "udp" && cached_tracker.is_none() {
                let host = match url.host().unwrap() { url::Host::Domain(host) => host.to_owned(), url::Host::Ipv4(ip) => ip.to_string(), url::Host::Ipv6(ip) => ip.to_string() };
                let addresses = client::resolve_tracker_host(&ctx, host, url.port().unwrap()).await?;
                let mut allowed = addresses.into_iter().filter(|addr| addr.is_ipv4() == local.is_ipv4()
                    && ensure_remote_allowed(&ctx.get_underlay_policy(), *addr).is_ok()).collect::<Vec<_>>();
                allowed.sort_unstable();
                allowed.dedup();
                ensure!(!allowed.is_empty(), "no allowed UDP tracker address");
                let remote = allowed[address_index % allowed.len()];
                let tracker = UdpTracker::new(remote, udp.clone(), packets.clone());
                tracker.connect().await?;
                cached_tracker = Some(tracker);
            }
            // Hold the watch read lock until the valid mapping has been copied.
            // Refresh can withdraw a mapping between separate check and read operations.
            let address = mapped.wait_for(Option::is_some).await?
                .expect("wait_for retains the matching mapping until it is copied");
            let announce = Announce { hash, peer, key: u32::from_be_bytes(peer[..4].try_into().unwrap()), port: address.port(), event: if started { 2 } else { 0 } };
            let peers = if let Some(tracker) = cached_tracker.as_ref() { tracker.announce(&announce).await? }
                else { tokio::time::timeout(Duration::from_secs(15), client::http_announce_rotating(&url, &announce, local, &ctx, address_index)).await?? };
            tracing::info!(tracker = %tracker_name, protocol = %ctx.get_flags().default_protocol, count = peers.addresses.len(), interval = peers.interval, ?address, "tracker discovery announce succeeded");
            for peer in peers.addresses {
                if peer != address && peer != local && ensure_remote_allowed(&ctx.get_underlay_policy(), peer).is_ok() {
                    let _ = candidates.try_send(peer);
                }
            }
            Ok::<u32, anyhow::Error>(peers.interval)
        }.await;
        let interval = match result {
            Ok(interval) => {
                started = false;
                Duration::from_secs(u64::from(interval))
            }
            Err(error) => {
                cached_tracker = None;
                // A failed DNS address must not monopolize subsequent tracker attempts.
                address_index = address_index.wrapping_add(1);
                tracing::debug!(tracker = %tracker_name, %error, "tracker discovery request failed");
                Duration::from_secs(60)
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            changed = mapped.changed() => {
                // A changed NAT mapping is a new announce event, not membership polling.
                if changed.is_err() { tokio::time::sleep(interval).await; }
                else { started = true; tokio::time::sleep(Duration::from_secs(15)).await; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::server::TrackerServer;
    use super::*;
    use crate::peers::tests::create_mock_peer_manager_secure;

    #[tokio::test]
    async fn udp_mapping_failure_withdraws_and_same_address_recovery_notifies() {
        let address = "198.51.100.7:16969".parse().unwrap();
        let (sender, mut receiver) = watch::channel(None);
        assert_eq!(publish_udp_mapping(&sender, None), Duration::from_secs(5));
        assert!(!receiver.has_changed().unwrap());
        assert_eq!(
            publish_udp_mapping(&sender, Some(address)),
            Duration::from_secs(30)
        );
        assert_eq!(*receiver.borrow_and_update(), Some(address));
        publish_udp_mapping(&sender, Some(address));
        assert!(!receiver.has_changed().unwrap());
        assert_eq!(publish_udp_mapping(&sender, None), Duration::from_secs(5));
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow_and_update(), None);
        publish_udp_mapping(&sender, Some(address));
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow_and_update(), Some(address));
    }

    #[tokio::test]
    async fn queued_handshake_consumes_ready_and_closed_upgrades() {
        for reply in [None, Some(42)] {
            let slots = Arc::new(tokio::sync::Semaphore::new(1));
            let held = slots.clone().acquire_owned().await.unwrap();
            let (sender, receiver) = oneshot::channel();
            let task_slots = slots.clone();
            let task = tokio::spawn(async move {
                let mut upgrade = Some(receiver);
                let mut expected = None;
                let _permit = acquire_quic_discovery_slot(&task_slots, &mut upgrade, &mut expected)
                    .await
                    .unwrap();
                assert!(
                    upgrade.is_none(),
                    "completed upgrade remained available for another poll"
                );
                expected
            });
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            if let Some(peer) = reply {
                sender.send(peer).unwrap();
            } else {
                drop(sender);
            }
            drop(held);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap(),
                reply
            );
            assert_eq!(slots.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn duplicate_candidates_keep_one_authenticated_probe_challenge() {
        let peers =
            create_mock_peer_manager_secure("probe-test".into(), "probe-secret".into()).await;
        let ctx = peers.get_global_ctx();
        let key = ctx.get_network_identity().network_secret_digest.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (packets, _) = broadcast::channel(128);
        let (endpoint, socket) = quic::discovery_endpoint(socket, &ctx, packets.clone()).unwrap();
        let (candidates, receiver) = mpsc::channel(64);
        let _task = AbortOnDropHandle::new(tokio::spawn(candidate_loop(
            ctx,
            peers,
            socket,
            packets,
            Some(endpoint),
            None,
            receiver,
            candidates.clone(),
            key,
        )));
        let address = remote.local_addr().unwrap();
        candidates.send(address).await.unwrap();
        let mut bytes = [0; 128];
        let (length, _) = remote.recv_from(&mut bytes).await.unwrap();
        let first = wire::read_punch(&bytes[..length], &key, unix_seconds()).unwrap();
        // Independent tracker replies can repeat an endpoint before its first reply arrives.
        for _ in 0..7 {
            candidates.send(address).await.unwrap();
        }
        for _ in 0..4 {
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                wire::read_punch(&bytes[..length], &key, unix_seconds()).unwrap(),
                first
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), async {
                loop {
                    let (length, _) = remote.recv_from(&mut bytes).await.unwrap();
                    assert!(
                        !(length == wire::PUNCH_BYTES && bytes[..4] == [0, b'L', b'T', 1]),
                        "duplicate probe burst"
                    );
                }
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_reply_replaces_a_failed_fresh_port_attempt() {
        let a = create_mock_peer_manager_secure("late-punch".into(), "late-secret".into()).await;
        let b = create_mock_peer_manager_secure("late-punch".into(), "late-secret".into()).await;
        let (client, server) = if a.my_peer_id() < b.my_peer_id() {
            (a, b)
        } else {
            (b, a)
        };
        let ctx = client.get_global_ctx();
        let key = ctx.get_network_identity().network_secret_digest.unwrap();
        let (packets, _) = broadcast::channel(128);
        let (endpoint, socket) = quic::discovery_endpoint(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            &ctx,
            packets.clone(),
        )
        .unwrap();
        let original = socket.local_addr().unwrap();
        let (server_packets, _) = broadcast::channel(128);
        let (server_endpoint, _) = quic::discovery_endpoint(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            &server.get_global_ctx(),
            server_packets,
        )
        .unwrap();
        let server_address = server_endpoint.local_addr().unwrap();
        let mut listener =
            QuicTunnelListener::from_discovery_endpoint(server_endpoint, server.get_global_ctx())
                .unwrap();
        let accepting = server.clone();
        let _server = AbortOnDropHandle::new(tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            accepting
                .add_discovered_tunnel(tunnel, None, false)
                .await
                .unwrap();
        }));
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let server_id = server.my_peer_id();
        let (fallback_tx, fallback_rx) = tokio::sync::oneshot::channel();
        let _proxy = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = [0; 65535];
            let mut nonce = None;
            let mut fallback_tx = Some(fallback_tx);
            loop {
                let (length, source) = proxy.recv_from(&mut bytes).await.unwrap();
                if source == server_address {
                    proxy.send_to(&bytes[..length], original).await.unwrap();
                } else if let Ok((_, challenge, false)) =
                    wire::read_punch(&bytes[..length], &key, unix_seconds())
                {
                    assert_eq!(source, original);
                    nonce = Some(challenge);
                } else if source == original {
                    proxy
                        .send_to(&bytes[..length], server_address)
                        .await
                        .unwrap();
                } else if let Some(sent) = fallback_tx.take() {
                    // Reject the fresh flow before replying to the mapped socket's challenge.
                    proxy
                        .send_to(
                            &wire::punch(&key, server_id, nonce.unwrap(), unix_seconds(), true),
                            original,
                        )
                        .await
                        .unwrap();
                    sent.send(()).unwrap();
                }
            }
        }));
        let (candidates, receiver) = mpsc::channel(64);
        let _client = AbortOnDropHandle::new(tokio::spawn(candidate_loop(
            ctx,
            client.clone(),
            socket,
            packets,
            Some(endpoint),
            None,
            receiver,
            candidates.clone(),
            key,
        )));
        candidates.send(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), fallback_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !client.get_peer_map().has_peer(server.my_peer_id())
                || !server.get_peer_map().has_peer(client.my_peer_id())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated reply did not replace the failed fresh flow");
    }

    #[tokio::test]
    async fn tcp_bootstrap_retries_failed_authentication_and_stalled_tls() {
        for protocol in ["tcp", "wss"] {
            for stalled in [false, true] {
                tokio::time::timeout(BOOTSTRAP_TIMEOUT + Duration::from_secs(1), async {
                    let client =
                        create_mock_peer_manager_secure("tcp-retry".into(), "secret".into()).await;
                    let server =
                        create_mock_peer_manager_secure("tcp-retry".into(), "secret".into()).await;
                    let mut bootstraps = Vec::new();
                    for peer in [&client, &server] {
                        let ctx = peer.get_global_ctx();
                        let mut flags = ctx.get_flags();
                        flags.default_protocol = protocol.into();
                        ctx.set_flags(flags);
                        let reserve = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let address = reserve.local_addr().unwrap();
                        drop(reserve);
                        let tcp = TcpBootstrap::new(ctx, address, Some(address))
                            .await
                            .unwrap();
                        bootstraps.push((Arc::new(tcp), address));
                    }
                    let (accepting, address) = bootstraps.pop().unwrap();
                    let (tcp, original) = bootstraps.pop().unwrap();
                    let remote = server.clone();
                    let accepted = AbortOnDropHandle::new(tokio::spawn(async move {
                        let first = accepting.accept_stream().await.unwrap();
                        assert_eq!(first.peer_addr().unwrap(), original);
                        let retained = if stalled {
                            // Keep TCP open without answering the client's TLS handshake.
                            Some(first)
                        } else {
                            let first = accepting.accept(first).await.unwrap();
                            let (mut reader, writer) = first.split();
                            use futures::StreamExt;
                            let packet = reader
                                .next()
                                .await
                                .unwrap()
                                .unwrap()
                                .pop_singleton()
                                .unwrap();
                            assert_eq!(
                                packet.peer_manager_header().unwrap().packet_type,
                                crate::tunnel::packet_def::PacketType::NoiseHandshakeMsg1 as u8
                            );
                            drop((reader, writer, first));
                            None
                        };
                        let second = accepting.accept_stream().await.unwrap();
                        let source = second.peer_addr().unwrap();
                        assert_eq!(source.ip(), original.ip());
                        assert_ne!(source.port(), original.port());
                        let tunnel = accepting.accept(second).await.unwrap();
                        let peer = remote
                            .add_discovered_tunnel(tunnel, None, false)
                            .await
                            .unwrap();
                        drop(retained);
                        peer
                    }));
                    assert_eq!(
                        connect_tcp_candidate(&tcp, &client, address).await.unwrap(),
                        server.my_peer_id()
                    );
                    assert_eq!(accepted.await.unwrap(), client.my_peer_id());
                    assert!(client.get_peer_map().has_peer(server.my_peer_id()));
                    assert!(server.get_peer_map().has_peer(client.my_peer_id()));
                    assert_eq!(tcp.mapped().await, original);
                    // The fresh flow must not consume the advertised listening socket.
                    let connected = tokio::net::TcpStream::connect(original).await.unwrap();
                    assert_eq!(
                        tcp.accept_stream().await.unwrap().peer_addr().unwrap(),
                        connected.local_addr().unwrap()
                    );
                })
                .await
                .expect("TCP bootstrap did not recover through a fresh port");
            }
        }
    }

    #[tokio::test]
    async fn reachable_quic_peer_bootstraps_when_punch_replies_are_absent() {
        let a =
            create_mock_peer_manager_secure("fallback-test".into(), "fallback-secret".into()).await;
        let b =
            create_mock_peer_manager_secure("fallback-test".into(), "fallback-secret".into()).await;
        let (server_packets, _) = broadcast::channel(128);
        let (server, _) = quic::discovery_endpoint(
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            &a.get_global_ctx(),
            server_packets,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let mut listener =
            QuicTunnelListener::from_discovery_endpoint(server, a.get_global_ctx()).unwrap();
        let accepting = a.clone();
        let (source_tx, source_rx) = tokio::sync::oneshot::channel();
        // This receiver discards punch packets but accepts standard authenticated QUIC.
        let _server = AbortOnDropHandle::new(tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            source_tx
                .send(tunnel.info().unwrap().remote_addr.unwrap().url)
                .unwrap();
            accepting
                .add_discovered_tunnel(tunnel, None, false)
                .await
                .unwrap();
        }));
        let ctx = b.get_global_ctx();
        let key = ctx.get_network_identity().network_secret_digest.unwrap();
        let mut clients = Vec::new();
        let mut silent = Vec::new();
        let mut discovery_sources = Vec::new();
        // Two interface paths must retain memory for authentication during candidate bursts.
        for _ in 0..2 {
            let (packets, _) = broadcast::channel(128);
            let (endpoint, socket) = quic::discovery_endpoint(
                UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                &ctx,
                packets.clone(),
            )
            .unwrap();
            discovery_sources.push(socket.local_addr().unwrap());
            let (candidates, receiver) = mpsc::channel(64);
            clients.push(AbortOnDropHandle::new(tokio::spawn(candidate_loop(
                ctx.clone(),
                b.clone(),
                socket,
                packets,
                Some(endpoint),
                None,
                receiver,
                candidates.clone(),
                key,
            ))));
            candidates.send(address).await.unwrap();
            for _ in 0..7 {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                candidates.send(socket.local_addr().unwrap()).await.unwrap();
                silent.push(socket);
            }
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while !a.has_directly_connected_conn(b.my_peer_id())
                || !b.has_directly_connected_conn(a.my_peer_id())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("standard QUIC fallback did not authenticate");
        let source = url::Url::parse(&source_rx.await.unwrap()).unwrap();
        assert_eq!(source.host_str().unwrap(), "127.0.0.1");
        assert!(
            discovery_sources
                .iter()
                .all(|local| local.port() != source.port().unwrap())
        );
    }

    #[tokio::test]
    async fn discovery_rejects_foreign_networks_before_publication() {
        let a = create_mock_peer_manager_secure("tracker-a".into(), "secret-a".into()).await;
        let b = create_mock_peer_manager_secure("tracker-b".into(), "secret-b".into()).await;
        let (client, server) = crate::tunnel::ring::create_ring_tunnel_pair();
        let (client, server) = tokio::join!(
            a.add_discovered_tunnel(client, None, true),
            b.add_discovered_tunnel(server, None, false)
        );
        assert!(client.is_err(), "foreign tracker candidate was published");
        assert!(server.is_err(), "foreign discovery arrival was published");
        assert!(!a.has_directly_connected_conn(b.my_peer_id()));
        assert!(!b.has_directly_connected_conn(a.my_peer_id()));
    }

    #[tokio::test]
    async fn udp_and_http_trackers_bootstrap_all_transports_without_peer_urls() {
        for tracker_protocol in ["udp", "http"] {
            for protocol in ["quic", "tcp", "wss"] {
                tokio::time::timeout(Duration::from_secs(20), async {
                    let server = TrackerServer::new(1800).unwrap();
                    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let blackhole_url: url::Url =
                        format!("udp://{}/announce", blackhole.local_addr().unwrap())
                            .parse()
                            .unwrap();
                    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let http_url: url::Url =
                        format!("http://{}/announce", http.local_addr().unwrap())
                            .parse()
                            .unwrap();
                    let tracker_address = if tracker_protocol == "udp" {
                        udp.local_addr().unwrap()
                    } else {
                        http.local_addr().unwrap()
                    };
                    let tracker_url: url::Url = format!(
                        "{tracker_protocol}://localhost:{}/announce",
                        tracker_address.port()
                    )
                    .parse()
                    .unwrap();
                    let _udp = AbortOnDropHandle::new(tokio::spawn(server.clone().serve_udp(udp)));
                    let _http = AbortOnDropHandle::new(tokio::spawn(server.clone().serve_http(
                        http,
                        vec![],
                        "X-Real-IP".into(),
                    )));
                    let a = create_mock_peer_manager_secure(
                        "tracker-test".into(),
                        "tracker-test-secret".into(),
                    )
                    .await;
                    let b = create_mock_peer_manager_secure(
                        "tracker-test".into(),
                        "tracker-test-secret".into(),
                    )
                    .await;
                    let (a, b) = if a.my_peer_id() > b.my_peer_id() {
                        (a, b)
                    } else {
                        (b, a)
                    };
                    let mut silent_peers = Vec::new();
                    if protocol == "quic" {
                        let ctx = a.get_global_ctx();
                        let hash = wire::rendezvous_id(
                            &ctx.get_network_identity().network_secret_digest.unwrap(),
                            protocol,
                        );
                        // Eight simultaneous probes must leave room for the valid peer handshake.
                        for _ in 0..7 {
                            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                            let announce = Announce {
                                hash,
                                peer: rand::random(),
                                key: 0,
                                port: socket.local_addr().unwrap().port(),
                                event: 2,
                            };
                            client::http_announce(
                                &http_url,
                                &announce,
                                "127.0.0.1:0".parse().unwrap(),
                                &ctx,
                            )
                            .await
                            .unwrap();
                            silent_peers.push(socket);
                        }
                    }
                    let mut tasks = Vec::new();
                    for peer in [&a, &b] {
                        let ctx = peer.get_global_ctx();
                        let mut flags = ctx.get_flags();
                        flags.default_protocol = protocol.into();
                        ctx.set_flags(flags);
                        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                        let address = reserve.local_addr().unwrap();
                        drop(reserve);
                        let config = TrackerDiscoveryConfig {
                            trackers: vec![blackhole_url.clone(), tracker_url.clone()],
                            bind: Some(address),
                            advertise: Some(address),
                        };
                        assert!(ctx.config.get_peers().is_empty());
                        tasks.push(start(peer.clone(), config).unwrap());
                        while server.peer_count() < tasks.len() + silent_peers.len() {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    while !a.get_peer_map().has_peer(b.my_peer_id())
                        || !b.get_peer_map().has_peer(a.my_peer_id())
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    assert_eq!(
                        a.get_peer_map().list_peers_with_conn().await,
                        vec![b.my_peer_id()]
                    );
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("{tracker_protocol} tracker did not bootstrap {protocol}")
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn candidate_loop(
    ctx: ArcGlobalCtx,
    peers: Arc<PeerManager>,
    udp: Arc<UdpSocket>,
    packets: broadcast::Sender<StunPacket>,
    endpoint: Option<quinn::Endpoint>,
    tcp: Option<Arc<TcpBootstrap>>,
    mut candidates: mpsc::Receiver<SocketAddr>,
    retry_sender: mpsc::Sender<SocketAddr>,
    key: [u8; 32],
) -> Result<()> {
    let mut incoming = packets.subscribe();
    let mut attempts = JoinSet::new();
    let mut punch_tasks = JoinSet::new();
    let (fallback_tx, mut fallbacks) = mpsc::channel(64);
    let mut recent = HashMap::<SocketAddr, (Instant, Option<oneshot::Sender<u32>>)>::new();
    let mut probes = HashMap::<SocketAddr, ([u8; 16], Instant)>::new();
    let mut responses = HashMap::<SocketAddr, Instant>::new();
    let mut cached_candidates = HashMap::<SocketAddr, Instant>::new();
    let mut connected = HashMap::<SocketAddr, u32>::new();
    let (success_tx, mut success_rx) = mpsc::channel(16);
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let my_id = peers.my_peer_id();
    let local_ip = udp.local_addr()?.ip();
    loop {
        let mut connect = None;
        tokio::select! {
            Some(_) = attempts.join_next(), if !attempts.is_empty() => {}
            Some(_) = punch_tasks.join_next(), if !punch_tasks.is_empty() => {}
            Some((address, peer)) = success_rx.recv() => { if connected.len() < 64 { connected.insert(address, peer); } }
            Some(address) = fallbacks.recv(), if attempts.len() < 8 => {
                if peers.get_peer_map().list_peers_with_conn().await.is_empty() {
                    connect = Some((address, None));
                }
            }
            _ = retry.tick() => {
                connected.retain(|_, peer| peers.get_peer_map().has_peer(*peer));
                if !peers.get_peer_map().list_peers_with_conn().await.is_empty() { continue; }
                if let Some((&address, _)) = cached_candidates.iter()
                    .filter(|(address, time)| !connected.contains_key(address) && time.elapsed() >= Duration::from_secs(30))
                    .min_by_key(|(_, time)| **time) {
                    if retry_sender.try_send(address).is_ok() { cached_candidates.insert(address, Instant::now()); }
                }
            }
            Some(address) = candidates.recv(), if attempts.len() < 8 && punch_tasks.len() < 16 => {
                if connected.get(&address).is_some_and(|peer| peers.get_peer_map().has_peer(*peer)) { continue; }
                if cached_candidates.len() >= 64 && !cached_candidates.contains_key(&address) {
                    if let Some((&oldest, _)) = cached_candidates.iter().min_by_key(|(_, time)| **time) {
                        cached_candidates.remove(&oldest);
                    }
                }
                cached_candidates.insert(address, Instant::now());
                recent.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(30));
                if recent.contains_key(&address) { continue; }
                if endpoint.is_some() {
                    probes.retain(|_, (_, time)| time.elapsed() < Duration::from_secs(15));
                    // Duplicate tracker results must retain the challenge accepted by the responder.
                    if probes.contains_key(&address) || probes.len() >= 64 { continue; }
                    let nonce = rand::random();
                    probes.insert(address, (nonce, Instant::now()));
                    let udp = udp.clone();
                    let fallback = fallback_tx.clone();
                    punch_tasks.spawn(async move {
                        let start = Instant::now();
                        for millis in [0, 50, 150, 350, 750] {
                            tokio::time::sleep_until(start + Duration::from_millis(millis)).await;
                            let _ = udp.send_to(&wire::punch(&key, my_id, nonce, unix_seconds(), false), address).await;
                        }
                        // A reachable peer can accept QUIC even when the path drops custom probes.
                        let _ = fallback.try_send(address);
                    });
                } else { connect = Some((address, None)); }
            }
            packet = incoming.recv(), if endpoint.is_some() => {
                let packet = match packet { Ok(packet) => packet, Err(broadcast::error::RecvError::Lagged(_)) => continue, Err(error) => return Err(error.into()) };
                if ensure_remote_allowed(&ctx.get_underlay_policy(), packet.addr).is_err() { continue; }
                let Ok((peer, nonce, reply)) = wire::read_punch(&packet.data, &key, unix_seconds()) else { continue; };
                if peer == my_id { continue; }
                if reply {
                    if !probes.get(&packet.addr).is_some_and(|(sent, time)| *sent == nonce && time.elapsed() < Duration::from_secs(15)) { continue; }
                } else {
                    responses.retain(|_, time| time.elapsed() < Duration::from_secs(1));
                    if responses.len() >= 64 || responses.contains_key(&packet.addr) { continue; }
                    responses.insert(packet.addr, Instant::now());
                    let _ = udp.send_to(&wire::punch(&key, my_id, nonce, unix_seconds(), true), packet.addr).await;
                }
                if my_id < peer && !peers.get_peer_map().has_peer(peer) { connect = Some((packet.addr, Some(peer))); }
            }
        }
        let Some((address, expected)) = connect else {
            continue;
        };
        recent.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(30));
        if let Some((_, upgrade)) = recent.get_mut(&address) {
            if let Some(peer) = expected {
                if let Some(upgrade) = upgrade.take() {
                    // A verified probe can recover the mapped flow after a fresh-port fallback starts.
                    let _ = upgrade.send(peer);
                }
            }
            continue;
        }
        if attempts.len() >= 8 || recent.len() >= 64 {
            continue;
        }
        let (upgrade_tx, mut upgrade_rx) = if endpoint.is_some() && expected.is_none() {
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        recent.insert(address, (Instant::now(), upgrade_tx));
        let (ctx, peers, endpoint, tcp) =
            (ctx.clone(), peers.clone(), endpoint.clone(), tcp.clone());
        let success_tx = success_tx.clone();
        attempts.spawn(async move {
            let mut expected = expected;
            let _permit = if endpoint.is_some() {
                let Ok(permit) = acquire_quic_discovery_slot(
                    &QUIC_DISCOVERY_HANDSHAKES,
                    &mut upgrade_rx,
                    &mut expected,
                )
                .await
                else {
                    return;
                };
                let obsolete = if let Some(peer) = expected {
                    peers.get_peer_map().has_peer(peer)
                } else {
                    !peers.get_peer_map().list_peers_with_conn().await.is_empty()
                };
                if obsolete {
                    return;
                }
                Some(permit)
            } else {
                None
            };
            let result = tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
                let peer = if let Some(endpoint) = endpoint {
                    let tunnel = loop {
                        let connect = async {
                            let mut connector = if expected.is_some() {
                                QuicTunnelConnector::from_discovery_endpoint(
                                    endpoint.clone(),
                                    address,
                                    ctx.clone(),
                                )
                            } else {
                                // Preserve the mapped socket while testing a fresh bootstrap flow.
                                QuicTunnelConnector::from_discovery_source(
                                    local_ip,
                                    address,
                                    ctx.clone(),
                                )?
                            };
                            connector.connect().await
                        };
                        tokio::select! {
                            biased;
                            Ok(peer) = async {
                                match upgrade_rx.as_mut() {
                                    Some(receiver) => receiver.await,
                                    None => std::future::pending().await,
                                }
                            }, if expected.is_none() => { expected = Some(peer); }
                            tunnel = connect => break tunnel?,
                        }
                    };
                    peers.add_discovered_tunnel(tunnel, expected, true).await?
                } else {
                    connect_tcp_candidate(tcp.as_ref().unwrap(), &peers, address).await?
                };
                let _ = success_tx.try_send((address, peer));
                Ok::<(), anyhow::Error>(())
            })
            .await;
            match result {
                Ok(Ok(())) => {
                    tracing::info!(?address, "tracker bootstrap connected authenticated peer")
                }
                error => tracing::debug!(?address, ?error, "tracker bootstrap connection failed"),
            }
        });
    }
}

async fn connect_tcp_candidate(
    tcp: &TcpBootstrap,
    peers: &PeerManager,
    address: SocketAddr,
) -> Result<crate::common::PeerId> {
    // A stalled TLS or VPN handshake must leave time for the second source port.
    let mapped = tokio::time::timeout(BOOTSTRAP_TIMEOUT / 2, async {
        let tunnel = tcp.connect(address, false).await?;
        Ok::<_, anyhow::Error>(peers.add_discovered_tunnel(tunnel, None, true).await?)
    })
    .await
    .context("mapped TCP bootstrap attempt timed out")
    .and_then(|result| result);
    match mapped {
        Ok(peer) => Ok(peer),
        Err(error) => {
            // TIME_WAIT or destination-specific NAT state can outlive a failed bootstrap flow.
            // Keep the advertised listener and STUN mappings while trying one fresh source port.
            tracing::debug!(
                ?address,
                ?error,
                "TCP bootstrap retries with a fresh source port"
            );
            let tunnel = tcp.connect(address, true).await?;
            Ok(peers.add_discovered_tunnel(tunnel, None, true).await?)
        }
    }
}
