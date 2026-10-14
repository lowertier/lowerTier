//! Bounded socket and port search for one destination-dependent NAT.

use super::*;
use futures::{StreamExt, stream::FuturesUnordered};

use crate::connector::traversal::{
    EXPANDED_SOCKET_LIMIT, EXPANDED_TRAVERSAL_TIMEOUT, PORT_SEARCH_LIMIT, expanded_candidates,
    random_search_ports,
};
pub(super) use crate::connector::traversal::{Strategy, strategy};

// Probe traffic needs a small backlog. QUIC sizes only the selected socket.
struct ProbeSocket(UdpSocket);

impl crate::tunnel::common::Bindable for ProbeSocket {
    const TYPE: socket2::Type = socket2::Type::DGRAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::UDP);

    fn finalize(socket: socket2::Socket) -> std::result::Result<Self, crate::tunnel::TunnelError> {
        socket.set_recv_buffer_size(16 * 1024)?;
        socket.set_send_buffer_size(16 * 1024)?;
        Ok(Self(UdpSocket::from_std(socket.into())?))
    }
}

pub(super) fn mapping_varies(local: SocketAddr, candidates: &[SocketAddr]) -> bool {
    candidates
        .iter()
        .filter(|address| **address != local)
        .count()
        > 1
}

async fn receive(
    index: usize,
    socket: &UdpSocket,
    mut buffer: Vec<u8>,
) -> (usize, std::io::Result<(usize, SocketAddr)>, Vec<u8>) {
    let result = socket.recv_from(&mut buffer).await;
    (index, result, buffer)
}

pub(super) async fn run(
    socket: UdpSocket,
    candidates: &[SocketAddr],
    transaction: &[u8; 12],
    ctx: &ArcGlobalCtx,
    activation: Option<oneshot::Receiver<()>>,
    mode: Strategy,
) -> Result<(UdpSocket, SocketAddr)> {
    if mode == Strategy::Candidates {
        let remote = punch(&socket, candidates, transaction, ctx, activation).await?;
        return Ok((socket, remote));
    }
    let candidates = expanded_candidates(ctx, candidates, "QUIC")?;
    let ports = random_search_ports();
    run_with_ports(
        socket,
        &candidates,
        transaction,
        ctx,
        activation,
        mode,
        ports,
    )
    .await
}

async fn run_with_ports(
    socket: UdpSocket,
    candidates: &[SocketAddr],
    transaction: &[u8; 12],
    ctx: &ArcGlobalCtx,
    mut activation: Option<oneshot::Receiver<()>>,
    mode: Strategy,
    ports: Vec<u16>,
) -> Result<(UdpSocket, SocketAddr)> {
    // Drop inline receive futures and pool sockets before releasing this permit.
    let _permit = if mode == Strategy::SocketPool {
        Some(crate::connector::traversal_resources::PERMIT.try_acquire()?)
    } else {
        None
    };
    ensure!(
        !candidates.is_empty() && candidates.len() <= MAX_CANDIDATES,
        "invalid hard NAT candidates"
    );
    ensure!(
        ports.len() <= PORT_SEARCH_LIMIT,
        "hard NAT port budget exceeded"
    );
    for candidate in candidates {
        ensure_remote_allowed(&ctx.get_underlay_policy(), *candidate)?;
    }
    let local = socket.local_addr()?;
    ensure_local_allowed(&ctx.get_underlay_policy(), local)?;
    socket2::SockRef::from(&socket).set_recv_buffer_size(16 * 1024)?;
    socket2::SockRef::from(&socket).set_send_buffer_size(16 * 1024)?;
    let mut sockets = vec![socket];
    if mode == Strategy::SocketPool {
        let count = crate::connector::traversal_resources::capacity(1, 0, EXPANDED_SOCKET_LIMIT)?;
        for _ in 1..count {
            sockets.push(
                bind::<ProbeSocket>()
                    .addr(SocketAddr::new(local.ip(), 0))
                    .net_ns(ctx.net_ns.clone())
                    .maybe_socket_mark(ctx.get_flags().socket_mark)
                    .call()?
                    .0,
            );
        }
    }
    let mut reads = FuturesUnordered::new();
    for (index, socket) in sockets.iter().enumerate() {
        reads.push(receive(index, socket, vec![0; 512]));
    }
    // Overlap probability depends on the allocated pool and searched ports.
    // Every selected path still needs bidirectional proof.
    let spacing = if mode == Strategy::SocketPool { 8 } else { 5 };
    let mut tick = tokio::time::interval(Duration::from_millis(spacing));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let request = binding_request(transaction);
    // A separate transaction confirms the initiator's nominated pair.
    // Probe requests alone cannot select either endpoint.
    let mut nomination = *transaction;
    nomination[11] ^= 1;
    let nominate = binding_request(&nomination);
    let initiator = activation.is_none();
    let mut selected: Option<(usize, SocketAddr)> = None;
    let mut sends = 0usize;
    let mut port_index = 0usize;
    let mut socket_index = 0usize;
    let mut keepalive = tokio::time::Instant::now();
    let result = tokio::time::timeout(EXPANDED_TRAVERSAL_TIMEOUT, async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let target = if let Some((index, remote)) = selected {
                        if keepalive.elapsed() < Duration::from_millis(200) { continue; }
                        keepalive = tokio::time::Instant::now();
                        Some((index, remote))
                    } else if mode == Strategy::SocketPool {
                        // The stable endpoint remains the same destination for every mapping.
                        let index = socket_index % sockets.len();
                        socket_index += 1;
                        Some((index, candidates[0]))
                    } else if port_index < ports.len() {
                        let remote = SocketAddr::new(candidates[port_index % candidates.len()].ip(), ports[port_index]);
                        port_index += 1;
                        Some((0, remote))
                    } else { None };
                    if let Some((index, remote)) = target {
                        let payload = if initiator && selected.is_some() { &nominate } else { &request };
                        if let Err(error) = sockets[index].send_to(payload, remote).await {
                            tracing::trace!(?error, ?remote, "hard NAT probe send failed");
                        }
                        sends += 1;
                    }
                }
                activated = async { activation.as_mut().unwrap().await }, if activation.is_some() => {
                    activated.context("hard NAT activation was cancelled")?;
                    return selected.context("hard NAT activation has no verified endpoint");
                }
                received = reads.next() => {
                    let (index, received, buffer) = received.context("hard NAT receivers stopped")?;
                    let mut completed = None;
                    if let Ok((length, source)) = received {
                        let eligible = candidates.iter().any(|candidate| candidate.ip() == source.ip())
                            && source.port() != 0
                            && selected.is_none_or(|winner| winner == (index, source));
                        if eligible && buffer[..length] == request {
                            let _ = sockets[index].send_to(&binding_response(transaction, source), source).await;
                        } else if eligible && !initiator && buffer[..length] == nominate {
                            selected = Some((index, source));
                            let _ = sockets[index].send_to(&binding_response(&nomination, source), source).await;
                        } else if eligible && length == 32 && buffer[..8] == [1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42]
                            && buffer[20..26] == [0, 0x20, 0, 8, 0, 1] && initiator {
                            if buffer[8..20] == *transaction && selected.is_none() {
                                selected = Some((index, source));
                                let _ = sockets[index].send_to(&nominate, source).await;
                            } else if buffer[8..20] == nomination && selected == Some((index, source)) {
                                completed = selected;
                            }
                        }
                    }
                    reads.push(receive(index, &sockets[index], buffer));
                    if let Some(winner) = completed { return Ok(winner); }
                }
            }
        }
    }).await.context("hard NAT traversal timed out")?;
    drop(reads);
    let (index, remote) = result?;
    let socket = sockets.swap_remove(index);
    tracing::info!(?mode, local = ?socket.local_addr()?, ?remote, sends, port_index,
        allocated_sockets = sockets.len() + 1, "hard NAT selected a direct socket");
    Ok((socket, remote))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    };
    use futures::SinkExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    #[test]
    fn udp_pool_preserves_descriptors_and_releases_shared_capacity() {
        const CHILD: &str = "LOWERTIER_UDP_FD_LIMIT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "connector::quic_hole_punch::hard_nat::tests::udp_pool_preserves_descriptors_and_releases_shared_capacity", "--test-threads=1"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use crate::connector::traversal_resources::{PERMIT, capacity, open_descriptors};
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert!(hard >= 256);
        setrlimit(Resource::RLIMIT_NOFILE, 256, hard).unwrap();
        let _existing = (0..128)
            .map(|_| std::fs::File::open("/dev/null").unwrap())
            .collect::<Vec<_>>();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let ctx = super::super::tests::context();
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let candidates = [peer.local_addr().unwrap()];
            let token = [42; 12];
            let held = PERMIT.try_acquire().unwrap();
            let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            assert!(
                run_with_ports(
                    blocked,
                    &candidates,
                    &token,
                    &ctx,
                    None,
                    Strategy::SocketPool,
                    vec![]
                )
                .await
                .is_err()
            );
            drop(held);

            let pool = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let before = open_descriptors().unwrap();
            let count = capacity(1, 0, EXPANDED_SOCKET_LIMIT).unwrap();
            assert!(count < EXPANDED_SOCKET_LIMIT);
            let mut running = Box::pin(run_with_ports(
                pool,
                &candidates,
                &token,
                &ctx,
                None,
                Strategy::SocketPool,
                vec![],
            ));
            assert!(futures::poll!(running.as_mut()).is_pending());
            assert!(PERMIT.try_acquire().is_err());
            assert_eq!(open_descriptors().unwrap(), before + count - 1);
            assert!(count <= (256 - before) / 2);
            let control = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let client = std::net::TcpStream::connect(control.local_addr().unwrap()).unwrap();
            let (server, _) = control.accept().unwrap();
            assert_eq!(client.local_addr().unwrap(), server.peer_addr().unwrap());
            drop((control, client, server));
            drop(running);
            let _released = PERMIT.try_acquire().unwrap();
            assert_eq!(open_descriptors().unwrap(), before - 1);
        });
    }

    #[tokio::test]
    #[serial_test::serial(traversal_expansion)]
    async fn restrictive_nat_establishes_quic_in_both_roles() {
        for pool_is_client in [true, false] {
            tokio::time::timeout(Duration::from_secs(8), scenario(pool_is_client))
                .await
                .unwrap();
        }
    }

    async fn scenario(pool_is_client: bool) {
        let ctx = super::super::tests::context();
        let pool = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cone_inside = cone.local_addr().unwrap();
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cone_public = front.local_addr().unwrap();
        let stale = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stale_public = stale.local_addr().unwrap();
        let translated_count =
            crate::connector::traversal_resources::capacity(1, 0, EXPANDED_SOCKET_LIMIT).unwrap();
        let mut translated = Vec::with_capacity(translated_count);
        for _ in 0..translated_count {
            translated.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        let ports: Vec<_> = translated
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        let blocked = Arc::new(AtomicUsize::new(0));
        let blocked_count = blocked.clone();
        let first_blocked = Arc::new(tokio::sync::Notify::new());
        let proxy_blocked = first_blocked.clone();
        let proxy = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let mut mappings: HashMap<SocketAddr, usize> = HashMap::new();
            let mut inside = vec![None; translated_count];
            let mut opened = vec![false; translated_count];
            let mut reads = FuturesUnordered::new();
            for (i, socket) in translated.iter().enumerate() {
                reads.push(receive(i, socket, vec![0; 65535]));
            }
            let mut buffer = vec![0; 65535];
            loop {
                tokio::select! {
                    packet = front.recv_from(&mut buffer) => {
                        let (length, source) = packet.unwrap();
                        let next = mappings.len();
                        let index = *mappings.entry(source).or_insert(next);
                        assert!(index < translated_count);
                        inside[index] = Some(source);
                        if opened[index] {
                            translated[index].send_to(&buffer[..length], cone_inside).await.unwrap();
                        } else {
                            if blocked_count.fetch_add(1, Ordering::Relaxed) == 0 {
                                proxy_blocked.notify_one();
                            }
                        }
                    }
                    packet = reads.next() => {
                        let (index, packet, buffer) = packet.unwrap();
                        let (length, source) = packet.unwrap();
                        assert_eq!(source, cone_inside);
                        // Outbound contact opens only this exact external source port.
                        opened[index] = true;
                        if let Some(destination) = inside[index] {
                            front.send_to(&buffer[..length], destination).await.unwrap();
                        }
                        reads.push(receive(index, &translated[index], buffer));
                    }
                }
            }
        }));
        let token = rand::random();
        let (activate, activation) = oneshot::channel();
        let server_ctx = ctx.clone();
        let server_ports = ports.clone();
        let server_blocked = first_blocked.clone();
        let (
            server_socket,
            server_candidate,
            server_mode,
            client_socket,
            client_candidate,
            client_mode,
        ) = if pool_is_client {
            (
                cone,
                stale_public,
                Strategy::PortSearch,
                pool,
                cone_public,
                Strategy::SocketPool,
            )
        } else {
            (
                pool,
                cone_public,
                Strategy::SocketPool,
                cone,
                stale_public,
                Strategy::PortSearch,
            )
        };
        let server = tokio::spawn(async move {
            if server_mode == Strategy::PortSearch {
                server_blocked.notified().await;
            }
            let (socket, _) = run_with_ports(
                server_socket,
                &[server_candidate],
                &token,
                &server_ctx,
                Some(activation),
                server_mode,
                server_ports,
            )
            .await
            .unwrap();
            let local = socket.local_addr().unwrap();
            let mut listener = QuicTunnelListener::from_punched_socket(socket, server_ctx).unwrap();
            let tunnel = listener.accept().await.unwrap();
            (tunnel, local)
        });
        if client_mode == Strategy::PortSearch {
            first_blocked.notified().await;
        }
        let (client_socket, remote) = run_with_ports(
            client_socket,
            &[client_candidate],
            &token,
            &ctx,
            None,
            client_mode,
            ports,
        )
        .await
        .unwrap();
        activate.send(()).unwrap();
        let local = client_socket.local_addr().unwrap();
        let mut connector = QuicTunnelConnector::from_punched_socket(client_socket, remote, ctx);
        let client_tunnel = connector.connect().await.unwrap();
        let (server_tunnel, server_local) = server.await.unwrap();
        assert!(client_tunnel.transport_binding().is_some());
        assert_eq!(
            client_tunnel.transport_binding(),
            server_tunnel.transport_binding()
        );
        let (mut client_rx, mut client_tx) = client_tunnel.split();
        let (mut server_rx, mut server_tx) = server_tunnel.split();
        let mut packet = ZCPacket::new_with_payload(b"hard NAT QUIC payload");
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        client_tx
            .send(PacketBatch::singleton(packet))
            .await
            .unwrap();
        server_tx
            .send(server_rx.next().await.unwrap().unwrap())
            .await
            .unwrap();
        let received = client_rx
            .next()
            .await
            .unwrap()
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(received.payload(), b"hard NAT QUIC payload");
        assert!(blocked.load(Ordering::Relaxed) > 0);
        assert_ne!(local.port(), 0);
        assert_ne!(server_local.port(), 0);
        drop(proxy);
    }

    #[tokio::test]
    #[serial_test::serial(traversal_expansion)]
    async fn cancelled_pool_releases_the_original_socket() {
        let ctx = super::super::tests::context();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(80),
            run_with_ports(
                socket,
                &[blackhole.local_addr().unwrap()],
                &[42; 12],
                &ctx,
                None,
                Strategy::SocketPool,
                vec![],
            ),
        )
        .await;
        assert!(result.is_err());
        assert!(UdpSocket::bind(local).await.is_ok());
    }

    #[tokio::test]
    async fn disabled_symmetric_traversal_does_not_probe() {
        let ctx = super::super::tests::context();
        let mut flags = ctx.get_flags();
        flags.disable_sym_hole_punching = true;
        ctx.set_flags(flags);
        for mode in [Strategy::SocketPool, Strategy::PortSearch] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let result = run(socket, &[], &[0; 12], &ctx, None, mode).await;
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("symmetric NAT traversal is disabled")
            );
        }
    }

    #[tokio::test]
    async fn nomination_overrides_a_probe_from_another_mapping() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let ctx = super::super::tests::context();
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let winner = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let candidate = first.local_addr().unwrap();
            let token = [37; 12];
            let (activate, activation) = oneshot::channel();
            let task = tokio::spawn(async move {
                run_with_ports(
                    server,
                    &[candidate],
                    &token,
                    &ctx,
                    Some(activation),
                    Strategy::PortSearch,
                    vec![],
                )
                .await
                .unwrap()
            });
            first
                .send_to(&binding_request(&token), address)
                .await
                .unwrap();
            let mut buffer = [0; 512];
            let (length, _) = first.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], binding_response(&token, candidate));
            let mut nomination = token;
            nomination[11] ^= 1;
            winner
                .send_to(&binding_request(&nomination), address)
                .await
                .unwrap();
            let (length, _) = winner.recv_from(&mut buffer).await.unwrap();
            assert_eq!(
                &buffer[..length],
                binding_response(&nomination, winner.local_addr().unwrap())
            );
            activate.send(()).unwrap();
            let (_, remote) = task.await.unwrap();
            assert_eq!(remote, winner.local_addr().unwrap());
        })
        .await
        .unwrap();
    }
}
