//! Bounded native TCP traversal for one destination-dependent NAT.

use super::*;
use tokio::{sync::mpsc, time::Instant};

use crate::connector::traversal::{
    EXPANDED_SOCKET_LIMIT, EXPANDED_TRAVERSAL_TIMEOUT, PORT_SEARCH_LIMIT, expanded_candidates,
    random_search_ports,
};
pub(super) use crate::connector::traversal::{Strategy, strategy};
pub(super) use crate::connector::traversal_resources::PERMIT;
#[cfg(all(unix, test))]
use crate::connector::traversal_resources::open_descriptors;
pub(super) const TIMEOUT: Duration = EXPANDED_TRAVERSAL_TIMEOUT;
// Allow SYN retransmissions at approximately 1, 3, and 7 seconds.
const SEARCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
// Account for handoff, transport handshakes, and one newly accepted stream.
const STREAM_RESERVE: usize = 2 * MAX_CANDIDATES + 1;

pub(super) fn mapping_varies(mapping: &TcpPortMappings) -> bool {
    mapping
        .addresses
        .iter()
        .any(|address| mapping.addresses.first() != Some(address))
}

fn connection_limit(mode: Strategy) -> Result<usize> {
    let per_connection = if mode == Strategy::SocketPool { 2 } else { 1 };
    crate::connector::traversal_resources::capacity(
        per_connection,
        STREAM_RESERVE,
        EXPANDED_SOCKET_LIMIT,
    )
}

pub(super) struct Prepared {
    mode: Strategy,
    local: SocketAddr,
    candidates: Vec<SocketAddr>,
    listeners: Vec<Arc<TcpListener>>,
    ports: Vec<u16>,
    connection_limit: usize,
    // Drop owned listeners before releasing this permit.
    permit: Option<Arc<tokio::sync::SemaphorePermit<'static>>>,
}

impl Prepared {
    pub(super) fn new(
        ctx: &ArcGlobalCtx,
        local: SocketAddr,
        candidates: &[SocketAddr],
        mode: Strategy,
    ) -> Result<Self> {
        let candidates = expanded_candidates(ctx, candidates, "TCP")?;
        let ports = if mode == Strategy::PortSearch {
            random_search_ports()
        } else {
            Vec::new()
        };
        Self::with_ports(ctx, local, candidates, mode, ports)
    }

    fn with_ports(
        ctx: &ArcGlobalCtx,
        local: SocketAddr,
        candidates: Vec<SocketAddr>,
        mode: Strategy,
        ports: Vec<u16>,
    ) -> Result<Self> {
        ensure!(
            mode != Strategy::Candidates,
            "TCP traversal needs an expanded strategy"
        );
        ensure!(!candidates.is_empty(), "TCP traversal has no candidate");
        ensure!(
            ports.len() <= PORT_SEARCH_LIMIT,
            "TCP search port limit exceeded"
        );
        let connection_limit = connection_limit(mode)?;
        let mut listeners = Vec::new();
        if mode == Strategy::SocketPool {
            for _ in 0..connection_limit {
                listeners.push(Arc::new(listen(ctx, SocketAddr::new(local.ip(), 0))?));
            }
        }
        tracing::debug!(?mode, connection_limit, "TCP traversal descriptor capacity");
        Ok(Self {
            mode,
            local,
            candidates,
            listeners,
            ports,
            connection_limit,
            permit: None,
        })
    }

    pub(super) fn with_permit(mut self, permit: tokio::sync::SemaphorePermit<'static>) -> Self {
        self.permit = Some(Arc::new(permit));
        self
    }

    pub(super) async fn run(
        self,
        ctx: ArcGlobalCtx,
        streams: mpsc::Sender<TcpStream>,
    ) -> Result<()> {
        self.run_inner(ctx, streams).await
    }

    async fn run_inner(self, ctx: ArcGlobalCtx, streams: mpsc::Sender<TcpStream>) -> Result<()> {
        let mut accepts = futures::stream::FuturesUnordered::new();
        let mut locals = Vec::new();
        for listener in &self.listeners {
            locals.push(listener.local_addr()?);
            accepts.push(accept_once(listener.clone()));
        }
        let mut pending = vec![false; locals.len()];
        let mut retries = vec![Instant::now(); locals.len()];
        let mut connects = JoinSet::new();
        let mut next = 0usize;
        let mut launched = 0usize;
        let mut tick = tokio::time::interval(Duration::from_millis(8));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = streams.closed() => return Ok(()),
                _ = tick.tick(), if connects.len() < self.connection_limit => {
                    let attempt = match self.mode {
                        Strategy::SocketPool => {
                            let index = next % locals.len();
                            next = next.wrapping_add(1);
                            if pending[index] || retries[index] > Instant::now() { continue; }
                            pending[index] = true;
                            Some((Some(index), locals[index], self.candidates[0]))
                        }
                        Strategy::PortSearch if next < self.ports.len() => {
                            let remote = SocketAddr::new(self.candidates[next % self.candidates.len()].ip(), self.ports[next]);
                            next += 1;
                            Some((None, self.local, remote))
                        }
                        _ => None,
                    };
                    if let Some((index, local, remote)) = attempt {
                        let context = ctx.clone();
                        let permit = self.permit.clone();
                        connects.spawn(async move {
                            // JoinSet cancellation can outlive its parent future.
                            let _permit = permit;
                            let result = if index.is_some() {
                                connect_bound(context, local, remote).await
                            } else {
                                tokio::time::timeout(SEARCH_CONNECT_TIMEOUT, connect_bound(context, local, remote))
                                    .await.context("TCP search connection timed out").and_then(|result| result)
                            };
                            (index, remote, result)
                        });
                        launched += 1;
                    }
                }
                accepted = accepts.next(), if !accepts.is_empty() => {
                    let (listener, accepted) = accepted.context("TCP pool listeners stopped")?;
                    accepts.push(accept_once(listener));
                    match accepted {
                        Ok((stream, source)) if self.candidates.iter().any(|remote| remote.ip() == source.ip()) => {
                            let _ = streams.try_send(stream);
                        }
                        Ok(_) => {}
                        Err(error) => tracing::debug!(?error, "TCP pool accept failed"),
                    }
                }
                connected = connects.join_next(), if !connects.is_empty() => {
                    let (index, remote, result) = connected.context("TCP search connectors stopped")??;
                    if let Some(index) = index {
                        pending[index] = false;
                        retries[index] = Instant::now() + Duration::from_secs(4);
                    }
                    match result {
                        Ok(stream) => {
                            tracing::debug!(mode = ?self.mode, ?remote, launched, "TCP traversal found a stream");
                            let _ = streams.try_send(stream);
                        }
                        Err(error) => tracing::trace!(?remote, ?error, "TCP traversal connection failed"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};
    use tokio_util::task::AbortOnDropHandle;

    #[tokio::test]
    #[serial_test::serial(traversal_expansion)]
    async fn cancelled_tcp_search_retains_its_permit_until_workers_stop() {
        use std::{future::Future, task::Poll};
        for mode in [Strategy::SocketPool, Strategy::PortSearch] {
            let ctx = super::super::tests::context();
            let listener = listen(&ctx, "127.0.0.1:0".parse().unwrap()).unwrap();
            let local = listener.local_addr().unwrap();
            let prepared = Prepared::with_ports(&ctx, local, vec![local], mode, vec![local.port()])
                .unwrap()
                .with_permit(PERMIT.acquire().await.unwrap());
            let ownership = Arc::downgrade(prepared.permit.as_ref().unwrap());
            let (sender, _receiver) = mpsc::channel(MAX_CANDIDATES);
            let mut running = Box::pin(prepared.run(ctx, sender));
            tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| {
                    assert!(running.as_mut().poll(cx).is_pending());
                    // The timer can yield before spawning the first connection worker.
                    if ownership.strong_count() > 1 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }),
            )
            .await
            .unwrap();
            drop(running);
            // Aborted tasks still own their resources until the executor destroys them.
            assert!(PERMIT.try_acquire().is_err());
            let _released = tokio::time::timeout(Duration::from_secs(1), PERMIT.acquire())
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn port_search_reaches_an_unadvertised_pool_port_with_native_h2_and_wss() {
        for protocol in [Protocol::H2, Protocol::Wss] {
            for pool_is_client in [true, false] {
                tokio::time::timeout(Duration::from_secs(8), async {
                    let ctx = super::super::tests::context();
                    let stable = listen(&ctx, "127.0.0.1:0".parse().unwrap()).unwrap();
                    let local = stable.local_addr().unwrap();
                    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let stale = closed.local_addr().unwrap();
                    let pool = Prepared::with_ports(
                        &ctx,
                        local,
                        vec![stale],
                        Strategy::SocketPool,
                        vec![],
                    )
                    .unwrap();
                    assert_eq!(pool.listeners.len(), pool.connection_limit);
                    let target = pool.listeners.last().unwrap().local_addr().unwrap();
                    let search = Prepared::with_ports(
                        &ctx,
                        local,
                        vec![stale],
                        Strategy::PortSearch,
                        vec![stale.port(), target.port()],
                    )
                    .unwrap();
                    assert_ne!(target, stale);
                    drop(closed);
                    let (pool_tx, mut pool_rx) = mpsc::channel(MAX_CANDIDATES);
                    let (search_tx, mut search_rx) = mpsc::channel(MAX_CANDIDATES);
                    let pool_task =
                        AbortOnDropHandle::new(tokio::spawn(pool.run_inner(ctx.clone(), pool_tx)));
                    let search_task = AbortOnDropHandle::new(tokio::spawn(
                        search.run_inner(ctx.clone(), search_tx),
                    ));
                    let outgoing = search_rx.recv().await.unwrap();
                    let incoming = pool_rx.recv().await.unwrap();
                    assert_eq!(outgoing.local_addr().unwrap(), local);
                    assert_eq!(outgoing.peer_addr().unwrap(), target);
                    assert_eq!(incoming.local_addr().unwrap(), target);
                    assert_eq!(incoming.peer_addr().unwrap(), local);
                    let (pool, search) = tokio::join!(
                        establish(incoming, ctx.clone(), protocol, pool_is_client),
                        establish(outgoing, ctx, protocol, !pool_is_client),
                    );
                    let token = rand::random();
                    let (pool, search) = tokio::join!(
                        nominate(pool.unwrap(), token, pool_is_client),
                        nominate(search.unwrap(), token, !pool_is_client),
                    );
                    let (pool, search) = (pool.unwrap(), search.unwrap());
                    assert!(pool.transport_binding().is_some());
                    assert_eq!(pool.transport_binding(), search.transport_binding());
                    // TLS overlaps traversal. Closing the workers must preserve the selected stream.
                    drop((pool_rx, search_rx));
                    pool_task.await.unwrap().unwrap();
                    search_task.await.unwrap().unwrap();
                    let (_, mut writer) = pool.split();
                    let (mut reader, _) = search.split();
                    let mut packet = ZCPacket::new_with_payload(b"native TCP search");
                    packet.fill_peer_manager_hdr(
                        1,
                        2,
                        crate::tunnel::packet_def::PacketType::Data as u8,
                    );
                    writer.send(PacketBatch::singleton(packet)).await.unwrap();
                    assert_eq!(
                        reader
                            .next()
                            .await
                            .unwrap()
                            .unwrap()
                            .pop_singleton()
                            .unwrap()
                            .payload(),
                        b"native TCP search"
                    );
                })
                .await
                .expect("native TCP search did not complete");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn tcp_pool_preserves_descriptors_for_existing_work() {
        const CHILD: &str = "LOWERTIER_FD_LIMIT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "connector::tcp_hole_punch::hard_nat::tests::tcp_pool_preserves_descriptors_for_existing_work", "--test-threads=1"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        assert!(hard >= 256);
        setrlimit(Resource::RLIMIT_NOFILE, 256, hard).unwrap();
        let before = open_descriptors().unwrap();
        let _existing = (0..128)
            .map(|_| std::fs::File::open("/dev/null").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(open_descriptors().unwrap(), before + 128);
        assert!(connection_limit(Strategy::SocketPool).unwrap() * 2 + STREAM_RESERVE <= 128);
        assert!(connection_limit(Strategy::PortSearch).unwrap() + STREAM_RESERVE <= 128);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let ctx = super::super::tests::context();
            let local = "127.0.0.1:0".parse().unwrap();
            for mode in [Strategy::SocketPool, Strategy::PortSearch] {
                let available = 256 - open_descriptors().unwrap();
                let pool = Prepared::with_ports(&ctx, local, vec![local], mode, vec![1]).unwrap();
                let listeners = pool.listeners.len();
                // Own the full connection and handoff capacity, including sockets awaiting TLS.
                let _pending = (0..pool.connection_limit + STREAM_RESERVE)
                    .map(|_| TcpSocket::new_v4().unwrap())
                    .collect::<Vec<_>>();
                assert!(listeners + pool.connection_limit + STREAM_RESERVE <= available / 2);
                let control = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let client = std::net::TcpStream::connect(control.local_addr().unwrap()).unwrap();
                let (server, _) = control.accept().unwrap();
                assert_eq!(client.local_addr().unwrap(), server.peer_addr().unwrap());
            }
        });
        drop(runtime);
        port_search_reaches_an_unadvertised_pool_port_with_native_h2_and_wss();
    }
}
