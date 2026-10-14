use super::wire::{self, Announce, Peers};
use crate::common::stun::StunPacket;
use anyhow::{Context, Result, ensure};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, broadcast},
    time::Instant,
};

pub struct UdpTracker {
    remote: SocketAddr,
    socket: Arc<UdpSocket>,
    packets: broadcast::Sender<StunPacket>,
    connection: Mutex<Option<(u64, Instant, Option<SocketAddr>)>>,
    private: bool,
    url_data: String,
}

impl UdpTracker {
    pub fn new(
        remote: SocketAddr,
        socket: Arc<UdpSocket>,
        packets: broadcast::Sender<StunPacket>,
    ) -> Self {
        Self {
            remote,
            socket,
            packets,
            connection: Mutex::new(None),
            private: false,
            url_data: String::new(),
        }
    }

    pub fn with_url(mut self, url: &url::Url, private: bool) -> Self {
        self.private = private;
        self.url_data = url[url::Position::BeforePath..url::Position::AfterQuery].to_owned();
        self
    }

    pub async fn observed_sample(&self) -> Option<(SocketAddr, Instant)> {
        self.connection
            .lock()
            .await
            .as_ref()
            .filter(|(_, received, _)| received.elapsed() < Duration::from_secs(60))
            .and_then(|(_, received, observed)| observed.map(|address| (address, *received)))
    }

    async fn exchange(&self, request: &[u8], action: u32, transaction: u32) -> Result<Vec<u8>> {
        let mut incoming = self.packets.subscribe();
        // Public trackers use the BEP 15 retry schedule, never the peer punch schedule.
        for attempt in 0..=2 {
            self.socket.send_to(request, self.remote).await?;
            let timeout = Duration::from_secs(15 << attempt);
            let result = tokio::time::timeout(timeout, async {
                loop {
                    let packet = match incoming.recv().await {
                        Ok(packet) => packet,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    if packet.addr != self.remote || packet.data.len() < 8 {
                        continue;
                    }
                    if packet.data[4..8] != transaction.to_be_bytes() {
                        continue;
                    }
                    wire::response_header(&packet.data, action, transaction)?;
                    return Ok(packet.data);
                }
            })
            .await;
            if let Ok(result) = result {
                return result;
            }
        }
        anyhow::bail!("tracker response timeout")
    }

    pub async fn connect(&self) -> Result<u64> {
        let mut cached = self.connection.lock().await;
        if let Some((connection, received, _)) = *cached {
            if received.elapsed() < Duration::from_secs(60) {
                return Ok(connection);
            }
        }
        let transaction = rand::random();
        let mut request = wire::connect_request(transaction).to_vec();
        if self.private {
            request.extend_from_slice(wire::ECHO_MAGIC);
            request.resize(48, 0);
        }
        let reply = self.exchange(&request, 0, transaction).await?;
        let connection = wire::connect_response(&reply, transaction)?;
        let observed = if self.private {
            wire::observed_connect(&reply)?
        } else {
            None
        };
        *cached = Some((connection, Instant::now(), observed));
        Ok(connection)
    }

    pub async fn announce(&self, announce: &Announce) -> Result<Peers> {
        ensure!(announce.port != 0, "cannot advertise port zero");
        let connection = self.connect().await?;
        let transaction = rand::random();
        let age = self
            .connection
            .lock()
            .await
            .as_ref()
            .map(|(_, time, _)| time.elapsed())
            .unwrap_or_default();
        let remaining = Duration::from_secs(60).saturating_sub(age);
        // This exchange must end before the connection cookie expires.
        let mut packet = announce.udp(connection, transaction).to_vec();
        wire::append_url_data(&mut packet, &self.url_data)?;
        let response = tokio::time::timeout(
            Duration::from_secs(45).min(remaining),
            self.exchange(&packet, 1, transaction),
        )
        .await
        .context("tracker announce cookie expired")??;
        wire::announce_response(&response, transaction, self.remote.is_ipv6())
    }
}

pub(super) async fn resolve_tracker_host(
    ctx: &crate::common::global_ctx::ArcGlobalCtx,
    host: String,
    port: u16,
) -> Result<Vec<SocketAddr>> {
    let net_ns = ctx.net_ns.clone();
    // Namespace state belongs to a thread. DNS and guard cleanup must use that same thread.
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        net_ns.run(|| {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect)
        })
    })
    .await
    .context("tracker DNS worker failed")?
    .context("tracker DNS lookup failed")
}

#[cfg(test)]
pub async fn http_announce(
    url: &url::Url,
    announce: &Announce,
    local: SocketAddr,
    ctx: &crate::common::global_ctx::ArcGlobalCtx,
) -> Result<Peers> {
    http_announce_rotating(url, announce, local, ctx, 0).await
}

pub(super) async fn http_announce_rotating(
    url: &url::Url,
    announce: &Announce,
    local: SocketAddr,
    ctx: &crate::common::global_ctx::ArcGlobalCtx,
    address_index: usize,
) -> Result<Peers> {
    use crate::tunnel::common::{bind, ensure_remote_allowed};
    use tokio::net::TcpSocket;
    let host = match url.host().context("tracker URL has no host")? {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    ensure!(
        url.scheme() == "http" || url.scheme() == "https",
        "invalid HTTP tracker scheme"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "tracker userinfo is unsupported"
    );
    let port = url
        .port_or_known_default()
        .context("tracker URL has no port")?;
    let addresses = resolve_tracker_host(ctx, host.clone(), port).await?;
    let mut allowed = addresses
        .into_iter()
        .filter(|remote| {
            remote.is_ipv4() == local.is_ipv4()
                && ensure_remote_allowed(&ctx.get_underlay_policy(), *remote).is_ok()
        })
        .collect::<Vec<_>>();
    allowed.sort_unstable();
    allowed.dedup();
    ensure!(!allowed.is_empty(), "no allowed tracker address");
    let remote = allowed[address_index % allowed.len()];
    let socket = bind::<TcpSocket>()
        .addr(SocketAddr::new(local.ip(), 0))
        .net_ns(ctx.net_ns.clone())
        .maybe_socket_mark(ctx.get_flags().socket_mark)
        .call()?;
    let stream = socket.connect(remote).await?;
    let observation_socket = stream.local_addr()?;
    let mut target = url.clone();
    let query = match url.query() {
        Some(existing) => format!("{existing}&{}", announce.http_query()),
        None => announce.http_query(),
    };
    target.set_query(Some(&query));
    let authority_host = url.host_str().unwrap();
    let authority = match url.port() {
        Some(port) => format!("{authority_host}:{port}"),
        None => authority_host.to_owned(),
    };
    let path = &target[url::Position::BeforePath..url::Position::AfterQuery];
    let response = if url.scheme() == "https" {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        ensure!(!roots.is_empty(), "no system roots for HTTPS tracker");
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await?;
        http_get(stream, &authority, path).await?
    } else {
        http_get(stream, &authority, path).await?
    };
    let peers = wire::http_response(&response)?;
    if let Some(endpoint) = peers.observed.filter(|endpoint| {
        endpoint.is_ipv4() == observation_socket.is_ipv4()
            && endpoint.port() != 0
            && !endpoint.ip().is_unspecified()
            && !endpoint.ip().is_multicast()
            && ensure_remote_allowed(&ctx.get_underlay_policy(), *endpoint).is_ok()
    }) {
        // The HTTP observation describes the tracker connection, not the VPN transport socket.
        ctx.record_discovery_observation(super::DiscoveryObservation {
            protocol: "http".into(),
            socket: observation_socket,
            observer: super::observer_uri(url),
            endpoint,
            sampled_at: std::time::Instant::now(),
            lifetime: None,
            provisional: true,
        });
    }
    Ok(peers)
}

async fn http_get<S>(stream: S, host: &str, path: &str) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = http::Request::builder()
        .uri(path)
        .header(http::header::HOST, host)
        .header(http::header::USER_AGENT, "aria2/1.37.0")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    ensure!(
        response.status() == http::StatusCode::OK,
        "HTTP tracker returned {}",
        response.status()
    );
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            ensure!(
                bytes.len() + data.len() <= wire::MAX_RESPONSE,
                "HTTP tracker body too large"
            );
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}
