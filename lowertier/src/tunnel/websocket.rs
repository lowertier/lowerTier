use super::{
    FromUrl, IpVersion, TransportBinding, TransportBindingKind, Tunnel, TunnelConnector,
    TunnelError, TunnelListener,
    common::{TunnelWrapper, wait_for_connect_futures},
    packet_def::{ZCPacket, ZCPacketType},
};
use crate::tunnel::common::{
    bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
};
use crate::{common::underlay_policy::UnderlayPolicy, proto::common::TunnelInfo};
use anyhow::Context;
use forwarded_header_value::ForwardedHeaderValue;
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use pnet::ipnetwork::IpNetwork;
use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_websockets::{ClientBuilder, Config as WebSocketConfig, Limits, Message, ServerBuilder};
use zerocopy::AsBytes;

mod cdn;

const HTTP_1_1_ALPN: &[u8] = b"http/1.1";
// Match the bounded lane receive budget, including control packets.
const MAX_WS_MESSAGE_BYTES: usize = super::tcp_lanes::MAX_PENDING_BYTES;
const WSS_TRANSPORT_BINDING_LABEL: &[u8] = b"EXPORTER-LowTier-Wss-PeerConn-v1";
const WSS_TRANSPORT_BINDING_CONTEXT: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256|peerconn-v3|wss";
const WS_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

fn is_wss(addr: &url::Url) -> Result<bool, TunnelError> {
    match addr.scheme() {
        "wss" => Ok(true),
        "ws" => Ok(false),
        _ => Err(TunnelError::InvalidProtocol(addr.scheme().to_string())),
    }
}

fn normalize_ws_url(mut addr: url::Url) -> url::Url {
    if addr.path().is_empty() || addr.path() == "/" {
        addr.set_path("/ws");
    }
    addr
}

fn ws_via_cdn(url: &url::Url) -> bool {
    url.query_pairs().any(|(key, value)| {
        key == "via" && (value.eq_ignore_ascii_case("cdn") || value.eq_ignore_ascii_case("proxy"))
    })
}

fn ws_http_url(url: &url::Url) -> url::Url {
    let mut url = normalize_ws_url(url.clone());
    let rest: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "via")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if rest.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(rest);
    }
    url
}

fn ws_peer_tunnel_type(url: &url::Url) -> &'static str {
    if is_wss(url).unwrap_or(false) || ws_via_cdn(url) {
        "wss"
    } else {
        "ws"
    }
}

fn websocket_origin(addr: &url::Url) -> String {
    let scheme = if addr.scheme() == "wss" {
        "https"
    } else {
        "http"
    };
    match (addr.host_str(), addr.port()) {
        (Some(host), Some(port)) => format!("{scheme}://{host}:{port}"),
        (Some(host), None) => format!("{scheme}://{host}"),
        _ => format!("{scheme}://localhost"),
    }
}

fn wss_server_config() -> Result<rustls::ServerConfig, TunnelError> {
    let provider = super::stealth_tls::stealth_crypto_provider();
    let (certs, key) = super::stealth_tls::shared_ephemeral_identity();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("configure WSS TLS versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| "Failed to create WSS server config")?;
    config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];
    Ok(config)
}

fn derive_wss_binding(
    export: impl FnOnce(&mut [u8]) -> Result<(), rustls::Error>,
) -> Result<TransportBinding, TunnelError> {
    let mut bytes = [0_u8; 32];
    export(&mut bytes).map_err(|error| {
        TunnelError::InternalError(format!("derive WSS transport binding: {error:?}"))
    })?;
    Ok(TransportBinding {
        kind: TransportBindingKind::WssTlsExporterV1,
        bytes,
    })
}

fn browser_ws_client(addr: &url::Url) -> Result<ClientBuilder<'_>, TunnelError> {
    let origin = websocket_origin(addr);
    let origin = http::HeaderValue::from_str(&origin)
        .map_err(|_| TunnelError::InvalidAddr(format!("invalid websocket origin for {addr}")))?;
    let mut client =
        ClientBuilder::from_uri(http::Uri::try_from(ws_http_url(addr).to_string()).unwrap())
            .limits(Limits::default().max_payload_len(Some(MAX_WS_MESSAGE_BYTES)));
    if ws_via_cdn(addr) {
        client = client.add_header(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static(cdn::SUBPROTOCOL),
        )?;
    }
    if super::tcp_lanes::requested(addr)? > 1 {
        // Explicit batch flushes still send small/control messages immediately.
        client = client
            .config(WebSocketConfig::default().flush_threshold(64 * 1024))
            .limits(Limits::default().max_payload_len(Some(super::tcp_lanes::MAX_PENDING_BYTES)));
    }
    client
        .max_headers(128)
        .add_header(http::header::ORIGIN, origin)?
        .add_header(
            http::header::USER_AGENT,
            http::HeaderValue::from_static(WS_USER_AGENT),
        )?
        .add_header(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-cache"),
        )?
        .add_header(
            http::header::PRAGMA,
            http::HeaderValue::from_static("no-cache"),
        )
        .map_err(Into::into)
}

fn sink_from_zc_packet<E>(msg: ZCPacket) -> futures::future::Ready<Result<Message, E>> {
    futures::future::ready(Ok(Message::binary(msg.tunnel_payload_into_bytes())))
}

async fn map_from_ws_message(
    msg: Result<Message, tokio_websockets::Error>,
) -> Option<Result<ZCPacket, TunnelError>> {
    if let Err(e) = msg {
        tracing::error!(?e, "recv from websocket error");
        return Some(Err(TunnelError::WebSocketError(e)));
    }

    let msg = msg.unwrap();
    if msg.is_close() {
        tracing::warn!("recv close message from websocket");
        return None;
    }
    if msg.is_ping() || msg.is_pong() {
        return None;
    }

    if !msg.is_binary() {
        let msg = format!("{:?}", msg);
        tracing::error!(?msg, "Invalid packet");
        return Some(Err(TunnelError::InvalidPacket(msg)));
    }

    Some(Ok(ZCPacket::new_from_owned_bytes(
        msg.into_payload().into(),
        ZCPacketType::DummyTunnel,
    )))
}

static TRUSTED_PROXIES: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    [
        "127.0.0.0/8", // IPV4 Loopback
        "10.0.0.0/8",  // IPV4 Private Networks
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",  // IPV6 Loopback
        "fc00::/7", // IPV6 Private network
    ]
    .into_iter()
    .map(|s| s.parse().unwrap())
    .collect()
});

pub struct WsTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
    tls_acceptor: Option<TlsAcceptor>,
    lanes: tokio::sync::Mutex<super::tcp_lanes::LaneListener>,
}

impl std::fmt::Debug for WsTunnelListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsTunnelListener")
            .field("addr", &self.addr)
            .field("listener", &self.listener)
            .field("socket_mark", &self.socket_mark)
            .field("tls_enabled", &self.tls_acceptor.is_some())
            .finish()
    }
}

impl WsTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelListener {
            addr: normalize_ws_url(addr),
            listener: None,
            socket_mark: None,
            tls_acceptor: None,
            lanes: tokio::sync::Mutex::default(),
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub(crate) async fn accept_punched(stream: TcpStream) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "wss");
        let mut listener = Self::new(addr);
        listener.tls_acceptor = Some(TlsAcceptor::from(Arc::new(wss_server_config()?)));
        stream.set_nodelay(true)?;
        listener.try_accept(stream).await
    }

    async fn try_accept(&self, stream: TcpStream) -> Result<Box<dyn Tunnel>, TunnelError> {
        let peer_addr = stream.peer_addr()?;
        if is_wss(&self.addr)? {
            let acceptor = self.tls_acceptor.as_ref().ok_or_else(|| {
                TunnelError::InternalError("WSS listener has no TLS acceptor".to_string())
            })?;
            let stream = acceptor.accept(stream).await?;
            let binding = derive_wss_binding(|output| {
                stream
                    .get_ref()
                    .1
                    .export_keying_material(
                        output,
                        WSS_TRANSPORT_BINDING_LABEL,
                        Some(WSS_TRANSPORT_BINDING_CONTEXT),
                    )
                    .map(|_| ())
            })?;
            self.accept_stream(stream, Some(binding), peer_addr).await
        } else {
            self.accept_stream(stream, None, peer_addr).await
        }
    }

    async fn accept_stream<S>(
        &self,
        stream: S,
        transport_binding: Option<TransportBinding>,
        peer_addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Preserve the concrete writer's vectored-I/O capability. The pinned
        // tokio-util Either implementation falls back to scalar frame writes.
        let mut remote_addr =
            super::build_url_from_socket_addr(&peer_addr.to_string(), self.addr.scheme());
        let mut server = ServerBuilder::new()
            .limits(Limits::default().max_payload_len(Some(MAX_WS_MESSAGE_BYTES)));
        if ws_via_cdn(&self.addr) {
            server = server.add_header(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(cdn::SUBPROTOCOL),
            )?;
        }
        if super::tcp_lanes::requested(&self.addr)? > 1 {
            server = server
                .config(WebSocketConfig::default().flush_threshold(64 * 1024))
                .limits(
                    Limits::default().max_payload_len(Some(super::tcp_lanes::MAX_PENDING_BYTES)),
                );
        }
        let (request, stream) = server.max_headers(128).accept(stream).await?;
        if ws_via_cdn(&self.addr)
            && request
                .headers()
                .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|value| value.to_str().ok())
                != Some(cdn::SUBPROTOCOL)
        {
            return Err(TunnelError::InvalidProtocol(
                "CDN origin requires the inner TLS subprotocol".into(),
            ));
        }

        if TRUSTED_PROXIES
            .iter()
            .any(|net| net.contains(peer_addr.ip()))
            && let Some(forwarded) = request
                .headers()
                .get("Forwarded")
                .and_then(|f| f.to_str().ok())
                .and_then(|f| ForwardedHeaderValue::from_forwarded(f).ok())
                .or_else(|| {
                    request
                        .headers()
                        .get("X-Forwarded-For")
                        .and_then(|f| f.to_str().ok())
                        .and_then(|f| ForwardedHeaderValue::from_x_forwarded_for(f).ok())
                })
            && let Some(ip) = forwarded.remotest_forwarded_for_ip()
        {
            remote_addr
                .set_host(Some(&ip.to_string()))
                .map_err(|_| TunnelError::InvalidAddr(format!("invalid forwarded ip {}", ip)))?;
            remote_addr
                .query_pairs_mut()
                .append_pair("proxy", &peer_addr.to_string());
        }

        let remote_addr: crate::proto::common::Url = remote_addr.into();

        let info = TunnelInfo {
            tunnel_type: ws_peer_tunnel_type(&self.addr).to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(remote_addr.clone()),
            resolved_remote_addr: Some(remote_addr),
        };

        if ws_via_cdn(&self.addr) {
            return cdn::accept(stream, info).await;
        }
        let (write, read) = stream.split();

        Ok(Box::new(TunnelWrapper::new_with_transport_binding(
            read.filter_map(map_from_ws_message),
            write.with(sink_from_zc_packet),
            Some(info),
            transport_binding,
        )))
    }
}

#[async_trait::async_trait]
impl TunnelListener for WsTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        self.listener = None;
        self.tls_acceptor = None;
        super::tcp_lanes::requested(&self.addr)?;
        *self.lanes.get_mut() = Default::default();

        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let socket = bind::<TcpSocket>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        super::common::size_tcp_socket_buffers(&socket2::SockRef::from(&socket));
        let listener = socket.listen(1024)?;
        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        if is_wss(&self.addr)? {
            self.tls_acceptor = Some(TlsAcceptor::from(Arc::new(wss_server_config()?)));
        }
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let lane_count = super::tcp_lanes::requested(&self.addr)?;
        loop {
            self.lanes.get_mut().expire();
            let listener = self.listener.as_ref().unwrap();
            // Expire incomplete pairs even when no further connection arrives.
            let accepted = if lane_count > 1 {
                match timeout(super::tcp_lanes::JOIN_TIMEOUT, listener.accept()).await {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            } else {
                listener.accept().await
            };
            let (stream, _) = accepted?;
            stream.set_nodelay(true).unwrap();
            match timeout(Duration::from_secs(3), self.try_accept(stream)).await {
                Ok(Ok(tunnel)) => {
                    if lane_count == 1 {
                        return Ok(tunnel);
                    }
                    match self.lanes.get_mut().accept(tunnel, lane_count).await {
                        Ok(Some(tunnel)) => return Ok(tunnel),
                        Ok(None) => continue,
                        Err(error) => {
                            tracing::warn!(?error, "WebSocket lane join rejected");
                            continue;
                        }
                    }
                }
                e => {
                    tracing::error!(?e, ?self, "Failed to accept ws/wss tunnel");
                    continue;
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct WsTunnelConnector {
    addr: url::Url,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,

    bind_addrs: Vec<SocketAddr>,
    socket_mark: Option<u32>,
    underlay_policy: Arc<UnderlayPolicy>,
}

impl WsTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelConnector {
            addr,
            ip_version: IpVersion::Both,
            resolved_addr: None,

            bind_addrs: vec![],
            socket_mark: None,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }

    async fn connect_with(
        addr: url::Url,
        socket_addr: SocketAddr,
        tcp_socket: TcpSocket,
        underlay_policy: Arc<UnderlayPolicy>,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        super::common::size_tcp_socket_buffers(&socket2::SockRef::from(&tcp_socket));
        let stream = tcp_socket.connect(socket_addr).await?;
        Self::connect_punched(stream, addr, underlay_policy, None).await
    }

    pub(crate) async fn connect_punched(
        stream: TcpStream,
        addr: url::Url,
        underlay_policy: Arc<UnderlayPolicy>,
        net_ns: Option<crate::common::netns::NetNS>,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let is_wss = is_wss(&addr)?;
        let socket_addr = stream.peer_addr()?;
        {
            let _guard = net_ns.map(|namespace| namespace.guard());
            ensure_local_allowed(&underlay_policy, stream.local_addr()?)?;
        }
        ensure_remote_allowed(&underlay_policy, stream.peer_addr()?)?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay fail in ws connect");
        }

        let peer_type = ws_peer_tunnel_type(&addr);
        let info = TunnelInfo {
            tunnel_type: peer_type.to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), peer_type)
                    .into(),
            ),
            remote_addr: Some(addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&socket_addr.to_string(), peer_type).into(),
            ),
        };

        if is_wss {
            let via_cdn = ws_via_cdn(&addr);
            let name = addr.domain().unwrap_or("localhost");
            let stream =
                super::browser_tls::connect(stream, name, &[HTTP_1_1_ALPN], via_cdn).await?;
            let binding = if via_cdn {
                None
            } else {
                let mut bytes = [0; 32];
                stream
                    .get_ref()
                    .1
                    .export_keying_material(
                        &mut bytes,
                        WSS_TRANSPORT_BINDING_LABEL,
                        Some(WSS_TRANSPORT_BINDING_CONTEXT),
                    )
                    .map_err(|error| {
                        TunnelError::InternalError(format!("derive WSS transport binding: {error}"))
                    })?;
                Some(TransportBinding {
                    kind: TransportBindingKind::WssTlsExporterV1,
                    bytes,
                })
            };
            Self::connect_stream(&addr, stream, info, binding).await
        } else {
            Self::connect_stream(&addr, stream, info, None).await
        }
    }

    async fn connect_stream<S>(
        addr: &url::Url,
        stream: S,
        info: TunnelInfo,
        binding: Option<TransportBinding>,
    ) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (client, response) = browser_ws_client(addr)?.connect_on(stream).await?;
        if ws_via_cdn(addr) {
            if response
                .headers()
                .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|value| value.to_str().ok())
                != Some(cdn::SUBPROTOCOL)
            {
                return Err(TunnelError::InvalidProtocol(
                    "CDN origin did not select inner TLS".into(),
                ));
            }
            return timeout(Duration::from_secs(10), cdn::connect(client, info)).await?;
        }
        let (write, read) = client.split();
        Ok(Box::new(TunnelWrapper::new_with_transport_binding(
            read.filter_map(map_from_ws_message),
            write.with(sink_from_zc_packet),
            Some(info),
            binding,
        )))
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        crate::tunnel::common::apply_socket_mark(
            &socket2::SockRef::from(&socket),
            self.socket_mark,
        )?;
        Self::connect_with(
            self.addr.clone(),
            addr,
            socket,
            self.underlay_policy.clone(),
        )
        .await
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in bind_addrs {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(Self::connect_with(
                    self.addr.clone(),
                    addr,
                    socket,
                    self.underlay_policy.clone(),
                )),
                Err(error) => {
                    tracing::error!(?bind_addr, ?addr, ?error, "bind addr fail");
                    continue;
                }
            }
        }

        wait_for_connect_futures(futures).await
    }
}

#[async_trait::async_trait]
impl TunnelConnector for WsTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        ensure_remote_allowed(&self.underlay_policy, addr)?;
        let bind_addrs = eligible_bind_addrs(&self.underlay_policy, &self.bind_addrs, addr)?;
        let connect_lane = || async {
            if bind_addrs.is_empty() {
                self.connect_with_default_bind(addr).await
            } else {
                self.connect_with_custom_bind(addr, &bind_addrs).await
            }
        };
        {
            let count = super::tcp_lanes::requested(&self.addr)?;
            if count > 1 {
                return super::tcp_lanes::connect(count, connect_lane).await;
            }
        }
        connect_lane().await
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_underlay_policy(&mut self, policy: Arc<UnderlayPolicy>) {
        self.underlay_policy = policy;
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn server_frames_keep_vectored_writes() {
        use std::{
            pin::Pin,
            sync::atomic::{AtomicUsize, Ordering},
            task::{Context as TaskContext, Poll},
        };
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct CountWrites {
            inner: TcpStream,
            vectored: Arc<AtomicUsize>,
        }
        impl AsyncRead for CountWrites {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for CountWrites {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }
            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bufs: &[std::io::IoSlice<'_>],
            ) -> Poll<std::io::Result<usize>> {
                if bufs.len() > 1 {
                    self.vectored.fetch_add(1, Ordering::Relaxed);
                }
                Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
            }
            fn is_write_vectored(&self) -> bool {
                self.inner.is_write_vectored()
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client_io = TcpStream::connect(addr).await.unwrap();
            let (server_io, peer) = listener.accept().await.unwrap();
            let url: url::Url = format!("ws://{addr}/ws").parse().unwrap();
            let ws_listener = WsTunnelListener::new(url.clone());
            let vectored = Arc::new(AtomicUsize::new(0));
            let server_io = CountWrites {
                inner: server_io,
                vectored: vectored.clone(),
            };
            let client_builder = browser_ws_client(&url).unwrap();
            let (server, client) = tokio::join!(
                ws_listener.accept_stream(server_io, None, peer),
                client_builder.connect_on(client_io)
            );
            let server = server.unwrap();
            let (mut client, _) = client.unwrap();
            let (_read, mut write) = server.split();
            vectored.store(0, Ordering::Relaxed);
            let mut batch = crate::tunnel::batch::PacketBatch::new();
            for _ in 0..64 {
                batch
                    .try_push(ZCPacket::new_with_payload(&[7; 128]))
                    .unwrap();
            }
            let send = async {
                write.send(batch).await.unwrap();
            };
            let receive = async {
                for _ in 0..64 {
                    assert!(client.next().await.unwrap().unwrap().is_binary());
                }
            };
            tokio::join!(send, receive);
            assert!(
                vectored.load(Ordering::Relaxed) > 0,
                "WebSocket frame writes lost their vectored path"
            );
        })
        .await
        .unwrap();
    }

    #[test]
    fn websocket_connector_preserves_registered_urls() {
        for scheme in ["wss"] {
            for path in ["/", "/?via=cdn", "/ws", "/custom?n=1"] {
                let url: url::Url = format!("{scheme}://localhost:11010{path}").parse().unwrap();
                let connector = WsTunnelConnector::new(url.clone());
                assert_eq!(connector.remote_url(), url);
                let request = ws_http_url(&url);
                assert_eq!(
                    request.path(),
                    if url.path() == "/" { "/ws" } else { url.path() }
                );
            }
        }
    }

    #[tokio::test]
    async fn wss_looks_like_websocket_and_exports_a_tls_binding() {
        let mut listener = WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_addr = listener.local_url();
        assert_eq!(listener_addr.path(), "/ws");
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });

        let mut connector = WsTunnelConnector::new(listener_addr);
        let client = connector.connect().await.unwrap();
        let server = server.await.unwrap();

        assert_eq!(client.transport_binding(), server.transport_binding());
        assert_eq!(
            client.transport_binding().map(|binding| binding.kind),
            Some(TransportBindingKind::WssTlsExporterV1)
        );
    }

    #[test]
    fn cdn_websocket_urls_select_inner_tls() {
        let direct: url::Url = "wss://challenges.cloudflare.com/ws".parse().unwrap();
        let cdn: url::Url = "wss://challenges.cloudflare.com/ws?via=cdn"
            .parse()
            .unwrap();
        assert!(!ws_via_cdn(&direct));
        assert_eq!(ws_peer_tunnel_type(&direct), "wss");
        assert!(ws_via_cdn(&cdn));
        assert_eq!(ws_peer_tunnel_type(&cdn), "wss");
        assert!(ws_via_cdn(
            &"wss://challenges.cloudflare.com/ws?via=proxy"
                .parse()
                .unwrap()
        ));
        assert_eq!(
            ws_http_url(&cdn).as_str(),
            "wss://challenges.cloudflare.com/ws"
        );
        assert_eq!(
            ws_http_url(
                &"wss://challenges.cloudflare.com/ws?via=cdn&n=1"
                    .parse()
                    .unwrap()
            )
            .as_str(),
            "wss://challenges.cloudflare.com/ws?n=1"
        );
    }
    #[tokio::test]
    async fn websocket_rejects_oversized_frame_before_payload() {
        use tokio::io::AsyncWriteExt;
        timeout(Duration::from_secs(3), async {
            let mut listener = WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap());
            listener.listen().await.unwrap();
            let url = listener.local_url();
            let server = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, _) = tunnel.split();
                assert!(recv.next().await.unwrap().is_err());
            });
            let stream = TcpStream::connect(("127.0.0.1", url.port().unwrap()))
                .await
                .unwrap();
            let tls =
                super::super::browser_tls::connect(stream, "localhost", &[HTTP_1_1_ALPN], false)
                    .await
                    .unwrap();
            let (mut client, _) = browser_ws_client(&url)
                .unwrap()
                .connect_on(tls)
                .await
                .unwrap();
            let mut header = vec![0x82, 0xff];
            header.extend_from_slice(&((MAX_WS_MESSAGE_BYTES + 1) as u64).to_be_bytes());
            header.extend_from_slice(&[0; 4]);
            client.get_mut().write_all(&header).await.unwrap();
            client.get_mut().flush().await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cdn_inner_tls_binds_peers_and_carries_packets() {
        use crate::tunnel::batch::PacketBatch;
        timeout(Duration::from_secs(5), async {
            let mut listener =
                WsTunnelListener::new("ws://127.0.0.1:0/ws?via=cdn".parse().unwrap());
            listener.listen().await.unwrap();
            let url = listener.local_url();
            let server = tokio::spawn(async move { listener.accept().await.unwrap() });
            let client = WsTunnelConnector::new(url).connect().await.unwrap();
            let server = server.await.unwrap();
            assert_eq!(client.transport_binding(), server.transport_binding());
            assert_eq!(
                client.transport_binding().unwrap().kind,
                TransportBindingKind::WssTlsExporterV1
            );
            assert_eq!(client.info().unwrap().tunnel_type, "wss");
            let (mut recv, _) = server.split();
            let (_, mut send) = client.split();
            let packet = ZCPacket::new_with_payload(&[0x73; 2000]);
            send.send(PacketBatch::singleton(packet)).await.unwrap();
            assert_eq!(
                recv.next()
                    .await
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap()
                    .payload(),
                &[0x73; 2000]
            );
            let mut ordinary = WsTunnelListener::new("ws://127.0.0.1:0/ws".parse().unwrap());
            ordinary.listen().await.unwrap();
            let mut url = ordinary.local_url();
            url.set_query(Some("via=cdn"));
            let ordinary_server = tokio::spawn(async move { ordinary.accept().await });
            let result = WsTunnelConnector::new(url).connect().await;
            assert!(result.is_err(), "CDN mode accepted an unbound WebSocket");
            let _ = ordinary_server.await.unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn owned_websocket_receive_reuses_payload_and_preserves_control_handling() {
        let bytes = bytes::Bytes::from(vec![0x42; 64]);
        let pointer = bytes.as_ptr();
        let packet = map_from_ws_message(Ok(Message::binary(bytes)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.tunnel_payload().as_ptr(), pointer);
        assert_eq!(packet.tunnel_payload(), &[0x42; 64]);
        assert!(
            map_from_ws_message(Ok(Message::text("invalid")))
                .await
                .unwrap()
                .is_err()
        );
    }
}
