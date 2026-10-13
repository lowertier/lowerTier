//! HTTP/2 over TLS for the TCP underlay.
//!
//! The socket still looks like HTTPS: TLS ALPN `h2` then `http/1.1`, then one
//! extended CONNECT stream at the same MASQUE CONNECT-IP path as QUIC. Overlay
//! frames ride in HTTP/2 DATA. Direct hops use the TLS exporter and skip inner
//! session AEAD.
//!
//! With `quic_decoy_upstream` and without `quic_sni_passthrough`, marked
//! clients send a tiny TLS handshake record (record length = routing CID)
//! before the real ClientHello. Shallow DPI sees `16 03 01`. A browser
//! ClientHello is hundreds of bytes and is spliced to the decoy. Nginx must
//! then be a dumb stream proxy: `ssl_preread` would parse the tiny record.
//!
//! With `quic_sni_passthrough`, the first bytes are a normal ClientHello, so
//! Nginx `ssl_preread` can split the VPN hostname from other sites. LowTier
//! does not splice TCP in that mode.

use super::{
    TransportBinding, TransportBindingKind, Tunnel, TunnelError, TunnelInfo,
    common::{FramedWriter, TunnelWrapper},
    packet_def::{
        PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType,
        bounded_owned_buffer,
    },
    stealth_tls::{
        self, ConnectIpAdmission, QUIC_ROUTING_CID_BYTES, routing_cid_bytes,
        valid_routing_cid_bytes,
    },
};
use crate::common::config::Flags;
use bytes::{Buf, Bytes, BytesMut};
use futures::Stream;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, ready},
};
#[cfg(test)]
use tokio::io::{AsyncRead, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::AbortOnDropHandle;

const HTTP2_ALPN: &[u8] = b"h2";
const HTTP11_ALPN: &[u8] = b"http/1.1";
const TCP_ROUTING_RECORD_LEN: usize = 5 + QUIC_ROUTING_CID_BYTES;
const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
const HTTP2_TRANSPORT_BINDING_LABEL: &[u8] = b"EXPORTER-LowTier-Http2-PeerConn-v1";
const HTTP2_TRANSPORT_BINDING_CONTEXT: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256|peerconn-v3|h2";
// 8 ms * 650 Mbit is 0.65 MiB. Unique from_owner slabs in a 16 MiB
// window blow the 20 MiB process RSS cap. 2 MiB is still 3x that BDP.
const HTTP2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const HTTP2_CONN_WINDOW: u32 = 4 * 1024 * 1024;
const HTTP2_MAX_FRAME: u32 = 256 * 1024;
// h2 flushes TLS after every DATA frame. Match the TLS record / SETTINGS
// default so each flush carries a full record instead of one overlay packet.
const HTTP2_COALESCE_BYTES: usize = 16 * 1024;
const TCP_MTU_BYTES: usize = 2000;

fn window_sizes() -> (u32, u32) {
    // WINDOW_UPDATE is batched; leave credit for data sent during its round trip.
    let scale = if cfg!(target_os = "linux")
        && std::env::var_os("LOWTIER_ENABLE_TCP_LARGE_BUFFERS").is_some()
    {
        4
    } else {
        1
    };
    (HTTP2_STREAM_WINDOW * scale, HTTP2_CONN_WINDOW * scale)
}

pub fn tls_acceptor(flags: &Flags) -> Result<TlsAcceptor, TunnelError> {
    let config = stealth_tls::rustls_server_config(flags, &[HTTP2_ALPN])?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn decoy_upstream(flags: &Flags) -> Option<std::net::SocketAddr> {
    let upstream = flags.quic_decoy_upstream.as_str();
    if upstream.is_empty() {
        return None;
    }
    upstream.parse().ok().or_else(|| {
        std::net::ToSocketAddrs::to_socket_addrs(&upstream)
            .ok()
            .and_then(|mut addrs| addrs.next())
    })
}

fn routing_secret(flags: &Flags) -> Option<Vec<u8>> {
    if flags.quic_admission_secret.len() >= 16 {
        Some(flags.quic_admission_secret.as_bytes().to_vec())
    } else {
        None
    }
}

fn tcp_routing_prefix(flags: &Flags) -> bool {
    decoy_upstream(flags).is_some() && !flags.quic_sni_passthrough
}

fn tcp_routing_record(cid: &[u8; QUIC_ROUTING_CID_BYTES]) -> [u8; TCP_ROUTING_RECORD_LEN] {
    let mut record = [0_u8; TCP_ROUTING_RECORD_LEN];
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x01;
    record[3] = 0x00;
    record[4] = QUIC_ROUTING_CID_BYTES as u8;
    record[5..].copy_from_slice(cid);
    record
}

fn is_tcp_routing_record(header: &[u8; 5]) -> bool {
    header[0] == 0x16
        && header[1] == 0x03
        && header[2] == 0x01
        && u16::from_be_bytes([header[3], header[4]]) as usize == QUIC_ROUTING_CID_BYTES
}

fn spawn_passthrough_tcp(client: TcpStream, prefix: Vec<u8>, upstream: std::net::SocketAddr) {
    let Ok(peer) = client.peer_addr() else {
        return;
    };
    // Acquire before spawning or dialing. All listeners and both protocols share
    // the same process and source-IP budgets; authenticated tunnels bypass this.
    let Some(permit) = super::decoy::process_limiter().admit(peer.ip()) else {
        return;
    };
    tokio::spawn(async move {
        let result = tokio::time::timeout(
            super::decoy::FLOW_LIFETIME,
            passthrough_tcp(client, &prefix, upstream, &permit),
        )
        .await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::debug!(?result, "HTTP/2 decoy passthrough closed");
        }
    });
}

async fn passthrough_tcp(
    mut client: TcpStream,
    prefix: &[u8],
    upstream: std::net::SocketAddr,
    permit: &super::decoy::DecoyPermit,
) -> Result<(), TunnelError> {
    let mut upstream =
        tokio::time::timeout(super::decoy::CONNECT_TIMEOUT, TcpStream::connect(upstream)).await??;
    if let Err(error) = upstream.set_nodelay(true) {
        tracing::warn!(?error, "set_nodelay fail on HTTP/2 decoy upstream");
    }
    permit.wait(prefix.len()).await;
    tokio::time::timeout(super::decoy::IDLE_TIMEOUT, upstream.write_all(prefix)).await??;
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let activity = tokio::sync::Notify::new();
    let relay = async {
        tokio::try_join!(
            super::decoy::copy_tcp(client_read, upstream_write, permit, &activity),
            super::decoy::copy_tcp(upstream_read, client_write, permit, &activity),
        )
    };
    tokio::select! {
        result = relay => { result?; }
        _ = super::decoy::tcp_idle(&activity, super::decoy::IDLE_TIMEOUT) => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "decoy TCP idle timeout").into());
        }
    }
    Ok(())
}

fn derive_http2_binding(
    export: impl FnOnce(&mut [u8]) -> Result<(), rustls::Error>,
) -> Result<TransportBinding, TunnelError> {
    let mut bytes = [0_u8; 32];
    export(&mut bytes).map_err(|error| {
        TunnelError::InternalError(format!("derive HTTP/2 transport binding: {error:?}"))
    })?;
    Ok(TransportBinding {
        kind: TransportBindingKind::Http2TlsExporterV1,
        bytes,
    })
}

fn http2_authority(url: &url::Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        _ => "localhost".to_string(),
    }
}

fn connect_ip_request(url: &url::Url, bearer: Option<&str>) -> Result<Request<()>, TunnelError> {
    let uri = format!("https://{}{CONNECT_IP_PATH}", http2_authority(url));
    let mut builder = Request::builder().method(Method::CONNECT).uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header("proxy-authorization", format!("Bearer {bearer}"));
    }
    let mut request = builder
        .body(())
        .map_err(|error| TunnelError::InternalError(format!("build HTTP/2 CONNECT: {error}")))?;
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-ip"));
    Ok(request)
}

// AsyncRead reference adapter retained only for its original regression tests.
#[cfg(test)]
struct H2Reader {
    recv: RecvStream,
    buf: Bytes,
}

#[cfg(test)]
impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(dst.remaining());
                dst.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    if !data.is_empty() {
                        let _ = self.recv.flow_control().release_capacity(data.len());
                    }
                    self.buf = data;
                }
                Some(Err(error)) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// Own one DATA slab plus at most one incomplete LowTier frame. Complete
/// frames split disjoint mutable views directly, without an intermediate read.
#[derive(Default)]
struct H2FrameDecoder {
    chunk: BytesMut,
    partial: BytesMut,
}

impl H2FrameDecoder {
    fn load(&mut self, data: Bytes) {
        debug_assert!(self.chunk.is_empty());
        self.chunk = bounded_owned_buffer(data);
    }

    fn frame_len(header: &[u8]) -> Result<usize, TunnelError> {
        let body =
            u32::from_le_bytes(header[..TCP_TUNNEL_HEADER_SIZE].try_into().unwrap()) as usize;
        if !(PEER_MANAGER_HEADER_SIZE..=TCP_MTU_BYTES).contains(&body) {
            return Err(TunnelError::InvalidPacket(
                "invalid HTTP/2 tunnel frame length".into(),
            ));
        }
        body.checked_add(TCP_TUNNEL_HEADER_SIZE)
            .ok_or_else(|| TunnelError::InvalidPacket("HTTP/2 frame length overflow".into()))
    }

    fn decode(&mut self) -> Result<Option<ZCPacket>, TunnelError> {
        if self.partial.is_empty() && self.chunk.len() >= TCP_TUNNEL_HEADER_SIZE {
            let length = Self::frame_len(&self.chunk)?;
            if self.chunk.len() >= length {
                let packet = self.chunk.split_to(length);
                if self.chunk.is_empty() {
                    self.chunk = BytesMut::new();
                }
                return Ok(Some(ZCPacket::new_from_buf(packet, ZCPacketType::TCP)));
            }
        }
        if self.partial.len() < TCP_TUNNEL_HEADER_SIZE {
            let take = (TCP_TUNNEL_HEADER_SIZE - self.partial.len()).min(self.chunk.len());
            self.partial.extend_from_slice(&self.chunk[..take]);
            self.chunk.advance(take);
            if self.partial.len() < TCP_TUNNEL_HEADER_SIZE {
                return Ok(None);
            }
        }
        let length = Self::frame_len(&self.partial)?;
        let take = (length - self.partial.len()).min(self.chunk.len());
        // Allocation remains bounded by one validated frame even when the peer
        // sends a partial header followed by a huge advertised length.
        self.partial.reserve(length - self.partial.len());
        self.partial.extend_from_slice(&self.chunk[..take]);
        self.chunk.advance(take);
        if self.partial.len() == length {
            return Ok(Some(ZCPacket::new_from_buf(
                std::mem::take(&mut self.partial),
                ZCPacketType::TCP,
            )));
        }
        Ok(None)
    }

    fn finish(&self) -> Result<(), TunnelError> {
        if self.partial.is_empty() && self.chunk.is_empty() {
            Ok(())
        } else {
            Err(TunnelError::InvalidPacket(
                "truncated HTTP/2 tunnel frame".into(),
            ))
        }
    }
}

struct H2PacketReader {
    recv: RecvStream,
    decoder: H2FrameDecoder,
    // Return consumed credit at DATA boundaries, avoiding one flow-control
    // lock/wakeup operation for every small inner packet in a coalesced slab.
    pending_release: usize,
    ended: bool,
}

impl H2PacketReader {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            decoder: H2FrameDecoder::default(),
            pending_release: 0,
            ended: false,
        }
    }
}

impl Stream for H2PacketReader {
    type Item = Result<ZCPacket, TunnelError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        // Bound ready empty DATA frames so a peer cannot monopolize a worker.
        for _ in 0..super::batch::MAX_PACKET_BATCH_SIZE {
            let before = this.decoder.chunk.len();
            let packet = this.decoder.decode();
            let consumed = before - this.decoder.chunk.len();
            this.pending_release += consumed;
            if this.pending_release != 0 && (this.decoder.chunk.is_empty() || packet.is_err()) {
                let consumed = std::mem::take(&mut this.pending_release);
                if let Err(error) = this.recv.flow_control().release_capacity(consumed) {
                    this.ended = true;
                    return Poll::Ready(Some(Err(TunnelError::IOError(io::Error::other(error)))));
                }
            }
            match packet {
                Ok(Some(packet)) => return Poll::Ready(Some(Ok(packet))),
                Err(error) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Ok(None) => {}
            }
            match ready!(this.recv.poll_data(cx)) {
                Some(Ok(data)) => this.decoder.load(data),
                Some(Err(error)) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(TunnelError::IOError(io::Error::other(error)))));
                }
                None => {
                    this.ended = true;
                    return Poll::Ready(this.decoder.finish().err().map(Err));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

struct H2Writer {
    send: SendStream<Bytes>,
    pending: BytesMut,
    coalesce_bytes: usize,
}

impl H2Writer {
    fn new(send: SendStream<Bytes>) -> Self {
        let coalesce_bytes = if cfg!(target_os = "linux")
            && std::env::var_os("LOWTIER_ENABLE_TCP_LARGE_BUFFERS").is_some()
        {
            64 * 1024
        } else {
            HTTP2_COALESCE_BYTES
        };
        Self {
            send,
            pending: BytesMut::with_capacity(coalesce_bytes),
            coalesce_bytes,
        }
    }

    fn poll_send_one_frame(
        &mut self,
        cx: &mut TaskContext<'_>,
        end_stream: bool,
    ) -> Poll<io::Result<()>> {
        if self.pending.is_empty() {
            if end_stream {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(io::Error::other)?;
            }
            return Poll::Ready(Ok(()));
        }

        let want = self.pending.len().min(self.coalesce_bytes);
        self.send.reserve_capacity(want);
        match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(0)) => Poll::Pending,
            Some(Ok(capacity)) => {
                let take = capacity.min(want);
                if take == 0 {
                    return Poll::Pending;
                }
                let data = self.pending.split_to(take).freeze();
                let end = end_stream && self.pending.is_empty();
                self.send.send_data(data, end).map_err(io::Error::other)?;
                Poll::Ready(Ok(()))
            }
            Some(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 send stream closed",
            ))),
        }
    }

    fn poll_make_space(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.pending.len() >= self.coalesce_bytes {
            ready!(self.poll_send_one_frame(cx, false))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_make_space(cx))?;
        let space = self.coalesce_bytes.saturating_sub(self.pending.len());
        let n = buf.len().min(space.max(1));
        self.pending.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_make_space(cx))?;
        let space = self
            .coalesce_bytes
            .saturating_sub(self.pending.len())
            .max(1);
        let mut copied = 0;
        for buf in bufs {
            if copied == space {
                break;
            }
            let n = buf.len().min(space - copied);
            self.pending.extend_from_slice(&buf[..n]);
            copied += n;
            if n < buf.len() {
                break;
            }
        }
        Poll::Ready(Ok(copied))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            ready!(self.poll_send_one_frame(cx, false))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(self.poll_send_one_frame(cx, true))?;
        Poll::Ready(Ok(()))
    }
}

fn wrap_http2_tunnel(
    recv: RecvStream,
    send: SendStream<Bytes>,
    info: TunnelInfo,
    binding: TransportBinding,
    driver: AbortOnDropHandle<()>,
) -> Box<dyn Tunnel> {
    let mut tunnel = TunnelWrapper::new_with_transport_binding(
        H2PacketReader::new(recv),
        FramedWriter::new(H2Writer::new(send)),
        Some(info),
        Some(binding),
    );
    tunnel.set_associate_data(Box::new(driver));
    Box::new(tunnel)
}

pub async fn accept(
    stream: TcpStream,
    acceptor: &TlsAcceptor,
    local_url: url::Url,
    flags: &Flags,
) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
    // One deadline covers routing inspection, TLS, and CONNECT admission.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        accept_inner(stream, acceptor, local_url, flags),
    )
    .await
    .map_err(|_| TunnelError::InternalError("HTTP/2 admission timed out".into()))?
}

async fn accept_inner(
    mut stream: TcpStream,
    acceptor: &TlsAcceptor,
    local_url: url::Url,
    flags: &Flags,
) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
    if let Err(error) = stream.set_nodelay(true) {
        tracing::warn!(?error, "set_nodelay fail in HTTP/2 accept");
    }
    let peer_addr = stream.peer_addr()?;
    if let Some(upstream) = decoy_upstream(flags).filter(|_| tcp_routing_prefix(flags)) {
        let secret = routing_secret(flags).ok_or_else(|| {
            TunnelError::InternalError(
                "HTTP/2 decoy passthrough requires quic_admission_secret".to_owned(),
            )
        })?;
        let mut header = [0_u8; 5];
        tokio::time::timeout(
            super::decoy::CONNECT_TIMEOUT,
            stream.read_exact(&mut header),
        )
        .await??;
        if is_tcp_routing_record(&header) {
            let mut marker = [0_u8; QUIC_ROUTING_CID_BYTES];
            tokio::time::timeout(
                super::decoy::CONNECT_TIMEOUT,
                stream.read_exact(&mut marker),
            )
            .await??;
            if !valid_routing_cid_bytes(&marker, &secret, std::time::SystemTime::now()) {
                let mut prefix = [0_u8; TCP_ROUTING_RECORD_LEN];
                prefix[..5].copy_from_slice(&header);
                prefix[5..].copy_from_slice(&marker);
                spawn_passthrough_tcp(stream, prefix.to_vec(), upstream);
                return Ok(None);
            }
        } else {
            spawn_passthrough_tcp(stream, header.to_vec(), upstream);
            return Ok(None);
        }
    }
    let tls = acceptor.accept(stream).await?;
    let binding = derive_http2_binding(|output| {
        tls.get_ref()
            .1
            .export_keying_material(
                output,
                HTTP2_TRANSPORT_BINDING_LABEL,
                Some(HTTP2_TRANSPORT_BINDING_CONTEXT),
            )
            .map(|_| ())
    })?;

    let (stream_window, conn_window) = window_sizes();
    let mut server = h2::server::Builder::new();
    server
        .enable_connect_protocol()
        .initial_window_size(stream_window)
        .initial_connection_window_size(conn_window)
        .max_frame_size(HTTP2_MAX_FRAME);
    let mut conn = server
        .handshake(tls)
        .await
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 server handshake: {error}")))?;

    let (request, mut respond) = conn
        .accept()
        .await
        .ok_or_else(|| TunnelError::InternalError("HTTP/2 connection closed".to_owned()))?
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 accept: {error}")))?;

    let is_connect_ip = request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<h2::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str() == "connect-ip")
        && request.uri().path() == CONNECT_IP_PATH;
    let admission = ConnectIpAdmission::from_flags(flags);
    let authorized = match &admission {
        Some(admission) => request
            .headers()
            .get("proxy-authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| admission.verify_header(value)),
        None => true,
    };
    if !is_connect_ip || !authorized {
        let _ = respond.send_response(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap(),
            true,
        );
        return Err(TunnelError::InvalidProtocol(
            "HTTP/2 request was not CONNECT-IP".to_owned(),
        ));
    }

    let recv = request.into_body();
    let send = respond
        .send_response(
            Response::builder().status(StatusCode::OK).body(()).unwrap(),
            false,
        )
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 response: {error}")))?;

    let driver = AbortOnDropHandle::new(tokio::spawn(async move {
        while let Some(result) = conn.accept().await {
            if let Ok((_, mut respond)) = result {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
            }
        }
    }));

    let remote = super::build_url_from_socket_addr(&peer_addr.to_string(), "tcp");
    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote.clone().into()),
        resolved_remote_addr: Some(remote.into()),
    };
    Ok(Some(wrap_http2_tunnel(recv, send, info, binding, driver)))
}

pub async fn connect(
    mut stream: TcpStream,
    url: url::Url,
    flags: &Flags,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    if let Err(error) = stream.set_nodelay(true) {
        tracing::warn!(?error, "set_nodelay fail in HTTP/2 connect");
    }
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr()?;
    if let Some(secret) = routing_secret(flags).filter(|_| tcp_routing_prefix(flags)) {
        let marker = routing_cid_bytes(&secret, std::time::SystemTime::now());
        stream.write_all(&tcp_routing_record(&marker)).await?;
    }
    let server_name = stealth_tls::client_server_name(flags, &url)?;
    let tls = super::browser_tls::connect(
        stream,
        &server_name.to_str(),
        &[HTTP2_ALPN, HTTP11_ALPN],
        !stealth_tls::skip_server_verification(flags),
    )
    .await?;
    if tls.get_ref().1.alpn_protocol() != Some(HTTP2_ALPN) {
        return Err(TunnelError::InvalidProtocol(
            "HTTP/2 ALPN was not negotiated".into(),
        ));
    }
    let mut bytes = [0; 32];
    tls.get_ref()
        .1
        .export_keying_material(
            &mut bytes,
            HTTP2_TRANSPORT_BINDING_LABEL,
            Some(HTTP2_TRANSPORT_BINDING_CONTEXT),
        )
        .map_err(|error| {
            TunnelError::InternalError(format!("derive HTTP/2 transport binding: {error}"))
        })?;
    let binding = TransportBinding {
        kind: TransportBindingKind::Http2TlsExporterV1,
        bytes,
    };

    let (stream_window, conn_window) = window_sizes();
    let mut client = h2::client::Builder::new();
    client
        .initial_window_size(stream_window)
        .initial_connection_window_size(conn_window)
        .max_frame_size(HTTP2_MAX_FRAME);
    let (h2, conn) = client
        .handshake(tls)
        .await
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 client handshake: {error}")))?;
    let driver = AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = conn.await;
    }));

    let mut h2 = h2;
    std::future::poll_fn(|cx| h2.poll_ready(cx))
        .await
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 client ready: {error}")))?;
    let bearer = ConnectIpAdmission::from_flags(flags).map(|admission| admission.current_token());
    let request = connect_ip_request(&url, bearer.as_deref())?;
    let (response, send) = h2
        .send_request(request, false)
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 CONNECT: {error}")))?;
    let response = response
        .await
        .map_err(|error| TunnelError::InternalError(format!("HTTP/2 CONNECT response: {error}")))?;
    if !response.status().is_success() {
        return Err(TunnelError::InternalError(format!(
            "HTTP/2 CONNECT returned {}",
            response.status()
        )));
    }
    let recv = response.into_body();

    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(super::build_url_from_socket_addr(&local_addr.to_string(), "tcp").into()),
        remote_addr: Some(url.into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(&peer_addr.to_string(), "tcp").into(),
        ),
    };
    Ok(wrap_http2_tunnel(recv, send, info, binding, driver))
}

#[cfg(test)]
mod tests {
    use super::tcp_routing_prefix;
    use crate::common::config::gen_default_flags;

    async fn stream_pair() -> (
        super::H2Reader,
        h2::SendStream<bytes::Bytes>,
        tokio_util::task::AbortOnDropHandle<()>,
        tokio_util::task::AbortOnDropHandle<()>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            sender.send(send).unwrap();
            while connection.accept().await.is_some() {}
        }));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = http::Request::builder()
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let reader = super::H2Reader {
            recv: response.await.unwrap().into_body(),
            buf: bytes::Bytes::new(),
        };
        (reader, receiver.await.unwrap(), server, driver)
    }

    #[tokio::test]
    async fn empty_read_completes_on_an_idle_h2_stream() {
        use tokio::io::AsyncRead;
        let (mut reader, _send, _server, _driver) = stream_pair().await;
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let mut empty = tokio::io::ReadBuf::new(&mut []);
        assert!(matches!(
            std::pin::Pin::new(&mut reader).poll_read(&mut cx, &mut empty),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(reader.buf.is_empty());
    }

    #[tokio::test]
    async fn partial_h2_reads_preserve_the_unread_suffix_and_eof() {
        use tokio::io::AsyncReadExt;
        let (mut reader, mut send, _server, _driver) = stream_pair().await;
        send.send_data(bytes::Bytes::from_static(b"abcdef"), true)
            .unwrap();
        let mut prefix = [0; 2];
        reader.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"ab");
        assert_eq!(reader.buf.as_ref(), b"cdef");
        let pointer = reader.buf.as_ptr();
        reader.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"cd");
        assert_eq!(reader.buf.as_ptr(), pointer.wrapping_add(2));
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).await.unwrap();
        assert_eq!(&suffix, b"ef");
    }

    #[tokio::test]
    async fn empty_vectored_write_keeps_buffered_h2_data() {
        use tokio::io::AsyncWrite;
        let (_reader, send, _server, _driver) = stream_pair().await;
        let mut writer = super::H2Writer::new(send);
        writer.pending.resize(writer.coalesce_bytes, 0x5a);
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let empty = [std::io::IoSlice::new(&[])];
        assert!(matches!(
            std::pin::Pin::new(&mut writer).poll_write_vectored(&mut cx, &empty),
            std::task::Poll::Ready(Ok(0))
        ));
        assert_eq!(writer.pending.len(), writer.coalesce_bytes);
    }

    #[test]
    fn routing_prefix_is_off_behind_sni_passthrough() {
        let mut flags = gen_default_flags();
        flags.quic_decoy_upstream = "127.0.0.1:443".to_owned();
        flags.quic_admission_secret = "routing-test-secret-material".to_owned();
        assert!(tcp_routing_prefix(&flags));
        flags.quic_sni_passthrough = true;
        assert!(!tcp_routing_prefix(&flags));
    }

    #[test]
    fn routing_record_looks_like_a_tls_handshake_and_not_a_browser_clienthello() {
        use super::{
            QUIC_ROUTING_CID_BYTES, is_tcp_routing_record, routing_cid_bytes, tcp_routing_record,
        };
        use std::time::SystemTime;

        let cid = routing_cid_bytes(b"routing-test-secret-material", SystemTime::now());
        let record = tcp_routing_record(&cid);
        assert_eq!(&record[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(
            u16::from_be_bytes([record[3], record[4]]) as usize,
            QUIC_ROUTING_CID_BYTES
        );
        assert!(is_tcp_routing_record(record[..5].try_into().unwrap()));
        // Live challenges.cloudflare.com ClientHello is ~1500 bytes (0x06xx),
        // never a 8-byte handshake record.
        assert!(!is_tcp_routing_record(&[0x16, 0x03, 0x01, 0x06, 0x07]));
    }
    fn framed(body: usize, value: u8) -> bytes::Bytes {
        let mut bytes = Vec::with_capacity(body + 4);
        bytes.extend_from_slice(&(body as u32).to_le_bytes());
        bytes.resize(body + 4, value);
        bytes.into()
    }

    #[test]
    fn owned_h2_decoder_handles_every_split_and_coalesced_frame() {
        use super::*;
        let data = framed(96, 0x42);
        for split in 0..=data.len() {
            let mut decoder = H2FrameDecoder::default();
            decoder.load(data.slice(..split));
            let mut packets = Vec::new();
            while let Some(p) = decoder.decode().unwrap() {
                packets.push(p);
            }
            decoder.load(data.slice(split..));
            while let Some(p) = decoder.decode().unwrap() {
                packets.push(p);
            }
            assert_eq!(packets.len(), 1, "split={split}");
            assert_eq!(packets[0].tunnel_payload(), &[0x42; 96]);
            decoder.finish().unwrap();
        }
        let mut coalesced = Vec::new();
        for n in 0..64 {
            coalesced.extend_from_slice(&framed(96, n));
        }
        let coalesced = coalesced.into_boxed_slice().into_vec();
        let pointer = coalesced.as_ptr();
        let mut decoder = H2FrameDecoder::default();
        decoder.load(coalesced.into());
        let mut packets = Vec::new();
        for n in 0..64 {
            let p = decoder.decode().unwrap().unwrap();
            assert_eq!(p.tunnel_payload(), &[n as u8; 96]);
            assert_eq!(
                p.tunnel_payload().as_ptr(),
                pointer.wrapping_add(n * 100 + 4)
            );
            packets.push(p);
        }
        assert!(decoder.decode().unwrap().is_none());
        decoder.finish().unwrap();
    }

    #[test]
    fn owned_h2_decoder_rejects_bad_lengths_before_reserving_and_truncated_eof() {
        use super::*;
        for length in [0_u32, 15, 2001, u32::MAX] {
            let mut decoder = H2FrameDecoder::default();
            decoder.load(Bytes::copy_from_slice(&length.to_le_bytes()));
            assert!(decoder.decode().is_err());
            assert!(decoder.partial.capacity() <= 8);
        }
        for bytes in [Bytes::from_static(&[1, 2]), framed(96, 3).slice(..50)] {
            let mut decoder = H2FrameDecoder::default();
            decoder.load(bytes);
            assert!(decoder.decode().unwrap().is_none());
            assert!(decoder.finish().is_err());
        }
        for length in [PEER_MANAGER_HEADER_SIZE, TCP_MTU_BYTES] {
            let mut decoder = H2FrameDecoder::default();
            decoder.load(framed(length, 7));
            assert_eq!(
                decoder.decode().unwrap().unwrap().tunnel_payload().len(),
                length
            );
            decoder.finish().unwrap();
        }
    }

    #[tokio::test]
    async fn owned_h2_reader_delivers_split_data_and_returns_exact_credit() {
        use futures::StreamExt;
        let (reader, mut send, _server, _driver) = stream_pair().await;
        let mut reader = super::H2PacketReader::new(reader.recv);
        let mut data = Vec::new();
        for n in 0..32 {
            data.extend_from_slice(&framed(96, n));
        }
        let data = bytes::Bytes::from(data);
        send.send_data(data.slice(..2), false).unwrap();
        send.send_data(data.slice(2..199), false).unwrap();
        send.send_data(data.slice(199..), true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for n in 0..32 {
                let p = reader.next().await.unwrap().unwrap();
                assert_eq!(p.tunnel_payload(), &[n as u8; 96]);
            }
            assert!(reader.next().await.is_none());
            assert!(reader.next().await.is_none());
            assert_eq!(reader.recv.flow_control().used_capacity(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn owned_h2_reader_returns_coalesced_credit_at_the_data_boundary() {
        use futures::StreamExt;
        let (reader, mut send, _server, _driver) = stream_pair().await;
        let mut reader = super::H2PacketReader::new(reader.recv);
        let mut data = Vec::new();
        data.extend_from_slice(&framed(96, 1));
        data.extend_from_slice(&framed(96, 2));
        send.send_data(data.into(), true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let first = reader.next().await.unwrap().unwrap();
            assert_eq!(first.tunnel_payload(), &[1; 96]);
            assert_eq!(reader.pending_release, 100);
            assert_eq!(reader.recv.flow_control().used_capacity(), 200);
            let second = reader.next().await.unwrap().unwrap();
            assert_eq!(second.tunnel_payload(), &[2; 96]);
            assert_eq!(reader.pending_release, 0);
            assert_eq!(reader.recv.flow_control().used_capacity(), 0);
            assert!(reader.next().await.is_none());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn owned_h2_reader_reports_truncated_frame_once() {
        use futures::StreamExt;
        let (reader, mut send, _server, _driver) = stream_pair().await;
        let mut reader = super::H2PacketReader::new(reader.recv);
        send.send_data(framed(96, 1).slice(..50), true).unwrap();
        assert!(reader.next().await.unwrap().is_err());
        assert!(reader.next().await.is_none());
    }
}
