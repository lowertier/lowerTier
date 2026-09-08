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
    common::{FramedReader, FramedWriter, TunnelWrapper},
    stealth_tls::{self, ConnectIpAdmission, QUIC_ROUTING_CID_BYTES, routing_cid_bytes, valid_routing_cid_bytes},
};
use crate::common::config::Flags;
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::AbortOnDropHandle;

const HTTP2_ALPN: &[u8] = b"h2";
const HTTP11_ALPN: &[u8] = b"http/1.1";
const TCP_ROUTING_RECORD_LEN: usize = 5 + QUIC_ROUTING_CID_BYTES;
const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
const HTTP2_TRANSPORT_BINDING_LABEL: &[u8] = b"EXPORTER-LowTier-Http2-PeerConn-v1";
const HTTP2_TRANSPORT_BINDING_CONTEXT: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256|peerconn-v3|h2";
const HTTP2_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
const HTTP2_CONN_WINDOW: u32 = 32 * 1024 * 1024;
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

async fn passthrough_tcp(
    mut client: TcpStream,
    prefix: &[u8],
    upstream: std::net::SocketAddr,
) -> Result<(), TunnelError> {
    let mut upstream = TcpStream::connect(upstream).await?;
    if let Err(error) = upstream.set_nodelay(true) {
        tracing::warn!(?error, "set_nodelay fail on HTTP/2 decoy upstream");
    }
    upstream.write_all(prefix).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
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

struct H2Reader {
    recv: RecvStream,
    buf: Bytes,
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(dst.remaining());
                dst.put_slice(&self.buf[..n]);
                self.buf = self.buf.slice(n..);
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
        FramedReader::new(
            H2Reader {
                recv,
                buf: Bytes::new(),
            },
            TCP_MTU_BYTES,
        ),
        FramedWriter::new(H2Writer::new(send)),
        Some(info),
        Some(binding),
    );
    tunnel.set_associate_data(Box::new(driver));
    Box::new(tunnel)
}

pub async fn accept(
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
        stream.read_exact(&mut header).await?;
        if is_tcp_routing_record(&header) {
            let mut marker = [0_u8; QUIC_ROUTING_CID_BYTES];
            stream.read_exact(&mut marker).await?;
            if !valid_routing_cid_bytes(&marker, &secret, std::time::SystemTime::now()) {
                let mut prefix = [0_u8; TCP_ROUTING_RECORD_LEN];
                prefix[..5].copy_from_slice(&header);
                prefix[5..].copy_from_slice(&marker);
                tokio::spawn(async move {
                    if let Err(error) = passthrough_tcp(stream, &prefix, upstream).await {
                        tracing::debug!(?error, "HTTP/2 decoy passthrough closed");
                    }
                });
                return Ok(None);
            }
        } else {
            tokio::spawn(async move {
                if let Err(error) = passthrough_tcp(stream, &header, upstream).await {
                    tracing::debug!(?error, "HTTP/2 decoy passthrough closed");
                }
            });
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
        stream, &server_name.to_str(), &[HTTP2_ALPN, HTTP11_ALPN],
        !stealth_tls::skip_server_verification(flags),
    ).await?;
    if tls.get_ref().ssl().selected_alpn_protocol() != Some(HTTP2_ALPN) {
        return Err(TunnelError::InvalidProtocol("HTTP/2 ALPN was not negotiated".into()));
    }
    let mut bytes = [0; 32];
    tls.get_ref().ssl().export_keying_material(
        &mut bytes, "EXPORTER-LowTier-Http2-PeerConn-v1", Some(HTTP2_TRANSPORT_BINDING_CONTEXT),
    ).map_err(|error| TunnelError::InternalError(format!("derive HTTP/2 transport binding: {error}")))?;
    let binding = TransportBinding { kind: TransportBindingKind::Http2TlsExporterV1, bytes };

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
}
