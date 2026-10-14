//! QUIC stream control plus bounded DATAGRAM delivery for L2/L3 data.
//!
//! rustls/ring supplies standard TLS 1.3 QUIC packet protection. LowTier's
//! inner Noise session remains responsible for authenticated peer identity.

pub(crate) use super::stealth_tls::{
    ConnectIpAdmission, QUIC_ROUTING_CID_BYTES, routing_cid_bytes, valid_routing_cid_bytes,
};
use super::{
    BatchStreamItem, FromUrl, IpVersion, SinkError, TransportBinding, TransportBindingKind, Tunnel,
    TunnelConnector, TunnelError, TunnelListener,
};
use crate::common::{
    config::{Flags, gen_default_flags},
    dataplane_telemetry::{DataplaneIo, DataplaneStage, DataplaneTelemetry},
    global_ctx::{ArcGlobalCtx, ProcessMemoryPermit},
    underlay_policy::UnderlayPolicy,
};
use crate::tunnel::common::{
    bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
};
use crate::tunnel::{
    TunnelInfo,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, packet_batch_limit},
    common::BatchTunnelWrapper,
};
use anyhow::Context;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use futures::{Future, Sink, Stream, StreamExt};
use parking_lot::{Mutex as ParkingMutex, RwLock};
use quinn::{
    AckFrequencyConfig, AsyncUdpSocket, ClientConfig, ConnectError, Connection, ConnectionId,
    DatagramReceiveDropPolicy, Endpoint, EndpointConfig, Incoming, ServerConfig, TransportConfig,
    VarInt,
};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    OnceLock, Weak,
    atomic::{AtomicU32, AtomicU64, Ordering},
};
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use super::packet_def::ZCPacketType;
use super::packet_def::{NIC_TUNNEL_HEADROOM, PEER_MANAGER_HEADER_SIZE, ZCPacket};

#[cfg(test)]
mod decoy_tests;
mod fragments;
mod migration;
#[cfg(test)]
mod rebind_tests;
#[cfg(target_os = "linux")]
mod runtime;
mod sni;
#[cfg(target_os = "linux")]
use self::runtime::default_runtime;
use fragments::DatagramFragments;
#[cfg(target_os = "macos")]
mod darwin_runtime;
#[cfg(target_os = "macos")]
use darwin_runtime::default_runtime;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use quinn::default_runtime;
pub(crate) mod tunnel_cc;

use self::sni::quic_initial_sni_eq;
use migration::QuicMigrationPolicy;

// Begin at QUIC's Internet-safe UDP payload size. PMTUD probes upward before
// application traffic uses larger packets, including on lower-MTU PPPoE paths.
const QUIC_INITIAL_MTU: u16 = 1200;
const DATAGRAM_CONTEXT_WHOLE: u64 = 0;
const DATAGRAM_CONTEXT_FRAGMENT: u64 = 1;
const DATAGRAM_FRAGMENT_HEADER_LEN: usize = 6;
const DATAGRAM_FRAGMENT_MAX_PENDING: usize = 64;
// Preserve the WAN queue and flow-control windows. Quinn allocates storage from demand.
const QUIC_DATAGRAM_SEND_BUFFER_BYTES: usize = 1024 * 1024;
const QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW_BYTES: u64 = 2 * 1024 * 1024;
const QUIC_CONNECTION_RECEIVE_WINDOW_BYTES: u64 = 4 * 1024 * 1024;
const QUIC_CONNECTION_SEND_WINDOW_BYTES: u64 = 2 * 1024 * 1024;
const QUIC_PENDING_ACCEPT_BUFFER_BYTES: u64 = 256 * 1024;
// Idle loopback RSS grew by about 260 KiB per endpoint. Allow approximately four times that amount.
// This charge bounds admission, not peak RSS when connections fill their windows together.
pub(crate) const QUIC_CONNECTION_MEMORY_CHARGE_BYTES: usize = 1024 * 1024;
// Peer IDs are process-scoped. After a remote restart, the old UDP 4-tuple can
// remain locally writable until QUIC declares it idle, so routing can keep
// preferring a dead cost-1 incarnation. Transport keepalive makes healthy idle
// links prove receive liveness; the shorter idle timeout retires a blackholed
// incarnation before the next private-tracker rediscovery cycle.
const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(3);
const QUIC_RELIABLE_INITIAL_BUFFER_SIZE: usize = 4500;
/// Bound reliable frame allocation even though the wire length field is 32-bit.
const QUIC_RELIABLE_MAX_PACKET_SIZE: usize = 64 * 1024;
const QUIC_SOCKET_BUFFER_BYTES: usize = 7 * 1024 * 1024;
const QUIC_TRANSPORT_BINDING_LABEL: &[u8] = b"EXPORTER-LowTier-PeerConn-v1";
const QUIC_TRANSPORT_BINDING_CONTEXT: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256|peerconn-v3";

struct QuicSourcePermit {
    ip: IpAddr,
}

static QUIC_SOURCES: OnceLock<std::sync::Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();
const MAX_PENDING_QUIC_ACCEPTS_PER_IP_PROCESS_WIDE: usize = 32;

fn try_acquire_quic_source(ip: IpAddr) -> Option<QuicSourcePermit> {
    let mut sources = QUIC_SOURCES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if sources.get(&ip).copied().unwrap_or_default() >= MAX_PENDING_QUIC_ACCEPTS_PER_IP_PROCESS_WIDE
    {
        return None;
    }
    *sources.entry(ip).or_default() += 1;
    Some(QuicSourcePermit { ip })
}

impl Drop for QuicSourcePermit {
    fn drop(&mut self) {
        let Some(sources) = QUIC_SOURCES.get() else {
            return;
        };
        let mut sources = sources.lock().unwrap();
        if let Some(count) = sources.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                sources.remove(&self.ip);
            }
        }
    }
}

fn derive_transport_binding(connection: &Connection) -> Result<TransportBinding, TunnelError> {
    let mut bytes = [0_u8; 32];
    connection
        .export_keying_material(
            &mut bytes,
            QUIC_TRANSPORT_BINDING_LABEL,
            QUIC_TRANSPORT_BINDING_CONTEXT,
        )
        .map_err(|error| {
            TunnelError::InternalError(format!("derive QUIC transport binding: {error:?}"))
        })?;
    Ok(TransportBinding {
        kind: TransportBindingKind::QuicTlsExporterV1,
        bytes,
    })
}

const fn quic_socket_buffer_bytes() -> usize {
    QUIC_SOCKET_BUFFER_BYTES
}

const fn quic_socket_buffer_reported_target(target: usize, linux_accounting: bool) -> usize {
    if linux_accounting {
        // Linux doubles SO_RCVBUF/SO_SNDBUF for bookkeeping and reports the
        // doubled value through getsockopt.
        target.saturating_mul(2)
    } else {
        target
    }
}

fn quic_socket_buffer_target_is_met(
    reported: Option<usize>,
    target: usize,
    linux_accounting: bool,
) -> bool {
    reported.is_some_and(|reported| {
        reported >= quic_socket_buffer_reported_target(target, linux_accounting)
    })
}

#[cfg(target_os = "linux")]
fn force_linux_quic_socket_buffer(
    socket: &UdpSocket,
    option: nix::libc::c_int,
    target: usize,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let target = nix::libc::c_int::try_from(target).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "QUIC socket buffer target exceeds Linux c_int",
        )
    })?;
    let result = unsafe {
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            option,
            (&target as *const nix::libc::c_int).cast(),
            std::mem::size_of_val(&target) as nix::libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn prepare_quic_udp_socket(
    socket: UdpSocket,
    destination: Option<SocketAddr>,
) -> Result<std::net::UdpSocket, TunnelError> {
    let std_socket = socket.into_std()?;
    std_socket.set_nonblocking(true)?;
    if let Some(destination) = destination {
        let destination = match (std_socket.local_addr()?, destination) {
            (SocketAddr::V6(_), SocketAddr::V4(destination)) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    destination.ip().to_ipv6_mapped(),
                    destination.port(),
                    0,
                    0,
                ))
            }
            (_, destination) => destination,
        };
        std_socket.connect(destination)?;
    }
    Ok(std_socket)
}

fn configure_quic_socket_buffers(socket: &UdpSocket) {
    let socket_ref = socket2::SockRef::from(socket);
    let target = quic_socket_buffer_bytes();
    if let Err(error) = socket_ref.set_recv_buffer_size(target) {
        tracing::warn!(
            ?error,
            target,
            "failed to increase the QUIC UDP receive buffer"
        );
    }
    if let Err(error) = socket_ref.set_send_buffer_size(target) {
        tracing::warn!(
            ?error,
            target,
            "failed to increase the QUIC UDP send buffer"
        );
    }

    let recv_reported = socket_ref.recv_buffer_size().ok();
    let send_reported = socket_ref.send_buffer_size().ok();

    #[cfg(target_os = "linux")]
    let (recv_reported, send_reported, recv_forced, send_forced) = {
        let mut recv_reported = recv_reported;
        let mut send_reported = send_reported;
        let recv_forced = if quic_socket_buffer_target_is_met(recv_reported, target, true) {
            false
        } else {
            match force_linux_quic_socket_buffer(socket, nix::libc::SO_RCVBUFFORCE, target) {
                Ok(()) => {
                    recv_reported = socket_ref.recv_buffer_size().ok();
                    true
                }
                Err(error) => {
                    tracing::debug!(
                        ?error,
                        target,
                        ?recv_reported,
                        "SO_RCVBUFFORCE is unavailable for the QUIC UDP socket"
                    );
                    false
                }
            }
        };
        let send_forced = if quic_socket_buffer_target_is_met(send_reported, target, true) {
            false
        } else {
            match force_linux_quic_socket_buffer(socket, nix::libc::SO_SNDBUFFORCE, target) {
                Ok(()) => {
                    send_reported = socket_ref.send_buffer_size().ok();
                    true
                }
                Err(error) => {
                    tracing::debug!(
                        ?error,
                        target,
                        ?send_reported,
                        "SO_SNDBUFFORCE is unavailable for the QUIC UDP socket"
                    );
                    false
                }
            }
        };
        (recv_reported, send_reported, recv_forced, send_forced)
    };

    #[cfg(not(target_os = "linux"))]
    let (recv_reported, send_reported, recv_forced, send_forced) =
        (recv_reported, send_reported, false, false);

    let linux_accounting = cfg!(target_os = "linux");
    let recv_sufficient = quic_socket_buffer_target_is_met(recv_reported, target, linux_accounting);
    let send_sufficient = quic_socket_buffer_target_is_met(send_reported, target, linux_accounting);
    let expected_reported = quic_socket_buffer_reported_target(target, linux_accounting);
    if recv_sufficient && send_sufficient {
        if recv_forced || send_forced {
            tracing::info!(
                requested_bytes = target,
                expected_reported_bytes = expected_reported,
                ?recv_reported,
                ?send_reported,
                recv_forced,
                send_forced,
                "raised QUIC UDP socket buffers above the Linux kernel defaults"
            );
        } else {
            tracing::debug!(
                requested_bytes = target,
                expected_reported_bytes = expected_reported,
                ?recv_reported,
                ?send_reported,
                "configured QUIC UDP socket buffers"
            );
        }
    } else {
        tracing::warn!(
            requested_bytes = target,
            expected_reported_bytes = expected_reported,
            ?recv_reported,
            ?send_reported,
            recv_forced,
            send_forced,
            "QUIC UDP socket buffers remain below target; high-rate or high-RTT traffic may incur kernel queue drops"
        );
    }
}

type H3ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[async_trait::async_trait]
trait ConnectIpRequestStream: Send {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError>;
    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError>;
    async fn finish(&mut self) -> Result<(), TunnelError>;
}

#[async_trait::async_trait]
impl ConnectIpRequestStream for H3ClientStream {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError> {
        H3ClientStream::send_data(self, data)
            .await
            .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 DATA: {error}")))
    }

    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError> {
        H3ClientStream::recv_data(self)
            .await
            .map(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())))
            .map_err(|error| TunnelError::InternalError(format!("receive HTTP/3 DATA: {error}")))
    }

    async fn finish(&mut self) -> Result<(), TunnelError> {
        H3ClientStream::finish(self)
            .await
            .map_err(|error| TunnelError::InternalError(format!("finish HTTP/3 request: {error}")))
    }
}

#[async_trait::async_trait]
impl ConnectIpRequestStream for H3ServerStream {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError> {
        H3ServerStream::send_data(self, data)
            .await
            .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 DATA: {error}")))
    }

    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError> {
        H3ServerStream::recv_data(self)
            .await
            .map(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())))
            .map_err(|error| TunnelError::InternalError(format!("receive HTTP/3 DATA: {error}")))
    }

    async fn finish(&mut self) -> Result<(), TunnelError> {
        H3ServerStream::finish(self)
            .await
            .map_err(|error| TunnelError::InternalError(format!("finish HTTP/3 response: {error}")))
    }
}

fn connect_ip_stream_id(id: h3::quic::StreamId) -> u64 {
    id.index() * 4
}

async fn open_connect_ip_request(
    connection: &Connection,
    authority: &str,
    bearer: Option<&str>,
) -> Result<(Box<dyn ConnectIpRequestStream>, u64), TunnelError> {
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (mut driver, mut requests) = builder
        .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(h3_quinn::Connection::new(
            connection.clone(),
        ))
        .await
        .map_err(|error| TunnelError::InternalError(format!("start HTTP/3 client: {error}")))?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let uri = format!("https://{authority}{CONNECT_IP_PATH}")
        .parse::<http::Uri>()
        .context("build CONNECT-IP URI")?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1");
    if let Some(bearer) = bearer {
        request = request.header("proxy-authorization", format!("Bearer {bearer}"));
    }
    let request = request
        .extension(h3::ext::Protocol::CONNECT_IP)
        .body(())
        .context("build CONNECT-IP request")?;
    let mut stream = requests
        .send_request(request)
        .await
        .map_err(|error| TunnelError::InternalError(format!("send CONNECT-IP request: {error}")))?;
    let response = stream.recv_response().await.map_err(|error| {
        TunnelError::InternalError(format!("receive CONNECT-IP response: {error}"))
    })?;
    let capsule_enabled = response
        .headers()
        .get("capsule-protocol")
        .and_then(|value| value.to_str().ok())
        == Some("?1");
    if !response.status().is_success() || !capsule_enabled {
        return Err(TunnelError::InternalError(format!(
            "CONNECT-IP returned an invalid response with HTTP status {}",
            response.status(),
        )));
    }
    let stream_id = connect_ip_stream_id(stream.id());
    let guard_connection = connection.clone();
    tokio::spawn(async move {
        let _requests = requests;
        let _ = guard_connection.closed().await;
    });
    Ok((Box::new(stream), stream_id))
}

const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
// 8 bytes matches browser QUIC Initials (RFC 9000 §7.2 minimum, Chrome's size).
// 20-byte DCIDs fingerprint as quinn/rust, not a browser talking to Cloudflare.
const MAX_HTTP3_ORIGIN_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_ORIGIN_BODY: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Welcome</title></head><body><main><h1>Welcome</h1></main></body></html>";
const NOT_FOUND_BODY: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not Found</title></head><body><h1>Not Found</h1></body></html>";

fn quic_routing_cid(secret: &[u8], now: SystemTime) -> ConnectionId {
    ConnectionId::new(&routing_cid_bytes(secret, now))
}

fn quic_initial_dcid(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 6 || packet[0] & 0xf0 != 0xc0 || packet[1..5] != 1_u32.to_be_bytes() {
        return None;
    }
    let length = packet[5] as usize;
    (length <= 20 && packet.len() >= 6 + length).then_some(&packet[6..6 + length])
}

fn valid_quic_routing_marker(
    packet: &[u8],
    secret: &[u8],
    now: SystemTime,
) -> Option<[u8; QUIC_ROUTING_CID_BYTES]> {
    let Some(cid) = quic_initial_dcid(packet).filter(|cid| cid.len() == QUIC_ROUTING_CID_BYTES)
    else {
        return None;
    };
    valid_routing_cid_bytes(cid, secret, now)
        .then(|| cid.try_into().expect("routing CID length was checked"))
}

#[cfg(test)]
fn has_valid_quic_routing_marker(packet: &[u8], secret: &[u8], now: SystemTime) -> bool {
    valid_quic_routing_marker(packet, secret, now).is_some()
}

struct OriginResponse {
    status: http::StatusCode,
    content_type: &'static str,
    body: Bytes,
    cache_control: &'static str,
}

fn origin_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("ico") => "image/x-icon",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("webp") => "image/webp",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn origin_file(root: &Path, uri_path: &str) -> Option<(Bytes, &'static str)> {
    if !uri_path.starts_with('/')
        || uri_path.contains('%')
        || uri_path.contains('\\')
        || uri_path.split('/').any(|segment| segment == "..")
    {
        return None;
    }
    let relative = if uri_path == "/" {
        Path::new("index.html")
    } else {
        Path::new(uri_path.trim_start_matches('/'))
    };
    let canonical_root = tokio::fs::canonicalize(root).await.ok()?;
    let mut candidate = tokio::fs::canonicalize(canonical_root.join(relative))
        .await
        .ok()?;
    if !candidate.starts_with(&canonical_root) {
        return None;
    }
    let mut metadata = tokio::fs::metadata(&candidate).await.ok()?;
    if metadata.is_dir() {
        candidate = tokio::fs::canonicalize(candidate.join("index.html"))
            .await
            .ok()?;
        if !candidate.starts_with(&canonical_root) {
            return None;
        }
        metadata = tokio::fs::metadata(&candidate).await.ok()?;
    }
    if !metadata.is_file() || metadata.len() > MAX_HTTP3_ORIGIN_FILE_BYTES {
        return None;
    }
    let content_type = origin_content_type(&candidate);
    let body = tokio::fs::read(candidate).await.ok()?;
    Some((Bytes::from(body), content_type))
}

async fn normal_origin_response(
    request: &http::Request<()>,
    root: Option<&Path>,
) -> OriginResponse {
    let method_allows_body = matches!(*request.method(), http::Method::GET | http::Method::HEAD);
    if method_allows_body
        && let Some(root) = root
        && let Some((body, content_type)) = origin_file(root, request.uri().path()).await
    {
        return OriginResponse {
            status: http::StatusCode::OK,
            content_type,
            body,
            cache_control: "public, max-age=300",
        };
    }
    if method_allows_body && request.uri().path() == "/" {
        return OriginResponse {
            status: http::StatusCode::OK,
            content_type: "text/html; charset=utf-8",
            body: Bytes::from_static(DEFAULT_ORIGIN_BODY),
            cache_control: "public, max-age=60",
        };
    }
    OriginResponse {
        status: http::StatusCode::NOT_FOUND,
        content_type: "text/html; charset=utf-8",
        body: Bytes::from_static(NOT_FOUND_BODY),
        cache_control: "no-cache",
    }
}

async fn send_normal_http3_response(
    request: http::Request<()>,
    mut stream: H3ServerStream,
    root: Option<PathBuf>,
) -> Result<(), TunnelError> {
    let response_body = normal_origin_response(&request, root.as_deref()).await;
    let send_body = request.method() != http::Method::HEAD;
    let response = http::Response::builder()
        .status(response_body.status)
        .header("content-type", response_body.content_type)
        .header("content-length", response_body.body.len().to_string())
        .header("cache-control", response_body.cache_control)
        .header("x-content-type-options", "nosniff")
        .body(())
        .context("build HTTP/3 response")?;
    stream
        .send_response(response)
        .await
        .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 response: {error}")))?;
    if send_body && !response_body.body.is_empty() {
        stream
            .send_data(response_body.body)
            .await
            .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 body: {error}")))?;
    }
    stream
        .finish()
        .await
        .map_err(|error| TunnelError::InternalError(format!("finish HTTP/3 response: {error}")))
}

async fn serve_additional_http3_requests(
    connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    fallback_root: Option<PathBuf>,
) {
    serve_http3_requests(connection, fallback_root, None).await;
}

struct Http3Website {
    connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    first: (http::Request<()>, H3ServerStream),
}

enum ConnectIpAccept {
    Tunnel(Box<dyn ConnectIpRequestStream>, u64),
    Website(Box<Http3Website>),
}

async fn serve_http3_requests(
    mut connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    fallback_root: Option<PathBuf>,
    first: Option<(http::Request<()>, H3ServerStream)>,
) {
    let website = first.is_some();
    let mut responses = tokio::task::JoinSet::new();
    if let Some((request, stream)) = first {
        responses.spawn(send_normal_http3_response(
            request,
            stream,
            fallback_root.clone(),
        ));
    }
    loop {
        let accepted = tokio::select! {
            result = responses.join_next(), if !responses.is_empty() => {
                if let Some(Err(error)) = result { tracing::debug!(?error, "HTTP/3 response task stopped"); }
                continue;
            }
            accepted = connection.accept(), if responses.len() < 2 => accepted,
            _ = tokio::time::sleep(super::decoy::IDLE_TIMEOUT), if website && responses.is_empty() => return,
        };
        let resolver = match accepted {
            Ok(Some(resolver)) => resolver,
            Ok(None) | Err(_) => return,
        };
        match tokio::time::timeout(super::decoy::CONNECT_TIMEOUT, resolver.resolve_request()).await
        {
            Ok(Ok((request, stream))) => {
                responses.spawn(send_normal_http3_response(
                    request,
                    stream,
                    fallback_root.clone(),
                ));
            }
            Err(error) => tracing::debug!(?error, "reject malformed HTTP/3 request"),
            Ok(Err(error)) => tracing::debug!(?error, "reject malformed HTTP/3 request"),
        }
    }
}

async fn accept_connect_ip_request(
    connection: &Connection,
    admission: Option<&ConnectIpAdmission>,
    fallback_root: Option<PathBuf>,
) -> Result<ConnectIpAccept, TunnelError> {
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut h3 = builder
        .build::<h3_quinn::Connection, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| TunnelError::InternalError(format!("start HTTP/3 server: {error}")))?;

    loop {
        let resolver = h3
            .accept()
            .await
            .map_err(|error| TunnelError::InternalError(format!("accept HTTP/3 request: {error}")))?
            .ok_or_else(|| TunnelError::InternalError("HTTP/3 connection closed".to_owned()))?;
        let (request, mut stream) = resolver.resolve_request().await.map_err(|error| {
            TunnelError::InternalError(format!("resolve HTTP/3 request: {error}"))
        })?;
        let is_connect_ip = request.method() == http::Method::CONNECT
            && request
                .extensions()
                .get::<h3::ext::Protocol>()
                .is_some_and(|protocol| protocol.as_str() == "connect-ip")
            && request.uri().path() == CONNECT_IP_PATH;
        let authorized = match admission {
            Some(admission) => request
                .headers()
                .get("proxy-authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| admission.verify_header(value)),
            None => false,
        };
        if !is_connect_ip || !authorized {
            // Website requests leave VPN admission immediately. Their separate
            // owner applies website resource limits without the CONNECT deadline.
            return Ok(ConnectIpAccept::Website(Box::new(Http3Website {
                connection: h3,
                first: (request, stream),
            })));
        }
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("capsule-protocol", "?1")
            .body(())
            .context("build CONNECT-IP response")?;
        stream.send_response(response).await.map_err(|error| {
            TunnelError::InternalError(format!("send CONNECT-IP response: {error}"))
        })?;
        let stream_id = connect_ip_stream_id(stream.id());
        tokio::spawn(serve_additional_http3_requests(h3, fallback_root));
        return Ok(ConnectIpAccept::Tunnel(
            Box::new(stream) as Box<dyn ConnectIpRequestStream>,
            stream_id,
        ));
    }
}

fn connect_ip_bearer(global_ctx: &ArcGlobalCtx) -> Option<String> {
    ConnectIpAdmission::from_global_ctx(global_ctx).map(|admission| admission.current_token())
}

// region config
mod tls {
    #[cfg(test)]
    use std::path::PathBuf;

    use anyhow::Context as _;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer},
    };

    use crate::{common::config::Flags, tunnel::TunnelError};

    const HTTP3_ALPN: &[u8] = b"h3";

    #[cfg(test)]
    fn server_identity_paths(flags: &Flags) -> Option<(PathBuf, PathBuf)> {
        crate::tunnel::stealth_tls::server_identity_paths(flags)
    }

    fn server_identity(
        flags: &Flags,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TunnelError> {
        crate::tunnel::stealth_tls::server_identity(flags)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::common::config::gen_default_flags;

        #[test]
        fn certificate_paths_follow_server_name_without_manual_paths() {
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = "challenges.cloudflare.com".to_owned();

            let paths = server_identity_paths(&flags).unwrap();

            assert_eq!(
                paths.0,
                PathBuf::from("/etc/letsencrypt/live/challenges.cloudflare.com/fullchain.pem")
            );
            assert_eq!(
                paths.1,
                PathBuf::from("/etc/letsencrypt/live/challenges.cloudflare.com/privkey.pem")
            );
        }

        #[test]
        fn explicit_certificate_paths_take_priority() {
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = "challenges.cloudflare.com".to_owned();
            flags.camouflage_config_mut().tls_cert = "/run/cert.pem".to_owned();
            flags.camouflage_config_mut().tls_key = "/run/key.pem".to_owned();

            assert_eq!(
                server_identity_paths(&flags),
                Some((
                    PathBuf::from("/run/cert.pem"),
                    PathBuf::from("/run/key.pem")
                ))
            );
        }
    }

    pub(super) fn server_crypto(flags: &Flags) -> Result<QuicServerConfig, TunnelError> {
        let (certs, key) = server_identity(flags)?;

        let provider = crate::tunnel::stealth_tls::stealth_crypto_provider();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure QUIC TLS 1.3 server")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("configure ephemeral QUIC server identity")?;
        config.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
        QuicServerConfig::try_from(config)
            .context("convert rustls server config to Quinn")
            .map_err(Into::into)
    }

    pub(super) fn client_crypto(flags: &Flags) -> Result<QuicClientConfig, TunnelError> {
        let provider = crate::tunnel::stealth_tls::stealth_crypto_provider();
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("configure QUIC TLS 1.3 client")?;
        let mut config = if crate::tunnel::stealth_tls::skip_server_verification(flags) {
            builder
                .dangerous()
                .with_custom_certificate_verifier(
                    crate::tunnel::stealth_tls::NoiseAuthenticatedPeerVerifier::new(),
                )
                .with_no_client_auth()
        } else {
            let native = rustls_native_certs::load_native_certs();
            if native.certs.is_empty() {
                return Err(TunnelError::InternalError(format!(
                    "load native QUIC TLS roots: {:?}",
                    native.errors
                )));
            }
            let mut roots = RootCertStore::empty();
            let (added, ignored) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(TunnelError::InternalError(format!(
                    "no valid native QUIC TLS roots; ignored {ignored} certificates"
                )));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        config.alpn_protocols = vec![HTTP3_ALPN.to_vec()];
        QuicClientConfig::try_from(config)
            .context("convert rustls client config to Quinn")
            .map_err(Into::into)
    }
}
fn parse_pacing_burst_packets(value: Option<&str>) -> Result<std::num::NonZeroU16, TunnelError> {
    match value {
        None => Ok(std::num::NonZeroU16::new(64).unwrap()),
        Some(value) => value
            .parse::<std::num::NonZeroU16>()
            .ok()
            .filter(|value| value.get() <= 256)
            .ok_or_else(|| {
                TunnelError::InternalError(
                    "LOWTIER_QUIC_PACING_BURST_PACKETS must be an integer from 1 through 256"
                        .into(),
                )
            }),
    }
}

pub fn transport_config(flags: &Flags) -> Result<Arc<TransportConfig>, TunnelError> {
    let mut config = TransportConfig::default();
    // Resolve once at connection setup; the packet path keeps only the bound.
    // This diagnostic override varies burst injection independently of the
    // congestion controller for matched-binary validation on different links.
    let burst_override = std::env::var("LOWTIER_QUIC_PACING_BURST_PACKETS");
    let burst_value = match &burst_override {
        Ok(value) => Some(value.as_str()),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => {
            return Err(TunnelError::InternalError(
                "invalid pacing burst encoding".into(),
            ));
        }
    };
    config.pacing_burst_size(parse_pacing_burst_packets(burst_value)?);

    let stream_receive_window = VarInt::from_u64(
        flags
            .quic_initial_receive_window
            .min(QUIC_STREAM_RECEIVE_WINDOW_BYTES),
    )
    .map_err(|error| TunnelError::InternalError(error.to_string()))?;
    let receive_window = VarInt::from_u64(
        flags
            .quic_receive_window
            .min(QUIC_CONNECTION_RECEIVE_WINDOW_BYTES)
            .max(stream_receive_window.into_inner()),
    )
    .map_err(|error| TunnelError::InternalError(error.to_string()))?;
    let idle_timeout = QUIC_MAX_IDLE_TIMEOUT.try_into().map_err(|error| {
        TunnelError::InternalError(format!("invalid QUIC idle timeout: {error}"))
    })?;

    config
        .max_concurrent_bidi_streams(100_u8.into())
        .migration_requires_policy(true)
        .max_concurrent_uni_streams(3_u8.into())
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL))
        .initial_mtu(QUIC_INITIAL_MTU)
        .enable_segmentation_offload(true)
        .ack_frequency_config(Some({
            let mut ack_frequency = AckFrequencyConfig::default();
            ack_frequency.ack_eliciting_threshold(VarInt::from_u32(8));
            // The initial ten-packet window must elicit an ACK without a timer.
            ack_frequency.max_ack_delay(Some(Duration::from_millis(1)));
            ack_frequency
        }))
        .datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES))
        .datagram_receive_drop_policy(DatagramReceiveDropPolicy::Newest)
        .datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_BYTES)
        .datagram_send_queue_time(Some(Duration::from_millis(4)))
        .datagram_send_max_time(Some(Duration::from_millis(10)))
        .send_window(QUIC_CONNECTION_SEND_WINDOW_BYTES)
        .stream_receive_window(stream_receive_window)
        .receive_window(receive_window)
        .congestion_controller_factory(tunnel_cc::controller_factory()?);

    Ok(Arc::new(config))
}

pub fn server_config(flags: &Flags) -> Result<ServerConfig, TunnelError> {
    let mut config = ServerConfig::with_crypto(Arc::new(tls::server_crypto(flags)?));
    config.transport_config(transport_config(flags)?);
    configure_server_admission(&mut config);
    Ok(config)
}

pub fn client_config(flags: &Flags) -> Result<ClientConfig, TunnelError> {
    let mut config = ClientConfig::new(Arc::new(tls::client_crypto(flags)?));
    config.transport_config(transport_config(flags)?);
    if !flags.camouflage_config().udp_decoy().is_empty() {
        let secret: Arc<[u8]> = Arc::from(
            flags
                .camouflage_config()
                .admission_secret
                .clone()
                .into_bytes(),
        );
        config.initial_dst_cid_provider(Arc::new(move || {
            quic_routing_cid(&secret, SystemTime::now())
        }));
    }
    Ok(config)
}

fn configure_server_admission(config: &mut ServerConfig) {
    config.max_incoming(MAX_PENDING_QUIC_ACCEPTS * 2);
    config.incoming_buffer_size_total(QUIC_PENDING_ACCEPT_BUFFER_BYTES);
    config.migration(true);
}

pub fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    // Allow IPv4 Ethernet UDP payloads. Oversized TAP frames split across
    // DATAGRAMs instead of using STREAM.
    config.max_udp_payload_size(1500).unwrap();
    config
}
//endregion

//region rw pool
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
#[derive(Debug, Deref, DerefMut)]
struct RwPoolInner<Item> {
    #[deref]
    #[deref_mut]
    pool: Vec<Item>,
    enabled: bool,
}

#[derive(Debug)]
struct RwPool<Item> {
    ephemeral: RwLock<RwPoolInner<Item>>,
    persistent: RwLock<RwPoolInner<Item>>,
    capacity: usize,
}

impl<Item> RwPool<Item> {
    fn new(capacity: usize) -> Self {
        Self {
            ephemeral: RwLock::new(RwPoolInner::default()),
            persistent: RwLock::new(RwPoolInner::default()),
            capacity,
        }
    }

    /// return the capacity of the ephemeral pool;
    /// if `ephemeral` or `persistent` is None, read lock `self`'s pool
    fn capacity(
        &self,
        ephemeral: Option<&RwPoolInner<Item>>,
        persistent: Option<&RwPoolInner<Item>>,
    ) -> usize {
        let guard;
        let ephemeral = if let Some(ephemeral) = ephemeral {
            ephemeral
        } else {
            guard = self.ephemeral.read();
            &guard
        };

        let guard;
        let persistent = if let Some(persistent) = persistent {
            persistent
        } else {
            guard = self.persistent.read();
            &guard
        };

        (self.capacity * ephemeral.enabled as usize).saturating_sub(persistent.len())
    }

    fn is_enabled(&self) -> bool {
        self.ephemeral.read().enabled
    }

    fn enable(&self) {
        self.ephemeral.write().enabled = true;
        self.resize();
    }

    fn disable(&self) {
        self.ephemeral.write().enabled = false;
        self.resize();
    }

    #[cfg(target_os = "linux")]
    fn is_full(&self) -> bool {
        let pool = self.ephemeral.read();
        pool.len() >= self.capacity(Some(&pool), None)
    }

    fn len(&self) -> usize {
        let persistent_len = self.persistent.read().len();
        let ephemeral_len = self.ephemeral.read().len();
        persistent_len + ephemeral_len
    }

    /// try to push an item to the ephemeral pool, return the item if full
    fn try_push(&self, item: Item) -> Option<Item> {
        let mut pool = self.ephemeral.write();
        if pool.len() < self.capacity(Some(&pool), None) {
            pool.push(item);
            return None;
        }
        Some(item)
    }

    fn resize(&self) {
        let resize = {
            let pool = self.ephemeral.read();
            pool.capacity() != self.capacity(Some(&pool), None)
        };
        if resize {
            let mut pool = self.ephemeral.write();
            let capacity = self.capacity(Some(&pool), None);
            pool.reserve_exact(capacity);
            pool.truncate(capacity);
            pool.shrink_to(capacity);
        }
    }

    fn with_iter<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn Iterator<Item = &Item>) -> R,
    {
        let ephemeral = self.ephemeral.read();
        let persistent = self.persistent.read();
        f(&mut persistent.iter().chain(ephemeral.iter()))
    }
}

impl RwPool<Endpoint> {
    fn retain_endpoints<F>(&self, mut keep: F) -> usize
    where
        F: FnMut(&Endpoint) -> bool,
    {
        let persistent_removed = {
            let mut persistent = self.persistent.write();
            let before = persistent.len();
            persistent.retain(|endpoint| keep(endpoint));
            before - persistent.len()
        };

        let ephemeral_removed = {
            let mut ephemeral = self.ephemeral.write();
            let before = ephemeral.len();
            ephemeral.retain(|endpoint| keep(endpoint));
            before - ephemeral.len()
        };

        let removed = persistent_removed + ephemeral_removed;
        if removed > 0 {
            self.resize();
        }
        removed
    }

    fn remove_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        self.retain_endpoints(|endpoint| endpoint.local_addr().ok() != Some(local_addr))
    }
}
//endregion

//region endpoint manager
#[derive(Debug)]
pub struct QuicEndpointManager {
    ipv4: RwPool<Endpoint>,
    ipv6: RwPool<Endpoint>,
    both: RwPool<Endpoint>,
    servers: dashmap::DashMap<SocketAddr, Endpoint>,
    flags: Arc<Flags>,
    client_paths: ParkingMutex<Vec<Weak<ConnWrapper>>>,
    route_watcher: OnceLock<()>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct QuicEndpointManagerKey {
    owner_id: uuid::Uuid,
    socket_mark: Option<u32>,
    net_namespace: Option<String>,
    bind_device: bool,
    denied_interfaces: Vec<String>,
    denied_cidrs: Vec<String>,
}

static QUIC_ENDPOINT_MANAGERS: OnceLock<
    dashmap::DashMap<QuicEndpointManagerKey, Weak<QuicEndpointManager>>,
> = OnceLock::new();

#[derive(Clone, Copy)]
struct QuicConnectSecurity<'a> {
    flags: &'a Flags,
}

impl QuicEndpointManager {
    fn try_create(
        addr: SocketAddr,
        dual_stack: bool,
        socket_mark: Option<u32>,
    ) -> Result<Endpoint, TunnelError> {
        Self::try_create_for_peer(addr, dual_stack, socket_mark, None)
    }

    fn try_create_for_peer(
        addr: SocketAddr,
        dual_stack: bool,
        socket_mark: Option<u32>,
        destination: Option<SocketAddr>,
    ) -> Result<Endpoint, TunnelError> {
        let socket = bind::<UdpSocket>()
            .addr(addr)
            .only_v6(addr.is_ipv6() && !dual_stack)
            .maybe_socket_mark(socket_mark)
            .call()?;
        configure_quic_socket_buffers(&socket);
        let std_socket = prepare_quic_udp_socket(socket, destination)?;
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        let socket = runtime.wrap_udp_socket(std_socket)?;
        let mut endpoint =
            Endpoint::new_with_abstract_socket(endpoint_config(), None, socket, runtime)?;
        endpoint.set_default_client_config(client_config(&gen_default_flags())?);
        Ok(endpoint)
    }

    fn create<F>(
        &self,
        socket_mark: Option<u32>,
        mut selector: F,
    ) -> Result<(&RwPool<Endpoint>, Option<Endpoint>), TunnelError>
    where
        F: FnMut(&QuicEndpointManager) -> (&RwPool<Endpoint>, Option<(SocketAddr, bool)>),
    {
        loop {
            let (pool, r) = selector(self);
            let Some((addr, dual_stack)) = r else {
                return Ok((pool, None));
            };

            let created = Self::try_create(addr, dual_stack, socket_mark);
            if let Err(error) = created.as_ref()
                && dual_stack
            {
                tracing::warn!(?error, "create dual stack quic endpoint failed");
                self.both.disable();
                self.ipv4.enable();
                self.ipv6.enable();
                continue;
            }

            let endpoint = created?;
            return Ok((pool, Some(endpoint)));
        }
    }
}

impl QuicEndpointManager {
    fn new_with_flags(capacity: usize, flags: Arc<Flags>) -> Self {
        let ipv4 = RwPool::new(capacity.div_ceil(2));
        let ipv6 = RwPool::new(capacity.div_ceil(2));
        let both = RwPool::new(capacity);
        both.enable();
        Self {
            ipv4,
            ipv6,
            both,
            servers: dashmap::DashMap::new(),
            flags,
            client_paths: ParkingMutex::new(Vec::new()),
            route_watcher: OnceLock::new(),
        }
    }

    fn manager_key_for_flags(global_ctx: &ArcGlobalCtx, flags: &Flags) -> QuicEndpointManagerKey {
        QuicEndpointManagerKey {
            owner_id: global_ctx.id,
            socket_mark: flags.socket_mark,
            net_namespace: global_ctx.net_ns.name(),
            bind_device: flags.bind_device,
            denied_interfaces: flags.underlay_deny_interfaces.clone(),
            denied_cidrs: flags.underlay_deny_cidrs.clone(),
        }
    }

    fn load(global_ctx: &ArcGlobalCtx) -> Arc<Self> {
        use dashmap::mapref::entry::Entry;

        let flags = global_ctx.flags_arc();
        // One endpoint per address family keeps socket ownership compact.
        // Explicit source bindings retain their own endpoint when required.
        let capacity = 1;
        let managers = QUIC_ENDPOINT_MANAGERS.get_or_init(dashmap::DashMap::new);
        managers.retain(|_, manager| manager.strong_count() > 0);
        let key = Self::manager_key_for_flags(global_ctx, &flags);
        let manager = match managers.entry(key) {
            Entry::Occupied(mut entry) => {
                if let Some(manager) = entry.get().upgrade()
                    && Arc::ptr_eq(&manager.flags, &flags)
                {
                    manager
                } else {
                    let manager = Arc::new(Self::new_with_flags(capacity, flags));
                    entry.insert(Arc::downgrade(&manager));
                    manager
                }
            }
            Entry::Vacant(entry) => {
                let manager = Arc::new(Self::new_with_flags(capacity, flags));
                entry.insert(Arc::downgrade(&manager));
                manager
            }
        };
        for pool in [&manager.ipv4, &manager.ipv6, &manager.both] {
            pool.resize();
        }
        manager.route_watcher.get_or_init(|| {
            migration::observe_network_changes(&manager, global_ctx);
        });
        manager
    }

    fn client_pool(&self, ip_version: IpVersion) -> &RwPool<Endpoint> {
        let dual_stack = self.both.is_enabled();
        match ip_version {
            IpVersion::V4 => &self.ipv4,
            IpVersion::V6 if !dual_stack => &self.ipv6,
            _ => {
                if dual_stack {
                    &self.both
                } else {
                    &self.ipv6
                }
            }
        }
    }

    /// Get a QUIC endpoint to be used as a server
    ///
    /// # Arguments
    /// * `addr`: listen address
    fn server(
        _global_ctx: &ArcGlobalCtx,
        mgr: &Arc<Self>,
        addr: SocketAddr,
    ) -> Result<Endpoint, TunnelError> {
        let socket_mark = mgr.flags.socket_mark;

        let (_pool, endpoint) = mgr.create(socket_mark, |mgr| {
            let dual_stack = addr.ip() == Ipv6Addr::UNSPECIFIED && mgr.both.is_enabled();
            let pool = if addr.is_ipv4() {
                &mgr.ipv4
            } else if dual_stack {
                &mgr.both
            } else {
                &mgr.ipv6
            };
            (pool, Some((addr, dual_stack)))
        })?;

        let endpoint = endpoint.expect("server endpoint creation should not return None");
        endpoint.set_server_config(Some(server_config(&mgr.flags)?));
        mgr.servers.insert(endpoint.local_addr()?, endpoint.clone());

        Ok(endpoint)
    }

    fn server_with_decoy(
        mgr: &Arc<Self>,
        addr: SocketAddr,
        upstream: SocketAddr,
        secret: Arc<[u8]>,
        server_name: Option<Arc<str>>,
    ) -> Result<Endpoint, TunnelError> {
        if !addr.is_ipv4() || !upstream.is_ipv4() {
            return Err(TunnelError::InternalError(
                "QUIC decoy mode currently requires IPv4 addresses".to_owned(),
            ));
        }
        let socket = bind::<UdpSocket>()
            .addr(addr)
            .only_v6(false)
            .maybe_socket_mark(mgr.flags.socket_mark)
            .call()?;
        configure_quic_socket_buffers(&socket);
        let std_socket = prepare_quic_udp_socket(socket, None)?;
        let runtime = default_runtime().ok_or(TunnelError::InternalError(
            "no async runtime found".to_owned(),
        ))?;
        let socket = runtime.wrap_udp_socket(std_socket)?;
        let socket =
            QuicDecoySocket::new(socket, upstream, secret, mgr.flags.socket_mark, server_name);
        let mut endpoint =
            Endpoint::new_with_abstract_socket(endpoint_config(), None, socket, runtime)?;
        endpoint.set_default_client_config(client_config(&gen_default_flags())?);
        endpoint.set_server_config(Some(server_config(&mgr.flags)?));
        let local_addr = endpoint.local_addr()?;
        if local_addr == upstream {
            endpoint.close(VarInt::from_u32(1), b"invalid decoy upstream");
            return Err(TunnelError::InternalError(
                "QUIC decoy upstream equals the listen address".to_owned(),
            ));
        }
        mgr.servers.insert(local_addr, endpoint.clone());
        Ok(endpoint)
    }

    #[cfg(target_os = "macos")]
    fn client_endpoint(
        &self,
        _ip_version: IpVersion,
        socket_mark: Option<u32>,
        destination: SocketAddr,
    ) -> Result<Endpoint, TunnelError> {
        let addr = if destination.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        Self::try_create_for_peer(addr, false, socket_mark, Some(destination))
    }

    #[cfg(not(target_os = "macos"))]
    fn client_endpoint(
        &self,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
        _destination: SocketAddr,
    ) -> Result<Endpoint, TunnelError> {
        let (pool, endpoint) = self.create(socket_mark, |mgr| {
            let dual_stack = mgr.both.is_enabled();
            let (pool, addr) = match ip_version {
                IpVersion::V4 => {
                    mgr.ipv4.enable();
                    (&mgr.ipv4, (Ipv4Addr::UNSPECIFIED, 0).into())
                }
                IpVersion::V6 if !dual_stack => (&mgr.ipv6, (Ipv6Addr::UNSPECIFIED, 0).into()),
                _ => {
                    let pool = if dual_stack { &mgr.both } else { &mgr.ipv6 };
                    (pool, (Ipv6Addr::UNSPECIFIED, 0).into())
                }
            };
            if pool.is_full() {
                (pool, None)
            } else {
                (pool, Some((addr, dual_stack)))
            }
        })?;

        if let Some(endpoint) = endpoint {
            pool.try_push(endpoint);
        }

        pool.with_iter(|iter| iter.min_by_key(|e| e.open_connections()).cloned())
            .ok_or_else(|| {
                TunnelError::InternalError("no QUIC client endpoint available".to_owned())
            })
    }
    fn client_endpoint_for_source(
        &self,
        source: SocketAddr,
        socket_mark: Option<u32>,
        policy: &UnderlayPolicy,
        destination: SocketAddr,
    ) -> Result<Endpoint, TunnelError> {
        ensure_local_allowed(policy, source)?;
        #[cfg(target_os = "macos")]
        if source.port() == 0 {
            return Self::try_create_for_peer(source, false, socket_mark, Some(destination));
        }
        #[cfg(not(target_os = "macos"))]
        let _ = destination;

        let pool = if source.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };

        if let Some(endpoint) = pool.with_iter(|iter| {
            iter.filter(|endpoint| {
                endpoint.local_addr().is_ok_and(|local| {
                    local.ip() == source.ip()
                        && (source.port() == 0 || local.port() == source.port())
                })
            })
            .min_by_key(|endpoint| endpoint.open_connections())
            .cloned()
        }) {
            return Ok(endpoint);
        }

        let endpoint = Self::try_create(source, false, socket_mark)?;
        Ok(self.retain_source_endpoint(endpoint))
    }

    fn retain_source_endpoint(&self, endpoint: Endpoint) -> Endpoint {
        let pool = if endpoint
            .local_addr()
            .is_ok_and(|local_addr| local_addr.is_ipv4())
        {
            &self.ipv4
        } else {
            &self.ipv6
        };
        pool.enable();
        let connection_owner = endpoint.clone();
        pool.try_push(endpoint).unwrap_or(connection_owner)
    }

    fn remove_endpoint(&self, endpoint: &Endpoint) -> usize {
        let Ok(local_addr) = endpoint.local_addr() else {
            return 0;
        };
        self.remove_endpoint_by_local_addr(local_addr)
    }
    fn remove_endpoint_by_local_addr(&self, local_addr: SocketAddr) -> usize {
        let client_removed: usize = [&self.ipv4, &self.ipv6, &self.both]
            .into_iter()
            .map(|pool| pool.remove_by_local_addr(local_addr))
            .sum();
        client_removed + usize::from(self.servers.remove(&local_addr).is_some())
    }

    #[cfg(test)]
    async fn connect(
        global_ctx: &ArcGlobalCtx,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
        policy: Arc<UnderlayPolicy>,
    ) -> Result<(Endpoint, Connection, bool, bool), TunnelError> {
        let manager = Self::load(global_ctx);
        Self::connect_with_manager(global_ctx, &manager, addr, bind_addrs, policy).await
    }

    async fn connect_with_manager(
        _global_ctx: &ArcGlobalCtx,
        manager: &Arc<Self>,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
        policy: Arc<UnderlayPolicy>,
    ) -> Result<(Endpoint, Connection, bool, bool), TunnelError> {
        let ip_version = if addr.ip().is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let flags = manager.flags.clone();
        let security = QuicConnectSecurity {
            flags: flags.as_ref(),
        };
        let socket_mark = flags.socket_mark;
        ensure_remote_allowed(&policy, addr)?;
        let bind_addrs = eligible_bind_addrs(&policy, bind_addrs, addr)?;
        if bind_addrs.is_empty() {
            return manager
                .connect_with_ip_version(addr, ip_version, socket_mark, security)
                .await;
        }

        for source in bind_addrs {
            match manager
                .connect_with_source(addr, source, socket_mark, policy.clone(), security)
                .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    tracing::debug!(?source, ?error, "QUIC source connection failed");
                }
            }
        }
        Err(TunnelError::InternalError(
            "all eligible QUIC source addresses failed".to_owned(),
        ))
    }

    async fn connect_with_source(
        &self,
        addr: SocketAddr,
        source: SocketAddr,
        socket_mark: Option<u32>,
        policy: Arc<UnderlayPolicy>,
        security: QuicConnectSecurity<'_>,
    ) -> Result<(Endpoint, Connection, bool, bool), TunnelError> {
        let pool = if source.is_ipv4() {
            &self.ipv4
        } else {
            &self.ipv6
        };
        let max_endpoint_stopping_retries = pool.len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint_for_source(source, socket_mark, &policy, addr)?;
            let server_name = if security.flags.camouflage_config().server_name.is_empty() {
                addr.ip().to_string()
            } else {
                security.flags.camouflage_config().server_name.clone()
            };
            let connecting =
                match endpoint.connect_with(client_config(security.flags)?, addr, &server_name) {
                    Ok(connecting) => connecting,
                    Err(ConnectError::EndpointStopping) => {
                        self.remove_endpoint(&endpoint);
                        endpoint_stopping_retries += 1;
                        if endpoint_stopping_retries > max_endpoint_stopping_retries {
                            return Err(anyhow::Error::new(ConnectError::EndpointStopping)
                                .context(format!("failed to create connection to {}", addr))
                                .into());
                        }
                        continue;
                    }
                    Err(error) => {
                        return Err(anyhow::Error::new(error)
                            .context(format!("failed to create connection to {}", addr))
                            .into());
                    }
                };
            let connection = connecting
                .await
                .with_context(|| format!("failed to connect Noise-protected QUIC to {addr}"))?;
            ensure_local_allowed(&policy, endpoint.local_addr()?)?;
            ensure_remote_allowed(&policy, connection.remote_address())?;
            let dedicated_socket = cfg!(target_os = "macos") && source.port() == 0;
            return Ok((endpoint, connection, false, dedicated_socket));
        }
    }

    async fn connect_with_ip_version(
        &self,
        addr: SocketAddr,
        ip_version: IpVersion,
        socket_mark: Option<u32>,
        security: QuicConnectSecurity<'_>,
    ) -> Result<(Endpoint, Connection, bool, bool), TunnelError> {
        let max_endpoint_stopping_retries = self.client_pool(ip_version).len().saturating_add(1);
        let mut endpoint_stopping_retries = 0;

        loop {
            let endpoint = self.client_endpoint(ip_version, socket_mark, addr)?;
            let server_name = if security.flags.camouflage_config().server_name.is_empty() {
                addr.ip().to_string()
            } else {
                security.flags.camouflage_config().server_name.clone()
            };
            let connecting =
                match endpoint.connect_with(client_config(security.flags)?, addr, &server_name) {
                    Ok(connecting) => connecting,
                    Err(ConnectError::EndpointStopping) => {
                        let local_addr = endpoint.local_addr().ok();
                        let removed = self.remove_endpoint(&endpoint);
                        endpoint_stopping_retries += 1;
                        tracing::warn!(
                            ?addr,
                            ?local_addr,
                            removed,
                            "removed stopped quic endpoint and retry connect"
                        );
                        if endpoint_stopping_retries > max_endpoint_stopping_retries {
                            return Err(anyhow::Error::new(ConnectError::EndpointStopping)
                                .context(format!("failed to create connection to {}", addr))
                                .into());
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(anyhow::Error::new(e)
                            .context(format!("failed to create connection to {}", addr))
                            .into());
                    }
                };
            let connection = connecting
                .await
                .with_context(|| format!("failed to connect Noise-protected QUIC to {addr}"))?;

            return Ok((endpoint, connection, false, cfg!(target_os = "macos")));
        }
    }
}
//endregion

#[derive(Default)]
struct QuicIoObserved {
    tx_ios: AtomicU64,
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    rx_ios: AtomicU64,
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
}

impl QuicIoObserved {
    fn record(
        &self,
        telemetry: &DataplaneTelemetry,
        tx_ios: u64,
        tx_datagrams: u64,
        tx_bytes: u64,
        rx_ios: u64,
        rx_datagrams: u64,
        rx_bytes: u64,
    ) {
        telemetry.record_io(
            DataplaneIo::QuicUdpSend,
            counter_delta(&self.tx_ios, tx_ios),
            counter_delta(&self.tx_datagrams, tx_datagrams),
            counter_delta(&self.tx_bytes, tx_bytes),
        );
        telemetry.record_io(
            DataplaneIo::QuicUdpReceive,
            counter_delta(&self.rx_ios, rx_ios),
            counter_delta(&self.rx_datagrams, rx_datagrams),
            counter_delta(&self.rx_bytes, rx_bytes),
        );
    }
}

fn counter_delta(counter: &AtomicU64, current: u64) -> usize {
    let previous = counter.swap(current, Ordering::Relaxed);
    usize::try_from(current.saturating_sub(previous)).unwrap_or(usize::MAX)
}

struct ConnWrapper {
    conn: Connection,
    telemetry: Arc<DataplaneTelemetry>,
    io_observed: QuicIoObserved,
    migration_policy: Arc<QuicMigrationPolicy>,
    migration_rejections: crate::common::stats_manager::CounterHandle,
    observed_migration_rejections: AtomicU64,
    expired_datagrams: crate::common::stats_manager::CounterHandle,
    observed_expired_datagrams: AtomicU64,
    _memory_permit: Option<ProcessMemoryPermit>,
    _source_permit: Option<QuicSourcePermit>,
    _endpoint_manager: Option<Arc<QuicEndpointManager>>,
    _endpoint_owner: Option<Endpoint>,
}

impl ConnWrapper {
    fn record_io_stats(&self, stats: &quinn::ConnectionStats) {
        if stats.path.datagram_expired_packets
            != self.observed_expired_datagrams.load(Ordering::Relaxed)
        {
            self.expired_datagrams.add(counter_delta(
                &self.observed_expired_datagrams,
                stats.path.datagram_expired_packets,
            ) as u64);
        }
        if stats.path.migration_rejections
            != self.observed_migration_rejections.load(Ordering::Relaxed)
        {
            let rejected = counter_delta(
                &self.observed_migration_rejections,
                stats.path.migration_rejections,
            );
            if rejected != 0 {
                self.migration_rejections.add(rejected as u64);
            }
        }
        self.io_observed.record(
            self.telemetry.as_ref(),
            stats.udp_tx.ios,
            stats.udp_tx.datagrams,
            stats.udp_tx.bytes,
            stats.udp_rx.ios,
            stats.udp_rx.datagrams,
            stats.udp_rx.bytes,
        );
    }
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.record_io_stats(&self.conn.stats());
        self.conn.close(0u32.into(), b"done");
    }
}

static QUIC_STATS_INTERVAL: OnceLock<Option<Duration>> = OnceLock::new();

fn quic_stats_interval_from(value: Option<&str>) -> Option<Duration> {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|milliseconds| *milliseconds > 0)
        .map(Duration::from_millis)
}

fn quic_stats_interval() -> Option<Duration> {
    *QUIC_STATS_INTERVAL.get_or_init(|| {
        // Verbose per-path dumps are opt-in. Aggregate I/O counters stay live.
        quic_stats_interval_from(
            std::env::var("LOWTIER_QUIC_STATS_INTERVAL_MS")
                .ok()
                .as_deref(),
        )
    })
}

fn quic_observer_delay(active: bool, previous: Duration, diagnostic: Option<Duration>) -> Duration {
    if let Some(period) = diagnostic {
        period.min(Duration::from_secs(1))
    } else if active {
        Duration::from_secs(1)
    } else {
        previous.saturating_mul(2).min(Duration::from_secs(8))
    }
}

fn observe_quic_path(connection: &Arc<ConnWrapper>) {
    let log_period = quic_stats_interval();
    let tick_period = log_period
        .map(|period| period.min(Duration::from_secs(1)))
        .unwrap_or(Duration::from_secs(1));
    let connection = Arc::downgrade(connection);
    tokio::spawn(async move {
        let mut delay = tick_period;
        let mut previous_datagrams = (0, 0);
        let mut next_log = log_period.map(|period| Instant::now() + period);
        loop {
            tokio::time::sleep(delay).await;
            let Some(connection) = connection.upgrade() else {
                break;
            };
            let stats = connection.conn.stats();
            connection.record_io_stats(&stats);
            let datagrams = (stats.udp_tx.datagrams, stats.udp_rx.datagrams);
            delay = quic_observer_delay(datagrams != previous_datagrams, delay, log_period);
            previous_datagrams = datagrams;

            let now = Instant::now();
            let should_log = next_log.is_some_and(|deadline| now >= deadline);
            if should_log {
                tracing::warn!(
                    target: "CORE::TUNNEL::QUIC_PATH",
                    connection = connection.conn.stable_id(),
                    remote = %connection.conn.remote_address(),
                    migration_rejections = stats.path.migration_rejections,
                    tx_datagrams = stats.udp_tx.datagrams,
                    tx_bytes = stats.udp_tx.bytes,
                    tx_ios = stats.udp_tx.ios,
                    rx_datagrams = stats.udp_rx.datagrams,
                    rx_bytes = stats.udp_rx.bytes,
                    rx_ios = stats.udp_rx.ios,
                    tx_frames = stats.frame_tx.datagram,
                    rx_frames = stats.frame_rx.datagram,
                    rtt_us = stats.path.rtt.as_micros(),
                    cwnd = stats.path.cwnd,
                    pacing_rate_bps = stats.path.pacing_rate,
                    app_limited = stats.path.app_limited,
                    in_flight = stats.path.in_flight,
                    congestion_events = stats.path.congestion_events,
                    lost_packets = stats.path.lost_packets,
                    lost_bytes = stats.path.lost_bytes,
                    sent_packets = stats.path.sent_packets,
                    mtu = stats.path.current_mtu,
                    send_buffer_space = connection.conn.datagram_send_buffer_space(),
                    "QUIC path statistics"
                );
                if let Some(period) = log_period {
                    next_log = Some(now + period);
                }
            }
        }
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuicDelivery {
    PlainDatagram,
    ReliableStream,
}

fn select_quic_delivery(packet: &ZCPacket, _max_datagram_size: Option<usize>) -> QuicDelivery {
    let critical_l2 = packet
        .peer_manager_header()
        .is_some_and(|header| header.is_critical_l2_control());
    if packet.is_lossy() && !critical_l2 {
        // Lossy TAP/IP must stay unordered. A PMTUD shrink must not move
        // them onto the reliable CONNECT-IP STREAM (HOL + hidden loss).
        // Oversized packets use DATAGRAM fragments at the current path limit.
        return QuicDelivery::PlainDatagram;
    }
    QuicDelivery::ReliableStream
}

fn put_quic_varint(buffer: &mut BytesMut, value: u64) {
    let mut scratch = [0_u8; 8];
    let length = put_quic_varint_at(&mut scratch, 0, value);
    buffer.extend_from_slice(&scratch[..length]);
}

fn put_quic_varint_at(buffer: &mut [u8], offset: usize, value: u64) -> usize {
    match value {
        0..=63 => {
            buffer[offset] = value as u8;
            1
        }
        64..=16_383 => {
            let encoded = (value as u16) | 0x4000;
            buffer[offset..offset + 2].copy_from_slice(&encoded.to_be_bytes());
            2
        }
        16_384..=1_073_741_823 => {
            let encoded = (value as u32) | 0x8000_0000;
            buffer[offset..offset + 4].copy_from_slice(&encoded.to_be_bytes());
            4
        }
        _ => {
            let encoded = value | 0xc000_0000_0000_0000;
            buffer[offset..offset + 8].copy_from_slice(&encoded.to_be_bytes());
            8
        }
    }
}

fn decode_quic_varint(buffer: &[u8]) -> Option<(u64, usize)> {
    let first = *buffer.first()?;
    let length = 1_usize << (first >> 6);
    if buffer.len() < length {
        return None;
    }
    let value = match length {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([buffer[0] & 0x3f, buffer[1]])),
        4 => u64::from(u32::from_be_bytes([
            buffer[0] & 0x3f,
            buffer[1],
            buffer[2],
            buffer[3],
        ])),
        8 => u64::from_be_bytes([
            buffer[0] & 0x3f,
            buffer[1],
            buffer[2],
            buffer[3],
            buffer[4],
            buffer[5],
            buffer[6],
            buffer[7],
        ]),
        _ => unreachable!(),
    };
    Some((value, length))
}

fn connect_ip_datagram_overhead(stream_id: u64) -> usize {
    let quarter_stream_id = stream_id / 4;
    let quarter_length = match quarter_stream_id {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    quarter_length + 1
}

fn encode_quic_datagram_prefix(
    stream_id: u64,
    context_id: u64,
) -> ([u8; NIC_TUNNEL_HEADROOM], usize) {
    let mut prefix = [0_u8; NIC_TUNNEL_HEADROOM];
    let mut length = put_quic_varint_at(&mut prefix, 0, stream_id / 4);
    length += put_quic_varint_at(&mut prefix, length, context_id);
    (prefix, length)
}

fn encode_quic_datagram(packet: ZCPacket, stream_id: u64) -> Bytes {
    let (prefix, length) = encode_quic_datagram_prefix(stream_id, DATAGRAM_CONTEXT_WHOLE);
    packet.tunnel_payload_with_prefix_into_bytes(&prefix[..length])
}

fn encode_lossy_quic_datagrams(
    packet: ZCPacket,
    stream_id: u64,
    max_size: Option<usize>,
    out: &mut VecDeque<Bytes>,
) {
    let whole = encode_quic_datagram(packet, stream_id);
    let Some(max_size) = max_size else {
        out.push_back(whole);
        return;
    };
    if whole.len() <= max_size {
        out.push_back(whole);
        return;
    }
    let whole_prefix = connect_ip_datagram_overhead(stream_id);
    let payload = &whole[whole_prefix..];
    let (frag_prefix, frag_prefix_len) =
        encode_quic_datagram_prefix(stream_id, DATAGRAM_CONTEXT_FRAGMENT);
    let chunk = max_size.saturating_sub(frag_prefix_len + DATAGRAM_FRAGMENT_HEADER_LEN);
    if chunk == 0 {
        return;
    }
    let total = payload.len().div_ceil(chunk);
    if total == 0 || total > u8::MAX as usize {
        return;
    }
    static FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);
    let id = FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
    for (index, part) in payload.chunks(chunk).enumerate() {
        let mut encoded =
            BytesMut::with_capacity(frag_prefix_len + DATAGRAM_FRAGMENT_HEADER_LEN + part.len());
        encoded.extend_from_slice(&frag_prefix[..frag_prefix_len]);
        encoded.put_u32_le(id);
        encoded.put_u8(index as u8);
        encoded.put_u8(total as u8);
        encoded.extend_from_slice(part);
        out.push_back(encoded.freeze());
    }
}

fn datagram_packet_group(bytes: &Bytes) -> Option<u64> {
    let (_, quarter_length) = decode_quic_varint(bytes)?;
    let (context, context_length) = decode_quic_varint(&bytes[quarter_length..])?;
    if context != DATAGRAM_CONTEXT_FRAGMENT {
        return None;
    }
    let body = bytes.get(quarter_length + context_length..)?;
    Some(u64::from(u32::from_le_bytes(
        body.get(..4)?.try_into().ok()?,
    )))
}

fn packet_from_tunnel_payload(bytes: Bytes, header_length: usize) -> Result<ZCPacket, TunnelError> {
    if bytes.len().saturating_sub(header_length) < PEER_MANAGER_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "QUIC DATAGRAM is too short: {} < {}",
            bytes.len().saturating_sub(header_length),
            PEER_MANAGER_HEADER_SIZE
        )));
    }
    let bytes = bytes
        .try_into_mut()
        .unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
    Ok(ZCPacket::new_from_buf_with_prefix(
        bytes,
        header_length,
        ZCPacketType::DummyTunnel,
    ))
}

#[cfg(test)]
fn decode_quic_datagram(bytes: Bytes, stream_id: u64) -> Result<ZCPacket, TunnelError> {
    match decode_quic_datagram_parts(bytes, stream_id)? {
        DecodedDatagram::Whole(packet) => Ok(packet),
        DecodedDatagram::Fragment { .. } => Err(TunnelError::InvalidPacket(
            "CONNECT-IP DATAGRAM fragment needs reassembly".to_owned(),
        )),
    }
}

enum DecodedDatagram {
    Whole(ZCPacket),
    Fragment {
        id: u32,
        index: u8,
        count: u8,
        payload: Bytes,
    },
}

fn decode_quic_datagram_parts(
    bytes: Bytes,
    stream_id: u64,
) -> Result<DecodedDatagram, TunnelError> {
    let (quarter_stream_id, quarter_length) = decode_quic_varint(&bytes).ok_or_else(|| {
        TunnelError::InvalidPacket("HTTP/3 DATAGRAM has no Quarter Stream ID".to_owned())
    })?;
    let (context_id, context_length) =
        decode_quic_varint(&bytes[quarter_length..]).ok_or_else(|| {
            TunnelError::InvalidPacket("CONNECT-IP DATAGRAM has no Context ID".to_owned())
        })?;
    if quarter_stream_id != stream_id / 4 {
        return Err(TunnelError::InvalidPacket(
            "CONNECT-IP DATAGRAM has an unexpected request".to_owned(),
        ));
    }
    let header_length = quarter_length + context_length;
    match context_id {
        DATAGRAM_CONTEXT_WHOLE => {
            packet_from_tunnel_payload(bytes, header_length).map(DecodedDatagram::Whole)
        }
        DATAGRAM_CONTEXT_FRAGMENT => {
            let body = bytes.get(header_length..).unwrap_or(&[]);
            if body.len() < DATAGRAM_FRAGMENT_HEADER_LEN {
                return Err(TunnelError::InvalidPacket(
                    "CONNECT-IP DATAGRAM fragment is too short".to_owned(),
                ));
            }
            let id = u32::from_le_bytes(body[..4].try_into().unwrap());
            let index = body[4];
            let count = body[5];
            Ok(DecodedDatagram::Fragment {
                id,
                index,
                count,
                payload: bytes.slice(header_length + DATAGRAM_FRAGMENT_HEADER_LEN..),
            })
        }
        _ => Err(TunnelError::InvalidPacket(
            "CONNECT-IP DATAGRAM has an unexpected context".to_owned(),
        )),
    }
}

/// Combines reliable QUIC control frames with the unordered DATAGRAM data
/// lane. Poll preference alternates so a saturated data lane cannot starve
/// control traffic and vice versa.
struct QuicHybridReader {
    reliable: mpsc::Receiver<BatchStreamItem>,
    connection: Arc<ConnWrapper>,
    datagrams: Pin<Box<quinn::ReadDatagrams>>,
    connect_stream_id: u64,
    poll_datagram_first: bool,
    fragments: DatagramFragments,
}

impl QuicHybridReader {
    fn new(
        reliable: mpsc::Receiver<BatchStreamItem>,
        connection: Arc<ConnWrapper>,
        connect_stream_id: u64,
    ) -> Self {
        let batch_limit = packet_batch_limit();
        let datagrams = Box::pin(
            connection
                .conn
                .read_datagrams(Vec::with_capacity(batch_limit), batch_limit),
        );
        Self {
            reliable,
            connection,
            datagrams,
            connect_stream_id,
            poll_datagram_first: true,
            fragments: DatagramFragments::new(),
        }
    }

    fn decode_datagram_batch(&mut self, datagrams: &mut Vec<Bytes>) -> Option<PacketBatch> {
        let _stage =
            self.connection
                .telemetry
                .sample_stage_with_shape(DataplaneStage::QuicReceive, || {
                    (
                        datagrams.len(),
                        datagrams.iter().map(|bytes| bytes.len()).sum::<usize>(),
                    )
                });
        let mut batch = PacketBatch::with_capacity(datagrams.len());
        for bytes in datagrams.drain(..) {
            if let Some(packet) = self.fragments.ingest(bytes, self.connect_stream_id) {
                batch
                    .try_push(packet)
                    .expect("the QUIC receive batch has a fixed bound");
            }
        }
        (!batch.is_empty()).then_some(batch)
    }

    fn poll_datagram(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<BatchStreamItem>> {
        self.fragments.poll_expiry(cx);
        const MAX_INVALID_BATCHES_PER_POLL: usize = 4;
        for _ in 0..MAX_INVALID_BATCHES_PER_POLL {
            match self.datagrams.as_mut().poll(cx) {
                Poll::Pending => {
                    self.fragments.poll_expiry(cx);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(mut datagrams)) => {
                    let batch = self.decode_datagram_batch(&mut datagrams);
                    self.datagrams.as_mut().set(
                        self.connection
                            .conn
                            .read_datagrams(datagrams, packet_batch_limit()),
                    );
                    if let Some(batch) = batch {
                        return Poll::Ready(Some(Ok(batch)));
                    }
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Some(Err(TunnelError::Anyhow(
                        anyhow::Error::new(error).context("read QUIC DATAGRAM batch failed"),
                    ))));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_reliable(&mut self, cx: &mut TaskContext<'_>) -> Poll<Option<BatchStreamItem>> {
        self.reliable.poll_recv(cx)
    }
}

impl Stream for QuicHybridReader {
    type Item = BatchStreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let datagram_first = self.poll_datagram_first;
        self.poll_datagram_first = !datagram_first;

        if datagram_first {
            if let Poll::Ready(item) = self.poll_datagram(cx) {
                return Poll::Ready(item);
            }
            self.poll_reliable(cx)
        } else {
            if let Poll::Ready(item) = self.poll_reliable(cx) {
                return Poll::Ready(item);
            }
            self.poll_datagram(cx)
        }
    }
}

struct QuicHybridWriter {
    connection: Arc<ConnWrapper>,
    pending_datagrams: Option<VecDeque<Bytes>>,
    pending_datagrams_since: Option<std::time::Instant>,
    pending_datagram_send: Option<DatagramBatchSend>,
    spare_datagrams: VecDeque<Bytes>,
    spare_datagram_send: Option<DatagramBatchSend>,
    reliable_tx: Option<mpsc::Sender<ReliableWriteRequest>>,
    pending_reliable: Option<ReliableWriteRequest>,
    pending_reliable_since: Option<Instant>,
    reliable_reserve: Option<ReliableReserve>,
    reliable_completion: Option<oneshot::Receiver<Result<(), TunnelError>>>,
    reliable_task: Option<JoinHandle<Result<(), TunnelError>>>,
    graceful_close: bool,
    connect_stream_id: u64,
}

struct ReliableWriteRequest {
    batch: PacketBatch,
    completed: oneshot::Sender<Result<(), TunnelError>>,
}

type ReliableReserve = Pin<
    Box<
        dyn Future<
                Output = Result<
                    mpsc::OwnedPermit<ReliableWriteRequest>,
                    mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;
type DatagramBatchSend = tokio_util::sync::ReusableBoxFuture<
    'static,
    (
        Result<(), quinn::SendDatagramError>,
        VecDeque<Bytes>,
        Option<Instant>,
        usize,
        usize,
    ),
>;

const RELIABLE_LANE_QUEUE_BATCHES: usize = 1;

fn poll_reliable_reservation(
    reservation: &mut Option<ReliableReserve>,
    cx: &mut TaskContext<'_>,
) -> Poll<Result<mpsc::OwnedPermit<ReliableWriteRequest>, SinkError>> {
    let reserve = reservation
        .as_mut()
        .expect("the reliable reservation exists before polling");
    match reserve.as_mut().poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
            *reservation = None;
            Poll::Ready(Ok(permit))
        }
        Poll::Ready(Err(_)) => {
            *reservation = None;
            Poll::Ready(Err(TunnelError::InternalError(
                "reliable QUIC lane stopped".to_owned(),
            )))
        }
    }
}

fn clone_reliable_error(error: &TunnelError) -> TunnelError {
    TunnelError::InternalError(format!("reliable QUIC lane failed: {error}"))
}

async fn send_reliable_lane_error(incoming: mpsc::Sender<BatchStreamItem>, error: TunnelError) {
    let _ = incoming.send(Err(error)).await;
}

fn connection_closed_error(error: quinn::ConnectionError, context: &'static str) -> TunnelError {
    anyhow::Error::new(error).context(context).into()
}

const LOWTIER_PACKET_CAPSULE_TYPE: u64 = 0x4554;

fn encode_packet_capsule(packet: ZCPacket) -> Result<Bytes, TunnelError> {
    let body = packet.tunnel_payload_into_bytes();
    if body.len() < PEER_MANAGER_HEADER_SIZE || body.len() > QUIC_RELIABLE_MAX_PACKET_SIZE {
        return Err(TunnelError::InvalidPacket(
            "CONNECT-IP capsule packet has an invalid length".to_owned(),
        ));
    }
    let mut capsule = BytesMut::with_capacity(16 + body.len());
    put_quic_varint(&mut capsule, LOWTIER_PACKET_CAPSULE_TYPE);
    put_quic_varint(&mut capsule, body.len() as u64);
    capsule.extend_from_slice(&body);
    Ok(capsule.freeze())
}

fn decode_packet_capsules(buffer: &mut BytesMut) -> Result<PacketBatch, TunnelError> {
    let mut batch = PacketBatch::new();
    while batch.len() < MAX_PACKET_BATCH_SIZE {
        let Some((capsule_type, type_length)) = decode_quic_varint(buffer) else {
            break;
        };
        let Some((payload_length, length_length)) = decode_quic_varint(&buffer[type_length..])
        else {
            break;
        };
        let payload_length = usize::try_from(payload_length).map_err(|_| {
            TunnelError::InvalidPacket("CONNECT-IP capsule length is too large".to_owned())
        })?;
        if payload_length > QUIC_RELIABLE_MAX_PACKET_SIZE {
            return Err(TunnelError::InvalidPacket(
                "CONNECT-IP capsule exceeds the packet limit".to_owned(),
            ));
        }
        let header_length = type_length + length_length;
        let total_length = header_length.checked_add(payload_length).ok_or_else(|| {
            TunnelError::InvalidPacket("CONNECT-IP capsule length overflow".to_owned())
        })?;
        if buffer.len() < total_length {
            break;
        }
        buffer.advance(header_length);
        let payload = buffer.split_to(payload_length);
        if capsule_type != LOWTIER_PACKET_CAPSULE_TYPE {
            continue;
        }
        if payload.len() < PEER_MANAGER_HEADER_SIZE {
            return Err(TunnelError::InvalidPacket(
                "CONNECT-IP packet capsule is too short".to_owned(),
            ));
        }
        batch
            .try_push(ZCPacket::new_from_buf(payload, ZCPacketType::DummyTunnel))
            .expect("the CONNECT-IP capsule batch checks its bound");
    }
    Ok(batch)
}

async fn run_http3_reliable_lane(
    connection: Connection,
    mut stream: Box<dyn ConnectIpRequestStream>,
    mut outgoing: mpsc::Receiver<ReliableWriteRequest>,
    incoming: mpsc::Sender<BatchStreamItem>,
    writer_done: oneshot::Sender<Result<(), TunnelError>>,
) -> Result<(), TunnelError> {
    let mut receive_buffer = BytesMut::with_capacity(QUIC_RELIABLE_INITIAL_BUFFER_SIZE);
    let mut outgoing_open = true;
    let mut incoming_open = true;
    let mut writer_done = Some(writer_done);
    loop {
        tokio::select! {
            request = outgoing.recv(), if outgoing_open => {
                let Some(request) = request else {
                    outgoing_open = false;
                    let result = stream.finish().await;
                    if let Some(done) = writer_done.take() {
                        let _ = done.send(result.as_ref().map(|_| ()).map_err(clone_reliable_error));
                    }
                    result?;
                    if !incoming_open {
                        return Ok(());
                    }
                    continue;
                };
                let mut result = Ok(());
                for packet in request.batch {
                    match encode_packet_capsule(packet) {
                        Ok(capsule) => {
                            if let Err(error) = stream.send_data(capsule).await {
                                result = Err(error);
                                break;
                            }
                        }
                        Err(error) => {
                            result = Err(error);
                            break;
                        }
                    }
                }
                let failed = result.as_ref().err().map(clone_reliable_error);
                let _ = request.completed.send(result);
                if let Some(error) = failed {
                    return Err(error);
                }
            }
            data = stream.recv_data(), if incoming_open => {
                let Some(data) = data? else {
                    incoming_open = false;
                    if !outgoing_open {
                        return Ok(());
                    }
                    continue;
                };
                if receive_buffer.len().saturating_add(data.len())
                    > QUIC_RELIABLE_MAX_PACKET_SIZE + 16
                {
                    return Err(TunnelError::InvalidPacket(
                        "CONNECT-IP capsule receive buffer is full".to_owned(),
                    ));
                }
                receive_buffer.extend_from_slice(&data);
                let batch = decode_packet_capsules(&mut receive_buffer)?;
                if !batch.is_empty() && incoming.send(Ok(batch)).await.is_err() {
                    return Ok(());
                }
            }
            error = connection.closed() => {
                return Err(connection_closed_error(
                    error,
                    "QUIC connection closed during CONNECT-IP operation",
                ));
            }
        }
    }
}

impl QuicHybridWriter {
    fn new(
        reliable_tx: mpsc::Sender<ReliableWriteRequest>,
        reliable_task: JoinHandle<Result<(), TunnelError>>,
        connection: Arc<ConnWrapper>,
        connect_stream_id: u64,
    ) -> Self {
        Self {
            connection,
            pending_datagrams: Some(VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE)),
            pending_datagrams_since: None,
            pending_datagram_send: None,
            spare_datagrams: VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE),
            spare_datagram_send: None,
            reliable_tx: Some(reliable_tx),
            pending_reliable: None,
            pending_reliable_since: None,
            reliable_reserve: None,
            reliable_completion: None,
            reliable_task: Some(reliable_task),
            graceful_close: false,
            connect_stream_id,
        }
    }

    fn take_datagram_batch(
        queued: &mut VecDeque<Bytes>,
        spare: &mut VecDeque<Bytes>,
    ) -> VecDeque<Bytes> {
        let mut datagrams = std::mem::take(spare);
        debug_assert!(datagrams.is_empty());
        let batch_limit = packet_batch_limit();
        if queued.len() <= batch_limit {
            // The common case rotates storage without moving its entries.
            std::mem::swap(&mut datagrams, queued);
        } else {
            // Fragmentation can expand one input batch past the send bound.
            let mut end = batch_limit;
            if let Some(group) = datagram_packet_group(&queued[end - 1]) {
                if datagram_packet_group(&queued[end]) == Some(group) {
                    while end > 0 && datagram_packet_group(&queued[end - 1]) == Some(group) {
                        end -= 1;
                    }
                    if end == 0 {
                        end = queued
                            .iter()
                            .take_while(|data| datagram_packet_group(data) == Some(group))
                            .count();
                    }
                }
            }
            datagrams.extend(queued.drain(..end));
        }
        datagrams
    }

    fn begin_datagram_flush(&mut self) {
        if self.pending_datagram_send.is_some()
            || self
                .pending_datagrams
                .as_ref()
                .is_none_or(VecDeque::is_empty)
        {
            return;
        }
        let queued = self
            .pending_datagrams
            .as_mut()
            .expect("the pending QUIC batch is available before a flush");
        let datagrams = Self::take_datagram_batch(queued, &mut self.spare_datagrams);
        let queued_at = self
            .pending_datagrams_since
            .unwrap_or_else(std::time::Instant::now);
        if queued.is_empty() {
            self.pending_datagrams_since = None;
        }
        let packet_count = datagrams.len();
        let byte_count = datagrams.iter().map(Bytes::len).sum::<usize>();
        let started = DataplaneTelemetry::sample_start();
        // One driver owns UDP submission for data and control packets. A
        // blocked socket must not let newer control packets overtake sealed data.
        let connection = self.connection.conn.clone();
        let future = async move {
            let (result, datagrams) = connection
                .send_datagrams_wait_grouped(datagrams, queued_at, datagram_packet_group)
                .await;
            (result, datagrams, started, packet_count, byte_count)
        };
        // This async expression has a stable layout, so set reuses its box.
        self.pending_datagram_send = Some(match self.spare_datagram_send.take() {
            Some(mut send) => {
                send.set(future);
                send
            }
            None => DatagramBatchSend::new(future),
        });
    }

    fn requeue_datagrams_after_send(
        result: Result<(), quinn::SendDatagramError>,
        mut unsent: VecDeque<Bytes>,
        mut newly_queued: VecDeque<Bytes>,
    ) -> (Result<(), SinkError>, VecDeque<Bytes>, VecDeque<Bytes>) {
        // Quinn removes a datagram that returns `TooLarge` before it returns the
        // remaining queue. Drop only that offending datagram. Preserve all later
        // datagrams before packets that arrived while the send was pending.
        if unsent.is_empty() {
            std::mem::swap(&mut unsent, &mut newly_queued);
        } else {
            unsent.append(&mut newly_queued);
        }
        let result = match result {
            Ok(()) | Err(quinn::SendDatagramError::TooLarge) => Ok(()),
            Err(error) => Err(TunnelError::Anyhow(
                anyhow::Error::new(error).context("send QUIC DATAGRAM batch failed"),
            )),
        };
        (result, unsent, newly_queued)
    }

    fn poll_datagram_queue(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        let Some(send) = self.pending_datagram_send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match send.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((result, datagrams, started, packet_count, byte_count)) => {
                self.connection.telemetry.record_stage_sample(
                    DataplaneStage::QuicSend,
                    started,
                    packet_count,
                    byte_count,
                );
                let queued = self.pending_datagrams.take().unwrap_or_default();
                let (result, datagrams, spare) =
                    Self::requeue_datagrams_after_send(result, datagrams, queued);
                self.pending_datagrams = Some(datagrams);
                self.spare_datagrams = spare;
                self.spare_datagram_send = self.pending_datagram_send.take();
                match result {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
        }
    }

    fn poll_ready_queues(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        match self.poll_reliable_queue(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if self.pending_reliable.is_some() {
            return Poll::Pending;
        }
        match self.poll_reliable_completion(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        loop {
            if self
                .pending_datagrams
                .as_ref()
                .is_none_or(VecDeque::is_empty)
            {
                return Poll::Ready(Ok(()));
            }
            self.begin_datagram_flush();
            match self.poll_datagram_queue(cx) {
                Poll::Pending
                    if self.pending_datagram_send.is_some()
                        && self
                            .pending_datagrams
                            .as_ref()
                            .is_none_or(VecDeque::is_empty) =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // A completed send can move staged datagrams back to the
                // pending queue. Start that queue before the sink is ready.
                Poll::Ready(Ok(())) => {}
            }
        }
    }

    fn poll_flush_queues(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        match self.poll_reliable_queue(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        loop {
            self.begin_datagram_flush();
            match self.poll_datagram_queue(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let staged = self
                        .pending_datagrams
                        .as_ref()
                        .is_some_and(|datagrams| !datagrams.is_empty());
                    if staged || self.pending_datagram_send.is_some() {
                        continue;
                    }
                    return self.poll_reliable_completion(cx);
                }
            }
        }
    }

    fn poll_reliable_completion(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), SinkError>> {
        let Some(completion) = self.reliable_completion.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(completion).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                self.reliable_completion = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.reliable_completion = None;
                Poll::Ready(Err(TunnelError::InternalError(
                    "reliable QUIC lane stopped before batch completion".to_owned(),
                )))
            }
        }
    }

    fn poll_reliable_queue(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), SinkError>> {
        if self.pending_reliable.is_none() {
            return Poll::Ready(Ok(()));
        }
        if self.reliable_reserve.is_none() {
            let Some(sender) = self.reliable_tx.as_ref() else {
                return Poll::Ready(Err(TunnelError::InternalError(
                    "reliable QUIC lane is closed".to_owned(),
                )));
            };
            self.reliable_reserve = Some(Box::pin(sender.clone().reserve_owned()));
        }

        match poll_reliable_reservation(&mut self.reliable_reserve, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                let request = self.pending_reliable.take().unwrap();
                let _ = self.pending_reliable_since.take();
                permit.send(request);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}

impl Drop for QuicHybridWriter {
    fn drop(&mut self) {
        if !self.graceful_close {
            self.connection
                .conn
                .close(0_u32.into(), b"QUIC writer closed");
        }
        if let Some(task) = self.reliable_task.take() {
            task.abort();
        }
    }
}

impl Sink<PacketBatch> for QuicHybridWriter {
    type Error = SinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_ready_queues(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        let writer = self.as_mut().get_mut();
        let maximum = writer.connection.conn.max_datagram_size();
        let mut reliable = PacketBatch::with_capacity(batch.len());
        if writer.pending_reliable.is_some() {
            return Err(TunnelError::InternalError(
                "QUIC batch started without sink readiness".to_owned(),
            ));
        }
        let datagrams = writer.pending_datagrams.as_mut().ok_or_else(|| {
            TunnelError::InternalError(
                "QUIC DATAGRAM batch started while a flush is active".to_owned(),
            )
        })?;
        if !datagrams.is_empty() {
            return Err(TunnelError::InternalError(
                "QUIC batch started without sink readiness".to_owned(),
            ));
        }
        writer.pending_datagrams_since = Some(std::time::Instant::now());

        for packet in batch {
            match select_quic_delivery(&packet, maximum) {
                QuicDelivery::PlainDatagram => {
                    encode_lossy_quic_datagrams(
                        packet,
                        writer.connect_stream_id,
                        maximum,
                        datagrams,
                    );
                }
                QuicDelivery::ReliableStream => reliable
                    .try_push(packet)
                    .expect("the reliable subset cannot exceed its input batch"),
            }
        }

        if reliable.is_empty() {
            return Ok(());
        }
        let (completed, completion) = oneshot::channel();
        let request = ReliableWriteRequest {
            batch: reliable,
            completed,
        };
        let Some(sender) = writer.reliable_tx.as_ref() else {
            return Err(TunnelError::InternalError(
                "reliable QUIC lane is closed".to_owned(),
            ));
        };
        match sender.try_send(request) {
            Ok(()) => {
                writer.reliable_completion = Some(completion);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(request)) => {
                writer.pending_reliable = Some(request);
                writer.reliable_completion = Some(completion);
                if writer.pending_reliable_since.is_none() {
                    writer.pending_reliable_since = Some(Instant::now());
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TunnelError::InternalError(
                "reliable QUIC lane stopped".to_owned(),
            )),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_flush_queues(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().get_mut().poll_flush_queues(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        let writer = self.as_mut().get_mut();
        writer.reliable_tx.take();
        let Some(task) = writer.reliable_task.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                writer.reliable_task = None;
                writer.graceful_close = result.is_ok();
                Poll::Ready(result)
            }
            Poll::Ready(Err(error)) => {
                writer.reliable_task = None;
                Poll::Ready(Err(TunnelError::Anyhow(anyhow::Error::new(error))))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_connect_ip_tunnel(
    connection: Connection,
    stream: Box<dyn ConnectIpRequestStream>,
    connect_stream_id: u64,
    info: TunnelInfo,
    transport_authenticated: bool,
    memory_permit: Option<ProcessMemoryPermit>,
    source_permit: Option<QuicSourcePermit>,
    endpoint_manager: Option<Arc<QuicEndpointManager>>,
    endpoint_owner: Option<Endpoint>,
    global_ctx: ArcGlobalCtx,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let transport_binding = derive_transport_binding(&connection)?;
    let path_state = Arc::new(super::TunnelPathState {
        peer_authenticated: std::sync::atomic::AtomicBool::new(false),
        info: RwLock::new(info.clone()),
    });
    let migration_policy = Arc::new(QuicMigrationPolicy::new(&global_ctx, path_state.clone()));
    connection.set_path_policy(migration_policy.clone());
    let connection = Arc::new(ConnWrapper {
        conn: connection,
        telemetry: global_ctx.dataplane_telemetry().clone(),
        io_observed: QuicIoObserved::default(),
        migration_policy,
        migration_rejections: global_ctx
            .stats_manager()
            .get_simple_counter(crate::common::stats_manager::MetricName::QuicMigrationsRejected),
        observed_migration_rejections: AtomicU64::new(0),
        expired_datagrams: global_ctx
            .stats_manager()
            .get_simple_counter(crate::common::stats_manager::MetricName::QuicDatagramsExpired),
        observed_expired_datagrams: AtomicU64::new(0),
        _memory_permit: memory_permit,
        _source_permit: source_permit,
        _endpoint_manager: endpoint_manager,
        _endpoint_owner: endpoint_owner,
    });
    if connection.conn.side().is_client()
        && let Some(manager) = &connection._endpoint_manager
    {
        let mut paths = manager.client_paths.lock();
        paths.retain(|path| path.strong_count() != 0);
        paths.push(Arc::downgrade(&connection));
    }
    observe_quic_path(&connection);
    let (reliable_tx, reliable_outgoing) = mpsc::channel(RELIABLE_LANE_QUEUE_BATCHES);
    let (reliable_incoming, reliable_rx) = mpsc::channel(RELIABLE_LANE_QUEUE_BATCHES);
    let (writer_done_tx, writer_done_rx) = oneshot::channel();
    let supervisor_connection = connection.conn.clone();
    tokio::spawn(async move {
        let result = run_http3_reliable_lane(
            supervisor_connection,
            stream,
            reliable_outgoing,
            reliable_incoming.clone(),
            writer_done_tx,
        )
        .await;
        if let Err(error) = result {
            send_reliable_lane_error(reliable_incoming, error).await;
        }
    });
    let writer_task = tokio::spawn(async move {
        writer_done_rx.await.unwrap_or_else(|_| {
            Err(TunnelError::InternalError(
                "CONNECT-IP supervisor stopped".to_owned(),
            ))
        })
    });
    Ok(Box::new(
        BatchTunnelWrapper::new_with_transport_authentication_and_binding(
            QuicHybridReader::new(reliable_rx, connection.clone(), connect_stream_id),
            QuicHybridWriter::new(reliable_tx, writer_task, connection, connect_stream_id),
            Some(info),
            transport_authenticated,
            Some(transport_binding),
        )
        .with_path_state(path_state),
    ))
}

pub struct QuicTunnelListener {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    endpoint: Option<Endpoint>,
    endpoint_manager: Option<Arc<QuicEndpointManager>>,
    pending_state: std::sync::Mutex<PendingQuicAcceptState>,
}

const MAX_QUIC_DECOY_FLOWS: usize = 4096;
const QUIC_DECOY_FLOW_IDLE: Duration = Duration::from_secs(300);
const QUIC_DECOY_PACKET_BYTES: usize = 65535;
const QUIC_ROUTING_REPLAY_RETENTION: Duration = Duration::from_secs(900);
const MAX_QUIC_ROUTING_REPLAYS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicSocketRoute {
    Local,
    Decoy,
}

#[derive(Debug)]
struct QuicSocketRouteEntry {
    route: QuicSocketRoute,
    last_seen_seconds: AtomicU64,
}

#[derive(Debug)]
struct QuicRoutingReplayState {
    markers: HashMap<[u8; QUIC_ROUTING_CID_BYTES], Instant>,
    last_cleanup: Instant,
}

#[derive(Debug)]
struct QuicDecoyPacket {
    client: SocketAddr,
    server_ip: Option<IpAddr>,
    bytes: Bytes,
}

#[derive(Debug)]
struct QuicDecoySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    routes: Arc<dashmap::DashMap<SocketAddr, QuicSocketRouteEntry>>,
    secret: Arc<[u8]>,
    server_name: Option<Arc<str>>,
    replay: ParkingMutex<QuicRoutingReplayState>,
    decoy_tx: mpsc::Sender<QuicDecoyPacket>,
    last_route_cleanup_seconds: AtomicU64,
}

impl QuicDecoySocket {
    fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        upstream: SocketAddr,
        secret: Arc<[u8]>,
        socket_mark: Option<u32>,
        server_name: Option<Arc<str>>,
    ) -> Arc<Self> {
        let routes = Arc::new(dashmap::DashMap::new());
        // Keep unauthenticated ingress bounded independently of VPN routing.
        let (decoy_tx, decoy_rx) = mpsc::channel(64);
        tokio::spawn(run_quic_decoy_relays(
            inner.clone(),
            upstream,
            socket_mark,
            routes.clone(),
            decoy_rx,
        ));
        Arc::new(Self {
            inner,
            routes,
            secret,
            server_name,
            replay: ParkingMutex::new(QuicRoutingReplayState {
                markers: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            decoy_tx,
            last_route_cleanup_seconds: AtomicU64::new(0),
        })
    }

    fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn route(&self, client: SocketAddr, packet: &[u8]) -> Option<QuicSocketRoute> {
        let now_seconds = Self::now_seconds();
        if let Some(entry) = self.routes.get(&client) {
            entry
                .last_seen_seconds
                .store(now_seconds, Ordering::Relaxed);
            return Some(entry.route);
        }
        // Rebinding changes the tuple but keeps the connection ID. Quinn checks the
        // ID and packet keys without allocating a route or an upstream socket.
        // Unknown IDs can only elicit Quinn's rate-limited, smaller stateless reset.
        if packet.first().is_some_and(|first| first & 0x80 == 0) {
            return Some(QuicSocketRoute::Local);
        }
        let last_cleanup = self.last_route_cleanup_seconds.load(Ordering::Relaxed);
        if now_seconds.saturating_sub(last_cleanup) >= 60
            && self
                .last_route_cleanup_seconds
                .compare_exchange(
                    last_cleanup,
                    now_seconds,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.routes.retain(|_, entry| {
                now_seconds.saturating_sub(entry.last_seen_seconds.load(Ordering::Relaxed))
                    < QUIC_DECOY_FLOW_IDLE.as_secs()
            });
        }
        if self.routes.len() >= MAX_QUIC_DECOY_FLOWS {
            return None;
        }

        let marker = valid_quic_routing_marker(packet, &self.secret, SystemTime::now());
        let route = if marker.is_some_and(|marker| self.admit_marker(marker)) {
            QuicSocketRoute::Local
        } else if self
            .server_name
            .as_deref()
            .is_some_and(|name| quic_initial_sni_eq(packet, name))
        {
            QuicSocketRoute::Local
        } else if super::decoy::is_quic_initial(packet) {
            QuicSocketRoute::Decoy
        } else {
            // Only QUIC Initial packets can allocate a new upstream socket.
            return None;
        };
        if route == QuicSocketRoute::Local {
            self.routes.insert(
                client,
                QuicSocketRouteEntry {
                    route,
                    last_seen_seconds: AtomicU64::new(now_seconds),
                },
            );
        }
        // Decoy routes are cached only after the relay task admits the flow.
        // Otherwise overflowing the ingress queue could leave thousands of
        // orphan routes and prevent authenticated clients from being admitted.
        Some(route)
    }

    fn admit_marker(&self, marker: [u8; QUIC_ROUTING_CID_BYTES]) -> bool {
        let now = Instant::now();
        let mut replay = self.replay.lock();
        if now.saturating_duration_since(replay.last_cleanup) >= Duration::from_secs(60) {
            replay.markers.retain(|_, seen| {
                now.saturating_duration_since(*seen) < QUIC_ROUTING_REPLAY_RETENTION
            });
            replay.last_cleanup = now;
        }
        if replay.markers.len() >= MAX_QUIC_ROUTING_REPLAYS {
            return false;
        }
        replay.markers.insert(marker, now).is_none()
    }

    fn forward_decoy(&self, meta: quinn::udp::RecvMeta, bytes: &[u8]) {
        let stride = meta.stride.max(1);
        for offset in (0..meta.len).step_by(stride) {
            let end = (offset + stride).min(meta.len);
            let packet = QuicDecoyPacket {
                client: meta.addr,
                server_ip: meta.dst_ip,
                bytes: Bytes::copy_from_slice(&bytes[offset..end]),
            };
            if self.decoy_tx.try_send(packet).is_err() {
                break;
            }
        }
    }

    fn route_received(&self, received: quinn::udp::RecvMeta, bytes: &mut [u8]) -> usize {
        if let Some(entry) = self.routes.get(&received.addr) {
            entry
                .last_seen_seconds
                .store(Self::now_seconds(), Ordering::Relaxed);
            match entry.route {
                QuicSocketRoute::Local => return received.len,
                QuicSocketRoute::Decoy => {
                    self.forward_decoy(received, &bytes[..received.len]);
                    return 0;
                }
            }
        }
        let stride = received.stride.max(1);
        let mut local_len = 0;
        // A GRO buffer can mix established traffic and a new Initial packet.
        for offset in (0..received.len).step_by(stride) {
            let end = (offset + stride).min(received.len);
            match self.route(received.addr, &bytes[offset..end]) {
                Some(QuicSocketRoute::Local) => {
                    if offset != local_len {
                        bytes.copy_within(offset..end, local_len);
                    }
                    local_len += end - offset;
                }
                Some(QuicSocketRoute::Decoy) => {
                    let mut datagram = received;
                    datagram.len = end - offset;
                    datagram.stride = datagram.len;
                    self.forward_decoy(datagram, &bytes[offset..end]);
                }
                None => {}
            }
        }
        local_len
    }
}

impl AsyncUdpSocket for QuicDecoySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        const MAX_DECOY_BATCHES_PER_POLL: usize = 8;
        for _ in 0..MAX_DECOY_BATCHES_PER_POLL {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(count)) => count,
            };
            let mut local_count = 0;
            for index in 0..count {
                let mut received = meta[index];
                let local_len = self.route_received(received, &mut bufs[index]);
                if local_len != 0 {
                    received.len = local_len;
                    if local_count != index {
                        let (before, after) = bufs.split_at_mut(index);
                        before[local_count][..local_len].copy_from_slice(&after[0][..local_len]);
                    }
                    meta[local_count] = received;
                    local_count += 1;
                }
            }
            if local_count != 0 {
                return Poll::Ready(Ok(local_count));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

async fn send_quic_decoy_response(
    public: &Arc<dyn AsyncUdpSocket>,
    poller: &mut Pin<Box<dyn quinn::UdpPoller>>,
    client: SocketAddr,
    server_ip: Option<IpAddr>,
    bytes: &[u8],
) -> std::io::Result<()> {
    let transmit = quinn::udp::Transmit {
        destination: client,
        ecn: None,
        contents: bytes,
        segment_size: None,
        src_ip: server_ip,
    };
    loop {
        match public.try_send(&transmit) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                futures::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn run_quic_decoy_flow(
    public: Arc<dyn AsyncUdpSocket>,
    upstream: SocketAddr,
    socket_mark: Option<u32>,
    client: SocketAddr,
    server_ip: Option<IpAddr>,
    mut incoming: mpsc::Receiver<Bytes>,
    cleanup: mpsc::UnboundedSender<SocketAddr>,
    permit: super::decoy::DecoyPermit,
) {
    let relay = async {
        let socket = bind::<UdpSocket>()
            .addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .maybe_socket_mark(socket_mark)
            .call();
        let Ok(socket) = socket else {
            return;
        };
        if socket.connect(upstream).await.is_err() {
            return;
        }
        let mut poller = public.clone().create_io_poller();
        let mut response = [0_u8; QUIC_DECOY_PACKET_BYTES];
        let mut return_path = super::decoy::QuicReturnPath::default();
        loop {
            let activity = tokio::time::timeout(super::decoy::IDLE_TIMEOUT, async {
                tokio::select! {
                    packet = incoming.recv() => {
                        let Some(packet) = packet else { return false; };
                        // UDP cannot backpressure the sender: excess ingress is
                        // dropped. Only forwarded input earns response credit.
                        if !permit.allow_datagram(packet.len()) {
                            tracing::trace!(?client, length = packet.len(), "decoy ingress limited");
                            return true;
                        }
                        if socket.send(&packet).await.is_err() { return false; }
                        return_path.received(&packet);
                        tracing::trace!(?client, length = packet.len(), ?return_path, "decoy ingress forwarded");
                        true
                    }
                    received = socket.recv(&mut response) => {
                        let Ok(length) = received else { return false; };
                        if !return_path.can_send(length) {
                            tracing::trace!(?client, length, ?return_path, "decoy response amplification limited");
                            return true;
                        }
                        // One pending response, paced without altering datagrams.
                        // The socket and bounded ingress channel absorb bursts;
                        // overload drops instead of growing a delay queue.
                        permit.pace_datagram(length).await;
                        if send_quic_decoy_response(
                            &public,
                            &mut poller,
                            client,
                            server_ip,
                            &response[..length],
                        ).await.is_err() { return false; }
                        return_path.sent(&response[..length]);
                        tracing::trace!(?client, length, ?return_path, "decoy response forwarded");
                        true
                    }
                }
            })
            .await;
            if !matches!(activity, Ok(true)) {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(super::decoy::FLOW_LIFETIME, relay).await;
    let _ = cleanup.send(client);
}

async fn run_quic_decoy_relays(
    public: Arc<dyn AsyncUdpSocket>,
    upstream: SocketAddr,
    socket_mark: Option<u32>,
    routes: Arc<dashmap::DashMap<SocketAddr, QuicSocketRouteEntry>>,
    mut packets: mpsc::Receiver<QuicDecoyPacket>,
) {
    let mut flows: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                if let Some(flow) = flows.get(&packet.client) {
                    let _ = flow.try_send(packet.bytes);
                    continue;
                }
                // Check process-wide/source-IP admission before allocating a
                // socket or task. Rejected sources cannot fill the route table.
                let Some(permit) = super::decoy::process_limiter().admit(packet.client.ip()) else {
                    continue;
                };
                if !super::decoy::is_quic_initial(&packet.bytes) {
                    continue;
                }
                let route = routes.entry(packet.client).or_insert_with(|| QuicSocketRouteEntry {
                    route: QuicSocketRoute::Decoy,
                    last_seen_seconds: AtomicU64::new(QuicDecoySocket::now_seconds()),
                });
                if route.route != QuicSocketRoute::Decoy {
                    // A marked client may have been admitted while this Initial
                    // waited in the queue. Never overwrite its authenticated route.
                    continue;
                }
                drop(route);
                let (flow_tx, flow_rx) = mpsc::channel(4);
                let _ = flow_tx.try_send(packet.bytes);
                tokio::spawn(run_quic_decoy_flow(
                    public.clone(),
                    upstream,
                    socket_mark,
                    packet.client,
                    packet.server_ip,
                    flow_rx,
                    cleanup_tx.clone(),
                    permit,
                ));
                flows.insert(packet.client, flow_tx);
            }
            Some(client) = cleanup_rx.recv() => {
                flows.remove(&client);
                routes.remove_if(&client, |_, entry| entry.route == QuicSocketRoute::Decoy);
            }
        }
    }
}

struct PendingQuicAcceptState {
    pending_accepts: futures::stream::FuturesUnordered<PendingQuicAccept>,
    pending_by_ip: HashMap<IpAddr, usize>,
    admission_limiter: QuicAdmissionLimiter,
}

type PendingQuicAccept = Pin<
    Box<
        dyn Future<Output = (IpAddr, Result<Option<Box<dyn Tunnel>>, TunnelError>)>
            + Send
            + 'static,
    >,
>;

const MAX_PENDING_QUIC_ACCEPTS: usize = 32;
const MAX_PENDING_QUIC_ACCEPTS_PER_IP: usize = 1;
const MAX_QUIC_ADMISSIONS_PER_SECOND: u32 = 64;
const MAX_QUIC_ADMISSIONS_PER_PREFIX_PER_SECOND: u32 = 16;
const MAX_QUIC_ADMISSION_PREFIXES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum QuicSourcePrefix {
    V4(u32),
    V6(u64),
}

impl From<IpAddr> for QuicSourcePrefix {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(u32::from(ip) & 0xffff_ff00),
            IpAddr::V6(ip) => Self::V6((u128::from(ip) >> 64) as u64),
        }
    }
}

#[derive(Debug)]
struct QuicAdmissionWindow {
    started: Instant,
    count: u32,
}

impl QuicAdmissionWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            count: 0,
        }
    }

    fn admit(&mut self, now: Instant, limit: u32) -> bool {
        if now.saturating_duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.count = 0;
        }
        if self.count >= limit {
            return false;
        }
        self.count += 1;
        true
    }
}

#[derive(Debug)]
struct QuicAdmissionLimiter {
    global: QuicAdmissionWindow,
    prefixes: HashMap<QuicSourcePrefix, QuicAdmissionWindow>,
    last_cleanup: Instant,
}

impl QuicAdmissionLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            global: QuicAdmissionWindow::new(now),
            prefixes: HashMap::new(),
            last_cleanup: now,
        }
    }

    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_cleanup) >= Duration::from_secs(60) {
            self.prefixes.retain(|_, window| {
                now.saturating_duration_since(window.started) < Duration::from_secs(60)
            });
            self.last_cleanup = now;
        }
        if !self.global.admit(now, MAX_QUIC_ADMISSIONS_PER_SECOND) {
            return false;
        }
        let prefix = QuicSourcePrefix::from(ip);
        if !self.prefixes.contains_key(&prefix)
            && self.prefixes.len() >= MAX_QUIC_ADMISSION_PREFIXES
        {
            return false;
        }
        self.prefixes
            .entry(prefix)
            .or_insert_with(|| QuicAdmissionWindow::new(now))
            .admit(now, MAX_QUIC_ADMISSIONS_PER_PREFIX_PER_SECOND)
    }
}

impl QuicTunnelListener {
    pub(crate) fn from_discovery_endpoint(
        endpoint: Endpoint,
        global_ctx: ArcGlobalCtx,
    ) -> Result<Self, TunnelError> {
        let mut listener = Self::new(
            super::build_url_from_socket_addr(&endpoint.local_addr()?.to_string(), "quic"),
            global_ctx,
        );
        listener.endpoint = Some(endpoint);
        Ok(listener)
    }

    pub(crate) fn from_punched_socket(
        socket: UdpSocket,
        global_ctx: ArcGlobalCtx,
    ) -> Result<Self, TunnelError> {
        let local = socket.local_addr()?;
        ensure_local_allowed(&global_ctx.get_underlay_policy(), local)?;
        let mut listener = Self::new(
            super::build_url_from_socket_addr(&local.to_string(), "quic"),
            global_ctx.clone(),
        );
        listener.endpoint = Some(punched_endpoint(socket, &global_ctx, true)?);
        Ok(listener)
    }

    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelListener {
            addr,
            global_ctx,
            endpoint: None,
            endpoint_manager: None,
            pending_state: std::sync::Mutex::new(PendingQuicAcceptState {
                pending_accepts: futures::stream::FuturesUnordered::new(),
                pending_by_ip: HashMap::new(),
                admission_limiter: QuicAdmissionLimiter::new(),
            }),
        }
    }

    async fn finish_accept(
        incoming: Incoming,
        initial_remote: SocketAddr,
        global_ctx: ArcGlobalCtx,
        local_url: url::Url,
        memory_permit: ProcessMemoryPermit,
        source_permit: QuicSourcePermit,
        endpoint_manager: Option<Arc<QuicEndpointManager>>,
        endpoint_owner: Option<Endpoint>,
    ) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
        ensure_remote_allowed(&global_ctx.get_underlay_policy(), initial_remote)?;
        let conn = tokio::time::timeout(Duration::from_secs(7), incoming)
            .await
            .context("accept QUIC connection timed out")?
            .with_context(|| "accept QUIC connection failed")?;
        // Noise authenticates the peer after QUIC binds its transcript to the
        // TLS exporter. The ephemeral TLS certificate is not a password verifier.
        let transport_authenticated = false;
        let remote_addr = initial_remote;
        ensure_remote_allowed(&global_ctx.get_underlay_policy(), remote_addr)?;
        let admission = ConnectIpAdmission::from_global_ctx(&global_ctx);
        let fallback_root = match global_ctx
            .config
            .get_flags()
            .camouflage_config()
            .website_root
            .clone()
        {
            root if root.is_empty() => None,
            root => Some(PathBuf::from(root)),
        };
        let activation = tokio::time::timeout(
            Duration::from_secs(7),
            accept_connect_ip_request(&conn, admission.as_ref(), fallback_root.clone()),
        )
        .await
        .map_err(|_| TunnelError::InternalError("CONNECT-IP admission timed out".into()))
        .and_then(|result| result);
        let (connect_stream, connect_stream_id) = match activation {
            Ok(ConnectIpAccept::Tunnel(stream, id)) => (stream, id),
            Ok(ConnectIpAccept::Website(website)) => {
                drop(source_permit);
                let Some(website_permit) = super::decoy::process_limiter().admit(remote_addr.ip())
                else {
                    conn.close(VarInt::from_u32(1), b"website capacity full");
                    return Ok(None);
                };
                let Some(response_memory) = global_ctx
                    .process_memory_governor()
                    .try_reserve_owned(2 * MAX_HTTP3_ORIGIN_FILE_BYTES as usize)
                else {
                    conn.close(VarInt::from_u32(1), b"website memory full");
                    return Ok(None);
                };
                tokio::spawn(async move {
                    let _owners = (
                        memory_permit,
                        response_memory,
                        website_permit,
                        endpoint_manager,
                        endpoint_owner,
                    );
                    let _ = tokio::time::timeout(
                        super::decoy::FLOW_LIFETIME,
                        serve_http3_requests(
                            website.connection,
                            fallback_root,
                            Some(website.first),
                        ),
                    )
                    .await;
                    conn.close(VarInt::from_u32(0), b"website connection complete");
                });
                return Ok(None);
            }
            Err(error) => {
                conn.close(VarInt::from_u32(1), b"CONNECT-IP activation failed");
                return Err(error);
            }
        };

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(local_url.into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
        };

        // The process-wide source permit protects handshake activation only.
        // Keeping it on the live tunnel would allow one established peer to
        // block every other peer behind the same NAT/source IP indefinitely.
        drop(source_permit);
        build_connect_ip_tunnel(
            conn,
            connect_stream,
            connect_stream_id,
            info,
            transport_authenticated,
            Some(memory_permit),
            None,
            endpoint_manager,
            endpoint_owner,
            global_ctx,
        )
        .map(Some)
    }

    fn release_pending_ip(&mut self, ip: IpAddr) {
        let state = self.pending_state.get_mut().unwrap();
        let Some(count) = state.pending_by_ip.get_mut(&ip) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            state.pending_by_ip.remove(&ip);
        }
    }

    fn start_pending_accept(&mut self, incoming: Incoming, remote_addr: SocketAddr) {
        let ip = remote_addr.ip();
        let Some(source_permit) = try_acquire_quic_source(ip) else {
            incoming.refuse();
            tracing::trace!(?ip, "reject QUIC connection because the source is active");
            return;
        };
        let global_ctx = self.global_ctx.clone();
        let Some(memory_permit) = self
            .global_ctx
            .process_memory_governor()
            .try_reserve_connection(QUIC_CONNECTION_MEMORY_CHARGE_BYTES)
        else {
            incoming.refuse();
            self.global_ctx
                .process_memory_governor()
                .record_connection_refusal("quic accept");
            return;
        };
        let local_url = self.local_url();
        let endpoint_manager = self.endpoint_manager.clone();
        let endpoint_owner = self.endpoint.clone();
        let state = self.pending_state.get_mut().unwrap();
        let count = state.pending_by_ip.entry(ip).or_default();
        if *count >= MAX_PENDING_QUIC_ACCEPTS_PER_IP {
            incoming.refuse();
            tracing::warn!(
                ?ip,
                "reject QUIC connection because the pending peer limit is full"
            );
            return;
        }
        *count += 1;
        state.pending_accepts.push(Box::pin(async move {
            let result = Self::finish_accept(
                incoming,
                remote_addr,
                global_ctx,
                local_url,
                memory_permit,
                source_permit,
                endpoint_manager,
                endpoint_owner,
            )
            .await;
            (ip, result)
        }));
    }

    fn handle_completed_accept(
        &mut self,
        completed: (IpAddr, Result<Option<Box<dyn Tunnel>>, TunnelError>),
    ) -> Option<Box<dyn Tunnel>> {
        let (ip, result) = completed;
        self.release_pending_ip(ip);
        match result {
            Ok(tunnel) => tunnel,
            Err(error) => {
                tracing::warn!(?error, ?ip, "QUIC connection activation failed");
                None
            }
        }
    }
}

impl Drop for QuicTunnelListener {
    fn drop(&mut self) {
        let Some(endpoint) = &self.endpoint else {
            return;
        };
        let Ok(local_addr) = endpoint.local_addr() else {
            return;
        };
        if let Some(manager) = &self.endpoint_manager {
            manager.remove_endpoint_by_local_addr(local_addr);
        }
    }
}

#[async_trait::async_trait]
impl TunnelListener for QuicTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let endpoint_manager = QuicEndpointManager::load(&self.global_ctx);
        let flags = self.global_ctx.config.get_flags();
        let endpoint = if flags.camouflage_config().udp_decoy().is_empty() {
            QuicEndpointManager::server(&self.global_ctx, &endpoint_manager, addr)?
        } else {
            let upstream = tokio::net::lookup_host(&flags.camouflage_config().udp_decoy())
                .await
                .with_context(|| {
                    format!(
                        "resolve QUIC decoy upstream {}",
                        flags.camouflage_config().udp_decoy()
                    )
                })?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| {
                    TunnelError::InternalError("QUIC decoy upstream has no IPv4 address".to_owned())
                })?;
            ensure_remote_allowed(&self.global_ctx.get_underlay_policy(), upstream)?;
            QuicEndpointManager::server_with_decoy(
                &endpoint_manager,
                addr,
                upstream,
                Arc::from(
                    flags
                        .camouflage_config()
                        .admission_secret
                        .clone()
                        .into_bytes(),
                ),
                flags
                    .camouflage_config()
                    .sni_routing
                    .then(|| Arc::from(flags.camouflage_config().server_name.as_str())),
            )?
        };
        self.addr
            .set_port(Some(endpoint.local_addr()?.port()))
            .unwrap();
        self.endpoint = Some(endpoint);
        self.endpoint_manager = Some(endpoint_manager);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        loop {
            let endpoint = self.endpoint.as_ref().unwrap().clone();
            let (completed, incoming) = {
                let pending_state = self.pending_state.get_mut().unwrap();
                tokio::select! {
                    completed = pending_state.pending_accepts.next(), if !pending_state.pending_accepts.is_empty() => {
                        (Some(completed), None)
                    }
                    incoming = endpoint.accept() => {
                        (None, Some(incoming))
                    }
                }
            };
            if let Some(completed) = completed
                && let Some(completed) = completed
                && let Some(tunnel) = self.handle_completed_accept(completed)
            {
                return Ok(tunnel);
            }
            if let Some(incoming) = incoming {
                let Some(incoming) = incoming else {
                    return Err(TunnelError::InternalError(
                        "QUIC endpoint stopped accepting connections".to_string(),
                    ));
                };
                let remote = incoming.remote_address();
                if !incoming.remote_address_validated() {
                    if let Err(error) = incoming.retry() {
                        tracing::debug!(
                            ?error,
                            ?remote,
                            "failed to require QUIC address validation"
                        );
                    }
                    continue;
                }
                let remote_ip = remote.ip();
                if !self
                    .pending_state
                    .get_mut()
                    .unwrap()
                    .admission_limiter
                    .admit(remote_ip, Instant::now())
                {
                    tracing::warn!(
                        ?remote_ip,
                        "reject QUIC connection because the admission rate is full"
                    );
                    incoming.refuse();
                    continue;
                }
                if ensure_remote_allowed(&self.global_ctx.get_underlay_policy(), remote).is_err() {
                    incoming.refuse();
                } else if self.pending_state.get_mut().unwrap().pending_accepts.len()
                    >= MAX_PENDING_QUIC_ACCEPTS
                {
                    tracing::warn!(
                        remote = ?incoming.remote_address(),
                        "reject QUIC connection because the pending limit is full"
                    );
                    incoming.refuse();
                } else {
                    self.start_pending_accept(incoming, remote);
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct QuicTunnelConnector {
    addr: url::Url,
    global_ctx: ArcGlobalCtx,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    bind_addrs: Vec<SocketAddr>,
    underlay_policy: Arc<UnderlayPolicy>,
    endpoint_manager: Option<Arc<QuicEndpointManager>>,
    punched_socket: Option<UdpSocket>,
    shared_endpoint: Option<Endpoint>,
}

pub(crate) fn discovery_endpoint(
    socket: UdpSocket,
    global_ctx: &ArcGlobalCtx,
    packets: tokio::sync::broadcast::Sender<crate::common::stun::StunPacket>,
) -> Result<(Endpoint, Arc<UdpSocket>), TunnelError> {
    ensure_local_allowed(&global_ctx.get_underlay_policy(), socket.local_addr()?)?;
    configure_quic_socket_buffers(&socket);
    let runtime = default_runtime()
        .ok_or_else(|| TunnelError::InternalError("no async runtime found".to_owned()))?;
    let socket = prepare_quic_udp_socket(socket, None)?;
    let sender = Arc::new(UdpSocket::from_std(socket.try_clone()?)?);
    let socket = crate::connector::tracker_discovery::socket::DiscoverySocket::new(
        runtime.wrap_udp_socket(socket)?,
        packets,
    );
    let mut config = endpoint_config();
    // BEP 15 action words occupy the fixed-bit-zero namespace on this shared socket.
    config.grease_quic_bit(false);
    let endpoint = Endpoint::new_with_abstract_socket(
        config,
        Some(server_config(&global_ctx.get_flags())?),
        socket,
        runtime,
    )?;
    Ok((endpoint, sender))
}

// Keep the STUN mapping alive by transferring ownership of the original socket.
fn punched_endpoint(
    socket: UdpSocket,
    global_ctx: &ArcGlobalCtx,
    server: bool,
) -> Result<Endpoint, TunnelError> {
    ensure_local_allowed(&global_ctx.get_underlay_policy(), socket.local_addr()?)?;
    configure_quic_socket_buffers(&socket);
    let runtime = default_runtime()
        .ok_or_else(|| TunnelError::InternalError("no async runtime found".to_owned()))?;
    let socket = runtime.wrap_udp_socket(prepare_quic_udp_socket(socket, None)?)?;
    let config = if server {
        Some(server_config(&global_ctx.get_flags())?)
    } else {
        None
    };
    Ok(Endpoint::new_with_abstract_socket(
        endpoint_config(),
        config,
        socket,
        runtime,
    )?)
}

impl QuicTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        QuicTunnelConnector {
            addr,
            global_ctx,
            ip_version: IpVersion::Both,
            resolved_addr: None,
            bind_addrs: Vec::new(),
            underlay_policy: Arc::new(UnderlayPolicy::default()),
            endpoint_manager: None,
            punched_socket: None,
            shared_endpoint: None,
        }
    }

    pub(crate) fn from_punched_socket(
        socket: UdpSocket,
        remote: SocketAddr,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let mut connector = Self::new(
            super::build_url_from_socket_addr(&remote.to_string(), "quic"),
            global_ctx.clone(),
        );
        connector.underlay_policy = global_ctx.get_underlay_policy();
        connector.resolved_addr = Some(remote);
        connector.punched_socket = Some(socket);
        connector
    }

    pub(crate) fn from_discovery_endpoint(
        endpoint: Endpoint,
        remote: SocketAddr,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let mut connector = Self::new(
            super::build_url_from_socket_addr(&remote.to_string(), "quic"),
            global_ctx.clone(),
        );
        connector.underlay_policy = global_ctx.get_underlay_policy();
        connector.resolved_addr = Some(remote);
        connector.shared_endpoint = Some(endpoint);
        connector
    }

    pub(crate) fn from_discovery_source(
        source: IpAddr,
        remote: SocketAddr,
        global_ctx: ArcGlobalCtx,
    ) -> Result<Self, TunnelError> {
        let local = SocketAddr::new(source, 0);
        let endpoint = {
            let _guard = global_ctx.net_ns.guard();
            ensure_local_allowed(&global_ctx.get_underlay_policy(), local)?;
            ensure_remote_allowed(&global_ctx.get_underlay_policy(), remote)?;
            // This path must retain the discovery source even without configured exclusions.
            QuicEndpointManager::try_create_for_peer(
                local,
                false,
                global_ctx.get_flags().socket_mark,
                Some(remote),
            )?
        };
        Ok(Self::from_discovery_endpoint(endpoint, remote, global_ctx))
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QuicTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let memory_permit = self
            .global_ctx
            .process_memory_governor()
            .try_reserve_connection(QUIC_CONNECTION_MEMORY_CHARGE_BYTES)
            .ok_or_else(|| {
                self.global_ctx
                    .process_memory_governor()
                    .record_connection_refusal("quic connect");
                TunnelError::InternalError("QUIC connection memory limit is full".to_owned())
            })?;
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        let endpoint_manager = QuicEndpointManager::load(&self.global_ctx);
        let (endpoint, connection, transport_authenticated, _dedicated_endpoint) =
            if self.shared_endpoint.is_some() || self.punched_socket.is_some() {
                ensure_remote_allowed(&self.underlay_policy, addr)?;
                let endpoint = match self.shared_endpoint.take() {
                    Some(endpoint) => endpoint,
                    None => punched_endpoint(
                        self.punched_socket.take().unwrap(),
                        &self.global_ctx,
                        false,
                    )?,
                };
                let flags = self.global_ctx.get_flags();
                let name = if flags.camouflage_config().server_name.is_empty() {
                    addr.ip().to_string()
                } else {
                    flags.camouflage_config().server_name.clone()
                };
                let connection = endpoint
                    .connect_with(client_config(&flags)?, addr, &name)
                    .context("start punched QUIC connection")?
                    .await
                    .context("connect punched QUIC socket")?;
                (endpoint, connection, false, true)
            } else {
                QuicEndpointManager::connect_with_manager(
                    &self.global_ctx,
                    &endpoint_manager,
                    addr,
                    &self.bind_addrs,
                    self.underlay_policy.clone(),
                )
                .await?
            };
        let local_addr = endpoint.local_addr()?;
        self.endpoint_manager = Some(endpoint_manager);

        let authority = if self
            .global_ctx
            .config
            .get_flags()
            .camouflage_config()
            .server_name
            .is_empty()
        {
            self.addr
                .host_str()
                .map(str::to_owned)
                .unwrap_or_else(|| addr.ip().to_string())
        } else {
            self.global_ctx
                .config
                .get_flags()
                .camouflage_config()
                .server_name
                .clone()
        };
        let http_host = self
            .global_ctx
            .get_flags()
            .camouflage_config()
            .http_host
            .clone();
        let authority = if http_host.is_empty() {
            authority
        } else {
            http_host
        };
        let bearer = connect_ip_bearer(&self.global_ctx);
        let (connect_stream, connect_stream_id) =
            open_connect_ip_request(&connection, &authority, bearer.as_deref()).await?;

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&connection.remote_address().to_string(), "quic")
                    .into(),
            ),
        };

        build_connect_ip_tunnel(
            connection,
            connect_stream,
            connect_stream_id,
            info,
            transport_authenticated,
            Some(memory_permit),
            None,
            self.endpoint_manager.clone(),
            Some(endpoint),
            self.global_ctx.clone(),
        )
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
}

#[cfg(test)]
mod tests {
    use crate::common::{
        global_ctx::tests::get_mock_global_ctx_with_network, underlay_policy::UnderlayPolicy,
    };
    use crate::tunnel::{
        TunnelConnector,
        common::tests::_tunnel_pingpong,
        packet_def::{PacketType, ZCPacket},
    };
    use futures::{SinkExt, StreamExt};
    use std::sync::LazyLock;
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    // Shared runtime for all tests to avoid endpoint invalidation across runtimes
    static RUNTIME: LazyLock<Runtime> =
        LazyLock::new(|| Builder::new_multi_thread().enable_all().build().unwrap());

    fn test_identity() -> crate::common::config::NetworkIdentity {
        // QUIC listeners require a verifiable network identity. Provision a
        // shared secret so the tests exercise the authenticated path.
        crate::common::config::NetworkIdentity::new(
            "default".to_owned(),
            "quic-test-secret".to_owned(),
        )
    }

    fn global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(Some(test_identity()))
    }

    fn test_connection_wrapper(conn: Connection) -> Arc<ConnWrapper> {
        let ctx = global_ctx();
        let state = Arc::new(super::super::TunnelPathState {
            peer_authenticated: std::sync::atomic::AtomicBool::new(false),
            info: RwLock::new(TunnelInfo::default()),
        });
        Arc::new(ConnWrapper {
            conn,
            telemetry: ctx.dataplane_telemetry().clone(),
            io_observed: QuicIoObserved::default(),
            migration_policy: Arc::new(QuicMigrationPolicy::new(&ctx, state)),
            migration_rejections: ctx.stats_manager().get_simple_counter(
                crate::common::stats_manager::MetricName::QuicMigrationsRejected,
            ),
            observed_migration_rejections: AtomicU64::new(0),
            expired_datagrams: ctx
                .stats_manager()
                .get_simple_counter(crate::common::stats_manager::MetricName::QuicDatagramsExpired),
            observed_expired_datagrams: AtomicU64::new(0),
            _endpoint_manager: None,
            _endpoint_owner: None,
            _memory_permit: None,
            _source_permit: None,
        })
    }

    const CAMOUFLAGE_HOST: &str = "challenges.cloudflare.com";

    struct UdpPassthrough {
        public: SocketAddr,
        _nginx: Option<NginxUdpProxy>,
        _task: Option<tokio::task::JoinHandle<()>>,
        _dir: Option<tempfile::TempDir>,
    }

    impl Drop for UdpPassthrough {
        fn drop(&mut self) {
            if let Some(task) = &self._task {
                task.abort();
            }
        }
    }

    struct NginxUdpProxy {
        child: std::process::Child,
    }

    impl Drop for NginxUdpProxy {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn nginx_binary() -> Option<std::path::PathBuf> {
        for candidate in [
            "/opt/homebrew/opt/nginx/bin/nginx",
            "/usr/sbin/nginx",
            "/usr/bin/nginx",
        ] {
            let path = std::path::PathBuf::from(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    fn reserve_udp_port() -> SocketAddr {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
    }

    fn start_nginx_udp_passthrough(backend: SocketAddr) -> Option<UdpPassthrough> {
        let nginx = nginx_binary()?;
        let dir = tempfile::tempdir().ok()?;
        let public = reserve_udp_port();
        let conf = dir.path().join("nginx.conf");
        let error = dir.path().join("error.log");
        let pid = dir.path().join("nginx.pid");
        std::fs::write(
            &conf,
            format!(
                "daemon off;\nerror_log {};\npid {};\nevents {{ worker_connections 64; }}\nstream {{\n    server {{\n        listen {} udp;\n        proxy_pass {};\n        proxy_timeout 60s;\n    }}\n}}\n",
                error.display(),
                pid.display(),
                public,
                backend
            ),
        )
        .ok()?;
        let child = std::process::Command::new(nginx)
            .arg("-c")
            .arg(&conf)
            .arg("-p")
            .arg(dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        for _ in 0..50 {
            if std::net::UdpSocket::bind(public).is_err() {
                return Some(UdpPassthrough {
                    public,
                    _nginx: Some(NginxUdpProxy { child }),
                    _task: None,
                    _dir: Some(dir),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(NginxUdpProxy { child });
        None
    }

    async fn start_tokio_udp_passthrough(backend: SocketAddr) -> UdpPassthrough {
        let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let public = front.local_addr().unwrap();
        let task = tokio::spawn(run_tokio_udp_passthrough(front, backend));
        UdpPassthrough {
            public,
            _nginx: None,
            _task: Some(task),
            _dir: None,
        }
    }

    async fn start_udp_passthrough(backend: SocketAddr) -> UdpPassthrough {
        if let Some(proxy) = start_nginx_udp_passthrough(backend) {
            return proxy;
        }
        start_tokio_udp_passthrough(backend).await
    }

    async fn run_tokio_udp_passthrough(front: UdpSocket, backend: SocketAddr) {
        let front = Arc::new(front);
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
        let mut sessions = HashMap::<SocketAddr, mpsc::Sender<Bytes>>::new();
        let mut buf = vec![0_u8; 2048];
        loop {
            tokio::select! {
                recv = front.recv_from(&mut buf) => {
                    let Ok((n, client)) = recv else { return };
                    if let Some(tx) = sessions.get(&client) {
                        let _ = tx.try_send(Bytes::copy_from_slice(&buf[..n]));
                        continue;
                    }
                    let (tx, rx) = mpsc::channel(64);
                    let _ = tx.try_send(Bytes::copy_from_slice(&buf[..n]));
                    sessions.insert(client, tx);
                    tokio::spawn(tokio_udp_passthrough_session(
                        front.clone(),
                        backend,
                        client,
                        rx,
                        cleanup_tx.clone(),
                    ));
                }
                Some(client) = cleanup_rx.recv() => {
                    sessions.remove(&client);
                }
            }
        }
    }

    async fn tokio_udp_passthrough_session(
        front: Arc<UdpSocket>,
        backend: SocketAddr,
        client: SocketAddr,
        mut incoming: mpsc::Receiver<Bytes>,
        cleanup: mpsc::UnboundedSender<SocketAddr>,
    ) {
        let Ok(up) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
            let _ = cleanup.send(client);
            return;
        };
        if up.connect(backend).await.is_err() {
            let _ = cleanup.send(client);
            return;
        }
        let mut buf = vec![0_u8; 2048];
        loop {
            tokio::select! {
                packet = incoming.recv() => {
                    let Some(packet) = packet else { break };
                    if up.send(&packet).await.is_err() {
                        break;
                    }
                }
                result = up.recv(&mut buf) => {
                    let Ok(n) = result else { break };
                    if front.send_to(&buf[..n], client).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = cleanup.send(client);
    }

    fn camouflage_url(port: u16) -> url::Url {
        format!("quic://127.0.0.1:{port}").parse().unwrap()
    }

    fn hybrid_writer_without_reliable_io(connection: Arc<ConnWrapper>) -> QuicHybridWriter {
        let (sender, mut receiver) =
            mpsc::channel::<ReliableWriteRequest>(RELIABLE_LANE_QUEUE_BATCHES);
        let task = tokio::spawn(async move {
            while receiver.recv().await.is_some() {}
            Ok(())
        });
        QuicHybridWriter::new(sender, task, connection, 0)
    }

    #[test]
    fn quic_admission_deadline_releases_source_for_another_peer() {
        RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(12), async {
                let context = global_ctx();
                let mut listener =
                    QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), context.clone());
                listener.listen().await.unwrap();
                let url = listener.local_url();
                let addr = SocketAddr::from_url(url.clone(), IpVersion::Both)
                    .await
                    .unwrap();
                let server = tokio::spawn(async move { listener.accept().await.unwrap() });
                let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                endpoint.set_default_client_config(client_config(&context.get_flags()).unwrap());
                let stalled = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
                // QUIC remains active, but this client never sends CONNECT-IP.
                let closed = tokio::time::timeout(Duration::from_secs(9), stalled.closed())
                    .await
                    .unwrap();
                assert!(matches!(
                    closed,
                    quinn::ConnectionError::ApplicationClosed(_)
                ));
                let client = QuicTunnelConnector::new(url, global_ctx())
                    .connect()
                    .await
                    .unwrap();
                let accepted = server.await.unwrap();
                assert_eq!(client.transport_binding(), accepted.transport_binding());
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn quic_hybrid_lanes_cross_a_live_connection() {
        RUNTIME.block_on(async {
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
            listener.listen().await.unwrap();
            let remote = listener.local_url();
            let (received_tx, received_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, mut send) = tunnel.split();
                for _ in 0..3 {
                    let packet = recv.next().await.unwrap().unwrap();
                    send.send(packet).await.unwrap();
                    send.flush().await.unwrap();
                }
                received_rx.await.unwrap();
                send.close().await.unwrap();
            });

            let tunnel = QuicTunnelConnector::new(remote, global_ctx())
                .connect()
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();

            let mut normal = ZCPacket::new_with_payload(b"normal datagram");
            normal.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            let mut critical = ZCPacket::new_with_payload(&[0_u8; 42]);
            critical.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            critical
                .mut_peer_manager_header()
                .unwrap()
                .set_critical_l2_control(true);

            let mut oversized = ZCPacket::new_with_payload(&[0x5a; 9000]);
            oversized.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            for expected in [normal, critical, oversized] {
                send.send(PacketBatch::singleton(expected.clone()))
                    .await
                    .unwrap();
                send.flush().await.unwrap();
                let received = tokio::time::timeout(Duration::from_secs(2), recv.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap();
                assert_eq!(received.payload(), expected.payload());
                assert_eq!(
                    received
                        .peer_manager_header()
                        .unwrap()
                        .is_critical_l2_control(),
                    expected
                        .peer_manager_header()
                        .unwrap()
                        .is_critical_l2_control()
                );
            }

            send.close().await.unwrap();
            received_tx.send(()).unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn unrelated_http3_request_gets_a_normal_response() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx());
            listener.listen().await.unwrap();
            let url = listener.local_url();
            let server_addr = SocketAddr::from_url(url.clone(), IpVersion::Both)
                .await
                .unwrap();
            let server = tokio::spawn(async move { listener.accept().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let connection = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let mut builder = h3::client::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let (mut driver, mut requests) = builder
                .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(
                    h3_quinn::Connection::new(connection),
                )
                .await
                .unwrap();
            let driver = tokio::spawn(async move {
                let _ = driver.wait_idle().await;
            });
            let request = http::Request::builder()
                .uri("https://example.com/")
                .body(())
                .unwrap();
            let mut stream = requests.send_request(request).await.unwrap();
            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                "text/html; charset=utf-8"
            );
            let mut body = stream.recv_data().await.unwrap().unwrap();
            assert!(
                body.copy_to_bytes(body.remaining())
                    .starts_with(b"<!doctype html>")
            );

            // A website owner releases VPN admission for peers behind the same NAT.
            let _peer = tokio::time::timeout(
                Duration::from_secs(2),
                QuicTunnelConnector::new(url, global_ctx()).connect(),
            )
            .await
            .unwrap()
            .unwrap();
            let _accepted = server.await.unwrap();
            // The website remains usable after the CONNECT admission deadline.
            tokio::time::sleep(Duration::from_secs(8)).await;

            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://example.com{CONNECT_IP_PATH}"))
                .header("capsule-protocol", "?1")
                .header("proxy-authorization", "Bearer invalid")
                .extension(h3::ext::Protocol::CONNECT_IP)
                .body(())
                .unwrap();
            let mut stream = requests.send_request(request).await.unwrap();
            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
            drop(requests);
            driver.abort();
        });
    }

    #[test]
    fn connect_ip_admission_tokens_rotate_and_reject_changes() {
        let admission = ConnectIpAdmission {
            key: Arc::from(b"test-admission-key-material".as_slice()),
        };
        let window = ConnectIpAdmission::window(SystemTime::now());
        let token = admission.token_for_window(window);

        assert!(admission.verify_header(&format!("Bearer {token}")));
        assert!(!admission.verify_header(&format!("Bearer {token}x")));
        assert!(!admission.verify_header("Bearer invalid"));
    }

    #[test]
    fn routing_connection_ids_validate_and_reject_changes() {
        let secret = b"routing-test-secret-material";
        let now = UNIX_EPOCH + Duration::from_secs(1_800);
        let cid = quic_routing_cid(secret, now);
        let mut packet = vec![0xc0, 0, 0, 0, 1, cid.len() as u8];
        packet.extend_from_slice(&cid);
        packet.resize(1200, 0);

        assert_eq!(cid.len(), QUIC_ROUTING_CID_BYTES);
        let (prefix, length) = encode_quic_datagram_prefix(0, DATAGRAM_CONTEXT_WHOLE);
        assert_eq!(length, 2);
        assert_eq!(&prefix[..2], &[0, 0]);
        assert!(has_valid_quic_routing_marker(&packet, secret, now));
        packet[10] ^= 1;
        assert!(!has_valid_quic_routing_marker(&packet, secret, now));
    }

    #[test]
    fn probe_without_marker_is_passed_through_to_decoy() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let upstream = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let upstream_addr = upstream.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let connection = upstream.accept().await.unwrap().await.unwrap();
                if let Ok(ConnectIpAccept::Website(website)) =
                    accept_connect_ip_request(&connection, None, None).await
                {
                    serve_http3_requests(website.connection, None, Some(website.first)).await;
                }
            });
            let global_ctx = global_ctx();
            let mut listener_flags = global_ctx.get_flags();
            listener_flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            listener_flags
                .camouflage_config_mut()
                .set_decoy_upstream(upstream_addr.to_string());
            listener_flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            global_ctx.set_flags(listener_flags);
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx);
            listener.listen().await.unwrap();
            let backend = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            let proxy = start_tokio_udp_passthrough(backend).await;

            let mut probe = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            probe.set_default_client_config(client_config(&flags).unwrap());
            let connection = probe
                .connect(proxy.public, CAMOUFLAGE_HOST)
                .unwrap()
                .await
                .unwrap();
            let mut builder = h3::client::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let (mut driver, mut requests) = builder
                .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(
                    h3_quinn::Connection::new(connection),
                )
                .await
                .unwrap();
            let driver_task = tokio::spawn(async move {
                let _ = driver.wait_idle().await;
            });
            let request = http::Request::builder()
                .uri(format!("https://{CAMOUFLAGE_HOST}/"))
                .body(())
                .unwrap();
            let mut stream = requests.send_request(request).await.unwrap();
            let response = stream.recv_response().await.unwrap();

            assert_eq!(response.status(), http::StatusCode::OK);
            driver_task.abort();
            upstream_task.abort();
        });
    }

    #[test]
    fn live_challenges_cloudflare_probe_through_udp_passthrough() {
        RUNTIME.block_on(async {
            let upstream = tokio::net::lookup_host((CAMOUFLAGE_HOST, 443))
                .await
                .expect("resolve challenges.cloudflare.com")
                .find(SocketAddr::is_ipv4)
                .expect("challenges.cloudflare.com has IPv4");
            let global_ctx = global_ctx();
            let mut listener_flags = global_ctx.get_flags();
            listener_flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            listener_flags
                .camouflage_config_mut()
                .set_decoy_upstream(upstream.to_string());
            listener_flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            global_ctx.set_flags(listener_flags);
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx);
            listener.listen().await.unwrap();
            let backend = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            let proxy = start_udp_passthrough(backend).await;
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            let mut probe = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            probe.set_default_client_config(client_config(&flags).unwrap());
            let connection = tokio::time::timeout(
                Duration::from_secs(15),
                probe.connect(proxy.public, CAMOUFLAGE_HOST).unwrap(),
            )
            .await
            .expect("probe handshake through passthrough")
            .expect("probe TLS to challenges.cloudflare.com");
            let (mut driver, mut requests) = h3::client::builder()
                .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(
                    h3_quinn::Connection::new(connection),
                )
                .await
                .unwrap();
            let driver_task = tokio::spawn(async move {
                let _ = driver.wait_idle().await;
            });
            let request = http::Request::builder()
                .uri(format!("https://{CAMOUFLAGE_HOST}/"))
                .header("user-agent", "lowertier-probe")
                .body(())
                .unwrap();
            let mut stream = requests.send_request(request).await.unwrap();
            let _ = stream.finish().await;
            if let Ok(Ok(response)) =
                tokio::time::timeout(Duration::from_secs(10), stream.recv_response()).await
            {
                assert!(
                    response.status().is_success() || response.status().is_redirection(),
                    "probe status {}",
                    response.status()
                );
            }
            driver_task.abort();
            drop(proxy);
            drop(listener);
        });
    }

    #[test]
    fn marked_client_reaches_local_quic_listener() {
        RUNTIME.block_on(async {
            let decoy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let global_ctx = global_ctx();
            let mut flags = global_ctx.get_flags();
            flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            flags
                .camouflage_config_mut()
                .set_decoy_upstream(decoy.local_addr().unwrap().to_string());
            flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            global_ctx.set_flags(flags);

            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx.clone());
            listener.listen().await.unwrap();
            let remote = listener.local_url();
            let (received_tx, received_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                let tunnel = listener.accept().await.unwrap();
                let (mut recv, mut send) = tunnel.split();
                let packet = recv.next().await.unwrap().unwrap();
                send.send(packet).await.unwrap();
                send.flush().await.unwrap();
                received_rx.await.unwrap();
            });

            let tunnel = QuicTunnelConnector::new(remote, global_ctx)
                .connect()
                .await
                .unwrap();
            let (mut recv, mut send) = tunnel.split();
            let mut packet = ZCPacket::new_with_payload(b"marked route");
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
            send.send(PacketBatch::singleton(packet.clone()))
                .await
                .unwrap();
            send.flush().await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(2), recv.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .pop_singleton()
                .unwrap();

            assert_eq!(received.payload(), packet.payload());
            received_tx.send(()).unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn sni_without_a_routing_marker_reaches_local_when_passthrough() {
        RUNTIME.block_on(async {
            let decoy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let global_ctx = global_ctx();
            let mut flags = global_ctx.get_flags();
            flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            flags
                .camouflage_config_mut()
                .set_decoy_upstream(decoy.local_addr().unwrap().to_string());
            flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            flags.camouflage_config_mut().sni_routing = true;
            global_ctx.set_flags(flags);

            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx);
            listener.listen().await.unwrap();
            let public_addr = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
            let _server = tokio::spawn(async move {
                let _ = listener.accept().await;
            });

            let mut probe = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            probe.set_default_client_config(client_config(&gen_default_flags()).unwrap());
            tokio::time::timeout(
                Duration::from_secs(2),
                probe.connect(public_addr, CAMOUFLAGE_HOST).unwrap(),
            )
            .await
            .expect("QUIC handshake through SNI passthrough")
            .unwrap();
        });
    }

    #[test]
    fn unmatched_sni_is_passed_through_when_passthrough() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let upstream = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let upstream_addr = upstream.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let _ = upstream.accept().await.unwrap().await.unwrap();
            });
            let global_ctx = global_ctx();
            let mut listener_flags = global_ctx.get_flags();
            listener_flags.camouflage_config_mut().server_name = "lowertier.invalid".to_owned();
            listener_flags
                .camouflage_config_mut()
                .set_decoy_upstream(upstream_addr.to_string());
            listener_flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            listener_flags.camouflage_config_mut().sni_routing = true;
            global_ctx.set_flags(listener_flags);
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx);
            listener.listen().await.unwrap();
            let public_addr = listener.endpoint.as_ref().unwrap().local_addr().unwrap();

            let mut probe = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            probe.set_default_client_config(client_config(&flags).unwrap());
            tokio::time::timeout(
                Duration::from_secs(2),
                probe.connect(public_addr, CAMOUFLAGE_HOST).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            tokio::time::timeout(Duration::from_secs(2), upstream_task)
                .await
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn normal_origin_serves_configured_files_and_blocks_parent_paths() {
        RUNTIME.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("site");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("index.html"), b"site home").unwrap();
            std::fs::write(directory.path().join("private.txt"), b"private").unwrap();

            let request = http::Request::builder()
                .uri("https://example.com/")
                .body(())
                .unwrap();
            let response = normal_origin_response(&request, Some(&root)).await;
            assert_eq!(response.status, http::StatusCode::OK);
            assert_eq!(response.body, Bytes::from_static(b"site home"));

            let request = http::Request::builder()
                .uri("https://example.com/../private.txt")
                .body(())
                .unwrap();
            let response = normal_origin_response(&request, Some(&root)).await;
            assert_eq!(response.status, http::StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn connect_ip_capsules_round_trip_reliable_packets() {
        let mut packet = ZCPacket::new_with_payload(b"route-control");
        packet.fill_peer_manager_hdr(3, 4, PacketType::RpcReq as u8);
        let expected = packet.tunnel_payload().to_vec();
        let capsule = encode_packet_capsule(packet).unwrap();
        let mut buffer = BytesMut::from(capsule.as_ref());
        let decoded = decode_packet_capsules(&mut buffer)
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(decoded.tunnel_payload(), expected);
        assert!(buffer.is_empty());
    }

    #[test]
    fn connect_ip_keeps_delivery_through_udp_passthrough() {
        RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let (direct_rate, direct_delivery, direct_elapsed) =
                    measure_connect_ip(true, false).await;
                let (proxy_rate, proxy_delivery, proxy_elapsed) = measure_connect_ip(true, true).await;
                if std::env::var_os("LOWTIER_BENCH").is_some() {
                    eprintln!(
                        "CONNECT-IP camouflage direct: {direct_rate:.1} Mbit/s, {direct_delivery:.2}% in {direct_elapsed:?}"
                    );
                    eprintln!(
                        "CONNECT-IP camouflage through UDP passthrough: {proxy_rate:.1} Mbit/s, {proxy_delivery:.2}% in {proxy_elapsed:?}"
                    );
                }
                assert!(
                    direct_delivery >= 99.5,
                    "direct camouflage delivered {direct_delivery:.2}%"
                );
                assert!(
                    proxy_delivery >= 99.5,
                    "passthrough camouflage delivered {proxy_delivery:.2}%"
                );
            })
            .await
            .expect("CONNECT-IP delivery stalled");
        });
    }

    async fn measure_connect_ip(camouflage: bool, passthrough: bool) -> (f64, f64, Duration) {
        const PACKETS: usize = 20_000;
        const PAYLOAD: usize = 1200;
        let global_ctx = global_ctx();
        let decoy = if camouflage {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut flags = global_ctx.get_flags();
            flags.camouflage_config_mut().server_name = CAMOUFLAGE_HOST.to_owned();
            flags
                .camouflage_config_mut()
                .set_decoy_upstream(socket.local_addr().unwrap().to_string());
            flags.camouflage_config_mut().admission_secret =
                "routing-test-secret-material".to_owned();
            global_ctx.set_flags(flags);
            Some(socket)
        } else {
            None
        };
        let mut listener =
            QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), global_ctx.clone());
        listener.listen().await.unwrap();
        let backend = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
        let proxy = if passthrough {
            Some(start_udp_passthrough(backend).await)
        } else {
            None
        };
        let remote = match &proxy {
            Some(proxy) => camouflage_url(proxy.public.port()),
            None => listener.local_url(),
        };
        let server = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            let (mut receive, _send) = tunnel.split();
            let mut received = 0;
            let mut first = None;
            let mut last = None;
            while received < PACKETS {
                let Ok(Some(Ok(batch))) =
                    tokio::time::timeout(Duration::from_secs(2), receive.next()).await
                else {
                    break;
                };
                let now = Instant::now();
                first.get_or_insert(now);
                last = Some(now);
                received += batch.len();
            }
            (received, last.unwrap().duration_since(first.unwrap()))
        });
        let tunnel = QuicTunnelConnector::new(remote, global_ctx)
            .connect()
            .await
            .unwrap();
        let (_receive, mut send) = tunnel.split();
        let mut template = ZCPacket::new_with_payload(&vec![0x5a; PAYLOAD]);
        template.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut sent = 0;
        while sent < PACKETS {
            let count = (PACKETS - sent).min(MAX_PACKET_BATCH_SIZE);
            let mut batch = PacketBatch::with_capacity(count);
            for _ in 0..count {
                batch.try_push(template.clone()).unwrap();
            }
            send.send(batch).await.unwrap();
            sent += count;
        }
        send.flush().await.unwrap();
        let (received, elapsed) = tokio::time::timeout(Duration::from_secs(30), server)
            .await
            .unwrap()
            .unwrap();
        assert!(received > 0);
        drop(proxy);
        drop(decoy);
        let bits = (received * (PAYLOAD + PEER_MANAGER_HEADER_SIZE) * 8) as f64;
        (
            bits / elapsed.as_secs_f64() / 1_000_000.0,
            received as f64 / PACKETS as f64 * 100.0,
            elapsed,
        )
    }

    #[test]
    fn quic_pingpong_with_strict_source_bind() {
        RUNTIME.block_on(async {
            let listener =
                QuicTunnelListener::new("quic://127.0.0.1:21013".parse().unwrap(), global_ctx());
            let mut connector =
                QuicTunnelConnector::new("quic://127.0.0.1:21013".parse().unwrap(), global_ctx());
            connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
            connector.set_underlay_policy(Arc::new(
                UnderlayPolicy::new(&[], &["100.64.0.0/10".into()]).unwrap(),
            ));
            _tunnel_pingpong(listener, connector).await;
        });
    }

    #[test]
    fn ipv6_pingpong() {
        RUNTIME.block_on(ipv6_pingpong_impl())
    }

    async fn ipv6_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:32015".parse().unwrap(), global_ctx());
        let connector =
            QuicTunnelConnector::new("quic://[::1]:32015".parse().unwrap(), global_ctx());
        _tunnel_pingpong(listener, connector).await
    }

    #[test]
    fn ipv6_domain_pingpong() {
        RUNTIME.block_on(ipv6_domain_pingpong_impl())
    }

    async fn ipv6_domain_pingpong_impl() {
        let listener = QuicTunnelListener::new("quic://[::1]:32016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:32016".parse().unwrap(), global_ctx());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener =
            QuicTunnelListener::new("quic://127.0.0.1:32016".parse().unwrap(), global_ctx());
        let mut connector =
            QuicTunnelConnector::new("quic://localhost:32016".parse().unwrap(), global_ctx());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[test]
    fn normal_data_uses_plain_datagrams_and_critical_l2_uses_the_stream() {
        let _runtime = RUNTIME.enter();
        let mut data = ZCPacket::new_with_payload(b"data");
        data.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);
        assert_eq!(
            select_quic_delivery(&data, Some(data.tunnel_payload().len())),
            QuicDelivery::PlainDatagram
        );

        let mut ethernet = ZCPacket::new_with_payload(&[0x5a; 1000]);
        ethernet.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Ethernet as u8);
        assert_eq!(
            select_quic_delivery(&ethernet, Some(1200)),
            QuicDelivery::PlainDatagram
        );

        ethernet
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);
        assert_eq!(
            select_quic_delivery(&ethernet, Some(1200)),
            QuicDelivery::ReliableStream
        );

        let mut tap_frame = ZCPacket::new_with_payload(&[0x5a; 1360]);
        tap_frame.fill_peer_manager_hdr(
            1,
            2,
            crate::tunnel::packet_def::PacketType::Ethernet as u8,
        );
        assert_eq!(
            select_quic_delivery(&tap_frame, Some(1154)),
            QuicDelivery::PlainDatagram
        );
        let mut fragments = VecDeque::new();
        encode_lossy_quic_datagrams(tap_frame, 0, Some(1154), &mut fragments);
        assert!(
            fragments.len() > 1,
            "a TAP frame larger than the DATAGRAM ceiling must split"
        );
        let mut reassembly = DatagramFragments::new();
        let mut assembled = None;
        for fragment in fragments {
            if let Some(packet) = reassembly.ingest(fragment, 0) {
                assembled = Some(packet);
            }
        }
        assert_eq!(
            assembled
                .expect("split TAP frame reassembles")
                .payload_len(),
            1360
        );

        let mut control = ZCPacket::new_with_payload(b"rpc");
        control.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::RpcReq as u8);
        assert_eq!(
            select_quic_delivery(&control, Some(usize::MAX)),
            QuicDelivery::ReliableStream
        );
    }

    #[test]
    fn quic_datagram_round_trip_reuses_the_tunnel_payload() {
        let mut packet = ZCPacket::new_with_payload(b"datagram-payload");
        packet.fill_peer_manager_hdr(7, 9, crate::tunnel::packet_def::PacketType::Data as u8);
        let expected = packet.tunnel_payload().to_vec();
        let payload_pointer = packet.tunnel_payload().as_ptr();

        let encoded = encode_quic_datagram(packet, 0);
        assert_eq!(&encoded[connect_ip_datagram_overhead(0)..], expected);
        assert_eq!(
            encoded[connect_ip_datagram_overhead(0)..].as_ptr(),
            payload_pointer
        );

        let decoded = decode_quic_datagram(encoded, 0).unwrap();
        assert_eq!(decoded.tunnel_payload(), expected);
        assert!(decoded.is_lossy());
        let decoded_payload_pointer = decoded.tunnel_payload().as_ptr();
        let reencoded = encode_quic_datagram(decoded, 0);
        assert_eq!(
            reencoded[connect_ip_datagram_overhead(0)..].as_ptr(),
            decoded_payload_pointer
        );
    }

    #[test]
    fn quic_liveness_keeps_idle_peer_and_reaps_a_blackholed_path() {
        RUNTIME.block_on(async {
            use std::sync::atomic::{AtomicBool, Ordering};

            let flags = gen_default_flags();
            let server_config = server_config(&flags).unwrap();
            let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let server_addr = endpoint.local_addr().unwrap();

            // Forward both directions through one UDP socket so the established
            // QUIC path can later be turned into a silent NAT-style blackhole.
            let proxy = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let proxy_addr = proxy.local_addr().unwrap();
            let client_addr = Arc::new(tokio::sync::Mutex::new(None));
            let blackhole = Arc::new(AtomicBool::new(false));
            let proxy_task = {
                let proxy = proxy.clone();
                let client_addr = client_addr.clone();
                let blackhole = blackhole.clone();
                tokio::spawn(async move {
                    let mut bytes = vec![0_u8; 65535];
                    loop {
                        let (length, source) = proxy.recv_from(&mut bytes).await.unwrap();
                        if blackhole.load(Ordering::Acquire) {
                            continue;
                        }
                        if source == server_addr {
                            if let Some(client) = *client_addr.lock().await {
                                proxy.send_to(&bytes[..length], client).await.unwrap();
                            }
                        } else {
                            *client_addr.lock().await = Some(source);
                            proxy.send_to(&bytes[..length], server_addr).await.unwrap();
                        }
                    }
                })
            };

            let accept =
                tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(proxy_addr, "127.0.0.1")
                .unwrap()
                .await
                .unwrap();
            let server = accept.await.unwrap();

            // Keepalive traffic must preserve a genuinely idle healthy mesh link
            // beyond the configured idle timeout.
            tokio::time::sleep(QUIC_MAX_IDLE_TIMEOUT + Duration::from_secs(2)).await;
            assert!(client.close_reason().is_none());
            let payload = Bytes::from_static(b"liveness");
            client.send_datagram(payload.clone()).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                payload
            );

            // A restarted/NAT-lost peer becomes a silent UDP blackhole. The old
            // connection must stop being considered live well before Quinn's
            // former 30-second default.
            blackhole.store(true, Ordering::Release);
            tokio::time::timeout(
                QUIC_MAX_IDLE_TIMEOUT + Duration::from_secs(4),
                client.closed(),
            )
            .await
            .expect("blackholed QUIC connection outlived its idle timeout");
            proxy_task.abort();
        });
    }

    #[test]
    fn quic_initial_path_mtu_is_safe_before_discovery() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let mut transport = transport_config(&flags).unwrap();
            Arc::get_mut(&mut transport)
                .unwrap()
                .mtu_discovery_config(None);
            let mut server_config = server_config(&flags).unwrap();
            server_config.transport_config(transport.clone());
            let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let accept =
                tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
            let mut client_config = client_config(&flags).unwrap();
            client_config.transport_config(transport);
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(client_config);
            let client = endpoint
                .connect(address, "127.0.0.1")
                .unwrap()
                .await
                .unwrap();
            let server = accept.await.unwrap();
            assert_eq!(client.stats().path.current_mtu, 1200);
            assert_eq!(server.stats().path.current_mtu, 1200);
            let payload = Bytes::from(vec![0x5a; client.max_datagram_size().unwrap()]);
            client.send_datagram(payload.clone()).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                payload
            );
        });
    }

    #[test]
    fn quic_transport_uses_tls13_and_survives_a_key_update() {
        quic_transport_uses_an_ephemeral_identity();
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let server_name = server_addr.ip().to_string();
            let client = client_endpoint
                .connect(server_addr, &server_name)
                .unwrap()
                .await
                .unwrap();
            let server = server.await.unwrap();

            let handshake = client.handshake_data().unwrap();
            let client_handshake = handshake
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .expect("QUIC must use rustls TLS 1.3");
            assert_eq!(client_handshake.protocol.as_deref(), Some(b"h3".as_slice()));

            let server_handshake = server.handshake_data().unwrap();
            let server_handshake = server_handshake
                .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                .expect("QUIC must use rustls TLS 1.3");
            assert_eq!(server_handshake.server_name, None);

            client.force_key_update();
            client
                .send_datagram(Bytes::from_static(b"after-key-update"))
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                Bytes::from_static(b"after-key-update")
            );
        });
    }

    #[test]
    fn datagram_batches_reuse_both_allocations_after_warmup() {
        datagram_fragment_batches_keep_the_send_bound_and_order();
        let mut queued = VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE);
        let mut spare = VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE);
        let mut addresses = [
            queued.make_contiguous().as_ptr() as usize,
            spare.make_contiguous().as_ptr() as usize,
        ];
        addresses.sort_unstable();
        for _ in 0..256 {
            queued.extend((0..MAX_PACKET_BATCH_SIZE).map(|_| Bytes::from_static(b"queued")));
            let mut sending = QuicHybridWriter::take_datagram_batch(&mut queued, &mut spare);
            assert_eq!(sending.len(), MAX_PACKET_BATCH_SIZE);
            assert!(queued.is_empty());
            // Model a second batch arriving while the first awaits capacity.
            queued.extend((0..MAX_PACKET_BATCH_SIZE).map(|_| Bytes::from_static(b"next")));
            sending.clear();
            let (result, next, recycled) =
                QuicHybridWriter::requeue_datagrams_after_send(Ok(()), sending, queued);
            assert!(result.is_ok());
            queued = next;
            spare = recycled;
            assert_eq!(queued.len(), MAX_PACKET_BATCH_SIZE);
            assert!(queued.iter().all(|bytes| bytes.as_ref() == b"next"));
            let mut current = [
                queued.make_contiguous().as_ptr() as usize,
                spare.make_contiguous().as_ptr() as usize,
            ];
            current.sort_unstable();
            assert_eq!(current, addresses);
            queued.clear();
        }
    }

    fn datagram_fragment_batches_keep_the_send_bound_and_order() {
        let expected: Vec<_> = (0..(MAX_PACKET_BATCH_SIZE * 2 + 3))
            .map(|index| Bytes::copy_from_slice(&(index as u32).to_le_bytes()))
            .collect();
        let mut queued: VecDeque<_> = expected.iter().cloned().collect();
        let mut spare = VecDeque::with_capacity(MAX_PACKET_BATCH_SIZE);
        let mut actual = Vec::new();
        while !queued.is_empty() {
            let mut sending = QuicHybridWriter::take_datagram_batch(&mut queued, &mut spare);
            assert!(!sending.is_empty());
            assert!(sending.len() <= MAX_PACKET_BATCH_SIZE);
            actual.extend(sending.drain(..));
            let (result, next, recycled) =
                QuicHybridWriter::requeue_datagrams_after_send(Ok(()), sending, queued);
            assert!(result.is_ok());
            queued = next;
            spare = recycled;
        }
        assert_eq!(actual, expected);
    }

    fn datagram_too_large_preserves_unsent_before_new_arrivals() {
        let unsent = VecDeque::from([Bytes::from_static(b"older")]);
        let queued = VecDeque::from([Bytes::from_static(b"newer")]);
        let (result, ready, spare) = QuicHybridWriter::requeue_datagrams_after_send(
            Err(quinn::SendDatagramError::TooLarge),
            unsent,
            queued,
        );
        assert!(result.is_ok());
        assert_eq!(
            ready,
            VecDeque::from([Bytes::from_static(b"older"), Bytes::from_static(b"newer"),])
        );
        assert!(spare.is_empty());
    }

    #[test]
    fn datagram_fatal_error_preserves_queued_data_and_reports_failure() {
        datagram_too_large_preserves_unsent_before_new_arrivals();
        let unsent = VecDeque::from([Bytes::from_static(b"older")]);
        let queued = VecDeque::from([Bytes::from_static(b"newer")]);
        let (result, ready, spare) = QuicHybridWriter::requeue_datagrams_after_send(
            Err(quinn::SendDatagramError::Disabled),
            unsent,
            queued,
        );
        assert!(result.is_err());
        assert_eq!(ready.len(), 2);
        assert!(spare.is_empty());
    }

    #[test]
    fn quic_writer_waits_for_full_datagram_queue_capacity() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server_task =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server_task.await.unwrap();
            let maximum = client.max_datagram_size().unwrap();
            let filler = Bytes::from(vec![0; maximum]);
            while client.datagram_send_buffer_space() >= filler.len() {
                client.send_datagram(filler.clone()).unwrap();
            }
            assert!(client.datagram_send_buffer_space() < filler.len());

            let connection = test_connection_wrapper(client.clone());
            let mut writer = hybrid_writer_without_reliable_io(connection);
            let payload =
                vec![0x5a; maximum - PEER_MANAGER_HEADER_SIZE - connect_ip_datagram_overhead(0)];
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

            Pin::new(&mut writer)
                .start_send(PacketBatch::singleton(packet))
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(2),
                futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx)),
            )
            .await
            .unwrap()
            .unwrap();

            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let datagram = server.read_datagram().await.unwrap();
                    if datagram
                        .get(connect_ip_datagram_overhead(0) + PEER_MANAGER_HEADER_SIZE)
                        .is_some_and(|byte| *byte == 0x5a)
                    {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn quic_writer_starts_staged_datagrams_before_accepting_another_batch() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server_task =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server_task.await.unwrap();
            let maximum = client.max_datagram_size().unwrap();
            let filler = Bytes::from(vec![0; maximum]);
            while client.datagram_send_buffer_space() >= filler.len() {
                client.send_datagram(filler.clone()).unwrap();
            }

            let connection = test_connection_wrapper(client);
            let mut writer = hybrid_writer_without_reliable_io(connection);
            let packet = |marker| {
                let mut packet = ZCPacket::new_with_payload(&[marker; 64]);
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                PacketBatch::singleton(packet)
            };

            Pin::new(&mut writer).start_send(packet(0xa1)).unwrap();
            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
                .await
                .unwrap();
            Pin::new(&mut writer).start_send(packet(0xb2)).unwrap();
            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
                .await
                .unwrap();
            Pin::new(&mut writer).start_send(packet(0xc3)).unwrap();
            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
                .await
                .unwrap();

            let mut markers = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), async {
                while markers.len() != 3 {
                    let datagram = server.read_datagram().await.unwrap();
                    let marker =
                        datagram[connect_ip_datagram_overhead(0) + PEER_MANAGER_HEADER_SIZE];
                    if matches!(marker, 0xa1 | 0xb2 | 0xc3) {
                        markers.push(marker);
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(markers, vec![0xa1, 0xb2, 0xc3]);
        });
    }

    #[test]
    fn quic_writer_keeps_one_owned_datagram_batch_until_flush() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server_task =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server_task.await.unwrap();
            let connection = test_connection_wrapper(client.clone());
            let mut writer = hybrid_writer_without_reliable_io(connection);
            let mut batch = PacketBatch::with_capacity(8);
            for sequence in 0..8_u8 {
                let mut packet = ZCPacket::new_with_payload(&[sequence; 64]);
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                batch.try_push(packet).unwrap();
            }
            Pin::new(&mut writer).start_send(batch).unwrap();

            assert_eq!(writer.pending_datagrams.as_ref().unwrap().len(), 8);
            assert!(writer.pending_datagram_send.is_none());

            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
                .await
                .unwrap();
            assert!(writer.pending_datagrams.as_ref().unwrap().is_empty());
            assert!(writer.pending_datagram_send.is_none());

            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), async {
                while received.len() != 8 {
                    received.push(server.read_datagram().await.unwrap());
                }
            })
            .await
            .unwrap();
            assert_eq!(
                received
                    .iter()
                    .map(|datagram| {
                        datagram[connect_ip_datagram_overhead(0) + PEER_MANAGER_HEADER_SIZE]
                    })
                    .collect::<Vec<_>>(),
                (0..8_u8).collect::<Vec<_>>()
            );

            let allocation = writer
                .spare_datagram_send
                .as_mut()
                .unwrap()
                .get_pin()
                .as_ref()
                .get_ref() as *const _ as *const ();
            for sequence in 8..32_u8 {
                let mut packet = ZCPacket::new_with_payload(&[sequence; 64]);
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                Pin::new(&mut writer)
                    .start_send(PacketBatch::singleton(packet))
                    .unwrap();
                writer.begin_datagram_flush();
                let current = writer
                    .pending_datagram_send
                    .as_mut()
                    .unwrap()
                    .get_pin()
                    .as_ref()
                    .get_ref() as *const _ as *const ();
                assert_eq!(
                    current, allocation,
                    "the send future retains its allocation"
                );
                futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
                    .await
                    .unwrap();
                let received = tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    received[connect_ip_datagram_overhead(0) + PEER_MANAGER_HEADER_SIZE],
                    sequence
                );
            }
        });
    }

    fn quic_transport_uses_an_ephemeral_identity() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let server =
                tokio::spawn(async move { server_endpoint.accept().await.unwrap().await.unwrap() });

            let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_endpoint.set_default_client_config(client_config(&flags).unwrap());
            let client = client_endpoint
                .connect(server_addr, &server_addr.ip().to_string())
                .unwrap()
                .await
                .unwrap();
            let server = server.await.unwrap();

            assert!(client.peer_identity().is_some());
            assert!(server.peer_identity().is_none());
        });
    }

    #[test]
    fn quic_admission_limiter_bounds_global_and_prefix_rates() {
        migration::check_budget();
        let now = Instant::now();
        let mut limiter = QuicAdmissionLimiter::new();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        for host in 1..=MAX_QUIC_ADMISSIONS_PER_PREFIX_PER_SECOND {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host as u8));
            assert!(limiter.admit(ip, now));
        }
        assert!(!limiter.admit(first, now));
        assert!(limiter.admit(first, now + Duration::from_secs(1)));
    }

    #[test]
    fn secure_mode_allows_noise_protected_quic() {
        RUNTIME.block_on(async {
            let flags = gen_default_flags();
            let server_endpoint = Endpoint::server(
                server_config(&flags).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();
            let accept_endpoint = server_endpoint.clone();
            let server = tokio::spawn(async move {
                loop {
                    let incoming = accept_endpoint.accept().await.unwrap();
                    if let Ok(connection) = incoming.await {
                        return connection;
                    }
                }
            });

            let context = global_ctx();
            context
                .config
                .set_secure_mode(Some(crate::proto::common::SecureModeConfig {
                    enabled: true,
                    local_private_key: None,
                    local_public_key: None,
                    ..Default::default()
                }));
            let (_endpoint, connection, authenticated, _dedicated_endpoint) =
                QuicEndpointManager::connect(
                    &context,
                    server_addr,
                    &[],
                    Arc::new(UnderlayPolicy::default()),
                )
                .await
                .unwrap();
            let _server = server.await.unwrap();

            assert!(!authenticated);
            connection.close(0_u32.into(), b"test complete");
        });
    }
}

#[cfg(test)]
mod pacing_configuration_tests {
    use super::*;

    #[test]
    fn burst_override_is_nonzero_bounded_and_optional() {
        use crate::common::global_ctx::{ProcessMemoryGovernor, process_memory_limit};
        for (physical, network_extension, expected) in [
            (0, false, 48),
            (16 * 1024 * 1024 * 1024, false, 768),
            (0, true, 12),
        ] {
            let governor = Arc::new(ProcessMemoryGovernor::with_limit(process_memory_limit(
                physical,
                None,
                network_extension,
            )));
            let mut permits = Vec::new();
            while let Some(permit) =
                governor.try_reserve_connection(QUIC_CONNECTION_MEMORY_CHARGE_BYTES)
            {
                permits.push(permit);
            }
            assert_eq!(permits.len(), expected);
            let retained = governor.retained();
            assert!(
                governor
                    .try_reserve_connection(QUIC_CONNECTION_MEMORY_CHARGE_BYTES)
                    .is_none()
            );
            assert_eq!(governor.retained(), retained);
            assert!(governor.try_reserve_owned(governor.limit() / 4).is_some());
            drop(permits);
            assert_eq!(governor.retained(), 0);
        }
        assert_eq!(parse_pacing_burst_packets(None).unwrap().get(), 64);
        for value in ["1", "32", "64", "128", "256"] {
            assert_eq!(
                parse_pacing_burst_packets(Some(value)).unwrap().get(),
                value.parse::<u16>().unwrap()
            );
        }
        for value in ["", "0", "-1", "257", "65536", "64 packets"] {
            assert!(parse_pacing_burst_packets(Some(value)).is_err(), "{value}");
        }
    }
}

#[cfg(test)]
mod idle_observer_tests {
    use super::*;
    #[test]
    fn diagnostics_are_opt_in_and_idle_backoff_is_bounded() {
        assert_eq!(quic_stats_interval_from(None), None);
        assert_eq!(quic_stats_interval_from(Some("0")), None);
        assert_eq!(quic_stats_interval_from(Some("garbage")), None);
        let mut delay = Duration::from_secs(1);
        for expected in [2, 4, 8, 8] {
            delay = quic_observer_delay(false, delay, None);
            assert_eq!(delay, Duration::from_secs(expected));
        }
        assert_eq!(
            quic_observer_delay(true, delay, None),
            Duration::from_secs(1)
        );
        assert_eq!(
            quic_observer_delay(false, delay, Some(Duration::from_millis(250))),
            Duration::from_millis(250)
        );
    }
}
