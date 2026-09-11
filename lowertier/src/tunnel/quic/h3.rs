use std::path::{Path, PathBuf};

use anyhow::Context as _;
use bytes::{Buf as _, Bytes, BytesMut};
use quinn::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    tunnel::{
        BatchStreamItem, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacket, ZCPacketType},
        stealth_tls::ConnectIpAdmission,
    },
};

use super::{
    QUIC_RELIABLE_INITIAL_BUFFER_SIZE, QUIC_RELIABLE_MAX_PACKET_SIZE, ReliableWriteRequest,
    clone_reliable_error, connection_closed_error,
};

type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
const DATAGRAM_CONTEXT_ID: u64 = 0;
const LOWTIER_PACKET_CAPSULE_TYPE: u64 = 0x4554;
const MAX_ORIGIN_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_ORIGIN_BODY: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Welcome</title></head><body><main><h1>Welcome</h1></main></body></html>";
const NOT_FOUND_BODY: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not Found</title></head><body><h1>Not Found</h1></body></html>";

#[async_trait::async_trait]
pub(super) trait RequestStream: Send {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError>;
    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError>;
    async fn finish(&mut self) -> Result<(), TunnelError>;
}

#[async_trait::async_trait]
impl RequestStream for ClientStream {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError> {
        ClientStream::send_data(self, data)
            .await
            .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 DATA: {error}")))
    }

    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError> {
        ClientStream::recv_data(self)
            .await
            .map(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())))
            .map_err(|error| TunnelError::InternalError(format!("receive HTTP/3 DATA: {error}")))
    }

    async fn finish(&mut self) -> Result<(), TunnelError> {
        ClientStream::finish(self)
            .await
            .map_err(|error| TunnelError::InternalError(format!("finish HTTP/3 request: {error}")))
    }
}

#[async_trait::async_trait]
impl RequestStream for ServerStream {
    async fn send_data(&mut self, data: Bytes) -> Result<(), TunnelError> {
        ServerStream::send_data(self, data)
            .await
            .map_err(|error| TunnelError::InternalError(format!("send HTTP/3 DATA: {error}")))
    }

    async fn recv_data(&mut self) -> Result<Option<Bytes>, TunnelError> {
        ServerStream::recv_data(self)
            .await
            .map(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())))
            .map_err(|error| TunnelError::InternalError(format!("receive HTTP/3 DATA: {error}")))
    }

    async fn finish(&mut self) -> Result<(), TunnelError> {
        ServerStream::finish(self)
            .await
            .map_err(|error| TunnelError::InternalError(format!("finish HTTP/3 response: {error}")))
    }
}

fn stream_id(id: h3::quic::StreamId) -> u64 {
    id.index() * 4
}

pub(super) async fn open_request(
    connection: &Connection,
    authority: &str,
    bearer: Option<&str>,
) -> Result<(Box<dyn RequestStream>, u64), TunnelError> {
    let mut builder = h3::client::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true);
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
    let stream_id = stream_id(stream.id());
    let guard_connection = connection.clone();
    tokio::spawn(async move {
        let _requests = requests;
        let _ = guard_connection.closed().await;
    });
    Ok((Box::new(stream), stream_id))
}

pub(super) fn bearer(global_ctx: &ArcGlobalCtx) -> Option<String> {
    ConnectIpAdmission::from_global_ctx(global_ctx).map(|admission| admission.current_token())
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
    if !metadata.is_file() || metadata.len() > MAX_ORIGIN_FILE_BYTES {
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

async fn send_normal_response(
    request: http::Request<()>,
    mut stream: ServerStream,
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

async fn serve_additional_requests(
    mut connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    fallback_root: Option<PathBuf>,
) {
    loop {
        let resolver = match connection.accept().await {
            Ok(Some(resolver)) => resolver,
            Ok(None) | Err(_) => return,
        };
        match resolver.resolve_request().await {
            Ok((request, stream)) => {
                let fallback_root = fallback_root.clone();
                tokio::spawn(async move {
                    let _ = send_normal_response(request, stream, fallback_root).await;
                });
            }
            Err(error) => tracing::debug!(?error, "reject malformed HTTP/3 request"),
        }
    }
}

pub(super) async fn accept_request(
    connection: &Connection,
    admission: Option<&ConnectIpAdmission>,
    fallback_root: Option<PathBuf>,
) -> Result<(Box<dyn RequestStream>, u64), TunnelError> {
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(true);
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
        let authorized = admission.is_some_and(|admission| {
            request
                .headers()
                .get("proxy-authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| admission.verify_header(value))
        });
        if !is_connect_ip || !authorized {
            let fallback_root = fallback_root.clone();
            tokio::spawn(async move {
                let _ = send_normal_response(request, stream, fallback_root).await;
            });
            continue;
        }
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("capsule-protocol", "?1")
            .body(())
            .context("build CONNECT-IP response")?;
        stream.send_response(response).await.map_err(|error| {
            TunnelError::InternalError(format!("send CONNECT-IP response: {error}"))
        })?;
        let stream_id = stream_id(stream.id());
        tokio::spawn(serve_additional_requests(h3, fallback_root));
        return Ok((Box::new(stream), stream_id));
    }
}

fn put_varint_at(buffer: &mut [u8], offset: usize, value: u64) -> usize {
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

fn decode_varint(buffer: &[u8]) -> Option<(u64, usize)> {
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

pub(super) fn datagram_overhead(stream_id: u64) -> usize {
    let quarter_stream_id = stream_id / 4;
    let quarter_length = match quarter_stream_id {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    quarter_length + 1
}

pub(super) fn encode_datagram(packet: ZCPacket, stream_id: u64) -> Bytes {
    let mut prefix = [0_u8; 18];
    let mut length = put_varint_at(&mut prefix, 0, stream_id / 4);
    length += put_varint_at(&mut prefix, length, DATAGRAM_CONTEXT_ID);
    packet.tunnel_payload_with_prefix_into_bytes(&prefix[..length])
}

pub(super) fn decode_datagram(bytes: Bytes, stream_id: u64) -> Result<ZCPacket, TunnelError> {
    let (quarter_stream_id, quarter_length) = decode_varint(&bytes).ok_or_else(|| {
        TunnelError::InvalidPacket("HTTP/3 DATAGRAM has no Quarter Stream ID".to_owned())
    })?;
    let (context_id, context_length) =
        decode_varint(&bytes[quarter_length..]).ok_or_else(|| {
            TunnelError::InvalidPacket("CONNECT-IP DATAGRAM has no Context ID".to_owned())
        })?;
    if quarter_stream_id != stream_id / 4 || context_id != DATAGRAM_CONTEXT_ID {
        return Err(TunnelError::InvalidPacket(
            "CONNECT-IP DATAGRAM has an unexpected request context".to_owned(),
        ));
    }
    let header_length = quarter_length + context_length;
    if bytes.len().saturating_sub(header_length) < PEER_MANAGER_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(
            "CONNECT-IP DATAGRAM payload is too short".to_owned(),
        ));
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

fn put_varint(buffer: &mut BytesMut, value: u64) {
    let mut scratch = [0_u8; 8];
    let length = put_varint_at(&mut scratch, 0, value);
    buffer.extend_from_slice(&scratch[..length]);
}

fn encode_packet_capsule(packet: ZCPacket) -> Result<Bytes, TunnelError> {
    let body = packet.tunnel_payload_into_bytes();
    if body.len() < PEER_MANAGER_HEADER_SIZE || body.len() > QUIC_RELIABLE_MAX_PACKET_SIZE {
        return Err(TunnelError::InvalidPacket(
            "CONNECT-IP capsule packet has an invalid length".to_owned(),
        ));
    }
    let mut capsule = BytesMut::with_capacity(16 + body.len());
    put_varint(&mut capsule, LOWTIER_PACKET_CAPSULE_TYPE);
    put_varint(&mut capsule, body.len() as u64);
    capsule.extend_from_slice(&body);
    Ok(capsule.freeze())
}

fn decode_packet_capsules(buffer: &mut BytesMut) -> Result<PacketBatch, TunnelError> {
    let mut batch = PacketBatch::new();
    while batch.len() < MAX_PACKET_BATCH_SIZE {
        let Some((capsule_type, type_length)) = decode_varint(buffer) else {
            break;
        };
        let Some((payload_length, length_length)) = decode_varint(&buffer[type_length..]) else {
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

pub(super) async fn run_reliable_lane(
    connection: Connection,
    mut stream: Box<dyn RequestStream>,
    mut outgoing: mpsc::Receiver<ReliableWriteRequest>,
    incoming: mpsc::Sender<BatchStreamItem>,
    writer_done: oneshot::Sender<Result<(), TunnelError>>,
) -> Result<(), TunnelError> {
    let mut receive_buffer = BytesMut::with_capacity(QUIC_RELIABLE_INITIAL_BUFFER_SIZE);
    let mut outgoing_open = true;
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
            data = stream.recv_data() => {
                let Some(data) = data? else {
                    return Ok(());
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
