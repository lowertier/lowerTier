use std::{fmt, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use super::fast_socks5::{
    server::{AsyncTcpConnector, ProxyTcpStream},
    util::target_addr::TargetAddr,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyRequestKind {
    Connect,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyTarget {
    host: String,
    port: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedProxyRequest {
    kind: ProxyRequestKind,
    target: ProxyTarget,
    outbound_prefix: Vec<u8>,
}

#[derive(Debug)]
struct HttpProxyError {
    status_code: u16,
    reason: &'static str,
}

impl HttpProxyError {
    fn new(status_code: u16, reason: &'static str) -> Self {
        Self {
            status_code,
            reason,
        }
    }
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP proxy error {}: {}",
            self.status_code, self.reason
        )
    }
}

impl std::error::Error for HttpProxyError {}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<ProxyTarget, HttpProxyError> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        return Err(HttpProxyError::new(400, "invalid destination authority"));
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| HttpProxyError::new(400, "invalid IPv6 destination"))?;
        let host = &rest[..close];
        let suffix = &rest[close + 1..];
        let port = if suffix.is_empty() {
            default_port.ok_or_else(|| HttpProxyError::new(400, "destination port is missing"))?
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| HttpProxyError::new(400, "invalid IPv6 destination"))?
                .parse::<u16>()
                .map_err(|_| HttpProxyError::new(400, "invalid destination port"))?
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err(HttpProxyError::new(
                400,
                "IPv6 destinations must use brackets",
            ));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| HttpProxyError::new(400, "invalid destination port"))?;
        (host, port)
    } else {
        (
            authority,
            default_port.ok_or_else(|| HttpProxyError::new(400, "destination port is missing"))?,
        )
    };

    if host.is_empty() {
        return Err(HttpProxyError::new(400, "destination host is missing"));
    }

    Ok(ProxyTarget {
        host: host.to_string(),
        port,
    })
}

fn parse_request(data: &[u8]) -> Result<ParsedProxyRequest, HttpProxyError> {
    if data.len() > MAX_HEADER_BYTES {
        return Err(HttpProxyError::new(431, "request header is too large"));
    }
    let header_end = find_header_end(data)
        .ok_or_else(|| HttpProxyError::new(400, "request header is incomplete"))?;
    let header_text = std::str::from_utf8(&data[..header_end])
        .map_err(|_| HttpProxyError::new(400, "request header is not UTF-8"))?;
    let mut lines = header_text[..header_text.len() - 4].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpProxyError::new(400, "request line is missing"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| HttpProxyError::new(400, "request method is missing"))?;
    let request_target = request_parts
        .next()
        .ok_or_else(|| HttpProxyError::new(400, "request target is missing"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| HttpProxyError::new(400, "HTTP version is missing"))?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpProxyError::new(400, "invalid request line"));
    }

    let mut host_header = None;
    let mut request_headers = Vec::new();
    let mut connection_header_names = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpProxyError::new(400, "invalid request header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(HttpProxyError::new(400, "invalid request header name"));
        }
        if name.eq_ignore_ascii_case("host") && host_header.is_none() {
            host_header = Some(value.to_string());
        }
        if name.eq_ignore_ascii_case("connection") {
            connection_header_names.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }
        request_headers.push((name, value));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = parse_authority(request_target, None)?;
        return Ok(ParsedProxyRequest {
            kind: ProxyRequestKind::Connect,
            target,
            outbound_prefix: data[header_end..].to_vec(),
        });
    }

    let (target, forwarded_target) = if request_target.starts_with('/') || request_target == "*" {
        let authority = host_header
            .as_deref()
            .ok_or_else(|| HttpProxyError::new(400, "Host header is missing"))?;
        (
            parse_authority(authority, Some(80))?,
            request_target.to_string(),
        )
    } else {
        let url: url::Url = request_target
            .parse()
            .map_err(|_| HttpProxyError::new(400, "invalid absolute request target"))?;
        if url.scheme() != "http" {
            return Err(HttpProxyError::new(405, "unsupported proxy URL scheme"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| HttpProxyError::new(400, "destination host is missing"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| HttpProxyError::new(400, "destination port is missing"))?;
        let mut path = url.path().to_string();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        (
            ProxyTarget {
                host: host.to_string(),
                port,
            },
            path,
        )
    };

    let mut outbound_prefix = Vec::with_capacity(data.len());
    outbound_prefix
        .extend_from_slice(format!("{method} {forwarded_target} {version}\r\n").as_bytes());
    for (name, value) in request_headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
            || connection_header_names
                .iter()
                .any(|connection_name| name.eq_ignore_ascii_case(connection_name))
        {
            continue;
        }
        outbound_prefix.extend_from_slice(name.as_bytes());
        outbound_prefix.extend_from_slice(b": ");
        outbound_prefix.extend_from_slice(value.as_bytes());
        outbound_prefix.extend_from_slice(b"\r\n");
    }
    outbound_prefix.extend_from_slice(b"Connection: close\r\n");
    outbound_prefix.extend_from_slice(b"\r\n");
    outbound_prefix.extend_from_slice(&data[header_end..]);

    Ok(ParsedProxyRequest {
        kind: ProxyRequestKind::Forward,
        target,
        outbound_prefix,
    })
}

async fn read_request<I>(inbound: &mut I) -> Result<ParsedProxyRequest, HttpProxyError>
where
    I: AsyncRead + Unpin,
{
    timeout(REQUEST_TIMEOUT, async {
        let mut request = Vec::with_capacity(1024);
        let mut buffer = [0_u8; 2048];
        loop {
            if find_header_end(&request).is_some() {
                return parse_request(&request);
            }
            if request.len() >= MAX_HEADER_BYTES {
                return Err(HttpProxyError::new(431, "request header is too large"));
            }
            let remaining = MAX_HEADER_BYTES + 1 - request.len();
            let read_len = remaining.min(buffer.len());
            let count = inbound
                .read(&mut buffer[..read_len])
                .await
                .map_err(|_| HttpProxyError::new(400, "failed to read request header"))?;
            if count == 0 {
                return Err(HttpProxyError::new(400, "request header is incomplete"));
            }
            request.extend_from_slice(&buffer[..count]);
        }
    })
    .await
    .map_err(|_| HttpProxyError::new(408, "request header timed out"))?
}

fn connector_target(target: &ProxyTarget) -> TargetAddr {
    if let Ok(ip) = target.host.parse() {
        return TargetAddr::Ip(SocketAddr::new(ip, target.port));
    }
    TargetAddr::Domain(target.host.clone(), target.port)
}

async fn write_error<I>(inbound: &mut I, error: &HttpProxyError)
where
    I: AsyncWrite + Unpin,
{
    let reason = match error.status_code {
        400 => "Bad Request",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Proxy Error",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        error.status_code, reason
    );
    let _ = inbound.write_all(response.as_bytes()).await;
    let _ = inbound.shutdown().await;
}

pub(crate) async fn serve_http_proxy<I, C>(mut inbound: I, connector: C) -> anyhow::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send,
    C: AsyncTcpConnector,
{
    let request = match read_request(&mut inbound).await {
        Ok(request) => request,
        Err(error) => {
            write_error(&mut inbound, &error).await;
            return Err(error.into());
        }
    };
    let destination = connector_target(&request.target);
    let mut outbound = match connector
        .tcp_connect_target(destination, REQUEST_TIMEOUT.as_secs())
        .await
    {
        Ok(outbound) => outbound,
        Err(source) => {
            let error = HttpProxyError::new(502, "destination connection failed");
            write_error(&mut inbound, &error).await;
            return Err(anyhow::Error::new(source).context(error));
        }
    };

    match request.kind {
        ProxyRequestKind::Connect => {
            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !request.outbound_prefix.is_empty() {
                outbound.write_all(&request.outbound_prefix).await?;
            }
        }
        ProxyRequestKind::Forward => {
            outbound.write_all(&request.outbound_prefix).await?;
        }
    }

    outbound.transfer(&mut inbound).await.map_err(Into::into)
}
