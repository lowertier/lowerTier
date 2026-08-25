use std::{fmt, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use super::fast_socks5::{server::AsyncTcpConnector, util::target_addr::TargetAddr};

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

    fn status_code(&self) -> u16 {
        self.status_code
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
    I: AsyncRead + AsyncWrite + Unpin,
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

    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::fast_socks5::{
        Result, server::AsyncTcpConnector, util::target_addr::TargetAddr,
    };
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    struct DirectConnector;

    #[async_trait::async_trait]
    impl AsyncTcpConnector for DirectConnector {
        type S = TcpStream;

        async fn tcp_connect(&self, addr: SocketAddr, _timeout_s: u64) -> Result<Self::S> {
            Ok(TcpStream::connect(addr).await?)
        }
    }

    struct DomainConnector {
        destination: SocketAddr,
    }

    #[async_trait::async_trait]
    impl AsyncTcpConnector for DomainConnector {
        type S = TcpStream;

        async fn tcp_connect(&self, _addr: SocketAddr, _timeout_s: u64) -> Result<Self::S> {
            panic!("the proxy resolved the target before the central dialer");
        }

        async fn tcp_connect_target(&self, target: TargetAddr, _timeout_s: u64) -> Result<Self::S> {
            assert_eq!(target, TargetAddr::Domain("peer.et.net".to_string(), 443));
            Ok(TcpStream::connect(self.destination).await?)
        }
    }

    #[test]
    fn parses_connect_authority() {
        let parsed =
            parse_request(b"CONNECT node.example:443 HTTP/1.1\r\nHost: node.example:443\r\n\r\n")
                .unwrap();

        assert_eq!(parsed.kind, ProxyRequestKind::Connect);
        assert_eq!(parsed.target.host, "node.example");
        assert_eq!(parsed.target.port, 443);
        assert!(parsed.outbound_prefix.is_empty());
    }

    #[test]
    fn parses_bracketed_ipv6_connect_authority() {
        let parsed =
            parse_request(b"CONNECT [fd00::2]:8443 HTTP/1.1\r\nHost: [fd00::2]:8443\r\n\r\n")
                .unwrap();

        assert_eq!(parsed.target.host, "fd00::2");
        assert_eq!(parsed.target.port, 8443);
    }

    #[test]
    fn rewrites_absolute_http_request_and_removes_proxy_headers() {
        let parsed = parse_request(
            b"GET http://node.example:8080/status?q=1 HTTP/1.1\r\nHost: node.example:8080\r\nProxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();

        assert_eq!(parsed.kind, ProxyRequestKind::Forward);
        assert_eq!(parsed.target.host, "node.example");
        assert_eq!(parsed.target.port, 8080);
        assert_eq!(
            String::from_utf8(parsed.outbound_prefix).unwrap(),
            "GET /status?q=1 HTTP/1.1\r\nHost: node.example:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn uses_host_header_for_origin_form_request() {
        let parsed = parse_request(b"GET /health HTTP/1.1\r\nHost: node.example\r\n\r\n").unwrap();

        assert_eq!(parsed.target.host, "node.example");
        assert_eq!(parsed.target.port, 80);
    }

    #[test]
    fn rejects_request_without_destination() {
        let error = parse_request(b"GET /health HTTP/1.1\r\nAccept: */*\r\n\r\n").unwrap_err();

        assert_eq!(error.status_code(), 400);
    }

    #[test]
    fn rejects_unsupported_absolute_scheme() {
        let error =
            parse_request(b"GET ftp://node.example/file HTTP/1.1\r\nHost: node.example\r\n\r\n")
                .unwrap_err();

        assert_eq!(error.status_code(), 405);
    }

    #[test]
    fn rejects_large_headers() {
        let request = vec![b'a'; MAX_HEADER_BYTES + 1];

        let error = parse_request(&request).unwrap_err();

        assert_eq!(error.status_code(), 431);
    }

    #[tokio::test]
    async fn connect_relays_bytes_in_both_directions() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let (mut client, server) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(serve_http_proxy(server, DirectConnector));

        client
            .write_all(
                format!("CONNECT {destination_addr} HTTP/1.1\r\nHost: {destination_addr}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        client.shutdown().await.unwrap();

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_passes_domain_to_central_dialer() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
        });
        let (mut client, server) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(serve_http_proxy(
            server,
            DomainConnector {
                destination: destination_addr,
            },
        ));

        client
            .write_all(b"CONNECT peer.et.net:443 HTTP/1.1\r\nHost: peer.et.net:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_proxy_rewrites_request_for_destination() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /health HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (mut client, server) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(serve_http_proxy(server, DirectConnector));

        client
            .write_all(
                format!(
                    "GET http://{destination_addr}/health HTTP/1.1\r\nHost: {destination_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_request_gets_standard_http_error() {
        let (mut client, server) = tokio::io::duplex(1024);
        let proxy_task = tokio::spawn(serve_http_proxy(server, DirectConnector));

        client
            .write_all(b"GET /missing-host HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(proxy_task.await.unwrap().is_err());
    }
}
