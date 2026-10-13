use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use super::FromUrl;
use crate::{
    common::underlay_policy::UnderlayPolicy,
    tunnel::common::{
        apply_socket_mark, bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
    },
};
use async_trait::async_trait;
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use super::{IpVersion, Tunnel, TunnelError, TunnelListener, common::wait_for_connect_futures};

const MAX_PENDING_ACCEPTS: usize = 32;
const MAX_PENDING_ACCEPTS_PER_IP: usize = 4;
type PendingAccept = BoxFuture<'static, (IpAddr, Result<Option<Box<dyn Tunnel>>, TunnelError>)>;

pub struct TcpTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
    underlay_policy: Arc<UnderlayPolicy>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    lanes: tokio::sync::Mutex<super::tcp_lanes::LaneListener>,
    flags: crate::common::config::Flags,
    pending: Mutex<FuturesUnordered<PendingAccept>>,
    pending_by_ip: HashMap<IpAddr, usize>,
}

impl std::fmt::Debug for TcpTunnelListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTunnelListener")
            .field("addr", &self.addr)
            .field("listener", &self.listener)
            .field("socket_mark", &self.socket_mark)
            .finish()
    }
}

impl TcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
            tls_acceptor: None,
            lanes: tokio::sync::Mutex::default(),
            flags: crate::common::config::gen_default_flags(),
            pending: Mutex::new(FuturesUnordered::new()),
            pending_by_ip: HashMap::new(),
        }
    }
    pub fn set_flags(&mut self, flags: crate::common::config::Flags) {
        self.flags = flags;
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub fn set_underlay_policy(&mut self, underlay_policy: Arc<UnderlayPolicy>) {
        self.underlay_policy = underlay_policy;
    }

    fn start_accept(&mut self, stream: TcpStream, remote: SocketAddr) -> Result<(), TunnelError> {
        ensure_remote_allowed(&self.underlay_policy, remote)?;
        let ip = remote.ip();
        if self.pending.get_mut().unwrap().len() >= MAX_PENDING_ACCEPTS
            || self.pending_by_ip.get(&ip).copied().unwrap_or(0) >= MAX_PENDING_ACCEPTS_PER_IP
        {
            return Ok(());
        }
        let acceptor = self
            .tls_acceptor
            .as_ref()
            .ok_or_else(|| {
                TunnelError::InternalError("HTTP/2 TCP listener has no TLS acceptor".into())
            })?
            .clone();
        let url = self.local_url();
        let flags = self.flags.clone();
        *self.pending_by_ip.entry(ip).or_default() += 1;
        self.pending.get_mut().unwrap().push(Box::pin(async move {
            (
                ip,
                super::http2::accept(stream, &acceptor, url, &flags).await,
            )
        }));
        Ok(())
    }
}

#[async_trait]
impl TunnelListener for TcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        self.listener = None;
        *self.pending.get_mut().unwrap() = FuturesUnordered::new();
        self.pending_by_ip.clear();
        {
            super::tcp_lanes::requested(&self.addr)?;
            *self.lanes.get_mut() = Default::default();
        }

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
        {
            self.tls_acceptor = Some(super::http2::tls_acceptor(&self.flags)?);
        }
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let lane_count = super::tcp_lanes::requested(&self.addr)?;
        loop {
            self.lanes.get_mut().expire();
            let pending = self.pending.get_mut().unwrap();
            let completed = tokio::select! {
                biased;
                completed = pending.next(), if !pending.is_empty() => completed,
                accepted = self.listener.as_ref().unwrap().accept() => {
                    let (stream, remote) = accepted?;
                    if let Err(error) = self.start_accept(stream, remote) {
                        tracing::debug!(?error, "HTTP/2 admission rejected");
                    }
                    continue;
                }
                _ = tokio::time::sleep(super::tcp_lanes::JOIN_TIMEOUT), if lane_count > 1 => continue,
            };
            let Some((ip, result)) = completed else {
                continue;
            };
            if let Some(count) = self.pending_by_ip.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    self.pending_by_ip.remove(&ip);
                }
            }
            match result {
                Ok(Some(ret)) => {
                    if lane_count > 1 {
                        match self.lanes.get_mut().accept(ret, lane_count).await {
                            Ok(Some(tunnel)) => return Ok(tunnel),
                            Ok(None) => continue,
                            Err(error) => {
                                tracing::warn!(?error, "TCP lane join rejected");
                                continue;
                            }
                        }
                    }
                    return Ok(ret);
                }
                Ok(None) => continue,
                Err(error) => tracing::debug!(?error, "HTTP/2 admission failed"),
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

async fn get_tunnel_with_tcp_stream(
    stream: TcpStream,
    remote_url: url::Url,
    flags: &crate::common::config::Flags,
) -> Result<Box<dyn Tunnel>, super::TunnelError> {
    super::http2::connect(stream, remote_url, flags).await
}

#[derive(Debug)]
pub struct TcpTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
    underlay_policy: Arc<UnderlayPolicy>,
    flags: crate::common::config::Flags,
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
            flags: crate::common::config::gen_default_flags(),
        }
    }
    pub fn set_flags(&mut self, flags: crate::common::config::Flags) {
        self.flags = flags;
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(url = ?self.addr, ?addr, "connect tcp start, bind addrs: {:?}", self.bind_addrs);
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_socket_mark(&socket2::SockRef::from(&socket), self.socket_mark)?;
        super::common::size_tcp_socket_buffers(&socket2::SockRef::from(&socket));
        let stream = socket.connect(addr).await?;
        ensure_local_allowed(&self.underlay_policy, stream.local_addr()?)?;
        ensure_remote_allowed(&self.underlay_policy, stream.peer_addr()?)?;
        tracing::info!(url = ?self.addr, ?addr, "connect tcp succ");
        get_tunnel_with_tcp_stream(stream, self.addr.clone(), &self.flags).await
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in bind_addrs {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind::<TcpSocket>()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => {
                    super::common::size_tcp_socket_buffers(&socket2::SockRef::from(&socket));
                    futures.push(socket.connect(addr));
                }
                Err(error) => {
                    tracing::error!(?bind_addr, ?addr, ?error, "bind addr fail");
                    continue;
                }
            }
        }

        let stream = wait_for_connect_futures(futures).await?;
        ensure_local_allowed(&self.underlay_policy, stream.local_addr()?)?;
        ensure_remote_allowed(&self.underlay_policy, stream.peer_addr()?)?;
        get_tunnel_with_tcp_stream(stream, self.addr.clone(), &self.flags).await
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
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

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
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
mod tests {
    use super::*;
    use crate::tunnel::TunnelConnector;

    #[tokio::test]
    async fn tcp_http2_exports_a_tls_binding() {
        use crate::tunnel::TransportBindingKind;

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_addr = listener.local_url();
        // An idle client must not delay a separate TLS and CONNECT handshake.
        let _idle = TcpStream::connect(
            SocketAddr::from_url(listener_addr.clone(), IpVersion::Both)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });

        let mut connector = TcpTunnelConnector::new(listener_addr);
        let client = tokio::time::timeout(std::time::Duration::from_secs(2), connector.connect())
            .await
            .unwrap()
            .unwrap();
        let server = server.await.unwrap();

        assert_eq!(client.transport_binding(), server.transport_binding());
        assert_eq!(
            client.transport_binding().map(|binding| binding.kind),
            Some(TransportBindingKind::Http2TlsExporterV1)
        );
    }

    #[tokio::test]
    async fn http2_admission_deadline_covers_tls_and_connect() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(13), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let flags = crate::common::config::gen_default_flags();
            let acceptor = super::super::http2::tls_acceptor(&flags).unwrap();
            let server = tokio::spawn(async move {
                let mut pending = FuturesUnordered::new();
                for _ in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    let flags = flags.clone();
                    pending.push(tokio::spawn(async move {
                        let error = super::super::http2::accept(
                            stream,
                            &acceptor,
                            format!("tcp://{addr}").parse().unwrap(),
                            &flags,
                        )
                        .await
                        .err()
                        .unwrap();
                        assert!(error.to_string().contains("admission timed out"));
                    }));
                }
                while let Some(result) = pending.next().await {
                    result.unwrap();
                }
            });
            let mut idle = TcpStream::connect(addr).await.unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();
            let tls = super::super::browser_tls::connect(stream, "localhost", &[b"h2"], false)
                .await
                .unwrap();
            let (_requests, connection) = h2::client::handshake(tls).await.unwrap();
            let connection = tokio::spawn(connection);
            let mut byte = [0; 1];
            assert_eq!(idle.read(&mut byte).await.unwrap(), 0);
            let _ = connection.await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tcp_http2_carries_a_framed_packet() {
        use crate::tunnel::{Tunnel, batch::PacketBatch, packet_def::ZCPacket};
        use futures::{SinkExt, StreamExt};

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_addr = listener.local_url();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });

        let mut connector = TcpTunnelConnector::new(listener_addr);
        let client = connector.connect().await.unwrap();
        let server = server.await.unwrap();

        let payload = b"http2-tcp";
        let (mut client_recv, mut client_send) = client.split();
        let (mut server_recv, mut server_send) = server.split();

        client_send
            .send(PacketBatch::singleton(ZCPacket::new_with_payload(payload)))
            .await
            .unwrap();
        let got = server_recv
            .next()
            .await
            .unwrap()
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(got.payload(), &payload[..]);

        server_send
            .send(PacketBatch::singleton(ZCPacket::new_with_payload(payload)))
            .await
            .unwrap();
        let got = client_recv
            .next()
            .await
            .unwrap()
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(got.payload(), &payload[..]);
    }

    #[tokio::test]
    async fn tcp_http2_preserves_coalesced_frames() {
        use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};
        use futures::{SinkExt, StreamExt};

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_addr = listener.local_url();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = TcpTunnelConnector::new(listener_addr);
        let client = connector.connect().await.unwrap();
        let server = server.await.unwrap();
        let (mut client_recv, mut client_send) = client.split();
        let (mut server_recv, mut server_send) = server.split();
        let count = 257_u32;

        let client = async {
            for sequence in 0..count {
                let mut payload = vec![sequence as u8; 33 + sequence as usize % 4 * 443];
                payload[..4].copy_from_slice(&sequence.to_le_bytes());
                client_send
                    .feed(PacketBatch::singleton(ZCPacket::new_with_payload(&payload)))
                    .await
                    .unwrap();
            }
            client_send.flush().await.unwrap();
            let mut received = 0_u32;
            while received < count {
                let batch = client_recv.next().await.unwrap().unwrap();
                for packet in batch.into_vec() {
                    let payload = packet.payload();
                    assert_eq!(payload.len(), 33 + received as usize % 4 * 443);
                    assert_eq!(&payload[..4], &received.to_le_bytes());
                    assert!(payload[4..].iter().all(|&byte| byte == received as u8));
                    received += 1;
                }
            }
            assert_eq!(received, count);
        };
        let server = async {
            let mut received = 0;
            while received < count as usize {
                let batch = server_recv.next().await.unwrap().unwrap();
                received += batch.len();
                server_send.feed(batch).await.unwrap();
            }
            assert_eq!(received, count as usize);
            server_send.flush().await.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(client, server);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn http2_skips_the_routing_prefix_behind_sni_passthrough() {
        use crate::tunnel::TransportBindingKind;

        let mut flags = crate::common::config::gen_default_flags();
        flags.quic_server_name = "challenges.cloudflare.com".to_owned();
        flags.quic_decoy_upstream = "127.0.0.1:9".to_owned();
        flags.quic_admission_secret = "routing-test-secret-material".to_owned();
        flags.quic_sni_passthrough = true;

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.set_flags(flags.clone());
        listener.listen().await.unwrap();
        let listener_addr = listener.local_url();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });

        let mut connector = TcpTunnelConnector::new(listener_addr);
        connector.set_flags(flags);
        let client = connector.connect().await.unwrap();
        let server = server.await.unwrap();

        assert_eq!(
            client.transport_binding().map(|binding| binding.kind),
            Some(TransportBindingKind::Http2TlsExporterV1)
        );
        assert_eq!(client.transport_binding(), server.transport_binding());
    }

    #[tokio::test]
    async fn unmarked_tcp_is_passed_through_to_decoy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let decoy_task = tokio::spawn(async move {
            let (mut stream, _) = decoy.accept().await.unwrap();
            let mut buf = vec![0_u8; 64];
            stream.read_exact(&mut buf).await.unwrap();
            let _ = seen_tx.send(buf);
        });

        let mut flags = crate::common::config::gen_default_flags();
        flags.quic_server_name = "challenges.cloudflare.com".to_owned();
        flags.quic_decoy_upstream = decoy_addr.to_string();
        flags.quic_admission_secret = "routing-test-secret-material".to_owned();

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.set_flags(flags);
        listener.listen().await.unwrap();
        let listen_addr = listener.local_url();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut probe = TcpStream::connect(format!(
            "{}:{}",
            listen_addr.host_str().unwrap(),
            listen_addr.port().unwrap()
        ))
        .await
        .unwrap();
        // A browser ClientHello starts 16 03 01 <length≠8>, so the listener
        // must splice those bytes intact to the decoy host.
        let payload = [0x16_u8; 64];
        probe.write_all(&payload).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), seen_rx)
            .await
            .expect("decoy did not receive the spliced probe")
            .unwrap();
        assert_eq!(received, payload);

        accept.abort();
        decoy_task.abort();
    }

    const CAMOUFLAGE_HOST: &str = "challenges.cloudflare.com";

    struct TcpPassthrough {
        public: SocketAddr,
        _nginx: Option<std::process::Child>,
        _task: Option<tokio::task::JoinHandle<()>>,
        _dir: Option<tempfile::TempDir>,
    }

    impl Drop for TcpPassthrough {
        fn drop(&mut self) {
            if let Some(child) = &mut self._nginx {
                let _ = child.kill();
                let _ = child.wait();
            }
            if let Some(task) = &self._task {
                task.abort();
            }
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

    fn start_nginx_tcp_passthrough(backend: SocketAddr) -> Option<TcpPassthrough> {
        let nginx = nginx_binary()?;
        let dir = tempfile::tempdir().ok()?;
        let public = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?;
        let conf = dir.path().join("nginx.conf");
        let error = dir.path().join("error.log");
        let pid = dir.path().join("nginx.pid");
        std::fs::write(
            &conf,
            format!(
                "daemon off;\nerror_log {};\npid {};\nevents {{ worker_connections 64; }}\nstream {{\n    server {{\n        listen {};\n        proxy_pass {};\n        proxy_timeout 60s;\n    }}\n}}\n",
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
            if std::net::TcpListener::bind(public).is_err() {
                return Some(TcpPassthrough {
                    public,
                    _nginx: Some(child),
                    _task: None,
                    _dir: Some(dir),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    async fn start_tokio_tcp_passthrough(backend: SocketAddr) -> TcpPassthrough {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let Ok(mut upstream) = TcpStream::connect(backend).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        TcpPassthrough {
            public,
            _nginx: None,
            _task: Some(task),
            _dir: None,
        }
    }

    async fn start_tcp_passthrough(backend: SocketAddr) -> TcpPassthrough {
        if let Some(proxy) = start_nginx_tcp_passthrough(backend) {
            return proxy;
        }
        start_tokio_tcp_passthrough(backend).await
    }

    #[tokio::test]
    async fn live_challenges_cloudflare_probe_through_tcp_passthrough() {
        let upstream = tokio::net::lookup_host((CAMOUFLAGE_HOST, 443))
            .await
            .expect("resolve challenges.cloudflare.com")
            .find(SocketAddr::is_ipv4)
            .expect("challenges.cloudflare.com has IPv4");

        let mut flags = crate::common::config::gen_default_flags();
        flags.quic_server_name = CAMOUFLAGE_HOST.to_owned();
        flags.quic_decoy_upstream = upstream.to_string();
        flags.quic_admission_secret = "routing-test-secret-material".to_owned();

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.set_flags(flags);
        listener.listen().await.unwrap();
        let backend = SocketAddr::new(
            listener.local_url().host_str().unwrap().parse().unwrap(),
            listener.local_url().port().unwrap(),
        );
        let proxy = start_tcp_passthrough(backend).await;
        let accept = tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let mut probe_flags = crate::common::config::gen_default_flags();
        probe_flags.quic_server_name = CAMOUFLAGE_HOST.to_owned();
        let tls_config =
            crate::tunnel::stealth_tls::rustls_client_config(&probe_flags, &[b"h2", b"http/1.1"])
                .unwrap();
        let stream = TcpStream::connect(proxy.public).await.unwrap();
        let tls = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(
                rustls::pki_types::ServerName::try_from(CAMOUFLAGE_HOST).unwrap(),
                stream,
            ),
        )
        .await
        .expect("probe handshake through passthrough")
        .expect("probe TLS to challenges.cloudflare.com");
        assert!(
            tls.get_ref()
                .1
                .peer_certificates()
                .is_some_and(|certs| !certs.is_empty()),
            "Cloudflare must present a certificate"
        );

        accept.abort();
        drop(proxy);
    }

    #[tokio::test]
    async fn http2_keeps_delivery_through_tcp_passthrough() {
        use crate::tunnel::{
            Tunnel,
            batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
            packet_def::{PEER_MANAGER_HEADER_SIZE, PacketType, ZCPacket},
        };
        use futures::{SinkExt, StreamExt};
        use std::time::{Duration, Instant};

        async fn measure(passthrough: bool) -> (f64, f64, Duration) {
            const PACKETS: usize = 20_000;
            const PAYLOAD: usize = 1200;
            let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut flags = crate::common::config::gen_default_flags();
            flags.quic_server_name = CAMOUFLAGE_HOST.to_owned();
            flags.quic_decoy_upstream = decoy.local_addr().unwrap().to_string();
            flags.quic_admission_secret = "routing-test-secret-material".to_owned();

            let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
            listener.set_flags(flags.clone());
            listener.listen().await.unwrap();
            let backend = SocketAddr::new(
                listener.local_url().host_str().unwrap().parse().unwrap(),
                listener.local_url().port().unwrap(),
            );
            let proxy = if passthrough {
                Some(start_tcp_passthrough(backend).await)
            } else {
                None
            };
            let remote = match &proxy {
                Some(proxy) => format!("tcp://{}", proxy.public).parse().unwrap(),
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
            let mut connector = TcpTunnelConnector::new(remote);
            connector.set_flags(flags);
            let tunnel = connector.connect().await.unwrap();
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

        let (direct_rate, direct_delivery, direct_elapsed) = measure(false).await;
        let (proxy_rate, proxy_delivery, proxy_elapsed) = measure(true).await;
        assert!(
            direct_delivery > 50.0,
            "direct HTTP/2 delivered {direct_delivery:.1}%"
        );
        assert!(
            proxy_delivery > 50.0,
            "passthrough HTTP/2 delivered {proxy_delivery:.1}%"
        );
        if std::env::var_os("LOWTIER_BENCH").is_some() {
            eprintln!(
                "HTTP/2 camouflage direct: {direct_rate:.1} Mbit/s, {direct_delivery:.1}% in {direct_elapsed:?}"
            );
            eprintln!(
                "HTTP/2 camouflage through TCP passthrough: {proxy_rate:.1} Mbit/s, {proxy_delivery:.1}% in {proxy_elapsed:?}"
            );
        }
    }
}
