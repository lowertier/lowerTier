//! TCP proxy bodies carried by independent HTTP/3 CONNECT streams on the
//! already authenticated QUIC connection. Packet forwarding remains separate.
use super::H3ServerStream;
use crate::common::global_ctx::{ArcGlobalCtx, ProcessMemoryPermit};
use crate::common::stats_manager::{CounterHandle, MetricName};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};

pub(crate) const FEATURE: &str = "quic-tcp-proxy-v1";
// Covered by the existing Noise admission-context hash. Missing on old peers.
pub(crate) const RECEIVE_CAPABILITY: u64 = 1;
const SOURCE_HEADER: &str = "lowertier-proxy-v1";
const COPY_BYTES: usize = 32 * 1024;
const MAX_STREAMS: usize = 32;
type Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientSend = h3::client::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::SendStream,
    Bytes,
>;
type ClientRecv = h3::client::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::RecvStream,
    Bytes,
>;
type ServerSend = h3::server::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::SendStream,
    Bytes,
>;
type ServerRecv = h3::server::RequestStream<
    <h3_quinn::BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::RecvStream,
    Bytes,
>;
fn error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

pub struct ProxyEndpoint {
    requests: Option<Mutex<Requests>>,
    incoming: mpsc::Sender<IncomingProxy>,
    receiver: Mutex<Option<mpsc::Receiver<IncomingProxy>>>,
    authenticated: AtomicBool,
    slots: Arc<Semaphore>,
    context: ArcGlobalCtx,
    tx_bytes: CounterHandle,
    rx_bytes: CounterHandle,
    opened: CounterHandle,
}
impl ProxyEndpoint {
    pub(super) fn new(requests: Option<Requests>, context: ArcGlobalCtx) -> Arc<Self> {
        let (incoming, receiver) = mpsc::channel(2);
        let stats = context.stats_manager();
        let tx_bytes = stats.get_simple_counter(MetricName::TcpStreamProxyTxBytes);
        let rx_bytes = stats.get_simple_counter(MetricName::TcpStreamProxyRxBytes);
        let opened = stats.get_simple_counter(MetricName::TcpStreamProxyOpen);
        Arc::new(Self {
            tx_bytes,
            rx_bytes,
            opened,
            requests: requests.map(Mutex::new),
            incoming,
            receiver: Mutex::new(Some(receiver)),
            authenticated: AtomicBool::new(false),
            slots: Arc::new(Semaphore::new(MAX_STREAMS)),
            context,
        })
    }
    pub(crate) fn authenticated(&self, value: bool) {
        self.authenticated.store(value, Ordering::Release);
    }
    pub(crate) fn take_incoming(&self) -> Option<mpsc::Receiver<IncomingProxy>> {
        self.receiver.lock().unwrap().take()
    }
    fn check(&self) -> io::Result<()> {
        if !self.authenticated.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy peer is no longer authenticated",
            ));
        }
        // The packet path retains ACL connection tracking/rate semantics. If an
        // ACL is enabled while a direct stream is live, stop the stream too.
        if self.context.get_acl_filter().is_enabled() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy policy changed; reconnect through the packet path",
            ));
        }
        Ok(())
    }
    fn reserve(&self) -> io::Result<StreamPermit> {
        let slot = self.slots.clone().try_acquire_owned().map_err(error)?;
        let memory = self
            .context
            .process_memory_governor()
            .try_reserve_owned(COPY_BYTES * 2)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "TCP proxy memory budget exhausted",
                )
            })?;
        Ok(StreamPermit {
            _slot: slot,
            _memory: memory,
        })
    }
    pub(crate) async fn connect(
        self: &Arc<Self>,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<ProxyStream>> {
        let Some(requests) = &self.requests else {
            return Ok(None);
        };
        if self.context.get_acl_filter().is_enabled() {
            return Ok(None);
        }
        self.check()?;
        let permit = self.reserve()?;
        let mut requests = requests.lock().unwrap().clone();
        let uri = http::Uri::builder()
            .authority(destination.to_string())
            .build()
            .map_err(error)?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .header(SOURCE_HEADER, source.to_string())
            .body(())
            .map_err(error)?;
        let mut stream = requests.send_request(request).await.map_err(error)?;
        let response = stream.recv_response().await.map_err(error)?;
        if response.status() == http::StatusCode::NOT_IMPLEMENTED {
            // A peer with ACLs or a destination outside this direct scope uses
            // the original packet path, with all its routing/policy checks.
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Ok(None);
        }
        if response.status() != http::StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("TCP proxy refused: {}", response.status()),
            ));
        }
        self.check()?;
        let (send, recv) = stream.split();
        Ok(Some(ProxyStream::new(
            SendHalf::Client(send),
            RecvHalf::Client(recv),
            self.clone(),
            permit,
        )))
    }
    pub(super) fn is_request(request: &http::Request<()>) -> bool {
        request.method() == http::Method::CONNECT
            && request.headers().contains_key(SOURCE_HEADER)
            && request.extensions().get::<h3::ext::Protocol>().is_none()
    }
    pub(super) async fn receive(
        self: Arc<Self>,
        request: http::Request<()>,
        stream: H3ServerStream,
    ) -> Result<(), super::TunnelError> {
        let source = request
            .headers()
            .get(SOURCE_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        let destination = request
            .uri()
            .authority()
            .and_then(|value| value.as_str().parse().ok());
        let status = if !self.authenticated.load(Ordering::Acquire) {
            Some(http::StatusCode::NOT_FOUND)
        } else if self.context.get_acl_filter().is_enabled() {
            Some(http::StatusCode::NOT_IMPLEMENTED)
        } else if source.is_none() || destination.is_none() {
            Some(http::StatusCode::BAD_REQUEST)
        } else {
            None
        };
        if let Some(status) = status {
            return reject(stream, status).await;
        }
        let permit = match self.reserve() {
            Ok(permit) => permit,
            Err(_) => return reject(stream, http::StatusCode::SERVICE_UNAVAILABLE).await,
        };
        let incoming = IncomingProxy {
            source: source.unwrap(),
            destination: destination.unwrap(),
            stream,
            endpoint: self.clone(),
            permit,
        };
        if let Err(error) = self.incoming.try_send(incoming) {
            return reject(
                error.into_inner().stream,
                http::StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }
        Ok(())
    }
}
async fn reject(
    mut stream: H3ServerStream,
    status: http::StatusCode,
) -> Result<(), super::TunnelError> {
    stream
        .send_response(
            http::Response::builder()
                .status(status)
                .body(())
                .map_err(error)?,
        )
        .await
        .map_err(error)?;
    stream.finish().await.map_err(error)?;
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    Ok(())
}
struct StreamPermit {
    _slot: OwnedSemaphorePermit,
    _memory: ProcessMemoryPermit,
}
pub(crate) struct IncomingProxy {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    stream: H3ServerStream,
    endpoint: Arc<ProxyEndpoint>,
    permit: StreamPermit,
}
impl IncomingProxy {
    pub(crate) async fn reject(self, status: http::StatusCode) -> Result<(), super::TunnelError> {
        reject(self.stream, status).await
    }
    pub(crate) async fn accept(mut self) -> io::Result<ProxyStream> {
        self.endpoint.check()?;
        self.stream
            .send_response(
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .body(())
                    .map_err(error)?,
            )
            .await
            .map_err(error)?;
        let (send, recv) = self.stream.split();
        Ok(ProxyStream::new(
            SendHalf::Server(send),
            RecvHalf::Server(recv),
            self.endpoint,
            self.permit,
        ))
    }
}
enum SendHalf {
    Client(ClientSend),
    Server(ServerSend),
}
impl SendHalf {
    async fn data(&mut self, data: Bytes) -> io::Result<()> {
        match self {
            Self::Client(s) => s.send_data(data).await.map_err(error),
            Self::Server(s) => s.send_data(data).await.map_err(error),
        }
    }
    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Client(s) => s.finish().await.map_err(error),
            Self::Server(s) => s.finish().await.map_err(error),
        }
    }
}
enum RecvHalf {
    Client(ClientRecv),
    Server(ServerRecv),
}
impl RecvHalf {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match self {
            Self::Client(s) => s.poll_recv_data(cx).map(|result| {
                result
                    .map(|data| data.map(|mut b| b.copy_to_bytes(b.remaining())))
                    .map_err(error)
            }),
            Self::Server(s) => s.poll_recv_data(cx).map(|result| {
                result
                    .map(|data| data.map(|mut b| b.copy_to_bytes(b.remaining())))
                    .map_err(error)
            }),
        }
    }
}
type PendingWrite = Pin<Box<dyn Future<Output = (SendHalf, io::Result<()>)> + Send>>;
struct WriteState {
    send: Option<SendHalf>,
    pending: Option<PendingWrite>,
    finished: bool,
}
impl WriteState {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(pending) = &mut self.pending {
            let (send, result) = ready!(pending.as_mut().poll(cx));
            self.pending = None;
            self.send = Some(send);
            result?;
        }
        Poll::Ready(Ok(()))
    }
}
/// A bounded byte stream: no packet queue, inner TCP stack, or retry protocol.
/// The mutex only makes the stored Send future Sync; I/O uses exclusive access.
pub struct ProxyStream {
    recv: RecvHalf,
    current: Bytes,
    write: Mutex<WriteState>,
    endpoint: Arc<ProxyEndpoint>,
    _permit: StreamPermit,
}
impl ProxyStream {
    fn new(
        send: SendHalf,
        recv: RecvHalf,
        endpoint: Arc<ProxyEndpoint>,
        permit: StreamPermit,
    ) -> Self {
        endpoint.opened.inc();
        Self {
            recv,
            current: Bytes::new(),
            write: Mutex::new(WriteState {
                send: Some(send),
                pending: None,
                finished: false,
            }),
            endpoint,
            _permit: permit,
        }
    }
    /// SOCKS transfers retain owned HTTP/3 chunks and read upload bytes directly
    /// into their send allocation. HTTP adapters can use AsyncRead/AsyncWrite.
    pub(crate) fn copy_owned<'a, I>(
        mut self,
        inbound: &'a mut I,
    ) -> futures::future::BoxFuture<'a, io::Result<(u64, u64)>>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'a,
    {
        Box::pin(async move {
            futures::future::poll_fn(|cx| self.write.get_mut().unwrap().poll_pending(cx)).await?;
            let mut send = self.write.get_mut().unwrap().send.take().unwrap();
            let (mut read, mut write) = tokio::io::split(inbound);
            let endpoint = self.endpoint.clone();
            let upload = async move {
                let mut total = 0;
                loop {
                    endpoint.check()?;
                    let mut bytes = BytesMut::with_capacity(COPY_BYTES);
                    let length = read.read_buf(&mut bytes).await?;
                    endpoint.check()?;
                    if length == 0 {
                        send.finish().await?;
                        return Ok::<_, io::Error>(total);
                    }
                    send.data(bytes.freeze()).await?;
                    total += length as u64;
                    endpoint.tx_bytes.add(length as u64);
                }
            };
            let download = async {
                let mut total = 0;
                loop {
                    self.endpoint.check()?;
                    let data = if !self.current.is_empty() {
                        Some(std::mem::take(&mut self.current))
                    } else {
                        futures::future::poll_fn(|cx| self.recv.poll_data(cx)).await?
                    };
                    self.endpoint.check()?;
                    let Some(data) = data else {
                        write.shutdown().await?;
                        return Ok::<_, io::Error>(total);
                    };
                    write.write_all(&data).await?;
                    total += data.len() as u64;
                    self.endpoint.rx_bytes.add(data.len() as u64);
                }
            };
            tokio::try_join!(upload, download)
        })
    }
}
impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.endpoint.check()?;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.current.is_empty() {
            let Some(data) = ready!(self.recv.poll_data(cx))? else {
                return Poll::Ready(Ok(()));
            };
            self.current = data;
        }
        let length = self.current.len().min(output.remaining());
        output.put_slice(&self.current[..length]);
        self.current.advance(length);
        self.endpoint.rx_bytes.add(length as u64);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.endpoint.check()?;
        let state = self.write.get_mut().unwrap();
        ready!(state.poll_pending(cx))?;
        if state.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = input.len().min(COPY_BYTES);
        let data = Bytes::copy_from_slice(&input[..length]);
        let mut send = state.send.take().unwrap();
        state.pending = Some(Box::pin(async move {
            let result = send.data(data).await;
            (send, result)
        }));
        self.endpoint.tx_bytes.add(length as u64);
        Poll::Ready(Ok(length))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.endpoint.check()?;
        self.write.get_mut().unwrap().poll_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.endpoint.check()?;
        let state = self.write.get_mut().unwrap();
        ready!(state.poll_pending(cx))?;
        if !state.finished {
            state.finished = true;
            let mut send = state.send.take().unwrap();
            state.pending = Some(Box::pin(async move {
                let result = send.finish().await;
                (send, result)
            }));
        }
        state.poll_pending(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{
            TunnelConnector, TunnelListener,
            quic::{QuicTunnelConnector, QuicTunnelListener},
        },
    };

    #[tokio::test]
    async fn streams_require_peer_admission_preserve_half_close_and_cancel_on_policy_change() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let server_ctx = get_mock_global_ctx();
            let mut listener =
                QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), server_ctx.clone());
            listener.listen().await.unwrap();
            let url = listener.local_url();
            let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
            let client_tunnel = QuicTunnelConnector::new(url, get_mock_global_ctx())
                .connect()
                .await
                .unwrap();
            let server_tunnel = accepted.await.unwrap();
            let client = client_tunnel.tcp_proxy().unwrap();
            let server = server_tunnel.tcp_proxy().unwrap();
            let source = "192.0.2.1:40000".parse().unwrap();
            let destination = "192.0.2.2:8080".parse().unwrap();
            assert!(client.connect(source, destination).await.is_err());
            client.authenticated(true);
            assert!(
                client.connect(source, destination).await.is_err(),
                "unauthenticated remote accepted a stream"
            );
            server.authenticated(true);
            let mut incoming = server.take_incoming().unwrap();
            let remote = tokio::spawn(async move {
                let request = incoming.recv().await.unwrap();
                assert_eq!(request.source, source);
                assert_eq!(request.destination, destination);
                let mut stream = request.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, vec![0x5a; 256 * 1024]);
                stream.write_all(b"response after FIN").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = client.connect(source, destination).await.unwrap().unwrap();
            stream.write_all(&vec![0x5a; 256 * 1024]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response after FIN");
            remote.await.unwrap();
            server_ctx
                .get_acl_filter()
                .reload_rules(Some(&crate::proto::acl::Acl::default()));
            assert!(server.check().is_err());
            assert!(
                client.connect(source, destination).await.unwrap().is_none(),
                "ACL peer did not request packet fallback"
            );
            client.authenticated(false);
            assert!(client.check().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stream_slot_and_memory_reservations_release_on_drop() {
        let endpoint = ProxyEndpoint::new(None, get_mock_global_ctx());
        let permits: Vec<_> = (0..MAX_STREAMS)
            .map(|_| endpoint.reserve().unwrap())
            .collect();
        assert!(endpoint.reserve().is_err());
        drop(permits);
        assert!(endpoint.reserve().is_ok());
    }
}
