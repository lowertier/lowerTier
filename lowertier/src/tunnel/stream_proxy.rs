//! TCP proxy bodies use native CONNECT streams on an authenticated transport.
use super::{http2, quic::H3ServerStream};
use crate::common::global_ctx::{ArcGlobalCtx, ProcessMemoryPermit};
use crate::common::stats_manager::{CounterHandle, MetricName};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};

pub(crate) const FEATURE: &str = "tcp-stream-proxy-v1";
pub(crate) const DESTINATION_FEATURE: &str = "tcp-stream-local-ipv4-v1";
// The Noise admission context authenticates this capability.
pub(crate) const RECEIVE_CAPABILITY: u64 = 1;
pub(crate) const LOCAL_DESTINATION_CAPABILITY: u64 = 1 << 1;
const SOURCE_HEADER: &str = "lowertier-proxy-v1";
const COPY_BYTES: usize = 32 * 1024;
pub(super) const MAX_STREAMS: usize = 32;
type H3Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
#[derive(Clone)]
enum Requests {
    H3(H3Requests),
    H2(h2::client::SendRequest<http2::H2Data>),
}
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
    context: OnceLock<ArcGlobalCtx>,
    metrics: OnceLock<ProxyMetrics>,
    h2_budget: Option<Arc<http2::H2SendBudget>>,
    h2_receive: Option<Arc<http2::H2ReceiveBudget>>,
    auto: Mutex<AutoState>,
}
struct ProxyMetrics {
    tx_bytes: CounterHandle,
    rx_bytes: CounterHandle,
    opened: CounterHandle,
}
#[derive(Default)]
struct AutoState {
    failures: u32,
    retry_at: Option<Instant>,
    probing: bool,
    generation: u64,
}
impl AutoState {
    fn admit(&mut self, now: Instant) -> Option<u64> {
        match self.retry_at {
            None => Some(self.generation),
            Some(deadline) if now < deadline || self.probing => None,
            Some(_) => {
                self.probing = true;
                Some(self.generation)
            }
        }
    }
    fn failed(&mut self, generation: u64, now: Instant) {
        if generation != self.generation {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        self.generation = self.generation.wrapping_add(1);
        self.retry_at = Some(now + Duration::from_secs((1_u64 << self.failures.min(5)).min(30)));
        self.probing = false;
    }
}
struct AutoAttempt<'a> {
    state: &'a Mutex<AutoState>,
    complete: bool,
    generation: u64,
}
impl AutoAttempt<'_> {
    fn success(&mut self) {
        let mut state = self.state.lock().unwrap();
        if state.generation == self.generation && state.retry_at.is_some() {
            *state = AutoState {
                generation: state.generation.wrapping_add(1),
                ..AutoState::default()
            };
        }
        self.complete = true;
    }
    fn neutral(&mut self) {
        let mut state = self.state.lock().unwrap();
        if state.generation == self.generation {
            state.probing = false;
        }
        self.complete = true;
    }
    fn failed(&mut self) {
        self.state
            .lock()
            .unwrap()
            .failed(self.generation, Instant::now());
        self.complete = true;
    }
}
impl Drop for AutoAttempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.state
                .lock()
                .unwrap()
                .failed(self.generation, Instant::now());
        }
    }
}
impl ProxyEndpoint {
    pub(super) fn new(requests: Option<H3Requests>, context: ArcGlobalCtx) -> Arc<Self> {
        let endpoint = Self::create(requests.map(Requests::H3), None, None);
        endpoint.bind_context(context);
        endpoint
    }
    pub(super) fn new_h2(
        requests: Option<h2::client::SendRequest<http2::H2Data>>,
        budget: Arc<http2::H2SendBudget>,
        receive: Arc<http2::H2ReceiveBudget>,
    ) -> Arc<Self> {
        Self::create(requests.map(Requests::H2), Some(budget), Some(receive))
    }
    fn create(
        requests: Option<Requests>,
        h2_budget: Option<Arc<http2::H2SendBudget>>,
        h2_receive: Option<Arc<http2::H2ReceiveBudget>>,
    ) -> Arc<Self> {
        let (incoming, receiver) = mpsc::channel(2);
        Arc::new(Self {
            requests: requests.map(Mutex::new),
            incoming,
            receiver: Mutex::new(Some(receiver)),
            authenticated: AtomicBool::new(false),
            slots: Arc::new(Semaphore::new(MAX_STREAMS)),
            context: OnceLock::new(),
            metrics: OnceLock::new(),
            h2_budget,
            h2_receive,
            auto: Mutex::new(AutoState::default()),
        })
    }
    pub(crate) fn bind_context(&self, context: ArcGlobalCtx) {
        self.metrics.get_or_init(|| {
            let stats = context.stats_manager();
            ProxyMetrics {
                tx_bytes: stats.get_simple_counter(MetricName::TcpStreamProxyTxBytes),
                rx_bytes: stats.get_simple_counter(MetricName::TcpStreamProxyRxBytes),
                opened: stats.get_simple_counter(MetricName::TcpStreamProxyOpen),
            }
        });
        self.context.get_or_init(|| context);
    }
    fn context(&self) -> io::Result<&ArcGlobalCtx> {
        self.context.get().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "proxy transport has no peer context",
            )
        })
    }
    fn mode(&self) -> io::Result<&str> {
        if self.h2_budget.is_none() {
            return Ok("on");
        }
        // Return stable literals; configuration snapshots can change between flows.
        Ok(match self.context()?.flags_arc().h2_tcp_proxy.as_str() {
            "on" => "on",
            "auto" => "auto",
            _ => "off",
        })
    }
    pub(crate) fn requires_capability(&self) -> bool {
        self.h2_budget.is_some() && matches!(self.mode(), Ok("on"))
    }
    fn decision(&self, selected: &str, reason: &str) {
        tracing::debug!(
            configured = self.mode().unwrap_or("off"),
            selected,
            reason,
            protocol = if self.h2_budget.is_some() {
                "h2"
            } else {
                "quic"
            },
            "TCP proxy path decision"
        );
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
        if self.context()?.get_acl_filter().is_enabled() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy policy changed; reconnect through the packet path",
            ));
        }
        Ok(())
    }
    fn reserve(&self) -> io::Result<StreamPermit> {
        let slot = self.slots.clone().try_acquire_owned().map_err(error)?;
        let governor = self.context()?.process_memory_governor();
        let exhausted = || {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "TCP proxy memory budget exhausted",
            )
        };
        let memory = governor
            .try_reserve_owned(COPY_BYTES * 2)
            .ok_or_else(exhausted)?;
        let receive = self
            .h2_receive
            .as_ref()
            .map(|receive| receive.reserve(&governor).ok_or_else(exhausted))
            .transpose()?;
        Ok(StreamPermit {
            _slot: slot,
            _memory: memory,
            _h2_receive: receive,
        })
    }
    pub(crate) async fn connect(
        self: &Arc<Self>,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<ProxyStream>> {
        let mode = self.mode()?;
        if mode == "off" {
            self.decision("packet", "disabled");
            return Ok(None);
        }
        if self.context()?.get_acl_filter().is_enabled() {
            return Ok(None);
        }
        self.check()?;
        let Some(requests) = &self.requests else {
            if self.requires_capability() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native HTTP/2 streams require the client side of the connection",
                ));
            }
            self.decision("packet", "native_initiator_unavailable");
            return Ok(None);
        };
        let mut attempt = if self.h2_budget.is_some() && mode == "auto" {
            let generation = self.auto.lock().unwrap().admit(Instant::now());
            let Some(generation) = generation else {
                self.decision("packet", "native_cooldown");
                return Ok(None);
            };
            Some(AutoAttempt {
                state: &self.auto,
                complete: false,
                generation,
            })
        } else {
            None
        };
        let permit = match self.reserve() {
            Ok(permit) => permit,
            Err(_) if mode == "auto" => {
                if let Some(attempt) = &mut attempt {
                    attempt.neutral();
                }
                self.decision("packet", "native_capacity");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
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
        let opened = async {
            match &mut requests {
                Requests::H3(requests) => {
                    let mut stream = requests.send_request(request).await.map_err(error)?;
                    let status = stream.recv_response().await.map_err(error)?.status();
                    let (send, recv) = stream.split();
                    Ok::<_, io::Error>((status, SendHalf::Client(send), RecvHalf::Client(recv)))
                }
                Requests::H2(requests) => {
                    let mut requests = requests.clone().ready().await.map_err(error)?;
                    let (response, send) = requests.send_request(request, false).map_err(error)?;
                    let response = response.await.map_err(error)?;
                    Ok((
                        response.status(),
                        SendHalf::H2(send, self.h2_budget.as_ref().unwrap().clone()),
                        RecvHalf::H2(response.into_body()),
                    ))
                }
            }
        }
        .await?;
        let (status, send, recv) = opened;
        if status == http::StatusCode::NOT_ACCEPTABLE {
            if let Some(attempt) = &mut attempt {
                attempt.success();
            }
            self.decision("packet", "destination_outside_native_scope");
            return Ok(None);
        }
        if status == http::StatusCode::NOT_IMPLEMENTED
            || status == http::StatusCode::SERVICE_UNAVAILABLE
        {
            if let Some(attempt) = &mut attempt {
                attempt.failed();
            }
            if mode == "auto" || self.h2_budget.is_none() {
                self.decision("packet", "native_refused_before_admission");
                return Ok(None);
            }
        }
        // A destination or policy refusal is not a transport fault.
        if let Some(attempt) = &mut attempt {
            attempt.success();
        }
        if status != http::StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("TCP proxy refused: {status}"),
            ));
        }
        self.check()?;
        self.decision("native", "eligible");
        Ok(Some(ProxyStream::new(send, recv, self.clone(), permit)))
    }
    pub(super) fn is_request<B>(request: &http::Request<B>) -> bool {
        request.method() == http::Method::CONNECT
            && request.headers().contains_key(SOURCE_HEADER)
            && request.extensions().get::<h3::ext::Protocol>().is_none()
            && request.extensions().get::<h2::ext::Protocol>().is_none()
    }
    pub(super) async fn receive(
        self: Arc<Self>,
        request: http::Request<()>,
        stream: H3ServerStream,
    ) -> Result<(), super::TunnelError> {
        self.receive_inner(request, IncomingStream::H3(stream))
            .await
    }
    pub(super) async fn receive_h2(
        self: Arc<Self>,
        request: http::Request<h2::RecvStream>,
        respond: h2::server::SendResponse<http2::H2Data>,
    ) -> Result<(), super::TunnelError> {
        let (parts, recv) = request.into_parts();
        self.receive_inner(
            http::Request::from_parts(parts, ()),
            IncomingStream::H2(recv, respond),
        )
        .await
    }
    async fn receive_inner(
        self: Arc<Self>,
        request: http::Request<()>,
        stream: IncomingStream,
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
        } else if self.mode()? == "off" || self.context()?.get_acl_filter().is_enabled() {
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
        // Each pending request holds a stream slot and a memory permit.
        // Wait for the bounded queue instead of rejecting a permitted burst.
        if let Err(error) = self.incoming.send(incoming).await {
            return reject(error.0.stream, http::StatusCode::SERVICE_UNAVAILABLE).await;
        }
        Ok(())
    }
}
enum IncomingStream {
    H3(H3ServerStream),
    H2(h2::RecvStream, h2::server::SendResponse<http2::H2Data>),
}
async fn reject(
    stream: IncomingStream,
    status: http::StatusCode,
) -> Result<(), super::TunnelError> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .map_err(error)?;
    match stream {
        IncomingStream::H3(mut stream) => {
            stream.send_response(response).await.map_err(error)?;
            stream.finish().await.map_err(error)?;
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        IncomingStream::H2(_recv, mut respond) => {
            respond.send_response(response, true).map_err(error)?;
        }
    }
    Ok(())
}
struct StreamPermit {
    // Release accounting before another flow can acquire the slot.
    _h2_receive: Option<http2::H2ReceivePermit>,
    _memory: ProcessMemoryPermit,
    _slot: OwnedSemaphorePermit,
}
pub(crate) struct IncomingProxy {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    stream: IncomingStream,
    endpoint: Arc<ProxyEndpoint>,
    permit: StreamPermit,
}
impl IncomingProxy {
    pub(crate) async fn reject(self, status: http::StatusCode) -> Result<(), super::TunnelError> {
        reject(self.stream, status).await
    }
    pub(crate) async fn accept(self) -> io::Result<ProxyStream> {
        self.endpoint.check()?;
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .map_err(error)?;
        let (send, recv) = match self.stream {
            IncomingStream::H3(mut stream) => {
                stream.send_response(response).await.map_err(error)?;
                let (send, recv) = stream.split();
                (SendHalf::Server(send), RecvHalf::Server(recv))
            }
            IncomingStream::H2(recv, mut respond) => {
                let send = respond.send_response(response, false).map_err(error)?;
                (
                    SendHalf::H2(send, self.endpoint.h2_budget.as_ref().unwrap().clone()),
                    RecvHalf::H2(recv),
                )
            }
        };
        Ok(ProxyStream::new(send, recv, self.endpoint, self.permit))
    }
}
enum SendHalf {
    Client(ClientSend),
    Server(ServerSend),
    H2(h2::SendStream<http2::H2Data>, Arc<http2::H2SendBudget>),
}
impl SendHalf {
    async fn data(&mut self, data: Bytes) -> io::Result<()> {
        match self {
            Self::Client(s) => s.send_data(data).await.map_err(error),
            Self::Server(s) => s.send_data(data).await.map_err(error),
            Self::H2(send, budget) => {
                let mut data = data;
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let capacity = if send.capacity() != 0 {
                        send.capacity()
                    } else {
                        futures::future::poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
                            .map_err(error)?
                    };
                    if capacity == 0 {
                        continue;
                    }
                    let notified = budget.notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let take = budget.claim(capacity.min(data.len()));
                    if take == 0 {
                        notified.await;
                        continue;
                    }
                    send.send_data(http2::H2Data::admitted(data.split_to(take), budget), false)
                        .map_err(error)?;
                }
                Ok(())
            }
        }
    }
    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Client(s) => s.finish().await.map_err(error),
            Self::Server(s) => s.finish().await.map_err(error),
            Self::H2(send, budget) => send
                .send_data(http2::H2Data::new(Bytes::new(), budget), true)
                .map_err(error),
        }
    }
}
enum RecvHalf {
    Client(ClientRecv),
    Server(ServerRecv),
    H2(h2::RecvStream),
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
            Self::H2(recv) => recv
                .poll_data(cx)
                .map(|result| result.transpose().map_err(error)),
        }
    }
    fn consumed(&mut self, length: usize) -> io::Result<()> {
        if let Self::H2(recv) = self {
            recv.flow_control()
                .release_capacity(length)
                .map_err(error)?;
        }
        Ok(())
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
        endpoint.metrics.get().unwrap().opened.inc();
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
    /// SOCKS transfers retain owned transport chunks and read upload bytes directly
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
                    endpoint.metrics.get().unwrap().tx_bytes.add(length as u64);
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
                    self.recv.consumed(data.len())?;
                    total += data.len() as u64;
                    self.endpoint
                        .metrics
                        .get()
                        .unwrap()
                        .rx_bytes
                        .add(data.len() as u64);
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
        self.recv.consumed(length)?;
        self.endpoint
            .metrics
            .get()
            .unwrap()
            .rx_bytes
            .add(length as u64);
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
        self.endpoint
            .metrics
            .get()
            .unwrap()
            .tx_bytes
            .add(length as u64);
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

    async fn h2_pair() -> (
        Arc<ProxyEndpoint>,
        Arc<ProxyEndpoint>,
        Box<dyn crate::tunnel::Tunnel>,
        Box<dyn crate::tunnel::Tunnel>,
    ) {
        use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};
        let client_context = get_mock_global_ctx();
        let server_context = get_mock_global_ctx();
        for context in [&client_context, &server_context] {
            let mut flags = context.config.get_flags();
            flags.h2_tcp_proxy = "on".into();
            context.set_flags(flags);
        }
        let mut listener = TcpTunnelListener::new("h2://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let url = listener.local_url();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let client_tunnel = TcpTunnelConnector::new(url).connect().await.unwrap();
        let server_tunnel = accepted.await.unwrap();
        assert_eq!(
            client_tunnel.transport_binding(),
            server_tunnel.transport_binding()
        );
        let client = client_tunnel.tcp_proxy().unwrap();
        let server = server_tunnel.tcp_proxy().unwrap();
        client.bind_context(client_context);
        server.bind_context(server_context);
        (client, server, client_tunnel, server_tunnel)
    }

    #[tokio::test]
    async fn h2_authentication_modes_half_close_and_live_changes() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (client, server, _client_tunnel, server_tunnel) = h2_pair().await;
            let source = "192.0.2.1:40000".parse().unwrap();
            let destination = "192.0.2.2:8080".parse().unwrap();
            assert!(client.connect(source, destination).await.is_err());
            client.authenticated(true);
            assert!(client.connect(source, destination).await.is_err());
            server.authenticated(true);
            server_tunnel.probe_guard().unwrap().authenticate();
            assert!(server.connect(source, destination).await.is_err());
            let mut incoming = server.take_incoming().unwrap();
            let remote = tokio::spawn(async move {
                let mut stream = incoming.recv().await.unwrap().accept().await.unwrap();
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, vec![0x5a; 256 * 1024]);
                stream.write_all(b"response after FIN").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = client.connect(source, destination).await.unwrap().unwrap();
            let mut flags = client.context().unwrap().config.get_flags();
            flags.h2_tcp_proxy = "off".into();
            client.context().unwrap().set_flags(flags);
            assert!(client.connect(source, destination).await.unwrap().is_none());
            stream.write_all(&vec![0x5a; 256 * 1024]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response after FIN");
            remote.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_auto_falls_back_only_before_admission() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (client, server, _client_tunnel, server_tunnel) = h2_pair().await;
            client.authenticated(true);
            server.authenticated(true);
            server_tunnel.probe_guard().unwrap().authenticate();
            let source = "192.0.2.1:40000".parse().unwrap();
            let destination = "192.0.2.2:8080".parse().unwrap();
            let mut flags = server.context().unwrap().config.get_flags();
            flags.h2_tcp_proxy = "off".into();
            server.context().unwrap().set_flags(flags);
            assert!(client.connect(source, destination).await.is_err());
            let mut flags = client.context().unwrap().config.get_flags();
            flags.h2_tcp_proxy = "auto".into();
            client.context().unwrap().set_flags(flags);
            assert!(client.connect(source, destination).await.unwrap().is_none());
            assert!(client.connect(source, destination).await.unwrap().is_none());
            client.auto.lock().unwrap().retry_at = Some(Instant::now());
            let mut flags = server.context().unwrap().config.get_flags();
            flags.h2_tcp_proxy = "on".into();
            server.context().unwrap().set_flags(flags);
            let mut incoming = server.take_incoming().unwrap();
            let remote = tokio::spawn(async move {
                incoming
                    .recv()
                    .await
                    .unwrap()
                    .reject(http::StatusCode::BAD_GATEWAY)
                    .await
                    .unwrap();
                incoming
                    .recv()
                    .await
                    .unwrap()
                    .reject(http::StatusCode::FORBIDDEN)
                    .await
                    .unwrap();
                incoming
                    .recv()
                    .await
                    .unwrap()
                    .reject(http::StatusCode::NOT_ACCEPTABLE)
                    .await
                    .unwrap();
            });
            assert!(client.connect(source, destination).await.is_err());
            assert!(client.auto.lock().unwrap().retry_at.is_none());
            assert!(client.connect(source, destination).await.is_err());
            assert!(client.connect(source, destination).await.unwrap().is_none());
            assert!(client.auto.lock().unwrap().retry_at.is_none());
            remote.await.unwrap();
            let permits: Vec<_> = (0..MAX_STREAMS)
                .map(|_| client.reserve().unwrap())
                .collect();
            assert!(client.connect(source, destination).await.unwrap().is_none());
            drop(permits);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_ambiguous_open_failure_never_returns_packet_fallback() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (client, server, _client_tunnel, server_tunnel) = h2_pair().await;
            client.authenticated(true);
            server.authenticated(true);
            server_tunnel.probe_guard().unwrap().authenticate();
            let mut flags = client.context().unwrap().config.get_flags();
            flags.h2_tcp_proxy = "auto".into();
            client.context().unwrap().set_flags(flags);
            let source = "192.0.2.1:40000".parse().unwrap();
            let destination = "192.0.2.2:8080".parse().unwrap();
            let mut incoming = server.take_incoming().unwrap();
            let (release, released) = tokio::sync::oneshot::channel();
            let remote = tokio::spawn(async move {
                let pending = incoming.recv().await.unwrap();
                released.await.unwrap();
                drop(pending);
                drop(incoming.recv().await.unwrap());
            });
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    client.connect(source, destination)
                )
                .await
                .is_err()
            );
            assert!(client.auto.lock().unwrap().retry_at.is_some());
            release.send(()).unwrap();
            client.auto.lock().unwrap().retry_at = Some(Instant::now());
            assert!(client.connect(source, destination).await.is_err());
            assert!(client.auto.lock().unwrap().retry_at.is_some());
            remote.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_blocked_readers_preserve_native_and_packet_progress() {
        use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};
        use futures::{SinkExt, StreamExt};
        tokio::time::timeout(Duration::from_secs(15), async {
            let (client, server, client_tunnel, server_tunnel) = h2_pair().await;
            client.authenticated(true);
            server.authenticated(true);
            server_tunnel.probe_guard().unwrap().authenticate();
            let source = "192.0.2.1:40000".parse().unwrap();
            let destination = "192.0.2.2:8080".parse().unwrap();
            let mut incoming = server.take_incoming().unwrap();
            let (filled, mut filled_receiver) = mpsc::channel(2);
            let remote = tokio::spawn(async move {
                let mut writers = Vec::new();
                for _ in 0..2 {
                    let mut stalled = incoming.recv().await.unwrap().accept().await.unwrap();
                    let filled = filled.clone();
                    writers.push(tokio::spawn(async move {
                        stalled
                            .write_all(&vec![0x5a; 2 * 1024 * 1024])
                            .await
                            .unwrap();
                        stalled.flush().await.unwrap();
                        filled.send(()).await.unwrap();
                        stalled.write_all(&vec![0x5a; 1024 * 1024]).await
                    }));
                }
                let mut quick = incoming.recv().await.unwrap().accept().await.unwrap();
                let mut request = Vec::new();
                quick.read_to_end(&mut request).await.unwrap();
                assert!(request.is_empty());
                quick.write_all(b"independent").await.unwrap();
                quick.shutdown().await.unwrap();
                writers
            });
            let _first_slow = client.connect(source, destination).await.unwrap().unwrap();
            let _second_slow = client.connect(source, destination).await.unwrap().unwrap();
            filled_receiver.recv().await.unwrap();
            filled_receiver.recv().await.unwrap();
            let mut quick = client.connect(source, destination).await.unwrap().unwrap();
            quick.shutdown().await.unwrap();
            let mut data = Vec::new();
            quick.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"independent");
            let (mut client_recv, mut client_send) = client_tunnel.split();
            let (mut server_recv, mut server_send) = server_tunnel.split();
            client_send
                .send(PacketBatch::singleton(ZCPacket::new_with_payload(
                    b"packet control",
                )))
                .await
                .unwrap();
            let packet = server_recv
                .next()
                .await
                .unwrap()
                .unwrap()
                .pop_singleton()
                .unwrap();
            assert_eq!(packet.payload(), b"packet control");
            server_send
                .send(PacketBatch::singleton(packet))
                .await
                .unwrap();
            assert_eq!(
                client_recv
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap()
                    .payload(),
                b"packet control"
            );
            for writer in remote.await.unwrap() {
                assert!(!writer.is_finished());
                writer.abort();
                let _ = writer.await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn cancelled_recovery_releases_the_single_probe() {
        let now = Instant::now();
        let state = Mutex::new(AutoState {
            retry_at: Some(now),
            ..AutoState::default()
        });
        let generation = state.lock().unwrap().admit(now).unwrap();
        assert!(state.lock().unwrap().admit(now).is_none());
        drop(AutoAttempt {
            state: &state,
            complete: false,
            generation,
        });
        let mut state = state.lock().unwrap();
        assert!(!state.probing);
        let deadline = state.retry_at.unwrap();
        assert!(state.admit(deadline).is_some());
    }

    #[test]
    fn stale_success_does_not_clear_a_newer_failure() {
        let state = Mutex::new(AutoState::default());
        let generation = state.lock().unwrap().admit(Instant::now()).unwrap();
        let mut older = AutoAttempt {
            state: &state,
            complete: false,
            generation,
        };
        let mut newer = AutoAttempt {
            state: &state,
            complete: false,
            generation,
        };
        newer.failed();
        older.success();
        assert!(state.lock().unwrap().retry_at.is_some());
    }

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

    #[tokio::test]
    async fn admitted_streams_wait_for_incoming_queue_capacity() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let mut listener = QuicTunnelListener::new(
                "quic://127.0.0.1:0".parse().unwrap(),
                get_mock_global_ctx(),
            );
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
            client.authenticated(true);
            server.authenticated(true);
            let mut incoming = server.take_incoming().unwrap();
            let opens: Vec<_> = (0..4)
                .map(|_| {
                    let client = client.clone();
                    tokio::spawn(async move {
                        client
                            .connect(
                                "192.0.2.1:40000".parse().unwrap(),
                                "192.0.2.2:8080".parse().unwrap(),
                            )
                            .await
                    })
                })
                .collect();
            while server.slots.available_permits() > MAX_STREAMS - opens.len()
                && !opens.iter().any(tokio::task::JoinHandle::is_finished)
            {
                tokio::task::yield_now().await;
            }
            assert!(
                opens.iter().all(|open| !open.is_finished()),
                "queue pressure rejected an admitted stream"
            );
            assert_eq!(incoming.len(), 2);
            let mut accepted_streams = Vec::new();
            for _ in 0..opens.len() {
                let mut stream = incoming.recv().await.unwrap().accept().await.unwrap();
                stream.write_all(b"accepted").await.unwrap();
                stream.shutdown().await.unwrap();
                accepted_streams.push(stream);
            }
            for open in opens {
                let mut stream = open.await.unwrap().unwrap().unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"accepted");
            }
            drop(accepted_streams);
            assert_eq!(server.slots.available_permits(), MAX_STREAMS);
        })
        .await
        .unwrap();
    }
}
