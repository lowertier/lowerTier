use super::{reactor::Reactor, socket_allocator::SocketHandle};
use futures::future::{self, poll_fn};
pub use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::mem::replace;
use std::net::IpAddr;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A TCP socket server, listening for connections.
///
/// You can accept a new connection by using the accept method.
pub struct TcpListener {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

fn map_err<E: std::error::Error>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

impl TcpListener {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<TcpListener> {
        let handle = reactor.socket_allocator().new_tcp_socket()?;
        {
            let mut socket = reactor.get_socket::<tcp::Socket>(*handle);
            socket.listen(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);
        Ok(TcpListener {
            handle,
            reactor,
            local_addr,
        })
    }
    pub fn poll_accept(&mut self, cx: &Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.state() == tcp::State::Established {
            drop(socket);
            return Poll::Ready(Ok(TcpStream::accept(self)?));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
    #[cfg(feature = "ffi-dataplane")]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

fn ep2sa(ep: &IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(v6), ep.port),
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    #[cfg(feature = "ffi-dataplane")]
    local_addr: SocketAddr,
}

impl TcpStream {
    pub(super) async fn connect(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
        remote_endpoint: IpEndpoint,
    ) -> io::Result<TcpStream> {
        let handle = reactor.socket_allocator().new_tcp_socket()?;

        // see https://github.com/spacemeowx2/tokio-smoltcp/pull/12
        let connect_result = {
            // Issue #11. We must lock the context before we call connect to
            // avoid lock inversion deadlocks, but drop it before constructing
            // the TcpStream to avoid a second mutable borror of the reactor.
            let mut context = reactor.context();
            reactor.get_socket::<tcp::Socket>(*handle).connect(
                &mut context,
                remote_endpoint,
                local_endpoint,
            )
        };
        connect_result.map_err(map_err)?;

        let local_addr = ep2sa(&local_endpoint);
        let tcp = TcpStream {
            handle,
            reactor,
            #[cfg(feature = "ffi-dataplane")]
            local_addr,
        };

        tcp.reactor.notify();
        future::poll_fn(|cx| tcp.poll_connected(cx)).await?;

        Ok(tcp)
    }

    fn accept(listener: &mut TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
        let reactor = listener.reactor.clone();
        let new_handle = reactor.socket_allocator().new_tcp_socket()?;
        {
            let mut new_socket = reactor.get_socket::<tcp::Socket>(*new_handle);
            new_socket.listen(listener.local_addr).map_err(map_err)?;
        }
        let (peer_addr, local_addr) = {
            let socket = reactor.get_socket::<tcp::Socket>(*listener.handle);
            match (socket.remote_endpoint(), socket.local_endpoint()) {
                (Some(remote_endpoint), Some(local_endpoint)) => (
                    // should be Some, because the state is Established
                    ep2sa(&remote_endpoint),
                    ep2sa(&local_endpoint),
                ),
                _ => return Err(io::ErrorKind::NotConnected.into()),
            }
        };

        Ok((
            TcpStream {
                handle: replace(&mut listener.handle, new_handle),
                reactor,
                #[cfg(feature = "ffi-dataplane")]
                local_addr,
            },
            peer_addr,
        ))
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    pub fn poll_connected(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if socket.state() == tcp::State::Established {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        if socket.can_recv() {
            let read = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(map_err)?;
            self.handle
                .2
                .as_ref()
                .unwrap()
                .lock()
                .received(&mut socket, read);
            self.reactor.notify();
            buf.advance(read);
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            let r = socket.send_slice(buf).map_err(map_err)?;
            self.handle.2.as_ref().unwrap().lock().sent(&mut socket, r);
            self.reactor.notify();
            return Poll::Ready(Ok(r));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // SocketHandle::drop removes the stack's retransmission queue. Keep
        // flush ACK-backed until graceful orphaned-socket ownership exists;
        // returning early here would make write/flush/drop lose trailing data.
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut socket = self.reactor.get_socket::<tcp::Socket>(*self.handle);

        if socket.may_send() {
            socket.close();
            self.reactor.notify();
        }
        // AsyncWrite shutdown closes only the transmit half. Requiring the
        // peer's FIN (or TIME-WAIT expiry) deadlocks request/response protocols.
        // Wait for our FIN ACK so dropping the handle cannot lose a tail.
        if matches!(
            socket.state(),
            tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
        ) {
            return if socket.send_queue() == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            };
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use crate::gateway::tokio_smoltcp::{Net, NetConfig, channel_device::ChannelDevice};
    use crate::tunnel::batch::PacketBatch;
    use smoltcp::{
        iface::Config,
        phy::{DeviceCapabilities, Medium},
        wire::HardwareAddress,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::task::AbortOnDropHandle;

    async fn connected_test_pair() -> (
        Net,
        Net,
        AbortOnDropHandle<()>,
        AbortOnDropHandle<()>,
        TcpStream,
        TcpStream,
    ) {
        connected_test_pair_with_ack_loss(
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await
    }

    async fn connected_test_pair_with_ack_loss(
        drop_ack: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) -> (
        Net,
        Net,
        AbortOnDropHandle<()>,
        AbortOnDropHandle<()>,
        TcpStream,
        TcpStream,
    ) {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        let (a_device, to_a, mut from_a) = ChannelDevice::new(caps.clone());
        let (b_device, to_b, mut from_b) = ChannelDevice::new(caps);
        let a = Net::new(
            a_device,
            NetConfig::new(
                Config::new(HardwareAddress::Ip),
                "192.0.2.1/24".parse().unwrap(),
                vec![],
                None,
            ),
        );
        let b = Net::new(
            b_device,
            NetConfig::new(
                Config::new(HardwareAddress::Ip),
                "192.0.2.2/24".parse().unwrap(),
                vec![],
                None,
            ),
        );
        let forward = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = from_a.recv().await {
                let ip = smoltcp::wire::Ipv4Packet::new_checked(packet.payload()).unwrap();
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.ack()
                    && !tcp.fin()
                    && tcp.payload().is_empty()
                    && drop_ack.swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    dropped.store(true, std::sync::atomic::Ordering::SeqCst);
                    continue;
                }
                if to_b.send(Ok(PacketBatch::singleton(packet))).await.is_err() {
                    break;
                }
            }
        }));
        let backward = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = from_b.recv().await {
                if to_a.send(Ok(PacketBatch::singleton(packet))).await.is_err() {
                    break;
                }
            }
        }));
        let mut listener = b.tcp_bind("192.0.2.2:8080".parse().unwrap()).await.unwrap();
        let (client, server) = tokio::join!(
            a.tcp_connect("192.0.2.2:8080".parse().unwrap(), 12000),
            listener.accept()
        );
        (a, b, forward, backward, client.unwrap(), server.unwrap().0)
    }

    #[tokio::test]
    async fn shutdown_half_close_delivers_tail_and_reclaims_time_wait_buffers() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (_a, _b, _forward, _backward, mut client, mut server) = connected_test_pair().await;
            let request = vec![0x5a; 128 * 1024];
            let response = vec![0xa5; 96 * 1024];
            let send = async {
                client.write_all(&request).await.unwrap();
                client.shutdown().await.unwrap();
                // The peer still owes its response: shutdown must preserve reading.
                assert_eq!(
                    client
                        .reactor
                        .get_socket::<tcp::Socket>(*client.handle)
                        .send_queue(),
                    0
                );
                client.shutdown().await.unwrap();
                let mut received = Vec::new();
                client.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, response);
            };
            let receive = async {
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, request);
                server.write_all(&response).await.unwrap();
                server.shutdown().await.unwrap();
            };
            tokio::join!(send, receive);
            assert_eq!(
                client
                    .reactor
                    .get_socket::<tcp::Socket>(*client.handle)
                    .state(),
                tcp::State::TimeWait
            );
            let reactor = client.reactor.clone();
            let handle = *client.handle;
            drop(client);
            assert!(reactor.socket_allocator().has_retired());
            {
                let socket = reactor.get_socket::<tcp::Socket>(handle);
                assert_eq!(socket.state(), tcp::State::TimeWait);
                assert_eq!(socket.send_capacity(), 0);
                assert_eq!(socket.recv_capacity(), 0);
            }
            // Linger metadata has a fixed deadline even if no packet wakes it.
            let allocator = reactor.socket_allocator();
            let mut sockets = allocator.sockets().lock();
            allocator.reap_retired(
                &mut sockets,
                std::time::Instant::now() + std::time::Duration::from_secs(61),
            );
            assert!(!sockets.iter().any(|(h, _)| h == handle));
            assert!(!allocator.has_retired());
        })
        .await
        .expect("half-close blocked until peer FIN or TIME-WAIT expiry");
    }

    #[tokio::test]
    async fn dropped_acknowledged_half_close_keeps_fin_wait_protocol_state() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (_a, _b, _forward, _backward, mut client, mut server) = connected_test_pair().await;
            client.write_all(b"complete tail").await.unwrap();
            // Before the current-thread reactor has run, the tail has no ACK.
            {
                let shutdown = client.shutdown();
                tokio::pin!(shutdown);
                assert!(futures::poll!(shutdown.as_mut()).is_pending());
            }
            client.shutdown().await.unwrap();
            let reactor = client.reactor.clone();
            let handle = *client.handle;
            assert_eq!(
                reactor.get_socket::<tcp::Socket>(handle).state(),
                tcp::State::FinWait2
            );
            drop(client);
            assert!(reactor.socket_allocator().has_retired());
            assert!(reactor.get_socket::<tcp::Socket>(handle).recv_capacity() > 0);
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(&received, b"complete tail");
            server.shutdown().await.unwrap();
            assert_eq!(
                reactor.get_socket::<tcp::Socket>(handle).state(),
                tcp::State::TimeWait
            );
            let allocator = reactor.socket_allocator();
            let mut sockets = allocator.sockets().lock();
            allocator.reap_retired(&mut sockets, std::time::Instant::now());
            assert_eq!(sockets.get::<tcp::Socket>(handle).recv_capacity(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn legacy_full_close_wait_reproduces_half_close_stall() {
        let (_a, _b, _forward, _backward, mut client, mut server) = connected_test_pair().await;
        client.write_all(b"request").await.unwrap();
        // Exact previous shutdown condition: only CLOSED is accepted.
        let legacy = future::poll_fn(|cx| {
            let mut socket = client.reactor.get_socket::<tcp::Socket>(*client.handle);
            if socket.is_open() {
                socket.close();
                client.reactor.notify();
            }
            if socket.state() == tcp::State::Closed {
                return Poll::Ready(());
            }
            socket.register_send_waker(cx.waker());
            Poll::Pending
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), legacy)
                .await
                .is_err()
        );
        assert_eq!(
            client
                .reactor
                .get_socket::<tcp::Socket>(*client.handle)
                .state(),
            tcp::State::FinWait2
        );
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
    }

    #[tokio::test]
    async fn buffer_reclamation_preserves_live_windows_and_unread_tail() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (_a, _b, _forward, _backward, mut client, mut server) = connected_test_pair().await;
            {
                let mut socket = client.reactor.get_socket::<tcp::Socket>(*client.handle);
                let capacity = socket.recv_capacity();
                assert!(!socket.release_time_wait_buffers());
                assert_eq!(socket.recv_capacity(), capacity);
            }
            client.shutdown().await.unwrap();
            server.write_all(b"unread response").await.unwrap();
            server.shutdown().await.unwrap();
            {
                let mut socket = client.reactor.get_socket::<tcp::Socket>(*client.handle);
                assert_eq!(socket.state(), tcp::State::TimeWait);
                assert!(!socket.release_time_wait_buffers());
                assert!(socket.recv_queue() > 0);
            }
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(&response, b"unread response");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reclaimed_time_wait_socket_acknowledges_retransmitted_fin() {
        use std::sync::atomic::{AtomicBool, Ordering};
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            let drop_ack = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicBool::new(false));
            let (_a, _b, _forward, _backward, mut client, mut server) =
                connected_test_pair_with_ack_loss(drop_ack.clone(), dropped.clone()).await;
            client.shutdown().await.unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            drop_ack.store(true, Ordering::SeqCst);
            let closing = AbortOnDropHandle::new(tokio::spawn(async move {
                server.shutdown().await.unwrap();
            }));
            while !dropped.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            let reactor = client.reactor.clone();
            let handle = *client.handle;
            assert_eq!(
                reactor.get_socket::<tcp::Socket>(handle).state(),
                tcp::State::TimeWait
            );
            drop(client);
            assert_eq!(reactor.get_socket::<tcp::Socket>(handle).send_capacity(), 0);
            assert_eq!(reactor.get_socket::<tcp::Socket>(handle).recv_capacity(), 0);
            // The peer's first FIN ACK was lost. The empty TIME-WAIT socket
            // must still answer its retransmitted FIN after its owner was dropped.
            closing.await.unwrap();
            assert!(dropped.load(Ordering::SeqCst));
        })
        .await
        .expect("lost final ACK stranded the peer after buffer reclamation");
    }

    #[tokio::test]
    async fn flush_preserves_acknowledged_delivery_before_handle_destruction() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = 1280;
            let (a, to_a, mut from_a) = ChannelDevice::new(caps.clone());
            let (b, to_b, mut from_b) = ChannelDevice::new(caps);
            let a = Net::new(
                a,
                NetConfig::new(
                    Config::new(HardwareAddress::Ip),
                    "192.0.2.1/24".parse().unwrap(),
                    vec![],
                    None,
                ),
            );
            let b = Net::new(
                b,
                NetConfig::new(
                    Config::new(HardwareAddress::Ip),
                    "192.0.2.2/24".parse().unwrap(),
                    vec![],
                    None,
                ),
            );
            let _a_to_b = AbortOnDropHandle::new(tokio::spawn(async move {
                while let Some(packet) = from_a.recv().await {
                    if to_b.send(Ok(PacketBatch::singleton(packet))).await.is_err() {
                        break;
                    }
                }
            }));
            let _b_to_a = AbortOnDropHandle::new(tokio::spawn(async move {
                while let Some(packet) = from_b.recv().await {
                    if to_a.send(Ok(PacketBatch::singleton(packet))).await.is_err() {
                        break;
                    }
                }
            }));
            let mut listener = b.tcp_bind("192.0.2.2:8080".parse().unwrap()).await.unwrap();
            let (client, server) = tokio::join!(
                a.tcp_connect("192.0.2.2:8080".parse().unwrap(), 12000),
                listener.accept(),
            );
            let mut client = client.unwrap();
            let (mut server, _) = server.unwrap();
            let payload = vec![0x5a; 4096];
            client.write_all(&payload).await.unwrap();
            assert!(
                client
                    .reactor
                    .get_socket::<tcp::Socket>(*client.handle)
                    .send_queue()
                    > 0
            );
            // Current-thread runtime: the peer cannot ACK between the write
            // and this poll. Dropping this handle now would discard its queue.
            {
                let flush = client.flush();
                tokio::pin!(flush);
                assert!(futures::poll!(flush.as_mut()).is_pending());
            }
            client.flush().await.unwrap();
            assert_eq!(
                client
                    .reactor
                    .get_socket::<tcp::Socket>(*client.handle)
                    .send_queue(),
                0
            );
            let mut received = vec![0; payload.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            server.write_all(b"acknowledged payload").await.unwrap();
            let mut reply = [0; 20];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"acknowledged payload");
        })
        .await
        .unwrap();
    }
}

/// A UDP socket.
pub struct UdpSocket {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    #[cfg(feature = "ffi-dataplane")]
    local_addr: SocketAddr,
}

impl UdpSocket {
    pub(super) async fn new(
        reactor: Arc<Reactor>,
        local_endpoint: IpEndpoint,
    ) -> io::Result<UdpSocket> {
        let handle = reactor.socket_allocator().new_udp_socket();
        {
            let mut socket = reactor.get_socket::<udp::Socket>(*handle);
            socket.bind(local_endpoint).map_err(map_err)?;
        }

        let local_addr = ep2sa(&local_endpoint);

        Ok(UdpSocket {
            handle,
            reactor,
            #[cfg(feature = "ffi-dataplane")]
            local_addr,
        })
    }
    /// Note that on multiple calls to a poll_* method in the send direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_send_to(
        &self,
        cx: &Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);
        let target_ip: IpEndpoint = target.into();

        match socket.send_slice(buf, target_ip) {
            // the buffer is full
            Err(udp::SendError::BufferFull) => {}
            r => {
                r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok(buf.len()));
            }
        }

        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_send_to`
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
    /// Note that on multiple calls to a poll_* method in the recv direction, only the Waker from the Context passed to the most recent call will be scheduled to receive a wakeup.
    pub fn poll_recv_from(
        &self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut socket = self.reactor.get_socket::<udp::Socket>(*self.handle);

        match socket.recv_slice(buf) {
            // the buffer is empty
            Err(udp::RecvError::Exhausted) => {}
            r => {
                let (size, metadata) = r.map_err(map_err)?;
                self.reactor.notify();
                return Poll::Ready(Ok((size, ep2sa(&metadata.endpoint))));
            }
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
    /// See note on `poll_recv_from`
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }
    #[cfg(feature = "ffi-dataplane")]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}
