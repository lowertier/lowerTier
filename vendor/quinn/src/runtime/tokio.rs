use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper};

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(UdpSocket::from_std(sock)?))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
    // Socket mode is fixed before transfer to Quinn. Endpoint::rebind wraps a
    // new socket, so it obtains fresh state without querying the kernel per packet.
    #[cfg(target_os = "macos")]
    connected: bool,
}

impl UdpSocket {
    fn from_std(sock: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            #[cfg(target_os = "macos")]
            connected: sock.peer_addr().is_ok(),
            inner: udp::UdpSocketState::new((&sock).into())?,
            io: tokio::net::UdpSocket::from_std(sock)?,
        })
    }
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn super::UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if self.connected {
            return connected_send_result(
                self.io.try_send(transmit.contents),
                transmit.contents.len(),
            );
        }
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        #[cfg(target_os = "macos")]
        if self.connected {
            return 1;
        }
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

#[cfg(any(target_os = "macos", test))]
fn connected_send_result(result: io::Result<usize>, expected: usize) -> io::Result<()> {
    match result {
        Ok(sent) => {
            if sent == expected {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "connected UDP send was partial",
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
        Err(error) => {
            // Match UdpSocketState::send. UDP errors represent packet loss;
            // ENOBUFS must not stop the connection's ACK and timer driver.
            tracing::debug!(?error, "UDP send failed; QUIC will recover packet loss");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn wrapping_preserves_connected_and_unconnected_udp_delivery() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let destination = receiver.local_addr().unwrap();
                for connected in [false, true] {
                    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    socket.set_nonblocking(true).unwrap();
                    if connected {
                        socket.connect(destination).unwrap();
                    }
                    let socket = UdpSocket::from_std(socket).unwrap();
                    assert_eq!(socket.connected, connected);
                    let transmit = udp::Transmit {
                        destination,
                        ecn: None,
                        contents: b"cached UDP mode",
                        segment_size: None,
                        src_ip: None,
                    };
                    tokio::time::timeout(std::time::Duration::from_secs(1), async {
                        loop {
                            socket.io.writable().await.unwrap();
                            match socket.try_send(&transmit) {
                                Ok(()) => break,
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(error) => panic!("UDP submission failed: {error}"),
                            }
                        }
                        let mut buffer = [0; 64];
                        let (received, source) = receiver.recv_from(&mut buffer).await.unwrap();
                        assert_eq!(&buffer[..received], transmit.contents);
                        assert_eq!(source, socket.local_addr().unwrap());
                    })
                    .await
                    .unwrap();
                }
            });
    }

    #[test]
    fn connected_udp_errors_preserve_the_driver() {
        assert!(connected_send_result(Err(io::Error::from_raw_os_error(55)), 1200).is_ok());
        assert_eq!(
            connected_send_result(Err(io::ErrorKind::WouldBlock.into()), 1200)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock,
        );
        assert!(connected_send_result(Ok(1200), 1200).is_ok());
        assert_eq!(
            connected_send_result(Ok(1199), 1200).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
