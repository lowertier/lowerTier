use tokio::net::TcpStream;

// Limit unsent data separately from socket capacity for packets in flight.
pub(super) const TCP_NOTSENT_BYTES: u32 = 128 * 1024;

#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT: i32 = nix::libc::TCP_NOTSENT_LOWAT;
// Darwin's netinet/tcp.h defines this option; libc does not expose it.
#[cfg(target_vendor = "apple")]
const TCP_NOTSENT_LOWAT: i32 = 0x201;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn set_notsent_lowat(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let value = TCP_NOTSENT_BYTES;
    // The descriptor and option value remain valid for this synchronous call.
    let result = unsafe {
        nix::libc::setsockopt(
            stream.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&value as *const u32).cast(),
            std::mem::size_of_val(&value) as nix::libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_vendor = "apple"))]
pub(super) type TcpUnderlay = TcpStream;

pub(super) fn prepare(stream: TcpStream) -> TcpUnderlay {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let limited = match set_notsent_lowat(&stream) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(?error, "TCP_NOTSENT_LOWAT failed for tunnel socket");
            false
        }
    };
    #[cfg(target_vendor = "apple")]
    return TcpUnderlay { stream, limited };
    #[cfg(not(target_vendor = "apple"))]
    {
        #[cfg(target_os = "linux")]
        let _ = limited;
        stream
    }
}

#[cfg(target_vendor = "apple")]
pub(super) struct TcpUnderlay {
    stream: TcpStream,
    limited: bool,
}

#[cfg(target_vendor = "apple")]
mod darwin {
    use super::TcpUnderlay;
    use std::{
        io::{self, IoSlice},
        os::fd::AsRawFd,
        pin::Pin,
        task::{Context, Poll, ready},
    };
    use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

    // Darwin gates readiness, not send(). Bound overshoot to one write.
    const MAX_WRITE_BYTES: usize = 64 * 1024;

    impl TcpUnderlay {
        pub(super) fn write_ready(&self) -> io::Result<()> {
            if !self.limited {
                return Ok(());
            }
            let mut descriptor = nix::libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: nix::libc::POLLOUT,
                revents: 0,
            };
            // poll() uses Darwin's unsent-byte check and never waits here.
            let result = unsafe { nix::libc::poll(&mut descriptor, 1, 0) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if descriptor.revents == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(())
        }

        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            send: impl Fn(&socket2::Socket) -> io::Result<usize>,
        ) -> Poll<io::Result<usize>> {
            loop {
                ready!(self.stream.poll_write_ready(cx))?;
                let result = self.stream.try_io(Interest::WRITABLE, || {
                    self.write_ready()?;
                    send(&socket2::SockRef::from(&self.stream))
                });
                match result {
                    // Clear Tokio's cached readiness when the unsent limit is hit.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    result => return Poll::Ready(result),
                }
            }
        }
    }

    impl AsyncRead for TcpUnderlay {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TcpUnderlay {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let buf = &buf[..buf.len().min(MAX_WRITE_BYTES)];
            self.poll_send(cx, |socket| socket.send(buf))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut slices = [IoSlice::new(&[]); 64];
            let mut count = 0;
            let mut remaining = MAX_WRITE_BYTES;
            for buf in bufs.iter().filter(|buf| !buf.is_empty()) {
                let take = remaining.min(buf.len());
                slices[count] = IoSlice::new(&buf[..take]);
                count += 1;
                remaining -= take;
                if remaining == 0 || count == slices.len() {
                    break;
                }
            }
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            self.poll_send(cx, |socket| socket.send_vectored(&slices[..count]))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[tokio::test]
    async fn unsent_limit_preserves_flight_buffers_and_write_readiness() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = tokio::net::TcpSocket::new_v4().unwrap();
            listener.set_recv_buffer_size(16 * 1024).unwrap();
            listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let listener = listener.listen(1).unwrap();
            let (client, server) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept(),
            );
            let client = client.unwrap();
            let (server, _) = server.unwrap();
            for stream in [&client, &server] {
                let socket = socket2::SockRef::from(stream);
                let before = socket.send_buffer_size().unwrap();
                set_notsent_lowat(stream).unwrap();
                let mut value = 0_u32;
                let mut size = std::mem::size_of_val(&value) as nix::libc::socklen_t;
                // Both output pointers have the size required by getsockopt().
                let result = unsafe {
                    nix::libc::getsockopt(
                        stream.as_raw_fd(),
                        nix::libc::IPPROTO_TCP,
                        TCP_NOTSENT_LOWAT,
                        (&mut value as *mut u32).cast(),
                        &mut size,
                    )
                };
                assert_eq!(result, 0);
                assert_eq!(value, TCP_NOTSENT_BYTES);
                assert_eq!(socket.send_buffer_size().unwrap(), before);
            }

            #[cfg(target_vendor = "apple")]
            {
                use std::{io, pin::Pin, task::Context};
                use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

                socket2::SockRef::from(&client)
                    .set_send_buffer_size(1024 * 1024)
                    .unwrap();
                let mut client = prepare(client);
                client.stream.writable().await.unwrap();
                let mut sent = 0;
                let block = [0x5a; 64 * 1024];
                while client.write_ready().is_ok() {
                    assert!(
                        sent < 8 * 1024 * 1024,
                        "unsent limit did not stop readiness"
                    );
                    sent += socket2::SockRef::from(&client.stream).send(&block).unwrap();
                }
                assert_eq!(
                    client.write_ready().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                // send() still accepts bytes, although Darwin reports no write readiness.
                sent += socket2::SockRef::from(&client.stream)
                    .send(&[0x5a])
                    .unwrap();
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                assert!(
                    Pin::new(&mut client)
                        .poll_write(&mut cx, b"wake")
                        .is_pending()
                );
                let mut server = server;
                let (written, received) = tokio::join!(
                    async {
                        client.write_all(b"wake").await.unwrap();
                        client.shutdown().await.unwrap();
                    },
                    async {
                        let mut data = Vec::new();
                        server.read_to_end(&mut data).await.unwrap();
                        data
                    },
                );
                let _ = written;
                assert_eq!(received.len(), sent + 4);
                assert_eq!(&received[sent..], b"wake");
            }
        })
        .await
        .unwrap();
    }
}
