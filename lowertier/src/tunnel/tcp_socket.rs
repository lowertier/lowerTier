use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

// Limit unsent data separately from socket capacity for packets in flight.
pub(super) const TCP_NOTSENT_BYTES: u32 = if cfg!(target_vendor = "apple") {
    256 * 1024
} else {
    128 * 1024
};
pub(super) const TCP_MAX_UNSENT_BYTES: usize = 4 * 1024 * 1024;
const RATE_INTERVAL: Duration = Duration::from_millis(100);

fn queue_budget(bytes_per_second: u64) -> usize {
    (bytes_per_second.saturating_mul(4) / 1000)
        .clamp(u64::from(TCP_NOTSENT_BYTES), TCP_MAX_UNSENT_BYTES as u64) as usize
}

#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT: i32 = nix::libc::TCP_NOTSENT_LOWAT;
// Darwin's netinet/tcp.h defines this option; libc does not expose it.
#[cfg(target_vendor = "apple")]
const TCP_NOTSENT_LOWAT: i32 = 0x201;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn set_notsent_lowat(stream: &TcpStream, value: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

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

pub(super) fn prepare(stream: TcpStream) -> TcpUnderlay {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let limited = match set_notsent_lowat(&stream, TCP_NOTSENT_BYTES) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(?error, "TCP_NOTSENT_LOWAT failed for tunnel socket");
            false
        }
    };
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    let limited = false;
    TcpUnderlay {
        stream,
        limited,
        budget: Arc::new(AtomicUsize::new(TCP_NOTSENT_BYTES as usize)),
        next_update: Instant::now(),
        #[cfg(target_vendor = "apple")]
        last_sent: None,
    }
}

pub(super) struct TcpUnderlay {
    stream: TcpStream,
    limited: bool,
    budget: Arc<AtomicUsize>,
    next_update: Instant,
    #[cfg(target_vendor = "apple")]
    last_sent: Option<(Instant, u64)>,
}

impl TcpUnderlay {
    pub(super) fn send_budget(&self) -> Arc<AtomicUsize> {
        self.budget.clone()
    }

    fn refresh_budget(&mut self) {
        if !self.limited {
            return;
        }
        let now = Instant::now();
        if now < self.next_update {
            return;
        }
        self.next_update = now + RATE_INTERVAL;
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        if let Ok(rate) = self.send_rate(now) {
            let bytes = queue_budget(rate);
            if bytes != self.budget.load(Ordering::Relaxed) {
                if let Err(error) = set_notsent_lowat(&self.stream, bytes as u32) {
                    tracing::warn!(?error, "TCP_NOTSENT_LOWAT update failed for tunnel socket");
                } else {
                    self.budget.store(bytes, Ordering::Relaxed);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn send_rate(&self, _now: Instant) -> io::Result<u64> {
        // libc's GNU tcp_info stops before the rate fields. Linux appends these fields at fixed offsets.
        #[repr(C)]
        #[derive(Default)]
        struct RateInfo {
            prefix: [u64; 13],
            pacing_rate: u64,
            max_pacing_rate: u64,
            bytes_acked: u64,
            bytes_received: u64,
            segs_out: u32,
            segs_in: u32,
            notsent_bytes: u32,
            min_rtt: u32,
            data_segs_in: u32,
            data_segs_out: u32,
            delivery_rate: u64,
        }
        let mut info = RateInfo::default();
        let size = socket_info(&self.stream, nix::libc::TCP_INFO, &mut info)?;
        if size >= std::mem::size_of::<RateInfo>() && info.delivery_rate != 0 {
            Ok(info.delivery_rate)
        } else if size >= 112 && info.pacing_rate != u64::MAX {
            Ok(info.pacing_rate)
        } else {
            Ok(0)
        }
    }

    #[cfg(target_vendor = "apple")]
    fn send_rate(&mut self, now: Instant) -> io::Result<u64> {
        // Darwin packs the TFO bitfields into one u32. libc's counter offsets do not match that ABI.
        #[repr(C)]
        #[derive(Default)]
        struct ConnectionInfo {
            prefix: [u32; 14],
            tx_packets: u64,
            tx_bytes: u64,
            tx_retransmit_bytes: u64,
        }
        let mut info = ConnectionInfo::default();
        socket_info(&self.stream, nix::libc::TCP_CONNECTION_INFO, &mut info)?;
        let sent = info.tx_bytes.saturating_sub(info.tx_retransmit_bytes);
        let previous = self.last_sent.replace((now, sent));
        Ok(previous.map_or(0, |(then, bytes)| {
            (sent.saturating_sub(bytes) as f64 / now.duration_since(then).as_secs_f64().max(0.001))
                as u64
        }))
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn socket_info<T>(stream: &TcpStream, option: i32, info: &mut T) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let mut size = std::mem::size_of::<T>() as nix::libc::socklen_t;
    // The initialized buffer remains valid for the reported output length.
    let result = unsafe {
        nix::libc::getsockopt(
            stream.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            option,
            (info as *mut T).cast(),
            &mut size,
        )
    };
    if result == 0 {
        Ok(size as usize)
    } else {
        Err(io::Error::last_os_error())
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.refresh_budget();
        #[cfg(target_vendor = "apple")]
        return self.poll_send(cx, |socket| socket.send(buf));
        #[cfg(not(target_vendor = "apple"))]
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        self.refresh_budget();
        #[cfg(target_vendor = "apple")]
        return self.poll_send(cx, |socket| socket.send_vectored(bufs));
        #[cfg(not(target_vendor = "apple"))]
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
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

#[cfg(target_vendor = "apple")]
mod darwin {
    use super::TcpUnderlay;
    use std::{
        io,
        os::fd::AsRawFd,
        task::{Context, Poll, ready},
    };
    use tokio::io::Interest;

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

        pub(super) fn poll_send(
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
}

#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[tokio::test]
    async fn unsent_limit_preserves_flight_buffers_and_write_readiness() {
        assert_eq!(queue_budget(0), TCP_NOTSENT_BYTES as usize);
        assert_eq!(
            queue_budget(450_000_000 / 8),
            225_000_usize.max(TCP_NOTSENT_BYTES as usize)
        );
        assert_eq!(queue_budget(8_000_000_000 / 8), 4_000_000);
        assert_eq!(queue_budget(u64::MAX), TCP_MAX_UNSENT_BYTES);
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
                set_notsent_lowat(stream, TCP_NOTSENT_BYTES).unwrap();
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

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut client = prepare(client);
            let mut server = server;
            client.refresh_budget();
            let mut received = [0; 16 * 1024];
            let (sent, read) = tokio::join!(
                client.write_all(&[0x5a; 16 * 1024]),
                server.read_exact(&mut received),
            );
            sent.unwrap();
            read.unwrap();
            assert_eq!(received, [0x5a; 16 * 1024]);
            assert!(client.send_rate(Instant::now()).unwrap() > 0);

            #[cfg(target_vendor = "apple")]
            {
                use std::{io, pin::Pin, task::Context};
                use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

                socket2::SockRef::from(&client.stream)
                    .set_send_buffer_size(1024 * 1024)
                    .unwrap();
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
