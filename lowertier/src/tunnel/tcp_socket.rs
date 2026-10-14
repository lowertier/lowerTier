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
#[cfg(not(target_vendor = "apple"))]
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
    let underlay = TcpUnderlay {
        stream,
        limited,
        budget: Arc::new(AtomicUsize::new(TCP_NOTSENT_BYTES as usize)),
        #[cfg(not(target_vendor = "apple"))]
        next_update: Instant::now(),
        #[cfg(target_vendor = "apple")]
        last_sent: None,
        #[cfg(target_vendor = "apple")]
        update: Box::pin(tokio::time::sleep(Duration::from_millis(50))),
        #[cfg(target_vendor = "apple")]
        send_buffer: 0,
    };
    #[cfg(target_vendor = "apple")]
    {
        let mut underlay = underlay;
        underlay.refresh_budget();
        underlay
    }
    #[cfg(not(target_vendor = "apple"))]
    underlay
}

pub(super) struct TcpUnderlay {
    stream: TcpStream,
    limited: bool,
    budget: Arc<AtomicUsize>,
    #[cfg(not(target_vendor = "apple"))]
    next_update: Instant,
    #[cfg(target_vendor = "apple")]
    last_sent: Option<(Instant, u64)>,
    #[cfg(target_vendor = "apple")]
    update: Pin<Box<tokio::time::Sleep>>,
    #[cfg(target_vendor = "apple")]
    send_buffer: usize,
}

impl TcpUnderlay {
    pub(super) fn send_budget(&self) -> Arc<AtomicUsize> {
        self.budget.clone()
    }

    #[cfg(not(target_vendor = "apple"))]
    fn refresh_budget(&mut self) {
        if !self.limited {
            return;
        }
        let now = Instant::now();
        if now < self.next_update {
            return;
        }
        self.next_update = now + RATE_INTERVAL;
        #[cfg(target_os = "linux")]
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

    #[cfg(target_vendor = "apple")]
    fn refresh_budget(&mut self) {
        if !self.limited {
            return;
        }
        let result = self
            .send_capacity(Instant::now())
            .and_then(|(rate, flight)| {
                let bytes = queue_budget(rate);
                // The unsent ceiling excludes flight, which still needs its congestion window.
                let capacity = flight.saturating_add(bytes);
                if capacity != self.send_buffer {
                    socket2::SockRef::from(&self.stream).set_send_buffer_size(capacity)?;
                    self.send_buffer = capacity;
                }
                if bytes != self.budget.load(Ordering::Relaxed) {
                    set_notsent_lowat(&self.stream, bytes as u32)?;
                    self.budget.store(bytes, Ordering::Relaxed);
                }
                Ok(())
            });
        if let Err(error) = result {
            tracing::warn!(?error, "TCP send budget update failed for tunnel socket");
        }
    }

    #[cfg(target_vendor = "apple")]
    fn poll_budget(&mut self, cx: &mut Context<'_>) {
        use std::future::Future;
        if self.update.as_mut().poll(cx).is_ready() {
            self.refresh_budget();
            self.update
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(50));
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
    fn send_capacity(&mut self, now: Instant) -> io::Result<(u64, usize)> {
        // Darwin packs the TFO bitfields into one u32. libc's counter offsets do not match that ABI.
        #[repr(C)]
        #[derive(Default)]
        struct ConnectionInfo {
            prefix: [u32; 6],
            cwnd: u32,
            send_window: u32,
            socket_bytes: u32,
            receive_window: u32,
            rtt: u32,
            smoothed_rtt: u32,
            rtt_variance: u32,
            tfo: u32,
            tx_packets: u64,
            tx_bytes: u64,
            tx_retransmit_bytes: u64,
        }
        let mut info = ConnectionInfo::default();
        socket_info(&self.stream, nix::libc::TCP_CONNECTION_INFO, &mut info)?;
        let sent = info.tx_bytes.saturating_sub(info.tx_retransmit_bytes);
        let previous = self.last_sent.replace((now, sent));
        let rate = previous.map_or(0, |(then, bytes)| {
            (sent.saturating_sub(bytes) as f64 / now.duration_since(then).as_secs_f64().max(0.001))
                as u64
        });
        Ok((rate, info.cwnd as usize))
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
        #[cfg(target_vendor = "apple")]
        self.poll_budget(cx);
        #[cfg(not(target_vendor = "apple"))]
        self.refresh_budget();
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
        #[cfg(target_vendor = "apple")]
        self.poll_budget(cx);
        #[cfg(not(target_vendor = "apple"))]
        self.refresh_budget();
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
            #[cfg(target_os = "linux")]
            assert!(client.send_rate(Instant::now()).unwrap() > 0);
            #[cfg(target_vendor = "apple")]
            assert!(client.send_capacity(Instant::now()).unwrap().0 > 0);

            #[cfg(target_vendor = "apple")]
            {
                use std::{io, pin::Pin, task::Context};
                use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

                let capacity = socket2::SockRef::from(&client.stream)
                    .send_buffer_size()
                    .unwrap();
                assert_eq!(capacity, client.send_buffer);
                assert!(capacity >= TCP_NOTSENT_BYTES as usize);
                client.stream.writable().await.unwrap();
                let mut sent = 0;
                let block = [0x5a; 64 * 1024];
                loop {
                    assert!(
                        sent < 8 * 1024 * 1024,
                        "socket capacity did not stop writing"
                    );
                    match client.stream.try_write(&block) {
                        Ok(bytes) => sent += bytes,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("socket write failed: {error}"),
                    }
                }
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                assert!(
                    Pin::new(&mut client)
                        .poll_write(&mut cx, b"wake")
                        .is_pending()
                );
                let refreshed = client.last_sent.unwrap().0;
                let mut first_update = None;
                let timer = tokio::time::timeout(
                    Duration::from_millis(120),
                    std::future::poll_fn(|cx| {
                        let result = Pin::new(&mut client).poll_write(cx, b"wake");
                        let updated = client.last_sent.unwrap().0;
                        if updated > refreshed {
                            first_update.get_or_insert(updated);
                        }
                        result
                    }),
                )
                .await;
                assert!(timer.is_err(), "the receiver must keep the write blocked");
                assert!(
                    first_update.unwrap().duration_since(refreshed) < Duration::from_millis(100)
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
