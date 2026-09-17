use std::{
    future::Future,
    io,
    net::UdpSocket,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use nix::libc;
use quinn::{AsyncTimer, AsyncUdpSocket};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::time::{Sleep, sleep_until};

pub(super) fn default_runtime() -> Option<Arc<dyn quinn::Runtime>> {
    tokio::runtime::Handle::try_current().ok()?;
    Some(Arc::new(Runtime))
}

#[derive(Debug)]
struct Runtime;

impl quinn::Runtime for Runtime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        match Timer::new(deadline) {
            Ok(timer) => Box::pin(timer),
            Err(error) => {
                tracing::warn!(?error, "QUIC timerfd unavailable; using Tokio timer");
                quinn::TokioRuntime.new_timer(deadline)
            }
        }
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        quinn::TokioRuntime.spawn(future);
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

// Tokio's millisecond timer rounds sub-millisecond pacing deadlines up. A
// reusable timerfd lets small UDP batches sustain the controller's send rate.
#[derive(Debug)]
struct Timer {
    fd: AsyncFd<OwnedFd>,
    deadline: Instant,
    armed: Option<Instant>,
    fallback: Option<Pin<Box<Sleep>>>,
}

impl Timer {
    fn new(deadline: Instant) -> io::Result<Self> {
        // SAFETY: timerfd_create has no pointer arguments. The successful fd is
        // transferred once to OwnedFd, which also closes it on registration error.
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: AsyncFd::with_interest(fd, Interest::READABLE)?,
            deadline,
            armed: None,
            fallback: None,
        })
    }

    fn poll_timer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let now = Instant::now();
        if now >= self.deadline {
            return Poll::Ready(Ok(()));
        }
        if self.armed != Some(self.deadline) {
            let delay = self.deadline - now;
            let specification = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: delay.as_secs().try_into().unwrap_or(libc::time_t::MAX),
                    tv_nsec: delay.subsec_nanos() as _,
                },
            };
            // SAFETY: fd remains owned; specification is initialized and valid
            // for the call. A null old_value requests no previous state.
            let result = unsafe {
                libc::timerfd_settime(self.fd.as_raw_fd(), 0, &specification, std::ptr::null_mut())
            };
            if result < 0 {
                return Poll::Ready(Err(io::Error::last_os_error()));
            }
            self.armed = Some(self.deadline);
        }
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let mut expirations = 0u64;
                // SAFETY: the owned nonblocking timerfd writes exactly one u64
                // to this valid, aligned output buffer.
                let bytes =
                    unsafe { libc::read(fd.as_raw_fd(), (&mut expirations as *mut u64).cast(), 8) };
                if bytes < 0 {
                    Err(io::Error::last_os_error())
                } else if bytes == 8 {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short timerfd read",
                    ))
                }
            }) {
                Ok(Ok(())) => return Poll::Ready(Ok(())),
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
        self.deadline = deadline;
        if let Some(fallback) = &mut self.fallback {
            fallback.as_mut().reset(deadline.into());
        }
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(fallback) = &mut self.fallback {
            return Future::poll(fallback.as_mut(), cx);
        }
        match self.poll_timer(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                tracing::warn!(?error, "QUIC timerfd failed; using Tokio timer");
                self.fallback = Some(Box::pin(sleep_until(self.deadline.into())));
                Future::poll(self.fallback.as_mut().unwrap().as_mut(), cx)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, time::Duration};

    #[tokio::test]
    async fn timer_observes_rearmed_deadline_and_reuses_readiness() {
        let mut timer = Box::pin(Timer::new(Instant::now() + Duration::from_secs(1)).unwrap());
        poll_fn(|cx| {
            assert!(timer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        for delay in [2, 5, 1] {
            let deadline = Instant::now() + Duration::from_millis(delay);
            timer.as_mut().reset(deadline);
            tokio::time::timeout(
                Duration::from_secs(1),
                poll_fn(|cx| timer.as_mut().poll(cx)),
            )
            .await
            .unwrap();
            assert!(Instant::now() >= deadline);
        }
        timer
            .as_mut()
            .reset(Instant::now() - Duration::from_millis(1));
        poll_fn(|cx| {
            assert!(timer.as_mut().poll(cx).is_ready());
            Poll::Ready(())
        })
        .await;
    }
}
