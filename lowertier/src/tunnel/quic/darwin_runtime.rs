//! Sub-millisecond QUIC deadlines using one reusable, pollable kernel timer.
//! No spin loop, timer thread, per-expiration allocation, or traffic-rate override.
use nix::libc;
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime as _};
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
use tokio::io::{Interest, unix::AsyncFd};

pub(super) fn default_runtime() -> Option<Arc<dyn quinn::Runtime>> {
    tokio::runtime::Handle::try_current().ok()?;
    if std::env::var_os("LOWTIER_QUIC_DISABLE_PRECISE_TIMER").is_some() {
        return Some(Arc::new(quinn::TokioRuntime));
    }
    Some(Arc::new(Runtime))
}

#[derive(Debug)]
struct Runtime;
impl quinn::Runtime for Runtime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        match Timer::new(deadline) {
            Ok(timer) => Box::pin(timer),
            Err(error) => {
                tracing::warn!(?error, "QUIC kqueue timer unavailable; using Tokio timer");
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

#[derive(Debug)]
struct Timer {
    queue: AsyncFd<OwnedFd>,
    deadline: Instant,
    armed: Option<Instant>,
    fallback: Option<Pin<Box<dyn AsyncTimer>>>,
}
impl Timer {
    fn new(deadline: Instant) -> io::Result<Self> {
        // SAFETY: no pointer arguments; ownership is transferred once on success.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            queue: AsyncFd::with_interest(fd, Interest::READABLE)?,
            deadline,
            armed: None,
            fallback: None,
        })
    }

    fn arm(&mut self, now: Instant) -> io::Result<()> {
        let nanos = self
            .deadline
            .saturating_duration_since(now)
            .as_nanos()
            .clamp(1, i64::MAX as u128) as i64;
        let change = libc::kevent64_s {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            // Default coalescing can turn 250 us pacing into multi-ms bursts.
            // Use critical mode only for short transport deadlines.
            fflags: libc::NOTE_NSECONDS
                | if nanos < 10_000_000 {
                    libc::NOTE_CRITICAL
                } else {
                    0
                },
            data: nanos,
            udata: 0,
            ext: [0; 2],
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: initialized change; no output events; zero timeout never blocks.
        let result = unsafe {
            libc::kevent64(
                self.queue.get_ref().as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                0,
                &zero,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        self.armed = Some(self.deadline);
        Ok(())
    }

    fn drain(fd: &OwnedFd) -> io::Result<()> {
        let mut event: libc::kevent64_s = unsafe { std::mem::zeroed() };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: initialized event buffer for one result; nonblocking zero timeout.
        let count =
            unsafe { libc::kevent64(fd.as_raw_fd(), std::ptr::null(), 0, &mut event, 1, 0, &zero) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if event.flags & libc::EV_ERROR != 0 {
            return Err(io::Error::from_raw_os_error(event.data as i32));
        }
        Ok(())
    }

    fn poll_timer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let now = Instant::now();
            if now >= self.deadline {
                return Poll::Ready(Ok(()));
            }
            if self.armed != Some(self.deadline) {
                self.arm(now)?;
            }
            let result = {
                let mut ready = ready!(self.queue.poll_read_ready(cx))?;
                ready.try_io(|fd| Self::drain(fd.get_ref()))
            };
            match result {
                Ok(Ok(())) => {
                    // A reset can leave an old expiration ready. Recheck the
                    // current deadline and rearm rather than returning early.
                    self.armed = None;
                }
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
        if let Some(timer) = self.fallback.as_mut() {
            timer.as_mut().reset(deadline);
        }
    }
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(timer) = self.fallback.as_mut() {
            return timer.as_mut().poll(cx);
        }
        match self.poll_timer(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                tracing::warn!(?error, "QUIC kqueue timer failed; using Tokio timer");
                self.fallback = Some(quinn::TokioRuntime.new_timer(self.deadline));
                self.fallback.as_mut().unwrap().as_mut().poll(cx)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, time::Duration};
    #[tokio::test]
    async fn rearm_preserves_deadlines_and_reuses_one_descriptor() {
        let mut timer = Box::pin(Timer::new(Instant::now() + Duration::from_secs(1)).unwrap());
        let descriptor = timer.queue.get_ref().as_raw_fd();
        poll_fn(|cx| {
            assert!(timer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        for micros in [250, 2500, 500, 50] {
            let deadline = Instant::now() + Duration::from_micros(micros);
            timer.as_mut().reset(deadline);
            tokio::time::timeout(
                Duration::from_secs(1),
                poll_fn(|cx| timer.as_mut().poll(cx)),
            )
            .await
            .unwrap();
            assert!(Instant::now() >= deadline);
            assert!(timer.fallback.is_none());
            assert_eq!(timer.queue.get_ref().as_raw_fd(), descriptor);
        }
    }
    #[tokio::test]
    async fn stale_expiration_cannot_finish_a_later_deadline() {
        let mut timer = Box::pin(Timer::new(Instant::now() + Duration::from_millis(1)).unwrap());
        poll_fn(|cx| {
            assert!(timer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        let deadline = Instant::now() + Duration::from_millis(5);
        timer.as_mut().reset(deadline);
        tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| timer.as_mut().poll(cx)),
        )
        .await
        .unwrap();
        assert!(Instant::now() >= deadline);
        assert!(timer.fallback.is_none());
    }
    #[tokio::test]
    async fn expired_deadline_is_ready_without_arming() {
        let mut timer = Box::pin(Timer::new(Instant::now() - Duration::from_millis(1)).unwrap());
        poll_fn(|cx| {
            assert!(timer.as_mut().poll(cx).is_ready());
            Poll::Ready(())
        })
        .await;
        assert_eq!(timer.armed, None);
    }
}
