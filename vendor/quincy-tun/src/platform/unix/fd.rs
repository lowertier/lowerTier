use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

/// POSIX file descriptor support for `io` traits.
pub(crate) struct Fd {
    pub(crate) inner: RawFd,
    borrow: bool,
}

impl Fd {
    #[cfg(any(
        target_os = "windows",
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    pub(crate) fn new(value: RawFd) -> io::Result<Self> {
        if value < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Creates an `Fd` without checking that `value` is valid.
    ///
    /// # Safety
    ///
    /// `value` must be a valid, open file descriptor (or `-1` if the
    /// `Fd` will never be used for I/O before being overwritten).
    pub(crate) unsafe fn new_unchecked(value: RawFd) -> Self {
        unsafe {
            // SAFETY: delegates to `new_unchecked_with_borrow` which only stores the value.
            Fd::new_unchecked_with_borrow(value, false)
        }
    }

    /// Creates an `Fd` without checking that `value` is valid, optionally
    /// marking it as borrowed (so `Drop` will not close it).
    ///
    /// # Safety
    ///
    /// `value` must be a valid, open file descriptor (or `-1`).
    pub(crate) unsafe fn new_unchecked_with_borrow(value: RawFd, borrow: bool) -> Self {
        Fd {
            inner: value,
            borrow,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn set_cloexec(&self) -> io::Result<()> {
        // SAFETY: `self.inner` is a valid open fd (invariant of Fd).
        unsafe {
            let flags = libc::fcntl(self.inner, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(self.inner, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Enable non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        // SAFETY: fd is valid; `nonblocking` is a stack-local `c_int`.
        match unsafe { libc::ioctl(self.as_raw_fd(), libc::FIONBIO, &mut nonblocking) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Reads up to `buf.len()` bytes from the file descriptor into `buf`.
    #[inline]
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        // SAFETY: `fd` is valid; `buf.as_mut_ptr()` and `buf.len()` are correct for this slice.
        let amount = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }

    /// Reads into multiple buffers using vectored I/O.
    #[inline]
    pub fn readv(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        if bufs.len() > max_iov() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // SAFETY: fd is valid; `bufs` is a valid slice of `IoSliceMut` whose pointers are valid.
        let amount = unsafe {
            libc::readv(
                self.as_raw_fd(),
                bufs.as_mut_ptr() as *mut libc::iovec as *const libc::iovec,
                bufs.len() as libc::c_int,
            )
        };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }

    /// Writes up to `buf.len()` bytes from `buf` to the file descriptor.
    #[inline]
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        // SAFETY: `fd` is valid; `buf.as_ptr()` and `buf.len()` are correct for this slice.
        let amount = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }

    /// Writes multiple buffers using vectored I/O.
    #[inline]
    pub fn writev(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        if bufs.len() > max_iov() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // SAFETY: fd is valid; `bufs` is a valid slice of `IoSlice` whose pointers are valid.
        let amount = unsafe {
            libc::writev(
                self.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as libc::c_int,
            )
        };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_vendor = "apple",
))]
pub(crate) const fn max_iov() -> usize {
    libc::IOV_MAX as usize
}

#[cfg(any(
    target_os = "android",
    target_os = "emscripten",
    target_os = "linux",
    target_os = "nto",
))]
pub(crate) const fn max_iov() -> usize {
    libc::UIO_MAXIOV as usize
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.inner;
        self.inner = -1;
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if !self.borrow && self.inner >= 0 {
            // SAFETY: `self.inner` was checked `>= 0` and was a valid open fd when stored.
            unsafe { libc::close(self.inner) };
            self.inner = -1;
        }
    }
}
