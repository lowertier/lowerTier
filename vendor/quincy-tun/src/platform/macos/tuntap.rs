use crate::builder::DeviceConfig;
use crate::platform::macos::sys::{
    IN6_IFF_NODAD, UTUN_CONTROL_NAME, ctl_info, ctliocginfo, in6_ifreq, siocsifmtu,
};
use crate::platform::unix::Tun;
use crate::platform::unix::device::ctl;
use libc::{
    AF_SYS_CONTROL, AF_SYSTEM, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
    c_char, c_uint, sockaddr, socklen_t,
};
use std::ffi::{CStr, c_void};
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::{io, mem, ptr};

/// macOS utun device wrapper obtained through the `PF_SYSTEM` / `SYSPROTO_CONTROL`
/// kernel control socket.
pub struct TunTap(Tun);

impl TunTap {
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self(tun)
    }

    /// Opens a new utun device using `config`.
    ///
    /// If `config.dev_name` is supplied it must start with `utun` and the
    /// numeric suffix is translated to the kernel's unit numbering scheme.
    pub fn new(config: DeviceConfig) -> io::Result<Self> {
        let packet_information = config.packet_information.unwrap_or(false);
        let id = config
            .dev_name
            .as_ref()
            .map(|tun_name| {
                if tun_name.len() > IFNAMSIZ {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "device name too long",
                    ));
                }
                if !tun_name.starts_with("utun") {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "device name must start with utun",
                    ));
                }
                tun_name[4..]
                    .parse::<u32>()
                    .map(|v| v + 1)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))
            })
            .transpose()?
            .unwrap_or(0);

        // SAFETY: `socket`, `connect`, `getsockopt` are called with valid fd,
        // properly-typed pointers, and correct sizes.
        unsafe {
            let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            let tun = crate::platform::unix::Fd::new(fd)?;
            _ = tun.set_cloexec();
            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            if let Err(err) = ctliocginfo(tun.inner, &mut info as *mut _ as *mut _) {
                return Err(io::Error::from(err));
            }

            let addr = libc::sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            let address = &addr as *const libc::sockaddr_ctl as *const sockaddr;
            if libc::connect(tun.inner, address, mem::size_of_val(&addr) as socklen_t) < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(tun.inner, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(io::Error::last_os_error());
            }
            let tun = Tun::new(tun);
            tun.set_ignore_packet_info(!packet_information);
            Ok(TunTap(tun))
        }
    }

    /// Returns the interface name (e.g. `utun1`) from the kernel.
    pub fn name(&self) -> io::Result<String> {
        let mut tun_name = [0u8; 64];
        let mut name_len: socklen_t = 64;

        let optval = &mut tun_name as *mut _ as *mut c_void;
        let optlen = &mut name_len as *mut socklen_t;
        // SAFETY: `self.0.as_raw_fd()` is a valid open fd; `tun_name` and `name_len`
        // are stack-local with correct types and sizes.
        unsafe {
            if libc::getsockopt(
                self.0.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                optval,
                optlen,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into())
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Sends `buf` over the utun device.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)
    }

    /// Sends multiple buffers using vectored I/O.
    #[inline]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.send_vectored(bufs)
    }

    /// Receives up to `buf.len()` bytes into `buf`.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }

    /// Receives into multiple buffers using vectored I/O.
    #[inline]
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.recv_vectored(bufs)
    }

    /// Builds an `ifreq` populated with this interface's name.
    pub fn request(&self) -> io::Result<libc::ifreq> {
        let tun_name = self.name()?;
        // SAFETY: `tun_name` is a valid string; `ifreq` is zeroed (zeroing is valid for POD);
        // copy length is within `ifr_name` bounds (tun_name.len() < IFNAMSIZ checked in `new`).
        unsafe {
            let mut req: libc::ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tun_name.len(),
            );
            Ok(req)
        }
    }

    /// Builds an IPv6 `in6_ifreq` populated with this interface's name.
    pub fn request_v6(&self) -> io::Result<in6_ifreq> {
        let tun_name = self.name()?;
        // SAFETY: same as `request`; `in6_ifreq` is POD so zeroing is valid.
        unsafe {
            let mut req: in6_ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifra_name.as_mut_ptr(),
                tun_name.len(),
            );
            req.ifr_ifru.ifru_flags = IN6_IFF_NODAD as _;
            Ok(req)
        }
    }

    #[inline]
    pub(crate) fn ignore_packet_info(&self) -> bool {
        self.0.ignore_packet_info()
    }

    pub(crate) fn set_ignore_packet_info(&self, ign: bool) {
        self.0.set_ignore_packet_info(ign)
    }

    /// Sets the interface MTU to `value`.
    pub fn set_mtu(&self, value: u16) -> io::Result<()> {
        // SAFETY: `ctl()` returns a valid fd; `req` is properly initialised.
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = value as i32;
            if let Err(err) = siocsifmtu(ctl.as_raw_fd(), &req) {
                return Err(io::Error::from(err));
            }
            Ok(())
        }
    }
}

impl AsRawFd for TunTap {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for TunTap {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}
