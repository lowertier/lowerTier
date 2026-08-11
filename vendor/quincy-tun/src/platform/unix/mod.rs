mod sockaddr;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
pub(crate) use sockaddr::sockaddr_union;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[allow(unused_imports)]
pub(crate) use sockaddr::ipaddr_to_sockaddr;

mod fd;
pub(crate) use self::fd::Fd;
mod tun;
pub(crate) use self::tun::Tun;

pub(crate) mod device;

#[cfg(any(target_os = "android", target_os = "ios"))]
/// A TUN device for Android/iOS.
///
/// On these platforms the TUN fd is created by the OS (e.g. Android VpnService).
/// Use [`crate::AsyncDevice::from_fd`] to wrap it.  Interface-configuration
/// methods (`name`, `enabled`, `mtu`) are not available and return
/// `Err(Unsupported)` because the raw fd alone does not expose them.
pub struct DeviceImpl {
    pub(crate) tun: Tun,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl DeviceImpl {
    pub(crate) fn from_tun(tun: Tun) -> std::io::Result<Self> {
        Ok(Self { tun })
    }

    /// Returns `Err(Unsupported)` — the interface name cannot be queried from
    /// a raw TUN fd on this platform without platform-specific APIs.
    pub fn name(&self) -> std::io::Result<String> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// Returns `Err(Unsupported)` — see [`name`](Self::name).
    pub fn enabled(&self, _value: bool) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// Returns `Err(Unsupported)` — see [`name`](Self::name).
    pub fn mtu(&self) -> std::io::Result<u16> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}
