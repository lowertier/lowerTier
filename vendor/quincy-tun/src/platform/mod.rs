#[cfg(unix)]
pub(crate) mod unix;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub use self::unix::DeviceImpl;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) mod linux;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub use self::linux::*;

#[cfg(target_os = "freebsd")]
pub(crate) mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::DeviceImpl;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::DeviceImpl;

#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::DeviceImpl;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use getifaddrs::Interface;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub(crate) fn get_if_addrs_by_name(if_name: String) -> std::io::Result<Vec<Interface>> {
    let addrs = getifaddrs::getifaddrs()?;
    let ifs = addrs.filter(|v| v.name == if_name).collect();
    Ok(ifs)
}

/// Internal synchronous TUN device wrapper.
///
/// This is pub(crate) because Quincy only uses [`crate::AsyncDevice`].
/// It exists so that `DeviceBuilder::build_async` can construct the
/// platform `DeviceImpl` and hand it to the async layer.
#[repr(transparent)]
pub(crate) struct SyncDevice(pub(crate) DeviceImpl);

impl std::ops::Deref for SyncDevice {
    type Target = DeviceImpl;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
