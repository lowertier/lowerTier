pub mod dns_server;
#[allow(clippy::module_inception)]
pub mod instance;

pub mod listeners;

pub(crate) mod l2_tun;

#[cfg(all(feature = "tun", any(target_os = "macos", target_os = "ios")))]
mod darwin_tun;

#[cfg(all(target_os = "linux", feature = "tun"))]
mod linux_tun;

mod public_ipv6_provider;

pub mod proxy_cidrs_monitor;

#[cfg(feature = "tun")]
pub mod virtual_nic;

#[cfg(any(windows, test))]
pub(crate) mod windows_udp_broadcast;
