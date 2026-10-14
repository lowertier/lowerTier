pub mod dns_server;
#[allow(clippy::module_inception)]
pub mod instance;
#[cfg(all(target_os = "linux", feature = "tun"))]
pub(crate) mod tun_scheduler;

pub mod listeners;

mod ip_proxy;
pub(crate) mod l2_tun;

#[cfg(all(feature = "tun", any(target_os = "macos", target_os = "ios")))]
mod darwin_tun;

#[cfg(all(target_os = "linux", feature = "tun"))]
mod linux_tun;
#[cfg(all(target_os = "linux", feature = "tun"))]
mod linux_tun_uring;

mod public_ipv6_provider;

pub mod proxy_cidrs_monitor;

#[cfg(feature = "tun")]
mod nic_ingress;
#[cfg(feature = "tun")]
mod nic_ingress_workers;
#[cfg(feature = "tun")]
mod tap_mac;
#[cfg(feature = "tun")]
pub mod virtual_nic;

#[cfg(windows)]
pub(crate) mod windows_udp_broadcast;
