use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::platform::{DeviceImpl, SyncDevice};

type IPV4 = (
    io::Result<Ipv4Addr>,
    io::Result<u8>,
    Option<io::Result<Ipv4Addr>>,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Layer {
    L2,
    #[default]
    L3,
}

/// Configuration for a TUN interface.
#[derive(Clone, Default, Debug)]
pub(crate) struct DeviceConfig {
    pub(crate) dev_name: Option<String>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) layer: Layer,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) queues: usize,
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
    pub(crate) packet_information: Option<bool>,
    #[cfg(target_os = "macos")]
    pub(crate) associate_route: Option<bool>,
    #[cfg(target_os = "linux")]
    pub(crate) offload: Option<bool>,
    #[cfg(windows)]
    pub(crate) description: Option<String>,
    #[cfg(windows)]
    pub(crate) device_guid: Option<u128>,
    #[cfg(windows)]
    pub(crate) wintun_log: Option<bool>,
    #[cfg(windows)]
    pub(crate) wintun_file: Option<String>,
    #[cfg(windows)]
    pub(crate) ring_capacity: Option<u32>,
    #[cfg(windows)]
    pub(crate) delete_driver: Option<bool>,
}

/// A builder for configuring a TUN interface.
///
/// # Example
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use quincy_tun::DeviceBuilder;
///
/// let dev = DeviceBuilder::new()
///     .name("tun0")
///     .mtu(1400)
///     .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24, None)
///     .build_async()?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Default)]
pub struct DeviceBuilder {
    dev_name: Option<String>,
    layer: Layer,
    queues: usize,
    enabled: Option<bool>,
    mtu: Option<u16>,
    ipv4: Option<IPV4>,
    ipv6: Option<Vec<(io::Result<Ipv6Addr>, io::Result<u8>)>>,
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
    packet_information: Option<bool>,
    #[cfg(target_os = "macos")]
    associate_route: Option<bool>,
    #[cfg(target_os = "linux")]
    offload: Option<bool>,
    #[cfg(windows)]
    description: Option<String>,
    #[cfg(windows)]
    device_guid: Option<u128>,
    #[cfg(windows)]
    wintun_log: Option<bool>,
    #[cfg(windows)]
    wintun_file: Option<String>,
    #[cfg(windows)]
    ring_capacity: Option<u32>,
    #[cfg(windows)]
    delete_driver: Option<bool>,
}

impl DeviceBuilder {
    /// Creates a new `DeviceBuilder` with sensible defaults (device enabled).
    pub fn new() -> Self {
        Self::default().enable(true)
    }

    /// Sets the device name.
    pub fn name<S: Into<String>>(mut self, dev_name: S) -> Self {
        self.dev_name = Some(dev_name.into());
        self
    }

    /// Sets the OSI layer for the virtual device.
    pub fn layer(mut self, layer: Layer) -> Self {
        self.layer = layer;
        self
    }

    /// Sets the number of Linux TUN or TAP queues.
    pub fn queues(mut self, queues: usize) -> Self {
        self.queues = queues;
        self
    }

    /// Sets the device MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Configures the IPv4 address.
    ///
    /// - `address`: The IPv4 address.
    /// - `mask`: The subnet mask or prefix length.
    /// - `destination`: Optional destination address for point-to-point links.
    pub fn ipv4<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        mut self,
        address: IPv4,
        mask: Netmask,
        destination: Option<IPv4>,
    ) -> Self {
        self.ipv4 = Some((address.ipv4(), mask.prefix(), destination.map(|v| v.ipv4())));
        self
    }

    /// Configures a single IPv6 address.
    pub fn ipv6<IPv6: ToIpv6Address, Netmask: ToIpv6Netmask>(
        mut self,
        address: IPv6,
        mask: Netmask,
    ) -> Self {
        if let Some(v) = &mut self.ipv6 {
            v.push((address.ipv6(), mask.prefix()));
        } else {
            self.ipv6 = Some(vec![(address.ipv6(), mask.prefix())]);
        }

        self
    }

    /// Enables or disables the network interface upon creation (default: enabled).
    pub fn enable(mut self, enable: bool) -> Self {
        self.enabled = Some(enable);
        self
    }

    /// Enables or disables packet information headers on Unix platforms.
    ///
    /// Disabled by default.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
    pub fn packet_information(mut self, packet_information: bool) -> Self {
        self.packet_information = Some(packet_information);
        self
    }

    /// Enables TUN offloads (TSO/GSO/GRO) on Linux.
    ///
    /// After enabling, use `recv_multiple`/`send_multiple` on the
    /// [`crate::AsyncDevice`] for batch I/O.
    #[cfg(target_os = "linux")]
    pub fn offload(mut self, offload: bool) -> Self {
        self.offload = Some(offload);
        self
    }

    /// Platforms with a native `DeviceImpl::new` (Linux, macOS, FreeBSD, Windows).
    /// On the Unix fallback (Android/iOS) only `from_fd` is supported.
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
    ))]
    pub(crate) fn build_config(&mut self) -> DeviceConfig {
        DeviceConfig {
            dev_name: self.dev_name.take(),
            layer: self.layer,
            queues: self.queues.max(1),
            #[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
            packet_information: self.packet_information.take(),
            #[cfg(target_os = "macos")]
            associate_route: self.associate_route,
            #[cfg(target_os = "linux")]
            offload: self.offload.take(),
            #[cfg(windows)]
            description: self.description.take(),
            #[cfg(windows)]
            device_guid: self.device_guid,
            #[cfg(windows)]
            wintun_log: self.wintun_log.take(),
            #[cfg(windows)]
            wintun_file: self.wintun_file.take(),
            #[cfg(windows)]
            ring_capacity: self.ring_capacity.take(),
            #[cfg(windows)]
            delete_driver: self.delete_driver.take(),
        }
    }

    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
    ))]
    pub(crate) fn config(self, device: &DeviceImpl) -> io::Result<()> {
        if let Some(mtu) = self.mtu {
            device.set_mtu(mtu)?;
        }

        if let Some((address, prefix, destination)) = self.ipv4 {
            let prefix = prefix?;
            let address = address?;
            let destination = destination.transpose()?;
            device.set_network_address(address, prefix, destination)?;
        }

        if let Some(ipv6) = self.ipv6 {
            for (address, prefix) in ipv6 {
                let prefix = prefix?;
                let address = address?;
                device.add_address_v6(address, prefix)?;
            }
        }

        if let Some(enabled) = self.enabled {
            device.enabled(enabled)?;
        }

        Ok(())
    }

    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
    ))]
    pub(crate) fn build_sync(mut self) -> io::Result<SyncDevice> {
        let device = DeviceImpl::new(self.build_config())?;
        self.config(&device)?;
        Ok(SyncDevice(device))
    }

    /// Builds an asynchronous device.
    ///
    /// Not available on the Unix fallback (Android/iOS); use
    /// `AsyncDevice::from_fd` on those platforms.
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
    ))]
    pub fn build_async(self) -> io::Result<crate::AsyncDevice> {
        let sync_device = self.build_sync()?;
        crate::AsyncDevice::new_dev(sync_device.0)
    }

    /// Builds all file descriptors for one Linux multiqueue device.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    pub fn build_async_queues(mut self) -> io::Result<Vec<crate::AsyncDevice>> {
        let mut device_config = self.build_config();
        let queue_count = device_config.queues;
        let first = DeviceImpl::new(device_config.clone())?;
        self.config(&first)?;
        let device_name = first.name()?;
        let mut devices = Vec::with_capacity(queue_count);
        devices.push(crate::AsyncDevice::new_dev(first)?);

        device_config.dev_name = Some(device_name);
        for _ in 1..queue_count {
            devices.push(crate::AsyncDevice::new_dev(DeviceImpl::new(
                device_config.clone(),
            )?)?);
        }
        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceBuilder, Layer};

    #[test]
    fn builder_keeps_tap_layer_and_queue_count() {
        let mut builder = DeviceBuilder::new().layer(Layer::L2).queues(3);
        let config = builder.build_config();

        assert_eq!(config.layer, Layer::L2);
        assert_eq!(config.queues, 3);
    }
}

/// Trait for converting various types into an IPv4 address.
pub trait ToIpv4Address {
    fn ipv4(&self) -> io::Result<Ipv4Addr>;
}

impl ToIpv4Address for Ipv4Addr {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        Ok(*self)
    }
}

impl ToIpv4Address for IpAddr {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        match self {
            IpAddr::V4(ip) => Ok(*ip),
            IpAddr::V6(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address",
            )),
        }
    }
}

impl ToIpv4Address for String {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        self.as_str().ipv4()
    }
}

impl ToIpv4Address for &str {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        Ipv4Addr::from_str(self)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 str"))
    }
}

/// Trait for converting various types into an IPv6 address.
pub trait ToIpv6Address {
    fn ipv6(&self) -> io::Result<Ipv6Addr>;
}

impl ToIpv6Address for Ipv6Addr {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        Ok(*self)
    }
}

impl ToIpv6Address for IpAddr {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        match self {
            IpAddr::V4(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address",
            )),
            IpAddr::V6(ip) => Ok(*ip),
        }
    }
}

impl ToIpv6Address for String {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        self.as_str().ipv6()
    }
}

impl ToIpv6Address for &str {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        Ipv6Addr::from_str(self)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 str"))
    }
}

/// Trait for converting various types into an IPv4 netmask (prefix length).
pub trait ToIpv4Netmask {
    fn prefix(&self) -> io::Result<u8>;

    fn netmask(&self) -> io::Result<Ipv4Addr> {
        let ip = u32::MAX
            .checked_shl(32 - self.prefix()? as u32)
            .unwrap_or(0);
        Ok(Ipv4Addr::from(ip))
    }
}

impl ToIpv4Netmask for u8 {
    fn prefix(&self) -> io::Result<u8> {
        if *self > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP prefix length",
            ));
        }
        Ok(*self)
    }
}

impl ToIpv4Netmask for Ipv4Addr {
    fn prefix(&self) -> io::Result<u8> {
        let ip = u32::from_be_bytes(self.octets());
        if ip.leading_ones() != ip.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask",
            ));
        }
        Ok(ip.leading_ones() as u8)
    }
}

impl ToIpv4Netmask for String {
    fn prefix(&self) -> io::Result<u8> {
        ToIpv4Netmask::prefix(&self.as_str())
    }
}

impl ToIpv4Netmask for &str {
    fn prefix(&self) -> io::Result<u8> {
        Ipv4Addr::from_str(self)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid netmask str"))
            .and_then(|ip| ip.prefix())
    }
}

/// Trait for converting various types into an IPv6 netmask (prefix length).
pub trait ToIpv6Netmask {
    fn prefix(&self) -> io::Result<u8>;

    fn netmask(&self) -> io::Result<Ipv6Addr> {
        let ip = u128::MAX
            .checked_shl(128 - self.prefix()? as u32)
            .unwrap_or(0);
        Ok(Ipv6Addr::from(ip))
    }
}

impl ToIpv6Netmask for u8 {
    fn prefix(&self) -> io::Result<u8> {
        if *self > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP prefix length",
            ));
        }
        Ok(*self)
    }
}

impl ToIpv6Netmask for Ipv6Addr {
    fn prefix(&self) -> io::Result<u8> {
        let ip = u128::from_be_bytes(self.octets());
        if ip.leading_ones() != ip.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask",
            ));
        }
        Ok(ip.leading_ones() as u8)
    }
}

impl ToIpv6Netmask for String {
    fn prefix(&self) -> io::Result<u8> {
        ToIpv6Netmask::prefix(&self.as_str())
    }
}

impl ToIpv6Netmask for &str {
    fn prefix(&self) -> io::Result<u8> {
        Ipv6Addr::from_str(self)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid netmask str"))
            .and_then(|ip| ip.prefix())
    }
}
