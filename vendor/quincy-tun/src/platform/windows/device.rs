use crate::builder::DeviceConfig;
use crate::platform::ETHER_ADDR_LEN;
use crate::platform::windows::dns;
use crate::platform::windows::netsh;
use crate::platform::windows::tun::{TunDevice, check_adapter_if_orphaned_devices};
use crate::{ToIpv4Address, ToIpv4Netmask, ToIpv6Address, ToIpv6Netmask};
use getifaddrs::Interface;
use ipnet::IpNet;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::RwLock;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::core::GUID;

pub(crate) const GUID_NETWORK_ADAPTER: GUID = GUID {
    data1: 0x4d36e972,
    data2: 0xe325,
    data3: 0x11ce,
    data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
};

/// A TUN device using the wintun driver.
pub struct DeviceImpl {
    lock: RwLock<()>,
    pub(crate) driver: TunDevice,
}

impl DeviceImpl {
    /// Create a new TUN device for the given configuration.
    pub(crate) fn new(config: DeviceConfig) -> io::Result<Self> {
        let mut count = 0;
        let interfaces: HashSet<String> = Self::get_all_adapter_address()?
            .into_iter()
            .map(|v| v.description)
            .collect();

        let wintun_log = config.wintun_log.unwrap_or(false);
        let wintun_file = config.wintun_file.as_deref().unwrap_or("wintun.dll");
        let ring_capacity = config.ring_capacity.unwrap_or(0x20_0000);
        let delete_driver = config.delete_driver.unwrap_or(false);
        let mut attempts = 0;

        let tun_device = loop {
            let default_name = format!("tun{count}");
            count += 1;
            let name = config.dev_name.as_deref().unwrap_or(&default_name);

            if interfaces.contains(name) {
                if config.dev_name.is_none() {
                    continue;
                }

                let is_orphaned_adapter = check_adapter_if_orphaned_devices(name);
                if !is_orphaned_adapter {
                    break TunDevice::open(
                        wintun_file,
                        name,
                        ring_capacity,
                        delete_driver,
                        wintun_log,
                    )?;
                }
            }
            let description = config.description.as_deref().unwrap_or(name);
            match TunDevice::create(
                wintun_file,
                name,
                description,
                config.device_guid,
                ring_capacity,
                delete_driver,
                wintun_log,
            ) {
                Ok(tun_device) => break tun_device,
                Err(e) => {
                    if attempts > 3 {
                        Err(e)?
                    }
                    attempts += 1;
                }
            }
        };

        Ok(DeviceImpl {
            lock: RwLock::new(()),
            driver: tun_device,
        })
    }

    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.driver.recv(buf)
    }

    pub(crate) fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.driver.try_recv(buf)
    }

    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.driver.send(buf)
    }

    pub(crate) fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.driver.try_send(buf)
    }

    pub(crate) fn wait_readable_interruptible(
        &self,
        event: &crate::platform::windows::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        self.driver
            .wait_readable_interruptible(&event.handle, timeout)
    }

    pub(crate) fn write_interruptible(
        &self,
        buf: &[u8],
        event: &crate::platform::windows::InterruptEvent,
    ) -> io::Result<usize> {
        self.driver.send_interruptible(buf, &event.handle)
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.driver.shutdown()
    }

    fn if_index_impl(&self) -> io::Result<u32> {
        Ok(self.driver.index())
    }

    fn luid_impl(&self) -> NET_LUID_LH {
        self.driver.luid()
    }

    fn get_all_adapter_address() -> io::Result<Vec<Interface>> {
        Ok(getifaddrs::getifaddrs()?.collect())
    }

    fn name_impl(&self) -> io::Result<String> {
        self.driver.get_name()
    }
}

impl DeviceImpl {
    pub fn name(&self) -> io::Result<String> {
        let _guard = self.lock.read().unwrap();
        self.name_impl()
    }

    pub fn set_name(&self, value: &str) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        let name = self.name_impl()?;
        if value == name {
            return Ok(());
        }
        netsh::set_interface_name(&name, value)
    }

    pub fn if_index(&self) -> io::Result<u32> {
        let _guard = self.lock.read().unwrap();
        self.if_index_impl()
    }

    pub fn if_luid(&self) -> io::Result<NET_LUID_LH> {
        let _guard = self.lock.read().unwrap();
        Ok(self.luid_impl())
    }

    pub fn enabled(&self, value: bool) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        self.driver.enabled(value)
    }

    pub fn addresses(&self) -> io::Result<Vec<IpAddr>> {
        let _guard = self.lock.read().unwrap();
        let index = self.if_index_impl()?;
        Ok(Self::get_all_adapter_address()?
            .into_iter()
            .filter(|v| v.index == Some(index))
            .filter_map(|v| v.address.ip_addr())
            .collect())
    }

    pub fn set_network_address<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: IPv4,
        netmask: Netmask,
        destination: Option<IPv4>,
    ) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::set_address(
            self.if_index_impl()?,
            address.ipv4()?.into(),
            netmask.prefix()?,
            destination.map(|v| v.ipv4()).transpose()?.map(|v| v.into()),
        )
    }

    pub fn add_address_v4<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: IPv4,
        netmask: Netmask,
    ) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        let interface = netconfig_rs::Interface::try_from_index(self.if_index_impl()?)
            .map_err(io::Error::from)?;
        interface
            .add_address(IpNet::new_assert(address.ipv4()?.into(), netmask.prefix()?))
            .map_err(io::Error::from)
    }

    pub fn remove_address(&self, addr: IpAddr) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::remove_address(self.if_index_impl()?, addr)
    }

    pub fn add_address_v6<IPv6: ToIpv6Address, Netmask: ToIpv6Netmask>(
        &self,
        addr: IPv6,
        netmask: Netmask,
    ) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::add_address(
            self.if_index_impl()?,
            addr.ipv6()?.into(),
            netmask.prefix()?,
            None,
        )
    }

    pub fn mtu(&self) -> io::Result<u16> {
        let _guard = self.lock.read().unwrap();
        let index = self.if_index_impl()?;
        Ok(crate::platform::windows::ffi::get_mtu_by_index(index, true)? as _)
    }

    pub fn mtu_v6(&self) -> io::Result<u16> {
        let _guard = self.lock.read().unwrap();
        let index = self.if_index_impl()?;
        Ok(crate::platform::windows::ffi::get_mtu_by_index(index, false)? as _)
    }

    pub fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::set_interface_mtu(self.if_index_impl()?, mtu as _, true)
    }

    pub fn set_mtu_v6(&self, mtu: u16) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::set_interface_mtu(self.if_index_impl()?, mtu as _, false)
    }

    pub fn set_mac_address(&self, _eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn set_metric(&self, metric: u16) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        super::ffi::set_interface_metric(self.if_index_impl()?, metric as u32)
    }

    pub fn version(&self) -> io::Result<String> {
        let _guard = self.lock.read().unwrap();
        self.driver.version()
    }

    pub fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        dns::set_dns_servers(self.if_index_impl()?, &self.luid_impl(), dns_servers)
    }

    pub fn clear_dns_servers(&self, is_ipv4: bool) -> io::Result<()> {
        let _guard = self.lock.write().unwrap();
        dns::clear_dns_servers(self.if_index_impl()?, &self.luid_impl(), is_ipv4)
    }
}
