use std::{
    collections::BTreeSet,
    ffi::CString,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZero,
    os::fd::AsRawFd,
};

use anyhow::Context;
use async_trait::async_trait;
use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkDeserializable,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourHeader, NeighbourMessage,
        NeighbourState,
    },
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    ifaddrs::getifaddrs,
    libc::{self, Ioctl, SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCSIFMTU, ifreq, ioctl},
    net::if_::InterfaceFlags,
    sys::socket::SockaddrLike as _,
};
use pnet::ipnetwork::ip_mask_to_prefix;

use super::{Error, IfConfiguerTrait};

pub(crate) fn dummy_socket() -> Result<std::net::UdpSocket, Error> {
    Ok(std::net::UdpSocket::bind("0:0")?)
}

fn build_ifreq(name: &str) -> ifreq {
    let c_str = CString::new(name).unwrap();
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = c_str.as_bytes_with_nul();
    for (i, &b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn send_netlink_req<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    flags: u16,
) -> Result<Socket, Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut req: NetlinkMessage<T> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(req));
    req.header.flags = flags;

    req.finalize();
    let mut buf = vec![0; req.header.length as _];
    req.serialize(&mut buf);

    tracing::debug!("net link request >>> {:?}", req);
    socket.send(&buf, 0)?;

    Ok(socket)
}

fn send_netlink_req_and_wait_one_resp<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    is_remove: bool,
) -> Result<(), Error> {
    let socket = send_netlink_req(
        req,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REQUEST | if !is_remove { NLM_F_EXCL } else { 0 },
    )?;
    let resp = socket.recv_from_full()?;
    let ret = NetlinkMessage::<T>::deserialize(&resp.0)
        .with_context(|| "Failed to deserialize netlink message")?;

    tracing::debug!("net link response <<< {:?}", ret);

    match ret.payload {
        NetlinkPayload::Error(e) => {
            if e.code == NonZero::new(0) {
                Ok(())
            } else {
                Err(e.to_io().into())
            }
        }
        p => {
            tracing::error!("Unexpected netlink response: {:?}", p);
            Err(anyhow::anyhow!("Unexpected netlink response").into())
        }
    }
}

fn addr_to_ip(addr: RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(addr.into()),
        RouteAddress::Inet6(addr) => Some(addr.into()),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteIdentity {
    destination: IpAddr,
    prefix: u8,
    ifindex: Option<u32>,
}

impl From<&RouteMessage> for RouteIdentity {
    fn from(msg: &RouteMessage) -> Self {
        let mut destination = None;
        let mut ifindex = None;

        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Destination(addr) => {
                    destination = addr_to_ip(addr.clone());
                }
                RouteAttribute::Oif(i) => {
                    ifindex = Some(*i);
                }
                _ => {}
            }
        }
        // Netlink omits the destination attribute for a default route.
        let destination = destination.unwrap_or_else(|| match msg.header.address_family {
            AddressFamily::Inet => Ipv4Addr::UNSPECIFIED.into(),
            AddressFamily::Inet6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => panic!("invalid destination family"),
        });
        Self {
            destination,
            prefix: msg.header.destination_prefix_length,
            ifindex,
        }
    }
}

pub struct NetlinkIfConfiger {}

impl NetlinkIfConfiger {
    pub(crate) fn get_interface_index(name: &str) -> Result<u32, Error> {
        let name = CString::new(name).with_context(|| "failed to convert interface name")?;
        match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => Err(std::io::Error::last_os_error().into()),
            n => Ok(n),
        }
    }

    fn get_prefix_len(name: &str, ip: Ipv4Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V4(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ip(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(ip)));

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::DelAddress(message),
            true,
        )
    }

    fn get_prefix_len_ipv6(name: &str, ip: Ipv6Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V6(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ipv6(name: &str, ip: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet6;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V6(ip)));

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::DelAddress(message),
            true,
        )
    }

    pub(crate) fn mtu_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        value: libc::c_int,
    ) -> Result<u32, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let dummy_socket = dummy_socket()?;

        let mut ifr: ifreq = build_ifreq(name);

        unsafe {
            ifr.ifr_ifru.ifru_mtu = value;

            // 使用ioctl获取MTU
            if ioctl(dummy_socket.as_raw_fd(), op.try_into().unwrap(), &ifr) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu as u32 })
    }

    pub fn list_addresses(name: &str) -> Result<Vec<IpInet>, Error> {
        let mut result = vec![];

        for interface in getifaddrs()
            .with_context(|| "failed to call getifaddrs")?
            .filter(|x| x.interface_name == name)
        {
            let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
                continue;
            };

            use nix::sys::socket::AddressFamily::{Inet, Inet6};

            let (address, netmask) = match (address.family(), netmask.family()) {
                (Some(Inet), Some(Inet)) => (
                    IpAddr::V4(address.as_sockaddr_in().unwrap().ip()),
                    IpAddr::V4(netmask.as_sockaddr_in().unwrap().ip()),
                ),
                (Some(Inet6), Some(Inet6)) => (
                    IpAddr::V6(address.as_sockaddr_in6().unwrap().ip()),
                    IpAddr::V6(netmask.as_sockaddr_in6().unwrap().ip()),
                ),
                (_, _) => continue,
            };

            let prefix = ip_mask_to_prefix(netmask).unwrap();

            result.push(IpInet::new(address, prefix).unwrap());
        }
        Ok(result)
    }

    pub(crate) fn set_flags_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        flags: InterfaceFlags,
    ) -> Result<InterfaceFlags, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let mut req = build_ifreq(name);
        req.ifr_ifru.ifru_flags = flags.bits() as _;

        let socket = dummy_socket()?;

        unsafe {
            if ioctl(socket.as_raw_fd(), op.try_into().unwrap(), &req) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(InterfaceFlags::from_bits_truncate(
                req.ifr_ifru.ifru_flags as _,
            ))
        }
    }

    pub(crate) fn set_flags(name: &str, flags: InterfaceFlags) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCSIFFLAGS, flags)
    }

    pub(crate) fn get_flags(name: &str) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCGIFFLAGS, InterfaceFlags::empty())
    }

    fn list_route_messages(address_family: AddressFamily) -> Result<Vec<RouteMessage>, Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_UNSPEC;
        message.header.protocol = RouteProtocol::Unspec;

        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;

        message.header.address_family = address_family;
        message.header.destination_prefix_length = 0;
        message.header.source_prefix_length = 0;

        let s = send_netlink_req(
            RouteNetlinkMessage::GetRoute(message),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;

        let mut ret_vec = vec![];

        let mut resp = Vec::<u8>::new();
        loop {
            if resp.is_empty() {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }
            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink message")?;
            resp = resp.split_off(ret.buffer_len());

            tracing::debug!("net link response <<< {:?}", ret);

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    tracing::debug!("net link response <<< {:?}", m);
                    ret_vec.push(m);
                }
                NetlinkPayload::Done(_) => {
                    break;
                }
                p => {
                    tracing::error!("Unexpected netlink response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink response").into());
                }
            }
        }

        Ok(ret_vec)
    }

    fn list_routes() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(AddressFamily::Inet)
    }

    pub(crate) fn list_ipv6_route_messages() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(AddressFamily::Inet6)
    }

    fn ipv6_ndp_proxy_message(name: &str, address: Ipv6Addr) -> Result<NeighbourMessage, Error> {
        let mut message = NeighbourMessage::default();
        message.header = NeighbourHeader {
            family: AddressFamily::Inet6,
            ifindex: Self::get_interface_index(name)?,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Proxy,
            kind: RouteType::Unicast,
        };
        message
            .attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                address,
            )));
        Ok(message)
    }

    pub(crate) fn add_ipv6_ndp_proxy(name: &str, address: Ipv6Addr) -> Result<(), Error> {
        send_netlink_req_and_wait_one_resp(
            RouteNetlinkMessage::NewNeighbour(Self::ipv6_ndp_proxy_message(name, address)?),
            false,
        )
    }

    pub(crate) fn remove_ipv6_ndp_proxy(name: &str, address: Ipv6Addr) -> Result<(), Error> {
        send_netlink_req_and_wait_one_resp(
            RouteNetlinkMessage::DelNeighbour(Self::ipv6_ndp_proxy_message(name, address)?),
            true,
        )
    }

    fn list_neighbour_messages(
        address_family: AddressFamily,
    ) -> Result<Vec<NeighbourMessage>, Error> {
        let mut message = NeighbourMessage::default();
        message.header.family = address_family;
        message.header.flags = NeighbourFlags::Proxy;

        let s = send_netlink_req(
            RouteNetlinkMessage::GetNeighbour(message),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;

        let mut ret_vec = vec![];
        let mut resp = Vec::<u8>::new();
        loop {
            if resp.is_empty() {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }

            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink neighbour message")?;
            resp = resp.split_off(ret.buffer_len());

            tracing::debug!("net link response <<< {:?}", ret);

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => {
                    ret_vec.push(m);
                }
                NetlinkPayload::Done(_) => {
                    break;
                }
                p => {
                    tracing::error!("Unexpected netlink response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink response").into());
                }
            }
        }

        Ok(ret_vec)
    }

    pub(crate) fn list_ipv6_ndp_proxy(name: &str) -> Result<BTreeSet<Ipv6Addr>, Error> {
        let ifindex = Self::get_interface_index(name)?;

        Ok(Self::list_neighbour_messages(AddressFamily::Inet6)?
            .into_iter()
            .filter(|message| {
                message.header.ifindex == ifindex
                    && message.header.flags.contains(NeighbourFlags::Proxy)
            })
            .filter_map(|message| {
                message.attributes.into_iter().find_map(|attr| match attr {
                    NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => Some(addr),
                    _ => None,
                })
            })
            .collect())
    }
}

#[async_trait]
impl IfConfiguerTrait for NetlinkIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;
        message.header.address_family = AddressFamily::Inet;
        // metric
        message
            .attributes
            .push(RouteAttribute::Priority(cost.unwrap_or(65535) as u32));
        // output interface
        message
            .attributes
            .push(RouteAttribute::Oif(NetlinkIfConfiger::get_interface_index(
                name,
            )?));
        // source address
        message.header.destination_prefix_length = cidr_prefix;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(address)));

        send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::NewRoute(message), false)
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_routes()?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let other_route = RouteIdentity::from(&msg);
            if other_route.destination == std::net::IpAddr::V4(address)
                && other_route.prefix == cidr_prefix
                && other_route.ifindex == Some(ifidx)
            {
                send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::DelRoute(msg), true)?;
                return Ok(());
            }
        }

        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut message = AddressMessage::default();

        message.header.prefix_len = cidr_prefix;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(address)));

        // for IPv4 the IFA_LOCAL address can be set to the same value as
        // IFA_ADDRESS
        message
            .attributes
            .push(AddressAttribute::Local(std::net::IpAddr::V4(address)));

        // set the IFA_BROADCAST address as well
        if cidr_prefix == 32 {
            message
                .attributes
                .push(AddressAttribute::Broadcast(address));
        } else {
            let ip_addr = u32::from(address);
            let brd = Ipv4Addr::from((0xffff_ffff_u32) >> u32::from(cidr_prefix) | ip_addr);
            message.attributes.push(AddressAttribute::Broadcast(brd));
        };

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::NewAddress(message),
            false,
        )
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        let mut flags = Self::get_flags(name)?;
        flags.set(InterfaceFlags::IFF_UP, up);
        Self::set_flags(name, flags)?;
        Ok(())
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            let prefix_len = Self::get_prefix_len(name, ip.address())?;
            Self::remove_one_ip(name, ip.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.address() {
                    Self::remove_one_ip(name, ipv4, addr.network_length())?;
                }
            }
        }

        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        Self::mtu_op(name, SIOCSIFMTU, mtu as libc::c_int)?;

        Ok(())
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut message = AddressMessage::default();

        message.header.prefix_len = cidr_prefix;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet6;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V6(address)));

        // For IPv6, we don't need IFA_LOCAL or IFA_BROADCAST
        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::NewAddress(message),
            false,
        )
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ipv6) = ip {
            let prefix_len = Self::get_prefix_len_ipv6(name, ipv6.address())?;
            Self::remove_one_ipv6(name, ipv6.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V6(ipv6) = addr.address() {
                    let prefix_len = addr.network_length();
                    Self::remove_one_ipv6(name, ipv6, prefix_len)?;
                }
            }
        }

        Ok(())
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut message = RouteMessage::default();

        message.header.address_family = AddressFamily::Inet6;
        message.header.destination_prefix_length = cidr_prefix;
        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;

        message
            .attributes
            .push(RouteAttribute::Priority(cost.unwrap_or(65535) as u32));

        message
            .attributes
            .push(RouteAttribute::Oif(NetlinkIfConfiger::get_interface_index(
                name,
            )?));

        if cidr_prefix != 0 {
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(address)));
        }

        send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::NewRoute(message), false)
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_route_messages(AddressFamily::Inet6)?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let other_route = RouteIdentity::from(&msg);
            if other_route.destination == std::net::IpAddr::V6(address)
                && other_route.prefix == cidr_prefix
                && other_route.ifindex == Some(ifidx)
            {
                send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::DelRoute(msg), true)?;
                return Ok(());
            }
        }

        Ok(())
    }
}
