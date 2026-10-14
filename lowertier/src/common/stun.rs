use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::proto::common::{NatType, StunInfo};
use anyhow::Context;
use arc_swap::ArcSwap;
use chrono::Local;
use crossbeam::atomic::AtomicCell;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use quanta::Instant;
use rand::seq::IteratorRandom;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinSet;
use tracing::{Instrument, Level};

use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

use crate::common::{error::Error, underlay_policy::UnderlayPolicy};

use super::dns::resolve_txt_record;
use super::stun_codec_ext::*;

fn extract_mapped_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
    msg.attributes().find_map(|attribute| match attribute {
        Attribute::MappedAddress(addr) => Some(addr.address()),
        Attribute::XorMappedAddress(addr) => Some(addr.address()),
        _ => None,
    })
}

const DEFAULT_UDP_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
];

const DEFAULT_TCP_STUN_SERVERS: &[&str] = &[
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];

const DEFAULT_UDP_V6_STUN_SERVERS: &[&str] = &["stun.cloudflare.com:3478"];

fn strict_stun_hosts(hosts: Vec<String>) -> Vec<String> {
    hosts
        .into_iter()
        .filter(|host| host.parse::<SocketAddr>().is_ok() || host.parse::<Ipv4Addr>().is_ok())
        .collect()
}

fn select_stun_bind_addrs<'a>(
    policy: &UnderlayPolicy,
    candidates: impl IntoIterator<Item = (&'a str, IpAddr)>,
    ipv6: bool,
    port: u16,
) -> Vec<SocketAddr> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for (interface, ip) in candidates {
        if ip.is_ipv6() != ipv6
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || !policy.allows_local_endpoint(Some(interface), ip)
        {
            continue;
        }
        let addr = SocketAddr::new(ip, port);
        if seen.insert(addr) {
            selected.push(addr);
        }
    }
    selected
}

fn stun_bind_addrs(
    policy: &UnderlayPolicy,
    ipv6: bool,
    port: u16,
) -> Result<Vec<SocketAddr>, Error> {
    if !policy.is_active() {
        let ip = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let interfaces = NetworkInterface::show().map_err(|error| anyhow::anyhow!(error))?;
    let candidates = interfaces.iter().flat_map(|interface| {
        interface
            .addr
            .iter()
            .map(move |addr| (interface.name.as_str(), addr.ip()))
    });
    let addrs = select_stun_bind_addrs(policy, candidates, ipv6, port);
    if addrs.is_empty() {
        return Err(Error::NotFound);
    }
    Ok(addrs)
}

struct HostResolverIter {
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
    max_ip_per_domain: u32,
    use_ipv6: bool,
}

impl HostResolverIter {
    fn new(hostnames: Vec<String>, max_ip_per_domain: u32, use_ipv6: bool) -> Self {
        Self {
            hostnames,
            ips: vec![],
            max_ip_per_domain,
            use_ipv6,
        }
    }

    async fn get_txt_record(domain_name: &str) -> Result<Vec<String>, Error> {
        let txt_data = resolve_txt_record(domain_name).await?;
        Ok(txt_data.split(" ").map(|x| x.to_string()).collect())
    }

    #[async_recursion::async_recursion]
    async fn next(&mut self) -> Option<SocketAddr> {
        if self.ips.is_empty() {
            if self.hostnames.is_empty() {
                return None;
            }

            let host = self.hostnames.remove(0);
            let host = if host.contains(':') {
                host
            } else {
                format!("{}:3478", host)
            };

            if let Ok(addr) = host.parse::<SocketAddr>() {
                if addr.is_ipv6() == self.use_ipv6 {
                    self.ips.push(addr);
                }
                return self.next().await;
            }

            if host.starts_with("txt:") {
                let domain_name = host.trim_start_matches("txt:");
                match Self::get_txt_record(domain_name).await {
                    Ok(hosts) => {
                        tracing::info!(
                            ?domain_name,
                            ?hosts,
                            "get txt record success when resolve stun server"
                        );
                        // insert hosts to the head of hostnames
                        self.hostnames.splice(0..0, hosts.into_iter());
                    }
                    Err(e) => {
                        tracing::warn!(
                            ?domain_name,
                            ?e,
                            "get txt record failed when resolve stun server"
                        );
                    }
                }
                return self.next().await;
            }

            let use_ipv6 = self.use_ipv6;

            match lookup_host(&host).await {
                Ok(ips) => {
                    self.ips = ips
                        .filter(|x| if use_ipv6 { x.is_ipv6() } else { x.is_ipv4() })
                        .choose_multiple(&mut rand::thread_rng(), self.max_ip_per_domain as usize);

                    if self.ips.is_empty() {
                        return self.next().await;
                    }
                }
                Err(e) => {
                    tracing::warn!(?host, ?e, "lookup host for stun failed");
                    return self.next().await;
                }
            };
        }

        Some(self.ips.remove(0))
    }
}

#[derive(Debug, Clone)]
pub struct StunPacket {
    pub(crate) data: Vec<u8>,
    pub(crate) addr: SocketAddr,
}

pub type StunPacketReceiver = tokio::sync::broadcast::Receiver<StunPacket>;

#[derive(Debug, Clone, Copy)]
struct BindRequestResponse {
    local_addr: SocketAddr,
    stun_server_addr: SocketAddr,

    recv_from_addr: SocketAddr,
    mapped_socket_addr: Option<SocketAddr>,
    real_ip_changed: bool,
    real_port_changed: bool,

    latency_us: u32,
}

#[derive(Debug, Clone)]
struct StunClient {
    stun_server: SocketAddr,
    resp_timeout: Duration,
    req_repeat: u32,
    socket: Arc<UdpSocket>,
    stun_packet_receiver: Arc<Mutex<StunPacketReceiver>>,
}

impl StunClient {
    pub fn new(
        stun_server: SocketAddr,
        socket: Arc<UdpSocket>,
        stun_packet_receiver: StunPacketReceiver,
    ) -> Self {
        Self {
            stun_server,
            resp_timeout: Duration::from_millis(3000),
            req_repeat: 2,
            socket,
            stun_packet_receiver: Arc::new(Mutex::new(stun_packet_receiver)),
        }
    }

    #[tracing::instrument(skip(self, buf))]
    async fn wait_stun_response<'a, const N: usize>(
        &self,
        buf: &'a mut [u8; N],
        tids: &Vec<u32>,
        expected_ip_changed: bool,
        expected_port_changed: bool,
        stun_host: &SocketAddr,
    ) -> Result<(Message<Attribute>, SocketAddr), Error> {
        let mut now = tokio::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut locked_receiver = self.stun_packet_receiver.lock().await;
            let stun_packet_raw = tokio::time::timeout(deadline - now, locked_receiver.recv())
                .await?
                .with_context(|| "recv stun packet from broadcast channel error")?;
            now = tokio::time::Instant::now();

            let (len, remote_addr) = (stun_packet_raw.data.len(), stun_packet_raw.addr);

            if len < 20 {
                continue;
            }

            let udp_buf = stun_packet_raw.data;

            // TODO:: we cannot borrow `buf` directly in udp recv_from, so we copy it here
            unsafe { std::ptr::copy(udp_buf.as_ptr(), buf.as_ptr() as *mut u8, len) };

            let mut decoder = MessageDecoder::<Attribute>::new();
            let Ok(msg) = decoder
                .decode_from_bytes(&buf[..len])
                .with_context(|| format!("decode stun msg {:?}", buf))?
            else {
                continue;
            };

            tracing::trace!(b = ?&udp_buf[..len], ?tids, ?remote_addr, ?stun_host, "recv stun response, msg: {:#?}", msg);

            if msg.class() != MessageClass::SuccessResponse
                || msg.method() != BINDING
                || !tids.contains(&tid_to_u32(&msg.transaction_id()))
            {
                continue;
            }

            return Ok((msg, remote_addr));
        }

        Err(Error::Unknown)
    }

    fn extract_changed_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
        let mut changed_addr = None;
        for x in msg.attributes() {
            match x {
                Attribute::OtherAddress(m) if changed_addr.is_none() => {
                    let _ = changed_addr.insert(m.address());
                }
                Attribute::ChangedAddress(m) if changed_addr.is_none() => {
                    let _ = changed_addr.insert(m.address());
                }
                _ => {}
            }
        }
        changed_addr
    }

    #[tracing::instrument(ret, level = Level::TRACE)]
    pub async fn bind_request(
        self,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindRequestResponse, Error> {
        let stun_host = self.stun_server;
        // repeat req in case of packet loss
        let mut tids = vec![];
        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            // let tid = 1;
            let mut buf = [0u8; 28];
            // memset buf
            unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };

            let mut message =
                Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));

            // Encodes the message
            let mut encoder = MessageEncoder::new();
            let msg = encoder
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            tids.push(tid);
            tracing::trace!(?message, ?msg, tid, "send stun request");
            self.socket.send_to(msg.as_slice(), &stun_host).await?;
        }

        let now = Instant::now();

        tracing::trace!("waiting stun response");
        let mut buf = [0; 1620];
        let (msg, recv_addr) = self
            .wait_stun_response(&mut buf, &tids, change_ip, change_port, &stun_host)
            .await?;

        let changed_socket_addr = Self::extract_changed_addr(&msg);
        let real_ip_changed = stun_host.ip() != recv_addr.ip();
        let real_port_changed = stun_host.port() != recv_addr.port();

        let resp = BindRequestResponse {
            local_addr: self.socket.local_addr()?,
            stun_server_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: extract_mapped_addr(&msg),

            real_ip_changed,
            real_port_changed,

            latency_us: now.elapsed().as_micros() as u32,
        };

        tracing::trace!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );

        Ok(resp)
    }
}

struct StunClientBuilder {
    udp: Arc<UdpSocket>,
    task_set: JoinSet<()>,
    stun_packet_sender: broadcast::Sender<StunPacket>,
}

impl StunClientBuilder {
    pub fn new(udp: Arc<UdpSocket>) -> Self {
        let (stun_packet_sender, _) = broadcast::channel(1024);
        let mut task_set = JoinSet::new();

        let udp_clone = udp.clone();
        let stun_packet_sender_clone = stun_packet_sender.clone();
        task_set.spawn(
            async move {
                let mut buf = [0; 1620];
                tracing::trace!("start stun packet listener");
                loop {
                    let Ok((len, addr)) = udp_clone.recv_from(&mut buf).await else {
                        tracing::error!("udp recv_from error");
                        break;
                    };
                    let data = buf[..len].to_vec();
                    tracing::trace!(?addr, ?data, "recv udp stun packet");
                    let _ = stun_packet_sender_clone.send(StunPacket { data, addr });
                }
            }
            .instrument(tracing::info_span!("stun_packet_listener")),
        );

        Self {
            udp,
            task_set,
            stun_packet_sender,
        }
    }

    pub fn new_stun_client(&self, stun_server: SocketAddr) -> StunClient {
        StunClient::new(
            stun_server,
            self.udp.clone(),
            self.stun_packet_sender.subscribe(),
        )
    }

    pub async fn stop(&mut self) {
        self.task_set.abort_all();
        while self.task_set.join_next().await.is_some() {}
    }
}

#[derive(Debug, Clone)]
pub enum StunTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct StunNatTypeDetectResult {
    transport: StunTransport,
    source_addr: SocketAddr,
    stun_resps: Vec<BindRequestResponse>,
    // if we are easy symmetric nat, we need to test with another port to check inc or dec
    extra_bind_test: Option<BindRequestResponse>,
}

impl StunNatTypeDetectResult {
    fn new(
        transport: StunTransport,
        source_addr: SocketAddr,
        stun_resps: Vec<BindRequestResponse>,
    ) -> Self {
        Self {
            transport,
            source_addr,
            stun_resps,
            extra_bind_test: None,
        }
    }

    fn has_ip_changed_resp(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.real_ip_changed {
                return true;
            }
        }
        false
    }

    fn has_port_changed_resp(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.real_port_changed {
                return true;
            }
        }
        false
    }

    fn is_open_internet(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.mapped_socket_addr == Some(self.source_addr) {
                return true;
            }
        }
        false
    }

    fn is_no_pat(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.mapped_socket_addr.map(|x| x.port()) == Some(self.source_addr.port()) {
                return true;
            }
        }
        false
    }

    fn stun_server_count(&self) -> usize {
        // find resp with distinct stun server
        self.stun_resps
            .iter()
            .map(|x| x.recv_from_addr)
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn is_cone(&self) -> bool {
        // if unique mapped addr count is less than stun server count, it is cone
        let mapped_addr_count = self
            .stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr)
            .collect::<BTreeSet<_>>()
            .len();
        mapped_addr_count == 1
    }

    fn nat_type_udp(&self) -> NatType {
        if self.stun_server_count() < 2 {
            return NatType::Unknown;
        }

        if self.is_cone() {
            if self.has_ip_changed_resp() {
                if self.is_open_internet() {
                    NatType::OpenInternet
                } else if self.is_no_pat() {
                    NatType::NoPat
                } else {
                    NatType::FullCone
                }
            } else if self.has_port_changed_resp() {
                NatType::Restricted
            } else {
                NatType::PortRestricted
            }
        } else if !self.stun_resps.is_empty() {
            if self.public_ips().len() != 1
                || self.usable_stun_resp_count() <= 1
                || self.max_port() - self.min_port() > 15
            {
                NatType::Symmetric
            } else if let Some(extra_bind_mapped) = self
                .extra_bind_test
                .as_ref()
                .and_then(|extra| extra.mapped_socket_addr)
            {
                let extra_port = extra_bind_mapped.port();

                let max_port_diff = extra_port.saturating_sub(self.max_port());
                let min_port_diff = self.min_port().saturating_sub(extra_port);
                if max_port_diff != 0 && max_port_diff < 100 {
                    NatType::SymmetricEasyInc
                } else if min_port_diff != 0 && min_port_diff < 100 {
                    NatType::SymmetricEasyDec
                } else {
                    NatType::Symmetric
                }
            } else {
                NatType::Symmetric
            }
        } else {
            NatType::Unknown
        }
    }

    fn nat_type_tcp(&self) -> NatType {
        if self.is_open_internet() {
            return NatType::OpenInternet;
        }

        if self.stun_server_count() < 2 || self.stun_resps.is_empty() {
            return NatType::Unknown;
        }

        if self.is_cone() {
            if self.is_no_pat() {
                NatType::NoPat
            } else {
                NatType::FullCone
            }
        } else {
            NatType::Symmetric
        }
    }

    pub fn nat_type(&self) -> NatType {
        match self.transport {
            StunTransport::Udp => self.nat_type_udp(),
            StunTransport::Tcp => self.nat_type_tcp(),
        }
    }

    pub fn public_ips(&self) -> Vec<IpAddr> {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.ip()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn collect_available_stun_server(&self) -> Vec<SocketAddr> {
        let mut ret = vec![];
        for resp in self.stun_resps.iter() {
            if !ret.contains(&resp.stun_server_addr) {
                ret.push(resp.stun_server_addr);
            }
        }
        ret
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.source_addr
    }

    pub fn extend_result(&mut self, other: StunNatTypeDetectResult) {
        self.stun_resps.extend(other.stun_resps);
    }

    pub fn min_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.port()))
            .min()
            .unwrap_or(0)
    }

    pub fn max_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.port()))
            .max()
            .unwrap_or(u16::MAX)
    }

    pub fn usable_stun_resp_count(&self) -> usize {
        self.stun_resps
            .iter()
            .filter(|x| x.mapped_socket_addr.is_some())
            .count()
    }
}

pub struct UdpNatTypeDetector {
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
    underlay_policy: Arc<UnderlayPolicy>,
}

impl UdpNatTypeDetector {
    pub fn new(stun_server_hosts: Vec<String>, max_ip_per_domain: u32) -> Self {
        Self {
            stun_server_hosts,
            max_ip_per_domain,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }

    fn with_underlay_policy(mut self, underlay_policy: Arc<UnderlayPolicy>) -> Self {
        self.underlay_policy = underlay_policy;
        self
    }

    async fn get_extra_bind_result(
        &self,
        source_addr: SocketAddr,
        stun_server: SocketAddr,
    ) -> Result<BindRequestResponse, Error> {
        if !self.underlay_policy.allows_remote(stun_server.ip()) {
            return Err(Error::NotFound);
        }
        let udp = Arc::new(UdpSocket::bind(source_addr).await?);
        let client_builder = StunClientBuilder::new(udp.clone());
        client_builder
            .new_stun_client(stun_server)
            .bind_request(false, false)
            .await
    }

    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> Result<StunNatTypeDetectResult, Error> {
        let udp = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", source_port)).await?);
        self.detect_nat_type_with_socket(udp).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn detect_nat_type_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<StunNatTypeDetectResult, Error> {
        let mut stun_servers = vec![];
        let hosts = if self.underlay_policy.is_active() {
            strict_stun_hosts(self.stun_server_hosts.clone())
        } else {
            self.stun_server_hosts.clone()
        };
        let mut host_resolver = HostResolverIter::new(hosts, self.max_ip_per_domain, false);
        while let Some(addr) = host_resolver.next().await {
            if self.underlay_policy.allows_remote(addr.ip()) {
                stun_servers.push(addr);
            }
        }

        let client_builder = StunClientBuilder::new(udp.clone());
        let mut stun_task_set = JoinSet::new();

        for stun_server in stun_servers.iter() {
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(false, false),
            );
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(false, true),
            );
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(true, true),
            );
        }

        let mut bind_resps = vec![];
        while let Some(resp) = stun_task_set.join_next().await {
            if let Ok(Ok(resp)) = resp {
                bind_resps.push(resp);
            }
        }

        Ok(StunNatTypeDetectResult::new(
            StunTransport::Udp,
            udp.local_addr()?,
            bind_resps,
        ))
    }
}

#[derive(Debug, Clone)]
struct TcpStunClient {
    stun_server: SocketAddr,
    conn_timeout: Duration,
    io_timeout: Duration,
    source_port: u16,
    source_ip: Option<IpAddr>,
    socket_mark: Option<u32>,
    net_ns: Option<super::netns::NetNS>,
}

impl TcpStunClient {
    pub fn new(stun_server: SocketAddr, source_port: u16) -> Self {
        Self {
            stun_server,
            conn_timeout: Duration::from_millis(1500),
            io_timeout: Duration::from_millis(3000),
            source_port,
            source_ip: None,
            socket_mark: None,
            net_ns: None,
        }
    }

    fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_ip = Some(source_ip);
        self
    }

    fn with_socket_mark(mut self, mark: Option<u32>) -> Self {
        self.socket_mark = mark;
        self
    }

    fn with_net_ns(mut self, net_ns: super::netns::NetNS) -> Self {
        self.net_ns = Some(net_ns);
        self
    }

    fn message_size_from_header(header: &[u8; 20]) -> Result<usize, Error> {
        if (header[0] & 0b1100_0000) != 0 {
            return Err(Error::MessageDecodeError(
                "invalid stun message type".to_string(),
            ));
        }
        let msg_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if !msg_len.is_multiple_of(4) {
            return Err(Error::MessageDecodeError(
                "invalid stun message length".to_string(),
            ));
        }
        let total = 20usize
            .checked_add(msg_len)
            .ok_or_else(|| Error::MessageDecodeError("invalid stun message size".to_string()))?;
        if total > 4096 {
            return Err(Error::MessageDecodeError(
                "stun message too large".to_string(),
            ));
        }
        Ok(total)
    }

    async fn tcp_read_stun_message(
        stream: &mut tokio::net::TcpStream,
        timeout: Duration,
    ) -> Result<Message<Attribute>, Error> {
        let mut header = [0u8; 20];
        tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;
        let total_size = Self::message_size_from_header(&header)?;
        let mut buf = vec![0u8; total_size];
        buf[..20].copy_from_slice(&header);
        if total_size > 20 {
            tokio::time::timeout(timeout, stream.read_exact(&mut buf[20..])).await??;
        }

        let mut decoder = MessageDecoder::<Attribute>::new();
        let Ok(msg) = decoder
            .decode_from_bytes(&buf)
            .with_context(|| "decode tcp stun message")?
        else {
            return Err(Error::MessageDecodeError(
                "invalid stun message".to_string(),
            ));
        };
        Ok(msg)
    }

    async fn connect(&self) -> Result<tokio::net::TcpStream, Error> {
        let bind_addr = SocketAddr::new(
            self.source_ip.unwrap_or(match self.stun_server {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            }),
            self.source_port,
        );

        let socket = crate::tunnel::common::bind::<tokio::net::TcpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .reuse_port(true)
            .maybe_net_ns(self.net_ns.clone())
            .maybe_socket_mark(self.socket_mark)
            .call()?;
        let stream =
            tokio::time::timeout(self.conn_timeout, socket.connect(self.stun_server)).await??;

        let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));

        Ok(stream)
    }

    #[tracing::instrument(ret, level = Level::TRACE)]
    pub async fn bind_request(self) -> Result<BindRequestResponse, Error> {
        self.bind_request_retained()
            .await
            .map(|(response, _stream)| response)
    }

    async fn bind_request_retained(
        self,
    ) -> Result<(BindRequestResponse, tokio::net::TcpStream), Error> {
        let mut stream = self.connect().await?;
        let response = self.bind_request_on_stream(&mut stream).await?;
        Ok((response, stream))
    }

    async fn bind_request_on_stream(
        &self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<BindRequestResponse, Error> {
        let local_addr = stream.local_addr()?;
        let stun_host = self.stun_server;

        let tid = rand::random::<u32>();
        let message = Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
        let mut encoder = MessageEncoder::new();
        let msg = encoder
            .encode_into_bytes(message.clone())
            .with_context(|| "encode tcp stun message")?;
        tokio::time::timeout(self.io_timeout, stream.write_all(msg.as_slice())).await??;

        let now = Instant::now();
        let msg = Self::tcp_read_stun_message(stream, self.io_timeout).await?;
        if msg.class() != MessageClass::SuccessResponse
            || msg.method() != BINDING
            || tid_to_u32(&msg.transaction_id()) != tid
        {
            return Err(Error::MessageDecodeError(
                "unexpected stun response".to_string(),
            ));
        }

        Ok(BindRequestResponse {
            local_addr,
            stun_server_addr: stun_host,
            recv_from_addr: stun_host,
            mapped_socket_addr: extract_mapped_addr(&msg),
            real_ip_changed: false,
            real_port_changed: false,
            latency_us: now.elapsed().as_micros() as u32,
        })
    }
}

pub struct TcpNatTypeDetector {
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
    underlay_policy: Arc<UnderlayPolicy>,
}

impl TcpNatTypeDetector {
    pub fn new(stun_server_hosts: Vec<String>, max_ip_per_domain: u32) -> Self {
        Self {
            stun_server_hosts,
            max_ip_per_domain,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }

    fn with_underlay_policy(mut self, underlay_policy: Arc<UnderlayPolicy>) -> Self {
        self.underlay_policy = underlay_policy;
        self
    }

    #[tracing::instrument(skip(self))]
    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> Result<StunNatTypeDetectResult, Error> {
        self.detect_nat_type_with_bind_addrs(
            source_port,
            &[SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source_port,
            )],
        )
        .await
    }

    async fn detect_nat_type_with_bind_addrs(
        &self,
        source_port: u16,
        bind_addrs: &[SocketAddr],
    ) -> Result<StunNatTypeDetectResult, Error> {
        let mut stun_servers = vec![];
        let hosts = if self.underlay_policy.is_active() {
            strict_stun_hosts(self.stun_server_hosts.clone())
        } else {
            self.stun_server_hosts.clone()
        };
        let mut host_resolver = HostResolverIter::new(hosts, self.max_ip_per_domain, false);
        while let Some(addr) = host_resolver.next().await {
            if self.underlay_policy.allows_remote(addr.ip()) {
                stun_servers.push(addr);
            }
        }

        for bind_addr in bind_addrs {
            let mut bind_resps = vec![];
            let mut source_addr = None;
            let mut selected_source_port = if source_port == 0 {
                None
            } else {
                Some(source_port)
            };
            for server in stun_servers.iter() {
                let resp = TcpStunClient::new(*server, selected_source_port.unwrap_or(0))
                    .with_source_ip(bind_addr.ip())
                    .bind_request()
                    .await;
                if let Ok(resp) = resp {
                    if selected_source_port.is_none() {
                        selected_source_port = Some(resp.local_addr.port());
                    }
                    source_addr.get_or_insert(resp.local_addr);
                    bind_resps.push(resp);
                    if bind_resps.len() >= 3 {
                        break;
                    }
                }
            }
            if let Some(source_addr) = source_addr {
                return Ok(StunNatTypeDetectResult::new(
                    StunTransport::Tcp,
                    source_addr,
                    bind_resps,
                ));
            }
        }
        Err(Error::NotFound)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait StunInfoCollectorTrait: Send + Sync {
    fn get_stun_info(&self) -> StunInfo;
    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error>;
    async fn get_udp_port_mapping_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<SocketAddr, Error>;
    async fn get_udp_port_mappings_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<Vec<SocketAddr>, Error> {
        self.get_udp_port_mapping_with_socket(udp)
            .await
            .map(|mapping| vec![mapping])
    }
    async fn get_udp_port_mappings_with_socket_receiver(
        &self,
        udp: Arc<UdpSocket>,
        _receiver: StunPacketReceiver,
    ) -> Result<Vec<SocketAddr>, Error> {
        self.get_udp_port_mappings_with_socket(udp).await
    }
    async fn get_tcp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error>;
    async fn get_first_udp_mapping_with_receiver(
        &self,
        udp: Arc<UdpSocket>,
        receiver: StunPacketReceiver,
    ) -> Result<SocketAddr, Error> {
        self.get_udp_port_mappings_with_socket_receiver(udp, receiver)
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NotFound)
    }
    async fn get_tcp_port_mappings_bound(
        &self,
        local: SocketAddr,
        _socket_mark: Option<u32>,
        _net_ns: super::netns::NetNS,
    ) -> Result<TcpPortMappings, Error> {
        Ok(TcpPortMappings {
            addresses: vec![self.get_tcp_port_mapping(local.port()).await?],
            connections: vec![],
        })
    }
}

pub struct TcpPortMappings {
    pub addresses: Vec<SocketAddr>,
    // Keep the STUN connections alive until the peer establishes its TCP path.
    pub connections: Vec<tokio::net::TcpStream>,
}

impl TcpPortMappings {
    pub(crate) async fn refresh(&mut self) -> Result<(), Error> {
        // Reuse each established tuple. A second connection cannot own that tuple.
        let requests = self.connections.drain(..).map(|mut stream| async move {
            let server = stream.peer_addr()?;
            let client = TcpStunClient::new(server, stream.local_addr()?.port());
            let response = client.bind_request_on_stream(&mut stream).await?;
            let mapped = response.mapped_socket_addr.ok_or(Error::NotFound)?;
            Ok::<_, Error>((mapped, stream))
        });
        let replies = futures::future::join_all(requests).await;
        self.addresses.clear();
        for (mapped, stream) in replies.into_iter().flatten() {
            if !self.addresses.contains(&mapped) {
                self.addresses.push(mapped);
            }
            self.connections.push(stream);
        }
        if self.addresses.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}

pub struct StunInfoCollector {
    stun_servers: Arc<RwLock<Vec<String>>>,
    tcp_stun_servers: Arc<RwLock<Vec<String>>>,
    stun_servers_v6: Arc<RwLock<Vec<String>>>,
    udp_nat_test_result: Arc<RwLock<Option<StunNatTypeDetectResult>>>,
    tcp_nat_test_result: Arc<RwLock<Option<StunNatTypeDetectResult>>>,
    public_ipv6: Arc<AtomicCell<Option<Ipv6Addr>>>,
    nat_test_result_time: Arc<AtomicCell<chrono::DateTime<Local>>>,
    redetect_notify: Arc<tokio::sync::Notify>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    started: AtomicBool,
    nat_protocols: (bool, bool), // UDP, TCP; immutable after sharing.
    underlay_policy: Arc<ArcSwap<UnderlayPolicy>>,
}

impl StunInfoCollector {
    async fn gather_udp_port_mappings(
        &self,
        udp: Arc<UdpSocket>,
        receiver: Option<StunPacketReceiver>,
        first_only: bool,
    ) -> Result<Vec<SocketAddr>, Error> {
        let local_addr = udp.local_addr()?;
        let policy = self.underlay_policy.load_full();
        if policy.is_active() {
            if local_addr.ip().is_unspecified() {
                return Err(Error::TunnelError(
                    crate::tunnel::TunnelError::UnderlayPolicyDenied(format!(
                        "STUN socket local address {local_addr} is not concrete"
                    )),
                ));
            }
            crate::tunnel::common::ensure_local_allowed(&policy, local_addr)?;
        }

        let mut stun_servers = self
            .udp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|x| x.collect_available_stun_server())
            .unwrap_or_default();

        if stun_servers.is_empty() {
            let hosts = if policy.is_active() {
                strict_stun_hosts(self.stun_servers.read().unwrap().clone())
            } else {
                self.stun_servers.read().unwrap().clone()
            };
            let mut host_resolver = HostResolverIter::new(hosts, 1, false);
            while let Some(addr) = host_resolver.next().await {
                if self.underlay_policy.load().allows_remote(addr.ip()) {
                    stun_servers.push(addr);
                }
                if stun_servers.len() >= 3 {
                    break;
                }
            }
        }

        if stun_servers.is_empty() {
            return Err(Error::NotFound);
        }

        let mut owned_builder = receiver
            .is_none()
            .then(|| StunClientBuilder::new(udp.clone()));
        let mut requests = JoinSet::new();
        for (index, server) in stun_servers.into_iter().take(3).enumerate() {
            if !policy.allows_remote(server.ip()) {
                continue;
            }
            let client = if let Some(receiver) = receiver.as_ref() {
                StunClient::new(server, udp.clone(), receiver.resubscribe())
            } else {
                owned_builder
                    .as_ref()
                    .expect("owned STUN receiver exists")
                    .new_stun_client(server)
            };
            requests.spawn(async move { (index, server, client.bind_request(false, false).await) });
        }

        let mut observations = Vec::new();
        while let Some(result) = requests.join_next().await {
            let Ok((index, server, result)) = result else {
                continue;
            };
            match result {
                Ok(response) => {
                    if let Some(mapped_addr) = response.mapped_socket_addr {
                        tracing::info!(
                            ?server,
                            ?mapped_addr,
                            latency_us = response.latency_us,
                            "STUN candidate observed"
                        );
                        observations.push((index, mapped_addr));
                        if first_only {
                            break;
                        }
                    }
                }
                Err(error) => tracing::warn!(?server, ?error, "stun bind request failed"),
            }
        }

        if let Some(builder) = owned_builder.as_mut() {
            builder.stop().await;
        }
        observations.sort_unstable_by_key(|(index, _)| *index);
        let mut seen = BTreeSet::new();
        let mappings = observations
            .into_iter()
            .map(|(_, mapping)| mapping)
            .filter(|mapping| seen.insert(*mapping))
            .collect::<Vec<_>>();
        if mappings.is_empty() {
            Err(Error::NotFound)
        } else {
            Ok(mappings)
        }
    }
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for StunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        self.start_stun_routine();

        let udp_result = self.udp_nat_test_result.read().unwrap().clone();
        let tcp_result = self.tcp_nat_test_result.read().unwrap().clone();
        if udp_result.is_none() && tcp_result.is_none() {
            return Default::default();
        }

        let mut public_ip = BTreeSet::<String>::new();
        if let Some(result) = &udp_result {
            public_ip.extend(result.public_ips().into_iter().map(|x| x.to_string()));
        }
        if let Some(result) = &tcp_result {
            public_ip.extend(result.public_ips().into_iter().map(|x| x.to_string()));
        }
        if let Some(v6) = self.public_ipv6.load() {
            public_ip.insert(v6.to_string());
        }

        StunInfo {
            udp_nat_type: udp_result
                .as_ref()
                .map(|x| x.nat_type() as i32)
                .unwrap_or(NatType::Unknown as i32),
            tcp_nat_type: tcp_result
                .as_ref()
                .map(|x| x.nat_type() as i32)
                .unwrap_or(NatType::Unknown as i32),
            last_update_time: self.nat_test_result_time.load().timestamp(),
            public_ip: public_ip.into_iter().collect(),
            min_port: udp_result
                .as_ref()
                .map(|x| x.min_port() as u32)
                .or_else(|| tcp_result.as_ref().map(|x| x.min_port() as u32))
                .unwrap_or(0),
            max_port: udp_result
                .as_ref()
                .map(|x| x.max_port() as u32)
                .or_else(|| tcp_result.as_ref().map(|x| x.max_port() as u32))
                .unwrap_or(0),
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        let policy = self.underlay_policy.load_full();
        for bind_addr in stun_bind_addrs(&policy, false, local_port)? {
            let Ok(udp) = UdpSocket::bind(bind_addr).await else {
                continue;
            };
            if let Ok(mapped) = self.get_udp_port_mapping_with_socket(Arc::new(udp)).await {
                return Ok(mapped);
            }
        }
        Err(Error::NotFound)
    }

    async fn get_udp_port_mapping_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<SocketAddr, Error> {
        self.get_udp_port_mappings_with_socket(udp)
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NotFound)
    }

    async fn get_udp_port_mappings_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<Vec<SocketAddr>, Error> {
        self.gather_udp_port_mappings(udp, None, false).await
    }

    async fn get_udp_port_mappings_with_socket_receiver(
        &self,
        udp: Arc<UdpSocket>,
        receiver: StunPacketReceiver,
    ) -> Result<Vec<SocketAddr>, Error> {
        self.gather_udp_port_mappings(udp, Some(receiver), false)
            .await
    }

    async fn get_first_udp_mapping_with_receiver(
        &self,
        udp: Arc<UdpSocket>,
        receiver: StunPacketReceiver,
    ) -> Result<SocketAddr, Error> {
        self.gather_udp_port_mappings(udp, Some(receiver), true)
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NotFound)
    }

    async fn get_tcp_port_mappings_bound(
        &self,
        local: SocketAddr,
        socket_mark: Option<u32>,
        net_ns: super::netns::NetNS,
    ) -> Result<TcpPortMappings, Error> {
        let policy = self.underlay_policy.load_full();
        {
            let _guard = net_ns.guard();
            crate::tunnel::common::ensure_local_allowed(&policy, local)?;
        }
        let hosts = self.tcp_stun_servers.read().unwrap().clone();
        let hosts = if policy.is_active() {
            strict_stun_hosts(hosts)
        } else {
            hosts
        };
        let mut resolver = HostResolverIter::new(hosts, 1, false);
        let mut requests = JoinSet::new();
        while let Some(server) = resolver.next().await {
            if !server.is_ipv4() || !policy.allows_remote(server.ip()) {
                continue;
            }
            requests.spawn(
                TcpStunClient::new(server, local.port())
                    .with_source_ip(local.ip())
                    .with_socket_mark(socket_mark)
                    .with_net_ns(net_ns.clone())
                    .bind_request_retained(),
            );
            if requests.len() == 2 {
                break;
            }
        }
        let mut result = TcpPortMappings {
            addresses: vec![],
            connections: vec![],
        };
        while let Some(response) = requests.join_next().await {
            let Ok(Ok((response, stream))) = response else {
                continue;
            };
            if let Some(mapped) = response
                .mapped_socket_addr
                .filter(|address| policy.allows_ip(address.ip()))
            {
                if !result.addresses.contains(&mapped) {
                    result.addresses.push(mapped);
                }
                result.connections.push(stream);
            }
        }
        if result.addresses.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(result)
    }

    async fn get_tcp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        self.start_stun_routine();

        let mut stun_servers = self
            .tcp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|x| x.collect_available_stun_server())
            .unwrap_or_default();

        if stun_servers.is_empty() {
            let policy = self.underlay_policy.load_full();
            let hosts = if policy.is_active() {
                strict_stun_hosts(self.tcp_stun_servers.read().unwrap().clone())
            } else {
                self.tcp_stun_servers.read().unwrap().clone()
            };
            let mut host_resolver = HostResolverIter::new(hosts, 2, false);
            while let Some(addr) = host_resolver.next().await {
                stun_servers.push(addr);
                if stun_servers.len() >= 2 {
                    break;
                }
            }
        }

        if stun_servers.is_empty() {
            return Err(Error::NotFound);
        }

        for server in stun_servers.iter() {
            let policy = self.underlay_policy.load_full();
            if !policy.allows_remote(server.ip()) {
                continue;
            }
            for bind_addr in stun_bind_addrs(&policy, false, local_port)? {
                let Ok(ret) = TcpStunClient::new(*server, local_port)
                    .with_source_ip(bind_addr.ip())
                    .bind_request()
                    .await
                else {
                    tracing::warn!(?server, ?bind_addr, "tcp stun bind request failed");
                    continue;
                };

                if let Some(mapped_addr) = ret.mapped_socket_addr {
                    return Ok(mapped_addr);
                }
            }
        }

        Err(Error::NotFound)
    }
}

impl StunInfoCollector {
    pub fn new(
        udp_stun_servers: Vec<String>,
        tcp_stun_servers: Vec<String>,
        stun_servers_v6: Vec<String>,
    ) -> Self {
        Self {
            stun_servers: Arc::new(RwLock::new(udp_stun_servers)),
            tcp_stun_servers: Arc::new(RwLock::new(tcp_stun_servers)),
            stun_servers_v6: Arc::new(RwLock::new(stun_servers_v6)),
            udp_nat_test_result: Arc::new(RwLock::new(None)),
            tcp_nat_test_result: Arc::new(RwLock::new(None)),
            public_ipv6: Arc::new(AtomicCell::new(None)),
            nat_test_result_time: Arc::new(AtomicCell::new(Local::now())),
            redetect_notify: Arc::new(tokio::sync::Notify::new()),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            started: AtomicBool::new(false),
            nat_protocols: (true, true),
            underlay_policy: Arc::new(ArcSwap::from_pointee(UnderlayPolicy::default())),
        }
    }

    pub fn set_nat_protocols(&mut self, udp: bool, tcp: bool) {
        self.nat_protocols = (udp, tcp);
    }

    pub fn set_underlay_policy_source(&mut self, underlay_policy: Arc<ArcSwap<UnderlayPolicy>>) {
        self.underlay_policy = underlay_policy;
    }

    pub fn new_with_default_servers() -> Self {
        Self::new(
            Self::get_default_servers(),
            Self::get_default_tcp_servers(),
            Self::get_default_servers_v6(),
        )
    }

    pub fn set_stun_servers(&self, stun_servers: Vec<String>) {
        let mut g = self.stun_servers.write().unwrap();
        *g = stun_servers;
    }

    pub fn set_stun_servers_v6(&self, stun_servers_v6: Vec<String>) {
        let mut g = self.stun_servers_v6.write().unwrap();
        *g = stun_servers_v6;
    }

    pub fn set_tcp_stun_servers(&self, stun_servers: Vec<String>) {
        let mut g = self.tcp_stun_servers.write().unwrap();
        *g = stun_servers;
    }

    pub fn get_default_servers() -> Vec<String> {
        if cfg!(test) {
            Vec::new()
        } else {
            // NOTICE: we may need to choose stun server based on geolocation
            // stun server cross nation may return an external ip address with high latency and loss rate
            DEFAULT_UDP_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect()
        }
    }

    pub fn get_default_tcp_servers() -> Vec<String> {
        // if test, return empty vector
        if cfg!(test) {
            Vec::new()
        } else {
            DEFAULT_TCP_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect()
        }
    }

    pub fn get_default_servers_v6() -> Vec<String> {
        if cfg!(test) {
            Vec::new()
        } else {
            DEFAULT_UDP_V6_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect()
        }
    }

    async fn get_public_ipv6(
        servers: &[String],
        underlay_policy: Arc<UnderlayPolicy>,
    ) -> Option<Ipv6Addr> {
        let hosts = if underlay_policy.is_active() {
            strict_stun_hosts(servers.to_vec())
        } else {
            servers.to_vec()
        };
        let mut ips = HostResolverIter::new(hosts, 10, true);
        while let Some(ip) = ips.next().await {
            if !underlay_policy.allows_remote(ip.ip()) {
                continue;
            }
            let Ok(bind_addrs) = stun_bind_addrs(&underlay_policy, true, 0) else {
                return None;
            };
            for bind_addr in bind_addrs {
                let Ok(udp_socket) = UdpSocket::bind(bind_addr).await else {
                    continue;
                };
                let udp = Arc::new(udp_socket);
                let ret = StunClientBuilder::new(udp.clone())
                    .new_stun_client(ip)
                    .bind_request(false, false)
                    .await;
                tracing::debug!(?ret, ?bind_addr, "finish ipv6 udp nat type detect");
                if let Ok(Some(IpAddr::V6(v6))) = ret.map(|x| x.mapped_socket_addr.map(|x| x.ip()))
                {
                    return Some(v6);
                }
            }
        }
        None
    }

    fn start_stun_routine(&self) {
        if self.started.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        if self.nat_protocols.0 {
            let stun_servers = self.stun_servers.clone();
            let udp_nat_test_result = self.udp_nat_test_result.clone();
            let nat_test_time = self.nat_test_result_time.clone();
            let redetect_notify = self.redetect_notify.clone();
            let underlay_policy = self.underlay_policy.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    let udp_servers = stun_servers.read().unwrap().clone();
                    let udp_servers: Vec<String> = udp_servers
                        .iter()
                        .take(2)
                        .chain(udp_servers.iter().skip(2).choose(&mut rand::thread_rng()))
                        .map(|x| x.to_string())
                        .collect();

                    let policy = underlay_policy.load_full();
                    let udp_detector = UdpNatTypeDetector::new(udp_servers, 1)
                        .with_underlay_policy(policy.clone());
                    let mut udp_ret = Err(Error::NotFound);
                    if let Ok(bind_addrs) = stun_bind_addrs(&policy, false, 0) {
                        for bind_addr in bind_addrs {
                            let Ok(socket) = UdpSocket::bind(bind_addr).await else {
                                continue;
                            };
                            udp_ret = udp_detector
                                .detect_nat_type_with_socket(Arc::new(socket))
                                .await;
                            if udp_ret.is_ok() {
                                break;
                            }
                        }
                    }
                    tracing::debug!(?udp_ret, "finish udp nat type detect");

                    let mut nat_type = NatType::Unknown;
                    if let Ok(resp) = &udp_ret {
                        tracing::debug!(?resp, "got udp nat type detect result");
                        nat_type = resp.nat_type();
                    }

                    // if nat type is symmtric, detect with another port to gather more info
                    if nat_type == NatType::Symmetric {
                        let old_resp = udp_ret.as_mut().unwrap();
                        tracing::debug!(?old_resp, "start get extra bind result");
                        let available_stun_servers = old_resp.collect_available_stun_server();
                        for server in available_stun_servers.iter() {
                            let ret = udp_detector
                                .get_extra_bind_result(
                                    SocketAddr::new(old_resp.local_addr().ip(), 0),
                                    *server,
                                )
                                .await
                                .with_context(|| "get extra bind result failed");
                            tracing::debug!(?ret, "finish udp nat type detect with another port");
                            if let Ok(resp) = ret {
                                old_resp.extra_bind_test = Some(resp);
                                break;
                            }
                        }
                    }

                    let mut sleep_sec = 10;
                    if let Ok(resp) = &udp_ret {
                        nat_test_time.store(Local::now());
                        *udp_nat_test_result.write().unwrap() = Some(resp.clone());
                        if nat_type != NatType::Unknown
                            && (nat_type != NatType::Symmetric || resp.extra_bind_test.is_some())
                        {
                            sleep_sec = 600
                        }
                    }

                    tokio::select! {
                        _ = redetect_notify.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                    }
                }
            });
        }
        if self.nat_protocols.1 {
            let tcp_stun_servers = self.tcp_stun_servers.clone();
            let tcp_nat_test_result = self.tcp_nat_test_result.clone();
            let nat_test_time = self.nat_test_result_time.clone();
            let redetect_notify = self.redetect_notify.clone();
            let underlay_policy = self.underlay_policy.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    let tcp_servers = tcp_stun_servers.read().unwrap().clone();
                    let tcp_servers: Vec<String> = tcp_servers
                        .iter()
                        .take(2)
                        .chain(tcp_servers.iter().skip(2).choose(&mut rand::thread_rng()))
                        .map(|x| x.to_string())
                        .collect();

                    let policy = underlay_policy.load_full();
                    let tcp_detector = TcpNatTypeDetector::new(tcp_servers, 1)
                        .with_underlay_policy(policy.clone());
                    let tcp_ret = match stun_bind_addrs(&policy, false, 0) {
                        Ok(bind_addrs) => {
                            tcp_detector
                                .detect_nat_type_with_bind_addrs(0, &bind_addrs)
                                .await
                        }
                        Err(error) => Err(error),
                    };
                    tracing::debug!(?tcp_ret, "finish tcp nat type detect");

                    let mut sleep_sec = 10;
                    if let Ok(resp) = &tcp_ret {
                        nat_test_time.store(Local::now());
                        *tcp_nat_test_result.write().unwrap() = Some(resp.clone());
                        if resp.nat_type() != NatType::Unknown {
                            sleep_sec = 600;
                        }
                    }

                    tokio::select! {
                        _ = redetect_notify.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                    }
                }
            });
        }
        let stun_servers_v6 = self.stun_servers_v6.clone();
        if !stun_servers_v6.read().unwrap().is_empty() {
            let stored_ipv6 = self.public_ipv6.clone();
            let redetect_notify = self.redetect_notify.clone();
            let underlay_policy = self.underlay_policy.clone();
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    let servers = stun_servers_v6.read().unwrap().clone();
                    if servers.is_empty() {
                        break;
                    }
                    if let Some(x) =
                        Self::get_public_ipv6(&servers, underlay_policy.load_full()).await
                    {
                        stored_ipv6.store(Some(x))
                    }

                    let sleep_sec = if stored_ipv6.load().is_none() {
                        60
                    } else {
                        360
                    };

                    tokio::select! {
                        _ = redetect_notify.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                    }
                }
            });
        }
    }

    pub fn update_stun_info(&self) {
        self.redetect_notify.notify_waiters();
    }
}

pub struct MockStunInfoCollector {
    pub udp_nat_type: NatType,
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for MockStunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        StunInfo {
            udp_nat_type: self.udp_nat_type as i32,
            tcp_nat_type: NatType::Unknown as i32,
            last_update_time: Local::now().timestamp(),
            min_port: 100,
            max_port: 200,
            public_ip: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }

    async fn get_udp_port_mapping(&self, mut port: u16) -> Result<std::net::SocketAddr, Error> {
        if port == 0 {
            port = 40144;
        }
        Ok(format!("127.0.0.1:{}", port).parse().unwrap())
    }

    async fn get_udp_port_mapping_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<std::net::SocketAddr, Error> {
        self.get_udp_port_mapping(udp.local_addr()?.port()).await
    }

    async fn get_tcp_port_mapping(&self, mut port: u16) -> Result<std::net::SocketAddr, Error> {
        if port == 0 {
            port = 40144;
        }
        Ok(format!("127.0.0.1:{}", port).parse().unwrap())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn tcp_stun_retains_the_reserved_source_port() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let reservation = crate::tunnel::common::bind::<tokio::net::TcpSocket>()
                .addr("127.0.0.1:0".parse().unwrap())
                .reuse_port(true)
                .call()
                .unwrap()
                .listen(4)
                .unwrap();
            let local = reservation.local_addr().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, source) = listener.accept().await.unwrap();
                assert_eq!(source, local);
                for port in [source.port(), source.port().wrapping_add(1).max(1)] {
                    let mut request = [0; 20];
                    stream.read_exact(&mut request).await.unwrap();
                    let mut response = Vec::from([1, 1, 0, 12]);
                    response.extend_from_slice(&request[4..20]);
                    response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
                    response.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
                    response.extend_from_slice(
                        &(u32::from(Ipv4Addr::LOCALHOST) ^ 0x2112a442).to_be_bytes(),
                    );
                    stream.write_all(&response).await.unwrap();
                }
            });
            let (mapping, stream) = TcpStunClient::new(server, local.port())
                .with_source_ip(local.ip())
                .bind_request_retained()
                .await
                .unwrap();
            assert_eq!(mapping.mapped_socket_addr, Some(local));
            assert_eq!(stream.local_addr().unwrap(), local);
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            let mut mappings = TcpPortMappings {
                addresses: vec![local],
                connections: vec![stream],
            };
            mappings.refresh().await.unwrap();
            assert_eq!(
                mappings.addresses,
                vec![SocketAddr::new(
                    local.ip(),
                    local.port().wrapping_add(1).max(1)
                )]
            );
            assert_eq!(mappings.connections[0].local_addr().unwrap(), local);
            task.await.unwrap();
            assert!(mappings.refresh().await.is_err());
            assert!(mappings.addresses.is_empty());
            assert!(mappings.connections.is_empty());
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod protocol_memory_tests {
    use super::*;
    #[tokio::test]
    async fn discovery_starts_only_selected_workers_once() {
        for (udp, tcp) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut collector = StunInfoCollector::new(Vec::new(), Vec::new(), Vec::new());
            collector.set_nat_protocols(udp, tcp);
            let collector = Arc::new(collector);
            for _ in 0..8 {
                collector.get_stun_info();
            }
            assert_eq!(
                collector.tasks.lock().unwrap().len(),
                usize::from(udp) + usize::from(tcp)
            );
        }
    }
}
