use bytes::Bytes;
use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;
use zerocopy::byteorder::*;

use crate::{
    common::PeerId,
    proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
};

type DefaultEndian = LittleEndian;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

// TCP TunnelHeader
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct TCPTunnelHeader {
    pub len: U32<DefaultEndian>,
}
pub const TCP_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<TCPTunnelHeader>();

#[derive(AsBytes, FromZeroes, Clone, Debug)]
#[repr(u8)]
pub enum UdpPacketType {
    Invalid = 0,
    Syn = 1,
    Sack = 2,
    Data = 3,
    Fin = 4,
    HolePunch = 5,
    V4HolePunch = 6, // when receiving v4 hole punch packet, the packet contains a socket addr of other peer, we
    // will send a hole punch packet to that peer. we only accept this packet from loopback interface.
    V6HolePunch = 7, // when receiving v6 hole punch packet, the packet contains a socket addr of other peer, we
                     // will send a hole punch packet to that peer. we only accept this packet from lookback interface.
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct V4HolePunchPacket {
    pub dst_ipv4: [u8; 4],
    pub dst_port: U16<DefaultEndian>,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct V6HolePunchPacket {
    pub dst_ipv6: [u8; 16],
    pub dst_port: U16<DefaultEndian>,
    pub preferred_src_ipv6: [u8; 16],
    pub preferred_src_ifindex: U32<DefaultEndian>,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct UDPTunnelHeader {
    pub conn_id: U32<DefaultEndian>,
    pub msg_type: u8,
    pub padding: u8,
    pub len: U16<DefaultEndian>,
}
pub const UDP_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<UDPTunnelHeader>();

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct WGTunnelHeader {
    pub ipv4_header: [u8; 20],
}
pub const WG_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<WGTunnelHeader>();

#[derive(AsBytes, FromZeroes, Copy, Clone, Debug)]
#[repr(u8)]
pub enum PacketType {
    Invalid = 0,
    Data = 1,
    HandShake = 2,
    RoutePacket = 3, // deprecated
    Ping = 4,
    Pong = 5,
    TaRpc = 6, // deprecated
    Route = 7, // deprecated
    RpcReq = 8,
    RpcResp = 9,
    ForeignNetworkPacket = 10,
    KcpSrc = 11,
    KcpDst = 12,
    QuicSrc = 16,
    QuicDst = 17,
    NoiseHandshakeMsg1 = 13,
    NoiseHandshakeMsg2 = 14,
    NoiseHandshakeMsg3 = 15,
    RelayHandshake = 20,
    RelayHandshakeAck = 21,
    Ethernet = 22,
    AlternateFecSource = 23,
    AlternateFecParity = 24,
    SpeedProbe = 25,
    SpeedProbeAck = 26,
    RelayHandshakeConfirm = 27,
    RelayHandshakeConfirmAck = 28,
    RelayHandshakeReadyReceipt = 32,
    RelayHandshakeReadyReceiptAck = 33,
    RelayHandshakeReady = 34,
    RelayHandshakeReadyAck = 35,
    NoiseHandshakeCommit = 29,
    NoiseHandshakeCommitAck = 30,
    NoiseHandshakeCommitDone = 31,
    NoiseHandshakeReady = 36,
    NoiseHandshakeReadyAck = 37,
    NoiseHandshakeReadyReceipt = 38,
    NoiseHandshakeReadyReceiptAck = 39,
    RelayHandshakeReset = 40,
    RelayHandshakeResetAck = 41,
    ReceiverPressure = 42,

    // used internally,
    DataWithKcpSrcModified = 18,
    DataWithQuicSrcModified = 19,
}

bitflags::bitflags! {
    struct PeerManagerHeaderFlags: u8 {
        const ENCRYPTED = 0b0000_0001;
        const LATENCY_FIRST = 0b0000_0010;
        const EXIT_NODE = 0b0000_0100;
        const NO_PROXY = 0b0000_1000;
        const COMPRESSED = 0b0001_0000;
        const SPEED_FIRST = 0b0010_0000;
        const NOT_SEND_TO_TUN = 0b0100_0000;
        const HYBRID_IP_ETHERNET = 0b1000_0000;

        const _ = !0;
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct PeerManagerHeader {
    pub from_peer_id: U32<DefaultEndian>,
    pub to_peer_id: U32<DefaultEndian>,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    reserved: u8,
    pub len: U32<DefaultEndian>,
}
pub const PEER_MANAGER_HEADER_SIZE: usize = std::mem::size_of::<PeerManagerHeader>();
pub const PEER_MANAGER_STABLE_AUTH_DATA_SIZE: usize = 19;
const FLOW_SHARD_PRESENT: u8 = 0x80;
const FLOW_SHARD_MASK: u8 = 0x3f;
const CRITICAL_L2_CONTROL: u8 = 0x40;

impl PeerManagerHeader {
    fn initialize(&mut self, from_peer_id: u32, to_peer_id: u32, packet_type: u8, len: u32) {
        self.from_peer_id.set(from_peer_id);
        self.to_peer_id.set(to_peer_id);
        self.packet_type = packet_type;
        self.flags = 0;
        self.forward_counter = 1;
        self.reserved = 0;
        self.len.set(len);
    }

    pub fn flow_shard(&self) -> Option<u16> {
        (self.reserved & FLOW_SHARD_PRESENT != 0)
            .then_some(u16::from(self.reserved & FLOW_SHARD_MASK))
    }

    pub fn set_flow_shard(&mut self, shard: u16) {
        assert!(shard <= u16::from(FLOW_SHARD_MASK));
        self.reserved = (self.reserved & CRITICAL_L2_CONTROL) | FLOW_SHARD_PRESENT | shard as u8;
    }

    pub fn is_critical_l2_control(&self) -> bool {
        self.reserved & CRITICAL_L2_CONTROL != 0
    }

    pub fn set_critical_l2_control(&mut self, critical: bool) {
        if critical {
            self.reserved |= CRITICAL_L2_CONTROL;
        } else {
            self.reserved &= !CRITICAL_L2_CONTROL;
        }
    }

    pub fn is_encrypted(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::ENCRYPTED)
    }

    /// Return the canonical authenticated header fields.
    ///
    /// Relays can update encrypted state, forwarding count, latency preference,
    /// and speed preference while forwarding. The byte order is fixed.
    pub fn stable_auth_data(&self) -> [u8; PEER_MANAGER_STABLE_AUTH_DATA_SIZE] {
        let mut data = [0_u8; PEER_MANAGER_STABLE_AUTH_DATA_SIZE];
        data[..4].copy_from_slice(b"ETAD");
        data[4..8].copy_from_slice(&self.from_peer_id.get().to_be_bytes());
        data[8..12].copy_from_slice(&self.to_peer_id.get().to_be_bytes());
        data[12] = self.packet_type;
        data[13] = self.stable_auth_flags();
        data[14] = self
            .flow_shard()
            .map(|shard| 0x80 | (shard as u8 & FLOW_SHARD_MASK))
            .unwrap_or(0)
            | if self.is_critical_l2_control() {
                CRITICAL_L2_CONTROL
            } else {
                0
            };
        data[15..19].copy_from_slice(&self.len.get().to_be_bytes());
        data
    }

    pub fn set_encrypted(&mut self, encrypted: bool) {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if encrypted {
            flags.insert(PeerManagerHeaderFlags::ENCRYPTED);
        } else {
            flags.remove(PeerManagerHeaderFlags::ENCRYPTED);
        }
        self.flags = flags.bits();
    }

    pub fn is_latency_first(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::LATENCY_FIRST)
    }

    pub fn is_speed_first(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::SPEED_FIRST)
    }

    pub fn is_hybrid_ip_ethernet(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::HYBRID_IP_ETHERNET)
    }

    pub fn set_hybrid_ip_ethernet(&mut self, hybrid_ip_ethernet: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if hybrid_ip_ethernet {
            flags.insert(PeerManagerHeaderFlags::HYBRID_IP_ETHERNET);
        } else {
            flags.remove(PeerManagerHeaderFlags::HYBRID_IP_ETHERNET);
        }
        self.flags = flags.bits();
        self
    }

    /// Return the immutable peer-manager flag bits for authentication.
    ///
    /// Relays may clear latency and speed route-policy bits. Encryption also
    /// changes its flag at each session boundary. Critical L2 state belongs to
    /// the reserved byte and is encoded separately in stable authentication data.
    /// Keep every other flag bit authenticated, including currently reserved
    /// bits, so a future flag cannot become an unauthenticated control input.
    pub fn stable_auth_flags(&self) -> u8 {
        let mutable_mask = (PeerManagerHeaderFlags::ENCRYPTED
            | PeerManagerHeaderFlags::LATENCY_FIRST
            | PeerManagerHeaderFlags::SPEED_FIRST)
            .bits();
        self.flags & !mutable_mask
    }

    pub fn is_exit_node(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::EXIT_NODE)
    }

    pub fn is_no_proxy(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::NO_PROXY)
    }

    pub fn is_compressed(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::COMPRESSED)
    }

    pub fn set_latency_first(&mut self, latency_first: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if latency_first {
            flags.insert(PeerManagerHeaderFlags::LATENCY_FIRST);
        } else {
            flags.remove(PeerManagerHeaderFlags::LATENCY_FIRST);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_speed_first(&mut self, speed_first: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if speed_first {
            flags.insert(PeerManagerHeaderFlags::SPEED_FIRST);
        } else {
            flags.remove(PeerManagerHeaderFlags::SPEED_FIRST);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_exit_node(&mut self, exit_node: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if exit_node {
            flags.insert(PeerManagerHeaderFlags::EXIT_NODE);
        } else {
            flags.remove(PeerManagerHeaderFlags::EXIT_NODE);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_no_proxy(&mut self, no_proxy: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if no_proxy {
            flags.insert(PeerManagerHeaderFlags::NO_PROXY);
        } else {
            flags.remove(PeerManagerHeaderFlags::NO_PROXY);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_compressed(&mut self, compressed: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if compressed {
            flags.insert(PeerManagerHeaderFlags::COMPRESSED);
        } else {
            flags.remove(PeerManagerHeaderFlags::COMPRESSED);
        }
        self.flags = flags.bits();
        self
    }

    pub fn mark_kcp_src_modified(&mut self) -> &mut Self {
        assert_eq!(self.packet_type, PacketType::Data as u8);
        self.packet_type = PacketType::DataWithKcpSrcModified as u8;
        self
    }

    pub fn is_kcp_src_modified(&self) -> bool {
        self.packet_type == PacketType::DataWithKcpSrcModified as u8
    }

    pub fn mark_quic_src_modified(&mut self) -> &mut Self {
        assert_eq!(self.packet_type, PacketType::Data as u8);
        self.packet_type = PacketType::DataWithQuicSrcModified as u8;
        self
    }

    pub fn is_quic_src_modified(&self) -> bool {
        self.packet_type == PacketType::DataWithQuicSrcModified as u8
    }

    pub fn set_not_send_to_tun(&mut self, not_send_to_tun: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if not_send_to_tun {
            flags.insert(PeerManagerHeaderFlags::NOT_SEND_TO_TUN);
        } else {
            flags.remove(PeerManagerHeaderFlags::NOT_SEND_TO_TUN);
        }
        self.flags = flags.bits();
        self
    }

    pub fn is_not_send_to_tun(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::NOT_SEND_TO_TUN)
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct ForeignNetworkPacketHeader {
    pub header_len: U16<DefaultEndian>,
    pub dst_peer_id: U32<DefaultEndian>,
    pub network_name_offset: U16<DefaultEndian>,
    pub network_name_len: U16<DefaultEndian>,
    /* variable length network_name string */
}

impl ForeignNetworkPacketHeader {
    pub fn new(dst_peer_id: u32, network_name: &str) -> Self {
        let network_name_offset = std::mem::size_of::<ForeignNetworkPacketHeader>() as u16;
        let network_name_len = network_name.len() as u16;
        let header_len = network_name_offset + network_name_len;
        Self {
            header_len: U16::new(header_len),
            dst_peer_id: U32::new(dst_peer_id),
            network_name_offset: U16::new(network_name_offset),
            network_name_len: U16::new(network_name_len),
        }
    }

    pub fn get_network_name(&self, zc_packet_payload: &[u8]) -> Option<String> {
        self.validate(zc_packet_payload)?;
        let offset = self.network_name_offset.get() as usize;
        let len = self.network_name_len.get() as usize;
        let end = offset.checked_add(len)?;
        std::str::from_utf8(zc_packet_payload.get(offset..end)?)
            .ok()
            .map(str::to_owned)
    }

    fn validate(&self, payload: &[u8]) -> Option<()> {
        let fixed_len = std::mem::size_of::<Self>();
        let header_len = self.get_header_len();
        let name_offset = self.network_name_offset.get() as usize;
        let name_len = self.network_name_len.get() as usize;
        let name_end = name_offset.checked_add(name_len)?;
        (header_len >= fixed_len
            && header_len <= payload.len()
            && name_offset >= fixed_len
            && name_len != 0
            && name_end == header_len)
            .then_some(())
    }

    pub fn get_dst_peer_id(&self) -> u32 {
        self.dst_peer_id.get()
    }

    pub fn get_header_len(&self) -> usize {
        self.header_len.get() as usize
    }
}

// reserve space for AEAD authentication tag and nonce
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug)]
pub struct AeadTail<const TAG_SIZE: usize, const NONCE_SIZE: usize> {
    pub tag: [u8; TAG_SIZE],
    pub nonce: [u8; NONCE_SIZE],
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize> AeadTail<TAG_SIZE, NONCE_SIZE> {
    pub const TAG_SIZE: usize = TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;

    pub const SIZE: usize = std::mem::size_of::<Self>();
}

pub type StandardAeadTail = AeadTail<16, 12>;

#[derive(AsBytes, FromZeroes, Clone, Debug, Copy, PartialEq, Hash, Eq)]
#[repr(u8)]
pub enum CompressorAlgo {
    None = 0,
    #[cfg(feature = "zstd")]
    ZstdDefault = 1,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct CompressorTail {
    pub algo: u8,
}
pub const COMPRESSOR_TAIL_SIZE: usize = std::mem::size_of::<CompressorTail>();

impl CompressorTail {
    pub fn get_algo(&self) -> Option<CompressorAlgo> {
        match self.algo {
            #[cfg(feature = "zstd")]
            1 => Some(CompressorAlgo::ZstdDefault),
            _ => None,
        }
    }

    pub fn new(algo: CompressorAlgo) -> Self {
        Self { algo: algo as u8 }
    }
}

pub const LINK_ENVELOPE_RESERVED_SIZE: usize = 24;
pub const TAIL_RESERVED_SIZE: usize = max(
    max(StandardAeadTail::SIZE, COMPRESSOR_TAIL_SIZE),
    LINK_ENVELOPE_RESERVED_SIZE,
);

#[derive(Default, Debug)]
pub struct ZCPacketOffsets {
    pub payload_offset: usize,
    pub peer_manager_header_offset: usize,
    pub tcp_tunnel_header_offset: usize,
    pub udp_tunnel_header_offset: usize,
    pub wg_tunnel_header_offset: usize,
    pub dummy_tunnel_header_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZCPacketType {
    // received from peer tcp connection
    TCP,
    // received from peer udp connection
    UDP,
    // received from peer wireguard connection
    WG,
    // received from local tun device, should reserve header space for tcp or udp tunnel
    NIC,
    // tunnel without header
    DummyTunnel,
}

const PAYLOAD_OFFSET_FOR_NIC_PACKET: usize = max(
    max(TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE),
    WG_TUNNEL_HEADER_SIZE,
) + PEER_MANAGER_HEADER_SIZE;

// UDP Tunnel: TUN MTU + 24 (Easy) + 20 (Encrypted) + 8(UDP) + 20(IP) = TUN MTU + 72
// TCP Tunnel: TUN MTU + 20 (Easy) + 20 (Encrypted) + 20(TCP) + 20(IP) = TUN MTU + 80

const INVALID_OFFSET: usize = usize::MAX;

const fn get_converted_offset(old_hdr_size: usize, new_hdr_size: usize) -> usize {
    if old_hdr_size < new_hdr_size {
        INVALID_OFFSET
    } else {
        old_hdr_size - new_hdr_size
    }
}

impl ZCPacketType {
    pub fn get_packet_offsets(&self) -> ZCPacketOffsets {
        match self {
            ZCPacketType::TCP => ZCPacketOffsets {
                payload_offset: TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: TCP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: 0,
                udp_tunnel_header_offset: get_converted_offset(
                    TCP_TUNNEL_HEADER_SIZE,
                    UDP_TUNNEL_HEADER_SIZE,
                ),
                wg_tunnel_header_offset: get_converted_offset(
                    TCP_TUNNEL_HEADER_SIZE,
                    WG_TUNNEL_HEADER_SIZE,
                ),
                dummy_tunnel_header_offset: get_converted_offset(TCP_TUNNEL_HEADER_SIZE, 0),
            },
            ZCPacketType::UDP => ZCPacketOffsets {
                payload_offset: UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: UDP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: get_converted_offset(
                    UDP_TUNNEL_HEADER_SIZE,
                    TCP_TUNNEL_HEADER_SIZE,
                ),
                udp_tunnel_header_offset: 0,
                wg_tunnel_header_offset: get_converted_offset(
                    UDP_TUNNEL_HEADER_SIZE,
                    WG_TUNNEL_HEADER_SIZE,
                ),
                dummy_tunnel_header_offset: get_converted_offset(UDP_TUNNEL_HEADER_SIZE, 0),
            },
            ZCPacketType::WG => ZCPacketOffsets {
                payload_offset: WG_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: WG_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: get_converted_offset(
                    WG_TUNNEL_HEADER_SIZE,
                    TCP_TUNNEL_HEADER_SIZE,
                ),
                udp_tunnel_header_offset: get_converted_offset(
                    WG_TUNNEL_HEADER_SIZE,
                    UDP_TUNNEL_HEADER_SIZE,
                ),
                wg_tunnel_header_offset: 0,
                dummy_tunnel_header_offset: get_converted_offset(WG_TUNNEL_HEADER_SIZE, 0),
            },
            ZCPacketType::NIC => ZCPacketOffsets {
                payload_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET,
                peer_manager_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE,
                tcp_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - TCP_TUNNEL_HEADER_SIZE,
                udp_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - UDP_TUNNEL_HEADER_SIZE,
                wg_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - WG_TUNNEL_HEADER_SIZE,
                dummy_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE,
            },
            ZCPacketType::DummyTunnel => ZCPacketOffsets {
                payload_offset: PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: 0,
                tcp_tunnel_header_offset: get_converted_offset(0, TCP_TUNNEL_HEADER_SIZE),
                udp_tunnel_header_offset: get_converted_offset(0, UDP_TUNNEL_HEADER_SIZE),
                wg_tunnel_header_offset: get_converted_offset(0, WG_TUNNEL_HEADER_SIZE),
                dummy_tunnel_header_offset: 0,
            },
        }
    }
}

struct ReusableBufferPoolInner {
    buffers: ArrayQueue<BytesMut>,
    buffer_len: usize,
}

#[derive(Clone)]
pub(crate) struct ReusableBufferPool {
    inner: Arc<ReusableBufferPoolInner>,
}

impl std::fmt::Debug for ReusableBufferPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReusableBufferPool")
            .field("available", &self.available())
            .field("capacity", &self.inner.buffers.capacity())
            .field("buffer_len", &self.inner.buffer_len)
            .finish()
    }
}

impl ReusableBufferPool {
    pub(crate) fn new(buffer_len: usize, buffer_count: usize) -> Self {
        assert!(buffer_len > 0);
        assert!(buffer_count > 0);
        let buffers = ArrayQueue::new(buffer_count);
        for _ in 0..buffer_count {
            buffers
                .push(zeroed_packet_buffer(buffer_len))
                .expect("a new reusable buffer pool has room");
        }
        Self {
            inner: Arc::new(ReusableBufferPoolInner {
                buffers,
                buffer_len,
            }),
        }
    }

    pub(crate) fn try_take(&self) -> Option<BytesMut> {
        self.inner.buffers.pop()
    }

    pub(crate) fn take_or_allocate(&self) -> BytesMut {
        self.try_take()
            .unwrap_or_else(|| zeroed_packet_buffer(self.inner.buffer_len))
    }

    fn recycle(&self, mut buffer: BytesMut) {
        if buffer.capacity() < self.inner.buffer_len {
            buffer = zeroed_packet_buffer(self.inner.buffer_len);
        } else {
            buffer.truncate(self.inner.buffer_len);
            if buffer.len() < self.inner.buffer_len {
                buffer.resize(self.inner.buffer_len, 0);
            }
        }
        let _ = self.inner.buffers.push(buffer);
    }

    fn recycle_initialized(&self, mut buffer: BytesMut, allocation_start: usize) {
        if buffer.as_ptr() as usize != allocation_start || buffer.capacity() < self.inner.buffer_len
        {
            self.replace_detached();
            return;
        }
        buffer.truncate(self.inner.buffer_len);
        if buffer.len() < self.inner.buffer_len {
            // This allocation came from a fully initialized pool slab.
            unsafe { buffer.set_len(self.inner.buffer_len) };
        }
        let _ = self.inner.buffers.push(buffer);
    }

    fn replace_detached(&self) {
        self.recycle(zeroed_packet_buffer(self.inner.buffer_len));
    }

    pub(crate) fn available(&self) -> usize {
        self.inner.buffers.len()
    }
}

fn zeroed_packet_buffer(length: usize) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(length);
    buffer.resize(length, 0);
    buffer
}

struct ReusableBytesOwner {
    prefix: Option<BytesMut>,
    buffer: Option<BytesMut>,
    pool: ReusableBufferPool,
    allocation_start: usize,
}

impl AsRef<[u8]> for ReusableBytesOwner {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref().expect("the reusable buffer exists")
    }
}

impl Drop for ReusableBytesOwner {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let mut buffer = buffer;
            if let Some(mut prefix) = self.prefix.take() {
                prefix.unsplit(buffer);
                buffer = prefix;
            }
            self.pool.recycle_initialized(buffer, self.allocation_start);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct VlanStack {
    tags: [u16; 4],
    len: u8,
}

impl VlanStack {
    pub(crate) fn as_slice(&self) -> &[u16] {
        &self.tags[..usize::from(self.len)]
    }

    fn push(&mut self, tag: u16) -> Option<()> {
        let slot = self.tags.get_mut(usize::from(self.len))?;
        *slot = tag;
        self.len += 1;
        Some(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EthernetNetworkMetadata {
    pub(crate) ether_type: u16,
    pub(crate) payload_offset: usize,
    pub(crate) vlan_stack: VlanStack,
}

pub(crate) fn ethernet_network_metadata(frame: &[u8]) -> Option<EthernetNetworkMetadata> {
    let mut ether_type = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let mut payload_offset = 14;
    let mut vlan_stack = VlanStack::default();
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        let tag = frame.get(payload_offset..payload_offset + 4)?;
        vlan_stack.push(u16::from_be_bytes(tag[..2].try_into().ok()?) & 0x0fff)?;
        ether_type = u16::from_be_bytes(tag[2..4].try_into().ok()?);
        payload_offset += 4;
    }
    Some(EthernetNetworkMetadata {
        ether_type,
        payload_offset,
        vlan_stack,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedPacketMetadata {
    pub(crate) from_peer_id: u32,
    pub(crate) to_peer_id: u32,
    pub(crate) packet_type: u8,
    pub(crate) encrypted: bool,
    pub(crate) compressed: bool,
    pub(crate) not_send_to_tun: bool,
    pub(crate) flow_shard: Option<u16>,
    pub(crate) ethernet_destination: Option<[u8; 6]>,
    pub(crate) ethernet_source: Option<[u8; 6]>,
    pub(crate) ethernet_network: Option<EthernetNetworkMetadata>,
}

#[derive(Debug)]
pub struct ZCPacket {
    inner: BytesMut,
    packet_type: ZCPacketType,
    lossy_hint: Option<bool>,
    authenticated_peer_id: Option<PeerId>,
    authenticated_peer_identity_type: Option<PeerIdentityType>,
    authenticated_peer_secure_auth_level: Option<SecureAuthLevel>,
    authenticated_session_id: Option<uuid::Uuid>,
    verified_origin_peer_id: Option<PeerId>,
    verified_origin_peer_identity_type: Option<PeerIdentityType>,
    verified_origin_peer_secure_auth_level: Option<SecureAuthLevel>,
    verified_origin_session_id: Option<uuid::Uuid>,
    /// Full flow hash for local path selection before the packet is serialized.
    /// The wire header carries only the bounded shard.
    flow_hash: Option<u64>,
    /// Local-only identity used to join a packet with batch sidecar metadata.
    batch_key: Option<usize>,
    parsed_metadata: Option<ParsedPacketMetadata>,
    reusable_pool: Option<ReusableBufferPool>,
    reusable_prefix: Option<BytesMut>,
    reusable_allocation_start: Option<usize>,
}

impl Clone for ZCPacket {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            packet_type: self.packet_type,
            lossy_hint: self.lossy_hint,
            authenticated_peer_id: self.authenticated_peer_id,
            authenticated_peer_identity_type: self.authenticated_peer_identity_type,
            authenticated_peer_secure_auth_level: self.authenticated_peer_secure_auth_level,
            authenticated_session_id: self.authenticated_session_id,
            verified_origin_peer_id: self.verified_origin_peer_id,
            verified_origin_peer_identity_type: self.verified_origin_peer_identity_type,
            verified_origin_peer_secure_auth_level: self.verified_origin_peer_secure_auth_level,
            verified_origin_session_id: self.verified_origin_session_id,
            flow_hash: self.flow_hash,
            batch_key: self.batch_key,
            parsed_metadata: self.parsed_metadata,
            reusable_pool: None,
            reusable_prefix: None,
            reusable_allocation_start: None,
        }
    }
}

impl Drop for ZCPacket {
    fn drop(&mut self) {
        self.recycle_reusable_buffer();
    }
}

impl ZCPacket {
    fn detach_reusable_buffer(&mut self) {
        if let Some(pool) = self.reusable_pool.take() {
            self.reusable_prefix.take();
            self.reusable_allocation_start.take();
            pool.replace_detached();
        }
    }

    fn advance_inner(&mut self, length: usize) {
        let prefix = self.inner.split_to(length);
        if let Some(existing) = self.reusable_prefix.as_mut() {
            existing.unsplit(prefix);
        } else if self.reusable_pool.is_some() {
            self.reusable_prefix = Some(prefix);
        }
    }

    fn recycle_reusable_buffer(&mut self) {
        let Some(pool) = self.reusable_pool.take() else {
            return;
        };
        let allocation_start = self.reusable_allocation_start.take();
        let mut buffer = std::mem::take(&mut self.inner);
        if let Some(mut prefix) = self.reusable_prefix.take() {
            prefix.unsplit(buffer);
            buffer = prefix;
        }
        if let Some(allocation_start) = allocation_start {
            pool.recycle_initialized(buffer, allocation_start);
        } else {
            pool.recycle(buffer);
        }
    }

    fn bytes_from_offset(&self, offset: usize) -> Option<&[u8]> {
        self.inner.get(offset..)
    }

    fn mut_bytes_from_offset(&mut self, offset: usize) -> Option<&mut [u8]> {
        self.inner.get_mut(offset..)
    }

    pub fn new_nic_packet() -> Self {
        Self {
            inner: BytesMut::new(),
            packet_type: ZCPacketType::NIC,
            lossy_hint: None,
            authenticated_peer_id: None,
            authenticated_peer_identity_type: None,
            authenticated_peer_secure_auth_level: None,
            authenticated_session_id: None,
            verified_origin_peer_id: None,
            verified_origin_peer_identity_type: None,
            verified_origin_peer_secure_auth_level: None,
            verified_origin_session_id: None,
            flow_hash: None,
            batch_key: None,
            parsed_metadata: None,
            reusable_pool: None,
            reusable_prefix: None,
            reusable_allocation_start: None,
        }
    }

    pub fn new_from_buf(buf: BytesMut, packet_type: ZCPacketType) -> Self {
        Self {
            inner: buf,
            packet_type,
            lossy_hint: None,
            authenticated_peer_id: None,
            authenticated_peer_identity_type: None,
            authenticated_peer_secure_auth_level: None,
            authenticated_session_id: None,
            verified_origin_peer_id: None,
            verified_origin_peer_identity_type: None,
            verified_origin_peer_secure_auth_level: None,
            verified_origin_session_id: None,
            flow_hash: None,
            batch_key: None,
            parsed_metadata: None,
            reusable_pool: None,
            reusable_prefix: None,
            reusable_allocation_start: None,
        }
    }

    pub(crate) fn new_from_reusable_buf(
        buf: BytesMut,
        packet_type: ZCPacketType,
        reusable_pool: ReusableBufferPool,
    ) -> Self {
        let reusable_allocation_start = Some(buf.as_ptr() as usize);
        Self {
            inner: buf,
            packet_type,
            lossy_hint: None,
            authenticated_peer_id: None,
            authenticated_peer_identity_type: None,
            authenticated_peer_secure_auth_level: None,
            authenticated_session_id: None,
            verified_origin_peer_id: None,
            verified_origin_peer_identity_type: None,
            verified_origin_peer_secure_auth_level: None,
            verified_origin_session_id: None,
            flow_hash: None,
            batch_key: None,
            parsed_metadata: None,
            reusable_pool: Some(reusable_pool),
            reusable_prefix: None,
            reusable_allocation_start,
        }
    }

    pub fn new_with_payload(payload: &[u8]) -> Self {
        let mut ret = Self::new_nic_packet();
        let payload_off = ret.packet_type.get_packet_offsets().payload_offset;
        let total_len = payload_off + payload.len();
        ret.inner.resize(total_len, 0);
        ret.mut_payload().copy_from_slice(payload);
        ret
    }

    pub(crate) fn new_with_payload_len(payload_len: usize) -> Self {
        let mut ret = Self::new_nic_packet();
        let payload_off = ret.packet_type.get_packet_offsets().payload_offset;
        ret.inner.resize(payload_off + payload_len, 0);
        ret
    }

    pub fn new_for_tun(cap: usize, packet_info_len: usize) -> Self {
        let mut ret = Self::new_nic_packet();
        let total_len = ret.packet_type.get_packet_offsets().payload_offset - packet_info_len;
        ret.inner.reserve(cap.max(total_len));
        ret.inner.resize(total_len, 0);
        ret
    }

    pub fn new_for_foreign_network(
        network_name: &str,
        dst_peer_id: u32,
        foreign_zc_packet: &ZCPacket,
    ) -> Self {
        let foreign_network_hdr = ForeignNetworkPacketHeader::new(dst_peer_id, network_name);
        let total_payload_len =
            foreign_network_hdr.get_header_len() + foreign_zc_packet.tunnel_payload().len();

        let mut ret = Self::new_nic_packet();
        let payload_off = ret.packet_type.get_packet_offsets().payload_offset;
        ret.inner.resize(payload_off + total_payload_len, 0);

        let fixed_hdr_len = std::mem::size_of::<ForeignNetworkPacketHeader>();
        ret.mut_payload()[..fixed_hdr_len].copy_from_slice(foreign_network_hdr.as_bytes());

        let name_offset = foreign_network_hdr.network_name_offset.get() as usize;
        let name_len = foreign_network_hdr.network_name_len.get() as usize;
        ret.mut_payload()[name_offset..name_offset + name_len]
            .copy_from_slice(network_name.as_bytes());

        ret.mut_payload()[foreign_network_hdr.get_header_len()..]
            .copy_from_slice(foreign_zc_packet.tunnel_payload());

        let hdr = ret.mut_peer_manager_header().unwrap();
        hdr.initialize(
            0,
            0,
            PacketType::ForeignNetworkPacket as u8,
            total_payload_len as u32,
        );

        ret
    }

    pub fn packet_type(&self) -> ZCPacketType {
        self.packet_type
    }

    pub(crate) fn refresh_parsed_metadata(&mut self) -> Option<ParsedPacketMetadata> {
        let header = self.peer_manager_header()?;
        let from_peer_id = header.from_peer_id.get();
        let to_peer_id = header.to_peer_id.get();
        let packet_type = header.packet_type;
        let encrypted = header.is_encrypted();
        let compressed = header.is_compressed();
        let not_send_to_tun = header.is_not_send_to_tun();
        let flow_shard = header.flow_shard();
        let (ethernet_destination, ethernet_source, ethernet_network) =
            if packet_type == PacketType::Ethernet as u8 {
                let frame = self.payload();
                match (frame.get(..6), frame.get(6..12), frame.get(12..14)) {
                    (Some(destination), Some(source), Some(_)) => {
                        let mut parsed_destination = [0_u8; 6];
                        let mut parsed_source = [0_u8; 6];
                        parsed_destination.copy_from_slice(destination);
                        parsed_source.copy_from_slice(source);
                        (
                            Some(parsed_destination),
                            Some(parsed_source),
                            ethernet_network_metadata(frame),
                        )
                    }
                    _ => (None, None, None),
                }
            } else {
                (None, None, None)
            };
        let metadata = ParsedPacketMetadata {
            from_peer_id,
            to_peer_id,
            packet_type,
            encrypted,
            compressed,
            not_send_to_tun,
            flow_shard,
            ethernet_destination,
            ethernet_source,
            ethernet_network,
        };
        self.parsed_metadata = Some(metadata);
        Some(metadata)
    }

    pub(crate) fn parsed_metadata(&self) -> Option<&ParsedPacketMetadata> {
        self.parsed_metadata.as_ref()
    }

    pub fn payload_offset(&self) -> usize {
        self.packet_type.get_packet_offsets().payload_offset
    }

    pub fn mut_payload(&mut self) -> &mut [u8] {
        self.flow_hash = None;
        self.parsed_metadata = None;
        let offset = self.payload_offset();
        &mut self.inner[offset..]
    }

    pub(crate) fn mut_payload_preserving_flow_hash(&mut self) -> &mut [u8] {
        self.parsed_metadata = None;
        let offset = self.payload_offset();
        &mut self.inner[offset..]
    }

    pub fn mut_peer_manager_header(&mut self) -> Option<&mut PeerManagerHeader> {
        self.parsed_metadata = None;
        let offset = self
            .packet_type
            .get_packet_offsets()
            .peer_manager_header_offset;
        let bytes = self.mut_bytes_from_offset(offset)?;
        PeerManagerHeader::mut_from_prefix(bytes)
    }

    pub fn mut_tcp_tunnel_header(&mut self) -> Option<&mut TCPTunnelHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .tcp_tunnel_header_offset;
        let bytes = self.mut_bytes_from_offset(offset)?;
        TCPTunnelHeader::mut_from_prefix(bytes)
    }

    pub fn mut_udp_tunnel_header(&mut self) -> Option<&mut UDPTunnelHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .udp_tunnel_header_offset;
        let bytes = self.mut_bytes_from_offset(offset)?;
        UDPTunnelHeader::mut_from_prefix(bytes)
    }

    pub fn mut_wg_tunnel_header(&mut self) -> Option<&mut WGTunnelHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .wg_tunnel_header_offset;
        let bytes = self.mut_bytes_from_offset(offset)?;
        WGTunnelHeader::mut_from_prefix(bytes)
    }

    // ref versions
    pub fn payload(&self) -> &[u8] {
        &self.inner[self.payload_offset()..]
    }

    pub fn payload_bytes(mut self) -> BytesMut {
        self.advance_inner(self.payload_offset());
        self.detach_reusable_buffer();
        std::mem::take(&mut self.inner)
    }

    pub fn peer_manager_header(&self) -> Option<&PeerManagerHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .peer_manager_header_offset;
        let bytes = self.bytes_from_offset(offset)?;
        PeerManagerHeader::ref_from_prefix(bytes)
    }

    pub fn tcp_tunnel_header(&self) -> Option<&TCPTunnelHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .tcp_tunnel_header_offset;
        let bytes = self.bytes_from_offset(offset)?;
        TCPTunnelHeader::ref_from_prefix(bytes)
    }

    pub fn udp_tunnel_header(&self) -> Option<&UDPTunnelHeader> {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .udp_tunnel_header_offset;
        let bytes = self.bytes_from_offset(offset)?;
        UDPTunnelHeader::ref_from_prefix(bytes)
    }

    pub fn udp_payload(&self) -> &[u8] {
        &self.inner[self
            .packet_type
            .get_packet_offsets()
            .udp_tunnel_header_offset
            + UDP_TUNNEL_HEADER_SIZE..]
    }

    pub fn payload_len(&self) -> usize {
        self.inner.len() - self.payload_offset()
    }

    pub(crate) fn flow_hash(&self) -> Option<u64> {
        self.flow_hash
    }

    pub(crate) fn set_flow_hash(&mut self, flow_hash: u64) {
        self.flow_hash = Some(flow_hash);
    }

    pub(crate) fn clear_flow_hash(&mut self) {
        self.flow_hash = None;
    }

    pub(crate) fn batch_key(&self) -> Option<usize> {
        self.batch_key
    }

    pub(crate) fn set_batch_key(&mut self, key: usize) {
        self.batch_key = Some(key);
    }

    pub(crate) fn clear_batch_key(&mut self) {
        self.batch_key = None;
    }

    pub fn remove_payload_prefix(&mut self, prefix_len: usize) -> Result<(), &'static str> {
        let payload_len = self.payload_len();
        if prefix_len > payload_len {
            return Err("payload prefix exceeds the packet length");
        }
        self.advance_inner(prefix_len);
        self.flow_hash = None;
        self.parsed_metadata = None;
        Ok(())
    }

    pub(crate) fn remove_payload_prefix_preserving_flow_hash(
        &mut self,
        prefix_len: usize,
    ) -> Result<(), &'static str> {
        let payload_len = self.payload_len();
        if prefix_len > payload_len {
            return Err("payload prefix exceeds the packet length");
        }
        self.advance_inner(prefix_len);
        self.parsed_metadata = None;
        Ok(())
    }

    /// Restore a prefix removed from reusable headroom without moving the payload.
    ///
    /// This path is valid after one matching prefix removal from a pooled packet.
    /// The method restores the original allocation, writes the new prefix, and keeps the flow
    /// hash. It returns false when the packet has no exact reusable headroom.
    pub(crate) fn restore_payload_prefix_from_reusable_headroom(&mut self, prefix: &[u8]) -> bool {
        let Some(mut reusable_prefix) = self.reusable_prefix.take() else {
            return false;
        };
        if reusable_prefix.len() != prefix.len()
            || self.inner.len() < self.payload_offset().saturating_add(prefix.len())
        {
            self.reusable_prefix = Some(reusable_prefix);
            return false;
        }

        reusable_prefix.unsplit(std::mem::take(&mut self.inner));
        self.inner = reusable_prefix;
        let payload_offset = self.payload_offset();
        self.inner[payload_offset..payload_offset + prefix.len()].copy_from_slice(prefix);
        self.parsed_metadata = None;
        true
    }

    pub fn prepend_payload(&mut self, prefix: &[u8]) -> Result<(), &'static str> {
        let payload_offset = self.payload_offset();
        let old_len = self.inner.len();
        let new_inner_len = old_len
            .checked_add(prefix.len())
            .ok_or("payload length overflow")?;
        self.inner.reserve(prefix.len());
        self.inner.resize(new_inner_len, 0);
        self.inner
            .copy_within(payload_offset..old_len, payload_offset + prefix.len());
        self.inner[payload_offset..payload_offset + prefix.len()].copy_from_slice(prefix);
        self.flow_hash = None;
        self.parsed_metadata = None;
        Ok(())
    }

    pub(crate) fn prepend_payload_preserving_flow_hash(
        &mut self,
        prefix: &[u8],
    ) -> Result<(), &'static str> {
        let payload_offset = self.payload_offset();
        let old_len = self.inner.len();
        let new_inner_len = old_len
            .checked_add(prefix.len())
            .ok_or("payload length overflow")?;
        self.inner.reserve(prefix.len());
        self.inner.resize(new_inner_len, 0);
        self.inner
            .copy_within(payload_offset..old_len, payload_offset + prefix.len());
        self.inner[payload_offset..payload_offset + prefix.len()].copy_from_slice(prefix);
        self.parsed_metadata = None;
        Ok(())
    }

    pub fn append_payload(&mut self, suffix: &[u8]) -> Result<(), &'static str> {
        self.inner
            .len()
            .checked_add(suffix.len())
            .ok_or("payload length overflow")?;
        self.inner.extend_from_slice(suffix);
        self.flow_hash = None;
        self.parsed_metadata = None;
        Ok(())
    }

    pub(crate) fn append_payload_preserving_flow_hash(
        &mut self,
        suffix: &[u8],
    ) -> Result<(), &'static str> {
        self.inner
            .len()
            .checked_add(suffix.len())
            .ok_or("payload length overflow")?;
        self.inner.extend_from_slice(suffix);
        self.parsed_metadata = None;
        Ok(())
    }

    pub fn remove_payload_suffix(&mut self, suffix_len: usize) -> Result<(), &'static str> {
        let payload_len = self.payload_len();
        if suffix_len > payload_len {
            return Err("payload suffix exceeds the packet length");
        }
        self.inner.truncate(self.inner.len() - suffix_len);
        self.flow_hash = None;
        self.parsed_metadata = None;
        Ok(())
    }

    pub(crate) fn remove_payload_suffix_preserving_flow_hash(
        &mut self,
        suffix_len: usize,
    ) -> Result<(), &'static str> {
        let payload_len = self.payload_len();
        if suffix_len > payload_len {
            return Err("payload suffix exceeds the packet length");
        }
        self.inner.truncate(self.inner.len() - suffix_len);
        self.parsed_metadata = None;
        Ok(())
    }

    pub fn buf_len(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn retained_buffer_capacity(&self) -> usize {
        self.inner
            .capacity()
            .saturating_add(self.reusable_prefix.as_ref().map_or(0, BytesMut::capacity))
    }

    /// Copy the active packet bytes into a tight allocation and release any
    /// oversized receive slab retained behind this packet.
    ///
    /// Metadata remains local to the packet object. Reusable input storage is
    /// returned to its pool before this method returns.
    pub(crate) fn compact_retained_buffer(&mut self) {
        if self.retained_buffer_capacity() <= self.inner.len() {
            return;
        }

        let mut compact = BytesMut::with_capacity(self.inner.len());
        compact.extend_from_slice(&self.inner);
        if self.reusable_pool.is_some() {
            self.recycle_reusable_buffer();
        }
        self.inner = compact;
        debug_assert!(self.reusable_pool.is_none());
        debug_assert!(self.reusable_prefix.is_none());
        debug_assert!(self.reusable_allocation_start.is_none());
    }

    pub fn fill_peer_manager_hdr(&mut self, from_peer_id: u32, to_peer_id: u32, packet_type: u8) {
        self.flow_hash = None;
        let payload_len = self.payload_len();
        let hdr = self.mut_peer_manager_header().unwrap();
        hdr.initialize(from_peer_id, to_peer_id, packet_type, payload_len as u32);
    }

    /// Initialize the peer header without invalidating the payload-derived flow hash.
    pub(crate) fn fill_peer_manager_hdr_preserving_flow_hash(
        &mut self,
        from_peer_id: u32,
        to_peer_id: u32,
        packet_type: u8,
    ) {
        let flow_hash = self.flow_hash;
        self.fill_peer_manager_hdr(from_peer_id, to_peer_id, packet_type);
        self.flow_hash = flow_hash;
    }

    pub(crate) fn refresh_peer_manager_hdr_len(&mut self) {
        let payload_len = self.payload_len();
        if let Some(header) = self.mut_peer_manager_header() {
            header.len.set(payload_len as u32);
        }
    }

    pub fn tunnel_payload(&self) -> &[u8] {
        &self.inner[self
            .packet_type
            .get_packet_offsets()
            .peer_manager_header_offset..]
    }

    pub fn tunnel_payload_bytes(mut self) -> BytesMut {
        self.advance_inner(
            self.packet_type
                .get_packet_offsets()
                .peer_manager_header_offset,
        );
        self.detach_reusable_buffer();
        std::mem::take(&mut self.inner)
    }

    pub fn tunnel_payload_into_bytes(self) -> Bytes {
        let offset = self
            .packet_type
            .get_packet_offsets()
            .peer_manager_header_offset;
        self.into_bytes().slice(offset..)
    }

    pub(crate) fn convert_type_in_place(
        &mut self,
        target_packet_type: ZCPacketType,
    ) -> Result<(), &'static str> {
        if target_packet_type == self.packet_type {
            return Ok(());
        }

        let new_offset = match target_packet_type {
            ZCPacketType::TCP => {
                self.packet_type
                    .get_packet_offsets()
                    .tcp_tunnel_header_offset
            }
            ZCPacketType::UDP => {
                self.packet_type
                    .get_packet_offsets()
                    .udp_tunnel_header_offset
            }
            ZCPacketType::WG => {
                self.packet_type
                    .get_packet_offsets()
                    .wg_tunnel_header_offset
            }
            ZCPacketType::DummyTunnel => {
                self.packet_type
                    .get_packet_offsets()
                    .dummy_tunnel_header_offset
            }
            ZCPacketType::NIC => return Err("in-place NIC conversion is not supported"),
        };
        if new_offset == INVALID_OFFSET {
            return Err("the packet does not have the required in-place prefix");
        }

        self.advance_inner(new_offset);
        self.packet_type = target_packet_type;
        Ok(())
    }

    pub fn convert_type(mut self, target_packet_type: ZCPacketType) -> Self {
        if target_packet_type == self.packet_type {
            return self;
        }

        let new_offset = match target_packet_type {
            ZCPacketType::TCP => {
                self.packet_type
                    .get_packet_offsets()
                    .tcp_tunnel_header_offset
            }
            ZCPacketType::UDP => {
                self.packet_type
                    .get_packet_offsets()
                    .udp_tunnel_header_offset
            }
            ZCPacketType::WG => {
                self.packet_type
                    .get_packet_offsets()
                    .wg_tunnel_header_offset
            }
            ZCPacketType::DummyTunnel => {
                self.packet_type
                    .get_packet_offsets()
                    .dummy_tunnel_header_offset
            }
            ZCPacketType::NIC => unreachable!(),
        };

        tracing::trace!(?self.packet_type, ?target_packet_type, ?new_offset, "convert zc packet type");

        if new_offset == INVALID_OFFSET {
            // copy peer manager header and payload to new buffer
            let tunnel_payload = self.tunnel_payload();
            let new_pm_offset = target_packet_type
                .get_packet_offsets()
                .peer_manager_header_offset;
            let mut buf = BytesMut::with_capacity(new_pm_offset + tunnel_payload.len());
            buf.resize(new_pm_offset, 0);
            buf.extend_from_slice(tunnel_payload);
            let mut packet = Self::new_from_buf(buf, target_packet_type);
            packet.lossy_hint = self.lossy_hint;
            packet.authenticated_peer_id = self.authenticated_peer_id;
            packet.authenticated_peer_identity_type = self.authenticated_peer_identity_type;
            packet.authenticated_peer_secure_auth_level = self.authenticated_peer_secure_auth_level;
            packet.authenticated_session_id = self.authenticated_session_id;
            packet.verified_origin_peer_id = self.verified_origin_peer_id;
            packet.verified_origin_peer_identity_type = self.verified_origin_peer_identity_type;
            packet.verified_origin_peer_secure_auth_level =
                self.verified_origin_peer_secure_auth_level;
            packet.verified_origin_session_id = self.verified_origin_session_id;
            packet.flow_hash = self.flow_hash;
            packet.batch_key = self.batch_key;
            self.recycle_reusable_buffer();
            return packet;
        }

        self.advance_inner(new_offset);
        self.packet_type = target_packet_type;
        self
    }

    pub fn into_bytes(mut self) -> Bytes {
        if let Some(pool) = self.reusable_pool.take() {
            Bytes::from_owner(ReusableBytesOwner {
                prefix: self.reusable_prefix.take(),
                buffer: Some(std::mem::take(&mut self.inner)),
                pool,
                allocation_start: self
                    .reusable_allocation_start
                    .take()
                    .expect("a reusable packet records its allocation"),
            })
        } else {
            std::mem::take(&mut self.inner).freeze()
        }
    }

    pub fn inner(mut self) -> BytesMut {
        self.detach_reusable_buffer();
        std::mem::take(&mut self.inner)
    }

    pub fn mut_inner(&mut self) -> &mut BytesMut {
        self.flow_hash = None;
        self.parsed_metadata = None;
        &mut self.inner
    }

    pub(crate) fn mut_inner_preserving_flow_hash(&mut self) -> &mut BytesMut {
        self.parsed_metadata = None;
        &mut self.inner
    }

    pub fn is_lossy(&self) -> bool {
        if let Some(lossy) = self.lossy_hint {
            return lossy;
        }
        self.peer_manager_header()
            .map(|hdr| {
                hdr.packet_type == PacketType::Data as u8
                    || hdr.packet_type == PacketType::Ethernet as u8
                    || hdr.packet_type == PacketType::AlternateFecSource as u8
                    || hdr.packet_type == PacketType::AlternateFecParity as u8
            })
            .unwrap_or(false)
    }

    pub(crate) fn set_lossy_hint(&mut self, lossy: bool) {
        self.lossy_hint = Some(lossy);
    }

    pub(crate) fn set_authenticated_peer_id(&mut self, peer_id: PeerId) -> bool {
        if peer_id == 0 {
            return false;
        }
        match self.authenticated_peer_id {
            None => {
                self.authenticated_peer_id = Some(peer_id);
                true
            }
            Some(current) => current == peer_id,
        }
    }

    pub(crate) fn authenticated_peer_id(&self) -> Option<PeerId> {
        self.authenticated_peer_id
    }

    pub(crate) fn set_authenticated_peer_identity_type(
        &mut self,
        identity_type: PeerIdentityType,
    ) -> bool {
        match self.authenticated_peer_identity_type {
            None => {
                self.authenticated_peer_identity_type = Some(identity_type);
                true
            }
            Some(current) => current == identity_type,
        }
    }

    pub(crate) fn authenticated_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.authenticated_peer_identity_type
    }

    pub(crate) fn set_authenticated_peer_secure_auth_level(
        &mut self,
        level: SecureAuthLevel,
    ) -> bool {
        match self.authenticated_peer_secure_auth_level {
            None => {
                self.authenticated_peer_secure_auth_level = Some(level);
                true
            }
            Some(current) => current == level,
        }
    }

    pub(crate) fn authenticated_peer_secure_auth_level(&self) -> Option<SecureAuthLevel> {
        self.authenticated_peer_secure_auth_level
    }

    pub(crate) fn set_authenticated_session_id(&mut self, session_id: uuid::Uuid) -> bool {
        match self.authenticated_session_id {
            None => {
                self.authenticated_session_id = Some(session_id);
                true
            }
            Some(current) => current == session_id,
        }
    }

    pub(crate) fn authenticated_session_id(&self) -> Option<uuid::Uuid> {
        self.authenticated_session_id
    }

    pub(crate) fn set_verified_origin(
        &mut self,
        peer_id: PeerId,
        identity_type: PeerIdentityType,
        secure_auth_level: SecureAuthLevel,
        session_id: uuid::Uuid,
    ) -> bool {
        if peer_id == 0 {
            return false;
        }
        match (
            self.verified_origin_peer_id,
            self.verified_origin_peer_identity_type,
            self.verified_origin_peer_secure_auth_level,
            self.verified_origin_session_id,
        ) {
            (None, None, None, None) => {
                self.verified_origin_peer_id = Some(peer_id);
                self.verified_origin_peer_identity_type = Some(identity_type);
                self.verified_origin_peer_secure_auth_level = Some(secure_auth_level);
                self.verified_origin_session_id = Some(session_id);
                true
            }
            (
                Some(current_peer),
                Some(current_identity),
                Some(current_auth_level),
                Some(current_session),
            ) => {
                current_peer == peer_id
                    && current_identity == identity_type
                    && current_auth_level == secure_auth_level
                    && current_session == session_id
            }
            _ => false,
        }
    }

    pub(crate) fn logical_authenticated_peer_id(&self) -> Option<PeerId> {
        if self.verified_origin_peer_id.is_some() {
            self.verified_origin_peer_id
        } else {
            self.authenticated_peer_id
        }
    }

    pub(crate) fn logical_authenticated_peer_identity_type(&self) -> Option<PeerIdentityType> {
        if self.verified_origin_peer_id.is_some() {
            self.verified_origin_peer_identity_type
        } else {
            self.authenticated_peer_identity_type
        }
    }

    pub(crate) fn logical_authenticated_peer_secure_auth_level(&self) -> Option<SecureAuthLevel> {
        if self.verified_origin_peer_id.is_some() {
            self.verified_origin_peer_secure_auth_level
        } else {
            self.authenticated_peer_secure_auth_level
        }
    }

    pub(crate) fn logical_authenticated_session_id(&self) -> Option<uuid::Uuid> {
        if self.verified_origin_peer_id.is_some() {
            self.verified_origin_session_id
        } else {
            self.authenticated_session_id
        }
    }

    pub(crate) fn verified_origin_peer_id(&self) -> Option<PeerId> {
        self.verified_origin_peer_id
    }

    pub(crate) fn verified_origin_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.verified_origin_peer_identity_type
    }

    pub(crate) fn verified_origin_session_id(&self) -> Option<uuid::Uuid> {
        self.verified_origin_session_id
    }

    pub(crate) fn verified_origin_peer_secure_auth_level(&self) -> Option<SecureAuthLevel> {
        self.verified_origin_peer_secure_auth_level
    }

    pub(crate) fn clear_authenticated_peer_id(&mut self) {
        self.authenticated_peer_id = None;
        self.authenticated_peer_identity_type = None;
        self.authenticated_peer_secure_auth_level = None;
        self.authenticated_session_id = None;
        self.verified_origin_peer_id = None;
        self.verified_origin_peer_identity_type = None;
        self.verified_origin_peer_secure_auth_level = None;
        self.verified_origin_session_id = None;
    }

    pub fn foreign_network_hdr(&self) -> Option<&ForeignNetworkPacketHeader> {
        let peer_header = self.peer_manager_header()?;
        if peer_header.packet_type != PacketType::ForeignNetworkPacket as u8 {
            return None;
        }
        let payload = self.payload();
        let header = ForeignNetworkPacketHeader::ref_from_prefix(payload)?;
        header.validate(payload)?;
        Some(header)
    }

    pub fn foreign_network_inner_packet_type(&self) -> Option<u8> {
        if self.peer_manager_header()?.packet_type != PacketType::ForeignNetworkPacket as u8 {
            return None;
        }

        let payload = self.payload();
        let hdr = self.foreign_network_hdr()?;
        let inner_packet = payload.get(hdr.get_header_len()..)?;
        PeerManagerHeader::ref_from_prefix(inner_packet).map(|hdr| hdr.packet_type)
    }

    pub fn foreign_network_packet(mut self) -> Option<Self> {
        let hdr = self.foreign_network_hdr()?;
        let foreign_hdr_len = hdr.get_header_len();
        if foreign_hdr_len < std::mem::size_of::<ForeignNetworkPacketHeader>()
            || foreign_hdr_len > self.payload().len()
        {
            return None;
        }
        self.advance_inner(foreign_hdr_len + self.payload_offset());
        self.packet_type = ZCPacketType::DummyTunnel;
        Some(self)
    }

    pub fn get_src_peer_id(&self) -> Option<u32> {
        self.peer_manager_header().map(|hdr| hdr.from_peer_id.get())
    }

    pub fn get_dst_peer_id(&self) -> Option<u32> {
        self.peer_manager_header().map(|hdr| hdr.to_peer_id.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_length_constructor_exposes_initialized_payload() {
        let mut packet = ZCPacket::new_with_payload_len(1284);

        assert_eq!(packet.payload().len(), 1284);
        assert!(packet.payload().iter().all(|byte| *byte == 0));
        packet.mut_payload()[0] = 7;
        assert_eq!(packet.payload()[0], 7);
    }

    #[test]
    fn reusable_buffer_returns_after_transport_bytes_drop() {
        let pool = ReusableBufferPool::new(256, 2);
        let buffer = pool.try_take().unwrap();
        assert_eq!(pool.available(), 1);
        let packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());

        let transport_bytes = packet.into_bytes();
        assert_eq!(pool.available(), 1);
        drop(transport_bytes);

        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn reusable_buffer_returns_after_tunnel_payload_bytes_drop() {
        let pool = ReusableBufferPool::new(256, 1);
        let mut buffer = pool.try_take().unwrap();
        buffer.truncate(96);
        let packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::TCP, pool.clone());
        let expected = packet.tunnel_payload().to_vec();

        let payload = packet.tunnel_payload_into_bytes();
        assert_eq!(payload.as_ref(), expected);
        assert_eq!(pool.available(), 0);
        drop(payload);

        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn reusable_buffer_returns_when_packet_drops_early() {
        let pool = ReusableBufferPool::new(256, 1);
        let buffer = pool.try_take().unwrap();
        let original_pointer = buffer.as_ptr();
        let packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());

        drop(packet);

        let recycled = pool.try_take().unwrap();
        assert_eq!(recycled.as_ptr(), original_pointer);
    }

    #[test]
    fn reusable_buffer_pool_allocates_without_waiting_when_empty() {
        let pool = ReusableBufferPool::new(256, 1);
        let pooled = pool.try_take().unwrap();

        let replacement = pool.take_or_allocate();

        assert_eq!(replacement.len(), 256);
        assert_eq!(pool.available(), 0);
        drop(pooled);
    }

    #[test]
    fn generic_recycle_initializes_the_restored_slab_length() {
        let pool = ReusableBufferPool::new(256, 1);
        let mut buffer = pool.try_take().unwrap();
        buffer.fill(0xa5);
        buffer.truncate(32);

        pool.recycle(buffer);
        let buffer = pool.try_take().unwrap();

        assert_eq!(buffer.len(), 256);
        assert!(buffer[..32].iter().all(|byte| *byte == 0xa5));
        assert!(buffer[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn reusable_slab_conversion_returns_the_original_allocation() {
        let pool = ReusableBufferPool::new(256, 1);
        let mut buffer = pool.try_take().unwrap();
        let original_pointer = buffer.as_ptr();
        buffer.truncate(96);
        let packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());

        let bytes = packet.convert_type(ZCPacketType::DummyTunnel).into_bytes();
        drop(bytes);

        let recycled = pool.try_take().unwrap();
        assert_eq!(recycled.as_ptr(), original_pointer);
        assert_eq!(recycled.capacity(), 256);
        assert_eq!(recycled.len(), 256);
    }

    #[test]
    fn reusable_slab_waits_for_all_transport_aliases() {
        let pool = ReusableBufferPool::new(256, 1);
        let mut buffer = pool.try_take().unwrap();
        buffer.truncate(96);
        let packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());
        let bytes = packet.convert_type(ZCPacketType::DummyTunnel).into_bytes();
        let alias = bytes.clone();

        drop(bytes);
        assert_eq!(pool.available(), 0);
        drop(alias);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn parsed_ethernet_metadata_stays_with_the_owned_packet() {
        let mut frame = vec![0_u8; 64];
        frame[..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload(&frame);
        packet.fill_peer_manager_hdr(7, 9, PacketType::Ethernet as u8);

        let metadata = packet.refresh_parsed_metadata().unwrap();

        assert_eq!(metadata.from_peer_id, 7);
        assert_eq!(metadata.to_peer_id, 9);
        assert_eq!(metadata.ethernet_destination, Some([0x02, 0, 0, 0, 0, 1]));
        assert_eq!(metadata.ethernet_source, Some([0x02, 0, 0, 0, 0, 2]));
        assert_eq!(packet.parsed_metadata(), Some(&metadata));
    }

    #[test]
    fn ethernet_metadata_keeps_the_vlan_stack() {
        let mut frame = vec![0_u8; 64];
        frame[..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&7_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x88a8_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&8_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x0800_u16.to_be_bytes());

        let metadata = ethernet_network_metadata(&frame).unwrap();
        assert_eq!(metadata.ether_type, 0x0800);
        assert_eq!(metadata.payload_offset, 22);
        assert_eq!(metadata.vlan_stack.as_slice(), &[7, 8]);
    }

    #[test]
    fn test_zc_packet() {
        let payload = b"hello world";
        let mut packet = ZCPacket::new_with_payload(payload);
        let peer_manager_header = packet.mut_peer_manager_header().unwrap();
        peer_manager_header.packet_type = PacketType::Data as u8;
        peer_manager_header.len.set(payload.len() as u32);

        let tcp_tunnel_header = packet.mut_tcp_tunnel_header().unwrap();
        tcp_tunnel_header.len.set(payload.len() as u32);

        // let udp_tunnel_header = packet.mut_udp_tunnel_header().unwrap();
        // udp_tunnel_header.conn_id = 1;
        // udp_tunnel_header.msg_type = 2;
        // udp_tunnel_header.len = payload.len() as u32;

        assert_eq!(packet.payload(), b"hello world");
        assert_eq!(packet.payload_len(), 11);
        println!("{:?}", packet.inner);

        let tcp_packet = packet.convert_type(ZCPacketType::TCP).into_bytes();
        assert_eq!(&tcp_packet[..1], b"\x0b");
        println!("{:?}", tcp_packet);
    }

    #[test]
    fn test_short_tcp_packet_header_access_is_safe() {
        let mut packet = ZCPacket::new_from_buf(BytesMut::from(&b"\x01"[..]), ZCPacketType::TCP);

        assert!(packet.peer_manager_header().is_none());
        assert!(packet.tcp_tunnel_header().is_none());
        assert!(packet.udp_tunnel_header().is_none());
        assert!(packet.mut_peer_manager_header().is_none());
        assert!(packet.mut_tcp_tunnel_header().is_none());
        assert!(packet.mut_udp_tunnel_header().is_none());
        assert!(packet.mut_wg_tunnel_header().is_none());
    }

    #[test]
    fn test_invalid_converted_header_offset_is_safe() {
        let mut packet = ZCPacket::new_from_buf(BytesMut::from(&b"\x01"[..]), ZCPacketType::UDP);

        assert!(packet.mut_wg_tunnel_header().is_none());
    }

    #[test]
    fn critical_l2_marker_and_flow_shard_share_the_reserved_byte() {
        let mut header = PeerManagerHeader::default();
        header.set_critical_l2_control(true);
        header.set_flow_shard(37);
        assert!(header.is_critical_l2_control());
        assert_eq!(header.flow_shard(), Some(37));

        header.set_critical_l2_control(false);
        assert!(!header.is_critical_l2_control());
        assert_eq!(header.flow_shard(), Some(37));
    }

    #[test]
    fn filling_peer_header_clears_stale_reserved_flags() {
        let mut packet = ZCPacket::new_with_payload(b"payload");
        let header = packet.mut_peer_manager_header().unwrap();
        header.set_critical_l2_control(true);
        header.set_flow_shard(17);

        packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);

        let header = packet.peer_manager_header().unwrap();
        assert!(!header.is_critical_l2_control());
        assert_eq!(header.flow_shard(), None);
    }

    #[test]
    fn peer_header_initialization_clears_all_reused_state() {
        let mut header = PeerManagerHeader {
            flags: u8::MAX,
            forward_counter: 7,
            ..Default::default()
        };
        header.set_critical_l2_control(true);
        header.set_flow_shard(17);

        header.initialize(3, 4, PacketType::ForeignNetworkPacket as u8, 99);

        assert_eq!(header.from_peer_id.get(), 3);
        assert_eq!(header.to_peer_id.get(), 4);
        assert_eq!(header.packet_type, PacketType::ForeignNetworkPacket as u8);
        assert_eq!(header.flags, 0);
        assert_eq!(header.forward_counter, 1);
        assert!(!header.is_critical_l2_control());
        assert_eq!(header.flow_shard(), None);
        assert_eq!(header.len.get(), 99);
    }

    #[test]
    fn stable_auth_data_has_canonical_endian_and_mutability_fields() {
        let mut header = PeerManagerHeader::default();
        header.initialize(
            0x0102_0304,
            0xa0b0_c0d0,
            PacketType::Data as u8,
            0x1122_3344,
        );
        header.flags = 0xff;
        header.forward_counter = 9;
        header.set_flow_shard(17);
        header.set_critical_l2_control(true);

        let data = header.stable_auth_data();
        assert_eq!(&data[..4], b"ETAD");
        assert_eq!(&data[4..8], &[1, 2, 3, 4]);
        assert_eq!(&data[8..12], &[0xa0, 0xb0, 0xc0, 0xd0]);
        assert_eq!(data[12], PacketType::Data as u8);
        assert_eq!(data[13], 0xdc);
        assert_eq!(data[14], 0x80 | 0x40 | 17);
        assert_eq!(&data[15..19], &[0x11, 0x22, 0x33, 0x44]);

        header.forward_counter = 1;
        header.set_encrypted(true);
        header.set_latency_first(false).set_speed_first(false);
        assert_eq!(header.stable_auth_data(), data);
    }

    fn foreign_packet_for_parser_test() -> ZCPacket {
        let mut inner = ZCPacket::new_with_payload(b"inner");
        inner.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut outer = ZCPacket::new_for_foreign_network("network", 2, &inner);
        outer.fill_peer_manager_hdr(3, 4, PacketType::ForeignNetworkPacket as u8);
        outer
    }

    #[test]
    fn foreign_packet_rejects_a_name_range_outside_the_header() {
        let mut packet = foreign_packet_for_parser_test();
        let header = ForeignNetworkPacketHeader::mut_from_prefix(packet.mut_payload()).unwrap();
        header.network_name_len.set(u16::MAX);

        assert!(packet.foreign_network_hdr().is_none());
        assert!(packet.foreign_network_inner_packet_type().is_none());
        assert!(packet.foreign_network_packet().is_none());
    }

    #[test]
    fn foreign_packet_rejects_a_short_or_oversized_header() {
        for header_len in [1, u16::MAX] {
            let mut packet = foreign_packet_for_parser_test();
            let header = ForeignNetworkPacketHeader::mut_from_prefix(packet.mut_payload()).unwrap();
            header.header_len.set(header_len);

            assert!(packet.foreign_network_hdr().is_none());
            assert!(packet.foreign_network_inner_packet_type().is_none());
            assert!(packet.foreign_network_packet().is_none());
        }
    }

    #[test]
    fn foreign_packet_rejects_invalid_utf8_network_name() {
        let mut packet = foreign_packet_for_parser_test();
        let name_offset = packet
            .foreign_network_hdr()
            .unwrap()
            .network_name_offset
            .get() as usize;
        packet.mut_payload()[name_offset] = 0xff;

        let header = packet.foreign_network_hdr().unwrap();
        assert!(header.get_network_name(packet.payload()).is_none());
    }

    #[test]
    fn speed_first_flag_is_independent_from_latency_first() {
        let mut header = PeerManagerHeader::default();

        header.set_speed_first(true);

        assert!(header.is_speed_first());
        assert!(!header.is_latency_first());

        header.set_speed_first(false);

        assert!(!header.is_speed_first());
        assert!(!header.is_latency_first());
    }

    #[test]
    fn alternate_fec_records_use_the_lossy_datagram_lane() {
        for packet_type in [
            PacketType::AlternateFecSource,
            PacketType::AlternateFecParity,
        ] {
            let mut packet = ZCPacket::new_with_payload(b"fec");
            packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
            assert!(packet.is_lossy());
        }
    }

    #[test]
    fn lossy_hint_survives_tunnel_type_conversion() {
        let mut packet = ZCPacket::new_with_payload(b"protected data");
        packet.set_lossy_hint(true);

        let packet = packet.convert_type(ZCPacketType::DummyTunnel);
        let packet = packet.convert_type(ZCPacketType::UDP);

        assert!(packet.is_lossy());
    }

    #[test]
    fn in_place_dummy_conversion_keeps_the_packet_allocation() {
        let mut packet = ZCPacket::new_with_payload(b"protected data");
        let original_pointer = packet.tunnel_payload().as_ptr();

        packet
            .convert_type_in_place(ZCPacketType::DummyTunnel)
            .unwrap();

        assert_eq!(packet.tunnel_payload().as_ptr(), original_pointer);
        assert_eq!(packet.payload(), b"protected data");
    }

    #[test]
    fn authenticated_peer_identity_is_immutable_and_survives_local_conversion() {
        let mut packet = ZCPacket::new_with_payload(b"authenticated data");
        let session_id = uuid::Uuid::new_v4();
        let other_session_id = uuid::Uuid::new_v4();

        assert!(packet.set_authenticated_peer_id(7));
        assert!(packet.set_authenticated_peer_id(7));
        assert!(!packet.set_authenticated_peer_id(8));
        assert!(packet.set_authenticated_peer_identity_type(PeerIdentityType::Admin));
        assert!(packet.set_authenticated_peer_identity_type(PeerIdentityType::Admin));
        assert!(!packet.set_authenticated_peer_identity_type(PeerIdentityType::Credential));
        assert!(packet.set_authenticated_session_id(session_id));
        assert!(packet.set_authenticated_session_id(session_id));
        assert!(!packet.set_authenticated_session_id(other_session_id));

        let packet = packet.convert_type(ZCPacketType::DummyTunnel);
        let cloned = packet.clone();

        assert_eq!(packet.authenticated_peer_id(), Some(7));
        assert_eq!(cloned.authenticated_peer_id(), Some(7));
        assert_eq!(packet.authenticated_session_id(), Some(session_id));
        assert_eq!(cloned.authenticated_session_id(), Some(session_id));
        assert_eq!(
            packet.authenticated_peer_identity_type(),
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(
            cloned.authenticated_peer_identity_type(),
            Some(PeerIdentityType::Admin)
        );
    }

    #[test]
    fn verified_origin_stores_complete_authenticated_tuple() {
        let mut packet = ZCPacket::new_with_payload(b"origin");
        let session_id = uuid::Uuid::new_v4();

        assert!(packet.set_verified_origin(
            9,
            PeerIdentityType::Admin,
            SecureAuthLevel::PeerVerified,
            session_id,
        ));
        assert_eq!(packet.verified_origin_peer_id(), Some(9));
        assert_eq!(
            packet.logical_authenticated_peer_identity_type(),
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(
            packet.verified_origin_peer_secure_auth_level(),
            Some(SecureAuthLevel::PeerVerified)
        );
        assert_eq!(packet.logical_authenticated_session_id(), Some(session_id));
    }

    #[test]
    fn missing_origin_assurance_never_falls_back_to_hop_assurance() {
        let mut packet = ZCPacket::new_with_payload(b"origin");
        packet.authenticated_peer_secure_auth_level = Some(SecureAuthLevel::NetworkSecretConfirmed);
        packet.verified_origin_peer_id = Some(9);
        packet.verified_origin_peer_identity_type = Some(PeerIdentityType::Admin);
        packet.verified_origin_session_id = Some(uuid::Uuid::new_v4());

        assert_eq!(packet.logical_authenticated_peer_secure_auth_level(), None);
    }

    #[test]
    fn verified_origin_assurance_survives_clone_conversion_and_clear() {
        let mut packet = ZCPacket::new_with_payload(b"origin");
        let session_id = uuid::Uuid::new_v4();
        assert!(packet.set_verified_origin(
            9,
            PeerIdentityType::Credential,
            SecureAuthLevel::PeerVerified,
            session_id,
        ));

        let converted = packet.convert_type(ZCPacketType::DummyTunnel);
        let cloned = converted.clone();
        for candidate in [&converted, &cloned] {
            assert_eq!(candidate.verified_origin_peer_id(), Some(9));
            assert_eq!(
                candidate.verified_origin_peer_secure_auth_level(),
                Some(SecureAuthLevel::PeerVerified)
            );
            assert_eq!(
                candidate.logical_authenticated_session_id(),
                Some(session_id)
            );
        }

        let mut cleared = cloned;
        cleared.clear_authenticated_peer_id();
        assert_eq!(cleared.verified_origin_peer_id(), None);
        assert_eq!(cleared.verified_origin_peer_secure_auth_level(), None);
        assert_eq!(cleared.logical_authenticated_peer_secure_auth_level(), None);
    }

    #[test]
    fn verified_admin_origin_does_not_borrow_weak_hop_assurance() {
        let mut packet = ZCPacket::new_with_payload(b"origin");
        packet.authenticated_peer_secure_auth_level =
            Some(SecureAuthLevel::EncryptedUnauthenticated);
        assert!(packet.set_verified_origin(
            9,
            PeerIdentityType::Admin,
            SecureAuthLevel::PeerVerified,
            uuid::Uuid::new_v4(),
        ));

        assert_eq!(
            packet.logical_authenticated_peer_secure_auth_level(),
            Some(SecureAuthLevel::PeerVerified)
        );
    }

    #[test]
    fn weak_origin_does_not_borrow_verified_hop_assurance() {
        let mut packet = ZCPacket::new_with_payload(b"origin");
        packet.authenticated_peer_secure_auth_level = Some(SecureAuthLevel::NetworkSecretConfirmed);
        assert!(packet.set_verified_origin(
            9,
            PeerIdentityType::SharedNode,
            SecureAuthLevel::EncryptedUnauthenticated,
            uuid::Uuid::new_v4(),
        ));

        assert_eq!(
            packet.logical_authenticated_peer_secure_auth_level(),
            Some(SecureAuthLevel::EncryptedUnauthenticated)
        );
    }

    #[test]
    fn removes_payload_prefix_without_moving_the_ip_packet() {
        let mut packet = ZCPacket::new_with_payload(b"ethernet-headerpayload");
        let original_pointer = packet.inner.as_ptr();

        packet.remove_payload_prefix(15).unwrap();

        assert_eq!(packet.payload(), b"payload");
        assert_eq!(packet.inner.as_ptr(), original_pointer.wrapping_add(15));
    }

    #[test]
    fn pooled_prefix_restore_keeps_the_ip_pointer() {
        let pool = ReusableBufferPool::new(256, 1);
        let mut buffer = pool.try_take().unwrap();
        let payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        let ethernet_header = [0xabu8; crate::instance::l2_tun::ETHERNET_HEADER_LEN];
        let ip_payload = [0xcdu8; 20];
        buffer.truncate(
            payload_offset + crate::instance::l2_tun::ETHERNET_HEADER_LEN + ip_payload.len(),
        );
        let mut packet = ZCPacket::new_from_reusable_buf(buffer, ZCPacketType::NIC, pool.clone());
        packet.mut_payload()[..ethernet_header.len()].copy_from_slice(&ethernet_header);
        packet.mut_payload()[ethernet_header.len()..].copy_from_slice(&ip_payload);
        let original_ip_pointer = packet
            .payload()
            .as_ptr()
            .wrapping_add(ethernet_header.len());

        packet
            .remove_payload_prefix_preserving_flow_hash(ethernet_header.len())
            .unwrap();
        assert_eq!(packet.payload().as_ptr(), original_ip_pointer);
        assert!(packet.restore_payload_prefix_from_reusable_headroom(&ethernet_header));
        assert_eq!(
            packet
                .payload()
                .as_ptr()
                .wrapping_add(ethernet_header.len()),
            original_ip_pointer
        );
        assert_eq!(&packet.payload()[..ethernet_header.len()], &ethernet_header);
        assert_eq!(&packet.payload()[ethernet_header.len()..], &ip_payload);
    }

    #[test]
    fn prepends_payload_without_allocation_when_tail_space_exists() {
        let mut packet = ZCPacket::new_with_payload(b"payload");
        packet.inner.reserve(15);
        let original_capacity = packet.inner.capacity();

        packet.prepend_payload(b"ethernet-header").unwrap();
        assert_eq!(packet.payload(), b"ethernet-headerpayload");
        assert_eq!(packet.inner.capacity(), original_capacity);
    }

    #[test]
    fn appends_and_removes_payload_suffix_without_moving_the_packet() {
        let mut packet = ZCPacket::new_with_payload(b"payload");
        packet.inner.reserve(6);
        let original_pointer = packet.inner.as_ptr();

        packet.append_payload(b"-proof").unwrap();
        assert_eq!(packet.payload(), b"payload-proof");
        assert_eq!(packet.inner.as_ptr(), original_pointer);

        packet.remove_payload_suffix(6).unwrap();
        assert_eq!(packet.payload(), b"payload");
        assert_eq!(packet.inner.as_ptr(), original_pointer);
    }

    #[test]
    fn removed_payload_prefix_keeps_the_peer_header_writable() {
        let mut packet = ZCPacket::new_with_payload(b"ethernet-headerpayload");

        packet.remove_payload_prefix(15).unwrap();
        packet.fill_peer_manager_hdr(7, 9, PacketType::Data as u8);

        assert_eq!(packet.payload(), b"payload");
        let header = packet.peer_manager_header().unwrap();
        assert_eq!(header.from_peer_id.get(), 7);
        assert_eq!(header.to_peer_id.get(), 9);
        assert_eq!(header.len.get(), 7);
    }
}
