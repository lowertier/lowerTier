use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{Sink, stream::FuturesUnordered};
use hmac::{Hmac, Mac};
use rand::{Rng, SeedableRng};
use sha2::Sha256;
use smallvec::SmallVec;
use zerocopy::{AsBytes, FromBytes};

use std::sync::atomic::{AtomicBool, Ordering};
use tokio::{
    net::UdpSocket,
    sync::{
        OwnedSemaphorePermit, Semaphore,
        mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel},
    },
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{
    FromUrl, IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelInfo, TunnelListener,
    TunnelUrl,
    common::wait_for_connect_futures,
    packet_def::{UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, V4HolePunchPacket, V6HolePunchPacket},
    ring::{RingSink, RingStream},
};
use crate::tunnel::common::{
    bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
};
use crate::{
    common::{
        join_joinset_background, shrink_dashmap,
        stun::{StunPacket, is_stun_binding_success},
        underlay_policy::UnderlayPolicy,
    },
    tunnel::{
        batch::{IO_FLUSH_PACKET_BUDGET, PacketBatch, ScalarToBatchStream},
        build_url_from_socket_addr,
        common::BatchTunnelWrapper,
        packet_def::{UdpPacketType, ZCPacket, ZCPacketType},
        ring::RingTunnel,
        udp_src,
    },
};

pub const UDP_DATA_MTU: usize = 2000;
const UDP_LISTENER_CONNECTION_CAPACITY: usize = 32;
const UDP_CONTROL_TASK_CAPACITY: usize = 32;
const UDP_RING_PACKET_CAPACITY: usize = crate::tunnel::batch::MAX_PACKET_BATCH_SIZE * 2;
const UDP_CONTROL_PACKET_RESERVE: usize = IO_FLUSH_PACKET_BUDGET;
const UDP_SYN_COOKIE_LEN: usize = 16;
const UDP_SYN_COOKIE_TAG_LEN: usize = 8;
const UDP_SYN_COOKIE_BUCKET_SECONDS: u64 = 30;

type UdpCloseEventSender = UnboundedSender<(SocketAddr, u32, Option<TunnelError>)>;
type UdpCloseEventReceiver = UnboundedReceiver<(SocketAddr, u32, Option<TunnelError>)>;

struct UdpConnectionAdmission {
    _permit: OwnedSemaphorePermit,
}

struct UdpConnectionState {
    closed: AtomicBool,
}

impl UdpConnectionState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
        }
    }

    fn is_replaceable(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferredIpv6Source {
    pub ip: Ipv6Addr,
    pub ifindex: u32,
}

fn new_udp_packet<F>(f: F, udp_body: Option<&[u8]>) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(
        UDP_TUNNEL_HEADER_SIZE + udp_body.as_ref().map(|v| v.len()).unwrap_or(0),
        0,
    );
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body.unwrap());

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&magic.to_le_bytes()),
    )
}

fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&magic.to_le_bytes()),
    )
}

fn new_syn_cookie_packet(conn_id: u32, magic: u64, tag: [u8; UDP_SYN_COOKIE_TAG_LEN]) -> ZCPacket {
    let mut payload = [0_u8; UDP_SYN_COOKIE_LEN];
    payload[..8].copy_from_slice(&magic.to_le_bytes());
    payload[8..].copy_from_slice(&tag);
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(UDP_SYN_COOKIE_LEN as u16);
        },
        Some(&payload),
    )
}

fn new_syn_cookie_challenge(
    conn_id: u32,
    magic: u64,
    tag: [u8; UDP_SYN_COOKIE_TAG_LEN],
) -> ZCPacket {
    let mut packet = new_syn_cookie_packet(conn_id, magic, tag);
    packet.mut_udp_tunnel_header().unwrap().msg_type = UdpPacketType::Sack as u8;
    packet
}

pub fn new_hole_punch_packet(tid: u32, buf_len: u16) -> ZCPacket {
    // generate a 128 bytes vec with random data
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut buf = vec![0u8; buf_len as usize];
    rng.fill(&mut buf[..]);
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::HolePunch as u8;
            header.conn_id.set(tid);
            header.len.set(buf_len);
        },
        Some(&buf),
    )
}

pub fn new_authenticated_hole_punch_packet(tid: u32, token: &[u8; 16]) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::HolePunch as u8;
            header.conn_id.set(tid);
            header.len.set(token.len() as u16);
        },
        Some(token),
    )
}

pub fn new_v6_hole_punch_packet(
    dst: &SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> ZCPacket {
    // generate a 128 bytes vec with random data
    let mut body = V6HolePunchPacket::default();
    body.dst_ipv6.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    if let Some(src) = preferred_src {
        body.preferred_src_ipv6.copy_from_slice(&src.ip.octets());
        body.preferred_src_ifindex.set(src.ifindex);
    }
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V6HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V6HolePunchPacket>() as u16);
        },
        Some(body.as_bytes()),
    )
}

pub fn new_v4_hole_punch_packet(dst: &SocketAddrV4) -> ZCPacket {
    let mut body = V4HolePunchPacket::default();
    body.dst_ipv4.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V4HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V4HolePunchPacket>() as u16);
        },
        Some(body.as_bytes()),
    )
}

fn extract_dst_addr_from_v4_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV4> {
    let body = V4HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv4Addr::from(body.dst_ipv4);
    Some(SocketAddrV4::new(ip, body.dst_port.get()))
}

fn extract_v6_hole_punch_packet(buf: &[u8]) -> Option<(SocketAddrV6, Option<PreferredIpv6Source>)> {
    let body = V6HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv6Addr::from(body.dst_ipv6);
    let preferred_src_ipv6 = Ipv6Addr::from(body.preferred_src_ipv6);
    let preferred_src = (!preferred_src_ipv6.is_unspecified()).then_some(PreferredIpv6Source {
        ip: preferred_src_ipv6,
        ifindex: body.preferred_src_ifindex.get(),
    });
    Some((
        SocketAddrV6::new(ip, body.dst_port.get(), 0, 0),
        preferred_src,
    ))
}

fn is_stun_packet(b: &[u8]) -> bool {
    // stun has following pattern:
    // 1. first two bits are 0b00
    // 2. magic cookie between 32-64 bits: 0x2112A442
    b[4..8] == [0x21, 0x12, 0xA4, 0x42] && b[0] & 0xC0 == 0
}

pub async fn send_v6_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("[::1]:0").await?;
    let udp_packet = new_v6_hole_punch_packet(&dst_addr, preferred_src);
    let remote_addr = format!("[::1]:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

pub async fn send_v4_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV4,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_packet = new_v4_hole_punch_packet(&dst_addr);
    let remote_addr = format!("127.0.0.1:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

fn stun_response_bind_addr(
    policy: &UnderlayPolicy,
    listener_local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<Option<SocketAddr>, TunnelError> {
    ensure_remote_allowed(policy, remote_addr)?;
    if !policy.is_active() {
        return Ok(None);
    }
    if listener_local_addr.ip().is_unspecified() {
        return Err(TunnelError::UnderlayPolicyDenied(format!(
            "cannot prove the local source for STUN listener {listener_local_addr}"
        )));
    }
    ensure_local_allowed(policy, listener_local_addr)?;
    Ok(Some(SocketAddr::new(listener_local_addr.ip(), 0)))
}

async fn respond_stun_packet(
    socket: Arc<UdpSocket>,
    send_gate: Arc<tokio::sync::Mutex<()>>,
    addr: SocketAddr,
    req_buf: Vec<u8>,
    underlay_policy: Arc<UnderlayPolicy>,
    socket_mark: Option<u32>,
) -> Result<(), anyhow::Error> {
    use crate::common::stun_codec_ext::*;
    use bytecodec::{DecodeExt as _, EncodeExt as _};
    use stun_codec::{
        Message, MessageClass, MessageDecoder, MessageEncoder,
        rfc5389::{attributes::XorMappedAddress, methods::BINDING},
    };

    let mut decoder = MessageDecoder::<Attribute>::new();
    let req_msg = decoder
        .decode_from_bytes(&req_buf)
        .map_err(|e| anyhow::anyhow!("stun decode error: {:?}", e))?
        .map_err(|e| anyhow::anyhow!("stun decode broken message error: {:?}", e))?;

    let tid = req_msg.transaction_id();
    // we only respond lowertier stun req, whose tid has 0xdeadbeef prefix
    if tid.as_bytes()[0..4] != [0xde, 0xad, 0xbe, 0xef] {
        anyhow::bail!("stun req tid not from lowertier");
    }

    let mut resp_msg = Message::<Attribute>::new(
        MessageClass::SuccessResponse,
        BINDING,
        // we discard the prefix, make sure our implementation is not compatible with other stun client
        u32_to_tid(tid_to_u32(&tid)),
    );
    resp_msg.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

    let mut encoder = MessageEncoder::new();
    let rsp_buf = encoder
        .encode_into_bytes(resp_msg.clone())
        .map_err(|e| anyhow::anyhow!("stun encode error: {:?}", e))?;

    let change_req = req_msg
        .get_attribute::<ChangeRequest>()
        .map(|r| r.ip() || r.port())
        .unwrap_or(false);
    let strict_bind_addr = stun_response_bind_addr(&underlay_policy, socket.local_addr()?, addr)?;

    if !change_req {
        let _send_guard = send_gate.lock().await;
        socket
            .send_to(&rsp_buf, addr)
            .await
            .with_context(|| "send stun response error")?;
    } else {
        // send from a new udp socket
        let bind_addr = if let Some(bind_addr) = strict_bind_addr {
            bind_addr
        } else if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket: UdpSocket = bind()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(socket_mark)
            .call()?;
        socket.send_to(&rsp_buf, addr).await?;
    }

    tracing::debug!(?addr, ?req_msg, ?change_req, "udp respond stun packet done");
    Ok(())
}

fn get_zcpacket_from_buf(
    buf: BytesMut,
    reusable_pool: Option<crate::tunnel::packet_def::ReusableBufferPool>,
    allow_stun: bool,
) -> Result<ZCPacket, TunnelError> {
    let dg_size = buf.len();
    let is_stun = allow_stun
        && dg_size >= UDP_TUNNEL_HEADER_SIZE
        && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]);
    let mut packet = if let Some(pool) = reusable_pool {
        ZCPacket::new_from_reusable_buf(buf, ZCPacketType::UDP, pool)
    } else {
        ZCPacket::new_from_buf(buf, ZCPacketType::UDP)
    };
    if dg_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "udp packet size too small: {:?}, packet: {:?}",
            dg_size, packet
        )));
    }

    if is_stun {
        return Ok(packet);
    }

    let header = packet.udp_tunnel_header().unwrap();
    if header.msg_type == UdpPacketType::Data as u8 {
        let payload_len = header.len.get() as usize;
        if payload_len != dg_size - UDP_TUNNEL_HEADER_SIZE {
            return Err(TunnelError::InvalidPacket(format!(
                "udp packet payload len not match: header len: {:?}, real len: {:?}",
                payload_len,
                dg_size - UDP_TUNNEL_HEADER_SIZE
            )));
        }
    } else {
        packet.set_lossy_hint(header.padding & 1 != 0);
    }
    Ok(packet)
}

fn prepare_udp_data_packet(packet: ZCPacket, conn_id: u32) -> ZCPacket {
    let protected_lossy = packet.is_lossy();
    let protected_mask = (packet.packet_type() == ZCPacketType::DummyTunnel
        && packet.tunnel_payload().len() >= 20)
        .then(|| {
            let mut mask = [0_u8; 4];
            mask.copy_from_slice(&packet.tunnel_payload()[16..20]);
            mask
        });
    let mut packet = packet.convert_type(ZCPacketType::UDP);
    let udp_payload_len = packet.udp_payload().len();
    let header = packet.mut_udp_tunnel_header().unwrap();
    header.conn_id.set(conn_id);
    if let Some(mask) = protected_mask {
        header.msg_type = if mask[0] == UdpPacketType::Data as u8 {
            mask[0] ^ 0x80
        } else {
            mask[0]
        };
        header.padding = (mask[1] & !1) | u8::from(protected_lossy);
        header.len.set(u16::from_le_bytes([mask[2], mask[3]]));
    } else {
        header.len.set(udp_payload_len as u16);
        header.msg_type = UdpPacketType::Data as u8;
        header.padding = 0;
    }
    packet
}

struct UdpBatchSink {
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    conn_id: u32,
    pending: Option<SmallVec<[bytes::Bytes; 4]>>,
    spare: SmallVec<[bytes::Bytes; 4]>,
    completed: usize,
    close_event_sender: Option<UdpCloseEventSender>,
    _admission: Option<Arc<UdpConnectionAdmission>>,
    connection_state: Arc<UdpConnectionState>,
}

impl UdpBatchSink {
    fn new(
        socket: Arc<UdpSocket>,
        destination: SocketAddr,
        conn_id: u32,
        close_event_sender: UdpCloseEventSender,
        admission: Option<Arc<UdpConnectionAdmission>>,
        connection_state: Arc<UdpConnectionState>,
    ) -> Self {
        Self {
            socket,
            destination,
            conn_id,
            pending: None,
            spare: SmallVec::new(),
            completed: 0,
            close_event_sender: Some(close_event_sender),
            _admission: admission,
            connection_state,
        }
    }

    fn notify_close(&mut self, error: Option<TunnelError>) {
        self.connection_state.closed.store(true, Ordering::Release);
        if let Some(sender) = self.close_event_sender.take() {
            let _ = sender.send((self.destination, self.conn_id, error));
        }
    }

    fn poll_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), TunnelError>> {
        let Self {
            socket,
            destination,
            pending,
            completed,
            ..
        } = self;
        let Some(buffers) = pending.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        match super::udp_vector_io::poll_send_batch(socket, *destination, buffers, completed, cx) {
            Poll::Ready(Ok(())) => {
                let mut buffers = self
                    .pending
                    .take()
                    .expect("the completed UDP send has pending buffers");
                buffers.clear();
                self.spare = buffers;
                self.completed = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                let message = error.to_string();
                let mut buffers = self
                    .pending
                    .take()
                    .expect("the failed UDP send has pending buffers");
                buffers.clear();
                self.spare = buffers;
                self.completed = 0;
                self.notify_close(Some(TunnelError::InternalError(message)));
                Poll::Ready(Err(TunnelError::IOError(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<PacketBatch> for UdpBatchSink {
    type Error = TunnelError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_pending(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(TunnelError::InternalError(
                "UDP batch sink received data before readiness".to_string(),
            ));
        }
        let mut buffers = std::mem::take(&mut self.spare);
        buffers.clear();
        buffers.reserve(batch.len());
        for packet in batch {
            buffers.push(prepare_udp_data_packet(packet, self.conn_id).into_bytes());
        }
        self.pending = Some(buffers);
        self.completed = 0;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_pending(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.poll_pending(cx) {
            Poll::Ready(Ok(())) => {
                self.notify_close(None);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl Drop for UdpBatchSink {
    fn drop(&mut self) {
        self.notify_close(None);
    }
}

async fn udp_recv_from_socket_forward_task(
    socket: &UdpSocket,
    receiver: &mut super::udp_vector_io::UdpBatchReceiver,
    allow_stun: bool,
) -> Result<SmallVec<[(ZCPacket, SocketAddr); 4]>, TunnelError> {
    loop {
        let datagrams = receiver.recv_batch(socket, UDP_DATA_MTU).await?;
        let mut packets = SmallVec::with_capacity(datagrams.len());
        for datagram in datagrams {
            tracing::trace!(
                addr = ?datagram.source,
                size = datagram.buffer.len(),
                "udp recv packet batch entry"
            );
            match get_zcpacket_from_buf(datagram.buffer, datagram.reusable_pool, allow_stun) {
                Ok(packet) => packets.push((packet, datagram.source)),
                Err(error) => {
                    tracing::warn!(?error, "udp get zc packet from batch entry error");
                }
            }
        }
        if !packets.is_empty() {
            return Ok(packets);
        }
    }
}

struct UdpConnection {
    conn_id: u32,
    ring_sender: RingSink,
    _admission: Option<Arc<UdpConnectionAdmission>>,
    state: Arc<UdpConnectionState>,
}

#[cfg(test)]
struct UdpRingBatchSink {
    inner: RingSink,
    pending: Option<PacketBatch>,
}

#[cfg(test)]
impl UdpRingBatchSink {
    fn new(inner: RingSink) -> Self {
        Self {
            inner,
            pending: None,
        }
    }

    fn pending_run(&self) -> Option<(usize, bool)> {
        let batch = self.pending.as_ref()?;
        let lossy = batch[0].is_lossy();
        let run_len = batch
            .iter()
            .take_while(|packet| packet.is_lossy() == lossy)
            .count();
        Some((run_len, lossy))
    }

    fn take_pending_run(&mut self, run_len: usize) -> PacketBatch {
        let pending = self
            .pending
            .as_mut()
            .expect("a pending reliability run has a packet batch");
        if run_len == pending.len() {
            return self
                .pending
                .take()
                .expect("the complete pending packet batch exists");
        }
        let remainder = pending.split_off(run_len);
        std::mem::replace(pending, remainder)
    }

    fn poll_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), TunnelError>> {
        while let Some((run_len, lossy)) = self.pending_run() {
            let reserve = if lossy { UDP_CONTROL_PACKET_RESERVE } else { 0 };
            std::task::ready!(self.inner.poll_reserve_batch(cx, run_len, reserve))?;
            let run = self.take_pending_run(run_len);
            self.inner.start_send_reserved_batch(run)?;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
impl Sink<PacketBatch> for UdpRingBatchSink {
    type Error = TunnelError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_pending(cx)
    }

    fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        let self_mut = self.get_mut();
        if self_mut.pending.is_some() {
            return Err(TunnelError::InternalError(
                "UDP ring batch sink received data before readiness".to_owned(),
            ));
        }
        if !batch.is_empty() {
            self_mut.pending = Some(batch);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        std::task::ready!(self_mut.poll_pending(cx))?;
        <RingSink as Sink<ZCPacket>>::poll_flush(Pin::new(&mut self_mut.inner), cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        std::task::ready!(self_mut.poll_pending(cx))?;
        <RingSink as Sink<ZCPacket>>::poll_close(Pin::new(&mut self_mut.inner), cx)
    }
}

fn admit_udp_ring_batch(ring_sender: &mut RingSink, batch: PacketBatch) -> Result<(), TunnelError> {
    let all_lossy = batch.iter().all(ZCPacket::is_lossy);
    let any_lossy = batch.iter().any(ZCPacket::is_lossy);
    if all_lossy {
        return admit_udp_ring_run(ring_sender, batch, true);
    }
    if !any_lossy {
        return admit_udp_ring_run(ring_sender, batch, false);
    }

    let mut run = PacketBatch::with_capacity(1);
    let mut run_lossy = batch[0].is_lossy();
    for packet in batch {
        let packet_lossy = packet.is_lossy();
        if packet_lossy != run_lossy {
            admit_udp_ring_run(ring_sender, run, run_lossy)?;
            run = PacketBatch::with_capacity(1);
            run_lossy = packet_lossy;
        }
        run.try_push(packet)
            .expect("a UDP reliability run cannot exceed its input batch");
    }
    admit_udp_ring_run(ring_sender, run, run_lossy)
}

fn admit_udp_ring_run(
    ring_sender: &mut RingSink,
    batch: PacketBatch,
    lossy: bool,
) -> Result<(), TunnelError> {
    if !lossy {
        return ring_sender
            .force_send_batch(batch)
            .map_err(|_| TunnelError::BufferFull);
    }

    let batch_len = batch.len();
    let admitted = ring_sender.try_send_batch_lossy_with_reserve(batch, UDP_CONTROL_PACKET_RESERVE);
    if admitted != batch_len {
        tracing::trace!(
            admitted,
            dropped = batch_len - admitted,
            "ring sender full, drop lossy packet overflow"
        );
    }
    Ok(())
}

impl UdpConnection {
    pub fn new(
        conn_id: u32,
        ring_sender: RingSink,
        admission: Option<Arc<UdpConnectionAdmission>>,
        state: Arc<UdpConnectionState>,
    ) -> Self {
        Self {
            conn_id,
            ring_sender,
            _admission: admission,
            state,
        }
    }

    pub fn handle_packet_from_remote(&mut self, zc_packet: ZCPacket) -> Result<(), TunnelError> {
        self.handle_packet_batch_from_remote(PacketBatch::singleton(zc_packet))
    }

    pub fn handle_packet_batch_from_remote(
        &mut self,
        batch: PacketBatch,
    ) -> Result<(), TunnelError> {
        for zc_packet in &batch {
            let header = zc_packet.udp_tunnel_header().unwrap();
            let conn_id = header.conn_id.get();

            if self.conn_id != conn_id {
                return Err(TunnelError::ConnIdNotMatch(self.conn_id, conn_id));
            }
        }
        admit_udp_ring_batch(&mut self.ring_sender, batch)
    }
}

#[derive(Clone)]
struct UdpTunnelListenerData {
    local_url: url::Url,
    socket: Option<Arc<UdpSocket>>,
    send_gate: Arc<tokio::sync::Mutex<()>>,
    sock_map: Arc<DashMap<SocketAddr, UdpConnection>>,
    conn_send: Sender<Box<dyn Tunnel>>,
    close_event_sender: UdpCloseEventSender,
    connection_admission: Arc<Semaphore>,
    control_task_admission: Arc<Semaphore>,
    syn_cookie_secret: Arc<[u8; 32]>,
    underlay_policy: Arc<UnderlayPolicy>,
    socket_mark: Option<u32>,
    stun_packet_sender: tokio::sync::broadcast::Sender<StunPacket>,
}

impl UdpTunnelListenerData {
    pub fn new(
        local_url: url::Url,
        conn_send: Sender<Box<dyn Tunnel>>,
        close_event_sender: UdpCloseEventSender,
    ) -> Self {
        let (stun_packet_sender, _) = tokio::sync::broadcast::channel(64);
        let mut syn_cookie_secret = [0_u8; 32];
        rand::rngs::OsRng.fill(&mut syn_cookie_secret);
        Self {
            local_url,
            socket: None,
            send_gate: Arc::new(tokio::sync::Mutex::new(())),
            sock_map: Arc::new(DashMap::new()),
            conn_send,
            close_event_sender,
            connection_admission: Arc::new(Semaphore::new(UDP_LISTENER_CONNECTION_CAPACITY)),
            control_task_admission: Arc::new(Semaphore::new(UDP_CONTROL_TASK_CAPACITY)),
            syn_cookie_secret: Arc::new(syn_cookie_secret),
            underlay_policy: Arc::new(UnderlayPolicy::default()),
            socket_mark: None,
            stun_packet_sender,
        }
    }

    async fn send_control(
        &self,
        socket: &UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> std::io::Result<usize> {
        let _send_guard = self.send_gate.lock().await;
        socket.send_to(payload, destination).await
    }

    fn syn_cookie_bucket() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / UDP_SYN_COOKIE_BUCKET_SECONDS
    }

    fn syn_cookie_tag_for_bucket(
        &self,
        remote_addr: SocketAddr,
        conn_id: u32,
        magic: u64,
        bucket: u64,
    ) -> [u8; UDP_SYN_COOKIE_TAG_LEN] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.syn_cookie_secret.as_ref())
            .expect("the UDP SYN cookie key has a fixed valid length");
        match remote_addr {
            SocketAddr::V4(addr) => {
                mac.update(&[4]);
                mac.update(&addr.ip().octets());
                mac.update(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                mac.update(&[6]);
                mac.update(&addr.ip().octets());
                mac.update(&addr.port().to_be_bytes());
                mac.update(&addr.scope_id().to_be_bytes());
            }
        }
        mac.update(&conn_id.to_be_bytes());
        mac.update(&magic.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let mut tag = [0_u8; UDP_SYN_COOKIE_TAG_LEN];
        tag.copy_from_slice(&digest[..UDP_SYN_COOKIE_TAG_LEN]);
        tag
    }

    fn syn_cookie_tag(
        &self,
        remote_addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> [u8; UDP_SYN_COOKIE_TAG_LEN] {
        self.syn_cookie_tag_for_bucket(remote_addr, conn_id, magic, Self::syn_cookie_bucket())
    }

    fn syn_cookie_valid(
        &self,
        remote_addr: SocketAddr,
        conn_id: u32,
        magic: u64,
        supplied: &[u8],
    ) -> bool {
        if supplied.len() != UDP_SYN_COOKIE_TAG_LEN {
            return false;
        }
        let current = Self::syn_cookie_bucket();
        [current, current.saturating_sub(1)]
            .into_iter()
            .any(|bucket| {
                let expected = self.syn_cookie_tag_for_bucket(remote_addr, conn_id, magic, bucket);
                let mut difference = 0_u8;
                for (left, right) in expected.iter().zip(supplied) {
                    difference |= left ^ right;
                }
                difference == 0
            })
    }

    async fn handle_new_connect(
        self,
        remote_addr: SocketAddr,
        zc_packet: ZCPacket,
        admission_permit: OwnedSemaphorePermit,
    ) {
        let udp_payload = zc_packet.udp_payload();
        if udp_payload.len() != UDP_SYN_COOKIE_LEN {
            tracing::warn!(
                "udp syn packet payload len not match: {:?}, packet: {:?}",
                udp_payload.len(),
                zc_packet,
            );
            return;
        }
        let magic = u64::from_le_bytes(udp_payload[..8].try_into().unwrap());
        let conn_id = zc_packet.udp_tunnel_header().unwrap().conn_id.get();

        tracing::info!(?conn_id, ?remote_addr, "udp connection accept handling",);
        let socket = self.socket.as_ref().unwrap().clone();

        let sack_buf = new_sack_packet(conn_id, magic).into_bytes();
        if let Some(connection) = self.sock_map.get(&remote_addr) {
            if connection.conn_id == conn_id {
                if let Err(error) = self.send_control(&socket, &sack_buf, remote_addr).await {
                    tracing::error!(?error, "UDP resend SACK packet failed");
                }
                tracing::debug!(?conn_id, ?remote_addr, "UDP duplicate SYN resent SACK");
                return;
            } else if !connection.state.is_replaceable() {
                tracing::warn!(?remote_addr, "drop UDP SYN because the address is active");
                return;
            }
            let old_conn_id = connection.conn_id;
            drop(connection);
            self.sock_map.remove_if(&remote_addr, |_, connection| {
                connection.conn_id == old_conn_id
            });
        }

        let ring_for_recv_udp = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        tracing::debug!(?ring_for_recv_udp, "udp build tunnel for listener");

        let admission = Arc::new(UdpConnectionAdmission {
            _permit: admission_permit,
        });
        let connection_state = Arc::new(UdpConnectionState::new());
        let new_internal_conn = || {
            UdpConnection::new(
                conn_id,
                RingSink::new(ring_for_recv_udp.clone()),
                Some(admission.clone()),
                connection_state.clone(),
            )
        };
        let duplicate_syn = match self.sock_map.entry(remote_addr) {
            dashmap::mapref::entry::Entry::Occupied(_) => true,
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(new_internal_conn());
                false
            }
        };
        if duplicate_syn {
            if let Err(e) = self.send_control(&socket, &sack_buf, remote_addr).await {
                tracing::error!(?e, "udp resend sack packet error");
            }
            tracing::debug!(?conn_id, ?remote_addr, "udp duplicate syn, resent sack");
            return;
        }

        if let Err(e) = self.send_control(&socket, &sack_buf, remote_addr).await {
            self.sock_map
                .remove_if(&remote_addr, |_, conn| conn.conn_id == conn_id);
            tracing::error!(?e, "udp send sack packet error");
            return;
        }

        let udp_sink = UdpBatchSink::new(
            socket,
            remote_addr,
            conn_id,
            self.close_event_sender.clone(),
            Some(admission),
            connection_state,
        );
        let conn = Box::new(BatchTunnelWrapper::new(
            ScalarToBatchStream::new(RingStream::new(ring_for_recv_udp)),
            udp_sink,
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(self.local_url.clone().into()),
                remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
            }),
        ));

        tracing::info!(info = ?conn.info().unwrap().remote_addr, "udp connection accept done");

        if let Err(error) = self.conn_send.try_send(conn) {
            self.sock_map
                .remove_if(&remote_addr, |_, connection| connection.conn_id == conn_id);
            tracing::warn!(?error, "drop UDP connection because accept ingress is full");
        }
    }

    fn do_forward_one_packet_to_conn(&self, zc_packet: ZCPacket, addr: SocketAddr) {
        if let Err(error) = ensure_remote_allowed(&self.underlay_policy, addr) {
            tracing::warn!(?addr, ?error, "drop UDP packet denied by underlay policy");
            return;
        }
        let header = zc_packet.udp_tunnel_header().unwrap();
        let conn_id = header.conn_id.get();
        let looks_like_syn = header.msg_type == UdpPacketType::Syn as u8
            && header.len.get() == 8
            && zc_packet.udp_payload().len() == 8;
        if !looks_like_syn
            && let Some(mut conn) = self.sock_map.get_mut(&addr)
            && conn.conn_id == conn_id
        {
            if let Err(error) = conn.handle_packet_from_remote(zc_packet) {
                tracing::trace!(?error, "udp forward packet error");
            }
            return;
        }

        if header.msg_type == UdpPacketType::Syn as u8 {
            let payload = zc_packet.udp_payload();
            if payload.len() == 8 {
                let magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
                let challenge = new_syn_cookie_challenge(
                    conn_id,
                    magic,
                    self.syn_cookie_tag(addr, conn_id, magic),
                )
                .into_bytes();
                let socket = self.socket.as_ref().unwrap().clone();
                let send_gate = self.send_gate.clone();
                let Ok(task_permit) = self.control_task_admission.clone().try_acquire_owned()
                else {
                    tracing::warn!(?addr, "drop UDP SYN challenge because admission is full");
                    return;
                };
                tokio::spawn(async move {
                    let _task_permit = task_permit;
                    let _send_guard = send_gate.lock().await;
                    if let Err(error) = socket.send_to(&challenge, addr).await {
                        tracing::debug!(?addr, ?error, "UDP SYN challenge send failed");
                    }
                });
                return;
            }
            if payload.len() != UDP_SYN_COOKIE_LEN {
                tracing::warn!(?addr, "drop UDP SYN with an invalid cookie length");
                return;
            }
            let magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
            if !self.syn_cookie_valid(addr, conn_id, magic, &payload[8..]) {
                tracing::warn!(?addr, "drop UDP SYN with an invalid cookie");
                return;
            }
            let Ok(admission_permit) = self.connection_admission.clone().try_acquire_owned() else {
                tracing::warn!(?addr, "drop UDP connection because admission is full");
                return;
            };
            tokio::spawn(Self::handle_new_connect(
                self.clone(),
                addr,
                zc_packet,
                admission_permit,
            ));
        } else if is_stun_packet(header.as_bytes()) {
            let raw = zc_packet.inner().to_vec();
            if is_stun_binding_success(&raw) {
                let _ = self.stun_packet_sender.send(StunPacket { data: raw, addr });
                return;
            }
            tracing::debug!("udp forward packet handle stun request");
            let socket = self.socket.as_ref().unwrap().clone();
            let underlay_policy = self.underlay_policy.clone();
            let socket_mark = self.socket_mark;
            let send_gate = self.send_gate.clone();
            let Ok(task_permit) = self.control_task_admission.clone().try_acquire_owned() else {
                tracing::warn!(?addr, "drop STUN request because admission is full");
                return;
            };
            tokio::spawn(async move {
                let _task_permit = task_permit;
                let ret =
                    respond_stun_packet(socket, send_gate, addr, raw, underlay_policy, socket_mark)
                        .await;
                if let Err(e) = ret {
                    tracing::error!(?e, "udp respond stun packet error");
                }
            });
        } else if header.msg_type == UdpPacketType::V4HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v4 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv4() {
                tracing::warn!(?addr, "v4 hole punch packet should be sent from ipv4");
                return;
            }
            let Some(dst_addr) =
                extract_dst_addr_from_v4_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v4 hole punch packet");
                return;
            };
            if let Err(error) =
                ensure_remote_allowed(&self.underlay_policy, SocketAddr::V4(dst_addr))
            {
                tracing::warn!(?dst_addr, ?error, "deny local v4 hole punch destination");
                return;
            }
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            if let Err(e) = socket.try_send_to(&udp_packet.into_bytes(), SocketAddr::V4(dst_addr)) {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(?dst_addr, "udp forward packet send hole punch packet");
        } else if header.msg_type == UdpPacketType::V6HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v6 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv6() {
                tracing::warn!(?addr, "v6 hole punch packet should be sent from ipv6");
                return;
            }
            let Some((dst_addr, preferred_src)) =
                extract_v6_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v6 hole punch packet");
                return;
            };
            if let Err(error) =
                ensure_remote_allowed(&self.underlay_policy, SocketAddr::V6(dst_addr))
            {
                tracing::warn!(?dst_addr, ?error, "deny local v6 hole punch destination");
                return;
            }
            if let Some(src) = preferred_src
                && let Err(error) = ensure_local_allowed(
                    &self.underlay_policy,
                    SocketAddr::V6(SocketAddrV6::new(src.ip, 0, 0, src.ifindex)),
                )
            {
                tracing::warn!(?src, ?error, "deny local v6 hole punch source");
                return;
            }
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            let udp_packet = udp_packet.into_bytes();
            let sent_with_src = if let Some(src) = preferred_src {
                match udp_src::send_to_with_src_ipv6(
                    &socket,
                    src.ip,
                    src.ifindex,
                    dst_addr,
                    &udp_packet,
                ) {
                    Ok(ret) => {
                        tracing::debug!(
                            ?src,
                            ?dst_addr,
                            ?ret,
                            "udp forward packet send hole punch packet with preferred ipv6 source"
                        );
                        true
                    }
                    Err(e) => {
                        tracing::debug!(
                            ?src,
                            ?dst_addr,
                            ?e,
                            "udp forward packet preferred ipv6 source failed, falling back"
                        );
                        false
                    }
                }
            } else {
                false
            };
            if !sent_with_src
                && let Err(e) = socket.try_send_to(&udp_packet, SocketAddr::V6(dst_addr))
            {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(
                ?dst_addr,
                ?preferred_src,
                "udp forward packet send hole punch packet"
            );
        } else if header.msg_type != UdpPacketType::HolePunch as u8 {
            let Some(mut conn) = self.sock_map.get_mut(&addr) else {
                tracing::trace!(?header, "udp forward packet error, connection not found");
                return;
            };
            if let Err(e) = conn.handle_packet_from_remote(zc_packet) {
                tracing::trace!(?e, "udp forward packet error");
            }
        } else {
            tracing::trace!(?header, "udp forward packet ignore hole punch packet");
        }
    }

    fn forward_existing_batch(&self, addr: SocketAddr, conn_id: u32, batch: PacketBatch) {
        let Some(mut connection) = self.sock_map.get_mut(&addr) else {
            return;
        };
        if connection.conn_id != conn_id {
            return;
        }
        if let Err(error) = connection.handle_packet_batch_from_remote(batch) {
            tracing::trace!(?error, "UDP batch forwarding failed");
        }
    }

    fn do_forward_packet_batch(&self, packets: SmallVec<[(ZCPacket, SocketAddr); 4]>) {
        let mut pending: Option<(SocketAddr, u32, PacketBatch)> = None;
        for (packet, addr) in packets {
            if let Err(error) = ensure_remote_allowed(&self.underlay_policy, addr) {
                tracing::warn!(?addr, ?error, "drop UDP packet denied by underlay policy");
                continue;
            }
            let header = packet.udp_tunnel_header().unwrap();
            let conn_id = header.conn_id.get();
            let looks_like_syn = header.msg_type == UdpPacketType::Syn as u8
                && header.len.get() == 8
                && packet.udp_payload().len() == 8;
            let established = !looks_like_syn
                && self
                    .sock_map
                    .get(&addr)
                    .is_some_and(|connection| connection.conn_id == conn_id);
            if established {
                match pending.as_mut() {
                    Some((pending_addr, pending_conn_id, batch))
                        if *pending_addr == addr && *pending_conn_id == conn_id =>
                    {
                        batch
                            .try_push(packet)
                            .expect("UDP receive batches have a fixed packet bound");
                    }
                    _ => {
                        if let Some((pending_addr, pending_conn_id, batch)) = pending.take() {
                            self.forward_existing_batch(pending_addr, pending_conn_id, batch);
                        }
                        pending = Some((addr, conn_id, PacketBatch::singleton(packet)));
                    }
                }
            } else {
                if let Some((pending_addr, pending_conn_id, batch)) = pending.take() {
                    self.forward_existing_batch(pending_addr, pending_conn_id, batch);
                }
                self.do_forward_one_packet_to_conn(packet, addr);
            }
        }
        if let Some((addr, conn_id, batch)) = pending {
            self.forward_existing_batch(addr, conn_id, batch);
        }
    }

    async fn do_forward_task(self) {
        let socket = self.socket.as_ref().unwrap().clone();
        let mut batch_receiver = super::udp_vector_io::UdpBatchReceiver::new();
        loop {
            match udp_recv_from_socket_forward_task(&socket, &mut batch_receiver, true).await {
                Ok(packets) => self.do_forward_packet_batch(packets),
                Err(e) => {
                    tracing::error!(?e, "udp recv packet error");
                    break;
                }
            }
        }
    }
}

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,

    conn_recv: Receiver<Box<dyn Tunnel>>,
    data: UdpTunnelListenerData,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    close_event_recv: Option<UdpCloseEventReceiver>,
    socket_mark: Option<u32>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (close_event_send, close_event_recv) = unbounded_channel();
        let (conn_send, conn_recv) = channel(100);
        Self {
            addr: addr.clone(),
            socket: None,
            conn_recv,
            data: UdpTunnelListenerData::new(addr, conn_send, close_event_send),
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            close_event_recv: Some(close_event_recv),
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
        self.data.socket_mark = socket_mark;
    }

    pub fn set_underlay_policy(&mut self, underlay_policy: Arc<UnderlayPolicy>) {
        self.data.underlay_policy = underlay_policy;
    }

    pub fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let mut listener = Self::new(addr);
        listener.socket = Some(socket);
        listener
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    pub(crate) fn stun_packet_sender(&self) -> tokio::sync::broadcast::Sender<StunPacket> {
        self.data.stun_packet_sender.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        if self.socket.is_none() {
            let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
            let tunnel_url: TunnelUrl = self.addr.clone().into();
            self.socket = Some(Arc::new(
                bind()
                    .addr(addr)
                    .only_v6(true)
                    .maybe_dev(tunnel_url.bind_dev())
                    .maybe_socket_mark(self.socket_mark)
                    .call()?,
            ));
        }
        self.data.socket = self.socket.clone();

        self.addr
            .set_port(Some(self.socket.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(self.data.clone().do_forward_task());

        let sock_map = Arc::downgrade(&self.data.sock_map.clone());
        let mut close_recv = self.close_event_recv.take().unwrap();
        self.forward_tasks.lock().unwrap().spawn(async move {
            while let Some((dst_addr, conn_id, err)) = close_recv.recv().await {
                if let Some(err) = err {
                    tracing::error!(?err, "udp close event error");
                }
                if let Some(sock_map) = sock_map.upgrade() {
                    sock_map.remove_if(&dst_addr, |_, connection| connection.conn_id == conn_id);
                    shrink_dashmap(&sock_map, None);
                }
            }
        });

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::info!("start udp accept: {:?}", self.addr);
        if let Some(conn) = self.conn_recv.recv().await {
            return Ok(conn);
        }
        return Err(super::TunnelError::InternalError(
            "udp accept error".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        struct UdpTunnelConnCounter {
            sock_map: Weak<DashMap<SocketAddr, UdpConnection>>,
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                self.sock_map.upgrade().map(|x| x.len() as u32)
            }
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("sock_map_len", &self.get())
                    .finish()
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            sock_map: Arc::downgrade(&self.data.sock_map.clone()),
        }))
    }
}

#[derive(Debug)]
pub struct UdpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
    underlay_policy: Arc<UnderlayPolicy>,
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }

    fn should_resend_syn_to_hole_punch_source(
        recv_addr: SocketAddr,
        expected_addr: SocketAddr,
    ) -> bool {
        recv_addr == expected_addr
    }

    async fn wait_sack(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, TunnelError> {
        let mut buf = BytesMut::new();
        buf.reserve(UDP_DATA_MTU);

        let (usize, recv_addr) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            socket.recv_buf_from(&mut buf),
        )
        .await??;
        let zc_packet = get_zcpacket_from_buf(buf.split(), None, false)?;
        let header = zc_packet.udp_tunnel_header().unwrap();
        if header.msg_type == UdpPacketType::HolePunch as u8 {
            tracing::debug!(?recv_addr, ?addr, "udp wait sack got hole punch packet");
            if Self::should_resend_syn_to_hole_punch_source(recv_addr, addr) {
                let udp_packet = new_syn_packet(conn_id, magic).into_bytes();
                match socket.send_to(&udp_packet, recv_addr).await {
                    Ok(ret) => {
                        tracing::debug!(?recv_addr, ?ret, "udp send syn to hole punch source")
                    }
                    Err(e) => {
                        tracing::debug!(?recv_addr, ?e, "udp send syn to hole punch source failed")
                    }
                }
            } else {
                tracing::debug!(
                    ?recv_addr,
                    ?addr,
                    "ignore hole punch packet from unexpected source"
                );
            }
            return Err(TunnelError::InvalidPacket(
                "got hole punch packet while waiting for sack".to_owned(),
            ));
        }
        if recv_addr != addr {
            tracing::warn!(?recv_addr, ?addr, ?usize, "udp wait sack addr not match");
            return Err(TunnelError::InvalidPacket(
                "UDP SACK source address does not match".to_owned(),
            ));
        }

        if header.conn_id.get() != conn_id {
            return Err(super::TunnelError::ConnIdNotMatch(
                header.conn_id.get(),
                conn_id,
            ));
        }

        if header.msg_type != UdpPacketType::Sack as u8 {
            return Err(TunnelError::InvalidPacket("not sack packet".to_owned()));
        }

        let payload = zc_packet.udp_payload();
        if payload.len() == UDP_SYN_COOKIE_LEN {
            let sack_magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
            if sack_magic != magic {
                return Err(TunnelError::InvalidPacket(
                    "udp SYN cookie magic not match".to_owned(),
                ));
            }
            let mut tag = [0_u8; UDP_SYN_COOKIE_TAG_LEN];
            tag.copy_from_slice(&payload[8..]);
            let cookie_packet = new_syn_cookie_packet(conn_id, magic, tag).into_bytes();
            socket.send_to(&cookie_packet, recv_addr).await?;
            return Err(TunnelError::InvalidPacket(
                "UDP SYN cookie challenge completed".to_owned(),
            ));
        }
        if payload.len() != 8 {
            return Err(TunnelError::InvalidPacket(
                "udp sack packet payload len not match".to_owned(),
            ));
        }

        let sack_magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if sack_magic != magic {
            return Err(TunnelError::InvalidPacket(
                "udp sack magic not match".to_owned(),
            ));
        }

        Ok(recv_addr)
    }

    async fn wait_sack_loop(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, super::TunnelError> {
        loop {
            let ret = Self::wait_sack(socket, addr, conn_id, magic).await;
            if ret.is_err() {
                tracing::debug!(?ret, "udp wait sack error");
                continue;
            } else {
                return ret;
            }
        }
    }

    async fn build_tunnel(
        &self,
        socket: Arc<UdpSocket>,
        dst_addr: SocketAddr,
        conn_id: u32,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let ring_for_recv_udp = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        tracing::debug!(?ring_for_recv_udp, "udp build tunnel for connector");

        let (close_event_sender, mut close_event_recv) = unbounded_channel();

        let ring_sender = RingSink::new(ring_for_recv_udp.clone());
        let connection_state = Arc::new(UdpConnectionState::new());
        let mut udp_conn = UdpConnection::new(conn_id, ring_sender, None, connection_state.clone());

        let socket_clone = socket.clone();
        let underlay_policy = self.underlay_policy.clone();

        let recv_loop = async move {
            let mut batch_receiver = super::udp_vector_io::UdpBatchReceiver::new();
            loop {
                match udp_recv_from_socket_forward_task(&socket_clone, &mut batch_receiver, false)
                    .await
                {
                    Ok(packets) => {
                        let mut batch = PacketBatch::with_capacity(packets.len());
                        for (packet, addr) in packets {
                            if addr != dst_addr {
                                tracing::warn!(
                                    ?addr,
                                    ?dst_addr,
                                    "drop UDP packet from unexpected source"
                                );
                                continue;
                            }
                            if let Err(error) = ensure_remote_allowed(&underlay_policy, addr) {
                                tracing::warn!(
                                    ?addr,
                                    ?error,
                                    "drop connector UDP packet denied by underlay policy"
                                );
                                continue;
                            }
                            if packet
                                .udp_tunnel_header()
                                .is_none_or(|header| header.conn_id.get() != conn_id)
                            {
                                tracing::warn!(
                                    ?addr,
                                    "drop UDP packet with an unexpected connection ID"
                                );
                                continue;
                            }
                            tracing::trace!(?addr, "connector udp forward task done");
                            batch
                                .try_push(packet)
                                .expect("UDP receive vectors are bounded");
                        }
                        if !batch.is_empty()
                            && let Err(e) = udp_conn.handle_packet_batch_from_remote(batch)
                        {
                            tracing::trace!(?e, "udp forward packet batch error");
                        }
                    }
                    Err(e) => {
                        tracing::trace!(?e, "udp forward task error");
                        break;
                    }
                }
            }
        };
        tokio::spawn(
            async move {
                tokio::select! {
                    _ = close_event_recv.recv() => {
                        tracing::debug!("connector udp close event");
                    }
                    _ = recv_loop => {
                        tracing::debug!("connector udp forward task done");
                    }
                }
            }
            .instrument(tracing::info_span!(
                "udp forward from udp to ring",
                ?conn_id,
                ?dst_addr,
            )),
        );

        let udp_sink = UdpBatchSink::new(
            socket.clone(),
            dst_addr,
            conn_id,
            close_event_sender,
            None,
            connection_state,
        );
        Ok(Box::new(BatchTunnelWrapper::new(
            ScalarToBatchStream::new(RingStream::new(ring_for_recv_udp)),
            udp_sink,
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(
                    build_url_from_socket_addr(&socket.local_addr()?.to_string(), "udp").into(),
                ),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&dst_addr.to_string(), "udp").into(),
                ),
            }),
        )))
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("udp connect: {:?}", self.addr);
        ensure_remote_allowed(&self.underlay_policy, addr)?;
        ensure_local_allowed(&self.underlay_policy, socket.local_addr()?)?;

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.as_ref())?;

        // send syn
        let conn_id = rand::random();
        let magic = rand::random();
        let udp_packet = new_syn_packet(conn_id, magic).into_bytes();
        let ret = socket.send_to(&udp_packet, &addr).await?;
        tracing::warn!(?udp_packet, ?ret, "udp send syn");
        let resend_task = AbortOnDropHandle::new(tokio::spawn({
            let socket = socket.clone();
            let udp_packet = udp_packet.clone();
            let resend_addr = addr;
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    match socket.send_to(&udp_packet, &resend_addr).await {
                        Ok(ret) => tracing::trace!(?ret, ?resend_addr, "udp resend syn"),
                        Err(e) => {
                            tracing::debug!(?e, ?resend_addr, "udp resend syn failed");
                            break;
                        }
                    }
                }
            }
        }));

        // wait sack
        let recv_addr = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            Self::wait_sack_loop(&socket, addr, conn_id, magic),
        )
        .await??;
        drop(resend_task);

        if recv_addr != addr {
            tracing::debug!(?recv_addr, ?addr, "udp connect addr not match");
        }
        ensure_remote_allowed(&self.underlay_policy, recv_addr)?;

        self.build_tunnel(socket, recv_addr, conn_id).await
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // Route through bind() so socket_mark is applied consistently for
        // both the None (no-op) and Some(_) paths.
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        return self.try_connect_with_socket(Arc::new(socket), addr).await;
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
        bind_addrs: &[SocketAddr],
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in bind_addrs {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(self.try_connect_with_socket(Arc::new(socket), addr)),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        ensure_remote_allowed(&self.underlay_policy, addr)?;
        let bind_addrs = eligible_bind_addrs(&self.underlay_policy, &self.bind_addrs, addr)?;
        if bind_addrs.is_empty() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr, &bind_addrs).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_underlay_policy(&mut self, policy: Arc<UnderlayPolicy>) {
        self.underlay_policy = policy;
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use futures::{SinkExt, StreamExt};

    use super::*;
    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, underlay_policy::UnderlayPolicy},
        tunnel::{
            TunnelConnector,
            common::{
                get_interface_name_by_ip,
                tests::{_tunnel_echo_server, _tunnel_pingpong, wait_for_condition},
            },
            packet_def::PacketType,
        },
    };

    fn new_udp_data_packet(conn_id: u32, packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"udp-data").convert_type(ZCPacketType::UDP);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.msg_type = UdpPacketType::Data as u8;
        header.len.set(udp_payload_len as u16);
        packet
    }

    fn new_tagged_udp_data_packet(conn_id: u32, packet_type: PacketType, tag: u8) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&[tag]).convert_type(ZCPacketType::UDP);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.msg_type = UdpPacketType::Data as u8;
        header.len.set(udp_payload_len as u16);
        packet
    }

    #[test]
    fn syn_cookie_binds_source_connection_and_nonce() {
        let (connection_sender, _connection_receiver) = channel(1);
        let (close_sender, _close_receiver) = unbounded_channel();
        let data = UdpTunnelListenerData::new(
            "udp://127.0.0.1:11010".parse().unwrap(),
            connection_sender,
            close_sender,
        );
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let tag = data.syn_cookie_tag(source, 17, 23);

        assert!(data.syn_cookie_valid(source, 17, 23, &tag));
        assert!(!data.syn_cookie_valid("192.0.2.10:41001".parse().unwrap(), 17, 23, &tag));
        assert!(!data.syn_cookie_valid(source, 18, 23, &tag));
        assert!(!data.syn_cookie_valid(source, 17, 24, &tag));
    }

    #[test]
    fn protected_udp_data_has_no_fixed_type_or_length_fields() {
        let mut envelope = vec![0_u8; 64];
        envelope[16..20].copy_from_slice(&[0xa4, 0xb5, 0xc6, 0xd7]);
        let mut packet = ZCPacket::new_from_buf(
            BytesMut::from(envelope.as_slice()),
            ZCPacketType::DummyTunnel,
        );
        packet.set_lossy_hint(true);

        let packet = prepare_udp_data_packet(packet, 0x1234_5678);
        let header = packet.udp_tunnel_header().unwrap();

        assert_eq!(header.conn_id.get(), 0x1234_5678);
        assert_eq!(header.msg_type, 0xa4);
        assert_eq!(header.padding, 0xb5 | 1);
        assert_eq!(header.len.get(), u16::from_le_bytes([0xc6, 0xd7]));
        assert!(packet.is_lossy());
    }

    #[test]
    fn protected_udp_wire_round_trip_preserves_the_complete_envelope() {
        use crate::peers::link_envelope::LinkEnvelopeSession;

        let root_key = [0x5a; 32];
        let handshake_hash = [0xa5; 32];
        let client = LinkEnvelopeSession::new(root_key, &handshake_hash, true, 1, 2);
        let server = LinkEnvelopeSession::new(root_key, &handshake_hash, false, 2, 1);

        for packet_type in [PacketType::RpcReq, PacketType::Ethernet] {
            let mut packet = ZCPacket::new_with_payload(b"protected UDP payload");
            packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
            let original = packet.tunnel_payload().to_vec();
            let expected_lossy = packet.is_lossy();

            let sealed = client.seal(packet).unwrap();
            let framed = prepare_udp_data_packet(sealed, 0x1234_5678);
            assert_eq!(
                framed.udp_tunnel_header().unwrap().conn_id.get(),
                0x1234_5678
            );

            let wire = framed.into_bytes();
            let received =
                get_zcpacket_from_buf(BytesMut::from(wire.as_ref()), None, false).unwrap();
            assert_eq!(received.is_lossy(), expected_lossy);

            let opened = server.open(received).unwrap();
            assert_eq!(opened.tunnel_payload(), original);
        }
    }

    #[test]
    fn plain_udp_data_clears_reused_padding() {
        let mut packet = ZCPacket::new_with_payload(b"plain-data").convert_type(ZCPacketType::UDP);
        packet.mut_udp_tunnel_header().unwrap().padding = 0xfe;

        let packet = prepare_udp_data_packet(packet, 0x1234_5678);

        assert_eq!(packet.udp_tunnel_header().unwrap().padding, 0);
    }

    fn assert_sync_packet_handler(_: fn(&mut UdpConnection, ZCPacket) -> Result<(), TunnelError>) {}

    #[test]
    fn udp_listener_admission_is_bounded() {
        let (connection_sender, _connection_receiver) = channel(1);
        let (close_sender, _close_receiver) = unbounded_channel();
        let data = UdpTunnelListenerData::new(
            "udp://127.0.0.1:11010".parse().unwrap(),
            connection_sender,
            close_sender,
        );

        let connection_permits = (0..UDP_LISTENER_CONNECTION_CAPACITY)
            .map(|_| {
                data.connection_admission
                    .clone()
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            data.connection_admission
                .clone()
                .try_acquire_owned()
                .is_err()
        );

        let control_permits = (0..UDP_CONTROL_TASK_CAPACITY)
            .map(|_| {
                data.control_task_admission
                    .clone()
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            data.control_task_admission
                .clone()
                .try_acquire_owned()
                .is_err()
        );

        drop((connection_permits, control_permits));
        assert_eq!(
            data.connection_admission.available_permits(),
            UDP_LISTENER_CONNECTION_CAPACITY
        );
        assert_eq!(
            data.control_task_admission.available_permits(),
            UDP_CONTROL_TASK_CAPACITY
        );
    }

    #[test]
    fn udp_connection_accepts_full_non_lossy_vector_batch() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let ring_sender = crate::tunnel::ring::RingSink::new(tunnel.clone());
        let mut ring_stream = crate::tunnel::ring::RingStream::new(tunnel);
        let mut connection =
            UdpConnection::new(77, ring_sender, None, Arc::new(UdpConnectionState::new()));
        let mut batch = PacketBatch::new();
        for _ in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
            let packet = new_udp_data_packet(77, PacketType::RpcReq);
            assert!(!packet.is_lossy());
            batch.try_push(packet).unwrap();
        }

        connection.handle_packet_batch_from_remote(batch).unwrap();
        let received = ring_stream
            .try_recv_batch()
            .expect("the full UDP vector batch is queued");
        assert_eq!(received.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
    }

    #[test]
    fn udp_connection_preserves_mixed_reliability_order() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let ring_sender = crate::tunnel::ring::RingSink::new(tunnel.clone());
        let mut ring_stream = crate::tunnel::ring::RingStream::new(tunnel);
        let mut connection =
            UdpConnection::new(77, ring_sender, None, Arc::new(UdpConnectionState::new()));
        let packet_types = [
            PacketType::Data,
            PacketType::RpcReq,
            PacketType::Ethernet,
            PacketType::Ping,
            PacketType::Data,
            PacketType::RpcResp,
        ];
        let mut batch = PacketBatch::new();
        for (tag, packet_type) in packet_types.into_iter().enumerate() {
            batch
                .try_push(new_tagged_udp_data_packet(77, packet_type, tag as u8))
                .unwrap();
        }

        connection.handle_packet_batch_from_remote(batch).unwrap();

        let mut tags = Vec::new();
        while let Some(batch) = ring_stream.try_recv_batch() {
            tags.extend(batch.iter().map(|packet| packet.payload()[0]));
        }
        assert_eq!(tags, (0_u8..packet_types.len() as u8).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn udp_tunnel_receive_stream_keeps_full_vector_batch() {
        let mut listener = UdpTunnelListener::new("udp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let mut connector = UdpTunnelConnector::new(listener.local_url());
        let (connected, accepted) = tokio::join!(connector.connect(), listener.accept());
        let connected = connected.unwrap();
        let accepted = accepted.unwrap();
        let (_connected_stream, mut connected_sink) = connected.split();
        let (mut accepted_stream, _accepted_sink) = accepted.split();
        let mut sent = PacketBatch::new();
        for tag in 0_u8..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE as u8 {
            sent.try_push(new_tagged_udp_data_packet(0, PacketType::RpcReq, tag))
                .unwrap();
        }

        connected_sink.send(sent).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), accepted_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            received
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            (0_u8..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE as u8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn udp_connection_lossy_vector_batch_admits_available_prefix() {
        let tunnel = Arc::new(RingTunnel::new(16));
        let ring_sender = crate::tunnel::ring::RingSink::new(tunnel.clone());
        let mut ring_stream = crate::tunnel::ring::RingStream::new(tunnel);
        let mut connection =
            UdpConnection::new(77, ring_sender, None, Arc::new(UdpConnectionState::new()));
        let mut batch = PacketBatch::new();
        for _ in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
            batch
                .try_push(new_udp_data_packet(77, PacketType::Data))
                .unwrap();
        }

        connection.handle_packet_batch_from_remote(batch).unwrap();
        let received = ring_stream
            .try_recv_batch()
            .expect("the available lossy prefix is queued");
        assert_eq!(received.len(), 8);
    }

    #[test]
    fn udp_connection_keeps_ring_credits_for_reliable_control() {
        let tunnel = Arc::new(RingTunnel::new(16));
        let ring_sender = crate::tunnel::ring::RingSink::new(tunnel.clone());
        let mut ring_stream = crate::tunnel::ring::RingStream::new(tunnel);
        let mut connection =
            UdpConnection::new(77, ring_sender, None, Arc::new(UdpConnectionState::new()));
        let mut bulk = PacketBatch::new();
        for _ in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE {
            bulk.try_push(new_udp_data_packet(77, PacketType::Data))
                .unwrap();
        }
        connection.handle_packet_batch_from_remote(bulk).unwrap();

        let mut mixed = PacketBatch::new();
        mixed
            .try_push(new_udp_data_packet(77, PacketType::Data))
            .unwrap();
        mixed
            .try_push(new_udp_data_packet(77, PacketType::RpcReq))
            .unwrap();
        connection.handle_packet_batch_from_remote(mixed).unwrap();

        let first = ring_stream.try_recv_batch().unwrap();
        let second = ring_stream.try_recv_batch().unwrap();
        assert_eq!(first.len(), 8);
        assert_eq!(second.len(), 1);
        assert!(!second[0].is_lossy());
    }

    #[tokio::test]
    async fn udp_outbound_batch_sink_keeps_credits_for_reliable_control() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let mut sink = UdpRingBatchSink::new(crate::tunnel::ring::RingSink::new(tunnel.clone()));
        let mut stream = crate::tunnel::ring::RingStream::new(tunnel);
        let make_bulk = |len: usize| {
            let mut batch = PacketBatch::new();
            for _ in 0..len {
                batch
                    .try_push(new_udp_data_packet(77, PacketType::Data))
                    .unwrap();
            }
            batch
        };
        sink.send(make_bulk(crate::tunnel::batch::MAX_PACKET_BATCH_SIZE))
            .await
            .unwrap();
        sink.send(make_bulk(
            UDP_RING_PACKET_CAPACITY
                - UDP_CONTROL_PACKET_RESERVE
                - crate::tunnel::batch::MAX_PACKET_BATCH_SIZE,
        ))
        .await
        .unwrap();
        sink.send(PacketBatch::singleton(new_udp_data_packet(
            77,
            PacketType::Ping,
        )))
        .await
        .unwrap();

        let first = stream.try_recv_batch().unwrap();
        let second = stream.try_recv_batch().unwrap();
        let third = stream.try_recv_batch().unwrap();
        assert_eq!(first.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            second.len(),
            UDP_RING_PACKET_CAPACITY
                - UDP_CONTROL_PACKET_RESERVE
                - crate::tunnel::batch::MAX_PACKET_BATCH_SIZE
        );
        assert_eq!(third.len(), 1);
        assert!(!third[0].is_lossy());
    }

    #[tokio::test]
    async fn udp_outbound_batch_sink_preserves_mixed_reliability_order() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let mut sink = UdpRingBatchSink::new(crate::tunnel::ring::RingSink::new(tunnel.clone()));
        let mut stream = crate::tunnel::ring::RingStream::new(tunnel);
        let packet_types = [
            PacketType::Data,
            PacketType::RpcReq,
            PacketType::Ethernet,
            PacketType::Ping,
            PacketType::Data,
            PacketType::RpcResp,
        ];
        let mut mixed = PacketBatch::new();
        for (tag, packet_type) in packet_types.into_iter().enumerate() {
            mixed
                .try_push(new_tagged_udp_data_packet(77, packet_type, tag as u8))
                .unwrap();
        }

        sink.send(mixed).await.unwrap();

        let mut tags = Vec::new();
        while let Some(batch) = stream.try_recv_batch() {
            tags.extend(batch.iter().map(|packet| packet.payload()[0]));
        }
        assert_eq!(tags, (0_u8..packet_types.len() as u8).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn udp_outbound_second_full_data_batch_waits_without_dropping_suffix() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let mut sink = UdpRingBatchSink::new(crate::tunnel::ring::RingSink::new(tunnel.clone()));
        let mut stream = crate::tunnel::ring::RingStream::new(tunnel);
        let make_batch = |start: u8| {
            let mut batch = PacketBatch::new();
            for offset in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE as u8 {
                batch
                    .try_push(new_tagged_udp_data_packet(
                        77,
                        PacketType::Data,
                        start + offset,
                    ))
                    .unwrap();
            }
            batch
        };

        sink.send(make_batch(0)).await.unwrap();
        let mut second_send = Box::pin(sink.send(make_batch(64)));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second_send)
                .await
                .is_err(),
            "the second full data batch must wait for ring credits"
        );

        let first = stream.recv_batch().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), second_send)
            .await
            .unwrap()
            .unwrap();
        let second = stream.recv_batch().await.unwrap();

        assert_eq!(first.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
        assert_eq!(second.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            second
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            (64_u8..128).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn udp_outbound_cancelled_wait_retains_the_full_pending_batch() {
        let tunnel = Arc::new(RingTunnel::new(UDP_RING_PACKET_CAPACITY));
        let mut sink = UdpRingBatchSink::new(crate::tunnel::ring::RingSink::new(tunnel.clone()));
        let mut stream = crate::tunnel::ring::RingStream::new(tunnel);
        let make_batch = || {
            let mut batch = PacketBatch::new();
            for tag in 0..crate::tunnel::batch::MAX_PACKET_BATCH_SIZE as u8 {
                batch
                    .try_push(new_tagged_udp_data_packet(77, PacketType::Data, tag))
                    .unwrap();
            }
            batch
        };

        sink.send(make_batch()).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), sink.send(make_batch()))
                .await
                .is_err(),
            "the second send must remain pending before cancellation"
        );

        let _first = stream.recv_batch().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), sink.flush())
            .await
            .unwrap()
            .unwrap();
        let second = stream.recv_batch().await.unwrap();

        assert_eq!(second.len(), crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
    }

    #[tokio::test]
    async fn platform_udp_batch_preserves_datagram_boundaries_and_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let payloads = [
            bytes::Bytes::from_static(b"one"),
            bytes::Bytes::from_static(b"two-two"),
            bytes::Bytes::from_static(b"three-three-three"),
        ];

        crate::tunnel::udp_vector_io::send_batch(&sender, destination, &payloads)
            .await
            .unwrap();

        let mut received = Vec::new();
        for _ in 0..payloads.len() {
            let mut buffer = [0_u8; 64];
            let (length, source) = receiver.recv_from(&mut buffer).await.unwrap();
            assert_eq!(source, sender.local_addr().unwrap());
            received.push(buffer[..length].to_vec());
        }
        assert_eq!(
            received,
            payloads
                .iter()
                .map(|payload| payload.to_vec())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn native_udp_batch_sink_preserves_packet_order() {
        let receiver = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let destination = receiver.local_addr().unwrap();
        let (close_sender, _close_receiver) = unbounded_channel();
        let mut sink = UdpBatchSink::new(
            sender,
            destination,
            77,
            close_sender,
            None,
            Arc::new(UdpConnectionState::new()),
        );
        let mut batch = PacketBatch::new();
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            batch.try_push(ZCPacket::new_with_payload(payload)).unwrap();
        }

        sink.send(batch).await.unwrap();

        for expected in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            let mut buffer = [0_u8; 256];
            let (length, _) = receiver.recv_from(&mut buffer).await.unwrap();
            let packet =
                get_zcpacket_from_buf(BytesMut::from(&buffer[..length]), None, false).unwrap();
            assert_eq!(packet.udp_tunnel_header().unwrap().conn_id.get(), 77);
            assert_eq!(packet.payload(), expected);
        }
    }

    #[tokio::test]
    async fn platform_udp_receive_batch_preserves_sources_and_boundaries() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        for payload in [b"a".as_slice(), b"bb", b"ccc"] {
            sender.send_to(payload, destination).await.unwrap();
        }

        let datagrams = tokio::time::timeout(Duration::from_secs(1), async {
            let mut datagrams = Vec::new();
            while datagrams.len() < 3 {
                datagrams.extend(
                    crate::tunnel::udp_vector_io::recv_batch(&receiver, UDP_DATA_MTU).await?,
                );
            }
            Ok::<_, std::io::Error>(datagrams)
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(datagrams.len(), 3);
        assert!(
            datagrams
                .iter()
                .all(|datagram| datagram.source == sender.local_addr().unwrap())
        );
        assert_eq!(
            datagrams
                .iter()
                .map(|datagram| datagram.buffer.to_vec())
                .collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()]
        );
    }

    #[test]
    fn strict_stun_response_reuses_allowed_listener_source() {
        let policy = UnderlayPolicy::new(&[], &["100.64.0.0/10".into()]).unwrap();

        let bind_addr = stun_response_bind_addr(
            &policy,
            "192.0.2.20:11010".parse().unwrap(),
            "198.51.100.8:22020".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(bind_addr, Some("192.0.2.20:0".parse().unwrap()));
    }

    #[test]
    fn strict_stun_response_rejects_unproven_or_denied_paths() {
        let policy = UnderlayPolicy::new(&[], &["100.64.0.0/10".into()]).unwrap();

        assert!(matches!(
            stun_response_bind_addr(
                &policy,
                "0.0.0.0:11010".parse().unwrap(),
                "198.51.100.8:22020".parse().unwrap(),
            ),
            Err(TunnelError::UnderlayPolicyDenied(_))
        ));
        assert!(matches!(
            stun_response_bind_addr(
                &policy,
                "192.0.2.20:11010".parse().unwrap(),
                "100.100.10.20:22020".parse().unwrap(),
            ),
            Err(TunnelError::UnderlayPolicyDenied(_))
        ));
    }

    #[test]
    fn hole_punch_source_must_match_connect_addr_before_syn_resend() {
        let expected_addr: SocketAddr = "198.51.100.10:11010".parse().unwrap();
        let same_port_different_ip: SocketAddr = "198.51.100.11:11010".parse().unwrap();
        let same_ip_different_port: SocketAddr = "198.51.100.10:11011".parse().unwrap();

        assert!(UdpTunnelConnector::should_resend_syn_to_hole_punch_source(
            expected_addr,
            expected_addr
        ));
        assert!(!UdpTunnelConnector::should_resend_syn_to_hole_punch_source(
            same_port_different_ip,
            expected_addr
        ));
        assert!(!UdpTunnelConnector::should_resend_syn_to_hole_punch_source(
            same_ip_different_port,
            expected_addr
        ));
    }

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn active_policy_without_bind_sources_fails_closed() {
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:9".parse().unwrap());
        connector.set_resolved_addr("127.0.0.1:9".parse().unwrap());
        connector.set_underlay_policy(Arc::new(
            UnderlayPolicy::new(&[], &["100.64.0.0/10".into()]).unwrap(),
        ));

        let result = connector.connect().await;

        assert!(matches!(result, Err(TunnelError::UnderlayPolicyDenied(_))));
    }

    #[tokio::test]
    async fn udp_connection_handler_uses_sync_nonblocking_ring_delivery() {
        assert_sync_packet_handler(UdpConnection::handle_packet_from_remote);

        let ring_for_recv_udp = Arc::new(RingTunnel::new(8));
        let mut conn = UdpConnection::new(
            7,
            RingSink::new(ring_for_recv_udp),
            None,
            Arc::new(UdpConnectionState::new()),
        );

        for _ in 0..16 {
            conn.handle_packet_from_remote(new_udp_data_packet(7, PacketType::Data))
                .unwrap();
        }

        let mut got_buffer_full = false;
        for _ in 0..16 {
            match conn.handle_packet_from_remote(new_udp_data_packet(7, PacketType::Ping)) {
                Ok(()) => {}
                Err(TunnelError::BufferFull) => {
                    got_buffer_full = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert!(got_buffer_full);
    }

    #[tokio::test]
    async fn udp_bench_with_bind() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5554".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5554".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn udp_bench_with_bind_fail() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5553".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5553".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn udp_multiple_conns() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5557".parse().unwrap());
        listener.listen().await.unwrap();

        let _lis = tokio::spawn(async move {
            loop {
                let ret = listener.accept().await.unwrap();
                assert_eq!(
                    ret.info()
                        .unwrap()
                        .local_addr
                        .unwrap_or_default()
                        .to_string(),
                    listener.local_url().to_string()
                );
                tokio::spawn(async move { _tunnel_echo_server(ret, false).await });
            }
        });

        let mut connector1 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());
        let mut connector2 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());

        let t1 = connector1.connect().await.unwrap();
        let t2 = connector2.connect().await.unwrap();

        let sender1 = tokio::spawn(async move {
            let (mut stream, mut sink) = t1.split();

            for i in 0..10 {
                sink.send(PacketBatch::singleton(ZCPacket::new_with_payload(
                    "hello1".as_bytes(),
                )))
                .await
                .unwrap();
                let recv = stream
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap();
                println!("t1 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello1".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let sender2 = tokio::spawn(async move {
            let (mut stream, mut sink) = t2.split();

            for i in 0..10 {
                sink.send(PacketBatch::singleton(ZCPacket::new_with_payload(
                    "hello2".as_bytes(),
                )))
                .await
                .unwrap();
                let recv = stream
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .pop_singleton()
                    .unwrap();
                println!("t2 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello2".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let _ = tokio::join!(sender1, sender2);
    }

    #[tokio::test]
    async fn bind_multi_ip_to_same_dev() {
        let global_ctx = get_mock_global_ctx();
        let ips = global_ctx
            .get_ip_collector()
            .collect_ip_addrs()
            .await
            .interface_ipv4s;
        if ips.is_empty() {
            return;
        }
        let bind_dev = get_interface_name_by_ip(&IpAddr::V4(ips[0].into()));

        for ip in ips {
            println!("bind to ip: {}, {:?}", ip, bind_dev);
            let addr = SocketAddr::from_url(
                format!("udp://{}:11111", ip).parse().unwrap(),
                IpVersion::Both,
            )
            .await
            .unwrap();
            let _ = bind::<UdpSocket>()
                .addr(addr)
                .maybe_dev(bind_dev.clone())
                .only_v6(true)
                .call()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn bind_same_port() {
        println!("{}", "[::]:8888".parse::<SocketAddr>().unwrap());
        let mut listener = UdpTunnelListener::new("udp://[::]:31014".parse().unwrap());
        let mut listener2 = UdpTunnelListener::new("udp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31015".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31016".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://localhost:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = UdpTunnelListener::new("udp://127.0.0.1:31016".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://localhost:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_conn_counter() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5558".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5558".parse().unwrap());
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let _c1 = connector.connect().await.unwrap();
            let _c2 = connector.connect().await.unwrap();
        });

        let conn_counter = listener.get_conn_counter();

        listener.listen().await.unwrap();
        let c1 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(1));
        let c2 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(2));

        drop(c2);
        wait_for_condition(
            || async { conn_counter.get() == Some(1) },
            Duration::from_secs(1),
        )
        .await;

        drop(c1);
        wait_for_condition(
            || async { conn_counter.get().unwrap_or(0) == 0 },
            Duration::from_secs(1),
        )
        .await;
    }

    #[test]
    fn v6_hole_punch_packet_preserves_preferred_source_ifindex() {
        let dst_addr = "[2001:db8::1]:10001".parse::<SocketAddrV6>().unwrap();
        let preferred_src = PreferredIpv6Source {
            ip: "2001:db8::2".parse().unwrap(),
            ifindex: 42,
        };

        let packet = new_v6_hole_punch_packet(&dst_addr, Some(preferred_src));
        let (parsed_dst_addr, parsed_preferred_src) =
            extract_v6_hole_punch_packet(packet.udp_payload()).unwrap();

        assert_eq!(parsed_dst_addr, dst_addr);
        assert_eq!(parsed_preferred_src, Some(preferred_src));
    }

    #[tokio::test]
    async fn test_v6_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        lis.listen().await.unwrap();

        // a socket to receive forwarded hole punch packets
        let socket = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tracing::info!("lis local addr: {:?}", lis.local_url());
        tracing::info!("socket local addr: {:?}", socket.local_addr().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // a socket to send v6 hole punch packets
        send_v6_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V6(addr_v6) => addr_v6,
                _ => panic!("Expected an IPv6 address"),
            },
            None,
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v6 hole punch packet")
            .unwrap();
    }

    #[tokio::test]
    async fn test_v4_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        lis.listen().await.unwrap();

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        send_v4_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V4(addr_v4) => addr_v4,
                _ => panic!("Expected an IPv4 address"),
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v4 hole punch packet")
            .unwrap();
    }
}
