use std::{
    collections::{BTreeMap, HashMap},
    future::pending,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::{DashMap, DashSet};
use prost::Message;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    sync::{mpsc, oneshot},
    time::{sleep_until, timeout},
};
use tokio_util::{io::InspectReader, sync::PollSender};

use super::{CidrSet, tcp_proxy::TcpProxy};
use crate::{
    common::{PeerId, acl_processor::PacketInfo, error::Result as LowTierResult},
    peers::{
        PeerPacketFilter, acl_filter::AclFilter, peer_conn::PeerConn, peer_manager::PeerManager,
    },
    proto::{
        acl::{Action, ChainType, Protocol},
        peer_rpc::QuicConnData,
    },
    tunnel::packet_def::{PacketType, ZCPacket},
};

const PROTOCOL_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 30;

#[derive(Clone)]
struct ProxyAclHandler {
    acl_filter: Arc<AclFilter>,
    packet_info: PacketInfo,
    chain_type: ChainType,
}

impl ProxyAclHandler {
    fn handle_packet(&self, buf: &[u8]) -> LowTierResult<()> {
        let mut packet_info = self.packet_info.clone();
        packet_info.packet_size = buf.len();
        let processor = self.acl_filter.get_processor();
        let result = processor.process_packet(&packet_info, self.chain_type);
        self.acl_filter
            .handle_acl_result(&result, &packet_info, self.chain_type, &processor);
        if !matches!(result.action, Action::Allow) {
            return Err(anyhow!("acl denied").into());
        }
        Ok(())
    }

    async fn copy_bidirection_with_acl(
        &self,
        src: impl AsyncRead + AsyncWrite + Unpin,
        mut dst: impl AsyncRead + AsyncWrite + Unpin,
    ) -> LowTierResult<()> {
        let (src_reader, src_writer) = tokio::io::split(src);
        let src_reader = InspectReader::new(src_reader, |buf| {
            let _ = self.handle_packet(buf);
        });
        let mut src = tokio::io::join(src_reader, src_writer);
        copy_bidirectional(&mut src, &mut dst).await?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKind {
    Open = 1,
    OpenAck = 2,
    Data = 3,
    Ack = 4,
    Fin = 5,
    Reset = 6,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::OpenAck),
            3 => Ok(Self::Data),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Fin),
            6 => Ok(Self::Reset),
            _ => Err(FrameDecodeError::Kind),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Frame {
    kind: FrameKind,
    stream_id: u64,
    sequence: u64,
    acknowledgement: u64,
    receive_window: u32,
    payload: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameDecodeError {
    Short,
    Version,
    Kind,
}

impl Frame {
    fn encode(&self) -> Bytes {
        let mut encoded = BytesMut::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(self.kind as u8);
        encoded.put_u64(self.stream_id);
        encoded.put_u64(self.sequence);
        encoded.put_u64(self.acknowledgement);
        encoded.put_u32(self.receive_window);
        encoded.extend_from_slice(&self.payload);
        encoded.freeze()
    }

    fn decode(mut encoded: Bytes) -> Result<Self, FrameDecodeError> {
        if encoded.len() < FRAME_HEADER_LEN {
            return Err(FrameDecodeError::Short);
        }
        if encoded.get_u8() != PROTOCOL_VERSION {
            return Err(FrameDecodeError::Version);
        }
        let kind = FrameKind::try_from(encoded.get_u8())?;
        Ok(Self {
            kind,
            stream_id: encoded.get_u64(),
            sequence: encoded.get_u64(),
            acknowledgement: encoded.get_u64(),
            receive_window: encoded.get_u32(),
            payload: encoded,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveWindowError {
    Full,
    Overlap,
}

struct SendWindow {
    capacity: usize,
    next_sequence: u64,
    buffered_bytes: usize,
    chunks: BTreeMap<u64, Bytes>,
}

impl SendWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_sequence: 0,
            buffered_bytes: 0,
            chunks: BTreeMap::new(),
        }
    }

    fn push(&mut self, payload: Bytes) -> Result<u64, Bytes> {
        if payload.is_empty() || self.buffered_bytes.saturating_add(payload.len()) > self.capacity {
            return Err(payload);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(payload.len() as u64);
        self.buffered_bytes += payload.len();
        self.chunks.insert(sequence, payload);
        Ok(sequence)
    }

    fn acknowledge(&mut self, acknowledgement: u64) {
        let acknowledged = self
            .chunks
            .iter()
            .take_while(|(sequence, payload)| {
                sequence.saturating_add(payload.len() as u64) <= acknowledgement
            })
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>();
        for sequence in acknowledged {
            if let Some(payload) = self.chunks.remove(&sequence) {
                self.buffered_bytes -= payload.len();
            }
        }
    }

    fn get(&self, sequence: u64) -> Option<&Bytes> {
        self.chunks.get(&sequence)
    }

    fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    fn first_sequence(&self) -> Option<u64> {
        self.chunks.first_key_value().map(|(sequence, _)| *sequence)
    }
}

struct ReceiveWindow {
    capacity: usize,
    next_sequence: u64,
    delivered_unconsumed: usize,
    out_of_order_bytes: usize,
    out_of_order: BTreeMap<u64, Bytes>,
}

impl ReceiveWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_sequence: 0,
            delivered_unconsumed: 0,
            out_of_order_bytes: 0,
            out_of_order: BTreeMap::new(),
        }
    }

    fn insert(&mut self, sequence: u64, payload: Bytes) -> Result<Vec<Bytes>, ReceiveWindowError> {
        if payload.is_empty() || sequence < self.next_sequence {
            return Ok(Vec::new());
        }
        let payload_end = sequence.saturating_add(payload.len() as u64);
        if self
            .out_of_order
            .iter()
            .any(|(existing_sequence, existing)| {
                let existing_end = existing_sequence.saturating_add(existing.len() as u64);
                sequence < existing_end && *existing_sequence < payload_end
            })
        {
            return if self.out_of_order.contains_key(&sequence) {
                Ok(Vec::new())
            } else {
                Err(ReceiveWindowError::Overlap)
            };
        }
        if self.buffered_bytes().saturating_add(payload.len()) > self.capacity {
            return Err(ReceiveWindowError::Full);
        }

        if sequence != self.next_sequence {
            self.out_of_order_bytes += payload.len();
            self.out_of_order.insert(sequence, payload);
            return Ok(Vec::new());
        }

        let mut delivered = Vec::new();
        self.next_sequence = payload_end;
        self.delivered_unconsumed += payload.len();
        delivered.push(payload);
        while let Some(payload) = self.out_of_order.remove(&self.next_sequence) {
            self.out_of_order_bytes -= payload.len();
            self.next_sequence += payload.len() as u64;
            self.delivered_unconsumed += payload.len();
            delivered.push(payload);
        }
        Ok(delivered)
    }

    fn consume(&mut self, bytes: usize) {
        self.delivered_unconsumed = self.delivered_unconsumed.saturating_sub(bytes);
    }

    fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn buffered_bytes(&self) -> usize {
        self.delivered_unconsumed + self.out_of_order_bytes
    }

    fn available_bytes(&self) -> usize {
        self.capacity.saturating_sub(self.buffered_bytes())
    }
}

const STREAM_WINDOW_BYTES: usize = 256 * 1024;
const STREAM_DATA_BYTES: usize = 1120;
const MAX_STREAM_WIRE_OVERHEAD_BYTES: usize = 160;
const APP_WRITE_QUEUE_CHUNKS: usize = 64;
const APP_READ_QUEUE_CHUNKS: usize = STREAM_WINDOW_BYTES.div_ceil(STREAM_DATA_BYTES);
const FRAME_QUEUE_PACKETS: usize = STREAM_WINDOW_BYTES.div_ceil(STREAM_DATA_BYTES);
const ACK_DELAY: Duration = Duration::from_millis(1);
const ACK_BATCH_BYTES: usize = STREAM_WINDOW_BYTES / 4;
const RETRANSMIT_AFTER: Duration = Duration::from_millis(100);
const FIN_RETRANSMIT_AFTER: Duration = Duration::from_millis(100);
const OPEN_RETRANSMIT_AFTER: Duration = Duration::from_millis(200);
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

type SessionKey = (PeerId, u64);

enum StreamCommand {
    Consumed(usize),
    Finish,
    Reset,
}

struct StreamLifecycle {
    command_tx: mpsc::UnboundedSender<StreamCommand>,
    shutdown_sent: AtomicBool,
}

impl StreamLifecycle {
    fn finish(&self) {
        if !self.shutdown_sent.swap(true, Ordering::Relaxed) {
            let _ = self.command_tx.send(StreamCommand::Finish);
        }
    }
}

impl Drop for StreamLifecycle {
    fn drop(&mut self) {
        if !self.shutdown_sent.swap(true, Ordering::Relaxed) {
            let _ = self.command_tx.send(StreamCommand::Reset);
        }
    }
}

pub struct OverlayStream {
    read_rx: mpsc::Receiver<Bytes>,
    read_current: Option<Bytes>,
    write_tx: PollSender<Bytes>,
    owned_write_tx: Option<mpsc::Sender<Bytes>>,
    lifecycle: StreamLifecycle,
}

impl OverlayStream {
    fn new(
        read_rx: mpsc::Receiver<Bytes>,
        write_tx: mpsc::Sender<Bytes>,
        command_tx: mpsc::UnboundedSender<StreamCommand>,
    ) -> Self {
        Self {
            read_rx,
            read_current: None,
            write_tx: PollSender::new(write_tx.clone()),
            owned_write_tx: Some(write_tx),
            lifecycle: StreamLifecycle {
                command_tx,
                shutdown_sent: AtomicBool::new(false),
            },
        }
    }

    pub async fn copy_bidirectional_owned<I>(self, inbound: &mut I) -> io::Result<(u64, u64)>
    where
        I: AsyncRead + AsyncWrite + Unpin,
    {
        let Self {
            mut read_rx,
            read_current: _,
            write_tx,
            owned_write_tx,
            lifecycle,
        } = self;
        drop(write_tx);
        let owned_write_tx = owned_write_tx.expect("owned transfer has its write sender");
        let command_tx = lifecycle.command_tx.clone();
        let (mut inbound_read, mut inbound_write) = tokio::io::split(inbound);

        let upload = async move {
            let mut transferred = 0_u64;
            loop {
                let mut allocation = BytesMut::with_capacity(16 * 1024);
                let read = inbound_read.read_buf(&mut allocation).await?;
                if read == 0 {
                    drop(owned_write_tx);
                    lifecycle.finish();
                    return Ok::<u64, io::Error>(transferred);
                }
                let mut owned = allocation.freeze();
                transferred += owned.len() as u64;
                while !owned.is_empty() {
                    let length = owned.len().min(STREAM_DATA_BYTES);
                    let chunk = owned.split_to(length);
                    owned_write_tx.send(chunk).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "overlay stream closed")
                    })?;
                }
            }
        };
        let download = async move {
            let mut transferred = 0_u64;
            while let Some(bytes) = read_rx.recv().await {
                inbound_write.write_all(&bytes).await?;
                transferred += bytes.len() as u64;
                let _ = command_tx.send(StreamCommand::Consumed(bytes.len()));
            }
            inbound_write.shutdown().await?;
            Ok::<u64, io::Error>(transferred)
        };
        let (uploaded, downloaded) = tokio::try_join!(upload, download)?;
        Ok((uploaded, downloaded))
    }
}

impl AsyncRead for OverlayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(current) = self.read_current.as_mut() {
                let length = current.len().min(destination.remaining());
                destination.put_slice(&current[..length]);
                current.advance(length);
                let empty = current.is_empty();
                if empty {
                    self.read_current = None;
                }
                let _ = self
                    .lifecycle
                    .command_tx
                    .send(StreamCommand::Consumed(length));
                return Poll::Ready(Ok(()));
            }
            match self.read_rx.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => self.read_current = Some(bytes),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for OverlayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let length = source.len().min(STREAM_DATA_BYTES);
                self.write_tx
                    .send_item(Bytes::copy_from_slice(&source[..length]))
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                self.write_tx.abort_send();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_tx.close();
        self.owned_write_tx.take();
        self.lifecycle.finish();
        Poll::Ready(Ok(()))
    }
}

fn earliest_timer_deadline<const N: usize>(deadlines: [Option<Instant>; N]) -> Option<Instant> {
    deadlines.into_iter().flatten().min()
}

async fn wait_for_timer(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline.into()).await,
        None => pending().await,
    }
}

fn request_ack(ack_pending: &mut bool, ack_deadline: &mut Option<Instant>, immediate: bool) {
    let deadline = Instant::now() + if immediate { Duration::ZERO } else { ACK_DELAY };
    if !*ack_pending || ack_deadline.is_none_or(|current| deadline < current) {
        *ack_deadline = Some(deadline);
    }
    *ack_pending = true;
}

fn ready_to_send_fin(finish_requested: bool, write_closed: bool, write_empty: bool) -> bool {
    finish_requested && write_closed && write_empty
}

fn remote_fin_complete(fin_sequence: Option<u64>, next_sequence: u64) -> bool {
    fin_sequence.is_some_and(|sequence| next_sequence >= sequence)
}

#[derive(Clone)]
pub struct OverlayStreamConnector {
    endpoint: Arc<OverlayStreamEndpoint>,
}

impl OverlayStreamConnector {
    pub async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<OverlayStream> {
        self.endpoint.connect(src, dst).await
    }
}

pub struct OverlayStreamEndpoint {
    peer_manager: Arc<PeerManager>,
    sessions: DashMap<SessionKey, mpsc::Sender<Frame>>,
    opening: DashSet<SessionKey>,
    next_stream_id: AtomicU64,
    accept_input: bool,
    direct_paths: DashMap<PeerId, Arc<PeerConn>>,
    cidr_set: Arc<CidrSet>,
    route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
}

impl OverlayStreamEndpoint {
    pub async fn start(peer_manager: Arc<PeerManager>, accept_input: bool) -> Arc<Self> {
        let seed = (u64::from(peer_manager.my_peer_id()) << 32) | 1;
        let endpoint = Arc::new(Self {
            cidr_set: Arc::new(CidrSet::new(peer_manager.get_global_ctx())),
            route: Arc::new(peer_manager.get_route()),
            peer_manager: peer_manager.clone(),
            sessions: DashMap::new(),
            opening: DashSet::new(),
            next_stream_id: AtomicU64::new(seed),
            accept_input,
            direct_paths: DashMap::new(),
        });
        peer_manager
            .add_packet_process_pipeline(Box::new(OverlayStreamPacketFilter {
                endpoint: Arc::downgrade(&endpoint),
            }))
            .await;
        endpoint
    }

    pub fn connector(self: &Arc<Self>) -> OverlayStreamConnector {
        OverlayStreamConnector {
            endpoint: self.clone(),
        }
    }

    async fn connect(
        self: &Arc<Self>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> anyhow::Result<OverlayStream> {
        let SocketAddr::V4(destination) = dst else {
            bail!("overlay streams currently support IPv4 destinations only");
        };
        let destination_peer = self
            .peer_manager
            .get_peer_map()
            .get_peer_id_by_ipv4(destination.ip())
            .await
            .ok_or_else(|| anyhow!("no peer found for overlay stream destination {dst}"))?;
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let metadata = QuicConnData {
            src: Some(src.into()),
            dst: Some(dst.into()),
        };
        let (stream, ready) = self.spawn_session(
            destination_peer,
            stream_id,
            true,
            Bytes::from(metadata.encode_to_vec()),
        );
        timeout(SESSION_TIMEOUT, ready)
            .await
            .context("overlay stream open timed out")?
            .map_err(|_| anyhow!("overlay stream open task stopped"))??;
        Ok(stream)
    }

    fn spawn_session(
        self: &Arc<Self>,
        remote_peer: PeerId,
        stream_id: u64,
        initiator: bool,
        open_payload: Bytes,
    ) -> (OverlayStream, oneshot::Receiver<anyhow::Result<()>>) {
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_QUEUE_PACKETS);
        let (write_tx, write_rx) = mpsc::channel(APP_WRITE_QUEUE_CHUNKS);
        let (read_tx, read_rx) = mpsc::channel(APP_READ_QUEUE_CHUNKS);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        self.sessions.insert((remote_peer, stream_id), frame_tx);
        let endpoint = self.clone();
        tokio::spawn(async move {
            endpoint
                .run_session(
                    remote_peer,
                    stream_id,
                    initiator,
                    open_payload,
                    frame_rx,
                    write_rx,
                    read_tx,
                    command_rx,
                    ready_tx,
                )
                .await;
            endpoint.sessions.remove(&(remote_peer, stream_id));
        });
        (OverlayStream::new(read_rx, write_tx, command_tx), ready_rx)
    }

    async fn handle_frame(self: &Arc<Self>, remote_peer: PeerId, frame: Frame) {
        let key = (remote_peer, frame.stream_id);
        if let Some(session) = self.sessions.get(&key) {
            let _ = session.try_send(frame);
            return;
        }
        if frame.kind != FrameKind::Open || !self.accept_input || !self.opening.insert(key) {
            if frame.kind == FrameKind::Open && !self.accept_input {
                let _ = self
                    .send_frame(
                        remote_peer,
                        Frame {
                            kind: FrameKind::Reset,
                            stream_id: frame.stream_id,
                            sequence: 0,
                            acknowledgement: 0,
                            receive_window: 0,
                            payload: Bytes::new(),
                        },
                    )
                    .await;
            }
            return;
        }
        let endpoint = self.clone();
        tokio::spawn(async move {
            let result = endpoint.accept_open(remote_peer, frame).await;
            endpoint.opening.remove(&key);
            if let Err(error) = result {
                tracing::warn!(
                    ?error,
                    remote_peer,
                    stream_id = key.1,
                    "overlay stream open failed"
                );
                let _ = endpoint
                    .send_frame(
                        remote_peer,
                        Frame {
                            kind: FrameKind::Reset,
                            stream_id: key.1,
                            sequence: 0,
                            acknowledgement: 0,
                            receive_window: 0,
                            payload: Bytes::new(),
                        },
                    )
                    .await;
            }
        });
    }

    async fn accept_open(
        self: &Arc<Self>,
        remote_peer: PeerId,
        frame: Frame,
    ) -> anyhow::Result<()> {
        let metadata = QuicConnData::decode(frame.payload.clone())?;
        let mut destination: SocketAddr = metadata
            .dst
            .ok_or_else(|| anyhow!("overlay stream destination is missing"))?
            .into();
        let source: SocketAddr = metadata.src.unwrap_or_default().into();
        if let IpAddr::V4(mapped) = destination.ip() {
            let mut real = mapped;
            if self.cidr_set.contains_v4(mapped, &mut real) {
                destination.set_ip(real.into());
            }
        }

        let global_ctx = self.peer_manager.get_global_ctx();
        if global_ctx.should_deny_proxy(&destination, false) {
            bail!("overlay stream destination {destination} is a LowTier listener");
        }
        let source_ip = source.ip();
        let destination_ip = destination.ip();
        let (source_groups, destination_groups) = tokio::join!(
            self.route.get_peer_groups_by_ip(&source_ip),
            self.route.get_peer_groups_by_ip(&destination_ip)
        );
        let send_to_self = global_ctx.is_ip_local_virtual_ip(&destination_ip);
        if send_to_self && global_ctx.no_tun() {
            destination.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        let acl = ProxyAclHandler {
            acl_filter: global_ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip: source_ip,
                dst_ip: destination_ip,
                src_port: Some(source.port()),
                dst_port: Some(destination.port()),
                protocol: Protocol::Tcp,
                packet_size: frame.payload.len(),
                src_groups: source_groups,
                dst_groups: destination_groups,
            },
            chain_type: if send_to_self {
                ChainType::Inbound
            } else {
                ChainType::Forward
            },
        };
        acl.handle_packet(&frame.payload)?;

        let _namespace = global_ctx.net_ns.guard();
        let destination_stream = TcpProxy::connect_nat_dst(destination).await?;
        drop(_namespace);

        let stream_id = frame.stream_id;
        let (stream, _ready) = self.spawn_session(remote_peer, stream_id, false, Bytes::new());
        tokio::spawn(async move {
            if let Err(error) = acl
                .copy_bidirection_with_acl(stream, destination_stream)
                .await
            {
                tracing::debug!(?error, stream_id, "overlay stream transfer ended");
            }
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session(
        &self,
        remote_peer: PeerId,
        stream_id: u64,
        initiator: bool,
        open_payload: Bytes,
        mut frame_rx: mpsc::Receiver<Frame>,
        mut write_rx: mpsc::Receiver<Bytes>,
        read_tx: mpsc::Sender<Bytes>,
        mut command_rx: mpsc::UnboundedReceiver<StreamCommand>,
        ready_tx: oneshot::Sender<anyhow::Result<()>>,
    ) {
        let mut receive = ReceiveWindow::new(STREAM_WINDOW_BYTES);
        let mut send = SendWindow::new(STREAM_WINDOW_BYTES);
        let mut sent_at = HashMap::<u64, Instant>::new();
        let mut remote_window = STREAM_WINDOW_BYTES;
        let mut opened = !initiator;
        let mut ready_tx = Some(ready_tx);
        let mut open_sent_at: Option<Instant> = None;
        let mut ack_pending = false;
        let mut ack_deadline = None;
        let mut last_acknowledgement = 0_u64;
        let mut last_advertised_window = STREAM_WINDOW_BYTES;
        let mut finish_requested = false;
        let mut local_fin = None;
        let mut fin_sent_at: Option<Instant> = None;
        let mut remote_fin_sequence = None;

        if !initiator {
            let _ = self
                .send_control(remote_peer, stream_id, FrameKind::OpenAck, 0, 0, &receive)
                .await;
            if let Some(ready) = ready_tx.take() {
                let _ = ready.send(Ok(()));
            }
        }

        loop {
            if local_fin.is_none()
                && ready_to_send_fin(finish_requested, write_rx.is_closed(), write_rx.is_empty())
            {
                local_fin = Some(send.next_sequence);
            }
            if initiator
                && !opened
                && open_sent_at.is_none_or(|sent| sent.elapsed() >= OPEN_RETRANSMIT_AFTER)
            {
                let _ = self
                    .send_frame(
                        remote_peer,
                        Frame {
                            kind: FrameKind::Open,
                            stream_id,
                            sequence: 0,
                            acknowledgement: receive.next_sequence(),
                            receive_window: receive.available_bytes() as u32,
                            payload: open_payload.clone(),
                        },
                    )
                    .await;
                open_sent_at = Some(Instant::now());
            }

            let retransmit_deadline = send
                .first_sequence()
                .and_then(|sequence| sent_at.get(&sequence).map(|sent| *sent + RETRANSMIT_AFTER));
            let open_deadline = (initiator && !opened)
                .then(|| open_sent_at.map(|sent| sent + OPEN_RETRANSMIT_AFTER))
                .flatten();
            let fin_deadline = local_fin.map(|_| {
                fin_sent_at
                    .map(|sent| sent + FIN_RETRANSMIT_AFTER)
                    .unwrap_or_else(Instant::now)
            });
            let timer_deadline = earliest_timer_deadline([
                ack_deadline,
                retransmit_deadline,
                open_deadline,
                fin_deadline,
            ]);

            let writable = opened
                && local_fin.is_none()
                && send.buffered_bytes() + STREAM_DATA_BYTES <= STREAM_WINDOW_BYTES
                && remote_window >= STREAM_DATA_BYTES;
            tokio::select! {
                biased;
                Some(frame) = frame_rx.recv() => {
                    remote_window = frame.receive_window as usize;
                    match frame.kind {
                        FrameKind::Open if !initiator => {
                            let _ = self.send_control(remote_peer, stream_id, FrameKind::OpenAck, 0, 0, &receive).await;
                        }
                        FrameKind::OpenAck if initiator => {
                            opened = true;
                            if let Some(ready) = ready_tx.take() {
                                let _ = ready.send(Ok(()));
                            }
                        }
                        FrameKind::Data => {
                            match receive.insert(frame.sequence, frame.payload) {
                                Ok(delivered) => {
                                    for bytes in delivered {
                                        if read_tx.send(bytes).await.is_err() {
                                            return;
                                        }
                                    }
                                    let immediate = receive
                                        .next_sequence()
                                        .saturating_sub(last_acknowledgement)
                                        >= ACK_BATCH_BYTES as u64;
                                    request_ack(&mut ack_pending, &mut ack_deadline, immediate);
                                }
                                Err(ReceiveWindowError::Full | ReceiveWindowError::Overlap) => {
                                    request_ack(&mut ack_pending, &mut ack_deadline, false);
                                }
                            }
                        }
                        FrameKind::Ack => {
                            send.acknowledge(frame.acknowledgement);
                            sent_at.retain(|sequence, _| send.get(*sequence).is_some());
                            if local_fin.is_some_and(|sequence| frame.acknowledgement > sequence) {
                                local_fin = None;
                                fin_sent_at = None;
                                if remote_fin_complete(remote_fin_sequence, receive.next_sequence()) {
                                    break;
                                }
                            }
                        }
                        FrameKind::Fin => {
                            remote_fin_sequence = Some(frame.sequence);
                            request_ack(&mut ack_pending, &mut ack_deadline, true);
                        }
                        FrameKind::Reset => {
                            if let Some(ready) = ready_tx.take() {
                                let _ = ready.send(Err(anyhow!("remote rejected overlay stream")));
                            }
                            break;
                        }
                        FrameKind::Open | FrameKind::OpenAck => {}
                    }
                }
                Some(bytes) = write_rx.recv(), if writable => {
                    if let Ok(sequence) = send.push(bytes.clone()) {
                        remote_window = remote_window.saturating_sub(bytes.len());
                        let _ = self.send_data(remote_peer, stream_id, sequence, bytes, &receive).await;
                        sent_at.insert(sequence, Instant::now());
                    }
                }
                Some(command) = command_rx.recv() => {
                    match command {
                        StreamCommand::Consumed(bytes) => {
                            receive.consume(bytes);
                            let immediate = receive.available_bytes().saturating_sub(last_advertised_window)
                                >= ACK_BATCH_BYTES;
                            request_ack(&mut ack_pending, &mut ack_deadline, immediate);
                        }
                        StreamCommand::Finish => finish_requested = true,
                        StreamCommand::Reset => {
                            let _ = self.send_control(remote_peer, stream_id, FrameKind::Reset, 0, 0, &receive).await;
                            break;
                        }
                    }
                }
                _ = wait_for_timer(timer_deadline) => {
                    let now = Instant::now();
                    let acknowledgement_due = ack_deadline.is_some_and(|deadline| deadline <= now);
                    if ack_pending && acknowledgement_due {
                        let complete = remote_fin_complete(remote_fin_sequence, receive.next_sequence());
                        let acknowledgement = receive.next_sequence() + u64::from(complete);
                        let _ = self.send_control(remote_peer, stream_id, FrameKind::Ack, 0, acknowledgement, &receive).await;
                        ack_pending = false;
                        ack_deadline = None;
                        last_acknowledgement = acknowledgement;
                        last_advertised_window = receive.available_bytes();
                        if complete && send.buffered_bytes() == 0 && local_fin.is_none() {
                            break;
                        }
                    }
                    let retransmission_due = retransmit_deadline.is_some_and(|deadline| deadline <= now);
                    if retransmission_due {
                        let retransmit = sent_at.iter()
                            .filter(|(_, sent)| sent.elapsed() >= RETRANSMIT_AFTER)
                            .map(|(sequence, _)| *sequence)
                            .collect::<Vec<_>>();
                        for sequence in retransmit {
                            if let Some(bytes) = send.get(sequence).cloned() {
                                let _ = self.send_data(remote_peer, stream_id, sequence, bytes, &receive).await;
                                sent_at.insert(sequence, Instant::now());
                            }
                        }
                    }
                    let fin_due = fin_deadline.is_some_and(|deadline| deadline <= now);
                    if fin_due && let Some(sequence) = local_fin {
                        let _ = self.send_control(remote_peer, stream_id, FrameKind::Fin, sequence, receive.next_sequence(), &receive).await;
                        fin_sent_at = Some(Instant::now());
                    }
                }
                else => break,
            }
        }
        if let Some(ready) = ready_tx.take() {
            let _ = ready.send(Err(anyhow!("overlay stream closed before opening")));
        }
    }

    async fn send_data(
        &self,
        remote_peer: PeerId,
        stream_id: u64,
        sequence: u64,
        payload: Bytes,
        receive: &ReceiveWindow,
    ) -> LowTierResult<()> {
        self.send_frame(
            remote_peer,
            Frame {
                kind: FrameKind::Data,
                stream_id,
                sequence,
                acknowledgement: receive.next_sequence(),
                receive_window: receive.available_bytes() as u32,
                payload,
            },
        )
        .await
    }

    async fn send_control(
        &self,
        remote_peer: PeerId,
        stream_id: u64,
        kind: FrameKind,
        sequence: u64,
        acknowledgement: u64,
        receive: &ReceiveWindow,
    ) -> LowTierResult<()> {
        self.send_frame(
            remote_peer,
            Frame {
                kind,
                stream_id,
                sequence,
                acknowledgement,
                receive_window: receive.available_bytes() as u32,
                payload: Bytes::new(),
            },
        )
        .await
    }

    fn packet_for_frame(&self, remote_peer: PeerId, frame: Frame) -> ZCPacket {
        let mut header = [0_u8; FRAME_HEADER_LEN];
        header[0] = PROTOCOL_VERSION;
        header[1] = frame.kind as u8;
        header[2..10].copy_from_slice(&frame.stream_id.to_be_bytes());
        header[10..18].copy_from_slice(&frame.sequence.to_be_bytes());
        header[18..26].copy_from_slice(&frame.acknowledgement.to_be_bytes());
        header[26..30].copy_from_slice(&frame.receive_window.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload_parts(&[&header, &frame.payload]);
        packet.fill_peer_manager_hdr(
            self.peer_manager.my_peer_id(),
            remote_peer,
            PacketType::OverlayStream as u8,
        );
        packet
    }

    async fn send_frame(&self, remote_peer: PeerId, frame: Frame) -> LowTierResult<()> {
        let packet = self.packet_for_frame(remote_peer, frame);
        let cached = self
            .direct_paths
            .get(&remote_peer)
            .map(|connection| connection.clone())
            .or_else(|| {
                let connection = self.peer_manager.only_direct_proxy_conn(remote_peer)?;
                self.direct_paths.insert(remote_peer, connection.clone());
                Some(connection)
            });
        if let Some(connection) = cached {
            let result = self
                .peer_manager
                .send_msg_for_proxy_on_conn(packet, remote_peer, &connection)
                .await;
            if result.is_err() {
                self.direct_paths
                    .remove_if(&remote_peer, |_, current| Arc::ptr_eq(current, &connection));
            }
            return result;
        }
        self.peer_manager
            .send_msg_for_proxy(packet, remote_peer)
            .await
    }
}

struct OverlayStreamPacketFilter {
    endpoint: Weak<OverlayStreamEndpoint>,
}

#[async_trait::async_trait]
impl PeerPacketFilter for OverlayStreamPacketFilter {
    fn is_interested_in_direct_nic_batch(
        &self,
        _batch: &crate::tunnel::batch::PacketBatch,
    ) -> bool {
        false
    }

    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header()?;
        if header.packet_type != PacketType::OverlayStream as u8 {
            return Some(packet);
        }
        let remote_peer = header.from_peer_id.get();
        let Some(endpoint) = self.endpoint.upgrade() else {
            return None;
        };
        match Frame::decode(packet.payload_bytes().freeze()) {
            Ok(frame) => endpoint.handle_frame(remote_peer, frame).await,
            Err(error) => tracing::debug!(?error, remote_peer, "invalid overlay stream frame"),
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn active_timer_has_no_idle_deadline_and_selects_the_earliest_work() {
        let now = Instant::now();
        assert_eq!(earliest_timer_deadline([None, None, None, None]), None);
        assert_eq!(
            earliest_timer_deadline([
                Some(now + Duration::from_millis(100)),
                Some(now + Duration::from_millis(1)),
                None,
                Some(now + Duration::from_millis(200)),
            ]),
            Some(now + Duration::from_millis(1))
        );
    }

    #[test]
    fn stream_chunk_stays_inside_the_conservative_ipv6_wire_budget() {
        assert_eq!(STREAM_DATA_BYTES, 1120);
        assert!(STREAM_DATA_BYTES + MAX_STREAM_WIRE_OVERHEAD_BYTES <= 1280);
    }

    #[test]
    fn receive_window_delivers_owned_bytes_in_order_and_rejects_overflow() {
        let mut window = ReceiveWindow::new(8);

        assert!(
            window
                .insert(4, Bytes::from_static(b"efgh"))
                .unwrap()
                .is_empty()
        );
        let delivered = window.insert(0, Bytes::from_static(b"abcd")).unwrap();
        assert_eq!(
            delivered,
            [Bytes::from_static(b"abcd"), Bytes::from_static(b"efgh")]
        );
        assert_eq!(window.next_sequence(), 8);
        assert_eq!(window.buffered_bytes(), 8);
        assert!(matches!(
            window.insert(8, Bytes::from_static(b"x")),
            Err(ReceiveWindowError::Full)
        ));

        window.consume(5);
        assert_eq!(window.available_bytes(), 5);
    }

    #[test]
    fn send_window_is_byte_bounded_and_cumulative_ack_releases_ownership() {
        let mut window = SendWindow::new(8);
        let first = Bytes::from_static(b"abcd");
        let second = Bytes::from_static(b"efgh");
        assert_eq!(window.push(first.clone()).unwrap(), 0);
        assert_eq!(window.push(second.clone()).unwrap(), 4);
        assert!(window.push(Bytes::from_static(b"x")).is_err());
        assert_eq!(window.buffered_bytes(), 8);
        assert_eq!(window.get(0).unwrap().as_ptr(), first.as_ptr());

        window.acknowledge(4);
        assert_eq!(window.buffered_bytes(), 4);
        assert_eq!(window.get(4).unwrap().as_ptr(), second.as_ptr());
    }

    #[test]
    fn retained_bytes_recover_a_dropped_chunk_after_reordering() {
        let mut send = SendWindow::new(8);
        let first = Bytes::from_static(b"abcd");
        let second = Bytes::from_static(b"efgh");
        send.push(first.clone()).unwrap();
        send.push(second.clone()).unwrap();

        let mut receive = ReceiveWindow::new(8);
        assert!(receive.insert(4, second).unwrap().is_empty());
        let retransmitted = send.get(0).unwrap().clone();
        assert_eq!(retransmitted.as_ptr(), first.as_ptr());
        assert_eq!(
            receive.insert(0, retransmitted).unwrap(),
            [Bytes::from_static(b"abcd"), Bytes::from_static(b"efgh")]
        );

        send.acknowledge(receive.next_sequence());
        assert_eq!(send.buffered_bytes(), 0);
    }

    #[test]
    fn finish_waits_until_the_owned_write_queue_is_closed_and_drained() {
        assert!(!ready_to_send_fin(true, false, true));
        assert!(!ready_to_send_fin(true, true, false));
        assert!(!ready_to_send_fin(false, true, true));
        assert!(ready_to_send_fin(true, true, true));
    }

    #[tokio::test]
    async fn standard_shutdown_closes_every_owned_write_sender() {
        let (write_tx, mut write_rx) = mpsc::channel(1);
        let (_read_tx, read_rx) = mpsc::channel(1);
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let mut stream = OverlayStream::new(read_rx, write_tx, command_tx);

        stream.shutdown().await.unwrap();

        assert!(
            timeout(Duration::from_millis(10), write_rx.recv())
                .await
                .expect("shutdown must close the write queue")
                .is_none()
        );
    }

    #[test]
    fn remote_fin_waits_for_every_lower_sequence_byte() {
        assert!(!remote_fin_complete(Some(1024), 900));
        assert!(remote_fin_complete(Some(1024), 1024));
        assert!(!remote_fin_complete(None, 1024));
    }

    #[test]
    fn frame_round_trip_keeps_payload_owned_and_validates_version() {
        let frame = Frame {
            kind: FrameKind::Data,
            stream_id: 9,
            sequence: 12,
            acknowledgement: 7,
            receive_window: 4096,
            payload: Bytes::from_static(b"owned"),
        };
        let encoded = frame.encode();
        let decoded = Frame::decode(encoded.clone()).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(
            decoded.payload.as_ptr(),
            encoded[FRAME_HEADER_LEN..].as_ptr()
        );

        let mut invalid = encoded.to_vec();
        invalid[0] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            Frame::decode(Bytes::from(invalid)),
            Err(FrameDecodeError::Version)
        ));
    }
}
