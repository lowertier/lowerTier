use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use atomic_shim::AtomicU64;
use futures::{Sink, SinkExt, Stream, StreamExt, task::AtomicWaker};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout};

use super::{
    BatchStreamItem, PacketBatchSink, PacketBatchStream, SplitTunnel, TransportBinding,
    TransportBindingKind, Tunnel, TunnelError, TunnelInfo,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    packet_def::{PacketType, ZCPacket},
};

pub(super) const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_JOINS: usize = 32;
const MAX_TRACKED_FLOWS: usize = 256;
pub(super) const MAX_PENDING_BYTES: usize = MAX_PACKET_BATCH_SIZE * 4096;
const RECORD_BYTES: usize = 54;
const DOMAIN: &[u8] = b"LowTier TCP lanes v1";
type JoinId = [u8; 16];

pub(super) fn requested(url: &url::Url) -> Result<usize, TunnelError> {
    let mut values = url.query_pairs().filter(|(key, _)| key == "lanes");
    let count = match values.next() {
        None => return Ok(1),
        Some((_, value)) if value == "1" => 1,
        Some((_, value)) if value == "2" => 2,
        Some((_, value)) if value == "4" => 4,
        _ => return Err(TunnelError::InvalidAddr("lanes must be 1, 2 or 4".into())),
    };
    if values.next().is_some() {
        return Err(TunnelError::InvalidAddr("duplicate lanes option".into()));
    }
    if count > 1 && !(url.scheme() == "wss" || (cfg!(feature = "quic") && url.scheme() == "tcp")) {
        return Err(TunnelError::InvalidAddr(
            "TCP lanes require end-to-end TLS".into(),
        ));
    }
    if count > 1
        && url.query_pairs().any(|(key, value)| {
            key == "via"
                && (value.eq_ignore_ascii_case("cdn") || value.eq_ignore_ascii_case("proxy"))
        })
    {
        return Err(TunnelError::InvalidAddr(
            "TCP lanes require end-to-end TLS".into(),
        ));
    }
    Ok(count)
}

struct Lane {
    tunnel: Box<dyn Tunnel>,
    recv: Pin<Box<dyn PacketBatchStream>>,
    send: Pin<Box<dyn PacketBatchSink>>,
    binding: TransportBinding,
}

impl Lane {
    fn new(tunnel: Box<dyn Tunnel>) -> Result<Self, TunnelError> {
        let binding = tunnel
            .transport_binding()
            .ok_or_else(|| TunnelError::InvalidProtocol("TCP lane has no TLS exporter".into()))?;
        binding_code(binding)?;
        let (recv, send) = tunnel.split();
        Ok(Self {
            tunnel,
            recv,
            send,
            binding,
        })
    }

    async fn read_record(&mut self) -> Result<[u8; RECORD_BYTES], TunnelError> {
        let batch = self.recv.next().await.ok_or(TunnelError::Shutdown)??;
        let packet = batch.pop_singleton().map_err(|_| {
            TunnelError::InvalidPacket("TCP lane join must contain one record".into())
        })?;
        let record: [u8; RECORD_BYTES] = packet
            .payload()
            .try_into()
            .map_err(|_| TunnelError::InvalidPacket("invalid TCP lane join length".into()))?;
        if &record[..4] != b"LTL2" || !matches!(record[5], 2 | 4) || record[4] & 0x7f >= record[5] {
            return Err(TunnelError::InvalidProtocol(
                "invalid TCP lane join version or role".into(),
            ));
        }
        Ok(record)
    }

    async fn write_record(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), TunnelError> {
        self.send
            .send(PacketBatch::singleton(ZCPacket::new_with_payload(record)))
            .await
    }
}

fn binding_code(binding: TransportBinding) -> Result<u8, TunnelError> {
    match binding.kind {
        TransportBindingKind::Http2TlsExporterV1 => Ok(1),
        TransportBindingKind::WssTlsExporterV1 => Ok(2),
        _ => Err(TunnelError::InvalidProtocol(
            "unsupported TCP lane binding".into(),
        )),
    }
}

fn join_mac(
    primary: TransportBinding,
    other: TransportBinding,
    role: u8,
    count: u8,
    id: JoinId,
) -> Result<Hmac<Sha256>, TunnelError> {
    if primary.kind != other.kind {
        return Err(TunnelError::InvalidProtocol(
            "TCP lane binding kinds differ".into(),
        ));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&primary.bytes).expect("fixed HMAC key length");
    mac.update(DOMAIN);
    mac.update(&[role, count, binding_code(primary)?]);
    mac.update(&id);
    mac.update(&other.bytes);
    Ok(mac)
}

fn join_record(
    primary: TransportBinding,
    other: TransportBinding,
    role: u8,
    count: u8,
    id: JoinId,
) -> Result<[u8; RECORD_BYTES], TunnelError> {
    let mut record = [0; RECORD_BYTES];
    record[..4].copy_from_slice(b"LTL2");
    record[4] = role;
    record[5] = count;
    record[6..22].copy_from_slice(&id);
    record[22..].copy_from_slice(
        &join_mac(primary, other, role, count, id)?
            .finalize()
            .into_bytes(),
    );
    Ok(record)
}

fn verify_record(
    record: &[u8; RECORD_BYTES],
    primary: TransportBinding,
    other: TransportBinding,
    role: u8,
    count: u8,
    id: JoinId,
) -> Result<(), TunnelError> {
    if &record[..4] != b"LTL2" || record[4] != role || record[5] != count || record[6..22] != id {
        return Err(TunnelError::InvalidPacket(
            "TCP lane join transcript mismatch".into(),
        ));
    }
    join_mac(primary, other, role, count, id)?
        .verify_slice(&record[22..])
        .map_err(|_| TunnelError::InvalidPacket("TCP lane join authentication failed".into()))
}

struct PendingJoin {
    lanes: Vec<Lane>,
    deadline: Instant,
}

#[derive(Default)]
pub(super) struct LaneListener {
    pending: HashMap<JoinId, PendingJoin>,
}

impl LaneListener {
    pub(super) fn expire(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, join| join.deadline > now);
    }

    pub(super) async fn accept(
        &mut self,
        tunnel: Box<dyn Tunnel>,
        count: usize,
    ) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
        self.expire();
        timeout(JOIN_TIMEOUT, async {
            let mut lane = Lane::new(tunnel)?;
            let record = lane.read_record().await?;
            if usize::from(record[5]) != count || record[4] & 0x80 != 0 {
                return Err(TunnelError::InvalidProtocol(
                    "TCP lane count or role mismatch".into(),
                ));
            }
            let index = record[4];
            let id: JoinId = record[6..22].try_into().expect("fixed join id length");
            if index == 0 {
                verify_record(&record, lane.binding, lane.binding, 0, count as u8, id)?;
                if self.pending.len() >= MAX_PENDING_JOINS || self.pending.contains_key(&id) {
                    return Err(TunnelError::InvalidPacket(
                        "TCP lane join is duplicate or full".into(),
                    ));
                }
                let reply = join_record(lane.binding, lane.binding, 0x80, count as u8, id)?;
                lane.write_record(&reply).await?;
                let mut lanes = Vec::with_capacity(count);
                lanes.push(lane);
                self.pending.insert(
                    id,
                    PendingJoin {
                        lanes,
                        deadline: Instant::now() + JOIN_TIMEOUT,
                    },
                );
                return Ok(None);
            }
            let pending = self
                .pending
                .get(&id)
                .filter(|join| {
                    join.deadline > Instant::now() && join.lanes.len() == usize::from(index)
                })
                .ok_or_else(|| {
                    TunnelError::InvalidPacket(
                        "unknown, expired or out-of-order TCP lane join".into(),
                    )
                })?;
            let primary = pending.lanes[0].binding;
            verify_record(&record, primary, lane.binding, index, count as u8, id)?;
            // Authentication precedes all mutation of another connection's group.
            let reply = join_record(primary, lane.binding, index | 0x80, count as u8, id)?;
            lane.write_record(&reply).await?;
            let pending = self.pending.get_mut(&id).expect("verified pending join");
            pending.lanes.push(lane);
            if pending.lanes.len() == count {
                let pending = self.pending.remove(&id).expect("complete lane group");
                Ok(Some(TcpLanes::wrap(pending.lanes, id)?))
            } else {
                Ok(None)
            }
        })
        .await?
    }
}

pub(super) async fn connect<F, Fut>(
    count: usize,
    mut connect_lane: F,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Box<dyn Tunnel>, TunnelError>>,
{
    if !matches!(count, 2 | 4) {
        return Err(TunnelError::InvalidAddr(
            "TCP lane count must be 2 or 4".into(),
        ));
    }
    timeout(JOIN_TIMEOUT, async {
        let id = rand::random::<JoinId>();
        let mut lanes: Vec<Lane> = Vec::with_capacity(count);
        for index in 0..count {
            let mut lane = Lane::new(connect_lane().await?)?;
            let primary = lanes.first().map_or(lane.binding, |lane| lane.binding);
            let record = join_record(primary, lane.binding, index as u8, count as u8, id)?;
            lane.write_record(&record).await?;
            let reply = lane.read_record().await?;
            verify_record(
                &reply,
                primary,
                lane.binding,
                index as u8 | 0x80,
                count as u8,
                id,
            )?;
            lanes.push(lane);
        }
        TcpLanes::wrap(lanes, id)
    })
    .await?
}

#[derive(Default)]
struct LaneState {
    failed: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    tx_bytes: [AtomicU64; 4],
    rx_bytes: [AtomicU64; 4],
}

impl LaneState {
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.read_waker.wake();
        self.write_waker.wake();
    }
}

struct TcpLanes {
    halves: Mutex<Option<SplitTunnel>>,
    tunnels: Vec<Box<dyn Tunnel>>,
    binding: TransportBinding,
    state: Arc<LaneState>,
}

impl TcpLanes {
    fn wrap(lanes: Vec<Lane>, id: JoinId) -> Result<Box<dyn Tunnel>, TunnelError> {
        let count = lanes.len();
        if !matches!(count, 2 | 4) {
            return Err(TunnelError::InvalidProtocol(
                "incomplete TCP lane group".into(),
            ));
        }
        let kind = lanes[0].binding.kind;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update([count as u8, binding_code(lanes[0].binding)?]);
        digest.update(id);
        let mut tunnels = Vec::with_capacity(count);
        let mut readers = Vec::with_capacity(count);
        let mut writers = Vec::with_capacity(count);
        let mut pending = Vec::with_capacity(count);
        for lane in lanes {
            if lane.binding.kind != kind {
                return Err(TunnelError::InvalidProtocol(
                    "TCP lane binding kinds differ".into(),
                ));
            }
            digest.update(lane.binding.bytes);
            tunnels.push(lane.tunnel);
            readers.push(lane.recv);
            writers.push(lane.send);
            pending.push(PacketBatch::new());
        }
        let binding = TransportBinding {
            kind: TransportBindingKind::TlsExporterLanesV1,
            bytes: digest.finalize().into(),
        };
        let state = Arc::new(LaneState::default());
        let reader = LaneReader {
            lanes: readers,
            next: 0,
            ended: false,
            state: state.clone(),
        };
        let writer = LaneWriter {
            lanes: writers,
            pending,
            closed: vec![false; count],
            flow_lanes: HashMap::with_capacity(MAX_TRACKED_FLOWS),
            next_lane: 0,
            state: state.clone(),
        };
        Ok(Box::new(Self {
            halves: Mutex::new(Some((Box::pin(reader), Box::pin(writer)))),
            tunnels,
            binding,
            state,
        }))
    }
}

impl Tunnel for TcpLanes {
    fn split(&self) -> SplitTunnel {
        self.halves
            .lock()
            .unwrap()
            .take()
            .expect("TCP lanes split once")
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.tunnels[0].info()
    }

    fn transport_binding(&self) -> Option<TransportBinding> {
        Some(self.binding)
    }
}

impl Drop for TcpLanes {
    fn drop(&mut self) {
        self.state.fail();
        tracing::info!(target: "CORE",
            tx_lane0 = self.state.tx_bytes[0].load(Ordering::Relaxed),
            tx_lane1 = self.state.tx_bytes[1].load(Ordering::Relaxed),
            rx_lane0 = self.state.rx_bytes[0].load(Ordering::Relaxed),
            rx_lane1 = self.state.rx_bytes[1].load(Ordering::Relaxed),
            tx_lane2 = self.state.tx_bytes[2].load(Ordering::Relaxed),
            tx_lane3 = self.state.tx_bytes[3].load(Ordering::Relaxed),
            rx_lane2 = self.state.rx_bytes[2].load(Ordering::Relaxed),
            rx_lane3 = self.state.rx_bytes[3].load(Ordering::Relaxed),
            "TCP lanes closed");
    }
}

struct LaneReader {
    lanes: Vec<Pin<Box<dyn PacketBatchStream>>>,
    next: usize,
    ended: bool,
    state: Arc<LaneState>,
}

impl Stream for LaneReader {
    type Item = BatchStreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        self.state.read_waker.register(cx.waker());
        if self.state.failed.load(Ordering::Acquire) {
            self.ended = true;
            return Poll::Ready(Some(Err(TunnelError::Shutdown)));
        }
        let first = self.next;
        for offset in 0..self.lanes.len() {
            let index = (first + offset) & (self.lanes.len() - 1);
            match self.lanes[index].as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) => {
                    self.next = (index + 1) & (self.lanes.len() - 1);
                    self.state.rx_bytes[index]
                        .fetch_add(batch.buffer_byte_len() as u64, Ordering::Relaxed);
                    return Poll::Ready(Some(Ok(batch)));
                }
                Poll::Ready(result) => {
                    self.ended = true;
                    self.state.fail();
                    return Poll::Ready(Some(result.unwrap_or(Err(TunnelError::Shutdown))));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

impl Drop for LaneReader {
    fn drop(&mut self) {
        self.state.fail();
    }
}

struct LaneWriter {
    lanes: Vec<Pin<Box<dyn PacketBatchSink>>>,
    pending: Vec<PacketBatch>,
    closed: Vec<bool>,
    flow_lanes: HashMap<u64, u8>,
    next_lane: u8,
    state: Arc<LaneState>,
}

impl LaneWriter {
    fn packet_lane(&mut self, packet: &ZCPacket) -> usize {
        let Some(header) = packet.peer_manager_header() else {
            return 0;
        };
        // Ciphertext and control traffic keep their existing replay domain.
        if header.is_encrypted()
            || header.forward_counter != 1
            || header.is_critical_l2_control()
            || !matches!(header.packet_type, p if p == PacketType::Data as u8 || p == PacketType::Ethernet as u8)
        {
            return 0;
        }
        // Reparse the cleartext tuple: the wire shard has only six bits, and
        // the optional cached hash may describe an earlier Ethernet encoding.
        let hash = if header.is_compressed() {
            let Some(hash) = packet.flow_hash() else {
                return 0;
            };
            hash
        } else {
            crate::peers::flow::classify_payload_flow(packet.payload(), header.packet_type).hash
        };
        if let Some(lane) = self.flow_lanes.get(&hash) {
            return usize::from(*lane);
        }
        if self.flow_lanes.len() == MAX_TRACKED_FLOWS {
            // Never evict an assigned flow while older packets may be in flight.
            // Once full, new flows use this stable mapping for the group lifetime.
            return ((hash.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32) as usize)
                & (self.lanes.len() - 1);
        }
        let lane = self.next_lane;
        self.flow_lanes.insert(hash, lane);
        self.next_lane = (lane + 1) & (self.lanes.len() as u8 - 1);
        usize::from(lane)
    }

    fn poll_lanes(&mut self, cx: &mut Context<'_>, flush: bool) -> Poll<Result<(), TunnelError>> {
        self.state.write_waker.register(cx.waker());
        if self.state.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(TunnelError::Shutdown));
        }
        let mut pending = false;
        for index in 0..self.lanes.len() {
            if self.closed[index] {
                continue;
            }
            if !self.pending[index].is_empty() {
                match self.lanes[index].as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let batch = std::mem::take(&mut self.pending[index]);
                        let bytes = batch.buffer_byte_len() as u64;
                        if let Err(error) = self.lanes[index].as_mut().start_send(batch) {
                            self.state.fail();
                            return Poll::Ready(Err(error));
                        }
                        self.state.tx_bytes[index].fetch_add(bytes, Ordering::Relaxed);
                    }
                    Poll::Ready(Err(error)) => {
                        self.state.fail();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => {
                        pending = true;
                        continue;
                    }
                }
            }
            if flush {
                match self.lanes[index].as_mut().poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => {
                        self.state.fail();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending && !flush {
            // A blocked lane must not strand buffered ACK/control frames on
            // its siblings. Readiness still does not wait for their flushes.
            for index in 0..self.lanes.len() {
                if self.closed[index] || !self.pending[index].is_empty() {
                    continue;
                }
                if let Poll::Ready(Err(error)) = self.lanes[index].as_mut().poll_flush(cx) {
                    self.state.fail();
                    return Poll::Ready(Err(error));
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl Sink<PacketBatch> for LaneWriter {
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_lanes(cx, false)
    }

    fn start_send(mut self: Pin<&mut Self>, mut batch: PacketBatch) -> Result<(), Self::Error> {
        if self.state.failed.load(Ordering::Acquire) || self.closed.iter().any(|closed| *closed) {
            return Err(TunnelError::Shutdown);
        }
        if self.pending.iter().any(|batch| !batch.is_empty()) {
            return Err(TunnelError::BufferFull);
        }
        if batch.retained_buffer_capacity() > MAX_PENDING_BYTES {
            for packet in batch.iter_mut() {
                packet.compact_retained_buffer();
            }
            if batch.retained_buffer_capacity() > MAX_PENDING_BYTES {
                return Err(TunnelError::ExceedMaxPacketSize(
                    MAX_PENDING_BYTES,
                    batch.retained_buffer_capacity(),
                ));
            }
        }
        for packet in batch {
            let index = self.packet_lane(&packet);
            self.pending[index]
                .try_push(packet)
                .expect("a lane partition fits its input batch");
        }
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_lanes(cx, true)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_lanes(cx, true))?;
        let mut pending = false;
        for index in 0..self.lanes.len() {
            if self.closed[index] {
                continue;
            }
            match self.lanes[index].as_mut().poll_close(cx) {
                Poll::Ready(Ok(())) => self.closed[index] = true,
                Poll::Ready(Err(error)) => {
                    self.state.fail();
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => pending = true,
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl Drop for LaneWriter {
    fn drop(&mut self) {
        self.state.fail();
    }
}

#[cfg(test)]
mod tests;
