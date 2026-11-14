//! Transport-agnostic multipath packet scheduler, active path prober, and destination reorder
//! buffer.
//!
//! Works uniformly across `quic`, `h2`, `wss`, and mixed-transport relay chains using:
//! - Universal queue pressure + drain-rate estimation from `DirectTunnelSender::queue_snapshot()`,
//! - End-to-end encrypted `PathProbe` / `PathProbeAck` RTT tracking (`ΔOWD` invariant on asymmetric paths),
//! - BLEST head-of-line blocking guard to skip stalled relays,
//! - Burstlet sticky deficit round-robin to preserve intra-burst ordering and saturate multiple relays,
//! - Zero-overhead in-order fast path and lazy `Box` ring reorder buffer at the destination.

use std::{
    collections::VecDeque,
    sync::{
        OnceLock,
        atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use parking_lot::Mutex;
use quanta::Instant;
use smallvec::SmallVec;
use tokio::sync::Notify;

use crate::{
    common::PeerId,
    peers::{
        path_policy::{CandidateChain, MAX_ACTIVE_CHAINS, MAX_LAYERS},
        peer_map::PeerMap,
        route_trait::NextHopPolicy,
    },
    tunnel::{
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::{PacketType, ZCPacket},
    },
};

pub const PATH_PROBE_MAGIC: [u8; 4] = *b"LTPP";
pub const PATH_PROBE_SIZE: usize = 16;

const SHARD_COUNT: usize = 64;
const MAX_FLOWS_PER_SHARD: usize = 64;
const MAX_CHAIN_METRICS: usize = 2048;

const BURSTLET_MAX_PACKETS: u8 = 8;
const BURSTLET_MAX_BYTES: u32 = 12_288;
const REORDER_BUDGET_US: u64 = 15_000;
const PROBE_INTERVAL_US: u64 = 2_000_000;
const MAX_PROBES_PER_BATCH: usize = 4;

const FLOW_RING_CAP: usize = 512;
const MAX_GLOBAL_REORDER_PACKETS: usize = 8192;
pub const REORDER_GAP_TIMEOUT: Duration = Duration::from_millis(20);
pub const REORDER_FLUSH_TICK: Duration = Duration::from_millis(3);
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

static MONO_EPOCH: OnceLock<Instant> = OnceLock::new();

pub(crate) fn now_mono_us() -> u64 {
    let base = MONO_EPOCH.get_or_init(Instant::now);
    u64::try_from(Instant::now().saturating_duration_since(*base).as_micros()).unwrap_or(u64::MAX)
}

pub(crate) fn build_path_probe_packet(
    my_peer_id: PeerId,
    dst_peer_id: PeerId,
    path_id: u8,
    nonce: u32,
) -> ZCPacket {
    let mut payload = [0_u8; PATH_PROBE_SIZE];
    let sent_us = (now_mono_us() & 0xffff_ffff) as u32;
    payload[..4].copy_from_slice(&PATH_PROBE_MAGIC);
    payload[4] = path_id;
    payload[5] = 0;
    payload[6..8].copy_from_slice(&0_u16.to_le_bytes());
    payload[8..12].copy_from_slice(&nonce.to_le_bytes());
    payload[12..16].copy_from_slice(&sent_us.to_le_bytes());
    let mut pkt = ZCPacket::new_with_payload(&payload);
    pkt.fill_peer_manager_hdr(my_peer_id, dst_peer_id, PacketType::PathProbe as u8);
    pkt
}

pub(crate) fn build_path_probe_ack(
    my_peer_id: PeerId,
    requester_peer_id: PeerId,
    probe_payload: &[u8],
) -> Option<ZCPacket> {
    if probe_payload.len() != PATH_PROBE_SIZE || probe_payload[..4] != PATH_PROBE_MAGIC {
        return None;
    }
    let mut pkt = ZCPacket::new_with_payload(probe_payload);
    pkt.fill_peer_manager_hdr(
        my_peer_id,
        requester_peer_id,
        PacketType::PathProbeAck as u8,
    );
    Some(pkt)
}

pub(crate) fn parse_path_probe_ack(payload: &[u8]) -> Option<(u8, u32)> {
    if payload.len() != PATH_PROBE_SIZE || payload[..4] != PATH_PROBE_MAGIC {
        return None;
    }
    let path_id = payload[4];
    let sent_us = u32::from_le_bytes(payload[12..16].try_into().ok()?);
    let now_us = (now_mono_us() & 0xffff_ffff) as u32;
    let rtt_us = now_us.wrapping_sub(sent_us);
    (rtt_us < 30_000_000).then_some((path_id, rtt_us))
}

#[inline]
fn fold_flow_tag(flow_hash: u64) -> u32 {
    let mixed = flow_hash ^ (flow_hash >> 32);
    (mixed as u32).max(1)
}

#[inline]
fn shard_index(peer_id: PeerId, tag: u32) -> usize {
    let mut x = (u64::from(peer_id) << 32) | u64::from(tag);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    (x as usize) & (SHARD_COUNT - 1)
}

#[derive(Default)]
struct ChainMetrics {
    srtt_us: AtomicU32,
    rttvar_us: AtomicU32,
    last_probe_us: AtomicU64,
    packets: AtomicU64,
    deficit: AtomicI64,
}

impl ChainMetrics {
    fn record_rtt(&self, sample_us: u32) {
        let sample = sample_us.max(1);
        let prev = self.srtt_us.load(Ordering::Relaxed);
        if prev == 0 {
            self.srtt_us.store(sample, Ordering::Relaxed);
            self.rttvar_us.store(sample / 2, Ordering::Relaxed);
        } else {
            let diff = prev.abs_diff(sample);
            let next_srtt = ((u64::from(prev) * 7 + u64::from(sample)) / 8) as u32;
            let prev_var = self.rttvar_us.load(Ordering::Relaxed);
            let next_var = ((u64::from(prev_var) * 3 + u64::from(diff)) / 4) as u32;
            self.srtt_us.store(next_srtt.max(1), Ordering::Relaxed);
            self.rttvar_us.store(next_var, Ordering::Relaxed);
        }
    }
}

struct FlowTxState {
    flow_tag: u32,
    dst_peer_id: PeerId,
    next_seq: u32,
    active_hops: SmallVec<[PeerId; MAX_LAYERS]>,
    burst_packets: u8,
    burst_bytes: u32,
    last_tx: Instant,
}

pub struct MultipathSender {
    my_peer_id: PeerId,
    chains: DashMap<(PeerId, SmallVec<[PeerId; MAX_LAYERS]>), std::sync::Arc<ChainMetrics>>,
    probe_routes: DashMap<(PeerId, u8), SmallVec<[PeerId; MAX_LAYERS]>>,
    flows: Vec<Mutex<VecDeque<FlowTxState>>>,
    next_nonce: AtomicU32,
}

impl MultipathSender {
    pub fn new(my_peer_id: PeerId) -> Self {
        let flows = (0..SHARD_COUNT)
            .map(|_| Mutex::new(VecDeque::new()))
            .collect();
        Self {
            my_peer_id,
            chains: DashMap::new(),
            probe_routes: DashMap::new(),
            flows,
            next_nonce: AtomicU32::new(1),
        }
    }

    fn metrics_for(&self, dst_peer_id: PeerId, hops: &[PeerId]) -> std::sync::Arc<ChainMetrics> {
        let key = (dst_peer_id, SmallVec::from_slice(hops));
        if let Some(entry) = self.chains.get(&key) {
            return entry.clone();
        }
        if self.chains.len() >= MAX_CHAIN_METRICS {
            let remove_key = self.chains.iter().next().map(|entry| entry.key().clone());
            if let Some(oldest) = remove_key {
                self.chains.remove(&oldest);
            }
        }
        self.chains
            .entry(key)
            .or_insert_with(|| std::sync::Arc::new(ChainMetrics::default()))
            .clone()
    }

    pub fn record_probe_ack(&self, from_peer_id: PeerId, payload: &[u8]) {
        let Some((path_id, rtt_us)) = parse_path_probe_ack(payload) else {
            return;
        };
        let Some(hops) = self
            .probe_routes
            .get(&(from_peer_id, path_id))
            .map(|entry| entry.clone())
        else {
            return;
        };
        self.metrics_for(from_peer_id, &hops).record_rtt(rtt_us);
    }

    pub fn chain_telemetry(
        &self,
        dst_peer_id: Option<PeerId>,
        _path_id: u8,
        hops: &[PeerId],
    ) -> (u32, u64, u64, bool) {
        if let Some(dst) = dst_peer_id
            && let Some(metrics) = self.chains.get(&(dst, SmallVec::from_slice(hops)))
        {
            return (
                metrics.srtt_us.load(Ordering::Relaxed),
                0,
                metrics.packets.load(Ordering::Relaxed),
                true,
            );
        }
        let mut best_rtt = 0_u32;
        let mut total_packets = 0_u64;
        for entry in self.chains.iter() {
            if entry.key().1.as_slice() == hops {
                total_packets =
                    total_packets.saturating_add(entry.value().packets.load(Ordering::Relaxed));
                let rtt = entry.value().srtt_us.load(Ordering::Relaxed);
                if rtt > 0 && (best_rtt == 0 || rtt < best_rtt) {
                    best_rtt = rtt;
                }
            }
        }
        (best_rtt, 0, total_packets, true)
    }

    #[cfg(test)]
    pub(crate) fn set_chain_srtt_for_test(
        &self,
        dst_peer_id: PeerId,
        hops: &[PeerId],
        srtt_us: u32,
    ) {
        self.metrics_for(dst_peer_id, hops)
            .srtt_us
            .store(srtt_us, Ordering::Relaxed);
    }

    /// Assign a per-flow sequence proof to `packet`, select a chain via BLEST + burstlet weighted
    /// deficit round-robin, and collect any due active `PathProbe` packets.
    #[allow(clippy::too_many_arguments)]
    pub fn assign_packet(
        &self,
        peer_map: &PeerMap,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        chains: &[CandidateChain],
        packet: &mut ZCPacket,
        flow_hash: u64,
        probes_out: &mut SmallVec<[(CandidateChain, ZCPacket); MAX_PROBES_PER_BATCH]>,
    ) -> usize {
        debug_assert!(!chains.is_empty());
        let packet_bytes = packet.buf_len().max(1);
        let flow_tag = fold_flow_tag(flow_hash);

        let count = chains.len().min(MAX_ACTIVE_CHAINS);
        let mut arrival_us = [u64::MAX; MAX_ACTIVE_CHAINS];
        let mut saturated = [false; MAX_ACTIVE_CHAINS];
        let mut metrics = SmallVec::<[std::sync::Arc<ChainMetrics>; MAX_ACTIVE_CHAINS]>::new();

        let now_us = now_mono_us();
        let mut min_arrival = u64::MAX;
        for (i, chain) in chains.iter().take(count).enumerate() {
            let m = self.metrics_for(dst_peer_id, &chain.hops);
            let srtt = m.srtt_us.load(Ordering::Relaxed);
            let link_state =
                peer_map.first_hop_link_state(chain.hops[0], flow_hash, policy.clone());
            let (snap, first_hop_rtt_us) = link_state.unwrap_or_default();
            let base_rtt = if srtt > 0 {
                u64::from(srtt)
            } else {
                u64::from(first_hop_rtt_us).max(1_000)
            };
            let queue_delay_us = if snap.drain_rate_bps > 1.0 {
                ((snap.queued_bytes as f64) * 8_000_000.0 / snap.drain_rate_bps) as u64
            } else {
                (snap.queued_bytes as u64) / 128
            };
            let est = base_rtt.saturating_add(queue_delay_us);
            arrival_us[i] = est;
            saturated[i] = snap.saturated;
            if !saturated[i] && est < min_arrival {
                min_arrival = est;
            }
            if probes_out.len() < MAX_PROBES_PER_BATCH {
                let last_probe = m.last_probe_us.load(Ordering::Relaxed);
                if (last_probe == 0 || now_us.saturating_sub(last_probe) >= PROBE_INTERVAL_US)
                    && m.last_probe_us
                        .compare_exchange(
                            last_probe,
                            now_us.max(1),
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    self.probe_routes
                        .insert((dst_peer_id, chain.path_id), chain.hops.clone());
                    let nonce = self.next_nonce.fetch_add(1, Ordering::Relaxed);
                    probes_out.push((
                        chain.clone(),
                        build_path_probe_packet(self.my_peer_id, dst_peer_id, chain.path_id, nonce),
                    ));
                }
            }
            metrics.push(m);
        }

        let mut eligible = 0_u16;
        if min_arrival < u64::MAX {
            let ceiling = min_arrival.saturating_add(REORDER_BUDGET_US);
            for i in 0..count {
                if !saturated[i] && arrival_us[i] <= ceiling {
                    eligible |= 1_u16 << i;
                }
            }
        }
        if eligible == 0 {
            let min_any = arrival_us[..count].iter().copied().min().unwrap_or(0);
            let ceiling = min_any.saturating_add(REORDER_BUDGET_US);
            for (i, &arrival) in arrival_us.iter().enumerate().take(count) {
                if arrival <= ceiling {
                    eligible |= 1_u16 << i;
                }
            }
            if eligible == 0 {
                eligible = 1;
            }
        }

        let now = Instant::now();
        let shard = &self.flows[shard_index(dst_peer_id, flow_tag)];
        let (seq, chosen_idx) = {
            let mut flows = shard.lock();
            let pos = if let Some(pos) = flows
                .iter()
                .position(|entry| entry.dst_peer_id == dst_peer_id && entry.flow_tag == flow_tag)
            {
                pos
            } else {
                if flows.len() >= MAX_FLOWS_PER_SHARD {
                    flows.pop_front();
                }
                flows.push_back(FlowTxState {
                    flow_tag,
                    dst_peer_id,
                    next_seq: 0,
                    active_hops: SmallVec::new(),
                    burst_packets: 0,
                    burst_bytes: 0,
                    last_tx: now,
                });
                flows.len() - 1
            };

            let state = &mut flows[pos];
            let seq = state.next_seq;
            state.next_seq = seq.wrapping_add(1);
            state.last_tx = now;

            let sticky = (0..count).find(|&i| {
                (eligible & (1_u16 << i)) != 0
                    && state.active_hops == chains[i].hops
                    && state.burst_packets < BURSTLET_MAX_PACKETS
                    && state.burst_bytes < BURSTLET_MAX_BYTES
            });

            let chosen = if let Some(idx) = sticky {
                state.burst_packets = state.burst_packets.saturating_add(1);
                state.burst_bytes = state.burst_bytes.saturating_add(packet_bytes as u32);
                metrics[idx]
                    .deficit
                    .fetch_sub(packet_bytes as i64, Ordering::Relaxed);
                idx
            } else {
                let mut min_rounds = i64::MAX;
                for i in 0..count {
                    if (eligible & (1_u16 << i)) == 0 {
                        continue;
                    }
                    let current = metrics[i].deficit.load(Ordering::Relaxed);
                    if current > 0 {
                        min_rounds = 0;
                        break;
                    }
                    let quantum = i64::from(chains[i].weight.max(1)).saturating_mul(1500);
                    let rounds = current.saturating_neg() / quantum + 1;
                    min_rounds = min_rounds.min(rounds);
                }

                let mut best = eligible.trailing_zeros() as usize;
                let mut best_score = i64::MIN;
                for i in 0..count {
                    if (eligible & (1_u16 << i)) == 0 {
                        continue;
                    }
                    let current = metrics[i].deficit.load(Ordering::Relaxed);
                    let updated = if min_rounds > 0 {
                        let quantum = i64::from(chains[i].weight.max(1)).saturating_mul(1500);
                        let add = quantum.saturating_mul(min_rounds);
                        // Cap accumulated credit so an idle chain doesn't starve active ones on recovery.
                        let next = current.saturating_add(add).min(quantum.saturating_mul(4));
                        metrics[i].deficit.store(next, Ordering::Relaxed);
                        next
                    } else {
                        current
                    };
                    if updated > best_score {
                        best_score = updated;
                        best = i;
                    }
                }
                metrics[best]
                    .deficit
                    .fetch_sub(packet_bytes as i64, Ordering::Relaxed);
                state.active_hops = chains[best].hops.clone();
                state.burst_packets = 1;
                state.burst_bytes = packet_bytes as u32;
                chosen_normalize(best, count)
            };
            (seq, chosen)
        };

        metrics[chosen_idx].packets.fetch_add(1, Ordering::Relaxed);
        packet.multipath_seq = Some((flow_tag, seq));
        chosen_idx
    }
}

#[inline]
fn chosen_normalize(idx: usize, count: usize) -> usize {
    if idx < count { idx } else { 0 }
}

type RingSlot = Option<(ZCPacket, Instant)>;

struct FlowRxState {
    from_peer_id: PeerId,
    flow_tag: u32,
    expected_seq: u32,
    buffered_count: usize,
    gap_since: Option<Instant>,
    last_seen: Instant,
    ring: Option<Box<[RingSlot; FLOW_RING_CAP]>>,
}

impl FlowRxState {
    fn new(from_peer_id: PeerId, flow_tag: u32, expected_seq: u32, now: Instant) -> Self {
        Self {
            from_peer_id,
            flow_tag,
            expected_seq,
            buffered_count: 0,
            gap_since: None,
            last_seen: now,
            ring: None,
        }
    }

    fn drain_contiguous(&mut self, global_buffered: &AtomicUsize, out: &mut BatchCollector) {
        let Some(ring) = self.ring.as_deref_mut() else {
            return;
        };
        while let Some((packet, _)) =
            ring[(self.expected_seq as usize) & (FLOW_RING_CAP - 1)].take()
        {
            self.buffered_count -= 1;
            global_buffered.fetch_sub(1, Ordering::AcqRel);
            self.expected_seq = self.expected_seq.wrapping_add(1);
            out.push(packet);
        }
        self.refresh_gap_since();
    }

    fn refresh_gap_since(&mut self) {
        if self.buffered_count == 0 {
            self.gap_since = None;
            return;
        }
        let Some(ring) = self.ring.as_deref() else {
            self.gap_since = None;
            return;
        };
        let mut earliest: Option<Instant> = None;
        for offset in 1..FLOW_RING_CAP {
            let seq = self.expected_seq.wrapping_add(offset as u32);
            if let Some((_, ts)) = &ring[(seq as usize) & (FLOW_RING_CAP - 1)] {
                earliest = Some(earliest.map_or(*ts, |current| current.min(*ts)));
            }
        }
        self.gap_since = earliest;
    }

    fn advance_until(
        &mut self,
        target_expected: u32,
        global_buffered: &AtomicUsize,
        out: &mut BatchCollector,
    ) {
        let Some(ring) = self.ring.as_deref_mut() else {
            self.expected_seq = target_expected;
            return;
        };
        while self.expected_seq != target_expected
            && target_expected.wrapping_sub(self.expected_seq) < 0x8000_0000
        {
            if let Some((packet, _)) =
                ring[(self.expected_seq as usize) & (FLOW_RING_CAP - 1)].take()
            {
                self.buffered_count -= 1;
                global_buffered.fetch_sub(1, Ordering::AcqRel);
                out.push(packet);
            }
            self.expected_seq = self.expected_seq.wrapping_add(1);
        }
        self.drain_contiguous(global_buffered, out);
    }

    fn advance_to_earliest_buffered(
        &mut self,
        global_buffered: &AtomicUsize,
        out: &mut BatchCollector,
    ) {
        let Some(ring) = self.ring.as_deref() else {
            return;
        };
        for offset in 1..FLOW_RING_CAP {
            let seq = self.expected_seq.wrapping_add(offset as u32);
            if ring[(seq as usize) & (FLOW_RING_CAP - 1)].is_some() {
                self.expected_seq = seq;
                break;
            }
        }
        self.drain_contiguous(global_buffered, out);
    }
}

pub(crate) struct BatchCollector {
    pub batches: SmallVec<[PacketBatch; 2]>,
}

impl BatchCollector {
    pub(crate) fn new() -> Self {
        Self {
            batches: SmallVec::new(),
        }
    }

    pub(crate) fn push(&mut self, packet: ZCPacket) {
        let need_new = self
            .batches
            .last()
            .is_none_or(|batch| batch.len() >= MAX_PACKET_BATCH_SIZE);
        if need_new {
            self.batches.push(PacketBatch::singleton(packet));
        } else {
            self.batches
                .last_mut()
                .expect("checked")
                .try_push(packet)
                .expect("batch capacity checked");
        }
    }
}

pub struct MultipathReorderBuffer {
    shards: Vec<Mutex<VecDeque<FlowRxState>>>,
    global_buffered: AtomicUsize,
    total_reordered: AtomicU64,
    per_peer_reordered: DashMap<PeerId, AtomicU64>,
    timer_wake: Notify,
}

impl Default for MultipathReorderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl MultipathReorderBuffer {
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(VecDeque::new()))
            .collect();
        Self {
            shards,
            global_buffered: AtomicUsize::new(0),
            total_reordered: AtomicU64::new(0),
            per_peer_reordered: DashMap::new(),
            timer_wake: Notify::new(),
        }
    }

    pub fn has_buffered(&self) -> bool {
        self.global_buffered.load(Ordering::Acquire) > 0
    }

    pub async fn wait_for_buffered(&self) {
        if self.has_buffered() {
            return;
        }
        let notified = self.timer_wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.has_buffered() {
            return;
        }
        notified.await;
    }

    pub fn reordered_count_for_peer(&self, peer_id: Option<PeerId>) -> u64 {
        match peer_id {
            Some(id) => self
                .per_peer_reordered
                .get(&id)
                .map_or(0, |entry| entry.load(Ordering::Relaxed)),
            None => self.total_reordered.load(Ordering::Relaxed),
        }
    }

    fn record_reordered(&self, from_peer_id: PeerId) {
        self.total_reordered.fetch_add(1, Ordering::Relaxed);
        self.per_peer_reordered
            .entry(from_peer_id)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn ingest_batch(&self, batch: PacketBatch, now: Instant) -> SmallVec<[PacketBatch; 2]> {
        if !batch.iter().any(|packet| packet.multipath_seq.is_some()) {
            let mut out = SmallVec::new();
            out.push(batch);
            return out;
        }

        let mut collector = BatchCollector::new();
        for mut packet in batch {
            let Some((flow_tag, seq)) = packet.multipath_seq.take() else {
                collector.push(packet);
                continue;
            };
            let from_peer_id = packet
                .peer_manager_header()
                .map_or(0, |header| header.from_peer_id.get());

            let shard = &self.shards[shard_index(from_peer_id, flow_tag)];
            let mut flows = shard.lock();
            let pos = if let Some(pos) = flows
                .iter()
                .position(|entry| entry.from_peer_id == from_peer_id && entry.flow_tag == flow_tag)
            {
                pos
            } else {
                if flows.len() >= MAX_FLOWS_PER_SHARD
                    && let Some(mut evicted) = flows.pop_front()
                {
                    let target = evicted.expected_seq.wrapping_add(FLOW_RING_CAP as u32);
                    evicted.advance_until(target, &self.global_buffered, &mut collector);
                }
                let initial_expected = if seq < FLOW_RING_CAP as u32 { 0 } else { seq };
                flows.push_back(FlowRxState::new(
                    from_peer_id,
                    flow_tag,
                    initial_expected,
                    now,
                ));
                flows.len() - 1
            };

            let state = &mut flows[pos];
            state.last_seen = now;

            let diff = seq.wrapping_sub(state.expected_seq);
            if diff == 0 {
                collector.push(packet);
                state.expected_seq = state.expected_seq.wrapping_add(1);
                if state.buffered_count > 0 {
                    state.drain_contiguous(&self.global_buffered, &mut collector);
                }
            } else if diff >= 0x8000_0000 {
                // Packet arrived after a timeout gap already advanced past it; anti-replay already checked it.
                collector.push(packet);
            } else {
                if state.ring.is_none() {
                    state.ring = Some(Box::new(std::array::from_fn(|_| None)));
                }
                if diff as usize >= FLOW_RING_CAP {
                    let target = seq.wrapping_sub(FLOW_RING_CAP as u32 - 1);
                    state.advance_until(target, &self.global_buffered, &mut collector);
                }
                if self.global_buffered.load(Ordering::Acquire) >= MAX_GLOBAL_REORDER_PACKETS {
                    state.advance_to_earliest_buffered(&self.global_buffered, &mut collector);
                }
                let ring = state.ring.as_deref_mut().expect("allocated");
                let slot = &mut ring[(seq as usize) & (FLOW_RING_CAP - 1)];
                if slot.is_some() {
                    // Slot collision should not occur after capacity advance, deliver directly.
                    collector.push(packet);
                    continue;
                }
                *slot = Some((packet, now));
                state.buffered_count += 1;
                if state.gap_since.is_none() {
                    state.gap_since = Some(now);
                }
                let prev_global = self.global_buffered.fetch_add(1, Ordering::AcqRel);
                if prev_global == 0 {
                    self.timer_wake.notify_one();
                }
                self.record_reordered(from_peer_id);
            }
        }
        collector.batches
    }

    pub fn flush_expired(&self, now: Instant) -> SmallVec<[PacketBatch; 2]> {
        let mut collector = BatchCollector::new();
        for shard in &self.shards {
            let mut flows = shard.lock();
            if flows.is_empty() {
                continue;
            }
            for flow in flows.iter_mut() {
                while flow.buffered_count > 0
                    && flow.gap_since.is_some_and(|since| {
                        now.saturating_duration_since(since) >= REORDER_GAP_TIMEOUT
                    })
                {
                    flow.advance_to_earliest_buffered(&self.global_buffered, &mut collector);
                }
            }
            flows.retain(|flow| {
                flow.buffered_count > 0
                    || now.saturating_duration_since(flow.last_seen) < FLOW_IDLE_TIMEOUT
            });
        }
        collector.batches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::tunnel::packet_def::PEER_MANAGER_HEADER_SIZE;

    fn mp_packet(from: PeerId, to: PeerId, seq: u32, payload: &[u8]) -> ZCPacket {
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
        pkt.multipath_seq = Some((7, seq));
        pkt
    }

    #[test]
    fn reorder_buffer_zero_alloc_inorder_and_out_of_order_burst() {
        let buffer = MultipathReorderBuffer::new();
        let now = Instant::now();

        // Non-multipath batch bypasses unchanged.
        let mut plain = ZCPacket::new_with_payload(b"plain");
        plain.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let res = buffer.ingest_batch(PacketBatch::singleton(plain), now);
        assert_eq!(res.len(), 1);
        assert!(!buffer.has_buffered());

        // Deliver 1,200 packets intentionally permuted in chunks of 4 across multiple batches.
        let mut out_seqs = Vec::new();
        for base in (0..1_200_u32).step_by(4) {
            let mut batch = PacketBatch::new();
            for offset in [3, 1, 2, 0] {
                let seq = base + offset;
                let mut payload = [0_u8; 4];
                payload.copy_from_slice(&seq.to_le_bytes());
                let _ = batch.try_push(mp_packet(10, 20, seq, &payload));
            }
            for b in buffer.ingest_batch(batch, now) {
                for pkt in b {
                    let s = u32::from_le_bytes(pkt.payload()[..4].try_into().unwrap());
                    out_seqs.push(s);
                }
            }
        }
        assert_eq!(out_seqs, (0..1_200_u32).collect::<Vec<_>>());
        assert!(!buffer.has_buffered());
        assert!(buffer.reordered_count_for_peer(Some(10)) > 0);
    }

    #[test]
    fn reorder_buffer_flushes_gap_on_timeout_and_ring_overflow() {
        let buffer = MultipathReorderBuffer::new();
        let t0 = Instant::now();

        // Seq 0 delivered, seq 1 lost, seq 2..4 buffered.
        let mut b = PacketBatch::new();
        let _ = b.try_push(mp_packet(5, 6, 0, b"0"));
        let _ = b.try_push(mp_packet(5, 6, 2, b"2"));
        let _ = b.try_push(mp_packet(5, 6, 3, b"3"));
        let immediate: Vec<Vec<u8>> = buffer
            .ingest_batch(b, t0)
            .into_iter()
            .flatten()
            .map(|p| p.payload().to_vec())
            .collect();
        assert_eq!(immediate, vec![b"0".to_vec()]);
        assert!(buffer.has_buffered());

        // Before timeout: nothing flushes.
        assert!(
            buffer
                .flush_expired(t0 + Duration::from_millis(5))
                .is_empty()
        );
        // After 20ms gap timeout: 2 and 3 flush in order.
        let flushed: Vec<Vec<u8>> = buffer
            .flush_expired(t0 + REORDER_GAP_TIMEOUT + Duration::from_millis(1))
            .into_iter()
            .flatten()
            .map(|p| p.payload().to_vec())
            .collect();
        assert_eq!(flushed, vec![b"2".to_vec(), b"3".to_vec()]);
        assert!(!buffer.has_buffered());

        // Late arrival of seq 1 delivers without blocking.
        let late: Vec<Vec<u8>> = buffer
            .ingest_batch(PacketBatch::singleton(mp_packet(5, 6, 1, b"1")), t0)
            .into_iter()
            .flatten()
            .map(|p| p.payload().to_vec())
            .collect();
        assert_eq!(late, vec![b"1".to_vec()]);
    }

    #[test]
    fn path_probe_roundtrip_and_ewma_rtt() {
        let ctx = get_mock_global_ctx();
        let (tx, _rx) = crate::peers::create_packet_recv_chan();
        let peer_map = PeerMap::new(tx, ctx, 1);
        let sender = MultipathSender::new(1);

        let chain = CandidateChain {
            path_id: 2,
            hops: SmallVec::from_slice(&[3, 4]),
            member_picks: SmallVec::new(),
            weight: 1,
        };
        let chains = [chain.clone()];
        sender.probe_routes.insert((9, 2), chain.hops.clone());

        let probe = build_path_probe_packet(1, 9, 2, 77);
        assert!(probe.buf_len() >= PEER_MANAGER_HEADER_SIZE + PATH_PROBE_SIZE);
        let ack = build_path_probe_ack(9, 1, probe.payload()).unwrap();
        sender.record_probe_ack(9, ack.payload());
        let (rtt_us, _, _, _) = sender.chain_telemetry(Some(9), 2, &chains[0].hops);
        assert!(rtt_us >= 1);
        let _ = peer_map;
    }

    #[test]
    fn burstlet_drr_respects_burst_cap_and_weights() {
        let ctx = get_mock_global_ctx();
        let (tx, _rx) = crate::peers::create_packet_recv_chan();
        let peer_map = PeerMap::new(tx, ctx, 1);
        let sender = MultipathSender::new(1);

        let chains = vec![
            CandidateChain {
                path_id: 0,
                hops: SmallVec::from_slice(&[2]),
                member_picks: SmallVec::new(),
                weight: 3,
            },
            CandidateChain {
                path_id: 1,
                hops: SmallVec::from_slice(&[3]),
                member_picks: SmallVec::new(),
                weight: 1,
            },
        ];

        let mut picks = [0_usize; 2];
        let mut seqs = Vec::with_capacity(400);
        let mut flow_tag = None;
        let mut current_chain = None;
        let mut current_run = 0_u16;
        let mut saw_burstlet_cap = false;

        for expected_seq in 0..400_u32 {
            let mut pkt = ZCPacket::new_with_payload(&[0xab; 100]);
            pkt.fill_peer_manager_hdr(1, 9, PacketType::Data as u8);
            let mut probes = SmallVec::new();
            let chosen = sender.assign_packet(
                &peer_map,
                9,
                NextHopPolicy::LeastCost,
                &chains,
                &mut pkt,
                42,
                &mut probes,
            );
            let (tag, seq) = pkt.multipath_seq.expect("assigned multipath sequence");
            if let Some(prev_tag) = flow_tag {
                assert_eq!(tag, prev_tag);
            } else {
                flow_tag = Some(tag);
            }
            assert_eq!(seq, expected_seq);
            seqs.push(seq);
            picks[chosen] += 1;

            if current_chain == Some(chosen) {
                current_run += 1;
            } else {
                if current_run == u16::from(BURSTLET_MAX_PACKETS) {
                    saw_burstlet_cap = true;
                }
                current_chain = Some(chosen);
                current_run = 1;
            }
        }
        if current_run == u16::from(BURSTLET_MAX_PACKETS) {
            saw_burstlet_cap = true;
        }
        assert_eq!(seqs.len(), 400);
        assert!(
            saw_burstlet_cap,
            "expected a burstlet run of {BURSTLET_MAX_PACKETS}, picks={picks:?}"
        );
        assert!(
            (260..=340).contains(&picks[0]) && (60..=140).contains(&picks[1]),
            "expected ~3:1 weight split, got {picks:?}"
        );
    }

    #[test]
    fn blest_skips_high_rtt_chain_outside_reorder_budget() {
        let ctx = get_mock_global_ctx();
        let (tx, _rx) = crate::peers::create_packet_recv_chan();
        let peer_map = PeerMap::new(tx, ctx, 1);
        let sender = MultipathSender::new(1);

        let chains = vec![
            CandidateChain {
                path_id: 0,
                hops: SmallVec::from_slice(&[2]),
                member_picks: SmallVec::new(),
                weight: 1,
            },
            CandidateChain {
                path_id: 1,
                hops: SmallVec::from_slice(&[3]),
                member_picks: SmallVec::new(),
                weight: 1,
            },
        ];
        sender.set_chain_srtt_for_test(9, &chains[0].hops, 2_000);
        sender.set_chain_srtt_for_test(9, &chains[1].hops, 40_000);

        for _ in 0..64 {
            let mut pkt = ZCPacket::new_with_payload(&[0x55; 128]);
            pkt.fill_peer_manager_hdr(1, 9, PacketType::Data as u8);
            let mut probes = SmallVec::new();
            let chosen = sender.assign_packet(
                &peer_map,
                9,
                NextHopPolicy::LeastCost,
                &chains,
                &mut pkt,
                99,
                &mut probes,
            );
            assert_eq!(chosen, 0);
        }
    }

    #[test]
    fn session_replay_window_and_reorder_buffer_handle_1500_packet_out_of_order_burst() {
        use crate::peers::peer_session::PeerSession;
        use crate::peers::relay_peer_map::{
            attach_relay_origin_proof, verify_and_remove_relay_origin_proof,
        };

        let root_key = PeerSession::new_root_key();
        let sender = PeerSession::new(
            9,
            root_key,
            1,
            0,
            "chacha20-poly1305".to_string(),
            "chacha20-poly1305".to_string(),
            Some([1; 32]),
        );
        let receiver = PeerSession::new(
            1,
            root_key,
            1,
            0,
            "chacha20-poly1305".to_string(),
            "chacha20-poly1305".to_string(),
            Some([2; 32]),
        );

        let make_sealed = |flow_tag: u32, seq: u32, payload: &[u8]| -> ZCPacket {
            let mut pkt = ZCPacket::new_with_payload(payload);
            pkt.fill_peer_manager_hdr(1, 9, PacketType::Data as u8);
            pkt.multipath_seq = Some((flow_tag, seq));
            attach_relay_origin_proof(&mut pkt).unwrap();
            sender.encrypt_payload(1, 9, &mut pkt).unwrap();
            pkt
        };
        let open_sealed = |pkt: &mut ZCPacket| {
            receiver.decrypt_payload(1, 9, pkt).unwrap();
            verify_and_remove_relay_origin_proof(pkt).unwrap();
        };

        // Hold back one Flow B packet while 1,200 Flow A packets advance the session replay window.
        let mut delayed_flow_b = make_sealed(2, 0, b"delayed-flow-b");
        for seq in 0..1_200_u32 {
            let mut flow_a = make_sealed(1, seq, &seq.to_le_bytes());
            open_sealed(&mut flow_a);
            assert_eq!(flow_a.multipath_seq, Some((1, seq)));
        }
        open_sealed(&mut delayed_flow_b);
        assert_eq!(delayed_flow_b.multipath_seq, Some((2, 0)));
        assert_eq!(delayed_flow_b.payload(), b"delayed-flow-b");

        // Now seal and out-of-order decrypt 1,500 Flow C packets in reversed chunks of 64.
        let buffer = MultipathReorderBuffer::new();
        let now = Instant::now();
        let mut out_seqs = Vec::with_capacity(1_500);
        let mut seq = 0_u32;
        while seq < 1_500 {
            let end = (seq + 64).min(1_500);
            let mut sealed_chunk: Vec<ZCPacket> = (seq..end)
                .map(|s| make_sealed(3, s, &s.to_le_bytes()))
                .collect();
            sealed_chunk.reverse();

            let mut iter = sealed_chunk.into_iter();
            loop {
                let mut batch = PacketBatch::new();
                for mut pkt in iter.by_ref().take(16) {
                    open_sealed(&mut pkt);
                    let _ = batch.try_push(pkt);
                }
                if batch.is_empty() {
                    break;
                }
                for ready in buffer.ingest_batch(batch, now) {
                    for pkt in ready {
                        let got = u32::from_le_bytes(pkt.payload()[..4].try_into().unwrap());
                        out_seqs.push(got);
                    }
                }
            }
            seq = end;
        }
        assert_eq!(out_seqs, (0..1_500_u32).collect::<Vec<_>>());
        assert!(!buffer.has_buffered());
    }
}
