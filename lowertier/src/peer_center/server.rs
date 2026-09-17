use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};

use arc_swap::ArcSwap;
use rand::{RngCore, rngs::OsRng};
use tokio::task::JoinSet;

use crate::{
    common::PeerId,
    proto::{
        peer_rpc::{
            DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
            PeerCenterRpc, PeerCenterSourceDelta, PeerInfoForGlobalMap, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
};

use super::Digest;

// Keep reported rates below the physical and protocol range supported by this overlay.
const MAX_REPORTED_DELIVERY_BPS: u64 = 1_000_000_000_000;
const MAX_REPORTED_LATENCY_MS: i32 = 10 * 60 * 1_000;
const MAX_REPORTED_SAMPLE_TTL_MS: u64 = 15 * 60 * 1_000;
const MAX_DIRECT_PEERS_PER_REPORT: usize = 1_024;
const MAX_REPORT_SOURCES: usize = 4_096;
const MAX_UNIQUE_NODES: usize = 4_096;
const MAX_TOTAL_DIRECTED_EDGES: usize = 262_144;
const MIN_REPORT_INTERVAL: Duration = Duration::from_secs(1);
const PEER_REPORT_EXPIRY: Duration = Duration::from_secs(180);
const FULL_MAP_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PEER_CENTER_DELTAS: usize = 4_096;

fn validate_direct_peer_info(
    mut info: DirectConnectedPeerInfo,
) -> Result<DirectConnectedPeerInfo, rpc_types::error::Error> {
    if info.latency_ms == 0 {
        // Zero means that the sender has no latency sample.
        info.latency_ms = 1;
    } else if info.latency_ms < 0 || info.latency_ms > MAX_REPORTED_LATENCY_MS {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "reported latency is outside 1..={MAX_REPORTED_LATENCY_MS} ms"
        )));
    }
    if info.tx_delivery_bps > MAX_REPORTED_DELIVERY_BPS {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "reported delivery rate exceeds {MAX_REPORTED_DELIVERY_BPS} bits per second"
        )));
    }
    if info.tx_loss_ppm > 1_000_000 {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "reported loss exceeds one million parts per million".to_string(),
        ));
    }

    if info.tx_delivery_bps == 0 {
        // Zero rate means that no speed sample exists.
        info.speed_sample_age_ms = 0;
        info.speed_sample_ttl_ms = 0;
        info.speed_probe_generation = 0;
    } else {
        if !(1..=MAX_REPORTED_SAMPLE_TTL_MS).contains(&info.speed_sample_ttl_ms) {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "reported speed sample TTL is outside 1..={MAX_REPORTED_SAMPLE_TTL_MS} ms"
            )));
        }
        if info.speed_sample_age_ms >= info.speed_sample_ttl_ms {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "reported speed sample is already expired".to_string(),
            ));
        }
    }

    Ok(info)
}

#[derive(Debug, Clone)]
pub(crate) struct PeerCenterInfoEntry {
    info: DirectConnectedPeerInfo,
    update_time: std::time::Instant,
}

#[derive(Debug, Clone)]
struct SourceAdjacency {
    edges: Arc<HashMap<PeerId, PeerCenterInfoEntry>>,
}

#[derive(Debug, Clone)]
struct PeerCenterSnapshot {
    generation: Digest,
    sources: Arc<HashMap<PeerId, Arc<SourceAdjacency>>>,
    published_at: std::time::Instant,
    delta_base_generation: Digest,
    deltas: Arc<Vec<PeerCenterSourceDelta>>,
    full_response: Arc<OnceLock<GetGlobalPeerMapResponse>>,
}

#[derive(Debug)]
struct PeerCenterWriterState {
    sources: HashMap<PeerId, Arc<SourceAdjacency>>,
    report_times: HashMap<PeerId, std::time::Instant>,
    node_ref_counts: HashMap<PeerId, usize>,
    total_edges: usize,
    generation: Digest,
    delta_base_generation: Digest,
    deltas: Vec<PeerCenterSourceDelta>,
    delta_update_times: Vec<std::time::Instant>,
}

impl PeerCenterWriterState {
    fn new() -> Self {
        Self::with_generation(initial_generation())
    }

    fn with_generation(generation: Digest) -> Self {
        Self {
            sources: HashMap::new(),
            report_times: HashMap::new(),
            node_ref_counts: HashMap::new(),
            total_edges: 0,
            generation: if generation == 0 { 1 } else { generation },
            delta_base_generation: if generation == 0 { 1 } else { generation },
            deltas: Vec::new(),
            delta_update_times: Vec::new(),
        }
    }
}

struct PeerCenterServerData {
    writer: std::sync::Mutex<PeerCenterWriterState>,
    snapshot: ArcSwap<PeerCenterSnapshot>,
    full_map_reads: std::sync::Mutex<HashMap<PeerId, (std::time::Instant, Digest)>>,
}

impl PeerCenterServerData {
    fn new() -> Self {
        Self::with_generation(initial_generation())
    }

    fn with_generation(generation: Digest) -> Self {
        let writer = PeerCenterWriterState::with_generation(generation);
        let generation = writer.generation;
        Self {
            writer: std::sync::Mutex::new(writer),
            snapshot: ArcSwap::from_pointee(PeerCenterSnapshot {
                generation,
                sources: Arc::new(HashMap::new()),
                published_at: std::time::Instant::now(),
                delta_base_generation: generation,
                deltas: Arc::new(Vec::new()),
                full_response: Arc::new(OnceLock::new()),
            }),
            full_map_reads: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

fn initial_generation() -> Digest {
    let mut generation = OsRng.next_u64();
    if generation == 0 {
        generation = 1;
    }
    generation
}

fn next_generation(generation: Digest) -> Digest {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn increment_node_ref(node_ref_counts: &mut HashMap<PeerId, usize>, peer_id: PeerId) {
    *node_ref_counts.entry(peer_id).or_default() += 1;
}

fn decrement_node_ref(node_ref_counts: &mut HashMap<PeerId, usize>, peer_id: PeerId) {
    let Some(count) = node_ref_counts.get_mut(&peer_id) else {
        return;
    };
    if *count <= 1 {
        node_ref_counts.remove(&peer_id);
    } else {
        *count -= 1;
    }
}

fn remove_source_refs(state: &mut PeerCenterWriterState, source: PeerId) {
    let Some(adjacency) = state.sources.get(&source).cloned() else {
        return;
    };
    decrement_node_ref(&mut state.node_ref_counts, source);
    for peer_id in adjacency.edges.keys().copied() {
        decrement_node_ref(&mut state.node_ref_counts, peer_id);
    }
    state.total_edges = state.total_edges.saturating_sub(adjacency.edges.len());
}

fn add_source_refs(state: &mut PeerCenterWriterState, source: PeerId, adjacency: &SourceAdjacency) {
    increment_node_ref(&mut state.node_ref_counts, source);
    for peer_id in adjacency.edges.keys().copied() {
        increment_node_ref(&mut state.node_ref_counts, peer_id);
    }
    state.total_edges = state.total_edges.saturating_add(adjacency.edges.len());
}

fn validate_source_replacement(
    state: &PeerCenterWriterState,
    source: PeerId,
    new_edges: &HashMap<PeerId, DirectConnectedPeerInfo>,
) -> Result<(), rpc_types::error::Error> {
    if new_edges.len() > MAX_DIRECT_PEERS_PER_REPORT {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "peer report contains too many direct peers: {}",
            new_edges.len()
        )));
    }
    if !state.sources.contains_key(&source) && state.sources.len() >= MAX_REPORT_SOURCES {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "peer center contains too many report sources: {}",
            state.sources.len()
        )));
    }
    if new_edges.contains_key(&source) {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "peer report contains a self link".to_string(),
        ));
    }

    let old_edge_count = state
        .sources
        .get(&source)
        .map(|adjacency| adjacency.edges.len())
        .unwrap_or_default();
    let next_total_edges = state
        .total_edges
        .saturating_sub(old_edge_count)
        .saturating_add(new_edges.len());
    if next_total_edges > MAX_TOTAL_DIRECTED_EDGES {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "peer center contains too many directed edges: {next_total_edges}"
        )));
    }

    // Account for the replaced source without cloning the complete node index.
    let mut replaced_nodes = std::collections::HashSet::with_capacity(
        state
            .sources
            .get(&source)
            .map(|adjacency| adjacency.edges.len() + 1)
            .unwrap_or(1),
    );
    replaced_nodes.insert(source);
    if let Some(old_adjacency) = state.sources.get(&source) {
        for peer_id in old_adjacency.edges.keys().copied() {
            replaced_nodes.insert(peer_id);
        }
    }
    let removed_singletons = replaced_nodes
        .iter()
        .filter(|peer_id| state.node_ref_counts.get(peer_id).copied() == Some(1))
        .count();
    let mut candidate_node_count = state
        .node_ref_counts
        .len()
        .saturating_sub(removed_singletons);
    for peer_id in std::iter::once(source).chain(new_edges.keys().copied()) {
        let retained = state.node_ref_counts.get(&peer_id).copied().unwrap_or(0)
            > usize::from(replaced_nodes.contains(&peer_id));
        if !retained {
            candidate_node_count += 1;
        }
    }
    if candidate_node_count > MAX_UNIQUE_NODES {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "peer center contains too many unique peer nodes: {}",
            candidate_node_count
        )));
    }
    Ok(())
}

fn publish_snapshot(data: &PeerCenterServerData, state: &PeerCenterWriterState) {
    let published_at = std::time::Instant::now();
    let mut deltas = state.deltas.clone();
    for (delta, update_time) in deltas.iter_mut().zip(&state.delta_update_times) {
        delta.residence_age_ms = u64::try_from(
            published_at
                .saturating_duration_since(*update_time)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
    }
    data.snapshot.store(Arc::new(PeerCenterSnapshot {
        generation: state.generation,
        sources: Arc::new(state.sources.clone()),
        published_at,
        delta_base_generation: state.delta_base_generation,
        deltas: Arc::new(deltas),
        full_response: Arc::new(OnceLock::new()),
    }));
}

fn append_delta(
    state: &mut PeerCenterWriterState,
    previous_generation: Digest,
    delta: PeerCenterSourceDelta,
    update_time: std::time::Instant,
) {
    if state.deltas.is_empty() {
        state.delta_base_generation = previous_generation;
    }
    state.deltas.push(delta);
    state.delta_update_times.push(update_time);
    if state.deltas.len() > MAX_PEER_CENTER_DELTAS {
        let removed = state.deltas.remove(0);
        state.delta_update_times.remove(0);
        state.delta_base_generation = removed.generation;
    }
}

fn replace_source(
    data: &PeerCenterServerData,
    state: &mut PeerCenterWriterState,
    source: PeerId,
    edges: HashMap<PeerId, PeerCenterInfoEntry>,
    now: std::time::Instant,
) {
    let adjacency = Arc::new(SourceAdjacency {
        edges: Arc::new(edges),
    });
    if state.sources.contains_key(&source) {
        remove_source_refs(state, source);
    }
    state.sources.insert(source, adjacency.clone());
    add_source_refs(state, source, &adjacency);
    state.report_times.insert(source, now);
    let previous_generation = state.generation;
    state.generation = next_generation(state.generation);
    append_delta(
        state,
        previous_generation,
        PeerCenterSourceDelta {
            generation: state.generation,
            source_peer_id: source,
            peer_info: Some(PeerInfoForGlobalMap {
                direct_peers: adjacency
                    .edges
                    .iter()
                    .map(|(peer_id, entry)| {
                        let mut info = entry.info;
                        info.speed_sample_age_ms = info.speed_sample_age_ms.saturating_add(
                            u64::try_from(entry.update_time.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                        );
                        (*peer_id, info)
                    })
                    .collect(),
            }),
            residence_age_ms: 0,
            removed: false,
        },
        now,
    );
    publish_snapshot(data, state);
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    data: Arc<PeerCenterServerData>,
    tasks: Arc<JoinSet<()>>,
}

impl std::fmt::Debug for PeerCenterServerData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerCenterServerData")
            .finish_non_exhaustive()
    }
}

impl Default for PeerCenterServerData {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerCenterServer {
    pub fn new() -> Self {
        Self::from_data(Arc::new(PeerCenterServerData::default()))
    }

    fn from_data(data: Arc<PeerCenterServerData>) -> Self {
        let weak_data = Arc::downgrade(&data);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let Some(data) = weak_data.upgrade() else {
                    break;
                };
                PeerCenterServer::clean_outdated_peer_data(&data);
            }
        });

        PeerCenterServer {
            data,
            tasks: Arc::new(tasks),
        }
    }

    #[cfg(test)]
    fn with_generation(generation: Digest) -> Self {
        Self::from_data(Arc::new(PeerCenterServerData::with_generation(generation)))
    }

    fn clean_outdated_peer_data(data: &PeerCenterServerData) {
        let now = std::time::Instant::now();
        let mut state = data.writer.lock().unwrap();
        let stale_sources = state
            .report_times
            .iter()
            .filter_map(|(peer_id, report_time)| {
                (now.duration_since(*report_time) >= PEER_REPORT_EXPIRY).then_some(*peer_id)
            })
            .collect::<Vec<_>>();
        if stale_sources.is_empty() {
            return;
        }

        for source in stale_sources {
            if state.sources.contains_key(&source) {
                remove_source_refs(&mut state, source);
                state.sources.remove(&source);
            }
            state.report_times.remove(&source);
            let previous_generation = state.generation;
            let generation = next_generation(state.generation);
            state.generation = generation;
            append_delta(
                &mut state,
                previous_generation,
                PeerCenterSourceDelta {
                    generation,
                    source_peer_id: source,
                    peer_info: None,
                    residence_age_ms: 0,
                    removed: true,
                },
                now,
            );
        }
        publish_snapshot(data, &state);
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterServer {
    type Controller = BaseController;

    #[tracing::instrument()]
    async fn report_peers(
        &self,
        ctrl: BaseController,
        req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        let authenticated_peer_id = ctrl.authenticated_peer_id().ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket(
                "peer center report requires an authenticated peer".to_string(),
            )
        })?;
        if ctrl.authenticated_peer_identity_type()
            != Some(crate::proto::peer_rpc::PeerIdentityType::Admin)
            || ctrl.authenticated_peer_secure_auth_level()
                != Some(crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed)
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "only authenticated admin peers may report peer center costs".to_string(),
            ));
        }
        let my_peer_id = req.my_peer_id;
        if authenticated_peer_id != my_peer_id {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "peer center report peer mismatch: authenticated {authenticated_peer_id}, claimed {my_peer_id}"
            )));
        }
        let peers = req.peer_infos.unwrap_or_default();
        if peers.direct_peers.len() > MAX_DIRECT_PEERS_PER_REPORT {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "peer report contains too many direct peers: {}",
                peers.direct_peers.len()
            )));
        }
        let mut validated_peers = HashMap::with_capacity(peers.direct_peers.len());
        for (peer_id, peer_info) in peers.direct_peers {
            if peer_id == my_peer_id {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "peer report contains a self link".to_string(),
                ));
            }
            validated_peers.insert(peer_id, validate_direct_peer_info(peer_info)?);
        }

        let now = std::time::Instant::now();
        let data = &self.data;
        // Remove expired source reports before applying unrelated-source churn.
        // This keeps the published authority graph bounded without waiting for the timer task.
        Self::clean_outdated_peer_data(data);
        let mut state = data.writer.lock().unwrap();
        if let Some(last_report) = state.report_times.get(&my_peer_id)
            && now.duration_since(*last_report) < MIN_REPORT_INTERVAL
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "peer report rate limit exceeded".to_string(),
            ));
        }
        validate_source_replacement(&state, my_peer_id, &validated_peers)?;

        tracing::debug!("receive report_peers");
        let edges = validated_peers
            .into_iter()
            .map(|(peer_id, info)| {
                (
                    peer_id,
                    PeerCenterInfoEntry {
                        info,
                        update_time: now,
                    },
                )
            })
            .collect();
        replace_source(data, &mut state, my_peer_id, edges, now);

        Ok(ReportPeersResponse::default())
    }

    #[tracing::instrument()]
    async fn get_global_peer_map(
        &self,
        ctrl: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let authenticated_peer_id = ctrl.authenticated_peer_id().ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket(
                "peer center map requires an authenticated peer".to_string(),
            )
        })?;
        if ctrl.authenticated_peer_identity_type()
            != Some(crate::proto::peer_rpc::PeerIdentityType::Admin)
            || ctrl.authenticated_peer_secure_auth_level()
                != Some(crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed)
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "peer center map requires verified admin authentication".to_string(),
            ));
        }

        let snapshot = self.data.snapshot.load();
        if req.digest != 0 && req.digest == snapshot.generation {
            // An unchanged response uses the exact default protobuf value.
            // The instance client uses this value to keep its cached map.
            return Ok(GetGlobalPeerMapResponse::default());
        }

        if req.digest != 0 {
            let delta_start = if req.digest == snapshot.delta_base_generation {
                Some(0)
            } else {
                snapshot
                    .deltas
                    .iter()
                    .position(|delta| delta.generation == req.digest)
                    .map(|position| position + 1)
            };
            if let Some(delta_start) = delta_start {
                let residence_age_ms =
                    u64::try_from(snapshot.published_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                let mut deltas = snapshot.deltas[delta_start..].to_vec();
                for delta in &mut deltas {
                    delta.residence_age_ms =
                        delta.residence_age_ms.saturating_add(residence_age_ms);
                }
                return Ok(GetGlobalPeerMapResponse {
                    global_peer_map: Default::default(),
                    digest: Some(snapshot.generation),
                    deltas,
                    full_snapshot: false,
                    snapshot_residence_age_ms: 0,
                });
            }
        }

        {
            let now = std::time::Instant::now();
            let mut reads = self.data.full_map_reads.lock().unwrap();
            reads.retain(|_, (last_read, generation)| {
                *generation == snapshot.generation
                    && now.duration_since(*last_read) < PEER_REPORT_EXPIRY
            });
            if reads.len() >= MAX_REPORT_SOURCES {
                if let Some(oldest_peer_id) = reads
                    .iter()
                    .min_by_key(|(_, (last_read, _))| *last_read)
                    .map(|(peer_id, _)| *peer_id)
                {
                    reads.remove(&oldest_peer_id);
                }
            }
            if let Some((last_read, generation)) = reads.get(&authenticated_peer_id)
                && *generation == snapshot.generation
                && now.duration_since(*last_read) < FULL_MAP_REFRESH_INTERVAL
            {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "peer center full map refresh is rate limited".to_string(),
                ));
            }
            reads.insert(authenticated_peer_id, (now, snapshot.generation));
        }

        let full_response = snapshot.full_response.get_or_init(|| {
            let global_peer_map = snapshot
                .sources
                .iter()
                .map(|(source, adjacency)| {
                    let direct_peers = adjacency
                        .edges
                        .iter()
                        .map(|(destination, entry)| {
                            let mut info = entry.info;
                            let age_ms = u64::try_from(
                                snapshot
                                    .published_at
                                    .saturating_duration_since(entry.update_time)
                                    .as_millis(),
                            )
                            .unwrap_or(u64::MAX);
                            info.speed_sample_age_ms =
                                info.speed_sample_age_ms.saturating_add(age_ms);
                            (*destination, info)
                        })
                        .collect();
                    (*source, PeerInfoForGlobalMap { direct_peers })
                })
                .collect();
            GetGlobalPeerMapResponse {
                global_peer_map,
                digest: Some(snapshot.generation),
                deltas: Vec::new(),
                full_snapshot: true,
                snapshot_residence_age_ms: 0,
            }
        });
        let mut response = full_response.clone();
        response.snapshot_residence_age_ms =
            u64::try_from(snapshot.published_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated(peer_id: PeerId) -> BaseController {
        let mut ctrl = BaseController::default();
        ctrl.set_authenticated_peer_id(Some(peer_id));
        ctrl.set_authenticated_peer_identity_type(Some(
            crate::proto::peer_rpc::PeerIdentityType::Admin,
        ));
        ctrl.set_authenticated_peer_secure_auth_level(Some(
            crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed,
        ));
        ctrl
    }
}
