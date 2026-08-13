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

    #[tokio::test]
    async fn server_clones_share_instance_data() {
        let server = PeerCenterServer::new();
        let server_clone = server.clone();

        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            100,
            DirectConnectedPeerInfo {
                latency_ms: 3,
                ..Default::default()
            },
        );

        server
            .report_peers(
                authenticated(99),
                ReportPeersRequest {
                    my_peer_id: 99,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp = server_clone
            .get_global_peer_map(authenticated(100), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        assert_eq!(1, resp.global_peer_map.len());
        assert!(resp.global_peer_map[&99].direct_peers.contains_key(&100));
    }

    #[tokio::test]
    async fn report_replaces_complete_source_adjacency() {
        let server = PeerCenterServer::new();
        let mut first_peers = PeerInfoForGlobalMap::default();
        first_peers
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        first_peers
            .direct_peers
            .insert(3, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(first_peers),
                },
            )
            .await
            .unwrap();

        let first = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        tokio::time::sleep(MIN_REPORT_INTERVAL).await;

        let mut replacement = PeerInfoForGlobalMap::default();
        replacement
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(replacement),
                },
            )
            .await
            .unwrap();

        let second = server
            .get_global_peer_map(
                authenticated(2),
                GetGlobalPeerMapRequest {
                    digest: first.digest.unwrap(),
                },
            )
            .await
            .unwrap();
        assert_eq!(second.global_peer_map[&1].direct_peers.len(), 1);
        assert!(second.global_peer_map[&1].direct_peers.contains_key(&2));
        assert!(!second.global_peer_map[&1].direct_peers.contains_key(&3));
        assert_ne!(first.digest, second.digest);
    }

    #[tokio::test]
    async fn rejected_report_does_not_change_published_snapshot() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();
        let first = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        tokio::time::sleep(MIN_REPORT_INTERVAL).await;

        let mut too_many_peers = PeerInfoForGlobalMap::default();
        too_many_peers.direct_peers = (2..=MAX_DIRECT_PEERS_PER_REPORT as u32 + 2)
            .map(|peer_id| (peer_id, DirectConnectedPeerInfo::default()))
            .collect();
        let result = server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(too_many_peers),
                },
            )
            .await;
        assert!(result.is_err());

        let second = server
            .get_global_peer_map(authenticated(3), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(second.global_peer_map[&1].direct_peers.len(), 1);
    }

    #[tokio::test]
    async fn independent_server_instances_do_not_share_data() {
        let server_a = PeerCenterServer::new();
        let server_b = PeerCenterServer::new();

        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            101,
            DirectConnectedPeerInfo {
                latency_ms: 5,
                ..Default::default()
            },
        );

        server_a
            .report_peers(
                authenticated(100),
                ReportPeersRequest {
                    my_peer_id: 100,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp_a = server_a
            .get_global_peer_map(authenticated(101), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        assert_eq!(1, resp_a.global_peer_map.len());

        let resp_b = server_b
            .get_global_peer_map(authenticated(102), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        assert!(resp_b.global_peer_map.is_empty());
    }

    #[tokio::test]
    async fn server_preserves_directed_speed_and_adds_residence_age() {
        let server = PeerCenterServer::new();
        let forward = DirectConnectedPeerInfo {
            latency_ms: 70,
            tx_delivery_bps: 20_000_000,
            tx_loss_ppm: 1_000,
            speed_sample_age_ms: 11,
            speed_sample_ttl_ms: 90_000,
            speed_probe_generation: 7,
        };
        let reverse = DirectConnectedPeerInfo {
            latency_ms: 160,
            tx_delivery_bps: 5_000_000,
            tx_loss_ppm: 2_000,
            speed_sample_age_ms: 13,
            speed_sample_ttl_ms: 90_000,
            speed_probe_generation: 8,
        };

        for (source, destination, info) in [(1, 2, forward), (2, 1, reverse)] {
            let mut peers = PeerInfoForGlobalMap::default();
            peers.direct_peers.insert(destination, info);
            server
                .report_peers(
                    authenticated(source),
                    ReportPeersRequest {
                        my_peer_id: source,
                        peer_infos: Some(peers),
                    },
                )
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let response = server
            .get_global_peer_map(authenticated(1), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        let actual_forward = &response.global_peer_map[&1].direct_peers[&2];
        let actual_reverse = &response.global_peer_map[&2].direct_peers[&1];
        assert_eq!(actual_forward.tx_delivery_bps, 20_000_000);
        assert_eq!(actual_reverse.tx_delivery_bps, 5_000_000);
        assert!(actual_forward.speed_sample_age_ms >= 21);
        assert!(actual_reverse.speed_sample_age_ms >= 23);
    }

    #[tokio::test]
    async fn delivery_change_updates_digest_without_a_topology_change() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            2,
            DirectConnectedPeerInfo {
                tx_delivery_bps: 5_000_000,
                speed_sample_ttl_ms: 90_000,
                ..Default::default()
            },
        );
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers.clone()),
                },
            )
            .await
            .unwrap();
        let first = server
            .get_global_peer_map(authenticated(1), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        peers.direct_peers.get_mut(&2).unwrap().tx_delivery_bps = 20_000_000;
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();
        let second = server
            .get_global_peer_map(
                authenticated(1),
                GetGlobalPeerMapRequest {
                    digest: first.digest.unwrap(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            second.global_peer_map[&1].direct_peers[&2].tx_delivery_bps,
            20_000_000
        );
        assert_ne!(first.digest, second.digest);
    }

    #[tokio::test]
    async fn report_peers_rejects_a_spoofed_source_peer() {
        let server = PeerCenterServer::new();
        let result = server
            .report_peers(
                authenticated(7),
                ReportPeersRequest {
                    my_peer_id: 8,
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[tokio::test]
    async fn report_peers_rejects_implausible_link_quality() {
        let server = PeerCenterServer::new();
        for info in [
            DirectConnectedPeerInfo {
                latency_ms: 1,
                tx_delivery_bps: MAX_REPORTED_DELIVERY_BPS + 1,
                ..Default::default()
            },
            DirectConnectedPeerInfo {
                latency_ms: 1,
                tx_delivery_bps: 1,
                speed_sample_ttl_ms: MAX_REPORTED_SAMPLE_TTL_MS + 1,
                ..Default::default()
            },
            DirectConnectedPeerInfo {
                latency_ms: 1,
                tx_delivery_bps: 1,
                speed_sample_age_ms: 100,
                speed_sample_ttl_ms: 100,
                ..Default::default()
            },
            DirectConnectedPeerInfo {
                latency_ms: -1,
                ..Default::default()
            },
        ] {
            let mut peers = PeerInfoForGlobalMap::default();
            peers.direct_peers.insert(2, info);
            let result = server
                .report_peers(
                    authenticated(1),
                    ReportPeersRequest {
                        my_peer_id: 1,
                        peer_infos: Some(peers),
                    },
                )
                .await;
            assert!(matches!(
                result,
                Err(rpc_types::error::Error::MalformatRpcPacket(_))
            ));
        }
    }

    #[tokio::test]
    async fn report_peers_caps_entries_and_report_rate() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers = (2..(2 + MAX_DIRECT_PEERS_PER_REPORT as u32 + 1))
            .map(|peer_id| {
                (
                    peer_id,
                    DirectConnectedPeerInfo {
                        latency_ms: 1,
                        ..Default::default()
                    },
                )
            })
            .collect();
        let result = server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));

        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            2,
            DirectConnectedPeerInfo {
                latency_ms: 1,
                ..Default::default()
            },
        );
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers.clone()),
                },
            )
            .await
            .unwrap();
        let result = server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[tokio::test]
    async fn report_peers_rate_limit_is_atomic_for_concurrent_reports() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers.direct_peers.insert(
            2,
            DirectConnectedPeerInfo {
                latency_ms: 1,
                ..Default::default()
            },
        );
        let request = ReportPeersRequest {
            my_peer_id: 1,
            peer_infos: Some(peers),
        };

        let (first, second) = tokio::join!(
            server.report_peers(authenticated(1), request.clone()),
            server.report_peers(authenticated(1), request),
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    }

    #[tokio::test]
    async fn get_global_peer_map_requires_authentication() {
        let server = PeerCenterServer::new();
        let result = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest::default(),
            )
            .await;
        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[tokio::test]
    async fn peer_verified_admin_metadata_cannot_publish_or_read_costs() {
        let server = PeerCenterServer::new();
        let mut ctrl = authenticated(1);
        ctrl.set_authenticated_peer_secure_auth_level(Some(
            crate::proto::peer_rpc::SecureAuthLevel::PeerVerified,
        ));
        let report = server
            .report_peers(
                ctrl.clone(),
                ReportPeersRequest {
                    my_peer_id: 1,
                    ..Default::default()
                },
            )
            .await;
        assert!(report.is_err());

        let read = server
            .get_global_peer_map(ctrl, GetGlobalPeerMapRequest::default())
            .await;
        assert!(read.is_err());
    }

    #[test]
    fn concurrent_snapshot_reads_keep_one_generation() {
        let data = Arc::new(PeerCenterServerData::default());
        let writer_data = data.clone();
        let writer = std::thread::spawn(move || {
            for index in 0..2_000_u32 {
                let destination = if index % 2 == 0 { 2 } else { 3 };
                let mut edges = HashMap::new();
                edges.insert(
                    destination,
                    PeerCenterInfoEntry {
                        info: DirectConnectedPeerInfo::default(),
                        update_time: std::time::Instant::now(),
                    },
                );
                let mut state = writer_data.writer.lock().unwrap();
                validate_source_replacement(
                    &state,
                    1,
                    &HashMap::from([(destination, DirectConnectedPeerInfo::default())]),
                )
                .unwrap();
                replace_source(
                    &writer_data,
                    &mut state,
                    1,
                    edges,
                    std::time::Instant::now(),
                );
            }
        });

        for _ in 0..2_000 {
            let snapshot = data.snapshot.load();
            assert_ne!(snapshot.generation, 0);
            if let Some(source) = snapshot.sources.get(&1) {
                assert_eq!(source.edges.len(), 1);
                assert!(source.edges.contains_key(&2) || source.edges.contains_key(&3));
            }
        }
        writer.join().unwrap();
    }

    #[tokio::test]
    async fn cleanup_removes_stale_sources_and_publishes_generation() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();
        let first = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();

        {
            let mut state = server.data.writer.lock().unwrap();
            state.report_times.insert(
                1,
                std::time::Instant::now()
                    .checked_sub(PEER_REPORT_EXPIRY + Duration::from_secs(1))
                    .unwrap(),
            );
        }
        PeerCenterServer::clean_outdated_peer_data(&server.data);

        let second = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest { digest: 0 })
            .await
            .unwrap();
        assert!(second.global_peer_map.is_empty());
        assert_ne!(first.digest, second.digest);
    }

    #[test]
    fn source_bounds_reject_without_state_mutation() {
        let mut source_limit_state = PeerCenterWriterState::new();
        for source in 0..MAX_REPORT_SOURCES as u32 {
            source_limit_state.sources.insert(
                source,
                Arc::new(SourceAdjacency {
                    edges: Arc::new(HashMap::new()),
                }),
            );
            source_limit_state.node_ref_counts.insert(source, 1);
        }
        let source_limit_before = (
            source_limit_state.sources.len(),
            source_limit_state.node_ref_counts.len(),
            source_limit_state.total_edges,
            source_limit_state.generation,
        );
        assert!(
            validate_source_replacement(
                &source_limit_state,
                MAX_REPORT_SOURCES as u32 + 1,
                &HashMap::new(),
            )
            .is_err()
        );
        assert_eq!(
            source_limit_before,
            (
                source_limit_state.sources.len(),
                source_limit_state.node_ref_counts.len(),
                source_limit_state.total_edges,
                source_limit_state.generation,
            )
        );

        let mut edge_limit_state = PeerCenterWriterState::new();
        edge_limit_state.total_edges = MAX_TOTAL_DIRECTED_EDGES;
        assert!(
            validate_source_replacement(
                &edge_limit_state,
                1,
                &HashMap::from([(2, DirectConnectedPeerInfo::default())]),
            )
            .is_err()
        );

        let mut node_limit_state = PeerCenterWriterState::new();
        node_limit_state.node_ref_counts = (0..MAX_UNIQUE_NODES as u32)
            .map(|peer_id| (peer_id, 1))
            .collect();
        assert!(
            validate_source_replacement(
                &node_limit_state,
                MAX_UNIQUE_NODES as u32 + 1,
                &HashMap::from([(
                    MAX_UNIQUE_NODES as u32 + 2,
                    DirectConnectedPeerInfo::default()
                )]),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn fresh_server_epoch_does_not_accept_an_old_digest() {
        let old_server = PeerCenterServer::with_generation(7);
        let old_digest = old_server
            .get_global_peer_map(authenticated(1), GetGlobalPeerMapRequest::default())
            .await
            .unwrap()
            .digest
            .unwrap();
        let fresh_server = PeerCenterServer::with_generation(8);
        let fresh = fresh_server
            .get_global_peer_map(
                authenticated(1),
                GetGlobalPeerMapRequest { digest: old_digest },
            )
            .await
            .unwrap();
        assert_ne!(old_digest, fresh.digest.unwrap());
        assert_ne!(fresh, GetGlobalPeerMapResponse::default());
    }

    #[tokio::test]
    async fn matching_digest_returns_unchanged_response_and_new_generation_fetches() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let first = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest::default())
            .await
            .unwrap();
        let matching = server
            .get_global_peer_map(
                authenticated(2),
                GetGlobalPeerMapRequest {
                    digest: first.digest.unwrap(),
                },
            )
            .await
            .unwrap();
        assert_eq!(matching, GetGlobalPeerMapResponse::default());

        tokio::time::sleep(MIN_REPORT_INTERVAL).await;
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(PeerInfoForGlobalMap::default()),
                },
            )
            .await
            .unwrap();
        let updated = server
            .get_global_peer_map(
                authenticated(2),
                GetGlobalPeerMapRequest {
                    digest: first.digest.unwrap(),
                },
            )
            .await
            .unwrap();
        assert!(updated.global_peer_map.is_empty());
        assert_ne!(updated.digest, first.digest);
    }

    #[tokio::test]
    async fn full_map_response_is_reused_until_generation_changes() {
        let server = PeerCenterServer::new();
        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(2, DirectConnectedPeerInfo::default());
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let first_response = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest::default())
            .await
            .unwrap();
        let first_snapshot = server.data.snapshot.load();
        assert!(first_snapshot.full_response.get().is_some());
        let second_snapshot = server.data.snapshot.load();
        assert!(std::ptr::eq(
            first_snapshot.full_response.get().unwrap(),
            second_snapshot.full_response.get().unwrap()
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let later_response = server
            .get_global_peer_map(authenticated(3), GetGlobalPeerMapRequest::default())
            .await
            .unwrap();
        assert!(
            later_response.snapshot_residence_age_ms > first_response.snapshot_residence_age_ms
        );
        let repeated = server
            .get_global_peer_map(authenticated(2), GetGlobalPeerMapRequest::default())
            .await;
        assert!(repeated.is_err());

        tokio::time::sleep(MIN_REPORT_INTERVAL).await;
        server
            .report_peers(
                authenticated(1),
                ReportPeersRequest {
                    my_peer_id: 1,
                    peer_infos: Some(PeerInfoForGlobalMap::default()),
                },
            )
            .await
            .unwrap();
        let third_snapshot = server.data.snapshot.load();
        assert!(third_snapshot.full_response.get().is_none());
        assert_eq!(first_response.global_peer_map.len(), 1);
    }
}
