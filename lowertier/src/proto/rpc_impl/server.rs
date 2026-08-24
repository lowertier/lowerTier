use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use prost::Message;
use quanta::Instant;
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};
use tokio_stream::StreamExt;

use crate::{
    common::{
        PeerId, join_joinset_background,
        stats_manager::{LabelSet, LabelType, MetricName, StatsManager},
    },
    proto::{
        common::{self, RpcCompressionInfo, RpcPacket, RpcRequest, RpcResponse, TunnelInfo},
        rpc_impl::packet::BuildRpcPacketArgs,
        rpc_types::{
            controller::Controller,
            error::{Error, Result},
        },
    },
    tunnel::{
        Tunnel, ZCPacketStream,
        batch::BatchToScalarStream,
        mpsc::{MpscTunnel, MpscTunnelSender},
        ring::create_ring_tunnel_pair,
    },
};

fn foreign_relay_rpc_allowed(desc: &common::RpcDescriptor) -> bool {
    // Match generated service descriptors. Do not authorize by method labels.
    matches!(
        (desc.proto_name.as_str(), desc.service_name.as_str()),
        ("OspfRouteRpc", "OspfRouteRpc") | ("DirectConnectorRpc", "DirectConnectorRpc")
    )
}

fn rpc_source_matches_authenticated_peer(
    authenticated_peer_id: Option<PeerId>,
    claimed_peer_id: PeerId,
    claimed_destination_peer_id: PeerId,
    transport_source_peer_id: Option<PeerId>,
    transport_destination_peer_id: Option<PeerId>,
) -> bool {
    match authenticated_peer_id {
        Some(peer_id) => peer_id == claimed_peer_id,
        None => {
            claimed_peer_id == claimed_destination_peer_id
                && transport_source_peer_id == Some(claimed_peer_id)
                && transport_destination_peer_id == Some(claimed_destination_peer_id)
        }
    }
}

fn rpc_authentication_tuple_valid(
    authenticated_peer_id: Option<PeerId>,
    authenticated_peer_identity_type: Option<crate::proto::peer_rpc::PeerIdentityType>,
    authenticated_peer_secure_auth_level: Option<crate::proto::peer_rpc::SecureAuthLevel>,
    authenticated_session_id: Option<uuid::Uuid>,
) -> bool {
    match (
        authenticated_peer_id,
        authenticated_peer_identity_type,
        authenticated_peer_secure_auth_level,
        authenticated_session_id,
    ) {
        (None, None, None, None) => true,
        (
            Some(_),
            Some(
                crate::proto::peer_rpc::PeerIdentityType::ForeignRelay
                | crate::proto::peer_rpc::PeerIdentityType::SharedNode,
            ),
            Some(level),
            Some(_),
        ) => matches!(
            level,
            crate::proto::peer_rpc::SecureAuthLevel::EncryptedUnauthenticated
                | crate::proto::peer_rpc::SecureAuthLevel::PeerVerified
        ),
        (Some(_), Some(_), Some(level), Some(_)) => {
            level >= crate::proto::peer_rpc::SecureAuthLevel::PeerVerified
        }
        _ => false,
    }
}

use super::{
    RpcController, Transport,
    packet::{
        MAX_RPC_BODY_BYTES, PacketMerger, build_rpc_packet, compress_packet, decompress_packet,
        logical_body_size, supported_rpc_compression,
    },
    service_registry::ServiceRegistry,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PacketMergerKey {
    authenticated_peer_id: Option<PeerId>,
    authenticated_peer_identity_type: Option<crate::proto::peer_rpc::PeerIdentityType>,
    authenticated_peer_secure_auth_level: Option<crate::proto::peer_rpc::SecureAuthLevel>,
    authenticated_session_id: Option<uuid::Uuid>,
    from_peer_id: PeerId,
    transaction_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MergerSessionKey {
    peer_id: PeerId,
    session_id: uuid::Uuid,
}

const LOCAL_RPC_BUDGET_PEER_ID: PeerId = 0;

fn rpc_budget_session(
    authenticated_peer_id: Option<PeerId>,
    authenticated_session_id: Option<uuid::Uuid>,
) -> Option<MergerSessionKey> {
    match (authenticated_peer_id, authenticated_session_id) {
        (Some(peer_id), Some(session_id)) => Some(MergerSessionKey {
            peer_id,
            session_id,
        }),
        (None, None) => Some(MergerSessionKey {
            peer_id: LOCAL_RPC_BUDGET_PEER_ID,
            session_id: uuid::Uuid::nil(),
        }),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct MergerSessionUsage {
    transactions: usize,
    bytes: usize,
}

#[derive(Debug)]
struct MergerBudget {
    transactions: usize,
    bytes: usize,
    sessions: HashMap<MergerSessionKey, MergerSessionUsage>,
    peers: HashMap<PeerId, MergerSessionUsage>,
    process_memory: Arc<crate::common::global_ctx::ProcessMemoryGovernor>,
}

const MAX_RPC_MERGER_TRANSACTIONS: usize = 256;
const MAX_RPC_MERGER_TRANSACTIONS_PER_PEER: usize = 64;
const MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION: usize = 16;
const MAX_RPC_MERGER_BYTES: usize = 512 * 1024;
const MAX_RPC_MERGER_BYTES_PER_PEER: usize = 256 * 1024;
const MAX_RPC_MERGER_BYTES_PER_SESSION: usize = 256 * 1024;
const MAX_RPC_TIMEOUT_MS: u64 = 120_000;
const MAX_RPC_TASKS: usize = 64;
const MAX_RPC_TASKS_PER_PEER: usize = 16;
const MAX_RPC_TASKS_PER_SESSION: usize = 8;

impl MergerBudget {
    fn reserve(&mut self, session: &MergerSessionKey, new_transaction: bool, bytes: usize) -> bool {
        let Some(new_bytes) = self.bytes.checked_add(bytes) else {
            return false;
        };
        if new_bytes > MAX_RPC_MERGER_BYTES {
            return false;
        }
        let (current_transactions, current_session_bytes) = self
            .sessions
            .get(session)
            .map(|usage| (usage.transactions, usage.bytes))
            .unwrap_or((0, 0));
        let (current_peer_transactions, current_peer_bytes) = self
            .peers
            .get(&session.peer_id)
            .map(|usage| (usage.transactions, usage.bytes))
            .unwrap_or((0, 0));
        if new_transaction
            && (self.transactions >= MAX_RPC_MERGER_TRANSACTIONS
                || current_peer_transactions >= MAX_RPC_MERGER_TRANSACTIONS_PER_PEER
                || current_transactions >= MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION)
        {
            return false;
        }
        let Some(session_bytes) = current_session_bytes.checked_add(bytes) else {
            return false;
        };
        if session_bytes > MAX_RPC_MERGER_BYTES_PER_SESSION {
            return false;
        }
        let Some(peer_bytes) = current_peer_bytes.checked_add(bytes) else {
            return false;
        };
        if peer_bytes > MAX_RPC_MERGER_BYTES_PER_PEER {
            return false;
        }
        if !self.process_memory.reserve(bytes) {
            return false;
        }
        self.bytes = new_bytes;
        let session_usage = self.sessions.entry(session.clone()).or_default();
        session_usage.bytes = session_bytes;
        let peer_usage = self.peers.entry(session.peer_id).or_default();
        peer_usage.bytes = peer_bytes;
        if new_transaction {
            self.transactions += 1;
            session_usage.transactions += 1;
            peer_usage.transactions += 1;
        }
        true
    }

    fn release(&mut self, session: &MergerSessionKey, transaction: bool, bytes: usize) {
        self.process_memory.release(bytes);
        self.bytes = self.bytes.saturating_sub(bytes);
        let mut remove = false;
        let mut remove_peer = false;
        if let Some(usage) = self.sessions.get_mut(session) {
            usage.bytes = usage.bytes.saturating_sub(bytes);
            if transaction {
                usage.transactions = usage.transactions.saturating_sub(1);
                self.transactions = self.transactions.saturating_sub(1);
            }
            remove = usage.transactions == 0 && usage.bytes == 0;
        }
        if remove {
            self.sessions.remove(session);
        }
        if let Some(usage) = self.peers.get_mut(&session.peer_id) {
            usage.bytes = usage.bytes.saturating_sub(bytes);
            if transaction {
                usage.transactions = usage.transactions.saturating_sub(1);
            }
            remove_peer = usage.transactions == 0 && usage.bytes == 0;
        }
        if remove_peer {
            self.peers.remove(&session.peer_id);
        }
    }

    fn reserve_execution(&mut self, session: &MergerSessionKey, bytes: usize) -> bool {
        let Some(new_bytes) = self.bytes.checked_add(bytes) else {
            return false;
        };
        if new_bytes > MAX_RPC_MERGER_BYTES {
            return false;
        }
        let current_session_bytes = self
            .sessions
            .get(session)
            .map(|usage| usage.bytes)
            .unwrap_or(0);
        let current_peer_bytes = self
            .peers
            .get(&session.peer_id)
            .map(|usage| usage.bytes)
            .unwrap_or(0);
        let Some(new_session_bytes) = current_session_bytes.checked_add(bytes) else {
            return false;
        };
        if new_session_bytes > MAX_RPC_MERGER_BYTES_PER_SESSION {
            return false;
        }
        let Some(new_peer_bytes) = current_peer_bytes.checked_add(bytes) else {
            return false;
        };
        if new_peer_bytes > MAX_RPC_MERGER_BYTES_PER_PEER {
            return false;
        }
        if !self.process_memory.reserve(bytes) {
            return false;
        }
        let usage = self.sessions.entry(session.clone()).or_default();
        self.bytes = new_bytes;
        usage.bytes = new_session_bytes;
        self.peers.entry(session.peer_id).or_default().bytes = new_peer_bytes;
        true
    }

    fn release_execution(&mut self, session: &MergerSessionKey, bytes: usize) {
        self.release(session, false, bytes);
    }

    fn transfer_to_execution(
        &mut self,
        session: &MergerSessionKey,
        retained_bytes: usize,
        logical_bytes: usize,
    ) -> bool {
        let Some(usage) = self.sessions.get_mut(session) else {
            return false;
        };
        let Some(peer_usage) = self.peers.get_mut(&session.peer_id) else {
            return false;
        };
        if usage.transactions == 0 || usage.bytes < retained_bytes || self.bytes < retained_bytes {
            return false;
        }
        let remaining_bytes = self.bytes - retained_bytes;
        let remaining_session_bytes = usage.bytes - retained_bytes;
        let remaining_peer_bytes = peer_usage.bytes.saturating_sub(retained_bytes);
        let Some(new_bytes) = remaining_bytes.checked_add(logical_bytes) else {
            return false;
        };
        let Some(new_session_bytes) = remaining_session_bytes.checked_add(logical_bytes) else {
            return false;
        };
        let Some(new_peer_bytes) = remaining_peer_bytes.checked_add(logical_bytes) else {
            return false;
        };
        if new_bytes > MAX_RPC_MERGER_BYTES
            || new_peer_bytes > MAX_RPC_MERGER_BYTES_PER_PEER
            || new_session_bytes > MAX_RPC_MERGER_BYTES_PER_SESSION
        {
            return false;
        }

        let additional = logical_bytes.saturating_sub(retained_bytes);
        if additional > 0 && !self.process_memory.reserve(additional) {
            return false;
        }

        self.bytes = new_bytes;
        usage.bytes = new_session_bytes;
        usage.transactions = usage.transactions.saturating_sub(1);
        peer_usage.bytes = new_peer_bytes;
        peer_usage.transactions = peer_usage.transactions.saturating_sub(1);
        self.transactions = self.transactions.saturating_sub(1);
        if retained_bytes > logical_bytes {
            self.process_memory.release(retained_bytes - logical_bytes);
        }
        true
    }
}

impl Default for MergerBudget {
    fn default() -> Self {
        Self {
            transactions: 0,
            bytes: 0,
            sessions: HashMap::new(),
            peers: HashMap::new(),
            process_memory: crate::common::global_ctx::global_process_memory_governor(),
        }
    }
}

struct ExecutionBudgetPermit {
    budget: Option<Arc<Mutex<MergerBudget>>>,
    session: Option<MergerSessionKey>,
    bytes: usize,
}

impl ExecutionBudgetPermit {
    fn new(
        budget: Option<Arc<Mutex<MergerBudget>>>,
        session: Option<MergerSessionKey>,
        bytes: usize,
    ) -> Self {
        Self {
            budget,
            session,
            bytes,
        }
    }

    fn reserve_extra(&mut self, bytes: usize) -> bool {
        let (Some(budget), Some(session)) = (self.budget.as_ref(), self.session.as_ref()) else {
            return true;
        };
        if !budget.lock().unwrap().reserve_execution(session, bytes) {
            return false;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        true
    }

    fn release_all(&mut self) {
        let bytes = self.bytes;
        self.bytes = 0;
        if bytes == 0 {
            return;
        }
        let (Some(budget), Some(session)) = (self.budget.as_ref(), self.session.as_ref()) else {
            return;
        };
        budget.lock().unwrap().release_execution(session, bytes);
    }
}

impl Drop for ExecutionBudgetPermit {
    fn drop(&mut self) {
        let (Some(budget), Some(session)) = (self.budget.as_ref(), self.session.as_ref()) else {
            return;
        };
        budget
            .lock()
            .unwrap()
            .release_execution(session, self.bytes);
    }
}

pub struct Server {
    registry: Arc<ServiceRegistry>,

    mpsc: Mutex<Option<MpscTunnel<Box<dyn Tunnel>>>>,

    transport: Mutex<Transport>,

    tasks: Arc<Mutex<JoinSet<()>>>,
    packet_mergers: Arc<DashMap<PacketMergerKey, PacketMerger>>,
    merger_budget: Arc<Mutex<MergerBudget>>,
    rpc_task_semaphore: Arc<Semaphore>,
    rpc_peer_task_semaphores: Arc<DashMap<PeerId, Arc<Semaphore>>>,
    rpc_session_task_semaphores: Arc<DashMap<MergerSessionKey, Arc<Semaphore>>>,
    stats_manager: Option<Arc<StatsManager>>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Server::new_with_registry(Arc::new(ServiceRegistry::new()))
    }

    pub fn new_with_registry(registry: Arc<ServiceRegistry>) -> Self {
        let (ring_a, ring_b) = create_ring_tunnel_pair();

        Self {
            registry,
            mpsc: Mutex::new(Some(MpscTunnel::new(ring_a, None))),
            transport: Mutex::new(MpscTunnel::new(ring_b, None)),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            packet_mergers: Arc::new(DashMap::new()),
            merger_budget: Arc::new(Mutex::new(MergerBudget::default())),
            rpc_task_semaphore: Arc::new(Semaphore::new(MAX_RPC_TASKS)),
            rpc_peer_task_semaphores: Arc::new(DashMap::new()),
            rpc_session_task_semaphores: Arc::new(DashMap::new()),
            stats_manager: None,
        }
    }

    pub fn new_with_registry_and_stats_manager(
        registry: Arc<ServiceRegistry>,
        stats_manager: Arc<StatsManager>,
    ) -> Self {
        let mut ret = Self::new_with_registry(registry);
        ret.stats_manager = Some(stats_manager);
        ret
    }

    pub fn registry(&self) -> &ServiceRegistry {
        &self.registry
    }

    pub fn get_transport_sink(&self) -> MpscTunnelSender {
        self.transport.lock().unwrap().get_sink()
    }

    pub fn get_transport_stream(&self) -> Pin<Box<dyn ZCPacketStream>> {
        Box::pin(BatchToScalarStream::new(
            self.transport.lock().unwrap().get_stream(),
        ))
    }

    pub fn run(&self) {
        let tasks = self.tasks.clone();
        join_joinset_background(tasks.clone(), "rpc server".to_string());

        let mpsc = self.mpsc.lock().unwrap().take().unwrap();

        let packet_merges = self.packet_mergers.clone();
        let merger_budget = self.merger_budget.clone();
        let rpc_task_semaphore = self.rpc_task_semaphore.clone();
        let rpc_peer_task_semaphores = self.rpc_peer_task_semaphores.clone();
        let rpc_session_task_semaphores = self.rpc_session_task_semaphores.clone();
        let reg = self.registry.clone();
        let stats_manager = self.stats_manager.clone();
        let t = Arc::downgrade(&tasks);
        let tunnel_info = mpsc.tunnel_info();
        tasks.lock().unwrap().spawn(async move {
            let mut mpsc = mpsc;
            let mut rx = BatchToScalarStream::new(mpsc.get_stream());

            while let Some(packet) = rx.next().await {
                if let Err(err) = packet {
                    tracing::error!(?err, "Failed to receive packet");
                    continue;
                }
                let packet = packet.unwrap();
                let transport_source_peer_id = packet.get_src_peer_id();
                let transport_destination_peer_id = packet.get_dst_peer_id();
                let authenticated_peer_id = packet.logical_authenticated_peer_id();
                let authenticated_peer_identity_type =
                    packet.logical_authenticated_peer_identity_type();
                let authenticated_peer_secure_auth_level =
                    packet.logical_authenticated_peer_secure_auth_level();
                let authenticated_session_id = packet.logical_authenticated_session_id();
                if !rpc_authentication_tuple_valid(
                    authenticated_peer_id,
                    authenticated_peer_identity_type,
                    authenticated_peer_secure_auth_level,
                    authenticated_session_id,
                ) {
                    tracing::warn!("Dropping RPC packet with invalid authentication metadata");
                    continue;
                }
                let packet = match common::RpcPacket::decode(packet.payload()) {
                    Err(err) => {
                        tracing::error!(?err, "Failed to decode packet");
                        continue;
                    }
                    Ok(packet) => packet,
                };

                let unfragmented = packet.total_pieces <= 1;
                if unfragmented && packet.piece_idx != 0 {
                    tracing::warn!(
                        from_peer = packet.from_peer,
                        transaction_id = packet.transaction_id,
                        piece_idx = packet.piece_idx,
                        "Dropping RPC packet with an invalid unfragmented piece index"
                    );
                    continue;
                }
                if unfragmented && packet.body.len() > MAX_RPC_BODY_BYTES {
                    tracing::warn!(
                        from_peer = packet.from_peer,
                        transaction_id = packet.transaction_id,
                        body_bytes = packet.body.len(),
                        "Dropping unfragmented RPC body above the protocol limit"
                    );
                    continue;
                }

                let Some(task_session) =
                    rpc_budget_session(authenticated_peer_id, authenticated_session_id)
                else {
                    tracing::warn!(
                        from_peer = packet.from_peer,
                        transaction_id = packet.transaction_id,
                        "Dropping RPC packet with incomplete authentication metadata"
                    );
                    continue;
                };
                let merger_session = (!unfragmented).then_some(task_session.clone());

                if !packet.is_request {
                    tracing::warn!(
                        transaction_id = packet.transaction_id,
                        body_len = packet.body.len(),
                        "Received non-request RPC packet"
                    );
                    continue;
                }

                if matches!(
                    authenticated_peer_identity_type,
                    Some(
                        crate::proto::peer_rpc::PeerIdentityType::ForeignRelay
                            | crate::proto::peer_rpc::PeerIdentityType::SharedNode
                    )
                ) {
                    let Some(desc) = packet.descriptor.as_ref() else {
                        tracing::warn!(
                            from_peer = packet.from_peer,
                            transaction_id = packet.transaction_id,
                            piece_idx = packet.piece_idx,
                            "Dropping foreign relay RPC piece without descriptor"
                        );
                        continue;
                    };
                    if !foreign_relay_rpc_allowed(desc) {
                        tracing::warn!(
                            from_peer = packet.from_peer,
                            transaction_id = packet.transaction_id,
                            piece_idx = packet.piece_idx,
                            proto_name = %desc.proto_name,
                            service_name = %desc.service_name,
                            "Dropping foreign relay RPC piece for denied service"
                        );
                        continue;
                    }
                }

                if !rpc_source_matches_authenticated_peer(
                    authenticated_peer_id,
                    packet.from_peer,
                    packet.to_peer,
                    transport_source_peer_id,
                    transport_destination_peer_id,
                ) {
                    tracing::warn!(
                        authenticated_peer_id,
                        claimed_peer_id = packet.from_peer,
                        transaction_id = packet.transaction_id,
                        "Dropping RPC packet with a spoofed source peer"
                    );
                    continue;
                }

                let key = PacketMergerKey {
                    authenticated_peer_id,
                    authenticated_peer_identity_type,
                    authenticated_peer_secure_auth_level,
                    authenticated_session_id,
                    from_peer_id: packet.from_peer,
                    transaction_id: packet.transaction_id,
                };

                tracing::trace!(
                    ?key,
                    piece_idx = packet.piece_idx,
                    total_pieces = packet.total_pieces,
                    body_len = packet.body.len(),
                    "Received request RPC packet"
                );

                let mut reserved_bytes = 0usize;
                let actual_delta: usize;
                let mut removed_bytes = 0usize;
                let mut transaction_reserved = false;
                let mut completed_packet = None;
                let mut feed_error = None;

                if unfragmented {
                    // Reject a mode change while a fragmented transaction is
                    // active. The packet never removes that entry or budget.
                    if packet_merges.contains_key(&key) {
                        tracing::warn!(
                            from_peer = packet.from_peer,
                            transaction_id = packet.transaction_id,
                            "Dropping unfragmented RPC packet while fragmented transaction is active"
                        );
                        continue;
                    }
                    // Unfragmented packets bypass the merger map.
                    actual_delta = 0;
                    completed_packet = Some(packet);
                } else {
                    match packet_merges.entry(key.clone()) {
                        Entry::Occupied(mut entry) => {
                            let before = entry.get().retained_bytes();
                            if let Some(session) = merger_session.as_ref() {
                                reserved_bytes = PacketMerger::reservation_bytes(&packet, false)
                                    .unwrap_or(usize::MAX);
                                if reserved_bytes == usize::MAX
                                    || !merger_budget.lock().unwrap().reserve(
                                        session,
                                        false,
                                        reserved_bytes,
                                    )
                                {
                                    tracing::warn!(
                                        ?session,
                                        from_peer = packet.from_peer,
                                        transaction_id = packet.transaction_id,
                                        "Dropping RPC fragment because the merger budget is full"
                                    );
                                    continue;
                                }
                            }
                            let ret = entry.get_mut().feed(packet);
                            let after = entry.get().retained_bytes();
                            actual_delta = after.saturating_sub(before);
                            match ret {
                                Ok(Some(packet)) => {
                                    removed_bytes = after;
                                    completed_packet = Some(packet);
                                    entry.remove();
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    removed_bytes = after;
                                    feed_error = Some(error);
                                    entry.remove();
                                }
                            }
                        }
                        Entry::Vacant(entry) => {
                            let new_transaction = true;
                            if let Some(session) = merger_session.as_ref() {
                                reserved_bytes = PacketMerger::reservation_bytes(&packet, true)
                                    .unwrap_or(usize::MAX);
                                if reserved_bytes == usize::MAX
                                    || !merger_budget.lock().unwrap().reserve(
                                        session,
                                        new_transaction,
                                        reserved_bytes,
                                    )
                                {
                                    tracing::warn!(
                                        ?session,
                                        from_peer = packet.from_peer,
                                        transaction_id = packet.transaction_id,
                                        "Dropping RPC fragment because the merger budget is full"
                                    );
                                    continue;
                                }
                                transaction_reserved = new_transaction;
                            }
                            let mut merger = PacketMerger::new();
                            let ret = merger.feed(packet);
                            let after = merger.retained_bytes();
                            actual_delta = after;
                            match ret {
                                Ok(Some(packet)) => {
                                    removed_bytes = after;
                                    completed_packet = Some(packet);
                                }
                                Ok(None) => {
                                    entry.insert(merger);
                                }
                                Err(error) => {
                                    removed_bytes = after;
                                    feed_error = Some(error);
                                }
                            }
                        }
                    }
                }

                let mut execution_permit = None;
                if let Some(session) = merger_session.as_ref() {
                    if reserved_bytes > actual_delta {
                        merger_budget.lock().unwrap().release(
                            session,
                            false,
                            reserved_bytes - actual_delta,
                        );
                    }
                    if let Some(packet) = completed_packet.as_ref() {
                        let logical_bytes = match logical_body_size(packet) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                feed_error = Some(error);
                                0
                            }
                        };
                        let decompressed_extra = packet
                            .compression_info
                            .as_ref()
                            .is_some_and(|info| info.algo() != common::CompressionAlgoPb::None)
                            .then_some(logical_bytes)
                            .unwrap_or(0);
                        let execution_bytes = packet
                            .encoded_len()
                            .checked_add(decompressed_extra)
                            .unwrap_or(usize::MAX);
                        if feed_error.is_none()
                            && merger_budget.lock().unwrap().transfer_to_execution(
                                session,
                                removed_bytes,
                                execution_bytes,
                            )
                        {
                            execution_permit = Some(ExecutionBudgetPermit::new(
                                Some(merger_budget.clone()),
                                Some(session.clone()),
                                execution_bytes,
                            ));
                        } else {
                            completed_packet = None;
                            merger_budget
                                .lock()
                                .unwrap()
                                .release(session, true, removed_bytes);
                        }
                    } else if feed_error.is_some() {
                        merger_budget.lock().unwrap().release(
                            session,
                            transaction_reserved || feed_error.is_some(),
                            removed_bytes,
                        );
                    }
                } else if let Some(packet) = completed_packet.as_ref() {
                    let logical_bytes = match logical_body_size(packet) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            feed_error = Some(error);
                            0
                        }
                    };
                    let execution_bytes = packet
                        .encoded_len()
                        .checked_add(logical_bytes)
                        .unwrap_or(usize::MAX);
                    if feed_error.is_none() {
                        if merger_budget
                            .lock()
                            .unwrap()
                            .reserve_execution(&task_session, execution_bytes)
                        {
                            execution_permit = Some(ExecutionBudgetPermit::new(
                                Some(merger_budget.clone()),
                                Some(task_session.clone()),
                                execution_bytes,
                            ));
                        } else {
                            completed_packet = None;
                            feed_error = Some(Error::MalformatRpcPacket(
                                "RPC execution memory budget is full".to_string(),
                            ));
                        }
                    } else {
                        completed_packet = None;
                    }
                }

                if let Some(packet) = completed_packet {
                    let Some(t) = t.upgrade() else {
                        tracing::error!("tasks is dropped");
                        return;
                    };
                    let Ok(permit) = rpc_task_semaphore.clone().try_acquire_owned() else {
                        tracing::warn!(
                            from_peer = packet.from_peer,
                            transaction_id = packet.transaction_id,
                            "Dropping RPC request because the task limit is full"
                        );
                        continue;
                    };
                    let entry = rpc_peer_task_semaphores.entry(task_session.peer_id);
                    let result = match entry {
                        Entry::Occupied(entry) => entry.get().clone().try_acquire_owned(),
                        Entry::Vacant(entry) => entry
                            .insert(Arc::new(Semaphore::new(MAX_RPC_TASKS_PER_PEER)))
                            .clone()
                            .try_acquire_owned(),
                    };
                    let peer_permit = match result {
                        Ok(permit) => permit,
                        Err(_) => {
                            drop(permit);
                            tracing::warn!(
                                peer_id = task_session.peer_id,
                                transaction_id = packet.transaction_id,
                                "Dropping RPC request because the peer task limit is full"
                            );
                            continue;
                        }
                    };
                    let entry = rpc_session_task_semaphores.entry(task_session.clone());
                    let result = match entry {
                        Entry::Occupied(entry) => entry.get().clone().try_acquire_owned(),
                        Entry::Vacant(entry) => entry
                            .insert(Arc::new(Semaphore::new(MAX_RPC_TASKS_PER_SESSION)))
                            .clone()
                            .try_acquire_owned(),
                    };
                    let session_permit = match result {
                        Ok(permit) => permit,
                        Err(_) => {
                            drop(peer_permit);
                            drop(permit);
                            tracing::warn!(
                                ?task_session,
                                from_peer = packet.from_peer,
                                transaction_id = packet.transaction_id,
                                "Dropping RPC request because the session task limit is full"
                            );
                            continue;
                        }
                    };
                    let sender = mpsc.get_sink();
                    let registry = reg.clone();
                    let task_tunnel_info = tunnel_info.clone();
                    let task_stats_manager = stats_manager.clone();
                    t.lock().unwrap().spawn(async move {
                        let _permit = permit;
                        let _peer_permit = peer_permit;
                        let _session_permit = session_permit;
                        Self::handle_rpc(
                            sender,
                            packet,
                            registry,
                            task_tunnel_info,
                            key.authenticated_peer_id,
                            key.authenticated_peer_identity_type,
                            key.authenticated_peer_secure_auth_level,
                            task_stats_manager,
                            execution_permit,
                        )
                        .await;
                    });
                }
                if let Some(err) = feed_error {
                    tracing::error!("Failed to feed packet to merger, {}", err);
                }
            }
        });

        let packet_mergers = self.packet_mergers.clone();
        let merger_budget = self.merger_budget.clone();
        let rpc_peer_task_semaphores = self.rpc_peer_task_semaphores.clone();
        let rpc_session_task_semaphores = self.rpc_session_task_semaphores.clone();
        tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                let mut expired = Vec::new();
                packet_mergers.retain(|key, v| {
                    let keep = v.last_updated().elapsed().as_secs() < 10;
                    if !keep {
                        if let Some(session) = rpc_budget_session(
                            key.authenticated_peer_id,
                            key.authenticated_session_id,
                        ) {
                            expired.push((session, v.retained_bytes()));
                        }
                    }
                    keep
                });
                if !expired.is_empty() {
                    let mut budget = merger_budget.lock().unwrap();
                    for (session, bytes) in expired {
                        budget.release(&session, true, bytes);
                    }
                }
                packet_mergers.shrink_to_fit();
                rpc_peer_task_semaphores.retain(|_, semaphore| {
                    semaphore.available_permits() < MAX_RPC_TASKS_PER_PEER
                        || Arc::strong_count(semaphore) > 1
                });
                rpc_session_task_semaphores.retain(|_, semaphore| {
                    semaphore.available_permits() < MAX_RPC_TASKS_PER_SESSION
                        || Arc::strong_count(semaphore) > 1
                });
            }
        });
    }

    async fn handle_rpc_request(
        packet: RpcPacket,
        reg: Arc<ServiceRegistry>,
        tunnel_info: Option<TunnelInfo>,
        authenticated_peer_id: Option<PeerId>,
        authenticated_peer_identity_type: Option<crate::proto::peer_rpc::PeerIdentityType>,
        authenticated_peer_secure_auth_level: Option<crate::proto::peer_rpc::SecureAuthLevel>,
    ) -> Result<Bytes> {
        if matches!(
            authenticated_peer_identity_type,
            Some(
                crate::proto::peer_rpc::PeerIdentityType::ForeignRelay
                    | crate::proto::peer_rpc::PeerIdentityType::SharedNode
            )
        ) && !foreign_relay_rpc_allowed(packet.descriptor.as_ref().ok_or_else(|| {
            anyhow::anyhow!("foreign relay RPC request has no service descriptor")
        })?) {
            return Err(anyhow::anyhow!("foreign relay RPC service is not permitted").into());
        }

        let body = if let Some(compression_info) = packet.compression_info {
            let compression_algo = common::CompressionAlgoPb::try_from(compression_info.algo)
                .map_err(|_| {
                    Error::MalformatRpcPacket(format!(
                        "unknown RPC compression algorithm: {}",
                        compression_info.algo
                    ))
                })?;
            decompress_packet(compression_algo, &packet.body).await?
        } else {
            if packet.body.len() > MAX_RPC_BODY_BYTES {
                return Err(Error::MalformatRpcPacket(format!(
                    "RPC body is too large: {} bytes",
                    packet.body.len()
                )));
            }
            packet.body
        };
        let rpc_request = RpcRequest::decode(Bytes::from(body))?;
        let timeout_ms = u64::try_from(rpc_request.timeout_ms)
            .ok()
            .filter(|timeout_ms| (1..=MAX_RPC_TIMEOUT_MS).contains(timeout_ms))
            .ok_or_else(|| {
                Error::MalformatRpcPacket(format!(
                    "RPC timeout must be between 1 and {MAX_RPC_TIMEOUT_MS} milliseconds"
                ))
            })?;
        let timeout_duration = std::time::Duration::from_millis(timeout_ms);
        let mut ctrl = RpcController::default();
        let raw_req = Bytes::from(rpc_request.request);
        ctrl.set_raw_input(raw_req.clone());
        ctrl.set_tunnel_info(tunnel_info);
        ctrl.set_authenticated_peer_id(authenticated_peer_id);
        ctrl.set_authenticated_peer_identity_type(authenticated_peer_identity_type);
        ctrl.set_authenticated_peer_secure_auth_level(authenticated_peer_secure_auth_level);
        let Some(descriptor) = packet.descriptor else {
            return Err(Error::MalformatRpcPacket(
                "descriptor is missing".to_owned(),
            ));
        };
        let ret = timeout(
            timeout_duration,
            reg.call_method(descriptor, ctrl.clone(), raw_req),
        )
        .await??;
        if let Some(raw_output) = ctrl.get_raw_output() {
            Ok(raw_output)
        } else {
            Ok(ret)
        }
    }

    async fn handle_rpc(
        sender: MpscTunnelSender,
        packet: RpcPacket,
        reg: Arc<ServiceRegistry>,
        tunnel_info: Option<TunnelInfo>,
        authenticated_peer_id: Option<PeerId>,
        authenticated_peer_identity_type: Option<crate::proto::peer_rpc::PeerIdentityType>,
        authenticated_peer_secure_auth_level: Option<crate::proto::peer_rpc::SecureAuthLevel>,
        stats_manager: Option<Arc<StatsManager>>,
        mut execution_permit: Option<ExecutionBudgetPermit>,
    ) {
        let from_peer = packet.from_peer;
        let to_peer = packet.to_peer;
        let transaction_id = packet.transaction_id;
        let trace_id = packet.trace_id;
        let Some(desc) = packet.descriptor.clone() else {
            tracing::warn!(
                from_peer,
                transaction_id,
                "Dropping RPC request without descriptor"
            );
            return;
        };
        let (metric_domain, metric_service, method_name) = match reg.get_method_name(&desc) {
            Some(method_name) => (
                desc.domain_name.to_string(),
                desc.service_name.to_string(),
                method_name,
            ),
            None => (
                "__unknown__".to_string(),
                "__unknown__".to_string(),
                "__unknown__".to_string(),
            ),
        };
        let labels = LabelSet::new()
            .with_label_type(LabelType::NetworkName(metric_domain))
            .with_label_type(LabelType::SrcPeerId(from_peer))
            .with_label_type(LabelType::DstPeerId(to_peer))
            .with_label_type(LabelType::ServiceName(metric_service))
            .with_label_type(LabelType::MethodName(method_name));

        // Record RPC server RX stats
        if let Some(ref stats_manager) = stats_manager {
            stats_manager
                .get_counter(MetricName::PeerRpcServerRx, labels.clone())
                .inc();
        }

        let mut resp_msg = RpcResponse::default();
        let now = Instant::now();

        let compression_info = packet.compression_info;
        let resp_bytes = Self::handle_rpc_request(
            packet,
            reg,
            tunnel_info,
            authenticated_peer_id,
            authenticated_peer_identity_type,
            authenticated_peer_secure_auth_level,
        )
        .await;

        // The request packet and decoded request are no longer retained after the
        // handler returns. Release their execution charge before admitting the
        // response so sequential request/response memory is not counted as if it
        // were permanently concurrent.
        if let Some(permit) = execution_permit.as_mut() {
            permit.release_all();
        }

        match &resp_bytes {
            Ok(r) => {
                resp_msg.response = r.clone().into();

                // Record successful RPC server TX and duration stats
                if let Some(ref stats_manager) = stats_manager {
                    let labels = labels
                        .clone()
                        .with_label_type(LabelType::Status("success".to_string()));

                    stats_manager
                        .get_counter(MetricName::PeerRpcServerTx, labels.clone())
                        .inc();

                    let duration_ms = now.elapsed().as_millis() as u64;
                    stats_manager
                        .get_counter(MetricName::PeerRpcDuration, labels)
                        .add(duration_ms);
                }
            }
            Err(err) => {
                resp_msg.error = Some(err.into());

                // Record RPC server error stats
                if let Some(ref stats_manager) = stats_manager {
                    let labels = labels
                        .clone()
                        .with_label_type(LabelType::Status("error".to_string()));

                    stats_manager
                        .get_counter(MetricName::PeerRpcErrors, labels.clone())
                        .inc();

                    let duration_ms = now.elapsed().as_millis() as u64;
                    stats_manager
                        .get_counter(MetricName::PeerRpcDuration, labels)
                        .add(duration_ms);
                }
            }
        };
        resp_msg.runtime_us = now.elapsed().as_micros() as u64;

        let response_too_large = resp_msg.response.len() > MAX_RPC_BODY_BYTES
            || execution_permit
                .as_mut()
                .is_some_and(|permit| !permit.reserve_extra(resp_msg.response.len()));
        if response_too_large {
            tracing::warn!(
                from_peer,
                transaction_id,
                response_bytes = resp_msg.response.len(),
                "Dropping RPC response above the protocol limit"
            );
            resp_msg.response.clear();
            resp_msg.error =
                Some((&Error::MalformatRpcPacket("RPC response is too large".to_string())).into());
        }

        let (compressed_resp, algo) = compress_packet(
            compression_info.unwrap_or_default().accepted_algo(),
            &resp_msg.encode_to_vec(),
        )
        .await
        .unwrap();

        let packets = build_rpc_packet(BuildRpcPacketArgs {
            from_peer: to_peer,
            to_peer: from_peer,
            rpc_desc: desc,
            transaction_id,
            is_req: false,
            content: &compressed_resp,
            trace_id,
            compression_info: RpcCompressionInfo {
                algo: algo.into(),
                accepted_algo: supported_rpc_compression().into(),
            },
        });
        for packet in packets {
            if let Err(err) = sender.send(packet).await {
                tracing::error!(?err, "Failed to send response packet");
            }
        }
    }

    pub fn inflight_count(&self) -> usize {
        self.packet_mergers.len()
    }

    pub fn close(&self) {
        self.transport.lock().unwrap().close();
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::{
        common::{CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket},
        peer_rpc::{PeerIdentityType, SecureAuthLevel},
        rpc_impl::packet::{BuildRpcPacketArgs, build_rpc_packet},
        rpc_impl::service_registry::ServiceRegistry,
        rpc_types::error::Error,
    };

    use super::{
        ExecutionBudgetPermit, MAX_RPC_MERGER_BYTES, MAX_RPC_MERGER_BYTES_PER_PEER,
        MAX_RPC_MERGER_BYTES_PER_SESSION, MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION,
        MAX_RPC_TASKS_PER_SESSION, MergerBudget, MergerSessionKey, PacketMergerKey, Server,
        foreign_relay_rpc_allowed, rpc_authentication_tuple_valid, rpc_budget_session,
        rpc_source_matches_authenticated_peer,
    };

    fn descriptor(proto_name: &str, service_name: &str) -> RpcDescriptor {
        RpcDescriptor {
            domain_name: "foreign-test".to_owned(),
            proto_name: proto_name.to_owned(),
            service_name: service_name.to_owned(),
            method_index: 1,
        }
    }

    #[test]
    fn foreign_relay_rpc_auth_tuple_accepts_scoped_encrypted_session_only() {
        let session_id = uuid::Uuid::new_v4();
        assert!(rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::ForeignRelay),
            Some(SecureAuthLevel::EncryptedUnauthenticated),
            Some(session_id),
        ));
        assert!(rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::ForeignRelay),
            Some(SecureAuthLevel::PeerVerified),
            Some(session_id),
        ));
        assert!(rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::SharedNode),
            Some(SecureAuthLevel::EncryptedUnauthenticated),
            Some(session_id),
        ));
        assert!(rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::SharedNode),
            Some(SecureAuthLevel::PeerVerified),
            Some(session_id),
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::ForeignRelay),
            Some(SecureAuthLevel::NetworkSecretConfirmed),
            Some(session_id),
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::SharedNode),
            Some(SecureAuthLevel::NetworkSecretConfirmed),
            Some(session_id),
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::Admin),
            Some(SecureAuthLevel::EncryptedUnauthenticated),
            Some(session_id),
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(42),
            Some(PeerIdentityType::ForeignRelay),
            Some(SecureAuthLevel::EncryptedUnauthenticated),
            None,
        ));
    }

    #[test]
    fn foreign_relay_rpc_policy_allows_route_and_direct_services() {
        assert!(foreign_relay_rpc_allowed(&descriptor(
            "OspfRouteRpc",
            "OspfRouteRpc"
        )));
        assert!(foreign_relay_rpc_allowed(&descriptor(
            "DirectConnectorRpc",
            "DirectConnectorRpc"
        )));
    }

    #[test]
    fn foreign_relay_rpc_policy_denies_administrative_services() {
        assert!(!foreign_relay_rpc_allowed(&descriptor(
            "ConfigRpc",
            "ConfigRpc"
        )));
        assert!(!foreign_relay_rpc_allowed(&descriptor(
            "CredentialManageRpc",
            "CredentialManageRpc"
        )));
    }

    #[tokio::test]
    async fn foreign_relay_rpc_is_rejected_before_body_decode() {
        let packet = RpcPacket {
            descriptor: Some(descriptor("ConfigRpc", "ConfigRpc")),
            // This body is not a valid compressed or protobuf request.
            body: vec![0xff, 0x00, 0x7f],
            ..Default::default()
        };

        let result = Server::handle_rpc_request(
            packet,
            std::sync::Arc::new(ServiceRegistry::new()),
            None,
            Some(42),
            Some(PeerIdentityType::ForeignRelay),
            None,
        )
        .await;

        assert!(matches!(result, Err(Error::ExecutionError(_))));
        let Err(Error::ExecutionError(error)) = result else {
            unreachable!();
        };
        assert_eq!(
            error.to_string(),
            "foreign relay RPC service is not permitted"
        );
    }

    #[tokio::test]
    async fn foreign_relay_allowed_services_reach_request_decode() {
        for (proto_name, service_name) in [
            ("OspfRouteRpc", "OspfRouteRpc"),
            ("DirectConnectorRpc", "DirectConnectorRpc"),
        ] {
            let packet = RpcPacket {
                descriptor: Some(descriptor(proto_name, service_name)),
                body: vec![0xff, 0x00, 0x7f],
                ..Default::default()
            };

            let result = Server::handle_rpc_request(
                packet,
                std::sync::Arc::new(ServiceRegistry::new()),
                None,
                Some(42),
                Some(PeerIdentityType::ForeignRelay),
                None,
            )
            .await;

            assert!(matches!(result, Err(Error::DecodeError)));
        }
    }

    #[tokio::test]
    async fn denied_foreign_relay_fragments_do_not_enter_merger() {
        let server = Server::new();
        server.run();

        let content = vec![0x5a; 4096];
        let packets = build_rpc_packet(BuildRpcPacketArgs {
            from_peer: 42,
            to_peer: 1,
            rpc_desc: descriptor("ConfigRpc", "ConfigRpc"),
            transaction_id: 33,
            is_req: true,
            content: &content,
            trace_id: 0,
            compression_info: RpcCompressionInfo {
                algo: CompressionAlgoPb::None.into(),
                accepted_algo: CompressionAlgoPb::None.into(),
            },
        });
        assert!(packets.len() > 1);

        let sender = server.get_transport_sink();
        for mut packet in packets {
            assert!(packet.set_authenticated_peer_id(42));
            assert!(packet.set_authenticated_peer_identity_type(PeerIdentityType::ForeignRelay));
            sender.send(packet).await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(server.inflight_count(), 0);
    }

    #[test]
    fn rpc_fragment_keys_separate_authenticated_sessions() {
        let first_session = uuid::Uuid::new_v4();
        let second_session = uuid::Uuid::new_v4();
        let first = PacketMergerKey {
            authenticated_peer_id: Some(7),
            authenticated_peer_identity_type: None,
            authenticated_peer_secure_auth_level: None,
            authenticated_session_id: Some(first_session),
            from_peer_id: 7,
            transaction_id: 9,
        };
        let second = PacketMergerKey {
            authenticated_session_id: Some(second_session),
            ..first.clone()
        };

        assert_ne!(first, second);
    }

    #[test]
    fn rpc_source_must_match_authenticated_peer() {
        assert!(rpc_source_matches_authenticated_peer(
            None,
            7,
            7,
            Some(7),
            Some(7)
        ));
        assert!(!rpc_source_matches_authenticated_peer(
            None,
            7,
            8,
            Some(7),
            Some(8)
        ));
        assert!(rpc_source_matches_authenticated_peer(
            Some(7),
            7,
            8,
            Some(9),
            Some(8)
        ));
        assert!(!rpc_source_matches_authenticated_peer(
            Some(7),
            8,
            9,
            Some(8),
            Some(9)
        ));
    }

    #[test]
    fn remote_rpc_requires_complete_verified_authentication() {
        let session = uuid::Uuid::new_v4();
        assert!(rpc_authentication_tuple_valid(
            Some(7),
            Some(PeerIdentityType::Admin),
            Some(SecureAuthLevel::PeerVerified),
            Some(session)
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(7),
            Some(PeerIdentityType::Admin),
            Some(SecureAuthLevel::EncryptedUnauthenticated),
            Some(session)
        ));
        assert!(!rpc_authentication_tuple_valid(
            Some(7),
            Some(PeerIdentityType::Admin),
            None,
            Some(session)
        ));
        assert!(rpc_authentication_tuple_valid(None, None, None, None));
    }

    #[test]
    fn local_rpc_uses_the_same_bounded_execution_accounting() {
        let local = rpc_budget_session(None, None).unwrap();
        assert_eq!(local.peer_id, 0);
        assert_eq!(local.session_id, uuid::Uuid::nil());
        assert!(rpc_budget_session(Some(7), None).is_none());
        assert!(rpc_budget_session(None, Some(uuid::Uuid::new_v4())).is_none());
    }

    #[test]
    fn merger_budget_isolated_by_authenticated_session_and_releases() {
        let first_session = MergerSessionKey {
            peer_id: 7,
            session_id: uuid::Uuid::new_v4(),
        };
        let second_session = MergerSessionKey {
            peer_id: 7,
            session_id: uuid::Uuid::new_v4(),
        };
        let mut budget = MergerBudget::default();

        for index in 0..MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION {
            assert!(
                budget.reserve(&first_session, true, 1),
                "transaction {index}"
            );
        }
        assert!(!budget.reserve(&first_session, true, 1));
        assert!(budget.reserve(&second_session, true, 1));

        budget.release(&first_session, true, 1);
        assert!(budget.reserve(&first_session, true, 1));
        for _ in 0..MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION {
            budget.release(&first_session, true, 1);
        }
        budget.release(&second_session, true, 1);
        assert_eq!(budget.transactions, 0);
    }

    #[test]
    fn merger_budget_limits_all_sessions_for_one_peer() {
        let mut budget = MergerBudget::default();
        let sessions = (0..5)
            .map(|_| MergerSessionKey {
                peer_id: 7,
                session_id: uuid::Uuid::new_v4(),
            })
            .collect::<Vec<_>>();

        for session in sessions.iter().take(4) {
            for _ in 0..MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION {
                assert!(budget.reserve(session, true, 1));
            }
        }
        assert!(!budget.reserve(&sessions[4], true, 1));

        for session in sessions.iter().take(4) {
            for _ in 0..MAX_RPC_MERGER_TRANSACTIONS_PER_SESSION {
                budget.release(session, true, 1);
            }
        }
        assert_eq!(budget.transactions, 0);
        assert_eq!(budget.bytes, 0);
        assert!(budget.sessions.is_empty());
        assert!(budget.peers.is_empty());
    }

    #[test]
    fn merger_budget_releases_failed_transaction_bytes() {
        let session = MergerSessionKey {
            peer_id: 9,
            session_id: uuid::Uuid::new_v4(),
        };
        let mut budget = MergerBudget::default();

        assert!(budget.reserve(&session, true, 4096));
        budget.release(&session, true, 4096);

        assert_eq!(budget.transactions, 0);
        assert_eq!(budget.bytes, 0);
        assert!(budget.sessions.is_empty());
        assert!(budget.reserve(&session, true, 4096));
    }

    #[test]
    fn concurrent_merger_feed_and_cleanup_budget_stays_balanced() {
        let budget = std::sync::Arc::new(std::sync::Mutex::new(MergerBudget::default()));
        let session = MergerSessionKey {
            peer_id: 9,
            session_id: uuid::Uuid::new_v4(),
        };
        let mut workers = Vec::new();
        for _ in 0..8 {
            let budget = budget.clone();
            let session = session.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    let reserved = {
                        let mut budget = budget.lock().unwrap();
                        budget.reserve(&session, true, 256)
                    };
                    if reserved {
                        let mut budget = budget.lock().unwrap();
                        budget.release(&session, true, 256);
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let budget = budget.lock().unwrap();
        assert_eq!(budget.transactions, 0);
        assert_eq!(budget.bytes, 0);
        assert!(budget.sessions.is_empty());
    }

    #[tokio::test]
    async fn fragmented_then_unfragmented_collision_preserves_budget_and_allows_next_transaction() {
        let server = Server::new();
        server.run();
        let sender = server.get_transport_sink();
        let session = MergerSessionKey {
            peer_id: 9,
            session_id: uuid::Uuid::new_v4(),
        };

        for transaction_id in 1..=4 {
            let mut fragmented = build_rpc_packet(BuildRpcPacketArgs {
                from_peer: session.peer_id,
                to_peer: 1,
                rpc_desc: descriptor("TestRpc", "TestRpc"),
                transaction_id,
                is_req: true,
                content: &[0x5a; 4096],
                trace_id: 0,
                compression_info: RpcCompressionInfo {
                    algo: CompressionAlgoPb::None.into(),
                    accepted_algo: CompressionAlgoPb::None.into(),
                },
            });
            assert!(fragmented.len() > 1);
            let mut first = fragmented.remove(0);
            assert!(first.set_authenticated_peer_id(session.peer_id));
            assert!(first.set_authenticated_session_id(session.session_id));
            sender.send(first).await.unwrap();
            for _ in 0..100 {
                if server.inflight_count() == 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            assert_eq!(server.inflight_count(), 1);

            let mut collision = build_rpc_packet(BuildRpcPacketArgs {
                from_peer: session.peer_id,
                to_peer: 1,
                rpc_desc: descriptor("TestRpc", "TestRpc"),
                transaction_id,
                is_req: true,
                content: &[0x2a; 16],
                trace_id: 0,
                compression_info: RpcCompressionInfo {
                    algo: CompressionAlgoPb::None.into(),
                    accepted_algo: CompressionAlgoPb::None.into(),
                },
            });
            assert_eq!(collision.len(), 1);
            let mut collision = collision.remove(0);
            assert!(collision.set_authenticated_peer_id(session.peer_id));
            assert!(collision.set_authenticated_session_id(session.session_id));
            sender.send(collision).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            assert_eq!(server.inflight_count(), 1);
            assert_eq!(server.merger_budget.lock().unwrap().transactions, 1);

            for mut piece in fragmented {
                assert!(piece.set_authenticated_peer_id(session.peer_id));
                assert!(piece.set_authenticated_session_id(session.session_id));
                sender.send(piece).await.unwrap();
            }
            for _ in 0..100 {
                let budget = server.merger_budget.lock().unwrap();
                if server.inflight_count() == 0 && budget.transactions == 0 && budget.bytes == 0 {
                    break;
                }
                drop(budget);
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            let budget = server.merger_budget.lock().unwrap();
            assert_eq!(server.inflight_count(), 0);
            assert_eq!(budget.transactions, 0);
            assert_eq!(budget.bytes, 0);
            assert!(budget.sessions.is_empty());
        }

        let budget = server.merger_budget.lock().unwrap();
        assert_eq!(budget.transactions, 0);
        assert_eq!(budget.bytes, 0);
    }

    #[test]
    fn execution_budget_bounds_compressed_and_uncompressed_requests() {
        let session = MergerSessionKey {
            peer_id: 11,
            session_id: uuid::Uuid::new_v4(),
        };
        let mut budget = MergerBudget::default();
        assert!(budget.reserve_execution(&session, MAX_RPC_MERGER_BYTES_PER_SESSION));
        assert!(!budget.reserve_execution(&session, 1));
        budget.release_execution(&session, MAX_RPC_MERGER_BYTES_PER_SESSION);

        let second_session = MergerSessionKey {
            peer_id: 12,
            session_id: uuid::Uuid::new_v4(),
        };
        assert!(budget.reserve_execution(&session, MAX_RPC_MERGER_BYTES_PER_PEER));
        assert!(budget.reserve_execution(
            &second_session,
            MAX_RPC_MERGER_BYTES - MAX_RPC_MERGER_BYTES_PER_PEER
        ));
        assert!(!budget.reserve_execution(&session, 1));
        budget.release_execution(&session, MAX_RPC_MERGER_BYTES_PER_PEER);
        budget.release_execution(
            &second_session,
            MAX_RPC_MERGER_BYTES - MAX_RPC_MERGER_BYTES_PER_PEER,
        );
        assert_eq!(budget.bytes, 0);
        assert!(budget.sessions.is_empty());
    }

    #[test]
    fn execution_budget_permit_transitions_from_request_to_response_bytes() {
        let session = MergerSessionKey {
            peer_id: 13,
            session_id: uuid::Uuid::new_v4(),
        };
        let budget = std::sync::Arc::new(std::sync::Mutex::new(MergerBudget::default()));
        assert!(budget.lock().unwrap().reserve_execution(&session, 1024));
        let mut permit =
            ExecutionBudgetPermit::new(Some(budget.clone()), Some(session.clone()), 1024);
        assert!(permit.reserve_extra(2048));
        assert_eq!(budget.lock().unwrap().bytes, 3072);

        permit.release_all();
        assert_eq!(budget.lock().unwrap().bytes, 0);
        assert!(permit.reserve_extra(2048));
        assert_eq!(budget.lock().unwrap().bytes, 2048);

        drop(permit);
        assert_eq!(budget.lock().unwrap().bytes, 0);
        assert!(budget.lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn session_semaphore_cleanup_keeps_active_permit_clone() {
        let session = MergerSessionKey {
            peer_id: 12,
            session_id: uuid::Uuid::new_v4(),
        };
        let semaphores = super::DashMap::new();
        semaphores.insert(
            session.clone(),
            std::sync::Arc::new(super::Semaphore::new(MAX_RPC_TASKS_PER_SESSION)),
        );

        let cloned = semaphores.get(&session).unwrap().clone();
        let permit = cloned.clone().try_acquire_owned().unwrap();
        semaphores.retain(|_, semaphore| {
            semaphore.available_permits() < MAX_RPC_TASKS_PER_SESSION
                || std::sync::Arc::strong_count(semaphore) > 1
        });
        assert!(semaphores.contains_key(&session));

        drop(permit);
        drop(cloned);
        semaphores.retain(|_, semaphore| {
            semaphore.available_permits() < MAX_RPC_TASKS_PER_SESSION
                || std::sync::Arc::strong_count(semaphore) > 1
        });
        assert!(!semaphores.contains_key(&session));
    }
}
