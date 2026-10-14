use arc_swap::ArcSwap;
use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use parking_lot::{Mutex as SyncMutex, RwLock as SyncRwLock};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use quanta::Instant;
use smallvec::SmallVec;
use std::collections::{BTreeSet, HashMap};
use std::{
    fmt::Debug,
    future::Future,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
};

use crate::{
    common::{
        PeerId,
        constants::LOWTIER_VERSION,
        dataplane_telemetry::{DataplaneQueueClass, DataplaneStage, DataplaneTelemetry},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        shrink_dashmap,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
    },
    peers::{
        PeerPacketFilter,
        fabric::{FabricBatch, FabricPacket, FabricPayloadKind},
        flow::{
            is_critical_l2_control, partition_packet_batch_by_flow, stamp_critical_control,
            stamp_critical_l2_control, stamp_packet_flow,
        },
        l2_fabric::{EthernetDestination, L2DestinationBatch, L2Fabric, L2IngressBatch},
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        peer_session::PeerSessionStore,
        recv_packet_batch_from_chan,
        route_trait::{ForeignNetworkRouteInfoMap, MockRoute, NextHopPolicy, RouteInterface},
        service_route::{RouteSource, ServiceRoute, ServiceRouteAction, ServiceRouteStore},
        speed_probe::{ProbeBudget, split_cycle_budget},
        traffic_metrics::{
            InstanceLabelKind, LogicalTrafficMetrics, TrafficKind, TrafficMetricRecorder,
            is_relay_data_packet_type, route_peer_info_instance_id, traffic_kind,
        },
    },
    proto::{
        api::instance::{
            self, ListGlobalForeignNetworkResponse,
            list_global_foreign_network_response::OneForeignNetwork,
        },
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdentityType,
            RouteForeignNetworkSummary, SecureAuthLevel,
        },
    },
    tunnel::{
        PacketBatchSink, Tunnel, TunnelConnector, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::{PEER_MANAGER_HEADER_SIZE, PacketType, ZCPacket},
    },
};

fn tunnel_url_ip(url: &crate::proto::common::Url) -> Option<IpAddr> {
    url::Url::try_from(url)
        .ok()?
        .host_str()?
        .parse::<IpAddr>()
        .ok()
}

fn check_tunnel_info_underlay(
    info: &crate::proto::common::TunnelInfo,
    policy: &crate::common::underlay_policy::UnderlayPolicy,
) -> Result<(), anyhow::Error> {
    if info.tunnel_type == "ring" {
        return Ok(());
    }

    if let Some(remote) = info.remote_addr.as_ref().and_then(tunnel_url_ip)
        && let Some(rule) = policy.denied_ip_rule(remote)
    {
        anyhow::bail!("remote underlay address {remote} matches denied CIDR {rule}");
    }
    if let Some(local) = info.local_addr.as_ref().and_then(tunnel_url_ip)
        && let Some(rule) = policy.denied_ip_rule(local)
    {
        anyhow::bail!("local underlay address {local} matches denied CIDR {rule}");
    }
    Ok(())
}

pub(crate) fn packet_supports_speed_first(packet: &ZCPacket) -> bool {
    let Some(header) = packet.peer_manager_header() else {
        return false;
    };
    if header.is_critical_l2_control()
        || (header.packet_type == PacketType::Ethernet as u8
            && is_critical_l2_control(packet.payload()))
    {
        return false;
    }
    matches!(
        header.packet_type,
        packet_type
            if packet_type == PacketType::Data as u8
                || packet_type == PacketType::ForeignNetworkPacket as u8
                || packet_type == PacketType::OverlayStream as u8
                || packet_type == PacketType::Ethernet as u8
    )
}

fn apply_local_route_policy(packet: &mut ZCPacket, speed_first: bool, latency_first: bool) {
    // Authenticate routing-control classification before choosing a path. The
    // later preparation pass observes the marker and avoids reparsing.
    stamp_critical_control(packet);
    let use_speed = speed_first && packet_supports_speed_first(packet);
    let header = packet.mut_peer_manager_header().unwrap();
    header.set_speed_first(use_speed);
    if !use_speed {
        header.set_latency_first(latency_first || speed_first);
    }
}

fn suppress_local_tun_delivery(header: &mut crate::tunnel::packet_def::PeerManagerHeader) {
    header.set_not_send_to_tun(true);
    header.set_no_proxy(true);
}

fn ordered_probe_indexes(candidates: &[(PeerId, PeerConnId, bool)], rotation: usize) -> Vec<usize> {
    let mut indexes = (0..candidates.len()).collect::<Vec<_>>();
    indexes.sort_by_key(|index| {
        let (peer_id, conn_id, recent) = candidates[*index];
        (!recent, peer_id, conn_id)
    });
    let recent_count = indexes
        .iter()
        .take_while(|index| candidates[**index].2)
        .count();
    if recent_count > 1 {
        indexes[..recent_count].rotate_left(rotation % recent_count);
    }
    let idle_count = indexes.len().saturating_sub(recent_count);
    if idle_count > 1 {
        indexes[recent_count..].rotate_left(rotation % idle_count);
    }
    indexes
}

use super::{
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChan, PacketRecvChanReceiver,
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{ForeignNetworkManager, GlobalForeignNetworkAccessor},
    peer_conn::PeerConnId,
    peer_map::{OriginAuthCapability, OriginAuthSource, PeerMap, PeerMapDataPlaneDescriptor},
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    peer_task::ExternalTaskSignal,
    relay_peer_map::{FullEthernetAuthorizationToken, RelayBatchDecryptOutcome, RelayPeerMap},
    route_trait::{
        ArcRoute, ForwardingDecisionSnapshotHandle, ForwardingDecisionSnapshotSource,
        ForwardingPeerInfo, ForwardingPeerTable, ForwardingSnapshotSourceToken,
        OriginAuthPublication, Route,
    },
};

const RPC_INGRESS_PACKET_CAPACITY: usize = 128;
const RPC_REMOTE_INGRESS_CAPACITY: usize = 96;
const RPC_INGRESS_CAPACITY_PER_PEER: usize = 16;

#[derive(Default)]
struct RpcPeerIngressCounts {
    peers: HashMap<PeerId, usize>,
}

struct RpcIngressAdmission {
    remote: Arc<Semaphore>,
    peers: std::sync::Mutex<RpcPeerIngressCounts>,
}

impl RpcIngressAdmission {
    fn try_admit(self: &Arc<Self>, peer_id: PeerId) -> Option<RpcIngressPermits> {
        let remote = self.remote.clone().try_acquire_owned().ok()?;
        let mut counts = self.peers.lock().unwrap();
        let count = counts.peers.entry(peer_id).or_default();
        if *count >= RPC_INGRESS_CAPACITY_PER_PEER {
            return None;
        }
        *count += 1;
        Some(RpcIngressPermits {
            peer_id,
            admission: self.clone(),
            _remote: remote,
        })
    }

    fn release_peer(&self, peer_id: PeerId) {
        let mut counts = self.peers.lock().unwrap();
        let remove = if let Some(count) = counts.peers.get_mut(&peer_id) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            counts.peers.remove(&peer_id);
        }
    }
}

struct RpcIngressPermits {
    peer_id: PeerId,
    admission: Arc<RpcIngressAdmission>,
    _remote: OwnedSemaphorePermit,
}

impl Drop for RpcIngressPermits {
    fn drop(&mut self) {
        self.admission.release_peer(self.peer_id);
    }
}

struct RpcIngressEnvelope {
    packet: ZCPacket,
    _permits: Option<RpcIngressPermits>,
}

#[derive(Clone)]
struct RpcIngressSender {
    sender: Sender<RpcIngressEnvelope>,
    admission: Arc<RpcIngressAdmission>,
}

impl RpcIngressSender {
    fn try_send(
        &self,
        packet: ZCPacket,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<ZCPacket>> {
        let permits = if let Some(peer_id) = packet.logical_authenticated_peer_id() {
            let Some(permits) = self.admission.try_admit(peer_id) else {
                return Err(tokio::sync::mpsc::error::TrySendError::Full(packet));
            };
            Some(permits)
        } else {
            None
        };
        let envelope = RpcIngressEnvelope {
            packet,
            _permits: permits,
        };
        self.sender.try_send(envelope).map_err(|error| match error {
            tokio::sync::mpsc::error::TrySendError::Full(envelope) => {
                tokio::sync::mpsc::error::TrySendError::Full(envelope.packet)
            }
            tokio::sync::mpsc::error::TrySendError::Closed(envelope) => {
                tokio::sync::mpsc::error::TrySendError::Closed(envelope.packet)
            }
        })
    }
}

fn create_rpc_ingress_channel() -> (RpcIngressSender, Receiver<RpcIngressEnvelope>) {
    let (sender, receiver) = mpsc::channel(RPC_INGRESS_PACKET_CAPACITY);
    (
        RpcIngressSender {
            sender,
            admission: Arc::new(RpcIngressAdmission {
                remote: Arc::new(Semaphore::new(RPC_REMOTE_INGRESS_CAPACITY)),
                peers: std::sync::Mutex::new(RpcPeerIngressCounts::default()),
            }),
        },
        receiver,
    )
}

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<Receiver<RpcIngressEnvelope>>,
    peer_rpc_tspt_sender: RpcIngressSender,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let foreign_peers = self
            .foreign_peers
            .lock()
            .await
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(foreign_peers) = foreign_peers
            && foreign_peers.has_next_hop(dst_peer_id)
        {
            return foreign_peers.send_msg(msg, dst_peer_id).await;
        }

        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;
        // Local and routed peers still use the normal peer receive/forwarding path.
        peers.send_msg_directly(msg, self.my_peer_id).await
    }

    async fn recv(&self) -> Result<ZCPacket, Error> {
        if let Some(envelope) = self.packet_recv.lock().await.recv().await {
            Ok(envelope.packet)
        } else {
            Err(Error::Unknown)
        }
    }
}

pub enum RouteAlgoType {
    Ospf,
    None,
}

enum RouteAlgoInst {
    Ospf(Arc<PeerRoute>),
    None,
}

impl Clone for RouteAlgoInst {
    fn clone(&self) -> Self {
        match self {
            RouteAlgoInst::Ospf(route) => RouteAlgoInst::Ospf(route.clone()),
            RouteAlgoInst::None => RouteAlgoInst::None,
        }
    }
}

struct SelfTxCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
    compact_l3_packets: CounterHandle,
    compact_l3_bytes: CounterHandle,
    full_ethernet_packets: CounterHandle,
    full_ethernet_bytes: CounterHandle,
}

struct EthernetBatchInput {
    packet: ZCPacket,
    destination_peer_id: Option<PeerId>,
    is_exit_node: bool,
    suppress_local_delivery: bool,
}

type EthernetBatchInputs = SmallVec<[EthernetBatchInput; 4]>;

struct TapBatchMeta {
    ethernet_header: [u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN],
}

type TapBatchMetadata = SmallVec<[Option<TapBatchMeta>; MAX_PACKET_BATCH_SIZE]>;

struct OrderedPeerBatch {
    peer_id: PeerId,
    next_hop: Option<PeerId>,
    packets: PacketBatch,
    mark_recent: bool,
}

struct OrderedPeerBatches {
    batches: SmallVec<[OrderedPeerBatch; 2]>,
    indexes: HashMap<(PeerId, Option<PeerId>), usize>,
}

const MAX_ORDERED_SEND_CONCURRENCY: usize = 64;

struct OrderedSendCompletion {
    result: Result<(), Error>,
    peer_id: PeerId,
    packet_type: u8,
    hybrid_ip_ethernet: bool,
    bytes: u64,
    packets: u64,
    record_metrics: bool,
}

struct HybridRecipientSets {
    compact_peers: Vec<PeerId>,
    full_peers: Vec<PeerId>,
    is_exit_node: bool,
    is_multicast: bool,
    is_broadcast: bool,
    bridge_fallback: bool,
}

fn direct_batch_group_key(
    transport_peer: PeerId,
    conn_id: PeerConnId,
    header: &crate::tunnel::packet_def::PeerManagerHeader,
) -> (PeerId, PeerConnId, u8, u8, u8) {
    let policy_bits = u8::from(header.is_speed_first())
        | (u8::from(header.is_latency_first()) << 1)
        | (u8::from(header.is_critical_l2_control()) << 2);
    (
        transport_peer,
        conn_id,
        header.packet_type,
        policy_bits,
        header.flags,
    )
}

fn lazy_batch_group_index<K>(
    key: K,
    next_index: usize,
    inline: &mut SmallVec<[(K, usize); 4]>,
    spill: &mut Option<HashMap<K, usize>>,
) -> Option<usize>
where
    K: Copy + Eq + Hash,
{
    if let Some(indexes) = spill.as_mut() {
        if let Some(index) = indexes.get(&key).copied() {
            return Some(index);
        }
        indexes.insert(key, next_index);
        return None;
    }
    if let Some((_, index)) = inline.iter().find(|(group_key, _)| *group_key == key) {
        return Some(*index);
    }
    if inline.len() < 4 {
        inline.push((key, next_index));
        return None;
    }
    let mut indexes = HashMap::with_capacity(inline.len() + 1);
    indexes.extend(inline.drain(..));
    indexes.insert(key, next_index);
    *spill = Some(indexes);
    None
}

fn direct_selected_conn_allowed(
    final_peer: PeerId,
    next_hop: Option<PeerId>,
    latency_first: bool,
) -> bool {
    !next_hop.is_some_and(|hop| hop != final_peer) && !(next_hop.is_none() && latency_first)
}

impl OrderedPeerBatches {
    fn new() -> Self {
        Self {
            batches: SmallVec::new(),
            indexes: HashMap::new(),
        }
    }

    fn push_packet_with_next_hop(
        &mut self,
        peer_id: PeerId,
        packet: ZCPacket,
        mark_recent: bool,
        next_hop: Option<PeerId>,
    ) {
        let key = (peer_id, next_hop);
        if let Some(last) = self.batches.last_mut()
            && (last.peer_id, last.next_hop) == key
        {
            last.mark_recent |= mark_recent;
            last.packets
                .try_push(packet)
                .expect("a per-peer group cannot exceed its bounded ingress batch");
            return;
        }
        if self.indexes.is_empty() && !self.batches.is_empty() {
            for (index, batch) in self.batches.iter().enumerate() {
                self.indexes.insert((batch.peer_id, batch.next_hop), index);
            }
        }
        if let Some(index) = self.indexes.get(&key).copied() {
            let peer_batch = &mut self.batches[index];
            peer_batch.mark_recent |= mark_recent;
            peer_batch
                .packets
                .try_push(packet)
                .expect("a per-peer group cannot exceed its bounded ingress batch");
            return;
        }

        let mut packets = PacketBatch::new();
        packets
            .try_push(packet)
            .expect("a new per-peer group accepts its first packet");
        if !self.indexes.is_empty() {
            self.indexes.insert(key, self.batches.len());
        }
        self.batches.push(OrderedPeerBatch {
            peer_id,
            next_hop,
            packets,
            mark_recent,
        });
    }
}

impl IntoIterator for OrderedPeerBatches {
    type Item = OrderedPeerBatch;
    type IntoIter = smallvec::IntoIter<[OrderedPeerBatch; 2]>;

    fn into_iter(self) -> Self::IntoIter {
        self.batches.into_iter()
    }
}

type HybridRoutePeers = SmallVec<[PeerId; 2]>;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct HybridBatchRouteKey {
    address: IpAddr,
    flow: u64,
}

#[derive(Clone)]
struct HybridBatchRoute {
    peers: HybridRoutePeers,
    is_exit_node: bool,
    blackholed: bool,
}

fn is_peer_rpc_packet_type(packet_type: u8) -> bool {
    packet_type == PacketType::TaRpc as u8
        || packet_type == PacketType::RpcReq as u8
        || packet_type == PacketType::RpcResp as u8
}

fn is_foreign_network_packet_type(packet_type: u8) -> bool {
    packet_type == PacketType::ForeignNetworkPacket as u8
}

fn decoded_local_nic_batch_source(batch: &PacketBatch, my_peer_id: PeerId) -> Option<(PeerId, u8)> {
    let first = batch.first()?;
    let (source, packet_type) = first
        .parsed_metadata()
        .map(|metadata| (metadata.from_peer_id, metadata.packet_type))
        .or_else(|| {
            first
                .peer_manager_header()
                .map(|header| (header.from_peer_id.get(), header.packet_type))
        })?;
    if packet_type != PacketType::Data as u8 && packet_type != PacketType::Ethernet as u8 {
        return None;
    }
    let expected_authenticated_peer = (source != my_peer_id).then_some(source);
    if first.authenticated_peer_id() != expected_authenticated_peer {
        return None;
    }
    batch
        .iter()
        .all(|packet| {
            if packet.authenticated_peer_id() != expected_authenticated_peer {
                return false;
            }
            if let Some(metadata) = packet.parsed_metadata() {
                return metadata.packet_type == packet_type
                    && metadata.from_peer_id == source
                    && metadata.to_peer_id == my_peer_id
                    && !metadata.encrypted
                    && !metadata.compressed
                    && (packet_type != PacketType::Ethernet as u8
                        || (metadata.ethernet_destination.is_some()
                            && metadata.ethernet_source.is_some()));
            }
            packet.peer_manager_header().is_some_and(|header| {
                header.packet_type == packet_type
                    && header.from_peer_id.get() == source
                    && header.to_peer_id.get() == my_peer_id
                    && !header.is_encrypted()
                    && !header.is_compressed()
                    && (packet_type != PacketType::Ethernet as u8 || packet.payload().len() >= 14)
            })
        })
        .then_some((source, packet_type))
}

fn prepare_direct_nic_batch<F>(
    batch: &PacketBatch,
    ethernet_input: bool,
    mut learn_ethernet_source: F,
) -> bool
where
    F: FnMut(&[u8], PeerId),
{
    // Tests and callers that only need structural validation pass peer id 0 and
    // skip the destination identity check by using a dedicated helper below.
    inspect_direct_nic_batch_structure(batch, ethernet_input, &mut learn_ethernet_source)
}

fn inspect_direct_nic_batch_structure<F>(
    batch: &PacketBatch,
    ethernet_input: bool,
    learn_ethernet_source: &mut F,
) -> bool
where
    F: FnMut(&[u8], PeerId),
{
    if batch.is_empty() {
        return false;
    }
    for packet in batch {
        if let Some(metadata) = packet.parsed_metadata() {
            let is_ethernet = metadata.packet_type == PacketType::Ethernet as u8;
            if (metadata.packet_type != PacketType::Data as u8 && !is_ethernet)
                || metadata.not_send_to_tun
                || (is_ethernet && !ethernet_input)
                || metadata.encrypted
                || metadata.compressed
            {
                return false;
            }
            if is_ethernet {
                learn_ethernet_source(packet.payload(), metadata.from_peer_id);
            }
            continue;
        }
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        let is_ethernet = header.packet_type == PacketType::Ethernet as u8;
        if (header.packet_type != PacketType::Data as u8 && !is_ethernet)
            || header.is_not_send_to_tun()
            || (is_ethernet && !ethernet_input)
            || header.is_encrypted()
            || header.is_compressed()
        {
            return false;
        }
        if is_ethernet {
            learn_ethernet_source(packet.payload(), header.from_peer_id.get());
        }
    }
    true
}

/// One pass validates a direct NIC batch, returns its source, and optionally
/// learns Ethernet sources. Callers no longer scan the same batch three times.
fn inspect_direct_nic_batch<F>(
    batch: &PacketBatch,
    my_peer_id: PeerId,
    ethernet_input: bool,
    learn_ethernet_source: &mut F,
) -> Option<(PeerId, u8)>
where
    F: FnMut(&[u8], PeerId),
{
    if batch.is_empty() {
        return None;
    }

    let first = batch.first()?;
    let (source, packet_type) = first
        .parsed_metadata()
        .map(|metadata| (metadata.from_peer_id, metadata.packet_type))
        .or_else(|| {
            first
                .peer_manager_header()
                .map(|header| (header.from_peer_id.get(), header.packet_type))
        })?;
    if packet_type != PacketType::Data as u8 && packet_type != PacketType::Ethernet as u8 {
        return None;
    }
    if first.authenticated_peer_id() != Some(source) {
        return None;
    }
    let is_ethernet = packet_type == PacketType::Ethernet as u8;
    if is_ethernet && !ethernet_input {
        return None;
    }

    for packet in batch {
        if packet.authenticated_peer_id() != Some(source) {
            return None;
        }
        if let Some(metadata) = packet.parsed_metadata() {
            if metadata.packet_type != packet_type
                || metadata.from_peer_id != source
                || metadata.to_peer_id != my_peer_id
                || metadata.not_send_to_tun
                || metadata.encrypted
                || metadata.compressed
                || (is_ethernet
                    && (metadata.ethernet_destination.is_none()
                        || metadata.ethernet_source.is_none()))
            {
                return None;
            }
            if is_ethernet {
                learn_ethernet_source(packet.payload(), metadata.from_peer_id);
            }
            continue;
        }
        let header = packet.peer_manager_header()?;
        if header.packet_type != packet_type
            || header.from_peer_id.get() != source
            || header.to_peer_id.get() != my_peer_id
            || header.is_not_send_to_tun()
            || header.is_encrypted()
            || header.is_compressed()
            || (is_ethernet && packet.payload().len() < 14)
        {
            return None;
        }
        if is_ethernet {
            learn_ethernet_source(packet.payload(), header.from_peer_id.get());
        }
    }

    Some((source, packet_type))
}

fn packet_batch_contains_peer_rpc(batch: &PacketBatch) -> bool {
    batch.iter().any(|packet| {
        packet
            .peer_manager_header()
            .is_some_and(|header| is_peer_rpc_packet_type(header.packet_type))
    })
}

struct PreparedPacketBatch {
    batch: PacketBatch,
    bytes_before: u64,
    bytes_after: u64,
    contains_ethernet: bool,
    first_packet_type: u8,
    first_is_hybrid_ip_ethernet: bool,
    uniform_direct_priority: bool,
}

fn prepare_packet_batch(mut batch: PacketBatch) -> Result<PreparedPacketBatch, Error> {
    let mut bytes_before = 0_u64;
    let mut contains_ethernet = false;
    let mut first_packet_type = 0;
    let mut first_is_hybrid_ip_ethernet = false;
    let mut first_is_data = None;
    let mut uniform_direct_priority = true;
    for packet in batch.iter_mut() {
        bytes_before = bytes_before.saturating_add(packet.buf_len() as u64);
        stamp_critical_l2_control(packet);
        stamp_packet_flow(packet);
        let header = packet
            .peer_manager_header()
            .expect("packet preparation requires a peer header");
        if first_is_data.is_none() {
            first_packet_type = header.packet_type;
            first_is_hybrid_ip_ethernet = header.is_hybrid_ip_ethernet();
        }
        contains_ethernet |= header.packet_type == PacketType::Ethernet as u8;
        let is_data = crate::tunnel::direct::is_data_packet(packet);
        uniform_direct_priority &= first_is_data.is_none_or(|first| first == is_data);
        first_is_data.get_or_insert(is_data);
    }

    Ok(PreparedPacketBatch {
        batch,
        bytes_before,
        bytes_after: bytes_before,
        contains_ethernet,
        first_packet_type,
        first_is_hybrid_ip_ethernet,
        uniform_direct_priority,
    })
}

const DIRECT_NIC_QUEUE_BATCH_CAPACITY: usize = 3;
pub(crate) const DIRECT_NIC_QUEUE_PACKET_CAPACITY: usize =
    MAX_PACKET_BATCH_SIZE * DIRECT_NIC_QUEUE_BATCH_CAPACITY;
const DIRECT_NIC_QUEUE_SLOT_BYTES: usize = 4 * 1024;
const DIRECT_NIC_QUEUE_CREDIT_BYTES: usize =
    DIRECT_NIC_QUEUE_PACKET_CAPACITY * DIRECT_NIC_QUEUE_SLOT_BYTES;
// Preserve the previous data-lane per-batch retained-memory ceiling while
// sharing the aggregate control/data budget in one ordered queue.
const DIRECT_NIC_BATCH_CREDIT_BYTES: usize =
    MAX_PACKET_BATCH_SIZE * 2 * DIRECT_NIC_QUEUE_SLOT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectNicBatchPlan {
    byte_count: u64,
    packet_count: u64,
    queue_credits: u32,
}

struct DirectNicDelivery {
    batch: PacketBatch,
    plan: DirectNicBatchPlan,
    byte_count: u64,
    packet_count: u64,
}

struct DirectNicQueueState {
    packets: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicUsize,
    telemetry: Arc<DataplaneTelemetry>,
}

impl DirectNicQueueState {
    fn new(telemetry: Arc<DataplaneTelemetry>) -> Self {
        Self {
            packets: std::sync::atomic::AtomicUsize::new(0),
            bytes: std::sync::atomic::AtomicUsize::new(0),
            telemetry,
        }
    }

    fn acquire(self: &Arc<Self>, plan: DirectNicBatchPlan) -> DirectNicQueueGuard {
        self.packets.fetch_add(
            plan.packet_count as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.bytes.fetch_add(
            plan.queue_credits as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.publish();
        DirectNicQueueGuard {
            state: self.clone(),
            plan,
        }
    }

    fn release(&self, plan: DirectNicBatchPlan) {
        self.packets.fetch_sub(
            plan.packet_count as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.bytes.fetch_sub(
            plan.queue_credits as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.publish();
    }

    fn publish(&self) {
        self.telemetry.set_queue_occupancy(
            DataplaneQueueClass::DirectNic,
            0,
            self.packets.load(std::sync::atomic::Ordering::Relaxed),
            self.bytes.load(std::sync::atomic::Ordering::Relaxed),
        );
    }
}

struct DirectNicQueueGuard {
    state: Arc<DirectNicQueueState>,
    plan: DirectNicBatchPlan,
}

impl Drop for DirectNicQueueGuard {
    fn drop(&mut self) {
        self.state.release(self.plan);
    }
}

struct DirectNicWork {
    batch: PacketBatch,
    queue_guard: DirectNicQueueGuard,
    queue_credits: OwnedSemaphorePermit,
}

struct DirectNicWriteBatch {
    batch: PacketBatch,
    ownership:
        SmallVec<[(DirectNicQueueGuard, OwnedSemaphorePermit); DIRECT_NIC_QUEUE_BATCH_CAPACITY]>,
}

impl DirectNicWriteBatch {
    fn new(work: DirectNicWork) -> Self {
        let DirectNicWork {
            batch,
            queue_guard,
            queue_credits,
        } = work;
        let mut ownership = SmallVec::new();
        ownership.push((queue_guard, queue_credits));
        Self { batch, ownership }
    }

    fn try_append(&mut self, work: DirectNicWork) -> Result<(), DirectNicWork> {
        if self.batch.len().saturating_add(work.batch.len()) > MAX_PACKET_BATCH_SIZE {
            return Err(work);
        }
        let DirectNicWork {
            batch,
            queue_guard,
            queue_credits,
        } = work;
        self.batch
            .try_append(batch)
            .expect("the direct NIC write batch checks its packet bound");
        self.ownership.push((queue_guard, queue_credits));
        Ok(())
    }
}

pub(crate) struct DirectNicEndpoint {
    sender: mpsc::Sender<DirectNicWork>,
    queue_credits: Arc<Semaphore>,
    queue_state: Arc<DirectNicQueueState>,
    terminal_error: Arc<OnceLock<String>>,
}

impl DirectNicEndpoint {
    fn terminal_error(&self) -> TunnelError {
        self.terminal_error
            .get()
            .map_or(TunnelError::Shutdown, |error| {
                TunnelError::InternalError(format!("direct NIC writer failed: {error}"))
            })
    }

    async fn enqueue(
        &self,
        batch: PacketBatch,
        plan: DirectNicBatchPlan,
    ) -> Result<(), TunnelError> {
        if self.terminal_error.get().is_some() {
            return Err(self.terminal_error());
        }
        let _stage = self.queue_state.telemetry.sample_stage(
            DataplaneStage::DirectNicAdmission,
            plan.packet_count as usize,
            plan.byte_count as usize,
        );
        let permit = match self
            .queue_credits
            .clone()
            .try_acquire_many_owned(plan.queue_credits)
        {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                let started = std::time::Instant::now();
                let result = self
                    .queue_credits
                    .clone()
                    .acquire_many_owned(plan.queue_credits)
                    .await
                    .map_err(|_| self.terminal_error());
                self.queue_state.telemetry.record_queue_stall(
                    DataplaneQueueClass::DirectNic,
                    0,
                    started.elapsed(),
                );
                result?
            }
            Err(tokio::sync::TryAcquireError::Closed) => return Err(self.terminal_error()),
        };
        let work = DirectNicWork {
            batch,
            queue_guard: self.queue_state.acquire(plan),
            queue_credits: permit,
        };
        match self.sender.try_send(work) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(work)) => {
                let started = std::time::Instant::now();
                let result = self
                    .sender
                    .send(work)
                    .await
                    .map_err(|_| self.terminal_error());
                self.queue_state.telemetry.record_queue_stall(
                    DataplaneQueueClass::DirectNic,
                    0,
                    started.elapsed(),
                );
                result
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self.terminal_error()),
        }
    }
}

fn finish_direct_nic_batch(
    mut batch: PacketBatch,
    byte_count: usize,
    mut retained_bytes: usize,
) -> Result<DirectNicDelivery, TunnelError> {
    if batch.len() > MAX_PACKET_BATCH_SIZE {
        return Err(TunnelError::ExceedMaxPacketSize(
            MAX_PACKET_BATCH_SIZE,
            batch.len(),
        ));
    }
    let packet_credits = batch
        .len()
        .checked_mul(DIRECT_NIC_QUEUE_SLOT_BYTES)
        .ok_or_else(|| TunnelError::InternalError("direct NIC packet credits overflow".into()))?;
    let mut queue_credits = retained_bytes.max(packet_credits);
    if queue_credits > DIRECT_NIC_BATCH_CREDIT_BYTES
        && byte_count.max(packet_credits) <= DIRECT_NIC_BATCH_CREDIT_BYTES
    {
        retained_bytes = 0;
        for packet in batch.iter_mut() {
            packet.compact_retained_buffer();
            retained_bytes = retained_bytes.saturating_add(packet.retained_buffer_capacity());
        }
        queue_credits = retained_bytes.max(packet_credits);
    }
    if queue_credits > DIRECT_NIC_BATCH_CREDIT_BYTES {
        return Err(TunnelError::ExceedMaxPacketSize(
            DIRECT_NIC_BATCH_CREDIT_BYTES,
            queue_credits,
        ));
    }
    let plan = DirectNicBatchPlan {
        byte_count: byte_count as u64,
        packet_count: batch.len() as u64,
        queue_credits: u32::try_from(queue_credits).expect("direct NIC credits fit u32"),
    };
    Ok(DirectNicDelivery {
        batch,
        plan,
        byte_count: byte_count as u64,
        packet_count: plan.packet_count,
    })
}

fn plan_direct_nic_delivery(mut batch: PacketBatch) -> Result<DirectNicDelivery, TunnelError> {
    debug_assert!(!batch.is_empty());
    let mut byte_count = 0_usize;
    let mut retained_bytes = 0_usize;
    for packet in batch.iter_mut() {
        stamp_packet_flow(packet);
        byte_count = byte_count.saturating_add(packet.buf_len());
        retained_bytes = retained_bytes.saturating_add(packet.retained_buffer_capacity());
    }
    finish_direct_nic_batch(batch, byte_count, retained_bytes)
}

fn collect_direct_nic_write_batch(
    first: DirectNicWork,
    receiver: &mut mpsc::Receiver<DirectNicWork>,
    pending: &mut Option<DirectNicWork>,
) -> DirectNicWriteBatch {
    let mut write = DirectNicWriteBatch::new(first);
    while write.batch.len() < MAX_PACKET_BATCH_SIZE {
        let work = match receiver.try_recv() {
            Ok(work) => work,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        };
        if let Err(work) = write.try_append(work) {
            *pending = Some(work);
            break;
        }
    }
    write
}

async fn feed_direct_nic_write_batch(
    sink: &mut std::pin::Pin<Box<dyn PacketBatchSink>>,
    write: DirectNicWriteBatch,
) -> Result<(), TunnelError> {
    let DirectNicWriteBatch {
        batch,
        ownership: _ownership,
    } = write;
    sink.feed(batch).await?;
    Ok(())
}

fn record_direct_nic_writer_failure(
    terminal_error: &OnceLock<String>,
    global_ctx: &ArcGlobalCtx,
    error: TunnelError,
) {
    let error = error.to_string();
    let _ = terminal_error.set(error.clone());
    global_ctx.set_tun_device_error(format!("TUN write failed: {error}"));
    tracing::error!(%error, "direct NIC writer failed");
}

async fn run_direct_nic_writer(
    mut sink: std::pin::Pin<Box<dyn PacketBatchSink>>,
    mut receiver: mpsc::Receiver<DirectNicWork>,
    terminal_error: Arc<OnceLock<String>>,
    global_ctx: ArcGlobalCtx,
) {
    let mut pending = None;
    while let Some(work) = match pending.take() {
        Some(work) => Some(work),
        None => receiver.recv().await,
    } {
        let write = collect_direct_nic_write_batch(work, &mut receiver, &mut pending);
        if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
            record_direct_nic_writer_failure(&terminal_error, &global_ctx, error);
            return;
        }

        loop {
            if let Some(work) = pending.take() {
                let write = collect_direct_nic_write_batch(work, &mut receiver, &mut pending);
                if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
                    record_direct_nic_writer_failure(&terminal_error, &global_ctx, error);
                    return;
                }
                continue;
            }
            tokio::select! {
                biased;
                next = receiver.recv() => {
                    match next {
                        Some(work) => {
                            let write = collect_direct_nic_write_batch(
                                work,
                                &mut receiver,
                                &mut pending,
                            );
                            if let Err(error) = feed_direct_nic_write_batch(&mut sink, write).await {
                                record_direct_nic_writer_failure(
                                    &terminal_error,
                                    &global_ctx,
                                    error,
                                );
                                return;
                            }
                        }
                        None => {
                            if let Err(error) = sink.flush().await {
                                record_direct_nic_writer_failure(
                                    &terminal_error,
                                    &global_ctx,
                                    error,
                                );
                            }
                            return;
                        }
                    }
                }
                result = sink.flush() => {
                    match result {
                        Ok(()) => {
                            break;
                        }
                        Err(error) => {
                            record_direct_nic_writer_failure(
                                &terminal_error,
                                &global_ctx,
                                error,
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct DirectNicBatchWriter {
    endpoint: SyncRwLock<Weak<DirectNicEndpoint>>,
}

impl DirectNicBatchWriter {
    fn install(
        &self,
        sink: std::pin::Pin<Box<dyn PacketBatchSink>>,
        global_ctx: ArcGlobalCtx,
    ) -> Arc<DirectNicEndpoint> {
        let (sender, receiver) = mpsc::channel(DIRECT_NIC_QUEUE_BATCH_CAPACITY);
        let terminal_error = Arc::new(OnceLock::new());
        let queue_state = Arc::new(DirectNicQueueState::new(
            global_ctx.dataplane_telemetry().clone(),
        ));
        let endpoint = Arc::new(DirectNicEndpoint {
            sender,
            queue_credits: Arc::new(Semaphore::new(DIRECT_NIC_QUEUE_CREDIT_BYTES)),
            queue_state,
            terminal_error: terminal_error.clone(),
        });
        *self.endpoint.write() = Arc::downgrade(&endpoint);
        tokio::spawn(run_direct_nic_writer(
            sink,
            receiver,
            terminal_error,
            global_ctx,
        ));
        endpoint
    }

    fn current_endpoint(&self) -> Option<Arc<DirectNicEndpoint>> {
        self.endpoint.read().upgrade()
    }

    async fn send_to(
        endpoint: Arc<DirectNicEndpoint>,
        delivery: DirectNicDelivery,
    ) -> Result<(), TunnelError> {
        endpoint.enqueue(delivery.batch, delivery.plan).await
    }
}

pub(crate) struct DirectNicIngress {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    global_ctx: ArcGlobalCtx,
    route: ArcRoute,
    l2_fabric: Arc<L2Fabric>,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    ethernet_input: bool,
    nic: Arc<DirectNicBatchWriter>,
    self_rx_bytes: CounterHandle,
    self_rx_packets: CounterHandle,
    compress_rx_bytes_before: CounterHandle,
    compress_rx_bytes_after: CounterHandle,
}

impl DirectNicIngress {
    pub(crate) async fn try_process(&self, mut batch: PacketBatch) -> Result<(), PacketBatch> {
        let _stage = self
            .global_ctx
            .dataplane_telemetry()
            .sample_stage_with_shape(DataplaneStage::DirectNicIngress, || {
                (batch.len(), batch.buffer_byte_len())
            });
        let Some(peers) = self.peers.upgrade() else {
            return Err(batch);
        };
        let Some(endpoint) = self.nic.current_endpoint() else {
            return Err(batch);
        };
        for packet in batch.iter_mut() {
            if packet.parsed_metadata().is_none() && packet.refresh_parsed_metadata().is_none() {
                return Err(batch);
            }
        }

        let Some((from_peer_id, packet_type)) =
            inspect_direct_nic_batch(&batch, self.my_peer_id, self.ethernet_input, &mut |_, _| {})
        else {
            return Err(batch);
        };

        if packet_type == PacketType::Ethernet as u8
            && !PeerManager::credential_ethernet_peer_is_allowed(&peers, packet_type, from_peer_id)
                .await
        {
            tracing::warn!(
                from_peer_id,
                "drop ethernet batch from suppressed credential peer"
            );
            return Ok(());
        }
        if packet_type == PacketType::Ethernet as u8 {
            let mut authorized = true;
            for packet in &batch {
                if !PeerManager::full_ethernet_receive_is_authorized(
                    &peers,
                    None,
                    &self.global_ctx,
                    self.my_peer_id,
                    packet,
                ) {
                    authorized = false;
                    break;
                }
            }
            if !authorized {
                tracing::debug!(from_peer_id, "drop complete Ethernet from a hybrid peer");
                return Ok(());
            }
        }

        let batch = self
            .global_ctx
            .get_acl_filter()
            .process_packet_batch_with_acl(
                batch,
                true,
                self.global_ctx.get_ipv4().map(|address| address.address()),
                |destination| self.global_ctx.is_ip_local_ipv6(&destination),
                self.route.as_ref(),
            );
        if batch.is_empty() {
            return Ok(());
        }

        let mut batch = batch;
        {
            let pipelines = self.peer_packet_process_pipeline.read().await;
            for pipeline in pipelines.iter().rev() {
                if pipeline.is_direct_nic_terminal()
                    || !pipeline.is_interested_in_direct_nic_batch(&batch)
                {
                    continue;
                }
                batch = pipeline.try_process_batch_from_peer(batch).await;
                if batch.is_empty() {
                    return Ok(());
                }
            }
        }

        let now = std::time::Instant::now();
        if self.ethernet_input {
            let mut ingress_batch = L2IngressBatch::default();
            let keep: SmallVec<[bool; 64]> = batch
                .iter()
                .map(|packet| {
                    if packet_type == PacketType::Ethernet as u8 {
                        self.l2_fabric.admit_ingress_batch_at(
                            packet.payload(),
                            from_peer_id,
                            self.my_peer_id,
                            now,
                            &mut ingress_batch,
                        )
                    } else {
                        PeerManager::admit_compact_to_tap(
                            &self.l2_fabric,
                            packet.payload(),
                            from_peer_id,
                            &self.global_ctx,
                            now,
                        )
                    }
                })
                .collect();
            batch.retain_flags(&keep);
            if batch.is_empty() {
                return Ok(());
            }
        }
        // Stamp flow shards, account bytes and size the bounded TUN admission
        // in one pass while the cleartext tuple is still available.
        let delivery = match plan_direct_nic_delivery(batch) {
            Ok(delivery) => delivery,
            Err(error) => {
                tracing::error!(?error, "prepare direct packet batch for NIC failed");
                return Ok(());
            }
        };
        self.self_rx_bytes.add(delivery.byte_count);
        self.self_rx_packets.add(delivery.packet_count);
        self.compress_rx_bytes_before.add(delivery.byte_count);
        self.compress_rx_bytes_after.add(delivery.byte_count);
        if !self.traffic_metrics.try_record_rx_batch(
            from_peer_id,
            packet_type,
            delivery.byte_count,
            delivery.packet_count,
        ) {
            self.traffic_metrics
                .record_rx_batch(
                    from_peer_id,
                    packet_type,
                    delivery.byte_count,
                    delivery.packet_count,
                )
                .await;
        }

        if let Err(error) = DirectNicBatchWriter::send_to(endpoint, delivery).await {
            tracing::error!(?error, "send direct packet batch to NIC failed");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserRoutePlan {
    System,
    Overlay {
        peer_ids: Vec<PeerId>,
        is_exit_node: bool,
    },
    Blackhole,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: PacketRecvChan,
    packet_ingress: PacketRecvChan,
    direct_nic_writer: Arc<DirectNicBatchWriter>,

    tasks: Mutex<JoinSet<()>>,

    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,
    relay_peer_map: Arc<RelayPeerMap>,

    l2_fabric: Arc<L2Fabric>,
    service_routes: Arc<ServiceRouteStore>,
    local_bgp_routes_lock: SyncMutex<()>,
    local_bgp_route_generation: AtomicU64,
    topology_service_route_generation: AtomicU64,
    static_service_route_generation: AtomicU64,

    exit_nodes: ArcSwap<Vec<IpAddr>>,

    reserved_my_peer_id_map: DashMap<String, PeerId>,
    recent_have_traffic: Arc<DashMap<PeerId, Instant>>,
    recent_data_traffic: Arc<DashMap<PeerId, Instant>>,
    p2p_demand_notify: Arc<ExternalTaskSignal>,

    allow_loopback_tunnel: AtomicBool,

    self_tx_counters: SelfTxCounters,
    traffic_metrics: Arc<TrafficMetricRecorder>,

    peer_session_store: Arc<PeerSessionStore>,
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_peer_id", &self.my_peer_id())
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .finish()
    }
}

impl PeerManager {
    pub fn l2_snapshot(&self) -> super::l2_fabric::L2Snapshot {
        self.l2_fabric.snapshot()
    }

    pub fn l2_counters(&self) -> super::l2_fabric::L2Counters {
        self.l2_fabric.counters()
    }

    fn admit_compact_to_tap(
        fabric: &L2Fabric,
        payload: &[u8],
        peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
        now: std::time::Instant,
    ) -> bool {
        let is_flood = match payload.first().map(|byte| byte >> 4) {
            Some(4) => Ipv4Packet::new(payload).is_some_and(|packet| {
                let destination = packet.get_destination();
                destination.is_multicast()
                    || destination.is_broadcast()
                    || global_ctx
                        .get_ipv4()
                        .is_some_and(|network| destination == network.last_address())
            }),
            Some(6) => Ipv6Packet::new(payload)
                .is_some_and(|packet| packet.get_destination().is_multicast()),
            _ => false,
        };
        fabric.admit_compact_ingress_at(payload, peer_id, now, is_flood)
    }

    pub(crate) fn l2_destination_is_live(
        descriptor: &PeerMapDataPlaneDescriptor,
        peer_id: PeerId,
        local_peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        if peer_id == local_peer_id {
            return Self::local_bridge_is_authorized(global_ctx);
        }
        descriptor.forwarding_snapshot.as_ref().is_some_and(|snapshot| {
            (peer_id == local_peer_id || snapshot.next_hop(peer_id, NextHopPolicy::LeastHop).is_some())
                && Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    descriptor.origin_auth_snapshot.as_ref(), snapshot, peer_id, local_peer_id, global_ctx,
                )
        })
    }

    fn live_l2_destination(
        &self,
        destination: EthernetDestination,
        descriptor: &PeerMapDataPlaneDescriptor,
    ) -> EthernetDestination {
        if let EthernetDestination::Known(peer_id) = destination
            && !Self::l2_destination_is_live(descriptor, peer_id, self.my_peer_id, &self.global_ctx)
        {
            self.l2_fabric.forget_peer(peer_id);
            return EthernetDestination::Flood;
        }
        destination
    }

    fn complete_ethernet_is_authorized(local: &crate::proto::common::PeerFeatureFlag) -> bool {
        local.ethernet_input && local.hybrid_l3 && local.bridge_input && !local.is_credential_peer
    }

    /// Check local bridge authorization from both authenticated local identity and capabilities.
    fn local_bridge_is_authorized(global_ctx: &ArcGlobalCtx) -> bool {
        let features = global_ctx.get_feature_flags();
        Self::complete_ethernet_is_authorized(&features)
            && global_ctx.get_network_identity().network_secret.is_some()
            && !global_ctx
                .get_hostname()
                .starts_with(crate::peers::PUBLIC_SERVER_HOSTNAME_PREFIX)
    }

    fn hybrid_ip_ethernet_is_valid(packet: &ZCPacket) -> bool {
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        if !header.is_hybrid_ip_ethernet() {
            return true;
        }
        let payload = packet.payload();
        if payload.len() < crate::instance::l2_tun::ETHERNET_HEADER_LEN {
            return false;
        }
        match &payload[12..14] {
            [0x08, 0x00] => Ipv4Packet::new(&payload[14..]).is_some(),
            [0x86, 0xdd] => Ipv6Packet::new(&payload[14..]).is_some(),
            _ => false,
        }
    }

    /// Check local bridge authorization and one complete authenticated origin tuple.
    fn full_ethernet_receive_is_authorized(
        peers: &PeerMap,
        relay_peer_map: Option<&RelayPeerMap>,
        global_ctx: &ArcGlobalCtx,
        my_peer_id: PeerId,
        packet: &ZCPacket,
    ) -> bool {
        if !Self::local_bridge_is_authorized(global_ctx) {
            return false;
        }
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        if header.packet_type != PacketType::Ethernet as u8 {
            return false;
        }
        if !Self::hybrid_ip_ethernet_is_valid(packet) {
            return false;
        }
        let header_origin_peer_id = header.from_peer_id.get();

        let verified_metadata_present = packet.verified_origin_peer_id().is_some()
            || packet.verified_origin_peer_identity_type().is_some()
            || packet.verified_origin_peer_secure_auth_level().is_some()
            || packet.verified_origin_session_id().is_some();
        let logical_origin = if verified_metadata_present {
            match (
                packet.verified_origin_peer_id(),
                packet.verified_origin_peer_identity_type(),
                packet.verified_origin_peer_secure_auth_level(),
                packet.verified_origin_session_id(),
            ) {
                (Some(peer_id), Some(identity_type), Some(auth_level), Some(session_id)) => {
                    Some((peer_id, identity_type, auth_level, session_id))
                }
                _ => None,
            }
        } else if packet.authenticated_peer_id().is_some()
            || packet.authenticated_peer_identity_type().is_some()
            || packet.authenticated_peer_secure_auth_level().is_some()
            || packet.authenticated_session_id().is_some()
        {
            match (
                packet.authenticated_peer_id(),
                packet.authenticated_peer_identity_type(),
                packet.authenticated_peer_secure_auth_level(),
                packet.authenticated_session_id(),
            ) {
                (Some(peer_id), Some(identity_type), Some(auth_level), Some(session_id)) => {
                    Some((peer_id, identity_type, auth_level, session_id))
                }
                _ => None,
            }
        } else if header_origin_peer_id == my_peer_id {
            // Locally generated loopback packets have no transport tuple.
            return true;
        } else {
            None
        };

        let Some((logical_peer_id, identity_type, secure_auth_level, session_id)) = logical_origin
        else {
            return false;
        };
        if header_origin_peer_id != logical_peer_id
            || identity_type != PeerIdentityType::Admin
            || !matches!(
                secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
        {
            return false;
        }

        if packet.verified_origin_peer_id().is_some() {
            return relay_peer_map.is_some_and(|relay_peer_map| {
                relay_peer_map.ethernet_origin_is_authorized(packet, logical_peer_id)
            });
        }

        if header.is_hybrid_ip_ethernet() {
            peers.direct_authenticated_admin_is_authorized(logical_peer_id, session_id)
        } else {
            peers.direct_full_ethernet_bridge_is_authorized(logical_peer_id, session_id)
        }
    }

    fn full_ethernet_batch_is_authorized(
        peers: &PeerMap,
        relay_peer_map: Option<&RelayPeerMap>,
        global_ctx: &ArcGlobalCtx,
        my_peer_id: PeerId,
        batch: &PacketBatch,
    ) -> bool {
        for packet in batch {
            if !Self::full_ethernet_receive_is_authorized(
                peers,
                relay_peer_map,
                global_ctx,
                my_peer_id,
                packet,
            ) {
                return false;
            }
        }
        true
    }

    /// Keep the terminal NIC filter defensive without adding an await point.
    /// The receive loop performs the complete route-key and session check first.
    fn full_ethernet_receive_is_authorized_fast(
        peers: &PeerMap,
        relay_peer_map: Option<&RelayPeerMap>,
        global_ctx: &ArcGlobalCtx,
        my_peer_id: PeerId,
        packet: &ZCPacket,
    ) -> bool {
        if !Self::local_bridge_is_authorized(global_ctx) {
            return false;
        }
        let Some(header) = packet.peer_manager_header() else {
            return false;
        };
        if header.packet_type != PacketType::Ethernet as u8 {
            return false;
        }
        if !Self::hybrid_ip_ethernet_is_valid(packet) {
            return false;
        }
        let verified_metadata_present = packet.verified_origin_peer_id().is_some()
            || packet.verified_origin_peer_identity_type().is_some()
            || packet.verified_origin_peer_secure_auth_level().is_some()
            || packet.verified_origin_session_id().is_some();
        if verified_metadata_present {
            let Some(origin_peer_id) = packet.verified_origin_peer_id() else {
                return false;
            };
            return relay_peer_map.is_some_and(|relay_peer_map| {
                relay_peer_map.ethernet_origin_is_authorized(packet, origin_peer_id)
            });
        }
        let authenticated_metadata_present = packet.authenticated_peer_id().is_some()
            || packet.authenticated_peer_identity_type().is_some()
            || packet.authenticated_peer_secure_auth_level().is_some()
            || packet.authenticated_session_id().is_some();
        let Some((peer_id, identity_type, auth_level, session_id)) = packet
            .authenticated_peer_id()
            .zip(packet.authenticated_peer_identity_type())
            .zip(packet.authenticated_peer_secure_auth_level())
            .zip(packet.authenticated_session_id())
            .map(|(((peer_id, identity_type), auth_level), session_id)| {
                (peer_id, identity_type, auth_level, session_id)
            })
        else {
            if authenticated_metadata_present {
                return false;
            }
            return header.from_peer_id.get() == my_peer_id;
        };
        if header.from_peer_id.get() != peer_id
            || identity_type != PeerIdentityType::Admin
            || !matches!(
                auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
        {
            return false;
        }
        let Some(connection) = peers.get_live_direct_conn(peer_id, session_id) else {
            return false;
        };
        let info = connection.get_conn_info();
        if info.peer_id != peer_id || info.conn_id != session_id.to_string() {
            return false;
        }
        let Some(static_key) = <[u8; 32]>::try_from(info.noise_remote_static_pubkey).ok() else {
            return false;
        };
        let snapshot = peers.origin_auth_snapshot();
        let Some(identity) = snapshot.lookup(peer_id) else {
            return false;
        };
        let identity_valid = identity.identity_type == PeerIdentityType::Admin
            && matches!(
                identity.secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
            && identity.noise_static_pubkey == static_key;
        if !identity_valid {
            return false;
        }
        if header.is_hybrid_ip_ethernet() {
            return true;
        }
        let Some(grant) = snapshot.lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
        else {
            return false;
        };
        grant.peer_id == peer_id
            && grant.source == OriginAuthSource::RouteAttestation
            && grant.noise_static_pubkey == static_key
            && grant.is_live(quanta::Instant::now())
    }

    /// Check a complete Ethernet destination against one immutable forwarding snapshot.
    fn snapshot_allows_full_ethernet_destination(
        snapshot: &ForwardingDecisionSnapshotHandle,
        destination_peer_id: PeerId,
        my_peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        if destination_peer_id == my_peer_id {
            Self::local_bridge_is_authorized(global_ctx)
        } else {
            snapshot.is_authorized_bridge(destination_peer_id)
        }
    }

    fn current_full_ethernet_destination_is_authorized_from_snapshot(
        origin_snapshot: &crate::peers::peer_map::OriginAuthSnapshot,
        destination_peer_id: PeerId,
        my_peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        if destination_peer_id == my_peer_id {
            return Self::local_bridge_is_authorized(global_ctx);
        }
        let Some(identity) = origin_snapshot.lookup(destination_peer_id) else {
            return false;
        };
        let Some(grant) = origin_snapshot.lookup_grant(
            destination_peer_id,
            OriginAuthCapability::FullEthernetBridge,
        ) else {
            return false;
        };
        identity.peer_id == destination_peer_id
            && identity.identity_type == PeerIdentityType::Admin
            && matches!(
                identity.secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
            && grant.peer_id == destination_peer_id
            && grant.source == OriginAuthSource::RouteAttestation
            && identity.noise_static_pubkey == grant.noise_static_pubkey
            && grant.is_live(quanta::Instant::now())
    }

    fn snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
        origin_snapshot: &crate::peers::peer_map::OriginAuthSnapshot,
        snapshot: &ForwardingDecisionSnapshotHandle,
        destination_peer_id: PeerId,
        my_peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        Self::snapshot_allows_full_ethernet_destination(
            snapshot,
            destination_peer_id,
            my_peer_id,
            global_ctx,
        ) && Self::current_full_ethernet_destination_is_authorized_from_snapshot(
            origin_snapshot,
            destination_peer_id,
            my_peer_id,
            global_ctx,
        )
    }

    /// Check a complete Ethernet destination using the current immutable route snapshot.
    async fn full_ethernet_destination_is_authorized(
        peers: &PeerMap,
        destination_peer_id: PeerId,
    ) -> bool {
        let descriptor = peers.dataplane_descriptor();
        descriptor
            .forwarding_snapshot
            .as_ref()
            .is_some_and(|snapshot| {
                Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    descriptor.origin_auth_snapshot.as_ref(),
                    snapshot,
                    destination_peer_id,
                    peers.my_peer_id(),
                    &peers.get_global_ctx(),
                )
            })
    }

    // Keep lazy-p2p demand alive across the 5s task rescan interval and a full on-demand
    // connect attempt, without retaining extra per-task state in the hot path.
    const RECENT_HAVE_TRAFFIC_TTL: Duration = Duration::from_secs(30);

    fn gc_recent_traffic_entries<F>(
        recent_have_traffic: &DashMap<PeerId, Instant>,
        now: Instant,
        mut has_directly_connected_conn: F,
    ) where
        F: FnMut(PeerId) -> bool,
    {
        let mut to_remove = Vec::new();
        for entry in recent_have_traffic.iter() {
            let peer_id = *entry.key();
            let expired =
                now.saturating_duration_since(*entry.value()) > Self::RECENT_HAVE_TRAFFIC_TTL;
            if expired || has_directly_connected_conn(peer_id) {
                to_remove.push(peer_id);
            }
        }

        if !to_remove.is_empty() {
            for peer_id in to_remove {
                recent_have_traffic.remove(&peer_id);
            }
            shrink_dashmap(recent_have_traffic, None);
        }
    }

    pub fn new(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        nic_channel: PacketRecvChan,
    ) -> Self {
        let my_peer_id = rand::random();

        let (packet_send, packet_recv) = nic_channel.create_sibling_channel();
        let packet_ingress = packet_send.clone();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));
        let peer_session_store = Arc::new(PeerSessionStore::new());

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = create_rpc_ingress_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id,
            peers: Arc::downgrade(&peers),
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
        });
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new_with_stats_manager(
            rpc_tspt.clone(),
            global_ctx.stats_manager().clone(),
        ));

        let route_algo_inst = match route_algo {
            RouteAlgoType::Ospf => RouteAlgoInst::Ospf(PeerRoute::new(
                my_peer_id,
                global_ctx.clone(),
                peer_rpc_mgr.clone(),
            )),
            RouteAlgoType::None => RouteAlgoInst::None,
        };

        let foreign_network_manager = Arc::new(ForeignNetworkManager::new(
            my_peer_id,
            global_ctx.clone(),
            peer_session_store.clone(),
            packet_send.clone(),
            Self::build_foreign_network_manager_accessor(&peers),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            global_ctx.clone(),
            packet_send,
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        let l2_flags = global_ctx.get_flags();
        let l2_fabric = Arc::new(L2Fabric::from_flags(&l2_flags));
        peers.install_l2_fabric(l2_fabric.clone());
        let service_routes = Arc::new(ServiceRouteStore::new(65_536, Duration::from_secs(300)));

        let exit_nodes = global_ctx.config.get_exit_nodes();

        let stats_manager = global_ctx.stats_manager();
        let network_name = global_ctx.get_network_name();
        let traffic_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let traffic_control_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
            MetricName::TrafficControlBytesTxByInstance,
            MetricName::TrafficControlPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let relay_peer_map = RelayPeerMap::new(
            peers.clone(),
            Some(foreign_network_client.clone()),
            global_ctx.clone(),
            my_peer_id,
            peer_session_store.clone(),
            None,
        );
        let self_tx_counters = SelfTxCounters {
            self_tx_packets: stats_manager.get_counter(
                MetricName::TrafficPacketsSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            self_tx_bytes: stats_manager.get_counter(
                MetricName::TrafficBytesSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_before: stats_manager.get_counter(
                MetricName::CompressionBytesTxBefore,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_after: stats_manager.get_counter(
                MetricName::CompressionBytesTxAfter,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compact_l3_packets: stats_manager.get_counter(
                MetricName::HybridCompactL3PacketsTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compact_l3_bytes: stats_manager.get_counter(
                MetricName::HybridCompactL3BytesTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            full_ethernet_packets: stats_manager.get_counter(
                MetricName::HybridFullEthernetPacketsTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            full_ethernet_bytes: stats_manager.get_counter(
                MetricName::HybridFullEthernetBytesTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
        };
        let traffic_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name,
            MetricName::TrafficBytesRx,
            MetricName::TrafficPacketsRx,
            MetricName::TrafficBytesRxByInstance,
            MetricName::TrafficPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let traffic_control_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            global_ctx.get_network_name(),
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
            MetricName::TrafficControlBytesRxByInstance,
            MetricName::TrafficControlPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let route_algo_inst_for_metrics = route_algo_inst.clone();
        let traffic_metrics = Arc::new(TrafficMetricRecorder::new(
            my_peer_id,
            traffic_tx_metrics,
            traffic_control_tx_metrics,
            traffic_rx_metrics,
            traffic_control_rx_metrics,
            move |peer_id| {
                let route_algo_inst = route_algo_inst_for_metrics.clone();
                async move {
                    match &route_algo_inst {
                        RouteAlgoInst::Ospf(route) => route
                            .get_peer_info(peer_id)
                            .await
                            .as_ref()
                            .and_then(route_peer_info_instance_id),
                        RouteAlgoInst::None => None,
                    }
                }
            },
        ));

        PeerManager {
            my_peer_id,

            global_ctx,
            nic_channel,
            packet_ingress,
            direct_nic_writer: Arc::new(DirectNicBatchWriter::default()),

            tasks: Mutex::new(JoinSet::new()),

            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),

            peers,

            peer_rpc_mgr,
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),
            nic_packet_process_pipeline: Arc::new(RwLock::new(Vec::new())),

            route_algo_inst,

            foreign_network_manager,
            foreign_network_client,
            relay_peer_map,

            l2_fabric,
            service_routes,
            local_bgp_routes_lock: SyncMutex::new(()),
            local_bgp_route_generation: AtomicU64::new(0),
            topology_service_route_generation: AtomicU64::new(0),
            static_service_route_generation: AtomicU64::new(0),

            exit_nodes: ArcSwap::from_pointee(exit_nodes),

            reserved_my_peer_id_map: DashMap::new(),
            recent_have_traffic: Arc::new(DashMap::new()),
            recent_data_traffic: Arc::new(DashMap::new()),
            p2p_demand_notify: Arc::new(ExternalTaskSignal::new()),

            allow_loopback_tunnel: AtomicBool::new(true),

            self_tx_counters,
            traffic_metrics,

            peer_session_store,
        }
    }

    pub fn set_allow_loopback_tunnel(&self, allow_loopback_tunnel: bool) {
        self.allow_loopback_tunnel
            .store(allow_loopback_tunnel, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn mark_recent_traffic(&self, dst_peer_id: PeerId) {
        if dst_peer_id == self.my_peer_id {
            return;
        }

        let now = Instant::now();
        self.recent_data_traffic.insert(dst_peer_id, now);

        let flags = self.global_ctx.flags_arc();
        if flags.disable_p2p || !flags.lazy_p2p || self.has_directly_connected_conn(dst_peer_id) {
            return;
        }

        if let Some(mut last_seen) = self.recent_have_traffic.get_mut(&dst_peer_id) {
            let should_notify =
                now.saturating_duration_since(*last_seen) > Self::RECENT_HAVE_TRAFFIC_TTL;
            *last_seen = now;
            if !should_notify {
                return;
            }
        } else {
            self.recent_have_traffic.insert(dst_peer_id, now);
        }
        self.p2p_demand_notify.notify();
    }

    pub fn has_recent_traffic(&self, peer_id: PeerId, now: Instant) -> bool {
        if self.has_directly_connected_conn(peer_id) {
            return false;
        }

        self.recent_have_traffic
            .get(&peer_id)
            .map(|last_seen| {
                now.saturating_duration_since(*last_seen) <= Self::RECENT_HAVE_TRAFFIC_TTL
            })
            .unwrap_or(false)
    }

    pub fn clear_recent_traffic(&self, peer_id: PeerId) {
        self.recent_have_traffic.remove(&peer_id);
    }

    pub fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        self.p2p_demand_notify.clone()
    }

    async fn close_untrusted_credential_peers(peer_map: &Arc<PeerMap>, global_ctx: &ArcGlobalCtx) {
        let network_name = global_ctx.get_network_name();
        for peer_id in peer_map.list_peers() {
            if !matches!(
                peer_map.get_peer_identity_type(peer_id),
                Some(PeerIdentityType::Credential)
            ) {
                continue;
            }
            let Some(peer) = peer_map.get_peer_by_id(peer_id) else {
                continue;
            };
            let Some(pubkey) = peer.get_peer_public_key() else {
                continue;
            };

            if global_ctx.is_pubkey_trusted(&pubkey, &network_name) {
                continue;
            }

            tracing::warn!(?peer_id, "closing untrusted credential peer");
            if let Err(e) = peer_map.close_peer(peer_id).await {
                tracing::warn!(?e, ?peer_id, "failed to close untrusted credential peer");
            }
        }
    }

    fn build_foreign_network_manager_accessor(
        peer_map: &Arc<PeerMap>,
    ) -> Box<dyn GlobalForeignNetworkAccessor> {
        struct T {
            peer_map: Weak<PeerMap>,
        }

        #[async_trait::async_trait]
        impl GlobalForeignNetworkAccessor for T {
            async fn list_authenticated_global_foreign_peers(
                &self,
                network_identity: &NetworkIdentity,
            ) -> Vec<(PeerId, Vec<u8>)> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                peer_map
                    .list_authenticated_foreign_network_peers(network_identity)
                    .await
            }
        }

        Box::new(T {
            peer_map: Arc::downgrade(peer_map),
        })
    }

    async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        let my_identity = self.global_ctx.get_network_identity();
        let peer_identity = peer_conn.get_network_identity();
        let conn_info = peer_conn.get_conn_info();
        let local_secure_mode = self
            .global_ctx
            .config
            .get_secure_mode()
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);
        let peer_secure_mode = !conn_info.noise_remote_static_pubkey.is_empty();

        if local_secure_mode != peer_secure_mode {
            return Err(Error::SecretKeyError(
                "same-network peers must use the same secure mode".to_string(),
            ));
        }

        // A digest identifies a network. It does not prove secret possession.
        // The Noise handshake already enforced proof or trusted-key admission.
        let identity_ok = my_identity.network_name == peer_identity.network_name;

        if !identity_ok {
            return Err(Error::SecretKeyError(
                "network identity not match".to_string(),
            ));
        }
        let peer_id = peer_conn.get_peer_id();
        self.peers.add_new_peer_conn(peer_conn).await?;
        self.clear_recent_traffic(peer_id);
        Ok(())
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, None)
            .await
    }

    pub(crate) async fn add_punched_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        expected_peer: PeerId,
        client: bool,
    ) -> Result<(), Error> {
        let mut peer = PeerConn::new_with_peer_id_hint(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            Some(expected_peer),
            self.peer_session_store.clone(),
        );
        peer.set_is_hole_punched(true);
        if client {
            peer.do_handshake_as_client().await?;
        } else {
            peer.do_handshake_as_server().await?;
        }
        // Rendezvous authorizes one peer. Check identity before publishing the connection.
        if peer.get_peer_id() != expected_peer {
            return Err(Error::SecretKeyError(
                "punched peer differs from rendezvous peer".to_owned(),
            ));
        }
        self.add_new_peer_conn(peer).await
    }
    #[cfg(test)]
    pub(crate) async fn add_discovered_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        expected_peer: Option<PeerId>,
        client: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.add_discovered_tunnel_with_hint(tunnel, expected_peer, client, None)
            .await
    }

    pub(crate) async fn add_discovered_tunnel_with_hint(
        &self,
        tunnel: Box<dyn Tunnel>,
        expected_peer: Option<PeerId>,
        client: bool,
        hint: Option<Arc<super::peer_conn::DiscoveryPeerHint>>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let info = tunnel
            .info()
            .ok_or_else(|| anyhow::anyhow!("discovery tunnel has no info"))?;
        check_tunnel_info_underlay(&info, &self.global_ctx.get_underlay_policy())?;
        self.check_remote_addr_not_from_virtual_network(&tunnel)?;
        let mut peer = PeerConn::new_with_peer_id_hint(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            expected_peer.or_else(|| hint.as_ref().and_then(|hint| hint.peer_id())),
            self.peer_session_store.clone(),
        );
        if let Some(hint) = hint {
            peer.set_discovery_peer_hint(hint);
        }
        peer.set_is_hole_punched(expected_peer.is_some());
        if client {
            peer.do_handshake_as_client().await?;
        } else {
            peer.do_handshake_as_server().await?;
        }
        let peer_id = peer.get_peer_id();
        if expected_peer.is_some_and(|expected| expected != peer_id) {
            return Err(Error::SecretKeyError(
                "discovery peer differs from authenticated punch peer".to_owned(),
            ));
        }
        // Tracker candidates cannot authorize foreign-network relay membership.
        let conn_id = peer.get_conn_id();
        self.add_new_peer_conn(peer).await?;
        Ok((peer_id, conn_id))
    }

    pub async fn add_client_tunnel_with_peer_id_hint(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new_with_peer_id_hint(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            peer_id_hint,
            self.peer_session_store.clone(),
        );
        peer.set_is_hole_punched(!is_directly_connected);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        if peer.get_network_identity().network_name
            == self.global_ctx.get_network_identity().network_name
        {
            self.add_new_peer_conn(peer).await?;
        } else {
            self.foreign_network_client.add_new_peer_conn(peer).await?;
        }
        Ok((peer_id, conn_id))
    }

    pub fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    pub(crate) fn has_live_peer_connection(&self, peer_id: PeerId) -> bool {
        self.peers
            .get_peer_by_id(peer_id)
            .is_some_and(|peer| peer.has_live_conns())
            || self
                .foreign_network_client
                .get_peer_map()
                .get_peer_by_id(peer_id)
                .is_some_and(|peer| peer.has_live_conns())
    }

    #[tracing::instrument]
    pub async fn try_direct_connect<C>(&self, connector: C) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        self.try_direct_connect_with_peer_id_hint(connector, None)
            .await
    }

    #[tracing::instrument]
    pub async fn try_direct_connect_with_peer_id_hint<C>(
        &self,
        connector: C,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        let t = self.connect_tunnel(connector).await?;
        self.add_client_tunnel_with_peer_id_hint(t, true, peer_id_hint)
            .await
    }

    pub(crate) async fn connect_tunnel<C>(&self, mut connector: C) -> Result<Box<dyn Tunnel>, Error>
    where
        C: TunnelConnector + Debug,
    {
        let ns = self.global_ctx.net_ns.clone();
        Ok(ns
            .run_async(|| async move { connector.connect().await })
            .await?)
    }

    // avoid loop back to virtual network
    fn check_remote_addr_not_from_virtual_network(
        &self,
        tunnel: &dyn Tunnel,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("check remote addr not from virtual network");
        let Some(tunnel_info) = tunnel.info() else {
            anyhow::bail!("tunnel info is not set");
        };
        let Some(src) = tunnel_info.remote_addr.map(url::Url::from) else {
            anyhow::bail!("tunnel info remote addr is not set");
        };
        if src.scheme() == "ring" {
            return Ok(());
        }
        let Ok(Some(addr)) = src.socket_addrs(|| Some(1)).map(|x| x.first().cloned()) else {
            // if the tunnel is not rely on ip address, skip check
            return Ok(());
        };

        // if no-tun is enabled, the src ip of packet in virtual network is converted to loopback address
        // we already filter out the connection in tcp/quic proxy so no need check here.
        if addr.ip().is_loopback() {
            // allow other loopback address, good for conn from cdn/l4 connection
            return Ok(());
        }

        if self.global_ctx.is_ip_in_same_network(&addr.ip()) {
            anyhow::bail!(
                "tunnel src {} is from the same network (ignore this error please)",
                addr
            );
        }

        Ok(())
    }

    fn release_reserved_peer_id(&self, network_name: &str) {
        self.reserved_my_peer_id_map.remove(network_name);
        shrink_dashmap(&self.reserved_my_peer_id_map, None);
    }

    #[tracing::instrument(ret)]
    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        let tunnel_info = tunnel
            .info()
            .ok_or_else(|| anyhow::anyhow!("tunnel info is not set"))?;
        check_tunnel_info_underlay(&tunnel_info, &self.global_ctx.get_underlay_policy())?;
        self.check_remote_addr_not_from_virtual_network(&tunnel)?;

        let mut conn = PeerConn::new(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            self.peer_session_store.clone(),
        );
        let mut reserved_peer_id_network_name = None;
        let handshake_ret = conn
            .do_handshake_as_server_ext_with_admission(
                |peer, network_name: &str| {
                    if network_name
                        == self.global_ctx.get_network_identity().network_name
                    {
                        return Ok(());
                    }

                    let mut peer_id = self
                        .foreign_network_manager
                        .get_network_peer_id(network_name);
                    if peer_id.is_none() {
                        reserved_peer_id_network_name = Some(network_name.to_string());
                        peer_id = Some(
                            *self
                                .reserved_my_peer_id_map
                                .entry(network_name.to_string())
                                .or_insert_with(|| rand::random::<PeerId>())
                                .value(),
                        );
                    }
                    peer.set_peer_id(peer_id.unwrap());

                    tracing::info!(
                        ?peer_id,
                        ?network_name,
                        "handshake as server with foreign network, new peer id: {}, peer id in foreign manager: {:?}",
                        peer.get_my_peer_id(),
                        peer_id
                    );

                    Ok(())
                },
                |network_name, secure_auth_level, private_admission, remote_static| {
                    if network_name == self.global_ctx.get_network_identity().network_name {
                        return Ok(());
                    }

                    let flags = self.global_ctx.get_flags();
                    if !flags.relay_all_peer_rpc
                        && self
                            .global_ctx
                            .check_network_in_whitelist(network_name)
                            .is_err()
                    {
                        return Err(Error::SecretKeyError(format!(
                            "foreign network {network_name} is not in relay whitelist"
                        )));
                    }

                    if flags.private_mode && !private_admission.is_authorized() {
                        return Err(Error::SecretKeyError(
                            "private mode is turned on, foreign network admission failed"
                                .to_string(),
                        ));
                    }

                    tracing::debug!(
                        %network_name,
                        ?secure_auth_level,
                        remote_static_len = remote_static.len(),
                        "foreign peer passed pre-commit admission"
                    );
                    Ok(())
                },
            )
        .await;

        if let Err(err) = handshake_ret {
            if let Some(network_name) = reserved_peer_id_network_name {
                self.release_reserved_peer_id(&network_name);
            }
            return Err(err);
        }

        let peer_identity = conn.get_network_identity();
        let peer_network_name = peer_identity.network_name.clone();
        let my_identity = self.global_ctx.get_network_identity();
        let is_local_network = peer_network_name == my_identity.network_name;
        // Use the authorization result captured during Msg3 verification.
        // Do not recompute authority from a network digest or mutable trust state.
        let foreign_network_allowed = conn.private_admission().is_authorized();

        if !is_local_network && self.global_ctx.get_flags().private_mode && !foreign_network_allowed
        {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(Error::SecretKeyError(
                "private mode is turned on, foreign network secret mismatch".to_string(),
            ));
        }

        conn.set_is_hole_punched(!is_directly_connected);

        let add_peer_ret = if is_local_network {
            self.add_new_peer_conn(conn).await
        } else {
            self.foreign_network_manager.add_peer_conn(conn).await
        };

        if let Err(err) = add_peer_ret {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(err);
        }

        self.release_reserved_peer_id(&peer_network_name);

        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn handle_foreign_network_packet(
        mut packet: ZCPacket,
        my_peer_id: PeerId,
        peer_map: &PeerMap,
        relay_peer_map: &Arc<RelayPeerMap>,
        foreign_network_mgr: &ForeignNetworkManager,
    ) -> Result<(), ZCPacket> {
        let Some(pm_header) = packet.peer_manager_header() else {
            return Ok(());
        };
        let from_peer_id = pm_header.from_peer_id.get();
        let to_peer_id = pm_header.to_peer_id.get();

        let Some(foreign_hdr) = packet.foreign_network_hdr() else {
            tracing::warn!(
                from_peer_id,
                to_peer_id,
                "drop invalid foreign network packet"
            );
            return Ok(());
        };
        let Some(foreign_network_name) = foreign_hdr.get_network_name(packet.payload()) else {
            tracing::warn!(
                from_peer_id,
                to_peer_id,
                "drop malformed foreign network name"
            );
            return Ok(());
        };
        let foreign_peer_id = foreign_hdr.get_dst_peer_id();
        let foreign_network_my_peer_id =
            foreign_network_mgr.get_network_peer_id(&foreign_network_name);

        let buf_len = packet.buf_len();
        let stats_manager = peer_map.get_global_ctx().stats_manager().clone();
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(foreign_network_name.clone()));
        let add_counter = move |bytes_metric, packets_metric| {
            stats_manager
                .get_counter(bytes_metric, label_set.clone())
                .add(buf_len as u64);
            stats_manager.get_counter(packets_metric, label_set).inc();
        };

        if packet.authenticated_peer_id().is_none()
            && Some(from_peer_id) == foreign_network_my_peer_id
        {
            packet.transit_data = Self::is_relay_data_zc_packet(&packet);
            let Some(to_peer_id) = peer_map
                .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
                .await
            else {
                tracing::debug!(
                    ?foreign_network_name,
                    ?to_peer_id,
                    "cannot find the owner of the foreign network peer"
                );
                return Err(packet);
            };
            add_counter(
                MetricName::TrafficBytesForeignForwardTx,
                MetricName::TrafficPacketsForeignForwardTx,
            );

            let header = packet.mut_peer_manager_header().unwrap();
            header.from_peer_id.set(my_peer_id);
            header.to_peer_id.set(to_peer_id);
            let policy = Self::get_next_hop_policy(header);

            if let Err(error) = relay_peer_map.send_msg(packet, to_peer_id, policy).await {
                tracing::debug!(?error, ?to_peer_id, "secure foreign packet send failed");
            }
            Ok(())
        } else if to_peer_id == my_peer_id {
            let Some(owner_peer_id) = packet.logical_authenticated_peer_id() else {
                tracing::warn!(from_peer_id, "drop unauthenticated foreign network packet");
                return Ok(());
            };
            let Some(_owner_session_id) = packet.logical_authenticated_session_id() else {
                tracing::warn!(
                    owner_peer_id,
                    "drop foreign packet without a secure session"
                );
                return Ok(());
            };
            let Some(mut inner_packet) = packet.foreign_network_packet() else {
                tracing::warn!(foreign_peer_id, "drop malformed inner foreign packet");
                return Ok(());
            };
            let Some(inner_header) = inner_packet.peer_manager_header() else {
                tracing::warn!(foreign_peer_id, "drop invalid inner foreign packet");
                return Ok(());
            };
            let inner_peer_id = inner_header.from_peer_id.get();
            let inner_is_encrypted = inner_header.is_encrypted();
            let inner_packet_type = inner_header.packet_type;
            let inner_is_relay_handshake =
                RelayPeerMap::is_handshake_packet_type(inner_packet_type);
            if !inner_is_encrypted && !inner_is_relay_handshake {
                tracing::warn!(
                    inner_peer_id,
                    inner_packet_type,
                    "drop plaintext inner foreign payload"
                );
                return Ok(());
            }
            let Some(network_identity) =
                foreign_network_mgr.get_network_identity(&foreign_network_name)
            else {
                tracing::warn!(
                    ?foreign_network_name,
                    "drop packet for an unknown foreign network"
                );
                return Ok(());
            };
            let Some(expected_owner_key) = peer_map
                .get_authenticated_foreign_origin_owner_key(&network_identity, inner_peer_id)
                .await
            else {
                tracing::warn!(
                    inner_peer_id,
                    "drop foreign packet without an attested owner"
                );
                return Ok(());
            };
            let owner_key = if let Some(key) = peer_map.get_peer_public_key(owner_peer_id) {
                Some(key)
            } else {
                peer_map
                    .authenticated_route_peer_evidence_from_descriptor(owner_peer_id)
                    .map(|evidence| evidence.noise_static_pubkey)
            };
            if owner_key.as_deref() != Some(expected_owner_key.as_slice()) {
                tracing::warn!(
                    owner_peer_id,
                    inner_peer_id,
                    "drop foreign packet with an invalid owner"
                );
                return Ok(());
            }

            inner_packet.transit_data = Self::is_relay_data_packet(inner_packet_type);
            add_counter(
                MetricName::TrafficBytesForeignForwardRx,
                MetricName::TrafficPacketsForeignForwardRx,
            );
            inner_packet.clear_authenticated_peer_id();
            if let Err(e) = foreign_network_mgr
                .forward_foreign_network_packet(
                    &foreign_network_name,
                    foreign_peer_id,
                    inner_packet,
                )
                .await
            {
                tracing::debug!(
                    ?e,
                    ?foreign_network_name,
                    ?foreign_peer_id,
                    "foreign network mgr send_msg_to_peer failed"
                );
            }
            Ok(())
        } else {
            add_counter(
                MetricName::TrafficBytesForeignForwardForwarded,
                MetricName::TrafficPacketsForeignForwardForwarded,
            );
            Err(packet)
        }
    }

    fn is_relay_data_packet(packet_type: u8) -> bool {
        is_relay_data_packet_type(packet_type)
    }

    fn is_relay_data_zc_packet(packet: &ZCPacket) -> bool {
        let Some(hdr) = packet.peer_manager_header() else {
            return false;
        };

        if hdr.packet_type == PacketType::ForeignNetworkPacket as u8 {
            if hdr.is_foreign_control() {
                return false;
            }
            if hdr.is_encrypted() {
                return true;
            }
            let inner_packet_type = packet.foreign_network_inner_packet_type();
            if inner_packet_type.is_none() {
                tracing::warn!(
                    ?hdr,
                    "foreign network packet has unparseable inner peer manager header"
                );
            }
            return inner_packet_type.is_none_or(Self::is_relay_data_packet);
        }

        Self::is_relay_data_packet(hdr.packet_type)
    }

    fn relay_batch_outcome_at(
        outcomes: &[RelayBatchDecryptOutcome],
        index: usize,
    ) -> RelayBatchDecryptOutcome {
        outcomes
            .get(index)
            .copied()
            .unwrap_or(RelayBatchDecryptOutcome::NotAttempted)
    }

    fn relay_batch_should_decrypt(batch: &PacketBatch, my_peer_id: PeerId) -> bool {
        let mut has_relay_ciphertext = false;
        for packet in batch {
            let Some(header) = packet.peer_manager_header() else {
                return false;
            };
            if header.to_peer_id.get() != my_peer_id {
                return false;
            }
            if header.is_encrypted()
                && !RelayPeerMap::is_handshake_packet_type(header.packet_type)
                && !RelayPeerMap::is_handshake_confirmation_packet_type(header.packet_type)
            {
                has_relay_ciphertext = true;
            }
        }
        has_relay_ciphertext
    }

    async fn credential_ethernet_peer_is_allowed(
        peers: &PeerMap,
        packet_type: u8,
        peer_id: PeerId,
    ) -> bool {
        packet_type != PacketType::Ethernet as u8
            || !matches!(
                peers.get_peer_identity_type(peer_id),
                Some(PeerIdentityType::Credential)
            )
            || peers.has_route_to_peer(peer_id).await
    }

    async fn start_peer_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let my_peer_id = self.my_peer_id;
        let peers = self.peers.clone();
        let pipe_line = self.peer_packet_process_pipeline.clone();
        let foreign_client = self.foreign_network_client.clone();
        let relay_peer_map = self.relay_peer_map.clone();
        let foreign_mgr = self.foreign_network_manager.clone();
        let acl_filter = self.global_ctx.get_acl_filter().clone();
        let global_ctx = self.global_ctx.clone();
        let stats_mgr = self.global_ctx.stats_manager().clone();
        let route = self.get_route();
        let is_credential_node = self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none();

        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(global_ctx.get_network_name()));

        let self_tx_bytes = self.self_tx_counters.self_tx_bytes.clone();
        let self_tx_packets = self.self_tx_counters.self_tx_packets.clone();
        let self_rx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone());
        let self_rx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsSelfRx, label_set.clone());
        let forward_data_tx_bytes =
            stats_mgr.get_counter(MetricName::TrafficBytesForwarded, label_set.clone());
        let forward_data_tx_packets =
            stats_mgr.get_counter(MetricName::TrafficPacketsForwarded, label_set.clone());
        let forward_control_tx_bytes =
            stats_mgr.get_counter(MetricName::TrafficControlBytesForwarded, label_set.clone());
        let forward_control_tx_packets = stats_mgr.get_counter(
            MetricName::TrafficControlPacketsForwarded,
            label_set.clone(),
        );

        let compress_tx_bytes_before = self.self_tx_counters.compress_tx_bytes_before.clone();
        let compress_tx_bytes_after = self.self_tx_counters.compress_tx_bytes_after.clone();
        let compress_rx_bytes_before =
            stats_mgr.get_counter(MetricName::CompressionBytesRxBefore, label_set.clone());
        let compress_rx_bytes_after =
            stats_mgr.get_counter(MetricName::CompressionBytesRxAfter, label_set.clone());
        let traffic_metrics = self.traffic_metrics.clone();

        self.tasks.lock().await.spawn(async move {
            tracing::trace!("start_peer_recv");
            while let Ok(mut batch) = recv_packet_batch_from_chan(&mut recv).await {
                let mut local_batch = if let Some((from_peer_id, packet_type)) =
                    decoded_local_nic_batch_source(&batch, my_peer_id)
                {
                    if packet_type == PacketType::Ethernet as u8
                        && !Self::credential_ethernet_peer_is_allowed(
                            &peers,
                            packet_type,
                            from_peer_id,
                        )
                        .await
                    {
                        tracing::warn!(
                            from_peer_id,
                            "drop ethernet batch from suppressed credential peer"
                        );
                        continue;
                    }
                    if packet_type == PacketType::Ethernet as u8
                        && !Self::full_ethernet_batch_is_authorized(
                            &peers,
                            None,
                            &global_ctx,
                            my_peer_id,
                            &batch,
                        )
                    {
                        tracing::debug!(
                            from_peer_id,
                            "drop complete Ethernet on a non-bridge node"
                        );
                        continue;
                    }

                    let bytes = batch.buffer_byte_len() as u64;
                    let packets = batch.len() as u64;
                    self_rx_bytes.add(bytes);
                    self_rx_packets.add(packets);
                    compress_rx_bytes_before.add(bytes);
                    compress_rx_bytes_after.add(bytes);
                    traffic_metrics
                        .record_rx_batch(from_peer_id, packet_type, bytes, packets)
                        .await;
                    batch
                } else {
                    let relay_decrypt_outcomes =
                        if Self::relay_batch_should_decrypt(&batch, my_peer_id) {
                            relay_peer_map.decrypt_batch_if_needed(&mut batch)
                        } else {
                            Vec::new()
                        };
                    let mut local_batch = PacketBatch::new();
                    let mut local_rx_bytes = 0_u64;
                    let mut local_rx_packets = 0_u64;
                    let mut compression_rx_before = 0_u64;
                    let mut compression_rx_after = 0_u64;
                    let mut rx_metric_batches: SmallVec<[(PeerId, u8, u64, u64); 4]> =
                        SmallVec::new();
                    for (batch_index, mut ret) in batch.into_iter().enumerate() {
                        let relay_batch_outcome =
                            Self::relay_batch_outcome_at(&relay_decrypt_outcomes, batch_index);
                        if relay_batch_outcome == RelayBatchDecryptOutcome::Failed {
                            tracing::debug!(batch_index, "drop failed relay batch member");
                            continue;
                        }
                        let relay_batch_decrypted =
                            relay_batch_outcome == RelayBatchDecryptOutcome::Decrypted;
                        let Some(header) = ret.peer_manager_header() else {
                            tracing::warn!(?ret, "invalid packet, skip");
                            continue;
                        };
                        let initial_metadata = (
                            header.from_peer_id.get(),
                            header.to_peer_id.get(),
                            header.packet_type,
                            header.is_encrypted(),
                        );
                        if !relay_batch_decrypted
                            && is_foreign_network_packet_type(initial_metadata.2)
                            && initial_metadata.1 == my_peer_id
                            && initial_metadata.3
                        {
                            match relay_peer_map.decrypt_if_needed(&mut ret).await {
                                Ok(true) => {
                                    let _ = ret.refresh_parsed_metadata();
                                }
                                Ok(false) => {
                                    tracing::warn!(
                                        from_peer_id = initial_metadata.0,
                                        "drop foreign packet without a secure relay session"
                                    );
                                    continue;
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        ?error,
                                        from_peer_id = initial_metadata.0,
                                        "foreign packet decryption failed"
                                    );
                                    continue;
                                }
                            }
                        }
                        let handle_foreign_packet =
                            is_foreign_network_packet_type(initial_metadata.2)
                                && (initial_metadata.1 == my_peer_id
                                    || ret.authenticated_peer_id().is_none());
                        let (from_peer_id, to_peer_id, packet_type, is_encrypted) =
                            if handle_foreign_packet {
                                let Err(foreign_packet) = Self::handle_foreign_network_packet(
                                    ret,
                                    my_peer_id,
                                    &peers,
                                    &relay_peer_map,
                                    &foreign_mgr,
                                )
                                .await
                                else {
                                    continue;
                                };
                                ret = foreign_packet;
                                let Some(header) = ret.peer_manager_header() else {
                                    tracing::warn!(?ret, "invalid foreign network packet, skip");
                                    continue;
                                };
                                (
                                    header.from_peer_id.get(),
                                    header.to_peer_id.get(),
                                    header.packet_type,
                                    header.is_encrypted(),
                                )
                            } else {
                                initial_metadata
                            };

                        let buf_len = ret.buf_len();
                        let authenticated_peer_id = ret.authenticated_peer_id();
                        let authorization_peer_id = if from_peer_id == my_peer_id {
                            if authenticated_peer_id.is_some() {
                                tracing::warn!(
                                    authenticated_peer_id,
                                    "drop remote packet that claims the local peer identity"
                                );
                                continue;
                            }
                            my_peer_id
                        } else {
                            let Some(authenticated_peer_id) = authenticated_peer_id else {
                                tracing::warn!(
                                    from_peer_id,
                                    "drop remote packet without authenticated session identity"
                                );
                                continue;
                            };
                            let authenticated_relay_payload =
                                authenticated_peer_id != from_peer_id && is_encrypted;
                            let relay_handshake = authenticated_peer_id != from_peer_id
                                && RelayPeerMap::is_handshake_packet_type(packet_type);
                            let verified_relay_origin = authenticated_peer_id != from_peer_id
                                && ret.verified_origin_peer_id() == Some(from_peer_id)
                                && ret.verified_origin_peer_identity_type().is_some()
                                && ret.verified_origin_peer_secure_auth_level().is_some()
                                && ret.verified_origin_session_id().is_some();
                            if authenticated_peer_id != from_peer_id
                                && !authenticated_relay_payload
                                && !relay_handshake
                                && !verified_relay_origin
                            {
                                tracing::warn!(
                                    authenticated_peer_id,
                                    from_peer_id,
                                    to_peer_id,
                                    packet_type,
                                    is_encrypted,
                                    my_peer_id,
                                    "drop packet with an unauthenticated claimed origin"
                                );
                                continue;
                            }
                            if verified_relay_origin {
                                from_peer_id
                            } else {
                                authenticated_peer_id
                            }
                        };
                        let is_relay_data_packet = if is_foreign_network_packet_type(packet_type) {
                            Self::is_relay_data_zc_packet(&ret)
                        } else {
                            Self::is_relay_data_packet(packet_type)
                        };

                        tracing::trace!(
                            from_peer_id,
                            to_peer_id,
                            packet_type,
                            "peer recv a packet"
                        );
                        if !Self::credential_ethernet_peer_is_allowed(
                            &peers,
                            packet_type,
                            authorization_peer_id,
                        )
                        .await
                        {
                            tracing::warn!(
                                authorization_peer_id,
                                "drop ethernet packet from suppressed credential peer"
                            );
                            continue;
                        }
                        if to_peer_id != my_peer_id {
                            ret.transit_data = is_relay_data_packet && from_peer_id != my_peer_id;

                            let Some(header) = ret.mut_peer_manager_header() else {
                                tracing::warn!(?ret, "invalid forwarded packet, skip");
                                continue;
                            };

                            if header.forward_counter > 7 {
                                tracing::warn!(?header, "forward counter exceed, drop packet");
                                continue;
                            }

                            // Step 10b: credential nodes don't forward handshake packets
                            if is_credential_node
                                && (packet_type == PacketType::HandShake as u8
                                    || packet_type == PacketType::NoiseHandshakeMsg1 as u8
                                    || packet_type == PacketType::NoiseHandshakeMsg2 as u8
                                    || packet_type == PacketType::NoiseHandshakeMsg3 as u8)
                            {
                                tracing::debug!(
                                    "credential node dropping forwarded handshake packet"
                                );
                                continue;
                            }

                            header.forward_counter += 1;

                            if from_peer_id == my_peer_id {
                                compress_tx_bytes_before.add(buf_len as u64);

                                if packet_type == PacketType::Data as u8
                                    || packet_type == PacketType::Ethernet as u8
                                    || packet_type == PacketType::OverlayStream as u8
                                {
                                    Self::prepare_packet(&mut ret);
                                }

                                compress_tx_bytes_after.add(ret.buf_len() as u64);
                                self_tx_bytes.add(ret.buf_len() as u64);
                                self_tx_packets.inc();
                            } else {
                                match traffic_kind(packet_type) {
                                    TrafficKind::Data => {
                                        forward_data_tx_bytes.add(buf_len as u64);
                                        forward_data_tx_packets.inc();
                                    }
                                    TrafficKind::Control => {
                                        forward_control_tx_bytes.add(buf_len as u64);
                                        forward_control_tx_packets.inc();
                                    }
                                }
                            }

                            tracing::trace!(?to_peer_id, ?my_peer_id, "need forward");
                            let tx_metrics = if from_peer_id == my_peer_id {
                                Some(&traffic_metrics)
                            } else {
                                None
                            };
                            let ret = Self::send_msg_internal(
                                &peers,
                                &foreign_client,
                                &relay_peer_map,
                                tx_metrics,
                                ret,
                                to_peer_id,
                            )
                            .await;
                            if ret.is_err() {
                                tracing::error!(
                                    ?ret,
                                    ?to_peer_id,
                                    ?from_peer_id,
                                    "forward packet error"
                                );
                            }
                        } else {
                            if RelayPeerMap::is_handshake_packet_type(packet_type) {
                                if let Err(error) =
                                    relay_peer_map.handle_handshake_packet(ret).await
                                {
                                    tracing::warn!(?error, "relay handshake failed");
                                }
                                continue;
                            }
                            if is_encrypted && !relay_batch_decrypted {
                                match relay_peer_map.decrypt_if_needed(&mut ret).await {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        tracing::error!("secure session not found");
                                        continue;
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            ?e,
                                            from_peer_id,
                                            to_peer_id,
                                            packet_type,
                                            "secure decrypt failed"
                                        );
                                        continue;
                                    }
                                }
                            }

                            if packet_type == PacketType::Ethernet as u8
                                && !Self::full_ethernet_receive_is_authorized(
                                    &peers,
                                    Some(&relay_peer_map),
                                    &global_ctx,
                                    my_peer_id,
                                    &ret,
                                )
                            {
                                tracing::warn!(
                                    from_peer_id,
                                    authenticated_peer_id,
                                    "drop relayed Ethernet without a verified origin proof"
                                );
                                continue;
                            }

                            if RelayPeerMap::is_handshake_confirmation_packet_type(packet_type) {
                                if let Err(error) =
                                    relay_peer_map.handle_handshake_confirmation(ret).await
                                {
                                    tracing::warn!(?error, "relay confirmation failed");
                                }
                                continue;
                            }

                            let logical_origin_authenticated =
                                ret.logical_authenticated_peer_id() == Some(from_peer_id);
                            if logical_origin_authenticated
                                && !Self::credential_ethernet_peer_is_allowed(
                                    &peers,
                                    packet_type,
                                    from_peer_id,
                                )
                                .await
                            {
                                tracing::warn!(
                                    from_peer_id,
                                    "drop ethernet packet from suppressed logical origin"
                                );
                                continue;
                            }

                            local_rx_bytes += buf_len as u64;
                            local_rx_packets += 1;
                            compression_rx_before += buf_len as u64;
                            if let Some((_, _, bytes, packets)) =
                                rx_metric_batches.iter_mut().find(|(peer_id, kind, _, _)| {
                                    *peer_id == from_peer_id && *kind == packet_type
                                })
                            {
                                *bytes += buf_len as u64;
                                *packets += 1;
                            } else {
                                rx_metric_batches.push((
                                    from_peer_id,
                                    packet_type,
                                    buf_len as u64,
                                    1,
                                ));
                            }

                            if ret
                                .peer_manager_header()
                                .is_some_and(|header| header.is_compressed())
                            {
                                tracing::debug!(from_peer_id, "drop unsupported compressed packet");
                                continue;
                            }
                            if packet_type == PacketType::Ethernet as u8 {
                                if !Self::local_bridge_is_authorized(&global_ctx) {
                                    tracing::debug!(
                                        from_peer_id,
                                        "drop complete Ethernet from a hybrid peer"
                                    );
                                    continue;
                                }
                            }

                            compression_rx_after += ret.buf_len() as u64;

                            local_batch
                                .try_push(ret)
                                .expect("the local batch cannot exceed the received batch");
                        }
                    }

                    self_rx_bytes.add(local_rx_bytes);
                    self_rx_packets.add(local_rx_packets);
                    compress_rx_bytes_before.add(compression_rx_before);
                    compress_rx_bytes_after.add(compression_rx_after);
                    for (peer_id, packet_type, bytes, packets) in rx_metric_batches {
                        traffic_metrics
                            .record_rx_batch(peer_id, packet_type, bytes, packets)
                            .await;
                    }

                    local_batch
                };

                local_batch = acl_filter.process_packet_batch_with_acl(
                    local_batch,
                    true,
                    global_ctx.get_ipv4().map(|address| address.address()),
                    |destination| global_ctx.is_ip_local_ipv6(&destination),
                    &route,
                );
                if local_batch.is_empty() {
                    continue;
                }
                tracing::trace!(packets = local_batch.len(), "process peer packet batch");
                let pipelines = pipe_line.read().await;
                for pipeline in pipelines.iter().rev() {
                    if !pipeline.is_interested_in_batch_from_peer(&local_batch) {
                        continue;
                    }
                    local_batch = pipeline.try_process_batch_from_peer(local_batch).await;
                    if local_batch.is_empty() {
                        break;
                    }
                }
                if !local_batch.is_empty() {
                    tracing::error!(packets = local_batch.len(), "unhandled packet batch");
                }
            }
            panic!("done_peer_recv");
        });
    }

    pub async fn add_packet_process_pipeline(&self, pipeline: BoxPeerPacketFilter) {
        // newest pipeline will be executed first
        self.peer_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    pub async fn add_nic_packet_process_pipeline(&self, pipeline: BoxNicPacketFilter) {
        // newest pipeline will be executed first
        self.nic_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    async fn init_packet_process_pipeline(&self) {
        // for tun/tap ip/eth packet.
        enum NicPacketAction {
            Send(ZCPacket),
            Continue(ZCPacket),
            Drop,
        }

        struct NicPacketProcessor {
            nic_channel: PacketRecvChan,
            l2_fabric: Arc<L2Fabric>,
            peers: Arc<PeerMap>,
            relay_peer_map: Arc<RelayPeerMap>,
            global_ctx: ArcGlobalCtx,
            ethernet_input: bool,
            local_bridge_authorized: bool,
            my_peer_id: PeerId,
        }

        impl NicPacketProcessor {
            fn classify_at(&self, packet: ZCPacket, now: std::time::Instant) -> NicPacketAction {
                let hdr = packet.peer_manager_header().unwrap();
                let packet_type = hdr.packet_type;
                let from_peer_id = hdr.from_peer_id.get();
                let is_ethernet = packet_type == PacketType::Ethernet as u8;
                if (packet_type != PacketType::Data as u8 && !is_ethernet)
                    || hdr.is_not_send_to_tun()
                {
                    return NicPacketAction::Continue(packet);
                }
                if is_ethernet && !self.ethernet_input {
                    tracing::debug!(
                        from_peer_id,
                        "dropping ethernet packet because tap input is disabled"
                    );
                    return NicPacketAction::Drop;
                }
                if is_ethernet && !self.local_bridge_authorized {
                    tracing::debug!(
                        from_peer_id,
                        "dropping ethernet packet because local node is not an authorized bridge"
                    );
                    return NicPacketAction::Drop;
                }
                if is_ethernet
                    && !PeerManager::full_ethernet_receive_is_authorized_fast(
                        &self.peers,
                        Some(&self.relay_peer_map),
                        &self.global_ctx,
                        self.my_peer_id,
                        &packet,
                    )
                {
                    tracing::debug!(
                        from_peer_id,
                        "dropping ethernet packet because origin authorization is incomplete"
                    );
                    return NicPacketAction::Drop;
                }
                if hdr.is_encrypted() || hdr.is_compressed() {
                    tracing::warn!(
                        from_peer_id,
                        to_peer_id = hdr.to_peer_id.get(),
                        encrypted = hdr.is_encrypted(),
                        compressed = hdr.is_compressed(),
                        "dropping packet before nic because it is not fully decoded"
                    );
                    return NicPacketAction::Drop;
                }
                if is_ethernet {
                    if !self.l2_fabric.admit_ingress_at(
                        packet.payload(),
                        from_peer_id,
                        self.my_peer_id,
                        now,
                    ) {
                        return NicPacketAction::Drop;
                    }
                } else if self.ethernet_input
                    && !PeerManager::admit_compact_to_tap(
                        &self.l2_fabric,
                        packet.payload(),
                        from_peer_id,
                        &self.global_ctx,
                        now,
                    )
                {
                    return NicPacketAction::Drop;
                }
                NicPacketAction::Send(packet)
            }

            fn classify(&self, packet: ZCPacket) -> NicPacketAction {
                self.classify_at(packet, std::time::Instant::now())
            }
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for NicPacketProcessor {
            fn is_direct_nic_terminal(&self) -> bool {
                true
            }

            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                match self.classify(packet) {
                    NicPacketAction::Send(packet) => {
                        tracing::trace!(?packet, "send packet to nic channel");
                        let _ = self.nic_channel.send(packet).await;
                        None
                    }
                    NicPacketAction::Continue(packet) => Some(packet),
                    NicPacketAction::Drop => None,
                }
            }

            async fn try_process_batch_from_peer(&self, mut batch: PacketBatch) -> PacketBatch {
                let batch_time = std::time::Instant::now();
                if self.local_bridge_authorized
                    && batch.iter().all(|packet| {
                        packet.peer_manager_header().is_some_and(|header| {
                            header.packet_type != PacketType::Ethernet as u8
                                || PeerManager::full_ethernet_receive_is_authorized_fast(
                                    &self.peers,
                                    Some(&self.relay_peer_map),
                                    &self.global_ctx,
                                    self.my_peer_id,
                                    packet,
                                )
                        })
                    })
                    && prepare_direct_nic_batch(&batch, self.ethernet_input, |_, _| {})
                {
                    let mut ingress_batch = L2IngressBatch::default();
                    let keep: SmallVec<[bool; 64]> = batch
                        .iter()
                        .map(|packet| {
                            let header = packet.peer_manager_header().unwrap();
                            if header.packet_type == PacketType::Ethernet as u8 {
                                self.l2_fabric.admit_ingress_batch_at(
                                    packet.payload(),
                                    header.from_peer_id.get(),
                                    self.my_peer_id,
                                    batch_time,
                                    &mut ingress_batch,
                                )
                            } else {
                                !self.ethernet_input
                                    || PeerManager::admit_compact_to_tap(
                                        &self.l2_fabric,
                                        packet.payload(),
                                        header.from_peer_id.get(),
                                        &self.global_ctx,
                                        batch_time,
                                    )
                            }
                        })
                        .collect();
                    batch.retain_flags(&keep);
                    tracing::trace!(
                        packets = batch.len(),
                        "send owned packet batch to nic channel"
                    );
                    if !batch.is_empty() {
                        let _ = self.nic_channel.send_batch(batch).await;
                    }
                    return PacketBatch::new();
                }

                let mut to_nic = PacketBatch::new();
                let mut remaining = PacketBatch::new();
                for packet in batch {
                    match self.classify_at(packet, batch_time) {
                        NicPacketAction::Send(packet) => to_nic
                            .try_push(packet)
                            .expect("a NIC batch cannot exceed its input batch"),
                        NicPacketAction::Continue(packet) => remaining
                            .try_push(packet)
                            .expect("a filtered batch cannot exceed its input batch"),
                        NicPacketAction::Drop => {}
                    }
                }
                if !to_nic.is_empty() {
                    tracing::trace!(packets = to_nic.len(), "send packet batch to nic channel");
                    // The channel is bounded and preserves packet order.
                    let _ = self.nic_channel.send_batch(to_nic).await;
                }
                remaining
            }
        }
        self.add_packet_process_pipeline(Box::new(NicPacketProcessor {
            nic_channel: self.nic_channel.clone(),
            l2_fabric: self.l2_fabric.clone(),
            peers: self.peers.clone(),
            relay_peer_map: self.relay_peer_map.clone(),
            global_ctx: self.global_ctx.clone(),
            ethernet_input: self.global_ctx.get_feature_flags().ethernet_input,
            local_bridge_authorized: Self::local_bridge_is_authorized(&self.global_ctx),
            my_peer_id: self.my_peer_id,
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: RpcIngressSender,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            fn is_interested_in_direct_nic_batch(&self, _batch: &PacketBatch) -> bool {
                false
            }

            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if is_peer_rpc_packet_type(hdr.packet_type) {
                    let packet_type = hdr.packet_type;
                    let from_peer = hdr.from_peer_id.get();
                    let packet_bytes = packet.buf_len();
                    if let Err(error) = self.peer_rpc_tspt_sender.try_send(packet) {
                        let reason = match error {
                            tokio::sync::mpsc::error::TrySendError::Full(_) => "full",
                            tokio::sync::mpsc::error::TrySendError::Closed(_) => "closed",
                        };
                        tracing::trace!(
                            reason,
                            packet_type,
                            from_peer,
                            packet_bytes,
                            "drop peer RPC packet because ingress is unavailable"
                        );
                    }
                    None
                } else {
                    Some(packet)
                }
            }

            async fn try_process_batch_from_peer(&self, batch: PacketBatch) -> PacketBatch {
                if !packet_batch_contains_peer_rpc(&batch) {
                    return batch;
                }

                let mut remaining = PacketBatch::with_capacity(batch.len());
                for packet in batch {
                    let header = packet.peer_manager_header().unwrap();
                    if is_peer_rpc_packet_type(header.packet_type) {
                        let packet_type = header.packet_type;
                        let from_peer = header.from_peer_id.get();
                        let packet_bytes = packet.buf_len();
                        if let Err(error) = self.peer_rpc_tspt_sender.try_send(packet) {
                            let reason = match error {
                                tokio::sync::mpsc::error::TrySendError::Full(_) => "full",
                                tokio::sync::mpsc::error::TrySendError::Closed(_) => "closed",
                            };
                            tracing::trace!(
                                reason,
                                packet_type,
                                from_peer,
                                packet_bytes,
                                "drop peer RPC packet because ingress is unavailable"
                            );
                        }
                    } else {
                        remaining
                            .try_push(packet)
                            .expect("a filtered batch cannot exceed its input batch");
                    }
                }
                remaining
            }
        }
        self.add_packet_process_pipeline(Box::new(PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: self.peer_rpc_tspt.peer_rpc_tspt_sender.clone(),
        }))
        .await;
    }

    pub async fn add_route<T>(&self, route: T)
    where
        T: Route + Send + Sync + Clone + 'static,
    {
        let route_install_lock = self.peers.route_install_lock();
        let _route_install_guard = route_install_lock.lock().await;

        struct Interface {
            my_peer_id: PeerId,
            owner_noise_static_pubkey: Vec<u8>,
            peers: Weak<PeerMap>,
            foreign_network_client: Weak<ForeignNetworkClient>,
            foreign_network_manager: Weak<ForeignNetworkManager>,
            forwarding_snapshot_source: ForwardingDecisionSnapshotSource,
        }

        #[async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let Some(foreign_client) = self.foreign_network_client.upgrade() else {
                    return vec![];
                };

                let Some(peer_map) = self.peers.upgrade() else {
                    return vec![];
                };

                let mut peers = foreign_client.list_public_peers().await;
                peers.extend(peer_map.list_peers_with_conn().await);
                peers
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            fn forwarding_decision_snapshot_source(
                &self,
            ) -> Option<ForwardingDecisionSnapshotSource> {
                Some(self.forwarding_snapshot_source.clone())
            }

            fn publish_origin_auth_batch(
                &self,
                source_token: ForwardingSnapshotSourceToken,
                generation: u64,
                publications: &[OriginAuthPublication],
            ) -> Result<(), super::route_trait::RouteOriginAuthPublishError> {
                if let Some(peer_map) = self.peers.upgrade() {
                    return peer_map.publish_route_origin_auth_batch(
                        source_token,
                        generation,
                        publications,
                    );
                }
                Err(super::route_trait::RouteOriginAuthPublishError::SourceNotRegistered)
            }

            fn discard_origin_auth_batch(
                &self,
                source_token: ForwardingSnapshotSourceToken,
                _generation: u64,
            ) {
                if let Some(peer_map) = self.peers.upgrade() {
                    peer_map.discard_route_source(source_token);
                }
            }

            async fn close_peer(&self, peer_id: PeerId) {
                if let Some(peer_map) = self.peers.upgrade() {
                    let _ = peer_map.close_peer(peer_id).await;
                }

                if let Some(foreign_client) = self.foreign_network_client.upgrade() {
                    let _ = foreign_client.get_peer_map().close_peer(peer_id).await;
                }
            }

            async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
                if let Some(public_key) = self
                    .peers
                    .upgrade()
                    .and_then(|peer_map| peer_map.get_peer_public_key(peer_id))
                {
                    return Some(public_key);
                }

                self.foreign_network_client
                    .upgrade()
                    .and_then(|client| client.get_peer_map().get_peer_public_key(peer_id))
            }

            async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
                let direct_identity = self
                    .peers
                    .upgrade()
                    .and_then(|peer_map| peer_map.get_peer_identity_type(peer_id));
                if let Some(identity_type) = direct_identity {
                    return Some(identity_type);
                }

                self.foreign_network_client
                    .upgrade()
                    .and_then(|client| client.get_peer_map().get_peer_identity_type(peer_id))
            }

            async fn get_authenticated_peer_secure_auth_level(
                &self,
                peer_id: PeerId,
            ) -> Option<SecureAuthLevel> {
                if let Some(level) = self
                    .peers
                    .upgrade()
                    .and_then(|peer_map| peer_map.get_peer_secure_auth_level(peer_id))
                {
                    return Some(level);
                }
                self.foreign_network_client
                    .upgrade()
                    .and_then(|client| client.get_peer_map().get_peer_secure_auth_level(peer_id))
            }

            async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
                let ret = DashMap::new();
                let Some(foreign_mgr) = self.foreign_network_manager.upgrade() else {
                    return ret;
                };

                let networks = foreign_mgr.list_foreign_networks().await;
                for (network_name, info) in networks.foreign_networks.iter() {
                    if info.peers.is_empty() {
                        continue;
                    }

                    let last_update = foreign_mgr
                        .get_foreign_network_last_update(network_name)
                        .unwrap_or(SystemTime::now());
                    ret.insert(
                        ForeignNetworkRouteInfoKey {
                            peer_id: self.my_peer_id,
                            network_name: network_name.clone(),
                        },
                        ForeignNetworkRouteInfoEntry {
                            foreign_peer_ids: info.peers.iter().map(|x| x.peer_id).collect(),
                            last_update: Some(last_update.into()),
                            version: 0,
                            network_secret_digest: info.network_secret_digest.clone(),
                            my_peer_id_for_this_network: info.my_peer_id_for_this_network,
                            owner_noise_static_pubkey: self.owner_noise_static_pubkey.clone(),
                        },
                    );
                }
                ret
            }
        }

        let my_peer_id = self.my_peer_id;
        let owner_noise_static_pubkey = self
            .global_ctx
            .config
            .get_secure_mode()
            .and_then(|secure_mode| secure_mode.public_key().ok())
            .map(|public_key| public_key.as_bytes().to_vec())
            .unwrap_or_default();
        let Ok(forwarding_snapshot_registration) =
            self.peers.begin_forwarding_snapshot_source_registration()
        else {
            tracing::warn!("route source token exhausted; route not installed");
            return;
        };
        self.peers.install_forwarding_snapshot_hook();
        let forwarding_snapshot_source = forwarding_snapshot_registration.source();
        let route_opened = route
            .open(Box::new(Interface {
                my_peer_id,
                owner_noise_static_pubkey,
                peers: Arc::downgrade(&self.peers),
                foreign_network_client: Arc::downgrade(&self.foreign_network_client),
                foreign_network_manager: Arc::downgrade(&self.foreign_network_manager),
                forwarding_snapshot_source,
            }))
            .await;
        if route_opened.is_err() {
            tracing::warn!("route open failed; previous forwarding source restored");
            return;
        }

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route_unlocked(arc_route.clone()).await;
        // Keep the previous snapshot visible until the route vector contains the new route.
        if let Err(error) = forwarding_snapshot_registration.commit() {
            self.peers.remove_route_unlocked(&arc_route).await;
            tracing::warn!(
                ?error,
                "route forwarding snapshot commit failed; route removed"
            );
        }
    }

    pub fn get_route(&self) -> Box<dyn Route + Send + Sync + 'static> {
        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => Box::new(route.clone()),
            RouteAlgoInst::None => Box::new(MockRoute {}),
        }
    }

    pub async fn list_routes(&self) -> Vec<instance::Route> {
        self.get_route().list_routes().await
    }

    pub async fn get_route_peer_info_last_update_time(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }

    pub async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        self.get_route().list_proxy_cidrs().await
    }

    pub async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        self.get_route().list_proxy_cidrs_v6().await
    }

    pub async fn list_public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.get_route().list_public_ipv6_routes().await
    }

    pub async fn get_my_public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.get_route().get_my_public_ipv6_addr().await
    }

    pub async fn get_local_public_ipv6_info(&self) -> instance::ListPublicIpv6InfoResponse {
        self.get_route().get_local_public_ipv6_info().await
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    pub fn replace_local_bgp_routes(&self, routes: Vec<ServiceRoute>) -> u64 {
        let _guard = self.local_bgp_routes_lock.lock();
        self.service_routes.replace_source(RouteSource::Bgp, routes);
        let generation = self
            .local_bgp_route_generation
            .load(Ordering::Relaxed)
            .wrapping_add(1)
            .max(1);
        self.local_bgp_route_generation
            .store(generation, Ordering::Release);
        generation
    }

    pub fn local_bgp_routes_snapshot(&self) -> (Vec<ServiceRoute>, u64) {
        let _guard = self.local_bgp_routes_lock.lock();
        (
            self.service_routes.routes_from(RouteSource::Bgp),
            self.local_bgp_route_generation.load(Ordering::Acquire),
        )
    }

    pub async fn list_global_foreign_network(&self) -> ListGlobalForeignNetworkResponse {
        let mut resp = ListGlobalForeignNetworkResponse::default();
        let ret = self.get_route().list_foreign_network_info().await;
        for info in ret.infos.iter() {
            let entry = resp
                .foreign_networks
                .entry(info.key.as_ref().unwrap().peer_id)
                .or_insert_with(Default::default);
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };

            let f = OneForeignNetwork {
                network_name: info.key.as_ref().unwrap().network_name.clone(),
                peer_ids: route_info.foreign_peer_ids.clone(),
                last_updated: serde_json::to_string(&route_info.last_update.unwrap()).unwrap(),
                version: route_info.version,
            };

            entry.foreign_networks.push(f);
        }

        resp
    }

    pub async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        self.get_route().get_foreign_network_summary().await
    }

    async fn run_nic_packet_process_pipeline_batch(&self, mut batch: PacketBatch) -> PacketBatch {
        let pipelines = self.nic_packet_process_pipeline.read().await;
        for pipeline in pipelines.iter().rev() {
            batch = pipeline.try_process_batch_from_nic(batch).await;
            if batch.is_empty() {
                break;
            }
        }
        for packet in batch.iter_mut() {
            packet.refresh_peer_manager_hdr_len();
        }
        self.global_ctx
            .get_acl_filter()
            .process_packet_batch_with_acl(batch, false, None, |_| false, &self.get_route())
    }

    pub async fn remove_nic_packet_process_pipeline(&self, id: String) -> Result<(), Error> {
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        if let Some(pos) = pipelines.iter().position(|x| x.id() == id) {
            pipelines.remove(pos);
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub(crate) fn get_next_hop_policy(
        header: &crate::tunnel::packet_def::PeerManagerHeader,
    ) -> NextHopPolicy {
        if !Self::is_relay_data_packet(header.packet_type)
            && !is_foreign_network_packet_type(header.packet_type)
            || header.is_foreign_control()
        {
            NextHopPolicy::ControlHop
        } else if header.is_speed_first() {
            NextHopPolicy::MaxGoodput
        } else if header.is_latency_first() {
            NextHopPolicy::LeastCost
        } else {
            NextHopPolicy::LeastHop
        }
    }

    fn check_p2p_only_before_send(&self, dst_peer_id: PeerId) -> Result<(), Error> {
        if self.global_ctx.p2p_only() && !self.peers.has_peer(dst_peer_id) {
            return Err(Error::RouteError(None));
        }
        Ok(())
    }

    fn local_snapshot_next_hop(
        &self,
        snapshot: &ForwardingDecisionSnapshotHandle,
        destination: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        if self.global_ctx.p2p_only() {
            return self.peers.has_peer(destination).then_some(destination);
        }
        snapshot
            .next_hop(destination, policy)
            .map(|hop| hop.next_hop_peer_id)
    }

    pub async fn send_msg_for_proxy(
        &self,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.mark_recent_traffic(dst_peer_id);
        self.check_p2p_only_before_send(dst_peer_id)?;

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        Self::prepare_packet(&mut msg);

        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        apply_local_route_policy(
            &mut msg,
            self.global_ctx.speed_first(),
            self.global_ctx.latency_first(),
        );

        let msg_len = msg.buf_len() as u64;
        let result = Self::send_msg_internal(
            &self.peers,
            &self.foreign_network_client,
            &self.relay_peer_map,
            Some(&self.traffic_metrics),
            msg,
            dst_peer_id,
        )
        .await;
        if result.is_ok() {
            self.self_tx_counters.self_tx_bytes.add(msg_len);
            self.self_tx_counters.self_tx_packets.inc();
        }
        result
    }

    pub(crate) fn only_direct_proxy_conn(&self, dst_peer_id: PeerId) -> Option<Arc<PeerConn>> {
        self.peers.only_direct_conn(dst_peer_id)
    }

    pub(crate) async fn send_msg_for_proxy_on_conn(
        &self,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
        conn: &Arc<PeerConn>,
    ) -> Result<(), Error> {
        self.mark_recent_traffic(dst_peer_id);
        self.check_p2p_only_before_send(dst_peer_id)?;
        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);
        Self::prepare_packet(&mut msg);
        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);
        apply_local_route_policy(
            &mut msg,
            self.global_ctx.speed_first(),
            self.global_ctx.latency_first(),
        );
        let packet_type = msg.peer_manager_header().unwrap().packet_type;
        let msg_len = msg.buf_len() as u64;
        let result = self
            .peers
            .send_msg_on_selected_conn(dst_peer_id, conn, msg)
            .await;
        if result.is_ok() {
            self.self_tx_counters.self_tx_bytes.add(msg_len);
            self.self_tx_counters.self_tx_packets.inc();
            if !self
                .traffic_metrics
                .try_record_tx_batch(dst_peer_id, packet_type, msg_len, 1)
            {
                self.traffic_metrics
                    .record_tx(dst_peer_id, packet_type, msg_len)
                    .await;
            }
        }
        result
    }

    /// Send a complete Ethernet frame through the existing peer, relay, compression, and
    /// encryption stack. Known unicast uses one FDB lookup; unknown and multicast frames are
    /// replicated only to peers that announced TAP capability.
    #[cfg(test)]
    pub async fn send_msg_by_ethernet(&self, msg: ZCPacket) -> Result<(), Error> {
        self.send_fabric_packet(FabricPacket::new(FabricPayloadKind::Ethernet, msg))
            .await
    }

    #[cfg(test)]
    pub async fn send_msg_by_ethernet_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        self.send_fabric_batch(FabricBatch::new(FabricPayloadKind::Ethernet, batch))
            .await
    }

    async fn send_preclassified_ethernet_batch_with_descriptor<I>(
        &self,
        inputs: I,
        descriptor: &PeerMapDataPlaneDescriptor,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = EthernetBatchInput>,
    {
        let forwarding_snapshot = descriptor.forwarding_snapshot.as_ref().ok_or_else(|| {
            Error::RouteError(Some(
                "forwarding decision snapshot is unavailable for complete Ethernet".to_string(),
            ))
        })?;
        let mut per_peer_batches = OrderedPeerBatches::new();
        let origin_auth_snapshot = descriptor.origin_auth_snapshot.as_ref();
        let mut errors = Vec::new();
        let mut flood_peers: Option<Vec<PeerId>> = None;
        let latency_first = self.global_ctx.latency_first();
        let speed_first = self.global_ctx.speed_first();
        let fdb_batch_time = std::time::Instant::now();
        let mut destination_batch = L2DestinationBatch::default();

        for input in inputs {
            let EthernetBatchInput {
                mut packet,
                destination_peer_id,
                is_exit_node,
                suppress_local_delivery,
            } = input;
            let msg = &mut packet;
            let needs_header = msg
                .peer_manager_header()
                .is_none_or(|header| header.packet_type != PacketType::Ethernet as u8);
            if needs_header {
                msg.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
            }
            let header = msg.mut_peer_manager_header().unwrap();
            if let Some(peer_id) = destination_peer_id {
                header.to_peer_id.set(peer_id);
            }
            header.set_exit_node(is_exit_node);
            if suppress_local_delivery {
                header.set_not_send_to_tun(true);
                header.set_no_proxy(true);
            }

            let overridden_dst = msg.peer_manager_header().unwrap().to_peer_id.get();
            if overridden_dst != 0 {
                if !Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    origin_auth_snapshot,
                    forwarding_snapshot,
                    overridden_dst,
                    self.my_peer_id,
                    &self.global_ctx,
                ) {
                    errors.push(Error::RouteError(Some(
                        "complete Ethernet destination is not an authorized bridge".to_string(),
                    )));
                    continue;
                }
                apply_local_route_policy(msg, speed_first, latency_first);
                let next_hop = (overridden_dst == self.my_peer_id)
                    .then_some(overridden_dst)
                    .or_else(|| {
                        self.local_snapshot_next_hop(
                            forwarding_snapshot,
                            overridden_dst,
                            Self::get_next_hop_policy(packet.peer_manager_header().unwrap()),
                        )
                    });
                if next_hop.is_none() {
                    errors.push(Error::RouteError(Some(
                        "snapshot next hop is unavailable".to_string(),
                    )));
                    continue;
                }
                per_peer_batches.push_packet_with_next_hop(
                    overridden_dst,
                    packet,
                    true,
                    Some(next_hop.expect("the complete Ethernet route has a next hop")),
                );
                continue;
            }

            let destination = match destination_batch.resolve_at(
                &self.l2_fabric,
                msg.payload(),
                fdb_batch_time,
            ) {
                Ok(destination) => destination,
                Err(error) => {
                    errors.push(Error::InvalidEthernetFrame(error.to_string()));
                    continue;
                }
            };
            let destination = self.live_l2_destination(destination, descriptor);
            let (dst_peers, known_unicast) = match destination {
                EthernetDestination::Known(peer_id) => (vec![peer_id], true),
                EthernetDestination::Flood => {
                    if flood_peers.is_none() {
                        flood_peers = Some(
                            Self::select_ethernet_peers(
                                forwarding_snapshot.capabilities(),
                                self.my_peer_id,
                            )
                            .into_iter()
                            .filter(|peer_id| {
                                Self::l2_destination_is_live(
                                    descriptor,
                                    *peer_id,
                                    self.my_peer_id,
                                    &self.global_ctx,
                                )
                            })
                            .collect(),
                        );
                    }
                    let peers = flood_peers.as_ref().unwrap().clone();
                    if peers.is_empty() {
                        continue;
                    }
                    (peers, false)
                }
            };

            if dst_peers.iter().any(|peer_id| {
                !Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    origin_auth_snapshot,
                    forwarding_snapshot,
                    *peer_id,
                    self.my_peer_id,
                    &self.global_ctx,
                )
            }) {
                errors.push(Error::RouteError(Some(
                    "complete Ethernet destination is not an authorized bridge".to_string(),
                )));
                continue;
            }

            if !known_unicast
                && let Err(error) = self.reserve_fanout(msg.buf_len(), dst_peers.len())
            {
                errors.push(error);
                continue;
            }

            apply_local_route_policy(msg, speed_first, latency_first);

            let total_dst_peers = dst_peers.len();
            let mut msg = Some(packet);
            for (index, peer_id) in dst_peers.into_iter().enumerate() {
                let mut per_peer_msg = if index + 1 == total_dst_peers {
                    msg.take().unwrap()
                } else {
                    msg.clone().unwrap()
                };
                per_peer_msg
                    .mut_peer_manager_header()
                    .unwrap()
                    .to_peer_id
                    .set(peer_id);
                let next_hop = (peer_id == self.my_peer_id).then_some(peer_id).or_else(|| {
                    self.local_snapshot_next_hop(
                        forwarding_snapshot,
                        peer_id,
                        Self::get_next_hop_policy(per_peer_msg.peer_manager_header().unwrap()),
                    )
                });
                if next_hop.is_none() {
                    errors.push(Error::RouteError(Some(
                        "snapshot next hop is unavailable".to_string(),
                    )));
                    continue;
                }
                per_peer_batches.push_packet_with_next_hop(
                    peer_id,
                    per_peer_msg,
                    known_unicast,
                    Some(next_hop.expect("the complete Ethernet route has a next hop")),
                );
            }
        }

        self.send_ordered_peer_batches(per_peer_batches, &mut errors, Some(descriptor))
            .await?;

        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.pop().expect("one Ethernet delivery error exists")),
            _ => Err(anyhow::anyhow!("ethernet frame delivery failed: {errors:?}").into()),
        }
    }

    async fn record_ordered_send_completion(
        &self,
        completion: OrderedSendCompletion,
        errors: &mut Vec<Error>,
    ) {
        if let Err(error) = completion.result {
            errors.push(error);
            return;
        }
        self.self_tx_counters.self_tx_bytes.add(completion.bytes);
        self.self_tx_counters
            .self_tx_packets
            .add(completion.packets);
        if completion.packet_type == PacketType::Data as u8 {
            self.self_tx_counters.compact_l3_bytes.add(completion.bytes);
            self.self_tx_counters
                .compact_l3_packets
                .add(completion.packets);
        } else if completion.hybrid_ip_ethernet {
            self.self_tx_counters
                .full_ethernet_bytes
                .add(completion.bytes);
            self.self_tx_counters
                .full_ethernet_packets
                .add(completion.packets);
        }
        if completion.record_metrics
            && !self.traffic_metrics.try_record_tx_batch(
                completion.peer_id,
                completion.packet_type,
                completion.bytes,
                completion.packets,
            )
        {
            self.traffic_metrics
                .record_tx_batch(
                    completion.peer_id,
                    completion.packet_type,
                    completion.bytes,
                    completion.packets,
                )
                .await;
        }
    }

    async fn send_ordered_peer_batches(
        &self,
        peer_batches: OrderedPeerBatches,
        errors: &mut Vec<Error>,
        full_ethernet_descriptor: Option<&PeerMapDataPlaneDescriptor>,
    ) -> Result<(), Error> {
        let single_peer_batch = peer_batches.batches.len() == 1;
        let mut pending: FuturesUnordered<
            Pin<Box<dyn Future<Output = OrderedSendCompletion> + Send>>,
        > = FuturesUnordered::new();

        for peer_batch in peer_batches {
            let OrderedPeerBatch {
                peer_id,
                next_hop,
                packets: peer_batch,
                mark_recent,
            } = peer_batch;
            if mark_recent {
                self.mark_recent_traffic(peer_id);
            }
            if let Err(error) = self.check_p2p_only_before_send(peer_id) {
                errors.push(error);
                continue;
            }
            let prepared = match prepare_packet_batch(peer_batch) {
                Ok(prepared) => prepared,
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            };
            if prepared.contains_ethernet {
                let Some(descriptor) = full_ethernet_descriptor else {
                    errors.push(Error::RouteError(Some(
                        "complete Ethernet snapshot is unavailable".to_string(),
                    )));
                    continue;
                };
                let Some(snapshot) = descriptor.forwarding_snapshot.as_ref() else {
                    errors.push(Error::RouteError(Some(
                        "forwarding decision snapshot is unavailable for complete Ethernet"
                            .to_string(),
                    )));
                    continue;
                };
                if !Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    descriptor.origin_auth_snapshot.as_ref(),
                    snapshot,
                    peer_id,
                    self.my_peer_id,
                    &self.global_ctx,
                ) {
                    errors.push(Error::RouteError(Some(
                        "complete Ethernet destination is not an authorized bridge".to_string(),
                    )));
                    continue;
                }
                if !Self::credential_ethernet_peer_is_allowed(
                    &self.peers,
                    PacketType::Ethernet as u8,
                    peer_id,
                )
                .await
                {
                    tracing::warn!(peer_id, "block suppressed credential ethernet peer");
                    errors.push(Error::RouteError(None));
                    continue;
                }
            }
            self.self_tx_counters
                .compress_tx_bytes_before
                .add(prepared.bytes_before);
            self.self_tx_counters
                .compress_tx_bytes_after
                .add(prepared.bytes_after);
            let prepared_bytes = prepared.bytes_after;
            let first_packet_type = prepared.first_packet_type;
            let first_is_hybrid_ip_ethernet = prepared.first_is_hybrid_ip_ethernet;
            let uniform_direct_priority = prepared.uniform_direct_priority;
            let peer_batch = prepared.batch;

            if single_peer_batch && uniform_direct_priority {
                let first_header = peer_batch
                    .first()
                    .and_then(|packet| packet.peer_manager_header());
                let transport_peer = next_hop.unwrap_or(peer_id);
                let direct_conn = first_header
                    .filter(|header| {
                        direct_selected_conn_allowed(peer_id, next_hop, header.is_latency_first())
                    })
                    .and_then(|_| self.peers.only_direct_conn(transport_peer));
                if let Some(conn) = direct_conn {
                    if first_packet_type == PacketType::Ethernet as u8 {
                        let Some(descriptor) = full_ethernet_descriptor else {
                            errors.push(Error::RouteError(Some(
                                "complete Ethernet snapshot is unavailable".to_string(),
                            )));
                            continue;
                        };
                        let current_descriptor = self.peers.dataplane_descriptor();
                        if !self.full_ethernet_descriptor_is_current(
                            descriptor,
                            &current_descriptor,
                            &[peer_id],
                        ) {
                            errors.push(Error::RouteError(Some(
                                "complete Ethernet authority changed before dispatch".to_string(),
                            )));
                            continue;
                        }
                    }
                    let completion = OrderedSendCompletion {
                        bytes: prepared_bytes,
                        packets: peer_batch.len() as u64,
                        result: self
                            .peers
                            .send_prepared_msg_batch_on_selected_conn(
                                transport_peer,
                                &conn,
                                peer_batch,
                            )
                            .await,
                        peer_id,
                        packet_type: first_packet_type,
                        hybrid_ip_ethernet: first_is_hybrid_ip_ethernet,
                        record_metrics: true,
                    };
                    self.record_ordered_send_completion(completion, errors)
                        .await;
                    continue;
                }
            }

            let mut relay_batches = Vec::<(PeerId, Option<PeerId>, u8, PacketBatch)>::new();
            let mut relay_inline_indexes =
                SmallVec::<[((PeerId, Option<PeerId>, u8, u8, u8), usize); 4]>::new();
            let mut relay_indexes = None::<HashMap<(PeerId, Option<PeerId>, u8, u8, u8), usize>>;
            let mut selected_batches = Vec::<(PeerId, u8, Arc<PeerConn>, PacketBatch)>::new();
            let mut selected_inline_indexes =
                SmallVec::<[((PeerId, PeerConnId, u8, u8, u8), usize); 4]>::new();
            let mut selected_indexes = None::<HashMap<(PeerId, PeerConnId, u8, u8, u8), usize>>;
            for (flow, flow_batch) in partition_packet_batch_by_flow(peer_batch) {
                let Some(first) = flow_batch.first() else {
                    continue;
                };
                let Some(header) = first.peer_manager_header() else {
                    errors.push(Error::RouteError(Some(
                        "packet without peer manager header".to_owned(),
                    )));
                    continue;
                };
                let packet_type = header.packet_type;
                if packet_type == PacketType::Ethernet as u8 {
                    let Some(descriptor) = full_ethernet_descriptor else {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet snapshot is unavailable".to_string(),
                        )));
                        continue;
                    };
                    let Some(snapshot) = descriptor.forwarding_snapshot.as_ref() else {
                        errors.push(Error::RouteError(Some(
                            "forwarding decision snapshot is unavailable for complete Ethernet"
                                .to_string(),
                        )));
                        continue;
                    };
                    if !Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                        descriptor.origin_auth_snapshot.as_ref(),
                        snapshot,
                        peer_id,
                        self.my_peer_id,
                        &self.global_ctx,
                    ) {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet destination is not an authorized bridge".to_string(),
                        )));
                        continue;
                    }
                }

                let transport_peer = next_hop.unwrap_or(peer_id);
                let selected_conn =
                    if direct_selected_conn_allowed(peer_id, next_hop, header.is_latency_first()) {
                        self.peers.select_direct_conn_for_flow(
                            transport_peer,
                            Self::get_next_hop_policy(header),
                            flow.hash,
                        )
                    } else {
                        None
                    };
                if let Some(conn) = selected_conn {
                    let key = direct_batch_group_key(transport_peer, conn.get_conn_id(), header);
                    if let Some(index) = lazy_batch_group_index(
                        key,
                        selected_batches.len(),
                        &mut selected_inline_indexes,
                        &mut selected_indexes,
                    ) {
                        for packet in flow_batch {
                            selected_batches[index]
                                .3
                                .try_push(packet)
                                .expect("selected groups remain within the ingress batch bound");
                        }
                    } else {
                        selected_batches.push((transport_peer, packet_type, conn, flow_batch));
                    }
                } else {
                    let policy_bits = u8::from(header.is_speed_first())
                        | (u8::from(header.is_latency_first()) << 1)
                        | (u8::from(header.is_critical_l2_control()) << 2);
                    let key = (peer_id, next_hop, packet_type, policy_bits, header.flags);
                    if let Some(index) = lazy_batch_group_index(
                        key,
                        relay_batches.len(),
                        &mut relay_inline_indexes,
                        &mut relay_indexes,
                    ) {
                        for packet in flow_batch {
                            relay_batches[index]
                                .3
                                .try_push(packet)
                                .expect("relay groups remain within the ingress batch bound");
                        }
                    } else {
                        relay_batches.push((peer_id, next_hop, packet_type, flow_batch));
                    }
                }
            }

            for (transport_peer, packet_type, conn, flow_batch) in selected_batches {
                let hybrid_ip_ethernet = flow_batch
                    .first()
                    .and_then(|packet| packet.peer_manager_header())
                    .is_some_and(|header| header.is_hybrid_ip_ethernet());
                if packet_type == PacketType::Ethernet as u8 {
                    let Some(prepared_descriptor) = full_ethernet_descriptor else {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet snapshot is unavailable".to_string(),
                        )));
                        continue;
                    };
                    let current_descriptor = self.peers.dataplane_descriptor();
                    if !self.full_ethernet_descriptor_is_current(
                        prepared_descriptor,
                        &current_descriptor,
                        &[peer_id],
                    ) {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet authority changed before dispatch".to_string(),
                        )));
                        continue;
                    }
                }
                let bytes = flow_batch.buffer_byte_len() as u64;
                let packets = flow_batch.len() as u64;
                let peers = self.peers.clone();
                let full_ethernet_descriptor = full_ethernet_descriptor.cloned();
                pending.push(Box::pin(async move {
                    if packet_type == PacketType::Ethernet as u8 {
                        let Some(descriptor) = full_ethernet_descriptor.as_ref() else {
                            return OrderedSendCompletion {
                                result: Err(Error::RouteError(Some(
                                    "complete Ethernet snapshot is unavailable".to_string(),
                                ))),
                                peer_id,
                                packet_type,
                                hybrid_ip_ethernet,
                                bytes: 0,
                                packets: 0,
                                record_metrics: false,
                            };
                        };
                        let current_descriptor = peers.dataplane_descriptor();
                        if !PeerManager::full_ethernet_descriptor_is_current_for_destination(
                            descriptor,
                            current_descriptor.as_ref(),
                            peer_id,
                            peers.my_peer_id(),
                            &peers.get_global_ctx(),
                        ) {
                            return OrderedSendCompletion {
                                result: Err(Error::RouteError(Some(
                                    "complete Ethernet authority changed before direct send"
                                        .to_string(),
                                ))),
                                peer_id,
                                packet_type,
                                hybrid_ip_ethernet,
                                bytes: 0,
                                packets: 0,
                                record_metrics: false,
                            };
                        }
                    }
                    let result = peers
                        .send_prepared_msg_batch_on_selected_conn(transport_peer, &conn, flow_batch)
                        .await;
                    OrderedSendCompletion {
                        result,
                        peer_id,
                        packet_type,
                        hybrid_ip_ethernet,
                        bytes,
                        packets,
                        record_metrics: true,
                    }
                }));
                if pending.len() >= MAX_ORDERED_SEND_CONCURRENCY
                    && let Some(completion) = pending.next().await
                {
                    self.record_ordered_send_completion(completion, errors)
                        .await;
                }
            }

            for (peer_id, next_hop, packet_type, flow_batch) in relay_batches {
                let hybrid_ip_ethernet = flow_batch
                    .first()
                    .and_then(|packet| packet.peer_manager_header())
                    .is_some_and(|header| header.is_hybrid_ip_ethernet());
                if packet_type == PacketType::Ethernet as u8 {
                    let Some(prepared_descriptor) = full_ethernet_descriptor else {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet snapshot is unavailable".to_string(),
                        )));
                        continue;
                    };
                    let current_descriptor = self.peers.dataplane_descriptor();
                    if !self.full_ethernet_descriptor_is_current(
                        prepared_descriptor,
                        &current_descriptor,
                        &[peer_id],
                    ) {
                        errors.push(Error::RouteError(Some(
                            "complete Ethernet authority changed before dispatch".to_string(),
                        )));
                        continue;
                    }
                }
                let bytes = flow_batch.buffer_byte_len() as u64;
                let packets = flow_batch.len() as u64;
                let peers = self.peers.clone();
                let foreign_network_client = self.foreign_network_client.clone();
                let relay_peer_map = self.relay_peer_map.clone();
                let traffic_metrics = self.traffic_metrics.clone();
                let full_ethernet_descriptor = full_ethernet_descriptor.cloned();
                let authorization = (packet_type == PacketType::Ethernet as u8)
                    .then(|| {
                        full_ethernet_descriptor.as_ref().map(|descriptor| {
                            FullEthernetAuthorizationToken::from_descriptor(descriptor, peer_id)
                        })
                    })
                    .flatten();
                pending.push(Box::pin(async move {
                    if packet_type == PacketType::Ethernet as u8 {
                        let Some(descriptor) = full_ethernet_descriptor.as_ref() else {
                            return OrderedSendCompletion {
                                result: Err(Error::RouteError(Some(
                                    "complete Ethernet snapshot is unavailable".to_string(),
                                ))),
                                peer_id,
                                packet_type,
                                hybrid_ip_ethernet,
                                bytes: 0,
                                packets: 0,
                                record_metrics: false,
                            };
                        };
                        let current_descriptor = peers.dataplane_descriptor();
                        if !PeerManager::full_ethernet_descriptor_is_current_for_destination(
                            descriptor,
                            current_descriptor.as_ref(),
                            peer_id,
                            peers.my_peer_id(),
                            &peers.get_global_ctx(),
                        ) {
                            return OrderedSendCompletion {
                                result: Err(Error::RouteError(Some(
                                    "complete Ethernet authority changed before relay send"
                                        .to_string(),
                                ))),
                                peer_id,
                                packet_type,
                                hybrid_ip_ethernet,
                                bytes: 0,
                                packets: 0,
                                record_metrics: false,
                            };
                        }
                    }
                    let result = if let Some(next_hop) = next_hop {
                        PeerManager::send_msg_internal_batch_with_next_hop_authorized(
                            &peers,
                            &foreign_network_client,
                            &relay_peer_map,
                            Some(&traffic_metrics),
                            flow_batch,
                            peer_id,
                            next_hop,
                            authorization.clone(),
                        )
                        .await
                    } else {
                        PeerManager::send_msg_internal_batch_authorized(
                            &peers,
                            &foreign_network_client,
                            &relay_peer_map,
                            Some(&traffic_metrics),
                            flow_batch,
                            peer_id,
                            authorization.clone(),
                        )
                        .await
                    };
                    OrderedSendCompletion {
                        result,
                        peer_id,
                        packet_type,
                        hybrid_ip_ethernet,
                        bytes,
                        packets,
                        record_metrics: false,
                    }
                }));
                if pending.len() >= MAX_ORDERED_SEND_CONCURRENCY
                    && let Some(completion) = pending.next().await
                {
                    self.record_ordered_send_completion(completion, errors)
                        .await;
                }
            }
        }

        while let Some(completion) = pending.next().await {
            self.record_ordered_send_completion(completion, errors)
                .await;
        }
        Ok(())
    }

    async fn send_msg_internal(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        Self::send_msg_internal_authorized(
            peers,
            foreign_network_client,
            relay_peer_map,
            direct_tx_metrics,
            msg,
            dst_peer_id,
            None,
        )
        .await
    }

    async fn send_msg_internal_authorized(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<(), Error> {
        let policy = Self::get_next_hop_policy(msg.peer_manager_header().unwrap());
        let packet_type = msg.peer_manager_header().unwrap().packet_type;
        if packet_type == PacketType::Ethernet as u8
            && !Self::full_ethernet_destination_is_authorized(peers, dst_peer_id).await
        {
            tracing::warn!(
                dst_peer_id,
                "block complete Ethernet to an unauthorized bridge"
            );
            return Err(Error::RouteError(Some(
                "complete Ethernet destination is not an authorized bridge".to_string(),
            )));
        }
        if !Self::credential_ethernet_peer_is_allowed(peers, packet_type, dst_peer_id).await {
            tracing::warn!(dst_peer_id, "block suppressed credential ethernet peer");
            return Err(Error::RouteError(None));
        }
        let msg_len = msg.buf_len() as u64;
        let latency_first_gateway = {
            peers
                .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), &msg)
                .await
                .filter(|gateway| *gateway != dst_peer_id)
        };
        let send_result = if let Some(gateway) = latency_first_gateway
            && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
        {
            relay_peer_map
                .send_msg_with_next_hop_authorized(
                    msg,
                    dst_peer_id,
                    policy,
                    None,
                    authorization.clone(),
                )
                .await
        } else if peers.has_peer(dst_peer_id) {
            peers.send_msg_directly(msg, dst_peer_id).await
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            relay_peer_map
                .send_msg_with_next_hop_authorized(
                    msg,
                    dst_peer_id,
                    policy,
                    None,
                    authorization.clone(),
                )
                .await
        } else if let Some(gateway) = peers
            .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), &msg)
            .await
        {
            if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
                relay_peer_map
                    .send_msg_with_next_hop_authorized(
                        msg,
                        dst_peer_id,
                        policy,
                        None,
                        authorization.clone(),
                    )
                    .await
            } else {
                tracing::warn!(
                    ?gateway,
                    ?dst_peer_id,
                    "cannot send msg to peer through gateway"
                );
                Err(Error::RouteError(None))
            }
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            // Check the foreign network again to avoid another lookup on the common path.
            relay_peer_map
                .send_msg_with_next_hop_authorized(msg, dst_peer_id, policy, None, authorization)
                .await
        } else {
            tracing::debug!(?dst_peer_id, "no gateway for peer");
            Err(Error::RouteError(None))
        };

        if send_result.is_ok()
            && let Some(metrics) = direct_tx_metrics
        {
            if !metrics.try_record_tx_batch(dst_peer_id, packet_type, msg_len, 1) {
                metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
            }
        }

        send_result
    }

    async fn send_msg_internal_batch_authorized(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<(), Error> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        let header = first.peer_manager_header().unwrap();
        let packet_type = header.packet_type;
        if packet_type == PacketType::Ethernet as u8
            && !Self::full_ethernet_destination_is_authorized(peers, dst_peer_id).await
        {
            tracing::warn!(
                dst_peer_id,
                "block complete Ethernet batch to an unauthorized bridge"
            );
            return Err(Error::RouteError(Some(
                "complete Ethernet destination is not an authorized bridge".to_string(),
            )));
        }
        if !Self::credential_ethernet_peer_is_allowed(peers, packet_type, dst_peer_id).await {
            tracing::warn!(dst_peer_id, "block suppressed credential ethernet peer");
            return Err(Error::RouteError(None));
        }
        let policy = Self::get_next_hop_policy(header);
        let bytes = batch.buffer_byte_len() as u64;
        let packets = batch.len() as u64;
        let latency_first_gateway = {
            peers
                .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), first)
                .await
                .filter(|gateway| *gateway != dst_peer_id)
        };

        let send_result = if let Some(gateway) = latency_first_gateway
            && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
        {
            relay_peer_map
                .send_msg_batch_with_next_hop_authorized(
                    batch,
                    dst_peer_id,
                    policy,
                    None,
                    authorization.clone(),
                )
                .await
        } else if peers.has_peer(dst_peer_id) {
            peers.send_msg_batch_directly(batch, dst_peer_id).await
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            relay_peer_map
                .send_msg_batch_with_next_hop_authorized(
                    batch,
                    dst_peer_id,
                    policy,
                    None,
                    authorization.clone(),
                )
                .await
        } else if let Some(gateway) = peers
            .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), first)
            .await
        {
            if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
                relay_peer_map
                    .send_msg_batch_with_next_hop_authorized(
                        batch,
                        dst_peer_id,
                        policy,
                        None,
                        authorization.clone(),
                    )
                    .await
            } else {
                Err(Error::RouteError(None))
            }
        } else {
            Err(Error::RouteError(None))
        };

        if send_result.is_ok()
            && let Some(metrics) = direct_tx_metrics
        {
            if !metrics.try_record_tx_batch(dst_peer_id, packet_type, bytes, packets) {
                metrics
                    .record_tx_batch(dst_peer_id, packet_type, bytes, packets)
                    .await;
            }
        }
        send_result
    }

    async fn send_msg_internal_batch_with_next_hop_authorized(
        peers: &Arc<PeerMap>,
        _foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        next_hop: PeerId,
        authorization: Option<FullEthernetAuthorizationToken>,
    ) -> Result<(), Error> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        let header = first
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let policy = Self::get_next_hop_policy(header);
        let packet_type = header.packet_type;
        if packet_type == PacketType::Ethernet as u8
            && !Self::full_ethernet_destination_is_authorized(peers, dst_peer_id).await
        {
            tracing::warn!(
                dst_peer_id,
                "block complete Ethernet batch to an unauthorized bridge"
            );
            return Err(Error::RouteError(Some(
                "complete Ethernet destination is not an authorized bridge".to_string(),
            )));
        }
        if !Self::credential_ethernet_peer_is_allowed(peers, packet_type, dst_peer_id).await {
            return Err(Error::RouteError(None));
        }
        let bytes = batch.buffer_byte_len() as u64;
        let packets = batch.len() as u64;
        let send_result = if next_hop == dst_peer_id && peers.has_peer(next_hop) {
            peers.send_msg_batch_directly(batch, next_hop).await
        } else {
            relay_peer_map
                .send_msg_batch_with_next_hop_authorized(
                    batch,
                    dst_peer_id,
                    policy,
                    Some(next_hop),
                    authorization,
                )
                .await
        };
        if send_result.is_ok()
            && let Some(metrics) = direct_tx_metrics
        {
            if !metrics.try_record_tx_batch(dst_peer_id, packet_type, bytes, packets) {
                metrics
                    .record_tx_batch(dst_peer_id, packet_type, bytes, packets)
                    .await;
            }
        }
        send_result
    }

    pub async fn get_msg_dst_peer(&self, addr: &IpAddr) -> (Vec<PeerId>, bool) {
        match addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(ipv6_addr).await,
        }
    }

    fn is_all_peers_broadcast_ipv4(&self, ipv4_addr: &Ipv4Addr) -> bool {
        ipv4_addr.is_broadcast()
            || ipv4_addr.is_multicast()
            || self
                .global_ctx
                .get_ipv4()
                .is_some_and(|network| *ipv4_addr == network.last_address())
    }

    fn is_all_peers_broadcast_ipv6(&self, ipv6_addr: &Ipv6Addr) -> bool {
        ipv6_addr.is_multicast()
    }

    fn select_ipv4_broadcast_peers(
        routes: &ForwardingPeerTable,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        routes
            .ipv4_peers()
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != my_peer_id)
            .collect()
    }

    fn select_ip_multicast_peers(
        routes: &ForwardingPeerTable,
        my_peer_id: PeerId,
        address: IpAddr,
    ) -> Vec<PeerId> {
        routes
            .multicast_peers(address)
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != my_peer_id)
            .collect()
    }

    fn select_ethernet_peers(routes: &ForwardingPeerTable, my_peer_id: PeerId) -> Vec<PeerId> {
        routes
            .ethernet_peers()
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != my_peer_id)
            .collect()
    }

    fn route_requires_full_ethernet(route: &ForwardingPeerInfo, my_peer_id: PeerId) -> bool {
        route.peer_id != my_peer_id
            && route.feature_flag.as_ref().is_some_and(|features| {
                features.ethernet_input
                    && features.bridge_input
                    && !features.hybrid_l3
                    && route.bridge_authorized
                    && route
                        .bridge_authorization_deadline
                        .is_none_or(|deadline| deadline > Instant::now())
            })
    }

    /// Rebuild a complete Ethernet frame in the owned packet buffer.
    ///
    /// The caller must pass ownership when no compact representation is needed.
    /// This avoids allocating a second packet and avoids copying the IP payload into a new
    /// vector. A clone remains necessary when compact and complete representations coexist.
    fn rebuild_ethernet_from_accepted_ip_owned(
        mut ip_packet: ZCPacket,
        ethernet_header: &[u8],
    ) -> Result<ZCPacket, Error> {
        if ethernet_header.len() < crate::instance::l2_tun::ETHERNET_HEADER_LEN {
            return Err(Error::InvalidEthernetFrame(
                "Ethernet header is shorter than 14 bytes".to_string(),
            ));
        }
        let ethernet_header = &ethernet_header[..crate::instance::l2_tun::ETHERNET_HEADER_LEN];
        if !ip_packet.restore_payload_prefix_from_reusable_headroom(ethernet_header) {
            ip_packet
                .prepend_payload_preserving_flow_hash(
                    &[0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN],
                )
                .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))?;
            ip_packet
                .mut_payload_preserving_flow_hash()
                .get_mut(..crate::instance::l2_tun::ETHERNET_HEADER_LEN)
                .ok_or_else(|| {
                    Error::InvalidEthernetFrame("Ethernet headroom is unavailable".to_string())
                })?
                .copy_from_slice(ethernet_header);
        }
        Ok(ip_packet)
    }

    fn ensure_ethernet_headroom(packet: &mut ZCPacket) -> Result<(), Error> {
        if packet.restore_payload_prefix_from_reusable_headroom(
            &[0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN],
        ) {
            return Ok(());
        }
        packet
            .prepend_payload_preserving_flow_hash(
                &[0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN],
            )
            .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))
    }

    fn hybrid_compact_unicast_peer(
        &self,
        candidate_peers: &[PeerId],
        ip_addr: IpAddr,
        snapshot: &ForwardingDecisionSnapshotHandle,
    ) -> Option<PeerId> {
        if candidate_peers.len() != 1 || ip_addr.is_multicast() {
            return None;
        }
        let is_broadcast = match ip_addr {
            IpAddr::V4(address) => self.is_all_peers_broadcast_ipv4(&address),
            IpAddr::V6(address) => self.is_all_peers_broadcast_ipv6(&address),
        };
        if is_broadcast {
            return None;
        }

        let peer_id = candidate_peers[0];
        if peer_id == self.my_peer_id {
            return Some(peer_id);
        }
        snapshot.capabilities().get(peer_id).and_then(|route| {
            (Self::route_accepts_compact_ip(route)
                && !Self::route_requires_full_ethernet(route, self.my_peer_id))
            .then_some(peer_id)
        })
    }

    fn hybrid_recipient_sets(
        &self,
        candidate_peers: Vec<PeerId>,
        is_exit_node: bool,
        ip_addr: IpAddr,
        snapshot: &ForwardingDecisionSnapshotHandle,
        fdb_destination: Option<EthernetDestination>,
        allow_bridge_fallback: bool,
    ) -> HybridRecipientSets {
        let is_multicast = ip_addr.is_multicast();
        let is_broadcast = match ip_addr {
            IpAddr::V4(address) => self.is_all_peers_broadcast_ipv4(&address),
            IpAddr::V6(address) => self.is_all_peers_broadcast_ipv6(&address),
        };
        let routes = snapshot.capabilities();
        let mut candidate_peers = candidate_peers;
        let mut bridge_fallback = false;
        let mut targeted_bridge = None;
        if candidate_peers.is_empty() && !is_multicast && !is_broadcast {
            if let Some(EthernetDestination::Known(peer_id)) = fdb_destination
                && routes.is_authorized_bridge(peer_id)
            {
                candidate_peers.push(peer_id);
                targeted_bridge = Some(peer_id);
            } else if allow_bridge_fallback {
                candidate_peers = routes.ethernet_peers();
                bridge_fallback = true;
            }
        }

        let full_peers = if is_multicast {
            routes
                .ethernet_multicast_peers(ip_addr)
                .into_iter()
                .filter(|peer_id| *peer_id != self.my_peer_id)
                .collect()
        } else if is_broadcast {
            routes.ethernet_peers()
        } else if targeted_bridge.is_some() {
            candidate_peers.clone()
        } else if bridge_fallback {
            routes
                .ethernet_peers()
                .into_iter()
                .filter(|peer_id| *peer_id != self.my_peer_id)
                .collect()
        } else {
            candidate_peers
                .iter()
                .copied()
                .filter(|peer_id| {
                    routes.get(*peer_id).is_some_and(|route| {
                        Self::route_requires_full_ethernet(route, self.my_peer_id)
                    })
                })
                .collect()
        };
        let compact_peers = candidate_peers
            .iter()
            .copied()
            .filter(|peer_id| {
                full_peers.binary_search(peer_id).is_err()
                    && targeted_bridge != Some(*peer_id)
                    && (*peer_id == self.my_peer_id
                        || routes
                            .get(*peer_id)
                            .is_some_and(|route| Self::route_accepts_compact_ip(route)))
            })
            .collect();
        HybridRecipientSets {
            compact_peers,
            full_peers,
            is_exit_node,
            is_multicast,
            is_broadcast,
            bridge_fallback,
        }
    }

    pub(crate) fn full_ethernet_descriptor_is_current_for_destination(
        prepared: &PeerMapDataPlaneDescriptor,
        current: &PeerMapDataPlaneDescriptor,
        destination_peer_id: PeerId,
        my_peer_id: PeerId,
        global_ctx: &ArcGlobalCtx,
    ) -> bool {
        if prepared.source_token != current.source_token
            || prepared.origin_auth_snapshot.auth_generation
                != current.origin_auth_snapshot.auth_generation
            || prepared.route_trust.source_token != current.route_trust.source_token
            || prepared.route_trust.generation != current.route_trust.generation
            || prepared
                .forwarding_snapshot
                .as_ref()
                .map(|snapshot| snapshot.generation())
                != current
                    .forwarding_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.generation())
        {
            return false;
        }
        let Some(current_snapshot) = current.forwarding_snapshot.as_ref() else {
            return false;
        };
        let Some(prepared_snapshot) = prepared.forwarding_snapshot.as_ref() else {
            return false;
        };
        prepared.origin_auth_snapshot.lookup(destination_peer_id)
            == current.origin_auth_snapshot.lookup(destination_peer_id)
            && prepared.origin_auth_snapshot.lookup_grant(
                destination_peer_id,
                OriginAuthCapability::FullEthernetBridge,
            ) == current.origin_auth_snapshot.lookup_grant(
                destination_peer_id,
                OriginAuthCapability::FullEthernetBridge,
            )
            && prepared.route_trust.generic.get(&destination_peer_id)
                == current.route_trust.generic.get(&destination_peer_id)
            && prepared.route_trust.bridge.get(&(
                destination_peer_id,
                OriginAuthCapability::FullEthernetBridge,
            )) == current.route_trust.bridge.get(&(
                destination_peer_id,
                OriginAuthCapability::FullEthernetBridge,
            ))
            && Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                current.origin_auth_snapshot.as_ref(),
                current_snapshot,
                destination_peer_id,
                my_peer_id,
                global_ctx,
            )
            && Self::snapshot_allows_full_ethernet_destination(
                prepared_snapshot,
                destination_peer_id,
                my_peer_id,
                global_ctx,
            )
    }

    fn full_ethernet_descriptor_is_current(
        &self,
        prepared: &PeerMapDataPlaneDescriptor,
        current: &PeerMapDataPlaneDescriptor,
        destination_peers: &[PeerId],
    ) -> bool {
        destination_peers.iter().all(|destination_peer_id| {
            Self::full_ethernet_descriptor_is_current_for_destination(
                prepared,
                current,
                *destination_peer_id,
                self.my_peer_id,
                &self.global_ctx,
            )
        })
    }

    fn append_hybrid_ordered_peer_packets(
        &self,
        peer_batches: &mut OrderedPeerBatches,
        mut packet: ZCPacket,
        destination_peers: &[PeerId],
        is_exit_node: bool,
        suppress_local_delivery: bool,
        snapshot: &ForwardingDecisionSnapshotHandle,
        mark_recent: bool,
    ) -> Result<(), Error> {
        if destination_peers.is_empty() {
            return Ok(());
        }
        apply_local_route_policy(
            &mut packet,
            self.global_ctx.speed_first(),
            self.global_ctx.latency_first(),
        );
        let mut packet = Some(packet);
        for (index, peer_id) in destination_peers.iter().copied().enumerate() {
            let mut peer_packet = if index + 1 == destination_peers.len() {
                packet
                    .take()
                    .expect("the final hybrid recipient owns the packet")
            } else {
                packet
                    .as_ref()
                    .expect("the hybrid recipient packet remains available")
                    .clone()
            };
            let header = peer_packet.mut_peer_manager_header().ok_or_else(|| {
                Error::RouteError(Some("packet without peer manager header".to_string()))
            })?;
            header.to_peer_id.set(peer_id);
            header.set_exit_node(is_exit_node);
            if suppress_local_delivery && peer_id == self.my_peer_id {
                suppress_local_tun_delivery(header);
            }
            let next_hop = if peer_id == self.my_peer_id {
                Some(peer_id)
            } else {
                self.local_snapshot_next_hop(snapshot, peer_id, Self::get_next_hop_policy(header))
            };
            let Some(next_hop) = next_hop else {
                return Err(Error::RouteError(Some(
                    "snapshot next hop is unavailable".to_string(),
                )));
            };
            peer_batches.push_packet_with_next_hop(
                peer_id,
                peer_packet,
                mark_recent,
                Some(next_hop),
            );
        }
        Ok(())
    }

    fn prepare_hybrid_full_ethernet_frame(
        &self,
        packet: &mut ZCPacket,
        destination_peer_id: Option<PeerId>,
    ) -> Result<(), Error> {
        let result = crate::instance::l2_tun::prepare_ip_frame_with_ipv4_prefix(
            packet.mut_payload_preserving_flow_hash(),
            self.my_peer_id,
            destination_peer_id,
            self.global_ctx
                .get_ipv4()
                .map(|network| (network.first_address(), network.network_length())),
        )
        .map_err(|error| Error::InvalidEthernetFrame(error.to_string()));
        result
    }

    fn reserve_fanout(&self, frame_len: usize, recipient_count: usize) -> Result<(), Error> {
        if !self
            .reserve_fanout_output_bytes(frame_len.saturating_mul(recipient_count), recipient_count)
        {
            return Err(Error::L2FloodRateLimited);
        }
        Ok(())
    }

    fn reserve_fanout_output_bytes(&self, output_bytes: usize, recipient_count: usize) -> bool {
        self.l2_fabric
            .allow_flood_output_bytes(output_bytes, recipient_count)
    }

    fn hybrid_delivery_requires_fanout_budget(
        is_multicast: bool,
        is_broadcast: bool,
        bridge_fallback: bool,
        compact_recipient_count: usize,
        full_recipient_count: usize,
    ) -> bool {
        is_multicast
            || is_broadcast
            || bridge_fallback
            || compact_recipient_count.saturating_add(full_recipient_count) > 1
    }

    fn hybrid_destination_from_snapshot(
        &self,
        snapshot: &ForwardingDecisionSnapshotHandle,
        ip_addr: IpAddr,
        configured_exit_nodes: &[IpAddr],
    ) -> (Vec<PeerId>, bool) {
        let routes = snapshot.capabilities();
        if ip_addr.is_multicast() {
            return (
                Self::select_ip_multicast_peers(routes, self.my_peer_id, ip_addr),
                false,
            );
        }
        let is_broadcast = match ip_addr {
            IpAddr::V4(address) => self.is_all_peers_broadcast_ipv4(&address),
            IpAddr::V6(address) => self.is_all_peers_broadcast_ipv6(&address),
        };
        if is_broadcast {
            return match ip_addr {
                IpAddr::V4(_) => (
                    Self::select_ipv4_broadcast_peers(routes, self.my_peer_id),
                    false,
                ),
                IpAddr::V6(_) => (routes.iter().map(|route| route.peer_id).collect(), false),
            };
        }

        if let Some(peer_id) = snapshot.peer_id_by_ip(&ip_addr) {
            return (vec![peer_id], false);
        }
        let same_network = self.global_ctx.is_ip_in_same_network(&ip_addr);
        if !same_network && let Some(peer_id) = snapshot.proxy_peer_id_by_ip(&ip_addr) {
            return (vec![peer_id], false);
        }

        if matches!(ip_addr, IpAddr::V6(address) if !address.is_unicast_link_local())
            && let Some(peer_id) = snapshot.public_ipv6_gateway_peer_id()
        {
            return (vec![peer_id], false);
        }

        let allow_configured_exit = match ip_addr {
            IpAddr::V4(_) => !same_network,
            IpAddr::V6(address) => !address.is_unicast_link_local(),
        };
        if !allow_configured_exit {
            return (Vec::new(), false);
        }
        for exit_node in configured_exit_nodes {
            if std::mem::discriminant(exit_node) != std::mem::discriminant(&ip_addr) {
                continue;
            }
            if let Some(peer_id) = snapshot.peer_id_by_ip(exit_node) {
                return (vec![peer_id], true);
            }
            if let Some(peer_id) = snapshot.proxy_peer_id_by_ip(exit_node) {
                return (vec![peer_id], true);
            }
        }
        (Vec::new(), false)
    }

    fn sync_topology_service_routes(&self, snapshot: &ForwardingDecisionSnapshotHandle) {
        let topology_routes = snapshot.service_routes();
        let topology_generation = topology_routes.generation();
        if self
            .topology_service_route_generation
            .swap(topology_generation, Ordering::AcqRel)
            != topology_generation
        {
            self.service_routes
                .replace_source(RouteSource::Overlay, topology_routes.routes().to_vec());
        }
        if self
            .static_service_route_generation
            .swap(snapshot.generation(), Ordering::AcqRel)
            != snapshot.generation()
        {
            let flags = self.global_ctx.flags_arc();
            let policy = match flags.relay_config().policy() {
                crate::proto::common::RelayPolicy::Hop => NextHopPolicy::LeastHop,
                crate::proto::common::RelayPolicy::Latency => NextHopPolicy::LeastCost,
                crate::proto::common::RelayPolicy::Goodput => NextHopPolicy::MaxGoodput,
            };
            let static_routes = topology_routes
                .routes()
                .iter()
                .filter(|route| {
                    snapshot
                        .next_hop(route.gateway, policy.clone())
                        .is_some_and(|hop| hop.preferred)
                })
                .cloned()
                .map(|mut route| {
                    route.preference = 10;
                    route
                })
                .collect();
            self.service_routes
                .replace_source(RouteSource::Static, static_routes);
        }
    }

    fn hybrid_destination_from_packet_snapshot_with_synced_routes(
        &self,
        packet: &ZCPacket,
        snapshot: &ForwardingDecisionSnapshotHandle,
        ip_addr: IpAddr,
        configured_exit_nodes: &[IpAddr],
    ) -> (Vec<PeerId>, bool, bool) {
        let overridden_peer = packet
            .peer_manager_header()
            .map(|header| header.to_peer_id.get())
            .unwrap_or_default();
        if overridden_peer != 0 {
            let is_exit_node = packet
                .peer_manager_header()
                .is_some_and(|header| header.is_exit_node());
            return (vec![overridden_peer], is_exit_node, false);
        }
        if let Some(route) = self.service_routes.select_gateway(
            ip_addr,
            packet.flow_hash().unwrap_or_default(),
            |gateway| {
                gateway == self.my_peer_id
                    || snapshot
                        .next_hop(gateway, NextHopPolicy::LeastCost)
                        .is_some()
            },
        ) {
            return match route.action {
                ServiceRouteAction::Forward => (vec![route.gateway], false, false),
                ServiceRouteAction::ExitSnat => (vec![route.gateway], true, false),
                ServiceRouteAction::Blackhole => (Vec::new(), false, true),
            };
        }
        let (peers, is_exit_node) =
            self.hybrid_destination_from_snapshot(snapshot, ip_addr, configured_exit_nodes);
        (peers, is_exit_node, false)
    }

    fn hybrid_destination_from_packet_snapshot(
        &self,
        packet: &ZCPacket,
        snapshot: &ForwardingDecisionSnapshotHandle,
        ip_addr: IpAddr,
        configured_exit_nodes: &[IpAddr],
    ) -> (Vec<PeerId>, bool, bool) {
        self.sync_topology_service_routes(snapshot);
        self.hybrid_destination_from_packet_snapshot_with_synced_routes(
            packet,
            snapshot,
            ip_addr,
            configured_exit_nodes,
        )
    }

    pub async fn plan_user_route(&self, ip_addr: IpAddr) -> Result<UserRoutePlan, Error> {
        let snapshot = self
            .peers
            .forwarding_decision_snapshot()
            .await
            .ok_or_else(|| {
                Error::RouteError(Some(
                    "forwarding decision snapshot is unavailable".to_string(),
                ))
            })?;
        self.sync_topology_service_routes(&snapshot);
        let flow = match ip_addr {
            IpAddr::V4(address) => u64::from(u32::from(address)),
            IpAddr::V6(address) => {
                let address = u128::from(address);
                address as u64 ^ (address >> 64) as u64
            }
        };
        if let Some(route) = self
            .service_routes
            .select_gateway(ip_addr, flow, |gateway| {
                gateway == self.my_peer_id
                    || snapshot
                        .next_hop(gateway, NextHopPolicy::LeastCost)
                        .is_some()
            })
        {
            return Ok(match route.action {
                ServiceRouteAction::Forward => UserRoutePlan::Overlay {
                    peer_ids: vec![route.gateway],
                    is_exit_node: false,
                },
                ServiceRouteAction::ExitSnat => UserRoutePlan::Overlay {
                    peer_ids: vec![route.gateway],
                    is_exit_node: true,
                },
                ServiceRouteAction::Blackhole => UserRoutePlan::Blackhole,
            });
        }
        let configured_exit_nodes = self.exit_nodes.load_full();
        let (peer_ids, is_exit_node) =
            self.hybrid_destination_from_snapshot(&snapshot, ip_addr, &configured_exit_nodes);
        if peer_ids.is_empty() {
            Ok(UserRoutePlan::System)
        } else {
            Ok(UserRoutePlan::Overlay {
                peer_ids,
                is_exit_node,
            })
        }
    }

    pub async fn get_msg_dst_peer_ipv4(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if ipv4_addr.is_multicast() {
            dst_peers.extend(Self::select_ip_multicast_peers(
                &*self.peers.list_forwarding_peers().await,
                self.my_peer_id,
                IpAddr::V4(*ipv4_addr),
            ));
        } else if self.is_all_peers_broadcast_ipv4(ipv4_addr) {
            dst_peers.extend(Self::select_ipv4_broadcast_peers(
                &*self.peers.list_forwarding_peers().await,
                self.my_peer_id,
            ));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(ipv4_addr).await {
            dst_peers.push(peer_id);
        } else if !self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            let configured_exit_nodes = self.exit_nodes.load_full();
            for exit_node in configured_exit_nodes.iter() {
                let IpAddr::V4(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }
        (dst_peers, is_exit_node)
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if ipv6_addr.is_multicast() {
            dst_peers.extend(Self::select_ip_multicast_peers(
                &*self.peers.list_forwarding_peers().await,
                self.my_peer_id,
                IpAddr::V6(*ipv6_addr),
            ));
        } else if self.is_all_peers_broadcast_ipv6(ipv6_addr) {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(ipv6_addr).await {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local()
            && let Some(peer_id) = self.get_route().get_public_ipv6_gateway_peer_id().await
        {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local() {
            // NOTE: never route link local address to exit node.
            let configured_exit_nodes = self.exit_nodes.load_full();
            for exit_node in configured_exit_nodes.iter() {
                let IpAddr::V6(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }

        (dst_peers, is_exit_node)
    }

    fn prepare_packet(msg: &mut ZCPacket) {
        stamp_critical_l2_control(msg);
        stamp_packet_flow(msg);
    }

    pub(crate) fn routed_packet_destination(&self, packet: &ZCPacket) -> Option<(IpAddr, bool)> {
        let payload = packet.payload();
        let version = payload.first().map(|byte| byte >> 4)?;
        match version {
            4 => {
                let ipv4 = Ipv4Packet::new(payload)?;
                if ipv4.get_version() != 4 {
                    return None;
                }
                let source_is_local =
                    self.global_ctx.get_ipv4().map(|ip| ip.address()) == Some(ipv4.get_source());
                Some((IpAddr::V4(ipv4.get_destination()), source_is_local))
            }
            6 => {
                let ipv6 = Ipv6Packet::new(payload)?;
                if ipv6.get_version() != 6 {
                    return None;
                }
                let source = ipv6.get_source();
                let source_is_local = self.global_ctx.is_ip_local_ipv6(&source);
                if source.is_unicast_link_local() && !source_is_local {
                    return None;
                }
                Some((IpAddr::V6(ipv6.get_destination()), source_is_local))
            }
            _ => None,
        }
    }

    fn route_accepts_compact_ip(route: &ForwardingPeerInfo) -> bool {
        route
            .feature_flag
            .as_ref()
            .is_some_and(|features| features.hybrid_l3)
    }

    pub async fn send_fabric_batch(&self, batch: FabricBatch) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let _stage = self
            .global_ctx
            .dataplane_telemetry()
            .sample_stage_with_shape(DataplaneStage::FabricForward, || batch.shape());
        let payload_kind = batch.payload_kind();
        let packets = batch.into_packets();
        match payload_kind {
            FabricPayloadKind::Ip => self.send_msg_by_hybrid_ip_batch(packets).await,
            FabricPayloadKind::Ethernet => self.send_msg_by_hybrid_ethernet_batch(packets).await,
        }
    }

    pub async fn send_fabric_packet(&self, packet: FabricPacket) -> Result<(), Error> {
        self.send_fabric_batch(FabricBatch::singleton(packet)).await
    }

    pub async fn send_msg_by_hybrid_ethernet_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let descriptor = self.peers.dataplane_descriptor();
        let snapshot = descriptor.forwarding_snapshot.as_ref().ok_or_else(|| {
            Error::RouteError(Some(
                "forwarding decision snapshot is unavailable".to_string(),
            ))
        })?;
        let configured_exit_nodes = self.exit_nodes.load_full();
        let origin_auth_snapshot = descriptor.origin_auth_snapshot.as_ref();
        let mut exceptional_inputs = EthernetBatchInputs::new();
        let mut errors = Vec::new();
        let mut nic_batch = PacketBatch::with_capacity(batch.len());
        let mut metadata = TapBatchMetadata::new();
        let policy_time = std::time::Instant::now();
        for packet in batch {
            let frame = packet.payload();
            if self.l2_fabric.has_policy()
                && !self
                    .l2_fabric
                    .admit_source_at(frame, self.my_peer_id, policy_time)
            {
                continue;
            }
            if !self.l2_fabric.has_policy() {
                self.l2_fabric
                    .learn_source_at(frame, self.my_peer_id, policy_time);
            }
            #[cfg(feature = "tun")]
            if crate::instance::virtual_nic::NicCtx::handle_hybrid_control_frame(&packet, self)
                .await
            {
                continue;
            }
            let Some(ethernet_header) = frame
                .get(..crate::instance::l2_tun::ETHERNET_HEADER_LEN)
                .and_then(|header| {
                    <[u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN]>::try_from(header).ok()
                })
            else {
                errors.push(Error::InvalidEthernetFrame(
                    "frame is shorter than the Ethernet header".to_string(),
                ));
                continue;
            };
            let ether_type = &ethernet_header[12..14];
            let ip_payload = &frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN..];
            match ether_type {
                [0x08, 0x00] if Ipv4Packet::new(ip_payload).is_none() => {
                    errors.push(Error::InvalidEthernetFrame(
                        "invalid Ethernet IPv4 payload".to_string(),
                    ));
                    continue;
                }
                [0x86, 0xdd] if Ipv6Packet::new(ip_payload).is_none() => {
                    errors.push(Error::InvalidEthernetFrame(
                        "invalid Ethernet IPv6 payload".to_string(),
                    ));
                    continue;
                }
                [0x08, 0x00] | [0x86, 0xdd] => {}
                _ => {
                    let mut packet = packet;
                    // Reused NIC buffers can contain a previous packet's routing header.
                    packet.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
                    exceptional_inputs.push(EthernetBatchInput {
                        packet,
                        destination_peer_id: None,
                        is_exit_node: false,
                        suppress_local_delivery: false,
                    });
                    continue;
                }
            }
            let metadata_index = metadata.len();
            metadata.push(Some(TapBatchMeta { ethernet_header }));
            let mut ip_packet = packet;
            ip_packet
                .remove_payload_prefix_preserving_flow_hash(
                    crate::instance::l2_tun::ETHERNET_HEADER_LEN,
                )
                .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))?;
            ip_packet.fill_peer_manager_hdr_preserving_flow_hash(
                self.my_peer_id,
                0,
                PacketType::Data as u8,
            );
            ip_packet.set_batch_key(metadata_index);
            nic_batch
                .try_push(ip_packet)
                .expect("a TAP IP batch cannot exceed its input");
        }

        // Run ACL and all NIC transforms once before any route or representation decision.
        let accepted_batch = self.run_nic_packet_process_pipeline_batch(nic_batch).await;
        let mut compact_batches = OrderedPeerBatches::new();
        let mut full_batches = OrderedPeerBatches::new();
        let fdb_batch_time = std::time::Instant::now();
        let mut destination_batch = L2DestinationBatch::default();
        for mut ip_packet in accepted_batch {
            let metadata_index = ip_packet.batch_key().ok_or_else(|| {
                Error::InvalidEthernetFrame("TAP pipeline removed packet identity".to_string())
            })?;
            let metadata = metadata
                .get_mut(metadata_index)
                .and_then(Option::take)
                .ok_or_else(|| {
                    Error::InvalidEthernetFrame(
                        "TAP pipeline returned unknown packet identity".to_string(),
                    )
                })?;
            ip_packet.clear_batch_key();
            stamp_packet_flow(&mut ip_packet);
            let Some((ip_addr, source_is_local)) = self.routed_packet_destination(&ip_packet)
            else {
                errors.push(Error::InvalidEthernetFrame(
                    "NIC pipeline produced an invalid IP payload".to_string(),
                ));
                continue;
            };
            let fdb_destination = self.live_l2_destination(
                destination_batch
                    .resolve_at(&self.l2_fabric, &metadata.ethernet_header, fdb_batch_time)
                    .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))?,
                &descriptor,
            );
            let bridged_peer = match fdb_destination {
                EthernetDestination::Known(peer_id)
                    if snapshot.peer_id_by_ip(&ip_addr).is_none()
                        && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr)
                        && metadata.ethernet_header[..6]
                            != crate::instance::l2_tun::encode_peer_mac(self.my_peer_id)
                        && metadata.ethernet_header[..6]
                            != crate::instance::l2_tun::encode_peer_mac(peer_id) =>
                {
                    Some(peer_id)
                }
                _ => None,
            };
            let (candidate_peers, is_exit_node, blackholed) = self
                .hybrid_destination_from_packet_snapshot(
                    &ip_packet,
                    snapshot,
                    ip_addr,
                    &configured_exit_nodes,
                );
            if blackholed {
                continue;
            }
            // Keep explicit policy destinations. The FDB takes priority over automatic IP routes.
            let (candidate_peers, is_exit_node) = if bridged_peer.is_some()
                && ip_packet
                    .peer_manager_header()
                    .is_some_and(|header| header.to_peer_id.get() == 0)
            {
                (Vec::new(), false)
            } else {
                (candidate_peers, is_exit_node)
            };
            if let Some(peer_id) =
                self.hybrid_compact_unicast_peer(&candidate_peers, ip_addr, snapshot)
            {
                let suppress_local_delivery =
                    source_is_local && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr);
                if let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut compact_batches,
                    ip_packet,
                    &[peer_id],
                    is_exit_node,
                    suppress_local_delivery,
                    snapshot,
                    true,
                ) {
                    errors.push(error);
                }
                continue;
            }
            let fdb_destination = candidate_peers.is_empty().then_some(fdb_destination);
            let sets = self.hybrid_recipient_sets(
                candidate_peers,
                is_exit_node,
                ip_addr,
                snapshot,
                fdb_destination,
                true,
            );
            let mut full_peers = Vec::with_capacity(sets.full_peers.len());
            let mut unauthorized_full = false;
            for peer_id in sets.full_peers.iter().copied() {
                if Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    origin_auth_snapshot,
                    snapshot,
                    peer_id,
                    self.my_peer_id,
                    &self.global_ctx,
                ) {
                    full_peers.push(peer_id);
                } else {
                    unauthorized_full = true;
                }
            }
            if unauthorized_full {
                errors.push(Error::RouteError(Some(
                    "complete Ethernet destination is not an authorized bridge".to_string(),
                )));
            }
            let compact_peers = sets.compact_peers;
            if compact_peers.is_empty() && full_peers.is_empty() {
                continue;
            }

            let mut pending_packet = Some(ip_packet);
            let mut full_packet = None;
            if !full_peers.is_empty() {
                let source_packet = if compact_peers.is_empty() {
                    pending_packet
                        .take()
                        .expect("the full-only branch owns the accepted packet")
                } else {
                    pending_packet
                        .as_ref()
                        .expect("the compact branch retains the accepted packet")
                        .clone()
                };
                let mut packet = Self::rebuild_ethernet_from_accepted_ip_owned(
                    source_packet,
                    &metadata.ethernet_header,
                )?;
                // TAP supplied the destination MAC. Preserve this header for LAN hosts.
                packet.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_hybrid_ip_ethernet(true);
                full_packet = Some(packet);
            }

            let recipient_count = compact_peers.len().saturating_add(full_peers.len());
            let compact_bytes = pending_packet.as_ref().map_or(0, |packet| {
                packet.buf_len().saturating_mul(compact_peers.len())
            });
            let full_bytes = full_packet.as_ref().map_or(0, |packet| {
                packet.buf_len().saturating_mul(full_peers.len())
            });
            if Self::hybrid_delivery_requires_fanout_budget(
                sets.is_multicast,
                sets.is_broadcast,
                sets.bridge_fallback,
                compact_peers.len(),
                full_peers.len(),
            ) && !self.reserve_fanout_output_bytes(
                compact_bytes.saturating_add(full_bytes),
                recipient_count,
            ) {
                errors.push(Error::L2FloodRateLimited);
                continue;
            }
            let mark_recent = !sets.is_multicast && !sets.is_broadcast && !sets.bridge_fallback;
            let suppress_local_delivery =
                source_is_local && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr);
            if !compact_peers.is_empty() {
                let compact_packet = pending_packet
                    .take()
                    .expect("the compact branch owns the accepted packet");
                if let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut compact_batches,
                    compact_packet,
                    &compact_peers,
                    sets.is_exit_node,
                    suppress_local_delivery,
                    snapshot,
                    mark_recent,
                ) {
                    errors.push(error);
                }
            }
            if let Some(full_packet) = full_packet
                && let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut full_batches,
                    full_packet,
                    &full_peers,
                    sets.is_exit_node,
                    suppress_local_delivery,
                    snapshot,
                    mark_recent,
                )
            {
                errors.push(error);
            }
        }

        if !exceptional_inputs.is_empty()
            && let Err(error) = self
                .send_preclassified_ethernet_batch_with_descriptor(exceptional_inputs, &descriptor)
                .await
        {
            errors.push(error);
        }
        if !compact_batches.batches.is_empty() {
            self.send_ordered_peer_batches(compact_batches, &mut errors, None)
                .await?;
        }
        if !full_batches.batches.is_empty() {
            self.send_ordered_peer_batches(full_batches, &mut errors, Some(&descriptor))
                .await?;
        }
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors
                .pop()
                .expect("one hybrid Ethernet delivery error exists")),
            _ => Err(anyhow::anyhow!("hybrid Ethernet batch delivery failed: {errors:?}").into()),
        }
    }

    pub async fn send_msg_by_hybrid_ip_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut batch = batch;
        for packet in batch.iter_mut() {
            packet.fill_peer_manager_hdr_preserving_flow_hash(
                self.my_peer_id,
                0,
                PacketType::Data as u8,
            );
        }
        let batch = self.run_nic_packet_process_pipeline_batch(batch).await;
        if batch.is_empty() {
            return Ok(());
        }
        let descriptor = self.peers.dataplane_descriptor();
        let snapshot = descriptor.forwarding_snapshot.as_ref().ok_or_else(|| {
            Error::RouteError(Some(
                "forwarding decision snapshot is unavailable".to_string(),
            ))
        })?;
        let configured_exit_nodes = self.exit_nodes.load_full();
        let origin_auth_snapshot = descriptor.origin_auth_snapshot.as_ref();
        self.sync_topology_service_routes(snapshot);
        let mut route_cache = SmallVec::<[HybridBatchRoute; 4]>::new();
        let mut route_inline_indexes = SmallVec::<[(HybridBatchRouteKey, usize); 4]>::new();
        let mut route_spill_indexes = None;
        let mut compact_batches = OrderedPeerBatches::new();
        let mut full_batches = OrderedPeerBatches::new();
        let mut errors = Vec::new();
        for mut packet in batch {
            stamp_packet_flow(&mut packet);
            let Some((ip_addr, not_send_to_self)) = self.routed_packet_destination(&packet) else {
                continue;
            };
            let overridden_peer = packet
                .peer_manager_header()
                .map(|header| header.to_peer_id.get())
                .unwrap_or_default();
            let route = if overridden_peer != 0 {
                let is_exit_node = packet
                    .peer_manager_header()
                    .is_some_and(|header| header.is_exit_node());
                HybridBatchRoute {
                    peers: HybridRoutePeers::from_slice(&[overridden_peer]),
                    is_exit_node,
                    blackholed: false,
                }
            } else {
                let key = HybridBatchRouteKey {
                    address: ip_addr,
                    flow: packet.flow_hash().unwrap_or_default(),
                };
                if let Some(index) = lazy_batch_group_index(
                    key,
                    route_cache.len(),
                    &mut route_inline_indexes,
                    &mut route_spill_indexes,
                ) {
                    route_cache[index].clone()
                } else {
                    let (peers, is_exit_node, blackholed) = self
                        .hybrid_destination_from_packet_snapshot_with_synced_routes(
                            &packet,
                            snapshot,
                            ip_addr,
                            &configured_exit_nodes,
                        );
                    let route = HybridBatchRoute {
                        peers: peers.into_iter().collect(),
                        is_exit_node,
                        blackholed,
                    };
                    route_cache.push(route.clone());
                    route
                }
            };
            if route.blackholed {
                continue;
            }
            let HybridBatchRoute {
                peers: candidate_peers,
                is_exit_node,
                blackholed: _,
            } = route;
            if let Some(peer_id) =
                self.hybrid_compact_unicast_peer(&candidate_peers, ip_addr, snapshot)
            {
                if let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut compact_batches,
                    packet,
                    &[peer_id],
                    is_exit_node,
                    not_send_to_self && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr),
                    snapshot,
                    true,
                ) {
                    errors.push(error);
                }
                continue;
            }
            let sets = self.hybrid_recipient_sets(
                candidate_peers.into_iter().collect(),
                is_exit_node,
                ip_addr,
                snapshot,
                None,
                false,
            );
            let mut full_peers = Vec::with_capacity(sets.full_peers.len());
            let mut unauthorized_full = false;
            for peer_id in sets.full_peers.iter().copied() {
                if Self::snapshot_and_current_full_ethernet_destination_is_authorized_from_snapshot(
                    origin_auth_snapshot,
                    snapshot,
                    peer_id,
                    self.my_peer_id,
                    &self.global_ctx,
                ) {
                    full_peers.push(peer_id);
                } else {
                    unauthorized_full = true;
                }
            }
            if unauthorized_full {
                errors.push(Error::RouteError(Some(
                    "complete Ethernet destination is not an authorized bridge".to_string(),
                )));
            }
            let compact_peers = sets.compact_peers;
            if compact_peers.is_empty() && full_peers.is_empty() {
                continue;
            }

            let mut pending_packet = Some(packet);
            let mut full_packet = None;
            if !full_peers.is_empty() {
                let direct_full_peer =
                    if full_peers.len() == 1 && !sets.is_multicast && !sets.is_broadcast {
                        Some(full_peers[0])
                    } else {
                        None
                    };
                let source_packet = if compact_peers.is_empty() {
                    pending_packet
                        .take()
                        .expect("the full-only branch owns the accepted IP packet")
                } else {
                    pending_packet
                        .as_ref()
                        .expect("the compact branch retains the accepted IP packet")
                        .clone()
                };
                let mut frame = source_packet;
                Self::ensure_ethernet_headroom(&mut frame)?;
                self.prepare_hybrid_full_ethernet_frame(&mut frame, direct_full_peer)?;
                frame.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
                frame
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_hybrid_ip_ethernet(true);
                full_packet = Some(frame);
            }
            let recipient_count = compact_peers.len().saturating_add(full_peers.len());
            let compact_bytes = pending_packet.as_ref().map_or(0, |packet| {
                packet.buf_len().saturating_mul(compact_peers.len())
            });
            let full_bytes = full_packet.as_ref().map_or(0, |packet| {
                packet.buf_len().saturating_mul(full_peers.len())
            });
            if Self::hybrid_delivery_requires_fanout_budget(
                sets.is_multicast,
                sets.is_broadcast,
                sets.bridge_fallback,
                compact_peers.len(),
                full_peers.len(),
            ) && !self.reserve_fanout_output_bytes(
                compact_bytes.saturating_add(full_bytes),
                recipient_count,
            ) {
                errors.push(Error::L2FloodRateLimited);
                continue;
            }
            let mark_recent = !sets.is_multicast && !sets.is_broadcast && !sets.bridge_fallback;
            if !compact_peers.is_empty() {
                let compact_packet = pending_packet
                    .take()
                    .expect("the compact branch owns the accepted IP packet");
                if let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut compact_batches,
                    compact_packet,
                    &compact_peers,
                    sets.is_exit_node,
                    not_send_to_self && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr),
                    snapshot,
                    mark_recent,
                ) {
                    errors.push(error);
                }
            }
            if let Some(full_packet) = full_packet
                && let Err(error) = self.append_hybrid_ordered_peer_packets(
                    &mut full_batches,
                    full_packet,
                    &full_peers,
                    sets.is_exit_node,
                    not_send_to_self && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr),
                    snapshot,
                    mark_recent,
                )
            {
                errors.push(error);
            }
        }

        if !compact_batches.batches.is_empty() {
            self.send_ordered_peer_batches(compact_batches, &mut errors, None)
                .await?;
        }
        if !full_batches.batches.is_empty() {
            self.send_ordered_peer_batches(full_batches, &mut errors, Some(&descriptor))
                .await?;
        }
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.pop().expect("one hybrid IP delivery error exists")),
            _ => Err(anyhow::anyhow!("hybrid IP batch delivery failed: {errors:?}").into()),
        }
    }

    async fn run_clean_peer_without_conn_routine(&self) {
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                peer_map.clean_peer_without_conn().await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    async fn run_relay_session_gc_routine(&self) {
        let relay_peer_map = self.relay_peer_map.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                relay_peer_map.evict_idle_sessions(std::time::Duration::from_secs(60));
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_recent_traffic_gc_routine(&self) {
        let recent_have_traffic = self.recent_have_traffic.clone();
        let peers = self.peers.clone();
        let foreign_network_client = self.foreign_network_client.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                PeerManager::gc_recent_traffic_entries(
                    recent_have_traffic.as_ref(),
                    Instant::now(),
                    |peer_id| {
                        if let Some(peer) = peers.get_peer_by_id(peer_id) {
                            peer.has_directly_connected_conn()
                        } else {
                            foreign_network_client.get_peer_map().has_peer(peer_id)
                        }
                    },
                );
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_peer_session_gc_routine(&self) {
        let peer_session_store = self.peer_session_store.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                peer_session_store.evict_unused_sessions();
            }
        });
    }

    async fn run_credential_gc_routine(&self) {
        let global_ctx = self.global_ctx.clone();
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                if global_ctx.get_network_identity().network_secret.is_some() {
                    if global_ctx
                        .get_credential_manager()
                        .remove_expired_credentials()
                    {
                        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);
                    }

                    Self::close_untrusted_credential_peers(&peer_map, &global_ctx).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    async fn run_traffic_metrics_gc_routine(&self) {
        let mut event_receiver = self.global_ctx.subscribe();
        let traffic_metrics = self.traffic_metrics.clone();
        let l2_fabric = self.l2_fabric.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::PeerRemoved(peer_id)) => {
                        traffic_metrics.remove_peer(peer_id);
                        l2_fabric.forget_peer(peer_id);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "traffic metrics GC receiver lagged; clearing peer cache to avoid stale metric attribution"
                        );
                        traffic_metrics.clear_peer_cache();
                        l2_fabric.clear();
                        event_receiver = event_receiver.resubscribe();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn run_foriegn_network(&self) {
        self.peer_rpc_tspt
            .foreign_peers
            .lock()
            .await
            .replace(Arc::downgrade(&self.foreign_network_client));

        self.foreign_network_client.run().await;
    }

    async fn run_speed_probe_routine(&self) {
        let global_ctx = self.global_ctx.clone();
        let peers = self.peers.clone();
        let recent_data_traffic = self.recent_data_traffic.clone();
        self.tasks.lock().await.spawn(async move {
            let mut active_config = None;
            let mut budget = None;
            let mut generation = 0_u64;
            let mut rotation = 0_usize;
            loop {
                let flags = global_ctx.flags_arc();
                if flags.relay_config().probe_budget_bps == 0
                    || flags.relay_config().probe_interval() == 0
                {
                    active_config = None;
                    budget = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let interval = Duration::from_secs(flags.relay_config().probe_interval());
                let config = (
                    flags.relay_config().probe_budget_bps,
                    flags.relay_config().probe_interval(),
                );
                if active_config != Some(config) {
                    match ProbeBudget::new(
                        flags.relay_config().probe_budget_bps,
                        interval,
                        std::time::Instant::now(),
                    ) {
                        Ok(new_budget) => {
                            budget = Some(new_budget);
                            active_config = Some(config);
                        }
                        Err(error) => {
                            tracing::warn!(?error, "invalid speed probe budget");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    }
                }

                let now = Instant::now();
                recent_data_traffic.retain(|_, last_seen| {
                    now.saturating_duration_since(*last_seen) <= Self::RECENT_HAVE_TRAFFIC_TTL
                });
                let connections = peers.list_speed_probe_connections();
                let packet_size = (flags.mtu as usize)
                    .max(PEER_MANAGER_HEADER_SIZE + crate::peers::speed_probe::PROBE_HEADER_SIZE);
                let snapshot = budget
                    .as_mut()
                    .unwrap()
                    .take_cycle_snapshot(std::time::Instant::now());
                let allocation = split_cycle_budget(snapshot, connections.len(), packet_size);
                budget
                    .as_mut()
                    .unwrap()
                    .return_unused(allocation.unused_bytes);

                let keys = connections
                    .iter()
                    .map(|(peer_id, connection)| {
                        (
                            *peer_id,
                            connection.get_conn_id(),
                            recent_data_traffic.contains_key(peer_id),
                        )
                    })
                    .collect::<Vec<_>>();
                let order = ordered_probe_indexes(&keys, rotation);
                rotation = rotation.wrapping_add(1);
                generation = generation.saturating_add(1);

                let mut probes = JoinSet::new();
                for (index, share) in order.into_iter().zip(allocation.shares) {
                    let connection = connections[index].1.clone();
                    probes.spawn(async move {
                        connection
                            .run_speed_probe(generation, share, packet_size, interval)
                            .await
                    });
                }
                while let Some(result) = probes.join_next().await {
                    match result {
                        Ok(unused) => budget.as_mut().unwrap().return_unused(unused),
                        Err(error) => tracing::warn!(?error, "speed probe task failed"),
                    }
                }

                tokio::time::sleep(interval).await;
            }
        });
    }

    pub async fn run(&self) -> Result<(), Error> {
        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => self.add_route(route.clone()).await,
            RouteAlgoInst::None => {}
        };

        self.init_packet_process_pipeline().await;
        self.peer_rpc_mgr.run();

        self.start_peer_recv().await;
        self.run_clean_peer_without_conn_routine().await;
        self.run_relay_session_gc_routine().await;
        self.run_recent_traffic_gc_routine().await;
        self.run_peer_session_gc_routine().await;
        self.run_credential_gc_routine().await;
        self.run_traffic_metrics_gc_routine().await;
        self.run_speed_probe_routine().await;

        self.run_foriegn_network().await;

        Ok(())
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_relay_peer_map(&self) -> Arc<RelayPeerMap> {
        self.relay_peer_map.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn get_peer_session_store(&self) -> Arc<PeerSessionStore> {
        self.peer_session_store.clone()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.global_ctx.get_id()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_global_ctx_ref(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn get_nic_channel(&self) -> PacketRecvChan {
        self.nic_channel.clone()
    }

    pub(crate) fn install_direct_nic_sink(
        &self,
        sink: std::pin::Pin<Box<dyn PacketBatchSink>>,
    ) -> Arc<DirectNicEndpoint> {
        let label_set = LabelSet::new()
            .with_label_type(LabelType::NetworkName(self.global_ctx.get_network_name()));
        let stats = self.global_ctx.stats_manager();
        self.packet_ingress
            .install_direct_nic(Arc::new(DirectNicIngress {
                my_peer_id: self.my_peer_id,
                peers: Arc::downgrade(&self.peers),
                global_ctx: self.global_ctx.clone(),
                route: self.get_route().into(),
                l2_fabric: self.l2_fabric.clone(),
                traffic_metrics: self.traffic_metrics.clone(),
                peer_packet_process_pipeline: self.peer_packet_process_pipeline.clone(),
                ethernet_input: self.global_ctx.get_feature_flags().ethernet_input,
                nic: self.direct_nic_writer.clone(),
                self_rx_bytes: stats.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone()),
                self_rx_packets: stats
                    .get_counter(MetricName::TrafficPacketsSelfRx, label_set.clone()),
                compress_rx_bytes_before: stats
                    .get_counter(MetricName::CompressionBytesRxBefore, label_set.clone()),
                compress_rx_bytes_after: stats
                    .get_counter(MetricName::CompressionBytesRxAfter, label_set),
            }));
        self.direct_nic_writer
            .install(sink, self.global_ctx.clone())
    }

    pub(crate) async fn inject_packet_to_nic(
        &self,
        mut packet: ZCPacket,
    ) -> Result<(), TunnelError> {
        let endpoint = self
            .direct_nic_writer
            .current_endpoint()
            .ok_or(TunnelError::Shutdown)?;
        stamp_critical_l2_control(&mut packet);
        let delivery = plan_direct_nic_delivery(PacketBatch::singleton(packet))?;
        DirectNicBatchWriter::send_to(endpoint, delivery).await
    }

    // Drain target for the legacy peer-packet channel. The batched dataplane
    // rework removed the task that consumed this channel, so batches stranded
    // there kept their byte credits forever and starved every sibling channel
    // sharing the same semaphore under load.
    pub(crate) async fn deliver_batch_to_nic(&self, batch: PacketBatch) {
        if batch.is_empty() {
            return;
        }
        let Some(endpoint) = self.direct_nic_writer.current_endpoint() else {
            tracing::debug!(
                packets = batch.len(),
                "dropping NIC-bound batch because no direct NIC endpoint is installed"
            );
            return;
        };
        match plan_direct_nic_delivery(batch) {
            Ok(delivery) => {
                if let Err(error) = DirectNicBatchWriter::send_to(endpoint, delivery).await {
                    tracing::error!(?error, "send direct packet batch to NIC failed");
                }
            }
            Err(error) => {
                tracing::error!(?error, "prepare direct packet batch for NIC failed");
            }
        }
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub async fn get_my_info(&self) -> instance::NodeInfo {
        instance::NodeInfo {
            peer_id: self.my_peer_id,
            ipv4_addr: self
                .global_ctx
                .get_ipv4()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            proxy_cidrs: self
                .global_ctx
                .config
                .get_proxy_cidrs()
                .into_iter()
                .map(|x| match x.mapped_cidr {
                    None => x.cidr.to_string(),
                    Some(mapped) => format!("{}->{}", x.cidr, mapped),
                })
                .collect(),
            hostname: self.global_ctx.get_hostname(),
            stun_info: Some(self.global_ctx.get_stun_info_collector().get_stun_info()),
            inst_id: self.global_ctx.get_id().to_string(),
            listeners: self
                .global_ctx
                .get_running_listeners()
                .iter()
                .map(|x| x.to_string())
                .collect(),
            config: self.global_ctx.config.dump(),
            version: LOWTIER_VERSION.to_string(),
            feature_flag: Some(self.global_ctx.get_feature_flags()),
            ip_list: Some(self.global_ctx.get_ip_collector().collect_ip_addrs().await),
            public_ipv6_addr: self.get_my_public_ipv6_addr().await.map(Into::into),
            ipv6_public_addr_prefix: self
                .global_ctx
                .get_advertised_ipv6_public_addr_prefix()
                .map(|prefix| {
                    cidr::Ipv6Inet::new(prefix.first_address(), prefix.network_length())
                        .unwrap()
                        .into()
                }),
        }
    }

    pub async fn wait(&self) {
        while !self.tasks.lock().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn clear_resources(&self) {
        let mut peer_pipeline = self.peer_packet_process_pipeline.write().await;
        peer_pipeline.clear();
        let mut nic_pipeline = self.nic_packet_process_pipeline.write().await;
        nic_pipeline.clear();

        self.peer_rpc_mgr.rpc_server().registry().unregister_all();
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        let ret = self.peers.close_peer_conn(peer_id, conn_id).await;
        tracing::info!("close_peer_conn in peer map: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_client
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network client: {:?}", ret);
        if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
            return ret;
        }

        let ret = self
            .foreign_network_manager
            .close_peer_conn(peer_id, conn_id)
            .await;
        tracing::info!("close_peer_conn in foreign network manager done: {:?}", ret);
        ret
    }

    pub async fn update_exit_nodes(&self) {
        let exit_nodes = self.global_ctx.config.get_exit_nodes();
        self.exit_nodes.store(Arc::new(exit_nodes));
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt as _, StreamExt as _};
    use std::{
        fmt::Debug,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use crate::{
        common::{PeerId, config::Flags, global_ctx::tests::get_mock_global_ctx},
        peers::{
            PacketRecvChanReceiver, create_packet_recv_chan,
            peer_manager::RouteAlgoType,
            route_trait::{ForwardingPeerInfo, ForwardingPeerTable},
            service_route::{ServiceRoute, ServiceRouteAction},
            tests::{connect_peer_manager, wait_route_appear},
        },
        proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
        tunnel::{
            batch::PacketBatch,
            packet_def::{PacketType, ZCPacket},
        },
    };

    use super::{
        DIRECT_NIC_QUEUE_CREDIT_BYTES, DirectNicDelivery, DirectNicEndpoint, DirectNicQueueState,
        PeerManager, plan_direct_nic_delivery, run_direct_nic_writer,
    };

    #[test]
    fn locally_suppressed_data_is_not_reproxied() {
        let mut packet = ZCPacket::new_with_payload(&[]);
        packet.fill_peer_manager_hdr(1, 1, PacketType::Data as u8);
        let header = packet.mut_peer_manager_header().unwrap();
        super::suppress_local_tun_delivery(header);
        assert!(header.is_not_send_to_tun());
        assert!(header.is_no_proxy());
    }

    #[derive(Debug, PartialEq, Eq)]
    enum DirectNicWriterEvent {
        Start(Vec<u8>),
        Flush,
    }

    struct ImmediateFlushDirectNicSink {
        events: futures::channel::mpsc::UnboundedSender<DirectNicWriterEvent>,
    }

    impl futures::Sink<PacketBatch> for ImmediateFlushDirectNicSink {
        type Error = crate::tunnel::TunnelError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            self.get_mut()
                .events
                .unbounded_send(DirectNicWriterEvent::Start(
                    batch.iter().map(|packet| packet.payload()[0]).collect(),
                ))
                .map_err(|_| crate::tunnel::TunnelError::Shutdown)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.get_mut()
                .events
                .unbounded_send(DirectNicWriterEvent::Flush)
                .map_err(|_| crate::tunnel::TunnelError::Shutdown)?;
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    fn direct_nic_writer_batch(marker: u8, packet_count: usize) -> DirectNicDelivery {
        let mut batch = PacketBatch::new();
        for sequence in 0..packet_count {
            batch
                .try_push(ZCPacket::new_with_payload(&[marker, sequence as u8]))
                .unwrap();
        }
        plan_direct_nic_delivery(batch).unwrap()
    }

    #[tokio::test]
    async fn direct_nic_writer_coalesces_ready_batches_in_order() {
        let global_ctx = get_mock_global_ctx();
        let (sender, receiver) = tokio::sync::mpsc::channel(3);
        let terminal_error = Arc::new(std::sync::OnceLock::new());
        let queue_state = Arc::new(DirectNicQueueState::new(
            global_ctx.dataplane_telemetry().clone(),
        ));
        let endpoint = Arc::new(DirectNicEndpoint {
            sender,
            queue_credits: Arc::new(tokio::sync::Semaphore::new(DIRECT_NIC_QUEUE_CREDIT_BYTES)),
            queue_state,
            terminal_error: terminal_error.clone(),
        });
        let first = direct_nic_writer_batch(1, 2);
        endpoint.enqueue(first.batch, first.plan).await.unwrap();
        let second = direct_nic_writer_batch(2, 2);
        endpoint.enqueue(second.batch, second.plan).await.unwrap();
        drop(endpoint);

        let (events_tx, mut events_rx) = futures::channel::mpsc::unbounded();
        run_direct_nic_writer(
            Box::pin(ImmediateFlushDirectNicSink { events: events_tx }),
            receiver,
            terminal_error,
            global_ctx,
        )
        .await;

        assert_eq!(
            events_rx.next().await,
            Some(DirectNicWriterEvent::Start(vec![1, 1, 2, 2]))
        );
        assert_eq!(events_rx.next().await, Some(DirectNicWriterEvent::Flush));
        assert_eq!(events_rx.next().await, None);
    }

    async fn create_tap_peer_manager(
        l2_flood_bytes_per_second: u64,
    ) -> (Arc<PeerManager>, PacketRecvChanReceiver) {
        create_tap_peer_manager_with_ipv4(l2_flood_bytes_per_second, None).await
    }

    async fn create_tap_peer_manager_with_ipv4(
        l2_flood_bytes_per_second: u64,
        ipv4: Option<std::net::Ipv4Addr>,
    ) -> (Arc<PeerManager>, PacketRecvChanReceiver) {
        create_tap_peer_manager_with_policy(l2_flood_bytes_per_second, ipv4, |_| {}).await
    }

    async fn create_tap_peer_manager_with_policy(
        l2_flood_bytes_per_second: u64,
        ipv4: Option<std::net::Ipv4Addr>,
        configure: impl FnOnce(&mut Flags),
    ) -> (Arc<PeerManager>, PacketRecvChanReceiver) {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(ipv4.map(|address| cidr::Ipv4Inet::new(address, 24).unwrap()));
        let mut flags = global_ctx.get_flags();
        flags.enable_bridge = true;
        flags.l2_flood_bytes_per_second = l2_flood_bytes_per_second;
        configure(&mut flags);
        global_ctx.set_flags(flags);
        let mut features = global_ctx.get_feature_flags();
        features.ethernet_input = true;
        features.hybrid_l3 = true;
        features.bridge_input = true;
        features.multicast_membership = true;
        global_ctx.set_base_advertised_feature_flags(features);

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            packet_send,
        ));
        peer_manager.run().await.unwrap();
        (peer_manager, packet_recv)
    }
    fn routed_ipv4_packet(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        marker: u8,
    ) -> ZCPacket {
        let mut bytes = vec![0_u8; 64];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&64_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..22].copy_from_slice(&1000_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&2000_u16.to_be_bytes());
        bytes[24] = marker;
        ZCPacket::new_with_payload(&bytes)
    }

    fn ethernet_frame(destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
        let mut frame = vec![0_u8; 64];
        frame[..6].copy_from_slice(&destination);
        frame[6..12].copy_from_slice(&source);
        frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        frame
    }

    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn l2_nic_policy_precedes_neighbor_replies_and_membership() {
        use crate::instance::virtual_nic::NicCtx;
        let (peer_a, _legacy_nic_a) =
            create_tap_peer_manager_with_policy(0, Some("10.77.0.1".parse().unwrap()), |flags| {
                flags.l2_allowed_vlans = vec![0];
                flags.l2_allowed_ether_types = vec![0x0806, 0x0800];
            })
            .await;
        let (nic_send, mut nic_a) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let _nic_endpoint = peer_a
            .install_direct_nic_sink(Box::pin(nic_send.sink_map_err(|error| {
                crate::tunnel::TunnelError::InvalidPacket(error.to_string())
            })));
        let (peer_b, _nic_b) =
            create_tap_peer_manager_with_ipv4(0, Some("10.77.0.2".parse().unwrap())).await;
        connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
        wait_route_appear(peer_a.clone(), peer_b.clone())
            .await
            .unwrap();
        let source = [2, 0, 0, 0, 0, 1];
        let mut arp = ethernet_frame([0xff; 6], source);
        arp[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        arp[22..28].copy_from_slice(&source);
        arp[28..32].copy_from_slice(&[10, 77, 0, 1]);
        arp[38..42].copy_from_slice(&[10, 77, 0, 2]);
        let mut denied_arp = arp.clone();
        denied_arp.splice(12..12, [0x81, 0, 0, 7]);
        let mut membership = ethernet_frame([1, 0, 0x5e, 1, 2, 3], source);
        membership[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        membership[14] = 0x45;
        membership[16..18].copy_from_slice(&28_u16.to_be_bytes());
        membership[22] = 1;
        membership[23] = 2;
        membership[26..30].copy_from_slice(&[10, 77, 0, 1]);
        membership[30..34].copy_from_slice(&[239, 1, 2, 3]);
        membership[34..42].copy_from_slice(&[0x16, 0, 0xf8, 0xfa, 239, 1, 2, 3]);
        let mut denied_membership = membership.clone();
        denied_membership.splice(12..12, [0x81, 0, 0, 7]);
        let mut denied = PacketBatch::new();
        for frame in [&denied_arp, &denied_membership] {
            denied.try_push(ZCPacket::new_with_payload(frame)).unwrap();
        }
        let adapter = crate::common::config::InterfaceAdapter::Tap;
        NicCtx::do_forward_nic_batch_to_peers(denied, &peer_a, adapter).await;
        assert!(peer_a.global_ctx.get_multicast_groups().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), nic_a.next())
                .await
                .is_err()
        );
        NicCtx::do_forward_nic_to_peers(ZCPacket::new_with_payload(&arp), &peer_a, adapter).await;
        let reply = tokio::time::timeout(Duration::from_secs(1), nic_a.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[0].payload()[20..22], &[0, 2]);
        NicCtx::do_forward_nic_to_peers(ZCPacket::new_with_payload(&membership), &peer_a, adapter)
            .await;
        assert!(
            peer_a
                .global_ctx
                .get_multicast_groups()
                .contains(&"239.1.2.3".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn l2_bridge_policy_filters_batches_and_external_reflection() {
        let (peer_a, mut nic_a) = create_tap_peer_manager(0).await;
        let (peer_b, mut nic_b) = create_tap_peer_manager_with_policy(0, None, |flags| {
            flags.l2_max_macs_per_peer = 1;
            flags.l2_mac_move_hold_seconds = 30;
            flags.l2_allowed_vlans = vec![0];
            flags.l2_allowed_ether_types = vec![0x88b5];
        })
        .await;
        connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
        wait_route_appear(peer_a.clone(), peer_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_b.clone(), peer_a.clone())
            .await
            .unwrap();
        let accepted = ethernet_frame([0xff; 6], [2, 0, 0, 0, 0, 1]);
        let excess = ethernet_frame([0xff; 6], [2, 0, 0, 0, 0, 2]);
        let mut tagged = accepted.clone();
        tagged.splice(12..12, [0x81, 0x00, 0, 7]);
        let mut batch = PacketBatch::new();
        for frame in [&accepted, &excess, &tagged] {
            batch.try_push(ZCPacket::new_with_payload(frame)).unwrap();
        }
        peer_a.send_msg_by_ethernet_batch(batch).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), nic_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.payload(), accepted);
        // An external LAN can reflect this received frame into the local TAP.
        peer_b
            .send_msg_by_ethernet(ZCPacket::new_with_payload(&accepted))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), nic_a.recv())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), nic_b.recv())
                .await
                .is_err()
        );
        assert_eq!(peer_b.l2_fabric.len(), 1);
    }

    #[tokio::test]
    async fn l2_direct_nic_policy_checks_compact_ip_types() {
        for allowed_type in [0x0800, 0x86dd] {
            let (peer, _legacy_nic) = create_tap_peer_manager_with_policy(0, None, |flags| {
                flags.l2_allowed_ether_types = vec![allowed_type];
            })
            .await;
            let (send, mut receive) = futures::channel::mpsc::unbounded::<PacketBatch>();
            let _endpoint = peer.install_direct_nic_sink(Box::pin(send.sink_map_err(|error| {
                crate::tunnel::TunnelError::InvalidPacket(error.to_string())
            })));
            let mut batch = PacketBatch::new();
            for version in [4, 6] {
                let mut payload = vec![0; if version == 4 { 28 } else { 48 }];
                if version == 4 {
                    payload[0] = 0x45;
                    payload[2..4].copy_from_slice(&28_u16.to_be_bytes());
                    payload[8] = 64;
                    payload[9] = 17;
                    payload[12..16].copy_from_slice(&[10, 77, 0, 2]);
                    payload[16..20].copy_from_slice(&[10, 77, 0, 1]);
                    payload[24..26].copy_from_slice(&8_u16.to_be_bytes());
                } else {
                    payload[0] = 0x60;
                    payload[4..6].copy_from_slice(&8_u16.to_be_bytes());
                    payload[6] = 17;
                    payload[7] = 64;
                    payload[8] = 0xfd;
                    payload[23] = 2;
                    payload[24] = 0xfd;
                    payload[39] = 1;
                    payload[44..46].copy_from_slice(&8_u16.to_be_bytes());
                }
                let mut packet = ZCPacket::new_with_payload(&payload);
                packet.fill_peer_manager_hdr(42, peer.my_peer_id, PacketType::Data as u8);
                assert!(packet.set_authenticated_peer_id(42));
                assert!(packet.set_authenticated_peer_identity_type(PeerIdentityType::Admin));
                assert!(packet.set_authenticated_peer_secure_auth_level(
                    SecureAuthLevel::NetworkSecretConfirmed
                ));
                assert!(packet.set_authenticated_session_id(uuid::Uuid::new_v4()));
                batch.try_push(packet).unwrap();
            }
            peer.packet_ingress.send_batch(batch).await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(1), receive.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].payload()[0] >> 4,
                if allowed_type == 0x0800 { 4 } else { 6 }
            );
        }
    }

    #[tokio::test]
    async fn l2_known_unicast_preserves_lan_headers_and_route_rules() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(0).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let mac_a = [0x02, 0, 0, 0, 0, 1];
        let mac_b = [0x02, 0, 0, 0, 0, 2];
        peer_mgr_a
            .l2_fabric
            .learn_source(&ethernet_frame([0xff; 6], mac_b), peer_mgr_b.my_peer_id());
        let frame = ethernet_frame(mac_b, mac_a);

        peer_mgr_a
            .send_msg_by_ethernet(ZCPacket::new_with_payload(&frame))
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            received.peer_manager_header().unwrap().packet_type,
            PacketType::Ethernet as u8
        );
        assert_eq!(received.payload(), frame);
        assert_eq!(
            peer_mgr_b
                .l2_fabric
                .destination(&ethernet_frame(mac_a, mac_b)),
            Ok(crate::peers::l2_fabric::EthernetDestination::Known(
                peer_mgr_a.my_peer_id()
            ))
        );
        {
            let (a, mut nic_a) =
                create_tap_peer_manager_with_ipv4(0, Some("10.42.0.1".parse().unwrap())).await;
            let (b, mut nic_b) =
                create_tap_peer_manager_with_ipv4(0, Some("10.42.0.2".parse().unwrap())).await;
            connect_peer_manager(a.clone(), b.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            let mac_a = [2, 1, 1, 1, 1, 1];
            let mac_b = [2, 1, 1, 1, 1, 2];
            for ipv6 in [false, true] {
                for learned in [false, true] {
                    for (sender, receiver, nic, source, destination) in [
                        (&a, &b, &mut nic_b, mac_a, mac_b),
                        (&b, &a, &mut nic_a, mac_b, mac_a),
                    ] {
                        sender.l2_fabric.clear();
                        if learned {
                            sender.l2_fabric.learn_source(
                                &ethernet_frame([0xff; 6], destination),
                                receiver.my_peer_id(),
                            );
                        }
                        let mut frame = ethernet_frame(destination, source);
                        let (source_host, destination_host) =
                            if source == mac_a { (11, 12) } else { (12, 11) };
                        let ip = if ipv6 {
                            let mut bytes = vec![0; 64];
                            bytes[0] = 0x60;
                            bytes[4..6].copy_from_slice(&24_u16.to_be_bytes());
                            bytes[6] = 17;
                            bytes[7] = 64;
                            bytes[8..24].copy_from_slice(
                                &std::net::Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, source_host)
                                    .octets(),
                            );
                            bytes[24..40].copy_from_slice(
                                &std::net::Ipv6Addr::new(
                                    0xfd42,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    destination_host,
                                )
                                .octets(),
                            );
                            bytes
                        } else {
                            routed_ipv4_packet(
                                std::net::Ipv4Addr::new(10, 42, 0, source_host as u8),
                                std::net::Ipv4Addr::new(10, 42, 0, destination_host as u8),
                                1,
                            )
                            .payload()
                            .to_vec()
                        };
                        frame.truncate(14);
                        frame[12..14].copy_from_slice(
                            &(if ipv6 { 0x86dd_u16 } else { 0x0800 }).to_be_bytes(),
                        );
                        frame.extend_from_slice(&ip);
                        sender
                            .send_msg_by_hybrid_ethernet_batch(PacketBatch::singleton(
                                ZCPacket::new_with_payload(&frame),
                            ))
                            .await
                            .unwrap();
                        let received = tokio::time::timeout(Duration::from_secs(5), nic.recv())
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(received.payload(), frame, "ipv6={ipv6}, learned={learned}");
                    }
                }
            }
            let (exit, mut nic_exit) =
                create_tap_peer_manager_with_ipv4(0, Some("10.42.0.3".parse().unwrap())).await;
            connect_peer_manager(a.clone(), exit.clone()).await;
            wait_route_appear(a.clone(), exit.clone()).await.unwrap();
            a.exit_nodes
                .store(Arc::new(vec!["10.42.0.3".parse().unwrap()]));
            a.l2_fabric
                .learn_source(&ethernet_frame([0xff; 6], mac_b), b.my_peer_id());
            let mut frame = ethernet_frame(mac_b, mac_a);
            frame.truncate(14);
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame.extend_from_slice(
                routed_ipv4_packet(
                    "192.0.2.11".parse().unwrap(),
                    "192.0.2.12".parse().unwrap(),
                    2,
                )
                .payload(),
            );
            a.send_msg_by_hybrid_ethernet_batch(PacketBatch::singleton(
                ZCPacket::new_with_payload(&frame),
            ))
            .await
            .unwrap();
            let received = tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.payload(), frame);
            assert!(!received.peer_manager_header().unwrap().is_exit_node());
            assert!(
                tokio::time::timeout(Duration::from_millis(100), nic_exit.recv())
                    .await
                    .is_err()
            );
            a.service_routes.replace_source(
                crate::peers::service_route::RouteSource::Bgp,
                vec![ServiceRoute {
                    prefix: "192.0.2.0/24".parse().unwrap(),
                    gateway: 0,
                    preference: 100,
                    metric: 0,
                    path_id: 1,
                    action: ServiceRouteAction::Blackhole,
                }],
            );
            a.send_msg_by_hybrid_ethernet_batch(PacketBatch::singleton(
                ZCPacket::new_with_payload(&frame),
            ))
            .await
            .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), nic_b.recv())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn l2_batch_groups_known_unicast_and_preserves_per_peer_order() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(0).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        let (peer_mgr_c, mut nic_c) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let mac_a = [0x02, 0, 0, 0, 0, 1];
        let mac_b = [0x02, 0, 0, 0, 0, 2];
        let mac_c = [0x02, 0, 0, 0, 0, 3];
        peer_mgr_a
            .l2_fabric
            .learn_source(&ethernet_frame([0xff; 6], mac_b), peer_mgr_b.my_peer_id());
        peer_mgr_a
            .l2_fabric
            .learn_source(&ethernet_frame([0xff; 6], mac_c), peer_mgr_c.my_peer_id());

        let mut batch = PacketBatch::new();
        for (destination, marker) in [(mac_b, 1_u8), (mac_c, 2), (mac_b, 3), (mac_c, 4)] {
            let mut frame = ethernet_frame(destination, mac_a);
            frame[14] = marker;
            batch.try_push(ZCPacket::new_with_payload(&frame)).unwrap();
        }

        peer_mgr_a.send_msg_by_ethernet_batch(batch).await.unwrap();

        let b = tokio::time::timeout(Duration::from_secs(5), async {
            [
                nic_b.recv().await.unwrap().payload()[14],
                nic_b.recv().await.unwrap().payload()[14],
            ]
        })
        .await
        .unwrap();
        let c = tokio::time::timeout(Duration::from_secs(5), async {
            [
                nic_c.recv().await.unwrap().payload()[14],
                nic_c.recv().await.unwrap().payload()[14],
            ]
        })
        .await
        .unwrap();
        assert_eq!(b, [1, 3]);
        assert_eq!(c, [2, 4]);
    }

    #[tokio::test]
    async fn l2_unknown_or_stale_unicast_floods_to_live_bridges() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(0).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        let (peer_mgr_c, mut nic_c) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let frame = ethernet_frame([0x02, 0, 0, 0, 0, 99], [0x02, 0, 0, 0, 0, 1]);
        peer_mgr_a
            .send_msg_by_ethernet(ZCPacket::new_with_payload(&frame))
            .await
            .unwrap();

        for nic in [&mut nic_b, &mut nic_c] {
            let received = tokio::time::timeout(Duration::from_secs(5), nic.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.payload(), frame);
            assert_eq!(
                received.peer_manager_header().unwrap().packet_type,
                PacketType::Ethernet as u8
            );
        }
        {
            let (a, _nic_a) = create_tap_peer_manager(0).await;
            let (b, mut nic_b) = create_tap_peer_manager(0).await;
            connect_peer_manager(a.clone(), b.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            let mac = [2, 1, 1, 1, 1, 2];
            a.l2_fabric.learn_source(
                &ethernet_frame([0xff; 6], mac),
                b.my_peer_id().wrapping_add(1),
            );
            let frame = ethernet_frame(mac, [2, 1, 1, 1, 1, 1]);
            a.send_msg_by_ethernet(ZCPacket::new_with_payload(&frame))
                .await
                .unwrap();
            let received = tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.payload(), frame);
        }

        {
            use crate::peers::l2_fabric::EthernetDestination;
            let (a, _nic_a) = create_tap_peer_manager(0).await;
            let (b, _nic_b) = create_tap_peer_manager(0).await;
            connect_peer_manager(a.clone(), b.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            let local_mac = [2, 1, 1, 1, 1, 1];
            let remote_mac = [2, 1, 1, 1, 1, 2];
            let learned = ethernet_frame([0xff; 6], remote_mac);
            a.l2_fabric.learn_source(&learned, b.my_peer_id());
            a.l2_fabric
                .learn_source(&ethernet_frame([0xff; 6], local_mac), a.my_peer_id());
            assert!(a.peers.revoke_bridge_route_evidence(b.my_peer_id(), None));
            assert_eq!(
                a.l2_fabric
                    .destination(&ethernet_frame(remote_mac, local_mac)),
                Ok(EthernetDestination::Flood)
            );
            // A source replacement withdraws routes without removing a direct connection.
            a.l2_fabric.learn_source(&learned, b.my_peer_id());
            a.peers
                .install_forwarding_snapshot_source()
                .unwrap()
                .revoke();
            assert_eq!(
                a.l2_fabric
                    .destination(&ethernet_frame(remote_mac, local_mac)),
                Ok(EthernetDestination::Flood)
            );
            assert_eq!(
                a.l2_fabric
                    .destination(&ethernet_frame(local_mac, remote_mac)),
                Ok(EthernetDestination::Known(a.my_peer_id()))
            );
        }
    }

    #[tokio::test]
    async fn l2_flood_budgets_limit_output_and_ingress() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(1).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let frame = ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]);
        assert!(matches!(
            peer_mgr_a
                .send_msg_by_ethernet(ZCPacket::new_with_payload(&frame))
                .await,
            Err(crate::common::error::Error::L2FloodRateLimited)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), nic_b.recv())
                .await
                .is_err()
        );
        {
            let (a, _nic_a) = create_tap_peer_manager(0).await;
            let (b, mut nic_b) = create_tap_peer_manager(100).await;
            connect_peer_manager(a.clone(), b.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            let frame = ethernet_frame([0xff; 6], [2, 1, 1, 1, 1, 1]);
            let mut batch = PacketBatch::new();
            batch.try_push(ZCPacket::new_with_payload(&frame)).unwrap();
            batch.try_push(ZCPacket::new_with_payload(&frame)).unwrap();
            a.send_msg_by_ethernet_batch(batch).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .payload(),
                frame
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), nic_b.recv())
                    .await
                    .is_err()
            );
            assert_eq!(b.l2_counters().ingress_flood_drops, 1);
        }
    }

    #[tokio::test]
    async fn l2_fanout_budget_rejects_unknown_broadcast_and_multicast_before_send() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(100).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        let (peer_mgr_c, mut nic_c) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        for destination in [[0x02, 0, 0, 0, 0, 99], [0xff; 6], [0x01, 0, 0x5e, 1, 2, 3]] {
            assert!(matches!(
                peer_mgr_a
                    .send_msg_by_ethernet(ZCPacket::new_with_payload(&ethernet_frame(
                        destination,
                        [0x02, 0, 0, 0, 0, 1],
                    )))
                    .await,
                Err(crate::common::error::Error::L2FloodRateLimited)
            ));
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(200), nic_b.recv())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), nic_c.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn l2_fanout_budget_allows_all_recipients_when_within_budget() {
        let (peer_mgr_a, _nic_a) = create_tap_peer_manager(1_000_000).await;
        let (peer_mgr_b, mut nic_b) = create_tap_peer_manager(0).await;
        let (peer_mgr_c, mut nic_c) = create_tap_peer_manager(0).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let frame = ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]);
        peer_mgr_a
            .send_msg_by_ethernet(ZCPacket::new_with_payload(&frame))
            .await
            .unwrap();

        let received_b = tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
            .await
            .unwrap()
            .unwrap();
        let received_c = tokio::time::timeout(Duration::from_secs(5), nic_c.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_b.payload(), frame);
        assert_eq!(received_c.payload(), frame);
    }

    #[tokio::test]
    async fn l2_encrypted_or_compressed_packet_never_reaches_nic_before_decode() {
        let (peer_mgr, mut nic) = create_tap_peer_manager(0).await;
        let mut packet =
            ZCPacket::new_with_payload(&ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]));
        packet.fill_peer_manager_hdr(7, peer_mgr.my_peer_id(), PacketType::Ethernet as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(true);

        peer_mgr
            .peers
            .send_msg_directly(packet, peer_mgr.my_peer_id())
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), nic.recv())
                .await
                .is_err()
        );
    }

    fn ethernet_route(
        peer_id: PeerId,
        ethernet_input: bool,
        hybrid_l3: bool,
        bridge_input: bool,
        is_credential_peer: bool,
    ) -> ForwardingPeerInfo {
        ForwardingPeerInfo {
            peer_id,
            feature_flag: Some(crate::proto::common::PeerFeatureFlag {
                ethernet_input,
                hybrid_l3,
                bridge_input,
                is_credential_peer,
                ..Default::default()
            }),
            bridge_authorized: bridge_input && !is_credential_peer,
            ..Default::default()
        }
    }

    #[test]
    fn ethernet_peer_selection_requires_capability_and_deduplicates() {
        let routes = ForwardingPeerTable::new(vec![
            ethernet_route(1, true, true, true, false),
            ethernet_route(2, false, false, false, false),
            ethernet_route(3, true, true, true, false),
            ethernet_route(1, true, true, true, false),
            ethernet_route(4, true, true, true, false),
        ]);

        assert_eq!(PeerManager::select_ethernet_peers(&routes, 3), vec![1, 4]);
    }
}
