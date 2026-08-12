use anyhow::Context;
use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use futures::SinkExt;
use parking_lot::RwLock as SyncRwLock;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use quanta::Instant;
use smallvec::SmallVec;
use std::collections::BTreeSet;
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock, Weak, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use tokio::sync::{Mutex, RwLock};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};

use crate::{
    common::{
        PeerId,
        compressor::{Compressor as _, DefaultCompressor},
        constants::LOWTIER_VERSION,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        shrink_dashmap,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
    },
    peers::{
        PeerPacketFilter,
        flow::{
            classify_packet_flow, is_critical_l2_control, split_packet_batch_by_flow_shard,
            stamp_packet_flow,
        },
        l2_fabric::{EthernetDestination, L2DestinationBatch, L2Fabric, L2SourceBatch},
        peer_conn::PeerConn,
        peer_rpc::PeerRpcManagerTransport,
        peer_session::PeerSessionStore,
        recv_packet_batch_from_chan,
        route_trait::{ForeignNetworkRouteInfoMap, MockRoute, NextHopPolicy, RouteInterface},
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
            RouteForeignNetworkSummary,
        },
    },
    tunnel::{
        self, PacketBatchSink, Tunnel, TunnelConnector, TunnelError,
        batch::PacketBatch,
        packet_def::{CompressorAlgo, PEER_MANAGER_HEADER_SIZE, PacketType, ZCPacket},
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
    if header.packet_type == PacketType::Ethernet as u8
        && (header.is_critical_l2_control() || is_critical_l2_control(packet.payload()))
    {
        return false;
    }
    matches!(
        header.packet_type,
        packet_type
            if packet_type == PacketType::Data as u8
                || packet_type == PacketType::ForeignNetworkPacket as u8
                || packet_type == PacketType::KcpSrc as u8
                || packet_type == PacketType::KcpDst as u8
                || packet_type == PacketType::QuicSrc as u8
                || packet_type == PacketType::QuicDst as u8
                || packet_type == PacketType::DataWithKcpSrcModified as u8
                || packet_type == PacketType::DataWithQuicSrcModified as u8
                || packet_type == PacketType::Ethernet as u8
                || packet_type == PacketType::AlternateFecSource as u8
                || packet_type == PacketType::AlternateFecParity as u8
    )
}

fn apply_local_route_policy(packet: &mut ZCPacket, speed_first: bool, latency_first: bool) {
    let use_speed = speed_first && packet_supports_speed_first(packet);
    let header = packet.mut_peer_manager_header().unwrap();
    header.set_speed_first(use_speed);
    if !use_speed {
        header.set_latency_first(latency_first || speed_first);
    }
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
    create_packet_recv_chan,
    encrypt::{Encryptor, NullCipher},
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{ForeignNetworkManager, GlobalForeignNetworkAccessor},
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    peer_task::ExternalTaskSignal,
    relay_peer_map::RelayPeerMap,
    route_trait::{ArcRoute, Route},
};

struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<dyn Encryptor>,
    is_secure_mode_enabled: bool,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        let peers = self.peers.upgrade().ok_or(Error::Unknown)?;
        // NOTE: if route info is not exchanged, this will return None. treat it as public server.
        let is_dst_peer_public_server = peers
            .get_route_peer_info(dst_peer_id)
            .await
            .and_then(|x| x.feature_flag.map(|x| x.is_public_server))
            // if dst is directly connected, it's must not public server
            .unwrap_or(!peers.has_peer(dst_peer_id));
        if !is_dst_peer_public_server && !self.is_secure_mode_enabled {
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
        }
        // send to self and this packet will be forwarded in peer_recv loop
        peers.send_msg_directly(msg, self.my_peer_id).await
    }

    async fn recv(&self) -> Result<ZCPacket, Error> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
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
}

struct EthernetBatchInput {
    packet: ZCPacket,
    destination_peer_id: Option<PeerId>,
    is_exit_node: bool,
    suppress_local_delivery: bool,
}

type EthernetBatchInputs = SmallVec<[EthernetBatchInput; 4]>;

struct OrderedPeerBatch {
    peer_id: PeerId,
    packets: PacketBatch,
    mark_recent: bool,
}

type OrderedPeerBatches = SmallVec<[OrderedPeerBatch; 2]>;

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
    batch
        .iter()
        .all(|packet| {
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
    let is_ethernet = packet_type == PacketType::Ethernet as u8;
    if is_ethernet && !ethernet_input {
        return None;
    }

    for packet in batch {
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

static BATCH_QUEUE_DISABLED: OnceLock<bool> = OnceLock::new();

fn batch_queue_disabled() -> bool {
    *BATCH_QUEUE_DISABLED
        .get_or_init(|| std::env::var_os("LOWTIER_DEBUG_DISABLE_BATCH_QUEUE").is_some())
}

static FLOW_SHARD_SPLIT_ENABLED: OnceLock<bool> = OnceLock::new();

fn flow_shard_split_enabled() -> bool {
    *FLOW_SHARD_SPLIT_ENABLED
        .get_or_init(|| std::env::var_os("LOWTIER_ENABLE_FLOW_SHARD_SPLIT").is_some())
}

#[derive(Clone, Copy)]
enum L2TunBatchRoute {
    Direct {
        destination_peer_id: PeerId,
        is_exit_node: bool,
    },
    Flood,
    Drop,
}

fn push_ordered_peer_batch(
    peer_batches: &mut OrderedPeerBatches,
    peer_id: PeerId,
    packet: ZCPacket,
    mark_recent: bool,
) {
    if let Some(peer_batch) = peer_batches
        .iter_mut()
        .find(|batch| batch.peer_id == peer_id)
    {
        peer_batch.mark_recent |= mark_recent;
        peer_batch
            .packets
            .try_push(packet)
            .expect("a per-peer group cannot exceed its bounded ingress batch");
        return;
    }

    let mut peer_batch = PacketBatch::new();
    peer_batch
        .try_push(packet)
        .expect("a new per-peer group accepts its first packet");
    peer_batches.push(OrderedPeerBatch {
        peer_id,
        packets: peer_batch,
        mark_recent,
    });
}

fn prepare_packet_batch(
    compress_algo: CompressorAlgo,
    mut batch: PacketBatch,
) -> Result<PacketBatch, Error> {
    let compressor = DefaultCompressor {};
    for packet in batch.iter_mut() {
        stamp_packet_flow(packet);
        compressor
            .compress(packet, compress_algo)
            .with_context(|| "compress failed")?;
    }
    Ok(batch)
}

pub(crate) struct DirectNicEndpoint {
    sink: Mutex<std::pin::Pin<Box<dyn PacketBatchSink>>>,
}

#[derive(Default)]
struct DirectNicBatchWriter {
    endpoint: SyncRwLock<Weak<DirectNicEndpoint>>,
}

impl DirectNicBatchWriter {
    fn install(&self, sink: std::pin::Pin<Box<dyn PacketBatchSink>>) -> Arc<DirectNicEndpoint> {
        let endpoint = Arc::new(DirectNicEndpoint {
            sink: Mutex::new(sink),
        });
        *self.endpoint.write() = Arc::downgrade(&endpoint);
        endpoint
    }

    fn current_endpoint(&self) -> Option<Arc<DirectNicEndpoint>> {
        self.endpoint.read().upgrade()
    }

    async fn send_to(
        endpoint: Arc<DirectNicEndpoint>,
        batch: PacketBatch,
    ) -> Result<(), TunnelError> {
        let mut sink = endpoint.sink.lock().await;
        sink.send(batch).await
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

        let mut source_batch = L2SourceBatch::default();
        let Some((from_peer_id, packet_type)) = inspect_direct_nic_batch(
            &batch,
            self.my_peer_id,
            self.ethernet_input,
            &mut |frame, peer_id| {
                source_batch.record(frame, peer_id);
            },
        ) else {
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

        if packet_type == PacketType::Ethernet as u8 {
            self.l2_fabric
                .learn_source_batch_at(source_batch, std::time::Instant::now());
        }
        // Stamp flow shards once so multiqueue TUN writers fan out by flow.
        for packet in batch.iter_mut() {
            stamp_packet_flow(packet);
        }
        let bytes = batch.buffer_byte_len() as u64;
        let packets = batch.len() as u64;
        self.self_rx_bytes.add(bytes);
        self.self_rx_packets.add(packets);
        self.compress_rx_bytes_before.add(bytes);
        self.compress_rx_bytes_after.add(bytes);
        if !self
            .traffic_metrics
            .try_record_rx_batch(from_peer_id, packet_type, bytes, packets)
        {
            self.traffic_metrics
                .record_rx_batch(from_peer_id, packet_type, bytes, packets)
                .await;
        }

        if let Err(error) = DirectNicBatchWriter::send_to(endpoint, batch).await {
            tracing::error!(?error, "send direct packet batch to NIC failed");
        }
        Ok(())
    }
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

    encryptor: Arc<dyn Encryptor + 'static>,
    data_compress_algo: CompressorAlgo,
    l2_fabric: Arc<L2Fabric>,

    exit_nodes: RwLock<Vec<IpAddr>>,

    reserved_my_peer_id_map: DashMap<String, PeerId>,
    recent_have_traffic: Arc<DashMap<PeerId, Instant>>,
    recent_data_traffic: Arc<DashMap<PeerId, Instant>>,
    p2p_demand_notify: Arc<ExternalTaskSignal>,

    allow_loopback_tunnel: AtomicBool,

    self_tx_counters: SelfTxCounters,
    traffic_metrics: Arc<TrafficMetricRecorder>,

    peer_session_store: Arc<PeerSessionStore>,
    is_secure_mode_enabled: bool,
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
    // Keep lazy-p2p demand alive across the 5s task rescan interval and a full on-demand
    // connect attempt, without retaining extra per-task state in the hot path.
    const RECENT_HAVE_TRAFFIC_TTL: Duration = Duration::from_secs(30);

    fn should_mark_recent_traffic_for_fanout(total_dst_peers: usize) -> bool {
        total_dst_peers <= 1
    }

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

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let packet_ingress = packet_send.clone();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));
        let peer_session_store = Arc::new(PeerSessionStore::new());

        let encryptor = if global_ctx.get_flags().enable_encryption {
            // 只有在启用加密时才使用工厂函数选择算法
            let algorithm = &global_ctx.get_flags().encryption_algorithm;
            super::encrypt::create_encryptor(
                algorithm,
                global_ctx.get_128_key(),
                global_ctx.get_256_key(),
            )
        } else {
            // disable_encryption = true 时使用 NullCipher
            Arc::new(NullCipher)
        };

        if global_ctx
            .check_network_in_whitelist(&global_ctx.get_network_name())
            .is_err()
        {
            // if local network is not in whitelist, avoid relay data when exist any other route path
            global_ctx.set_avoid_relay_data_preference(true);
        }

        let is_secure_mode_enabled = global_ctx
            .config
            .get_secure_mode()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);

        // TODO: remove these because we have impl pipeline processor.
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let rpc_tspt = Arc::new(RpcTransport {
            my_peer_id,
            peers: Arc::downgrade(&peers),
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
            encryptor: encryptor.clone(),
            is_secure_mode_enabled,
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

        let data_compress_algo = global_ctx
            .get_flags()
            .data_compress_algo()
            .try_into()
            .expect("invalid data compress algo, maybe some features not enabled");
        let l2_flags = global_ctx.get_flags();
        let l2_fabric = Arc::new(L2Fabric::new(
            l2_flags.l2_fdb_capacity as usize,
            Duration::from_secs(l2_flags.l2_fdb_age_seconds),
            l2_flags.l2_flood_bps,
        ));

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

            encryptor,
            data_compress_algo,
            l2_fabric,

            exit_nodes: RwLock::new(exit_nodes),

            reserved_my_peer_id_map: DashMap::new(),
            recent_have_traffic: Arc::new(DashMap::new()),
            recent_data_traffic: Arc::new(DashMap::new()),
            p2p_demand_notify: Arc::new(ExternalTaskSignal::new()),

            allow_loopback_tunnel: AtomicBool::new(true),

            self_tx_counters,
            traffic_metrics,

            peer_session_store,
            is_secure_mode_enabled,
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

    fn gc_recent_traffic(&self) {
        Self::gc_recent_traffic_entries(&self.recent_have_traffic, Instant::now(), |peer_id| {
            self.has_directly_connected_conn(peer_id)
        });
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
            async fn list_global_foreign_peer(
                &self,
                network_identity: &NetworkIdentity,
            ) -> Vec<PeerId> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                peer_map
                    .list_peers_own_foreign_network(network_identity)
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

        // For credential nodes, network_secret_digest is either None or all-zeros
        // (all-zeros when received over the wire via handshake).
        // In this case, only compare network_name.
        let my_digest_empty = my_identity
            .network_secret_digest
            .as_ref()
            .is_none_or(|d| d.iter().all(|b| *b == 0));
        let peer_digest_empty = peer_identity
            .network_secret_digest
            .as_ref()
            .is_none_or(|d| d.iter().all(|b| *b == 0));

        let identity_ok = if my_digest_empty || peer_digest_empty {
            // Credential node: only check network_name
            my_identity.network_name == peer_identity.network_name
        } else {
            my_identity == peer_identity
        };

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
        // we already filter out the connection in tcp/quic/kcp proxy so no need check here.
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
        let handshake_ret = conn.do_handshake_as_server_ext(|peer, network_name:&str| {
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
                peer_id = Some(*self.reserved_my_peer_id_map.entry(network_name.to_string()).or_insert_with(|| {
                    rand::random::<PeerId>()
                }).value());
            }
            peer.set_peer_id(peer_id.unwrap());

            tracing::info!(
                ?peer_id,
                ?network_name,
                "handshake as server with foreign network, new peer id: {}, peer id in foreign manager: {:?}",
                peer.get_my_peer_id(), peer_id
            );

            Ok(())
        })
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
        let trusted_foreign_credential =
            matches!(conn.get_peer_identity_type(), PeerIdentityType::Credential)
                && self
                    .foreign_network_manager
                    .is_existing_credential_pubkey_trusted(
                        &peer_network_name,
                        &conn.get_conn_info().noise_remote_static_pubkey,
                    );
        let foreign_network_allowed =
            conn.matches_local_network_secret() || trusted_foreign_credential;

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
        foreign_network_mgr: &ForeignNetworkManager,
        disable_relay_data: bool,
    ) -> Result<(), ZCPacket> {
        let pm_header = packet.peer_manager_header().unwrap();
        let from_peer_id = pm_header.from_peer_id.get();
        let to_peer_id = pm_header.to_peer_id.get();

        if disable_relay_data && Self::is_relay_data_zc_packet(&packet) {
            tracing::debug!(
                ?from_peer_id,
                ?to_peer_id,
                inner_packet_type = ?packet.foreign_network_inner_packet_type(),
                "drop foreign network relay data while relay data is disabled"
            );
            return Ok(());
        }

        let foreign_hdr = packet.foreign_network_hdr().unwrap();
        let foreign_network_name = foreign_hdr.get_network_name(packet.payload());
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

        // NOTICE: the to peer id is modified by the src from foreign network my peer id to the origin my peer id
        if to_peer_id == my_peer_id {
            // packet sent from other peer to me, extract the inner packet and forward it
            add_counter(
                MetricName::TrafficBytesForeignForwardRx,
                MetricName::TrafficPacketsForeignForwardRx,
            );
            if let Err(e) = foreign_network_mgr
                .forward_foreign_network_packet(
                    &foreign_network_name,
                    foreign_peer_id,
                    packet.foreign_network_packet(),
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
        } else if Some(from_peer_id) == foreign_network_my_peer_id {
            // to_peer_id is my peer id for the foreign network, need to convert to the origin my_peer_id of dst
            let Some(to_peer_id) = peer_map
                .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
                .await
            else {
                tracing::debug!(
                    ?foreign_network_name,
                    ?to_peer_id,
                    "cannot find origin my peer id for foreign network."
                );
                return Err(packet);
            };

            add_counter(
                MetricName::TrafficBytesForeignForwardTx,
                MetricName::TrafficPacketsForeignForwardTx,
            );

            // modify the to_peer id from foreign network my peer id to the origin my peer id
            packet
                .mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(to_peer_id);

            // packet is generated from foreign network mgr and should be forward to other peer
            if let Err(e) = peer_map
                .send_msg(packet, to_peer_id, NextHopPolicy::LeastHop)
                .await
            {
                tracing::debug!(
                    ?e,
                    ?to_peer_id,
                    "send_msg_directly failed when forward local generated foreign network packet"
                );
            }
            Ok(())
        } else {
            // target is not me, forward it. try get origin peer id
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
        let encryptor = self.encryptor.clone();
        let compress_algo = self.data_compress_algo;
        let acl_filter = self.global_ctx.get_acl_filter().clone();
        let global_ctx = self.global_ctx.clone();
        let secure_mode_enabled = self.is_secure_mode_enabled;
        let stats_mgr = self.global_ctx.stats_manager().clone();
        let route = self.get_route();
        let is_credential_node = self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none()
            && secure_mode_enabled;

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
            while let Ok(batch) = recv_packet_batch_from_chan(&mut recv).await {
                let disable_relay_data = global_ctx.flags_arc().disable_relay_data;
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
                    let mut local_batch = PacketBatch::new();
                    let mut local_rx_bytes = 0_u64;
                    let mut local_rx_packets = 0_u64;
                    let mut compression_rx_before = 0_u64;
                    let mut compression_rx_after = 0_u64;
                    let mut rx_metric_batches: SmallVec<[(PeerId, u8, u64, u64); 4]> =
                        SmallVec::new();
                    for mut ret in batch {
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
                        let (from_peer_id, to_peer_id, packet_type, is_encrypted) =
                            if is_foreign_network_packet_type(initial_metadata.2) {
                                let Err(foreign_packet) = Self::handle_foreign_network_packet(
                                    ret,
                                    my_peer_id,
                                    &peers,
                                    &foreign_mgr,
                                    disable_relay_data,
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
                            from_peer_id,
                        )
                        .await
                        {
                            tracing::warn!(
                                from_peer_id,
                                "drop ethernet packet from suppressed credential peer"
                            );
                            continue;
                        }
                        if to_peer_id != my_peer_id {
                            if disable_relay_data && is_relay_data_packet {
                                tracing::debug!(
                                    ?from_peer_id,
                                    ?to_peer_id,
                                    packet_type,
                                    "drop forwarded relay data while relay data is disabled"
                                );
                                continue;
                            }

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

                            if header.forward_counter > 2 && header.is_latency_first() {
                                tracing::trace!(
                                    ?header,
                                    "set_latency_first false because too many hop"
                                );
                                header.set_speed_first(false).set_latency_first(false);
                            }

                            header.forward_counter += 1;

                            if from_peer_id == my_peer_id {
                                compress_tx_bytes_before.add(buf_len as u64);

                                if packet_type == PacketType::Data as u8
                                    || packet_type == PacketType::Ethernet as u8
                                    || packet_type == PacketType::KcpSrc as u8
                                    || packet_type == PacketType::KcpDst as u8
                                {
                                    let _ = Self::try_compress(compress_algo, &mut ret);
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
                            if packet_type == PacketType::RelayHandshake as u8
                                || packet_type == PacketType::RelayHandshakeAck as u8
                            {
                                let _ = relay_peer_map.handle_handshake_packet(ret).await;
                                continue;
                            }
                            if !secure_mode_enabled && is_encrypted {
                                if let Err(e) = encryptor.decrypt(&mut ret) {
                                    tracing::error!(?e, "decrypt failed");
                                    continue;
                                }
                            } else if is_encrypted {
                                match relay_peer_map.decrypt_if_needed(&mut ret).await {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        tracing::error!("secure session not found");
                                        continue;
                                    }
                                    Err(e) => {
                                        tracing::error!(?e, "secure decrypt failed");
                                        continue;
                                    }
                                }
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

                            let compressor = DefaultCompressor {};
                            if let Err(e) = compressor.decompress(&mut ret) {
                                tracing::error!(?e, "decompress failed");
                                continue;
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
            ethernet_input: bool,
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
                    self.l2_fabric
                        .learn_source_at(packet.payload(), from_peer_id, now);
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

            async fn try_process_batch_from_peer(&self, batch: PacketBatch) -> PacketBatch {
                let batch_time = std::time::Instant::now();
                let mut source_batch = L2SourceBatch::default();
                if prepare_direct_nic_batch(&batch, self.ethernet_input, |frame, peer_id| {
                    source_batch.record(frame, peer_id);
                }) {
                    self.l2_fabric
                        .learn_source_batch_at(source_batch, batch_time);
                    tracing::trace!(
                        packets = batch.len(),
                        "send owned packet batch to nic channel"
                    );
                    let _ = self.nic_channel.send_batch(batch).await;
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
            ethernet_input: self.global_ctx.get_feature_flags().ethernet_input,
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            fn is_interested_in_direct_nic_batch(&self, _batch: &PacketBatch) -> bool {
                false
            }

            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if is_peer_rpc_packet_type(hdr.packet_type) {
                    self.peer_rpc_tspt_sender.send(packet).unwrap();
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
                        self.peer_rpc_tspt_sender.send(packet).unwrap();
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
        struct Interface {
            my_peer_id: PeerId,
            peers: Weak<PeerMap>,
            foreign_network_client: Weak<ForeignNetworkClient>,
            foreign_network_manager: Weak<ForeignNetworkManager>,
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

            async fn close_peer(&self, peer_id: PeerId) {
                if let Some(peer_map) = self.peers.upgrade() {
                    let _ = peer_map.close_peer(peer_id).await;
                }

                if let Some(foreign_client) = self.foreign_network_client.upgrade() {
                    let _ = foreign_client.get_peer_map().close_peer(peer_id).await;
                }
            }

            async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
                let peer_map = self.peers.upgrade()?;
                peer_map.get_peer_public_key(peer_id)
            }

            async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
                let peer_map = self.peers.upgrade()?;
                peer_map.get_peer_identity_type(peer_id)
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
                        },
                    );
                }
                ret
            }
        }

        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(Box::new(Interface {
                my_peer_id,
                peers: Arc::downgrade(&self.peers),
                foreign_network_client: Arc::downgrade(&self.foreign_network_client),
                foreign_network_manager: Arc::downgrade(&self.foreign_network_manager),
            }))
            .await
            .unwrap();

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route(arc_route).await;
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

    async fn run_nic_packet_process_pipeline(&self, data: &mut ZCPacket) -> bool {
        if data
            .peer_manager_header()
            .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
        {
            // L3 proxy filters do not inspect transparent Ethernet frames.
            return true;
        }

        // Enforce ACL for outbound (NIC-originated) packets. If ACL denies, stop processing.
        if !self.global_ctx.get_acl_filter().process_packet_with_acl(
            data,
            false,
            None,
            |_| false,
            &self.get_route(),
        ) {
            return false;
        }

        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            let _ = pipeline.try_process_packet_from_nic(data).await;
        }

        true
    }

    async fn run_nic_packet_process_pipeline_batch(&self, batch: PacketBatch) -> PacketBatch {
        let mut batch = self
            .global_ctx
            .get_acl_filter()
            .process_packet_batch_with_acl(batch, false, None, |_| false, &self.get_route());
        if batch.is_empty() {
            return batch;
        }

        let pipelines = self.nic_packet_process_pipeline.read().await;
        for pipeline in pipelines.iter().rev() {
            batch = pipeline.try_process_batch_from_nic(batch).await;
            if batch.is_empty() {
                break;
            }
        }
        batch
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

    fn get_next_hop_policy(header: &crate::tunnel::packet_def::PeerManagerHeader) -> NextHopPolicy {
        if header.is_speed_first() {
            NextHopPolicy::MaxGoodput
        } else if header.is_latency_first() {
            NextHopPolicy::LeastCost
        } else {
            NextHopPolicy::LeastHop
        }
    }

    fn get_local_data_policy(&self) -> NextHopPolicy {
        if self.global_ctx.speed_first() {
            NextHopPolicy::MaxGoodput
        } else if self.global_ctx.latency_first() {
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

        Self::try_compress(self.data_compress_algo, &mut msg)?;

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

    /// Send a complete Ethernet frame through the existing peer, relay, compression, and
    /// encryption stack. Known unicast uses one FDB lookup; unknown and multicast frames are
    /// replicated only to peers that announced TAP capability.
    pub async fn send_msg_by_ethernet(&self, msg: ZCPacket) -> Result<(), Error> {
        self.send_msg_by_ethernet_to_peer(msg, None, false, false)
            .await
    }

    pub async fn send_msg_by_ethernet_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let batch = match batch.pop_singleton() {
            Ok(packet) => return self.send_msg_by_ethernet(packet).await,
            Err(batch) => batch,
        };
        self.send_msg_by_ethernet_batch_to_peer(batch, None, false, false)
            .await
    }

    pub(crate) async fn send_ethernet_to_peer(
        &self,
        msg: ZCPacket,
        destination_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.send_msg_by_ethernet_to_peer(msg, Some(destination_peer_id), false, false)
            .await
    }

    async fn send_msg_by_ethernet_to_peer(
        &self,
        mut msg: ZCPacket,
        destination_peer_id: Option<PeerId>,
        is_exit_node: bool,
        suppress_local_delivery: bool,
    ) -> Result<(), Error> {
        msg.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
        {
            let header = msg.mut_peer_manager_header().unwrap();
            if let Some(peer_id) = destination_peer_id {
                header.to_peer_id.set(peer_id);
            }
            header.set_exit_node(is_exit_node);
            if suppress_local_delivery {
                header.set_not_send_to_tun(true);
                header.set_no_proxy(true);
            }
        }
        if !self.run_nic_packet_process_pipeline(&mut msg).await {
            return Ok(());
        }

        let overridden_dst = msg.peer_manager_header().unwrap().to_peer_id.get();
        let (dst_peers, known_unicast) = if overridden_dst != 0 {
            (vec![overridden_dst], true)
        } else {
            match self
                .l2_fabric
                .destination(msg.payload())
                .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))?
            {
                EthernetDestination::Known(peer_id) => (vec![peer_id], true),
                EthernetDestination::Flood => {
                    let peers = Self::select_ethernet_peers(
                        &self.peers.list_route_infos().await,
                        self.my_peer_id,
                    );
                    if peers.is_empty() {
                        return Ok(());
                    }
                    if !self.l2_fabric.allow_flood(msg.payload_len()) {
                        return Err(Error::L2FloodRateLimited);
                    }
                    (peers, false)
                }
            }
        };

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);
        Self::try_compress(self.data_compress_algo, &mut msg)?;
        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        apply_local_route_policy(
            &mut msg,
            self.global_ctx.speed_first(),
            self.global_ctx.latency_first(),
        );

        let mut errors = Vec::new();
        let total_dst_peers = dst_peers.len();
        let mut msg = Some(msg);
        for (index, peer_id) in dst_peers.iter().enumerate() {
            if known_unicast {
                self.mark_recent_traffic(*peer_id);
            }
            if let Err(error) = self.check_p2p_only_before_send(*peer_id) {
                errors.push(error);
                continue;
            }

            let mut per_peer_msg = if index + 1 == total_dst_peers {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };
            per_peer_msg
                .mut_peer_manager_header()
                .unwrap()
                .to_peer_id
                .set(*peer_id);
            let msg_len = per_peer_msg.buf_len() as u64;

            match Self::send_msg_internal(
                &self.peers,
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                per_peer_msg,
                *peer_id,
            )
            .await
            {
                Ok(()) => {
                    self.self_tx_counters.self_tx_bytes.add(msg_len);
                    self.self_tx_counters.self_tx_packets.inc();
                }
                Err(error) => errors.push(error),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("ethernet frame delivery failed: {errors:?}").into())
        }
    }

    async fn send_msg_by_ethernet_batch_to_peer(
        &self,
        batch: PacketBatch,
        destination_peer_id: Option<PeerId>,
        is_exit_node: bool,
        suppress_local_delivery: bool,
    ) -> Result<(), Error> {
        let batch = match batch.pop_singleton() {
            Ok(packet) => {
                return self
                    .send_msg_by_ethernet_to_peer(
                        packet,
                        destination_peer_id,
                        is_exit_node,
                        suppress_local_delivery,
                    )
                    .await;
            }
            Err(batch) => batch,
        };
        let inputs = batch.into_iter().map(|packet| EthernetBatchInput {
            packet,
            destination_peer_id,
            is_exit_node,
            suppress_local_delivery,
        });
        self.send_preclassified_ethernet_batch(inputs).await
    }

    async fn send_preclassified_ethernet_batch<I>(&self, inputs: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = EthernetBatchInput>,
    {
        let mut per_peer_batches = OrderedPeerBatches::new();
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
            msg.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Ethernet as u8);
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
                apply_local_route_policy(msg, speed_first, latency_first);
                push_ordered_peer_batch(&mut per_peer_batches, overridden_dst, packet, true);
                continue;
            }

            let (dst_peers, known_unicast) = match destination_batch
                .resolve_at(&self.l2_fabric, msg.payload(), fdb_batch_time)
                .map_err(|error| Error::InvalidEthernetFrame(error.to_string()))?
            {
                EthernetDestination::Known(peer_id) => (vec![peer_id], true),
                EthernetDestination::Flood => {
                    if flood_peers.is_none() {
                        flood_peers = Some(Self::select_ethernet_peers(
                            &self.peers.list_route_infos().await,
                            self.my_peer_id,
                        ));
                    }
                    let peers = flood_peers.as_ref().unwrap().clone();
                    if peers.is_empty() {
                        continue;
                    }
                    if !self.l2_fabric.allow_flood(msg.payload_len()) {
                        errors.push(Error::L2FloodRateLimited);
                        continue;
                    }
                    (peers, false)
                }
            };

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
                push_ordered_peer_batch(
                    &mut per_peer_batches,
                    peer_id,
                    per_peer_msg,
                    known_unicast,
                );
            }
        }

        self.send_ordered_peer_batches(per_peer_batches, &mut errors)
            .await?;

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("ethernet frame delivery failed: {errors:?}").into())
        }
    }

    async fn send_ordered_peer_batches(
        &self,
        peer_batches: OrderedPeerBatches,
        errors: &mut Vec<Error>,
    ) -> Result<(), Error> {
        for peer_batch in peer_batches {
            let OrderedPeerBatch {
                peer_id,
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
            self.self_tx_counters
                .compress_tx_bytes_before
                .add(peer_batch.buffer_byte_len() as u64);
            let peer_batch = prepare_packet_batch(self.data_compress_algo, peer_batch)?;
            self.self_tx_counters
                .compress_tx_bytes_after
                .add(peer_batch.buffer_byte_len() as u64);
            if batch_queue_disabled() {
                for packet in peer_batch {
                    let packet_len = packet.buf_len() as u64;
                    match Self::send_msg_internal(
                        &self.peers,
                        &self.foreign_network_client,
                        &self.relay_peer_map,
                        Some(&self.traffic_metrics),
                        packet,
                        peer_id,
                    )
                    .await
                    {
                        Ok(()) => {
                            self.self_tx_counters.self_tx_bytes.add(packet_len);
                            self.self_tx_counters.self_tx_packets.inc();
                        }
                        Err(error) => errors.push(error),
                    }
                }
                continue;
            }
            let flow_batches = if flow_shard_split_enabled() {
                split_packet_batch_by_flow_shard(peer_batch)
            } else {
                let flow = peer_batch
                    .first()
                    .map(classify_packet_flow)
                    .expect("a prepared peer vector is not empty");
                let mut intact = SmallVec::new();
                intact.push((flow, peer_batch));
                intact
            };
            for (_, flow_batch) in flow_batches {
                let msg_len = flow_batch.buffer_byte_len() as u64;
                let msg_count = flow_batch.len() as u64;
                match Self::send_msg_internal_batch(
                    &self.peers,
                    &self.foreign_network_client,
                    &self.relay_peer_map,
                    Some(&self.traffic_metrics),
                    flow_batch,
                    peer_id,
                )
                .await
                {
                    Ok(()) => {
                        self.self_tx_counters.self_tx_bytes.add(msg_len);
                        self.self_tx_counters.self_tx_packets.add(msg_count);
                    }
                    Err(error) => errors.push(error),
                }
            }
        }
        Ok(())
    }

    /// Carry an IP-only TUN edge through the Ethernet overlay. Unicast reuses the existing
    /// IP route lookup and addresses the selected peer directly; broadcast and multicast use
    /// the bounded Ethernet flood path.
    pub async fn send_msg_by_l2_tun(
        &self,
        mut msg: ZCPacket,
        ip_addr: IpAddr,
        not_send_to_self: bool,
    ) -> Result<(), Error> {
        let (destination_peers, is_exit_node) = self.get_msg_dst_peer(&ip_addr).await;
        if destination_peers.is_empty() {
            tracing::info!(%ip_addr, "no peer ID for compatible Ethernet packet");
            return Ok(());
        }

        let is_broadcast_or_multicast = match ip_addr {
            IpAddr::V4(address) => self.is_all_peers_broadcast_ipv4(&address),
            IpAddr::V6(address) => self.is_all_peers_broadcast_ipv6(&address),
        };
        if !is_broadcast_or_multicast && destination_peers.len() == 1 {
            let destination_peer_id = destination_peers[0];
            crate::instance::l2_tun::prepare_ip_frame(msg.mut_payload(), self.my_peer_id, None)
                .map_err(|error| anyhow::anyhow!(error))?;
            let suppress_local_delivery = not_send_to_self
                && destination_peer_id == self.my_peer_id
                && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr);
            self.send_msg_by_ethernet_to_peer(
                msg,
                Some(destination_peer_id),
                is_exit_node,
                suppress_local_delivery,
            )
            .await
        } else {
            crate::instance::l2_tun::prepare_ip_frame(msg.mut_payload(), self.my_peer_id, None)
                .map_err(|error| anyhow::anyhow!(error))?;
            self.send_msg_by_ethernet(msg).await
        }
    }

    pub async fn send_msg_by_l2_tun_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let mut inputs = EthernetBatchInputs::with_capacity(batch.len());
        let mut route_cache: SmallVec<[(IpAddr, L2TunBatchRoute); 4]> = SmallVec::new();
        for mut packet in batch {
            let Some(ip_packet) = packet
                .payload()
                .get(crate::instance::l2_tun::ETHERNET_HEADER_LEN..)
            else {
                return Err(anyhow::anyhow!("compatible Ethernet packet is too short").into());
            };
            let Some(version) = ip_packet.first().map(|byte| byte >> 4) else {
                continue;
            };
            let (ip_addr, not_send_to_self) = match version {
                4 => {
                    let ipv4 = Ipv4Packet::new(ip_packet).ok_or_else(|| {
                        anyhow::anyhow!("invalid compatible Ethernet IPv4 packet")
                    })?;
                    let source = ipv4.get_source();
                    (
                        IpAddr::V4(ipv4.get_destination()),
                        self.global_ctx.get_ipv4().map(|ip| ip.address()) == Some(source),
                    )
                }
                6 => {
                    let ipv6 = Ipv6Packet::new(ip_packet).ok_or_else(|| {
                        anyhow::anyhow!("invalid compatible Ethernet IPv6 packet")
                    })?;
                    let source = ipv6.get_source();
                    (
                        IpAddr::V6(ipv6.get_destination()),
                        self.global_ctx.is_ip_local_ipv6(&source),
                    )
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "unsupported compatible Ethernet IP version {version}"
                    )
                    .into());
                }
            };

            let route = if let Some((_, route)) = route_cache
                .iter()
                .find(|(cached_address, _)| *cached_address == ip_addr)
            {
                *route
            } else {
                let (destination_peers, is_exit_node) = self.get_msg_dst_peer(&ip_addr).await;
                let is_broadcast_or_multicast = match ip_addr {
                    IpAddr::V4(address) => self.is_all_peers_broadcast_ipv4(&address),
                    IpAddr::V6(address) => self.is_all_peers_broadcast_ipv6(&address),
                };
                let route = if destination_peers.is_empty() {
                    L2TunBatchRoute::Drop
                } else if !is_broadcast_or_multicast && destination_peers.len() == 1 {
                    L2TunBatchRoute::Direct {
                        destination_peer_id: destination_peers[0],
                        is_exit_node,
                    }
                } else {
                    L2TunBatchRoute::Flood
                };
                route_cache.push((ip_addr, route));
                route
            };
            if matches!(route, L2TunBatchRoute::Drop) {
                continue;
            }
            crate::instance::l2_tun::prepare_ip_frame(packet.mut_payload(), self.my_peer_id, None)
                .map_err(|error| anyhow::anyhow!(error))?;

            if let L2TunBatchRoute::Direct {
                destination_peer_id,
                is_exit_node,
            } = route
            {
                let suppress_local_delivery = not_send_to_self
                    && destination_peer_id == self.my_peer_id
                    && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr);
                inputs.push(EthernetBatchInput {
                    packet,
                    destination_peer_id: Some(destination_peer_id),
                    is_exit_node,
                    suppress_local_delivery,
                });
            } else if matches!(route, L2TunBatchRoute::Flood) {
                inputs.push(EthernetBatchInput {
                    packet,
                    destination_peer_id: None,
                    is_exit_node: false,
                    suppress_local_delivery: false,
                });
            }
        }

        self.send_preclassified_ethernet_batch(inputs).await
    }

    async fn send_msg_internal(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let policy = Self::get_next_hop_policy(msg.peer_manager_header().unwrap());
        let is_latency_first = msg.peer_manager_header().unwrap().is_latency_first();
        let packet_type = msg.peer_manager_header().unwrap().packet_type;
        if !Self::credential_ethernet_peer_is_allowed(peers, packet_type, dst_peer_id).await {
            tracing::warn!(dst_peer_id, "block suppressed credential ethernet peer");
            return Err(Error::RouteError(None));
        }
        let msg_len = msg.buf_len() as u64;
        let latency_first_gateway = if is_latency_first {
            peers
                .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), &msg)
                .await
                .filter(|gateway| *gateway != dst_peer_id)
        } else {
            None
        };
        let send_result = if let Some(gateway) = latency_first_gateway
            && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
        {
            relay_peer_map.send_msg(msg, dst_peer_id, policy).await
        } else if peers.has_peer(dst_peer_id) {
            peers.send_msg_directly(msg, dst_peer_id).await
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            foreign_network_client.send_msg(msg, dst_peer_id).await
        } else if let Some(gateway) = peers
            .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), &msg)
            .await
        {
            if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
                relay_peer_map.send_msg(msg, dst_peer_id, policy).await
            } else {
                tracing::warn!(
                    ?gateway,
                    ?dst_peer_id,
                    "cannot send msg to peer through gateway"
                );
                Err(Error::RouteError(None))
            }
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            // check foreign network again. so in happy path we can avoid extra check
            foreign_network_client.send_msg(msg, dst_peer_id).await
        } else {
            tracing::debug!(?dst_peer_id, "no gateway for peer");
            Err(Error::RouteError(None))
        };

        if send_result.is_ok()
            && let Some(metrics) = direct_tx_metrics
        {
            metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
        }

        send_result
    }

    async fn send_msg_internal_batch(
        peers: &Arc<PeerMap>,
        foreign_network_client: &Arc<ForeignNetworkClient>,
        relay_peer_map: &Arc<RelayPeerMap>,
        direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
        batch: PacketBatch,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        let header = first.peer_manager_header().unwrap();
        let is_latency_first = header.is_latency_first();
        let packet_type = header.packet_type;
        if !Self::credential_ethernet_peer_is_allowed(peers, packet_type, dst_peer_id).await {
            tracing::warn!(dst_peer_id, "block suppressed credential ethernet peer");
            return Err(Error::RouteError(None));
        }
        let policy = Self::get_next_hop_policy(header);
        let bytes = batch.buffer_byte_len() as u64;
        let packets = batch.len() as u64;
        let latency_first_gateway = if is_latency_first {
            peers
                .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), first)
                .await
                .filter(|gateway| *gateway != dst_peer_id)
        } else {
            None
        };

        let send_result = if let Some(gateway) = latency_first_gateway
            && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
        {
            relay_peer_map
                .send_msg_batch(batch, dst_peer_id, policy)
                .await
        } else if peers.has_peer(dst_peer_id) {
            peers.send_msg_batch_directly(batch, dst_peer_id).await
        } else if foreign_network_client.has_next_hop(dst_peer_id) {
            for packet in batch {
                foreign_network_client.send_msg(packet, dst_peer_id).await?;
            }
            Ok(())
        } else if let Some(gateway) = peers
            .get_gateway_peer_id_for_packet(dst_peer_id, policy.clone(), first)
            .await
        {
            if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
                relay_peer_map
                    .send_msg_batch(batch, dst_peer_id, policy)
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
            metrics
                .record_tx_batch(dst_peer_id, packet_type, bytes, packets)
                .await;
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
        let network_length = self
            .global_ctx
            .get_ipv4()
            .map(|x| x.network_length())
            .unwrap_or(24);
        let ipv4_inet = cidr::Ipv4Inet::new(*ipv4_addr, network_length).unwrap();
        ipv4_addr.is_broadcast()
            || ipv4_addr.is_multicast()
            || *ipv4_addr == ipv4_inet.last_address()
    }

    fn is_all_peers_broadcast_ipv6(&self, ipv6_addr: &Ipv6Addr) -> bool {
        let network_length = self
            .global_ctx
            .get_ipv6()
            .map(|x| x.network_length())
            .unwrap_or(64);
        let ipv6_inet = cidr::Ipv6Inet::new(*ipv6_addr, network_length).unwrap();
        ipv6_addr.is_multicast() || *ipv6_addr == ipv6_inet.last_address()
    }

    fn select_ipv4_broadcast_peers<'a>(
        routes: impl IntoIterator<Item = &'a instance::Route>,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        routes
            .into_iter()
            .filter_map(|route| {
                (route.peer_id != my_peer_id && route.ipv4_addr.is_some()).then_some(route.peer_id)
            })
            .collect()
    }

    fn select_ethernet_peers<'a>(
        routes: impl IntoIterator<Item = &'a instance::Route>,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        routes
            .into_iter()
            .filter_map(|route| {
                (route.peer_id != my_peer_id
                    && route
                        .feature_flag
                        .as_ref()
                        .is_some_and(|features| features.ethernet_input))
                .then_some(route.peer_id)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub async fn get_msg_dst_peer_ipv4(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv4(ipv4_addr) {
            dst_peers.extend(Self::select_ipv4_broadcast_peers(
                &self.peers.list_route_infos().await,
                self.my_peer_id,
            ));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(ipv4_addr).await {
            dst_peers.push(peer_id);
        } else if !self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            for exit_node in self.exit_nodes.read().await.iter() {
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
        #[cfg(target_env = "ohos")]
        {
            if dst_peers.is_empty()
                && !self
                    .global_ctx
                    .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
            {
                tracing::trace!("no peer id for ipv4: {}, set exit_node for ohos", ipv4_addr);
                dst_peers.push(self.my_peer_id.clone());
                is_exit_node = true;
            }
        }
        (dst_peers, is_exit_node)
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv6(ipv6_addr) {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(ipv6_addr).await {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local()
            && let Some(peer_id) = self.get_route().get_public_ipv6_gateway_peer_id().await
        {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local() {
            // NOTE: never route link local address to exit node.
            for exit_node in self.exit_nodes.read().await.iter() {
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

    pub fn try_compress(compress_algo: CompressorAlgo, msg: &mut ZCPacket) -> Result<(), Error> {
        stamp_packet_flow(msg);
        let compressor = DefaultCompressor {};
        compressor
            .compress(msg, compress_algo)
            .with_context(|| "compress failed")?;
        Ok(())
    }

    fn routed_packet_destination(&self, packet: &ZCPacket) -> Option<(IpAddr, bool)> {
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

    pub async fn send_msg_by_ip_batch(&self, mut batch: PacketBatch) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }

        for packet in batch.iter_mut() {
            packet.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Data as u8);
        }
        let batch = self.run_nic_packet_process_pipeline_batch(batch).await;
        if batch.is_empty() {
            return Ok(());
        }

        let latency_first = self.global_ctx.latency_first();
        let speed_first = self.global_ctx.speed_first();
        let mut route_cache: SmallVec<[(IpAddr, Vec<PeerId>, bool); 4]> = SmallVec::new();
        let mut peer_batches = OrderedPeerBatches::new();

        for mut packet in batch {
            let overridden_peer = packet.peer_manager_header().unwrap().to_peer_id.get();
            apply_local_route_policy(&mut packet, speed_first, latency_first);
            if overridden_peer != 0 {
                push_ordered_peer_batch(&mut peer_batches, overridden_peer, packet, true);
                continue;
            }

            let Some((ip_addr, not_send_to_self)) = self.routed_packet_destination(&packet) else {
                tracing::trace!(?packet, "drop invalid routed IP packet");
                continue;
            };
            let route_index = if let Some(index) = route_cache
                .iter()
                .position(|(cached_address, _, _)| *cached_address == ip_addr)
            {
                index
            } else {
                let (peers, is_exit_node) = self.get_msg_dst_peer(&ip_addr).await;
                route_cache.push((ip_addr, peers, is_exit_node));
                route_cache.len() - 1
            };
            let (_, destination_peers, is_exit_node) = &route_cache[route_index];
            if destination_peers.is_empty() {
                continue;
            }

            packet
                .mut_peer_manager_header()
                .unwrap()
                .set_exit_node(*is_exit_node);
            let mark_recent = Self::should_mark_recent_traffic_for_fanout(destination_peers.len());
            let peer_count = destination_peers.len();
            let mut packet = Some(packet);
            for (index, peer_id) in destination_peers.iter().copied().enumerate() {
                let mut peer_packet = if index + 1 == peer_count {
                    packet.take().unwrap()
                } else {
                    packet.clone().unwrap()
                };
                let header = peer_packet.mut_peer_manager_header().unwrap();
                header.to_peer_id.set(peer_id);
                #[cfg(not(target_env = "ohos"))]
                if not_send_to_self
                    && peer_id == self.my_peer_id
                    && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr)
                {
                    header.set_not_send_to_tun(true);
                    header.set_no_proxy(true);
                }
                push_ordered_peer_batch(&mut peer_batches, peer_id, peer_packet, mark_recent);
            }
        }

        let mut errors = Vec::new();
        self.send_ordered_peer_batches(peer_batches, &mut errors)
            .await?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("routed packet batch delivery failed: {errors:?}").into())
        }
    }

    pub async fn send_msg_by_ip(
        &self,
        mut msg: ZCPacket,
        ip_addr: IpAddr,
        not_send_to_self: bool,
    ) -> Result<(), Error> {
        tracing::trace!(
            "do send_msg in peer manager, msg: {:?}, ip_addr: {}",
            msg,
            ip_addr
        );

        msg.fill_peer_manager_hdr(
            self.my_peer_id,
            0,
            tunnel::packet_def::PacketType::Data as u8,
        );
        if !self.run_nic_packet_process_pipeline(&mut msg).await {
            return Ok(());
        }
        apply_local_route_policy(
            &mut msg,
            self.global_ctx.speed_first(),
            self.global_ctx.latency_first(),
        );
        let cur_to_peer_id = msg.peer_manager_header().unwrap().to_peer_id.into();
        if cur_to_peer_id != 0 {
            self.mark_recent_traffic(cur_to_peer_id);
            return Self::send_msg_internal(
                &self.peers,
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                cur_to_peer_id,
            )
            .await;
        }

        let (dst_peers, is_exit_node) = match ip_addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(&ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(&ipv6_addr).await,
        };

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ip: {}", ip_addr);
            return Ok(());
        }

        self.self_tx_counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        Self::try_compress(self.data_compress_algo, &mut msg)?;

        self.self_tx_counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        msg.mut_peer_manager_header()
            .unwrap()
            .set_exit_node(is_exit_node);

        let mut errs: Vec<Error> = vec![];
        let mut msg = Some(msg);
        let total_dst_peers = dst_peers.len();
        let should_mark_recent_traffic =
            Self::should_mark_recent_traffic_for_fanout(total_dst_peers);
        for (i, peer_id) in dst_peers.iter().enumerate() {
            if should_mark_recent_traffic {
                self.mark_recent_traffic(*peer_id);
            }
            if let Err(e) = self.check_p2p_only_before_send(*peer_id) {
                errs.push(e);
                continue;
            }

            let mut msg = if i == total_dst_peers - 1 {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };

            let hdr = msg.mut_peer_manager_header().unwrap();
            hdr.to_peer_id.set(*peer_id);

            #[cfg(not(target_env = "ohos"))]
            {
                if not_send_to_self
                    && *peer_id == self.my_peer_id
                    && !self.global_ctx.is_ip_local_virtual_ip(&ip_addr)
                {
                    // Keep the loop-prevention flags for proxy-induced self-delivery where
                    // the destination is not this node's own LowTier-managed IP.
                    hdr.set_not_send_to_tun(true);
                    hdr.set_no_proxy(true);
                }
            }

            self.self_tx_counters
                .self_tx_bytes
                .add(msg.buf_len() as u64);
            self.self_tx_counters.self_tx_packets.inc();

            if let Err(e) = Self::send_msg_internal(
                &self.peers,
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                *peer_id,
            )
            .await
            {
                errs.push(e);
            }
        }

        tracing::trace!(?dst_peers, "do send_msg in peer manager done");

        if errs.is_empty() {
            Ok(())
        } else {
            tracing::error!(?errs, "send_msg has error");
            Err(anyhow::anyhow!("send_msg has error: {:?}", errs).into())
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
                if flags.speed_probe_budget_bps == 0 || flags.speed_probe_interval_seconds == 0 {
                    active_config = None;
                    budget = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let interval = Duration::from_secs(flags.speed_probe_interval_seconds);
                let config = (
                    flags.speed_probe_budget_bps,
                    flags.speed_probe_interval_seconds,
                );
                if active_config != Some(config) {
                    match ProbeBudget::new(
                        flags.speed_probe_budget_bps,
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
        self.direct_nic_writer.install(sink)
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

    pub async fn check_allow_kcp_to_dst(&self, dst_ip: &IpAddr) -> bool {
        let route = self.get_route();
        let Some(dst_peer_id) = route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        // check dst allow kcp input
        if !peer_info.feature_flag.map(|x| x.kcp_input).unwrap_or(false) {
            return false;
        }

        let next_hop_policy = self.get_local_data_policy();
        // check relay node allow relay kcp.
        let Some(next_hop_id) = route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        if next_hop_id == dst_peer_id {
            // dst p2p, no need to relay
            return true;
        }

        let Some(next_hop_info) = route.get_peer_info(next_hop_id).await else {
            return false;
        };

        // check next hop allow kcp relay
        if next_hop_info
            .feature_flag
            .map(|x| x.no_relay_kcp)
            .unwrap_or(false)
        {
            return false;
        }

        true
    }

    pub async fn check_allow_quic_to_dst(&self, dst_ip: &IpAddr) -> bool {
        let route = self.get_route();
        let Some(dst_peer_id) = route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        // check dst allow quic input
        if !peer_info
            .feature_flag
            .map(|x| x.quic_input)
            .unwrap_or(false)
        {
            return false;
        }

        let next_hop_policy = self.get_local_data_policy();
        // check relay node allow relay quic.
        let Some(next_hop_id) = route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        if next_hop_id == dst_peer_id {
            // dst p2p, no need to relay
            return true;
        }

        let Some(next_hop_info) = route.get_peer_info(next_hop_id).await else {
            return false;
        };

        // check next hop allow quic relay
        if next_hop_info
            .feature_flag
            .map(|x| x.no_relay_quic)
            .unwrap_or(false)
        {
            return false;
        }

        true
    }

    pub async fn update_exit_nodes(&self) {
        let exit_nodes = self.global_ctx.config.get_exit_nodes();
        *self.exit_nodes.write().await = exit_nodes;
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use futures::{SinkExt as _, StreamExt as _};
    use std::{
        collections::HashMap,
        fmt::Debug,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use quanta::Instant;

    use crate::{
        common::{
            PeerId,
            config::Flags,
            global_ctx::{NetworkIdentity, tests::get_mock_global_ctx},
            stats_manager::{LabelSet, LabelType, MetricName},
        },
        connector::{
            create_connector_by_url, direct::PeerManagerForDirectConnector,
            udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        },
        instance::listeners::create_listener_by_url,
        peers::{
            PacketRecvChanReceiver, PeerPacketFilter, create_packet_recv_chan,
            peer_conn::tests::set_secure_mode_cfg,
            peer_manager::RouteAlgoType,
            peer_rpc::tests::register_service,
            route_trait::{MockRoute, NextHopPolicy, RouteCostCalculatorInterface},
            tests::{
                connect_peer_manager, create_mock_peer_manager_with_name, wait_route_appear,
                wait_route_appear_with_cost,
            },
        },
        proto::{
            common::{CompressionAlgoPb, NatType, SecureModeConfig},
            peer_rpc::SecureAuthLevel,
        },
        tunnel::{
            TunnelConnector, TunnelListener,
            batch::PacketBatch,
            common::tests::wait_for_condition,
            filter::{TunnelWithFilter, tests::DropSendTunnelFilter},
            packet_def::{PacketType, ZCPacket},
            ring::create_ring_tunnel_pair,
        },
    };

    use super::{
        DirectNicBatchWriter, PeerManager, apply_local_route_policy, check_tunnel_info_underlay,
        decoded_local_nic_batch_source, is_foreign_network_packet_type, ordered_probe_indexes,
        packet_batch_contains_peer_rpc, packet_supports_speed_first, prepare_direct_nic_batch,
        prepare_packet_batch,
    };

    #[test]
    fn probe_order_keeps_recent_peers_first_and_rotates_every_group() {
        let candidates = vec![
            (30, uuid::Uuid::from_u128(3), false),
            (10, uuid::Uuid::from_u128(1), true),
            (40, uuid::Uuid::from_u128(4), false),
            (20, uuid::Uuid::from_u128(2), true),
            (50, uuid::Uuid::from_u128(5), false),
        ];

        let first = ordered_probe_indexes(&candidates, 0);
        let second = ordered_probe_indexes(&candidates, 1);
        let third = ordered_probe_indexes(&candidates, 2);

        for order in [&first, &second, &third] {
            assert!(candidates[order[0]].2);
            assert!(candidates[order[1]].2);
            assert!(!candidates[order[2]].2);
        }
        assert_ne!(first[..2], second[..2]);
        assert_ne!(first[2..], second[2..]);
        assert_ne!(second[2..], third[2..]);
    }

    #[test]
    fn speed_first_allowlist_contains_only_data_packets() {
        for packet_type in [
            PacketType::Data,
            PacketType::ForeignNetworkPacket,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
            PacketType::Ethernet,
            PacketType::AlternateFecSource,
            PacketType::AlternateFecParity,
        ] {
            let mut packet = ZCPacket::new_with_payload(b"data");
            packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
            assert!(packet_supports_speed_first(&packet), "{packet_type:?}");
        }

        for packet_type in [
            PacketType::HandShake,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::RpcReq,
            PacketType::RpcResp,
            PacketType::RelayHandshake,
            PacketType::RelayHandshakeAck,
        ] {
            let mut packet = ZCPacket::new_with_payload(b"control");
            packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
            assert!(!packet_supports_speed_first(&packet), "{packet_type:?}");
        }
    }

    #[test]
    fn critical_ethernet_does_not_use_speed_first() {
        let mut packet = ZCPacket::new_with_payload(b"control");
        packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);

        assert!(!packet_supports_speed_first(&packet));
    }

    #[test]
    fn speed_first_policy_precedes_the_compatibility_latency_flag() {
        let mut packet = ZCPacket::new_with_payload(b"data");
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_speed_first(true);

        assert_eq!(
            PeerManager::get_next_hop_policy(packet.peer_manager_header().unwrap()),
            NextHopPolicy::MaxGoodput
        );
    }

    #[test]
    fn speed_mode_keeps_control_packets_on_latency_policy() {
        let mut data = ZCPacket::new_with_payload(b"data");
        data.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        apply_local_route_policy(&mut data, true, false);
        assert!(data.peer_manager_header().unwrap().is_speed_first());

        let mut control = ZCPacket::new_with_payload(b"control");
        control.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        apply_local_route_policy(&mut control, true, false);
        let header = control.peer_manager_header().unwrap();
        assert!(!header.is_speed_first());
        assert!(header.is_latency_first());
        assert_eq!(
            PeerManager::get_next_hop_policy(header),
            NextHopPolicy::LeastCost
        );
    }

    #[test]
    fn direct_nic_writer_exposes_the_installed_endpoint() {
        let writer = DirectNicBatchWriter::default();
        let (sink, _receiver) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let installed = writer.install(Box::pin(sink));
        let observed = writer.current_endpoint().unwrap();

        assert!(Arc::ptr_eq(&installed, &observed));
    }

    #[test]
    fn direct_nic_writer_reports_endpoint_removal() {
        let writer = DirectNicBatchWriter::default();
        assert!(writer.current_endpoint().is_none());

        let (sink, _receiver) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let installed = writer.install(Box::pin(sink));
        assert!(writer.current_endpoint().is_some());

        drop(installed);
        assert!(writer.current_endpoint().is_none());
    }

    #[tokio::test]
    async fn direct_nic_ingress_does_not_retain_the_peer_map() {
        let global_ctx = get_mock_global_ctx();
        let (nic_sender, _legacy_nic) = create_packet_recv_chan();
        let peer_manager = PeerManager::new(RouteAlgoType::Ospf, global_ctx, nic_sender);
        let peers = Arc::downgrade(&peer_manager.peers);
        let (sink, _receiver) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint = peer_manager.install_direct_nic_sink(Box::pin(sink));

        drop(peer_manager);

        assert!(peers.upgrade().is_none());
    }

    #[test]
    fn route_registration_does_not_require_a_packet_filter() {
        fn register(manager: &PeerManager, route: MockRoute) {
            drop(manager.add_route(route));
        }

        let _ = register;
    }

    #[test]
    fn peer_rpc_batch_scan_distinguishes_data_from_control() {
        let mut data_batch = PacketBatch::new();
        for value in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[value]);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            data_batch.try_push(packet).unwrap();
        }
        assert!(!packet_batch_contains_peer_rpc(&data_batch));

        let mut control = ZCPacket::new_with_payload(b"request");
        control.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        data_batch.try_push(control).unwrap();
        assert!(packet_batch_contains_peer_rpc(&data_batch));
    }

    #[test]
    fn foreign_network_dispatch_ignores_normal_ethernet() {
        assert!(!is_foreign_network_packet_type(PacketType::Ethernet as u8));
        assert!(is_foreign_network_packet_type(
            PacketType::ForeignNetworkPacket as u8
        ));
    }

    #[test]
    fn decoded_ethernet_batch_can_keep_its_owned_storage_for_nic() {
        let mut batch = PacketBatch::new();
        for value in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[value; 64]);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }

        assert!(prepare_direct_nic_batch(&batch, true, |_, _| {}));

        let mut control = ZCPacket::new_with_payload(b"control");
        control.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
        batch.try_push(control).unwrap();
        assert!(!prepare_direct_nic_batch(&batch, true, |_, _| {}));
    }

    #[test]
    fn decoded_local_ethernet_batch_has_one_source() {
        let mut batch = PacketBatch::new();
        for value in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[value; 64]);
            packet.fill_peer_manager_hdr(10, 20, PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }
        assert_eq!(
            decoded_local_nic_batch_source(&batch, 20),
            Some((10, PacketType::Ethernet as u8))
        );

        batch[7]
            .mut_peer_manager_header()
            .unwrap()
            .to_peer_id
            .set(21);
        assert_eq!(decoded_local_nic_batch_source(&batch, 20), None);
    }

    #[test]
    fn decoded_local_routed_batch_keeps_one_source_and_packet_type() {
        let mut batch = PacketBatch::new();
        for value in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[value; 64]);
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            batch.try_push(packet).unwrap();
        }

        assert_eq!(
            decoded_local_nic_batch_source(&batch, 20),
            Some((10, PacketType::Data as u8))
        );
    }

    #[tokio::test]
    async fn packet_batch_defers_encryption_until_transport_selection() {
        let mut batch = PacketBatch::new();
        for sequence in 0_u8..8 {
            let mut packet = ZCPacket::new_with_payload(&[sequence; 64]);
            packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }

        let batch =
            prepare_packet_batch(crate::tunnel::packet_def::CompressorAlgo::None, batch).unwrap();

        for (sequence, packet) in batch.into_iter().enumerate() {
            assert!(!packet.peer_manager_header().unwrap().is_encrypted());
            assert_eq!(packet.payload(), &[sequence as u8; 64]);
        }
    }

    async fn create_tap_peer_manager(
        l2_flood_bps: u64,
    ) -> (Arc<PeerManager>, PacketRecvChanReceiver) {
        create_tap_peer_manager_with_ipv4(l2_flood_bps, None).await
    }

    async fn create_tap_peer_manager_with_ipv4(
        l2_flood_bps: u64,
        ipv4: Option<std::net::Ipv4Addr>,
    ) -> (Arc<PeerManager>, PacketRecvChanReceiver) {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(ipv4.map(|address| cidr::Ipv4Inet::new(address, 24).unwrap()));
        let mut flags = global_ctx.get_flags();
        flags.port_mode = "ethernet".to_string();
        flags.l2_flood_bps = l2_flood_bps;
        global_ctx.set_flags(flags);

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            packet_send,
        ));
        peer_manager.run().await.unwrap();
        (peer_manager, packet_recv)
    }

    async fn create_routed_peer_manager_with_ipv4(ipv4: std::net::Ipv4Addr) -> Arc<PeerManager> {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(Some(cidr::Ipv4Inet::new(ipv4, 24).unwrap()));
        let mut flags = global_ctx.get_flags();
        flags.port_mode = "routed".to_string();
        global_ctx.set_flags(flags);

        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            packet_send,
        ));
        peer_manager.run().await.unwrap();
        peer_manager
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

    #[tokio::test]
    async fn routed_l3_batch_reaches_direct_peer_as_one_owned_batch() {
        let address_a = "10.144.144.2".parse().unwrap();
        let address_b = "10.144.144.3".parse().unwrap();
        let peer_mgr_a = create_routed_peer_manager_with_ipv4(address_a).await;
        let peer_mgr_b = create_routed_peer_manager_with_ipv4(address_b).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        let peer_b_id = peer_mgr_b.my_peer_id();
        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    peer_mgr_a
                        .get_msg_dst_peer(&std::net::IpAddr::V4(address_b))
                        .await
                        .0
                        .contains(&peer_b_id)
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let (sink, mut direct_nic) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint = peer_mgr_b.install_direct_nic_sink(Box::pin(sink));
        let mut batch = PacketBatch::new();
        for marker in 0_u8..8 {
            batch
                .try_push(routed_ipv4_packet(address_a, address_b, marker))
                .unwrap();
        }

        peer_mgr_a.send_msg_by_ip_batch(batch).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(5), direct_nic.next())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.len(), 8);
        assert_eq!(
            received
                .iter()
                .map(|packet| packet.payload()[24])
                .collect::<Vec<_>>(),
            (0_u8..8).collect::<Vec<_>>()
        );
        assert!(direct_nic.try_next().is_err());
    }

    #[tokio::test]
    async fn routed_l3_batch_groups_destinations_and_preserves_order() {
        let address_a = "10.144.144.11".parse().unwrap();
        let address_b = "10.144.144.12".parse().unwrap();
        let address_c = "10.144.144.13".parse().unwrap();
        let peer_mgr_a = create_routed_peer_manager_with_ipv4(address_a).await;
        let peer_mgr_b = create_routed_peer_manager_with_ipv4(address_b).await;
        let peer_mgr_c = create_routed_peer_manager_with_ipv4(address_c).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let (sink_b, mut nic_b) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink_b = sink_b.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint_b = peer_mgr_b.install_direct_nic_sink(Box::pin(sink_b));
        let (sink_c, mut nic_c) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink_c = sink_c.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint_c = peer_mgr_c.install_direct_nic_sink(Box::pin(sink_c));

        let mut batch = PacketBatch::new();
        for (destination, marker) in [
            (address_b, 1_u8),
            (address_c, 2),
            (address_b, 3),
            (address_c, 4),
        ] {
            batch
                .try_push(routed_ipv4_packet(address_a, destination, marker))
                .unwrap();
        }
        peer_mgr_a.send_msg_by_ip_batch(batch).await.unwrap();

        let batch_b = tokio::time::timeout(Duration::from_secs(5), nic_b.next())
            .await
            .unwrap()
            .unwrap();
        let batch_c = tokio::time::timeout(Duration::from_secs(5), nic_c.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            batch_b
                .iter()
                .map(|packet| packet.payload()[24])
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(
            batch_c
                .iter()
                .map(|packet| packet.payload()[24])
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
    }

    #[tokio::test]
    async fn direct_nic_ingress_bypasses_both_packet_channels() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.port_mode = "ethernet".to_string();
        global_ctx.set_flags(flags);
        let (nic_sender, mut legacy_nic) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            nic_sender,
        ));
        let (sink, mut direct_nic) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint = peer_manager.install_direct_nic_sink(Box::pin(sink));
        let mut batch = PacketBatch::new();
        for marker in 0_u8..8 {
            let mut frame = ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, marker + 1]);
            frame[14] = marker;
            let mut packet = ZCPacket::new_with_payload(&frame);
            packet.fill_peer_manager_hdr(42, peer_manager.my_peer_id(), PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }

        peer_manager.packet_ingress.send_batch(batch).await.unwrap();
        let received = direct_nic.next().await.unwrap();

        assert_eq!(received.len(), 8);
        assert!(
            peer_manager
                .packet_recv
                .lock()
                .await
                .as_mut()
                .unwrap()
                .try_recv()
                .is_err()
        );
        assert!(legacy_nic.try_recv().is_err());
    }

    #[tokio::test]
    async fn direct_nic_ingress_runs_registered_peer_filters() {
        struct ConsumeBatch {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for ConsumeBatch {
            async fn try_process_batch_from_peer(&self, batch: PacketBatch) -> PacketBatch {
                self.calls.fetch_add(1, Ordering::Relaxed);
                drop(batch);
                PacketBatch::new()
            }
        }

        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.port_mode = "ethernet".to_string();
        global_ctx.set_flags(flags);
        let (nic_sender, _legacy_nic) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            nic_sender,
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        peer_manager
            .add_packet_process_pipeline(Box::new(ConsumeBatch {
                calls: calls.clone(),
            }))
            .await;
        let (sink, mut direct_nic) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint = peer_manager.install_direct_nic_sink(Box::pin(sink));
        let mut packet =
            ZCPacket::new_with_payload(&ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]));
        packet.fill_peer_manager_hdr(42, peer_manager.my_peer_id(), PacketType::Ethernet as u8);

        peer_manager
            .packet_ingress
            .send_batch(PacketBatch::singleton(packet))
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(direct_nic.try_next().is_err());
    }

    #[tokio::test]
    async fn routed_direct_nic_ingress_rejects_ethernet() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.port_mode = "routed".to_string();
        global_ctx.set_flags(flags);
        let (nic_sender, _legacy_nic) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            nic_sender,
        ));
        let (sink, mut direct_nic) = futures::channel::mpsc::unbounded::<PacketBatch>();
        let sink = sink.sink_map_err(|_| crate::tunnel::TunnelError::Shutdown);
        let _endpoint = peer_manager.install_direct_nic_sink(Box::pin(sink));
        let mut packet =
            ZCPacket::new_with_payload(&ethernet_frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]));
        packet.fill_peer_manager_hdr(42, peer_manager.my_peer_id(), PacketType::Ethernet as u8);

        peer_manager
            .packet_ingress
            .send_batch(PacketBatch::singleton(packet))
            .await
            .unwrap();

        assert!(direct_nic.try_next().is_err());
        assert_eq!(
            peer_manager
                .packet_recv
                .lock()
                .await
                .as_mut()
                .unwrap()
                .try_recv()
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .packet_type,
            PacketType::Ethernet as u8
        );
    }

    fn ethernet_frame(destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
        let mut frame = vec![0_u8; 64];
        frame[..6].copy_from_slice(&destination);
        frame[6..12].copy_from_slice(&source);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame
    }

    #[tokio::test]
    async fn l2_known_unicast_delivers_frame_and_learns_source() {
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
    async fn l2_unknown_unicast_fans_out_to_ethernet_capable_peers() {
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
    }

    #[tokio::test]
    async fn l2_tun_unicast_uses_ip_route_without_flooding() {
        let (peer_mgr_a, _nic_a) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.1".parse().unwrap())).await;
        let (peer_mgr_b, mut nic_b) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.2".parse().unwrap())).await;
        let (peer_mgr_c, mut nic_c) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.3".parse().unwrap())).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let destination = peer_mgr_b.get_global_ctx().get_ipv4().unwrap().address();
        let mut frame = vec![0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN + 20];
        frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN] = 0x45;
        frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN + 16..][..4]
            .copy_from_slice(&destination.octets());

        peer_mgr_a
            .send_msg_by_l2_tun(
                ZCPacket::new_with_payload(&frame),
                std::net::IpAddr::V4(destination),
                false,
            )
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
        assert_eq!(&received.payload()[..6], &[0xff; 6]);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), nic_c.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn l2_tun_batch_uses_shared_per_peer_ordering() {
        let (peer_mgr_a, _nic_a) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.1".parse().unwrap())).await;
        let (peer_mgr_b, mut nic_b) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.2".parse().unwrap())).await;
        let (peer_mgr_c, mut nic_c) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.3".parse().unwrap())).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let ip_b = peer_mgr_b.get_global_ctx().get_ipv4().unwrap().address();
        let ip_c = peer_mgr_c.get_global_ctx().get_ipv4().unwrap().address();
        let mut batch = PacketBatch::new();
        for (destination, marker) in [(ip_b, 1_u8), (ip_c, 2), (ip_b, 3), (ip_c, 4)] {
            let mut frame = vec![0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN + 20];
            let ip = &mut frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN..];
            ip[0] = 0x45;
            ip[8] = marker;
            ip[16..20].copy_from_slice(&destination.octets());
            batch.try_push(ZCPacket::new_with_payload(&frame)).unwrap();
        }

        peer_mgr_a.send_msg_by_l2_tun_batch(batch).await.unwrap();

        let payload_offset = crate::instance::l2_tun::ETHERNET_HEADER_LEN + 8;
        let b = tokio::time::timeout(Duration::from_secs(5), async {
            [
                nic_b.recv().await.unwrap().payload()[payload_offset],
                nic_b.recv().await.unwrap().payload()[payload_offset],
            ]
        })
        .await
        .unwrap();
        let c = tokio::time::timeout(Duration::from_secs(5), async {
            [
                nic_c.recv().await.unwrap().payload()[payload_offset],
                nic_c.recv().await.unwrap().payload()[payload_offset],
            ]
        })
        .await
        .unwrap();
        assert_eq!(b, [1, 3]);
        assert_eq!(c, [2, 4]);
    }

    #[tokio::test]
    async fn l2_tun_ip_broadcast_keeps_broadcast_ethernet_destination() {
        let (peer_mgr_a, _nic_a) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.1".parse().unwrap())).await;
        let (peer_mgr_b, mut nic_b) =
            create_tap_peer_manager_with_ipv4(0, Some("10.144.144.2".parse().unwrap())).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let destination: std::net::Ipv4Addr = "10.144.144.255".parse().unwrap();
        let mut frame = vec![0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN + 20];
        frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN] = 0x45;
        frame[crate::instance::l2_tun::ETHERNET_HEADER_LEN + 16..][..4]
            .copy_from_slice(&destination.octets());

        peer_mgr_a
            .send_msg_by_l2_tun(
                ZCPacket::new_with_payload(&frame),
                std::net::IpAddr::V4(destination),
                false,
            )
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), nic_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received.payload()[..6], &[0xff; 6]);
    }

    #[tokio::test]
    async fn l2_flood_budget_returns_a_typed_error_without_delivery() {
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

    #[test]
    fn ingress_underlay_policy_rejects_denied_local_and_remote_addresses() {
        let policy =
            crate::common::underlay_policy::UnderlayPolicy::new(&[], &["100.64.0.0/10".into()])
                .unwrap();
        let info = crate::proto::common::TunnelInfo {
            tunnel_type: "udp".into(),
            local_addr: Some("udp://192.0.2.10:11010".parse::<url::Url>().unwrap().into()),
            remote_addr: Some(
                "udp://100.108.186.13:40000"
                    .parse::<url::Url>()
                    .unwrap()
                    .into(),
            ),
            resolved_remote_addr: None,
        };

        let error = check_tunnel_info_underlay(&info, &policy).unwrap_err();
        assert!(error.to_string().contains("remote"));

        let local_denied = crate::proto::common::TunnelInfo {
            local_addr: Some(
                "tcp://100.108.186.13:11010"
                    .parse::<url::Url>()
                    .unwrap()
                    .into(),
            ),
            remote_addr: Some("tcp://192.0.2.20:40000".parse::<url::Url>().unwrap().into()),
            ..info
        };
        let error = check_tunnel_info_underlay(&local_denied, &policy).unwrap_err();
        assert!(error.to_string().contains("local"));
    }

    async fn create_lazy_peer_manager() -> Arc<PeerManager> {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut flags = peer_mgr.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        peer_mgr.get_global_ctx().set_flags(flags);
        peer_mgr
    }

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: &LabelSet) -> u64 {
        peer_mgr
            .get_global_ctx()
            .stats_manager()
            .get_metric(metric, labels)
            .map(|metric| metric.value)
            .unwrap_or(0)
    }

    fn network_labels(peer_mgr: &PeerManager) -> LabelSet {
        LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ))
    }

    struct TestCostCalculator {
        costs: HashMap<(PeerId, PeerId), i32>,
    }

    impl RouteCostCalculatorInterface for TestCostCalculator {
        fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
            *self.costs.get(&(src, dst)).unwrap_or(&1)
        }
    }

    #[test]
    fn recent_traffic_fanout_policy_only_marks_single_peer() {
        assert!(PeerManager::should_mark_recent_traffic_for_fanout(0));
        assert!(PeerManager::should_mark_recent_traffic_for_fanout(1));
        assert!(!PeerManager::should_mark_recent_traffic_for_fanout(2));
    }

    fn route_with_ipv4(
        peer_id: u32,
        ipv4_addr: Option<std::net::Ipv4Addr>,
    ) -> crate::proto::api::instance::Route {
        crate::proto::api::instance::Route {
            peer_id,
            ipv4_addr: ipv4_addr.map(|addr| cidr::Ipv4Inet::new(addr, 24).unwrap().into()),
            ..Default::default()
        }
    }

    fn ethernet_route(peer_id: PeerId, ethernet_input: bool) -> crate::proto::api::instance::Route {
        crate::proto::api::instance::Route {
            peer_id,
            feature_flag: Some(crate::proto::common::PeerFeatureFlag {
                ethernet_input,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn ethernet_peer_selection_requires_capability_and_deduplicates() {
        let routes = vec![
            ethernet_route(1, true),
            ethernet_route(2, false),
            ethernet_route(3, true),
            ethernet_route(1, true),
            ethernet_route(4, true),
        ];

        assert_eq!(PeerManager::select_ethernet_peers(&routes, 3), vec![1, 4]);
    }

    #[test]
    fn ipv4_broadcast_peer_selection_skips_peers_without_ipv4() {
        let routes = vec![
            route_with_ipv4(1, Some(std::net::Ipv4Addr::new(10, 126, 126, 1))),
            route_with_ipv4(2, None),
            route_with_ipv4(3, Some(std::net::Ipv4Addr::new(10, 126, 126, 3))),
            route_with_ipv4(4, None),
        ];

        assert_eq!(
            PeerManager::select_ipv4_broadcast_peers(&routes, 3),
            vec![1]
        );
    }

    #[test]
    fn gc_recent_traffic_removes_expired_and_connected_entries() {
        let stale_peer = 1;
        let direct_peer = 2;
        let active_peer = 3;
        let recent_have_traffic = dashmap::DashMap::new();

        recent_have_traffic.insert(
            stale_peer,
            Instant::now() - PeerManager::RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1),
        );
        recent_have_traffic.insert(direct_peer, Instant::now());
        recent_have_traffic.insert(active_peer, Instant::now());

        let future_peer = 4;

        recent_have_traffic.insert(future_peer, Instant::now() + Duration::from_secs(1));

        PeerManager::gc_recent_traffic_entries(&recent_have_traffic, Instant::now(), |peer_id| {
            peer_id == direct_peer
        });

        assert!(!recent_have_traffic.contains_key(&stale_peer));
        assert!(!recent_have_traffic.contains_key(&direct_peer));
        assert!(recent_have_traffic.contains_key(&active_peer));
        assert!(recent_have_traffic.contains_key(&future_peer));
    }

    #[tokio::test]
    async fn recent_traffic_skips_direct_peers_and_clears_after_direct_connect() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()));

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (client_ret, server_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, true),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        client_ret.unwrap();
        server_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { peer_mgr_a.has_directly_connected_conn(peer_b_id) }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()) }
            },
            Duration::from_secs(5),
        )
        .await;

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(
            !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()),
            "directly connected peers should not be tracked as lazy-p2p demand"
        );
    }

    #[tokio::test]
    async fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();
        let signal = peer_mgr_a.p2p_demand_notify();

        let initial_version = signal.version();
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 1);

        let first_seen = *peer_mgr_a.recent_have_traffic.get(&peer_b_id).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "fresh demand should not wake all p2p workers again"
        );
        let refreshed_seen = *peer_mgr_a.recent_have_traffic.get(&peer_b_id).unwrap();
        assert!(refreshed_seen > first_seen);

        if let Some(mut last_seen) = peer_mgr_a.recent_have_traffic.get_mut(&peer_b_id) {
            *last_seen =
                Instant::now() - PeerManager::RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1);
        }
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 2);
    }

    #[test]
    fn disable_relay_data_classifies_data_plane_packets_only() {
        for packet_type in [
            PacketType::Data,
            PacketType::Ethernet,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
            PacketType::ForeignNetworkPacket,
        ] {
            assert!(PeerManager::is_relay_data_packet(packet_type as u8));
        }

        for packet_type in [
            PacketType::RpcReq,
            PacketType::RpcResp,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::HandShake,
            PacketType::NoiseHandshakeMsg1,
            PacketType::NoiseHandshakeMsg2,
            PacketType::NoiseHandshakeMsg3,
            PacketType::RelayHandshake,
            PacketType::RelayHandshakeAck,
        ] {
            assert!(!PeerManager::is_relay_data_packet(packet_type as u8));
        }
    }

    #[test]
    fn disable_relay_data_inspects_foreign_network_inner_packet_type() {
        let network_name = "net1".to_string();

        let mut rpc_packet = ZCPacket::new_with_payload(b"rpc");
        rpc_packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        let mut foreign_rpc_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &rpc_packet);
        foreign_rpc_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_rpc_packet.foreign_network_inner_packet_type(),
            Some(PacketType::RpcReq as u8)
        );
        assert!(!PeerManager::is_relay_data_zc_packet(&foreign_rpc_packet));

        let mut data_packet = ZCPacket::new_with_payload(b"data");
        data_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut foreign_data_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &data_packet);
        foreign_data_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_data_packet.foreign_network_inner_packet_type(),
            Some(PacketType::Data as u8)
        );
        assert!(PeerManager::is_relay_data_zc_packet(&foreign_data_packet));
    }

    #[tokio::test]
    async fn non_whitelisted_network_avoid_relay_survives_disable_relay_data_toggle() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        flags.relay_network_whitelist = "other-network".to_string();
        global_ctx.set_flags(flags);

        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let _peer_mgr = PeerManager::new(RouteAlgoType::Ospf, global_ctx.clone(), packet_send);

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_on_failed_delivery() {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let dst_peer_id = peer_mgr.my_peer_id().wrapping_add(1);
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        let result = PeerManager::send_msg_internal(
            &peer_mgr.peers,
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficBytesTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficPacketsTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficPacketsTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_for_self_loop() {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            get_mock_global_ctx(),
            s,
        ));
        let dst_peer_id = peer_mgr.my_peer_id();
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        PeerManager::send_msg_internal(
            &peer_mgr.peers,
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await
        .unwrap();

        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficBytesTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficPacketsTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlBytesTx,
                &network_labels
            ),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlPacketsTx,
                &network_labels
            ),
            0
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(
                    MetricName::TrafficControlBytesTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);
        let mut pkt = ZCPacket::new_with_payload(b"data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels)
                        >= a_data_tx_before + pkt_len
                        && metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels)
                            >= b_data_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_uses_latency_first_gateway_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_b.clone(), peer_mgr_c.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        peer_mgr_a
            .get_route()
            .set_route_cost_fn(Box::new(TestCostCalculator {
                costs: HashMap::from([
                    ((peer_mgr_a.my_peer_id(), peer_mgr_c.my_peer_id()), 100),
                    ((peer_mgr_a.my_peer_id(), peer_mgr_b.my_peer_id()), 1),
                    ((peer_mgr_b.my_peer_id(), peer_mgr_c.my_peer_id()), 1),
                ]),
            }))
            .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let peer_mgr_c = peer_mgr_c.clone();
                async move {
                    peer_mgr_a
                        .get_route()
                        .get_next_hop_with_policy(peer_mgr_c.my_peer_id(), NextHopPolicy::LeastCost)
                        .await
                        == Some(peer_mgr_b.my_peer_id())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"latency-first");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::Data as u8,
        );
        pkt.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(true);
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_control_tx_before = metric_value(
            &peer_mgr_a,
            MetricName::TrafficControlBytesTx,
            &a_network_labels,
        );
        let b_control_rx_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesRx,
            &b_network_labels,
        );
        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);

        let mut pkt = ZCPacket::new_with_payload(b"ctrl");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_a,
                        MetricName::TrafficControlBytesTx,
                        &a_network_labels,
                    ) >= a_control_tx_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlBytesRx,
                            &b_network_labels,
                        ) >= b_control_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels),
            a_data_tx_before
        );
        assert_eq!(
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels),
            b_data_rx_before
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-control");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        PeerManager::send_msg_internal(
            &peer_mgr_a.peers,
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
        .await
        .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficControlBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn recent_traffic_tolerates_future_timestamps() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a
            .recent_have_traffic
            .insert(peer_b_id, Instant::now() + Duration::from_secs(1));

        assert!(peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()));
        peer_mgr_a.mark_recent_traffic(peer_b_id);
    }

    #[tokio::test]
    async fn drop_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        // wait mgr_a have 2 peers
        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 2 },
            std::time::Duration::from_secs(5),
        )
        .await;

        drop(peer_mgr_b);

        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 1 },
            std::time::Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_connect_between_peers() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_a
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_b
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_a.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_b.get_global_ctx(), true);

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (a_ret, b_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, false),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        let (peer_b_id, _) = a_ret.unwrap();
        b_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    if !peer_mgr_a
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_b_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_a.get_peer_map().list_peer_conns(peer_b_id).await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        let peer_a_id = peer_mgr_a.my_peer_id();
        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                async move {
                    if !peer_mgr_b
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_a_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_b.get_peer_map().list_peer_conns(peer_a_id).await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_same_network_secure_mode_mismatch_rejected() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
        );
        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "same-network peer with mismatched secure mode should be rejected"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn credential_node_rejects_legacy_client() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
        );

        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "credential server should reject legacy client"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_shared_node_pinning_connect() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "shared".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });

        set_secure_mode_cfg(&peer_mgr_client.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let server_pub_b64 = peer_mgr_server
            .get_global_ctx()
            .config
            .get_secure_mode()
            .unwrap()
            .local_public_key
            .unwrap();

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let server_remote_url: url::Url = a_ring
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        peer_mgr_client.get_global_ctx().config.set_peers(vec![
            crate::common::config::PeerConfig {
                uri: server_remote_url,
                peer_public_key: Some(server_pub_b64.clone()),
            },
        ]);

        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(a_ring, false),
            peer_mgr_server.add_tunnel_as_server(b_ring, true)
        );
        c_ret.unwrap();
        s_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_client = peer_mgr_client.clone();
                async move {
                    let foreign_peer_map =
                        peer_mgr_client.get_foreign_network_client().get_peer_map();
                    if foreign_peer_map.list_peers_with_conn().await.len() != 1 {
                        return false;
                    }
                    let Some(peer_id) = foreign_peer_map
                        .list_peers_with_conn()
                        .await
                        .into_iter()
                        .next()
                    else {
                        return false;
                    };
                    let Some(conns) = foreign_peer_map.list_peer_conns(peer_id).await else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.secure_auth_level == SecureAuthLevel::PeerVerified as i32
                            && c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    let foreigns = peer_mgr_server
                        .get_foreign_network_manager()
                        .list_foreign_networks()
                        .await;
                    let Some(entry) = foreigns.foreign_networks.get("user") else {
                        return false;
                    };
                    entry.peers.iter().any(|p| {
                        p.conns
                            .iter()
                            .any(|c| c.noise_local_static_pubkey.len() == 32)
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    async fn connect_peer_manager_with<C: TunnelConnector + Debug + 'static, L: TunnelListener>(
        client_mgr: Arc<PeerManager>,
        server_mgr: &Arc<PeerManager>,
        mut client: C,
        server: &mut L,
    ) {
        server.listen().await.unwrap();

        tokio::spawn(async move {
            client.set_bind_addrs(vec![]);
            client_mgr.try_direct_connect(client).await.unwrap();
        });

        server_mgr
            .add_client_tunnel(server.accept().await.unwrap(), false)
            .await
            .unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(forward_packet_test)]
    async fn forward_packet(
        #[values("tcp", "udp", "quic")] proto1: &str,
        #[values("tcp", "udp", "quic")] proto2: &str,
    ) {
        use crate::proto::{
            rpc_impl::RpcController,
            tests::{GreetingClientFactory, SayHelloRequest},
        };

        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_a.peer_rpc_mgr, "", 0, "hello a");

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_c.peer_rpc_mgr, "", 0, "hello c");

        let mut listener1 = create_listener_by_url(
            &format!("{}://0.0.0.0:31013", proto1).parse().unwrap(),
            peer_mgr_b.get_global_ctx(),
        )
        .unwrap();
        let connector1 = create_connector_by_url(
            format!("{}://127.0.0.1:31013", proto1).as_str(),
            &peer_mgr_a.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_a.clone(), &peer_mgr_b, connector1, &mut listener1)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let mut listener2 = create_listener_by_url(
            &format!("{}://0.0.0.0:31014", proto2).parse().unwrap(),
            peer_mgr_c.get_global_ctx(),
        )
        .unwrap();
        let connector2 = create_connector_by_url(
            format!("{}://127.0.0.1:31014", proto2).as_str(),
            &peer_mgr_b.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_b.clone(), &peer_mgr_c, connector2, &mut listener2)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let stub = peer_mgr_a
            .peer_rpc_mgr
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id,
                peer_mgr_c.my_peer_id,
                "".to_string(),
            );

        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest {
                    name: "abc".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(ret.greeting, "hello c abc!");
    }

    #[tokio::test]
    async fn communicate_between_enc_and_non_enc() {
        let create_mgr = |enable_encryption| async move {
            let (s, _r) = create_packet_recv_chan();
            let mock_global_ctx = get_mock_global_ctx();
            mock_global_ctx.set_flags(Flags {
                enable_encryption,
                data_compress_algo: CompressionAlgoPb::Zstd.into(),
                ..Default::default()
            });
            let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, mock_global_ctx, s));
            peer_mgr.run().await.unwrap();
            peer_mgr
        };

        let peer_mgr_a = create_mgr(true).await;
        let peer_mgr_b = create_mgr(false).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;

        // wait 5sec should not crash.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // both mgr should alive
        let mgr_c = create_mgr(true).await;
        connect_peer_manager(peer_mgr_a.clone(), mgr_c.clone()).await;
        wait_route_appear(mgr_c, peer_mgr_a).await.unwrap();

        let mgr_d = create_mgr(false).await;
        connect_peer_manager(peer_mgr_b.clone(), mgr_d.clone()).await;
        wait_route_appear(mgr_d, peer_mgr_b).await.unwrap();
    }

    #[tokio::test]
    async fn test_avoid_relay_data() {
        // a->b->c
        // a->d->e->c
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_d = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_e = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        println!("peer_mgr_a: {}", peer_mgr_a.my_peer_id);
        println!("peer_mgr_b: {}", peer_mgr_b.my_peer_id);
        println!("peer_mgr_c: {}", peer_mgr_c.my_peer_id);
        println!("peer_mgr_d: {}", peer_mgr_d.my_peer_id);
        println!("peer_mgr_e: {}", peer_mgr_e.my_peer_id);

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_d.clone()).await;
        connect_peer_manager(peer_mgr_d.clone(), peer_mgr_e.clone()).await;
        connect_peer_manager(peer_mgr_e.clone(), peer_mgr_c.clone()).await;

        // when b's avoid_relay_data is false, a->c should route through b and cost is 2
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));

        // when b's avoid_relay_data is true, a->c should route through d and e, cost is 3
        peer_mgr_b
            .get_global_ctx()
            .set_avoid_relay_data_preference(true);
        tokio::time::sleep(Duration::from_secs(2)).await;
        if wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(3))
            .await
            .is_err()
        {
            panic!(
                "route not appear, a route table: {}, table: {:#?}",
                peer_mgr_a.get_route().dump().await,
                peer_mgr_a.get_route().list_routes().await
            )
        }

        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_d.my_peer_id));

        println!("route table: {:#?}", peer_mgr_a.list_routes().await);

        // drop e, path should go back to through b
        drop(peer_mgr_e);
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));
    }

    #[tokio::test]
    async fn test_client_inbound_blackhole() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        // a is client, b is server

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let a_ring = Box::new(TunnelWithFilter::new(
            a_ring,
            DropSendTunnelFilter::new(2, 50000),
        ));

        let a_mgr_copy = peer_mgr_a.clone();
        tokio::spawn(async move {
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = peer_mgr_b.clone();
        tokio::spawn(async move {
            b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
        });

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_peer_map() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let conns = peer_mgr_a
            .get_peer_map()
            .list_peer_conns(peer_mgr_b.my_peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();

        peer_mgr_a
            .close_peer_conn(peer_mgr_b.my_peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
        // a is client, b is server
    }

    #[tokio::test]
    async fn expired_credential_peer_conn_is_closed_without_ospf() {
        let (admin_ch, _admin_rx) = create_packet_recv_chan();
        let admin_ctx = get_mock_global_ctx();
        admin_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&admin_ctx, true);
        let admin = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            admin_ctx.clone(),
            admin_ch,
        ));
        admin.run().await.unwrap();

        let (_cred_id, cred_secret) = admin_ctx.get_credential_manager().generate_credential(
            vec![],
            false,
            vec![],
            Duration::from_secs(1),
        );
        let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let public = x25519_dalek::PublicKey::from(&private);
        let (credential_ch, _credential_rx) = create_packet_recv_chan();
        let credential_ctx = get_mock_global_ctx();
        credential_ctx
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));
        credential_ctx
            .config
            .set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(private.as_bytes()),
                ),
                local_public_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                ),
            }));
        let credential = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            credential_ctx,
            credential_ch,
        ));
        credential.run().await.unwrap();
        let credential_peer_id = credential.my_peer_id();

        connect_peer_manager(credential.clone(), admin.clone()).await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_some_and(|conns| !conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_none_or(|conns| conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_client() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let peer_id = peer_mgr_client
            .foreign_network_client
            .list_public_peers()
            .await[0];
        let conns = peer_mgr_client
            .foreign_network_client
            .get_peer_map()
            .list_peer_conns(peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();
        peer_mgr_client
            .close_peer_conn(peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_manager() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let conns = peer_mgr_server
            .foreign_network_manager
            .list_foreign_networks()
            .await;
        let client_info = conns.foreign_networks["client"].peers[0].clone();
        let conn_info = client_info.conns[0].clone();
        peer_mgr_server
            .close_peer_conn(client_info.peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}
