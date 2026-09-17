use std::sync::Arc;

use std::sync::atomic::{AtomicU32, Ordering};

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use parking_lot::Mutex;
use parking_lot::RwLock;

use tokio::{select, sync::mpsc};

use tracing::Instrument;

use super::alternate_fec::{
    AlternateFecDecoder, AlternateFecEncoder, CompletedAlternateFecBlock, FEC_FLUSH_DELAY,
    parity_packets, source_metadata, wrap_source_packet,
};
use super::{
    PacketRecvChan,
    flow::{FlowPathCache, classify_packet_flow, stamp_critical_l2_control, stamp_packet_flow},
    peer_conn::{PeerConn, PeerConnId},
    route_trait::NextHopPolicy,
};
use crate::{
    common::dataplane_telemetry::{DataplaneFec, DataplaneTelemetry},
    tunnel::packet_def::PacketType,
};
use crate::{common::shrink_dashmap, proto::api::instance::PeerConnInfo};
use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
    tunnel::{batch::PacketBatch, packet_def::ZCPacket},
};
use tokio_util::task::AbortOnDropHandle;

pub(crate) type ArcPeerConn = Arc<PeerConn>;
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

const ALTERNATE_FEC_PARITY_QUEUE_CAPACITY: usize = 32;

struct AlternateFecParityWork {
    conn: ArcPeerConn,
    local_peer_id: PeerId,
    block: CompletedAlternateFecBlock,
}

pub(crate) type OriginAuthUpdate =
    Arc<dyn Fn(PeerId, Option<(PeerIdentityType, Vec<u8>, SecureAuthLevel)>) + Send + Sync>;

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn_id: Arc<AtomicCell<PeerConnId>>,
    connection_flow_paths: Arc<FlowPathCache<PeerConnId>>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    origin_auth_update: Arc<RwLock<OriginAuthUpdate>>,
    default_conn_refresh_task: AbortOnDropHandle<()>,

    alternate_fec_encoder: Option<Arc<Mutex<AlternateFecEncoder>>>,
    alternate_fec_decoder: Option<Arc<Mutex<AlternateFecDecoder>>>,
    alternate_fec_primary: Arc<AtomicCell<PeerConnId>>,
    alternate_fec_local_peer_id: Arc<AtomicU32>,
    alternate_fec_notify: Option<Arc<tokio::sync::Notify>>,
    alternate_fec_parity_sender: Option<mpsc::Sender<AlternateFecParityWork>>,
    alternate_fec_worker_task: Option<AbortOnDropHandle<()>>,
}

fn select_alternate_conn(conns: &ConnMap, primary: &ArcPeerConn) -> Option<ArcPeerConn> {
    conns
        .iter()
        .filter(|candidate| {
            !candidate.value().is_closed()
                && candidate.get_conn_id() != primary.get_conn_id()
                && candidate.value().alternate_fec_remote_receive_ready()
                && candidate.value().alternate_parity_path_allowed()
                && primary.has_distinct_quic_surface(candidate.value())
        })
        .min_by_key(|candidate| {
            let latency = candidate.value().get_stats().latency_us;
            if latency == 0 { u64::MAX } else { latency }
        })
        .map(|candidate| candidate.clone())
}

fn is_alternate_fec_source(packet: &ZCPacket, peer_node_id: PeerId) -> bool {
    packet.peer_manager_header().is_some_and(|header| {
        header.packet_type == PacketType::Ethernet as u8
            && header.to_peer_id.get() == peer_node_id
            && !header.is_critical_l2_control()
    })
}

fn alternate_fec_capture_allowed(
    primary: &ArcPeerConn,
    alternate: &ArcPeerConn,
    packet: &ZCPacket,
    encoder: &AlternateFecEncoder,
) -> bool {
    let Some(source_payload_len) = primary.alternate_fec_source_payload_len(packet) else {
        return false;
    };
    let Some((source_record_len, parity_record_len)) =
        encoder.record_lengths_for_source(source_payload_len)
    else {
        return false;
    };
    primary.alternate_fec_record_fits(source_record_len)
        && alternate.alternate_fec_record_fits(parity_record_len)
}

async fn send_alternate_parity(
    remote_peer_id: PeerId,
    work: AlternateFecParityWork,
    telemetry: &DataplaneTelemetry,
) {
    let AlternateFecParityWork {
        conn,
        local_peer_id,
        block,
    } = work;
    let block_id = block.block_id;
    let source_count = block.source_count;
    let packets = parity_packets(local_peer_id, remote_peer_id, &block);
    let mut batch = PacketBatch::with_capacity(packets.len());
    for packet in packets {
        if !conn.alternate_fec_record_fits(packet.payload().len()) {
            tracing::debug!(
                block_id,
                record_len = packet.payload().len(),
                budget = conn.alternate_fec_datagram_budget(),
                "dropping alternate-path parity record above current DATAGRAM budget"
            );
            continue;
        }
        batch
            .try_push(packet)
            .expect("alternate parity batch is bounded to three packets");
    }
    if batch.is_empty() {
        return;
    }
    let packets = batch.len();
    let bytes = batch.buffer_byte_len();
    if let Err(error) = conn.send_msg_batch(batch).await {
        tracing::warn!(
            ?error,
            block_id,
            source_count,
            "alternate-path parity send failed"
        );
    } else {
        telemetry.record_fec(DataplaneFec::ParityTx, packets, bytes);
    }
}

fn enqueue_alternate_parity(
    sender: &mpsc::Sender<AlternateFecParityWork>,
    work: AlternateFecParityWork,
) {
    match sender.try_send(work) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(work)) => {
            tracing::debug!(
                block_id = work.block.block_id,
                "alternate-path parity queue is full; dropping parity block"
            );
        }
        Err(mpsc::error::TrySendError::Closed(work)) => {
            tracing::debug!(
                block_id = work.block.block_id,
                "alternate-path parity owner is closed"
            );
        }
    }
}

fn timer_alternate_parity_work(
    conns: &ConnMap,
    primary_id: &Arc<AtomicCell<PeerConnId>>,
    local_peer_id: &Arc<AtomicU32>,
    block: CompletedAlternateFecBlock,
) -> Option<AlternateFecParityWork> {
    let primary = conns.get(&primary_id.load()).map(|conn| conn.clone())?;
    let conn = select_alternate_conn(conns, &primary)?;
    let local_peer_id = local_peer_id.load(Ordering::Relaxed);
    (local_peer_id != 0).then_some(AlternateFecParityWork {
        conn,
        local_peer_id,
        block,
    })
}

async fn run_alternate_fec_owner(
    encoder: Arc<Mutex<AlternateFecEncoder>>,
    mut parity_receiver: mpsc::Receiver<AlternateFecParityWork>,
    notify: Arc<tokio::sync::Notify>,
    shutdown: Arc<tokio::sync::Notify>,
    conns: ConnMap,
    primary_id: Arc<AtomicCell<PeerConnId>>,
    local_peer_id: Arc<AtomicU32>,
    remote_peer_id: PeerId,
    telemetry: Arc<DataplaneTelemetry>,
) {
    loop {
        let deadline = encoder.lock().next_flush_at();
        match deadline {
            Some(deadline) => {
                let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                tokio::pin!(sleep);
                tokio::select! {
                    biased;
                    work = parity_receiver.recv() => {
                        let Some(work) = work else { break };
                        send_alternate_parity(remote_peer_id, work, &telemetry).await;
                    }
                    _ = shutdown.notified() => break,
                    _ = &mut sleep => {
                        let block = match encoder.lock().take_due(std::time::Instant::now()) {
                            Ok(Some(block)) => block,
                            Ok(None) => continue,
                            Err(error) => {
                                tracing::warn!(?error, "alternate-path FEC flush failed");
                                continue;
                            }
                        };
                        if let Some(work) = timer_alternate_parity_work(
                            &conns,
                            &primary_id,
                            &local_peer_id,
                            block,
                        ) {
                            send_alternate_parity(remote_peer_id, work, &telemetry).await;
                        }
                    }
                }
            }
            None => {
                tokio::select! {
                    biased;
                    work = parity_receiver.recv() => {
                        let Some(work) = work else { break };
                        send_alternate_parity(remote_peer_id, work, &telemetry).await;
                    }
                    _ = shutdown.notified() => break,
                    _ = notify.notified() => {}
                }
            }
        }
    }
}

async fn wait_for_alternate_fec_deadline(
    encoder: Arc<Mutex<AlternateFecEncoder>>,
    notify: Arc<tokio::sync::Notify>,
) -> std::time::Instant {
    loop {
        let notified = notify.notified();
        if let Some(deadline) = encoder.lock().next_flush_at() {
            return deadline;
        }
        notified.await;
    }
}

impl Peer {
    pub fn new(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        Self::new_with_flow_cache(
            peer_node_id,
            packet_recv_chan,
            global_ctx,
            Arc::new(FlowPathCache::new(
                4096,
                std::time::Duration::from_secs(120),
            )),
        )
    }

    pub(crate) fn new_with_flow_cache(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
        connection_flow_paths: Arc<FlowPathCache<PeerConnId>>,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::new());
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());
        let peer_identity_type = Arc::new(AtomicCell::new(None));
        let peer_identity_type_copy = peer_identity_type.clone();
        let peer_public_key = Arc::new(RwLock::new(None));
        let peer_public_key_copy = peer_public_key.clone();
        let origin_auth_update = Arc::new(RwLock::new(Arc::new(|_, _| {}) as OriginAuthUpdate));
        let origin_auth_update_copy = origin_auth_update.clone();
        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let global_ctx_copy = global_ctx.clone();
        let connection_flow_paths_copy = connection_flow_paths.clone();
        let close_event_listener = AbortOnDropHandle::new(tokio::spawn(
            async move {
                loop {
                    select! {
                        ret = close_event_receiver.recv() => {
                            if ret.is_none() {
                                break;
                            }
                            let ret = ret.unwrap();
                            tracing::warn!(
                                ?peer_node_id,
                                ?ret,
                                "notified that peer conn is closed",
                            );

                            if let Some((_, conn)) = conns_copy.remove(&ret) {
                                connection_flow_paths_copy.invalidate_path(ret);
                                global_ctx_copy.issue_event(GlobalCtxEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
                                let evidence = Peer::authenticated_origin_evidence_from_map(&conns_copy);
                                (origin_auth_update_copy.read())(peer_node_id, evidence);
                                shrink_dashmap(&conns_copy, Some(4));
                                if conns_copy.is_empty() {
                                    peer_identity_type_copy.store(None);
                                    *peer_public_key_copy.write() = None;
                                }
                            }
                        }

                        _ = shutdown_notifier_copy.notified() => {
                            close_event_receiver.close();
                            tracing::warn!(?peer_node_id, "peer close event listener notified");
                        }
                    }
                }
                tracing::info!("peer {} close event listener exit", peer_node_id);
            }
            .instrument(tracing::info_span!(
                "peer_close_event_listener",
                ?peer_node_id,
            )),
        ));

        let default_conn_id = Arc::new(AtomicCell::new(PeerConnId::default()));

        let conns_copy = conns.clone();
        let default_conn_id_copy = default_conn_id.clone();
        let selection_ctx = global_ctx.clone();
        let default_conn_refresh_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let default_conn_id = default_conn_id_copy.load();
                let preferred_protocol = selection_ctx.flags_arc();
                let preferred_protocol = preferred_protocol.default_protocol.as_str();
                let current = conns_copy.get(&default_conn_id);
                let current_is_live = current
                    .as_ref()
                    .is_some_and(|entry| !entry.value().is_closed());
                let current_is_preferred = current.as_ref().is_some_and(|entry| {
                    !entry.value().is_closed()
                        && entry.value().tunnel_type() == Some(preferred_protocol)
                });
                drop(current);
                let has_preferred = conns_copy.iter().any(|entry| {
                    !entry.value().is_closed()
                        && entry.value().tunnel_type() == Some(preferred_protocol)
                });
                if !current_is_live || (has_preferred && !current_is_preferred) {
                    default_conn_id_copy.store(PeerConnId::default());
                }
            }
        }));

        let (alternate_fec_encoder, alternate_fec_decoder) = {
            let flags = global_ctx.get_flags();
            if flags.quic_datagram_alternate_path_parity
                && matches!(flags.quic_datagram_fec_parity, 2 | 3)
            {
                (
                    Some(Arc::new(Mutex::new(
                        AlternateFecEncoder::new_with_budget(
                            flags.quic_datagram_fec_parity as usize,
                            FEC_FLUSH_DELAY,
                            global_ctx.fec_resource_budget(),
                        )
                        .expect("validated alternate FEC configuration"),
                    ))),
                    Some(Arc::new(Mutex::new(AlternateFecDecoder::new(
                        global_ctx.fec_resource_budget(),
                    )))),
                )
            } else {
                (None, None)
            }
        };
        let alternate_fec_primary = Arc::new(AtomicCell::new(PeerConnId::default()));
        let alternate_fec_local_peer_id = Arc::new(AtomicU32::new(0));
        let alternate_fec_notify = alternate_fec_encoder
            .as_ref()
            .map(|_| Arc::new(tokio::sync::Notify::new()));
        let (alternate_fec_parity_sender, alternate_fec_parity_receiver) =
            if alternate_fec_encoder.is_some() {
                let (sender, receiver) = mpsc::channel(ALTERNATE_FEC_PARITY_QUEUE_CAPACITY);
                (Some(sender), Some(receiver))
            } else {
                (None, None)
            };
        let alternate_fec_worker_task = match (
            alternate_fec_encoder.clone(),
            alternate_fec_parity_receiver,
            alternate_fec_notify.clone(),
            alternate_fec_parity_sender.clone(),
        ) {
            (Some(encoder), Some(receiver), Some(notify), Some(_sender)) => {
                let conns = conns.clone();
                let primary_id = alternate_fec_primary.clone();
                let local_peer_id = alternate_fec_local_peer_id.clone();
                let shutdown = shutdown_notifier.clone();
                let telemetry = global_ctx.dataplane_telemetry().clone();
                Some(AbortOnDropHandle::new(tokio::spawn(
                    run_alternate_fec_owner(
                        encoder,
                        receiver,
                        notify,
                        shutdown,
                        conns,
                        primary_id,
                        local_peer_id,
                        peer_node_id,
                        telemetry,
                    ),
                )))
            }
            _ => None,
        };

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            global_ctx,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn_id,
            connection_flow_paths,
            peer_identity_type,
            peer_public_key,
            origin_auth_update,
            default_conn_refresh_task,

            alternate_fec_encoder,
            alternate_fec_decoder,
            alternate_fec_primary,
            alternate_fec_local_peer_id,
            alternate_fec_notify,
            alternate_fec_parity_sender,
            alternate_fec_worker_task,
        }
    }

    pub async fn add_peer_conn(&self, mut conn: PeerConn) -> Result<(), Error> {
        let conn_identity_type = conn.get_peer_identity_type();
        let peer_identity_type = self.peer_identity_type.load();
        if let Some(peer_identity_type) = peer_identity_type {
            if peer_identity_type != conn_identity_type {
                return Err(Error::SecretKeyError(format!(
                    "peer identity type mismatch. peer: {:?}, conn: {:?}",
                    peer_identity_type, conn_identity_type
                )));
            }
        } else {
            self.peer_identity_type.store(Some(conn_identity_type));
        }

        let close_notifier = conn.get_close_notifier();
        let conn_info = conn.get_conn_info();
        let conn_pubkey = conn_info.noise_remote_static_pubkey.clone();
        {
            let mut peer_pubkey = self.peer_public_key.write();
            if let Some(existing_pubkey) = peer_pubkey.as_ref() {
                if existing_pubkey != &conn_pubkey {
                    return Err(Error::SecretKeyError(format!(
                        "peer public key mismatch. peer_id: {}, existing_len: {}, new_len: {}",
                        self.peer_node_id,
                        existing_pubkey.len(),
                        conn_pubkey.len()
                    )));
                }
            } else {
                *peer_pubkey = Some(conn_pubkey);
            }
        }

        conn.set_alternate_fec_decoder(self.alternate_fec_decoder.clone());
        conn.start_recv_loop(self.packet_recv_chan.clone()).await;
        conn.start_pingpong();
        self.conns.insert(conn.get_conn_id(), Arc::new(conn));

        let close_event_sender = self.close_event_sender.clone();
        tokio::spawn(async move {
            let conn_id = close_notifier.get_conn_id();
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            if let Err(e) = close_event_sender.send(conn_id).await {
                tracing::warn!(?conn_id, "failed to send close event: {}", e);
            }
        });

        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerConnAdded(conn_info));
        Ok(())
    }

    pub(crate) fn set_origin_auth_update(&self, update: OriginAuthUpdate) {
        *self.origin_auth_update.write() = update;
    }

    fn best_connection(&self, policy: NextHopPolicy) -> Option<ArcPeerConn> {
        let now = std::time::Instant::now();
        let flags = self.global_ctx.flags_arc();
        let preferred_protocol = flags.default_protocol.as_str();
        let current_conn_id = self.default_conn_id.load();
        match policy {
            NextHopPolicy::MaxGoodput => self
                .conns
                .iter()
                .filter(|entry| !entry.value().is_closed())
                .min_by_key(|entry| {
                    let conn = entry.value();
                    let speed = conn
                        .fresh_speed_sample(now)
                        .filter(|sample| sample.delivery_bps > 0);
                    let latency_us = conn.get_stats().latency_us;
                    (
                        speed.is_none(),
                        std::cmp::Reverse(
                            speed.map(|sample| sample.delivery_bps).unwrap_or_default(),
                        ),
                        latency_us == 0,
                        latency_us,
                        conn.tunnel_type() != Some(preferred_protocol),
                        conn.get_conn_id() != current_conn_id,
                        conn.get_conn_id(),
                    )
                })
                .map(|entry| entry.value().clone()),
            NextHopPolicy::LeastCost => self
                .conns
                .iter()
                .filter(|entry| !entry.value().is_closed())
                .min_by_key(|entry| {
                    let conn = entry.value();
                    let latency_us = conn.get_stats().latency_us;
                    (
                        latency_us == 0,
                        latency_us,
                        conn.tunnel_type() != Some(preferred_protocol),
                        conn.get_conn_id() != current_conn_id,
                        conn.get_conn_id(),
                    )
                })
                .map(|entry| entry.value().clone()),
            NextHopPolicy::LeastHop => self
                .conns
                .iter()
                .filter(|entry| !entry.value().is_closed())
                .min_by_key(|entry| {
                    let conn = entry.value();
                    let latency_us = conn.get_stats().latency_us;
                    (
                        conn.tunnel_type() != Some(preferred_protocol),
                        latency_us == 0,
                        latency_us,
                        conn.get_conn_id() != current_conn_id,
                        conn.get_conn_id(),
                    )
                })
                .map(|entry| entry.value().clone()),
        }
    }

    pub(crate) fn select_conn_for_flow(
        &self,
        policy: NextHopPolicy,
        flow_hash: u64,
    ) -> Option<ArcPeerConn> {
        if let Some(conn) = self.only_direct_conn() {
            self.default_conn_id.store(conn.get_conn_id());
            return Some(conn);
        }
        let policy_flow = match policy {
            NextHopPolicy::LeastHop => flow_hash,
            NextHopPolicy::LeastCost => flow_hash ^ (1_u64 << 63),
            NextHopPolicy::MaxGoodput => flow_hash ^ (1_u64 << 62),
        };
        let selected_id = self.connection_flow_paths.select_with_candidate(
            self.peer_node_id,
            policy_flow,
            0,
            None,
            || self.best_connection(policy).map(|conn| conn.get_conn_id()),
            |conn_id| {
                self.conns
                    .get(&conn_id)
                    .is_some_and(|conn| !conn.is_closed())
            },
        )?;
        let selected = self.conns.get(&selected_id)?.clone();
        self.default_conn_id.store(selected.get_conn_id());
        Some(selected)
    }

    pub(crate) fn only_direct_conn(&self) -> Option<ArcPeerConn> {
        if self.conns.len() != 1 {
            return None;
        }
        self.conns
            .iter()
            .find(|entry| !entry.value().is_closed())
            .map(|entry| entry.value().clone())
    }

    fn packet_connection_policy(packet: &ZCPacket) -> NextHopPolicy {
        let Some(header) = packet.peer_manager_header() else {
            return NextHopPolicy::LeastHop;
        };
        if header.is_critical_l2_control() {
            NextHopPolicy::LeastCost
        } else if header.is_speed_first() {
            NextHopPolicy::MaxGoodput
        } else if header.is_latency_first() {
            NextHopPolicy::LeastCost
        } else {
            NextHopPolicy::LeastHop
        }
    }

    pub async fn send_msg(&self, mut msg: ZCPacket) -> Result<(), Error> {
        stamp_critical_l2_control(&mut msg);
        stamp_packet_flow(&mut msg);
        let policy = Self::packet_connection_policy(&msg);
        let flow_hash = classify_packet_flow(&msg).hash;
        let Some(conn) = self.select_conn_for_flow(policy, flow_hash) else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        if let Some(encoder) = self.alternate_fec_encoder.as_ref()
            && conn.alternate_fec_remote_receive_ready()
            && is_alternate_fec_source(&msg, self.peer_node_id)
            && let Some(alternate) = select_alternate_conn(&self.conns, &conn)
            && alternate.alternate_fec_remote_receive_ready()
        {
            let capture_allowed = {
                let encoder = encoder.lock();
                alternate_fec_capture_allowed(&conn, &alternate, &msg, &encoder)
            };
            if capture_allowed {
                conn.encrypt_alternate_fec_source(&mut msg)?;
                let metadata = source_metadata(&msg)?;
                let local_peer_id = msg.peer_manager_header().unwrap().from_peer_id.get();
                self.alternate_fec_primary.store(conn.get_conn_id());
                self.alternate_fec_local_peer_id
                    .store(local_peer_id, Ordering::Relaxed);
                let parity_sender = self.alternate_fec_parity_sender.as_ref();
                let source = {
                    let mut encoder = encoder.lock();
                    let output =
                        encoder.push(msg.tunnel_payload_into_bytes(), std::time::Instant::now())?;
                    if let Some(block) = output.completed
                        && let Some(sender) = parity_sender.as_ref()
                    {
                        enqueue_alternate_parity(
                            sender,
                            AlternateFecParityWork {
                                conn: alternate.clone(),
                                local_peer_id,
                                block,
                            },
                        );
                    }
                    output.source
                };
                if let Some(notify) = self.alternate_fec_notify.as_ref() {
                    notify.notify_one();
                }
                let wrapped = wrap_source_packet(metadata, source);
                let source_bytes = wrapped.buf_len();
                conn.send_msg(wrapped).await?;
                self.global_ctx.dataplane_telemetry().record_fec(
                    DataplaneFec::SourceTx,
                    1,
                    source_bytes,
                );
                return Ok(());
            }
        }

        conn.send_msg(msg).await?;

        Ok(())
    }

    pub async fn send_msg_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let mut batch = match batch.pop_singleton() {
            Ok(packet) => return self.send_msg(packet).await,
            Err(batch) => batch,
        };
        for packet in batch.iter_mut() {
            stamp_critical_l2_control(packet);
            stamp_packet_flow(packet);
        }
        let first = batch.first().expect("a non-singleton batch is not empty");
        let policy = Self::packet_connection_policy(first);
        let flow_hash = classify_packet_flow(first).hash;
        let Some(conn) = self.select_conn_for_flow(policy, flow_hash) else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        self.send_msg_batch_to_conn(conn, batch).await
    }

    async fn send_msg_batch_to_conn(
        &self,
        conn: ArcPeerConn,
        batch: PacketBatch,
    ) -> Result<(), Error> {
        if let Some(encoder) = self.alternate_fec_encoder.as_ref()
            && conn.alternate_fec_remote_receive_ready()
            && batch
                .iter()
                .any(|packet| is_alternate_fec_source(packet, self.peer_node_id))
            && let Some(alternate) = select_alternate_conn(&self.conns, &conn)
            && alternate.alternate_fec_remote_receive_ready()
        {
            let parity_sender = self.alternate_fec_parity_sender.as_ref();
            let (primary_batch, local_peer_id, source_records, source_bytes) = {
                let mut primary_batch = PacketBatch::with_capacity(batch.len());
                let mut local_peer_id = 0;
                let mut source_records = 0;
                let mut source_bytes = 0;
                let mut encoder = encoder.lock();
                for mut packet in batch {
                    if is_alternate_fec_source(&packet, self.peer_node_id)
                        && alternate_fec_capture_allowed(&conn, &alternate, &packet, &encoder)
                    {
                        conn.encrypt_alternate_fec_source(&mut packet)?;
                        let metadata = source_metadata(&packet)?;
                        local_peer_id = packet.peer_manager_header().unwrap().from_peer_id.get();
                        source_records += 1;
                        let output = encoder.push(
                            packet.tunnel_payload_into_bytes(),
                            std::time::Instant::now(),
                        )?;
                        let completed = output.completed;
                        let wrapped = wrap_source_packet(metadata, output.source);
                        source_bytes += wrapped.buf_len();
                        primary_batch
                            .try_push(wrapped)
                            .expect("alternate FEC source preserves the input batch bound");
                        if let Some(block) = completed
                            && let Some(sender) = parity_sender
                        {
                            enqueue_alternate_parity(
                                sender,
                                AlternateFecParityWork {
                                    conn: alternate.clone(),
                                    local_peer_id,
                                    block,
                                },
                            );
                        }
                    } else {
                        primary_batch
                            .try_push(packet)
                            .expect("alternate FEC preserves the input batch bound");
                    }
                }
                (primary_batch, local_peer_id, source_records, source_bytes)
            };
            self.alternate_fec_primary.store(conn.get_conn_id());
            self.alternate_fec_local_peer_id
                .store(local_peer_id, Ordering::Relaxed);
            if source_records != 0
                && let Some(notify) = self.alternate_fec_notify.as_ref()
            {
                notify.notify_one();
            }
            conn.send_msg_batch(primary_batch).await?;
            if source_records != 0 {
                self.global_ctx.dataplane_telemetry().record_fec(
                    DataplaneFec::SourceTx,
                    source_records,
                    source_bytes,
                );
            }
            return Ok(());
        }

        conn.send_msg_batch(batch).await?;

        Ok(())
    }

    pub(crate) async fn send_msg_on_conn(
        &self,
        conn: &ArcPeerConn,
        mut msg: ZCPacket,
    ) -> Result<(), Error> {
        stamp_critical_l2_control(&mut msg);
        stamp_packet_flow(&mut msg);
        conn.send_msg(msg).await
    }

    pub(crate) async fn send_msg_batch_on_conn(
        &self,
        conn: &ArcPeerConn,
        mut batch: PacketBatch,
    ) -> Result<(), Error> {
        for packet in batch.iter_mut() {
            stamp_critical_l2_control(packet);
            stamp_packet_flow(packet);
        }
        self.send_msg_batch_to_conn(conn.clone(), batch).await
    }

    /// Sends a batch whose control and flow metadata was already stamped by
    /// `PeerManager::prepare_packet_batch`.
    pub(crate) async fn send_prepared_msg_batch_on_conn(
        &self,
        conn: &ArcPeerConn,
        batch: PacketBatch,
    ) -> Result<(), Error> {
        debug_assert!(batch.iter().all(|packet| packet.flow_hash().is_some()));
        self.send_msg_batch_to_conn(conn.clone(), batch).await
    }

    pub async fn close_peer_conn(&self, conn_id: &PeerConnId) -> Result<(), Error> {
        let has_key = self.conns.contains_key(conn_id);
        if !has_key {
            return Err(Error::NotFound);
        }
        self.close_event_sender.send(*conn_id).await.unwrap();
        Ok(())
    }

    pub async fn list_peer_conns(&self) -> Vec<PeerConnInfo> {
        let mut conns = vec![];
        for conn in self.conns.iter() {
            // do not lock here, otherwise it will cause dashmap deadlock
            conns.push(conn.clone());
        }

        let mut ret = Vec::new();
        for conn in conns {
            let info = conn.get_conn_info();
            if !info.is_closed {
                ret.push(info);
            } else {
                let conn_id = info.conn_id.parse().unwrap();
                let _ = self.close_peer_conn(&conn_id).await;
            }
        }
        ret
    }

    pub(crate) fn speed_probe_connections(&self) -> Vec<ArcPeerConn> {
        self.conns
            .iter()
            .filter(|entry| !entry.value().is_closed() && entry.value().supports_speed_routing())
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn has_live_conns(&self) -> bool {
        self.conns.iter().any(|entry| !entry.value().is_closed())
    }

    pub fn has_directly_connected_conn(&self) -> bool {
        self.conns
            .iter()
            .any(|entry| !entry.value().is_closed() && !entry.value().is_hole_punched())
    }

    pub fn get_directly_connections(&self) -> DashSet<uuid::Uuid> {
        self.conns
            .iter()
            .filter(|entry| !(entry.value()).is_hole_punched())
            .map(|entry| (entry.value()).get_conn_id())
            .collect()
    }

    /// Return one live connection only when the caller names its exact session.
    pub(crate) fn get_live_conn(&self, conn_id: PeerConnId) -> Option<ArcPeerConn> {
        self.conns
            .get(&conn_id)
            .filter(|entry| !entry.value().is_closed())
            .map(|entry| entry.value().clone())
    }

    pub fn get_default_conn_id(&self) -> PeerConnId {
        self.default_conn_id.load()
    }

    pub fn get_peer_identity_type(&self) -> Option<PeerIdentityType> {
        if let Some(identity_type) = self.peer_identity_type.load() {
            return Some(identity_type);
        }

        let identity_type = self
            .conns
            .iter()
            .next()
            .map(|connection| connection.get_peer_identity_type());
        if let Some(identity_type) = identity_type {
            self.peer_identity_type.store(Some(identity_type));
        }
        identity_type
    }

    pub fn get_peer_public_key(&self) -> Option<Vec<u8>> {
        self.peer_public_key.read().clone()
    }

    /// Return the strongest authenticated level from a live direct session.
    pub fn get_peer_secure_auth_level(&self) -> Option<SecureAuthLevel> {
        self.conns
            .iter()
            .filter(|entry| !entry.value().is_closed())
            .filter_map(|entry| entry.value().secure_auth_level())
            .max_by_key(|level| *level as i32)
    }

    /// Return one direct authentication tuple only when every live connection
    /// agrees on the same peer key, role, and authentication level.
    pub(crate) fn authenticated_origin_evidence(
        &self,
    ) -> Option<(PeerIdentityType, Vec<u8>, SecureAuthLevel)> {
        Self::authenticated_origin_evidence_from_map(&self.conns)
    }

    fn authenticated_origin_evidence_from_map(
        conns: &ConnMap,
    ) -> Option<(PeerIdentityType, Vec<u8>, SecureAuthLevel)> {
        let mut evidence = None;
        for connection in conns.iter().filter(|entry| !entry.value().is_closed()) {
            let candidate = connection.value().origin_auth_tuple()?;
            if candidate.1.len() != 32
                || !crate::peers::route_trait::AuthenticatedRoutePeerEvidence::
                    is_allowed_role_auth_pair(candidate.0, candidate.2)
            {
                return None;
            }
            if evidence
                .as_ref()
                .is_some_and(|current| current != &candidate)
            {
                return None;
            }
            evidence = Some(candidate);
        }
        evidence
    }
}

// pritn on drop
impl Drop for Peer {
    fn drop(&mut self) {
        self.conns.retain(|_, conn| {
            self.global_ctx
                .issue_event(GlobalCtxEvent::PeerConnRemoved(conn.get_conn_info()));
            false
        });
        self.shutdown_notifier.notify_one();
        tracing::info!("peer {} drop", self.peer_node_id);
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_STANDARD, Engine as _};
    use rand::rngs::OsRng;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use crate::proto::common::TunnelInfo;
    use crate::tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    };
    use crate::{
        common::{
            config::{NetworkIdentity, PeerConfig},
            global_ctx::{
                GlobalCtx,
                tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            },
            new_peer_id,
        },
        peers::{
            create_packet_recv_chan, peer_conn::PeerConn, peer_session::PeerSessionStore,
            route_trait::NextHopPolicy, speed_probe::SpeedSample,
        },
        proto::common::SecureModeConfig,
        tunnel::ring::create_ring_tunnel_pair,
    };

    use super::Peer;
    use super::{
        ALTERNATE_FEC_PARITY_QUEUE_CAPACITY, AlternateFecParityWork, enqueue_alternate_parity,
        is_alternate_fec_source, wait_for_alternate_fec_deadline,
    };
    use crate::peers::alternate_fec::CompletedAlternateFecBlock;

    #[test]
    fn critical_l2_control_bypasses_alternate_fec() {
        let mut frame = vec![0_u8; 14 + 28];
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload(&frame);
        packet.fill_peer_manager_hdr(11, 22, PacketType::Ethernet as u8);

        assert!(crate::peers::flow::stamp_critical_l2_control(&mut packet));
        assert!(!is_alternate_fec_source(&packet, 22));
    }

    #[tokio::test]
    async fn alternate_fec_waiter_stays_idle_until_data_arrives() {
        let now = std::time::Instant::now();
        let delay = std::time::Duration::from_millis(40);
        let encoder = Arc::new(parking_lot::Mutex::new(
            crate::peers::alternate_fec::AlternateFecEncoder::new(2, delay).unwrap(),
        ));
        let notify = Arc::new(tokio::sync::Notify::new());
        let wait = wait_for_alternate_fec_deadline(encoder.clone(), notify.clone());
        tokio::pin!(wait);

        assert!(futures::poll!(wait.as_mut()).is_pending());
        encoder
            .lock()
            .push(bytes::Bytes::from_static(b"source"), now)
            .unwrap();
        notify.notify_one();

        assert_eq!(wait.await, now + delay);
    }

    fn parity_work(
        conn: Arc<PeerConn>,
        block_id: u64,
        local_peer_id: crate::common::PeerId,
    ) -> AlternateFecParityWork {
        AlternateFecParityWork {
            conn,
            local_peer_id,
            block: CompletedAlternateFecBlock::for_test(
                block_id,
                1,
                vec![bytes::Bytes::from_static(b"parity")],
            ),
        }
    }

    #[tokio::test]
    async fn alternate_fec_primary_enqueue_does_not_wait_for_blocked_sink() {
        let global_ctx = get_mock_global_ctx();
        let conn = Arc::new(unstarted_peer_conn(global_ctx));
        let (sender, _receiver) = mpsc::channel(ALTERNATE_FEC_PARITY_QUEUE_CAPACITY);
        for block_id in 1..=ALTERNATE_FEC_PARITY_QUEUE_CAPACITY as u64 {
            enqueue_alternate_parity(&sender, parity_work(conn.clone(), block_id, 11));
        }

        let result = timeout(Duration::from_millis(50), async {
            enqueue_alternate_parity(&sender, parity_work(conn.clone(), 10_000, 11));
        })
        .await;
        assert!(result.is_ok(), "primary enqueue waited for the parity sink");
    }

    #[tokio::test]
    async fn alternate_fec_parity_queue_preserves_block_order() {
        let global_ctx = get_mock_global_ctx();
        let conn = Arc::new(unstarted_peer_conn(global_ctx));
        let (sender, mut receiver) = mpsc::channel(ALTERNATE_FEC_PARITY_QUEUE_CAPACITY);
        for block_id in 1..=3 {
            enqueue_alternate_parity(&sender, parity_work(conn.clone(), block_id, 11));
        }

        let mut received = Vec::new();
        while let Some(work) = receiver.recv().await {
            received.push(work.block.block_id);
            if received.len() == 3 {
                break;
            }
        }
        assert_eq!(received, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn alternate_fec_parity_queue_is_bounded_and_releases_work_on_shutdown() {
        let global_ctx = get_mock_global_ctx();
        let conn = Arc::new(unstarted_peer_conn(global_ctx));
        let (sender, receiver) = mpsc::channel(ALTERNATE_FEC_PARITY_QUEUE_CAPACITY);
        for block_id in 1..=ALTERNATE_FEC_PARITY_QUEUE_CAPACITY as u64 {
            enqueue_alternate_parity(&sender, parity_work(conn.clone(), block_id, 11));
        }
        assert!(matches!(
            sender.try_send(parity_work(conn.clone(), 10_000, 11)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert!(Arc::strong_count(&conn) > 1);
        drop(receiver);
        assert_eq!(Arc::strong_count(&conn), 1);
    }

    fn unstarted_peer_conn(global_ctx: Arc<GlobalCtx>) -> PeerConn {
        let (tunnel, _other_end) = create_ring_tunnel_pair();
        PeerConn::new(
            new_peer_id(),
            global_ctx,
            Box::new(tunnel),
            Arc::new(PeerSessionStore::new()),
        )
    }

    fn test_tunnel_info(protocol: &str, local: &str, remote: &str) -> TunnelInfo {
        TunnelInfo {
            tunnel_type: protocol.into(),
            local_addr: Some(url::Url::parse(local).unwrap().into()),
            remote_addr: Some(url::Url::parse(remote).unwrap().into()),
            resolved_remote_addr: Some(url::Url::parse(remote).unwrap().into()),
        }
    }

    #[tokio::test]
    async fn l2_parity_uses_the_distinct_authenticated_connection() {
        let peer_a_id = new_peer_id();
        let peer_b_id = new_peer_id();
        let ctx_a = get_mock_global_ctx();
        let ctx_b = get_mock_global_ctx();
        for ctx in [&ctx_a, &ctx_b] {
            let mut flags = ctx.get_flags().clone();
            flags.quic_datagram_fec_parity = 2;
            flags.quic_datagram_alternate_path_parity = true;
            ctx.set_flags(flags);
        }
        let (send_a, _recv_a) = create_packet_recv_chan();
        let (send_b, mut recv_b) = create_packet_recv_chan();
        let peer_a = Peer::new(peer_b_id, send_a, ctx_a.clone());
        let peer_b = Peer::new(peer_a_id, send_b, ctx_b.clone());
        let sessions_a = Arc::new(PeerSessionStore::new());
        let sessions_b = Arc::new(PeerSessionStore::new());

        let mut local_ids = Vec::new();
        for (index, (local_ip, remote_ip)) in [
            ("192.0.2.10", "198.51.100.20"),
            ("192.0.2.11", "203.0.113.50"),
        ]
        .into_iter()
        .enumerate()
        {
            let (tunnel_a, tunnel_b) = create_ring_tunnel_pair();
            let mut conn_a = PeerConn::new(peer_a_id, ctx_a.clone(), tunnel_a, sessions_a.clone());
            let mut conn_b = PeerConn::new(peer_b_id, ctx_b.clone(), tunnel_b, sessions_b.clone());
            let (client, server) = tokio::join!(
                conn_a.do_handshake_as_client(),
                conn_b.do_handshake_as_server()
            );
            client.unwrap();
            server.unwrap();
            conn_a.set_tunnel_info_for_test(test_tunnel_info(
                "quic",
                &format!("quic://{local_ip}:{}", 31000 + index),
                &format!("quic://{remote_ip}:11010"),
            ));
            conn_b.set_tunnel_info_for_test(test_tunnel_info(
                "quic",
                &format!("quic://{remote_ip}:11010"),
                &format!("quic://{local_ip}:{}", 31000 + index),
            ));
            conn_a.record_latency_for_test(1_000 + index as u32 * 1_000);
            let local_id = conn_a.get_conn_id();
            local_ids.push(local_id);
            peer_a.add_peer_conn(conn_a).await.unwrap();
            peer_b.add_peer_conn(conn_b).await.unwrap();
        }
        peer_a.default_conn_id.store(local_ids[0]);
        let alternate_before = peer_a
            .conns
            .get(&local_ids[1])
            .unwrap()
            .get_stats()
            .tx_packets;

        let mut batch = PacketBatch::with_capacity(16);
        for index in 0_u8..16 {
            let mut packet = ZCPacket::new_with_payload(&[index; 128]);
            packet.fill_peer_manager_hdr(peer_a_id, peer_b_id, PacketType::Ethernet as u8);
            batch.try_push(packet).unwrap();
        }
        let selected_primary = peer_a.conns.get(&local_ids[0]).unwrap().clone();
        let primary_before = selected_primary.get_stats().tx_packets;
        peer_a
            .send_msg_batch_on_conn(&selected_primary, batch)
            .await
            .unwrap();

        let mut received = Vec::new();
        timeout(std::time::Duration::from_secs(2), async {
            while received.len() < 16 {
                received.push(recv_b.recv().await.unwrap().payload()[0]);
            }
        })
        .await
        .unwrap();
        received.sort_unstable();
        assert_eq!(received, (0_u8..16).collect::<Vec<_>>());
        assert!(
            selected_primary.get_stats().tx_packets >= primary_before + 16,
            "source records must stay on the selected primary connection"
        );
        timeout(std::time::Duration::from_secs(2), async {
            loop {
                let alternate_after = peer_a
                    .conns
                    .get(&local_ids[1])
                    .unwrap()
                    .get_stats()
                    .tx_packets;
                if alternate_after >= alternate_before + 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    fn set_secure_mode_cfg(global_ctx: &GlobalCtx, enabled: bool) {
        if !enabled {
            global_ctx.config.set_secure_mode(None);
        } else {
            let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&private);
            global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
                ..Default::default()
            }));
        }
    }
}
