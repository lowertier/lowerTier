use std::sync::Arc;

use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use parking_lot::RwLock;

use tokio::{select, sync::mpsc};

use tracing::Instrument;

use super::{
    PacketRecvChan,
    flow::{FlowPathCache, classify_packet_flow, stamp_critical_l2_control, stamp_packet_flow},
    peer_conn::{PeerConn, PeerConnId},
    route_trait::NextHopPolicy,
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

pub(crate) type OriginAuthUpdate =
    Arc<dyn Fn(PeerId, Option<(PeerIdentityType, Vec<u8>, SecureAuthLevel)>) + Send + Sync>;

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    _close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn_id: Arc<AtomicCell<PeerConnId>>,
    connection_flow_paths: Arc<FlowPathCache<PeerConnId>>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    origin_auth_update: Arc<RwLock<OriginAuthUpdate>>,
    _default_conn_refresh_task: AbortOnDropHandle<()>,
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

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            global_ctx,

            close_event_sender,
            _close_event_listener: close_event_listener,

            shutdown_notifier,
            default_conn_id,
            connection_flow_paths,
            peer_identity_type,
            peer_public_key,
            origin_auth_update,
            _default_conn_refresh_task: default_conn_refresh_task,
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
