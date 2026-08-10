use std::sync::Arc;

#[cfg(feature = "quic")]
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "quic")]
use bytes::Bytes;
use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
#[cfg(feature = "quic")]
use parking_lot::Mutex;
use parking_lot::RwLock;

use tokio::{select, sync::mpsc};

use tracing::Instrument;

#[cfg(feature = "quic")]
use super::alternate_fec::{
    AlternateFecDecoder, AlternateFecEncoder, AlternateFecMetrics, CompletedAlternateFecBlock,
    parity_packets, wrap_source_packet,
};
use super::{
    PacketRecvChan,
    peer_conn::{PeerConn, PeerConnId},
};
#[cfg(feature = "quic")]
use crate::tunnel::packet_def::PacketType;
use crate::{common::shrink_dashmap, proto::api::instance::PeerConnInfo};
use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    proto::peer_rpc::PeerIdentityType,
    tunnel::{batch::PacketBatch, packet_def::ZCPacket},
};
use tokio_util::task::AbortOnDropHandle;

type ArcPeerConn = Arc<PeerConn>;
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn_id: Arc<AtomicCell<PeerConnId>>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    default_conn_id_clear_task: AbortOnDropHandle<()>,

    #[cfg(feature = "quic")]
    alternate_fec_encoder: Option<Arc<Mutex<AlternateFecEncoder>>>,
    #[cfg(feature = "quic")]
    alternate_fec_decoder: Option<Arc<Mutex<AlternateFecDecoder>>>,
    #[cfg(feature = "quic")]
    alternate_fec_primary: Arc<AtomicCell<PeerConnId>>,
    #[cfg(feature = "quic")]
    alternate_fec_local_peer_id: Arc<AtomicU32>,
    #[cfg(feature = "quic")]
    alternate_fec_metrics: Arc<AlternateFecMetrics>,
    #[cfg(feature = "quic")]
    alternate_fec_flush_task: Option<AbortOnDropHandle<()>>,
}

#[cfg(feature = "quic")]
fn select_alternate_conn(conns: &ConnMap, primary: &ArcPeerConn) -> Option<ArcPeerConn> {
    conns
        .iter()
        .filter(|candidate| {
            !candidate.value().is_closed()
                && candidate.get_conn_id() != primary.get_conn_id()
                && candidate.value().alternate_parity_path_allowed()
                && primary.has_distinct_quic_surface(candidate.value())
        })
        .min_by_key(|candidate| {
            let latency = candidate.value().get_stats().latency_us;
            if latency == 0 { u64::MAX } else { latency }
        })
        .map(|candidate| candidate.clone())
}

#[cfg(feature = "quic")]
async fn send_alternate_parity(
    conn: &ArcPeerConn,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    block: CompletedAlternateFecBlock,
    metrics: &AlternateFecMetrics,
) {
    let block_id = block.block_id;
    let source_count = block.source_count;
    let parity_records = block.parity.len();
    let parity_bytes = block.parity.iter().map(Bytes::len).sum();
    let packets = parity_packets(local_peer_id, remote_peer_id, block);
    let mut batch = PacketBatch::with_capacity(packets.len());
    for packet in packets {
        batch
            .try_push(packet)
            .expect("alternate parity batch is bounded to three packets");
    }
    if let Err(error) = conn.send_msg_batch(batch).await {
        metrics.record_parity_send_failure();
        tracing::warn!(
            ?error,
            block_id,
            source_count,
            "alternate-path parity send failed"
        );
    } else {
        metrics.record_parity_sent(parity_records, parity_bytes);
    }
}

impl Peer {
    pub fn new(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::new());
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());
        let peer_identity_type = Arc::new(AtomicCell::new(None));
        let peer_identity_type_copy = peer_identity_type.clone();
        let peer_public_key = Arc::new(RwLock::new(None));
        let peer_public_key_copy = peer_public_key.clone();

        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let global_ctx_copy = global_ctx.clone();
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
                                global_ctx_copy.issue_event(GlobalCtxEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
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
        let default_conn_id_clear_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let has_sampled_connection = conns_copy.iter().any(|entry| {
                    !entry.value().is_closed() && entry.value().get_stats().latency_us > 0
                });
                if conns_copy.len() > 1 && has_sampled_connection {
                    default_conn_id_copy.store(PeerConnId::default());
                }
            }
        }));

        #[cfg(feature = "quic")]
        let (alternate_fec_encoder, alternate_fec_decoder) = {
            let flags = global_ctx.get_flags();
            if flags.quic_datagram_alternate_path_parity
                && matches!(flags.quic_datagram_fec_parity, 2 | 3)
            {
                (
                    Some(Arc::new(Mutex::new(
                        AlternateFecEncoder::new(
                            flags.quic_datagram_fec_parity as usize,
                            crate::tunnel::quic::fec::FEC_FLUSH_DELAY,
                        )
                        .expect("validated alternate FEC configuration"),
                    ))),
                    Some(Arc::new(Mutex::new(AlternateFecDecoder::default()))),
                )
            } else {
                (None, None)
            }
        };
        #[cfg(feature = "quic")]
        let alternate_fec_primary = Arc::new(AtomicCell::new(PeerConnId::default()));
        #[cfg(feature = "quic")]
        let alternate_fec_local_peer_id = Arc::new(AtomicU32::new(0));
        #[cfg(feature = "quic")]
        let alternate_fec_metrics = Arc::new(AlternateFecMetrics::default());
        #[cfg(feature = "quic")]
        let alternate_fec_flush_task = alternate_fec_encoder.as_ref().map(|encoder| {
            let encoder = encoder.clone();
            let conns = conns.clone();
            let primary_id = alternate_fec_primary.clone();
            let local_peer_id = alternate_fec_local_peer_id.clone();
            let metrics = alternate_fec_metrics.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut next_metrics =
                    std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    interval.tick().await;
                    let now = std::time::Instant::now();
                    if now >= next_metrics {
                        let metrics_row = metrics.tsv_row();
                        tracing::info!(
                            target: "CORE::ALTERNATE_FEC_METRICS",
                            event = "EAP1_METRICS",
                            reason = "periodic",
                            atomic_header = AlternateFecMetrics::tsv_header(),
                            atomic_row = %metrics_row,
                            "EAP1_METRICS_TSV\tperiodic\t{}",
                            metrics_row,
                        );
                        next_metrics = now + std::time::Duration::from_secs(5);
                    }
                    let block = match encoder.lock().take_due(now) {
                        Ok(Some(block)) => block,
                        Ok(None) => continue,
                        Err(error) => {
                            tracing::warn!(?error, "alternate-path FEC flush failed");
                            continue;
                        }
                    };
                    let Some(primary) = conns.get(&primary_id.load()).map(|conn| conn.clone())
                    else {
                        metrics.record_parity_skipped_no_path();
                        continue;
                    };
                    let Some(alternate) = select_alternate_conn(&conns, &primary) else {
                        metrics.record_parity_skipped_no_path();
                        continue;
                    };
                    let local_peer_id = local_peer_id.load(Ordering::Relaxed);
                    if local_peer_id != 0 {
                        send_alternate_parity(
                            &alternate,
                            local_peer_id,
                            peer_node_id,
                            block,
                            &metrics,
                        )
                        .await;
                    } else {
                        metrics.record_parity_skipped_no_path();
                    }
                }
            }))
        });

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            global_ctx,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn_id,
            peer_identity_type,
            peer_public_key,
            default_conn_id_clear_task,

            #[cfg(feature = "quic")]
            alternate_fec_encoder,
            #[cfg(feature = "quic")]
            alternate_fec_decoder,
            #[cfg(feature = "quic")]
            alternate_fec_primary,
            #[cfg(feature = "quic")]
            alternate_fec_local_peer_id,
            #[cfg(feature = "quic")]
            alternate_fec_metrics,
            #[cfg(feature = "quic")]
            alternate_fec_flush_task,
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

        #[cfg(feature = "quic")]
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

    async fn select_conn(&self) -> Option<ArcPeerConn> {
        let default_conn_id = self.default_conn_id.load();
        if let Some(conn) = self.conns.get(&default_conn_id)
            && !conn.is_closed()
        {
            return Some(conn.clone());
        }

        // A zero latency means ping sampling has not completed. It must not beat
        // a real measurement merely because its numeric value is smaller.
        let mut min_latency = u64::MAX;
        for conn in self.conns.iter() {
            if conn.value().is_closed() {
                continue;
            }
            let latency = conn.value().get_stats().latency_us;
            if latency > 0 && latency < min_latency {
                min_latency = latency;
                self.default_conn_id.store(conn.get_conn_id());
            }
        }

        if let Some(conn) = self.conns.get(&self.default_conn_id.load()) {
            return Some(conn.clone());
        }

        let fallback = self
            .conns
            .iter()
            .find(|conn| !conn.value().is_closed())
            .map(|conn| conn.clone());
        if let Some(conn) = &fallback {
            self.default_conn_id.store(conn.get_conn_id());
        }
        fallback
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        let Some(conn) = self.select_conn().await else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        #[cfg(feature = "quic")]
        if let Some(encoder) = self.alternate_fec_encoder.as_ref()
            && msg.peer_manager_header().is_some_and(|header| {
                header.packet_type == PacketType::Ethernet as u8
                    && header.to_peer_id.get() == self.peer_node_id
            })
            && let Some(alternate) = select_alternate_conn(&self.conns, &conn)
        {
            let header = msg.peer_manager_header().unwrap();
            let local_peer_id = header.from_peer_id.get();
            self.alternate_fec_primary.store(conn.get_conn_id());
            self.alternate_fec_local_peer_id
                .store(local_peer_id, Ordering::Relaxed);
            let source_bytes = msg.tunnel_payload().len();
            let output = encoder.lock().push(
                Bytes::copy_from_slice(msg.tunnel_payload()),
                std::time::Instant::now(),
            )?;
            let wrapped = wrap_source_packet(msg, output.source)?;
            conn.send_msg(wrapped).await?;
            self.alternate_fec_metrics.record_source(source_bytes);
            if let Some(block) = output.completed {
                send_alternate_parity(
                    &alternate,
                    local_peer_id,
                    self.peer_node_id,
                    block,
                    &self.alternate_fec_metrics,
                )
                .await;
            }
            return Ok(());
        }

        conn.send_msg(msg).await?;

        Ok(())
    }

    pub async fn send_msg_batch(&self, batch: PacketBatch) -> Result<(), Error> {
        let batch = match batch.pop_singleton() {
            Ok(packet) => return self.send_msg(packet).await,
            Err(batch) => batch,
        };
        let Some(conn) = self.select_conn().await else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        #[cfg(feature = "quic")]
        if let Some(encoder) = self.alternate_fec_encoder.as_ref()
            && batch.iter().any(|packet| {
                packet.peer_manager_header().is_some_and(|header| {
                    header.packet_type == PacketType::Ethernet as u8
                        && header.to_peer_id.get() == self.peer_node_id
                })
            })
            && let Some(alternate) = select_alternate_conn(&self.conns, &conn)
        {
            let mut primary_batch = PacketBatch::with_capacity(batch.len());
            let mut completed = Vec::new();
            let mut local_peer_id = 0;
            let mut source_records = 0;
            let mut source_bytes = 0;
            for packet in batch {
                if packet.peer_manager_header().is_some_and(|header| {
                    header.packet_type == PacketType::Ethernet as u8
                        && header.to_peer_id.get() == self.peer_node_id
                }) {
                    local_peer_id = packet.peer_manager_header().unwrap().from_peer_id.get();
                    source_records += 1;
                    source_bytes += packet.tunnel_payload().len();
                    let output = encoder.lock().push(
                        Bytes::copy_from_slice(packet.tunnel_payload()),
                        std::time::Instant::now(),
                    )?;
                    primary_batch
                        .try_push(wrap_source_packet(packet, output.source)?)
                        .expect("alternate FEC source preserves the input batch bound");
                    if let Some(block) = output.completed {
                        completed.push(block);
                    }
                } else {
                    primary_batch
                        .try_push(packet)
                        .expect("alternate FEC preserves the input batch bound");
                }
            }
            self.alternate_fec_primary.store(conn.get_conn_id());
            self.alternate_fec_local_peer_id
                .store(local_peer_id, Ordering::Relaxed);
            conn.send_msg_batch(primary_batch).await?;
            self.alternate_fec_metrics
                .record_sources(source_records, source_bytes);
            for block in completed {
                send_alternate_parity(
                    &alternate,
                    local_peer_id,
                    self.peer_node_id,
                    block,
                    &self.alternate_fec_metrics,
                )
                .await;
            }
            return Ok(());
        }

        conn.send_msg_batch(batch).await?;

        Ok(())
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

    pub fn get_default_conn_id(&self) -> PeerConnId {
        self.default_conn_id.load()
    }

    pub fn get_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.peer_identity_type.load()
    }

    pub fn get_peer_public_key(&self) -> Option<Vec<u8>> {
        self.peer_public_key.read().clone()
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
    use std::sync::Arc;
    use tokio::time::timeout;

    use crate::{
        common::{
            config::{NetworkIdentity, PeerConfig},
            global_ctx::{GlobalCtx, tests::get_mock_global_ctx},
            new_peer_id,
        },
        peers::{create_packet_recv_chan, peer_conn::PeerConn, peer_session::PeerSessionStore},
        proto::common::SecureModeConfig,
        tunnel::ring::create_ring_tunnel_pair,
    };
    #[cfg(feature = "quic")]
    use crate::{
        proto::common::TunnelInfo,
        tunnel::{
            batch::PacketBatch,
            packet_def::{PacketType, ZCPacket},
        },
    };

    use super::Peer;

    fn unstarted_peer_conn(global_ctx: Arc<GlobalCtx>) -> PeerConn {
        let (tunnel, _other_end) = create_ring_tunnel_pair();
        PeerConn::new(
            new_peer_id(),
            global_ctx,
            Box::new(tunnel),
            Arc::new(PeerSessionStore::new()),
        )
    }

    #[cfg(feature = "quic")]
    fn quic_test_info(local: &str, remote: &str) -> TunnelInfo {
        TunnelInfo {
            tunnel_type: "quic".into(),
            local_addr: Some(url::Url::parse(local).unwrap().into()),
            remote_addr: Some(url::Url::parse(remote).unwrap().into()),
            resolved_remote_addr: Some(url::Url::parse(remote).unwrap().into()),
        }
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn l2_parity_uses_the_distinct_authenticated_connection() {
        let peer_a_id = new_peer_id();
        let peer_b_id = new_peer_id();
        let ctx_a = get_mock_global_ctx();
        let ctx_b = get_mock_global_ctx();
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
            conn_a.set_tunnel_info_for_test(quic_test_info(
                &format!("quic://{local_ip}:{}", 31000 + index),
                &format!("quic://{remote_ip}:11010"),
            ));
            conn_b.set_tunnel_info_for_test(quic_test_info(
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
        peer_a.send_msg_batch(batch).await.unwrap();

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
        let alternate_after = peer_a
            .conns
            .get(&local_ids[1])
            .unwrap()
            .get_stats()
            .tx_packets;
        assert!(alternate_after >= alternate_before + 2);
        let metrics = peer_a.alternate_fec_metrics.snapshot();
        assert_eq!(metrics.source_records, 16);
        assert_eq!(metrics.parity_blocks_sent, 1);
        assert_eq!(metrics.parity_records_sent, 2);
        assert_eq!(metrics.parity_send_failures, 0);
        assert_eq!(metrics.parity_blocks_skipped_no_path, 0);
    }

    #[tokio::test]
    async fn sampled_connection_wins_over_unsampled_connection() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let peer = Peer::new(new_peer_id(), packet_send, global_ctx.clone());
        let unsampled = Arc::new(unstarted_peer_conn(global_ctx.clone()));
        let sampled = Arc::new(unstarted_peer_conn(global_ctx));
        sampled.record_latency_for_test(4_000);
        let sampled_id = sampled.get_conn_id();

        peer.conns.insert(unsampled.get_conn_id(), unsampled);
        peer.conns.insert(sampled_id, sampled);

        let selected_id = peer.select_conn().await.unwrap().get_conn_id();
        peer.conns.clear();
        assert_eq!(selected_id, sampled_id);
    }

    #[tokio::test]
    async fn refresh_keeps_live_selection_while_all_connections_are_unsampled() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let peer = Peer::new(new_peer_id(), packet_send, global_ctx.clone());
        let current = Arc::new(unstarted_peer_conn(global_ctx.clone()));
        let other = Arc::new(unstarted_peer_conn(global_ctx));
        let current_id = current.get_conn_id();

        peer.conns.insert(current_id, current);
        peer.conns.insert(other.get_conn_id(), other);
        peer.default_conn_id.store(current_id);

        tokio::time::sleep(std::time::Duration::from_secs(6)).await;

        let retained_id = peer.default_conn_id.load();
        let selected_id = peer.select_conn().await.unwrap().get_conn_id();
        peer.conns.clear();
        assert_eq!(retained_id, current_id);
        assert_eq!(selected_id, current_id);
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
            }));
        }
    }

    #[tokio::test]
    async fn close_peer() {
        let (local_packet_send, _local_packet_recv) = create_packet_recv_chan();
        let (remote_packet_send, _remote_packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer = Peer::new(new_peer_id(), local_packet_send, global_ctx.clone());
        let remote_peer = Peer::new(new_peer_id(), remote_packet_send, global_ctx.clone());

        let ps = Arc::new(PeerSessionStore::new());
        let (local_tunnel, remote_tunnel) = create_ring_tunnel_pair();
        let mut local_peer_conn = PeerConn::new(
            local_peer.peer_node_id,
            global_ctx.clone(),
            local_tunnel,
            ps.clone(),
        );
        let mut remote_peer_conn = PeerConn::new(
            remote_peer.peer_node_id,
            global_ctx.clone(),
            remote_tunnel,
            ps.clone(),
        );

        assert!(!local_peer_conn.handshake_done());
        assert!(!remote_peer_conn.handshake_done());

        let (a, b) = tokio::join!(
            local_peer_conn.do_handshake_as_client(),
            remote_peer_conn.do_handshake_as_server()
        );
        a.unwrap();
        b.unwrap();

        let local_conn_id = local_peer_conn.get_conn_id();

        local_peer.add_peer_conn(local_peer_conn).await.unwrap();
        remote_peer.add_peer_conn(remote_peer_conn).await.unwrap();

        assert_eq!(local_peer.list_peer_conns().await.len(), 1);
        assert_eq!(remote_peer.list_peer_conns().await.len(), 1);

        let close_handler =
            tokio::spawn(async move { local_peer.close_peer_conn(&local_conn_id).await });

        // wait for remote peer conn close
        timeout(std::time::Duration::from_secs(5), async {
            while !remote_peer.list_peer_conns().await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        println!("wait for close handler");
        close_handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_identity_type() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, global_ctx);

        let ps = Arc::new(PeerSessionStore::new());

        let (shared_client_tunnel, shared_server_tunnel) = create_ring_tunnel_pair();
        let shared_client_ctx = get_mock_global_ctx();
        let shared_server_ctx = get_mock_global_ctx();
        shared_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        shared_server_ctx
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "net2".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });
        set_secure_mode_cfg(&shared_client_ctx, true);
        set_secure_mode_cfg(&shared_server_ctx, true);
        let remote_url: url::Url = shared_client_tunnel
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        shared_client_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_public_key: Some(
                shared_server_ctx
                    .config
                    .get_secure_mode()
                    .unwrap()
                    .local_public_key
                    .unwrap(),
            ),
        }]);
        let mut shared_client_conn = PeerConn::new(
            local_peer_id,
            shared_client_ctx,
            Box::new(shared_client_tunnel),
            ps.clone(),
        );
        let mut shared_server_conn = PeerConn::new(
            remote_peer_id,
            shared_server_ctx,
            Box::new(shared_server_tunnel),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            shared_client_conn.do_handshake_as_client(),
            shared_server_conn.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();
        assert_eq!(
            shared_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::SharedNode
        );

        let (admin_client_tunnel, admin_server_tunnel) = create_ring_tunnel_pair();
        let admin_client_ctx = get_mock_global_ctx();
        let admin_server_ctx = get_mock_global_ctx();
        admin_client_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        admin_server_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        set_secure_mode_cfg(&admin_client_ctx, true);
        set_secure_mode_cfg(&admin_server_ctx, true);
        let mut admin_client_conn = PeerConn::new(
            local_peer_id,
            admin_client_ctx,
            Box::new(admin_client_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let mut admin_server_conn = PeerConn::new(
            remote_peer_id,
            admin_server_ctx,
            Box::new(admin_server_tunnel),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            admin_client_conn.do_handshake_as_client(),
            admin_server_conn.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();
        assert_eq!(
            admin_client_conn.get_peer_identity_type(),
            crate::proto::peer_rpc::PeerIdentityType::Admin
        );

        peer.add_peer_conn(shared_client_conn).await.unwrap();
        let ret = peer.add_peer_conn(admin_client_conn).await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn reject_peer_conn_with_mismatched_public_key() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let local_peer_id = new_peer_id();
        let remote_peer_id = new_peer_id();
        let peer = Peer::new(remote_peer_id, packet_send, get_mock_global_ctx());
        let ps = Arc::new(PeerSessionStore::new());

        let (client_tunnel_1, server_tunnel_1) = create_ring_tunnel_pair();
        let client_ctx_1 = get_mock_global_ctx();
        let server_ctx_1 = get_mock_global_ctx();
        client_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_1
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_1, true);
        set_secure_mode_cfg(&server_ctx_1, true);
        let mut client_conn_1 = PeerConn::new(
            local_peer_id,
            client_ctx_1,
            Box::new(client_tunnel_1),
            ps.clone(),
        );
        let mut server_conn_1 = PeerConn::new(
            remote_peer_id,
            server_ctx_1,
            Box::new(server_tunnel_1),
            ps.clone(),
        );
        let (c1, s1) = tokio::join!(
            client_conn_1.do_handshake_as_client(),
            server_conn_1.do_handshake_as_server()
        );
        c1.unwrap();
        s1.unwrap();

        let (client_tunnel_2, server_tunnel_2) = create_ring_tunnel_pair();
        let client_ctx_2 = get_mock_global_ctx();
        let server_ctx_2 = get_mock_global_ctx();
        client_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        server_ctx_2
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        set_secure_mode_cfg(&client_ctx_2, true);
        set_secure_mode_cfg(&server_ctx_2, true);
        let mut client_conn_2 = PeerConn::new(
            local_peer_id,
            client_ctx_2,
            Box::new(client_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let mut server_conn_2 = PeerConn::new(
            remote_peer_id,
            server_ctx_2,
            Box::new(server_tunnel_2),
            Arc::new(PeerSessionStore::new()),
        );
        let (c2, s2) = tokio::join!(
            client_conn_2.do_handshake_as_client(),
            server_conn_2.do_handshake_as_server()
        );
        c2.unwrap();
        s2.unwrap();

        let pubkey_1 = client_conn_1.get_conn_info().noise_remote_static_pubkey;
        let pubkey_2 = client_conn_2.get_conn_info().noise_remote_static_pubkey;
        assert_ne!(pubkey_1, pubkey_2);

        peer.add_peer_conn(client_conn_1).await.unwrap();
        assert_eq!(peer.get_peer_public_key(), Some(pubkey_1));
        let ret = peer.add_peer_conn(client_conn_2).await;
        assert!(ret.is_err());
    }
}
