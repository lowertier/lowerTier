use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use guarden::defer;
use prost::Message;
use quanta::Instant;
use rand::{RngCore, rngs::OsRng};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_stream::StreamExt;

use crate::common::{
    PeerId, shrink_dashmap,
    stats_manager::{LabelSet, LabelType, MetricName, StatsManager},
};
use crate::proto::common::{RpcCompressionInfo, RpcDescriptor, RpcPacket, RpcRequest, RpcResponse};
use crate::proto::rpc_impl::packet::{
    BuildRpcPacketArgs, MAX_RPC_BODY_BYTES, build_rpc_packet, compress_packet, decompress_packet,
    supported_rpc_compression,
};
use crate::proto::rpc_types::controller::Controller;
use crate::proto::rpc_types::descriptor::MethodDescriptor;
use crate::proto::rpc_types::{
    __rt::RpcClientFactory, descriptor::ServiceDescriptor, handler::Handler,
};

use crate::proto::rpc_types::error::{Error, Result};
use crate::tunnel::mpsc::{MpscTunnel, MpscTunnelSender};
use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::ring::create_ring_tunnel_pair;
use crate::tunnel::{Tunnel, TunnelError, ZCPacketStream, batch::BatchToScalarStream};

use super::packet::PacketMerger;
use super::{RpcTransactId, Transport};

type RpcPacketSender = mpsc::UnboundedSender<RpcPacket>;
type RpcPacketReceiver = mpsc::UnboundedReceiver<RpcPacket>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InflightRequestKey {
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    transaction_id: RpcTransactId,
}

struct InflightRequest {
    sender: RpcPacketSender,
    merger: PacketMerger,
    start_time: Instant,
    expected_remote_peer: PeerId,
    requester_peer: PeerId,
    authenticated_session_id: Option<uuid::Uuid>,
    process_memory: Arc<crate::common::global_ctx::ProcessMemoryGovernor>,
    retained_bytes: usize,
}

impl InflightRequest {
    fn new(
        sender: RpcPacketSender,
        start_time: Instant,
        expected_remote_peer: PeerId,
        requester_peer: PeerId,
    ) -> Self {
        Self {
            sender,
            merger: PacketMerger::new(),
            start_time,
            expected_remote_peer,
            requester_peer,
            authenticated_session_id: None,
            process_memory: crate::common::global_ctx::global_process_memory_governor(),
            retained_bytes: 0,
        }
    }
}

impl Drop for InflightRequest {
    fn drop(&mut self) {
        self.process_memory.release(self.retained_bytes);
    }
}

impl std::fmt::Debug for InflightRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InflightRequest")
            .field("sender", &self.sender)
            .field("start_time", &self.start_time)
            .field("expected_remote_peer", &self.expected_remote_peer)
            .field("requester_peer", &self.requester_peer)
            .field("authenticated_session_id", &self.authenticated_session_id)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerInfo {
    pub peer_id: PeerId,
    pub compression_info: RpcCompressionInfo,
    pub last_active: Option<Instant>,
}

type InflightRequestTable = Arc<DashMap<InflightRequestKey, InflightRequest>>;
pub(crate) type PeerInfoTable = Arc<DashMap<PeerId, PeerInfo>>;

fn response_peer_binding_valid(
    zc_packet: &ZCPacket,
    response: &RpcPacket,
    expected_remote_peer: PeerId,
    requester_peer: PeerId,
    logical_authenticated_peer_id: Option<PeerId>,
) -> bool {
    if response.from_peer != expected_remote_peer || response.to_peer != requester_peer {
        return false;
    }

    if let Some(authenticated_peer_id) = logical_authenticated_peer_id {
        return authenticated_peer_id == response.from_peer;
    }

    // Only local loopback may omit transport authentication metadata.
    expected_remote_peer == requester_peer
        && zc_packet.get_src_peer_id() == Some(response.from_peer)
        && zc_packet.get_dst_peer_id() == Some(response.to_peer)
}

fn response_session_binding_valid(
    authenticated_session_id: Option<uuid::Uuid>,
    expected_session_id: Option<uuid::Uuid>,
    remote_response: bool,
) -> bool {
    match (authenticated_session_id, expected_session_id) {
        (Some(actual), Some(expected)) => actual == expected,
        (Some(_), None) => true,
        (None, None) => !remote_response,
        (None, Some(_)) => false,
    }
}

pub struct Client {
    mpsc: Mutex<MpscTunnel<Box<dyn Tunnel>>>,
    transport: Mutex<Transport>,
    inflight_requests: InflightRequestTable,
    peer_info: PeerInfoTable,
    tasks: Mutex<JoinSet<()>>,
    stats_manager: Option<Arc<StatsManager>>,
    inflight_admission: Arc<Semaphore>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        let (ring_a, ring_b) = create_ring_tunnel_pair();
        Self {
            mpsc: Mutex::new(MpscTunnel::new(ring_a, None)),
            transport: Mutex::new(MpscTunnel::new(ring_b, None)),
            inflight_requests: Arc::new(DashMap::new()),
            peer_info: Arc::new(DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
            stats_manager: None,
            inflight_admission: Arc::new(Semaphore::new(256)),
        }
    }

    pub fn new_with_stats_manager(stats_manager: Arc<StatsManager>) -> Self {
        let mut ret = Self::new();
        ret.stats_manager = Some(stats_manager);
        ret
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
        let mut tasks = self.tasks.lock().unwrap();

        let peer_infos = self.peer_info.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let now = Instant::now();
                peer_infos.retain(|_, v| {
                    if let Some(last_active) = v.last_active {
                        return now.duration_since(last_active)
                            < std::time::Duration::from_secs(120);
                    }
                    true
                });
                peer_infos.shrink_to_fit();
            }
        });

        let mut rx = BatchToScalarStream::new(self.mpsc.lock().unwrap().get_stream());
        let inflight_requests = self.inflight_requests.clone();
        tasks.spawn(async move {
            while let Some(packet) = rx.next().await {
                if let Err(err) = packet {
                    tracing::error!(?err, "Failed to receive packet");
                    continue;
                }
                let zc_packet = packet.unwrap();
                let logical_authenticated_peer_id = zc_packet.logical_authenticated_peer_id();
                let logical_authenticated_peer_identity_type =
                    zc_packet.logical_authenticated_peer_identity_type();
                let logical_authenticated_peer_secure_auth_level =
                    zc_packet.logical_authenticated_peer_secure_auth_level();
                let logical_authenticated_session_id = zc_packet.logical_authenticated_session_id();
                let packet = match RpcPacket::decode(zc_packet.payload()) {
                    Err(err) => {
                        tracing::error!(?err, "Failed to decode packet");
                        continue;
                    }
                    Ok(packet) => packet,
                };

                if packet.is_request {
                    tracing::warn!(
                        transaction_id = packet.transaction_id,
                        body_len = packet.body.len(),
                        "Received non-response RPC packet"
                    );
                    continue;
                }

                let key = InflightRequestKey {
                    from_peer_id: packet.to_peer,
                    to_peer_id: packet.from_peer,
                    transaction_id: packet.transaction_id,
                };

                let Some(mut inflight_request) = inflight_requests.get_mut(&key) else {
                    tracing::warn!(
                        ?key,
                        ?inflight_requests,
                        "No inflight request found for key"
                    );
                    continue;
                };

                if !response_peer_binding_valid(
                    &zc_packet,
                    &packet,
                    inflight_request.expected_remote_peer,
                    inflight_request.requester_peer,
                    logical_authenticated_peer_id,
                ) {
                    tracing::warn!(
                        ?key,
                        response_from = packet.from_peer,
                        response_to = packet.to_peer,
                        expected_remote = inflight_request.expected_remote_peer,
                        requester = inflight_request.requester_peer,
                        "Dropping RPC response with a mismatched peer binding"
                    );
                    continue;
                }

                let self_rpc =
                    inflight_request.expected_remote_peer == inflight_request.requester_peer;
                if !self_rpc
                    && (logical_authenticated_peer_identity_type.is_none()
                        || logical_authenticated_peer_secure_auth_level.is_none())
                {
                    tracing::warn!(
                        ?key,
                        "Dropping remote RPC response with incomplete authenticated origin"
                    );
                    continue;
                }
                if !response_session_binding_valid(
                    logical_authenticated_session_id,
                    inflight_request.authenticated_session_id,
                    !self_rpc,
                ) {
                    tracing::warn!(
                        ?key,
                        "Dropping remote RPC response without an authenticated session"
                    );
                    continue;
                }
                if inflight_request.authenticated_session_id.is_none() {
                    inflight_request.authenticated_session_id = logical_authenticated_session_id;
                }

                tracing::trace!(
                    transaction_id = packet.transaction_id,
                    piece_idx = packet.piece_idx,
                    total_pieces = packet.total_pieces,
                    body_len = packet.body.len(),
                    "Received response RPC packet"
                );

                let reservation_bytes = if inflight_request.merger.contains_piece(packet.piece_idx)
                {
                    0
                } else {
                    let Some(reservation_bytes) = PacketMerger::reservation_bytes(
                        &packet,
                        inflight_request.merger.is_empty(),
                    ) else {
                        tracing::warn!(?key, "drop malformed RPC response reservation");
                        drop(inflight_request);
                        inflight_requests.remove(&key);
                        continue;
                    };
                    reservation_bytes
                };
                if reservation_bytes > 0
                    && !inflight_request.process_memory.reserve(reservation_bytes)
                {
                    tracing::warn!(?key, "drop RPC response because the memory limit is full");
                    drop(inflight_request);
                    inflight_requests.remove(&key);
                    continue;
                }
                let ret = inflight_request.merger.feed(packet);
                if ret.is_ok() {
                    inflight_request.retained_bytes += reservation_bytes;
                } else if reservation_bytes > 0 {
                    inflight_request.process_memory.release(reservation_bytes);
                }
                match ret {
                    Ok(Some(rpc_packet)) => {
                        if inflight_request.sender.send(rpc_packet).is_err() {
                            // The caller may have timed out while this response was in flight.
                            // Remove the stale request after releasing the DashMap guard.
                            drop(inflight_request);
                            inflight_requests.remove(&key);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::error!(?err, "Failed to feed packet to merger");
                    }
                }
            }
        });
    }

    pub fn scoped_client<F: RpcClientFactory>(
        &self,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        domain_name: String,
    ) -> F::ClientImpl {
        #[derive(Clone)]
        struct HandlerImpl<F> {
            domain_name: String,
            from_peer_id: PeerId,
            to_peer_id: PeerId,
            zc_packet_sender: MpscTunnelSender,
            inflight_requests: InflightRequestTable,
            peer_info: PeerInfoTable,
            stats_manager: Option<Arc<StatsManager>>,
            inflight_admission: Arc<Semaphore>,
            _phan: PhantomData<F>,
        }

        impl<F: RpcClientFactory> HandlerImpl<F> {
            async fn do_rpc(
                &self,
                packets: Vec<ZCPacket>,
                rx: &mut RpcPacketReceiver,
            ) -> Result<RpcPacket> {
                for packet in packets {
                    self.zc_packet_sender.send(packet).await?;
                }

                Ok(rx.recv().await.ok_or(TunnelError::Shutdown)?)
            }
        }

        #[async_trait::async_trait]
        impl<F: RpcClientFactory> Handler for HandlerImpl<F> {
            type Descriptor = F::Descriptor;
            type Controller = F::Controller;

            async fn call(
                &self,
                mut ctrl: Self::Controller,
                method: <Self::Descriptor as ServiceDescriptor>::Method,
                input: bytes::Bytes,
            ) -> Result<bytes::Bytes> {
                let start_time = Instant::now();
                let _inflight_permit = self
                    .inflight_admission
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("RPC client admission remains open");
                let (tx, mut rx) = mpsc::unbounded_channel();
                let desc = self.service_descriptor();
                let labels = LabelSet::new()
                    .with_label_type(LabelType::NetworkName(self.domain_name.to_string()))
                    .with_label_type(LabelType::SrcPeerId(self.from_peer_id))
                    .with_label_type(LabelType::DstPeerId(self.to_peer_id))
                    .with_label_type(LabelType::ServiceName(desc.name().to_string()))
                    .with_label_type(LabelType::MethodName(method.name().to_string()));

                let (transaction_id, key) = loop {
                    let transaction_id = OsRng.next_u64() as RpcTransactId;
                    let key = InflightRequestKey {
                        from_peer_id: self.from_peer_id,
                        to_peer_id: self.to_peer_id,
                        transaction_id,
                    };
                    match self.inflight_requests.entry(key.clone()) {
                        Entry::Vacant(entry) => {
                            entry.insert(InflightRequest::new(
                                tx.clone(),
                                start_time,
                                self.to_peer_id,
                                self.from_peer_id,
                            ));
                            break (transaction_id, key);
                        }
                        Entry::Occupied(_) => continue,
                    }
                };
                defer!(self.inflight_requests.remove(&key); shrink_dashmap(&self.inflight_requests, Some(4)););

                // Record RPC client TX stats
                if let Some(ref stats_manager) = self.stats_manager {
                    stats_manager
                        .get_counter(MetricName::PeerRpcClientTx, labels.clone())
                        .inc();
                }

                let rpc_desc = RpcDescriptor {
                    domain_name: self.domain_name.clone(),
                    proto_name: desc.proto_name().to_string(),
                    service_name: desc.name().to_string(),
                    method_index: method.index() as u32,
                };

                let rpc_req = RpcRequest {
                    request: if let Some(raw_input) = ctrl.get_raw_input() {
                        raw_input.into()
                    } else {
                        input.into()
                    },
                    timeout_ms: ctrl.timeout_ms(),
                    ..Default::default()
                };

                let rpc_req_bytes = rpc_req.encode_to_vec();
                if rpc_req_bytes.len() > MAX_RPC_BODY_BYTES {
                    return Err(Error::MalformatRpcPacket(format!(
                        "RPC request is too large: {} bytes",
                        rpc_req_bytes.len()
                    )));
                }

                let peer_info = self
                    .peer_info
                    .get(&self.to_peer_id)
                    .map(|v| v.clone())
                    .unwrap_or_default();
                let (buf, c_algo) = compress_packet(
                    peer_info.compression_info.accepted_algo(),
                    &rpc_req_bytes,
                )
                .await?;

                let packets = build_rpc_packet(BuildRpcPacketArgs {
                    from_peer: self.from_peer_id,
                    to_peer: self.to_peer_id,
                    rpc_desc,
                    transaction_id,
                    is_req: true,
                    content: &buf,
                    trace_id: ctrl.trace_id(),
                    compression_info: RpcCompressionInfo {
                        algo: c_algo.into(),
                        accepted_algo: supported_rpc_compression().into(),
                    },
                });
                let timeout_dur = std::time::Duration::from_millis(ctrl.timeout_ms() as u64);
                let mut rpc_packet = timeout(timeout_dur, self.do_rpc(packets, &mut rx)).await??;

                if let Some(compression_info) = rpc_packet.compression_info {
                    self.peer_info.insert(
                        self.to_peer_id,
                        PeerInfo {
                            peer_id: self.to_peer_id,
                            compression_info,
                            last_active: Some(Instant::now()),
                        },
                    );

                    rpc_packet.body =
                        decompress_packet(compression_info.algo(), &rpc_packet.body).await?;
                }

                assert_eq!(rpc_packet.transaction_id, transaction_id);

                let rpc_resp = RpcResponse::decode(Bytes::from(rpc_packet.body))?;

                if let Some(err) = &rpc_resp.error {
                    // Record RPC error stats
                    if let Some(ref stats_manager) = self.stats_manager {
                        let labels = labels
                            .clone()
                            .with_label_type(LabelType::ErrorType(format!("{:?}", err.error_kind)))
                            .with_label_type(LabelType::Status("error".to_string()));

                        stats_manager
                            .get_counter(MetricName::PeerRpcErrors, labels.clone())
                            .inc();

                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        stats_manager
                            .get_counter(MetricName::PeerRpcDuration, labels)
                            .add(duration_ms);
                    }
                    return Err(err.into());
                }

                let raw_output = Bytes::from(rpc_resp.response);
                ctrl.set_raw_output(raw_output.clone());

                // Record RPC client RX and duration stats
                if let Some(ref stats_manager) = self.stats_manager {
                    let labels = labels
                        .clone()
                        .with_label_type(LabelType::Status("success".to_string()));

                    stats_manager
                        .get_counter(MetricName::PeerRpcClientRx, labels.clone())
                        .inc();

                    let duration_ms = start_time.elapsed().as_millis() as u64;
                    stats_manager
                        .get_counter(MetricName::PeerRpcDuration, labels)
                        .add(duration_ms);
                }

                Ok(raw_output)
            }
        }

        F::new(HandlerImpl::<F> {
            domain_name,
            from_peer_id,
            to_peer_id,
            zc_packet_sender: self.mpsc.lock().unwrap().get_sink(),
            inflight_requests: self.inflight_requests.clone(),
            peer_info: self.peer_info.clone(),
            stats_manager: self.stats_manager.clone(),
            inflight_admission: self.inflight_admission.clone(),
            _phan: PhantomData,
        })
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight_requests.len()
    }

    pub(crate) fn peer_info_table(&self) -> PeerInfoTable {
        self.peer_info.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::{CompressionAlgoPb, RpcCompressionInfo, RpcPacket, RpcResponse};
    use crate::tunnel::packet_def::{PacketType, ZCPacket};

    fn response(from_peer: PeerId, to_peer: PeerId) -> RpcPacket {
        RpcPacket {
            from_peer,
            to_peer,
            transaction_id: 17,
            ..Default::default()
        }
    }

    #[test]
    fn authenticated_origin_cannot_complete_a_different_peer_response() {
        let mut packet = ZCPacket::new_with_payload(b"response");
        packet.fill_peer_manager_hdr(7, 1, PacketType::Data as u8);
        assert!(packet.set_authenticated_peer_id(7));

        assert!(!response_peer_binding_valid(
            &packet,
            &response(9, 1),
            9,
            1,
            Some(7)
        ));
    }

    #[test]
    fn response_fragments_cannot_cross_authenticated_sessions() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        assert!(response_session_binding_valid(Some(first), None, true));
        assert!(!response_session_binding_valid(
            Some(second),
            Some(first),
            true
        ));
        assert!(response_session_binding_valid(
            Some(first),
            Some(first),
            true
        ));
    }

    #[test]
    fn loopback_response_requires_local_peer_headers() {
        let mut packet = ZCPacket::new_with_payload(b"response");
        packet.fill_peer_manager_hdr(4, 4, PacketType::Data as u8);
        assert!(response_peer_binding_valid(
            &packet,
            &response(4, 4),
            4,
            4,
            None
        ));

        packet.fill_peer_manager_hdr(4, 5, PacketType::Data as u8);
        assert!(!response_peer_binding_valid(
            &packet,
            &response(4, 4),
            4,
            4,
            None
        ));
    }

    fn response_zc_packet(transaction_id: RpcTransactId) -> ZCPacket {
        let body = RpcResponse::default().encode_to_vec();
        let mut packets = build_rpc_packet(BuildRpcPacketArgs {
            from_peer: 7,
            to_peer: 1,
            rpc_desc: RpcDescriptor::default(),
            transaction_id,
            is_req: false,
            content: &body,
            trace_id: 0,
            compression_info: RpcCompressionInfo {
                algo: CompressionAlgoPb::None.into(),
                accepted_algo: CompressionAlgoPb::None.into(),
            },
        });
        assert_eq!(packets.len(), 1);
        packets.remove(0)
    }

    #[tokio::test]
    async fn receive_loop_rejects_injection_and_survives_closed_request_receiver() {
        let client = Client::new();
        let transaction_id = 71;
        let key = InflightRequestKey {
            from_peer_id: 1,
            to_peer_id: 7,
            transaction_id,
        };
        let (closed_sender, closed_receiver) = mpsc::unbounded_channel();
        drop(closed_receiver);
        client.inflight_requests.insert(
            key.clone(),
            InflightRequest::new(closed_sender, Instant::now(), 7, 1),
        );
        client.run();

        let mut injected = response_zc_packet(transaction_id);
        assert!(injected.set_authenticated_peer_id(9));
        assert!(injected.set_authenticated_session_id(uuid::Uuid::new_v4()));
        client.get_transport_sink().send(injected).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(client.inflight_requests.contains_key(&key));

        let mut closed_response = response_zc_packet(transaction_id);
        assert!(closed_response.set_authenticated_peer_id(7));
        assert!(
            closed_response.set_authenticated_peer_identity_type(
                crate::proto::peer_rpc::PeerIdentityType::Admin
            )
        );
        assert!(closed_response.set_authenticated_peer_secure_auth_level(
            crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed
        ));
        assert!(closed_response.set_authenticated_session_id(uuid::Uuid::new_v4()));
        client
            .get_transport_sink()
            .send(closed_response)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!client.inflight_requests.contains_key(&key));

        let (sender, mut receiver) = mpsc::unbounded_channel();
        client.inflight_requests.insert(
            InflightRequestKey {
                transaction_id: transaction_id + 1,
                ..key.clone()
            },
            InflightRequest::new(sender, Instant::now(), 7, 1),
        );
        let mut valid = response_zc_packet(transaction_id + 1);
        assert!(valid.set_verified_origin(
            7,
            crate::proto::peer_rpc::PeerIdentityType::ForeignRelay,
            crate::proto::peer_rpc::SecureAuthLevel::PeerVerified,
            uuid::Uuid::new_v4(),
        ));
        client.get_transport_sink().send(valid).await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.transaction_id, transaction_id + 1);
    }
}
