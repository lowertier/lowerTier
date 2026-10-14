use super::*;
use futures::task::noop_waker;
use std::sync::atomic::AtomicUsize;

fn binding(byte: u8) -> TransportBinding {
    TransportBinding {
        kind: TransportBindingKind::Http2TlsExporterV1,
        bytes: [byte; 32],
    }
}

fn packet(flow: u64, sequence: u32) -> ZCPacket {
    let mut payload = [0_u8; 128];
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&128_u16.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&[10, 0, 0, 1]);
    payload[16..20].copy_from_slice(&[10, 0, 0, 2]);
    payload[20..22].copy_from_slice(&(10000_u16 + flow as u16).to_be_bytes());
    payload[22..24].copy_from_slice(&5201_u16.to_be_bytes());
    payload[32] = 0x50;
    payload[40..44].copy_from_slice(&sequence.to_le_bytes());
    payload[44] = flow as u8;
    let mut packet = ZCPacket::new_with_payload(&payload);
    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    packet.mut_peer_manager_header().unwrap().forward_counter = 1;
    crate::peers::flow::stamp_packet_flow(&mut packet);
    packet
}

#[test]
fn lane_options_are_explicit_and_require_tls() {
    for value in [
        "wss://localhost",
        "wss://localhost?lanes=1",
        "tcp://localhost",
    ] {
        assert_eq!(requested(&value.parse().unwrap()).unwrap(), 1);
    }
    assert_eq!(
        requested(&"wss://localhost?lanes=2".parse().unwrap()).unwrap(),
        2
    );
    assert_eq!(
        requested(&"wss://localhost?lanes=4".parse().unwrap()).unwrap(),
        4
    );
    for value in [
        "wss://localhost?via=cdn&lanes=2",
        "wss://localhost?via=PROXY&lanes=4",
        "wss://localhost?via=CDN&lanes=2",
        "wss://localhost?lanes=3",
        "wss://localhost?lanes=2&lanes=1",
        "wss://localhost?lanes=0",
    ] {
        assert!(requested(&value.parse().unwrap()).is_err(), "{value}");
    }
}

#[test]
fn join_proof_binds_both_connections_role_and_group() {
    let id = [9; 16];
    let record = join_record(binding(1), binding(2), 1, 2, id).unwrap();
    verify_record(&record, binding(1), binding(2), 1, 2, id).unwrap();
    assert!(verify_record(&record, binding(3), binding(2), 1, 2, id).is_err());
    assert!(verify_record(&record, binding(1), binding(3), 1, 2, id).is_err());
    assert!(verify_record(&record, binding(1), binding(2), 3, 2, id).is_err());
    assert!(verify_record(&record, binding(1), binding(2), 1, 2, [8; 16]).is_err());
    for index in 0..RECORD_BYTES {
        let mut changed = record;
        changed[index] ^= 1;
        assert!(verify_record(&changed, binding(1), binding(2), 1, 2, id).is_err());
    }
    let other_kind = TransportBinding {
        kind: TransportBindingKind::WssTlsExporterV1,
        bytes: [2; 32],
    };
    assert!(join_record(binding(1), other_kind, 1, 2, id).is_err());
}

#[test]
fn encrypted_control_and_relay_packets_stay_on_primary() {
    let mut writer = writer(&[Arc::new(Probe::default()), Arc::new(Probe::default())]);
    assert_eq!(writer.packet_lane(&packet(0, 0)), 0);
    let mut p = packet(1, 0);
    assert_eq!(writer.packet_lane(&p), 1);
    p.mut_peer_manager_header().unwrap().set_encrypted(true);
    assert_eq!(writer.packet_lane(&p), 0);
    p.mut_peer_manager_header().unwrap().set_encrypted(false);
    p.mut_peer_manager_header().unwrap().forward_counter = 2;
    assert_eq!(writer.packet_lane(&p), 0);
    p.mut_peer_manager_header().unwrap().forward_counter = 1;
    p.mut_peer_manager_header().unwrap().packet_type = PacketType::Ping as u8;
    assert_eq!(writer.packet_lane(&p), 0);
}

#[test]
fn even_ephemeral_ports_use_both_lanes_with_stable_shard_fallback() {
    let mut writer = writer(&[Arc::new(Probe::default()), Arc::new(Probe::default())]);
    let mut counts = [0; 2];
    let mut low_bits = [0; 2];
    for port in (45312_u16..45376).step_by(2) {
        let mut ip = [0_u8; 40];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 201, 4, 1]);
        ip[16..20].copy_from_slice(&[10, 201, 4, 2]);
        ip[20..22].copy_from_slice(&port.to_be_bytes());
        ip[22..24].copy_from_slice(&5201_u16.to_be_bytes());
        let mut p = ZCPacket::new_with_payload(&ip);
        p.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        p.mut_peer_manager_header().unwrap().forward_counter = 1;
        let flow = crate::peers::flow::classify_packet_flow(&p);
        low_bits[(flow.hash & 1) as usize] += 1;
        p.set_flow_hash(flow.hash);
        p.mut_peer_manager_header()
            .unwrap()
            .set_flow_shard(flow.shard);
        let lane = writer.packet_lane(&p);
        counts[lane] += 1;
        let _ = p.mut_payload();
        assert_eq!(p.flow_hash(), None);
        assert_eq!(writer.packet_lane(&p), lane);
    }
    assert!(
        low_bits.contains(&0),
        "low-bit selection must reproduce parity concentration"
    );
    assert!(counts.iter().all(|count| *count >= 8));
}

#[test]
fn sparse_flows_are_balanced_once_and_control_does_not_consume_slots() {
    let mut writer = writer(&[Arc::new(Probe::default()), Arc::new(Probe::default())]);
    for flow in 0..64 {
        let mut p = packet(flow, 0);
        p.mut_peer_manager_header().unwrap().set_encrypted(true);
        assert_eq!(writer.packet_lane(&p), 0);
    }
    assert!(writer.flow_lanes.is_empty());
    let shards: Vec<u64> = (0..64_u32)
        .filter(|shard| shard.wrapping_mul(0x9e37_79b9) >> 31 == 0)
        .take(4)
        .map(u64::from)
        .collect();
    for (index, shard) in shards.iter().enumerate() {
        assert_eq!(writer.packet_lane(&packet(*shard, 0)), index % 2);
    }
    for flow in 0..64 {
        let _ = writer.packet_lane(&packet(flow, 0));
    }
    for (index, shard) in shards.iter().enumerate().rev() {
        assert_eq!(writer.packet_lane(&packet(*shard, 1)), index % 2);
    }
}

#[derive(Default)]
struct Probe {
    blocked: AtomicBool,
    flush_blocked: AtomicBool,
    close_blocked: AtomicBool,
    fail: AtomicBool,
    waker: AtomicWaker,
    received: Mutex<Vec<(u32, usize)>>,
    flushes: AtomicUsize,
    closes: AtomicUsize,
}

struct ProbeSink(Arc<Probe>);

impl Sink<PacketBatch> for ProbeSink {
    type Error = TunnelError;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.waker.register(cx.waker());
        if self.0.fail.load(Ordering::Acquire) {
            return Poll::Ready(Err(TunnelError::Shutdown));
        }
        if self.0.blocked.load(Ordering::Acquire) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
        for packet in batch {
            self.0.received.lock().unwrap().push((
                u32::from_le_bytes(packet.payload()[40..44].try_into().unwrap()),
                packet.payload().as_ptr() as usize,
            ));
        }
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.waker.register(cx.waker());
        self.0.flushes.fetch_add(1, Ordering::Relaxed);
        if self.0.flush_blocked.load(Ordering::Acquire) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.waker.register(cx.waker());
        if self.0.close_blocked.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        assert_eq!(self.0.closes.fetch_add(1, Ordering::Relaxed), 0);
        Poll::Ready(Ok(()))
    }
}

fn writer(probes: &[Arc<Probe>; 2]) -> LaneWriter {
    LaneWriter {
        lanes: vec![
            Box::pin(ProbeSink(probes[0].clone())),
            Box::pin(ProbeSink(probes[1].clone())),
        ],
        pending: vec![PacketBatch::new(), PacketBatch::new()],
        closed: vec![false; 2],
        flow_lanes: HashMap::with_capacity(MAX_TRACKED_FLOWS),
        next_lane: 0,
        state: Arc::new(LaneState::default()),
    }
}

#[test]
fn blocked_readiness_flushes_buffered_sibling_without_a_global_barrier() {
    let probes = [Arc::new(Probe::default()), Arc::new(Probe::default())];
    let mut writer = writer(&probes);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut writer).poll_ready(&mut cx).is_ready());
    probes[0].blocked.store(true, Ordering::Release);
    probes[1].flush_blocked.store(true, Ordering::Release);
    let mut batch = PacketBatch::new();
    batch.try_push(packet(0, 0)).unwrap();
    batch.try_push(packet(1, 1)).unwrap();
    Pin::new(&mut writer).start_send(batch).unwrap();
    assert!(Pin::new(&mut writer).poll_ready(&mut cx).is_pending());
    assert_eq!(probes[1].received.lock().unwrap().len(), 1);
    assert!(probes[1].flushes.load(Ordering::Relaxed) > 0);
    probes[0].blocked.store(false, Ordering::Release);
    probes[0].waker.wake();
    assert!(Pin::new(&mut writer).poll_ready(&mut cx).is_ready());
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    probes[1].flush_blocked.store(false, Ordering::Release);
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_ready());
}

#[test]
fn blocked_lane_does_not_prevent_sibling_submission_or_copy_payloads() {
    let probes = [Arc::new(Probe::default()), Arc::new(Probe::default())];
    probes[0].blocked.store(true, Ordering::Release);
    let mut writer = writer(&probes);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut writer).poll_ready(&mut cx).is_ready());
    let mut batch = PacketBatch::new();
    let mut pointers = [Vec::new(), Vec::new()];
    for sequence in 0..64 {
        let p = packet(u64::from(sequence % 2), sequence);
        pointers[sequence as usize % 2].push(p.payload().as_ptr() as usize);
        batch.try_push(p).unwrap();
    }
    Pin::new(&mut writer).start_send(batch).unwrap();
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    assert!(probes[0].received.lock().unwrap().is_empty());
    assert_eq!(probes[1].received.lock().unwrap().len(), 32);
    assert!(Pin::new(&mut writer).poll_ready(&mut cx).is_pending());
    probes[0].blocked.store(false, Ordering::Release);
    probes[0].waker.wake();
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_ready());
    for index in 0..2 {
        let received = probes[index].received.lock().unwrap();
        assert_eq!(
            received.iter().map(|p| p.0).collect::<Vec<_>>(),
            (index as u32..64).step_by(2).collect::<Vec<_>>()
        );
        assert_eq!(
            received.iter().map(|p| p.1).collect::<Vec<_>>(),
            pointers[index]
        );
    }
}

#[test]
fn flush_and_close_poll_both_lanes_and_preserve_completion() {
    let probes = [Arc::new(Probe::default()), Arc::new(Probe::default())];
    let mut writer = writer(&probes);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    probes[0].flush_blocked.store(true, Ordering::Release);
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    assert_eq!(probes[1].flushes.load(Ordering::Relaxed), 1);
    probes[0].flush_blocked.store(false, Ordering::Release);
    probes[1].close_blocked.store(true, Ordering::Release);
    assert!(Pin::new(&mut writer).poll_close(&mut cx).is_pending());
    assert_eq!(probes[0].closes.load(Ordering::Relaxed), 1);
    probes[1].close_blocked.store(false, Ordering::Release);
    assert!(Pin::new(&mut writer).poll_close(&mut cx).is_ready());
    assert!(
        Pin::new(&mut writer)
            .start_send(PacketBatch::singleton(packet(0, 0)))
            .is_err()
    );
}

#[test]
fn receive_failure_terminates_both_halves() {
    let probes = [Arc::new(Probe::default()), Arc::new(Probe::default())];
    let mut writer = writer(&probes);
    let mut reader = LaneReader {
        lanes: vec![
            Box::pin(futures::stream::empty()),
            Box::pin(futures::stream::pending()),
        ],
        next: 0,
        ended: false,
        state: writer.state.clone(),
    };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(
        Pin::new(&mut reader).poll_next(&mut cx),
        Poll::Ready(Some(Err(_)))
    ));
    assert!(matches!(
        Pin::new(&mut reader).poll_next(&mut cx),
        Poll::Ready(None)
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_ready(&mut cx),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn pending_bytes_are_bounded_before_any_lane_accepts_data() {
    let probes = [Arc::new(Probe::default()), Arc::new(Probe::default())];
    let mut writer = writer(&probes);
    let packet = ZCPacket::new_with_payload(&vec![0; MAX_PENDING_BYTES + 1]);
    assert!(matches!(
        Pin::new(&mut writer).start_send(PacketBatch::singleton(packet)),
        Err(TunnelError::ExceedMaxPacketSize(..))
    ));
    assert!(writer.pending.iter().all(|batch| batch.is_empty()));
}

#[tokio::test]
async fn delayed_lane_is_delivered_after_more_than_a_replay_window_of_sibling_data() {
    let gate = Arc::new(Probe::default());
    gate.blocked.store(true, Ordering::Release);
    let delayed = gate.clone();
    let mut first = Some(PacketBatch::singleton(packet(0, 0)));
    let slow = futures::stream::poll_fn(move |cx| {
        delayed.waker.register(cx.waker());
        if delayed.blocked.load(Ordering::Acquire) {
            Poll::Pending
        } else {
            match first.take() {
                Some(batch) => Poll::Ready(Some(Ok(batch))),
                None => Poll::Pending,
            }
        }
    });
    let fast = futures::stream::iter((0..2048).map(|i| Ok(PacketBatch::singleton(packet(1, i)))))
        .chain(futures::stream::pending());
    let mut reader = LaneReader {
        lanes: vec![Box::pin(slow), Box::pin(fast)],
        next: 0,
        ended: false,
        state: Arc::new(LaneState::default()),
    };
    for sequence in 0..2048 {
        let packet = reader
            .next()
            .await
            .unwrap()
            .unwrap()
            .pop_singleton()
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(packet.payload()[40..44].try_into().unwrap()),
            sequence
        );
        assert_eq!(packet.payload()[44], 1);
    }
    gate.blocked.store(false, Ordering::Release);
    gate.waker.wake();
    let packet = reader
        .next()
        .await
        .unwrap()
        .unwrap()
        .pop_singleton()
        .unwrap();
    assert_eq!(packet.payload()[44], 0);
}

struct BoundTunnel {
    inner: Box<dyn Tunnel>,
    binding: TransportBinding,
}
impl Tunnel for BoundTunnel {
    fn split(&self) -> SplitTunnel {
        self.inner.split()
    }
    fn info(&self) -> Option<TunnelInfo> {
        let mut info = self.inner.info()?;
        info.tunnel_type = "tcp".into();
        Some(info)
    }
    fn transport_binding(&self) -> Option<TransportBinding> {
        Some(self.binding)
    }
}
fn bound_pair(binding: TransportBinding) -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let (a, b) = crate::tunnel::ring::create_ring_tunnel_pair();
    (
        Box::new(BoundTunnel { inner: a, binding }),
        Box::new(BoundTunnel { inner: b, binding }),
    )
}

#[tokio::test]
async fn invalid_join_cannot_consume_a_pending_primary_and_valid_join_is_single_use() {
    let mut listener = LaneListener::default();
    let id = [7; 16];
    let (client, server) = bound_pair(binding(1));
    let mut primary = Lane::new(client).unwrap();
    primary
        .write_record(&join_record(binding(1), binding(1), 0, 2, id).unwrap())
        .await
        .unwrap();
    assert!(listener.accept(server, 2).await.unwrap().is_none());
    primary.read_record().await.unwrap();
    let (client, server) = bound_pair(binding(2));
    let mut impostor = Lane::new(client).unwrap();
    impostor
        .write_record(&join_record(binding(3), binding(2), 1, 2, id).unwrap())
        .await
        .unwrap();
    assert!(listener.accept(server, 2).await.is_err());
    assert_eq!(listener.pending.len(), 1);
    let (client, server) = bound_pair(binding(4));
    let mut secondary = Lane::new(client).unwrap();
    let record = join_record(binding(1), binding(4), 1, 2, id).unwrap();
    secondary.write_record(&record).await.unwrap();
    let paired = listener.accept(server, 2).await.unwrap().unwrap();
    let reply = secondary.read_record().await.unwrap();
    verify_record(&reply, binding(1), binding(4), 0x81, 2, id).unwrap();
    assert!(listener.pending.is_empty());
    let client = TcpLanes::wrap(vec![primary, secondary], id).unwrap();
    assert_eq!(client.transport_binding(), paired.transport_binding());
    let (client, server) = bound_pair(binding(4));
    let mut replay = Lane::new(client).unwrap();
    replay.write_record(&record).await.unwrap();
    assert!(listener.accept(server, 2).await.is_err());
}

#[tokio::test]
async fn incomplete_join_expires() {
    let mut listener = LaneListener::default();
    let (client, server) = bound_pair(binding(1));
    let mut primary = Lane::new(client).unwrap();
    let id = [1; 16];
    primary
        .write_record(&join_record(binding(1), binding(1), 0, 2, id).unwrap())
        .await
        .unwrap();
    listener.accept(server, 2).await.unwrap();
    listener.pending.get_mut(&id).unwrap().deadline = Instant::now();
    listener.expire();
    assert!(listener.pending.is_empty());
}

async fn transfer(
    send: &mut Pin<Box<dyn PacketBatchSink>>,
    recv: &mut Pin<Box<dyn PacketBatchStream>>,
    flow_count: u32,
) {
    timeout(Duration::from_secs(10), async {
        let send = async {
            for group in 0..64_u32 {
                let mut batch = PacketBatch::new();
                for index in 0..64_u32 {
                    let sequence = group * 64 + index;
                    batch
                        .try_push(packet(
                            u64::from(sequence % flow_count),
                            sequence / flow_count,
                        ))
                        .unwrap();
                }
                send.send(batch).await.unwrap();
            }
        };
        let recv = async {
            let mut counts = vec![0_u32; flow_count as usize];
            while counts.iter().sum::<u32>() < 4096 {
                for packet in recv.next().await.unwrap().unwrap() {
                    let index = packet.payload()[44] as usize;
                    let sequence = u32::from_le_bytes(packet.payload()[40..44].try_into().unwrap());
                    assert_eq!(sequence, counts[index]);
                    counts[index] += 1;
                }
            }
            assert!(counts.iter().all(|count| *count == 4096 / flow_count));
        };
        tokio::join!(send, recv);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_and_wss_pairs_preserve_frames_and_bind_both_connections() {
    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        tcp::{TcpTunnelConnector, TcpTunnelListener},
        websocket::{WsTunnelConnector, WsTunnelListener},
    };
    for (scheme, lane_count) in [("tcp", 2), ("tcp", 4), ("wss", 2), ("wss", 4)] {
        let addr = format!("{scheme}://127.0.0.1:0?lanes={lane_count}")
            .parse()
            .unwrap();
        let mut listener: Box<dyn TunnelListener> = if scheme == "tcp" {
            Box::new(TcpTunnelListener::new(addr))
        } else {
            Box::new(WsTunnelListener::new(addr))
        };
        listener.listen().await.unwrap();
        let url = listener.local_url();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector: Box<dyn TunnelConnector> = if scheme == "tcp" {
            Box::new(TcpTunnelConnector::new(url))
        } else {
            Box::new(WsTunnelConnector::new(url))
        };
        let client = connector.connect().await.unwrap();
        let server = server.await.unwrap();
        assert_eq!(client.transport_binding(), server.transport_binding());
        assert_eq!(
            client.transport_binding().unwrap().kind,
            TransportBindingKind::TlsExporterLanesV1
        );
        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();
        transfer(&mut cw, &mut sr, lane_count).await;
        transfer(&mut sw, &mut cr, lane_count).await;
    }
}

#[tokio::test]
async fn authenticated_pair_delivers_delayed_lane_after_2048_sibling_packets() {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        peers::{create_packet_recv_chan, peer_conn::PeerConn, peer_session::PeerSessionStore},
    };
    let (c0, s0) = bound_pair(binding(1));
    let (c1, s1) = bound_pair(binding(2));
    let gate = Arc::new(Probe::default());
    let delayed = gate.clone();
    let Lane {
        tunnel,
        recv: mut recv0,
        send,
        binding: tls_binding,
    } = Lane::new(s0).unwrap();
    let recv = futures::stream::poll_fn(move |cx| {
        delayed.waker.register(cx.waker());
        if delayed.blocked.load(Ordering::Acquire) {
            Poll::Pending
        } else {
            recv0.as_mut().poll_next(cx)
        }
    });
    let s0 = Lane {
        tunnel,
        recv: Box::pin(recv),
        send,
        binding: tls_binding,
    };
    let id = [5; 16];
    let client = TcpLanes::wrap(vec![Lane::new(c0).unwrap(), Lane::new(c1).unwrap()], id).unwrap();
    let server = TcpLanes::wrap(vec![s0, Lane::new(s1).unwrap()], id).unwrap();
    let mut client = PeerConn::new(
        1,
        get_mock_global_ctx(),
        client,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        get_mock_global_ctx(),
        server,
        Arc::new(PeerSessionStore::new()),
    );
    timeout(Duration::from_secs(10), async {
        let (a, b) = tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server()
        );
        a.unwrap();
        b.unwrap();
    })
    .await
    .unwrap();
    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    gate.blocked.store(true, Ordering::Release);
    client.start_recv_loop(client_tx).await;
    server.start_recv_loop(server_tx).await;
    timeout(Duration::from_secs(10), async {
        client.send_msg(packet(0, u32::MAX)).await.unwrap();
        let send = async {
            for group in 0..32_u32 {
                let mut batch = PacketBatch::new();
                for index in 0..64_u32 {
                    batch.try_push(packet(1, group * 64 + index)).unwrap();
                }
                client.send_msg_batch(batch).await.unwrap();
            }
        };
        let receive = async {
            for sequence in 0..2048_u32 {
                let p = server_rx.recv().await.unwrap();
                assert_eq!(p.payload()[44], 1);
                assert!(!p.peer_manager_header().unwrap().is_encrypted());
                assert_eq!(
                    u32::from_le_bytes(p.payload()[40..44].try_into().unwrap()),
                    sequence
                );
            }
        };
        tokio::join!(send, receive);
        gate.blocked.store(false, Ordering::Release);
        gate.waker.wake();
        let late = server_rx.recv().await.unwrap();
        assert_eq!(late.payload()[44], 0);
        assert_eq!(
            u32::from_le_bytes(late.payload()[40..44].try_into().unwrap()),
            u32::MAX
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_and_wss_pairs_authenticate_and_deliver_through_one_peer_connection() {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        peers::{create_packet_recv_chan, peer_conn::PeerConn, peer_session::PeerSessionStore},
        tunnel::{
            TunnelConnector, TunnelListener,
            tcp::{TcpTunnelConnector, TcpTunnelListener},
            websocket::{WsTunnelConnector, WsTunnelListener},
        },
    };
    for (scheme, lane_count) in [("tcp", 2), ("tcp", 4), ("wss", 2), ("wss", 4)] {
        let addr = format!("{scheme}://127.0.0.1:0?lanes={lane_count}")
            .parse()
            .unwrap();
        let mut listener: Box<dyn TunnelListener> = if scheme == "tcp" {
            Box::new(TcpTunnelListener::new(addr))
        } else {
            Box::new(WsTunnelListener::new(addr))
        };
        listener.listen().await.unwrap();
        let url = listener.local_url();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector: Box<dyn TunnelConnector> = if scheme == "tcp" {
            Box::new(TcpTunnelConnector::new(url))
        } else {
            Box::new(WsTunnelConnector::new(url))
        };
        let client = connector.connect().await.unwrap();
        let server = accept.await.unwrap();
        let mut client = PeerConn::new(
            1,
            get_mock_global_ctx(),
            client,
            Arc::new(PeerSessionStore::new()),
        );
        let mut server = PeerConn::new(
            2,
            get_mock_global_ctx(),
            server,
            Arc::new(PeerSessionStore::new()),
        );
        timeout(Duration::from_secs(10), async {
            let (a, b) = tokio::join!(
                client.do_handshake_as_client(),
                server.do_handshake_as_server()
            );
            a.unwrap();
            b.unwrap();
        })
        .await
        .unwrap();
        let (client_tx, mut client_rx) = create_packet_recv_chan();
        let (server_tx, mut server_rx) = create_packet_recv_chan();
        client.start_recv_loop(client_tx).await;
        server.start_recv_loop(server_tx).await;
        timeout(Duration::from_secs(10), async {
            let send = async {
                for group in 0..64_u32 {
                    let mut batch = PacketBatch::new();
                    for index in 0..64_u32 {
                        let sequence = group * 64 + index;
                        batch
                            .try_push(packet(
                                u64::from(sequence % lane_count),
                                sequence / lane_count,
                            ))
                            .unwrap();
                    }
                    client.send_msg_batch(batch).await.unwrap();
                }
            };
            let receive = async {
                let mut counts = vec![0_u32; lane_count as usize];
                while counts.iter().sum::<u32>() < 4096 {
                    let p = server_rx.recv().await.unwrap();
                    let index = p.payload()[44] as usize;
                    assert!(!p.peer_manager_header().unwrap().is_encrypted());
                    assert_eq!(
                        u32::from_le_bytes(p.payload()[40..44].try_into().unwrap()),
                        counts[index]
                    );
                    counts[index] += 1;
                }
                assert!(counts.iter().all(|count| *count == 4096 / lane_count));
            };
            tokio::join!(send, receive);
            let mut response = packet(1, 42);
            response.fill_peer_manager_hdr(2, 1, PacketType::Data as u8);
            response.mut_peer_manager_header().unwrap().forward_counter = 1;
            response.set_flow_hash(1);
            server.send_msg(response).await.unwrap();
            let response = client_rx.recv().await.unwrap();
            assert_eq!(
                u32::from_le_bytes(response.payload()[40..44].try_into().unwrap()),
                42
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn four_lane_group_requires_all_indices_and_rejects_count_changes() {
    let mut listener = LaneListener::default();
    let id = [6; 16];
    let mut clients = Vec::new();
    let mut server_group = None;
    for index in 0..4_u8 {
        let (client, server) = bound_pair(binding(index + 1));
        let mut client = Lane::new(client).unwrap();
        client
            .write_record(&join_record(binding(1), binding(index + 1), index, 4, id).unwrap())
            .await
            .unwrap();
        let accepted = listener.accept(server, 4).await.unwrap();
        let reply = client.read_record().await.unwrap();
        verify_record(&reply, binding(1), binding(index + 1), index | 0x80, 4, id).unwrap();
        clients.push(client);
        if index < 3 {
            assert!(accepted.is_none());
            assert_eq!(listener.pending[&id].lanes.len(), usize::from(index) + 1);
            let (wrong_client, wrong_server) = bound_pair(binding(9));
            let mut wrong = Lane::new(wrong_client).unwrap();
            wrong
                .write_record(&join_record(binding(1), binding(9), 1, 2, id).unwrap())
                .await
                .unwrap();
            assert!(listener.accept(wrong_server, 4).await.is_err());
            assert_eq!(listener.pending[&id].lanes.len(), usize::from(index) + 1);
        } else {
            server_group = accepted;
        }
    }
    assert!(listener.pending.is_empty());
    let client = TcpLanes::wrap(clients, id).unwrap();
    assert_eq!(
        client.transport_binding(),
        server_group.unwrap().transport_binding()
    );
}

#[test]
fn four_lanes_balance_new_shards_without_moving_existing_flows() {
    let probes: [Arc<Probe>; 4] = std::array::from_fn(|_| Arc::new(Probe::default()));
    let mut lanes: Vec<Pin<Box<dyn PacketBatchSink>>> = Vec::new();
    let mut pending = Vec::new();
    for probe in &probes {
        lanes.push(Box::pin(ProbeSink(probe.clone())));
        pending.push(PacketBatch::new());
    }
    let mut writer = LaneWriter {
        lanes,
        pending,
        closed: vec![false; 4],
        flow_lanes: HashMap::with_capacity(MAX_TRACKED_FLOWS),
        next_lane: 0,
        state: Arc::new(LaneState::default()),
    };
    for (index, shard) in [6, 8, 14, 62].into_iter().enumerate() {
        assert_eq!(writer.packet_lane(&packet(shard, 0)), index);
    }
    for flow in 0..64 {
        let _ = writer.packet_lane(&packet(flow, 0));
    }
    for (index, shard) in [6, 8, 14, 62].into_iter().enumerate().rev() {
        assert_eq!(writer.packet_lane(&packet(shard, 1)), index);
    }
}

#[tokio::test]
async fn wss_listener_rejects_oversized_join_without_poisoning_next_group() {
    use crate::tunnel::{
        TunnelConnector, TunnelListener,
        websocket::{WsTunnelConnector, WsTunnelListener},
    };
    timeout(Duration::from_secs(10), async {
        let mut listener = WsTunnelListener::new("wss://127.0.0.1:0?lanes=4".parse().unwrap());
        listener.listen().await.unwrap();
        let paired_url = listener.local_url();
        let mut single_url = paired_url.clone();
        single_url.set_query(None);
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let bad = WsTunnelConnector::new(single_url).connect().await.unwrap();
        let (mut recv, mut send) = bad.split();
        let oversized = ZCPacket::new_with_payload(&vec![0; MAX_PENDING_BYTES + 1]);
        let _ = send.send(PacketBatch::singleton(oversized)).await;
        assert!(!matches!(recv.next().await, Some(Ok(_))));
        drop(send);
        drop(recv);
        drop(bad);
        let client = WsTunnelConnector::new(paired_url).connect().await.unwrap();
        let server = accepted.await.unwrap();
        assert_eq!(client.transport_binding(), server.transport_binding());
    })
    .await
    .unwrap();
}

#[test]
fn colliding_wire_shards_remain_distinct_and_flow_mapping_stays_bounded() {
    let probes = std::array::from_fn::<_, 4, _>(|_| Arc::new(Probe::default()));
    let mut writer = LaneWriter {
        lanes: probes
            .iter()
            .map(|p| Box::pin(ProbeSink(p.clone())) as Pin<Box<dyn PacketBatchSink>>)
            .collect(),
        pending: (0..4).map(|_| PacketBatch::new()).collect(),
        closed: vec![false; 4],
        flow_lanes: HashMap::with_capacity(MAX_TRACKED_FLOWS),
        next_lane: 0,
        state: Arc::new(LaneState::default()),
    };
    let shard = crate::peers::flow::classify_packet_flow(&packet(0, 0)).shard;
    let flows: Vec<u64> = (0..4096)
        .filter(|flow| crate::peers::flow::classify_packet_flow(&packet(*flow, 0)).shard == shard)
        .take(4)
        .collect();
    assert_eq!(flows.len(), 4);
    for (lane, flow) in flows.iter().enumerate() {
        let mut p = packet(*flow, 0);
        assert_eq!(writer.packet_lane(&p), lane);
        let _ = p.mut_payload();
        assert!(p.flow_hash().is_none());
        assert_eq!(writer.packet_lane(&p), lane);
    }
    for flow in 0..4096 {
        let _ = writer.packet_lane(&packet(flow, 1));
    }
    assert_eq!(writer.flow_lanes.len(), MAX_TRACKED_FLOWS);
    for (lane, flow) in flows.iter().enumerate() {
        assert_eq!(writer.packet_lane(&packet(*flow, 2)), lane);
    }
    let late = writer.packet_lane(&packet(5000, 0));
    for flow in 6000..7000 {
        let _ = writer.packet_lane(&packet(flow, 1));
    }
    assert_eq!(writer.packet_lane(&packet(5000, 2)), late);
    assert_eq!(writer.flow_lanes.len(), MAX_TRACKED_FLOWS);
}

