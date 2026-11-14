use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{sleep, timeout},
};

use crate::{
    common::{
        PeerId,
        global_ctx::{NetworkIdentity, tests::get_mock_global_ctx_with_network},
        stats_manager::{LabelSet, LabelType, MetricName},
    },
    gateway::overlay_stream::OverlayStreamEndpoint,
    peers::{
        PacketRecvChanReceiver, create_packet_recv_chan,
        peer_conn::tests::set_secure_mode_cfg,
        peer_manager::{PeerManager, RouteAlgoType},
        route_trait::Route,
        tests::wait_route_appear,
    },
    proto::common::{PathGroup, PathPolicy, PathRule, PathStage},
    tunnel::{
        IpVersion, TunnelListener,
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
        quic::QuicTunnelListener,
        tcp::TcpTunnelListener,
        websocket::WsTunnelListener,
    },
};

struct TestNode {
    mgr: Arc<PeerManager>,
    nic_rx: PacketRecvChanReceiver,
    ipv4: Ipv4Addr,
    enable_bridge: bool,
}

impl TestNode {
    fn apply_bridge_feature_flags(
        ctx: &crate::common::global_ctx::ArcGlobalCtx,
        enable_bridge: bool,
    ) {
        if enable_bridge {
            let mut features = ctx.get_feature_flags();
            features.ethernet_input = true;
            features.hybrid_l3 = true;
            features.bridge_input = true;
            features.multicast_membership = true;
            ctx.set_base_advertised_feature_flags(features);
        }
    }

    async fn new(net_name: &str, ip: &str, no_tun: bool, enable_bridge: bool) -> Self {
        let ipv4: Ipv4Addr = ip.parse().unwrap();
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            net_name.to_string(),
            "multipath-secret".to_string(),
        )));
        set_secure_mode_cfg(&global_ctx, true);
        global_ctx.set_ipv4(Some(cidr::Ipv4Inet::new(ipv4, 24).unwrap()));

        let mut flags = global_ctx.get_flags();
        flags.no_tun = no_tun;
        flags.enable_bridge = enable_bridge;
        if enable_bridge {
            flags.l2_flood_bytes_per_second = 64 * 1024 * 1024;
        }
        global_ctx.set_flags(flags);
        Self::apply_bridge_feature_flags(&global_ctx, enable_bridge);

        let (packet_send, nic_rx) = create_packet_recv_chan();
        let mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx,
            packet_send,
        ));
        mgr.run().await.unwrap();
        Self {
            mgr,
            nic_rx,
            ipv4,
            enable_bridge,
        }
    }

    fn pub_key(&self) -> String {
        self.mgr
            .get_global_ctx()
            .config
            .get_secure_mode()
            .and_then(|mode| mode.local_public_key)
            .expect("node should have secure_mode local_public_key")
    }

    fn peer_id(&self) -> PeerId {
        self.mgr.my_peer_id()
    }

    fn set_path_policy(&self, policy: PathPolicy) {
        let ctx = self.mgr.get_global_ctx();
        let mut flags = ctx.get_flags();
        flags.path_policy = Some(policy);
        ctx.set_flags(flags);
        Self::apply_bridge_feature_flags(&ctx, self.enable_bridge);
    }

    fn set_no_tun(&self, no_tun: bool) {
        let ctx = self.mgr.get_global_ctx();
        let mut flags = ctx.get_flags();
        flags.no_tun = no_tun;
        ctx.set_flags(flags);
        Self::apply_bridge_feature_flags(&ctx, self.enable_bridge);
    }

    fn forwarded_packets(&self) -> u64 {
        let ctx = self.mgr.get_global_ctx();
        let labels =
            LabelSet::new().with_label_type(LabelType::NetworkName(ctx.get_network_name()));
        ctx.stats_manager()
            .get_counter(MetricName::TrafficPacketsForwarded, labels)
            .get()
    }

    fn self_rx_packets(&self) -> u64 {
        let ctx = self.mgr.get_global_ctx();
        let labels =
            LabelSet::new().with_label_type(LabelType::NetworkName(ctx.get_network_name()));
        ctx.stats_manager()
            .get_counter(MetricName::TrafficPacketsRx, labels)
            .get()
    }
}

async fn connect_real_transport(
    client: &TestNode,
    server: &TestNode,
    protocol: &str,
) -> Box<dyn TunnelListener> {
    let url = format!("{protocol}://127.0.0.1:0").parse().unwrap();
    let mut listener: Box<dyn TunnelListener> = match protocol {
        "quic" => Box::new(QuicTunnelListener::new(url, server.mgr.get_global_ctx())),
        "h2" => {
            let mut l = TcpTunnelListener::new(url);
            l.set_global_ctx(&server.mgr.get_global_ctx());
            Box::new(l)
        }
        "wss" => {
            let mut l = WsTunnelListener::new(url);
            l.set_global_ctx(&server.mgr.get_global_ctx());
            Box::new(l)
        }
        other => panic!("unsupported transport {other}"),
    };
    listener.listen().await.unwrap();
    let mut connector = crate::connector::create_connector_by_url(
        listener.local_url().as_str(),
        &client.mgr.get_global_ctx(),
        IpVersion::Both,
    )
    .await
    .unwrap();
    let (left, right) = tokio::join!(connector.connect(), listener.accept());
    let (c_res, s_res) = tokio::join!(
        client.mgr.add_client_tunnel(left.unwrap(), true),
        server.mgr.add_tunnel_as_server(right.unwrap(), true),
    );
    c_res.unwrap();
    s_res.unwrap();
    listener
}

fn routed_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, seq: u32) -> ZCPacket {
    let mut bytes = vec![0_u8; 512];
    let total_len = bytes.len() as u16;
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&src.octets());
    bytes[16..20].copy_from_slice(&dst.octets());
    bytes[20..22].copy_from_slice(&1000_u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&dst_port.to_be_bytes());
    bytes[24..26].copy_from_slice(&(total_len - 20).to_be_bytes());
    bytes[28..32].copy_from_slice(&seq.to_le_bytes());
    ZCPacket::new_with_payload(&bytes)
}

fn ethernet_frame_with_tag(dst: [u8; 6], src: [u8; 6], tag: &[u8]) -> ZCPacket {
    let mut frame = vec![0_u8; 64.max(14 + tag.len())];
    frame[..6].copy_from_slice(&dst);
    frame[6..12].copy_from_slice(&src);
    frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    frame[14..14 + tag.len()].copy_from_slice(tag);
    ZCPacket::new_with_payload(&frame)
}

async fn send_ipv4_burst(
    sender: &TestNode,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dst_port: u16,
    seqs: std::ops::Range<u32>,
) {
    let packets: Vec<ZCPacket> = seqs
        .map(|seq| routed_ipv4_packet(src, dst, dst_port, seq))
        .collect();
    for chunk in packets.chunks(8) {
        let mut batch = PacketBatch::new();
        for pkt in chunk {
            let _ = batch.try_push(pkt.clone());
        }
        sender.mgr.send_msg_by_hybrid_ip_batch(batch).await.unwrap();
    }
}

async fn recv_ipv4_seqs(
    rx: &mut PacketRecvChanReceiver,
    expected_src: Ipv4Addr,
    expected_dst: Ipv4Addr,
    dst_port: u16,
    count: usize,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let pkt = rx
            .recv()
            .await
            .expect("nic_rx closed before receiving expected packets");
        if pkt
            .peer_manager_header()
            .is_some_and(|h| h.packet_type == PacketType::Data as u8)
        {
            let p = pkt.payload();
            if p.len() >= 32
                && (p[0] >> 4) == 4
                && p[12..16] == expected_src.octets()
                && p[16..20] == expected_dst.octets()
                && u16::from_be_bytes([p[22], p[23]]) == dst_port
            {
                let seq = u32::from_le_bytes(p[28..32].try_into().unwrap());
                out.push(seq);
            }
        }
    }
    out
}

async fn recv_ethernet_tagged(
    rx: &mut PacketRecvChanReceiver,
    expected_src: [u8; 6],
    expected_tag: &[u8],
) {
    loop {
        let pkt = rx
            .recv()
            .await
            .expect("nic_rx closed before receiving expected Ethernet frame");
        if pkt
            .peer_manager_header()
            .is_some_and(|h| h.packet_type == PacketType::Ethernet as u8)
        {
            let p = pkt.payload();
            if p.len() >= 14 + expected_tag.len()
                && p[6..12] == expected_src
                && &p[14..14 + expected_tag.len()] == expected_tag
            {
                return;
            }
        }
    }
}

async fn warmup_e2e_session(sender: &TestNode, receiver: &mut TestNode) {
    let pkt = routed_ipv4_packet(sender.ipv4, receiver.ipv4, 1999, u32::MAX);
    sender
        .mgr
        .send_msg_by_hybrid_ip_batch(PacketBatch::singleton(pkt))
        .await
        .unwrap();
    let got = recv_ipv4_seqs(&mut receiver.nic_rx, sender.ipv4, receiver.ipv4, 1999, 1).await;
    assert_eq!(got, vec![u32::MAX]);
}

#[tokio::test]
async fn parallel_single_layer_stripes_across_quic_h2_and_wss() {
    timeout(Duration::from_secs(30), async {
        let net = "mp-test-1";
        let a = TestNode::new(net, "10.88.0.1", true, false).await;
        let r1 = TestNode::new(net, "10.88.0.2", true, false).await;
        let r2 = TestNode::new(net, "10.88.0.3", true, false).await;
        let r3 = TestNode::new(net, "10.88.0.4", true, false).await;
        let mut b = TestNode::new(net, "10.88.0.5", true, false).await;

        let _listeners = [
            connect_real_transport(&a, &r1, "quic").await,
            connect_real_transport(&r1, &b, "quic").await,
            connect_real_transport(&a, &r2, "h2").await,
            connect_real_transport(&r2, &b, "h2").await,
            connect_real_transport(&a, &r3, "wss").await,
            connect_real_transport(&r3, &b, "wss").await,
        ];

        for target in [&r1.mgr, &r2.mgr, &r3.mgr, &b.mgr] {
            wait_route_appear(a.mgr.clone(), target.clone())
                .await
                .unwrap();
            wait_route_appear(target.clone(), a.mgr.clone())
                .await
                .unwrap();
        }
        for relay in [&r1.mgr, &r2.mgr, &r3.mgr] {
            wait_route_appear(relay.clone(), b.mgr.clone())
                .await
                .unwrap();
        }

        a.set_path_policy(PathPolicy {
            group: vec![PathGroup {
                name: "pool".to_string(),
                nodes: vec![r1.pub_key(), r2.pub_key(), r3.pub_key()],
                mode: "parallel".to_string(),
                weights: Vec::new(),
            }],
            path: vec![PathRule {
                to: b.pub_key(),
                mode: "parallel".to_string(),
                layers: vec![PathStage {
                    nodes: vec!["pool".to_string()],
                    mode: String::new(),
                    weights: Vec::new(),
                }],
                gateway: None,
                strict: true,
            }],
        });

        warmup_e2e_session(&a, &mut b).await;
        let r1_before = (r1.forwarded_packets(), r1.self_rx_packets());
        let r2_before = (r2.forwarded_packets(), r2.self_rx_packets());
        let r3_before = (r3.forwarded_packets(), r3.self_rx_packets());

        send_ipv4_burst(&a, a.ipv4, b.ipv4, 2000, 0..240).await;
        let seqs = recv_ipv4_seqs(&mut b.nic_rx, a.ipv4, b.ipv4, 2000, 240).await;
        assert_eq!(seqs, (0..240_u32).collect::<Vec<_>>());

        assert!(r1.forwarded_packets() > r1_before.0, "quic relay r1 unused");
        assert!(r2.forwarded_packets() > r2_before.0, "h2 relay r2 unused");
        assert!(r3.forwarded_packets() > r3_before.0, "wss relay r3 unused");
        assert_eq!(r1.self_rx_packets(), r1_before.1, "r1 terminated payload");
        assert_eq!(r2.self_rx_packets(), r2_before.1, "r2 terminated payload");
        assert_eq!(r3.self_rx_packets(), r3_before.1, "r3 terminated payload");

        assert!(a.mgr.get_relay_peer_map().has_session(b.peer_id()));
        assert!(b.mgr.get_relay_peer_map().has_session(a.peer_id()));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multilayer_mixed_transport_chain_opaque_forwarding_and_probe_rtt() {
    timeout(Duration::from_secs(30), async {
        let net = "mp-test-2";
        let a = TestNode::new(net, "10.88.1.1", true, false).await;
        let l1a = TestNode::new(net, "10.88.1.2", true, false).await;
        let l1b = TestNode::new(net, "10.88.1.3", true, false).await;
        let l2a = TestNode::new(net, "10.88.1.4", true, false).await;
        let l2b = TestNode::new(net, "10.88.1.5", true, false).await;
        let mut b = TestNode::new(net, "10.88.1.6", true, false).await;

        let _listeners = [
            connect_real_transport(&a, &l1a, "quic").await,
            connect_real_transport(&a, &l1b, "wss").await,
            connect_real_transport(&l1a, &l2a, "h2").await,
            connect_real_transport(&l1a, &l2b, "wss").await,
            connect_real_transport(&l1b, &l2a, "quic").await,
            connect_real_transport(&l1b, &l2b, "h2").await,
            connect_real_transport(&l2a, &b, "wss").await,
            connect_real_transport(&l2b, &b, "quic").await,
        ];

        for target in [&l1a, &l1b, &l2a, &l2b, &b] {
            wait_route_appear(a.mgr.clone(), target.mgr.clone())
                .await
                .unwrap();
            wait_route_appear(target.mgr.clone(), a.mgr.clone())
                .await
                .unwrap();
        }
        for l1 in [&l1a, &l1b] {
            for l2 in [&l2a, &l2b] {
                wait_route_appear(l1.mgr.clone(), l2.mgr.clone())
                    .await
                    .unwrap();
            }
        }
        for l2 in [&l2a, &l2b] {
            wait_route_appear(l2.mgr.clone(), b.mgr.clone())
                .await
                .unwrap();
        }

        a.set_path_policy(PathPolicy {
            group: Vec::new(),
            path: vec![PathRule {
                to: b.pub_key(),
                mode: "parallel".to_string(),
                layers: vec![
                    PathStage {
                        nodes: vec![l1a.pub_key(), l1b.pub_key()],
                        mode: "parallel".to_string(),
                        weights: Vec::new(),
                    },
                    PathStage {
                        nodes: vec![l2a.pub_key(), l2b.pub_key()],
                        mode: "parallel".to_string(),
                        weights: Vec::new(),
                    },
                ],
                gateway: None,
                strict: true,
            }],
        });

        warmup_e2e_session(&a, &mut b).await;
        let l1a_before = (l1a.forwarded_packets(), l1a.self_rx_packets());
        let l1b_before = (l1b.forwarded_packets(), l1b.self_rx_packets());
        let l2a_before = (l2a.forwarded_packets(), l2a.self_rx_packets());
        let l2b_before = (l2b.forwarded_packets(), l2b.self_rx_packets());

        send_ipv4_burst(&a, a.ipv4, b.ipv4, 2000, 0..160).await;
        let seqs = recv_ipv4_seqs(&mut b.nic_rx, a.ipv4, b.ipv4, 2000, 160).await;
        assert_eq!(seqs, (0..160_u32).collect::<Vec<_>>());

        assert!(l1a.forwarded_packets() > l1a_before.0, "l1a unused");
        assert!(l1b.forwarded_packets() > l1b_before.0, "l1b unused");
        assert!(l2a.forwarded_packets() > l2a_before.0, "l2a unused");
        assert!(l2b.forwarded_packets() > l2b_before.0, "l2b unused");
        assert_eq!(
            l1a.self_rx_packets(),
            l1a_before.1,
            "l1a terminated payload"
        );
        assert_eq!(
            l1b.self_rx_packets(),
            l1b_before.1,
            "l1b terminated payload"
        );
        assert_eq!(
            l2a.self_rx_packets(),
            l2a_before.1,
            "l2a terminated payload"
        );
        assert_eq!(
            l2b.self_rx_packets(),
            l2b_before.1,
            "l2b terminated payload"
        );

        assert!(a.mgr.get_relay_peer_map().has_session(b.peer_id()));
        assert!(b.mgr.get_relay_peer_map().has_session(a.peer_id()));

        let mut probe_ok = false;
        for _ in 0..40 {
            let status = a.mgr.path_status().await;
            assert_eq!(status.len(), 1);
            assert_eq!(status[0].state, "ready");
            assert_eq!(status[0].chains.len(), 4);
            if status[0].chains.iter().any(|chain| chain.rtt_us > 0) {
                probe_ok = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(
            probe_ok,
            "expected PathProbe RTT sample on multi-layer chains"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn asymmetric_paths_cover_data_ethernet_overlay_stream_and_socks5_guard() {
    timeout(Duration::from_secs(30), async {
        let net = "mp-test-3";
        let mut a = TestNode::new(net, "10.89.0.1", false, true).await;
        let r_fwd = TestNode::new(net, "10.89.0.2", true, false).await;
        let r_rev = TestNode::new(net, "10.89.0.3", true, false).await;
        let mut b = TestNode::new(net, "10.89.0.4", false, true).await;

        let _listeners = [
            // Direct link must NOT bypass configured asymmetric [[path]] rules.
            connect_real_transport(&a, &b, "quic").await,
            connect_real_transport(&a, &r_fwd, "h2").await,
            connect_real_transport(&r_fwd, &b, "h2").await,
            connect_real_transport(&b, &r_rev, "wss").await,
            connect_real_transport(&r_rev, &a, "wss").await,
        ];

        for target in [&r_fwd, &r_rev, &b] {
            wait_route_appear(a.mgr.clone(), target.mgr.clone())
                .await
                .unwrap();
            wait_route_appear(target.mgr.clone(), a.mgr.clone())
                .await
                .unwrap();
        }
        wait_route_appear(r_fwd.mgr.clone(), b.mgr.clone())
            .await
            .unwrap();
        wait_route_appear(r_rev.mgr.clone(), b.mgr.clone())
            .await
            .unwrap();
        wait_route_appear(b.mgr.clone(), r_rev.mgr.clone())
            .await
            .unwrap();

        a.set_path_policy(PathPolicy {
            group: Vec::new(),
            path: vec![PathRule {
                to: b.pub_key(),
                mode: "parallel".to_string(),
                layers: vec![PathStage {
                    nodes: vec![r_fwd.pub_key()],
                    mode: String::new(),
                    weights: Vec::new(),
                }],
                gateway: None,
                strict: true,
            }],
        });
        b.set_path_policy(PathPolicy {
            group: Vec::new(),
            path: vec![PathRule {
                to: a.pub_key(),
                mode: "parallel".to_string(),
                layers: vec![PathStage {
                    nodes: vec![r_rev.pub_key()],
                    mode: String::new(),
                    weights: Vec::new(),
                }],
                gateway: None,
                strict: true,
            }],
        });

        assert!(a.mgr.path_applies_to(b.peer_id()));
        assert!(b.mgr.path_applies_to(a.peer_id()));
        assert!(a.mgr.get_peer_map().only_direct_conn(b.peer_id()).is_some());
        assert!(a.mgr.only_direct_proxy_conn(b.peer_id()).is_none());

        // 1) Asymmetric L3 Data packets
        let fwd0 = r_fwd.forwarded_packets();
        let rev0 = r_rev.forwarded_packets();
        send_ipv4_burst(&a, a.ipv4, b.ipv4, 2000, 0..16).await;
        assert_eq!(
            timeout(
                Duration::from_secs(8),
                recv_ipv4_seqs(&mut b.nic_rx, a.ipv4, b.ipv4, 2000, 16),
            )
            .await
            .expect("l3 data a->b"),
            (0..16_u32).collect::<Vec<_>>()
        );
        assert!(r_fwd.forwarded_packets() >= fwd0 + 16);
        assert_eq!(r_rev.forwarded_packets(), rev0);

        let fwd1 = r_fwd.forwarded_packets();
        let rev1 = r_rev.forwarded_packets();
        send_ipv4_burst(&b, b.ipv4, a.ipv4, 2001, 0..16).await;
        assert_eq!(
            timeout(
                Duration::from_secs(8),
                recv_ipv4_seqs(&mut a.nic_rx, b.ipv4, a.ipv4, 2001, 16),
            )
            .await
            .expect("l3 data b->a"),
            (0..16_u32).collect::<Vec<_>>()
        );
        assert_eq!(r_fwd.forwarded_packets(), fwd1);
        assert!(r_rev.forwarded_packets() >= rev1 + 16);

        // Wait for OSPF FullEthernetBridge grants and dataplane descriptors before testing relayed L2 Ethernet.
        let mut bridge_ready = false;
        for _ in 0..100 {
            let evidence_ready = a
                .mgr
                .get_route()
                .get_bridge_peer_evidence(b.peer_id())
                .await
                .is_some()
                && b.mgr
                    .get_route()
                    .get_bridge_peer_evidence(a.peer_id())
                    .await
                    .is_some();
            let a_desc = a.mgr.get_peer_map().dataplane_descriptor();
            let b_desc = b.mgr.get_peer_map().dataplane_descriptor();
            let descriptors_live = PeerManager::l2_destination_is_live(
                &a_desc,
                a.peer_id(),
                a.peer_id(),
                &a.mgr.get_global_ctx(),
            ) && PeerManager::l2_destination_is_live(
                &a_desc,
                b.peer_id(),
                a.peer_id(),
                &a.mgr.get_global_ctx(),
            ) && PeerManager::l2_destination_is_live(
                &b_desc,
                b.peer_id(),
                b.peer_id(),
                &b.mgr.get_global_ctx(),
            ) && PeerManager::l2_destination_is_live(
                &b_desc,
                a.peer_id(),
                b.peer_id(),
                &b.mgr.get_global_ctx(),
            );
            if evidence_ready && descriptors_live {
                bridge_ready = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(bridge_ready, "FullEthernetBridge evidence did not converge");

        // 2) Asymmetric L2 Ethernet frames (flood + unicast learned FDB)
        let mac_a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mac_b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let fwd2 = r_fwd.forwarded_packets();
        let rev2 = r_rev.forwarded_packets();
        a.mgr
            .send_msg_by_ethernet(ethernet_frame_with_tag([0xff; 6], mac_a, b"l2-a2b-1"))
            .await
            .unwrap();
        timeout(
            Duration::from_secs(8),
            recv_ethernet_tagged(&mut b.nic_rx, mac_a, b"l2-a2b-1"),
        )
        .await
        .expect("l2 flood a->b");
        assert!(r_fwd.forwarded_packets() > fwd2);
        assert_eq!(r_rev.forwarded_packets(), rev2);

        let fwd3 = r_fwd.forwarded_packets();
        let rev3 = r_rev.forwarded_packets();
        b.mgr
            .send_msg_by_ethernet(ethernet_frame_with_tag(mac_a, mac_b, b"l2-b2a-1"))
            .await
            .unwrap();
        timeout(
            Duration::from_secs(8),
            recv_ethernet_tagged(&mut a.nic_rx, mac_b, b"l2-b2a-1"),
        )
        .await
        .expect("l2 unicast b->a");
        assert_eq!(r_fwd.forwarded_packets(), fwd3);
        assert!(r_rev.forwarded_packets() > rev3);

        let fwd4 = r_fwd.forwarded_packets();
        let rev4 = r_rev.forwarded_packets();
        a.mgr
            .send_msg_by_ethernet(ethernet_frame_with_tag(mac_b, mac_a, b"l2-a2b-2"))
            .await
            .unwrap();
        timeout(
            Duration::from_secs(8),
            recv_ethernet_tagged(&mut b.nic_rx, mac_a, b"l2-a2b-2"),
        )
        .await
        .expect("l2 unicast a->b");
        assert!(r_fwd.forwarded_packets() > fwd4);
        assert_eq!(r_rev.forwarded_packets(), rev4);

        // 3) Asymmetric OverlayStream (direct QUIC link must not bypass [[path]])
        a.set_no_tun(true);
        b.set_no_tun(true);
        let ep_a = OverlayStreamEndpoint::start(a.mgr.clone(), false).await;
        let _ep_b = OverlayStreamEndpoint::start(b.mgr.clone(), true).await;

        let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let _echo_task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = echo_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = tcp.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        }));

        let fwd5 = r_fwd.forwarded_packets();
        let rev5 = r_rev.forwarded_packets();
        let mut stream = timeout(
            Duration::from_secs(8),
            ep_a.connector().connect(
                SocketAddr::new(IpAddr::V4(a.ipv4), 40_000),
                SocketAddr::new(IpAddr::V4(b.ipv4), echo_port),
            ),
        )
        .await
        .expect("overlay stream connect")
        .unwrap();

        let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
        timeout(Duration::from_secs(8), async {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0_u8; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        })
        .await
        .expect("overlay stream echo");

        assert!(
            r_fwd.forwarded_packets() > fwd5,
            "OverlayStream a->b bypassed r_fwd"
        );
        assert!(
            r_rev.forwarded_packets() > rev5,
            "OverlayStream b->a bypassed r_rev"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn automatic_routing_stays_single_relay_without_path_rule() {
    timeout(Duration::from_secs(30), async {
        let net = "mp-test-4";
        let a = TestNode::new(net, "10.90.0.1", true, false).await;
        let r1 = TestNode::new(net, "10.90.0.2", true, false).await;
        let r2 = TestNode::new(net, "10.90.0.3", true, false).await;
        let mut b = TestNode::new(net, "10.90.0.4", true, false).await;

        let _listeners = [
            timeout(
                Duration::from_secs(5),
                connect_real_transport(&a, &r1, "quic"),
            )
            .await
            .expect("a->r1 quic"),
            timeout(
                Duration::from_secs(5),
                connect_real_transport(&r1, &b, "quic"),
            )
            .await
            .expect("r1->b quic"),
            timeout(
                Duration::from_secs(5),
                connect_real_transport(&a, &r2, "h2"),
            )
            .await
            .expect("a->r2 h2"),
            timeout(
                Duration::from_secs(5),
                connect_real_transport(&r2, &b, "h2"),
            )
            .await
            .expect("r2->b h2"),
        ];

        for (label, from, to) in [
            ("a->r1", &a.mgr, &r1.mgr),
            ("r1->a", &r1.mgr, &a.mgr),
            ("a->r2", &a.mgr, &r2.mgr),
            ("r2->a", &r2.mgr, &a.mgr),
            ("a->b", &a.mgr, &b.mgr),
            ("b->a", &b.mgr, &a.mgr),
            ("r1->b", &r1.mgr, &b.mgr),
            ("r2->b", &r2.mgr, &b.mgr),
        ] {
            timeout(
                Duration::from_secs(5),
                wait_route_appear(from.clone(), to.clone()),
            )
            .await
            .unwrap_or_else(|_| panic!("route timeout: {label}"))
            .unwrap();
        }

        assert!(!a.mgr.path_applies_to(b.peer_id()));
        timeout(Duration::from_secs(5), warmup_e2e_session(&a, &mut b))
            .await
            .expect("warmup_e2e_session");

        let r1_before = r1.forwarded_packets();
        let r2_before = r2.forwarded_packets();
        send_ipv4_burst(&a, a.ipv4, b.ipv4, 2000, 0..100).await;
        let seqs = timeout(
            Duration::from_secs(5),
            recv_ipv4_seqs(&mut b.nic_rx, a.ipv4, b.ipv4, 2000, 100),
        )
        .await
        .expect("recv_ipv4_seqs 100");
        assert_eq!(seqs, (0..100_u32).collect::<Vec<_>>());

        let d1 = r1.forwarded_packets() - r1_before;
        let d2 = r2.forwarded_packets() - r2_before;
        assert!(
            (d1 >= 100 && d2 == 0) || (d2 >= 100 && d1 == 0),
            "expected strictly single-relay automatic routing, got r1={d1} r2={d2}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cold_start_strict_multipath_queues_and_delivers_zero_drops() {
    timeout(Duration::from_secs(30), async {
        let net = "mp-test-5";
        let a = TestNode::new(net, "10.91.0.1", true, false).await;
        let r1 = TestNode::new(net, "10.91.0.2", true, false).await;
        let r2 = TestNode::new(net, "10.91.0.3", true, false).await;
        let mut b = TestNode::new(net, "10.91.0.4", true, false).await;

        let _listeners = [
            connect_real_transport(&a, &r1, "quic").await,
            connect_real_transport(&r1, &b, "quic").await,
            connect_real_transport(&a, &r2, "wss").await,
            connect_real_transport(&r2, &b, "wss").await,
        ];

        for target in [&r1, &r2, &b] {
            wait_route_appear(a.mgr.clone(), target.mgr.clone())
                .await
                .unwrap();
            wait_route_appear(target.mgr.clone(), a.mgr.clone())
                .await
                .unwrap();
        }
        wait_route_appear(r1.mgr.clone(), b.mgr.clone())
            .await
            .unwrap();
        wait_route_appear(r2.mgr.clone(), b.mgr.clone())
            .await
            .unwrap();

        a.set_path_policy(PathPolicy {
            group: Vec::new(),
            path: vec![PathRule {
                to: b.pub_key(),
                mode: "parallel".to_string(),
                layers: vec![PathStage {
                    nodes: vec![r1.pub_key(), r2.pub_key()],
                    mode: "parallel".to_string(),
                    weights: Vec::new(),
                }],
                gateway: None,
                strict: true,
            }],
        });

        assert!(
            !a.mgr.get_relay_peer_map().has_session(b.peer_id()),
            "session should be cold prior to first packet"
        );

        send_ipv4_burst(&a, a.ipv4, b.ipv4, 2000, 0..24).await;
        let seqs = recv_ipv4_seqs(&mut b.nic_rx, a.ipv4, b.ipv4, 2000, 24).await;
        assert_eq!(seqs, (0..24_u32).collect::<Vec<_>>());
        assert!(a.mgr.get_relay_peer_map().has_session(b.peer_id()));
        let _ = b.mgr.reordered_packets_from(a.peer_id());
    })
    .await
    .unwrap();
}
