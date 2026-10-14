use super::*;
use crate::{
    common::{config::NetworkIdentity, global_ctx::tests::get_mock_global_ctx_with_network},
    peers::{
        PacketRecvChanReceiver, create_packet_recv_chan,
        peer_conn::{PeerConn, tests::set_secure_mode_cfg},
        peer_session::{PeerSessionStore, SessionKey},
    },
    tunnel::packet_def::PacketType,
};
use tokio::sync::watch;
use tokio_util::task::AbortOnDropHandle;

struct RebindingProxy {
    address: SocketAddr,
    source: watch::Sender<Arc<UdpSocket>>,
    _task: AbortOnDropHandle<()>,
}

impl RebindingProxy {
    async fn new(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = front.local_addr().unwrap();
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (source, mut changed) = watch::channel(back.clone());
        let task = tokio::spawn(async move {
            let mut back = back;
            let mut client = None;
            let mut upstream = vec![0; 65535];
            let mut downstream = vec![0; 65535];
            loop {
                tokio::select! {
                    biased;
                    update = changed.changed() => {
                        if update.is_err() { break; }
                        back = changed.borrow_and_update().clone();
                    }
                    received = front.recv_from(&mut upstream) => {
                        let (length, remote) = received.unwrap();
                        client = Some(remote);
                        back.send_to(&upstream[..length], server).await.unwrap();
                    }
                    received = back.recv_from(&mut downstream) => {
                        let (length, remote) = received.unwrap();
                        if remote == server && let Some(client) = client {
                            front.send_to(&downstream[..length], client).await.unwrap();
                        }
                    }
                }
            }
        });
        Self {
            address,
            source,
            _task: AbortOnDropHandle::new(task),
        }
    }

    async fn rebind(&self) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = socket.local_addr().unwrap();
        self.source.send_replace(socket);
        address
    }
}

struct Peers {
    client: PeerConn,
    server: PeerConn,
    client_rx: PacketRecvChanReceiver,
    server_rx: PacketRecvChanReceiver,
    server_ctx: ArcGlobalCtx,
    server_path: Arc<crate::tunnel::TunnelPathState>,
    client_sessions: Arc<PeerSessionStore>,
    proxy: RebindingProxy,
    _decoy_upstream: Option<UdpSocket>,
}

impl Peers {
    async fn new(decoy: bool) -> Self {
        let context = || {
            let ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "quic-rebinding".into(),
                "test-rebinding-secret".into(),
            )));
            set_secure_mode_cfg(&ctx, true);
            ctx
        };
        let server_ctx = context();
        let client_ctx = context();
        let decoy_upstream = if decoy {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut flags = server_ctx.get_flags();
            flags.quic_decoy_upstream = upstream.local_addr().unwrap().to_string();
            flags.quic_admission_secret = "test-rebinding-routing-secret".into();
            flags.quic_server_name = "challenges.cloudflare.com".into();
            server_ctx.set_flags(flags);
            let mut flags = client_ctx.get_flags();
            flags.quic_decoy_upstream = upstream.local_addr().unwrap().to_string();
            flags.quic_admission_secret = "test-rebinding-routing-secret".into();
            flags.quic_server_name = "challenges.cloudflare.com".into();
            client_ctx.set_flags(flags);
            Some(upstream)
        } else {
            None
        };
        let mut listener =
            QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), server_ctx.clone());
        listener.listen().await.unwrap();
        let server_addr = listener.endpoint.as_ref().unwrap().local_addr().unwrap();
        let proxy = RebindingProxy::new(server_addr).await;
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut connector = QuicTunnelConnector::new(
            super::super::build_url_from_socket_addr(&proxy.address.to_string(), "quic"),
            client_ctx.clone(),
        );
        let client_tunnel = connector.connect().await.unwrap();
        let server_tunnel = accept.await.unwrap();
        let server_path = server_tunnel.path_state().unwrap();
        assert!(!server_path.peer_authenticated.load(Ordering::Acquire));
        let initial = proxy.source.borrow().local_addr().unwrap();
        let policy = QuicRebindingPolicy {
            global_ctx: Arc::downgrade(&server_ctx),
            initial_remote: initial,
            path_state: server_path.clone(),
        };
        assert!(!quinn::PathPolicy::allow(&policy, initial, initial));
        assert_eq!(
            client_tunnel.transport_binding(),
            server_tunnel.transport_binding()
        );
        assert_eq!(
            client_tunnel.transport_binding().unwrap().kind,
            TransportBindingKind::QuicTlsExporterV1
        );
        assert!(!client_tunnel.is_transport_authenticated());
        assert!(!server_tunnel.is_transport_authenticated());
        let client_sessions = Arc::new(PeerSessionStore::new());
        let mut client = PeerConn::new(1001, client_ctx, client_tunnel, client_sessions.clone());
        let mut server = PeerConn::new(
            2002,
            server_ctx.clone(),
            server_tunnel,
            Arc::new(PeerSessionStore::new()),
        );
        let (client_result, server_result) = tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server(),
        );
        client_result.unwrap();
        server_result.unwrap();
        assert!(server_path.peer_authenticated.load(Ordering::Acquire));
        let (client_tx, client_rx) = create_packet_recv_chan();
        let (server_tx, server_rx) = create_packet_recv_chan();
        client.start_recv_loop(client_tx).await;
        server.start_recv_loop(server_tx).await;
        Self {
            client,
            server,
            client_rx,
            server_rx,
            server_ctx,
            server_path,
            client_sessions,
            proxy,
            _decoy_upstream: decoy_upstream,
        }
    }

    async fn deliver(&mut self) {
        for (sender, receiver, from, to) in [
            (&self.client, &mut self.server_rx, 1001, 2002),
            (&self.server, &mut self.client_rx, 2002, 1001),
        ] {
            let mut packet = ZCPacket::new_with_payload(b"after-rebinding");
            packet.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
            sender.send_msg(packet).await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.payload(), b"after-rebinding");
            assert!(received.is_lossy(), "delivery must use QUIC DATAGRAM");
        }
    }

    fn remote(&self) -> url::Url {
        url::Url::parse(
            &self
                .server
                .get_conn_info()
                .tunnel
                .unwrap()
                .resolved_remote_addr
                .unwrap()
                .url,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn authenticated_quic_survives_source_port_rebinding() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut peers = Peers::new(true).await;
        peers.deliver().await;
        let connection_id = peers.server.get_conn_id();
        let session_key = SessionKey::new("quic-rebinding".into(), 2002);
        let session = peers.client_sessions.get(&session_key).unwrap();
        let old_remote = peers.remote();
        let new_remote = peers.proxy.rebind().await;
        assert_ne!(Some(new_remote.port()), old_remote.port());
        peers.deliver().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while peers.remote().port() != Some(new_remote.port()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(QUIC_MAX_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        peers.deliver().await;
        assert_eq!(peers.server.get_conn_id(), connection_id);
        assert!(Arc::ptr_eq(
            &session,
            &peers.client_sessions.get(&session_key).unwrap()
        ));
        assert_eq!(peers.remote().port(), Some(new_remote.port()));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn quic_rebinding_keeps_the_old_path_when_policy_denies_the_new_path() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peers = Peers::new(false).await;
        peers.deliver().await;
        let old_remote = peers.remote();
        let old_source = peers.proxy.source.borrow().clone();
        let mut flags = peers.server_ctx.get_flags();
        flags.underlay_deny_cidrs = vec!["127.0.0.0/8".into()];
        peers.server_ctx.set_flags(flags);
        let new_remote = peers.proxy.rebind().await;
        let mut packet = ZCPacket::new_with_payload(b"denied-path");
        packet.fill_peer_manager_hdr(1001, 2002, PacketType::Data as u8);
        peers.client.send_msg(packet).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peers.server_rx.recv())
                .await
                .is_err()
        );
        assert_eq!(peers.remote(), old_remote);
        assert_ne!(peers.remote().port(), Some(new_remote.port()));
        let policy = QuicRebindingPolicy {
            global_ctx: Arc::downgrade(&peers.server_ctx),
            initial_remote: old_source.local_addr().unwrap(),
            path_state: peers.server_path.clone(),
        };
        assert!(!quinn::PathPolicy::allow(&policy, new_remote, new_remote));
        peers.proxy.source.send_replace(old_source);
        peers.deliver().await;
        assert_eq!(peers.remote(), old_remote);
    })
    .await
    .unwrap();
}
