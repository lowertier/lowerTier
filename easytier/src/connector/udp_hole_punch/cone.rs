use std::{sync::Arc, time::Duration};

use anyhow::Context;
use quanta::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{PeerId, upnp},
    connector::udp_hole_punch::common::{
        HOLE_PUNCH_PACKET_BODY_LEN, UdpSocketArray, bind_ipv4_socket, try_connect_with_socket,
    },
    connector::udp_hole_punch::handle_rpc_result,
    peers::peer_manager::PeerManager,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketConeRequest, UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{Tunnel, udp::new_authenticated_hole_punch_packet},
};

use super::common::PunchHoleServerCommon;

pub(crate) struct PunchConeHoleServer {
    common: Arc<PunchHoleServerCommon>,
}

impl PunchConeHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self { common }
    }

    #[tracing::instrument(skip(self, request), fields(transaction_id = request.transaction_id, candidate_count = request.dest_addrs.len()), ret, err)]
    pub(crate) async fn send_punch_packet_cone(
        &self,
        _: BaseController,
        request: SendPunchPacketConeRequest,
    ) -> Result<Void, rpc_types::error::Error> {
        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing listener_mapped_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_for_cone failed to find listener"
            ))?;

        let token: [u8; HOLE_PUNCH_PACKET_BODY_LEN as usize] =
            request.auth_token.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("send_punch_packet_for_cone requires a 16-byte token")
            })?;
        let mut dest_addrs = request
            .dest_addrs
            .iter()
            .copied()
            .map(std::net::SocketAddr::from)
            .collect::<Vec<_>>();
        if dest_addrs.is_empty()
            && let Some(dest_addr) = request.dest_addr
        {
            dest_addrs.push(dest_addr.into());
        }
        dest_addrs.sort_unstable();
        dest_addrs.dedup();
        if dest_addrs.is_empty() {
            return Err(
                anyhow::anyhow!("send_punch_packet_for_cone request missing destinations").into(),
            );
        }
        for dest_addr in &dest_addrs {
            let dest_ip = dest_addr.ip();
            if dest_ip.is_unspecified()
                || dest_ip.is_multicast()
                || !self
                    .common
                    .get_global_ctx()
                    .get_underlay_policy()
                    .allows_remote(dest_ip)
            {
                return Err(anyhow::anyhow!(
                    "send_punch_packet_for_cone destination is malformed or denied: {dest_addr}"
                )
                .into());
            }
        }

        for _ in 0..request.packet_batch_count {
            tracing::info!(?request, "sending hole punching packet");

            for dest_addr in &dest_addrs {
                for _ in 0..request.packet_count_per_batch {
                    let udp_packet =
                        new_authenticated_hole_punch_packet(request.transaction_id, &token);
                    if let Err(e) = listener.send_to(&udp_packet.into_bytes(), dest_addr).await {
                        tracing::error!(?e, ?dest_addr, "failed to send hole punch packet");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(request.packet_interval_ms as u64)).await;
        }

        Ok(Void::default())
    }
}

pub(crate) struct PunchConeHoleClient {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchConeHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr,
            blacklist,
        }
    }

    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        tracing::info!(?dst_peer_id, "start hole punching");
        let tid = rand::random();
        let auth_token: [u8; HOLE_PUNCH_PACKET_BODY_LEN as usize] = rand::random();

        let global_ctx = self.peer_mgr.get_global_ctx();
        let udp_array = UdpSocketArray::new(1, global_ctx.clone());

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let resp = rpc_stub
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    force_new: false,
                    prefer_port_mapping: true,
                },
            )
            .await;

        let resp = handle_rpc_result(resp, dst_peer_id, &self.blacklist)?;

        let remote_mapped_addr = resp.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "select_punch_listener response missing listener_mapped_addr"
        ))?;
        let remote_socket_addr = std::net::SocketAddr::from(remote_mapped_addr);
        if !global_ctx
            .get_underlay_policy()
            .allows_remote(remote_socket_addr.ip())
        {
            return Err(anyhow::anyhow!(
                "remote UDP mapped address is denied by underlay policy"
            ));
        }

        // STUN owns recv_from until candidate gathering completes. Only then is the
        // exact same socket handed to the punch demultiplexer and final UDP tunnel.
        let local_socket = bind_ipv4_socket(&global_ctx).await?;
        let local_addr = local_socket
            .local_addr()
            .with_context(|| "failed to get local addr from udp punch socket")?;
        let local_listener: url::Url = format!("udp://{local_addr}").parse().unwrap();
        let (local_mapped_addrs, _local_port_mapping_lease) = upnp::resolve_udp_public_addrs(
            global_ctx.clone(),
            &local_listener,
            local_socket.clone(),
        )
        .await
        .with_context(|| "failed to resolve udp public addr for cone hole punch")?;

        tracing::debug!(
            ?local_mapped_addrs,
            ?remote_mapped_addr,
            "hole punch got remote listener"
        );

        udp_array.add_new_socket(local_socket).await?;
        udp_array.add_authenticated_interest_tid(tid, auth_token);
        let send_from_local = || async {
            udp_array
                .send_with_all(
                    &new_authenticated_hole_punch_packet(tid, &auth_token).into_bytes(),
                    remote_socket_addr,
                )
                .await
                .with_context(|| "failed to send hole punch packet from local")
        };

        send_from_local().await?;

        let primary_local_mapped_addr = local_mapped_addrs[0];
        let rpc_dest_addrs = local_mapped_addrs
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
            if let Err(e) = rpc_stub
                .send_punch_packet_cone(
                    BaseController {
                        timeout_ms: 4000,
                        ..Default::default()
                    },
                    SendPunchPacketConeRequest {
                        listener_mapped_addr: Some(remote_mapped_addr),
                        dest_addr: Some(primary_local_mapped_addr.into()),
                        transaction_id: tid,
                        packet_count_per_batch: 2,
                        packet_batch_count: 5,
                        packet_interval_ms: 400,
                        dest_addrs: rpc_dest_addrs,
                        auth_token: auth_token.to_vec(),
                    },
                )
                .await
            {
                tracing::error!(?e, "failed to call remote send punch packet");
            }
        }));

        // server: will send some punching resps, total 10 packets.
        // client: use the socket to create UdpTunnel with UdpTunnelConnector
        // NOTICE: UdpTunnelConnector will ignore the punching resp packet sent by remote.
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && punch_task.is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, send some more hole punch packets");
                send_from_local().await?;
                continue;
            };

            tracing::debug!(?socket, ?tid, "punched socket found, try connect with it");

            for _ in 0..2 {
                match try_connect_with_socket(
                    global_ctx.clone(),
                    socket.socket.clone(),
                    socket.remote_addr,
                )
                .await
                {
                    Ok(tunnel) => {
                        tracing::info!(?tunnel, "hole punched");
                        return Ok(Some(tunnel));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                    }
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::{
        common::upnp::{
            reset_udp_port_mapping_attempts_for_test, udp_port_mapping_attempts_for_test,
        },
        connector::udp_hole_punch::{
            UdpHolePunchConnector, cone::PunchConeHoleClient,
            tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear, wait_route_appear_with_cost},
        proto::common::NatType,
    };

    #[tokio::test]
    async fn hole_punching_cone() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        println!("{:?}", p_a.list_routes().await);

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run_as_client().await.unwrap();
        hole_punching_c.run_as_server().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
        println!("{:?}", p_a.list_routes().await);
    }

    #[tokio::test]
    async fn cone_hole_punch_does_not_create_upnp_mapping_before_listener_rpc_succeeds() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::Restricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_upnp = false;
        p_a.get_global_ctx().set_flags(flags);

        reset_udp_port_mapping_attempts_for_test();

        let ret = PunchConeHoleClient::new(p_a.clone(), Arc::new(timedmap::TimedMap::new()))
            .do_hole_punching(p_c.my_peer_id())
            .await;

        assert!(ret.is_err());
        assert_eq!(udp_port_mapping_attempts_for_test(), 0);
    }
}
