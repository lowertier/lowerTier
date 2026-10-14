use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;

use crate::{
    instance::instance::InstanceRpcServerHook,
    instance_manager::NetworkInstanceManager,
    proto::{
        api::control::v1::ControlPlaneV1RpcServer,
        rpc_impl::{service_registry::ServiceRegistry, standalone::StandAloneServer},
        rpc_types::error::Error,
    },
    rpc_service::{
        control::{ControlPlaneService, ControlToken},
        protected_port,
    },
    tunnel::{TunnelListener, tcp::TcpTunnelListener},
};

pub struct ApiRpcServer<T: TunnelListener + 'static> {
    rpc_server: StandAloneServer<T>,
    protected_tcp_port: Option<u16>,
}

impl ApiRpcServer<TcpTunnelListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(
            TcpTunnelListener::new(
                format!("tcp://{}", rpc_addr)
                    .parse()
                    .context("failed to parse rpc portal address")?,
            ),
            instance_manager,
        )?;
        protected_port::register_protected_tcp_port(rpc_addr.port());
        server.protected_tcp_port = Some(rpc_addr.port());

        server
            .rpc_server
            .set_hook(Arc::new(InstanceRpcServerHook::new(rpc_portal_whitelist)));

        Ok(server)
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub fn from_tunnel(
        tunnel: T,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let token_path = ControlToken::default_path(
            instance_manager.get_config_dir().map(|path| path.as_path()),
        )?;
        let token = ControlToken::load_or_create(&token_path)?;
        let rpc_server = StandAloneServer::new(tunnel);
        register_api_rpc_service(&instance_manager, rpc_server.registry(), token);
        Ok(Self {
            rpc_server,
            protected_tcp_port: None,
        })
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

impl<T: TunnelListener + 'static> Drop for ApiRpcServer<T> {
    fn drop(&mut self) {
        if let Some(port) = self.protected_tcp_port.take() {
            protected_port::unregister_protected_tcp_port(port);
        }
        self.rpc_server.registry().unregister_all();
    }
}

pub fn register_api_rpc_service(
    instance_manager: &Arc<NetworkInstanceManager>,
    registry: &ServiceRegistry,
    token: ControlToken,
) {
    registry.register(
        ControlPlaneV1RpcServer::new(ControlPlaneService::new(instance_manager.clone(), token)),
        "",
    );
}

fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        Ok(SocketAddr::from(([127, 0, 0, 1], port)))
    } else {
        let mut rpc_addr = rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?;
        select_proper_rpc_port(&mut rpc_addr)?;
        let rpc_addr =
            rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))?;
        if !rpc_addr.ip().is_loopback() {
            return Err(anyhow::anyhow!(
                "the management RPC portal requires a loopback address"
            ));
        }
        Ok(rpc_addr)
    }
}

fn select_proper_rpc_port(addr: &mut Option<SocketAddr>) -> anyhow::Result<()> {
    match addr {
        None => {
            *addr = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
            select_proper_rpc_port(addr)?;
            Ok(())
        }
        Some(addr) => {
            if addr.port() == 0 {
                let Some(port) = crate::utils::find_free_tcp_port(15888..15900) else {
                    tracing::warn!(
                        "No free port found for RPC portal, skipping setting RPC portal"
                    );
                    return Err(anyhow::anyhow!("No free port found for RPC portal"));
                };
                addr.set_port(port);
            }
            Ok(())
        }
    }
}
