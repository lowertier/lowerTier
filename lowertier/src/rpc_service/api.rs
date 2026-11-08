use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;

use crate::{
    common::config::ConfigLoader,
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
    _maintenance: tokio_util::task::AbortOnDropHandle<()>,
    rpc_server: StandAloneServer<T>,
    protected_tcp_port: Option<u16>,
    pub addr: Option<SocketAddr>,
    pub token_path: std::path::PathBuf,
}

/// Control token settings from `[control]`.
#[derive(Default)]
pub struct TokenOptions {
    pub path: Option<std::path::PathBuf>,
    pub group: Option<String>,
}

impl ApiRpcServer<TcpTunnelListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        token: TokenOptions,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(
            TcpTunnelListener::new_local_service(
                format!("h2://{}", rpc_addr)
                    .parse()
                    .context("failed to parse rpc portal address")?,
            )?,
            token,
            instance_manager,
        )?;
        protected_port::register_protected_tcp_port(rpc_addr.port());
        server.protected_tcp_port = Some(rpc_addr.port());
        server.addr = Some(rpc_addr);

        server
            .rpc_server
            .set_hook(Arc::new(InstanceRpcServerHook::new(rpc_portal_whitelist)));

        Ok(server)
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    fn from_tunnel(
        tunnel: T,
        token: TokenOptions,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let mut configured = token
            .path
            .into_iter()
            .chain(
                instance_manager
                    .iter()
                    .filter_map(|instance| instance.get_config().get_control_token_file()),
            )
            .collect::<Vec<_>>();
        configured.sort();
        configured.dedup();
        anyhow::ensure!(
            configured.len() <= 1,
            "The process requires one control token file."
        );
        let token_path = match configured.pop() {
            Some(path) => path,
            None => ControlToken::default_path(
                instance_manager.get_config_dir().map(|path| path.as_path()),
            )?,
        };
        let control_token = ControlToken::load_or_create(&token_path, token.group.as_deref())
            .with_context(|| format!("control token {}", token_path.display()))?;
        let rpc_server = StandAloneServer::new(tunnel);
        register_api_rpc_service(&instance_manager, rpc_server.registry(), control_token);
        Ok(Self {
            _maintenance: crate::rpc_service::control::maintenance::spawn(&instance_manager),
            rpc_server,
            protected_tcp_port: None,
            addr: None,
            token_path,
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
