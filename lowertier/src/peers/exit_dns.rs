use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, ensure};
use tokio::sync::Semaphore;

use crate::{
    common::global_ctx::ArcGlobalCtx,
    proto::{
        peer_rpc::{
            ExitDnsRequest, ExitDnsResponse, ExitDnsRpc, ExitDnsRpcClientFactory, PeerIdentityType,
            SecureAuthLevel,
        },
        rpc_types::{controller::BaseController, error},
    },
};

impl super::peer_manager::PeerManager {
    pub(crate) fn resolve_proxy_domain(
        &self,
        name: String,
        port: u16,
        connection: u64,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<Option<SocketAddr>>> {
        Box::pin(async move {
            let Some(exit) = self.proxy_dns_exit(connection).await? else {
                return Ok(None);
            };
            let name = idna::domain_to_ascii(&name).context("invalid proxy DNS name")?;
            let manager = self.get_peer_rpc_mgr();
            let client = manager
                .rpc_client()
                .scoped_client::<ExitDnsRpcClientFactory<BaseController>>(
                    self.my_peer_id(),
                    exit,
                    self.get_global_ctx().get_network_name(),
                );
            let response = client
                .resolve(
                    BaseController {
                        timeout_ms: 8000,
                        ..Default::default()
                    },
                    ExitDnsRequest {
                        name,
                        port: u32::from(port),
                    },
                )
                .await
                .context("exit DNS failed")?;
            ensure!(
                response.addresses.len() <= MAX_DNS_ADDRESSES,
                "exit DNS response is too large"
            );
            let address = response
                .addresses
                .into_iter()
                .filter_map(|address| {
                    if address.port != u32::from(port) || address.ip.is_none() {
                        return None;
                    }
                    let address: SocketAddr = address.into();
                    (address.is_ipv4()
                        && !address.ip().is_loopback()
                        && !address.ip().is_unspecified()
                        && !address.ip().is_multicast()
                        && address.ip() != std::net::Ipv4Addr::BROADCAST)
                        .then_some(address)
                })
                .next()
                .context("exit DNS returned no usable IPv4 address")?;
            // The normal dial path still checks the resolved address against routes and ACLs.
            Ok(Some(address))
        })
    }
}

pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_ADDRESSES: usize = 16;

#[derive(Clone)]
pub(crate) struct ExitDnsServer {
    context: ArcGlobalCtx,
    slots: Arc<Semaphore>,
}

impl ExitDnsServer {
    pub(crate) fn new(context: ArcGlobalCtx) -> Self {
        Self {
            context,
            slots: Arc::new(Semaphore::new(16)),
        }
    }

    async fn resolve_inner(
        &self,
        controller: BaseController,
        request: ExitDnsRequest,
    ) -> anyhow::Result<ExitDnsResponse> {
        validate_request(&controller, &request)?;
        ensure!(
            self.context.flags_arc().enable_exit_node,
            "exit DNS is disabled"
        );
        // Reject excess requests instead of retaining an unbounded resolver queue.
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("exit DNS is busy")?;
        let context = self.context.clone();
        let lookup = tokio::task::spawn_blocking(move || {
            // A timed-out getaddrinfo cannot be canceled. Keep its slot until the worker returns.
            let _slot = slot;
            context
                .net_ns
                .run(|| (request.name.as_str(), request.port as u16).to_socket_addrs())
        });
        let addresses = tokio::time::timeout(DNS_TIMEOUT, lookup)
            .await
            .context("exit DNS timed out")?
            .context("exit DNS worker failed")??;
        let mut result = Vec::new();
        for address in addresses.filter(SocketAddr::is_ipv4) {
            if !result.contains(&address) {
                result.push(address);
            }
            if result.len() == MAX_DNS_ADDRESSES {
                break;
            }
        }
        ensure!(!result.is_empty(), "exit DNS returned no IPv4 address");
        Ok(ExitDnsResponse {
            addresses: result.into_iter().map(Into::into).collect(),
        })
    }
}

fn validate_request(controller: &BaseController, request: &ExitDnsRequest) -> anyhow::Result<()> {
    ensure!(
        controller.authenticated_peer_id.is_some()
            && matches!(
                controller.authenticated_peer_identity_type,
                Some(PeerIdentityType::Admin | PeerIdentityType::Credential)
            )
            && matches!(
                controller.authenticated_peer_secure_auth_level,
                Some(SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed)
            ),
        "exit DNS requires an authenticated network peer"
    );
    let name = request.name.strip_suffix('.').unwrap_or(&request.name);
    ensure!(
        !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }),
        "invalid exit DNS name"
    );
    ensure!((1..=65535).contains(&request.port), "invalid exit DNS port");
    Ok(())
}

#[async_trait::async_trait]
impl ExitDnsRpc for ExitDnsServer {
    type Controller = BaseController;

    async fn resolve(
        &self,
        controller: BaseController,
        request: ExitDnsRequest,
    ) -> error::Result<ExitDnsResponse> {
        self.resolve_inner(controller, request)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        peers::tests::{connect_peer_manager, create_mock_peer_manager_secure, wait_route_appear},
        proto::{
            common::{PathGroup, PathPolicy, PathRule, PathStage},
            peer_rpc::ExitDnsRpcServer,
        },
    };

    #[tokio::test]
    async fn exit_dns_requires_admission_and_exit_service() {
        let context = crate::common::global_ctx::tests::get_mock_global_ctx();
        let server = ExitDnsServer::new(context.clone());
        let request = ExitDnsRequest {
            name: "localhost".into(),
            port: 80,
        };
        assert!(
            server
                .resolve(BaseController::default(), request.clone())
                .await
                .is_err()
        );
        let controller = BaseController {
            authenticated_peer_id: Some(7),
            authenticated_peer_identity_type: Some(PeerIdentityType::Admin),
            authenticated_peer_secure_auth_level: Some(SecureAuthLevel::NetworkSecretConfirmed),
            ..Default::default()
        };
        assert!(
            server
                .resolve(controller.clone(), request.clone())
                .await
                .is_err()
        );
        let mut flags = context.get_flags();
        flags.enable_exit_node = true;
        context.set_flags(flags);
        let response = server.resolve(controller.clone(), request).await.unwrap();
        assert!(response.addresses.iter().all(|address| {
            let address: SocketAddr = (*address).into();
            address.is_ipv4() && address.ip().is_loopback() && address.port() == 80
        }));
        for name in ["", "bad name", "-bad.test", "bad..test"] {
            assert!(
                server
                    .resolve(
                        controller.clone(),
                        ExitDnsRequest {
                            name: name.into(),
                            port: 80,
                        }
                    )
                    .await
                    .is_err()
            );
        }
        let _slots = server.slots.acquire_many(16).await.unwrap();
        assert!(
            server
                .resolve(
                    controller,
                    ExitDnsRequest {
                        name: "localhost".into(),
                        port: 80,
                    }
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("busy")
        );
    }

    #[derive(Clone)]
    struct RemoteDns {
        reject: Arc<std::sync::atomic::AtomicBool>,
        answer: SocketAddr,
    }

    #[async_trait::async_trait]
    impl ExitDnsRpc for RemoteDns {
        type Controller = BaseController;
        async fn resolve(
            &self,
            controller: BaseController,
            request: ExitDnsRequest,
        ) -> error::Result<ExitDnsResponse> {
            validate_request(&controller, &request)?;
            assert_eq!(request.name, "exit-only.invalid");
            if self.reject.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(anyhow::anyhow!("test exit DNS refused").into());
            }
            Ok(ExitDnsResponse {
                addresses: vec![self.answer.into()],
            })
        }
    }

    #[tokio::test]
    async fn proxy_dns_uses_authenticated_exit_and_never_falls_back_on_failure() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let a = create_mock_peer_manager_secure("exit-dns".into(), "secret".into()).await;
            let b = create_mock_peer_manager_secure("exit-dns".into(), "secret".into()).await;
            a.get_global_ctx()
                .set_ipv4(Some("10.42.0.1/24".parse().unwrap()));
            b.get_global_ctx()
                .set_ipv4(Some("10.42.0.2/24".parse().unwrap()));
            let mut flags = b.get_global_ctx().get_flags();
            flags.enable_exit_node = true;
            b.get_global_ctx().set_flags(flags);
            let reject = Arc::new(std::sync::atomic::AtomicBool::new(false));
            b.get_peer_rpc_mgr().rpc_server().registry().register(
                ExitDnsRpcServer::new(RemoteDns {
                    reject: reject.clone(),
                    answer: "192.0.2.17:443".parse().unwrap(),
                }),
                "exit-dns",
            );
            connect_peer_manager(a.clone(), b.clone()).await;
            wait_route_appear(a.clone(), b.clone()).await.unwrap();
            let mut flags = a.get_global_ctx().get_flags();
            flags.path_policy = Some(PathPolicy {
                group: Vec::new(),
                path: vec![PathRule {
                    to: "internet".into(),
                    gateway: Some(PathStage {
                        nodes: vec!["10.42.0.2".into()],
                        ..Default::default()
                    }),
                    strict: true,
                    ..Default::default()
                }],
            });
            a.get_global_ctx().set_flags(flags);
            assert_eq!(
                a.resolve_proxy_domain("exit-only.invalid".into(), 443, 7)
                    .await
                    .unwrap(),
                Some("192.0.2.17:443".parse().unwrap())
            );
            reject.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(
                a.resolve_proxy_domain("exit-only.invalid".into(), 443, 7)
                    .await
                    .is_err()
            );
            let mut flags = a.get_global_ctx().get_flags();
            flags.path_policy.as_mut().unwrap().path[0].gateway = Some(PathStage {
                nodes: vec!["10.42.0.99".into()],
                ..Default::default()
            });
            a.get_global_ctx().set_flags(flags);
            assert!(
                a.resolve_proxy_domain("exit-only.invalid".into(), 443, 7)
                    .await
                    .is_err()
            );
            let mut flags = a.get_global_ctx().get_flags();
            reject.store(false, std::sync::atomic::Ordering::Relaxed);
            let c = create_mock_peer_manager_secure("exit-dns".into(), "secret".into()).await;
            c.get_global_ctx().set_ipv4(Some("10.42.0.3/24".parse().unwrap()));
            let mut c_flags = c.get_global_ctx().get_flags();
            c_flags.enable_exit_node = true;
            c.get_global_ctx().set_flags(c_flags);
            c.get_peer_rpc_mgr().rpc_server().registry().register(
                ExitDnsRpcServer::new(RemoteDns { reject: reject.clone(), answer: "192.0.2.18:443".parse().unwrap() }),
                "exit-dns",
            );
            connect_peer_manager(a.clone(), c.clone()).await;
            wait_route_appear(a.clone(), c.clone()).await.unwrap();
            flags.path_policy = Some(PathPolicy {
                group: vec![PathGroup {
                    name: "exits".into(),
                    nodes: vec!["10.42.0.2".into(), "10.42.0.3".into()],
                    mode: "flow".into(),
                    weights: Vec::new(),
                }],
                path: vec![PathRule {
                    to: "internet".into(),
                    gateway: Some(PathStage {
                        nodes: vec!["exits".into()],
                        ..Default::default()
                    }),
                    strict: true,
                    ..Default::default()
                }],
            });
            a.get_global_ctx().set_flags(flags.clone());
            for flow in 0..16 {
                let answer = a.resolve_proxy_domain("exit-only.invalid".into(), 443, flow).await.unwrap().unwrap();
                let expected = if answer.ip() == "192.0.2.17".parse::<std::net::IpAddr>().unwrap() { b.my_peer_id() } else { c.my_peer_id() };
                assert!(matches!(a.plan_user_route(answer.ip(), flow).await.unwrap(),
                    super::super::peer_manager::UserRoutePlan::Overlay { peer_ids, is_exit_node: true } if peer_ids == [expected]));
            }
            flags.path_policy = None;
            a.get_global_ctx().set_flags(flags);
            assert_eq!(
                a.resolve_proxy_domain("exit-only.invalid".into(), 443, 7)
                    .await
                    .unwrap(),
                None
            );
        })
        .await
        .unwrap();
    }
}
