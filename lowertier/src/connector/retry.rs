use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use parking_lot::Mutex;
use tokio::time::Instant;

use crate::proto::common::TunnelInfo;
use crate::tunnel::{
    ReceiveBackpressure, SplitTunnel, TransportBinding, Tunnel, TunnelConnector, TunnelError,
    TunnelPathState,
};

type Endpoint = (String, SocketAddr, String);

#[derive(Default)]
pub(crate) struct TransportRetries {
    endpoints: Mutex<BTreeMap<Endpoint, Option<Instant>>>,
}

impl TransportRetries {
    #[cfg(test)]
    pub(crate) fn begin(
        self: &Arc<Self>,
        protocol: &str,
        address: SocketAddr,
    ) -> Result<Attempt, TunnelError> {
        self.begin_identity(protocol, address, String::new())
    }

    pub(crate) fn begin_url(
        self: &Arc<Self>,
        url: &url::Url,
        address: SocketAddr,
    ) -> Result<Attempt, TunnelError> {
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
        let authority = if host.parse::<std::net::IpAddr>().ok() == Some(address.ip()) {
            ""
        } else {
            host
        };
        let path = match url.path() {
            "" | "/" => "",
            path => path,
        };
        let mut identity = format!("{authority}{path}");
        if let Some(query) = url.query() {
            let fields = query
                .split('&')
                .filter(|field| {
                    !url::form_urlencoded::parse(field.as_bytes())
                        .next()
                        .is_some_and(|(key, _)| key == "lanes")
                })
                .collect::<Vec<_>>();
            if !fields.is_empty() {
                identity.push('?');
                identity.push_str(&fields.join("&"));
            }
        }
        if identity.len() > 1024 {
            return Err(TunnelError::InvalidAddr(
                "transport routing identity is too long".into(),
            ));
        }
        self.begin_identity(url.scheme(), address, identity)
    }

    fn begin_identity(
        self: &Arc<Self>,
        protocol: &str,
        address: SocketAddr,
        identity: String,
    ) -> Result<Attempt, TunnelError> {
        let key = (protocol.to_owned(), address, identity);
        let now = Instant::now();
        let mut endpoints = self.endpoints.lock();
        endpoints.retain(|_, deadline| deadline.is_none_or(|deadline| deadline > now));
        if endpoints.contains_key(&key) {
            return Err(TunnelError::InternalError(
                "transport endpoint is active or in cold retry".into(),
            ));
        }
        // This bound covers active connections and failed discovery endpoints together.
        if endpoints.len() >= 1024 {
            return Err(TunnelError::InternalError(
                "transport retry table is full".into(),
            ));
        }
        endpoints.insert(key.clone(), None);
        Ok(Attempt {
            _lease: Arc::new(AttemptLease {
                retries: self.clone(),
                key,
                paths: Mutex::new(Vec::new()),
                authenticated: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }
}

pub(crate) fn begin_endpoint(
    context: &crate::common::global_ctx::ArcGlobalCtx,
    protocol: &str,
    address: SocketAddr,
) -> Result<Attempt, TunnelError> {
    let url = url::Url::parse(&format!("{protocol}://{address}"))
        .map_err(|error| TunnelError::InvalidAddr(error.to_string()))?;
    let url = crate::tunnel::websocket::effective_wss_url(url, &context.get_flags());
    context.transport_retries.begin_url(&url, address)
}

#[derive(Clone)]
pub(crate) struct Attempt {
    _lease: Arc<AttemptLease>,
}

impl Attempt {
    pub(crate) fn authenticated(&self) {
        self._lease
            .authenticated
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

struct AttemptLease {
    retries: Arc<TransportRetries>,
    key: Endpoint,
    paths: Mutex<Vec<Arc<TunnelPathState>>>,
    authenticated: std::sync::atomic::AtomicBool,
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        let authenticated = self
            .authenticated
            .load(std::sync::atomic::Ordering::Acquire)
            || self.paths.lock().iter().any(|path| {
                path.peer_authenticated
                    .load(std::sync::atomic::Ordering::Acquire)
            });
        let mut endpoints = self.retries.endpoints.lock();
        if authenticated {
            endpoints.remove(&self.key);
        } else {
            endpoints.insert(
                self.key.clone(),
                Some(Instant::now() + super::COLD_RETRY_INTERVAL),
            );
        }
    }
}

pub(crate) fn retain_attempt(inner: Box<dyn Tunnel>, attempt: Attempt) -> Box<dyn Tunnel> {
    retain_attempts(inner, vec![attempt])
}

pub(crate) fn retain_attempts(inner: Box<dyn Tunnel>, attempts: Vec<Attempt>) -> Box<dyn Tunnel> {
    retain_with_pin(inner, attempts, None)
}

pub(super) fn retain_with_pin(
    inner: Box<dyn Tunnel>,
    attempts: Vec<Attempt>,
    pin: Option<String>,
) -> Box<dyn Tunnel> {
    let remote = inner
        .info()
        .and_then(|info| info.resolved_remote_addr.or(info.remote_addr))
        .and_then(|remote| url::Url::parse(&remote.url).ok())
        .and_then(|url| {
            Some(SocketAddr::new(
                url.host_str()?.trim_matches(['[', ']']).parse().ok()?,
                url.port_or_known_default()?,
            ))
        });
    // Only the selected endpoint inherits authentication. Other candidate leases become cold.
    let attempts = attempts
        .into_iter()
        .filter(|attempt| remote.is_none_or(|remote| attempt._lease.key.1 == remote))
        .collect::<Vec<_>>();
    let path = inner.path_state().or_else(|| {
        inner.info().map(|info| {
            Arc::new(TunnelPathState {
                peer_authenticated: std::sync::atomic::AtomicBool::new(false),
                info: parking_lot::RwLock::new(info),
            })
        })
    });
    if let Some(path) = &path {
        for attempt in &attempts {
            attempt._lease.paths.lock().push(path.clone());
        }
    }
    Box::new(RetryingTunnel {
        inner,
        _attempts: attempts,
        path,
        pin,
    })
}

pub(crate) fn reserve_candidates(
    context: &crate::common::global_ctx::ArcGlobalCtx,
    protocol: &str,
    candidates: Vec<SocketAddr>,
) -> anyhow::Result<(Vec<SocketAddr>, Vec<Attempt>)> {
    let mut addresses = Vec::new();
    let mut attempts = Vec::new();
    for address in candidates {
        if let Ok(attempt) = begin_endpoint(context, protocol, address) {
            addresses.push(address);
            attempts.push(attempt);
        }
    }
    anyhow::ensure!(
        !addresses.is_empty(),
        "transport candidates are active or in cold retry"
    );
    Ok((addresses, attempts))
}

pub(super) struct RetryingConnector {
    pub inner: Box<dyn TunnelConnector>,
    pub retries: Arc<TransportRetries>,
    pub address: SocketAddr,
    pub pin: Option<String>,
    pub identity: url::Url,
}

#[async_trait::async_trait]
impl TunnelConnector for RetryingConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let attempt = self.retries.begin_url(&self.identity, self.address)?;
        let inner = self.inner.connect().await?;
        Ok(retain_with_pin(inner, vec![attempt], self.pin.clone()))
    }
    fn remote_url(&self) -> url::Url {
        self.inner.remote_url()
    }
    fn set_bind_addrs(&mut self, addresses: Vec<SocketAddr>) {
        self.inner.set_bind_addrs(addresses);
    }
    fn set_ip_version(&mut self, version: crate::tunnel::IpVersion) {
        self.inner.set_ip_version(version);
    }
    fn set_resolved_addr(&mut self, address: SocketAddr) {
        self.address = address;
        self.inner.set_resolved_addr(address);
    }
    fn set_underlay_policy(&mut self, policy: Arc<crate::common::underlay_policy::UnderlayPolicy>) {
        self.inner.set_underlay_policy(policy);
    }
    fn set_socket_mark(&mut self, mark: Option<u32>) {
        self.inner.set_socket_mark(mark);
    }
    fn set_pinned_peer_key(&mut self, key: Option<String>) {
        self.pin = key;
    }
}

struct RetryingTunnel {
    inner: Box<dyn Tunnel>,
    // Retain admission through Noise authentication and the established connection lifetime.
    _attempts: Vec<Attempt>,
    path: Option<Arc<TunnelPathState>>,
    pin: Option<String>,
}

impl Tunnel for RetryingTunnel {
    fn split(&self) -> SplitTunnel {
        self.inner.split()
    }
    fn info(&self) -> Option<TunnelInfo> {
        self.inner.info()
    }
    fn path_state(&self) -> Option<Arc<TunnelPathState>> {
        self.path.clone()
    }
    fn transport_binding(&self) -> Option<TransportBinding> {
        self.inner.transport_binding()
    }
    fn is_transport_authenticated(&self) -> bool {
        self.inner.is_transport_authenticated()
    }
    fn probe_guard(&self) -> Option<Arc<crate::tunnel::ProbeGuard>> {
        self.inner.probe_guard()
    }
    fn pinned_peer_key(&self) -> Option<&str> {
        self.pin.as_deref().or_else(|| self.inner.pinned_peer_key())
    }
    fn tcp_proxy(&self) -> Option<Arc<crate::tunnel::quic::proxy::ProxyEndpoint>> {
        self.inner.tcp_proxy()
    }
    fn receive_backpressure(&self) -> Option<ReceiveBackpressure> {
        self.inner.receive_backpressure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AddressedTunnel {
        inner: Box<dyn Tunnel>,
        remote: SocketAddr,
    }
    impl Tunnel for AddressedTunnel {
        fn split(&self) -> SplitTunnel {
            self.inner.split()
        }
        fn info(&self) -> Option<TunnelInfo> {
            let mut info = self.inner.info()?;
            let remote = url::Url::parse(&format!("h2://{}", self.remote)).unwrap();
            info.remote_addr = Some(remote.clone().into());
            info.resolved_remote_addr = Some(remote.into());
            Some(info)
        }
    }

    #[test]
    fn endpoint_cooldown_is_shared_bounded_and_protocol_specific() {
        let retries = Arc::new(TransportRetries::default());
        let address = "127.0.0.1:11012".parse().unwrap();
        let attempt = retries.begin("quic", address).unwrap();
        assert!(retries.begin("quic", address).is_err());
        assert!(retries.begin("wss", address).is_ok());
        drop(attempt);
        let deadline = retries.endpoints.lock()[&("quic".into(), address, String::new())].unwrap();
        assert!(deadline.duration_since(Instant::now()).as_secs() >= 599);
        assert!(retries.begin("quic", address).is_err());
        retries.endpoints.lock().insert(
            ("quic".into(), address, String::new()),
            Some(Instant::now()),
        );
        assert!(retries.begin("quic", address).is_ok());
        let live = retries.begin("h2", address).unwrap();
        live._lease.paths.lock().push(Arc::new(TunnelPathState {
            peer_authenticated: std::sync::atomic::AtomicBool::new(true),
            info: parking_lot::RwLock::new(TunnelInfo::default()),
        }));
        drop(live);
        assert!(retries.begin("h2", address).is_ok());
        let full = Arc::new(TransportRetries::default());
        let active = (1..=1024)
            .map(|port| {
                full.begin("h2", SocketAddr::new(address.ip(), port))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            full.begin("h2", "127.0.0.1:65535".parse().unwrap())
                .is_err()
        );
        drop(active);
        let logical = Arc::new(TransportRetries::default());
        let first = logical
            .begin_url(&"wss://first.test/one".parse().unwrap(), address)
            .unwrap();
        let second = logical
            .begin_url(&"wss://second.test/two".parse().unwrap(), address)
            .unwrap();
        first.authenticated();
        drop(first);
        assert!(
            logical
                .begin_url(&"wss://first.test/one".parse().unwrap(), address)
                .is_ok()
        );
        drop(second);
        assert!(
            logical
                .begin_url(&"wss://second.test/two".parse().unwrap(), address)
                .is_err()
        );
        for (left, right) in [
            ("wss://first.test/node", "wss://first.test/node/"),
            ("wss://first.test/?a=b%3Fc%3Dd", "wss://first.test/?a=b&c=d"),
        ] {
            let left = logical.begin_url(&left.parse().unwrap(), address).unwrap();
            let right = logical.begin_url(&right.parse().unwrap(), address).unwrap();
            drop((left, right));
        }
        let candidates = Arc::new(TransportRetries::default());
        let other: SocketAddr = "127.0.0.1:11013".parse().unwrap();
        let attempts = vec![
            candidates.begin("h2", address).unwrap(),
            candidates.begin("h2", other).unwrap(),
        ];
        let (inner, _remote) = crate::tunnel::ring::create_ring_tunnel_pair();
        let tunnel = retain_attempts(
            Box::new(AddressedTunnel {
                inner,
                remote: address,
            }),
            attempts,
        );
        tunnel
            .path_state()
            .unwrap()
            .peer_authenticated
            .store(true, std::sync::atomic::Ordering::Release);
        drop(tunnel);
        assert!(candidates.begin("h2", address).is_ok());
        assert!(candidates.begin("h2", other).is_err());
    }
}
