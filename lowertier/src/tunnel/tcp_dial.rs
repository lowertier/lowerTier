//! Shared outbound TCP setup for H2 and WSS.
//!
//! Address policy applies before socket creation and after connection.
//! Each attempt from a source address includes its transport handshake.
//! The first complete transport wins. Failed attempts do not cancel the other attempts.
//! Multiple lanes repeat the same procedure and retain their authenticated lane binding.

use std::{future::Future, net::SocketAddr, sync::Arc};

use futures::stream::FuturesUnordered;
use tokio::net::{TcpSocket, TcpStream};

use crate::common::underlay_policy::UnderlayPolicy;

use super::{
    FromUrl, IpVersion, Tunnel, TunnelError,
    common::{
        apply_socket_mark, bind, eligible_bind_addrs, ensure_local_allowed, ensure_remote_allowed,
        size_tcp_socket_buffers, wait_for_connect_futures,
    },
};

/// Socket selection and policy shared by both TCP transports.
///
/// An explicit resolved address avoids a second DNS lookup.
/// Empty source addresses let the operating system select the source.
/// Explicit sources race independently after the policy filters them.
#[derive(Debug)]
pub(super) struct TcpDialer {
    pub bind_addrs: Vec<SocketAddr>,
    pub ip_version: IpVersion,
    pub resolved_addr: Option<SocketAddr>,
    pub socket_mark: Option<u32>,
    pub underlay_policy: Arc<UnderlayPolicy>,
}

impl Default for TcpDialer {
    fn default() -> Self {
        Self {
            bind_addrs: Vec::new(),
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
            underlay_policy: Arc::new(UnderlayPolicy::default()),
        }
    }
}

impl TcpDialer {
    /// Connect one transport, or its requested set of authenticated lanes.
    ///
    /// A pinned address takes precedence over DNS. Policy rejection stops before dialing.
    /// A single lane returns the first complete handshake.
    /// Multiple lanes use the same dial procedure and the existing lane admission limits.
    pub async fn connect<F, Fut>(
        &self,
        url: &url::Url,
        handshake: F,
    ) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        F: Fn(TcpStream) -> Fut + Sync,
        Fut: Future<Output = Result<Box<dyn Tunnel>, TunnelError>> + Send,
    {
        let remote = match self.resolved_addr {
            Some(remote) => remote,
            None => SocketAddr::from_url(url.clone(), self.ip_version).await?,
        };
        ensure_remote_allowed(&self.underlay_policy, remote)?;
        let sources = eligible_bind_addrs(&self.underlay_policy, &self.bind_addrs, remote)?;
        let connect_lane = || async {
            if sources.is_empty() {
                return self.connect_from(remote, None, &handshake).await;
            }
            let attempts = FuturesUnordered::new();
            for source in &sources {
                attempts.push(self.connect_from(remote, Some(*source), &handshake));
            }
            wait_for_connect_futures(attempts).await
        };
        let lanes = super::tcp_lanes::requested(url)?;
        if lanes > 1 {
            super::tcp_lanes::connect(lanes, connect_lane).await
        } else {
            connect_lane().await
        }
    }

    /// Apply socket settings and policy before handing the stream to its transport.
    ///
    /// Explicit sources use a bound socket. Automatic sources select the remote address family.
    /// The handshake runs only after the connected local and remote addresses pass policy.
    async fn connect_from<F, Fut>(
        &self,
        remote: SocketAddr,
        source: Option<SocketAddr>,
        handshake: &F,
    ) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        F: Fn(TcpStream) -> Fut + Sync,
        Fut: Future<Output = Result<Box<dyn Tunnel>, TunnelError>> + Send,
    {
        let socket = match source {
            Some(source) => bind::<TcpSocket>()
                .addr(source)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()?,
            None => {
                let socket = if remote.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                apply_socket_mark(&socket2::SockRef::from(&socket), self.socket_mark)?;
                socket
            }
        };
        size_tcp_socket_buffers(&socket2::SockRef::from(&socket));
        let stream = socket.connect(remote).await?;
        ensure_local_allowed(&self.underlay_policy, stream.local_addr()?)?;
        ensure_remote_allowed(&self.underlay_policy, stream.peer_addr()?)?;
        handshake(stream).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use super::*;

    #[tokio::test]
    async fn failed_handshake_keeps_other_sources_active() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let explicit_source = source.local_addr().unwrap();
        drop(source);
        let dialer = TcpDialer {
            bind_addrs: vec!["127.0.0.1:0".parse().unwrap(), explicit_source],
            resolved_addr: Some(listener.local_addr().unwrap()),
            ..Default::default()
        };
        let attempts = AtomicUsize::new(0);
        let tunnel = tokio::time::timeout(
            Duration::from_secs(3),
            dialer.connect(&"h2://unresolved.invalid".parse().unwrap(), |_stream| {
                let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if first {
                        return Err(std::io::Error::other("source handshake rejected").into());
                    }
                    Ok(crate::tunnel::ring::create_ring_tunnel_pair().0)
                }
            }),
        )
        .await
        .unwrap();
        assert!(tunnel.is_ok(), "{tunnel:?}");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
