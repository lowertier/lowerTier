//! Shared NAT-traversal policy and rendezvous invariants.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use rand::seq::SliceRandom;

use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx},
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{PeerIdentityType, SecureAuthLevel},
        rpc_types::controller::BaseController,
    },
    tunnel::common::ensure_remote_allowed,
};

use super::{should_background_p2p_with_peer, should_try_p2p_with_peer};

pub(super) const MAX_CANDIDATES: usize = 4;
pub(super) const EXPANDED_SOCKET_LIMIT: usize = 128;
pub(super) const PORT_SEARCH_LIMIT: usize = 4096;
pub(super) const EXPANDED_TRAVERSAL_TIMEOUT: Duration = Duration::from_secs(28);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Strategy {
    Candidates,
    SocketPool,
    PortSearch,
}

pub(super) fn strategy(local_varies: bool, remote_varies: bool) -> Strategy {
    match (local_varies, remote_varies) {
        (true, false) => Strategy::SocketPool,
        (false, true) => Strategy::PortSearch,
        _ => Strategy::Candidates,
    }
}

// Enumerate diagonals so unequal interface counts cannot omit crossed pairs.
pub(super) fn source_pair(attempt: u32) -> (u32, u32) {
    let diagonal = ((8 * u64::from(attempt) + 1).isqrt() - 1) / 2;
    let local = u64::from(attempt) - diagonal * (diagonal + 1) / 2;
    (local as u32, (diagonal - local) as u32)
}

pub(super) fn public_candidates(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    candidates
        .iter()
        .copied()
        .filter(|address| address.is_ipv4() && public_candidate(*address))
        .collect()
}

pub(super) fn public_candidate(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && octets[0] != 0
                && octets[0] < 240
                && !(octets[0] == 100 && (64..128).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_candidate(SocketAddr::new(ip.into(), address.port()));
            }
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}

pub(super) fn expanded_candidates(
    ctx: &ArcGlobalCtx,
    candidates: &[SocketAddr],
    protocol: &'static str,
) -> Result<Vec<SocketAddr>> {
    ensure!(
        !ctx.get_flags().disable_sym_hole_punching,
        "symmetric NAT traversal is disabled"
    );
    let candidates = public_candidates(candidates);
    ensure!(
        !candidates.is_empty(),
        "{protocol} hard NAT traversal has no public candidate"
    );
    Ok(candidates)
}

pub(super) fn random_search_ports() -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut ports: Vec<u16> =
        rand::seq::index::sample(&mut rng, u16::MAX as usize, PORT_SEARCH_LIMIT)
            .into_iter()
            .map(|index| (index + 1) as u16)
            .collect();
    ports.shuffle(&mut rng);
    ports
}

pub(super) fn authenticate_rendezvous_peer(
    ctrl: &BaseController,
    protocol: &'static str,
) -> Result<PeerId> {
    ensure!(
        matches!(
            ctrl.authenticated_peer_identity_type,
            Some(PeerIdentityType::Admin | PeerIdentityType::Credential)
        ) && matches!(
            ctrl.authenticated_peer_secure_auth_level,
            Some(SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed)
        ),
        "{protocol} rendezvous requires an authenticated network peer"
    );
    ctrl.authenticated_peer_id
        .with_context(|| format!("{protocol} rendezvous has no authenticated peer"))
}

pub(super) fn validate_ipv4_candidates(
    ctx: &ArcGlobalCtx,
    candidates: &[crate::proto::common::SocketAddr],
    protocol: &'static str,
) -> Result<Vec<SocketAddr>> {
    ensure!(
        !candidates.is_empty() && candidates.len() <= MAX_CANDIDATES,
        "invalid {protocol} candidate count"
    );
    let mut result = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        ensure!(
            candidate.ip.is_some() && candidate.port > 0 && candidate.port <= u16::MAX as u32,
            "invalid {protocol} candidate"
        );
        let address: SocketAddr = candidate.clone().into();
        ensure!(
            address.is_ipv4()
                && !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && address.ip() != std::net::Ipv4Addr::BROADCAST,
            "invalid {protocol} destination"
        );
        ensure_remote_allowed(&ctx.get_underlay_policy(), address)?;
        if !result.contains(&address) {
            result.push(address);
        }
    }
    Ok(result)
}

pub(super) async fn hole_punch_peers(peer_mgr: &PeerManager) -> Vec<PeerId> {
    let flags = peer_mgr.get_global_ctx().get_flags();
    let my_peer_id = peer_mgr.my_peer_id();
    let now = quanta::Instant::now();
    peer_mgr
        .list_routes()
        .await
        .into_iter()
        .filter(|route| {
            // One stable initiator role prevents duplicate rendezvous sessions.
            route.peer_id > my_peer_id
                && !peer_mgr.has_live_peer_connection(route.peer_id)
                && (should_background_p2p_with_peer(
                    route.feature_flag.as_ref(),
                    false,
                    flags.lazy_p2p,
                    flags.disable_p2p,
                    flags.need_p2p,
                ) || (should_try_p2p_with_peer(
                    route.feature_flag.as_ref(),
                    false,
                    flags.disable_p2p,
                    flags.need_p2p,
                ) && peer_mgr.has_recent_traffic(route.peer_id, now)))
        })
        .map(|route| route.peer_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_matrix_is_shared_across_transports() {
        assert_eq!(strategy(true, false), Strategy::SocketPool);
        assert_eq!(strategy(false, true), Strategy::PortSearch);
        assert_eq!(strategy(true, true), Strategy::Candidates);
        assert_eq!(strategy(false, false), Strategy::Candidates);
    }

    #[test]
    fn source_schedule_covers_crossed_and_unequal_interface_pairs() {
        for (local_count, remote_count) in [(2, 2), (2, 3), (3, 1)] {
            let observed: std::collections::HashSet<_> = (0..16)
                .map(|attempt| {
                    let (local, remote) = source_pair(attempt);
                    (local % local_count, remote % remote_count)
                })
                .collect();
            for local in 0..local_count {
                for remote in 0..remote_count {
                    assert!(observed.contains(&(local, remote)));
                }
            }
        }
    }

    #[test]
    fn hard_search_uses_only_public_ipv4_candidates() {
        let candidates: Vec<SocketAddr> = [
            "127.0.0.1:1",
            "192.168.0.1:1",
            "100.64.0.1:1",
            "169.254.1.1:1",
            "224.0.0.1:1",
            "255.255.255.255:1",
            "0.1.2.3:1",
            "8.8.8.8:1",
        ]
        .into_iter()
        .map(|value| value.parse().unwrap())
        .collect();
        assert_eq!(
            public_candidates(&candidates),
            vec!["8.8.8.8:1".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn port_search_sampling_is_bounded_unique_and_nonzero() {
        let ports = random_search_ports();
        assert_eq!(ports.len(), PORT_SEARCH_LIMIT);
        assert!(ports.iter().all(|port| *port != 0));
        assert_eq!(
            ports
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            PORT_SEARCH_LIMIT
        );
    }
}
