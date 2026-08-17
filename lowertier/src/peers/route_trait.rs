use arc_swap::ArcSwapOption;
use cidr::Ipv6Inet;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use prefix_trie::PrefixMap;
use quanta::Instant;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};

use crate::{
    common::{PeerId, global_ctx::NetworkIdentity},
    proto::{
        api::instance::ListPublicIpv6InfoResponse,
        common::PeerFeatureFlag,
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdentityType,
            RouteForeignNetworkInfos, RouteForeignNetworkSummary, RoutePeerInfo, SecureAuthLevel,
        },
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedRoutePeerEvidence {
    pub peer_id: PeerId,
    pub identity_type: PeerIdentityType,
    pub noise_static_pubkey: Vec<u8>,
    pub secure_auth_level: SecureAuthLevel,
}

impl AuthenticatedRoutePeerEvidence {
    /// Validate one local authentication tuple for the requested peer.
    ///
    /// Route topology data cannot satisfy this check. The static key must be
    /// one complete Noise public key, and the role must match its auth level.
    pub fn validate_for(&self, expected_peer_id: PeerId) -> bool {
        self.peer_id == expected_peer_id
            && self.noise_static_pubkey.len() == 32
            && Self::is_allowed_role_auth_pair(self.identity_type, self.secure_auth_level)
    }

    pub fn is_allowed_role_auth_pair(
        identity_type: PeerIdentityType,
        secure_auth_level: SecureAuthLevel,
    ) -> bool {
        match identity_type {
            PeerIdentityType::Admin => matches!(
                secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            ),
            PeerIdentityType::Credential => {
                matches!(secure_auth_level, SecureAuthLevel::PeerVerified)
            }
            PeerIdentityType::SharedNode => matches!(
                secure_auth_level,
                SecureAuthLevel::EncryptedUnauthenticated | SecureAuthLevel::PeerVerified
            ),
            PeerIdentityType::ForeignRelay => matches!(
                secure_auth_level,
                SecureAuthLevel::EncryptedUnauthenticated | SecureAuthLevel::PeerVerified
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeRoutePeerEvidence {
    pub peer_id: PeerId,
    pub noise_static_pubkey: Vec<u8>,
    /// None means direct authenticated authority. Some means an attestation deadline.
    pub deadline: Option<Instant>,
    pub generation: u64,
}

/// One route-generation authority update.
///
/// The callback publishes the complete route-origin set in one operation.
/// Missing route-origin entries revoke previous route authority.
#[derive(Clone, Debug, Default)]
pub struct OriginAuthPublication {
    pub peer_id: PeerId,
    pub generic: Option<AuthenticatedRoutePeerEvidence>,
    pub bridge: Option<BridgeRoutePeerEvidence>,
    pub foreign_owner: Option<([u8; 32], u64)>,
}

impl BridgeRoutePeerEvidence {
    pub fn validate_for(&self, expected_peer_id: PeerId, now: Instant) -> bool {
        self.peer_id == expected_peer_id
            && self.noise_static_pubkey.len() == 32
            && self.deadline.is_none_or(|deadline| deadline > now)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ForwardingPeerInfo {
    pub peer_id: PeerId,
    pub has_ipv4: bool,
    pub feature_flag: Option<PeerFeatureFlag>,
    pub multicast_groups: Vec<Vec<u8>>,
    /// Set only from authenticated route identity, never from a peer claim.
    pub bridge_authorized: bool,
    /// None means direct authenticated authority. Some means a verified deadline.
    pub bridge_authorization_deadline: Option<Instant>,
}

#[derive(Clone, Debug, Default)]
pub struct ForwardingPeerTable {
    peers: Vec<ForwardingPeerInfo>,
    peer_indexes: HashMap<PeerId, usize>,
    ipv4_peers: Vec<PeerId>,
    ethernet_peers: Vec<PeerId>,
    multicast_peers: HashMap<IpAddr, Vec<PeerId>>,
    ethernet_multicast_peers: HashMap<IpAddr, Vec<PeerId>>,
}

impl ForwardingPeerTable {
    pub fn new(mut peers: Vec<ForwardingPeerInfo>) -> Self {
        peers.sort_unstable_by_key(|peer| peer.peer_id);
        peers.dedup_by_key(|peer| peer.peer_id);
        let peer_indexes = peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (peer.peer_id, index))
            .collect();
        let ethernet_peers = peers
            .iter()
            .filter_map(|peer| {
                peer.feature_flag
                    .as_ref()
                    .is_some_and(|features| {
                        features.ethernet_input
                            && features.hybrid_l3
                            && features.bridge_input
                            && peer.bridge_authorized
                    })
                    .then_some(peer.peer_id)
            })
            .collect::<Vec<_>>();
        let ipv4_peers = peers
            .iter()
            .filter_map(|peer| peer.has_ipv4.then_some(peer.peer_id))
            .collect();
        let ethernet_peer_set = ethernet_peers.iter().copied().collect::<BTreeSet<_>>();
        let mut multicast_peers: HashMap<IpAddr, Vec<PeerId>> = HashMap::new();
        let mut ethernet_multicast_peers: HashMap<IpAddr, Vec<PeerId>> = HashMap::new();
        for peer in &peers {
            let supports_membership = peer
                .feature_flag
                .as_ref()
                .is_some_and(|features| features.hybrid_l3 && features.multicast_membership);
            if !supports_membership {
                continue;
            }
            for group in &peer.multicast_groups {
                let address = match group.as_slice() {
                    [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
                    bytes if bytes.len() == 16 => <[u8; 16]>::try_from(bytes)
                        .ok()
                        .map(Ipv6Addr::from)
                        .map(IpAddr::V6),
                    _ => None,
                };
                let Some(address) = address.filter(|address| address.is_multicast()) else {
                    continue;
                };
                multicast_peers
                    .entry(address)
                    .or_default()
                    .push(peer.peer_id);
                if ethernet_peer_set.contains(&peer.peer_id) {
                    ethernet_multicast_peers
                        .entry(address)
                        .or_default()
                        .push(peer.peer_id);
                }
            }
        }
        Self {
            peers,
            peer_indexes,
            ipv4_peers,
            ethernet_peers,
            multicast_peers,
            ethernet_multicast_peers,
        }
    }

    pub fn get(&self, peer_id: PeerId) -> Option<&ForwardingPeerInfo> {
        self.peer_indexes
            .get(&peer_id)
            .and_then(|index| self.peers.get(*index))
    }

    /// Return true only for an authenticated Admin bridge with hybrid Ethernet capability.
    pub fn is_authorized_bridge(&self, peer_id: PeerId) -> bool {
        let now = Instant::now();
        self.get(peer_id).is_some_and(|peer| {
            peer.bridge_authorized
                && peer
                    .bridge_authorization_deadline
                    .is_none_or(|deadline| deadline > now)
                && peer.feature_flag.as_ref().is_some_and(|features| {
                    features.ethernet_input && features.hybrid_l3 && features.bridge_input
                })
        })
    }

    pub fn ethernet_peers(&self) -> Vec<PeerId> {
        let now = Instant::now();
        self.ethernet_peers
            .iter()
            .copied()
            .filter(|peer_id| {
                self.get(*peer_id).is_some_and(|peer| {
                    peer.bridge_authorized
                        && peer
                            .bridge_authorization_deadline
                            .is_none_or(|deadline| deadline > now)
                })
            })
            .collect()
    }

    pub fn ipv4_peers(&self) -> &[PeerId] {
        &self.ipv4_peers
    }

    pub fn multicast_peers(&self, address: IpAddr) -> &[PeerId] {
        self.multicast_peers
            .get(&address)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn ethernet_multicast_peers(&self, address: IpAddr) -> Vec<PeerId> {
        let now = Instant::now();
        self.ethernet_multicast_peers
            .get(&address)
            .into_iter()
            .flatten()
            .copied()
            .filter(|peer_id| {
                self.get(*peer_id).is_some_and(|peer| {
                    peer.bridge_authorized
                        && peer
                            .bridge_authorization_deadline
                            .is_none_or(|deadline| deadline > now)
                })
            })
            .collect()
    }
}

impl std::ops::Deref for ForwardingPeerTable {
    type Target = [ForwardingPeerInfo];

    fn deref(&self) -> &Self::Target {
        &self.peers
    }
}

impl<'a> IntoIterator for &'a ForwardingPeerTable {
    type Item = &'a ForwardingPeerInfo;
    type IntoIter = std::slice::Iter<'a, ForwardingPeerInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers.iter()
    }
}

pub type ForwardingPeerSnapshot = Arc<ForwardingPeerTable>;

/// Immutable forwarding decision data captured from one published route generation.
#[derive(Clone, Debug)]
pub struct ForwardingDecisionSnapshot {
    generation: u64,
    capabilities: ForwardingPeerSnapshot,
    suppressed_peer_ids: Arc<HashSet<PeerId>>,
    public_ipv6_gateway_peer_id: Option<PeerId>,
    least_hop: Arc<HashMap<PeerId, ForwardingNextHop>>,
    least_cost: Arc<HashMap<PeerId, ForwardingNextHop>>,
    max_goodput: Arc<HashMap<PeerId, ForwardingNextHop>>,
    ipv4_peer_ids: Arc<HashMap<Ipv4Addr, PeerId>>,
    ipv6_peer_ids: Arc<HashMap<Ipv6Addr, PeerId>>,
    proxy_ipv4: Arc<PrefixMap<Ipv4Cidr, PeerId>>,
    proxy_ipv6: Arc<PrefixMap<Ipv6Cidr, PeerId>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForwardingNextHop {
    pub next_hop_peer_id: PeerId,
    pub path_delivery_bps: u64,
    pub path_latency: i32,
    pub path_len: usize,
    pub version: u32,
}

impl ForwardingDecisionSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        generation: u64,
        capabilities: ForwardingPeerSnapshot,
        suppressed_peer_ids: Arc<HashSet<PeerId>>,
        public_ipv6_gateway_peer_id: Option<PeerId>,
        least_hop: Arc<HashMap<PeerId, ForwardingNextHop>>,
        least_cost: Arc<HashMap<PeerId, ForwardingNextHop>>,
        max_goodput: Arc<HashMap<PeerId, ForwardingNextHop>>,
        ipv4_peer_ids: Arc<HashMap<Ipv4Addr, PeerId>>,
        ipv6_peer_ids: Arc<HashMap<Ipv6Addr, PeerId>>,
        proxy_ipv4: Arc<PrefixMap<Ipv4Cidr, PeerId>>,
        proxy_ipv6: Arc<PrefixMap<Ipv6Cidr, PeerId>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            generation,
            capabilities,
            suppressed_peer_ids,
            public_ipv6_gateway_peer_id,
            least_hop,
            least_cost,
            max_goodput,
            ipv4_peer_ids,
            ipv6_peer_ids,
            proxy_ipv4,
            proxy_ipv6,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn capabilities(&self) -> &ForwardingPeerTable {
        &self.capabilities
    }

    /// Return true only for a route peer that the authenticated route marked as an Admin bridge.
    pub fn is_authorized_bridge(&self, peer_id: PeerId) -> bool {
        self.capabilities.is_authorized_bridge(peer_id)
    }

    pub fn public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        self.public_ipv6_gateway_peer_id
    }

    pub fn next_hop(&self, peer_id: PeerId, policy: NextHopPolicy) -> Option<ForwardingNextHop> {
        if self.suppressed_peer_ids.contains(&peer_id) {
            return None;
        }
        match policy {
            NextHopPolicy::MaxGoodput => self
                .max_goodput
                .get(&peer_id)
                .copied()
                .or_else(|| self.least_cost.get(&peer_id).copied())
                .or_else(|| self.least_hop.get(&peer_id).copied()),
            NextHopPolicy::LeastCost => self
                .least_cost
                .get(&peer_id)
                .copied()
                .or_else(|| self.least_hop.get(&peer_id).copied()),
            NextHopPolicy::LeastHop => self.least_hop.get(&peer_id).copied(),
        }
    }

    pub fn peer_id_by_ipv4(&self, address: &Ipv4Addr) -> Option<PeerId> {
        self.ipv4_peer_ids.get(address).copied()
    }

    pub fn peer_id_by_ipv6(&self, address: &Ipv6Addr) -> Option<PeerId> {
        self.ipv6_peer_ids.get(address).copied()
    }

    pub fn peer_id_by_ip(&self, address: &IpAddr) -> Option<PeerId> {
        match address {
            IpAddr::V4(address) => self.peer_id_by_ipv4(address),
            IpAddr::V6(address) => self.peer_id_by_ipv6(address),
        }
    }

    pub fn proxy_peer_id_by_ip(&self, address: &IpAddr) -> Option<PeerId> {
        match address {
            IpAddr::V4(address) => self
                .proxy_ipv4
                .get_lpm(&Ipv4Cidr::new(*address, 32).ok()?)
                .map(|entry| *entry.1),
            IpAddr::V6(address) => self
                .proxy_ipv6
                .get_lpm(&Ipv6Cidr::new(*address, 128).ok()?)
                .map(|entry| *entry.1),
        }
    }

    pub(crate) fn next_hop_map_arc(
        &self,
        policy: NextHopPolicy,
    ) -> &Arc<HashMap<PeerId, ForwardingNextHop>> {
        match policy {
            NextHopPolicy::LeastHop => &self.least_hop,
            NextHopPolicy::LeastCost => &self.least_cost,
            NextHopPolicy::MaxGoodput => &self.max_goodput,
        }
    }
}

pub type ForwardingDecisionSnapshotHandle = Arc<ForwardingDecisionSnapshot>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ForwardingSnapshotSourceToken(u64);

impl ForwardingSnapshotSourceToken {
    pub fn is_nonzero(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone)]
struct ForwardingSnapshotPublication {
    source_token: ForwardingSnapshotSourceToken,
    generation: u64,
    snapshot: ForwardingDecisionSnapshotHandle,
}

#[derive(Default)]
struct ForwardingSnapshotSourceState {
    active_source_token: ForwardingSnapshotSourceToken,
    pending_snapshots:
        HashMap<ForwardingSnapshotSourceToken, Option<Arc<ForwardingSnapshotPublication>>>,
    transitioning_source: Option<ForwardingSnapshotSourceToken>,
}

/// Shared immutable snapshot registry for packet-forwarding readers.
///
/// Readers load the immutable pointer without a lock.
/// Committing a source registration invalidates snapshots from the previous route owner.
pub struct ForwardingDecisionSnapshotStoreInner {
    snapshots: ArcSwapOption<ForwardingSnapshotPublication>,
    next_source_token: AtomicU64,
    source_state: Mutex<ForwardingSnapshotSourceState>,
    transition_lock: Mutex<()>,
    publish_hook: Mutex<Option<Arc<dyn ForwardingSnapshotPublishHook>>>,
}

/// Bridges forwarding source state to one owner of the dataplane descriptor.
///
/// The source store calls this hook only after it validates source ownership.
/// A pending source remains invisible until `activate` is true.
pub trait ForwardingSnapshotPublishHook: Send + Sync {
    fn publish_forwarding_snapshot(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        snapshot: ForwardingDecisionSnapshotHandle,
        activate: bool,
    ) -> bool;
    fn revoke_forwarding_snapshot(&self, source_token: ForwardingSnapshotSourceToken);
    fn discard_forwarding_snapshot(&self, source_token: ForwardingSnapshotSourceToken);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardingSnapshotCommitError {
    MissingPendingSource,
    PublicationRejected,
    SourceTokenExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardingSnapshotPublishError {
    SourceNotRegistered,
    StaleGeneration,
    PublicationRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOriginAuthPublishError {
    SourceNotRegistered,
    StaleGeneration,
    InvalidPublication,
    AuthGenerationExhausted,
    PublicationRejected,
}

impl ForwardingDecisionSnapshotStoreInner {
    pub fn new() -> Self {
        Self {
            snapshots: ArcSwapOption::empty(),
            next_source_token: AtomicU64::new(0),
            source_state: Mutex::new(ForwardingSnapshotSourceState::default()),
            transition_lock: Mutex::new(()),
            publish_hook: Mutex::new(None),
        }
    }

    pub fn set_publish_hook(&self, hook: Arc<dyn ForwardingSnapshotPublishHook>) {
        *self.publish_hook.lock().unwrap() = Some(hook);
    }

    pub fn load_full(&self) -> Option<ForwardingDecisionSnapshotHandle> {
        self.snapshots
            .load_full()
            .map(|publication| publication.snapshot.clone())
    }

    pub fn accepts_source_generation(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        generation: u64,
    ) -> bool {
        if source_token.0 == 0 {
            return false;
        }
        let state = self.source_state.lock().unwrap();
        if state.active_source_token != source_token
            && !state.pending_snapshots.contains_key(&source_token)
        {
            return false;
        }
        if state.transitioning_source == Some(source_token) {
            return false;
        }
        if state
            .pending_snapshots
            .get(&source_token)
            .and_then(|pending| pending.as_ref())
            .is_some_and(|pending| pending.generation >= generation)
        {
            return false;
        }
        self.snapshots.load().as_ref().is_none_or(|current| {
            current.source_token != source_token || current.generation < generation
        })
    }

    /// Make this route the active publisher.
    pub fn register_source(
        self: &Arc<Self>,
    ) -> Result<ForwardingDecisionSnapshotSource, ForwardingSnapshotCommitError> {
        let mut registration = self.begin_source_registration()?;
        let source = registration.source();
        let _transition_guard = self.transition_lock.lock().unwrap();
        let previous_source = {
            let mut state = self.source_state.lock().unwrap();
            state.pending_snapshots.remove(&source.source_token);
            let previous_source = state.active_source_token;
            state.transitioning_source = Some(source.source_token);
            previous_source
        };
        if previous_source.0 != 0
            && let Some(hook) = self.publish_hook.lock().unwrap().clone()
        {
            hook.revoke_forwarding_snapshot(previous_source);
        }
        let mut state = self.source_state.lock().unwrap();
        state.active_source_token = source.source_token;
        state.transitioning_source = None;
        self.snapshots.store(None);
        registration.committed = true;
        Ok(source)
    }

    /// Stage a source registration without changing the active snapshot.
    pub fn begin_source_registration(
        self: &Arc<Self>,
    ) -> Result<ForwardingSnapshotRegistration, ForwardingSnapshotCommitError> {
        let previous = self
            .next_source_token
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ForwardingSnapshotCommitError::SourceTokenExhausted)?;
        let source_token = ForwardingSnapshotSourceToken(
            previous
                .checked_add(1)
                .ok_or(ForwardingSnapshotCommitError::SourceTokenExhausted)?,
        );
        self.source_state
            .lock()
            .unwrap()
            .pending_snapshots
            .insert(source_token, None);
        Ok(ForwardingSnapshotRegistration {
            source: ForwardingDecisionSnapshotSource {
                store: self.clone(),
                source_token,
            },
            committed: false,
        })
    }

    /// Publish a snapshot for an active source or stage it for a pending source.
    fn store_if_newer(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        snapshot: ForwardingDecisionSnapshotHandle,
    ) -> Result<(), ForwardingSnapshotPublishError> {
        if source_token.0 == 0 {
            return Err(ForwardingSnapshotPublishError::SourceNotRegistered);
        }
        let generation = snapshot.generation();
        let snapshot_for_hook = snapshot.clone();
        let publication = Arc::new(ForwardingSnapshotPublication {
            source_token,
            generation,
            snapshot,
        });
        let (is_active, hook) = {
            let source_state = self.source_state.lock().unwrap();
            if source_state.transitioning_source == Some(source_token) {
                return Err(ForwardingSnapshotPublishError::PublicationRejected);
            }
            let is_active = source_state.active_source_token == source_token;
            if !is_active && !source_state.pending_snapshots.contains_key(&source_token) {
                return Err(ForwardingSnapshotPublishError::SourceNotRegistered);
            }
            if is_active
                && self.snapshots.load().as_ref().is_some_and(|current| {
                    current.source_token == source_token && current.generation >= generation
                })
            {
                return Err(ForwardingSnapshotPublishError::StaleGeneration);
            }
            if !is_active
                && source_state
                    .pending_snapshots
                    .get(&source_token)
                    .and_then(|pending| pending.as_ref())
                    .is_some_and(|current| current.generation >= generation)
            {
                return Err(ForwardingSnapshotPublishError::StaleGeneration);
            }
            (is_active, self.publish_hook.lock().unwrap().clone())
        };
        if is_active {
            let _transition_guard = self.transition_lock.lock().unwrap();
            let mut source_state = self.source_state.lock().unwrap();
            if source_state.active_source_token != source_token
                || source_state.transitioning_source.is_some()
            {
                return Err(ForwardingSnapshotPublishError::StaleGeneration);
            }
            source_state.transitioning_source = Some(source_token);
            drop(source_state);
            if let Some(hook) = hook
                && !hook.publish_forwarding_snapshot(source_token, snapshot_for_hook, true)
            {
                self.source_state.lock().unwrap().transitioning_source = None;
                return Err(ForwardingSnapshotPublishError::PublicationRejected);
            }
            let mut source_state = self.source_state.lock().unwrap();
            if source_state.active_source_token != source_token
                || self.snapshots.load().as_ref().is_some_and(|current| {
                    current.source_token == source_token && current.generation >= generation
                })
            {
                source_state.transitioning_source = None;
                return Err(ForwardingSnapshotPublishError::StaleGeneration);
            }
            self.snapshots.store(Some(publication));
            source_state.transitioning_source = None;
            return Ok(());
        }
        let mut source_state = self.source_state.lock().unwrap();
        let Some(pending) = source_state.pending_snapshots.get_mut(&source_token) else {
            return Err(ForwardingSnapshotPublishError::SourceNotRegistered);
        };
        if pending
            .as_ref()
            .is_some_and(|current| current.generation >= generation)
        {
            return Err(ForwardingSnapshotPublishError::StaleGeneration);
        }
        *pending = Some(publication.clone());
        drop(source_state);
        if let Some(hook) = hook
            && !hook.publish_forwarding_snapshot(source_token, snapshot_for_hook, false)
        {
            let mut source_state = self.source_state.lock().unwrap();
            if source_state
                .pending_snapshots
                .get(&source_token)
                .and_then(|pending| pending.as_ref())
                .is_some_and(|current| Arc::ptr_eq(current, &publication))
            {
                source_state.pending_snapshots.remove(&source_token);
            }
            return Err(ForwardingSnapshotPublishError::PublicationRejected);
        }
        Ok(())
    }

    fn commit_source(
        &self,
        source_token: ForwardingSnapshotSourceToken,
    ) -> Result<(), ForwardingSnapshotCommitError> {
        let _transition_guard = self.transition_lock.lock().unwrap();
        let snapshot = {
            let mut source_state = self.source_state.lock().unwrap();
            if source_state.transitioning_source.is_some() {
                return Err(ForwardingSnapshotCommitError::PublicationRejected);
            }
            let Some(snapshot) = source_state.pending_snapshots.get(&source_token).cloned() else {
                return Err(ForwardingSnapshotCommitError::MissingPendingSource);
            };
            source_state.transitioning_source = Some(source_token);
            snapshot
        };
        let Some(snapshot) = snapshot else {
            let mut source_state = self.source_state.lock().unwrap();
            source_state.transitioning_source = None;
            return Err(ForwardingSnapshotCommitError::MissingPendingSource);
        };
        let hook = self.publish_hook.lock().unwrap().clone();
        let hook_activated = hook.as_ref().is_none_or(|hook| {
            hook.publish_forwarding_snapshot(source_token, snapshot.snapshot.clone(), true)
        });
        if !hook_activated {
            self.source_state.lock().unwrap().transitioning_source = None;
            return Err(ForwardingSnapshotCommitError::PublicationRejected);
        }
        let mut source_state = self.source_state.lock().unwrap();
        let pending_matches = source_state
            .pending_snapshots
            .get(&source_token)
            .and_then(Option::as_ref)
            .is_some_and(|current| Arc::ptr_eq(current, &snapshot));
        assert!(
            pending_matches,
            "pending source changed while the source transition lock was held"
        );
        let current = source_state
            .pending_snapshots
            .get(&source_token)
            .and_then(Option::as_ref)
            .expect("pending source must survive the transition callback");
        debug_assert!(Arc::ptr_eq(current, &snapshot));
        let Some(snapshot) = source_state.pending_snapshots.remove(&source_token) else {
            source_state.transitioning_source = None;
            return Err(ForwardingSnapshotCommitError::MissingPendingSource);
        };
        source_state.active_source_token = source_token;
        self.snapshots.store(snapshot);
        source_state.transitioning_source = None;
        Ok(())
    }

    fn rollback_source(&self, source_token: ForwardingSnapshotSourceToken) {
        let _transition_guard = self.transition_lock.lock().unwrap();
        let mut source_state = self.source_state.lock().unwrap();
        source_state.pending_snapshots.remove(&source_token);
        source_state.transitioning_source = None;
        drop(source_state);
        if let Some(hook) = self.publish_hook.lock().unwrap().clone() {
            hook.discard_forwarding_snapshot(source_token);
        }
    }

    fn revoke_source(&self, source_token: ForwardingSnapshotSourceToken) {
        if source_token.0 == 0 {
            return;
        }
        let _transition_guard = self.transition_lock.lock().unwrap();
        let mut source_state = self.source_state.lock().unwrap();
        source_state.pending_snapshots.remove(&source_token);
        if source_state.active_source_token != source_token {
            return;
        }
        source_state.transitioning_source = Some(source_token);
        drop(source_state);
        let hook = self.publish_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook.revoke_forwarding_snapshot(source_token);
        }
        let mut source_state = self.source_state.lock().unwrap();
        if source_state.active_source_token != source_token {
            source_state.transitioning_source = None;
            return;
        }
        source_state.active_source_token = ForwardingSnapshotSourceToken(0);
        self.snapshots.store(None);
        source_state.transitioning_source = None;
    }
}

pub type ForwardingDecisionSnapshotStore = Arc<ForwardingDecisionSnapshotStoreInner>;

#[derive(Clone)]
pub struct ForwardingDecisionSnapshotSource {
    store: ForwardingDecisionSnapshotStore,
    source_token: ForwardingSnapshotSourceToken,
}

/// A source registration that restores the previous source when dropped.
pub struct ForwardingSnapshotRegistration {
    source: ForwardingDecisionSnapshotSource,
    committed: bool,
}

impl ForwardingSnapshotRegistration {
    pub fn source(&self) -> ForwardingDecisionSnapshotSource {
        self.source.clone()
    }

    pub fn commit(mut self) -> Result<(), ForwardingSnapshotCommitError> {
        let result = self.source.store.commit_source(self.source.source_token);
        if result.is_ok() {
            self.committed = true;
        }
        result
    }
}

impl Drop for ForwardingSnapshotRegistration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.source.store.rollback_source(self.source.source_token);
    }
}

impl ForwardingDecisionSnapshotSource {
    pub fn source_token(&self) -> ForwardingSnapshotSourceToken {
        self.source_token
    }

    pub fn publish(
        &self,
        snapshot: ForwardingDecisionSnapshotHandle,
    ) -> Result<(), ForwardingSnapshotPublishError> {
        self.store.store_if_newer(self.source_token, snapshot)
    }

    /// Revoke this source only when it is still active.
    pub fn revoke(&self) {
        self.store.revoke_source(self.source_token);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NextHopPolicy {
    #[default]
    LeastHop,
    LeastCost,
    MaxGoodput,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteQuality {
    pub delivery_bps: u64,
    pub latency_ms: u64,
    pub hops: usize,
}

pub type ForeignNetworkRouteInfoMap =
    DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>;

#[async_trait::async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn my_peer_id(&self) -> PeerId;
    fn forwarding_decision_snapshot_source(&self) -> Option<ForwardingDecisionSnapshotSource> {
        None
    }
    fn publish_origin_auth_batch(
        &self,
        _source_token: ForwardingSnapshotSourceToken,
        _generation: u64,
        _publications: &[OriginAuthPublication],
    ) -> Result<(), RouteOriginAuthPublishError> {
        Ok(())
    }
    fn discard_origin_auth_batch(
        &self,
        _source_token: ForwardingSnapshotSourceToken,
        _generation: u64,
    ) {
    }
    fn need_periodic_requery_peers(&self) -> bool {
        false
    }
    async fn close_peer(&self, _peer_id: PeerId) {}
    async fn get_peer_public_key(&self, _peer_id: PeerId) -> Option<Vec<u8>> {
        None
    }
    async fn get_peer_identity_type(&self, _peer_id: PeerId) -> Option<PeerIdentityType> {
        None
    }
    /// Return authentication evidence from a local live session.
    ///
    /// Route wire data must not provide this value. Implementations return
    /// `None` when local authentication evidence is unavailable.
    async fn get_authenticated_peer_secure_auth_level(
        &self,
        _peer_id: PeerId,
    ) -> Option<SecureAuthLevel> {
        None
    }

    async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
        DashMap::new()
    }
}

pub type RouteInterfaceBox = Box<dyn RouteInterface + Send + Sync>;

#[auto_impl::auto_impl(Box , &mut)]
pub trait RouteCostCalculatorInterface: Send + Sync {
    fn begin_update(&mut self) {}
    fn end_update(&mut self) {}

    fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
        1
    }

    fn calculate_delivery_bps(&self, _src: PeerId, _dst: PeerId) -> Option<u64> {
        None
    }

    fn need_update(&self) -> bool {
        false
    }

    fn cost_need_update(&self) -> bool {
        self.need_update()
    }

    fn delivery_need_update(&self) -> bool {
        self.need_update()
    }

    fn next_update_in(&self) -> Option<std::time::Duration> {
        None
    }

    fn next_delivery_update_in(&self) -> Option<std::time::Duration> {
        self.next_update_in()
    }

    fn dump(&self) -> String {
        "All routes have cost 1".to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct DefaultRouteCostCalculator;

impl RouteCostCalculatorInterface for DefaultRouteCostCalculator {}

pub type RouteCostCalculator = Box<dyn RouteCostCalculatorInterface>;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, Arc)]
pub trait Route {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()>;
    async fn close(&self);

    async fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId>;
    async fn get_next_hop_with_policy(
        &self,
        peer_id: PeerId,
        _policy: NextHopPolicy,
    ) -> Option<PeerId> {
        self.get_next_hop(peer_id).await
    }

    /// Return a next hop and the route generation used for the decision.
    ///
    /// Flow pins use this pair to reject a stale path after a destination route
    /// changes. Implementations that do not expose generations use zero.
    async fn get_next_hop_with_policy_and_generation(
        &self,
        peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<(PeerId, u64)> {
        self.get_next_hop_with_policy(peer_id, policy)
            .await
            .map(|next_hop| (next_hop, self.forwarding_generation()))
    }

    async fn forwarding_decision_snapshot(&self) -> Option<ForwardingDecisionSnapshotHandle> {
        None
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route>;

    async fn list_forwarding_peers(&self) -> ForwardingPeerSnapshot {
        Arc::new(ForwardingPeerTable::new(
            self.list_routes()
                .await
                .into_iter()
                .map(|route| ForwardingPeerInfo {
                    peer_id: route.peer_id,
                    has_ipv4: route.ipv4_addr.is_some(),
                    feature_flag: route.feature_flag,
                    multicast_groups: route.multicast_groups,
                    bridge_authorized: false,
                    bridge_authorization_deadline: None,
                })
                .collect(),
        ))
    }

    async fn list_forwarding_peer_capabilities(&self) -> ForwardingPeerSnapshot {
        self.list_forwarding_peers().await
    }

    async fn list_forwarding_peer_capabilities_with_generation(
        &self,
    ) -> (u64, ForwardingPeerSnapshot) {
        (
            self.forwarding_generation(),
            self.list_forwarding_peer_capabilities().await,
        )
    }

    fn forwarding_generation(&self) -> u64 {
        0
    }

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr>;

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr>;

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        BTreeSet::new()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        None
    }

    async fn get_public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        None
    }

    async fn get_local_public_ipv6_info(&self) -> ListPublicIpv6InfoResponse {
        ListPublicIpv6InfoResponse::default()
    }

    async fn get_peer_id_by_ipv4(&self, _ipv4: &Ipv4Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ipv6(&self, _ipv6: &Ipv6Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ip(&self, ip: &std::net::IpAddr) -> Option<PeerId> {
        match ip {
            std::net::IpAddr::V4(v4) => self.get_peer_id_by_ipv4(v4).await,
            std::net::IpAddr::V6(v6) => self.get_peer_id_by_ipv6(v6).await,
        }
    }

    async fn list_authenticated_foreign_network_peers(
        &self,
        _network_identity: &NetworkIdentity,
    ) -> Vec<(PeerId, Vec<u8>)> {
        vec![]
    }

    async fn get_authenticated_foreign_origin_owner_key(
        &self,
        _network_identity: &NetworkIdentity,
        _origin_peer_id: PeerId,
    ) -> Option<Vec<u8>> {
        None
    }

    async fn list_foreign_network_info(&self) -> RouteForeignNetworkInfos {
        Default::default()
    }

    async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        Default::default()
    }

    // my peer id in foreign network is different from the one in local network
    // this function is used to get the peer id in local network
    async fn get_origin_my_peer_id(
        &self,
        _network_name: &str,
        _foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {}

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo>;

    async fn get_authenticated_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.get_peer_info(peer_id).await
    }

    /// Return the auth level of the route peer's authenticated attestation.
    ///
    /// This value is local metadata. It is never accepted from route wire data.
    async fn get_authenticated_peer_secure_auth_level(
        &self,
        _peer_id: PeerId,
    ) -> Option<SecureAuthLevel> {
        None
    }

    async fn get_authenticated_peer_evidence(
        &self,
        _peer_id: PeerId,
    ) -> Option<AuthenticatedRoutePeerEvidence> {
        None
    }

    async fn get_bridge_peer_evidence(&self, _peer_id: PeerId) -> Option<BridgeRoutePeerEvidence> {
        None
    }

    async fn get_peer_info_last_update_time(&self) -> Instant;

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>>;

    async fn refresh_acl_groups(&self) {}

    async fn get_peer_groups_by_ip(&self, ip: &std::net::IpAddr) -> Arc<Vec<String>> {
        match self.get_peer_id_by_ip(ip).await {
            Some(peer_id) => self.get_peer_groups(peer_id),
            None => Arc::new(Vec::new()),
        }
    }

    async fn get_peer_groups_by_ipv4(&self, ipv4: &Ipv4Addr) -> Arc<Vec<String>> {
        match self.get_peer_id_by_ipv4(ipv4).await {
            Some(peer_id) => self.get_peer_groups(peer_id),
            None => Arc::new(Vec::new()),
        }
    }

    async fn dump(&self) -> String {
        "this route implementation does not support dump".to_string()
    }
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;

#[derive(Clone)]
pub struct MockRoute {}

#[async_trait::async_trait]
impl Route for MockRoute {
    async fn open(&self, _interface: RouteInterfaceBox) -> Result<u8, ()> {
        panic!("mock route")
    }

    async fn close(&self) {
        panic!("mock route")
    }

    async fn get_next_hop(&self, _peer_id: PeerId) -> Option<PeerId> {
        panic!("mock route")
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        panic!("mock route")
    }

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        unimplemented!()
    }

    // TODO: rewrite route management, remove this
    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        unimplemented!()
    }

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        unimplemented!()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        panic!("mock route")
    }

    async fn get_peer_info(&self, _peer_id: PeerId) -> Option<RoutePeerInfo> {
        panic!("mock route")
    }

    async fn get_peer_info_last_update_time(&self) -> Instant {
        panic!("mock route")
    }

    fn get_peer_groups(&self, _peer_id: PeerId) -> Arc<Vec<String>> {
        panic!("mock route")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(generation: u64) -> ForwardingDecisionSnapshotHandle {
        ForwardingDecisionSnapshot::from_parts(
            generation,
            Arc::new(ForwardingPeerTable::default()),
            Arc::new(HashSet::new()),
            None,
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(PrefixMap::new()),
            Arc::new(PrefixMap::new()),
        )
    }

    #[test]
    fn foreign_relay_accepts_scoped_encrypted_transport_identity() {
        assert!(AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
            PeerIdentityType::ForeignRelay,
            SecureAuthLevel::EncryptedUnauthenticated,
        ));
        assert!(AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
            PeerIdentityType::ForeignRelay,
            SecureAuthLevel::PeerVerified,
        ));
        assert!(!AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
            PeerIdentityType::ForeignRelay,
            SecureAuthLevel::NetworkSecretConfirmed,
        ));
    }

    #[test]
    fn pending_source_keeps_previous_snapshot_until_commit_or_rollback() {
        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(snapshot(1));
        assert_eq!(store.load_full().unwrap().generation(), 1);

        let pending = store.begin_source_registration().unwrap();
        let pending_source = pending.source();
        let _ = pending_source.publish(snapshot(2));
        // Readers must continue to use the last committed source while open is pending.
        assert_eq!(store.load_full().unwrap().generation(), 1);
        drop(pending);
        assert_eq!(store.load_full().unwrap().generation(), 1);

        let committed = store.begin_source_registration().unwrap();
        let _ = committed.source().publish(snapshot(3));
        committed.commit().unwrap();
        assert_eq!(store.load_full().unwrap().generation(), 3);
    }

    #[test]
    fn stale_source_revoke_does_not_clear_newer_source() {
        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(snapshot(1));

        let new_registration = store.begin_source_registration().unwrap();
        let new_source = new_registration.source();
        let _ = new_source.publish(snapshot(2));
        new_registration.commit().unwrap();
        assert_eq!(store.load_full().unwrap().generation(), 2);

        old_source.revoke();
        assert_eq!(store.load_full().unwrap().generation(), 2);
        new_source.revoke();
        assert!(store.load_full().is_none());
    }

    #[test]
    fn source_generation_acceptance_rejects_equal_and_older_updates() {
        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let registration = store.begin_source_registration().unwrap();
        let source = registration.source();
        let _ = source.publish(snapshot(2));
        assert!(!store.accepts_source_generation(source.source_token(), 2));
        assert!(!store.accepts_source_generation(source.source_token(), 1));
        registration.commit().unwrap();
        assert!(!store.accepts_source_generation(source.source_token(), 2));
        assert!(store.accepts_source_generation(source.source_token(), 3));
    }

    #[test]
    fn source_tokens_start_at_one_and_fail_closed_on_exhaustion() {
        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        assert!(!store.accepts_source_generation(ForwardingSnapshotSourceToken(0), 1));
        let registration = store.begin_source_registration().unwrap();
        assert_ne!(registration.source().source_token().0, 0);
        drop(registration);
        store.next_source_token.store(u64::MAX, Ordering::Relaxed);
        assert!(matches!(
            store.begin_source_registration(),
            Err(ForwardingSnapshotCommitError::SourceTokenExhausted)
        ));
    }

    #[test]
    fn revoke_waits_for_commit_barrier_and_clears_activated_source() {
        struct BarrierHook {
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
            done: Arc<std::sync::Barrier>,
            revoked: Arc<std::sync::atomic::AtomicBool>,
            source: ForwardingDecisionSnapshotSource,
            update_rejected: Arc<std::sync::atomic::AtomicBool>,
        }

        impl ForwardingSnapshotPublishHook for BarrierHook {
            fn publish_forwarding_snapshot(
                &self,
                _source_token: ForwardingSnapshotSourceToken,
                _snapshot: ForwardingDecisionSnapshotHandle,
                activate: bool,
            ) -> bool {
                if activate {
                    let source = self.source.clone();
                    let update_rejected = self.update_rejected.clone();
                    let done = self.done.clone();
                    std::thread::spawn(move || {
                        update_rejected
                            .store(source.publish(snapshot(3)).is_err(), Ordering::Release);
                        done.wait();
                    });
                    self.entered.wait();
                    self.release.wait();
                    self.done.wait();
                }
                true
            }

            fn revoke_forwarding_snapshot(&self, _source_token: ForwardingSnapshotSourceToken) {
                self.revoked.store(true, Ordering::Release);
            }

            fn discard_forwarding_snapshot(&self, _source_token: ForwardingSnapshotSourceToken) {}
        }

        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(snapshot(1));
        let registration = store.begin_source_registration().unwrap();
        let source = registration.source();
        let _ = source.publish(snapshot(2));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let done = Arc::new(std::sync::Barrier::new(2));
        let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let update_rejected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        store.set_publish_hook(Arc::new(BarrierHook {
            entered: entered.clone(),
            release: release.clone(),
            done: done.clone(),
            revoked: revoked.clone(),
            source: source.clone(),
            update_rejected: update_rejected.clone(),
        }));

        let commit_store = store.clone();
        let commit = std::thread::spawn(move || registration.commit());
        entered.wait();
        let revoke_source = source.clone();
        let revoke = std::thread::spawn(move || revoke_source.revoke());
        release.wait();
        assert!(commit.join().unwrap().is_ok());
        revoke.join().unwrap();
        drop(commit_store);
        assert!(update_rejected.load(Ordering::Acquire));
        assert!(revoked.load(Ordering::Acquire));
        assert!(store.load_full().is_none());
    }

    fn evidence(
        peer_id: PeerId,
        identity_type: PeerIdentityType,
        secure_auth_level: SecureAuthLevel,
    ) -> AuthenticatedRoutePeerEvidence {
        AuthenticatedRoutePeerEvidence {
            peer_id,
            identity_type,
            noise_static_pubkey: vec![7; 32],
            secure_auth_level,
        }
    }

    #[test]
    fn authenticated_evidence_requires_expected_peer_id_and_full_key() {
        let valid = evidence(
            7,
            PeerIdentityType::Admin,
            SecureAuthLevel::NetworkSecretConfirmed,
        );
        assert!(valid.validate_for(7));
        assert!(!valid.validate_for(8));

        for key_len in [0, 31, 33] {
            let mut invalid = valid.clone();
            invalid.noise_static_pubkey = vec![7; key_len];
            assert!(!invalid.validate_for(7));
        }
    }

    #[test]
    fn authenticated_evidence_allows_only_role_auth_pairs() {
        let valid_pairs = [
            (PeerIdentityType::Admin, SecureAuthLevel::PeerVerified),
            (
                PeerIdentityType::Admin,
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
            (PeerIdentityType::Credential, SecureAuthLevel::PeerVerified),
            (
                PeerIdentityType::SharedNode,
                SecureAuthLevel::EncryptedUnauthenticated,
            ),
            (PeerIdentityType::SharedNode, SecureAuthLevel::PeerVerified),
            (
                PeerIdentityType::ForeignRelay,
                SecureAuthLevel::PeerVerified,
            ),
        ];
        for (identity_type, secure_auth_level) in valid_pairs {
            assert!(
                evidence(7, identity_type, secure_auth_level).validate_for(7),
                "unexpectedly rejected {identity_type:?}/{secure_auth_level:?}"
            );
        }

        let invalid_pairs = [
            (PeerIdentityType::Admin, SecureAuthLevel::None),
            (
                PeerIdentityType::Admin,
                SecureAuthLevel::EncryptedUnauthenticated,
            ),
            (PeerIdentityType::Credential, SecureAuthLevel::None),
            (
                PeerIdentityType::Credential,
                SecureAuthLevel::EncryptedUnauthenticated,
            ),
            (
                PeerIdentityType::Credential,
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
            (PeerIdentityType::SharedNode, SecureAuthLevel::None),
            (
                PeerIdentityType::SharedNode,
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
            (PeerIdentityType::ForeignRelay, SecureAuthLevel::None),
            (
                PeerIdentityType::ForeignRelay,
                SecureAuthLevel::EncryptedUnauthenticated,
            ),
            (
                PeerIdentityType::ForeignRelay,
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
        ];
        for (identity_type, secure_auth_level) in invalid_pairs {
            assert!(
                !evidence(7, identity_type, secure_auth_level).validate_for(7),
                "unexpectedly accepted {identity_type:?}/{secure_auth_level:?}"
            );
        }
    }

    #[test]
    fn bridge_snapshot_rechecks_attestation_after_deadline() {
        let deadline = Instant::now() + std::time::Duration::from_millis(20);
        let table = ForwardingPeerTable::new(vec![ForwardingPeerInfo {
            peer_id: 7,
            feature_flag: Some(PeerFeatureFlag {
                ethernet_input: true,
                hybrid_l3: true,
                bridge_input: true,
                ..Default::default()
            }),
            bridge_authorized: true,
            bridge_authorization_deadline: Some(deadline),
            ..Default::default()
        }]);

        assert!(table.is_authorized_bridge(7));
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(!table.is_authorized_bridge(7));
        assert!(table.ethernet_peers().is_empty());
    }

    #[test]
    fn bridge_evidence_rejects_expired_attestation() {
        let evidence = BridgeRoutePeerEvidence {
            peer_id: 7,
            noise_static_pubkey: vec![7; 32],
            deadline: Some(Instant::now() - std::time::Duration::from_millis(1)),
            generation: 4,
        };
        assert!(!evidence.validate_for(7, Instant::now()));
    }
}
