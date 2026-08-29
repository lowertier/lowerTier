use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use parking_lot::Mutex;
use quanta::Instant as QuantaInstant;
use tokio::sync::RwLock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    common::{
        PeerId,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        shrink_dashmap,
    },
    proto::{
        api::instance::{self, PeerConnInfo},
        peer_rpc::{PeerIdentityType, RoutePeerInfo, SecureAuthLevel},
    },
    tunnel::{TunnelError, batch::PacketBatch, packet_def::ZCPacket},
};

use super::{
    PacketRecvChan,
    flow::{FlowPathCache, classify_packet_flow},
    peer::{ArcPeerConn, Peer},
    peer_conn::{PeerConn, PeerConnId},
    route_trait::{
        ArcRoute, AuthenticatedRoutePeerEvidence, BridgeRoutePeerEvidence,
        ForwardingDecisionSnapshotHandle, ForwardingDecisionSnapshotSource,
        ForwardingDecisionSnapshotStore, ForwardingDecisionSnapshotStoreInner,
        ForwardingSnapshotPublishHook, ForwardingSnapshotRegistration,
        ForwardingSnapshotSourceToken, NextHopPolicy, OriginAuthPublication,
    },
};

const MAX_LIVE_PEER_CONNECTIONS: usize = 64;
const MAX_LIVE_CONNECTIONS_PER_PEER: usize = 2;

struct PeerConnectionAdmission {
    global: Arc<Semaphore>,
    per_peer: Mutex<HashMap<PeerId, usize>>,
}

pub(crate) struct PeerConnectionPermit {
    peer_id: PeerId,
    admission: Arc<PeerConnectionAdmission>,
    _global: OwnedSemaphorePermit,
}

impl PeerConnectionAdmission {
    fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(MAX_LIVE_PEER_CONNECTIONS)),
            per_peer: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, peer_id: PeerId) -> Option<PeerConnectionPermit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let mut per_peer = self.per_peer.lock();
        let count = per_peer.entry(peer_id).or_default();
        if *count >= MAX_LIVE_CONNECTIONS_PER_PEER {
            return None;
        }
        *count += 1;
        drop(per_peer);
        Some(PeerConnectionPermit {
            peer_id,
            admission: self.clone(),
            _global: global,
        })
    }
}

impl Drop for PeerConnectionPermit {
    fn drop(&mut self) {
        let mut per_peer = self.admission.per_peer.lock();
        if let Some(count) = per_peer.get_mut(&self.peer_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_peer.remove(&self.peer_id);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OriginAuthSource {
    Direct,
    RouteIdentity,
    RouteAttestation,
    ForeignOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum OriginAuthCapability {
    GenericRelayOrigin,
    FullEthernetBridge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OriginAuthEntry {
    pub peer_id: PeerId,
    pub identity_type: PeerIdentityType,
    pub noise_static_pubkey: [u8; 32],
    pub secure_auth_level: SecureAuthLevel,
    pub source: OriginAuthSource,
    pub source_token: Option<ForwardingSnapshotSourceToken>,
    pub source_generation: u64,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OriginAuthGrant {
    pub peer_id: PeerId,
    pub capability: OriginAuthCapability,
    pub noise_static_pubkey: [u8; 32],
    pub source: OriginAuthSource,
    pub source_token: Option<ForwardingSnapshotSourceToken>,
    pub source_generation: u64,
    pub revision: u64,
    pub expires_at: Option<QuantaInstant>,
}

impl OriginAuthEntry {
    fn same_attestation(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
            && self.identity_type == other.identity_type
            && self.noise_static_pubkey == other.noise_static_pubkey
            && self.secure_auth_level == other.secure_auth_level
    }
}

impl OriginAuthGrant {
    pub(crate) fn is_live(&self, now: QuantaInstant) -> bool {
        self.expires_at.is_none_or(|deadline| now < deadline)
    }

    fn same_attestation(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
            && self.capability == other.capability
            && self.noise_static_pubkey == other.noise_static_pubkey
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct OriginAuthSnapshot {
    pub auth_generation: u64,
    entries: HashMap<PeerId, OriginAuthEntry>,
    grants: HashMap<(PeerId, OriginAuthCapability), OriginAuthGrant>,
}

impl OriginAuthSnapshot {
    pub(crate) fn lookup(&self, peer_id: PeerId) -> Option<OriginAuthEntry> {
        self.entries.get(&peer_id).copied()
    }

    pub(crate) fn lookup_grant(
        &self,
        peer_id: PeerId,
        capability: OriginAuthCapability,
    ) -> Option<OriginAuthGrant> {
        self.grants.get(&(peer_id, capability)).copied()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RouteTrustSnapshot {
    pub source_token: Option<ForwardingSnapshotSourceToken>,
    pub generation: u64,
    pub generic: HashMap<PeerId, OriginAuthEntry>,
    pub bridge: HashMap<(PeerId, OriginAuthCapability), OriginAuthGrant>,
}

impl RouteTrustSnapshot {
    fn from_sources(
        source_token: Option<ForwardingSnapshotSourceToken>,
        sources: &DashMap<(PeerId, OriginAuthSource), OriginAuthEntry>,
        grants: &DashMap<(PeerId, OriginAuthCapability), OriginAuthGrant>,
        generation: u64,
    ) -> Self {
        let Some(source_token) = source_token.filter(|token| token.is_nonzero()) else {
            return Self {
                source_token: None,
                generation,
                generic: HashMap::new(),
                bridge: HashMap::new(),
            };
        };
        Self {
            source_token: Some(source_token),
            generation,
            generic: sources
                .iter()
                .filter_map(|entry| {
                    (matches!(entry.key().1, OriginAuthSource::RouteIdentity)
                        && entry.value().source_token == Some(source_token)
                        && entry.value().source_generation == generation)
                        .then_some((entry.key().0, *entry.value()))
                })
                .collect(),
            bridge: grants
                .iter()
                .filter_map(|entry| {
                    (entry.value().source_token == Some(source_token)
                        && entry.value().source_generation == generation)
                        .then_some((*entry.key(), *entry.value()))
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PeerMapDataPlaneDescriptor {
    pub forwarding_snapshot: Option<ForwardingDecisionSnapshotHandle>,
    pub origin_auth_snapshot: Arc<OriginAuthSnapshot>,
    pub source_token: Option<ForwardingSnapshotSourceToken>,
    pub route_trust: Arc<RouteTrustSnapshot>,
}

impl Default for PeerMapDataPlaneDescriptor {
    fn default() -> Self {
        Self {
            forwarding_snapshot: None,
            origin_auth_snapshot: Arc::new(OriginAuthSnapshot::default()),
            source_token: None,
            route_trust: Arc::new(RouteTrustSnapshot::default()),
        }
    }
}

#[derive(Clone, Debug)]
struct StagedRouteOriginAuth {
    source_token: ForwardingSnapshotSourceToken,
    generation: u64,
    publications: Vec<OriginAuthPublication>,
}

fn merge_authenticated_route_peer_evidence(
    expected_peer_id: PeerId,
    candidates: impl IntoIterator<Item = AuthenticatedRoutePeerEvidence>,
) -> Option<AuthenticatedRoutePeerEvidence> {
    let mut accepted = None;
    for candidate in candidates {
        if !candidate.validate_for(expected_peer_id) {
            return None;
        }
        if accepted
            .as_ref()
            .is_some_and(|current| current != &candidate)
        {
            return None;
        }
        accepted = Some(candidate);
    }
    accepted
}

fn merge_bridge_route_peer_evidence(
    expected_peer_id: PeerId,
    candidates: impl IntoIterator<Item = BridgeRoutePeerEvidence>,
) -> Option<BridgeRoutePeerEvidence> {
    let now = QuantaInstant::now();
    let mut accepted = None;
    for candidate in candidates {
        if !candidate.validate_for(expected_peer_id, now) {
            return None;
        }
        if accepted
            .as_ref()
            .is_some_and(|current| current != &candidate)
        {
            return None;
        }
        accepted = Some(candidate);
    }
    accepted
}

pub struct PeerMap {
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_map: DashMap<PeerId, Arc<Peer>>,
    packet_send: PacketRecvChan,
    routes: RwLock<Vec<ArcRoute>>,
    route_install_lock: Arc<tokio::sync::Mutex<()>>,
    forwarding_snapshot: ForwardingDecisionSnapshotStore,
    data_plane_descriptor: Arc<ArcSwap<PeerMapDataPlaneDescriptor>>,
    origin_auth_sources: Arc<DashMap<(PeerId, OriginAuthSource), OriginAuthEntry>>,
    origin_auth_grants: Arc<DashMap<(PeerId, OriginAuthCapability), OriginAuthGrant>>,
    staged_route_origin_auth: Arc<DashMap<ForwardingSnapshotSourceToken, StagedRouteOriginAuth>>,
    origin_auth_publish_lock: Arc<Mutex<()>>,
    origin_auth_generation: Arc<AtomicU64>,
    peer_instance_epochs: Arc<DashMap<PeerId, u64>>,
    next_peer_instance_epoch: Arc<AtomicU64>,
    peer_lifecycle_lock: Arc<Mutex<()>>,
    alive_client_urls: Arc<Mutex<multimap::MultiMap<url::Url, PeerConnId>>>,
    connection_flow_paths: Arc<FlowPathCache<PeerConnId>>,
    route_flow_paths: Arc<FlowPathCache<PeerId>>,
    connection_admission: Arc<PeerConnectionAdmission>,
}

impl PeerMap {
    pub fn new(packet_send: PacketRecvChan, global_ctx: ArcGlobalCtx, my_peer_id: PeerId) -> Self {
        let data_plane_descriptor =
            Arc::new(ArcSwap::from_pointee(PeerMapDataPlaneDescriptor::default()));
        let origin_auth_sources = Arc::new(DashMap::new());
        let origin_auth_grants = Arc::new(DashMap::new());
        let origin_auth_generation = Arc::new(AtomicU64::new(0));
        PeerMap {
            global_ctx,
            my_peer_id,
            peer_map: DashMap::new(),
            packet_send,
            routes: RwLock::new(Vec::new()),
            route_install_lock: Arc::new(tokio::sync::Mutex::new(())),
            forwarding_snapshot: Arc::new(ForwardingDecisionSnapshotStoreInner::new()),
            data_plane_descriptor,
            origin_auth_sources,
            origin_auth_grants,
            staged_route_origin_auth: Arc::new(DashMap::new()),
            origin_auth_publish_lock: Arc::new(Mutex::new(())),
            origin_auth_generation,
            peer_instance_epochs: Arc::new(DashMap::new()),
            next_peer_instance_epoch: Arc::new(AtomicU64::new(0)),
            peer_lifecycle_lock: Arc::new(Mutex::new(())),
            alive_client_urls: Arc::new(Mutex::new(multimap::MultiMap::new())),
            connection_flow_paths: Arc::new(FlowPathCache::new(4096, Duration::from_secs(120))),
            route_flow_paths: Arc::new(FlowPathCache::new(1024, Duration::from_secs(120))),
            connection_admission: Arc::new(PeerConnectionAdmission::new()),
        }
    }

    fn next_auth_generation(&self) -> Option<u64> {
        let current = self.origin_auth_generation.load(Ordering::Acquire);
        let next = current.checked_add(1)?;
        self.origin_auth_generation.store(next, Ordering::Release);
        Some(next)
    }

    fn auth_generation_available(&self) -> bool {
        self.origin_auth_generation.load(Ordering::Acquire) != u64::MAX
    }

    fn load_dataplane_descriptor(&self) -> Arc<PeerMapDataPlaneDescriptor> {
        self.data_plane_descriptor.load_full()
    }

    pub(crate) fn dataplane_descriptor(&self) -> Arc<PeerMapDataPlaneDescriptor> {
        self.load_dataplane_descriptor()
    }

    pub(crate) fn authenticated_route_peer_evidence_from_descriptor(
        &self,
        peer_id: PeerId,
    ) -> Option<AuthenticatedRoutePeerEvidence> {
        let descriptor = self.load_dataplane_descriptor();
        descriptor
            .route_trust
            .generic
            .get(&peer_id)
            .map(|entry| AuthenticatedRoutePeerEvidence {
                peer_id,
                identity_type: entry.identity_type,
                noise_static_pubkey: entry.noise_static_pubkey.to_vec(),
                secure_auth_level: entry.secure_auth_level,
            })
    }

    fn publish_dataplane_descriptor(
        &self,
        forwarding_snapshot: Option<ForwardingDecisionSnapshotHandle>,
        origin_auth_snapshot: Arc<OriginAuthSnapshot>,
    ) {
        let descriptor = self.load_dataplane_descriptor();
        let source_token = descriptor.source_token;
        self.publish_dataplane_descriptor_with_source(
            forwarding_snapshot,
            origin_auth_snapshot,
            source_token,
        );
    }

    fn publish_dataplane_descriptor_with_source(
        &self,
        forwarding_snapshot: Option<ForwardingDecisionSnapshotHandle>,
        origin_auth_snapshot: Arc<OriginAuthSnapshot>,
        source_token: Option<ForwardingSnapshotSourceToken>,
    ) {
        let route_trust = Arc::new(RouteTrustSnapshot::from_sources(
            source_token,
            &self.origin_auth_sources,
            &self.origin_auth_grants,
            forwarding_snapshot
                .as_ref()
                .map(|snapshot| snapshot.generation())
                .unwrap_or_default(),
        ));
        self.data_plane_descriptor
            .store(Arc::new(PeerMapDataPlaneDescriptor {
                forwarding_snapshot,
                origin_auth_snapshot,
                source_token,
                route_trust,
            }));
    }

    fn publish_auth_snapshot(&self, origin_auth_snapshot: Arc<OriginAuthSnapshot>) {
        let descriptor = self.load_dataplane_descriptor();
        self.publish_dataplane_descriptor_with_source(
            descriptor.forwarding_snapshot.clone(),
            origin_auth_snapshot,
            descriptor.source_token,
        );
    }

    fn add_new_peer(&self, peer: Peer) {
        let peer_id = peer.peer_node_id;
        self.peer_map.insert(peer_id, Arc::new(peer));
        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerAdded(peer_id));
    }

    pub async fn add_new_peer_conn(self: &Arc<Self>, mut peer_conn: PeerConn) -> Result<(), Error> {
        let _ = self.maintain_alive_client_urls(&peer_conn);
        let peer_id = peer_conn.get_peer_id();
        let permit = self
            .connection_admission
            .try_acquire(peer_id)
            .ok_or_else(|| Error::RouteError(Some("peer connection admission is full".into())))?;
        peer_conn.attach_connection_permit(permit);
        let peer_conn_id = peer_conn.get_conn_id();
        let _lifecycle_guard = self.peer_lifecycle_lock.lock();
        let peer_epoch = if let Some(epoch) = self.peer_instance_epochs.get(&peer_id) {
            *epoch
        } else {
            let previous = self
                .next_peer_instance_epoch
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| Error::RouteError(Some("peer instance epoch exhausted".into())))?;
            let epoch = previous
                .checked_add(1)
                .ok_or_else(|| Error::RouteError(Some("peer instance epoch exhausted".into())))?;
            self.peer_instance_epochs.insert(peer_id, epoch);
            epoch
        };
        let weak_peer_map = Arc::downgrade(self);
        let origin_auth_update: crate::peers::peer::OriginAuthUpdate =
            Arc::new(move |peer_id, evidence| {
                let Some(peer_map) = weak_peer_map.upgrade() else {
                    return;
                };
                let evidence =
                    evidence.and_then(|(identity_type, public_key, secure_auth_level)| {
                        Some((
                            identity_type,
                            <[u8; 32]>::try_from(public_key).ok()?,
                            secure_auth_level,
                        ))
                    });
                let _lifecycle_guard = peer_map.peer_lifecycle_lock.lock();
                peer_map.publish_origin_auth_source(
                    peer_id,
                    OriginAuthSource::Direct,
                    evidence,
                    Some(peer_epoch),
                    0,
                    None,
                );
            });
        let no_entry = self.peer_map.get(&peer_id).is_none();
        let peer = if no_entry {
            let new_peer = Peer::new_with_flow_cache(
                peer_id,
                self.packet_send.clone(),
                self.global_ctx.clone(),
                self.connection_flow_paths.clone(),
            );
            new_peer.set_origin_auth_update(origin_auth_update.clone());
            self.add_new_peer(new_peer);
            self.peer_map.get(&peer_id).map(|entry| entry.clone())
        } else {
            self.peer_map.get(&peer_id).map(|entry| entry.clone())
        };
        drop(_lifecycle_guard);
        let Some(peer) = peer else {
            return Err(Error::NotFound);
        };
        peer.set_origin_auth_update(origin_auth_update);
        if let Err(error) = peer.add_peer_conn(peer_conn).await {
            let _lifecycle_guard = self.peer_lifecycle_lock.lock();
            if self
                .peer_map
                .get(&peer_id)
                .is_some_and(|current| Arc::ptr_eq(current.value(), &peer))
                && !peer.has_live_conns()
            {
                self.peer_map.remove(&peer_id);
                self.publish_origin_auth_source(
                    peer_id,
                    OriginAuthSource::Direct,
                    None,
                    Some(peer_epoch),
                    0,
                    None,
                );
                self.peer_instance_epochs.remove(&peer_id);
            }
            return Err(error);
        }
        let stale = {
            let _lifecycle_guard = self.peer_lifecycle_lock.lock();
            let current_is_same = self
                .peer_map
                .get(&peer_id)
                .is_some_and(|current| Arc::ptr_eq(current.value(), &peer));
            let epoch_is_same = self
                .peer_instance_epochs
                .get(&peer_id)
                .is_some_and(|current| *current == peer_epoch);
            if !current_is_same || !epoch_is_same {
                true
            } else {
                let evidence = peer.authenticated_origin_evidence().and_then(
                    |(identity_type, public_key, secure_auth_level)| {
                        Some((
                            identity_type,
                            <[u8; 32]>::try_from(public_key).ok()?,
                            secure_auth_level,
                        ))
                    },
                );
                self.publish_origin_auth_source(
                    peer_id,
                    OriginAuthSource::Direct,
                    evidence,
                    Some(peer_epoch),
                    0,
                    None,
                );
                false
            }
        };
        if stale {
            let _ = peer.close_peer_conn(&peer_conn_id).await;
            return Err(Error::RouteError(Some(
                "peer connection became stale during insertion".to_string(),
            )));
        }
        Ok(())
    }

    pub(crate) fn start_origin_auth_listener(self: &Arc<Self>) {
        let mut events = self.global_ctx.subscribe();
        let weak_peer_map = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let peer_id = match event {
                    GlobalCtxEvent::PeerConnAdded(info) | GlobalCtxEvent::PeerConnRemoved(info) => {
                        info.peer_id
                    }
                    _ => continue,
                };
                let Some(peer_map) = weak_peer_map.upgrade() else {
                    break;
                };
                peer_map.publish_direct_origin_auth_evidence(peer_id);
            }
        });
    }

    fn publish_origin_auth_source(
        &self,
        peer_id: PeerId,
        source: OriginAuthSource,
        evidence: Option<(PeerIdentityType, [u8; 32], SecureAuthLevel)>,
        instance_epoch: Option<u64>,
        source_generation: u64,
        expected_source_generation: Option<u64>,
    ) -> bool {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        if !self.auth_generation_available() {
            return false;
        }
        if source == OriginAuthSource::Direct {
            let Some(epoch) = instance_epoch else {
                return false;
            };
            let epoch_matches = self
                .peer_instance_epochs
                .get(&peer_id)
                .is_some_and(|current| *current == epoch);
            if evidence.is_some() && !epoch_matches {
                return false;
            }
            if evidence.is_none()
                && self
                    .peer_instance_epochs
                    .get(&peer_id)
                    .is_some_and(|current| *current != epoch)
            {
                return false;
            }
        }
        let source_key = (peer_id, source);
        let previous = self.origin_auth_snapshot();
        let current_source = self
            .origin_auth_sources
            .get(&source_key)
            .map(|entry| *entry);
        match evidence {
            Some((identity_type, noise_static_pubkey, secure_auth_level)) => {
                if current_source
                    .is_some_and(|current| current.source_generation > source_generation)
                {
                    return false;
                }
                let candidate = OriginAuthEntry {
                    peer_id,
                    identity_type,
                    noise_static_pubkey,
                    secure_auth_level,
                    source,
                    source_token: None,
                    source_generation,
                    revision: current_source
                        .map(|entry| entry.revision)
                        .unwrap_or_else(|| {
                            previous
                                .lookup(peer_id)
                                .map(|entry| entry.revision)
                                .unwrap_or_default()
                        }),
                };
                if current_source.is_some_and(|current| current.same_attestation(&candidate)) {
                    return true;
                }
                self.origin_auth_sources.insert(source_key, candidate);
            }
            None => {
                if expected_source_generation.is_some_and(|generation| {
                    current_source.is_none_or(|current| current.source_generation != generation)
                }) {
                    return false;
                }
                if current_source.is_none() {
                    return true;
                }
                self.origin_auth_sources.remove(&source_key);
            }
        }

        let candidates = [
            OriginAuthSource::Direct,
            OriginAuthSource::RouteIdentity,
            OriginAuthSource::ForeignOwner,
        ]
        .into_iter()
        .filter_map(|candidate_source| {
            self.origin_auth_sources
                .get(&(peer_id, candidate_source))
                .map(|entry| *entry)
        })
        .collect::<Vec<_>>();
        let selected = if candidates.is_empty() {
            None
        } else if candidates.iter().all(|candidate| {
            candidates.first().is_some_and(|first| {
                candidate.peer_id == first.peer_id
                    && candidate.identity_type == first.identity_type
                    && candidate.noise_static_pubkey == first.noise_static_pubkey
                    && candidate.secure_auth_level == first.secure_auth_level
            })
        }) {
            // A direct source remains preferred when all sources carry the same
            // authenticated identity. A different key or role revokes authority.
            candidates.into_iter().next()
        } else {
            tracing::warn!(
                ?peer_id,
                "conflicting origin authentication sources; authority revoked"
            );
            None
        };
        let old_selected = previous.lookup(peer_id);
        let selected_same = match (selected, old_selected) {
            (Some(current), Some(previous)) => current.same_attestation(&previous),
            (None, None) => true,
            _ => false,
        };
        if selected_same {
            return true;
        }
        let Some(revision) = self.next_auth_generation() else {
            return false;
        };
        let selected = selected.map(|mut entry| {
            entry.revision = revision;
            entry
        });
        let mut entries = previous.entries.clone();
        match selected {
            Some(entry) => {
                entries.insert(peer_id, entry);
            }
            None => {
                entries.remove(&peer_id);
            }
        }
        let grants = previous.grants.clone();
        self.publish_auth_snapshot(Arc::new(OriginAuthSnapshot {
            auth_generation: revision,
            entries,
            grants,
        }));
        true
    }

    /// Stage a complete route authority set. This does not change the live
    /// descriptor until the matching forwarding source is activated.
    pub(crate) fn publish_route_origin_auth_batch(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        generation: u64,
        publications: &[OriginAuthPublication],
    ) -> Result<(), super::route_trait::RouteOriginAuthPublishError> {
        // Serialize source staging with route revocation. The source check must
        // run while this coordinator is held, or a late stage can survive revoke.
        let _publish_guard = self.origin_auth_publish_lock.lock();
        if !self
            .forwarding_snapshot
            .accepts_source_generation(source_token, generation)
        {
            return Err(super::route_trait::RouteOriginAuthPublishError::SourceNotRegistered);
        }
        if !self.auth_generation_available() {
            return Err(super::route_trait::RouteOriginAuthPublishError::AuthGenerationExhausted);
        }
        let mut normalized = HashMap::<PeerId, OriginAuthPublication>::new();
        for publication in publications {
            if publication.peer_id == self.my_peer_id || publication.foreign_owner.is_some() {
                // Foreign owner keys from route wire data are not trusted.
                // A typed trusted-key store must provide this evidence later.
                if publication.foreign_owner.is_some() {
                    return Err(
                        super::route_trait::RouteOriginAuthPublishError::InvalidPublication,
                    );
                }
                continue;
            }
            if let Some(existing) = normalized.get(&publication.peer_id) {
                if existing.generic != publication.generic || existing.bridge != publication.bridge
                {
                    return Err(
                        super::route_trait::RouteOriginAuthPublishError::InvalidPublication,
                    );
                }
            }
            if publication
                .generic
                .as_ref()
                .is_some_and(|evidence| !evidence.validate_for(publication.peer_id))
                || publication.bridge.as_ref().is_some_and(|evidence| {
                    !evidence.validate_for(publication.peer_id, QuantaInstant::now())
                })
            {
                return Err(super::route_trait::RouteOriginAuthPublishError::InvalidPublication);
            }
            normalized.insert(publication.peer_id, publication.clone());
        }
        if self
            .staged_route_origin_auth
            .get(&source_token)
            .is_some_and(|staged| staged.generation >= generation)
        {
            return Err(super::route_trait::RouteOriginAuthPublishError::StaleGeneration);
        }
        self.staged_route_origin_auth.insert(
            source_token,
            StagedRouteOriginAuth {
                source_token,
                generation,
                publications: normalized.into_values().collect(),
            },
        );
        Ok(())
    }

    fn activate_route_source(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        forwarding_snapshot: ForwardingDecisionSnapshotHandle,
    ) -> bool {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        let generation = forwarding_snapshot.generation();
        let Some(staged) = self
            .staged_route_origin_auth
            .get(&source_token)
            .map(|staged| staged.clone())
        else {
            return false;
        };
        if staged.generation != generation {
            self.staged_route_origin_auth.remove(&source_token);
            return false;
        }
        if staged.source_token != source_token {
            self.staged_route_origin_auth.remove(&source_token);
            return false;
        }
        let applied = self.apply_route_origin_auth_batch_locked(
            source_token,
            generation,
            &staged.publications,
            forwarding_snapshot,
        );
        self.staged_route_origin_auth.remove(&source_token);
        applied
    }

    pub(crate) fn discard_route_source(&self, source_token: ForwardingSnapshotSourceToken) {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        self.staged_route_origin_auth.remove(&source_token);
    }

    fn revoke_route_source(&self, source_token: ForwardingSnapshotSourceToken) {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        if self.load_dataplane_descriptor().source_token != Some(source_token) {
            return;
        }
        let previous = self.origin_auth_snapshot();
        let mut source_candidates = self
            .origin_auth_sources
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect::<HashMap<_, _>>();
        let mut grant_candidates = self
            .origin_auth_grants
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect::<HashMap<_, _>>();
        self.staged_route_origin_auth.remove(&source_token);
        let removed_peers = source_candidates
            .iter()
            .filter_map(|(key, entry)| (entry.source_token == Some(source_token)).then_some(*key))
            .collect::<Vec<_>>();
        for key in removed_peers {
            source_candidates.remove(&key);
        }
        let removed_grants = grant_candidates
            .iter()
            .filter_map(|(key, entry)| (entry.source_token == Some(source_token)).then_some(*key))
            .collect::<Vec<_>>();
        for key in &removed_grants {
            grant_candidates.remove(key);
        }
        let mut entries = previous.entries.clone();
        let mut changed_peers = Vec::new();
        let peer_ids = source_candidates
            .keys()
            .map(|key| key.0)
            .chain(previous.entries.keys().copied())
            .collect::<std::collections::HashSet<_>>();
        for peer_id in peer_ids {
            let candidates = [
                OriginAuthSource::Direct,
                OriginAuthSource::RouteIdentity,
                OriginAuthSource::ForeignOwner,
            ]
            .into_iter()
            .filter_map(|source| source_candidates.get(&(peer_id, source)).copied())
            .collect::<Vec<_>>();
            let selected = candidates.first().copied().filter(|first| {
                candidates.iter().all(|candidate| {
                    candidate.identity_type == first.identity_type
                        && candidate.noise_static_pubkey == first.noise_static_pubkey
                        && candidate.secure_auth_level == first.secure_auth_level
                })
            });
            match selected {
                Some(mut selected) => {
                    let old = previous.lookup(peer_id);
                    if old.is_some_and(|old| old.same_attestation(&selected)) {
                        selected.revision = old.expect("the previous entry was checked").revision;
                    } else {
                        changed_peers.push(peer_id);
                    }
                    entries.insert(peer_id, selected);
                }
                None => {
                    if previous.lookup(peer_id).is_some() {
                        changed_peers.push(peer_id);
                    }
                    entries.remove(&peer_id);
                }
            }
        }
        let mut grants = previous.grants.clone();
        for key in &removed_grants {
            grants.remove(key);
        }
        let auth_changed = !changed_peers.is_empty() || !removed_grants.is_empty();
        let auth_generation = if auth_changed {
            match self.next_auth_generation() {
                Some(generation) => {
                    for peer_id in changed_peers {
                        if let Some(entry) = entries.get_mut(&peer_id) {
                            entry.revision = generation;
                        }
                    }
                    generation
                }
                None => {
                    // Epoch exhaustion is fail-closed. Clear every authority
                    // and publish an empty descriptor instead of stale trust.
                    entries.clear();
                    grants.clear();
                    source_candidates.clear();
                    grant_candidates.clear();
                    previous.auth_generation
                }
            }
        } else {
            previous.auth_generation
        };
        self.origin_auth_sources.clear();
        for (key, entry) in source_candidates {
            self.origin_auth_sources.insert(key, entry);
        }
        self.origin_auth_grants.clear();
        for (key, grant) in grant_candidates {
            self.origin_auth_grants.insert(key, grant);
        }
        self.publish_dataplane_descriptor_with_source(
            None,
            Arc::new(OriginAuthSnapshot {
                auth_generation,
                entries,
                grants,
            }),
            None,
        );
    }

    fn apply_route_origin_auth_batch_locked(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        generation: u64,
        publications: &[OriginAuthPublication],
        forwarding_snapshot: ForwardingDecisionSnapshotHandle,
    ) -> bool {
        if !self.auth_generation_available() {
            return false;
        }
        let mut normalized = HashMap::<PeerId, OriginAuthPublication>::new();
        for publication in publications {
            if publication.peer_id == self.my_peer_id {
                continue;
            }
            if publication.foreign_owner.is_some() {
                return false;
            }
            if let Some(existing) = normalized.get(&publication.peer_id) {
                if existing.generic != publication.generic
                    || existing.bridge != publication.bridge
                    || existing.foreign_owner != publication.foreign_owner
                {
                    return false;
                }
            }
            normalized.insert(publication.peer_id, publication.clone());
        }
        let previous = self.origin_auth_snapshot();
        let mut source_candidates = self
            .origin_auth_sources
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect::<HashMap<_, _>>();
        let mut grant_candidates = self
            .origin_auth_grants
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect::<HashMap<_, _>>();

        // Validate the complete batch and generation cursors before mutating
        // any source. A rejected batch must leave the previous publication
        // unchanged.
        let now = QuantaInstant::now();
        for publication in normalized.values() {
            if let Some(evidence) = publication.generic.as_ref() {
                if !evidence.validate_for(publication.peer_id) {
                    return false;
                }
                let key = (publication.peer_id, OriginAuthSource::RouteIdentity);
                if source_candidates
                    .get(&key)
                    .is_some_and(|entry| entry.source_generation > generation)
                {
                    return false;
                }
            }
            if let Some(evidence) = publication.bridge.as_ref() {
                if !evidence.validate_for(publication.peer_id, now) {
                    return false;
                }
                let key = (
                    publication.peer_id,
                    OriginAuthCapability::FullEthernetBridge,
                );
                if grant_candidates
                    .get(&key)
                    .is_some_and(|entry| entry.source_generation > evidence.generation)
                {
                    return false;
                }
            }
            if let Some((_, owner_generation)) = publication.foreign_owner {
                let key = (publication.peer_id, OriginAuthSource::ForeignOwner);
                if source_candidates
                    .get(&key)
                    .is_some_and(|entry| entry.source_generation > owner_generation)
                {
                    return false;
                }
            }
        }

        let mut changed_grants = HashSet::new();
        let route_sources = [
            OriginAuthSource::RouteIdentity,
            OriginAuthSource::ForeignOwner,
        ];
        let stale_sources = source_candidates
            .iter()
            .filter_map(|(key, entry)| {
                (route_sources.contains(&key.1)
                    && entry.source_token.is_some()
                    && (entry.source_token != Some(source_token)
                        || !normalized.contains_key(&key.0)))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in stale_sources {
            source_candidates.remove(&key);
        }
        let stale_grants = grant_candidates
            .iter()
            .filter_map(|(key, entry)| {
                (key.1 == OriginAuthCapability::FullEthernetBridge
                    && entry.source_token.is_some()
                    && (entry.source_token != Some(source_token)
                        || !normalized.contains_key(&key.0)))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in stale_grants {
            grant_candidates.remove(&key);
            changed_grants.insert(key);
        }
        let mut changed_identity_peers = HashSet::new();

        for publication in normalized.values() {
            if let Some(evidence) = publication.generic.as_ref() {
                let Some(noise_static_pubkey) =
                    <[u8; 32]>::try_from(evidence.noise_static_pubkey.as_slice()).ok()
                else {
                    unreachable!("generic evidence was prevalidated");
                };
                let key = (publication.peer_id, OriginAuthSource::RouteIdentity);
                let old = source_candidates.get(&key).copied();
                let revision = old
                    .map(|entry| entry.revision)
                    .or_else(|| {
                        previous
                            .lookup(publication.peer_id)
                            .map(|entry| entry.revision)
                    })
                    .unwrap_or_default();
                source_candidates.insert(
                    key,
                    OriginAuthEntry {
                        peer_id: publication.peer_id,
                        identity_type: evidence.identity_type,
                        noise_static_pubkey,
                        secure_auth_level: evidence.secure_auth_level,
                        source: OriginAuthSource::RouteIdentity,
                        source_token: Some(source_token),
                        source_generation: generation,
                        revision,
                    },
                );
            } else {
                source_candidates.remove(&(publication.peer_id, OriginAuthSource::RouteIdentity));
            }

            if let Some((noise_static_pubkey, owner_generation)) = publication.foreign_owner {
                let key = (publication.peer_id, OriginAuthSource::ForeignOwner);
                let old = source_candidates.get(&key).copied();
                source_candidates.insert(
                    key,
                    OriginAuthEntry {
                        peer_id: publication.peer_id,
                        identity_type: PeerIdentityType::ForeignRelay,
                        noise_static_pubkey,
                        secure_auth_level: SecureAuthLevel::PeerVerified,
                        source: OriginAuthSource::ForeignOwner,
                        source_token: Some(source_token),
                        source_generation: owner_generation,
                        revision: old.map(|entry| entry.revision).unwrap_or_default(),
                    },
                );
            } else {
                source_candidates.remove(&(publication.peer_id, OriginAuthSource::ForeignOwner));
            }
            if let Some(evidence) = publication.bridge.as_ref() {
                let Some(noise_static_pubkey) =
                    <[u8; 32]>::try_from(evidence.noise_static_pubkey.as_slice()).ok()
                else {
                    unreachable!("bridge evidence was prevalidated");
                };
                let key = (
                    publication.peer_id,
                    OriginAuthCapability::FullEthernetBridge,
                );
                let old = grant_candidates.get(&key).copied();
                let previous_grant = previous.grants.get(&key).copied();
                let revision = old
                    .map(|grant| grant.revision)
                    .or_else(|| previous_grant.map(|grant| grant.revision))
                    .unwrap_or_default();
                if old.is_none_or(|old| old.noise_static_pubkey != noise_static_pubkey) {
                    changed_grants.insert(key);
                }
                grant_candidates.insert(
                    key,
                    OriginAuthGrant {
                        peer_id: publication.peer_id,
                        capability: OriginAuthCapability::FullEthernetBridge,
                        noise_static_pubkey,
                        source: OriginAuthSource::RouteAttestation,
                        source_token: Some(source_token),
                        source_generation: evidence.generation,
                        revision,
                        expires_at: evidence.deadline,
                    },
                );
            } else {
                let key = (
                    publication.peer_id,
                    OriginAuthCapability::FullEthernetBridge,
                );
                if grant_candidates
                    .get(&key)
                    .is_some_and(|grant| grant.source_token == Some(source_token))
                {
                    grant_candidates.remove(&key);
                    changed_grants.insert(key);
                }
            }
        }

        let mut entries = previous.entries.clone();
        let mut grants = previous.grants.clone();
        for key in grant_candidates.iter().filter_map(|(key, grant)| {
            (!previous
                .grants
                .get(key)
                .is_some_and(|old| old.same_attestation(grant)))
            .then_some(*key)
        }) {
            changed_grants.insert(key);
        }
        for peer_id in normalized.keys().copied().chain(
            previous
                .entries
                .keys()
                .copied()
                .filter(|peer_id| !normalized.contains_key(peer_id)),
        ) {
            let candidates = [
                OriginAuthSource::Direct,
                OriginAuthSource::RouteIdentity,
                OriginAuthSource::ForeignOwner,
            ]
            .into_iter()
            .filter_map(|source| source_candidates.get(&(peer_id, source)).copied())
            .collect::<Vec<_>>();
            let selected = candidates.first().copied().filter(|first| {
                candidates.iter().all(|candidate| {
                    candidate.identity_type == first.identity_type
                        && candidate.noise_static_pubkey == first.noise_static_pubkey
                        && candidate.secure_auth_level == first.secure_auth_level
                })
            });
            match selected {
                Some(mut selected) => {
                    let old = previous.lookup(peer_id);
                    let semantic_changed = old.is_none_or(|old| !old.same_attestation(&selected));
                    if semantic_changed {
                        selected.revision = 0;
                    } else {
                        selected.revision =
                            old.map(|entry| entry.revision).unwrap_or(selected.revision);
                    }
                    entries.insert(peer_id, selected);
                    if semantic_changed {
                        changed_identity_peers.insert(peer_id);
                    }
                }
                None => {
                    if previous.lookup(peer_id).is_some() {
                        changed_identity_peers.insert(peer_id);
                    }
                    entries.remove(&peer_id);
                }
            }
        }
        let grant_keys = grant_candidates.keys().copied().collect::<Vec<_>>();
        for key in grant_keys {
            if let Some(grant) = grant_candidates.get(&key).copied() {
                grants.insert(key, grant);
            }
        }
        grants.retain(|key, _| grant_candidates.contains_key(key));
        let auth_changed = !changed_identity_peers.is_empty() || !changed_grants.is_empty();
        let auth_generation = if auth_changed {
            let Some(generation) = self.next_auth_generation() else {
                return false;
            };
            for peer_id in changed_identity_peers {
                if let Some(entry) = entries.get_mut(&peer_id) {
                    entry.revision = generation;
                }
            }
            for key in changed_grants {
                if let Some(grant) = grants.get_mut(&key) {
                    grant.revision = generation;
                }
            }
            generation
        } else {
            previous.auth_generation
        };
        self.origin_auth_sources.clear();
        for (key, entry) in source_candidates {
            self.origin_auth_sources.insert(key, entry);
        }
        self.origin_auth_grants.clear();
        for (key, grant) in grant_candidates {
            self.origin_auth_grants.insert(key, grant);
        }
        self.publish_dataplane_descriptor_with_source(
            Some(forwarding_snapshot),
            Arc::new(OriginAuthSnapshot {
                auth_generation,
                entries,
                grants,
            }),
            Some(source_token),
        );
        true
    }

    fn publish_origin_auth_grant(&self, grant: Option<OriginAuthGrant>) -> Option<OriginAuthGrant> {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        if !self.auth_generation_available() {
            return None;
        }
        let previous = self.origin_auth_snapshot();
        let Some(grant) = grant else {
            return None;
        };
        let grant_key = (grant.peer_id, grant.capability);
        let current = self.origin_auth_grants.get(&grant_key).map(|entry| *entry);
        if current.is_some_and(|entry| entry.same_attestation(&grant)) {
            let mut updated = current.expect("the current grant was checked");
            if updated.expires_at == grant.expires_at {
                return Some(updated);
            }
            updated.expires_at = grant.expires_at;
            self.origin_auth_grants.insert(grant_key, updated);
            let entries = previous.entries.clone();
            let mut grants = previous.grants.clone();
            grants.insert(grant_key, updated);
            self.publish_auth_snapshot(Arc::new(OriginAuthSnapshot {
                auth_generation: previous.auth_generation,
                entries,
                grants,
            }));
            return Some(updated);
        }
        let mut grant = grant;
        let Some(generation) = self.next_auth_generation() else {
            return None;
        };
        grant.revision = generation;
        self.origin_auth_grants.insert(grant_key, grant);
        let entries = previous.entries.clone();
        let mut grants = previous.grants.clone();
        grants.insert(grant_key, grant);
        self.publish_auth_snapshot(Arc::new(OriginAuthSnapshot {
            auth_generation: generation,
            entries,
            grants,
        }));
        Some(grant)
    }

    fn revoke_origin_auth_grant(
        &self,
        peer_id: PeerId,
        capability: OriginAuthCapability,
        expected_source_generation: Option<u64>,
    ) -> bool {
        let _publish_guard = self.origin_auth_publish_lock.lock();
        if !self.auth_generation_available() {
            return false;
        }
        let grant_key = (peer_id, capability);
        let Some(current) = self.origin_auth_grants.get(&grant_key).map(|entry| *entry) else {
            return expected_source_generation.is_none();
        };
        if expected_source_generation
            .is_some_and(|generation| current.source_generation != generation)
        {
            return false;
        }
        self.origin_auth_grants.remove(&grant_key);
        let previous = self.origin_auth_snapshot();
        let entries = previous.entries.clone();
        let mut grants = previous.grants.clone();
        grants.remove(&grant_key);
        let Some(generation) = self.next_auth_generation() else {
            return false;
        };
        self.publish_auth_snapshot(Arc::new(OriginAuthSnapshot {
            auth_generation: generation,
            entries,
            grants,
        }));
        true
    }

    fn publish_direct_origin_auth_evidence(&self, peer_id: PeerId) {
        let _lifecycle_guard = self.peer_lifecycle_lock.lock();
        let epoch = self.peer_instance_epochs.get(&peer_id).map(|epoch| *epoch);
        let evidence = self
            .get_peer_by_id(peer_id)
            .and_then(|peer| peer.authenticated_origin_evidence())
            .and_then(|(identity_type, public_key, secure_auth_level)| {
                Some((
                    identity_type,
                    <[u8; 32]>::try_from(public_key).ok()?,
                    secure_auth_level,
                ))
            });
        self.publish_origin_auth_source(
            peer_id,
            OriginAuthSource::Direct,
            evidence,
            epoch,
            0,
            None,
        );
    }

    pub(crate) fn publish_bridge_route_evidence(&self, evidence: BridgeRoutePeerEvidence) -> bool {
        if !evidence.validate_for(evidence.peer_id, QuantaInstant::now()) {
            return false;
        }
        let Some(noise_static_pubkey) = <[u8; 32]>::try_from(evidence.noise_static_pubkey).ok()
        else {
            return false;
        };
        self.publish_origin_auth_grant(Some(OriginAuthGrant {
            peer_id: evidence.peer_id,
            capability: OriginAuthCapability::FullEthernetBridge,
            noise_static_pubkey,
            source: OriginAuthSource::RouteAttestation,
            source_token: None,
            source_generation: evidence.generation,
            revision: 0,
            expires_at: evidence.deadline,
        }))
        .is_some()
    }

    pub(crate) fn revoke_bridge_route_evidence(
        &self,
        peer_id: PeerId,
        expected_generation: Option<u64>,
    ) -> bool {
        self.revoke_origin_auth_grant(
            peer_id,
            OriginAuthCapability::FullEthernetBridge,
            expected_generation,
        )
    }

    pub(crate) fn origin_auth_snapshot(&self) -> Arc<OriginAuthSnapshot> {
        self.load_dataplane_descriptor()
            .origin_auth_snapshot
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn install_test_origin_auth_evidence(
        &self,
        peer_id: PeerId,
        noise_static_pubkey: [u8; 32],
        source_generation: u64,
    ) {
        let epoch = source_generation.max(1);
        self.peer_instance_epochs.insert(peer_id, epoch);
        self.publish_origin_auth_source(
            peer_id,
            OriginAuthSource::Direct,
            Some((
                PeerIdentityType::Admin,
                noise_static_pubkey,
                SecureAuthLevel::PeerVerified,
            )),
            Some(epoch),
            source_generation,
            None,
        );
        self.publish_origin_auth_grant(Some(OriginAuthGrant {
            peer_id,
            capability: OriginAuthCapability::FullEthernetBridge,
            noise_static_pubkey,
            source: OriginAuthSource::RouteAttestation,
            source_token: None,
            source_generation,
            revision: 0,
            expires_at: None,
        }));
    }

    fn maintain_alive_client_urls(&self, peer_conn: &PeerConn) -> Option<()> {
        let conn_info = peer_conn.get_conn_info();
        if !conn_info.is_client {
            return None;
        }

        let close_notifier = peer_conn.get_close_notifier();
        let alive_conns_weak = Arc::downgrade(&self.alive_client_urls);
        let conn_id = close_notifier.get_conn_id();
        let alive_client_url: url::Url = conn_info.tunnel?.remote_addr?.into();
        self.alive_client_urls
            .lock()
            .insert(alive_client_url.clone(), conn_id);

        tokio::spawn(async move {
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            let Some(alive_conns) = alive_conns_weak.upgrade() else {
                return;
            };
            let mut guard = alive_conns.lock();
            if let Some(mut conn_ids) = guard.remove(&alive_client_url) {
                conn_ids.retain(|id| id != &conn_id);
                if !conn_ids.is_empty() {
                    guard.insert_many(alive_client_url, conn_ids);
                }
            };
            let alive_conn_count = guard.len();
            drop(guard);
            tracing::debug!(
                ?conn_id,
                "peer conn is closed, current alive conns: {}",
                alive_conn_count
            );
        });

        Some(())
    }

    pub fn is_client_url_alive(&self, url: &url::Url) -> bool {
        self.alive_client_urls.lock().contains_key(url)
    }

    pub fn get_peer_by_id(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.peer_map.get(&peer_id).map(|v| v.clone())
    }

    pub fn get_directly_connections_by_peer_id(&self, peer_id: PeerId) -> DashSet<uuid::Uuid> {
        if let Some(peer) = self.get_peer_by_id(peer_id) {
            return peer.get_directly_connections();
        }

        DashSet::new()
    }

    pub fn has_peer(&self, peer_id: PeerId) -> bool {
        peer_id == self.my_peer_id || self.peer_map.contains_key(&peer_id)
    }

    pub async fn send_msg_directly(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
        if dst_peer_id == self.my_peer_id {
            return self
                .packet_send
                .send(msg)
                .await
                .with_context(|| "send msg to self failed")
                .map_err(Error::from);
        }

        match self.get_peer_by_id(dst_peer_id) {
            Some(peer) => peer.send_msg(msg).await?,
            None => {
                tracing::error!("no peer for dst_peer_id: {}", dst_peer_id);
                return Err(Error::RouteError(Some(format!(
                    "peer map sengmsg directly no connected dst_peer_id: {}",
                    dst_peer_id
                ))));
            }
        }
        Ok(())
    }

    pub(crate) fn select_direct_conn_for_flow(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        flow_hash: u64,
    ) -> Option<ArcPeerConn> {
        self.get_peer_by_id(dst_peer_id)
            .and_then(|peer| peer.select_conn_for_flow(policy, flow_hash))
    }

    pub(crate) fn only_direct_conn(&self, dst_peer_id: PeerId) -> Option<ArcPeerConn> {
        self.get_peer_by_id(dst_peer_id)
            .and_then(|peer| peer.only_direct_conn())
    }

    pub(crate) async fn send_msg_on_selected_conn(
        &self,
        dst_peer_id: PeerId,
        conn: &ArcPeerConn,
        msg: ZCPacket,
    ) -> Result<(), Error> {
        let peer = self
            .get_peer_by_id(dst_peer_id)
            .ok_or_else(|| Error::RouteError(Some("peer is not connected".to_owned())))?;
        peer.send_msg_on_conn(conn, msg).await
    }

    pub(crate) async fn send_prepared_msg_batch_on_selected_conn(
        &self,
        dst_peer_id: PeerId,
        conn: &ArcPeerConn,
        batch: PacketBatch,
    ) -> Result<(), Error> {
        let peer = self
            .get_peer_by_id(dst_peer_id)
            .ok_or_else(|| Error::RouteError(Some("peer is not connected".to_owned())))?;
        peer.send_prepared_msg_batch_on_conn(conn, batch).await
    }

    pub async fn send_msg_batch_directly(
        &self,
        batch: PacketBatch,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        if dst_peer_id == self.my_peer_id {
            return self
                .packet_send
                .send_batch(batch)
                .await
                .with_context(|| "send msg to self failed")
                .map_err(Error::from);
        }
        let batch = match batch.pop_singleton() {
            Ok(packet) => return self.send_msg_directly(packet, dst_peer_id).await,
            Err(batch) => batch,
        };

        match self.get_peer_by_id(dst_peer_id) {
            Some(peer) => {
                peer.send_msg_batch(batch).await?;
            }
            None => {
                tracing::error!("no peer for dst_peer_id: {}", dst_peer_id);
                return Err(Error::RouteError(Some(format!(
                    "peer map sengmsg directly no connected dst_peer_id: {}",
                    dst_peer_id
                ))));
            }
        }

        Ok(())
    }

    pub async fn get_gateway_peer_id(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        self.get_gateway_peer_id_with_generation(dst_peer_id, policy)
            .await
            .map(|(gateway_peer_id, _)| gateway_peer_id)
    }

    pub async fn get_gateway_peer_id_for_flow(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        flow_hash: u64,
    ) -> Option<PeerId> {
        let policy_flow = match policy {
            NextHopPolicy::LeastHop => flow_hash,
            NextHopPolicy::LeastCost => flow_hash ^ (1_u64 << 63),
            NextHopPolicy::MaxGoodput => flow_hash ^ (1_u64 << 62),
        };
        let (candidate, route_generation) = self
            .get_gateway_peer_id_with_generation(dst_peer_id, policy)
            .await?;
        Some(self.route_flow_paths.select_at_generation(
            dst_peer_id,
            policy_flow,
            candidate,
            route_generation,
            |next_hop| self.has_peer(next_hop),
        ))
    }

    async fn get_gateway_peer_id_with_generation(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<(PeerId, u64)> {
        let snapshot = self
            .load_dataplane_descriptor()
            .forwarding_snapshot
            .clone()?;

        if dst_peer_id == self.my_peer_id {
            return Some((dst_peer_id, snapshot.generation()));
        }

        if self.has_peer(dst_peer_id) && matches!(policy, NextHopPolicy::LeastHop) {
            return Some((dst_peer_id, snapshot.generation()));
        }

        snapshot
            .next_hop(dst_peer_id, policy)
            .map(|next_hop| (next_hop.next_hop_peer_id, snapshot.generation()))
    }

    pub async fn get_gateway_peer_id_for_packet(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        packet: &ZCPacket,
    ) -> Option<PeerId> {
        self.get_gateway_peer_id_for_flow(dst_peer_id, policy, classify_packet_flow(packet).hash)
            .await
    }

    pub(crate) fn replace_authenticated_foreign_owner_snapshot(
        &self,
        bindings: &[(PeerId, Vec<u8>)],
    ) {
        let mut normalized = std::collections::BTreeMap::<PeerId, Option<[u8; 32]>>::new();
        for (peer_id, key) in bindings {
            if *peer_id == self.my_peer_id {
                continue;
            }
            let Some(key) = <[u8; 32]>::try_from(key.as_slice()).ok() else {
                normalized.insert(*peer_id, None);
                continue;
            };
            match normalized.entry(*peer_id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(key));
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if slot.get().is_none_or(|existing| existing != key) {
                        slot.insert(None);
                    }
                }
            }
        }

        let desired = normalized
            .into_iter()
            .filter_map(|(peer_id, key)| key.map(|key| (peer_id, key)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let existing = self
            .origin_auth_sources
            .iter()
            .filter_map(|entry| {
                (entry.key().1 == OriginAuthSource::ForeignOwner
                    && entry.value().source_token.is_none())
                .then_some(entry.key().0)
            })
            .collect::<Vec<_>>();

        for peer_id in existing {
            if !desired.contains_key(&peer_id) {
                self.publish_origin_auth_source(
                    peer_id,
                    OriginAuthSource::ForeignOwner,
                    None,
                    None,
                    0,
                    None,
                );
            }
        }
        for (peer_id, key) in desired {
            self.publish_origin_auth_source(
                peer_id,
                OriginAuthSource::ForeignOwner,
                Some((
                    PeerIdentityType::ForeignRelay,
                    key,
                    SecureAuthLevel::PeerVerified,
                )),
                None,
                0,
                None,
            );
        }
    }

    pub async fn list_authenticated_foreign_network_peers(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<(PeerId, Vec<u8>)> {
        let mut bindings = std::collections::BTreeMap::<PeerId, Option<Vec<u8>>>::new();
        for route in self.routes.read().await.iter() {
            for (peer_id, key) in route
                .list_authenticated_foreign_network_peers(network_identity)
                .await
            {
                match bindings.entry(peer_id) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(Some(key));
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        if slot.get().as_ref().is_none_or(|existing| *existing != key) {
                            slot.insert(None);
                        }
                    }
                }
            }
        }
        bindings
            .into_iter()
            .filter_map(|(peer_id, key)| key.map(|key| (peer_id, key)))
            .collect()
    }

    pub async fn get_authenticated_foreign_origin_owner_key(
        &self,
        network_identity: &NetworkIdentity,
        origin_peer_id: PeerId,
    ) -> Option<Vec<u8>> {
        let mut selected = None;
        for route in self.routes.read().await.iter() {
            let Some(key) = route
                .get_authenticated_foreign_origin_owner_key(network_identity, origin_peer_id)
                .await
            else {
                continue;
            };
            match selected.as_ref() {
                None => selected = Some(key),
                Some(existing) if *existing == key => {}
                Some(_) => return None,
            }
        }
        selected
    }

    pub async fn send_msg(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        self.send_msg_batch(PacketBatch::singleton(msg), dst_peer_id, policy)
            .await
    }

    pub async fn send_msg_batch(
        &self,
        batch: PacketBatch,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        let Some(gateway_peer_id) = self
            .get_gateway_peer_id_for_packet(dst_peer_id, policy, first)
            .await
        else {
            return Err(Error::RouteError(Some(format!(
                "peer map sengmsg no gateway for dst_peer_id: {}",
                dst_peer_id
            ))));
        };

        self.send_msg_batch_directly(batch, gateway_peer_id).await?;
        Ok(())
    }

    pub async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let peer_id = route.get_peer_id_by_ipv4(ipv4).await;
            if peer_id.is_some() {
                return peer_id;
            }
        }
        None
    }

    pub async fn get_peer_id_by_ipv6(&self, ipv6: &Ipv6Addr) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let peer_id = route.get_peer_id_by_ipv6(ipv6).await;
            if peer_id.is_some() {
                return peer_id;
            }
        }
        None
    }

    pub async fn get_route_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        for route in self.routes.read().await.iter() {
            if let Some(info) = route.get_peer_info(peer_id).await {
                return Some(info);
            }
        }
        None
    }

    pub async fn get_authenticated_route_peer_info(
        &self,
        peer_id: PeerId,
    ) -> Option<RoutePeerInfo> {
        for route in self.routes.read().await.iter() {
            if let Some(info) = route.get_authenticated_peer_info(peer_id).await {
                return Some(info);
            }
        }
        None
    }

    pub async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let origin_peer_id = route
                .get_origin_my_peer_id(network_name, foreign_my_peer_id)
                .await;
            if origin_peer_id.is_some() {
                return origin_peer_id;
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.peer_map.is_empty()
    }

    pub fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for item in self.peer_map.iter() {
            let peer_id = item.key();
            ret.push(*peer_id);
        }
        ret
    }

    pub async fn list_peers_with_conn(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for item in self.peer_map.iter() {
            if item.value().has_live_conns() {
                ret.push(*item.key());
            }
        }
        ret
    }

    pub async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            Some(p.list_peer_conns().await)
        } else {
            None
        }
    }

    pub(crate) fn list_speed_probe_connections(
        &self,
    ) -> Vec<(PeerId, crate::peers::peer::ArcPeerConn)> {
        let mut connections = Vec::new();
        for entry in self.peer_map.iter() {
            let peer_id = *entry.key();
            connections.extend(
                entry
                    .value()
                    .speed_probe_connections()
                    .into_iter()
                    .map(|connection| (peer_id, connection)),
            );
        }
        connections
    }

    pub async fn get_peer_default_conn_id(&self, peer_id: PeerId) -> Option<PeerConnId> {
        self.get_peer_by_id(peer_id)
            .map(|p| p.get_default_conn_id())
    }

    pub fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        self.get_peer_by_id(peer_id)
            .and_then(|p| p.get_peer_identity_type())
    }

    pub async fn has_route_to_peer(&self, peer_id: PeerId) -> bool {
        for route in self.routes.read().await.iter() {
            if route.get_next_hop(peer_id).await.is_some() {
                return true;
            }
        }
        false
    }

    pub fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        self.get_peer_by_id(peer_id)
            .and_then(|p| p.get_peer_public_key())
    }

    pub fn get_peer_secure_auth_level(&self, peer_id: PeerId) -> Option<SecureAuthLevel> {
        self.get_peer_by_id(peer_id)
            .and_then(|peer| peer.get_peer_secure_auth_level())
    }

    pub(crate) fn get_live_direct_conn(
        &self,
        peer_id: PeerId,
        conn_id: PeerConnId,
    ) -> Option<ArcPeerConn> {
        self.get_peer_by_id(peer_id)
            .and_then(|peer| peer.get_live_conn(conn_id))
    }

    fn direct_authenticated_admin_key(
        &self,
        peer_id: PeerId,
        session_id: uuid::Uuid,
    ) -> Option<[u8; 32]> {
        let Some(connection) = self.get_live_direct_conn(peer_id, session_id) else {
            return None;
        };
        let info = connection.get_conn_info();
        if info.peer_id != peer_id || info.conn_id != session_id.to_string() {
            return None;
        }
        let identity_type = connection.get_peer_identity_type();
        if identity_type != PeerIdentityType::Admin {
            return None;
        }
        let Some(auth_level) = SecureAuthLevel::try_from(info.secure_auth_level).ok() else {
            return None;
        };
        if !matches!(
            auth_level,
            SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
        ) {
            return None;
        }
        let Some(static_key) = <[u8; 32]>::try_from(info.noise_remote_static_pubkey).ok() else {
            return None;
        };
        let snapshot = self.origin_auth_snapshot();
        let Some(identity) = snapshot.lookup(peer_id) else {
            return None;
        };
        (identity.peer_id == peer_id
            && identity.identity_type == PeerIdentityType::Admin
            && matches!(
                identity.secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
            && identity.noise_static_pubkey == static_key)
            .then_some(static_key)
    }

    pub(crate) fn direct_authenticated_admin_is_authorized(
        &self,
        peer_id: PeerId,
        session_id: uuid::Uuid,
    ) -> bool {
        self.direct_authenticated_admin_key(peer_id, session_id)
            .is_some()
    }

    /// Prove a full-Ethernet grant for one exact authenticated direct session.
    ///
    /// The route evidence binds the current bridge key and capability revision.
    /// The connection check binds that evidence to the live session that received
    /// the packet. A peer role alone never grants bridge authority.
    pub(crate) fn direct_full_ethernet_bridge_is_authorized(
        &self,
        peer_id: PeerId,
        session_id: uuid::Uuid,
    ) -> bool {
        let Some(static_key) = self.direct_authenticated_admin_key(peer_id, session_id) else {
            return false;
        };
        let snapshot = self.origin_auth_snapshot();
        let Some(grant) = snapshot.lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
        else {
            return false;
        };
        grant.peer_id == peer_id
            && grant.source == OriginAuthSource::RouteAttestation
            && grant.noise_static_pubkey == static_key
            && grant.is_live(quanta::Instant::now())
    }

    pub async fn get_authenticated_route_peer_secure_auth_level(
        &self,
        peer_id: PeerId,
    ) -> Option<SecureAuthLevel> {
        self.get_authenticated_route_peer_evidence(peer_id)
            .await
            .map(|evidence| evidence.secure_auth_level)
    }

    pub async fn get_authenticated_route_peer_evidence(
        &self,
        peer_id: PeerId,
    ) -> Option<AuthenticatedRoutePeerEvidence> {
        let mut candidates = Vec::new();
        for route in self.routes.read().await.iter() {
            if let Some(evidence) = route.get_authenticated_peer_evidence(peer_id).await {
                candidates.push(evidence);
            }
        }
        merge_authenticated_route_peer_evidence(peer_id, candidates)
    }

    pub async fn get_bridge_route_peer_evidence(
        &self,
        peer_id: PeerId,
    ) -> Option<BridgeRoutePeerEvidence> {
        let mut candidates = Vec::new();
        for route in self.routes.read().await.iter() {
            if let Some(evidence) = route.get_bridge_peer_evidence(peer_id).await {
                candidates.push(evidence);
            }
        }
        merge_bridge_route_peer_evidence(peer_id, candidates)
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            let result = p.close_peer_conn(conn_id).await;
            // The Peer close listener publishes the final tuple after removal.
            // Reconcile here as well so an already-removed connection cannot
            // keep stale direct authority in the snapshot.
            self.publish_direct_origin_auth_evidence(peer_id);
            result
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn close_peer(&self, peer_id: PeerId) -> Result<(), TunnelError> {
        let _lifecycle_guard = self.peer_lifecycle_lock.lock();
        let remove_ret = self.peer_map.remove(&peer_id);
        let instance_epoch = self.peer_instance_epochs.get(&peer_id).map(|entry| *entry);
        self.peer_instance_epochs.remove(&peer_id);
        self.publish_origin_auth_source(
            peer_id,
            OriginAuthSource::Direct,
            None,
            instance_epoch,
            0,
            None,
        );
        shrink_dashmap(&self.peer_map, None);

        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        tracing::info!(
            ?peer_id,
            has_old_value = ?remove_ret.is_some(),
            peer_ref_counter = ?remove_ret.map(|v| Arc::strong_count(&v.1)),
            "peer is closed"
        );
        Ok(())
    }

    pub async fn add_route(&self, route: ArcRoute) {
        let _install_guard = self.route_install_lock.lock().await;
        self.add_route_unlocked(route).await;
    }

    /// Add a route while the caller holds the route installation lock.
    pub(crate) async fn add_route_unlocked(&self, route: ArcRoute) {
        let mut routes = self.routes.write().await;
        routes.insert(0, route);
    }

    pub(crate) async fn remove_route_unlocked(&self, route: &ArcRoute) {
        let mut routes = self.routes.write().await;
        routes.retain(|current| !Arc::ptr_eq(current, route));
    }

    pub(crate) fn route_install_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.route_install_lock.clone()
    }

    pub async fn clean_peer_without_conn(&self) {
        let mut to_remove = vec![];

        for peer_id in self.list_peers() {
            let conns = self.list_peer_conns(peer_id).await;
            if conns.is_none() || conns.as_ref().unwrap().is_empty() {
                to_remove.push(peer_id);
            }
        }

        for peer_id in to_remove {
            self.close_peer(peer_id).await.unwrap();
        }
    }

    pub async fn list_routes(&self) -> DashMap<PeerId, PeerId> {
        let route_map = DashMap::new();
        for route in self.routes.read().await.iter() {
            for item in route.list_routes().await.iter() {
                route_map.insert(item.peer_id, item.next_hop_peer_id);
            }
        }
        route_map
    }

    pub async fn list_route_infos(&self) -> Vec<instance::Route> {
        if let Some(route) = self.routes.read().await.iter().next() {
            return route.list_routes().await;
        }
        vec![]
    }

    pub async fn list_forwarding_peers(&self) -> super::route_trait::ForwardingPeerSnapshot {
        if let Some(route) = self.routes.read().await.iter().next() {
            return route.list_forwarding_peers().await;
        }
        Arc::new(super::route_trait::ForwardingPeerTable::default())
    }

    pub async fn list_forwarding_peer_capabilities(
        &self,
    ) -> super::route_trait::ForwardingPeerSnapshot {
        if let Some(route) = self.routes.read().await.iter().next() {
            return route.list_forwarding_peer_capabilities().await;
        }
        Arc::new(super::route_trait::ForwardingPeerTable::default())
    }

    pub async fn list_forwarding_peer_capabilities_with_generation(
        &self,
    ) -> (u64, super::route_trait::ForwardingPeerSnapshot) {
        if let Some(route) = self.routes.read().await.iter().next() {
            return route
                .list_forwarding_peer_capabilities_with_generation()
                .await;
        }
        (
            0,
            Arc::new(super::route_trait::ForwardingPeerTable::default()),
        )
    }

    pub async fn forwarding_generation(&self) -> u64 {
        self.routes
            .read()
            .await
            .iter()
            .next()
            .map(|route| route.forwarding_generation())
            .unwrap_or_default()
    }

    pub async fn forwarding_decision_snapshot(&self) -> Option<ForwardingDecisionSnapshotHandle> {
        self.load_dataplane_descriptor().forwarding_snapshot.clone()
    }

    pub fn install_forwarding_snapshot_source(
        &self,
    ) -> Result<ForwardingDecisionSnapshotSource, super::route_trait::ForwardingSnapshotCommitError>
    {
        self.forwarding_snapshot.register_source()
    }

    pub(crate) fn install_forwarding_snapshot_hook(self: &Arc<Self>) {
        self.forwarding_snapshot
            .set_publish_hook(Arc::new(PeerMapForwardingSnapshotHook {
                peer_map: Arc::downgrade(self),
            }));
    }

    pub fn begin_forwarding_snapshot_source_registration(
        &self,
    ) -> Result<ForwardingSnapshotRegistration, super::route_trait::ForwardingSnapshotCommitError>
    {
        self.forwarding_snapshot.begin_source_registration()
    }

    pub async fn need_relay_by_foreign_network(&self, dst_peer_id: PeerId) -> Result<bool, Error> {
        // if gateway_peer_id is not connected to me, means need relay by foreign network
        let gateway_id = self
            .get_gateway_peer_id(dst_peer_id, NextHopPolicy::LeastHop)
            .await
            .ok_or(Error::RouteError(Some(format!(
                "peer map need_relay_by_foreign_network no gateway for dst_peer_id: {}",
                dst_peer_id
            ))))?;

        Ok(!self.has_peer(gateway_id))
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }
}

impl Drop for PeerMap {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.global_ctx.get_network_identity(),
            "PeerMap is dropped"
        );
    }
}

struct PeerMapForwardingSnapshotHook {
    peer_map: std::sync::Weak<PeerMap>,
}

impl ForwardingSnapshotPublishHook for PeerMapForwardingSnapshotHook {
    fn publish_forwarding_snapshot(
        &self,
        source_token: ForwardingSnapshotSourceToken,
        snapshot: ForwardingDecisionSnapshotHandle,
        activate: bool,
    ) -> bool {
        let Some(peer_map) = self.peer_map.upgrade() else {
            return false;
        };
        if activate {
            peer_map.activate_route_source(source_token, snapshot)
        } else {
            true
        }
    }

    fn revoke_forwarding_snapshot(&self, source_token: ForwardingSnapshotSourceToken) {
        if let Some(peer_map) = self.peer_map.upgrade() {
            peer_map.revoke_route_source(source_token);
        }
    }

    fn discard_forwarding_snapshot(&self, source_token: ForwardingSnapshotSourceToken) {
        if let Some(peer_map) = self.peer_map.upgrade() {
            peer_map.discard_route_source(source_token);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use prefix_trie::PrefixMap;
    use tokio::sync::Notify;

    use super::{
        MAX_LIVE_CONNECTIONS_PER_PEER, OriginAuthCapability, OriginAuthSource,
        PeerConnectionAdmission, PeerMap, merge_authenticated_route_peer_evidence,
    };
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        peers::{
            create_packet_recv_chan,
            peer::Peer,
            route_trait::{
                ArcRoute, AuthenticatedRoutePeerEvidence, BridgeRoutePeerEvidence,
                ForwardingDecisionSnapshot, ForwardingNextHop, ForwardingPeerTable, MockRoute,
                NextHopPolicy, OriginAuthPublication, Route,
            },
        },
        proto::peer_rpc::{PeerIdentityType, SecureAuthLevel},
        tunnel::{batch::PacketBatch, packet_def::ZCPacket},
    };

    #[test]
    fn connection_admission_allows_two_paths_per_peer_and_releases_permits() {
        let admission = Arc::new(PeerConnectionAdmission::new());
        let peer_id = 7;

        let first = admission.try_acquire(peer_id).unwrap();
        let second = admission.try_acquire(peer_id).unwrap();
        assert_eq!(MAX_LIVE_CONNECTIONS_PER_PEER, 2);
        assert!(admission.try_acquire(peer_id).is_none());
        assert!(admission.try_acquire(peer_id + 1).is_some());

        drop(first);
        let replacement = admission.try_acquire(peer_id).unwrap();
        drop((second, replacement));
        assert!(admission.try_acquire(peer_id).is_some());
    }

    fn forwarding_snapshot(
        generation: u64,
        destination: u32,
        least_hop: u32,
        least_cost: u32,
        max_goodput: u32,
    ) -> Arc<ForwardingDecisionSnapshot> {
        let next_hop = |peer_id| ForwardingNextHop {
            next_hop_peer_id: peer_id,
            ..Default::default()
        };
        ForwardingDecisionSnapshot::from_parts(
            generation,
            Arc::new(ForwardingPeerTable::default()),
            Arc::new(HashSet::new()),
            None,
            Arc::new(HashMap::from([(destination, next_hop(least_hop))])),
            Arc::new(HashMap::from([(destination, next_hop(least_cost))])),
            Arc::new(HashMap::from([(destination, next_hop(max_goodput))])),
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(PrefixMap::new()),
            Arc::new(PrefixMap::new()),
        )
    }

    async fn install_panicking_route(peer_map: &PeerMap) {
        let route: ArcRoute = Arc::new(Box::new(MockRoute {}) as Box<dyn Route + Send + Sync>);
        peer_map.routes.write().await.push(route);
    }

    fn evidence(
        peer_id: u32,
        identity_type: PeerIdentityType,
        secure_auth_level: SecureAuthLevel,
    ) -> super::AuthenticatedRoutePeerEvidence {
        super::AuthenticatedRoutePeerEvidence {
            peer_id,
            identity_type,
            noise_static_pubkey: vec![7; 32],
            secure_auth_level,
        }
    }

    #[tokio::test]
    async fn forwarding_snapshot_is_unset_without_a_route() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        peer_map.install_forwarding_snapshot_hook();

        assert!(peer_map.forwarding_decision_snapshot().await.is_none());
    }

    #[tokio::test]
    async fn forwarding_snapshot_lookup_uses_one_generation_without_route_queries() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let peer_map = PeerMap::new(packet_send.clone(), global_ctx.clone(), 1);
        let direct_peer_id = 7;
        let routed_peer_id = 40;
        peer_map.peer_map.insert(
            direct_peer_id,
            Arc::new(Peer::new(direct_peer_id, packet_send, global_ctx)),
        );
        install_panicking_route(&peer_map).await;

        let source = peer_map.install_forwarding_snapshot_source().unwrap();
        let _ = source.publish(forwarding_snapshot(10, routed_peer_id, 8, 9, 10));

        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(1, NextHopPolicy::LeastHop)
                .await,
            Some((1, 10))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(direct_peer_id, NextHopPolicy::LeastHop)
                .await,
            Some((direct_peer_id, 10))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::LeastHop)
                .await,
            Some((8, 10))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::LeastCost)
                .await,
            Some((9, 10))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::MaxGoodput)
                .await,
            Some((10, 10))
        );

        let replacement = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let _ = replacement
            .source()
            .publish(forwarding_snapshot(11, routed_peer_id, 18, 19, 20));
        replacement.commit().unwrap();

        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::LeastHop)
                .await,
            Some((18, 11))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::LeastCost)
                .await,
            Some((19, 11))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(routed_peer_id, NextHopPolicy::MaxGoodput)
                .await,
            Some((20, 11))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(1, NextHopPolicy::LeastHop)
                .await,
            Some((1, 11))
        );
        assert_eq!(
            peer_map
                .get_gateway_peer_id_with_generation(direct_peer_id, NextHopPolicy::LeastHop)
                .await,
            Some((direct_peer_id, 11))
        );
    }

    #[tokio::test]
    async fn route_installation_lock_serializes_overlapping_transactions() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        let route_install_lock = peer_map.route_install_lock();
        let first_entered = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let second_entered = Arc::new(AtomicBool::new(false));

        let first_task = {
            let route_install_lock = route_install_lock.clone();
            let first_entered = first_entered.clone();
            let release_first = release_first.clone();
            tokio::spawn(async move {
                let _guard = route_install_lock.lock().await;
                first_entered.notify_one();
                release_first.notified().await;
            })
        };
        first_entered.notified().await;

        let second_task = {
            let route_install_lock = route_install_lock.clone();
            let second_entered = second_entered.clone();
            tokio::spawn(async move {
                let _guard = route_install_lock.lock().await;
                second_entered.store(true, Ordering::Release);
            })
        };
        for _ in 0..16 {
            tokio::task::yield_now().await;
            assert!(!second_entered.load(Ordering::Acquire));
        }

        release_first.notify_one();
        first_task.await.unwrap();
        second_task.await.unwrap();
        assert!(second_entered.load(Ordering::Acquire));
        drop(peer_map);
    }

    #[tokio::test]
    async fn self_batch_delivery_preserves_order_and_reports_closed_channel() {
        let (packet_send, mut packet_recv) = create_packet_recv_chan();
        let peer_map = PeerMap::new(packet_send, get_mock_global_ctx(), 1);
        let mut batch = PacketBatch::new();
        batch
            .try_push(ZCPacket::new_with_payload(b"first"))
            .unwrap();
        batch
            .try_push(ZCPacket::new_with_payload(b"second"))
            .unwrap();

        peer_map.send_msg_batch_directly(batch, 1).await.unwrap();
        let delivered = packet_recv.recv_batch().await.unwrap();
        let payloads = delivered
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec()]);

        let (closed_send, closed_recv) = create_packet_recv_chan();
        drop(closed_recv);
        let closed_map = PeerMap::new(closed_send, get_mock_global_ctx(), 1);
        let mut closed_batch = PacketBatch::new();
        closed_batch
            .try_push(ZCPacket::new_with_payload(b"closed"))
            .unwrap();
        closed_batch
            .try_push(ZCPacket::new_with_payload(b"closed-second"))
            .unwrap();
        assert!(
            closed_map
                .send_msg_batch_directly(closed_batch, 1)
                .await
                .is_err()
        );
    }

    #[test]
    fn foreign_owner_snapshot_is_complete_and_conflicts_fail_closed() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = PeerMap::new(packet_send, get_mock_global_ctx(), 1);
        let key = vec![7_u8; 32];

        peer_map.replace_authenticated_foreign_owner_snapshot(&[(7, key.clone())]);
        let first = peer_map
            .origin_auth_snapshot()
            .lookup(7)
            .expect("verified foreign owner is published");
        assert_eq!(first.identity_type, PeerIdentityType::ForeignRelay);
        assert_eq!(first.secure_auth_level, SecureAuthLevel::PeerVerified);
        assert_eq!(first.noise_static_pubkey.as_slice(), key.as_slice());

        peer_map
            .replace_authenticated_foreign_owner_snapshot(&[(7, key.clone()), (7, vec![8_u8; 32])]);
        assert!(peer_map.origin_auth_snapshot().lookup(7).is_none());

        peer_map.replace_authenticated_foreign_owner_snapshot(&[(7, key)]);
        assert!(peer_map.origin_auth_snapshot().lookup(7).is_some());
        peer_map.replace_authenticated_foreign_owner_snapshot(&[]);
        assert!(peer_map.origin_auth_snapshot().lookup(7).is_none());
    }

    #[test]
    fn identical_authenticated_route_evidence_is_accepted() {
        let candidate = evidence(7, PeerIdentityType::Admin, SecureAuthLevel::PeerVerified);
        assert_eq!(
            merge_authenticated_route_peer_evidence(7, [candidate.clone(), candidate.clone()]),
            Some(candidate)
        );
    }

    #[test]
    fn conflicting_authenticated_route_evidence_is_rejected() {
        let first = evidence(7, PeerIdentityType::Admin, SecureAuthLevel::PeerVerified);
        let mut conflicting = first.clone();
        conflicting.noise_static_pubkey[0] ^= 1;
        assert!(merge_authenticated_route_peer_evidence(7, [first, conflicting]).is_none());
    }

    #[test]
    fn legacy_only_route_provider_cannot_supply_authenticated_evidence() {
        assert!(
            merge_authenticated_route_peer_evidence(7, std::iter::empty()).is_none(),
            "a provider that only exposes RoutePeerInfo must not authenticate a peer"
        );
    }

    #[test]
    fn generic_identity_revision_survives_revoke_and_regrant() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = PeerMap::new(packet_send, get_mock_global_ctx(), 1);
        let peer_id = 7;
        let key = [9; 32];
        peer_map.install_test_origin_auth_evidence(peer_id, key, 1);

        let first_revision = peer_map
            .origin_auth_snapshot()
            .lookup(peer_id)
            .expect("the initial identity is published")
            .revision;
        let first_epoch = *peer_map
            .peer_instance_epochs
            .get(&peer_id)
            .expect("the test identity has an epoch");
        assert!(peer_map.publish_origin_auth_source(
            peer_id,
            super::OriginAuthSource::Direct,
            None,
            Some(first_epoch),
            0,
            None,
        ));
        assert!(peer_map.origin_auth_snapshot().lookup(peer_id).is_none());

        let second_epoch = first_epoch + 1;
        peer_map.peer_instance_epochs.insert(peer_id, second_epoch);
        assert!(peer_map.publish_origin_auth_source(
            peer_id,
            super::OriginAuthSource::Direct,
            Some((PeerIdentityType::Admin, key, SecureAuthLevel::PeerVerified,)),
            Some(second_epoch),
            0,
            None,
        ));
        let second_revision = peer_map
            .origin_auth_snapshot()
            .lookup(peer_id)
            .expect("the regranted identity is published")
            .revision;
        assert!(second_revision > first_revision);
    }

    #[test]
    fn bridge_grant_revision_survives_revoke_and_regrant() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = PeerMap::new(packet_send, get_mock_global_ctx(), 1);
        let peer_id = 8;
        let key = vec![4; 32];
        assert!(
            peer_map.publish_bridge_route_evidence(BridgeRoutePeerEvidence {
                peer_id,
                noise_static_pubkey: key.clone(),
                deadline: None,
                generation: 1,
            })
        );
        let grant_key = (peer_id, OriginAuthCapability::FullEthernetBridge);
        let first_revision = peer_map
            .origin_auth_snapshot()
            .lookup_grant(peer_id, grant_key.1)
            .expect("the initial bridge grant is published")
            .revision;
        assert!(peer_map.revoke_bridge_route_evidence(peer_id, None));
        assert!(
            peer_map
                .origin_auth_snapshot()
                .lookup_grant(peer_id, grant_key.1)
                .is_none()
        );

        assert!(
            peer_map.publish_bridge_route_evidence(BridgeRoutePeerEvidence {
                peer_id,
                noise_static_pubkey: key,
                deadline: None,
                generation: 2,
            })
        );
        let second_revision = peer_map
            .origin_auth_snapshot()
            .lookup_grant(peer_id, grant_key.1)
            .expect("the bridge grant is regranted")
            .revision;
        assert!(second_revision > first_revision);
    }

    #[test]
    fn route_source_replacement_with_missing_entry_revokes_route_authority() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        peer_map.install_forwarding_snapshot_hook();
        let first_registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let first_source = first_registration.source();
        let peer_id = 7;
        let key = vec![6; 32];
        assert!(
            peer_map
                .publish_route_origin_auth_batch(
                    first_source.source_token(),
                    1,
                    &[OriginAuthPublication {
                        peer_id,
                        generic: Some(AuthenticatedRoutePeerEvidence {
                            peer_id,
                            identity_type: PeerIdentityType::Admin,
                            noise_static_pubkey: key.clone(),
                            secure_auth_level: SecureAuthLevel::PeerVerified,
                        }),
                        bridge: Some(BridgeRoutePeerEvidence {
                            peer_id,
                            noise_static_pubkey: key,
                            deadline: None,
                            generation: 1,
                        }),
                        foreign_owner: None,
                    }],
                )
                .is_ok()
        );
        let _ = first_source.publish(forwarding_snapshot(1, 7, 7, 7, 7));
        first_registration.commit().unwrap();
        assert!(peer_map.origin_auth_snapshot().lookup(peer_id).is_some());
        assert!(
            peer_map
                .origin_auth_snapshot()
                .lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
                .is_some()
        );

        let registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let replacement = registration.source();
        let replacement_token = replacement.source_token();
        assert!(
            peer_map
                .publish_route_origin_auth_batch(replacement_token, 2, &[])
                .is_ok()
        );
        let _ = replacement.publish(forwarding_snapshot(2, 7, 7, 7, 7));
        registration.commit().unwrap();
        first_source.revoke();
        assert_eq!(
            peer_map
                .load_dataplane_descriptor()
                .forwarding_snapshot
                .as_ref()
                .expect("the replacement remains active")
                .generation(),
            2
        );
        assert!(peer_map.origin_auth_snapshot().lookup(peer_id).is_none());
        assert!(
            peer_map
                .origin_auth_snapshot()
                .lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
                .is_none()
        );
    }

    #[test]
    fn route_batch_missing_entry_revokes_authority_for_active_source() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        peer_map.install_forwarding_snapshot_hook();
        let registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let source = registration.source();
        let peer_id = 9;
        let key = vec![5; 32];
        assert!(
            peer_map
                .publish_route_origin_auth_batch(
                    source.source_token(),
                    1,
                    &[OriginAuthPublication {
                        peer_id,
                        generic: Some(AuthenticatedRoutePeerEvidence {
                            peer_id,
                            identity_type: PeerIdentityType::Credential,
                            noise_static_pubkey: key.clone(),
                            secure_auth_level: SecureAuthLevel::PeerVerified,
                        }),
                        bridge: Some(BridgeRoutePeerEvidence {
                            peer_id,
                            noise_static_pubkey: key,
                            deadline: None,
                            generation: 1,
                        }),
                        foreign_owner: None,
                    }],
                )
                .is_ok()
        );
        let _ = source.publish(forwarding_snapshot(1, 9, 9, 9, 9));
        registration.commit().unwrap();
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 2, &[])
                .is_ok()
        );
        let _ = source.publish(forwarding_snapshot(2, 9, 9, 9, 9));
        let snapshot = peer_map.origin_auth_snapshot();
        assert!(snapshot.lookup(peer_id).is_none());
        assert!(
            snapshot
                .lookup_grant(peer_id, OriginAuthCapability::FullEthernetBridge)
                .is_none()
        );
    }

    #[test]
    fn direct_conflict_revoke_recomputes_active_route_authority() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        peer_map.install_forwarding_snapshot_hook();
        let registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let source = registration.source();
        let peer_id = 11;
        let route_key = [1; 32];
        assert!(
            peer_map
                .publish_route_origin_auth_batch(
                    source.source_token(),
                    1,
                    &[OriginAuthPublication {
                        peer_id,
                        generic: Some(AuthenticatedRoutePeerEvidence {
                            peer_id,
                            identity_type: PeerIdentityType::Admin,
                            noise_static_pubkey: route_key.to_vec(),
                            secure_auth_level: SecureAuthLevel::PeerVerified,
                        }),
                        bridge: None,
                        foreign_owner: None,
                    }],
                )
                .is_ok()
        );
        let _ = source.publish(forwarding_snapshot(1, peer_id, peer_id, peer_id, peer_id));
        registration.commit().unwrap();
        let route_revision = peer_map
            .origin_auth_snapshot()
            .lookup(peer_id)
            .expect("route authority is active")
            .revision;

        peer_map.peer_instance_epochs.insert(peer_id, 1);
        assert!(peer_map.publish_origin_auth_source(
            peer_id,
            OriginAuthSource::Direct,
            Some((
                PeerIdentityType::Admin,
                [2; 32],
                SecureAuthLevel::PeerVerified,
            )),
            Some(1),
            0,
            None,
        ));
        assert!(peer_map.origin_auth_snapshot().lookup(peer_id).is_none());
        assert!(peer_map.publish_origin_auth_source(
            peer_id,
            OriginAuthSource::Direct,
            None,
            Some(1),
            0,
            None,
        ));
        let recovered = peer_map
            .origin_auth_snapshot()
            .lookup(peer_id)
            .expect("route authority returns after direct conflict removal");
        assert!(recovered.revision > route_revision);
    }

    #[test]
    fn route_authority_staging_rejects_out_of_order_generations() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = PeerMap::new(packet_send, get_mock_global_ctx(), 1);
        let registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let source = registration.source();
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 2, &[])
                .is_ok()
        );
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 1, &[])
                .is_err()
        );
        let _ = source.publish(forwarding_snapshot(2, 7, 7, 7, 7));
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 2, &[])
                .is_err()
        );
        registration.commit().unwrap();
    }

    #[test]
    fn late_authority_stage_after_source_revoke_is_rejected() {
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, get_mock_global_ctx(), 1));
        peer_map.install_forwarding_snapshot_hook();
        let registration = peer_map
            .begin_forwarding_snapshot_source_registration()
            .unwrap();
        let source = registration.source();
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 1, &[])
                .is_ok()
        );
        let _ = source.publish(forwarding_snapshot(1, 7, 7, 7, 7));
        registration.commit().unwrap();
        source.revoke();
        assert!(
            peer_map
                .publish_route_origin_auth_batch(source.source_token(), 2, &[])
                .is_err()
        );
        assert!(peer_map.dataplane_descriptor().source_token.is_none());
    }
}
