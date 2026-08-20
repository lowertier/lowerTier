use std::{
    collections::{BTreeSet, HashMap, hash_map::DefaultHasher},
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::{
    PeerId,
    config::{ConfigLoader, Flags, PortMode, process_secure_mode_cfg, validate_flags},
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
    underlay_policy::UnderlayPolicy,
};
use crate::{
    common::{
        config::ProxyNetworkConfig, dataplane_telemetry::DataplaneTelemetry, shrink_dashmap,
        stats_manager::StatsManager, token_bucket::TokenBucketManager,
    },
    peers::{acl_filter::AclFilter, credential_manager::CredentialManager},
    proto::{
        acl::GroupIdentity,
        api::{config::InstanceConfigPatch, instance::PeerConnInfo},
        common::{PeerFeatureFlag, PortForwardConfigPb, SecureModeConfig},
        peer_rpc::PeerGroupInfo,
    },
    rpc_service::protected_port,
    tunnel::matches_protocol,
};
use crossbeam::atomic::AtomicCell;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use socket2::Protocol;

pub type NetworkIdentity = crate::common::config::NetworkIdentity;

pub(crate) const PROCESS_RETAINED_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const FEC_INSTANCE_MAX_RETAINED_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub(crate) struct ProcessMemoryGovernor {
    limit: usize,
    retained: AtomicUsize,
}

#[derive(Debug)]
pub(crate) struct ProcessMemoryPermit {
    governor: Arc<ProcessMemoryGovernor>,
    bytes: usize,
}

impl Drop for ProcessMemoryPermit {
    fn drop(&mut self) {
        self.governor.release(self.bytes);
    }
}

static PROCESS_MEMORY_GOVERNOR: OnceLock<Arc<ProcessMemoryGovernor>> = OnceLock::new();

pub(crate) fn global_process_memory_governor() -> Arc<ProcessMemoryGovernor> {
    PROCESS_MEMORY_GOVERNOR
        .get_or_init(|| Arc::new(ProcessMemoryGovernor::new()))
        .clone()
}

impl ProcessMemoryGovernor {
    pub(crate) fn new() -> Self {
        Self::with_limit(PROCESS_RETAINED_MEMORY_LIMIT_BYTES)
    }

    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            retained: AtomicUsize::new(0),
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> bool {
        self.retained
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|total| *total <= self.limit)
            })
            .is_ok()
    }

    pub(crate) fn try_reserve_owned(self: &Arc<Self>, bytes: usize) -> Option<ProcessMemoryPermit> {
        self.reserve(bytes).then(|| ProcessMemoryPermit {
            governor: self.clone(),
            bytes,
        })
    }

    pub(crate) fn release(&self, bytes: usize) {
        let mut current = self.retained.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_sub(bytes) else {
                tracing::error!(
                    retained = current,
                    release = bytes,
                    "process memory governor underflow"
                );
                debug_assert!(false, "process memory governor ownership was lost");
                return;
            };
            match self.retained.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn retained(&self) -> usize {
        self.retained.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) struct FecResourceBudget {
    limit: usize,
    retained: AtomicUsize,
    process: Option<Arc<ProcessMemoryGovernor>>,
}

impl FecResourceBudget {
    pub(crate) fn new() -> Self {
        Self::with_limit(FEC_INSTANCE_MAX_RETAINED_BYTES)
    }

    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            retained: AtomicUsize::new(0),
            process: None,
        }
    }

    pub(crate) fn with_process(limit: usize, process: Arc<ProcessMemoryGovernor>) -> Self {
        Self {
            limit,
            retained: AtomicUsize::new(0),
            process: Some(process),
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> bool {
        if self
            .process
            .as_ref()
            .is_some_and(|process| !process.reserve(bytes))
        {
            return false;
        }
        let reserved = self
            .retained
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|total| *total <= self.limit)
            })
            .is_ok();
        if !reserved && let Some(process) = self.process.as_ref() {
            process.release(bytes);
        }
        reserved
    }

    pub(crate) fn release(&self, bytes: usize) -> bool {
        let mut current = self.retained.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_sub(bytes) else {
                tracing::error!(
                    retained = current,
                    release = bytes,
                    "alternate FEC resource budget underflow"
                );
                debug_assert!(
                    false,
                    "alternate FEC resource budget released more bytes than retained"
                );
                return false;
            };
            match self.retained.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if let Some(process) = self.process.as_ref() {
                        process.release(bytes);
                    }
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn retained(&self) -> usize {
        self.retained.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GlobalCtxEvent {
    TunDeviceReady(String),
    TunDeviceError(String),

    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),

    ListenerAdded(url::Url),
    ListenerAddFailed(url::Url, String), // (url, error message)
    ListenerAcceptFailed(url::Url, String), // (url, error message)
    ConnectionAccepted(String, String),  // (local url, remote url)
    ConnectionError(String, String, String), // (local url, remote url, error message)
    ListenerPortMappingEstablished {
        local_listener: url::Url,
        mapped_listener: url::Url,
        backend: String,
    },

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),
    PublicIpv6Changed(Option<cidr::Ipv6Inet>, Option<cidr::Ipv6Inet>), // (old, new)
    PublicIpv6RoutesUpdated(Vec<cidr::Ipv6Inet>, Vec<cidr::Ipv6Inet>), // (added, removed)

    PortForwardAdded(PortForwardConfigPb),

    ConfigPatched(InstanceConfigPatch),

    ProxyCidrsUpdated(Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>), // (added, removed)

    UdpBroadcastRelayStartResult {
        capture_backend: Option<String>,
        error: Option<String>,
    },

    CredentialChanged,
    MulticastGroupsUpdated,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

/// Source of a trusted public key from OSPF route propagation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeySource {
    /// Peer node's noise static pubkey
    OspfNode,
    /// Admin-declared trusted credential pubkey
    OspfCredential,
}

/// Metadata for a trusted public key
#[derive(Debug, Clone)]
pub struct TrustedKeyMetadata {
    pub source: TrustedKeySource,
    /// Expiry time in Unix seconds. None means never expires.
    pub expiry_unix: Option<i64>,
}

impl TrustedKeyMetadata {
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_unix {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            return now >= expiry;
        }
        false
    }
}

// key is (pubkey, network-name)
pub type TrustedKeyMap = HashMap<Vec<u8>, TrustedKeyMetadata>;

struct TrustedKeyMapManager {
    network_trusted_keys: DashMap<String, ArcSwap<TrustedKeyMap>>,
}

impl TrustedKeyMapManager {
    pub fn new() -> Self {
        Self {
            network_trusted_keys: DashMap::new(),
        }
    }

    pub fn update_trusted_keys(&self, network_name: &str, trusted_keys: TrustedKeyMap) {
        match self.network_trusted_keys.entry(network_name.to_string()) {
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ArcSwap::new(Arc::new(trusted_keys)));
            }
            dashmap::Entry::Occupied(entry) => {
                entry.get().store(Arc::new(trusted_keys));
            }
        }
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.network_trusted_keys.remove(network_name);
        shrink_dashmap(&self.network_trusted_keys, None);
    }

    pub fn verify_trusted_key(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.verify_trusted_key_with_source(pubkey, network_name, None)
    }

    pub fn verify_trusted_key_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: Option<TrustedKeySource>,
    ) -> bool {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return false;
        };

        let Some(metadata) = trusted_keys.get(&pubkey.to_vec()) else {
            return false;
        };

        if let Some(source) = source {
            metadata.source == source && !metadata.is_expired()
        } else {
            !metadata.is_expired()
        }
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return Vec::new();
        };

        let mut items = trusted_keys
            .iter()
            .filter(|(_, metadata)| !metadata.is_expired())
            .map(|(pubkey, metadata)| (pubkey.clone(), metadata.clone()))
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.0.cmp(&right.0));
        items
    }
}

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_lease: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_routes: Mutex<BTreeSet<std::net::Ipv6Addr>>,
    multicast_membership_state: Mutex<MulticastMembershipState>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<url::Url>>,
    advertised_ipv6_public_addr_prefix: Mutex<Option<cidr::Ipv6Cidr>>,
    tun_device_name: Mutex<Option<String>>,

    flags: ArcSwap<Flags>,
    underlay_policy: Arc<ArcSwap<UnderlayPolicy>>,

    // Runtime/base advertised feature flags before config-owned fields are
    // overlaid by set_flags. Keep this separate so config patches do not erase
    // runtime state such as public-server role, IPv6 provider status, or the
    // non-whitelist avoid-relay preference.
    base_feature_flags: AtomicCell<PeerFeatureFlag>,

    feature_flags: AtomicCell<PeerFeatureFlag>,

    token_bucket_manager: TokenBucketManager,

    stats_manager: Arc<StatsManager>,
    dataplane_telemetry: Arc<DataplaneTelemetry>,

    acl_filter: Arc<AclFilter>,

    credential_manager: Arc<CredentialManager>,

    /// OSPF propagated trusted keys (peer pubkeys and admin credentials)
    /// Stored in ArcSwap for lock-free reads and atomic batch updates
    trusted_keys: Arc<TrustedKeyMapManager>,

    fec_resource_budget: Arc<FecResourceBudget>,
    process_memory_governor: Arc<ProcessMemoryGovernor>,
}

impl std::fmt::Debug for GlobalCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCtx")
            .field("inst_name", &self.inst_name)
            .field("id", &self.id)
            .field("net_ns", &self.net_ns.name())
            .field("event_bus", &"EventBus")
            .field("ipv4", &self.cached_ipv4)
            .finish()
    }
}

pub type ArcGlobalCtx = std::sync::Arc<GlobalCtx>;

/// Identifies the edge reporter that announced a multicast membership.
///
/// The key keeps VLAN context and both source identities. This prevents a
/// leave from one edge host or VLAN from removing another host membership.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MulticastReporterKey {
    pub vlan_tags: [u16; 4],
    pub vlan_len: u8,
    pub source_mac: [u8; 6],
    pub source_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct MulticastMembershipKey {
    reporter: MulticastReporterKey,
    group: IpAddr,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MulticastMembershipWorkCounters {
    /// Number of report entries processed by the membership state.
    pub updates: u64,
    /// Number of live membership entries removed by expiry or capacity eviction.
    pub expired_or_evicted: u64,
    /// Number of deadline index entries popped from the head.
    pub deadline_index_pops: u64,
    /// Number of stale deadline index entries discarded from the head.
    pub stale_deadline_entries: u64,
    /// Number of group reference count changes.
    pub group_refcount_updates: u64,
    /// Full-map scans must remain zero on the report path.
    pub full_map_scans: u64,
}

#[derive(Debug)]
struct MulticastMembershipEntry {
    deadline: Instant,
}

#[derive(Debug)]
struct MulticastMembershipState {
    configured_groups: BTreeSet<IpAddr>,
    memberships: HashMap<MulticastMembershipKey, MulticastMembershipEntry>,
    group_refcounts: HashMap<IpAddr, usize>,
    deadline_index: BTreeSet<(Instant, MulticastMembershipKey)>,
    next_expiry: Option<Instant>,
    expiry_notify: Arc<tokio::sync::Notify>,
    work: MulticastMembershipWorkCounters,
}

impl MulticastMembershipState {
    fn new() -> Self {
        Self {
            configured_groups: BTreeSet::new(),
            memberships: HashMap::new(),
            group_refcounts: HashMap::new(),
            deadline_index: BTreeSet::new(),
            next_expiry: None,
            expiry_notify: Arc::new(tokio::sync::Notify::new()),
            work: MulticastMembershipWorkCounters::default(),
        }
    }

    fn advertised_groups(&self) -> BTreeSet<IpAddr> {
        let mut groups = self.configured_groups.clone();
        groups.extend(
            self.group_refcounts
                .iter()
                .filter_map(|(group, count)| (*count > 0).then_some(*group)),
        );
        groups
    }

    fn refresh_next_expiry(&mut self) {
        self.next_expiry = self.deadline_index.first().map(|(deadline, _)| *deadline);
    }

    fn decrement_group_refcount(&mut self, group: IpAddr) -> bool {
        let Some(count) = self.group_refcounts.get_mut(&group) else {
            return false;
        };
        self.work.group_refcount_updates += 1;
        if *count <= 1 {
            self.group_refcounts.remove(&group);
            true
        } else {
            *count -= 1;
            false
        }
    }

    fn increment_group_refcount(&mut self, group: IpAddr) -> bool {
        let count = self.group_refcounts.entry(group).or_insert(0);
        self.work.group_refcount_updates += 1;
        let crossed_zero = *count == 0;
        *count += 1;
        crossed_zero
    }

    fn expire_from_deadline_head(&mut self, now: Instant) -> bool {
        let mut groups_changed = false;
        while let Some((deadline, key)) = self.deadline_index.first().copied() {
            if deadline > now {
                break;
            }
            self.deadline_index.pop_first();
            self.work.deadline_index_pops += 1;
            let is_current = self
                .memberships
                .get(&key)
                .is_some_and(|entry| entry.deadline == deadline);
            if !is_current {
                self.work.stale_deadline_entries += 1;
                continue;
            }
            self.memberships.remove(&key);
            self.work.expired_or_evicted += 1;
            let crossed_one = self.decrement_group_refcount(key.group);
            groups_changed |= crossed_one && !self.configured_groups.contains(&key.group);
        }
        self.refresh_next_expiry();
        groups_changed
    }

    fn refresh_membership_deadline(
        &mut self,
        key: MulticastMembershipKey,
        deadline: Instant,
    ) -> bool {
        let Some(old_deadline) = self.memberships.get(&key).map(|entry| entry.deadline) else {
            return false;
        };
        if old_deadline == deadline {
            return true;
        }
        self.deadline_index.remove(&(old_deadline, key));
        self.memberships
            .get_mut(&key)
            .expect("membership exists after deadline lookup")
            .deadline = deadline;
        self.deadline_index.insert((deadline, key));
        true
    }

    fn remove_membership(&mut self, key: MulticastMembershipKey) -> bool {
        let Some(entry) = self.memberships.remove(&key) else {
            return false;
        };
        self.deadline_index.remove(&(entry.deadline, key));
        let crossed_one = self.decrement_group_refcount(key.group);
        crossed_one && !self.configured_groups.contains(&key.group)
    }

    fn evict_oldest(&mut self) -> Option<(IpAddr, bool)> {
        while let Some((deadline, key)) = self.deadline_index.pop_first() {
            self.work.deadline_index_pops += 1;
            let is_current = self
                .memberships
                .get(&key)
                .is_some_and(|entry| entry.deadline == deadline);
            if !is_current {
                self.work.stale_deadline_entries += 1;
                continue;
            }
            self.memberships.remove(&key);
            self.work.expired_or_evicted += 1;
            let crossed_one = self.decrement_group_refcount(key.group);
            self.refresh_next_expiry();
            return Some((key.group, crossed_one));
        }
        self.refresh_next_expiry();
        None
    }
}

pub(crate) const MAX_MULTICAST_MEMBERSHIPS: usize = 4096;
pub(crate) const MULTICAST_MEMBERSHIP_TTL: Duration = Duration::from_secs(260);

impl GlobalCtx {
    fn apply_required_feature_flags(
        flags: &Flags,
        mut feature_flags: PeerFeatureFlag,
    ) -> PeerFeatureFlag {
        if flags.disable_relay_data {
            feature_flags.avoid_relay_data = true;
        }
        feature_flags.speed_routing = true;
        feature_flags.relay_origin_proof = true;
        feature_flags
    }

    fn derive_feature_flags(flags: &Flags, mut feature_flags: PeerFeatureFlag) -> PeerFeatureFlag {
        feature_flags.kcp_input = !flags.disable_kcp_input;
        feature_flags.no_relay_kcp = flags.disable_relay_kcp;
        feature_flags.support_conn_list_sync = true;
        feature_flags.quic_input = !flags.disable_quic_input;
        feature_flags.no_relay_quic = flags.disable_relay_quic;
        feature_flags.need_p2p = flags.need_p2p;
        feature_flags.disable_p2p = flags.disable_p2p;
        let port_mode = PortMode::from_flags(flags);
        feature_flags.ethernet_input = port_mode.uses_ethernet_overlay();
        feature_flags.hybrid_l3 = true;
        feature_flags.bridge_input = port_mode.allows_bridge_input(flags.enable_bridge);
        feature_flags.multicast_membership = true;
        Self::apply_required_feature_flags(flags, feature_flags)
    }

    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        let secure_mode = match config_fs.get_secure_mode() {
            Some(secure_mode) => Some(
                process_secure_mode_cfg(secure_mode)
                    .expect("secure mode configuration must be valid"),
            ),
            None => Some(
                process_secure_mode_cfg(SecureModeConfig {
                    enabled: true,
                    local_private_key: None,
                    local_public_key: None,
                    credential_bundle: None,
                    credential_root_fingerprint: Vec::new(),
                    credential_certificate: Vec::new(),
                })
                .expect("automatic secure mode configuration must be valid"),
            ),
        };
        config_fs.set_secure_mode(secure_mode);
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();

        let (event_bus, _) = tokio::sync::broadcast::channel(16);

        let mut stun_info_collector = StunInfoCollector::new_with_default_servers();

        if let Some(stun_servers) = config_fs.get_stun_servers() {
            stun_info_collector.set_stun_servers(stun_servers);
        } else {
            stun_info_collector.set_stun_servers(StunInfoCollector::get_default_servers());
        }

        if let Some(stun_servers) = config_fs.get_stun_servers_v6() {
            stun_info_collector.set_stun_servers_v6(stun_servers);
        } else {
            stun_info_collector.set_stun_servers_v6(StunInfoCollector::get_default_servers_v6());
        }

        let flags = config_fs.get_flags();
        validate_flags(&flags).expect("configuration flags must be valid");
        let underlay_policy = Arc::new(ArcSwap::new(Arc::new(
            UnderlayPolicy::new(&flags.underlay_deny_interfaces, &flags.underlay_deny_cidrs)
                .expect("underlay policy was validated"),
        )));
        stun_info_collector.set_underlay_policy_source(underlay_policy.clone());
        let stun_info_collector = Arc::new(stun_info_collector);

        let base_feature_flags = PeerFeatureFlag::default();
        let feature_flags = Self::derive_feature_flags(&flags, base_feature_flags);

        let credential_storage_path = config_fs.get_credential_file();
        let secure_mode = config_fs.get_secure_mode();
        let network_secret = network
            .network_secret
            .as_deref()
            .filter(|secret| !secret.is_empty());
        if network_secret.is_some()
            && secure_mode
                .as_ref()
                .and_then(|secure_mode| secure_mode.credential_bundle.as_deref())
                .is_some()
        {
            panic!("network secret and credential bundle cannot be used together");
        }
        if network.is_credential_marker()
            && secure_mode
                .as_ref()
                .and_then(|secure_mode| secure_mode.credential_bundle.as_deref())
                .is_none()
        {
            panic!("credential identity requires a signed credential bundle");
        }
        let credential_manager = if let Some(network_secret) = network_secret {
            CredentialManager::new_with_network(
                credential_storage_path,
                network.network_name.clone(),
                Some(network_secret),
            )
        } else {
            let credential_bundle = secure_mode
                .as_ref()
                .and_then(|secure_mode| secure_mode.credential_bundle.as_deref());
            CredentialManager::new_with_network_and_bundle_pinned(
                credential_storage_path,
                network.network_name.clone(),
                None,
                credential_bundle,
                network
                    .credential_root_fingerprint()
                    .map(|fingerprint| fingerprint.as_slice()),
            )
            .unwrap_or_else(|error| {
                panic!("credential identity failed validation before startup: {error}")
            })
        };
        let credential_manager = Arc::new(credential_manager);
        let process_memory_governor = global_process_memory_governor();

        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,

            event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_ipv6: AtomicCell::new(None),
            public_ipv6_lease: AtomicCell::new(None),
            public_ipv6_routes: Mutex::new(BTreeSet::new()),
            multicast_membership_state: Mutex::new(MulticastMembershipState::new()),
            cached_proxy_cidrs: AtomicCell::new(None),

            ip_collector: Mutex::new(Some(Arc::new(IPCollector::new(
                net_ns,
                stun_info_collector.clone(),
                underlay_policy.clone(),
            )))),

            hostname: Mutex::new(hostname),

            stun_info_collection: Mutex::new(stun_info_collector),

            running_listeners: Mutex::new(Vec::new()),
            advertised_ipv6_public_addr_prefix: Mutex::new(None),
            tun_device_name: Mutex::new(None),

            flags: ArcSwap::new(Arc::new(flags)),
            underlay_policy,

            base_feature_flags: AtomicCell::new(base_feature_flags),

            feature_flags: AtomicCell::new(feature_flags),

            token_bucket_manager: TokenBucketManager::new(),

            stats_manager: Arc::new(StatsManager::new()),
            dataplane_telemetry: Arc::new(DataplaneTelemetry::new()),

            acl_filter: Arc::new(AclFilter::new()),

            credential_manager,

            trusted_keys: Arc::new(TrustedKeyMapManager::new()),

            fec_resource_budget: Arc::new(FecResourceBudget::with_process(
                FEC_INSTANCE_MAX_RETAINED_BYTES,
                process_memory_governor.clone(),
            )),
            process_memory_governor,
        }
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
    }

    fn set_tun_device_name(&self, name: Option<String>) {
        *self.tun_device_name.lock().unwrap() = name;
    }

    pub(crate) fn set_tun_device_ready(&self, name: String) {
        self.set_tun_device_name(Some(name.clone()));
        self.issue_event(GlobalCtxEvent::TunDeviceReady(name));
    }

    pub(crate) fn set_tun_device_error(&self, error: String) {
        self.set_tun_device_name(None);
        self.issue_event(GlobalCtxEvent::TunDeviceError(error));
    }

    pub fn get_tun_device_name(&self) -> Option<String> {
        self.tun_device_name.lock().unwrap().clone()
    }

    pub fn get_multicast_groups(&self) -> BTreeSet<std::net::IpAddr> {
        let now = Instant::now();
        let (groups, changed) = {
            let mut state = self.multicast_membership_state.lock().unwrap();
            let changed = state.expire_from_deadline_head(now);
            (state.advertised_groups(), changed)
        };
        if changed {
            self.issue_event(GlobalCtxEvent::MulticastGroupsUpdated);
        }
        groups
    }

    pub fn set_multicast_groups(&self, groups: BTreeSet<std::net::IpAddr>) -> bool {
        const MAX_MULTICAST_GROUPS: usize = 256;
        let groups = groups
            .into_iter()
            .filter(std::net::IpAddr::is_multicast)
            .take(MAX_MULTICAST_GROUPS)
            .collect();
        let mut state = self.multicast_membership_state.lock().unwrap();
        if state.configured_groups == groups {
            return false;
        }
        state.configured_groups = groups;
        drop(state);
        self.issue_event(GlobalCtxEvent::MulticastGroupsUpdated);
        true
    }

    /// Updates one reporter membership and returns whether the advertised group set changed.
    pub(crate) fn update_multicast_membership(
        &self,
        reporter: MulticastReporterKey,
        group: IpAddr,
        joined: bool,
        now: Instant,
    ) -> bool {
        self.update_multicast_memberships(&[(reporter, group, joined)], now)
    }

    /// Updates a batch of reporter memberships while holding each state lock once.
    pub(crate) fn update_multicast_memberships(
        &self,
        updates: &[(MulticastReporterKey, IpAddr, bool)],
        now: Instant,
    ) -> bool {
        if updates.is_empty() {
            return false;
        }
        let deadline = now + MULTICAST_MEMBERSHIP_TTL;
        let (changed, expiry_notify) = {
            let mut state = self.multicast_membership_state.lock().unwrap();
            let mut changed = state.expire_from_deadline_head(now);

            for &(reporter, group, joined) in updates {
                if !group.is_multicast() {
                    continue;
                }
                state.work.updates += 1;
                let key = MulticastMembershipKey { reporter, group };
                if joined {
                    if state.memberships.contains_key(&key) {
                        debug_assert!(state.refresh_membership_deadline(key, deadline));
                    } else {
                        while state.memberships.len() >= MAX_MULTICAST_MEMBERSHIPS {
                            let Some((evicted_group, crossed_one)) = state.evict_oldest() else {
                                break;
                            };
                            changed |=
                                crossed_one && !state.configured_groups.contains(&evicted_group);
                        }
                        if state.memberships.len() >= MAX_MULTICAST_MEMBERSHIPS {
                            continue;
                        }
                        let crossed_zero = state.increment_group_refcount(group);
                        changed |= crossed_zero && !state.configured_groups.contains(&group);
                        state
                            .memberships
                            .insert(key, MulticastMembershipEntry { deadline });
                        state.deadline_index.insert((deadline, key));
                    }
                } else {
                    changed |= state.remove_membership(key);
                }
            }
            state.refresh_next_expiry();
            (changed, state.expiry_notify.clone())
        };
        expiry_notify.notify_one();
        changed
    }

    /// Removes expired reporter entries and returns whether advertised groups changed.
    pub(crate) fn expire_multicast_memberships(&self, now: Instant) -> bool {
        let (changed, expiry_notify) = {
            let mut state = self.multicast_membership_state.lock().unwrap();
            let changed = state.expire_from_deadline_head(now);
            (changed, state.expiry_notify.clone())
        };
        expiry_notify.notify_one();
        if changed {
            self.issue_event(GlobalCtxEvent::MulticastGroupsUpdated);
        }
        changed
    }

    pub(crate) fn multicast_membership_next_expiry(&self) -> Option<Instant> {
        self.multicast_membership_state.lock().unwrap().next_expiry
    }

    pub(crate) fn multicast_membership_notify(&self) -> Arc<tokio::sync::Notify> {
        let notify = self
            .multicast_membership_state
            .lock()
            .unwrap()
            .expiry_notify
            .clone();
        notify
    }

    pub(crate) fn multicast_membership_work_counters(&self) -> MulticastMembershipWorkCounters {
        self.multicast_membership_state.lock().unwrap().work
    }

    pub fn check_network_in_whitelist(&self, network_name: &str) -> Result<(), anyhow::Error> {
        if self
            .get_flags()
            .relay_network_whitelist
            .split(" ")
            .map(wildmatch::WildMatch::new)
            .any(|wl| wl.matches(network_name))
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("network {} not in whitelist", network_name))
        }
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr);
        addr
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.set_ipv4(addr);
        self.cached_ipv4.store(None);
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        if let Some(ret) = self.cached_ipv6.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv6();
        self.cached_ipv6.store(addr);
        addr
    }

    pub fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.set_ipv6(addr);
        self.cached_ipv6.store(None);
    }

    pub fn get_public_ipv6_lease(&self) -> Option<cidr::Ipv6Inet> {
        self.public_ipv6_lease.load()
    }

    pub fn set_public_ipv6_lease(&self, addr: Option<cidr::Ipv6Inet>) {
        self.public_ipv6_lease.store(addr);
    }

    pub fn set_public_ipv6_routes(&self, routes: BTreeSet<cidr::Ipv6Inet>) {
        *self.public_ipv6_routes.lock().unwrap() =
            routes.into_iter().map(|route| route.address()).collect();
    }

    pub fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_ipv6().map(|x| x.address() == *ip).unwrap_or(false)
            || self
                .get_public_ipv6_lease()
                .map(|x| x.address() == *ip)
                .unwrap_or(false)
    }

    pub fn is_ip_lowertier_managed_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.is_ip_local_ipv6(ip) || self.public_ipv6_routes.lock().unwrap().contains(ip)
    }

    pub fn get_advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        *self.advertised_ipv6_public_addr_prefix.lock().unwrap()
    }

    pub fn set_advertised_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>) -> bool {
        let mut guard = self.advertised_ipv6_public_addr_prefix.lock().unwrap();
        if *guard == prefix {
            return false;
        }

        *guard = prefix;
        true
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.config.get_id()
    }

    pub fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.contains(v4)).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.contains(v6)).unwrap_or(false),
        }
    }

    pub fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.address() == *v4).unwrap_or(false),
            IpAddr::V6(v6) => self.is_ip_local_ipv6(v6),
        }
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.config.get_network_identity()
    }

    pub fn get_secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let network_secret = self
            .get_network_identity()
            .network_secret
            .filter(|secret| !secret.is_empty())?;
        let key = network_secret.as_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(b"lowertier secret proof");
        mac.update(challenge);
        Some(mac)
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.lock().unwrap().as_ref().unwrap().clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_stun_info_collector(&self) -> Arc<dyn StunInfoCollectorTrait> {
        self.stun_info_collection.lock().unwrap().clone()
    }

    pub fn replace_stun_info_collector(&self, collector: Box<dyn StunInfoCollectorTrait>) {
        let arc_collector: Arc<dyn StunInfoCollectorTrait> = Arc::new(collector);
        *self.stun_info_collection.lock().unwrap() = arc_collector.clone();

        // rebuild the ip collector
        *self.ip_collector.lock().unwrap() = Some(Arc::new(IPCollector::new(
            self.net_ns.clone(),
            arc_collector,
            self.underlay_policy.clone(),
        )));
    }

    pub fn get_running_listeners(&self) -> Vec<url::Url> {
        self.running_listeners.lock().unwrap().clone()
    }

    pub fn add_running_listener(&self, url: url::Url) {
        let mut l = self.running_listeners.lock().unwrap();
        if !l.contains(&url) {
            l.push(url);
        }
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.flags.load().as_ref().clone()
    }

    pub(crate) fn fec_resource_budget(&self) -> Arc<FecResourceBudget> {
        self.fec_resource_budget.clone()
    }

    pub(crate) fn process_memory_governor(&self) -> Arc<ProcessMemoryGovernor> {
        self.process_memory_governor.clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        if let Err(error) = validate_flags(&flags) {
            tracing::error!(?error, "rejected invalid runtime flags");
            return;
        }
        let policy =
            UnderlayPolicy::new(&flags.underlay_deny_interfaces, &flags.underlay_deny_cidrs)
                .expect("underlay policy was validated");
        self.config.set_flags(flags.clone());
        self.feature_flags.store(Self::derive_feature_flags(
            &flags,
            self.base_feature_flags.load(),
        ));
        self.underlay_policy.store(Arc::new(policy));
        self.flags.store(Arc::new(flags));
    }

    pub fn get_underlay_policy(&self) -> Arc<UnderlayPolicy> {
        self.underlay_policy.load_full()
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        self.flags.load_full()
    }

    pub fn get_128_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..8]);
        key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..16]);
        key
    }

    pub fn get_256_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        hasher.write(b"lowertier-256bit-key"); // 添加固定盐值以区分128位和256位密钥

        // 生成32字节密钥
        for i in 0..4 {
            let chunk_start = i * 8;
            let chunk_end = chunk_start + 8;
            hasher.write(&key[0..chunk_start]);
            hasher.write(&[i as u8]); // 添加索引以确保每个8字节块都不同
            key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
        }
        key
    }

    pub fn enable_exit_node(&self) -> bool {
        self.flags.load().enable_exit_node || cfg!(target_env = "ohos")
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.flags.load().proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.flags.load().no_tun
    }

    pub fn get_feature_flags(&self) -> PeerFeatureFlag {
        self.feature_flags.load()
    }

    /// Replace the runtime/base advertised flags as a complete snapshot.
    ///
    /// This is intended for foreign scoped contexts that inherit an already
    /// computed feature-flag snapshot from their parent. Most callers should use
    /// a narrower setter so they do not accidentally overwrite unrelated runtime
    /// state.
    pub fn set_base_advertised_feature_flags(&self, feature_flags: PeerFeatureFlag) {
        self.base_feature_flags.store(feature_flags);
        let flags = self.flags.load();
        self.feature_flags.store(Self::apply_required_feature_flags(
            flags.as_ref(),
            feature_flags,
        ));
    }

    /// Set the avoid-relay preference that is independent of disable_relay_data.
    ///
    /// disable_relay_data still forces the effective advertised flag to true,
    /// but this base preference is preserved when that config flag is toggled.
    pub fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        let mut base_feature_flags = self.base_feature_flags.load();
        base_feature_flags.avoid_relay_data = avoid_relay_data;
        self.base_feature_flags.store(base_feature_flags);

        let mut feature_flags = self.feature_flags.load();
        let previous = feature_flags.avoid_relay_data;
        feature_flags.avoid_relay_data = avoid_relay_data || self.flags.load().disable_relay_data;
        self.feature_flags.store(feature_flags);
        previous != feature_flags.avoid_relay_data
    }

    /// Set the runtime IPv6-provider advertised bit without touching
    /// config-derived feature flags.
    pub fn set_ipv6_public_addr_provider_feature_flag(&self, enabled: bool) -> bool {
        let mut base_feature_flags = self.base_feature_flags.load();
        base_feature_flags.ipv6_public_addr_provider = enabled;
        self.base_feature_flags.store(base_feature_flags);

        let mut feature_flags = self.feature_flags.load();
        if feature_flags.ipv6_public_addr_provider == enabled {
            return false;
        }

        feature_flags.ipv6_public_addr_provider = enabled;
        self.feature_flags.store(feature_flags);
        true
    }

    pub fn token_bucket_manager(&self) -> &TokenBucketManager {
        &self.token_bucket_manager
    }

    pub fn stats_manager(&self) -> &Arc<StatsManager> {
        &self.stats_manager
    }

    pub fn dataplane_telemetry(&self) -> &Arc<DataplaneTelemetry> {
        &self.dataplane_telemetry
    }

    pub fn get_acl_filter(&self) -> &Arc<AclFilter> {
        &self.acl_filter
    }

    pub fn get_credential_manager(&self) -> &Arc<CredentialManager> {
        &self.credential_manager
    }

    /// Check if a public key is trusted using two-level lookup:
    /// 1. OSPF propagated trusted_keys (lock-free)
    /// 2. Local credential_manager
    pub fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        // First level: check OSPF propagated keys (lock-free)
        if self.trusted_keys.verify_trusted_key(pubkey, network_name) {
            return true;
        }

        // Second level: check local credential_manager if in the same network
        if network_name == self.get_network_name() {
            return self.credential_manager.is_pubkey_trusted(pubkey);
        }

        false
    }

    pub fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.trusted_keys
            .verify_trusted_key_with_source(pubkey, network_name, Some(source))
    }

    /// Atomically replace all OSPF trusted keys with a new set
    /// Called by OSPF route layer after each route update
    pub fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.trusted_keys.update_trusted_keys(network_name, keys);
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.trusted_keys.remove_trusted_keys(network_name);
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.trusted_keys.list_trusted_keys(network_name)
    }

    pub fn get_acl_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        use std::collections::HashSet;
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| {
                let memberships: HashSet<_> = group.members.iter().collect();
                group
                    .declares
                    .iter()
                    .filter(|g| memberships.contains(&g.group_name))
                    .map(|g| {
                        PeerGroupInfo::generate_with_proof(
                            g.group_name.clone(),
                            g.group_secret.clone(),
                            peer_id,
                        )
                    })
                    .collect()
            })
    }

    pub fn get_acl_group_declarations(&self) -> Vec<GroupIdentity> {
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| group.declares.to_vec())
    }

    pub fn p2p_only(&self) -> bool {
        self.flags.load().p2p_only
    }

    pub fn latency_first(&self) -> bool {
        // NOTICE: p2p only is conflict with latency first
        let flags = self.flags.load();
        flags.latency_first && !flags.p2p_only
    }

    pub fn speed_first(&self) -> bool {
        let flags = self.flags.load();
        flags.speed_first && !flags.p2p_only
    }

    pub fn speed_probes_enabled(&self) -> bool {
        self.flags.load().speed_probe_budget_bps > 0
    }

    fn is_port_in_running_listeners(&self, port: u16, is_udp: bool) -> bool {
        self.running_listeners
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.port() == Some(port) && matches_protocol!(x, Protocol::UDP) == is_udp)
    }

    #[tracing::instrument(ret, skip(self))]
    pub fn should_deny_proxy(&self, dst_addr: &SocketAddr, is_udp: bool) -> bool {
        let _g = self.net_ns.guard();
        let ip = dst_addr.ip();
        // first check if ip is an LowTier-managed local address
        // then try bind this ip, if succ means it is local ip
        let dst_is_local_et_ip = self.is_ip_local_virtual_ip(&ip);
        // this is an expensive operation, should be called sparingly
        // 1. tcp/kcp/quic call this only after proxy conn is established
        // 2. udp cache the result in nat entry
        let dst_is_local_phy_ip = std::net::UdpSocket::bind(format!("{}:0", ip)).is_ok();

        tracing::trace!(
            "check should_deny_proxy: dst_addr={}, dst_is_local_et_ip={}, dst_is_local_phy_ip={}, is_udp={}",
            dst_addr,
            dst_is_local_et_ip,
            dst_is_local_phy_ip,
            is_udp
        );

        if dst_is_local_et_ip || dst_is_local_phy_ip {
            // if is local ip, make sure the port is not one of the listening ports
            self.is_port_in_running_listeners(dst_addr.port(), is_udp)
                || (!is_udp && protected_port::is_protected_tcp_port(dst_addr.port()))
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::{config::TomlConfigLoader, new_peer_id, stun::MockStunInfoCollector},
        proto::common::NatType,
    };

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut subscriber = global_ctx.subscribe();
        let peer_id = new_peer_id();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default())
        );
    }

    #[tokio::test]
    async fn global_context_enables_secure_mode_automatically() {
        let config = TomlConfigLoader::default();
        config.set_secure_mode(None);

        let global_ctx = GlobalCtx::new(config);
        let secure_mode = global_ctx.config.get_secure_mode().unwrap();

        assert!(secure_mode.enabled);
        assert!(secure_mode.local_private_key.is_some());
        assert!(secure_mode.local_public_key.is_some());
    }

    #[tokio::test]
    async fn test_tun_device_name_tracks_explicit_runtime_state() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        assert_eq!(global_ctx.get_tun_device_name(), None);

        global_ctx.issue_event(GlobalCtxEvent::TunDeviceReady("ignored".to_string()));
        assert_eq!(global_ctx.get_tun_device_name(), None);

        let mut subscriber = global_ctx.subscribe();

        global_ctx.set_tun_device_ready("lowertier0".to_string());
        assert_eq!(
            global_ctx.get_tun_device_name(),
            Some("lowertier0".to_string())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceReady("lowertier0".to_string())
        );

        global_ctx.set_tun_device_error("closed".to_string());
        assert_eq!(global_ctx.get_tun_device_name(), None);
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceError("closed".to_string())
        );
    }

    #[test]
    fn multicast_memberships_are_reporter_scoped_and_vlan_scoped() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let group: IpAddr = "239.1.2.3".parse().unwrap();
        let now = Instant::now();
        let reporter_a = MulticastReporterKey {
            source_mac: [1, 2, 3, 4, 5, 6],
            vlan_tags: [100, 0, 0, 0],
            vlan_len: 1,
            ..MulticastReporterKey::default()
        };
        let reporter_b = MulticastReporterKey {
            source_mac: [7, 8, 9, 10, 11, 12],
            vlan_tags: [100, 0, 0, 0],
            vlan_len: 1,
            ..MulticastReporterKey::default()
        };
        let reporter_other_vlan = MulticastReporterKey {
            source_mac: reporter_a.source_mac,
            vlan_tags: [200, 0, 0, 0],
            vlan_len: 1,
            ..MulticastReporterKey::default()
        };

        assert!(global_ctx.update_multicast_membership(reporter_a, group, true, now));
        assert!(!global_ctx.update_multicast_membership(reporter_b, group, true, now));
        assert!(!global_ctx.update_multicast_membership(reporter_a, group, false, now));
        assert!(global_ctx.get_multicast_groups().contains(&group));

        assert!(!global_ctx.update_multicast_membership(reporter_other_vlan, group, true, now,));
        assert!(!global_ctx.update_multicast_membership(reporter_b, group, false, now,));
        assert!(global_ctx.get_multicast_groups().contains(&group));
        assert!(global_ctx.update_multicast_membership(reporter_other_vlan, group, false, now,));
        assert!(global_ctx.get_multicast_groups().is_empty());
    }

    #[test]
    fn multicast_memberships_expire_after_bounded_lifetime() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let group: IpAddr = "239.1.2.4".parse().unwrap();
        let now = Instant::now();
        let reporter = MulticastReporterKey {
            source_ip: Some("192.0.2.10".parse().unwrap()),
            ..MulticastReporterKey::default()
        };

        assert!(global_ctx.update_multicast_membership(reporter, group, true, now));
        assert!(global_ctx.get_multicast_groups().contains(&group));
        assert!(global_ctx.expire_multicast_memberships(now + MULTICAST_MEMBERSHIP_TTL));
        assert!(!global_ctx.get_multicast_groups().contains(&group));
    }

    #[test]
    fn multicast_membership_updates_touch_only_report_entries() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let now = Instant::now();
        let updates = (0..MAX_MULTICAST_MEMBERSHIPS)
            .map(|index| {
                let reporter = MulticastReporterKey {
                    source_mac: [
                        (index & 0xff) as u8,
                        ((index >> 8) & 0xff) as u8,
                        1,
                        2,
                        3,
                        4,
                    ],
                    ..MulticastReporterKey::default()
                };
                let group = IpAddr::V4(std::net::Ipv4Addr::new(
                    239,
                    1,
                    (index / 255) as u8,
                    (index % 255) as u8,
                ));
                (reporter, group, true)
            })
            .collect::<Vec<_>>();
        assert!(global_ctx.update_multicast_memberships(&updates, now));

        let refreshes = updates[..256]
            .iter()
            .map(|(reporter, group, _)| (*reporter, *group, true))
            .collect::<Vec<_>>();
        let before = global_ctx.multicast_membership_work_counters();
        assert!(!global_ctx.update_multicast_memberships(&refreshes, now + Duration::from_secs(1)));
        let after = global_ctx.multicast_membership_work_counters();

        assert_eq!(after.updates - before.updates, 256);
        assert_eq!(after.full_map_scans, 0);
        assert_eq!(
            global_ctx.get_multicast_groups().len(),
            MAX_MULTICAST_MEMBERSHIPS
        );
    }

    #[test]
    fn multicast_membership_refresh_keeps_entry_until_new_deadline() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let group: IpAddr = "239.1.2.5".parse().unwrap();
        let reporter = MulticastReporterKey {
            source_mac: [9, 8, 7, 6, 5, 4],
            ..MulticastReporterKey::default()
        };
        let now = Instant::now();

        assert!(global_ctx.update_multicast_membership(reporter, group, true, now));
        assert!(!global_ctx.update_multicast_membership(
            reporter,
            group,
            true,
            now + MULTICAST_MEMBERSHIP_TTL / 2,
        ));
        assert_eq!(
            global_ctx
                .multicast_membership_state
                .lock()
                .unwrap()
                .deadline_index
                .len(),
            1
        );
        assert!(!global_ctx.expire_multicast_memberships(now + MULTICAST_MEMBERSHIP_TTL));
        assert!(global_ctx.get_multicast_groups().contains(&group));
        assert!(global_ctx.expire_multicast_memberships(
            now + MULTICAST_MEMBERSHIP_TTL + MULTICAST_MEMBERSHIP_TTL / 2,
        ));
        assert!(!global_ctx.get_multicast_groups().contains(&group));

        assert_eq!(
            global_ctx
                .multicast_membership_state
                .lock()
                .unwrap()
                .deadline_index
                .len(),
            0
        );
        let work = global_ctx.multicast_membership_work_counters();
        assert_eq!(work.stale_deadline_entries, 0);
        assert_eq!(work.full_map_scans, 0);
    }

    #[test]
    fn multicast_membership_expiry_discards_stale_deadline_index_entries() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let now = Instant::now();
        let stale_key = MulticastMembershipKey {
            reporter: MulticastReporterKey {
                source_mac: [4, 3, 2, 1, 0, 9],
                ..MulticastReporterKey::default()
            },
            group: "239.1.2.9".parse().unwrap(),
        };
        {
            let mut state = global_ctx.multicast_membership_state.lock().unwrap();
            state
                .deadline_index
                .insert((now - Duration::from_secs(1), stale_key));
            state.refresh_next_expiry();
        }

        assert!(!global_ctx.expire_multicast_memberships(now));
        let state = global_ctx.multicast_membership_state.lock().unwrap();
        assert!(state.deadline_index.is_empty());
        assert_eq!(state.memberships.len(), 0);
        assert_eq!(state.work.stale_deadline_entries, 1);
    }

    #[test]
    fn multicast_membership_capacity_evicts_oldest_deadline() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let now = Instant::now();
        let oldest_group: IpAddr = "239.1.2.6".parse().unwrap();
        let oldest_reporter = MulticastReporterKey {
            source_mac: [0, 0, 0, 0, 0, 1],
            ..MulticastReporterKey::default()
        };
        assert!(global_ctx.update_multicast_membership(oldest_reporter, oldest_group, true, now,));

        let mut fill = Vec::with_capacity(MAX_MULTICAST_MEMBERSHIPS - 1);
        for index in 1..MAX_MULTICAST_MEMBERSHIPS {
            let reporter = MulticastReporterKey {
                source_mac: [
                    (index & 0xff) as u8,
                    ((index >> 8) & 0xff) as u8,
                    2,
                    3,
                    4,
                    5,
                ],
                ..MulticastReporterKey::default()
            };
            let group = IpAddr::V4(std::net::Ipv4Addr::new(
                239,
                2,
                (index / 255) as u8,
                (index % 255) as u8,
            ));
            fill.push((reporter, group, true));
        }
        assert!(global_ctx.update_multicast_memberships(&fill, now + Duration::from_millis(1)));

        let new_group: IpAddr = "239.1.2.7".parse().unwrap();
        let new_reporter = MulticastReporterKey {
            source_mac: [0, 0, 0, 0, 0, 255],
            ..MulticastReporterKey::default()
        };
        assert!(global_ctx.update_multicast_membership(
            new_reporter,
            new_group,
            true,
            now + Duration::from_millis(2),
        ));
        assert!(!global_ctx.get_multicast_groups().contains(&oldest_group));
        assert!(global_ctx.get_multicast_groups().contains(&new_group));
        assert_eq!(
            global_ctx
                .multicast_membership_work_counters()
                .full_map_scans,
            0
        );
    }

    #[test]
    fn multicast_membership_report_without_change_does_not_emit_event() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        let group: IpAddr = "239.1.2.8".parse().unwrap();
        let reporter = MulticastReporterKey {
            source_mac: [1, 1, 1, 1, 1, 1],
            ..MulticastReporterKey::default()
        };
        let mut subscriber = global_ctx.subscribe();
        let now = Instant::now();

        assert!(global_ctx.update_multicast_membership(reporter, group, true, now));
        global_ctx.issue_event(GlobalCtxEvent::MulticastGroupsUpdated);
        assert_eq!(
            subscriber.try_recv().unwrap(),
            GlobalCtxEvent::MulticastGroupsUpdated
        );
        assert!(!global_ctx.update_multicast_membership(reporter, group, true, now));
        assert!(subscriber.try_recv().is_err());
        assert!(global_ctx.update_multicast_membership(reporter, group, false, now));
        assert_eq!(
            global_ctx
                .multicast_membership_state
                .lock()
                .unwrap()
                .deadline_index
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn trusted_key_source_lookup_is_precise() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let network_name = "net1";
        let pubkey = vec![1; 32];

        global_ctx.update_trusted_keys(
            HashMap::from([(
                pubkey.clone(),
                TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
            network_name,
        );

        assert!(global_ctx.is_pubkey_trusted(&pubkey, network_name));
        assert!(!global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfNode,
        ));
        assert!(global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfCredential,
        ));
    }

    #[tokio::test]
    async fn set_flags_keeps_derived_feature_flags_in_sync() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut feature_flags = global_ctx.get_feature_flags();
        feature_flags.avoid_relay_data = true;
        feature_flags.is_public_server = true;
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_kcp_input = true;
        flags.disable_relay_kcp = true;
        flags.disable_quic_input = true;
        flags.disable_relay_quic = true;
        flags.need_p2p = true;
        flags.disable_p2p = true;
        flags.port_mode = "ethernet".to_string();
        global_ctx.set_flags(flags);

        let feature_flags = global_ctx.get_feature_flags();
        assert!(!feature_flags.kcp_input);
        assert!(feature_flags.no_relay_kcp);
        assert!(!feature_flags.quic_input);
        assert!(feature_flags.no_relay_quic);
        assert!(feature_flags.need_p2p);
        assert!(feature_flags.disable_p2p);
        assert!(feature_flags.ethernet_input);
        assert!(feature_flags.hybrid_l3);
        assert!(feature_flags.bridge_input);
        assert!(feature_flags.support_conn_list_sync);
        assert!(feature_flags.avoid_relay_data);
        assert!(feature_flags.is_public_server);
        assert!(!feature_flags.ipv6_public_addr_provider);

        let mut flags = global_ctx.get_flags();
        flags.port_mode = "routed".to_string();
        global_ctx.set_flags(flags);
        let feature_flags = global_ctx.get_feature_flags();
        assert!(!feature_flags.ethernet_input);
        assert!(feature_flags.hybrid_l3);
        assert!(!feature_flags.bridge_input);
        assert!(feature_flags.multicast_membership);

        let mut flags = global_ctx.get_flags();
        flags.port_mode = "compatible-ethernet".to_string();
        global_ctx.set_flags(flags);
        let feature_flags = global_ctx.get_feature_flags();
        assert!(feature_flags.ethernet_input);
        assert!(feature_flags.hybrid_l3);
        assert!(feature_flags.bridge_input);

        let mut flags = global_ctx.get_flags();
        flags.port_mode = "auto".to_string();
        flags.enable_bridge = false;
        global_ctx.set_flags(flags);
        assert!(!global_ctx.get_feature_flags().bridge_input);

        let mut flags = global_ctx.get_flags();
        flags.enable_bridge = true;
        global_ctx.set_flags(flags);
        let feature_flags = global_ctx.get_feature_flags();
        assert!(feature_flags.hybrid_l3);
        assert!(feature_flags.multicast_membership);
        assert_eq!(
            feature_flags.bridge_input,
            cfg!(any(target_os = "linux", target_os = "freebsd"))
        );
    }

    #[tokio::test]
    async fn set_flags_refreshes_underlay_policy_and_rejects_invalid_updates() {
        let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
        assert!(
            global_ctx
                .get_underlay_policy()
                .allows_ip("100.108.186.13".parse().unwrap())
        );

        let mut flags = global_ctx.get_flags();
        flags.underlay_deny_interfaces = vec!["utun5".into()];
        flags.underlay_deny_cidrs = vec!["100.64.0.0/10".into()];
        global_ctx.set_flags(flags.clone());

        let policy = global_ctx.get_underlay_policy();
        assert!(!policy.allows_interface("utun5"));
        assert!(!policy.allows_ip("100.108.186.13".parse().unwrap()));

        flags.underlay_deny_cidrs = vec!["invalid".into()];
        global_ctx.set_flags(flags);
        assert_eq!(
            global_ctx.get_flags().underlay_deny_cidrs,
            ["100.64.0.0/10"]
        );
    }

    #[tokio::test]
    async fn set_base_advertised_feature_flags_applies_current_values() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let feature_flags = PeerFeatureFlag {
            kcp_input: false,
            no_relay_kcp: true,
            quic_input: false,
            no_relay_quic: true,
            is_public_server: true,
            ..Default::default()
        };
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        let advertised = global_ctx.get_feature_flags();
        assert!(advertised.speed_routing);
        assert_eq!(advertised.is_public_server, feature_flags.is_public_server);
        assert_eq!(advertised.kcp_input, feature_flags.kcp_input);
        assert_eq!(advertised.no_relay_kcp, feature_flags.no_relay_kcp);
        assert_eq!(advertised.quic_input, feature_flags.quic_input);
        assert_eq!(advertised.no_relay_quic, feature_flags.no_relay_quic);
    }

    #[tokio::test]
    async fn set_base_advertised_feature_flags_keeps_disable_relay_data_effective() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        let mut feature_flags = global_ctx.get_feature_flags();
        feature_flags.avoid_relay_data = false;
        feature_flags.is_public_server = true;
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        let advertised_feature_flags = global_ctx.get_feature_flags();
        assert!(advertised_feature_flags.avoid_relay_data);
        assert!(advertised_feature_flags.is_public_server);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        let advertised_feature_flags = global_ctx.get_feature_flags();
        assert!(!advertised_feature_flags.avoid_relay_data);
        assert!(advertised_feature_flags.is_public_server);
    }

    #[tokio::test]
    async fn disable_relay_data_sets_avoid_relay_feature_flag() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(!global_ctx.get_feature_flags().avoid_relay_data);

        global_ctx.set_avoid_relay_data_preference(true);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    #[serial_test::serial(protected_tcp_ports)]
    async fn should_deny_proxy_for_process_wide_rpc_port() {
        protected_port::clear_protected_tcp_ports_for_test();
        protected_port::register_protected_tcp_port(15888);

        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let rpc_addr = SocketAddr::from(([127, 0, 0, 1], 15888));
        let other_tcp_addr = SocketAddr::from(([127, 0, 0, 1], 15889));

        assert!(global_ctx.should_deny_proxy(&rpc_addr, false));
        assert!(!global_ctx.should_deny_proxy(&rpc_addr, true));
        assert!(!global_ctx.should_deny_proxy(&other_tcp_addr, false));

        protected_port::clear_protected_tcp_ports_for_test();
    }

    #[tokio::test]
    async fn virtual_ipv6_and_public_ipv6_lease_are_stored_separately() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let virtual_ipv6 = "fd00::1/64".parse().unwrap();
        let public_ipv6 = "2001:db8::2/64".parse().unwrap();

        global_ctx.set_ipv6(Some(virtual_ipv6));
        global_ctx.set_public_ipv6_lease(Some(public_ipv6));

        assert_eq!(global_ctx.get_ipv6(), Some(virtual_ipv6));
        assert_eq!(global_ctx.get_public_ipv6_lease(), Some(public_ipv6));
    }

    #[tokio::test]
    #[serial_test::serial(protected_tcp_ports)]
    async fn public_ipv6_lease_is_treated_as_local_ip() {
        protected_port::clear_protected_tcp_ports_for_test();

        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let public_ipv6 = "2001:db8::2/64".parse().unwrap();
        let listener: url::Url = "tcp://[2001:db8::2]:11010".parse().unwrap();
        global_ctx.set_public_ipv6_lease(Some(public_ipv6));
        global_ctx.add_running_listener(listener);

        let ip = std::net::IpAddr::V6(public_ipv6.address());
        let socket = SocketAddr::from((public_ipv6.address(), 11010));

        assert!(global_ctx.is_ip_local_virtual_ip(&ip));
        assert!(global_ctx.should_deny_proxy(&socket, false));

        protected_port::clear_protected_tcp_ports_for_test();
    }

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        let network_identity = network_identy.unwrap_or_else(|| {
            NetworkIdentity::new("default".to_owned(), "test-default-root".to_owned())
        });
        config_fs.set_network_identity(network_identity);

        let ctx = Arc::new(GlobalCtx::new(config_fs));
        ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        ctx
    }

    /// Create a mock context with an explicit signed credential bundle.
    pub fn get_mock_credential_global_ctx(network_name: impl Into<String>) -> ArcGlobalCtx {
        let network_name = network_name.into();
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));

        let issuer = CredentialManager::new_with_network(
            None,
            network_name.clone(),
            Some("test-credential-issuer"),
        );
        let (_, encoded_bundle) = issuer
            .generate_credential_bundle(
                Vec::new(),
                false,
                Vec::new(),
                Duration::from_secs(3600),
                None,
                true,
            )
            .expect("test credential issuer must sign a bundle");
        let bundle = CredentialManager::parse_credential_bundle(&encoded_bundle)
            .expect("test credential bundle must decode");
        config_fs.set_network_identity(
            crate::common::config::NetworkIdentity::new_credential_with_root_fingerprint(
                network_name,
                &bundle.root_fingerprint,
            )
            .expect("test credential root fingerprint must be valid"),
        );
        config_fs.set_secure_mode(Some(SecureModeConfig {
            enabled: true,
            local_private_key: None,
            local_public_key: None,
            credential_bundle: Some(encoded_bundle),
            credential_root_fingerprint: bundle.root_fingerprint,
            credential_certificate: bundle
                .certificate
                .map(|certificate| prost::Message::encode_to_vec(&certificate))
                .unwrap_or_default(),
        }));

        let ctx = Arc::new(GlobalCtx::new(config_fs));
        ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        ctx
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }

    #[test]
    fn mock_credential_context_uses_a_signed_bundle() {
        let global_ctx = get_mock_credential_global_ctx("credential-test");
        let secure_mode = global_ctx
            .config
            .get_secure_mode()
            .expect("credential context has secure mode");
        assert!(secure_mode.credential_bundle.is_some());
        assert!(secure_mode.local_private_key.is_some());
        assert!(secure_mode.local_public_key.is_some());
        assert!(
            global_ctx
                .get_network_identity()
                .credential_root_fingerprint()
                .is_some()
        );
    }
}
