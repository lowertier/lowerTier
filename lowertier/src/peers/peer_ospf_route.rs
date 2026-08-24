use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr, Ipv6Inet};
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use ordered_hash_map::OrderedHashMap;
use parking_lot::{RwLock, lock_api::RwLockUpgradableReadGuard};
use petgraph::{
    Directed,
    algo::dijkstra,
    graph::{Graph, NodeIndex},
    visit::{EdgeRef, IntoNodeReferences},
};
use prefix_trie::PrefixMap;
use prost::Message;
use prost_reflect::{DynamicMessage, ReflectMessage};
use quanta::Instant;
use sha2::Sha256;
use tokio::{
    select,
    sync::{Mutex, Notify},
    task::{JoinHandle, JoinSet},
};

use crate::{
    common::{
        PeerId,
        config::NetworkIdentity,
        constants::LOWTIER_VERSION,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, ProcessMemoryGovernor},
        shrink_dashmap,
        stats_manager::{LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
    },
    peers::route_trait::{
        AuthenticatedRoutePeerEvidence, BridgeRoutePeerEvidence, ForwardingDecisionSnapshot,
        ForwardingDecisionSnapshotHandle, ForwardingDecisionSnapshotSource, ForwardingNextHop,
        OriginAuthPublication, Route, RouteInterface, RouteInterfaceBox,
    },
    proto::{
        acl::GroupIdentity,
        common::{Ipv4Inet, NatType, StunInfo},
        peer_rpc::{
            ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, OspfRouteRpc,
            OspfRouteRpcClientFactory, OspfRouteRpcServer, PeerGroupInfo, PeerIdVersion,
            PeerIdentityType, PublicIpv6AddrRpcServer, RouteForeignNetworkInfos,
            RouteForeignNetworkSummary, RoutePeerInfo, RoutePeerInfos, SecureAuthLevel,
            SyncRouteInfoError, SyncRouteInfoRequest, SyncRouteInfoResponse,
            TrustedCredentialPubkey, TrustedCredentialPubkeyProof, route_foreign_network_infos,
            route_foreign_network_summary, sync_route_info_request::ConnInfo,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
    use_global_var,
};

use super::{
    graph_algo::{dijkstra_with_first_hop, dijkstra_with_first_hop_filtered},
    peer_rpc::PeerRpcManager,
    public_ipv6::{
        PublicIpv6PeerRouteInfo, PublicIpv6RouteControl, PublicIpv6Service, PublicIpv6SyncTrigger,
    },
    route_trait::{
        DefaultRouteCostCalculator, ForeignNetworkRouteInfoMap, NextHopPolicy, RouteCostCalculator,
        RouteCostCalculatorInterface, RouteQuality,
    },
    service_route::{ServiceRoute, ServiceRouteAction, ServiceRouteSnapshot},
};
use crate::peers::PUBLIC_SERVER_HOSTNAME_PREFIX;

use crate::proto::common::TimestampExt;
use atomic_shim::AtomicU64;
use prost_wkt_types::Timestamp;

static SERVICE_ID: u32 = 7;
static UPDATE_PEER_INFO_PERIOD: Duration = Duration::from_secs(3600);
static REMOVE_DEAD_PEER_INFO_AFTER: Duration = Duration::from_secs(3660);
// the cost (latency between two peers) is i32, i32::MAX is large enough.
static AVOID_RELAY_COST: usize = i32::MAX as usize;
static FORCE_USE_CONN_LIST: AtomicBool = AtomicBool::new(false);

// if a peer is unreachable for `REMOVE_UNREACHABLE_PEER_INFO_AFTER` time, we can remove it because
// 1. all the ospf sessions between two zone are already destroy, new created session will resend the peer info.
// 2. all the dst_saved_peer_info_version in all sessions already remove the peer info, the peer info will be propagated
//    in another zone when two zone restore the conneciton.
static REMOVE_UNREACHABLE_PEER_INFO_AFTER: Duration = Duration::from_secs(90);

// Bound decoded route state before graph construction and bitmap scanning.
const MAX_ROUTE_SYNC_PEERS: usize = 4096;
// Keep dense topology rebuilds inside the process memory contract.
const MAX_ROUTE_SYNC_EDGES: usize = 32_768;
const MAX_ROUTE_SYNC_EDGES_PER_SOURCE: usize = 1024;
// Bound repeated group proofs and foreign-network records in one sync request.
const MAX_ROUTE_SYNC_GROUPS_PER_PEER: usize = 256;
const MAX_ROUTE_SYNC_MULTICAST_GROUPS_PER_PEER: usize = 256;
const MAX_ROUTE_SYNC_FOREIGN_NETWORK_INFOS: usize = 1024;
const MAX_ROUTE_SYNC_CREDENTIAL_PROOFS_PER_PEER: usize = 256;
const MAX_ROUTE_SYNC_CREDENTIAL_BYTES_PER_PROOF: usize = 16 * 1024;
const MAX_ROUTE_SYNC_CREDENTIAL_BYTES_PER_REQUEST: usize = 1024 * 1024;
const MAX_ROUTE_SYNC_RAW_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROUTE_SYNC_RAW_PEER_INFO_BYTES: usize = 64 * 1024;
const ROUTE_PEER_RETAINED_OVERHEAD_BYTES: usize = 512;
const ROUTE_PEER_RETAINED_EXPANSION_FACTOR: usize = 4;
const MAX_ROUTE_SYNC_PROXY_CIDRS_PER_PEER: usize = 256;
const MAX_ROUTE_SYNC_TEXT_BYTES: usize = 256;
const MAX_ROUTE_SYNC_CREDENTIAL_HMAC_BYTES: usize = 32;
const MAX_ROUTE_SYNC_CREDENTIAL_SIGNATURE_BYTES: usize = 64;
const ROUTE_CREDENTIAL_ID_BYTES: usize = 16;
// Bound structural route work before policy construction. This protects the
// previous complete snapshot from adversarial dense topology input.
const MAX_ROUTE_REBUILD_WORK: usize = 8_000_000;

fn credential_is_current(
    credential: &TrustedCredentialPubkey,
    manager: &crate::peers::credential_manager::CredentialManager,
    now: i64,
) -> bool {
    credential.expiry_unix > now
        && credential.certificate_id.len() == ROUTE_CREDENTIAL_ID_BYTES
        && credential.certificate_id.iter().any(|byte| *byte != 0)
        && !manager.is_certificate_id_revoked(&credential.certificate_id)
}

const BRIDGE_ATTESTATION_PROTOCOL_VERSION: u32 = 1;
const BRIDGE_ATTESTATION_DOMAIN: &[u8] = b"lowertier bridge attestation v1";
const BRIDGE_ATTESTATION_LIFETIME: Duration = Duration::from_secs(120);
const BRIDGE_ATTESTATION_REFRESH: Duration = Duration::from_secs(60);
const BRIDGE_ATTESTATION_CLOCK_SKEW: Duration = Duration::from_secs(10);
const BRIDGE_ATTESTATION_MAX_DEADLINE: Duration = Duration::from_secs(130);

fn unix_time_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn bridge_attestation_payload(
    network_name: &str,
    peer_id: PeerId,
    noise_static_pubkey: &[u8],
    bridge_input: bool,
    issued_unix_ms: u64,
    expiry_unix_ms: u64,
) -> Option<Vec<u8>> {
    if noise_static_pubkey.len() != 32 {
        return None;
    }
    let network_name = network_name.as_bytes();
    let network_name_len = u32::try_from(network_name.len()).ok()?;

    let mut payload = Vec::with_capacity(
        BRIDGE_ATTESTATION_DOMAIN.len()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u32>()
            + network_name.len()
            + std::mem::size_of::<PeerId>()
            + noise_static_pubkey.len()
            + 1
            + std::mem::size_of::<u64>() * 2,
    );
    payload.extend_from_slice(BRIDGE_ATTESTATION_DOMAIN);
    payload.extend_from_slice(&BRIDGE_ATTESTATION_PROTOCOL_VERSION.to_be_bytes());
    payload.extend_from_slice(&network_name_len.to_be_bytes());
    payload.extend_from_slice(network_name);
    payload.extend_from_slice(&peer_id.to_be_bytes());
    payload.extend_from_slice(noise_static_pubkey);
    payload.push(u8::from(bridge_input));
    payload.extend_from_slice(&issued_unix_ms.to_be_bytes());
    payload.extend_from_slice(&expiry_unix_ms.to_be_bytes());
    Some(payload)
}

fn generate_bridge_attestation_hmac(
    network_secret: &str,
    network_name: &str,
    peer_id: PeerId,
    noise_static_pubkey: &[u8],
    bridge_input: bool,
    issued_unix_ms: u64,
    expiry_unix_ms: u64,
) -> Option<Vec<u8>> {
    if network_secret.is_empty() {
        return None;
    }
    let payload = bridge_attestation_payload(
        network_name,
        peer_id,
        noise_static_pubkey,
        bridge_input,
        issued_unix_ms,
        expiry_unix_ms,
    )?;
    let mut mac = Hmac::<Sha256>::new_from_slice(network_secret.as_bytes()).ok()?;
    mac.update(&payload);
    Some(mac.finalize().into_bytes().to_vec())
}

fn verify_bridge_attestation_hmac(
    network_secret: &str,
    network_name: &str,
    peer_id: PeerId,
    noise_static_pubkey: &[u8],
    bridge_input: bool,
    issued_unix_ms: u64,
    expiry_unix_ms: u64,
    proof: &[u8],
) -> bool {
    if network_secret.is_empty() {
        return false;
    }
    let Some(payload) = bridge_attestation_payload(
        network_name,
        peer_id,
        noise_static_pubkey,
        bridge_input,
        issued_unix_ms,
        expiry_unix_ms,
    ) else {
        return false;
    };
    let Ok(mut verifier) = Hmac::<Sha256>::new_from_slice(network_secret.as_bytes()) else {
        return false;
    };
    verifier.update(&payload);
    verifier.verify_slice(proof).is_ok()
}

fn bridge_attestation_time_valid(
    now_unix_ms: u64,
    issued_unix_ms: u64,
    expiry_unix_ms: u64,
) -> bool {
    let Some(lifetime) = expiry_unix_ms.checked_sub(issued_unix_ms) else {
        return false;
    };
    let max_lifetime = BRIDGE_ATTESTATION_LIFETIME.as_millis() as u64;
    let max_clock_skew = BRIDGE_ATTESTATION_CLOCK_SKEW.as_millis() as u64;
    expiry_unix_ms > issued_unix_ms
        && lifetime <= max_lifetime
        && issued_unix_ms <= now_unix_ms.saturating_add(max_clock_skew)
        && now_unix_ms <= expiry_unix_ms.saturating_add(max_clock_skew)
}

fn route_info_admin_attestation_capable(info: &RoutePeerInfo) -> bool {
    info.identity_type == PeerIdentityType::Admin as i32 && info.noise_static_pubkey.len() == 32
}

fn route_info_bridge_input(info: &RoutePeerInfo) -> bool {
    info.feature_flag
        .as_ref()
        .is_some_and(|features| features.bridge_input)
}

fn route_info_bridge_capability(info: &RoutePeerInfo) -> bool {
    route_info_admin_attestation_capable(info) && route_info_bridge_input(info)
}

fn clear_bridge_attestation(info: &mut RoutePeerInfo) {
    info.bridge_attestation_hmac.clear();
    info.bridge_attestation_issued_unix_ms = 0;
    info.bridge_attestation_expiry_unix_ms = 0;
}

fn refresh_local_bridge_attestation(
    global_ctx: &ArcGlobalCtx,
    info: &mut RoutePeerInfo,
    old: Option<&RoutePeerInfo>,
) {
    if !route_info_admin_attestation_capable(info) {
        clear_bridge_attestation(info);
        return;
    }
    let Some(network_secret) = global_ctx.get_network_identity().network_secret else {
        clear_bridge_attestation(info);
        return;
    };
    let Some(now_unix_ms) = unix_time_ms() else {
        clear_bridge_attestation(info);
        return;
    };
    let bridge_input = route_info_bridge_input(info);
    if let Some(old) = old.filter(|old| {
        route_info_admin_attestation_capable(old)
            && old.peer_id == info.peer_id
            && old.noise_static_pubkey == info.noise_static_pubkey
            && route_info_bridge_input(old) == bridge_input
            && old.bridge_attestation_hmac.len() == 32
            && old
                .bridge_attestation_issued_unix_ms
                .checked_add(BRIDGE_ATTESTATION_REFRESH.as_millis() as u64)
                .is_some_and(|refresh_at| now_unix_ms < refresh_at)
            && bridge_attestation_time_valid(
                now_unix_ms,
                old.bridge_attestation_issued_unix_ms,
                old.bridge_attestation_expiry_unix_ms,
            )
            && verify_bridge_attestation_hmac(
                &network_secret,
                &global_ctx.get_network_identity().network_name,
                old.peer_id,
                &old.noise_static_pubkey,
                bridge_input,
                old.bridge_attestation_issued_unix_ms,
                old.bridge_attestation_expiry_unix_ms,
                &old.bridge_attestation_hmac,
            )
    }) {
        info.bridge_attestation_hmac = old.bridge_attestation_hmac.clone();
        info.bridge_attestation_issued_unix_ms = old.bridge_attestation_issued_unix_ms;
        info.bridge_attestation_expiry_unix_ms = old.bridge_attestation_expiry_unix_ms;
        return;
    }

    let Some(expiry_unix_ms) =
        now_unix_ms.checked_add(BRIDGE_ATTESTATION_LIFETIME.as_millis() as u64)
    else {
        clear_bridge_attestation(info);
        return;
    };
    let network_name = global_ctx.get_network_identity().network_name;
    let Some(proof) = generate_bridge_attestation_hmac(
        &network_secret,
        &network_name,
        info.peer_id,
        &info.noise_static_pubkey,
        bridge_input,
        now_unix_ms,
        expiry_unix_ms,
    ) else {
        clear_bridge_attestation(info);
        return;
    };
    info.bridge_attestation_hmac = proof;
    info.bridge_attestation_issued_unix_ms = now_unix_ms;
    info.bridge_attestation_expiry_unix_ms = expiry_unix_ms;
}

type Version = u32;

/// Check if `child` CIDR is a subset of `parent` CIDR.
/// Returns true if `child` is contained within `parent`, or if they are equal.
fn cidr_is_subset(child: &IpCidr, parent: &IpCidr) -> bool {
    match (child, parent) {
        (IpCidr::V4(c), IpCidr::V4(p)) => {
            p.first_address() <= c.first_address() && c.last_address() <= p.last_address()
        }
        (IpCidr::V6(c), IpCidr::V6(p)) => {
            p.first_address() <= c.first_address() && c.last_address() <= p.last_address()
        }
        _ => false, // mixed v4/v6
    }
}

/// Check if `child` CIDR is a subset of `parent` CIDR (both as string representations).
fn cidr_is_subset_str(child: &str, parent: &str) -> bool {
    let Ok(child_cidr) = child.parse::<IpCidr>() else {
        return false;
    };
    let Ok(parent_cidr) = parent.parse::<IpCidr>() else {
        return false;
    };
    cidr_is_subset(&child_cidr, &parent_cidr)
}

/// Patch specific fields in a raw DynamicMessage from a decoded RoutePeerInfo,
/// preserving all other fields (including unknown ones).
fn patch_raw_from_info(raw: &mut DynamicMessage, info: &RoutePeerInfo, fields: &[&str]) {
    let mut decoded_raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
    decoded_raw.transcode_from(info).unwrap();
    for field_name in fields {
        if let Some(value) = decoded_raw.get_field_by_name(field_name) {
            raw.set_field_by_name(field_name, value.into_owned());
        }
    }
}

fn raw_credential_bytes_from_route_info(
    raw_route_info: &DynamicMessage,
    proof_idx: usize,
) -> Option<Vec<u8>> {
    raw_route_info
        .get_field_by_name("trusted_credential_pubkeys")?
        .as_list()?
        .get(proof_idx)?
        .as_message()?
        .get_field_by_name("credential")?
        .as_message()
        .map(|credential| credential.encode_to_vec())
}

fn raw_credential_certificate_bytes_from_route_info(
    raw_route_info: &DynamicMessage,
    proof_idx: usize,
) -> Option<Vec<u8>> {
    raw_route_info
        .get_field_by_name("trusted_credential_pubkeys")?
        .as_list()?
        .get(proof_idx)?
        .as_message()?
        .get_field_by_name("credential")?
        .as_message()?
        .get_field_by_name("certificate")?
        .as_message()
        .map(|certificate| certificate.encode_to_vec())
}

fn route_peer_inst_id(info: &RoutePeerInfo) -> Option<uuid::Uuid> {
    info.inst_id.map(Into::into)
}

#[derive(Debug, Clone)]
struct AtomicVersion(Arc<AtomicU32>);

impl AtomicVersion {
    fn new() -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(0)))
    }

    fn get(&self) -> Version {
        self.0.load(Ordering::Acquire)
    }

    fn set(&self, version: Version) {
        self.0.store(version, Ordering::Release);
    }

    fn inc(&self) -> Version {
        self.0.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn set_if_larger(&self, version: Version) -> bool {
        // return true if the version is set.
        self.0.fetch_max(version, Ordering::AcqRel) < version
    }
}

impl From<Version> for AtomicVersion {
    fn from(version: Version) -> Self {
        AtomicVersion(Arc::new(AtomicU32::new(version)))
    }
}

fn is_foreign_network_info_newer(
    next: &ForeignNetworkRouteInfoEntry,
    prev: &ForeignNetworkRouteInfoEntry,
) -> Option<bool> {
    Some(
        SystemTime::try_from(next.last_update?).ok()?
            > SystemTime::try_from(prev.last_update?).ok()?,
    )
}

impl RoutePeerInfo {
    fn normalize_multicast_groups(&mut self) {
        self.multicast_groups
            .retain(|group| match group.as_slice() {
                [a, b, c, d] => Ipv4Addr::from([*a, *b, *c, *d]).is_multicast(),
                bytes if bytes.len() == 16 => <[u8; 16]>::try_from(bytes)
                    .ok()
                    .map(Ipv6Addr::from)
                    .is_some_and(|address| address.is_multicast()),
                _ => false,
            });
        self.multicast_groups.sort_unstable();
        self.multicast_groups.dedup();
        self.multicast_groups
            .truncate(MAX_ROUTE_SYNC_MULTICAST_GROUPS_PER_PEER);
    }

    #[allow(deprecated)]
    pub fn new() -> Self {
        Self {
            peer_id: 0,
            inst_id: Some(uuid::Uuid::nil().into()),
            cost: 0,
            ipv4_addr: None,
            proxy_cidrs: Vec::new(),
            hostname: None,
            udp_nat_type: 0,
            tcp_nat_type: 0,
            // ensure this is updated when the peer_infos/conn_info/foreign_network lock is acquired.
            // else we may assign a older timestamp than iterate time.
            last_update: None,
            version: 0,
            lowertier_version: LOWTIER_VERSION.to_string(),
            feature_flag: None,
            peer_route_id: 0,
            network_length: 24,
            ipv6_addr: None,
            groups: Vec::new(),

            quic_port: None,
            noise_static_pubkey: Vec::new(),
            trusted_credential_pubkeys: Vec::new(),
            ipv6_public_addr_prefix: None,
            ipv6_public_addr_lease: None,
            multicast_groups: Vec::new(),
            identity_type: PeerIdentityType::Admin as i32,
            bridge_attestation_hmac: Vec::new(),
            bridge_attestation_issued_unix_ms: 0,
            bridge_attestation_expiry_unix_ms: 0,
        }
    }

    /// Creates a new `RoutePeerInfo` instance with updated information from the given context.
    ///
    /// # Parameters
    /// - `my_peer_id`: The unique identifier for the peer.
    /// - `peer_route_id`: The route identifier associated with the peer.
    /// - `global_ctx`: Reference to the global context containing configuration and state.
    ///
    /// # Returns
    /// A new `RoutePeerInfo` instance initialized with values from the provided context and parameters.
    pub fn new_updated_self(
        my_peer_id: PeerId,
        peer_route_id: u64,
        global_ctx: &ArcGlobalCtx,
        public_ipv6_addr_lease: Option<Ipv6Inet>,
    ) -> Self {
        let stun_info = global_ctx.get_stun_info_collector().get_stun_info();
        let noise_static_pubkey = global_ctx
            .config
            .get_secure_mode()
            .and_then(|cfg| cfg.public_key().ok())
            .map(|pk| pk.as_bytes().to_vec())
            .unwrap_or_default();
        let identity_type = if global_ctx
            .get_hostname()
            .starts_with(PUBLIC_SERVER_HOSTNAME_PREFIX)
        {
            PeerIdentityType::ForeignRelay
        } else if global_ctx.get_network_identity().network_secret.is_some() {
            PeerIdentityType::Admin
        } else {
            PeerIdentityType::Credential
        };
        let mut feature_flag = global_ctx.get_feature_flags();
        feature_flag.is_credential_peer = matches!(identity_type, PeerIdentityType::Credential);
        if matches!(identity_type, PeerIdentityType::ForeignRelay) {
            feature_flag.ethernet_input = false;
            feature_flag.bridge_input = false;
            feature_flag.multicast_membership = false;
        }
        let proxy_cidrs = if matches!(identity_type, PeerIdentityType::ForeignRelay) {
            Vec::new()
        } else {
            global_ctx
                .config
                .get_proxy_cidrs()
                .iter()
                .map(|x| x.mapped_cidr.unwrap_or(x.cidr))
                .chain(global_ctx.get_vpn_portal_cidr())
                .map(|x| x.to_string())
                .collect()
        };
        let groups = if matches!(identity_type, PeerIdentityType::ForeignRelay) {
            Vec::new()
        } else {
            global_ctx.get_acl_groups(my_peer_id)
        };
        let mut info = Self {
            peer_id: my_peer_id,
            inst_id: Some(global_ctx.get_id().into()),
            cost: 0,
            ipv4_addr: global_ctx.get_ipv4().map(|x| x.address().into()),
            proxy_cidrs,
            hostname: Some(global_ctx.get_hostname()),
            udp_nat_type: stun_info.udp_nat_type,
            tcp_nat_type: stun_info.tcp_nat_type,

            // these two fields should not participate in comparison.
            last_update: None,
            version: 0,

            lowertier_version: LOWTIER_VERSION.to_string(),
            feature_flag: Some(feature_flag),
            peer_route_id,
            network_length: global_ctx
                .get_ipv4()
                .map(|x| x.network_length() as u32)
                .unwrap_or(24),

            ipv6_addr: global_ctx.get_ipv6().map(|x| x.into()),
            ipv6_public_addr_prefix: global_ctx.get_advertised_ipv6_public_addr_prefix().map(
                |prefix| {
                    Ipv6Inet::new(prefix.first_address(), prefix.network_length())
                        .unwrap()
                        .into()
                },
            ),
            ipv6_public_addr_lease: public_ipv6_addr_lease.map(Into::into),

            groups,

            noise_static_pubkey,

            // Only admin nodes (holding network_secret) publish trusted credential pubkeys
            trusted_credential_pubkeys: if matches!(identity_type, PeerIdentityType::Admin)
                && let Some(network_secret) = global_ctx.get_network_identity().network_secret
            {
                global_ctx
                    .get_credential_manager()
                    .get_trusted_pubkeys(&network_secret)
            } else {
                Vec::new()
            },

            multicast_groups: if matches!(identity_type, PeerIdentityType::ForeignRelay) {
                Vec::new()
            } else {
                global_ctx
                    .get_multicast_groups()
                    .into_iter()
                    .map(|address| match address {
                        IpAddr::V4(address) => address.octets().to_vec(),
                        IpAddr::V6(address) => address.octets().to_vec(),
                    })
                    .collect()
            },

            identity_type: identity_type as i32,

            ..Default::default()
        };
        refresh_local_bridge_attestation(global_ctx, &mut info, None);
        info
    }

    /// Attempts to update the `new` RoutePeerInfo based on the `old` RoutePeerInfo.
    ///
    /// An update is triggered if any fields in `new` differ from `old`, or if the time since
    /// `old.last_update` exceeds the `UPDATE_PEER_INFO_PERIOD`.
    ///
    /// If an update occurs, `new.last_update` is set to the current time and `new.version` is incremented.
    /// Otherwise, `new.last_update` and `new.version` are copied from `old` without modification.
    ///
    /// Returns `true` if an update was performed (fields changed or periodic update required),
    /// or `false` if no update was necessary.
    pub fn try_update_new_peer_info(old: &RoutePeerInfo, new: &mut RoutePeerInfo) -> bool {
        let need_update_periodically = if let Ok(Ok(d)) =
            SystemTime::try_from(old.last_update.unwrap_or_default()).map(|x| x.elapsed())
        {
            d > UPDATE_PEER_INFO_PERIOD
        } else {
            true
        };

        // these two fields should not participate in comparison.
        new.version = old.version;
        new.last_update = old.last_update;

        if *new != *old || need_update_periodically {
            new.version += 1;
            true
        } else {
            false
        }
    }
}

impl From<RoutePeerInfo> for crate::proto::api::instance::Route {
    fn from(val: RoutePeerInfo) -> Self {
        let network_length = if val.network_length == 0 {
            24
        } else {
            val.network_length
        };
        let peer_identity_type =
            PeerIdentityType::try_from(val.identity_type).unwrap_or(PeerIdentityType::SharedNode);

        crate::proto::api::instance::Route {
            peer_id: val.peer_id,
            ipv4_addr: val.ipv4_addr.map(|ipv4_addr| Ipv4Inet {
                address: Some(ipv4_addr),
                network_length,
            }),
            next_hop_peer_id: 0, // next_hop_peer_id is calculated in RouteTable.
            cost: 0,             // cost is calculated in RouteTable.
            path_latency: 0,     // path_latency is calculated in RouteTable.
            proxy_cidrs: val.proxy_cidrs.clone(),
            hostname: val.hostname.unwrap_or_default(),
            stun_info: {
                let mut stun_info = StunInfo::default();
                if let Ok(udp_nat_type) = NatType::try_from(val.udp_nat_type) {
                    stun_info.set_udp_nat_type(udp_nat_type);
                }
                if let Ok(tcp_nat_type) = NatType::try_from(val.tcp_nat_type) {
                    stun_info.set_tcp_nat_type(tcp_nat_type);
                }
                Some(stun_info)
            },
            inst_id: val.inst_id.map(|x| x.to_string()).unwrap_or_default(),
            version: val.lowertier_version,
            feature_flag: val.feature_flag,

            next_hop_peer_id_latency_first: None,
            cost_latency_first: None,
            path_latency_latency_first: None,

            ipv6_addr: val.ipv6_addr,
            public_ipv6_addr: val.ipv6_public_addr_lease,
            ipv6_public_addr_prefix: val.ipv6_public_addr_prefix,
            next_hop_peer_id_speed_first: None,
            path_delivery_bps_speed_first: None,
            path_latency_speed_first: None,
            path_len_speed_first: None,
            multicast_groups: val.multicast_groups,
            peer_identity_type: peer_identity_type as i32,
            // RoutePeerInfo is wire data. It does not prove the advertised role.
            // Keep the role for display, but fail closed for authority decisions.
            secure_auth_level: SecureAuthLevel::EncryptedUnauthenticated as i32,
        }
    }
}

type RouteConnBitmap = crate::proto::peer_rpc::RouteConnBitmap;
type RouteConnPeerList = crate::proto::peer_rpc::RouteConnPeerList;
type PeerConnInfo = crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo;

impl RouteConnBitmap {
    fn get_bit(&self, idx: usize) -> bool {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        let Some(byte) = self.bitmap.get(byte_idx) else {
            return false;
        };
        ((*byte >> bit_idx) & 1) == 1
    }

    fn get_connected_peers(&self, peer_idx: usize) -> BTreeSet<PeerId> {
        let mut connected_peers = BTreeSet::new();
        for (idx, peer_id_version) in self.peer_ids.iter().enumerate() {
            if self.get_bit(peer_idx * self.peer_ids.len() + idx) {
                connected_peers.insert(peer_id_version.peer_id);
            }
        }
        connected_peers
    }
}

fn bitmap_row_edge_count(
    bitmap: &RouteConnBitmap,
    peer_count: usize,
    source_idx: usize,
) -> Option<usize> {
    if peer_count == 0 {
        return Some(0);
    }
    let row_start = source_idx.checked_mul(peer_count)?;
    let row_end = row_start.checked_add(peer_count)?;
    let first_byte = row_start / 8;
    let last_byte = (row_end - 1) / 8;
    let mut count = 0usize;
    for byte_idx in first_byte..=last_byte {
        let mut byte = *bitmap.bitmap.get(byte_idx)?;
        if byte_idx == first_byte {
            byte &= u8::MAX << (row_start % 8);
        }
        if byte_idx == last_byte {
            let valid_bits = ((row_end - 1) % 8) + 1;
            if valid_bits < 8 {
                byte &= (1u8 << valid_bits) - 1;
            }
        }
        count = count.checked_add(byte.count_ones() as usize)?;
    }
    Some(count)
}

fn validate_route_peer_infos(peer_infos: &[RoutePeerInfo]) -> rpc_types::error::Result<()> {
    if peer_infos.len() > MAX_ROUTE_SYNC_PEERS {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "route synchronization contains too many peer infos: {}",
            peer_infos.len()
        )));
    }

    let mut peer_ids = HashSet::with_capacity(peer_infos.len());
    let mut credential_bytes = 0usize;
    for peer_info in peer_infos {
        if !peer_ids.insert(peer_info.peer_id) {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization contains duplicate peer id {}",
                peer_info.peer_id
            )));
        }
        if peer_info.groups.len() > MAX_ROUTE_SYNC_GROUPS_PER_PEER {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has too many group declarations: {}",
                peer_info.peer_id,
                peer_info.groups.len()
            )));
        }
        if peer_info.multicast_groups.len() > MAX_ROUTE_SYNC_MULTICAST_GROUPS_PER_PEER {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has too many multicast groups: {}",
                peer_info.peer_id,
                peer_info.multicast_groups.len()
            )));
        }
        if peer_info.proxy_cidrs.len() > MAX_ROUTE_SYNC_PROXY_CIDRS_PER_PEER {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has too many proxy CIDRs: {}",
                peer_info.peer_id,
                peer_info.proxy_cidrs.len()
            )));
        }
        if peer_info
            .proxy_cidrs
            .iter()
            .any(|cidr| cidr.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has an oversized proxy CIDR",
                peer_info.peer_id
            )));
        }
        if peer_info.lowertier_version.len() > MAX_ROUTE_SYNC_TEXT_BYTES
            || peer_info
                .hostname
                .as_ref()
                .is_some_and(|hostname| hostname.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
            || (!peer_info.noise_static_pubkey.is_empty()
                && peer_info.noise_static_pubkey.len() != 32)
            || (!peer_info.bridge_attestation_hmac.is_empty()
                && peer_info.bridge_attestation_hmac.len() != 32)
            || peer_info.multicast_groups.iter().any(|group| {
                group.len() != std::mem::size_of::<Ipv4Addr>()
                    && group.len() != std::mem::size_of::<Ipv6Addr>()
            })
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has an invalid bounded field",
                peer_info.peer_id
            )));
        }
        let mut group_names = HashSet::with_capacity(peer_info.groups.len());
        for group in &peer_info.groups {
            if group.group_name.len() > MAX_ROUTE_SYNC_TEXT_BYTES
                || group.group_proof.len() > MAX_ROUTE_SYNC_CREDENTIAL_SIGNATURE_BYTES
            {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has an oversized group proof",
                    peer_info.peer_id
                )));
            }
            if !group_names.insert(group.group_name.as_str()) {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has duplicate group declaration {}",
                    peer_info.peer_id, group.group_name
                )));
            }
        }
        if peer_info.trusted_credential_pubkeys.len() > MAX_ROUTE_SYNC_CREDENTIAL_PROOFS_PER_PEER {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer {} has too many credential proofs: {}",
                peer_info.peer_id,
                peer_info.trusted_credential_pubkeys.len()
            )));
        }
        for proof in &peer_info.trusted_credential_pubkeys {
            if proof.credential_hmac.len() != MAX_ROUTE_SYNC_CREDENTIAL_HMAC_BYTES {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has an invalid credential HMAC length",
                    peer_info.peer_id
                )));
            }
            let Some(credential) = proof.credential.as_ref() else {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has a credential proof without a credential",
                    peer_info.peer_id
                )));
            };
            if credential.pubkey.len() != 32
                || credential.root_public_key.len() != 32
                || credential.root_fingerprint.len() != 32
                || credential.certificate_id.len() != ROUTE_CREDENTIAL_ID_BYTES
                || credential.certificate_id.iter().all(|byte| *byte == 0)
                || credential.network_name.len() > MAX_ROUTE_SYNC_TEXT_BYTES
                || credential.role.len() > MAX_ROUTE_SYNC_TEXT_BYTES
                || credential.groups.len() > MAX_ROUTE_SYNC_GROUPS_PER_PEER
                || credential.allowed_proxy_cidrs.len() > MAX_ROUTE_SYNC_PROXY_CIDRS_PER_PEER
                || credential.certificate_signature.len()
                    != MAX_ROUTE_SYNC_CREDENTIAL_SIGNATURE_BYTES
            {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has an invalid credential shape",
                    peer_info.peer_id
                )));
            }
            if credential
                .groups
                .iter()
                .any(|group| group.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
                || credential
                    .allowed_proxy_cidrs
                    .iter()
                    .any(|cidr| cidr.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
            {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has oversized credential metadata",
                    peer_info.peer_id
                )));
            }
            let Some(certificate) = credential.certificate.as_ref() else {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has no credential certificate",
                    peer_info.peer_id
                )));
            };
            if certificate.network_name.len() > MAX_ROUTE_SYNC_TEXT_BYTES
                || certificate.role.len() > MAX_ROUTE_SYNC_TEXT_BYTES
                || certificate.root_public_key.len() != 32
                || certificate.root_fingerprint.len() != 32
                || certificate.subject_x25519_public_key.len() != 32
                || certificate.certificate_id.len() != ROUTE_CREDENTIAL_ID_BYTES
                || certificate.certificate_id.iter().all(|byte| *byte == 0)
                || certificate.groups.len() > MAX_ROUTE_SYNC_GROUPS_PER_PEER
                || certificate.allowed_proxy_cidrs.len() > MAX_ROUTE_SYNC_PROXY_CIDRS_PER_PEER
                || certificate.signature.len() != MAX_ROUTE_SYNC_CREDENTIAL_SIGNATURE_BYTES
                || certificate
                    .groups
                    .iter()
                    .any(|group| group.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
                || certificate
                    .allowed_proxy_cidrs
                    .iter()
                    .any(|cidr| cidr.len() > MAX_ROUTE_SYNC_TEXT_BYTES)
            {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has an invalid credential certificate",
                    peer_info.peer_id
                )));
            }
            let encoded_len = proof.encoded_len();
            if encoded_len > MAX_ROUTE_SYNC_CREDENTIAL_BYTES_PER_PROOF {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer {} has an oversized credential proof",
                    peer_info.peer_id
                )));
            }
            credential_bytes = credential_bytes.checked_add(encoded_len).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization credential size overflow".to_string(),
                )
            })?;
            if credential_bytes > MAX_ROUTE_SYNC_CREDENTIAL_BYTES_PER_REQUEST {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization credential data is too large".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_route_conn_info(conn_info: &ConnInfo) -> rpc_types::error::Result<()> {
    match conn_info {
        ConnInfo::ConnBitmap(bitmap) => {
            let peer_count = bitmap.peer_ids.len();
            if peer_count > MAX_ROUTE_SYNC_PEERS {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization bitmap contains too many peers: {peer_count}"
                )));
            }

            let mut peer_ids = HashSet::with_capacity(peer_count);
            for peer_id in &bitmap.peer_ids {
                if !peer_ids.insert(peer_id.peer_id) {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization bitmap contains duplicate peer id {}",
                        peer_id.peer_id
                    )));
                }
            }

            let edge_bits = peer_count.checked_mul(peer_count).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization bitmap edge count overflow".to_string(),
                )
            })?;
            let expected_bytes = edge_bits.div_ceil(8);
            if bitmap.bitmap.len() != expected_bytes {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization bitmap length {} does not match {} peers",
                    bitmap.bitmap.len(),
                    peer_count
                )));
            }

            if let Some(last_byte) = bitmap.bitmap.last()
                && edge_bits % 8 != 0
            {
                let valid_bits = edge_bits % 8;
                let trailing_bits_mask = !((1u8 << valid_bits) - 1);
                if last_byte & trailing_bits_mask != 0 {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(
                        "route synchronization bitmap has set bits outside its peer matrix"
                            .to_string(),
                    ));
                }
            }

            let mut edge_count = 0usize;
            for source_idx in 0..peer_count {
                let source_edge_count = bitmap_row_edge_count(bitmap, peer_count, source_idx)
                    .ok_or_else(|| {
                        rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization bitmap row offset overflow".to_string(),
                        )
                    })?;
                if source_edge_count > MAX_ROUTE_SYNC_EDGES_PER_SOURCE {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization bitmap source {source_idx} has too many edges: {source_edge_count}"
                    )));
                }
                edge_count = edge_count.checked_add(source_edge_count).ok_or_else(|| {
                    rpc_types::error::Error::MalformatRpcPacket(
                        "route synchronization bitmap edge count overflow".to_string(),
                    )
                })?;
                if edge_count > MAX_ROUTE_SYNC_EDGES {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization bitmap contains too many edges: {edge_count}"
                    )));
                }
            }
        }
        ConnInfo::ConnPeerList(list) => {
            let source_count = list.peer_conn_infos.len();
            if source_count > MAX_ROUTE_SYNC_PEERS {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization list contains too many source peers: {source_count}"
                )));
            }

            let mut source_ids = HashSet::with_capacity(source_count);
            let mut node_ids = HashSet::with_capacity(source_count);
            let mut edge_count = 0usize;
            for source in &list.peer_conn_infos {
                let Some(peer_id) = source.peer_id else {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(
                        "route synchronization list has a missing source peer".to_string(),
                    ));
                };
                if !source_ids.insert(peer_id.peer_id) {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization list contains duplicate source peer {}",
                        peer_id.peer_id
                    )));
                }
                node_ids.insert(peer_id.peer_id);

                let connected_count = source.connected_peer_ids.len();
                if connected_count > MAX_ROUTE_SYNC_EDGES_PER_SOURCE {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization list has too many connected peers for source {}: {}",
                        peer_id.peer_id, connected_count
                    )));
                }
                edge_count = edge_count.checked_add(connected_count).ok_or_else(|| {
                    rpc_types::error::Error::MalformatRpcPacket(
                        "route synchronization list edge count overflow".to_string(),
                    )
                })?;
                if edge_count > MAX_ROUTE_SYNC_EDGES {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization list contains too many edges: {edge_count}"
                    )));
                }

                let mut connected_peer_ids = HashSet::with_capacity(connected_count);
                for connected_peer_id in &source.connected_peer_ids {
                    if !connected_peer_ids.insert(*connected_peer_id) {
                        return Err(rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization list contains duplicate connected peer id"
                                .to_string(),
                        ));
                    }
                    node_ids.insert(*connected_peer_id);
                }
                if node_ids.len() > MAX_ROUTE_SYNC_PEERS {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization list contains too many peer ids: {}",
                        node_ids.len()
                    )));
                }
            }
        }
    }

    Ok(())
}

fn validate_route_foreign_network_info(
    foreign_network: &RouteForeignNetworkInfos,
) -> rpc_types::error::Result<()> {
    if foreign_network.infos.len() > MAX_ROUTE_SYNC_FOREIGN_NETWORK_INFOS {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "route synchronization contains too many foreign-network records: {}",
            foreign_network.infos.len()
        )));
    }

    let mut keys = HashSet::with_capacity(foreign_network.infos.len());
    let mut foreign_edge_count = 0usize;
    for item in &foreign_network.infos {
        let Some(key) = item.key.as_ref() else {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization foreign-network record has no key".to_string(),
            ));
        };
        let Some(value) = item.value.as_ref() else {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization foreign-network record has no value".to_string(),
            ));
        };
        if value.foreign_peer_ids.len() > MAX_ROUTE_SYNC_EDGES_PER_SOURCE {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "foreign network {} has too many peer ids: {}",
                key.network_name,
                value.foreign_peer_ids.len()
            )));
        }
        foreign_edge_count = foreign_edge_count
            .checked_add(value.foreign_peer_ids.len())
            .ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "foreign-network edge count overflow".to_string(),
                )
            })?;
        if foreign_edge_count > MAX_ROUTE_SYNC_EDGES {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization contains too many foreign-network peer edges: {foreign_edge_count}"
            )));
        }
        if !keys.insert((key.peer_id, key.network_name.clone())) {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization contains duplicate foreign-network key {}:{}",
                key.peer_id, key.network_name
            )));
        }
        if key.network_name.len() > MAX_ROUTE_SYNC_TEXT_BYTES
            || (!value.network_secret_digest.is_empty() && value.network_secret_digest.len() != 32)
            || (!value.owner_noise_static_pubkey.is_empty()
                && value.owner_noise_static_pubkey.len() != 32)
        {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization foreign-network record has an invalid bounded field"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_foreign_relay_conn_scope(
    from_peer_id: PeerId,
    conn_info: &ConnInfo,
) -> rpc_types::error::Result<()> {
    let ConnInfo::ConnPeerList(list) = conn_info else {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "foreign relay connection topology must use the peer-list encoding".to_string(),
        ));
    };
    if list.peer_conn_infos.len() != 1 {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "foreign relay can assert exactly one connection source".to_string(),
        ));
    }
    let Some(source) = list.peer_conn_infos.first() else {
        unreachable!("length was checked above");
    };
    let Some(peer_id) = source.peer_id else {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "foreign relay connection source is missing".to_string(),
        ));
    };
    if peer_id.peer_id != from_peer_id {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "foreign relay can assert only its own connection adjacency".to_string(),
        ));
    }
    Ok(())
}

/// Enforce the authenticated sender role before expensive generic validation.
///
/// Restricted roles cannot use a valid record to send a larger topology.
fn validate_route_sync_role_shape(
    from_peer_id: PeerId,
    identity_type: PeerIdentityType,
    peer_infos: Option<&[RoutePeerInfo]>,
    conn_info: Option<&ConnInfo>,
    foreign_network: Option<&RouteForeignNetworkInfos>,
) -> rpc_types::error::Result<()> {
    if !matches!(identity_type, PeerIdentityType::Admin) && foreign_network.is_some() {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "only an authenticated admin can send foreign-network route data".to_string(),
        ));
    }

    if matches!(
        identity_type,
        PeerIdentityType::SharedNode | PeerIdentityType::Credential
    ) && let Some(peer_infos) = peer_infos
    {
        if peer_infos.len() != 1 {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "restricted route sender must send exactly one peer record".to_string(),
            ));
        }
        if peer_infos[0].peer_id != from_peer_id {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "restricted route sender can send only its own peer record".to_string(),
            ));
        }
    }

    match identity_type {
        PeerIdentityType::Admin => {}
        PeerIdentityType::ForeignRelay => {
            if let Some(conn_info) = conn_info {
                validate_foreign_relay_conn_scope(from_peer_id, conn_info)?;
            }
        }
        PeerIdentityType::SharedNode => {
            if conn_info.is_some() {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "shared-node senders cannot assert connection topology".to_string(),
                ));
            }
        }
        PeerIdentityType::Credential => {
            if conn_info.is_some() {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "credential senders cannot assert connection topology".to_string(),
                ));
            }
        }
    }

    Ok(())
}

type Error = SyncRouteInfoError;

#[derive(Debug, Clone)]
struct RouteConnInfo {
    connected_peers: BTreeSet<PeerId>,
    version: AtomicVersion,
    last_update: SystemTime,
}

impl Default for RouteConnInfo {
    fn default() -> Self {
        Self {
            connected_peers: BTreeSet::new(),
            version: AtomicVersion::new(),
            last_update: SystemTime::now(),
        }
    }
}

#[derive(Debug, Default)]
struct InterfacePeerSnapshot {
    generation: u64,
    peers: BTreeSet<PeerId>,
    identity_types: BTreeMap<PeerId, Option<PeerIdentityType>>,
    authenticated: BTreeMap<PeerId, InterfacePeerEvidence>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct InterfacePeerEvidence {
    identity_type: Option<PeerIdentityType>,
    public_key: Option<Vec<u8>>,
    secure_auth_level: Option<SecureAuthLevel>,
}

// constructed with all infos synced from all peers.
struct SyncedRouteInfo {
    /// Network identity used to validate every propagated credential certificate.
    network_name: String,
    credential_manager: Arc<crate::peers::credential_manager::CredentialManager>,
    credential_root_public_key: Vec<u8>,
    credential_root_fingerprint: Vec<u8>,
    /// Serializes topology mutations with forwarding-input capture.
    topology_state_lock: std::sync::Mutex<()>,
    process_memory: Arc<ProcessMemoryGovernor>,
    retained_peer_bytes: std::sync::Mutex<HashMap<PeerId, usize>>,
    retained_peer_bytes_total: AtomicUsize,
    peer_infos: RwLock<OrderedHashMap<PeerId, RoutePeerInfo>>,
    // prost doesn't support unknown fields, so we use DynamicMessage to store raw infos and propagate them to other peers.
    raw_peer_infos: DashMap<PeerId, DynamicMessage>,
    conn_map: RwLock<OrderedHashMap<PeerId, RouteConnInfo>>,
    foreign_network: DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>,
    group_trust_map: DashMap<PeerId, HashMap<String, Vec<u8>>>,
    group_trust_map_cache: DashMap<PeerId, Arc<Vec<String>>>, // cache for group trust map, should sync with group_trust_map

    // Aggregated trusted credential pubkeys from all admin nodes
    // Maps pubkey bytes -> TrustedCredentialPubkey
    trusted_credential_pubkeys: DashMap<Vec<u8>, TrustedCredentialPubkey>,
    // Tracks the currently accepted peer for non-reusable credentials.
    // Maps credential pubkey bytes -> peer_id.
    non_reusable_credential_owners: DashMap<Vec<u8>, PeerId>,
    // Duplicate non-reusable credential peers are kept for OSPF sync and topology
    // reachability, but excluded from forwarding until owner election selects them.
    suppressed_non_reusable_credential_peers: DashMap<PeerId, ()>,
    // Local authentication evidence is the only source for propagated Admin keys.
    locally_authenticated_peers: DashMap<PeerId, AuthenticatedRoutePeerEvidence>,

    version: AtomicVersion,
}

impl Debug for SyncedRouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedRouteInfo")
            .field("peer_infos", &self.peer_infos)
            .field("conn_map", &self.conn_map)
            .field("foreign_network", &self.foreign_network)
            .field("group_trust_map", &self.group_trust_map)
            .field("version", &self.version.get())
            .finish()
    }
}

impl SyncedRouteInfo {
    fn topology_state_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.topology_state_lock.lock().unwrap()
    }

    fn set_peer_groups(&self, peer_id: PeerId, groups: HashMap<String, Vec<u8>>) {
        if groups.is_empty() {
            self.group_trust_map.remove(&peer_id);
            self.group_trust_map_cache.remove(&peer_id);
            return;
        }

        let group_names = groups.keys().cloned().collect();
        self.group_trust_map.insert(peer_id, groups);
        self.group_trust_map_cache
            .insert(peer_id, Arc::new(group_names));
    }

    fn get_proof_groups(&self, peer_id: PeerId) -> HashMap<String, Vec<u8>> {
        self.group_trust_map
            .get(&peer_id)
            .map(|groups| {
                groups
                    .iter()
                    .filter(|(_, proof)| !proof.is_empty())
                    .map(|(group, proof)| (group.clone(), proof.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_peer_identity(info: &mut RoutePeerInfo, identity_type: PeerIdentityType) {
        let mut feature_flag = info.feature_flag.unwrap_or_default();
        feature_flag.is_credential_peer = matches!(identity_type, PeerIdentityType::Credential);
        info.feature_flag = Some(feature_flag);
        info.identity_type = identity_type as i32;
    }

    fn sanitize_foreign_relay_feature_flag(info: &mut RoutePeerInfo) {
        let mut feature_flag = info.feature_flag.unwrap_or_default();
        feature_flag.ethernet_input = false;
        feature_flag.bridge_input = false;
        feature_flag.multicast_membership = false;
        info.feature_flag = Some(feature_flag);
        info.multicast_groups.clear();
    }

    fn sanitize_untrusted_role_capabilities(
        info: &mut RoutePeerInfo,
        identity_type: PeerIdentityType,
    ) {
        if matches!(identity_type, PeerIdentityType::Admin) {
            return;
        }
        Self::sanitize_foreign_relay_feature_flag(info);
    }

    fn peer_identity_type(info: &RoutePeerInfo) -> Option<PeerIdentityType> {
        PeerIdentityType::try_from(info.identity_type).ok()
    }

    fn is_credential_peer_info(info: &RoutePeerInfo) -> bool {
        matches!(
            Self::peer_identity_type(info),
            Some(PeerIdentityType::Credential)
        )
    }

    fn credential_is_reusable(info: &TrustedCredentialPubkey) -> bool {
        info.reusable.unwrap_or(true)
    }

    fn credential_proof_is_valid(
        &self,
        raw_route_info: Option<&DynamicMessage>,
        proof_idx: usize,
        proof: &TrustedCredentialPubkeyProof,
        network_secret: Option<&str>,
    ) -> bool {
        let Some(secret) = network_secret.filter(|secret| !secret.is_empty()) else {
            // A credential proof has no trust value without the local secret.
            return false;
        };

        raw_route_info
            .and_then(|raw| raw_credential_bytes_from_route_info(raw, proof_idx))
            .map(|raw_credential_bytes| {
                proof.verify_credential_hmac_with_bytes(&raw_credential_bytes, secret)
            })
            .unwrap_or_else(|| proof.verify_credential_hmac(secret))
    }

    fn normalize_credential_policy(
        &self,
        credential: &TrustedCredentialPubkey,
        now: i64,
    ) -> Option<(TrustedCredentialPubkey, Vec<u8>)> {
        let certificate = credential.certificate.as_ref()?;
        if credential.root_public_key != self.credential_root_public_key
            || credential.root_fingerprint != self.credential_root_fingerprint
            || credential.serial != 0
            || certificate.serial != 0
            || credential.certificate_id.len() != ROUTE_CREDENTIAL_ID_BYTES
            || credential.certificate_id.iter().all(|byte| *byte == 0)
            || certificate.certificate_id != credential.certificate_id
            || certificate.version != credential.credential_version
            || certificate.network_name != credential.network_name
            || certificate.root_public_key != credential.root_public_key
            || certificate.root_fingerprint != credential.root_fingerprint
            || certificate.subject_x25519_public_key != credential.pubkey
            || certificate.expiry_unix != credential.expiry_unix
            || certificate.role != credential.role
            || certificate.groups != credential.groups
            || certificate.allow_relay != credential.allow_relay
            || certificate.allowed_proxy_cidrs != credential.allowed_proxy_cidrs
            || credential.reusable != Some(certificate.reusable)
            || credential.certificate_signature != certificate.signature
        {
            return None;
        }

        // Certificate verification is manager-owned. Route code only checks the
        // duplicate-field invariant and normalizes from the verified certificate.
        crate::peers::credential_manager::CredentialManager::verify_trusted_credential(
            credential,
            &self.network_name,
            Some(&self.credential_root_fingerprint),
            now,
        )
        .ok()?;
        if !credential_is_current(credential, self.credential_manager.as_ref(), now) {
            return None;
        }

        let mut normalized = credential.clone();
        normalized.credential_version = certificate.version;
        normalized.network_name = certificate.network_name.clone();
        normalized.root_public_key = certificate.root_public_key.clone();
        normalized.root_fingerprint = certificate.root_fingerprint.clone();
        normalized.pubkey = certificate.subject_x25519_public_key.clone();
        normalized.serial = 0;
        normalized.certificate_id = certificate.certificate_id.clone();
        normalized.expiry_unix = certificate.expiry_unix;
        normalized.role = certificate.role.clone();
        normalized.groups = certificate.groups.clone();
        normalized.allow_relay = certificate.allow_relay;
        normalized.allowed_proxy_cidrs = certificate.allowed_proxy_cidrs.clone();
        normalized.reusable = Some(certificate.reusable);
        normalized.certificate_signature = certificate.signature.clone();

        let mut identity = vec![1u8];
        identity.extend_from_slice(&certificate.encode_to_vec());
        Some((normalized, identity))
    }

    fn collect_trusted_credentials(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        network_secret: Option<&str>,
        now: i64,
    ) -> (
        HashMap<Vec<u8>, TrustedCredentialPubkey>,
        HashMap<Vec<u8>, crate::common::global_ctx::TrustedKeyMetadata>,
    ) {
        use crate::common::global_ctx::{TrustedKeyMetadata, TrustedKeySource};

        let mut candidates = BTreeMap::<Vec<u8>, (TrustedCredentialPubkey, Vec<u8>, i64)>::new();
        let mut conflicting_pubkeys = HashSet::new();
        let mut global_trusted_keys = HashMap::new();

        for (peer_id, info) in peer_infos.iter() {
            if !self.is_admin_peer(info) {
                continue;
            }

            let locally_authenticated_admin = self
                .locally_authenticated_peers
                .get(peer_id)
                .is_some_and(|evidence| {
                    evidence.identity_type == PeerIdentityType::Admin
                        && evidence.noise_static_pubkey == info.noise_static_pubkey
                        && evidence.validate_for(*peer_id)
                });
            if locally_authenticated_admin {
                global_trusted_keys.insert(
                    info.noise_static_pubkey.clone(),
                    TrustedKeyMetadata {
                        source: TrustedKeySource::OspfNode,
                        expiry_unix: None,
                    },
                );
            }

            let raw_route_info = self.raw_peer_infos.get(peer_id);
            let raw_route_info = raw_route_info.as_deref();

            for (proof_idx, proof) in info.trusted_credential_pubkeys.iter().enumerate() {
                if !self.credential_proof_is_valid(raw_route_info, proof_idx, proof, network_secret)
                {
                    continue;
                }

                let Some(credential) = proof.credential.as_ref() else {
                    continue;
                };
                let Some((credential, certificate_identity)) =
                    self.normalize_credential_policy(credential, now)
                else {
                    continue;
                };
                let certificate_identity = raw_route_info
                    .and_then(|raw| {
                        raw_credential_certificate_bytes_from_route_info(raw, proof_idx)
                    })
                    .map(|raw_certificate| {
                        let mut identity = vec![1u8];
                        identity.extend_from_slice(&raw_certificate);
                        identity
                    })
                    .unwrap_or(certificate_identity);
                let expiry_unix = credential.expiry_unix;
                match candidates.entry(credential.pubkey.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((credential, certificate_identity, expiry_unix));
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        if entry.get().1 != certificate_identity {
                            conflicting_pubkeys.insert(entry.key().clone());
                        }
                    }
                }
            }
        }

        let mut all_trusted = HashMap::new();
        for (pubkey, (credential, _, expiry_unix)) in candidates {
            if conflicting_pubkeys.contains(&pubkey) {
                continue;
            }
            global_trusted_keys.insert(
                pubkey.clone(),
                TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: Some(expiry_unix),
                },
            );
            all_trusted.insert(pubkey, credential);
        }

        (all_trusted, global_trusted_keys)
    }

    fn replace_trusted_credential_pubkeys(
        &self,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) -> HashSet<Vec<u8>> {
        let prev_trusted = self
            .trusted_credential_pubkeys
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        self.trusted_credential_pubkeys.clear();
        for (pubkey, credential) in all_trusted {
            self.trusted_credential_pubkeys
                .insert(pubkey.clone(), credential.clone());
        }

        prev_trusted
    }

    fn collect_non_reusable_credential_owners<F>(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
        mut is_peer_active: F,
    ) -> (HashMap<Vec<u8>, PeerId>, BTreeSet<PeerId>)
    where
        F: FnMut(PeerId) -> bool,
    {
        let mut candidates: BTreeMap<Vec<u8>, BTreeSet<PeerId>> = BTreeMap::new();

        for (peer_id, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() {
                continue;
            }

            let Some(credential) = all_trusted.get(&info.noise_static_pubkey) else {
                continue;
            };
            if Self::credential_is_reusable(credential) {
                continue;
            }
            if !is_peer_active(*peer_id) {
                continue;
            }

            candidates
                .entry(info.noise_static_pubkey.clone())
                .or_default()
                .insert(*peer_id);
        }

        let mut active_owners = HashMap::new();
        let mut duplicate_untrusted_peers = BTreeSet::new();

        for (pubkey, candidate_peer_ids) in candidates {
            let Some(owner_peer_id) = candidate_peer_ids.iter().next().copied() else {
                continue;
            };
            active_owners.insert(pubkey, owner_peer_id);

            duplicate_untrusted_peers.extend(
                candidate_peer_ids
                    .into_iter()
                    .filter(|peer_id| *peer_id != owner_peer_id),
            );
        }

        (active_owners, duplicate_untrusted_peers)
    }

    fn replace_non_reusable_credential_owners(&self, active_owners: HashMap<Vec<u8>, PeerId>) {
        self.non_reusable_credential_owners
            .retain(|pubkey, _| active_owners.contains_key(pubkey));

        for (pubkey, peer_id) in active_owners {
            self.non_reusable_credential_owners.insert(pubkey, peer_id);
        }
    }

    fn replace_suppressed_non_reusable_credential_peers(
        &self,
        suppressed_peers: BTreeSet<PeerId>,
    ) -> bool {
        let _topology_guard = self.topology_state_lock();
        self.replace_suppressed_non_reusable_credential_peers_locked(suppressed_peers)
    }

    /// Replace the suppression set while the topology lock is already held.
    ///
    /// Credential verification can hold a peer-info read guard while it updates
    /// suppression. The locked helper avoids taking the topology lock twice.
    fn replace_suppressed_non_reusable_credential_peers_locked(
        &self,
        suppressed_peers: BTreeSet<PeerId>,
    ) -> bool {
        let current: BTreeSet<_> = self
            .suppressed_non_reusable_credential_peers
            .iter()
            .map(|entry| *entry.key())
            .collect();
        if current == suppressed_peers {
            return false;
        }

        self.suppressed_non_reusable_credential_peers
            .retain(|peer_id, _| suppressed_peers.contains(peer_id));

        for peer_id in suppressed_peers {
            self.suppressed_non_reusable_credential_peers
                .insert(peer_id, ());
        }

        self.version.inc();
        true
    }

    fn is_route_suppressed(&self, peer_id: PeerId) -> bool {
        self.suppressed_non_reusable_credential_peers
            .contains_key(&peer_id)
    }

    fn update_credential_groups(
        &self,
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) {
        for (_, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() {
                continue;
            }

            let Some(credential) = all_trusted.get(&info.noise_static_pubkey) else {
                continue;
            };
            let mut group_map = self.get_proof_groups(info.peer_id);
            for group in &credential.groups {
                group_map.entry(group.clone()).or_default();
            }
            self.set_peer_groups(info.peer_id, group_map);
        }
    }

    fn collect_revoked_credential_peers(
        peer_infos: &OrderedHashMap<PeerId, RoutePeerInfo>,
        prev_trusted: &HashSet<Vec<u8>>,
        all_trusted: &HashMap<Vec<u8>, TrustedCredentialPubkey>,
    ) -> BTreeSet<PeerId> {
        let mut untrusted_peers = BTreeSet::new();

        for (peer_id, info) in peer_infos.iter() {
            if info.noise_static_pubkey.is_empty() || info.version == 0 {
                continue;
            }

            if prev_trusted.contains(&info.noise_static_pubkey)
                && !all_trusted.contains_key(&info.noise_static_pubkey)
            {
                untrusted_peers.insert(*peer_id);
            }
        }

        untrusted_peers
    }

    fn get_connected_peers<T: FromIterator<PeerId>>(&self, peer_id: PeerId) -> Option<T> {
        self.conn_map
            .read()
            .get(&peer_id)
            .map(|x| x.connected_peers.iter().copied().collect())
    }

    fn remove_peer(&self, peer_id: PeerId) {
        self.remove_peers([peer_id]);
    }

    fn remove_peers<I>(&self, peer_ids: I)
    where
        I: IntoIterator<Item = PeerId>,
    {
        let _topology_guard = self.topology_state_lock();
        self.remove_peers_locked(peer_ids);
    }

    /// Remove peers while the topology lock is already held.
    fn remove_peers_locked<I>(&self, peer_ids: I)
    where
        I: IntoIterator<Item = PeerId>,
    {
        let peer_ids: HashSet<_> = peer_ids.into_iter().collect();
        if peer_ids.is_empty() {
            return;
        }

        for peer_id in &peer_ids {
            tracing::warn!(?peer_id, "remove_peer from synced_route_info");
        }

        {
            let mut peer_infos = self.peer_infos.write();
            let mut conn_map = self.conn_map.write();
            for peer_id in &peer_ids {
                peer_infos.remove(peer_id);
                conn_map.remove(peer_id);
            }
        }

        for peer_id in &peer_ids {
            self.raw_peer_infos.remove(peer_id);
            if let Some(bytes) = self.retained_peer_bytes.lock().unwrap().remove(peer_id) {
                self.retained_peer_bytes_total
                    .fetch_sub(bytes, Ordering::AcqRel);
                self.process_memory.release(bytes);
            }
            self.group_trust_map.remove(peer_id);
            self.group_trust_map_cache.remove(peer_id);
        }
        self.foreign_network
            .retain(|k, _| !peer_ids.contains(&k.peer_id));

        shrink_dashmap(&self.raw_peer_infos, None);
        shrink_dashmap(&self.foreign_network, None);
        shrink_dashmap(&self.group_trust_map, None);
        shrink_dashmap(&self.group_trust_map_cache, None);

        self.version.inc();
    }

    /// Fill missing peer records while the topology lock is already held.
    fn fill_empty_peer_info_locked(&self, peer_ids: &BTreeSet<PeerId>) -> bool {
        let mut need_inc_version = false;
        for peer_id in peer_ids {
            let guard = self.peer_infos.upgradable_read();
            if !guard.contains_key(peer_id) {
                let mut peer_info = RoutePeerInfo::new();
                let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
                peer_info.last_update = Some(Timestamp::now());
                guard.insert(*peer_id, peer_info);
                need_inc_version = true;
            } else {
                drop(guard);
            }

            let guard = self.conn_map.upgradable_read();
            if !guard.contains_key(peer_id) {
                let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
                guard.insert(*peer_id, RouteConnInfo::default());
                need_inc_version = true;
            } else {
                drop(guard);
            }
        }
        need_inc_version
    }

    fn fill_empty_peer_info(&self, peer_ids: &BTreeSet<PeerId>) {
        if self.fill_empty_peer_info_locked(peer_ids) {
            self.version.inc();
        }
    }

    fn get_peer_info_version_with_default(&self, peer_id: PeerId) -> Version {
        self.peer_infos
            .read()
            .get(&peer_id)
            .map(|x| x.version)
            .unwrap_or(0)
    }

    fn get_avoid_relay_data(&self, peer_id: PeerId) -> bool {
        // if avoid relay, just set all outgoing edges to a large value: AVOID_RELAY_COST.
        self.peer_infos
            .read()
            .get(&peer_id)
            .and_then(|x| x.feature_flag)
            .map(|x| x.avoid_relay_data)
            .unwrap_or_default()
    }

    fn check_duplicate_peer_id(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        dst_peer_route_id: Option<u64>,
        info: &RoutePeerInfo,
    ) -> Result<(), Error> {
        // 1. check if we are duplicated.
        if info.peer_id == my_peer_id {
            if info.peer_route_id != my_peer_route_id
                && info.version > self.get_peer_info_version_with_default(info.peer_id)
            {
                return Err(Error::DuplicatePeerId);
            }
        } else if info.peer_id == dst_peer_id {
            let Some(dst_peer_route_id) = dst_peer_route_id else {
                return Ok(());
            };

            if dst_peer_route_id != info.peer_route_id
                && info.version < self.get_peer_info_version_with_default(info.peer_id)
            {
                // if dst peer send to us with lower version info of dst peer, dst peer id is duplicated
                return Err(Error::DuplicatePeerId);
            }
        }

        Ok(())
    }

    /// Check the complete merged route state before any map mutation.
    ///
    /// Per-request limits do not protect state accumulated across updates.
    fn validate_merged_route_state_locked(
        &self,
        peer_infos: &[RoutePeerInfo],
        conn_info: Option<&ConnInfo>,
    ) -> Result<(), Error> {
        let current_peer_infos = self.peer_infos.read();
        let current_conn_map = self.conn_map.read();
        let mut peer_ids = current_peer_infos.keys().copied().collect::<HashSet<_>>();
        let mut merged_conn = current_conn_map
            .iter()
            .map(|(peer_id, info)| (*peer_id, (info.version.get(), info.connected_peers.clone())))
            .collect::<HashMap<PeerId, (Version, BTreeSet<PeerId>)>>();

        for info in peer_infos {
            peer_ids.insert(info.peer_id);
        }

        let mut add_peer_id = |peer_id: PeerId| -> Result<(), Error> {
            peer_ids.insert(peer_id);
            if peer_ids.len() > MAX_ROUTE_SYNC_PEERS {
                return Err(Error::Stopped);
            }
            Ok(())
        };

        if let Some(conn_info) = conn_info {
            match conn_info {
                ConnInfo::ConnBitmap(bitmap) => {
                    for peer_id in &bitmap.peer_ids {
                        add_peer_id(peer_id.peer_id)?;
                    }
                    for (source_idx, peer_id) in bitmap.peer_ids.iter().enumerate() {
                        let connected_peers = bitmap.get_connected_peers(source_idx);
                        for connected_peer_id in &connected_peers {
                            add_peer_id(*connected_peer_id)?;
                        }
                        let should_replace = merged_conn
                            .get(&peer_id.peer_id)
                            .is_none_or(|(version, _)| peer_id.version > *version);
                        if should_replace {
                            merged_conn.insert(peer_id.peer_id, (peer_id.version, connected_peers));
                        }
                    }
                }
                ConnInfo::ConnPeerList(list) => {
                    for source in &list.peer_conn_infos {
                        let Some(peer_id) = source.peer_id else {
                            return Err(Error::Stopped);
                        };
                        add_peer_id(peer_id.peer_id)?;
                        let connected_peers = source
                            .connected_peer_ids
                            .iter()
                            .copied()
                            .collect::<BTreeSet<_>>();
                        for connected_peer_id in &connected_peers {
                            add_peer_id(*connected_peer_id)?;
                        }
                        let should_replace = merged_conn
                            .get(&peer_id.peer_id)
                            .is_none_or(|(version, _)| peer_id.version > *version);
                        if should_replace {
                            merged_conn.insert(peer_id.peer_id, (peer_id.version, connected_peers));
                        }
                    }
                }
            }
        }

        if peer_ids.len() > MAX_ROUTE_SYNC_PEERS {
            return Err(Error::Stopped);
        }
        let mut edge_count = 0usize;
        for (_, (_, connected_peers)) in merged_conn {
            if connected_peers.len() > MAX_ROUTE_SYNC_EDGES_PER_SOURCE {
                return Err(Error::Stopped);
            }
            edge_count = edge_count
                .checked_add(connected_peers.len())
                .ok_or(Error::Stopped)?;
            if edge_count > MAX_ROUTE_SYNC_EDGES {
                return Err(Error::Stopped);
            }
        }
        Ok(())
    }

    fn update_peer_infos(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
    ) -> Result<(), Error> {
        let _topology_guard = self.topology_state_lock();
        self.validate_merged_route_state_locked(peer_infos, None)?;
        self.update_peer_infos_locked(
            my_peer_id,
            my_peer_route_id,
            dst_peer_id,
            peer_infos,
            raw_peer_infos,
        )
    }

    fn update_peer_infos_locked(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
    ) -> Result<(), Error> {
        if peer_infos.len() != raw_peer_infos.len() {
            return Err(Error::Stopped);
        }
        let mut need_inc_version = false;
        for (idx, route_info) in peer_infos.iter().enumerate() {
            let Some(raw_route_info) = raw_peer_infos.get(idx) else {
                return Err(Error::Stopped);
            };
            let retained_bytes = route_info
                .encoded_len()
                .saturating_add(raw_route_info.encoded_len())
                .saturating_mul(ROUTE_PEER_RETAINED_EXPANSION_FACTOR)
                .saturating_add(ROUTE_PEER_RETAINED_OVERHEAD_BYTES);
            let mut route_info = route_info.clone();
            route_info.normalize_multicast_groups();
            self.check_duplicate_peer_id(
                my_peer_id,
                my_peer_route_id,
                dst_peer_id,
                if route_info.peer_id == dst_peer_id {
                    self.peer_infos
                        .read()
                        .get(&dst_peer_id)
                        .map(|x| x.peer_route_id)
                } else {
                    None
                },
                &route_info,
            )?;

            let Some(peer_id_raw) = raw_route_info
                .get_field_by_name("peer_id")
                .and_then(|field| field.as_u32())
            else {
                return Err(Error::Stopped);
            };
            if peer_id_raw != route_info.peer_id {
                return Err(Error::Stopped);
            }

            let mut guard = self.peer_infos.write();
            // time between peers may not be synchronized, so update last_update to local now.
            // note only last_update with larger version will be updated to local saved peer info.
            route_info.last_update = Some(Timestamp::now());
            if guard
                .get(&route_info.peer_id)
                .is_none_or(|old| route_info.version > old.version)
            {
                let old_bytes = self
                    .retained_peer_bytes
                    .lock()
                    .unwrap()
                    .get(&route_info.peer_id)
                    .copied()
                    .unwrap_or_default();
                let added_bytes = retained_bytes.saturating_sub(old_bytes);
                if added_bytes != 0 && !self.process_memory.reserve(added_bytes) {
                    return Err(Error::Stopped);
                }
                self.raw_peer_infos
                    .insert(route_info.peer_id, raw_route_info.clone());
                let peer_id = route_info.peer_id;
                guard.insert(peer_id, route_info);
                self.retained_peer_bytes
                    .lock()
                    .unwrap()
                    .insert(peer_id, retained_bytes);
                if retained_bytes >= old_bytes {
                    self.retained_peer_bytes_total
                        .fetch_add(retained_bytes - old_bytes, Ordering::AcqRel);
                } else {
                    let released = old_bytes - retained_bytes;
                    self.retained_peer_bytes_total
                        .fetch_sub(released, Ordering::AcqRel);
                    self.process_memory.release(released);
                }
                need_inc_version = true;
            }
        }
        if need_inc_version {
            self.version.inc();
        }
        Ok(())
    }

    fn update_conn_info_one_peer(
        &self,
        peer_id_version: &PeerIdVersion,
        connected_peers: BTreeSet<PeerId>,
    ) -> bool {
        let mut guard = self.conn_map.write();
        if guard
            .get_mut(&peer_id_version.peer_id)
            .is_none_or(|old| peer_id_version.version > old.version.get())
        {
            guard.insert(
                peer_id_version.peer_id,
                RouteConnInfo {
                    connected_peers,
                    version: peer_id_version.version.into(),
                    last_update: SystemTime::now(),
                },
            );
            return true;
        }

        false
    }

    fn update_conn_info_with_bitmap(&self, conn_bitmap: &RouteConnBitmap) {
        self.fill_empty_peer_info(&conn_bitmap.peer_ids.iter().map(|x| x.peer_id).collect());

        let mut need_inc_version = false;

        for (peer_idx, peer_id_version) in conn_bitmap.peer_ids.iter().enumerate() {
            let connceted_peers = conn_bitmap.get_connected_peers(peer_idx);
            self.fill_empty_peer_info(&connceted_peers);
            need_inc_version |= self.update_conn_info_one_peer(peer_id_version, connceted_peers);
        }
        if need_inc_version {
            self.version.inc();
        }
    }

    fn update_conn_info_with_list(&self, conn_peer_list: &RouteConnPeerList) {
        let mut need_inc_version = false;

        for peer_conn_info in &conn_peer_list.peer_conn_infos {
            let Some(peer_id_version) = peer_conn_info.peer_id else {
                continue;
            };
            let connected_peers: BTreeSet<PeerId> =
                peer_conn_info.connected_peer_ids.iter().copied().collect();

            self.fill_empty_peer_info(&connected_peers);
            need_inc_version |= self.update_conn_info_one_peer(&peer_id_version, connected_peers);
        }
        if need_inc_version {
            self.version.inc();
        }
    }

    fn update_peer_infos_and_conn_info(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
        conn_info: Option<&ConnInfo>,
    ) -> Result<(), Error> {
        self.update_peer_infos_and_conn_info_with_authority(
            my_peer_id,
            my_peer_route_id,
            dst_peer_id,
            peer_infos,
            raw_peer_infos,
            conn_info,
            true,
        )?;
        Ok(())
    }

    fn update_peer_infos_and_conn_info_with_authority(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        dst_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
        conn_info: Option<&ConnInfo>,
        source_has_topology_authority: bool,
    ) -> Result<bool, Error> {
        let _topology_guard = self.topology_state_lock();
        self.validate_merged_route_state_locked(peer_infos, conn_info)?;
        let version_before = self.version.get();
        if !source_has_topology_authority && self.conn_map.write().remove(&dst_peer_id).is_some() {
            self.version.inc();
        }
        self.update_peer_infos_locked(
            my_peer_id,
            my_peer_route_id,
            dst_peer_id,
            peer_infos,
            raw_peer_infos,
        )?;
        if let Some(conn_info) = conn_info {
            self.update_conn_info_locked(conn_info);
        }
        Ok(self.version.get() != version_before)
    }

    fn update_conn_info(&self, conn_info: &ConnInfo) {
        let _topology_guard = self.topology_state_lock();
        if self
            .validate_merged_route_state_locked(&[], Some(conn_info))
            .is_err()
        {
            tracing::warn!("route connection state budget rejected an update");
            return;
        }
        self.update_conn_info_locked(conn_info);
    }

    fn update_conn_info_locked(&self, conn_info: &ConnInfo) {
        match conn_info {
            ConnInfo::ConnBitmap(conn_bitmap) => {
                self.update_conn_info_with_bitmap(conn_bitmap);
            }
            ConnInfo::ConnPeerList(conn_peer_list) => {
                self.update_conn_info_with_list(conn_peer_list);
            }
        }
    }

    fn update_foreign_network(&self, foreign_network: &RouteForeignNetworkInfos) -> bool {
        let _topology_guard = self.topology_state_lock();
        let mut changed = false;
        for item in foreign_network.infos.iter().map(Clone::clone) {
            let Some(key) = item.key else {
                continue;
            };
            let Some(mut entry) = item.value else {
                continue;
            };

            entry.foreign_peer_ids.sort_unstable();
            entry.foreign_peer_ids.dedup();
            entry
                .foreign_peer_ids
                .truncate(MAX_ROUTE_SYNC_EDGES_PER_SOURCE);
            if entry.owner_noise_static_pubkey.len() != 32 {
                entry.owner_noise_static_pubkey.clear();
            }
            entry.last_update = Some(Timestamp::now());

            self.foreign_network
                .entry(key.clone())
                .and_modify(|old_entry| {
                    if entry.version > old_entry.version {
                        *old_entry = entry.clone();
                        changed = true;
                    }
                })
                .or_insert_with(|| {
                    changed = true;
                    entry.clone()
                });
        }
        changed
    }

    fn update_my_peer_info(
        &self,
        my_peer_id: PeerId,
        my_peer_route_id: u64,
        global_ctx: &ArcGlobalCtx,
        public_ipv6_addr_lease: Option<Ipv6Inet>,
    ) -> bool {
        let _topology_guard = self.topology_state_lock();
        let mut new = RoutePeerInfo::new_updated_self(
            my_peer_id,
            my_peer_route_id,
            global_ctx,
            public_ipv6_addr_lease,
        );
        let mut guard = self.peer_infos.upgradable_read();
        let old = guard.get(&my_peer_id);
        refresh_local_bridge_attestation(global_ctx, &mut new, old);
        let new_version = old.map(|x| x.version).unwrap_or(0) + 1;
        let need_insert_new = if let Some(old) = old {
            RoutePeerInfo::try_update_new_peer_info(old, &mut new)
        } else {
            true
        };

        if need_insert_new {
            let acl_groups = if old.map(|x| x.groups != new.groups).unwrap_or(true) {
                Some(new.groups.clone())
            } else {
                None
            };

            guard.with_upgraded(|peer_infos| {
                new.last_update = Some(Timestamp::now());
                new.version = new_version;
                peer_infos.insert(my_peer_id, new)
            });
            drop(guard);

            if let Some(acl_groups) = acl_groups {
                self.update_my_group_trusts(my_peer_id, &acl_groups);
            }

            self.version.inc();
            true
        } else {
            false
        }
    }

    /// Update local adjacency while the topology lock is already held.
    fn update_my_conn_info_locked(
        &self,
        my_peer_id: PeerId,
        connected_peers: BTreeSet<PeerId>,
    ) -> bool {
        let mut updated = self.fill_empty_peer_info_locked(&connected_peers);

        let guard = self.conn_map.upgradable_read();
        let my_conn_info = guard.get(&my_peer_id);
        let new_version = my_conn_info.map(|x| x.version.get()).unwrap_or(0) + 1;

        if my_conn_info.is_none_or(|old| old.connected_peers != connected_peers) {
            let mut guard = RwLockUpgradableReadGuard::upgrade(guard);
            guard.insert(
                my_peer_id,
                RouteConnInfo {
                    connected_peers,
                    version: new_version.into(),
                    last_update: SystemTime::now(),
                },
            );
            updated = true;
        }
        updated
    }

    fn update_my_conn_info(&self, my_peer_id: PeerId, connected_peers: BTreeSet<PeerId>) -> bool {
        let _topology_guard = self.topology_state_lock();
        let updated = self.update_my_conn_info_locked(my_peer_id, connected_peers);
        if updated {
            self.version.inc();
        }
        updated
    }

    fn update_my_foreign_network(
        &self,
        my_peer_id: PeerId,
        foreign_networks: ForeignNetworkRouteInfoMap,
    ) -> bool {
        let _topology_guard = self.topology_state_lock();
        let now = SystemTime::now();
        let now_version = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as Version;
        let mut updated = false;
        for mut item in self
            .foreign_network
            .iter_mut()
            .filter(|x| x.key().peer_id == my_peer_id)
        {
            let (key, entry) = item.pair_mut();
            if let Some(mut new_entry) = foreign_networks.get_mut(key) {
                assert!(!new_entry.foreign_peer_ids.is_empty());
                if let Some(is_newer) = is_foreign_network_info_newer(&new_entry, entry) {
                    let need_renew = is_newer
                        || now
                            .duration_since(entry.last_update.unwrap().try_into().unwrap())
                            .unwrap_or(Duration::from_secs(0))
                            > UPDATE_PEER_INFO_PERIOD;
                    if need_renew {
                        new_entry.version = std::cmp::max(new_entry.version + 1, now_version);
                        *entry = new_entry.clone();
                        updated = true;
                    }
                }
                drop(new_entry);
                foreign_networks.remove(key).unwrap();
            } else if !entry.foreign_peer_ids.is_empty() {
                entry.foreign_peer_ids.clear();
                entry.last_update = Some(Timestamp::now());
                entry.version = std::cmp::max(entry.version + 1, now_version);
                updated = true;
            }
        }

        for item in foreign_networks.iter() {
            assert!(!item.value().foreign_peer_ids.is_empty());
            self.foreign_network
                .entry(item.key().clone())
                .and_modify(|old_entry| {
                    if item.value().version > old_entry.version {
                        *old_entry = item.value().clone();
                    }
                })
                .or_insert_with(|| {
                    let mut v = item.value().clone();
                    v.version = now_version;
                    v
                });
            updated = true;
        }

        if updated {
            self.version.inc();
        }

        updated
    }

    fn get_next_last_sync_succ_timestamp(&self) -> SystemTime {
        let _peer_info_lock = self.peer_infos.read();
        let _conn_info_lock = self.conn_map.read();
        // TODO: add conn and foreign network lock

        SystemTime::now()
    }

    fn verify_and_update_group_trusts(
        &self,
        peer_infos: &[RoutePeerInfo],
        local_group_declarations: &[GroupIdentity],
        trust_admin_groups_without_proof: bool,
    ) {
        let local_group_declarations = local_group_declarations
            .iter()
            .map(|g| (g.group_name.as_str(), g.group_secret.as_str()))
            .collect::<std::collections::HashMap<&str, &str>>();

        let verify_groups = |info: &RoutePeerInfo| -> HashMap<String, Vec<u8>> {
            let mut trusted_groups_for_peer: HashMap<String, Vec<u8>> = HashMap::new();

            for group_proof in &info.groups {
                let name = &group_proof.group_name;
                let proof_bytes = group_proof.group_proof.clone();

                if let Some(&local_secret) =
                    local_group_declarations.get(group_proof.group_name.as_str())
                {
                    if group_proof.verify(local_secret, info.peer_id) {
                        trusted_groups_for_peer.insert(name.clone(), proof_bytes);
                    } else {
                        tracing::warn!(
                            peer_id = info.peer_id,
                            group = %group_proof.group_name,
                            "Group proof verification failed"
                        );
                    }
                }
            }

            if trust_admin_groups_without_proof && self.is_locally_authenticated_admin(info) {
                for group_proof in &info.groups {
                    trusted_groups_for_peer
                        .entry(group_proof.group_name.clone())
                        .or_default();
                }
            }

            trusted_groups_for_peer
        };

        for info in peer_infos {
            match self.group_trust_map.entry(info.peer_id) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    let trusted_groups_for_peer = verify_groups(info);

                    if trusted_groups_for_peer.is_empty() {
                        entry.remove();
                        self.group_trust_map_cache.remove(&info.peer_id);
                    } else {
                        let group_names = trusted_groups_for_peer.keys().cloned().collect();
                        self.group_trust_map_cache
                            .insert(info.peer_id, Arc::new(group_names));
                        *entry.get_mut() = trusted_groups_for_peer;
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    let trusted_groups_for_peer = verify_groups(info);

                    if !trusted_groups_for_peer.is_empty() {
                        let group_names = trusted_groups_for_peer.keys().cloned().collect();
                        self.group_trust_map_cache
                            .insert(info.peer_id, Arc::new(group_names));
                        entry.insert(trusted_groups_for_peer);
                    }
                }
            }
        }
    }

    fn update_my_group_trusts(&self, my_peer_id: PeerId, groups: &[PeerGroupInfo]) {
        let mut my_group_map = HashMap::new();

        for group in groups.iter() {
            my_group_map.insert(group.group_name.clone(), group.group_proof.clone());
        }

        self.set_peer_groups(my_peer_id, my_group_map);
    }

    /// Collect trusted credential pubkeys from admin nodes (network_secret holders)
    /// and verify credential peers. Returns set of peer_ids that should be removed.
    /// Also returns a HashMap of trusted keys for synchronization to GlobalCtx.
    fn verify_and_update_credential_trusts(
        &self,
        network_secret: Option<&str>,
    ) -> (
        Vec<PeerId>,
        HashMap<Vec<u8>, crate::common::global_ctx::TrustedKeyMetadata>,
    ) {
        self.verify_and_update_credential_trusts_with_active_peers(network_secret, |_| true)
    }

    fn verify_and_update_credential_trusts_with_active_peers<F>(
        &self,
        network_secret: Option<&str>,
        is_peer_active: F,
    ) -> (
        Vec<PeerId>,
        HashMap<Vec<u8>, crate::common::global_ctx::TrustedKeyMetadata>,
    )
    where
        F: FnMut(PeerId) -> bool,
    {
        let (untrusted_peers, global_trusted_keys, _) = self
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_secret,
                is_peer_active,
                None,
            );
        (untrusted_peers, global_trusted_keys)
    }

    fn verify_and_update_credential_trusts_with_active_peers_protecting<F>(
        &self,
        network_secret: Option<&str>,
        is_peer_active: F,
        protected_peer_id: Option<PeerId>,
    ) -> (
        Vec<PeerId>,
        HashMap<Vec<u8>, crate::common::global_ctx::TrustedKeyMetadata>,
        bool,
    )
    where
        F: FnMut(PeerId) -> bool,
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let _topology_guard = self.topology_state_lock();
        let peer_infos = self.peer_infos.read();
        let (all_trusted, global_trusted_keys) =
            self.collect_trusted_credentials(&peer_infos, network_secret, now);
        let prev_trusted = self.replace_trusted_credential_pubkeys(&all_trusted);
        let (active_non_reusable_owners, mut duplicate_untrusted_peers) =
            self.collect_non_reusable_credential_owners(&peer_infos, &all_trusted, is_peer_active);
        if let Some(protected_peer_id) = protected_peer_id {
            duplicate_untrusted_peers.remove(&protected_peer_id);
        }
        self.replace_non_reusable_credential_owners(active_non_reusable_owners);
        let suppressed_changed =
            self.replace_suppressed_non_reusable_credential_peers_locked(duplicate_untrusted_peers);
        self.update_credential_groups(&peer_infos, &all_trusted);

        let mut untrusted_peers =
            Self::collect_revoked_credential_peers(&peer_infos, &prev_trusted, &all_trusted);
        if let Some(protected_peer_id) = protected_peer_id {
            untrusted_peers.remove(&protected_peer_id);
        }

        // Remove untrusted peers from peer_infos so they won't appear in route graph
        if !untrusted_peers.is_empty() {
            drop(peer_infos); // release read lock before writing
            for peer_id in &untrusted_peers {
                tracing::warn!(?peer_id, "removing untrusted peer from route info");
            }
            self.remove_peers_locked(untrusted_peers.iter().copied());
        }

        (
            untrusted_peers.into_iter().collect(),
            global_trusted_keys,
            suppressed_changed,
        )
    }

    fn is_admin_peer(&self, info: &RoutePeerInfo) -> bool {
        if info.version == 0 {
            return false;
        }
        matches!(
            Self::peer_identity_type(info),
            Some(PeerIdentityType::Admin)
        )
    }

    fn is_locally_authenticated_admin(&self, info: &RoutePeerInfo) -> bool {
        self.locally_authenticated_peers
            .get(&info.peer_id)
            .is_some_and(|evidence| {
                evidence.identity_type == PeerIdentityType::Admin
                    && evidence.noise_static_pubkey == info.noise_static_pubkey
                    && evidence.validate_for(info.peer_id)
            })
    }

    fn is_credential_peer(&self, peer_id: PeerId) -> bool {
        let peer_infos = self.peer_infos.read();
        peer_infos
            .get(&peer_id)
            .map(Self::is_credential_peer_info)
            .unwrap_or(false)
    }

    fn get_credential_info_by_pubkey(&self, peer_pubkey: &[u8]) -> Option<TrustedCredentialPubkey> {
        if peer_pubkey.is_empty() {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(i64::MAX);
        self.trusted_credential_pubkeys
            .get(peer_pubkey)
            .map(|r| r.value().clone())
            .and_then(|credential| {
                self.normalize_credential_policy(&credential, now)
                    .map(|(normalized, _)| normalized)
            })
    }
}

type PeerGraph = Graph<PeerId, usize, Directed>;
type SpeedGraph = Graph<PeerId, SpeedEdge, Directed>;

/// Immutable route topology captured from one topology version.
///
/// This value is independent of route-cost measurements. Cost-only rebuilds
/// derive weighted graphs from this committed topology and never read live
/// topology state.
#[derive(Debug, Clone)]
struct TopologyBuildInput {
    version: Version,
    graph: PeerGraph,
    start_node: NodeIndex,
    peer_infos: Arc<HashMap<PeerId, RoutePeerInfo>>,
    conn_map: Arc<HashMap<PeerId, RouteConnBuildInfo>>,
    suppressed_peer_ids: Arc<HashSet<PeerId>>,
    relay_credential_peers: Arc<HashSet<PeerId>>,
    local_proxy_cidrs: Vec<IpCidr>,
}

/// Immutable route input with calculator-specific edge weights.
#[derive(Debug)]
struct RouteBuildInput {
    version: Version,
    graph: PeerGraph,
    speed_graph: SpeedGraph,
    speed_preparation: Option<WidestPathPreparation>,
    start_node: NodeIndex,
    peer_infos: Arc<HashMap<PeerId, RoutePeerInfo>>,
    conn_map: Arc<HashMap<PeerId, RouteConnBuildInfo>>,
    suppressed_peer_ids: Arc<HashSet<PeerId>>,
    local_proxy_cidrs: Vec<IpCidr>,
}

#[derive(Debug, Clone)]
struct RouteConnBuildInfo {
    connected_peers: BTreeSet<PeerId>,
    version: Version,
}

#[derive(Debug)]
struct SharedRouteMaps {
    peer_infos: Arc<HashMap<PeerId, RoutePeerInfo>>,
    suppressed_peer_ids: Arc<HashSet<PeerId>>,
    ipv4_peer_id_map: Arc<HashMap<Ipv4Addr, PeerId>>,
    ipv6_peer_id_map: Arc<HashMap<Ipv6Addr, PeerId>>,
    cidr_peer_id_map: Arc<PrefixMap<Ipv4Cidr, PeerId>>,
    cidr_v6_peer_id_map: Arc<PrefixMap<Ipv6Cidr, PeerId>>,
    service_routes: Arc<ServiceRouteSnapshot>,
    next_hop_map_version: Version,
}

fn add_authorized_relay_reverse_edges(
    graph: &mut PeerGraph,
    peer_id_to_node_index: &HashMap<PeerId, NodeIndex>,
    peer_infos: &HashMap<PeerId, RoutePeerInfo>,
    conn_map: &HashMap<PeerId, RouteConnBuildInfo>,
    relay_credential_peers: &HashSet<PeerId>,
    suppressed_peer_ids: &HashSet<PeerId>,
) {
    for (source_peer_id, source_conn) in conn_map {
        let source_is_admin = peer_infos
            .get(source_peer_id)
            .and_then(|info| PeerIdentityType::try_from(info.identity_type).ok())
            .is_some_and(|identity| matches!(identity, PeerIdentityType::Admin));
        if !source_is_admin {
            continue;
        }
        let Some(source_node) = peer_id_to_node_index.get(source_peer_id) else {
            continue;
        };
        for destination_peer_id in &source_conn.connected_peers {
            if suppressed_peer_ids.contains(destination_peer_id)
                || !relay_credential_peers.contains(destination_peer_id)
            {
                continue;
            }
            let Some(destination_node) = peer_id_to_node_index.get(destination_peer_id) else {
                continue;
            };
            let has_explicit_reverse = conn_map
                .get(destination_peer_id)
                .is_some_and(|connection| connection.connected_peers.contains(source_peer_id));
            if !has_explicit_reverse {
                graph.add_edge(*destination_node, *source_node, 0);
            }
        }
    }
}

impl TopologyBuildInput {
    fn capture(my_peer_id: PeerId, synced_info: &SyncedRouteInfo) -> Self {
        let (version, peer_infos, conn_map, suppressed_peer_ids) = {
            let _topology_guard = synced_info.topology_state_lock();
            let version = synced_info.version.get();
            let peer_infos = synced_info
                .peer_infos
                .read()
                .iter()
                .filter(|(_, info)| info.version != 0)
                .map(|(peer_id, info)| (*peer_id, info.clone()))
                .collect::<HashMap<_, _>>();
            let conn_map = synced_info
                .conn_map
                .read()
                .iter()
                .map(|(peer_id, info)| {
                    (
                        *peer_id,
                        RouteConnBuildInfo {
                            connected_peers: info.connected_peers.clone(),
                            version: info.version.get(),
                        },
                    )
                })
                .collect::<HashMap<_, _>>();
            let suppressed_peer_ids = synced_info
                .suppressed_non_reusable_credential_peers
                .iter()
                .map(|entry| *entry.key())
                .collect::<HashSet<_>>();
            (version, peer_infos, conn_map, suppressed_peer_ids)
        };

        let relay_credential_peers = peer_infos
            .iter()
            .filter_map(|(peer_id, info)| {
                SyncedRouteInfo::is_credential_peer_info(info)
                    .then(|| synced_info.get_credential_info_by_pubkey(&info.noise_static_pubkey))
                    .flatten()
                    .is_some_and(|credential| credential.allow_relay)
                    .then_some(*peer_id)
            })
            .collect::<HashSet<_>>();
        let relay_credential_peers = Arc::new(relay_credential_peers);
        let peer_infos = Arc::new(peer_infos);
        let conn_map = Arc::new(conn_map);
        let suppressed_peer_ids = Arc::new(suppressed_peer_ids);
        let mut graph = PeerGraph::new();
        let mut peer_id_to_node_index = HashMap::with_capacity(peer_infos.len());
        let mut start_node = NodeIndex::end();

        for (peer_id, info) in peer_infos.iter() {
            let node_idx = graph.add_node(*peer_id);
            peer_id_to_node_index.insert(*peer_id, node_idx);
            if *peer_id == my_peer_id {
                start_node = node_idx;
            }
            debug_assert_ne!(info.version, 0);
        }

        if start_node != NodeIndex::end() {
            for (src_peer_id, src_node_idx) in &peer_id_to_node_index {
                if *src_peer_id != my_peer_id && suppressed_peer_ids.contains(src_peer_id) {
                    continue;
                }
                let Some(connected_peers) = conn_map.get(src_peer_id) else {
                    continue;
                };
                for dst_peer_id in &connected_peers.connected_peers {
                    let Some(dst_node_idx) = peer_id_to_node_index.get(dst_peer_id) else {
                        continue;
                    };
                    // A zero edge is a topology placeholder. The calculator
                    // applies the current directed cost during derivation.
                    graph.add_edge(*src_node_idx, *dst_node_idx, 0);
                }
            }
            add_authorized_relay_reverse_edges(
                &mut graph,
                &peer_id_to_node_index,
                &peer_infos,
                &conn_map,
                &relay_credential_peers,
                &suppressed_peer_ids,
            );
        }

        let local_proxy_cidrs = peer_infos
            .get(&my_peer_id)
            .into_iter()
            .flat_map(|info| &info.proxy_cidrs)
            .filter_map(|cidr| cidr.parse::<IpCidr>().ok())
            .collect();

        Self {
            version,
            graph,
            start_node,
            peer_infos,
            conn_map,
            suppressed_peer_ids,
            relay_credential_peers,
            local_proxy_cidrs,
        }
    }
}

impl TopologyBuildInput {
    /// Capture each calculator measurement once for this immutable topology.
    ///
    /// The caller holds the calculator write guard for this complete capture.
    /// Cost and delivery callbacks can therefore not observe mixed updates.
    fn with_measurements<T: RouteCostCalculatorInterface + ?Sized>(
        &self,
        cost_calc: &T,
        capture_cost: bool,
        capture_delivery: bool,
    ) -> RouteBuildInput {
        let mut graph = if capture_cost {
            self.graph.clone()
        } else {
            PeerGraph::new()
        };
        let mut speed_graph = if capture_delivery {
            SpeedGraph::with_capacity(self.graph.node_count(), self.graph.edge_count())
        } else {
            SpeedGraph::new()
        };
        if capture_delivery {
            for (node, peer_id) in self.graph.node_references() {
                let speed_node = speed_graph.add_node(*peer_id);
                debug_assert_eq!(speed_node, node);
            }
        }
        for edge in self.graph.edge_references() {
            let edge_id = edge.id();
            let src = edge.source();
            let dst = edge.target();
            let src_peer_id = self.graph[src];
            let dst_peer_id = self.graph[dst];
            let peer_avoid_relay_data = self
                .peer_infos
                .get(&src_peer_id)
                .and_then(|info| info.feature_flag)
                .is_some_and(|flags| flags.avoid_relay_data);
            // Least-hop and least-cost rebuilds need an edge weight. A
            // delivery-only rebuild still captures cost for speed latency.
            let raw_cost = if capture_cost || capture_delivery {
                cost_calc.calculate_cost(src_peer_id, dst_peer_id).max(0) as usize
            } else {
                1
            };
            let effective_cost = if peer_avoid_relay_data {
                raw_cost.saturating_add(AVOID_RELAY_COST)
            } else {
                raw_cost
            };
            if capture_cost {
                *graph
                    .edge_weight_mut(edge_id)
                    .expect("topology edge weight") = effective_cost;
            }

            let source_can_publish_delivery = src == self.start_node
                || self
                    .peer_infos
                    .get(&src_peer_id)
                    .and_then(|info| PeerIdentityType::try_from(info.identity_type).ok())
                    .is_some_and(|identity| matches!(identity, PeerIdentityType::Admin))
                || self.relay_credential_peers.contains(&src_peer_id);
            if capture_delivery
                && source_can_publish_delivery
                && (src == self.start_node || !peer_avoid_relay_data)
            {
                let Some(delivery_bps) = cost_calc.calculate_delivery_bps(src_peer_id, dst_peer_id)
                else {
                    continue;
                };
                if delivery_bps == 0 {
                    continue;
                }
                speed_graph.add_edge(
                    src,
                    dst,
                    SpeedEdge {
                        delivery_bps,
                        latency_ms: raw_cost as u64,
                    },
                );
            }
        }

        let speed_preparation =
            capture_delivery.then(|| prepare_widest_path(&speed_graph, self.start_node));

        RouteBuildInput {
            version: self.version,
            graph,
            speed_graph,
            speed_preparation,
            start_node: self.start_node,
            peer_infos: self.peer_infos.clone(),
            conn_map: self.conn_map.clone(),
            suppressed_peer_ids: self.suppressed_peer_ids.clone(),
            local_proxy_cidrs: self.local_proxy_cidrs.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpeedEdge {
    delivery_bps: u64,
    latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpeedPath {
    next_hop_peer_id: PeerId,
    quality: RouteQuality,
}

#[derive(Debug, Clone)]
struct WidestPathPreparation {
    capacities: Vec<u64>,
    destinations: Vec<(u64, NodeIndex)>,
    minimum_delivery_bps: Option<u64>,
    active_edge_count: usize,
    // Work charged while computing capacities and destination eligibility.
    capacity_work: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WidestPathWorkError;

#[derive(Debug, Clone, Copy)]
struct WidestPathWorkBudget {
    used: usize,
    limit: usize,
}

impl WidestPathWorkBudget {
    fn with_used(used: usize, limit: usize) -> Result<Self, WidestPathWorkError> {
        if used > limit {
            return Err(WidestPathWorkError);
        }
        Ok(Self { used, limit })
    }

    fn charge(&mut self, amount: usize) -> Result<(), WidestPathWorkError> {
        let next_used = self.used.checked_add(amount).ok_or(WidestPathWorkError)?;
        if next_used > self.limit {
            return Err(WidestPathWorkError);
        }
        self.used = next_used;
        Ok(())
    }
}

fn widest_path_work_limit(
    node_count: usize,
    edge_count: usize,
) -> Result<usize, WidestPathWorkError> {
    let topology_work = node_count
        .checked_add(edge_count)
        .ok_or(WidestPathWorkError)?;
    let destination_work = topology_work
        .checked_mul(node_count.max(1))
        .ok_or(WidestPathWorkError)?;
    topology_work
        .checked_add(destination_work)
        .and_then(|work| work.checked_mul(4))
        .map(|work| work.min(MAX_ROUTE_REBUILD_WORK))
        .ok_or(WidestPathWorkError)
}

fn widest_path_with_first_hop(
    graph: &SpeedGraph,
    start: NodeIndex,
) -> HashMap<NodeIndex, SpeedPath> {
    widest_path_with_work_stats(graph, start).0
}

#[derive(Debug, Clone, Copy, Default)]
struct WidestPathWorkStats {
    #[cfg(test)]
    sorted_edge_capacity: usize,
    #[cfg(test)]
    activation_rounds: usize,
    #[cfg(test)]
    activated_edges: usize,
    #[cfg(test)]
    label_relaxations: usize,
    #[cfg(test)]
    scanned_edges: usize,
    #[cfg(test)]
    peak_queue_len: usize,
    #[cfg(test)]
    peak_label_count: usize,
    #[cfg(test)]
    peak_active_edges: usize,
    #[cfg(test)]
    peak_active_outer_capacity: usize,
    #[cfg(test)]
    peak_active_inner_capacity: usize,
    #[cfg(test)]
    finalization_visits: usize,
    #[cfg(test)]
    capacity_edge_scans: usize,
    #[cfg(test)]
    threshold_count: usize,
    #[cfg(test)]
    destination_capacity: usize,
    #[cfg(test)]
    peak_newly_reachable: usize,
    #[cfg(test)]
    peak_queue_capacity: usize,
    #[cfg(test)]
    peak_route_count: usize,
    #[cfg(test)]
    peak_route_capacity: usize,
    #[cfg(test)]
    label_capacity: usize,
    #[cfg(test)]
    finalized_capacity: usize,
    #[cfg(test)]
    widest_capacity_capacity: usize,
}

#[cfg(test)]
impl WidestPathWorkStats {
    fn estimated_peak_temp_bytes(self, node_count: usize) -> usize {
        self.sorted_edge_capacity * std::mem::size_of::<(u64, NodeIndex, NodeIndex, u64)>()
            + self.peak_active_outer_capacity * std::mem::size_of::<Vec<(NodeIndex, u64)>>()
            + self.peak_active_inner_capacity * std::mem::size_of::<(NodeIndex, u64)>()
            + self.label_capacity.max(node_count)
                * std::mem::size_of::<Option<(u64, usize, PeerId)>>()
            // B-tree entries also own links, parent metadata, and allocator padding.
            + self.peak_queue_capacity
                * (std::mem::size_of::<(u64, usize, PeerId, usize)>()
                    + 4 * std::mem::size_of::<usize>())
            + self.finalized_capacity.max(node_count) * std::mem::size_of::<bool>()
            + self.widest_capacity_capacity.max(node_count) * std::mem::size_of::<u64>()
            + self.destination_capacity * std::mem::size_of::<(u64, NodeIndex)>()
            // HashMap storage includes the key/value pair and hash-table
            // metadata. Two words cover the bucket and control metadata.
            + self.peak_route_capacity
                * (std::mem::size_of::<(NodeIndex, SpeedPath)>()
                    + 2 * std::mem::size_of::<usize>())
    }
}

#[cfg(test)]
type LabelCount = usize;

#[cfg(not(test))]
#[derive(Default)]
struct LabelCount;

fn widest_path_with_work_stats(
    graph: &SpeedGraph,
    start: NodeIndex,
) -> (HashMap<NodeIndex, SpeedPath>, WidestPathWorkStats) {
    let mut work_stats = WidestPathWorkStats::default();
    let preparation = prepare_widest_path_with_stats(graph, start, &mut work_stats);
    let Ok(work_limit) = widest_path_work_limit(graph.node_count(), graph.edge_count()) else {
        return (HashMap::new(), work_stats);
    };
    let Ok(mut budget) = WidestPathWorkBudget::with_used(preparation.capacity_work, work_limit)
    else {
        return (HashMap::new(), work_stats);
    };
    match widest_path_with_preparation(graph, start, &preparation, &mut budget, &mut work_stats) {
        Ok(routes) => (routes, work_stats),
        Err(_) => (HashMap::new(), work_stats),
    }
}

fn prepare_widest_path(graph: &SpeedGraph, start: NodeIndex) -> WidestPathPreparation {
    let mut work_stats = WidestPathWorkStats::default();
    prepare_widest_path_with_stats(graph, start, &mut work_stats)
}

fn prepare_widest_path_with_stats(
    graph: &SpeedGraph,
    start: NodeIndex,
    work_stats: &mut WidestPathWorkStats,
) -> WidestPathPreparation {
    let Ok(work_limit) = widest_path_work_limit(graph.node_count(), graph.edge_count()) else {
        return WidestPathPreparation {
            capacities: vec![0; graph.node_count()],
            destinations: Vec::new(),
            minimum_delivery_bps: None,
            active_edge_count: 0,
            capacity_work: usize::MAX,
        };
    };
    let Ok(mut budget) = WidestPathWorkBudget::with_used(0, work_limit) else {
        unreachable!("zero work must fit the route rebuild budget");
    };
    prepare_widest_path_with_budget(graph, start, work_stats, &mut budget).unwrap_or_else(|_| {
        WidestPathPreparation {
            capacities: vec![0; graph.node_count()],
            destinations: Vec::new(),
            minimum_delivery_bps: None,
            active_edge_count: 0,
            capacity_work: usize::MAX,
        }
    })
}

fn prepare_widest_path_with_budget(
    graph: &SpeedGraph,
    start: NodeIndex,
    work_stats: &mut WidestPathWorkStats,
    budget: &mut WidestPathWorkBudget,
) -> Result<WidestPathPreparation, WidestPathWorkError> {
    if graph.node_weight(start).is_none() {
        return Ok(WidestPathPreparation {
            capacities: Vec::new(),
            destinations: Vec::new(),
            minimum_delivery_bps: None,
            active_edge_count: 0,
            capacity_work: 0,
        });
    }

    let mut capacity_work = 0;
    let capacities =
        widest_capacities_checked(graph, start, work_stats, &mut capacity_work, budget)?;
    budget.charge(capacities.len())?;
    capacity_work = capacity_work
        .checked_add(capacities.len())
        .ok_or(WidestPathWorkError)?;
    let mut destinations = capacities
        .iter()
        .enumerate()
        .filter_map(|(index, capacity)| {
            (*capacity > 0 && index != start.index()).then_some((*capacity, NodeIndex::new(index)))
        })
        .collect::<Vec<_>>();
    destinations.sort_unstable_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.index().cmp(&right.1.index()))
    });
    budget.charge(destinations.len())?;
    capacity_work = capacity_work
        .checked_add(destinations.len())
        .ok_or(WidestPathWorkError)?;
    #[cfg(test)]
    {
        work_stats.destination_capacity = destinations.capacity();
    }
    let minimum_delivery_bps = destinations.last().map(|destination| destination.0);
    let mut active_edge_count = 0;
    if let Some(minimum_delivery_bps) = minimum_delivery_bps {
        for edge in graph.edge_references() {
            budget.charge(1)?;
            capacity_work = capacity_work.checked_add(1).ok_or(WidestPathWorkError)?;
            if edge.weight().delivery_bps >= minimum_delivery_bps
                && capacities[edge.source().index()] >= minimum_delivery_bps
            {
                active_edge_count += 1;
            }
        }
    }
    Ok(WidestPathPreparation {
        capacities,
        destinations,
        minimum_delivery_bps,
        active_edge_count,
        capacity_work,
    })
}

fn widest_path_with_preparation(
    graph: &SpeedGraph,
    start: NodeIndex,
    preparation: &WidestPathPreparation,
    budget: &mut WidestPathWorkBudget,
    work_stats: &mut WidestPathWorkStats,
) -> Result<HashMap<NodeIndex, SpeedPath>, WidestPathWorkError> {
    if graph.node_weight(start).is_none() || preparation.capacities.len() != graph.node_count() {
        return Ok(HashMap::new());
    }
    let Some(minimum_delivery_bps) = preparation.minimum_delivery_bps else {
        return Ok(HashMap::new());
    };
    let destinations = &preparation.destinations;

    // Sort exact capacities once. Equal capacities activate as one round.
    // Disconnected sources and edges below the last required threshold cannot
    // contribute to any destination route, so skip them before sorting.
    let mut edges = Vec::with_capacity(preparation.active_edge_count);
    for edge in graph.edge_references() {
        budget.charge(1)?;
        let delivery_bps = edge.weight().delivery_bps;
        if delivery_bps >= minimum_delivery_bps
            && preparation.capacities[edge.source().index()] >= minimum_delivery_bps
        {
            edges.push((
                delivery_bps,
                edge.source(),
                edge.target(),
                edge.weight().latency_ms,
            ));
        }
    }
    edges.sort_unstable_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.index().cmp(&right.1.index()))
            .then_with(|| left.2.index().cmp(&right.2.index()))
            .then_with(|| left.3.cmp(&right.3))
    });
    #[cfg(test)]
    {
        work_stats.sorted_edge_capacity = edges.capacity();
    }

    let mut active_edges: Vec<Vec<(NodeIndex, u64)>> =
        (0..graph.node_count()).map(|_| Vec::new()).collect();
    let mut labels = vec![None; graph.node_count()];
    labels[start.index()] = Some((0, 0, graph[start]));
    #[cfg(test)]
    {
        work_stats.peak_active_outer_capacity = active_edges.capacity();
        work_stats.label_capacity = labels.capacity();
    }
    let mut label_count = LabelCount::default();
    #[cfg(test)]
    {
        label_count = 1;
    }
    let mut finalized = vec![false; graph.node_count()];
    #[cfg(test)]
    {
        work_stats.finalized_capacity = finalized.capacity();
        work_stats.peak_label_count = label_count;
    }
    let mut pending = BTreeSet::new();
    let mut routes = HashMap::new();
    let mut edge_offset = 0_usize;
    let mut destination_offset = 0_usize;

    while destination_offset < destinations.len() {
        #[cfg(test)]
        {
            work_stats.threshold_count += 1;
        }
        let delivery_bps = destinations[destination_offset].0;
        let mut destination_end = destination_offset + 1;
        while destination_end < destinations.len()
            && destinations[destination_end].0 == delivery_bps
        {
            destination_end += 1;
        }

        let activation_start = edge_offset;
        while edge_offset < edges.len() && edges[edge_offset].0 >= delivery_bps {
            let (_, source, target, latency_ms) = edges[edge_offset];
            budget.charge(1)?;
            let active_adjacency = &mut active_edges[source.index()];
            #[cfg(test)]
            let previous_capacity = active_adjacency.capacity();
            active_adjacency.push((target, latency_ms));
            #[cfg(test)]
            {
                work_stats.peak_active_inner_capacity +=
                    active_adjacency.capacity() - previous_capacity;
            }
            edge_offset += 1;
        }
        #[cfg(test)]
        {
            work_stats.activation_rounds += 1;
            work_stats.activated_edges += edge_offset - activation_start;
            work_stats.peak_active_edges = work_stats.peak_active_edges.max(edge_offset);
        }

        // Seed all newly activated edges. Later relaxations scan every active
        // edge, so paths that become reachable in this round propagate fully.
        let mut newly_reachable = 0_usize;
        for &(_, source, target, latency_ms) in &edges[activation_start..edge_offset] {
            let Some(source_label) = labels[source.index()] else {
                continue;
            };
            let candidate =
                speed_path_label(graph, start, source, target, source_label, latency_ms);
            relax_speed_path(
                &mut labels,
                &mut pending,
                target,
                candidate,
                work_stats,
                &mut newly_reachable,
                &mut label_count,
                budget,
            )?;
        }

        while let Some((latency_ms, hops, first_hop_peer_id, node_index)) = pending.pop_first() {
            budget.charge(1)?;
            let node = NodeIndex::new(node_index);
            if labels[node.index()] != Some((latency_ms, hops, first_hop_peer_id)) {
                continue;
            }
            for &(target, edge_latency_ms) in &active_edges[node.index()] {
                budget.charge(1)?;
                #[cfg(test)]
                {
                    work_stats.scanned_edges += 1;
                }
                let candidate = speed_path_label(
                    graph,
                    start,
                    node,
                    target,
                    (latency_ms, hops, first_hop_peer_id),
                    edge_latency_ms,
                );
                relax_speed_path(
                    &mut labels,
                    &mut pending,
                    target,
                    candidate,
                    work_stats,
                    &mut newly_reachable,
                    &mut label_count,
                    budget,
                )?;
            }
        }

        for &(_, node) in &destinations[destination_offset..destination_end] {
            budget.charge(1)?;
            debug_assert!(!finalized[node.index()]);
            let Some((latency_ms, hops, next_hop_peer_id)) = labels[node.index()] else {
                debug_assert!(false, "widest capacity destination must be reachable");
                continue;
            };
            finalized[node.index()] = true;
            #[cfg(test)]
            {
                work_stats.finalization_visits += 1;
            }
            routes.insert(
                node,
                SpeedPath {
                    next_hop_peer_id,
                    quality: RouteQuality {
                        delivery_bps,
                        latency_ms,
                        hops,
                    },
                },
            );
            #[cfg(test)]
            {
                work_stats.peak_route_count = work_stats.peak_route_count.max(routes.len());
                work_stats.peak_route_capacity =
                    work_stats.peak_route_capacity.max(routes.capacity());
            }
        }
        destination_offset = destination_end;
    }

    Ok(routes)
}

fn widest_capacities_checked(
    graph: &SpeedGraph,
    start: NodeIndex,
    work_stats: &mut WidestPathWorkStats,
    capacity_work: &mut usize,
    budget: &mut WidestPathWorkBudget,
) -> Result<Vec<u64>, WidestPathWorkError> {
    #[cfg(not(test))]
    let _ = work_stats;
    let mut capacities = vec![0_u64; graph.node_count()];
    #[cfg(test)]
    {
        work_stats.widest_capacity_capacity = capacities.capacity();
    }
    let mut pending = BTreeSet::new();
    capacities[start.index()] = u64::MAX;
    pending.insert((u64::MAX, start.index()));

    while let Some((capacity, node_index)) = pending.pop_last() {
        budget.charge(1)?;
        *capacity_work = capacity_work.checked_add(1).ok_or(WidestPathWorkError)?;
        let node = NodeIndex::new(node_index);
        if capacities[node.index()] != capacity {
            continue;
        }
        for edge in graph.edges(node) {
            budget.charge(1)?;
            *capacity_work = capacity_work.checked_add(1).ok_or(WidestPathWorkError)?;
            #[cfg(test)]
            {
                work_stats.capacity_edge_scans += 1;
            }
            let target = edge.target();
            let next_capacity = capacity.min(edge.weight().delivery_bps);
            budget.charge(1)?;
            *capacity_work = capacity_work.checked_add(1).ok_or(WidestPathWorkError)?;
            if next_capacity == 0 || capacities[target.index()] >= next_capacity {
                continue;
            }
            if capacities[target.index()] != 0 {
                pending.remove(&(capacities[target.index()], target.index()));
            }
            capacities[target.index()] = next_capacity;
            pending.insert((next_capacity, target.index()));
        }
    }

    Ok(capacities)
}

fn speed_path_label(
    graph: &SpeedGraph,
    start: NodeIndex,
    source: NodeIndex,
    target: NodeIndex,
    source_label: (u64, usize, PeerId),
    edge_latency_ms: u64,
) -> (u64, usize, PeerId) {
    (
        source_label.0.saturating_add(edge_latency_ms),
        source_label.1.saturating_add(1),
        if source == start {
            graph[target]
        } else {
            source_label.2
        },
    )
}

fn relax_speed_path(
    labels: &mut [Option<(u64, usize, PeerId)>],
    pending: &mut BTreeSet<(u64, usize, PeerId, usize)>,
    target: NodeIndex,
    candidate: (u64, usize, PeerId),
    work_stats: &mut WidestPathWorkStats,
    newly_reachable: &mut usize,
    label_count: &mut LabelCount,
    budget: &mut WidestPathWorkBudget,
) -> Result<(), WidestPathWorkError> {
    budget.charge(1)?;
    #[cfg(not(test))]
    let _ = (newly_reachable, label_count);
    #[cfg(not(test))]
    let _ = work_stats;
    if labels[target.index()].is_some_and(|current| current <= candidate) {
        return Ok(());
    }
    let previous = labels[target.index()];
    let was_unreachable = previous.is_none();
    if let Some((latency_ms, hops, first_hop_peer_id)) = previous {
        pending.remove(&(latency_ms, hops, first_hop_peer_id, target.index()));
    }
    labels[target.index()] = Some(candidate);
    if was_unreachable {
        #[cfg(test)]
        {
            *newly_reachable += 1;
            *label_count += 1;
        }
    }
    pending.insert((candidate.0, candidate.1, candidate.2, target.index()));
    #[cfg(test)]
    {
        work_stats.label_relaxations += 1;
        work_stats.peak_queue_len = work_stats.peak_queue_len.max(pending.len());
        work_stats.peak_queue_capacity = work_stats.peak_queue_capacity.max(pending.len());
        work_stats.peak_label_count = work_stats.peak_label_count.max(*label_count);
        work_stats.peak_newly_reachable = work_stats.peak_newly_reachable.max(*newly_reachable);
    }
    Ok(())
}

type NextHopInfo = ForwardingNextHop;
// dst_peer_id -> (next_hop_peer_id, cost, path_len)
type NextHopMap = DashMap<PeerId, NextHopInfo>;

// computed with SyncedRouteInfo. used to get next hop.
#[derive(Debug)]
struct RouteTable {
    peer_infos: DashMap<PeerId, RoutePeerInfo>,
    next_hop_map: NextHopMap,
    suppressed_peer_ids: DashMap<PeerId, ()>,
    ipv4_peer_id_map: DashMap<Ipv4Addr, PeerIdVersion>,
    ipv6_peer_id_map: DashMap<Ipv6Addr, PeerIdVersion>,
    cidr_peer_id_map: ArcSwap<PrefixMap<Ipv4Cidr, PeerIdVersion>>,
    cidr_v6_peer_id_map: ArcSwap<PrefixMap<Ipv6Cidr, PeerIdVersion>>,
    next_hop_map_version: AtomicVersion,
    shared_maps: std::sync::Mutex<Option<Arc<SharedRouteMaps>>>,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable {
            peer_infos: DashMap::new(),
            next_hop_map: DashMap::new(),
            suppressed_peer_ids: DashMap::new(),
            ipv4_peer_id_map: DashMap::new(),
            ipv6_peer_id_map: DashMap::new(),
            cidr_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            cidr_v6_peer_id_map: ArcSwap::new(Arc::new(PrefixMap::new())),
            next_hop_map_version: AtomicVersion::new(),
            shared_maps: std::sync::Mutex::new(None),
        }
    }

    fn shared_maps(&self) -> Option<Arc<SharedRouteMaps>> {
        self.shared_maps.lock().unwrap().clone()
    }

    fn clear_for_version(&self, version: Version) {
        self.peer_infos.clear();
        self.next_hop_map.clear();
        self.suppressed_peer_ids.clear();
        self.ipv4_peer_id_map.clear();
        self.ipv6_peer_id_map.clear();
        self.cidr_peer_id_map.store(Arc::new(PrefixMap::new()));
        self.cidr_v6_peer_id_map.store(Arc::new(PrefixMap::new()));
        *self.shared_maps.lock().unwrap() = None;
        self.next_hop_map_version.set_if_larger(version);
    }

    fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        if let Some(shared_maps) = self.shared_maps() {
            if shared_maps.suppressed_peer_ids.contains(&dst_peer_id) {
                return None;
            }
        } else if self.suppressed_peer_ids.contains_key(&dst_peer_id) {
            return None;
        }
        self.get_topology_next_hop(dst_peer_id)
    }

    fn get_topology_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        let cur_version = self.next_hop_map_version.get();
        self.next_hop_map.get(&dst_peer_id).and_then(|x| {
            if x.version >= cur_version {
                Some(*x)
            } else {
                None
            }
        })
    }

    fn peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    fn topology_peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_topology_next_hop(peer_id).is_some()
    }

    fn get_udp_nat_type(&self, peer_id: PeerId) -> Option<NatType> {
        if let Some(shared_maps) = self.shared_maps() {
            return shared_maps
                .peer_infos
                .get(&peer_id)
                .map(|info| NatType::try_from(info.udp_nat_type).unwrap_or_default());
        }
        self.peer_infos
            .get(&peer_id)
            .map(|x| NatType::try_from(x.udp_nat_type).unwrap_or_default())
    }

    fn gen_next_hop_map_with_least_hop(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        if graph.node_weight(*start_node).is_none() {
            tracing::warn!(
                ?start_node,
                version,
                "invalid start node for least-hop route rebuild"
            );
            return;
        }
        let normalize_edge_cost = |e: petgraph::graph::EdgeReference<usize>| {
            if *e.weight() >= AVOID_RELAY_COST {
                AVOID_RELAY_COST + 1
            } else {
                1
            }
        };
        // Calculate the permitted shortest-hop distance once.
        let path_len_map = dijkstra(&graph, *start_node, None, normalize_edge_cost);
        let (costs, next_hops) = dijkstra_with_first_hop_filtered(graph, *start_node, |edge| {
            let source_distance = path_len_map.get(&edge.source())?;
            let target_distance = path_len_map.get(&edge.target())?;
            let hop_cost = normalize_edge_cost(edge);
            (*source_distance + hop_cost == *target_distance).then_some(*edge.weight())
        });
        self.install_weighted_routes(graph, &costs, &next_hops, version);
    }

    fn gen_next_hop_map_with_least_cost(
        &self,
        graph: &PeerGraph,
        start_node: &NodeIndex,
        version: Version,
    ) {
        if graph.node_weight(*start_node).is_none() {
            tracing::warn!(
                ?start_node,
                version,
                "invalid start node for least-cost route rebuild"
            );
            return;
        }
        let (costs, next_hops) = dijkstra_with_first_hop(&graph, *start_node, |e| *e.weight());
        self.install_weighted_routes(graph, &costs, &next_hops, version);
    }

    fn install_weighted_routes(
        &self,
        graph: &PeerGraph,
        costs: &HashMap<NodeIndex, usize>,
        next_hops: &HashMap<NodeIndex, (NodeIndex, usize)>,
        version: Version,
    ) {
        for (dst, (next_hop, path_len)) in next_hops.iter() {
            let info = NextHopInfo {
                next_hop_peer_id: *graph.node_weight(*next_hop).unwrap(),
                path_delivery_bps: 0,
                path_latency: (*costs.get(dst).unwrap() % AVOID_RELAY_COST) as i32,
                path_len: { *path_len },
                version,
            };
            let dst_peer_id = *graph.node_weight(*dst).unwrap();
            self.next_hop_map
                .entry(dst_peer_id)
                .and_modify(|x| {
                    if x.version < version {
                        *x = info;
                    }
                })
                .or_insert(info);
        }

        self.next_hop_map_version.set_if_larger(version);
    }

    fn gen_next_hop_map_with_max_goodput_checked(
        &self,
        graph: &SpeedGraph,
        start_node: &NodeIndex,
        version: Version,
        preparation: &WidestPathPreparation,
        budget: &mut WidestPathWorkBudget,
    ) -> Result<(), WidestPathWorkError> {
        if graph.node_weight(*start_node).is_none() {
            tracing::warn!(
                ?start_node,
                version,
                "invalid start node for maximum-goodput route rebuild"
            );
            return Ok(());
        }
        let mut work_stats = WidestPathWorkStats::default();
        let routes =
            widest_path_with_preparation(graph, *start_node, preparation, budget, &mut work_stats)?;
        for (dst, route) in routes {
            let info = NextHopInfo {
                next_hop_peer_id: route.next_hop_peer_id,
                path_delivery_bps: route.quality.delivery_bps,
                path_latency: route.quality.latency_ms.min(i32::MAX as u64) as i32,
                path_len: route.quality.hops,
                version,
            };
            let dst_peer_id = graph[dst];
            self.next_hop_map
                .entry(dst_peer_id)
                .and_modify(|current| {
                    if current.version < version {
                        *current = info;
                    }
                })
                .or_insert(info);
        }

        self.next_hop_map_version.set_if_larger(version);
        Ok(())
    }

    fn build_next_hop_map_from_input(
        input: &RouteBuildInput,
        policy: NextHopPolicy,
    ) -> HashMap<PeerId, NextHopInfo> {
        Self::build_next_hop_map_from_input_checked(input, policy).unwrap_or_default()
    }

    fn build_next_hop_map_from_input_checked(
        input: &RouteBuildInput,
        policy: NextHopPolicy,
    ) -> Result<HashMap<PeerId, NextHopInfo>, WidestPathWorkError> {
        let workspace = Self::new();
        workspace.next_hop_map_version.set(input.version);
        if input.start_node != NodeIndex::end() {
            match policy {
                NextHopPolicy::LeastHop => {
                    if input.graph.node_count() == 0 {
                        return Ok(HashMap::new());
                    }
                    workspace.gen_next_hop_map_with_least_hop(
                        &input.graph,
                        &input.start_node,
                        input.version,
                    )
                }
                NextHopPolicy::LeastCost => {
                    if input.graph.node_count() == 0 {
                        return Ok(HashMap::new());
                    }
                    workspace.gen_next_hop_map_with_least_cost(
                        &input.graph,
                        &input.start_node,
                        input.version,
                    )
                }
                NextHopPolicy::MaxGoodput => {
                    let graph = &input.speed_graph;
                    if graph.node_count() == 0 {
                        return Ok(HashMap::new());
                    }
                    let preparation = input
                        .speed_preparation
                        .as_ref()
                        .ok_or(WidestPathWorkError)?;
                    let work_limit =
                        widest_path_work_limit(graph.node_count(), graph.edge_count())?;
                    let mut budget =
                        WidestPathWorkBudget::with_used(preparation.capacity_work, work_limit)?;
                    workspace.gen_next_hop_map_with_max_goodput_checked(
                        graph,
                        &input.start_node,
                        input.version,
                        preparation,
                        &mut budget,
                    )?;
                }
            }
        }
        Ok(workspace
            .next_hop_map
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect())
    }

    fn build_shared_maps(
        my_peer_id: PeerId,
        input: &RouteBuildInput,
        baseline_next_hops: &HashMap<PeerId, NextHopInfo>,
    ) -> Arc<SharedRouteMaps> {
        let is_reachable = |peer_id: PeerId| {
            !input.suppressed_peer_ids.contains(&peer_id)
                && baseline_next_hops
                    .get(&peer_id)
                    .is_some_and(|route| route.version >= input.version)
        };
        let mut peer_infos = HashMap::new();
        let mut ipv4_peer_id_map = HashMap::new();
        let mut ipv6_peer_id_map = HashMap::new();
        let mut cidr_peer_id_map = PrefixMap::new();
        let mut cidr_v6_peer_id_map = PrefixMap::new();
        let mut service_routes = Vec::new();

        for (peer_id, info) in input.peer_infos.iter() {
            if !is_reachable(*peer_id) {
                continue;
            }

            peer_infos.insert(*peer_id, info.clone());
            let peer_id_and_version = PeerIdVersion {
                peer_id: *peer_id,
                version: input.version,
            };
            let is_new_peer_better = |old_peer: &PeerIdVersion| -> bool {
                if peer_id_and_version.version > old_peer.version {
                    return true;
                }
                if peer_id_and_version.peer_id == old_peer.peer_id {
                    return false;
                }
                let new_path_len = baseline_next_hops
                    .get(peer_id)
                    .map(|route| route.path_len)
                    .unwrap_or(usize::MAX);
                let old_path_len = baseline_next_hops
                    .get(&old_peer.peer_id)
                    .map(|route| route.path_len)
                    .unwrap_or(usize::MAX);
                new_path_len < old_path_len
            };

            if let Some(ipv4_addr) = info.ipv4_addr {
                ipv4_peer_id_map
                    .entry(ipv4_addr.into())
                    .and_modify(|value| {
                        if is_new_peer_better(value) {
                            *value = peer_id_and_version;
                        }
                    })
                    .or_insert(peer_id_and_version);
            }

            if let Some(ipv6_addr) = info.ipv6_addr.and_then(|x| x.address) {
                ipv6_peer_id_map
                    .entry(ipv6_addr.into())
                    .and_modify(|value| {
                        if is_new_peer_better(value) {
                            *value = peer_id_and_version;
                        }
                    })
                    .or_insert(peer_id_and_version);
            }

            if let Some(ipv6_addr) = info
                .ipv6_public_addr_lease
                .as_ref()
                .and_then(|addr| addr.address)
            {
                ipv6_peer_id_map
                    .entry(ipv6_addr.into())
                    .and_modify(|value| {
                        if is_new_peer_better(value) {
                            *value = peer_id_and_version;
                        }
                    })
                    .or_insert(peer_id_and_version);
            }

            for cidr in &info.proxy_cidrs {
                let Ok(cidr) = cidr.parse::<IpCidr>() else {
                    tracing::warn!("invalid proxy cidr: {:?}, from peer: {:?}", cidr, peer_id);
                    continue;
                };

                if *peer_id != my_peer_id
                    && input
                        .local_proxy_cidrs
                        .iter()
                        .any(|local_cidr| cidr_is_subset(&cidr, local_cidr))
                {
                    tracing::debug!(
                        ?peer_id,
                        ?my_peer_id,
                        ?input.local_proxy_cidrs,
                        ?cidr,
                        "skip remote proxy cidr covered by local announced proxy cidr while building route table"
                    );
                    continue;
                }

                service_routes.push(ServiceRoute {
                    prefix: cidr,
                    gateway: *peer_id,
                    preference: 100,
                    metric: 0,
                    path_id: u64::from(*peer_id),
                    action: ServiceRouteAction::Forward,
                });

                match cidr {
                    IpCidr::V4(cidr) => {
                        cidr_peer_id_map
                            .entry(cidr)
                            .and_modify(|value| {
                                if *peer_id == my_peer_id || is_new_peer_better(value) {
                                    *value = peer_id_and_version;
                                }
                            })
                            .or_insert(peer_id_and_version);
                    }
                    IpCidr::V6(cidr) => {
                        cidr_v6_peer_id_map
                            .entry(cidr)
                            .and_modify(|value| {
                                if *peer_id == my_peer_id || is_new_peer_better(value) {
                                    *value = peer_id_and_version;
                                }
                            })
                            .or_insert(peer_id_and_version);
                    }
                }
            }
        }

        let ipv4_peer_id_map = ipv4_peer_id_map
            .into_iter()
            .map(|(address, peer_id)| (address, peer_id.peer_id))
            .collect();
        let ipv6_peer_id_map = ipv6_peer_id_map
            .into_iter()
            .map(|(address, peer_id)| (address, peer_id.peer_id))
            .collect();
        let cidr_peer_id_map = cidr_peer_id_map
            .into_iter()
            .map(|(cidr, peer_id)| (cidr, peer_id.peer_id))
            .collect();
        let cidr_v6_peer_id_map = cidr_v6_peer_id_map
            .into_iter()
            .map(|(cidr, peer_id)| (cidr, peer_id.peer_id))
            .collect();

        Arc::new(SharedRouteMaps {
            peer_infos: Arc::new(peer_infos),
            suppressed_peer_ids: input.suppressed_peer_ids.clone(),
            ipv4_peer_id_map: Arc::new(ipv4_peer_id_map),
            ipv6_peer_id_map: Arc::new(ipv6_peer_id_map),
            cidr_peer_id_map: Arc::new(cidr_peer_id_map),
            cidr_v6_peer_id_map: Arc::new(cidr_v6_peer_id_map),
            service_routes: Arc::new(ServiceRouteSnapshot::from_routes(
                u64::from(input.version),
                service_routes,
            )),
            next_hop_map_version: input.version,
        })
    }

    fn replace_policy(
        &self,
        next_hops: HashMap<PeerId, NextHopInfo>,
        shared_maps: Arc<SharedRouteMaps>,
    ) {
        self.next_hop_map.clear();
        for (peer_id, next_hop) in next_hops {
            self.next_hop_map.insert(peer_id, next_hop);
        }
        self.next_hop_map_version
            .set(shared_maps.next_hop_map_version);
        self.peer_infos.clear();
        self.suppressed_peer_ids.clear();
        self.ipv4_peer_id_map.clear();
        self.ipv6_peer_id_map.clear();
        self.cidr_peer_id_map.store(Arc::new(PrefixMap::new()));
        self.cidr_v6_peer_id_map.store(Arc::new(PrefixMap::new()));
        *self.shared_maps.lock().unwrap() = Some(shared_maps);
    }

    /// Replace one route policy while retaining the shared topology maps.
    ///
    /// Cost and delivery changes do not change peer reachability or proxy maps.
    /// Reusing the shared maps avoids rebuilding and copying unrelated state.
    fn replace_next_hops(&self, next_hops: HashMap<PeerId, NextHopInfo>, version: Version) {
        self.next_hop_map.clear();
        for (peer_id, next_hop) in next_hops {
            self.next_hop_map.insert(peer_id, next_hop);
        }
        self.next_hop_map_version.set(version);
    }

    fn get_peer_id_for_proxy(&self, ip: &IpAddr) -> Option<PeerId> {
        if let Some(shared_maps) = self.shared_maps() {
            return match ip {
                IpAddr::V4(ipv4) => shared_maps
                    .cidr_peer_id_map
                    .get_lpm(&Ipv4Cidr::new(*ipv4, 32).ok()?)
                    .map(|x| *x.1),
                IpAddr::V6(ipv6) => shared_maps
                    .cidr_v6_peer_id_map
                    .get_lpm(&Ipv6Cidr::new(*ipv6, 128).ok()?)
                    .map(|x| *x.1),
            };
        }
        match ip {
            IpAddr::V4(ipv4) => self
                .cidr_peer_id_map
                .load()
                .get_lpm(&Ipv4Cidr::new(*ipv4, 32).unwrap())
                .map(|x| x.1.peer_id),
            IpAddr::V6(ipv6) => self
                .cidr_v6_peer_id_map
                .load()
                .get_lpm(&Ipv6Cidr::new(*ipv6, 128).unwrap())
                .map(|x| x.1.peer_id),
        }
    }

    fn into_snapshot(&self) -> RouteTableSnapshot {
        let shared_maps = self.shared_maps();
        RouteTableSnapshot {
            peer_infos: shared_maps
                .as_ref()
                .map(|maps| maps.peer_infos.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.peer_infos
                            .iter()
                            .map(|entry| (*entry.key(), entry.value().clone()))
                            .collect(),
                    )
                }),
            next_hop_map: Arc::new(
                self.next_hop_map
                    .iter()
                    .map(|entry| (*entry.key(), *entry.value()))
                    .collect(),
            ),
            suppressed_peer_ids: shared_maps
                .as_ref()
                .map(|maps| maps.suppressed_peer_ids.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.suppressed_peer_ids
                            .iter()
                            .map(|entry| *entry.key())
                            .collect(),
                    )
                }),
            ipv4_peer_id_map: shared_maps
                .as_ref()
                .map(|maps| maps.ipv4_peer_id_map.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.ipv4_peer_id_map
                            .iter()
                            .map(|entry| (*entry.key(), entry.value().peer_id))
                            .collect(),
                    )
                }),
            ipv6_peer_id_map: shared_maps
                .as_ref()
                .map(|maps| maps.ipv6_peer_id_map.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.ipv6_peer_id_map
                            .iter()
                            .map(|entry| (*entry.key(), entry.value().peer_id))
                            .collect(),
                    )
                }),
            cidr_peer_id_map: shared_maps
                .as_ref()
                .map(|maps| maps.cidr_peer_id_map.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.cidr_peer_id_map
                            .load()
                            .iter()
                            .map(|(cidr, peer_id)| (*cidr, peer_id.peer_id))
                            .collect(),
                    )
                }),
            cidr_v6_peer_id_map: shared_maps
                .as_ref()
                .map(|maps| maps.cidr_v6_peer_id_map.clone())
                .unwrap_or_else(|| {
                    Arc::new(
                        self.cidr_v6_peer_id_map
                            .load()
                            .iter()
                            .map(|(cidr, peer_id)| (*cidr, peer_id.peer_id))
                            .collect(),
                    )
                }),
            service_routes: shared_maps
                .as_ref()
                .map(|maps| maps.service_routes.clone())
                .unwrap_or_else(|| Arc::new(ServiceRouteSnapshot::default())),
            next_hop_map_version: self.next_hop_map_version.get(),
        }
    }
}

/// Immutable route data used by one forwarding decision.
#[derive(Debug, Clone)]
struct RouteTableSnapshot {
    peer_infos: Arc<HashMap<PeerId, RoutePeerInfo>>,
    next_hop_map: Arc<HashMap<PeerId, NextHopInfo>>,
    suppressed_peer_ids: Arc<HashSet<PeerId>>,
    ipv4_peer_id_map: Arc<HashMap<Ipv4Addr, PeerId>>,
    ipv6_peer_id_map: Arc<HashMap<Ipv6Addr, PeerId>>,
    cidr_peer_id_map: Arc<PrefixMap<Ipv4Cidr, PeerId>>,
    cidr_v6_peer_id_map: Arc<PrefixMap<Ipv6Cidr, PeerId>>,
    service_routes: Arc<ServiceRouteSnapshot>,
    next_hop_map_version: Version,
}

impl RouteTableSnapshot {
    fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        if self.suppressed_peer_ids.contains(&dst_peer_id) {
            return None;
        }
        self.get_topology_next_hop(dst_peer_id)
    }

    fn get_topology_next_hop(&self, dst_peer_id: PeerId) -> Option<NextHopInfo> {
        self.next_hop_map
            .get(&dst_peer_id)
            .copied()
            .filter(|route| route.version >= self.next_hop_map_version)
    }

    fn peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    fn topology_peer_reachable(&self, peer_id: PeerId) -> bool {
        self.get_topology_next_hop(peer_id).is_some()
    }

    fn get_udp_nat_type(&self, peer_id: PeerId) -> Option<NatType> {
        self.peer_infos
            .get(&peer_id)
            .map(|info| NatType::try_from(info.udp_nat_type).unwrap_or_default())
    }

    fn get_peer_id_for_proxy(&self, ip: &IpAddr) -> Option<PeerId> {
        match ip {
            IpAddr::V4(ipv4) => self
                .cidr_peer_id_map
                .get_lpm(&Ipv4Cidr::new(*ipv4, 32).ok()?)
                .map(|entry| *entry.1),
            IpAddr::V6(ipv6) => self
                .cidr_v6_peer_id_map
                .get_lpm(&Ipv6Cidr::new(*ipv6, 128).ok()?)
                .map(|entry| *entry.1),
        }
    }
}

type SessionId = u64;

type AtomicSessionId = atomic_shim::AtomicU64;

struct SessionTask {
    my_peer_id: PeerId,
    task: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
}

impl SessionTask {
    fn new(my_peer_id: PeerId) -> Self {
        SessionTask {
            my_peer_id,
            task: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn set_task(&self, task: JoinHandle<()>) {
        if let Some(old) = self.task.lock().unwrap().replace(task) {
            old.abort();
        }
    }

    fn is_running(&self) -> bool {
        if let Some(task) = self.task.lock().unwrap().as_ref() {
            !task.is_finished()
        } else {
            false
        }
    }
}

impl Drop for SessionTask {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        tracing::debug!(my_peer_id = self.my_peer_id, "drop SessionTask");
    }
}

impl Debug for SessionTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTask")
            .field("is_running", &self.is_running())
            .finish()
    }
}

#[derive(Debug)]
struct VersionAndTouchTime {
    version: AtomicVersion,
    touch_time: AtomicCell<Instant>,
}

impl Default for VersionAndTouchTime {
    fn default() -> Self {
        VersionAndTouchTime {
            version: AtomicVersion::new(),
            touch_time: AtomicCell::new(Instant::now()),
        }
    }
}

impl VersionAndTouchTime {
    fn touch(&self) {
        self.touch_time.store(Instant::now());
    }

    fn get(&self) -> Version {
        self.version.get()
    }

    fn set_if_larger(&self, version: Version) {
        self.version.set_if_larger(version);
    }

    fn is_expired(&self) -> bool {
        self.touch_time.load().elapsed() > Duration::from_secs(60)
    }
}

// if we need to sync route info with one peer, we create a SyncRouteSession with that peer.
#[derive(Debug)]
struct SyncRouteSession {
    my_peer_id: PeerId,
    dst_peer_id: PeerId,
    dst_saved_peer_info_versions: DashMap<PeerId, VersionAndTouchTime>,
    dst_saved_conn_info_version: DashMap<PeerId, VersionAndTouchTime>,
    dst_saved_foreign_network_versions: DashMap<ForeignNetworkRouteInfoKey, VersionAndTouchTime>,

    // we don't want to send unreachable peer infos / conn infos to peer, so we keep track of them.
    unreachable_peers_for_peer_info: parking_lot::Mutex<BTreeMap<PeerId, Version>>,
    unreachable_peers_for_conn_info: parking_lot::Mutex<BTreeMap<PeerId, Version>>,

    last_sync_succ_timestamp: AtomicCell<Option<SystemTime>>,

    my_session_id: AtomicSessionId,
    dst_session_id: AtomicSessionId,

    // every node should have exactly one initator session to one other non-initiator peer.
    we_are_initiator: AtomicBool,
    dst_is_initiator: AtomicBool,

    need_sync_initiator_info: AtomicBool,

    rpc_tx_count: AtomicU32,
    rpc_rx_count: AtomicU32,

    task: SessionTask,

    lock: parking_lot::Mutex<()>,
}

impl SyncRouteSession {
    fn new(my_peer_id: PeerId, dst_peer_id: PeerId) -> Self {
        SyncRouteSession {
            my_peer_id,
            dst_peer_id,
            dst_saved_peer_info_versions: DashMap::new(),
            dst_saved_conn_info_version: DashMap::new(),
            dst_saved_foreign_network_versions: DashMap::new(),

            unreachable_peers_for_peer_info: parking_lot::Mutex::new(BTreeMap::new()),
            unreachable_peers_for_conn_info: parking_lot::Mutex::new(BTreeMap::new()),

            last_sync_succ_timestamp: AtomicCell::new(None),

            my_session_id: AtomicSessionId::new(rand::random()),
            dst_session_id: AtomicSessionId::new(0),

            we_are_initiator: AtomicBool::new(false),
            dst_is_initiator: AtomicBool::new(false),

            need_sync_initiator_info: AtomicBool::new(false),

            rpc_tx_count: AtomicU32::new(0),
            rpc_rx_count: AtomicU32::new(0),

            task: SessionTask::new(my_peer_id),

            lock: parking_lot::Mutex::new(()),
        }
    }

    fn check_saved_peer_info_update_to_date(&self, peer_id: PeerId, version: Version) -> bool {
        if version == 0 || peer_id == self.dst_peer_id {
            // never send version 0 peer info to dst peer.
            return true;
        }
        self.dst_saved_peer_info_versions
            .get(&peer_id)
            .map(|v| {
                v.touch();
                v.get() >= version
            })
            .unwrap_or(false)
    }

    fn check_saved_conn_version_update_to_date(&self, peer_id: PeerId, version: Version) -> bool {
        if version == 0 || peer_id == self.dst_peer_id {
            // never send version 0 conn bitmap to dst peer.
            return true;
        }
        self.dst_saved_conn_info_version
            .get(&peer_id)
            .map(|v| {
                v.touch();
                v.get() >= version
            })
            .unwrap_or(false)
    }

    fn check_saved_foreign_network_version_update_to_date(
        &self,
        foreign_network_key: &ForeignNetworkRouteInfoKey,
        version: Version,
    ) -> bool {
        if version == 0 || foreign_network_key.peer_id == self.dst_peer_id {
            // never send version 0 foreign network to dst peer.
            return true;
        }

        self.dst_saved_foreign_network_versions
            .get(foreign_network_key)
            .map(|x| {
                x.touch();
                x.get() >= version
            })
            .unwrap_or(false)
    }

    fn update_dst_saved_peer_info_version(&self, infos: &[RoutePeerInfo], dst_peer_id: PeerId) {
        for info in infos.iter() {
            if info.peer_id == dst_peer_id {
                // we never send dst peer info to dst peer, so no need to store it.
                continue;
            }

            self.dst_saved_peer_info_versions
                .entry(info.peer_id)
                .or_default()
                .set_if_larger(info.version);
        }
    }

    fn update_dst_saved_conn_bitmap_version(
        &self,
        conn_bitmap: &RouteConnBitmap,
        dst_peer_id: PeerId,
    ) {
        for peer_id_version in conn_bitmap.peer_ids.iter() {
            if peer_id_version.peer_id == dst_peer_id {
                continue;
            }

            self.dst_saved_conn_info_version
                .entry(peer_id_version.peer_id)
                .or_default()
                .set_if_larger(peer_id_version.version);
        }
    }

    fn update_dst_saved_conn_peer_list_version(
        &self,
        conn_peer_list: &RouteConnPeerList,
        dst_peer_id: PeerId,
    ) {
        for peer_conn_info in &conn_peer_list.peer_conn_infos {
            let Some(peer_id_version) = peer_conn_info.peer_id else {
                continue;
            };
            if peer_id_version.peer_id == dst_peer_id {
                continue;
            }

            self.dst_saved_conn_info_version
                .entry(peer_id_version.peer_id)
                .or_default()
                .set_if_larger(peer_id_version.version);
        }
    }

    fn update_dst_saved_conn_info_version(&self, conn_info: &ConnInfo, dst_peer_id: PeerId) {
        match conn_info {
            ConnInfo::ConnBitmap(conn_bitmap) => {
                self.update_dst_saved_conn_bitmap_version(conn_bitmap, dst_peer_id);
            }
            ConnInfo::ConnPeerList(peer_list) => {
                self.update_dst_saved_conn_peer_list_version(peer_list, dst_peer_id);
            }
        }
    }

    fn update_dst_saved_foreign_network_version(
        &self,
        foreign_network: &RouteForeignNetworkInfos,
        dst_peer_id: PeerId,
    ) {
        for item in foreign_network.infos.iter() {
            let (Some(key), Some(value)) = (item.key.as_ref(), item.value.as_ref()) else {
                continue;
            };
            if key.peer_id == dst_peer_id {
                continue;
            }
            self.dst_saved_foreign_network_versions
                .entry(key.clone())
                .or_default()
                .set_if_larger(value.version);
        }
    }

    fn update_initiator_flag(&self, is_initiator: bool) {
        self.we_are_initiator.store(is_initiator, Ordering::Relaxed);
        self.need_sync_initiator_info.store(true, Ordering::Relaxed);
    }

    // return whether session id is updated
    fn update_dst_session_id(&self, session_id: SessionId) {
        if session_id != self.dst_session_id.load(Ordering::Relaxed) {
            tracing::warn!(?self, ?session_id, "session id mismatch, clear saved info.");
            self.dst_session_id.store(session_id, Ordering::Relaxed);
            self.dst_saved_conn_info_version.clear();
            self.dst_saved_peer_info_versions.clear();
            self.dst_saved_foreign_network_versions.clear();

            // update_dst_session_id is always called with session lock held, so clear
            // last_sync_succ_timestamp and unreachable_peers non-atomic is safe.
            self.last_sync_succ_timestamp.store(None);
            self.unreachable_peers_for_peer_info.lock().clear();
            self.unreachable_peers_for_conn_info.lock().clear();
        }
    }

    fn clean_dst_saved_map(&self) {
        self.dst_saved_peer_info_versions
            .retain(|_, v| !v.is_expired());
        self.dst_saved_peer_info_versions.shrink_to_fit();

        self.dst_saved_conn_info_version
            .retain(|_, v| !v.is_expired());
        self.dst_saved_conn_info_version.shrink_to_fit();

        self.dst_saved_foreign_network_versions
            .retain(|_, v| !v.is_expired());
        self.dst_saved_foreign_network_versions.shrink_to_fit();
    }

    fn update_last_sync_succ_timestamp(&self, next_last_sync_succ_timestamp: SystemTime) {
        let _ = self.last_sync_succ_timestamp.fetch_update(|x| {
            if x.is_none_or(|old| old < next_last_sync_succ_timestamp) {
                Some(Some(next_last_sync_succ_timestamp))
            } else {
                None
            }
        });
    }

    fn short_debug_string(&self) -> String {
        format!(
            "session_dst_peer: {:?}, my_session_id: {:?}, dst_session_id: {:?}, we_are_initiator: {:?}, dst_is_initiator: {:?}, rpc_tx_count: {:?}, rpc_rx_count: {:?}, task: {:?}",
            self.dst_peer_id,
            self.my_session_id,
            self.dst_session_id,
            self.we_are_initiator,
            self.dst_is_initiator,
            self.rpc_tx_count,
            self.rpc_rx_count,
            self.task
        )
    }
}

impl Drop for SyncRouteSession {
    fn drop(&mut self) {
        tracing::debug!(?self, "drop SyncRouteSession");
    }
}

/// Immutable forwarding state published as one unit.
#[derive(Debug, Clone)]
struct ForwardingSnapshot {
    generation: u64,
    route_table: Arc<RouteTableSnapshot>,
    route_table_with_cost: Arc<RouteTableSnapshot>,
    route_table_with_speed: Arc<RouteTableSnapshot>,
    forwarding_peers: Arc<super::route_trait::ForwardingPeerTable>,
    foreign_network_owner_map: Arc<HashMap<NetworkIdentity, Vec<PeerId>>>,
    foreign_network_my_peer_id_map: Arc<HashMap<(String, PeerId), PeerId>>,
    decision_snapshot: ForwardingDecisionSnapshotHandle,
}

/// Selects the state that a route rebuild must recompute.
///
/// The domains share one immutable publication. Unchanged components remain
/// behind their existing `Arc` values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RouteRebuildDomains {
    topology: bool,
    cost: bool,
    delivery: bool,
    bridge: bool,
    foreign: bool,
}

impl RouteRebuildDomains {
    fn topology() -> Self {
        Self {
            topology: true,
            cost: true,
            delivery: true,
            bridge: true,
            foreign: true,
        }
    }

    fn cost_and_delivery() -> Self {
        Self {
            cost: true,
            delivery: true,
            ..Self::default()
        }
    }

    fn cost() -> Self {
        Self {
            cost: true,
            ..Self::default()
        }
    }

    fn delivery() -> Self {
        Self {
            delivery: true,
            ..Self::default()
        }
    }

    fn bridge() -> Self {
        Self {
            bridge: true,
            ..Self::default()
        }
    }

    fn foreign() -> Self {
        Self {
            foreign: true,
            ..Self::default()
        }
    }

    fn needs_route_input(self) -> bool {
        self.topology || self.cost || self.delivery
    }

    fn needs_publication(self) -> bool {
        self.topology || self.cost || self.delivery || self.bridge || self.foreign
    }

    fn bits(self) -> u8 {
        u8::from(self.topology)
            | u8::from(self.cost) << 1
            | u8::from(self.delivery) << 2
            | u8::from(self.bridge) << 3
            | u8::from(self.foreign) << 4
    }

    fn from_bits(bits: u8) -> Self {
        Self {
            topology: bits & 1 != 0,
            cost: bits & (1 << 1) != 0,
            delivery: bits & (1 << 2) != 0,
            bridge: bits & (1 << 3) != 0,
            foreign: bits & (1 << 4) != 0,
        }
    }
}

#[derive(Debug, Default)]
struct RouteRebuildWorkCounters {
    topology_rebuilds: AtomicU64,
    least_hop_rebuilds: AtomicU64,
    least_cost_rebuilds: AtomicU64,
    max_goodput_rebuilds: AtomicU64,
    owner_map_rebuilds: AtomicU64,
    bridge_refreshes: AtomicU64,
    snapshot_publications: AtomicU64,
}

struct PeerRouteServiceImpl {
    my_peer_id: PeerId,
    my_peer_route_id: u64,
    global_ctx: ArcGlobalCtx,
    sessions: DashMap<PeerId, Arc<SyncRouteSession>>,

    // Keep one shared interface handle. Clone the handle before every await.
    interface: Mutex<Option<Arc<dyn RouteInterface + Send + Sync>>>,
    publish_interface: std::sync::RwLock<Option<Arc<dyn RouteInterface + Send + Sync>>>,

    cost_calculator: std::sync::RwLock<Option<RouteCostCalculator>>,
    route_table: RouteTable,
    route_table_with_cost: RouteTable,
    route_table_with_speed: RouteTable,
    committed_topology: std::sync::Mutex<Option<Arc<TopologyBuildInput>>>,
    forwarding_snapshot: ArcSwap<ForwardingSnapshot>,
    forwarding_snapshot_source: std::sync::RwLock<Option<ForwardingDecisionSnapshotSource>>,
    next_forwarding_generation: AtomicU64,
    route_rebuild_lock: std::sync::Mutex<()>,
    pending_route_rebuilds: AtomicU8,
    route_rebuild_notify: Notify,
    authenticated_peers: DashMap<PeerId, AuthenticatedPeerInfo>,
    verified_bridge_attestations: DashMap<PeerId, VerifiedBridgeAttestation>,
    bridge_attestation_next_deadline: std::sync::Mutex<Option<Instant>>,
    foreign_network_owner_map: DashMap<NetworkIdentity, Vec<PeerId>>,
    foreign_network_my_peer_id_map: DashMap<(String, PeerId), PeerId>,
    synced_route_info: SyncedRouteInfo,
    public_ipv6_service: std::sync::Mutex<Weak<PublicIpv6Service>>,
    self_public_ipv6_addr_lease: std::sync::Mutex<Option<Ipv6Inet>>,
    cached_interface_peer_snapshot: std::sync::Mutex<Arc<InterfacePeerSnapshot>>,
    interface_peers_generation: AtomicU64,
    applied_interface_peers_generation: AtomicU64,
    route_rebuild_failures: AtomicU8,

    rebuild_work: RouteRebuildWorkCounters,

    last_update_my_foreign_network: AtomicCell<Option<Instant>>,

    peer_info_last_update: AtomicCell<Instant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedPeerInfo {
    peer_id: PeerId,
    identity_type: PeerIdentityType,
    public_key: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticatedPeerSeedResult {
    Unchanged,
    Inserted,
    Conflict,
}

#[derive(Debug, Default)]
struct AuthenticatedPeerSnapshotUpdate {
    changed: bool,
    conflicts: BTreeSet<PeerId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedBridgeAttestation {
    noise_static_pubkey: Vec<u8>,
    bridge_input: bool,
    hmac: Vec<u8>,
    issued_unix_ms: u64,
    expiry_unix_ms: u64,
    network_secret_digest: Option<[u8; 32]>,
    deadline: Instant,
}

impl Debug for PeerRouteServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRouteServiceImpl")
            .field("my_peer_id", &self.my_peer_id)
            .field("my_peer_route_id", &self.my_peer_route_id)
            .field("network", &self.global_ctx.get_network_identity())
            .field("sessions", &self.sessions)
            .field("route_table", &self.route_table)
            .field("route_table_with_cost", &self.route_table_with_cost)
            .field("route_table_with_speed", &self.route_table_with_speed)
            .field("synced_route_info", &self.synced_route_info)
            .field("foreign_network_owner_map", &self.foreign_network_owner_map)
            .field(
                "foreign_network_my_peer_id_map",
                &self.foreign_network_my_peer_id_map,
            )
            .finish()
    }
}

impl PeerRouteServiceImpl {
    fn allocate_forwarding_generation(
        &self,
    ) -> Result<u64, super::route_trait::RouteOriginAuthPublishError> {
        let previous = self
            .next_forwarding_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                super::route_trait::RouteOriginAuthPublishError::AuthGenerationExhausted
            })?;
        previous
            .checked_add(1)
            .ok_or(super::route_trait::RouteOriginAuthPublishError::AuthGenerationExhausted)
    }

    fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx) -> Self {
        let credential_manager = global_ctx.get_credential_manager().clone();
        let credential_network_name = global_ctx.get_network_name();
        let credential_root_public_key = credential_manager.root_public_key().to_vec();
        let credential_root_fingerprint = credential_manager.root_fingerprint().to_vec();
        let process_memory = global_ctx.process_memory_governor();
        PeerRouteServiceImpl {
            my_peer_id,
            my_peer_route_id: rand::random(),
            global_ctx,
            sessions: DashMap::new(),

            interface: Mutex::new(None),
            publish_interface: std::sync::RwLock::new(None),

            cost_calculator: std::sync::RwLock::new(Some(Box::new(DefaultRouteCostCalculator))),

            route_table: RouteTable::new(),
            route_table_with_cost: RouteTable::new(),
            route_table_with_speed: RouteTable::new(),
            committed_topology: std::sync::Mutex::new(None),
            forwarding_snapshot: ArcSwap::new(Arc::new(ForwardingSnapshot {
                generation: 0,
                route_table: Arc::new(RouteTable::new().into_snapshot()),
                route_table_with_cost: Arc::new(RouteTable::new().into_snapshot()),
                route_table_with_speed: Arc::new(RouteTable::new().into_snapshot()),
                forwarding_peers: Arc::new(super::route_trait::ForwardingPeerTable::default()),
                foreign_network_owner_map: Arc::new(HashMap::new()),
                foreign_network_my_peer_id_map: Arc::new(HashMap::new()),
                decision_snapshot: ForwardingDecisionSnapshot::from_parts(
                    0,
                    Arc::new(super::route_trait::ForwardingPeerTable::default()),
                    Arc::new(HashSet::new()),
                    None,
                    Arc::new(HashMap::new()),
                    Arc::new(HashMap::new()),
                    Arc::new(HashMap::new()),
                    Arc::new(HashMap::new()),
                    Arc::new(HashMap::new()),
                    Arc::new(PrefixMap::new()),
                    Arc::new(PrefixMap::new()),
                ),
            })),
            forwarding_snapshot_source: std::sync::RwLock::new(None),
            next_forwarding_generation: AtomicU64::new(0),
            route_rebuild_lock: std::sync::Mutex::new(()),
            pending_route_rebuilds: AtomicU8::new(0),
            route_rebuild_notify: Notify::new(),
            authenticated_peers: DashMap::new(),
            verified_bridge_attestations: DashMap::new(),
            bridge_attestation_next_deadline: std::sync::Mutex::new(None),
            foreign_network_owner_map: DashMap::new(),
            foreign_network_my_peer_id_map: DashMap::new(),

            synced_route_info: SyncedRouteInfo {
                network_name: credential_network_name,
                credential_manager,
                credential_root_public_key,
                credential_root_fingerprint,
                topology_state_lock: std::sync::Mutex::new(()),
                process_memory,
                retained_peer_bytes: std::sync::Mutex::new(HashMap::new()),
                retained_peer_bytes_total: AtomicUsize::new(0),
                peer_infos: RwLock::new(OrderedHashMap::new()),
                raw_peer_infos: DashMap::new(),
                conn_map: RwLock::new(OrderedHashMap::new()),
                foreign_network: DashMap::new(),
                group_trust_map: DashMap::new(),
                group_trust_map_cache: DashMap::new(),
                trusted_credential_pubkeys: DashMap::new(),
                non_reusable_credential_owners: DashMap::new(),
                suppressed_non_reusable_credential_peers: DashMap::new(),
                locally_authenticated_peers: DashMap::new(),
                version: AtomicVersion::new(),
            },
            public_ipv6_service: std::sync::Mutex::new(Weak::new()),
            self_public_ipv6_addr_lease: std::sync::Mutex::new(None),
            cached_interface_peer_snapshot: std::sync::Mutex::new(Arc::new(
                InterfacePeerSnapshot::default(),
            )),
            interface_peers_generation: AtomicU64::new(1),
            applied_interface_peers_generation: AtomicU64::new(0),
            route_rebuild_failures: AtomicU8::new(0),

            rebuild_work: RouteRebuildWorkCounters::default(),

            last_update_my_foreign_network: AtomicCell::new(None),

            peer_info_last_update: AtomicCell::new(Instant::now()),
        }
    }

    fn get_my_secret_digest(&self) -> Option<Vec<u8>> {
        let ni = self.global_ctx.get_network_identity();
        ni.network_secret_digest.map(|d| d.to_vec())
    }

    fn forwarding_snapshot(&self) -> Arc<ForwardingSnapshot> {
        self.forwarding_snapshot.load_full()
    }

    fn get_next_hop_with_policy_from_snapshot(
        snapshot: &ForwardingSnapshot,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<NextHopInfo> {
        match policy {
            NextHopPolicy::MaxGoodput => snapshot
                .route_table_with_speed
                .get_next_hop(dst_peer_id)
                .or_else(|| snapshot.route_table_with_cost.get_next_hop(dst_peer_id))
                .or_else(|| snapshot.route_table.get_next_hop(dst_peer_id)),
            NextHopPolicy::LeastCost => snapshot
                .route_table_with_cost
                .get_next_hop(dst_peer_id)
                .or_else(|| snapshot.route_table.get_next_hop(dst_peer_id)),
            NextHopPolicy::LeastHop => snapshot.route_table.get_next_hop(dst_peer_id),
        }
    }

    fn get_next_hop_with_policy(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<NextHopInfo> {
        let snapshot = self.forwarding_snapshot();
        Self::get_next_hop_with_policy_from_snapshot(&snapshot, dst_peer_id, policy)
    }

    #[cfg(test)]
    fn is_active_non_reusable_credential_peer(&self, peer_id: PeerId) -> bool {
        peer_id == self.my_peer_id
            || self
                .route_table
                .next_hop_map
                .get(&peer_id)
                .is_some_and(|route| route.version >= self.route_table.next_hop_map_version.get())
    }

    fn is_credential_node(&self) -> bool {
        self.global_ctx
            .get_network_identity()
            .network_secret
            .is_none()
            && self
                .global_ctx
                .config
                .get_secure_mode()
                .map(|c| c.enabled)
                .unwrap_or(false)
    }

    fn set_public_ipv6_service(&self, service: Weak<PublicIpv6Service>) {
        *self.public_ipv6_service.lock().unwrap() = service;
    }

    fn public_ipv6_service(&self) -> Option<Arc<PublicIpv6Service>> {
        self.public_ipv6_service.lock().unwrap().upgrade()
    }

    fn notify_public_ipv6_route_change(&self) -> bool {
        self.public_ipv6_service()
            .map(|service| service.handle_route_change())
            .unwrap_or(false)
    }

    fn get_or_create_session(&self, dst_peer_id: PeerId) -> Arc<SyncRouteSession> {
        self.sessions
            .entry(dst_peer_id)
            .or_insert_with(|| Arc::new(SyncRouteSession::new(self.my_peer_id, dst_peer_id)))
            .value()
            .clone()
    }

    fn get_session(&self, dst_peer_id: PeerId) -> Option<Arc<SyncRouteSession>> {
        self.sessions.get(&dst_peer_id).map(|x| x.value().clone())
    }

    fn remove_session(&self, dst_peer_id: PeerId) {
        self.sessions.remove(&dst_peer_id);
        shrink_dashmap(&self.sessions, None);
    }

    fn authenticated_peer_info(
        peer_id: PeerId,
        identity_type: PeerIdentityType,
        public_key: Vec<u8>,
        secure_auth_level: SecureAuthLevel,
    ) -> Option<AuthenticatedPeerInfo> {
        (public_key.len() == 32
            && AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
                identity_type,
                secure_auth_level,
            ))
        .then_some(AuthenticatedPeerInfo {
            peer_id,
            identity_type,
            public_key,
            secure_auth_level,
        })
    }

    fn secure_auth_level_rank(level: SecureAuthLevel) -> u8 {
        match level {
            SecureAuthLevel::None => 0,
            SecureAuthLevel::EncryptedUnauthenticated => 1,
            SecureAuthLevel::PeerVerified => 2,
            SecureAuthLevel::NetworkSecretConfirmed => 3,
        }
    }

    /// Apply one interface evidence snapshot as one topology mutation.
    fn apply_authenticated_interface_snapshot(
        &self,
        snapshot: &InterfacePeerSnapshot,
    ) -> AuthenticatedPeerSnapshotUpdate {
        let mut candidates = Vec::with_capacity(snapshot.peers.len());
        let mut invalid_peers = BTreeSet::new();
        for peer_id in snapshot.peers.iter().copied() {
            let Some(evidence) = snapshot.authenticated.get(&peer_id) else {
                invalid_peers.insert(peer_id);
                self.mark_interface_peers_dirty();
                tracing::warn!(peer_id, "route session skipped missing peer evidence");
                continue;
            };
            let Some(identity_type) = evidence.identity_type else {
                invalid_peers.insert(peer_id);
                self.mark_interface_peers_dirty();
                tracing::warn!(
                    peer_id,
                    "route session skipped an unknown peer identity type"
                );
                continue;
            };
            let Some(public_key) = evidence.public_key.clone() else {
                invalid_peers.insert(peer_id);
                self.mark_interface_peers_dirty();
                tracing::warn!(peer_id, "route session skipped a peer without a public key");
                continue;
            };
            let secure_auth_level = evidence
                .secure_auth_level
                .unwrap_or(SecureAuthLevel::EncryptedUnauthenticated);
            if let Some(authenticated) =
                Self::authenticated_peer_info(peer_id, identity_type, public_key, secure_auth_level)
            {
                candidates.push(authenticated);
            } else {
                invalid_peers.insert(peer_id);
                self.mark_interface_peers_dirty();
                tracing::warn!(peer_id, "route session skipped invalid peer evidence");
            }
        }

        let mut update =
            self.apply_authenticated_peer_candidates(&candidates, Some(&snapshot.peers));
        update.conflicts.extend(invalid_peers);
        update
    }

    /// Apply authentication candidates without holding topology locks during no-op checks.
    fn apply_authenticated_peer_candidates(
        &self,
        candidates: &[AuthenticatedPeerInfo],
        connected_peers: Option<&BTreeSet<PeerId>>,
    ) -> AuthenticatedPeerSnapshotUpdate {
        let mut update = AuthenticatedPeerSnapshotUpdate::default();
        let mut desired_by_peer = BTreeMap::<PeerId, Option<AuthenticatedPeerInfo>>::new();

        // Compare the complete authentication tuple before taking the topology lock.
        for candidate in candidates {
            if connected_peers.is_some_and(|connected| !connected.contains(&candidate.peer_id)) {
                desired_by_peer.insert(candidate.peer_id, None);
                update.conflicts.insert(candidate.peer_id);
                continue;
            }
            if !candidate.public_key.as_slice().len().eq(&32)
                || !AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
                    candidate.identity_type,
                    candidate.secure_auth_level,
                )
            {
                desired_by_peer.insert(candidate.peer_id, None);
                update.conflicts.insert(candidate.peer_id);
                continue;
            }
            match desired_by_peer.entry(candidate.peer_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Some(candidate.clone()));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let differs = entry
                        .get()
                        .as_ref()
                        .is_none_or(|existing| existing != candidate);
                    if differs {
                        entry.insert(None);
                        update.conflicts.insert(candidate.peer_id);
                    }
                }
            }
        }

        let desired = desired_by_peer
            .values()
            .filter_map(Clone::clone)
            .collect::<Vec<_>>();

        let changed_candidates = desired
            .iter()
            .filter(|candidate| {
                self.authenticated_peers
                    .get(&candidate.peer_id)
                    .is_none_or(|existing| {
                        if Self::secure_auth_level_rank(existing.secure_auth_level)
                            > Self::secure_auth_level_rank(candidate.secure_auth_level)
                        {
                            update.conflicts.insert(candidate.peer_id);
                            false
                        } else {
                            *existing != **candidate
                        }
                    })
            })
            .cloned()
            .collect::<Vec<_>>();

        let desired_peer_ids = desired
            .iter()
            .filter(|candidate| !update.conflicts.contains(&candidate.peer_id))
            .map(|candidate| candidate.peer_id)
            .collect::<BTreeSet<_>>();
        let peers_to_revoke = connected_peers.map(|connected| {
            self.authenticated_peers
                .iter()
                .filter_map(|entry| {
                    (!connected.contains(entry.key()) || !desired_peer_ids.contains(entry.key()))
                        .then_some(*entry.key())
                })
                .collect::<Vec<_>>()
        });
        let has_revoke = peers_to_revoke
            .as_ref()
            .is_some_and(|peers| !peers.is_empty());

        let conn_may_change = connected_peers.is_some_and(|connected| {
            self.synced_route_info
                .conn_map
                .read()
                .get(&self.my_peer_id)
                .is_none_or(|old| old.connected_peers != *connected)
        });
        if changed_candidates.is_empty() && !has_revoke && !conn_may_change {
            return update;
        }

        let _topology_guard = self.synced_route_info.topology_state_lock();
        let mut auth_changed = false;
        if let Some(peers_to_revoke) = peers_to_revoke {
            for peer_id in peers_to_revoke {
                if self.authenticated_peers.remove(&peer_id).is_some() {
                    auth_changed = true;
                }
                self.synced_route_info
                    .locally_authenticated_peers
                    .remove(&peer_id);
            }
            shrink_dashmap(&self.authenticated_peers, None);
        }

        {
            let mut peer_infos = self.synced_route_info.peer_infos.write();
            for candidate in changed_candidates {
                if Self::secure_auth_level_rank(
                    self.authenticated_peers
                        .get(&candidate.peer_id)
                        .map(|entry| entry.secure_auth_level)
                        .unwrap_or(SecureAuthLevel::None),
                ) > Self::secure_auth_level_rank(candidate.secure_auth_level)
                {
                    update.conflicts.insert(candidate.peer_id);
                    continue;
                }

                if self
                    .authenticated_peers
                    .remove(&candidate.peer_id)
                    .is_some()
                {
                    auth_changed = true;
                }
                self.synced_route_info
                    .locally_authenticated_peers
                    .remove(&candidate.peer_id);

                if !peer_infos.contains_key(&candidate.peer_id) {
                    let mut peer_info = RoutePeerInfo::new();
                    peer_info.peer_id = candidate.peer_id;
                    peer_info.last_update = Some(Timestamp::now());
                    peer_infos.insert(candidate.peer_id, peer_info);
                }
                let peer_info = peer_infos
                    .get_mut(&candidate.peer_id)
                    .expect("the authenticated peer entry exists");
                peer_info.last_update = Some(Timestamp::now());
                peer_info.peer_id = candidate.peer_id;
                peer_info.noise_static_pubkey = candidate.public_key.clone();
                SyncedRouteInfo::set_peer_identity(peer_info, candidate.identity_type);
                let features = peer_info.feature_flag.get_or_insert_default();
                features.relay_origin_proof = true;
                SyncedRouteInfo::sanitize_untrusted_role_capabilities(
                    peer_info,
                    candidate.identity_type,
                );
                if !matches!(candidate.identity_type, PeerIdentityType::Admin) {
                    peer_info.proxy_cidrs.clear();
                    peer_info.groups.clear();
                    peer_info.trusted_credential_pubkeys.clear();
                }
                self.authenticated_peers
                    .insert(candidate.peer_id, candidate.clone());
                self.synced_route_info.locally_authenticated_peers.insert(
                    candidate.peer_id,
                    AuthenticatedRoutePeerEvidence {
                        peer_id: candidate.peer_id,
                        identity_type: candidate.identity_type,
                        noise_static_pubkey: candidate.public_key.clone(),
                        secure_auth_level: candidate.secure_auth_level,
                    },
                );
                auth_changed = true;
            }
        }

        if let Some(connected_peers) = connected_peers {
            auth_changed |= self
                .synced_route_info
                .update_my_conn_info_locked(self.my_peer_id, connected_peers.clone());
        }

        if auth_changed {
            self.synced_route_info.version.inc();
            update.changed = true;
        }
        update
    }

    fn seed_authenticated_peer(
        &self,
        peer_id: PeerId,
        identity_type: PeerIdentityType,
        public_key: Vec<u8>,
        secure_auth_level: SecureAuthLevel,
    ) -> AuthenticatedPeerSeedResult {
        let Some(authenticated_info) =
            Self::authenticated_peer_info(peer_id, identity_type, public_key, secure_auth_level)
        else {
            return AuthenticatedPeerSeedResult::Conflict;
        };
        let update = self
            .apply_authenticated_peer_candidates(std::slice::from_ref(&authenticated_info), None);
        if update.conflicts.contains(&peer_id) {
            AuthenticatedPeerSeedResult::Conflict
        } else if update.changed {
            AuthenticatedPeerSeedResult::Inserted
        } else {
            AuthenticatedPeerSeedResult::Unchanged
        }
    }

    fn retain_authenticated_interface_peers(&self, connected_peers: &BTreeSet<PeerId>) -> bool {
        self.apply_authenticated_peer_candidates(&[], Some(connected_peers))
            .changed
    }

    fn list_session_peers(&self) -> Vec<PeerId> {
        self.sessions.iter().map(|x| *x.key()).collect()
    }

    pub fn mark_interface_peers_dirty(&self) {
        self.interface_peers_generation
            .fetch_add(1, Ordering::Relaxed);
    }

    async fn interface_peer_snapshot_uncached(&self) -> InterfacePeerSnapshot {
        let interface = self.interface.lock().await.as_ref().cloned().unwrap();

        let peers: BTreeSet<_> = interface.list_peers().await.into_iter().collect();
        let mut identity_types = BTreeMap::new();
        let mut authenticated = BTreeMap::new();
        for peer_id in peers.iter().copied() {
            let identity_type = interface.get_peer_identity_type(peer_id).await;
            identity_types.insert(peer_id, identity_type);
            authenticated.insert(
                peer_id,
                InterfacePeerEvidence {
                    identity_type,
                    public_key: interface.get_peer_public_key(peer_id).await,
                    secure_auth_level: interface
                        .get_authenticated_peer_secure_auth_level(peer_id)
                        .await,
                },
            );
        }

        InterfacePeerSnapshot {
            generation: 0,
            peers,
            identity_types,
            authenticated,
        }
    }

    async fn interface_peer_snapshot(&self) -> Arc<InterfacePeerSnapshot> {
        loop {
            let start_generation = self.interface_peers_generation.load(Ordering::Acquire);
            {
                let cached = self.cached_interface_peer_snapshot.lock().unwrap();
                if cached.generation == start_generation {
                    return cached.clone();
                }
            }

            let mut snapshot = self.interface_peer_snapshot_uncached().await;
            let end_generation = self.interface_peers_generation.load(Ordering::Acquire);
            if start_generation == end_generation {
                snapshot.generation = end_generation;
                let snapshot = Arc::new(snapshot);
                *self.cached_interface_peer_snapshot.lock().unwrap() = snapshot.clone();
                return snapshot;
            }
        }
    }

    async fn list_peers_from_interface_snapshot(&self) -> (u64, BTreeSet<PeerId>) {
        let snapshot = self.interface_peer_snapshot().await;
        (snapshot.generation, snapshot.peers.clone())
    }

    async fn list_peers_from_interface<T: FromIterator<PeerId>>(&self) -> T {
        self.interface_peer_snapshot()
            .await
            .peers
            .iter()
            .copied()
            .collect()
    }

    async fn get_peer_identity_type_from_interface(
        &self,
        peer_id: PeerId,
    ) -> Option<PeerIdentityType> {
        let snapshot = self.interface_peer_snapshot().await;
        if let Some(Some(identity_type)) = snapshot.identity_types.get(&peer_id) {
            return Some(*identity_type);
        }

        let interface = self.interface.lock().await.as_ref().cloned().unwrap();
        interface.get_peer_identity_type(peer_id).await
    }

    async fn get_peer_public_key_from_interface(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let interface = self.interface.lock().await.as_ref().cloned().unwrap();
        interface.get_peer_public_key(peer_id).await
    }

    async fn get_peer_secure_auth_level_from_interface(
        &self,
        peer_id: PeerId,
    ) -> Option<SecureAuthLevel> {
        let interface = self.interface.lock().await.as_ref().cloned().unwrap();
        interface
            .get_authenticated_peer_secure_auth_level(peer_id)
            .await
    }

    fn update_my_peer_info(&self) -> bool {
        self.synced_route_info.update_my_peer_info(
            self.my_peer_id,
            self.my_peer_route_id,
            &self.global_ctx,
            *self.self_public_ipv6_addr_lease.lock().unwrap(),
        )
    }

    async fn update_my_conn_info(&self) -> bool {
        let current_generation = self.interface_peers_generation.load(Ordering::Acquire);
        let generation_applied = self
            .applied_interface_peers_generation
            .load(Ordering::Acquire)
            == current_generation;
        if generation_applied {
            let need_periodic_requery = self
                .interface
                .lock()
                .await
                .as_ref()
                .map(|x| x.need_periodic_requery_peers())
                .unwrap_or(false);
            if !need_periodic_requery {
                return false;
            }

            self.mark_interface_peers_dirty();
        }

        let snapshot = self.interface_peer_snapshot().await;
        let generation = snapshot.generation;
        let updated = self
            .apply_authenticated_interface_snapshot(&snapshot)
            .changed;
        self.applied_interface_peers_generation
            .store(generation, Ordering::Release);
        updated
    }

    async fn update_my_foreign_network(&self) -> bool {
        let last_time = self.last_update_my_foreign_network.load();
        if last_time.is_some()
            && last_time.unwrap().elapsed().as_secs()
                < use_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC)
        {
            return false;
        }

        self.last_update_my_foreign_network
            .store(Some(Instant::now()));

        let foreign_networks = self
            .interface
            .lock()
            .await
            .as_ref()
            .unwrap()
            .list_foreign_networks()
            .await;

        // do not need update owner map because we always filter out my peer id.

        self.synced_route_info
            .update_my_foreign_network(self.my_peer_id, foreign_networks)
    }

    fn route_build_work_within_budget(
        build_input: &RouteBuildInput,
        domains: RouteRebuildDomains,
    ) -> bool {
        let policy_count: usize = if domains.topology {
            3
        } else {
            (if domains.cost { 1 } else { 0 }) + (if domains.delivery { 1 } else { 0 })
        };
        let Some(edge_scans) = build_input
            .graph
            .edge_count()
            .checked_add(build_input.speed_graph.edge_count())
        else {
            return false;
        };
        let Some(node_scans) = build_input
            .graph
            .node_count()
            .checked_add(build_input.speed_graph.node_count())
        else {
            return false;
        };
        let Some(policy_factor) = policy_count.checked_mul(2) else {
            return false;
        };
        let Some(node_factor) = policy_count.checked_mul(4) else {
            return false;
        };
        let Some(base_work) = edge_scans
            .checked_mul(policy_factor.max(1))
            .and_then(|work| {
                node_scans
                    .checked_mul(node_factor.max(1))
                    .and_then(|nodes| work.checked_add(nodes))
            })
        else {
            return false;
        };

        let speed_work = if domains.topology || domains.delivery {
            let Some(preparation) = build_input.speed_preparation.as_ref() else {
                return false;
            };
            let speed_graph = &build_input.speed_graph;
            // The checked widest-path builder accounts for threshold-round
            // work while it runs. Preflight charges the one-time scans and
            // destination preparation performed before that builder.
            preparation
                .capacity_work
                .checked_add(speed_graph.edge_count())
                .and_then(|work| work.checked_add(preparation.destinations.len()))
                .unwrap_or(usize::MAX)
        } else {
            0
        };

        base_work
            .checked_add(speed_work)
            .is_some_and(|work| work <= MAX_ROUTE_REBUILD_WORK)
    }

    fn update_route_tables_for_domains(
        &self,
        mut domains: RouteRebuildDomains,
    ) -> Option<(RouteRebuildDomains, RouteBuildInput)> {
        if !domains.needs_route_input() {
            return None;
        }

        let topology = if domains.topology {
            Arc::new(TopologyBuildInput::capture(
                self.my_peer_id,
                &self.synced_route_info,
            ))
        } else {
            let current_version = self.synced_route_info.version.get();
            let committed = self.committed_topology.lock().unwrap().clone();
            if committed
                .as_ref()
                .is_none_or(|topology| topology.version != current_version)
            {
                // A cost update cannot use a stale topology. Escalate to one
                // complete topology capture before any policy is published.
                domains = RouteRebuildDomains::topology();
                let topology = Arc::new(TopologyBuildInput::capture(
                    self.my_peer_id,
                    &self.synced_route_info,
                ));
                topology
            } else {
                committed.expect("committed topology checked above")
            }
        };

        if domains.topology {
            self.rebuild_work
                .topology_rebuilds
                .fetch_add(1, Ordering::Relaxed);
        }

        // Keep the calculator write guard for the complete route build.
        // A replacement cannot split begin_update from end_update.
        let mut calc_locked = self.cost_calculator.write().unwrap();
        let calculator = calc_locked.as_mut().unwrap();
        calculator.begin_update();

        // Max-goodput needs delivery and latency. Least-cost needs cost.
        // Capture each directed edge once for all active policies.
        let capture_cost = domains.topology || domains.cost || domains.delivery;
        let capture_delivery = domains.topology || domains.delivery;
        let build_input = topology.with_measurements(&**calculator, capture_cost, capture_delivery);

        self.route_rebuild_failures
            .fetch_and(!domains.bits(), Ordering::AcqRel);
        if domains.topology && !Self::route_build_work_within_budget(&build_input, domains) {
            self.route_rebuild_failures
                .fetch_or(RouteRebuildDomains::topology().bits(), Ordering::AcqRel);
            tracing::warn!(
                version = build_input.version,
                nodes = build_input.graph.node_count(),
                edges = build_input.graph.edge_count(),
                speed_edges = build_input.speed_graph.edge_count(),
                limit = MAX_ROUTE_REBUILD_WORK,
                "route rebuild structural work exceeds the configured budget"
            );
            calculator.end_update();
            drop(calc_locked);
            return None;
        }
        if !domains.topology {
            if domains.cost
                && !Self::route_build_work_within_budget(&build_input, RouteRebuildDomains::cost())
            {
                domains.cost = false;
                self.route_rebuild_failures
                    .fetch_or(RouteRebuildDomains::cost().bits(), Ordering::AcqRel);
            }
            if domains.delivery
                && !Self::route_build_work_within_budget(
                    &build_input,
                    RouteRebuildDomains::delivery(),
                )
            {
                domains.delivery = false;
                self.route_rebuild_failures
                    .fetch_or(RouteRebuildDomains::delivery().bits(), Ordering::AcqRel);
            }
            if !domains.needs_route_input() {
                calculator.end_update();
                drop(calc_locked);
                return None;
            }
        }

        // The committed topology remains immutable. If a topology mutation
        // occurred while the calculator ran, discard this derived input and
        // rebuild from a fresh topology before publication.
        if self.synced_route_info.version.get() != topology.version {
            calculator.end_update();
            drop(calc_locked);
            return None;
        }

        if domains.topology {
            let baseline_next_hops = match RouteTable::build_next_hop_map_from_input_checked(
                &build_input,
                NextHopPolicy::LeastHop,
            ) {
                Ok(routes) => routes,
                Err(_) => {
                    self.route_rebuild_failures
                        .fetch_or(RouteRebuildDomains::topology().bits(), Ordering::AcqRel);
                    calculator.end_update();
                    drop(calc_locked);
                    return None;
                }
            };
            let cost_next_hops = match RouteTable::build_next_hop_map_from_input_checked(
                &build_input,
                NextHopPolicy::LeastCost,
            ) {
                Ok(routes) => routes,
                Err(_) => {
                    self.route_rebuild_failures
                        .fetch_or(RouteRebuildDomains::topology().bits(), Ordering::AcqRel);
                    calculator.end_update();
                    drop(calc_locked);
                    return None;
                }
            };
            let speed_next_hops = match RouteTable::build_next_hop_map_from_input_checked(
                &build_input,
                NextHopPolicy::MaxGoodput,
            ) {
                Ok(routes) => routes,
                Err(_) => {
                    self.route_rebuild_failures
                        .fetch_or(RouteRebuildDomains::topology().bits(), Ordering::AcqRel);
                    calculator.end_update();
                    drop(calc_locked);
                    return None;
                }
            };
            *self.committed_topology.lock().unwrap() = Some(topology.clone());
            self.rebuild_work
                .least_hop_rebuilds
                .fetch_add(1, Ordering::Relaxed);
            let shared_maps =
                RouteTable::build_shared_maps(self.my_peer_id, &build_input, &baseline_next_hops);
            self.route_table
                .replace_policy(baseline_next_hops, shared_maps.clone());

            self.rebuild_work
                .least_cost_rebuilds
                .fetch_add(1, Ordering::Relaxed);
            self.route_table_with_cost
                .replace_policy(cost_next_hops, shared_maps.clone());

            self.rebuild_work
                .max_goodput_rebuilds
                .fetch_add(1, Ordering::Relaxed);
            self.route_table_with_speed
                .replace_policy(speed_next_hops, shared_maps);
        } else {
            let cost_next_hops = if domains.cost {
                match RouteTable::build_next_hop_map_from_input_checked(
                    &build_input,
                    NextHopPolicy::LeastCost,
                ) {
                    Ok(routes) => Some(routes),
                    Err(_) => {
                        domains.cost = false;
                        self.route_rebuild_failures
                            .fetch_or(RouteRebuildDomains::cost().bits(), Ordering::AcqRel);
                        None
                    }
                }
            } else {
                None
            };
            let speed_next_hops = if domains.delivery {
                match RouteTable::build_next_hop_map_from_input_checked(
                    &build_input,
                    NextHopPolicy::MaxGoodput,
                ) {
                    Ok(routes) => Some(routes),
                    Err(_) => {
                        domains.delivery = false;
                        self.route_rebuild_failures
                            .fetch_or(RouteRebuildDomains::delivery().bits(), Ordering::AcqRel);
                        None
                    }
                }
            } else {
                None
            };
            if domains.cost {
                self.rebuild_work
                    .least_cost_rebuilds
                    .fetch_add(1, Ordering::Relaxed);
                self.route_table_with_cost.replace_next_hops(
                    cost_next_hops.expect("cost routes were built"),
                    build_input.version,
                );
            }
            if domains.delivery {
                self.rebuild_work
                    .max_goodput_rebuilds
                    .fetch_add(1, Ordering::Relaxed);
                self.route_table_with_speed.replace_next_hops(
                    speed_next_hops.expect("speed routes were built"),
                    build_input.version,
                );
            }
        }

        // Validate the topology generation before publishing any derived
        // statistics. A stale policy must not update visible metrics.
        if self.synced_route_info.version.get() != topology.version {
            calculator.end_update();
            drop(calc_locked);
            return None;
        }

        if domains.delivery || domains.topology {
            let network_name = self.global_ctx.get_network_name();
            for route in self.route_table.next_hop_map.iter() {
                let dst_peer_id = *route.key();
                if self.route_table.get_next_hop(dst_peer_id).is_none() {
                    continue;
                }
                let delivery_bps = self
                    .route_table_with_speed
                    .get_next_hop(dst_peer_id)
                    .map(|speed_route| speed_route.path_delivery_bps)
                    .unwrap_or_default();
                let labels = LabelSet::new()
                    .with_label_type(LabelType::NetworkName(network_name.clone()))
                    .with_label_type(LabelType::DstPeerId(dst_peer_id));
                self.global_ctx
                    .stats_manager()
                    .get_counter(MetricName::SpeedSelectedPathDeliveryBps, labels)
                    .set(delivery_bps);
            }
        }

        calculator.end_update();
        Some((domains, build_input))
    }

    fn update_route_table(&self) -> RouteBuildInput {
        self.update_route_tables_for_domains(RouteRebuildDomains::topology())
            .expect("topology rebuild must capture route input")
            .1
    }

    fn update_foreign_network_owner_map(&self) {
        self.foreign_network_my_peer_id_map.clear();
        self.foreign_network_owner_map.clear();
        for item in self.synced_route_info.foreign_network.iter() {
            let key = item.key();
            let entry = item.value();
            if key.peer_id == self.my_peer_id
                || !self.route_table.peer_reachable(key.peer_id)
                || entry.foreign_peer_ids.is_empty()
            {
                continue;
            }
            let network_identity = NetworkIdentity {
                network_name: key.network_name.clone(),
                network_secret: None,
                network_secret_digest: Some(
                    entry
                        .network_secret_digest
                        .clone()
                        .try_into()
                        .unwrap_or_default(),
                ),
            };
            self.foreign_network_owner_map
                .entry(network_identity)
                .or_default()
                .push(entry.my_peer_id_for_this_network);

            self.foreign_network_my_peer_id_map.insert(
                (key.network_name.clone(), entry.my_peer_id_for_this_network),
                key.peer_id,
            );
        }
    }

    fn authenticated_foreign_network_peers(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<(PeerId, Vec<u8>)> {
        let Some(expected_digest) = network_identity.network_secret_digest.as_ref() else {
            return Vec::new();
        };
        if expected_digest.iter().all(|byte| *byte == 0) {
            return Vec::new();
        }

        let snapshot = self.forwarding_snapshot();
        let mut bindings = BTreeMap::<PeerId, Option<Vec<u8>>>::new();
        for item in self.synced_route_info.foreign_network.iter() {
            let key = item.key();
            let entry = item.value();
            if key.peer_id == self.my_peer_id
                || key.network_name != network_identity.network_name
                || entry.foreign_peer_ids.is_empty()
                || entry.my_peer_id_for_this_network == 0
                || entry.my_peer_id_for_this_network == self.my_peer_id
                || entry.network_secret_digest.as_slice() != expected_digest.as_slice()
                || entry.owner_noise_static_pubkey.len() != 32
                || !snapshot.route_table.peer_reachable(key.peer_id)
                || snapshot
                    .foreign_network_my_peer_id_map
                    .get(&(key.network_name.clone(), entry.my_peer_id_for_this_network))
                    != Some(&key.peer_id)
            {
                continue;
            }

            let Some(authenticated_owner) = self.authenticated_peers.get(&key.peer_id) else {
                continue;
            };
            if authenticated_owner.identity_type != PeerIdentityType::Admin
                || !AuthenticatedRoutePeerEvidence::is_allowed_role_auth_pair(
                    authenticated_owner.identity_type,
                    authenticated_owner.secure_auth_level,
                )
                || authenticated_owner.public_key.len() != 32
                || authenticated_owner.public_key != entry.owner_noise_static_pubkey
            {
                continue;
            }

            let foreign_peer_id = entry.my_peer_id_for_this_network;
            let owner_key = authenticated_owner.public_key.clone();
            match bindings.entry(foreign_peer_id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(owner_key));
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if slot
                        .get()
                        .as_ref()
                        .is_none_or(|existing| *existing != owner_key)
                    {
                        slot.insert(None);
                    }
                }
            }
        }

        bindings
            .into_iter()
            .filter_map(|(peer_id, key)| key.map(|key| (peer_id, key)))
            .collect()
    }

    fn refresh_verified_bridge_attestations(&self, peer_infos: &HashMap<PeerId, RoutePeerInfo>) {
        let now_unix_ms = unix_time_ms();
        let now = Instant::now();
        let network_identity = self.global_ctx.get_network_identity();
        let network_secret = network_identity.network_secret.as_deref();

        self.verified_bridge_attestations.retain(|peer_id, cached| {
            let Some(info) = peer_infos.get(peer_id) else {
                return false;
            };
            let Some(now_unix_ms) = now_unix_ms else {
                return false;
            };
            route_info_admin_attestation_capable(info)
                && cached.bridge_input == route_info_bridge_input(info)
                && info.peer_id == *peer_id
                && info.noise_static_pubkey == cached.noise_static_pubkey
                && cached.hmac == info.bridge_attestation_hmac
                && cached.issued_unix_ms == info.bridge_attestation_issued_unix_ms
                && cached.expiry_unix_ms == info.bridge_attestation_expiry_unix_ms
                && network_identity.network_secret_digest.is_some()
                && cached.network_secret_digest == network_identity.network_secret_digest
                && cached.deadline > now
                && bridge_attestation_time_valid(
                    now_unix_ms,
                    info.bridge_attestation_issued_unix_ms,
                    info.bridge_attestation_expiry_unix_ms,
                )
                && info.bridge_attestation_expiry_unix_ms > now_unix_ms
        });

        if let (Some(now_unix_ms), Some(network_secret)) = (now_unix_ms, network_secret) {
            for (peer_id, info) in peer_infos {
                let bridge_input = route_info_bridge_input(info);
                let cache_is_current =
                    self.verified_bridge_attestations
                        .get(peer_id)
                        .is_some_and(|cached| {
                            network_identity.network_secret_digest.is_some()
                                && cached.network_secret_digest
                                    == network_identity.network_secret_digest
                                && cached.bridge_input == bridge_input
                                && cached.noise_static_pubkey == info.noise_static_pubkey
                                && cached.hmac == info.bridge_attestation_hmac
                                && cached.issued_unix_ms == info.bridge_attestation_issued_unix_ms
                                && cached.expiry_unix_ms == info.bridge_attestation_expiry_unix_ms
                                && cached.deadline > now
                        });
                if cache_is_current {
                    continue;
                }
                if *peer_id == self.my_peer_id
                    || !route_info_admin_attestation_capable(info)
                    || info.peer_id != *peer_id
                    || info.bridge_attestation_hmac.len() != 32
                    || !bridge_attestation_time_valid(
                        now_unix_ms,
                        info.bridge_attestation_issued_unix_ms,
                        info.bridge_attestation_expiry_unix_ms,
                    )
                    || info.bridge_attestation_expiry_unix_ms <= now_unix_ms
                    || !verify_bridge_attestation_hmac(
                        network_secret,
                        &network_identity.network_name,
                        info.peer_id,
                        &info.noise_static_pubkey,
                        bridge_input,
                        info.bridge_attestation_issued_unix_ms,
                        info.bridge_attestation_expiry_unix_ms,
                        &info.bridge_attestation_hmac,
                    )
                {
                    self.verified_bridge_attestations.remove(peer_id);
                    continue;
                }

                let remaining =
                    Duration::from_millis(info.bridge_attestation_expiry_unix_ms - now_unix_ms);
                let deadline = now + remaining.min(BRIDGE_ATTESTATION_MAX_DEADLINE);
                self.verified_bridge_attestations.insert(
                    *peer_id,
                    VerifiedBridgeAttestation {
                        noise_static_pubkey: info.noise_static_pubkey.clone(),
                        bridge_input,
                        hmac: info.bridge_attestation_hmac.clone(),
                        issued_unix_ms: info.bridge_attestation_issued_unix_ms,
                        expiry_unix_ms: info.bridge_attestation_expiry_unix_ms,
                        network_secret_digest: network_identity.network_secret_digest,
                        deadline,
                    },
                );
            }
        } else {
            self.verified_bridge_attestations.clear();
        }

        let next_deadline = self
            .verified_bridge_attestations
            .iter()
            .map(|entry| entry.deadline)
            .min();
        *self.bridge_attestation_next_deadline.lock().unwrap() = next_deadline;
    }

    fn expire_verified_bridge_attestations(&self) -> bool {
        let now = Instant::now();
        let mut expired = false;
        self.verified_bridge_attestations.retain(|_, cached| {
            let keep = cached.deadline > now;
            expired |= !keep;
            keep
        });
        let next_deadline = self
            .verified_bridge_attestations
            .iter()
            .map(|entry| entry.deadline)
            .min();
        *self.bridge_attestation_next_deadline.lock().unwrap() = next_deadline;
        expired
    }

    fn bridge_attestation_sleep_duration_at(&self, now: Instant) -> Duration {
        self.bridge_attestation_next_deadline
            .lock()
            .unwrap()
            .map(|deadline| {
                deadline
                    .saturating_duration_since(now)
                    .min(BRIDGE_ATTESTATION_REFRESH)
            })
            .unwrap_or(BRIDGE_ATTESTATION_REFRESH)
    }

    fn bridge_attestation_sleep_duration(&self) -> Duration {
        self.bridge_attestation_sleep_duration_at(Instant::now())
    }

    /// Publish one complete route-origin authority set for this forwarding
    /// generation. Missing entries revoke stale generic and bridge authority.
    fn publish_route_origin_auth_batch(
        &self,
        route_table: &RouteTableSnapshot,
        generation: u64,
    ) -> Result<(), super::route_trait::RouteOriginAuthPublishError> {
        let Some(source) = self.forwarding_snapshot_source.read().unwrap().clone() else {
            return Ok(());
        };

        // Capture local authentication and credential roots once. Route wire
        // labels do not provide authority, and concurrent updates must not
        // produce a mixed-generation publication.
        let _topology_guard = self.synced_route_info.topology_state_lock();
        let topology_is_current =
            self.synced_route_info.version.get() == route_table.next_hop_map_version;
        let authenticated = self
            .authenticated_peers
            .iter()
            .filter_map(|entry| {
                let info = entry.value();
                let evidence = AuthenticatedRoutePeerEvidence {
                    peer_id: info.peer_id,
                    identity_type: info.identity_type,
                    noise_static_pubkey: info.public_key.clone(),
                    secure_auth_level: info.secure_auth_level,
                };
                evidence
                    .validate_for(*entry.key())
                    .then_some((*entry.key(), evidence))
            })
            .collect::<BTreeMap<PeerId, AuthenticatedRoutePeerEvidence>>();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(i64::MAX);
        let trusted_credentials = self
            .synced_route_info
            .trusted_credential_pubkeys
            .iter()
            .filter_map(|entry| {
                let credential = entry.value();
                (entry.key().len() == 32
                    && credential_is_current(
                        credential,
                        self.global_ctx.get_credential_manager(),
                        now_unix,
                    ))
                .then_some(entry.key().clone())
            })
            .collect::<HashSet<Vec<u8>>>();

        let mut publications = BTreeMap::<PeerId, OriginAuthPublication>::new();
        for (peer_id, route_info) in route_table.peer_infos.iter() {
            if *peer_id == self.my_peer_id || !route_table.peer_reachable(*peer_id) {
                continue;
            }
            let generic = if topology_is_current {
                authenticated
                    .get(peer_id)
                    .filter(|evidence| {
                        route_info.noise_static_pubkey == evidence.noise_static_pubkey
                    })
                    .cloned()
                    .or_else(|| {
                        (SyncedRouteInfo::peer_identity_type(route_info)
                            == Some(PeerIdentityType::Credential)
                            && route_info.noise_static_pubkey.len() == 32
                            && trusted_credentials.contains(&route_info.noise_static_pubkey))
                        .then(|| AuthenticatedRoutePeerEvidence {
                            peer_id: *peer_id,
                            identity_type: PeerIdentityType::Credential,
                            noise_static_pubkey: route_info.noise_static_pubkey.clone(),
                            secure_auth_level: SecureAuthLevel::PeerVerified,
                        })
                    })
                    .or_else(|| self.attested_admin_identity_evidence(*peer_id, route_info))
            } else {
                None
            };
            let bridge =
                self.bridge_evidence_for_snapshot(*peer_id, route_info, route_table, generation);
            publications.insert(
                *peer_id,
                OriginAuthPublication {
                    peer_id: *peer_id,
                    generic,
                    bridge,
                    foreign_owner: None,
                },
            );
        }

        if topology_is_current {
            // A virtual foreign relay is authenticated by the parent overlay before
            // it can participate in this foreign OSPF topology. Publish that local
            // PeerVerified identity so RelayPeerMap can run Noise IK and bootstrap
            // the first OSPF exchange. Other unreachable identities remain absent.
            for (peer_id, evidence) in &authenticated {
                if *peer_id == self.my_peer_id
                    || evidence.identity_type != PeerIdentityType::ForeignRelay
                    || evidence.secure_auth_level != SecureAuthLevel::PeerVerified
                {
                    continue;
                }
                publications
                    .entry(*peer_id)
                    .or_insert_with(|| OriginAuthPublication {
                        peer_id: *peer_id,
                        generic: Some(evidence.clone()),
                        bridge: None,
                        foreign_owner: None,
                    });
            }
        }
        let publications = publications.into_values().collect::<Vec<_>>();
        let Some(interface) = self.publish_interface.read().unwrap().as_ref().cloned() else {
            return Ok(());
        };
        let result =
            interface.publish_origin_auth_batch(source.source_token(), generation, &publications);
        if result.is_err() {
            interface.discard_origin_auth_batch(source.source_token(), generation);
        }
        result
    }

    fn publish_forwarding_snapshot_for_domains(
        &self,
        domains: RouteRebuildDomains,
    ) -> Result<(), super::route_trait::RouteOriginAuthPublishError> {
        if !domains.needs_publication() {
            return Ok(());
        }
        let previous = self.forwarding_snapshot();
        let route_table = if domains.topology {
            Arc::new(self.route_table.into_snapshot())
        } else {
            previous.route_table.clone()
        };
        let route_table_with_cost = if domains.topology || domains.cost {
            Arc::new(self.route_table_with_cost.into_snapshot())
        } else {
            previous.route_table_with_cost.clone()
        };
        let route_table_with_speed = if domains.topology || domains.delivery {
            Arc::new(self.route_table_with_speed.into_snapshot())
        } else {
            previous.route_table_with_speed.clone()
        };
        let generation = self.allocate_forwarding_generation()?;

        if domains.topology || domains.bridge {
            self.refresh_verified_bridge_attestations(&route_table.peer_infos);
            self.rebuild_work
                .bridge_refreshes
                .fetch_add(1, Ordering::Relaxed);
        }

        let forwarding_peers = if domains.topology || domains.bridge {
            Arc::new(super::route_trait::ForwardingPeerTable::new(
                route_table
                    .peer_infos
                    .iter()
                    .filter_map(|(peer_id, info)| {
                        (*peer_id != self.my_peer_id && route_table.peer_reachable(*peer_id)).then(
                            || {
                                let bridge_evidence = self.bridge_evidence_for_snapshot(
                                    *peer_id,
                                    info,
                                    &route_table,
                                    generation,
                                );
                                super::route_trait::ForwardingPeerInfo {
                                    peer_id: *peer_id,
                                    has_ipv4: info.ipv4_addr.is_some(),
                                    feature_flag: info.feature_flag,
                                    multicast_groups: info.multicast_groups.clone(),
                                    bridge_authorized: bridge_evidence.is_some(),
                                    bridge_authorization_deadline: bridge_evidence
                                        .and_then(|evidence| evidence.deadline),
                                }
                            },
                        )
                    })
                    .collect(),
            ))
        } else {
            previous.forwarding_peers.clone()
        };
        let foreign_network_owner_map = if domains.topology || domains.foreign {
            Arc::new(
                self.foreign_network_owner_map
                    .iter()
                    .map(|entry| (entry.key().clone(), entry.value().clone()))
                    .collect(),
            )
        } else {
            previous.foreign_network_owner_map.clone()
        };
        let foreign_network_my_peer_id_map = if domains.topology || domains.foreign {
            Arc::new(
                self.foreign_network_my_peer_id_map
                    .iter()
                    .map(|entry| (entry.key().clone(), *entry.value()))
                    .collect(),
            )
        } else {
            previous.foreign_network_my_peer_id_map.clone()
        };
        let public_ipv6_gateway_peer_id = self
            .public_ipv6_service()
            .and_then(|service| service.provider_peer_id_for_client())
            .filter(|peer_id| {
                (*peer_id == self.my_peer_id || route_table.peer_reachable(*peer_id))
                    && route_table.peer_infos.get(peer_id).is_some_and(|info| {
                        info.feature_flag
                            .as_ref()
                            .is_some_and(|features| features.ipv6_public_addr_provider)
                            && info.ipv6_public_addr_prefix.is_some()
                    })
            });

        let decision_snapshot = ForwardingDecisionSnapshot::from_parts_with_service_routes(
            generation,
            forwarding_peers.clone(),
            route_table.suppressed_peer_ids.clone(),
            public_ipv6_gateway_peer_id,
            route_table.next_hop_map.clone(),
            route_table_with_cost.next_hop_map.clone(),
            route_table_with_speed.next_hop_map.clone(),
            route_table.ipv4_peer_id_map.clone(),
            route_table.ipv6_peer_id_map.clone(),
            route_table.cidr_peer_id_map.clone(),
            route_table.cidr_v6_peer_id_map.clone(),
            route_table.service_routes.clone(),
        );

        let next_snapshot = Arc::new(ForwardingSnapshot {
            generation,
            route_table,
            route_table_with_cost,
            route_table_with_speed,
            forwarding_peers,
            foreign_network_owner_map,
            foreign_network_my_peer_id_map,
            decision_snapshot,
        });
        let source = self.forwarding_snapshot_source.read().unwrap().clone();
        if let Some(source) = source {
            self.publish_route_origin_auth_batch(&next_snapshot.route_table, generation)?;
            if source
                .publish(next_snapshot.decision_snapshot.clone())
                .is_err()
            {
                if let Some(interface) = self.publish_interface.read().unwrap().as_ref().cloned() {
                    interface.discard_origin_auth_batch(source.source_token(), generation);
                }
                return Err(super::route_trait::RouteOriginAuthPublishError::PublicationRejected);
            }
        }
        self.forwarding_snapshot.store(next_snapshot);
        self.rebuild_work
            .snapshot_publications
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn publish_forwarding_snapshot(&self) {
        if let Err(error) =
            self.publish_forwarding_snapshot_for_domains(RouteRebuildDomains::topology())
        {
            tracing::warn!(?error, "forwarding snapshot publication rejected");
        }
    }

    /// Authorize complete Ethernet only from authenticated direct or attested peers.
    ///
    /// Route wire role and capability fields remain untrusted inputs. A static key
    /// in the route record must match local evidence when the route provides one.
    fn is_locally_authenticated_bridge(&self, peer_id: PeerId, route_info: &RoutePeerInfo) -> bool {
        if route_info.peer_id != peer_id || !route_info_bridge_capability(route_info) {
            return false;
        }
        let Some(authenticated) = self
            .authenticated_peers
            .get(&peer_id)
            .map(|entry| entry.value().clone())
        else {
            return false;
        };
        if authenticated.peer_id != peer_id
            || !matches!(authenticated.identity_type, PeerIdentityType::Admin)
            || !matches!(
                authenticated.secure_auth_level,
                SecureAuthLevel::PeerVerified | SecureAuthLevel::NetworkSecretConfirmed
            )
            || authenticated.public_key.len() != 32
        {
            return false;
        }
        route_info.noise_static_pubkey == authenticated.public_key
    }

    fn attested_admin_identity_evidence(
        &self,
        peer_id: PeerId,
        route_info: &RoutePeerInfo,
    ) -> Option<AuthenticatedRoutePeerEvidence> {
        if route_info.peer_id != peer_id || !route_info_admin_attestation_capable(route_info) {
            return None;
        }
        self.verified_bridge_attestations
            .get(&peer_id)
            .and_then(|attestation| {
                let live = attestation.noise_static_pubkey == route_info.noise_static_pubkey
                    && attestation.deadline > Instant::now();
                live.then(|| AuthenticatedRoutePeerEvidence {
                    peer_id,
                    identity_type: PeerIdentityType::Admin,
                    noise_static_pubkey: route_info.noise_static_pubkey.clone(),
                    secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
                })
            })
    }

    fn attested_bridge_deadline(
        &self,
        peer_id: PeerId,
        route_info: &RoutePeerInfo,
    ) -> Option<Instant> {
        if route_info.peer_id != peer_id || !route_info_bridge_capability(route_info) {
            return None;
        }
        self.verified_bridge_attestations
            .get(&peer_id)
            .and_then(|attestation| {
                let live = attestation.bridge_input
                    && attestation.noise_static_pubkey == route_info.noise_static_pubkey
                    && attestation.deadline > Instant::now();
                live.then_some(attestation.deadline)
            })
    }

    fn bridge_evidence_for_snapshot(
        &self,
        peer_id: PeerId,
        route_info: &RoutePeerInfo,
        route_table: &RouteTableSnapshot,
        generation: u64,
    ) -> Option<BridgeRoutePeerEvidence> {
        let Some(next_hop) = route_table.get_next_hop(peer_id) else {
            return None;
        };
        if next_hop.next_hop_peer_id == peer_id && next_hop.path_len == 1 {
            self.is_locally_authenticated_bridge(peer_id, route_info)
                .then(|| BridgeRoutePeerEvidence {
                    peer_id,
                    noise_static_pubkey: route_info.noise_static_pubkey.clone(),
                    deadline: None,
                    generation,
                })
        } else {
            self.attested_bridge_deadline(peer_id, route_info)
                .map(|deadline| BridgeRoutePeerEvidence {
                    peer_id,
                    noise_static_pubkey: route_info.noise_static_pubkey.clone(),
                    deadline: Some(deadline),
                    generation,
                })
        }
    }

    fn cost_calculator_update_domains(&self) -> RouteRebuildDomains {
        let calculator = self.cost_calculator.read().unwrap();
        let Some(calculator) = calculator.as_ref() else {
            return RouteRebuildDomains::default();
        };
        RouteRebuildDomains {
            cost: calculator.cost_need_update(),
            delivery: calculator.delivery_need_update(),
            ..RouteRebuildDomains::default()
        }
    }

    fn cost_calculator_next_update_in(&self) -> Option<Duration> {
        self.cost_calculator
            .read()
            .unwrap()
            .as_ref()
            .and_then(|calculator| calculator.next_delivery_update_in())
    }

    fn handle_global_ctx_event(&self, event: &GlobalCtxEvent) {
        if matches!(
            event,
            GlobalCtxEvent::PeerAdded(_)
                | GlobalCtxEvent::PeerRemoved(_)
                | GlobalCtxEvent::PeerConnAdded(_)
                | GlobalCtxEvent::PeerConnRemoved(_)
        ) {
            self.mark_interface_peers_dirty();
        }
    }

    fn update_route_table_and_cached_local_conn_bitmap(&self) {
        let _rebuild_guard = self.route_rebuild_lock.lock().unwrap();
        self.update_route_table_and_cached_local_conn_bitmap_locked();
    }

    fn update_route_table_and_cached_local_conn_bitmap_locked(&self) {
        self.rebuild_domains_locked(RouteRebuildDomains::topology());
    }

    fn rebuild_domains(&self, domains: RouteRebuildDomains) {
        if !domains.needs_publication() {
            return;
        }
        let _rebuild_guard = self.route_rebuild_lock.lock().unwrap();
        self.rebuild_domains_locked(domains);
    }

    fn request_route_rebuild(&self, domains: RouteRebuildDomains) {
        if !domains.needs_publication() {
            return;
        }
        self.pending_route_rebuilds
            .fetch_or(domains.bits(), Ordering::AcqRel);
        self.route_rebuild_notify.notify_one();
    }

    async fn route_rebuild_worker(self: Arc<Self>) {
        loop {
            self.route_rebuild_notify.notified().await;
            loop {
                let bits = self.pending_route_rebuilds.swap(0, Ordering::AcqRel);
                if bits == 0 {
                    break;
                }
                let domains = RouteRebuildDomains::from_bits(bits);
                self.rebuild_domains(domains);
                if domains.topology {
                    self.notify_public_ipv6_route_change();
                }
            }
        }
    }

    /// Recompute only the requested domains, then publish one coherent snapshot.
    ///
    /// The caller must hold `route_rebuild_lock` when it calls this method.
    fn rebuild_domains_locked(&self, domains: RouteRebuildDomains) {
        if domains.topology {
            self.update_peer_info_last_update();
        }

        let (mut effective_domains, mut build_input) =
            match self.update_route_tables_for_domains(domains) {
                Some(result) => {
                    self.route_rebuild_failures.swap(0, Ordering::AcqRel);
                    result
                }
                None => {
                    let failures = self.route_rebuild_failures.swap(0, Ordering::AcqRel);
                    if failures & RouteRebuildDomains::topology().bits() != 0 {
                        self.publish_conservative_forwarding_snapshot();
                        return;
                    }
                    let topology_is_current = self
                        .committed_topology
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|topology| {
                            topology.version == self.synced_route_info.version.get()
                        });
                    if topology_is_current {
                        if domains.foreign {
                            self.update_foreign_network_owner_map();
                            self.rebuild_work
                                .owner_map_rebuilds
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if let Err(error) = self.publish_forwarding_snapshot_for_domains(domains) {
                            tracing::warn!(?error, "forwarding snapshot publication rejected");
                        }
                        return;
                    }
                    let Some(result) =
                        self.update_route_tables_for_domains(RouteRebuildDomains::topology())
                    else {
                        self.route_rebuild_failures.swap(0, Ordering::AcqRel);
                        self.publish_conservative_forwarding_snapshot();
                        return;
                    };
                    result
                }
            };

        // Sync handlers can update topology while this thread computes owner
        // maps. Do not publish policy and metadata from different topologies.
        if self.synced_route_info.version.get() != build_input.version {
            let Some((fresh_domains, fresh_input)) =
                self.update_route_tables_for_domains(RouteRebuildDomains::topology())
            else {
                self.route_rebuild_failures.swap(0, Ordering::AcqRel);
                self.publish_conservative_forwarding_snapshot();
                return;
            };
            effective_domains = fresh_domains;
            build_input = fresh_input;
        }

        if effective_domains.topology || effective_domains.foreign {
            self.update_foreign_network_owner_map();
            self.rebuild_work
                .owner_map_rebuilds
                .fetch_add(1, Ordering::Relaxed);
        }

        if self.synced_route_info.version.get() != build_input.version {
            // Coalesce another topology rebuild into the periodic update loop.
            self.mark_interface_peers_dirty();
            return;
        }
        if let Err(error) = self.publish_forwarding_snapshot_for_domains(effective_domains) {
            tracing::warn!(?error, "forwarding snapshot publication rejected");
        }
    }

    fn publish_conservative_forwarding_snapshot(&self) {
        let version = self.synced_route_info.version.get();
        self.route_table.clear_for_version(version);
        self.route_table_with_cost.clear_for_version(version);
        self.route_table_with_speed.clear_for_version(version);
        *self.committed_topology.lock().unwrap() = None;
        self.foreign_network_owner_map.clear();
        self.foreign_network_my_peer_id_map.clear();
        self.verified_bridge_attestations.clear();
        *self.bridge_attestation_next_deadline.lock().unwrap() = None;
        if let Err(error) =
            self.publish_forwarding_snapshot_for_domains(RouteRebuildDomains::topology())
        {
            tracing::warn!(
                ?error,
                "conservative forwarding snapshot publication rejected"
            );
        }
    }

    fn build_route_info(&self, session: &SyncRouteSession) -> Option<Vec<RoutePeerInfo>> {
        let route_snapshot = self.forwarding_snapshot();
        let mut route_infos = Vec::new();
        let peer_infos = self.synced_route_info.peer_infos.read();
        let mut unreachable_peers_for_peer_info = session.unreachable_peers_for_peer_info.lock();
        let last_sync_succ_timestamp = session.last_sync_succ_timestamp.load();
        for (peer_id, peer_info) in peer_infos.iter().rev() {
            // stop iter if last_update of peer info is older than session.last_sync_succ_timestamp
            if let Some(last_update) = peer_info.last_update {
                let Ok(last_update) = SystemTime::try_from(last_update) else {
                    tracing::warn!(
                        peer_id,
                        "skip route info with an invalid last_update timestamp"
                    );
                    continue;
                };
                if last_sync_succ_timestamp.is_some_and(|t| last_update < t) {
                    break;
                }
            }

            if session.check_saved_peer_info_update_to_date(peer_info.peer_id, peer_info.version) {
                continue;
            }

            // do not send unreachable peer info to dst peer.
            if !route_snapshot.route_table.topology_peer_reachable(*peer_id) {
                unreachable_peers_for_peer_info.insert(*peer_id, peer_info.version);
                continue;
            }

            route_infos.push(peer_info.clone());
        }

        unreachable_peers_for_peer_info.retain(|peer_id, version| {
            if session.check_saved_peer_info_update_to_date(*peer_id, *version) {
                // if saved peer info is up-to-date, forget this peer id.
                return false;
            }
            let Some(peer_info) = peer_infos.get(peer_id) else {
                // if not found in peer info map, forget this peer id.
                return false;
            };

            if route_snapshot.route_table.topology_peer_reachable(*peer_id) {
                route_infos.push(peer_info.clone());
            }

            // this round rpc may fail, so keep it and remove the id only when it's in dst_saved_map
            true
        });

        if route_infos.is_empty() {
            None
        } else {
            Some(route_infos)
        }
    }

    fn build_conn_peer_list(
        &self,
        session: &SyncRouteSession,
        estimated_size: &mut usize,
    ) -> Option<RouteConnPeerList> {
        let route_snapshot = self.forwarding_snapshot();
        let last_sync_succ_timestamp = session.last_sync_succ_timestamp.load();
        let mut peer_conn_infos = Vec::new();
        *estimated_size = 0;

        let conn_map = self.synced_route_info.conn_map.read();
        let mut unreachable_peers_for_conn_info = session.unreachable_peers_for_conn_info.lock();

        let mut add_to_conn_peer_list = |peer_id: PeerId, conn_info: &RouteConnInfo| {
            peer_conn_infos.push(PeerConnInfo {
                peer_id: Some(PeerIdVersion {
                    peer_id,
                    version: conn_info.version.get(),
                }),
                connected_peer_ids: conn_info.connected_peers.iter().copied().collect(),
            });
            *estimated_size += std::mem::size_of::<PeerIdVersion>()
                + conn_info.connected_peers.len() * std::mem::size_of::<PeerId>();
        };

        for (peer_id, conn_info) in conn_map.iter().rev() {
            // stop iter if last_update of conn info is older than session.last_sync_succ_timestamp
            let last_update = TryInto::<SystemTime>::try_into(conn_info.last_update).unwrap();
            if last_sync_succ_timestamp.is_some_and(|t| last_update < t) {
                break;
            }

            if session.check_saved_conn_version_update_to_date(*peer_id, conn_info.version.get()) {
                continue;
            }

            if !route_snapshot.route_table.topology_peer_reachable(*peer_id) {
                unreachable_peers_for_conn_info.insert(*peer_id, conn_info.version.get());
                continue;
            }

            add_to_conn_peer_list(*peer_id, conn_info);
        }

        unreachable_peers_for_conn_info.retain(|peer_id, version| {
            if session.check_saved_conn_version_update_to_date(*peer_id, *version) {
                // if saved conn info is up-to-date, forget this peer id.
                return false;
            }
            let Some(conn_info) = conn_map.get(peer_id) else {
                // if not found in peer info map, forget this peer id.
                return false;
            };

            if route_snapshot.route_table.topology_peer_reachable(*peer_id) {
                add_to_conn_peer_list(*peer_id, conn_info);
            }

            // this round rpc may fail, so keep it and remove the id only when it's in dst_saved_map
            true
        });

        if peer_conn_infos.is_empty() {
            return None;
        }

        Some(RouteConnPeerList { peer_conn_infos })
    }

    fn build_foreign_network_info(
        &self,
        session: &SyncRouteSession,
    ) -> Option<RouteForeignNetworkInfos> {
        let mut foreign_networks = RouteForeignNetworkInfos::default();
        for item in self.synced_route_info.foreign_network.iter() {
            if session.check_saved_foreign_network_version_update_to_date(
                item.key(),
                item.value().version,
            ) {
                continue;
            }

            foreign_networks
                .infos
                .push(route_foreign_network_infos::Info {
                    key: Some(item.key().clone()),
                    value: Some(item.value().clone()),
                });
        }

        if foreign_networks.infos.is_empty() {
            None
        } else {
            Some(foreign_networks)
        }
    }

    async fn update_my_infos(&self) -> bool {
        let my_peer_info_updated = self.update_my_peer_info();
        let my_conn_info_updated = self.update_my_conn_info().await;
        let my_foreign_network_updated = self.update_my_foreign_network().await;
        let mut untrusted_changed = false;
        if my_peer_info_updated || my_conn_info_updated {
            // The interface snapshot mutation already changed topology. Reuse one
            // forwarding snapshot for credential owner election instead of rebuilding twice.
            self.update_route_table_and_cached_local_conn_bitmap();
            let untrusted = self.refresh_credential_trusts_with_existing_topology();
            self.disconnect_untrusted_peers(&untrusted).await;
            untrusted_changed = !untrusted.is_empty();
        }

        if my_foreign_network_updated && !(my_peer_info_updated || my_conn_info_updated) {
            self.rebuild_domains(RouteRebuildDomains::foreign());
        }

        let mut public_ipv6_state_updated = false;
        if untrusted_changed {
            self.update_route_table_and_cached_local_conn_bitmap();
            public_ipv6_state_updated = self.notify_public_ipv6_route_change();
        } else if my_peer_info_updated || my_conn_info_updated {
            public_ipv6_state_updated = self.notify_public_ipv6_route_change();
        }
        if my_peer_info_updated {
            self.update_peer_info_last_update();
        }
        my_peer_info_updated
            || my_conn_info_updated
            || my_foreign_network_updated
            || public_ipv6_state_updated
    }

    async fn refresh_acl_groups(&self) -> bool {
        let my_peer_info_updated = self.update_my_peer_info();
        let trust_admin_groups_without_proof = self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none();

        let peer_infos: Vec<_> = self
            .synced_route_info
            .peer_infos
            .read()
            .iter()
            .map(|(_, info)| info.clone())
            .collect();
        self.synced_route_info.verify_and_update_group_trusts(
            &peer_infos,
            &self.global_ctx.get_acl_group_declarations(),
            trust_admin_groups_without_proof,
        );

        let untrusted = self.refresh_credential_trusts_with_current_topology();
        self.disconnect_untrusted_peers(&untrusted).await;

        let mut public_ipv6_state_updated = false;
        if my_peer_info_updated || !untrusted.is_empty() {
            self.update_route_table_and_cached_local_conn_bitmap();
            public_ipv6_state_updated = self.notify_public_ipv6_route_change();
        }
        if my_peer_info_updated {
            self.update_peer_info_last_update();
        }

        my_peer_info_updated || !untrusted.is_empty() || public_ipv6_state_updated
    }

    fn refresh_credential_trusts(&self) -> Vec<PeerId> {
        let network_identity = self.global_ctx.get_network_identity();
        let (untrusted, global_trusted_keys, _) = self
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_identity.network_secret.as_deref(),
                |_| true,
                Some(self.my_peer_id),
            );
        self.global_ctx
            .update_trusted_keys(global_trusted_keys, &network_identity.network_name);

        untrusted
    }

    fn refresh_credential_trusts_with_current_topology(&self) -> Vec<PeerId> {
        let network_identity = self.global_ctx.get_network_identity();

        // Non-reusable credential owner election depends on reachability, so rebuild the
        // route table from the latest synced peer/conn state before checking active peers.
        self.update_route_table_and_cached_local_conn_bitmap();
        self.refresh_credential_trusts_with_existing_topology_inner(network_identity)
    }

    fn refresh_credential_trusts_with_existing_topology(&self) -> Vec<PeerId> {
        let network_identity = self.global_ctx.get_network_identity();
        self.refresh_credential_trusts_with_existing_topology_inner(network_identity)
    }

    fn refresh_credential_trusts_with_existing_topology_inner(
        &self,
        network_identity: NetworkIdentity,
    ) -> Vec<PeerId> {
        let route_snapshot = self.forwarding_snapshot();

        let (untrusted, global_trusted_keys, suppressed_changed) = self
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                network_identity.network_secret.as_deref(),
                |peer_id| {
                    peer_id == self.my_peer_id
                        || route_snapshot.route_table.topology_peer_reachable(peer_id)
                },
                Some(self.my_peer_id),
            );
        self.global_ctx
            .update_trusted_keys(global_trusted_keys, &network_identity.network_name);

        if !untrusted.is_empty() || suppressed_changed {
            self.update_route_table_and_cached_local_conn_bitmap();
        }
        untrusted
    }

    async fn refresh_credential_trusts_and_disconnect(&self) -> bool {
        let untrusted = self.refresh_credential_trusts_with_current_topology();
        self.disconnect_untrusted_peers(&untrusted).await;
        !untrusted.is_empty()
    }

    async fn disconnect_untrusted_peers(&self, untrusted_peers: &[PeerId]) {
        if untrusted_peers.is_empty() {
            return;
        }

        let interface = {
            let guard = self.interface.lock().await;
            guard.as_ref().cloned()
        };
        let Some(interface) = interface else {
            return;
        };

        for peer_id in untrusted_peers {
            tracing::warn!(?peer_id, "disconnecting untrusted peer");
            interface.close_peer(*peer_id).await;
        }
    }

    /// The identity this node presents to any peer, mirrored from
    /// `RoutePeerInfo::new_updated_self`.
    fn local_route_identity_type(&self) -> PeerIdentityType {
        if self
            .global_ctx
            .get_hostname()
            .starts_with(PUBLIC_SERVER_HOSTNAME_PREFIX)
        {
            PeerIdentityType::ForeignRelay
        } else if self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_some()
        {
            PeerIdentityType::Admin
        } else {
            PeerIdentityType::Credential
        }
    }

    fn build_foreign_relay_conn_info(
        &self,
        session: &SyncRouteSession,
    ) -> Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo> {
        let conn_map = self.synced_route_info.conn_map.read();
        let conn_info = conn_map.get(&self.my_peer_id)?;
        let route_snapshot = self.forwarding_snapshot();

        // A ForeignRelay owns exactly one advertised topology row. Its logical
        // adjacency includes peers it can currently reach through other relays,
        // allowing a downstream tenant to route A -> R1 -> R2 -> B while R1
        // remains the sole next hop selected by that tenant. No third-party
        // connection source is asserted by this record.
        let mut connected_peer_ids = conn_info.connected_peers.clone();
        for peer_id in route_snapshot.route_table.peer_infos.keys() {
            if *peer_id != self.my_peer_id && route_snapshot.route_table.peer_reachable(*peer_id) {
                connected_peer_ids.insert(*peer_id);
            }
        }

        // Reachability can change without a direct connection mutation. Fold the
        // route topology version into this relay-owned row so those changes are
        // delivered to established synchronization sessions.
        let version = conn_info
            .version
            .get()
            .max(self.synced_route_info.version.get());
        if session.check_saved_conn_version_update_to_date(self.my_peer_id, version) {
            return None;
        }
        Some(
            RouteConnPeerList {
                peer_conn_infos: vec![PeerConnInfo {
                    peer_id: Some(PeerIdVersion {
                        peer_id: self.my_peer_id,
                        version,
                    }),
                    connected_peer_ids: connected_peer_ids.into_iter().collect(),
                }],
            }
            .into(),
        )
    }

    fn restore_forwarded_admin_attestation(&self, info: &mut RoutePeerInfo) {
        let Some(raw_info) = self.synced_route_info.raw_peer_infos.get(&info.peer_id) else {
            return;
        };
        let raw_bytes = raw_info.encode_to_vec();
        let Ok(advertised) = RoutePeerInfo::decode(raw_bytes.as_slice()) else {
            return;
        };
        if advertised.peer_id != info.peer_id
            || advertised.version != info.version
            || advertised.identity_type != PeerIdentityType::Admin as i32
            || advertised.noise_static_pubkey != info.noise_static_pubkey
            || advertised.bridge_attestation_hmac.len() != 32
        {
            return;
        }

        // Restore only fields covered by, or required to verify, the shared-secret
        // Admin identity attestation. Other capabilities stay sanitized in the
        // relay's local typed view and in the forwarded typed record.
        SyncedRouteInfo::set_peer_identity(info, PeerIdentityType::Admin);
        info.feature_flag.get_or_insert_default().bridge_input =
            route_info_bridge_input(&advertised);
        info.bridge_attestation_hmac = advertised.bridge_attestation_hmac;
        info.bridge_attestation_issued_unix_ms = advertised.bridge_attestation_issued_unix_ms;
        info.bridge_attestation_expiry_unix_ms = advertised.bridge_attestation_expiry_unix_ms;
    }

    fn build_sync_request(
        &self,
        session: &SyncRouteSession,
        dst_peer_id: PeerId,
        destination_identity_type: Option<PeerIdentityType>,
    ) -> (
        Option<Vec<RoutePeerInfo>>,
        Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo>,
        Option<RouteForeignNetworkInfos>,
    ) {
        let route_infos = self.build_route_info(session);
        let local_identity_type = self.local_route_identity_type();
        if local_identity_type == PeerIdentityType::ForeignRelay {
            let route_infos = route_infos.map(|mut infos| {
                for info in &mut infos {
                    if info.peer_id != self.my_peer_id {
                        self.restore_forwarded_admin_attestation(info);
                    }
                }
                infos
            });
            return (
                route_infos,
                self.build_foreign_relay_conn_info(session),
                None,
            );
        }
        // Receivers enforce the sender role shape from the authenticated link
        // scope. An Admin tenant is presented as ForeignRelay/SharedNode on a
        // cross-network link, so it must use the restricted self-only shape.
        let destination_scopes_sender = matches!(
            destination_identity_type,
            Some(PeerIdentityType::ForeignRelay | PeerIdentityType::SharedNode)
        );
        if matches!(local_identity_type, PeerIdentityType::Admin) && !destination_scopes_sender {
            let conn_info = self.build_conn_info(session, dst_peer_id);
            let foreign_network = self.build_foreign_network_info(session);
            return (route_infos, conn_info, foreign_network);
        }
        let route_infos = route_infos.and_then(|infos| {
            let infos = infos
                .into_iter()
                .filter(|info| info.peer_id == self.my_peer_id)
                .collect::<Vec<_>>();
            (!infos.is_empty()).then_some(infos)
        });
        (route_infos, None, None)
    }

    fn build_conn_info(
        &self,
        session: &SyncRouteSession,
        _dst_peer_id: PeerId,
    ) -> Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo> {
        let mut conn_list_estimated_size = 0;
        self.build_conn_peer_list(session, &mut conn_list_estimated_size)
            .map(Into::into)
    }

    async fn clear_expired_peer(&self) {
        let now = SystemTime::now();
        let route_snapshot = self.forwarding_snapshot();
        let mut to_remove = Vec::new();
        for (peer_id, peer_info) in self.synced_route_info.peer_infos.read().iter() {
            let Some(last_update) = peer_info
                .last_update
                .and_then(|timestamp| SystemTime::try_from(timestamp).ok())
            else {
                tracing::warn!(
                    peer_id,
                    "remove route info with a missing or invalid last_update timestamp"
                );
                to_remove.push(*peer_id);
                continue;
            };

            if let Ok(d) = now.duration_since(last_update)
                && (d > REMOVE_DEAD_PEER_INFO_AFTER
                    || (d > REMOVE_UNREACHABLE_PEER_INFO_AFTER
                        && !route_snapshot.route_table.topology_peer_reachable(*peer_id)))
            {
                to_remove.push(*peer_id);
            }
        }

        self.synced_route_info
            .remove_peers(to_remove.iter().copied());

        // clear expired foreign network info
        let mut to_remove = Vec::new();
        for item in self.synced_route_info.foreign_network.iter() {
            let Some(since_last_update) = item
                .value()
                .last_update
                .and_then(|x| SystemTime::try_from(x).ok())
                .and_then(|x| now.duration_since(x).ok())
            else {
                to_remove.push(item.key().clone());
                continue;
            };

            if since_last_update > REMOVE_DEAD_PEER_INFO_AFTER {
                to_remove.push(item.key().clone());
            }
        }

        for p in to_remove.iter() {
            self.synced_route_info.foreign_network.remove(p);
        }

        self.refresh_credential_trusts_and_disconnect().await;
    }

    fn build_sync_route_raw_req(
        req: &SyncRouteInfoRequest,
        raw_peer_infos: &DashMap<PeerId, DynamicMessage>,
    ) -> DynamicMessage {
        use prost_reflect::Value;

        let mut req_dynamic_msg = DynamicMessage::new(SyncRouteInfoRequest::default().descriptor());
        req_dynamic_msg.transcode_from(req).unwrap();

        let peer_infos = req.peer_infos.as_ref().map(|x| &x.items);
        if let Some(peer_infos) = peer_infos {
            let mut peer_info_raws = Vec::new();
            for peer_info in peer_infos.iter() {
                if let Some(info) = raw_peer_infos.get(&peer_info.peer_id) {
                    peer_info_raws.push(Value::Message(info.clone()));
                } else {
                    let mut p = DynamicMessage::new(RoutePeerInfo::default().descriptor());
                    p.transcode_from(peer_info).unwrap();
                    peer_info_raws.push(Value::Message(p));
                }
            }

            let mut peer_infos = DynamicMessage::new(RoutePeerInfos::default().descriptor());
            peer_infos.set_field_by_name("items", Value::List(peer_info_raws));

            req_dynamic_msg.set_field_by_name("peer_infos", Value::Message(peer_infos));
        }

        req_dynamic_msg
    }

    async fn sync_route_with_peer(
        &self,
        dst_peer_id: PeerId,
        peer_rpc: Arc<PeerRpcManager>,
        sync_as_initiator: bool,
    ) -> bool {
        let destination_identity_type = {
            let interface = self.interface.lock().await.as_ref().cloned();
            match interface {
                Some(interface) => interface.get_peer_identity_type(dst_peer_id).await,
                None => None,
            }
        };
        let Some(session) = self.get_session(dst_peer_id) else {
            // if session not exist, exit the sync loop.
            return true;
        };

        let _session_lock = session.lock.lock();

        let my_peer_id = self.my_peer_id;

        let next_last_sync_succ_timestamp =
            self.synced_route_info.get_next_last_sync_succ_timestamp();
        let (peer_infos, conn_info, foreign_network) =
            self.build_sync_request(&session, dst_peer_id, destination_identity_type);
        if peer_infos.is_none()
            && conn_info.is_none()
            && foreign_network.is_none()
            && !session.need_sync_initiator_info.load(Ordering::Relaxed)
            && !(sync_as_initiator && session.we_are_initiator.load(Ordering::Relaxed))
        {
            return true;
        }

        tracing::debug!(
            ?foreign_network,
            "sync_route request need send to peer. my_id {:?}, dst_peer_id: {:?}, peer_infos: {:?}, conn_info: {:?}, synced_route_info: {:?} session: {:?}",
            my_peer_id,
            dst_peer_id,
            peer_infos,
            conn_info,
            self.synced_route_info,
            session
        );

        session
            .need_sync_initiator_info
            .store(false, Ordering::Relaxed);

        let rpc_stub = peer_rpc
            .rpc_client()
            .scoped_client::<OspfRouteRpcClientFactory<BaseController>>(
                self.my_peer_id,
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

        let sync_route_info_req = SyncRouteInfoRequest {
            my_peer_id,
            my_session_id: session.my_session_id.load(Ordering::Relaxed),
            is_initiator: session.we_are_initiator.load(Ordering::Relaxed),
            peer_infos: peer_infos.clone().map(|x| RoutePeerInfos { items: x }),
            conn_info: conn_info.clone(),
            foreign_network_infos: foreign_network.clone(),
        };

        let mut ctrl = BaseController::default();
        ctrl.set_timeout_ms(3000);
        ctrl.set_raw_input(
            Self::build_sync_route_raw_req(
                &sync_route_info_req,
                &self.synced_route_info.raw_peer_infos,
            )
            .encode_to_vec()
            .into(),
        );

        drop(_session_lock);
        let ret = rpc_stub
            .sync_route_info(ctrl, SyncRouteInfoRequest::default())
            .await;
        let _session_lock = session.lock.lock();

        tracing::debug!(
            "sync_route_info resp: {:?}, req: {:?}, session: {:?}, my_info: {:?}, next_last_sync_succ_timestamp: {:?}",
            ret,
            sync_route_info_req,
            session,
            self.global_ctx.network,
            next_last_sync_succ_timestamp
        );

        match ret.as_ref() {
            Err(e) => {
                tracing::error!(
                    ?ret,
                    ?my_peer_id,
                    ?dst_peer_id,
                    ?e,
                    "sync_route_info failed"
                );
                session
                    .need_sync_initiator_info
                    .store(true, Ordering::Relaxed);
            }
            Ok(resp) => {
                if let Some(err) = resp.error {
                    if err == Error::DuplicatePeerId as i32 {
                        if !self.global_ctx.get_feature_flags().is_public_server {
                            panic!("duplicate peer id");
                        }
                    } else {
                        tracing::error!(?ret, ?my_peer_id, ?dst_peer_id, "sync_route_info failed");
                        session
                            .need_sync_initiator_info
                            .store(true, Ordering::Relaxed);
                    }
                } else {
                    session.rpc_tx_count.fetch_add(1, Ordering::Relaxed);

                    session
                        .dst_is_initiator
                        .store(resp.is_initiator, Ordering::Relaxed);

                    session.update_dst_session_id(resp.session_id);

                    if let Some(peer_infos) = &peer_infos {
                        session.update_dst_saved_peer_info_version(peer_infos, dst_peer_id);
                    }

                    if let Some(conn_info) = &conn_info {
                        session.update_dst_saved_conn_info_version(conn_info, dst_peer_id);
                    }

                    if let Some(foreign_network) = &foreign_network {
                        session
                            .update_dst_saved_foreign_network_version(foreign_network, dst_peer_id);
                    }
                    session.update_last_sync_succ_timestamp(next_last_sync_succ_timestamp);
                }
            }
        }
        false
    }

    fn update_peer_info_last_update(&self) {
        tracing::debug!(
            "update_peer_info_last_update, my_peer_id: {:?}, prev: {:?}, new: {:?}",
            self.my_peer_id,
            self.peer_info_last_update.load(),
            Instant::now()
        );
        self.peer_info_last_update.store(Instant::now());
    }

    fn get_peer_info_last_update(&self) -> Instant {
        self.peer_info_last_update.load()
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.synced_route_info
            .group_trust_map_cache
            .get(&peer_id)
            .map(|groups| groups.value().clone())
            .unwrap_or_default()
    }

    fn clean_dst_saved_map(&self, dst_peer_id: PeerId) {
        let Some(session) = self.get_session(dst_peer_id) else {
            return;
        };

        session.clean_dst_saved_map();
    }
}

impl Drop for PeerRouteServiceImpl {
    fn drop(&mut self) {
        tracing::debug!(?self, "drop PeerRouteServiceImpl");
    }
}

#[derive(Clone)]
struct RouteSessionManager {
    service_impl: Weak<PeerRouteServiceImpl>,
    peer_rpc: Weak<PeerRpcManager>,

    sync_now_broadcast: tokio::sync::broadcast::Sender<()>,
}

impl Debug for RouteSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteSessionManager")
            .field("dump_sessions", &self.dump_sessions())
            .finish()
    }
}

fn read_wire_varint(input: &[u8], cursor: &mut usize) -> rpc_types::error::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *input.get(*cursor).ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization raw request has a truncated varint".to_string(),
            )
        })?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization raw request varint overflows u64".to_string(),
            ));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(rpc_types::error::Error::MalformatRpcPacket(
        "route synchronization raw request has an oversized varint".to_string(),
    ))
}

fn skip_wire_value(
    input: &[u8],
    cursor: &mut usize,
    wire_type: u64,
) -> rpc_types::error::Result<()> {
    match wire_type {
        0 => {
            read_wire_varint(input, cursor)?;
        }
        1 => {
            *cursor = (*cursor).checked_add(8).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization raw request offset overflow".to_string(),
                )
            })?;
        }
        2 => {
            let length = usize::try_from(read_wire_varint(input, cursor)?).map_err(|_| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization raw request length is too large".to_string(),
                )
            })?;
            *cursor = (*cursor).checked_add(length).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization raw request offset overflow".to_string(),
                )
            })?;
        }
        5 => {
            *cursor = (*cursor).checked_add(4).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization raw request offset overflow".to_string(),
                )
            })?;
        }
        _ => {
            return Err(rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization raw request has an unsupported wire type".to_string(),
            ));
        }
    }
    if *cursor > input.len() {
        return Err(rpc_types::error::Error::MalformatRpcPacket(
            "route synchronization raw request has a truncated field".to_string(),
        ));
    }
    Ok(())
}

fn get_raw_peer_infos(input: &[u8]) -> rpc_types::error::Result<Vec<DynamicMessage>> {
    if input.len() > MAX_ROUTE_SYNC_RAW_REQUEST_BYTES {
        return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
            "route synchronization raw request is too large: {}",
            input.len()
        )));
    }

    let mut cursor = 0usize;
    let mut peer_info_bytes = 0usize;
    let mut raw_peer_infos = Vec::new();
    while cursor < input.len() {
        let key = read_wire_varint(input, &mut cursor)?;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 4 && wire_type == 2 {
            let length = usize::try_from(read_wire_varint(input, &mut cursor)?).map_err(|_| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization peer-info container is too large".to_string(),
                )
            })?;
            let end = cursor.checked_add(length).ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization peer-info container offset overflow".to_string(),
                )
            })?;
            if end > input.len() {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization peer-info container is truncated".to_string(),
                ));
            }

            let mut nested = cursor;
            while nested < end {
                let nested_key = read_wire_varint(input, &mut nested)?;
                let nested_field = nested_key >> 3;
                let nested_wire = nested_key & 0x07;
                if nested_field == 1 && nested_wire == 2 {
                    let item_length = usize::try_from(read_wire_varint(input, &mut nested)?)
                        .map_err(|_| {
                            rpc_types::error::Error::MalformatRpcPacket(
                                "route synchronization peer info is too large".to_string(),
                            )
                        })?;
                    if item_length > MAX_ROUTE_SYNC_RAW_PEER_INFO_BYTES {
                        return Err(rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization peer info exceeds the raw size budget"
                                .to_string(),
                        ));
                    }
                    peer_info_bytes =
                        peer_info_bytes.checked_add(item_length).ok_or_else(|| {
                            rpc_types::error::Error::MalformatRpcPacket(
                                "route synchronization raw peer-info size overflow".to_string(),
                            )
                        })?;
                    if peer_info_bytes > MAX_ROUTE_SYNC_CREDENTIAL_BYTES_PER_REQUEST {
                        return Err(rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization raw peer-info data is too large".to_string(),
                        ));
                    }
                    nested = nested.checked_add(item_length).ok_or_else(|| {
                        rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization raw peer-info offset overflow".to_string(),
                        )
                    })?;
                    if nested > end {
                        return Err(rpc_types::error::Error::MalformatRpcPacket(
                            "route synchronization raw peer info is truncated".to_string(),
                        ));
                    }
                    let item_start = nested - item_length;
                    let raw = DynamicMessage::decode(
                        RoutePeerInfo::default().descriptor(),
                        &input[item_start..nested],
                    )
                    .map_err(|error| {
                        rpc_types::error::Error::MalformatRpcPacket(format!(
                            "route synchronization raw peer info decode failed: {error}"
                        ))
                    })?;
                    raw_peer_infos.push(raw);
                    continue;
                }
                skip_wire_value(input, &mut nested, nested_wire)?;
            }
            if nested != end {
                return Err(rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization peer-info container has a malformed field".to_string(),
                ));
            }
            cursor = end;
        } else {
            skip_wire_value(input, &mut cursor, wire_type)?;
        }
    }
    Ok(raw_peer_infos)
}

#[derive(Clone, Debug, Default)]
struct RouteSyncValidationProof {
    credential: Option<TrustedCredentialPubkey>,
}

#[async_trait::async_trait]
impl OspfRouteRpc for RouteSessionManager {
    type Controller = BaseController;
    async fn sync_route_info(
        &self,
        ctrl: BaseController,
        request: SyncRouteInfoRequest,
    ) -> Result<SyncRouteInfoResponse, rpc_types::error::Error> {
        let from_peer_id = request.my_peer_id;
        let authenticated_peer_id = ctrl.authenticated_peer_id().ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket(
                "route synchronization requires an authenticated peer".to_string(),
            )
        })?;
        if authenticated_peer_id != from_peer_id {
            return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                "route synchronization peer mismatch: authenticated {authenticated_peer_id}, claimed {from_peer_id}"
            )));
        }
        let authenticated_peer_identity_type =
            ctrl.authenticated_peer_identity_type().ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization requires an authenticated peer role".to_string(),
                )
            })?;
        let from_session_id = request.my_session_id;
        let is_initiator = request.is_initiator;
        let peer_infos = request.peer_infos.map(|x| x.items);
        let conn_info = request.conn_info;
        let foreign_network = request.foreign_network_infos;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(i64::MAX);
        let credential_info = if matches!(
            authenticated_peer_identity_type,
            PeerIdentityType::Credential
        ) {
            let service_impl = self
                .service_impl
                .upgrade()
                .ok_or_else(|| rpc_types::error::Error::Shutdown)?;
            service_impl
                .get_peer_public_key_from_interface(from_peer_id)
                .await
                .and_then(|pubkey| {
                    service_impl
                        .synced_route_info
                        .get_credential_info_by_pubkey(&pubkey)
                })
                .filter(|credential| {
                    credential_is_current(
                        credential,
                        service_impl.global_ctx.get_credential_manager(),
                        now_unix,
                    )
                })
        } else {
            None
        };
        validate_route_sync_role_shape(
            from_peer_id,
            authenticated_peer_identity_type,
            peer_infos.as_deref(),
            conn_info.as_ref(),
            foreign_network.as_ref(),
        )?;
        if let Some(peer_infos) = peer_infos.as_deref() {
            validate_route_peer_infos(peer_infos)?;
        }
        if let Some(conn_info) = conn_info.as_ref() {
            validate_route_conn_info(conn_info)?;
        }
        if let Some(foreign_network) = foreign_network.as_ref() {
            validate_route_foreign_network_info(foreign_network)?;
        }
        let raw_peer_infos = if let Some(peer_infos_ref) = &peer_infos {
            let raw_input = ctrl.get_raw_input().ok_or_else(|| {
                rpc_types::error::Error::MalformatRpcPacket(
                    "route synchronization request has no raw input".to_string(),
                )
            })?;
            let r = get_raw_peer_infos(raw_input.as_ref())?;
            if r.len() != peer_infos_ref.len() {
                return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                    "route synchronization peer info count mismatch: decoded {}, request {}",
                    r.len(),
                    peer_infos_ref.len()
                )));
            }
            for (index, (raw, typed)) in r.iter().zip(peer_infos_ref).enumerate() {
                let Some(raw_peer_id) = raw
                    .get_field_by_name("peer_id")
                    .and_then(|field| field.as_u32())
                else {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization raw peer info {index} has no valid peer_id"
                    )));
                };
                if raw_peer_id != typed.peer_id {
                    return Err(rpc_types::error::Error::MalformatRpcPacket(format!(
                        "route synchronization raw peer id {raw_peer_id} does not match typed peer id {}",
                        typed.peer_id
                    )));
                }
            }
            Some(r)
        } else {
            None
        };

        let ret = self
            .do_sync_route_info_validated(
                from_peer_id,
                from_session_id,
                is_initiator,
                peer_infos,
                raw_peer_infos,
                conn_info,
                foreign_network,
                authenticated_peer_identity_type,
                RouteSyncValidationProof {
                    credential: credential_info,
                },
            )
            .await;

        Ok(match ret {
            Ok(v) => v,
            Err(e) => SyncRouteInfoResponse {
                error: Some(e as i32),
                ..Default::default()
            },
        })
    }
}

impl RouteSessionManager {
    fn new(service_impl: Arc<PeerRouteServiceImpl>, peer_rpc: Arc<PeerRpcManager>) -> Self {
        RouteSessionManager {
            service_impl: Arc::downgrade(&service_impl),
            peer_rpc: Arc::downgrade(&peer_rpc),

            sync_now_broadcast: tokio::sync::broadcast::channel(100).0,
        }
    }

    async fn session_task(
        peer_rpc: Weak<PeerRpcManager>,
        service_impl: Weak<PeerRouteServiceImpl>,
        dst_peer_id: PeerId,
        mut sync_now: tokio::sync::broadcast::Receiver<()>,
    ) {
        const RETRY_BASE_MS: u64 = 50;
        const RETRY_MAX_MS: u64 = 5000;

        let mut last_sync = Instant::now();
        let mut last_clean_dst_saved_map = Instant::now();
        // Keep retry_delay_ms across outer iterations so that rapid
        // connect/disconnect flaps don't fully reset the backoff.
        let mut retry_delay_ms = RETRY_BASE_MS;
        loop {
            loop {
                let Some(service_impl) = service_impl.clone().upgrade() else {
                    return;
                };

                let Some(peer_rpc) = peer_rpc.clone().upgrade() else {
                    return;
                };

                // if we are initiator, we should ensure the dst has the session.
                let sync_as_initiator = if last_sync.elapsed().as_secs() > 10 {
                    last_sync = Instant::now();
                    true
                } else {
                    false
                };

                if service_impl
                    .sync_route_with_peer(dst_peer_id, peer_rpc.clone(), sync_as_initiator)
                    .await
                {
                    if last_clean_dst_saved_map.elapsed().as_secs() > 60 {
                        last_clean_dst_saved_map = Instant::now();
                        service_impl.clean_dst_saved_map(dst_peer_id);
                    }
                    // Successful sync: decay backoff towards base so the next
                    // real failure still starts at a reasonable level, but
                    // don't fully reset to avoid 50ms bursts during flapping.
                    retry_delay_ms = (retry_delay_ms / 2).max(RETRY_BASE_MS);
                    break;
                }

                drop(service_impl);
                drop(peer_rpc);

                tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
                retry_delay_ms = (retry_delay_ms * 2).min(RETRY_MAX_MS);
            }

            sync_now = sync_now.resubscribe();

            select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                ret = sync_now.recv() => if let Err(e) = ret {
                    tracing::debug!(?e, "session_task sync_now recv failed, ospf route may exit");
                    break;
                }
            }
        }
    }

    fn stop_session(&self, peer_id: PeerId) -> Result<(), Error> {
        tracing::warn!(?peer_id, "stop ospf sync session");
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };
        service_impl.remove_session(peer_id);
        Ok(())
    }

    fn start_session_task(&self, session: &SyncRouteSession) {
        if !session.task.is_running() {
            session.task.set_task(tokio::spawn(Self::session_task(
                self.peer_rpc.clone(),
                self.service_impl.clone(),
                session.dst_peer_id,
                self.sync_now_broadcast.subscribe(),
            )));
        }
    }

    fn get_or_start_session(&self, peer_id: PeerId) -> Result<Arc<SyncRouteSession>, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        tracing::info!(?service_impl.my_peer_id, ?peer_id, "start ospf sync session");

        let session = service_impl.get_or_create_session(peer_id);
        self.start_session_task(&session);
        Ok(session)
    }

    async fn maintain_sessions(&self, service_impl: Arc<PeerRouteServiceImpl>) -> bool {
        let mut cur_dst_peer_id_to_initiate = None;
        let mut next_sleep_ms = 0;
        loop {
            let mut recv = self.sync_now_broadcast.subscribe();
            select! {
                _ = tokio::time::sleep(Duration::from_millis(next_sleep_ms)) => {}
                _ = recv.recv() => {}
            }

            let interface_snapshot = service_impl.interface_peer_snapshot().await;
            let peers = &interface_snapshot.peers;
            let authentication_update = if service_impl
                .applied_interface_peers_generation
                .load(Ordering::Acquire)
                != interface_snapshot.generation
            {
                let update =
                    service_impl.apply_authenticated_interface_snapshot(&interface_snapshot);
                service_impl
                    .applied_interface_peers_generation
                    .store(interface_snapshot.generation, Ordering::Release);
                if update.changed {
                    service_impl.update_route_table_and_cached_local_conn_bitmap();
                }
                update
            } else {
                AuthenticatedPeerSnapshotUpdate::default()
            };
            let session_peers = self.list_session_peer_set();
            for peer_id in session_peers.iter() {
                if !peers.contains(peer_id) {
                    if Some(*peer_id) == cur_dst_peer_id_to_initiate {
                        cur_dst_peer_id_to_initiate = None;
                    }
                    let _ = self.stop_session(*peer_id);
                }
            }

            // find peer_ids that are not initiators.
            let mut initiator_candidates = Vec::new();
            for peer_id in peers.iter().copied() {
                // Step 9a: Filter OSPF session candidates based on direct auth level.
                // - Credential nodes only initiate sessions to admin nodes (not other credential nodes)
                // - Admin nodes don't initiate sessions to credential nodes
                let Some(evidence) = interface_snapshot.authenticated.get(&peer_id) else {
                    service_impl.mark_interface_peers_dirty();
                    tracing::warn!(peer_id, "route session skipped missing peer evidence");
                    continue;
                };
                let Some(identity_type) = evidence.identity_type else {
                    service_impl.mark_interface_peers_dirty();
                    tracing::warn!(
                        peer_id,
                        "route session skipped an unknown peer identity type"
                    );
                    continue;
                };
                let Some(public_key) = evidence.public_key.as_ref() else {
                    service_impl.mark_interface_peers_dirty();
                    tracing::warn!(peer_id, "route session skipped a peer without a public key");
                    continue;
                };
                let secure_auth_level = evidence
                    .secure_auth_level
                    .unwrap_or(SecureAuthLevel::EncryptedUnauthenticated);
                let Some(authenticated) = service_impl.authenticated_peers.get(&peer_id) else {
                    tracing::warn!(peer_id, "route session skipped unauthenticated peer");
                    continue;
                };
                if authenticated.identity_type != identity_type
                    || authenticated.public_key != *public_key
                    || authenticated.secure_auth_level != secure_auth_level
                {
                    tracing::warn!(
                        peer_id,
                        "route session rejected conflicting peer authentication"
                    );
                    continue;
                }
                if authentication_update.conflicts.contains(&peer_id) {
                    tracing::warn!(
                        peer_id,
                        "route session rejected conflicting peer authentication"
                    );
                    continue;
                }
                if matches!(identity_type, PeerIdentityType::Credential) {
                    continue;
                }

                let Some(session) = service_impl.get_session(peer_id) else {
                    initiator_candidates.push(peer_id);
                    continue;
                };

                if !session.dst_is_initiator.load(Ordering::Relaxed) {
                    initiator_candidates.push(peer_id);
                }
            }

            if initiator_candidates.is_empty() {
                next_sleep_ms = 1000;
                continue;
            }

            let mut new_initiator_dst = None;
            // if any peer has NoPAT or OpenInternet stun type, we should use it.
            let route_snapshot = service_impl.forwarding_snapshot();
            for peer_id in initiator_candidates.iter() {
                let Some(nat_type) = route_snapshot.route_table.get_udp_nat_type(*peer_id) else {
                    continue;
                };
                if nat_type == NatType::NoPat || nat_type == NatType::OpenInternet {
                    new_initiator_dst = Some(*peer_id);
                    break;
                }
            }
            if new_initiator_dst.is_none() {
                new_initiator_dst = Some(*initiator_candidates.first().unwrap());
            }

            if new_initiator_dst != cur_dst_peer_id_to_initiate {
                tracing::warn!(
                    "new_initiator: {:?}, prev: {:?}, my_id: {:?}",
                    new_initiator_dst,
                    cur_dst_peer_id_to_initiate,
                    service_impl.my_peer_id
                );
                // update initiator flag for previous session
                if let Some(cur_peer_id_to_initiate) = cur_dst_peer_id_to_initiate
                    && let Some(session) = service_impl.get_session(cur_peer_id_to_initiate)
                {
                    session.update_initiator_flag(false);
                }

                cur_dst_peer_id_to_initiate = new_initiator_dst;
                // update initiator flag for new session
                let Ok(session) = self.get_or_start_session(new_initiator_dst.unwrap()) else {
                    tracing::warn!("get_or_start_session failed");
                    continue;
                };
                session.update_initiator_flag(true);
                self.sync_now("update_initiator_flag");
            }

            // clear sessions that are neither dst_initiator or we_are_initiator.
            for peer_id in session_peers.iter() {
                if let Some(session) = service_impl.get_session(*peer_id) {
                    if (session.dst_is_initiator.load(Ordering::Relaxed)
                        || session.we_are_initiator.load(Ordering::Relaxed)
                        || session.need_sync_initiator_info.load(Ordering::Relaxed))
                        && session.task.is_running()
                    {
                        continue;
                    }
                    let _ = self.stop_session(*peer_id);
                }
            }

            next_sleep_ms = 1000;
        }
    }

    fn list_session_peers(&self) -> Vec<PeerId> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return vec![];
        };

        service_impl.list_session_peers()
    }

    fn list_session_peer_set(&self) -> BTreeSet<PeerId> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return BTreeSet::new();
        };

        service_impl.list_session_peers().into_iter().collect()
    }

    fn dump_sessions(&self) -> Result<String, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        let mut ret = format!("my_peer_id: {:?}\n", service_impl.my_peer_id);
        for item in service_impl.sessions.iter() {
            ret += format!(
                "    session: {}, {}\n",
                item.key(),
                item.value().short_debug_string()
            )
            .as_str();
        }

        Ok(ret.to_string())
    }

    fn sync_now(&self, reason: &str) {
        let ret = self.sync_now_broadcast.send(());
        tracing::debug!(?ret, ?reason, "sync_now_broadcast.send");
    }

    fn extract_credential_peer_info(
        &self,
        from_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
        credential: &TrustedCredentialPubkey,
    ) -> Option<(RoutePeerInfo, DynamicMessage)> {
        let info_idx = peer_infos.iter().position(|p| p.peer_id == from_peer_id)?;
        if credential.pubkey.len() != 32 {
            return None;
        }
        let mut info = peer_infos[info_idx].clone();
        let mut raw_info = raw_peer_infos[info_idx].clone();
        // The authenticated credential key is the route identity. Do not
        // retain a different key claimed by the route sender.
        info.noise_static_pubkey = credential.pubkey.clone();
        // Credential peers cannot delegate trust to another credential.
        info.trusted_credential_pubkeys.clear();
        let allowed_cidrs = &credential.allowed_proxy_cidrs;
        // Filter proxy_cidrs to only those allowed by credential
        if !allowed_cidrs.is_empty() {
            info.proxy_cidrs.retain(|cidr| {
                allowed_cidrs
                    .iter()
                    .any(|allowed| cidr_is_subset_str(cidr, allowed))
            });
        } else {
            // No allowed_proxy_cidrs → no proxy_cidrs allowed
            info.proxy_cidrs.clear();
        }
        SyncedRouteInfo::set_peer_identity(&mut info, PeerIdentityType::Credential);
        SyncedRouteInfo::sanitize_untrusted_role_capabilities(
            &mut info,
            PeerIdentityType::Credential,
        );
        patch_raw_from_info(
            &mut raw_info,
            &info,
            &[
                "proxy_cidrs",
                "feature_flag",
                "identity_type",
                "noise_static_pubkey",
                "trusted_credential_pubkeys",
            ],
        );
        Some((info, raw_info))
    }

    fn extract_shared_node_peer_info(
        &self,
        from_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
    ) -> Option<(RoutePeerInfo, DynamicMessage)> {
        let info_idx = peer_infos.iter().position(|p| p.peer_id == from_peer_id)?;
        let mut info = peer_infos[info_idx].clone();
        let mut raw_info = raw_peer_infos[info_idx].clone();
        info.proxy_cidrs.clear();
        info.groups.clear();
        info.trusted_credential_pubkeys.clear();
        SyncedRouteInfo::set_peer_identity(&mut info, PeerIdentityType::SharedNode);
        SyncedRouteInfo::sanitize_untrusted_role_capabilities(
            &mut info,
            PeerIdentityType::SharedNode,
        );
        // Keep the advertised identity and feature flag in the raw carrier. The
        // local typed view above remains scoped as SharedNode, while a public
        // ForeignRelay can later forward the tenant's independently verifiable
        // Admin attestation to peers that know this network's secret.
        patch_raw_from_info(
            &mut raw_info,
            &info,
            &["proxy_cidrs", "groups", "trusted_credential_pubkeys"],
        );
        Some((info, raw_info))
    }

    fn extract_foreign_relay_peer_infos(
        &self,
        from_peer_id: PeerId,
        peer_infos: &[RoutePeerInfo],
        raw_peer_infos: &[DynamicMessage],
    ) -> (Vec<RoutePeerInfo>, Vec<DynamicMessage>) {
        peer_infos
            .iter()
            .cloned()
            .zip(raw_peer_infos.iter().cloned())
            .map(|(mut info, mut raw_info)| {
                if info.peer_id == from_peer_id {
                    info.proxy_cidrs.clear();
                    info.groups.clear();
                    info.trusted_credential_pubkeys.clear();
                    SyncedRouteInfo::set_peer_identity(&mut info, PeerIdentityType::ForeignRelay);
                    SyncedRouteInfo::sanitize_untrusted_role_capabilities(
                        &mut info,
                        PeerIdentityType::ForeignRelay,
                    );
                    patch_raw_from_info(
                        &mut raw_info,
                        &info,
                        &[
                            "proxy_cidrs",
                            "groups",
                            "trusted_credential_pubkeys",
                            "feature_flag",
                            "multicast_groups",
                            "identity_type",
                        ],
                    );
                }
                (info, raw_info)
            })
            .unzip()
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_sync_route_info(
        &self,
        from_peer_id: PeerId,
        from_session_id: SessionId,
        is_initiator: bool,
        peer_infos: Option<Vec<RoutePeerInfo>>,
        raw_peer_infos: Option<Vec<DynamicMessage>>,
        conn_info: Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo>,
        foreign_network: Option<RouteForeignNetworkInfos>,
        from_identity_type: PeerIdentityType,
    ) -> Result<SyncRouteInfoResponse, Error> {
        self.do_sync_route_info_validated(
            from_peer_id,
            from_session_id,
            is_initiator,
            peer_infos,
            raw_peer_infos,
            conn_info,
            foreign_network,
            from_identity_type,
            RouteSyncValidationProof::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_sync_route_info_validated(
        &self,
        from_peer_id: PeerId,
        from_session_id: SessionId,
        is_initiator: bool,
        peer_infos: Option<Vec<RoutePeerInfo>>,
        raw_peer_infos: Option<Vec<DynamicMessage>>,
        conn_info: Option<crate::proto::peer_rpc::sync_route_info_request::ConnInfo>,
        foreign_network: Option<RouteForeignNetworkInfos>,
        from_identity_type: PeerIdentityType,
        validation: RouteSyncValidationProof,
    ) -> Result<SyncRouteInfoResponse, Error> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Err(Error::Stopped);
        };

        let my_peer_id = service_impl.my_peer_id;
        let session = self.get_or_start_session(from_peer_id)?;
        let from_is_credential = matches!(from_identity_type, PeerIdentityType::Credential);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(i64::MAX);
        let credential_info = if from_is_credential {
            if validation.credential.is_some() {
                validation.credential
            } else {
                service_impl
                    .get_peer_public_key_from_interface(from_peer_id)
                    .await
                    .and_then(|pubkey| {
                        service_impl
                            .synced_route_info
                            .get_credential_info_by_pubkey(&pubkey)
                    })
                    .filter(|credential| {
                        credential_is_current(
                            credential,
                            service_impl.global_ctx.get_credential_manager(),
                            now_unix,
                        )
                    })
            }
        } else {
            None
        };
        if from_is_credential && credential_info.is_none() {
            // no credential found
            return Err(Error::Stopped);
        }

        let _session_lock = session.lock.lock();

        session.rpc_rx_count.fetch_add(1, Ordering::Relaxed);

        session.update_dst_session_id(from_session_id);

        let mut need_update_route_table = false;
        let mut untrusted_peers = Vec::new();

        if let Some(peer_infos) = &peer_infos {
            let Some(raw_peer_infos) = raw_peer_infos.as_deref() else {
                return Err(Error::Stopped);
            };
            let restricted_info = match from_identity_type {
                PeerIdentityType::Admin => None,
                PeerIdentityType::Credential => self
                    .extract_credential_peer_info(
                        from_peer_id,
                        peer_infos,
                        raw_peer_infos,
                        credential_info.as_ref().unwrap(),
                    )
                    .map(|(info, raw)| (vec![info], vec![raw]))
                    .or_else(|| Some((Vec::new(), Vec::new()))),
                PeerIdentityType::SharedNode => self
                    .extract_shared_node_peer_info(from_peer_id, peer_infos, raw_peer_infos)
                    .map(|(info, raw)| (vec![info], vec![raw]))
                    .or_else(|| Some((Vec::new(), Vec::new()))),
                PeerIdentityType::ForeignRelay => Some(self.extract_foreign_relay_peer_infos(
                    from_peer_id,
                    peer_infos,
                    raw_peer_infos,
                )),
            };
            let (pi, rpi) = restricted_info
                .as_ref()
                .map(|(infos, raw)| (infos.as_slice(), raw.as_slice()))
                .unwrap_or((peer_infos.as_slice(), raw_peer_infos));
            let accept_conn_info = match from_identity_type {
                PeerIdentityType::Admin | PeerIdentityType::ForeignRelay => true,
                PeerIdentityType::Credential | PeerIdentityType::SharedNode => false,
            };
            let foreign_relay_overwrite =
                matches!(from_identity_type, PeerIdentityType::ForeignRelay)
                    && pi.iter().any(|info| {
                        info.peer_id == my_peer_id
                            || (info.peer_id != from_peer_id
                                && service_impl.authenticated_peers.contains_key(&info.peer_id))
                    });
            if foreign_relay_overwrite {
                tracing::warn!(
                    from_peer_id,
                    "foreign relay attempted to overwrite an authenticated local peer"
                );
                need_update_route_table |= service_impl
                    .synced_route_info
                    .update_peer_infos_and_conn_info_with_authority(
                        my_peer_id,
                        service_impl.my_peer_route_id,
                        from_peer_id,
                        &[],
                        &[],
                        None,
                        false,
                    )?;
            } else {
                let topology_changed = service_impl
                    .synced_route_info
                    .update_peer_infos_and_conn_info_with_authority(
                        my_peer_id,
                        service_impl.my_peer_route_id,
                        from_peer_id,
                        pi,
                        rpi,
                        accept_conn_info.then_some(conn_info.as_ref()).flatten(),
                        accept_conn_info,
                    )?;
                if !pi.is_empty() {
                    let trust_admin_groups_without_proof = service_impl
                        .global_ctx
                        .get_network_identity()
                        .network_secret
                        .is_none();
                    service_impl
                        .synced_route_info
                        .verify_and_update_group_trusts(
                            pi,
                            &service_impl.global_ctx.get_acl_group_declarations(),
                            trust_admin_groups_without_proof,
                        );
                    session.update_dst_saved_peer_info_version(pi, from_peer_id);
                }
                if accept_conn_info && let Some(conn_info) = conn_info.as_ref() {
                    session.update_dst_saved_conn_info_version(conn_info, from_peer_id);
                }
                need_update_route_table |= topology_changed;
            }
        } else if let Some(conn_info) = &conn_info {
            let accept_conn_info = match from_identity_type {
                PeerIdentityType::Admin | PeerIdentityType::ForeignRelay => true,
                PeerIdentityType::Credential | PeerIdentityType::SharedNode => false,
            };
            let topology_changed = service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info_with_authority(
                    my_peer_id,
                    service_impl.my_peer_route_id,
                    from_peer_id,
                    &[],
                    &[],
                    accept_conn_info.then_some(conn_info),
                    accept_conn_info,
                )?;
            if accept_conn_info {
                session.update_dst_saved_conn_info_version(conn_info, from_peer_id);
            }
            need_update_route_table |= topology_changed;
        } else if !matches!(from_identity_type, PeerIdentityType::Admin) {
            need_update_route_table |= service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info_with_authority(
                    my_peer_id,
                    service_impl.my_peer_route_id,
                    from_peer_id,
                    &[],
                    &[],
                    None,
                    false,
                )?;
        }

        if need_update_route_table {
            untrusted_peers = service_impl.refresh_credential_trusts_with_current_topology();
        }

        let mut foreign_network_changed = false;
        if let Some(foreign_network) = &foreign_network {
            if matches!(from_identity_type, PeerIdentityType::Admin) {
                foreign_network_changed = service_impl
                    .synced_route_info
                    .update_foreign_network(foreign_network);
                session.update_dst_saved_foreign_network_version(foreign_network, from_peer_id);
            }
        }

        if foreign_network_changed && !need_update_route_table {
            service_impl.request_route_rebuild(RouteRebuildDomains::foreign());
        }

        tracing::debug!(
            from_peer_id,
            is_initiator,
            peer_info_count = peer_infos.as_ref().map_or(0, Vec::len),
            has_connection_info = conn_info.is_some(),
            route_version = service_impl.synced_route_info.version.get(),
            "handled route synchronization"
        );

        session
            .dst_is_initiator
            .store(is_initiator, Ordering::Relaxed);
        let is_initiator = session.we_are_initiator.load(Ordering::Relaxed);
        let session_id = session.my_session_id.load(Ordering::Relaxed);

        drop(_session_lock);
        service_impl
            .disconnect_untrusted_peers(&untrusted_peers)
            .await;

        // Only trigger reverse sync when we actually received new data that
        // needs to be propagated to other peers.  Previously this was
        // unconditional, which created an A→B→A→B ping-pong storm even when
        // there was nothing new to propagate.
        if need_update_route_table || foreign_network_changed {
            self.sync_now("sync_route_info");
        }

        Ok(SyncRouteInfoResponse {
            is_initiator,
            session_id,
            error: None,
        })
    }
}

struct OspfPublicIpv6RouteHandle {
    service_impl: Weak<PeerRouteServiceImpl>,
}

impl PublicIpv6RouteControl for OspfPublicIpv6RouteHandle {
    fn my_peer_id(&self) -> PeerId {
        self.service_impl
            .upgrade()
            .map(|service_impl| service_impl.my_peer_id)
            .unwrap_or_default()
    }

    fn peer_route_snapshot(&self) -> Vec<PublicIpv6PeerRouteInfo> {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return Vec::new();
        };

        let snapshot = service_impl.forwarding_snapshot();
        service_impl
            .synced_route_info
            .peer_infos
            .read()
            .iter()
            .map(|(peer_id, info)| PublicIpv6PeerRouteInfo {
                peer_id: *peer_id,
                inst_id: route_peer_inst_id(info),
                is_provider: info
                    .feature_flag
                    .as_ref()
                    .map(|flags| flags.ipv6_public_addr_provider)
                    .unwrap_or(false),
                prefix: info
                    .ipv6_public_addr_prefix
                    .map(Into::into)
                    .map(|prefix: Ipv6Inet| prefix.network()),
                lease: info.ipv6_public_addr_lease.map(Into::into),
                reachable: *peer_id == service_impl.my_peer_id
                    || snapshot.route_table.peer_reachable(*peer_id),
            })
            .collect()
    }

    fn publish_self_public_ipv6_lease(&self, lease: Option<Ipv6Inet>) -> bool {
        let Some(service_impl) = self.service_impl.upgrade() else {
            return false;
        };

        let mut current = service_impl.self_public_ipv6_addr_lease.lock().unwrap();
        if *current == lease {
            return false;
        }
        *current = lease;
        drop(current);

        let changed = service_impl.update_my_peer_info();
        if changed {
            service_impl.update_route_table_and_cached_local_conn_bitmap();
        }
        changed
    }
}

#[derive(Clone)]
struct OspfPublicIpv6SyncTrigger {
    session_mgr: RouteSessionManager,
}

impl PublicIpv6SyncTrigger for OspfPublicIpv6SyncTrigger {
    fn sync_now(&self, reason: &str) {
        self.session_mgr.sync_now(reason);
    }
}

pub struct PeerRoute {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    peer_rpc: Weak<PeerRpcManager>,

    service_impl: Arc<PeerRouteServiceImpl>,
    public_ipv6_service: Arc<PublicIpv6Service>,
    session_mgr: RouteSessionManager,

    tasks: std::sync::Mutex<JoinSet<()>>,
}

impl Debug for PeerRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRoute")
            .field("my_peer_id", &self.my_peer_id)
            .field("service_impl", &self.service_impl)
            .field("session_mgr", &self.session_mgr)
            .finish()
    }
}

impl PeerRoute {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        peer_rpc: Arc<PeerRpcManager>,
    ) -> Arc<Self> {
        let service_impl = Arc::new(PeerRouteServiceImpl::new(my_peer_id, global_ctx.clone()));
        let session_mgr = RouteSessionManager::new(service_impl.clone(), peer_rpc.clone());
        let public_ipv6_service = Arc::new(PublicIpv6Service::new(
            global_ctx.clone(),
            Arc::downgrade(&peer_rpc),
            Arc::new(OspfPublicIpv6RouteHandle {
                service_impl: Arc::downgrade(&service_impl),
            }),
            Arc::new(OspfPublicIpv6SyncTrigger {
                session_mgr: session_mgr.clone(),
            }),
        ));
        service_impl.set_public_ipv6_service(Arc::downgrade(&public_ipv6_service));

        Arc::new(PeerRoute {
            my_peer_id,
            global_ctx,
            peer_rpc: Arc::downgrade(&peer_rpc),

            service_impl,
            public_ipv6_service,
            session_mgr,

            tasks: std::sync::Mutex::new(JoinSet::new()),
        })
    }

    async fn clear_expired_peer(service_impl: Arc<PeerRouteServiceImpl>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            service_impl.clear_expired_peer().await;
            // TODO: use debug log level for this.
            tracing::debug!(?service_impl, "clear_expired_peer");
        }
    }

    async fn maintain_session_tasks(
        session_mgr: RouteSessionManager,
        service_impl: Arc<PeerRouteServiceImpl>,
    ) {
        session_mgr.maintain_sessions(service_impl).await;
    }

    async fn update_my_peer_info_routine(
        service_impl: Arc<PeerRouteServiceImpl>,
        session_mgr: RouteSessionManager,
    ) {
        let mut global_event_receiver = service_impl.global_ctx.subscribe();
        service_impl.mark_interface_peers_dirty();
        loop {
            if service_impl.expire_verified_bridge_attestations() {
                service_impl.rebuild_domains(RouteRebuildDomains::bridge());
            }

            if service_impl.update_my_infos().await {
                session_mgr.sync_now("update_my_infos");
            }

            let measurement_domains = service_impl.cost_calculator_update_domains();
            if measurement_domains.needs_publication() {
                tracing::debug!(?measurement_domains, "route measurements need an update");
                service_impl.rebuild_domains(measurement_domains);
            }

            let bridge_attestation_sleep = service_impl.bridge_attestation_sleep_duration();
            let update_sleep = service_impl
                .cost_calculator_next_update_in()
                .map_or(bridge_attestation_sleep, |speed_expiry| {
                    bridge_attestation_sleep.min(speed_expiry)
                })
                // Local configuration changes (ipv4, proxy cidrs, ...) have no
                // global event. Keep the one-second resync cadence so
                // update_my_infos observes them promptly.
                .min(Duration::from_secs(1));
            select! {
                ev = global_event_receiver.recv() => {
                    if let Ok(ev_ref) = &ev {
                        service_impl.handle_global_ctx_event(ev_ref);
                    } else {
                        service_impl.mark_interface_peers_dirty();
                        global_event_receiver = global_event_receiver.resubscribe();
                    }
                    tracing::info!(?ev, "global event received in update_my_peer_info_routine");
                }
                _ = tokio::time::sleep(update_sleep) => {}
            }
        }
    }

    async fn start(&self) {
        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        // make sure my_peer_id is in the peer_infos.
        self.service_impl.update_my_infos().await;
        self.public_ipv6_service.handle_route_change();

        peer_rpc.rpc_server().registry().register(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.global_ctx.get_network_name(),
        );
        peer_rpc.rpc_server().registry().register(
            PublicIpv6AddrRpcServer::new(self.public_ipv6_service.rpc_server()),
            &self.global_ctx.get_network_name(),
        );

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::update_my_peer_info_routine(
                self.service_impl.clone(),
                self.session_mgr.clone(),
            ));

        self.tasks
            .lock()
            .unwrap()
            .spawn(self.service_impl.clone().route_rebuild_worker());

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::maintain_session_tasks(
                self.session_mgr.clone(),
                self.service_impl.clone(),
            ));

        self.tasks
            .lock()
            .unwrap()
            .spawn(Self::clear_expired_peer(self.service_impl.clone()));

        self.tasks
            .lock()
            .unwrap()
            .spawn(self.public_ipv6_service.clone().provider_gc_routine());

        self.tasks
            .lock()
            .unwrap()
            .spawn(self.public_ipv6_service.clone().client_routine());
    }
}

impl Drop for PeerRoute {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.global_ctx.get_network_identity(),
            service = ?self.service_impl,
            "PeerRoute drop"
        );

        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            return;
        };

        peer_rpc.rpc_server().registry().unregister(
            OspfRouteRpcServer::new(self.session_mgr.clone()),
            &self.global_ctx.get_network_name(),
        );
        peer_rpc.rpc_server().registry().unregister(
            PublicIpv6AddrRpcServer::new(self.public_ipv6_service.rpc_server()),
            &self.global_ctx.get_network_name(),
        );
    }
}

#[async_trait::async_trait]
impl Route for PeerRoute {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()> {
        let forwarding_snapshot_source = interface.forwarding_decision_snapshot_source();
        *self
            .service_impl
            .forwarding_snapshot_source
            .write()
            .unwrap() = forwarding_snapshot_source;
        let interface: Arc<dyn RouteInterface + Send + Sync> = Arc::from(interface);
        *self.service_impl.publish_interface.write().unwrap() = Some(interface.clone());
        *self.service_impl.interface.lock().await = Some(interface);
        self.start().await;
        Ok(1)
    }

    async fn close(&self) {
        if let Some(source) = self
            .service_impl
            .forwarding_snapshot_source
            .write()
            .unwrap()
            .take()
        {
            // Revoke route-origin authority before the forwarding source is
            // revoked. An empty publication removes every route grant.
            if let Ok(generation) = self.service_impl.allocate_forwarding_generation() {
                if let Some(interface) = self
                    .service_impl
                    .publish_interface
                    .read()
                    .unwrap()
                    .as_ref()
                    .cloned()
                {
                    let _ =
                        interface.publish_origin_auth_batch(source.source_token(), generation, &[]);
                }
            }
            source.revoke();
        }

        // Dropping sessions aborts their per-peer tasks.
        self.service_impl.sessions.clear();
        *self.service_impl.publish_interface.write().unwrap() = None;
        self.service_impl.interface.lock().await.take();

        let mut tasks = {
            let mut task_set = self.tasks.lock().unwrap();
            std::mem::take(&mut *task_set)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}

        if let Some(peer_rpc) = self.peer_rpc.upgrade() {
            peer_rpc.rpc_server().registry().unregister(
                OspfRouteRpcServer::new(self.session_mgr.clone()),
                &self.global_ctx.get_network_name(),
            );
            peer_rpc.rpc_server().registry().unregister(
                PublicIpv6AddrRpcServer::new(self.public_ipv6_service.rpc_server()),
                &self.global_ctx.get_network_name(),
            );
        }
    }

    async fn get_next_hop(&self, dst_peer_id: PeerId) -> Option<PeerId> {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_table = &snapshot.route_table;
        route_table
            .get_next_hop(dst_peer_id)
            .map(|x| x.next_hop_peer_id)
    }

    async fn get_next_hop_with_policy(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        let snapshot = self.service_impl.forwarding_snapshot();
        PeerRouteServiceImpl::get_next_hop_with_policy_from_snapshot(&snapshot, dst_peer_id, policy)
            .map(|x| x.next_hop_peer_id)
    }

    async fn get_next_hop_with_policy_and_generation(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<(PeerId, u64)> {
        let snapshot = self.service_impl.forwarding_snapshot();
        PeerRouteServiceImpl::get_next_hop_with_policy_from_snapshot(&snapshot, dst_peer_id, policy)
            .map(|next_hop| (next_hop.next_hop_peer_id, snapshot.generation))
    }

    async fn list_routes(&self) -> Vec<crate::proto::api::instance::Route> {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_table = &snapshot.route_table;
        let route_table_with_cost = &snapshot.route_table_with_cost;
        let route_table_with_speed = &snapshot.route_table_with_speed;
        let mut routes = Vec::new();
        for (peer_id, item) in route_table.peer_infos.iter() {
            if *peer_id == self.my_peer_id {
                continue;
            }
            let Some(next_hop_peer) = route_table.get_next_hop(*peer_id) else {
                continue;
            };
            let next_hop_peer_latency_first = route_table_with_cost.get_next_hop(*peer_id);
            let next_hop_peer_speed = route_table_with_speed.get_next_hop(*peer_id);
            let selected_speed_route = next_hop_peer_speed
                .or(next_hop_peer_latency_first)
                .or(Some(next_hop_peer));
            let mut route: crate::proto::api::instance::Route = item.clone().into();
            route.next_hop_peer_id = next_hop_peer.next_hop_peer_id;
            route.cost = next_hop_peer.path_len as i32;
            route.path_latency = next_hop_peer.path_latency;

            route.next_hop_peer_id_latency_first =
                next_hop_peer_latency_first.map(|x| x.next_hop_peer_id);
            route.cost_latency_first = next_hop_peer_latency_first.map(|x| x.path_len as i32);
            route.path_latency_latency_first = next_hop_peer_latency_first.map(|x| x.path_latency);

            route.next_hop_peer_id_speed_first = selected_speed_route.map(|x| x.next_hop_peer_id);
            route.path_delivery_bps_speed_first = next_hop_peer_speed.map(|x| x.path_delivery_bps);
            route.path_latency_speed_first = selected_speed_route.map(|x| x.path_latency);
            route.path_len_speed_first = selected_speed_route.map(|x| x.path_len as i32);

            route.feature_flag = item.feature_flag;

            // Replace wire role metadata with one locally authenticated snapshot.
            // A missing attestation is not eligible for peer-center authority.
            if let Some(authenticated) = self.service_impl.authenticated_peers.get(peer_id) {
                route.peer_identity_type = authenticated.identity_type as i32;
                route.secure_auth_level = authenticated.secure_auth_level as i32;
            } else {
                route.peer_identity_type = PeerIdentityType::SharedNode as i32;
                route.secure_auth_level = SecureAuthLevel::EncryptedUnauthenticated as i32;
            }

            routes.push(route);
        }
        routes
    }

    async fn list_forwarding_peers(&self) -> super::route_trait::ForwardingPeerSnapshot {
        self.service_impl
            .forwarding_snapshot()
            .forwarding_peers
            .clone()
    }

    async fn list_forwarding_peer_capabilities(
        &self,
    ) -> super::route_trait::ForwardingPeerSnapshot {
        self.service_impl
            .forwarding_snapshot()
            .forwarding_peers
            .clone()
    }

    async fn list_forwarding_peer_capabilities_with_generation(
        &self,
    ) -> (u64, super::route_trait::ForwardingPeerSnapshot) {
        let snapshot = self.service_impl.forwarding_snapshot();
        (snapshot.generation, snapshot.forwarding_peers.clone())
    }

    async fn forwarding_decision_snapshot(&self) -> Option<ForwardingDecisionSnapshotHandle> {
        Some(
            self.service_impl
                .forwarding_snapshot()
                .decision_snapshot
                .clone(),
        )
    }

    fn forwarding_generation(&self) -> u64 {
        self.service_impl.forwarding_snapshot().generation
    }

    async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        let my_peer_id = self.my_peer_id;
        self.service_impl
            .forwarding_snapshot()
            .route_table
            .cidr_peer_id_map
            .iter()
            .filter(|(_, pv)| **pv != my_peer_id)
            .map(|(cidr, _)| *cidr)
            .collect()
    }

    async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        let my_peer_id = self.my_peer_id;
        self.service_impl
            .forwarding_snapshot()
            .route_table
            .cidr_v6_peer_id_map
            .iter()
            .filter(|(_, pv)| **pv != my_peer_id)
            .map(|(cidr, _)| *cidr)
            .collect()
    }

    async fn list_public_ipv6_routes(&self) -> BTreeSet<Ipv6Inet> {
        self.public_ipv6_service.list_routes()
    }

    async fn get_my_public_ipv6_addr(&self) -> Option<Ipv6Inet> {
        self.public_ipv6_service.my_addr()
    }

    async fn get_public_ipv6_gateway_peer_id(&self) -> Option<PeerId> {
        self.public_ipv6_service.provider_peer_id_for_client()
    }

    async fn get_local_public_ipv6_info(
        &self,
    ) -> crate::proto::api::instance::ListPublicIpv6InfoResponse {
        let Some((provider, leases)) = self.public_ipv6_service.local_provider_state() else {
            return crate::proto::api::instance::ListPublicIpv6InfoResponse::default();
        };

        crate::proto::api::instance::ListPublicIpv6InfoResponse {
            provider_prefix: Some(
                Ipv6Inet::new(
                    provider.prefix.first_address(),
                    provider.prefix.network_length(),
                )
                .unwrap()
                .into(),
            ),
            provider_leases: leases
                .into_iter()
                .map(|lease| crate::proto::api::instance::PublicIpv6LeaseInfo {
                    peer_id: lease.peer_id,
                    inst_id: lease.inst_id.to_string(),
                    leased_addr: Some(lease.addr.into()),
                    valid_until_unix_seconds: lease
                        .valid_until
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                    reused: lease.reused,
                })
                .collect(),
        }
    }

    async fn get_peer_id_by_ipv4(&self, ipv4_addr: &Ipv4Addr) -> Option<PeerId> {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_table = &snapshot.route_table;
        if let Some(p) = route_table.ipv4_peer_id_map.get(ipv4_addr) {
            return Some(*p);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            tracing::trace!(?ipv4_addr, "ipv4 addr is in same network with us");
            return None;
        }

        if let Some(peer_id) = route_table.get_peer_id_for_proxy(&IpAddr::V4(*ipv4_addr)) {
            return Some(peer_id);
        }

        tracing::debug!(?ipv4_addr, "no peer id for ipv4");
        None
    }

    async fn get_peer_id_by_ipv6(&self, ipv6_addr: &Ipv6Addr) -> Option<PeerId> {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_table = &snapshot.route_table;
        if let Some(p) = route_table.ipv6_peer_id_map.get(ipv6_addr) {
            return Some(*p);
        }

        // only get peer id for proxy when the dst ipv4 is not in same network with us
        if self
            .global_ctx
            .is_ip_in_same_network(&std::net::IpAddr::V6(*ipv6_addr))
        {
            tracing::trace!(?ipv6_addr, "ipv6 addr is in same network with us");
            return None;
        }

        if let Some(peer_id) = route_table.get_peer_id_for_proxy(&IpAddr::V6(*ipv6_addr)) {
            return Some(peer_id);
        }

        tracing::debug!(?ipv6_addr, "no peer id for ipv6");
        None
    }

    async fn set_route_cost_fn(&self, cost_fn: RouteCostCalculator) {
        let _rebuild_guard = self.service_impl.route_rebuild_lock.lock().unwrap();
        *self.service_impl.cost_calculator.write().unwrap() = Some(cost_fn);
        self.service_impl
            .rebuild_domains_locked(RouteRebuildDomains::cost_and_delivery());
    }

    async fn dump(&self) -> String {
        format!("{:#?}", self)
    }

    async fn list_foreign_network_info(&self) -> RouteForeignNetworkInfos {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_table = &snapshot.route_table;
        let mut foreign_networks = RouteForeignNetworkInfos::default();
        for item in self
            .service_impl
            .synced_route_info
            .foreign_network
            .iter()
            .filter(|x| !x.value().foreign_peer_ids.is_empty())
            .filter(|x| route_table.peer_reachable(x.key().peer_id))
        {
            foreign_networks
                .infos
                .push(route_foreign_network_infos::Info {
                    key: Some(item.key().clone()),
                    value: Some(item.value().clone()),
                });
        }
        foreign_networks
    }

    async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        let mut info_map: BTreeMap<PeerId, route_foreign_network_summary::Info> = BTreeMap::new();
        for item in self.service_impl.synced_route_info.foreign_network.iter() {
            let entry = info_map.entry(item.key().peer_id).or_default();
            entry.network_count += 1;
            entry.peer_count += item.value().foreign_peer_ids.len() as u32;
        }
        RouteForeignNetworkSummary { info_map }
    }

    async fn list_authenticated_foreign_network_peers(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<(PeerId, Vec<u8>)> {
        self.service_impl
            .authenticated_foreign_network_peers(network_identity)
    }

    async fn get_authenticated_foreign_origin_owner_key(
        &self,
        network_identity: &NetworkIdentity,
        origin_peer_id: PeerId,
    ) -> Option<Vec<u8>> {
        self.service_impl
            .authenticated_foreign_network_peers(network_identity)
            .into_iter()
            .find_map(|(peer_id, key)| (peer_id == origin_peer_id).then_some(key))
    }

    async fn get_origin_my_peer_id(
        &self,
        network_name: &str,
        foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        self.service_impl
            .forwarding_snapshot()
            .foreign_network_my_peer_id_map
            .get(&(network_name.to_string(), foreign_my_peer_id))
            .copied()
    }

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        self.service_impl
            .forwarding_snapshot()
            .route_table
            .peer_infos
            .get(&peer_id)
            .cloned()
    }

    async fn get_authenticated_peer_evidence(
        &self,
        peer_id: PeerId,
    ) -> Option<AuthenticatedRoutePeerEvidence> {
        if let Some(authenticated) = self.service_impl.authenticated_peers.get(&peer_id) {
            return Some(AuthenticatedRoutePeerEvidence {
                peer_id,
                identity_type: authenticated.identity_type,
                noise_static_pubkey: authenticated.public_key.clone(),
                secure_auth_level: authenticated.secure_auth_level,
            });
        }

        None
    }

    async fn get_bridge_peer_evidence(&self, peer_id: PeerId) -> Option<BridgeRoutePeerEvidence> {
        let snapshot = self.service_impl.forwarding_snapshot();
        let route_info = snapshot.route_table.peer_infos.get(&peer_id)?;
        self.service_impl.bridge_evidence_for_snapshot(
            peer_id,
            route_info,
            &snapshot.route_table,
            snapshot.generation,
        )
    }

    async fn get_authenticated_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo> {
        let snapshot = self.service_impl.forwarding_snapshot();
        if let Some(authenticated) = self.service_impl.authenticated_peers.get(&peer_id) {
            let mut info = RoutePeerInfo::new();
            info.peer_id = peer_id;
            info.noise_static_pubkey = authenticated.public_key.clone();
            info.identity_type = authenticated.identity_type as i32;
            info.feature_flag = Some(crate::proto::common::PeerFeatureFlag {
                is_credential_peer: matches!(
                    authenticated.identity_type,
                    PeerIdentityType::Credential
                ),
                relay_origin_proof: true,
                ..Default::default()
            });
            return Some(info);
        }

        let info = self
            .service_impl
            .synced_route_info
            .peer_infos
            .read()
            .get(&peer_id)
            .cloned()?;
        if info.noise_static_pubkey.len() != 32
            || !info
                .feature_flag
                .as_ref()
                .is_some_and(|features| features.relay_origin_proof)
            || !snapshot.route_table.peer_reachable(peer_id)
        {
            return None;
        }
        let identity_type = SyncedRouteInfo::peer_identity_type(&info)?;
        if identity_type == PeerIdentityType::Admin
            && self
                .service_impl
                .attested_admin_identity_evidence(peer_id, &info)
                .is_some()
        {
            return Some(info);
        }
        let source = match identity_type {
            PeerIdentityType::Admin => crate::common::global_ctx::TrustedKeySource::OspfNode,
            PeerIdentityType::Credential => {
                crate::common::global_ctx::TrustedKeySource::OspfCredential
            }
            PeerIdentityType::SharedNode => return None,
            PeerIdentityType::ForeignRelay => return None,
        };
        let network_name = self.service_impl.global_ctx.get_network_name();
        self.service_impl
            .global_ctx
            .is_pubkey_trusted_with_source(&info.noise_static_pubkey, &network_name, source)
            .then_some(info)
    }

    async fn get_authenticated_peer_secure_auth_level(
        &self,
        peer_id: PeerId,
    ) -> Option<SecureAuthLevel> {
        if let Some(authenticated) = self.service_impl.authenticated_peers.get(&peer_id) {
            return Some(authenticated.secure_auth_level);
        }

        let snapshot = self.service_impl.forwarding_snapshot();
        let info = self
            .service_impl
            .synced_route_info
            .peer_infos
            .read()
            .get(&peer_id)
            .cloned()?;
        if info.noise_static_pubkey.len() != 32
            || !info
                .feature_flag
                .as_ref()
                .is_some_and(|features| features.relay_origin_proof)
            || !snapshot.route_table.peer_reachable(peer_id)
        {
            return None;
        }
        let identity_type = SyncedRouteInfo::peer_identity_type(&info)?;
        if identity_type == PeerIdentityType::Admin
            && let Some(evidence) = self
                .service_impl
                .attested_admin_identity_evidence(peer_id, &info)
        {
            return Some(evidence.secure_auth_level);
        }
        let source = match identity_type {
            PeerIdentityType::Admin => crate::common::global_ctx::TrustedKeySource::OspfNode,
            PeerIdentityType::Credential => {
                crate::common::global_ctx::TrustedKeySource::OspfCredential
            }
            PeerIdentityType::SharedNode | PeerIdentityType::ForeignRelay => {
                return Some(SecureAuthLevel::EncryptedUnauthenticated);
            }
        };
        let network_name = self.service_impl.global_ctx.get_network_name();
        self.service_impl
            .global_ctx
            .is_pubkey_trusted_with_source(&info.noise_static_pubkey, &network_name, source)
            .then_some(SecureAuthLevel::PeerVerified)
    }

    async fn get_peer_info_last_update_time(&self) -> Instant {
        self.service_impl.get_peer_info_last_update()
    }

    fn get_peer_groups(&self, peer_id: PeerId) -> Arc<Vec<String>> {
        self.service_impl.get_peer_groups(peer_id)
    }

    async fn refresh_acl_groups(&self) {
        if self.service_impl.refresh_acl_groups().await {
            self.session_mgr.sync_now("refresh_acl_groups");
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Inet};
    use dashmap::DashMap;
    use parking_lot::Mutex;
    use petgraph::{graph::NodeIndex, visit::EdgeRef as _};
    use prefix_trie::PrefixMap;
    use prost::Message;
    use prost_reflect::{DynamicMessage, ReflectMessage};
    use prost_wkt_types::Timestamp;
    use quanta::Instant;
    use std::cmp::Reverse;
    use std::net::IpAddr;
    use std::{
        collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet},
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant as StdInstant, SystemTime},
    };

    use super::{
        AuthenticatedPeerInfo, AuthenticatedPeerSeedResult, MAX_ROUTE_SYNC_EDGES,
        MAX_ROUTE_SYNC_EDGES_PER_SOURCE, MAX_ROUTE_SYNC_PEERS, NextHopInfo, PeerConnInfo,
        PeerRoute, REMOVE_DEAD_PEER_INFO_AFTER, RouteConnBitmap, RouteConnInfo, RouteConnPeerList,
        RouteQuality, RouteRebuildDomains, RouteTable, SpeedEdge, SpeedGraph, SyncRouteSession,
        SyncedRouteInfo, TopologyBuildInput, WidestPathWorkBudget,
        add_authorized_relay_reverse_edges, get_raw_peer_infos, prepare_widest_path,
        validate_route_conn_info, validate_route_foreign_network_info, validate_route_peer_infos,
        validate_route_sync_role_shape, widest_path_with_first_hop, widest_path_with_preparation,
        widest_path_with_work_stats, widest_path_work_limit,
    };

    use crate::proto::common::TimestampExt;
    use crate::{
        common::{
            PeerId,
            config::{ConfigLoader, NetworkIdentity},
            global_ctx::{
                GlobalCtxEvent, TrustedKeySource,
                tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            },
            stats_manager::{LabelSet, LabelType, MetricName},
        },
        connector::udp_hole_punch::tests::replace_stun_info_collector,
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
            peer_map::PeerMap,
            peer_ospf_route::{FORCE_USE_CONN_LIST, PeerIdVersion, PeerRouteServiceImpl},
            route_trait::{
                DefaultRouteCostCalculator, ForwardingDecisionSnapshot,
                ForwardingDecisionSnapshotStoreInner, ForwardingSnapshotSourceToken, NextHopPolicy,
                OriginAuthPublication, Route, RouteCostCalculatorInterface, RouteInterface,
                RouteInterfaceBox,
            },
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::{
            acl::{Acl, AclV1, GroupIdentity, GroupInfo},
            common::{NatType, PeerFeatureFlag},
            peer_rpc::{
                ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, OspfRouteRpc,
                PeerGroupInfo, PeerIdentityType, RouteForeignNetworkInfos, RoutePeerInfo,
                RoutePeerInfos, SecureAuthLevel, SyncRouteInfoRequest, TrustedCredentialPubkey,
                TrustedCredentialPubkeyProof, route_foreign_network_infos,
                sync_route_info_request::ConnInfo,
            },
            rpc_types::{
                self,
                controller::{BaseController, Controller},
            },
        },
        tunnel::common::tests::wait_for_condition,
    };
    use ordered_hash_map::OrderedHashMap;

    #[test]
    fn forwarding_snapshot_never_exposes_partial_route_state() {
        let service = Arc::new(PeerRouteServiceImpl::new(1, get_mock_global_ctx()));
        let failed = Arc::new(AtomicBool::new(false));
        let reader_service = service.clone();
        let reader_failed = failed.clone();
        let reader = thread::spawn(move || {
            for _ in 0..2_000 {
                let snapshot = reader_service.forwarding_snapshot();
                for (peer_id, route) in snapshot.route_table.next_hop_map.iter() {
                    if !snapshot.route_table.peer_infos.contains_key(peer_id)
                        || snapshot.forwarding_peers.get(*peer_id).is_none()
                    {
                        reader_failed.store(true, Ordering::Release);
                        return;
                    }
                    if route.next_hop_peer_id != *peer_id
                        && snapshot
                            .route_table
                            .get_next_hop(route.next_hop_peer_id)
                            .is_none()
                    {
                        reader_failed.store(true, Ordering::Release);
                        return;
                    }
                }
            }
        });

        for cycle in 0..200_u64 {
            service.route_table.peer_infos.clear();
            service.route_table.next_hop_map.clear();
            let peer_id: PeerId = 2 + (cycle % 2) as PeerId;
            let mut peer_info = RoutePeerInfo::new();
            peer_info.peer_id = peer_id;
            peer_info.version = 1;
            service
                .route_table
                .peer_infos
                .insert(peer_info.peer_id, peer_info);
            service.route_table.next_hop_map.insert(
                peer_id,
                NextHopInfo {
                    next_hop_peer_id: peer_id,
                    path_delivery_bps: 0,
                    path_latency: 1,
                    path_len: 1,
                    version: 1,
                },
            );
            service.route_table.next_hop_map_version.set(1);
            service.publish_forwarding_snapshot();
        }

        reader.join().unwrap();
        assert!(!failed.load(Ordering::Acquire));
    }

    #[test]
    fn conservative_snapshot_revokes_all_forwarding_state() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let mut peer_info = RoutePeerInfo::new();
        peer_info.peer_id = 2;
        peer_info.version = 1;
        service.route_table.peer_infos.insert(2, peer_info);
        service.route_table.next_hop_map.insert(
            2,
            NextHopInfo {
                next_hop_peer_id: 2,
                path_delivery_bps: 1,
                path_latency: 1,
                path_len: 1,
                version: 1,
            },
        );
        service.route_table.next_hop_map_version.set(1);
        service
            .foreign_network_owner_map
            .insert(service.global_ctx.get_network_identity(), vec![2]);
        service
            .foreign_network_my_peer_id_map
            .insert(("foreign".to_owned(), 2), 9);
        service.publish_forwarding_snapshot();

        assert!(
            service
                .forwarding_snapshot()
                .route_table
                .get_next_hop(2)
                .is_some()
        );
        assert!(
            !service
                .forwarding_snapshot()
                .foreign_network_owner_map
                .is_empty()
        );

        service.publish_conservative_forwarding_snapshot();

        let snapshot = service.forwarding_snapshot();
        assert!(snapshot.route_table.next_hop_map.is_empty());
        assert!(snapshot.route_table_with_cost.next_hop_map.is_empty());
        assert!(snapshot.route_table_with_speed.next_hop_map.is_empty());
        assert!(snapshot.forwarding_peers.ethernet_peers().is_empty());
        assert!(snapshot.foreign_network_owner_map.is_empty());
        assert!(snapshot.foreign_network_my_peer_id_map.is_empty());
        assert!(
            snapshot
                .decision_snapshot
                .next_hop(2, NextHopPolicy::LeastHop)
                .is_none()
        );
    }

    fn bridge_route_info(peer_id: PeerId, static_key: Vec<u8>) -> RoutePeerInfo {
        let mut info = RoutePeerInfo::new();
        info.peer_id = peer_id;
        info.version = 1;
        info.noise_static_pubkey = static_key;
        info.identity_type = PeerIdentityType::Admin as i32;
        info.feature_flag = Some(PeerFeatureFlag {
            ethernet_input: true,
            hybrid_l3: true,
            bridge_input: true,
            ..Default::default()
        });
        info
    }

    fn signed_bridge_route_info(
        network_name: &str,
        network_secret: &str,
        peer_id: PeerId,
        static_key: Vec<u8>,
        issued_unix_ms: u64,
        expiry_unix_ms: u64,
    ) -> RoutePeerInfo {
        let mut info = bridge_route_info(peer_id, static_key);
        info.bridge_attestation_issued_unix_ms = issued_unix_ms;
        info.bridge_attestation_expiry_unix_ms = expiry_unix_ms;
        info.bridge_attestation_hmac = super::generate_bridge_attestation_hmac(
            network_secret,
            network_name,
            peer_id,
            &info.noise_static_pubkey,
            true,
            issued_unix_ms,
            expiry_unix_ms,
        )
        .unwrap();
        info
    }

    fn publish_bridge_test_route(service: &PeerRouteServiceImpl, info: RoutePeerInfo) {
        publish_bridge_test_route_with_topology(service, info, None, 1);
    }

    fn publish_bridge_test_route_with_topology(
        service: &PeerRouteServiceImpl,
        info: RoutePeerInfo,
        next_hop_peer_id: Option<PeerId>,
        path_len: usize,
    ) {
        let peer_id = info.peer_id;
        service.route_table.peer_infos.insert(peer_id, info);
        service.route_table.next_hop_map.insert(
            peer_id,
            NextHopInfo {
                next_hop_peer_id: next_hop_peer_id.unwrap_or(peer_id),
                path_delivery_bps: 0,
                path_latency: 1,
                path_len,
                version: 1,
            },
        );
        service.route_table.next_hop_map_version.set(1);
        service.publish_forwarding_snapshot();
    }

    #[test]
    fn forged_transit_admin_cannot_authorize_bridge_forwarding() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        publish_bridge_test_route(&service, bridge_route_info(2, vec![7; 32]));

        let snapshot = service.forwarding_snapshot();
        assert!(!snapshot.forwarding_peers.is_authorized_bridge(2));
        assert!(snapshot.forwarding_peers.ethernet_peers().is_empty());
    }

    #[test]
    fn locally_verified_admin_with_matching_key_authorizes_bridge_forwarding() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let static_key = vec![7; 32];
        service.authenticated_peers.insert(
            2,
            AuthenticatedPeerInfo {
                peer_id: 2,
                identity_type: PeerIdentityType::Admin,
                public_key: static_key.clone(),
                secure_auth_level: SecureAuthLevel::PeerVerified,
            },
        );
        publish_bridge_test_route(&service, bridge_route_info(2, static_key));

        let snapshot = service.forwarding_snapshot();
        assert!(snapshot.forwarding_peers.is_authorized_bridge(2));
        assert_eq!(snapshot.forwarding_peers.ethernet_peers(), &[2]);
    }

    #[test]
    fn locally_verified_admin_with_mismatched_route_key_is_denied() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        service.authenticated_peers.insert(
            2,
            AuthenticatedPeerInfo {
                peer_id: 2,
                identity_type: PeerIdentityType::Admin,
                public_key: vec![8; 32],
                secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
            },
        );
        publish_bridge_test_route(&service, bridge_route_info(2, vec![7; 32]));

        assert!(
            !service
                .forwarding_snapshot()
                .forwarding_peers
                .is_authorized_bridge(2)
        );
    }

    #[test]
    fn signed_two_hop_bridge_attestation_authorizes_forwarding() {
        let network_name = "test-net";
        let network_secret = "test-secret";
        let service = PeerRouteServiceImpl::new(
            1,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network_name.to_string(),
                network_secret.to_string(),
            ))),
        );
        let issued = super::unix_time_ms().unwrap();
        let info = signed_bridge_route_info(
            network_name,
            network_secret,
            2,
            vec![7; 32],
            issued,
            issued + 120_000,
        );
        publish_bridge_test_route_with_topology(&service, info, Some(3), 2);

        assert!(
            service
                .forwarding_snapshot()
                .forwarding_peers
                .is_authorized_bridge(2)
        );
    }

    #[test]
    fn attested_bridge_does_not_create_generic_authenticated_evidence() {
        let network_name = "test-net";
        let network_secret = "test-secret";
        let service = PeerRouteServiceImpl::new(
            1,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network_name.to_string(),
                network_secret.to_string(),
            ))),
        );
        let issued = super::unix_time_ms().unwrap();
        let info = signed_bridge_route_info(
            network_name,
            network_secret,
            2,
            vec![7; 32],
            issued,
            issued + 120_000,
        );
        publish_bridge_test_route_with_topology(&service, info, Some(3), 2);
        let snapshot = service.forwarding_snapshot();
        let route_info = snapshot.route_table.peer_infos.get(&2).unwrap();

        assert!(service.authenticated_peers.get(&2).is_none());
        assert!(
            service
                .bridge_evidence_for_snapshot(
                    2,
                    route_info,
                    &snapshot.route_table,
                    snapshot.generation
                )
                .is_some()
        );
    }

    #[test]
    fn modified_bridge_attestation_fields_are_denied() {
        let network_name = "test-net";
        let network_secret = "test-secret";
        for mutation in 0..3 {
            let service = PeerRouteServiceImpl::new(
                1,
                get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                    network_name.to_string(),
                    network_secret.to_string(),
                ))),
            );
            let issued = super::unix_time_ms().unwrap();
            let mut info = signed_bridge_route_info(
                network_name,
                network_secret,
                2,
                vec![7; 32],
                issued,
                issued + 120_000,
            );
            match mutation {
                0 => info.peer_id = 4,
                1 => info.noise_static_pubkey[0] ^= 1,
                2 => info.feature_flag.as_mut().unwrap().bridge_input = false,
                _ => unreachable!(),
            }
            publish_bridge_test_route_with_topology(&service, info, Some(3), 2);
            assert!(
                !service
                    .forwarding_snapshot()
                    .forwarding_peers
                    .is_authorized_bridge(2)
            );
        }
    }

    #[test]
    fn credential_and_shared_node_attestations_are_denied() {
        let network_name = "test-net";
        let network_secret = "test-secret";
        for identity_type in [PeerIdentityType::Credential, PeerIdentityType::SharedNode] {
            let service = PeerRouteServiceImpl::new(
                1,
                get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                    network_name.to_string(),
                    network_secret.to_string(),
                ))),
            );
            let issued = super::unix_time_ms().unwrap();
            let mut info = signed_bridge_route_info(
                network_name,
                network_secret,
                2,
                vec![7; 32],
                issued,
                issued + 120_000,
            );
            info.identity_type = identity_type as i32;
            publish_bridge_test_route_with_topology(&service, info, Some(3), 2);
            assert!(
                !service
                    .forwarding_snapshot()
                    .forwarding_peers
                    .is_authorized_bridge(2)
            );
        }
    }

    #[test]
    fn expired_bridge_attestation_is_removed_from_cache() {
        let network_name = "test-net";
        let network_secret = "test-secret";
        let service = PeerRouteServiceImpl::new(
            1,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network_name.to_string(),
                network_secret.to_string(),
            ))),
        );
        let now = super::unix_time_ms().unwrap();
        let info = signed_bridge_route_info(
            network_name,
            network_secret,
            2,
            vec![7; 32],
            now.saturating_sub(120_000),
            now.saturating_sub(1),
        );
        publish_bridge_test_route_with_topology(&service, info, Some(3), 2);

        assert!(
            !service
                .forwarding_snapshot()
                .forwarding_peers
                .is_authorized_bridge(2)
        );
        assert!(!service.verified_bridge_attestations.contains_key(&2));
    }

    #[test]
    fn empty_route_key_denies_direct_bridge_evidence() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        service.authenticated_peers.insert(
            2,
            AuthenticatedPeerInfo {
                peer_id: 2,
                identity_type: PeerIdentityType::Admin,
                public_key: vec![7; 32],
                secure_auth_level: SecureAuthLevel::PeerVerified,
            },
        );
        publish_bridge_test_route(&service, bridge_route_info(2, Vec::new()));

        assert!(
            !service
                .forwarding_snapshot()
                .forwarding_peers
                .is_authorized_bridge(2)
        );
    }

    #[test]
    fn bridge_attestation_sleep_uses_local_refresh_when_cache_is_empty() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        assert_eq!(
            service.bridge_attestation_sleep_duration_at(Instant::now()),
            super::BRIDGE_ATTESTATION_REFRESH
        );
    }

    #[test]
    fn bridge_attestation_sleep_caps_distant_expiry_at_local_refresh() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let now = Instant::now();
        *service.bridge_attestation_next_deadline.lock().unwrap() =
            Some(now + Duration::from_secs(120));

        assert_eq!(
            service.bridge_attestation_sleep_duration_at(now),
            super::BRIDGE_ATTESTATION_REFRESH
        );
    }

    #[test]
    fn bridge_attestation_sleep_wakes_for_near_expiry() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let now = Instant::now();
        let near_expiry = Duration::from_secs(5);
        *service.bridge_attestation_next_deadline.lock().unwrap() = Some(now + near_expiry);

        assert_eq!(
            service.bridge_attestation_sleep_duration_at(now),
            near_expiry
        );
    }

    #[test]
    fn bridge_attestation_rejects_empty_network_secret() {
        let key = vec![7; 32];
        let issued = 1_000;
        let expiry = issued + 120_000;
        assert!(
            super::generate_bridge_attestation_hmac("", "test-net", 2, &key, true, issued, expiry,)
                .is_none()
        );
        assert!(!super::verify_bridge_attestation_hmac(
            "", "test-net", 2, &key, true, issued, expiry, &[0; 32],
        ));
    }

    fn seed_snapshot_test_topology(service: &PeerRouteServiceImpl, version: u32) {
        let mut self_info = RoutePeerInfo::new();
        self_info.peer_id = service.my_peer_id;
        self_info.version = 1;
        let mut peer_info = RoutePeerInfo::new();
        peer_info.peer_id = 2;
        peer_info.version = 1;
        let _topology_guard = service.synced_route_info.topology_state_lock();
        {
            let mut peer_infos = service.synced_route_info.peer_infos.write();
            peer_infos.insert(self_info.peer_id, self_info);
            peer_infos.insert(peer_info.peer_id, peer_info);
        }
        {
            let mut conn_map = service.synced_route_info.conn_map.write();
            conn_map.insert(
                service.my_peer_id,
                make_route_conn_info([2], SystemTime::now()),
            );
            conn_map.insert(
                2,
                make_route_conn_info([service.my_peer_id], SystemTime::now()),
            );
        }
        service.synced_route_info.version.set(version);
        drop(_topology_guard);
        service.update_route_table_and_cached_local_conn_bitmap();
    }

    #[test]
    fn cost_only_rebuild_reuses_topology() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);

        let topology_version = service.synced_route_info.version.get();
        let topology_route_version = service.route_table.next_hop_map_version.get();
        let topology_generation = service.forwarding_snapshot().generation;
        let least_hop = service
            .rebuild_work
            .least_hop_rebuilds
            .load(Ordering::Acquire);
        let least_cost = service
            .rebuild_work
            .least_cost_rebuilds
            .load(Ordering::Acquire);
        let max_goodput = service
            .rebuild_work
            .max_goodput_rebuilds
            .load(Ordering::Acquire);

        service.rebuild_domains(RouteRebuildDomains::cost_and_delivery());

        assert_eq!(
            service
                .rebuild_work
                .least_hop_rebuilds
                .load(Ordering::Acquire),
            least_hop
        );
        assert_eq!(
            service
                .rebuild_work
                .least_cost_rebuilds
                .load(Ordering::Acquire),
            least_cost + 1
        );
        assert_eq!(
            service
                .rebuild_work
                .max_goodput_rebuilds
                .load(Ordering::Acquire),
            max_goodput + 1
        );
        assert_eq!(service.synced_route_info.version.get(), topology_version);
        assert_eq!(
            service.route_table.next_hop_map_version.get(),
            topology_route_version
        );
        assert_eq!(
            service.route_table_with_cost.next_hop_map_version.get(),
            topology_route_version
        );
        assert_eq!(
            service.route_table_with_speed.next_hop_map_version.get(),
            topology_route_version
        );
        assert_eq!(
            service
                .forwarding_snapshot()
                .route_table
                .next_hop_map_version,
            topology_route_version
        );
        assert_eq!(
            service.forwarding_snapshot().generation,
            topology_generation + 1
        );
    }

    #[test]
    fn bridge_only_rebuild_does_not_rebuild_route_policies() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);

        let least_hop = service
            .rebuild_work
            .least_hop_rebuilds
            .load(Ordering::Acquire);
        let least_cost = service
            .rebuild_work
            .least_cost_rebuilds
            .load(Ordering::Acquire);
        let max_goodput = service
            .rebuild_work
            .max_goodput_rebuilds
            .load(Ordering::Acquire);

        service.rebuild_domains(RouteRebuildDomains::bridge());

        assert_eq!(
            service
                .rebuild_work
                .least_hop_rebuilds
                .load(Ordering::Acquire),
            least_hop
        );
        assert_eq!(
            service
                .rebuild_work
                .least_cost_rebuilds
                .load(Ordering::Acquire),
            least_cost
        );
        assert_eq!(
            service
                .rebuild_work
                .max_goodput_rebuilds
                .load(Ordering::Acquire),
            max_goodput
        );
        assert!(
            service
                .rebuild_work
                .bridge_refreshes
                .load(Ordering::Acquire)
                >= 1
        );
    }

    #[test]
    fn foreign_only_rebuild_publishes_the_current_owner_map() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);
        let network_name = "foreign-net".to_string();
        let network_secret_digest = [9_u8; 32];
        service.synced_route_info.foreign_network.insert(
            ForeignNetworkRouteInfoKey {
                peer_id: 2,
                network_name: network_name.clone(),
            },
            ForeignNetworkRouteInfoEntry {
                foreign_peer_ids: vec![77],
                version: 1,
                network_secret_digest: network_secret_digest.to_vec(),
                my_peer_id_for_this_network: 88,
                ..Default::default()
            },
        );

        service.rebuild_domains(RouteRebuildDomains::foreign());

        let network = NetworkIdentity {
            network_name,
            network_secret: None,
            network_secret_digest: Some(network_secret_digest),
        };
        assert_eq!(
            service
                .forwarding_snapshot()
                .foreign_network_owner_map
                .get(&network),
            Some(&vec![88])
        );
    }

    #[test]
    fn foreign_owner_key_requires_matching_authenticated_main_owner() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);
        let network_name = "foreign-net".to_string();
        let network_secret_digest = [9_u8; 32];
        let owner_key = vec![7_u8; 32];
        service.synced_route_info.foreign_network.insert(
            ForeignNetworkRouteInfoKey {
                peer_id: 2,
                network_name: network_name.clone(),
            },
            ForeignNetworkRouteInfoEntry {
                foreign_peer_ids: vec![77],
                version: 1,
                network_secret_digest: network_secret_digest.to_vec(),
                my_peer_id_for_this_network: 88,
                owner_noise_static_pubkey: owner_key.clone(),
                ..Default::default()
            },
        );
        service.rebuild_domains(RouteRebuildDomains::foreign());
        let network = NetworkIdentity {
            network_name,
            network_secret: None,
            network_secret_digest: Some(network_secret_digest),
        };

        assert!(
            service
                .authenticated_foreign_network_peers(&network)
                .is_empty()
        );

        service.authenticated_peers.insert(
            2,
            AuthenticatedPeerInfo {
                peer_id: 2,
                identity_type: PeerIdentityType::Admin,
                public_key: vec![8_u8; 32],
                secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
            },
        );
        assert!(
            service
                .authenticated_foreign_network_peers(&network)
                .is_empty()
        );

        service.authenticated_peers.insert(
            2,
            AuthenticatedPeerInfo {
                peer_id: 2,
                identity_type: PeerIdentityType::Admin,
                public_key: owner_key.clone(),
                secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
            },
        );
        assert_eq!(
            service.authenticated_foreign_network_peers(&network),
            vec![(88, owner_key)]
        );
    }

    #[test]
    fn stale_cost_rebuild_escalates_to_one_topology_capture() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);
        let topology_rebuilds = service
            .rebuild_work
            .topology_rebuilds
            .load(Ordering::Acquire);

        service.synced_route_info.version.set(2);
        service.rebuild_domains(RouteRebuildDomains::cost_and_delivery());

        assert_eq!(
            service
                .rebuild_work
                .topology_rebuilds
                .load(Ordering::Acquire),
            topology_rebuilds + 1
        );
        assert_eq!(
            service
                .committed_topology
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .version,
            2
        );
    }

    struct LifecycleCostCalculator {
        begin_seen: mpsc::Sender<()>,
        begin_release: Arc<Barrier>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RouteCostCalculatorInterface for LifecycleCostCalculator {
        fn begin_update(&mut self) {
            self.events.lock().push("begin");
            self.begin_seen
                .send(())
                .expect("the lifecycle test must receive begin_update");
            self.begin_release.wait();
        }

        fn end_update(&mut self) {
            self.events.lock().push("end");
        }

        fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
            self.events.lock().push("calculate");
            1
        }
    }

    #[test]
    fn route_cost_replacement_waits_for_complete_calculator_lifecycle() {
        let service = Arc::new(PeerRouteServiceImpl::new(1, get_mock_global_ctx()));
        seed_snapshot_test_topology(&service, 1);

        let events = Arc::new(Mutex::new(Vec::new()));
        let begin_release = Arc::new(Barrier::new(2));
        let (begin_seen, begin_received) = mpsc::channel();
        *service.cost_calculator.write().unwrap() = Some(Box::new(LifecycleCostCalculator {
            begin_seen,
            begin_release: begin_release.clone(),
            events: events.clone(),
        }));

        let rebuild_service = service.clone();
        let rebuild = thread::spawn(move || {
            rebuild_service.update_route_table_and_cached_local_conn_bitmap();
        });

        begin_received
            .recv_timeout(Duration::from_secs(1))
            .expect("route rebuild must enter begin_update");

        let (replacement_checked, replacement_result) = mpsc::channel();
        let replacement_service = service.clone();
        let replacement_events = events.clone();
        let replacement = thread::spawn(move || {
            let rebuild_is_still_locked =
                replacement_service.route_rebuild_lock.try_lock().is_err();
            replacement_checked
                .send(rebuild_is_still_locked)
                .expect("the lifecycle test must receive replacement status");

            let _rebuild_guard = replacement_service.route_rebuild_lock.lock().unwrap();
            *replacement_service.cost_calculator.write().unwrap() =
                Some(Box::new(DefaultRouteCostCalculator));
            replacement_events.lock().push("replacement");
        });

        assert!(
            replacement_result
                .recv_timeout(Duration::from_secs(1))
                .expect("replacement must attempt the rebuild lock before capture")
        );
        begin_release.wait();

        rebuild.join().expect("route rebuild must complete");
        replacement.join().expect("replacement must complete");

        let events = events.lock().clone();
        let end_index = events
            .iter()
            .position(|event| *event == "end")
            .expect("the original calculator must receive end_update");
        let replacement_index = events
            .iter()
            .position(|event| *event == "replacement")
            .expect("the replacement must install after the rebuild");
        assert_eq!(events.first(), Some(&"begin"));
        assert!(
            events[..end_index]
                .iter()
                .any(|event| *event == "calculate")
        );
        assert!(end_index < replacement_index);
    }

    fn measurement_test_topology(flagged_source: Option<PeerId>) -> TopologyBuildInput {
        let mut graph = super::PeerGraph::new();
        let start = graph.add_node(1);
        let relay = graph.add_node(2);
        let destination = graph.add_node(3);
        graph.add_edge(start, relay, 0);
        graph.add_edge(relay, destination, 0);
        graph.add_edge(start, destination, 0);

        let peer_infos = [1, 2, 3]
            .into_iter()
            .map(|peer_id| {
                let mut info = RoutePeerInfo::new();
                info.peer_id = peer_id;
                info.version = 1;
                if flagged_source == Some(peer_id) {
                    info.feature_flag = Some(PeerFeatureFlag {
                        avoid_relay_data: true,
                        ..Default::default()
                    });
                }
                (peer_id, info)
            })
            .collect();

        TopologyBuildInput {
            version: 1,
            graph,
            start_node: start,
            peer_infos: Arc::new(peer_infos),
            conn_map: Arc::new(HashMap::new()),
            suppressed_peer_ids: Arc::new(HashSet::new()),
            relay_credential_peers: Arc::new(HashSet::new()),
            local_proxy_cidrs: Vec::new(),
        }
    }

    #[test]
    fn admin_adjacency_proves_authorized_credential_reverse_edge() {
        let mut graph = super::PeerGraph::new();
        let admin = graph.add_node(1);
        let authorized = graph.add_node(2);
        let unauthorized = graph.add_node(3);
        let suppressed = graph.add_node(4);
        graph.add_edge(admin, authorized, 0);
        graph.add_edge(admin, unauthorized, 0);
        graph.add_edge(admin, suppressed, 0);
        let node_indices = HashMap::from([
            (1, admin),
            (2, authorized),
            (3, unauthorized),
            (4, suppressed),
        ]);
        let peer_infos = [
            (1, PeerIdentityType::Admin),
            (2, PeerIdentityType::Credential),
            (3, PeerIdentityType::Credential),
            (4, PeerIdentityType::Credential),
        ]
        .into_iter()
        .map(|(peer_id, identity)| {
            let mut info = RoutePeerInfo::new();
            info.peer_id = peer_id;
            info.identity_type = identity as i32;
            (peer_id, info)
        })
        .collect::<HashMap<_, _>>();
        let conn_map = HashMap::from([(
            1,
            super::RouteConnBuildInfo {
                connected_peers: BTreeSet::from([2, 3, 4]),
                version: 1,
            },
        )]);

        add_authorized_relay_reverse_edges(
            &mut graph,
            &node_indices,
            &peer_infos,
            &conn_map,
            &HashSet::from([2, 4]),
            &HashSet::from([4]),
        );

        assert!(graph.find_edge(authorized, admin).is_some());
        assert!(graph.find_edge(unauthorized, admin).is_none());
        assert!(graph.find_edge(suppressed, admin).is_none());
    }

    struct CountingStatefulMeasurements {
        cost_calls: AtomicUsize,
        delivery_calls: AtomicUsize,
    }

    impl RouteCostCalculatorInterface for CountingStatefulMeasurements {
        fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
            (self.cost_calls.fetch_add(1, Ordering::AcqRel) as i32 + 1) * 10
        }

        fn calculate_delivery_bps(&self, _src: PeerId, _dst: PeerId) -> Option<u64> {
            self.delivery_calls.fetch_add(1, Ordering::AcqRel);
            Some(100)
        }
    }

    #[test]
    fn route_measurements_are_captured_once_for_each_active_domain() {
        let topology = measurement_test_topology(None);
        let calculator = CountingStatefulMeasurements {
            cost_calls: AtomicUsize::new(0),
            delivery_calls: AtomicUsize::new(0),
        };
        let measured = topology.with_measurements(&calculator, true, true);

        assert_eq!(calculator.cost_calls.load(Ordering::Acquire), 3);
        assert_eq!(calculator.delivery_calls.load(Ordering::Acquire), 3);
        for edge in measured.graph.edge_references() {
            let speed_edge = measured
                .speed_graph
                .find_edge(edge.source(), edge.target())
                .expect("every measured topology edge has one speed measurement");
            assert_eq!(
                measured.speed_graph[speed_edge].latency_ms,
                *edge.weight() as u64
            );
        }

        let calculator = CountingStatefulMeasurements {
            cost_calls: AtomicUsize::new(0),
            delivery_calls: AtomicUsize::new(0),
        };
        let cost_only = topology.with_measurements(&calculator, true, false);
        assert_eq!(calculator.cost_calls.load(Ordering::Acquire), 3);
        assert_eq!(calculator.delivery_calls.load(Ordering::Acquire), 0);
        assert!(cost_only.speed_graph.edge_count() == 0);

        let calculator = CountingStatefulMeasurements {
            cost_calls: AtomicUsize::new(0),
            delivery_calls: AtomicUsize::new(0),
        };
        let delivery_only = topology.with_measurements(&calculator, false, true);
        assert_eq!(calculator.cost_calls.load(Ordering::Acquire), 3);
        assert_eq!(calculator.delivery_calls.load(Ordering::Acquire), 3);
        assert_eq!(delivery_only.graph.node_count(), 0);
        assert_eq!(delivery_only.speed_graph.edge_count(), 3);
    }

    #[test]
    fn remote_credential_measurements_cannot_select_speed_routes() {
        let mut topology = measurement_test_topology(None);
        let peer_infos = Arc::make_mut(&mut topology.peer_infos);
        peer_infos.get_mut(&2).unwrap().identity_type = PeerIdentityType::Credential as i32;
        let calculator = CountingStatefulMeasurements {
            cost_calls: AtomicUsize::new(0),
            delivery_calls: AtomicUsize::new(0),
        };

        let measured = topology.with_measurements(&calculator, false, true);

        assert_eq!(calculator.cost_calls.load(Ordering::Acquire), 3);
        assert_eq!(calculator.delivery_calls.load(Ordering::Acquire), 2);
        assert!(
            measured
                .speed_graph
                .find_edge(NodeIndex::new(1), NodeIndex::new(2))
                .is_none()
        );
        assert!(
            measured
                .speed_graph
                .find_edge(NodeIndex::new(0), NodeIndex::new(1))
                .is_some()
        );
        assert!(
            measured
                .speed_graph
                .find_edge(NodeIndex::new(0), NodeIndex::new(2))
                .is_some()
        );
    }

    #[test]
    fn authorized_credential_relay_can_publish_speed_measurements() {
        let mut topology = measurement_test_topology(None);
        Arc::make_mut(&mut topology.peer_infos)
            .get_mut(&2)
            .unwrap()
            .identity_type = PeerIdentityType::Credential as i32;
        Arc::make_mut(&mut topology.relay_credential_peers).insert(2);
        let calculator = CountingStatefulMeasurements {
            cost_calls: AtomicUsize::new(0),
            delivery_calls: AtomicUsize::new(0),
        };

        let measured = topology.with_measurements(&calculator, false, true);

        assert_eq!(calculator.delivery_calls.load(Ordering::Acquire), 3);
        assert!(
            measured
                .speed_graph
                .find_edge(NodeIndex::new(1), NodeIndex::new(2))
                .is_some()
        );
    }

    struct FixedSpeedMeasurements;

    impl RouteCostCalculatorInterface for FixedSpeedMeasurements {
        fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
            1
        }

        fn calculate_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
            Some(if src == 1 && dst == 3 { 10 } else { 100 })
        }
    }

    #[test]
    fn max_goodput_keeps_the_first_hop_avoid_relay_exception() {
        let calculator = FixedSpeedMeasurements;
        let relay_avoided = measurement_test_topology(Some(2));
        let measured = relay_avoided.with_measurements(&calculator, false, true);
        let next_hops =
            RouteTable::build_next_hop_map_from_input(&measured, NextHopPolicy::MaxGoodput);
        assert_eq!(next_hops[&3].next_hop_peer_id, 3);
        assert_eq!(next_hops[&3].path_delivery_bps, 10);

        let start_avoided = measurement_test_topology(Some(1));
        let measured = start_avoided.with_measurements(&calculator, false, true);
        let next_hops =
            RouteTable::build_next_hop_map_from_input(&measured, NextHopPolicy::MaxGoodput);
        assert_eq!(next_hops[&3].next_hop_peer_id, 2);
        assert_eq!(next_hops[&3].path_delivery_bps, 100);
    }

    struct HighLatencyMeasurements;

    impl RouteCostCalculatorInterface for HighLatencyMeasurements {
        fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
            if src == 2 && dst == 3 { i32::MAX } else { 1 }
        }

        fn calculate_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
            Some(if src == 1 && dst == 3 { 10 } else { 100 })
        }
    }

    #[test]
    fn max_goodput_does_not_infer_avoid_relay_from_raw_latency() {
        let topology = measurement_test_topology(None);
        let measured = topology.with_measurements(&HighLatencyMeasurements, false, true);
        let next_hops =
            RouteTable::build_next_hop_map_from_input(&measured, NextHopPolicy::MaxGoodput);

        assert_eq!(next_hops[&3].next_hop_peer_id, 2);
        assert_eq!(next_hops[&3].path_delivery_bps, 100);
        assert_eq!(next_hops[&3].path_latency, i32::MAX);
    }

    struct InterleavingCostCalculator {
        service: Arc<PeerRouteServiceImpl>,
        mutated: AtomicBool,
    }

    impl RouteCostCalculatorInterface for InterleavingCostCalculator {
        fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
            if !self.mutated.swap(true, Ordering::AcqRel) {
                let _topology_guard = self.service.synced_route_info.topology_state_lock();
                let mut peer_info = RoutePeerInfo::new();
                peer_info.peer_id = 3;
                peer_info.version = 1;
                self.service
                    .synced_route_info
                    .peer_infos
                    .write()
                    .insert(peer_info.peer_id, peer_info);

                let mut conn_map = self.service.synced_route_info.conn_map.write();
                conn_map
                    .get_mut(&self.service.my_peer_id)
                    .expect("the test topology has a local connection record")
                    .connected_peers
                    .insert(3);
                conn_map.insert(
                    3,
                    make_route_conn_info([self.service.my_peer_id], SystemTime::now()),
                );
                self.service.synced_route_info.version.set(2);
            }
            1
        }
    }

    struct DeliveryInterleavingCostCalculator {
        service: Arc<PeerRouteServiceImpl>,
        mutated: AtomicBool,
    }

    impl RouteCostCalculatorInterface for DeliveryInterleavingCostCalculator {
        fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
            1
        }

        fn calculate_delivery_bps(&self, _src: PeerId, _dst: PeerId) -> Option<u64> {
            if !self.mutated.swap(true, Ordering::AcqRel) {
                let _topology_guard = self.service.synced_route_info.topology_state_lock();
                let mut peer_info = RoutePeerInfo::new();
                peer_info.peer_id = 3;
                peer_info.version = 1;
                self.service
                    .synced_route_info
                    .peer_infos
                    .write()
                    .insert(peer_info.peer_id, peer_info);

                let mut conn_map = self.service.synced_route_info.conn_map.write();
                conn_map
                    .get_mut(&self.service.my_peer_id)
                    .expect("the test topology has a local connection record")
                    .connected_peers
                    .insert(3);
                conn_map.insert(
                    3,
                    make_route_conn_info([self.service.my_peer_id], SystemTime::now()),
                );
                self.service.synced_route_info.version.set(2);
            }
            Some(1)
        }
    }

    #[test]
    fn delivery_callback_topology_mutation_discards_stale_policy() {
        let service = Arc::new(PeerRouteServiceImpl::new(1, get_mock_global_ctx()));
        seed_snapshot_test_topology(&service, 1);
        let topology_rebuilds = service
            .rebuild_work
            .topology_rebuilds
            .load(Ordering::Acquire);
        *service.cost_calculator.write().unwrap() =
            Some(Box::new(DeliveryInterleavingCostCalculator {
                service: service.clone(),
                mutated: AtomicBool::new(false),
            }));

        service.rebuild_domains(RouteRebuildDomains::cost_and_delivery());

        let snapshot = service.forwarding_snapshot();
        assert_eq!(service.synced_route_info.version.get(), 2);
        assert!(
            service
                .rebuild_work
                .topology_rebuilds
                .load(Ordering::Acquire)
                >= topology_rebuilds + 1
        );
        assert!(snapshot.route_table.peer_infos.contains_key(&3));
        assert_eq!(snapshot.route_table.next_hop_map_version, 2);
        assert_eq!(snapshot.route_table_with_cost.next_hop_map_version, 2);
        assert_eq!(snapshot.route_table_with_speed.next_hop_map_version, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn captured_topology_input_keeps_route_tables_coherent() {
        let service = Arc::new(PeerRouteServiceImpl::new(1, get_mock_global_ctx()));
        seed_snapshot_test_topology(&service, 1);
        *service.cost_calculator.write().unwrap() = Some(Box::new(InterleavingCostCalculator {
            service: service.clone(),
            mutated: AtomicBool::new(false),
        }));

        service.update_route_table_and_cached_local_conn_bitmap();

        // The interleaved mutation invalidates the in-flight build; one fresh
        // coherent rebuild publishes the mutated topology instead.
        let snapshot = service.forwarding_snapshot();
        assert_eq!(service.synced_route_info.version.get(), 2);
        assert_eq!(snapshot.route_table.next_hop_map_version, 2);
        assert_eq!(snapshot.route_table_with_cost.next_hop_map_version, 2);
        assert_eq!(snapshot.route_table_with_speed.next_hop_map_version, 2);
        assert!(snapshot.route_table.peer_infos.contains_key(&3));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_map_snapshot_source_receives_latest_generation_under_interface_contention() {
        let global_ctx = get_mock_global_ctx();
        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let peer_map = Arc::new(PeerMap::new(packet_send, global_ctx.clone(), 1));
        // The peer map only ingests publications through its publish hook.
        peer_map.install_forwarding_snapshot_hook();
        let service = PeerRouteServiceImpl::new(1, global_ctx);
        // Stage origin-authority publications into the peer map, like the
        // peer manager interface does in production.
        struct StagingInterface {
            my_peer_id: PeerId,
            peer_map: Arc<PeerMap>,
        }
        #[async_trait::async_trait]
        impl RouteInterface for StagingInterface {
            async fn list_peers(&self) -> Vec<PeerId> {
                Vec::new()
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            fn publish_origin_auth_batch(
                &self,
                source_token: ForwardingSnapshotSourceToken,
                generation: u64,
                publications: &[OriginAuthPublication],
            ) -> Result<(), super::super::route_trait::RouteOriginAuthPublishError> {
                self.peer_map.publish_route_origin_auth_batch(
                    source_token,
                    generation,
                    publications,
                )
            }
        }
        *service.publish_interface.write().unwrap() = Some(Arc::new(StagingInterface {
            my_peer_id: 1,
            peer_map: peer_map.clone(),
        }));
        *service.forwarding_snapshot_source.write().unwrap() =
            Some(peer_map.install_forwarding_snapshot_source().unwrap());

        let interface_guard = service.interface.lock().await;
        let first_generation = service.forwarding_snapshot().generation + 1;
        service.publish_forwarding_snapshot();
        assert_eq!(
            peer_map
                .forwarding_decision_snapshot()
                .await
                .expect("peer map has a published snapshot")
                .generation(),
            first_generation
        );

        let second_generation = first_generation + 1;
        service.publish_forwarding_snapshot();
        assert_eq!(
            peer_map
                .forwarding_decision_snapshot()
                .await
                .expect("peer map keeps the latest snapshot")
                .generation(),
            second_generation
        );
        drop(interface_guard);
    }

    #[test]
    fn forwarding_snapshot_source_rejects_stale_generations_concurrently() {
        fn make_snapshot(generation: u64) -> Arc<ForwardingDecisionSnapshot> {
            ForwardingDecisionSnapshot::from_parts(
                generation,
                Arc::new(super::super::route_trait::ForwardingPeerTable::default()),
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

        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let source = store.register_source().unwrap();
        thread::scope(|scope| {
            for generation in 1..=256 {
                let source = source.clone();
                scope.spawn(move || {
                    let _ = source.publish(make_snapshot(generation));
                });
            }
        });

        assert_eq!(
            store
                .load_full()
                .expect("a concurrent publisher must publish a snapshot")
                .generation(),
            256
        );
    }

    #[test]
    fn forwarding_snapshot_source_replacement_rejects_late_old_publications() {
        fn make_snapshot(generation: u64) -> Arc<ForwardingDecisionSnapshot> {
            ForwardingDecisionSnapshot::from_parts(
                generation,
                Arc::new(super::super::route_trait::ForwardingPeerTable::default()),
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

        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(make_snapshot(50));
        assert_eq!(store.load_full().unwrap().generation(), 50);

        let new_source = store.register_source().unwrap();
        assert!(store.load_full().is_none());
        let _ = old_source.publish(make_snapshot(51));
        assert!(store.load_full().is_none());

        let _ = new_source.publish(make_snapshot(1));
        assert_eq!(store.load_full().unwrap().generation(), 1);
        let _ = new_source.publish(make_snapshot(0));
        assert_eq!(store.load_full().unwrap().generation(), 1);
    }

    #[test]
    fn forwarding_snapshot_source_replacement_is_safe_under_concurrent_publishers() {
        fn make_snapshot(generation: u64) -> Arc<ForwardingDecisionSnapshot> {
            ForwardingDecisionSnapshot::from_parts(
                generation,
                Arc::new(super::super::route_trait::ForwardingPeerTable::default()),
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

        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(make_snapshot(50));
        let new_source = store.register_source().unwrap();
        let barrier = Arc::new(Barrier::new(3));

        thread::scope(|scope| {
            let old_barrier = barrier.clone();
            let old_source = old_source.clone();
            scope.spawn(move || {
                old_barrier.wait();
                let _ = old_source.publish(make_snapshot(51));
            });

            let new_barrier = barrier.clone();
            scope.spawn(move || {
                new_barrier.wait();
                let _ = new_source.publish(make_snapshot(1));
            });

            barrier.wait();
        });

        assert_eq!(store.load_full().unwrap().generation(), 1);
    }

    #[test]
    fn forwarding_snapshot_source_registration_restores_state_on_open_failure() {
        fn make_snapshot(generation: u64) -> Arc<ForwardingDecisionSnapshot> {
            ForwardingDecisionSnapshot::from_parts(
                generation,
                Arc::new(super::super::route_trait::ForwardingPeerTable::default()),
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

        let store = Arc::new(ForwardingDecisionSnapshotStoreInner::new());
        let old_source = store.register_source().unwrap();
        let _ = old_source.publish(make_snapshot(50));
        {
            let registration = store.begin_source_registration().unwrap();
            let _ = registration.source().publish(make_snapshot(1));
            // Dropping the uncommitted registration simulates route.open failure.
        }

        assert_eq!(store.load_full().unwrap().generation(), 50);
        let _ = old_source.publish(make_snapshot(51));
        assert_eq!(store.load_full().unwrap().generation(), 51);
    }

    #[test]
    fn forwarding_snapshot_shares_policy_independent_maps() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 11);

        let snapshot = service.forwarding_snapshot();
        assert_eq!(
            snapshot.route_table.next_hop_map_version,
            snapshot.route_table_with_cost.next_hop_map_version
        );
        assert_eq!(
            snapshot.route_table.next_hop_map_version,
            snapshot.route_table_with_speed.next_hop_map_version
        );
        assert!(Arc::ptr_eq(
            &snapshot.route_table.peer_infos,
            &snapshot.route_table_with_cost.peer_infos
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table.peer_infos,
            &snapshot.route_table_with_speed.peer_infos
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table.suppressed_peer_ids,
            &snapshot.route_table_with_cost.suppressed_peer_ids
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table.ipv4_peer_id_map,
            &snapshot.route_table_with_speed.ipv4_peer_id_map
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table.cidr_peer_id_map,
            &snapshot.route_table_with_cost.cidr_peer_id_map
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table.next_hop_map,
            snapshot
                .decision_snapshot
                .next_hop_map_arc(NextHopPolicy::LeastHop)
        ));
        assert!(Arc::ptr_eq(
            &snapshot.route_table_with_speed.next_hop_map,
            snapshot
                .decision_snapshot
                .next_hop_map_arc(NextHopPolicy::MaxGoodput)
        ));
    }

    #[tokio::test]
    async fn captured_decision_snapshot_keeps_next_hop_after_route_swap() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        seed_snapshot_test_topology(&service, 1);
        let captured = service.forwarding_snapshot().decision_snapshot.clone();
        let captured_next_hop = captured
            .next_hop(2, NextHopPolicy::LeastHop)
            .expect("the captured route has peer 2")
            .next_hop_peer_id;

        let _topology_guard = service.synced_route_info.topology_state_lock();
        {
            let mut peer_infos = service.synced_route_info.peer_infos.write();
            peer_infos.remove(&2);
            let mut replacement = RoutePeerInfo::new();
            replacement.peer_id = 3;
            replacement.version = 1;
            peer_infos.insert(3, replacement);
        }
        {
            let mut conn_map = service.synced_route_info.conn_map.write();
            conn_map.remove(&1);
            conn_map.remove(&2);
            conn_map.insert(1, make_route_conn_info([3], SystemTime::now()));
            conn_map.insert(3, make_route_conn_info([1], SystemTime::now()));
        }
        service.synced_route_info.version.set(2);
        drop(_topology_guard);
        service.update_route_table_and_cached_local_conn_bitmap();

        let current = service.forwarding_snapshot().decision_snapshot.clone();
        assert_eq!(captured.generation() + 1, current.generation());
        assert_eq!(
            captured
                .next_hop(2, NextHopPolicy::LeastHop)
                .expect("captured state remains immutable")
                .next_hop_peer_id,
            captured_next_hop
        );
        assert!(current.next_hop(2, NextHopPolicy::LeastHop).is_none());
        for _ in 0..32 {
            assert_eq!(
                captured
                    .next_hop(2, NextHopPolicy::LeastHop)
                    .expect("captured route remains available to the batch")
                    .next_hop_peer_id,
                captured_next_hop
            );
        }
    }

    #[test]
    fn concurrent_route_updates_publish_one_topology_version() {
        let service = Arc::new(PeerRouteServiceImpl::new(1, get_mock_global_ctx()));
        seed_snapshot_test_topology(&service, 1);

        let reader_service = service.clone();
        let failed = Arc::new(AtomicBool::new(false));
        let reader_failed = failed.clone();
        let reader = thread::spawn(move || {
            for _ in 0..5_000 {
                let snapshot = reader_service.forwarding_snapshot();
                let versions = [
                    snapshot.route_table.next_hop_map_version,
                    snapshot.route_table_with_cost.next_hop_map_version,
                    snapshot.route_table_with_speed.next_hop_map_version,
                ];
                if versions[0] != versions[1] || versions[0] != versions[2] {
                    reader_failed.store(true, Ordering::Release);
                    return;
                }
                for route_table in [
                    &snapshot.route_table,
                    &snapshot.route_table_with_cost,
                    &snapshot.route_table_with_speed,
                ] {
                    if route_table
                        .next_hop_map
                        .values()
                        .any(|route| route.version != route_table.next_hop_map_version)
                    {
                        reader_failed.store(true, Ordering::Release);
                        return;
                    }
                }
            }
        });

        for cycle in 0..200_u32 {
            let version = cycle + 2;
            let _topology_guard = service.synced_route_info.topology_state_lock();
            {
                let mut peer_infos = service.synced_route_info.peer_infos.write();
                let peer_id = if cycle % 2 == 0 { 2 } else { 3 };
                let mut peer_info = RoutePeerInfo::new();
                peer_info.peer_id = peer_id;
                peer_info.version = 1;
                peer_infos.remove(&2);
                peer_infos.remove(&3);
                peer_infos.insert(peer_id, peer_info);
            }
            {
                let mut conn_map = service.synced_route_info.conn_map.write();
                let peer_id = if cycle % 2 == 0 { 2 } else { 3 };
                conn_map.remove(&2);
                conn_map.remove(&3);
                conn_map.insert(
                    service.my_peer_id,
                    make_route_conn_info([peer_id], SystemTime::now()),
                );
                conn_map.insert(
                    peer_id,
                    make_route_conn_info([service.my_peer_id], SystemTime::now()),
                );
            }
            service.synced_route_info.version.set(version);
            drop(_topology_guard);
            service.update_route_table_and_cached_local_conn_bitmap();
        }

        reader.join().unwrap();
        assert!(!failed.load(Ordering::Acquire));
    }

    #[test]
    fn concurrent_capture_and_credential_update_completes() {
        const NETWORK_SECRET: &str = "capture-lock-test";
        let service = Arc::new(PeerRouteServiceImpl::new(
            1,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "capture-lock-net".to_string(),
                NETWORK_SECRET.to_string(),
            ))),
        ));
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let admin_info = make_admin_route_peer_info(
            service.global_ctx.get_credential_manager(),
            30,
            &[17; 32],
            NETWORK_SECRET,
            now,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);
        let first_peer = make_credential_route_peer_info(39, &credential_key);
        let second_peer = make_credential_route_peer_info(41, &credential_key);
        let mut self_info = RoutePeerInfo::new();
        self_info.peer_id = 1;
        self_info.version = 1;

        {
            let _topology_guard = service.synced_route_info.topology_state_lock();
            let mut peer_infos = service.synced_route_info.peer_infos.write();
            peer_infos.insert(self_info.peer_id, self_info);
            peer_infos.insert(admin_info.peer_id, admin_info);
            peer_infos.insert(first_peer.peer_id, first_peer);
            peer_infos.insert(second_peer.peer_id, second_peer);
            drop(peer_infos);

            let mut conn_map = service.synced_route_info.conn_map.write();
            conn_map.insert(1, make_route_conn_info([30, 39, 41], SystemTime::now()));
            conn_map.insert(30, make_route_conn_info([1, 39, 41], SystemTime::now()));
            conn_map.insert(39, make_route_conn_info([30], SystemTime::now()));
            conn_map.insert(41, make_route_conn_info([30], SystemTime::now()));
            service.synced_route_info.version.set(1);
        }

        let (capture_done_tx, capture_done_rx) = mpsc::channel();
        let capture_service = service.clone();
        let capture_thread = thread::spawn(move || {
            for _ in 0..100 {
                capture_service.update_route_table_and_cached_local_conn_bitmap();
            }
            capture_done_tx.send(()).unwrap();
        });

        let (credential_done_tx, credential_done_rx) = mpsc::channel();
        let credential_service = service.clone();
        let credential_thread = thread::spawn(move || {
            for _ in 0..100 {
                let _ = credential_service
                    .synced_route_info
                    .verify_and_update_credential_trusts_with_active_peers(
                        Some(NETWORK_SECRET),
                        |_| true,
                    );
            }
            credential_done_tx.send(()).unwrap();
        });

        assert!(capture_done_rx.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(
            credential_done_rx
                .recv_timeout(Duration::from_secs(5))
                .is_ok()
        );
        capture_thread.join().unwrap();
        credential_thread.join().unwrap();
        assert!(service.synced_route_info.is_route_suppressed(41));
    }

    #[test]
    fn route_session_reset_clears_saved_foreign_network_versions() {
        let session = SyncRouteSession::new(10, 20);
        let key = ForeignNetworkRouteInfoKey {
            peer_id: 30,
            network_name: "net1".to_string(),
        };
        session
            .dst_saved_foreign_network_versions
            .entry(key)
            .or_default()
            .set_if_larger(7);

        session.update_dst_session_id(1);

        assert!(session.dst_saved_foreign_network_versions.is_empty());
    }

    #[test]
    fn multicast_group_normalization_filters_and_bounds_input() {
        let mut route = RoutePeerInfo::new();
        route.multicast_groups = vec![
            vec![239, 1, 2, 3],
            vec![239, 1, 2, 3],
            vec![10, 1, 2, 3],
            "ff02::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            vec![0; 15],
        ];
        for group in 0..300_u16 {
            route
                .multicast_groups
                .push(vec![239, 2, (group >> 8) as u8, group as u8]);
        }

        route.normalize_multicast_groups();

        assert_eq!(route.multicast_groups.len(), 256);
        assert!(
            route
                .multicast_groups
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(route.multicast_groups.iter().all(|group| {
            match group.as_slice() {
                [a, b, c, d] => std::net::Ipv4Addr::from([*a, *b, *c, *d]).is_multicast(),
                bytes if bytes.len() == 16 => <[u8; 16]>::try_from(bytes)
                    .ok()
                    .map(std::net::Ipv6Addr::from)
                    .is_some_and(|address| address.is_multicast()),
                _ => false,
            }
        }));
    }

    #[tokio::test]
    async fn authenticated_seed_completes_existing_peer_security_features() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let public_key = vec![7; 32];
        let mut peer_info = RoutePeerInfo::new();
        peer_info.peer_id = 2;
        peer_info.noise_static_pubkey = public_key.clone();
        service
            .synced_route_info
            .peer_infos
            .write()
            .insert(2, peer_info);

        assert_eq!(
            service.seed_authenticated_peer(
                2,
                PeerIdentityType::Admin,
                public_key,
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
            super::AuthenticatedPeerSeedResult::Inserted
        );

        let peer_infos = service.synced_route_info.peer_infos.read();
        let features = peer_infos
            .get(&2)
            .and_then(|peer| peer.feature_flag.as_ref())
            .expect("the authenticated seed must publish security features");
        assert!(features.relay_origin_proof);
        assert!(!features.is_credential_peer);
    }

    #[tokio::test]
    async fn authenticated_seed_expires_when_the_direct_interface_disappears() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        assert_eq!(
            service.seed_authenticated_peer(
                2,
                PeerIdentityType::Admin,
                vec![7; 32],
                SecureAuthLevel::PeerVerified,
            ),
            super::AuthenticatedPeerSeedResult::Inserted
        );

        let connected_peers = BTreeSet::new();
        assert!(service.retain_authenticated_interface_peers(&connected_peers));
        assert!(!service.authenticated_peers.contains_key(&2));
    }

    #[test]
    fn widest_path_keeps_forward_and_reverse_choices_independent() {
        let mut graph = SpeedGraph::new();
        let a = graph.add_node(1);
        let b = graph.add_node(2);
        let c = graph.add_node(3);
        graph.add_edge(
            a,
            c,
            SpeedEdge {
                delivery_bps: 5_000_000,
                latency_ms: 100,
            },
        );
        graph.add_edge(
            a,
            b,
            SpeedEdge {
                delivery_bps: 20_000_000,
                latency_ms: 40,
            },
        );
        graph.add_edge(
            b,
            c,
            SpeedEdge {
                delivery_bps: 25_000_000,
                latency_ms: 40,
            },
        );
        graph.add_edge(
            c,
            a,
            SpeedEdge {
                delivery_bps: 30_000_000,
                latency_ms: 70,
            },
        );
        graph.add_edge(
            c,
            b,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 30,
            },
        );
        graph.add_edge(
            b,
            a,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 30,
            },
        );

        let from_a = widest_path_with_first_hop(&graph, a);
        let from_c = widest_path_with_first_hop(&graph, c);

        assert_eq!(from_a[&c].next_hop_peer_id, 2);
        assert_eq!(from_a[&c].quality.delivery_bps, 20_000_000);
        assert_eq!(from_c[&a].next_hop_peer_id, 1);
        assert_eq!(from_c[&a].quality.delivery_bps, 30_000_000);
    }

    #[test]
    fn widest_path_uses_latency_hops_and_peer_id_tie_breakers() {
        let mut graph = SpeedGraph::new();
        let a = graph.add_node(1);
        let b = graph.add_node(2);
        let c = graph.add_node(3);
        let d = graph.add_node(4);
        let e = graph.add_node(5);
        for (source, target, latency_ms) in
            [(a, b, 20), (b, e, 20), (a, c, 10), (c, d, 10), (d, e, 10)]
        {
            graph.add_edge(
                source,
                target,
                SpeedEdge {
                    delivery_bps: 10_000_000,
                    latency_ms,
                },
            );
        }
        let routes = widest_path_with_first_hop(&graph, a);
        assert_eq!(routes[&e].next_hop_peer_id, 3);

        graph.update_edge(
            a,
            c,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 20,
            },
        );
        graph.update_edge(
            c,
            d,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 20,
            },
        );
        let routes = widest_path_with_first_hop(&graph, a);
        assert_eq!(routes[&e].next_hop_peer_id, 2);

        let f = graph.add_node(6);
        graph.add_edge(
            a,
            f,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 20,
            },
        );
        graph.add_edge(
            f,
            e,
            SpeedEdge {
                delivery_bps: 10_000_000,
                latency_ms: 20,
            },
        );
        let routes = widest_path_with_first_hop(&graph, a);
        assert_eq!(routes[&e].next_hop_peer_id, 2);
    }

    #[test]
    fn widest_path_budget_rejects_exhaustion_without_partial_routes() {
        let mut graph = SpeedGraph::new();
        let start = graph.add_node(1);
        let middle = graph.add_node(2);
        let destination = graph.add_node(3);
        graph.add_edge(
            start,
            middle,
            SpeedEdge {
                delivery_bps: 100,
                latency_ms: 1,
            },
        );
        graph.add_edge(
            middle,
            destination,
            SpeedEdge {
                delivery_bps: 80,
                latency_ms: 1,
            },
        );

        let preparation = prepare_widest_path(&graph, start);
        assert_eq!(preparation.destinations.len(), 2);
        assert_eq!(preparation.minimum_delivery_bps, Some(80));
        assert_eq!(preparation.active_edge_count, 2);
        let work_limit = widest_path_work_limit(graph.node_count(), graph.edge_count()).unwrap();
        let mut budget =
            WidestPathWorkBudget::with_used(preparation.capacity_work, preparation.capacity_work)
                .unwrap();
        let mut work_stats = super::WidestPathWorkStats::default();
        assert!(widest_path_with_preparation(
            &graph,
            start,
            &preparation,
            &mut budget,
            &mut work_stats,
        )
        .is_err());
        assert!(budget.used <= preparation.capacity_work);
        assert!(work_limit >= preparation.capacity_work);
    }

    #[test]
    fn widest_path_recalculates_latency_after_a_later_bottleneck() {
        let mut graph = SpeedGraph::new();
        let a = graph.add_node(1);
        let b = graph.add_node(2);
        let c = graph.add_node(3);
        let d = graph.add_node(4);
        let e = graph.add_node(5);
        graph.add_edge(
            a,
            b,
            SpeedEdge {
                delivery_bps: 100,
                latency_ms: 1_000,
            },
        );
        graph.add_edge(
            b,
            d,
            SpeedEdge {
                delivery_bps: 100,
                latency_ms: 1_000,
            },
        );
        graph.add_edge(
            a,
            c,
            SpeedEdge {
                delivery_bps: 50,
                latency_ms: 1,
            },
        );
        graph.add_edge(
            c,
            d,
            SpeedEdge {
                delivery_bps: 50,
                latency_ms: 1,
            },
        );
        graph.add_edge(
            d,
            e,
            SpeedEdge {
                delivery_bps: 10,
                latency_ms: 1,
            },
        );

        let routes = widest_path_with_first_hop(&graph, a);

        assert_eq!(routes[&e].quality.delivery_bps, 10);
        assert_eq!(routes[&e].quality.latency_ms, 3);
        assert_eq!(routes[&e].next_hop_peer_id, 3);
    }

    #[test]
    fn widest_path_forwarding_has_no_cross_source_loops() {
        // This graph is a cross-source forwarding-loop regression case.
        // Every source must reach every destination without repeating a node.
        let mut graph = SpeedGraph::new();
        let nodes: Vec<_> = (0..5).map(|peer_id| graph.add_node(peer_id)).collect();
        for (source, target, delivery_bps, latency_ms) in [
            (0, 2, 3, 10),
            (0, 3, 3, 2),
            (0, 4, 1, 1),
            (1, 0, 100, 0),
            (1, 2, 3, 1),
            (1, 4, 100, 3),
            (2, 1, 10, 100),
            (2, 4, 3, 1_000),
            (3, 0, 10, 3),
            (3, 1, 10, 1_000),
            (3, 4, 5, 5),
            (4, 1, 20, 0),
        ] {
            graph.add_edge(
                nodes[source],
                nodes[target],
                SpeedEdge {
                    delivery_bps,
                    latency_ms,
                },
            );
        }

        let routes_by_source: HashMap<_, _> = nodes
            .iter()
            .map(|source| (*source, widest_path_with_first_hop(&graph, *source)))
            .collect();
        let node_by_peer: HashMap<_, _> = nodes.iter().map(|node| (graph[*node], *node)).collect();

        for source in &nodes {
            for destination in &nodes {
                if source == destination {
                    continue;
                }
                let mut current = *source;
                let mut visited = HashSet::new();
                for _ in 0..=graph.node_count() {
                    if current == *destination {
                        break;
                    }
                    assert!(
                        visited.insert(current),
                        "forwarding loop from {} to {} at {}",
                        graph[*source],
                        graph[*destination],
                        graph[current]
                    );
                    let route = routes_by_source
                        .get(&current)
                        .and_then(|routes| routes.get(destination))
                        .unwrap_or_else(|| {
                            panic!(
                                "missing route from {} to {}",
                                graph[current], graph[*destination]
                            )
                        });
                    current = *node_by_peer
                        .get(&route.next_hop_peer_id)
                        .unwrap_or_else(|| panic!("unknown next hop {}", route.next_hop_peer_id));
                }
                assert_eq!(
                    current, *destination,
                    "route from {} to {} did not terminate",
                    graph[*source], graph[*destination]
                );
            }
        }
    }

    #[test]
    fn widest_path_incremental_matches_full_threshold_oracle() {
        fn oracle_widest_path(
            graph: &SpeedGraph,
            start: petgraph::graph::NodeIndex,
        ) -> HashMap<petgraph::graph::NodeIndex, super::SpeedPath> {
            let mut capacities = HashMap::new();
            let mut pending = BinaryHeap::new();
            capacities.insert(start, u64::MAX);
            pending.push((u64::MAX, Reverse(start.index())));
            while let Some((capacity, Reverse(node_index))) = pending.pop() {
                let node = petgraph::graph::NodeIndex::new(node_index);
                if capacities.get(&node).copied() != Some(capacity) {
                    continue;
                }
                for edge in graph.edges(node) {
                    let target = edge.target();
                    let next_capacity = capacity.min(edge.weight().delivery_bps);
                    if next_capacity == 0
                        || capacities
                            .get(&target)
                            .is_some_and(|current| *current >= next_capacity)
                    {
                        continue;
                    }
                    capacities.insert(target, next_capacity);
                    pending.push((next_capacity, Reverse(target.index())));
                }
            }

            let mut nodes_by_capacity = BTreeMap::<u64, Vec<_>>::new();
            for (node, capacity) in capacities {
                if node != start && capacity > 0 {
                    nodes_by_capacity.entry(capacity).or_default().push(node);
                }
            }

            let mut routes = HashMap::new();
            for (capacity, nodes) in nodes_by_capacity {
                let mut labels = vec![None; graph.node_count()];
                let mut queue = BinaryHeap::new();
                labels[start.index()] = Some((0_u64, 0_usize, graph[start]));
                queue.push(Reverse((0_u64, 0_usize, graph[start], start.index())));
                while let Some(Reverse((latency_ms, hops, first_hop_peer_id, node_index))) =
                    queue.pop()
                {
                    let node = petgraph::graph::NodeIndex::new(node_index);
                    if labels[node.index()] != Some((latency_ms, hops, first_hop_peer_id)) {
                        continue;
                    }
                    for edge in graph.edges(node) {
                        if edge.weight().delivery_bps < capacity {
                            continue;
                        }
                        let target = edge.target();
                        let candidate = (
                            latency_ms.saturating_add(edge.weight().latency_ms),
                            hops.saturating_add(1),
                            if node == start {
                                graph[target]
                            } else {
                                first_hop_peer_id
                            },
                        );
                        if labels[target.index()].is_some_and(|current| current <= candidate) {
                            continue;
                        }
                        labels[target.index()] = Some(candidate);
                        queue.push(Reverse((
                            candidate.0,
                            candidate.1,
                            candidate.2,
                            target.index(),
                        )));
                    }
                }
                for node in nodes {
                    if let Some((latency_ms, hops, next_hop_peer_id)) = labels[node.index()] {
                        routes.insert(
                            node,
                            super::SpeedPath {
                                next_hop_peer_id,
                                quality: RouteQuality {
                                    delivery_bps: capacity,
                                    latency_ms,
                                    hops,
                                },
                            },
                        );
                    }
                }
            }
            routes
        }

        fn measure_case(name: &str, graph: SpeedGraph, start: petgraph::graph::NodeIndex) {
            let incremental_start = StdInstant::now();
            let (incremental_routes, work) = widest_path_with_work_stats(&graph, start);
            let incremental_elapsed = incremental_start.elapsed();
            let oracle_start = StdInstant::now();
            let oracle_routes = oracle_widest_path(&graph, start);
            let oracle_elapsed = oracle_start.elapsed();

            assert_eq!(
                incremental_routes, oracle_routes,
                "route mismatch for {name}"
            );
            println!(
                "widest_work topology={name} nodes={} edges={} sorted_edge_capacity={} active_edges={} active_outer_capacity={} active_inner_capacity={} newly_reachable={} labels={} label_capacity={} queue={} queue_capacity={} finalized_capacity={} widest_capacity_capacity={} thresholds={} destination_capacity={} routes={} route_capacity={} activation_rounds={} activated_edges={} capacity_scans={} relaxations={} scanned_edges={} finalization_visits={} estimated_memory_bytes={} incremental_elapsed_us={} oracle_elapsed_us={}",
                graph.node_count(),
                graph.edge_count(),
                work.sorted_edge_capacity,
                work.peak_active_edges,
                work.peak_active_outer_capacity,
                work.peak_active_inner_capacity,
                work.peak_newly_reachable,
                work.peak_label_count,
                work.label_capacity,
                work.peak_queue_len,
                work.peak_queue_capacity,
                work.finalized_capacity,
                work.widest_capacity_capacity,
                work.threshold_count,
                work.destination_capacity,
                work.peak_route_count,
                work.peak_route_capacity,
                work.activation_rounds,
                work.activated_edges,
                work.capacity_edge_scans,
                work.label_relaxations,
                work.scanned_edges,
                work.finalization_visits,
                work.estimated_peak_temp_bytes(graph.node_count()),
                incremental_elapsed.as_micros(),
                oracle_elapsed.as_micros(),
            );
        }

        let mut sparse = SpeedGraph::new();
        let sparse_nodes: Vec<_> = (0..32).map(|peer_id| sparse.add_node(peer_id)).collect();
        for index in 0..31 {
            sparse.add_edge(
                sparse_nodes[index],
                sparse_nodes[index + 1],
                SpeedEdge {
                    delivery_bps: 1_000_000 - index as u64 * 1_000,
                    latency_ms: 2,
                },
            );
            sparse.add_edge(
                sparse_nodes[index + 1],
                sparse_nodes[index],
                SpeedEdge {
                    delivery_bps: 500_000 + index as u64 * 1_000,
                    latency_ms: 3,
                },
            );
        }
        measure_case("sparse", sparse, sparse_nodes[0]);

        let mut dense = SpeedGraph::new();
        let dense_nodes: Vec<_> = (0..24).map(|peer_id| dense.add_node(peer_id)).collect();
        for source in 0..24 {
            for target in 0..24 {
                if source == target {
                    continue;
                }
                dense.add_edge(
                    dense_nodes[source],
                    dense_nodes[target],
                    SpeedEdge {
                        delivery_bps: 1_000_000 + ((source * 37 + target * 13) % 29) as u64,
                        latency_ms: 1 + ((source + target) % 7) as u64,
                    },
                );
            }
        }
        measure_case("dense", dense, dense_nodes[0]);

        let mut asymmetric = SpeedGraph::new();
        let asymmetric_nodes: Vec<_> = (0..6).map(|peer_id| asymmetric.add_node(peer_id)).collect();
        for (source, target, delivery_bps, latency_ms) in [
            (0, 1, 100, 10),
            (1, 0, 5, 1),
            (0, 2, 80, 2),
            (2, 0, 40, 8),
            (1, 3, 70, 3),
            (3, 1, 20, 4),
            (2, 3, 60, 4),
            (3, 2, 30, 2),
            (3, 4, 50, 5),
            (4, 3, 10, 1),
            (4, 5, 25, 6),
            (5, 4, 15, 2),
            (2, 5, 12, 20),
            (5, 1, 9, 2),
        ] {
            asymmetric.add_edge(
                asymmetric_nodes[source],
                asymmetric_nodes[target],
                SpeedEdge {
                    delivery_bps,
                    latency_ms,
                },
            );
        }
        measure_case("asymmetric", asymmetric, asymmetric_nodes[0]);

        let mut many_capacities = SpeedGraph::new();
        let many_capacity_nodes: Vec<_> = (0..64)
            .map(|peer_id| many_capacities.add_node(peer_id))
            .collect();
        for index in 0..63 {
            many_capacities.add_edge(
                many_capacity_nodes[index],
                many_capacity_nodes[index + 1],
                SpeedEdge {
                    delivery_bps: 2_000_000 - index as u64 * 1_000,
                    latency_ms: 1,
                },
            );
        }
        measure_case("many-capacities", many_capacities, many_capacity_nodes[0]);

        let mut many_edge_rates_few_destinations = SpeedGraph::new();
        let source = many_edge_rates_few_destinations.add_node(1);
        let first_destination = many_edge_rates_few_destinations.add_node(2);
        let second_destination = many_edge_rates_few_destinations.add_node(3);
        many_edge_rates_few_destinations.add_edge(
            source,
            first_destination,
            SpeedEdge {
                delivery_bps: 100,
                latency_ms: 1,
            },
        );
        many_edge_rates_few_destinations.add_edge(
            first_destination,
            second_destination,
            SpeedEdge {
                delivery_bps: 50,
                latency_ms: 1,
            },
        );
        let unreachable: Vec<_> = (0..128)
            .map(|index| many_edge_rates_few_destinations.add_node(index as PeerId + 10))
            .collect();
        for index in 0..unreachable.len() - 1 {
            many_edge_rates_few_destinations.add_edge(
                unreachable[index],
                unreachable[index + 1],
                SpeedEdge {
                    delivery_bps: 1_000 + index as u64,
                    latency_ms: 1,
                },
            );
        }
        let (_, work) = widest_path_with_work_stats(&many_edge_rates_few_destinations, source);
        assert_eq!(work.threshold_count, 2);
        assert_eq!(work.activation_rounds, 2);
        assert_eq!(work.peak_active_edges, 2);

        for seed in [0x51a7_2d31_u64, 0x9e37_79b9_u64, 0xd1b5_4a32_u64] {
            let mut graph = SpeedGraph::with_capacity(20, 96);
            let nodes: Vec<_> = (0..20)
                .map(|peer_id| graph.add_node(peer_id as PeerId + 1))
                .collect();
            let mut random = seed;
            for source in 0..12 {
                for target in 0..12 {
                    if source == target {
                        continue;
                    }
                    random = random
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    if random % 5 != 0 {
                        continue;
                    }
                    let delivery_bps = 10 + ((random >> 16) % 7) * 10;
                    let latency_ms = if random & 1 == 0 {
                        0
                    } else {
                        (random >> 24) % 9
                    };
                    graph.add_edge(
                        nodes[source],
                        nodes[target],
                        SpeedEdge {
                            delivery_bps,
                            latency_ms,
                        },
                    );
                }
            }
            // Explicit parallel edges, ties, and zero-latency links.
            graph.add_edge(
                nodes[0],
                nodes[1],
                SpeedEdge {
                    delivery_bps: 100,
                    latency_ms: 0,
                },
            );
            graph.add_edge(
                nodes[0],
                nodes[1],
                SpeedEdge {
                    delivery_bps: 100,
                    latency_ms: 2,
                },
            );
            graph.add_edge(
                nodes[1],
                nodes[2],
                SpeedEdge {
                    delivery_bps: 80,
                    latency_ms: 0,
                },
            );
            graph.add_edge(
                nodes[2],
                nodes[3],
                SpeedEdge {
                    delivery_bps: 40,
                    latency_ms: 1,
                },
            );
            graph.add_edge(
                nodes[0],
                nodes[3],
                SpeedEdge {
                    delivery_bps: 40,
                    latency_ms: 5,
                },
            );
            // Keep a disconnected component with higher rates out of the route.
            for index in 12..19 {
                graph.add_edge(
                    nodes[index],
                    nodes[index + 1],
                    SpeedEdge {
                        delivery_bps: 1_000 - (index as u64 - 12) * 10,
                        latency_ms: 0,
                    },
                );
            }
            measure_case(&format!("seed-{seed:x}"), graph, nodes[0]);
        }
    }

    #[test]
    fn widest_path_near_limit_work_and_memory_are_bounded() {
        let node_count = MAX_ROUTE_SYNC_PEERS;
        let mut graph = SpeedGraph::with_capacity(node_count, node_count * 2);
        let nodes: Vec<_> = (0..node_count)
            .map(|index| graph.add_node(index as PeerId + 1))
            .collect();
        for index in 0..node_count - 1 {
            graph.add_edge(
                nodes[index],
                nodes[index + 1],
                SpeedEdge {
                    delivery_bps: (node_count - index) as u64,
                    latency_ms: 1,
                },
            );
            if index + 2 < node_count {
                graph.add_edge(
                    nodes[index],
                    nodes[index + 2],
                    SpeedEdge {
                        delivery_bps: (node_count - index - 1) as u64,
                        latency_ms: 2,
                    },
                );
            }
        }

        let started = StdInstant::now();
        let (routes, work) = widest_path_with_work_stats(&graph, nodes[0]);
        let elapsed = started.elapsed();
        assert_eq!(routes.len(), node_count - 1);
        assert_eq!(work.finalization_visits, node_count - 1);
        assert!(work.sorted_edge_capacity <= graph.edge_count());
        assert!(work.peak_active_edges <= work.sorted_edge_capacity);
        assert!(work.peak_active_inner_capacity >= work.peak_active_edges);
        assert!(work.destination_capacity >= routes.len());
        assert!(work.threshold_count <= routes.len());
        println!(
            "widest_near_limit nodes={} edges={} sorted_edge_capacity={} active_edges={} active_outer_capacity={} active_inner_capacity={} newly_reachable={} labels={} label_capacity={} queue={} queue_capacity={} finalized_capacity={} widest_capacity_capacity={} thresholds={} destination_capacity={} routes={} route_capacity={} activation_rounds={} relaxations={} scanned_edges={} capacity_scans={} finalization_visits={} estimated_memory_bytes={} elapsed_us={}",
            graph.node_count(),
            graph.edge_count(),
            work.sorted_edge_capacity,
            work.peak_active_edges,
            work.peak_active_outer_capacity,
            work.peak_active_inner_capacity,
            work.peak_newly_reachable,
            work.peak_label_count,
            work.label_capacity,
            work.peak_queue_len,
            work.peak_queue_capacity,
            work.finalized_capacity,
            work.widest_capacity_capacity,
            work.threshold_count,
            work.destination_capacity,
            work.peak_route_count,
            work.peak_route_capacity,
            work.activation_rounds,
            work.label_relaxations,
            work.scanned_edges,
            work.capacity_edge_scans,
            work.finalization_visits,
            work.estimated_peak_temp_bytes(graph.node_count()),
            elapsed.as_micros(),
        );
    }

    #[test]
    fn widest_path_dense_core_descending_gates_reports_work_evidence() {
        let node_count = 128_usize;
        let mut graph = SpeedGraph::with_capacity(
            node_count,
            node_count.saturating_mul(node_count.saturating_sub(1)),
        );
        let nodes: Vec<_> = (0..node_count)
            .map(|index| graph.add_node(index as PeerId + 1))
            .collect();
        for source in 0..node_count {
            for target in 0..node_count {
                if source == target {
                    continue;
                }
                graph.add_edge(
                    nodes[source],
                    nodes[target],
                    SpeedEdge {
                        // Descending gates create one capacity class per
                        // reachable core destination.
                        delivery_bps: ((node_count - target) * 1_000 + (node_count - source))
                            as u64,
                        latency_ms: 1 + ((source + target) % 5) as u64,
                    },
                );
            }
        }

        let started = StdInstant::now();
        let (routes, work) = widest_path_with_work_stats(&graph, nodes[0]);
        let elapsed = started.elapsed();
        assert_eq!(routes.len(), node_count - 1);
        assert!(work.threshold_count > 1);
        assert!(
            work.capacity_edge_scans <= graph.edge_count().saturating_mul(work.threshold_count)
        );
        assert!(work.peak_queue_capacity >= work.peak_queue_len);
        assert!(work.estimated_peak_temp_bytes(graph.node_count()) > 0);
        println!(
            "widest_dense_descending_gates nodes={} edges={} thresholds={} capacity_scans={} relaxations={} scanned_edges={} queue={} queue_capacity={} memory_bytes={} elapsed_us={}",
            graph.node_count(),
            graph.edge_count(),
            work.threshold_count,
            work.capacity_edge_scans,
            work.label_relaxations,
            work.scanned_edges,
            work.peak_queue_len,
            work.peak_queue_capacity,
            work.estimated_peak_temp_bytes(graph.node_count()),
            elapsed.as_micros(),
        );
    }

    #[test]
    fn widest_path_handles_representative_graph_matrix() {
        for node_count in [8_usize, 32, 128] {
            let mut graph = SpeedGraph::new();
            let nodes: Vec<_> = (0..node_count)
                .map(|index| graph.add_node((index + 1) as PeerId))
                .collect();
            for index in 0..node_count - 1 {
                graph.add_edge(
                    nodes[index],
                    nodes[index + 1],
                    SpeedEdge {
                        delivery_bps: 100_000_000 - index as u64 * 1_000,
                        latency_ms: 2,
                    },
                );
                graph.add_edge(
                    nodes[index + 1],
                    nodes[index],
                    SpeedEdge {
                        delivery_bps: 50_000_000 + index as u64 * 1_000,
                        latency_ms: 3,
                    },
                );
            }

            let forward = widest_path_with_first_hop(&graph, nodes[0]);
            let reverse = widest_path_with_first_hop(&graph, nodes[node_count - 1]);

            assert_eq!(graph.edge_count(), 2 * (node_count - 1));
            assert_eq!(forward.len(), node_count - 1);
            assert_eq!(reverse.len(), node_count - 1);
            assert!(
                forward
                    .values()
                    .all(|path| path.next_hop_peer_id == graph[nodes[1]])
            );
            assert!(
                reverse
                    .values()
                    .all(|path| { path.next_hop_peer_id == graph[nodes[node_count - 2]] })
            );
        }

        for node_count in [8_usize, 24, 48] {
            let mut graph = SpeedGraph::new();
            let nodes: Vec<_> = (0..node_count)
                .map(|index| graph.add_node((index + 1) as PeerId))
                .collect();
            for source in 0..node_count {
                for target in 0..node_count {
                    if source == target {
                        continue;
                    }
                    graph.add_edge(
                        nodes[source],
                        nodes[target],
                        SpeedEdge {
                            delivery_bps: 100_000_000,
                            latency_ms: 1,
                        },
                    );
                }
            }

            let routes = widest_path_with_first_hop(&graph, nodes[0]);

            assert_eq!(graph.edge_count(), node_count * (node_count - 1));
            assert_eq!(routes.len(), node_count - 1);
            for target in nodes.iter().skip(1) {
                assert_eq!(routes[target].next_hop_peer_id, graph[*target]);
                assert_eq!(routes[target].quality.hops, 1);
            }
        }
    }

    struct AuthOnlyInterface {
        my_peer_id: PeerId,
        identity_type: DashMap<PeerId, PeerIdentityType>,
        peer_public_key: DashMap<PeerId, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl RouteInterface for AuthOnlyInterface {
        async fn list_peers(&self) -> Vec<PeerId> {
            Vec::new()
        }

        fn my_peer_id(&self) -> PeerId {
            self.my_peer_id
        }

        async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
            self.peer_public_key
                .get(&peer_id)
                .map(|x| x.value().clone())
        }

        async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
            self.identity_type.get(&peer_id).map(|x| *x.value())
        }
    }

    struct TrackingInterface {
        my_peer_id: PeerId,
        closed_peers: Arc<Mutex<Vec<PeerId>>>,
    }

    #[async_trait::async_trait]
    impl RouteInterface for TrackingInterface {
        async fn list_peers(&self) -> Vec<PeerId> {
            Vec::new()
        }

        fn my_peer_id(&self) -> PeerId {
            self.my_peer_id
        }

        async fn close_peer(&self, peer_id: PeerId) {
            self.closed_peers.lock().push(peer_id);
        }
    }

    struct CountingInterface {
        my_peer_id: PeerId,
        peers: Arc<Mutex<Vec<PeerId>>>,
        peer_identity_types: Arc<Mutex<HashMap<PeerId, Option<PeerIdentityType>>>>,
        list_peers_calls: Arc<AtomicU32>,
        get_peer_identity_type_calls: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl RouteInterface for CountingInterface {
        async fn list_peers(&self) -> Vec<PeerId> {
            self.list_peers_calls.fetch_add(1, Ordering::Relaxed);
            self.peers.lock().clone()
        }

        async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
            self.get_peer_identity_type_calls
                .fetch_add(1, Ordering::Relaxed);
            self.peer_identity_types
                .lock()
                .get(&peer_id)
                .copied()
                .flatten()
        }

        async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
            Some(vec![peer_id as u8; 32])
        }

        fn my_peer_id(&self) -> PeerId {
            self.my_peer_id
        }
    }

    #[tokio::test]
    async fn interface_peer_cache_refreshes_only_when_marked_dirty() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::new()));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Arc::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types,
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls,
        }));

        let first: BTreeSet<_> = service_impl.list_peers_from_interface().await;
        let second: BTreeSet<_> = service_impl.list_peers_from_interface().await;

        assert_eq!(first, BTreeSet::from([2, 3]));
        assert_eq!(second, BTreeSet::from([2, 3]));
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);

        *peers.lock() = vec![2, 4];
        service_impl.handle_global_ctx_event(&GlobalCtxEvent::PeerConnAdded(Default::default()));

        let third: BTreeSet<_> = service_impl.list_peers_from_interface().await;
        assert_eq!(third, BTreeSet::from([2, 4]));
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn update_my_conn_info_skips_interface_scan_when_topology_is_unchanged() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::from([
            (2, Some(PeerIdentityType::SharedNode)),
            (3, Some(PeerIdentityType::SharedNode)),
            (4, Some(PeerIdentityType::SharedNode)),
        ])));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Arc::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types,
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls: get_peer_identity_type_calls.clone(),
        }));

        assert!(service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        assert!(!service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        *peers.lock() = vec![2, 4];
        service_impl.handle_global_ctx_event(&GlobalCtxEvent::PeerConnRemoved(Default::default()));

        assert!(service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);

        assert!(!service_impl.update_my_conn_info().await);
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);
    }

    fn authenticated_interface_snapshot(
        generation: u64,
        peer_ids: &[PeerId],
    ) -> super::InterfacePeerSnapshot {
        let peers = peer_ids.iter().copied().collect::<BTreeSet<_>>();
        let identity_types = peer_ids
            .iter()
            .copied()
            .map(|peer_id| (peer_id, Some(PeerIdentityType::Admin)))
            .collect();
        let authenticated = peer_ids
            .iter()
            .copied()
            .map(|peer_id| {
                (
                    peer_id,
                    super::InterfacePeerEvidence {
                        identity_type: Some(PeerIdentityType::Admin),
                        public_key: Some(vec![peer_id as u8; 32]),
                        secure_auth_level: Some(SecureAuthLevel::NetworkSecretConfirmed),
                    },
                )
            })
            .collect();
        super::InterfacePeerSnapshot {
            generation,
            peers,
            identity_types,
            authenticated,
        }
    }

    #[test]
    fn unchanged_interface_authentication_does_not_change_topology_or_rebuild() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let snapshot = authenticated_interface_snapshot(2, &[2, 3, 4]);

        let first = service.apply_authenticated_interface_snapshot(&snapshot);
        assert!(first.changed);
        service.update_route_table_and_cached_local_conn_bitmap();
        let version = service.synced_route_info.version.get();
        let generation = service.forwarding_snapshot().generation;

        let second = service.apply_authenticated_interface_snapshot(&snapshot);
        assert!(!second.changed);
        assert!(second.conflicts.is_empty());
        assert_eq!(service.synced_route_info.version.get(), version);
        assert_eq!(service.forwarding_snapshot().generation, generation);
    }

    #[test]
    fn interface_authentication_does_not_advance_remote_route_version() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let snapshot = authenticated_interface_snapshot(2, &[2]);

        assert!(
            service
                .apply_authenticated_interface_snapshot(&snapshot)
                .changed
        );
        assert_eq!(
            service
                .synced_route_info
                .peer_infos
                .read()
                .get(&2)
                .expect("the authenticated placeholder exists")
                .version,
            0
        );

        let mut route_info = RoutePeerInfo::new();
        route_info.peer_id = 2;
        route_info.peer_route_id = 22;
        route_info.version = 1;
        let ipv4: std::net::Ipv4Addr = "10.144.144.2".parse().unwrap();
        route_info.ipv4_addr = Some(ipv4.into());
        route_info.noise_static_pubkey = vec![2; 32];
        let mut raw_route_info = DynamicMessage::new(RoutePeerInfo::default().descriptor());
        raw_route_info.transcode_from(&route_info).unwrap();

        service
            .synced_route_info
            .update_peer_infos(
                service.my_peer_id,
                service.my_peer_route_id,
                2,
                &[route_info],
                &[raw_route_info],
            )
            .unwrap();

        let peer_infos = service.synced_route_info.peer_infos.read();
        let updated = peer_infos
            .get(&2)
            .expect("the route update replaces the placeholder");
        assert_eq!(updated.version, 1);
        assert_eq!(updated.ipv4_addr, Some(ipv4.into()));
    }

    #[test]
    fn interface_batch_add_remove_publishes_one_rebuild() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2, 3, 4]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );
        service.update_route_table_and_cached_local_conn_bitmap();
        let before_version = service.synced_route_info.version.get();
        let before_generation = service.forwarding_snapshot().generation;

        let replacement = authenticated_interface_snapshot(3, &[5, 6, 7]);
        let update = service.apply_authenticated_interface_snapshot(&replacement);
        assert!(update.changed);
        assert!(update.conflicts.is_empty());
        assert_eq!(service.synced_route_info.version.get(), before_version + 1);
        assert_eq!(service.forwarding_snapshot().generation, before_generation);

        service.update_route_table_and_cached_local_conn_bitmap();
        assert_eq!(
            service.forwarding_snapshot().generation,
            before_generation + 1
        );
    }

    #[test]
    fn changed_peer_key_replaces_old_authenticated_tuple() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );
        let before_version = service.synced_route_info.version.get();

        let mut replacement = authenticated_interface_snapshot(3, &[2]);
        replacement.authenticated.get_mut(&2).unwrap().public_key = Some(vec![9; 32]);
        let update = service.apply_authenticated_interface_snapshot(&replacement);

        assert!(update.changed);
        assert!(update.conflicts.is_empty());
        assert_eq!(service.synced_route_info.version.get(), before_version + 1);
        assert_eq!(
            service.authenticated_peers.get(&2).unwrap().public_key,
            vec![9; 32]
        );
    }

    #[test]
    fn auth_downgrade_revokes_old_tuple_until_exact_tuple_is_active() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );

        let mut downgrade = authenticated_interface_snapshot(3, &[2]);
        downgrade
            .authenticated
            .get_mut(&2)
            .unwrap()
            .secure_auth_level = Some(SecureAuthLevel::PeerVerified);
        let first = service.apply_authenticated_interface_snapshot(&downgrade);
        assert!(first.changed);
        assert!(first.conflicts.contains(&2));
        assert!(!service.authenticated_peers.contains_key(&2));

        let second = service.apply_authenticated_interface_snapshot(&downgrade);
        assert!(second.changed);
        assert!(!second.conflicts.contains(&2));
        assert_eq!(
            service
                .authenticated_peers
                .get(&2)
                .unwrap()
                .secure_auth_level,
            SecureAuthLevel::PeerVerified
        );
    }

    #[test]
    fn missing_interface_tuple_revokes_old_authority() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );

        let missing = super::InterfacePeerSnapshot {
            generation: 3,
            peers: BTreeSet::from([2]),
            identity_types: BTreeMap::from([(2, None)]),
            authenticated: BTreeMap::new(),
        };
        let update = service.apply_authenticated_interface_snapshot(&missing);

        assert!(update.changed);
        assert!(update.conflicts.contains(&2));
        assert!(!service.authenticated_peers.contains_key(&2));
    }

    #[test]
    fn conflicting_live_tuples_revoke_old_authority() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );
        let candidate_a = AuthenticatedPeerInfo {
            peer_id: 2,
            identity_type: PeerIdentityType::Admin,
            public_key: vec![2; 32],
            secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
        };
        let candidate_b = AuthenticatedPeerInfo {
            peer_id: 2,
            identity_type: PeerIdentityType::Admin,
            public_key: vec![3; 32],
            secure_auth_level: SecureAuthLevel::NetworkSecretConfirmed,
        };
        let update = service.apply_authenticated_peer_candidates(
            &[candidate_a, candidate_b],
            Some(&BTreeSet::from([2])),
        );

        assert!(update.changed);
        assert!(update.conflicts.contains(&2));
        assert!(!service.authenticated_peers.contains_key(&2));
    }

    #[test]
    fn removing_last_connection_revokes_then_allows_new_exact_tuple() {
        let service = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let initial = authenticated_interface_snapshot(2, &[2]);
        assert!(
            service
                .apply_authenticated_interface_snapshot(&initial)
                .changed
        );

        let removed = super::InterfacePeerSnapshot {
            generation: 3,
            peers: BTreeSet::new(),
            identity_types: BTreeMap::new(),
            authenticated: BTreeMap::new(),
        };
        let removal = service.apply_authenticated_interface_snapshot(&removed);
        assert!(removal.changed);
        assert!(!service.authenticated_peers.contains_key(&2));

        let replacement = authenticated_interface_snapshot(4, &[2]);
        let added = service.apply_authenticated_interface_snapshot(&replacement);
        assert!(added.changed);
        assert!(!added.conflicts.contains(&2));
        assert!(service.authenticated_peers.contains_key(&2));
    }

    #[tokio::test]
    async fn get_peer_identity_type_reuses_snapshot_until_topology_changes() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let peers = Arc::new(Mutex::new(vec![2, 3]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::from([
            (2, Some(PeerIdentityType::Credential)),
            (3, Some(PeerIdentityType::Admin)),
            (4, Some(PeerIdentityType::Admin)),
        ])));
        let list_peers_calls = Arc::new(AtomicU32::new(0));
        let get_peer_identity_type_calls = Arc::new(AtomicU32::new(0));
        *service_impl.interface.lock().await = Some(Arc::new(CountingInterface {
            my_peer_id: 1,
            peers: peers.clone(),
            peer_identity_types: peer_identity_types.clone(),
            list_peers_calls: list_peers_calls.clone(),
            get_peer_identity_type_calls: get_peer_identity_type_calls.clone(),
        }));

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(2).await,
            Some(PeerIdentityType::Credential)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(2).await,
            Some(PeerIdentityType::Credential)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 1);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 2);

        *peers.lock() = vec![2, 4];
        service_impl.handle_global_ctx_event(&GlobalCtxEvent::PeerConnRemoved(Default::default()));

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(4).await,
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);

        assert_eq!(
            service_impl.get_peer_identity_type_from_interface(4).await,
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(list_peers_calls.load(Ordering::Relaxed), 2);
        assert_eq!(get_peer_identity_type_calls.load(Ordering::Relaxed), 4);
    }

    async fn create_mock_route(peer_mgr: Arc<PeerManager>) -> Arc<PeerRoute> {
        let peer_route = PeerRoute::new(
            peer_mgr.my_peer_id(),
            peer_mgr.get_global_ctx(),
            peer_mgr.get_peer_rpc_mgr(),
        );
        peer_mgr.add_route(peer_route.clone()).await;
        peer_route
    }

    #[tokio::test]
    async fn sync_route_info_rejects_a_claimed_peer_that_differs_from_the_session_peer() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr).await;
        let request = SyncRouteInfoRequest {
            my_peer_id: 10001,
            ..Default::default()
        };
        let mut ctrl = BaseController::default();
        ctrl.set_raw_input(Bytes::from(request.encode_to_vec()));
        ctrl.set_authenticated_peer_id(Some(10002));

        let result = route.session_mgr.sync_route_info(ctrl, request).await;

        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[tokio::test]
    async fn sync_route_info_rejects_an_unknown_authenticated_identity_type() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr).await;
        let request = SyncRouteInfoRequest {
            my_peer_id: 10003,
            ..Default::default()
        };
        let mut ctrl = BaseController::default();
        ctrl.set_raw_input(Bytes::from(request.encode_to_vec()));
        ctrl.set_authenticated_peer_id(Some(10003));

        let result = route.session_mgr.sync_route_info(ctrl, request).await;

        assert!(matches!(
            result,
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn malformed_raw_peer_info_returns_an_rpc_error() {
        let mut raw = Bytes::from_static(&[0xff, 0xff, 0xff]);
        assert!(matches!(
            get_raw_peer_infos(&mut raw),
            Err(rpc_types::error::Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn route_sync_rejects_duplicate_and_over_limit_peer_infos() {
        let duplicate = vec![
            RoutePeerInfo {
                peer_id: 7,
                ..Default::default()
            },
            RoutePeerInfo {
                peer_id: 7,
                ..Default::default()
            },
        ];
        assert!(validate_route_peer_infos(&duplicate).is_err());

        let too_many = (0..=MAX_ROUTE_SYNC_PEERS)
            .map(|peer_id| RoutePeerInfo {
                peer_id: peer_id as u32,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        assert!(validate_route_peer_infos(&too_many).is_err());
    }

    #[test]
    fn route_sync_role_gate_limits_restricted_sender_shapes() {
        let self_info = RoutePeerInfo {
            peer_id: 42,
            ..Default::default()
        };
        let forwarded_info = RoutePeerInfo {
            peer_id: 43,
            ..Default::default()
        };
        let peer_infos = vec![self_info.clone(), forwarded_info];
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::Admin,
                Some(&peer_infos),
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::SharedNode,
                Some(&peer_infos),
                None,
                None,
            )
            .is_err()
        );
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::ForeignRelay,
                Some(std::slice::from_ref(&self_info)),
                None,
                Some(&RouteForeignNetworkInfos::default()),
            )
            .is_err()
        );
    }

    #[test]
    fn route_sync_role_gate_limits_connection_shapes() {
        let source_only = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![PeerConnInfo {
                peer_id: Some(PeerIdVersion {
                    peer_id: 42,
                    version: 1,
                }),
                connected_peer_ids: vec![43],
            }],
        });
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::Credential,
                None,
                Some(&source_only),
                None,
            )
            .is_err()
        );
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::Credential,
                None,
                Some(&source_only),
                None,
            )
            .is_err()
        );
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::Credential,
                None,
                Some(&ConnInfo::ConnBitmap(RouteConnBitmap::default())),
                None,
            )
            .is_err()
        );
        assert!(
            validate_route_sync_role_shape(
                42,
                PeerIdentityType::SharedNode,
                None,
                Some(&source_only),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn route_sync_validates_bitmap_shape_and_peer_ids() {
        let peer_ids = (0..MAX_ROUTE_SYNC_PEERS)
            .map(|peer_id| crate::proto::peer_rpc::PeerIdVersion {
                peer_id: peer_id as u32,
                version: 1,
            })
            .collect::<Vec<_>>();
        let edge_bits = MAX_ROUTE_SYNC_PEERS * MAX_ROUTE_SYNC_PEERS;
        let valid = ConnInfo::ConnBitmap(RouteConnBitmap {
            peer_ids,
            bitmap: vec![0; edge_bits.div_ceil(8)],
        });
        assert!(validate_route_conn_info(&valid).is_ok());

        let too_many_peers = ConnInfo::ConnBitmap(RouteConnBitmap {
            peer_ids: (0..=MAX_ROUTE_SYNC_PEERS)
                .map(|peer_id| crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: peer_id as u32,
                    version: 1,
                })
                .collect(),
            bitmap: Vec::new(),
        });
        assert!(validate_route_conn_info(&too_many_peers).is_err());

        let duplicate = ConnInfo::ConnBitmap(RouteConnBitmap {
            peer_ids: vec![
                crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 9,
                    version: 1,
                },
                crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 9,
                    version: 2,
                },
            ],
            bitmap: vec![0],
        });
        assert!(validate_route_conn_info(&duplicate).is_err());

        let trailing_bits = ConnInfo::ConnBitmap(RouteConnBitmap {
            peer_ids: vec![
                crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 9,
                    version: 1,
                },
                crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 10,
                    version: 1,
                },
                crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 11,
                    version: 1,
                },
            ],
            bitmap: vec![0, 0x80],
        });
        assert!(validate_route_conn_info(&trailing_bits).is_err());

        let peer_count = MAX_ROUTE_SYNC_EDGES_PER_SOURCE + 1;
        let edge_bits = peer_count * peer_count;
        let mut oversized_degree_bitmap = vec![0; edge_bits.div_ceil(8)];
        for destination_idx in 0..peer_count {
            oversized_degree_bitmap[destination_idx / 8] |= 1 << (destination_idx % 8);
        }
        let oversized_degree = ConnInfo::ConnBitmap(RouteConnBitmap {
            peer_ids: (0..peer_count)
                .map(|peer_id| crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: peer_id as u32,
                    version: 1,
                })
                .collect(),
            bitmap: oversized_degree_bitmap,
        });
        assert!(validate_route_conn_info(&oversized_degree).is_err());
    }

    #[test]
    fn route_sync_bounds_connection_lists_and_rejects_duplicate_sources() {
        let too_many_sources = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: (0..=MAX_ROUTE_SYNC_PEERS)
                .map(
                    |peer_id| crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                        peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                            peer_id: peer_id as u32,
                            version: 1,
                        }),
                        connected_peer_ids: Vec::new(),
                    },
                )
                .collect(),
        });
        assert!(validate_route_conn_info(&too_many_sources).is_err());

        let duplicate_source = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![
                crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                    peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                        peer_id: 7,
                        version: 1,
                    }),
                    connected_peer_ids: vec![8],
                },
                crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                    peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                        peer_id: 7,
                        version: 2,
                    }),
                    connected_peer_ids: Vec::new(),
                },
            ],
        });
        assert!(validate_route_conn_info(&duplicate_source).is_err());

        let too_many_connected = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                    peer_id: 7,
                    version: 1,
                }),
                connected_peer_ids: (0..=MAX_ROUTE_SYNC_PEERS as u32).collect(),
            }],
        });
        assert!(validate_route_conn_info(&too_many_connected).is_err());

        let too_many_edges = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: (0..=(MAX_ROUTE_SYNC_EDGES / MAX_ROUTE_SYNC_EDGES_PER_SOURCE))
                .map(
                    |peer_id| crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                        peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                            peer_id: peer_id as u32,
                            version: 1,
                        }),
                        connected_peer_ids: (0..MAX_ROUTE_SYNC_EDGES_PER_SOURCE as u32).collect(),
                    },
                )
                .collect(),
        });
        assert!(validate_route_conn_info(&too_many_edges).is_err());

        let too_many_unique_nodes = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: (0..5)
                .map(|source_idx| {
                    let source_peer_id = 10_000 + source_idx;
                    crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                        peer_id: Some(crate::proto::peer_rpc::PeerIdVersion {
                            peer_id: source_peer_id,
                            version: 1,
                        }),
                        connected_peer_ids: (0..MAX_ROUTE_SYNC_EDGES_PER_SOURCE as u32)
                            .map(|peer_idx| 20_000 + source_idx * 2_000 + peer_idx)
                            .collect(),
                    }
                })
                .collect(),
        });
        assert!(validate_route_conn_info(&too_many_unique_nodes).is_err());
    }

    #[test]
    fn route_sync_bounds_group_and_foreign_network_records() {
        let too_many_groups = vec![RoutePeerInfo {
            peer_id: 1,
            groups: (0..=super::MAX_ROUTE_SYNC_GROUPS_PER_PEER)
                .map(|index| PeerGroupInfo {
                    group_name: format!("group-{index}"),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }];
        assert!(validate_route_peer_infos(&too_many_groups).is_err());

        let too_many_multicast_groups = vec![RoutePeerInfo {
            peer_id: 1,
            multicast_groups: (0..=super::MAX_ROUTE_SYNC_MULTICAST_GROUPS_PER_PEER)
                .map(|_| vec![0xe0, 0, 0, 1])
                .collect(),
            ..Default::default()
        }];
        assert!(validate_route_peer_infos(&too_many_multicast_groups).is_err());

        let too_many_networks = RouteForeignNetworkInfos {
            infos: (0..=super::MAX_ROUTE_SYNC_FOREIGN_NETWORK_INFOS)
                .map(|peer_id| route_foreign_network_infos::Info {
                    key: Some(ForeignNetworkRouteInfoKey {
                        peer_id: peer_id as u32,
                        network_name: format!("network-{peer_id}"),
                    }),
                    value: Some(ForeignNetworkRouteInfoEntry::default()),
                })
                .collect(),
        };
        assert!(validate_route_foreign_network_info(&too_many_networks).is_err());

        let too_many_foreign_edges = RouteForeignNetworkInfos {
            infos: (0..=(MAX_ROUTE_SYNC_EDGES / MAX_ROUTE_SYNC_EDGES_PER_SOURCE))
                .map(|peer_id| route_foreign_network_infos::Info {
                    key: Some(ForeignNetworkRouteInfoKey {
                        peer_id: peer_id as u32,
                        network_name: format!("network-{peer_id}"),
                    }),
                    value: Some(ForeignNetworkRouteInfoEntry {
                        foreign_peer_ids: (0..MAX_ROUTE_SYNC_EDGES_PER_SOURCE as u32).collect(),
                        ..Default::default()
                    }),
                })
                .collect(),
        };
        assert!(validate_route_foreign_network_info(&too_many_foreign_edges).is_err());
    }

    fn get_rpc_counter(route: &Arc<PeerRoute>, peer_id: PeerId) -> (u32, u32) {
        let session = route.service_impl.get_session(peer_id).unwrap();
        (
            session.rpc_tx_count.load(Ordering::Relaxed),
            session.rpc_rx_count.load(Ordering::Relaxed),
        )
    }

    fn get_is_initiator(route: &Arc<PeerRoute>, peer_id: PeerId) -> (bool, bool) {
        let session = route.service_impl.get_session(peer_id).unwrap();
        (
            session.we_are_initiator.load(Ordering::Relaxed),
            session.dst_is_initiator.load(Ordering::Relaxed),
        )
    }

    fn make_credential_route_peer_info(
        peer_id: PeerId,
        noise_static_pubkey: &[u8],
    ) -> RoutePeerInfo {
        let mut peer_info = RoutePeerInfo::new();
        peer_info.peer_id = peer_id;
        peer_info.version = 1;
        peer_info.noise_static_pubkey = noise_static_pubkey.to_vec();
        peer_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });
        peer_info
    }

    fn signed_test_credential(
        manager: &crate::peers::credential_manager::CredentialManager,
        _subject: &[u8],
        ttl: Duration,
    ) -> TrustedCredentialPubkey {
        generated_test_credential(manager, Vec::new(), true, Vec::new(), ttl, true)
    }

    fn credential_from_certificate(
        certificate: crate::proto::peer_rpc::CredentialCertificate,
    ) -> TrustedCredentialPubkey {
        TrustedCredentialPubkey {
            pubkey: certificate.subject_x25519_public_key.clone(),
            credential_version: certificate.version,
            serial: 0,
            certificate_id: certificate.certificate_id.clone(),
            network_name: certificate.network_name.clone(),
            root_public_key: certificate.root_public_key.clone(),
            root_fingerprint: certificate.root_fingerprint.clone(),
            role: certificate.role.clone(),
            groups: certificate.groups.clone(),
            allow_relay: certificate.allow_relay,
            allowed_proxy_cidrs: certificate.allowed_proxy_cidrs.clone(),
            reusable: Some(certificate.reusable),
            certificate_signature: certificate.signature.clone(),
            certificate: Some(certificate.clone()),
            expiry_unix: certificate.expiry_unix,
            ..Default::default()
        }
    }

    fn credential_pubkey_from_info(info: &RoutePeerInfo) -> Vec<u8> {
        info.trusted_credential_pubkeys
            .first()
            .and_then(|proof| proof.credential.as_ref())
            .map(|credential| credential.pubkey.clone())
            .expect("test route info credential pubkey")
    }

    fn credential_from_context(
        ctx: &crate::common::global_ctx::ArcGlobalCtx,
    ) -> TrustedCredentialPubkey {
        let secure_mode = ctx
            .config
            .get_secure_mode()
            .expect("credential test context secure mode");
        let certificate = crate::proto::peer_rpc::CredentialCertificate::decode(
            secure_mode.credential_certificate.as_slice(),
        )
        .expect("credential test context certificate");
        credential_from_certificate(certificate)
    }

    fn generated_test_credential(
        manager: &crate::peers::credential_manager::CredentialManager,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        reusable: bool,
    ) -> TrustedCredentialPubkey {
        let (_, encoded) = manager
            .generate_credential_bundle(
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                ttl,
                None,
                reusable,
            )
            .expect("test credential bundle");
        let bundle =
            crate::peers::credential_manager::CredentialManager::parse_credential_bundle(&encoded)
                .expect("test credential bundle decode");
        let certificate = bundle.certificate.expect("test credential certificate");
        TrustedCredentialPubkey {
            pubkey: certificate.subject_x25519_public_key.clone(),
            credential_version: certificate.version,
            serial: 0,
            certificate_id: certificate.certificate_id.clone(),
            network_name: certificate.network_name.clone(),
            root_public_key: certificate.root_public_key.clone(),
            root_fingerprint: certificate.root_fingerprint.clone(),
            role: certificate.role.clone(),
            groups: certificate.groups.clone(),
            allow_relay: certificate.allow_relay,
            allowed_proxy_cidrs: certificate.allowed_proxy_cidrs.clone(),
            reusable: Some(certificate.reusable),
            certificate_signature: certificate.signature.clone(),
            certificate: Some(certificate.clone()),
            expiry_unix: certificate.expiry_unix,
            ..Default::default()
        }
    }

    fn make_admin_route_peer_info(
        manager: &crate::peers::credential_manager::CredentialManager,
        peer_id: PeerId,
        credential_key: &[u8],
        network_secret: &str,
        _now: i64,
    ) -> RoutePeerInfo {
        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = peer_id;
        admin_info.version = 1;
        admin_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: false,
            ..Default::default()
        });
        admin_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            generated_test_credential(
                manager,
                Vec::new(),
                true,
                Vec::new(),
                Duration::from_secs(600),
                false,
            ),
            network_secret,
        )];
        admin_info
    }

    fn make_route_conn_info<I>(connected_peers: I, last_update: SystemTime) -> RouteConnInfo
    where
        I: IntoIterator<Item = PeerId>,
    {
        RouteConnInfo {
            connected_peers: connected_peers.into_iter().collect(),
            version: 1.into(),
            last_update,
        }
    }

    async fn create_mock_pmgr() -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            get_mock_global_ctx(),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    fn check_rpc_counter(route: &Arc<PeerRoute>, peer_id: PeerId, max_tx: u32, max_rx: u32) {
        let (tx1, rx1) = get_rpc_counter(route, peer_id);
        assert!(tx1 <= max_tx);
        assert!(rx1 <= max_rx);
    }

    #[tokio::test]
    async fn identity_type_controls_role_classification() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());

        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = 10;
        admin_info.version = 1;
        admin_info.identity_type = PeerIdentityType::Admin as i32;
        admin_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: false,
            ..Default::default()
        });

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = 11;
        credential_info.version = 1;
        credential_info.identity_type = PeerIdentityType::Credential as i32;
        credential_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info.clone());
            guard.insert(credential_info.peer_id, credential_info.clone());
        }

        assert!(service_impl.synced_route_info.is_admin_peer(&admin_info));
        assert!(
            !service_impl
                .synced_route_info
                .is_admin_peer(&credential_info)
        );
        assert!(
            service_impl
                .synced_route_info
                .is_credential_peer(credential_info.peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .is_credential_peer(admin_info.peer_id)
        );
    }

    #[test]
    fn foreign_relay_self_info_has_no_local_authority_fields() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_hostname(format!(
            "{}test",
            crate::peers::PUBLIC_SERVER_HOSTNAME_PREFIX
        ));
        global_ctx
            .config
            .add_proxy_cidr("10.10.0.0/24".parse().unwrap(), None)
            .unwrap();
        global_ctx.set_multicast_groups(["224.0.0.1".parse().unwrap()].into_iter().collect());

        let info = RoutePeerInfo::new_updated_self(1, 1, &global_ctx, None);

        assert_eq!(
            SyncedRouteInfo::peer_identity_type(&info),
            Some(PeerIdentityType::ForeignRelay)
        );
        assert!(info.proxy_cidrs.is_empty());
        assert!(info.groups.is_empty());
        assert!(info.trusted_credential_pubkeys.is_empty());
        assert!(
            !info
                .feature_flag
                .as_ref()
                .is_some_and(|flags| flags.is_credential_peer)
        );
        let flags = info.feature_flag.as_ref().unwrap();
        assert!(!flags.ethernet_input);
        assert!(!flags.bridge_input);
        assert!(!flags.multicast_membership);
        assert!(info.multicast_groups.is_empty());
    }

    #[tokio::test]
    async fn trusted_credentials_only_from_admin_publishers() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "sec1";

        let manager = service_impl.global_ctx.get_credential_manager();

        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = 20;
        admin_info.version = 1;
        admin_info.identity_type = PeerIdentityType::Admin as i32;
        admin_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: false,
            ..Default::default()
        });
        let admin_credential = signed_test_credential(manager, &[1; 32], Duration::from_secs(600));
        let admin_key = admin_credential.pubkey.clone();
        admin_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            admin_credential,
            network_secret,
        )];

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = 21;
        credential_info.version = 1;
        credential_info.identity_type = PeerIdentityType::Credential as i32;
        credential_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });
        let credential_credential =
            signed_test_credential(manager, &[2; 32], Duration::from_secs(600));
        let credential_key = credential_credential.pubkey.clone();
        credential_info.trusted_credential_pubkeys =
            vec![TrustedCredentialPubkeyProof::new_signed(
                credential_credential,
                network_secret,
            )];

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info);
            guard.insert(credential_info.peer_id, credential_info);
        }

        service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));

        assert!(
            service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&admin_key)
        );
        assert!(
            !service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_key)
        );
    }

    #[test]
    fn credential_hmac_requires_a_local_network_secret() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let credential = signed_test_credential(
            service_impl.global_ctx.get_credential_manager(),
            &[4; 32],
            Duration::from_secs(600),
        );
        let proof = TrustedCredentialPubkeyProof::new_signed(credential, "route-secret");

        assert!(
            !service_impl
                .synced_route_info
                .credential_proof_is_valid(None, 0, &proof, None,)
        );
        assert!(service_impl.synced_route_info.credential_proof_is_valid(
            None,
            0,
            &proof,
            Some("route-secret"),
        ));
    }

    #[test]
    fn legacy_hmac_only_credential_shape_is_rejected() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let mut admin = RoutePeerInfo::new();
        admin.peer_id = 7;
        admin.identity_type = PeerIdentityType::Admin as i32;
        admin.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            TrustedCredentialPubkey {
                pubkey: vec![4; 32],
                expiry_unix: i64::MAX,
                ..Default::default()
            },
            "route-secret",
        )];
        let mut peers = OrderedHashMap::new();
        peers.insert(admin.peer_id, admin);
        let (trusted, metadata) = service_impl.synced_route_info.collect_trusted_credentials(
            &peers,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert!(trusted.is_empty());
        assert!(metadata.is_empty());
    }

    #[test]
    fn credential_route_admission_checks_expiry_at_lookup_time() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let key = vec![7; 32];
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        service_impl
            .synced_route_info
            .trusted_credential_pubkeys
            .insert(
                key.clone(),
                TrustedCredentialPubkey {
                    pubkey: key.clone(),
                    expiry_unix: now - 1,
                    ..Default::default()
                },
            );
        assert!(
            service_impl
                .synced_route_info
                .get_credential_info_by_pubkey(&key)
                .is_none()
        );
    }

    #[test]
    fn signed_credential_certificates_are_admitted_deterministically() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "duplicate-secret";
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let manager = service_impl.global_ctx.get_credential_manager();
        let credential_a = generated_test_credential(
            manager,
            Vec::new(),
            true,
            Vec::new(),
            Duration::from_secs(600),
            true,
        );
        let key_a = credential_a.pubkey.clone();
        let credential_b = generated_test_credential(
            manager,
            Vec::new(),
            true,
            Vec::new(),
            Duration::from_secs(600),
            true,
        );
        let key_b = credential_b.pubkey.clone();
        let mut first = RoutePeerInfo::new();
        first.peer_id = 101;
        first.version = 1;
        first.identity_type = PeerIdentityType::Admin as i32;
        first.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential_a,
            network_secret,
        )];
        let mut second = RoutePeerInfo::new();
        second.peer_id = 102;
        second.version = 1;
        second.identity_type = PeerIdentityType::Admin as i32;
        second.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential_b,
            network_secret,
        )];
        let mut peer_infos = OrderedHashMap::new();
        peer_infos.insert(first.peer_id, first);
        peer_infos.insert(second.peer_id, second);

        let (trusted, metadata) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some(network_secret),
            now,
        );
        assert!(trusted.contains_key(&key_a));
        assert!(trusted.contains_key(&key_b));
        assert!(metadata.contains_key(&key_a));
        assert!(metadata.contains_key(&key_b));
    }

    #[test]
    fn propagated_admin_labels_do_not_create_node_trust() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let peer_id = 91;
        let route_key = vec![8; 32];
        let mut route_info = RoutePeerInfo::new();
        route_info.peer_id = peer_id;
        route_info.version = 1;
        route_info.identity_type = PeerIdentityType::Admin as i32;
        route_info.noise_static_pubkey = route_key.clone();

        let mut peer_infos = OrderedHashMap::new();
        peer_infos.insert(peer_id, route_info.clone());
        let (_, untrusted_keys) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert!(!untrusted_keys.contains_key(&route_key));

        assert_eq!(
            service_impl.seed_authenticated_peer(
                peer_id,
                PeerIdentityType::Admin,
                route_key.clone(),
                SecureAuthLevel::NetworkSecretConfirmed,
            ),
            AuthenticatedPeerSeedResult::Inserted
        );
        // The seeded evidence creates a placeholder record; the trust
        // collector only reads peers with a synced route record.
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .get_mut(&peer_id)
            .expect("seeded peer record")
            .version = 1;
        let peer_infos = service_impl.synced_route_info.peer_infos.read();
        let (_, trusted_keys) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert_eq!(
            trusted_keys.get(&route_key).map(|metadata| metadata.source),
            Some(crate::common::global_ctx::TrustedKeySource::OspfNode)
        );
    }

    #[test]
    fn merged_route_budget_rejects_accumulated_peer_overflow_without_mutation() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let make_raw = |info: &RoutePeerInfo| {
            let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
            raw.transcode_from(info).unwrap();
            raw
        };

        for batch in 0..2 {
            let start = batch * (MAX_ROUTE_SYNC_PEERS / 2);
            let infos = (start..start + (MAX_ROUTE_SYNC_PEERS / 2))
                .map(|peer_id| {
                    let mut info = RoutePeerInfo::new();
                    info.peer_id = peer_id as PeerId + 1000;
                    info.version = 1;
                    info
                })
                .collect::<Vec<_>>();
            let raw = infos.iter().map(make_raw).collect::<Vec<_>>();
            service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    0,
                    &infos,
                    &raw,
                    None,
                )
                .unwrap();
        }

        let before_version = service_impl.synced_route_info.version.get();
        let mut overflow = RoutePeerInfo::new();
        overflow.peer_id = 9_999;
        overflow.version = 1;
        let raw = make_raw(&overflow);
        assert!(
            service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    0,
                    &[overflow],
                    &[raw],
                    None,
                )
                .is_err()
        );
        assert_eq!(
            service_impl.synced_route_info.peer_infos.read().len(),
            MAX_ROUTE_SYNC_PEERS
        );
        assert_eq!(service_impl.synced_route_info.version.get(), before_version);
    }

    #[test]
    fn merged_route_budget_rejects_source_degree_without_partial_edges() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let connected_peer_ids = (0..=MAX_ROUTE_SYNC_EDGES_PER_SOURCE as u32).collect();
        let conn_info = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![PeerConnInfo {
                peer_id: Some(PeerIdVersion {
                    peer_id: 77,
                    version: 1,
                }),
                connected_peer_ids,
            }],
        });

        assert!(
            service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    0,
                    &[],
                    &[],
                    Some(&conn_info),
                )
                .is_err()
        );
        assert!(service_impl.synced_route_info.conn_map.read().is_empty());
    }

    #[test]
    fn topology_role_downgrade_removes_the_previous_authority_row() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let source_peer = 77;
        let conn_info = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![PeerConnInfo {
                peer_id: Some(PeerIdVersion {
                    peer_id: source_peer,
                    version: 1,
                }),
                connected_peer_ids: vec![1],
            }],
        });
        assert!(
            service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info_with_authority(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    source_peer,
                    &[],
                    &[],
                    Some(&conn_info),
                    true,
                )
                .unwrap()
        );
        assert!(
            service_impl
                .synced_route_info
                .conn_map
                .read()
                .contains_key(&source_peer)
        );

        assert!(
            service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info_with_authority(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    source_peer,
                    &[],
                    &[],
                    None,
                    false,
                )
                .unwrap()
        );
        assert!(
            !service_impl
                .synced_route_info
                .conn_map
                .read()
                .contains_key(&source_peer)
        );
        assert!(
            !service_impl
                .synced_route_info
                .update_peer_infos_and_conn_info_with_authority(
                    service_impl.my_peer_id,
                    service_impl.my_peer_route_id,
                    source_peer,
                    &[],
                    &[],
                    None,
                    false,
                )
                .unwrap()
        );
    }

    #[test]
    fn local_admin_key_rotation_and_revoke_changes_route_trust() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let peer_id = 92;
        let first_key = vec![1; 32];
        let second_key = vec![2; 32];
        assert_eq!(
            service_impl.seed_authenticated_peer(
                peer_id,
                PeerIdentityType::Admin,
                first_key.clone(),
                SecureAuthLevel::PeerVerified,
            ),
            AuthenticatedPeerSeedResult::Inserted
        );
        // The seeded evidence creates a placeholder record; the trust
        // collector only reads peers with a synced route record.
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .get_mut(&peer_id)
            .expect("seeded peer record")
            .version = 1;
        let peer_infos = service_impl.synced_route_info.peer_infos.read();
        let (_, first_trusted) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert!(first_trusted.contains_key(&first_key));
        drop(peer_infos);

        assert_eq!(
            service_impl.seed_authenticated_peer(
                peer_id,
                PeerIdentityType::Admin,
                second_key.clone(),
                SecureAuthLevel::PeerVerified,
            ),
            AuthenticatedPeerSeedResult::Inserted
        );
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .get_mut(&peer_id)
            .expect("seeded peer record")
            .version = 1;
        let peer_infos = service_impl.synced_route_info.peer_infos.read();
        let (_, rotated_trusted) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert!(!rotated_trusted.contains_key(&first_key));
        assert!(rotated_trusted.contains_key(&second_key));
        drop(peer_infos);

        assert!(service_impl.retain_authenticated_interface_peers(&BTreeSet::new()));
        let peer_infos = service_impl.synced_route_info.peer_infos.read();
        let (_, revoked_trusted) = service_impl.synced_route_info.collect_trusted_credentials(
            &peer_infos,
            Some("route-secret"),
            i64::MAX - 1,
        );
        assert!(!revoked_trusted.contains_key(&second_key));
    }

    #[tokio::test]
    async fn credential_groups_merge_with_proof_groups_and_recompute_cleanly() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "sec1";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let credential_peer_id = 31;
        let manager = service_impl.global_ctx.get_credential_manager();
        let credential = generated_test_credential(
            manager,
            vec!["cred-group".to_string()],
            false,
            Vec::new(),
            Duration::from_secs(600),
            true,
        );
        let credential_pubkey = credential.pubkey.clone();

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = credential_peer_id;
        credential_info.version = 1;
        credential_info.noise_static_pubkey = credential_pubkey.clone();
        credential_info.groups = vec![PeerGroupInfo::generate_with_proof(
            "proof-group".to_string(),
            "proof-secret".to_string(),
            credential_peer_id,
        )];

        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = 32;
        admin_info.version = 1;
        admin_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: false,
            ..Default::default()
        });
        admin_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential,
            network_secret,
        )];

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info.clone());
            guard.insert(credential_peer_id, credential_info.clone());
        }

        service_impl
            .synced_route_info
            .verify_and_update_group_trusts(
                &[credential_info],
                &[GroupIdentity {
                    group_name: "proof-group".to_string(),
                    group_secret: "proof-secret".to_string(),
                }],
                false,
            );
        service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));

        let groups = service_impl.get_peer_groups(credential_peer_id);
        assert!(groups.contains(&"proof-group".to_string()));
        assert!(groups.contains(&"cred-group".to_string()));

        let guard = service_impl.synced_route_info.peer_infos.write();
        let admin_info = guard.get(&32).unwrap().clone();
        drop(guard);

        let replacement = generated_test_credential(
            manager,
            vec!["replacement-group".to_string()],
            false,
            Vec::new(),
            Duration::from_secs(600),
            true,
        );
        let replacement_pubkey = replacement.pubkey.clone();
        let mut updated_admin = admin_info;
        updated_admin.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            replacement,
            network_secret,
        )];
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .get_mut(&credential_peer_id)
            .expect("credential peer info")
            .noise_static_pubkey = replacement_pubkey;
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .insert(updated_admin.peer_id, updated_admin);

        service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));

        let groups = service_impl.get_peer_groups(credential_peer_id);
        assert!(groups.contains(&"proof-group".to_string()));
        assert!(groups.contains(&"replacement-group".to_string()));
        assert!(!groups.contains(&"cred-group".to_string()));
    }

    #[tokio::test]
    async fn remove_peers_batches_cleanup_and_version_increment() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let removed_peer_ids = [41, 42];
        let retained_peer_id = 43;

        {
            let mut peer_infos = service_impl.synced_route_info.peer_infos.write();
            let mut conn_map = service_impl.synced_route_info.conn_map.write();
            for peer_id in removed_peer_ids {
                let mut info = RoutePeerInfo::new();
                info.peer_id = peer_id;
                info.version = 1;
                peer_infos.insert(peer_id, info);
                conn_map.insert(peer_id, RouteConnInfo::default());
            }

            let mut retained_info = RoutePeerInfo::new();
            retained_info.peer_id = retained_peer_id;
            retained_info.version = 1;
            peer_infos.insert(retained_peer_id, retained_info);
            conn_map.insert(retained_peer_id, RouteConnInfo::default());
        }

        for peer_id in removed_peer_ids {
            service_impl.synced_route_info.raw_peer_infos.insert(
                peer_id,
                DynamicMessage::new(RoutePeerInfo::default().descriptor()),
            );
            service_impl.synced_route_info.group_trust_map.insert(
                peer_id,
                HashMap::from([("guest".to_string(), vec![1, 2, 3])]),
            );
            service_impl
                .synced_route_info
                .group_trust_map_cache
                .insert(peer_id, Arc::new(vec!["guest".to_string()]));
            service_impl.synced_route_info.foreign_network.insert(
                ForeignNetworkRouteInfoKey {
                    peer_id,
                    ..Default::default()
                },
                ForeignNetworkRouteInfoEntry::default(),
            );
        }

        service_impl.synced_route_info.foreign_network.insert(
            ForeignNetworkRouteInfoKey {
                peer_id: retained_peer_id,
                ..Default::default()
            },
            ForeignNetworkRouteInfoEntry::default(),
        );

        let initial_version = service_impl.synced_route_info.version.get();
        service_impl
            .synced_route_info
            .remove_peers(removed_peer_ids);

        assert_eq!(
            service_impl.synced_route_info.version.get(),
            initial_version + 1
        );
        for peer_id in removed_peer_ids {
            assert!(
                !service_impl
                    .synced_route_info
                    .peer_infos
                    .read()
                    .contains_key(&peer_id)
            );
            assert!(
                !service_impl
                    .synced_route_info
                    .conn_map
                    .read()
                    .contains_key(&peer_id)
            );
            assert!(
                !service_impl
                    .synced_route_info
                    .raw_peer_infos
                    .contains_key(&peer_id)
            );
            assert!(
                !service_impl
                    .synced_route_info
                    .group_trust_map
                    .contains_key(&peer_id)
            );
            assert!(
                !service_impl
                    .synced_route_info
                    .group_trust_map_cache
                    .contains_key(&peer_id)
            );
            assert!(
                !service_impl.synced_route_info.foreign_network.contains_key(
                    &ForeignNetworkRouteInfoKey {
                        peer_id,
                        ..Default::default()
                    }
                )
            );
        }

        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&retained_peer_id)
        );
        assert!(service_impl.synced_route_info.foreign_network.contains_key(
            &ForeignNetworkRouteInfoKey {
                peer_id: retained_peer_id,
                ..Default::default()
            }
        ));
    }

    #[tokio::test]
    async fn verify_trusted_credential_hmac_with_raw_payload_bytes() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "sec1";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = 30;
        admin_info.version = 1;

        let credential = signed_test_credential(
            service_impl.global_ctx.get_credential_manager(),
            &[7; 32],
            Duration::from_secs(600),
        );
        let credential_key = credential.pubkey.clone();
        let mut raw_credential_bytes = credential.encode_to_vec();
        prost::encoding::encode_key(
            9999,
            prost::encoding::WireType::Varint,
            &mut raw_credential_bytes,
        );
        prost::encoding::encode_varint(42, &mut raw_credential_bytes);

        let (admin_info, raw_admin_info) = make_route_info_with_raw_trusted_credential_proof(
            &admin_info,
            &raw_credential_bytes,
            &TrustedCredentialPubkeyProof::generate_credential_hmac_from_bytes(
                &raw_credential_bytes,
                network_secret,
            ),
        );
        assert_eq!(admin_info.trusted_credential_pubkeys.len(), 1);
        assert!(
            !admin_info.trusted_credential_pubkeys[0].verify_credential_hmac(network_secret),
            "typed verification should fail after nested unknown fields are dropped"
        );

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = 41;
        credential_info.version = 1;
        credential_info.noise_static_pubkey = credential_key.clone();
        credential_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        let mut raw_credential_info = DynamicMessage::new(RoutePeerInfo::default().descriptor());
        raw_credential_info
            .transcode_from(&credential_info)
            .unwrap();

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info);
            guard.insert(credential_info.peer_id, credential_info);
        }
        service_impl
            .synced_route_info
            .raw_peer_infos
            .insert(30, raw_admin_info);
        service_impl
            .synced_route_info
            .raw_peer_infos
            .insert(41, raw_credential_info);

        let (untrusted_peers, _) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));
        assert!(untrusted_peers.is_empty());
        assert!(
            service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_key)
        );
    }

    #[tokio::test]
    async fn non_reusable_credential_elects_lowest_peer_id() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "sec1";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let admin_info = make_admin_route_peer_info(
            service_impl.global_ctx.get_credential_manager(),
            30,
            &[7; 32],
            network_secret,
            now,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);

        let mut original_peer = RoutePeerInfo::new();
        original_peer.peer_id = 41;
        original_peer.version = 1;
        original_peer.noise_static_pubkey = credential_key.clone();
        original_peer.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info.clone());
            guard.insert(original_peer.peer_id, original_peer);
        }

        let (first_untrusted, _) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));
        assert!(first_untrusted.is_empty());
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(41)
        );

        let mut new_peer = RoutePeerInfo::new();
        new_peer.peer_id = 39;
        new_peer.version = 1;
        new_peer.noise_static_pubkey = credential_key.clone();
        new_peer.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });
        service_impl
            .synced_route_info
            .peer_infos
            .write()
            .insert(new_peer.peer_id, new_peer);
        service_impl
            .synced_route_info
            .non_reusable_credential_owners
            .insert(credential_key.clone(), 41);

        let (second_untrusted, _) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));
        assert!(second_untrusted.is_empty());
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&41)
        );
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&39)
        );
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(39)
        );
        assert!(service_impl.synced_route_info.is_route_suppressed(41));
        assert!(!service_impl.synced_route_info.is_route_suppressed(39));
    }

    #[tokio::test]
    async fn non_reusable_credential_ignores_unreachable_stale_owner() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let network_secret = "sec1";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let stale_peer_id = 41;
        let replacement_peer_id = 39;

        let admin_info = make_admin_route_peer_info(
            service_impl.global_ctx.get_credential_manager(),
            30,
            &[8; 32],
            network_secret,
            now,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);

        let mut stale_peer = RoutePeerInfo::new();
        stale_peer.peer_id = stale_peer_id;
        stale_peer.version = 1;
        stale_peer.noise_static_pubkey = credential_key.clone();
        stale_peer.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        let mut replacement_peer = RoutePeerInfo::new();
        replacement_peer.peer_id = replacement_peer_id;
        replacement_peer.version = 1;
        replacement_peer.noise_static_pubkey = credential_key.clone();
        replacement_peer.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info);
            guard.insert(stale_peer.peer_id, stale_peer);
            guard.insert(replacement_peer.peer_id, replacement_peer);
        }
        service_impl
            .synced_route_info
            .non_reusable_credential_owners
            .insert(credential_key.clone(), stale_peer_id);

        service_impl.route_table.next_hop_map.insert(
            replacement_peer_id,
            NextHopInfo {
                next_hop_peer_id: replacement_peer_id,
                path_delivery_bps: 0,
                path_latency: 0,
                path_len: 1,
                version: 1,
            },
        );
        service_impl.route_table.next_hop_map_version.set(1);

        let (untrusted_peers, _) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers(
                Some(network_secret),
                |peer_id| service_impl.is_active_non_reusable_credential_peer(peer_id),
            );
        assert!(untrusted_peers.is_empty());
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&stale_peer_id)
        );
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&replacement_peer_id)
        );
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(replacement_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .is_route_suppressed(stale_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .is_route_suppressed(replacement_peer_id)
        );
    }

    #[tokio::test]
    async fn suppressed_non_reusable_credential_peer_stays_synced_and_can_be_reactivated() {
        const NETWORK_SECRET: &str = "sec1";
        const SELF_PEER_ID: PeerId = 1;
        const ADMIN_PEER_ID: PeerId = 30;
        const FIRST_PEER_ID: PeerId = 39;
        const SECOND_PEER_ID: PeerId = 41;

        let service_impl = PeerRouteServiceImpl::new(
            SELF_PEER_ID,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "test-net".to_string(),
                NETWORK_SECRET.to_string(),
            ))),
        );
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let now = SystemTime::now();
        let mut self_info = RoutePeerInfo::new();
        self_info.peer_id = SELF_PEER_ID;
        self_info.version = 1;

        let admin_info = make_admin_route_peer_info(
            service_impl.global_ctx.get_credential_manager(),
            ADMIN_PEER_ID,
            &[10; 32],
            NETWORK_SECRET,
            now_unix,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);
        let mut first_peer = make_credential_route_peer_info(FIRST_PEER_ID, &credential_key);
        first_peer.ipv4_addr = Some(std::net::Ipv4Addr::new(10, 144, 0, 39).into());
        let mut second_peer = make_credential_route_peer_info(SECOND_PEER_ID, &credential_key);
        second_peer.ipv4_addr = Some(std::net::Ipv4Addr::new(10, 144, 0, 41).into());
        second_peer.proxy_cidrs.push("10.244.41.0/24".into());

        {
            let mut peer_infos = service_impl.synced_route_info.peer_infos.write();
            peer_infos.insert(self_info.peer_id, self_info);
            peer_infos.insert(admin_info.peer_id, admin_info);
            peer_infos.insert(first_peer.peer_id, first_peer);
            peer_infos.insert(second_peer.peer_id, second_peer);
        }
        {
            let mut conn_map = service_impl.synced_route_info.conn_map.write();
            conn_map.insert(SELF_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
            conn_map.insert(
                ADMIN_PEER_ID,
                make_route_conn_info([SELF_PEER_ID, FIRST_PEER_ID, SECOND_PEER_ID], now),
            );
            conn_map.insert(FIRST_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
            conn_map.insert(SECOND_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
        }
        service_impl.synced_route_info.version.set(1);

        let first_untrusted = service_impl.refresh_credential_trusts_with_current_topology();
        assert!(first_untrusted.is_empty());
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(FIRST_PEER_ID)
        );
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&SECOND_PEER_ID)
        );
        assert!(
            service_impl
                .synced_route_info
                .is_route_suppressed(SECOND_PEER_ID)
        );
        assert!(
            service_impl
                .route_table
                .topology_peer_reachable(SECOND_PEER_ID)
        );
        assert!(service_impl.route_table.peer_reachable(FIRST_PEER_ID));
        assert!(!service_impl.route_table.peer_reachable(SECOND_PEER_ID));
        assert!(
            service_impl
                .route_table
                .peer_infos
                .contains_key(&FIRST_PEER_ID)
        );
        assert!(
            !service_impl
                .route_table
                .peer_infos
                .contains_key(&SECOND_PEER_ID)
        );
        assert_eq!(
            service_impl
                .route_table
                .ipv4_peer_id_map
                .get(&"10.144.0.41".parse().unwrap())
                .map(|entry| entry.peer_id),
            None
        );
        assert_eq!(
            service_impl
                .route_table
                .get_peer_id_for_proxy(&"10.244.41.1".parse().unwrap()),
            None
        );
        let sync_session = SyncRouteSession::new(SELF_PEER_ID, ADMIN_PEER_ID);
        let sync_peer_ids: BTreeSet<_> = service_impl
            .build_route_info(&sync_session)
            .unwrap()
            .into_iter()
            .map(|info| info.peer_id)
            .collect();
        assert!(sync_peer_ids.contains(&SECOND_PEER_ID));

        {
            let mut conn_map = service_impl.synced_route_info.conn_map.write();
            conn_map.insert(
                ADMIN_PEER_ID,
                make_route_conn_info([SELF_PEER_ID, SECOND_PEER_ID], now),
            );
            conn_map.insert(FIRST_PEER_ID, make_route_conn_info([], now));
            conn_map.insert(SECOND_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
        }
        service_impl.synced_route_info.version.inc();

        let second_untrusted = service_impl.refresh_credential_trusts_with_current_topology();
        assert!(second_untrusted.is_empty());
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(SECOND_PEER_ID)
        );
        assert!(
            !service_impl
                .synced_route_info
                .is_route_suppressed(SECOND_PEER_ID)
        );
        assert!(
            service_impl
                .route_table
                .topology_peer_reachable(SECOND_PEER_ID)
        );
        assert!(!service_impl.route_table.peer_reachable(FIRST_PEER_ID));
        assert!(service_impl.route_table.peer_reachable(SECOND_PEER_ID));
        assert!(
            !service_impl
                .route_table
                .peer_infos
                .contains_key(&FIRST_PEER_ID)
        );
        assert!(
            service_impl
                .route_table
                .peer_infos
                .contains_key(&SECOND_PEER_ID)
        );
        assert_eq!(
            service_impl
                .route_table
                .ipv4_peer_id_map
                .get(&"10.144.0.41".parse().unwrap())
                .map(|entry| entry.peer_id),
            Some(SECOND_PEER_ID)
        );
        assert_eq!(
            service_impl
                .route_table
                .get_peer_id_for_proxy(&"10.244.41.1".parse().unwrap()),
            Some(SECOND_PEER_ID)
        );
    }

    #[tokio::test]
    async fn suppressed_non_reusable_credential_peer_is_not_transit_next_hop() {
        const NETWORK_SECRET: &str = "sec1";
        const SELF_PEER_ID: PeerId = 1;
        const ADMIN_PEER_ID: PeerId = 30;
        const FIRST_PEER_ID: PeerId = 39;
        const SECOND_PEER_ID: PeerId = 41;
        const DOWNSTREAM_PEER_ID: PeerId = 50;

        let service_impl = PeerRouteServiceImpl::new(
            SELF_PEER_ID,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "test-net".to_string(),
                NETWORK_SECRET.to_string(),
            ))),
        );
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let now = SystemTime::now();
        let mut self_info = RoutePeerInfo::new();
        self_info.peer_id = SELF_PEER_ID;
        self_info.version = 1;

        let admin_info = make_admin_route_peer_info(
            service_impl.global_ctx.get_credential_manager(),
            ADMIN_PEER_ID,
            &[10; 32],
            NETWORK_SECRET,
            now_unix,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);
        let first_peer = make_credential_route_peer_info(FIRST_PEER_ID, &credential_key);
        let second_peer = make_credential_route_peer_info(SECOND_PEER_ID, &credential_key);
        let mut downstream_peer = RoutePeerInfo::new();
        downstream_peer.peer_id = DOWNSTREAM_PEER_ID;
        downstream_peer.version = 1;

        {
            let mut peer_infos = service_impl.synced_route_info.peer_infos.write();
            peer_infos.insert(self_info.peer_id, self_info);
            peer_infos.insert(admin_info.peer_id, admin_info);
            peer_infos.insert(first_peer.peer_id, first_peer);
            peer_infos.insert(second_peer.peer_id, second_peer);
            peer_infos.insert(downstream_peer.peer_id, downstream_peer);
        }
        {
            let mut conn_map = service_impl.synced_route_info.conn_map.write();
            conn_map.insert(SELF_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
            conn_map.insert(
                ADMIN_PEER_ID,
                make_route_conn_info([SELF_PEER_ID, FIRST_PEER_ID, SECOND_PEER_ID], now),
            );
            conn_map.insert(FIRST_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
            conn_map.insert(
                SECOND_PEER_ID,
                make_route_conn_info([ADMIN_PEER_ID, DOWNSTREAM_PEER_ID], now),
            );
            conn_map.insert(
                DOWNSTREAM_PEER_ID,
                make_route_conn_info([SECOND_PEER_ID], now),
            );
        }
        service_impl.synced_route_info.version.set(1);

        let untrusted = service_impl.refresh_credential_trusts_with_current_topology();
        assert!(untrusted.is_empty());
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(FIRST_PEER_ID)
        );
        assert!(
            service_impl
                .synced_route_info
                .is_route_suppressed(SECOND_PEER_ID)
        );
        assert!(
            service_impl
                .route_table
                .topology_peer_reachable(SECOND_PEER_ID)
        );
        assert!(!service_impl.route_table.peer_reachable(SECOND_PEER_ID));
        assert!(!service_impl.route_table.peer_reachable(DOWNSTREAM_PEER_ID));
        assert!(
            service_impl
                .route_table
                .get_next_hop(DOWNSTREAM_PEER_ID)
                .is_none()
        );
        assert!(
            !service_impl
                .route_table
                .peer_infos
                .contains_key(&DOWNSTREAM_PEER_ID)
        );
    }

    #[tokio::test]
    async fn credential_trust_refresh_does_not_remove_self_peer() {
        let my_peer_id = 11;
        let remote_peer_id = 12;
        let service_impl = PeerRouteServiceImpl::new(my_peer_id, get_mock_global_ctx());
        let credential = signed_test_credential(
            service_impl.global_ctx.get_credential_manager(),
            &[8; 32],
            Duration::from_secs(600),
        );
        let credential_key = credential.pubkey.clone();

        let self_info = make_credential_route_peer_info(my_peer_id, &credential_key);
        let remote_info = make_credential_route_peer_info(remote_peer_id, &credential_key);

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(self_info.peer_id, self_info);
            guard.insert(remote_info.peer_id, remote_info);
        }
        service_impl
            .synced_route_info
            .trusted_credential_pubkeys
            .insert(credential_key.clone(), credential);

        let (untrusted_peers, _, _) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts_with_active_peers_protecting(
                None,
                |_| true,
                Some(my_peer_id),
            );

        assert_eq!(untrusted_peers, vec![remote_peer_id]);
        assert!(
            service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&my_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&remote_peer_id)
        );
    }

    #[tokio::test]
    async fn credential_refresh_rebuilds_reachability_before_owner_election() {
        const NETWORK_SECRET: &str = "sec1";
        const SELF_PEER_ID: PeerId = 1;

        let service_impl = PeerRouteServiceImpl::new(
            SELF_PEER_ID,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "test-net".to_string(),
                NETWORK_SECRET.to_string(),
            ))),
        );

        let admin_peer_id = 30;
        let stale_peer_id = 41;
        let replacement_peer_id = 39;

        let mut self_info = RoutePeerInfo::new();
        self_info.peer_id = SELF_PEER_ID;
        self_info.version = 1;

        let admin_info = make_admin_route_peer_info(
            service_impl.global_ctx.get_credential_manager(),
            admin_peer_id,
            &[9; 32],
            NETWORK_SECRET,
            0,
        );
        let credential_key = credential_pubkey_from_info(&admin_info);

        let stale_peer = make_credential_route_peer_info(stale_peer_id, &credential_key);
        let replacement_peer =
            make_credential_route_peer_info(replacement_peer_id, &credential_key);

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(self_info.peer_id, self_info);
            guard.insert(admin_info.peer_id, admin_info);
            guard.insert(stale_peer.peer_id, stale_peer);
            guard.insert(replacement_peer.peer_id, replacement_peer);
        }

        let now = std::time::SystemTime::now();
        {
            let mut guard = service_impl.synced_route_info.conn_map.write();
            guard.insert(SELF_PEER_ID, make_route_conn_info([admin_peer_id], now));
            guard.insert(
                admin_peer_id,
                make_route_conn_info([SELF_PEER_ID, replacement_peer_id], now),
            );
            guard.insert(
                replacement_peer_id,
                make_route_conn_info([admin_peer_id], now),
            );
            guard.insert(stale_peer_id, make_route_conn_info([], now));
        }
        service_impl.synced_route_info.version.set(2);

        service_impl.update_route_table_and_cached_local_conn_bitmap();
        assert!(!service_impl.is_active_non_reusable_credential_peer(stale_peer_id));
        assert!(service_impl.is_active_non_reusable_credential_peer(replacement_peer_id));

        service_impl.route_table.next_hop_map.clear();
        service_impl.route_table.next_hop_map.insert(
            stale_peer_id,
            NextHopInfo {
                next_hop_peer_id: stale_peer_id,
                path_delivery_bps: 0,
                path_latency: 0,
                path_len: 1,
                version: 1,
            },
        );
        service_impl.route_table.next_hop_map_version.set(1);

        let untrusted = service_impl.refresh_credential_trusts_with_current_topology();
        assert!(untrusted.is_empty());
        assert!(!service_impl.is_active_non_reusable_credential_peer(stale_peer_id));
        assert!(service_impl.is_active_non_reusable_credential_peer(replacement_peer_id));
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(replacement_peer_id)
        );
    }

    #[tokio::test]
    async fn update_my_infos_refreshes_non_reusable_owner_on_conn_change() {
        const NETWORK_SECRET: &str = "sec1";
        const ADMIN_PEER_ID: PeerId = 30;
        const FIRST_PEER_ID: PeerId = 39;
        const SECOND_PEER_ID: PeerId = 41;

        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "test-net".to_string(),
            NETWORK_SECRET.to_string(),
        )));
        let (_credential_id, credential_secret) = global_ctx
            .get_credential_manager()
            .generate_credential_with_options(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                false,
            )
            .unwrap();
        let credential_secret =
            crate::peers::credential_manager::CredentialManager::private_key_from_bundle(
                &credential_secret,
            )
            .unwrap();
        let credential_key = x25519_dalek::PublicKey::from(&credential_secret)
            .as_bytes()
            .to_vec();

        let service_impl = PeerRouteServiceImpl::new(ADMIN_PEER_ID, global_ctx);
        let peers = Arc::new(Mutex::new(vec![FIRST_PEER_ID, SECOND_PEER_ID]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::from([
            (FIRST_PEER_ID, Some(PeerIdentityType::Credential)),
            (SECOND_PEER_ID, Some(PeerIdentityType::Credential)),
        ])));
        *service_impl.interface.lock().await = Some(Arc::new(CountingInterface {
            my_peer_id: ADMIN_PEER_ID,
            peers: peers.clone(),
            peer_identity_types,
            list_peers_calls: Arc::new(AtomicU32::new(0)),
            get_peer_identity_type_calls: Arc::new(AtomicU32::new(0)),
        }));

        {
            let mut peer_infos = service_impl.synced_route_info.peer_infos.write();
            peer_infos.insert(
                FIRST_PEER_ID,
                make_credential_route_peer_info(FIRST_PEER_ID, &credential_key),
            );
            peer_infos.insert(
                SECOND_PEER_ID,
                make_credential_route_peer_info(SECOND_PEER_ID, &credential_key),
            );
        }
        let now = SystemTime::now();
        {
            let mut conn_map = service_impl.synced_route_info.conn_map.write();
            conn_map.insert(FIRST_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
            conn_map.insert(SECOND_PEER_ID, make_route_conn_info([ADMIN_PEER_ID], now));
        }

        assert!(service_impl.update_my_infos().await);
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(FIRST_PEER_ID)
        );
        assert!(service_impl.route_table.peer_reachable(FIRST_PEER_ID));
        assert!(!service_impl.route_table.peer_reachable(SECOND_PEER_ID));

        *peers.lock() = vec![SECOND_PEER_ID];
        service_impl.handle_global_ctx_event(&GlobalCtxEvent::PeerConnRemoved(Default::default()));

        assert!(service_impl.update_my_infos().await);
        assert_eq!(
            service_impl
                .synced_route_info
                .non_reusable_credential_owners
                .get(&credential_key)
                .map(|entry| *entry.value()),
            Some(SECOND_PEER_ID)
        );
        assert!(!service_impl.route_table.peer_reachable(FIRST_PEER_ID));
        assert!(service_impl.route_table.peer_reachable(SECOND_PEER_ID));
    }

    #[tokio::test]
    async fn sync_route_info_marks_credential_sender_and_filters_entries() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 10001;
        let forwarded_peer_id: PeerId = 10002;
        let forged_route_key = vec![4u8; 32];
        let credential = signed_test_credential(
            route.service_impl.global_ctx.get_credential_manager(),
            &[3u8; 32],
            Duration::from_secs(600),
        );
        let credential_pubkey = credential.pubkey.clone();

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::Credential);
        let peer_public_key = DashMap::new();
        peer_public_key.insert(from_peer_id, credential_pubkey.clone());
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key,
        }));
        // Publish the freshly generated credential from the local admin peer
        // info; the sync-time trust refresh drops proofs no admin publishes.
        route.service_impl.update_my_peer_info();
        route
            .service_impl
            .synced_route_info
            .trusted_credential_pubkeys
            .insert(credential_pubkey.clone(), credential);

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;
        // The sender claims a different route key than the authenticated key.
        sender_info.noise_static_pubkey = forged_route_key.clone();
        sender_info.proxy_cidrs = vec!["10.10.0.0/24".to_string()];

        let mut forwarded_info = RoutePeerInfo::new();
        forwarded_info.peer_id = forwarded_peer_id;
        forwarded_info.version = 1;

        let make_raw = |info: &RoutePeerInfo| {
            let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
            raw.transcode_from(info).unwrap();
            raw
        };
        let raw_infos = vec![make_raw(&sender_info), make_raw(&forwarded_info)];

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info, forwarded_info]),
                Some(raw_infos),
                None,
                None,
                PeerIdentityType::Credential,
            )
            .await
            .unwrap();

        let guard = route.service_impl.synced_route_info.peer_infos.read();
        let stored = guard.get(&from_peer_id).unwrap();
        assert!(
            stored
                .feature_flag
                .as_ref()
                .map(|x| x.is_credential_peer)
                .unwrap_or(false)
        );
        assert!(stored.proxy_cidrs.is_empty());
        assert_eq!(
            PeerIdentityType::try_from(stored.identity_type).unwrap(),
            PeerIdentityType::Credential
        );
        assert_eq!(stored.noise_static_pubkey, credential_pubkey);
        assert_ne!(stored.noise_static_pubkey, forged_route_key);
        assert!(guard.get(&forwarded_peer_id).is_none());
    }

    // shared node doesn't have hmac.
    #[tokio::test]
    async fn sync_route_info_shared_sender_cannot_publish_trusted_credentials() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 10021;
        let forwarded_peer_id: PeerId = 10022;
        let credential = signed_test_credential(
            route.service_impl.global_ctx.get_credential_manager(),
            &[9u8; 32],
            Duration::from_secs(600),
        );
        let credential_key = credential.pubkey.clone();

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::SharedNode);
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key: DashMap::new(),
        }));

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;

        let mut forwarded_info = RoutePeerInfo::new();
        forwarded_info.peer_id = forwarded_peer_id;
        forwarded_info.version = 1;
        forwarded_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential,
            "route-secret",
        )];

        let make_raw = |info: &RoutePeerInfo| {
            let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
            raw.transcode_from(info).unwrap();
            raw
        };
        let raw_infos = vec![make_raw(&sender_info), make_raw(&forwarded_info)];

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info, forwarded_info]),
                Some(raw_infos),
                None,
                None,
                PeerIdentityType::SharedNode,
            )
            .await
            .unwrap();

        assert!(
            !route
                .service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_key)
        );
        let guard = route.service_impl.synced_route_info.peer_infos.read();
        let stored = guard.get(&from_peer_id).unwrap();
        assert_eq!(
            PeerIdentityType::try_from(stored.identity_type).unwrap(),
            PeerIdentityType::SharedNode
        );
        assert!(guard.get(&forwarded_peer_id).is_none());
    }

    #[tokio::test]
    async fn sync_route_info_foreign_relay_accepts_only_authenticated_self_info() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 10031;
        let forwarded_peer_id: PeerId = 10032;
        let credential = signed_test_credential(
            route.service_impl.global_ctx.get_credential_manager(),
            &[8u8; 32],
            Duration::from_secs(600),
        );
        let credential_key = credential.pubkey.clone();

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::ForeignRelay);
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key: DashMap::new(),
        }));

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;
        sender_info.identity_type = PeerIdentityType::Admin as i32;
        sender_info.proxy_cidrs = vec!["10.10.0.0/24".to_string()];
        sender_info.groups = vec![PeerGroupInfo {
            group_name: "admin".to_string(),
            group_proof: vec![1, 2, 3],
        }];
        sender_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential,
            "route-secret",
        )];
        sender_info.feature_flag = Some(PeerFeatureFlag {
            ethernet_input: true,
            bridge_input: true,
            multicast_membership: true,
            ..Default::default()
        });
        sender_info.multicast_groups = vec![vec![224, 0, 0, 1]];

        let mut forwarded_info = RoutePeerInfo::new();
        forwarded_info.peer_id = forwarded_peer_id;
        forwarded_info.version = 1;
        forwarded_info.proxy_cidrs = vec!["10.20.0.0/24".to_string()];
        forwarded_info.groups = sender_info.groups.clone();
        forwarded_info.trusted_credential_pubkeys = sender_info.trusted_credential_pubkeys.clone();
        forwarded_info.feature_flag = sender_info.feature_flag;
        forwarded_info.multicast_groups = sender_info.multicast_groups.clone();

        let make_raw = |info: &RoutePeerInfo| {
            let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
            raw.transcode_from(info).unwrap();
            raw
        };
        let raw_infos = vec![make_raw(&sender_info), make_raw(&forwarded_info)];
        let foreign_network = RouteForeignNetworkInfos {
            infos: vec![route_foreign_network_infos::Info {
                key: Some(ForeignNetworkRouteInfoKey {
                    peer_id: from_peer_id,
                    network_name: "foreign-net".to_string(),
                }),
                value: Some(ForeignNetworkRouteInfoEntry {
                    foreign_peer_ids: vec![forwarded_peer_id],
                    version: 1,
                    network_secret_digest: vec![9; 32],
                    owner_noise_static_pubkey: vec![7; 32],
                    ..Default::default()
                }),
            }],
        };
        let conn_info = crate::proto::peer_rpc::sync_route_info_request::ConnInfo::ConnPeerList(
            RouteConnPeerList {
                peer_conn_infos: vec![crate::proto::peer_rpc::route_conn_peer_list::PeerConnInfo {
                    peer_id: Some(PeerIdVersion {
                        peer_id: from_peer_id,
                        version: 1,
                    }),
                    connected_peer_ids: vec![forwarded_peer_id],
                }],
            },
        );

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info, forwarded_info]),
                Some(raw_infos),
                Some(conn_info),
                Some(foreign_network),
                PeerIdentityType::ForeignRelay,
            )
            .await
            .unwrap();

        let guard = route.service_impl.synced_route_info.peer_infos.read();
        let stored_sender = guard.get(&from_peer_id).expect("relay route is stored");
        assert_eq!(
            SyncedRouteInfo::peer_identity_type(stored_sender),
            Some(PeerIdentityType::ForeignRelay)
        );
        assert!(stored_sender.proxy_cidrs.is_empty());
        assert!(stored_sender.groups.is_empty());
        assert!(stored_sender.trusted_credential_pubkeys.is_empty());

        assert!(guard.get(&forwarded_peer_id).is_none());
        assert!(
            stored_sender
                .feature_flag
                .as_ref()
                .is_some_and(|flags| !flags.ethernet_input
                    && !flags.bridge_input
                    && !flags.multicast_membership)
        );
        assert!(stored_sender.multicast_groups.is_empty());
        drop(guard);

        assert!(
            !route
                .service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_key)
        );
        assert!(
            !route
                .service_impl
                .synced_route_info
                .foreign_network
                .contains_key(&ForeignNetworkRouteInfoKey {
                    peer_id: from_peer_id,
                    network_name: "foreign-net".to_string(),
                })
        );
        assert!(
            !route
                .service_impl
                .synced_route_info
                .conn_map
                .read()
                .contains_key(&from_peer_id)
        );
    }

    #[tokio::test]
    async fn foreign_relay_cannot_overwrite_authenticated_local_peer() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 10041;
        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::ForeignRelay);
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key: DashMap::new(),
        }));

        let mut existing = RoutePeerInfo::new();
        existing.peer_id = from_peer_id;
        existing.version = 1;
        existing.identity_type = PeerIdentityType::Admin as i32;
        {
            route
                .service_impl
                .synced_route_info
                .peer_infos
                .write()
                .insert(from_peer_id, existing);
        }

        let mut forged = RoutePeerInfo::new();
        forged.peer_id = from_peer_id;
        forged.version = 99;
        forged.identity_type = PeerIdentityType::Admin as i32;
        let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
        raw.transcode_from(&forged).unwrap();

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![forged]),
                Some(vec![raw]),
                None,
                None,
                PeerIdentityType::ForeignRelay,
            )
            .await
            .unwrap();

        let guard = route.service_impl.synced_route_info.peer_infos.read();
        assert_eq!(
            SyncedRouteInfo::peer_identity_type(guard.get(&from_peer_id).unwrap()),
            Some(PeerIdentityType::Admin)
        );
        assert_eq!(guard.get(&from_peer_id).unwrap().version, 1);
    }

    #[tokio::test]
    async fn clear_expired_peer_recomputes_trust_after_last_admin_disappears() {
        let network_secret = "route-secret";
        let service_impl = PeerRouteServiceImpl::new(
            1,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "test-net".to_string(),
                network_secret.to_string(),
            ))),
        );
        let admin_peer_id: PeerId = 10051;
        let credential_peer_id: PeerId = 10052;
        let admin_pubkey = vec![5u8; 32];
        let credential = generated_test_credential(
            service_impl.global_ctx.get_credential_manager(),
            vec!["guest".to_string()],
            false,
            Vec::new(),
            Duration::from_secs(600),
            true,
        );
        let credential_pubkey = credential.pubkey.clone();
        let network_name = service_impl
            .global_ctx
            .get_network_identity()
            .network_name
            .clone();
        let now = SystemTime::now();
        let closed_peers = Arc::new(Mutex::new(Vec::new()));

        *service_impl.interface.lock().await = Some(Arc::new(TrackingInterface {
            my_peer_id: service_impl.my_peer_id,
            closed_peers: closed_peers.clone(),
        }));

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();

            let mut admin_info = RoutePeerInfo::new();
            admin_info.peer_id = admin_peer_id;
            admin_info.version = 1;
            admin_info.last_update =
                Some((now - REMOVE_DEAD_PEER_INFO_AFTER - Duration::from_secs(1)).into());
            admin_info.noise_static_pubkey = admin_pubkey;
            admin_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
                credential,
                network_secret,
            )];

            let mut credential_info = RoutePeerInfo::new();
            credential_info.peer_id = credential_peer_id;
            credential_info.version = 1;
            credential_info.last_update = Some(now.into());
            credential_info.noise_static_pubkey = credential_pubkey.clone();

            guard.insert(admin_peer_id, admin_info);
            guard.insert(credential_peer_id, credential_info);
        }

        let (_, global_trusted_keys) = service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(Some(network_secret));
        service_impl
            .global_ctx
            .update_trusted_keys(global_trusted_keys, &network_name);

        assert!(
            service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_pubkey)
        );
        assert!(
            service_impl
                .get_peer_groups(credential_peer_id)
                .contains(&"guest".to_string())
        );

        service_impl.clear_expired_peer().await;

        assert!(!service_impl.global_ctx.is_pubkey_trusted_with_source(
            &credential_pubkey,
            &network_name,
            TrustedKeySource::OspfCredential,
        ));
        assert!(closed_peers.lock().contains(&credential_peer_id));
        assert!(
            !service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&admin_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&credential_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .group_trust_map_cache
                .contains_key(&credential_peer_id)
        );
    }

    #[tokio::test]
    async fn refresh_acl_groups_returns_true_when_untrusted_peers_are_disconnected() {
        let service_impl = PeerRouteServiceImpl::new(1, get_mock_global_ctx());
        let credential_peer_id: PeerId = 10061;
        let closed_peers = Arc::new(Mutex::new(Vec::new()));
        // A previously trusted key that no admin currently publishes.
        let credential_pubkey = vec![8u8; 32];

        *service_impl.interface.lock().await = Some(Arc::new(TrackingInterface {
            my_peer_id: service_impl.my_peer_id,
            closed_peers: closed_peers.clone(),
        }));

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = credential_peer_id;
        credential_info.version = 1;
        credential_info.noise_static_pubkey = credential_pubkey.clone();
        credential_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });
        let self_info = RoutePeerInfo::new_updated_self(
            service_impl.my_peer_id,
            service_impl.my_peer_route_id,
            &service_impl.global_ctx,
            None,
        );
        let mut self_info = self_info;
        self_info.version = 1;
        self_info.last_update = Some(Timestamp::now());
        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(service_impl.my_peer_id, self_info);
            guard.insert(credential_peer_id, credential_info);
        }
        service_impl
            .synced_route_info
            .trusted_credential_pubkeys
            .insert(
                credential_pubkey.clone(),
                TrustedCredentialPubkey {
                    pubkey: credential_pubkey.clone(),
                    expiry_unix: i64::MAX,
                    ..Default::default()
                },
            );

        assert!(service_impl.refresh_acl_groups().await);
        assert!(closed_peers.lock().contains(&credential_peer_id));
        assert!(
            !service_impl
                .synced_route_info
                .peer_infos
                .read()
                .contains_key(&credential_peer_id)
        );
        assert!(
            !service_impl
                .synced_route_info
                .trusted_credential_pubkeys
                .contains_key(&credential_pubkey)
        );
    }

    #[tokio::test]
    async fn refresh_acl_groups_updates_local_membership_immediately() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let my_peer_id = peer_mgr.my_peer_id();

        assert!(route.service_impl.get_peer_groups(my_peer_id).is_empty());

        peer_mgr.get_global_ctx().config.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "admin".to_string(),
                        group_secret: "admin-secret".to_string(),
                    }],
                    members: vec!["admin".to_string()],
                }),
                ..Default::default()
            }),
        }));

        route.refresh_acl_groups().await;

        let groups = route.service_impl.get_peer_groups(my_peer_id);
        assert!(groups.contains(&"admin".to_string()));
        assert_eq!(groups.len(), 1);
    }

    #[tokio::test]
    async fn refresh_acl_groups_revalidates_cached_remote_groups() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let remote_peer_id = 200;
        let remote_group = PeerGroupInfo::generate_with_proof(
            "ops".to_string(),
            "secret-v1".to_string(),
            remote_peer_id,
        );

        peer_mgr.get_global_ctx().config.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "ops".to_string(),
                        group_secret: "secret-v1".to_string(),
                    }],
                    members: vec![],
                }),
                ..Default::default()
            }),
        }));

        let mut remote_info = RoutePeerInfo::new();
        remote_info.peer_id = remote_peer_id;
        remote_info.version = 1;
        remote_info.groups = vec![remote_group];
        route
            .service_impl
            .synced_route_info
            .peer_infos
            .write()
            .insert(remote_peer_id, remote_info.clone());
        route
            .service_impl
            .synced_route_info
            .verify_and_update_group_trusts(
                &[remote_info],
                &peer_mgr.get_global_ctx().get_acl_group_declarations(),
                false,
            );

        assert!(
            route
                .service_impl
                .get_peer_groups(remote_peer_id)
                .contains(&"ops".to_string())
        );

        peer_mgr.get_global_ctx().config.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "ops".to_string(),
                        group_secret: "secret-v2".to_string(),
                    }],
                    members: vec![],
                }),
                ..Default::default()
            }),
        }));

        route.refresh_acl_groups().await;

        assert!(
            route
                .service_impl
                .get_peer_groups(remote_peer_id)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn credential_verifier_trusts_admin_self_groups_from_multiple_admins() {
        let service_impl = PeerRouteServiceImpl::new(
            1,
            crate::common::global_ctx::tests::get_mock_credential_global_ctx("net1"),
        );

        let mut admin_a = RoutePeerInfo::new();
        admin_a.peer_id = 501;
        admin_a.version = 1;
        admin_a.noise_static_pubkey = vec![5; 32];
        admin_a.groups = vec![
            PeerGroupInfo {
                group_name: "ops".to_string(),
                group_proof: vec![1; 32],
            },
            PeerGroupInfo {
                group_name: "core-admin".to_string(),
                group_proof: vec![2; 32],
            },
        ];

        let mut admin_b = RoutePeerInfo::new();
        admin_b.peer_id = 502;
        admin_b.version = 1;
        admin_b.noise_static_pubkey = vec![6; 32];
        admin_b.groups = vec![PeerGroupInfo {
            group_name: "audit".to_string(),
            group_proof: vec![3; 32],
        }];

        assert_eq!(
            service_impl.seed_authenticated_peer(
                admin_a.peer_id,
                PeerIdentityType::Admin,
                admin_a.noise_static_pubkey.clone(),
                SecureAuthLevel::PeerVerified,
            ),
            AuthenticatedPeerSeedResult::Inserted
        );
        assert_eq!(
            service_impl.seed_authenticated_peer(
                admin_b.peer_id,
                PeerIdentityType::Admin,
                admin_b.noise_static_pubkey.clone(),
                SecureAuthLevel::PeerVerified,
            ),
            AuthenticatedPeerSeedResult::Inserted
        );

        service_impl
            .synced_route_info
            .verify_and_update_group_trusts(&[admin_a.clone(), admin_b.clone()], &[], true);

        let admin_a_groups = service_impl.get_peer_groups(admin_a.peer_id);
        assert!(admin_a_groups.contains(&"ops".to_string()));
        assert!(admin_a_groups.contains(&"core-admin".to_string()));

        let admin_b_groups = service_impl.get_peer_groups(admin_b.peer_id);
        assert!(admin_b_groups.contains(&"audit".to_string()));
    }

    #[tokio::test]
    async fn credential_verifier_still_checks_credential_self_declared_groups() {
        let service_impl = PeerRouteServiceImpl::new(
            1,
            crate::common::global_ctx::tests::get_mock_credential_global_ctx("net1"),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let credential_peer_id = 601;
        let credential = credential_from_context(&service_impl.global_ctx);
        let credential_pubkey = credential.pubkey.clone();

        let mut admin_info = RoutePeerInfo::new();
        admin_info.peer_id = 600;
        admin_info.version = 1;
        admin_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof {
            credential: Some(credential),
            credential_hmac: vec![7; 32],
        }];

        let mut credential_info = RoutePeerInfo::new();
        credential_info.peer_id = credential_peer_id;
        credential_info.version = 1;
        credential_info.noise_static_pubkey = credential_pubkey.clone();
        credential_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });
        credential_info.groups = vec![
            PeerGroupInfo::generate_with_proof(
                "proof-group".to_string(),
                "proof-secret".to_string(),
                credential_peer_id,
            ),
            PeerGroupInfo::generate_with_proof(
                "invalid-group".to_string(),
                "wrong-secret".to_string(),
                credential_peer_id,
            ),
        ];

        {
            let mut guard = service_impl.synced_route_info.peer_infos.write();
            guard.insert(admin_info.peer_id, admin_info.clone());
            guard.insert(credential_info.peer_id, credential_info.clone());
        }

        service_impl
            .synced_route_info
            .verify_and_update_group_trusts(
                &[admin_info, credential_info],
                &[
                    GroupIdentity {
                        group_name: "proof-group".to_string(),
                        group_secret: "proof-secret".to_string(),
                    },
                    GroupIdentity {
                        group_name: "invalid-group".to_string(),
                        group_secret: "actual-secret".to_string(),
                    },
                ],
                true,
            );
        service_impl
            .synced_route_info
            .verify_and_update_credential_trusts(None);

        let groups = service_impl.get_peer_groups(credential_peer_id);
        assert!(groups.contains(&"proof-group".to_string()));
        assert!(!groups.contains(&"cred-acl".to_string()));
        assert!(!groups.contains(&"invalid-group".to_string()));
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_2node(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);

        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;

        for r in [r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async {
                    println!("route: {:?}", r.list_routes().await);
                    r.list_routes().await.len() == 1
                },
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert_eq!(
            2,
            r_a.service_impl.synced_route_info.peer_infos.read().len()
        );
        assert_eq!(
            2,
            r_b.service_impl.synced_route_info.peer_infos.read().len()
        );

        for s in r_a.service_impl.sessions.iter() {
            assert!(s.value().task.is_running());
        }

        assert_eq!(
            r_a.service_impl
                .synced_route_info
                .peer_infos
                .read()
                .get(&p_a.my_peer_id())
                .unwrap()
                .version,
            r_a.service_impl
                .get_session(p_b.my_peer_id())
                .unwrap()
                .dst_saved_peer_info_versions
                .get(&p_a.my_peer_id())
                .unwrap()
                .value()
                .get()
        );

        assert_eq!((1, 1), get_rpc_counter(&r_a, p_b.my_peer_id()));
        assert_eq!((1, 1), get_rpc_counter(&r_b, p_a.my_peer_id()));

        let i_a = get_is_initiator(&r_a, p_b.my_peer_id());
        let i_b = get_is_initiator(&r_b, p_a.my_peer_id());
        assert_eq!(i_a.0, i_b.1);
        assert_eq!(i_b.0, i_a.1);

        println!("after drop p_b, r_b");

        drop(r_b);
        drop(p_b);

        wait_for_condition(
            || async { r_a.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async { r_a.service_impl.sessions.is_empty() },
            Duration::from_secs(5),
        )
        .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_multi_node(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);

        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in [r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.read().len() == 3 },
                Duration::from_secs(5),
            )
            .await;
        }

        connect_peer_manager(p_a.clone(), p_c.clone()).await;
        // for full-connected 3 nodes, the sessions between them may be a cycle or a line
        wait_for_condition(
            || async {
                let mut lens = vec![
                    r_a.service_impl.sessions.len(),
                    r_b.service_impl.sessions.len(),
                    r_c.service_impl.sessions.len(),
                ];
                lens.sort();

                lens == vec![1, 1, 2] || lens == vec![2, 2, 2]
            },
            Duration::from_secs(3),
        )
        .await;

        let p_d = create_mock_pmgr().await;
        let r_d = create_mock_route(p_d.clone()).await;
        connect_peer_manager(p_d.clone(), p_a.clone()).await;
        connect_peer_manager(p_d.clone(), p_b.clone()).await;
        connect_peer_manager(p_d.clone(), p_c.clone()).await;

        // find the smallest peer_id, which should be a center node
        let mut all_route = [r_a.clone(), r_b.clone(), r_c.clone(), r_d.clone()];
        all_route.sort_by_key(|r| r.my_peer_id);
        let mut all_peer_mgr = [p_a.clone(), p_b.clone(), p_c.clone(), p_d.clone()];
        all_peer_mgr.sort_by_key(|p| p.my_peer_id());

        wait_for_condition(
            || async { all_route[0].service_impl.sessions.len() == 3 },
            Duration::from_secs(3),
        )
        .await;

        for r in all_route.iter() {
            println!("session: {}", r.session_mgr.dump_sessions().unwrap());
        }

        let p_e = create_mock_pmgr().await;
        let r_e = create_mock_route(p_e.clone()).await;
        let last_p = all_peer_mgr.last().unwrap();
        connect_peer_manager(p_e.clone(), last_p.clone()).await;

        wait_for_condition(
            || async { r_e.session_mgr.list_session_peers().len() == 1 },
            Duration::from_secs(3),
        )
        .await;

        for s in r_e.service_impl.sessions.iter() {
            assert!(s.value().task.is_running());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        check_rpc_counter(&r_e, last_p.my_peer_id(), 2, 2);

        for r in all_route.iter() {
            if r.my_peer_id != last_p.my_peer_id() {
                wait_for_condition(
                    || async {
                        r.get_next_hop(p_e.my_peer_id()).await == Some(last_p.my_peer_id())
                    },
                    Duration::from_secs(3),
                )
                .await;
            } else {
                wait_for_condition(
                    || async { r.get_next_hop(p_e.my_peer_id()).await == Some(p_e.my_peer_id()) },
                    Duration::from_secs(3),
                )
                .await;
            }
        }
    }

    async fn check_route_sanity(p: &Arc<PeerRoute>, routable_peers: Vec<Arc<PeerManager>>) {
        let synced_info = &p.service_impl.synced_route_info;
        for routable_peer in routable_peers.iter() {
            // check conn map
            let conns = {
                let guard = synced_info.conn_map.read();
                guard.get(&routable_peer.my_peer_id()).cloned().unwrap()
            };

            assert_eq!(
                conns.connected_peers,
                routable_peer
                    .get_peer_map()
                    .list_peers()
                    .into_iter()
                    .collect::<BTreeSet<PeerId>>()
            );

            // check peer infos
            let peer_info = synced_info
                .peer_infos
                .read()
                .get(&routable_peer.my_peer_id())
                .cloned()
                .unwrap();
            assert_eq!(peer_info.peer_id, routable_peer.my_peer_id());
        }
    }

    async fn print_routes(peers: Vec<Arc<PeerRoute>>) {
        for p in peers.iter() {
            println!("p:{:?}, route: {:#?}", p.my_peer_id, p.list_routes().await);
        }
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn ospf_route_3node_disconnect(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_c.clone(), p_b.clone()).await;

        let mgrs = vec![p_a.clone(), p_b.clone(), p_c.clone()];

        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;
        let r_c = create_mock_route(p_c.clone()).await;

        for r in [r_a.clone(), r_b.clone(), r_c.clone()].iter() {
            wait_for_condition(
                || async { r.service_impl.synced_route_info.peer_infos.read().len() == 3 },
                Duration::from_secs(5),
            )
            .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        print_routes(vec![r_a.clone(), r_b.clone(), r_c.clone()]).await;
        check_route_sanity(&r_a, mgrs.clone()).await;
        check_route_sanity(&r_b, mgrs.clone()).await;
        check_route_sanity(&r_c, mgrs.clone()).await;

        assert_eq!(2, r_a.list_routes().await.len());

        drop(mgrs);
        drop(r_c);
        drop(p_c);

        for r in [r_a.clone(), r_b.clone()].iter() {
            wait_for_condition(
                || async { r.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
        }
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn peer_reconnect(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let r_a = create_mock_route(p_a.clone()).await;
        let r_b = create_mock_route(p_b.clone()).await;

        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        wait_for_condition(
            || async { r_a.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(1, r_b.list_routes().await.len());

        check_rpc_counter(&r_a, p_b.my_peer_id(), 2, 2);

        p_a.get_peer_map()
            .close_peer(p_b.my_peer_id())
            .await
            .unwrap();
        wait_for_condition(
            || async { r_a.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;

        // reconnect
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        wait_for_condition(
            || async { r_a.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        // wait session init
        tokio::time::sleep(Duration::from_secs(1)).await;

        println!("session: {:?}", r_a.session_mgr.dump_sessions());
        check_rpc_counter(&r_a, p_b.my_peer_id(), 2, 2);
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_cost_calculator(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_pmgr().await;
        let p_b = create_mock_pmgr().await;
        let p_c = create_mock_pmgr().await;
        let p_d = create_mock_pmgr().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_a.clone(), p_c.clone()).await;
        connect_peer_manager(p_d.clone(), p_b.clone()).await;
        connect_peer_manager(p_d.clone(), p_c.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        let _r_a = create_mock_route(p_a.clone()).await;
        let _r_b = create_mock_route(p_b.clone()).await;
        let _r_c = create_mock_route(p_c.clone()).await;
        let r_d = create_mock_route(p_d.clone()).await;

        // in normal mode, packet from p_c should directly forward to p_a
        // the routes are created after the connections, so the first sync
        // attempts can back off before they succeed
        wait_for_condition(
            || async { (r_d.get_next_hop(p_a.my_peer_id()).await).is_some() },
            Duration::from_secs(15),
        )
        .await;

        struct TestCostCalculator {
            p_a_peer_id: PeerId,
            p_b_peer_id: PeerId,
            p_c_peer_id: PeerId,
            p_d_peer_id: PeerId,
            include_delivery: bool,
        }

        impl RouteCostCalculatorInterface for TestCostCalculator {
            fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
                if src == self.p_d_peer_id && dst == self.p_b_peer_id {
                    return 100;
                }

                if src == self.p_d_peer_id && dst == self.p_c_peer_id {
                    return 1;
                }

                if src == self.p_c_peer_id && dst == self.p_a_peer_id {
                    return 101;
                }

                if src == self.p_b_peer_id && dst == self.p_a_peer_id {
                    return 1;
                }

                if src == self.p_c_peer_id && dst == self.p_b_peer_id {
                    return 2;
                }

                1
            }

            fn calculate_delivery_bps(&self, src: PeerId, dst: PeerId) -> Option<u64> {
                if !self.include_delivery {
                    return None;
                }
                if (src == self.p_d_peer_id && dst == self.p_b_peer_id)
                    || (src == self.p_b_peer_id && dst == self.p_a_peer_id)
                {
                    return Some(100_000_000);
                }
                Some(10_000_000)
            }
        }

        r_d.set_route_cost_fn(Box::new(TestCostCalculator {
            p_a_peer_id: p_a.my_peer_id(),
            p_b_peer_id: p_b.my_peer_id(),
            p_c_peer_id: p_c.my_peer_id(),
            p_d_peer_id: p_d.my_peer_id(),
            include_delivery: false,
        }))
        .await;

        // after set cost, packet from p_c should forward to p_b first
        wait_for_condition(
            || async {
                r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::LeastCost)
                    .await
                    == Some(p_c.my_peer_id())
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || async {
                r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::LeastHop)
                    .await
                    == Some(p_b.my_peer_id())
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::MaxGoodput)
                .await,
            Some(p_c.my_peer_id())
        );

        r_d.set_route_cost_fn(Box::new(TestCostCalculator {
            p_a_peer_id: p_a.my_peer_id(),
            p_b_peer_id: p_b.my_peer_id(),
            p_c_peer_id: p_c.my_peer_id(),
            p_d_peer_id: p_d.my_peer_id(),
            include_delivery: true,
        }))
        .await;

        assert_eq!(
            r_d.get_next_hop_with_policy(p_a.my_peer_id(), NextHopPolicy::MaxGoodput)
                .await,
            Some(p_b.my_peer_id())
        );
        let route = r_d
            .list_routes()
            .await
            .into_iter()
            .find(|route| route.peer_id == p_a.my_peer_id())
            .unwrap();
        assert_eq!(route.next_hop_peer_id_speed_first, Some(p_b.my_peer_id()));
        assert_eq!(route.path_delivery_bps_speed_first, Some(100_000_000));
        let labels = LabelSet::new()
            .with_label_type(LabelType::NetworkName(
                r_d.service_impl.global_ctx.get_network_name(),
            ))
            .with_label_type(LabelType::DstPeerId(p_a.my_peer_id()));
        assert_eq!(
            r_d.service_impl
                .global_ctx
                .stats_manager()
                .get_metric(MetricName::SpeedSelectedPathDeliveryBps, &labels)
                .unwrap()
                .value,
            100_000_000
        );
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_raw_peer_info(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let mut req = SyncRouteInfoRequest::default();
        let raw_info_map: DashMap<PeerId, DynamicMessage> = DashMap::new();

        req.peer_infos = Some(RoutePeerInfos {
            items: vec![RoutePeerInfo {
                peer_id: 1,
                ..Default::default()
            }],
        });

        let mut raw_req = DynamicMessage::new(RoutePeerInfo::default().descriptor());
        raw_req
            .transcode_from(&req.peer_infos.as_ref().unwrap().items[0])
            .unwrap();
        raw_info_map.insert(1, raw_req);

        let out = PeerRouteServiceImpl::build_sync_route_raw_req(&req, &raw_info_map);

        let out_bytes = out.encode_to_vec();

        let req2 = SyncRouteInfoRequest::decode(out_bytes.as_slice()).unwrap();

        assert_eq!(req, req2);
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn test_peer_id_map_override(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        let ip: Ipv4Inet = "10.0.0.1/24".parse().unwrap();
        let ipv6: Ipv6Inet = "2001:db8::1/64".parse().unwrap();
        let proxy: Ipv4Cidr = "10.3.0.0/24".parse().unwrap();
        let check_route_peer_id = async |p: Arc<PeerManager>| {
            let p = p.clone();
            wait_for_condition(
                || async {
                    p_a.get_route().get_peer_id_by_ipv4(&ip.address()).await == Some(p.my_peer_id())
                        && p_a.get_route().get_peer_id_by_ipv6(&ipv6.address()).await
                            == Some(p.my_peer_id())
                        && p_a
                            .get_route()
                            .get_peer_id_by_ipv4(&proxy.first_address())
                            .await
                            == Some(p.my_peer_id())
                },
                Duration::from_secs(5),
            )
            .await;
        };

        p_c.get_global_ctx().set_ipv4(Some(ip));
        p_c.get_global_ctx().set_ipv6(Some(ipv6));
        p_c.get_global_ctx()
            .config
            .add_proxy_cidr(proxy, None)
            .unwrap();
        check_route_peer_id(p_c.clone()).await;

        p_b.get_global_ctx().set_ipv4(Some(ip));
        p_b.get_global_ctx().set_ipv6(Some(ipv6));
        p_b.get_global_ctx()
            .config
            .add_proxy_cidr(proxy, None)
            .unwrap();
        check_route_peer_id(p_b.clone()).await;

        p_b.get_global_ctx()
            .set_ipv4(Some("10.0.0.2/24".parse().unwrap()));
        p_b.get_global_ctx()
            .set_ipv6(Some("2001:db8::2/64".parse().unwrap()));
        p_b.get_global_ctx().config.remove_proxy_cidr(proxy);
        check_route_peer_id(p_c.clone()).await;
    }
    #[rstest::rstest]
    #[tokio::test]
    async fn test_subnet_proxy_conflict(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        // Create three peer managers: A, B, C
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        // Connect A-B-C in a line topology
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        // Create routes for testing
        let route_a = p_a.get_route();
        let route_b = p_b.get_route();

        // Define the proxy CIDR that will be used by both A and B
        let proxy_cidr: Ipv4Cidr = "192.168.100.0/24".parse().unwrap();
        let test_ip = proxy_cidr.first_address();

        let mut cidr_peer_id_map: PrefixMap<Ipv4Cidr, PeerIdVersion> = PrefixMap::new();
        cidr_peer_id_map.insert(
            proxy_cidr,
            PeerIdVersion {
                peer_id: p_c.my_peer_id(),
                version: 0,
            },
        );
        assert_eq!(
            cidr_peer_id_map
                .get_lpm(&Ipv4Cidr::new(test_ip, 32).unwrap())
                .map(|v| v.1.peer_id)
                .unwrap_or(0),
            p_c.my_peer_id(),
        );

        // First, add proxy CIDR to node C to establish a baseline route
        p_c.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - A should route to C for the proxy CIDR
        wait_for_condition(
            || async {
                let peer_id_for_proxy = route_a.get_peer_id_by_ipv4(&test_ip).await;
                peer_id_for_proxy == Some(p_c.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;

        // Now add the same proxy CIDR to node A (creating a conflict)
        p_a.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - A should now route to itself for the proxy CIDR
        wait_for_condition(
            || async { route_a.get_peer_id_by_ipv4(&test_ip).await == Some(p_a.my_peer_id()) },
            Duration::from_secs(10),
        )
        .await;

        // Also add the same proxy CIDR to node B (creating another conflict)
        p_b.get_global_ctx()
            .config
            .add_proxy_cidr(proxy_cidr, None)
            .unwrap();

        // Wait for route convergence - B should route to itself for the proxy CIDR
        wait_for_condition(
            || async { route_b.get_peer_id_by_ipv4(&test_ip).await == Some(p_b.my_peer_id()) },
            Duration::from_secs(5),
        )
        .await;

        // Final verification: A should still route to itself even with multiple conflicts
        assert_eq!(
            route_a.get_peer_id_by_ipv4(&test_ip).await,
            Some(p_a.my_peer_id())
        );

        // remove proxy on A, a should route to B
        p_a.get_global_ctx().config.remove_proxy_cidr(proxy_cidr);
        wait_for_condition(
            || async {
                let peer_id_for_proxy = route_a.get_peer_id_by_ipv4(&test_ip).await;
                peer_id_for_proxy == Some(p_b.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;
        let snapshot = p_a
            .get_peer_map()
            .forwarding_decision_snapshot()
            .await
            .unwrap();
        let candidates = snapshot
            .service_routes()
            .candidates(IpAddr::V4(test_ip))
            .unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|route| route.gateway)
                .collect::<HashSet<_>>(),
            HashSet::from([p_b.my_peer_id(), p_c.my_peer_id()])
        );
    }
    #[rstest::rstest]
    #[tokio::test]
    async fn test_connect_at_different_time(#[values(true, false)] enable_conn_list_sync: bool) {
        FORCE_USE_CONN_LIST.store(enable_conn_list_sync, Ordering::Relaxed);
        // Create three peer managers: A, B, C
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        // Connect A-B-C in a line topology
        connect_peer_manager(p_a.clone(), p_b.clone()).await;

        wait_route_appear(p_a.clone(), p_b.clone()).await.unwrap();

        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
    }

    /// Helper: create a raw DynamicMessage from a RoutePeerInfo with an extra
    /// unknown field appended (field number 9999, varint value 42).
    /// Returns the raw DynamicMessage and the encoded unknown field bytes.
    fn make_raw_with_unknown_field(info: &RoutePeerInfo) -> (DynamicMessage, Vec<u8>) {
        // Encode the info to bytes
        let mut bytes = info.encode_to_vec();
        // Append an unknown field: field 9999, wire type 0 (varint), value 42
        // Tag = (9999 << 3) | 0 = 79992, encoded as varint
        prost::encoding::encode_key(9999, prost::encoding::WireType::Varint, &mut bytes);
        prost::encoding::encode_varint(42, &mut bytes);
        let unknown_field_bytes = bytes[info.encoded_len()..].to_vec();
        // Decode as DynamicMessage — unknown fields are preserved
        let raw = DynamicMessage::decode(RoutePeerInfo::default().descriptor(), bytes.as_slice())
            .unwrap();
        (raw, unknown_field_bytes)
    }

    /// Check that a raw DynamicMessage still contains the unknown field bytes
    /// by re-encoding and checking the suffix.
    fn raw_has_unknown_bytes(raw: &DynamicMessage, unknown_bytes: &[u8]) -> bool {
        let encoded = raw.encode_to_vec();
        // The unknown field bytes should appear somewhere in the encoded output
        encoded
            .windows(unknown_bytes.len())
            .any(|w| w == unknown_bytes)
    }

    fn encode_length_delimited_field(field_number: u32, payload: &[u8], dst: &mut Vec<u8>) {
        prost::encoding::encode_key(
            field_number,
            prost::encoding::WireType::LengthDelimited,
            dst,
        );
        prost::encoding::encode_varint(payload.len() as u64, dst);
        dst.extend_from_slice(payload);
    }

    fn make_route_info_with_raw_trusted_credential_proof(
        info: &RoutePeerInfo,
        raw_credential_bytes: &[u8],
        credential_hmac: &[u8],
    ) -> (RoutePeerInfo, DynamicMessage) {
        let mut proof_bytes = Vec::new();
        encode_length_delimited_field(1, raw_credential_bytes, &mut proof_bytes);
        encode_length_delimited_field(2, credential_hmac, &mut proof_bytes);

        let mut route_info_bytes = info.encode_to_vec();
        encode_length_delimited_field(19, &proof_bytes, &mut route_info_bytes);

        let typed_info = RoutePeerInfo::decode(route_info_bytes.as_slice()).unwrap();
        let raw_info = DynamicMessage::decode(
            RoutePeerInfo::default().descriptor(),
            route_info_bytes.as_slice(),
        )
        .unwrap();

        (typed_info, raw_info)
    }

    #[tokio::test]
    async fn sync_route_preserves_unknown_fields_for_credential_sender() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 20001;
        let credential = signed_test_credential(
            route.service_impl.global_ctx.get_credential_manager(),
            &[4u8; 32],
            Duration::from_secs(600),
        );
        let credential_pubkey = credential.pubkey.clone();

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::Credential);
        let peer_public_key = DashMap::new();
        peer_public_key.insert(from_peer_id, credential_pubkey.clone());
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key,
        }));
        // Publish the freshly generated credential from the local admin peer
        // info; the sync-time trust refresh drops proofs no admin publishes.
        route.service_impl.update_my_peer_info();
        route
            .service_impl
            .synced_route_info
            .trusted_credential_pubkeys
            .insert(credential_pubkey.clone(), credential);

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;

        let (raw, unknown_bytes) = make_raw_with_unknown_field(&sender_info);

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info]),
                Some(vec![raw]),
                None,
                None,
                PeerIdentityType::Credential,
            )
            .await
            .unwrap();

        let stored_raw = route
            .service_impl
            .synced_route_info
            .raw_peer_infos
            .get(&from_peer_id)
            .expect("raw peer info should be stored");
        assert!(
            raw_has_unknown_bytes(stored_raw.value(), &unknown_bytes),
            "unknown fields should be preserved for credential sender"
        );
    }

    #[tokio::test]
    async fn sync_route_preserves_unknown_fields_for_shared_sender() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 20011;
        let forwarded_peer_id: PeerId = 20012;
        let credential = signed_test_credential(
            route.service_impl.global_ctx.get_credential_manager(),
            &[9u8; 32],
            Duration::from_secs(600),
        );

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::SharedNode);
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key: DashMap::new(),
        }));

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;

        let mut forwarded_info = RoutePeerInfo::new();
        forwarded_info.peer_id = forwarded_peer_id;
        forwarded_info.version = 1;
        forwarded_info.trusted_credential_pubkeys = vec![TrustedCredentialPubkeyProof::new_signed(
            credential,
            "route-secret",
        )];

        let (raw_sender, unknown_sender) = make_raw_with_unknown_field(&sender_info);
        let (raw_forwarded, unknown_forwarded) = make_raw_with_unknown_field(&forwarded_info);

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info, forwarded_info]),
                Some(vec![raw_sender, raw_forwarded]),
                None,
                None,
                PeerIdentityType::SharedNode,
            )
            .await
            .unwrap();

        // The shared node can publish only its own route record.
        let stored_sender = route
            .service_impl
            .synced_route_info
            .raw_peer_infos
            .get(&from_peer_id)
            .expect("sender raw should be stored");
        assert!(
            raw_has_unknown_bytes(stored_sender.value(), &unknown_sender),
            "unknown fields should be preserved for shared sender's own info"
        );

        assert!(
            !route
                .service_impl
                .synced_route_info
                .raw_peer_infos
                .contains_key(&forwarded_peer_id)
        );
        assert!(!unknown_forwarded.is_empty());
    }

    #[tokio::test]
    async fn sync_route_preserves_unknown_fields_for_admin_sender() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 20021;

        let identity_type = DashMap::new();
        identity_type.insert(from_peer_id, PeerIdentityType::Admin);
        *route.service_impl.interface.lock().await = Some(Arc::new(AuthOnlyInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            identity_type,
            peer_public_key: DashMap::new(),
        }));

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;
        // Keep a conflicting compatibility flag in the admin record.
        sender_info.feature_flag = Some(PeerFeatureFlag {
            is_credential_peer: true,
            ..Default::default()
        });

        let (raw, unknown_bytes) = make_raw_with_unknown_field(&sender_info);

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info]),
                Some(vec![raw]),
                None,
                None,
                PeerIdentityType::Admin,
            )
            .await
            .unwrap();

        let stored_raw = route
            .service_impl
            .synced_route_info
            .raw_peer_infos
            .get(&from_peer_id)
            .expect("raw peer info should be stored");
        assert!(
            raw_has_unknown_bytes(stored_raw.value(), &unknown_bytes),
            "unknown fields should be preserved for admin sender (mark non-credential path)"
        );
    }

    #[tokio::test]
    async fn sync_route_info_prioritizes_local_over_remote_for_overlapped_proxy_cidrs() {
        let peer_mgr = create_mock_pmgr().await;
        let route = create_mock_route(peer_mgr.clone()).await;
        let from_peer_id: PeerId = 11001;

        let peers = Arc::new(Mutex::new(vec![from_peer_id]));
        let peer_identity_types = Arc::new(Mutex::new(HashMap::from([(
            from_peer_id,
            Some(PeerIdentityType::Admin),
        )])));
        *route.service_impl.interface.lock().await = Some(Arc::new(CountingInterface {
            my_peer_id: peer_mgr.my_peer_id(),
            peers,
            peer_identity_types,
            list_peers_calls: Arc::new(AtomicU32::new(0)),
            get_peer_identity_type_calls: Arc::new(AtomicU32::new(0)),
        }));
        route.service_impl.mark_interface_peers_dirty();
        assert!(route.service_impl.update_my_conn_info().await);

        route
            .service_impl
            .global_ctx
            .config
            .add_proxy_cidr("10.10.0.0/16".parse().unwrap(), None)
            .unwrap();
        assert!(route.service_impl.update_my_peer_info());

        let mut sender_info = RoutePeerInfo::new();
        sender_info.peer_id = from_peer_id;
        sender_info.version = 1;
        sender_info.proxy_cidrs = vec![
            "10.10.0.0/16".to_string(),
            "10.10.1.0/24".to_string(),
            "10.11.0.0/16".to_string(),
        ];

        let make_raw = |info: &RoutePeerInfo| {
            let mut raw = DynamicMessage::new(RoutePeerInfo::default().descriptor());
            raw.transcode_from(info).unwrap();
            raw
        };

        route
            .session_mgr
            .do_sync_route_info(
                from_peer_id,
                1,
                true,
                Some(vec![sender_info.clone()]),
                Some(vec![make_raw(&sender_info)]),
                None,
                None,
                PeerIdentityType::Admin,
            )
            .await
            .unwrap();

        // Keep route table in sync with interface-derived adjacency during assertion window.
        route
            .service_impl
            .update_route_table_and_cached_local_conn_bitmap();

        // Control plane: keep what remote announced.
        let guard = route.service_impl.synced_route_info.peer_infos.read();
        let stored = guard.get(&from_peer_id).unwrap();
        assert_eq!(stored.proxy_cidrs, sender_info.proxy_cidrs);
        drop(guard);

        // Route-table filtering: local announced /16 should dominate remote equal/subset.
        assert_eq!(
            route
                .service_impl
                .route_table
                .get_peer_id_for_proxy(&"10.10.1.1".parse::<IpAddr>().unwrap()),
            Some(peer_mgr.my_peer_id())
        );
        // Non-overlapped remote prefix should still route to remote.
        assert_eq!(
            route
                .service_impl
                .route_table
                .get_peer_id_for_proxy(&"10.11.0.1".parse::<IpAddr>().unwrap()),
            Some(from_peer_id)
        );
    }

    #[test]
    fn exact_delivery_rates_preserve_the_nine_and_fifteen_megabit_values() {
        let mut graph = SpeedGraph::new();
        let start = graph.add_node(1);
        let fast = graph.add_node(2);
        let slow = graph.add_node(3);
        graph.add_edge(
            start,
            fast,
            SpeedEdge {
                delivery_bps: 15_000_000,
                latency_ms: 4,
            },
        );
        graph.add_edge(
            fast,
            slow,
            SpeedEdge {
                delivery_bps: 9_000_000,
                latency_ms: 5,
            },
        );

        let routes = widest_path_with_first_hop(&graph, start);
        assert_eq!(routes[&fast].quality.delivery_bps, 15_000_000);
        assert_eq!(routes[&slow].quality.delivery_bps, 9_000_000);
    }

    #[test]
    fn distinct_capacity_chain_finalizes_each_node_once() {
        let node_count = 256_usize;
        let mut graph = SpeedGraph::new();
        let nodes: Vec<_> = (0..node_count)
            .map(|index| graph.add_node(index as PeerId + 1))
            .collect();
        for index in 0..node_count - 1 {
            graph.add_edge(
                nodes[index],
                nodes[index + 1],
                SpeedEdge {
                    delivery_bps: (node_count - index) as u64,
                    latency_ms: 1,
                },
            );
        }

        let (routes, work) = widest_path_with_work_stats(&graph, nodes[0]);
        assert_eq!(routes.len(), node_count - 1);
        assert_eq!(work.finalization_visits, node_count - 1);
        assert!(work.finalization_visits <= node_count);
    }

    #[tokio::test]
    async fn close_stops_owned_tasks_and_reopen_starts_them_again() {
        let peer_mgr = create_mock_pmgr().await;
        let route = PeerRoute::new(
            peer_mgr.my_peer_id(),
            peer_mgr.get_global_ctx(),
            peer_mgr.get_peer_rpc_mgr(),
        );
        let interface = || {
            Box::new(AuthOnlyInterface {
                my_peer_id: peer_mgr.my_peer_id(),
                identity_type: DashMap::new(),
                peer_public_key: DashMap::new(),
            }) as RouteInterfaceBox
        };

        route.open(interface()).await.unwrap();
        assert!(!route.tasks.lock().unwrap().is_empty());
        route.close().await;
        assert!(route.tasks.lock().unwrap().is_empty());

        route.open(interface()).await.unwrap();
        assert!(!route.tasks.lock().unwrap().is_empty());
        route.close().await;
        assert!(route.tasks.lock().unwrap().is_empty());
    }
}
