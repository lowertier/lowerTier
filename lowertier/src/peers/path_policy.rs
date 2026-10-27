//! Paths and load-balance groups chosen by the sending node.
//!
//! `[[group]]` and `[[path]]` compile to a [`PathPolicy`]. Against each forwarding snapshot the
//! members resolve to peers and usability. Every flow then picks one member per segment: weighted
//! rendezvous hashing for `flow` groups, the first usable member for `failover` groups. A member
//! that disappears moves only its own flows.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context as _, bail, ensure};
use arc_swap::ArcSwapOption;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use prefix_trie::PrefixMap;
use smallvec::SmallVec;

use crate::{
    common::{PeerId, config::Flags},
    peers::route_trait::{ForwardingDecisionSnapshot, NextHopPolicy},
    proto::common::{PathGroup, PathRule},
};

pub const MAX_GROUPS: usize = 64;
pub const MAX_PATHS: usize = 64;
pub const MAX_MEMBERS: usize = 32;
pub const MAX_WAYPOINTS: usize = 4;
const MAX_WEIGHT: u32 = 1000;

/// A peer named by its public key or virtual IP.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PeerRef {
    Key([u8; 32]),
    Ip(IpAddr),
}

impl PeerRef {
    pub fn parse(text: &str) -> Option<Self> {
        if let Ok(address) = text.parse::<IpAddr>() {
            return Some(Self::Ip(address));
        }
        let key = BASE64_STANDARD.decode(text).ok()?;
        Some(Self::Key(key.try_into().ok()?))
    }

    fn resolve(&self, snapshot: &ForwardingDecisionSnapshot, keys: &HashMap<[u8; 32], PeerId>) -> Option<PeerId> {
        match self {
            Self::Key(key) => keys.get(key).copied(),
            Self::Ip(address) => snapshot.peer_id_by_ip(address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Balance {
    Flow,
    Failover,
}

impl Balance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Failover => "failover",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Member {
    pub text: String,
    pub peer: PeerRef,
    pub weight: u32,
}

/// One position in a path: a group, or a single peer as a one-member group.
#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub balance: Balance,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Peer(PeerRef),
    Prefix(IpCidr),
    Internet,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub to_text: String,
    pub to: Target,
    pub via: Vec<Segment>,
    pub gateway: Option<Segment>,
    pub strict: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PathPolicy {
    pub rules: Vec<Rule>,
}

fn valid_group_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        && PeerRef::parse(name).is_none()
        && name != "internet"
}

impl PathPolicy {
    /// Validate the configuration and build the policy. Errors name the entry and field.
    pub fn compile(config: &crate::proto::common::PathPolicy) -> anyhow::Result<Self> {
        ensure!(config.group.len() <= MAX_GROUPS, "group permits {MAX_GROUPS} entries");
        ensure!(config.path.len() <= MAX_PATHS, "path permits {MAX_PATHS} entries");
        let mut groups = HashMap::<&str, Segment>::new();
        for (index, group) in config.group.iter().enumerate() {
            let segment = Self::group(group).with_context(|| format!("group {}", index + 1))?;
            ensure!(
                groups.insert(group.name.as_str(), segment).is_none(),
                "group {}: the name {:?} is used twice",
                index + 1,
                group.name
            );
        }
        let mut rules = Vec::with_capacity(config.path.len());
        let mut targets = HashSet::new();
        for (index, path) in config.path.iter().enumerate() {
            let rule = Self::rule(path, &groups).with_context(|| format!("path {}", index + 1))?;
            ensure!(
                targets.insert(format!("{:?}", rule.to)),
                "path {}: another path already has to = {:?}",
                index + 1,
                path.to
            );
            rules.push(rule);
        }
        Ok(Self { rules })
    }

    fn group(group: &PathGroup) -> anyhow::Result<Segment> {
        ensure!(
            valid_group_name(&group.name),
            "name {:?} must be 1 to 32 letters, digits, - or _, and not a key, an IP, or \"internet\"",
            group.name
        );
        let balance = match group.balance.as_str() {
            "" | "flow" => Balance::Flow,
            "failover" => Balance::Failover,
            other => bail!("balance {other:?} must be flow or failover"),
        };
        ensure!(
            (1..=MAX_MEMBERS).contains(&group.members.len()),
            "members must list 1 to {MAX_MEMBERS} peers"
        );
        ensure!(
            group.weights.is_empty() || group.weights.len() == group.members.len(),
            "weights must have one entry per member"
        );
        ensure!(
            group.weights.is_empty() || balance == Balance::Flow,
            "weights apply only to balance = \"flow\""
        );
        let mut members = Vec::with_capacity(group.members.len());
        for (index, text) in group.members.iter().enumerate() {
            let peer = PeerRef::parse(text)
                .with_context(|| format!("member {text:?} is not a peer public key or virtual IP"))?;
            ensure!(
                !members.iter().any(|member: &Member| member.peer == peer),
                "member {text:?} is listed twice"
            );
            let weight = group.weights.get(index).copied().unwrap_or(1);
            ensure!(
                (1..=MAX_WEIGHT).contains(&weight),
                "weights must be between 1 and {MAX_WEIGHT}"
            );
            members.push(Member {
                text: text.clone(),
                peer,
                weight,
            });
        }
        Ok(Segment {
            name: group.name.clone(),
            balance,
            members,
        })
    }

    fn segment(text: &str, groups: &HashMap<&str, Segment>) -> anyhow::Result<Segment> {
        if let Some(group) = groups.get(text) {
            return Ok(group.clone());
        }
        let peer = PeerRef::parse(text)
            .with_context(|| format!("{text:?} is not a group name, peer public key, or virtual IP"))?;
        Ok(Segment {
            name: text.to_owned(),
            balance: Balance::Failover,
            members: vec![Member {
                text: text.to_owned(),
                peer,
                weight: 1,
            }],
        })
    }

    fn rule(path: &PathRule, groups: &HashMap<&str, Segment>) -> anyhow::Result<Rule> {
        // Keys are base64 and may contain '/', so try a peer before a CIDR.
        let to = match path.to.as_str() {
            "internet" => Target::Internet,
            text => match PeerRef::parse(text) {
                Some(peer) => Target::Peer(peer),
                None => Target::Prefix(text.parse::<IpCidr>().map_err(|_| {
                    anyhow::anyhow!(
                        "to {text:?} must be a peer key, a virtual IP, a CIDR, or \"internet\""
                    )
                })?),
            },
        };
        ensure!(
            path.via.len() <= MAX_WAYPOINTS,
            "via permits {MAX_WAYPOINTS} waypoints"
        );
        let via = path
            .via
            .iter()
            .map(|text| Self::segment(text, groups))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let gateway = (!path.gateway.is_empty())
            .then(|| Self::segment(&path.gateway, groups))
            .transpose()?;
        match &to {
            Target::Peer(_) => ensure!(
                gateway.is_none(),
                "gateway applies only to a CIDR or \"internet\""
            ),
            Target::Internet => ensure!(gateway.is_some(), "to = \"internet\" needs a gateway"),
            Target::Prefix(_) => ensure!(
                gateway.is_some() || !via.is_empty(),
                "a CIDR path needs a gateway, waypoints in via, or both"
            ),
        }
        ensure!(
            gateway.is_some() || !via.is_empty(),
            "a path needs waypoints in via"
        );
        Ok(Rule {
            to_text: path.to.clone(),
            to,
            via,
            gateway,
            strict: path.strict,
        })
    }
}

/// Packet and selection counters, laid out like the compiled policy.
struct RuleCounters {
    waypoint_packets: AtomicU64,
    fallback_packets: AtomicU64,
    dropped_packets: AtomicU64,
    /// Per segment (via in order, then the gateway), per member.
    picks: Vec<Vec<AtomicU64>>,
}

struct Compiled {
    source: Option<crate::proto::common::PathPolicy>,
    policy: PathPolicy,
    counters: Vec<RuleCounters>,
    version: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ResolvedMember {
    peer: Option<PeerId>,
    reachable: bool,
    waypoint: bool,
    exit: bool,
}

struct Resolved {
    generation: u64,
    version: u64,
    /// Per rule: per segment (via, then gateway), per member.
    members: Vec<Vec<Vec<ResolvedMember>>>,
    peer_rules: HashMap<PeerId, u16>,
    rule_peers: Vec<Option<PeerId>>,
    prefix_v4: PrefixMap<Ipv4Cidr, u16>,
    prefix_v6: PrefixMap<Ipv6Cidr, u16>,
    internet: Option<u16>,
}

/// A gateway picked for one flow of IP traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayChoice {
    pub peer_id: PeerId,
    pub rule: u16,
    /// The gateway sends the traffic out of the overlay with source NAT.
    pub exit: bool,
}

/// Waypoints for one packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaypointPlan {
    /// No waypoints apply: route automatically.
    Automatic,
    /// Send through these peers, in order, before the destination.
    Via(SmallVec<[PeerId; MAX_WAYPOINTS]>),
    /// A segment has no usable member and the path falls back to automatic routing.
    Fallback,
    /// A segment has no usable member and the path is strict: drop the packet.
    Drop,
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Weighted rendezvous score: the member with the highest score wins the flow.
fn score(flow: u64, salt: u64, peer_id: PeerId, weight: u32) -> f64 {
    let hash = mix(flow ^ mix(salt ^ (u64::from(peer_id) << 20)));
    let unit = ((hash >> 11) as f64 + 0.5) / (1_u64 << 53) as f64;
    f64::from(weight) / -unit.ln()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Waypoint,
    Gateway,
}

pub struct PathRuntime {
    my_peer_id: PeerId,
    compiled: ArcSwapOption<Compiled>,
    resolved: ArcSwapOption<Resolved>,
    flags: ArcSwapOption<Flags>,
    rebuild: parking_lot::Mutex<()>,
}

impl PathRuntime {
    pub fn new(my_peer_id: PeerId) -> Self {
        Self {
            my_peer_id,
            compiled: ArcSwapOption::empty(),
            resolved: ArcSwapOption::empty(),
            flags: ArcSwapOption::empty(),
            rebuild: parking_lot::Mutex::new(()),
        }
    }

    /// Follow configuration changes. Cheap when the flags are unchanged.
    pub fn refresh(&self, flags: &Arc<Flags>) {
        if self
            .flags
            .load()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, flags))
        {
            return;
        }
        let _guard = self.rebuild.lock();
        let current = self.compiled.load_full();
        if current.as_ref().map(|compiled| &compiled.source) != Some(&flags.path_policy) {
            // Flags were validated before they were stored, so this compiles.
            let policy = flags
                .path_policy
                .as_ref()
                .and_then(|config| PathPolicy::compile(config).ok())
                .unwrap_or_default();
            let counters = policy
                .rules
                .iter()
                .map(|rule| RuleCounters {
                    waypoint_packets: AtomicU64::new(0),
                    fallback_packets: AtomicU64::new(0),
                    dropped_packets: AtomicU64::new(0),
                    picks: rule
                        .via
                        .iter()
                        .chain(&rule.gateway)
                        .map(|segment| segment.members.iter().map(|_| AtomicU64::new(0)).collect())
                        .collect(),
                })
                .collect();
            let version = current.as_ref().map_or(1, |compiled| compiled.version + 1);
            self.compiled.store(Some(Arc::new(Compiled {
                source: flags.path_policy.clone(),
                policy,
                counters,
                version,
            })));
            self.resolved.store(None);
        }
        self.flags.store(Some(flags.clone()));
    }

    pub fn is_active(&self) -> bool {
        self.compiled
            .load()
            .as_ref()
            .is_some_and(|compiled| !compiled.policy.rules.is_empty())
    }

    fn resolved(&self, snapshot: &ForwardingDecisionSnapshot) -> Option<(Arc<Compiled>, Arc<Resolved>)> {
        let compiled = self.compiled.load_full()?;
        if compiled.policy.rules.is_empty() {
            return None;
        }
        if let Some(resolved) = self.resolved.load_full()
            && resolved.generation == snapshot.generation()
            && resolved.version == compiled.version
        {
            return Some((compiled, resolved));
        }
        let resolved = Arc::new(Self::resolve(&compiled, snapshot, self.my_peer_id));
        self.resolved.store(Some(resolved.clone()));
        Some((compiled, resolved))
    }

    fn resolve(compiled: &Compiled, snapshot: &ForwardingDecisionSnapshot, my_peer_id: PeerId) -> Resolved {
        let keys: HashMap<[u8; 32], PeerId> = snapshot
            .capabilities()
            .iter()
            .filter_map(|peer| Some((peer.static_pubkey?, peer.peer_id)))
            .collect();
        let member = |reference: &PeerRef| {
            let Some(peer_id) = reference.resolve(snapshot, &keys) else {
                return ResolvedMember::default();
            };
            let features = snapshot
                .capabilities()
                .get(peer_id)
                .and_then(|peer| peer.feature_flag);
            ResolvedMember {
                peer: Some(peer_id),
                reachable: peer_id != my_peer_id
                    && snapshot.next_hop(peer_id, NextHopPolicy::LeastCost).is_some(),
                waypoint: features.is_some_and(|features| {
                    features.waypoint_v1 && features.relay_semantics_v1 && !features.deny_transit_data
                }),
                exit: features.is_some_and(|features| features.exit_node),
            }
        };
        let mut resolved = Resolved {
            generation: snapshot.generation(),
            version: compiled.version,
            members: Vec::with_capacity(compiled.policy.rules.len()),
            peer_rules: HashMap::new(),
            rule_peers: Vec::with_capacity(compiled.policy.rules.len()),
            prefix_v4: PrefixMap::new(),
            prefix_v6: PrefixMap::new(),
            internet: None,
        };
        for (index, rule) in compiled.policy.rules.iter().enumerate() {
            let index = index as u16;
            resolved.members.push(
                rule.via
                    .iter()
                    .chain(&rule.gateway)
                    .map(|segment| segment.members.iter().map(|item| member(&item.peer)).collect())
                    .collect(),
            );
            let mut rule_peer = None;
            match &rule.to {
                Target::Peer(reference) => {
                    rule_peer = reference.resolve(snapshot, &keys);
                    if let Some(peer_id) = rule_peer {
                        resolved.peer_rules.insert(peer_id, index);
                    }
                }
                Target::Prefix(IpCidr::V4(prefix)) => {
                    resolved.prefix_v4.insert(*prefix, index);
                }
                Target::Prefix(IpCidr::V6(prefix)) => {
                    resolved.prefix_v6.insert(*prefix, index);
                }
                Target::Internet => resolved.internet = Some(index),
            }
            resolved.rule_peers.push(rule_peer);
        }
        resolved
    }

    /// Pick one member of a segment for a flow.
    fn pick(
        segment: &Segment,
        members: &[ResolvedMember],
        flow: u64,
        salt: u64,
        role: Role,
        excluded: &[PeerId],
        exports: impl Fn(PeerId) -> bool,
    ) -> Option<(usize, PeerId)> {
        let usable = |member: &ResolvedMember| -> Option<PeerId> {
            let peer_id = member.peer?;
            let capable = match role {
                Role::Waypoint => member.waypoint,
                Role::Gateway => member.exit || exports(peer_id),
            };
            (member.reachable && capable && !excluded.contains(&peer_id)).then_some(peer_id)
        };
        match segment.balance {
            Balance::Failover => members
                .iter()
                .enumerate()
                .find_map(|(index, member)| Some((index, usable(member)?))),
            Balance::Flow => members
                .iter()
                .enumerate()
                .filter_map(|(index, member)| Some((index, usable(member)?)))
                .max_by(|(left, left_peer), (right, right_peer)| {
                    score(flow, salt, *left_peer, segment.members[*left].weight).total_cmp(&score(
                        flow,
                        salt,
                        *right_peer,
                        segment.members[*right].weight,
                    ))
                }),
        }
    }

    fn gateway_for_rule(
        &self,
        compiled: &Compiled,
        resolved: &Resolved,
        rule_index: u16,
        flow: u64,
        exports: impl Fn(PeerId) -> bool,
    ) -> Option<GatewayChoice> {
        let rule = compiled.policy.rules.get(usize::from(rule_index))?;
        let gateway = rule.gateway.as_ref()?;
        let members = resolved.members[usize::from(rule_index)].last()?;
        let salt = u64::from(rule_index) << 8 | rule.via.len() as u64;
        let picked = Self::pick(gateway, members, flow, salt, Role::Gateway, &[], &exports);
        let Some((member, peer_id)) = picked else {
            compiled.counters[usize::from(rule_index)]
                .fallback_packets
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        compiled.counters[usize::from(rule_index)].picks[rule.via.len()][member]
            .fetch_add(1, Ordering::Relaxed);
        Some(GatewayChoice {
            peer_id,
            rule: rule_index,
            exit: !exports(peer_id),
        })
    }

    /// A CIDR path that covers `address` and names a gateway. Explicit paths win over
    /// automatic subnet routes. The caller excludes overlay addresses.
    pub fn cidr_gateway(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        address: IpAddr,
        flow: u64,
    ) -> Option<GatewayChoice> {
        let (compiled, resolved) = self.resolved(snapshot)?;
        let rule = Self::prefix_rule(&resolved, address)?;
        let exports = |peer_id: PeerId| {
            snapshot
                .service_routes()
                .candidates(address)
                .is_some_and(|routes| routes.iter().any(|route| route.gateway == peer_id))
        };
        self.gateway_for_rule(&compiled, &resolved, rule, flow, exports)
    }

    /// The internet path's gateway for traffic that no other route claims.
    pub fn internet_gateway(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        flow: u64,
    ) -> Option<GatewayChoice> {
        let (compiled, resolved) = self.resolved(snapshot)?;
        let rule = resolved.internet?;
        self.gateway_for_rule(&compiled, &resolved, rule, flow, |_| false)
    }

    fn prefix_rule(resolved: &Resolved, address: IpAddr) -> Option<u16> {
        match address {
            IpAddr::V4(address) => resolved
                .prefix_v4
                .get_lpm(&Ipv4Cidr::new(address, 32).ok()?)
                .map(|(_, rule)| *rule),
            IpAddr::V6(address) => resolved
                .prefix_v6
                .get_lpm(&Ipv6Cidr::new(address, 128).ok()?)
                .map(|(_, rule)| *rule),
        }
    }

    /// The path for IP traffic to `address` that has no gateway of its own.
    pub fn rule_for_address(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        address: IpAddr,
    ) -> Option<u16> {
        let (_, resolved) = self.resolved(snapshot)?;
        Self::prefix_rule(&resolved, address)
    }

    /// The path for traffic to `peer_id` when the packet carries none: a path to that peer, or a
    /// path with waypoints whose gateway includes it.
    pub fn rule_for_destination(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        peer_id: PeerId,
    ) -> Option<u16> {
        let (compiled, resolved) = self.resolved(snapshot)?;
        if let Some(rule) = resolved.peer_rules.get(&peer_id) {
            return Some(*rule);
        }
        compiled
            .policy
            .rules
            .iter()
            .enumerate()
            .find(|(index, rule)| {
                rule.gateway.is_some()
                    && !rule.via.is_empty()
                    && resolved.members[*index]
                        .last()
                        .is_some_and(|members| members.iter().any(|member| member.peer == Some(peer_id)))
            })
            .map(|(index, _)| index as u16)
    }

    /// Waypoints for one packet of `flow` to `destination` under `rule`.
    pub fn waypoints(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        rule_index: u16,
        destination: PeerId,
        flow: u64,
    ) -> WaypointPlan {
        let Some((compiled, resolved)) = self.resolved(snapshot) else {
            return WaypointPlan::Automatic;
        };
        let Some(rule) = compiled.policy.rules.get(usize::from(rule_index)) else {
            return WaypointPlan::Automatic;
        };
        if rule.via.is_empty() {
            return WaypointPlan::Automatic;
        }
        let counters = &compiled.counters[usize::from(rule_index)];
        let members = &resolved.members[usize::from(rule_index)];
        let mut chain = SmallVec::<[PeerId; MAX_WAYPOINTS]>::new();
        let mut picked = SmallVec::<[(usize, usize); MAX_WAYPOINTS]>::new();
        for (position, segment) in rule.via.iter().enumerate() {
            let mut excluded = SmallVec::<[PeerId; MAX_WAYPOINTS + 1]>::from_slice(&chain);
            excluded.push(destination);
            let salt = u64::from(rule_index) << 8 | position as u64;
            match Self::pick(
                segment,
                &members[position],
                flow,
                salt,
                Role::Waypoint,
                &excluded,
                |_| false,
            ) {
                Some((member, peer_id)) => {
                    chain.push(peer_id);
                    picked.push((position, member));
                }
                None if rule.strict => {
                    counters.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    return WaypointPlan::Drop;
                }
                None => {
                    counters.fallback_packets.fetch_add(1, Ordering::Relaxed);
                    return WaypointPlan::Fallback;
                }
            }
        }
        counters.waypoint_packets.fetch_add(1, Ordering::Relaxed);
        for (position, member) in picked {
            counters.picks[position][member].fetch_add(1, Ordering::Relaxed);
        }
        WaypointPlan::Via(chain)
    }

    /// Count a packet that fell back after its plan could not be sent through the waypoints.
    pub fn record_send_fallback(&self, rule_index: u16, strict: bool) {
        let Some(compiled) = self.compiled.load_full() else {
            return;
        };
        let Some(counters) = compiled.counters.get(usize::from(rule_index)) else {
            return;
        };
        counters.waypoint_packets.fetch_sub(1, Ordering::Relaxed);
        if strict {
            counters.dropped_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.fallback_packets.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn is_strict(&self, rule_index: u16) -> bool {
        self.compiled.load().as_ref().is_some_and(|compiled| {
            compiled
                .policy
                .rules
                .get(usize::from(rule_index))
                .is_some_and(|rule| rule.strict)
        })
    }

    /// Status of every path for the control API.
    pub fn status(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        hostname: impl Fn(PeerId) -> String,
    ) -> Vec<crate::proto::api::control::v1::PathStatus> {
        use crate::proto::api::control::v1::{PathMember, PathSegment, PathStatus};
        let Some((compiled, resolved)) = self.resolved(snapshot) else {
            return Vec::new();
        };
        compiled
            .policy
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let counters = &compiled.counters[index];
                let members = &resolved.members[index];
                let mut missing = Vec::new();
                let segments: Vec<PathSegment> = rule
                    .via
                    .iter()
                    .map(|segment| (segment, Role::Waypoint))
                    .chain(rule.gateway.iter().map(|segment| (segment, Role::Gateway)))
                    .enumerate()
                    .map(|(position, (segment, role))| {
                        let resolved_members = &members[position];
                        let members: Vec<PathMember> = segment
                            .members
                            .iter()
                            .zip(resolved_members)
                            .enumerate()
                            .map(|(member_index, (member, state))| {
                                let reason = match state.peer {
                                    None => "Not in the network.",
                                    Some(peer_id) if peer_id == self.my_peer_id => "This node.",
                                    Some(_) if !state.reachable => "No route.",
                                    Some(_) if role == Role::Waypoint && !state.waypoint => {
                                        "Does not forward waypoint traffic (older version or transit denied)."
                                    }
                                    Some(_) if role == Role::Gateway && !state.exit => {
                                        "Not an exit (routes.serve_exit) or a subnet gateway."
                                    }
                                    Some(_) => "",
                                };
                                PathMember {
                                    r#ref: member.text.clone(),
                                    peer_id: state.peer,
                                    hostname: state.peer.map(&hostname).unwrap_or_default(),
                                    weight: member.weight,
                                    usable: reason.is_empty(),
                                    reason: reason.into(),
                                    picks: counters.picks[position][member_index]
                                        .load(Ordering::Relaxed),
                                }
                            })
                            .collect();
                        if !members.iter().any(|member| member.usable) {
                            missing.push(segment.name.clone());
                        }
                        PathSegment {
                            name: segment.name.clone(),
                            balance: segment.balance.as_str().into(),
                            members,
                        }
                    })
                    .collect();
                let gateway = rule.gateway.is_some().then(|| segments.last().cloned()).flatten();
                let via = segments[..rule.via.len()].to_vec();
                let to_peer_id = resolved.rule_peers[index];
                let (state, reason) = if matches!(rule.to, Target::Peer(_)) && to_peer_id.is_none() {
                    ("fallback", "The destination is not in the network.".to_owned())
                } else if missing.is_empty() {
                    ("ready", String::new())
                } else {
                    (
                        if rule.strict { "down" } else { "fallback" },
                        format!("No usable member in {}.", missing.join(", ")),
                    )
                };
                PathStatus {
                    index: index as u32,
                    to: rule.to_text.clone(),
                    to_peer_id,
                    via,
                    gateway,
                    strict: rule.strict,
                    state: state.into(),
                    reason,
                    waypoint_packets: counters.waypoint_packets.load(Ordering::Relaxed),
                    fallback_packets: counters.fallback_packets.load(Ordering::Relaxed),
                    dropped_packets: counters.dropped_packets.load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::PathPolicy as Config;

    fn key(byte: u8) -> String {
        BASE64_STANDARD.encode([byte; 32])
    }

    fn config(text: &str) -> Config {
        let table: toml::Table = text.parse().unwrap();
        Config {
            group: table
                .get("group")
                .map(|value| value.clone().try_into().unwrap())
                .unwrap_or_default(),
            path: table
                .get("path")
                .map(|value| value.clone().try_into().unwrap())
                .unwrap_or_default(),
        }
    }

    #[test]
    fn compile_validates_references() {
        let ok = config(&format!(
            "[[group]]\nname = \"relays\"\nmembers = [\"{}\", \"10.0.0.3\"]\nweights = [2, 1]\n\
             [[path]]\nto = \"{}\"\nvia = [\"relays\", \"10.0.0.4\"]\n\
             [[path]]\nto = \"internet\"\ngateway = \"relays\"\nstrict = true\n",
            key(2),
            key(9)
        ));
        let policy = PathPolicy::compile(&ok).unwrap();
        // A key with '/' is a peer, not a CIDR.
        let slash_key = BASE64_STANDARD.encode([0xff_u8; 32]);
        assert!(slash_key.contains('/'));
        let keyed = PathPolicy::compile(&config(&format!(
            "[[path]]\nto = \"{slash_key}\"\nvia = [\"10.0.0.2\"]\n[[path]]\nto = \"10.8.0.0/16\"\nvia = [\"10.0.0.2\"]\n"
        )))
        .unwrap();
        assert!(matches!(keyed.rules[0].to, Target::Peer(PeerRef::Key(_))));
        assert!(matches!(keyed.rules[1].to, Target::Prefix(_)));
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].via[0].members[0].weight, 2);
        assert_eq!(policy.rules[0].via[1].balance, Balance::Failover);

        for (text, message) in [
            ("[[path]]\nto = \"internet\"\nvia = [\"10.0.0.2\"]\n", "needs a gateway"),
            ("[[path]]\nto = \"10.0.0.9\"\nvia = [\"nope\"]\n", "not a group name"),
            ("[[path]]\nto = \"10.0.0.9\"\n", "needs waypoints"),
            (
                "[[group]]\nname = \"g\"\nmembers = [\"10.0.0.2\"]\nbalance = \"failover\"\nweights = [3]\n",
                "weights apply only",
            ),
            (
                "[[path]]\nto = \"10.0.0.9\"\nvia = [\"10.0.0.2\"]\n[[path]]\nto = \"10.0.0.9\"\nvia = [\"10.0.0.3\"]\n",
                "another path",
            ),
        ] {
            let error = format!("{:#}", PathPolicy::compile(&config(text)).unwrap_err());
            assert!(error.contains(message), "{message}: {error}");
        }
    }

    #[test]
    fn weighted_rendezvous_follows_weights_and_moves_only_lost_flows() {
        let segment = Segment {
            name: "g".into(),
            balance: Balance::Flow,
            members: [3, 1, 1]
                .into_iter()
                .enumerate()
                .map(|(index, weight)| Member {
                    text: index.to_string(),
                    peer: PeerRef::Ip(IpAddr::from([10, 0, 0, index as u8])),
                    weight,
                })
                .collect(),
        };
        let live = |peers: &[PeerId]| -> Vec<ResolvedMember> {
            peers
                .iter()
                .map(|peer| ResolvedMember {
                    peer: Some(*peer),
                    reachable: true,
                    waypoint: true,
                    exit: true,
                })
                .collect()
        };
        let all = live(&[11, 12, 13]);
        let mut counts = [0_u32; 3];
        let mut before = Vec::new();
        for flow in 0..20_000_u64 {
            let (index, _) =
                PathRuntime::pick(&segment, &all, mix(flow), 7, Role::Waypoint, &[], |_| false).unwrap();
            counts[index] += 1;
            before.push(index);
        }
        // Weights 3:1:1 give about 60%, 20%, 20%.
        assert!((11_000..13_000).contains(&counts[0]), "{counts:?}");
        assert!((3_400..4_600).contains(&counts[1]), "{counts:?}");

        let mut without_second = all.clone();
        without_second[1].reachable = false;
        for flow in 0..20_000_u64 {
            let (index, _) = PathRuntime::pick(
                &segment,
                &without_second,
                mix(flow),
                7,
                Role::Waypoint,
                &[],
                |_| false,
            )
            .unwrap();
            if before[flow as usize] != 1 {
                assert_eq!(index, before[flow as usize], "flow {flow} moved");
            }
        }
    }
}
