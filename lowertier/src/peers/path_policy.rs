//! Multipath and multilayer relay path policy compiled from `[[group]]` and `[[path]]`.
//!
//! Each `[[path]]` rule lists ordered `layers` of relay nodes/groups (up to 8 layers) and an optional
//! `gateway` stage for CIDR / `"internet"` exit routing. Multiple relays inside a layer default to
//! `mode = "parallel"` (packet-level striping across relay chains), while `"flow"` pins each flow
//! deterministically via weighted rendezvous hashing and `"failover"` picks the first usable relay.

use std::{
    cmp::Reverse,
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
    proto::common::{PathGroup, PathRule, PathStage},
    tunnel::packet_def::MAX_RELAY_LAYERS,
};

pub const MAX_GROUPS: usize = 64;
pub const MAX_PATHS: usize = 64;
pub const MAX_MEMBERS: usize = 32;
pub const MAX_LAYERS: usize = MAX_RELAY_LAYERS;
pub const MAX_ACTIVE_CHAINS: usize = 16;
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

    fn resolve(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        keys: &HashMap<[u8; 32], PeerId>,
    ) -> Option<PeerId> {
        match self {
            Self::Key(key) => keys.get(key).copied(),
            Self::Ip(address) => snapshot.peer_id_by_ip(address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Parallel,
    Flow,
    Failover,
}

impl Mode {
    pub fn parse(text: &str) -> anyhow::Result<Option<Self>> {
        match text {
            "" => Ok(None),
            "parallel" => Ok(Some(Self::Parallel)),
            "flow" => Ok(Some(Self::Flow)),
            "failover" => Ok(Some(Self::Failover)),
            other => bail!("mode {other:?} must be \"parallel\", \"flow\", or \"failover\""),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
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

/// One relay layer or gateway selector in a path.
#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub mode: Mode,
    explicit_mode: Option<Mode>,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Peer(PeerRef),
    AnyPeer,
    Prefix(IpCidr),
    Internet,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub to_text: String,
    pub to: Target,
    pub mode: Mode,
    pub layers: Vec<Segment>,
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
        && name != "*"
}

impl PathPolicy {
    /// Validate configuration and compile `[[group]]` and `[[path]]`.
    pub fn compile(config: &crate::proto::common::PathPolicy) -> anyhow::Result<Self> {
        ensure!(
            config.group.len() <= MAX_GROUPS,
            "group permits {MAX_GROUPS} entries"
        );
        ensure!(
            config.path.len() <= MAX_PATHS,
            "path permits {MAX_PATHS} entries"
        );
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
            "name {:?} must be 1 to 32 letters, digits, - or _, and not a key, an IP, \"*\", or \"internet\"",
            group.name
        );
        let explicit_mode = Mode::parse(&group.mode)?;
        let mode = explicit_mode.unwrap_or(if group.nodes.len() > 1 {
            Mode::Parallel
        } else {
            Mode::Failover
        });
        ensure!(
            (1..=MAX_MEMBERS).contains(&group.nodes.len()),
            "nodes must list 1 to {MAX_MEMBERS} peers"
        );
        ensure!(
            group.weights.is_empty() || group.weights.len() == group.nodes.len(),
            "weights must have one entry per node"
        );
        ensure!(
            group.weights.is_empty() || mode != Mode::Failover,
            "weights apply only to mode = \"parallel\" or \"flow\""
        );
        let mut members = Vec::with_capacity(group.nodes.len());
        for (index, text) in group.nodes.iter().enumerate() {
            let peer = PeerRef::parse(text)
                .with_context(|| format!("node {text:?} is not a peer public key or virtual IP"))?;
            ensure!(
                !members.iter().any(|member: &Member| member.peer == peer),
                "node {text:?} is listed twice"
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
            mode,
            explicit_mode,
            members,
        })
    }

    fn stage(
        stage: &PathStage,
        groups: &HashMap<&str, Segment>,
        rule_mode: Option<Mode>,
        role: Role,
    ) -> anyhow::Result<Segment> {
        ensure!(
            !stage.nodes.is_empty(),
            "stage must list at least one peer or group"
        );
        let stage_explicit_mode = Mode::parse(&stage.mode)?;

        // Fast path: stage directly references a single named group.
        if stage.nodes.len() == 1
            && let Some(group) = groups.get(stage.nodes[0].as_str())
        {
            let explicit_mode = stage_explicit_mode.or(group.explicit_mode);
            let mut mode = explicit_mode.or(rule_mode).unwrap_or(group.mode);
            if role == Role::Gateway && mode == Mode::Parallel {
                mode = Mode::Flow;
            }
            if !stage.weights.is_empty() {
                ensure!(
                    stage.weights.len() == group.members.len(),
                    "weights must have one entry per node in group {:?}",
                    group.name
                );
                ensure!(
                    mode != Mode::Failover,
                    "weights apply only to mode = \"parallel\" or \"flow\""
                );
            }
            let members = group
                .members
                .iter()
                .enumerate()
                .map(|(idx, member)| {
                    let weight = stage.weights.get(idx).copied().unwrap_or(member.weight);
                    ensure!(
                        (1..=MAX_WEIGHT).contains(&weight),
                        "weights must be between 1 and {MAX_WEIGHT}"
                    );
                    Ok(Member {
                        text: member.text.clone(),
                        peer: member.peer.clone(),
                        weight,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            return Ok(Segment {
                name: group.name.clone(),
                mode,
                explicit_mode,
                members,
            });
        }

        let mut members: Vec<Member> = Vec::new();
        for text in &stage.nodes {
            if let Some(group) = groups.get(text.as_str()) {
                for member in &group.members {
                    if !members.iter().any(|existing| existing.peer == member.peer) {
                        members.push(member.clone());
                    }
                }
            } else {
                let peer = PeerRef::parse(text).with_context(|| {
                    format!("{text:?} is not a group name, peer public key, or virtual IP")
                })?;
                ensure!(
                    !members.iter().any(|existing| existing.peer == peer),
                    "node {text:?} is listed twice in stage"
                );
                members.push(Member {
                    text: text.clone(),
                    peer,
                    weight: 1,
                });
            }
        }
        ensure!(
            (1..=MAX_MEMBERS).contains(&members.len()),
            "stage resolves to {} peers (max {MAX_MEMBERS})",
            members.len()
        );

        let default_mode = match role {
            Role::Layer if members.len() > 1 => Mode::Parallel,
            Role::Gateway if members.len() > 1 => Mode::Flow,
            _ => Mode::Failover,
        };
        let mut mode = stage_explicit_mode.or(rule_mode).unwrap_or(default_mode);
        if role == Role::Gateway && mode == Mode::Parallel {
            mode = Mode::Flow;
        }
        if !stage.weights.is_empty() {
            ensure!(
                stage.weights.len() == members.len(),
                "weights must have one entry per node ({} nodes, {} weights)",
                members.len(),
                stage.weights.len()
            );
            ensure!(
                mode != Mode::Failover,
                "weights apply only to mode = \"parallel\" or \"flow\""
            );
            for (member, weight) in members.iter_mut().zip(&stage.weights) {
                ensure!(
                    (1..=MAX_WEIGHT).contains(weight),
                    "weights must be between 1 and {MAX_WEIGHT}"
                );
                member.weight = *weight;
            }
        }
        let name = if stage.nodes.len() == 1 {
            stage.nodes[0].clone()
        } else {
            format!("[{}]", stage.nodes.join(", "))
        };
        Ok(Segment {
            name,
            mode,
            explicit_mode: stage_explicit_mode,
            members,
        })
    }

    fn rule(path: &PathRule, groups: &HashMap<&str, Segment>) -> anyhow::Result<Rule> {
        let to = match path.to.as_str() {
            "internet" => Target::Internet,
            "*" => Target::AnyPeer,
            text => match PeerRef::parse(text) {
                Some(peer) => Target::Peer(peer),
                None => Target::Prefix(text.parse::<IpCidr>().map_err(|_| {
                    anyhow::anyhow!(
                        "to {text:?} must be a peer key, a virtual IP, \"*\", a CIDR, or \"internet\""
                    )
                })?),
            },
        };
        let rule_explicit_mode = Mode::parse(&path.mode)?;
        ensure!(
            path.layers.len() <= MAX_LAYERS,
            "layers permits {MAX_LAYERS} stages"
        );
        let layers = path
            .layers
            .iter()
            .enumerate()
            .map(|(index, stage)| {
                Self::stage(stage, groups, rule_explicit_mode, Role::Layer)
                    .with_context(|| format!("layer {}", index + 1))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let gateway = path
            .gateway
            .as_ref()
            .map(|stage| {
                Self::stage(stage, groups, rule_explicit_mode, Role::Gateway).context("gateway")
            })
            .transpose()?;

        match &to {
            Target::Peer(_) | Target::AnyPeer => {
                ensure!(
                    gateway.is_none(),
                    "gateway applies only to a CIDR or \"internet\""
                );
                ensure!(!layers.is_empty(), "a peer path needs relays in layers");
            }
            Target::Internet => ensure!(gateway.is_some(), "to = \"internet\" needs a gateway"),
            Target::Prefix(_) => ensure!(
                gateway.is_some() || !layers.is_empty(),
                "a CIDR path needs a gateway, relays in layers, or both"
            ),
        }

        let effective_mode = rule_explicit_mode.unwrap_or_else(|| {
            if layers.iter().any(|layer| layer.mode == Mode::Parallel) {
                Mode::Parallel
            } else if layers.iter().any(|layer| layer.mode == Mode::Flow)
                || gateway.as_ref().is_some_and(|g| g.mode == Mode::Flow)
            {
                Mode::Flow
            } else {
                Mode::Failover
            }
        });

        Ok(Rule {
            to_text: path.to.clone(),
            to,
            mode: effective_mode,
            layers,
            gateway,
            strict: path.strict,
        })
    }
}

/// Packet and selection counters, laid out like the compiled policy.
struct RuleCounters {
    relayed_packets: AtomicU64,
    fallback_packets: AtomicU64,
    dropped_packets: AtomicU64,
    /// Per segment (`layers` in order, then optional `gateway`), per member.
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
    relay_capable: bool,
    exit: bool,
}

struct Resolved {
    generation: u64,
    version: u64,
    /// Per rule: per segment (`layers`, then optional `gateway`), per member.
    members: Vec<Vec<Vec<ResolvedMember>>>,
    peer_rules: HashMap<PeerId, u16>,
    any_peer: Option<u16>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateChain {
    pub path_id: u8,
    pub hops: SmallVec<[PeerId; MAX_LAYERS]>,
    pub member_picks: SmallVec<[(usize, usize); MAX_LAYERS]>,
    pub weight: u32,
}

/// Multipath or single-chain forwarding plan for one flow/packet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum MultipathPlan {
    /// No configured relay layers apply: route automatically (1-relay).
    Automatic,
    /// Single deterministic relay chain (1-member layers, `flow`, `failover`, or 1 remaining live chain).
    Single { chain: CandidateChain },
    /// Multiple active chains for parallel striping and active probing.
    Parallel {
        chains: SmallVec<[CandidateChain; MAX_ACTIVE_CHAINS]>,
    },
    /// No usable chain and `!strict`: fall back to automatic routing.
    Fallback,
    /// No usable chain and `strict`: drop the packet.
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
    Layer,
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
            let policy = flags
                .path_policy
                .as_ref()
                .and_then(|config| PathPolicy::compile(config).ok())
                .unwrap_or_default();
            let counters = policy
                .rules
                .iter()
                .map(|rule| RuleCounters {
                    relayed_packets: AtomicU64::new(0),
                    fallback_packets: AtomicU64::new(0),
                    dropped_packets: AtomicU64::new(0),
                    picks: rule
                        .layers
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

    fn resolved(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
    ) -> Option<(Arc<Compiled>, Arc<Resolved>)> {
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

    fn resolve(
        compiled: &Compiled,
        snapshot: &ForwardingDecisionSnapshot,
        my_peer_id: PeerId,
    ) -> Resolved {
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
                    && snapshot
                        .next_hop(peer_id, NextHopPolicy::LeastCost)
                        .is_some(),
                relay_capable: features.is_some_and(|features| {
                    features.multipath_relay_v1
                        && features.relay_semantics_v1
                        && !features.deny_transit_data
                }),
                exit: features.is_some_and(|features| features.exit_node),
            }
        };
        let mut resolved = Resolved {
            generation: snapshot.generation(),
            version: compiled.version,
            members: Vec::with_capacity(compiled.policy.rules.len()),
            peer_rules: HashMap::new(),
            any_peer: None,
            rule_peers: Vec::with_capacity(compiled.policy.rules.len()),
            prefix_v4: PrefixMap::new(),
            prefix_v6: PrefixMap::new(),
            internet: None,
        };
        for (index, rule) in compiled.policy.rules.iter().enumerate() {
            let index = index as u16;
            resolved.members.push(
                rule.layers
                    .iter()
                    .chain(&rule.gateway)
                    .map(|segment| {
                        segment
                            .members
                            .iter()
                            .map(|item| member(&item.peer))
                            .collect()
                    })
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
                Target::AnyPeer => resolved.any_peer = Some(index),
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

    fn member_usable(
        member: &ResolvedMember,
        role: Role,
        excluded: &[PeerId],
        exports: &impl Fn(PeerId) -> bool,
    ) -> Option<PeerId> {
        let peer_id = member.peer?;
        let capable = match role {
            Role::Layer => member.relay_capable,
            Role::Gateway => member.exit || exports(peer_id),
        };
        (member.reachable && capable && !excluded.contains(&peer_id)).then_some(peer_id)
    }

    /// Pick one member of a gateway or flow/failover segment.
    fn pick_one(
        segment: &Segment,
        members: &[ResolvedMember],
        flow: u64,
        salt: u64,
        role: Role,
        excluded: &[PeerId],
        exports: impl Fn(PeerId) -> bool,
    ) -> Option<(usize, PeerId)> {
        match segment.mode {
            Mode::Failover => members.iter().enumerate().find_map(|(index, member)| {
                Some((
                    index,
                    Self::member_usable(member, role, excluded, &exports)?,
                ))
            }),
            Mode::Flow | Mode::Parallel => {
                members
                    .iter()
                    .enumerate()
                    .filter_map(|(index, member)| {
                        Some((
                            index,
                            Self::member_usable(member, role, excluded, &exports)?,
                        ))
                    })
                    .max_by(|(left, left_peer), (right, right_peer)| {
                        score(flow, salt, *left_peer, segment.members[*left].weight).total_cmp(
                            &score(flow, salt, *right_peer, segment.members[*right].weight),
                        )
                    })
            }
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
        let salt = u64::from(rule_index) << 8 | rule.layers.len() as u64;
        let picked = Self::pick_one(gateway, members, flow, salt, Role::Gateway, &[], &exports);
        let Some((member, peer_id)) = picked else {
            compiled.counters[usize::from(rule_index)]
                .fallback_packets
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        compiled.counters[usize::from(rule_index)].picks[rule.layers.len()][member]
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

    /// The path for traffic to `peer_id` when the packet carries none: exact peer rule first,
    /// then a gateway rule whose `layers` apply to its exit, then wildcard `to = "*"`.
    pub fn rule_for_destination(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        peer_id: PeerId,
    ) -> Option<u16> {
        let (compiled, resolved) = self.resolved(snapshot)?;
        if let Some(rule) = resolved.peer_rules.get(&peer_id) {
            return Some(*rule);
        }
        if let Some(rule) = compiled
            .policy
            .rules
            .iter()
            .enumerate()
            .find(|(index, rule)| {
                rule.gateway.is_some()
                    && !rule.layers.is_empty()
                    && resolved.members[*index].last().is_some_and(|members| {
                        members.iter().any(|member| member.peer == Some(peer_id))
                    })
            })
            .map(|(index, _)| index as u16)
        {
            return Some(rule);
        }
        (peer_id != self.my_peer_id)
            .then_some(resolved.any_peer)
            .flatten()
    }

    fn expand_rule_chains(
        rule: &Rule,
        rule_index: u16,
        resolved_layers: &[Vec<ResolvedMember>],
        destination: Option<PeerId>,
        flow: u64,
        parallel_for_status: bool,
    ) -> Vec<CandidateChain> {
        struct Scratch {
            hops: SmallVec<[PeerId; MAX_LAYERS]>,
            picks: SmallVec<[(usize, usize); MAX_LAYERS]>,
        }

        #[allow(clippy::too_many_arguments)]
        fn dfs(
            rule: &Rule,
            rule_index: u16,
            resolved_layers: &[Vec<ResolvedMember>],
            destination: Option<PeerId>,
            flow: u64,
            parallel_for_status: bool,
            position: usize,
            acc_weight: u32,
            scratch: &mut Scratch,
            out: &mut Vec<CandidateChain>,
        ) {
            if out.len() >= 128 {
                return;
            }
            if position == rule.layers.len() {
                out.push(CandidateChain {
                    path_id: 0,
                    hops: scratch.hops.clone(),
                    member_picks: scratch.picks.clone(),
                    weight: acc_weight.max(1),
                });
                return;
            }
            let segment = &rule.layers[position];
            let members = &resolved_layers[position];
            let no_exports = |_: PeerId| false;
            let mut excluded = SmallVec::<[PeerId; MAX_LAYERS + 1]>::from_slice(&scratch.hops);
            if let Some(dst) = destination {
                excluded.push(dst);
            }

            let effective_mode = if parallel_for_status && segment.members.len() > 1 {
                match segment.mode {
                    Mode::Failover => Mode::Failover,
                    Mode::Flow | Mode::Parallel => Mode::Parallel,
                }
            } else {
                segment.mode
            };

            match effective_mode {
                Mode::Failover => {
                    if let Some((member_idx, peer_id)) =
                        members.iter().enumerate().find_map(|(i, m)| {
                            Some((
                                i,
                                PathRuntime::member_usable(m, Role::Layer, &excluded, &no_exports)?,
                            ))
                        })
                    {
                        scratch.hops.push(peer_id);
                        scratch.picks.push((position, member_idx));
                        dfs(
                            rule,
                            rule_index,
                            resolved_layers,
                            destination,
                            flow,
                            parallel_for_status,
                            position + 1,
                            acc_weight.saturating_mul(segment.members[member_idx].weight),
                            scratch,
                            out,
                        );
                        scratch.picks.pop();
                        scratch.hops.pop();
                    }
                }
                Mode::Flow => {
                    let salt = u64::from(rule_index) << 8 | position as u64;
                    if let Some((member_idx, peer_id)) = PathRuntime::pick_one(
                        segment,
                        members,
                        flow,
                        salt,
                        Role::Layer,
                        &excluded,
                        |_| false,
                    ) {
                        scratch.hops.push(peer_id);
                        scratch.picks.push((position, member_idx));
                        dfs(
                            rule,
                            rule_index,
                            resolved_layers,
                            destination,
                            flow,
                            parallel_for_status,
                            position + 1,
                            acc_weight.saturating_mul(segment.members[member_idx].weight),
                            scratch,
                            out,
                        );
                        scratch.picks.pop();
                        scratch.hops.pop();
                    }
                }
                Mode::Parallel => {
                    for (member_idx, member) in members.iter().enumerate() {
                        let Some(peer_id) =
                            PathRuntime::member_usable(member, Role::Layer, &excluded, &no_exports)
                        else {
                            continue;
                        };
                        scratch.hops.push(peer_id);
                        scratch.picks.push((position, member_idx));
                        let next_weight = acc_weight
                            .saturating_mul(segment.members[member_idx].weight)
                            .min(1_000_000);
                        dfs(
                            rule,
                            rule_index,
                            resolved_layers,
                            destination,
                            flow,
                            parallel_for_status,
                            position + 1,
                            next_weight,
                            scratch,
                            out,
                        );
                        scratch.picks.pop();
                        scratch.hops.pop();
                    }
                }
            }
        }

        let mut chains = Vec::new();
        let mut scratch = Scratch {
            hops: SmallVec::new(),
            picks: SmallVec::new(),
        };
        dfs(
            rule,
            rule_index,
            resolved_layers,
            destination,
            flow,
            parallel_for_status,
            0,
            1,
            &mut scratch,
            &mut chains,
        );
        if chains.len() > MAX_ACTIVE_CHAINS {
            chains.sort_by_key(|chain| Reverse(chain.weight));
            chains.truncate(MAX_ACTIVE_CHAINS);
        }
        for (idx, chain) in chains.iter_mut().enumerate() {
            chain.path_id = idx as u8;
        }
        chains
    }

    /// Build the single- or multi-chain relay plan for one packet/flow to `destination` under `rule`.
    pub fn plan_for_destination(
        &self,
        snapshot: &ForwardingDecisionSnapshot,
        rule_index: u16,
        destination: PeerId,
        flow: u64,
    ) -> MultipathPlan {
        let Some((compiled, resolved)) = self.resolved(snapshot) else {
            return MultipathPlan::Automatic;
        };
        let Some(rule) = compiled.policy.rules.get(usize::from(rule_index)) else {
            return MultipathPlan::Automatic;
        };
        if rule.layers.is_empty() {
            return MultipathPlan::Automatic;
        }
        let counters = &compiled.counters[usize::from(rule_index)];
        let resolved_layers = &resolved.members[usize::from(rule_index)][..rule.layers.len()];
        let mut chains = Self::expand_rule_chains(
            rule,
            rule_index,
            resolved_layers,
            Some(destination),
            flow,
            false,
        );
        if chains.is_empty() {
            if rule.strict {
                counters.dropped_packets.fetch_add(1, Ordering::Relaxed);
                return MultipathPlan::Drop;
            }
            counters.fallback_packets.fetch_add(1, Ordering::Relaxed);
            return MultipathPlan::Fallback;
        }
        if chains.len() == 1 {
            return MultipathPlan::Single {
                chain: chains.swap_remove(0),
            };
        }
        MultipathPlan::Parallel {
            chains: SmallVec::from_vec(chains),
        }
    }

    /// Record one packet routed along `chain` under `rule_index`.
    pub fn record_chain_pick(&self, rule_index: u16, chain: &CandidateChain) {
        let Some(compiled) = self.compiled.load_full() else {
            return;
        };
        let Some(counters) = compiled.counters.get(usize::from(rule_index)) else {
            return;
        };
        counters.relayed_packets.fetch_add(1, Ordering::Relaxed);
        for &(position, member_idx) in &chain.member_picks {
            if let Some(member_counter) = counters
                .picks
                .get(position)
                .and_then(|row| row.get(member_idx))
            {
                member_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Count a packet that fell back or was dropped when no chain could send it.
    pub fn record_send_fallback(&self, rule_index: u16, strict: bool, decrement_relayed: bool) {
        let Some(compiled) = self.compiled.load_full() else {
            return;
        };
        let Some(counters) = compiled.counters.get(usize::from(rule_index)) else {
            return;
        };
        if decrement_relayed {
            counters.relayed_packets.fetch_sub(1, Ordering::Relaxed);
        }
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
        chain_telemetry: impl Fn(Option<PeerId>, u8, &[PeerId]) -> (u32, u64, u64, bool),
        reordered_packets: impl Fn(Option<PeerId>) -> u64,
    ) -> Vec<crate::proto::api::control::v1::PathStatus> {
        use crate::proto::api::control::v1::{
            PathChainStatus, PathMember, PathSegment, PathStatus,
        };
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
                    .layers
                    .iter()
                    .map(|segment| (segment, Role::Layer))
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
                                    Some(_) if role == Role::Layer && !state.relay_capable => {
                                        "Does not forward multipath relay traffic (older version or transit denied)."
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
                            mode: segment.mode.as_str().into(),
                            members,
                        }
                    })
                    .collect();
                let gateway = rule
                    .gateway
                    .is_some()
                    .then(|| segments.last().cloned())
                    .flatten();
                let layers = segments[..rule.layers.len()].to_vec();
                let to_peer_id = resolved.rule_peers[index];
                let (state, reason) = if matches!(rule.to, Target::Peer(_)) && to_peer_id.is_none()
                {
                    ("fallback", "The destination is not in the network.".to_owned())
                } else if missing.is_empty() {
                    ("ready", String::new())
                } else {
                    (
                        if rule.strict { "down" } else { "fallback" },
                        format!("No usable member in {}.", missing.join(", ")),
                    )
                };
                let chains = if !rule.layers.is_empty() {
                    let expanded = Self::expand_rule_chains(
                        rule,
                        index as u16,
                        &members[..rule.layers.len()],
                        to_peer_id,
                        0,
                        true,
                    );
                    expanded
                        .into_iter()
                        .map(|chain| {
                            let (rtt_us, queued_bytes, packets, healthy) =
                                chain_telemetry(to_peer_id, chain.path_id, &chain.hops);
                            PathChainStatus {
                                path_id: u32::from(chain.path_id),
                                hop_peer_ids: chain.hops.into_vec(),
                                rtt_us,
                                queued_bytes,
                                packets,
                                healthy,
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                PathStatus {
                    index: index as u32,
                    to: rule.to_text.clone(),
                    to_peer_id,
                    mode: rule.mode.as_str().into(),
                    layers,
                    gateway,
                    strict: rule.strict,
                    state: state.into(),
                    reason,
                    relayed_packets: counters.relayed_packets.load(Ordering::Relaxed),
                    fallback_packets: counters.fallback_packets.load(Ordering::Relaxed),
                    dropped_packets: counters.dropped_packets.load(Ordering::Relaxed),
                    reordered_packets: reordered_packets(to_peer_id),
                    chains,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::{TomlPathGroup, TomlPathRule};
    use crate::peers::route_trait::{
        ForwardingDecisionSnapshot, ForwardingNextHop, ForwardingPeerInfo, ForwardingPeerTable,
    };
    use crate::proto::common::{PathPolicy as Config, PeerFeatureFlag};

    fn key(byte: u8) -> String {
        BASE64_STANDARD.encode([byte; 32])
    }

    fn config(text: &str) -> Config {
        let table: toml::Table = text.parse().unwrap();
        let group: Vec<TomlPathGroup> = table
            .get("group")
            .map(|value| value.clone().try_into().unwrap())
            .unwrap_or_default();
        let path: Vec<TomlPathRule> = table
            .get("path")
            .map(|value| value.clone().try_into().unwrap())
            .unwrap_or_default();
        Config {
            group: group.iter().map(Into::into).collect(),
            path: path.iter().map(Into::into).collect(),
        }
    }

    fn test_snapshot(
        my_peer_id: PeerId,
        generation: u64,
        peers: &[(PeerId, [u8; 4], bool)],
        reachable: &[PeerId],
    ) -> Arc<ForwardingDecisionSnapshot> {
        let mut peer_infos = Vec::new();
        let mut ipv4_peer_ids = HashMap::new();
        for &(peer_id, ip, exit_node) in peers {
            ipv4_peer_ids.insert(std::net::Ipv4Addr::from(ip), peer_id);
            peer_infos.push(ForwardingPeerInfo {
                peer_id,
                has_ipv4: true,
                static_pubkey: Some([peer_id as u8; 32]),
                feature_flag: Some(PeerFeatureFlag {
                    multipath_relay_v1: true,
                    relay_semantics_v1: true,
                    exit_node,
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        let mut hops = HashMap::new();
        for &peer_id in reachable {
            if peer_id == my_peer_id {
                continue;
            }
            hops.insert(
                peer_id,
                ForwardingNextHop {
                    next_hop_peer_id: peer_id,
                    path_delivery_bps: 10_000,
                    path_latency: 10,
                    path_len: 1,
                    version: 1,
                },
            );
        }
        let hops = Arc::new(hops);
        ForwardingDecisionSnapshot::from_parts(
            generation,
            Arc::new(ForwardingPeerTable::new(peer_infos)),
            Arc::new(HashSet::new()),
            None,
            hops.clone(),
            hops.clone(),
            hops,
            Arc::new(ipv4_peer_ids),
            Arc::new(HashMap::new()),
            Arc::new(Default::default()),
            Arc::new(Default::default()),
        )
    }

    #[test]
    fn compile_validates_multipath_and_multilayer_references() {
        let ok = config(&format!(
            "[[group]]\nname = \"relays\"\nnodes = [\"{}\", \"10.0.0.3\"]\nweights = [2, 1]\n\
             [[path]]\nto = \"{}\"\nlayers = [\"relays\", [\"10.0.0.4\", \"10.0.0.5\"], {{ nodes = [\"10.0.0.6\", \"10.0.0.7\"], mode = \"flow\", weights = [3, 1] }}]\n\
             [[path]]\nto = \"*\"\nlayers = [[\"10.0.0.2\", \"10.0.0.3\"]]\n\
             [[path]]\nto = \"internet\"\ngateway = \"relays\"\nstrict = true\n",
            key(2),
            key(9)
        ));
        let policy = PathPolicy::compile(&ok).unwrap();
        assert_eq!(policy.rules.len(), 3);
        assert_eq!(policy.rules[0].mode, Mode::Parallel);
        assert_eq!(policy.rules[0].layers.len(), 3);
        assert_eq!(policy.rules[0].layers[0].mode, Mode::Parallel);
        assert_eq!(policy.rules[0].layers[0].members[0].weight, 2);
        assert_eq!(policy.rules[0].layers[1].mode, Mode::Parallel);
        assert_eq!(policy.rules[0].layers[2].mode, Mode::Flow);
        assert_eq!(policy.rules[0].layers[2].members[0].weight, 3);
        assert_eq!(policy.rules[1].to, Target::AnyPeer);
        // Gateway coerces Parallel -> Flow to preserve SNAT connection affinity.
        assert_eq!(policy.rules[2].gateway.as_ref().unwrap().mode, Mode::Flow);

        // A key with '/' is a peer, not a CIDR.
        let slash_key = BASE64_STANDARD.encode([0xff_u8; 32]);
        assert!(slash_key.contains('/'));
        let keyed = PathPolicy::compile(&config(&format!(
            "[[path]]\nto = \"{slash_key}\"\nlayers = [\"10.0.0.2\"]\n[[path]]\nto = \"10.8.0.0/16\"\nlayers = [[\"10.0.0.2\", \"10.0.0.3\"]]\n"
        )))
        .unwrap();
        assert!(matches!(keyed.rules[0].to, Target::Peer(PeerRef::Key(_))));
        assert!(matches!(keyed.rules[1].to, Target::Prefix(_)));

        let too_many_layers = (1..=9)
            .map(|i| format!("\"10.0.0.{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        for (text, message) in [
            (
                "[[path]]\nto = \"internet\"\nlayers = [\"10.0.0.2\"]\n",
                "needs a gateway",
            ),
            (
                "[[path]]\nto = \"10.0.0.9\"\nlayers = [\"nope\"]\n",
                "not a group name",
            ),
            ("[[path]]\nto = \"10.0.0.9\"\n", "needs relays in layers"),
            (
                "[[group]]\nname = \"g\"\nnodes = [\"10.0.0.2\"]\nmode = \"failover\"\nweights = [3]\n",
                "weights apply only",
            ),
            (
                "[[path]]\nto = \"10.0.0.9\"\nlayers = [\"10.0.0.2\"]\n[[path]]\nto = \"10.0.0.9\"\nlayers = [\"10.0.0.3\"]\n",
                "another path",
            ),
            (
                "[[path]]\nto = \"*\"\ngateway = \"10.0.0.2\"\n",
                "gateway applies only",
            ),
            (
                &format!("[[path]]\nto = \"10.0.0.99\"\nlayers = [{too_many_layers}]\n"),
                "layers permits 8 stages",
            ),
        ] {
            let error = format!("{:#}", PathPolicy::compile(&config(text)).unwrap_err());
            assert!(error.contains(message), "{message}: {error}");
        }
    }

    #[test]
    fn expands_parallel_multilayer_chains_without_loops_and_prefers_exact_peer_over_wildcard() {
        let snapshot = test_snapshot(
            1,
            7,
            &[
                (1, [10, 0, 0, 1], false),
                (2, [10, 0, 0, 2], false),
                (3, [10, 0, 0, 3], false),
                (4, [10, 0, 0, 4], false),
                (9, [10, 0, 0, 9], false),
            ],
            &[2, 3, 4, 9],
        );

        let runtime = PathRuntime::new(1);
        let cfg = config(
            "[[path]]\nto = \"10.0.0.9\"\nlayers = [[\"10.0.0.2\", \"10.0.0.3\"], [\"10.0.0.3\", \"10.0.0.4\"]]\n\
             [[path]]\nto = \"*\"\nlayers = [\"10.0.0.4\"]\n",
        );
        let flags = Flags {
            path_policy: Some(cfg),
            ..Flags::default()
        };
        runtime.refresh(&Arc::new(flags));

        let exact = runtime.rule_for_destination(&snapshot, 9).unwrap();
        assert_eq!(exact, 0);
        let wild = runtime.rule_for_destination(&snapshot, 4).unwrap();
        assert_eq!(wild, 1);

        let MultipathPlan::Parallel { chains } =
            runtime.plan_for_destination(&snapshot, exact, 9, 42)
        else {
            panic!("expected parallel plan");
        };
        let hop_lists: Vec<Vec<PeerId>> = chains.iter().map(|c| c.hops.to_vec()).collect();
        // (2->3), (2->4), (3->4). (3->3) is excluded because it loops!
        assert_eq!(hop_lists, vec![vec![2, 3], vec![2, 4], vec![3, 4]]);
    }

    #[test]
    fn weighted_rendezvous_follows_weights_and_moves_only_lost_flows() {
        let segment = Segment {
            name: "g".into(),
            mode: Mode::Flow,
            explicit_mode: Some(Mode::Flow),
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
                    relay_capable: true,
                    exit: true,
                })
                .collect()
        };
        let all = live(&[11, 12, 13]);
        let mut counts = [0_u32; 3];
        let mut before = Vec::new();
        for flow in 0..20_000_u64 {
            let (index, _) =
                PathRuntime::pick_one(&segment, &all, mix(flow), 7, Role::Layer, &[], |_| false)
                    .unwrap();
            counts[index] += 1;
            before.push(index);
        }
        assert!((11_000..13_000).contains(&counts[0]), "{counts:?}");
        assert!((3_400..4_600).contains(&counts[1]), "{counts:?}");

        let mut without_second = all.clone();
        without_second[1].reachable = false;
        for flow in 0..20_000_u64 {
            let (index, _) = PathRuntime::pick_one(
                &segment,
                &without_second,
                mix(flow),
                7,
                Role::Layer,
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
