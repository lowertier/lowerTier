use std::{
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dashmap::{DashMap, mapref::entry::Entry};
use smallvec::SmallVec;
use thiserror::Error;

use crate::common::PeerId;
use crate::tunnel::packet_def::{VlanStack, ethernet_network_metadata};

pub type MacAddress = [u8; 6];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetDestination {
    Known(PeerId),
    Flood,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum L2FrameError {
    #[error("ethernet frame is shorter than the 14-byte header")]
    TooShort,
}

#[derive(Clone, Copy, Debug)]
struct FdbEntry {
    peer_id: PeerId,
    last_seen: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FdbKey {
    vlan: VlanStack,
    mac: MacAddress,
}

#[derive(Default)]
pub(crate) struct L2SourceBatch {
    sources: SmallVec<[(VlanStack, MacAddress, PeerId); 4]>,
    generation: u64,
}

#[derive(Default)]
pub(crate) struct L2DestinationBatch {
    destinations: SmallVec<[(VlanStack, MacAddress, EthernetDestination); 4]>,
}

#[derive(Default)]
pub(crate) struct L2IngressBatch {
    sources: L2SourceBatch,
    destinations: L2DestinationBatch,
}

impl L2DestinationBatch {
    pub(crate) fn resolve_at(
        &mut self,
        fabric: &L2Fabric,
        frame: &[u8],
        now: Instant,
    ) -> Result<EthernetDestination, L2FrameError> {
        let (vlan, destination, _) = ethernet_addresses(frame)?;
        if let Some((_, _, decision)) =
            self.destinations
                .iter()
                .find(|(recorded_vlan, recorded_destination, _)| {
                    *recorded_vlan == vlan && *recorded_destination == destination
                })
        {
            return Ok(*decision);
        }

        let decision = fabric.destination_address_at(vlan, destination, now);
        self.destinations.push((vlan, destination, decision));
        Ok(decision)
    }
}

impl L2SourceBatch {
    fn contains(
        &mut self,
        fabric: &L2Fabric,
        vlan: VlanStack,
        source: MacAddress,
        peer_id: PeerId,
    ) -> bool {
        let generation = fabric.generation();
        if generation != self.generation {
            self.sources.clear();
            self.generation = generation;
        }
        self.sources.contains(&(vlan, source, peer_id))
    }
    pub(crate) fn record_source(&mut self, vlan: VlanStack, source: MacAddress, peer_id: PeerId) {
        if !is_unicast(source) {
            return;
        }
        if let Some((_, _, recorded_peer_id)) =
            self.sources
                .iter_mut()
                .find(|(recorded_vlan, recorded_source, _)| {
                    *recorded_vlan == vlan && *recorded_source == source
                })
        {
            *recorded_peer_id = peer_id;
            return;
        }
        self.sources.push((vlan, source, peer_id));
    }
}

/// Concurrent Ethernet forwarding database used by the peer fast path.
///
/// Source learning and known-unicast lookups touch only one DashMap shard.
/// The entry reservation counter keeps the configured capacity strict even
/// when multiple peer receive tasks learn new addresses concurrently.
pub struct L2Fabric {
    fdb: DashMap<FdbKey, FdbEntry>,
    entry_count: AtomicUsize,
    generation: AtomicU64,
    capacity: usize,
    age: Duration,
    flood_bytes_per_second: u64,
    flood: Mutex<FloodBucket>,
    ingress: DashMap<PeerId, Mutex<FloodBucket>>,
    per_peer_counts: DashMap<PeerId, Arc<AtomicUsize>>,
    flood_drops: AtomicU64,
    ingress_flood_drops: AtomicU64,
    loop_drops: AtomicU64,
    policy_drops: AtomicU64,
    maintenance: Mutex<FdbMaintenance>,
    policy: L2Policy,
    bridge_enabled: bool,
}

#[derive(Default)]
pub(crate) struct L2Policy {
    max_macs_per_peer: usize,
    move_hold: Duration,
    allowed_vlans: Vec<u16>,
    allowed_ether_types: Vec<u16>,
}

impl L2Policy {
    pub(crate) fn from_flags(flags: &crate::common::config::Flags) -> Self {
        let mut policy = Self {
            max_macs_per_peer: flags.l2_max_macs_per_peer as usize,
            move_hold: Duration::from_secs(flags.l2_mac_move_hold_seconds),
            allowed_vlans: flags
                .l2_allowed_vlans
                .iter()
                .map(|value| *value as u16)
                .collect(),
            allowed_ether_types: flags
                .l2_allowed_ether_types
                .iter()
                .map(|value| *value as u16)
                .collect(),
        };
        policy.allowed_vlans.sort_unstable();
        policy.allowed_vlans.dedup();
        policy.allowed_ether_types.sort_unstable();
        policy.allowed_ether_types.dedup();
        policy
    }
}

struct FdbMaintenance {
    next_expiry: Instant,
}

struct FloodBucket {
    last_refill: Instant,
    // Nanobytes retain fractional refill credit without floating-point rounding.
    tokens: u128,
}

impl FloodBucket {
    fn new(rate: u64, now: Instant) -> Self {
        Self {
            last_refill: now,
            tokens: u128::from(rate) * 1_000_000_000,
        }
    }

    fn consume_at(&mut self, bytes: usize, rate: u64, now: Instant) -> bool {
        if rate == 0 {
            return true;
        }
        let elapsed = now.saturating_duration_since(self.last_refill).as_nanos();
        self.last_refill = self.last_refill.max(now);
        let capacity = u128::from(rate) * 1_000_000_000;
        self.tokens = self
            .tokens
            .saturating_add(elapsed.saturating_mul(u128::from(rate)))
            .min(capacity);
        let cost = (bytes as u128) * 1_000_000_000;
        if cost > self.tokens {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct L2Counters {
    pub flood_drops: u64,
    pub ingress_flood_drops: u64,
    pub loop_drops: u64,
    pub policy_drops: u64,
}

#[derive(Debug)]
pub struct L2FdbSnapshotEntry {
    pub vlans: SmallVec<[u16; 4]>,
    pub mac: MacAddress,
    pub peer_id: PeerId,
    pub idle: Duration,
}

#[derive(Debug)]
pub struct L2Snapshot {
    pub entries: Vec<L2FdbSnapshotEntry>,
    pub counters: L2Counters,
}

/// Keep one packet fanout within the maximum peer set accepted by route sync.
pub const MAX_FANOUT_RECIPIENTS: usize = 4_096;

impl L2Fabric {
    pub fn from_flags(flags: &crate::common::config::Flags) -> Self {
        let mut fabric = Self::with_policy(
            flags.l2_fdb_capacity as usize,
            Duration::from_secs(flags.l2_fdb_age_seconds),
            flags.l2_flood_bytes_per_second,
            L2Policy::from_flags(flags),
        );
        fabric.bridge_enabled = flags.enable_bridge;
        fabric
    }

    pub fn new(capacity: usize, age: Duration, flood_bytes_per_second: u64) -> Self {
        Self::with_policy(capacity, age, flood_bytes_per_second, L2Policy::default())
    }

    pub(crate) fn with_policy(
        capacity: usize,
        age: Duration,
        flood_bytes_per_second: u64,
        policy: L2Policy,
    ) -> Self {
        Self {
            fdb: DashMap::new(),
            entry_count: AtomicUsize::new(0),
            generation: AtomicU64::new(1),
            capacity,
            age,
            flood_bytes_per_second,
            flood: Mutex::new(FloodBucket::new(flood_bytes_per_second, Instant::now())),
            ingress: DashMap::new(),
            per_peer_counts: DashMap::new(),
            flood_drops: AtomicU64::new(0),
            ingress_flood_drops: AtomicU64::new(0),
            loop_drops: AtomicU64::new(0),
            policy_drops: AtomicU64::new(0),
            maintenance: Mutex::new(FdbMaintenance {
                next_expiry: Instant::now(),
            }),
            policy,
            bridge_enabled: true,
        }
    }

    pub(crate) fn needs_tap_admission(&self) -> bool {
        // Ownership and flood checks protect an attached LAN. Explicit filters also apply without a bridge.
        self.bridge_enabled
            || !self.policy.allowed_vlans.is_empty()
            || !self.policy.allowed_ether_types.is_empty()
    }

    pub(crate) fn has_policy(&self) -> bool {
        self.policy.max_macs_per_peer != 0
            || !self.policy.move_hold.is_zero()
            || !self.policy.allowed_vlans.is_empty()
            || !self.policy.allowed_ether_types.is_empty()
    }

    pub(crate) fn allows_compact_ip(&self, payload: &[u8]) -> bool {
        let ether_type = match payload.first().map(|byte| byte >> 4) {
            Some(4) => 0x0800,
            Some(6) => 0x86dd,
            _ => return false,
        };
        (self.policy.allowed_vlans.is_empty()
            || self.policy.allowed_vlans.binary_search(&0).is_ok())
            && (self.policy.allowed_ether_types.is_empty()
                || self
                    .policy
                    .allowed_ether_types
                    .binary_search(&ether_type)
                    .is_ok())
    }

    pub(crate) fn admit_compact_ingress_at(
        &self,
        payload: &[u8],
        peer_id: PeerId,
        now: Instant,
        is_flood: bool,
    ) -> bool {
        if !self.allows_compact_ip(payload) {
            self.policy_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        !is_flood || self.allow_ingress_flood_at(payload.len().saturating_add(14), peer_id, now)
    }

    /// Apply bridge policy before forwarding or learning an Ethernet source.
    pub(crate) fn admit_source_at(&self, frame: &[u8], peer_id: PeerId, now: Instant) -> bool {
        let Some((vlan, source)) = self.permitted_source(frame) else {
            return false;
        };
        self.learn_address_at(vlan, source, peer_id, now)
    }

    pub(crate) fn admit_source_batch_at(
        &self,
        frame: &[u8],
        peer_id: PeerId,
        now: Instant,
        batch: &mut L2SourceBatch,
    ) -> bool {
        if !self.has_policy()
            && !ethernet_addresses(frame).is_ok_and(|(_, _, source)| is_unicast(source))
        {
            return true;
        }
        let Some((vlan, source)) = self.permitted_source(frame) else {
            return false;
        };
        if batch.contains(self, vlan, source, peer_id) {
            return true;
        }
        let generation = batch.generation;
        let admitted = self.learn_address_at(vlan, source, peer_id, now);
        // Cache only an unchanged ownership generation. Withdrawal can race with learning.
        if admitted && generation == self.generation() {
            batch.record_source(vlan, source, peer_id);
        }
        admitted
    }

    fn permitted_source(&self, frame: &[u8]) -> Option<(VlanStack, MacAddress)> {
        let Some(metadata) = ethernet_network_metadata(frame) else {
            return None;
        };
        if !self.policy.allowed_ether_types.is_empty()
            && self
                .policy
                .allowed_ether_types
                .binary_search(&metadata.ether_type)
                .is_err()
        {
            return None;
        }
        if !self.policy.allowed_vlans.is_empty() {
            // Check every tag, so an allowed outer VLAN cannot hide a denied inner VLAN.
            let mut offset = 12;
            let mut tagged = false;
            while matches!(
                u16::from_be_bytes([frame[offset], frame[offset + 1]]),
                0x8100 | 0x88a8 | 0x9100
            ) {
                tagged = true;
                let vlan = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]) & 0x0fff;
                if self.policy.allowed_vlans.binary_search(&vlan).is_err() {
                    return None;
                }
                offset += 4;
            }
            if !tagged && self.policy.allowed_vlans.binary_search(&0).is_err() {
                return None;
            }
        }
        let source = frame[6..12].try_into().unwrap();
        is_unicast(source).then_some((metadata.vlan_stack, source))
    }

    fn reclaim_expired_at(&self, now: Instant, state: &mut FdbMaintenance) {
        if now < state.next_expiry {
            return;
        }
        // Pressure triggers at most one capacity-bounded sweep per second.
        // Never hold a DashMap entry while acquiring this maintenance lock.
        state.next_expiry = now + self.age.min(Duration::from_secs(1));
        self.fdb.retain(|_, entry| {
            if now.saturating_duration_since(entry.last_seen) <= self.age {
                return true;
            }
            self.release_peer_entry(entry.peer_id);
            self.entry_count.fetch_sub(1, Ordering::AcqRel);
            false
        });
    }

    pub fn learn_source(&self, frame: &[u8], peer_id: PeerId) {
        self.learn_source_at(frame, peer_id, Instant::now());
    }

    pub fn destination(&self, frame: &[u8]) -> Result<EthernetDestination, L2FrameError> {
        self.destination_at(frame, Instant::now())
    }

    /// Reserve the complete output byte cost before a frame is replicated.
    ///
    /// The recipient bound prevents an untrusted route table from forcing an
    /// unbounded clone set. The byte multiplication saturates before accounting.
    pub fn allow_flood_replicated(&self, frame_len: usize, recipient_count: usize) -> bool {
        let output_bytes = frame_len.saturating_mul(recipient_count);
        self.allow_flood_output_bytes(output_bytes, recipient_count)
    }

    /// Reserve an already aggregated output byte cost before any clone is made.
    ///
    /// Callers use this for mixed compact and full Ethernet fanout.
    pub fn allow_flood_output_bytes(&self, output_bytes: usize, recipient_count: usize) -> bool {
        let allowed = recipient_count <= MAX_FANOUT_RECIPIENTS
            && self.allow_flood_at(output_bytes, Instant::now());
        if !allowed {
            self.flood_drops.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    pub fn counters(&self) -> L2Counters {
        L2Counters {
            flood_drops: self.flood_drops.load(Ordering::Relaxed),
            ingress_flood_drops: self.ingress_flood_drops.load(Ordering::Relaxed),
            loop_drops: self.loop_drops.load(Ordering::Relaxed),
            policy_drops: self.policy_drops.load(Ordering::Relaxed),
        }
    }

    pub fn snapshot(&self) -> L2Snapshot {
        let now = Instant::now();
        L2Snapshot {
            entries: self
                .fdb
                .iter()
                .filter_map(|entry| {
                    let idle = now.saturating_duration_since(entry.last_seen);
                    (idle <= self.age).then_some(L2FdbSnapshotEntry {
                        vlans: SmallVec::from_slice(entry.key().vlan.as_slice()),
                        mac: entry.key().mac,
                        peer_id: entry.peer_id,
                        idle,
                    })
                })
                .collect(),
            counters: self.counters(),
        }
    }

    pub(crate) fn admit_ingress_at(
        &self,
        frame: &[u8],
        peer_id: PeerId,
        local_peer_id: PeerId,
        now: Instant,
    ) -> bool {
        self.admit_ingress_batch_at(
            frame,
            peer_id,
            local_peer_id,
            now,
            &mut L2IngressBatch::default(),
        )
    }

    pub(crate) fn admit_ingress_batch_at(
        &self,
        frame: &[u8],
        peer_id: PeerId,
        local_peer_id: PeerId,
        now: Instant,
        batch: &mut L2IngressBatch,
    ) -> bool {
        let Ok((vlan, _, source)) = ethernet_addresses(frame) else {
            return false;
        };
        if self.has_policy() && self.permitted_source(frame).is_none() {
            self.policy_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Ownership can change during a batch when another task withdraws a peer.
        let learned = batch.sources.contains(self, vlan, source, peer_id);
        let is_flood =
            batch.destinations.resolve_at(self, frame, now).unwrap() == EthernetDestination::Flood;
        if !learned
            && is_flood
            && peer_id != local_peer_id
            && self
                .fdb
                .get(&FdbKey { vlan, mac: source })
                .is_some_and(|entry| {
                    entry.peer_id == local_peer_id
                        && now.saturating_duration_since(entry.last_seen) < self.policy.move_hold
                })
        {
            self.loop_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if is_flood && !self.allow_ingress_flood_at(frame.len(), peer_id, now) {
            return false;
        }
        if !learned && is_unicast(source) {
            let generation = batch.sources.generation;
            let admitted = self.learn_address_at(vlan, source, peer_id, now);
            if !admitted {
                self.policy_drops.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if generation == self.generation() {
                batch.sources.record_source(vlan, source, peer_id);
            }
        }
        true
    }

    pub(crate) fn allow_ingress_flood_at(
        &self,
        bytes: usize,
        peer_id: PeerId,
        now: Instant,
    ) -> bool {
        if self.flood_bytes_per_second == 0 {
            return true;
        }
        let bucket = self
            .ingress
            .entry(peer_id)
            .or_insert_with(|| Mutex::new(FloodBucket::new(self.flood_bytes_per_second, now)));
        let allowed = bucket
            .lock()
            .unwrap()
            .consume_at(bytes, self.flood_bytes_per_second, now);
        if !allowed {
            self.ingress_flood_drops.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    /// Route publication removes unreachable or unauthorized owners without a timer.
    pub(crate) fn retain_peers(
        &self,
        mut reachable: impl FnMut(PeerId) -> bool,
        mut bridge: impl FnMut(PeerId) -> bool,
    ) {
        let _maintenance = self.maintenance.lock().unwrap();
        let invalid_owner = self.policy.max_macs_per_peer == 0
            || self
                .per_peer_counts
                .iter()
                .any(|entry| entry.load(Ordering::Acquire) != 0 && !bridge(*entry.key()));
        if invalid_owner {
            self.fdb.retain(|_, entry| {
                if bridge(entry.peer_id) {
                    return true;
                }
                self.release_peer_entry(entry.peer_id);
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
                false
            });
        }
        self.ingress.retain(|peer, _| reachable(*peer));
        self.per_peer_counts
            .retain(|_, count| count.load(Ordering::Acquire) != 0 || Arc::strong_count(count) != 1);
    }

    pub fn forget_peer(&self, peer_id: PeerId) {
        let _maintenance = self.maintenance.lock().unwrap();
        let keys = self
            .fdb
            .iter()
            .filter_map(|entry| (entry.peer_id == peer_id).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for key in keys {
            if self
                .fdb
                .remove_if(&key, |_, entry| {
                    if entry.peer_id != peer_id {
                        return false;
                    }
                    self.release_peer_entry(entry.peer_id);
                    true
                })
                .is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        self.ingress.remove(&peer_id);
    }

    pub fn clear(&self) {
        let _maintenance = self.maintenance.lock().unwrap();
        let keys = self
            .fdb
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for key in keys {
            if self
                .fdb
                .remove_if(&key, |_, entry| {
                    self.release_peer_entry(entry.peer_id);
                    true
                })
                .is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        self.ingress.clear();
    }

    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    pub(crate) fn learn_source_at(&self, frame: &[u8], peer_id: PeerId, now: Instant) {
        let Ok((vlan, _, source)) = ethernet_addresses(frame) else {
            return;
        };
        if !is_unicast(source) {
            return;
        }

        self.learn_address_at(vlan, source, peer_id, now);
    }

    fn learn_address_at(
        &self,
        vlan: VlanStack,
        source: MacAddress,
        peer_id: PeerId,
        now: Instant,
    ) -> bool {
        let key = FdbKey { vlan, mac: source };
        if let Some(mut entry) = self.fdb.get_mut(&key)
            && entry.peer_id == peer_id
        {
            entry.last_seen = now;
            return true;
        }
        let peer_full = self.policy.max_macs_per_peer != 0
            && self.per_peer_counts.get(&peer_id).is_some_and(|count| {
                count.load(Ordering::Acquire) >= self.policy.max_macs_per_peer
            });
        if peer_full || (self.len() >= self.capacity && !self.fdb.contains_key(&key)) {
            if let Ok(mut state) = self.maintenance.try_lock() {
                self.reclaim_expired_at(now, &mut state);
            }
        }
        match self.fdb.entry(key) {
            Entry::Occupied(mut occupied) => {
                let previous = occupied.get();
                if previous.peer_id != peer_id {
                    if now.saturating_duration_since(previous.last_seen) < self.policy.move_hold {
                        return false;
                    }
                    let Ok(_reservation) = self.try_reserve_peer(peer_id) else {
                        return false;
                    };
                    self.release_peer_entry(previous.peer_id);
                    *occupied.get_mut() = FdbEntry {
                        peer_id,
                        last_seen: now,
                    };
                } else {
                    occupied.get_mut().last_seen = now;
                }
            }
            Entry::Vacant(vacant) => {
                let Ok(owner_count) = self.try_reserve_peer(peer_id) else {
                    return false;
                };
                if self.try_reserve_entry() {
                    vacant.insert(FdbEntry {
                        peer_id,
                        last_seen: now,
                    });
                    self.generation.fetch_add(1, Ordering::Release);
                } else {
                    if let Some(count) = owner_count {
                        count.fetch_sub(1, Ordering::AcqRel);
                    }
                    if self.policy.max_macs_per_peer != 0 || !self.policy.move_hold.is_zero() {
                        // Ownership policies require a recorded source before forwarding.
                        return false;
                    }
                }
            }
        }
        true
    }

    fn release_peer_entry(&self, peer_id: PeerId) {
        self.generation.fetch_add(1, Ordering::Release);
        if self.policy.max_macs_per_peer != 0 {
            let count = self
                .per_peer_counts
                .get(&peer_id)
                .expect("a limited FDB owner has a counter");
            let previous = count.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous != 0);
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn try_reserve_peer(&self, peer_id: PeerId) -> Result<Option<Arc<AtomicUsize>>, ()> {
        if self.policy.max_macs_per_peer == 0 {
            return Ok(None);
        }
        let count = self
            .per_peer_counts
            .entry(peer_id)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.policy.max_macs_per_peer).then_some(count + 1)
            })
            .map_err(|_| ())?;
        Ok(Some(count))
    }

    pub(crate) fn destination_at(
        &self,
        frame: &[u8],
        now: Instant,
    ) -> Result<EthernetDestination, L2FrameError> {
        let (vlan, destination, _) = ethernet_addresses(frame)?;
        Ok(self.destination_address_at(vlan, destination, now))
    }

    fn destination_address_at(
        &self,
        vlan: VlanStack,
        destination: MacAddress,
        now: Instant,
    ) -> EthernetDestination {
        if !is_unicast(destination) {
            return EthernetDestination::Flood;
        }

        let key = FdbKey {
            vlan,
            mac: destination,
        };
        let Some(entry) = self.fdb.get(&key) else {
            return EthernetDestination::Flood;
        };
        if now.saturating_duration_since(entry.last_seen) <= self.age {
            return EthernetDestination::Known(entry.peer_id);
        }
        drop(entry);
        let _maintenance = self.maintenance.lock().unwrap();
        if self
            .fdb
            .remove_if(&key, |_, entry| {
                if now.saturating_duration_since(entry.last_seen) <= self.age {
                    return false;
                }
                self.release_peer_entry(entry.peer_id);
                true
            })
            .is_some()
        {
            self.entry_count.fetch_sub(1, Ordering::AcqRel);
        }
        EthernetDestination::Flood
    }

    fn try_reserve_entry(&self) -> bool {
        self.entry_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.capacity).then_some(count + 1)
            })
            .is_ok()
    }

    fn allow_flood_at(&self, frame_len: usize, now: Instant) -> bool {
        if self.flood_bytes_per_second == 0 {
            return true;
        }
        self.flood
            .lock()
            .unwrap()
            .consume_at(frame_len, self.flood_bytes_per_second, now)
    }
}

fn ethernet_addresses(frame: &[u8]) -> Result<(VlanStack, MacAddress, MacAddress), L2FrameError> {
    let network = ethernet_network_metadata(frame).ok_or(L2FrameError::TooShort)?;
    let destination = frame
        .get(..6)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(L2FrameError::TooShort)?;
    let source = frame
        .get(6..12)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(L2FrameError::TooShort)?;
    Ok((network.vlan_stack, destination, source))
}

fn is_unicast(address: MacAddress) -> bool {
    address != [0; 6] && address != [0xff; 6] && address[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{EthernetDestination, L2DestinationBatch, L2Fabric, MAX_FANOUT_RECIPIENTS};

    fn frame(destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..6].copy_from_slice(&destination);
        bytes[6..12].copy_from_slice(&source);
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes
    }

    fn vlan_frame(vlan: u16, destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 68];
        bytes[..6].copy_from_slice(&destination);
        bytes[6..12].copy_from_slice(&source);
        bytes[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        bytes[14..16].copy_from_slice(&(vlan & 0x0fff).to_be_bytes());
        bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes
    }

    #[test]
    fn learns_unicast_sources_and_rejects_invalid_sources() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let source = [0x02, 0, 0, 0, 0, 1];

        fabric.learn_source_at(&frame([0xff; 6], source), 7, now);

        assert_eq!(
            fabric.destination_at(&frame(source, [0x02, 0, 0, 0, 0, 2]), now),
            Ok(EthernetDestination::Known(7))
        );
        assert_eq!(fabric.len(), 1);
        {
            let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
            let now = Instant::now();

            for source in [[0; 6], [0xff; 6], [0x01, 0, 0, 0, 0, 1]] {
                fabric.learn_source_at(&frame([0xff; 6], source), 7, now);
            }

            assert_eq!(fabric.len(), 0);
        }
    }

    #[test]
    fn batch_destination_uses_one_decision_for_repeated_mac_addresses() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let destination = [0x02, 0, 0, 0, 0, 9];
        let learned = frame([0xff; 6], destination);
        let outbound = frame(destination, [0x02, 0, 0, 0, 0, 1]);
        fabric.learn_source_at(&learned, 7, now);

        let mut batch = L2DestinationBatch::default();
        assert_eq!(
            batch.resolve_at(&fabric, &outbound, now),
            Ok(EthernetDestination::Known(7))
        );

        fabric.learn_source_at(&learned, 8, now);
        assert_eq!(
            batch.resolve_at(&fabric, &outbound, now),
            Ok(EthernetDestination::Known(7))
        );
        assert_eq!(
            L2DestinationBatch::default().resolve_at(&fabric, &outbound, now),
            Ok(EthernetDestination::Known(8))
        );
    }

    #[test]
    fn vlan_stack_is_part_of_the_forwarding_database_key() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let destination = [0x02, 0, 0, 0, 0, 9];
        let source = [0x02, 0, 0, 0, 0, 1];

        fabric.learn_source_at(&vlan_frame(7, [0xff; 6], destination), 7, now);
        fabric.learn_source_at(&vlan_frame(8, [0xff; 6], destination), 8, now);

        assert_eq!(
            fabric.destination_at(&vlan_frame(7, destination, source), now),
            Ok(EthernetDestination::Known(7))
        );
        assert_eq!(
            fabric.destination_at(&vlan_frame(8, destination, source), now),
            Ok(EthernetDestination::Known(8))
        );
    }

    #[test]
    fn fresh_fabric_does_not_reserve_the_configured_entry_limit() {
        let fabric = L2Fabric::new(16_384, Duration::from_secs(300), 1024);

        assert_eq!(fabric.fdb.capacity(), 0);

        fabric.learn_source(&frame([0xff; 6], [0x02, 0, 0, 0, 0, 1]), 7);
        assert_eq!(fabric.len(), 1);
        assert!(fabric.fdb.capacity() > 0);
    }

    #[test]
    fn floods_unknown_broadcast_and_multicast_destinations() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let source = [0x02, 0, 0, 0, 0, 2];

        for destination in [[0x02, 0, 0, 0, 0, 99], [0xff; 6], [0x01, 0, 0x5e, 0, 0, 1]] {
            assert_eq!(
                fabric.destination_at(&frame(destination, source), now),
                Ok(EthernetDestination::Flood)
            );
        }
    }

    #[test]
    fn mac_move_updates_the_origin_peer() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let source = [0x02, 0, 0, 0, 0, 1];
        let learned = frame([0xff; 6], source);

        fabric.learn_source_at(&learned, 7, now);
        fabric.learn_source_at(&learned, 8, now + Duration::from_secs(1));

        assert_eq!(
            fabric.destination_at(
                &frame(source, [0x02, 0, 0, 0, 0, 2]),
                now + Duration::from_secs(1)
            ),
            Ok(EthernetDestination::Known(8))
        );
    }

    #[test]
    fn capacity_and_expiry_release_forwarding_entries() {
        let fabric = L2Fabric::new(1, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let first = [0x02, 0, 0, 0, 0, 1];
        let second = [0x02, 0, 0, 0, 0, 2];

        fabric.learn_source_at(&frame([0xff; 6], first), 7, now);
        fabric.learn_source_at(&frame([0xff; 6], second), 8, now);

        assert_eq!(fabric.len(), 1);
        assert_eq!(
            fabric.destination_at(&frame(first, second), now),
            Ok(EthernetDestination::Known(7))
        );
        assert_eq!(
            fabric.destination_at(&frame(second, first), now),
            Ok(EthernetDestination::Flood)
        );
        // An unused destination must not retain table capacity after expiry.
        let later = now + Duration::from_secs(301);
        fabric.learn_source_at(&frame([0xff; 6], second), 8, later);
        assert_eq!(fabric.len(), 1);
        assert_eq!(
            fabric.destination_at(&frame(second, first), later),
            Ok(EthernetDestination::Known(8))
        );
        {
            let fabric = L2Fabric::new(16, Duration::from_secs(10), 1024);
            let now = Instant::now();
            let source = [0x02, 0, 0, 0, 0, 1];

            fabric.learn_source_at(&frame([0xff; 6], source), 7, now);

            assert_eq!(
                fabric.destination_at(
                    &frame(source, [0x02, 0, 0, 0, 0, 2]),
                    now + Duration::from_secs(11)
                ),
                Ok(EthernetDestination::Flood)
            );
            assert_eq!(fabric.len(), 0);
        }
    }

    #[test]
    fn bridge_policy_limits_sources_tags_and_reflected_frames() {
        let mut flags = crate::common::config::gen_default_flags();
        flags.l2_max_macs_per_peer = 1;
        flags.l2_mac_move_hold_seconds = 10;
        flags.l2_allowed_vlans = vec![0, 7];
        flags.l2_allowed_ether_types = vec![0x0800];
        let fabric = L2Fabric::with_policy(
            4,
            Duration::from_secs(20),
            0,
            super::L2Policy::from_flags(&flags),
        );
        let now = Instant::now();
        let mac_a = [2, 0, 0, 0, 0, 1];
        let mac_b = [2, 0, 0, 0, 0, 2];
        let original = frame([0xff; 6], mac_a);
        assert!(fabric.admit_source_at(&original, 7, now));
        assert!(!fabric.admit_source_at(&original, 8, now + Duration::from_secs(1)));
        assert!(!fabric.admit_source_at(&frame([0xff; 6], mac_b), 7, now));
        assert!(!fabric.admit_source_at(&vlan_frame(8, [0xff; 6], mac_b), 8, now));
        let mut wrong_type = frame([0xff; 6], mac_b);
        wrong_type[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert!(!fabric.admit_source_at(&wrong_type, 8, now));
        assert!(fabric.allows_compact_ip(&[0x45]));
        assert!(!fabric.allows_compact_ip(&[0x60]));
        let mut nested = vlan_frame(7, [0xff; 6], mac_b);
        nested.splice(16..16, [0x81, 0x00, 0, 8]);
        assert!(!fabric.admit_source_at(&nested, 8, now));
        assert!(fabric.admit_source_at(&original, 8, now + Duration::from_secs(11)));
        // Moving and forgetting an owner release its source allowance.
        assert!(fabric.admit_source_at(&frame([0xff; 6], mac_b), 7, now + Duration::from_secs(11)));
        fabric.forget_peer(7);
        assert!(fabric.admit_source_at(&frame([0xff; 6], mac_b), 7, now + Duration::from_secs(12)));
        let mac_c = [2, 0, 0, 0, 0, 3];
        assert!(fabric.admit_source_at(&frame([0xff; 6], mac_c), 7, now + Duration::from_secs(33)));
        assert_eq!(fabric.len(), 1);
        {
            let mut flags = crate::common::config::gen_default_flags();
            flags.l2_max_macs_per_peer = 8;
            flags.l2_fdb_capacity = 8;
            let fabric = L2Fabric::from_flags(&flags);
            std::thread::scope(|scope| {
                for n in 1..=32 {
                    let fabric = &fabric;
                    scope.spawn(move || {
                        fabric.learn_source(&frame([0xff; 6], [2, 0, 0, 0, 0, n]), 7)
                    });
                }
            });
            assert_eq!(fabric.len(), 8);
            assert_eq!(
                fabric
                    .per_peer_counts
                    .get(&7)
                    .unwrap()
                    .load(std::sync::atomic::Ordering::Acquire),
                8
            );
            fabric.forget_peer(7);
            assert_eq!(
                fabric
                    .per_peer_counts
                    .get(&7)
                    .unwrap()
                    .load(std::sync::atomic::Ordering::Acquire),
                0
            );
            fabric.learn_source(&frame([0xff; 6], [2, 0, 0, 0, 0, 33]), 8);
            assert_eq!(fabric.len(), 1);
        }
    }

    #[test]
    fn flood_budgets_refill_and_isolate_ingress_peers() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 100);
        let now = Instant::now();
        assert!(fabric.allow_flood_at(100, now + Duration::from_millis(999)));
        assert!(!fabric.allow_flood_at(100, now + Duration::from_millis(1001)));
        assert!(!fabric.allow_flood_at(1, now + Duration::from_millis(1001)));
        assert!(fabric.allow_flood_at(50, now + Duration::from_millis(1499)));
        assert!(!fabric.allow_flood_at(1, now + Duration::from_millis(1498)));
        assert!(fabric.allow_flood_at(100, now + Duration::from_millis(2499)));
        {
            let fabric = L2Fabric::new(16, Duration::from_secs(300), 0);

            assert!(fabric.allow_flood_at(usize::MAX, Instant::now()));
            assert!(fabric.allow_flood_at(usize::MAX, Instant::now()));
        }

        {
            let mut flags = crate::common::config::gen_default_flags();
            flags.l2_flood_bytes_per_second = 100;
            let fabric = L2Fabric::from_flags(&flags);
            let now = Instant::now();
            let frame_a = frame([0xff; 6], [2, 0, 0, 0, 0, 1]);
            assert!(fabric.admit_ingress_at(&frame_a, 7, 1, now));
            assert!(!fabric.admit_ingress_at(&frame_a, 7, 1, now));
            assert!(fabric.admit_ingress_at(&frame([0xff; 6], [2, 0, 0, 0, 0, 2]), 8, 1, now));
            let local_frame = frame([0xff; 6], [2, 0, 0, 0, 0, 3]);
            fabric.learn_source_at(&local_frame, 1, now);
            assert!(!fabric.admit_ingress_at(&local_frame, 7, 1, now + Duration::from_secs(4)));
            assert!(fabric.admit_ingress_at(&local_frame, 7, 1, now + Duration::from_secs(6)));
            assert_eq!(fabric.counters().ingress_flood_drops, 1);
            assert_eq!(fabric.counters().loop_drops, 1);
            let mut batch = super::L2IngressBatch::default();
            let moving = frame([0xff; 6], [2, 0, 0, 0, 0, 4]);
            assert!(fabric.admit_ingress_batch_at(&moving, 9, 1, now, &mut batch));
            fabric.forget_peer(9);
            assert!(fabric.admit_source_at(&moving, 1, now));
            assert!(!fabric.admit_ingress_batch_at(&moving, 9, 1, now, &mut batch));
            assert_eq!(fabric.counters().loop_drops, 2);
            let mut sources = super::L2SourceBatch::default();
            let local = frame([0xff; 6], [2, 0, 0, 0, 0, 5]);
            assert!(fabric.admit_source_batch_at(&local, 1, now, &mut sources));
            assert!(fabric.admit_source_batch_at(&local, 1, now, &mut sources));
            fabric.forget_peer(1);
            assert!(fabric.admit_source_at(&local, 9, now));
            assert!(!fabric.admit_source_batch_at(&local, 1, now, &mut sources));
            assert!(!fabric.allow_flood_output_bytes(101, 1));
            assert_eq!(fabric.snapshot().counters.flood_drops, 1);
        }
    }

    #[test]
    fn replicated_flood_accounts_for_all_outputs_before_cloning() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 100);

        assert!(fabric.allow_flood_replicated(25, 4));
        assert!(!fabric.allow_flood_replicated(25, 1));
    }

    #[test]
    fn replicated_flood_rejects_excessive_recipient_count() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 0);

        assert!(!fabric.allow_flood_replicated(1, MAX_FANOUT_RECIPIENTS + 1));
        assert!(fabric.allow_flood_replicated(1, MAX_FANOUT_RECIPIENTS));
    }

    #[test]
    fn malformed_frame_returns_error() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);

        assert!(fabric.destination(&[0; 13]).is_err());
    }
}
