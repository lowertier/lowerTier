use std::{
    hint::spin_loop,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
}

#[derive(Default)]
pub(crate) struct L2DestinationBatch {
    destinations: SmallVec<[(VlanStack, MacAddress, EthernetDestination); 4]>,
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

    pub(crate) fn record(&mut self, frame: &[u8], peer_id: PeerId) {
        let Ok((vlan, _, source)) = ethernet_addresses(frame) else {
            return;
        };
        self.record_source(vlan, source, peer_id);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sources.len()
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
    capacity: usize,
    age: Duration,
    flood_bps: u64,
    flood_epoch: AtomicU64,
    flood_bytes: AtomicU64,
}

/// Keep one packet fanout within the maximum peer set accepted by route sync.
pub const MAX_FANOUT_RECIPIENTS: usize = 4_096;

impl L2Fabric {
    const FLOOD_EPOCH_RESETTING: u64 = 1 << 63;

    pub fn new(capacity: usize, age: Duration, flood_bps: u64) -> Self {
        Self {
            fdb: DashMap::new(),
            entry_count: AtomicUsize::new(0),
            capacity,
            age,
            flood_bps,
            flood_epoch: AtomicU64::new(0),
            flood_bytes: AtomicU64::new(0),
        }
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
        if recipient_count > MAX_FANOUT_RECIPIENTS {
            return false;
        }
        self.allow_flood_bytes(output_bytes)
    }

    fn allow_flood_bytes(&self, frame_len: usize) -> bool {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.allow_flood_at(frame_len, epoch)
    }

    pub fn forget_peer(&self, peer_id: PeerId) {
        let keys = self
            .fdb
            .iter()
            .filter_map(|entry| (entry.peer_id == peer_id).then_some(*entry.key()))
            .collect::<Vec<_>>();
        for key in keys {
            if self
                .fdb
                .remove_if(&key, |_, entry| entry.peer_id == peer_id)
                .is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    pub fn clear(&self) {
        let keys = self
            .fdb
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for key in keys {
            if self.fdb.remove(&key).is_some() {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
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

    pub(crate) fn learn_source_batch_at(&self, batch: L2SourceBatch, now: Instant) {
        for (vlan, source, peer_id) in batch.sources {
            self.learn_address_at(vlan, source, peer_id, now);
        }
    }

    fn learn_address_at(&self, vlan: VlanStack, source: MacAddress, peer_id: PeerId, now: Instant) {
        match self.fdb.entry(FdbKey { vlan, mac: source }) {
            Entry::Occupied(mut occupied) => {
                *occupied.get_mut() = FdbEntry {
                    peer_id,
                    last_seen: now,
                };
            }
            Entry::Vacant(vacant) => {
                if self.try_reserve_entry() {
                    vacant.insert(FdbEntry {
                        peer_id,
                        last_seen: now,
                    });
                }
            }
        }
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

        if self
            .fdb
            .remove_if(&key, |_, entry| {
                now.saturating_duration_since(entry.last_seen) > self.age
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

    fn allow_flood_at(&self, frame_len: usize, epoch: u64) -> bool {
        if self.flood_bps == 0 {
            return true;
        }

        let epoch = epoch & !Self::FLOOD_EPOCH_RESETTING;
        loop {
            let observed = self.flood_epoch.load(Ordering::Acquire);
            if observed & Self::FLOOD_EPOCH_RESETTING != 0 {
                spin_loop();
                continue;
            }
            if observed != epoch {
                if self
                    .flood_epoch
                    .compare_exchange(
                        observed,
                        epoch | Self::FLOOD_EPOCH_RESETTING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.flood_bytes.store(0, Ordering::Release);
                    self.flood_epoch.store(epoch, Ordering::Release);
                }
                continue;
            }

            let frame_len = u64::try_from(frame_len).unwrap_or(u64::MAX);
            return self
                .flood_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(frame_len)
                        .filter(|next| *next <= self.flood_bps)
                })
                .is_ok();
        }
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

    use super::{
        EthernetDestination, L2DestinationBatch, L2Fabric, L2SourceBatch, MAX_FANOUT_RECIPIENTS,
    };

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
    fn learns_unicast_source_and_resolves_destination() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let source = [0x02, 0, 0, 0, 0, 1];

        fabric.learn_source_at(&frame([0xff; 6], source), 7, now);

        assert_eq!(
            fabric.destination_at(&frame(source, [0x02, 0, 0, 0, 0, 2]), now),
            Ok(EthernetDestination::Known(7))
        );
        assert_eq!(fabric.len(), 1);
    }

    #[test]
    fn batch_learning_writes_each_source_once_with_the_latest_peer() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();
        let source = [0x02, 0, 0, 0, 0, 9];
        let learned = frame([0xff; 6], source);
        let mut sources = L2SourceBatch::default();

        sources.record(&learned, 7);
        sources.record(&learned, 8);
        assert_eq!(sources.len(), 1);
        fabric.learn_source_batch_at(sources, now);

        assert_eq!(
            fabric.destination_at(&frame(source, [0x02, 0, 0, 0, 0, 1]), now),
            Ok(EthernetDestination::Known(8))
        );
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
    fn rejects_non_unicast_source_addresses() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 1024);
        let now = Instant::now();

        for source in [[0; 6], [0xff; 6], [0x01, 0, 0, 0, 0, 1]] {
            fabric.learn_source_at(&frame([0xff; 6], source), 7, now);
        }

        assert_eq!(fabric.len(), 0);
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
    fn expired_entry_is_removed_during_lookup() {
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

    #[test]
    fn capacity_rejects_a_new_mac_without_replacing_fresh_entry() {
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
    }

    #[test]
    fn flood_budget_resets_at_the_next_second() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 100);

        assert!(fabric.allow_flood_at(60, 10));
        assert!(!fabric.allow_flood_at(60, 10));
        assert!(fabric.allow_flood_at(60, 11));
    }

    #[test]
    fn zero_flood_budget_is_unlimited() {
        let fabric = L2Fabric::new(16, Duration::from_secs(300), 0);

        assert!(fabric.allow_flood_at(usize::MAX, 10));
        assert!(fabric.allow_flood_at(usize::MAX, 10));
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
