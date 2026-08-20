use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};

use dashmap::{DashMap, mapref::entry::Entry};
use smallvec::SmallVec;

use crate::{
    common::PeerId,
    tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket, ethernet_network_metadata},
    },
};

pub(crate) const FLOW_SHARD_COUNT: u16 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketFlow {
    pub(crate) hash: u64,
    pub(crate) shard: u16,
}

#[derive(Default)]
struct StableFlowHasher(u64);

impl StableFlowHasher {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
}

impl Hasher for StableFlowHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

fn canonical_endpoints(
    hasher: &mut StableFlowHasher,
    source: [u8; 16],
    source_port: u16,
    destination: [u8; 16],
    destination_port: u16,
) {
    let source = (source, source_port);
    let destination = (destination, destination_port);
    let (first, second) = if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    };
    hasher.write(&first.0);
    hasher.write(&first.1.to_be_bytes());
    hasher.write(&second.0);
    hasher.write(&second.1.to_be_bytes());
}

fn transport_ports(protocol: u8, payload: &[u8]) -> (u16, u16) {
    if matches!(protocol, 6 | 17 | 132) && payload.len() >= 4 {
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        )
    } else {
        (0, 0)
    }
}

fn hash_ipv4(hasher: &mut StableFlowHasher, packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return false;
    }
    let protocol = packet[9];
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let is_fragment = fragment & 0x3fff != 0;
    let (source_port, destination_port) = if is_fragment {
        (0, 0)
    } else {
        transport_ports(protocol, &packet[header_len..])
    };
    let mut source = [0_u8; 16];
    let mut destination = [0_u8; 16];
    source[12..].copy_from_slice(&packet[12..16]);
    destination[12..].copy_from_slice(&packet[16..20]);
    hasher.write_u8(4);
    hasher.write_u8(protocol);
    canonical_endpoints(hasher, source, source_port, destination, destination_port);
    if is_fragment {
        hasher.write(&packet[4..6]);
    }
    true
}

fn hash_ipv6(hasher: &mut StableFlowHasher, packet: &[u8]) -> bool {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return false;
    }
    let mut next_header = packet[6];
    let mut offset = 40;
    let mut fragment_id = None;
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                if packet.len() < offset + 2 {
                    return false;
                }
                next_header = packet[offset];
                offset += (usize::from(packet[offset + 1]) + 1) * 8;
            }
            44 => {
                if packet.len() < offset + 8 {
                    return false;
                }
                next_header = packet[offset];
                fragment_id = Some([
                    packet[offset + 4],
                    packet[offset + 5],
                    packet[offset + 6],
                    packet[offset + 7],
                ]);
                offset += 8;
                break;
            }
            51 => {
                if packet.len() < offset + 2 {
                    return false;
                }
                next_header = packet[offset];
                offset += (usize::from(packet[offset + 1]) + 2) * 4;
            }
            _ => break,
        }
        if offset > packet.len() {
            return false;
        }
    }
    if offset > packet.len() {
        return false;
    }
    let (source_port, destination_port) = if fragment_id.is_some() {
        (0, 0)
    } else {
        transport_ports(next_header, &packet[offset..])
    };
    let mut source = [0_u8; 16];
    let mut destination = [0_u8; 16];
    source.copy_from_slice(&packet[8..24]);
    destination.copy_from_slice(&packet[24..40]);
    hasher.write_u8(6);
    hasher.write_u8(next_header);
    canonical_endpoints(hasher, source, source_port, destination, destination_port);
    if let Some(fragment_id) = fragment_id {
        hasher.write(&fragment_id);
    }
    true
}

fn hash_ethernet(hasher: &mut StableFlowHasher, frame: &[u8]) -> bool {
    if frame.len() < 14 {
        return false;
    }
    let (first_mac, second_mac) = if frame[..6] <= frame[6..12] {
        (&frame[..6], &frame[6..12])
    } else {
        (&frame[6..12], &frame[..6])
    };
    let Some(network) = ethernet_network_metadata(frame) else {
        return false;
    };
    hasher.write(first_mac);
    hasher.write(second_mac);
    for vlan in network.vlan_stack.as_slice() {
        hasher.write_u16(*vlan);
    }
    hasher.write_u16(network.ether_type);
    match network.ether_type {
        0x0800 => hash_ipv4(hasher, &frame[network.payload_offset..]),
        0x86dd => hash_ipv6(hasher, &frame[network.payload_offset..]),
        _ => true,
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    let network = ethernet_network_metadata(frame)?;
    Some((network.ether_type, frame.get(network.payload_offset..)?))
}

fn udp_ports_are(payload: &[u8], first: u16, second: u16) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let source = u16::from_be_bytes([payload[0], payload[1]]);
    let destination = u16::from_be_bytes([payload[2], payload[3]]);
    (source == first && destination == second) || (source == second && destination == first)
}

fn transport_port_is(payload: &[u8], expected: u16) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let source = u16::from_be_bytes([payload[0], payload[1]]);
    let destination = u16::from_be_bytes([payload[2], payload[3]]);
    source == expected || destination == expected
}

fn transport_port_is_bfd(payload: &[u8]) -> bool {
    [3784, 3785, 4784]
        .into_iter()
        .any(|port| transport_port_is(payload, port))
}

fn high_priority_dscp(dscp: u8) -> bool {
    dscp >= 48
}

fn critical_transport_control(protocol: u8, payload: &[u8]) -> bool {
    match protocol {
        1 | 58 | 89 => true,
        6 => transport_port_is(payload, 179),
        17 => transport_port_is_bfd(payload),
        _ => false,
    }
}

fn critical_ipv4_control(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return false;
    }
    if high_priority_dscp(packet[1] >> 2) {
        return true;
    }
    let protocol = packet[9];
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let payload = if fragment & 0x1fff == 0 {
        &packet[header_len..]
    } else {
        &[]
    };
    critical_transport_control(protocol, payload)
        || (protocol == 17 && udp_ports_are(payload, 67, 68))
}

fn ipv6_upper_layer(mut packet: &[u8]) -> Option<(u8, &[u8])> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let mut next_header = packet[6];
    packet = &packet[40..];
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                if packet.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(packet[1]) + 1) * 8;
                if packet.len() < header_len {
                    return None;
                }
                next_header = packet[0];
                packet = &packet[header_len..];
            }
            44 => {
                if packet.len() < 8 {
                    return None;
                }
                let fragment = u16::from_be_bytes([packet[2], packet[3]]);
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                next_header = packet[0];
                packet = &packet[8..];
            }
            51 => {
                if packet.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(packet[1]) + 2) * 4;
                if packet.len() < header_len {
                    return None;
                }
                next_header = packet[0];
                packet = &packet[header_len..];
            }
            _ => return Some((next_header, packet)),
        }
    }
    None
}

fn critical_ipv6_control(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    if high_priority_dscp(traffic_class >> 2) {
        return true;
    }
    let Some((next_header, payload)) = ipv6_upper_layer(packet) else {
        return false;
    };
    critical_transport_control(next_header, payload)
        || (next_header == 17 && udp_ports_are(payload, 546, 547))
}

pub(crate) fn is_critical_l2_control(frame: &[u8]) -> bool {
    let Some((ether_type, payload)) = ethernet_payload(frame) else {
        return false;
    };
    match ether_type {
        0x0806 => true,
        0x0800 => critical_ipv4_control(payload),
        0x86dd => critical_ipv6_control(payload),
        _ => false,
    }
}

pub(crate) fn is_critical_l3_control(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => critical_ipv4_control(packet),
        Some(6) => critical_ipv6_control(packet),
        _ => false,
    }
}

pub(crate) fn stamp_critical_control(packet: &mut ZCPacket) -> bool {
    let Some(header) = packet.peer_manager_header() else {
        return false;
    };
    if header.is_critical_l2_control() {
        return true;
    }
    if header.is_encrypted() {
        return false;
    }

    let critical = match header.packet_type {
        packet_type if packet_type == PacketType::Ethernet as u8 => {
            is_critical_l2_control(packet.payload())
        }
        packet_type if packet_type == PacketType::Data as u8 => {
            is_critical_l3_control(packet.payload())
        }
        _ => false,
    };
    if critical && let Some(header) = packet.mut_peer_manager_header() {
        header.set_critical_l2_control(true);
    }
    critical
}

pub(crate) fn stamp_critical_l2_control(packet: &mut ZCPacket) -> bool {
    stamp_critical_control(packet)
}

pub(crate) fn classify_packet_flow(packet: &ZCPacket) -> PacketFlow {
    if let Some(hash) = packet.flow_hash() {
        return PacketFlow {
            hash,
            shard: (hash % u64::from(FLOW_SHARD_COUNT)) as u16,
        };
    }
    if let Some(shard) = packet
        .peer_manager_header()
        .and_then(|header| header.flow_shard())
    {
        return PacketFlow {
            hash: u64::from(shard),
            shard,
        };
    }
    let mut hasher = StableFlowHasher::new();
    let packet_type = packet
        .peer_manager_header()
        .map(|header| header.packet_type)
        .unwrap_or(PacketType::Data as u8);
    hasher.write_u8(packet_type);
    let payload = packet.payload();
    let parsed = if packet_type == PacketType::Ethernet as u8 {
        hash_ethernet(&mut hasher, payload)
    } else {
        match payload.first().map(|byte| byte >> 4) {
            Some(4) => hash_ipv4(&mut hasher, payload),
            Some(6) => hash_ipv6(&mut hasher, payload),
            _ => false,
        }
    };
    if !parsed {
        hasher.write(&payload[..payload.len().min(64)]);
    }
    let hash = hasher.finish();
    PacketFlow {
        hash,
        shard: (hash % u64::from(FLOW_SHARD_COUNT)) as u16,
    }
}

/// Records the flow shard in the peer header while the cleartext L2/L3 tuple
/// is still available. The reserved header byte carries the shard across
/// encryption and relay hops without adding wire overhead.
pub(crate) fn stamp_packet_flow(packet: &mut ZCPacket) -> PacketFlow {
    let flow = classify_packet_flow(packet);
    if packet.flow_hash().is_none() {
        packet.set_flow_hash(flow.hash);
    }
    let encrypted = packet
        .peer_manager_header()
        .is_some_and(|header| header.is_encrypted());
    if !encrypted
        && packet
            .peer_manager_header()
            .and_then(|header| header.flow_shard())
            != Some(flow.shard)
        && let Some(header) = packet.mut_peer_manager_header()
    {
        header.set_flow_shard(flow.shard);
    }
    flow
}

/// Splits a bounded vector into stable per-shard vectors without copying any
/// packet backing buffers. First-seen shard order and packet order within a
/// shard are both retained.
pub(crate) fn split_packet_batch_by_flow_shard(
    batch: PacketBatch,
) -> SmallVec<[(PacketFlow, PacketBatch); 4]> {
    let mut groups = SmallVec::<[(PacketFlow, PacketBatch); 4]>::new();
    for mut packet in batch {
        let flow = stamp_packet_flow(&mut packet);
        if let Some((existing, group)) = groups.last_mut()
            && existing.shard == flow.shard
        {
            group
                .try_push(packet)
                .expect("a contiguous shard group cannot exceed its source vector");
            continue;
        }
        let mut group = PacketBatch::with_capacity(1);
        group
            .try_push(packet)
            .expect("a new shard group accepts its first packet");
        groups.push((flow, group));
    }
    groups
}

/// Partitions packets by their complete flow hash before path selection.
/// The first-seen flow order stays stable and each packet keeps its backing buffer.
pub(crate) fn partition_packet_batch_by_flow(
    batch: PacketBatch,
) -> SmallVec<[(PacketFlow, PacketBatch); 4]> {
    type FlowGroupKey = (u64, u8, u8, u8);
    let mut groups = SmallVec::<[(FlowGroupKey, PacketFlow, PacketBatch); 4]>::new();
    let mut indexes = None::<HashMap<FlowGroupKey, usize>>;
    for mut packet in batch {
        let flow = stamp_packet_flow(&mut packet);
        let (packet_type, policy_bits, flags) = packet
            .peer_manager_header()
            .map(|header| {
                (
                    header.packet_type,
                    u8::from(header.is_speed_first())
                        | (u8::from(header.is_latency_first()) << 1)
                        | (u8::from(header.is_critical_l2_control()) << 2),
                    header.flags,
                )
            })
            .unwrap_or((0, 0, 0));
        let key = (flow.hash, packet_type, policy_bits, flags);
        let existing_index = indexes
            .as_ref()
            .and_then(|map| map.get(&key).copied())
            .or_else(|| {
                indexes
                    .is_none()
                    .then(|| {
                        groups
                            .iter()
                            .position(|(group_key, _, _)| *group_key == key)
                    })
                    .flatten()
            });
        if let Some(index) = existing_index {
            groups[index]
                .2
                .try_push(packet)
                .expect("a flow group cannot exceed its source vector");
            continue;
        }
        if indexes.is_none() && groups.len() == 4 {
            indexes = Some(
                groups
                    .iter()
                    .enumerate()
                    .map(|(index, (group_key, _, _))| (*group_key, index))
                    .collect(),
            );
        }
        let mut group = PacketBatch::with_capacity(1);
        group
            .try_push(packet)
            .expect("a new flow group accepts its first packet");
        if let Some(indexes) = indexes.as_mut() {
            indexes.insert(key, groups.len());
        }
        groups.push((key, flow, group));
    }
    groups
        .into_iter()
        .map(|(_, flow, group)| (flow, group))
        .collect()
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowPathKey {
    destination: PeerId,
    flow: u64,
}

#[derive(Clone, Copy)]
struct PinnedPath<P> {
    path: P,
    created_at: Instant,
    route_generation: u64,
}

pub(crate) struct FlowPathCache<P = PeerId> {
    entries: DashMap<FlowPathKey, PinnedPath<P>>,
    capacity: usize,
    ttl: Duration,
}

impl<P> FlowPathCache<P>
where
    P: Copy + Eq + Send + Sync,
{
    pub(crate) fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0);
        Self {
            entries: DashMap::with_capacity(capacity.min(1024)),
            capacity,
            ttl,
        }
    }

    pub(crate) fn select<F>(&self, destination: PeerId, flow: u64, candidate: P, eligible: F) -> P
    where
        F: Fn(P) -> bool,
    {
        self.select_at_generation(destination, flow, candidate, 0, eligible)
    }

    pub(crate) fn select_at_generation<F>(
        &self,
        destination: PeerId,
        flow: u64,
        candidate: P,
        route_generation: u64,
        eligible: F,
    ) -> P
    where
        F: Fn(P) -> bool,
    {
        self.select_with_candidate(
            destination,
            flow,
            route_generation,
            Some(candidate),
            || Some(candidate),
            eligible,
        )
        .expect("the fixed candidate exists")
    }

    pub(crate) fn select_with_candidate<F, C>(
        &self,
        destination: PeerId,
        flow: u64,
        route_generation: u64,
        current_candidate: Option<P>,
        candidate: C,
        eligible: F,
    ) -> Option<P>
    where
        F: Fn(P) -> bool,
        C: FnOnce() -> Option<P>,
    {
        let key = FlowPathKey { destination, flow };
        let now = Instant::now();
        let mut candidate = Some(candidate);
        loop {
            match self.entries.entry(key) {
                Entry::Occupied(mut occupied) => {
                    let pinned = *occupied.get();
                    let route_unchanged = pinned.route_generation == route_generation
                        || current_candidate.is_some_and(|path| path == pinned.path);
                    if now.duration_since(pinned.created_at) <= self.ttl
                        && route_unchanged
                        && eligible(pinned.path)
                    {
                        return Some(pinned.path);
                    }
                    let path = (candidate.take()?)()?;
                    occupied.insert(PinnedPath {
                        path,
                        created_at: now,
                        route_generation,
                    });
                    return Some(path);
                }
                Entry::Vacant(vacant) => {
                    drop(vacant);
                    if self.entries.len() >= self.capacity {
                        self.prune(now);
                        continue;
                    }
                    let path = (candidate.take()?)()?;
                    match self.entries.entry(key) {
                        Entry::Occupied(occupied) => return Some(occupied.get().path),
                        Entry::Vacant(vacant) => {
                            vacant.insert(PinnedPath {
                                path,
                                created_at: now,
                                route_generation,
                            });
                            return Some(path);
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn lookup<F>(&self, destination: PeerId, flow: u64, eligible: F) -> Option<P>
    where
        F: Fn(P) -> bool,
    {
        self.lookup_at_generation(destination, flow, 0, None, eligible)
    }

    pub(crate) fn lookup_at_generation<F>(
        &self,
        destination: PeerId,
        flow: u64,
        route_generation: u64,
        current_candidate: Option<P>,
        eligible: F,
    ) -> Option<P>
    where
        F: Fn(P) -> bool,
    {
        self.lookup_key(
            FlowPathKey { destination, flow },
            Instant::now(),
            route_generation,
            current_candidate,
            &eligible,
        )
    }

    fn lookup_key<F>(
        &self,
        key: FlowPathKey,
        now: Instant,
        route_generation: u64,
        current_candidate: Option<P>,
        eligible: &F,
    ) -> Option<P>
    where
        F: Fn(P) -> bool,
    {
        if let Entry::Occupied(occupied) = self.entries.entry(key) {
            let pinned = *occupied.get();
            let route_unchanged = pinned.route_generation == route_generation
                || current_candidate.is_some_and(|candidate| candidate == pinned.path);
            if now.duration_since(pinned.created_at) <= self.ttl
                && route_unchanged
                && eligible(pinned.path)
            {
                return Some(pinned.path);
            }
            occupied.remove();
        }
        None
    }

    pub(crate) fn invalidate_path(&self, path: P) {
        self.entries.retain(|_, pinned| pinned.path != path);
        self.entries.shrink_to_fit();
    }

    fn prune(&self, now: Instant) {
        self.entries
            .retain(|_, pinned| now.duration_since(pinned.created_at) <= self.ttl);
        if self.entries.len() < self.capacity {
            return;
        }
        let remove_count = self.entries.len() - self.capacity.saturating_mul(3) / 4;
        let keys = self
            .entries
            .iter()
            .take(remove_count.max(1))
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for key in keys {
            self.entries.remove(&key);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use crate::tunnel::packet_def::{PacketType, ZCPacket};

    use super::{
        FlowPathCache, classify_packet_flow, is_critical_l2_control, is_critical_l3_control,
        partition_packet_batch_by_flow, split_packet_batch_by_flow_shard, stamp_critical_control,
        stamp_critical_l2_control, stamp_packet_flow,
    };

    fn ipv4_transport(protocol: u8, source_port: u16, destination_port: u16, dscp: u8) -> ZCPacket {
        let mut ip = vec![0_u8; 20 + 8];
        ip[0] = 0x45;
        ip[1] = dscp << 2;
        ip[2..4].copy_from_slice(&(28_u16).to_be_bytes());
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        ip[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        ip[20..22].copy_from_slice(&source_port.to_be_bytes());
        ip[22..24].copy_from_slice(&destination_port.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload(&ip);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn ethernet_ipv4_udp(
        source: Ipv4Addr,
        source_port: u16,
        destination: Ipv4Addr,
        destination_port: u16,
    ) -> ZCPacket {
        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(28_u16).to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&source.octets());
        ip[16..20].copy_from_slice(&destination.octets());
        ip[20..22].copy_from_slice(&source_port.to_be_bytes());
        ip[22..24].copy_from_slice(&destination_port.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload(&frame);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
        packet
    }

    #[test]
    fn reverse_ipv4_five_tuple_uses_the_same_flow_shard() {
        let a = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let b = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 2),
            443,
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
        );

        let a_flow = classify_packet_flow(&a);
        let b_flow = classify_packet_flow(&b);

        assert_eq!(a_flow.hash, b_flow.hash);
        assert_eq!(a_flow.shard, b_flow.shard);
    }

    #[test]
    fn stamped_flow_survives_local_payload_encryption() {
        let mut packet = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let stamped = stamp_packet_flow(&mut packet);
        packet.mut_payload_preserving_flow_hash().fill(0xa5);

        let relayed = classify_packet_flow(&packet);

        assert_eq!(relayed.shard, stamped.shard);
        assert_eq!(relayed.hash, stamped.hash);
    }

    #[test]
    fn encrypted_packet_without_flow_shard_preserves_authenticated_header() {
        let mut packet = ZCPacket::new_with_payload(b"ciphertext");
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        let before = packet.peer_manager_header().unwrap().stable_auth_data();

        let flow = stamp_packet_flow(&mut packet);

        let header = packet.peer_manager_header().unwrap();
        assert_eq!(header.flow_shard(), None);
        assert_eq!(header.stable_auth_data(), before);
        assert_eq!(packet.flow_hash(), Some(flow.hash));
    }

    #[test]
    fn encrypted_ethernet_does_not_reclassify_critical_control() {
        let mut arp = vec![0_u8; 14 + 28];
        arp[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        let mut packet = ZCPacket::new_with_payload(&arp);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Ethernet as u8);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        let before = packet.peer_manager_header().unwrap().stable_auth_data();

        assert!(!stamp_critical_l2_control(&mut packet));

        let header = packet.peer_manager_header().unwrap();
        assert!(!header.is_critical_l2_control());
        assert_eq!(header.stable_auth_data(), before);
    }

    #[test]
    fn payload_mutation_invalidates_the_cached_flow_hash() {
        let mut packet = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let original = stamp_packet_flow(&mut packet);

        packet.mut_payload()[14 + 12] ^= 1;

        assert_eq!(packet.flow_hash(), None);
        let updated = stamp_packet_flow(&mut packet);
        assert_ne!(updated.hash, original.hash);
    }

    #[test]
    fn inner_mutation_invalidates_the_cached_flow_hash() {
        let mut packet = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        stamp_packet_flow(&mut packet);
        let payload_offset = packet.payload_offset();
        let byte = packet
            .mut_inner()
            .get_mut(payload_offset + 14 + 12)
            .unwrap();
        *byte = (*byte).wrapping_add(1);

        assert_eq!(packet.flow_hash(), None);
    }

    #[test]
    fn mixed_vector_keeps_order_across_contiguous_flow_shard_runs() {
        let first = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let second = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 3),
            2200,
            Ipv4Addr::new(10, 0, 0, 4),
            443,
        );
        let third = first.clone();
        let first_ptr = first.payload().as_ptr();
        let third_ptr = third.payload().as_ptr();
        let mut batch = crate::tunnel::batch::PacketBatch::new();
        batch.try_push(first).unwrap();
        batch.try_push(second).unwrap();
        batch.try_push(third).unwrap();

        let groups = split_packet_batch_by_flow_shard(batch);

        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].1.len(), 1);
        assert_eq!(groups[2].1.len(), 1);
        assert_eq!(
            groups[0].1.iter().next().unwrap().payload().as_ptr(),
            first_ptr
        );
        assert_eq!(
            groups[2].1.iter().next().unwrap().payload().as_ptr(),
            third_ptr
        );
    }

    #[test]
    fn flow_partition_regroups_noncontiguous_packets_before_path_selection() {
        let first = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let second = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 3),
            2200,
            Ipv4Addr::new(10, 0, 0, 4),
            443,
        );
        let third = first.clone();
        let mut batch = crate::tunnel::batch::PacketBatch::new();
        batch.try_push(first).unwrap();
        batch.try_push(second).unwrap();
        batch.try_push(third).unwrap();

        let groups = partition_packet_batch_by_flow(batch);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn flow_partition_separates_route_flags_and_keeps_first_seen_order() {
        let mut plain = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let mut exit = plain.clone();
        let mut compressed = plain.clone();
        plain.set_flow_hash(77);
        exit.set_flow_hash(77);
        compressed.set_flow_hash(77);
        exit.mut_peer_manager_header().unwrap().set_exit_node(true);
        compressed
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(true);

        let mut batch = crate::tunnel::batch::PacketBatch::new();
        batch.try_push(plain.clone()).unwrap();
        batch.try_push(exit).unwrap();
        batch.try_push(compressed).unwrap();
        batch.try_push(plain).unwrap();

        let groups = partition_packet_batch_by_flow(batch);

        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].1.len(), 1);
        assert_eq!(groups[2].1.len(), 1);
        assert!(
            !groups[0]
                .1
                .first()
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .is_exit_node()
        );
        assert!(
            !groups[0]
                .1
                .iter()
                .nth(1)
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .is_exit_node()
        );
        assert!(
            groups[1]
                .1
                .first()
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .is_exit_node()
        );
        assert!(
            groups[2]
                .1
                .first()
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .is_compressed()
        );
    }

    #[test]
    fn flow_partition_separates_colliding_shards_and_policies() {
        let first = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let first_flow = classify_packet_flow(&first);
        let (mut second, second_flow) = (1001..20_000)
            .map(|source_port| {
                let packet = ethernet_ipv4_udp(
                    Ipv4Addr::new(10, 0, 0, 3),
                    source_port,
                    Ipv4Addr::new(10, 0, 0, 4),
                    443,
                );
                let flow = classify_packet_flow(&packet);
                (packet, flow)
            })
            .find(|(_, flow)| flow.shard == first_flow.shard && flow.hash != first_flow.hash)
            .expect("the flow hash must produce a shard collision in the search range");

        let mut first = first;
        first
            .mut_peer_manager_header()
            .unwrap()
            .set_speed_first(true);
        second
            .mut_peer_manager_header()
            .unwrap()
            .set_latency_first(true);

        let mut batch = crate::tunnel::batch::PacketBatch::new();
        batch.try_push(first).unwrap();
        batch.try_push(second).unwrap();

        let groups = partition_packet_batch_by_flow(batch);

        assert_eq!(first_flow.shard, second_flow.shard);
        assert_ne!(first_flow.hash, second_flow.hash);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn flow_partition_separates_packet_types_with_the_same_flow_hash() {
        let mut ethernet = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let mut data = ethernet.clone();
        data.mut_peer_manager_header().unwrap().packet_type = PacketType::Data as u8;
        ethernet.set_flow_hash(17);
        data.set_flow_hash(17);

        let mut batch = crate::tunnel::batch::PacketBatch::new();
        batch.try_push(ethernet).unwrap();
        batch.try_push(data).unwrap();

        let groups = partition_packet_batch_by_flow(batch);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn path_pin_survives_route_jitter_then_invalidates_on_failure() {
        let cache = FlowPathCache::new(8, Duration::from_secs(60));
        let flow = 0x1234;

        assert_eq!(cache.select(7, flow, 11, |_| true), 11);
        assert_eq!(cache.select(7, flow, 12, |_| true), 11);

        cache.invalidate_path(11);
        assert_eq!(cache.select(7, flow, 12, |_| true), 12);
    }

    #[test]
    fn path_lookup_returns_a_live_pin_without_a_new_candidate() {
        let cache = FlowPathCache::new(8, Duration::from_secs(60));
        let flow = 0x2345;

        assert_eq!(cache.select(7, flow, 11, |_| true), 11);
        assert_eq!(cache.lookup(7, flow, |path| path == 11), Some(11));
        assert_eq!(cache.lookup(7, flow, |_| false), None);
    }

    #[test]
    fn path_cache_can_pin_connection_identifiers() {
        let cache: FlowPathCache<uuid::Uuid> = FlowPathCache::new(8, Duration::from_secs(60));
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);

        assert_eq!(cache.select(7, 0x3456, first, |_| true), first);
        assert_eq!(cache.select(7, 0x3456, second, |_| true), first);

        cache.invalidate_path(first);
        assert_eq!(cache.select(7, 0x3456, second, |_| true), second);
    }

    #[test]
    fn path_pin_generation_changes_only_when_destination_route_changes() {
        let cache = FlowPathCache::new(8, Duration::from_secs(60));
        let flow = 0x789a;

        assert_eq!(cache.select_at_generation(7, flow, 11, 1, |_| true), 11);
        // A rebuild that keeps the same destination next hop keeps the pin.
        assert_eq!(
            cache.lookup_at_generation(7, flow, 2, Some(11), |_| true),
            Some(11)
        );
        // A rebuild that changes the destination next hop removes the old pin.
        assert_eq!(
            cache.lookup_at_generation(7, flow, 3, Some(12), |_| true),
            None
        );
        assert_eq!(cache.select_at_generation(7, flow, 12, 3, |_| true), 12);
    }

    #[test]
    fn denied_or_dead_pinned_path_is_never_reused() {
        let cache = FlowPathCache::new(8, Duration::from_secs(60));
        let flow = 0x5678;

        assert_eq!(cache.select(9, flow, 21, |_| true), 21);
        assert_eq!(cache.select(9, flow, 22, |path| path != 21), 22);
    }

    #[test]
    fn concurrent_first_packets_select_one_path() {
        let cache = std::sync::Arc::new(FlowPathCache::new(8, Duration::from_secs(60)));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = [31_u32, 32_u32].map(|candidate| {
            let cache = cache.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                cache.select_with_candidate(12, 0x9911, 1, None, || Some(candidate), |_| true)
            })
        });
        barrier.wait();
        let mut selected = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        selected.sort_unstable();
        assert_eq!(selected[0], selected[1]);
    }

    #[test]
    fn classifies_arp_dhcp_and_neighbor_discovery_as_critical_l2() {
        let mut arp = vec![0_u8; 14 + 28];
        arp[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert!(is_critical_l2_control(&arp));

        let dhcp = ethernet_ipv4_udp(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67);
        assert!(is_critical_l2_control(dhcp.payload()));

        let mut nd = vec![0_u8; 14 + 40 + 24];
        nd[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        nd[14] = 0x60;
        nd[14 + 6] = 58;
        nd[14 + 40] = 135;
        assert!(is_critical_l2_control(&nd));

        let ordinary = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        assert!(!is_critical_l2_control(ordinary.payload()));
        assert!(!is_critical_l2_control(&[0_u8; 13]));
    }

    #[test]
    fn critical_classifier_follows_vlan_and_ipv6_extension_headers() {
        let mut vlan_arp = vec![0_u8; 18 + 28];
        vlan_arp[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        vlan_arp[16..18].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert!(is_critical_l2_control(&vlan_arp));

        let mut nd = vec![0_u8; 14 + 48 + 24];
        nd[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        nd[14] = 0x60;
        nd[14 + 6] = 0;
        nd[14 + 40] = 58;
        nd[14 + 41] = 0;
        nd[14 + 48] = 136;
        assert!(is_critical_l2_control(&nd));
    }

    #[test]
    fn classifies_routing_protocols_and_cs6_as_critical_l3() {
        for packet in [
            ipv4_transport(1, 0, 0, 0),
            ipv4_transport(6, 50_000, 179, 0),
            ipv4_transport(17, 50_000, 3784, 0),
            ipv4_transport(17, 50_000, 4784, 0),
            ipv4_transport(89, 0, 0, 0),
            ipv4_transport(6, 50_000, 443, 48),
        ] {
            assert!(is_critical_l3_control(packet.payload()));
        }

        let ordinary = ipv4_transport(6, 50_000, 443, 0);
        assert!(!is_critical_l3_control(ordinary.payload()));
    }

    #[test]
    fn critical_l3_marker_is_authenticated_before_encryption() {
        let mut packet = ipv4_transport(6, 50_000, 179, 0);

        assert!(stamp_critical_control(&mut packet));
        assert!(
            packet
                .peer_manager_header()
                .unwrap()
                .is_critical_l2_control()
        );
        packet.mut_payload_preserving_flow_hash().fill(0xa5);
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        assert!(stamp_critical_control(&mut packet));
    }

    #[test]
    fn critical_marker_is_stamped_before_payload_encryption() {
        let mut packet = ethernet_ipv4_udp(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67);
        assert!(stamp_critical_l2_control(&mut packet));
        packet.mut_payload().fill(0xa5);
        assert!(
            packet
                .peer_manager_header()
                .unwrap()
                .is_critical_l2_control()
        );
    }
}
