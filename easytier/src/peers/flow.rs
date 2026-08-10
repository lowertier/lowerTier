use std::{
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use smallvec::SmallVec;

use crate::{
    common::PeerId,
    tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
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
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    hasher.write(first_mac);
    hasher.write(second_mac);
    for _ in 0..2 {
        if !matches!(ether_type, 0x8100 | 0x88a8) || frame.len() < offset + 4 {
            break;
        }
        hasher.write(&frame[offset..offset + 2]);
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    hasher.write_u16(ether_type);
    match ether_type {
        0x0800 => hash_ipv4(hasher, &frame[offset..]),
        0x86dd => hash_ipv6(hasher, &frame[offset..]),
        _ => true,
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < 14 {
        return None;
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    for _ in 0..2 {
        if !matches!(ether_type, 0x8100 | 0x88a8) {
            break;
        }
        if frame.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    Some((ether_type, frame.get(offset..)?))
}

fn udp_ports_are(payload: &[u8], first: u16, second: u16) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let source = u16::from_be_bytes([payload[0], payload[1]]);
    let destination = u16::from_be_bytes([payload[2], payload[3]]);
    (source == first && destination == second) || (source == second && destination == first)
}

fn critical_ipv4_control(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len || packet[9] != 17 {
        return false;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return false;
    }
    udp_ports_are(&packet[header_len..], 67, 68)
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
    let Some((next_header, payload)) = ipv6_upper_layer(packet) else {
        return false;
    };
    match next_header {
        17 => udp_ports_are(payload, 546, 547),
        58 => payload
            .first()
            .is_some_and(|kind| matches!(kind, 135 | 136)),
        _ => false,
    }
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

pub(crate) fn stamp_critical_l2_control(packet: &mut ZCPacket) -> bool {
    let critical = packet
        .peer_manager_header()
        .is_some_and(|header| header.packet_type == PacketType::Ethernet as u8)
        && is_critical_l2_control(packet.payload());
    if critical && let Some(header) = packet.mut_peer_manager_header() {
        header.set_critical_l2_duplicate(true);
    }
    critical
}

pub(crate) fn classify_packet_flow(packet: &ZCPacket) -> PacketFlow {
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
    if let Some(shard) = packet
        .peer_manager_header()
        .and_then(|header| header.flow_shard())
    {
        return PacketFlow {
            hash: u64::from(shard),
            shard,
        };
    }
    let flow = classify_packet_flow(packet);
    if let Some(header) = packet.mut_peer_manager_header() {
        header.set_flow_shard(flow.shard);
    }
    PacketFlow {
        hash: u64::from(flow.shard),
        shard: flow.shard,
    }
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
        if let Some((_, group)) = groups
            .iter_mut()
            .find(|(existing, _)| existing.shard == flow.shard)
        {
            group
                .try_push(packet)
                .expect("a shard group cannot exceed its source vector");
            continue;
        }
        let mut group = PacketBatch::new();
        group
            .try_push(packet)
            .expect("a new shard group accepts its first packet");
        groups.push((flow, group));
    }
    groups
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FlowPathKey {
    destination: PeerId,
    flow: u64,
}

#[derive(Clone, Copy)]
struct PinnedPath {
    path: PeerId,
    last_used: Instant,
}

pub(crate) struct FlowPathCache {
    entries: DashMap<FlowPathKey, PinnedPath>,
    capacity: usize,
    ttl: Duration,
}

impl FlowPathCache {
    pub(crate) fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0);
        Self {
            entries: DashMap::with_capacity(capacity.min(1024)),
            capacity,
            ttl,
        }
    }

    pub(crate) fn select<F>(
        &self,
        destination: PeerId,
        flow: u64,
        candidate: PeerId,
        eligible: F,
    ) -> PeerId
    where
        F: Fn(PeerId) -> bool,
    {
        let key = FlowPathKey { destination, flow };
        let now = Instant::now();
        if let Some(mut pinned) = self.entries.get_mut(&key) {
            if now.duration_since(pinned.last_used) <= self.ttl && eligible(pinned.path) {
                pinned.last_used = now;
                return pinned.path;
            }
            drop(pinned);
            self.entries.remove(&key);
        }
        if self.entries.len() >= self.capacity {
            self.prune(now);
        }
        self.entries.insert(
            key,
            PinnedPath {
                path: candidate,
                last_used: now,
            },
        );
        candidate
    }

    pub(crate) fn invalidate_path(&self, path: PeerId) {
        self.entries.retain(|_, pinned| pinned.path != path);
        self.entries.shrink_to_fit();
    }

    fn prune(&self, now: Instant) {
        self.entries
            .retain(|_, pinned| now.duration_since(pinned.last_used) <= self.ttl);
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
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use crate::tunnel::packet_def::{PacketType, ZCPacket};

    use super::{
        FlowPathCache, classify_packet_flow, is_critical_l2_control,
        split_packet_batch_by_flow_shard, stamp_critical_l2_control, stamp_packet_flow,
    };

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
    fn stamped_flow_survives_payload_encryption_and_relay_hops() {
        let mut packet = ethernet_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            1200,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let stamped = stamp_packet_flow(&mut packet);
        packet.mut_payload().fill(0xa5);

        let relayed = classify_packet_flow(&packet);

        assert_eq!(relayed.shard, stamped.shard);
        assert_eq!(relayed.hash, u64::from(stamped.shard));
    }

    #[test]
    fn mixed_vector_is_split_into_stable_zero_copy_flow_shards() {
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

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].1.len(), 1);
        assert_eq!(
            groups[0].1.iter().next().unwrap().payload().as_ptr(),
            first_ptr
        );
        assert_eq!(
            groups[0].1.iter().nth(1).unwrap().payload().as_ptr(),
            third_ptr
        );
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
    fn denied_or_dead_pinned_path_is_never_reused() {
        let cache = FlowPathCache::new(8, Duration::from_secs(60));
        let flow = 0x5678;

        assert_eq!(cache.select(9, flow, 21, |_| true), 21);
        assert_eq!(cache.select(9, flow, 22, |path| path != 21), 22);
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
    fn critical_marker_is_stamped_before_payload_encryption() {
        let mut packet = ethernet_ipv4_udp(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67);
        assert!(stamp_critical_l2_control(&mut packet));
        packet.mut_payload().fill(0xa5);
        assert!(
            packet
                .peer_manager_header()
                .unwrap()
                .is_critical_l2_duplicate()
        );
    }
}
