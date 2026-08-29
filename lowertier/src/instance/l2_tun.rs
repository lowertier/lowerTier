use crate::common::global_ctx::MulticastReporterKey;

pub(crate) const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NeighborTarget {
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
}

#[derive(Debug, Clone, Copy)]
enum NeighborRequestKind {
    Arp {
        requester_mac: [u8; 6],
        requester_ipv4: [u8; 4],
    },
    Ndp {
        requester_mac: [u8; 6],
        requester_ipv6: [u8; 16],
        duplicate_address_detection: bool,
    },
}

pub(crate) struct ValidatedNeighborRequest<'a> {
    frame: &'a [u8],
    payload_offset: usize,
    target: NeighborTarget,
    kind: NeighborRequestKind,
}

impl ValidatedNeighborRequest<'_> {
    pub(crate) fn target(&self) -> NeighborTarget {
        self.target
    }

    pub(crate) fn reply(&self, target_peer_id: u32) -> Vec<u8> {
        match (self.target, self.kind) {
            (
                NeighborTarget::Ipv4(target_ipv4),
                NeighborRequestKind::Arp {
                    requester_mac,
                    requester_ipv4,
                },
            ) => self.arp_reply(target_peer_id, target_ipv4, requester_mac, requester_ipv4),
            (
                NeighborTarget::Ipv6(target_ipv6),
                NeighborRequestKind::Ndp {
                    requester_mac,
                    requester_ipv6,
                    duplicate_address_detection,
                },
            ) => self.ndp_reply(
                target_peer_id,
                target_ipv6,
                requester_mac,
                requester_ipv6,
                duplicate_address_detection,
            ),
            _ => unreachable!("validated neighbor request type must match its target"),
        }
    }

    fn copy_ethernet_header(&self, reply: &mut [u8], destination: [u8; 6], source: [u8; 6]) {
        reply[..6].copy_from_slice(&destination);
        reply[6..12].copy_from_slice(&source);
        reply[12..self.payload_offset].copy_from_slice(&self.frame[12..self.payload_offset]);
    }

    fn arp_reply(
        &self,
        target_peer_id: u32,
        target_ipv4: std::net::Ipv4Addr,
        requester_mac: [u8; 6],
        requester_ipv4: [u8; 4],
    ) -> Vec<u8> {
        let target_mac = encode_peer_mac(target_peer_id);
        let mut reply = vec![0_u8; self.payload_offset + 28];
        self.copy_ethernet_header(&mut reply, requester_mac, target_mac);
        let arp = &mut reply[self.payload_offset..];
        arp[..6].copy_from_slice(&[0, 1, 0x08, 0, 6, 4]);
        arp[6..8].copy_from_slice(&2_u16.to_be_bytes());
        arp[8..14].copy_from_slice(&target_mac);
        arp[14..18].copy_from_slice(&target_ipv4.octets());
        arp[18..24].copy_from_slice(&requester_mac);
        arp[24..28].copy_from_slice(&requester_ipv4);
        reply
    }

    fn ndp_reply(
        &self,
        target_peer_id: u32,
        target_ipv6: std::net::Ipv6Addr,
        requester_mac: [u8; 6],
        requester_ipv6: [u8; 16],
        duplicate_address_detection: bool,
    ) -> Vec<u8> {
        const NDP_REPLY_PAYLOAD_LEN: usize = 32;
        let target_mac = encode_peer_mac(target_peer_id);
        let (destination_mac, destination_ipv6, flags) = if duplicate_address_detection {
            (
                [0x33, 0x33, 0, 0, 0, 1],
                "ff02::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
                0x2000_0000_u32,
            )
        } else {
            (requester_mac, requester_ipv6, 0x6000_0000_u32)
        };
        let ipv6_offset = self.payload_offset;
        let icmp_offset = ipv6_offset + 40;
        let mut reply = vec![0_u8; icmp_offset + NDP_REPLY_PAYLOAD_LEN];
        self.copy_ethernet_header(&mut reply, destination_mac, target_mac);
        reply[ipv6_offset] = 0x60;
        reply[ipv6_offset + 4..ipv6_offset + 6]
            .copy_from_slice(&(NDP_REPLY_PAYLOAD_LEN as u16).to_be_bytes());
        reply[ipv6_offset + 6] = 58;
        reply[ipv6_offset + 7] = 255;
        reply[ipv6_offset + 8..ipv6_offset + 24].copy_from_slice(&target_ipv6.octets());
        reply[ipv6_offset + 24..ipv6_offset + 40].copy_from_slice(&destination_ipv6);
        reply[icmp_offset] = 136;
        reply[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&flags.to_be_bytes());
        reply[icmp_offset + 8..icmp_offset + 24].copy_from_slice(&target_ipv6.octets());
        reply[icmp_offset + 24] = 2;
        reply[icmp_offset + 25] = 1;
        reply[icmp_offset + 26..icmp_offset + 32].copy_from_slice(&target_mac);
        let checksum = internet_checksum(&[
            &reply[ipv6_offset + 8..ipv6_offset + 24],
            &reply[ipv6_offset + 24..ipv6_offset + 40],
            &(NDP_REPLY_PAYLOAD_LEN as u32).to_be_bytes(),
            &[0, 0, 0, 58],
            &reply[icmp_offset..],
        ]);
        reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        reply
    }
}

pub(crate) fn validated_neighbor_request(frame: &[u8]) -> Option<ValidatedNeighborRequest<'_>> {
    let (ether_type, payload_offset) = ethernet_payload(frame)?;
    match ether_type {
        0x0806 => validated_arp_request(frame, payload_offset),
        0x86dd => validated_ndp_request(frame, payload_offset),
        _ => None,
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<(u16, usize)> {
    let metadata = crate::tunnel::packet_def::ethernet_network_metadata(frame)?;
    Some((metadata.ether_type, metadata.payload_offset))
}

fn valid_unicast_mac(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && mac[0] & 1 == 0
}

fn validated_arp_request(
    frame: &[u8],
    payload_offset: usize,
) -> Option<ValidatedNeighborRequest<'_>> {
    let arp = frame.get(payload_offset..payload_offset + 28)?;
    if arp[..8] != [0, 1, 0x08, 0, 6, 4, 0, 1] {
        return None;
    }
    let ethernet_source: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let requester_mac: [u8; 6] = arp[8..14].try_into().ok()?;
    if requester_mac != ethernet_source || !valid_unicast_mac(&requester_mac) {
        return None;
    }
    let requester_ipv4: [u8; 4] = arp[14..18].try_into().ok()?;
    let target_hardware: [u8; 6] = arp[18..24].try_into().ok()?;
    if target_hardware != [0; 6] {
        return None;
    }
    let target_ipv4 = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&arp[24..28]).ok()?);
    if target_ipv4.is_unspecified()
        || target_ipv4.is_multicast()
        || target_ipv4 == std::net::Ipv4Addr::BROADCAST
    {
        return None;
    }
    Some(ValidatedNeighborRequest {
        frame,
        payload_offset,
        target: NeighborTarget::Ipv4(target_ipv4),
        kind: NeighborRequestKind::Arp {
            requester_mac,
            requester_ipv4,
        },
    })
}

fn solicited_node_multicast(target: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    let target = target.octets();
    let mut multicast = [0_u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&target[13..]);
    std::net::Ipv6Addr::from(multicast)
}

fn validated_ndp_request(
    frame: &[u8],
    payload_offset: usize,
) -> Option<ValidatedNeighborRequest<'_>> {
    let ipv6_header = frame.get(payload_offset..payload_offset + 40)?;
    if ipv6_header[0] >> 4 != 6 || ipv6_header[7] != 255 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(ipv6_header[4..6].try_into().ok()?));
    let ipv6_end = payload_offset.checked_add(40)?.checked_add(payload_len)?;
    if ipv6_end > frame.len() {
        return None;
    }
    let source = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_header[8..24]).ok()?);
    let destination = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_header[24..40]).ok()?);
    if source.is_multicast() {
        return None;
    }

    let mut next_header = ipv6_header[6];
    let mut icmp_offset = payload_offset + 40;
    for _ in 0..8 {
        if next_header == 58 {
            break;
        }
        if !matches!(next_header, 0 | 43 | 60) {
            return None;
        }
        let extension = frame.get(icmp_offset..icmp_offset + 2)?;
        next_header = extension[0];
        let extension_len = (usize::from(extension[1]) + 1).checked_mul(8)?;
        icmp_offset = icmp_offset.checked_add(extension_len)?;
        if icmp_offset > ipv6_end {
            return None;
        }
    }
    if next_header != 58 {
        return None;
    }
    let icmp = frame.get(icmp_offset..ipv6_end)?;
    if icmp.len() < 24 || icmp[0] != 135 || icmp[1] != 0 {
        return None;
    }
    let target = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).ok()?);
    if target.is_unspecified() || target.is_multicast() {
        return None;
    }
    let solicited = solicited_node_multicast(target);
    let duplicate_address_detection = source.is_unspecified();
    if (duplicate_address_detection && destination != solicited)
        || (!duplicate_address_detection && destination != solicited && destination != target)
    {
        return None;
    }
    if internet_checksum(&[
        &source.octets(),
        &destination.octets(),
        &(icmp.len() as u32).to_be_bytes(),
        &[0, 0, 0, 58],
        icmp,
    ]) != 0
    {
        return None;
    }

    let ethernet_source: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    if !valid_unicast_mac(&ethernet_source) {
        return None;
    }
    let mut source_link_layer = None;
    let mut option_offset = 24;
    while option_offset < icmp.len() {
        let option = icmp.get(option_offset..option_offset + 2)?;
        let option_len = usize::from(option[1]).checked_mul(8)?;
        if option_len == 0 {
            return None;
        }
        let option = icmp.get(option_offset..option_offset + option_len)?;
        if option[0] == 1 {
            if option_len != 8 || source_link_layer.is_some() {
                return None;
            }
            source_link_layer = Some(<[u8; 6]>::try_from(&option[2..8]).ok()?);
        }
        option_offset = option_offset.checked_add(option_len)?;
    }
    if duplicate_address_detection {
        if source_link_layer.is_some() {
            return None;
        }
    } else if source_link_layer.is_some_and(|mac| mac != ethernet_source) {
        return None;
    }
    Some(ValidatedNeighborRequest {
        frame,
        payload_offset,
        target: NeighborTarget::Ipv6(target),
        kind: NeighborRequestKind::Ndp {
            requester_mac: ethernet_source,
            requester_ipv6: source.octets(),
            duplicate_address_detection,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum L2TunError {
    #[error("frame is too short for an Ethernet header and IP version")]
    FrameTooShort,
    #[error("TUN payload is not IPv4 or IPv6")]
    UnsupportedIpVersion,
    #[cfg(test)]
    #[error("Ethernet frame does not contain IPv4 or IPv6")]
    UnsupportedEtherType,
}

pub(crate) fn encode_peer_mac(peer_id: u32) -> [u8; 6] {
    let id = peer_id.to_be_bytes();
    [0x02, 0x45, id[0], id[1], id[2], id[3]]
}

pub(crate) fn ip_destination_mac(ip_packet: &[u8], unicast: [u8; 6]) -> Option<[u8; 6]> {
    match ip_packet.first().map(|byte| byte >> 4)? {
        4 => {
            let destination: [u8; 4] = ip_packet.get(16..20)?.try_into().ok()?;
            if destination[0] & 0xf0 == 0xe0 {
                Some([
                    0x01,
                    0x00,
                    0x5e,
                    destination[1] & 0x7f,
                    destination[2],
                    destination[3],
                ])
            } else if destination == [0xff; 4] {
                Some([0xff; 6])
            } else {
                Some(unicast)
            }
        }
        6 => {
            let destination: [u8; 16] = ip_packet.get(24..40)?.try_into().ok()?;
            if destination[0] == 0xff {
                Some([
                    0x33,
                    0x33,
                    destination[12],
                    destination[13],
                    destination[14],
                    destination[15],
                ])
            } else {
                Some(unicast)
            }
        }
        _ => None,
    }
}

fn ipv4_directed_broadcast(
    destination: std::net::Ipv4Addr,
    prefix: (std::net::Ipv4Addr, u8),
) -> bool {
    let prefix_len = prefix.1.min(32);
    if prefix_len == 32 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    let network = u32::from(prefix.0) & mask;
    u32::from(destination) == network | !mask
}

fn ip_destination_mac_with_ipv4_prefix(
    ip_packet: &[u8],
    unicast: [u8; 6],
    ipv4_prefix: Option<(std::net::Ipv4Addr, u8)>,
) -> Option<[u8; 6]> {
    if ip_packet.first().map(|byte| byte >> 4) == Some(4) {
        let destination =
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(ip_packet.get(16..20)?).ok()?);
        if destination == std::net::Ipv4Addr::BROADCAST
            || ipv4_prefix.is_some_and(|prefix| ipv4_directed_broadcast(destination, prefix))
        {
            return Some([0xff; 6]);
        }
    }
    ip_destination_mac(ip_packet, unicast)
}

#[cfg(test)]
pub(crate) fn prepare_ip_frame(
    frame: &mut [u8],
    source_peer_id: u32,
    destination_peer_id: Option<u32>,
) -> Result<(), L2TunError> {
    prepare_ip_frame_with_ipv4_prefix(frame, source_peer_id, destination_peer_id, None)
}

pub(crate) fn prepare_ip_frame_with_ipv4_prefix(
    frame: &mut [u8],
    source_peer_id: u32,
    destination_peer_id: Option<u32>,
    ipv4_prefix: Option<(std::net::Ipv4Addr, u8)>,
) -> Result<(), L2TunError> {
    let version = frame
        .get(ETHERNET_HEADER_LEN)
        .ok_or(L2TunError::FrameTooShort)?
        >> 4;
    let ether_type = match version {
        4 => EtherType::Ipv4,
        6 => EtherType::Ipv6,
        _ => return Err(L2TunError::UnsupportedIpVersion),
    };
    let unicast_destination = destination_peer_id
        .map(encode_peer_mac)
        .unwrap_or([0xff; 6]);
    let destination = ip_destination_mac_with_ipv4_prefix(
        &frame[ETHERNET_HEADER_LEN..],
        unicast_destination,
        ipv4_prefix,
    )
    .ok_or(L2TunError::FrameTooShort)?;
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&encode_peer_mac(source_peer_id));
    frame[12..14].copy_from_slice(&(ether_type as u16).to_be_bytes());
    Ok(())
}

#[cfg(test)]
pub(crate) fn decapsulate_ip(frame: &[u8]) -> Result<&[u8], L2TunError> {
    if frame.len() <= ETHERNET_HEADER_LEN {
        return Err(L2TunError::FrameTooShort);
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let expected_version = match ether_type {
        value if value == EtherType::Ipv4 as u16 => 4,
        value if value == EtherType::Ipv6 as u16 => 6,
        _ => return Err(L2TunError::UnsupportedEtherType),
    };
    let payload = &frame[ETHERNET_HEADER_LEN..];
    if payload[0] >> 4 != expected_version {
        return Err(L2TunError::UnsupportedIpVersion);
    }
    Ok(payload)
}

/// Build the proxy-ARP response that lets a native TAP peer address an IP-only TUN edge.
/// Non-ARP frames and requests for another address are deliberately ignored.
#[cfg(test)]
pub(crate) fn arp_reply_for_local_ipv4(
    frame: &[u8],
    local_peer_id: u32,
    local_ipv4: std::net::Ipv4Addr,
) -> Option<Vec<u8>> {
    arp_reply_for_known_ipv4(frame, local_peer_id, local_ipv4)
}

#[cfg(test)]
pub(crate) fn arp_reply_for_known_ipv4(
    frame: &[u8],
    target_peer_id: u32,
    target_ipv4: std::net::Ipv4Addr,
) -> Option<Vec<u8>> {
    let request = validated_neighbor_request(frame)?;
    (request.target() == NeighborTarget::Ipv4(target_ipv4)).then(|| request.reply(target_peer_id))
}

fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut high = None;
    for part in parts {
        for byte in *part {
            if let Some(previous) = high.take() {
                sum += u32::from(u16::from_be_bytes([previous, *byte]));
            } else {
                high = Some(*byte);
            }
        }
    }
    if let Some(previous) = high {
        sum += u32::from(u16::from_be_bytes([previous, 0]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
pub(crate) fn ndp_reply_for_known_ipv6(
    frame: &[u8],
    target_peer_id: u32,
    target_ipv6: std::net::Ipv6Addr,
) -> Option<Vec<u8>> {
    let request = validated_neighbor_request(frame)?;
    (request.target() == NeighborTarget::Ipv6(target_ipv6)).then(|| request.reply(target_peer_id))
}

const MAX_MEMBERSHIP_UPDATES_PER_FRAME: usize = 256;

#[cfg(test)]
pub(crate) fn multicast_membership_updates(frame: &[u8]) -> Vec<(std::net::IpAddr, bool)> {
    multicast_membership_updates_with_reporter(frame)
        .into_iter()
        .map(|(_, group, joined)| (group, joined))
        .collect()
}

#[cfg(test)]
pub(crate) fn multicast_membership_updates_from_ip(packet: &[u8]) -> Vec<(std::net::IpAddr, bool)> {
    multicast_membership_updates_from_ip_with_reporter(packet)
        .into_iter()
        .map(|(_, group, joined)| (group, joined))
        .collect()
}

pub(crate) fn multicast_membership_updates_with_reporter(
    frame: &[u8],
) -> Vec<(MulticastReporterKey, std::net::IpAddr, bool)> {
    let Some((packet, reporter)) = ethernet_ip_payload(frame) else {
        return Vec::new();
    };
    multicast_membership_updates_for_packet(packet, reporter)
}

pub(crate) fn multicast_membership_updates_from_ip_with_reporter(
    packet: &[u8],
) -> Vec<(MulticastReporterKey, std::net::IpAddr, bool)> {
    let reporter = MulticastReporterKey {
        source_ip: source_ip_from_packet(packet),
        ..MulticastReporterKey::default()
    };
    multicast_membership_updates_for_packet(packet, reporter)
}

fn ethernet_ip_payload(frame: &[u8]) -> Option<(&[u8], MulticastReporterKey)> {
    let source_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let mut ether_type = u16::from_be_bytes(<[u8; 2]>::try_from(frame.get(12..14)?).ok()?);
    let mut offset = ETHERNET_HEADER_LEN;
    let mut vlan_tags = [0_u16; 4];
    let mut vlan_len = 0_u8;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if vlan_len as usize >= vlan_tags.len() {
            return None;
        }
        let tag = frame.get(offset..offset + 4)?;
        vlan_tags[vlan_len as usize] = u16::from_be_bytes([tag[0], tag[1]]);
        ether_type = u16::from_be_bytes([tag[2], tag[3]]);
        offset += 4;
        vlan_len += 1;
    }
    if !matches!(ether_type, 0x0800 | 0x86dd) {
        return None;
    }
    let packet = frame.get(offset..)?;
    let source_ip = if source_mac == [0; 6] {
        source_ip_from_packet(packet)
    } else {
        None
    };
    Some((
        packet,
        MulticastReporterKey {
            vlan_tags,
            vlan_len,
            source_mac,
            source_ip,
        },
    ))
}

fn source_ip_from_packet(packet: &[u8]) -> Option<std::net::IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(packet.get(12..16)?).ok()?,
        ))),
        Some(6) => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(packet.get(8..24)?).ok()?,
        ))),
        _ => None,
    }
}

fn multicast_membership_updates_for_packet(
    packet: &[u8],
    reporter: MulticastReporterKey,
) -> Vec<(MulticastReporterKey, std::net::IpAddr, bool)> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => ipv4_membership_updates(packet, reporter),
        Some(6) => ipv6_membership_updates(packet, reporter),
        _ => Vec::new(),
    }
}

fn ipv4_membership_updates(
    packet: &[u8],
    reporter: MulticastReporterKey,
) -> Vec<(MulticastReporterKey, std::net::IpAddr, bool)> {
    let Some(first) = packet.first() else {
        return Vec::new();
    };
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < 20 || packet.get(9) != Some(&2) {
        return Vec::new();
    }
    let Some(total_len) = packet
        .get(2..4)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
    else {
        return Vec::new();
    };
    if total_len < header_len || total_len > packet.len() {
        return Vec::new();
    }
    let packet = &packet[..total_len];
    let offset = header_len;
    let Some(message_type) = packet.get(offset).copied() else {
        return Vec::new();
    };
    if matches!(message_type, 0x12 | 0x16 | 0x17) {
        if packet.get(offset..offset + 8).is_none()
            || internet_checksum(&[&packet[offset..offset + 8]]) != 0
        {
            return Vec::new();
        }
        let Some(group) = packet
            .get(offset + 4..offset + 8)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(std::net::Ipv4Addr::from)
        else {
            return Vec::new();
        };
        return vec![(reporter, std::net::IpAddr::V4(group), message_type != 0x17)];
    }
    if message_type != 0x22 {
        return Vec::new();
    }
    if packet.get(offset..offset + 8).is_none() || internet_checksum(&[&packet[offset..]]) != 0 {
        return Vec::new();
    }

    let record_count = packet
        .get(offset + 6..offset + 8)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .unwrap_or(0);
    if record_count > MAX_MEMBERSHIP_UPDATES_PER_FRAME {
        return Vec::new();
    }
    let mut cursor = offset + 8;
    let mut updates = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let Some(record) = packet.get(cursor..cursor + 8) else {
            return Vec::new();
        };
        let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
        let Some(record_len) = source_count
            .checked_mul(4)
            .and_then(|length| length.checked_add(usize::from(record[1]) * 4))
            .and_then(|length| length.checked_add(8))
        else {
            return Vec::new();
        };
        if packet.get(cursor..cursor + record_len).is_none() {
            return Vec::new();
        }
        let Some(group) = <[u8; 4]>::try_from(&record[4..8])
            .ok()
            .map(std::net::Ipv4Addr::from)
        else {
            return Vec::new();
        };
        let joined = match record[0] {
            2 | 4 => true,
            1 | 3 => source_count != 0,
            5 | 6 => continue,
            _ => return Vec::new(),
        };
        updates.push((reporter, std::net::IpAddr::V4(group), joined));
        let Some(next) = cursor.checked_add(record_len) else {
            return Vec::new();
        };
        cursor = next;
    }
    updates
}

fn ipv6_membership_updates(
    packet: &[u8],
    reporter: MulticastReporterKey,
) -> Vec<(MulticastReporterKey, std::net::IpAddr, bool)> {
    let Some(ipv6_header) = packet.get(..40) else {
        return Vec::new();
    };
    if ipv6_header[0] >> 4 != 6 {
        return Vec::new();
    }
    let payload_len = usize::from(u16::from_be_bytes([ipv6_header[4], ipv6_header[5]]));
    let Some(ipv6_end) = 40usize.checked_add(payload_len) else {
        return Vec::new();
    };
    if ipv6_end > packet.len() {
        return Vec::new();
    }
    let packet = &packet[..ipv6_end];
    let mut next_header = ipv6_header[6];
    let mut offset = 40;
    for _ in 0..8 {
        if next_header == 58 {
            break;
        }
        if !matches!(next_header, 0 | 43 | 60) {
            return Vec::new();
        }
        let Some(header) = packet.get(offset..offset + 2) else {
            return Vec::new();
        };
        next_header = header[0];
        let Some(extension_len) = (usize::from(header[1]) + 1).checked_mul(8) else {
            return Vec::new();
        };
        let Some(next_offset) = offset.checked_add(extension_len) else {
            return Vec::new();
        };
        if next_offset > packet.len() {
            return Vec::new();
        }
        offset = next_offset;
    }
    if next_header != 58 {
        return Vec::new();
    }
    let icmp_len = packet.len().saturating_sub(offset);
    let Ok(icmp_len_u32) = u32::try_from(icmp_len) else {
        return Vec::new();
    };
    let Some(message_type) = packet.get(offset).copied() else {
        return Vec::new();
    };
    if matches!(message_type, 131 | 132) {
        if packet.get(offset..offset + 24).is_none()
            || internet_checksum(&[
                &packet[8..24],
                &packet[24..40],
                &icmp_len_u32.to_be_bytes(),
                &[0, 0, 0, 58],
                &packet[offset..],
            ]) != 0
        {
            return Vec::new();
        }
        let Some(group) = packet
            .get(offset + 8..offset + 24)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .map(std::net::Ipv6Addr::from)
        else {
            return Vec::new();
        };
        return vec![(reporter, std::net::IpAddr::V6(group), message_type == 131)];
    }
    if message_type != 143 {
        return Vec::new();
    }
    if packet.get(offset..offset + 8).is_none()
        || internet_checksum(&[
            &packet[8..24],
            &packet[24..40],
            &icmp_len_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &packet[offset..],
        ]) != 0
    {
        return Vec::new();
    }

    let record_count = packet
        .get(offset + 6..offset + 8)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .unwrap_or(0);
    if record_count > MAX_MEMBERSHIP_UPDATES_PER_FRAME {
        return Vec::new();
    }
    let mut cursor = offset + 8;
    let mut updates = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let Some(record) = packet.get(cursor..cursor + 20) else {
            return Vec::new();
        };
        let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
        let Some(record_len) = source_count
            .checked_mul(16)
            .and_then(|length| length.checked_add(usize::from(record[1]) * 4))
            .and_then(|length| length.checked_add(20))
        else {
            return Vec::new();
        };
        if packet.get(cursor..cursor + record_len).is_none() {
            return Vec::new();
        }
        let Some(group) = <[u8; 16]>::try_from(&record[4..20])
            .ok()
            .map(std::net::Ipv6Addr::from)
        else {
            return Vec::new();
        };
        let joined = match record[0] {
            2 | 4 => true,
            1 | 3 => source_count != 0,
            5 | 6 => continue,
            _ => return Vec::new(),
        };
        updates.push((reporter, std::net::IpAddr::V6(group), joined));
        let Some(next) = cursor.checked_add(record_len) else {
            return Vec::new();
        };
        cursor = next;
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::{
        ETHERNET_HEADER_LEN, EtherType, NeighborTarget, arp_reply_for_known_ipv4,
        arp_reply_for_local_ipv4, decapsulate_ip, encode_peer_mac, internet_checksum,
        multicast_membership_updates, multicast_membership_updates_from_ip,
        multicast_membership_updates_with_reporter, ndp_reply_for_known_ipv6, prepare_ip_frame,
        prepare_ip_frame_with_ipv4_prefix, validated_neighbor_request,
    };

    #[test]
    fn peer_mac_is_local_unicast_and_contains_peer_id() {
        let mac = encode_peer_mac(0x1234_5678);

        assert_eq!(mac, [0x02, 0x45, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(mac[0] & 0x01, 0);
        assert_ne!(mac[0] & 0x02, 0);
    }

    #[test]
    fn prepares_ipv4_and_ipv6_frames_in_reserved_prefix() {
        let mut ipv4 = vec![0; ETHERNET_HEADER_LEN + 20];
        ipv4[ETHERNET_HEADER_LEN] = 0x45;
        prepare_ip_frame(&mut ipv4, 1, Some(2)).unwrap();
        assert_eq!(&ipv4[..6], &encode_peer_mac(2));
        assert_eq!(&ipv4[6..12], &encode_peer_mac(1));
        assert_eq!(&ipv4[12..14], &(EtherType::Ipv4 as u16).to_be_bytes());

        let mut ipv6 = vec![0; ETHERNET_HEADER_LEN + 40];
        ipv6[ETHERNET_HEADER_LEN] = 0x60;
        prepare_ip_frame(&mut ipv6, 3, None).unwrap();
        assert_eq!(&ipv6[..6], &[0xff; 6]);
        assert_eq!(&ipv6[12..14], &(EtherType::Ipv6 as u16).to_be_bytes());
    }

    #[test]
    fn prepares_standard_multicast_destination_macs() {
        let mut ipv4 = vec![0; ETHERNET_HEADER_LEN + 20];
        ipv4[ETHERNET_HEADER_LEN] = 0x45;
        ipv4[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20].copy_from_slice(&[239, 129, 2, 3]);
        prepare_ip_frame(&mut ipv4, 1, None).unwrap();
        assert_eq!(&ipv4[..6], &[0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]);

        let mut ipv6 = vec![0; ETHERNET_HEADER_LEN + 40];
        ipv6[ETHERNET_HEADER_LEN] = 0x60;
        ipv6[ETHERNET_HEADER_LEN + 24..ETHERNET_HEADER_LEN + 40].copy_from_slice(
            &"ff02::1:ff02:304"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        prepare_ip_frame(&mut ipv6, 1, None).unwrap();
        assert_eq!(&ipv6[..6], &[0x33, 0x33, 0xff, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn prepares_a_configured_ipv4_directed_broadcast_as_ethernet_broadcast() {
        let mut ipv4 = vec![0; ETHERNET_HEADER_LEN + 20];
        ipv4[ETHERNET_HEADER_LEN] = 0x45;
        ipv4[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20].copy_from_slice(&[10, 81, 0, 255]);

        prepare_ip_frame_with_ipv4_prefix(
            &mut ipv4,
            1,
            Some(2),
            Some(("10.81.0.1".parse().unwrap(), 24)),
        )
        .unwrap();

        assert_eq!(&ipv4[..6], &[0xff; 6]);
    }

    #[test]
    fn decapsulates_only_supported_ip_frames() {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 20];
        frame[ETHERNET_HEADER_LEN] = 0x45;
        prepare_ip_frame(&mut frame, 1, Some(2)).unwrap();
        assert_eq!(
            decapsulate_ip(&frame).unwrap(),
            &frame[ETHERNET_HEADER_LEN..]
        );

        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert!(decapsulate_ip(&frame).is_err());
        assert!(decapsulate_ip(&frame[..10]).is_err());
    }

    #[test]
    fn answers_arp_only_for_the_local_tun_ipv4() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let mut request = vec![0_u8; 42];
        request[..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        request[14..22].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        request[22..28].copy_from_slice(&requester_mac);
        request[28..32].copy_from_slice(&[10, 81, 0, 2]);
        request[38..42].copy_from_slice(&[10, 81, 0, 1]);

        let reply =
            arp_reply_for_local_ipv4(&request, 0x1234_5678, "10.81.0.1".parse().unwrap()).unwrap();
        let local_mac = encode_peer_mac(0x1234_5678);
        assert_eq!(&reply[..6], &requester_mac);
        assert_eq!(&reply[6..12], &local_mac);
        assert_eq!(&reply[20..22], &2_u16.to_be_bytes());
        assert_eq!(&reply[22..28], &local_mac);
        assert_eq!(&reply[28..32], &[10, 81, 0, 1]);
        assert_eq!(&reply[32..38], &requester_mac);
        assert_eq!(&reply[38..42], &[10, 81, 0, 2]);

        request[38..42].copy_from_slice(&[10, 81, 0, 99]);
        assert!(
            arp_reply_for_local_ipv4(&request, 0x1234_5678, "10.81.0.1".parse().unwrap(),)
                .is_none()
        );
    }

    #[test]
    fn answers_arp_for_a_known_overlay_peer() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let target: std::net::Ipv4Addr = "10.81.0.9".parse().unwrap();
        let mut request = vec![0_u8; 42];
        request[..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        request[14..22].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        request[22..28].copy_from_slice(&requester_mac);
        request[28..32].copy_from_slice(&[10, 81, 0, 2]);
        request[38..42].copy_from_slice(&target.octets());

        let reply = arp_reply_for_known_ipv4(&request, 9, target).unwrap();

        assert_eq!(&reply[..6], &requester_mac);
        assert_eq!(&reply[6..12], &encode_peer_mac(9));
        assert_eq!(&reply[22..28], &encode_peer_mac(9));
        assert_eq!(&reply[28..32], &target.octets());
    }

    #[test]
    fn rejects_arp_with_an_inconsistent_sender_mac() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let target: std::net::Ipv4Addr = "10.81.0.9".parse().unwrap();
        let mut request = vec![0_u8; 42];
        request[..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        request[14..22].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        request[22..28].copy_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        request[28..32].copy_from_slice(&[10, 81, 0, 2]);
        request[38..42].copy_from_slice(&target.octets());

        assert!(validated_neighbor_request(&request).is_none());
    }

    #[test]
    fn rejects_a_truncated_vlan_neighbor_request() {
        let mut request = vec![0_u8; 16];
        request[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());

        assert!(validated_neighbor_request(&request).is_none());
    }

    #[test]
    fn validates_an_arp_request_inside_a_vlan() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let target: std::net::Ipv4Addr = "10.81.0.9".parse().unwrap();
        let mut request = vec![0_u8; 46];
        request[..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        request[14..16].copy_from_slice(&7_u16.to_be_bytes());
        request[16..18].copy_from_slice(&0x0806_u16.to_be_bytes());
        request[18..26].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        request[26..32].copy_from_slice(&requester_mac);
        request[32..36].copy_from_slice(&[10, 81, 0, 2]);
        request[42..46].copy_from_slice(&target.octets());

        let request = validated_neighbor_request(&request).unwrap();

        assert_eq!(request.target(), NeighborTarget::Ipv4(target));
        let reply = request.reply(9);
        assert_eq!(reply.len(), 46);
        assert_eq!(&reply[12..18], &request.frame[12..18]);
        assert_eq!(&reply[24..26], &2_u16.to_be_bytes());
    }

    #[test]
    fn answers_ndp_for_a_known_overlay_peer() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let requester_ip: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let target: std::net::Ipv6Addr = "fd00::9".parse().unwrap();
        let mut request = vec![0_u8; 86];
        request[..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 9]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&32_u16.to_be_bytes());
        request[20] = 58;
        request[21] = 255;
        request[22..38].copy_from_slice(&requester_ip.octets());
        request[38..54].copy_from_slice(
            &"ff02::1:ff00:9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        request[54] = 135;
        request[62..78].copy_from_slice(&target.octets());
        request[78] = 1;
        request[79] = 1;
        request[80..86].copy_from_slice(&requester_mac);
        let checksum = internet_checksum(&[
            &request[22..38],
            &request[38..54],
            &32_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &request[54..],
        ]);
        request[56..58].copy_from_slice(&checksum.to_be_bytes());

        let reply = ndp_reply_for_known_ipv6(&request, 9, target).unwrap();

        assert_eq!(&reply[..6], &requester_mac);
        assert_eq!(&reply[6..12], &encode_peer_mac(9));
        assert_eq!(&reply[22..38], &target.octets());
        assert_eq!(&reply[38..54], &requester_ip.octets());
        assert_eq!(reply[54], 136);
        assert_eq!(&reply[78..80], &[2, 1]);
        assert_eq!(&reply[80..86], &encode_peer_mac(9));
        assert_eq!(
            internet_checksum(&[
                &reply[22..38],
                &reply[38..54],
                &32_u32.to_be_bytes(),
                &[0, 0, 0, 58],
                &reply[54..],
            ]),
            0
        );
    }

    #[test]
    fn rejects_normal_ipv6_as_a_neighbor_request() {
        let mut frame = vec![0_u8; 14 + 40 + 8];
        frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&8_u16.to_be_bytes());
        frame[20] = 17;
        frame[21] = 64;

        assert!(validated_neighbor_request(&frame).is_none());
    }

    #[test]
    fn rejects_an_ndp_request_with_a_bad_checksum() {
        let mut request = vec![0_u8; 86];
        request[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&32_u16.to_be_bytes());
        request[20] = 58;
        request[21] = 255;
        request[22..38].copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        request[38..54].copy_from_slice(
            &"ff02::1:ff00:9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        request[54] = 135;
        request[62..78].copy_from_slice(&"fd00::9".parse::<std::net::Ipv6Addr>().unwrap().octets());

        assert!(validated_neighbor_request(&request).is_none());
    }

    #[test]
    fn accepts_duplicate_address_detection_without_a_source_option() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let target: std::net::Ipv6Addr = "fd00::9".parse().unwrap();
        let destination = super::solicited_node_multicast(target);
        let mut request = vec![0_u8; 78];
        request[..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 9]);
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&24_u16.to_be_bytes());
        request[20] = 58;
        request[21] = 255;
        request[38..54].copy_from_slice(&destination.octets());
        request[54] = 135;
        request[62..78].copy_from_slice(&target.octets());
        let checksum = internet_checksum(&[
            &[0; 16],
            &destination.octets(),
            &24_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &request[54..],
        ]);
        request[56..58].copy_from_slice(&checksum.to_be_bytes());

        let request = validated_neighbor_request(&request).unwrap();
        let reply = request.reply(9);

        assert_eq!(request.target(), NeighborTarget::Ipv6(target));
        assert_eq!(&reply[..6], &[0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(
            &reply[38..54],
            &"ff02::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&reply[58..62], &0x2000_0000_u32.to_be_bytes());
    }

    #[test]
    fn rejects_duplicate_address_detection_with_a_source_option() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let target: std::net::Ipv6Addr = "fd00::9".parse().unwrap();
        let destination = super::solicited_node_multicast(target);
        let mut request = vec![0_u8; 86];
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&32_u16.to_be_bytes());
        request[20] = 58;
        request[21] = 255;
        request[38..54].copy_from_slice(&destination.octets());
        request[54] = 135;
        request[62..78].copy_from_slice(&target.octets());
        request[78] = 1;
        request[79] = 1;
        request[80..86].copy_from_slice(&requester_mac);
        let checksum = internet_checksum(&[
            &[0; 16],
            &destination.octets(),
            &32_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &request[54..],
        ]);
        request[56..58].copy_from_slice(&checksum.to_be_bytes());

        assert!(validated_neighbor_request(&request).is_none());
    }

    #[test]
    fn rejects_an_ndp_option_with_a_zero_length() {
        let requester_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let requester_ip: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let target: std::net::Ipv6Addr = "fd00::9".parse().unwrap();
        let destination = super::solicited_node_multicast(target);
        let mut request = vec![0_u8; 86];
        request[6..12].copy_from_slice(&requester_mac);
        request[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        request[14] = 0x60;
        request[18..20].copy_from_slice(&32_u16.to_be_bytes());
        request[20] = 58;
        request[21] = 255;
        request[22..38].copy_from_slice(&requester_ip.octets());
        request[38..54].copy_from_slice(&destination.octets());
        request[54] = 135;
        request[62..78].copy_from_slice(&target.octets());
        request[78] = 1;
        let checksum = internet_checksum(&[
            &requester_ip.octets(),
            &destination.octets(),
            &32_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &request[54..],
        ]);
        request[56..58].copy_from_slice(&checksum.to_be_bytes());

        assert!(validated_neighbor_request(&request).is_none());
    }

    #[test]
    fn reads_igmp_membership_changes() {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let mut report = vec![0_u8; 42];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[16..18].copy_from_slice(&28_u16.to_be_bytes());
        report[23] = 2;
        report[34] = 0x16;
        report[38..42].copy_from_slice(&group.octets());
        let checksum = internet_checksum(&[&report[34..42]]);
        report[36..38].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), true)]
        );
        assert_eq!(
            multicast_membership_updates_from_ip(&report[ETHERNET_HEADER_LEN..]),
            vec![(std::net::IpAddr::V4(group), true)]
        );

        report[34] = 0x17;
        report[36..38].fill(0);
        let checksum = internet_checksum(&[&report[34..42]]);
        report[36..38].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), false)]
        );
    }

    #[test]
    fn reads_igmp_v1_membership_report() {
        let group: std::net::Ipv4Addr = "239.1.2.4".parse().unwrap();
        let mut report = vec![0_u8; 42];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[16..18].copy_from_slice(&28_u16.to_be_bytes());
        report[23] = 2;
        report[34] = 0x12;
        report[38..42].copy_from_slice(&group.octets());
        let checksum = internet_checksum(&[&report[34..42]]);
        report[36..38].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), true)]
        );
    }

    #[test]
    fn reporter_key_preserves_source_mac_and_vlan_context() {
        let group: std::net::Ipv4Addr = "239.1.2.5".parse().unwrap();
        let source_mac = [0x02, 1, 2, 3, 4, 5];
        let mut report = vec![0_u8; 46];
        report[6..12].copy_from_slice(&source_mac);
        report[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        report[14..16].copy_from_slice(&100_u16.to_be_bytes());
        report[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[18] = 0x45;
        report[20..22].copy_from_slice(&28_u16.to_be_bytes());
        report[27] = 2;
        report[38] = 0x12;
        report[42..46].copy_from_slice(&group.octets());
        let checksum = internet_checksum(&[&report[38..46]]);
        report[40..42].copy_from_slice(&checksum.to_be_bytes());

        let updates = multicast_membership_updates_with_reporter(&report);
        assert_eq!(updates.len(), 1);
        let (reporter, update_group, joined) = updates[0];
        assert_eq!(reporter.source_mac, source_mac);
        assert_eq!(reporter.vlan_len, 1);
        assert_eq!(reporter.vlan_tags[0], 100);
        assert_eq!(reporter.source_ip, None);
        assert_eq!(update_group, std::net::IpAddr::V4(group));
        assert!(joined);
    }

    #[test]
    fn rejects_igmp_records_outside_the_declared_ipv4_length() {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let mut report = vec![0_u8; 42];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[16..18].copy_from_slice(&8_u16.to_be_bytes());
        report[23] = 2;
        report[34] = 0x16;
        report[38..42].copy_from_slice(&group.octets());

        assert!(multicast_membership_updates(&report).is_empty());
    }

    #[test]
    fn rejects_igmp_with_an_invalid_checksum() {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let mut report = vec![0_u8; 42];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[16..18].copy_from_slice(&28_u16.to_be_bytes());
        report[23] = 2;
        report[34] = 0x16;
        report[38..42].copy_from_slice(&group.octets());
        report[36..38].copy_from_slice(&1_u16.to_be_bytes());

        assert!(multicast_membership_updates(&report).is_empty());
    }

    #[test]
    fn source_filter_include_records_create_membership() {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let mut report = vec![0_u8; 54];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[16..18].copy_from_slice(&40_u16.to_be_bytes());
        report[23] = 2;
        report[34] = 0x22;
        report[40..42].copy_from_slice(&1_u16.to_be_bytes());
        report[42] = 1;
        report[44..46].copy_from_slice(&1_u16.to_be_bytes());
        report[46..50].copy_from_slice(&group.octets());
        let checksum = super::internet_checksum(&[&report[34..54]]);
        report[36..38].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), true)]
        );
    }

    #[test]
    fn reads_mldv2_include_membership_with_sources() {
        let group: std::net::Ipv6Addr = "ff02::1235".parse().unwrap();
        let source: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let mut report = vec![0_u8; ETHERNET_HEADER_LEN + 40 + 8 + 36];
        report[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        report[14] = 0x60;
        report[18..20].copy_from_slice(&44_u16.to_be_bytes());
        report[20] = 58;
        report[22..38].copy_from_slice(&source.octets());
        report[38..54].copy_from_slice(&group.octets());
        report[54] = 143;
        report[60..62].copy_from_slice(&1_u16.to_be_bytes());
        report[62] = 1;
        report[64..66].copy_from_slice(&1_u16.to_be_bytes());
        report[66..82].copy_from_slice(&group.octets());
        report[82..98].copy_from_slice(&source.octets());
        let checksum = internet_checksum(&[
            &report[22..38],
            &report[38..54],
            &44_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &report[54..98],
        ]);
        report[56..58].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V6(group), true)]
        );
    }

    #[test]
    fn reads_mld_membership_changes() {
        let group: std::net::Ipv6Addr = "ff02::1234".parse().unwrap();
        let mut report = vec![0_u8; 78];
        report[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        report[14] = 0x60;
        report[18..20].copy_from_slice(&24_u16.to_be_bytes());
        report[20] = 58;
        report[54] = 131;
        report[62..78].copy_from_slice(&group.octets());
        let checksum = internet_checksum(&[
            &report[22..38],
            &report[38..54],
            &24_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &report[54..78],
        ]);
        report[56..58].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V6(group), true)]
        );
        assert_eq!(
            multicast_membership_updates_from_ip(&report[ETHERNET_HEADER_LEN..]),
            vec![(std::net::IpAddr::V6(group), true)]
        );

        report[54] = 132;
        report[56..58].fill(0);
        let checksum = internet_checksum(&[
            &report[22..38],
            &report[38..54],
            &24_u32.to_be_bytes(),
            &[0, 0, 0, 58],
            &report[54..78],
        ]);
        report[56..58].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V6(group), false)]
        );
    }
}
