pub(crate) const ETHERNET_HEADER_LEN: usize = 14;

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
    #[error("Ethernet frame does not contain IPv4 or IPv6")]
    UnsupportedEtherType,
}

pub(crate) fn encode_peer_mac(peer_id: u32) -> [u8; 6] {
    let id = peer_id.to_be_bytes();
    [0x02, 0x45, id[0], id[1], id[2], id[3]]
}

pub(crate) fn prepare_ip_frame(
    frame: &mut [u8],
    source_peer_id: u32,
    destination_peer_id: Option<u32>,
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
    let destination = destination_peer_id
        .map(encode_peer_mac)
        .unwrap_or([0xff; 6]);
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&encode_peer_mac(source_peer_id));
    frame[12..14].copy_from_slice(&(ether_type as u16).to_be_bytes());
    Ok(())
}

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
pub(crate) fn arp_reply_for_local_ipv4(
    frame: &[u8],
    local_peer_id: u32,
    local_ipv4: std::net::Ipv4Addr,
) -> Option<[u8; 42]> {
    arp_reply_for_known_ipv4(frame, local_peer_id, local_ipv4)
}

pub(crate) fn arp_reply_for_known_ipv4(
    frame: &[u8],
    target_peer_id: u32,
    target_ipv4: std::net::Ipv4Addr,
) -> Option<[u8; 42]> {
    const ARP_FRAME_LEN: usize = 42;
    const ARP_ETHERTYPE: [u8; 2] = 0x0806_u16.to_be_bytes();
    const ARP_REQUEST_HEADER: [u8; 8] = [0, 1, 0x08, 0, 6, 4, 0, 1];

    if frame.len() < ARP_FRAME_LEN
        || frame[12..14] != ARP_ETHERTYPE
        || frame[14..22] != ARP_REQUEST_HEADER
        || frame[38..42] != target_ipv4.octets()
    {
        return None;
    }

    let requester_mac: [u8; 6] = frame[22..28].try_into().ok()?;
    let requester_ipv4: [u8; 4] = frame[28..32].try_into().ok()?;
    let target_mac = encode_peer_mac(target_peer_id);
    let mut reply = [0_u8; ARP_FRAME_LEN];
    reply[..6].copy_from_slice(&requester_mac);
    reply[6..12].copy_from_slice(&target_mac);
    reply[12..14].copy_from_slice(&ARP_ETHERTYPE);
    reply[14..20].copy_from_slice(&ARP_REQUEST_HEADER[..6]);
    reply[20..22].copy_from_slice(&2_u16.to_be_bytes());
    reply[22..28].copy_from_slice(&target_mac);
    reply[28..32].copy_from_slice(&target_ipv4.octets());
    reply[32..38].copy_from_slice(&requester_mac);
    reply[38..42].copy_from_slice(&requester_ipv4);
    Some(reply)
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

pub(crate) fn ndp_reply_for_known_ipv6(
    frame: &[u8],
    target_peer_id: u32,
    target_ipv6: std::net::Ipv6Addr,
) -> Option<[u8; 86]> {
    const FRAME_LEN: usize = 86;
    const IPV6_OFFSET: usize = ETHERNET_HEADER_LEN;
    const ICMP_OFFSET: usize = IPV6_OFFSET + 40;
    if frame.len() < FRAME_LEN
        || frame[12..14] != 0x86dd_u16.to_be_bytes()
        || frame[IPV6_OFFSET] >> 4 != 6
        || frame[IPV6_OFFSET + 6] != 58
        || frame[IPV6_OFFSET + 7] != 255
        || frame[ICMP_OFFSET] != 135
        || frame[ICMP_OFFSET + 1] != 0
        || frame[ICMP_OFFSET + 8..ICMP_OFFSET + 24] != target_ipv6.octets()
    {
        return None;
    }

    let requester_mac: [u8; 6] = frame[6..12].try_into().ok()?;
    let requester_ip: [u8; 16] = frame[IPV6_OFFSET + 8..IPV6_OFFSET + 24].try_into().ok()?;
    if requester_ip == [0; 16] {
        return None;
    }
    let target_mac = encode_peer_mac(target_peer_id);
    let mut reply = [0_u8; FRAME_LEN];
    reply[..6].copy_from_slice(&requester_mac);
    reply[6..12].copy_from_slice(&target_mac);
    reply[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    reply[IPV6_OFFSET] = 0x60;
    reply[IPV6_OFFSET + 4..IPV6_OFFSET + 6].copy_from_slice(&32_u16.to_be_bytes());
    reply[IPV6_OFFSET + 6] = 58;
    reply[IPV6_OFFSET + 7] = 255;
    reply[IPV6_OFFSET + 8..IPV6_OFFSET + 24].copy_from_slice(&target_ipv6.octets());
    reply[IPV6_OFFSET + 24..IPV6_OFFSET + 40].copy_from_slice(&requester_ip);
    reply[ICMP_OFFSET] = 136;
    reply[ICMP_OFFSET + 4..ICMP_OFFSET + 8].copy_from_slice(&0x6000_0000_u32.to_be_bytes());
    reply[ICMP_OFFSET + 8..ICMP_OFFSET + 24].copy_from_slice(&target_ipv6.octets());
    reply[ICMP_OFFSET + 24] = 2;
    reply[ICMP_OFFSET + 25] = 1;
    reply[ICMP_OFFSET + 26..ICMP_OFFSET + 32].copy_from_slice(&target_mac);

    let payload_len = 32_u32.to_be_bytes();
    let next_header = [0_u8, 0, 0, 58];
    let checksum = internet_checksum(&[
        &reply[IPV6_OFFSET + 8..IPV6_OFFSET + 24],
        &reply[IPV6_OFFSET + 24..IPV6_OFFSET + 40],
        &payload_len,
        &next_header,
        &reply[ICMP_OFFSET..],
    ]);
    reply[ICMP_OFFSET + 2..ICMP_OFFSET + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

const MAX_MEMBERSHIP_UPDATES_PER_FRAME: usize = 256;

pub(crate) fn multicast_membership_updates(frame: &[u8]) -> Vec<(std::net::IpAddr, bool)> {
    let Some(ether_type) = frame.get(12..14) else {
        return Vec::new();
    };
    match ether_type {
        [0x08, 0x00] => ipv4_membership_updates(frame),
        [0x86, 0xdd] => ipv6_membership_updates(frame),
        _ => Vec::new(),
    }
}

fn ipv4_membership_updates(frame: &[u8]) -> Vec<(std::net::IpAddr, bool)> {
    let Some(first) = frame.get(ETHERNET_HEADER_LEN) else {
        return Vec::new();
    };
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < 20 || frame.get(ETHERNET_HEADER_LEN + 9) != Some(&2) {
        return Vec::new();
    }
    let offset = ETHERNET_HEADER_LEN + header_len;
    let Some(message_type) = frame.get(offset).copied() else {
        return Vec::new();
    };
    if matches!(message_type, 0x16 | 0x17) {
        let Some(group) = frame
            .get(offset + 4..offset + 8)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(std::net::Ipv4Addr::from)
        else {
            return Vec::new();
        };
        return vec![(std::net::IpAddr::V4(group), message_type == 0x16)];
    }
    if message_type != 0x22 {
        return Vec::new();
    }

    let record_count = frame
        .get(offset + 6..offset + 8)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .unwrap_or(0)
        .min(MAX_MEMBERSHIP_UPDATES_PER_FRAME);
    let mut cursor = offset + 8;
    let mut updates = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let Some(record) = frame.get(cursor..cursor + 8) else {
            break;
        };
        let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
        let record_len = 8 + source_count * 4 + usize::from(record[1]) * 4;
        let Some(group) = <[u8; 4]>::try_from(&record[4..8])
            .ok()
            .map(std::net::Ipv4Addr::from)
        else {
            break;
        };
        let joined = !matches!(record[0], 1 | 3) || source_count != 0;
        updates.push((std::net::IpAddr::V4(group), joined));
        let Some(next) = cursor.checked_add(record_len) else {
            break;
        };
        cursor = next;
    }
    updates
}

fn ipv6_membership_updates(frame: &[u8]) -> Vec<(std::net::IpAddr, bool)> {
    let ipv6_offset = ETHERNET_HEADER_LEN;
    let Some(ipv6_header) = frame.get(ipv6_offset..ipv6_offset + 40) else {
        return Vec::new();
    };
    if ipv6_header[0] >> 4 != 6 {
        return Vec::new();
    }
    let mut next_header = ipv6_header[6];
    let mut offset = ipv6_offset + 40;
    for _ in 0..4 {
        if next_header == 58 {
            break;
        }
        if !matches!(next_header, 0 | 43 | 60) {
            return Vec::new();
        }
        let Some(header) = frame.get(offset..offset + 2) else {
            return Vec::new();
        };
        next_header = header[0];
        offset += (usize::from(header[1]) + 1) * 8;
    }
    if next_header != 58 {
        return Vec::new();
    }
    let Some(message_type) = frame.get(offset).copied() else {
        return Vec::new();
    };
    if matches!(message_type, 131 | 132) {
        let Some(group) = frame
            .get(offset + 8..offset + 24)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .map(std::net::Ipv6Addr::from)
        else {
            return Vec::new();
        };
        return vec![(std::net::IpAddr::V6(group), message_type == 131)];
    }
    if message_type != 143 {
        return Vec::new();
    }

    let record_count = frame
        .get(offset + 6..offset + 8)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .unwrap_or(0)
        .min(MAX_MEMBERSHIP_UPDATES_PER_FRAME);
    let mut cursor = offset + 8;
    let mut updates = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let Some(record) = frame.get(cursor..cursor + 20) else {
            break;
        };
        let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
        let record_len = 20 + source_count * 16 + usize::from(record[1]) * 4;
        let Some(group) = <[u8; 16]>::try_from(&record[4..20])
            .ok()
            .map(std::net::Ipv6Addr::from)
        else {
            break;
        };
        let joined = !matches!(record[0], 1 | 3) || source_count != 0;
        updates.push((std::net::IpAddr::V6(group), joined));
        let Some(next) = cursor.checked_add(record_len) else {
            break;
        };
        cursor = next;
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::{
        ETHERNET_HEADER_LEN, EtherType, arp_reply_for_known_ipv4, arp_reply_for_local_ipv4,
        decapsulate_ip, encode_peer_mac, internet_checksum, multicast_membership_updates,
        ndp_reply_for_known_ipv6, prepare_ip_frame,
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
    fn reads_igmp_membership_changes() {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let mut report = vec![0_u8; 42];
        report[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        report[14] = 0x45;
        report[23] = 2;
        report[34] = 0x16;
        report[38..42].copy_from_slice(&group.octets());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), true)]
        );

        report[34] = 0x17;
        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V4(group), false)]
        );
    }

    #[test]
    fn reads_mld_membership_changes() {
        let group: std::net::Ipv6Addr = "ff02::1234".parse().unwrap();
        let mut report = vec![0_u8; 78];
        report[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        report[14] = 0x60;
        report[20] = 58;
        report[54] = 131;
        report[62..78].copy_from_slice(&group.octets());

        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V6(group), true)]
        );

        report[54] = 132;
        assert_eq!(
            multicast_membership_updates(&report),
            vec![(std::net::IpAddr::V6(group), false)]
        );
    }
}
