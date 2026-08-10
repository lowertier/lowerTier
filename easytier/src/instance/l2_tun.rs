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
    const ARP_FRAME_LEN: usize = 42;
    const ARP_ETHERTYPE: [u8; 2] = 0x0806_u16.to_be_bytes();
    const ARP_REQUEST_HEADER: [u8; 8] = [0, 1, 0x08, 0, 6, 4, 0, 1];

    if frame.len() < ARP_FRAME_LEN
        || frame[12..14] != ARP_ETHERTYPE
        || frame[14..22] != ARP_REQUEST_HEADER
        || frame[38..42] != local_ipv4.octets()
    {
        return None;
    }

    let requester_mac: [u8; 6] = frame[22..28].try_into().ok()?;
    let requester_ipv4: [u8; 4] = frame[28..32].try_into().ok()?;
    let local_mac = encode_peer_mac(local_peer_id);
    let mut reply = [0_u8; ARP_FRAME_LEN];
    reply[..6].copy_from_slice(&requester_mac);
    reply[6..12].copy_from_slice(&local_mac);
    reply[12..14].copy_from_slice(&ARP_ETHERTYPE);
    reply[14..20].copy_from_slice(&ARP_REQUEST_HEADER[..6]);
    reply[20..22].copy_from_slice(&2_u16.to_be_bytes());
    reply[22..28].copy_from_slice(&local_mac);
    reply[28..32].copy_from_slice(&local_ipv4.octets());
    reply[32..38].copy_from_slice(&requester_mac);
    reply[38..42].copy_from_slice(&requester_ipv4);
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::{
        ETHERNET_HEADER_LEN, EtherType, arp_reply_for_local_ipv4, decapsulate_ip, encode_peer_mac,
        prepare_ip_frame,
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
}
