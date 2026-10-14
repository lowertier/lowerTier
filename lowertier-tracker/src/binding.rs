//! Bounded STUN Binding codec shared by rendezvous and authenticated peer probes.
use std::net::{IpAddr, SocketAddr};

pub const MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub const MAX_MESSAGE: usize = 20 + 512;

pub fn request(transaction: &[u8; 12]) -> [u8; 20] {
    let mut packet = [0; 20];
    packet[1] = 1;
    packet[4..8].copy_from_slice(&MAGIC);
    packet[8..20].copy_from_slice(transaction);
    packet
}

pub fn response(packet: &[u8], source: SocketAddr, alternate: bool) -> Option<(Vec<u8>, bool)> {
    if packet.len() < 20
        || packet.len() > MAX_MESSAGE
        || packet[..2] != [0, 1]
        || packet[4..8] != MAGIC
        || usize::from(u16::from_be_bytes(packet[2..4].try_into().ok()?)) != packet.len() - 20
        || !(packet.len() - 20).is_multiple_of(4)
    {
        return None;
    }
    let mut offset = 20;
    let mut change_port = false;
    while offset < packet.len() {
        let kind = u16::from_be_bytes(packet.get(offset..offset + 2)?.try_into().ok()?);
        let length = usize::from(u16::from_be_bytes(
            packet.get(offset + 2..offset + 4)?.try_into().ok()?,
        ));
        let value = packet.get(offset + 4..offset + 4 + length)?;
        if kind == 3 {
            let flags = u32::from_be_bytes(value.try_into().ok()?);
            if flags & !2 != 0 || (flags != 0 && !alternate) {
                return None;
            }
            change_port = flags == 2;
        } else if kind < 0x8000 && kind != 0x26 {
            return None;
        }
        offset = (offset + 4 + length + 3) & !3;
    }
    if offset != packet.len() || source.port() == 0 {
        return None;
    }
    let mut reply = packet[..20].to_vec();
    reply[..2].copy_from_slice(&[1, 1]);
    let address = match source.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let length = 4 + address.len();
    reply[2..4].copy_from_slice(&((length + 4) as u16).to_be_bytes());
    reply.extend_from_slice(&[
        0,
        0x20,
        0,
        length as u8,
        0,
        if source.is_ipv4() { 1 } else { 2 },
    ]);
    reply.extend_from_slice(&(source.port() ^ 0x2112).to_be_bytes());
    reply.extend(
        address
            .iter()
            .zip(&packet[4..20])
            .map(|(octet, mask)| octet ^ mask),
    );
    Some((reply, change_port))
}
