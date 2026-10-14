//! Tracker records contain candidates. They never authenticate a VPN peer.
use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const CONNECT_MAGIC: u64 = 0x41727101980;
pub const MAX_PEERS: usize = 16;
pub const MAX_RESPONSE: usize = 16 * 1024;
pub const IDLE_ANNOUNCE_INTERVAL_SECS: u32 = 30;
pub type Id = [u8; 20];
pub const ECHO_MAGIC: &[u8; 4] = b"LTO1";

pub fn observed_connect(packet: &[u8]) -> Result<Option<SocketAddr>> {
    if packet.get(16..20) != Some(ECHO_MAGIC) {
        return Ok(None);
    }
    ensure!(packet.len() >= 23, "short observed endpoint");
    let ip = match packet[20] {
        4 if packet.len() == 27 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[23..])?)),
        6 if packet.len() == 39 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[23..])?)),
        _ => bail!("invalid observed endpoint"),
    };
    Ok(Some(SocketAddr::new(
        ip,
        u16::from_be_bytes(packet[21..23].try_into()?),
    )))
}

// BEP 41 URLData options start after the standard 98-byte announce request.
pub fn append_url_data(packet: &mut Vec<u8>, target: &str) -> Result<()> {
    ensure!(target.len() <= 1024, "tracker URL data too large");
    for chunk in target.as_bytes().chunks(255) {
        packet.extend_from_slice(&[2, chunk.len() as u8]);
        packet.extend_from_slice(chunk);
    }
    Ok(())
}

pub fn url_data(packet: &[u8]) -> Result<String> {
    ensure!(packet.len() >= 98, "short tracker announce");
    let mut data = Vec::new();
    let mut offset = 98;
    while offset < packet.len() {
        let kind = packet[offset];
        offset += 1;
        if kind == 0 {
            break;
        }
        if kind == 1 {
            continue;
        }
        let length = usize::from(*packet.get(offset).context("short tracker option")?);
        offset += 1;
        let value = packet
            .get(offset..offset + length)
            .context("truncated tracker option")?;
        if kind == 2 {
            ensure!(data.len() + length <= 1024, "tracker URL data too large");
            data.extend_from_slice(value);
        }
        offset += length;
    }
    Ok(String::from_utf8(data)?)
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn rendezvous_id(key: &[u8], protocol: &str) -> Id {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"vpn-rendezvous-v1");
    // Compact tracker entries cannot identify the transport of an advertised port.
    if protocol != "quic" {
        mac.update(b"\0transport=");
        mac.update(protocol.as_bytes());
    }
    mac.finalize().into_bytes()[..20].try_into().unwrap()
}

pub fn connect_request(transaction: u32) -> [u8; 16] {
    let mut packet = [0; 16];
    packet[..8].copy_from_slice(&CONNECT_MAGIC.to_be_bytes());
    packet[12..].copy_from_slice(&transaction.to_be_bytes());
    packet
}

pub fn response_header(packet: &[u8], action: u32, transaction: u32) -> Result<()> {
    ensure!(
        packet.len() >= 8 && packet.len() <= MAX_RESPONSE,
        "invalid tracker response length"
    );
    ensure!(
        u32::from_be_bytes(packet[4..8].try_into()?) == transaction,
        "tracker transaction mismatch"
    );
    let received = u32::from_be_bytes(packet[..4].try_into()?);
    if received == 3 {
        bail!(
            "tracker error: {}",
            String::from_utf8_lossy(&packet[8..packet.len().min(264)])
        );
    }
    ensure!(received == action, "tracker action mismatch");
    Ok(())
}

pub fn connect_response(packet: &[u8], transaction: u32) -> Result<u64> {
    response_header(packet, 0, transaction)?;
    ensure!(packet.len() >= 16, "short tracker connect response");
    Ok(u64::from_be_bytes(packet[8..16].try_into()?))
}

#[derive(Clone, Debug)]
pub struct Announce {
    pub hash: Id,
    pub peer: Id,
    pub key: u32,
    pub port: u16,
    pub event: u32,
    // Both values stay nonzero to retain leecher discovery on public trackers.
    pub left: u64,
    pub numwant: i32,
}

impl Announce {
    pub fn udp(&self, connection: u64, transaction: u32) -> [u8; 98] {
        let mut packet = [0; 98];
        packet[..8].copy_from_slice(&connection.to_be_bytes());
        packet[8..12].copy_from_slice(&1u32.to_be_bytes());
        packet[12..16].copy_from_slice(&transaction.to_be_bytes());
        packet[16..36].copy_from_slice(&self.hash);
        packet[36..56].copy_from_slice(&self.peer);
        packet[64..72].copy_from_slice(&self.left.to_be_bytes());
        packet[80..84].copy_from_slice(&self.event.to_be_bytes());
        packet[88..92].copy_from_slice(&self.key.to_be_bytes());
        packet[92..96].copy_from_slice(&self.numwant.to_be_bytes());
        packet[96..98].copy_from_slice(&self.port.to_be_bytes());
        packet
    }

    pub fn http_query(&self) -> String {
        fn escape(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("%{byte:02X}")).collect()
        }
        let event = match self.event {
            2 => "started",
            3 => "stopped",
            _ => "",
        };
        format!(
            "info_hash={}&peer_id={}&port={}&key={}&uploaded=0&downloaded=0&left={}&compact=1&numwant={}&event={event}",
            escape(&self.hash),
            escape(&self.peer),
            self.port,
            self.key,
            self.left,
            self.numwant
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct Peers {
    pub interval: u32,
    pub addresses: Vec<SocketAddr>,
    pub observed: Option<SocketAddr>,
}

pub fn compact(bytes: &[u8], ipv6: bool) -> Result<Vec<SocketAddr>> {
    let stride = if ipv6 { 18 } else { 6 };
    ensure!(
        bytes.len().is_multiple_of(stride),
        "truncated compact peer list"
    );
    let mut peers = Vec::new();
    for entry in bytes.chunks_exact(stride) {
        let ip = if ipv6 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&entry[..16])?))
        } else {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&entry[..4])?))
        };
        let port = u16::from_be_bytes(entry[stride - 2..].try_into()?);
        if port == 0 || ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST {
            continue;
        }
        let address = SocketAddr::new(ip, port);
        if !peers.contains(&address) {
            peers.push(address);
        }
        if peers.len() == MAX_PEERS {
            break;
        }
    }
    Ok(peers)
}

pub fn announce_response(packet: &[u8], transaction: u32, ipv6: bool) -> Result<Peers> {
    response_header(packet, 1, transaction)?;
    ensure!(packet.len() >= 20, "short tracker announce response");
    let interval = u32::from_be_bytes(packet[8..12].try_into()?);
    ensure!(interval > 0, "tracker interval is zero");
    Ok(Peers {
        interval,
        addresses: compact(&packet[20..], ipv6)?,
        observed: None,
    })
}

struct Bencode<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Bencode<'a> {
    fn peers(&mut self) -> Result<Vec<SocketAddr>> {
        if self.peek()? != b'l' {
            return compact(self.string()?, false);
        }
        self.offset += 1;
        let mut peers = Vec::new();
        while self.peek()? != b'e' {
            ensure!(self.peek()? == b'd', "invalid tracker peer dictionary");
            self.offset += 1;
            let (mut ip, mut port) = (None, None);
            while self.peek()? != b'e' {
                match self.string()? {
                    b"ip" => {
                        ip = Some(std::str::from_utf8(self.string()?)?.parse::<IpAddr>()?);
                    }
                    b"port" => {
                        port = Some(u16::try_from(self.integer()?)?);
                    }
                    _ => self.skip(1)?,
                }
            }
            self.offset += 1;
            let address = SocketAddr::new(
                ip.context("missing peer IP")?,
                port.context("missing peer port")?,
            );
            if peers.len() < MAX_PEERS
                && address.port() != 0
                && !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && address.ip() != Ipv4Addr::BROADCAST
                && !peers.contains(&address)
            {
                peers.push(address);
            }
        }
        self.offset += 1;
        Ok(peers)
    }
    fn peek(&self) -> Result<u8> {
        self.bytes
            .get(self.offset)
            .copied()
            .context("truncated bencode")
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let start = self.offset;
        while self.peek()?.is_ascii_digit() {
            self.offset += 1;
        }
        ensure!(
            self.peek()? == b':' && self.offset > start,
            "invalid bencode string"
        );
        let length = std::str::from_utf8(&self.bytes[start..self.offset])?.parse::<usize>()?;
        self.offset += 1;
        let end = self
            .offset
            .checked_add(length)
            .context("bencode length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("short bencode string")?;
        self.offset = end;
        Ok(value)
    }
    fn integer(&mut self) -> Result<i64> {
        ensure!(self.peek()? == b'i', "expected bencode integer");
        self.offset += 1;
        let start = self.offset;
        while self.peek()? != b'e' {
            self.offset += 1;
        }
        let value = std::str::from_utf8(&self.bytes[start..self.offset])?.parse()?;
        self.offset += 1;
        Ok(value)
    }
    fn skip(&mut self, depth: usize) -> Result<()> {
        ensure!(depth <= 8, "bencode nesting limit");
        match self.peek()? {
            b'i' => {
                self.integer()?;
            }
            b'0'..=b'9' => {
                self.string()?;
            }
            b'l' | b'd' => {
                let dictionary = self.peek()? == b'd';
                self.offset += 1;
                while self.peek()? != b'e' {
                    if dictionary {
                        self.string()?;
                    }
                    self.skip(depth + 1)?;
                }
                self.offset += 1;
            }
            _ => bail!("invalid bencode value"),
        }
        Ok(())
    }
}

pub fn http_response(bytes: &[u8]) -> Result<Peers> {
    ensure!(
        bytes.len() <= MAX_RESPONSE,
        "HTTP tracker response too large"
    );
    let mut parser = Bencode { bytes, offset: 0 };
    ensure!(
        parser.peek()? == b'd',
        "tracker response is not a dictionary"
    );
    parser.offset += 1;
    let mut interval = None;
    let mut minimum = 0;
    let mut addresses = Vec::new();
    let mut observed = None;
    while parser.peek()? != b'e' {
        match parser.string()? {
            b"failure reason" => bail!(
                "tracker error: {}",
                String::from_utf8_lossy(parser.string()?)
            ),
            b"interval" => {
                interval = Some(u32::try_from(parser.integer()?)?);
            }
            b"min interval" => {
                minimum = u32::try_from(parser.integer()?)?;
            }
            b"peers" => addresses.extend(parser.peers()?),
            b"peers6" => addresses.extend(compact(parser.string()?, true)?),
            b"lt_observed" => observed = Some(std::str::from_utf8(parser.string()?)?.parse()?),
            _ => parser.skip(0)?,
        }
    }
    parser.offset += 1;
    ensure!(parser.offset == bytes.len(), "trailing tracker data");
    let interval = interval
        .filter(|value| *value > 0)
        .context("missing tracker interval")?;
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(MAX_PEERS);
    Ok(Peers {
        interval: interval.max(minimum),
        addresses,
        observed,
    })
}

pub const PUNCH_BYTES: usize = 65;
pub const PUNCH_MAGIC: [u8; 4] = [0, b'L', b'T', 1];

pub fn punch(key: &[u8], peer: u32, nonce: [u8; 16], now: u64, reply: bool) -> [u8; PUNCH_BYTES] {
    let mut bytes = [0; PUNCH_BYTES];
    bytes[..4].copy_from_slice(&PUNCH_MAGIC);
    bytes[4] = u8::from(reply);
    bytes[5..9].copy_from_slice(&peer.to_be_bytes());
    bytes[9..25].copy_from_slice(&nonce);
    bytes[25..33].copy_from_slice(&now.to_be_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"vpn-punch-v1\0");
    mac.update(&bytes[..33]);
    bytes[33..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

pub fn read_punch(bytes: &[u8], key: &[u8], now: u64) -> Result<(u32, [u8; 16], bool)> {
    ensure!(
        bytes.len() == PUNCH_BYTES && bytes[..4] == PUNCH_MAGIC && bytes[4] <= 1,
        "invalid punch packet"
    );
    let sent = u64::from_be_bytes(bytes[25..33].try_into()?);
    ensure!(now.abs_diff(sent) <= 60, "expired punch packet");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"vpn-punch-v1\0");
    mac.update(&bytes[..33]);
    mac.verify_slice(&bytes[33..])
        .map_err(|_| anyhow::anyhow!("invalid punch authentication"))?;
    Ok((
        u32::from_be_bytes(bytes[5..9].try_into()?),
        bytes[9..25].try_into()?,
        bytes[4] != 0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bep15_layout_and_response_validation() {
        let request = Announce {
            hash: [1; 20],
            peer: [2; 20],
            key: 7,
            port: 43821,
            event: 2,
            left: 1,
            numwant: MAX_PEERS as i32,
        };
        let packet = request.udp(23, 42);
        assert_eq!(packet.len(), 98);
        assert_eq!(&packet[84..88], &[0; 4]);
        assert_eq!(&packet[96..], &43821u16.to_be_bytes());
        assert_eq!(&packet[64..72], &1u64.to_be_bytes());
        let mut reply = Vec::from([0, 0, 0, 1, 0, 0, 0, 42, 0, 0, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        reply.extend_from_slice(&[192, 0, 2, 1, 0x12, 0x34]);
        assert_eq!(
            announce_response(&reply, 42, false).unwrap().addresses,
            vec!["192.0.2.1:4660".parse().unwrap()]
        );
        assert!(announce_response(&reply, 43, false).is_err());
        assert!(announce_response(&reply[..25], 42, false).is_err());
        assert!(announce_response(&reply, 42, true).is_err());
        let mut packet = packet.to_vec();
        let target = format!("/announce?passkey={}", "a".repeat(300));
        append_url_data(&mut packet, &target).unwrap();
        assert_eq!(url_data(&packet).unwrap(), target);
        packet.pop();
        assert!(url_data(&packet).is_err());

        let request = crate::binding::request(&[7; 12]);
        for source in ["192.0.2.1:3456", "[2001:db8::1]:3456"] {
            let source: SocketAddr = source.parse().unwrap();
            let (reply, changed) = crate::binding::response(&request, source, false).unwrap();
            assert!(!changed);
            assert_eq!(&reply[..2], &[1, 1]);
            assert_eq!(reply.len(), if source.is_ipv4() { 32 } else { 44 });
            assert_eq!(
                u16::from_be_bytes(reply[26..28].try_into().unwrap()) ^ 0x2112,
                source.port()
            );
            if let IpAddr::V6(ip) = source.ip() {
                let decoded: Vec<_> = reply[28..]
                    .iter()
                    .zip(&request[4..])
                    .map(|(octet, mask)| octet ^ mask)
                    .collect();
                assert_eq!(decoded, ip.octets());
            }
        }
        let source = "192.0.2.1:3456".parse().unwrap();
        let mut change = request.to_vec();
        change[3] = 8;
        change.extend_from_slice(&[0, 3, 0, 4, 0, 0, 0, 2]);
        assert!(crate::binding::response(&change, source, false).is_none());
        assert!(crate::binding::response(&change, source, true).unwrap().1);
        change[27] = 6;
        assert!(crate::binding::response(&change, source, true).is_none());
    }

    #[test]
    fn compact_http_is_bounded_and_transport_namespaces_differ() {
        let dictionary = b"d8:intervali1800e5:peersld2:ip9:127.0.0.14:porti1234eeee";
        assert_eq!(
            http_response(dictionary).unwrap().addresses,
            vec!["127.0.0.1:1234".parse().unwrap()]
        );
        let response = b"d8:intervali1800e5:peers6:\xc0\x00\x02\x01\x12\x34e";
        assert_eq!(http_response(response).unwrap().addresses.len(), 1);
        for end in 0..response.len() {
            assert!(http_response(&response[..end]).is_err());
        }
        assert!(http_response(b"d8:intervali0e5:peers0:e").is_err());
        assert_ne!(
            rendezvous_id(b"secret", "quic"),
            rendezvous_id(b"secret", "tcp")
        );
        assert_ne!(
            rendezvous_id(b"secret", "quic"),
            rendezvous_id(b"other", "quic")
        );
        let mut packet = punch(b"key", 17, [8; 16], 100, false);
        assert_eq!(
            read_punch(&packet, b"key", 110).unwrap(),
            (17, [8; 16], false)
        );
        assert!(read_punch(&packet, b"key", 161).is_err());
        packet[5] ^= 1;
        assert!(read_punch(&packet, b"key", 110).is_err());
    }
}
