//! Decrypt a QUIC Initial and read the TLS SNI.
//!
//! Nginx `ssl_preread` does this for TCP. Stock stream UDP cannot. The decoy
//! socket uses this so a dumb UDP passthrough can still split VPN traffic from
//! other HTTP/3 sites.

use std::sync::OnceLock;

use rustls::quic::{Suite, Version};

const QUIC_V1: [u8; 4] = [0, 0, 0, 1];
const QUIC_V2: [u8; 4] = [0x6b, 0x33, 0x43, 0xcf];
const HEADER_PROTECTION_SAMPLE: usize = 16;
const MAX_CRYPTO: usize = 16 * 1024;

pub fn quic_initial_sni_eq(packet: &[u8], server_name: &str) -> bool {
    quic_initial_sni(packet).is_some_and(|sni| sni.eq_ignore_ascii_case(server_name))
}

pub fn quic_initial_sni(packet: &[u8]) -> Option<String> {
    let crypto = decrypt_initial_crypto(packet)?;
    tls_client_hello_sni(&crypto)
}

fn initial_suite() -> Suite {
    static SUITE: OnceLock<Suite> = OnceLock::new();
    *SUITE.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .cipher_suites
            .iter()
            .find_map(|cs| match (cs.suite(), cs.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) => tls13.quic_suite(),
                _ => None,
            })
            .expect("ring TLS 1.3 AES-128-GCM provides QUIC initial keys")
    })
}

fn decrypt_initial_crypto(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 7 || packet[0] & 0xc0 != 0xc0 {
        return None;
    }
    let version = packet[1..5].try_into().ok()?;
    let (quic_version, initial_type) = match version {
        QUIC_V1 => (Version::V1, 0x00),
        QUIC_V2 => (Version::V2, 0x10),
        _ => return None,
    };
    if packet[0] & 0x30 != initial_type {
        return None;
    }

    let mut offset = 5;
    let dcid = take_cid(packet, &mut offset)?;
    let _scid = take_cid(packet, &mut offset)?;
    let token_len = get_varint(packet, &mut offset)? as usize;
    offset = offset.checked_add(token_len)?;
    if offset > packet.len() {
        return None;
    }
    let payload_plus_pn = get_varint(packet, &mut offset)? as usize;
    let pn_offset = offset;
    let packet_end = pn_offset.checked_add(payload_plus_pn)?;
    if packet_end > packet.len() || packet_end < pn_offset + 5 + HEADER_PROTECTION_SAMPLE {
        return None;
    }

    let sample_at = pn_offset + 4;
    let sample = packet.get(sample_at..sample_at + HEADER_PROTECTION_SAMPLE)?;
    let keys = initial_suite().keys(dcid, rustls::Side::Server, quic_version);

    let mut first = packet[0];
    let mut pn_sample = packet.get(pn_offset..pn_offset + 4)?.to_vec();
    keys.remote
        .header
        .decrypt_in_place(sample, &mut first, &mut pn_sample)
        .ok()?;
    let pn_len = (first & 0x03) as usize + 1;
    if pn_len > 4 {
        return None;
    }
    let packet_number = packet_number(&pn_sample[..pn_len]);
    let header_len = pn_offset + pn_len;
    if header_len >= packet_end {
        return None;
    }

    let mut header = packet[..header_len].to_vec();
    header[0] = first;
    header[pn_offset..header_len].copy_from_slice(&pn_sample[..pn_len]);

    let mut payload = packet[header_len..packet_end].to_vec();
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, &header, &mut payload)
        .ok()?;
    collect_crypto(plain)
}

fn take_cid<'a>(packet: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = *packet.get(*offset)? as usize;
    if len > 20 {
        return None;
    }
    *offset += 1;
    let start = *offset;
    *offset = offset.checked_add(len)?;
    packet.get(start..*offset)
}

fn get_varint(buf: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *buf.get(*offset)?;
    let len = 1usize << (first >> 6);
    if *offset + len > buf.len() {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[*offset + 1..*offset + len] {
        value = (value << 8) | u64::from(*byte);
    }
    *offset += len;
    Some(value)
}

fn packet_number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

fn collect_crypto(frames: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    let mut crypto = Vec::new();
    while offset < frames.len() {
        let ty = get_varint(frames, &mut offset)?;
        match ty {
            0x00 => {}
            0x01 => {}
            0x06 => {
                let crypto_offset = get_varint(frames, &mut offset)? as usize;
                let length = get_varint(frames, &mut offset)? as usize;
                if crypto_offset > MAX_CRYPTO || length > MAX_CRYPTO {
                    return None;
                }
                let end = offset.checked_add(length)?;
                let data = frames.get(offset..end)?;
                offset = end;
                let needed = crypto_offset.checked_add(data.len())?;
                if needed > MAX_CRYPTO {
                    return None;
                }
                if crypto.len() < needed {
                    crypto.resize(needed, 0);
                }
                crypto[crypto_offset..needed].copy_from_slice(data);
            }
            _ => break,
        }
    }
    (!crypto.is_empty()).then_some(crypto)
}

fn tls_client_hello_sni(crypto: &[u8]) -> Option<String> {
    if crypto.first().copied() != Some(0x01) || crypto.len() < 4 {
        return None;
    }
    let hello_len = u32::from_be_bytes([0, crypto[1], crypto[2], crypto[3]]) as usize;
    let hello = crypto.get(4..4 + hello_len)?;
    if hello.len() < 38 {
        return None;
    }
    let mut offset = 34;
    let session_len = usize::from(*hello.get(offset)?);
    offset += 1 + session_len;
    let suites_len = usize::from(u16::from_be_bytes(
        hello.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 2 + suites_len;
    let compression_len = usize::from(*hello.get(offset)?);
    offset += 1 + compression_len;
    let extensions_len = usize::from(u16::from_be_bytes(
        hello.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    let extensions = hello.get(offset..extensions_end)?;
    let mut ext_off = 0;
    while ext_off + 4 <= extensions.len() {
        let ty = u16::from_be_bytes(extensions[ext_off..ext_off + 2].try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(
            extensions[ext_off + 2..ext_off + 4].try_into().ok()?,
        ));
        ext_off += 4;
        let body = extensions.get(ext_off..ext_off + len)?;
        ext_off += len;
        if ty != 0 {
            continue;
        }
        if body.len() < 5 {
            return None;
        }
        let list_len = usize::from(u16::from_be_bytes(body[0..2].try_into().ok()?));
        let list = body.get(2..2 + list_len)?;
        if list.first().copied() != Some(0) || list.len() < 3 {
            return None;
        }
        let name_len = usize::from(u16::from_be_bytes(list[1..3].try_into().ok()?));
        let name = list.get(3..3 + name_len)?;
        return String::from_utf8(name.to_vec()).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let host = sni.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        let list_len = 1 + 2 + host.len();
        let ext_len = 2 + list_len;
        let exts_len = 2 + 2 + ext_len;
        body.extend_from_slice(&(exts_len as u16).to_be_bytes());
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        body.extend_from_slice(&(list_len as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host);

        let mut message = vec![0x01];
        let len = body.len() as u32;
        message.push((len >> 16) as u8);
        message.push((len >> 8) as u8);
        message.push(len as u8);
        message.extend(body);
        message
    }

    fn put_varint(buf: &mut Vec<u8>, value: u64) {
        if value < 64 {
            buf.push(value as u8);
        } else if value < 16_384 {
            buf.push(0x40 | (value >> 8) as u8);
            buf.push(value as u8);
        } else {
            panic!("test varint is too large");
        }
    }

    fn protect_initial(crypto: &[u8], dcid: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x06];
        put_varint(&mut payload, 0);
        put_varint(&mut payload, crypto.len() as u64);
        payload.extend_from_slice(crypto);

        let pn_len = 1;
        let tag_len = 16;
        let mut header = vec![0xc0];
        header.extend_from_slice(&QUIC_V1);
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0);
        put_varint(&mut header, 0);
        let length_at = header.len();
        header.extend_from_slice(&[0x40, 0]);
        let pn_offset = header.len();
        header.push(0);

        let min_payload = 1200usize.saturating_sub(header.len() + tag_len);
        if payload.len() < min_payload {
            payload.resize(min_payload, 0);
        }

        let length = (pn_len + payload.len() + tag_len) as u64;
        header[length_at] = 0x40 | (length >> 8) as u8;
        header[length_at + 1] = length as u8;

        let keys = initial_suite().keys(dcid, rustls::Side::Client, Version::V1);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(0, &header, &mut payload)
            .expect("protect Initial payload");
        payload.extend_from_slice(tag.as_ref());

        let mut packet = header;
        packet.extend_from_slice(&payload);
        let sample_at = pn_offset + 4;
        let sample = packet[sample_at..sample_at + HEADER_PROTECTION_SAMPLE].to_vec();
        let mut first = packet[0];
        let mut pn = [packet[pn_offset]];
        keys.local
            .header
            .encrypt_in_place(&sample, &mut first, &mut pn)
            .expect("protect Initial header");
        packet[0] = first;
        packet[pn_offset] = pn[0];
        packet
    }

    #[test]
    fn reads_sni_from_a_protected_quic_initial() {
        let hello = handshake_client_hello_with_sni("challenges.cloudflare.com");
        let packet = protect_initial(&hello, b"cidcidcidcidcidc");
        assert!(quic_initial_sni_eq(&packet, "challenges.cloudflare.com"));
        assert!(quic_initial_sni_eq(&packet, "CHALLENGES.CLOUDFLARE.COM"));
        assert!(!quic_initial_sni_eq(&packet, "other.example.com"));
        assert!(quic_initial_sni(&[0xc0, 0, 0, 0, 1, 0]).is_none());
    }
}
