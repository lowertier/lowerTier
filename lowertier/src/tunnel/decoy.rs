//! Process-wide limits for unauthenticated decoy forwarding only.
//!
//! TCP and UDP, both directions and all listeners/instances share these budgets.
//! Never reset an IP's burst when a connection closes. UDP ingress is policed,
//! responses are paced with bounded buffering; TCP waits and applies backpressure.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use parking_lot::Mutex;
use tokio::time::Instant;

const MAX_IPS: usize = 4096;
const MAX_FLOWS: usize = 128;
const MAX_IP_FLOWS: usize = 8;
const IP_RETENTION: Duration = Duration::from_secs(60);
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const FLOW_LIFETIME: Duration = Duration::from_secs(300);
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct Limits {
    bytes_per_second: u64,
    burst: u64,
    ip_bytes_per_second: u64,
    ip_burst: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes_per_second: 1024 * 1024,
            burst: 256 * 1024,
            ip_bytes_per_second: 128 * 1024,
            ip_burst: 64 * 1024,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn new(rate: u64, capacity: u64, now: Instant) -> Self {
        Self {
            rate: rate as f64,
            capacity: capacity as f64,
            tokens: capacity as f64,
            updated: now,
        }
    }

    fn delay(&mut self, amount: usize, now: Instant) -> Duration {
        self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.updated = now;
        Duration::from_secs_f64(((amount as f64 - self.tokens) / self.rate).max(0.0))
    }

    fn take(&mut self, amount: usize) {
        self.tokens -= amount as f64;
    }
}

#[derive(Debug)]
struct Source {
    bytes: Bucket,
    packets: Bucket,
    opens: Bucket,
    active: usize,
    used: Instant,
}

#[derive(Debug)]
struct State {
    bytes: Bucket,
    packets: Bucket,
    opens: Bucket,
    sources: HashMap<IpAddr, Source>,
    active: usize,
    cleaned: Instant,
}

pub(super) struct DecoyLimiter {
    limits: Limits,
    state: Mutex<State>,
}

pub(super) struct DecoyPermit {
    limiter: Arc<DecoyLimiter>,
    ip: IpAddr,
}

pub(super) fn process_limiter() -> Arc<DecoyLimiter> {
    static LIMITER: OnceLock<Arc<DecoyLimiter>> = OnceLock::new();
    LIMITER
        .get_or_init(|| DecoyLimiter::new(Limits::default()))
        .clone()
}

fn source_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

impl DecoyLimiter {
    fn new(limits: Limits) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            limits,
            state: Mutex::new(State {
                bytes: Bucket::new(limits.bytes_per_second, limits.burst, now),
                packets: Bucket::new(4096, 512, now),
                opens: Bucket::new(16, 32, now),
                sources: HashMap::new(),
                active: 0,
                cleaned: now,
            }),
        })
    }

    pub(super) fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<DecoyPermit> {
        self.admit_at(source_ip(ip), Instant::now())
    }

    fn admit_at(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Option<DecoyPermit> {
        let mut state = self.state.lock();
        if now.duration_since(state.cleaned) >= IP_RETENTION {
            state.sources.retain(|_, source| {
                source.active != 0 || now.duration_since(source.used) < IP_RETENTION
            });
            state.cleaned = now;
        }
        if state.active >= MAX_FLOWS || !state.opens.delay(1, now).is_zero() {
            return None;
        }
        if !state.sources.contains_key(&ip) && state.sources.len() >= MAX_IPS {
            return None;
        }
        let source = state.sources.entry(ip).or_insert_with(|| Source {
            bytes: Bucket::new(self.limits.ip_bytes_per_second, self.limits.ip_burst, now),
            packets: Bucket::new(512, 128, now),
            opens: Bucket::new(4, 8, now),
            active: 0,
            used: now,
        });
        source.used = now;
        if source.active >= MAX_IP_FLOWS || !source.opens.delay(1, now).is_zero() {
            return None;
        }
        source.opens.take(1);
        source.active += 1;
        state.opens.take(1);
        state.active += 1;
        Some(DecoyPermit {
            limiter: self.clone(),
            ip,
        })
    }
}

impl DecoyPermit {
    fn delay_at(&self, bytes: usize, udp: bool, now: Instant) -> Duration {
        let mut state = self.limiter.state.lock();
        let global = state.bytes.delay(bytes, now);
        let packets = if udp {
            state.packets.delay(1, now)
        } else {
            Duration::ZERO
        };
        let source = state
            .sources
            .get_mut(&self.ip)
            .expect("live permit keeps source");
        source.used = now;
        let mut delay = global.max(packets).max(source.bytes.delay(bytes, now));
        if udp {
            delay = delay.max(source.packets.delay(1, now));
        }
        // Charge both budgets atomically, only if both allow the operation.
        if delay.is_zero() {
            source.bytes.take(bytes);
            if udp {
                source.packets.take(1);
            }
            state.bytes.take(bytes);
            if udp {
                state.packets.take(1);
            }
        }
        delay
    }

    pub(super) fn allow_datagram(&self, bytes: usize) -> bool {
        self.delay_at(bytes, true, Instant::now()).is_zero()
    }

    pub(super) async fn wait(&self, bytes: usize) {
        self.wait_for(bytes, false).await;
    }

    pub(super) async fn pace_datagram(&self, bytes: usize) {
        self.wait_for(bytes, true).await;
    }

    async fn wait_for(&self, bytes: usize, udp: bool) {
        loop {
            let delay = self.delay_at(bytes, udp, Instant::now());
            if delay.is_zero() {
                return;
            }
            tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
        }
    }
}

impl Drop for DecoyPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock();
        state.active -= 1;
        let source = state
            .sources
            .get_mut(&self.ip)
            .expect("live permit keeps source");
        source.active -= 1;
        source.used = Instant::now();
    }
}

pub(super) async fn copy_tcp<R, W>(
    mut reader: R,
    mut writer: W,
    permit: &DecoyPermit,
    activity: &tokio::sync::Notify,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = [0; 16 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            return writer.shutdown().await;
        }
        activity.notify_one();
        permit.wait(length).await;
        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&buffer[..length])).await??;
        activity.notify_one();
    }
}

pub(super) async fn tcp_idle(activity: &tokio::sync::Notify, timeout: Duration) {
    // Idle is shared by both directions: a long download must not be killed
    // merely because the client has already finished sending its request.
    while tokio::time::timeout(timeout, activity.notified())
        .await
        .is_ok()
    {}
}

// Only supported QUIC long headers may establish decoy state. Checking the
// cleartext header is NOT authentication; the fixed upstream remains trusted.
struct LongHeader<'a> {
    version: u32,
    kind: u8,
    dcid: &'a [u8],
    scid: &'a [u8],
    payload: &'a [u8],
}

fn long_header(packet: &[u8]) -> Option<LongHeader<'_>> {
    // RFC 9287 permits either value of the QUIC bit (0x40), including in
    // Initial/Handshake/Retry packets. Only the long-header bit is invariant.
    if packet.first()? & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    let kind = (packet[0] >> 4) & 3;
    let kind = match version {
        1 => kind,
        0x6b3343cf => (kind + 3) % 4, // QUIC v2 rotates the packet types.
        _ => return None,
    };
    let dcid_len = usize::from(*packet.get(5)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(6..6 + dcid_len)?;
    let scid_len = usize::from(*packet.get(6 + dcid_len)?);
    if scid_len > 20 {
        return None;
    }
    let end = 7 + dcid_len + scid_len;
    Some(LongHeader {
        version,
        kind,
        dcid,
        scid: packet.get(7 + dcid_len..end)?,
        payload: packet.get(end..)?,
    })
}

fn varint(bytes: &mut &[u8]) -> Option<usize> {
    let length = 1 << (bytes.first()? >> 6);
    let mut value = u64::from(bytes.first()? & 0x3f);
    for byte in bytes.get(1..length)? {
        value = (value << 8) | u64::from(*byte);
    }
    *bytes = bytes.get(length..)?;
    usize::try_from(value).ok()
}

pub(super) fn is_quic_initial(packet: &[u8]) -> bool {
    let Some(header) = long_header(packet) else {
        return false;
    };
    if packet.len() < 1200 || header.kind != 0 || header.dcid.len() < 8 {
        return false;
    }
    let mut payload = header.payload;
    let Some(token_len) = varint(&mut payload) else {
        return false;
    };
    let Some(rest) = payload.get(token_len..) else {
        return false;
    };
    payload = rest;
    let Some(length) = varint(&mut payload) else {
        return false;
    };
    // At least a packet number and AEAD tag, within the received datagram.
    length >= 17 && length <= payload.len()
}

/// Before a client echoes an upstream-selected CID, return no more bytes OR
/// packets than it sent (1x, including IPv4/UDP overhead). This evidence is
/// per socket tuple, never shared by source IP. It is return-path evidence,
/// not QUIC authentication: the trusted upstream MUST generate unpredictable
/// CIDs of at least 8 bytes. Short/empty/reused client CIDs never lift the cap.
#[derive(Debug, Default)]
pub(super) struct QuicReturnPath {
    credit: usize,
    packets: usize,
    original_dcid: Vec<u8>,
    client_scid: Vec<u8>,
    server_cid: Vec<u8>,
    version: u32,
    returned: bool,
}

impl QuicReturnPath {
    pub(super) fn received(&mut self, packet: &[u8]) {
        if let Some(header) = long_header(packet) {
            let same_connection = header.version == self.version
                && header.scid == self.client_scid
                && (header.dcid == self.original_dcid || header.dcid == self.server_cid);
            if header.kind == 0 && !same_connection && is_quic_initial(packet) {
                // Reusing a source tuple for a new Initial (including version
                // negotiation) must not borrow the old connection's proof or
                // accumulated response credit. Spoofers could otherwise open a
                // fresh upstream connection on an already validated UDP tuple.
                self.original_dcid.clear();
                self.original_dcid.extend_from_slice(header.dcid);
                self.client_scid.clear();
                self.client_scid.extend_from_slice(header.scid);
                self.server_cid.clear();
                self.version = header.version;
                self.returned = false;
                self.credit = 0;
                self.packets = 0;
            } else if !self.server_cid.is_empty()
                && header.version == self.version
                && matches!(header.kind, 0 | 2)
                && header.dcid == self.server_cid
            {
                self.returned = true;
            }
        }
        // A finite ceiling also bounds spoofed input accumulated over time.
        self.credit = self.credit.saturating_add(packet.len() + 28).min(64 * 1024);
        self.packets = self.packets.saturating_add(1).min(32);
    }

    pub(super) fn can_send(&self, length: usize) -> bool {
        self.returned || (self.packets != 0 && length + 28 <= self.credit)
    }

    pub(super) fn sent(&mut self, packet: &[u8]) {
        if !self.returned {
            self.credit -= packet.len() + 28;
            self.packets -= 1;
            if self.server_cid.is_empty()
                && let Some(header) = long_header(packet)
                && header.version == self.version
                && matches!(header.kind, 0 | 3)
                && header.dcid == self.client_scid
                && header.scid.len() >= 8
                && header.scid != self.original_dcid
                && header.scid != self.client_scid
            {
                self.server_cid.extend_from_slice(header.scid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        [192, 0, 2, n].into()
    }

    #[test]
    fn burst_refills_but_reconnect_and_parallel_flows_do_not_reset_it() {
        let limiter = DecoyLimiter::new(Limits {
            bytes_per_second: 1000,
            burst: 1000,
            ip_bytes_per_second: 100,
            ip_burst: 100,
        });
        let now = Instant::now();
        let one = limiter.admit_at(ip(1), now).unwrap();
        let two = limiter.admit_at(ip(1), now).unwrap();
        assert!(one.delay_at(100, false, now).is_zero());
        assert_eq!(two.delay_at(50, false, now), Duration::from_millis(500));
        drop(one);
        drop(two);
        let next = limiter.admit_at(ip(1), now).unwrap();
        assert_eq!(next.delay_at(50, false, now), Duration::from_millis(500));
        assert!(
            next.delay_at(50, false, now + Duration::from_millis(500))
                .is_zero()
        );
        assert!(
            next.delay_at(100, false, now + Duration::from_secs(100))
                .is_zero()
        );
        assert!(
            !next
                .delay_at(1, false, now + Duration::from_secs(100))
                .is_zero()
        );
    }

    #[test]
    fn global_budget_is_shared_across_ips_and_protocols_without_partial_charges() {
        let limiter = DecoyLimiter::new(Limits {
            bytes_per_second: 100,
            burst: 100,
            ip_bytes_per_second: 100,
            ip_burst: 100,
        });
        let now = Instant::now();
        let tcp = limiter.admit_at(ip(1), now).unwrap();
        let udp = limiter.admit_at(ip(2), now).unwrap();
        assert!(tcp.delay_at(80, false, now).is_zero());
        assert_eq!(udp.delay_at(30, true, now), Duration::from_millis(100));
        assert!(udp.delay_at(20, true, now).is_zero());
        assert_eq!(limiter.state.lock().sources[&ip(2)].bytes.tokens, 80.0);
    }

    #[test]
    fn bounded_admission_retains_bursts_and_releases_active_permits() {
        let limiter = DecoyLimiter::new(Limits::default());
        let now = Instant::now();
        for _ in 0..8 {
            drop(limiter.admit_at(ip(1), now).unwrap());
        }
        assert!(limiter.admit_at(ip(1), now).is_none());
        assert_eq!(limiter.state.lock().active, 0);
        let later = now + Duration::from_secs(10);
        let mut permits = Vec::new();
        for i in 0..8 {
            permits.push(
                limiter
                    .admit_at(ip(1), later + Duration::from_secs(i))
                    .unwrap(),
            );
        }
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(10))
                .is_none()
        );
        drop(permits);
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(11))
                .is_some()
        );
    }

    #[test]
    fn global_flow_cap_is_independent_of_source_addresses() {
        let limiter = DecoyLimiter::new(Limits::default());
        let now = Instant::now();
        let mut permits = Vec::new();
        for n in 0..MAX_FLOWS {
            permits.push(
                limiter
                    .admit_at(ip(n as u8), now + Duration::from_millis(n as u64 * 100))
                    .unwrap(),
            );
        }
        assert!(
            limiter
                .admit_at(ip(200), now + Duration::from_secs(20))
                .is_none()
        );
        drop(permits);
        assert_eq!(limiter.state.lock().active, 0);
        assert!(
            limiter
                .admit_at(ip(200), now + Duration::from_secs(21))
                .is_some()
        );
    }

    #[test]
    fn udp_packet_rate_bounds_tiny_datagrams_in_both_directions() {
        let limiter = DecoyLimiter::new(Limits::default());
        let now = Instant::now();
        let permit = limiter.admit_at(ip(1), now).unwrap();
        for _ in 0..128 {
            assert!(permit.delay_at(1, true, now).is_zero());
        }
        assert!(!permit.delay_at(1, true, now).is_zero());
        assert!(
            permit
                .delay_at(1, true, now + Duration::from_millis(2))
                .is_zero()
        );
        // The packet budget must not accidentally throttle TCP reads/writes.
        assert!(
            permit
                .delay_at(1, false, now + Duration::from_millis(2))
                .is_zero()
        );
    }

    #[tokio::test]
    async fn tcp_copy_preserves_payload_and_half_close_while_pacing_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for _ in 0..3 {
            let limiter = DecoyLimiter::new(Limits {
                bytes_per_second: 256 * 1024,
                burst: 32 * 1024,
                ip_bytes_per_second: 256 * 1024,
                ip_burst: 32 * 1024,
            });
            let permit = limiter.admit(ip(1)).unwrap();
            let (mut client, mut front) = tokio::io::duplex(1024);
            let (mut back, mut server) = tokio::io::duplex(1024);
            let start = Instant::now();
            let proxy = tokio::spawn(async move {
                let (front_read, front_write) = tokio::io::split(&mut front);
                let (back_read, back_write) = tokio::io::split(&mut back);
                let activity = tokio::sync::Notify::new();
                tokio::try_join!(
                    copy_tcp(front_read, back_write, &permit, &activity),
                    copy_tcp(back_read, front_write, &permit, &activity)
                )
                .unwrap();
            });
            let payload = vec![0xa5; 128 * 1024];
            let expected = payload.clone();
            let peer = tokio::spawn(async move {
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected);
                server.write_all(&received).await.unwrap();
                server.shutdown().await.unwrap();
            });
            tokio::time::timeout(Duration::from_secs(10), async {
                client.write_all(&payload).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, payload);
                peer.await.unwrap();
                proxy.await.unwrap();
            })
            .await
            .unwrap();
            // Combined directions: (256 KiB - 32 KiB burst) / 256 KiB/s.
            assert!(start.elapsed() >= Duration::from_millis(875));
            assert_eq!(limiter.state.lock().active, 0);
        }
    }

    #[tokio::test]
    async fn tcp_idle_timer_tracks_activity_from_either_direction() {
        let activity = tokio::sync::Notify::new();
        let idle = tcp_idle(&activity, Duration::from_millis(200));
        tokio::pin!(idle);
        for _ in 0..8 {
            assert!(
                tokio::time::timeout(Duration::from_millis(40), &mut idle)
                    .await
                    .is_err()
            );
            activity.notify_one();
        }
        tokio::time::timeout(Duration::from_secs(1), idle)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_waiter_releases_flow_state_without_refilling_burst() {
        let limiter = DecoyLimiter::new(Limits {
            bytes_per_second: 1,
            burst: 64 * 1024,
            ip_bytes_per_second: 1,
            ip_burst: 64 * 1024,
        });
        let permit = limiter.admit(ip(1)).unwrap();
        assert!(permit.delay_at(64 * 1024, false, Instant::now()).is_zero());
        let task = tokio::spawn(async move {
            permit.wait(64 * 1024).await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.state.lock().active, 0);
        assert!(limiter.state.lock().sources[&ip(1)].bytes.tokens < 64.0 * 1024.0);
    }

    #[test]
    fn mapped_ipv4_cannot_obtain_a_second_budget() {
        assert_eq!(source_ip("::ffff:192.0.2.1".parse().unwrap()), ip(1));
        assert!(Arc::ptr_eq(&process_limiter(), &process_limiter()));
    }

    fn packet(kind: u8, dcid: &[u8], scid: &[u8], size: usize) -> Vec<u8> {
        let mut packet = vec![0xc0 | (kind << 4), 0, 0, 0, 1, dcid.len() as u8];
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet.extend_from_slice(&[0, 0x40, 32]); // Initial token len, payload len
        packet.resize(size, 0);
        packet
    }

    #[test]
    fn only_bounded_supported_initials_create_udp_state() {
        let good = packet(0, b"original", b"clientid", 1200);
        assert!(is_quic_initial(&good));
        for end in 0..good.len() {
            assert!(!is_quic_initial(&good[..end]));
        }
        assert!(!is_quic_initial(&packet(2, b"original", b"clientid", 1200)));
        let mut v2 = good.clone();
        v2[0] = 0xd0;
        v2[1..5].copy_from_slice(&0x6b3343cf_u32.to_be_bytes());
        assert!(is_quic_initial(&v2));
        v2[0] = 0xc0; // v2 Retry, not Initial
        assert!(!is_quic_initial(&v2));
        assert!(!is_quic_initial(&vec![0xff; 1200]));
    }

    #[test]
    fn spoofed_udp_cannot_amplify_bytes_or_packets_before_return_path_evidence() {
        let mut path = QuicReturnPath::default();
        path.received(&packet(0, b"original", b"clientid", 1200));
        assert!(!path.can_send(1201));
        let response = packet(0, b"clientid", b"serverid", 1200);
        assert!(path.can_send(response.len()));
        path.sent(&response);
        assert!(!path.can_send(1));
        // An arbitrary or wrong-CID packet does not lift the cap.
        path.received(&packet(2, b"original", b"clientid", 100));
        assert!(!path.can_send(1200));
        path.received(&packet(2, b"serverid", b"clientid", 100));
        assert!(path.can_send(65535));
        // No IP-wide authorization: another flow starts with no credit.
        assert!(!QuicReturnPath::default().can_send(1));
    }

    #[test]
    fn fresh_initial_on_the_same_tuple_cannot_borrow_proof_or_response_credit() {
        let mut path = QuicReturnPath::default();
        path.received(&packet(0, b"original", b"clientid", 1200));
        path.sent(&packet(0, b"clientid", b"serverid", 1200));
        path.received(&packet(2, b"serverid", b"clientid", 1200));
        assert!(path.can_send(65535));
        path.received(&packet(0, b"new_orig", b"new_clnt", 1200));
        assert!(!path.can_send(1201));
        path.sent(&packet(0, b"new_clnt", b"new_serv", 1200));
        assert!(!path.can_send(1));
        path.received(&packet(2, b"serverid", b"clientid", 100));
        assert!(!path.can_send(1200));
        path.received(&packet(2, b"new_serv", b"new_clnt", 100));
        assert!(path.can_send(65535));
    }

    #[test]
    fn greased_quic_bit_preserves_initial_admission_and_return_path_evidence() {
        let mut initial = packet(0, b"original", b"clientid", 1200);
        initial[0] &= !0x40;
        assert!(is_quic_initial(&initial));
        let mut path = QuicReturnPath::default();
        path.received(&initial);
        let mut response = packet(0, b"clientid", b"serverid", 1200);
        response[0] &= !0x40;
        path.sent(&response);
        assert!(!path.can_send(1));
        let mut echo = packet(2, b"serverid", b"clientid", 100);
        echo[0] &= !0x40;
        path.received(&echo);
        assert!(path.can_send(65535));
    }

    #[test]
    fn tiny_responses_cannot_amplify_packet_count_and_unsafe_cids_do_not_unlock() {
        for cid in [b"".as_slice(), b"short", b"original", b"clientid"] {
            let mut path = QuicReturnPath::default();
            path.received(&packet(0, b"original", b"clientid", 1200));
            path.sent(&packet(0, b"clientid", cid, 100));
            assert!(!path.can_send(100));
            path.received(&packet(2, cid, b"clientid", 100));
            assert!(!path.can_send(2000));
        }
    }
}
