//! Process-wide limits for unauthenticated decoy forwarding only.
//!
//! TCP and UDP, both directions and all listeners/instances share these budgets.
//! Never reset an IP's burst when a connection closes. UDP ingress is policed,
//! responses are paced with bounded buffering; TCP waits and applies backpressure.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
#[cfg(not(test))]
use std::sync::OnceLock;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

const MAX_IPS: usize = 4096;
const MAX_FLOWS: usize = 128;
const MAX_IP_FLOWS: usize = 2;
const IP_RETENTION: Duration = Duration::from_secs(60);
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const FLOW_LIFETIME: Duration = Duration::from_secs(10);
pub(super) const MAX_PROBE_BYTES: usize = 64 * 1024;
pub(super) const WEBSITE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const WEBSITE_FLOW_LIFETIME: Duration = Duration::from_secs(300);
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
    probes: [Option<Instant>; MAX_IP_FLOWS],
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
    remaining: AtomicUsize,
    probe_started: Option<Instant>,
}

pub(super) fn process_limiter() -> Arc<DecoyLimiter> {
    #[cfg(test)]
    {
        // Each test owns a listener group. Capture this owner before spawning tasks.
        thread_local! { static LIMITER: Arc<DecoyLimiter> = DecoyLimiter::new(Limits::default()); }
        return LIMITER.with(Arc::clone);
    }
    #[cfg(not(test))]
    {
        static LIMITER: OnceLock<Arc<DecoyLimiter>> = OnceLock::new();
        LIMITER
            .get_or_init(|| DecoyLimiter::new(Limits::default()))
            .clone()
    }
}

fn source_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or_else(|| {
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)))
        }),
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

    pub(super) fn admit_website(self: &Arc<Self>, ip: IpAddr) -> Option<DecoyPermit> {
        self.admit_inner(source_ip(ip), Instant::now(), false)
    }

    fn admit_at(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Option<DecoyPermit> {
        self.admit_inner(ip, now, true)
    }

    fn admit_inner(self: &Arc<Self>, ip: IpAddr, now: Instant, probe: bool) -> Option<DecoyPermit> {
        let mut state = self.state.lock();
        if now.duration_since(state.cleaned) >= Duration::from_secs(1) {
            state.sources.retain(|_, source| {
                source.active != 0
                    || source
                        .probes
                        .iter()
                        .flatten()
                        .any(|started| now.duration_since(*started) < IP_RETENTION)
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
            probes: [None; 2],
        });
        if source.active >= 8 || !source.opens.delay(1, now).is_zero() {
            return None;
        }
        if probe {
            let slot = source.probes.iter_mut().find(|started| {
                started.is_none_or(|started| now.duration_since(started) >= IP_RETENTION)
            })?;
            *slot = Some(now);
        }
        source.opens.take(1);
        source.active += 1;
        state.opens.take(1);
        state.active += 1;
        Some(DecoyPermit {
            limiter: self.clone(),
            ip,
            remaining: AtomicUsize::new(MAX_PROBE_BYTES),
            probe_started: probe.then_some(now),
        })
    }
}

impl DecoyPermit {
    /// A valid admission token removes only this provisional probe reservation.
    pub(super) fn exempt(self) {
        let mut state = self.limiter.state.lock();
        let source = state
            .sources
            .get_mut(&self.ip)
            .expect("live permit keeps source");
        if let Some(started) = self.probe_started {
            if let Some(slot) = source
                .probes
                .iter_mut()
                .find(|slot| **slot == Some(started))
            {
                *slot = None;
            }
        }
        source.opens.tokens = (source.opens.tokens + 1.0).min(source.opens.capacity);
        state.opens.tokens = (state.opens.tokens + 1.0).min(state.opens.capacity);
    }

    pub(super) fn next_session(&self) -> Option<Self> {
        self.limiter.admit(self.ip)
    }

    fn delay_at(&self, bytes: usize, udp: bool, now: Instant) -> Duration {
        let mut state = self.limiter.state.lock();
        let remaining = self.remaining.load(Ordering::Relaxed);
        if bytes > remaining {
            return Duration::MAX;
        }
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
        let mut delay = global.max(packets).max(source.bytes.delay(bytes, now));
        if udp {
            delay = delay.max(source.packets.delay(1, now));
        }
        // Charge both budgets atomically, only if both allow the operation.
        if delay.is_zero() {
            self.remaining.store(remaining - bytes, Ordering::Relaxed);
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

    pub(super) fn can_forward(&self, bytes: usize) -> bool {
        bytes <= self.remaining.load(Ordering::Relaxed)
    }

    pub(super) async fn wait(&self, bytes: usize) -> io::Result<()> {
        self.wait_for(bytes, false).await
    }

    pub(super) async fn pace_datagram(&self, bytes: usize) -> io::Result<()> {
        self.wait_for(bytes, true).await
    }

    async fn wait_for(&self, bytes: usize, udp: bool) -> io::Result<()> {
        loop {
            let delay = self.delay_at(bytes, udp, Instant::now());
            if delay == Duration::MAX {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "decoy session byte limit",
                ));
            }
            if delay.is_zero() {
                return Ok(());
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
    }
}

struct ProbeSession {
    permit: Option<DecoyPermit>,
    authenticated: bool,
    remaining: usize,
    started: Instant,
    activity: Instant,
    enforce_admission: bool,
}

/// Bounds transport setup until admission or Noise authentication succeeds.
#[doc(hidden)]
pub struct ProbeGuard {
    session: Mutex<Arc<Mutex<ProbeSession>>>,
    limiter: Arc<DecoyLimiter>,
    source: IpAddr,
}

impl ProbeGuard {
    pub(super) fn new(
        limiter: Arc<DecoyLimiter>,
        source: IpAddr,
        enforce_admission: bool,
    ) -> Arc<Self> {
        let now = Instant::now();
        let permit = limiter.admit(source);
        Arc::new(Self {
            session: Mutex::new(Arc::new(Mutex::new(ProbeSession {
                permit,
                authenticated: false,
                remaining: MAX_PROBE_BYTES,
                started: now,
                activity: now,
                enforce_admission,
            }))),
            limiter,
            source: source_ip(source),
        })
    }

    pub(crate) fn authenticate(&self) {
        let owner = self.session.lock().clone();
        let mut session = owner.lock();
        session.authenticated = true;
        if let Some(permit) = session.permit.take() {
            permit.exempt();
        }
    }

    pub(super) fn allow_response(&self) -> bool {
        let owner = self.session.lock().clone();
        let mut session = owner.lock();
        session.enforce_admission = true;
        session.authenticated || session.permit.is_some()
    }

    pub(super) fn join(&self, primary: &Self) -> Result<(), super::TunnelError> {
        if self.source != primary.source || !Arc::ptr_eq(&self.limiter, &primary.limiter) {
            return Err(super::TunnelError::InvalidProtocol(
                "probe lane source differs".into(),
            ));
        }
        let target = primary.session.lock().clone();
        let mut current = self.session.lock();
        if Arc::ptr_eq(&current, &target) {
            return Ok(());
        }
        {
            let mut old = current.lock();
            let mut session = target.lock();
            let consumed = MAX_PROBE_BYTES - old.remaining;
            if !session.authenticated {
                session.remaining = session.remaining.checked_sub(consumed).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "probe lane byte limit")
                })?;
                session.started = session.started.min(old.started);
            }
            if let Some(permit) = old.permit.take() {
                permit.exempt();
            }
        }
        *current = target;
        Ok(())
    }
}

/// Includes HTTP framing and control traffic in the setup byte and time limits.
pub(super) struct ProbeIo<S> {
    inner: S,
    guard: Option<Arc<ProbeGuard>>,
    timer: Pin<Box<tokio::time::Sleep>>,
}

impl<S> ProbeIo<S> {
    pub(super) fn new(inner: S, guard: Arc<ProbeGuard>) -> Self {
        Self {
            inner,
            guard: Some(guard),
            timer: Box::pin(tokio::time::sleep(IDLE_TIMEOUT)),
        }
    }

    fn authenticated(
        &mut self,
        owner: &Mutex<ProbeSession>,
        cx: &mut Context<'_>,
    ) -> io::Result<bool> {
        let session = owner.lock();
        if session.authenticated {
            self.guard = None;
            return Ok(true);
        }
        let deadline = (session.started + FLOW_LIFETIME).min(session.activity + IDLE_TIMEOUT);
        self.timer.as_mut().reset(deadline);
        if self.timer.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe session timeout",
            ));
        }
        if session.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe byte limit",
            ));
        }
        Ok(false)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProbeIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let Some(guard) = this.guard.clone() else {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        };
        // Keep the owner stable while a lane joins the shared session.
        let owner = guard.session.lock();
        if this.authenticated(&owner, cx)? {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        let mut session = owner.lock();
        let count = out.remaining().min(session.remaining);
        let mut limited = ReadBuf::new(out.initialize_unfilled_to(count));
        let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
        let count = limited.filled().len();
        session.remaining -= count;
        if count != 0 {
            session.activity = Instant::now();
        }
        out.advance(count);
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProbeIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(guard) = this.guard.clone() else {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        };
        let owner = guard.session.lock();
        if this.authenticated(&owner, cx)? {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        }
        let mut session = owner.lock();
        if session.enforce_admission && session.permit.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe session limit",
            )));
        }
        let count = bytes.len().min(session.remaining);
        let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]);
        if let Poll::Ready(Ok(count)) = result {
            session.remaining -= count;
            if count != 0 {
                session.activity = Instant::now();
            }
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(guard) = this.guard.clone() else {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bytes);
        };
        let owner = guard.session.lock();
        if this.authenticated(&owner, cx)? {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bytes);
        }
        let mut session = owner.lock();
        if session.enforce_admission && session.permit.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe session limit",
            )));
        }
        let total = bytes.iter().map(|bytes| bytes.len()).sum::<usize>();
        let result = if total <= session.remaining {
            Pin::new(&mut this.inner).poll_write_vectored(cx, bytes)
        } else {
            let first = bytes
                .iter()
                .find(|bytes| !bytes.is_empty())
                .map_or(&[][..], |bytes| &bytes[..]);
            Pin::new(&mut this.inner).poll_write(cx, &first[..first.len().min(session.remaining)])
        };
        if let Poll::Ready(Ok(count)) = result {
            session.remaining -= count;
            if count != 0 {
                session.activity = Instant::now();
            }
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(guard) = self.guard.clone() {
            let owner = guard.session.lock();
            self.authenticated(&owner, cx)?;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(guard) = self.guard.clone() {
            let owner = guard.session.lock();
            self.authenticated(&owner, cx)?;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
        permit.wait(length).await?;
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
    pub(super) fn is_new_connection(&self, packet: &[u8]) -> bool {
        !self.original_dcid.is_empty()
            && long_header(packet).is_some_and(|header| {
                header.kind == 0
                    && is_quic_initial(packet)
                    && !(header.version == self.version
                        && header.scid == self.client_scid
                        && (header.dcid == self.original_dcid || header.dcid == self.server_cid))
            })
    }

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
        assert!(limiter.admit_at(ip(1), now).is_none());
        assert!(
            limiter
                .admit_at(ip(1), now + Duration::from_secs(59))
                .is_none()
        );
        let next = limiter
            .admit_at(ip(1), now + Duration::from_secs(60))
            .unwrap();
        assert!(
            next.delay_at(100, false, now + Duration::from_secs(60))
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
        mapped_ipv4_cannot_obtain_a_second_budget();
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
        for _ in 0..2 {
            drop(limiter.admit_at(ip(1), now).unwrap());
        }
        assert!(limiter.admit_at(ip(1), now).is_none());
        assert_eq!(limiter.state.lock().active, 0);
        assert!(
            limiter
                .admit_at(ip(1), now + Duration::from_secs(59))
                .is_none()
        );
        let later = now + Duration::from_secs(60);
        let first = limiter.admit_at(ip(1), later).unwrap();
        let second = limiter
            .admit_at(ip(1), later + Duration::from_secs(1))
            .unwrap();
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(2))
                .is_none()
        );
        drop(first);
        drop(second);
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(59))
                .is_none()
        );
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(60))
                .is_some()
        );
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(60))
                .is_none()
        );
        assert!(
            limiter
                .admit_at(ip(1), later + Duration::from_secs(61))
                .is_some()
        );
        drop(
            limiter
                .admit_at(ip(2), later + Duration::from_secs(122))
                .unwrap(),
        );
        assert!(!limiter.state.lock().sources.contains_key(&ip(1)));
        let authenticated = DecoyLimiter::new(Limits::default());
        for _ in 0..64 {
            authenticated.admit_at(ip(3), now).unwrap().exempt();
        }
        assert_eq!(authenticated.state.lock().active, 0);
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
                bytes_per_second: 32 * 1024,
                burst: 4 * 1024,
                ip_bytes_per_second: 32 * 1024,
                ip_burst: 4 * 1024,
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
            let payload = vec![0xa5; 16 * 1024];
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
            // Combined directions: (32 KiB - 4 KiB burst) / 32 KiB/s.
            assert!(start.elapsed() >= Duration::from_millis(875));
            assert_eq!(limiter.state.lock().active, 0);
        }
    }

    #[tokio::test]
    async fn tcp_idle_timer_tracks_activity_from_either_direction() {
        probe_setup_limits_and_lane_authentication().await;
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

    async fn probe_setup_limits_and_lane_authentication() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let limiter = DecoyLimiter::new(Limits::default());
        let primary = ProbeGuard::new(limiter.clone(), ip(1), true);
        let mut lanes = Vec::new();
        for _ in 0..3 {
            let lane = ProbeGuard::new(limiter.clone(), ip(1), true);
            assert!(lane.allow_response());
            lane.join(&primary).unwrap();
            lanes.push(lane);
        }
        assert_eq!(limiter.state.lock().active, 1);
        assert_eq!(
            limiter.state.lock().sources[&ip(1)]
                .probes
                .iter()
                .flatten()
                .count(),
            1
        );
        let mut first = ProbeIo::new(tokio::io::sink(), primary.clone());
        first
            .write_all(&vec![1; MAX_PROBE_BYTES / 2])
            .await
            .unwrap();
        let mut second = ProbeIo::new(tokio::io::sink(), lanes[0].clone());
        second
            .write_all(&vec![2; MAX_PROBE_BYTES / 2])
            .await
            .unwrap();
        assert!(second.write_all(b"x").await.is_err());
        primary.authenticate();
        second
            .write_all(&vec![3; MAX_PROBE_BYTES * 2])
            .await
            .unwrap();
        assert_eq!(limiter.state.lock().active, 0);
        assert!(
            limiter.state.lock().sources[&ip(1)]
                .probes
                .iter()
                .all(Option::is_none)
        );

        for idle in [true, false] {
            let guard = ProbeGuard::new(limiter.clone(), ip(2), true);
            {
                let owner = guard.session.lock().clone();
                let mut session = owner.lock();
                if idle {
                    session.activity -= IDLE_TIMEOUT;
                } else {
                    session.started -= FLOW_LIFETIME;
                }
            }
            let (_sender, reader) = tokio::io::duplex(64);
            let mut reader = ProbeIo::new(reader, guard);
            let error = reader.read_u8().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        assert!(limiter.admit(ip(2)).is_none());
    }

    #[tokio::test]
    async fn cancelling_a_waiter_releases_flow_state_without_refilling_burst() {
        let limiter = DecoyLimiter::new(Limits {
            bytes_per_second: 1,
            burst: 32 * 1024,
            ip_bytes_per_second: 1,
            ip_burst: 32 * 1024,
        });
        let permit = limiter.admit(ip(1)).unwrap();
        assert!(permit.delay_at(32 * 1024, false, Instant::now()).is_zero());
        let task = tokio::spawn(async move {
            permit.wait(32 * 1024).await.unwrap();
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.state.lock().active, 0);
        assert!(limiter.state.lock().sources[&ip(1)].bytes.tokens < 32.0 * 1024.0);
    }

    fn mapped_ipv4_cannot_obtain_a_second_budget() {
        assert_eq!(source_ip("::ffff:192.0.2.1".parse().unwrap()), ip(1));
        assert!(Arc::ptr_eq(&process_limiter(), &process_limiter()));
        assert_eq!(
            source_ip("2001:db8:1:2::1".parse().unwrap()),
            source_ip("2001:db8:1:2::ffff".parse().unwrap())
        );
        assert_ne!(
            source_ip("2001:db8:1:2::1".parse().unwrap()),
            source_ip("2001:db8:1:3::1".parse().unwrap())
        );
        let limiter = DecoyLimiter::new(Limits::default());
        let permit = limiter.admit(ip(1)).unwrap();
        assert!(
            permit
                .delay_at(MAX_PROBE_BYTES, false, Instant::now())
                .is_zero()
        );
        assert!(!permit.can_forward(1));
        assert_eq!(permit.delay_at(1, false, Instant::now()), Duration::MAX);
    }

    #[tokio::test]
    async fn h2_quic_and_wss_share_two_probe_slots_and_admitted_wss_bypasses_them() {
        use crate::common::{
            config::gen_default_flags, global_ctx::tests::get_mock_global_ctx_with_network,
        };
        use crate::proto::common::DecoyUpstream;
        use crate::tunnel::{
            TunnelConnector, TunnelListener,
            quic::QuicTunnelListener,
            tcp::TcpTunnelListener,
            websocket::{WsTunnelConnector, WsTunnelListener},
        };
        use futures::{SinkExt, StreamExt};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream, UdpSocket},
        };
        use tokio_util::task::AbortOnDropHandle;

        tokio::time::timeout(Duration::from_secs(10), async {
            let tcp_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let udp_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut flags = gen_default_flags();
            flags.camouflage_config_mut().server_name = "challenges.cloudflare.com".into();
            flags.camouflage_config_mut().admission_secret = "shared-probe-test-admission-key".into();
            flags.camouflage_config_mut().decoy_upstream = Some(DecoyUpstream {
                tcp: tcp_origin.local_addr().unwrap().to_string(), udp: udp_origin.local_addr().unwrap().to_string(),
            });
            let mut h2 = TcpTunnelListener::new("h2://127.0.0.1:0".parse().unwrap());
            h2.set_flags(flags.clone()); h2.listen().await.unwrap();
            let h2_address = format!("127.0.0.1:{}", h2.local_url().port().unwrap());
            let _h2 = AbortOnDropHandle::new(tokio::spawn(async move { let _ = h2.accept().await; }));
            let mut first = TcpStream::connect(h2_address).await.unwrap();
            first.write_all(b"probe").await.unwrap();
            let (mut upstream, _) = tcp_origin.accept().await.unwrap();
            let mut prefix = [0; 5]; upstream.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"probe");
            upstream.write_all(b"ok").await.unwrap();
            let mut reply = [0; 2]; first.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok"); drop(first); drop(upstream);

            let context = get_mock_global_ctx_with_network(None); context.set_flags(flags.clone());
            let mut quic = QuicTunnelListener::new("quic://127.0.0.1:0".parse().unwrap(), context);
            quic.listen().await.unwrap();
            let quic_address = format!("127.0.0.1:{}", quic.local_url().port().unwrap());
            let _quic = AbortOnDropHandle::new(tokio::spawn(async move { let _ = quic.accept().await; }));
            let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            second.send_to(&packet(0, b"original", b"clientid", 1200), quic_address).await.unwrap();
            let mut datagram = [0; 1500];
            assert_eq!(udp_origin.recv_from(&mut datagram).await.unwrap().0, 1200);

            let mut wss = WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap());
            wss.set_flags(flags.clone()); wss.listen().await.unwrap();
            let url = wss.local_url();
            let server = tokio::spawn(async move { wss.accept().await.unwrap() });
            let stream = TcpStream::connect(format!("127.0.0.1:{}", url.port().unwrap())).await.unwrap();
            let mut probe = crate::tunnel::browser_tls::connect(stream, "challenges.cloudflare.com", &[b"http/1.1"], false).await.unwrap();
            probe.write_all(b"GET /other HTTP/1.1\r\nHost: challenges.cloudflare.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
            let mut response = Vec::new(); let _ = probe.read_to_end(&mut response).await;
            assert!(response.is_empty(), "third protocol received a probe response");
            let mut connector = WsTunnelConnector::new(url); connector.set_flags(flags);
            let client = connector.connect().await.unwrap(); let server = server.await.unwrap();
            assert_eq!(client.transport_binding(), server.transport_binding());
            let (_, mut send) = client.split(); let (mut receive, _) = server.split();
            let payload = vec![0x61; MAX_PROBE_BYTES * 2];
            let mut batch = crate::tunnel::batch::PacketBatch::new();
            batch.try_push(crate::tunnel::packet_def::ZCPacket::new_with_payload(&payload)).unwrap();
            send.send(batch).await.unwrap();
            let received = receive.next().await.unwrap().unwrap().pop_singleton().unwrap();
            assert_eq!(received.payload(), payload);
        }).await.unwrap();
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
        assert!(!path.is_new_connection(&packet(0, b"original", b"clientid", 1200)));
        assert!(path.is_new_connection(&packet(0, b"newstart", b"othercid", 1200)));
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
