//! A bounded BEP 15 and compact HTTP tracker for public or self-hosted bootstrap.
use super::wire::{self, Announce, Id, MAX_PEERS, unix_seconds};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::Full;
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};

const MAX_SWARMS: usize = 4096;
const MAX_ENTRIES: usize = 65_536;
const MAX_SWARM_ENTRIES: usize = 256;

struct Entry {
    address: SocketAddr,
    expires: Instant,
}
struct Store {
    swarms: HashMap<Id, HashMap<(Id, SocketAddr), Entry>>,
    entries: usize,
    cleanup: Instant,
    rate_second: u64,
    rates: HashMap<IpAddr, u32>,
    requests: u32,
    response_bytes: usize,
}

pub struct TrackerServer {
    secret: [u8; 32],
    passkey_tag: Option<[u8; 32]>,
    connections: Arc<Semaphore>,
    interval: u32,
    store: Mutex<Store>,
}

impl TrackerServer {
    fn announce_interval(&self, announce: &Announce) -> u32 {
        // LowTier uses a nonzero private hint. Public trackers still see an incomplete download.
        if announce.left == 2 {
            self.interval.max(wire::IDLE_ANNOUNCE_INTERVAL_SECS)
        } else {
            self.interval
        }
    }
    #[cfg(feature = "test-support")]
    pub fn peer_count(&self) -> usize {
        self.store.lock().unwrap().entries
    }
    pub fn new(interval: u32) -> Result<Arc<Self>> {
        Self::with_passkey(interval, None)
    }

    pub fn with_passkey(interval: u32, passkey: Option<&str>) -> Result<Arc<Self>> {
        ensure!(
            (1..=86400).contains(&interval),
            "rendezvous interval must be 1–86400 seconds"
        );
        ensure!(
            passkey.is_none_or(|key| !key.is_empty() && key.len() <= 256),
            "invalid passkey length"
        );
        let secret: [u8; 32] = rand::random();
        let passkey_tag = passkey.map(|key| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
            mac.update(key.as_bytes());
            mac.finalize().into_bytes().into()
        });
        Ok(Arc::new(Self {
            secret,
            passkey_tag,
            connections: Arc::new(Semaphore::new(64)),
            interval,
            store: Mutex::new(Store {
                swarms: HashMap::new(),
                entries: 0,
                cleanup: Instant::now(),
                rate_second: 0,
                rates: HashMap::new(),
                requests: 0,
                response_bytes: 0,
            }),
        }))
    }

    fn authorized(&self, query: Option<&str>) -> bool {
        let Some(tag) = &self.passkey_tag else {
            return true;
        };
        let mut keys = query.unwrap_or_default().split('&').filter_map(|field| {
            let (name, value) = field.split_once('=')?;
            (name == "passkey").then_some(value)
        });
        let Some(key) = keys.next() else {
            return false;
        };
        if keys.next().is_some() {
            return false;
        }
        let key = key.replace('+', " ");
        let key = percent_encoding::percent_decode_str(&key).collect::<Vec<_>>();
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(&key);
        mac.verify_slice(tag).is_ok()
    }

    fn cookie(&self, source: SocketAddr, bucket: u64) -> u64 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(b"lowertier-tracker-cookie-v1");
        match source.ip() {
            IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
        mac.update(&source.port().to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        u64::from_be_bytes(mac.finalize().into_bytes()[..8].try_into().unwrap())
    }

    fn admit(&self, source: IpAddr, now: u64) -> bool {
        // A rotating IPv6 interface identifier must not bypass source limits.
        let source = match source {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or_else(|| {
                IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)))
            }),
            ip => ip,
        };
        let mut store = self.store.lock().unwrap();
        if store.rate_second != now {
            store.rate_second = now;
            store.requests = 0;
            store.response_bytes = 0;
            store.rates.clear();
        }
        if store.requests >= 2048 {
            return false;
        }
        if !store.rates.contains_key(&source) && store.rates.len() >= 2048 {
            return false;
        }
        let count = store.rates.entry(source).or_default();
        if *count >= 32 {
            return false;
        }
        *count += 1;
        store.requests += 1;
        true
    }

    fn admit_response(&self, bytes: usize) -> bool {
        let mut store = self.store.lock().unwrap();
        if store.response_bytes + bytes > 128 * 1024 {
            return false;
        }
        store.response_bytes += bytes;
        true
    }

    fn announce(&self, announce: &Announce, source: IpAddr) -> Result<Vec<SocketAddr>> {
        ensure!(
            announce.port != 0 && matches!(announce.event, 0..=3),
            "invalid tracker announce"
        );
        let address = SocketAddr::new(source, announce.port);
        let key = (announce.peer, address);
        let mut store = self.store.lock().unwrap();
        let now = Instant::now();
        let capacity_reached = store.entries >= MAX_ENTRIES
            || store.swarms.len() >= MAX_SWARMS
            || store
                .swarms
                .get(&announce.hash)
                .is_some_and(|entries| entries.len() >= MAX_SWARM_ENTRIES);
        if store.cleanup.elapsed() >= Duration::from_secs(30)
            || (capacity_reached && store.cleanup.elapsed() >= Duration::from_secs(1))
        {
            store.swarms.retain(|_, entries| {
                entries.retain(|_, entry| entry.expires > now);
                !entries.is_empty()
            });
            store.entries = store.swarms.values().map(HashMap::len).sum();
            store.cleanup = now;
        }
        if let Some(entries) = store.swarms.get_mut(&announce.hash) {
            let previous = entries.len();
            entries.retain(|_, entry| entry.expires > now);
            let removed = previous - entries.len();
            store.entries -= removed;
        }
        if announce.event == 3 {
            if let Some(entries) = store.swarms.get_mut(&announce.hash) {
                if entries
                    .get(&key)
                    .is_some_and(|entry| entry.address.ip() == source)
                    && entries.remove(&key).is_some()
                {
                    store.entries -= 1;
                }
            }
            return Ok(Vec::new());
        }
        if !store.swarms.contains_key(&announce.hash) {
            ensure!(store.swarms.len() < MAX_SWARMS, "tracker swarm limit");
            store.swarms.insert(announce.hash, HashMap::new());
        }
        let new = !store.swarms[&announce.hash].contains_key(&key);
        if new {
            ensure!(
                store.entries < MAX_ENTRIES
                    && store.swarms[&announce.hash].len() < MAX_SWARM_ENTRIES,
                "tracker peer limit"
            );
            store.entries += 1;
        }
        let entries = store.swarms.get_mut(&announce.hash).unwrap();
        entries.insert(
            key,
            Entry {
                address,
                expires: now
                    + Duration::from_secs(
                        (u64::from(self.announce_interval(announce)) * 3).max(10),
                    ),
            },
        );
        let limit = if announce.numwant < 0 {
            MAX_PEERS
        } else {
            (announce.numwant as usize).min(MAX_PEERS)
        };
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut peers = entries
            .iter()
            .filter(|(id, entry)| {
                id.0 != announce.peer
                    && entry.expires > now
                    && entry.address.is_ipv6() == source.is_ipv6()
            })
            .map(|(_, entry)| entry.address)
            .collect::<Vec<_>>();
        // Rotate bounded replies so large groups do not hide the same endpoints forever.
        peers.sort_unstable();
        if !peers.is_empty() {
            let offset = unix_seconds() as usize % peers.len();
            peers.rotate_left(offset);
        }
        peers.truncate(limit);
        Ok(peers)
    }

    fn udp_response(&self, packet: &[u8], source: SocketAddr, now: u64) -> Option<Vec<u8>> {
        if packet.len() < 16 || !self.admit(source.ip(), now) {
            return None;
        }
        let connection = u64::from_be_bytes(packet[..8].try_into().ok()?);
        let action = u32::from_be_bytes(packet[8..12].try_into().ok()?);
        let transaction = &packet[12..16];
        if action == 0 && connection == wire::CONNECT_MAGIC {
            let mut reply = 0u32.to_be_bytes().to_vec();
            reply.extend_from_slice(transaction);
            reply.extend_from_slice(&self.cookie(source, now / 60).to_be_bytes());
            if packet.get(16..20) == Some(wire::ECHO_MAGIC) && packet.len() >= 48 {
                reply.extend_from_slice(wire::ECHO_MAGIC);
                reply.push(if source.is_ipv4() { 4 } else { 6 });
                reply.extend_from_slice(&source.port().to_be_bytes());
                match source.ip() {
                    IpAddr::V4(ip) => reply.extend_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => reply.extend_from_slice(&ip.octets()),
                }
            }
            return self.admit_response(reply.len()).then_some(reply);
        }
        if action != 1
            || packet.len() < 98
            || !(0..=2).any(|age| self.cookie(source, (now / 60).saturating_sub(age)) == connection)
        {
            return None;
        }
        let target = wire::url_data(packet).ok()?;
        if !self.authorized(target.split_once('?').map(|(_, query)| query)) {
            return None;
        }
        let announce = Announce {
            hash: packet[16..36].try_into().ok()?,
            peer: packet[36..56].try_into().ok()?,
            key: u32::from_be_bytes(packet[88..92].try_into().ok()?),
            port: u16::from_be_bytes(packet[96..98].try_into().ok()?),
            event: u32::from_be_bytes(packet[80..84].try_into().ok()?),
            left: u64::from_be_bytes(packet[64..72].try_into().ok()?),
            numwant: i32::from_be_bytes(packet[92..96].try_into().ok()?),
        };
        let peers = self.announce(&announce, source.ip()).ok()?;
        let mut reply = 1u32.to_be_bytes().to_vec();
        reply.extend_from_slice(transaction);
        reply.extend_from_slice(&self.announce_interval(&announce).to_be_bytes());
        reply.extend_from_slice(&0u64.to_be_bytes());
        for peer in peers {
            append_compact(&mut reply, peer);
        }
        self.admit_response(reply.len()).then_some(reply)
    }

    pub async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> Result<()> {
        self.serve_udp_with_alternate(Arc::new(socket), None).await
    }

    pub async fn serve_udp_with_alternate(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        alternate: Option<Arc<UdpSocket>>,
    ) -> Result<()> {
        let mut bytes = [0; 2048];
        loop {
            let (length, source) = socket.recv_from(&mut bytes).await?;
            let packet = &bytes[..length];
            if packet.len() >= 20 && packet[4..8] == crate::binding::MAGIC {
                if !self.admit(source.ip(), unix_seconds()) {
                    continue;
                }
                if let Some((reply, change)) =
                    crate::binding::response(packet, source, alternate.is_some())
                {
                    if self.admit_response(reply.len()) {
                        let output = if change {
                            alternate.as_ref().unwrap()
                        } else {
                            &socket
                        };
                        let _ = output.send_to(&reply, source).await;
                    }
                }
            } else if let Some(reply) = self.udp_response(packet, source, unix_seconds()) {
                let _ = socket.send_to(&reply, source).await;
            }
        }
    }

    pub async fn serve_stun_tcp(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                accepted = listener.accept() => {
                    let (mut stream, source) = accepted?;
                    let Ok(permit) = self.connections.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let mut bytes = [0; crate::binding::MAX_MESSAGE];
                        loop {
                            if !matches!(tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut bytes[..20])).await, Ok(Ok(_))) { break; }
                            let length = 20 + usize::from(u16::from_be_bytes(bytes[2..4].try_into().unwrap()));
                            if length > bytes.len() || !(length - 20).is_multiple_of(4) { break; }
                            if !matches!(tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut bytes[20..length])).await, Ok(Ok(_))) { break; }
                            if !server.admit(source.ip(), unix_seconds()) { break; }
                            let Some((reply, _)) = crate::binding::response(&bytes[..length], source, false) else { break; };
                            if !server.admit_response(reply.len()) { break; }
                            if !matches!(tokio::time::timeout(Duration::from_secs(5), stream.write_all(&reply)).await, Ok(Ok(()))) { break; }
                        }
                    });
                }
            }
        }
    }

    pub async fn serve_http(
        self: Arc<Self>,
        listener: TcpListener,
        trusted_proxies: Vec<cidr::IpCidr>,
        client_ip_header: String,
    ) -> Result<()> {
        let permits = self.connections.clone();
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                accepted = listener.accept() => {
                    let (stream, source) = accepted?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    let trusted = trusted_proxies.iter().any(|network| network.contains(&source.ip()));
                    let header = client_ip_header.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                            let server = server.clone();
                            let header = header.clone();
                            async move {
                                let source = if trusted {
                                    request.headers().get(&header).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<IpAddr>().ok()).map(|ip| SocketAddr::new(ip, 0))
                                } else { Some(source) };
                                server.http_response(request, source, unix_seconds())
                            }
                        });
                        let connection = hyper::server::conn::http1::Builder::new().keep_alive(false).max_buf_size(8192)
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                        let _ = tokio::time::timeout(Duration::from_secs(15), connection).await;
                    });
                }
            }
        }
    }

    fn http_response<B>(
        &self,
        request: http::Request<B>,
        source: Option<SocketAddr>,
        now: u64,
    ) -> std::io::Result<http::Response<Full<Bytes>>> {
        let source = source
            .filter(|source| self.admit(source.ip(), now))
            .ok_or(std::io::ErrorKind::PermissionDenied)?;
        let result = (|| -> Result<Vec<u8>> {
            ensure!(
                request.method() == http::Method::GET && request.uri().path() == "/announce",
                "use GET /announce"
            );
            let query = request.uri().query().context("missing query")?;
            ensure!(self.authorized(Some(query)), "invalid tracker request");
            let announce = parse_query(query)?;
            let peers = self.announce(&announce, source.ip())?;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for peer in peers.into_iter().take(MAX_PEERS) {
                append_compact(if peer.is_ipv4() { &mut ipv4 } else { &mut ipv6 }, peer);
            }
            let mut reply =
                format!("d8:intervali{}e", self.announce_interval(&announce)).into_bytes();
            if source.port() != 0 && query.split('&').any(|field| field == "lt_observe=1") {
                let observed = source.to_string();
                reply.extend_from_slice(
                    format!("11:lt_observed{}:{observed}", observed.len()).as_bytes(),
                );
            }
            reply.extend_from_slice(format!("5:peers{}:", ipv4.len()).as_bytes());
            reply.extend_from_slice(&ipv4);
            reply.extend_from_slice(format!("6:peers6{}:", ipv6.len()).as_bytes());
            reply.extend_from_slice(&ipv6);
            reply.push(b'e');
            Ok(reply)
        })();
        let body =
            result.unwrap_or_else(|_| b"d14:failure reason23:invalid tracker requeste".to_vec());
        if !self.admit_response(body.len()) {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/x-bittorrent")
            .header(http::header::CACHE_CONTROL, "no-store, private")
            .body(Full::new(Bytes::from(body)))
            .unwrap())
    }
}

fn append_compact(bytes: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.extend_from_slice(&ip.octets()),
    }
    bytes.extend_from_slice(&address.port().to_be_bytes());
}

fn parse_query(query: &str) -> Result<Announce> {
    ensure!(query.len() <= 4096, "tracker query too large");
    let mut fields = HashMap::new();
    for item in query.split('&') {
        let (name, value) = item.split_once('=').context("invalid tracker query")?;
        let value = value.replace('+', " ");
        let value = percent_encoding::percent_decode_str(&value).collect::<Vec<_>>();
        ensure!(
            fields.insert(name, value).is_none(),
            "duplicate tracker parameter"
        );
    }
    let required = |name| fields.get(name).context("missing tracker parameter");
    let hash = required("info_hash")?.as_slice().try_into()?;
    let peer = required("peer_id")?.as_slice().try_into()?;
    let port = std::str::from_utf8(required("port")?)?.parse()?;
    let event = match fields.get("event").map(Vec::as_slice).unwrap_or_default() {
        b"" => 0,
        b"started" => 2,
        b"stopped" => 3,
        b"completed" => 1,
        _ => anyhow::bail!("invalid tracker event"),
    };
    Ok(Announce {
        hash,
        peer,
        port,
        event,
        key: 0,
        left: fields
            .get("left")
            .map(|value| -> Result<u64> { Ok(std::str::from_utf8(value)?.parse()?) })
            .transpose()?
            .unwrap_or(1),
        numwant: fields
            .get("numwant")
            .map(|value| -> Result<i32> { Ok(std::str::from_utf8(value)?.parse()?) })
            .transpose()?
            .unwrap_or(MAX_PEERS as i32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cookies_scope_announces_and_tracker_never_overrides_advertised_port() {
        let server = TrackerServer::new(1800).unwrap();
        let source: SocketAddr = "192.0.2.1:50000".parse().unwrap();
        let reply = server
            .udp_response(&wire::connect_request(7), source, 600)
            .unwrap();
        let cookie = wire::connect_response(&reply, 7).unwrap();
        let mut echo = wire::connect_request(9).to_vec();
        echo.extend_from_slice(wire::ECHO_MAGIC);
        echo.resize(48, 0);
        assert_eq!(
            wire::observed_connect(&server.udp_response(&echo, source, 600).unwrap()).unwrap(),
            Some(source)
        );
        let announce = Announce {
            hash: [4; 20],
            peer: [8; 20],
            key: 2,
            port: 43821,
            event: 2,
            left: 1,
            numwant: MAX_PEERS as i32,
        };
        assert!(
            server
                .udp_response(
                    &announce.udp(cookie, 8),
                    "192.0.2.2:50000".parse().unwrap(),
                    600
                )
                .is_none()
        );
        assert!(
            server
                .udp_response(
                    &announce.udp(cookie, 8),
                    "192.0.2.1:50001".parse().unwrap(),
                    600
                )
                .is_none()
        );
        server
            .udp_response(&announce.udp(cookie, 8), source, 600)
            .unwrap();
        let second = Announce {
            peer: [9; 20],
            ..announce.clone()
        };
        let peers = server
            .announce(&second, "192.0.2.2".parse().unwrap())
            .unwrap();
        assert_eq!(peers, vec!["192.0.2.1:43821".parse().unwrap()]);
        let stopped = Announce {
            event: 3,
            ..announce.clone()
        };
        server.announce(&stopped, source.ip()).unwrap();
        assert!(
            server
                .announce(&second, "192.0.2.2".parse().unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            parse_query(&announce.http_query()).unwrap().hash,
            announce.hash
        );
        let private = TrackerServer::with_passkey(2, Some("local+key")).unwrap();
        assert!(!private.authorized(None));
        assert!(!private.authorized(Some("passkey=wrong")));
        assert!(!private.authorized(Some("passkey=local%2Bkey&passkey=local%2Bkey")));
        let connect = private
            .udp_response(&wire::connect_request(10), source, 600)
            .unwrap();
        let cookie = wire::connect_response(&connect, 10).unwrap();
        let mut packet = announce.udp(cookie, 11).to_vec();
        assert!(private.udp_response(&packet, source, 600).is_none());
        wire::append_url_data(&mut packet, "/announce?passkey=local%2Bkey").unwrap();
        assert!(private.udp_response(&packet, source, 600).is_some());
        let before = private.store.lock().unwrap().requests;
        let invalid = http::Request::builder().uri("/invalid").body(()).unwrap();
        assert!(private.http_response(invalid, Some(source), 600).is_ok());
        assert_eq!(private.store.lock().unwrap().requests, before + 1);
        private.store.lock().unwrap().response_bytes = 128 * 1024;
        let invalid = http::Request::builder().uri("/invalid").body(()).unwrap();
        assert!(private.http_response(invalid, Some(source), 600).is_err());

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut jobs = JoinSet::new();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        jobs.spawn(private.clone().serve_udp(udp));
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        jobs.spawn(private.clone().serve_stun_tcp(tcp));
        tokio::time::timeout(Duration::from_secs(2), async {
            let request = crate::binding::request(&[7; 12]);
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(&request, udp_address).await.unwrap();
            let mut reply = [0; 32];
            assert_eq!(client.recv_from(&mut reply).await.unwrap().0, 32);
            assert_eq!(
                u16::from_be_bytes(reply[26..28].try_into().unwrap()) ^ 0x2112,
                client.local_addr().unwrap().port()
            );
            let mut stream = tokio::net::TcpStream::connect(tcp_address).await.unwrap();
            for _ in 0..2 {
                stream.write_all(&request).await.unwrap();
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(
                    u16::from_be_bytes(reply[26..28].try_into().unwrap()) ^ 0x2112,
                    stream.local_addr().unwrap().port()
                );
            }
        })
        .await
        .unwrap();
    }
}
