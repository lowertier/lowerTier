//! A bounded BEP 15 and compact HTTP tracker for public or self-hosted bootstrap.
use super::wire::{self, Announce, Id, MAX_PEERS};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::Full;
use sha2::Sha256;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
}

pub struct TrackerServer {
    secret: [u8; 32],
    interval: u32,
    store: Mutex<Store>,
}

impl TrackerServer {
    #[cfg(test)]
    pub(crate) fn peer_count(&self) -> usize {
        self.store.lock().unwrap().entries
    }
    pub fn new(interval: u32) -> Result<Arc<Self>> {
        ensure!(
            (1..=86400).contains(&interval),
            "rendezvous interval must be 1–86400 seconds"
        );
        Ok(Arc::new(Self {
            secret: rand::random(),
            interval,
            store: Mutex::new(Store {
                swarms: HashMap::new(),
                entries: 0,
                cleanup: Instant::now(),
                rate_second: 0,
                rates: HashMap::new(),
                requests: 0,
            }),
        }))
    }

    fn cookie(&self, source: IpAddr, bucket: u64) -> u64 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(b"lowertier-tracker-cookie-v1");
        match source {
            IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
        mac.update(&bucket.to_be_bytes());
        u64::from_be_bytes(mac.finalize().into_bytes()[..8].try_into().unwrap())
    }

    fn admit(&self, source: IpAddr, now: u64) -> bool {
        let mut store = self.store.lock().unwrap();
        if store.rate_second != now {
            store.rate_second = now;
            store.requests = 0;
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
                expires: now + Duration::from_secs((u64::from(self.interval) * 3).max(10)),
            },
        );
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
        peers.truncate(MAX_PEERS);
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
            reply.extend_from_slice(&self.cookie(source.ip(), now / 60).to_be_bytes());
            return Some(reply);
        }
        if action != 1
            || packet.len() < 98
            || !(0..=2)
                .any(|age| self.cookie(source.ip(), (now / 60).saturating_sub(age)) == connection)
        {
            return None;
        }
        let announce = Announce {
            hash: packet[16..36].try_into().ok()?,
            peer: packet[36..56].try_into().ok()?,
            key: u32::from_be_bytes(packet[88..92].try_into().ok()?),
            port: u16::from_be_bytes(packet[96..98].try_into().ok()?),
            event: u32::from_be_bytes(packet[80..84].try_into().ok()?),
        };
        let peers = self.announce(&announce, source.ip()).ok()?;
        let mut reply = 1u32.to_be_bytes().to_vec();
        reply.extend_from_slice(transaction);
        reply.extend_from_slice(&self.interval.to_be_bytes());
        reply.extend_from_slice(&0u64.to_be_bytes());
        let want = i32::from_be_bytes(packet[92..96].try_into().ok()?);
        let limit = if want < 0 {
            MAX_PEERS
        } else {
            (want as usize).min(MAX_PEERS)
        };
        for peer in peers
            .into_iter()
            .filter(|peer| peer.is_ipv6() == source.is_ipv6())
            .take(limit)
        {
            append_compact(&mut reply, peer);
        }
        Some(reply)
    }

    pub async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> Result<()> {
        let mut bytes = [0; 2048];
        loop {
            let (length, source) = socket.recv_from(&mut bytes).await?;
            if let Some(reply) = self.udp_response(&bytes[..length], source, unix_seconds()) {
                let _ = socket.send_to(&reply, source).await;
            }
        }
    }

    pub async fn serve_http(
        self: Arc<Self>,
        listener: TcpListener,
        trusted_proxies: Vec<cidr::IpCidr>,
        client_ip_header: String,
    ) -> Result<()> {
        let permits = Arc::new(Semaphore::new(64));
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
                                    request.headers().get(&header).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<IpAddr>().ok())
                                } else { Some(source.ip()) };
                                Ok::<_, Infallible>(server.http_response(request, source))
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

    fn http_response(
        &self,
        request: http::Request<hyper::body::Incoming>,
        source: Option<IpAddr>,
    ) -> http::Response<Full<Bytes>> {
        let result = (|| -> Result<Vec<u8>> {
            let source = source.context("trusted proxy did not supply a valid client address")?;
            ensure!(
                request.method() == http::Method::GET && request.uri().path() == "/announce",
                "use GET /announce"
            );
            ensure!(self.admit(source, unix_seconds()), "tracker request limit");
            let announce = parse_query(request.uri().query().context("missing query")?)?;
            let peers = self.announce(&announce, source)?;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for peer in peers.into_iter().take(MAX_PEERS) {
                append_compact(if peer.is_ipv4() { &mut ipv4 } else { &mut ipv6 }, peer);
            }
            let mut reply =
                format!("d8:intervali{}e5:peers{}:", self.interval, ipv4.len()).into_bytes();
            reply.extend_from_slice(&ipv4);
            reply.extend_from_slice(format!("6:peers6{}:", ipv6.len()).as_bytes());
            reply.extend_from_slice(&ipv6);
            reply.push(b'e');
            Ok(reply)
        })();
        let body =
            result.unwrap_or_else(|_| b"d14:failure reason23:invalid tracker requeste".to_vec());
        http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/x-bittorrent")
            .header(http::header::CACHE_CONTROL, "no-store, private")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
}

pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookies_scope_announces_and_tracker_never_overrides_advertised_port() {
        let server = TrackerServer::new(1800).unwrap();
        let source: SocketAddr = "192.0.2.1:50000".parse().unwrap();
        let reply = server
            .udp_response(&wire::connect_request(7), source, 600)
            .unwrap();
        let cookie = wire::connect_response(&reply, 7).unwrap();
        let announce = Announce {
            hash: [4; 20],
            peer: [8; 20],
            key: 2,
            port: 43821,
            event: 2,
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
    }
}
