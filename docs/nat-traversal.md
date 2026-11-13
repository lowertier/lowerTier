# Discovery and NAT traversal

A lowertier network needs no coordination server and no machine with a fixed address.
Members find each other through ordinary BitTorrent trackers, then punch direct paths through NAT, and relay for each other when a direct path fails.

## Trackers

```toml
[discovery]
trackers = [
  "udp://tracker.opentrackr.org:1337/announce",
  "http://tracker.opentrackr.org:1337/announce",
  "https://tracker.nekomi.cn:443/announce",
]
```

Use more than one tracker.
Include at least one HTTP(S) tracker for networks that block UDP.

Each node announces a 20-byte hash derived from the network name and secret, one for each transport, and receives the addresses of other nodes that announced the same hash.
It then connects to those addresses. A tracker or an address grants nothing by itself: every connection must complete TLS and a Noise handshake with the network secret before it carries data.

What a tracker learns: the hash, the public address and port of each member, and when they announce. It does not learn the network name, the secret, or any traffic.
Anyone who watches the tracker can see which addresses share a hash.

lowertier speaks the standard tracker protocols, UDP (BEP 15) and HTTP(S), plus a `tcp://` framing that only `lowertier-tracker` serves.
HTTP/2 and WSS can bootstrap through HTTP(S) or TCP trackers with QUIC disabled.
Tracker discovery needs a shared network secret; nodes that join with a signed credential cannot use it yet.

## How a connection forms

Node A and Node B use the same network name, secret, and tracker list.

1. **Announce.** Each node announces to every tracker and gets back the members that announced before it.
2. **Dial.** It dials those addresses on QUIC, HTTP/2, and WSS, and authenticates each connection.
3. **Learn.** Connected members share the peer list and their listener addresses over the encrypted overlay, so one connection is enough to reach the rest.
4. **Punch.** STUN reports each node's public mapping. Members coordinate simultaneous opens over the overlay: UDP for QUIC, TCP for HTTP/2 and WSS.
   When one side's NAT changes ports for each destination, the other side searches a bounded range of ports.
5. **Relay.** If no direct path forms, traffic goes through other members. See [routing](routing.md).

Each transport punches its own path, so a working QUIC path does not stop an HTTP/2 or WSS attempt.
A failed endpoint waits 15 seconds before the next try, doubling after each failure up to 600 seconds. A success resets the wait. While it waits, its status reads `COLD_RETRY`.

Whether two NATs can connect directly depends on how each one maps and filters. Two NATs that both change ports per destination usually need a relay.
Keep at least one member that both can reach.

## How long discovery takes

A tracker tells each client how long to wait before it announces again. Public trackers ask for about 30 to 60 minutes.
A node re-announces sooner when its own NAT mapping changes, but otherwise follows the tracker.

- **The newcomer finds the earlier members at once**, from its first announce. If it can reach one of them, the network forms within seconds.
- **The earlier members learn of the newcomer only at their next announce.** That matters when the newcomer cannot reach any earlier member: say, a lone first node behind a NAT that drops unsolicited packets. Then the two connect at the first node's next announce, which on a public tracker can be up to an hour away.

To make discovery fast in every case, keep one member reachable from the internet, or [run your own tracker](#run-your-own-tracker), whose clients announce every 30 seconds.

## NAT settings

```toml
[nat]
p2p = "on"              # on | lazy (only when traffic needs it) | required (never relay) | off
udp_punch = true
tcp_punch = true
symmetric_punch = true  # port search toward NATs that change ports
# stun = ["192.0.2.20:3478"]       # built-in lists when absent
# stun_tcp = ["192.0.2.20:3478"]
```

A slow or failing STUN server does not delay tracker replies, outbound connections, or relays.
QUIC keeps the socket that STUN and punching used, so the NAT mapping stays valid. Connections survive NAT port changes on either side; see [QUIC path migration](design/quic-rebinding.md).

## Known addresses

A node can also dial addresses you give it, with or without trackers:

```toml
[[peer]]
uri = "quic://192.0.2.10:11012"
```

A configured peer connects at startup and keeps retrying. It is the fastest bootstrap when one member has a stable address.

## Run your own tracker

```bash
cargo build --release -p lowertier-tracker --features server --bin lowertier-tracker
lowertier-tracker --udp-listen 0.0.0.0:6969 --http-listen 127.0.0.1:6970
```

List it under `discovery.private_trackers`. Clients announce to a private tracker every 30 seconds, and may use private and local addresses it returns:

```toml
[discovery]
private_trackers = ["udp://tracker.example.net:6969/announce"]
```

The tracker also answers STUN. It keeps state in memory only, stores no torrent data, and relays no VPN traffic.
Behind an HTTPS reverse proxy such as Caddy, start it with `--trusted-proxy 127.0.0.1/32` so it reads the client address from `X-Real-IP`.
`--passkey-file` restricts who may announce.

The [tracker discovery](design/tracker-discovery.md) and [rendezvous](design/rendezvous.md) notes cover the bootstrap sequence, CDN deployment, TCP framing, timing, and the privacy limits in detail.
