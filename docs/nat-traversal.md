# NAT traversal and discovery

A node needs one way in: a peer it can reach, or a tracker that knows where peers are.
After that, connected peers introduce each other, punch direct connections through NAT, and relay for each other when punching fails.

## How a connection forms

1. **Bootstrap.** The node dials its configured `[[peer]]` entries, and announces to trackers if `[discovery]` is set.
2. **Authenticate.** Every connection completes TLS and a Noise handshake before it carries data. A tracker or an address alone grants nothing.
3. **Learn.** Connected peers share the peer list and their listener addresses over the encrypted overlay.
4. **Punch.** STUN reports each node's public mapping. Peers coordinate simultaneous opens over the overlay: UDP for QUIC, TCP for HTTP/2 and WSS.
   When one side's NAT changes ports for each destination, the other side searches a bounded range of ports.
5. **Relay.** If no direct path forms, traffic goes through other members. See [routing](routing.md).

Each transport punches its own path, so a working QUIC path does not stop an HTTP/2 or WSS attempt.
A failed endpoint waits at least 600 seconds before the next try, and its status reads `COLD_RETRY`.

Whether two NATs can connect directly depends on how each one maps and filters. Two NATs that both change ports per destination usually need a relay.
Keep at least one member that both can reach.

## Settings

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

## Trackers

Trackers are optional. A node with `[[peer]]` entries needs none.
Use them when no member has a stable address, or to let new nodes find the network without editing configuration.

```toml
[discovery]
trackers = [
  "udp://open.stealth.si:80/announce",
  "udp://tracker.torrent.eu.org:451/announce",
  "https://tracker.example.net/announce",
]
```

lowertier speaks the standard BitTorrent tracker protocols, UDP (BEP 15) and HTTP(S).
Nodes announce a hash derived from the network name and secret. Anyone watching the tracker can see that hash and the addresses behind it, but every candidate must pass authentication before it carries data.
Add an HTTP(S) or `tcp://` tracker when UDP is blocked; HTTP/2 and WSS can bootstrap with QUIC disabled.
Tracker discovery needs a shared network secret; nodes that join with a signed credential cannot use it yet.

A public tracker learns the rendezvous hash, each node's public address, and timing. It cannot join the network.
Keep tracker passkeys and network secrets out of shared files.

### Run your own tracker

```bash
cargo build --release -p lowertier-tracker --features server --bin lowertier-tracker
lowertier-tracker --udp-listen 0.0.0.0:6969 --http-listen 127.0.0.1:6970
```

The tracker also answers STUN. List it under `discovery.private_trackers`, which also allows private and local addresses as candidates:

```toml
[discovery]
private_trackers = ["udp://tracker.example.net:6969/announce"]
```

It keeps state in memory only, stores no torrent data, and relays no VPN traffic.
Behind an HTTPS reverse proxy such as Caddy, start it with `--trusted-proxy 127.0.0.1/32` so it reads the client address from `X-Real-IP`.
`--passkey-file` restricts who may announce.

The [tracker discovery](design/tracker-discovery.md) and [rendezvous](design/rendezvous.md) notes cover CDN deployment, TCP framing, timing, and the privacy limits in detail.
