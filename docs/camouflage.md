# Camouflage

Camouflage lets a node share port 443 with ordinary HTTPS.
Peers that prove the admission secret reach lowertier. Every other visitor is passed to a real website: either an upstream host or static files the node serves itself.

## How it works

Every listener speaks real TLS: QUIC (HTTP/3), HTTP/2, and WSS require matching TLS SNI and enable camouflage across all three transports without falling back to un-camouflaged listeners or built-in pages.
When `[camouflage]` leaves `server_names`, `website_root`, `tls_cert`/`tls_key`, and `decoy_upstream` unset, peers send `challenges.cloudflare.com` as the SNI and HTTP authority, WSS requires a non-root `camouflage.wss_path` (default `/ws`), nodes reuse `network.secret` for admission and routing markers, and non-loopback listeners forward unauthenticated probes to `challenges.cloudflare.com:443` (or silently reject and drop them if no decoy or `website_root` is available).
A peer proves it holds the admission secret before the node treats the connection as lowertier:

- QUIC peers place an HMAC of the secret in the connection ID of their first packet.
- HTTP/2 peers send the marker as a tiny TLS record before the ClientHello (unless `camouflage.sni_routing = true`), then an admission token on the CONNECT request.
- WSS peers send the token in the `Authorization` header of the upgrade request to `camouflage.wss_path`.

The token is an HMAC of the secret over a five-minute window. A connection without a matching SNI, valid marker/path, or valid token is treated as a probe:
the node splices it to `decoy_upstream`, serves `website_root`, or silently rejects and drops it before exposing LowTier, within the probe limits below.
After admission, Noise authenticates both peers and binds the TLS exporter, so a TLS endpoint in the middle cannot impersonate either one.

With several server names, a client picks one name per destination address and keeps it, so the SNI, HTTP authority, and certificate agree across reconnects.
Different destinations spread across the list. A server accepts every listed name and selects the matching certificate by SNI.

This changes what a casual probe sees. It does not make lowertier traffic indistinguishable from browser traffic,
and using a domain name as the TLS server name does not mean you hold its certificate.
Examples here use `challenges.cloudflare.com` because it is reachable; choose your own.

## Pass probes to an upstream site

The node listens on loopback and announces port 443. Nginx forwards raw bytes to it.

```toml
[transport]
listen = ["h2://127.0.0.1:8443", "quic://127.0.0.1:8443"]
advertise = ["h2://0.0.0.0:443", "quic://0.0.0.0:443"]

[camouflage]
server_names = ["challenges.cloudflare.com"]
admission_secret = "replace-with-a-random-shared-secret"

[camouflage.decoy_upstream]
tcp = "challenges.cloudflare.com:443"
udp = "challenges.cloudflare.com:443"
```

```nginx
stream {
    server {
        listen 443 reuseport;
        proxy_pass 127.0.0.1:8443;
        proxy_timeout 1d;
    }
    server {
        listen 443 udp reuseport;
        proxy_pass 127.0.0.1:8443;
        proxy_timeout 1d;
    }
}
```

Do not enable `ssl_preread`. Marked HTTP/2 clients send a tiny TLS record before the real ClientHello, and preread would try to parse it.
Leave `camouflage.sni_routing` off: peers and probes share one server name, so a proxy cannot split them by name.

Unmarked connections are spliced to the upstream and complete TLS with its real certificate.
The upstream must serve HTTP/3 on UDP 443. This path supports IPv4 listeners and upstreams.

The CLI can set the name and upstreams in one change. Restart the instance afterwards, because QUIC caches these settings:

```bash
lowertier set --stage camouflage.server_names=challenges.cloudflare.com \
  camouflage.decoy_upstream.tcp=challenges.cloudflare.com:443 \
  camouflage.decoy_upstream.udp=challenges.cloudflare.com:443
```

## Admission secret

Every peer needs the same `camouflage.admission_secret`, at least 16 bytes, or a shared `network.secret`.
Networks that use a shared `network.secret` fall back to that secret automatically for admission tokens, routing markers, and default or explicit decoy forwarding when the admission secret is empty;
nodes that join with a signed credential hold no network secret, so they need an explicit `camouflage.admission_secret` of at least 16 bytes to enable decoy forwarding.
The encrypted admission token rotates every five minutes.

## Limits on probes

WSS runs TLS and WebSocket setup concurrently.
Each listener permits at most 32 pending setups, with at most four per source IP.
Each setup has a three-second deadline.
A stalled setup does not block other admitted connections.
For multiple lanes, the setup queue also reads the initial lane record.
TLS EOF and reset errors during setup appear in debug logs.
Errors on an authenticated connection remain visible.

Visitors that fail admission get a small, bounded share of the upstream:

- two probe sessions per source address in any 60 seconds, shared across QUIC, HTTP/2, and WSS;
- 64 KiB, 5 seconds idle, and 10 seconds total per session;
- shared and per-address bandwidth caps, with backpressure on TCP and pacing on UDP.

The [decoy design note](design/decoy-passthrough.md) lists every limit and the UDP anti-amplification rules.

## Serve your own site instead

Set `website_root` and leave out `decoy_upstream`. The node terminates TLS for each name in `server_names`, so it needs a certificate for each name.
It loads `/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem` for every name unless you set `camouflage.tls_cert` and `camouflage.tls_key`, which then serve all names.

```toml
[camouflage]
server_names = ["challenges.cloudflare.com"]
admission_secret = "replace-with-a-random-shared-secret"
website_root = "/var/www/lowertier"
```

HTTP/3 serves the files. TCP connections that are not peers are not served from `website_root`.

## WSS through a CDN

A CDN that terminates TLS cannot carry QUIC or the HTTP/2 tunnel unchanged. Use WSS with `via=cdn` on both ends:

```toml
# Origin
[transport]
listen = ["wss://0.0.0.0:11012?via=cdn"]
```

```toml
# Client
[[peer]]
uri = "wss://YOUR-TUNNEL-HOST.example:443?via=cdn"
```

Replace the host with one you control. Configure the CDN to forward WebSocket connections to the origin, allow long-lived binary messages,
and pass the `Sec-WebSocket-Protocol: lowertier-tls-v1` header both ways.

The client checks the CDN's public certificate. A second TLS connection runs inside the WebSocket with the compatibility server name `challenges.cloudflare.com`, and its exporter binds the Noise handshake,
so the CDN cannot impersonate either peer. Set `camouflage.tls_cert` and `camouflage.tls_key` when the CDN verifies the origin's certificate.

CDN mode has no multi-lane TCP, a 256 KiB message limit, and the CPU cost of the extra TLS layer.
Set `camouflage.trusted_proxy_cidrs` to the CDN's ranges so the origin sees real client addresses; by default it trusts no proxy.

## Other settings

| Option | Use |
| --- | --- |
| `camouflage.wss_path` | WebSocket path, default `/ws`. Choose an ordinary-looking path such as `/assets/live` so a web server or CDN can route it to lowertier and serve everything else itself. The server answers an upgrade only on this path with a valid token. A path in the peer URI overrides it. |
| `camouflage.http_host` | HTTP authority sent on HTTP/2 and WSS. |
| `camouflage.sni_routing` | Classify by server name instead of the admission marker. |

HTTP/2 and WSS pick up camouflage changes on new connections. QUIC caches them until the instance restarts.
