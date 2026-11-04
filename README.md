# lowertier

lowertier is an L2-first mesh VPN for command-line deployments.

LowTier carries Ethernet frames between peers through the LowTier routing and transport engine.
One binary, `lowertier`, runs nodes, manages them, and shows a live dashboard.

This guide covers the command-line program.
It does not cover a web interface or graphical client.

## What LowTier provides

- Native TAP transport for complete Ethernet behavior on Linux.
- An Ethernet overlay with an IP-only TUN edge on macOS and Windows.
- Routed TUN mode for lower packet overhead.
- Unprivileged SOCKS5 and HTTP proxy mode without TUN or TAP.
- QUIC/HTTP/3 underlay by default, with H2 and WSS also available.
- Peer discovery, NAT traversal, subnet routes, exit nodes, ACLs, and port forwarding.
- Paths through chosen nodes, with load-balanced relay groups and exits. See [paths](docs/paths.md).
- ChaCha20-Poly1305 authenticated encryption, always on.
- Noise peer authentication with replay protection for every peer.

## Program model

| Program | Purpose |
| --- | --- |
| `lowertier run` | Runs nodes: the virtual interface, peer links, routing, and proxies. |
| `lowertier status`, `get`, `set`, and other commands | Read state and change settings through the local management portal. |
| `lowertier top` | Live terminal dashboard of peers, routes, relay traffic, and logs. |
| `lowertier gui` | Browser interface for modes, routing, traffic, and settings. See [browser interface](docs/gui.md). |
| `lowertier-tracker` | Serves UDP and HTTP tracker discovery for public or self-hosted bootstrap. |

Each node starts the browser interface on its overlay address by default. Access uses the node's GUI key and configured source networks; see [browser interface](docs/gui.md).

See [tracker discovery](docs/tracker-discovery.md) for client configuration, peer-assisted punching, and HTTP deployment behind a proxy or CDN.
See [mesh health](docs/mesh-health.md) for the peer authentication scopes and UDP forwarding counters.

The packet path has four main parts.

```text
Application or Ethernet host
        |
TAP, TUN, or local proxy
        |
LowTier route and Ethernet fabric
        |
Encrypted QUIC/HTTP/3, H2, or WSS link
        |
Remote LowTier peer
```

## Automatic interface adapter

LowTier selects the interface adapter from operating system capabilities.

| Adapter | Configuration | Local interface | Ethernet support | Privilege |
| --- | --- | --- | --- | --- |
| Automatic | `tun.mode = "kernel"` (default) | TAP on Linux and FreeBSD | Complete L2 with compact IP | Required |
| Automatic IP | `tun.mode = "kernel"` (default) | TUN on other systems | IP | Required |
| Userspace networking | `tun.mode = "userspace"` | None | No | Not required |
| No interface | `tun.mode = "none"` | None | No | Not required |

Native Ethernet supports ARP, VLAN, QinQ, LLDP, broadcast, multicast, and unknown EtherTypes.
Native Ethernet requires Linux or FreeBSD.

All adapters use the unified fabric protocol.
The TUN adapter receives only IPv4 and IPv6 packets.
LowTier uses compact IP for normal transfers from both adapters.

Userspace networking follows the Tailscale application-proxy model.
It does not provide ARP, raw Ethernet, transparent ping, or host routes.

## Build

Install rustup and the platform build tools; Cargo selects the nightly pinned in `rust-toolchain.toml`.

```bash
git clone https://github.com/lowertier/lowerTier.git
cd lowertier
cargo build --release --locked -p lowertier --bins
sudo install -m 0755 target/release/lowertier /usr/local/bin/lowertier
lowertier --version
```

The default build includes TAP/TUN, QUIC/H2/WSS, unprivileged proxy support, the `top` dashboard, and mimalloc so process RSS can fall after load.
The release profile uses fat LTO, optimization level 3, one code generation unit, symbol stripping, and aborting panics.
Development and test builds retain panic unwinding for diagnostics.

Use `--features full` only when the deployment requires Magic DNS; it does not change transport availability.
Build with `--no-default-features --features tun,socks5,mimalloc` to leave out the dashboard.

## Start a network

`lowertier init` writes a configuration, a random network secret, and an identity key.
The secret and key files are created with mode 0600 next to the configuration.

Node A:

```bash
lowertier init office.toml --network office-l2 --ipv4 10.44.0.1/24
sudo lowertier run -c office.toml
```

Copy `office.secret` to node B through a secure channel, then on node B:

```bash
lowertier init office.toml --network office-l2 --ipv4 10.44.0.2/24 \
  --peer quic://192.0.2.10:11012
cp /path/to/copied/office.secret office.secret
sudo lowertier run -c office.toml
```

Replace `192.0.2.10` with the reachable address of node A.
Permit TCP port `11010` and TCP and UDP port `11012` through the host and network firewalls.

Check the network from either node.

```bash
sudo lowertier status
sudo lowertier doctor
sudo lowertier top
sudo lowertier gui
ping 10.44.0.2
```

The commands find a running node by itself.
Nodes run as root read a token file that only root can read, so the commands need `sudo`.
Set `control.token_group` to let members of a group manage the node without `sudo`.

Add `[l2] bridge = true` on Linux nodes that should accept complete Ethernet frames from bridged hosts.
LowTier selects native Ethernet on Linux and an IP interface on macOS; both join one network.
The macOS `utun` interface does not expose arbitrary Ethernet frames.

## Run without administrator privileges

Userspace networking creates no TUN or TAP interface.
Applications connect through a local SOCKS5 or HTTP proxy.

```toml
[tun]
mode = "userspace"

[proxy]
socks5 = "127.0.0.1:1055"
http = "127.0.0.1:1055"
```

Configure an application with standard proxy variables.

```bash
export ALL_PROXY=socks5h://127.0.0.1:1055
export HTTP_PROXY=http://127.0.0.1:1055
export HTTPS_PROXY=http://127.0.0.1:1055
```

The shared listener detects SOCKS5 or HTTP from the first client byte.
SOCKS5 supports TCP and UDP association.
HTTP supports `CONNECT` and ordinary forwarding.

The local proxy has no authentication.
Bind the proxy to `127.0.0.1` or `::1`.

See [userspace networking](docs/userspace-networking.md) for protocol limits and measured results.

## Configuration files

Every option has one dotted path, such as `relay.policy`.
The same path works in the file, on the command line, and against a running node.

| Where | Form |
| --- | --- |
| Configuration file | `[relay]` then `policy = "latency"` |
| Starting a node | `lowertier run -c node.toml --set relay.policy=latency` |
| Running node | `lowertier set relay.policy=latency` |
| Reference | `lowertier config explain relay.policy` |

A production-oriented native L2 example:

```toml
[node]
instance_name = "office"
hostname = "node-a"

[network]
name = "office-l2"
secret_file = "/etc/lowertier/office.secret"

[identity]
private_key_file = "/etc/lowertier/office.key"

[address]
ipv4 = "10.44.0.1/24"

[transport]
listen = ["quic://0.0.0.0:11012", "tcp://0.0.0.0:11010", "wss://0.0.0.0:11012"]

[[peer]]
uri = "quic://192.0.2.11:11012"

[l2]
bridge = true
flood_bytes_per_second = "64MiB"

[relay]
policy = "latency"
```

Validate files before startup. Every problem is reported at once, and renamed options name their replacement.

```bash
lowertier check -c /etc/lowertier/office.toml
```

Start one or more files, or every `.toml` file in a directory.

```bash
sudo lowertier run -c /etc/lowertier/office.toml
sudo lowertier run --config-dir /etc/lowertier/nodes
```

`--set PATH=VALUE` overrides file values for one run and keeps the file unchanged.
Without a file, `--set` values alone describe a node:

```bash
lowertier run --set network.name=office-l2 --set network.secret_file=office.secret \
  --set tun.mode=userspace --set proxy.socks5=127.0.0.1:1055 --set peer=quic://192.0.2.10:11012
```

Values accept units: durations (`30s`, `5m`), rates in bit/s (`8Mbit`, `1Gbit`), and sizes (`256KiB`, `1GiB`).
Plain integers use the base unit listed in the reference.

LowTier expands `${NAME}`, `$NAME`, and `${NAME:-default}` in TOML files.
A file with an expanded variable becomes read-only through the management commands.
`LOWTIER_CONFIG` holds comma-separated file paths used when `run` and `check` get no `-c`.

Options from earlier releases are rejected with their new path.
There is no automatic migration; `lowertier check` lists every rename in a file.

## Configuration reference

`lowertier config explain` prints this list, and `lowertier config explain PATH` describes one option.
"Applies" says when a change to a running node takes effect: immediately, for new connections, after an instance restart, or after a process restart.

| Option | Type | Default | Applies | Purpose |
| --- | --- | --- | --- | --- |
| `node.hostname` | string | - | live | Name shown to peers. Defaults to the system host name. |
| `node.instance_name` | string | `default` | restart | Local instance name. Distinguishes instances in one process. |
| `node.instance_id` | string | - | restart | Stable instance UUID. Generated when absent. |
| `node.netns` | string | - | restart | Linux network namespace to run in. |
| `node.threads` | integer | `2` | restart | Runtime worker threads. 1 runs single-threaded. |
| `control.portal` | string | `127.0.0.1:15888` | process restart | Loopback management portal. Default 127.0.0.1:15888, or a free port up to 15899. |
| `control.portal_allow` | string list | - | process restart | Extra CIDRs admitted to the portal in addition to loopback. |
| `control.token_file` | path | - | process restart | Control token file. Created with mode 0600 when absent. |
| `control.token_group` | string | - | process restart | Unix group that may read the token file (mode 0640). |
| `identity.private_key` | secret string | - | restart | Base64 X25519 private key. Generated when absent. |
| `identity.private_key_file` | path | - | restart | File that holds identity.private_key. |
| `identity.public_key` | string | - | restart | Base64 X25519 public key. Must match the private key. |
| `identity.credential_root` | string | - | restart | Pinned credential root fingerprint (base64). |
| `network.name` | string | `default` | restart | Network name. Peers must use the same name. |
| `network.secret` | secret string | - | restart | Shared network secret. |
| `network.secret_file` | path | - | restart | File that holds network.secret. |
| `network.credential` | secret string | - | restart | Signed credential bundle. Replaces network.secret. |
| `network.credential_file` | path | - | restart | Store for credentials issued by this node. |
| `network.cipher` | chacha20-poly1305 \| aes-gcm \| aes-256-gcm | `chacha20-poly1305` | restart | Data cipher. Peers must agree. |
| `address.ipv4` | string | - | restart | Virtual IPv4 address with prefix, for example 10.126.126.1/24. |
| `address.ipv6` | string | - | restart | Virtual IPv6 address with prefix. |
| `address.dhcp` | bool | `false` | restart | Choose a free virtual IPv4 address automatically. |
| `address.public_ipv6.provide` | bool | `false` | restart | Lease this node's public IPv6 prefix to peers (Linux). |
| `address.public_ipv6.auto` | bool | `false` | restart | Obtain a public IPv6 address from a providing peer. |
| `address.public_ipv6.prefix` | string | - | restart | Public IPv6 prefix to lease instead of auto-detection. |
| `tun.mode` | kernel \| userspace \| none | `kernel` | restart | kernel: TUN/TAP device. userspace: in-process stack for proxies and forwards. none: no local interface. |
| `tun.name` | string | - | restart | Device name. Chosen automatically when empty. |
| `tun.mtu` | integer | `1380` | restart | Overlay MTU in bytes. |
| `tun.ipv6` | bool | `true` | restart | Carry IPv6 on the virtual interface. |
| `tun.udp_broadcast_relay` | bool | `false` | restart | Relay UDP broadcasts from the virtual interface (Windows). |
| `transport.protocols` | string list | - | restart | Allowed transports: quic, tcp, wss. Empty allows all. |
| `transport.prefer` | quic \| tcp \| wss | `quic` | restart | Transport tried first for discovered peers. |
| `transport.listen` | string list | - | restart | Listener URLs, for example quic://0.0.0.0:11012. |
| `transport.advertise` | string list | - | restart | Public listener URLs announced to peers, for port mappings. |
| `transport.quic.initial_receive_window` | bytes | `2MiB` | restart | Initial QUIC stream receive window. |
| `transport.quic.receive_window` | bytes | `4MiB` | restart | Maximum QUIC connection receive window. |
| `peer` | table array | - | restart | Peers to connect to: uri and optional pinned public_key. |
| `nat.p2p` | on \| lazy \| required \| off | `on` | restart | Direct connections: on, lazy (only when traffic needs it), required (never relay), off. |
| `nat.udp_punch` | bool | `true` | restart | UDP hole punching. |
| `nat.tcp_punch` | bool | `true` | restart | TCP hole punching. |
| `nat.symmetric_punch` | bool | `true` | restart | Hole punching toward symmetric NATs. |
| `nat.stun` | string list | - | restart | IPv4 STUN servers. Built-in list when absent. |
| `nat.stun_v6` | string list | - | restart | IPv6 STUN servers. Built-in list when absent. |
| `nat.stun_tcp` | string list | - | restart | TCP STUN servers. |
| `underlay.deny_interfaces` | string list | - | restart | Local interfaces the underlay must not use. |
| `underlay.deny_cidrs` | string list | - | restart | Local and remote CIDRs the underlay must not use. |
| `underlay.bind_device` | bool | `true` | restart | Bind underlay sockets to the physical device. |
| `underlay.socket_mark` | integer | - | restart | SO_MARK for underlay sockets (Linux). |
| `discovery.trackers` | string list | - | restart | Public BitTorrent trackers used for peer discovery. |
| `discovery.private_trackers` | string list | - | restart | lowertier-tracker servers used for peer discovery. |
| `discovery.bind` | string | - | restart | Local socket address for discovery traffic. |
| `discovery.advertise` | string | - | restart | Socket address announced to trackers. |
| `relay.policy` | hop \| latency \| goodput | `hop` | live | Route metric. goodput needs relay.probe_budget_bps. |
| `relay.use_relays` | bool | `true` | live | Send local data through relay peers. |
| `relay.transit` | allow \| avoid \| deny | `allow` | live | Carry data for other peers. |
| `relay.transit_networks` | string list | - | live | Foreign network name patterns this node relays. ["*"] permits all. |
| `relay.transit_bps_limit` | bit/s | - | live | Shared transit budget. Unlimited when absent. |
| `relay.transit_burst_bytes` | bytes | - | live | Transit burst capacity. |
| `relay.probe_interval_seconds` | duration | `30` | live | Interval between goodput probes. |
| `relay.probe_budget_bps` | bit/s | `0` | live | Bandwidth for goodput probes. |
| `relay.link_cost` | table array | - | live | Adjacent link cost bias: peer public key and bias_ms. |
| `relay.foreign_rpc` | bool | `false` | restart | Relay control RPC for foreign networks outside relay.transit_networks. |
| `relay.private_mode` | bool | `false` | restart | Reject foreign networks without authorized admission. |
| `camouflage.server_name` | string | - | new connections; QUIC restart | TLS server name (SNI). |
| `camouflage.tls_cert` | path | - | new connections; QUIC restart | TLS certificate file. Set together with tls_key. |
| `camouflage.tls_key` | path | - | new connections; QUIC restart | TLS private key file. |
| `camouflage.admission_secret` | secret string | - | new connections; QUIC restart | Secret that separates VPN clients from website visitors (16+ bytes). |
| `camouflage.website_root` | path | - | new connections; QUIC restart | Static website served to unauthenticated visitors. |
| `camouflage.sni_routing` | bool | `false` | new connections; QUIC restart | Classify connections by SNI instead of the admission marker. |
| `camouflage.decoy_upstream.tcp` | string | - | new connections; QUIC restart | TCP decoy upstream for unauthenticated connections. |
| `camouflage.decoy_upstream.udp` | string | - | new connections; QUIC restart | UDP decoy upstream for unauthenticated connections. |
| `camouflage.wss_path` | string | `/ws` | new connections | WebSocket path. |
| `camouflage.http_host` | string | - | new connections | HTTP authority for H2 and WSS. |
| `camouflage.trusted_proxy_cidrs` | string list | - | new connections | Reverse proxies trusted for client addresses. |
| `limits.memory_bytes` | bytes | - | process restart | Process memory budget. Default: RAM/16, 64MiB to 1GiB. |
| `limits.receive_bps` | bit/s | - | live | Instance receive limit. Unlimited when absent. |
| `l2.fdb_capacity` | integer | `16384` | restart | Forwarding database entries. |
| `l2.fdb_age` | duration | `300` | restart | Forwarding database entry lifetime. |
| `l2.flood_bytes_per_second` | bytes | `64MiB` | restart | Unknown-unicast, broadcast, and multicast budget per second. 0 disables. |
| `l2.bridge` | bool | `false` | restart | Accept complete Ethernet frames from this admin node. |
| `l2.max_macs_per_peer` | integer | `256` | restart | MAC addresses each peer may own. 0 disables the limit. |
| `l2.mac_move_hold` | duration | `5` | restart | Hold time before a MAC may move to another peer. |
| `l2.vlans` | integer list | - | restart | Allowed VLAN IDs. Empty allows all; 0 means untagged. |
| `l2.ether_types` | integer list | - | restart | Allowed EtherTypes. Empty allows all. |
| `routes.manual` | string list | - | restart | Routes installed instead of the automatic routes. |
| `routes.serve_exit` | bool | `false` | restart | Act as an exit node for peers. |
| `group` | table array | - | live | Load-balance groups: name, members (peer keys or virtual IPs), balance (flow or failover), weights. |
| `path` | table array | - | live | Paths: to (peer, CIDR, or internet), via (peers or groups in order), gateway (peer or group), strict. |
| `export` | table array | - | restart | Local subnets exported to peers: cidr, optional mapped_cidr and allow. |
| `proxy.socks5` | host:port | - | restart | SOCKS5 listener into the network. |
| `proxy.http` | host:port | - | restart | HTTP proxy listener into the network. |
| `proxy.system_forward` | bool | `false` | restart | Forward exported subnets with the system stack. |
| `forward` | table array | - | restart | Port forwards: proto, bind, dest. |
| `dns.accept` | bool | `false` | restart | Serve magic DNS for peer host names. |
| `dns.zone` | string | `et.net.` | restart | Magic DNS zone. |
| `acl` | table | - | live | ACL chains and groups. |
| `acl.tcp_ports` | string list | - | live | Local TCP ports peers may reach. Empty allows all. |
| `acl.udp_ports` | string list | - | live | Local UDP ports peers may reach. Empty allows all. |
| `log.console` | string | - | process restart | Console log level: off, error, warn, info, debug, trace. |
| `log.file` | string | - | process restart | File log level. |
| `log.dir` | path | - | process restart | File log directory. |
| `log.max_size_mb` | integer | - | process restart | File size before rotation, in MiB. |
| `log.max_files` | integer | - | process restart | Rotated files to keep. |

Peer, export, and forward entries are arrays of tables:

```toml
[[peer]]
uri = "quic://192.0.2.10:11012"
public_key = "<base64-x25519-public-key>"   # optional pin

[[export]]
cidr = "10.20.0.0/16"
mapped_cidr = "172.20.0.0/16"                # optional
allow = ["tcp", "udp", "icmp"]               # optional

[[forward]]
proto = "tcp"
bind = "127.0.0.1:8080"
dest = "10.44.0.2:80"
```

Peer schemes are `quic` (HTTP/3), `tcp` (HTTP/2), and `wss`.
Connector-only discovery schemes are `http`, `https`, `txt`, and `srv`.
Unix builds also support `unix` sockets.

Listeners are QUIC/HTTP/3, H2 over TLS, and WSS. Plain `ws://` and raw `udp://` underlays are rejected.

| Scheme | Network protocol | Default port |
| --- | --- | ---: |
| `quic` | HTTP/3 over QUIC/UDP | 11012 |
| `tcp` | HTTP/2 over TLS/TCP | 11010 |
| `wss` | WebSocket over TLS/TCP | 11012 |

An empty `transport.listen` creates an outbound-only node.
The default QUIC listener is `11012`, not `443`. HTTP/3 does not require port 443.
Bind `quic://0.0.0.0:443` only when a network allows UDP/443 and blocks other UDP.
That bind needs root or `CAP_NET_BIND_SERVICE`, and it collides with a local HTTPS server.
For a TLS-terminating CDN, configure [WSS CDN mode](docs/wss-cdn.md) at both endpoints.

### Identity and credentials

Every node authenticates peers with Noise and an X25519 identity key.
Without `identity.private_key` or `identity.private_key_file`, LowTier generates a key at startup.
Pin `peer.public_key` when a shared or relay node must have a stable verified identity.
LowTier uses Noise XX for direct authentication and Noise IK on relay paths,
with X25519, ChaCha20-Poly1305, SHA-256, sequence nonces, and replay windows.
The protocol uses LowTier's own packet format and has not received an external security audit.

Credential nodes omit `network.secret` and join with `network.credential`, a signed bundle issued by `lowertier creds issue`.

### ACL configuration

ACL chains inspect inbound, outbound, or forwarded IP traffic.
Native Ethernet frames do not enter IP ACL parsing.

```toml
[acl]
tcp_ports = ["22", "8000-8100"]   # local ports peers may reach; empty allows all

[[acl.acl_v1.chains]]
name = "protect-exported-subnet"
description = "Permit administrators and drop other forwarded traffic."
chain_type = 3
enabled = true
default_action = 2

[[acl.acl_v1.chains.rules]]
name = "allow-administrators"
description = "Permit the administrator overlay range."
priority = 1000
enabled = true
protocol = 5
ports = []
source_ports = []
source_ips = ["10.44.0.0/24"]
destination_ips = ["10.20.0.0/16"]
source_groups = []
destination_groups = []
action = 1
rate_limit = 0
burst_limit = 0
stateful = true
```

ACL numeric values use the following mappings.

| Type | Values |
| --- | --- |
| `chain_type` | `1` inbound, `2` outbound, `3` forward |
| `protocol` | `0` unspecified, `1` TCP, `2` UDP, `3` ICMP, `4` ICMPv6, `5` any |
| `action` and `default_action` | `0` no operation, `1` allow, `2` drop |

Higher `priority` values run first.
`ports` selects destination ports and `source_ports` selects source ports.
A zero `rate_limit` disables the packet rate limit.

ACL groups use shared group names and secrets.

```toml
[acl.acl_v1.group]
members = ["administrators"]

[[acl.acl_v1.group.declares]]
group_name = "administrators"
group_secret = "<group-secret>"
```

### NAT traversal

QUIC NAT traversal exchanges candidates through authenticated peer RPC.
It retains the selected UDP socket for the QUIC connection.
When one peer has destination-dependent mappings, traversal can use a bounded socket pool and public-port search.
The search respects the underlay policy and `nat.symmetric_punch`.
`nat.udp_punch = false` disables the QUIC traversal coordinator.
This UDP procedure does not establish H2 or WSS connections.
H2 and WSS use authenticated TCP rendezvous and simultaneous open.
TCP traversal retains one source port for listening, STUN, and peer connections.
The initiator nominates one TLS connection before the peers verify their identities.
`transport.prefer = "wss"` selects WSS traversal; other values select H2 for TCP traversal.
`nat.tcp_punch = false` disables both TCP traversal protocols.
Destination-dependent TCP mappings can still prevent direct connections.
Candidate discovery uses current interface addresses and configured underlay restrictions.
Production traversal does not require a fixed physical interface name.
When a mapped address is also a local address, traversal can reserve its mapped port exclusively.
TCP retains the original listener. QUIC also retries the original STUN socket.
Peer authentication must succeed before the direct connection becomes active.
See the [eth0 traversal measurements](docs/performance/eth0-direct-20260922.md) for verified behavior and limits.
See the [osku–UTMOWRT measurements](docs/performance/osku-utmowrt-20260922.md) for all three traversal protocols.


### Camouflage

Tests, demos, and examples use `challenges.cloudflare.com` because that
host is reachable. Peers connect to your public IP on port 443 with that
SNI. Nginx stream-passthroughs TCP and UDP to LowTier. Marked LowTier
clients become a VPN hop. Unmarked probes are spliced to the real
Cloudflare host and complete TLS with Cloudflare's certificate.

Configure the same `camouflage.admission_secret` on credential peers. Secret-based
networks use `network.secret` when `camouflage.admission_secret` is empty. LowTier
rotates the encrypted admission token every five minutes.

```toml
[transport]
listen = ["tcp://127.0.0.1:8443", "quic://127.0.0.1:8443"]
advertise = ["tcp://0.0.0.0:443", "quic://0.0.0.0:443"]

[camouflage]
server_name = "challenges.cloudflare.com"
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

Do not enable `ssl_preread` on that TCP listener. Marked HTTP/2 clients send a
tiny TLS handshake record before the real ClientHello so shallow DPI still
sees `16 03 01`. Preread would parse that record as a ClientHello and fail.
Nginx only forwards bytes. LowTier distinguishes peers from probes.

Decoy passthrough shares process-wide and per-source-IP bandwidth limits, with
burst allowance, across TCP and UDP. TCP uses backpressure; QUIC responses are
paced without changing their contents. UDP also has a pre-return-path
anti-amplification bound. See [passthrough limits and upstream requirements](docs/decoy-passthrough.md).

The upstream must support HTTP/3 on UDP port 443. This decoy path currently
supports IPv4 listeners and IPv4 upstream endpoints. Marked packets enter the
local QUIC endpoint through the public socket and do not use a loopback UDP
relay. TCP listeners use the same flags. A client with a valid routing prefix
reaches local HTTP/2. Every other TCP flow is spliced to
`camouflage.decoy_upstream`. TCP does not serve `camouflage.website_root`. The local
LowTier path uses Noise authentication and does not require a certificate for
the upstream name.

To serve your own static site instead of a Cloudflare decoy, set
`camouflage.website_root` and omit `camouflage.decoy_upstream`. LowTier then terminates
TLS for `camouflage.server_name` and loads
`/etc/letsencrypt/live/<server_name>/fullchain.pem` and `privkey.pem`
unless you set explicit certificate paths.

```toml
[camouflage]
server_name = "challenges.cloudflare.com"
admission_secret = "replace-with-a-random-shared-secret"
website_root = "/var/www/lowertier"
```

Leave `camouflage.sni_routing` off for this camouflage. Peers and probes
share the `challenges.cloudflare.com` SNI, so Nginx cannot split TCP by
name. HTTP/2 is still Nginx-forwardable: use the dumb stream block above,
not `ssl_preread`. Marked clients send a tiny TLS record then ClientHello;
Nginx forwards bytes; LowTier splices unmarked TCP to Cloudflare.

A TLS-terminating CDN cannot forward the existing CONNECT-IP or HTTP/3
DATAGRAM sessions unchanged. Direct WSS uses TLS exporter binding.
Use `via=cdn` at both WSS endpoints to carry an inner TLS connection through the CDN.
The inner TLS exporter remains bound to Noise peer authentication.
See [WSS CDN mode](docs/wss-cdn.md) for origin configuration and compatibility limits.

## Goodput routing

Goodput routing measures each direct direction independently.
Set a positive probe budget before selecting the goodput policy.

```toml
[relay]
policy = "hop"
probe_interval_seconds = 30
probe_budget_bps = 1000000
```

The example permits 1 Mbit/s of average probe traffic across the node.
Set `policy = "goodput"` after fresh samples appear.
The selector first minimizes avoided transit nodes.
It then maximizes the path's minimum valid directed delivery rate.
Equal bottlenecks use cost, hop count, and first-hop peer ID.
Destination-specific bottleneck thresholds preserve the cost tie-breaker.
Expired or missing samples use latency and then hop fallback.
Every data fallback excludes denied transit nodes.
Authenticated routing and handshake control use a separate hop table.
Complete Ethernet control frames still follow data transit restrictions.

Use `policy = "hop"` to restore hop selection.
Set `probe_budget_bps = 0` to stop measurement after changing the policy.
See [control configuration and migration](docs/control-config.md) for units, defaults, and retired options.

## Managing a running node

The commands talk to a node through its loopback management portal.
A running node records its portal and token file, so the commands find it without options.
`lowertier nodes` lists running nodes; pick one with `-n NAME` when several run.
`-p ADDR` and `--token-file PATH` select a portal and token directly.
`-i NAME` selects an instance when one node runs several.

| Command | Purpose |
| --- | --- |
| `status` | Node, addresses, NAT, discovery, listeners, relay, and peers on one screen. |
| `doctor` | Check token access, portal, instances, listeners, NAT, trackers, peers, and loss. Prints a fix for each problem. |
| `top` | Live dashboard. Tab or 1-5 switch panes, j/k move, Enter shows detail, `/` filters, `q` quits. |
| `get [PATH]` | Show the active configuration, and staged values when they differ. |
| `set PATH=VALUE...` | Change options in one transaction. |
| `unset PATH...` | Remove options so their defaults apply. |
| `edit` | Edit the configuration in `$EDITOR`, then apply the difference. |
| `config explain [PATH]` | Describe options. Works without a running node. |
| `peers [list\|show\|add\|rm]` | Peers with RTT, loss, rate, and session state; configured peer URIs. |
| `routes [list\|trace DEST]` | Routes, or the selected path to a destination hop by hop. |
| `relay`, `camouflage`, `discovery` | Relay policy and drops; camouflage settings; trackers and NAT observations. |
| `listeners [list\|add\|rm]` | Active listeners and configured listener URIs. |
| `l2 [fdb\|stats]` | Ethernet forwarding entries and counters. |
| `acl [show\|stats\|set FILE]` | ACL rules and counters. |
| `forward [list\|add\|rm]` | Port forwards. |
| `creds [list\|issue\|revoke]` | Network credentials. Requires `--admin-token` or `LOWTIER_ADMIN_TOKEN`. |
| `instance [list\|create FILE\|start\|stop\|delete]` | Instances inside one node process. |
| `stats [--prometheus] [-w]` | Metrics, once or whenever they change. |
| `logs [-f]`, `log-level [LEVEL]` | Recent log lines, optionally followed; the daemon log level. |
| `service install -- ARGS` | Register `lowertier run ARGS` with the system service manager. |

`set`, `unset`, and `edit` save the change to the node's configuration file.
`--no-persist` changes the running node only.
Each change reports whether it applied now, applies to new connections, or waits for an instance restart.
Changes that need a restart are refused unless `--stage` stores them; `lowertier instance stop` and `start` then apply them.
`--expected-revision N` refuses the change if the configuration moved on.

```bash
lowertier set relay.policy=latency relay.transit_bps_limit=50Mbit
lowertier set tun.mtu=1280 --stage
lowertier get relay
lowertier routes trace 10.44.0.2
lowertier peers add quic://192.0.2.12:11012
```

`-o json` prints one envelope with `schema_version`, `request_id`, `instance_id`, `revision`, `data`, and `error`.
Exactly one of `data` or `error` contains a value. Followed output prints one envelope per line.
Exit codes: 0 success, 1 internal error, 2 invalid arguments or configuration, 3 permission,
4 missing or ambiguous node, instance, or resource, 5 revision conflict or restart required,
6 connection or deadline, 7 partial failure or a failed `doctor` check.

`lowertier completion SHELL` prints a completion script for bash, elvish, fish, PowerShell, zsh, or Nushell.

## L2 forwarding behavior

LowTier learns valid unicast source MAC addresses in a bounded forwarding database.
Known unicast frames go to one routed destination peer.
Unknown unicast, multicast, and broadcast frames go only to peers that advertise Ethernet input.

LowTier removes forwarding entries after their age limit or peer disconnection.
The flood limiter controls replicated bytes for each second.
Keep a finite flood limit on production meshes.

TAP uses native Ethernet frames at the host boundary.
Normal IP traffic uses compact routed packets on the wire.
TUN uses the same compact IP representation.

See [the Ethernet operator guide](docs/l2-tap.md) for frame-level details.

## Underlay path control

Use deny rules when LowTier must avoid another VPN or physical interface.

```toml
[nat]
stun = ["192.0.2.20:3478"]
stun_v6 = ["[2001:db8::20]:3478"]

[underlay]
deny_interfaces = ["tailscale0", "utun5"]
deny_cidrs = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
```

Deny CIDRs match local source addresses and remote destinations.
Interface names must match exactly.
Interface names such as macOS `utun5` can change after restart.

Strict deny policy requires literal peer and STUN addresses.
The policy disables hostname and HTTP-based discovery paths.

Restart the instance after an underlay policy change.

## QUIC on lossy links

Inner transports own congestion control. QUIC only provides packet protection.

```toml
[transport.quic]
initial_receive_window = "8MiB"
receive_window = "32MiB"
```

Normal Ethernet frames use plain QUIC DATAGRAM records.
LowTier does not retransmit these records.
Inner TCP handles lost TCP-bearing Ethernet frames.
ARP, DHCP, and IPv6 neighbor-discovery frames use the reliable QUIC stream.

## Security and traffic visibility

LowTier always encrypts peer payloads with authenticated encryption, ChaCha20-Poly1305 by default.
Relay routing fields remain outside the payload AEAD.

Noise authentication protects the complete peer header and payload inside the link envelope,
and adds peer authentication, key epochs, and replay rejection.
Pin public peer keys when a shared or relay node must have a stable verified identity.

An observer can still see endpoints, packet sizes, timing, direction, transport type, and a random connection identifier.
UDP setup packets and QUIC traffic remain classifiable.
LowTier does not claim active-probing resistance or covert transport.

See [dataplane cryptography](docs/security/dataplane-crypto.md) for the protocol boundary.

## Measured performance

The latest protected native TAP test used a QEMU ARM64 environment.

| Path | Median throughput |
| --- | ---: |
| Protected LowTier TAP | 3.35 Gbit/s |
| Basic LowTier TAP | 3.84 Gbit/s |
| Kernel WireGuard L3 | 5.76 Gbit/s |

Protected TAP used about 39 MiB of combined memory for two processes.
Native TAP carries complete Ethernet frames.
Kernel WireGuard carries L3 packets.
The comparison is not feature equivalent.

The unprivileged proxy path reached about 106 through 125 Mbit/s.
Its steady-state RTT overhead remained below 0.2 ms in the same-host test.
The shared proxy process used about 24 MiB of idle resident memory.

See [L2 profile results](docs/performance/l2-profile-memory-results.md).
See [WireGuard comparison](docs/performance/wireguard-resource-comparison.md).
See [userspace networking results](docs/performance/userspace-networking-results.md).

## Troubleshooting

Start with `lowertier doctor`. It checks each layer in order and prints a fix for each problem.

| Symptom | Check |
| --- | --- |
| `lowertier check` reports renamed options | Edit the file as listed. Each message names the new option path. |
| `Cannot read the control token` | Run the command with `sudo`, or set `control.token_group` and restart the node. |
| `Several daemons are running` | Pick one with `-n NAME`; `lowertier nodes` lists them. |
| A peer stays unreachable | `lowertier peers`, `lowertier listeners`, `lowertier discovery`; check firewall access to every listener, or try an explicit QUIC, TCP, or WSS peer URI. |
| Large transfers stall | `lowertier doctor` reports high loss; try `lowertier set tun.mtu=1280`. |
| L2 discovery fails | Both peers need Ethernet input (`l2.bridge` on Linux) and a finite `l2.flood_bytes_per_second`. VLAN, QinQ, LLDP, and unknown EtherTypes need native Ethernet on both edges. |

Do not expose the management portal to an untrusted network; it binds to loopback.
`lowertier --help` and `lowertier COMMAND --help` reflect the features compiled into the binary.

## License

LowTier remains under the repository license.
See [LICENSE](LICENSE) for the complete terms.
