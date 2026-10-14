# lowertier

lowertier is an L2-first mesh VPN for command-line deployments.

LowTier carries Ethernet frames between peers through the LowTier routing and transport engine.
The project provides the `lowertier-core` and `lowertier-cli` binaries.

This guide covers only the command-line programs.
It does not cover a web interface or graphical client.

## What LowTier provides

- Native TAP transport for complete Ethernet behavior on Linux.
- An Ethernet overlay with an IP-only TUN edge on macOS and Windows.
- Routed TUN mode for lower packet overhead.
- Unprivileged SOCKS5 and HTTP proxy mode without TUN or TAP.
- QUIC/HTTP/3 underlay by default (stealth DATAGRAM fabric). UDP and TCP remain available.
- Peer discovery, NAT traversal, subnet routes, exit nodes, ACLs, and port forwarding.
- ChaCha20-Poly1305 authenticated encryption by default.
- An optional secure mode with Noise authentication and replay protection.

## Program model

LowTier provides a VPN daemon, a control client, and an optional tracker service.

| Program | Purpose |
| --- | --- |
| `lowertier-core` | Runs the VPN instance, virtual interface, peer links, routing, and proxies. |
| `lowertier-cli` | Reads status and changes supported runtime settings through the RPC portal. |
| `lowertier-tracker` | Serves UDP and HTTP tracker discovery for public or self-hosted bootstrap. |

See [tracker discovery](docs/tracker-discovery.md) for client configuration, peer-assisted punching, and HTTP deployment behind a proxy or CDN.

`lowertier-cli` prints tables by default.
Use `--output json` for scripts.
The repository does not provide a separate TUI binary.

The packet path has four main parts.

```text
Application or Ethernet host
        |
TAP, TUN, or local proxy
        |
LowTier route and Ethernet fabric
        |
Encrypted QUIC/HTTP/3, UDP, or TCP link
        |
Remote LowTier peer
```

## Automatic interface adapter

LowTier selects the interface adapter from operating system capabilities.

| Adapter | Configuration | Local interface | Ethernet support | Privilege |
| --- | --- | --- | --- | --- |
| Automatic | No setting | TAP on Linux and FreeBSD | Complete L2 with compact IP | Required |
| Automatic IP | No setting | TUN on other systems | IP | Required |
| Userspace networking | `--tun=userspace-networking` | None | No | Not required |

Native Ethernet supports ARP, VLAN, QinQ, LLDP, broadcast, multicast, and unknown EtherTypes.
Native Ethernet requires Linux or FreeBSD.

All adapters use the unified fabric protocol.
The TUN adapter receives only IPv4 and IPv6 packets.
LowTier uses compact IP for normal transfers from both adapters.

Userspace networking follows the Tailscale application-proxy model.
It does not provide ARP, raw Ethernet, transparent ping, or host routes.

## Build the command-line programs

Install a stable Rust toolchain and the platform build tools.
Then build only the command-line package.

```bash
git clone https://github.com/lowertier/lowerTier.git
cd lowertier
cargo build --release --locked -p lowertier --bins
```

The default build includes TAP/TUN, QUIC/H2/WSS, unprivileged proxy support, and mimalloc so process RSS can fall after load.
The release profile uses fat LTO, optimization level 3, one code generation unit, symbol stripping, and aborting panics.
Development and test builds retain panic unwinding for diagnostics.

Use `--features full` only when the deployment requires Magic DNS, Zstandard, or alternate crypto backends; it does not change transport availability.

The build creates these files.

```text
target/release/lowertier-core
target/release/lowertier-cli
```

Install both files in a directory from `PATH`.

```bash
sudo install -m 0755 target/release/lowertier-core /usr/local/bin/lowertier-core
sudo install -m 0755 target/release/lowertier-cli /usr/local/bin/lowertier-cli
```

Check the installed revision.

```bash
lowertier-core --version
lowertier-cli --version
```

## Start a native L2 network

The following example connects two Linux nodes.
Both nodes must use the same network name and secret.

Generate a strong secret once.

```bash
openssl rand -hex 32
```

Start node A.

```bash
sudo lowertier-core \
  --hostname node-a \
  --enable-bridge \
  --ipv4 10.44.0.1/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --listeners quic://0.0.0.0:11012
```

Start node B.

```bash
sudo lowertier-core \
  --hostname node-b \
  --enable-bridge \
  --ipv4 10.44.0.2/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --peers quic://192.0.2.10:11012
```

Replace `192.0.2.10` with the reachable address of node A.
Permit UDP port `11012` through the host and network firewalls.

Check the network from either node.

```bash
lowertier-cli node show
lowertier-cli peer list
lowertier-cli route list
ping 10.44.0.2
```

Command-line secrets can appear in process inspection tools.
Use a protected configuration file for a production deployment.

## Start a mixed Linux and macOS network

LowTier selects native Ethernet on Linux.
LowTier selects an IP interface on macOS.

Linux:

```bash
sudo lowertier-core \
  --ipv4 10.44.0.1/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>'
```

macOS:

```bash
sudo lowertier-core \
  --ipv4 10.44.0.2/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --peers quic://192.0.2.10:11012
```

The macOS edge carries IP through the fabric protocol.
The macOS `utun` interface does not expose arbitrary Ethernet frames.

## Run without administrator privileges

Userspace networking creates no TUN or TAP interface.
Applications connect through a local SOCKS5 or HTTP proxy.

```bash
lowertier-core \
  --tun=userspace-networking \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --peers quic://192.0.2.10:11012 \
  --socks5-server 127.0.0.1:1055 \
  --outbound-http-proxy-listen 127.0.0.1:1055
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

## Use a configuration file

Create one TOML file for each instance.
Protect files that contain a network secret or private key.

```bash
install -m 0600 /dev/null /etc/lowtier/office.toml
```

The following file is a production-oriented native L2 example.

```toml
instance_name = "office"
hostname = "node-a"
ipv4 = "10.44.0.1/24"
listeners = [
  "quic://0.0.0.0:11012",
  "tcp://0.0.0.0:11010",
  "wss://0.0.0.0:11013",
]

[network_identity]
network_name = "office-l2"
network_secret = "${LOWTIER_NETWORK_SECRET}"

[[peer]]
uri = "quic://192.0.2.11:11012"

[secure_mode]
enabled = true

[flags]
default_protocol = "quic"
enable_encryption = true
encryption_algorithm = "chacha20-poly1305"
mtu = 1380
bind_device = true
l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300
l2_flood_bytes_per_second = 67108864

[relay]
policy = "latency"
```

Validate the file before startup.

```bash
LOWTIER_NETWORK_SECRET='<same-secret>' \
  lowertier-core --config-file /etc/lowtier/office.toml --check-config
```

Start the instance.

```bash
sudo env LOWTIER_NETWORK_SECRET='<same-secret>' \
  lowertier-core --config-file /etc/lowtier/office.toml
```

LowTier expands `${NAME}`, `$NAME`, and `${NAME:-default}` in TOML files.
A file with an expanded variable becomes read-only through remote configuration APIs.
Use `--disable-env-parsing` to keep dollar signs literal.

Command-line values override matching file values.
Use `--config-file` more than once to start several files.
Use `--config-dir` to load every `.toml` file from one directory.

## Complete TOML reference

The following tables cover every user configuration field.
The internal `source` table records configuration ownership.
Normal CLI deployments must omit the `source` table.

### Top-level fields

| Field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `netns` | string | unset | Use a Linux network namespace. |
| `hostname` | string | operating system hostname | Set the peer name. LowTier keeps at most 32 non-control characters. |
| `instance_name` | string | `default` | Select the local instance name. |
| `instance_id` | UUID | generated | Keep a stable instance identity. |
| `ipv4` | IPv4 interface | unset | Set the overlay IPv4 address and prefix. A missing prefix becomes `/24`. |
| `ipv6` | IPv6 interface | unset | Set the overlay IPv6 address and prefix. |
| `ipv6_public_addr_provider` | boolean | `false` | Share a public IPv6 prefix on Linux. |
| `ipv6_public_addr_auto` | boolean | `false` | Request a public IPv6 address from a provider peer. |
| `ipv6_public_addr_prefix` | IPv6 CIDR | unset | Set the public IPv6 prefix to share. |
| `dhcp` | boolean | `false` | Let LowTier select the overlay IPv4 address. |
| `listeners` | URL array | generated by CLI | Set inbound underlay listeners. An empty array disables listeners. |
| `mapped_listeners` | URL array | empty | Advertise manually mapped public listener addresses. |
| `exit_nodes` | IP array | empty | Forward default traffic through these overlay addresses in listed order. |
| `routes` | IPv4 CIDR array | automatic | Replace propagated subnet routes with manual routes. |
| `socks5_proxy` | URL | unset | Listen for SOCKS5 clients. Example: `socks5://127.0.0.1:1055`. |
| `outbound_http_proxy` | URL | unset | Listen for HTTP proxy clients. Example: `http://127.0.0.1:1055`. |
| `tcp_whitelist` | port string array | empty | Allow only listed inbound TCP ports. Supports ports and ranges. |
| `udp_whitelist` | port string array | empty | Allow only listed inbound UDP ports. Supports ports and ranges. |
| `stun_servers` | string array | built-in list | Replace the IPv4 STUN server list. An empty array disables the list. |
| `stun_servers_v6` | string array | built-in list | Replace the IPv6 STUN server list. An empty array disables the list. |
| `tcp_stun_servers` | string array | built-in list | Replace the TCP STUN server list for H2 and WSS traversal. |
| `credential_file` | path | unset | Persist issued temporary credentials on an administrator node. |

### Network identity

```toml
[network_identity]
network_name = "office-l2"
network_secret = "${LOWTIER_NETWORK_SECRET}"
```

| Field | Required | Purpose |
| --- | --- | --- |
| `network_name` | Yes | Identifies the overlay network. |
| `network_secret` | Usually | Authenticates normal network membership and derives default traffic keys. |

Credential nodes omit `network_secret`.
Credential nodes must enable secure mode and supply a credential.

### Peers

Add one `peer` table for each initial connector.

```toml
[[peer]]
uri = "quic://192.0.2.10:11012"
peer_public_key = "<base64-x25519-public-key>"
```

| Field | Required | Purpose |
| --- | --- | --- |
| `uri` | Yes | Selects the peer address and transport or discovery method. |
| `peer_public_key` | No | Pins the peer X25519 public key in secure mode. |

Peer schemes are `quic` (HTTP/3), `tcp` (HTTP/2), and `wss`.
Connector-only discovery schemes are `http`, `https`, `txt`, and `srv`.
Unix builds also support `unix` sockets.

### Listeners

Use explicit URLs when predictable firewall rules are required.

```toml
listeners = [
  "quic://0.0.0.0:11012",
  "tcp://0.0.0.0:11010",
  "wss://0.0.0.0:11013",
]
```

Listeners are QUIC/HTTP/3, H2 over TLS, and WSS.
Plain `ws://` and raw `udp://` underlays are rejected.

| Scheme | Network protocol | Default port from base `11010` |
| --- | --- | ---: |
| `quic` | HTTP/3 over QUIC/UDP | 11012 |
| `tcp` | HTTP/2 over TLS/TCP | 11010 |
| `wss` | WebSocket over TLS/TCP | 11012 |

`--listeners 11010` creates every compiled IP listener with its standard offset.
`--no-listener` creates an outbound-only node.

For a TLS-terminating CDN, configure [WSS CDN mode](docs/wss-cdn.md) at both endpoints.

The default QUIC listener is `11012`, not `443`. HTTP/3 does not require port 443.
Bind `quic://0.0.0.0:443` only when a network allows UDP/443 and blocks other UDP.
That bind needs root or `CAP_NET_BIND_SERVICE`, and it collides with a local HTTPS server.

### Subnet proxy

Add one table for each local subnet.

```toml
[[proxy_network]]
cidr = "10.20.0.0/16"
mapped_cidr = "172.20.0.0/16"
allow = ["tcp", "udp", "icmp"]
```

| Field | Required | Purpose |
| --- | --- | --- |
| `cidr` | Yes | Selects the real local IPv4 subnet. |
| `mapped_cidr` | No | Presents the subnet through another equal-length CIDR. |
| `allow` | No | Limits the exported protocols to `tcp`, `udp`, or `icmp`. |

The CLI shorthand is `--proxy-networks 10.20.0.0/16->172.20.0.0/16`.

### Port forwarding

```toml
[[port_forward]]
bind_addr = "127.0.0.1:8080"
dst_addr = "10.44.0.2:80"
proto = "tcp"
```

`proto` accepts `tcp` or `udp`.
Repeat the table for more forwarding rules.

### Secure mode

```toml
[secure_mode]
enabled = true
local_private_key = "<base64-x25519-private-key>"
local_public_key = "<base64-x25519-public-key>"
```

| Field | Default | Purpose |
| --- | --- | --- |
| `enabled` | `false` | Enables Noise peer authentication and protected link envelopes. |
| `local_private_key` | generated | Sets a stable 32-byte X25519 private key in base64 form. |
| `local_public_key` | derived | Sets the matching X25519 public key in base64 form. |

LowTier uses Noise XX for direct authentication and Noise IK on relay paths.
Secure mode uses X25519, ChaCha20-Poly1305, SHA-256, sequence nonces, and replay windows.
Enable secure mode on every node in one deployment.
Mixed secure versions can fail after the handshake.

Secure mode is a native LowTier protocol.
It uses LowTier's own packet format.
The protected protocol has not received an external security audit.

### ACL configuration

ACL chains inspect inbound, outbound, or forwarded IP traffic.
Native Ethernet frames do not enter IP ACL parsing.

```toml
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

Each rule supports every field shown in the example.
Higher `priority` values run first.
`ports` selects destination ports.
`source_ports` selects source ports.
A zero `rate_limit` disables the packet rate limit.

ACL groups use shared group names and secrets.

```toml
[acl.acl_v1.group]
members = ["administrators"]

[[acl.acl_v1.group.declares]]
group_name = "administrators"
group_secret = "<group-secret>"
```

### Runtime flags

Put retained core settings under `[flags]`.
Use `[relay]`, `[camouflage]`, and `[limits]` for grouped settings.
The table uses TOML paths for grouped settings.

| Field | Default | Purpose | CLI option |
| --- | --- | --- | --- |
| `default_protocol` | `quic` | Select the preferred direct transport: `quic` (HTTP/3), `tcp` (HTTP/2), or `wss`. | `--default-protocol` |
| `dev_name` | empty | Set the TUN or TAP interface name. | `--dev-name` or `--tun` |
| `enable_encryption` | `true` | Encrypt peer payloads. | `--disable-encryption false` |
| `enable_ipv6` | `true` | Enable overlay IPv6. | `--disable-ipv6 false` |
| `mtu` | `1380` | Set the overlay MTU. Encryption gives the kernel interface a 1360-byte effective MTU. | `--mtu` |
| `relay.policy` | `hop` | Select hop, latency, or goodput routing. | `--relay-policy` |
| `relay.probe_interval_seconds` | `30` | Set the normal interval between direct-link probe cycles. | `--relay-probe-interval-seconds` |
| `relay.probe_budget_bps` | `0` | Limit average probe traffic across the complete node. Zero disables probes. | `--relay-probe-budget-bps` |
| `enable_exit_node` | `false` | Permit other peers to use this node as an exit node. | `--enable-exit-node` |
| `relay.transit_networks` | `[]` | Permit named foreign networks for transit. | `--relay-transit-networks` |
| `disable_p2p` | `false` | Disable ordinary automatic direct links. | `--disable-p2p` |
| `relay_all_peer_rpc` | `false` | Relay peer RPC outside configured transit networks. | `--relay-all-peer-rpc` |
| `disable_udp_hole_punching` | `false` | Disable UDP NAT hole punching. | `--disable-udp-hole-punching` |
| `multi_thread` | `true` | Use the multithread Tokio runtime. | `--multi-thread` |
| `bind_device` | `true` | Bind underlay sockets to selected physical devices. | `--bind-device` |
| `accept_dns` | `false` | Install and accept Magic DNS settings. | `--accept-dns` |
| `private_mode` | `false` | Require verified foreign-network membership. | `--private-mode` |
| `relay.transit_bps_limit` | unlimited | Limit all transit in bit/s. | `--relay-transit-bps-limit` |
| `multi_thread_count` | `2` | Set the multithread runtime worker count. | `--multi-thread-count` |
| `encryption_algorithm` | `chacha20-poly1305` | Select `chacha20-poly1305`, `aes-gcm`, or `aes-256-gcm`. | `--encryption-algorithm` |
| `disable_sym_hole_punching` | `false` | Disable symmetric-NAT UDP punching. | `--disable-sym-hole-punching` |
| `tld_dns_zone` | `et.net.` | Set the Magic DNS suffix. | `--tld-dns-zone` |
| `relay.use_relays` | `true` | Permit local data to use indirect paths. | `--relay-use-relays` |
| `disable_tcp_hole_punching` | `false` | Disable TCP NAT hole punching. | `--disable-tcp-hole-punching` |
| `lazy_p2p` | `false` | Create direct links only when traffic needs them. | `--lazy-p2p` |
| `need_p2p` | `false` | Ask lazy peers to connect before traffic arrives. | `--need-p2p` |
| `limits.receive_bps` | unlimited | Limit all instance input in bit/s. | `--receive-bps` |
| `relay.transit` | `allow` | Select allow, avoid, or deny for transit. | `--relay-transit` |
| `enable_udp_broadcast_relay` | `false` | Relay physical-interface UDP broadcasts on Windows. | `--enable-udp-broadcast-relay` |
| `socket_mark` | unset | Apply Linux `SO_MARK` to underlay sockets. | `--socket-mark` on Linux |
| `underlay_deny_interfaces` | empty | Deny exact local interface names for underlay traffic. | `--underlay-deny-interfaces` |
| `underlay_deny_cidrs` | empty | Deny local sources and remote destinations in listed CIDRs. | `--underlay-deny-cidrs` |
| `quic_initial_receive_window` | `2097152` | Set the QUIC initial per-stream receive window. | `--quic-initial-receive-window` |
| `quic_receive_window` | `4194304` | Set the QUIC connection receive window. | `--quic-receive-window` |
| `camouflage.admission_secret` | empty | Set a shared HTTP/3 CONNECT-IP admission secret. | `--admission-secret` |
| `camouflage.website_root` | empty | Serve this static website for ordinary HTTP/3 requests. | `--website-root` |
| `camouflage.decoy_upstream` | empty | Forward unmarked QUIC datagrams and splice unmarked TCP to this host. | `--decoy-tcp-upstream / --decoy-udp-upstream` |
| `camouflage.sni_routing` | `false` | Admit QUIC clients whose TLS SNI matches `camouflage.server_name`. Other UDP still goes to `camouflage.decoy_upstream`. | `--sni-routing` |
| `l2_fdb_capacity` | `16384` | Limit learned source MAC entries. | `--l2-fdb-capacity` |
| `l2_fdb_age_seconds` | `300` | Expire idle MAC entries after this interval. | `--l2-fdb-age-seconds` |
| `l2_flood_bytes_per_second` | `67108864` | Limit replicated Ethernet bytes per second. Zero removes the limit. | `--l2-flood-bytes-per-second` |

QUIC NAT traversal exchanges candidates through authenticated peer RPC.
It retains the selected UDP socket for the QUIC connection.
When one peer has destination-dependent mappings, traversal can use a bounded socket pool and public-port search.
The search respects the underlay policy and `disable_sym_hole_punching`.
`disable_udp_hole_punching` disables the QUIC traversal coordinator.
This UDP procedure does not establish H2 or WSS connections.
H2 and WSS use authenticated TCP rendezvous and simultaneous open.
TCP traversal retains one source port for listening, STUN, and peer connections.
The initiator nominates one TLS connection before the peers verify their identities.
`default_protocol = "wss"` selects WSS traversal; other values select H2 for TCP traversal.
`disable_tcp_hole_punching` disables both TCP traversal protocols.
Destination-dependent TCP mappings can still prevent direct connections.
Candidate discovery uses current interface addresses and configured underlay restrictions.
Production traversal does not require a fixed physical interface name.
When a mapped address is also a local address, traversal can reserve its mapped port exclusively.
TCP retains the original listener. QUIC also retries the original STUN socket.
Peer authentication must succeed before the direct connection becomes active.
See the [eth0 traversal measurements](docs/performance/eth0-direct-20260922.md) for verified behavior and limits.
See the [osku–UTMOWRT measurements](docs/performance/osku-utmowrt-20260922.md) for all three traversal protocols.

LowTier selects TAP on Linux and FreeBSD.
LowTier selects TUN on other systems.

`l2_fdb_capacity` accepts values from 1 through 1,048,576.
`l2_fdb_age_seconds` accepts values from 1 through 86,400.
`quic_receive_window` must not be smaller than `quic_initial_receive_window`.

Tests, demos, and examples use `challenges.cloudflare.com` because that
host is reachable. Peers connect to your public IP on port 443 with that
SNI. Nginx stream-passthroughs TCP and UDP to LowTier. Marked LowTier
clients become a VPN hop. Unmarked probes are spliced to the real
Cloudflare host and complete TLS with Cloudflare's certificate.

Configure the same `camouflage.admission_secret` on credential peers. Secret-based
networks use `network_secret` when `camouflage.admission_secret` is empty. LowTier
rotates the encrypted admission token every five minutes.

```toml
listeners = ["tcp://127.0.0.1:8443", "quic://127.0.0.1:8443"]
mapped_listeners = ["tcp://0.0.0.0:443", "quic://0.0.0.0:443"]

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

## Complete `lowertier-core` startup reference

Network values have matching `ET_` environment variables when `--help` shows an environment name.
For example, `--network-name` maps to `ET_NETWORK_NAME`.

### Instance and configuration input

| Option | Purpose |
| --- | --- |
| `--config-server`, `-w` | Read configuration from a UDP, TCP, WS, or WSS configuration server. |
| `--machine-id` | Set the stable machine identifier used for configuration recovery. |
| `--config-file`, `-c` | Load one or more TOML files. Use `-` to read one file from standard input. |
| `--config-dir` | Load every `.toml` file in one directory. |
| `--network-name` | Set `network_identity.network_name`. |
| `--network-secret` | Set `network_identity.network_secret`. |
| `--hostname` | Set the peer hostname. |
| `--instance-name`, `-m` | Set the local instance name. |
| `--ipv4`, `-i` | Set the overlay IPv4 interface address. |
| `--ipv6` | Set the overlay IPv6 interface address. |
| `--dhcp`, `-d` | Request an automatic overlay IPv4 address. |
| `--ipv6-public-addr-provider` | Share a public IPv6 prefix on Linux. |
| `--ipv6-public-addr-auto` | Request a public IPv6 address from a provider peer. |
| `--ipv6-public-addr-prefix` | Set the public IPv6 prefix to share. |

### Peers, listeners, and routes

| Option | Purpose |
| --- | --- |
| `--peers`, `-p` | Add one or more initial peer URLs. |
| `--external-node`, `-e` | Use a public shared node for peer discovery. |
| `--listeners`, `-l` | Add inbound listener URLs, ports, addresses, or `scheme:port` pairs. |
| `--mapped-listeners` | Advertise public addresses that map to local listeners. |
| `--no-listener` | Disable all inbound listeners. |
| `--proxy-networks`, `-n` | Export or map local IPv4 subnets. |
| `--manual-routes` | Replace propagated subnet routes. |
| `--exit-nodes` | Select ordered exit-node overlay addresses. |
| `--enable-exit-node` | Permit this node to forward exit traffic. |
| `--port-forward` | Add a TCP or UDP local-to-overlay forwarding rule. |

### Interface and userspace operation

| Option | Purpose |
| --- | --- |
| `--dev-name` | Set the TUN or TAP interface name. |
| `--tun` | Set the interface name or select `userspace-networking`. |
| `--mtu` | Set the overlay MTU. |
| `--socks5-server` | Start a SOCKS5 listener at `host:port`. |
| `--outbound-http-proxy-listen` | Start an HTTP proxy listener at `host:port`. |

`--tun=userspace-networking` sets the safe userspace flag combination.
The mode disables TUN, device binding, system proxy forwarding, Magic DNS acceptance, and UDP broadcast relay.
The mode rejects `--socket-mark` and `--dev-name`.

### Security, relay, transport, and limits

All matching runtime options appear in the configuration table above.
The remaining security options configure keys, credentials, and port access.

| Option | Purpose |
| --- | --- |
| `--local-private-key` | Set the base64 X25519 private key. |
| `--local-public-key` | Set the matching base64 X25519 public key. |
| `--credential` | Join with a base64 temporary credential instead of a network secret. |
| `--credential-file` | Persist issued credentials on an administrator node. |
| `--tcp-whitelist` | Allow listed inbound TCP ports or ranges. |
| `--udp-whitelist` | Allow listed inbound UDP ports or ranges. |
| `--stun-servers` | Replace the IPv4 STUN server list. |
| `--stun-servers-v6` | Replace the IPv6 STUN server list. |

### Logging, RPC, and process control

| Option | Purpose |
| --- | --- |
| `--console-log-level` | Set the console log filter. |
| `--file-log-level` | Set the file log filter. |
| `--file-log-dir` | Set the log directory. |
| `--file-log-size` | Set the maximum file size in MiB. The default is 100. |
| `--file-log-count` | Set the retained file count. The default is 10. |
| `--rpc-portal`, `-r` | Set the management RPC listener. The default tries `127.0.0.1:15888`. |
| `--rpc-portal-whitelist` | Restrict RPC clients by address or CIDR. |
| `--daemon` | Run in daemon mode. |
| `--check-config` | Validate configuration and exit. |
| `--disable-env-parsing` | Disable TOML environment-variable expansion. |
| `--gen-autocomplete` | Generate completion data for bash, elvish, fish, PowerShell, zsh, or Nushell. |
| `--version`, `-V` | Print the build version. |
| `--help`, `-h` | Print the generated option reference. |

## Complete `lowertier-cli` reference

The CLI connects to `127.0.0.1:15888` by default.
Every portal request requires the process control token.
Use `--control-token`, `LOWTIER_CONTROL_TOKEN`, or `--control-token-file`.
The default token file is `~/.config/lowertier/control.token` on Unix and `%LOCALAPPDATA%/LowTier/control.token` on Windows.
Set `LOWTIER_CONTROL_TOKEN_FILE` when the core uses another token file.
The CLI selects a sole instance automatically.
Use `--instance ID` when the process has multiple instances.
Mutations always select one instance.

| Root option | Purpose |
| --- | --- |
| `--rpc-portal`, `-p` | Select the core RPC address. |
| `--verbose`, `-v` | Increase diagnostics on stderr. |
| `--output`, `-o` | Select `table` or `json`. |
| `--instance`, `-i` | Select an instance by ID. |
| `--control-token` | Supply the process control token. |
| `--control-token-file` | Read the process control token from a file. |
| `--admin-token` | Supply the additional network administrator token for credential commands. |

JSON output uses one envelope with `schema_version`, `request_id`, `instance_id`, `revision`, `data`, and `error`.
Exactly one of `data` or `error` contains a value.
Protobuf field names use snake_case. Uint64 values use decimal strings. Bytes use base64.
Watch and follow commands emit one envelope per line.
JSON output preserves complete values. Tables preserve complete paths and show relayed peers as `via ID`.

Exit codes are 0 for success, 1 for internal errors, 2 for arguments or validation, and 3 for authorization.
Code 4 means missing or ambiguous resources. Code 5 means revision conflict or restart required.
Code 6 means connection or deadline failure. Code 7 means partial failure.

### Inspection commands

| Command | Purpose |
| --- | --- |
| `peer list` | List connected peers. |
| `peer show ID_OR_PUBLIC_KEY` | Show one peer. |
| `route list` | List propagated routes. |
| `route show DESTINATION --path` | Show a route and its complete captured path. |
| `node show` | Show local node information, including public IPv6 state. |
| `relay show` | Show active policy, permissions, limits, counters, and paths. |
| `l2 fdb`, `l2 stats` | Show forwarding entries or counters. |
| `discovery status` | Show trackers, candidate counts, and mapping observations. |
| `listener list` | Show listener authentication and transport state. |
| `camouflage show` | Show camouflage settings and certificate verification. |
| `config get` | Show desired configuration, active configuration, and pending restart fields. |
| `acl get` | Show ACL configuration and port whitelists. |
| `acl stats` | Show ACL rule counters. |
| `stats show` | Show general counters. |
| `stats show --prometheus` | Print protected Prometheus counters. JSON output wraps the text. |
| `stats watch [--prometheus]` | Watch paced statistics changes until interrupted. |
| `log read`, `log follow` | Read or follow the bounded process log. |
| `log level [LEVEL]` | Show or set off, error, warn, info, debug, or trace. |
| `instance list` | List running and stopped instances. |

Paged commands accept `--limit 1..256` and `--page-token TOKEN`.
Use the returned `next_page_token` to read another page.
Add `--path` to `route list` when complete paths are required.

### Goodput routing

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

### Runtime change commands

| Command | Purpose |
| --- | --- |
| `peer add URL [--public-key KEY]` | Add a configured peer. |
| `peer remove URL` | Remove a configured peer. |
| `listener add URL` | Add a configured listener. |
| `listener remove URL_OR_ID` | Remove a configured listener. |
| `relay set FIELD=JSON...` | Change relay fields. |
| `camouflage set FIELD=JSON...` | Change camouflage fields. |
| `config set PATH=JSON...` | Change configuration fields. |
| `config validate PATH=JSON...` | Validate a change and report apply classes without publication. |
| `port-forward add PROTOCOL BIND_ADDR DST_ADDR` | Add a TCP or UDP forwarding rule. |
| `port-forward remove PROTOCOL BIND_ADDR` | Remove a forwarding rule. |
| `port-forward list` | List forwarding rules. |
| `acl set --file FILE` | Replace ACL and whitelists from JSON. |
| `instance create --file FILE` | Create a stopped instance from NodeConfig JSON. |
| `instance start`, `instance stop`, `instance delete` | Change the selected instance lifecycle. Deletion requires a stopped instance. |

Configuration mutations read a revision before changing state.
Use `--expected-revision N` to require a specific revision. Conflicts do not trigger automatic retries.
Use `--persist` to write desired settings to an existing configuration file.
Use `--stage` to store restart fields while their active values stay unchanged.
The response lists `live_fields`, `new_connection_fields`, and `restart_fields`.
Staged instance fields activate after stop/start. Process fields require process restart.
See [control configuration](docs/control-config.md) for apply classifications and persistence limits.

Assignments accept JSON values and unquoted strings.
Arrays replace completely. Use `--clear PATH` to remove optional fields.
Alternatively, use `--values FILE --field PATH` with NodeConfig JSON.
Relay and camouflage commands accept relative field paths; values files always contain NodeConfig objects.

```bash
lowertier-cli relay set policy=latency use_relays=true
lowertier-cli config validate hostname=office
lowertier-cli camouflage set wss_path=/vpn
lowertier-cli listener add 'tcp://0.0.0.0:11010' --stage
lowertier-cli --instance INSTANCE_ID instance stop
```

### Credential commands

| Command | Purpose |
| --- | --- |
| `credential issue --ttl SECONDS` | Create a temporary credential. |
| `credential revoke CREDENTIAL_ID` | Revoke a credential. |
| `credential list` | List active credentials. |

Credential commands require `--admin-token` or `LOWTIER_ADMIN_TOKEN`, in addition to the control token.
`credential issue` also accepts these options.

| Option | Purpose |
| --- | --- |
| `--credential-id` | Reuse a caller-selected credential ID. |
| `--groups` | Assign comma-separated ACL groups. |
| `--allow-relay` | Permit the credential node to relay traffic. |
| `--allowed-proxy-cidrs` | Limit exported subnets to comma-separated CIDRs. |
| `--reusable true|false` | Permit or reject concurrent reuse. The default is `true`. |

### Service commands

| Command | Purpose |
| --- | --- |
| `service install [CORE_ARGS...]` | Register `lowertier-core` with the operating system service manager. |
| `service uninstall` | Remove the registered service. |
| `service status` | Show service status. |
| `service start` | Start the service. |
| `service stop` | Stop the service. |

Select a service name with `lowertier-cli service --name NAME`.
The install command accepts `--description`, `--display-name`, `--core-path`, and `--service-work-dir`.
The install command also accepts `--disable-autostart` and `--disable-restart-on-failure`.

Service and completion commands run locally without a control token.
Generate shell completions with `lowertier-cli completion SHELL`.

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
stun_servers = ["192.0.2.20:3478"]
stun_servers_v6 = ["[2001:db8::20]:3478"]

[flags]
underlay_deny_interfaces = ["tailscale0", "utun5"]
underlay_deny_cidrs = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
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
[flags]
quic_initial_receive_window = 8388608
quic_receive_window = 33554432
```

Normal Ethernet frames use plain QUIC DATAGRAM records.
LowTier does not retransmit these records.
Inner TCP handles lost TCP-bearing Ethernet frames.
ARP, DHCP, and IPv6 neighbor-discovery frames use the reliable QUIC stream.

## Security and traffic visibility

LowTier enables ChaCha20-Poly1305 authenticated encryption by default.
The default encryption protects the payload and authentication tag.
Relay routing fields remain outside the default payload AEAD.

Secure mode protects the complete peer header and payload inside the link envelope.
Secure mode also adds peer authentication, key epochs, and replay rejection.

Do not use `--disable-encryption` on an untrusted network.
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

### Validate configuration

```bash
lowertier-core --config-file /etc/lowtier/office.toml --check-config
```

The error report includes the file, line, and invalid field.

### Confirm the selected interface

```bash
lowertier-cli config get
lowertier-cli node show
```

Check the reported interface name and link type.

### Check peer and route state

```bash
lowertier-cli peer list
lowertier-cli listener list
lowertier-cli route list --path
lowertier-cli discovery status
```

Check firewall access to every configured listener.
Try an explicit QUIC, TCP, or WSS peer URL when automatic discovery cannot connect.

### Check L2 discovery

Confirm that both peers advertise Ethernet input.
Confirm that each peer uses the correct `tap` or `tun` adapter.
Check the configured flood limit when broadcast discovery fails.

VLAN, QinQ, LLDP, and unknown EtherTypes require native Ethernet on both local edges.

### Check RPC access

```bash
lowertier-cli --rpc-portal 127.0.0.1:15888 node show
```

Confirm the core RPC address, control token file, and whitelist.
Do not expose the RPC portal to an untrusted network.

### Get complete generated help

```bash
lowertier-core --help
lowertier-cli --help
lowertier-cli COMMAND --help
```

Generated help reflects the features compiled into the current binary.

## License

LowTier remains under the repository license.
See [LICENSE](LICENSE) for the complete terms.
