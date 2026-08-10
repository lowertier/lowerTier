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
- UDP, QUIC, and TCP underlay transports in published builds.
- Peer discovery, NAT traversal, subnet routes, exit nodes, ACLs, and port forwarding.
- ChaCha20-Poly1305 authenticated encryption by default.
- An optional secure mode with Noise authentication and replay protection.

## Program model

LowTier uses two command-line programs.

| Program | Purpose |
| --- | --- |
| `lowertier-core` | Runs the VPN instance, virtual interface, peer links, routing, and proxies. |
| `lowertier-cli` | Reads status and changes supported runtime settings through the RPC portal. |

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
Encrypted UDP, QUIC, or TCP link
        |
Remote LowTier peer
```

## Select a network mode

Select the mode that matches the operating system and application.

| Mode | Configuration | Local interface | Ethernet support | Privilege |
| --- | --- | --- | --- | --- |
| Native Ethernet | `port_mode = "ethernet"` | TAP | Complete L2 | Required |
| Compatible Ethernet | `port_mode = "compatible-ethernet"` | TUN | IPv4 and IPv6 over the Ethernet overlay | Required |
| Routed | `port_mode = "routed"` | TUN | No | Required |
| Userspace networking | `--tun=userspace-networking` | None | No | Not required |

Native Ethernet supports ARP, VLAN, QinQ, LLDP, broadcast, multicast, and unknown EtherTypes.
Native Ethernet requires Linux.

Compatible Ethernet supports mixed TAP and TUN peers.
The local TUN interface receives only IPv4 and IPv6 packets.
Use this mode on macOS and other systems without TAP support.

Routed mode has the lowest interface overhead.
LowTier selects native Ethernet by default on Linux.
LowTier selects compatible Ethernet by default on other systems.
Set `routed` only when the node must use the L3 packet path.

Userspace networking follows the Tailscale application-proxy model.
It does not provide ARP, raw Ethernet, transparent ping, or host routes.

## Build the command-line programs

Install a stable Rust toolchain and the platform build tools.
Then build only the command-line package.

```bash
git clone https://github.com/lowertier/lowerTier.git
cd lowertier
cargo build --release --locked -p lowertier --bins \
  --no-default-features --features lean
```

The `lean` feature keeps TAP/TUN, QUIC, and unprivileged proxy support.
It removes WebSocket, WireGuard, KCP, FakeTCP, Magic DNS, Zstandard, and optional allocators.
The release profile uses fat LTO, optimization level 3, one code generation unit, symbol stripping, and aborting panics.
Development and test builds retain panic unwinding for diagnostics.

Use `--features full` only when the deployment requires every optional transport and service.

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
  --ipv4 10.44.0.1/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --port-mode ethernet \
  --secure-mode true \
  --listeners udp://0.0.0.0:11010
```

Start node B.

```bash
sudo lowertier-core \
  --hostname node-b \
  --ipv4 10.44.0.2/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --port-mode ethernet \
  --secure-mode true \
  --peers udp://192.0.2.10:11010
```

Replace `192.0.2.10` with the reachable address of node A.
Permit UDP port `11010` through the host and network firewalls.

Check the network from either node.

```bash
lowertier-cli node info
lowertier-cli peer list
lowertier-cli route list
ping 10.44.0.2
```

Command-line secrets can appear in process inspection tools.
Use a protected configuration file for a production deployment.

## Start a mixed Linux and macOS network

Use native Ethernet on Linux.
Use compatible Ethernet on macOS.

Linux:

```bash
sudo lowertier-core \
  --ipv4 10.44.0.1/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --port-mode ethernet \
  --secure-mode true
```

macOS:

```bash
sudo lowertier-core \
  --ipv4 10.44.0.2/24 \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --port-mode compatible-ethernet \
  --secure-mode true \
  --peers udp://192.0.2.10:11010
```

The macOS edge carries IP through the Ethernet overlay.
The macOS `utun` interface does not expose arbitrary Ethernet frames.

## Run without administrator privileges

Userspace networking creates no TUN or TAP interface.
Applications connect through a local SOCKS5 or HTTP proxy.

```bash
lowertier-core \
  --tun=userspace-networking \
  --network-name office-l2 \
  --network-secret '<same-secret>' \
  --peers udp://192.0.2.10:11010 \
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
  "udp://0.0.0.0:11010",
  "quic://0.0.0.0:11012",
  "tcp://0.0.0.0:11010",
]

[network_identity]
network_name = "office-l2"
network_secret = "${LOWTIER_NETWORK_SECRET}"

[[peer]]
uri = "udp://192.0.2.11:11010"

[secure_mode]
enabled = true

[flags]
port_mode = "ethernet"
default_protocol = "udp"
enable_encryption = true
encryption_algorithm = "chacha20-poly1305"
mtu = 1380
bind_device = true
latency_first = true
l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300
l2_flood_bps = 67108864
quic_congestion = "bbr"
quic_datagram_fec_parity = 2
quic_critical_l2_duplication = true
quic_datagram_alternate_path_parity = true
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
| `routes` | IPv4 CIDR array | automatic | Replace propagated subnet and WireGuard routes with manual routes. |
| `socks5_proxy` | URL | unset | Listen for SOCKS5 clients. Example: `socks5://127.0.0.1:1055`. |
| `outbound_http_proxy` | URL | unset | Listen for HTTP proxy clients. Example: `http://127.0.0.1:1055`. |
| `tcp_whitelist` | port string array | empty | Allow only listed inbound TCP ports. Supports ports and ranges. |
| `udp_whitelist` | port string array | empty | Allow only listed inbound UDP ports. Supports ports and ranges. |
| `stun_servers` | string array | built-in list | Replace the IPv4 STUN server list. An empty array disables the list. |
| `stun_servers_v6` | string array | built-in list | Replace the IPv6 STUN server list. An empty array disables the list. |
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
uri = "udp://192.0.2.10:11010"
peer_public_key = "<base64-x25519-public-key>"
```

| Field | Required | Purpose |
| --- | --- | --- |
| `uri` | Yes | Selects the peer address and transport or discovery method. |
| `peer_public_key` | No | Pins the peer X25519 public key in secure mode. |

Published binaries support `udp`, `quic`, `tcp`, and `ring` peer schemes.
Full source builds also support `ws`, `wss`, `wg`, and `faketcp`.
Connector-only discovery schemes are `http`, `https`, `txt`, and `srv`.
Unix builds also support `unix` sockets.

### Listeners

Use explicit URLs when predictable firewall rules are required.

```toml
listeners = [
  "udp://0.0.0.0:11010",
  "quic://0.0.0.0:11012",
  "tcp://0.0.0.0:11010",
]
```

Published binaries support UDP, QUIC, and TCP listeners.
Rows marked as full require a full source build.

| Scheme | Network protocol | Default port from base `11010` |
| --- | --- | ---: |
| `udp` | UDP | 11010 |
| `quic` | UDP | 11012 |
| `wg` (full) | UDP | 11011 |
| `tcp` | TCP | 11010 |
| `ws` (full) | TCP | 11011 |
| `wss` (full) | TCP with TLS | 11012 |
| `faketcp` (full) | Raw or emulated TCP path | 11013 |

`--listeners 11010` creates every compiled IP listener with its standard offset.
`--no-listener` creates an outbound-only node.

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

### WireGuard portal in a full source build

```toml
[vpn_portal_config]
wireguard_listen = "0.0.0.0:11013"
client_cidr = "10.14.14.0/24"
```

`wireguard_listen` selects the local WireGuard listener.
`client_cidr` reserves addresses for WireGuard clients.

The CLI form is `--vpn-portal wg://0.0.0.0:11013/10.14.14.0/24`.

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
It is not WireGuard wire format.
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

Put runtime flags under `[flags]`.
The table includes every supported flag.

| Field | Default | Purpose | CLI option |
| --- | --- | --- | --- |
| `default_protocol` | `udp` | Select the preferred direct transport. | `--default-protocol` |
| `dev_name` | empty | Set the TUN or TAP interface name. | `--dev-name` or `--tun` |
| `enable_encryption` | `true` | Encrypt peer payloads. | `--disable-encryption false` |
| `enable_ipv6` | `true` | Enable overlay IPv6. | `--disable-ipv6 false` |
| `mtu` | `1380` | Set the overlay MTU. Encryption gives the kernel interface a 1360-byte effective MTU. | `--mtu` |
| `latency_first` | `false` | Prefer the measured low-latency route. | `--latency-first` |
| `enable_exit_node` | `false` | Permit other peers to use this node as an exit node. | `--enable-exit-node` |
| `no_tun` | `false` | Disable local virtual-interface creation. | `--no-tun` |
| `use_smoltcp` | `false` | Enable the userspace IP stack for proxy paths. | `--use-smoltcp` |
| `relay_network_whitelist` | `*` | Select network names that this node can relay. | `--relay-network-whitelist` |
| `disable_p2p` | `false` | Disable ordinary automatic direct links. | `--disable-p2p` |
| `relay_all_peer_rpc` | `false` | Relay peer RPC outside the relay whitelist. | `--relay-all-peer-rpc` |
| `disable_udp_hole_punching` | `false` | Disable UDP NAT hole punching. | `--disable-udp-hole-punching` |
| `multi_thread` | `true` | Use the multithread Tokio runtime. | `--multi-thread` |
| `data_compress_algo` | `1` | Select `1` for none or `2` for Zstandard. | `--compression none|zstd` |
| `bind_device` | `true` | Bind underlay sockets to selected physical devices. | `--bind-device` |
| `enable_kcp_proxy` | `false` | Convert eligible TCP streams to KCP. | `--enable-kcp-proxy` |
| `disable_kcp_input` | `false` | Reject inbound KCP stream conversion. | `--disable-kcp-input` |
| `disable_relay_kcp` | `false` | Reject relayed KCP packets from the local network. | `--disable-relay-kcp` |
| `proxy_forward_by_system` | `false` | Use kernel forwarding for exported subnets. | `--proxy-forward-by-system` |
| `accept_dns` | `false` | Install and accept Magic DNS settings. | `--accept-dns` |
| `private_mode` | `false` | Require verified foreign-network membership. | `--private-mode` |
| `enable_quic_proxy` | `false` | Convert eligible TCP streams to QUIC. | `--enable-quic-proxy` |
| `disable_quic_input` | `false` | Reject inbound QUIC stream conversion. | `--disable-quic-input` |
| `foreign_relay_bps_limit` | unlimited | Limit foreign-network relay bytes per second. | `--foreign-relay-bps-limit` |
| `multi_thread_count` | `2` | Set the multithread runtime worker count. | `--multi-thread-count` |
| `enable_relay_foreign_network_kcp` | `false` | Relay KCP packets for foreign networks. | `--enable-relay-foreign-network-kcp` |
| `encryption_algorithm` | `chacha20-poly1305` | Select `chacha20-poly1305`, `aes-gcm`, or `aes-256-gcm`. | `--encryption-algorithm` |
| `disable_sym_hole_punching` | `false` | Disable symmetric-NAT UDP punching. | `--disable-sym-hole-punching` |
| `tld_dns_zone` | `et.net.` | Set the Magic DNS suffix. | `--tld-dns-zone` |
| `p2p_only` | `false` | Send data only through established direct links. | `--p2p-only` |
| `quic_listen_port` | deprecated | Keep only for old configuration compatibility. | Use `--listeners quic://...` |
| `disable_tcp_hole_punching` | `false` | Disable TCP NAT hole punching. | `--disable-tcp-hole-punching` |
| `disable_relay_quic` | `false` | Reject relayed QUIC packets from the local network. | `--disable-relay-quic` |
| `enable_relay_foreign_network_quic` | `false` | Relay QUIC packets for foreign networks. | `--enable-relay-foreign-network-quic` |
| `lazy_p2p` | `false` | Create direct links only when traffic needs them. | `--lazy-p2p` |
| `need_p2p` | `false` | Ask lazy peers to connect before traffic arrives. | `--need-p2p` |
| `instance_recv_bps_limit` | unlimited | Limit total received bytes per second. | `--instance-recv-bps-limit` |
| `disable_upnp` | `false` | Disable automatic UPnP and NAT-PMP mapping. | `--disable-upnp` |
| `disable_relay_data` | `false` | Disable data relay while retaining control functions. | Configuration file only |
| `enable_udp_broadcast_relay` | `false` | Relay physical-interface UDP broadcasts on Windows. | `--enable-udp-broadcast-relay` |
| `socket_mark` | unset | Apply Linux `SO_MARK` to underlay sockets. | `--socket-mark` on Linux |
| `underlay_deny_interfaces` | empty | Deny exact local interface names for underlay traffic. | `--underlay-deny-interfaces` |
| `underlay_deny_cidrs` | empty | Deny local sources and remote destinations in listed CIDRs. | `--underlay-deny-cidrs` |
| `quic_congestion` | `bbr` | Select `adaptive`, `bbr`, or `brutal`. | `--quic-congestion` |
| `quic_brutal_send_bps` | `0` | Set the Brutal target send rate in bits per second. | `--quic-brutal-send-bps` |
| `quic_brutal_loss_compensation` | `true` | Add bounded Brutal attempts for measured loss. | `--quic-brutal-loss-compensation` |
| `quic_initial_receive_window` | `1250000` | Set the QUIC initial per-stream receive window. | `--quic-initial-receive-window` |
| `quic_receive_window` | `2^62-1` | Set the QUIC connection receive window. | `--quic-receive-window` |
| `port_mode` | platform L2 mode | Select `routed`, `ethernet`, `compatible-ethernet`, or `auto`. | `--port-mode` |
| `l2_fdb_capacity` | `16384` | Limit learned source MAC entries. | `--l2-fdb-capacity` |
| `l2_fdb_age_seconds` | `300` | Expire idle MAC entries after this interval. | `--l2-fdb-age-seconds` |
| `l2_flood_bps` | `67108864` | Limit replicated Ethernet bytes per second. Zero removes the limit. | `--l2-flood-bps` |
| `quic_datagram_fec_parity` | `2` | Select `0` off, `2` for 16+2, or `3` for 16+3 ETQ4 FEC. | `--quic-datagram-fec-parity` |
| `quic_critical_l2_duplication` | `true` | Duplicate critical ARP, DHCP, and neighbor-discovery frames. | `--quic-critical-l2-duplication` |
| `quic_datagram_alternate_path_parity` | `true` | Send L2 parity through a second distinct QUIC path. | `--quic-datagram-alternate-path-parity` |

`auto` selects native Ethernet on Linux.
`auto` selects routed mode on other systems.

`l2_fdb_capacity` accepts values from 1 through 1,048,576.
`l2_fdb_age_seconds` accepts values from 1 through 86,400.
`quic_receive_window` must not be smaller than `quic_initial_receive_window`.
Brutal mode requires a positive `quic_brutal_send_bps` value.

## Complete `lowertier-core` startup reference

Network values have matching `ET_` environment variables when `--help` shows an environment name.
For example, `--port-mode` maps to `ET_PORT_MODE`.

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
| `--manual-routes` | Replace propagated subnet and WireGuard routes. |
| `--exit-nodes` | Select ordered exit-node overlay addresses. |
| `--enable-exit-node` | Permit this node to forward exit traffic. |
| `--vpn-portal` | Start a WireGuard portal for external clients. |
| `--port-forward` | Add a TCP or UDP local-to-overlay forwarding rule. |

### Interface and userspace selection

| Option | Purpose |
| --- | --- |
| `--port-mode` | Select routed, native Ethernet, compatible Ethernet, or automatic mode. |
| `--dev-name` | Set the TUN or TAP interface name. |
| `--tun` | Set the interface name or select `userspace-networking`. |
| `--mtu` | Set the overlay MTU. |
| `--no-tun` | Disable the virtual interface. |
| `--use-smoltcp` | Enable the userspace IP stack. |
| `--socks5` | Start the legacy port-only SOCKS5 listener. |
| `--socks5-server` | Start a SOCKS5 listener at `host:port`. |
| `--outbound-http-proxy-listen` | Start an HTTP proxy listener at `host:port`. |

`--tun=userspace-networking` sets the safe userspace flag combination.
The mode disables TUN, device binding, system proxy forwarding, Magic DNS acceptance, and UDP broadcast relay.
The mode rejects `--socket-mark` and `--dev-name`.

### Security, relay, transport, and limits

All matching runtime options appear in the `[flags]` table above.
The remaining security options configure keys, credentials, and port access.

| Option | Purpose |
| --- | --- |
| `--secure-mode` | Enable secure peer sessions. |
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
Use the root options to select another RPC portal or instance.

| Root option | Purpose |
| --- | --- |
| `--rpc-portal`, `-p` | Select the core RPC address. |
| `--verbose`, `-v` | Print additional command details. |
| `--output`, `-o` | Select `table` or `json`. |
| `--no-trunc` | Disable table truncation. |
| `--instance-id`, `-i` | Select an instance by ID. |
| `--instance-name`, `-n` | Select an instance by name. |

### Inspection commands

| Command | Purpose |
| --- | --- |
| `peer list` | List connected peers. |
| `peer ipv6` | Show public IPv6 information. |
| `peer list-foreign [--trusted-keys]` | List discovered foreign networks. |
| `peer list-global-foreign` | List foreign networks from the peer center. |
| `route list` | List propagated routes. |
| `route dump` | Print routes as CIDRs. |
| `peer-center` | Show global peer information. |
| `node info` | Show local node information. |
| `node config` | Show the active node configuration. |
| `stun` | Run a STUN test. |
| `vpn-portal` | Print WireGuard portal information. |
| `proxy` | Show TCP, KCP, and QUIC proxy status. |
| `acl stats` | Show ACL rule counters. |
| `stats show` | Show general counters. |
| `stats prometheus` | Print counters in Prometheus text format. |

### Runtime change commands

| Command | Purpose |
| --- | --- |
| `connector add URL` | Add an initial connector. |
| `connector remove URL` | Remove a connector. |
| `connector list` | List connectors. |
| `mapped-listener add URL` | Add an advertised mapped listener. |
| `mapped-listener remove URL` | Remove a mapped listener. |
| `mapped-listener list` | List mapped listeners. |
| `port-forward add PROTOCOL BIND_ADDR DST_ADDR` | Add a TCP or UDP forwarding rule. |
| `port-forward remove PROTOCOL BIND_ADDR [DST_ADDR]` | Remove a forwarding rule. |
| `port-forward list` | List forwarding rules. |
| `whitelist set-tcp PORTS` | Replace the TCP port whitelist. |
| `whitelist set-udp PORTS` | Replace the UDP port whitelist. |
| `whitelist clear-tcp` | Remove the TCP whitelist. |
| `whitelist clear-udp` | Remove the UDP whitelist. |
| `whitelist show` | Show both port whitelists. |
| `logger get` | Show the active logger configuration. |
| `logger set LEVEL` | Set `disabled`, `error`, `warning`, `info`, `debug`, or `trace`. |

### Credential commands

| Command | Purpose |
| --- | --- |
| `credential generate --ttl SECONDS` | Create a temporary credential. |
| `credential revoke CREDENTIAL_ID` | Revoke a credential. |
| `credential list` | List active credentials. |

`credential generate` also accepts these options.

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

Generate shell completions with `lowertier-cli gen-autocomplete SHELL`.

## L2 forwarding behavior

LowTier learns valid unicast source MAC addresses in a bounded forwarding database.
Known unicast frames go to one routed destination peer.
Unknown unicast, multicast, and broadcast frames go only to peers that advertise Ethernet input.

LowTier removes forwarding entries after their age limit or peer disconnection.
The flood limiter controls replicated bytes for each second.
Keep a finite flood limit on production meshes.

Compatible Ethernet derives a locally administered MAC address from the peer ID.
The mode answers ARP for its overlay IPv4 address.
The mode sends normal unicast through the existing IP route table.

Restart an instance after a `port_mode` change.
Native Ethernet fails when the operating system does not provide TAP.
LowTier selects the interface mode before it creates the virtual interface.
LowTier does not change the interface mode while an instance runs.

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
The policy also disables automatic UPnP and NAT-PMP mapping.

Restart the instance after an underlay policy change.

## QUIC on lossy links

Use BBR when available capacity is unknown.
Use Brutal only when measured capacity is stable and known.

```toml
[flags]
quic_congestion = "brutal"
quic_brutal_send_bps = 50000000
quic_brutal_loss_compensation = true
quic_initial_receive_window = 8388608
quic_receive_window = 33554432
quic_datagram_fec_parity = 2
quic_critical_l2_duplication = true
quic_datagram_alternate_path_parity = true
```

Set the Brutal rate at or below measured available capacity.
An excessive value increases queueing, loss, and wasted traffic.

ETQ4 parity `2` uses a 16+2 profile.
Parity `3` uses the higher-overhead 16+3 profile.
Parity `0` disables FEC.

Alternate-path parity requires two authenticated QUIC paths with distinct IP surfaces.
The primary frame stays on its selected path.
Only bounded parity records use the second path.

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

### Confirm the selected interface mode

```bash
lowertier-cli node config
lowertier-cli node info
```

Check `port_mode` and the reported interface name.
Use `ethernet` only when the operating system provides TAP.

### Check peer and route state

```bash
lowertier-cli peer list
lowertier-cli connector list
lowertier-cli route list
lowertier-cli stun
```

Check firewall access to every configured listener.
Try an explicit UDP or TCP peer URL when automatic discovery cannot connect.

### Check L2 discovery

Confirm that both peers advertise Ethernet input.
Confirm that both peers use `ethernet` or `compatible-ethernet`.
Check the configured flood limit when broadcast discovery fails.

VLAN, QinQ, LLDP, and unknown EtherTypes require native Ethernet on both local edges.

### Check RPC access

```bash
lowertier-cli --rpc-portal 127.0.0.1:15888 node info
```

Confirm the core RPC address and whitelist.
Do not expose the RPC portal to an untrusted network.

### Get complete generated help

```bash
lowertier-core --help
lowertier-cli --help
lowertier-cli COMMAND --help
```

Generated help reflects the features compiled into the current binary.

## Compatibility names

LowTier accepts both descriptive and legacy mode names.

| Descriptive name | Legacy name |
| --- | --- |
| `routed` | `l3` |
| `ethernet` | `tap` |
| `compatible-ethernet` | `l2-tun` |

## License

LowTier remains under the repository license.
See [LICENSE](LICENSE) for the complete terms.
