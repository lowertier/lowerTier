# Configuration

A node reads one TOML file. Every option has one dotted path, such as `relay.policy`, and the same path works everywhere:

| Where | How |
| --- | --- |
| Configuration file | `[relay]` then `policy = "latency"` |
| Starting a node | `lowertier run -c node.toml --set relay.policy=latency` |
| Running node | `lowertier set relay.policy=latency` |
| Documentation | `lowertier config explain relay.policy` |

The [option reference](options.md) lists every path with its type, default, and when a change takes effect.

## A complete example

A Linux node that accepts peers on all three transports and bridges its LAN:

```toml
[node]
hostname = "node-a"

[network]
name = "office"
secret_file = "/etc/lowertier/office.secret"

[identity]
private_key_file = "/etc/lowertier/office.key"

[address]
ipv4 = "10.44.0.1/24"

[transport]
listen = ["quic://0.0.0.0:11012", "h2://0.0.0.0:11010", "wss://0.0.0.0:11012"]

[[peer]]
uri = "quic://192.0.2.11:11012"

[l2]
bridge = true

[relay]
policy = "latency"
```

## Check, run, and change

```bash
lowertier check -c /etc/lowertier/office.toml          # report every problem at once
sudo lowertier run -c /etc/lowertier/office.toml
sudo lowertier run --config-dir /etc/lowertier/nodes   # every .toml file in a directory
```

`--set PATH=VALUE` overrides the file for one run and leaves the file unchanged.
Without a file, `--set` values alone describe a node:

```bash
lowertier run --set network.name=office --set network.secret_file=office.secret \
  --set tun.mode=userspace --set proxy.socks5=127.0.0.1:1055 --set peer=quic://192.0.2.10:11012
```

On a running node, `lowertier set`, `unset`, and `edit` save the change to the file and apply it.
Each change reports whether it applied now, applies to new connections, or waits for a restart.
Changes that need a restart require `--stage`; the node then restarts the affected instance.

```bash
lowertier set relay.policy=latency relay.transit_bps_limit=50Mbit
lowertier set tun.mtu=1280 --stage
lowertier get relay
```

The node also watches its configuration file and the key, secret, token, and TLS files it names.
It checks them every second and applies valid edits.
An invalid edit keeps the running configuration, and `lowertier get` shows the error.
A node started with `--set` overrides does not reload its file; restart it instead.
Run services with explicit files so changes survive a service restart.

## Values

- Durations: `30`, `30s`, `5m`, `1h`.
- Rates in bit/s: `8000000`, `8Mbit`, `1Gbit`.
- Sizes: `1048576`, `256KiB`, `1GiB`.
- A plain number uses the base unit listed in the reference.

Files may use `${NAME}`, `$NAME`, and `${NAME:-default}`.
A file that expands a variable is read-only through the management commands.
`LOWTIER_CONFIG` holds comma-separated file paths for `run` and `check` when `-c` is absent.

Options from older releases are rejected with the name of their replacement, and `lowertier check` lists every one in a file.
There is no automatic migration. The [renamed options](design/renamed-options.md) table maps old names to new ones.

## Peers and listeners

Peer and listener URLs name the transport:

| Scheme | Carries | Default port |
| --- | --- | ---: |
| `quic` | HTTP/3 over QUIC over UDP | 11012 |
| `h2` | HTTP/2 over TLS over TCP | 11010 |
| `wss` | WebSocket over TLS over TCP | 11012 |

QUIC is preferred. A node tries every transport both sides allow and keeps the others as backups.
After connecting, it picks by measured delivery rate and round-trip time; `transport.prefer` only breaks ties.
`transport.protocols` limits a node to some transports, for example `["quic"]`.

Plain `ws://` and raw `udp://` are rejected.
Peers may also use the discovery schemes `http`, `https`, `txt`, and `srv`; Unix builds accept `unix` sockets.

```toml
[[peer]]
uri = "quic://192.0.2.10:11012"
public_key = "<base64 X25519 public key>"   # optional pin
```

An empty `transport.listen` makes an outbound-only node.
Port `0` lets the system pick, which suits a node behind NAT: `quic://0.0.0.0:0`.
A node that others bootstrap from needs a stable, reachable port.
`transport.advertise` announces a public URL when a port mapping sits in front of the node.

QUIC does not need port 443. Bind `quic://0.0.0.0:443` only on a network that blocks other UDP;
it needs root or `CAP_NET_BIND_SERVICE` and collides with a local HTTPS server.

## Identity

Each node has an X25519 identity key. Without `identity.private_key` or `identity.private_key_file`, the node generates one at startup, so its identity changes on restart.
`lowertier init` writes a key file for you.

Pin a peer's `public_key` when a shared or relay node must keep a verified identity.

Instead of a shared `network.secret`, a node can join with `network.credential`, a signed bundle issued by `lowertier creds issue`.

## Subnets, forwards, and access

```toml
[[export]]                          # share a local subnet with the network
cidr = "10.20.0.0/16"
mapped_cidr = "172.20.0.0/16"       # optional: peers see it under this range
allow = ["tcp", "udp", "icmp"]      # optional

[[forward]]                         # local port to a network address
proto = "tcp"
bind = "127.0.0.1:8080"
dest = "10.44.0.2:80"

[acl]
tcp_ports = ["22", "8000-8100"]     # local ports peers may reach; empty allows all
```

[Routing](routing.md) covers exit nodes and how subnet routes are chosen.

## Access control

ACL chains filter inbound, outbound, or forwarded IP traffic. Ethernet frames that are not IP skip them.
This chain lets administrators reach an exported subnet and drops other forwarded traffic:

```toml
[[acl.acl_v1.chains]]
name = "protect-exported-subnet"
description = "Permit administrators and drop other forwarded traffic."
chain_type = 3          # forward
enabled = true
default_action = 2      # drop

[[acl.acl_v1.chains.rules]]
name = "allow-administrators"
description = "Permit the administrator overlay range."
priority = 1000
enabled = true
protocol = 5            # any
ports = []
source_ports = []
source_ips = ["10.44.0.0/24"]
destination_ips = ["10.20.0.0/16"]
source_groups = []
destination_groups = []
action = 1              # allow
rate_limit = 0
burst_limit = 0
stateful = true
```

| Field | Values |
| --- | --- |
| `chain_type` | `1` inbound, `2` outbound, `3` forward |
| `protocol` | `0` unspecified, `1` TCP, `2` UDP, `3` ICMP, `4` ICMPv6, `5` any |
| `action`, `default_action` | `0` no operation, `1` allow, `2` drop |

Higher `priority` runs first. `ports` matches destination ports and `source_ports` source ports. A `rate_limit` of 0 means no packet rate limit.

Groups share a name and a secret:

```toml
[acl.acl_v1.group]
members = ["administrators"]

[[acl.acl_v1.group.declares]]
group_name = "administrators"
group_secret = "<group secret>"
```

The web interface edits the same rules.

## Underlay rules

Keep lowertier off another VPN or a particular interface:

```toml
[underlay]
deny_interfaces = ["tailscale0", "utun5"]
deny_cidrs = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
```

Deny CIDRs match local source addresses and remote destinations. Interface names must match exactly, and macOS `utun` numbers can change after a restart.

Strict rules disable hostname lookups, so peers and STUN servers must be IP literals.
The built-in STUN lists use hostnames, so set `nat.stun` and `nat.stun_tcp` to IP addresses.
Restart the instance after changing underlay rules.
