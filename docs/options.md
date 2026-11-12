# Option reference

Generated from the option registry in `lowertier/src/common/config_schema.rs` by `script/docs/options-reference.py`.
`lowertier config explain PATH` prints the same text for one option.

**Applies** says when a change to a running node takes effect: immediately (live), for new connections, after an instance restart, or after a process restart.
Secrets are redacted in all output.

## `[node]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `node.enabled` | bool | `true` | live | Run this instance. A false value keeps its persistent configuration available for management. |
| `node.hostname` | string |  | live | Name shown to peers. Defaults to the system host name. |
| `node.instance_name` | string | `default` | instance restart | Local instance name. Distinguishes instances in one process. |
| `node.instance_id` | string |  | instance restart | Stable instance UUID. Generated when absent. |
| `node.netns` | string |  | instance restart | Linux network namespace to run in. |
| `node.threads` | integer | `2` | instance restart | Runtime worker threads. 1 runs single-threaded. |

## `[control]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `control.portal` | string | `127.0.0.1:15888` | process restart | Loopback management portal. Default 127.0.0.1:15888, or a free port up to 15899. |
| `control.portal_allow` | list of strings |  | process restart | Extra CIDRs admitted to the portal in addition to loopback. |
| `control.token_file` | path |  | process restart | Control token file. Created with mode 0600 when absent. |
| `control.token_group` | string |  | process restart | Unix group that may read the token file (mode 0640). |
| `control.default` | string |  | live | Pinned alias of the default controller. |
| `control.allow` | list of strings |  | live | Callers with full control. Use pinned keys, aliases, local groups, or * for authenticated network members. |
| `control.keys` | table |  | live | Local aliases bound to complete X25519 public keys. |
| `control.groups` | table |  | live | Local groups of pinned key aliases. |
| `control.secret` | secret |  | live | Optional shared phrase or generated key for remote control authentication. |
| `control.secret_file` | path |  | live | Protected file containing control.secret. |
| `control.grant` | array of tables |  | live | Granular remote control and SSH grants. |

## `[gui]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `gui.enabled` | bool | `true` | instance restart | Serve the browser interface on loopback and this instance's overlay address. |
| `gui.port` | integer | `15880` | instance restart | TCP port of the interface on the overlay address. |
| `gui.loopback_port` | integer | `15880` | instance restart | TCP port on 127.0.0.1. Use separate ports for instances on the same host. |
| `gui.key_file` | path |  | instance restart | File holding the access key. Created with mode 0600 when absent. Default: gui.key beside the control token. |
| `gui.allow` | list of strings |  | instance restart | Source CIDRs that may open the overlay interface. Default: this instance's overlay subnet. API requests require the access key. |
| `gui.open` | list of strings |  | instance restart | Overlay CIDRs served without the access key, and allowed. Trust is by source address only: use it for a network you control. |

## `[identity]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `identity.private_key` | secret |  | instance restart | Base64 X25519 private key. Generated when absent. |
| `identity.private_key_file` | path |  | instance restart | File that holds identity.private_key. |
| `identity.public_key` | string |  | instance restart | Base64 X25519 public key. Must match the private key. |
| `identity.credential_root` | string |  | instance restart | Pinned credential root fingerprint (base64). |

## `[network]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `network.name` | string | `default` | instance restart | Network name. Peers must use the same name. |
| `network.secret` | secret |  | instance restart | Shared network secret. |
| `network.secret_file` | path |  | instance restart | File that holds network.secret. |
| `network.credential` | secret |  | instance restart | Signed credential bundle. Replaces network.secret. |
| `network.credential_file` | path |  | instance restart | Store for credentials issued by this node. |
| `network.cipher` | `chacha20-poly1305` \| `aes-gcm` \| `aes-256-gcm` | `chacha20-poly1305` | instance restart | Data cipher. Peers must agree. |

## `[address]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `address.ipv4` | string |  | instance restart | Virtual IPv4 address with prefix, for example 10.126.126.1/24. |
| `address.ipv6` | string |  | instance restart | Virtual IPv6 address with prefix. |
| `address.dhcp` | bool | `false` | instance restart | Choose a free virtual IPv4 address automatically. |
| `address.public_ipv6.provide` | bool | `false` | instance restart | Lease this node's public IPv6 prefix to peers (Linux). |
| `address.public_ipv6.auto` | bool | `false` | instance restart | Obtain a public IPv6 address from a providing peer. |
| `address.public_ipv6.prefix` | string |  | instance restart | Public IPv6 prefix to lease instead of auto-detection. |

## `[tun]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `tun.mode` | `kernel` \| `userspace` \| `none` | `kernel` | instance restart | kernel: TUN/TAP device. userspace: in-process stack for proxies and forwards. none: no local interface. |
| `tun.name` | string |  | instance restart | Device name. Chosen automatically when empty. |
| `tun.mtu` | integer | `1380` | instance restart | Overlay MTU in bytes. |
| `tun.ipv6` | bool | `true` | instance restart | Carry IPv6 on the virtual interface. |
| `tun.udp_broadcast_relay` | bool | `false` | instance restart | Relay UDP broadcasts from the virtual interface (Windows). |

## `[transport]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `transport.protocols` | list of strings |  | instance restart | Allowed transports: quic, h2, wss. Empty allows all. |
| `transport.prefer` | `quic` \| `h2` \| `wss` | `quic` | instance restart | Initial transport priority. Measured connection quality takes precedence after setup. |
| `transport.listen` | list of strings |  | instance restart | Listener URLs, for example quic://0.0.0.0:11012. |
| `transport.advertise` | list of strings |  | instance restart | Public listener URLs announced to peers, for port mappings. |
| `transport.quic.initial_receive_window` | size | `2MiB` | instance restart | Initial QUIC stream receive window. |
| `transport.quic.receive_window` | size | `4MiB` | instance restart | Maximum QUIC connection receive window. |

## `[[peer]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `peer` | array of tables |  | instance restart | Peers to connect to: uri and optional pinned public_key. |

## `[nat]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `nat.p2p` | `on` \| `lazy` \| `required` \| `off` | `on` | instance restart | Direct connections: on, lazy (only when traffic needs it), required (never relay), off. |
| `nat.udp_punch` | bool | `true` | instance restart | UDP hole punching. |
| `nat.tcp_punch` | bool | `true` | instance restart | TCP hole punching. |
| `nat.symmetric_punch` | bool | `true` | instance restart | Hole punching toward symmetric NATs. |
| `nat.stun` | list of strings |  | instance restart | IPv4 STUN servers. Built-in list when absent. |
| `nat.stun_v6` | list of strings |  | instance restart | IPv6 STUN servers. Built-in list when absent. |
| `nat.stun_tcp` | list of strings |  | instance restart | TCP STUN servers. |

## `[underlay]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `underlay.deny_interfaces` | list of strings |  | instance restart | Local interfaces the underlay must not use. |
| `underlay.deny_cidrs` | list of strings |  | instance restart | Local and remote CIDRs the underlay must not use. |
| `underlay.bind_device` | bool | `true` | instance restart | Bind underlay sockets to the physical device. |
| `underlay.socket_mark` | integer |  | instance restart | SO_MARK for underlay sockets (Linux). |

## `[discovery]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `discovery.trackers` | list of strings |  | instance restart | Tracker URLs: udp, http, https, or tcp for a LowTier hosted tracker. |
| `discovery.private_trackers` | list of strings |  | instance restart | Private tracker URLs. Supports udp, tcp, http, and https. |
| `discovery.bind` | string |  | instance restart | Local socket address for discovery traffic. |
| `discovery.advertise` | string |  | instance restart | Socket address announced to trackers. |

## `[relay]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `relay.policy` | `hop` \| `latency` \| `goodput` | `hop` | live | How to pick a relay route when no direct link exists: hop (fewest hops), latency (lowest round trip), or goodput (highest measured delivery rate; needs relay.probe_budget_bps). |
| `relay.use_relays` | bool | `true` | live | Send local data through relay peers. |
| `relay.transit` | `allow` \| `avoid` \| `deny` | `allow` | live | Carry data for other peers. |
| `relay.transit_networks` | list of strings |  | live | Foreign network name patterns this node relays. ["*"] permits all. |
| `relay.transit_bps_limit` | bit/s |  | live | Shared transit budget. Unlimited when absent. |
| `relay.transit_burst_bytes` | size |  | live | Transit burst capacity. |
| `relay.probe_interval_seconds` | duration | `30` | live | Seconds between speed test rounds, 1 to 300. |
| `relay.probe_budget_bps` | bit/s | `0` | live | Bandwidth limit for speed tests, for the whole machine. The tests measure how fast each direct connection delivers; the results show as RATE, start new flows on each peer's fastest connection (except under relay.policy=latency), and are required by relay.policy=goodput. 0 turns the tests off. |
| `relay.link_cost` | array of tables |  | live | Adjacent link cost bias: peer public key and bias_ms. |
| `relay.foreign_rpc` | bool | `false` | instance restart | Relay control RPC for foreign networks outside relay.transit_networks. |
| `relay.private_mode` | bool | `false` | instance restart | Reject foreign networks without authorized admission. |

## `[camouflage]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `camouflage.server_name` | string |  | new connections; QUIC: instance restart | User-selected TLS domain (SNI). Configure a decoy upstream or a website with a matching certificate. |
| `camouflage.tls_cert` | path |  | new connections; QUIC: instance restart | TLS certificate file. Set together with tls_key. |
| `camouflage.tls_key` | path |  | new connections; QUIC: instance restart | TLS private key file. |
| `camouflage.admission_secret` | secret |  | new connections; QUIC: instance restart | Secret that separates VPN clients from website visitors (16+ bytes). |
| `camouflage.website_root` | path |  | new connections; QUIC: instance restart | Static website served to unauthenticated visitors. |
| `camouflage.sni_routing` | bool | `false` | new connections; QUIC: instance restart | Classify connections by SNI instead of the admission marker. |
| `camouflage.decoy_upstream.tcp` | string |  | new connections; QUIC: instance restart | TCP decoy upstream for unauthenticated connections. |
| `camouflage.decoy_upstream.udp` | string |  | new connections; QUIC: instance restart | UDP decoy upstream for unauthenticated connections. |
| `camouflage.wss_path` | string | `/ws` | new connections | WebSocket path. |
| `camouflage.http_host` | string |  | new connections | HTTP authority for H2 and WSS. |
| `camouflage.trusted_proxy_cidrs` | list of strings |  | new connections | Reverse proxies trusted for client addresses. |

## `[limits]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `limits.memory_bytes` | size |  | process restart | Process memory budget. Default: RAM/16, 64MiB to 1GiB. |
| `limits.receive_bps` | bit/s |  | live | Instance receive limit. Unlimited when absent. |

## `[l2]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `l2.fdb_capacity` | integer | `16384` | instance restart | Forwarding database entries. |
| `l2.fdb_age` | duration | `300` | instance restart | Forwarding database entry lifetime. |
| `l2.flood_bytes_per_second` | size | `64MiB` | instance restart | Unknown-unicast, broadcast, and multicast budget per second. 0 disables. |
| `l2.bridge` | bool | `false` | instance restart | Accept complete Ethernet frames from this admin node. |
| `l2.max_macs_per_peer` | integer | `256` | instance restart | MAC addresses each peer may own. 0 disables the limit. |
| `l2.mac_move_hold` | duration | `5` | instance restart | Hold time before a MAC may move to another peer. |
| `l2.vlans` | list of integers |  | instance restart | Allowed VLAN IDs. Empty allows all; 0 means untagged. |
| `l2.ether_types` | list of integers |  | instance restart | Allowed EtherTypes. Empty allows all. |

## `[routes]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `routes.manual` | list of strings |  | instance restart | Routes installed instead of the automatic routes. |
| `routes.serve_exit` | bool | `false` | instance restart | Act as an exit node for peers. |

## `[[group]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `group` | array of tables |  | live | Load-balance groups: name, members (peer keys or virtual IPs), balance (flow or failover), weights. |

## `[[path]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `path` | array of tables |  | live | Paths: to (peer, CIDR, or internet), via (peers or groups in order), gateway (peer or group), strict. |

## `[[note]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `note` | array of tables |  | live | Local peer names and notes for the management interface: peer (public key), name, text. |

## `[[export]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `export` | array of tables |  | instance restart | Local subnets exported to peers: cidr, optional mapped_cidr and allow. |

## `[proxy]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `proxy.socks5` | host:port |  | instance restart | SOCKS5 listener into the network. |
| `proxy.http` | host:port |  | instance restart | HTTP proxy listener into the network. |
| `proxy.system_forward` | bool | `false` | instance restart | Forward exported subnets with the system stack. |

## `[[forward]]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `forward` | array of tables |  | instance restart | Port forwards: proto, bind, dest. |

## `[dns]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `dns.accept` | bool | `false` | instance restart | Serve magic DNS for peer host names. |
| `dns.zone` | string | `lt.net.` | instance restart | Magic DNS zone. |

## `[acl]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `acl` | table |  | live | ACL chains and groups. |
| `acl.tcp_ports` | list of strings |  | live | Local TCP ports peers may reach. Empty allows all. |
| `acl.udp_ports` | list of strings |  | live | Local UDP ports peers may reach. Empty allows all. |

## `[log]`

| Option | Type | Default | Applies | What it does |
| --- | --- | --- | --- | --- |
| `log.console` | string |  | live | Console log level: off, error, warn, info, debug, trace. |
| `log.file` | string |  | process restart | File log level. |
| `log.dir` | path |  | process restart | File log directory. |
| `log.max_size_mb` | integer |  | process restart | File size before rotation, in MiB. |
| `log.max_files` | integer |  | process restart | Rotated files to keep. |
