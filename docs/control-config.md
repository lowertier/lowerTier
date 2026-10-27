# Relay and camouflage configuration

LowTier uses one relay policy and separate permissions for local relay use and data transit.
Same-network transit defaults to `allow`. Foreign transit defaults to denied.

```toml
[relay]
policy = "hop"
use_relays = true
transit = "allow"
transit_networks = []
# transit_bps_limit = 8000000
# transit_burst_bytes = 1000000
probe_interval_seconds = 30
probe_budget_bps = 0

[camouflage]
# server_name = "challenges.cloudflare.com"
wss_path = "/ws"
trusted_proxy_cidrs = []

[control]
# portal = "127.0.0.1:15888"
token_file = "/path/to/control.token"
# token_group = "lowertier"   # group members may read the token (mode 0640)
```

`policy` accepts `hop`, `latency`, and `goodput`. Goodput requires a positive probe budget.
`use_relays=false` permits local data only through directly connected peers. It does not change transit permission.
`transit` accepts `allow`, `avoid`, and `deny`. Denied nodes remain reachable as endpoints.
`transit_networks` contains foreign network name patterns. Use `["*"]` to permit every foreign network.
An empty list denies foreign transit. A public relay must explicitly permit each client network.
For example, a relay outside `office-l2` can permit that network with this configuration:

```toml
[relay]
transit = "allow"
transit_networks = ["office-l2"]
```

Transit and probe limits use bit/s. Burst capacity uses bytes. Omit the transit limit for unlimited transit.
The default burst holds one second of traffic or one 256 KiB maximum packet, whichever is larger.
An explicit burst must hold at least one maximum packet.
Every direction, foreign network, and same-network transit flow shares the instance transit budget.
Each egress copy consumes its serialized overlay size once. Transport retransmissions do not consume this budget.
The final sink checks permission and credit after queued data becomes ready for framing.
Avoided transit nodes remain available. Routing minimizes their count before the selected policy metric.

Use [[path]] and [[group]] to send this node's traffic through chosen peers. See [paths](paths.md).
Use `[[relay.link_cost]]` with `peer` and nonnegative `bias_ms` for an adjacent link cost bias.
Keys use standard base64 and contain 32 bytes. Invalid or unavailable paths use automatic routing.
Authenticated routing and handshake control use the hop table.
Nodes without `relay_semantics_v1` remain endpoints and control participants.
They cannot supply data transit.

`[limits] receive_bps` sets the independent instance receive limit in bit/s.
The receive limit also applies to foreign connections. Omission means unlimited input.

`[limits] memory_bytes` sets the shared process memory budget in bytes.
The default is physical RAM divided by 16, with a minimum of 64 MiB and a maximum of 1 GiB.
An explicit positive value replaces this default.
The value must fit the platform address space.
Instances share one process budget and use the smallest explicit value supplied during the process lifetime.
Lower values take effect immediately for new reservations.
Existing connections keep their reservations.
Restart the process to increase or remove an explicit limit after its first configuration.

```toml
[limits]
memory_bytes = 268435456
```

iOS and `macos-ne` builds cap this budget at 16 MiB, including explicit overrides.
This leaves space below the approximate 50 MiB Network Extension limit for executable pages, runtime state, and uncharged allocations.
The governor bounds QUIC admission. It does not bound peak RSS under simultaneous full-rate load or kernel socket memory.
Other consumers, including userspace TCP, retain their separate memory reservations.

QUIC reserves a fixed 1 MiB per connection for admission.
Idle loopback RSS grew by approximately 260 KiB per endpoint; the charge provides approximately four times that measured allowance.
The charge does not reserve the worst-case sum of throughput windows.
The DATAGRAM send and receive limits remain 1 MiB and 2 MiB.
The stream receive, aggregate receive, and connection send windows remain 2 MiB, 4 MiB, and 2 MiB.
The incoming bidirectional stream limit remains 100.
Idle connections allocate buffer storage on demand.
New QUIC connections leave one quarter of the process budget available for control packets and shared buffer growth.
The 64 MiB minimum admits up to 48 QUIC connections when no other reservations exist.
The 1 GiB default ceiling admits up to 768 connections under the same condition.
The 16 MiB Network Extension ceiling admits up to 12 connections under the same condition.
Network Extension builds may need smaller windows later; any such change requires separate measurement and platform configuration.
Full budgets produce a counted warning and a connection refusal.
Received DATAGRAM payloads use owned copies to prevent small slices from retaining padded packets.
The receive queue also bounds the count of tiny and empty frames.

Tracker handshake concurrency initially follows one quarter of the configured budget divided by the QUIC connection charge.
Existing handshake slots keep their initial capacity after a budget decrease; new connection reservations enforce the current limit.
At least one handshake can attempt admission; the current governor rejects attempts that lack memory credit.
Userspace TCP buffers grow from demand within one eighth of the current budget per direction, up to 8 MiB.
Existing TCP receive windows do not shrink when the budget decreases.

Camouflage supports `server_name`, `tls_cert`, `tls_key`, `admission_secret`, `website_root`,
`sni_routing`, `wss_path`, `http_host`, and `trusted_proxy_cidrs`.
Set separate TCP and UDP endpoints when necessary:

```toml
[camouflage.decoy_upstream]
tcp = "127.0.0.1:8443"
udp = "127.0.0.1:8443"
```

Certificate and key paths must be configured together.
Decoy forwarding requires an admission secret of at least 16 bytes and a server name.
`sni_routing=true` replaces marker classification with SNI classification. Noise still authenticates VPN peers.
Named QUIC/H2 connections validate certificates when no decoy is configured.
Otherwise QUIC/H2 uses the existing Noise-authenticated certificate verifier.
Direct WSS retains its existing Noise verifier. CDN outer TLS always validates the public CDN certificate.
CDN inner TLS retains the end-to-end exporter binding. Missing subprotocol negotiation fails the connection.

TCP and WSS listeners read camouflage changes for new connections.
Existing connections keep their authenticated transport binding.
QUIC listeners cache certificates and decoy settings until listener recreation.
The control API stages cached QUIC settings as restart fields while QUIC is enabled.
Stop and start the instance to recreate those endpoints.

Endpoint URLs retain `via=cdn`, `lanes=1,2,4`, and WSS paths.
An explicit WSS URL path overrides `camouflage.wss_path`. The listener rejects a different request path.
WSS peer URLs with an empty or root path use `camouflage.wss_path`, which defaults to `/ws`.
Manual connectors retain this effective path so an active connection prevents repeated dialing.
Multiple lanes are unavailable in CDN mode. Trusted proxy CIDRs default to none.
CIDR and interface restrictions remain enforced. Strict underlay policy continues to reject peer hostnames.
VPN/SNI examples use `challenges.cloudflare.com`. This name does not establish certificate ownership.
Use explicit loopback endpoints for local tests.

## Removed settings

Old settings fail with an error that names the replacement. There is no migration tool.
`lowertier check -c FILE` lists every renamed or removed key in a file at once.
`lowertier run --set` and `lowertier set` use the same option paths as the file.
Old `ET_*` environment variables are ignored; retained QUIC resource settings use `LOWTIER_QUIC_*` variables.

### Sectioned layout (2026-10)

Every option moved into a section. Keys under `[flags]` were also accepted at the top level and are rejected in both places.
`enable_encryption` was removed because traffic is always encrypted; it only changed the TUN MTU arithmetic.
`node.threads` replaces `multi_thread` and `multi_thread_count`; `tun.mode` replaces `no_tun` and `use_smoltcp`;
`nat.p2p` replaces `disable_p2p`, `lazy_p2p`, and `need_p2p`. The `nat.*_punch` options are positive: `true` enables punching.
The `--tun=userspace-networking` startup option is `tun.mode = "userspace"`.
Network secrets and identity keys may live in files: `network.secret_file` and `identity.private_key_file`.

| Old key | New path |
| --- | --- |
| `hostname` | `node.hostname` |
| `instance_name` | `node.instance_name` |
| `instance_id` | `node.instance_id` |
| `netns` | `node.netns` |
| `ipv4` | `address.ipv4` |
| `ipv6` | `address.ipv6` |
| `dhcp` | `address.dhcp` |
| `ipv6_public_addr_provider` | `address.public_ipv6.provide` |
| `ipv6_public_addr_auto` | `address.public_ipv6.auto` |
| `ipv6_public_addr_prefix` | `address.public_ipv6.prefix` |
| `listeners` | `transport.listen` |
| `mapped_listeners` | `transport.advertise` |
| `exit_nodes` | `[[path]]` with `to = "internet"` and a `gateway` |
| `routes.exit_nodes` | `[[path]]` with `to = "internet"` and a `gateway` |
| `relay.prefer` | `[[path]]` with one `via` |
| `routes` | `routes.manual` |
| `proxy_network` | `export` |
| `socks5_proxy` | `proxy.socks5` |
| `outbound_http_proxy` | `proxy.http` |
| `port_forward` | `forward` |
| `tcp_whitelist` | `acl.tcp_ports` |
| `udp_whitelist` | `acl.udp_ports` |
| `stun_servers` | `nat.stun` |
| `stun_servers_v6` | `nat.stun_v6` |
| `tcp_stun_servers` | `nat.stun_tcp` |
| `credential_file` | `network.credential_file` |
| `network_identity` | `network` |
| `network_identity.network_name` | `network.name` |
| `network_identity.network_secret` | `network.secret` |
| `secure_mode` | `identity` |
| `secure_mode.enabled` | removed |
| `secure_mode.local_private_key` | `identity.private_key` |
| `secure_mode.local_public_key` | `identity.public_key` |
| `secure_mode.credential_bundle` | `network.credential` |
| `secure_mode.credential_root_fingerprint` | `identity.credential_root` |
| `secure_mode.credential_certificate` | removed |
| `peer.peer_public_key` | `peer.public_key` |
| `export.mapped` | `export.mapped_cidr` |
| `forward.bind_addr` | `forward.bind` |
| `forward.dst_addr` | `forward.dest` |
| `flags.default_protocol` | `transport.prefer` |
| `flags.enabled_protocols` | `transport.protocols` |
| `flags.dev_name` | `tun.name` |
| `flags.enable_encryption` | removed |
| `flags.enable_ipv6` | `tun.ipv6` |
| `flags.mtu` | `tun.mtu` |
| `flags.enable_exit_node` | `routes.serve_exit` |
| `flags.no_tun` | `tun.mode` |
| `flags.use_smoltcp` | `tun.mode` |
| `flags.disable_p2p` | `nat.p2p` |
| `flags.lazy_p2p` | `nat.p2p` |
| `flags.need_p2p` | `nat.p2p` |
| `flags.relay_all_peer_rpc` | `relay.foreign_rpc` |
| `flags.disable_udp_hole_punching` | `nat.udp_punch` |
| `flags.disable_tcp_hole_punching` | `nat.tcp_punch` |
| `flags.disable_sym_hole_punching` | `nat.symmetric_punch` |
| `flags.multi_thread` | `node.threads` |
| `flags.multi_thread_count` | `node.threads` |
| `flags.bind_device` | `underlay.bind_device` |
| `flags.proxy_forward_by_system` | `proxy.system_forward` |
| `flags.accept_dns` | `dns.accept` |
| `flags.private_mode` | `relay.private_mode` |
| `flags.encryption_algorithm` | `network.cipher` |
| `flags.tld_dns_zone` | `dns.zone` |
| `flags.enable_udp_broadcast_relay` | `tun.udp_broadcast_relay` |
| `flags.socket_mark` | `underlay.socket_mark` |
| `flags.underlay_deny_interfaces` | `underlay.deny_interfaces` |
| `flags.underlay_deny_cidrs` | `underlay.deny_cidrs` |
| `flags.quic_initial_receive_window` | `transport.quic.initial_receive_window` |
| `flags.quic_receive_window` | `transport.quic.receive_window` |
| `flags.l2_fdb_capacity` | `l2.fdb_capacity` |
| `flags.l2_fdb_age_seconds` | `l2.fdb_age` |
| `flags.l2_flood_bytes_per_second` | `l2.flood_bytes_per_second` |
| `flags.l2_flood_bps` | `l2.flood_bytes_per_second` |
| `flags.enable_bridge` | `l2.bridge` |
| `flags.l2_max_macs_per_peer` | `l2.max_macs_per_peer` |
| `flags.l2_mac_move_hold_seconds` | `l2.mac_move_hold` |
| `flags.l2_allowed_vlans` | `l2.vlans` |
| `flags.l2_allowed_ether_types` | `l2.ether_types` |
| `source` | removed |
| `config_server` | removed |
| `external_node` | `peer` |

### Relay and camouflage (2026-10)

| Old key or flag | Replacement |
| --- | --- |
| `latency_first`, `speed_first` | `relay.policy`: hop, latency, or goodput |
| `p2p_only` | `relay.use_relays=false` |
| `disable_relay_data` | `relay.transit="deny"` |
| `relay_network_whitelist`, GUI enable/list | `relay.transit_networks`; configure local `transit` separately |
| `foreign_relay_bps_limit` | `relay.transit_bps_limit`; multiply old byte/s values by eight; omit the old maximum sentinel |
| `instance_recv_bps_limit` | `limits.receive_bps`; multiply old byte/s values by eight; omit the old maximum sentinel |
| `speed_probe_interval_seconds` | `relay.probe_interval_seconds` |
| `speed_probe_budget_bps` | `relay.probe_budget_bps`; retain bit/s units |
| `quic_server_name` | `camouflage.server_name` |
| `quic_tls_cert`, `quic_tls_key` | `camouflage.tls_cert`, `camouflage.tls_key` |
| `quic_admission_secret` | `camouflage.admission_secret` |
| `quic_fallback_root` | `camouflage.website_root` |
| `quic_decoy_upstream` | `camouflage.decoy_upstream.tcp` and `.udp` |
| `quic_sni_passthrough` | `camouflage.sni_routing` |

Update test nodes explicitly. Preserve identities, key pins, ACLs, routes, and port forwards.
Deploy new transit semantics together; older nodes cannot serve as data transit nodes in the new graph.
