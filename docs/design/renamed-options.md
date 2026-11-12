# Renamed and removed options

Old settings fail with an error that names the replacement. There is no migration tool.
`lowertier check -c FILE` lists every renamed or removed key in a file at once.
`lowertier run --set` and `lowertier set` use the same option paths as the file.
Retained QUIC resource settings use `LOWTIER_QUIC_*` environment variables.

## Sectioned layout (2026-10)

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

## Relay and camouflage (2026-10)

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
