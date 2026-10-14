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
```

`policy` accepts `hop`, `latency`, and `goodput`. Goodput requires a positive probe budget.
`use_relays=false` permits local data only through directly connected peers. It does not change transit permission.
`transit` accepts `allow`, `avoid`, and `deny`. Denied nodes remain reachable as endpoints.
`transit_networks` contains foreign network name patterns. Use `["*"]` to permit every foreign network.
Transit and probe limits use bit/s. Burst capacity uses bytes. Omit the transit limit for unlimited transit.
The default burst holds one second of traffic or one 256 KiB maximum packet, whichever is larger.
An explicit burst must hold at least one maximum packet.
Every direction, foreign network, and same-network transit flow shares the instance transit budget.
Each egress copy consumes its serialized overlay size once. Transport retransmissions do not consume this budget.
The final sink checks permission and credit after queued data becomes ready for framing.
Avoided transit nodes remain available. Routing minimizes their count before the selected policy metric.

Use `[[relay.prefer]]` with `peer` and `via` public keys for a first-hop preference.
Use `[[relay.link_cost]]` with `peer` and nonnegative `bias_ms` for an adjacent link cost bias.
Keys use standard base64 and contain 32 bytes. Invalid or unavailable paths use automatic routing.
Authenticated routing and handshake control use the hop table.
Nodes without `relay_semantics_v1` remain endpoints and control participants.
They cannot supply data transit.

`[limits] receive_bps` sets the independent instance receive limit in bit/s.
The receive limit also applies to foreign connections. Omission means unlimited input.

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
The future control API must prepare replacement listeners before it reports these settings as active.

Endpoint URLs retain `via=cdn`, `lanes=1,2,4`, and WSS paths.
An explicit WSS URL path overrides `camouflage.wss_path`. The listener rejects a different request path.
Multiple lanes are unavailable in CDN mode. Trusted proxy CIDRs default to none.
CIDR and interface restrictions remain enforced. Strict underlay policy continues to reject peer hostnames.
VPN/SNI examples use `challenges.cloudflare.com`. This name does not establish certificate ownership.
Use explicit loopback endpoints for local tests.

## Removed settings

Old settings fail with an error that names the replacement. There is no migration tool.
CLI options use the same new names with hyphens and relay prefixes.
Old `ET_QUIC_*` environment variables fail; retained QUIC resource settings use `LOWTIER_QUIC_*` variables.

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
