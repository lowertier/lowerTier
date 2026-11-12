# Relay and transit semantics

The [routing guide](../routing.md) covers configuration. This note records the exact rules.

## Policy and permissions

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
# server_names = ["challenges.cloudflare.com"]
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

Use [[path]] and [[group]] to send this node's traffic through chosen peers. See [paths](../paths.md).
Use `[[relay.link_cost]]` with `peer` and nonnegative `bias_ms` for an adjacent link cost bias.
Keys use standard base64 and contain 32 bytes. Invalid or unavailable paths use automatic routing.
Authenticated routing and handshake control use the hop table.
Nodes without `relay_semantics_v1` remain endpoints and control participants.
They cannot supply data transit.

## Goodput selection

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
For relay fallbacks, the selector first minimizes avoided transit nodes.
It then maximizes the path's minimum valid directed delivery rate.
Equal bottlenecks use cost, hop count, and first-hop peer ID.
Destination-specific bottleneck thresholds preserve the cost tie-breaker.
Expired or missing samples use latency and then hop fallback.
Every data fallback excludes denied transit nodes.
Authenticated routing and handshake control use a separate hop table.
Complete Ethernet control frames still follow data transit restrictions.

Use `policy = "hop"` to restore hop selection.
Set `probe_budget_bps = 0` to stop measurement after changing the policy.
