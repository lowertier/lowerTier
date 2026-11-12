# Routing and relays

Every node routes on its own. Traffic to a peer uses a direct connection when one exists.
When none does, it goes through other members, which relay it without being able to read it.

## Relay fallback

`relay.policy` ranks relay routes when no direct connection exists:

| Policy | Picks the route with |
| --- | --- |
| `hop` (default) | the fewest hops |
| `latency` | the lowest measured round-trip time |
| `goodput` | the highest measured delivery rate at its slowest link |

Goodput needs measurements. Give the node a probe budget first, then switch once samples appear:

```toml
[relay]
policy = "hop"
probe_interval_seconds = 30
probe_budget_bps = 1000000   # 1 Mbit/s of probe traffic for the whole node
```

```bash
lowertier set relay.policy=goodput
```

Goodput measures each direction separately.
It first avoids nodes that set `transit = "avoid"`, then maximizes the slowest link, then breaks ties by cost, hop count, and peer ID.
Routes without fresh samples fall back to latency, then hops.
Set `probe_budget_bps = 0` to stop probing after switching away.

`lowertier routes trace 10.44.0.2` shows the path a packet takes, hop by hop.

## Carrying traffic for others

```toml
[relay]
use_relays = true          # false: send only over direct connections
transit = "allow"          # allow | avoid | deny: carry data for other peers
transit_networks = []      # foreign networks this node relays; ["*"] allows all
# transit_bps_limit = "50Mbit"
# transit_burst_bytes = "1MiB"
```

- `use_relays = false` keeps this node's own traffic on direct links. It does not change what the node carries for others.
- `transit = "deny"` refuses to carry other peers' data. The node stays reachable as an endpoint.
- `transit = "avoid"` keeps the node usable as a relay, but routes pass through as few `avoid` nodes as possible.
- A node only relays for its own network unless `transit_networks` names others. A public relay must list each network it serves:

```toml
[relay]
transit = "allow"
transit_networks = ["office"]
```

All transit, in every direction and for every network, shares `transit_bps_limit`. Leave it out for no limit.
The default burst holds one second of traffic or one 256 KiB packet, whichever is larger.
`limits.receive_bps` caps everything the instance receives, including foreign traffic.

`[[relay.link_cost]]` biases one adjacent link: `peer` (a public key) and a non-negative `bias_ms`.

Nodes that run an older version without `relay_semantics_v1` stay reachable as endpoints but cannot carry transit.

## Exit nodes and subnets

A node becomes an exit for internet traffic with `routes.serve_exit = true`.
Other nodes send internet traffic through it with a path:

```toml
[[path]]
to = "internet"
gateway = "<exit peer key or virtual IP>"
```

A node shares a local subnet with `[[export]]` (see [configuration](configuration.md#subnets-forwards-and-access)).
Peers route to it automatically.

For IP traffic, a node picks routes in this order:

1. Addresses of peers go to that peer.
2. A subnet path with a gateway.
3. Automatic subnet routes from `[[export]]`.
4. The internet path, for everything else.

To send traffic through chosen nodes, balance flows across several relays or exits, or pin a subnet to a set of gateways, see [paths and groups](paths.md).
