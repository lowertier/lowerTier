# Paths and relay groups

A `[[path]]` steers this node's outbound traffic through chosen relays or relay layers instead of taking automatic single-relay routing.

- Automatic routing (`hop`, `latency`, `goodput`) always picks **1 best relay path**.
- User `[[path]]` and `[[group]]` rules unlock **multipath aggregation** (`mode = "parallel"`) and **multilayer relay chains** (`layers` up to `8` stages) across `quic`, `h2`, `wss`, and mixed-transport links.

```toml
[[group]]
name = "relays"
nodes = ["<peer public key>", "10.144.0.7"]   # keys or virtual IPs, up to 32
mode = "parallel"       # parallel (default) | flow | failover
weights = [2, 1]        # optional weights (1..=1000) for parallel or flow

[[group]]
name = "exits"
nodes = ["10.144.0.21", "10.144.0.22"]
mode = "flow"

# Traffic to one peer stripes across r1 and r2 in layer 1, then crosses layer 2.
[[path]]
to = "<peer key or virtual IP>"
layers = [["<r1 key>", "<r2 key>"], "relays"]

# Default rule for any peer without a specific [[path]] entry.
[[path]]
to = "*"
layers = ["relays"]

# Internet traffic strips across relays toward a flow-pinned exit gateway.
[[path]]
to = "internet"
layers = [["<r1 key>", "<r2 key>"]]
gateway = "exits"
strict = true

# Per-layer inline options: parallel layer 1, then flow-pinned layer 2.
[[path]]
to = "10.8.0.0/16"
layers = [
  "relays",
  { nodes = ["10.144.0.8", "10.144.0.9"], mode = "flow", weights = [3, 1] },
]
gateway = "exits"
strict = true
```

Changes apply live: `lowertier set`, `lowertier edit`, the configuration file, or the Routes page of the [web interface](web-interface.md).

## Modes and chain expansion

- **`parallel` (default)**: Expands usable relays across `layers` into up to `16` loop-free relay chains and stripes traffic at packet/burstlet granularity across all transports (`quic`, `h2`, `wss`, or mixed).
  - The scheduler tracks live queue pressure and drain rate on each first hop alongside active encrypted `PathProbe` / `PathProbeAck` RTT measurements (`ΔOWD`-invariant for asymmetric forward/reverse paths).
  - A BLEST arrival guard keeps slow or saturated chains outside the 15 ms reorder budget from blocking fast ones, while 8-packet / 12 KiB burstlet weighted deficit round-robin preserves intra-burst locality.
  - The sender attaches an authenticated `ETMP` sequence proof inside each packet's AEAD envelope, and the destination restores strict per-flow packet order in a lock-sharded reorder buffer guarded by a 16,384-bit anti-replay window.
- **`flow`**: Pins each connection (5-tuple flow) deterministically using weighted rendezvous hashing so packets stay on one chain; when one node goes down, only its flows move.
- **`failover`**: Uses the first usable node in listed order.
- **`gateway` coercion**: When a `gateway` stage is configured for `"internet"` or a CIDR in `mode = "parallel"`, the final `gateway` stage automatically coerces to `flow` per connection so SNAT exit flows keep one public source IP, while any preceding `layers` still stripe in `parallel`.

## Usable nodes and fallback

- A relay node in `layers` is usable when it is reachable, advertises `multipath_relay_v1` and `relay_semantics_v1`, and does not deny transit (`relay.transit = "deny"`).
- An internet `gateway` node needs `routes.serve_exit = true`. A subnet `gateway` node must export the subnet or serve as an exit.
- When no usable chain or gateway exists, `[[path]]` falls back to automatic single-relay routing unless `strict = true`, which drops traffic instead.

## Targets, precedence, and asymmetric paths

1. Addresses of overlay peers: an explicit peer `[[path]]` (`to = "<key or IP>"`) wins over a wildcard `to = "*"` default `[[path]]`, which wins over automatic routing.
2. A CIDR `[[path]]` (`gateway` or `layers`) wins over automatic `[[export]]` subnet routes.
3. Automatic `[[export]]` subnet routes.
4. `to = "internet"` for destinations outside the overlay network.

Paths govern traffic this node **sends** across L3 IP payloads, L2 bridged Ethernet frames, and `OverlayStream` connections (including SOCKS5/HTTP `tcp_proxy` destinations). Return traffic follows the remote peer's own `[[path]]` and routes, so forward and reverse directions can be completely asymmetric.

## Source-routed transit without decryption

The sender seals every packet end-to-end for its final destination (`from_peer_id -> dst_peer_id` with encrypted `ETMP` tag), writes an outer source-route header targeting the first relay in the selected chain, and appends a constant-length 36-byte trailer (`[hop_index, hop_count, hops[0..8], dst_peer_id, original_type]`). Intermediate relays advance `hop_index` in place and forward opaquely over their existing `quic`, `h2`, or `wss` links without decrypting payloads or holding per-flow endpoint sessions. When the final relay forwards to the destination, the destination unwraps the source route before AEAD decryption and per-flow reordering.

## Status

`lowertier paths` shows each path's mode, usable nodes per layer, active end-to-end chains with probe RTT and packet counts, reordered packet counts, fallbacks, and drops. `lowertier routes` marks destinations routed via a `[[path]]`, and `lowertier routes trace` names the matching path. The web interface displays the same layers, active chains, and traffic shares live.
