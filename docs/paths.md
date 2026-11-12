# Paths and load-balance groups

A path sends this node's traffic through chosen peers instead of the automatic route.
A group is a set of peers that share one position in a path. Each flow uses one member.

```toml
[[group]]
name = "relays"
members = ["<peer public key>", "10.144.0.7"]   # keys or virtual IPs, up to 32
balance = "flow"        # flow: spread flows by weight; failover: first usable member
weights = [2, 1]        # optional, flow only

[[group]]
name = "exits"
members = ["10.144.0.21", "10.144.0.22"]

# Traffic to one peer passes beta, then one member of relays.
[[path]]
to = "<peer key or virtual IP>"
via = ["<beta key>", "relays"]

# Internet traffic leaves through the exits group, balanced per flow.
[[path]]
to = "internet"
gateway = "exits"

# A subnet behind several gateways, through a relay tier, never routed automatically.
[[path]]
to = "10.8.0.0/16"
via = ["relays"]
gateway = "exits"
strict = true
```

Changes apply live: `lowertier set`, `lowertier edit`, the configuration file, or the Routes page of the [web interface](web-interface.md).

## Choosing members

- A flow is a connection: the same addresses, ports, and protocol. All its packets use the same members, so TCP stays in order and an exit keeps one public address per connection.
- `flow` groups use weighted rendezvous hashing. With weights 2:1 a member carries about two thirds of the flows. When a member disappears, only its flows move; the others stay where they are.
- `failover` groups use the first usable member in the listed order.
- A waypoint member is usable when it is reachable, runs a version with `waypoint_v1`, and does not deny transit (`relay.transit = "deny"`).
- An internet gateway member needs `routes.serve_exit = true`. A subnet gateway member must export the subnet or serve as an exit.
- When a segment has no usable member, the path falls back to automatic routing. With `strict = true` the traffic is dropped instead.

## Precedence for IP traffic

1. Addresses of overlay peers route to that peer. A path with `to` set to that peer adds waypoints.
2. A CIDR path with a gateway wins over automatic subnet routes.
3. Automatic subnet routes.
4. The internet path, for everything else outside the overlay network.

Paths apply to traffic this node sends. Replies follow the other node's own paths and routes.

## Waypoints forward without opening packets

The sender seals each packet for its final destination, exactly as for any relayed packet. It then rewrites only the header and appends a small trailer: the remaining waypoints, the final destination, and the original packet type: 7 bytes plus 4 bytes per further waypoint. Each waypoint reads the trailer, sets the next destination, and forwards the packet. It does not decrypt, re-encrypt, or copy the payload. The last waypoint restores the original header and removes the trailer, so the destination receives the bytes the sender sealed.

Nodes between waypoints see an ordinary encrypted transit packet and forward it by its destination, so they need no upgrade. A first waypoint that is a direct neighbor is not written into the trailer: the packet is sent over that link, and a path with only that waypoint carries no trailer at all.

## Status

`lowertier paths` lists each path's state, every member with whether it is usable and why not, and how many packets each member carried. `lowertier routes` marks destinations that follow a path, and `lowertier routes trace` names the path. The GUI shows the same with a traffic share bar per member.
