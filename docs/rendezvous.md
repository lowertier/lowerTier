# Minimal rendezvous

`lowertier-tracker` supplies temporary endpoints for the initial VPN handshake.
It accepts standard BEP 15 UDP requests and compact HTTP announcements.
HTTP can run behind an HTTPS reverse proxy.
Public tracker clients remain compatible.
The service does not implement torrent storage, scraping, indexing, or VPN relaying.

## Explicit ports

Set each listening port and each URL port explicitly in deployment configuration.
UDP and HTTP both default to port `16969`.
Their sockets use different transport protocols, so they can share that number.
The HTTP default address is loopback.
Any available port can be configured.
Ports below 1024 can require operating-system permission.

This command serves a local dual-stack test:

```sh
lowertier-tracker \
  --udp-listen '127.0.0.1:16969,[::1]:16969' \
  --http-listen '127.0.0.1:16969,[::1]:16969' \
  --interval 2
```

Repeat the listen options or supply comma-separated addresses to bind more interfaces.
IPv6 sockets use `IPV6_V6ONLY`, which prevents conflicts with IPv4 sockets on the same port.

See [the client configuration example](../script/mesh-discovery/client.example.toml).
Its addresses refer to local test services.
Set actual service addresses before deployment.
Set explicit ports for STUN, discovery, VPN listeners, and the RPC portal.
Use an HTTPS URL with an explicit port when a proxy terminates TLS.

## Identity and endpoint state

One discovery session identifier covers all interface addresses of a running node.
Each announcement uses its interface address as the source address.
The service stores a separate lease for each session and observed endpoint.
An IPv4 announcement does not replace an IPv6 announcement.
One interface announcement does not replace another interface announcement.

The service uses the observed source IP and the announced transport port.
It does not accept a supplied replacement IP.
The service excludes the requesting session from its peer list.
Each reply contains at most 16 endpoints from the request's address family.
Reply rotation exposes additional endpoints in larger groups.

Leases last three announce intervals, with a minimum of ten seconds.
New endpoints can coexist with old endpoints until their leases expire.
An endpoint-specific stop event does not remove the node's other endpoints.
Expired entries cannot authenticate a node or establish online status.

The VPN authenticates each connection with the existing network identity and Noise handshake.
TLS exporter binding remains enabled for QUIC, H2, and WSS.
Changing an IP address does not change the running node's peer identity.
A process restart creates a new runtime incarnation.
Tracker session identifiers are discovery identifiers, not persistent device credentials.

## Interfaces and connection attempts

Automatic discovery checks active, permitted interfaces every two seconds.
It uses IPv4 and IPv6 concurrently when IPv6 is enabled.
Underlay exclusions and virtual-network checks still apply.
Removing one interface stops that discovery path without removing other paths.
Path removal closes its published connections and releases their connection slots.
Other paths retry after the slots become available.
An explicit `discovery.bind` selects one local address instead.

Each address family needs a reachable tracker address in that family.
Configure both A and AAAA records, or provide explicit IPv4 and IPv6 tracker URLs.
An IPv4-only service cannot observe a node's IPv6 source address.
Native IPv6 listeners advertise their bound ports without waiting for IPv4 STUN.
IPv4 NAT mappings still use STUN.

The client attempts candidates from each permitted source interface.
Connection state refers to a specific authenticated connection.
A healthy connection on another interface does not suppress repair of a failed connection.
Expired candidate observations stop producing retries.
The existing process and peer connection limits still apply.
Discovery candidates do not allocate unlimited VPN connections.

QUIC retains its authenticated peer probes and mapped UDP socket.
H2 and WSS retain their mapped TCP listening sockets.
Both endpoints select opposite TLS roles for coordinated TCP attempts.
A conventional TCP connection remains available for reachable listeners and older peers.
Existing authenticated peer-assisted traversal remains available after bootstrap.
NAT mapping and filtering behavior can still prevent a direct connection.
For example, a NAT can change the source port for each destination.
The endpoint observed by STUN then differs from the endpoint used for a peer.
Initial rendezvous alone cannot guarantee traversal of that NAT.

## Timing and HTTP identification

The private service defaults to a two-second announce interval.
Clients honor the interval returned by each public tracker.
A changed mapping starts a new announce event without the previous extra 15-second delay.
Independent tracker requests prevent one unavailable service from blocking another service.

HTTP and HTTPS requests send `User-Agent: aria2/1.37.0`.
This changes the HTTP identification field.
It does not change TLS behavior or provide an indistinguishability guarantee.

The protocol references are [BEP 15](https://www.bittorrent.org/beps/bep_0015.html)
and [BEP 7](https://www.bittorrent.org/beps/bep_0007.html).
