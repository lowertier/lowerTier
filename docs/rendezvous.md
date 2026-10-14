# Minimal rendezvous

`lowertier-tracker` supplies temporary endpoints for the initial VPN handshake.
It accepts standard BEP 15 UDP requests and compact HTTP announcements.
HTTP can run behind an HTTPS reverse proxy.
Public tracker clients remain compatible.
Client configurations identify private services with `discovery.private_trackers`, using URLs also present in `discovery.trackers`.
Public tracker candidates exclude loopback, private, link-local, and shared IPv4 addresses by default.
Private tracker candidates and authenticated peer candidates retain the configured underlay policy.
The service does not implement torrent storage, scraping, indexing, or VPN relaying.

The standalone crate builds with `cargo build -p lowertier-tracker --features server --release`.
The tracker UDP socket also answers bounded STUN Binding requests for IPv4 and IPv6.
Use `--stun-tcp-listen 0.0.0.0:16780` to enable retained TCP Binding sessions for H2 and WSS mappings.
Use `--stun-change-port` with two UDP ports on each listen address to enable CHANGE-PORT.
CHANGE-IP and TURN remain unsupported. The Python Binding service remains available during deployment migration.

Use `--passkey-file /path/to/passkey` to restrict HTTP and UDP announcements.
Clients supply `?passkey=...` in each private tracker URL. UDP uses bounded BEP 41 URLData options.
Passkeys remain visible on plaintext HTTP and UDP paths. Keep passkeys out of shared configuration and request logs.
HTTP and TCP Binding connections share a limit of 64 across all listeners.
Tracker and Binding responses share a 128 KiB payload limit per second.

Private clients request a padded, versioned UDP CONNECT echo with the `LTO1` marker.
The response keeps the standard 16-byte CONNECT prefix and leaves compact ANNOUNCE replies unchanged.
Clients use the observed UDP endpoint only for that tracker and the shared QUIC socket, for at most 60 seconds.
An explicit `advertise` overrides observations. A UDP observation cannot establish a TCP mapping.
Private HTTP requests use `lt_observe=1`; replies can include the bencoded `lt_observed` endpoint.
HTTP clients use a separate source port, so that port is not a VPN listener mapping.
Trusted proxies supply only the client IP; their replies omit observed endpoints when the original port is unavailable.

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
IPv4 paths announce their bound port provisionally while STUN collects the mapped port.
This port can be unreachable behind NAT, but outbound bootstrap to a reachable peer can still succeed.
Mapping observations trigger a new announcement, with at least five seconds between successful mapping events.

The client attempts candidates from each permitted source interface.
Connection state refers to a specific authenticated connection.
A live connection to the same peer suppresses duplicate attempts on other interfaces.
A healthy connection to a different peer does not suppress repair of a lost peer.
Expired candidate observations stop producing retries.
The existing process and peer connection limits still apply.
Discovery candidates do not allocate unlimited VPN connections.
All discovery paths share limits of 32 connection attempts and 64 KiB of punch payload per second.
These limits cover bootstrap probes and candidate attempts, including fresh-port fallback.
QUIC packet traffic retains the existing transport admission and memory limits.

QUIC retains its authenticated peer probes and mapped UDP socket.
H2 and WSS bind TCP listeners before collecting mappings.
STUN failures do not block tracker replies, outbound seed connections, or relay bootstrap.
Both endpoints select opposite TLS roles for coordinated TCP attempts.
Mapped TCP attempts remain active through one default private polling interval and the existing handshake allowance.
The caller limits this complete attempt to 45 seconds.
The existing limit of eight concurrent candidate attempts remains unchanged.
A conventional TCP connection remains available for reachable listeners and older peers.
Existing authenticated peer-assisted traversal remains available after bootstrap.
NAT mapping and filtering behavior can still prevent a direct connection.
For example, a NAT can change the source port for each destination.
The endpoint observed by STUN then differs from the endpoint used for a peer.
Initial rendezvous alone cannot guarantee traversal of that NAT.

## Timing and HTTP identification

The private service defaults to a two-second announce interval.
After authentication, clients request an interval of at least 30 seconds from the private service.
Clients retain all interface paths and continue to request candidate endpoints.
This permits new nodes and disconnected groups to establish connections.
The private hint uses `left=2`; bootstrap uses `left=1`.
Both values remain nonzero for compatibility with public trackers that exclude other seeders from seeder replies.
The private service extends each endpoint lease to three returned intervals.
Clients honor the interval returned by each public tracker.
A changed mapping starts a new announce event without the previous extra 15-second delay.
Link loss and mapping changes cancel pending tracker requests.
Mapping changes also discard tracker cookies that can depend on the previous source IP.
Independent tracker requests prevent one unavailable service from blocking another service.

HTTP and HTTPS requests send `User-Agent: aria2/1.37.0`.
This changes the HTTP identification field.
It does not change TLS behavior or provide an indistinguishability guarantee.

## Discovery through authenticated peers

The existing authenticated overlay carries versioned peer information and connection requests.
It maintains the peer list without a second gossip protocol.
Unchanged peer information does not require another full synchronization message.
The endpoint RPC now includes active discovery listeners and their mapped addresses.
A new node can use one known peer to learn other peers and establish direct connections.

Peer and route changes immediately trigger connection-task checks.
The periodic check remains available for recovery.
An existing live connection, including a hole-punched connection, suppresses duplicate direct connection and traversal attempts.
Endpoint lists remove duplicate URLs before connection attempts.
Task membership checks use a local hash table instead of repeated linear searches and concurrent-map locks.

Rendezvous remains necessary when two groups have no authenticated path between them.
The longer private interval can add up to one polling interval before an established group discovers a new endpoint.
Handshake retries and public tracker intervals can add further delay.
Cached candidates continue to support repair while another mesh connection remains active.
Failed liveness checks mark the connection closed, even when a silent TCP stream remains open.

Multiple NAT layers do not by themselves determine whether direct traversal will work.
Mapping and filtering behavior at every layer determine the result.
Two endpoints with incompatible destination-dependent mappings can require an authenticated relay.
Configure a reachable LowTier peer for this fallback.
The tracker supplies endpoints only and cannot relay VPN traffic.

The protocol references are [BEP 15](https://www.bittorrent.org/beps/bep_0015.html)
and [BEP 7](https://www.bittorrent.org/beps/bep_0007.html).
