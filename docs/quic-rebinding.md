# QUIC path migration

An authenticated H3/CONNECT-IP connection can survive a change to the client's public UDP port or IP address.
The connection keeps its TLS exporter binding, Noise session, and memory credit.

The server permits rebinding after CONNECT-IP admission and the complete Noise handshake.
Website connections and unauthenticated connections cannot rebind.
Each new endpoint must pass the current underlay deny policy.
Established connections do not acquire handshake source-IP permits for migration.
These permits limit pending handshakes, not established peers behind one NAT.
One process-wide token bucket admits 32 validations per second with a burst of 64.
Each connection permits one validation at a time and waits at least two seconds between validation starts.
These limits are constants and have no configuration setting.
Quinn validates the endpoint with standard `PATH_CHALLENGE` and `PATH_RESPONSE` frames.
Its anti-amplification limit applies while validation is in progress.
Receive credit belongs to the packet's source path.
Probing-only packets from an unknown endpoint receive no path response before migration admission.
Peer endpoint information changes only after validation.
Tracker discovery reads this validated information when it updates candidate observations.

UDP decoy routing passes short-header packets from a new tuple to Quinn for connection-ID lookup.
This does not create a route entry or an upstream socket.
Quinn checks packet protection and the authenticated path policy before accepting the new endpoint.
An unknown connection ID can receive a standard stateless reset.
Quinn limits reset frequency and sends fewer bytes than the triggering packet.
An existing decoy route retains priority for its cached UDP tuple.
Rebinding into that tuple can therefore require reconnect or relay recovery before the decoy route expires.

A policy denial leaves the previous path available.
Failed validation restores the previous path through Quinn's existing timeout handling.
Rejected attempts and validation failures increment `quic_migrations_rejected`.
The existing idle timeout and relay recovery remain available if neither path works.

Linux and macOS clients monitor interface and route notifications.
They also check source selection and underlay policy changes every two seconds.
The client uses `quinn::Endpoint::rebind` when the route or permitted source changes.
Local changes use the same migration budget and cooldown.
The previous socket remains available until the replacement socket receives a matching validation response.
Failed validation restores the connection's previous send socket and keeps its receive socket available.
Validated local endpoint information changes only after this check succeeds.

Shared endpoints wait until all their outgoing connections authenticate.
Quinn keeps the original sockets for handshakes that start during a rebind.
Discovery listener endpoints retain their advertised sockets and do not migrate actively.
With active deny rules, a shared endpoint defers migration if its connections require different source addresses.
Migration requires a usable route to the existing peer address.
Other platforms support remote path migration but do not automatically rebind client sockets.
This includes Windows, Android, and iOS.
If native notifications are unavailable, Linux and macOS retain the source-selection checks.
