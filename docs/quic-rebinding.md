# QUIC NAT rebinding

An authenticated H3/CONNECT-IP connection can survive a change to the client's public UDP source port.
The remote IP must remain the same.
The connection keeps its TLS exporter binding, Noise session, and memory credit.

The server permits rebinding after CONNECT-IP admission and the complete Noise handshake.
Website connections and unauthenticated connections cannot rebind.
Each new endpoint must pass the current underlay deny policy.
Quinn validates the endpoint with standard `PATH_CHALLENGE` and `PATH_RESPONSE` frames.
Its anti-amplification limit applies while validation is in progress.
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
The existing idle timeout and relay recovery remain available if neither path works.

IP migration remains disabled.
It requires source-IP admission changes before the previous source permit can be released.
The current source-IP permits protect handshake activation and are released before a tunnel becomes established.
Retaining these permits for established tunnels would impose the handshake limit on all peers behind one NAT.
This change does not add that restriction.
