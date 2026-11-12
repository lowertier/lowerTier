# Security

lowertier uses its own protocol built from standard parts: TLS 1.3, Noise, X25519, and ChaCha20-Poly1305.
It has not had an external security audit.

## Who may join

A node is admitted when it proves either the shared `network.secret` or a signed credential issued by a member (`lowertier creds issue`).
Every node also has an X25519 identity key, and every connection completes a Noise handshake against it:
Noise XX between neighbors and Noise IK across relays, with SHA-256 and ChaCha20-Poly1305.

Pin `peer.public_key` when a node must only ever talk to one specific identity, such as a shared relay.
The admission secret in [camouflage](camouflage.md) adds a further check before a connection reaches the handshake.

## What is encrypted

Every link is TLS 1.3: QUIC, HTTP/2, or WebSocket. The Noise handshake is bound to that TLS session through its exporter, so a proxy in the middle cannot splice two TLS sessions together.

- **Between neighbors**, packets ride inside that TLS session. lowertier adds no second layer of encryption there.
- **Across relays**, the sender seals each packet for the destination with the session key: ChaCha20-Poly1305 by default (`network.cipher` also offers AES-GCM),
  a 16-byte tag, a 12-byte nonce, and the packet header's stable fields as associated data.
  Relays and [waypoints](paths.md) forward the sealed packet without opening it.

Session keys are per direction, rotate in epochs, and use sequence nonces with replay windows.

The 16-byte packet header stays outside the seal because relays update routing fields. Its stable fields are authenticated.

## What an observer sees

An observer on the path still sees endpoints, packet sizes and timing, direction, which transport is in use, and a random connection identifier.
UDP setup packets and QUIC traffic can be classified. lowertier does not claim resistance to active probing or a covert transport;
[camouflage](camouflage.md) changes what a probe sees but is not a guarantee.

A public tracker sees the network's rendezvous hash, the public addresses that announce it, and their timing. It cannot join.

## Local surfaces

- The control port listens on loopback and requires the control token, which only the node's user can read.
- The SOCKS5 and HTTP proxies have no authentication. Bind them to loopback.
- The web interface needs its access key except from sources listed in `gui.open`.

The [dataplane cryptography note](design/dataplane-crypto.md) records the cipher details and the protocol boundary.
