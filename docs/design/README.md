# Design notes

These notes record how lowertier works inside: exact limits, protocol rules, and the reasons behind them.
The guides one level up cover setup and use.

## Protocol

- [Fabric protocol version 4](fabric-protocol-v4.md): one dataplane for IP packets and Ethernet frames.
- [Dataplane cryptography](dataplane-crypto.md): ciphers, Noise, and the protocol boundary.
- [Transport activation](protocol-activation.md): restricting an instance to some transports, and what it allocates.
- [QUIC path migration](quic-rebinding.md): surviving NAT port and address changes.
- [Peer authentication scopes](mesh-health.md): the three authentication fields in peer status, and UDP reply counters.

## Behavior

- [Ethernet forwarding rules](l2-forwarding.md): learning, flooding, MAC ownership, MTU, and the test harness.
- [Relay and transit semantics](relay-transit.md): permissions, budgets, and goodput selection.
- [Userspace proxy internals](userspace-proxy.md): name resolution, dialing, and buffers.
- [Memory budget](memory-budget.md): QUIC admission, userspace TCP buffers, and Network Extension limits.
- [Decoy passthrough limits](decoy-passthrough.md): probe sessions, bandwidth, and UDP anti-amplification.

## Discovery

- [Tracker discovery](tracker-discovery.md): bootstrap sequence, punching, and tracker privacy.
- [Rendezvous service](rendezvous.md): the `lowertier-tracker` server.

## Management

- [Control API](control-api.md): the management RPC contract.
- [Retired management services](control-api-tombstones.md)
- [Renamed and removed options](renamed-options.md)
- [Lean core](lean-core.md): what was removed and why.

Implementation notes for the core crate live in `lowertier/docs/`.
