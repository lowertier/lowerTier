# Security and Data Plane Efficiency Design

## Goal

Protect authenticated peer identity and remove proven structural work from the data plane.

## Security boundary

Transport authentication defines the immediate peer identity.

RPC handlers must receive that identity from trusted transport metadata.

Route synchronization must reject a request when its claimed peer differs from the authenticated peer.

Unknown peer identity types must fail closed.

Packet authorization must distinguish the authenticated next hop from the logical origin.

Direct packets must use the authenticated next hop as their origin.

Relayed packets can retain another origin only after verified end-to-end protection.

## QUIC recovery

Reliable stream EOF is a recoverable error unless the connection closes.

Listener activation must use a bounded timeout.

The listener must accept new connections without waiting for one connection to activate.

Reliable replay must use sequence identifiers and receive deduplication.

Endpoint reuse keys must include socket ownership and underlay attributes.

## Data plane work reduction

Reusable packet slabs keep the complete allocation owner.

An active byte range selects the packet view without reducing the slab capacity.

Hybrid routing uses one immutable data-plane snapshot per batch.

The snapshot contains only routing and capability fields required by forwarding.

Mixed-capability delivery keeps compact and Ethernet packets in separate peer batches.

ARP and NDP requests must pass complete validation before route lookup.

## Compatibility

Legacy L2 delivery remains available through capability negotiation.

Authorized bridge nodes continue to receive complete Ethernet frames.

Normal IP unicast continues to use compact L3 packets.

Security checks apply to old and new capabilities.

## Verification

Tests cover identity spoofing, unknown identity types, relayed traffic, QUIC EOF, replay, and activation timeout.

Tests cover slab reuse, mixed-capability batch preservation, and neighbor validation.

Benchmarks record throughput, allocation evidence, route snapshot counts, copied bytes, and socket calls.

The workload matrix includes direct, relay, mixed-version, multicast, secure UDP, and QUIC traffic.
