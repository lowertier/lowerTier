# Security and Data Plane Efficiency Design

## Goal

Protect authenticated peer identity and remove proven structural work from the data plane.

## Security boundary

Transport authentication defines the immediate peer identity.

The completed authenticated peer session supplies this identity.

Packets keep the identity as immutable local metadata through ingress queues.

The final peer-connection egress filter removes this local metadata.

RPC handlers must receive that identity from trusted transport metadata.

Route synchronization must reject a request when its claimed peer differs from the authenticated peer.

Route synchronization must reject missing identity metadata.

Unknown peer identity types must be rejected.

ForeignRelay authority is limited to its authenticated peer record and the
allowlisted OSPF and DirectConnector services.

Credential and SharedNode route claims cannot grant bridge, multicast, proxy,
or foreign-network authority.

Admin topology input remains bounded before route graph construction.

Route synchronization accepts at most 4096 peer records, 262144 directed
edges, and 1024 edges from one source.

Bitmap and list forms reject duplicate peer identifiers and malformed lengths.

Foreign-network records and group declarations have structural count limits.

RPC fragments use bounded body, transaction, session, and task budgets.

Compressed RPC bodies must declare a bounded decompressed size before decode.

Directed link-quality reports require authenticated source identity, bounded
rate and latency values, fresh sample TTL, and a per-source report limit.

RPC reassembly keys include the authenticated session peer.

All fragments in one message must use the same authenticated session peer.

Packet authorization must distinguish the authenticated next hop from the logical origin.

Direct packets must use the authenticated next hop as their origin.

Relayed packets can retain another origin only after verified end-to-end protection.

The relay proof is mandatory in protocol version 2.

The proof authenticates the origin, destination, packet type, protocol version, session generation, epoch, sequence, and payload.

The Noise session static keys are the trust root.

The receive replay window supplies freshness.

Peers must reject proof replay, field changes, and missing proof.

All direct and relay handshakes must use protocol version 2.

Nodes must reject every other protocol version.

## QUIC recovery

The current framing does not replace or replay reliable streams.

A clean FIN half-closes one direction. The opposite direction remains usable.

A non-clean reliable read or write error closes the QUIC connection.

The writer keeps a partial frame suffix. It resumes that suffix after a cancelled
write and never replays a completed prefix.

Listener activation must use a bounded timeout.

The listener must accept new connections without waiting for one connection to activate.

Future reliable replay framing requires a new mandatory protocol version.

That future version can add epochs, monotonic sequence numbers, acknowledgements,
bounded unacknowledged frames, and receiver deduplication.

The future version must reset sequence state only after both sides confirm
activation and must close the lane before sequence wrap.

Current peers keep the current framing and do not replay after a partial write.

Pending activation has global and per-peer bounds.

Timeout and saturation close the pending stream and connection.

Endpoint reuse keys include socket mark, bind address, address family, dual-stack mode, interface, namespace, role, and owner lifetime.

Policy generation changes prevent endpoint reuse.

## Data plane work reduction

Reusable packet slabs keep the complete allocation owner.

An active byte range selects the packet view without reducing the slab capacity.

The active range contains only initialized bytes for the current packet.

Reuse resets the active range and cannot occur while an alias exists.

Hybrid routing uses one immutable data-plane snapshot per batch.

Every updated node advertises hybrid L3 support.

TUN and TAP edges use the same overlay packet contract.

The snapshot contains only routing and capability fields required by forwarding.

Each TUN-originated IP packet enters the outbound NIC and ACL pipeline once.

The accepted packet then feeds both compact IP and authorized Ethernet branches.

The full input batch uses one immutable snapshot and one selected next hop per recipient.

Mixed-capability delivery keeps compact and Ethernet packets in separate peer batches.

Each eligible peer receives each packet once in original per-peer order.

Classification uses one authorization and routing generation.

Fanout checks the complete recipient count before packet cloning.

Fanout accounting uses saturating output-byte multiplication and a hard recipient bound.

Unknown unicast, broadcast, and multicast fanout are rejected before partial replication.

Bridge authorization remains separate from packet capability.

ARP and NDP requests must pass complete validation before route lookup.

ARP validation checks VLAN bounds, Ethernet and hardware types, address lengths, opcode, frame length, and sender consistency.

NDP validation checks VLAN bounds, IPv6 length, next-header chain, hop limit, checksum, source rules, target rules, and option bounds.

Duplicate-address detection uses the unspecified-source rules from RFC 4861.

Malformed requests drop before route lookup.

Valid unsupported frames pass through unchanged.

## Updated-only protocol

The implementation does not accept legacy handshakes or packet protection.

Authorized bridge nodes continue to receive complete Ethernet frames.

Normal IP unicast continues to use compact L3 packets.

Every joined node must run the updated binaries.

The speed-first flag has independent version 2 semantics.

## Verification

Tests cover identity spoofing, unknown identity types, relayed traffic, QUIC EOF, replay, and activation timeout.

Tests cover slab reuse, mixed-capability batch preservation, and neighbor validation.

Benchmarks record throughput, allocation evidence, route snapshot counts, copied bytes, and socket calls.

The workload matrix includes direct, relay, version rejection, multicast, secure UDP, and QUIC traffic.
