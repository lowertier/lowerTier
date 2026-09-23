# Transport activation and memory ownership

LowTier can explicitly restrict an instance to QUIC, H2/TCP, WSS, or a selected combination. The list is a startup setting; restart the instance when changing it.

## QUIC-only instance

```toml
listeners = ["quic://0.0.0.0:14192"]

# Every optional [[peer]] URI and mapped listener must also use quic.
[flags]
default_protocol = "quic"
enabled_protocols = ["quic"]
```

For H2-only use `default_protocol = "tcp"`, `enabled_protocols = ["tcp"]`, and `tcp://` listeners/peers. For WSS-only use `"wss"` and `wss://`. A mixed instance can list more than one protocol. An empty list, including the omitted default, preserves the previous all-protocol behavior.

The configuration loader rejects unsupported names, duplicates, a disabled preferred protocol, and listeners or bootstrap peers outside the list. Runtime listener/connector factories also reject disabled transports before DNS or socket creation. Direct discovery and authenticated rendezvous cannot reactivate a disabled transport.

## What is allocated

A QUIC-only instance omits TCP/WSS puncher servers, candidate maps and associated task reapers. TCP/WSS-only instances omit the QUIC puncher. NAT discovery runs only the selected transport family. Common address-discovery and management services remain separate from data transport selection.

Optional inner-IP proxy state is created only when subnet proxying, exit-node behavior or no-TUN operation needs it. An inactive proxy status query returns an empty result without constructing the TCP, UDP or ICMP proxy. Underlay protocol selection does not restrict which inner IP protocols the VPN can carry.

Route-cache limits remain traffic ceilings. Empty stores no longer reserve flow-entry tables at startup.

QUIC receive scratch starts with one complete GRO slot on GRO-capable sockets, then doubles the number of slots when the current batch fills, up to the unchanged batch limit. Every slot fits the full configured maximum coalesced message. Ordinary non-GRO batching is unchanged. Once the last endpoint connection drains, spare receive scratch is released. Active connections retain their warmed high-water scratch, avoiding allocation on each packet or idle interval.

For the Linux 1500-byte/64-segment/32-slot case, receive scratch initially uses 96,000 bytes instead of 3,072,000 bytes per endpoint. Its maximum remains 3,072,000 bytes. This is allocation accounting, not a claim that total process RSS falls by exactly that amount.

## Configuration metadata

Configuration differences are generated from the protobuf schema during the build. Normal configuration dumping compares typed fields and emits only differences from the application defaults. It does not decode the full runtime reflection pool just to serialize flags. Schema-equivalence tests cover every field, including optional zero values, explicit false values, enum names and unknown enum numbers. Reflection remains available for consumers that explicitly need it.

## Scope and compatibility

Shared routing, authentication, TLS primitives, configuration, metrics and management state remain necessary. The universal binary still links all supported transports. Removing unused executable code requires separate conditional-compilation profiles; runtime activation alone does not do that.

Protocol activation does not change encryption, packet formats, flow-control windows, congestion control, socket-buffer ceilings, per-flow delivery semantics or public-path MTU.

Compare memory at matching peer counts, offered load, transport, MTU and operating system. RSS includes shared mappings; macOS physical footprint is a separate measure. Linux kernel WireGuard and a userspace daemon do not have interchangeable process-RSS accounting. No matched WireGuard memory-parity claim is made by this change.
