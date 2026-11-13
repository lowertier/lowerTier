# Memory budget

The process memory budget bounds admission of QUIC connections and the growth of userspace TCP buffers.
Set it with `limits.memory_bytes`; see the [option reference](../options.md).

`[limits] receive_bps` sets the independent instance receive limit in bit/s.
The receive limit also applies to foreign connections. Omission means unlimited input.

`[limits] memory_bytes` sets the shared process memory budget in bytes.
The default is physical RAM divided by 16, with a minimum of 64 MiB and a maximum of 1 GiB.
An explicit positive value replaces this default.
The value must fit the platform address space.
Instances share one process budget and use the smallest explicit value supplied during the process lifetime.
Lower values take effect immediately for new reservations.
Existing connections keep their reservations.
Restart the process to increase or remove an explicit limit after its first configuration.

```toml
[limits]
memory_bytes = 268435456
```

iOS and `macos-ne` builds cap this budget at 16 MiB, including explicit overrides.
This leaves space below the approximate 50 MiB Network Extension limit for executable pages, runtime state, and uncharged allocations.
The governor bounds QUIC admission. It does not bound peak RSS under simultaneous full-rate load or kernel socket memory.
Other consumers, including userspace TCP, retain their separate memory reservations.

QUIC reserves a fixed 1 MiB per connection for admission.
The charge does not reserve the worst-case sum of throughput windows.
The DATAGRAM send and receive limits remain 1 MiB and 2 MiB.
The stream receive, aggregate receive, and connection send windows remain 2 MiB, 4 MiB, and 2 MiB.
The incoming bidirectional stream limit remains 100.
Idle connections allocate buffer storage on demand.
New QUIC connections leave one quarter of the process budget available for control packets and shared buffer growth.
The 64 MiB minimum admits up to 48 QUIC connections when no other reservations exist.
The 1 GiB default ceiling admits up to 768 connections under the same condition.
The 16 MiB Network Extension ceiling admits up to 12 connections under the same condition.
Network Extension builds may need smaller windows later; any such change requires separate measurement and platform configuration.
Full budgets produce a counted warning and a connection refusal.
Received DATAGRAM payloads use owned copies to prevent small slices from retaining padded packets.
The receive queue also bounds the count of tiny and empty frames.

Tracker handshake concurrency initially follows one quarter of the configured budget divided by the QUIC connection charge.
Existing handshake slots keep their initial capacity after a budget decrease; new connection reservations enforce the current limit.
At least one handshake can attempt admission; the current governor rejects attempts that lack memory credit.
Userspace TCP buffers grow from demand within one eighth of the current budget per direction, up to 8 MiB.
Existing TCP receive windows do not shrink when the budget decreases.
