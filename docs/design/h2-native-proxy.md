# H2 native TCP proxy

H2 uses native CONNECT streams on the existing authenticated TCP carrier.
The implementation shares destination admission and byte copying with the H3 proxy.
It adds no smux layer, retry protocol, or carrier pool.
The public option is `transport.h2.tcp_proxy = "off" | "on" | "auto"`.
The default is `off`.
The [proxy guide](../proxy-mode.md#h2-tcp-streams) defines the modes.

## Admission and failure boundaries

The authenticated Noise capability is `tcp-stream-proxy-v1`.
The separate `tcp-stream-local-ipv4-v1` capability identifies a userspace destination peer.
Kernel peers omit that destination capability.
The sender therefore selects packets without an extra native CONNECT exchange.
The transport retains its TLS exporter binding.
Both peers must authenticate before a native request can reach destination admission.
The receiver checks the source peer, destination scope, ACL state, and protected ports.
Application bytes cannot pass before the successful CONNECT response.

| Result | Meaning | Automatic action |
| --- | --- | --- |
| HTTP 200 | The destination was admitted. | Use this stream. |
| HTTP 406 | The destination is outside native scope. No application bytes were sent. | Use packets without changing endpoint health. |
| HTTP 501 | The endpoint disabled native streams. | Use packets and start a cooldown. |
| HTTP 503 | Native stream or memory capacity is unavailable before admission. | Use packets and start a cooldown. |
| Destination or policy error | The native transport answered. | Fail this flow without reducing endpoint health. |
| Native open error or timeout | Destination admission can be ambiguous. | Fail this flow. Start a cooldown for later automatic flows. |

Strict `on` reports HTTP 501 and 503 as errors.
HTTP 406 retains the packet path in all modes because the destination is outside native scope.
No fallback follows an ambiguous failure.
No application bytes are replayed.

Each endpoint stores a failure count, deadline, probe flag, and generation.
The cooldown starts at two seconds and caps at thirty seconds.
One real flow can probe recovery after the deadline.
Generation checks prevent stale concurrent results from changing newer health state.
A cancelled probe releases its ownership and starts another cooldown.
Local capacity pressure does not reset the health history.

## Work and traffic model

Let `B` be delivered application bytes.
Let `M` be the inner IPv4 MTU.
Let `T` be the inner TCP header size.
Let `P = M - 20 - T` be application payload per full inner packet.
Let `C` be a native copy chunk, at most 32 KiB.
Let `N` be concurrent admitted native streams, at most 32.

The model excludes outer IP, TCP, TLS, and their acknowledgments.
Both paths still require those costs.
Actual frame counts depend on partial reads and negotiated H2 frame limits.

| Step | Packet path | Native path | Added bound or work |
| --- | --- | --- | --- |
| Carrier setup | Existing TLS and H2 connection. | Reuse the same connection. | No extra carrier handshake. |
| Flow selection | Route and peer selection. | Same selection, mode check, and capability check. | Constant work per flow. |
| Flow admission | Inner TCP setup and destination connection. | CONNECT request, source check, and destination connection. | One request/response exchange; variable HPACK headers. |
| Resource admission | Packet socket buffers and connection state. | One stream slot and one memory reservation. | Constant work per admitted flow. |
| Upload buffering | Inner TCP buffers, packet headers, and H2 coalescing. | Read into an owned chunk and pass ownership to H2. | At most one pending copy chunk per direction. |
| Download buffering | Packet parsing, inner TCP reassembly, and socket buffers. | Retain the H2 DATA chunk until the destination consumes it. | Return receive credit after consumption. |
| Data framing | Inner IPv4, TCP, 16-byte peer header, and 4-byte length. | H2 DATA frames. | H2 adds a 9-byte header per DATA frame on both paths. |
| Reliability | Inner TCP recovery runs over outer TCP recovery. | Outer TCP handles byte delivery. | No second TCP recovery loop for the native flow. |
| Health policy | Normal carrier management. | A mutex update for automatic opens and outcomes. | No per-byte health check or background probe. |

For full inner packets, packet framing adds approximately `ceil(B / P) × (20 + T + 20)` bytes.
This excludes inner TCP acknowledgments and H2 framing.
With `M = 1280` and `T = 20`, the data overhead is `60 / 1240`, or approximately 4.84%.
TCP options and partial packets increase that ratio.
Inner TCP acknowledgments add reverse traffic.

A full 32 KiB native DATA frame adds `9 / 32768`, or approximately 0.0275%, in H2 framing.
This excludes CONNECT headers, WINDOW_UPDATE frames, outer transport headers, and TLS.
Small writes have a larger framing ratio.
Native streams therefore remove packet work rather than guaranteeing a fixed throughput increase.

## Separate resource controls

The existing TCP underlay determines the application send queue budget.
Packets and native streams share that budget through atomic claims.
An H2 capacity reservation is separate from a queue reservation.
Senders reuse retained H2 capacity after a queue wakeup.
They do not wait for a new H2 capacity increase when credit is already available.
Consumed or discarded DATA releases queue admission and wakes all native waiters.

The standard receive settings start with a 2 MiB stream window and a 4 MiB connection window.
Each admitted H2 native stream reserves its full receive window plus 64 KiB of copy storage.
The existing process memory governor can refuse that reservation.
The governor's limit does not increase.
The maximum standard reservation for 32 native streams is 66 MiB per endpoint.
Reservations describe governed storage, not total process RSS.

For `N` active native reservations, the target connection window is:

```text
target_connection_window = original_connection_window + N × stream_receive_window
```

This preserves the original packet credit when admitted native readers stop consuming data.
The H2 driver receives one coalesced window update signal when reservations change.
Closing a stream reduces the target.
H2 cannot revoke credit already advertised to the peer.
It withholds later updates until outstanding data falls below the reduced target.

The receiver returns native stream credit only after the destination consumes the bytes.
The server always drives the H2 connection, including when its bounded request handlers are full.
A full handler set returns a refusal before destination admission.
The process limits, stream limit, queue budget, and receive windows remain separate controls.

## Reliability limits

H2 stream resets isolate individual application exchanges.
Memory reservations prevent admitted slow readers from consuming the packet credit allowance.
Neither mechanism removes TCP head-of-line blocking.
A lost outer segment can still delay every H2 stream.
A broken carrier can terminate every stream.
Automatic packet selection on that carrier cannot repair either condition.

QUIC already provides independent reliable streams and datagrams.
This implementation preserves the existing H3 path and adds no second multiplexer to QUIC.
