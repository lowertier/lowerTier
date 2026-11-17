# QUIC native proxy admission

The useful H2 mechanism for QUIC is the admission policy.
QUIC already provides multiplexed streams.
LowTier already uses H3 CONNECT streams for eligible direct TCP proxy traffic.
Another multiplexer would add framing, buffering, and state.

The public option is `transport.quic.tcp_proxy = "off" | "on" | "auto"`.
The default is `auto`.
The November 17, 2026 implementation reuses the H2 admission state.
It changes neither the admitted data path nor QUIC congestion control.

## Current behavior

Both transports share `ProxyEndpoint` in `lowertier/src/tunnel/stream_proxy.rs`.
The sender checks authenticated capabilities before selecting the native path.
The receiver checks authentication, source identity, destination scope, and policy.
Application bytes wait for a successful CONNECT response.

The native scope requires the remote userspace peer's own IPv4 address.
The local node must have initiated the transport connection.
ACL-controlled traffic, kernel destinations, relays, and mapped routes retain packets.

| Admission result | Automatic action |
| --- | --- |
| Missing capability or destination scope | Select packets before CONNECT. |
| Missing local stream or memory capacity | Select packets before CONNECT without changing endpoint health. |
| HTTP 406 | Select packets without a health penalty. |
| HTTP 501 or 503 before admission | Select packets and start endpoint cooldown. |
| Native open error or timeout | Fail this flow and start cooldown for later flows. |
| Destination or policy refusal | Fail this flow without changing endpoint health. |

The previous QUIC path always attempted eligible native streams.
Local stream or memory exhaustion failed the flow before CONNECT.
Explicit remote refusals could select packets, but later flows repeated the native attempt.
Automatic admission now handles both cases.

`off` selects packets.
`on` requires native streams within the supported scope.
Strict mode reports capability, capacity, and native-open errors.
HTTP 406 still selects packets because the destination is outside native scope.
Changes apply to new flows.

## Admission boundary

Both transports reuse capability checks, refusal classification, and endpoint health state.
The cooldown grows from two seconds to thirty seconds.
One real flow probes recovery after the deadline.
Generation checks reject stale concurrent outcomes.
Cancellation releases recovery ownership and starts another cooldown.
Local capacity pressure does not reset endpoint failure history.

A successful admission keeps its native stream.
An ambiguous admission fails the current flow.
The proxy does not replay application bytes.
It does not move admitted flows between streams and datagrams.

Packet fallback still needs packet-stack memory.
It can fail when the process has insufficient resources.
The policy targets avoidable native-open failures.
It cannot guarantee recovery from general memory exhaustion.

## Cost model

Let `F` be new TCP proxy flows.
Let `B` be delivered application bytes.
Let `N` be concurrent native proxy streams on one endpoint.

The policy adds constant work per flow: `O(F)`.
It adds no work proportional to `B`.
A successful automatic attempt locks endpoint health before CONNECT and after its response.
The shared constructor already allocates one health record per QUIC endpoint.
The policy reuses that record.
No background probe, extra carrier handshake, or data frame is required.
Cooling endpoints skip native CONNECT exchanges until the recovery probe.
The locks do not occur on the payload path.

Each native stream currently reserves 64 KiB for copy storage.
The endpoint permits at most 32 native streams.
Its copy-storage charge is therefore `N × 64 KiB`, at most 2 MiB.
This charge excludes QUIC windows, packet queues, kernel sockets, and other process memory.
Automatic admission preserves these limits.
The owned copy future retains the slot and charge while either direction remains active.
Completion, error, or cancellation releases the reservation.

The QUIC configuration caps the stream receive window at 2 MiB.
It caps the connection receive window at 4 MiB and the send window at 2 MiB.
It bounds datagram receive and send storage separately.
These controls have different purposes from admission.
The H2 receive-credit reservation mechanism does not transfer directly to QUIC.
At 112 ms RTT, a 2 MiB send window corresponds to about 150 Mbit/s before overhead.
This bound does not establish achievable throughput.

## Reliability and performance limits

Reliable QUIC streams deliver bytes independently.
All streams still share connection congestion control and connection resources.
A failed QUIC connection can terminate all its streams.

QUIC DATAGRAM frames have no reliable-delivery or stream-credit contract.
They still use the connection's congestion controller.
Packet fallback on the same QUIC connection cannot remove connection congestion.
It cannot repair a failed carrier.

Admission policy should use capability, capacity, and open-health evidence.
RTT alone does not establish that packet forwarding will outperform native streams.
No throughput selector or new threshold follows from the H2 results.
The jpaws-LA H2 measurements do not establish a QUIC gain.

Focused tests cover refusal, capacity pressure, cancellation, recovery, and live mode changes.
Shared state tests cover stale outcomes and single recovery ownership.
WAN evidence must distinguish admission failures from packet loss and carrier failure.

The November 17 jpaws-LA slow-reader test exposed shared-carrier pressure.
Four unread native downloads blocked all six later short requests in `on`.
They also blocked all six requests in `auto`, including packet fallback attempts.
The packet-only control delivered six of six requests.
Closing the unread transfers restored a native request on the same QUIC connection.

Source inspection identifies two application dependencies.
The packet writer waits for reliable completion before it accepts later DATAGRAM batches.
A selected CONNECT-IP write also delays reads on that stream.
These dependencies can propagate blocked stream writes into unrelated packet traffic.
Shared connection-credit exhaustion is consistent with the observations.
The experiment did not capture the exact blocked operation or active `MAX_DATA` state.

Automatic admission does not resolve these dependencies.
It improves capacity and explicit-refusal handling relative to the previous always-native policy.
The default does not add a new native data path.
Further isolation needs independent packet progress and protected control capacity.
Larger windows alone do not establish that isolation.
See the [jpaws-LA report](../performance/quic-auto-20261117.md) for measurements and limits.

## WSS

WSS currently puts each overlay packet in a binary WebSocket message.
It has no native TCP stream endpoint or admission mode.
An `auto` switch alone would add no useful behavior.
WSS also supports explicit two-lane and four-lane TCP configurations.
Those configurations distribute packets across authenticated carriers.
They retain inner TCP and do not provide native proxy byte streams.
The default single-lane path is the WSS benchmark baseline.

A native WSS design would need stream identifiers, admission responses, resets, and flow control.
It would also need bounded scheduling and memory accounting.
Its benefit could come from removing inner TCP packets and their processing.
Its framing and implementation costs require a separate experiment.
The shared outer TCP carrier would still impose head-of-line blocking.
Native H2 already provides standard stream framing when H2 is available.

For an illustrative WSS cost model, assume one complete binary frame per chunk.
Assume an eight-byte application stream header.
This header is an estimate, not an implemented wire format.
With a 16 KiB payload, WebSocket adds eight bytes upstream and four bytes downstream.
The combined framing ratio would be approximately 0.098% upstream and 0.073% downstream.
This excludes TLS, outer IP and TCP, setup, flow-control messages, and retransmissions.
Small chunks have a higher ratio.

The current packet path includes a 16-byte peer header and inner IP/TCP headers.
It does not use the H2 four-byte packet-length prefix.
With a 1280-byte inner MTU and plain 20-byte TCP headers, application payload is 1240 bytes.
Its data framing adds 56 bytes before WebSocket framing.
This excludes TCP options, inner acknowledgments, and packet encryption overhead.
Removing packet work can help WSS, but a header calculation does not establish throughput or reliability.
Keep the current WSS packet path until a native protocol passes those tests.

## Sources

- [Sukka, Hikyaku](https://blog.skk.moe/post/hikyaku-proxy/): shared carriers, admission cost, timeouts, and health checks.
- `lowertier/src/tunnel/stream_proxy.rs`: admission, health state, stream slots, and copy storage.
- `lowertier/src/tunnel/quic.rs`: H3 CONNECT setup, transport windows, and datagram queues.
- `lowertier/src/peers/peer_conn.rs`: authenticated capability selection.
- `lowertier/src/gateway/socks5.rs`: timeout and fallback boundaries.
- [RFC 9000, Sections 2 and 4](https://www.rfc-editor.org/rfc/rfc9000.html): stream and connection flow control.
- [RFC 9221, Sections 5.3 and 5.4](https://www.rfc-editor.org/rfc/rfc9221.html): datagram flow control and congestion control.
- [RFC 6455, Sections 5.2 and 5.3](https://www.rfc-editor.org/rfc/rfc6455.html): WebSocket frame lengths and client masking.
- [RFC 9114, Section 6.1](https://www.rfc-editor.org/rfc/rfc9114.html): client-initiated HTTP/3 request streams.

The RFC copies and download records are in `benchmark-results/.work/h2-auto-20261117/` and `benchmark-results/.work/quic-auto-20261117/`.
