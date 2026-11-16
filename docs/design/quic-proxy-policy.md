# QUIC native proxy admission

The useful H2 mechanism for QUIC is the admission policy.
QUIC already provides multiplexed streams.
LowTier already uses H3 CONNECT streams for eligible direct TCP proxy traffic.
Another multiplexer would add framing, buffering, and state.

This note records source analysis on November 17, 2026.
It proposes a later change.
The H2 automatic-policy rollout does not change QUIC.

## Current behavior

Both transports share `ProxyEndpoint` in `lowertier/src/tunnel/stream_proxy.rs`.
The sender checks authenticated capabilities before selecting the native path.
The receiver checks authentication, source identity, destination scope, and policy.
Application bytes wait for a successful CONNECT response.

The native scope requires the remote userspace peer's own IPv4 address.
The local node must have initiated the transport connection.
ACL-controlled traffic, kernel destinations, relays, and mapped routes retain packets.

| Admission result | QUIC today | Useful policy change |
| --- | --- | --- |
| Missing capability or destination scope | Select packets before CONNECT. | Keep this behavior. |
| Missing local stream or memory capacity | Fail the current flow. | Permit packet selection before CONNECT. |
| HTTP 406 | Select packets without a health penalty. | Keep this behavior. |
| HTTP 501 or 503 before admission | Select packets. | Add endpoint cooldown for later flows. |
| Native open error or timeout | Fail the current flow. | Also start cooldown for later flows. |
| Destination or policy refusal | Fail the current flow. | Keep endpoint health unchanged. |

`mode()` currently returns `on` for QUIC.
The local resource fallback requires `mode == "auto"`.
The cooldown also requires an H2 budget and `auto`.
QUIC therefore has safe remote refusal fallback without the H2 health state transitions.

## Proposed boundary

Reuse capability checks, refusal classification, and endpoint health state.
Use the existing two-to-thirty-second cooldown.
Allow one real flow to probe recovery after the deadline.
Keep generation checks for concurrent outcomes.
Keep local capacity pressure separate from endpoint failure history.

Preserve the current flow after a successful admission.
Fail the current flow when admission is ambiguous.
Do not replay application bytes.
Do not move an admitted flow between streams and datagrams.

Packet fallback still needs packet-stack memory.
It can fail when the process has insufficient resources.
The policy can reduce avoidable native-open failures.
It cannot guarantee recovery from general memory exhaustion.

## Cost model

Let `F` be new TCP proxy flows.
Let `B` be delivered application bytes.
Let `N` be concurrent native proxy streams on one endpoint.

The proposed policy adds constant work per flow: `O(F)`.
It adds no work proportional to `B`.
An automatic native attempt locks endpoint health at admission and at completion.
The shared constructor already allocates one health record per QUIC endpoint.
The proposed policy can reuse that record.
No background probe, extra carrier handshake, or data frame is required.
Cooling endpoints skip native CONNECT exchanges until the recovery probe.
No measured CPU or latency bound is available for this proposed change.

Each native stream currently reserves 64 KiB for copy storage.
The endpoint permits at most 32 native streams.
Its copy-storage charge is therefore `N × 64 KiB`, at most 2 MiB.
This charge excludes QUIC windows, packet queues, kernel sockets, and other process memory.
The proposed policy must preserve these limits.

The QUIC configuration caps the stream receive window at 2 MiB.
It caps the connection receive window at 4 MiB and the send window at 2 MiB.
It bounds datagram receive and send storage separately.
These controls have different purposes from admission.
The H2 receive-credit reservation mechanism does not transfer directly to QUIC.

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

A later implementation needs focused refusal, cancellation, and concurrent-recovery tests.
Matched jpaws-LA measurements must compare native and packet paths.
The comparison must include short flows, bulk flows, mixed UDP traffic, and a slow reader.
It must report delivery, latency, loss, retransmissions, effective throughput, CPU per delivered Gbit, and RSS scope.
Use repeated trials without changing memory limits or MTUs.

## Sources

- `lowertier/src/tunnel/stream_proxy.rs`: admission, health state, stream slots, and copy storage.
- `lowertier/src/tunnel/quic.rs`: H3 CONNECT setup, transport windows, and datagram queues.
- `lowertier/src/peers/peer_conn.rs`: authenticated capability selection.
- `lowertier/src/gateway/socks5.rs`: timeout and fallback boundaries.
- [RFC 9000, Sections 2 and 4](https://www.rfc-editor.org/rfc/rfc9000.html): stream and connection flow control.
- [RFC 9221, Sections 5.3 and 5.4](https://www.rfc-editor.org/rfc/rfc9221.html): datagram flow control and congestion control.

The RFC copies and download records are in `benchmark-results/.work/h2-auto-20261117/`.
