# Handshake and UDP ownership repair

The repair is committed as `c35b93b1`.
Eleven reachable test instances run the repaired version 0.03.
The verification date is November 15, 2026, in Japan.

## Causes and changes

The reported WSS listener, `58.147.235.242:14193/ws`, belongs to `hattori-opwrt`.
Its saved logs contain the reported connection ID and peer ID.
The relay queue errors continued after the earlier MTU rollout.
They were not limited to service restart times.

Simultaneous direct handshakes could reserve conflicting session transitions.
A regression test reproduced failure in both directions before the repair.
The endpoint with the lower peer ID now orders incoming and outgoing handshakes.
Unknown destinations defer a competing outgoing handshake.
The surviving initiator waits for the losing reservation to release.
Only typed transition-busy errors receive this bounded retry.
Cancellation releases the gate.
Authentication, TLS exporter binding, and exact transition confirmation remain required.

UDP NAT lookup previously used only source and destination sockets.
A restarted peer could reuse those sockets while replies retained the previous peer ID.
The NAT key now includes both overlay peer IDs.
Fragment reassembly uses the same ownership boundary for UDP and ICMP.
This prevents fragments from different peers from forming one datagram.
The repair also removes a duplicate-start race in the UDP forwarding task.

WSS previously completed TLS and WebSocket setup serially.
One stalled socket could delay every following connection.
Setup now runs concurrently with limits of 32 connections per listener and four per source IP.
The three-second setup deadline includes the initial lane record.
Lane MAC validation and exporter binding remain required.
The existing total H2 lane deadline is preserved.
Unauthenticated setup EOF and reset messages use debug logging.
Established connection errors remain visible.

The relay queue limits remain unchanged.
The repair removes conflicting session ownership and stale UDP destinations.
It does not increase queue capacity.

## Verification

- The failing simultaneous-handshake reproducer passes after repair.
- Tests cover known, unknown, and mixed peer hints, delayed cleanup, cancellation, and packet delivery.
- The UDP echo test reuses a socket tuple across peer IDs.
- The fragment test interleaves identical IPv4 fragment IDs from two peers and verifies separate payloads and reply destinations.
- The WSS test holds a TLS socket open without a handshake.
- The WSS test also holds an upgraded socket without a lane record while another two-lane connection completes.
- The serial core suite passed 545 tests.
- The two ignored Caddy tests passed in separate processes.
- Twenty lane tests passed after the final H2 deadline correction.
- Tracker bootstrap connected two nodes without peer URLs and transferred 4 MiB with verified integrity.
- Native macOS, x86_64 Linux, and aarch64 Linux release builds passed.

The initial parallel core run passed 544 tests and failed one shared recovery-quota assertion.
The assertion passed in isolation.
The serial suite then passed.
The evidence supports test interference; the global quota was not increased.

All eleven instances passed executable transfer-integrity checks.
All eleven preserved their instance IDs, public keys, configuration, GUI policy, and MTU settings.
Each instance had authenticated receiving connections on H2, QUIC, and WSS.
The local controller received all 30 fleet ping replies.
The affected router received all 20 replies from the other reachable instances.
Every Web UI returned its page and API without a key from the overlay.
Every Web UI rejected a foreign Origin.

A persistent UDP socket sent 140 datagrams across a local node restart.
Payload sizes were 1559–1561 bytes, which exercised fragmentation.
The local peer ID changed from `3907039432` to `663035031`.
One datagram timed out during restart.
Delivery resumed within approximately 1.8 seconds of the restart command.
All 119 datagrams after the first recovered reply arrived correctly.
The complete run delivered 216,870 payload bytes.
The median RTT was 5.08 ms; the 95th percentile was 21.35 ms.

A continuous 122.24-second fleet log check verified sequence continuity.
It found no listed handshake, TLS EOF, or relay queue errors.
An earlier rollout window still contained one closed-handshake message.
The final observation does not establish long-term availability.

## Throughput checks and limits

The checks used the local native Mac and s6916 at effective MTU 1280.
Each trial used one TCP stream, one second of warmup, and five measured seconds.
Each direction had two trials per stage.
Automatic connection selection remained enabled.
These are delivery checks, not a controlled transport performance comparison.

| Stage | Download Mbit/s | Upload Mbit/s |
| --- | --- | --- |
| Before repair | 414.16, 411.66 | 456.67, 401.13 |
| Early after rollout | 457.46, 460.93 | 250.83, 186.50 |
| Later checks | 474.06, 454.61 | 435.26, 444.22 |

The later upload trials reported zero TCP retransmissions.
The download trials reported 11,647–23,616 TCP retransmissions.
The earlier baseline reported zero.
Connection selection changed after restart, so these results do not establish a performance improvement or an equivalent path comparison.
The cause of the download retransmissions remains unresolved.
Raw iperf logs retain every trial.
Their CPU fields describe iperf processes only.
LowTier CPU per delivered Gbit and RSS were not sampled.

## Deployment recovery and remaining issues

AliBJ's direct upload timed out.
The replacement upload passed through JPaws.
The router's first Web UI check timed out during convergence.
Its repeated complete verification passed.
The local node registry was initially empty after restart.
Process inspection confirmed startup, and the repeated integrity check passed.

Taiwan SSH still times out.
Taiwan retains its pending status and incomplete candidate.
The historical `btower` and `UTMOWRT` hosts remain pending.
No incomplete binary was executed.

Other errors remain outside the repaired paths.
The continuous window contains BTROUTER STUN timeouts and malformed replies, plus one QUIC UDP send error.
It also contains AliBJ–861jp route synchronization timeouts, a peer-center timeout, and two closed-path send errors.
The repair does not establish their causes.

Task-owned fixture listeners are stopped.
Transfer files and superseded installed binaries are removed.
Configuration references and logs remain preserved.
The original s6916 iperf server remains active.

The durable summary is `benchmark-results/handshake-relay-20261115/summary.json`.
Complete commands, raw results, protected snapshots, and audit records are in `benchmark-results/.work/handshake-relay-20261115/`.
