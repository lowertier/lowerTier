# Direct eth0 traversal investigation, 2026-09-21

The direct benchmark must use Hattori `eth0`. The earlier PPPoE measurements do not satisfy this path requirement.

The bounded UDP and TCP traversal attempts exchanged no direct peer payload.
No QUIC, H2, or WSS throughput result exists for this new path.
The tests below measure connectivity and NAT behavior. They do not measure encrypted tunnel performance.

## Required path

- Yutoms source: `172.25.23.12`, interface `en1`.
- Hattori source: `192.168.64.23`, interface `eth0`, gateway `192.168.64.1`.
- Observed Hattori NAT address: `217.178.105.142`.
- Observed yutoms NAT address: `133.1.22.2`.
- Rendezvous host: S6916, `193.32.149.82`.
- Management: SSH through Tailscale.

Both Hattori probe implementations bind the local source address and set `SO_BINDTODEVICE` to `eth0`.
The route lookup confirms that `133.1.22.2` uses `eth0` from the selected source.
The UDP capture shows outbound probe packets on `eth0`.
The rendezvous server exchanges STUN responses only. It does not forward direct probe payloads.

Future throughput acceptance requires a direct peer connection and packet witnesses on this interface.
PPPoE, Tailscale payload encapsulation, and relay payload forwarding must fail that acceptance check.
One successful rendezvous exchange does not establish direct connectivity.

## Observations

The UDP probe retained one socket per endpoint for 30 seconds.
It sent peer probes every 200 milliseconds after exchanging mapped addresses through SSH.
Neither endpoint received a valid direct probe.

| Transport | Endpoint | Mapping to rendezvous port 15478 | Mapping to rendezvous port 15479 |
| --- | --- | --- | --- |
| UDP | Hattori | `217.178.105.142:15482` | `217.178.105.142:15482` |
| UDP | Yutoms | `133.1.22.2:18526` | `133.1.22.2:27808` |
| TCP | Hattori | `217.178.105.142:15483` | `217.178.105.142:15483` |
| TCP | Yutoms | `133.1.22.2:51544` | `133.1.22.2:60606` |

The TCP probe retained both STUN connections and reused the same local port for listening and simultaneous connect.
Its 20-second window included rendezvous coordination. The connection attempts lasted approximately 16 seconds.
Neither endpoint received peer data. The probe did not record a terminal TCP connection state.
The saved records include socket errors and initial nonblocking connect results.
The later TCP capture started too late to establish where the initial SYN packets stopped.
Its zero-packet result is not evidence that no SYN was sent.

The UDP filtering control used a fresh local port, `15484`.
Each phase sent three requests:

| Response path | Hattori responses | Yutoms responses |
| --- | ---: | ---: |
| Same server address and port | 3/3 | 3/3 |
| Same server address, changed source port | 0/3 | 0/3 |
| Second server port, after explicit outbound contact | 3/3 | 3/3 |

Hattori retained external port `15484` in both successful phases.
Yutoms changed its external port from `8561` to `43154`.
The server recorded all 18 responses sent across both endpoints.

The final concurrent capture repeated this control with fresh local port `15487`.
S6916's packet capture recorded nine requests and nine outgoing responses for Hattori.
Three outgoing responses used the changed source port during the middle phase.
Hattori's `eth0` capture recorded all nine requests but only six responses.
The three changed-port responses were absent. The capture reported zero kernel capture drops.
The loss occurs between S6916's egress capture point and Hattori's interface capture point.
The captures do not identify the upstream filtering device.

Yutoms has no global IPv6 address on its active physical interface.
The available interface snapshot does not provide an IPv6 direct alternative.

A separate Tailscale path check returned one DERP response and two S6916 peer-relay responses, at 25–26 ms.
This check does not establish that all Tailscale traversal attempts must fail.

## Interpretation and limits

Yutoms uses destination-port-dependent mappings for the tested UDP and TCP destinations on one rendezvous IP.
Hattori's UDP filtering control is consistent with port-dependent inbound filtering.
The exact upstream device that applies the filter remains unidentified.

These observations explain why exchanging the rendezvous addresses can fail.
Yutoms can receive a different external port when it sends toward Hattori.
Hattori has opened its filter for the rendezvous-observed port, not necessarily that new port.
Neither endpoint then learns the usable peer address from an incoming packet.

These tests do not prove that every NAT traversal technique is impossible.
They do not test broad port prediction, port scanning, PCP, or a configured gateway mapping.
Two read-only NAT-PMP public-address requests to `192.168.64.1:5351` received no response within one second each.
A read-only UPnP gateway discovery request on `eth0` received no response during its four-second window.
Neither discovery check changed a gateway mapping.
Gateway access would help identify the filtering device. It is not required to implement or attempt hole punching.
No gateway settings, firewall policy, production VPN, or NIC offload settings were changed.

## Source findings

`lowertier/src/connector/tcp_hole_punch.rs` contains a TCP traversal coordinator.
Its peer-selection code excludes symmetric TCP NAT initiators.

`lowertier/src/peers/peer_rpc_service.rs` validates `SendUdpHolePunchPacket` requests but sends no packets.
Before this change, no active UDP traversal coordinator was registered in `lowertier/src/instance/instance.rs`.
Therefore, the old configuration flag alone did not provide QUIC hole punching.

## QUIC traversal implementation

`lowertier/src/connector/quic_hole_punch.rs` now provides authenticated QUIC rendezvous.
The existing `disable_udp_hole_punching` flag controls this coordinator.

- An encrypted RPC exchanges up to four IPv4 candidates.
- STUN discovery, peer probes, and QUIC retain the same UDP socket.
- A random 96-bit transaction links probes to their authenticated RPC session.
- Received probes can identify a changed peer source address.
- An activation RPC separates probing from QUIC socket ownership.
- QUIC retains CONNECT-IP admission, Noise authentication, and TLS exporter binding.
- The authenticated tunnel peer must match the rendezvous peer before connection publication.
- Attempts enforce the underlay policy, socket mark, source address, and interface binding.
- Four concurrent attempts, 30-second retry intervals, and bounded timeouts limit resource use.
- Per-peer retries cover interface pairs. Failed interfaces and candidate sends do not cancel other usable choices.

Eleven focused traversal tests pass.
They cover same-network and foreign-relay rendezvous, socket retention, packet loss, changed mappings, peer identity, and underlay denial.
They also cover cancellation during mapping, probing, and QUIC acceptance.
The QUIC transport regression suite reports 31 passing tests.
Optional external integration cases remain subject to their existing environment gates.
The Caddy integration test was not run because the Caddy binary is unavailable.

The restrictive NAT test deliberately reports failure.
STUN candidate exchange cannot discover an unknown peer-facing port when the other endpoint rejects that source port.
This implementation does not add port prediction, broad port scanning, gateway mapping, or IPv6 traversal.
It must not report relay throughput as direct throughput.

A fresh Tailscale check returned DERP and S6916 peer-relay paths, at 26–55 ms.
That check did not force Tailscale to `eth0`. It provides no evidence of a direct Tailscale connection.

Validation receipts reside in `benchmark-results/eth0-punch-20260921/`.
The final focused receipt is `test-quic-punch-final.json`.
The transport receipt is `quic-transport-regression.json`.
Build manifests identify the candidate binaries and changed source hashes.

The probe cost is approximately 4 KB of request payload per full attempt with four candidates.
This estimate uses 20-byte requests, five sends per candidate per second, and a 10-second window.
It excludes IP/UDP headers, STUN discovery, responses, and any subsequent QUIC handshake.
Probing stops before application traffic starts. No throughput or CPU improvement is claimed from this implementation.

The first hardware run failed before rendezvous.
Yutoms rejected the relay administrator certificate with `Expired`; Hattori connected successfully.
The validator uses the same error for `issued_unix > now` and actual expiry.
Measured clocks differed by fractions of a second, while administrator certificates have a 60-second lifetime.
The evidence points to a whole-second issuance boundary during repeated connection attempts.
Staggered test-process startup restored both authenticated relay connections in the second run.
No host clock or certificate validation policy changed.
The first run remains separate under the `fixture-*` receipts.
The second run uses `fixture2-*` receipts.

## Final hardware result

The second run established both authenticated H2 connections to the rendezvous relay.
The peers discovered each other and invoked the new QUIC rendezvous RPC.
Eight samples, spaced approximately 10 seconds apart, showed `relay(2)` on both hosts.
No sample or tunnel log showed a direct QUIC connection.

Two peer-probe sessions completed and timed out at both endpoints.
An intermediate preparation request hit the server retry limit before peer probing began.
Hattori mapped three sockets; yutoms mapped two corresponding peer-probe sockets.

| Attempt | Hattori local socket | Hattori mapped endpoint | Yutoms STUN candidates |
| --- | --- | --- | --- |
| First completed probe | `192.168.64.23:43149` | `217.178.105.142:43149` | `133.1.22.2:29348`, `133.1.22.2:45181` |
| Second completed probe | `192.168.64.23:53185` | `217.178.105.142:53185` | `133.1.22.2:47112`, `133.1.22.2:35578` |

The capture recorded 204 outbound peer probes from those sockets, all on `eth0`.
It recorded no matching inbound peer packets and no kernel capture drops.
The capture also contained 432 unrelated packets, including production traffic on PPPoE.
The analysis excluded those packets by matching the test socket addresses from the traversal logs.
The capture ended at its configured limit with exit code 124.

No application throughput test ran because a direct tunnel was not established.
Direct QUIC, H2, and WSS throughput on this required path remains unmeasured.
The earlier PPPoE results and relay results remain separate comparisons.

The implemented rendezvous removes the missing-software blocker.
The observed port-dependent NAT behavior still prevents these direct attempts.
This result does not prove that every possible traversal method must fail.
It also does not establish direct Tailscale connectivity through `eth0`.

The complete summary is `benchmark-results/eth0-punch-20260921/fixture2-summary.json`.
Per-host traversal logs are `fixture2-hattori-traversal.log` and `fixture2-yutoms-traversal.log` in the same directory.
Both final endpoint binaries used the same seven-file source manifest.
The relay used the preserved x86-64 release binary and forwarded rendezvous traffic only.
This investigation has not implemented that missing coordinator.

## Failures and recovery

- The first Hattori command lacked `hostname`. Reading `/proc/sys/kernel/hostname` verified the host.
- The first UDP attempt read an incomplete destination file. Atomic file publication fixed the race.
- The second UDP attempt completed normally. Both endpoints recorded zero direct packets.
- A guessed QUIC source path did not exist. File discovery located the endpoint manager inside `quic.rs`.
- The TCP capture reached its timeout. The partial capture remains saved and does not support a SYN-loss claim.
- Hattori lacked `ss`. Process and socket checks used `/proc` instead.
- The local host had no `bridge100` interface. It was not identified as Hattori's gateway.
- S6916 lacked `tcpdump`. The final capture used a bounded `AF_PACKET` socket on `eth0`.
- The first raw capture selected IPv4 ingress only. The final capture used `ETH_P_ALL` and recorded outgoing replies.
- Optional gateway CLI tools were absent. The read-only NAT-PMP query used the request format from the installed dependency.

## Artifacts

Raw receipts and executable probes are in `benchmark-results/eth0-punch-20260921/`.
The audit log is `benchmark-results/.work/eth0-punch-20260921.jsonl`.
The `r2-udp-probe-*`, `tcp-probe-*`, and `filter-client-*` receipts retain the completed results.
The first failed UDP attempt remains separate from the corrected attempt.
The final concurrent packet evidence uses the `filter4-*` receipts.

No source implementation or production service changed during these diagnostics.
All probe processes ended. Final process checks cover both endpoints and the rendezvous server.
The temporary probe proof files were removed after testing. Scripts and raw receipts remain available.
