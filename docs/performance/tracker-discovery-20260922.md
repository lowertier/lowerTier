# Tracker discovery and peer joins, 2026-09-22

Tracker discovery authenticated osku, Hattori, yutomac, and UTMOWRT without configured peer URLs.
Build v11 verified direct QUIC delivery from Hattori to all three clients through public UDP and private HTTPS discovery.
All four nodes also joined with H2 and WSS through HTTPS discovery.
Osku–Hattori and yutomac–Hattori still used relays for H2 and WSS.
UTMOWRT–Hattori used direct connections for all three transports, but its TCP payload transfers remained slow.
The later v16 check verified direct H2 and WSS delivery from Hattori to all three clients.
Hattori IPv4 TCP segmentation offload was temporarily disabled and then restored.
The v16 logs also exposed file-descriptor exhaustion on yutomac. The subsequent resource fix passed focused checks but has not been deployed.
These results establish functionality, not reliable low-latency punching or sustained throughput.
A separate H2 diagnostic later exposed a persistent relay-recovery failure between Hattori and UTMOWRT.

## Implementation

LowTier now supports BEP 15 UDP trackers and compact HTTP/HTTPS trackers.
The `lowertier-tracker` binary provides a self-hosted UDP and HTTP service.
HTTPS can terminate at a reverse proxy. The tracker accepts client IP headers only from configured trusted proxies.
Tracker responses disable caching. HTTPS clients verify certificates and hostnames.

The client races independent trackers with STUN.
It treats returned endpoints as untrusted candidates.
Transport authentication, TLS exporter binding, Noise authentication, and same-network admission remain required.
The rendezvous hash uses HMAC and separates QUIC, H2, and WSS namespaces.
Existing encrypted membership and rendezvous RPCs provide peer-assisted discovery and punching after bootstrap.
DHT is not implemented.

QUIC shares the discovery socket with authenticated punching and punched connections.
Duplicate tracker responses retain the active nonce.
Probe tasks and connection attempts have separate bounds.
When bootstrap has no peer, a standard QUIC fallback uses a fresh port on the selected local address.
This path preserves the network namespace and underlay policy.
H2 and WSS advertise their TCP STUN mapping and retain the reserved source port.

Configuration and deployment instructions are in [Tracker discovery](../tracker-discovery.md).

## Fixture and interpretation

The isolated network contained osku, Hattori OpenWrt, yutomac, UTMOWRT, and a reachable Linux seed.
Every client configuration had an empty listener list and no configured peer URLs.
The final matrix uses a distinct network name for each transport, tracker mode, and build revision.
This separates new joins from stale entries created by earlier diagnostics.
Management SSH used Tailscale. Test data used LowTier.
The configured VPN MTU was 1280 bytes. Linux TAP interfaces reported 1260 bytes.
Osku and yutomac used userspace networking and a loopback SOCKS proxy.
UTMOWRT used its kernel network stack through the test TAP interface.
Hattori's permitted test path used `eth0` and public address `217.178.105.142`.
The fixture excluded its PPP path by address policy.
Production code discovers source addresses and interface indices dynamically.

The seed used `193.32.149.82:16969`.
The private HTTPS tracker used a reverse proxy on port 16975 and an origin on loopback port 16973.
A temporary test CA was supplied only to fixture processes.
The tests did not install a system CA or deploy an actual CDN provider.

All seven UDP trackers supplied by the user returned valid BEP 15 responses.
Public trackers can return stale or unrelated endpoints. Their replies never authorize membership.
The client respects each tracker interval and retries cached candidates locally.

## Validation

Eight focused tracker tests passed.
They cover UDP and HTTP bootstrap for all three transports without peer URLs, foreign-network rejection, and bounded wire parsing.
They also cover mixed UDP receive batches, duplicate PUNCH nonces, and standard QUIC fallback without PUNCH replies.
The fallback regression verifies the selected source IP and a different source port.
Existing focused TCP and QUIC traversal tests passed.
The Caddy H2/WSS and QUIC regression checks passed.
Proxy checks verified trusted headers, rejection of invalid headers, rate limits, and cache controls.

Native macOS and Linux ARM64/x86-64 release builds use source manifests and binary hashes.
The earlier matrix used build v8 from the same source manifest.
The eight tracker tests include the final global handshake limit.
The traversal and Caddy checks preceded that limit change; their production paths did not change afterward.

## Build v11 live results

All five fixture hosts used matching v11 core binaries.
The native, ARM64, and x86-64 manifests contain identical hashes for 732 source files.
The seed tracker and copied core binaries passed SHA-256 checks.
CLI hashes are recorded separately; the CLI executables were not rebuilt as part of v11.
All ten focused tracker tests passed before these builds.

First authentication measures the interval from each host's `CORE: Starting` message to its first tracker-authenticated VPN peer.
Each value represents one startup. It is separate from complete-membership polling and direct-path establishment.

| Transport and tracker | Osku | Hattori | Yutomac | UTMOWRT |
| --- | ---: | ---: | ---: | ---: |
| QUIC, public UDP | 1.559 s | 0.766 s | 1.636 s | 1.265 s |
| QUIC, private HTTPS | 0.468 s | 0.284 s | 0.441 s | 0.251 s |
| H2, private HTTPS | 0.505 s | 0.278 s | 0.512 s | 0.243 s |
| WSS, private HTTPS | 0.444 s | 0.253 s | 0.654 s | 0.252 s |

All seven configured public trackers produced successful announce responses somewhere in the public run.
The logs contain 4–7 successful announcements per tracker across fixture sockets.
This does not establish that every tracker succeeded from every interface.
The seed remained an authenticated VPN peer; this was not a tracker-only infrastructure test without a reachable peer.

Direct QUIC routes to Hattori appeared within the following polling upper bounds:

| Tracker mode | Osku | Yutomac | UTMOWRT |
| --- | ---: | ---: | ---: |
| Public UDP | 43.265 s | 7.706 s | 7.919 s |
| Private HTTPS | 11.660 s | 45.452 s | 7.745 s |

Each of the six QUIC transfers delivered one MiB with the expected hash.
Both endpoints selected direct routes before and after each transfer.
Authenticated connection IDs remained stable, and reciprocal connection counters covered the payload volume.
The measured endpoint tuples also matched both hosts' hole-punch logs.
Hattori used local address `192.168.64.23` on its Ethernet interface and public address `217.178.105.142`.
These snapshots do not prove continuous route selection between observations.
Connection counters include headers and control traffic.

| Transport and tracker | Osku delivery | Yutomac delivery | UTMOWRT delivery |
| --- | ---: | ---: | ---: |
| QUIC, public UDP | Direct, 0.131497 s | Direct, 0.160852 s | Direct, 0.540749 s* |
| QUIC, private HTTPS | Direct, 0.086133 s | Direct, 0.360149 s | Direct, 0.551255 s* |
| H2, private HTTPS | Relay, 34.147681 s | Relay, 32.666096 s | Direct, 41.679671 s* |
| WSS, private HTTPS | Relay, 34.159113 s | Relay, 42.994618 s | Direct, 42.990235 s* |

All twelve transfers passed the one-MiB integrity check.
Osku and yutomac times come from curl's transfer timer.
Values marked `*` include SSH and Node.js process overhead; they are not directly comparable with curl times.
Each v11 transfer had a 90-second deadline.
H2 and WSS did not establish direct osku–Hattori or yutomac–Hattori routes within the 240-second observation window.
Those failed direct-path conditions remain unresolved despite successful relay delivery.

The saved H2 logs show different public TCP ports for the two STUN destinations on osku and yutomac.
For example, osku's `172.25.3.108:54852` socket advertised `133.1.22.2:21308` and `133.1.22.2:14234`.
Yutomac's `172.25.23.12:64117` socket advertised `133.1.22.2:30479` and `133.1.22.2:42752`.
Hattori's `192.168.64.23:39487` socket advertised one public endpoint, `217.178.105.142:39487`.
These observations establish destination-dependent TCP mappings for those macOS sockets.
They do not reveal the mappings used toward Hattori or prove where each SYN was lost.
The v11 TCP coordinator tried observed endpoints and private candidates. It did not search unobserved external ports.
This mapping mismatch remains a separate traversal constraint from the relay recovery defects.

The STUN log recorded no source-rate-limit rejection during this matrix.
The fixture intentionally rejected unsupported STUN CHANGE-REQUEST flags.
Its original log does not count rejected TCP sessions at the separate 32-session limit.
The separate diagnostic below checks that limit and outer TCP retransmissions.

Hattori's Ethernet interface had a global IPv6 address, but osku's physical interfaces had only link-local IPv6 addresses.
Thus this fixture had no native IPv6 alternative for osku–Hattori.
Read-only gateway discovery sent no port-mapping request.
NAT-PMP and PCP queries to `192.168.64.1:5351` returned `Connection refused`; UPnP discovery received no response within three seconds.
These observations do not establish the cause of the TCP traversal failure.

The matrix and cleanup completed without execution errors.
The complete v11 receipts are under `v11-live/`; `reduced.json` records bootstrap times and source receipt hashes.
The four failed TCP direct-path conditions are results, not execution errors.
The earlier v8 failures and late recovery remain below as separate evidence.

## Separate v11 TCP diagnostic

This run used the same v11 binaries with additional logging and read-only socket inspection.
All four nodes joined. No client established a direct Hattori route within 240 seconds.
Osku and yutomac received the complete one-MiB payload through relays in 47.329945 and 36.503019 seconds.
UTMOWRT received zero payload bytes before its 90-second deadline.
This failure remains separate from its successful direct transfers in the preceding matrix.

The STUN service admitted 128 TCP handlers and reached a peak of 26 concurrent handlers.
It rejected no session at its unchanged 32-handler limit and logged no source-rate rejection.
These observations exclude the fixture limits as the cause of this run's failure.
Handler closure does not establish when the kernel finished closing its TCP connection.

Hattori and UTMOWRT logged reciprocal full secure relay queues for more than four minutes.
UTMOWRT also logged four early `relay responder handshake is busy` errors.
Source inspection found that both send paths return from the non-ready queue branch before calling `ensure_session`.
After a failed handshake leaves `AwaitingSession`, later packets fill the queue without restarting authentication.
The logs support this persistent recovery failure but do not identify its initial handshake transition.
A focused three-peer regression filled the queue and sent one more packet.
The original implementation failed to authenticate within the regression deadline.
The correction calls `ensure_session` for `AwaitingSession` before queue admission can reject that packet.
The corrected regression passed for both scalar and batch sends without increasing queue limits.
The live v11 binaries do not contain this correction.
Review also identified stale confirmation cleanup that can overwrite a replacement handshake's phase.
The correction checks confirmation identity and changes the phase under one queue lock.
A READY timeout now restores retry eligibility while preserving the durable recovery reservation.
A late ACK must pass the current confirmation owner check before it can resume that reservation.
Queue closure retains in-flight memory credit until the sender completes or drops its batch.
Each batch now requeues its packets on cancellation, preventing an abandoned in-flight count from blocking subsequent drains.
Four recovery tests passed, including the previously failing timeout and closure tests.
The final critical integration suite passed all 69 tests in 30.52 seconds, with no failures or ignored tests.
It covers the five relay regressions, session recovery, tracker bootstrap, and authenticated TCP and QUIC traversal.
The native v12 release build completed.
The user then requested more source-derived fixes and fewer tests.
The automatic live matrix and superseded Linux builds stopped before further source changes.
No v12 live result is claimed.

The 200-sample Hattori trace also recorded 1,794 additional retransmitted outer TCP segments to the seed.
Samples covered 199.751 seconds, including both successful relayed payloads.
The negotiated send MSS stayed at 1,408 bytes. The sampled congestion window ranged from 1 to 19 segments.
Inner TCP sockets also retransmitted data.
These socket counters establish retransmission, not a packet-loss percentage.
They do not measure the preceding matrix's direct Hattori–UTMOWRT flow.

A separate raw TCP test sent one MiB from Hattori's Ethernet source to the seed, without LowTier.
The test changed `TCP_MAXSEG` only on temporary sockets. It kept the host network settings unchanged.
The default/limited/limited/default sequence produced these results:

| Trial | Requested maximum segment size | Actual send MSS | Receiver time | Sender retransmitted segments |
| --- | ---: | ---: | ---: | ---: |
| 1 | Default | 1,408 B | 22.174576 s | 682 |
| 2 | 1,200 B | 1,188 B | 26.621446 s | 860 |
| 3 | 1,200 B | 1,188 B | 26.204424 s | 798 |
| 4 | Default | 1,408 B | 23.063445 s | 398 |

All four raw transfers passed the payload hash check.
Smaller TCP segments did not remove the slow delivery or retransmissions.
The evidence does not support a packet-size workaround for this path.
The underlying loss location remains unknown.
Both diagnostic fixtures stopped their processes and completed cleanup.
Their receipts are under `v11-tcp-diagnostic/`, `v11-tcp-inner-and-outer-hattori.json`, and `v11-mss-*.json`.

## Hattori TCP segmentation offload diagnostic

A later raw TCP diagnostic captured the test flow at Hattori and the seed.
Both packet sockets reported zero dropped capture records.
Hattori transmitted repeated byte ranges totaling 1,109,504; 917,136; 836,352; and 1,286,912 bytes across four trials.
Each total exactly matched the sender's TCP retransmission count multiplied by its MSS.
The seed received each payload byte once.
Every distinct cumulative ACK value from the seed also appeared at Hattori.
This does not establish that every individual ACK packet arrived.

TCP timestamp and sequence matching attributed every delivered byte to sender records no larger than one MSS.
No delivered byte matched a sender record larger than one MSS.
Large sender capture records are normal before device segmentation; their size alone does not prove an oversized wire packet.
Linux documents this distinction in its [segmentation offload documentation](https://docs.kernel.org/networking/segmentation-offloads.html).
Hattori used the `virtio_net` driver with IPv4 TCP segmentation offload enabled.

The next diagnostic disabled only `tx-tcp-segmentation` on the interface resolved from `192.168.64.23`.
It then restored the original feature set and repeated the control.
Each row used a complete one-MiB payload with a verified hash.

| Trial | Actual MSS | TSO on, captured baseline | Retransmissions | TSO off | Retransmissions | TSO restored | Retransmissions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 1408 | 24.964 s | 788 | 0.088 s | 0 | 23.844 s | 744 |
| 1 | 1188 | 26.875 s | 772 | 0.100 s | 0 | 24.650 s | 814 |
| 2 | 1188 | 24.352 s | 704 | 0.080 s | 2 | 24.365 s | 458 |
| 3 | 1408 | 25.560 s | 914 | 0.080 s | 0 | 21.048 s | 634 |

Times come from the raw receiver. They are short transfer measurements, not sustained capacity measurements.
The baseline had packet capture enabled; the offload intervention and restored control did not.
The restored control reproduced the failure without capture, excluding capture as its cause.
The experiment identifies an IPv4 TSO-dependent failure on this virtualized path.
It does not identify the defective driver, virtual switch, NAT, or upstream component.
The diagnostic restored the complete original feature output and stopped its processes.
Production LowTier does not change NIC offload settings.

The prepared v12 fixture supports temporary disablement and verified restoration of this feature.
That fixture has not run.
The first capture attempt lacked `tcpdump` on the seed.
The initial Python capture recorded ingress only; its reducer rejected the incomplete evidence.
The corrected capture includes ingress and egress and remains separate under `v12-raw3-*`.
The intervention and restored control receipts are under `v12-tso-*`.

## Subsequent discovery fixes

Source inspection found that automatic H2/WSS bootstrap mappings never refreshed after startup.
The client now refreshes retained TCP STUN sessions and reacquires failed sessions from the reserved source port.
It withdraws an unavailable mapping from new announcements until recovery succeeds.
Mapped listeners remain open while valid and change with the advertised local public port.
Existing VPN sessions do not depend on the discovery listener's lifetime.

Tracker retries also selected the first DNS address repeatedly.
UDP and HTTP/HTTPS retries now advance through sorted, deduplicated permitted addresses.
Sorting prevents changing DNS answer order from repeatedly selecting the same failed endpoint.
Independent review checked mapping ownership, listener replacement, policy checks, and address selection.
All four focused checks passed in 2.39 seconds, with no failures or ignored tests.
They cover retained STUN refresh and expiry, mapped-listener replacement, bootstrap for all transports, and authenticated H2/WSS punching.
No diagnostic sweep or live matrix was repeated for this additional change.
These latest source fixes have not been deployed to the four live hosts.

## Earlier v8 QUIC results

Join time measures process startup to the first tracker-discovered, authenticated VPN peer.
It excludes the later work that establishes a direct connection to every member.
Each row represents one startup per node, not an average.

| Tracker mode | Osku join | Hattori join | Yutomac join | UTMOWRT join |
| --- | ---: | ---: | ---: | ---: |
| Seven public UDP trackers | 61.744 s | 0.788 s | 1.729 s | 0.508 s |
| Private HTTPS tracker | 1.255 s | 74.038 s | 1.184 s | 0.229 s |

Both initial QUIC direct-path gates failed for osku–Hattori.
No payload was measured during either failed gate.
The HTTPS processes continued running after the deadline.
Osku logged its direct Hattori connection 197.788 seconds after startup.
Nodes started in stages; this is not a simultaneous-start measurement.
A later check verified a direct selected route before and after the file transfer.
The same QUIC connection ID remained present across both snapshots.
The one-MiB transfer completed in 0.302898 seconds with the expected SHA-256 hash.
The direct connection received 1,097,529 bytes across those snapshots.
Osku's seed, UTMOWRT, and yutomac connections showed no byte increase during that interval.
The transfer time excludes discovery and connection setup.
This late success does not replace the failed deadline result.

Hattori also formed direct QUIC connections with yutomac and UTMOWRT during the HTTPS run.
Those two connections later disappeared; their direct file delivery was not verified on build v8.
Both nodes retained membership through other peers.
Earlier v7 HTTPS checks verified direct one-MiB delivery from all three clients to Hattori.
Those earlier results remain separate from v8.

Hattori logged STUN response timeouts during the failed punching period.
Its discovery socket still received mapped-address responses.
Later punch sockets received mappings and established direct connections.
The current error text, `no allowed IPv4 source for QUIC hole punching`, also covers exhausted STUN attempts.
It does not prove that the host lacked a permitted interface.
The saved service log records successful responses, so it cannot distinguish every network loss from a server-side rate rejection.
The cause of each missing response remains unresolved.

## Earlier v8 H2 and WSS results

All four nodes authenticated through the private HTTPS tracker and learned the complete five-node membership set.

| Transport | Osku join | Hattori join | Yutomac join | UTMOWRT join |
| --- | ---: | ---: | ---: | ---: |
| H2 | 0.542 s | 0.267 s | 0.447 s | 0.258 s |
| WSS | 0.545 s | 0.267 s | 0.440 s | 0.248 s |

Osku–Hattori had no direct H2 or WSS connection in the before/after transfer snapshots.
Their selected route used a relay.
UTMOWRT had direct H2 and WSS connections to both osku and Hattori.
Yutomac joined successfully and had direct connections to osku and UTMOWRT.
These checks do not establish direct TCP traversal between osku and Hattori's two NATs.

| Transport | Osku–Hattori path | Delivered payload | Transfer time | Integrity |
| --- | --- | ---: | ---: | --- |
| QUIC, late recovery | Direct | 1 MiB | 0.302898 s | SHA-256 passed |
| H2 | Relay | 1 MiB | 40.195791 s | SHA-256 passed |
| WSS | Relay | 1 MiB | 28.770269 s | SHA-256 passed |

Each transfer delivered the complete requested payload.
These paths differ, so the table does not compare transport capacity under matched conditions.
Final per-transfer packet loss and retransmission counters were not collected.
The earlier TCP captures show retransmission but do not quantify loss in these final transfers.

## Earlier failures and recovery

Public and HTTPS trackers returned candidates to osku, but shared-socket QUIC bootstrap timed out in intermediate builds.
A separate ordinary QUIC connection immediately authenticated and enabled direct osku–Hattori punching.
The fresh-port fallback uses that working connection path without adding a configured peer URL.
The evidence does not identify which network component rejected the original discovery flow.
The v7 macOS diagnostic then authenticated through the tracker-selected seed in 36.083 seconds.
It established direct osku–Hattori QUIC at 45.522 seconds after startup.
That diagnostic used old Linux builds and a tracker namespace containing stale fixture entries.
It remains separate from the final matched-build checks.

Repeated tracker results also replaced an active PUNCH nonce.
A regression test reproduced that defect before the fix.
The corrected code retains the nonce for the active probe period.

The v7 public-tracker run exposed a second defect.
Two source interfaces could each start eight QUIC connections, with a four-MiB reservation for each connection.
Those reservations could consume the entire 64-MiB process budget before authentication packets could be queued.
A regression test reproduced the memory rejection and failed authentication.
The fix shares four speculative QUIC handshake permits across the process.
This caps their fixed reservations at 16 MiB without increasing the global budget.
Queued attempts recheck membership and release their permit after authentication or cancellation.
Silent candidates can occupy all four slots for their handshake deadlines and delay a useful candidate.
The implementation bounds resource use; it does not yet bound join latency independently of candidate quality.
This cap does not reserve memory against all established and inbound traffic.
The v8 macOS diagnostic then authenticated through public trackers in 1.732 seconds.
It established direct osku–Hattori QUIC in 7.392 seconds.
That diagnostic retained v7 Linux binaries and remains separate from matched-build results.

Plain HTTP full announcements from osku timed out with both LowTier and an independent HTTP client.
HTTPS announcements through the same test host succeeded.
Local HTTP bootstrap passed for QUIC, H2, and WSS.
The external plain HTTP failure remains a recorded path limitation.

Earlier H2 and WSS joins succeeded through public UDP and private HTTPS trackers.
Osku–Hattori used a relay for these transports.
UTMOWRT established direct H2 and WSS connections to both hosts.
The original 30-second file-transfer failures remain failures.
Separate 90-second integrity checks completed one MiB through HTTPS-discovered H2 in 40.726 seconds and WSS in 40.053 seconds.
Those results used build v3 and are not matched measurements of the final build.

An ordinary TCP transfer from Hattori to the seed took 24.045 seconds for one MiB without LowTier.
Packet captures also showed TCP retransmissions.
This establishes a slow underlying TCP path. It does not explain the entire VPN delay because the routes differ.

Some packet-capture commands timed out. Process checks confirmed cleanup, and replacement captures completed.
Obsolete release builds were cancelled before source changes. Their logs remain separate from successful builds.
The ARM build wrapper reached its timeout after waiting for the shared Cargo lock.
Its compiler continued under Cargo. The recovery preserved that running compilation.
Cargo completed the ARM build. A cache-only rerun returned success and produced its verified manifest.

## Pending-fallback correction after the recorded live runs

A fresh-port fallback marked its candidate as recent before its connection completed.
The 30-second duplicate filter then discarded a later valid PUNCH reply for that endpoint.
The correction sends the authenticated peer identity to the pending attempt.
That attempt cancels its fresh flow and connects through the original mapped discovery socket.
It retains the existing handshake permit, timeout, and VPN identity checks.
A queued attempt consumes an available upgrade before checking whether another peer has already connected.
Completed upgrade channels are removed before they can be polled again.

The regression fixture rejects the fresh source port and then sends a valid reply to the original challenge.
The corrected implementation authenticates through the original socket.
The first patched test authenticated both peers but used a status method that excludes hole-punched connections.
The corrected assertion checks the direct peer map, as the existing traversal tests do.
A separate test covers reply delivery and sender closure while the handshake waits for a permit.
All ten focused tracker tests passed in `tracker-late-punch-final-suite.json` under the ZeroTier-goal evidence directory.
The final source hash is recorded in `tracker-late-punch-source.json` there.

This correction is absent from the v8 live results above and the v9 throughput measurements.
The matching v11 builds and live matrix above include the correction.
The correction does not establish the cause of every earlier join delay or STUN timeout.

## Limits

These checks establish discovery, authentication, path selection, and file integrity.
They are not a matched throughput or CPU comparison with Tailscale or ZeroTier.
Later native osku–UTMOWRT measurements cover direct QUIC, H2, and WSS in
[Native transport results](zerotier-native-20260922.md).
Those measurements use a separate fixture with effective MTU 1280 and retain their own path and comparison limits.
CPU per delivered Gbit and RSS were not sampled in this fixture.
One-MiB transfer times are short functional checks, not sustained link-capacity measurements.
Each recorded phase contains one transfer per listed client.
The earlier v8 QUIC checks used a 30-second deadline.
The v11 checks and earlier H2/WSS full-delivery checks used a 90-second deadline.
Every successful transfer matched SHA-256 `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`.
The payload contains 4096 repetitions of byte values 0 through 255.

A tracker cannot guarantee initial reachability through every NAT.
A reachable same-network seed remains necessary when no advertised peer accepts initial traffic.
The initial implementation selects IPv4 interfaces automatically and uses one permitted DNS address per tracker.
The measured v11 build kept TCP bootstrap mappings fixed until the discovery path restarted.
The later source changes add mapping refresh, mapping withdrawal, and tracker DNS failover.
The connected QUIC fallback requires reconnection if its remote endpoint changes.

## v14 source fixes and focused checks

Tracker tasks now copy valid mappings while holding the watch read lock.
Concurrent mapping withdrawal could previously occur between the validity check and the second read, causing a panic.
UDP and HTTP tracker DNS now resolves on a blocking worker inside the selected network namespace.
Namespace entry and restoration use the same thread; neither operation spans an asynchronous wait.
The bootstrap integration check uses `localhost` tracker names to exercise this resolver for both tracker protocols.

Runtime protobuf descriptors now omit source comments and locations after code generation.
Generated documentation and schema data remain available.
The runtime descriptor is 28,101 bytes, down from 77,778 bytes.
This matches the input from the earlier allocation experiment; it does not measure production RSS.

Three focused checks passed in 0.95 seconds:
descriptor equality except source metadata, configuration serialization, and UDP/HTTP bootstrap with QUIC, H2, and WSS.
The initial configuration check also passed before the discovery changes.
Receipts are `v14-final-focused.json`, `v14-descriptor-config-focused.json`, and `v14-descriptor-artifact.json`.
Source review found no blocking defect.
A non-default Linux namespace remains untested.
Matching native, Linux ARM64, and Linux x86-64 releases completed and were deployed for the H2 check below.

## v14 H2 check

All four clients authenticated through the private HTTPS tracker without configured peer URLs.
Their first authenticated bootstrap times were 0.574 seconds for osku, 0.252 for Hattori, 62.506 for yutomac, and 0.250 for UTMOWRT.
The cause of yutomac's bootstrap delay remains unresolved.
UTMOWRT–Hattori became direct within 8.916 seconds of observation.
Neither Mac–Hattori path became direct within the 240-second observation window.

Each client received one 1,048,576-byte payload from Hattori with the expected SHA-256 hash.

| Client | Selected path | Transfer measurement |
| --- | --- | ---: |
| osku | Relay | 0.310462 seconds, curl |
| yutomac | Relay | 0.355413 seconds, curl |
| UTMOWRT | Direct | 0.643506 seconds, command wall time |

UTMOWRT's time includes SSH and Node startup. It is not directly comparable with the curl times.
Reciprocal authenticated UTMOWRT–Hattori connection identifiers remained unchanged across the transfer snapshots.
Their counter increases were 1,111,557 received bytes and 1,115,049 sent bytes, including control traffic.
These snapshots do not prove continuous routing between samples.

The fixture temporarily disabled only Hattori's IPv4 `tx-tcp-segmentation` feature.
It selected the interface from its local address and restored the complete original feature state after the check.
The check combined software changes with this temporary condition; it does not isolate their individual effects.
It did not measure sustained throughput, CPU, or RSS, and it did not repeat QUIC or WSS.

Hattori's capture contains 260 outgoing SYN packets to the Macs' shared public address and no incoming packets matching the SYN/reset filter.
Tcpdump reported zero kernel capture drops.
The capture does not establish Mac transmission, external translated ports, or the device responsible for loss.
TCP STUN logs still show destination-dependent mappings on both Macs and port-preserving mappings on Hattori.
The STUN service admitted and closed 72 handlers, with 22 concurrent handlers at peak and no admission rejection.
One source-rate-limit event was logged for UDP. This log does not exclude later rejected packets in the same logging interval.

Bootstrap, payload integrity, cleanup, and host restoration gates passed. The direct-delivery gate failed.
The runner returned exit code 1 for that failed gate, without a fixture error.
All fixture processes stopped, and private fixture files were removed.
Evidence resides in `v14-live/summary.json`, `v14-live/reduced.json`, and the 327 numbered command receipts in that directory.
The capture reduction is `v14-syn-summary.json`. All three build manifests contain the same 732 source paths.

## TCP recovery changes after v14

Source analysis found two independent retry defects.
TCP punching cancelled each pending connection after three seconds, inside a 20-second traversal attempt.
That cancellation discarded the kernel's pending SYN state before the traversal deadline.
Pending connections now retain that state for the traversal attempt.
Each candidate retries independently after an error, so one pending candidate cannot stop another candidate's retry.
The bounds remain four candidates, four transport handshakes, and a 20-second traversal deadline per attempt.
New connections recheck both local and remote underlay policy.

TCP tracker bootstrap previously reused its reserved source port after every failed connection or VPN handshake.
A failed flow can leave TCP or NAT state associated with that tuple.
Bootstrap now tries one fresh source port on the same permitted local address after such a failure.
Both sequential attempts share the existing 15-second deadline and retain transport and VPN authentication.
The advertised listener and retained STUN connections remain available.

Four focused checks passed in 1.99 seconds in `v15-tcp-recovery-focused.json`.
They cover fresh-port recovery, authenticated relay rendezvous, H2/WSS transport binding and payload, and UDP/HTTP tracker bootstrap.
Review found that the initial recovery fixture could fail before VPN authentication started.
The strengthened fixture reads `NoiseHandshakeMsg1` before it closes the first tunnel.
That regression passed in 0.53 seconds in `v15-tcp-auth-recovery-final.json`.
No live test matrix or benchmark was repeated.

These changes do not discover peer-specific ports assigned by a destination-dependent TCP NAT.
They do not establish the cause of yutomac's v14 bootstrap delay or resolve the failed Mac–Hattori direct-path gates.
They have not been deployed to the remote fixture hosts.
TCP traversal depends on NAT handling of simultaneous open and early errors, as described in
[RFC 5382, sections 4.2–4.3](https://www.rfc-editor.org/rfc/rfc5382#section-4.2).

## v16 TCP port-search implementation

The v14 evidence shows varying TCP mappings on both Macs and port-preserving mappings on Hattori.
Trying only STUN endpoints cannot identify a different port allocated for the peer destination.
The v16 source adds optional, authenticated RPC fields to negotiate a socket pool and port search when one side has varying mappings.
Both peers must opt in. Old peers keep the existing candidate-only behavior.
The variable side opens 128 source-port listeners and connects toward the stable peer.
The stable side searches the variable peer's public address from its reserved local port.
H2 and WSS retain native TCP, TLS exporter binding, rendezvous nomination, and VPN authentication.

One process-wide permit limits expanded traversal.
The pool owns at most 128 listeners and 128 pending outgoing connections.
The search owns at most 128 pending outgoing connections.
The ordinary candidate attempts, four transport-handshake slots, and four-stream handoff queue remain separately bounded.
Pool accept futures run in the traversal task, which avoids 128 separate accept tasks and their completed-result queues.
Connection workers retain shared permit ownership until they release their sockets.
The prepared listener owner drops its listeners before it releases its permit.

The shuffled search list contains at most 4096 ports.
Eight-millisecond pacing, an eight-second connection timeout, and a 28-second traversal deadline limit actual work further.
With silent drops, approximately four waves of 128 connections can start before the deadline.
This is not a guarantee of 4096 tested ports or successful traversal.
Kernel TCP memory depends on the platform. No new peak-memory or CPU measurement is available.
The retained port list uses 8192 payload bytes; its initial shuffle temporarily uses 131070 payload bytes.
Task state, vector capacity, allocator overhead, TCP socket state, and listener queues add memory beyond those payload sizes.

The initial focused command failed compilation because the shared test context function was private to a sibling module.
The helper now has parent-module visibility. The failed receipt is `v16-tcp-search-focused.json`.
The final focused command is recorded separately in `v16-tcp-search-final.json`.
That command passed three checks but failed the cancellation check.
The cancellation fixture assumed that its first poll had already spawned a worker.
The timer can yield before that event, so the fixture now waits for a worker's shared permit ownership before cancellation.
The corrected cancellation check is recorded separately in `v16-tcp-cancel-final.json`.
It passed in 1.28 seconds. All four selected checks now pass.
The new checks cover native H2/WSS delivery through an unadvertised pool port and permit retention during cancellation.
Existing checks cover authenticated relay rendezvous and rejection of a different nomination token.
The loopback fixture does not emulate NAT or prove Internet traversal.
The matching v16 builds were deployed to all five fixture hosts. The results follow below.

The v16 fixture now attempts each cleanup stage independently.
A failed core stop or log read cannot skip the remaining process stops or private-file removal.
Cancellation waits for a command boundary, so startup can record process ownership before cleanup begins.
The fixture supervisor allows 900 seconds for cleanup after its 1800-second execution deadline.
Forced termination records cleanup as unverified.
Two local fixture checks passed. They used injected cleanup failures and a child process that records graceful shutdown.
These checks made no remote calls.
The final receipt is `v16-cleanup-cancellation-check.json`.
The original waiting runner stopped with exit 143 before deployment. Release builds continued without interruption.
The replacement runner uses the corrected cleanup and supervisor.

## v16 direct H2 and WSS results

All four clients joined through the private HTTPS tracker without configured peer URLs.
All three release manifests matched across 733 source paths. All six binary hashes passed verification.
Both transports established authenticated direct Hattori connections to osku, yutomac, and UTMOWRT.
Each of the six transfers delivered one MiB with the expected SHA-256 hash.
Before/after routes, stable authenticated connection IDs, and reciprocal byte counters passed the direct-delivery checks.
These snapshots do not establish continuous route selection between observations.

| Transport | Osku direct-route bound | Yutomac direct-route bound | UTMOWRT direct-route bound |
| --- | ---: | ---: | ---: |
| H2 | 67.781 s | 16.880 s | 8.254 s |
| WSS | 137.520 s | 95.898 s | 7.972 s |

These values are polling upper bounds from one startup per transport.
The H2 logs show the new socket-pool and port-search paths establishing both Mac connections.
Hattori found yutomac at public port 19902 and osku at public port 33306.
Those peer-specific mappings differed from the advertised STUN candidates.
The WSS paths also completed direct delivery. The method remains probabilistic.

| Transport | Osku first authentication | Hattori first authentication | Yutomac first authentication | UTMOWRT first authentication |
| --- | ---: | ---: | ---: | ---: |
| H2 | 0.573 s | 0.258 s | 0.464 s | 0.251 s |
| WSS | 0.516 s | 0.277 s | 3.451 s | 0.257 s |

Authentication timing uses each host's startup and first authenticated tracker connection log timestamps.
It differs from full-membership and direct-route polling.
The run did not measure sustained iperf3 throughput, CPU per delivered Gbit, or RSS.
It does not establish the performance goal.

The local capture contains 2101 SYN/reset observations: 2099 outgoing and two incoming.
Hattori's capture contains 11578 observations: 11573 outgoing and five incoming.
Both capture logs report zero kernel drops.
macOS raised the requested snapshot size from 96 to 524288 bytes. Its largest captured packet was 64 bytes.
Hattori retained a 96-byte snapshot size. Its largest captured packet was 78 bytes, including the Ethernet header.
The captures do not observe both NAT external interfaces. Local capture can observe multiple interfaces.
The raw captures, decoder receipts, and hashes remain in `v16-live/` and `v16-syn-summary.json`.

All 21 cleanup stages passed. The original offload state was restored.
Both captures stopped. The fixture removed its private files and stopped its owned services.
The runner and evidence reduction exited with code zero.

## Resource and bootstrap fixes after v16

The saved yutomac logs contain `Too many open files` errors during both transport phases.
The inherited shell soft file limit is 256. The old pool alone could own 128 listeners and 128 pending connections.
This left no capacity for established peers, management RPC, or other daemon work.
The errors explain the observed management RPC failures. They do not invalidate the later payload integrity checks.

Expanded TCP traversal now reads the Unix process soft file limit and counts its open descriptors.
It leaves at least half the remaining capacity for other work and accounts for handoff, TLS, and an accepted stream.
Each pool entry costs two descriptors. Each search connection costs one.
The existing ceiling remains 128 entries. Actual capacity depends on the descriptor count at preparation time.
This policy does not raise the process limit. Failed descriptor enumeration disables expansion.
Unrelated work can consume capacity after the snapshot, so allocation can still fail under concurrent pressure.
Reduced pools can require more traversal attempts. No new Internet latency result is available for this fix.

Source review also found that a stalled mapped-port TLS handshake could consume the full bootstrap deadline.
The outer timeout then canceled the fresh-port retry before it started.
The mapped attempt now receives half the existing 15-second deadline. The remaining time permits one fresh-port retry.
Both attempts retain transport, TLS exporter, and VPN authentication.
This source defect is separate from the observed yutomac descriptor exhaustion.

The initial two focused checks passed in 17.47 seconds. Their receipt is `v17-resource-bootstrap-focused.json`.
Review found that the initial resource fixture did not exercise peak socket occupancy.
The revised check uses an isolated child with a 256-descriptor limit and 128 existing file descriptors.
It fills the modeled listener, connection, and stream capacity, then verifies an independent control connection.
It also establishes native H2 and WSS traversal with both TLS roles while traversal workers remain active.
The final descriptor check passed in 1.34 seconds. Its receipt is `v17-descriptor-headroom-final.json`.
The bootstrap check covered failed VPN authentication and silent TLS, followed by an authenticated fresh-port connection.
The timeout implementation has not changed since that check passed.

Further source review found a cross-protocol resource gap.
QUIC still allocated 128 UDP sockets, and each network had an independent expansion permit.
Two networks could exhaust a 256-descriptor process before established connections and control traffic.
A QUIC pool could also overlap the TCP allocation despite TCP's own descriptor calculation.
TCP expansion and QUIC socket pools now share one process-wide permit and the available-descriptor calculation.
UDP port search uses one existing socket. It retains its existing per-network limit.
QUIC owns its receive futures and sockets inline, so cancellation releases those resources before the shared permit.

The v17 native release build passed. Its manifest and binaries remain available.
The waiting live runner and Linux builds were deliberately stopped before deployment after this source finding.
Both Linux build receipts record SIGTERM, with exit code -15. This was not a compiler failure.
Three focused resource checks passed in 4.29 seconds. Their receipt is `v18-resource-focused.json`.
The UDP check holds 128 existing files under a 256-descriptor limit.
It verifies actual pool occupancy, shared-permit exclusion, an independent control connection, and cancellation cleanup.
The transport checks preserve native QUIC, H2, and WSS authentication after traversal.
Four existing tests now share a test-only serialization key because they use the same process-wide permit.
This prevents unrelated test instances from competing for production traversal capacity.
All four shared-permit checks passed with four test threads in 10.37 seconds.
Their receipt is `v18-shared-permit-focused.json`.
No v17 Internet measurement occurred.

The v18 builds and waiting runner were also stopped before live deployment after a packet-buffer initialization defect was confirmed.
All three build receipts record deliberate SIGTERM termination with exit code -15.
The v19 correction initializes overflow slabs before exposing their bytes and passed one focused buffer regression.
The shared traversal limits remain unchanged.
See [packet pool initialization](resident-memory-20260922.md#packet-pool-initialization-correction) for the source evidence and test-filter recovery.

## Evidence

Complete command receipts, failures, packet-header captures, manifests, and host logs reside in
`benchmark-results/tracker-discovery-20260922/`.
The command audit is `benchmark-results/.work/tracker-discovery-20260922.jsonl`.
Credentials are redacted from saved logs.
Cleanup stopped the temporary daemon, tracker, STUN, proxy, and payload services.
Cleanup removed the test secret, generated configurations, private keys, and temporary CA files.
The original osku, Hattori, and yutomac production processes remained running.

The v11 core SHA-256 hashes are:

| Platform | SHA-256 |
| --- | --- |
| macOS ARM64 | `9419019ccee6f9649789ae2d4ef7506ed40dbfa0f615123030a41203d2f7b815` |
| Linux ARM64 | `458ad34e835b34f25620707af2297134629cb355dc8f2ead4082c7acab733ef8` |
| Linux x86-64 | `d890d58dd381dc659b72c7cdd701b15953274c525841bbfe1bb0e45a8b91c238` |

The earlier v8 core SHA-256 hashes are:

| Platform | SHA-256 |
| --- | --- |
| macOS ARM64 | `8767db3924f69510339cbfcd10a8a705cbf5084375748acbada98f226177f033` |
| Linux ARM64 | `0c8b7fddd2eaa225363fce4322c6f8818aac46f9b87a4626c2a86fd309b790d5` |
| Linux x86-64 | `80f07dd70e865c6eb000c1976a2779b665a3ea0e3b3c988314ce856b2eae018a` |

Key receipts include `tracker-v8-final-live-matrix.json`, `tracker-v8-https-live-matrix.json`,
`tracker-v8-quic-late-direct-delivery.json`, and `tracker-v8-tcp-final-live-matrix.json`.
The first two receipts record failed direct-path gates.
The latter two record the separate successful delivery checks.
