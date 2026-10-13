# Transport and Ethernet repairs — 2026-10-13

The implementation addresses the eight transport and L2 review items.
The changes preserve TLS exporter authentication for H2, QUIC, direct WSS, and native CDN WSS.

## Behavior changes

| Review item | Result |
|---|---|
| WSS receive allocation | A 256 KiB message limit applies before payload allocation, including fragmented messages. |
| H2 admission | Concurrent admission has global and per-source bounds. One deadline covers routing inspection, TLS, and CONNECT. |
| QUIC admission | One deadline covers TLS and CONNECT activation. Ordinary HTTP/3 requests retain their response path. |
| Native CDN WSS | Inner TLS supplies the exporter across a terminating WebSocket proxy. Missing subprotocol support causes rejection. |
| Bridge setup | Examples and the three-node feature harness enable bridge authorization explicitly. |
| FDB expiry | Capacity pressure reclaims expired entries, including entries that were never used as destinations. |
| L2 policy | Optional source quotas, MAC move holds, VLAN lists, and EtherType lists apply before forwarding and neighbor replies. |
| Platform and loop coverage | The Linux TAP feature suite covers three transports and reflected frames. Platform and topology limits are documented. |

L2 policy also checks compact IP delivery. An IP packet cannot bypass the VLAN or EtherType policy through compaction.
The options are startup configuration. Default values preserve existing policy behavior.
These controls do not implement STP, a general distributed rule engine, or authenticated ARP address ownership.

## Source-derived Ethernet fix

Linux recycles receive buffers without clearing their packet-header prefix.
The compact IPv4/IPv6 path initialized this header, but the exceptional Ethernet path did not.
The shared sender accepted an existing Ethernet header and treated its old destination as an explicit forwarding override.
This could send a flooded frame to only one peer.

The local exceptional Ethernet path now initializes the header before forwarding.
This resets the destination and routing flags without changing a received peer packet or an explicit preclassified destination.
The complete three-node TAP suite passed after this correction.

## Critical verification

- Linux and macOS release builds passed from an isolated source snapshot.
- The selected admission, TLS binding, message limit, configuration, and bridge policy checks passed before the final feature campaign.
- Real Caddy-L4 tests passed with two backends each for H2, H3/QUIC, and WSS.
- Caddy tests preserved TLS bindings and normal website access with SNI passthrough enabled and disabled.
- Native Linux TAP checks passed for QUIC, H2, and WSS across a forced three-node relay topology.
- TAP checks covered exact unknown EtherType, VLAN, QinQ, LLDP, broadcast, known/unknown unicast, MAC moves, reflected frames, and MTU boundaries.

Linux network namespaces replaced unavailable Docker instances for the TAP checks.
The isolated namespace network had no external route.
The harness initially encountered delayed namespace teardown between protocols.
Explicit removal of the harness veth devices corrected that cleanup race.
The successful QUIC result and the subsequent successful H2/WSS results remain separate records.

Native Ethernet was verified on Linux. FreeBSD has a TAP implementation but did not receive a runtime check in this campaign.
macOS and Windows remain TUN platforms. These changes do not add native Ethernet adapters on those platforms.

## Internet measurement method

The direct comparison used the same Mac Studio and s6916 Linux VM, public endpoint, configuration, and native interfaces for both versions.
The Mac has 16 logical CPUs. The Linux VM has two logical CPUs.
The Mac used native TUN. Linux used native TAP with compact IP.
Configured MTU was 1300; effective interface MTU was 1280, with inner TCP MSS 1228.
LowTier used two worker threads. Tests used one TCP stream for 12 seconds, twice in each direction.
Upload means Mac to s6916. Download means s6916 to Mac.
There was no excluded warmup interval. Each trial included 12 loaded ping probes.

The baseline is deployed revision `60753501`.
The candidate includes these repairs and the admission protections from revision `85dec010`.
The source snapshot excludes unrelated uncommitted work.
The build snapshot tree is `854aa28328c5f8be947f7ab5b25903404836a660`.
This comparison measures the complete candidate against the deployed binary. It does not isolate each individual change.

Mac baseline core SHA256: `4ba1b2794b457063987d28e69c52a09a2b91a46cd0df38fb7db2dff1a2b9dd45`.
Linux baseline core SHA256: `4c7b732b74a5637471e003a69b762acc0516ea819fcb6ddbe559a381768dda60`.
Mac candidate core SHA256: `7dcbb664a922bcc0f90b61d07c1f5ad123b23fbd3cf1a135406be073debe7ecc`.
Linux candidate core SHA256: `1037d29ccc591278e1baf0e33460659e0445b18a106414585c74a272ecadf64b`.

CPU measures user and system time charged to the tested processes, normalized by receiver-delivered Gbit.
Direct tests measure the LowTier core at each endpoint.
Native CDN tests include the remote cloudflared process. No local cloudflared process is required.
Cloudflare edge resources are outside the measurement scope.
RSS includes shared resident pages and excludes kernel socket memory. Summed process RSS can count shared pages more than once.
Sampling is nominally 250 ms. Raw samples preserve the actual intervals.
Mean sample intervals ranged from 270.3 to 356.3 ms on the Mac and 250.7 to 251.2 ms on Linux.

Direct tests used iperf 3.21 on the Mac and Debian iperf `3.9-1+deb11u3` on Linux.
The final native CDN campaign used iperf 3.21 at both endpoints.
The Linux test binary was built from the official source with Zig and used only inside the authenticated test network.
It did not replace the system iperf package.
Therefore, the native CDN measurements are not a matched performance comparison with the direct paths.

Whole-host CPU and Linux interrupt and steal counters remain in the raw records.
Process and host counters do not reconcile in some VM observations.
Do not subtract process CPU from host CPU to infer exclusive kernel cost.
Short sequential groups cannot separate code effects from changing network conditions, VM scheduling, or background load.

## Measurement results

Each row contains two 12-second trials. The `tcp` configuration selects H2.
All 28 reported trials retained authenticated connections and sufficient tunnel byte counters to account for the delivered traffic.
All 336 loaded ping probes returned. This does not establish zero data-packet loss.

| Version / transport | Direction | Delivered Mbit/s, median (range) | Mean ping range, ms | Inner TCP retransmissions |
|---|---|---:|---:|---:|
| Baseline QUIC | Upload | 445.0 (440.4–449.6) | 17.4–19.5 | 998, 827 |
| Candidate QUIC | Upload | 435.8 (428.4–443.1) | 17.9–22.3 | 1979, 309 |
| Baseline QUIC | Download | 439.5 (422.8–456.1) | 12.4–12.4 | 18194, 26234 |
| Candidate QUIC | Download | 452.3 (451.1–453.5) | 12.6–13.3 | 37907, 28821 |
| Baseline H2 | Upload | 400.0 (391.0–409.1) | 31.6–33.7 | 252, 320 |
| Candidate H2 | Upload | 439.5 (439.2–439.9) | 27.7–32.8 | 229, 366 |
| Baseline H2 | Download | 445.2 (442.3–448.2) | 24.1–27.8 | 12, 0 |
| Candidate H2 | Download | 444.6 (443.5–445.7) | 27.2–33.7 | 11, 13 |
| Baseline WSS | Upload | 440.4 (438.7–442.2) | 52.5–60.9 | 454, 5 |
| Candidate WSS | Upload | 449.2 (448.3–450.0) | 42.3–42.3 | 270, 89 |
| Baseline WSS | Download | 417.4 (404.9–429.8) | 26.3–37.0 | 0, 0 |
| Candidate WSS | Download | 455.5 (455.0–455.9) | 21.2–42.0 | 0, 0 |
| Native CDN WSS | Upload | 376.9 (361.9–391.8) | 70.7–74.0 | 285, 10 |
| Native CDN WSS | Download | 416.9 (413.0–420.9) | 27.6–31.5 | 0, 0 |

CPU values are medians in CPU seconds per delivered Gbit. RSS values span both trials.
Native CDN server figures include LowTier and cloudflared; all other figures include LowTier only.

| Version / transport | Direction | Mac CPU s/Gbit | Server CPU s/Gbit | Mac RSS MiB | Server RSS MiB |
|---|---|---:|---:|---:|---:|
| Baseline QUIC | Upload | 0.84 | 3.14 | 25.9–33.4 | 22.9–32.7 |
| Candidate QUIC | Upload | 0.81 | 3.14 | 26.0–33.2 | 19.6–30.7 |
| Baseline QUIC | Download | 1.11 | 2.50 | 32.5–32.6 | 27.6–30.4 |
| Candidate QUIC | Download | 1.15 | 2.53 | 30.6–31.2 | 26.8–28.7 |
| Baseline H2 | Upload | 0.77 | 2.97 | 24.8–35.1 | 18.5–26.8 |
| Candidate H2 | Upload | 0.68 | 2.78 | 24.9–35.1 | 18.6–28.1 |
| Baseline H2 | Download | 1.05 | 1.49 | 34.0–34.3 | 24.1–27.1 |
| Candidate H2 | Download | 1.07 | 1.32 | 34.3–34.8 | 24.2–27.3 |
| Baseline WSS | Upload | 0.98 | 2.91 | 24.9–32.8 | 19.2–24.0 |
| Candidate WSS | Upload | 0.45 | 2.85 | 24.9–31.8 | 18.6–23.4 |
| Baseline WSS | Download | 0.68 | 1.52 | 31.5–31.8 | 21.4–22.5 |
| Candidate WSS | Download | 0.79 | 1.30 | 31.8–32.4 | 20.9–22.3 |
| Native CDN WSS | Upload | 1.01 | 4.06 | 31.2–41.8 | 61.8–81.3 |
| Native CDN WSS | Download | 1.09 | 3.47 | 41.0–41.7 | 73.5–79.7 |

The candidate improved measured H2 upload and WSS throughput. QUIC upload decreased by 2.1%; QUIC download increased by 2.9%.
These observations do not establish a general performance improvement.
Receiver/sender byte ratios ranged from 97.18% to 99.92% for the candidate direct paths.
Those ratios include end-of-test accounting and buffered data. They must not be reported as packet delivery probabilities.

QUIC connection counters covered both directions and all four trials per version, including intervening control traffic.
Baseline declared-loss/sent-packet deltas were 1696/1269389 on the Mac and 44836/1319205 on Linux.
Candidate deltas were 2096/1259086 on the Mac and 66878/1368727 on Linux.
Declared losses can include spurious loss detection. These counters do not directly measure unrecovered application loss.

Linux outer TCP retransmissions also increased during the candidate download groups.
H2 totals were 9953 segments for the baseline and 17609 for the candidate.
WSS totals were 4029 segments for the baseline and 61925 for the candidate.
The calculation matches established sockets before and after each trial and excludes old closing sockets.
Mac outer TCP retransmissions and Cloudflare edge loss counters were not collected.
Cloudflared metrics and inner TCP retransmissions remain available for the CDN path.
This loss evidence prevents a claim that the candidate improved reliability or network efficiency.

## Failures and evidence limits

One direct WSS upload timed out during iperf result exchange. Its throughput result is unavailable.
The tunnel remained connected until cleanup, and all 12 ping probes returned.
A separate recovery upload completed. The failed attempt remains in `implementation-wan/failed-wss-upload-2.json`.
The collector now preserves malformed server output and client transcripts before parsing.

Several earlier CDN attempts also stalled during iperf result exchange.
The first campaign retained three completed trials; the fourth timed out. These results remain separate from the final campaign.
Both endpoint captures then showed that Linux received and acknowledged the stop message before the stall.
Linux emitted its response only after the client closed approximately 10 seconds later.
The response crossed LowTier promptly. The packet evidence locates this delay inside the server application.

The installed Debian package contains a security backport that adds a 10-second `select` wait to `Nread`.
The old TCP data reader uses that function for partial data blocks on the same thread that handles control messages.
Thus a final partial block can delay control-message processing until the data wait ends.
The saved process samples show the server in `select` during the delay.
The warning comes from a subsequent incomplete control-message read, rather than establishing a LowTier framing defect.
The exact [Debian patch archive](https://archive.debian.org/debian-security/pool/updates/main/i/iperf3/iperf3_3.9-1+deb11u3.debian.tar.xz) and its verified SHA256 remain in the evidence directory.
Iperf 3.21 uses `Nrecv_no_select` for TCP data and separates transfer workers from control handling.
All four final CDN trials completed with that version, without changes to LowTier.
The original direct WSS failure lacks both endpoint captures, so its exact cause remains unconfirmed.

Quick Tunnel registration sometimes preceded DNS availability. The harness now checks DNS before starting traffic, with a 180-second setup budget.
Failed DNS attempts remain saved. No resolver policy was changed.
The iperf cross-build initially used the macOS archive tool; rebuilding its Linux archive with Zig corrected the link failure.

## Deployment decision

The candidate ran on both test nodes for native transport, CDN authentication, and delivery checks.
The candidate binaries are retained separately for the validated H2, WSS, and Linux bridge scenarios.
The Mac archive is `/Users/boyu/et/baselines/transport-20261013/`.
The Linux archive is `/opt/lowertier-baselines/transport-20261013/`.
The resident QUIC instances retain revision `60753501` under the fastest-validated-baseline policy.
The candidate has no matched multiple-stream result, and its QUIC upload and loss counters do not support general promotion.
No default transport change was made from these single-stream results.
Final checks confirmed the resident binary hashes, authenticated peer connections at both endpoints, and three returned ping probes.
Temporary cores, proxy processes, interfaces, and test namespaces were removed. The existing `wgcf` namespace remains.

## Artifacts

Complete evidence is under `benchmark-results/.work/transport-review-20261013/`.
The directory includes source snapshots, release logs, feature logs, raw trials, packet evidence, and JSONL audit records.
`implementation-l2-quic-passed-cleanup-failed.log` contains the successful QUIC feature suite and the later harness cleanup failure.
`implementation-l2-native.log` contains the successful H2 and WSS feature suites.
`implementation-caddy-all.log` contains the complete shared-port integration result.
`implementation-wan/` contains the direct comparisons and the retained failed attempt.
`implementation-cdn-matched-iperf/` contains the four final native CDN measurements and authentication manifest.
`implementation-cdn/`, `implementation-cdn-incomplete/`, and `implementation-cdn-recovery/` retain earlier incomplete campaigns and diagnostic evidence.
`implementation-validated-summary.json` contains validated metrics and outer transport counter deltas.
`implementation-final-state.json` records the retained binaries, resident authentication, delivery, and cleanup checks.
Private generated configurations are removed after each campaign.
