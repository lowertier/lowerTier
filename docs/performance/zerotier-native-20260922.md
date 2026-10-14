# Native osku–UTMOWRT transport measurements, 2026-09-22

Tracker-discovered QUIC, H2, and WSS carried direct traffic between osku and UTMOWRT.
The complete speed and resource goal remains unmet.
QUIC v9 exceeded the earlier ZeroTier throughput medians in all four TCP conditions and used less process CPU per delivered Gbit.
Its resident memory remained higher, and ZeroTier's measured underlay path remains unverified.
H2 and WSS used less process CPU per delivered Gbit, but their resident memory was also higher.
All fifty trials in the completed LowTier matrices passed their route, authentication, connection, and payload checks.

## Conditions and path evidence

The tests used native virtual interfaces on both hosts, with a verified effective MTU of 1280 bytes.
Osku ran macOS ARM64; UTMOWRT ran OpenWrt Linux 6.6.110 ARM64.
The same iperf3 binaries ran throughout: 3.21 on osku and 3.17.1 on UTMOWRT.
Each TCP condition used two 20-second trials, with either one or four streams in each direction.
Each transport also had one 20-second UDP trial per direction, at 10 Mbit/s with 1000-byte payloads.
Upstream means osku to UTMOWRT.
Receiver counters supply delivered throughput.

The original LowTier matrices used release v8 from the tracker-discovery source manifests.
The later QUIC matrix used matching v9 native and ARM data endpoints.
Only the MTU detector source changed between those measured endpoints and v8.
The seed and tracker retained the exact v8 baseline binaries.
The separate queued-datagram boundary correction is absent from the measured v9 binaries.
The seed advertised through a private UDP tracker at `193.32.149.82:17970`.
Clients had no configured peer URLs.
The fixture enabled encryption and secure authentication.
Interface selection remained automatic; management connections used Tailscale.
The VPN addresses were `10.127.122.1` and `10.127.122.2`.
Source manifests and binary hashes are preserved in `native-build-manifests.json`.
The v9 endpoint and baseline service manifests are preserved in `native-v9-build-manifests.json`.

LowTier checks recorded an authenticated direct connection and its selected route before, during, and after each accepted trial.
The same connection IDs remained in all three snapshots.
The corrected H2/WSS fixture also requires direct byte counters to cover the delivered payload.
These snapshots establish sampled path stability, not continuous packet-level monitoring.

The v8 QUIC logs independently show the punched endpoints.
UTMOWRT reserved and used `14.10.162.66:9336`.
It connected to osku's mapped endpoint `133.1.22.2:7139`.
Both measured connection tuples match the punching logs.

ZeroTier versions were 1.16.1 on osku and 1.14.1 on UTMOWRT.
The temporary UTMOWRT membership used osku's existing public ZeroTier network.
The measured addresses were `10.244.100.106` and `10.244.49.239`.
ZeroTier's peer path arrays were empty in every saved snapshot.
Its directness and actual underlay route remain unverified.
The software used the same hosts and inner MTU, but this is not a verified comparison of matching underlay paths.

A later five-second, 10-Mbit/s UDP diagnostic identified a relay path.
Osku sent 6440 UDP packets containing 6,845,242 UDP payload bytes to `79.127.159.187:9993`.
The peer list identified that endpoint as ZeroTier planet `cafefd6717`.
The capture contained no direct flow to UTMOWRT's public IPv4 address.
The receiver delivered 6419 application datagrams without loss.
Both hosts still reported empty paths for their opposite test peer.
The capture reported zero kernel drops.
This supports relay use during that diagnostic; it does not retroactively establish the earlier TCP paths.
The diagnostic retained ZeroTier's original interface MTU and ran during a release build.
It is path evidence, not an additional throughput or CPU comparison.
The diagnostic removed its temporary UTMOWRT network membership afterward.
Receipts use the `zt-path-trace` prefix; `zt-path-trace-flows.json` contains the reduced packet-header capture.

## TCP receiver throughput

Values show median Mbit/s, followed by the minimum and maximum of two trials.
The H2 table uses the corrected `native-v8-routecheck` campaign.

| Transport | Upstream, 1 stream | Upstream, 4 streams | Downstream, 1 stream | Downstream, 4 streams |
| --- | ---: | ---: | ---: | ---: |
| ZeroTier, path unverified | 225.4 (223.3–227.5) | 270.6 (262.6–278.6) | 484.6 (481.8–487.3) | 512.7 (511.2–514.2) |
| QUIC v8, direct | 303.5 (264.2–342.8) | 229.8 (221.2–238.4) | 228.5 (226.8–230.3) | 321.1 (180.8–461.4) |
| QUIC v9, direct | 318.3 (294.3–342.4) | 383.5 (364.9–402.1) | 538.9 (536.7–541.1) | 527.3 (512.2–542.5) |
| H2 v8, direct | 594.2 (576.9–611.5) | 594.6 (589.5–599.6) | 467.6 (451.6–483.5) | 486.0 (485.8–486.3) |
| WSS v8, direct | 630.7 (627.4–633.9) | 630.4 (620.1–640.6) | 445.3 (412.7–477.9) | 494.7 (489.1–500.3) |

The original H2 campaign separately completed one accepted upstream trial at 562.2 Mbit/s.
That extra trial is preserved but is not mixed into the two-repeat table.
Its next transfer completed at 445.0 Mbit/s but failed the original route assertion.
That transfer remains outside the accepted matrix.

## CPU, memory, and delivery

The following CPU values divide summed process CPU seconds by summed receiver-delivered Gbit across eight TCP trials.
RSS ranges cover the corresponding samples.
Osku's ZeroTier figure includes both `zerotier-one` and `MacEthernetTapAgent`.
LowTier figures include the fixture daemon on each host.

| Transport | Osku CPU s/Gbit | UTMOWRT CPU s/Gbit | Osku RSS MiB | UTMOWRT RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| ZeroTier | 2.618 | 2.431 | 17.73–18.03 | 10.82–10.86 |
| QUIC v8 | 1.751 | 2.607 | 31.39–44.34 | 31.75–55.04 |
| QUIC v9 | 1.302 | 1.697 | 31.20–43.47 | 29.85–56.22 |
| H2 v8 | 0.724 | 1.562 | 29.08–42.58 | 23.11–46.04 |
| WSS v8 | 0.736 | 1.648 | 30.00–39.25 | 23.06–37.45 |

Sampling targeted one-second intervals.
Linux samples used `/proc` process and host counters, with the clock rate read from the auxiliary vector.
macOS samples used `ps` process counters and Mach host counters.
Actual CPU windows were approximately 23 seconds on UTMOWRT and 25.4–27.6 seconds on osku.
They include setup and completion around each 20-second payload window.
RSS means sampled resident memory; it excludes kernel socket memory and does not measure exact allocation peaks.
ZeroTier was a long-running service with other peers. LowTier ran in a fresh isolated network.

Whole-host CPU includes kernel network processing and unrelated applications.
Its aggregate seconds/Gbit were 20.998/3.731 for ZeroTier and 32.259/3.480 for QUIC, in osku/UTMOWRT order.
H2 measured 17.764/2.197; WSS measured 16.312/2.459.
QUIC v9 measured 17.830/2.320.
These whole-host values cannot attribute kernel cost precisely to one VPN implementation.
No builds or profiling ran during payload measurements.

| Transport | Inner TCP retransmissions, all 8 trials | Receiver/sender byte ratio range | Mean ping RTT range across trials |
| --- | ---: | ---: | ---: |
| ZeroTier | 271009 | 97.07–99.92% | 21.57–45.17 ms |
| QUIC v8 | 16327 | 94.27–99.83% | 22.80–42.58 ms |
| QUIC v9 | 16015 | 97.84–99.72% | 19.76–29.81 ms |
| H2 v8 | 7761 | 97.97–99.88% | 21.56–28.71 ms |
| WSS v8 | 12212 | 97.57–99.96% | 20.41–54.03 ms |

TCP byte ratios compare application counters at test completion.
Outstanding sender data and endpoint timing affect these ratios; they are not packet-loss estimates.
The retransmission column describes inner TCP, not transport-specific outer retransmissions.
The complete per-trial counters remain in `measurement-summary.json`.

Each UDP row below represents one 20-second trial at an offered rate of 10 Mbit/s.
ZeroTier's downstream receiver lost three packets; all other trials reported zero loss.

| Transport | Direction | Delivered Mbit/s | Lost/total packets | Receiver jitter |
| --- | --- | ---: | ---: | ---: |
| ZeroTier | Up | 9.988 | 0/25184 | 0.087 ms |
| ZeroTier | Down | 9.999 | 3/25179 | 0.474 ms |
| QUIC v8 | Up | 9.991 | 0/25184 | 0.202 ms |
| QUIC v8 | Down | 10.001 | 0/25120 | 0.327 ms |
| QUIC v9 | Up | 9.991 | 0/25181 | 0.122 ms |
| QUIC v9 | Down | 10.001 | 0/25187 | 0.677 ms |
| H2 | Up | 9.991 | 0/25014 | 0.133 ms |
| H2 | Down | 10.000 | 0/25183 | 0.309 ms |
| WSS | Up | 9.992 | 0/25186 | 0.156 ms |
| WSS | Down | 10.001 | 0/25187 | 0.369 ms |

## QUIC investigation

The v8 reverse TCP sender repeatedly reported an outer MTU between 1200 and 1420 bytes.
Forward trials retained 1420 bytes.
Reverse sender loss estimates ranged from 0.093% through 0.221% across telemetry brackets.
Those brackets lasted longer than the payload tests and include connection traffic outside the exact test window.
The measurements do not establish whether every reduction represented a true path change.

A new unit regression reproduced false MTU reduction when an older large ACK hid newer smaller deliveries.
The correction and its cost model are recorded in [QUIC MTU evidence](quic-mtu-ack-20260922.md).
All 41 focused MTU unit and integration tests passed after the correction.
They include real MTU reduction, path migration, probe loss, and packet splitting.
The v8 results above do not contain that correction.

The v9 matrix completed all eight TCP trials and both UDP trials.
All TCP sender telemetry brackets retained MTU 1420.
Reverse sender loss estimates ranged from 0.013% through 0.070%.
Reverse datagrams per send call ranged from 4.81 through 12.50.
The brackets lasted 21–24 seconds, so these counters include traffic outside the exact payload window.
Both UDP receivers reported zero loss.

The v9 punching logs match the measured connection endpoints.
UTMOWRT reserved and connected from `14.10.162.66:46193` to osku's mapped endpoint `133.1.22.2:1749`.
Osku recorded the accepted connection on its automatically selected local address.
All trials also passed direct-route, authentication, stable-connection, and delivered-byte coverage checks.

These observations agree with the source model: retaining a sufficient MTU removes fragmentation work.
The original v8 reverse results varied substantially, and the campaigns ran at different times.
A new v8 control matrix reproduced MTU reductions and lower reverse throughput after the v9 run.
The speed and resource goal remains unmet because RSS is still higher and several H2/WSS throughput conditions remain below ZeroTier.

## v8 control after v9

The `native-v8-recheck` campaign restored the verified v8 data endpoints immediately after the v9 campaign.
It retained the same seed, tracker, configuration, hosts, inner MTU, and iperf3 binaries.
Both campaigns used fresh daemons and new network secrets.
No build or profiler ran during either performance matrix.
All ten control trials and cleanup passed.

| Condition | v8 control median Mbit/s, range | v9 median Mbit/s, range |
| --- | ---: | ---: |
| Up, one stream | 262.7 (204.7–320.8) | 318.3 (294.3–342.4) |
| Up, four streams | 196.9 (65.4–328.5) | 383.5 (364.9–402.1) |
| Down, one stream | 313.9 (262.6–365.2) | 538.9 (536.7–541.1) |
| Down, four streams | 271.9 (264.9–278.9) | 527.3 (512.2–542.5) |

Every reverse control bracket again included MTUs from 1200 through 1420.
Two forward brackets also included a reduction to 1200.
The slowest forward trial reported 1.663% outer loss in its telemetry bracket; it remains included in the table.
Reverse control brackets reported 0.094–0.200% outer loss and 1.91–3.73 datagrams per send call.
Across the four reverse brackets, average UDP payload size was 791.1 bytes for the control and 1328.9 bytes for v9.
Aggregate reverse datagrams per send call were 2.20 and 7.84, respectively.
These packet-work counters use the telemetry brackets, not the exact iperf windows.

Control process CPU cost was 2.197 s/Gbit on osku and 2.845 s/Gbit on UTMOWRT.
The corresponding v9 values were 1.302 and 1.697.
Control RSS ranged from 30.22–42.23 MiB on osku and 30.11–49.74 MiB on UTMOWRT.
Control inner TCP retransmissions totaled 24,300; both control UDP trials reported zero loss.
Full latency, delivery, CPU, memory, and path counters remain in `measurement-summary.json` under the separate campaign prefix.

The control strengthens the evidence that the detector correction improves this path.
It does not remove all network timing variation or establish behavior for every NAT and MTU.

## Failures, recovery, and cleanup

The first non-root macOS iperf invocation reported `No route to host`, while ping succeeded.
Packet capture showed no corresponding outgoing test packets.
The same iperf binary succeeded under `sudo`.
The exact local permission mechanism remains unresolved.
All reported trials use the successful privileged invocation.

UTMOWRT lacked `getconf`, `hostname`, and `timeout` commands expected by early scripts.
The recovered fixture used the auxiliary vector, `/proc/sys/kernel/hostname`, and a Node child-process timer.
An initial server timeout left a remote iperf process running.
Cleanup verified its command before stopping it.
A local capture timeout also left a verified root capture process, which cleanup stopped.

All ten QUIC measurements completed before cleanup failed on BusyBox's rejection of `sleep .2`.
The corrected cleanup used integer seconds, verified process exit, and restarted the required helper services.
The QUIC measurements remain valid and separate from that cleanup error.

The original H2 route assertion required every alternative routing policy to select the direct peer.
The fixture disabled both latency-first and speed-first policies.
Source review confirmed that the least-hop route controlled test traffic.
The failed snapshot retained that direct route and the same authenticated connection.
Direct receive counters increased by 1.191 GB, while seed traffic increased by only kilobytes.
The corrected fixture checks the active route and adds payload byte coverage.
Its new campaign prefix preserves all original receipts, including the failed validation.

Final cleanup stopped the fixture daemons, tracker, and STUN service.
It removed private fixture files and the UTMOWRT test interface.
Osku's two ZeroTier interfaces returned to MTU 2800.
UTMOWRT left the temporary ZeroTier network; its final membership list was empty.
Osku's original LowTier, ZeroTier, and ZeroTier interface helper processes remained running.

## Evidence

Complete command receipts, CPU samples, peer snapshots, source manifests, and service logs reside in
`benchmark-results/zerotier-goal-20260922/`.
The command audit is `benchmark-results/.work/zerotier-goal-20260922.jsonl`.
The reducer is `summarize.py` in the result directory.
It retains every accepted trial and separates campaign prefixes.
Failed and incomplete attempts remain separate receipts.

Four-host discovery and the remaining osku–Hattori limits are documented in
[Tracker discovery results](tracker-discovery-20260922.md).
