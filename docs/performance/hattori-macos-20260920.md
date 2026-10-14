# Hattori to Mac throughput, 2026-09-20

The later [eth0 retest](eth0-hattori-20260920.md) replaces this benchmark's PPPoE path with an eth0 path through S6916.

This experiment measures the three retained underlays with iperf3.
It uses the candidate with the four CPU and memory changes.
It does not compare those changes with the saved baseline.

## Endpoints and paths

| Endpoint | System | CPU threads | Memory | LowTier access mode |
| --- | --- | ---: | ---: | --- |
| Hattori | OpenWrt, Linux 6.12.63, ARM64 VM | 4 | 3.84 GiB | TAP |
| Yutoms | Mac15,14, Darwin 24.6.0 | 32 | 256 GiB | Userspace, smoltcp |
| Osku, this machine | Mac16,9, Darwin 27.0.0 | 16 | 128 GiB | Native utun |

The underlay destination is Hattori's public IPv4 address, `58.147.236.32`.
Both Mac hosts reach that address through physical Ethernet and gateway `172.25.0.1`.
Their public source address is `133.1.22.2`.
Hattori's source-address routing sends replies through `pppoe-bbd`.
SSH uses Tailscale for control only.
The data connections use the public addresses.
These tests do not measure a local 10 Gbit/s Ethernet path.

Each endpoint runs an isolated candidate instance.
Production instances remain active.
The test overlay uses `10.127.125.0/24` and a fresh private network identity.
Only the known client public address can reach the temporary public listeners.
Automatic peer discovery and UPnP are disabled.
Peer records must show one direct connection with the selected protocol.

The selected URLs are:

- `quic://58.147.236.32:14392` for QUIC/H3.
- `tcp://58.147.236.32:14390` for H2 over TLS.
- `wss://58.147.236.32:14393/ws` for WSS.

The `tcp://` scheme does not select an unencrypted raw TCP tunnel.
Plain `ws://` and raw `udp://` are rejected by the current source.
WSS uses direct TLS exporter binding in this experiment.

## Measurement method

All endpoints run iperf3 3.17.1 from the same saved source archive.
The Mac binary uses only the system C library.
The Linux binary is statically linked for ARM64 musl.
Both LowTier release binaries come from the same working tree.
The benchmark directory records binary SHA-256 hashes.

The matrix has 48 TCP transfers:

- Two client hosts and three underlays.
- One or four parallel streams.
- Both directions.
- Two 20-second trials per case.

Every transfer starts a fresh Hattori iperf server.
Reported throughput uses receiver bytes and receiver duration.
All completed trials remain in the aggregate, including slower trials.
The two hosts and underlays run sequentially, so they do not compete with each other for test bandwidth.
Uncontrolled production and WAN traffic can still affect the results.

Both LowTier instances use two runtime worker threads and a configured MTU of 1,280.
The Hattori TAP MTU is 1,260 after encryption overhead.
The effective Mac utun MTU is also 1,260.
iperf uses the negotiated TCP MSS.
An explicit MSS setting failed on macOS before data transfer and was removed from every measured case.

Yutoms binds a local TCP forward at `127.0.0.1:15209`.
The forward connects through smoltcp to Hattori at `10.127.125.100:5209`.
iperf reverse mode sends data from Hattori through the same established connections.
`LOWTIER_EXPERIMENT_OVERLAY_STREAM` is unset, so the experimental reliable stream is not active.
Yutoms creates no test kernel interface.
Osku sends directly through a task-owned utun interface.
macOS assigns the actual interface name; the smoke test used `utun11`.

Userspace forwarding splits each application connection into local TCP and overlay TCP connections.
The local iperf sender's counters therefore do not measure Yutoms overlay retransmissions or RTT.
Hattori's reverse sender reports overlay TCP retransmissions.
macOS does not supply all Linux TCP counters through this iperf build.
Missing counters are reported as unavailable, not zero.
Sender and receiver byte differences can include queued data at test termination; they are not packet-loss measurements.

Peer heartbeat RTT and heartbeat loss are sampled during each transfer and after each transfer.
Heartbeat loss is not application packet loss.
The kernel-interface smoke test also verifies ICMP delivery through the overlay.

CPU and RSS are sampled with a one-second delay between samples around each 20-second transfer.
The 25-sample windows span 24.030–27.655 seconds because sampling also takes time.
Linux CPU time comes from `/proc/PID/stat` with the system clock-tick rate.
Mac CPU time comes from cumulative `ps` process time with 0.01-second resolution.
CPU seconds are divided by receiver-delivered Gbit.
The CPU totals include process time throughout the complete sampling window, including its tail after traffic.
These values include the task-owned LowTier process, but exclude iperf, other processes, and uncharged kernel work.
They are not total host CPU costs.
RSS values are sampled process resident memory, not heap size or an exact lifetime peak.

## Cost model and interpretation

For delivered payload `D` and effective packet payload `P`, the packet path handles roughly `D/P` packets before retransmissions.
QUIC transports packet datagrams.
H2 and WSS add reliable TCP stream delivery beneath the inner TCP connection.
Loss can therefore cause stream head-of-line blocking for H2 and WSS.
The userspace path also copies data through a local TCP connection and schedules the smoltcp reactor.
It uses 128 KiB receive and transmit buffers per overlay TCP socket.
For four data connections, those buffers occupy about 1 MiB before the control connection and protocol overhead.
This is a source-derived allocation estimate, not a measured RSS attribution.

The experiments preserve default resource bounds.
No fixture-specific window, cache, or thread tuning is applied.
Host, operating system, and access mode differ between Yutoms and Osku.
Their results therefore compare complete endpoint configurations and do not isolate the cost of userspace mode alone.

Raw artifacts are in `benchmark-results/hattori-macos-20260920/`.

## Results

All 48 transfers completed. Values below use both trials.

Toward Hattori means Mac to router. From Hattori means router to Mac.
Throughput cells show the median and the full two-trial range in Mbit/s.

| Client | Underlay | Streams | Toward Hattori | From Hattori |
| --- | --- | ---: | ---: | ---: |
| Yutoms | QUIC/H3 | 1 | 17.3 (17.0–17.7) | 26.3 (26.3–26.4) |
| Yutoms | QUIC/H3 | 4 | 9.3 (8.5–10.1) | 26.2 (26.2–26.3) |
| Yutoms | H2/TLS | 1 | 19.2 (18.7–19.7) | 26.4 (26.3–26.5) |
| Yutoms | H2/TLS | 4 | 26.2 (25.8–26.6) | 26.5 (26.5–26.5) |
| Yutoms | WSS | 1 | 18.8 (18.7–19.0) | 26.3 (26.3–26.4) |
| Yutoms | WSS | 4 | 26.4 (26.3–26.6) | 26.5 (26.5–26.5) |
| Osku | QUIC/H3 | 1 | 26.1 (26.1–26.2) | 26.0 (26.0–26.0) |
| Osku | QUIC/H3 | 4 | 25.7 (25.5–25.9) | 25.9 (25.9–25.9) |
| Osku | H2/TLS | 1 | 25.1 (24.9–25.3) | 26.3 (26.2–26.3) |
| Osku | H2/TLS | 4 | 25.1 (25.1–25.1) | 26.1 (26.1–26.1) |
| Osku | WSS | 1 | 25.9 (25.6–26.2) | 26.3 (26.3–26.3) |
| Osku | WSS | 4 | 25.7 (25.2–26.1) | 23.6 (21.2–26.0) |

CPU values combine all eight transfers for each client and underlay.
RSS is the median of the eight per-transfer RSS medians, in MiB.

| Client | Underlay | Client CPU s/Gbit | Hattori CPU s/Gbit | Client RSS MiB | Hattori RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Yutoms | QUIC/H3 | 9.11 | 20.48 | 30.5 | 27.3 |
| Yutoms | H2/TLS | 6.09 | 12.39 | 32.3 | 27.5 |
| Yutoms | WSS | 5.23 | 11.01 | 32.2 | 44.9 |
| Osku | QUIC/H3 | 9.69 | 18.82 | 31.5 | 45.6 |
| Osku | H2/TLS | 5.10 | 11.03 | 42.4 | 38.2 |
| Osku | WSS | 7.13 | 10.60 | 37.6 | 27.5 |

The next table reports heartbeat RTT during traffic and Hattori TCP retransmissions in the reverse direction.
Each retransmission cell contains the two trial counts.

| Client | Underlay | Sampled RTT range, ms | Reverse P1 retransmissions | Reverse P4 retransmissions |
| --- | --- | ---: | ---: | ---: |
| Yutoms | QUIC/H3 | 8.18–8.47 | 3942, 5054 | 11733, 12054 |
| Yutoms | H2/TLS | 7.71–23.40 | 0, 0 | 0, 0 |
| Yutoms | WSS | 8.19–54.05 | 0, 0 | 0, 0 |
| Osku | QUIC/H3 | 4.80–4.99 | 4612, 4503 | 13974, 14053 |
| Osku | H2/TLS | 40.48–76.15 | 0, 0 | 0, 0 |
| Osku | WSS | 16.18–52.65 | 0, 0 | 0, 0 |

The maximum reported heartbeat loss during the sampled transfers was 0.0%.
The heartbeat samples do not measure application packet loss.
The Mac sender does not report overlay TCP retransmission counts in these records.

No direct raw-IP or Tailscale throughput baseline was added to this retained-underlay matrix.
The subsequent [Tailscale comparison](tailscale-hattori-20260920.md) uses the same workload but different WAN routes.
The results alone cannot establish whether a common throughput ceiling comes from the WAN path or LowTier.
They do not establish 10 Gbit/s performance or parity with Tailscale.

## Findings and limits

Most completed cases cluster near 25–27 Mbit/s on this public IPv4 path.
Yutoms QUIC upload is lower, especially with four streams: 8.5 and 10.1 Mbit/s.
The last Osku WSS four-stream reverse trial delivered 21.2 Mbit/s, compared with 26.0 Mbit/s in its first trial.
Both results remain in the reported median and range.

H2 and WSS used fewer process CPU seconds per delivered Gbit than QUIC in both endpoint configurations.
They also showed higher sampled heartbeat latency in several loaded cases.
Every Hattori reverse TCP sender reported zero inner TCP retransmissions over H2 and WSS.
QUIC reverse transfers reported thousands of inner TCP retransmissions.
This distinction does not establish the location or cause of packet loss.
The sequential test order and shared production traffic limit causal comparisons.

Maximum sampled RSS was 33.1 MiB for Yutoms, 42.7 MiB for Osku, and 47.6 MiB for Hattori.
Memory medians varied by endpoint configuration and underlay.
These measurements do not support a universal memory ranking.
Hattori's reported guest CPU steal counter remained zero throughout the sampling windows.
Its LowTier process averaged 10.6–49.4% of one CPU across those windows.
These guest measurements do not exclude short CPU spikes or unreported host scheduling delays.

The four implementation changes have a separate matched baseline comparison in [the CPU and memory report](cpu-memory-20260920.md).
That comparison does not establish a general CPU or throughput improvement.
This endpoint matrix measures the current candidate only.

## Verification and cleanup

The completeness check passed for all 48 transfers and 24 two-trial groups.
Each transfer has receiver results, both endpoint CPU/RSS samples, and peer records during and after traffic.
Every selected route remained direct and used the requested underlay.
The saved public route records show physical Ethernet on both Macs.
Yutoms retained its original kernel interface set throughout the test.

macOS assigned `utun11` despite the requested device name.
The running harness retained an obsolete `ifconfig utun79` query.
Its route and ping checks still used `utun11` correctly.
Separate interface captures recovered the actual state for each Mac underlay.
The saved runtime snapshot and audit record distinguish that harmless query failure from the successful traffic measurements.

The first cleanup attempt failed because OpenWrt `sleep` rejected a fractional interval.
The recovered cleanup used integer seconds and passed all exit checks.
No executable remained under the task directory on any host.
Task interfaces, firewall rules, private configurations, remote binaries, and SSH control sockets were removed.
Production process start times and binary hashes match their saved values.
Hattori's firewall table list and both Mac interface sets match their pre-test state.
The raw measurements, build logs, failed attempts, and source snapshots remain available locally.
