# Deployed transport review — 2026-10-13

WSS had the highest measured median upload speed. Tailscale had the highest measured median download speed on this host pair.
H2 had lower server CPU cost per received Gbit than QUIC in both directions.
These short sequential tests do not establish a general performance ranking.

## Scope and method

The test used the deployed LowTier binaries on the local Mac Studio and s6916. Both report revision `60753501`.
Temporary LowTier instances used an isolated network. The original tests used authenticated direct public connections; the CDN follow-up used Cloudflare bridges.
Existing resident instances remained active.
The Mac used native TUN. Linux used native TAP with compact IP. Tailscale used its resident native interfaces.
All interfaces used MTU 1280. Observed inner TCP MSS was 1228.
The Mac has 16 logical CPUs. The Linux virtual machine has two logical CPUs.
Tailscale versions were 1.102.3 on the Mac and 1.102.2 on Linux. Iperf versions were 3.21 and 3.9, respectively.
Each transport ran one TCP stream for 12 seconds per trial, twice in each direction. Total: 20 trials and 240 scheduled transfer seconds.
Tests included connection startup; there was no excluded warmup period. Protocol order was QUIC, H2, Tailscale, WSS, then the WSS/CDN bridge.
WSS added four matching tests after the original campaign. Earlier measurements were retained without rerunning them.
The WSS follow-up verified the same deployed binary hashes, host pair, authentication, direct path, and MTU.
Upload means Mac to s6916. Download means s6916 to Mac.
Each trial also sent 12 ping probes at 0.5-second intervals. All 240 probes returned.

## Receiver throughput and loaded latency

Throughput is receiver-side application data. Each range retains both repetitions.

| Transport | Direction | Median Mbit/s | Range Mbit/s | Mean ping range, ms | Inner TCP retransmissions |
|---|---|---:|---:|---:|---:|
| QUIC | upload | 390.1 | 386.2–393.9 | 15.8–20.6 | 716, 190 |
| QUIC | download | 347.5 | 323.0–372.0 | 12.0–13.3 | 149, 141 |
| H2 | upload | 360.4 | 344.7–376.0 | 36.2–53.4 | 512, 543 |
| H2 | download | 443.4 | 428.1–458.8 | 28.4–47.2 | 8, 0 |
| WebSocket (WSS) | upload | 454.2 | 454.0–454.5 | 60.5–63.8 | 14, 0 |
| WebSocket (WSS) | download | 446.5 | 438.2–454.7 | 22.3–30.5 | 0, 0 |
| WSS/CDN bridge | upload | 377.5 | 375.0–380.1 | 60.2–89.3 | 112, 7 |
| WSS/CDN bridge | download | 407.2 | 406.2–408.3 | 35.1–46.7 | 0, 0 |
| Tailscale | upload | 391.2 | 391.0–391.4 | 28.7–37.0 | 1391, 2260 |
| Tailscale | download | 467.4 | 466.8–468.0 | 13.4–14.6 | 56206, 55759 |

Retransmissions cover inner iperf TCP only. Outer H2/WSS TCP retransmissions and QUIC packet loss were not measured.
The retained receiver/sender byte ratios are end-of-test accounting ratios. They are not packet-loss measurements.

## Cloudflare follow-up

Four additional trials used an anonymous Quick Tunnel and `cloudflared` 2026.8.3 at both endpoints.
The tested path was LowTier WSS → local cloudflared → Cloudflare WebSocket edge → server cloudflared → LowTier WSS.
The server cloudflared connection to the Cloudflare edge used QUIC.
This path retains end-to-end LowTier TLS exporter authentication. It adds an outer WebSocket stream and two cloudflared processes.
The native `via=cdn` attempt failed before authentication. The strict underlay policy used in these tests rejected the hostname because it requires literal IP addresses.
Source inspection also shows an incompatible binding path: `via=cdn` omits the exporter but retains the `wss` label, which requires an exporter.
The hostname policy prevented a runtime test of that second condition. No routing or authentication policy was disabled.
The bridge uses a literal loopback peer address on the client. Cloudflare connects to the server’s own interface address through a kernel local route.
An initial loopback-origin attempt returned HTTP 502 because LowTier did not listen on loopback. The corrected local origin address resolved that error.
The table labels this result as WSS/CDN bridge. It does not establish native `via=cdn` throughput.
The original 16 trial records remain unchanged. The CDN tests ran later and retain the same short-test comparison limits.
Cloudflare documents [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) and [TCP over WebSockets](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/).

## Process resources

CPU includes user time and system time charged to the measured processes. CPU 100% means one logical CPU.
Direct rows measure VPN daemons. CDN rows include LowTier plus cloudflared at each endpoint. Cloudflare edge resources are outside measurement scope.
CPU seconds per received Gbit use each observed trial window, including setup and teardown.
Sampling was nominally 250 ms. Per-trial average Mac intervals ranged from 272 to 348 ms. Linux averages ranged from 251 to 252 ms.
RSS ranges are observed values, not guaranteed peak memory. RSS includes shared resident pages and excludes kernel socket memory.

CDN RSS adds both process readings. Shared resident pages can therefore be counted more than once.

| Transport | Direction | Mac CPU % | Server CPU % | Mac CPU s/Gbit | Server CPU s/Gbit | Mac RSS MiB | Server RSS MiB |
|---|---|---:|---:|---:|---:|---:|---:|
| QUIC | upload | 45.0 | 129.5 | 1.16 | 3.38 | 25.8–34.3 | 21.4–31.6 |
| QUIC | download | 23.7 | 88.2 | 0.80 | 2.84 | 31.4–31.6 | 26.5–31.0 |
| H2 | upload | 19.4 | 103.3 | 0.55 | 2.92 | 24.8–35.5 | 15.5–24.0 |
| H2 | download | 51.4 | 59.6 | 1.18 | 1.37 | 34.3–35.1 | 21.5–24.7 |
| WebSocket (WSS) | upload | 15.9 | 128.7 | 0.35 | 2.88 | 24.8–32.8 | 18.8–24.2 |
| WebSocket (WSS) | download | 42.9 | 59.3 | 0.97 | 1.37 | 31.2–31.5 | 21.7–23.5 |
| WSS/CDN bridge | upload | 25.1 | 160.9 | 0.68 | 4.37 | 58.5–77.2 | 61.4–82.0 |
| WSS/CDN bridge | download | 39.4 | 148.3 | 0.98 | 3.73 | 73.2–77.1 | 70.8–77.8 |
| Tailscale | upload | 113.3 | 141.1 | 2.93 | 3.67 | 80.0–146.4 | 262.8–342.2 |
| Tailscale | download | 121.8 | 106.7 | 2.63 | 2.32 | 93.3–130.8 | 314.1–341.0 |

CPU columns show medians. Full CPU ranges remain in `validated-summary.json`.
Tailscale daemons had existing mesh state and longer process histories. Their RSS cannot establish an intrinsic memory-efficiency ratio against fresh LowTier instances.
LowTier instances used default transport settings and two worker threads. This comparison measures deployed binaries under test configuration, not resident configuration parity.

## Kernel and host accounting limits

Raw samples include whole-host CPU counters. Linux samples also include interrupt, softirq, and steal counters.
Whole-host counters include daemons, kernel work, iperf, SSH, monitoring, and other background work. The CDN rows also include the measured cloudflared proxies.
Process and host counters do not reconcile in several Linux trials. QUIC download 1 reports 11.47 process CPU seconds and 10.66 host busy seconds.
Do not add these counters or subtract process CPU from host CPU. Exclusive kernel CPU cost remains unavailable.
Tailscale uploads recorded 2.60–2.72 seconds of server steal time. QUIC uploads recorded 0.40–1.30 seconds; H2 recorded approximately 0.18–0.19 seconds.
The second QUIC download sampled 15.85 seconds locally for approximately 12 seconds of transfer. Its CPU cost includes the extended observation window.
Two trials and sequential protocol groups cannot separate protocol effects from changing network conditions and host load.

## Implementation review

1. **P1: An idle TCP client can block the H2 listener.** Default single-lane acceptance waits for TLS and CONNECT-IP before accepting another connection.
   No deadline bounds this path. See `lowertier/src/tunnel/tcp.rs:111` and `lowertier/src/tunnel/http2.rs:537`.
2. **P1: An HTTP/3 client can retain QUIC admission for its source IP.** The seven-second timeout covers TLS only.
   CONNECT-IP admission has no deadline. One pending connection reaches the per-IP limit and can prevent admission for peers behind the same NAT.
   See `lowertier/src/tunnel/quic.rs:3679`, `:687`, and `:3767`.
3. **P2: TCP decoy forwarding has no concurrency or idle limit.** Unmarked connections create detached forwarding tasks that retain two sockets.
   This applies when decoy forwarding is enabled without SNI passthrough. See `lowertier/src/tunnel/http2.rs:128` and `:529`.
These findings follow from source inspection. This campaign did not run denial-of-service probes against deployed services.
QUIC, H2, and WSS derive TLS exporter bindings for peer authentication. All measured LowTier connections retained `NetworkSecretConfirmed` and stable connection IDs.
LowTier connection byte counters covered the delivered application bytes. Tailscale retained the direct server endpoint `193.32.149.82:41641`.

QUIC adds per-datagram encryption, ACK processing, congestion control, and possible fragmentation. H2 uses ordered TCP and TLS record coalescing.
The default H2 stream window is 2 MiB. At this approximately 12 ms path delay, the simple window/RTT bound exceeds 1 Gbit/s.
QUIC requests 7 MiB socket buffers in each direction. These capacity limits do not measure resident memory.
No build, optimization, or source repair was part of this campaign. The local QUIC file already contained uncommitted changes.

## Identity, verification, and recovery

Mac binary SHA256: `4ba1b2794b457063987d28e69c52a09a2b91a46cd0df38fb7db2dff1a2b9dd45`.
Linux binary SHA256: `4c7b732b74a5637471e003a69b762acc0516ea819fcb6ddbe559a381768dda60`.
All 20 benchmark clients and servers exited successfully. The Darwin CPU meter matched an independent process CPU measurement.
The temporary instances stopped. The resident PIDs and binary hashes remained unchanged. The resident authenticated peer path remained present.
The original campaign ended with two resident ping replies and 11.82 ms mean latency. The WSS follow-up also verified resident delivery after cleanup.
Discovery found a missing old CLI path and an incompatible old RPC port. The correct deployed CLI and separate test RPC port resolved both issues.
The first launcher used root’s SSH identity. The next attempt could not read its private configuration as the SSH user.
Using the established SSH identity and private standard input resolved both failures. Host-key verification remained enabled.
No resident transport baseline was replaced. Short single-flow results do not meet the broader baseline-promotion criteria.
No multistream, full-duplex, UDP saturation, Caddy routing, or long-duration tests ran. These omissions keep this requested campaign small.

Artifacts: `benchmark-results/.work/transport-review-20261013/`. The directory contains raw trials, source scripts, summaries, complete logs, and `audit.jsonl`.
The audit marks missing metadata explicitly. Generated private test configurations were removed after testing.
