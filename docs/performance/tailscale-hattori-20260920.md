# Tailscale comparison, 2026-09-20

The [eth0 retest](eth0-hattori-20260920.md) measures LowTier through Hattori eth0 and the S6916 relay.
It includes the connection failures found on that path.

This comparison uses the same endpoint pairs and iperf3 workload as the earlier LowTier matrix.
The network paths differ, so this is an end-to-end configuration comparison, not an isolated transport comparison.

## Conditions

- iperf3 3.17.1, using the same compiled binaries as the LowTier test.
- One and four TCP streams, both directions, two 20-second trials per case.
- Sixteen new transfers. Receiver bytes and duration determine throughput.
- Hattori runs Tailscale 1.92.3 on OpenWrt with a kernel TUN interface.
- Yutoms runs Tailscale 1.102.2 in userspace mode, node `100.76.95.60`.
- Osku runs Tailscale 1.102.3 with a kernel utun interface, node `100.108.186.13`.
- Tailscale uses MTU 1280. The earlier LowTier test interfaces used MTU 1260.
- Each transfer starts a fresh Hattori iperf server bound to `100.69.88.25:5219`.
- No production VPN process was restarted or reconfigured.

Yutoms uses a temporary local TCP forward through the existing Tailscale userspace daemon.
The forward uses the same LocalAPI TCP dial operation as `tailscale nc`.
It adds a local TCP socket and a Unix socket copy in each direction.
Its CPU and RSS are sampled separately and included with the daemon counters.
The separate Yutoms Tailscale desktop app belongs to another network and was excluded.
All remote control uses SSH.

## Route differences

Tailscale used peer relays during these tests.
The saved path probes identify relay addresses and latency for each transfer.
Hattori routes traffic to the observed relay addresses through `eth0` and gateway `192.168.64.1`.
LowTier used direct public IPv4 connections to `58.147.236.32`.
Hattori routes replies from that address through `pppoe-bbd`.
The measurements therefore cannot separate protocol performance from the different WAN routes.
They also run sequentially after the LowTier matrix, rather than as interleaved A/B trials.

## Throughput

Values are Mbit/s. Each cell shows the median and the full two-trial range.
Toward Hattori means Mac to router. From Hattori means router to Mac.

| Client | Streams | Tailscale toward Hattori | Tailscale from Hattori |
| --- | ---: | ---: | ---: |
| Yutoms | 1 | 152.9 (139.3–166.5) | 365.8 (365.0–366.6) |
| Yutoms | 4 | 213.2 (196.4–230.0) | 372.1 (367.7–376.4) |
| Osku | 1 | 215.7 (182.5–248.9) | 495.3 (466.0–524.5) |
| Osku | 4 | 249.8 (235.8–263.8) | 420.8 (411.3–430.4) |

Four-stream comparison with the earlier LowTier medians:

| Client | Transport | Toward Hattori Mbit/s | From Hattori Mbit/s |
| --- | --- | ---: | ---: |
| Yutoms | Tailscale | 213.2 | 372.1 |
| Yutoms | LowTier QUIC/H3 | 9.3 | 26.2 |
| Yutoms | LowTier H2/TLS | 26.2 | 26.5 |
| Yutoms | LowTier WSS | 26.4 | 26.5 |
| Osku | Tailscale | 249.8 | 420.8 |
| Osku | LowTier QUIC/H3 | 25.7 | 25.9 |
| Osku | LowTier H2/TLS | 25.1 | 26.1 |
| Osku | LowTier WSS | 25.7 | 23.6 |

## CPU, memory, and delivery evidence

Each transfer includes 25 samples with a one-second delay between samples.
The observed sampling windows span 24.016–27.015 seconds.
The sampling windows include the traffic interval and additional time after traffic.
Daemon counters include unrelated production traffic and SSH control work.
Host CPU counters include kernel work, iperf, the userspace forward, and other processes.
Linux uses `/proc/stat`; macOS uses Mach `HOST_CPU_LOAD_INFO`.
Host CPU seconds are estimated from the active tick fraction, observed elapsed time, and CPU count.
Some Hattori host CPU estimates are lower than its measured process CPU time.
Those inconsistent host totals are retained as diagnostic data and cannot support a CPU efficiency claim.
The earlier LowTier matrix lacks matching complete-host counters.
No matched total CPU comparison is claimed.

The table reports Tailscale daemon CPU and the Yutoms helper CPU together.
RSS is the median of per-transfer medians, summed across sampled processes.
It is not peak memory or memory attributable only to these tests.

| Client | Client CPU s/Gbit | Hattori CPU s/Gbit | Client RSS MiB | Hattori RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| Yutoms | 11.20 | 3.52 | 215.5 | 144.6 |
| Osku | 3.41 | 2.24 | 257.1 | 164.1 |

| Client | Streams | Reverse TCP retransmissions, two trials | Loaded Tailscale ping range, ms |
| --- | ---: | ---: | ---: |
| Yutoms | 1 | 1669, 1240 | 24.0–56.0 |
| Yutoms | 4 | 487, 440 | 25.0–50.0 |
| Osku | 1 | 7155, 5089 | 21.0–33.0 |
| Osku | 4 | 39958, 28238 | 21.0–61.0 |

All sixteen TCP transfers completed. All receiver records remain in the aggregate.
Tailscale path ping latency is not identical to LowTier heartbeat latency.
The Mac clients do not provide comparable overlay TCP retransmission counts.
For userspace mode, local client counters describe the loopback connection.
Sender and receiver byte differences at termination are not packet-loss measurements.

Artifacts: `benchmark-results/tailscale-hattori-20260920/`.

## Result and cleanup

Tailscale is substantially faster than the earlier LowTier configurations on these endpoint pairs.
For four streams, its medians are about 8–16 times the LowTier H2 medians, depending on endpoint and direction.
The different WAN routes prevent attributing the complete gap to transport implementation.
LowTier has not reached Tailscale parity in these measurements.

All sixteen server reports identify the expected Tailscale client address.
All saved path probes during traffic used peer relays.
One transfer changed peer relay during measurement; its complete result remains included.

Cleanup passed.
The temporary iperf server and userspace forward exited.
All task directories and SSH control sockets were removed.
Tailscale and LowTier process start times remain unchanged.
LowTier binary hashes, Hattori firewall table names, and Mac interface sets match the saved state.
No production VPN was restarted or reconfigured.
