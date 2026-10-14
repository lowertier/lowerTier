# Receive queue deadlock fix and eth0 retest, 2026-09-20

The retest completed 48 of 48 transfers. 0 transfers failed.
The previous run completed 35 of 48 transfers. 13 transfers failed.

## Correction and resource model

The ingress and NIC queues previously shared one 512 KiB admission budget.
Ingress could refill released credits before its consumer forwarded the current batch to NIC.
The consumer then waited for credits that only another ingress dequeue could release.
The original diagnostic reproduced this wait in `benchmark-results/.work/eth0-credit-cycle-20260920-recovered.log`.
Encrypted relay packets reach this receive-to-NIC path after decryption.
Each queue now has independent credits. The capacity of each queue remains 512 KiB.
No extra packet copy, encryption operation, worker, or queue was added.
Each instance in the single-network fixture has a combined 1 MiB queue admission limit.
Each foreign-network entry also receives its own 512 KiB queue budget.
These bounds exclude waiting producers, dequeued batches, metadata, and the separate direct-NIC path.
They are not process RSS limits.

The deterministic regression fills ingress, dequeues one batch, and refills ingress before NIC delivery.
NIC delivery completes. The test also verifies independent saturation, packet contents, and release after dequeue.
All ten packet-manager tests pass. They cover ordering, forwarding permissions, and rejection before decryption.

Seven local transport checks also pass: H2/WSS TLS bindings, QUIC secure mode, probe handling, and ordinary HTTP service.
Caddy dual-backend tests were not run because no Caddy binary was found in PATH or the existing build artifacts.
The correction does not change transport framing, TLS binding, or Caddy routing.

## Measurement conditions

Both Macs connect through S6916 at 193.32.149.82 to Hattori.
Hattori uses eth0 with source 192.168.64.23 and gateway 192.168.64.1.
Temporary firewall rules reject test underlay traffic on other output interfaces.
Per-transfer eth0 counters and peer records validate each completed transfer.
The data-direction eth0 bytes must exceed delivered application bytes.
SSH control uses Tailscale. LowTier data uses public IPv4.
The isolated instances use secure mode, encryption, two workers, and disabled P2P discovery.
Hattori uses TAP, Osku uses native utun, and Yutoms uses the userspace TCP forward.
Configured MTU is 1280. The TAP and utun MTU is 1260.
All transfers use iperf3 3.17.1, one or four streams, both directions, and two 20-second trials.
Each trial starts a fresh iperf server. Throughput uses receiver bytes and receiver duration.
The baseline and retest use the same endpoints and transport settings, but run at different times.
Production traffic and WAN conditions are not controlled.
The runs do not establish a matched CPU-efficiency improvement.
The baseline restarted instances after failures. Different process lifetimes also limit direct RSS comparisons.
Binary hashes, raw output, CPU samples, routes, and firewall counters remain in the artifact directory.

## Throughput

Values are median Mbit/s with the full range of two completed trials.
Single completions and failed transfers are marked separately.

| Client | Transport | Streams | Mac → Hattori | Hattori → Mac |
| --- | --- | ---: | ---: | ---: |
| osku | QUIC/H3 | 1 | 22.1 (18.9–25.3) | 349.0 (346.9–351.1) |
| osku | QUIC/H3 | 4 | 86.8 (85.7–87.9) | 363.2 (355.8–370.6) |
| osku | H2/TLS | 1 | 54.1 (36.9–71.2) | 0.34 (0.31–0.37) |
| osku | H2/TLS | 4 | 39.8 (37.3–42.2) | 0.23 (0.21–0.26) |
| osku | WSS | 1 | 55.1 (54.9–55.2) | 0.26 (0.21–0.31) |
| osku | WSS | 4 | 44.0 (41.1–46.8) | 0.21 (0.21–0.21) |
| yutoms | QUIC/H3 | 1 | 17.8 (17.3–18.3) | 10.0 (10.0–10.1) |
| yutoms | QUIC/H3 | 4 | 94.1 (91.7–96.4) | 118.8 (118.3–119.3) |
| yutoms | H2/TLS | 1 | 18.8 (18.7–18.9) | 0.26 (0.26–0.26) |
| yutoms | H2/TLS | 4 | 4.0 (3.8–4.2) | 0.21 (0.21–0.21) |
| yutoms | WSS | 1 | 18.3 (18.3–18.3) | 0.31 (0.31–0.31) |
| yutoms | WSS | 4 | 4.8 (4.8–4.9) | 0.21 (0.21–0.21) |

Earlier Tailscale four-stream medians:

| Client | Mac → Hattori Mbit/s | Hattori → Mac Mbit/s |
| --- | ---: | ---: |
| osku | 249.8 | 420.8 |
| yutoms | 213.2 | 372.1 |

Tailscale used eth0 and peer relays, including S6916. Some trials used another relay.
Tailscale MTU was 1280. The earlier trials were not interleaved with this retest.
This comparison does not isolate transport implementation costs.

## CPU, memory, delivery, and latency

Each transfer records 25 process and host samples with one-second delays.
Process CPU uses cumulative counters and includes time after the transfer.
CPU seconds are normalized by delivered Gbit across completed transfers.
RSS shows the median of per-transfer medians. The range covers all recorded samples.
Host counters include kernel work, iperf, control commands, and production traffic.

| Client | Transport | Client CPU s/Gbit | Hattori CPU s/Gbit | Relay CPU s/Gbit | Client RSS MiB | Hattori RSS MiB | Relay RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| osku | QUIC/H3 | 1.82 | 2.42 | 4.24 | 34.20 | 39.97 | 29.51 |
| osku | H2/TLS | 1.23 | 3.83 | 3.04 | 40.72 | 38.26 | 24.46 |
| osku | WSS | 2.50 | 4.70 | 4.04 | 38.25 | 22.82 | 34.48 |
| yutoms | QUIC/H3 | 4.88 | 8.64 | 8.95 | 32.46 | 26.06 | 25.66 |
| yutoms | H2/TLS | 13.67 | 22.28 | 16.04 | 30.62 | 22.62 | 21.09 |
| yutoms | WSS | 12.22 | 20.31 | 14.75 | 30.87 | 35.38 | 20.21 |

osku sampled RSS: 29.8–41.1 MiB.

yutoms sampled RSS: 28.2–32.8 MiB.

hattori sampled RSS: 21.8–42.7 MiB.

s6916 sampled RSS: 18.8–36.7 MiB.

CPU sampling windows span 24.016–27.727 seconds.

18 process sampling windows exceed the estimated host active CPU total.
Host active CPU estimates cannot establish VPN CPU efficiency.

| Client | Transport | Streams | Reverse TCP retransmissions | Loaded ICMP RTT range, ms | Replies / probes |
| --- | --- | ---: | --- | ---: | ---: |
| osku | QUIC/H3 | 1 | [20286, 20922] | 23.3–57.6 | 12 / 12 |
| osku | QUIC/H3 | 4 | [58294, 53447] | 23.0–72.0 | 12 / 12 |
| osku | H2/TLS | 1 | [1, 1] | 24.1–1167.4 | 12 / 12 |
| osku | H2/TLS | 4 | [6, 6] | 375.2–1592.1 | 9 / 12 |
| osku | WSS | 1 | [1, 1] | 216.9–1010.3 | 12 / 12 |
| osku | WSS | 4 | [5, 5] | 256.2–1819.2 | 10 / 12 |
| yutoms | QUIC/H3 | 1 | [193, 196] | 27.5–161.3 | 12 / 12 |
| yutoms | QUIC/H3 | 4 | [28, 58] | 28.4–32.6 | 12 / 12 |
| yutoms | H2/TLS | 1 | [4, 1] | 28.2–1264.0 | 12 / 12 |
| yutoms | H2/TLS | 4 | [7, 4] | 180.1–1429.7 | 9 / 12 |
| yutoms | WSS | 1 | [1, 1] | 26.8–640.2 | 12 / 12 |
| yutoms | WSS | 4 | [50, 27] | 511.0–2038.6 | 10 / 12 |

Mac TCP retransmission counts are unavailable. Yutoms client counters describe the loopback connection.
Sender and receiver byte differences at termination are not packet loss.
ICMP loss and TCP retransmissions do not identify underlay loss independently.
Failed transfers remain in the result and are excluded from completed-transfer throughput and CPU aggregates.

Receiver/sender byte ratios at termination, across both stream counts and directions:

| Client | Transport | Minimum | Maximum |
| --- | --- | ---: | ---: |
| osku | QUIC/H3 | 97.3% | 99.8% |
| osku | H2/TLS | 14.3% | 100.0% |
| osku | WSS | 14.3% | 100.0% |
| yutoms | QUIC/H3 | 93.1% | 97.8% |
| yutoms | H2/TLS | 14.3% | 96.3% |
| yutoms | WSS | 14.3% | 96.2% |

Sender bytes count socket writes. Some bytes remain buffered when the timed test ends.
These ratios do not measure packet loss. They expose substantial undelivered buffered data in the slow H2/WSS trials.
A completed iperf process does not establish full delivery of every byte accepted by its sender socket.
H2/WSS throughput remains poor. Tailscale throughput parity has not been reached.

## Artifacts and cleanup

Artifacts: `benchmark-results/eth0-deadlock-fix-20260920/`.
Audit: `benchmark-results/.work/eth0-deadlock-fix-20260920.jsonl`.
Production LowTier services were not replaced.

Cleanup passed. Production identities and interface sets match. Task processes, files, interfaces, and firewall rules were removed.
