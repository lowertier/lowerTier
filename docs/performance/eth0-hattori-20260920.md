# LowTier through Hattori eth0, 2026-09-20

LowTier used Hattori `eth0` through an isolated S6916 relay.
This replaces the earlier benchmark path through `pppoe-bbd`.
Production LowTier configurations remain unchanged.

## Path and configuration

Both endpoint instances connect to the public S6916 address `193.32.149.82`.
Hattori uses source `192.168.64.23`, gateway `192.168.64.1`, and interface `eth0`.
S6916 is also one of the peer relays observed in the Tailscale comparison.
The other observed Tailscale relay was `18.183.209.161`.
The LowTier path is Mac → S6916 → Hattori, in both traffic directions.
SSH uses Tailscale for control. The LowTier data connections use public IPv4.

Hattori sets `bind_device = false` so the operating system selects its normal route.
A temporary nftables table drops traffic to the test relay ports on any other output interface.
Per-transfer counters confirm eth0 ingress and egress traffic.
The data-direction underlay byte count exceeds delivered application bytes in every validated completed transfer.
The non-eth0 output counters remain zero.
The experiment does not independently count or block matching non-eth0 ingress.

The test uses the same candidate binaries as the earlier LowTier matrix.
Binary hashes are saved in `binary-hashes.json` and checked against the staged binaries.
Each instance uses a fresh private network identity, encryption, TLS authentication, and two runtime workers.
Automatic P2P and UPnP are disabled.
S6916 uses `no_tun = true`; it creates no test interface.
Hattori uses a test TAP. Osku uses a test utun. Yutoms remains in userspace mode.
Peer records confirm a direct relay connection with the selected protocol on each leg.
The endpoint route is `relay(2)` throughout the validated completed tests.
A failed QUIC trial lost the Hattori peer at the relay.

The retained listeners are `quic://193.32.149.82:14392`, `tcp://193.32.149.82:14390`, and `wss://193.32.149.82:14393/ws`.
The `tcp://` scheme selects H2 over TLS.
Configured MTU is 1280. The measured Hattori TAP and Osku utun MTU is 1260.
The Tailscale interfaces use MTU 1280.

## Measurement conditions

All tests use the same iperf3 3.17.1 binaries as the previous endpoint comparison.
The matrix contains 48 transfer attempts: two clients, three transports, one or four streams, both directions, and two 20-second trials.
35 attempts completed and passed record validation. 13 attempts failed.
Each transfer starts a fresh Hattori iperf server.
Throughput uses receiver bytes and receiver duration. Every complete trial remains in the aggregate.
Yutoms uses the built-in TCP forward at `127.0.0.1:15209` through smoltcp.
The experimental overlay stream is disabled.
The selected underlay applies to both relay legs.
Tests run sequentially. Production and WAN traffic are not controlled.

## Throughput

Values are Mbit/s. Cells with two completed trials show the median and full range.
A single completed trial is marked explicitly. Failed attempts are listed separately.

| Client | Transport | Streams | Mac → Hattori | Hattori → Mac |
| --- | --- | ---: | ---: | ---: |
| Yutoms | QUIC/H3 | 1 | 18.7 (18.1–19.4) | 10.9 (10.5–11.3) |
| Yutoms | QUIC/H3 | 4 | 101.5 (100.1–103.0) | 126.3 (126.1–126.4) |
| Yutoms | H2/TLS | 1 | 18.6 (18.5–18.7) | 0.29 (0.26–0.31) |
| Yutoms | H2/TLS | 4 | 4.6 (4.2–5.0) | 0.16 (0.16–0.16) |
| Yutoms | WSS | 1 | 18.1 (18.1–18.2) | 0.31 (0.26–0.37) |
| Yutoms | WSS | 4 | 5.2 (4.4–6.1) | 0.24 (0.21–0.26) |
| Osku | QUIC/H3 | 1 | 27.1 (13.2–41.0) | failed |
| Osku | QUIC/H3 | 4 | failed | failed |
| Osku | H2/TLS | 1 | failed | 0.26 (0.26–0.26) |
| Osku | H2/TLS | 4 | failed | 0.26 (0.21–0.31) |
| Osku | WSS | 1 | 36.0 (1 completed; 1 failed) | 0.29 (0.26–0.31) |
| Osku | WSS | 4 | failed | 0.21 (0.21–0.21) |

Four-stream comparison with the earlier Tailscale trials:

| Client | Transport | Mac → Hattori Mbit/s | Hattori → Mac Mbit/s |
| --- | --- | ---: | ---: |
| Yutoms | Tailscale | 213.2 | 372.1 |
| Yutoms | QUIC/H3 | 101.5 | 126.3 |
| Yutoms | H2/TLS | 4.6 | 0.16 |
| Yutoms | WSS | 5.2 | 0.24 |
| Osku | Tailscale | 249.8 | 420.8 |
| Osku | QUIC/H3 | failed | failed |
| Osku | H2/TLS | failed | 0.26 |
| Osku | WSS | failed | 0.21 |

The Tailscale trials used peer relays, including S6916, and Hattori eth0.
Some Tailscale probes used a different relay. One transfer changed relay during measurement.
The trials are sequential, not interleaved, and the effective MTUs differ.
These values compare endpoint configurations. They do not isolate transport implementation costs.

LowTier has not established Tailscale throughput parity or reliable completion on this route.

## CPU and memory

Each transfer records 25 process and host samples with a one-second delay between samples.
The observed sampling windows span 24.029–27.609 seconds.
The windows include time after traffic stops.
Process CPU is measured from cumulative counters and normalized by delivered Gbit.
The table includes the test LowTier process on each endpoint and on S6916.
CPU and RSS aggregates include validated completed transfers only.
RSS shows the median of per-transfer medians. It is not an exact lifetime peak.
Host counters include kernel work, iperf, control commands, and unrelated production traffic.
Host totals are retained as diagnostic data; they do not establish matched VPN CPU efficiency.

| Client | Transport | Client CPU s/Gbit | Hattori CPU s/Gbit | Relay CPU s/Gbit | Client RSS MiB | Hattori RSS MiB | Relay RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Yutoms | QUIC/H3 | 4.80 | 8.31 | 8.96 | 32.5 | 38.9 | 27.9 |
| Yutoms | H2/TLS | 13.72 | 22.35 | 16.02 | 31.0 | 36.1 | 33.6 |
| Yutoms | WSS | 12.37 | 20.00 | 14.39 | 31.0 | 22.4 | 20.2 |
| Osku | QUIC/H3 | 2.86 | 8.76 | 9.56 | 32.0 | 27.5 | 27.1 |
| Osku | H2/TLS | 41.48 | 103.47 | 80.59 | 30.4 | 28.2 | 19.9 |
| Osku | WSS | 3.07 | 7.61 | 5.73 | 30.9 | 22.0 | 19.5 |

Sampled RSS ranges across validated completed transfers:

| Host | Minimum MiB | Maximum MiB |
| --- | ---: | ---: |
| Yutoms | 28.8 | 32.9 |
| Osku | 29.6 | 35.0 |
| Hattori | 21.9 | 41.5 |
| S6916 | 18.7 | 37.2 |

Hattori CPU steal spans 0.000–0.000% in these sampling windows.

S6916 CPU steal spans 0.063–0.787% in these sampling windows.

9 process sampling windows exceed the estimated host active CPU total.
Those host estimates cannot support CPU efficiency claims.
Tailscale counters include shared production daemons and a separate Yutoms forwarding helper.
The earlier Tailscale test did not sample relay CPU. A complete three-host CPU comparison is unavailable.

## Delivery, latency, and retransmissions

35 TCP transfers completed. Each includes three overlay ICMP probes during traffic.
ICMP latency measures the complete relay path. Peer heartbeat latency measures each direct relay leg.
The displayed 1000 ms latency on some relayed CLI rows is not used as a measured RTT.
Hattori reverse TCP retransmission counts describe the overlay TCP connection.
Mac retransmission counts are unavailable. Yutoms local client counters would describe its loopback connection.
Sender and receiver byte differences at termination are not packet loss.

| Client | Transport | Streams | Reverse TCP retransmissions, two trials | Loaded ICMP RTT range, ms | ICMP replies / probes |
| --- | --- | ---: | --- | ---: | ---: |
| Yutoms | QUIC/H3 | 1 | 187, 202 | 25.8–128.7 | 12 / 12 |
| Yutoms | QUIC/H3 | 4 | 63, 78 | 25.1–30.6 | 12 / 12 |
| Yutoms | H2/TLS | 1 | 4, 2 | 27.5–957.8 | 12 / 12 |
| Yutoms | H2/TLS | 4 | 20, 14 | 304.2–1699.6 | 9 / 12 |
| Yutoms | WSS | 1 | 1, 1 | 29.2–1005.2 | 12 / 12 |
| Yutoms | WSS | 4 | 24, 19 | 380.7–1818.8 | 12 / 12 |
| Osku | QUIC/H3 | 1 | unavailable | 24.3–25.9 | 6 / 6 |
| Osku | QUIC/H3 | 4 | unavailable | unavailable | 0 / 0 |
| Osku | H2/TLS | 1 | 1, 1 | 363.7–810.5 | 6 / 6 |
| Osku | H2/TLS | 4 | 5, 6 | 439.4–935.3 | 4 / 6 |
| Osku | WSS | 1 | 1, 1 | 25.6–1281.6 | 9 / 9 |
| Osku | WSS | 4 | 5, 6 | 284.5–1665.6 | 5 / 6 |

Failed attempts remain excluded from completed-transfer throughput and CPU aggregates. Their failures remain part of the result.

| Attempt | Error | Locally measured partial receiver bytes |
| --- | --- | ---: |
| osku-h2-r1-p1-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-h2-r1-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-h2-r2-p1-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-h2-r2-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-quic-r1-p1-from-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | 51204832 |
| osku-quic-r1-p4-from-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | 311526936 |
| osku-quic-r1-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-quic-r2-p1-from-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | 130356488 |
| osku-quic-r2-p4-from-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | 188698304 |
| osku-quic-r2-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-wss-r1-p1-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-wss-r1-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |
| osku-wss-r2-p4-to-hattori | unable to send control message - port may not be available, the other side may have stopped running, etc.: Broken pipe | unavailable |

The first failed reverse QUIC attempt delivered data briefly, then stalled.
The relay lost its Hattori peer, and routing RPC calls timed out.
The test process did not exit within 15 seconds after SIGTERM.
The runner verified the executable path before force-stopping that task process.
The remaining cases resumed with fresh test connections. No failed attempt was replaced by a successful retry.

## Source model and limits

For delivered payload D and packet payload P, each relay leg handles approximately D/P packets before retransmissions.
At 500 Mbit/s and about 1220 payload bytes per inner TCP packet, this is roughly 51,000 packets/s per leg.
The relay receives and sends this traffic through authenticated underlay connections.
This adds forwarding work and transport encryption on the relay.
Yutoms also copies data through local TCP and schedules the smoltcp reactor.
Its overlay TCP sockets use 128 KiB receive buffers and 128 KiB transmit buffers.
Four data sockets therefore reserve about 1 MiB before the control connection and other overhead.
At 25 ms RTT, a 128 KiB window gives an approximate 41.9 Mbit/s single-stream limit.
Loss, scheduling, acknowledgments, and congestion control can lower that rate.
This model does not explain all measured differences and is not a profile-derived cause.
No buffer, thread, cache, or packet threshold tuning was applied.

## Setup recovery and cleanup

The first staging attempt had an incomplete SSH ControlPath option. The corrected attempt completed.
The first QUIC topology check failed before benchmark traffic.
The strict underlay source filter rejected the private eth0 address for the public relay destination.
Source inspection found that `eligible_bind_addrs` clears IPv4 candidates with fewer than 16 common address-prefix bits.
An active policy then rejects the empty candidate list.
The test uses normal route selection and a task-specific output firewall rule instead.
No transport source code changed during this experiment.
The failed setup and successful recovery remain in the audit record.

Artifacts: `benchmark-results/eth0-hattori-20260920/`.
Audit: `benchmark-results/.work/eth0-hattori-20260920.jsonl`.

Cleanup passed.
All test processes, temporary directories, private test configurations, interfaces, firewall rules, and SSH control sockets were removed.
Production LowTier identities and the saved interface sets match the initial state.
Production LowTier configurations remain unchanged.
