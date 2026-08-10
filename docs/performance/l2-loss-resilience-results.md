# ETQ4 L2 loss-resilience results

## Test boundary

These measurements ran on 2026-07-19 in the `colima-lowertier-l2` QEMU
backend on an aarch64 VM with four vCPUs. Both container egress interfaces used
Linux netem with 140 ms mean delay, 40 ms jitter, and 3% loss. The LowTier
underlay was QUIC, the port mode was `l2-tun`, the offered UDP payload rate was
5 Mbit/s, and Brutal was capped at 10 Mbit/s. Each measured direction ran for
10 seconds after a two-second iperf omit period.

The final image used ETQ4 ACK ranges, fragment-selective NACKs, critical L2
duplication, a 40 ms maximum partial-block FEC deadline, and the established
`reed-solomon-simd` implementation. The matrix used FEC off, 16+2, and 16+3.
TCP workloads and the separate TCP CPU probe were disabled for this focused
comparison. Raw bridge TCP remains a substrate diagnostic, not a 10GbE claim.

Artifacts:

- independent loss: `/tmp/lowertier-etq4-final-independent-20260719`
- 75% correlated burst loss: `/tmp/lowertier-etq4-final-burst-20260719`
- final-image lossy smoke: `/tmp/lowertier-etq4-final-image-smoke-20260719`
- alternate-connection run: `/tmp/lowertier-etq4-alternate-path-clean-20260719`

Both `workload-errors.tsv` files contain only their header. The LowTier logs
contain no panic, invalid ETQ4 record, peer receive error, or QUIC protocol
error. A metrics snapshot whose reason is `connection_drop` is the expected
harness shutdown after `SIGTERM`, not a workload disconnect.

## Independent 3% loss

| Profile | Forward Mbit/s | Reverse Mbit/s | RTT average ms | RTT maximum ms |
| --- | ---: | ---: | ---: | ---: |
| FEC off | 4.985 | 5.005 | 314.936 | 817.352 |
| 16+2 | 4.998 | 4.989 | 279.018 | 372.866 |
| 16+3 | 4.993 | 4.992 | 267.621 | 342.775 |

The iperf reverse FEC-off loss percentage is slightly negative because sender
and receiver interval accounting differ at the short test boundary. Received
bits per second and ETQ4 counters are the stable comparison.

Latest endpoint snapshots:

| Profile | Endpoint | Source symbols | Parity symbols | Symbol overhead | Recovered symbols | Unrecoverable blocks | Queue drops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16+2 | A | 11,609 | 1,572 | 13.54% | 1,160 | 38 | 0 |
| 16+2 | B | 10,195 | 1,354 | 13.28% | 1,174 | 39 | 0 |
| 16+3 | A | 11,585 | 2,346 | 20.25% | 1,365 | 21 | 0 |
| 16+3 | B | 10,096 | 2,019 | 20.00% | 1,619 | 36 | 0 |

16+2 cut average unloaded RTT by 35.9 ms and the observed maximum by 444.5 ms
relative to FEC off. 16+3 recovered more symbols and reduced the observed
maximum by another 30.1 ms, but it spent about 50% more parity symbols than
16+2 and did not improve application throughput.

## Correlated burst loss

| Profile | Forward Mbit/s | Reverse Mbit/s | RTT average ms | RTT maximum ms |
| --- | ---: | ---: | ---: | ---: |
| FEC off | 5.002 | 4.996 | 283.783 | 352.905 |
| 16+2 | 4.985 | 4.994 | 274.394 | 359.695 |
| 16+3 | 5.002 | 4.997 | 273.616 | 348.678 |

| Profile | Endpoint | Source symbols | Parity symbols | Symbol overhead | Recovered symbols | Unrecoverable blocks | Queue drops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16+2 | A | 11,585 | 1,566 | 13.52% | 897 | 2 | 0 |
| 16+2 | B | 11,856 | 1,572 | 13.26% | 1,222 | 2 | 0 |
| 16+3 | A | 11,587 | 2,346 | 20.25% | 1,345 | 2 | 0 |
| 16+3 | B | 11,869 | 2,358 | 19.87% | 1,693 | 2 | 0 |

All profiles sustained the offered rate under this correlated-loss trace.
16+2 reduced average unloaded RTT by 9.4 ms. 16+3 provided no material
throughput or average-latency gain over 16+2, while retaining its roughly 20%
symbol overhead.

## Decision

Configured Brutal plus 16+2 is the recommended known-capacity lossy L2
profile. It passed the 4.75 Mbit/s bidirectional gate in both matrices, had no
bounded-queue drops, recovered missing symbols, and materially reduced the
independent-loss RTT tail. FEC off remains available. 16+3 remains an explicit
high-loss benchmark option, not the default, because this matrix did not
justify its added parity cost for normal 3% loss.

The single-path gate was therefore passed before alternate-path parity was
implemented.

## Alternate-connection parity gate

The final ARM64 image was then run with two authenticated QUIC connections
between separate `172.31.10.0/24` and `172.32.10.0/24` Docker networks. With
node B sending a 5 Mbit/s L2-TUN UDP workload for 10 measured seconds, iperf
reported 5.000 Mbit/s, zero overlay loss, and 0.357 ms jitter. The latest EAP1
atomic snapshot reported:

| Wrapped sources | Source bytes | Parity blocks | Parity records | Parity bytes | Send failures | No-path skips |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5,755 | 7,996,046 | 366 | 732 | 1,017,800 | 0 | 0 |

Every completed 16+2 block therefore emitted exactly two parity records on the
selected second QUIC connection. A separate authenticated in-process test
holds the primary connection fixed, verifies that its 16 source frames arrive
exactly once, and observes at least two transmissions on the distinct-IP
secondary connection. Same-IP port changes, recovered identity mismatches,
denied CIDRs, and active interface-deny configurations are rejected.

The container result proves a distinct remote QUIC surface, not a distinct
physical NIC. In this Docker topology, Linux retained the same local source and
egress interface while routing the two remote subnets. A dual-NIC hardware
claim therefore remains out of scope for this artifact.
