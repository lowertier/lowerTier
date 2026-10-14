# CPU and memory changes, 2026-09-20

This report compares the saved baseline with four combined changes.
The final network measurements are recorded in `benchmark-results/cpu-memory-20260920/final/`.

## Implementation

1. Reuse the pinned QUIC receive future and packet batch containers.
2. Bound incomplete fragment storage by bytes, process budget, count, and expiry.
3. Give local peer-center jobs the current local identity and the registered server state.
4. Remove local peer-center serialization and task handoffs, and the temporary receive-prefetch queue.

Remote peer-center calls retain RPC authentication.
Local calls still require an eligible administrator and pass the server identity checks.
Credential peers cannot become a local center.
QUIC, H2, and WSS authentication and TLS exporter binding remain in place.

## Work and memory model

Let `B` be received batches per second and `k` be packets per batch, where `1 <= k <= 64`.
The measured native type sizes are 256 bytes per packet descriptor, 24 bytes per batch container, and 104 bytes per receive future.
The old receive path allocates one future per batch.
It also allocates a descriptor vector when `k < 64`.
The old prefetch path allocates another queue during each direct batch delivery.

The revised receive path keeps the future allocation.
The existing 32-container pool now accepts capacities from 1 through 64.
An empty pool allocates only the requested capacity.
Retained descriptor storage stays within 512 KiB, excluding container and allocator overhead.
The persistent prefetch queue replaces each temporary queue.
The queue bound and FIFO order remain unchanged.

The allocation fixture measures the actual batch container operations with a counting allocator.
It uses a native debug build and a counted system allocator.
It excludes packet payload allocation, network processing, and elapsed-time comparisons.
The network measurements use optimized Linux builds with the existing mimalloc allocator.
For 10,000 iterations, warmed batches of 1, 8, or 32 packets need no container allocations at depths through 32.
At depth 64, allocation count and requested bytes fall by half for those batch sizes.
Full 64-packet batches retain their previous allocation behavior.
The old prefetch queue allocates 10,000 times; the persistent queue allocates zero times inside the measured loop.

The first candidate always requested 64 descriptor slots.
The fixture exposed excess allocation bytes when more than 32 small batches were live.
The final candidate corrects this behavior without increasing the pool size.
The first candidate and its measurements remain separate from the final results.

Incomplete fragment storage has these bounds:

- 64 assemblies per connection.
- 2 MiB of payload and fragment-table storage per connection.
- The existing shared 64 MiB process memory governor.
- A fixed 15-second lifetime from the first fragment.

Stored fragments own their payload bytes.
This adds a fragment copy but prevents a small slice from retaining a complete receive slab.
A test confirms that a 64-byte slice releases its original 64 KiB owner immediately.
Its retained payload and two-slot fragment table occupy 128 charged bytes.
Completed packets receive one exact-size output allocation with a separate peak reservation.

The pressure fixture submits 16,256 incomplete fragments for each payload size.

| Fragment payload | Peak charged bytes | Charged bytes after expiry |
| --- | ---: | ---: |
| 64 bytes | 1,562,624 | 0 |
| 512 bytes | 2,097,152 | 0 |
| 1,200 bytes | 2,097,120 | 0 |

These charges exclude map, queue, and allocator overhead.
Idle expiry requires the receive stream to be polled.
Downstream backpressure can delay expiry, but cannot increase the byte bound.

## Measurement conditions

The endpoint pair is `s6916` and UTM OpenWrt.
Both versions use isolated processes, the same private test network, and direct QUIC over public IPv6.
The configured MTU is 1,280; the effective TAP MTU is 1,260.
TCP uses MSS 1,200.
Both endpoints use iperf3 3.17.1.
The server restarts before every transfer to avoid its stale idle timer.

The final order is baseline, candidate, candidate, baseline.
Each version has two runs of each workload:

- TCP with one and four streams, upload and download, 20 seconds each.
- UDP with 1,200-byte payloads at 350 Mbit/s, both directions, 10 seconds each.
- UDP with 512-byte payloads at 100 Mbit/s, both directions, 10 seconds each.
- Idle sampling before traffic for 30 seconds and after traffic for 20 seconds.

Process CPU, thread runtime, host CPU, RSS, swap, and memory availability are sampled every two seconds.
CPU windows include four seconds beyond each nominal transfer, plus sampling overhead.
CPU seconds per delivered Gbit use receiver byte counts.
Thread runtime cross-checks process ticks.
The thread sum covers threads present at both sample-window endpoints; transient threads are excluded.
Process ticks include all process threads.
The analysis requires complete CPU and metric records before it aggregates a transfer.
Host CPU includes iperf, kernel work, monitoring, and existing production services.
RSS is process-wide resident memory, not a heap-only measurement.
`VmHWM` is the process lifetime maximum, not a separate maximum for each workload.

UDP loss uses receiver packet counts.
Upload counts come from the server receiver report because combined iperf JSON can report inconsistent loss fields.
The analysis verifies that delivered bytes equal delivered packet count times payload length.
Raw sender and receiver durations remain available.
ICMP latency samples run every two seconds during each transfer.

The final run also records UTM dataplane stage samples before and after each transfer.
The default sampling period is one selected stage start per 256 calls on each thread.
Stage durations are elapsed time within instrumented code and can include waiting.
They are not exclusive CPU profiles.
The `perf` launcher is present on `s6916`, but its backend executable is absent.

## Verification and limits

All 122 focused tests passed after the final source changes.
The checks cover fragment pressure and expiry, batch ownership, QUIC delivery, local authorization, H2, WSS, TLS binding, and shared memory admission.
Both Linux release targets build: x86_64 musl and aarch64 musl.

An earlier QUIC test run hit an existing shutdown race after successful packet delivery.
The receive supervisor can exit at peer EOF before the other writer closes.
The isolated test, the next complete QUIC run, and the final focused run passed.
The failed log remains in the audit trail.

The public Cloudflare probe was excluded because project tests must use local test destinations.
Local HTTP/3 origin, decoy forwarding, unauthorized routing, and TCP passthrough tests passed.
Caddy is not installed locally, so this run does not validate an actual Caddy deployment.

## Final results

All 32 transfers completed.
The combined changes reduce allocation work, but do not establish a general CPU or throughput improvement.
The table gives median receiver throughput from two trials per version.
Upload means UTM to S6916.

| TCP workload | Baseline Mbit/s | Candidate Mbit/s |
| --- | ---: | ---: |
| One stream, upload | 410.7 | 266.7 |
| One stream, download | 461.7 | 458.9 |
| Four streams, upload | 417.5 | 419.3 |
| Four streams, download | 464.3 | 462.2 |

The candidate one-stream uploads were 124.4 and 409.0 Mbit/s.
The slower trial started near 350 Mbit/s, then fell to about 98 Mbit/s.
It reported no TCP retransmissions.
Its BBR congestion window decreased while the receiver window remained available.
Application CPU was low, and the LowTier pacing configuration did not explain the limit.
The cause remains unresolved.
The follow-up BBR/CUBIC experiment was cancelled before traffic when the requested endpoint matrix changed.
The slow trial remains in all aggregates.

Across all TCP transfers, CPU seconds are divided by total delivered Gbit.
RSS values are medians of the per-transfer RSS medians.

| Endpoint | Baseline CPU s/Gbit | Candidate CPU s/Gbit | Baseline RSS KiB | Candidate RSS KiB |
| --- | ---: | ---: | ---: | ---: |
| S6916 | 2.783 | 2.776 | 31,872 | 34,902 |
| UTM | 1.651 | 1.708 | 48,804 | 32,068 |

UTM RSS decreased during TCP traffic, while S6916 RSS increased.
Post-traffic candidate UTM RSS also varied: 52,460 and 32,996 KiB.
The results do not establish a persistent process-wide memory reduction on both endpoints.
Host CPU accounting sometimes reported less CPU time than the measured LowTier process.
Host totals therefore cannot establish a CPU improvement.
Process ticks and thread runtime provide independent, consistent process CPU measurements.

| UDP workload | Baseline Mbit/s | Candidate Mbit/s | Baseline loss | Candidate loss |
| --- | ---: | ---: | ---: | ---: |
| 1,200 bytes at 350 Mbit/s, upload | 309.1 | 310.3 | 11.57% | 11.16% |
| 1,200 bytes at 350 Mbit/s, download | 349.9 | 349.8 | 0.031% | 0.042% |
| 512 bytes at 100 Mbit/s, upload | 92.2 | 92.3 | 7.73% | 7.54% |
| 512 bytes at 100 Mbit/s, download | 100.0 | 100.0 | 0% | 0% |

These UDP figures measure inner application traffic over QUIC.
They do not test a raw UDP underlay.
The upload loss remains substantial and prevents a claim of reliable delivery at the offered rates.
Candidate logs contain no repeated local peer-center authentication errors.
Baseline logs contain the errors at the periodic job intervals.

Cleanup passed after the complete-artifact check.
Task-owned processes, interfaces, firewall rules, remote files, and private test configurations were removed.
Production process start times, binary hashes, and firewall tables match the saved pre-test state.
Raw measurements, failed attempts, source snapshots, and baseline binaries remain in the benchmark directory.
