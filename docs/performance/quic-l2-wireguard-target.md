# QUIC L2 WireGuard performance target

Status date: 2026-08-30

## Goal

LowTier QUIC L2 must reach at least 90 percent of kernel WireGuard throughput.
Each matched clean workload must pass the target independently.
An aggregate result cannot compensate for a failed workload.

## Reference boundary

The reference used two temporary containers in one four-CPU ARM64 QEMU Colima VM.
Both containers used the existing `lowertier-throughput:local` runtime image.

The reference used kernel WireGuard from Linux 6.8.0-117-generic.
The inner MTU was 1,360 bytes.
Kernel BBR controlled TCP at both endpoints.
Each workload used three ten-second measurements after a two-second omit period.
Docker image builds and pulls were disabled.

The raw bridge reached 29.615 Gbit/s with one TCP flow.
It reached 51.966 Gbit/s with four TCP flows.
The substrate did not limit the clean WireGuard result.

## Saved WireGuard target

For workload \(k\), define the LowTier target as

\[
T_k = 0.90 \times \operatorname{median}(W_k),
\]

where \(W_k\) contains the saved kernel WireGuard throughput samples.

| Direction | TCP flows | WireGuard samples in Gbit/s | WireGuard median | LowTier 90% target |
| --- | ---: | --- | ---: | ---: |
| Forward | 1 | 6.475, 6.565, 6.542 | 6.542 Gbit/s | 5.888 Gbit/s |
| Forward | 4 | 5.483, 5.383, 5.397 | 5.397 Gbit/s | 4.857 Gbit/s |
| Reverse | 1 | 6.650, 6.475, 6.624 | 6.624 Gbit/s | 5.962 Gbit/s |
| Reverse | 4 | 5.555, 5.441, 5.393 | 5.441 Gbit/s | 4.897 Gbit/s |

The saved unloaded WireGuard RTT averaged 1.404 ms.
All twelve WireGuard overlay workloads completed without an iperf error.

## Acceptance gate

A target-validation run must use at least five interleaved samples for each workload.
The run must use the same host class, VM size, MTU, BBR configuration, and workload duration.
The raw substrate must remain above the required target throughput.

LowTier must meet all four throughput targets in the table.
LowTier must not reconnect during a workload.
LowTier must not drop reliable traffic silently.
Every iperf workload must complete.
Correctness and encryption checks must pass.

The final report must include received throughput, retransmissions, RTT, CPU cores per Gbit, and resident memory.
The 90 percent milestone does not replace the normal regression gate.
Every intermediate change must still beat its matched LowTier baseline.

## Impaired-path guardrail

The saved WAN test used 140 ms mean delay and 40 ms random jitter on each endpoint egress.
It also used 3 percent independent random packet loss on each endpoint egress.
Measured WireGuard RTT averaged 368.538 ms and observed 6 percent ping loss.

WireGuard reached 6.555 Mbit/s forward and 6.575 Mbit/s reverse with four TCP flows.
These values are diagnostic guardrails and not absolute optimization targets.
Random queue effects constrained the raw substrate and the one-flow workloads.

## Evidence

The raw results stay in the ignored `benchmark-results` directory.
The clean target table comes from `wireguard-bbr-clean-complete/throughput.tsv`.
The impaired guardrail comes from `wireguard-bbr-wan/throughput.tsv`.
The result summary is stored in `summary.md` in the same directory.
