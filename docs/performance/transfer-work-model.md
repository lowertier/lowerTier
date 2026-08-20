# LowTier transfer-work reduction program

Updated: 2026-08-20

## Objective

Maximize stable delivered payload throughput while preserving authenticated routing control, per-flow ordering, bounded memory, replay protection, direct/relay interoperability, and useful operation on high-RTT paths.

The primary efficiency model is

\[
 u(L,B)=\beta_0+\beta_1L+\frac{\beta_2}{B},
\]

where \(u\) is CPU seconds per packet, \(L\) is inner packet length, and \(B\) is effective batch size. The production objective is stable mean goodput and bounded tail latency, rather than peak-only throughput.

## Work ledger

| # | Work item | State | Acceptance gate |
|---:|---|---|---|
| 1 | Authenticate critical classification before local speed policy | Complete | Focused BGP and critical-route regressions pass |
| 2 | Sampled service-time, queue, stall, batch, and syscall telemetry | Complete | Prometheus export and deterministic bounded-cardinality sampling are active |
| 3 | Packet-size and batch-size sweep; fit \(\beta_0,\beta_1,\beta_2\) | Complete initial fit | Reproducible artifacts are in `target/gpt-work-model/` |
| 4 | Portable Linux multiqueue independent of virtio offload | Complete | Multiple portable TUN queues operate with Linux TUN offload disabled |
| 5 | One flow-stable bounded writer per TUN queue | Complete | Stable shard-to-queue mapping and independent bounded writer state are covered by regressions |
| 6 | Fixed-array DRR with flow-preserving control priority | Complete | 64 fixed shards preserve same-flow FIFO and bound control bursts |
| 7 | Independent TUN writes through `io_uring` | Implemented; runtime retention pending | Native Linux kernel regression passes; the current container profile still reports zero `io_uring_submit` operations |
| 8 | Receiver-clocked pacing under measured destination pressure | Complete; explicit opt-in | Two opposite-order 160 ms A/B pairs reduce stalls but fail the all-directions default-on repeatability gate; enable with `LOWTIER_ENABLE_RECEIVER_PACING=1` |
| 9 | 160 ms RTT validation with zero artificial loss | Complete | Controlled portable and `io_uring` profiles record throughput, CPU, loaded latency, and pressure telemetry |
| 10 | Conditional FEC from measured RTT/loss | Pending loss matrix | Default parity remains zero until the 0.1% and 0.5% dual-path economic gate is measured |

## Measurement matrix

Packet lengths: 64, 256, 512, 1024, and effective MTU payload.

Batch caps: 1, 4, 16, and 64.

Flow counts: 1 and 4 initially; 16 for scheduler stress.

Path profiles: clean local, 160 ms RTT with zero loss, then 0.1% and 0.5% random loss only after the zero-loss gate.

For each run record delivered bits/s, packets/s, retransmissions, CPU seconds, queue occupancy, queue sojourn/stall time, packets per receive/write syscall, effective batch size, and direct-versus-relay path.

## Current reference

The controlled ARM64 healthy ceiling is approximately 4.6–4.8 Gbit/s. Later multi-flow runs exhibit a lower-throughput state with reduced CPU utilization, so queue stability and feedback behavior are the immediate priority.
