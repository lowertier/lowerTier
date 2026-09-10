# Current dataplane throughput architecture

Updated: 2026-09-10.

## Objective

Deliver 10 Gbit/s-class encrypted TCP throughput while preserving authenticated routing, per-flow FIFO, replay protection, bounded memory, cancellation, delivery-error propagation, and responsiveness.

## Production design

- NIC ingress uses one fair admission owner across all TUN queues.
- `NicIngressQueue` bounds active flows, packets, and retained bytes.
- Delivery uses persistent fixed workers. A worker slot owns one admitted batch until completion; the admission queue preserves same-flow FIFO.
- The ingress owner performs a cooperative Tokio yield after 256 KiB of received data.
- Batch crypto/filter work stays inline and ordered. The async crypto-slot experiment and per-batch Rayon crypto path have been removed.
- Packet batching uses the production maximum directly; the runtime batch-size experiment knob has been removed.
- Linux queue/offload behavior remains capability-driven so unsupported kernel features degrade safely at the platform boundary.

## Retained ablation result

The production choice comes from a balanced 2x2 H2/TCP ablation with four distinct Rust 1.95 release binaries, two 30-second measurements per cell, four TCP lanes, 40 ms one-way netem delay, and 0.1% loss.

| Delivery | Yield | Forward median | Reverse median |
|---|---:|---:|---:|
| persistent | 1 MiB | 5.796 Gbit/s | 5.220 Gbit/s |
| per-batch task | 1 MiB | 5.979 Gbit/s | 5.594 Gbit/s |
| persistent | 256 KiB | **6.219 Gbit/s** | **5.749 Gbit/s** |
| per-batch task | 256 KiB | 5.788 Gbit/s | 5.251 Gbit/s |

Across the factorial, persistent delivery contributed +2.05% forward and +1.07% reverse goodput. Changing the cooperative-yield interval to 1 MiB reduced goodput by 1.89% forward and 1.65% reverse. The interaction is material, so the retained pair is persistent delivery plus 256 KiB yielding.

All observed request classes delivered 100% in the factorial runs. Loaded p99 latency for the retained cell remained high in this four-lane environment (about 394 ms forward and 360 ms reverse median across the two runs), so transfer-speed progress does not close the responsiveness work.

## Verification

The fallback-free production snapshot passed the focused ingress, link-envelope, and replay-window tests and built successfully with Rust 1.95 offline/locked release settings. Final live-main validation is required after the retained 256 KiB value is applied.

## Next performance target

Further throughput work should attack retransmission, queue residence, packet-copy/syscall cost, and kernel/hardware utilization. Threshold sweeps and alternate runtime branches are excluded from the production optimization strategy.
