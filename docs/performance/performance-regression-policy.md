# Dataplane performance regression policy

Status date: 2026-08-20

Scope: default-on dataplane, scheduling, queueing, batching, crypto, TUN/TAP, UDP, routing, and liveness changes

## Governing rule

A performance change is accepted only when the candidate is measurably faster than the last accepted baseline in every required workload. Equal, mixed, uncertain, and slower results fail the gate. A failed candidate is reverted, redesigned, or retained behind an explicit experimental switch that is disabled by default.

Correctness and security work may be mandatory. A change with a measured throughput cost cannot be described or merged as a performance optimization. Its cost must be recorded and recovered before the corresponding performance milestone is considered complete.

The QUIC L2 milestone is 90 percent of the saved kernel WireGuard throughput.
Each matched direction and flow count must pass independently.
See [QUIC L2 WireGuard performance target](quic-l2-wireguard-target.md).

## What the 2026-08-20 bisection established

The measurements below used adjacent runs in the same ARM64 Colima profile. Absolute throughput moved with host load. The adjacent deltas repeatedly identified the same expensive boundaries.

| Isolated change | Control | Candidate | Delta | Decision |
| --- | ---: | ---: | ---: | --- |
| Bounded UDP ingress with scalar ring | 2.097 Gbit/s | 1.769 Gbit/s | -15.7% | redesign |
| Rewritten direct-send pipeline | 3.607 Gbit/s | 2.170 Gbit/s | -39.8% | remove |
| ARM64 TUN backend | 3.252 Gbit/s | 3.473 Gbit/s | +6.8% | retain for full-matrix validation |
| Security/session/FEC batch changes | 3.449 Gbit/s | 2.515 Gbit/s | -27.1% | redesign |
| Peer receive-loop integration | 2.654 Gbit/s | 1.277 Gbit/s | -51.9% | redesign |
| Native batch ring boundary | 3.568 Gbit/s | 2.729 Gbit/s | -23.5% | redesign |
| Complete queue-rewrite stack | 2.534 Gbit/s | 0.00445 Gbit/s | -99.8% | reject |
| Complete stack with baseline direct sender | 1.956 Gbit/s | 1.695 Gbit/s | -13.4% | remaining overhead isolated |

The complete stack reached only a few megabits per second even though its individual components passed unit tests. Restoring the direct sender recovered gigabit throughput immediately. This is evidence of compounding queue and feedback costs rather than one isolated arithmetic hot spot.

## Why the apparent optimizations became slower

### Additional task and actor handoffs

Moving a vector through an actor or channel creates scheduler wakeups, queue metadata traffic, atomic synchronization, and cache-line movement. It increases throughput only when the new owner performs useful work concurrently with another independent stage. The UDP socket, per-peer ordering point, and final sink remained serial resources, so several handoffs added overhead without increasing service capacity.

At high packet rates, one extra wakeup per vector is material. A second effect is more damaging: a task handoff delays ACK-bearing traffic and control packets behind bulk work, which increases TCP feedback latency and reduces the congestion window.

### Duplicate capacity controllers

Several prototypes combined a queue-slot semaphore, packet-credit semaphore, ring occupancy bound, sink readiness state, and downstream direct-send budget. Each individual bound was finite. Together they created nested backpressure and convoying.

A full vector could hold one class of credits while waiting for another. Other vectors then waited behind it even when the final transport had useful capacity. This produces head-of-line blocking at vector granularity.

The safe rule is one authoritative capacity controller per scarce resource. A new queue must remove or replace an existing queue in the same path. Adding another bounded queue still adds latency and synchronization.

### Deeper direct-send pipelines

The rejected direct pipeline allowed more batches to exist before transport completion. The UDP sink and per-peer ordered commit remained the limiting stages. Pipeline depth therefore increased queue residence time rather than completed sends per second.

Longer residence time delays inner TCP acknowledgements. Retransmission timers and congestion control respond to that delay, so a local queue can cause an end-to-end throughput collapse even when it never drops a packet. Early caller acknowledgement also obscures terminal transport failure and requires more ownership and error-propagation state.

### Batch preservation without stage elimination

Keeping a `PacketBatch` intact is necessary for high throughput. It is insufficient by itself. The native batch ring preserved packet storage and vector boundaries while adding an async ring job, packet permits, pending sink state, and another ownership transfer. The existing peer queue and UDP queue remained present.

A useful batch path removes scalar transitions and redundant stages. A vector wrapper placed around the same number of queues can be slower than the scalar baseline.

### Batch-scoped parallel crypto

Rayon parallelism performed fork, dispatch, work stealing, join, and ordered merge for each batch. ChaCha20-Poly1305 on the observed batch sizes did not provide enough work to amortize that lifecycle. Rayon also competed with Tokio and the benchmark workload for a small VM CPU set.

WireGuard's effective model uses persistent workers: reserve sequence numbers once, enqueue stable packet ownership, transform packets in parallel, then commit in per-peer order. Worker creation and scheduling are amortized across many vectors. Future LowTier parallel crypto must follow that ownership model. Small vectors remain inline.

### Per-packet peer-loop work

The peer receive-loop changes added metadata refresh, identity checks, atomic activity accounting, liveness observations, prefetch bookkeeping, and delivery error handling inside packet loops. Each operation is individually small. Their combination is branch-heavy, synchronization-heavy, and cache-unfriendly.

Activity, metrics, and liveness should be aggregated once per vector. Session and peer state should be loaded once per homogeneous group. Packet metadata should be parsed once at the earliest trusted boundary and then carried forward.

### Eager flow-shard splitting

Splitting one useful vector into one job per flow or shard multiplies queue operations and shrinks the batches presented to crypto and UDP. Earlier measurements reduced TCP p4 from approximately 3.9 Gbit/s to approximately 2.6-2.7 Gbit/s and roughly doubled CPU per delivered Gbit.

Flow identity should be stamped while the vector remains intact. Persistent workers may later consume that identity while preserving large I/O vectors and per-flow order.

### Late socket batching and unmatched offloads

`sendmmsg`, UDP GSO, and GRO cannot reconstruct a vector that upstream stages already fragmented. Late batching adds descriptor construction and fallback logic while receiving tiny groups.

GRO also changes receive semantics. A scalar receiver can observe several logical datagrams in one buffer and reject the combined record. Every offload requires matching transmit metadata, receive parsing, segmentation tests, and a capability fallback. Offload is enabled only after the complete path consumes its metadata correctly.

### Deep queues can look CPU-efficient

Several slow candidates reported lower CPU utilization. The pipeline was starved or waiting, so it performed less useful work. CPU percentage must be interpreted with delivered goodput:

\[
E = \frac{\text{CPU cores}}{\text{delivered Gbit/s}}.
\]

A lower CPU percentage with lower goodput is not an efficiency improvement. Queue stalls, loaded latency, retransmissions, and delivered bits must be evaluated together.

### Incorrect loss eligibility

Ordinary TCP-bearing `Data` and `Ethernet` packets cannot become transport-drop eligible merely because their packet type is commonly loss tolerant. Dropping an inner TCP frame causes retransmission and congestion-window reduction. Only traffic carrying an explicit authenticated lossy indication may use partial or drop admission.

## Architectural rules for future work

The accepted architecture follows these constraints:

1. One owned vector enters at TUN/TAP or UDP receive and remains intact through classification whenever destinations and ordering allow it.
2. Peer, session, route, and liveness state is loaded or updated once per vector or homogeneous subgroup.
3. Parallel packet transforms use persistent bounded workers. Per-peer ordered commit is a separate serial phase.
4. A queue is introduced only when it enables measured overlap between independent resources. The design identifies which existing queue it replaces.
5. One authoritative packet or byte budget controls each scarce resource.
6. Control traffic has a bounded guaranteed lane and cannot wait behind an unlimited bulk drain.
7. No batching timer is added to the latency path. Only already-ready packets join a vector.
8. Flow sharding preserves intact transport vectors and per-flow FIFO.
9. Kernel and socket offloads remain disabled until both directions consume matching metadata and pass integrity tests.
10. Telemetry is sampled or aggregated. Per-packet atomics are prohibited in the bulk path unless profiling proves they are cheaper than the alternative.

## Mandatory acceptance procedure

The baseline is the last accepted commit and immutable image. The candidate contains one isolated architectural change. Baseline and candidate use the same host, VM, CPU allocation, image profile, MTU, encryption, underlay, duration, directions, stream counts, and network impairment.

Final acceptance uses at least five matched runs for each of these TCP workloads:

- forward, one stream;
- reverse, one stream;
- forward, eight streams;
- reverse, eight streams.

Runs should alternate order to limit thermal and host-load bias. Host load and unrelated CPU consumers are recorded before each pair.

For workload \(k\), define the median throughput gain

\[
G_k = \frac{\operatorname{median}(C_k)}{\operatorname{median}(B_k)} - 1,
\]

where \(B_k\) and \(C_k\) are the baseline and candidate received-throughput samples. The default merge gate requires

\[
G_k \ge 0.02
\]

for every workload, and every matched candidate run must be strictly faster than its baseline run. A two-percent margin prevents benchmark noise from being accepted as an optimization.

For TCP reliability, compare normalized retransmission density

\[
D_k = \operatorname{median}\left(\frac{\text{retransmits}}{\text{received bits/s}}\right).
\]

Because duration is identical, this is proportional to retransmissions per delivered bit. The candidate must satisfy \(D_{k,C} \le D_{k,B}\). UDP loss percentage cannot increase. Workload errors, peer reconnects, silent reliable-packet drops, invalid substrate results, and environment mismatches fail the comparison.

The repository comparator enforces these rules:

```bash
python3 script/colima-throughput/performance_gate.py \
  /path/to/baseline-p1-results \
  /path/to/candidate-p1-results \
  --baseline-extra-result-dir /path/to/baseline-p8-results \
  --candidate-extra-result-dir /path/to/candidate-p8-results
```

Extra baseline and candidate directories are paired by option order. The options may be repeated when a matrix spans additional isolated runs.

A smoke comparison may reduce `--min-samples` and use `--allow-partial-matrix` or `--allow-substrate-not-run`. Those options do not authorize a default-on merge.

## Decision states

**Pass:** every required workload exceeds the positive margin, every matched run is faster, reliability is no worse, and stability checks pass. The candidate may proceed.

**Fail:** any required workload is equal or slower, reliability worsens, or the system reconnects or drops reliable traffic. The candidate is reverted or redesigned.

**Invalid:** environments differ, required samples are missing, the substrate is limited, or the host is materially contended. The candidate remains unaccepted until a valid comparison exists.

There is no aggregate-average escape hatch. A large gain in one direction cannot compensate for a regression in another direction or stream count.
