# Colima 10GbE-class dataplane benchmark

This harness offers LowTier up to 12 Gbit/s inside the VZ-backed default Colima VM. It is a
software throughput and CPU-efficiency test, not a claim that Colima emulates a physical 10GbE
NIC.

The raw Docker bridge is measured first with one and eight TCP streams. Its eight-stream result
must reach `RAW_GATE_BPS` (12 Gbit/s by default) for the run to be marked `valid`. When it does not,
`substrate-status.txt` contains `substrate-limited`; LowTier measurements are retained for
diagnostics but cannot establish a 10GbE ceiling. Set `REQUIRE_RAW_GATE=1` to stop immediately.

## Prerequisites

- a running default Colima profile using VZ with enough CPU and memory;
- Docker context `colima`;
- Docker BuildKit;
- enough free disk space for the Rust release image.

Suggested profile resources are at least 12 CPUs and 16 GiB RAM. Confirm them with
`colima status` before interpreting results.

## Runs

Quick smoke test:

```bash
QUICK=1 script/colima-throughput/e2e.sh
```

Full L3, L2-TUN, and TAP matrix:

```bash
script/colima-throughput/e2e.sh
```

Reuse an already-built image:

```bash
BUILD_IMAGE=0 RUNS=3 DURATION=15 script/colima-throughput/e2e.sh
```

Reliable QUIC DATAGRAM L2-TUN under randomized 100-180 ms one-way delay and 3%
loss in each egress direction:

```bash
DOCKER_CONTEXT=colima-lowertier-l2 \
UNDERLAY_PROTOCOL=quic \
MODES=l2-tun \
NETEM_DELAY=140ms \
NETEM_JITTER=40ms \
NETEM_LOSS=3% \
RAW_GATE_BPS=0 \
PARALLEL_STREAMS=4 \
UDP_RATES=100M \
DURATION=10 \
OMIT=2 \
QUIC_FEC_PROFILES="0 2 3" \
LOWTIER_CORE_ARGS="--quic-congestion brutal --quic-brutal-send-bps 10000000" \
script/colima-throughput/e2e.sh
```

This is the recommended known-capacity lossy L2 profile: Brutal at a measured
send ceiling, immediate critical L2 duplication, and 16+2 FEC. BBR remains the
safe choice when the path capacity is unknown. The matrix above labels results
`l2-tun-fec0`, `l2-tun-fec2`, and `l2-tun-fec3`.

For burst loss, repeat the same run with correlated netem loss:

```bash
NETEM_LOSS=3% NETEM_LOSS_CORRELATION=75% QUIC_FEC_PROFILES="0 2 3" \
script/colima-throughput/e2e.sh
```

The delay and loss qdisc is applied to `eth0` on both containers. Each data
direction therefore sees 3% loss, while round trips also include independently
impaired acknowledgements. Leaving `NETEM_DELAY` empty disables emulation.
The QUIC transport is protected by TLS 1.3 through rustls/ring; LowTier's
configured authenticated dataplane cipher remains enabled inside that tunnel.

Important controls:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOCKER_CONTEXT` | `colima` | Docker endpoint for the VZ profile |
| `RESULT_DIR` | temporary directory | Stable location for raw JSON and summaries |
| `RAW_GATE_BPS` | `12000000000` | Minimum valid substrate throughput |
| `MODES` | `l3 l2-tun tap` | LowTier port modes |
| `PARALLEL_STREAMS` | `8` | Aggregate TCP stream count |
| `ENCRYPTION_ALGORITHM` | `chacha20-poly1305` | Explicit authenticated dataplane cipher |
| `UNDERLAY_PROTOCOL` | `udp` | LowTier underlay, `udp` or `quic` |
| `LOWTIER_CORE_ARGS` | empty | Extra arguments passed to both LowTier nodes |
| `NETEM_DELAY` | empty | Mean egress delay; empty disables netem |
| `NETEM_JITTER` | `0ms` | Random delay range around the mean |
| `NETEM_LOSS` | `0%` | Random egress packet loss |
| `NETEM_LOSS_CORRELATION` | `0%` | Correlation for burst-loss experiments |
| `NETEM_LIMIT` | `250000` | Netem queue capacity in packets |
| `QUIC_FEC_PROFILES` | `2` | Space-separated ETQ4 parity profiles: `0`, `2`, or `3` |
| `UDP_RATES` | `2500M 5000M 7500M 10000M 12000M` | UDP offered-rate sweep |
| `RUNS` | `1` | Repetitions per workload |
| `DURATION` | `10` | Measured seconds per iperf run |
| `RUN_TCP` | `1` | Run overlay TCP workloads; set to `0` for a focused UDP/FEC matrix |
| `RUN_UDP` | `1` | Run overlay UDP workloads |
| `RUN_CPU_PROBE` | `1` | Run the separate loaded TCP CPU/latency probe |
| `IPERF_BUSY_RETRIES` | `3` | Restart and retry when the delayed iperf server is still closing its prior test |

`throughput.tsv` contains only complete normalized iperf results. If an overload
resets an inner iperf control flow, `workload-errors.tsv` records the workload
and exact iperf error instead of emitting a malformed throughput row.
`cpu-cores-per-gbit.tsv` reports each LowTier endpoint's process CPU divided by
received payload throughput. Raw iperf JSON, unloaded and loaded ping samples,
offload state, logs, and environment metadata remain alongside them.
`quic-datagram-metrics.tsv` exports ETQ4 source, feedback, selective recovery,
duplication, FEC, RTT, congestion window, QUIC loss, MTU, and queue counters.
When a peer has two eligible QUIC surfaces, `alternate-fec-metrics.tsv` exports
the EAP1 wrapped-source count and bytes, parity blocks, parity records and
bytes, send failures, and blocks skipped because no distinct allowed path was
available. These are relaxed atomic dataplane counters; string formatting only
occurs in the five-second benchmark log task.

Absolute results are not directly comparable with Tailscale's published bare-metal 25GbE test.
The comparable engineering question is whether LowTier preserves packets in batches, avoids
avoidable syscalls and queue handoffs, and reduces CPU cores consumed per Gbit/s.
