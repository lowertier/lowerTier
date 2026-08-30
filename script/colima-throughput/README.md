# Colima dataplane benchmark

This harness measures LowTier inside a Colima virtual machine.
Set `DOCKER_CONTEXT` when the benchmark uses a non-default Colima profile.

The raw Docker bridge is measured first with one and eight TCP streams. Its eight-stream result
must reach `RAW_GATE_BPS` (12 Gbit/s by default) for the run to be marked `valid`. When it does not,
`substrate-status.txt` contains `substrate-limited`; LowTier measurements are retained for
diagnostics but cannot establish a 10GbE ceiling. Set `REQUIRE_RAW_GATE=1` to stop immediately.

## Build once

Build one Linux binary with the existing builder image:

```bash
script/colima-throughput/build-core.sh
```

The QEMU profile supports 9p file shares. It does not support VirtioFS. The build script shares
only the 14 MB source input set. It copies that set into the VM-local volume before compilation.
It excludes the large repository `target` directory.

The script keeps Cargo sources and compiled objects in the `lowertier-linux-build-cache` Docker
volume. The first build copies the host Cargo cache. Later builds use the VM-local cache.

The script uses `easytier-throughput:wan-builder`. It does not pull or create an image.

Run the same binary in both benchmark containers:

```bash
BUILD_IMAGE=0 \
LOWTIER_CORE_BINARY=benchmark-results/.work/lowertier-core-linux \
script/colima-throughput/e2e.sh
```

The runtime containers use the selected existing runtime image. They receive `NET_ADMIN` and
`/dev/net/tun`. The binary mount is read-only.

## Runs

Quick smoke test:

```bash
QUICK=1 script/colima-throughput/e2e.sh
```

Full automatic-adapter run:

```bash
script/colima-throughput/e2e.sh
```

Reuse an already-built image:

```bash
BUILD_IMAGE=0 RUNS=3 DURATION=15 script/colima-throughput/e2e.sh
```

QUIC DATAGRAM TUN test with 100-180 ms one-way delay and 3% random loss:

```bash
BUILD_IMAGE=0 \
LOWTIER_CORE_BINARY=benchmark-results/.work/lowertier-core-linux \
UNDERLAY_PROTOCOL=quic \
NETEM_DELAY=140ms \
NETEM_JITTER=40ms \
NETEM_LOSS=3% \
RAW_GATE_BPS=0 \
PARALLEL_STREAMS=4 \
UDP_RATES=100M \
DURATION=10 \
OMIT=2 \
TCP_CONGESTION_CONTROL=bbr \
LOWTIER_CORE_ARGS="--quic-congestion tunnel" \
script/colima-throughput/e2e.sh
```

Tunnel mode does not pace or retransmit business datagrams. Upper applications control
congestion. QUIC still supplies TLS 1.3 encryption and valid QUIC packets.

For burst loss, repeat the same run with correlated netem loss:

```bash
NETEM_LOSS=3% NETEM_LOSS_CORRELATION=75% \
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
| `DOCKER_CONTEXT` | `colima` | Docker endpoint. Set this value for a non-default profile. |
| `RESULT_DIR` | temporary directory | Stable location for raw JSON and summaries |
| `RAW_GATE_BPS` | `12000000000` | Minimum valid substrate throughput |
| `PARALLEL_STREAMS` | `8` | Aggregate TCP stream count |
| `TCP_STREAMS` | `1 PARALLEL_STREAMS` | Overlay TCP stream counts. Set one value for an isolated workload. |
| `ENCRYPTION_ALGORITHM` | `chacha20-poly1305` | Explicit authenticated dataplane cipher |
| `UNDERLAY_PROTOCOL` | `udp` | LowTier underlay, `udp` or `quic` |
| `LOWTIER_CORE_ARGS` | empty | Extra arguments passed to both LowTier nodes |
| `LOWTIER_CORE_BINARY` | empty | Linux binary mounted into both runtime containers |
| `TCP_CONGESTION_CONTROL` | empty | Inner TCP congestion control. Use `bbr` for matched results. |
| `NETEM_DELAY` | empty | Mean egress delay; empty disables netem |
| `NETEM_JITTER` | `0ms` | Random delay range around the mean |
| `NETEM_LOSS` | `0%` | Random egress packet loss |
| `NETEM_LOSS_CORRELATION` | `0%` | Correlation for burst-loss experiments |
| `NETEM_LIMIT` | `250000` | Netem queue capacity in packets |
| `UDP_RATES` | `2500M 5000M 7500M 10000M 12000M` | UDP offered-rate sweep |
| `RUNS` | `1` | Repetitions per workload |
| `DURATION` | `10` | Measured seconds per iperf run |
| `IPERF_TIMEOUT_SECONDS` | `DURATION + OMIT + 15` | Maximum seconds for one iperf client |
| `RUN_TCP` | `1` | Run overlay TCP workloads. Set `0` to omit these workloads. |
| `RUN_UDP` | `1` | Run overlay UDP workloads |
| `RUN_CPU_PROBE` | `1` | Run the separate loaded TCP CPU/latency probe |
| `IPERF_BUSY_RETRIES` | `3` | Restart and retry when the delayed iperf server is still closing its prior test |

`throughput.tsv` contains only complete normalized iperf results. If an overload
resets an inner iperf control flow, `workload-errors.tsv` records the workload
and exact iperf error instead of emitting a malformed throughput row.
The timeout also prevents an overloaded reverse flow from blocking the matrix.
`cpu-cores-per-gbit.tsv` reports each LowTier endpoint's process CPU divided by
received payload throughput. Raw iperf JSON, unloaded and loaded ping samples,
offload state, logs, and environment metadata remain alongside them.

## Hard candidate gate

Default-on dataplane changes must be faster than the last accepted baseline in
every required workload. Equal, mixed, uncertain, and slower comparisons fail.
The rationale and rejected architectural patterns are recorded in
`docs/performance/performance-regression-policy.md`.

Create matched result directories with at least five runs, one and eight TCP
streams, and both directions. Then run:

```bash
python3 script/colima-throughput/performance_gate.py \
  /path/to/baseline-p1-results \
  /path/to/candidate-p1-results \
  --baseline-extra-result-dir /path/to/baseline-p8-results \
  --candidate-extra-result-dir /path/to/candidate-p8-results
```

Extra baseline and candidate directories are paired by option order and may be
repeated for additional isolated runs.

The default gate requires at least two percent median throughput gain in every
matched workload, requires every paired candidate run to be faster, rejects a
normalized TCP retransmission increase, rejects workload errors, verifies the
comparable environment fields, and requires a valid raw substrate result. A
smoke run may use `--min-samples 1`, `--allow-partial-matrix`, and
`--allow-substrate-not-run`; that result cannot authorize a default-on merge.

Absolute results are not directly comparable with Tailscale's published bare-metal 25GbE test.
The comparable engineering question is whether LowTier preserves packets in batches, avoids
avoidable syscalls and queue handoffs, and reduces CPU cores consumed per Gbit/s.
