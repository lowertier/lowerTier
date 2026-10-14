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

The default image is `easytier-throughput:wan-builder`. Set `LOWTIER_BUILDER_IMAGE`
to select another prepared image. H2/WSS client TLS requires CMake and libclang
(`cmake` and `libclang-dev` on Debian), in addition to the existing C/C++, Rust
and Protobuf tools. The checked-in Dockerfile includes these dependencies.
The build script does not pull or create an image.

Run the same binary in both benchmark containers:

```bash
BUILD_IMAGE=0 \
LOWTIER_CORE_BINARY=benchmark-results/.work/lowertier-core-linux \
script/colima-throughput/e2e.sh
```

The runtime containers use the selected existing runtime image. They receive `NET_ADMIN` and
`/dev/net/tun`. The binary mount is read-only.

## TCP buffer experiment

H2 and WebSocket can opt into larger Linux TCP socket buffers with
`LOWTIER_ENABLE_TCP_LARGE_BUFFERS=1`. For this harness, pass it through
`LOWTIER_RUNTIME_ENV=LOWTIER_ENABLE_TCP_LARGE_BUFFERS=1` on both nodes.
The experiment requests 32 MiB per direction before the TCP handshake; Linux
reports a 64 MiB accounting limit. This limit is separate from process RSS.
With the VPN's existing `NET_ADMIN` capability, the request uses per-socket
buffer overrides. Without that capability, small system limits leave TCP
autotuning unchanged. No global sysctls are changed.

This experiment is disabled by default pending the complete throughput and
reliability matrix in `docs/performance/performance-regression-policy.md`.
A TCP reverse proxy has its own socket limits and must be measured separately.
Both this harness and `script/kernel-wireguard-bench/e2e.sh` accept optional
`TCP_RMEM` and `TCP_WMEM` triplets for per-container TCP autotuning controls.
For example, `TCP_RMEM="4096 131072 16777216"` and
`TCP_WMEM="4096 16384 16777216"` raise the maxima to 16 MiB. Apply the same
settings to the WireGuard control; they also affect inner TCP flows.

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
| `UNDERLAY_PROTOCOL` | `udp` | LowTier underlay, `udp`, `tcp`, `quic`, `ws`, or `wss` |
| `LOWTIER_CORE_ARGS` | empty | Extra arguments passed to both LowTier nodes |
| `LOWTIER_CORE_BINARY` | empty | Linux binary mounted into both runtime containers |
| `LOWTIER_CONFIG_DIR` | empty | Directory with one TOML file per container name; replaces generated startup arguments |
| `IPERF_EXEC_WRAPPER` | empty | Executable prepended to each iperf command; receives `IPERF_OBSERVER_OUTPUT` |
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


## Browser TLS and independent TCP lanes

Build with `LOWTIER_BUILD_FEATURES=tun` for both H2 and WSS.
For a matched comparison, use one binary and select `UNDERLAY_PROTOCOL=tcp`
(H2) or `UNDERLAY_PROTOCOL=wss`, with `LOWTIER_TCP_LANES=1`, `2` or `4`.
The harness applies the corresponding `?lanes=N` to both listener and peer
URLs. A multi-lane group retains one authenticated logical peer connection.

For ordinary TLS on H2, use `--quic-sni-passthrough true`; the legacy routing
prefix mode is deliberately distinguishable and is outside the browser TLS
profile. WSS uses normal TLS followed by the WebSocket upgrade. Multiple
lanes require end-to-end TLS; plain WS and `via=cdn` / `via=proxy` are rejected.
An L4 proxy must keep all lanes on one backend, for example with Caddy
`lb_policy ip_hash`. Round-robin backend selection is suitable for single lanes.

The client profile is compared with isolated Chrome 152 captures. Stable TLS
fields align with that browser family; H2 does not advertise unsupported ALPS,
native trust-anchor hints may differ, and signature-algorithm GREASE differs
from the captured Chrome build. Packet timing, HTTP/2 settings, server identity
and application behavior are separate properties. QUIC retains its existing
TLS implementation. See `docs/performance/tcp-lanes-tracklist.md` for the
measurement gates and recorded experiments.
