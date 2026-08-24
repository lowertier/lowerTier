# Benchmarks

Criterion benchmarks for LowTier hot paths.

| Bench                       | What it measures                                                                 |
| --------------------------- | -------------------------------------------------------------------------------- |
| `tx_throughput`             | Unified fabric scalar, batch, and saturation paths                               |
| `packet_bytes_extraction`   | `ZCPacket::payload_bytes` / `tunnel_payload_bytes` extraction (advance hot path)  |

## Packet Bytes Extraction

Criterion benchmark for `ZCPacket` bytes extraction — the methods touched by the
`advance`-based slicing refactor. Measures `payload_bytes` and
`tunnel_payload_bytes` at two payload sizes (1280, 4096). Setup
(`ZCPacket::new_with_payload`) runs in the benchmark harness's preparation
phase and is excluded from the timed region, so the numbers reflect only the
extraction call.

### Quick start

```bash
cargo bench --bench packet_bytes_extraction
```

Smoke run:

```bash
PACKET_BYTES_MEASUREMENT_SECS=2 \
PACKET_BYTES_WARMUP_SECS=1 \
PACKET_BYTES_SAMPLE_SIZE=10 \
cargo bench --bench packet_bytes_extraction -- --quiet
```

### Environment variables

| Variable                        | Default | Notes                        |
| ------------------------------- | ------- | ---------------------------- |
| `PACKET_BYTES_MEASUREMENT_SECS` | `10`    | Criterion `measurement_time` |
| `PACKET_BYTES_WARMUP_SECS`      | `3`     | Criterion `warm_up_time`     |
| `PACKET_BYTES_SAMPLE_SIZE`      | `10`    | Criterion `sample_size` (min 10) |

---

## TX Throughput Benchmark

This Criterion benchmark measures the unified LowTier fabric transmit path.

## What it measures

The benchmark sets up two LowTier instances named `hot-a` and `hot-b`.
It sends IP packets through the unified fabric API.
The measured path includes route lookup, encryption, peer processing, and tunnel transmission.

Three variants are reported for each tunnel type:

| Bench | What it measures |
| --- | --- |
| `tx_throughput/<tunnel>-p<size>-b<batch>-scalar` | Sends one fabric packet for each API call. |
| `tx_throughput/<tunnel>-p<size>-b<batch>-batch` | Sends up to `TX_THROUGHPUT_BATCH_SIZE` packets for each API call. |
| `tx_throughput/<tunnel>-p<size>-b<batch>-saturate` | Sends scalar packets from concurrent Tokio tasks. |

The benchmark does not include TUN or TAP device access.
The Colima throughput harness measures these device paths.
The benchmark also excludes compression, reverse traffic, and multi-peer fanout.

## Quick start

### ring tunnel (no root, fastest)

```bash
cargo bench --bench tx_throughput
```

Smoke run (faster iteration):

```bash
TX_THROUGHPUT_MEASUREMENT_SECS=2 \
TX_THROUGHPUT_WARMUP_SECS=1 \
TX_THROUGHPUT_SAMPLE_SIZE=10 \
cargo bench --bench tx_throughput -- --quiet
```

### tcp / udp tunnels (requires Docker + root)

The benchmark creates a Docker network and registers each container's netns
under `/var/run/netns`, which requires root. Run the whole command under
`sudo`:

```bash
sudo TX_THROUGHPUT_TUNNEL=tcp \
     TX_THROUGHPUT_MEASUREMENT_SECS=5 \
     TX_THROUGHPUT_WARMUP_SECS=2 \
     TX_THROUGHPUT_INFLIGHT=64 \
     cargo bench --bench tx_throughput -- --quiet

sudo TX_THROUGHPUT_TUNNEL=udp cargo bench --bench tx_throughput -- --quiet
```

> If `sudo` cannot find `cargo`, use `sudo -E` or the absolute path
> (`$(which cargo)`).

## Environment variables

| Variable                         | Default               | Notes                                  |
| -------------------------------- | --------------------- | -------------------------------------- |
| `TX_THROUGHPUT_TUNNEL`           | `ring`                | `ring` / `tcp` / `udp`                 |
| `TX_THROUGHPUT_PKT_SIZE`         | `1400`                | IP total length in bytes               |
| `TX_THROUGHPUT_WORKER_THREADS`   | `4`                   | tokio worker threads                   |
| `TX_THROUGHPUT_INFLIGHT`         | `64`                  | saturate-mode concurrency (task count) |
| `TX_THROUGHPUT_BATCH_SIZE`       | `64`                  | packets in each unified fabric batch   |
| `TX_THROUGHPUT_TUNNEL_PORT`      | `35521`               | tcp/udp listen port                    |
| `TX_THROUGHPUT_MEASUREMENT_SECS` | `10`                  | Criterion `measurement_time`           |
| `TX_THROUGHPUT_WARMUP_SECS`      | `3`                   | Criterion `warm_up_time`               |
| `TX_THROUGHPUT_SAMPLE_SIZE`      | `10`                  | Criterion `sample_size` (min 10)       |
| `TX_THROUGHPUT_DOCKER_IMAGE`     | `busybox:latest`      | tcp/udp only                           |
| `TX_THROUGHPUT_DOCKER_NET`       | `lowertier-bench-<id>` | auto-generated unique name             |
| `TX_THROUGHPUT_DOCKER_SUBNET`    | `172.31.250.0/24`     |                                        |
| `TX_THROUGHPUT_DOCKER_IP_A`      | `172.31.250.2`        |                                        |
| `TX_THROUGHPUT_DOCKER_IP_B`      | `172.31.250.3`        |                                        |

## Parameter sweeps

```bash
# Packet size
for sz in 64 256 1400 9000; do
  TX_THROUGHPUT_PKT_SIZE=$sz cargo bench --bench tx_throughput -- --quick
done

# Inflight depth (self-check: depth=1 should match serial baseline)
for d in 1 4 16 64 256; do
  TX_THROUGHPUT_INFLIGHT=$d cargo bench --bench tx_throughput -- --quick
done

# Worker threads
for w in 1 2 4 8; do
  TX_THROUGHPUT_WORKER_THREADS=$w cargo bench --bench tx_throughput -- --quick
done
```

## Interpreting results

- **`<tunnel>`** reports per-packet latency. Lower is better. Throughput
  column here is "what one in-flight sender sustains".
- **`<tunnel>-saturate`** reports aggregate throughput across
  `TX_THROUGHPUT_INFLIGHT` concurrent senders. If this matches the serial
  baseline, the TX path is bottlenecked on an internal serialization point
  (lock, single-threaded queue, etc.) rather than CPU or link bandwidth.

### Known finding (ring, single peer)

On the ring tunnel with a single destination peer, saturate does **not** beat
serial (observed ~277 MiB/s saturate vs ~288 MiB/s serial on a 4-worker
runtime). This points to a serialization point inside the peer-connection TX
path. Tunnels with real I/O await points (tcp/udp via Docker) are expected to
show a saturate > serial gap; verify with the sudo commands above.

The 2026-07-18 Apple Silicon run with eight workers, 128 in-flight sends, and
1400-byte packets measured about 188 MiB/s serial and 193 MiB/s saturated. The
small concurrency gain confirms that adding sender tasks does not unlock the
common single-peer path. End-to-end VZ and native macOS results are recorded in
[`docs/performance/10gbe-dataplane-results.md`](../../docs/performance/10gbe-dataplane-results.md).

## Output artifacts

Criterion writes HTML reports + SVG plots under
`lowertier/target/criterion/`. Open `tx_throughput/<tunnel>/report/index.html`
or `.../<tunnel>-saturate/report/index.html` in a browser to inspect
distributions and regressions across runs.
