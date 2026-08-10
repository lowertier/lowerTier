# Native macOS TUN efficiency benchmark

This harness runs `lowertier-core` natively through macOS utun and connects it to a Linux LowTier
peer in Colima. It measures L2-TUN in both directions with parallel TCP streams, unloaded and
loaded latency, and native LowTier CPU per Gbit.

Absolute throughput is often limited by the macOS-to-VM path, especially when the selected Colima
profile uses QEMU or UDP port forwarding. CPU per Gbit and latency are therefore the primary
macOS efficiency measurements. Use the VZ Colima throughput harness for the 10GbE-class Linux
ceiling.

## Prerequisites

- a release `lowertier-core` binary built with the `tun` feature;
- passwordless `sudo` for launching and stopping the native client;
- a running Colima profile and an LowTier benchmark image containing iperf3;
- host `iperf3` and `jq`.

Build and run:

```bash
cargo build --locked --release -p lowertier --bin lowertier-core \
  --no-default-features --features tun
script/macos-tun-bench/e2e.sh target/release/lowertier-core
```

The harness explicitly selects `chacha20-poly1305` so throughput results always include
authenticated encryption. Override it only for controlled comparisons with
`ENCRYPTION_ALGORITHM`. It also sets the inner MTU to 1360 explicitly so WireGuard comparisons do
not depend on LowTier's computed default.

Useful controls:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PARALLEL_STREAMS` | `8` | TCP streams used to expose aggregate capacity |
| `RUNS` | `3` | Throughput repetitions in each direction |
| `DURATION` | `10` | Seconds per throughput run |
| `CPU_DURATION` | `15` | Seconds in the CPU and loaded-latency probe |
| `MTU` | `1360` | Inner TUN MTU used by both benchmark peers |
| `PROFILE_DURATION` | `0` | Seconds per optional symbol, interface-counter, and process profile |
| `COLIMA_PROFILE` | `lowertier-l2` | Peer VM profile |
| `DOCKER_CONTEXT` | `colima-lowertier-l2` | Peer Docker endpoint |
| `RESULT_DIR` | temporary directory | Persistent output location |

The result directory contains normalized throughput TSV, raw iperf JSON, unloaded ping samples,
loaded-latency samples, native `top` samples, RSS and thread samples, LowTier CPU per Gbit, and
environment metadata. With `PROFILE_DURATION` greater than zero it also contains macOS `sample`,
`sc_usage`, `vmmap`, and utun interface-counter artifacts. `sc_usage` is known to return unusable
zero activity on some macOS releases; the other artifacts remain independent.
