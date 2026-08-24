# Kernel WireGuard throughput benchmark

This harness measures Linux kernel WireGuard in the existing Colima VM.
Both WireGuard endpoints use the same Linux kernel module.
The harness does not run `wireguard-go`.

The test uses two privileged containers as separate network namespaces.
Each container gets one kernel `wg0` interface.
The test records raw bridge throughput before WireGuard throughput.
It also records unloaded latency and total VM CPU use.

The VM CPU value includes WireGuard kernel workers, iperf, Docker, and VM background work.
Do not compare this value directly with LowTier process-only CPU values.

Run a short test:

```bash
RUNS=1 DURATION=5 CPU_DURATION=5 \
STREAM_COUNTS="1 4" \
script/kernel-wireguard-bench/e2e.sh
```

Run the retention matrix:

```bash
RUNS=3 DURATION=10 CPU_DURATION=10 \
STREAM_COUNTS="1 4" \
script/kernel-wireguard-bench/e2e.sh
```

The harness reuses the small image definition from `wireguard-macos-bench`.
Set `BUILD_IMAGE=0` to reuse an existing benchmark image.
Private keys remain inside shell variables and temporary container files.
The cleanup removes both containers and the Docker network.

The result directory contains these primary files:

- `throughput.tsv` contains raw and WireGuard TCP results.
- `substrate-status.txt` contains the raw bridge gate result.
- `kernel-evidence.txt` identifies the kernel and WireGuard module.
- `vm-cpu-cores-per-gbit.tsv` contains total VM CPU estimates.
- `unloaded-latency.txt` contains 100 ping samples.
- `workload-errors.tsv` contains incomplete or timed-out workloads.
