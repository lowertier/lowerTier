# Native macOS WireGuard resource benchmark

This harness runs the pinned Tailscale `wireguard-go` implementation on native macOS and kernel
WireGuard in the existing QEMU Colima profile. It uses the same UDP port-forwarding boundary,
inner MTU, `iperf3` workloads, latency sampling, and CPU-per-Gbit calculation as the EasyTier
native L2-TUN benchmark.

The primary comparison is production-shaped rather than feature-equivalent. WireGuard carries L3
traffic with a compact direct-peer header. EasyTier carries an L2 frame and routed-overlay metadata.

The harness creates ephemeral keys, keeps private keys out of the result directory, chooses an
unused high-numbered `utun`, and removes the host route, userspace process, UAPI socket, and test
container on exit.

Run a short smoke test:

```bash
RUNS=1 DURATION=5 CPU_DURATION=5 \
  RESULT_DIR=/tmp/wireguard-macos-smoke \
  script/wireguard-macos-bench/e2e.sh
```

The default `WIREGUARD_GO_SOURCE` is the pinned Tailscale module already used for the EasyTier
reference analysis. Override it only for an explicit version comparison.

Set `PROFILE_DURATION=8` to add separate macOS `sample`, `sc_usage`, `vmmap`, utun counter, RSS,
and thread-count windows. The harness uses a 1360-byte MTU by default; override both comparison
harnesses with the same `MTU` value when testing another packet size.
