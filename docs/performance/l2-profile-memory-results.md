# L2 Profile and Memory Results

Date: 2026-08-10

## Result

Secure native TAP throughput increased by 3.0 percent in the interleaved QEMU test.

The median p99 RTT overhead decreased by 11.5 percent.

The median RTT overhead increased by 0.132 ms.

Combined mean LowTier RSS decreased by 0.43 MiB, or 1.1 percent.

The complete Ethernet, L2-TUN, mixed-edge, and L3 correctness tests passed.

## Changes

The secure replay window now shifts four `u64` words.

The old path moved 256 individual bits for most received packets.

The replay microbenchmark measured a 120.6 times faster shift operation.

The replay window still uses 32 bytes.

The Ethernet forwarding table now allocates entries when LowTier learns MAC addresses.

The fresh default table capacity changed from 28,672 backing slots to zero.

The configured 16,384-entry logical limit did not change.

The benchmark now records mean RSS, peak RSS, and thread counts for both LowTier nodes.

The `port_mode` field now accepts these profile names:

- `routed` selects the IP-only TUN path.
- `ethernet` selects native TAP and complete Ethernet behavior.
- `compatible-ethernet` selects an IP-only edge on the Ethernet overlay.

The existing `l3`, `tap`, and `l2-tun` names remain valid.

Linux and FreeBSD use native Ethernet by default.
Other systems use compatible Ethernet by default.
Select `routed` to use the L3 path.

## Test Environment

The tests used the `lowertier-l2` Colima QEMU profile.

The virtual machine used four ARM64 virtual CPUs.

LowTier used UDP transport, secure mode, and native TAP.

Each primary run used 1000 ping samples and a 10-second throughput test.

The test order alternated the old and new images for three pairs.

This method reduces drift from virtual-machine load.

## Primary Interleaved Results

| Measurement | Before | After | Change |
| --- | ---: | ---: | ---: |
| Secure TAP throughput | 3.257 Gbit/s | 3.354 Gbit/s | 3.0% faster |
| Median RTT overhead | 0.565 ms | 0.697 ms | 0.132 ms higher |
| p99 RTT overhead | 1.563 ms | 1.383 ms | 11.5% lower |
| Combined mean RSS | 39.41 MiB | 38.98 MiB | 0.43 MiB lower |
| Combined peak RSS | 39.62 MiB | 39.31 MiB | 0.30 MiB lower |
| Threads per process | 7 | 7 | No change |

The median RTT result varied more than the throughput result.

The change does not establish a median RTT gain.

The p99 result shows less tail overhead in this test.

The empty forwarding-table capacity reduction is deterministic.

Process RSS also includes allocator and binary-layout variation.

## WireGuard Comparison

The latest interleaved series did not repeat the WireGuard test.

The table combines this result with the prior same-profile comparison.

| QEMU throughput | Median |
| --- | ---: |
| New protected LowTier TAP | 3.35 Gbit/s |
| Basic LowTier TAP | 3.84 Gbit/s |
| Kernel WireGuard | 5.76 Gbit/s |

The new protected TAP path is 12.7 percent slower than basic LowTier TAP.

The previous protected path was 16.3 percent slower.

The new protected TAP path is 41.8 percent slower than kernel WireGuard.

WireGuard carries L3 packets.

LowTier TAP carries complete Ethernet frames.

The comparison is not feature equivalent.

## Security and Traffic Signature

The packet format and cryptographic design did not change.

Secure mode still uses Noise XX, X25519, ChaCha20-Poly1305, and SHA-256.

The protected envelope still encrypts the complete peer header and payload.

The 256-packet replay window still rejects duplicate and stale packets.

Every steady-state scan passed in all six interleaved runs.

Each scan found no common prefix, common suffix, fixed position, or forbidden string.

Packet size, timing, direction, endpoints, and a random connection identifier remain visible.

The tests do not claim active probing resistance.

## Full L2 Verification

The QEMU harness passed native TAP, relay, L2-TUN, mixed TAP and L2-TUN, and L3 checks.

The exact frame cases included VLAN, QinQ, LLDP, broadcast, unicast, MAC movement, and MTU boundaries.

The `ethernet` profile fails when native TAP is unavailable.

LowTier does not silently replace complete Ethernet behavior with L2-TUN.

## Verification Commands

```text
cargo fmt --all -- --check
cargo test --locked -p lowertier --no-default-features --features tun port_mode
cargo test --locked -p lowertier --no-default-features --features tun link_envelope::tests -- --nocapture
cargo test --locked -p lowertier --no-default-features --features tun l2_fabric::tests -- --nocapture
cargo test --locked -p lowertier --no-default-features --features tun l2 -- --nocapture
cargo test --locked -p lowertier --no-default-features --features tun peer_conn_secure_mode -- --nocapture
bash script/tests/colima-l2-static-test.sh
bash script/tests/colima-l2-benchmark-static-test.sh
COLIMA_DOCKER_CONTEXT=colima-lowertier-l2 SKIP_IMAGE_BUILD=1 bash script/colima-l2/e2e.sh
```

## Limits

QEMU scheduling affects latency and process RSS.

A native host-to-host test is still required for production latency data.

The secure protocol has not received an external security audit.

A broad Cargo test run reported three failures outside this performance diff.

The failures cover URL parsing, local IPv6 routing, and RPC compression timing.

One existing UDP stress test exceeded three minutes, so the broad run was stopped.
