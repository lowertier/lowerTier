# Darwin batched TUN results

Date: 2026-07-18

Host: Apple Silicon macOS, native LowTier client

Peer: Colima `lowertier-l2` profile, QEMU aarch64, Linux container

Overlay: L2-TUN on both nodes, UDP transport, MTU 1360

Tool: iperf3 3.20, one TCP stream, 10 measured seconds after a 2-second omit

## What changed

The Apple virtual-NIC backend now uses one `AsyncFd` around the utun socket for independent read
and write readiness. It uses Darwin `recvmsg_x` and `sendmsg_x` with batches capped at 64 packets,
raises `UTUN_OPT_MAX_PENDING_PACKETS` to the same bound, and scatters the four-byte utun header
away from the IP payload on receive. Both L3 and L2-TUN share this implementation. L2-TUN only
changes the reserved payload prefix from zero to 14 bytes.

Peer-to-NIC delivery takes the first packet immediately, drains only packets already queued, and
flushes once. There is no batching timer and therefore no deliberate latency penalty. Generic
non-Apple TUN output remains capped at one buffered packet so `writev` cannot merge packet
boundaries.

This follows the kernel-facing parts of SagerNet sing-tun rather than importing its userspace
network stack. LowTier retains its current overlay, routing, packet buffers, and L2 fabric.

## Reproduction

Build:

```bash
cargo build --locked --release -p lowertier --bin lowertier-core \
  --no-default-features --features tun
```

Run the native macOS/QEMU experiment:

```bash
script/macos-tun-bench/e2e.sh target/release/lowertier-core
```

The script requires passwordless `sudo` for the native client, the running QEMU-backed Colima
profile `lowertier-l2`, and the fixed Linux image `lowertier-l2-qemu-test:local`. It writes the exact
ping and per-run iperf summaries to a new temporary result directory.

## Exact pre-change baseline

Baseline commit: `b21b0583` (`feat(udp): add authenticated public STUN punching`). The QEMU image
and server process were held fixed across variants.

| Direction | Run 1 | Run 2 | Run 3 | Median | Median retransmits |
|---|---:|---:|---:|---:|---:|
| macOS to QEMU | 431.9 Mbit/s | 401.8 Mbit/s | 425.2 Mbit/s | 425.2 Mbit/s | not reported |
| QEMU to macOS | 361.2 Mbit/s | 380.4 Mbit/s | 380.0 Mbit/s | 380.0 Mbit/s | 480 |

The QEMU boundary has visible scheduling noise, so the comparison uses medians and does not use a
single best sample. Native iperf CPU medians were 2.08% in the forward direction and 17.99% in the
reverse direction; these values cover iperf itself, not the LowTier process.

## Post-change result

| Direction | Run 1 | Run 2 | Run 3 | Median | Change | Median retransmits |
|---|---:|---:|---:|---:|---:|---:|
| macOS to QEMU | 445.0 Mbit/s | 422.9 Mbit/s | 420.2 Mbit/s | 422.9 Mbit/s | -0.5% | not reported |
| QEMU to macOS | 382.2 Mbit/s | 380.3 Mbit/s | 378.7 Mbit/s | 380.3 Mbit/s | +0.1% | 458 |

The QEMU link, UDP overlay, and peer processing cap throughput before the native utun loop does.
The throughput medians are therefore a tie within experimental noise. The useful result appears in
the native LowTier process CPU measured by 16 one-second `top` samples during otherwise identical
15-second transfers:

| Direction | Baseline throughput | Batched throughput | Baseline LowTier CPU | Batched LowTier CPU | CPU change |
|---|---:|---:|---:|---:|---:|
| macOS to QEMU | 440.6 Mbit/s | 427.1 Mbit/s | 80.7% | 33.8% | -58.1% |
| QEMU to macOS | 382.6 Mbit/s | 357.5 Mbit/s | 81.3% | 77.6% | -4.5% |

The forward direction exercises batched utun reads and shows the expected large CPU reduction. In
this two-node test, packets arriving from the peer are frequently delivered to the channel one at a
time, so `sendmsg_x` has fewer opportunities to batch. Its result is correspondingly smaller.
After replacing the peer-to-NIC batch `Vec` with the final zero-allocation iterator, the reproducible
script measured 31.3% forward LowTier CPU. That later run's QEMU throughput was only 360.1 Mbit/s,
so the table keeps the earlier, more closely throughput-matched A/B pair rather than overstating the
additional improvement.

Initial unloaded L2-TUN checks were 1.608 ms average before and 1.523 ms after, both with zero loss.
Longer ping runs later in the session had multi-millisecond QEMU scheduling outliers in both variants,
so they were not used to claim a latency improvement. There is no batch-fill wait in the code.

The same binary also completed a native macOS-to-QEMU L3 smoke test at 427.3 Mbit/s forward and
383.2 Mbit/s reverse, confirming that L3 and L2-TUN share the backend. A cross-check for
`aarch64-apple-ios` completed successfully after fixing the mobile Magic DNS feature guard.

## Interpretation

Keep the implementation. It preserves throughput and unloaded latency while materially reducing
native CPU on the direction where utun batching is available. The remaining reverse-path cost is
upstream of the utun writer: peer packets usually reach the NIC channel singly. Improving that path
requires batching earlier in peer decode/dispatch rather than waiting in the NIC task, since waiting
there would trade latency for artificial batch size.
