# TCP unsent data budget

Updated: 2026-10-15. H2 and WSS use a rate-based budget for each socket, including TCP lanes and punched connections.
The matched confirmation is recorded in [the performance report](lean-core-ab-20261014.md).
All clean throughput guards pass. Public upload and latency targets remain unmet.

## Socket admission

The unsent threshold is `clamp(rate_bytes_per_second × 0.004, floor, 4 MiB)`.
The floor is 128 KiB on Linux and 256 KiB on Darwin.
Every socket receives its floor before TLS starts.
The write adapter refreshes the estimate at most once per 100 ms, during existing write activity.
No background task, packet queue, or periodic timer is added.
The shared budget adds one atomic value per socket.

Linux reads `TCP_INFO.tcpi_delivery_rate` in bytes per second.
It uses the pacing rate when a delivery estimate is unavailable.
Older kernels without either field retain the floor.
The rate fields use the append-only [Linux TCP_INFO layout](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h).
The adapter retains Tokio's normal Linux write path.
[Linux TCP documentation](https://docs.kernel.org/networking/ip-sysctl.html#tcp-notsent-lowat-unsigned-integer) defines socket admission and readiness behavior.

Darwin reads `TCP_CONNECTION_INFO` transmitted-byte and retransmitted-byte counters.
The difference between successive samples estimates new transmitted bytes per second.
This is a transmission estimate, not an ACK-based delivery estimate.
The adapter uses the SDK layout because libc's Darwin TFO bitfield representation changes the counter offsets.
The first sample retains the floor.
[XNU TCP](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp.h) defines the counters.

Darwin checks the unsent threshold in socket readiness, while `send()` can still accept data beyond that threshold.
The adapter therefore retains the zero-timeout `poll()` check before each send.
It clears Tokio's cached readiness when the threshold blocks writing.
Scalar and vectored writes retain their full input lengths.
The previous separate 64 KiB write cap is removed.
One caller write can overshoot the threshold. Rustls retains its own output bound.
[XNU documentation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man4/tcp.4) describes readiness notifications for this option.

Option failures retain the connection and the last successful budget.
Other operating systems retain normal socket writes and the 128 KiB H2 scheduling floor.
Socket send and receive buffers, H2 receive-credit windows, and authentication remain unchanged.
An 11 ms path at 450 Mbit/s still requires approximately 619 kB in flight.
The unsent budget does not remove capacity for transmitted bytes.

## H2 admission and ownership

H2 uses the same shared budget as its socket.
The h2 builder permits up to 4 MiB. Application admission enforces the current rate-based limit.
Each DATA buffer charges its payload length until h2 consumes those bytes.
Partial consumption and buffer destruction both release the corresponding charge.
Blocked application writers register a waker before checking available capacity.
DATA consumption and reset cleanup wake those writers.
This accounting adds no packet queue and preserves h2's existing buffer ownership.
H2 codec output and TLS output remain separate bounded storage.

Normal H2 coalescing remains 16 KiB.
Linux large-buffer mode retains 64 KiB coalescing.
Explicit flush sends incomplete data immediately.
WSS retains its existing flush thresholds and message bounds.
Flow assignments remain stable across TCP lanes.

## Queue and throughput model

Equivalent serialization time is `bytes / service_rate`.
These estimates describe each stage, not total loaded RTT.

| Stage | Previous limit | New limit at 450 Mbit/s | New limit at 8 Gbit/s |
| --- | ---: | ---: | ---: |
| Linux unsent socket threshold | 128 KiB: 2.33 ms / 0.13 ms | 225,000 bytes: 4.00 ms | 4,000,000 bytes: 4.00 ms |
| Darwin unsent socket threshold | 128 KiB: 2.33 ms / 0.13 ms | 256 KiB: 4.66 ms | 4,000,000 bytes: 4.00 ms |
| H2 DATA admission | 128 KiB: 2.33 ms / 0.13 ms | Same platform budget | 4,000,000 bytes: 4.00 ms |
| Normal H2 coalescing | 16 KiB | 0.29 ms | 0.016 ms |
| Linux large-buffer H2 coalescing | 64 KiB | 1.17 ms | 0.066 ms |

The former 128 KiB budget allowed only 131 microseconds between writer wakeups at 8 Gbit/s.
The new target supplies approximately 4 ms, reducing the chance of socket starvation after scheduler delays.
At 450 Mbit/s, the larger Darwin floor also supplies more margin for readiness and task wakeup delays.
It can permit more local queue time than the former floor.
The confirmation must therefore assess throughput and loaded latency together.
Kernel socket memory remains outside process RSS.
The 4 MiB ceiling limits each stage when a recent rate estimate exceeds current service capacity.

## Verification scope

The socket regression checks option readback, unchanged flight buffers, rate-counter decoding, and Darwin blocked-write recovery.
The H2 regression checks changed limits, partial DATA consumption, discarded DATA, and registered wake delivery.
Existing H2 and WSS tests check framing, authentication, and transport binding.
The matched campaign compares public upload/download and clean Colima throughput.
