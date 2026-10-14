# H2 and WSS unsent data budget

Updated: 2026-10-14. This change limits local unsent data on each H2 and WSS socket, including TCP lanes.
It does not establish a measured latency or throughput improvement.
The PM must run the matched throughput and loaded-latency comparison before accepting the performance result.
The [TCP lanes milestone](tcp-lanes-milestone.md) records the earlier throughput baseline.

## Socket admission and flight capacity

Each connected or accepted socket requests `TCP_NOTSENT_LOWAT=131072` before TLS starts.
This includes punched connections and every socket in a lane group.
Unsupported operating systems retain their existing socket behavior.
Option failures produce a warning and retain the working transport.

The change preserves socket send and receive buffer sizing.
The Linux `LOWTIER_ENABLE_TCP_LARGE_BUFFERS` setting still increases flight capacity and H2 receive windows.
Receive windows supply peer credit; they do not define the local unsent budget.
At 450 Mbit/s, an 11 ms path requires approximately 619 kB in flight.
The unsent limit does not remove capacity for those transmitted bytes.

[Linux TCP documentation](https://docs.kernel.org/networking/ip-sysctl.html#tcp-notsent-lowat-unsigned-integer) describes both readiness gating and send admission.
Linux keeps the existing Tokio write path.
The limit is a threshold, with possible send-operation overshoot.

Darwin requires an additional write adapter.
[XNU socket readiness](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c) checks the unsent threshold in `sowriteable()`.
[XNU TCP](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_subr.c) computes unsent bytes as socket bytes minus transmitted, unacknowledged bytes.
However, `sosendcheck()` in [XNU socket sending](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c) checks buffer space without this threshold.
Tokio retains write readiness until an operation returns `WouldBlock`.
Therefore, setting the option alone can leave a large send buffer filling through cached readiness.

The Darwin adapter checks socket write readiness with a zero-timeout `poll()` before each send operation.
It returns `WouldBlock` through `TcpStream::try_io()` when the threshold stops readiness.
This clears cached readiness and registers the existing task for the next writable event.
Scalar and vectored writes permit at most 64 KiB per operation.
Thus, a successful option limits socket overshoot to one write, approximately 192 KiB total unsent data.
The adapter retains vectored writes and allocates no new packet queue.
It adds one readiness syscall per write on Darwin.

## Application buffers and delay model

For a saturated 450 Mbit/s service, delay is `bytes / 56,250 bytes per ms`.
These values describe equivalent serialization time, not measured RTT or complete queue occupancy.

| Stage | Before | After | Equivalent time before / after |
| --- | ---: | ---: | ---: |
| Socket unsent threshold | No per-socket limit | 128 KiB | Unknown / 2.33 ms |
| Darwin maximum write overshoot | No separate bound | 64 KiB | Unknown / 1.17 ms |
| h2 stream send buffer | 400 KiB | 128 KiB | 7.28 / 2.33 ms |
| H2 coalescing, normal | 16 KiB | 16 KiB | 0.29 / 0.29 ms |
| H2 coalescing, Linux large-buffer setting | 64 KiB | 64 KiB | 1.17 / 1.17 ms |
| WSS flush threshold, one lane | 8 KiB | 8 KiB | 0.15 / 0.15 ms |
| WSS flush threshold, multiple lanes | 64 KiB | 64 KiB | 1.17 / 1.17 ms |

The H2 stream and coalescing subtotal falls from 7.57 ms to 2.62 ms normally.
With Linux large buffers, this subtotal falls from 8.45 ms to 3.50 ms.
Adding the nominal socket threshold gives approximately 4.95 ms normally, or 5.83 ms with Linux large buffers.
On Darwin, one maximum write increases this subtotal to approximately 6.12 ms.
HTTP/2 encoding, TLS output, packet adapters, and upstream admission add further bounded storage.
These subtotals are not total transport latency guarantees.

WSS readiness checks the queued byte count before accepting another message.
Its queue can therefore exceed the flush threshold by one message and framing overhead.
The existing message limit is 256 KiB; ordinary MTU-sized packets have much smaller overshoot.
Each batch adapter holds at most 64 packets.
The lane partition adds at most one 64-packet batch, with 256 KiB retained capacity across all partitions.
An all-to-one-lane batch uses that shared limit; the partition limit does not multiply by lane count.
At 1280 payload bytes per packet, one 64-packet batch represents 1.46 ms at 450 Mbit/s.
Retained allocation capacity and payload bytes measure different quantities.

H2 flush sends an incomplete coalescing buffer immediately.
Linux large buffers retain the milestone's 64 KiB coalescing threshold to preserve bulk batching.
That threshold represents 1.17 ms at 450 Mbit/s, or 0.075 ms at 7 Gbit/s.
WSS explicit flush drains messages below its threshold.
The lane writer polls sibling flushes when another lane blocks.
No new fill timer delays sparse traffic.

Flow assignments remain stable for the lane group lifetime.
Moving ACK packets from an established bulk flow could reorder that flow.
No packet classification or adaptive lane migration was added.
Multiple saturated lanes can still contribute combined backlog at a shared bottleneck.
TCP loss recovery and network queues can still increase loaded RTT.

## Verification scope

One socket regression checks both endpoints, option readback, and unchanged send buffer capacity.
On Darwin, it also reproduces send admission beyond the readiness limit.
The test checks adapter backpressure and resumed delivery after receiver draining.
Existing H2, WSS, and TCP lane tests cover transport framing and exporter binding.
Benchmarks remain outside this change's verification scope.
