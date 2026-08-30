# Fabric protocol v4 transfer results

Date: 2026-08-23

These tests measure the unified fabric packet path.
They include the unified batch API and real TUN and TAP devices.
All data stayed in memory or temporary storage.
The test reused an existing Colima profile.
The test did not create a VM.

## Test system

The Colima profile used QEMU with four ARM64 CPUs and 8 GiB of memory.
The Linux tests used real `/dev/net/tun` TUN and TAP interfaces.
The native macOS test used an `utun` interface.
The dataplane used `chacha20-poly1305` encryption and a 1360-byte inner MTU.

The raw Docker bridge reached 114.00 Gbit/s with one TCP flow.
It reached 128.98 Gbit/s with four TCP flows.
The raw substrate was not the throughput limit.

The kernel WireGuard comparison used Linux 6.8.0-117-generic.
The in-tree WireGuard 1.0.0 module handled both endpoints.
No `wireguard-go` process ran during this comparison.

## Cost model

Let `N` be the packet count.
Let `P` be the total payload bytes.
Let `B` be the fabric batch size.

The scalar API performs `N` shared send-boundary operations.
The batch API reduces these operations toward `ceil(N / B)`.
Packet validation, route selection, encryption, and transport processing remain `O(N)`.
Payload movement remains `O(P)`.
The live batch metadata is `O(B)`.

Compact IP traffic omits the 14-byte Ethernet header at the interface boundary.
This change removes approximately 1 percent of traffic for a 1400-byte IP packet.
Compatible Ethernet traffic keeps the complete Ethernet frame.

The synthetic ring test isolates the fabric API and routing work.
The TUN and TAP tests also include kernel transitions, encryption, and UDP transport.
These per-packet operations dominate the end-to-end result after fabric batching removes repeated shared work.

## Unified fabric batch ceiling

The final 1400-byte Criterion test used eight worker threads and 128 in-flight scalar sends.
Each final result used a one-second warm-up and a two-second measurement.
Each result used ten samples.
The 512-byte results came from the earlier four-worker matrix.

| IP packet | Path | Batch | Throughput | Relative to scalar |
| ---: | --- | ---: | ---: | ---: |
| 1400 bytes | scalar fabric send | 1 | 96.60 MiB/s | 1.00x |
| 1400 bytes | unified fabric batch | 64 | 270.51 MiB/s | 2.80x |
| 1400 bytes | concurrent scalar sends | 1 | 110.91 MiB/s | 1.15x |
| 512 bytes | scalar fabric send | 1 | 32.10 MiB/s | 1.00x |
| 512 bytes | unified fabric batch | 64 | 82.17 MiB/s | 2.56x |
| 512 bytes | concurrent scalar sends | 1 | 41.02 MiB/s | 1.28x |

The 1400-byte batch result equals 2.27 Gbit/s of IP payload.
A batch size of 16 also reached 276.10 MiB/s for 1400-byte packets.
Batch sizes above 16 did not give a material gain in this test.

## Linux TUN and TAP throughput

These tests ran two LowTier nodes in the existing Colima VM.
Each endpoint used a real Linux virtual interface.
Each TCP result used a five-second measurement after a one-second omit period.
The table reports the median received payload rate.

| Adapter | Direction | TCP flows | Median | Minimum | Maximum |
| --- | --- | ---: | ---: | ---: | ---: |
| TUN | forward | 1 | 1.263 Gbit/s | 1.243 Gbit/s | 1.283 Gbit/s |
| TUN | reverse | 1 | 1.192 Gbit/s | 1.182 Gbit/s | 1.202 Gbit/s |
| TUN | forward | 4 | 1.664 Gbit/s | 1.663 Gbit/s | 1.664 Gbit/s |
| TUN | reverse | 4 | 1.593 Gbit/s | 1.563 Gbit/s | 1.622 Gbit/s |
| TAP | forward | 1 | 1.256 Gbit/s | 1.255 Gbit/s | 1.256 Gbit/s |
| TAP | reverse | 1 | 1.253 Gbit/s | 1.220 Gbit/s | 1.262 Gbit/s |
| TAP | forward | 4 | 1.712 Gbit/s | 1.701 Gbit/s | 1.723 Gbit/s |
| TAP | reverse | 4 | 1.610 Gbit/s | 1.573 Gbit/s | 1.636 Gbit/s |

The unloaded TUN latency averaged 0.335 ms across 100 packets.
The unloaded TAP latency averaged 0.357 ms across 100 packets.
Both tests had zero unloaded packet loss.
The LowTier resident set was approximately 25 MiB to 27 MiB per Linux node.

The TUN CPU probes delivered 1.591 Gbit/s in both directions.
The two nodes used 1.05 cores per Gbit/s forward.
They used 1.13 cores per Gbit/s reverse.
The TAP CPU probes delivered 1.552 Gbit/s forward and 1.554 Gbit/s reverse.
The two nodes used 1.09 cores per Gbit/s forward.
They used 1.12 cores per Gbit/s reverse.

## Kernel WireGuard target

The kernel WireGuard test used the same four-CPU QEMU VM.
Two containers supplied separate network namespaces.
Both `wg0` interfaces used the Linux kernel WireGuard module.
Each workload used three eight-second samples and a two-second omit period.

| Direction | TCP flows | Median | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| forward | 1 | 8.38 Gbit/s | 8.36 Gbit/s | 8.45 Gbit/s |
| forward | 4 | 8.40 Gbit/s | 8.32 Gbit/s | 8.60 Gbit/s |
| reverse | 1 | 8.21 Gbit/s | 6.64 Gbit/s | 8.36 Gbit/s |
| reverse | 4 | 6.62 Gbit/s | 4.09 Gbit/s | 8.44 Gbit/s |

The raw bridge reached 111.94 Gbit/s with one flow.
It reached 127.37 Gbit/s with four flows.
The WireGuard forward result was stable across all samples.
The reverse result had more QEMU scheduling variation.

Unloaded WireGuard latency averaged 0.221 ms across 100 packets.
The test had zero unloaded packet loss.
The forward CPU probe delivered 7.83 Gbit/s and used 3.47 total VM cores.
The reverse CPU probe delivered 8.39 Gbit/s and used 3.55 total VM cores.
These totals include kernel workers, iperf, Docker, and VM background work.

The 8.38 Gbit/s forward median is 4.89 times the 1.712 Gbit/s TAP result.
It is 5.04 times the 1.664 Gbit/s TUN result.
The measurements used different sample counts and durations.
Therefore, these ratios show the target gap and not a strict regression result.

## Native macOS TUN throughput

The native LowTier node used `utun14`.
The Linux peer connected from Colima through `host.docker.internal`.
This connection avoided experimental Colima UDP port forwarding.

| Direction | TCP flows | Received payload | Retransmits |
| --- | ---: | ---: | ---: |
| forward | 1 | 0.12 Gbit/s | 0 |
| reverse | 1 | 0.51 Gbit/s | 648 |
| forward | 4 | 0.80 Gbit/s | 0 |
| reverse | 4 | 2.23 Gbit/s | 1410 |

The one-flow CPU probes delivered 0.81 Gbit/s forward and 1.30 Gbit/s reverse.
The native process used 0.707 and 0.680 CPU cores per Gbit/s, respectively.
The native process used approximately 27.3 MiB to 27.5 MiB of resident memory.
Unloaded latency averaged 0.778 ms in the one-flow run.

The native results varied between consecutive workloads.
The four-flow reverse CPU probe delivered no payload after the throughput run.
Therefore, 2.23 Gbit/s is a measured peak and not a stable capacity claim.

## Findings

The unified batch API removes most repeated send-boundary work.
It gives a 2.80x synthetic gain for 1400-byte packets.
Real Linux TUN and TAP traffic reaches 1.66 Gbit/s to 1.71 Gbit/s with four flows.
The native macOS utun path also passes real traffic in both directions.

Kernel WireGuard reaches 8.38 Gbit/s in the same four-CPU VM.
The unified fabric is therefore below the useful target by approximately five times.
The 2.27 Gbit/s ring result also shows that kernel entry is not the primary explanation.

Tailscale and `wireguard-go` show the required userspace structure.
They retain vectors of up to 128 packets before peer selection and encryption.
Persistent workers encrypt packets in parallel.
A sequential per-peer sender preserves packet order after encryption.
Linux uses batched UDP I/O, UDP GSO and GRO, and TUN TSO and GRO.

LowTier now keeps batch ownership through routing, link encryption, UDP admission, and Linux TUN delivery.
Persistent encryption workers replace batch-scoped worker creation.
The direct sender preserves one ordered sequence after concurrent preparation.
The UDP path uses native batch admission and reserves one I/O quantum for reliable control.
The Linux TUN path keeps offload metadata and bounds each kernel I/O quantum to eight packets.
The direct NIC path drops lossy bulk when its bounded queue is full.
It does not block peer control processing behind a stalled kernel writer.

The complete TUN matrix kept one peer connection for all workloads.
The combined TAP matrix reconnected after approximately 52 seconds.
A fresh TAP reverse matrix completed three one-flow and three four-flow samples without a reconnect.
The TAP connection-age defect remains open.

These measurements do not have a matched old-protocol baseline.
They do not prove a performance regression or improvement against the removed implementations.
Use the repository performance gate with matched builds before a release decision.

## Commands

The ring ceiling used this command:

```bash
TX_THROUGHPUT_TUNNEL=ring \
TX_THROUGHPUT_PKT_SIZE=1400 \
TX_THROUGHPUT_WORKER_THREADS=8 \
TX_THROUGHPUT_INFLIGHT=128 \
TX_THROUGHPUT_BATCH_SIZE=64 \
TX_THROUGHPUT_WARMUP_SECS=1 \
TX_THROUGHPUT_MEASUREMENT_SECS=2 \
TX_THROUGHPUT_SAMPLE_SIZE=10 \
cargo bench -p lowertier --bench tx_throughput
```

The current Linux device test uses automatic TAP selection:

```bash
BUILD_IMAGE=0 \
RUN_TCP=1 RUN_UDP=0 RUN_CPU_PROBE=1 \
RUNS=2 DURATION=5 CPU_DURATION=5 PARALLEL_STREAMS=4 \
script/colima-throughput/e2e.sh
```

The native macOS device test used this command shape:

```bash
COLIMA_PROFILE=PROFILE_NAME \
DOCKER_CONTEXT=DOCKER_CONTEXT_NAME \
RUNS=1 DURATION=5 CPU_DURATION=5 PROFILE_DURATION=0 \
PARALLEL_STREAMS=4 \
script/macos-tun-bench/e2e.sh target/release/lowertier-core
```

The kernel WireGuard target used this command:

```bash
COLIMA_PROFILE=PROFILE_NAME \
DOCKER_CONTEXT=DOCKER_CONTEXT_NAME \
RUNS=3 DURATION=8 CPU_DURATION=8 OMIT=2 \
STREAM_COUNTS="1 4" \
script/kernel-wireguard-bench/e2e.sh
```
