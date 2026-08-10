# Native macOS LowTier versus WireGuard

Date: 2026-07-18

## Result

On this Apple Silicon host, native LowTier L2-TUN is already substantially more CPU-efficient
than the pinned Tailscale `wireguard-go` reference. LowTier is 31.8% faster in the host-to-VM
direction, effectively tied in the reverse direction, and uses fewer native CPU cores per Gbit in
both directions. It pays for that with a larger sampled RSS and a higher unloaded latency floor.

The comparison does not support replacing LowTier's established ChaCha20-Poly1305 implementation
or adding hand-written SIMD. Both implementations already reach architecture-specific ChaCha code.
The next credible gain is structural: keep a received packet vector intact through UDP decode, peer
processing, and the NIC queue, then shard independent flows onto persistent workers while preserving
order within each flow.

## Controlled boundary

The primary topology was:

```text
native macOS client
  -> encrypted UDP over 127.0.0.1 port forwarding
  -> Colima QEMU VM, 4 vCPU and 8 GiB
  -> privileged benchmark container
```

LowTier used native macOS L2-TUN and a Linux LowTier peer. WireGuard used the pinned Tailscale
`wireguard-go` userspace implementation on macOS and kernel WireGuard in the same Linux VM profile.
Both used:

- 1360-byte inner MTU;
- ChaCha20-Poly1305 authenticated encryption;
- eight parallel TCP streams;
- three 10-second throughput runs in each direction;
- a separate 15-second CPU and loaded-latency run;
- the same QEMU profile and host UDP forwarding boundary;
- two complete passes, with the implementation order reversed on pass two.

The WireGuard source revision was `2e01ba5b00f0`. The recorded LowTier base revision was
`5e635e5dc761769ecf337504056ec0c463657ab8`, with the packet-batch work in the dirty feature
worktree. Private WireGuard keys were ephemeral and were not written to the result directory.

This is a dataplane-cost comparison, not a feature-equivalence claim. WireGuard transports L3
packets with a compact direct-peer format. LowTier transports an Ethernet-capable routed overlay
and performs L2-TUN frame preparation and peer selection.

## Throughput and native resource use

Throughput is the median of six independent 10-second samples. CPU/Gbit is the mean of the two
separate 15-second probes. RSS and thread counts are the means of those probe windows.

| Native macOS measurement | LowTier | WireGuard | LowTier relative result |
| --- | ---: | ---: | ---: |
| Forward TCP | 496.0 Mbit/s | 376.3 Mbit/s | 31.8% faster |
| Reverse TCP | 432.8 Mbit/s | 426.9 Mbit/s | 1.4% faster |
| Forward CPU cores/Gbit | 1.145 | 3.791 | 69.8% lower |
| Reverse CPU cores/Gbit | 2.572 | 3.558 | 27.7% lower |
| Sampled RSS | 26.2 MiB | 16.5 MiB | 58.2% higher |
| OS threads | 6.0 | 19.5 | 69.2% fewer |
| `vmmap` physical footprint | 11.9 MiB | 13.4 MiB | 11.2% lower |

The two independent CPU probes were consistent:

| Probe | LowTier forward | WireGuard forward | LowTier reverse | WireGuard reverse |
| --- | ---: | ---: | ---: | ---: |
| Pass 1 cores/Gbit | 1.214 | 3.873 | 2.593 | 3.577 |
| Pass 2 cores/Gbit | 1.076 | 3.708 | 2.552 | 3.538 |

## Latency

QEMU and host port forwarding added visible run-to-run jitter. The unloaded minimum is a more useful
floor than one pass's average, while the loaded average shows behavior during the CPU probe.

| Latency measurement | LowTier | WireGuard |
| --- | ---: | ---: |
| Mean unloaded minimum | 1.936 ms | 0.984 ms |
| Mean unloaded average | 4.829 ms | 2.423 ms |
| Forward loaded average | 2.475 ms | 2.788 ms |
| Reverse loaded average | 2.792 ms | 2.510 ms |

LowTier therefore has an approximately 0.95 ms worse idle RTT floor in this topology. Under load,
the forward direction is 0.31 ms better and the reverse direction is 0.28 ms worse. Throughput and
CPU efficiency do not justify ignoring the idle-latency gap. A future direct host-to-host test should
remove QEMU port forwarding before assigning all of that gap to LowTier itself.

## Profile evidence

The profile runs used symbolized release builds and separate traffic windows. The macOS `sample`
leaf counts below are sampling observations, not syscall invocation counts or percentages.

LowTier's most visible active leaves were:

| Direction | Important sampled leaves |
| --- | --- |
| Forward | scalar UDP `sendto` 254, UDP `recvmsg_x` 110, ChaCha20-Poly1305 seal 35, utun `sendmsg_x` 15 |
| Reverse | UDP `recvmsg_x` 352, scalar UDP `sendto` 278, utun `sendmsg_x` 87, ChaCha20-Poly1305 open 56 |

WireGuard's profile showed:

| Direction | Important sampled leaves |
| --- | --- |
| Forward | utun `read` 2544, UDP `sendmsg` 491, UDP `recvmsg` 79, ARM ChaCha vector path 36 |
| Reverse | utun `read` 2427, UDP `sendmsg` 340, UDP `recvmsg` 294, ARM ChaCha vector path 76 |

The pinned Darwin WireGuard TUN backend reports `BatchSize() == 1`, performs one file read per TUN
read, and loops over writes with one file write per packet. This explains much of its macOS CPU
cost. It is also a warning about the comparison: Tailscale's shipping Network Extension integration
is not identical to this standalone Darwin backend.

LowTier's macOS backend already uses `recvmsg_x` and `sendmsg_x` for utun and feeds the writer with
upstream-ready packets. This is a real current advantage over the pinned reference. At the UDP
socket edge, receive vectors are enabled. Darwin UDP `sendmsg_x` remains opt-in because repeated
A/B tests have not shown a retention-grade improvement.

`sc_usage` returned zero activity even for a root-attached control process on macOS 27, so its data
was excluded. `sample`, `top`, `ps -M`, `vmmap`, interface counters, and iperf results were usable.

## What the reference implementations teach

WireGuard uses pooled packet elements and pooled element containers. A TUN read fills a vector,
classifies packets by peer once, and sends one per-peer container to both a parallel encryption
queue and an ordered peer queue. A sequential sender waits for encryption completion, then emits
the container in order. The receive path mirrors that shape through UDP receive, peer grouping,
parallel decryption, replay validation, and one TUN batch write.

Tailscale's Linux batching wrapper keeps arrays of packet buffers and message descriptors, uses
`sendmmsg` and `recvmmsg`, coalesces compatible packets with UDP GSO, splits UDP GRO results, reuses
batch storage, and disables offload dynamically when the kernel rejects it. LowTier's retained
Linux GSO/GRO work follows the same established mechanisms.

ZeroTier computes a small flow identifier from L3 protocol and L4 ports, maps a flow to a stable
worker bucket, and retains a packet-record pool. This preserves ordering for a flow while allowing
independent flows to proceed concurrently. ZeroTier disables that multiplexer on Apple platforms,
which is another reason not to copy it blindly into the macOS path.

## Rust vectorization and data shape

The expensive operations in the measured path are not simple numeric loops. They are syscalls,
async state transitions, hash and route lookups, reference-counted buffer movement, queue wakeups,
and authenticated encryption. LLVM cannot turn those dependencies into useful SIMD merely by
rewriting an iterator as an index loop.

This was checked on the actual final LTO binary with:

```bash
cargo rustc --locked --release -p lowertier --bin lowertier-core -- \
  -C debuginfo=1 -C remark=loop-vectorize
```

LLVM emitted 79 missed loop-vectorization remarks and no passed remark. None of the remarks mapped
to the measured `virtual_nic`, `darwin_tun`, `peer_manager`, `peer_conn`, packet-batch, MPSC, ring,
or UDP vector-I/O files. The common reasons elsewhere were calls inside the loop, early exits,
unsupported control flow, or values escaping the loop. This matches the profile: the current hot
path does not contain a flat arithmetic loop that the compiler can profitably widen.

The established `ring` ChaCha implementation already dispatches to an AArch64 NEON path for
sufficiently large inputs. The LowTier profile reached `ring_core_0_17_14__chacha20_poly1305_*`;
the WireGuard profile reached `golang.org/x/crypto/chacha20.xorKeyStreamVX`. Hand-written Rust SIMD
around either library would duplicate mature cryptographic code and would violate the project's
crypto rule.

Data that may benefit from compiler vectorization should be kept flat and independent, for example
checksum preparation or fixed-width descriptor validation. The packet control plane should instead
be shaped for cache locality and fewer transitions:

```text
BatchStorage
  payloads: owned packet buffers
  lengths: contiguous u16/u32 array
  peer_ids: contiguous u32 array
  flow_ids: contiguous u32 array
  flags: contiguous bytes
```

That structure-of-arrays form lets routing, accounting, and eligibility scans touch only the fields
they need. It should not replace owned payload buffers or weaken bounds. A practical implementation
can start with a compact descriptor array beside the existing `ZCPacket` owners, then prove with
LLVM remarks and assembly that a specific flat loop vectorizes before retaining it.

## Rejected experiment: coherent ring flush

A narrow experiment buffered one ring flush round before publishing its packets. The hypothesis was
that the UDP sender would see fuller ready batches and make Darwin `sendmsg_x` profitable. A new test
first demonstrated the old partial-publication behavior, then passed with coherent publication.

Adjacent three-run A/B results were:

| Configuration | Forward median | Reverse median | Forward cores/Gbit | Reverse cores/Gbit |
| --- | ---: | ---: | ---: | ---: |
| Existing ring, scalar UDP | 495.1 Mbit/s | 427.2 Mbit/s | 1.055 | 2.411 |
| Coherent ring, scalar UDP | 518.5 Mbit/s | 420.2 Mbit/s | 1.036 | 2.485 |
| Existing ring, `sendmsg_x` | 497.4 Mbit/s | 429.2 Mbit/s | 1.017 | 2.387 |
| Coherent ring, `sendmsg_x` | 509.4 Mbit/s | 424.9 Mbit/s | 1.034 | 2.405 |

The best throughput change was 4.7%, forward CPU improved only 1.7%, and reverse efficiency
regressed. This missed the 15% retention gate, so the source change and its temporary test were
removed.

## Next implementation boundary

The next useful change is not another local `try_send` or flush tweak. It is an explicit batch API
across the receive side:

1. Let UDP receive return one bounded batch item rather than immediately flattening it into the
   ring.
2. Decode and authenticate the batch while retaining its descriptor storage.
3. Group packets by destination and flow once.
4. Send a bounded batch through peer processing and the NIC channel with packet-count credits, not
   merely batch-count capacity.
5. Use persistent flow workers only after the single-threaded batch path is measured. Hash each
   independent flow to one worker and preserve order within that worker.
6. Feed the resulting batch directly to the existing macOS utun `sendmsg_x` writer.

This requires a deliberate stream/sink contract change. Hiding it inside one ring flush was too
small to remove the scalar boundaries and produced no retention-grade result.

## Reproduce

```bash
RUNS=3 DURATION=10 CPU_DURATION=15 PROFILE_DURATION=0 \
  PARALLEL_STREAMS=8 MTU=1360 HOST_UDP_PORT=12014 \
  RESULT_DIR=/tmp/lowertier-vs-wireguard-et \
  script/macos-tun-bench/e2e.sh target/release/lowertier-core

RUNS=3 DURATION=10 CPU_DURATION=15 PROFILE_DURATION=0 \
  PARALLEL_STREAMS=8 MTU=1360 HOST_UDP_PORT=12020 \
  RESULT_DIR=/tmp/lowertier-vs-wireguard-wg \
  script/wireguard-macos-bench/e2e.sh
```

Set `PROFILE_DURATION=8` for separate `sample`, `vmmap`, interface-counter, and resource windows.
