# Userspace networking results

Date: 2026-08-25

## Result

The unprivileged proxy mode passed TCP, UDP, HTTP, and interface tests.

The median steady-state RTT overhead was 0.058 ms for SOCKS5.
The median overhead was 0.056 ms for HTTP CONNECT.
SOCKS5 reached 198.327 Mbit/s median throughput.
HTTP CONNECT reached 203.635 Mbit/s median throughput.

The shared proxy process used 27.234 MiB of idle resident memory.
The same process used 27.453 MiB with only SOCKS5 enabled.
The measured 0.219 MiB difference is allocator noise.
The shared process reached 28.766 MiB during transfers.

## Test boundary

The test ran two release LowTier processes on one ARM64 host.
Rust 1.95.0 built the current worktree.

The build used only the `socks5` and `quic` features.
Both nodes used the default ChaCha20-Poly1305 overlay encryption.
The underlay used UDP through loopback.
The client used `--tun=userspace-networking`.
The SOCKS5 and HTTP proxies shared one loopback listener.

This same-host test isolates userspace path overhead.
It does not represent Internet capacity or latency.

## Correctness

| Check | Result |
| --- | --- |
| SOCKS5 TCP through the overlay | Pass |
| SOCKS5 UDP association through the overlay | Pass |
| HTTP CONNECT through the overlay | Pass |
| Ordinary HTTP forwarding through the overlay | Pass |
| Peer hostname resolution through the overlay | Pass |
| Operating system interface list | No change |
| Effective user identifier | 501 |

The test used no administrator privileges.
LowTier created no TUN, TAP, or other network interface.

## RTT

Each path used one established TCP connection.
The test discarded ten warm-up exchanges.
The test then recorded 101 request and response exchanges.

| Path | Minimum | Median | Maximum | Overhead versus direct median |
| --- | ---: | ---: | ---: | ---: |
| Direct loopback | 0.073 ms | 0.088 ms | 0.108 ms | Baseline |
| SOCKS5 over LowTier | 0.117 ms | 0.146 ms | 0.267 ms | 0.058 ms |
| HTTP CONNECT over LowTier | 0.119 ms | 0.144 ms | 0.163 ms | 0.056 ms |

The measured overhead is below the 0.2 ms target.

## Connection setup

Each value includes proxy negotiation, overlay TCP setup, and one echo exchange.
The median uses 11 runs.

| Path | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Direct loopback | 0.216 ms | 0.227 ms | 0.261 ms |
| SOCKS5 over LowTier | 0.409 ms | 0.476 ms | 0.746 ms |
| HTTP CONNECT over LowTier | 0.417 ms | 0.447 ms | 0.707 ms |

## Throughput

Each run transferred 64 MiB over one TCP connection.
The reported value is the median of five runs.

| Path | Runs in Mbit/s | Median |
| --- | --- | ---: |
| Direct loopback | 40683.467, 43048.253, 44486.843, 85388.721, 85788.384 | 44486.843 Mbit/s |
| SOCKS5 over LowTier | 195.588, 198.327, 197.080, 201.518, 200.763 | 198.327 Mbit/s |
| HTTP CONNECT over LowTier | 202.603, 203.635, 203.796, 203.098, 204.624 | 203.635 Mbit/s |

SOCKS5 improved by 59.2 percent from the 2026-08-10 median.
HTTP CONNECT improved by 92.3 percent from the 2026-08-10 median.

The shared protocol detector reads only the first client byte.
The detector performs no work on transferred payload bytes.
The shared listener therefore adds no steady-state data copy.

## Memory

The idle values are medians from ten process samples.
The active value is the highest sample during the transfer series.

| Client process mode | Resident memory |
| --- | ---: |
| SOCKS5 only, idle | 27.453 MiB |
| Shared SOCKS5 and HTTP, idle | 27.234 MiB |
| Shared SOCKS5 and HTTP, active peak | 28.766 MiB |

One shared address creates one listener and one userspace network stack.
The UDP association limits one client to 256 active targets.
Each UDP response task uses one bounded 8 KiB buffer.

## Data movement evidence

Ingress now moves each owned packet into the userspace stack without a payload copy.
Egress now allocates the final packet buffer before smoltcp writes the payload.
The fabric sender drains all ready egress packets into one bounded batch.
The proxy adapters no longer resolve peer names through system DNS first.

The current SOCKS5 median is 4.96 percent of the 4 Gbit/s target.
At a 1284-byte MTU, 4 Gbit/s requires approximately 389,000 packets each second.
The measured SOCKS5 rate represents approximately 19,300 full-size packets each second.
The remaining factor is 20.2.
One smoltcp reactor and its shared socket state remain the dominant structural limit.
A direct overlay stream transport is required for a 4 Gbit/s TCP proxy target.

## Direct QUIC connector experiment

Date: 2026-08-29

The TCP proxy now opens eligible QUIC streams at the SOCKS5 and HTTP connector boundary.
It no longer writes proxy payload into source-side smoltcp merely to packetize it and reconstruct it in the QUIC source proxy.
The destination policy check remains mandatory; unavailable or disallowed QUIC destinations retain the existing fallback path.
UDP continues to use smoltcp.

The experiment compared control and candidate modes in ABBA order with the same release binary.
Each position transferred 64 MiB three times per proxy protocol.
All correctness checks passed in all four positions.

| Metric | Control mean | Direct QUIC mean | Change |
| --- | ---: | ---: | ---: |
| HTTP CONNECT throughput | 422.514 Mbit/s | 502.279 Mbit/s | +18.9% |
| SOCKS5 throughput | 412.260 Mbit/s | 467.342 Mbit/s | +13.4% |
| HTTP CONNECT median RTT | 0.205 ms | 0.166 ms | -0.039 ms |
| SOCKS5 median RTT | 0.268 ms | 0.280 ms | +0.012 ms |
| Active resident-memory peak | 33.664 MiB | 30.250 MiB | -3.414 MiB |

A second ABBA run measured client and server process CPU time while transferring 128 MiB twice per proxy protocol.
CPU work fell from 122.44 to 103.43 process-seconds per overlay GiB, a 15.5 percent reduction.
Concurrent CPU use rose 3.7 percent while active because the candidate completed transfers faster.
The CPU figure includes identical direct-loopback control work, so it is a conservative comparative measure rather than isolated overlay CPU cost.

The direct path removes a source smoltcp socket-buffer copy, TCP segmentation/reassembly work, and the associated reactor and packet-queue handoffs.
The application proxy buffer writes directly to the QUIC stream, after which QUIC datagrams enter the normal encrypted peer pipeline.
This reduces ownership transitions and cache traffic without changing overlay encryption or destination handling.

### Remaining QUIC overhead

A 2026-08-29 protocol ABBA comparison used one release binary containing both proxy transports.
Direct KCP used the same peer routing, outer encryption, and UDP underlay as direct QUIC, making it an architectural diagnostic for the inner transport cost.

| Metric | Direct QUIC | Direct KCP | Change |
| --- | ---: | ---: | ---: |
| HTTP CONNECT throughput | 549.182 Mbit/s | 923.031 Mbit/s | +68.1% |
| SOCKS5 throughput | 553.592 Mbit/s | 924.160 Mbit/s | +66.9% |
| CPU work | 108.60 s/GiB | 50.61 s/GiB | -53.4% |
| Idle resident memory | 28.297 MiB | 27.516 MiB | -0.781 MiB |
| Active resident-memory peak | 30.023 MiB | 29.852 MiB | -0.172 MiB |

KCP is an optional diagnostic here, not a recommendation to add its C dependency back to the maintained lean build.
The result shows that the shared LowTier peer, encryption, routing, and UDP path can approach 1 Gbit/s.
The direct QUIC path remains limited by a second encrypted reliable transport: Quinn copies each transmit into a margin-bearing buffer, performs TLS packet protection, congestion and loss accounting, sends it through a task/channel handoff, and copies received packets into Quinn buffers.
LowTier then applies the normal outer authenticated encryption and UDP transport.

Two narrower experiments were rejected:

- Reducing each QUIC proxy channel from 1,024 to 64 entries changed active RSS by only -320 KiB and reduced SOCKS5 throughput by 1.25 percent. The queues were not retaining enough datagrams to explain active memory.
- Draining ready QUIC datagrams into peer batches reduced HTTP throughput by 6.87 percent and SOCKS5 throughput by 5.30 percent. macOS still issued scalar UDP sends, so batching added staging without removing system calls.

This explains an important difference from Tailscale.
Tailscale carries TCP through one packet transport and one WireGuard protection layer; its proxy handoff is a pair of `io.Copy` loops.
On Linux it also benefits from owned packet batches and UDP GRO/GSO.
On macOS Tailscale and wireguard-go deliberately use batch size one, but they still avoid an inner QUIC-over-encrypted-overlay stack.
The next maintained-path improvement should replace inner QUIC with a lightweight authenticated overlay stream or reuse an existing reliable peer stream, rather than add more buffering or batching around Quinn.

## Lightweight overlay stream experiment

Date: 2026-08-29

`LOWTIER_EXPERIMENT_OVERLAY_STREAM=1` replaces the inner Quinn/TLS proxy transport with a reliable stream carried by ordinary encrypted LowTier peer packets. It keeps peer routing and relay handling, outer authenticated encryption, destination mapping, destination ACL evaluation, and the existing kernel/smoltcp fallback selection. It does not add a second TLS or payload-encryption layer.

Each stream has a 256 KiB byte-bounded send window and a 256 KiB byte-bounded receive window. The protocol uses 1,024-byte owned `Bytes` chunks, cumulative acknowledgements, advertised receive capacity, retransmission, out-of-order reassembly, and explicit OPEN, FIN, and RESET frames. FIN cannot pass queued writes or lower-sequence reordered data. The application upload path reads directly into `BytesMut`, freezes and splits that allocation, and passes the resulting shared `Bytes` to the reliability owner; retransmission retains those same allocations until acknowledgement.

A 128 MiB, three-run-per-protocol ABBA comparison against direct QUIC produced:

| Metric | Direct QUIC | Overlay stream | Change |
| --- | ---: | ---: | ---: |
| HTTP CONNECT throughput | 541.9 Mbit/s | 1,160.2 Mbit/s | +114.1% |
| SOCKS5 throughput | 551.6 Mbit/s | 1,187.2 Mbit/s | +115.2% |
| HTTP CONNECT median RTT | 0.181 ms | 0.143 ms | -0.038 ms |
| SOCKS5 median RTT | 0.306 ms | 0.146 ms | -0.160 ms |
| Idle resident memory | 28.211 MiB | 26.828 MiB | -1.383 MiB |
| Active resident-memory peak | 29.734 MiB | 28.969 MiB | -0.766 MiB |

All SOCKS5 TCP/UDP, HTTP CONNECT/forwarding, hostname-resolution, unprivileged-operation, and interface-integrity checks passed in every position. A separate run completed three 128 MiB transfers for each TCP proxy protocol.

CPU ABBA measurement reduced total work from 88.43 to 57.08 process-seconds per overlay GiB, a 35.5 percent reduction. Active parallel CPU rose from 521 to 732 percent because the transfers completed more than twice as quickly. An isolated generic-buffer versus owned-buffer overlay comparison found no material throughput or RSS change and 0.8 percent more CPU work, within run noise; ownership was retained because it satisfies the bounded lifetime and copy-traffic design requirement without a demonstrated material regression.

Two subsequent stream-layer changes were retained. Increasing the MTU-safe data chunk from 1,024 to 1,120 bytes reduced packet count by 8.6 percent and CPU work by 2.4 percent without a material throughput regression. Replacing the unconditional 1 ms per-stream tick with active ACK, OPEN, FIN, and retransmission deadlines improved HTTP throughput by 4.8 percent, SOCKS5 throughput by 1.7 percent, and CPU work per GiB by 6.6 percent. An idle established stream now has no timer deadline; delayed ACKs fire immediately after 64 KiB of progress or after at most 1 ms.

Receive-side vectored coalescing was rejected. It reduced CPU work by about 5 percent but reduced HTTP throughput by 1.9 percent and SOCKS5 throughput by 2.8 percent on macOS, with no material RTT or RSS benefit. No-delay stream packet batching was also rejected: HTTP throughput fell 15.2 percent, SOCKS5 throughput fell 12.8 percent, idle RSS rose 304 KiB, and active RSS rose 568 KiB. The macOS transport remained scalar, so staging retained more packet containers without eliminating final sends.

The overlay packet builder now appends initialized frame headers and retained payload directly into reserved packet capacity instead of zero-filling the complete payload and overwriting it. Controlled runs showed about 0.5 percent lower CPU work overall, a 1.2 percent reduction in the stable adjacent pair, no idle RSS change, and no repeatable throughput or latency regression.

Streams now cache a sole live direct peer connection and bypass repeated route, peer, flow-classification, and connection-selection work. Relay and multipath destinations retain normal routing. A failed cached send removes the entry so the retained retransmission replans through the normal path. Controlled ABBA results improved HTTP and SOCKS5 throughput by 2.3 percent, reduced CPU work per GiB by 1.7 percent, left RTT neutral, and changed RSS by less than one allocator page per process.

This remains an explicit experiment while wire capability negotiation and mixed-version fallback are unresolved. Enabling it requires compatible peers; default direct QUIC remains the safe maintained path.

## WireGuard status

The existing controlled macOS comparison measured native LowTier L2-TUN against `wireguard-go`.
That comparison measured 496.0 Mbit/s for LowTier and 376.3 Mbit/s for WireGuard in the forward direction.
The reverse results were 432.8 Mbit/s and 426.9 Mbit/s.

The userspace proxy result is lower than both native interface paths.
This result is expected because each proxy connection uses an additional userspace TCP stack.
The two measurements use different topologies, so their exact values are not directly comparable.
See the [WireGuard resource comparison](wireguard-resource-comparison.md).

Use native TUN or TAP when throughput is the primary requirement.
Use userspace networking when the process cannot create a kernel interface.

## Reproduce

```bash
export CARGO_TARGET_DIR=/tmp/lowertier-target
cargo build --release --locked \
  -p lowertier \
  --bin lowertier-core \
  --no-default-features \
  --features socks5,quic

LOWTIER_CORE=/tmp/lowertier-target/release/lowertier-core \
  bash script/tests/userspace-proxy-test.sh
```
