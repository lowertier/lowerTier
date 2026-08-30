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
