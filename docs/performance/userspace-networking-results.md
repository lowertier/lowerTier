# Userspace networking results

Date: 2026-08-10

## Result

The unprivileged proxy mode passed TCP, UDP, HTTP, and interface tests.

The median steady-state RTT overhead was 0.022 ms for SOCKS5.
The median overhead was 0.116 ms for HTTP CONNECT.
SOCKS5 reached 124.560 Mbit/s median throughput.
HTTP CONNECT reached 105.891 Mbit/s median throughput.

The shared proxy process used 23.953 MiB of idle resident memory.
The same process used 23.984 MiB with only SOCKS5 enabled.
The measured 0.031 MiB difference is allocator noise.
The shared process reached 25.750 MiB during transfers.

## Test boundary

The test ran two release LowTier processes on one Apple M4 Max host.
The host ran macOS 27.0 on ARM64.
Rust 1.95.0 built commit `b0a3c41638731521e516801f0e738b2b81c179f1`.

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
| Direct loopback | 0.070 ms | 0.087 ms | 0.129 ms | Baseline |
| SOCKS5 over LowTier | 0.101 ms | 0.109 ms | 0.142 ms | 0.022 ms |
| HTTP CONNECT over LowTier | 0.130 ms | 0.203 ms | 0.278 ms | 0.116 ms |

The measured overhead is below the 0.2 ms target.

## Connection setup

Each value includes proxy negotiation, overlay TCP setup, and one echo exchange.
The median uses 11 runs.

| Path | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Direct loopback | 0.207 ms | 0.217 ms | 0.357 ms |
| SOCKS5 over LowTier | 0.398 ms | 0.428 ms | 0.677 ms |
| HTTP CONNECT over LowTier | 0.577 ms | 0.606 ms | 0.871 ms |

## Throughput

Each run transferred 64 MiB over one TCP connection.
The reported value is the median of five runs.

| Path | Runs in Mbit/s | Median |
| --- | --- | ---: |
| Direct loopback | 44243.195, 43276.410, 83391.477, 82659.109, 82514.597 | 82514.597 Mbit/s |
| SOCKS5 over LowTier | 121.067, 124.560, 127.369, 129.481, 124.399 | 124.560 Mbit/s |
| HTTP CONNECT over LowTier | 113.273, 102.832, 102.969, 106.671, 105.891 | 105.891 Mbit/s |

A separate 512 MiB run reached 105.894 Mbit/s through SOCKS5.
The same run reached 121.630 Mbit/s through HTTP CONNECT.
These results confirm the lower sustained range.

The shared protocol detector reads only the first client byte.
The detector performs no work on transferred payload bytes.
The shared listener therefore adds no steady-state data copy.

## Memory

The idle values are medians from ten process samples.
The active value is the highest sample during the transfer series.

| Client process mode | Resident memory |
| --- | ---: |
| SOCKS5 only, idle | 23.984 MiB |
| Shared SOCKS5 and HTTP, idle | 23.953 MiB |
| Shared SOCKS5 and HTTP, active peak | 25.750 MiB |

One shared address creates one listener and one userspace network stack.
The UDP association limits one client to 256 active targets.
Each UDP response task uses one bounded 8 KiB buffer.

## Profile evidence

An eight-second macOS sample covered a 512 MiB proxy transfer.
Most samples waited in `kevent`, condition variables, or work queues.
The important active leaves were 311 `sendto` samples and 258 `recvmsg_x` samples.
The profile recorded 16 `memmove` samples and six small allocation samples.

The profile did not show an encryption or allocation hot loop.
The current limit is userspace packet and TCP progress through smoltcp.
The evidence does not support a small loop or constant adjustment.
A larger gain requires a structural stream or batch path change.

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
export CARGO_TARGET_DIR=/tmp/lowerTier-target
cargo build --release --locked \
  -p lowertier \
  --bin lowertier-core \
  --no-default-features \
  --features socks5,quic

LOWTIER_CORE=/tmp/lowerTier-target/release/lowertier-core \
  bash script/tests/userspace-proxy-test.sh
```
