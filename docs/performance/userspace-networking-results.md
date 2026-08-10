# Userspace networking results

Date: 2026-08-10

## Result

The unprivileged proxy mode passed TCP, UDP, HTTP, and interface tests.

The median steady-state RTT overhead was 0.026 ms on the local encrypted overlay.
SOCKS5 reached 124.483 Mbit/s median throughput.
HTTP CONNECT reached 132.321 Mbit/s median throughput.

The shared proxy process used 24.031 MiB of idle resident memory.
The same process used 23.969 MiB with only SOCKS5 enabled.
The measured 0.062 MiB difference is allocator noise.
The shared process reached 26.078 MiB during transfers.

## Test boundary

The test ran two release EasyTier processes on one Apple M4 Max host.
The host ran macOS 27.0 on ARM64.
Rust 1.95.0 built commit `4a57854c4bd7090594860d50f7d6d945eb0affb8`.

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
EasyTier created no TUN, TAP, or other network interface.

## RTT

Each path used one established TCP connection.
The test discarded ten warm-up exchanges.
The test then recorded 101 request and response exchanges.

| Path | Minimum | Median | Maximum | Overhead versus direct median |
| --- | ---: | ---: | ---: | ---: |
| Direct loopback | 0.073 ms | 0.084 ms | 0.105 ms | Baseline |
| SOCKS5 over EasyTier | 0.104 ms | 0.110 ms | 0.127 ms | 0.026 ms |
| HTTP CONNECT over EasyTier | 0.103 ms | 0.110 ms | 0.152 ms | 0.026 ms |

The measured overhead is below the 0.2 ms target.

## Connection setup

Each value includes proxy negotiation, overlay TCP setup, and one echo exchange.
The median uses 11 runs.

| Path | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Direct loopback | 0.201 ms | 0.259 ms | 0.316 ms |
| SOCKS5 over EasyTier | 0.461 ms | 0.640 ms | 0.685 ms |
| HTTP CONNECT over EasyTier | 0.558 ms | 0.583 ms | 0.901 ms |

## Throughput

Each run transferred 64 MiB over one TCP connection.
The reported value is the median of five runs.

| Path | Runs in Mbit/s | Median |
| --- | --- | ---: |
| Direct loopback | 38925.550, 45916.653, 84566.017, 92710.481, 92094.206 | 84566.017 Mbit/s |
| SOCKS5 over EasyTier | 146.218, 144.134, 124.483, 54.725, 92.327 | 124.483 Mbit/s |
| HTTP CONNECT over EasyTier | 142.654, 143.235, 122.982, 132.321, 118.893 | 132.321 Mbit/s |

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
| SOCKS5 only, idle | 23.969 MiB |
| Shared SOCKS5 and HTTP, idle | 24.031 MiB |
| Shared SOCKS5 and HTTP, active peak | 26.078 MiB |

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

The existing controlled macOS comparison measured native EasyTier L2-TUN against `wireguard-go`.
That comparison measured 496.0 Mbit/s for EasyTier and 376.3 Mbit/s for WireGuard in the forward direction.
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
  -p easytier \
  --bin easytier-core \
  --no-default-features \
  --features socks5,quic

EASYTIER_CORE=/tmp/lowerTier-target/release/easytier-core \
  bash script/tests/userspace-proxy-test.sh
```
