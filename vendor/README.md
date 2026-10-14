# Vendored Rust dependencies

LowTier keeps local dependency snapshots for transport, userspace networking, platform interfaces, and service management.
Local path dependencies preserve the patches used by the core build.

| Directory | Version or revision | Purpose |
| --- | --- | --- |
| `quinn` | 0.11.11 | Async QUIC transport with local transport patches. |
| `quinn-proto` | 0.11.16 | QUIC protocol state and DATAGRAM handling. |
| `quincy-tun` | 1.0.0 | Async interface access for the QUIC transport. |
| `smoltcp` | 0.12.0 | IP stack for userspace networking. |
| `rust-tun` | `12378839e7985283df0e4fb536b7137230356db5` | Platform TUN and TAP interface access. |
| `service-manager-rs` | `5eb28f7a686858eea4f4933534ed989d3b71dc2a` | Operating system service installation and control. |
| `thunk` | `cbbeec75a66b7b3cf0824ae890d9d06bcfb9d1f3` | Windows API compatibility during builds. |
| `tokio-websockets` | `dc9771c7c215882349c3cb328877550a3593df21` | Async WebSocket transport for WSS. |
| `windivert-rust` | `adcc56d1550f7b5377ec2b3429f413ee24a77375` | Windows packet capture and injection bindings. |

The import changes package names and metadata where the LowTier build requires them.
The repository formatter also formats the imported Rust source.
Each dependency keeps its included license files and package license metadata.
