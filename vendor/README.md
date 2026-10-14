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

## QUIC migration policy

`quinn-proto::Connection::set_path_policy` installs a per-connection `PathPolicy`.
The policy checks a new remote endpoint before protocol processing.
`PathPolicy::begin_validation` admits an authenticated non-probing packet before Quinn selects its path or queues responses.
Unknown probing-only paths cannot use the current path's amplification credit.
Receive credit follows the actual source, including packets from the previous path.
It receives a notification only after a matching `PATH_RESPONSE` validates the path.
The policy is checked again at validation because runtime deny rules can change.
A denial preserves the previous path.
Quinn retains its standard path challenges, anti-amplification limit, validation timeout, and congestion handling.

`quinn::Connection::set_path_policy` exposes this hook to the async transport.
LowTier enables port and IP migration only after CONNECT-IP admission and the Noise handshake.
`TransportConfig::migration_requires_policy` prevents migration on connections without this application policy.
The default value remains false for other Quinn users.
LowTier's policy enforces a process-wide budget, one validation per connection, and a cooldown.
Path changes preserve the TLS exporter, Noise session, and process memory credit.
Validated endpoint information supplies peer status and tracker candidate observations.
Local rebinding starts validation through `PathPolicy::begin_local_validation`.
`validation_failed` releases application admission after timeout or revocation.
`LocalPathValidationFinished` identifies the challenge and tells the async transport to retain or restore its socket.
Receive batches identify their socket so an old-socket response cannot validate the replacement socket.
The endpoint retains old receive sockets while connection states hold them.
This also protects pending handshakes that reject a shared endpoint rebind.
`Endpoint::has_server_config` lets LowTier preserve discovery listener sockets.
The protocol regression checks denied responses, probing amplification, source credit, and local validation on the wrong socket.
