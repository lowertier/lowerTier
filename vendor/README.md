# Vendored Rust dependencies

LowTier vendors patched dependencies that are not available under stable registry identities.
Local path dependencies make builds reproducible after the project rename.

| Directory | Version or revision | Source |
| --- | --- | --- |
| `boringtun-lowertier` | 0.6.1 | Patched BoringTun snapshot |
| `http_req` | `b10aa9fc0db3067cc3d2174683a87250b80a1ea9` | `https://github.com/jayjamesjay/http_req` fork snapshot |
| `kcp-sys` | `d7427c22d764deb1860a7d37acc446ed5033464c` | Patched KCP snapshot |
| `rust-tun` | `12378839e7985283df0e4fb536b7137230356db5` | Patched Rust TUN snapshot |
| `service-manager-rs` | `5eb28f7a686858eea4f4933534ed989d3b71dc2a` | `https://github.com/chipsenkbeil/service-manager-rs` fork snapshot |
| `thunk` | `cbbeec75a66b7b3cf0824ae890d9d06bcfb9d1f3` | `https://github.com/felixmaker/thunk` fork snapshot |
| `tokio-websockets` | `dc9771c7c215882349c3cb328877550a3593df21` | `https://github.com/Gelbpunkt/tokio-websockets` fork snapshot |
| `windivert-rust` | `adcc56d1550f7b5377ec2b3429f413ee24a77375` | `https://github.com/Rubensei/windivert-rust` fork snapshot |

The import changes package names and metadata where the LowTier build requires them.
The repository formatter also formats the imported Rust source.
Each dependency keeps its included license files and package license metadata.
