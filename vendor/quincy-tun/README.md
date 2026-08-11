# quincy-tun
[![Crates.io](https://img.shields.io/crates/v/quincy-tun.svg)](https://crates.io/crates/quincy-tun)
[![Documentation](https://docs.rs/quincy-tun/badge.svg)](https://docs.rs/quincy-tun/)
[![Build status](https://github.com/quincy-rs/quincy-tun/workflows/CI/badge.svg)](https://github.com/quincy-rs/quincy-tun/actions?query=workflow%3ACI)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

quincy-tun is a cross-platform asynchronous TUN interface library built for [Quincy](https://github.com/quincy-rs/quincy). It is based on [tun-rs](https://github.com/tun-rs/tun-rs) and provides only the Tokio API used by Quincy, including optional GSO/GRO offload on Linux.

## Table of contents
- [Supported platforms](#supported-platforms)
- [Installation](#installation)
- [Usage](#usage)
  - [Desktop platforms](#desktop-platforms)
  - [Mobile platforms](#mobile-platforms)
  - [Linux offload](#linux-offload)
- [Building from sources](#building-from-sources)
- [Attribution](#attribution)

## Supported platforms
- [X] Windows (x86_64), using [Wintun](https://www.wintun.net/)
- [X] Linux (x86_64, aarch64)
- [X] FreeBSD (x86_64, aarch64)
- [X] macOS (x86_64, aarch64)
- [X] Android (aarch64), using a file descriptor supplied by `VpnService`
- [X] iOS (x86_64, aarch64), using a file descriptor supplied by `NEPacketTunnelProvider`

## Installation
Using Cargo, add the following dependency to your project:
```toml
[dependencies]
quincy-tun = "1"
```

## Usage

### Desktop platforms
Linux, macOS, Windows and FreeBSD create native TUN interfaces using `DeviceBuilder::build_async`:
```rust
use quincy_tun::DeviceBuilder;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let device = DeviceBuilder::new()
        .ipv4("10.0.0.1", 24, None)
        .build_async()?;

    let mut buffer = vec![0u8; 65536];
    loop {
        let length = device.recv(&mut buffer).await?;
        device.send(&buffer[..length]).await?;
    }
}
```

Creating and configuring a TUN interface requires the appropriate system privileges.

### Mobile platforms
Android and iOS do not create or discover VPN file descriptors. Transfer ownership of a TUN file descriptor obtained from the platform VPN API:
```rust
use std::os::fd::IntoRawFd;
use quincy_tun::AsyncDevice;

let device = unsafe { AsyncDevice::from_fd(fd.into_raw_fd()) }?;
```

The file descriptor must refer to a valid TUN interface and is closed when the device is dropped.

### Linux offload
Linux supports TSO/GSO/GRO offload for batched packet I/O. Enable it when building the device, then use `recv_multiple` and `send_multiple`:
```rust
use quincy_tun::{DeviceBuilder, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

let device = DeviceBuilder::new()
    .ipv4("10.0.0.1", 24, None)
    .offload(true)
    .build_async()?;

let mut original_buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
let mut buffers = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
let mut sizes = vec![0; IDEAL_BATCH_SIZE];

let packet_count = device
    .recv_multiple(&mut original_buffer, &mut buffers, &mut sizes, 0)
    .await?;
```

## Building from sources
As Quincy Tun does not rely upon any non-Rust libraries at build time, the build process is simple:
```bash
cargo build
```

Rust 1.88 or newer is required. The resulting library can be found in the `target/debug` directory.

## Attribution
Quincy Tun is based on [tun-rs](https://github.com/tun-rs/tun-rs) by the tun-rs contributors and is licensed under the [Apache License 2.0](LICENSE).
