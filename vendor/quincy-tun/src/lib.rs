/*!
# quincy-tun

Cross-platform async TUN library for [Quincy](https://github.com/quincy-rs/quincy).

Forked from [tun-rs](https://github.com/tun-rs/tun-rs) and trimmed to the
exact surface Quincy needs: an async (tokio) TUN device with optional
GSO/GRO offload on Linux.

## Supported platforms

Linux, macOS, Windows, FreeBSD, Android, iOS.

## Quick start

```no_run
# async fn _main() -> std::io::Result<()> {
use quincy_tun::DeviceBuilder;

let dev = DeviceBuilder::new()
    .ipv4("10.0.0.1", 24, None)
    .build_async()?;

let mut buf = vec![0u8; 65536];
loop {
    let len = dev.recv(&mut buf).await?;
    dev.send(&buf[..len]).await?;
}
# Ok(()) }
```

## Linux offload (GSO/GRO)

On Linux, enable TSO/GSO for a 3-4x throughput boost:

```no_run
# #[cfg(target_os = "linux")]
# async fn offload_example() -> std::io::Result<()> {
use quincy_tun::{DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

let dev = DeviceBuilder::new()
    .ipv4("10.0.0.1", 24, None)
    .offload(true)
    .build_async()?;

let mut original_buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
let mut sizes = vec![0; IDEAL_BATCH_SIZE];
let mut gro_table = GROTable::default();

let num = dev.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0).await?;
# Ok(()) }
```
*/

pub use crate::builder::*;
pub use crate::platform::*;

mod async_device;
mod builder;
mod platform;

pub use async_device::AsyncDevice;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub(crate) const PACKET_INFORMATION_LENGTH: usize = 4;
