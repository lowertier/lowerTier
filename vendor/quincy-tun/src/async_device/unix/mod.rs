use crate::platform::DeviceImpl;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use crate::platform::GROTable;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use crate::{
    builder::Layer,
    platform::offload::{
        VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN, VirtioNetHdr,
        gso_none_checksum, handle_gro, handle_gro_ethernet,
    },
};
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

mod tokio;
pub use self::tokio::AsyncDevice;

impl FromRawFd for AsyncDevice {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        unsafe {
            // SAFETY: caller guarantees `fd` is a valid, open TUN fd (FromRawFd contract).
            AsyncDevice::from_fd(fd).unwrap()
        }
    }
}

impl IntoRawFd for AsyncDevice {
    fn into_raw_fd(self) -> RawFd {
        self.into_fd().unwrap()
    }
}

impl AsRawFd for AsyncDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().as_raw_fd()
    }
}

impl Deref for AsyncDevice {
    type Target = DeviceImpl;

    fn deref(&self) -> &Self::Target {
        self.get_ref()
    }
}

impl AsyncDevice {
    /// Constructs an `AsyncDevice` from an existing raw file descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open file descriptor for a TUN device.
    pub unsafe fn from_fd(fd: RawFd) -> io::Result<AsyncDevice> {
        unsafe {
            // SAFETY: caller guarantees `fd` is valid (per `/// # Safety`).
            AsyncDevice::new_dev(DeviceImpl::from_fd(fd)?)
        }
    }

    /// Consumes the async device and returns the underlying raw file descriptor.
    pub fn into_fd(self) -> io::Result<RawFd> {
        Ok(self.into_device()?.into_raw_fd())
    }

    /// Waits for the device to become readable.
    ///
    /// This function is usually paired with `try_recv()` for manual readiness-based I/O.
    ///
    /// The function may complete without the device being readable. This is a
    /// false-positive and attempting a `try_recv()` will return with
    /// `io::ErrorKind::WouldBlock`.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Once a readiness event occurs, the method
    /// will continue to return immediately until the readiness event is
    /// consumed by an attempt to read that fails with `WouldBlock` or
    /// `Poll::Pending`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// use quincy_tun::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_async()?;
    ///
    /// // Wait for the device to be readable
    /// dev.readable().await?;
    ///
    /// // Try to read (may still return WouldBlock)
    /// let mut buf = vec![0u8; 1500];
    /// match dev.try_recv(&mut buf) {
    ///     Ok(n) => println!("Read {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    ///         println!("False positive readiness");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn readable(&self) -> io::Result<()> {
        self.0.readable().await.map(|_| ())
    }

    /// Waits for the device to become writable.
    ///
    /// This function is usually paired with `try_send()` for manual readiness-based I/O.
    ///
    /// The function may complete without the device being writable. This is a
    /// false-positive and attempting a `try_send()` will return with
    /// `io::ErrorKind::WouldBlock`.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. Once a readiness event occurs, the method
    /// will continue to return immediately until the readiness event is
    /// consumed by an attempt to write that fails with `WouldBlock` or
    /// `Poll::Pending`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// use quincy_tun::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_async()?;
    ///
    /// // Prepare a packet
    /// let packet = b"Hello, TUN!";
    ///
    /// // Wait for the device to be writable
    /// dev.writable().await?;
    ///
    /// // Try to send (may still return WouldBlock)
    /// match dev.try_send(packet) {
    ///     Ok(n) => println!("Sent {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    ///         println!("False positive writability");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn writable(&self) -> io::Result<()> {
        self.0.writable().await.map(|_| ())
    }

    /// Receives a single packet from the device.
    /// On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_with(|device| device.recv(buf)).await
    }

    /// Tries to receive a single packet from the device.
    /// On success, returns the number of bytes read.
    ///
    /// This method must be called with valid byte array `buf` of sufficient size
    /// to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// When there is no pending data, `Err(io::ErrorKind::WouldBlock)` is
    /// returned. This function is usually paired with `readable()`.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_read_io(|device| device.recv(buf))
    }

    /// Sends a packet to the device.
    ///
    /// # Return
    /// On success, the number of bytes sent is returned, otherwise, the encountered error is returned.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_with(|device| device.send(buf)).await
    }

    /// Tries to send a packet to the device.
    ///
    /// When the device buffer is full, `Err(io::ErrorKind::WouldBlock)` is
    /// returned. This function is usually paired with `writable()`.
    ///
    /// # Returns
    ///
    /// If successful, `Ok(n)` is returned, where `n` is the number of bytes
    /// sent. If the device is not ready to send data,
    /// `Err(ErrorKind::WouldBlock)` is returned.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.try_write_io(|device| device.send(buf))
    }

    /// Receives a packet into multiple buffers (scatter read).
    /// **Processes single packet per call**.
    pub async fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.read_with(|device| device.recv_vectored(bufs)).await
    }

    /// Non-blocking version of `recv_vectored`.
    pub fn try_recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.try_read_io(|device| device.recv_vectored(bufs))
    }

    /// Sends multiple buffers as a single packet (gather write).
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.write_with(|device| device.send_vectored(bufs)).await
    }

    /// Non-blocking version of `send_vectored`.
    pub fn try_send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.try_write_io(|device| device.send_vectored(bufs))
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl AsyncDevice {
    /// Receives one packet from the device and, when offload is enabled, splits
    /// it into separate segment buffers.
    ///
    /// `original_buffer` holds the raw data including the `VirtioNetHdr` and the
    /// unsplit IP packet. `bufs` and `sizes` receive the segmented IP packets and
    /// must have equal lengths. `offset` is the starting position within each
    /// segment buffer.
    #[cfg(target_os = "linux")]
    pub async fn recv_multiple<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        if bufs.is_empty() || bufs.len() != sizes.len() {
            return Err(io::Error::other("bufs error"));
        }

        if bufs.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many packet buffers",
            ));
        }

        let tun = self.get_ref();

        if tun.vnet_hdr {
            let direct_capacity = bufs[0].as_ref().len().saturating_sub(offset);
            if direct_capacity != 0 && original_buffer.len() >= direct_capacity {
                let mut header = [0_u8; VIRTIO_NET_HDR_LEN];
                let len = {
                    let direct = &mut bufs[0].as_mut()[offset..];
                    let overflow = &mut original_buffer[direct_capacity..];
                    let mut vectors = [
                        IoSliceMut::new(&mut header),
                        IoSliceMut::new(direct),
                        IoSliceMut::new(overflow),
                    ];
                    self.recv_vectored(&mut vectors).await?
                };
                if len <= VIRTIO_NET_HDR_LEN {
                    return Err(io::Error::other(format!(
                        "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                    )));
                }
                let hdr = VirtioNetHdr::decode(&header)?;
                let packet_len = len - VIRTIO_NET_HDR_LEN;
                let direct_len = packet_len.min(direct_capacity);
                if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE {
                    if packet_len > direct_capacity {
                        return Err(io::Error::other(format!(
                            "non-GSO packet length {packet_len} exceeds direct buffer length {direct_capacity}",
                        )));
                    }
                    let packet = &mut bufs[0].as_mut()[offset..offset + packet_len];
                    if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
                        gso_none_checksum(packet, hdr.csum_start, hdr.csum_offset)?;
                    }
                    sizes[0] = packet_len;
                    return Ok(1);
                }

                original_buffer[..direct_len]
                    .copy_from_slice(&bufs[0].as_ref()[offset..offset + direct_len]);
                return tun.handle_virtio_read(
                    hdr,
                    &mut original_buffer[..packet_len],
                    bufs,
                    sizes,
                    offset,
                );
            }

            let len = self.recv(original_buffer).await?;
            if len <= VIRTIO_NET_HDR_LEN {
                Err(io::Error::other(format!(
                    "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                )))?
            }
            let hdr = VirtioNetHdr::decode(&original_buffer[..VIRTIO_NET_HDR_LEN])?;
            tun.handle_virtio_read(
                hdr,
                &mut original_buffer[VIRTIO_NET_HDR_LEN..len],
                bufs,
                sizes,
                offset,
            )
        } else {
            let Some(buf) = bufs[0].as_mut().get_mut(offset..) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid offset",
                ));
            };

            let len = self.recv(buf).await?;
            sizes[0] = len;
            Ok(1)
        }
    }

    /// Receives one ready packet without waiting and splits a GSO packet.
    #[cfg(target_os = "linux")]
    pub fn try_recv_multiple<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        if bufs.is_empty() || bufs.len() != sizes.len() {
            return Err(io::Error::other("bufs error"));
        }
        if bufs.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many packet buffers",
            ));
        }

        let tun = self.get_ref();
        if tun.vnet_hdr {
            let direct_capacity = bufs[0].as_ref().len().saturating_sub(offset);
            if direct_capacity != 0 && original_buffer.len() >= direct_capacity {
                let mut header = [0_u8; VIRTIO_NET_HDR_LEN];
                let len = {
                    let direct = &mut bufs[0].as_mut()[offset..];
                    let overflow = &mut original_buffer[direct_capacity..];
                    let mut vectors = [
                        IoSliceMut::new(&mut header),
                        IoSliceMut::new(direct),
                        IoSliceMut::new(overflow),
                    ];
                    self.try_recv_vectored(&mut vectors)?
                };
                if len <= VIRTIO_NET_HDR_LEN {
                    return Err(io::Error::other(format!(
                        "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                    )));
                }
                let hdr = VirtioNetHdr::decode(&header)?;
                let packet_len = len - VIRTIO_NET_HDR_LEN;
                let direct_len = packet_len.min(direct_capacity);
                if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE {
                    if packet_len > direct_capacity {
                        return Err(io::Error::other(format!(
                            "non-GSO packet length {packet_len} exceeds direct buffer length {direct_capacity}",
                        )));
                    }
                    let packet = &mut bufs[0].as_mut()[offset..offset + packet_len];
                    if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
                        gso_none_checksum(packet, hdr.csum_start, hdr.csum_offset)?;
                    }
                    sizes[0] = packet_len;
                    return Ok(1);
                }

                original_buffer[..direct_len]
                    .copy_from_slice(&bufs[0].as_ref()[offset..offset + direct_len]);
                return tun.handle_virtio_read(
                    hdr,
                    &mut original_buffer[..packet_len],
                    bufs,
                    sizes,
                    offset,
                );
            }

            let len = self.try_recv(original_buffer)?;
            if len <= VIRTIO_NET_HDR_LEN {
                return Err(io::Error::other(format!(
                    "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                )));
            }
            let hdr = VirtioNetHdr::decode(&original_buffer[..VIRTIO_NET_HDR_LEN])?;
            tun.handle_virtio_read(
                hdr,
                &mut original_buffer[VIRTIO_NET_HDR_LEN..len],
                bufs,
                sizes,
                offset,
            )
        } else {
            let Some(buf) = bufs[0].as_mut().get_mut(offset..) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid offset",
                ));
            };
            let len = self.try_recv(buf)?;
            sizes[0] = len;
            Ok(1)
        }
    }

    /// Sends multiple fragmented data packets, optionally merging via GRO.
    ///
    /// `gro_table` may be reused across calls to assist coalescing. `offset`
    /// must be large enough to reserve `VIRTIO_NET_HDR_LEN` bytes when
    /// virtual network headers are enabled (i.e. `offset > 10`).
    #[cfg(target_os = "linux")]
    pub async fn send_multiple<B: crate::platform::ExpandBuffer>(
        &self,
        gro_table: &mut GROTable,
        bufs: &mut [B],
        offset: usize,
    ) -> io::Result<usize> {
        self.send_multiple_with_stats(gro_table, bufs, offset)
            .await
            .map(|(bytes, _writes)| bytes)
    }

    /// Sends independently framed packets and returns `(bytes, write_syscalls)`.
    /// The aggregate permits callers to update telemetry once per batch.
    #[cfg(target_os = "linux")]
    pub async fn send_multiple_with_stats<B: crate::platform::ExpandBuffer>(
        &self,
        gro_table: &mut GROTable,
        bufs: &mut [B],
        mut offset: usize,
    ) -> io::Result<(usize, usize)> {
        gro_table.reset();

        if bufs.is_empty() {
            return Ok((0, 0));
        }

        if bufs.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many packet buffers",
            ));
        }

        let tun = self.get_ref();

        if tun.vnet_hdr {
            if tun.layer == Layer::L2 {
                handle_gro_ethernet(
                    bufs,
                    offset,
                    &mut gro_table.tcp_gro_table,
                    &mut gro_table.udp_gro_table,
                    tun.udp_gso,
                    &mut gro_table.to_write,
                )?;
            } else {
                handle_gro(
                    bufs,
                    offset,
                    &mut gro_table.tcp_gro_table,
                    &mut gro_table.udp_gro_table,
                    tun.udp_gso,
                    &mut gro_table.to_write,
                )?;
            }
            offset -= VIRTIO_NET_HDR_LEN;
        } else {
            for i in 0..bufs.len() {
                gro_table.to_write.push(i);
            }
        }

        let mut total = 0;
        let mut writes = 0;
        let mut error = None;
        let mut next = 0;
        while next < gro_table.to_write.len() {
            self.writable().await?;
            while next < gro_table.to_write.len() {
                let buf_idx = gro_table.to_write[next];
                let Some(buf) = bufs[buf_idx].as_ref().get(offset..) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid offset",
                    ));
                };
                writes += 1;
                match self.try_send(buf) {
                    Ok(n) => {
                        total += n;
                        next += 1;
                    }
                    Err(current) if current.kind() == io::ErrorKind::WouldBlock => break,
                    Err(current) => {
                        if current.raw_os_error() == Some(libc::EBADFD) {
                            return Err(current);
                        }
                        error = Some(current);
                        next += 1;
                    }
                }
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        Ok((total, writes))
    }
}
