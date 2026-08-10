use std::{
    collections::VecDeque,
    io::{self, IoSlice},
    os::fd::AsRawFd,
    pin::Pin,
    ptr,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::Stream;
use nix::libc;
use tokio::io::{AsyncWrite, unix::AsyncFd};

use crate::tunnel::{
    StreamItem,
    packet_def::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
};

const UTUN_HEADER_LEN: usize = 4;
pub(super) const MAX_TUN_BATCH: usize = 64;
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;

#[repr(C)]
struct MsgHdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: usize,
}

impl Default for MsgHdrX {
    fn default() -> Self {
        Self {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        }
    }
}

unsafe extern "C" {
    fn recvmsg_x(
        socket: libc::c_int,
        messages: *mut MsgHdrX,
        count: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;

    fn sendmsg_x(
        socket: libc::c_int,
        messages: *const MsgHdrX,
        count: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

struct ReceiveSlot {
    utun_header: [u8; UTUN_HEADER_LEN],
    packet: BytesMut,
    payload_offset: usize,
    mtu: usize,
}

impl ReceiveSlot {
    fn new(payload_prefix_len: usize, mtu: usize) -> Self {
        let payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        let initialized_len = payload_offset + payload_prefix_len;
        let mut packet = BytesMut::with_capacity(initialized_len + mtu + TAIL_RESERVED_SIZE);
        packet.resize(initialized_len, 0);
        Self {
            utun_header: [0; UTUN_HEADER_LEN],
            packet,
            payload_offset: initialized_len,
            mtu,
        }
    }

    fn payload_ptr(&mut self) -> *mut u8 {
        self.packet.spare_capacity_mut().as_mut_ptr().cast()
    }

    fn finish(mut self, received_len: usize) -> io::Result<ZCPacket> {
        if received_len <= UTUN_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun message did not contain an IP packet",
            ));
        }
        let payload_len = received_len - UTUN_HEADER_LEN;
        if payload_len > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun message exceeded the configured MTU",
            ));
        }
        // recvmsg_x initialized exactly payload_len bytes at payload_ptr().
        unsafe { self.packet.set_len(self.payload_offset + payload_len) };
        Ok(ZCPacket::new_from_buf(self.packet, ZCPacketType::NIC))
    }

    #[cfg(test)]
    fn write_payload_for_test(&mut self, payload: &[u8]) {
        assert!(payload.len() <= self.mtu);
        // The test mirrors recvmsg_x by initializing the slot's spare payload capacity.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), self.payload_ptr(), payload.len());
        }
    }
}

fn completed_batch_bytes(packet_lengths: &[usize], completed_messages: usize) -> usize {
    packet_lengths
        .iter()
        .take(completed_messages)
        .copied()
        .sum()
}

struct DarwinTunDevice {
    io: AsyncFd<tun::platform::Device>,
}

impl DarwinTunDevice {
    fn new(device: tun::platform::Device) -> io::Result<Arc<Self>> {
        device.set_nonblock()?;
        let pending_packets = MAX_TUN_BATCH as libc::c_int;
        let set_pending_result = unsafe {
            libc::setsockopt(
                device.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_MAX_PENDING_PACKETS,
                (&pending_packets as *const libc::c_int).cast(),
                std::mem::size_of_val(&pending_packets) as libc::socklen_t,
            )
        };
        if set_pending_result != 0 {
            tracing::warn!(
                error = %io::Error::last_os_error(),
                "failed to raise Darwin utun pending-packet limit"
            );
        }
        Ok(Arc::new(Self {
            io: AsyncFd::new(device)?,
        }))
    }
}

pub(super) struct DarwinTunStream {
    device: Arc<DarwinTunDevice>,
    slots: Vec<ReceiveSlot>,
    pending: VecDeque<ZCPacket>,
    payload_prefix_len: usize,
    mtu: usize,
}

impl DarwinTunStream {
    fn new(device: Arc<DarwinTunDevice>, payload_prefix_len: usize, mtu: usize) -> Self {
        Self {
            device,
            slots: Vec::with_capacity(MAX_TUN_BATCH),
            pending: VecDeque::with_capacity(MAX_TUN_BATCH),
            payload_prefix_len,
            mtu,
        }
    }

    fn refill_slots(&mut self) {
        while self.slots.len() < MAX_TUN_BATCH {
            self.slots
                .push(ReceiveSlot::new(self.payload_prefix_len, self.mtu));
        }
    }

    fn recv_batch(&mut self, fd: libc::c_int) -> io::Result<usize> {
        self.refill_slots();
        let mut iovecs: [[libc::iovec; 2]; MAX_TUN_BATCH] = std::array::from_fn(|_| {
            std::array::from_fn(|_| libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            })
        });
        for (slot, iovec) in self.slots.iter_mut().zip(&mut iovecs) {
            *iovec = [
                libc::iovec {
                    iov_base: slot.utun_header.as_mut_ptr().cast(),
                    iov_len: UTUN_HEADER_LEN,
                },
                libc::iovec {
                    iov_base: slot.payload_ptr().cast(),
                    iov_len: slot.mtu,
                },
            ];
        }
        let mut messages: [MsgHdrX; MAX_TUN_BATCH] = std::array::from_fn(|_| MsgHdrX::default());
        for (message, iovec) in messages.iter_mut().zip(&mut iovecs) {
            *message = MsgHdrX {
                msg_iov: iovec.as_mut_ptr(),
                msg_iovlen: iovec.len() as libc::c_int,
                ..MsgHdrX::default()
            };
        }

        let received = unsafe {
            recvmsg_x(
                fd,
                messages.as_mut_ptr(),
                MAX_TUN_BATCH as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        if received > messages.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recvmsg_x returned more messages than requested",
            ));
        }

        let slots = &mut self.slots;
        let pending = &mut self.pending;
        for (slot, message) in slots.drain(..received).zip(messages) {
            pending.push_back(slot.finish(message.msg_datalen)?);
        }
        Ok(received)
    }
}

impl Stream for DarwinTunStream {
    type Item = StreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(packet) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(packet)));
        }

        let device = self.device.clone();
        let fd = device.io.get_ref().as_raw_fd();
        loop {
            let mut readiness = match device.io.poll_read_ready(cx) {
                Poll::Ready(Ok(readiness)) => readiness,
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
                Poll::Pending => return Poll::Pending,
            };
            match readiness.try_io(|_| self.recv_batch(fd)) {
                Ok(Ok(0)) => return Poll::Ready(None),
                Ok(Ok(_)) => {
                    let packet = self
                        .pending
                        .pop_front()
                        .expect("non-empty Darwin TUN batch");
                    return Poll::Ready(Some(Ok(packet)));
                }
                Ok(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
                Err(_would_block) => continue,
            }
        }
    }
}

pub(super) struct DarwinTunAsyncWrite {
    device: Arc<DarwinTunDevice>,
}

impl DarwinTunAsyncWrite {
    fn new(device: Arc<DarwinTunDevice>) -> Self {
        Self { device }
    }

    fn send_batch(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let bufs = &bufs[..bufs.len().min(MAX_TUN_BATCH)];
        if bufs.is_empty() {
            return Ok(0);
        }
        let mut iovecs: [libc::iovec; MAX_TUN_BATCH] = std::array::from_fn(|_| libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 0,
        });
        let mut packet_lengths = [0_usize; MAX_TUN_BATCH];
        for ((iovec, packet_len), buf) in
            iovecs.iter_mut().zip(&mut packet_lengths).zip(bufs.iter())
        {
            *iovec = libc::iovec {
                iov_base: buf.as_ptr().cast_mut().cast(),
                iov_len: buf.len(),
            };
            *packet_len = buf.len();
        }
        let mut messages: [MsgHdrX; MAX_TUN_BATCH] = std::array::from_fn(|_| MsgHdrX::default());
        for (message, iovec) in messages.iter_mut().zip(&mut iovecs).take(bufs.len()) {
            *message = MsgHdrX {
                msg_iov: iovec,
                msg_iovlen: 1,
                msg_datalen: iovec.iov_len,
                ..MsgHdrX::default()
            };
        }
        let sent = unsafe {
            sendmsg_x(
                self.device.io.get_ref().as_raw_fd(),
                messages.as_ptr(),
                bufs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize > bufs.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sendmsg_x returned more messages than requested",
            ));
        }
        Ok(completed_batch_bytes(
            &packet_lengths[..bufs.len()],
            sent as usize,
        ))
    }
}

impl AsyncWrite for DarwinTunAsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(buf)])
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut readiness = match self.device.io.poll_write_ready(cx) {
                Poll::Ready(Ok(readiness)) => readiness,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            match readiness.try_io(|_| self.send_batch(bufs)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(super) fn split_device(
    device: tun::platform::Device,
    payload_prefix_len: usize,
    mtu: usize,
) -> io::Result<(DarwinTunStream, DarwinTunAsyncWrite)> {
    let device = DarwinTunDevice::new(device)?;
    Ok((
        DarwinTunStream::new(device.clone(), payload_prefix_len, mtu),
        DarwinTunAsyncWrite::new(device),
    ))
}

#[cfg(test)]
mod tests {
    use super::{ReceiveSlot, UTUN_HEADER_LEN, completed_batch_bytes};
    use crate::tunnel::packet_def::ZCPacketType;

    #[test]
    fn receive_slot_places_l3_payload_at_nic_payload_offset() {
        let payload = [0x45, 0, 0, 20];
        let mut slot = ReceiveSlot::new(0, 1500);
        slot.write_payload_for_test(&payload);

        let packet = slot.finish(UTUN_HEADER_LEN + payload.len()).unwrap();

        assert_eq!(
            packet.payload_offset(),
            ZCPacketType::NIC.get_packet_offsets().payload_offset
        );
        assert_eq!(packet.payload(), payload);
    }

    #[test]
    fn receive_slot_reserves_l2_tun_ethernet_prefix() {
        let payload = [0x60, 0, 0, 0];
        let mut slot = ReceiveSlot::new(crate::instance::l2_tun::ETHERNET_HEADER_LEN, 1500);
        slot.write_payload_for_test(&payload);

        let packet = slot.finish(UTUN_HEADER_LEN + payload.len()).unwrap();

        assert_eq!(
            packet.payload().len(),
            crate::instance::l2_tun::ETHERNET_HEADER_LEN + payload.len()
        );
        assert_eq!(
            &packet.payload()[crate::instance::l2_tun::ETHERNET_HEADER_LEN..],
            payload
        );
    }

    #[test]
    fn receive_slot_rejects_short_utun_result() {
        let slot = ReceiveSlot::new(0, 1500);
        assert!(slot.finish(UTUN_HEADER_LEN).is_err());
    }

    #[test]
    fn partial_batch_counts_only_complete_messages() {
        assert_eq!(completed_batch_bytes(&[120, 80, 40], 0), 0);
        assert_eq!(completed_batch_bytes(&[120, 80, 40], 2), 200);
        assert_eq!(completed_batch_bytes(&[120, 80, 40], 8), 240);
    }
}
