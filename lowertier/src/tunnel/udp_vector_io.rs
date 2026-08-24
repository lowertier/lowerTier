use std::{
    io,
    net::SocketAddr,
    sync::OnceLock,
    task::{Context, Poll, ready},
};

use bytes::{Bytes, BytesMut};
use smallvec::{SmallVec, smallvec};
use tokio::{io::Interest, net::UdpSocket};

use super::batch::MAX_PACKET_BATCH_SIZE;
use super::packet_def::ReusableBufferPool;

const MAX_UDP_GSO_PAYLOAD: usize = u16::MAX as usize;
static UDP_SEND_VECTOR_DISABLED: OnceLock<bool> = OnceLock::new();
static UDP_RECV_VECTOR_DISABLED: OnceLock<bool> = OnceLock::new();

fn udp_send_vector_disabled() -> bool {
    *UDP_SEND_VECTOR_DISABLED.get_or_init(|| {
        let explicitly_disabled = std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_VECTOR").is_some()
            || std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_SEND_VECTOR").is_some();
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            explicitly_disabled || std::env::var_os("LOWTIER_ENABLE_UDP_SEND_VECTOR").is_none()
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        explicitly_disabled
    })
}

fn udp_recv_vector_disabled() -> bool {
    *UDP_RECV_VECTOR_DISABLED.get_or_init(|| {
        std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_VECTOR").is_some()
            || std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_RECV_VECTOR").is_some()
    })
}

/// Return the largest prefix that Linux UDP GSO can submit as one super-packet.
/// All segments have the first packet's size, except for an optional shorter
/// final segment. The kernel API represents both the segment size and total
/// payload with 16-bit values.
fn compatible_gso_prefix(buffers: &[Bytes]) -> usize {
    let Some(first) = buffers.first() else {
        return 0;
    };
    let segment_size = first.len();
    if segment_size == 0 || segment_size > MAX_UDP_GSO_PAYLOAD {
        return 1;
    }

    let mut total: usize = 0;
    for (index, buffer) in buffers.iter().take(MAX_PACKET_BATCH_SIZE).enumerate() {
        if buffer.is_empty()
            || buffer.len() > segment_size
            || total.saturating_add(buffer.len()) > MAX_UDP_GSO_PAYLOAD
        {
            return index.max(1);
        }
        total += buffer.len();
        if buffer.len() < segment_size {
            return index + 1;
        }
    }
    buffers.len().min(MAX_PACKET_BATCH_SIZE)
}

fn split_gro_buffer(mut buffer: BytesMut, stride: usize) -> io::Result<Vec<BytesMut>> {
    if stride == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP GRO returned a zero segment size",
        ));
    }
    let mut segments = Vec::with_capacity(buffer.len().div_ceil(stride));
    while !buffer.is_empty() {
        segments.push(buffer.split_to(buffer.len().min(stride)));
    }
    Ok(segments)
}

pub(crate) struct ReceivedDatagram {
    pub(crate) buffer: BytesMut,
    pub(crate) source: SocketAddr,
    pub(crate) reusable_pool: Option<ReusableBufferPool>,
}

pub(crate) type ReceivedDatagramBatch = SmallVec<[ReceivedDatagram; 4]>;

pub(crate) struct UdpBatchReceiver {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
    slots: ReceiveSlotPool,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
    reusable_pool: Option<(usize, ReusableBufferPool)>,
    #[cfg(target_os = "linux")]
    gro_enabled: Option<bool>,
}

impl UdpBatchReceiver {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
            slots: ReceiveSlotPool::default(),
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
            reusable_pool: None,
            #[cfg(target_os = "linux")]
            gro_enabled: None,
        }
    }

    pub(crate) async fn recv_batch(
        &mut self,
        socket: &UdpSocket,
        max_datagram_size: usize,
    ) -> io::Result<ReceivedDatagramBatch> {
        if udp_recv_vector_disabled() {
            let mut buffer = BytesMut::with_capacity(max_datagram_size);
            let (_, source) = socket.recv_buf_from(&mut buffer).await?;
            return Ok(smallvec![ReceivedDatagram {
                buffer,
                source,
                reusable_pool: None,
            }]);
        }

        #[cfg(target_os = "linux")]
        let gro_enabled = if let Some(enabled) = self.gro_enabled {
            enabled
        } else {
            let enabled = enable_udp_gro(socket)?;
            self.gro_enabled = Some(enabled);
            enabled
        };

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let reusable_pool = self.receive_pool(max_datagram_size).clone();
        #[cfg(target_os = "linux")]
        let reusable_pool = (!gro_enabled).then(|| self.receive_pool(max_datagram_size).clone());

        loop {
            socket.readable().await?;
            match socket.try_io(Interest::READABLE, || {
                #[cfg(target_os = "linux")]
                {
                    try_recv_batch(
                        socket,
                        max_datagram_size,
                        gro_enabled,
                        &mut self.slots,
                        reusable_pool.as_ref(),
                    )
                }
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                {
                    try_recv_batch(socket, max_datagram_size, &mut self.slots, &reusable_pool)
                }
                #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
                {
                    try_recv_batch(socket, max_datagram_size)
                }
            }) {
                Ok(datagrams) if !datagrams.is_empty() => return Ok(datagrams),
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
    fn receive_pool(&mut self, slot_size: usize) -> &ReusableBufferPool {
        let replace = self
            .reusable_pool
            .as_ref()
            .is_none_or(|(existing_size, _)| *existing_size != slot_size);
        if replace {
            self.reusable_pool = Some((
                slot_size,
                ReusableBufferPool::new(slot_size, MAX_PACKET_BATCH_SIZE),
            ));
        }
        &self.reusable_pool.as_ref().unwrap().1
    }
}

impl Default for UdpBatchReceiver {
    fn default() -> Self {
        Self::new()
    }
}

fn checked_message_count(result: isize, requested: usize) -> io::Result<usize> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let completed = result as usize;
    if completed > requested {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vector UDP syscall completed more messages than requested",
        ));
    }
    Ok(completed)
}

pub(crate) async fn send_batch(
    socket: &UdpSocket,
    destination: SocketAddr,
    buffers: &[Bytes],
) -> io::Result<()> {
    let mut completed = 0;
    std::future::poll_fn(|cx| poll_send_batch(socket, destination, buffers, &mut completed, cx))
        .await
}

pub(crate) fn poll_send_batch(
    socket: &UdpSocket,
    destination: SocketAddr,
    buffers: &[Bytes],
    completed: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *completed < buffers.len() {
        ready!(socket.poll_send_ready(cx))?;
        if udp_send_vector_disabled() {
            match socket.try_send_to(&buffers[*completed], destination) {
                Ok(sent) if sent == buffers[*completed].len() => *completed += 1,
                Ok(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "scalar UDP fallback sent a partial datagram",
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
            continue;
        }

        let remaining = &buffers[*completed..];
        match socket.try_io(Interest::WRITABLE, || {
            try_send_batch(socket, destination, remaining)
        }) {
            Ok(0) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vector UDP send completed zero datagrams",
                )));
            }
            Ok(sent) => *completed += sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    Poll::Ready(Ok(()))
}

pub(crate) async fn recv_batch(
    socket: &UdpSocket,
    max_datagram_size: usize,
) -> io::Result<ReceivedDatagramBatch> {
    if udp_recv_vector_disabled() {
        let mut buffer = BytesMut::with_capacity(max_datagram_size);
        let (_, source) = socket.recv_buf_from(&mut buffer).await?;
        return Ok(smallvec![ReceivedDatagram {
            buffer,
            source,
            reusable_pool: None,
        }]);
    }

    UdpBatchReceiver::new()
        .recv_batch(socket, max_datagram_size)
        .await
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
struct ReceiveSlot {
    buffer: BytesMut,
    source: nix::libc::sockaddr_storage,
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
impl ReceiveSlot {
    fn new(max_datagram_size: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(max_datagram_size),
            source: unsafe { std::mem::zeroed() },
        }
    }

    fn from_pool(pool: &ReusableBufferPool) -> Self {
        let mut buffer = pool.take_or_allocate();
        buffer.clear();
        Self {
            buffer,
            source: unsafe { std::mem::zeroed() },
        }
    }

    fn buffer_ptr(&mut self) -> *mut nix::libc::c_void {
        self.buffer.spare_capacity_mut().as_mut_ptr().cast()
    }

    fn finish(
        mut self,
        received: usize,
        source_len: usize,
        reusable_pool: Option<ReusableBufferPool>,
    ) -> io::Result<ReceivedDatagram> {
        if received > self.buffer.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vector UDP receive exceeded its buffer",
            ));
        }
        unsafe { self.buffer.set_len(received) };
        Ok(ReceivedDatagram {
            buffer: self.buffer,
            source: sockaddr_to_socket_addr(&self.source, source_len)?,
            reusable_pool,
        })
    }
}

/// Owns receive buffers across syscalls. Completed slots move into the packet
/// pipeline, while every unused allocation stays at the same bounded index.
/// A consumed slot is replenished only when the next receive is prepared.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
#[derive(Default)]
struct ReceiveSlotPool {
    slots: Vec<Option<ReceiveSlot>>,
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
impl ReceiveSlotPool {
    #[cfg(test)]
    fn new(count: usize, slot_size: usize) -> Self {
        let mut pool = Self::default();
        pool.prepare(count, slot_size, None);
        pool
    }

    fn prepare(
        &mut self,
        count: usize,
        slot_size: usize,
        reusable_pool: Option<&ReusableBufferPool>,
    ) {
        assert!(count <= MAX_PACKET_BATCH_SIZE);
        if self.slots.len() < count {
            self.slots.resize_with(count, || None);
        }
        for slot in &mut self.slots[..count] {
            let must_replace = slot
                .as_ref()
                .is_none_or(|slot| slot.buffer.capacity() < slot_size);
            if must_replace {
                *slot = Some(
                    reusable_pool
                        .map(ReceiveSlot::from_pool)
                        .unwrap_or_else(|| ReceiveSlot::new(slot_size)),
                );
            }
        }
    }

    fn slot_mut(&mut self, index: usize) -> &mut ReceiveSlot {
        self.slots[index]
            .as_mut()
            .expect("receive slot must be prepared")
    }

    fn take(&mut self, index: usize) -> ReceiveSlot {
        self.slots[index]
            .take()
            .expect("completed receive slot must be prepared")
    }

    #[cfg(test)]
    fn refill(&mut self, slot_size: usize) {
        let count = self.slots.len();
        self.prepare(count, slot_size, None);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots.len()
    }

    #[cfg(test)]
    fn buffer_ptrs_for_test(&self) -> Vec<*const u8> {
        self.slots
            .iter()
            .map(|slot| slot.as_ref().unwrap().buffer.as_ptr())
            .collect()
    }

    #[cfg(test)]
    fn take_completed_for_test(&mut self, count: usize) -> Vec<ReceiveSlot> {
        (0..count).map(|index| self.take(index)).collect()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn sockaddr_to_socket_addr(
    storage: &nix::libc::sockaddr_storage,
    source_len: usize,
) -> io::Result<SocketAddr> {
    use nix::libc;

    match storage.ss_family as libc::c_int {
        libc::AF_INET if source_len >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if source_len >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported UDP source address family {family}"),
        )),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn try_recv_batch(
    socket: &UdpSocket,
    max_datagram_size: usize,
    slots: &mut ReceiveSlotPool,
    reusable_pool: &ReusableBufferPool,
) -> io::Result<ReceivedDatagramBatch> {
    use std::{os::fd::AsRawFd, ptr};

    use nix::libc;

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

    unsafe extern "C" {
        fn recvmsg_x(
            socket: libc::c_int,
            messages: *mut MsgHdrX,
            count: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;
    }

    slots.prepare(
        MAX_PACKET_BATCH_SIZE,
        max_datagram_size,
        Some(reusable_pool),
    );
    let mut iovecs: [libc::iovec; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    });
    let mut messages: [MsgHdrX; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| MsgHdrX {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        msg_datalen: 0,
    });
    for index in 0..MAX_PACKET_BATCH_SIZE {
        iovecs[index] = libc::iovec {
            iov_base: slots.slot_mut(index).buffer_ptr(),
            iov_len: max_datagram_size,
        };
        messages[index] = MsgHdrX {
            msg_name: (&mut slots.slot_mut(index).source as *mut libc::sockaddr_storage).cast(),
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &mut iovecs[index],
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        };
    }

    let result = unsafe {
        recvmsg_x(
            socket.as_raw_fd(),
            messages.as_mut_ptr(),
            MAX_PACKET_BATCH_SIZE as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };
    let completed = checked_message_count(result, MAX_PACKET_BATCH_SIZE)?;
    messages
        .into_iter()
        .take(completed)
        .enumerate()
        .map(|(index, message)| {
            slots.take(index).finish(
                message.msg_datalen,
                message.msg_namelen as usize,
                Some(reusable_pool.clone()),
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn try_recv_batch(
    socket: &UdpSocket,
    max_datagram_size: usize,
    gro_enabled: bool,
    slots: &mut ReceiveSlotPool,
    reusable_pool: Option<&ReusableBufferPool>,
) -> io::Result<ReceivedDatagramBatch> {
    use std::{mem, os::fd::AsRawFd, ptr};

    use nix::libc;

    let message_count = if gro_enabled {
        // A single GRO super-packet carries up to 64 upstream datagrams. Using
        // one 64 KiB slot avoids allocating 4 MiB on every receive syscall.
        1
    } else {
        MAX_PACKET_BATCH_SIZE
    };
    let slot_size = if gro_enabled {
        MAX_UDP_GSO_PAYLOAD
    } else {
        max_datagram_size
    };
    slots.prepare(message_count, slot_size, reusable_pool);
    let mut iovecs: [libc::iovec; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    });
    let mut messages: [libc::mmsghdr; MAX_PACKET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut controls = [[0_usize; 8]; MAX_PACKET_BATCH_SIZE];
    for index in 0..message_count {
        iovecs[index] = libc::iovec {
            iov_base: slots.slot_mut(index).buffer_ptr(),
            iov_len: slot_size,
        };
        messages[index].msg_hdr.msg_name =
            (&mut slots.slot_mut(index).source as *mut libc::sockaddr_storage).cast();
        messages[index].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        messages[index].msg_hdr.msg_iov = &mut iovecs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
        messages[index].msg_hdr.msg_control = controls[index].as_mut_ptr().cast();
        #[cfg(not(target_env = "musl"))]
        {
            messages[index].msg_hdr.msg_controllen = mem::size_of_val(&controls[index]);
        }
        #[cfg(target_env = "musl")]
        {
            messages[index].msg_hdr.msg_controllen =
                mem::size_of_val(&controls[index]) as libc::socklen_t;
        }
    }

    #[cfg(not(target_env = "musl"))]
    let flags = libc::MSG_DONTWAIT;
    #[cfg(target_env = "musl")]
    let flags = libc::MSG_DONTWAIT as libc::c_uint;
    let result = unsafe {
        libc::recvmmsg(
            socket.as_raw_fd(),
            messages.as_mut_ptr(),
            message_count as libc::c_uint,
            flags,
            ptr::null_mut(),
        )
    };
    let completed = checked_message_count(result as isize, message_count)?;
    let mut datagrams = ReceivedDatagramBatch::new();
    for (index, message) in messages.into_iter().take(completed).enumerate() {
        let gro_stride = udp_gro_stride(&message.msg_hdr)?;
        let datagram = slots.take(index).finish(
            message.msg_len as usize,
            message.msg_hdr.msg_namelen as usize,
            reusable_pool.cloned(),
        )?;
        if let Some(stride) = gro_stride {
            let source = datagram.source;
            for buffer in split_gro_buffer(datagram.buffer, stride)? {
                if datagrams.len() == MAX_PACKET_BATCH_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP GRO returned more than the bounded packet batch",
                    ));
                }
                datagrams.push(ReceivedDatagram {
                    buffer,
                    source,
                    reusable_pool: None,
                });
            }
        } else {
            datagrams.push(datagram);
        }
    }
    Ok(datagrams)
}

#[cfg(target_os = "linux")]
fn enable_udp_gro(socket: &UdpSocket) -> io::Result<bool> {
    use std::{mem, os::fd::AsRawFd};

    use nix::libc;

    if std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_GRO").is_some() {
        return Ok(false);
    }

    const SOL_UDP: libc::c_int = 17;
    const UDP_GRO: libc::c_int = 104;
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_UDP,
            UDP_GRO,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if udp_gso_is_unsupported(&error) {
        tracing::debug!(?error, "Linux UDP GRO is unavailable; using recvmmsg");
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn udp_gro_stride(message: &nix::libc::msghdr) -> io::Result<Option<usize>> {
    use std::{mem, ptr};

    use nix::libc;

    const SOL_UDP: libc::c_int = 17;
    const UDP_GRO: libc::c_int = 104;
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP GRO control message was truncated",
        ));
    }

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == SOL_UDP && header.cmsg_type == UDP_GRO {
            let minimum = unsafe { libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint) };
            #[cfg(not(target_env = "musl"))]
            let minimum = minimum as usize;
            if header.cmsg_len < minimum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP GRO segment-size control message was truncated",
                ));
            }
            let stride = unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>()) };
            return Ok(Some(stride as usize));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(message, cmsg) };
    }
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn try_recv_batch(
    socket: &UdpSocket,
    max_datagram_size: usize,
) -> io::Result<ReceivedDatagramBatch> {
    let mut buffer = vec![0_u8; max_datagram_size];
    let (received, source) = socket.try_recv_from(&mut buffer)?;
    buffer.truncate(received);
    Ok(smallvec![ReceivedDatagram {
        buffer: BytesMut::from(buffer.as_slice()),
        source,
        reusable_pool: None,
    }])
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn try_send_batch(
    socket: &UdpSocket,
    destination: SocketAddr,
    buffers: &[Bytes],
) -> io::Result<usize> {
    use std::{os::fd::AsRawFd, ptr};

    use nix::libc;

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

    unsafe extern "C" {
        fn sendmsg_x(
            socket: libc::c_int,
            messages: *const MsgHdrX,
            count: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;
    }

    let buffers = &buffers[..buffers.len().min(MAX_PACKET_BATCH_SIZE)];
    if buffers.is_empty() {
        return Ok(0);
    }
    let destination = socket2::SockAddr::from(destination);
    let mut iovecs: [libc::iovec; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    });
    for (iovec, buffer) in iovecs.iter_mut().zip(buffers) {
        *iovec = libc::iovec {
            iov_base: buffer.as_ptr().cast_mut().cast(),
            iov_len: buffer.len(),
        };
    }
    let mut messages: [MsgHdrX; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| MsgHdrX {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        msg_datalen: 0,
    });
    for (message, iovec) in messages.iter_mut().zip(&mut iovecs).take(buffers.len()) {
        *message = MsgHdrX {
            msg_name: destination.as_ptr().cast_mut().cast(),
            msg_namelen: destination.len(),
            msg_iov: iovec,
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: iovec.iov_len,
        };
    }

    let result = unsafe {
        sendmsg_x(
            socket.as_raw_fd(),
            messages.as_ptr(),
            buffers.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };
    checked_message_count(result, buffers.len())
}

#[cfg(target_os = "linux")]
fn try_send_batch(
    socket: &UdpSocket,
    destination: SocketAddr,
    buffers: &[Bytes],
) -> io::Result<usize> {
    use std::{os::fd::AsRawFd, ptr};

    use nix::libc;

    let buffers = &buffers[..buffers.len().min(MAX_PACKET_BATCH_SIZE)];
    if buffers.is_empty() {
        return Ok(0);
    }
    let gso_prefix = compatible_gso_prefix(buffers);
    if gso_prefix >= 2 && std::env::var_os("LOWTIER_DEBUG_DISABLE_UDP_GSO").is_none() {
        match try_send_gso(socket, destination, &buffers[..gso_prefix]) {
            Ok(()) => return Ok(gso_prefix),
            Err(error) if udp_gso_is_unsupported(&error) => {}
            Err(error) => return Err(error),
        }
    }
    let destination = socket2::SockAddr::from(destination);
    let mut iovecs: [libc::iovec; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    });
    for (iovec, buffer) in iovecs.iter_mut().zip(buffers) {
        *iovec = libc::iovec {
            iov_base: buffer.as_ptr().cast_mut().cast(),
            iov_len: buffer.len(),
        };
    }
    let mut messages: [libc::mmsghdr; MAX_PACKET_BATCH_SIZE] = unsafe { std::mem::zeroed() };
    for (message, iovec) in messages.iter_mut().zip(&mut iovecs).take(buffers.len()) {
        message.msg_hdr.msg_name = destination.as_ptr().cast_mut().cast();
        message.msg_hdr.msg_namelen = destination.len();
        message.msg_hdr.msg_iov = iovec;
        message.msg_hdr.msg_iovlen = 1;
    }

    #[cfg(not(target_env = "musl"))]
    let flags = libc::MSG_DONTWAIT;
    #[cfg(target_env = "musl")]
    let flags = libc::MSG_DONTWAIT as libc::c_uint;
    let result = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            messages.as_mut_ptr(),
            buffers.len() as libc::c_uint,
            flags,
        )
    };
    checked_message_count(result as isize, buffers.len())
}

#[cfg(target_os = "linux")]
fn try_send_gso(socket: &UdpSocket, destination: SocketAddr, buffers: &[Bytes]) -> io::Result<()> {
    use std::{mem, os::fd::AsRawFd, ptr};

    use nix::libc;

    // These values are part of Linux's stable UDP userspace ABI but are not
    // exported by every libc release supported by lowertier.
    const SOL_UDP: libc::c_int = 17;
    const UDP_SEGMENT: libc::c_int = 103;

    debug_assert!(buffers.len() >= 2);
    let destination = socket2::SockAddr::from(destination);
    let mut iovecs: [libc::iovec; MAX_PACKET_BATCH_SIZE] = std::array::from_fn(|_| libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    });
    let mut total = 0_usize;
    for (iovec, buffer) in iovecs.iter_mut().zip(buffers) {
        *iovec = libc::iovec {
            iov_base: buffer.as_ptr().cast_mut().cast(),
            iov_len: buffer.len(),
        };
        total += buffer.len();
    }

    let control_len = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as libc::c_uint) } as usize;
    let mut control = [0_usize; 8];
    debug_assert!(control_len <= mem::size_of_val(&control));
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = destination.as_ptr().cast_mut().cast();
    message.msg_namelen = destination.len();
    message.msg_iov = iovecs.as_mut_ptr();
    #[cfg(not(target_env = "musl"))]
    {
        message.msg_iovlen = buffers.len();
    }
    #[cfg(target_env = "musl")]
    {
        message.msg_iovlen = buffers.len() as libc::c_int;
    }
    message.msg_control = control.as_mut_ptr().cast();
    #[cfg(not(target_env = "musl"))]
    {
        message.msg_controllen = control_len;
    }
    #[cfg(target_env = "musl")]
    {
        message.msg_controllen = control_len as libc::socklen_t;
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to allocate UDP GSO control message",
        ));
    }
    unsafe {
        (*cmsg).cmsg_level = SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        #[cfg(not(target_env = "musl"))]
        {
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint) as usize;
        }
        #[cfg(target_env = "musl")]
        {
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint);
        }
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), buffers[0].len() as u16);
    }

    let result = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_DONTWAIT) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result as usize != total {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("UDP GSO sent {result} of {total} payload bytes"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn udp_gso_is_unsupported(error: &io::Error) -> bool {
    use nix::libc;

    matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EINVAL
                || code == libc::ENOPROTOOPT
                || code == libc::EOPNOTSUPP
                || code == libc::EIO
    )
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn try_send_batch(
    socket: &UdpSocket,
    destination: SocketAddr,
    buffers: &[Bytes],
) -> io::Result<usize> {
    let Some(buffer) = buffers.first() else {
        return Ok(0);
    };
    socket.try_send_to(buffer, destination).map(|_| 1)
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};

    use super::{ReceiveSlotPool, checked_message_count, compatible_gso_prefix, split_gro_buffer};

    #[test]
    fn receive_slot_pool_retains_every_unused_allocation() {
        let mut pool = ReceiveSlotPool::new(4, 2048);
        let before = pool.buffer_ptrs_for_test();

        let completed = pool.take_completed_for_test(1);
        assert_eq!(completed.len(), 1);
        pool.refill(2048);

        let after = pool.buffer_ptrs_for_test();
        assert_eq!(&after[1..], &before[1..]);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn vector_completion_rejects_impossible_kernel_counts() {
        assert_eq!(checked_message_count(2, 3).unwrap(), 2);
        assert!(checked_message_count(4, 3).is_err());
    }

    #[test]
    fn gso_prefix_accepts_equal_segments_and_one_short_tail() {
        let equal = vec![Bytes::from(vec![1; 1200]); 4];
        assert_eq!(compatible_gso_prefix(&equal), 4);

        let with_tail = vec![
            Bytes::from(vec![1; 1200]),
            Bytes::from(vec![2; 1200]),
            Bytes::from(vec![3; 400]),
            Bytes::from(vec![4; 1200]),
        ];
        assert_eq!(compatible_gso_prefix(&with_tail), 3);

        let incompatible = vec![Bytes::from(vec![1; 400]), Bytes::from(vec![2; 1200])];
        assert_eq!(compatible_gso_prefix(&incompatible), 1);
    }

    #[test]
    fn gro_stride_restores_individual_datagrams_without_copying() {
        let parts = split_gro_buffer(BytesMut::from(&b"aabbc"[..]), 2).unwrap();
        assert_eq!(
            parts.iter().map(|part| part.as_ref()).collect::<Vec<_>>(),
            vec![b"aa".as_slice(), b"bb", b"c"]
        );
        assert!(split_gro_buffer(BytesMut::from(&b"abc"[..]), 0).is_err());
    }

    #[test]
    fn gro_stride_restores_full_bounded_batch() {
        let stride = 1000;
        let mut super_packet = Vec::with_capacity(super::MAX_PACKET_BATCH_SIZE * stride);
        for tag in 0_u8..super::MAX_PACKET_BATCH_SIZE as u8 {
            super_packet.extend(std::iter::repeat_n(tag, stride));
        }

        let parts = split_gro_buffer(BytesMut::from(super_packet.as_slice()), stride).unwrap();

        assert_eq!(parts.len(), super::MAX_PACKET_BATCH_SIZE);
        for (tag, part) in parts.iter().enumerate() {
            assert_eq!(part.len(), stride);
            assert!(part.iter().all(|byte| *byte == tag as u8));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_udp_gso_and_gro_round_trip_restores_full_bounded_batch() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let payloads = (0_u8..super::MAX_PACKET_BATCH_SIZE as u8)
            .map(|index| {
                let mut payload = vec![index; 1000];
                payload[999] = 0xff - index;
                Bytes::from(payload)
            })
            .collect::<Vec<_>>();

        assert!(super::enable_udp_gro(&receiver).unwrap());
        sender.writable().await.unwrap();
        super::try_send_gso(&sender, destination, &payloads).unwrap();
        receiver.readable().await.unwrap();
        let mut slots = super::ReceiveSlotPool::default();
        let datagrams = super::try_recv_batch(&receiver, 2048, true, &mut slots, None).unwrap();

        assert_eq!(datagrams.len(), payloads.len());
        for (index, (datagram, payload)) in datagrams.iter().zip(payloads).enumerate() {
            assert_eq!(datagram.source, sender.local_addr().unwrap());
            assert_eq!(
                datagram.buffer.as_ref(),
                payload.as_ref(),
                "segment {index}"
            );
        }
    }
}
