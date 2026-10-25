//! Submit already paced QUIC segments as separate, standard UDP datagrams.
use std::{
    ffi::{c_int, c_uint, c_void},
    io, ptr,
};

pub(super) const BATCH_SIZE: usize = 16;

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

// Darwin's msghdr_x ABI, also used by LowTier's utun vector I/O.
#[repr(C)]
struct MsgHdrX {
    name: *mut c_void,
    name_len: u32,
    iov: *mut IoVec,
    iov_len: c_int,
    control: *mut c_void,
    control_len: u32,
    flags: c_int,
    data_len: usize,
}

unsafe extern "C" {
    fn sendmsg_x(fd: c_int, messages: *const MsgHdrX, count: c_uint, flags: c_int) -> isize;
}

pub(super) fn send(fd: c_int, transmit: &udp::Transmit<'_>) -> io::Result<usize> {
    let segment = transmit.segment_size.expect("segmented transmit");
    if segment == 0 || transmit.contents.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty UDP segment",
        ));
    }
    let count = transmit.contents.len().div_ceil(segment).min(BATCH_SIZE);
    let mut iovs: [IoVec; BATCH_SIZE] = std::array::from_fn(|_| IoVec {
        base: ptr::null_mut(),
        len: 0,
    });
    let mut messages: [MsgHdrX; BATCH_SIZE] = std::array::from_fn(|_| MsgHdrX {
        name: ptr::null_mut(),
        name_len: 0,
        iov: ptr::null_mut(),
        iov_len: 0,
        control: ptr::null_mut(),
        control_len: 0,
        flags: 0,
        data_len: 0,
    });
    for ((bytes, iov), message) in transmit
        .contents
        .chunks(segment)
        .zip(&mut iovs)
        .zip(&mut messages)
    {
        *iov = IoVec {
            base: bytes.as_ptr().cast_mut().cast(),
            len: bytes.len(),
        };
        message.iov = iov;
        message.iov_len = 1;
    }
    // SAFETY: descriptors point into the live immutable transmit; sendmsg_x
    // reads these buffers synchronously. The socket is already nonblocking.
    let sent = unsafe { sendmsg_x(fd, messages.as_ptr(), count as c_uint, 0) };
    if sent < 0 {
        let error = io::Error::last_os_error();
        // Darwin EINVAL / EMSGSIZE / ENOTSUP: let the caller fall back to
        // ordinary datagram sends when vector I/O is unavailable or too large.
        if matches!(error.raw_os_error(), Some(22 | 40 | 45)) {
            return Err(error);
        }
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Err(error);
        }
        // Preserve Quinn's UDP error semantics (e.g. ENOBUFS is packet loss).
        tracing::debug!(
            ?error,
            "UDP batch send failed; QUIC will recover packet loss"
        );
        return Ok(transmit.contents.len());
    }
    if sent == 0 || sent as usize > count {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "invalid UDP batch completion",
        ));
    }
    Ok((sent as usize * segment).min(transmit.contents.len()))
}
