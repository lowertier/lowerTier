use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, OnceLock,
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread,
};

use bytes::BytesMut;
use io_uring::{IoUring, opcode, squeue, types};
use tokio::sync::oneshot;

const RING_ENTRIES: u32 = 128;
const WORK_QUEUE_CAPACITY: usize = 1;

static ENABLED: OnceLock<bool> = OnceLock::new();

pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("LOWTIER_ENABLE_IO_URING_TUN").is_some_and(|value| value != "0")
    })
}

struct Work {
    buffers: Vec<BytesMut>,
    completion: oneshot::Sender<(io::Result<(usize, usize)>, Vec<BytesMut>)>,
}

#[derive(Clone)]
pub(crate) struct IoUringTunWriter {
    sender: SyncSender<Work>,
    terminal_error: Arc<OnceLock<String>>,
}

impl IoUringTunWriter {
    pub(crate) fn new(fd: RawFd, queue_index: usize, payload_offset: usize) -> io::Result<Self> {
        let fd = duplicate_fd(fd)?;
        let ring = IoUring::new(RING_ENTRIES)?;
        let (sender, receiver) = sync_channel(WORK_QUEUE_CAPACITY);
        let terminal_error = Arc::new(OnceLock::new());
        let worker_error = terminal_error.clone();
        thread::Builder::new()
            .name(format!("lowertier-tun-uring-{queue_index}"))
            .spawn(move || run_worker(ring, fd, receiver, payload_offset, worker_error))?;
        Ok(Self {
            sender,
            terminal_error,
        })
    }

    pub(crate) async fn submit(
        &self,
        buffers: Vec<BytesMut>,
    ) -> (io::Result<(usize, usize)>, Vec<BytesMut>) {
        if let Some(error) = self.terminal_error.get() {
            return (
                Err(io::Error::other(format!(
                    "io_uring TUN writer stopped: {error}"
                ))),
                buffers,
            );
        }
        let (completion, result) = oneshot::channel();
        let work = Work {
            buffers,
            completion,
        };
        match self.sender.try_send(work) {
            Ok(()) => {}
            Err(TrySendError::Full(work)) => {
                return (
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "io_uring TUN work queue is full",
                    )),
                    work.buffers,
                );
            }
            Err(TrySendError::Disconnected(work)) => {
                return (
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "io_uring TUN worker is closed",
                    )),
                    work.buffers,
                );
            }
        }
        match result.await {
            Ok(result) => result,
            Err(_) => (
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "io_uring TUN worker dropped its completion",
                )),
                Vec::new(),
            ),
        }
    }
}

fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `dup` does not borrow the original descriptor after returning.
    let duplicated = unsafe { nix::libc::dup(fd) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `dup` returns a new descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn run_worker(
    mut ring: IoUring,
    fd: OwnedFd,
    receiver: Receiver<Work>,
    payload_offset: usize,
    terminal_error: Arc<OnceLock<String>>,
) {
    while let Ok(work) = receiver.recv() {
        let Work {
            mut buffers,
            completion,
        } = work;
        let result = submit_batch(&mut ring, fd.as_raw_fd(), &mut buffers, payload_offset);
        let failed = result.as_ref().err().map(ToString::to_string);
        let completion_closed = completion.send((result, buffers)).is_err();
        if let Some(error) = failed {
            let _ = terminal_error.set(error);
            return;
        }
        if completion_closed {
            return;
        }
    }
}

fn submit_batch(
    ring: &mut IoUring,
    fd: RawFd,
    buffers: &mut [BytesMut],
    payload_offset: usize,
) -> io::Result<(usize, usize)> {
    if buffers.is_empty() {
        return Ok((0, 0));
    }
    if buffers.len() > RING_ENTRIES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN batch exceeds io_uring depth",
        ));
    }

    {
        let mut submission = ring.submission();
        for (index, buffer) in buffers.iter().enumerate() {
            let payload = buffer.get(payload_offset..).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TUN packet is shorter than the io_uring payload offset",
                )
            })?;
            let mut entry = opcode::Write::new(
                types::Fd(fd),
                payload.as_ptr(),
                u32::try_from(payload.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "TUN packet exceeds u32")
                })?,
            )
            .offset(u64::MAX)
            .build()
            .user_data(index as u64);
            // Keep packets in the scheduler-selected order. Each write remains
            // an independent packet operation while one submit amortizes the
            // ring transition for the complete ready batch.
            if index + 1 != buffers.len() {
                entry = entry.flags(squeue::Flags::IO_HARDLINK);
            }
            // SAFETY: each buffer remains alive and immovable until all CQEs
            // are consumed below, and the ring has at least `RING_ENTRIES` SQEs.
            unsafe {
                submission.push(&entry).map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "io_uring SQ is full")
                })?;
            }
        }
    }

    ring.submit_and_wait(buffers.len())?;
    let mut completed = vec![false; buffers.len()];
    let mut remaining = buffers.len();
    let mut total_bytes = 0_usize;
    let mut first_error = None;
    while remaining != 0 {
        let mut made_progress = false;
        {
            let mut completion = ring.completion();
            for cqe in &mut completion {
                made_progress = true;
                let index = usize::try_from(cqe.user_data()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid io_uring user data")
                })?;
                if index >= buffers.len() || completed[index] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate or out-of-range io_uring completion",
                    ));
                }
                completed[index] = true;
                remaining -= 1;
                let result = cqe.result();
                if result < 0 {
                    if first_error.is_none() {
                        first_error = Some(io::Error::from_raw_os_error(-result));
                    }
                    continue;
                }
                let written = result as usize;
                let expected = buffers[index].len().saturating_sub(payload_offset);
                if written != expected {
                    if first_error.is_none() {
                        first_error = Some(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!("partial TUN write through io_uring: {written} of {expected}"),
                        ));
                    }
                    continue;
                }
                total_bytes = total_bytes.saturating_add(written);
            }
        }
        if remaining != 0 && !made_progress {
            ring.submit_and_wait(remaining)?;
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok((total_bytes, buffers.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram, time::Duration};

    use bytes::BytesMut;

    use super::{IoUringTunWriter, RING_ENTRIES, enabled};

    #[test]
    fn ring_depth_covers_one_dataplane_batch() {
        assert!(RING_ENTRIES as usize >= crate::tunnel::batch::MAX_PACKET_BATCH_SIZE);
    }

    #[test]
    fn io_uring_is_explicitly_opt_in() {
        if std::env::var_os("LOWTIER_ENABLE_IO_URING_TUN").is_none() {
            assert!(!enabled());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires a Linux kernel that permits io_uring_setup"]
    async fn persistent_writer_preserves_independent_packet_boundaries_and_order() {
        let (writer_socket, reader_socket) = UnixDatagram::pair().unwrap();
        reader_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let writer = IoUringTunWriter::new(writer_socket.as_raw_fd(), 0, 1).unwrap();
        let buffers = vec![
            BytesMut::from(&b"xfirst"[..]),
            BytesMut::from(&b"xsecond-packet"[..]),
            BytesMut::from(&b"xthird"[..]),
        ];

        let (result, returned) = writer.submit(buffers).await;
        assert_eq!(result.unwrap(), (5 + 13 + 5, 3));
        assert_eq!(returned.len(), 3);

        for expected in [&b"first"[..], &b"second-packet"[..], &b"third"[..]] {
            let mut received = [0_u8; 64];
            let length = reader_socket.recv(&mut received).unwrap();
            assert_eq!(&received[..length], expected);
        }
    }
}
