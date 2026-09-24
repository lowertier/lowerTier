use parking_lot::Mutex;
use smoltcp::{
    iface::{SocketHandle as InnerSocketHandle, SocketSet},
    socket::{tcp, udp},
    time::Duration,
};
use std::{
    io,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};

use super::tcp_buffers::TcpBuffers;
use crate::common::global_ctx::global_process_memory_governor;

/// `BufferSize` is used to configure the size of the socket buffer.
#[derive(Debug, Clone, Copy)]
pub struct BufferSize {
    pub tcp_rx_size: usize,
    pub tcp_tx_size: usize,

    pub udp_rx_size: usize,
    pub udp_tx_size: usize,
    pub udp_rx_meta_size: usize,
    pub udp_tx_meta_size: usize,
}

impl Default for BufferSize {
    fn default() -> Self {
        BufferSize {
            tcp_rx_size: 8192,
            tcp_tx_size: 8192,

            udp_rx_size: 8192,
            udp_tx_size: 8192,
            udp_rx_meta_size: 32,
            udp_tx_meta_size: 32,
        }
    }
}

type SharedSocketSet = Arc<Mutex<SocketSet<'static>>>;

// Retain only protocol state after an acknowledged close. A fixed bound limits
// TIME-WAIT metadata and abandoned receive halves independently of traffic.
const MAX_RETIRED_TCP_SOCKETS: usize = 64;
const RETIRED_TCP_TIMEOUT: StdDuration = StdDuration::from_secs(60);

struct RetiredSocket {
    handle: InnerSocketHandle,
    deadline: Instant,
    buffers: Option<Mutex<TcpBuffers>>,
}

#[derive(Default)]
struct RetiredSockets {
    entries: Mutex<Vec<RetiredSocket>>,
    count: AtomicUsize,
}

#[derive(Clone)]
pub struct SocketAlloctor {
    sockets: SharedSocketSet,
    buffer_size: BufferSize,
    retired: Arc<RetiredSockets>,
}

impl SocketAlloctor {
    pub(crate) fn new(buffer_size: BufferSize) -> SocketAlloctor {
        let sockets = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        SocketAlloctor {
            sockets,
            buffer_size,
            retired: Arc::new(RetiredSockets::default()),
        }
    }
    pub(crate) fn sockets(&self) -> &SharedSocketSet {
        &self.sockets
    }
    pub(super) fn has_retired(&self) -> bool {
        self.retired.count.load(Ordering::Relaxed) != 0
    }

    pub(super) fn reap_retired(&self, sockets: &mut SocketSet<'static>, now: Instant) {
        let mut retired = self.retired.entries.lock();
        retired.retain_mut(|entry| {
            let tcp = sockets.get_mut::<tcp::Socket>(entry.handle);
            if tcp.state() == tcp::State::Closed || now >= entry.deadline {
                sockets.remove(entry.handle);
                return false;
            }
            // FIN-WAIT-2 still receives data. Keep its receive storage and
            // accounting until the peer closes; never shrink an advertised window.
            if tcp.release_time_wait_buffers() {
                entry.buffers = None;
            }
            true
        });
        self.retired.count.store(retired.len(), Ordering::Relaxed);
    }

    pub fn new_tcp_socket(&self) -> io::Result<SocketHandle> {
        let buffers = TcpBuffers::new(
            self.buffer_size.tcp_rx_size,
            self.buffer_size.tcp_tx_size,
            global_process_memory_governor(),
        )?;
        let mut set = self.sockets.lock();
        let handle = set.add(self.alloc_tcp_socket());
        let mut handle = SocketHandle::new(handle, self.sockets.clone(), self.retired.clone());
        handle.2 = Some(Mutex::new(buffers));
        Ok(handle)
    }
    fn alloc_tcp_socket(&self) -> tcp::Socket<'static> {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_rx_size]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_tx_size]);
        let mut tcp = tcp::Socket::new(rx_buffer, tx_buffer);
        tcp.set_recv_capacity_limit(TcpBuffers::recv_limit(self.buffer_size.tcp_rx_size));
        tcp.set_nagle_enabled(false);
        tcp.set_keep_alive(Some(Duration::from_secs(10)));
        tcp.set_timeout(Some(Duration::from_secs(60)));

        tcp
    }

    pub fn new_udp_socket(&self) -> SocketHandle {
        let mut set = self.sockets.lock();
        let handle = set.add(self.alloc_udp_socket());
        SocketHandle::new(handle, self.sockets.clone(), self.retired.clone())
    }

    fn alloc_udp_socket(&self) -> udp::Socket<'static> {
        let rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_rx_meta_size],
            vec![0; self.buffer_size.udp_rx_size],
        );
        let tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_tx_meta_size],
            vec![0; self.buffer_size.udp_tx_size],
        );

        udp::Socket::new(rx_buffer, tx_buffer)
    }
}

pub struct SocketHandle(
    InnerSocketHandle,
    SharedSocketSet,
    pub(super) Option<Mutex<TcpBuffers>>,
    Arc<RetiredSockets>,
);

impl SocketHandle {
    fn new(
        inner: InnerSocketHandle,
        set: SharedSocketSet,
        retired: Arc<RetiredSockets>,
    ) -> SocketHandle {
        SocketHandle(inner, set, None, retired)
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        let mut sockets = self.1.lock();
        if self.2.is_some() {
            let tcp = sockets.get_mut::<tcp::Socket>(self.0);
            // An acknowledged FIN proves the complete transmit queue arrived.
            // Keep the socket available for a lost final ACK / retransmitted FIN.
            if matches!(tcp.state(), tcp::State::FinWait2 | tcp::State::TimeWait)
                && tcp.send_queue() == 0
            {
                let mut retired = self.3.entries.lock();
                if retired.len() < MAX_RETIRED_TCP_SOCKETS {
                    if tcp.release_time_wait_buffers() {
                        self.2 = None;
                    }
                    retired.push(RetiredSocket {
                        handle: self.0,
                        deadline: Instant::now() + RETIRED_TCP_TIMEOUT,
                        buffers: self.2.take(),
                    });
                    self.3.count.store(retired.len(), Ordering::Relaxed);
                    return;
                }
                // At the bound, retain the existing handle-destruction behavior.
                // All local payload was acknowledged before reaching this path.
            }
        }
        sockets.remove(self.0);
    }
}

impl Deref for SocketHandle {
    type Target = InnerSocketHandle;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SocketHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
