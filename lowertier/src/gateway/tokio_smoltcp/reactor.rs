use super::{
    device::{BufferDevice, Packet},
    socket_allocator::{BufferSize, SocketAlloctor},
};
use futures::{FutureExt, SinkExt, Stream, StreamExt, stream::iter};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use smoltcp::{
    iface::{Context, Interface, PollResult, SocketHandle, SocketSet},
    socket::{AnySocket, Socket},
    time::{Duration, Instant},
};
use std::{collections::VecDeque, future::Future, io, sync::Arc};
use tokio::{pin, select, sync::Notify, time::sleep};

pub(crate) type BufferInterface = Arc<Mutex<Interface>>;
const MAX_BURST_SIZE: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::packet_def::ZCPacket;
    use smoltcp::{
        iface::Config,
        phy::{ChecksumCapabilities, DeviceCapabilities, Medium},
        socket::tcp,
        wire::{
            HardwareAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl,
            TcpPacket, TcpRepr, TcpSeqNumber,
        },
    };

    #[tokio::test]
    async fn notification_before_the_reactor_wait_is_retained() {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        let (async_device, _incoming, _outgoing) =
            super::super::channel_device::ChannelDevice::new(caps.clone());
        let mut device = BufferDevice::new(caps);
        let iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        let (reactor, _running) = Reactor::new(
            async_device,
            iface,
            device,
            BufferSize::default(),
            Arc::new(Notify::new()),
        );
        // An application can enqueue data after poll_delay releases the lock,
        // before the reactor constructs its next Notified future.
        reactor.notify();
        reactor.notify();
        assert!(reactor.notify.notified().now_or_never().is_some());
        // Multiple writes coalesce into one pending poll, avoiding a spin loop.
        assert!(reactor.notify.notified().now_or_never().is_none());
    }

    #[test]
    fn full_receive_batch_preserves_the_next_packet() {
        let mut incoming = iter((0..5).map(|value| Ok(ZCPacket::new_with_payload(&[value]))));
        let mut received = VecDeque::new();
        drain_ready_packets(&mut incoming, &mut received, 4);
        assert_eq!(received.len(), 4);
        for (value, packet) in received.iter().enumerate() {
            assert_eq!(packet.payload(), &[value as u8]);
        }
        let next = incoming.next().now_or_never().flatten().unwrap().unwrap();
        assert_eq!(next.payload(), &[4]);
    }

    #[test]
    fn ready_tcp_segments_fill_one_bounded_batch() {
        let local = Ipv4Address::new(10, 0, 0, 1);
        let remote = Ipv4Address::new(10, 0, 0, 2);
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps.max_burst_size = Some(4);
        let mut device = BufferDevice::new(caps);
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now);
        iface.update_ip_addrs(|addresses| addresses.push(IpCidr::new(local.into(), 24)).unwrap());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 16384]),
            tcp::SocketBuffer::new(vec![0; 16384]),
        );
        socket.set_nagle_enabled(false);
        socket
            .connect(iface.context(), (remote, 5209), (local, 40000))
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);
        poll_packets(&mut iface, &mut device, &mut sockets, now, 4);
        let syn = device.drain_send_queue().next().unwrap();
        let ip = Ipv4Packet::new_checked(syn.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let reply = TcpRepr {
            src_port: 5209,
            dst_port: 40000,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1000),
            ack_number: Some(tcp.seq_number() + 1),
            window_len: u16::MAX,
            window_scale: None,
            // Four segments fit the initial 2048-byte Reno window.
            max_seg_size: Some(512),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip_reply = Ipv4Repr {
            src_addr: remote,
            dst_addr: local,
            next_header: IpProtocol::Tcp,
            payload_len: reply.buffer_len(),
            hop_limit: 64,
        };
        let mut packet = ZCPacket::new_with_payload_len(ip_reply.buffer_len() + reply.buffer_len());
        let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
        let checksums = ChecksumCapabilities::default();
        ip_reply.emit(&mut ip, &checksums);
        reply.emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &remote.into(),
            &local.into(),
            &checksums,
        );
        device.push_recv_queue(std::iter::once(packet));
        poll_packets(
            &mut iface,
            &mut device,
            &mut sockets,
            Instant::from_millis(10),
            4,
        );
        device.drain_send_queue();
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        assert_eq!(socket.state(), tcp::State::Established);
        assert_eq!(socket.send_slice(&[0x5a; 16384]).unwrap(), 16384);
        let mut delivered = 0;
        while delivered < 16384 {
            poll_packets(
                &mut iface,
                &mut device,
                &mut sockets,
                Instant::from_millis(11),
                4,
            );
            let packets: Vec<_> = device.drain_send_queue().collect();
            assert!(!packets.is_empty() && packets.len() <= 4);
            if delivered == 0 {
                assert_eq!(packets.len(), 4);
            }
            let mut next_ack = None;
            for packet in packets {
                let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert!(!tcp.payload().is_empty());
                assert!(tcp.payload().iter().all(|&byte| byte == 0x5a));
                delivered += tcp.payload().len();
                next_ack = Some(tcp.seq_number() + tcp.payload().len());
            }
            // Model the peer's cumulative ACK. Each following batch needs
            // credit released by the prior flight with congestion control on.
            let ack = TcpRepr {
                control: TcpControl::None,
                seq_number: TcpSeqNumber(1001),
                ack_number: next_ack,
                max_seg_size: None,
                ..reply
            };
            let ip_ack = Ipv4Repr {
                payload_len: ack.buffer_len(),
                ..ip_reply
            };
            let mut packet = ZCPacket::new_with_payload_len(ip_ack.buffer_len() + ack.buffer_len());
            let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
            ip_ack.emit(&mut ip, &checksums);
            ack.emit(
                &mut TcpPacket::new_unchecked(ip.payload_mut()),
                &remote.into(),
                &local.into(),
                &checksums,
            );
            device.push_recv_queue(std::iter::once(packet));
        }
        assert_eq!(delivered, 16384);
    }
}

fn poll_packets(
    iface: &mut Interface,
    device: &mut BufferDevice,
    sockets: &mut SocketSet<'_>,
    now: Instant,
    burst_limit: usize,
) {
    iface.poll(now, device, sockets);
    // smoltcp emits at most one segment per socket in each egress pass.
    // Fill the bounded device queue before a timer or channel wakeup.
    for _ in 1..burst_limit {
        if iface.poll_egress(now, device, sockets) == PollResult::None {
            break;
        }
    }
}

pub(crate) struct Reactor {
    notify: Arc<Notify>,
    iface: BufferInterface,
    socket_allocator: SocketAlloctor,
}

async fn receive(
    async_iface: &mut impl super::device::AsyncDevice,
    recv_buf: &mut VecDeque<Packet>,
) -> io::Result<()> {
    if let Some(packet) = async_iface.next().await {
        recv_buf.push_back(packet?);
    }
    Ok(())
}

fn drain_ready_packets(
    incoming: &mut (impl Stream<Item = io::Result<Packet>> + Unpin),
    received: &mut VecDeque<Packet>,
    limit: usize,
) {
    // Check capacity before polling. Polling a full batch consumes and loses
    // the next packet, even when a tuple pattern rejects the loop body.
    while received.len() < limit {
        let Some(Ok(packet)) = incoming.next().now_or_never().flatten() else {
            break;
        };
        received.push_back(packet);
    }
}

async fn run(
    mut async_iface: impl super::device::AsyncDevice,
    iface: BufferInterface,
    mut device: BufferDevice,
    socket_allocator: SocketAlloctor,
    notify: Arc<Notify>,
    stopper: Arc<Notify>,
) -> io::Result<()> {
    let default_timeout = Duration::from_secs(60);
    let timer = sleep(default_timeout.into());
    let max_burst_size = async_iface
        .capabilities()
        .max_burst_size
        .unwrap_or(MAX_BURST_SIZE);
    let mut recv_buf = VecDeque::with_capacity(max_burst_size);
    pin!(timer);

    loop {
        let packets = device.drain_send_queue();

        async_iface.send_all(&mut iter(packets).map(Ok)).await?;

        if recv_buf.is_empty() && device.need_wait() {
            let start = Instant::now();
            let deadline = {
                iface
                    .lock()
                    .poll_delay(start, &socket_allocator.sockets().lock())
                    .unwrap_or(default_timeout)
            };

            timer
                .as_mut()
                .reset(tokio::time::Instant::now() + deadline.into());
            select! {
                _ = &mut timer => {},
                _ = receive(&mut async_iface,&mut recv_buf) => {}
                _ = notify.notified() => {}
                _ = stopper.notified() => break,
            };

            drain_ready_packets(&mut async_iface, &mut recv_buf, max_burst_size);
        }

        let mut iface = iface.lock();

        device.push_recv_queue(recv_buf.drain(..device.avaliable_recv_queue().min(recv_buf.len())));

        let mut sockets = socket_allocator.sockets().lock();
        poll_packets(
            &mut iface,
            &mut device,
            &mut sockets,
            Instant::now(),
            max_burst_size,
        );

        // wake up all closed sockets (smoltcp seems have a bug that it doesn't wake up closed sockets)
        for (_, socket) in sockets.iter_mut() {
            if let Socket::Tcp(tcp) = socket
                && tcp.state() == smoltcp::socket::tcp::State::Closed
            {
                tcp.abort();
            }
        }
    }

    Ok(())
}

impl Reactor {
    pub fn new(
        async_device: impl super::device::AsyncDevice,
        iface: Interface,
        device: BufferDevice,
        buffer_size: BufferSize,
        stopper: Arc<Notify>,
    ) -> (Self, impl Future<Output = io::Result<()>> + Send) {
        let iface = Arc::new(Mutex::new(iface));
        let notify = Arc::new(Notify::new());
        let socket_allocator = SocketAlloctor::new(buffer_size);
        let fut = run(
            async_device,
            iface.clone(),
            device,
            socket_allocator.clone(),
            notify.clone(),
            stopper,
        );

        (
            Reactor {
                notify,
                iface,
                socket_allocator,
            },
            fut,
        )
    }
    pub fn get_socket<T: AnySocket<'static>>(
        &self,
        handle: SocketHandle,
    ) -> MappedMutexGuard<'_, T> {
        MutexGuard::map(
            self.socket_allocator.sockets().lock(),
            |sockets: &mut smoltcp::iface::SocketSet<'_>| sockets.get_mut::<T>(handle),
        )
    }
    pub fn context(&self) -> MappedMutexGuard<'_, Context> {
        MutexGuard::map(self.iface.lock(), |iface| iface.context())
    }
    pub fn socket_allocator(&self) -> &SocketAlloctor {
        &self.socket_allocator
    }
    pub fn notify(&self) {
        // There is one reactor consumer. Preserve a permit for writes that
        // race with poll_delay or happen while the previous batch is draining.
        self.notify.notify_one();
    }
    pub fn iface(&self) -> &BufferInterface {
        &self.iface
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        for (_, socket) in self.socket_allocator.sockets().lock().iter_mut() {
            if let Socket::Tcp(tcp) = socket {
                tcp.close()
            }
        }
    }
}
