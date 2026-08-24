use std::{
    collections::BTreeSet,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use crate::{
    common::{
        config::{Flags, InterfaceAdapter},
        dataplane_telemetry::DataplaneStage,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        ifcfg::{IfConfiger, IfConfiguerTrait},
        log,
    },
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{
        PacketRecvChanReceiver,
        fabric::{FabricBatch, FabricPacket, FabricPayloadKind},
        flow::{FLOW_SHARD_COUNT, classify_nic_packet_flow},
        peer_manager::{DirectNicEndpoint, PeerManager},
    },
    tunnel::{
        PacketBatchSink, PacketBatchStream, StreamItem, Tunnel, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, RECEIVE_PREFETCH_BATCHES},
        common::{FramedWriter, TunnelWrapper, ZCPacketToBytes},
        packet_def::{ZCPacket, ZCPacketType},
    },
};

use byteorder::WriteBytesExt as _;
use bytes::{Buf, BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{FutureExt, Sink, Stream, StreamExt, lock::BiLock, ready};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "windows")]
use tokio_util::task::AbortOnDropHandle;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use zerocopy::{NativeEndian, NetworkEndian};

fn parse_interface_mac(value: &str) -> Option<[u8; 6]> {
    let mut mac = [0_u8; 6];
    let mut parts = value.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

fn interface_mac(ifname: &str) -> Result<[u8; 6], Error> {
    NetworkInterface::show()
        .map_err(|error| anyhow::anyhow!("cannot list network interfaces: {error}"))?
        .into_iter()
        .find(|interface| interface.name == ifname)
        .and_then(|interface| interface.mac_addr)
        .and_then(|address| parse_interface_mac(&address))
        .ok_or_else(|| anyhow::anyhow!("cannot find the MAC address for {ifname}").into())
}

fn restore_compact_ip_for_tap(
    packet: &mut ZCPacket,
    local_mac: [u8; 6],
) -> Result<(), &'static str> {
    let Some(header) = packet.peer_manager_header() else {
        return Err("packet has no peer header");
    };
    if header.packet_type != crate::tunnel::packet_def::PacketType::Data as u8 {
        return Ok(());
    }
    let source_mac = crate::instance::l2_tun::encode_peer_mac(header.from_peer_id.get());
    let ether_type = match packet.payload().first().map(|byte| byte >> 4) {
        Some(4) => 0x0800_u16,
        Some(6) => 0x86dd_u16,
        _ => return Err("compact packet is not IPv4 or IPv6"),
    };
    let destination_mac = crate::instance::l2_tun::ip_destination_mac(packet.payload(), local_mac)
        .ok_or("compact packet has an invalid IP destination")?;
    let mut ethernet_header = [0_u8; crate::instance::l2_tun::ETHERNET_HEADER_LEN];
    ethernet_header[..6].copy_from_slice(&destination_mac);
    ethernet_header[6..12].copy_from_slice(&source_mac);
    ethernet_header[12..14].copy_from_slice(&ether_type.to_be_bytes());
    packet.prepend_payload_preserving_flow_hash(&ethernet_header)
}

struct HybridTapSink {
    inner: Pin<Box<dyn PacketBatchSink>>,
    local_mac: [u8; 6],
}

impl Sink<PacketBatch> for HybridTapSink {
    type Error = TunnelError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_ready(context)
    }

    fn start_send(mut self: Pin<&mut Self>, mut batch: PacketBatch) -> Result<(), Self::Error> {
        for packet in batch.iter_mut() {
            restore_compact_ip_for_tap(packet, self.local_mac)
                .map_err(|error| TunnelError::InvalidPacket(error.to_string()))?;
        }
        self.inner.as_mut().start_send(batch)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_flush(context)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().poll_close(context)
    }
}

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;

const NIC_PACKET_BATCH_SIZE: usize = MAX_PACKET_BATCH_SIZE;
static NIC_BATCH_COUNT: AtomicU64 = AtomicU64::new(0);
static NIC_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
static NIC_MAX_BATCH: AtomicUsize = AtomicUsize::new(0);
static PEER_BATCH_DISABLED: OnceLock<bool> = OnceLock::new();

#[derive(Default)]
struct NicIngressFlowLane {
    next_ticket: u64,
    serving: u64,
    completed: BTreeSet<u64>,
}

struct NicIngressFlowGate {
    lanes: StdMutex<Vec<NicIngressFlowLane>>,
    notifiers: Vec<Notify>,
}

impl NicIngressFlowGate {
    fn new() -> Self {
        let lane_count = usize::from(FLOW_SHARD_COUNT);
        Self {
            lanes: StdMutex::new(
                std::iter::repeat_with(NicIngressFlowLane::default)
                    .take(lane_count)
                    .collect(),
            ),
            notifiers: std::iter::repeat_with(Notify::new)
                .take(lane_count)
                .collect(),
        }
    }

    fn reserve_batch(
        self: &Arc<Self>,
        batch: &PacketBatch,
        adapter: InterfaceAdapter,
    ) -> NicIngressFlowPermit {
        let ethernet = adapter.uses_native_ethernet();
        self.reserve_shards(
            batch
                .iter()
                .map(|packet| classify_nic_packet_flow(packet, ethernet).shard),
        )
    }

    fn reserve_shards(
        self: &Arc<Self>,
        shards: impl IntoIterator<Item = u16>,
    ) -> NicIngressFlowPermit {
        let mut present = [false; FLOW_SHARD_COUNT as usize];
        for shard in shards {
            present[usize::from(shard) % present.len()] = true;
        }

        // One short lock gives every intersecting batch the same reservation order.
        let mut lanes = self.lanes.lock().expect("NIC ingress flow gate poisoned");
        let mut tickets = Vec::new();
        for (index, is_present) in present.into_iter().enumerate() {
            if !is_present {
                continue;
            }
            let lane = &mut lanes[index];
            let ticket = lane.next_ticket;
            lane.next_ticket = lane.next_ticket.wrapping_add(1);
            tickets.push((index, ticket));
        }
        drop(lanes);
        NicIngressFlowPermit {
            gate: self.clone(),
            tickets,
        }
    }
}

struct NicIngressFlowPermit {
    gate: Arc<NicIngressFlowGate>,
    tickets: Vec<(usize, u64)>,
}

impl NicIngressFlowPermit {
    async fn wait(&self) {
        for &(index, ticket) in &self.tickets {
            loop {
                let notified = self.gate.notifiers[index].notified();
                let ready = self
                    .gate
                    .lanes
                    .lock()
                    .expect("NIC ingress flow gate poisoned")[index]
                    .serving
                    == ticket;
                if ready {
                    break;
                }
                notified.await;
            }
        }
    }
}

impl Drop for NicIngressFlowPermit {
    fn drop(&mut self) {
        let mut notify = Vec::new();
        let mut lanes = self
            .gate
            .lanes
            .lock()
            .expect("NIC ingress flow gate poisoned");
        for &(index, ticket) in &self.tickets {
            let lane = &mut lanes[index];
            lane.completed.insert(ticket);
            let previous = lane.serving;
            while lane.completed.remove(&lane.serving) {
                lane.serving = lane.serving.wrapping_add(1);
            }
            if lane.serving != previous {
                notify.push(index);
            }
        }
        drop(lanes);
        for index in notify {
            self.gate.notifiers[index].notify_waiters();
        }
    }
}

fn nic_packet_batch_size() -> usize {
    std::env::var("LOWTIER_DEBUG_NIC_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, MAX_PACKET_BATCH_SIZE))
        .unwrap_or(NIC_PACKET_BATCH_SIZE)
}

#[cfg(target_os = "linux")]
fn linux_tun_offload_enabled() -> bool {
    linux_tun_offload_configured(
        std::env::var_os("LOWTIER_ENABLE_LINUX_TUN_OFFLOAD").is_some(),
        std::env::var_os("LOWTIER_DISABLE_LINUX_TUN_OFFLOAD").is_some(),
        linux_tun_offload_auto_supported_for(std::env::consts::ARCH),
    )
}

#[cfg(any(target_os = "linux", test))]
fn linux_tun_offload_auto_supported_for(arch: &str) -> bool {
    match arch {
        // Keep the existing well-covered x86_64 behavior.
        "x86_64" => true,
        // The vendored TUN backend uses NEON for checksum accumulation.
        // Enable the complete TSO and GRO path on AArch64.
        "aarch64" => true,
        _ => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_tun_offload_configured(
    explicitly_enabled: bool,
    explicitly_disabled: bool,
    automatically_supported: bool,
) -> bool {
    !explicitly_disabled && (explicitly_enabled || automatically_supported)
}

/// Maximum Linux TUN/TAP queues. Each queue is one character device FD with
/// independent read and write completion. More than four queues adds memory
/// without helping the single-core receive pump.
const LINUX_VIRTUAL_NIC_MAX_QUEUES: usize = 4;

#[cfg(target_os = "linux")]
fn linux_virtual_nic_queue_count(
    _native_ethernet: bool,
    parallelism: usize,
    requested: Option<usize>,
) -> usize {
    let available = parallelism.max(1);
    let default = if available >= 2 {
        available.min(LINUX_VIRTUAL_NIC_MAX_QUEUES)
    } else {
        1
    };
    requested
        .unwrap_or(default)
        .clamp(1, LINUX_VIRTUAL_NIC_MAX_QUEUES)
        .min(available)
}

fn record_nic_batch_size(batch_size: usize) {
    let previous_packets = NIC_PACKET_COUNT.fetch_add(batch_size as u64, Ordering::Relaxed);
    let batch_count = NIC_BATCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    NIC_MAX_BATCH.fetch_max(batch_size, Ordering::Relaxed);
    let packet_count = previous_packets + batch_size as u64;
    if batch_count.is_power_of_two() || previous_packets / 65_536 != packet_count / 65_536 {
        tracing::warn!(
            batch_count,
            packet_count,
            average_batch_size = packet_count as f64 / batch_count as f64,
            max_batch_size = NIC_MAX_BATCH.load(Ordering::Relaxed),
            "NIC packet batch statistics"
        );
    }
}

fn peer_batch_disabled() -> bool {
    *PEER_BATCH_DISABLED
        .get_or_init(|| std::env::var_os("LOWTIER_DEBUG_DISABLE_PEER_BATCH").is_some())
}

async fn read_ready_packet_batch<S>(
    stream: &mut S,
    max_packets: usize,
) -> Result<Option<PacketBatch>, TunnelError>
where
    S: Stream<Item = StreamItem> + Unpin,
{
    assert!(max_packets > 0);
    let Some(first) = stream.next().await else {
        return Ok(None);
    };
    // Most scalar TUN implementations wake us for one packet at a time. Do not
    // allocate a 64-entry backing vector until ready packets actually exist.
    let mut batch = PacketBatch::new();
    batch
        .try_push(first?)
        .expect("a new packet batch always accepts its first packet");

    let limit = max_packets.min(MAX_PACKET_BATCH_SIZE);
    while batch.len() < limit {
        match stream.next().now_or_never() {
            Some(Some(Ok(packet))) => batch
                .try_push(packet)
                .expect("the batch length is checked before pushing"),
            Some(Some(Err(error))) => return Err(error),
            Some(None) | None => break,
        }
    }

    Ok(Some(batch))
}

pin_project! {
    pub struct TunStream {
        #[pin]
        l: BiLock<AsyncDevice>,
        cur_buf: BytesMut,
        has_packet_info: bool,
        payload_offset: usize,
        payload_prefix_len: usize,
    }
}

impl TunStream {
    pub fn new(l: BiLock<AsyncDevice>, has_packet_info: bool, payload_prefix_len: usize) -> Self {
        let mut payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        if has_packet_info {
            payload_offset -= 4;
        }
        Self {
            l,
            cur_buf: BytesMut::new(),
            has_packet_info,
            payload_offset,
            payload_prefix_len,
        }
    }
}

const TUN_READ_SPARE_BYTES: usize = 2500;

fn prepare_tun_read_buffer(buf: &mut BytesMut, prefix_len: usize) {
    if buf.is_empty() {
        buf.resize(prefix_len, 0);
    }
    let spare = buf.capacity().saturating_sub(buf.len());
    if spare < TUN_READ_SPARE_BYTES {
        buf.reserve(TUN_READ_SPARE_BYTES);
    }
}

impl Stream for TunStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        prepare_tun_read_buffer(
            self_mut.cur_buf,
            *self_mut.payload_offset + *self_mut.payload_prefix_len,
        );
        let spare = self_mut.cur_buf.spare_capacity_mut();
        let mut buf = ReadBuf::uninit(spare);

        let ret = ready!(g.as_pin_mut().poll_read(cx, &mut buf));
        let len = buf.filled().len();
        if len == 0 {
            return Poll::Ready(None);
        }
        // ReadBuf confirms that the device initialized these bytes.
        unsafe { self_mut.cur_buf.advance_mut(len) };

        let ret_buf = self_mut.cur_buf.split();

        match ret {
            Ok(_) => Poll::Ready(Some(Ok(ZCPacket::new_from_buf(ret_buf, ZCPacketType::NIC)))),
            Err(err) => {
                log::error!("tun stream error: {:?}", err);
                Poll::Ready(None)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum PacketProtocol {
    #[default]
    IPv4,
    IPv6,
    Other(u8),
}

// Note: the protocol in the packet information header is platform dependent.
impl PacketProtocol {
    #[cfg(any(target_os = "linux", target_os = "android", target_env = "ohos"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::IPv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::IPv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(target_os = "windows")]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        unimplemented!()
    }
}

/// Infer the protocol based on the first nibble in the packet buffer.
fn infer_proto(buf: &[u8]) -> PacketProtocol {
    match buf[0] >> 4 {
        4 => PacketProtocol::IPv4,
        6 => PacketProtocol::IPv6,
        p => PacketProtocol::Other(p),
    }
}

struct TunZCPacketToBytes {
    has_packet_info: bool,
}

impl TunZCPacketToBytes {
    pub fn new(has_packet_info: bool) -> Self {
        Self { has_packet_info }
    }

    pub fn fill_packet_info(
        &self,
        mut buf: &mut [u8],
        proto: PacketProtocol,
    ) -> Result<(), io::Error> {
        // flags is always 0
        buf.write_u16::<NativeEndian>(0)?;
        // write the protocol as network byte order
        buf.write_u16::<NetworkEndian>(proto.into_pi_field()?)?;
        Ok(())
    }
}

impl ZCPacketToBytes for TunZCPacketToBytes {
    fn zcpacket_into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, TunnelError> {
        let payload_offset = zc_packet.payload_offset();
        let mut inner = zc_packet.inner();
        // we have peer manager header, so payload offset must larger than 4
        assert!(payload_offset >= 4);

        let ret = if self.has_packet_info {
            inner.advance(payload_offset - 4);
            let proto = infer_proto(&inner[4..]);
            self.fill_packet_info(&mut inner[0..4], proto)?;
            inner
        } else {
            inner.advance(payload_offset);
            inner
        };

        tracing::debug!(?ret, ?payload_offset, "convert zc packet to tun packet");

        Ok(ret.into())
    }
}

pin_project! {
    pub struct TunAsyncWrite {
        #[pin]
        l: BiLock<AsyncDevice>,
    }
}

impl AsyncWrite for TunAsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

pub struct VirtualNic {
    global_ctx: ArcGlobalCtx,

    ifname: Option<String>,
    ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,
}

impl Drop for VirtualNic {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref ifname) = self.ifname {
                // Try to clean up firewall rules, but don't panic in destructor
                if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
                    log::warn!(
                        %error,
                        "failed to remove firewall rules for interface {}",
                        ifname
                    );
                }
            }
        }
    }
}

impl VirtualNic {
    fn interface_adapter(flags: &Flags) -> InterfaceAdapter {
        InterfaceAdapter::from_flags(flags)
    }

    fn needs_tap_edge_adapter(adapter: InterfaceAdapter) -> bool {
        adapter.uses_native_ethernet()
    }

    fn wrap_tun_device(
        dev: tun::platform::Device,
        has_packet_info: bool,
        mtu: usize,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let payload_prefix_len = 0;

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let (stream, writer) =
                crate::instance::darwin_tun::split_device(dev, payload_prefix_len, mtu)?;
            let tunnel = TunnelWrapper::new(
                stream,
                FramedWriter::new_with_converter(writer, TunZCPacketToBytes::new(has_packet_info)),
                None,
            );
            Ok(Box::new(tunnel))
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = mtu;
            let dev = AsyncDevice::new(dev)?;
            let (reader, writer) = BiLock::new(dev);
            let tunnel = TunnelWrapper::new(
                TunStream::new(reader, has_packet_info, payload_prefix_len),
                FramedWriter::new_with_converter_and_max_buffer_count(
                    TunAsyncWrite { l: writer },
                    TunZCPacketToBytes::new(has_packet_info),
                    1,
                ),
                None,
            );
            Ok(Box::new(tunnel))
        }
    }

    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            ifname: None,
            ifcfg: Box::new(IfConfiger {}),
        }
    }

    /// Check and create TUN device node if necessary on Linux systems
    #[cfg(target_os = "linux")]
    async fn ensure_tun_device_node() {
        const TUN_DEV_PATH: &str = "/dev/net/tun";
        const TUN_DIR_PATH: &str = "/dev/net";

        // Check if /dev/net/tun already exists
        if tokio::fs::metadata(TUN_DEV_PATH).await.is_ok() {
            tracing::debug!("TUN device node {} already exists", TUN_DEV_PATH);
            return;
        }

        tracing::info!(
            "TUN device node {} not found, attempting to create",
            TUN_DEV_PATH
        );

        // Check if TUN kernel module is available
        let tun_module_available = tokio::fs::metadata("/proc/net/dev").await.is_ok()
            && (tokio::fs::read_to_string("/proc/modules").await)
                .map(|content| content.contains("tun"))
                .unwrap_or(false);

        if !tun_module_available {
            log::warn!("TUN kernel module may not be available.");
            log::warn!("\tYou may need to load it with: sudo modprobe tun.");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(error) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                log::warn!(
                    ?error,
                    "Failed to create directory {}. TUN device creation may fail. Continuing anyway.",
                    TUN_DIR_PATH
                );
                log::warn!(
                    "\tYou may need to run with root privileges or manually create the TUN device."
                );
                Self::print_troubleshooting_info();
                return;
            }
            tracing::info!("Created directory {}", TUN_DIR_PATH);
        }

        // Try to create the TUN device node
        // Major number 10, minor number 200 for /dev/net/tun
        let dev_node = nix::sys::stat::makedev(10, 200);

        match nix::sys::stat::mknod(
            TUN_DEV_PATH,
            nix::sys::stat::SFlag::S_IFCHR,
            nix::sys::stat::Mode::from_bits(0o600).unwrap(),
            dev_node,
        ) {
            Ok(_) => {
                log::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Failed to create TUN device node {}. Continuing anyway.",
                    TUN_DEV_PATH,
                );
                Self::print_troubleshooting_info();
            }
        }
    }

    /// Print troubleshooting information for TUN device issues
    #[cfg(target_os = "linux")]
    fn print_troubleshooting_info() {
        log::info!(
            "Possible solutions:\
            \n\t1. Run with root privileges: sudo ./lowertier-core [options]\
            \n\t2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200\
            \n\t3. Load TUN kernel module: sudo modprobe tun\
            \n\t4. Use --no-tun flag if TUN functionality is not needed\
            \n\t5. Check if your system/container supports TUN devices\
            \nNote: TUN functionality may still work if the kernel supports dynamic device creation."
        );
    }

    /// For non-Linux systems, this is a no-op
    #[cfg(not(target_os = "linux"))]
    async fn ensure_tun_device_node() -> Result<(), Error> {
        Ok(())
    }

    /// FreeBSD specific: Rename a TUN interface
    #[cfg(target_os = "freebsd")]
    async fn rename_tun_interface(old_name: &str, new_name: &str) -> Result<(), Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg(old_name)
            .arg("name")
            .arg(new_name)
            .output()
            .await?;

        if output.status.success() {
            tracing::info!(
                "Successfully renamed interface {} to {}",
                old_name,
                new_name
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "Failed to rename interface {} to {}: {}",
                old_name,
                new_name,
                stderr
            );
            // Return Ok even if rename fails, as it's not critical
            Ok(())
        }
    }

    /// FreeBSD specific: List all TUN interface names
    #[cfg(target_os = "freebsd")]
    async fn list_tun_names() -> Result<Vec<String>, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-g")
            .arg("tun")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tun_names: Vec<String> = stdout
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            tracing::debug!("Found TUN interfaces: {:?}", tun_names);
            Ok(tun_names)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to list TUN interfaces: {}", stderr);
            Ok(Vec::new())
        }
    }

    /// FreeBSD specific: Get interface information
    #[cfg(target_os = "freebsd")]
    async fn get_interface_info(ifname: &str) -> Result<String, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-v")
            .arg(ifname)
            .output()
            .await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(
                anyhow::anyhow!("Failed to get interface details for {}: {}", ifname, stderr)
                    .into(),
            )
        }
    }

    /// FreeBSD specific: Extract original name from interface information
    #[cfg(target_os = "freebsd")]
    fn extract_original_name(ifinfo: &str) -> Option<String> {
        ifinfo
            .lines()
            .find(|line| line.trim().starts_with("drivername:"))
            .and_then(|line| line.trim().split_whitespace().nth(1))
            .map(|name| name.to_string())
    }

    /// FreeBSD specific: Check if interface is used by any process
    #[cfg(target_os = "freebsd")]
    fn is_interface_used(ifinfo: &str) -> bool {
        ifinfo.contains("Opened by PID")
    }

    /// FreeBSD specific: Restore TUN interface name to its original value
    #[cfg(target_os = "freebsd")]
    async fn restore_tun_name(dev_name: &str) -> Result<(), Error> {
        let tun_names = Self::list_tun_names().await?;

        // Check if desired dev_name is in use
        if tun_names.iter().any(|name| name == dev_name) {
            tracing::debug!(
                "Desired dev_name {} is in TUN interfaces list, checking if it can be renamed",
                dev_name
            );

            let ifinfo = Self::get_interface_info(dev_name).await?;

            // Check if interface is not occupied
            if !Self::is_interface_used(&ifinfo) {
                // Extract original name
                if let Some(orig_name) = Self::extract_original_name(&ifinfo) {
                    if orig_name != dev_name {
                        tracing::info!(
                            "Restoring dev_name {} to original name {}",
                            dev_name,
                            orig_name
                        );
                        // Rename interface
                        Self::rename_tun_interface(dev_name, &orig_name).await?;
                    }
                }
            } else {
                tracing::debug!(
                    "Interface {} is opened by a process, skipping rename",
                    dev_name
                );
            }
        }

        Ok(())
    }

    async fn create_tun(&self) -> Result<tun::platform::Device, Error> {
        let mut config = Configuration::default();
        let flags = self.global_ctx.get_flags();
        let adapter = Self::interface_adapter(&flags);
        if adapter.uses_native_ethernet() {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            config.layer(Layer::L2);

            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            return Err(anyhow::anyhow!(
                "interface_adapter=tap is supported only on Linux and FreeBSD; use interface_adapter=tun"
            )
            .into());
        } else {
            config.layer(Layer::L3);
        }

        // FreeBSD specific: Check and restore TUN interfaces before creating new one
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() {
                // Restore TUN interface name if needed, ignoring errors as it's not critical
                let _ = Self::restore_tun_name(&dev_name).await;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check and create TUN device node if necessary (Linux only)
            Self::ensure_tun_device_node().await;

            let dev_name = self.global_ctx.get_flags().dev_name;
            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            }
        }

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        #[cfg(target_os = "windows")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            match crate::arch::windows::add_self_to_firewall_allowlist() {
                Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
                Err(error) => {
                    log::warn!(%error, "Failed to add LowTier to firewall allowlist, Subnet proxy and KCP proxy may not work properly.");
                    log::warn!(
                        "You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack."
                    );
                }
            }

            match RegistryManager::reg_delete_obsoleted_items(&dev_name) {
                Ok(_) => tracing::trace!("delete successful!"),
                Err(e) => tracing::error!("An error occurred: {}", e),
            }

            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            } else {
                use rand::distributions::Distribution as _;
                let c = crate::arch::windows::interface_count()?;
                let mut rng = rand::thread_rng();
                let s: String = rand::distributions::Alphanumeric
                    .sample_iter(&mut rng)
                    .take(4)
                    .map(char::from)
                    .collect::<String>()
                    .to_lowercase();

                let random_dev_name = format!("et_{}_{}", c, s);
                config.tun_name(random_dev_name.clone());

                let mut flags = self.global_ctx.get_flags();
                flags.dev_name = random_dev_name.clone();
                self.global_ctx.set_flags(flags);
            }

            config.platform_config(|config| {
                config.skip_config(true);
                config.ring_cap(Some(std::cmp::min(
                    config.min_ring_cap() * 32,
                    config.max_ring_cap(),
                )));
            });
        }

        config.up();

        let _g = self.global_ctx.net_ns.guard();
        Ok(tun::create(&config)?)
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let flags = self.global_ctx.get_flags();
        let adapter = Self::interface_adapter(&flags);
        if adapter.uses_native_ethernet() {
            return Err(anyhow::anyhow!(
                "interface_adapter=tap is not supported by mobile virtual NICs"
            )
            .into());
        }
        log::debug!(%tun_fd);
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        #[cfg(any(target_os = "ios", all(target_os = "macos", feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        config.raw_fd(tun_fd);
        config.close_fd_on_drop(false);
        config.up();

        let has_packet_info = cfg!(any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ));
        let dev = tun::create(&config)?;
        let mtu = flags.mtu as usize;
        let ft = Self::wrap_tun_device(dev, has_packet_info, mtu)?;

        self.ifname = Some(format!("tunfd_{}", tun_fd));

        Ok(ft)
    }

    #[cfg(target_os = "linux")]
    async fn create_linux_dev(&mut self, offload: bool) -> Result<Box<dyn Tunnel>, Error> {
        Self::ensure_tun_device_node().await;
        let flags = self.global_ctx.config.get_flags();
        let mut effective_mtu = flags.mtu;
        if flags.enable_encryption {
            effective_mtu -= 20;
        }
        let kernel_mtu = u16::try_from(effective_mtu)
            .map_err(|_| anyhow::anyhow!("TUN MTU {effective_mtu} exceeds Linux u16 limits"))?;

        let native_ethernet = Self::interface_adapter(&flags).uses_native_ethernet();
        let parallelism = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        let requested_queue_count = std::env::var("LOWTIER_TUN_QUEUES")
            .or_else(|_| std::env::var("LOWTIER_TAP_QUEUES"))
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        let queue_count =
            linux_virtual_nic_queue_count(native_ethernet, parallelism, requested_queue_count);
        if queue_count > 1 {
            tracing::info!(
                queue_count,
                native_ethernet,
                offload,
                "Linux virtual NIC uses multiqueue"
            );
        }
        let mut builder = quincy_tun::DeviceBuilder::new()
            .mtu(kernel_mtu)
            .packet_information(false)
            .offload(offload)
            .layer(if native_ethernet {
                quincy_tun::Layer::L2
            } else {
                quincy_tun::Layer::L3
            })
            .queues(queue_count);
        if !flags.dev_name.is_empty() {
            builder = builder.name(flags.dev_name.clone());
        }
        let devices = {
            let _guard = self.global_ctx.net_ns.guard();
            builder.build_async_queues()?
        };
        if offload && devices.iter().any(|device| !device.tcp_gso()) {
            return Err(anyhow::anyhow!(
                "Linux TUN virtio offload was requested but the kernel rejected TSO/GRO"
            )
            .into());
        }

        let ifname = devices
            .first()
            .ok_or_else(|| anyhow::anyhow!("Linux virtual NIC has no queues"))?
            .name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;
        {
            let _guard = self.global_ctx.net_ns.guard();
            self.ifcfg.set_mtu(ifname.as_str(), effective_mtu).await?;
        }
        let tunnel = crate::instance::linux_tun::wrap_devices(
            devices,
            effective_mtu as usize,
            self.global_ctx.dataplane_telemetry().clone(),
            offload,
        );
        self.ifname = Some(ifname);
        Ok(tunnel)
    }

    pub async fn create_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        #[cfg(target_os = "linux")]
        {
            let offload = linux_tun_offload_enabled();
            match self.create_linux_dev(offload).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) if offload => {
                    tracing::warn!(
                        ?error,
                        "Linux TUN offload is unavailable; retrying portable multiqueue"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "portable Linux TUN multiqueue is unavailable; falling back to rust-tun"
                    );
                }
            }
            if offload {
                match self.create_linux_dev(false).await {
                    Ok(tunnel) => return Ok(tunnel),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "portable Linux TUN multiqueue is unavailable; falling back to rust-tun"
                        );
                    }
                }
            }
        }

        let dev = self.create_tun().await?;

        #[cfg(not(target_os = "freebsd"))]
        let ifname = dev.tun_name()?;

        #[cfg(target_os = "freebsd")]
        let mut ifname = dev.tun_name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        // FreeBSD TUN interface rename functionality
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() && dev_name != ifname {
                // Use ifconfig to rename the TUN interface
                if Self::rename_tun_interface(&ifname, &dev_name).await.is_ok() {
                    ifname = dev_name;
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(guid) = RegistryManager::find_interface_guid(&ifname) {
                if let Err(e) = RegistryManager::disable_dynamic_updates(&guid) {
                    tracing::error!(
                        "Failed to disable dhcp for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }

                // Disable NetBIOS over TCP/IP
                if let Err(e) = RegistryManager::disable_netbios(&guid) {
                    tracing::error!(
                        "Failed to disable netbios for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }
            }
        }

        let flags = self.global_ctx.config.get_flags();
        let mut mtu_in_config = flags.mtu;
        if flags.enable_encryption {
            mtu_in_config -= 20;
        }
        {
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.global_ctx.net_ns.guard();
            self.ifcfg.set_mtu(ifname.as_str(), mtu_in_config).await?;
        }

        let has_packet_info = cfg!(all(target_os = "macos", not(feature = "macos-ne")));
        let ft = Self::wrap_tun_device(dev, has_packet_info, mtu_in_config as usize)?;

        self.ifname = Some(ifname.to_owned());

        #[cfg(target_os = "windows")]
        {
            // Add firewall rules for virtual NIC interface to allow all traffic
            match crate::arch::windows::add_interface_to_firewall_allowlist(&ifname) {
                Ok(_) => {
                    tracing::info!(
                        "Successfully configured Windows Firewall for interface: {}",
                        ifname
                    );
                    tracing::info!(
                        "All protocols (TCP/UDP/ICMP) are now allowed on interface: {}",
                        ifname
                    );
                }
                Err(error) => {
                    log::warn!(%error, "Failed to configure Windows Firewall for interface {}\
                    \n\tThis may cause connectivity issues with ping and other network functions.\
                    \n\tPlease run as Administrator or manually configure Windows Firewall.\
                    \n\tAlternatively, you can disable Windows Firewall for testing purposes.", ifname);
                }
            }
        }

        Ok(ft)
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        self.add_ipv6_route_with_cost(address, cidr, None).await
    }

    pub async fn add_ipv6_route_with_cost(
        &self,
        address: Ipv6Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, cost)
            .await?;
        Ok(())
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .remove_ipv6_route(self.ifname(), address, cidr)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ipv6(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub fn get_ifcfg(&self) -> impl IfConfiguerTrait + use<> {
        IfConfiger {}
    }
}

pub struct NicCtx {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Weak<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,

    close_notifier: Arc<Notify>,

    nic: Arc<Mutex<VirtualNic>>,
    tasks: JoinSet<()>,
    multicast_expiry_task_started: bool,
    direct_nic_endpoint: Option<Arc<DirectNicEndpoint>>,

    #[cfg(target_os = "windows")]
    windows_udp_broadcast_relay: Option<AbortOnDropHandle<()>>,
}

impl NicCtx {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
    ) -> Self {
        NicCtx {
            global_ctx: global_ctx.clone(),
            peer_mgr: Arc::downgrade(peer_manager),
            peer_packet_receiver,

            close_notifier,

            nic: Arc::new(Mutex::new(VirtualNic::new(global_ctx))),
            tasks: JoinSet::new(),
            multicast_expiry_task_started: false,
            direct_nic_endpoint: None,

            #[cfg(target_os = "windows")]
            windows_udp_broadcast_relay: None,
        }
    }

    fn start_multicast_membership_expiry_task(&mut self) {
        if self.multicast_expiry_task_started {
            return;
        }
        self.multicast_expiry_task_started = true;
        let global_ctx = self.global_ctx.clone();
        self.tasks.spawn(async move {
            loop {
                let notify = global_ctx.multicast_membership_notify();
                let notified = notify.notified();
                let deadline = global_ctx.multicast_membership_next_expiry();
                tokio::select! {
                    biased;
                    _ = notified => {},
                    _ = async {
                        let Some(deadline) = deadline else {
                            std::future::pending::<()>().await;
                            return;
                        };
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                        global_ctx.expire_multicast_memberships(Instant::now());
                    } => {},
                }
            }
        });
    }

    pub async fn ifname(&self) -> Option<String> {
        let nic = self.nic.lock().await;
        nic.ifname.as_ref().map(|s| s.to_owned())
    }

    pub async fn assign_ipv4_to_tun_device(&self, ipv4_addr: cidr::Ipv4Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ip(None).await?;
        nic.add_ip(ipv4_addr.address(), ipv4_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_route(ipv4_addr.first_address(), ipv4_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_to_tun_device(&self, ipv6_addr: cidr::Ipv6Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ipv6(None).await?;
        nic.add_ipv6(ipv6_addr.address(), ipv6_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
        }
        Ok(())
    }

    async fn do_forward_nic_to_peers(ret: ZCPacket, mgr: &PeerManager, adapter: InterfaceAdapter) {
        let payload_kind = if adapter.uses_native_ethernet() {
            Self::learn_hybrid_multicast_membership(ret.payload(), mgr);
            if Self::handle_hybrid_control_frame(&ret, mgr).await {
                return;
            }
            FabricPayloadKind::Ethernet
        } else {
            Self::learn_hybrid_ip_multicast_membership(ret.payload(), mgr);
            FabricPayloadKind::Ip
        };
        if let Err(error) = mgr
            .send_fabric_packet(FabricPacket::new(payload_kind, ret))
            .await
        {
            tracing::trace!(?error, "[USER_PACKET] send fabric packet failed");
        }
    }

    async fn do_forward_nic_batch_to_peers(
        batch: PacketBatch,
        mgr: &PeerManager,
        adapter: InterfaceAdapter,
    ) {
        if peer_batch_disabled() {
            for packet in batch {
                Self::do_forward_nic_to_peers(packet, mgr, adapter).await;
            }
            return;
        }
        let (payload_kind, batch) = if adapter.uses_native_ethernet() {
            let mut data = PacketBatch::new();
            for packet in batch {
                Self::learn_hybrid_multicast_membership(packet.payload(), mgr);
                if Self::handle_hybrid_control_frame(&packet, mgr).await {
                    continue;
                }
                data.try_push(packet)
                    .expect("a filtered NIC batch cannot exceed its input");
            }
            (FabricPayloadKind::Ethernet, data)
        } else {
            for packet in &batch {
                Self::learn_hybrid_ip_multicast_membership(packet.payload(), mgr);
            }
            (FabricPayloadKind::Ip, batch)
        };
        if let Err(error) = mgr
            .send_fabric_batch(FabricBatch::new(payload_kind, batch))
            .await
        {
            tracing::trace!(?error, "[USER_PACKET] send fabric batch failed");
        }
    }

    async fn handle_hybrid_control_frame(packet: &ZCPacket, mgr: &PeerManager) -> bool {
        let frame = packet.payload();
        let Some(request) = crate::instance::l2_tun::validated_neighbor_request(frame) else {
            return false;
        };
        let peer_id = match request.target() {
            crate::instance::l2_tun::NeighborTarget::Ipv4(target) => {
                let Some(peer_id) = mgr.get_route().get_peer_id_by_ipv4(&target).await else {
                    return false;
                };
                peer_id
            }
            crate::instance::l2_tun::NeighborTarget::Ipv6(target) => {
                let Some(peer_id) = mgr.get_route().get_peer_id_by_ipv6(&target).await else {
                    return false;
                };
                peer_id
            }
        };
        let reply = request.reply(peer_id);
        let mut reply = ZCPacket::new_with_payload(&reply);
        reply.fill_peer_manager_hdr(
            mgr.my_peer_id(),
            mgr.my_peer_id(),
            crate::tunnel::packet_def::PacketType::Ethernet as u8,
        );
        match mgr.inject_packet_to_nic(reply).await {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(?error, "local hybrid neighbor reply failed");
                false
            }
        }
    }

    fn learn_hybrid_multicast_membership(frame: &[u8], mgr: &PeerManager) {
        let updates = crate::instance::l2_tun::multicast_membership_updates_with_reporter(frame);
        Self::apply_hybrid_multicast_membership_updates(updates, mgr);
    }

    fn learn_hybrid_ip_multicast_membership(packet: &[u8], mgr: &PeerManager) {
        let updates =
            crate::instance::l2_tun::multicast_membership_updates_from_ip_with_reporter(packet);
        Self::apply_hybrid_multicast_membership_updates(updates, mgr);
    }

    fn apply_hybrid_multicast_membership_updates(
        updates: Vec<(
            crate::common::global_ctx::MulticastReporterKey,
            std::net::IpAddr,
            bool,
        )>,
        mgr: &PeerManager,
    ) {
        if updates.is_empty() {
            return;
        }
        let global_ctx = mgr.get_global_ctx_ref();
        let now = Instant::now();
        let changed = global_ctx.update_multicast_memberships(&updates, now);
        if changed {
            global_ctx.issue_event(GlobalCtxEvent::MulticastGroupsUpdated);
        }
    }

    fn report_nic_ingress_failure(
        mgr: &PeerManager,
        close_notifier: &Notify,
        cancellation: &CancellationToken,
        reported: &AtomicBool,
        error: Option<&TunnelError>,
    ) {
        if !Self::claim_nic_ingress_failure(reported) {
            cancellation.cancel();
            return;
        }
        if let Some(error) = error {
            mgr.get_global_ctx()
                .set_tun_device_error(format!("TUN read failed: {error}"));
            tracing::error!(?error, "read from nic failed");
        } else {
            mgr.get_global_ctx()
                .set_tun_device_error("TUN input stream closed".to_owned());
            tracing::error!("nic closed when receiving from it");
        }
        cancellation.cancel();
        close_notifier.notify_one();
    }

    fn claim_nic_ingress_failure(reported: &AtomicBool) -> bool {
        !reported.swap(true, Ordering::AcqRel)
    }

    async fn run_nic_ingress_worker(
        mut stream: Pin<Box<dyn PacketBatchStream>>,
        mgr: Arc<PeerManager>,
        adapter: InterfaceAdapter,
        flow_gate: Arc<NicIngressFlowGate>,
        close_notifier: Arc<Notify>,
        cancellation: CancellationToken,
        reported: Arc<AtomicBool>,
    ) {
        let disable_batching = std::env::var_os("LOWTIER_DEBUG_DISABLE_PACKET_BATCH").is_some()
            || std::env::var_os("LOWTIER_DEBUG_DISABLE_NIC_BATCH").is_some();

        if disable_batching {
            loop {
                let Some(result) = (tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => None,
                    result = stream.next() => result,
                }) else {
                    if !cancellation.is_cancelled() {
                        Self::report_nic_ingress_failure(
                            mgr.as_ref(),
                            close_notifier.as_ref(),
                            &cancellation,
                            reported.as_ref(),
                            None,
                        );
                    }
                    return;
                };

                match result {
                    Ok(batch) => {
                        for packet in batch {
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => return,
                                _ = Self::do_forward_nic_to_peers(packet, mgr.as_ref(), adapter) => {}
                            }
                        }
                    }
                    Err(error) => {
                        if !cancellation.is_cancelled() {
                            Self::report_nic_ingress_failure(
                                mgr.as_ref(),
                                close_notifier.as_ref(),
                                &cancellation,
                                reported.as_ref(),
                                Some(&error),
                            );
                        }
                        return;
                    }
                }
            }
        }

        let record_batch_stats = std::env::var_os("LOWTIER_DEBUG_BATCH_STATS").is_some();
        let max_in_flight = RECEIVE_PREFETCH_BATCHES + 1;
        let mut deliveries = JoinSet::new();
        let mut stream_open = true;
        while stream_open || !deliveries.is_empty() {
            if deliveries.len() >= max_in_flight || !stream_open {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return,
                    _ = deliveries.join_next(), if !deliveries.is_empty() => {}
                }
                continue;
            }

            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return,
                result = stream.next() => {
                    let Some(result) = result else {
                        stream_open = false;
                        continue;
                    };
                    let batch = match result {
                        Ok(batch) => batch,
                        Err(error) => {
                            if !cancellation.is_cancelled() {
                                Self::report_nic_ingress_failure(
                                    mgr.as_ref(),
                                    close_notifier.as_ref(),
                                    &cancellation,
                                    reported.as_ref(),
                                    Some(&error),
                                );
                            }
                            return;
                        }
                    };
                    if record_batch_stats {
                        record_nic_batch_size(batch.len());
                    }
                    let permit = flow_gate.reserve_batch(&batch, adapter);
                    let delivery_mgr = mgr.clone();
                    deliveries.spawn(async move {
                        permit.wait().await;
                        let _stage = delivery_mgr
                            .get_global_ctx_ref()
                            .dataplane_telemetry()
                            .sample_stage_with_shape(DataplaneStage::NicIngress, || {
                                (batch.len(), batch.buffer_byte_len())
                            });
                        Self::do_forward_nic_batch_to_peers(
                            batch,
                            delivery_mgr.as_ref(),
                            adapter,
                        )
                        .await;
                    });
                }
                _ = deliveries.join_next(), if !deliveries.is_empty() => {}
            }
        }

        if !cancellation.is_cancelled() {
            Self::report_nic_ingress_failure(
                mgr.as_ref(),
                close_notifier.as_ref(),
                &cancellation,
                reported.as_ref(),
                None,
            );
        }
    }

    fn do_forward_nic_to_peers_task(
        &mut self,
        streams: Vec<Pin<Box<dyn PacketBatchStream>>>,
    ) -> Result<(), Error> {
        let Some(mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        if streams.is_empty() {
            return Err(anyhow::anyhow!("virtual NIC has no ingress queues").into());
        }

        let adapter = VirtualNic::interface_adapter(&self.global_ctx.get_flags());
        let cancellation = CancellationToken::new();
        let reported = Arc::new(AtomicBool::new(false));
        let flow_gate = Arc::new(NicIngressFlowGate::new());
        let close_notifier = self.close_notifier.clone();
        for stream in streams {
            self.tasks.spawn(Self::run_nic_ingress_worker(
                stream,
                mgr.clone(),
                adapter,
                flow_gate.clone(),
                close_notifier.clone(),
                cancellation.clone(),
                reported.clone(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn start_windows_udp_broadcast_relay(&mut self, virtual_ipv4: Ipv4Inet) {
        if !self.global_ctx.get_flags().enable_udp_broadcast_relay {
            return;
        }

        let Some(peer_manager) = self.peer_mgr.upgrade() else {
            tracing::warn!("peer manager is dropped, skip Windows UDP broadcast relay");
            return;
        };

        match super::windows_udp_broadcast::start(peer_manager, virtual_ipv4) {
            Ok(handle) => {
                self.windows_udp_broadcast_relay = Some(handle);
                tracing::info!("Windows UDP broadcast relay started");
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to start Windows UDP broadcast relay; administrator privileges are required"
                );
            }
        }
    }

    async fn apply_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
        added: Vec<cidr::Ipv4Cidr>,
        removed: Vec<cidr::Ipv4Cidr>,
    ) {
        tracing::debug!(?added, ?removed, "applying proxy_cidrs route changes");

        // Remove routes
        for cidr in removed {
            if !cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv4_route(ifname, cidr.first_address(), cidr.network_length())
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "remove route failed.",
                );
            }
            cur_proxy_cidrs.remove(&cidr);
        }

        // Add routes
        for cidr in added {
            if cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv4_route(ifname, cidr.first_address(), cidr.network_length(), None)
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "add route failed.",
                );
            }
            cur_proxy_cidrs.insert(cidr);
        }
    }

    async fn apply_public_ipv6_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_routes: &mut BTreeSet<cidr::Ipv6Inet>,
        added: Vec<cidr::Ipv6Inet>,
        removed: Vec<cidr::Ipv6Inet>,
    ) {
        for route in removed {
            if !cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv6_route(ifname, route.address(), route.network_length())
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "remove public ipv6 route failed");
            }
            cur_routes.remove(&route);
        }

        for route in added {
            if cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv6_route(ifname, route.address(), route.network_length(), None)
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "add public ipv6 route failed");
            } else {
                cur_routes.insert(route);
            }
        }
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::<cidr::Ipv4Cidr>::new();

            // Initial sync: get current proxy_cidrs state and apply routes
            let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                peer_mgr.as_ref(),
                &global_ctx,
                &cur_proxy_cidrs,
            )
            .await;
            Self::apply_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_proxy_cidrs,
                added,
                removed,
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("event bus closed, stopping proxy_cidrs route updater");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "event bus lagged in proxy_cidrs route updater, doing full sync"
                        );
                        event_receiver = event_receiver.resubscribe();
                        // Full sync after lagged to recover consistent state
                        let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_mgr.as_ref(),
                            &global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        GlobalCtxEvent::ProxyCidrsUpdated(added, removed)
                    }
                };

                // Only handle ProxyCidrsUpdated events
                let (added, removed) = match event {
                    GlobalCtxEvent::ProxyCidrsUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_proxy_cidrs,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_routes = BTreeSet::<cidr::Ipv6Inet>::new();
            let initial_routes = peer_mgr.list_public_ipv6_routes().await;
            let initial_added = initial_routes.iter().copied().collect::<Vec<_>>();
            Self::apply_public_ipv6_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_routes,
                initial_added,
                Vec::new(),
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.list_public_ipv6_routes().await;
                        let added = latest.difference(&cur_routes).copied().collect::<Vec<_>>();
                        let removed = cur_routes.difference(&latest).copied().collect::<Vec<_>>();
                        GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed)
                    }
                };

                let (added, removed) = match event {
                    GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_public_ipv6_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_routes,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_addr_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let nic = self.nic.clone();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut current_addr = peer_mgr.get_my_public_ipv6_addr().await;
            if let Some(addr) = current_addr {
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Err(err) = nic.add_ipv6(addr.address(), addr.network_length() as i32).await {
                    tracing::warn!(addr = ?addr, ?err, "failed to add public ipv6 address");
                }
                if let Err(err) = nic
                    .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                    .await
                {
                    tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                }
            }

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.get_my_public_ipv6_addr().await;
                        GlobalCtxEvent::PublicIpv6Changed(current_addr, latest)
                    }
                };

                let (old, new) = match event {
                    GlobalCtxEvent::PublicIpv6Changed(old, new) => (old, new),
                    _ => continue,
                };

                current_addr = new;
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Some(old) = old {
                    if let Err(err) = nic.remove_ipv6_route(Ipv6Addr::UNSPECIFIED, 0).await {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to remove default public ipv6 route");
                    }
                    if let Err(err) = nic.remove_ipv6(Some(old)).await {
                        tracing::warn!(addr = ?old, ?err, "failed to remove old public ipv6 address");
                    }
                }
                if let Some(new) = new {
                    if let Err(err) = nic.add_ipv6(new.address(), new.network_length() as i32).await
                    {
                        tracing::warn!(addr = ?new, ?err, "failed to add public ipv6 address");
                    }
                    if let Err(err) = nic
                        .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                        .await
                    {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn run(
        &mut self,
        ipv4_addr: Option<cidr::Ipv4Inet>,
        ipv6_addr: Option<cidr::Ipv6Inet>,
    ) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev().await {
                Ok(ret) => {
                    #[cfg(target_os = "windows")]
                    {
                        let dev_name = self.global_ctx.get_flags().dev_name;
                        let _ = RegistryManager::reg_change_catrgory_in_profile(&dev_name);
                    }

                    #[cfg(any(
                        all(target_os = "macos", not(feature = "macos-ne")),
                        target_os = "freebsd"
                    ))]
                    {
                        // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
                        let _ = nic
                            .ifcfg
                            .remove_ipv4_route(nic.ifname(), "10.0.0.0".parse().unwrap(), 24)
                            .await;
                    }

                    self.global_ctx
                        .set_tun_device_ready(nic.ifname().to_string());
                    ret
                }
                Err(err) => {
                    self.global_ctx.set_tun_device_error(err.to_string());
                    return Err(err);
                }
            }
        };

        let flags = self.global_ctx.get_flags();
        let adapter = VirtualNic::interface_adapter(&flags);
        let hybrid_tap_mac = if VirtualNic::needs_tap_edge_adapter(adapter) {
            let ifname = self
                .ifname()
                .await
                .ok_or_else(|| anyhow::anyhow!("virtual NIC has no interface name"))?;
            let _guard = self.global_ctx.net_ns.guard();
            Some(interface_mac(&ifname)?)
        } else {
            None
        };
        let (streams, sink) = tunnel.split_ingress_queues();

        let peer_mgr = self
            .peer_mgr
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer manager not available"))?;
        let sink: Pin<Box<dyn PacketBatchSink>> = if let Some(local_mac) = hybrid_tap_mac {
            Box::pin(HybridTapSink {
                inner: sink,
                local_mac,
            })
        } else {
            sink
        };
        self.direct_nic_endpoint = Some(peer_mgr.install_direct_nic_sink(sink));
        self.do_forward_nic_to_peers_task(streams)?;

        // Assign IPv4 address if provided
        if let Some(ipv4_addr) = ipv4_addr {
            self.assign_ipv4_to_tun_device(ipv4_addr).await?;
            #[cfg(target_os = "windows")]
            self.start_windows_udp_broadcast_relay(ipv4_addr);
        }

        // Assign IPv6 address if provided
        if let Some(ipv6_addr) = ipv6_addr {
            self.assign_ipv6_to_tun_device(ipv6_addr).await?;
        }

        self.run_proxy_cidrs_route_updater().await?;
        self.run_public_ipv6_route_updater().await?;
        // Keep the updater running so runtime config patches can enable auto mode
        // without recreating the NIC.
        self.run_public_ipv6_addr_updater().await?;
        self.start_multicast_membership_expiry_task();

        Ok(())
    }

    #[cfg(mobile)]
    pub async fn run_for_mobile(&mut self, tun_fd: std::os::fd::RawFd) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev_for_mobile(tun_fd).await {
                Ok(ret) => {
                    self.global_ctx
                        .set_tun_device_ready(nic.ifname().to_string());
                    ret
                }
                Err(err) => {
                    self.global_ctx.set_tun_device_error(err.to_string());
                    return Err(err);
                }
            }
        };

        let (streams, sink) = tunnel.split_ingress_queues();

        self.do_forward_nic_to_peers_task(streams)?;
        let peer_mgr = self
            .peer_mgr
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer manager not available"))?;
        self.direct_nic_endpoint = Some(peer_mgr.install_direct_nic_sink(sink));
        self.start_multicast_membership_expiry_task();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::common::{
        config::gen_default_flags, error::Error, global_ctx::tests::get_mock_global_ctx,
    };
    use crate::instance::l2_tun::{ETHERNET_HEADER_LEN, prepare_ip_frame};
    use crate::tunnel::{
        TunnelError,
        common::ZCPacketToBytes,
        packet_def::{PacketType, ZCPacket},
    };
    use futures::{StreamExt as _, stream};

    use super::{
        NicCtx, NicIngressFlowGate, TUN_READ_SPARE_BYTES, TunZCPacketToBytes, VirtualNic,
        parse_interface_mac, prepare_tun_read_buffer, read_ready_packet_batch,
        restore_compact_ip_for_tap,
    };

    #[test]
    fn tun_read_buffer_restores_spare_capacity_after_split() {
        let mut buffer = bytes::BytesMut::with_capacity(TUN_READ_SPARE_BYTES);
        buffer.resize(TUN_READ_SPARE_BYTES, 0);
        let _completed = buffer.split();

        prepare_tun_read_buffer(&mut buffer, 96);

        assert_eq!(buffer.len(), 96);
        assert!(buffer.capacity() - buffer.len() >= TUN_READ_SPARE_BYTES);
    }

    #[test]
    fn parses_interface_mac_address() {
        assert_eq!(
            parse_interface_mac("02:45:01:23:45:67"),
            Some([0x02, 0x45, 0x01, 0x23, 0x45, 0x67])
        );
        assert_eq!(parse_interface_mac("missing"), None);
    }

    #[test]
    fn restores_compact_ip_for_a_tap_edge() {
        let local_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let mut packet = ZCPacket::new_with_payload(&[0x45; 20]);
        packet.fill_peer_manager_hdr(9, 7, PacketType::Data as u8);

        restore_compact_ip_for_tap(&mut packet, local_mac).unwrap();

        assert_eq!(&packet.payload()[..6], &local_mac);
        assert_eq!(
            &packet.payload()[6..12],
            &crate::instance::l2_tun::encode_peer_mac(9)
        );
        assert_eq!(&packet.payload()[12..14], &0x0800_u16.to_be_bytes());
        assert_eq!(&packet.payload()[14..], &[0x45; 20]);
    }

    #[test]
    fn keeps_complete_ethernet_for_a_tap_edge() {
        let frame = [0x5a; 42];
        let mut packet = ZCPacket::new_with_payload(&frame);
        packet.fill_peer_manager_hdr(9, 7, PacketType::Ethernet as u8);

        restore_compact_ip_for_tap(&mut packet, [0x02; 6]).unwrap();

        assert_eq!(packet.payload(), frame);
    }

    #[test]
    fn linux_tun_offload_tracks_auto_support_and_explicit_overrides() {
        assert!(super::linux_tun_offload_configured(false, false, true));
        assert!(!super::linux_tun_offload_configured(false, false, false));
        assert!(super::linux_tun_offload_configured(true, false, false));
        assert!(!super::linux_tun_offload_configured(true, true, true));
    }

    #[test]
    fn linux_tun_offload_auto_support_is_conservative_by_arch() {
        assert!(super::linux_tun_offload_auto_supported_for("x86_64"));
        assert!(super::linux_tun_offload_auto_supported_for("aarch64"));
        assert!(!super::linux_tun_offload_auto_supported_for("riscv64"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn virtual_nic_queues_follow_host_parallelism_with_a_fixed_cap() {
        assert_eq!(super::linux_virtual_nic_queue_count(false, 1, None), 1);
        assert_eq!(super::linux_virtual_nic_queue_count(true, 1, None), 1);
        assert_eq!(super::linux_virtual_nic_queue_count(false, 2, None), 2);
        assert_eq!(super::linux_virtual_nic_queue_count(true, 2, None), 2);
        assert_eq!(super::linux_virtual_nic_queue_count(false, 16, None), 4);
        assert_eq!(super::linux_virtual_nic_queue_count(true, 16, None), 4);
        assert_eq!(super::linux_virtual_nic_queue_count(true, 16, Some(1)), 1);
        assert_eq!(super::linux_virtual_nic_queue_count(false, 16, Some(8)), 4);
        assert_eq!(super::linux_virtual_nic_queue_count(true, 3, Some(8)), 3);
    }

    #[tokio::test]
    async fn peer_packet_vector_reaches_the_nic_boundary_intact() {
        let (sender, mut receiver) = crate::peers::create_packet_recv_chan();
        let mut sent = crate::tunnel::batch::PacketBatch::new();
        for value in 1..=4_u8 {
            sent.try_push(ZCPacket::new_with_payload(&[value])).unwrap();
        }
        sender.send_batch(sent).await.unwrap();

        let batch = receiver.recv_batch().await.unwrap();

        assert_eq!(
            batch
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[tokio::test]
    async fn nic_ingress_batch_does_not_wait_for_a_pending_packet() {
        let mut stream =
            stream::iter([Ok(ZCPacket::new_with_payload(b"ready"))]).chain(stream::pending());

        let batch = tokio::time::timeout(
            tokio::time::Duration::from_millis(50),
            read_ready_packet_batch(&mut stream, 64),
        )
        .await
        .expect("batch reader waited for a fill timer")
        .unwrap()
        .unwrap();

        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload(), b"ready");
    }

    #[tokio::test]
    async fn nic_ingress_batch_drains_ready_packets_and_preserves_tail() {
        let mut stream =
            stream::iter((1..=4_u8).map(|value| Ok(ZCPacket::new_with_payload(&[value]))));

        let batch = read_ready_packet_batch(&mut stream, 3)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            batch
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(stream.next().await.unwrap().unwrap().payload(), &[4]);
    }

    #[tokio::test]
    async fn nic_ingress_batch_surfaces_a_ready_read_error() {
        let mut stream = stream::iter([
            Ok(ZCPacket::new_with_payload(b"first")),
            Err(TunnelError::InvalidPacket("bad vector entry".to_owned())),
        ]);

        let error = read_ready_packet_batch(&mut stream, 64).await.unwrap_err();

        assert!(
            matches!(error, TunnelError::InvalidPacket(message) if message == "bad vector entry")
        );
    }

    #[tokio::test]
    async fn nic_ingress_gate_serializes_one_flow() {
        let gate = Arc::new(NicIngressFlowGate::new());
        let first = gate.reserve_shards([7]);
        first.wait().await;
        let second = gate.reserve_shards([7]);

        assert!(
            tokio::time::timeout(tokio::time::Duration::from_millis(20), second.wait())
                .await
                .is_err()
        );

        drop(first);
        tokio::time::timeout(tokio::time::Duration::from_millis(100), second.wait())
            .await
            .expect("the next same-flow batch did not start");
    }

    #[tokio::test]
    async fn nic_ingress_gate_allows_independent_flows() {
        let gate = Arc::new(NicIngressFlowGate::new());
        let first = gate.reserve_shards([7]);
        first.wait().await;
        let independent = gate.reserve_shards([8]);

        tokio::time::timeout(tokio::time::Duration::from_millis(100), independent.wait())
            .await
            .expect("an independent flow did not start");
    }

    #[tokio::test]
    async fn nic_ingress_gate_skips_a_cancelled_reservation() {
        let gate = Arc::new(NicIngressFlowGate::new());
        let first = gate.reserve_shards([7]);
        first.wait().await;
        let cancelled = gate.reserve_shards([7]);
        let third = gate.reserve_shards([7]);

        drop(cancelled);
        drop(first);
        tokio::time::timeout(tokio::time::Duration::from_millis(100), third.wait())
            .await
            .expect("a cancelled reservation blocked its flow");
    }

    #[test]
    fn tap_adapter_selects_ethernet_frames() {
        let mut flags = gen_default_flags();
        flags.interface_adapter = "tap".to_string();

        let adapter = VirtualNic::interface_adapter(&flags);
        assert!(adapter.uses_ethernet_overlay());
        assert!(VirtualNic::needs_tap_edge_adapter(adapter));
    }

    #[test]
    fn tun_adapter_keeps_ip_packet_forwarding() {
        let mut flags = gen_default_flags();
        flags.interface_adapter = "tun".to_string();

        let adapter = VirtualNic::interface_adapter(&flags);
        assert!(!adapter.uses_ethernet_overlay());
        assert!(!VirtualNic::needs_tap_edge_adapter(adapter));
    }

    #[test]
    fn compatible_ethernet_maps_to_the_tun_adapter() {
        let mut flags = gen_default_flags();
        flags.port_mode = "compatible-ethernet".to_string();

        let adapter = VirtualNic::interface_adapter(&flags);
        assert!(!adapter.uses_ethernet_overlay());
        assert!(!adapter.uses_native_ethernet());
    }

    #[test]
    fn tap_writer_keeps_the_complete_ethernet_frame() {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 20];
        frame[ETHERNET_HEADER_LEN] = 0x45;
        prepare_ip_frame(&mut frame, 1, Some(2)).unwrap();
        let packet = ZCPacket::new_with_payload(&frame);

        let bytes = TunZCPacketToBytes::new(false)
            .zcpacket_into_bytes(packet)
            .unwrap();

        assert_eq!(bytes.as_ref(), frame.as_slice());
    }

    #[test]
    fn nic_ingress_failure_is_claimed_once() {
        let claimed = AtomicBool::new(false);
        assert!(NicCtx::claim_nic_ingress_failure(&claimed));
        assert!(!NicCtx::claim_nic_ingress_failure(&claimed));
    }

    async fn run_test_helper() -> Result<VirtualNic, Error> {
        let mut dev = VirtualNic::new(get_mock_global_ctx());
        let _tunnel = dev.create_dev().await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        dev.link_up().await?;
        dev.remove_ip(None).await?;
        dev.add_ip("10.144.111.1".parse().unwrap(), 24).await?;
        Ok(dev)
    }

    #[tokio::test]
    #[ignore = "requires privileged TUN access"]
    async fn tun_test() {
        let _dev = run_test_helper().await.unwrap();

        // let mut stream = nic.pin_recv_stream();
        // while let Some(item) = stream.next().await {
        //     println!("item: {:?}", item);
        // }

        // let framed = dev.into_framed();
        // let (mut s, mut b) = framed.split();
        // loop {
        //     let tmp = b.next().await.unwrap().unwrap();
        //     let tmp = EthernetPacket::new(tmp.get_bytes());
        //     println!("ret: {:?}", tmp.unwrap());
        // }
    }
}
