use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use crate::{
    common::{
        config::{Flags, PortMode},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        ifcfg::{IfConfiger, IfConfiguerTrait},
        log,
    },
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{
        PacketRecvChanReceiver,
        peer_manager::{DirectNicEndpoint, PeerManager},
        recv_packet_batch_from_chan,
    },
    tunnel::{
        PacketBatchSink, PacketBatchStream, StreamItem, Tunnel, TunnelError,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch, wait_for_delivery_with_one_prefetch},
        common::{FramedWriter, TunnelWrapper, ZCPacketToBytes, reserve_buf},
        packet_def::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
    },
};

use byteorder::WriteBytesExt as _;
use bytes::{Buf, BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{FutureExt, SinkExt, Stream, StreamExt, lock::BiLock, ready};
use pin_project_lite::pin_project;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
#[cfg(target_os = "windows")]
use tokio_util::task::AbortOnDropHandle;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use zerocopy::{NativeEndian, NetworkEndian};

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;

const NIC_PACKET_BATCH_SIZE: usize = MAX_PACKET_BATCH_SIZE;
static NIC_BATCH_COUNT: AtomicU64 = AtomicU64::new(0);
static NIC_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
static NIC_MAX_BATCH: AtomicUsize = AtomicUsize::new(0);
static PEER_BATCH_DISABLED: OnceLock<bool> = OnceLock::new();

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
        std::env::var_os("LOWTIER_DEBUG_DISABLE_TUN_OFFLOAD").is_some(),
        linux_vector_checksum_available(),
    )
}

#[cfg(target_os = "linux")]
const fn linux_vector_checksum_available() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

#[cfg(target_os = "linux")]
fn linux_tun_offload_configured(
    explicitly_enabled: bool,
    explicitly_disabled: bool,
    vector_checksum_available: bool,
) -> bool {
    !explicitly_disabled && (explicitly_enabled || vector_checksum_available)
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

impl Stream for TunStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        reserve_buf(self_mut.cur_buf, 2500, 4 * 1024);
        if self_mut.cur_buf.is_empty() {
            unsafe {
                self_mut
                    .cur_buf
                    .set_len(*self_mut.payload_offset + *self_mut.payload_prefix_len);
            }
        }
        let buf = self_mut.cur_buf.chunk_mut().as_mut_ptr();
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, 2500) };
        let mut buf = ReadBuf::new(buf);

        let ret = ready!(g.as_pin_mut().poll_read(cx, &mut buf));
        let len = buf.filled().len();
        if len == 0 {
            return Poll::Ready(None);
        }
        unsafe { self_mut.cur_buf.advance_mut(len + TAIL_RESERVED_SIZE) };

        let mut ret_buf = self_mut.cur_buf.split();
        let cur_len = ret_buf.len();
        ret_buf.truncate(cur_len - TAIL_RESERVED_SIZE);

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
    l2_tun: bool,
}

impl TunZCPacketToBytes {
    pub fn new(has_packet_info: bool, l2_tun: bool) -> Self {
        Self {
            has_packet_info,
            l2_tun,
        }
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

        let l2_prefix_len = if self.l2_tun {
            crate::instance::l2_tun::decapsulate_ip(&inner[payload_offset..])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            crate::instance::l2_tun::ETHERNET_HEADER_LEN
        } else {
            0
        };
        let ret = if self.has_packet_info {
            inner.advance(payload_offset + l2_prefix_len - 4);
            let proto = infer_proto(&inner[4..]);
            self.fill_packet_info(&mut inner[0..4], proto)?;
            inner
        } else {
            inner.advance(payload_offset + l2_prefix_len);
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
    fn uses_ethernet_frames(flags: &Flags) -> bool {
        flags
            .port_mode
            .parse::<PortMode>()
            .map(PortMode::uses_ethernet_overlay)
            .unwrap_or(false)
    }

    fn uses_native_ethernet_frames(flags: &Flags) -> bool {
        flags
            .port_mode
            .parse::<PortMode>()
            .map(PortMode::uses_native_ethernet)
            .unwrap_or(false)
    }

    fn uses_l2_tun(flags: &Flags) -> bool {
        matches!(flags.port_mode.parse::<PortMode>(), Ok(PortMode::L2Tun))
    }

    fn wrap_tun_device(
        dev: tun::platform::Device,
        has_packet_info: bool,
        l2_tun: bool,
        mtu: usize,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let payload_prefix_len = if l2_tun {
            crate::instance::l2_tun::ETHERNET_HEADER_LEN
        } else {
            0
        };

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let (stream, writer) =
                crate::instance::darwin_tun::split_device(dev, payload_prefix_len, mtu)?;
            let tunnel = TunnelWrapper::new(
                stream,
                FramedWriter::new_with_converter(
                    writer,
                    TunZCPacketToBytes::new(has_packet_info, l2_tun),
                ),
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
                    TunZCPacketToBytes::new(has_packet_info, l2_tun),
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
        if Self::uses_native_ethernet_frames(&flags) {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            config.layer(Layer::L2);

            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            return Err(anyhow::anyhow!(
                "port_mode=tap is supported only on Linux and FreeBSD; use port_mode=l3"
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
        if Self::uses_native_ethernet_frames(&self.global_ctx.get_flags()) {
            return Err(
                anyhow::anyhow!("port_mode=tap is not supported by mobile virtual NICs").into(),
            );
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
        let l2_tun = Self::uses_l2_tun(&self.global_ctx.get_flags());
        let mtu = self.global_ctx.get_flags().mtu as usize;
        let ft = Self::wrap_tun_device(dev, has_packet_info, l2_tun, mtu)?;

        self.ifname = Some(format!("tunfd_{}", tun_fd));

        Ok(ft)
    }

    #[cfg(target_os = "linux")]
    async fn create_linux_offload_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        Self::ensure_tun_device_node().await;
        let flags = self.global_ctx.config.get_flags();
        let mut effective_mtu = flags.mtu;
        if flags.enable_encryption {
            effective_mtu -= 20;
        }
        let kernel_mtu = u16::try_from(effective_mtu)
            .map_err(|_| anyhow::anyhow!("TUN MTU {effective_mtu} exceeds Linux u16 limits"))?;

        let native_ethernet = Self::uses_native_ethernet_frames(&flags);
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
                "Linux virtual NIC uses multiqueue"
            );
        }
        let mut builder = quincy_tun::DeviceBuilder::new()
            .mtu(kernel_mtu)
            .packet_information(false)
            .offload(true)
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
        if devices.iter().any(|device| !device.tcp_gso()) {
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
        let l2_tun = Self::uses_l2_tun(&flags);
        let tunnel =
            crate::instance::linux_tun::wrap_devices(devices, l2_tun, effective_mtu as usize);
        self.ifname = Some(ifname);
        Ok(tunnel)
    }

    pub async fn create_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        #[cfg(target_os = "linux")]
        if linux_tun_offload_enabled() {
            match self.create_linux_offload_dev().await {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "Linux TUN offload is unavailable; falling back to the portable TUN backend"
                    );
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
        let l2_tun = Self::uses_l2_tun(&flags);
        let ft = Self::wrap_tun_device(dev, has_packet_info, l2_tun, mtu_in_config as usize)?;

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
            direct_nic_endpoint: None,

            #[cfg(target_os = "windows")]
            windows_udp_broadcast_relay: None,
        }
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

    async fn do_forward_nic_to_peers_ipv4(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv4) = Ipv4Packet::new(ret.payload()) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
                return;
            }
            let dst_ipv4 = ipv4.get_destination();
            let src_ipv4 = ipv4.get_source();
            let my_ipv4 = mgr.get_global_ctx().get_ipv4().map(|x| x.address());
            tracing::trace!(
                ?ret,
                ?src_ipv4,
                ?dst_ipv4,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // Subnet A is proxied as 10.0.0.0/24, and Subnet B is also proxied as 10.0.0.0/24.
            //
            // Subnet A has received a route advertised by Subnet B. As a result, A can reach
            // the physical subnet 10.0.0.0/24 directly and has also added a virtual route for
            // the same subnet 10.0.0.0/24. However, the physical route has a higher priority
            // (lower metric) than the virtual one.
            //
            // When A sends a UDP packet to a non-existent IP within this subnet, the packet
            // cannot be delivered on the physical network and is instead routed to the virtual
            // network interface.
            //
            // The virtual interface receives the packet and forwards it to itself, which triggers
            // the subnet proxy logic. The subnet proxy then attempts to send another packet to
            // the same destination address, causing the same process to repeat and creating an
            // infinite loop. Therefore, we must avoid re-sending packets back to ourselves
            // when the subnet proxy itself is the originator of the packet.
            //
            // However, there is a special scenario to consider: when A acts as a gateway,
            // packets from devices behind A may be forwarded by the OS to the ET (e.g., an
            // eBPF or tunneling component), which happens to proxy the subnet. In this case,
            // the packet’s source IP is not A’s own IP, and we must allow such packets to be
            // sent to the virtual interface (i.e., "sent to ourselves") to maintain correct
            // forwarding behavior. Thus, loop prevention should only apply when the source IP
            // belongs to the local host.
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V4(dst_ipv4), Some(src_ipv4) == my_ipv4)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    async fn do_forward_nic_to_peers_ipv6(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv6) = Ipv6Packet::new(ret.payload()) {
            if ipv6.get_version() != 6 {
                tracing::info!("[USER_PACKET] not ipv6 packet: {:?}", ipv6);
                return;
            }
            let src_ipv6 = ipv6.get_source();
            let dst_ipv6 = ipv6.get_destination();
            let is_local_src = mgr.get_global_ctx().is_ip_local_ipv6(&src_ipv6);
            tracing::trace!(
                ?ret,
                ?src_ipv6,
                ?dst_ipv6,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            if src_ipv6.is_unicast_link_local() && !is_local_src {
                // do not route link local packet to other nodes unless the address is assigned by user
                return;
            }

            // TODO: use zero-copy
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V6(dst_ipv6), is_local_src)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv6 packet");
        }
    }

    async fn do_forward_l2_tun_to_peers(ret: ZCPacket, mgr: &PeerManager) {
        let Some(ip_packet) = ret
            .payload()
            .get(crate::instance::l2_tun::ETHERNET_HEADER_LEN..)
        else {
            tracing::warn!(
                ?ret,
                "[USER_PACKET] compatible Ethernet packet is too short"
            );
            return;
        };
        let Some(version) = ip_packet.first().map(|byte| byte >> 4) else {
            return;
        };
        let (destination, local_source) = match version {
            4 => {
                let Some(ipv4) = Ipv4Packet::new(ip_packet) else {
                    tracing::warn!(
                        ?ret,
                        "[USER_PACKET] invalid compatible Ethernet IPv4 packet"
                    );
                    return;
                };
                let source = ipv4.get_source();
                (
                    IpAddr::V4(ipv4.get_destination()),
                    mgr.get_global_ctx().get_ipv4().map(|ip| ip.address()) == Some(source),
                )
            }
            6 => {
                let Some(ipv6) = Ipv6Packet::new(ip_packet) else {
                    tracing::warn!(
                        ?ret,
                        "[USER_PACKET] invalid compatible Ethernet IPv6 packet"
                    );
                    return;
                };
                let source = ipv6.get_source();
                (
                    IpAddr::V6(ipv6.get_destination()),
                    mgr.get_global_ctx().is_ip_local_ipv6(&source),
                )
            }
            _ => {
                tracing::warn!(
                    version,
                    "[USER_PACKET] unsupported compatible Ethernet IP version"
                );
                return;
            }
        };

        if let Err(error) = mgr.send_msg_by_l2_tun(ret, destination, local_source).await {
            tracing::trace!(
                ?error,
                "[USER_PACKET] send compatible Ethernet frame failed"
            );
        }
    }

    async fn do_forward_nic_to_peers(ret: ZCPacket, mgr: &PeerManager) {
        let flags = mgr.get_global_ctx().get_flags();
        if VirtualNic::uses_native_ethernet_frames(&flags) {
            let send_ret = mgr.send_msg_by_ethernet(ret).await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send ethernet frame failed");
            }
            return;
        }
        if VirtualNic::uses_l2_tun(&flags) {
            Self::do_forward_l2_tun_to_peers(ret, mgr).await;
            return;
        }

        let payload = ret.payload();
        if payload.is_empty() {
            return;
        }

        match payload[0] >> 4 {
            4 => Self::do_forward_nic_to_peers_ipv4(ret, mgr).await,
            6 => Self::do_forward_nic_to_peers_ipv6(ret, mgr).await,
            _ => {
                tracing::warn!(?ret, "[USER_PACKET] unknown IP version");
            }
        }
    }

    async fn do_forward_nic_batch_to_peers(batch: PacketBatch, mgr: &PeerManager) {
        if peer_batch_disabled() {
            for packet in batch {
                Self::do_forward_nic_to_peers(packet, mgr).await;
            }
            return;
        }
        let flags = mgr.get_global_ctx().get_flags();
        if VirtualNic::uses_native_ethernet_frames(&flags) {
            match batch.pop_singleton() {
                Ok(packet) => {
                    if let Err(error) = mgr.send_msg_by_ethernet(packet).await {
                        tracing::trace!(?error, "[USER_PACKET] send ethernet packet failed");
                    }
                }
                Err(batch) => {
                    if let Err(error) = mgr.send_msg_by_ethernet_batch(batch).await {
                        tracing::trace!(?error, "[USER_PACKET] send ethernet batch failed");
                    }
                }
            }
            return;
        }
        if VirtualNic::uses_l2_tun(&flags) {
            match batch.pop_singleton() {
                Ok(packet) => Self::do_forward_nic_to_peers(packet, mgr).await,
                Err(batch) => {
                    if let Err(error) = mgr.send_msg_by_l2_tun_batch(batch).await {
                        tracing::trace!(
                            ?error,
                            "[USER_PACKET] send compatible Ethernet batch failed"
                        );
                    }
                }
            }
            return;
        }

        if let Err(error) = mgr.send_msg_by_ip_batch(batch).await {
            tracing::trace!(?error, "[USER_PACKET] send routed IP batch failed");
        }
    }

    fn do_forward_nic_to_peers_task(
        &mut self,
        mut stream: Pin<Box<dyn PacketBatchStream>>,
    ) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let Some(mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            if std::env::var_os("LOWTIER_DEBUG_DISABLE_PACKET_BATCH").is_some()
                || std::env::var_os("LOWTIER_DEBUG_DISABLE_NIC_BATCH").is_some()
            {
                while let Some(result) = stream.next().await {
                    match result {
                        Ok(batch) => {
                            for packet in batch {
                                Self::do_forward_nic_to_peers(packet, mgr.as_ref()).await;
                            }
                        }
                        Err(error) => {
                            tracing::error!(?error, "read from nic failed");
                            break;
                        }
                    }
                }
                close_notifier.notify_one();
                tracing::error!("nic closed when recving from it");
                return;
            }
            let record_batch_stats = std::env::var_os("LOWTIER_DEBUG_BATCH_STATS").is_some();
            let mut pending = stream.next().await;
            while let Some(result) = pending {
                let batch = match result {
                    Ok(batch) => batch,
                    Err(error) => {
                        mgr.get_global_ctx()
                            .set_tun_device_error(format!("TUN read failed: {error}"));
                        tracing::error!(?error, "read from nic failed");
                        break;
                    }
                };
                if record_batch_stats {
                    record_nic_batch_size(batch.len());
                }
                let (_, prefetched) = wait_for_delivery_with_one_prefetch(&mut stream, async {
                    Self::do_forward_nic_batch_to_peers(batch, mgr.as_ref()).await;
                    Ok::<(), ()>(())
                })
                .await;
                pending = match prefetched {
                    Some(next) => next,
                    None => stream.next().await,
                };
            }
            mgr.get_global_ctx()
                .set_tun_device_error("TUN input stream closed".to_owned());
            close_notifier.notify_one();
            tracing::error!("nic closed when recving from it");
        });

        Ok(())
    }

    async fn l2_tun_packet_is_deliverable(packet: &ZCPacket, mgr: &PeerManager) -> bool {
        let payload = packet.payload();
        let Some(ether_type) = payload.get(12..14) else {
            return false;
        };
        match ether_type {
            [0x08, 0x00] | [0x86, 0xdd] => true,
            [0x08, 0x06] => {
                let Some(local_ipv4) = mgr.get_global_ctx().get_ipv4().map(|ip| ip.address())
                else {
                    return false;
                };
                let Some(reply) = crate::instance::l2_tun::arp_reply_for_local_ipv4(
                    payload,
                    mgr.my_peer_id(),
                    local_ipv4,
                ) else {
                    return false;
                };
                let from_peer_id = packet
                    .peer_manager_header()
                    .map(|header| header.from_peer_id.get())
                    .unwrap_or_default();
                if from_peer_id == 0 {
                    return false;
                }
                if let Err(error) = mgr
                    .send_ethernet_to_peer(ZCPacket::new_with_payload(&reply), from_peer_id)
                    .await
                {
                    tracing::debug!(
                        ?error,
                        from_peer_id,
                        "failed to send compatible Ethernet proxy ARP reply"
                    );
                }
                false
            }
            _ => false,
        }
    }

    fn do_forward_peers_to_nic(&mut self, mut sink: Pin<Box<dyn PacketBatchSink>>) {
        let channel = self.peer_packet_receiver.clone();
        let close_notifier = self.close_notifier.clone();
        let l2_tun = VirtualNic::uses_l2_tun(&self.global_ctx.get_flags());
        let peer_mgr = self.peer_mgr.upgrade();
        self.tasks.spawn(async move {
            // unlock until coroutine finished
            let mut channel = channel.lock().await;
            while let Ok(batch) = recv_packet_batch_from_chan(&mut channel).await {
                if !l2_tun {
                    if let Err(error) = sink.send(batch).await {
                        tracing::error!(?error, "send native Ethernet batch to NIC failed");
                    }
                    continue;
                }

                let mut deliverable = PacketBatch::new();
                for packet in batch {
                    tracing::trace!(
                        "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                        packet
                    );
                    if l2_tun {
                        let Some(mgr) = peer_mgr.as_deref() else {
                            tracing::debug!(
                                "peer manager unavailable for compatible Ethernet ingress"
                            );
                            continue;
                        };
                        if !Self::l2_tun_packet_is_deliverable(&packet, mgr).await {
                            continue;
                        }
                    }
                    deliverable
                        .try_push(packet)
                        .expect("the compatible Ethernet output cannot exceed its input");
                }
                if !deliverable.is_empty()
                    && let Err(error) = sink.send(deliverable).await
                {
                    tracing::error!(?error, "send compatible Ethernet batch to NIC failed");
                }
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when sending to it");
        });
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

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        if !VirtualNic::uses_l2_tun(&self.global_ctx.get_flags()) {
            let peer_mgr = self
                .peer_mgr
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("peer manager not available"))?;
            self.direct_nic_endpoint = Some(peer_mgr.install_direct_nic_sink(sink));
        } else {
            self.do_forward_peers_to_nic(sink);
        }

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

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        if !VirtualNic::uses_l2_tun(&self.global_ctx.get_flags()) {
            let peer_mgr = self
                .peer_mgr
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("peer manager not available"))?;
            self.direct_nic_endpoint = Some(peer_mgr.install_direct_nic_sink(sink));
        } else {
            self.do_forward_peers_to_nic(sink);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{
        config::gen_default_flags, error::Error, global_ctx::tests::get_mock_global_ctx,
    };
    use crate::instance::l2_tun::{ETHERNET_HEADER_LEN, prepare_ip_frame};
    use crate::tunnel::{TunnelError, common::ZCPacketToBytes, packet_def::ZCPacket};
    use futures::{StreamExt as _, stream};

    use super::{TunZCPacketToBytes, VirtualNic, read_ready_packet_batch};

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_offload_tracks_checksum_acceleration_and_explicit_overrides() {
        assert!(super::linux_tun_offload_configured(false, false, true));
        assert!(!super::linux_tun_offload_configured(false, false, false));
        assert!(super::linux_tun_offload_configured(true, false, false));
        assert!(!super::linux_tun_offload_configured(true, true, true));
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn linux_tun_offload_uses_neon_by_default() {
        assert!(super::linux_vector_checksum_available());
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

    #[test]
    fn tap_port_mode_selects_ethernet_frames() {
        let mut flags = gen_default_flags();
        flags.port_mode = "ethernet".to_string();

        assert!(VirtualNic::uses_ethernet_frames(&flags));
    }

    #[test]
    fn l3_port_mode_keeps_ip_packet_forwarding() {
        let mut flags = gen_default_flags();
        flags.port_mode = "routed".to_string();

        assert!(!VirtualNic::uses_ethernet_frames(&flags));
    }

    #[test]
    fn l2_tun_uses_ethernet_overlay_on_a_layer_three_device() {
        let mut flags = gen_default_flags();
        flags.port_mode = "compatible-ethernet".to_string();

        assert!(VirtualNic::uses_ethernet_frames(&flags));
        assert!(!VirtualNic::uses_native_ethernet_frames(&flags));
    }

    #[test]
    fn l2_tun_writer_removes_ethernet_header_before_tun_delivery() {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 20];
        frame[ETHERNET_HEADER_LEN] = 0x45;
        prepare_ip_frame(&mut frame, 1, Some(2)).unwrap();
        let packet = ZCPacket::new_with_payload(&frame);

        let bytes = TunZCPacketToBytes::new(false, true)
            .zcpacket_into_bytes(packet)
            .unwrap();

        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0] >> 4, 4);
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
