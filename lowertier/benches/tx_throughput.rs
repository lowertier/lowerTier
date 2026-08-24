use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use lowertier::{
    common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
    instance::instance::Instance,
    peers::{
        PeerPacketFilter,
        fabric::{FabricBatch, FabricPacket, FabricPayloadKind},
    },
    tunnel::{
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::ZCPacket,
        ring::RingTunnelConnector,
        tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector,
    },
};

const VIRTUAL_IP_A: &str = "10.144.144.1";
const VIRTUAL_IP_B: &str = "10.144.144.2";
const DEFAULT_DOCKER_SUBNET: &str = "172.31.250.0/24";
const DEFAULT_DOCKER_IP_A: &str = "172.31.250.2";
const DEFAULT_DOCKER_IP_B: &str = "172.31.250.3";
const DEFAULT_TUNNEL_PORT: u16 = 35521;
const MAX_PREPARED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREPARED_PACKETS: usize = 4096;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
enum TunnelKind {
    Ring,
    Tcp,
    Udp,
}

impl TunnelKind {
    fn as_str(self) -> &'static str {
        match self {
            TunnelKind::Ring => "ring",
            TunnelKind::Tcp => "tcp",
            TunnelKind::Udp => "udp",
        }
    }
}

impl FromStr for TunnelKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ring" => Ok(TunnelKind::Ring),
            "tcp" => Ok(TunnelKind::Tcp),
            "udp" => Ok(TunnelKind::Udp),
            other => Err(format!(
                "unsupported TX_THROUGHPUT_TUNNEL={other:?}; expected ring, tcp, or udp"
            )),
        }
    }
}

struct BenchTopology {
    _docker: Option<DockerNetns>,
    inst_a: Instance,
    _inst_b: Instance,
    packet: ZCPacket,
    completion: CompletionTracker,
}

#[derive(Clone)]
struct CompletionTracker {
    completed: Arc<AtomicU64>,
    notify: Arc<tokio::sync::Notify>,
}

impl CompletionTracker {
    fn new() -> Self {
        Self {
            completed: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn target_after(&self, packet_count: usize) -> u64 {
        self.completed
            .load(Ordering::Acquire)
            .checked_add(packet_count as u64)
            .expect("the receiver completion count does not overflow")
    }

    async fn wait_for(&self, target: u64) {
        loop {
            if self.completed.load(Ordering::Acquire) >= target {
                return;
            }
            self.notify.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for CompletionTracker {
    fn is_interested_in_packet_from_peer(&self, packet: &ZCPacket) -> bool {
        is_benchmark_packet(packet)
    }

    async fn try_process_batch_from_peer(&self, batch: PacketBatch) -> PacketBatch {
        let mut completed = 0_u64;
        let mut remaining = PacketBatch::new();
        for packet in batch {
            if is_benchmark_packet(&packet) {
                completed += 1;
            } else {
                remaining
                    .try_push(packet)
                    .expect("the retained batch cannot exceed its input batch");
            }
        }
        if completed != 0 {
            self.completed.fetch_add(completed, Ordering::Release);
            self.notify.notify_one();
        }
        remaining
    }
}

struct DockerNetns {
    network: String,
    container_a: String,
    container_b: String,
    netns_a: String,
    netns_b: String,
    ip_a: String,
    netns_a_path: PathBuf,
    netns_b_path: PathBuf,
}

impl DockerNetns {
    fn create() -> Self {
        let id = unique_id();
        let image = env_string("TX_THROUGHPUT_DOCKER_IMAGE", "busybox:latest");
        let network = env_string("TX_THROUGHPUT_DOCKER_NET", &format!("lowertier-bench-{id}"));
        let subnet = env_string("TX_THROUGHPUT_DOCKER_SUBNET", DEFAULT_DOCKER_SUBNET);
        let ip_a = env_string("TX_THROUGHPUT_DOCKER_IP_A", DEFAULT_DOCKER_IP_A);
        let ip_b = env_string("TX_THROUGHPUT_DOCKER_IP_B", DEFAULT_DOCKER_IP_B);
        let container_a = format!("lowertier-bench-a-{id}");
        let container_b = format!("lowertier-bench-b-{id}");
        let netns_a = format!("lowertier-bench-a-{id}");
        let netns_b = format!("lowertier-bench-b-{id}");

        docker(&[
            "network", "create", "--driver", "bridge", "--subnet", &subnet, &network,
        ]);

        let mut docker_netns = Self {
            network,
            container_a,
            container_b,
            netns_a,
            netns_b,
            ip_a: ip_a.clone(),
            netns_a_path: PathBuf::new(),
            netns_b_path: PathBuf::new(),
        };

        docker_netns.start_container(&docker_netns.container_a, &ip_a, &image);
        docker_netns.start_container(&docker_netns.container_b, &ip_b, &image);

        let pid_a = docker(&["inspect", "-f", "{{.State.Pid}}", &docker_netns.container_a]);
        let pid_b = docker(&["inspect", "-f", "{{.State.Pid}}", &docker_netns.container_b]);

        docker_netns.netns_a_path = register_netns(&docker_netns.netns_a, &pid_a);
        docker_netns.netns_b_path = register_netns(&docker_netns.netns_b, &pid_b);
        docker_netns
    }

    fn start_container(&self, name: &str, ip: &str, image: &str) {
        docker(&[
            "run",
            "-d",
            "--name",
            name,
            "--network",
            &self.network,
            "--ip",
            ip,
            image,
            "sleep",
            "3600",
        ]);
    }
}

impl Drop for DockerNetns {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.netns_a_path);
        let _ = std::fs::remove_file(&self.netns_b_path);
        docker_ignore(&["rm", "-f", &self.container_a, &self.container_b]);
        docker_ignore(&["network", "rm", &self.network]);
    }
}

fn bench_tx_throughput(c: &mut Criterion) {
    let tunnel = env_string("TX_THROUGHPUT_TUNNEL", "ring")
        .parse::<TunnelKind>()
        .unwrap_or_else(|err| panic!("{err}"));
    let packet_size = env_parse("TX_THROUGHPUT_PKT_SIZE", 1400usize);
    const MIN_PKT_SIZE: usize = 28; // IPv4 (20) + UDP (8) header
    assert!(
        packet_size >= MIN_PKT_SIZE,
        "TX_THROUGHPUT_PKT_SIZE={packet_size} is smaller than the minimum {MIN_PKT_SIZE} (IPv4+UDP headers)"
    );
    assert!(
        packet_size <= usize::from(u16::MAX),
        "TX_THROUGHPUT_PKT_SIZE={packet_size} exceeds the IPv4 total-length limit"
    );
    let worker_threads = env_parse("TX_THROUGHPUT_WORKER_THREADS", 4usize);
    let inflight_depth = env_parse("TX_THROUGHPUT_INFLIGHT", 64usize).max(1);
    let batch_size = env_parse("TX_THROUGHPUT_BATCH_SIZE", MAX_PACKET_BATCH_SIZE)
        .clamp(1, MAX_PACKET_BATCH_SIZE);
    let preparation_limit = prepared_packet_limit(packet_size);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("create tokio runtime");

    let topology = runtime.block_on(setup_topology(tunnel, packet_size));
    let peer_manager = topology.inst_a.get_peer_manager();
    let packet = topology.packet.clone();
    let completion = topology.completion.clone();

    eprintln!(
        "tx_throughput: measurement=completed-receiver-transfer tunnel={} inflight={} workers={} pkt_size={} batch_size={} preparation_limit={}",
        tunnel.as_str(),
        inflight_depth.max(1),
        worker_threads,
        packet_size,
        batch_size,
        preparation_limit
    );

    let benchmark_result = catch_unwind(AssertUnwindSafe(|| {
        let mut group = c.benchmark_group("tx_throughput");
        group.throughput(Throughput::Bytes(packet_size as u64));
        let benchmark_prefix = format!("{}-p{packet_size}-b{batch_size}", tunnel.as_str());

        // The scalar case submits one packet for each fabric API call.
        // Each timed window ends after the receiver consumes all submitted packets.
        group.bench_function(format!("{benchmark_prefix}-scalar"), |b| {
            b.iter_custom(|iterations| {
                let pm = peer_manager.clone();
                let pkt = packet.clone();
                let completion = completion.clone();
                runtime.block_on(async move {
                    let mut measured = Duration::ZERO;
                    let mut remaining = iterations;
                    let window_limit = inflight_depth
                        .saturating_mul(batch_size)
                        .clamp(1, preparation_limit) as u64;
                    while remaining != 0 {
                        let packet_count = remaining.min(window_limit) as usize;
                        let packets = prepare_scalar_window(&pkt, packet_count);
                        let completion_target = completion.target_after(packet_count);
                        let start = Instant::now();
                        for packet in packets {
                            pm.send_fabric_packet(FabricPacket::new(FabricPayloadKind::Ip, packet))
                                .await
                                .expect("send one packet through the LowTier fabric");
                        }
                        wait_for_completed_transfer(&completion, completion_target).await;
                        measured += start.elapsed();
                        remaining -= packet_count as u64;
                    }
                    measured
                })
            });
        });

        group.bench_function(format!("{benchmark_prefix}-batch"), |b| {
            b.iter_custom(|iterations| {
                let pm = peer_manager.clone();
                let pkt = packet.clone();
                let completion = completion.clone();
                runtime.block_on(async move {
                    let mut measured = Duration::ZERO;
                    let mut remaining = iterations;
                    let window_limit = inflight_depth
                        .saturating_mul(batch_size)
                        .clamp(1, preparation_limit) as u64;
                    while remaining != 0 {
                        let packet_count = remaining.min(window_limit) as usize;
                        let batches = prepare_batch_window(&pkt, packet_count, batch_size);
                        let completion_target = completion.target_after(packet_count);
                        let start = Instant::now();
                        for batch in batches {
                            pm.send_fabric_batch(batch)
                                .await
                                .expect("send one batch through the LowTier fabric");
                        }
                        wait_for_completed_transfer(&completion, completion_target).await;
                        measured += start.elapsed();
                        remaining -= packet_count as u64;
                    }
                    measured
                })
            });
        });

        // Concurrent tasks submit scalar fabric packets.
        // Each timed window includes receiver completion.
        group.bench_function(format!("{benchmark_prefix}-saturate"), |b| {
            b.iter_custom(|iterations| {
                let pm = peer_manager.clone();
                let pkt = packet.clone();
                let completion = completion.clone();
                let concurrency = inflight_depth
                    .min(iterations as usize)
                    .min(preparation_limit)
                    .max(1);
                runtime.block_on(async move {
                    let mut measured = Duration::ZERO;
                    let mut remaining = iterations;
                    let window_limit = concurrency
                        .saturating_mul(batch_size)
                        .clamp(1, preparation_limit) as u64;
                    while remaining != 0 {
                        let packet_count = remaining.min(window_limit) as usize;
                        let worker_packets =
                            prepare_saturate_window(&pkt, packet_count, concurrency);
                        let completion_target = completion.target_after(packet_count);
                        let start = Instant::now();
                        let mut handles = Vec::with_capacity(concurrency);
                        for packets in worker_packets {
                            let pm = pm.clone();
                            handles.push(tokio::spawn(async move {
                                for packet in packets {
                                    pm.send_fabric_packet(FabricPacket::new(
                                        FabricPayloadKind::Ip,
                                        packet,
                                    ))
                                    .await
                                    .expect("send one packet through the LowTier fabric");
                                }
                            }));
                        }
                        for handle in handles {
                            handle.await.expect("saturate worker task panicked");
                        }
                        wait_for_completed_transfer(&completion, completion_target).await;
                        measured += start.elapsed();
                        remaining -= packet_count as u64;
                    }
                    measured
                })
            });
        });

        group.finish();
    }));

    drop(peer_manager);
    drop(packet);
    drop(completion);
    runtime.block_on(teardown_topology(topology));
    if let Err(payload) = benchmark_result {
        resume_unwind(payload);
    }
}

async fn setup_topology(tunnel: TunnelKind, packet_size: usize) -> BenchTopology {
    let tunnel_port = env_parse("TX_THROUGHPUT_TUNNEL_PORT", DEFAULT_TUNNEL_PORT);
    let docker = match tunnel {
        TunnelKind::Ring => None,
        TunnelKind::Tcp | TunnelKind::Udp => Some(DockerNetns::create()),
    };

    let (netns_a, netns_b) = match &docker {
        Some(docker) => (Some(docker.netns_a.clone()), Some(docker.netns_b.clone())),
        None => (None, None),
    };
    let listeners_a = match tunnel {
        TunnelKind::Ring => Vec::new(),
        TunnelKind::Tcp | TunnelKind::Udp => vec![
            format!("{}://0.0.0.0:{}", tunnel.as_str(), tunnel_port)
                .parse()
                .unwrap(),
        ],
    };

    let mut inst_a = Instance::new(no_tun_config("hot-a", VIRTUAL_IP_A, netns_a, listeners_a));
    let mut inst_b = Instance::new(no_tun_config("hot-b", VIRTUAL_IP_B, netns_b, Vec::new()));

    inst_a.run().await.expect("inst_a run");
    inst_b.run().await.expect("inst_b run");
    let completion = CompletionTracker::new();
    inst_b
        .get_peer_manager()
        .add_packet_process_pipeline(Box::new(completion.clone()))
        .await;

    match tunnel {
        TunnelKind::Ring => inst_b
            .get_conn_manager()
            .add_connector(RingTunnelConnector::new(
                format!("ring://{}", inst_a.id()).parse().unwrap(),
            )),
        TunnelKind::Tcp => inst_b
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                format!(
                    "tcp://{}:{}",
                    docker.as_ref().expect("tcp benchmark needs Docker").ip_a,
                    tunnel_port
                )
                .parse()
                .unwrap(),
            )),
        TunnelKind::Udp => inst_b
            .get_conn_manager()
            .add_connector(UdpTunnelConnector::new(
                format!(
                    "udp://{}:{}",
                    docker.as_ref().expect("udp benchmark needs Docker").ip_a,
                    tunnel_port
                )
                .parse()
                .unwrap(),
            )),
    }

    wait_for_routes(&inst_a, &inst_b).await;

    BenchTopology {
        _docker: docker,
        inst_a,
        _inst_b: inst_b,
        packet: make_data_packet(VIRTUAL_IP_A, VIRTUAL_IP_B, packet_size),
        completion,
    }
}

async fn teardown_topology(mut topology: BenchTopology) {
    topology.inst_a.clear_resources().await;
    topology._inst_b.clear_resources().await;
    drop(topology);
    tokio::task::yield_now().await;
}

fn prepared_packet_limit(packet_size: usize) -> usize {
    (MAX_PREPARED_PAYLOAD_BYTES / packet_size).clamp(1, MAX_PREPARED_PACKETS)
}

fn is_benchmark_packet(packet: &ZCPacket) -> bool {
    let payload = packet.payload();
    payload.len() >= 28
        && payload[0] >> 4 == 4
        && payload[9] == 17
        && payload[16..20] == [10, 144, 144, 2]
        && payload[20..24] == [0x30, 0x39, 0xd4, 0x31]
}

async fn wait_for_completed_transfer(completion: &CompletionTracker, target: u64) {
    tokio::time::timeout(RECEIVE_TIMEOUT, completion.wait_for(target))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the receiver completed {} packets before the transfer timeout; expected {target}",
                completion.completed.load(Ordering::Acquire)
            )
        });
}

fn make_packet_batch(packet: &ZCPacket, packet_count: usize) -> PacketBatch {
    let mut batch = PacketBatch::with_capacity(packet_count);
    for _ in 0..packet_count {
        batch
            .try_push(packet.clone())
            .expect("the configured packet count fits one batch");
    }
    batch
}

fn prepare_scalar_window(packet: &ZCPacket, packet_count: usize) -> Vec<ZCPacket> {
    (0..packet_count).map(|_| packet.clone()).collect()
}

fn prepare_batch_window(
    packet: &ZCPacket,
    packet_count: usize,
    batch_size: usize,
) -> Vec<FabricBatch> {
    let mut remaining = packet_count;
    let mut batches = Vec::with_capacity(packet_count.div_ceil(batch_size));
    while remaining != 0 {
        let current = remaining.min(batch_size);
        batches.push(FabricBatch::new(
            FabricPayloadKind::Ip,
            make_packet_batch(packet, current),
        ));
        remaining -= current;
    }
    batches
}

fn prepare_saturate_window(
    packet: &ZCPacket,
    packet_count: usize,
    concurrency: usize,
) -> Vec<Vec<ZCPacket>> {
    let mut workers = (0..concurrency)
        .map(|_| Vec::with_capacity(packet_count.div_ceil(concurrency)))
        .collect::<Vec<_>>();
    for index in 0..packet_count {
        workers[index % concurrency].push(packet.clone());
    }
    workers
}

async fn wait_for_routes(inst_a: &Instance, inst_b: &Instance) {
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let routes_a = inst_a.get_peer_manager().list_routes().await;
            let routes_b = inst_b.get_peer_manager().list_routes().await;
            if !routes_a.is_empty() && !routes_b.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await;
    if result.is_ok() {
        return;
    }

    let peer_manager_a = inst_a.get_peer_manager();
    let peer_manager_b = inst_b.get_peer_manager();
    panic!(
        "LowTier routes did not converge within 15s.\n\
         routes_a={:?}\n\
         routes_b={:?}\n\
         peers_a={:?}\n\
         peers_b={:?}\n\
         connectors_b={:?}",
        peer_manager_a.list_routes().await,
        peer_manager_b.list_routes().await,
        peer_manager_a.get_peer_map().list_peers(),
        peer_manager_b.get_peer_map().list_peers(),
        inst_b.get_conn_manager().list_connectors().await,
    );
}

fn make_data_packet(src: &str, dst: &str, total_size: usize) -> ZCPacket {
    use std::net::Ipv4Addr;

    let hdr_len = 28;
    let payload_len = total_size.saturating_sub(hdr_len);
    let ip_total_len = (hdr_len + payload_len) as u16;
    let mut buf = BytesMut::with_capacity(total_size);

    buf.extend_from_slice(&[
        0x45,
        0x00,
        (ip_total_len >> 8) as u8,
        (ip_total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
    ]);
    let src: Ipv4Addr = src.parse().unwrap();
    buf.extend_from_slice(&src.octets());
    let dst: Ipv4Addr = dst.parse().unwrap();
    buf.extend_from_slice(&dst.octets());

    let udp_len = (8 + payload_len) as u16;
    buf.extend_from_slice(&[
        0x30,
        0x39,
        0xd4,
        0x31,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
        0x00,
        0x00,
    ]);

    buf.resize(total_size, 0xaa);
    ZCPacket::new_with_payload(&buf)
}

fn no_tun_config(
    name: &str,
    ipv4: &str,
    netns: Option<String>,
    listeners: Vec<url::Url>,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(name.to_owned());
    config.set_network_identity(NetworkIdentity::new(
        "tx-throughput".to_owned(),
        "tx-throughput-secret".to_owned(),
    ));
    config.set_netns(netns);
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_listeners(listeners);
    let mut flags = config.get_flags();
    flags.no_tun = true;
    config.set_flags(flags);
    config
}

fn register_netns(name: &str, pid: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let dir = PathBuf::from("/var/run/netns");
        std::fs::create_dir_all(&dir).expect("create /var/run/netns");
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink(format!("/proc/{pid}/ns/net"), &path)
            .expect("link Docker netns into /var/run/netns");
        path
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, pid);
        panic!("Docker netns benchmark requires Linux");
    }
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run docker {args:?}: {err}"));
    if !output.status.success() {
        panic!(
            "docker {:?} failed with status {:?}: {}",
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn docker_ignore(args: &[&str]) {
    let _ = Command::new("docker")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn env_parse<T>(name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|err| panic!("invalid {name}={value:?}: {err}")),
        Err(_) => default,
    }
}

fn criterion_config() -> Criterion {
    let measurement_secs = env_parse("TX_THROUGHPUT_MEASUREMENT_SECS", 10u64);
    let warmup_secs = env_parse("TX_THROUGHPUT_WARMUP_SECS", 3u64);
    let sample_size = env_parse("TX_THROUGHPUT_SAMPLE_SIZE", 10usize).max(10);

    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .warm_up_time(Duration::from_secs(warmup_secs))
        .sample_size(sample_size)
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_tx_throughput
}
criterion_main!(benches);
