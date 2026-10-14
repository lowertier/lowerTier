use crate::common::config::ConfigFileControl;
#[cfg(feature = "ffi-dataplane")]
use crate::gateway::socks5::Socks5Server;
#[cfg(feature = "ffi-dataplane")]
pub use crate::gateway::socks5::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};
use crate::rpc_service::control::ControlInstance;
use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        constants::LOWTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
    },
    instance::instance::Instance,
    proto::api::instance::list_peer_route_pair,
};
use anyhow::Context;
use chrono::{DateTime, Local};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, atomic::AtomicBool},
};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};

pub type MyNodeInfo = crate::proto::api::manage::MyNodeInfo;

type ArcMutApiService = Arc<RwLock<Option<Arc<ControlInstance>>>>;
type TunFd = Option<i32>;

#[derive(serde::Serialize, Clone)]
pub struct Event {
    time: DateTime<Local>,
    event: GlobalCtxEvent,
}

struct LowTierData {
    events: RwLock<VecDeque<Event>>,
    tun_fd: (mpsc::Sender<TunFd>, Mutex<Option<mpsc::Receiver<TunFd>>>),
    event_subscriber: RwLock<broadcast::Sender<GlobalCtxEvent>>,
    instance_stop_notifier: Arc<tokio::sync::Notify>,
    #[cfg(feature = "ffi-dataplane")]
    data_plane: tokio::sync::watch::Sender<Option<Arc<Socks5Server>>>,
    #[cfg(feature = "ffi-dataplane")]
    runtime_handle: (
        parking_lot::Mutex<Option<tokio::runtime::Handle>>,
        parking_lot::Condvar,
    ),
}

impl Default for LowTierData {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(16);
        let (sender, receiver) = mpsc::channel(16);
        Self {
            event_subscriber: RwLock::new(tx),
            events: RwLock::new(VecDeque::new()),
            tun_fd: (sender, Mutex::new(Some(receiver))),
            instance_stop_notifier: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "ffi-dataplane")]
            data_plane: tokio::sync::watch::channel(None).0,
            #[cfg(feature = "ffi-dataplane")]
            runtime_handle: (parking_lot::Mutex::new(None), parking_lot::Condvar::new()),
        }
    }
}

enum InstanceJoin {
    Thread(std::thread::JoinHandle<()>),
    Task(tokio::task::JoinHandle<()>),
}

pub struct LowTierLauncher {
    instance_alive: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    instance_join: Option<InstanceJoin>,
    api_service: ArcMutApiService,
    running_cfg: String,
    error_msg: Arc<RwLock<Option<String>>>,
    data: Arc<LowTierData>,
}

impl LowTierLauncher {
    pub fn new() -> Self {
        let instance_alive = Arc::new(AtomicBool::new(false));
        Self {
            instance_alive,
            instance_join: None,
            api_service: Arc::new(RwLock::new(None)),
            error_msg: Arc::new(RwLock::new(None)),
            running_cfg: String::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            data: Arc::new(LowTierData::default()),
        }
    }

    async fn handle_lowertier_event(event: GlobalCtxEvent, data: &LowTierData) {
        let mut events = data.events.write().unwrap();
        let _ = data.event_subscriber.read().unwrap().send(event.clone());
        events.push_front(Event {
            time: chrono::Local::now(),
            event,
        });
        if events.len() > 20 {
            events.pop_back();
        }
    }

    #[cfg(mobile)]
    async fn run_routine_for_mobile(
        instance: &Instance,
        data: &LowTierData,
        tasks: &mut JoinSet<()>,
    ) {
        let global_ctx = instance.get_global_ctx();
        let peer_mgr = instance.get_peer_manager();
        let nic_ctx = instance.get_nic_ctx();
        let peer_packet_receiver = instance.get_peer_packet_receiver();
        let mut tun_fd_receiver = data.tun_fd.1.lock().unwrap().take().unwrap();

        tasks.spawn(async move {
            loop {
                let Some(tun_fd) = tun_fd_receiver.recv().await.flatten() else {
                    return;
                };
                let res = Instance::setup_nic_ctx_for_mobile(
                    nic_ctx.clone(),
                    global_ctx.clone(),
                    peer_mgr.clone(),
                    peer_packet_receiver.clone(),
                    tun_fd,
                )
                .await;
            }
        });
    }

    async fn lowertier_routine(
        cfg: TomlConfigLoader,
        stop_signal: Arc<tokio::sync::Notify>,
        api_service: ArcMutApiService,
        data: Arc<LowTierData>,
    ) -> Result<(), anyhow::Error> {
        let mut instance = Instance::new(cfg);
        let mut tasks = JoinSet::new();

        // Subscribe to global context events
        let global_ctx = instance.get_global_ctx();
        let data_c = data.clone();
        tasks.spawn(async move {
            let mut receiver = global_ctx.subscribe();
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        Self::handle_lowertier_event(event.clone(), &data_c).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // do nothing currently
                        receiver = receiver.resubscribe();
                    }
                }
            }
        });

        #[cfg(mobile)]
        Self::run_routine_for_mobile(&instance, &data, &mut tasks).await;

        if let Err(err) = instance.run().await {
            tasks.abort_all();
            drop(tasks);
            instance.clear_resources().await;
            return Err(err.into());
        }

        #[cfg(feature = "ffi-dataplane")]
        data.data_plane
            .send_replace(Some(instance.get_socks5_server()));

        api_service
            .write()
            .unwrap()
            .replace(Arc::new(instance.control_instance()));
        drop(api_service);

        stop_signal.notified().await;

        tasks.abort_all();
        drop(tasks);

        instance.clear_resources().await;
        drop(instance);

        Ok(())
    }

    pub fn start<F>(&mut self, cfg_generator: F)
    where
        F: FnOnce() -> Result<TomlConfigLoader, anyhow::Error> + Send + Sync,
    {
        let error_msg = self.error_msg.clone();
        let cfg = match cfg_generator() {
            Err(e) => {
                error_msg.write().unwrap().replace(e.to_string());
                return;
            }
            Ok(cfg) => cfg,
        };

        self.running_cfg = cfg.dump();

        let stop_flag = self.stop_flag.clone();

        let instance_alive = self.instance_alive.clone();
        instance_alive.store(true, std::sync::atomic::Ordering::Relaxed);

        let data = self.data.clone();
        let api_service = self.api_service.clone();
        let attach_to_current =
            !cfg.get_flags().multi_thread && tokio::runtime::Handle::try_current().is_ok();
        if attach_to_current {
            self.instance_join = Some(InstanceJoin::Task(tokio::spawn(Self::run_until_stopped(
                cfg,
                stop_flag,
                api_service,
                data,
                error_msg,
                instance_alive,
            ))));
            return;
        }

        self.instance_join = Some(InstanceJoin::Thread(std::thread::spawn(move || {
            let rt = if cfg.get_flags().multi_thread {
                let worker_threads = 2.max(cfg.get_flags().multi_thread_count as usize);
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(worker_threads)
                    .enable_all()
                    .build()
            } else {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
            }
            .unwrap();
            rt.block_on(Self::run_until_stopped(
                cfg,
                stop_flag,
                api_service,
                data,
                error_msg,
                instance_alive,
            ));
            rt.shutdown_background();
        })));
    }

    async fn run_until_stopped(
        cfg: TomlConfigLoader,
        stop_flag: Arc<AtomicBool>,
        api_service: ArcMutApiService,
        data: Arc<LowTierData>,
        error_msg: Arc<RwLock<Option<String>>>,
        instance_alive: Arc<AtomicBool>,
    ) {
        #[cfg(feature = "ffi-dataplane")]
        {
            let (lock, cvar) = &data.runtime_handle;
            *lock.lock() = Some(tokio::runtime::Handle::current());
            cvar.notify_all();
        }

        let stop_notifier = Arc::new(tokio::sync::Notify::new());
        let stop_notifier_clone = stop_notifier.clone();
        let stop_watch = tokio::spawn(async move {
            while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            stop_notifier_clone.notify_one();
        });

        let notifier = data.instance_stop_notifier.clone();
        let ret = Self::lowertier_routine(cfg, stop_notifier, api_service, data).await;
        stop_watch.abort();
        if let Err(e) = ret {
            error_msg.write().unwrap().replace(format!("{:?}", e));
        }
        instance_alive.store(false, std::sync::atomic::Ordering::Relaxed);
        notifier.notify_one();
    }

    pub fn error_msg(&self) -> Option<String> {
        self.error_msg.read().unwrap().clone()
    }

    pub fn running(&self) -> bool {
        self.instance_alive
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) async fn stop(mut self) -> anyhow::Result<()> {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Release);
        match self.instance_join.take() {
            Some(InstanceJoin::Task(task)) => task.await.map_err(anyhow::Error::from)?,
            Some(InstanceJoin::Thread(thread)) => {
                tokio::task::spawn_blocking(move || thread.join())
                    .await?
                    .map_err(|_| anyhow::anyhow!("The instance thread failed."))?;
            }
            None => {}
        }
        Ok(())
    }

    pub fn get_events(&self) -> Vec<Event> {
        let events = self.data.events.read().unwrap();
        events.iter().cloned().collect()
    }

    pub fn get_api_service(&self) -> Option<Arc<ControlInstance>> {
        match self.api_service.read() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                tracing::error!("Failed to acquire read lock for api_service: {:?}", e);
                None
            }
        }
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn get_data_plane(&self) -> Option<Arc<Socks5Server>> {
        self.data.data_plane.borrow().clone()
    }

    /// Waits up to `deadline` for the data-plane server to be published.
    #[cfg(feature = "ffi-dataplane")]
    pub async fn wait_data_plane(
        &self,
        deadline: tokio::time::Instant,
    ) -> Option<Arc<Socks5Server>> {
        let mut rx = self.data.data_plane.subscribe();
        loop {
            if let Some(server) = rx.borrow_and_update().clone() {
                return Some(server);
            }
            if tokio::time::timeout_at(deadline, rx.changed())
                .await
                .is_err()
            {
                return None;
            }
        }
    }

    /// Blocks up to `timeout` for the runtime handle to be published.
    #[cfg(feature = "ffi-dataplane")]
    pub fn wait_runtime_handle(
        &self,
        timeout: std::time::Duration,
    ) -> Option<tokio::runtime::Handle> {
        let (lock, cvar) = &self.data.runtime_handle;
        let mut guard = lock.lock();
        cvar.wait_while_for(&mut guard, |h| h.is_none(), timeout);
        guard.clone()
    }
}

impl Default for LowTierLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LowTierLauncher {
    fn drop(&mut self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        match self.instance_join.take() {
            Some(InstanceJoin::Thread(handle)) => {
                if let Err(e) = handle.join() {
                    println!("Error when joining thread: {:?}", e);
                }
            }
            Some(InstanceJoin::Task(handle)) => handle.abort(),
            None => {}
        }
    }
}

pub type NetworkInstanceRunningInfo = crate::proto::api::manage::NetworkInstanceRunningInfo;

pub struct NetworkInstance {
    config: TomlConfigLoader,
    launcher: Option<LowTierLauncher>,
    config_file_control: ConfigFileControl,
}

impl NetworkInstance {
    pub fn new(config: TomlConfigLoader, config_file_control: ConfigFileControl) -> Self {
        Self {
            config,
            launcher: None,
            config_file_control,
        }
    }

    pub fn is_lowertier_running(&self) -> bool {
        self.launcher.is_some() && self.launcher.as_ref().unwrap().running()
    }

    pub async fn get_running_info(&self) -> anyhow::Result<NetworkInstanceRunningInfo> {
        let launcher = self.launcher.as_ref().ok_or_else(|| {
            anyhow::anyhow!("instance is not running, please start the instance first")
        })?;
        let api_service = self.get_api_service().ok_or_else(|| {
            anyhow::anyhow!("failed to get api service, instance may not be running")
        })?;
        let peer_manager = api_service.peers()?;
        let peers = ControlInstance::list_peers(&peer_manager).await;
        let my_info = peer_manager.get_my_info().await;
        let routes = peer_manager.list_routes().await;
        let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());
        let foreign_network_summary = Some(peer_manager.get_foreign_network_summary().await);
        let dev_name = api_service.context()?.get_flags().dev_name;

        Ok(NetworkInstanceRunningInfo {
            dev_name,
            my_node_info: Some(MyNodeInfo {
                virtual_ipv4: my_info
                    .ipv4_addr
                    .parse::<cidr::Ipv4Inet>()
                    .ok()
                    .map(Into::into),
                hostname: my_info.hostname,
                version: LOWTIER_VERSION.to_string(),
                ips: my_info.ip_list,
                stun_info: my_info.stun_info,
                listeners: my_info
                    .listeners
                    .into_iter()
                    .map(|s| s.parse::<url::Url>().unwrap().into())
                    .collect(),
                peer_id: my_info.peer_id,
            }),
            events: launcher
                .get_events()
                .iter()
                .map(|e| serde_json::to_string(e).unwrap())
                .collect(),
            routes,
            peers,
            peer_route_pairs,
            running: launcher.running(),
            error_msg: launcher.error_msg(),
            foreign_network_summary,
        })
    }

    pub fn get_inst_name(&self) -> String {
        self.config.get_inst_name()
    }

    pub fn get_network_name(&self) -> String {
        self.config.get_network_identity().network_name
    }

    pub fn get_tun_fd_sender(&self) -> Option<mpsc::Sender<TunFd>> {
        self.launcher
            .as_ref()
            .map(|launcher| launcher.data.tun_fd.0.clone())
    }

    pub fn start(&mut self) -> Result<EventBusSubscriber, anyhow::Error> {
        if self.is_lowertier_running() {
            return Ok(self.subscribe_event().unwrap());
        }

        let launcher = LowTierLauncher::new();
        self.launcher = Some(launcher);
        let ev = self.subscribe_event().unwrap();

        self.launcher
            .as_mut()
            .unwrap()
            .start(|| Ok(self.config.clone()));

        Ok(ev)
    }

    pub(crate) fn take_launcher(&mut self) -> Option<LowTierLauncher> {
        self.launcher.take()
    }

    pub fn subscribe_event(&self) -> Option<broadcast::Receiver<GlobalCtxEvent>> {
        self.launcher
            .as_ref()
            .map(|launcher| launcher.data.event_subscriber.read().unwrap().subscribe())
    }

    pub fn get_stop_notifier(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.launcher
            .as_ref()
            .map(|launcher| launcher.data.instance_stop_notifier.clone())
    }

    pub fn get_config_file_control(&self) -> &ConfigFileControl {
        &self.config_file_control
    }

    pub fn get_config(&self) -> TomlConfigLoader {
        self.config.clone()
    }

    pub fn get_latest_error_msg(&self) -> Option<String> {
        if let Some(launcher) = self.launcher.as_ref() {
            launcher.error_msg.read().unwrap().clone()
        } else {
            None
        }
    }

    pub fn get_api_service(&self) -> Option<Arc<ControlInstance>> {
        self.launcher
            .as_ref()
            .and_then(|launcher| launcher.get_api_service())
    }

    /// Waits up to `timeout` for the data-plane server to come up, returning it
    /// together with the deadline so the caller can spend the remaining budget
    /// on the actual operation.
    #[cfg(feature = "ffi-dataplane")]
    async fn wait_data_plane(
        &self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(Arc<Socks5Server>, tokio::time::Instant)> {
        let deadline = tokio::time::Instant::now() + timeout;
        let launcher = self
            .launcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("data plane is not ready"))?;
        let server = launcher
            .wait_data_plane(deadline)
            .await
            .ok_or_else(|| anyhow::anyhow!("data plane is not ready"))?;
        Ok((server, deadline))
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: std::time::Duration,
    ) -> anyhow::Result<DataPlaneTcpStream> {
        let (server, deadline) = self.wait_data_plane(timeout).await?;
        server
            .data_plane_tcp_connect(dst_addr, deadline - tokio::time::Instant::now())
            .await
            .map_err(Into::into)
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<DataPlaneTcpListener> {
        let (server, deadline) = self.wait_data_plane(timeout).await?;
        server
            .data_plane_tcp_bind(local_port, deadline - tokio::time::Instant::now())
            .await
            .map_err(Into::into)
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<DataPlaneUdpSocket> {
        let (server, deadline) = self.wait_data_plane(timeout).await?;
        server
            .data_plane_udp_bind(local_port, deadline - tokio::time::Instant::now())
            .await
            .map_err(Into::into)
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn wait_runtime_handle(
        &self,
        timeout: std::time::Duration,
    ) -> Option<tokio::runtime::Handle> {
        self.launcher
            .as_ref()
            .and_then(|launcher| launcher.wait_runtime_handle(timeout))
    }
}

pub fn add_proxy_network_to_config(
    proxy_network: &str,
    cfg: &TomlConfigLoader,
) -> Result<(), anyhow::Error> {
    let parts: Vec<&str> = proxy_network.split("->").collect();
    let real_cidr = parts[0]
        .parse()
        .with_context(|| format!("failed to parse proxy network: {}", parts[0]))?;

    if parts.len() > 2 {
        return Err(anyhow::anyhow!(
                    "invalid proxy network format: {}, support format: <real_cidr> or <real_cidr>-><mapped_cidr>, example:
                    10.0.0.0/24 or 10.0.0.0/24->192.168.0.0/24",
                    proxy_network
                ));
    }

    let mapped_cidr = if parts.len() == 2 {
        Some(
            parts[1]
                .parse()
                .with_context(|| format!("failed to parse mapped network: {}", parts[1]))?,
        )
    } else {
        None
    };
    cfg.add_proxy_cidr(real_cidr, mapped_cidr)?;
    Ok(())
}
