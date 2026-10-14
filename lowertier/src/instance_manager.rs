#[cfg(feature = "ffi-dataplane")]
use crate::launcher::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};
use dashmap::DashMap;
use std::fmt::{Display, Formatter};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{
        config::{ConfigFileControl, ConfigLoader, ConfigSource, TomlConfigLoader},
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
        log,
    },
    launcher::{NetworkInstance, NetworkInstanceRunningInfo},
    proto::{self},
    rpc_service::control::ControlInstance,
};

pub(crate) struct DaemonGuard {
    guard: Option<Arc<()>>,
    stop_check_notifier: Arc<tokio::sync::Notify>,
}
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.stop_check_notifier.notify_one();
    }
}

pub struct NetworkInstanceManager {
    instance_map: Arc<DashMap<uuid::Uuid, NetworkInstance>>,
    instance_stop_tasks: Arc<DashMap<uuid::Uuid, AbortOnDropHandle<()>>>,
    stop_check_notifier: Arc<tokio::sync::Notify>,
    instance_error_messages: Arc<DashMap<uuid::Uuid, String>>,
    config_dir: Option<PathBuf>,
    guard_counter: Arc<()>,
    remote_mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Default for NetworkInstanceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkInstanceManager {
    pub fn new() -> Self {
        NetworkInstanceManager {
            instance_map: Arc::new(DashMap::new()),
            instance_stop_tasks: Arc::new(DashMap::new()),
            stop_check_notifier: Arc::new(tokio::sync::Notify::new()),
            instance_error_messages: Arc::new(DashMap::new()),
            config_dir: None,
            guard_counter: Arc::new(()),
            remote_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn with_config_path(mut self, config_dir: Option<PathBuf>) -> Self {
        self.config_dir = config_dir;
        self
    }

    pub fn remote_mutation_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.remote_mutation_lock.clone()
    }

    fn start_instance_task(&self, instance_id: uuid::Uuid) -> Result<(), anyhow::Error> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(anyhow::anyhow!(
                "tokio runtime not found, cannot start instance task"
            ));
        }

        let instance = self
            .instance_map
            .get(&instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {} not found", instance_id))?;
        let instance_stop_notifier = instance.get_stop_notifier();
        let instance_event_receiver = instance.subscribe_event();

        let instance_map = self.instance_map.clone();
        let instance_stop_tasks = self.instance_stop_tasks.clone();
        let instance_error_messages = self.instance_error_messages.clone();

        let stop_check_notifier = self.stop_check_notifier.clone();
        self.instance_stop_tasks.insert(
            instance_id,
            AbortOnDropHandle::new(tokio::spawn(async move {
                let Some(instance_stop_notifier) = instance_stop_notifier else {
                    return;
                };
                let _t = instance_event_receiver
                    .map(|event| AbortOnDropHandle::new(handle_event(instance_id, event)));
                instance_stop_notifier.notified().await;
                if let Some(instance) = instance_map.get(&instance_id)
                    && let Some(error) = instance.get_latest_error_msg()
                {
                    log::error!(%error, "instance {} stopped", instance_id);
                    instance_error_messages.insert(instance_id, error);
                }
                stop_check_notifier.notify_one();
                instance_stop_tasks.remove(&instance_id);
                instance_stop_tasks.shrink_to_fit();
            })),
        );
        Ok(())
    }

    pub fn run_network_instance(
        &self,
        cfg: TomlConfigLoader,
        watch_event: bool,
        config_file_control: ConfigFileControl,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        let instance_id = cfg.get_id();
        if self.instance_map.contains_key(&instance_id) {
            anyhow::bail!("instance {} already exists", instance_id);
        }

        let mut instance = NetworkInstance::new(cfg, config_file_control);
        instance.start()?;

        self.instance_map.insert(instance_id, instance);
        if watch_event {
            self.start_instance_task(instance_id)?;
        }
        Ok(instance_id)
    }

    pub fn retain_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| instance_ids.contains(k));
        self.instance_map.shrink_to_fit();
        self.instance_error_messages
            .retain(|k, _| instance_ids.contains(k));
        self.instance_error_messages.shrink_to_fit();
        Ok(self.list_network_instance_ids())
    }

    pub(crate) fn create_network_instance(
        &self,
        cfg: TomlConfigLoader,
        control: ConfigFileControl,
    ) -> anyhow::Result<uuid::Uuid> {
        let id = cfg.get_id();
        match self.instance_map.entry(id) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(NetworkInstance::new(cfg, control));
                Ok(id)
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                anyhow::bail!("The instance already exists.")
            }
        }
    }

    pub(crate) fn start_network_instance(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        self.instance_map
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("The instance does not exist."))?
            .start()?;
        self.instance_error_messages.remove(&id);
        self.start_instance_task(id)
    }

    pub(crate) async fn stop_network_instance(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        let launcher = self
            .instance_map
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("The instance does not exist."))?
            .take_launcher();
        if let Some(launcher) = launcher {
            launcher.stop().await?;
        }
        self.instance_stop_tasks.remove(&id);
        Ok(())
    }

    pub fn delete_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| !instance_ids.contains(k));
        self.instance_map.shrink_to_fit();
        self.instance_error_messages
            .retain(|k, _| !instance_ids.contains(k));
        self.instance_error_messages.shrink_to_fit();
        Ok(self.list_network_instance_ids())
    }

    pub async fn collect_network_infos(
        &self,
    ) -> Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>, anyhow::Error> {
        let mut ret = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Ok(info) = instance.get_running_info().await {
                ret.insert(*instance.key(), info);
            }
        }
        for v in self.instance_error_messages.iter() {
            ret.insert(
                *v.key(),
                NetworkInstanceRunningInfo {
                    error_msg: Some(v.value().clone()),
                    ..Default::default()
                },
            );
        }
        Ok(ret)
    }

    pub fn collect_network_infos_sync(
        &self,
    ) -> Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>, anyhow::Error> {
        tokio::runtime::Runtime::new()?.block_on(self.collect_network_infos())
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_tcp_connect(
        &self,
        instance_id: &uuid::Uuid,
        dst_addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<DataPlaneTcpStream, anyhow::Error> {
        let instance = self
            .instance_map
            .get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {} not found", instance_id))?;
        instance.data_plane_tcp_connect(dst_addr, timeout).await
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_tcp_bind(
        &self,
        instance_id: &uuid::Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> Result<DataPlaneTcpListener, anyhow::Error> {
        let instance = self
            .instance_map
            .get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {} not found", instance_id))?;
        instance.data_plane_tcp_bind(local_port, timeout).await
    }

    #[cfg(feature = "ffi-dataplane")]
    pub async fn data_plane_udp_bind(
        &self,
        instance_id: &uuid::Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> Result<DataPlaneUdpSocket, anyhow::Error> {
        let instance = self
            .instance_map
            .get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {} not found", instance_id))?;
        instance.data_plane_udp_bind(local_port, timeout).await
    }

    #[cfg(feature = "ffi-dataplane")]
    pub fn data_plane_wait_runtime_handle(
        &self,
        instance_id: &uuid::Uuid,
        timeout: std::time::Duration,
    ) -> Option<tokio::runtime::Handle> {
        self.instance_map
            .get(instance_id)
            .and_then(|inst| inst.wait_runtime_handle(timeout))
    }

    pub async fn get_network_info(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<NetworkInstanceRunningInfo> {
        if let Some(err_msg) = self.instance_error_messages.get(instance_id) {
            return Some(NetworkInstanceRunningInfo {
                error_msg: Some(err_msg.value().clone()),
                ..Default::default()
            });
        }
        self.instance_map
            .get(instance_id)?
            .get_running_info()
            .await
            .ok()
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_map.iter().map(|item| *item.key()).collect()
    }

    pub fn get_instance_name(&self, instance_id: &uuid::Uuid) -> Option<String> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_inst_name())
    }

    pub fn get_network_name(&self, instance_id: &uuid::Uuid) -> Option<String> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_network_name())
    }

    pub fn iter(&self) -> dashmap::iter::Iter<'_, uuid::Uuid, NetworkInstance> {
        self.instance_map.iter()
    }

    pub fn get_instance_config_control(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<ConfigFileControl> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_config_file_control().clone())
    }

    pub fn get_instance_config(&self, instance_id: &uuid::Uuid) -> Option<TomlConfigLoader> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_config())
    }

    pub fn get_instance_network_config_source(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<ConfigSource> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_network_config_source())
    }

    pub fn get_instance_service(&self, instance_id: &uuid::Uuid) -> Option<Arc<ControlInstance>> {
        self.instance_map
            .get(instance_id)
            .and_then(|instance| instance.value().get_api_service())
    }

    pub fn set_tun_fd(&self, instance_id: &uuid::Uuid, fd: i32) -> Result<(), anyhow::Error> {
        let sender = self
            .instance_map
            .get(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance not found"))?
            .get_tun_fd_sender()
            .ok_or_else(|| anyhow::anyhow!("tun fd sender not found"))?;

        sender
            .try_send(Some(fd))
            .map_err(|e| anyhow::anyhow!("failed to send tun fd: {}", e))?;

        Ok(())
    }

    pub fn get_config_dir(&self) -> Option<&PathBuf> {
        self.config_dir.as_ref()
    }

    pub(crate) fn register_daemon(&self) -> DaemonGuard {
        DaemonGuard {
            guard: Some(self.guard_counter.clone()),
            stop_check_notifier: self.stop_check_notifier.clone(),
        }
    }

    pub async fn wait(&self) {
        loop {
            let local_instance_running = self
                .instance_map
                .iter()
                .any(|item| item.value().is_lowertier_running());
            let daemon_running = Arc::strong_count(&self.guard_counter) > 1;

            if !local_instance_running && !daemon_running {
                break;
            }

            self.stop_check_notifier.notified().await;
        }
    }
}

macro_rules! event {
    ($lvl:ident, category: $cat:expr, $($args:tt)+) => {
        event!(@impl $lvl, concat!("INSTANCE::", $cat), $($args)+)
    };

    ($lvl:ident, $($args:tt)+) => {
        event!(@impl $lvl, "INSTANCE", $($args)+)
    };

    (@impl $lvl:ident, $cat:expr, $($args:tt)+) => {
        log::$lvl!(
            category: $cat,
            $($args)+
        );
    };
}

#[tracing::instrument]
fn handle_event(
    instance_id: uuid::Uuid,
    mut events: EventBusSubscriber,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Ok(e) = events.recv().await {
                match e {
                    GlobalCtxEvent::PeerAdded(peer_id) => {
                        event!(info, peer_id, "[{}] new peer added", instance_id);
                    }

                    GlobalCtxEvent::PeerRemoved(peer_id) => {
                        event!(info, peer_id, "[{}] peer removed", instance_id);
                    }

                    GlobalCtxEvent::PeerConnAdded(conn_info) => {
                        event!(
                            info,
                            category: "CONNECTION",
                            %conn_info,
                            "[{}] new peer connection added",
                            instance_id,
                        );
                    }

                    GlobalCtxEvent::PeerConnRemoved(conn_info) => {
                        event!(
                            info,
                            category: "CONNECTION",
                            %conn_info,
                            "[{}] peer connection removed",
                            instance_id,
                        );
                    }

                    GlobalCtxEvent::ListenerAddFailed(listener, msg) => {
                        event!(warn, %listener, msg, "[{}] listener add failed", instance_id);
                    }

                    GlobalCtxEvent::ListenerAcceptFailed(listener, msg) => {
                        event!(warn,  %listener, msg, "[{}] listener accept failed", instance_id);
                    }

                    GlobalCtxEvent::ListenerAdded(listener) => {
                        if listener.scheme() == "ring" {
                            continue;
                        }
                        event!(
                            info,
                            %listener,
                            "[{}] new listener added",
                            instance_id
                        );
                    }

                    GlobalCtxEvent::ConnectionAccepted(local, remote) => {
                        event!(info, category: "CONNECTION", local, remote, "[{}] new connection accepted", instance_id);
                    }

                    GlobalCtxEvent::ConnectionError(local, remote, err) => {
                        event!(info, category: "CONNECTION", local, remote, err, "[{}] connection error", instance_id);
                    }

                    GlobalCtxEvent::TunDeviceReady(dev) => {
                        event!(info, dev, "[{}] tun device ready", instance_id);
                    }

                    GlobalCtxEvent::TunDeviceError(err) => {
                        event!(error, %err, "[{}] tun device error", instance_id);
                    }

                    GlobalCtxEvent::Connecting(dst) => {
                        event!(info, category: "CONNECTION", %dst, "[{}] connecting to peer", instance_id);
                    }

                    GlobalCtxEvent::ConnectError(dst, ip_version, error) => {
                        event!(
                            info,
                            category: "CONNECTION",
                            dst,
                            ip_version,
                            %error,
                            "[{}] connect to peer error",
                            instance_id
                        );
                    }

                    GlobalCtxEvent::DhcpIpv4Changed(old, new) => {
                        event!(info, ?old, ?new, "[{}] dhcp ip changed", instance_id);
                    }

                    GlobalCtxEvent::DhcpIpv4Conflicted(ip) => {
                        event!(info, ?ip, "[{}] dhcp ip conflict", instance_id);
                    }

                    GlobalCtxEvent::PublicIpv6Changed(old, new) => {
                        event!(info, ?old, ?new, "[{}] public ipv6 changed", instance_id);
                    }

                    GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed) => {
                        event!(
                            info,
                            ?added,
                            ?removed,
                            "[{}] public ipv6 routes updated",
                            instance_id
                        );
                    }

                    GlobalCtxEvent::PortForwardAdded(cfg) => {
                        event!(
                            info,
                            local = %cfg.bind_addr.unwrap(),
                            remote = %cfg.dst_addr.unwrap(),
                            proto = %cfg.socket_type().as_str_name(),
                            "[{}] port forward added",
                            instance_id,
                        );
                    }

                    GlobalCtxEvent::ConfigPatched(patch) => {
                        event!(info, ?patch, "[{}] config patched", instance_id);
                    }

                    GlobalCtxEvent::ProxyCidrsUpdated(added, removed) => {
                        event!(
                            info,
                            ?added,
                            ?removed,
                            "[{}] proxy CIDRs updated",
                            instance_id
                        );
                    }

                    GlobalCtxEvent::UdpBroadcastRelayStartResult {
                        capture_backend,
                        error,
                    } => {
                        if let Some(error) = error {
                            event!(
                                warn,
                                ?capture_backend,
                                %error,
                                "[{}] UDP broadcast relay start failed",
                                instance_id
                            );
                        } else {
                            event!(
                                info,
                                ?capture_backend,
                                "[{}] UDP broadcast relay started",
                                instance_id
                            );
                        }
                    }

                    GlobalCtxEvent::CredentialChanged => {
                        event!(info, "[{}] credential changed", instance_id);
                    }

                    GlobalCtxEvent::MulticastGroupsUpdated => {
                        event!(debug, "[{}] multicast membership changed", instance_id);
                    }
                    GlobalCtxEvent::PeerRoutesUpdated => {}
                }
            } else {
                events = events.resubscribe();
            }
        }
    })
}

impl Display for proto::api::instance::PeerConnInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnInfo")
            .field("my_peer_id", &self.my_peer_id)
            .field("dst_peer_id", &self.peer_id)
            .field("tunnel_info", &self.tunnel)
            .finish()
    }
}
