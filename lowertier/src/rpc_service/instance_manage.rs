use std::{collections::HashSet, sync::Arc};

use crate::{
    common::config::{
        ConfigFileControl, ConfigFilePermission, ConfigLoader, ConfigSource, TomlConfigLoader,
    },
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::GetConfigRequest,
            manage::{
                CollectNetworkInfoRequest, CollectNetworkInfoResponse,
                DeleteNetworkInstanceRequest, DeleteNetworkInstanceResponse,
                GetNetworkInstanceConfigRequest, GetNetworkInstanceConfigResponse,
                ListNetworkInstanceMetaRequest, ListNetworkInstanceMetaResponse,
                ListNetworkInstanceRequest, ListNetworkInstanceResponse,
                NetworkInstanceRunningInfoMap, NetworkMeta, RetainNetworkInstanceRequest,
                RetainNetworkInstanceResponse, RunNetworkInstanceRequest,
                RunNetworkInstanceResponse, ValidateConfigRequest, ValidateConfigResponse,
                WebClientService,
            },
        },
        rpc_types::{self, controller::BaseController},
    },
};

#[async_trait::async_trait]
pub trait WebClientHooks: Send + Sync {
    fn manages_remote_config_instances(&self) -> bool {
        false
    }

    async fn pre_run_network_instance(&self, _cfg: &TomlConfigLoader) -> Result<(), String> {
        Ok(())
    }

    async fn post_run_network_instance(&self, _id: &uuid::Uuid) -> Result<(), String> {
        Ok(())
    }

    async fn post_remove_network_instances(&self, _ids: &[uuid::Uuid]) -> Result<(), String> {
        Ok(())
    }
}

pub struct DefaultHooks;

#[async_trait::async_trait]
impl WebClientHooks for DefaultHooks {}

#[derive(Clone)]
pub struct InstanceManageRpcService {
    manager: Arc<NetworkInstanceManager>,
    hooks: Arc<dyn WebClientHooks>,
    remote_mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

impl InstanceManageRpcService {
    pub fn new(manager: Arc<NetworkInstanceManager>, hooks: Arc<dyn WebClientHooks>) -> Self {
        let remote_mutation_lock = manager.remote_mutation_lock();
        Self {
            manager,
            hooks,
            remote_mutation_lock,
        }
    }
}

async fn is_remote_removable(control: &ConfigFileControl) -> bool {
    if control.is_read_only() || !control.is_deletable() {
        return false;
    }
    let Some(path) = control.path.as_ref() else {
        return true;
    };

    !ConfigFileControl::from_path(path.clone())
        .await
        .is_read_only()
}

async fn ensure_remote_overwritable(
    inst_id: uuid::Uuid,
    control: &ConfigFileControl,
) -> anyhow::Result<()> {
    if control.is_read_only() {
        return Err(anyhow::anyhow!(
            "instance {} is read-only, cannot be overwritten",
            inst_id
        ));
    }
    if !control.is_deletable() {
        return Err(anyhow::anyhow!(
            "instance {} is no-delete, cannot be overwritten",
            inst_id
        ));
    }

    if let Some(path) = control.path.as_ref() {
        let real_control = ConfigFileControl::from_path(path.clone()).await;
        if real_control.is_read_only() {
            return Err(anyhow::anyhow!(
                "config file {} is read-only, cannot be overwritten",
                path.display()
            ));
        }
    }

    Ok(())
}

async fn ensure_overwritable(
    inst_id: uuid::Uuid,
    control: &ConfigFileControl,
) -> anyhow::Result<()> {
    if control.is_read_only() {
        return Err(anyhow::anyhow!(
            "instance {} is read-only, cannot be overwritten",
            inst_id
        ));
    }

    if let Some(path) = control.path.as_ref() {
        let real_control = ConfigFileControl::from_path(path.clone()).await;
        if real_control.is_read_only() {
            return Err(anyhow::anyhow!(
                "config file {} is read-only, cannot be overwritten",
                path.display()
            ));
        }
    }

    Ok(())
}

struct StartedInstanceCleanup {
    manager: Arc<NetworkInstanceManager>,
    started_inst_id: Option<uuid::Uuid>,
    config_file_cleanup: Option<ConfigFileCleanup>,
    restore_instance: Option<(TomlConfigLoader, ConfigFileControl)>,
    armed: bool,
}

enum ConfigFileCleanup {
    Remove(std::path::PathBuf),
    Restore {
        path: std::path::PathBuf,
        contents: Vec<u8>,
    },
}

impl ConfigFileCleanup {
    fn apply(self) {
        match self {
            Self::Remove(config_file) => {
                let _ = std::fs::remove_file(config_file);
            }
            Self::Restore { path, contents } => {
                if let Err(e) = std::fs::write(&path, contents) {
                    tracing::warn!("failed to restore config file {}: {}", path.display(), e);
                }
            }
        }
    }
}

impl StartedInstanceCleanup {
    fn new(
        manager: Arc<NetworkInstanceManager>,
        config_file_cleanup: Option<ConfigFileCleanup>,
        restore_instance: Option<(TomlConfigLoader, ConfigFileControl)>,
    ) -> Self {
        Self {
            manager,
            started_inst_id: None,
            config_file_cleanup,
            restore_instance,
            armed: true,
        }
    }

    fn mark_started(&mut self, inst_id: uuid::Uuid) {
        self.started_inst_id = Some(inst_id);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartedInstanceCleanup {
    fn drop(&mut self) {
        if self.armed {
            if let Some(inst_id) = self.started_inst_id {
                let _ = self.manager.delete_network_instance(vec![inst_id]);
            }
            if let Some(config_file_cleanup) = self.config_file_cleanup.take() {
                config_file_cleanup.apply();
            }
            if let Some((cfg, control)) = self.restore_instance.take()
                && let Err(e) = self.manager.run_network_instance(cfg, true, control)
            {
                tracing::warn!("failed to restore overwritten instance: {}", e);
            }
        }
    }
}

#[async_trait::async_trait]
impl WebClientService for InstanceManageRpcService {
    type Controller = BaseController;

    async fn validate_config(
        &self,
        _: BaseController,
        req: ValidateConfigRequest,
    ) -> Result<ValidateConfigResponse, rpc_types::error::Error> {
        let toml_config = req.config.unwrap_or_default().gen_config()?.dump();
        Ok(ValidateConfigResponse { toml_config })
    }

    async fn run_network_instance(
        &self,
        _: BaseController,
        req: RunNetworkInstanceRequest,
    ) -> Result<RunNetworkInstanceResponse, rpc_types::error::Error> {
        if req.config.is_none() {
            return Err(anyhow::anyhow!("config is required").into());
        }
        let cfg = req.config.unwrap().gen_config()?;
        let mut effective_id = cfg.get_id();
        if let Some(inst_id) = req.inst_id {
            effective_id = inst_id.into();
            cfg.set_id(effective_id);
        }
        let requested_source = ConfigSource::from_rpc(req.source);
        let resp = RunNetworkInstanceResponse {
            inst_id: Some(effective_id.into()),
        };
        let _mutation_guard = self.remote_mutation_lock.lock().await;
        let managed_remote = self.hooks.manages_remote_config_instances();

        let mut overwrite_existing = false;
        let mut restore_instance = None;
        let mut control =
            if let Some(control) = self.manager.get_instance_config_control(&effective_id) {
                let existing_source = self
                    .manager
                    .get_instance_network_config_source(&effective_id);
                let error_msg = self
                    .manager
                    .get_network_info(&effective_id)
                    .await
                    .and_then(|i| i.error_msg)
                    .unwrap_or_default();

                if !req.overwrite && error_msg.is_empty() {
                    return Ok(resp);
                }
                if managed_remote {
                    ensure_remote_overwritable(effective_id, &control).await?;
                } else {
                    ensure_overwritable(effective_id, &control).await?;
                }

                cfg.set_network_config_source(requested_source.or(existing_source));
                overwrite_existing = true;
                restore_instance = self
                    .manager
                    .get_instance_config(&effective_id)
                    .map(|cfg| (cfg, control.clone()));
                control.clone()
            } else if let Some(config_dir) = self.manager.get_config_dir() {
                cfg.set_network_config_source(requested_source);
                ConfigFileControl::new(
                    Some(config_dir.join(format!("{}.toml", effective_id))),
                    ConfigFilePermission::default(),
                )
            } else {
                cfg.set_network_config_source(requested_source);
                ConfigFileControl::new(None, ConfigFilePermission::default())
            };

        if let Err(e) = self.hooks.pre_run_network_instance(&cfg).await {
            return Err(anyhow::anyhow!("pre-run hook failed: {}", e).into());
        }

        if overwrite_existing {
            if managed_remote {
                ensure_remote_overwritable(effective_id, &control).await?;
            } else {
                ensure_overwritable(effective_id, &control).await?;
            }
        }

        let mut config_file_cleanup = None;
        if !control.is_read_only()
            && let Some(config_file) = control.path.as_ref()
        {
            let cleanup = if config_file.exists() {
                match std::fs::read(config_file) {
                    Ok(contents) => Some(ConfigFileCleanup::Restore {
                        path: config_file.clone(),
                        contents,
                    }),
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "failed to backup config file {} before overwrite: {}",
                            config_file.display(),
                            e
                        )
                        .into());
                    }
                }
            } else {
                Some(ConfigFileCleanup::Remove(config_file.clone()))
            };
            match std::fs::write(config_file, cfg.dump()) {
                Ok(()) => {
                    config_file_cleanup = cleanup;
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to write config file {}: {}",
                        config_file.display(),
                        e
                    );
                    control.set_read_only(true);
                }
            }
        }

        let mut started_instance = StartedInstanceCleanup::new(
            self.manager.clone(),
            config_file_cleanup,
            restore_instance,
        );

        if overwrite_existing {
            self.manager.delete_network_instance(vec![effective_id])?;
        }

        if let Err(e) = self.manager.run_network_instance(cfg, true, control) {
            return Err(e.into());
        }
        started_instance.mark_started(effective_id);
        println!("instance {} started", effective_id);

        if let Err(e) = self.hooks.post_run_network_instance(&effective_id).await {
            if managed_remote {
                return Err(anyhow::anyhow!("post-run hook failed: {}", e).into());
            }
            tracing::warn!("post-run hook failed: {}", e);
        }
        started_instance.disarm();

        Ok(resp)
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        req: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, rpc_types::error::Error> {
        let _mutation_guard = self.remote_mutation_lock.lock().await;
        if !self.hooks.manages_remote_config_instances() {
            let remain = self
                .manager
                .retain_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?;
            println!("instance {:?} retained", remain);
            return Ok(RetainNetworkInstanceResponse {
                remain_inst_ids: remain.iter().map(|item| (*item).into()).collect(),
            });
        }

        let mut retain_id_set = req
            .inst_ids
            .into_iter()
            .map(Into::into)
            .collect::<HashSet<uuid::Uuid>>();
        let mut removed_ids = Vec::new();
        for (instance_id, control) in self
            .manager
            .iter()
            .map(|instance| (*instance.key(), instance.get_config_file_control().clone()))
            .collect::<Vec<_>>()
        {
            if retain_id_set.contains(&instance_id) {
                continue;
            }
            if is_remote_removable(&control).await {
                removed_ids.push(instance_id);
            } else {
                retain_id_set.insert(instance_id);
            }
        }
        let remain = self
            .manager
            .retain_network_instance(retain_id_set.into_iter().collect())?;
        println!("instance {:?} retained", remain);
        if let Err(e) = self.hooks.post_remove_network_instances(&removed_ids).await {
            return Err(anyhow::anyhow!("post-remove hook failed: {}", e).into());
        }
        Ok(RetainNetworkInstanceResponse {
            remain_inst_ids: remain.iter().map(|item| (*item).into()).collect(),
        })
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        req: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, rpc_types::error::Error> {
        let mut ret = NetworkInstanceRunningInfoMap {
            map: self
                .manager
                .collect_network_infos()
                .await?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        };
        let include_inst_ids = req
            .inst_ids
            .iter()
            .cloned()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        if !include_inst_ids.is_empty() {
            let mut to_remove = Vec::new();
            for (k, _) in ret.map.iter() {
                if !include_inst_ids.contains(k) {
                    to_remove.push(k.clone());
                }
            }

            for k in to_remove {
                ret.map.remove(&k);
            }
        }
        Ok(CollectNetworkInfoResponse { info: Some(ret) })
    }

    //   rpc ListNetworkInstance(ListNetworkInstanceRequest) returns (ListNetworkInstanceResponse) {}
    async fn list_network_instance(
        &self,
        _: BaseController,
        _: ListNetworkInstanceRequest,
    ) -> Result<ListNetworkInstanceResponse, rpc_types::error::Error> {
        Ok(ListNetworkInstanceResponse {
            inst_ids: self
                .manager
                .list_network_instance_ids()
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    //   rpc DeleteNetworkInstance(DeleteNetworkInstanceRequest) returns (DeleteNetworkInstanceResponse) {}
    async fn delete_network_instance(
        &self,
        _: BaseController,
        req: DeleteNetworkInstanceRequest,
    ) -> Result<DeleteNetworkInstanceResponse, rpc_types::error::Error> {
        let _mutation_guard = self.remote_mutation_lock.lock().await;
        let inst_ids: HashSet<uuid::Uuid> = req.inst_ids.into_iter().map(Into::into).collect();

        if !self.hooks.manages_remote_config_instances() {
            let hook_ids: Vec<uuid::Uuid> = inst_ids.iter().cloned().collect();
            let inst_ids = self
                .manager
                .iter()
                .filter(|v| inst_ids.contains(v.key()))
                .filter(|v| v.get_config_file_control().is_deletable())
                .map(|v| *v.key())
                .collect::<Vec<_>>();
            let config_files = inst_ids
                .iter()
                .filter_map(|id| {
                    self.manager
                        .get_instance_config_control(id)
                        .and_then(|control| control.path)
                })
                .collect::<Vec<_>>();
            let remain_inst_ids = self.manager.delete_network_instance(inst_ids)?;
            println!("instance {:?} retained", remain_inst_ids);

            if let Err(e) = self.hooks.post_remove_network_instances(&hook_ids).await {
                tracing::warn!("post-remove hook failed: {}", e);
            }

            for config_file in config_files {
                if let Err(e) = std::fs::remove_file(&config_file) {
                    tracing::warn!(
                        "failed to remove config file {}: {}",
                        config_file.display(),
                        e
                    );
                }
            }
            return Ok(DeleteNetworkInstanceResponse {
                remain_inst_ids: remain_inst_ids.into_iter().map(Into::into).collect(),
            });
        }

        let mut deletable_inst_ids = Vec::new();
        for (instance_id, control) in self
            .manager
            .iter()
            .filter(|v| inst_ids.contains(v.key()))
            .map(|instance| (*instance.key(), instance.get_config_file_control().clone()))
            .collect::<Vec<_>>()
        {
            if is_remote_removable(&control).await {
                deletable_inst_ids.push(instance_id);
            }
        }
        let inst_ids = deletable_inst_ids;
        let config_files = inst_ids
            .iter()
            .filter_map(|id| {
                self.manager
                    .get_instance_config_control(id)
                    .and_then(|control| control.path)
            })
            .collect::<Vec<_>>();
        let hook_ids = inst_ids.clone();
        let remain_inst_ids = self.manager.delete_network_instance(inst_ids)?;
        println!("instance {:?} retained", remain_inst_ids);

        if let Err(e) = self.hooks.post_remove_network_instances(&hook_ids).await {
            return Err(anyhow::anyhow!("post-remove hook failed: {}", e).into());
        }

        for config_file in config_files {
            if ConfigFileControl::from_path(config_file.clone())
                .await
                .is_read_only()
            {
                continue;
            }
            if let Err(e) = std::fs::remove_file(&config_file) {
                tracing::warn!(
                    "failed to remove config file {}: {}",
                    config_file.display(),
                    e
                );
            }
        }
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: remain_inst_ids.into_iter().map(Into::into).collect(),
        })
    }

    async fn get_network_instance_config(
        &self,
        _: BaseController,
        req: GetNetworkInstanceConfigRequest,
    ) -> Result<GetNetworkInstanceConfigResponse, rpc_types::error::Error> {
        let inst_id: uuid::Uuid = req
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("instance id is required"))?
            .into();

        let control = self
            .manager
            .get_instance_config_control(&inst_id)
            .ok_or_else(|| anyhow::anyhow!("instance config control not found"))?;

        if control.is_read_only() {
            return Err(anyhow::anyhow!(
                "Configuration for instance {} is read-only (uses environment variables) and cannot be retrieved via API. \
                 Please access the configuration file directly on the file system.",
                inst_id
            )
            .into());
        }

        let config = self
            .manager
            .get_instance_service(&inst_id)
            .ok_or_else(|| anyhow::anyhow!("instance service not found"))?
            .get_config_service()
            .get_config(BaseController::default(), GetConfigRequest::default())
            .await?
            .config;
        Ok(GetNetworkInstanceConfigResponse {
            config,
            source: self
                .manager
                .get_instance_network_config_source(&inst_id)
                .unwrap_or(ConfigSource::User)
                .to_rpc(),
        })
    }

    async fn list_network_instance_meta(
        &self,
        _: BaseController,
        req: ListNetworkInstanceMetaRequest,
    ) -> Result<ListNetworkInstanceMetaResponse, rpc_types::error::Error> {
        let mut metas = Vec::with_capacity(req.inst_ids.len());
        for inst_id in req.inst_ids {
            let inst_id: uuid::Uuid = (inst_id).into();
            let Some(control) = self.manager.get_instance_config_control(&inst_id) else {
                continue;
            };
            let Some(network_name) = self.manager.get_network_name(&inst_id) else {
                continue;
            };
            let Some(instance_name) = self.manager.get_instance_name(&inst_id) else {
                continue;
            };
            let meta = NetworkMeta {
                inst_id: Some(inst_id.into()),
                network_name,
                config_permission: control.permission.into(),
                instance_name,
                source: self
                    .manager
                    .get_instance_network_config_source(&inst_id)
                    .unwrap_or(ConfigSource::User)
                    .to_rpc(),
            };
            metas.push(meta);
        }
        Ok(ListNetworkInstanceMetaResponse { metas })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::TomlConfigLoader;
    use crate::proto::api::manage::{NetworkConfig, NetworkingMethod};
    use super::DefaultHooks;
    use std::{path::PathBuf, sync::Mutex};
    use uuid::Uuid;

    #[derive(Default)]
    struct RecordingHooks {
        run_ids: Mutex<Vec<Uuid>>,
        removed_ids: Mutex<Vec<Vec<Uuid>>>,
        reject_pre_run: bool,
        reject_post_run: bool,
        reject_post_remove: bool,
        readonly_on_pre_run: Mutex<Vec<PathBuf>>,
        readonly_on_post_remove: Mutex<Vec<PathBuf>>,
    }

    #[async_trait::async_trait]
    impl WebClientHooks for RecordingHooks {
        fn manages_remote_config_instances(&self) -> bool {
            true
        }

        async fn pre_run_network_instance(&self, _cfg: &TomlConfigLoader) -> Result<(), String> {
            for path in self.readonly_on_pre_run.lock().unwrap().drain(..) {
                set_file_readonly(&path, true);
            }
            if self.reject_pre_run {
                Err("pre-run rejected".to_string())
            } else {
                Ok(())
            }
        }

        async fn post_run_network_instance(&self, _id: &Uuid) -> Result<(), String> {
            if self.reject_post_run {
                Err("post-run rejected".to_string())
            } else {
                self.run_ids.lock().unwrap().push(*_id);
                Ok(())
            }
        }

        async fn post_remove_network_instances(&self, ids: &[Uuid]) -> Result<(), String> {
            if self.reject_post_remove {
                return Err("post-remove rejected".to_string());
            }
            self.removed_ids.lock().unwrap().push(ids.to_vec());
            for path in self.readonly_on_post_remove.lock().unwrap().drain(..) {
                set_file_readonly(&path, true);
            }
            Ok(())
        }
    }

    fn temp_config_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lowertier-instance-manage-{}-{}.toml",
            test_name,
            Uuid::new_v4()
        ))
    }

    fn set_file_readonly(path: &PathBuf, readonly: bool) {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(readonly);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn cleanup_temp_config(path: &PathBuf) {
        if path.exists() {
            set_file_readonly(path, false);
            let _ = std::fs::remove_file(path);
        }
    }
}
