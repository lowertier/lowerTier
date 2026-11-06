use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex, Weak},
    time::{Duration, SystemTime},
};

use anyhow::{Context, ensure};
use tokio_util::task::AbortOnDropHandle;

use super::{ControlPlaneService, config};
use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
    proto::api::control::v1::{ConfigPatch, RequestMeta},
};

pub(crate) static RESTART_FILES: LazyLock<Mutex<Option<Vec<PathBuf>>>> =
    LazyLock::new(|| Mutex::new(None));

pub(crate) fn spawn(manager: &Arc<NetworkInstanceManager>) -> AbortOnDropHandle<()> {
    let manager = Arc::downgrade(manager);
    AbortOnDropHandle::new(tokio::spawn(async move {
        maintain(manager).await;
    }))
}

async fn maintain(manager: Weak<NetworkInstanceManager>) {
    let mut observed = BTreeMap::<uuid::Uuid, (String, Vec<Reference>)>::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(manager) = manager.upgrade() else {
            return;
        };
        super::remote::register(&manager);
        super::remote::sweep(&manager).await;
        let ids = manager.list_network_instance_ids();
        observed.retain(|id, _| ids.contains(id));
        for id in ids {
            let Some(control) = manager.get_instance_config_control(&id) else {
                continue;
            };
            if !control.reload_enabled {
                continue;
            }
            let Some(path) = &control.path else { continue };
            match tokio::fs::read_to_string(path).await {
                Ok(text) => {
                    if !observed.contains_key(&id) && !control.is_read_only() {
                        let active = manager.get_instance_config(&id).unwrap();
                        let raw = text.parse::<toml::Table>().ok();
                        if raw.as_ref().is_some_and(|raw| {
                            raw.get("identity").is_none()
                                || raw
                                    .get("node")
                                    .and_then(|node| node.get("instance_id"))
                                    .is_none()
                        }) {
                            let _guard = manager.remote_mutation_lock().lock_owned().await;
                            if config::persist_change(&active, &control, Some(&active)).is_ok() {
                                continue;
                            }
                        }
                    }
                    if manager
                        .reload_errors
                        .lock()
                        .unwrap()
                        .get(&id)
                        .is_some_and(|message| message.starts_with("Cannot read"))
                    {
                        manager.reload_errors.lock().unwrap().remove(&id);
                    }
                    let references = references(&manager.get_instance_config(&id).unwrap());
                    let reference_changes = observed
                        .get(&id)
                        .map(|(_, previous)| {
                            references
                                .iter()
                                .filter(|reference| {
                                    previous.iter().any(|old| {
                                        old.field == reference.field
                                            && old.path == reference.path
                                            && old != *reference
                                    })
                                })
                                .map(|reference| reference.field.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let references_changed = !reference_changes.is_empty();
                    if observed
                        .get(&id)
                        .is_none_or(|(previous, _)| previous != &text)
                        || references_changed
                    {
                        observed.insert(id, (text.clone(), references));
                        if let Err(error) =
                            reload(&manager, id, path, &text, &reference_changes).await
                        {
                            let error = super::api_error(error);
                            let message = if error.code == "invalid_argument" {
                                error.message
                            } else {
                                "The configuration or a referenced file is invalid.".into()
                            };
                            manager
                                .reload_errors
                                .lock()
                                .unwrap()
                                .insert(id, message.clone());
                            tracing::warn!(instance = %id, reason = %message, "Configuration reload rejected; the previous configuration remains active");
                        }
                    }
                }
                Err(error) => {
                    manager
                        .reload_errors
                        .lock()
                        .unwrap()
                        .insert(id, "Cannot read the node configuration file.".into());
                    tracing::warn!(instance = %id, %error, "Cannot read the node configuration");
                }
            }
            if manager.reload_errors.lock().unwrap().contains_key(&id) {
                continue;
            }
            if activate(&manager, id).await.is_err() {
                manager.reload_errors.lock().unwrap().entry(id).or_insert_with(|| "Activation failed. The previous runtime remains active. Check all process configuration files.".into());
                tracing::error!(instance = %id, "Configuration activation failed; inspect the configuration status");
            }
            if !manager.reload_errors.lock().unwrap().contains_key(&id) {
                if let Some((_, previous)) = observed.get_mut(&id) {
                    *previous = references(&manager.get_instance_config(&id).unwrap());
                }
            }
        }
    }
}

#[derive(PartialEq)]
struct Reference {
    field: String,
    path: String,
    modified: Option<SystemTime>,
    length: u64,
    identity: (u64, u64, i64, i64),
}

fn references(config: &TomlConfigLoader) -> Vec<Reference> {
    let document = config::document(config).unwrap_or_default();
    REFERENCE_PATHS
        .iter()
        .filter_map(|field| {
            document
                .pointer(&format!("/{}", field.replace('.', "/")))
                .and_then(serde_json::Value::as_str)
                .map(|path| (*field, path))
        })
        .map(|(field, path)| {
            let metadata = std::fs::metadata(path).ok();
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                metadata.as_ref().map_or((0, 0, 0, 0), |value| {
                    (value.dev(), value.ino(), value.ctime(), value.ctime_nsec())
                })
            };
            #[cfg(not(unix))]
            let identity = (0, 0, 0, 0);
            Reference {
                field: field.to_owned(),
                path: path.to_owned(),
                modified: metadata.as_ref().and_then(|value| value.modified().ok()),
                length: metadata.map_or(0, |value| value.len()),
                identity,
            }
        })
        .collect()
}

const REFERENCE_PATHS: &[&str] = &[
    "control.secret_file",
    "control.token_file",
    "network.secret_file",
    "identity.private_key_file",
    "camouflage.tls_cert",
    "camouflage.tls_key",
];

async fn reload(
    manager: &Arc<NetworkInstanceManager>,
    id: uuid::Uuid,
    path: &std::path::Path,
    text: &str,
    reference_changes: &[String],
) -> anyhow::Result<()> {
    let references_changed = !reference_changes.is_empty();
    let _guard = manager.remote_mutation_lock().lock_owned().await;
    if std::fs::read_to_string(path).ok().as_deref() != Some(text) {
        return Ok(());
    }
    ensure!(
        text.len() <= 2 * 1024 * 1024,
        "The configuration exceeds the file size limit"
    );
    let active = manager
        .get_instance_config(&id)
        .context("The node was deleted")?;
    let (expanded, _) = crate::common::env_parser::expand_env_vars(text);
    let mut raw: toml::Table = expanded.parse().map_err(|error: toml::de::Error| {
        let offset = error
            .span()
            .map_or(0, |span| span.start)
            .min(expanded.len());
        let line = expanded[..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        super::failure(
            "INVALID_ARGUMENT",
            &format!("The TOML is invalid at line {line}."),
            "config",
        )
    })?;
    config::retain_identity(&mut raw, &active);
    let desired =
        TomlConfigLoader::new_from_table(&path.display().to_string(), &raw).map_err(|_| {
            super::failure(
                "INVALID_ARGUMENT",
                "The configuration values or referenced files are invalid.",
                "config",
            )
        })?;
    if raw
        .get("node")
        .and_then(|node| node.get("instance_id"))
        .is_some()
    {
        ensure!(
            desired.get_id() == id,
            "node.instance_id cannot change during reload"
        );
    } else {
        desired.set_id(id);
    }
    let state = manager
        .control_configs
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .unwrap_or_default();
    let current = state
        .desired
        .as_deref()
        .map(TomlConfigLoader::new_from_str)
        .transpose()?
        .unwrap_or(active);
    let before = config::document(&current)?;
    let after = config::document(&desired)?;
    let mut changed = Vec::new();
    config::changed_paths(&before, &after, "", &mut changed);
    if changed.is_empty() && !references_changed {
        let mut errors = manager.reload_errors.lock().unwrap();
        if errors
            .get(&id)
            .is_none_or(|message| !message.starts_with("Activation failed"))
        {
            errors.remove(&id);
        }
        return Ok(());
    }
    let reference_fields = reference_changes
        .iter()
        .filter(|path| {
            after
                .pointer(&format!("/{}", path.replace('.', "/")))
                .is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let changed_values = !changed.is_empty();
    if changed.is_empty() {
        changed = reference_fields.clone();
    }
    if changed.is_empty() {
        return Ok(());
    }
    if reference_changes
        .iter()
        .any(|field| field == "control.token_file")
        || changed.iter().any(|field| field == "control.token_file")
    {
        if let Some(path) = desired.get_control_token_file() {
            ensure!(path.is_file(), "The control token file is missing");
            super::ControlToken::load_or_create(
                &path,
                desired.get_control_config().token_group.as_deref(),
            )?;
        }
    }
    let mut service = ControlPlaneService::for_owned_instances(manager.clone());
    service.externally_locked = true;
    service.from_file = true;
    let mut mask = Vec::new();
    let mut clear = Vec::new();
    for path in changed {
        if after
            .pointer(&format!("/{}", path.replace('.', "/")))
            .is_some_and(|value| !value.is_null())
        {
            mask.push(path);
        } else {
            clear.push(path);
        }
    }
    service
        .transact(
            Some(&RequestMeta {
                instance_id: id.to_string(),
                ..Default::default()
            }),
            ConfigPatch {
                expected_revision: state.revision,
                field_mask: mask,
                clear_paths: clear,
                values: Some(config::node_config(&after)?),
                stage: true,
                persist: false,
            },
        )
        .await?;
    if references_changed {
        let mut states = manager.control_configs.lock().unwrap();
        let state = states.entry(id).or_default();
        if !changed_values {
            state.revision = state
                .revision
                .checked_add(1)
                .context("Configuration revision exhausted")?;
        }
        for field in reference_fields
            .into_iter()
            .filter(|field| field != "control.secret_file")
        {
            if !state.restart_fields.contains(&field) {
                state.restart_fields.push(field);
            }
        }
        if !state.restart_fields.is_empty() {
            state.desired = Some(desired.dump());
        }
    }
    manager.reload_errors.lock().unwrap().remove(&id);
    Ok(())
}

async fn activate(manager: &Arc<NetworkInstanceManager>, id: uuid::Uuid) -> anyhow::Result<()> {
    let _guard = manager.remote_mutation_lock().lock_owned().await;
    let active = manager
        .get_instance_config(&id)
        .context("The node was deleted")?;
    let running = manager.get_instance_service(&id).is_some();
    let state = manager
        .control_configs
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .unwrap_or_default();
    let control = manager
        .get_instance_config_control(&id)
        .context("The node was deleted")?;
    if state
        .restart_fields
        .iter()
        .any(|path| config::is_process_path(path))
    {
        let mut files = Vec::new();
        let mut tokens = Vec::new();
        let owner = *manager.process_owner.lock().unwrap();
        let mut instances = manager.list_network_instance_ids();
        instances.sort_by_key(|instance| (Some(*instance) != owner, *instance));
        for instance in instances {
            let control = manager
                .get_instance_config_control(&instance)
                .context("The instance was deleted")?;
            ensure!(
                control.reload_enabled,
                "A process with startup overrides requires an external restart"
            );
            let path = control
                .path
                .clone()
                .context("A process restart requires persistent instance configurations")?;
            let text = std::fs::read_to_string(&path)?;
            let (expanded, _) = crate::common::env_parser::expand_env_vars(&text);
            let mut raw: toml::Table = expanded.parse().map_err(|_| {
                anyhow::anyhow!("A process configuration is invalid; restart is deferred")
            })?;
            let runtime = manager
                .get_instance_config(&instance)
                .context("The instance was deleted")?;
            let source = raw.clone();
            config::retain_identity(&mut raw, &runtime);
            let checked =
                TomlConfigLoader::new_from_table("process restart", &raw).map_err(|_| {
                    anyhow::anyhow!("A process configuration is invalid; restart is deferred")
                })?;
            if raw
                .get("node")
                .and_then(|node| node.get("instance_id"))
                .is_none()
            {
                checked.set_id(instance);
            }
            ensure!(
                checked.get_id() == instance,
                "A process configuration changed its instance ID"
            );
            if raw != source
                || source
                    .get("node")
                    .and_then(|node| node.get("instance_id"))
                    .is_none()
            {
                config::persist_change(&checked, &control, Some(&checked))?;
            }
            if let Some(token) = checked.get_control_token_file() {
                tokens.push(token);
            }
            files.push(path);
        }
        tokens.sort();
        tokens.dedup();
        ensure!(
            tokens.len() <= 1,
            "All process instances must use one control.token_file before restart"
        );
        *RESTART_FILES.lock().unwrap() = Some(files);
        manager.process_restart.notify_one();
        return Ok(());
    }
    if !active.get_enabled() {
        if running {
            manager.hold_stopped(id);
            manager.stop_network_instance(id).await?;
        }
        if let Some(desired) = state.desired.as_deref() {
            active.replace_active(&TomlConfigLoader::new_from_str(desired)?);
            manager.control_configs.lock().unwrap().insert(
                id,
                config::ConfigState {
                    revision: state.revision,
                    desired: None,
                    restart_fields: Vec::new(),
                },
            );
        }
        return Ok(());
    }
    if state.restart_fields.is_empty() {
        let alive = manager
            .iter()
            .any(|instance| *instance.key() == id && instance.is_lowertier_running());
        if !running && !alive && manager.reload_errors.lock().unwrap().get(&id).is_none() {
            manager.start_network_instance(id)?;
            wait_ready(manager, id).await?;
            manager.release_stopped(&id);
        }
        return Ok(());
    }
    if control.path.is_none() {
        return Ok(());
    }
    let desired = TomlConfigLoader::new_from_str(
        state
            .desired
            .as_deref()
            .context("Missing desired configuration")?,
    )?;
    let previous = active.snapshot();
    let _hold = manager.register_daemon();
    manager.stop_network_instance(id).await?;
    active.replace_active(&desired);
    {
        let started = match manager.start_network_instance(id) {
            Ok(()) => wait_ready(manager, id).await,
            Err(error) => Err(error),
        };
        if let Err(error) = started {
            let _ = manager.stop_network_instance(id).await;
            let stored = control
                .path
                .as_ref()
                .and_then(|path| TomlConfigLoader::new(path).ok());
            let file_restored = if stored
                .as_ref()
                .is_some_and(|stored| stored.dump() == desired.dump())
            {
                config::persist_change(&previous, &control, Some(&desired)).is_ok()
            } else {
                false
            };
            active.replace_active(&previous);
            manager.start_network_instance(id)?;
            wait_ready(manager, id).await?;
            manager.control_configs.lock().unwrap().insert(
                id,
                config::ConfigState {
                    revision: state
                        .revision
                        .checked_add(1)
                        .context("Configuration revision exhausted")?,
                    desired: None,
                    restart_fields: Vec::new(),
                },
            );
            manager.reload_errors.lock().unwrap().insert(id, if file_restored {
                "Activation failed. The previous running configuration and file were restored."
            } else { "Activation failed. The previous runtime was restored. The configuration file requires correction." }.into());
            return Err(error);
        }
    }
    manager.control_configs.lock().unwrap().insert(
        id,
        config::ConfigState {
            revision: state.revision,
            desired: None,
            restart_fields: Vec::new(),
        },
    );
    manager.release_stopped(&id);
    tracing::info!(instance = %id, "Applied persisted configuration through an instance restart");
    Ok(())
}

pub(super) async fn wait_ready(
    manager: &Arc<NetworkInstanceManager>,
    id: uuid::Uuid,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if manager.get_instance_service(&id).is_some() {
                return Ok(());
            }
            if manager
                .iter()
                .find(|instance| *instance.key() == id)
                .and_then(|instance| instance.get_latest_error_msg())
                .is_some()
            {
                anyhow::bail!("The instance failed during startup");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("The instance did not become ready before its startup deadline")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::ConfigFileControl;

    #[tokio::test]
    async fn reload_rejects_invalid_files_updates_references_and_restores_failed_startup() {
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("control.secret");
        std::fs::write(&secret, "first phrase").unwrap();
        let text = format!(
            r#"
[node]
threads = 1
[identity]
private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
[network]
name = "reload-test"
secret = "reload-network-secret"
[transport]
listen = []
[tun]
mode = "none"
ipv6 = false
[gui]
enabled = false
[nat]
p2p = "off"
udp_punch = false
tcp_punch = false
stun = []
stun_v6 = []
stun_tcp = []
[control]
secret_file = {:?}
"#,
            secret.display().to_string()
        );
        let config = TomlConfigLoader::new_from_str(&text).unwrap();
        let id = config.get_id();
        let path = directory.path().join("node.toml");
        let file = ConfigFileControl::new(Some(path.clone()), 0u8.into());
        config::persist(&config, &file).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let manager = Arc::new(NetworkInstanceManager::new());
        manager
            .run_network_instance(config.clone(), false, file.clone())
            .unwrap();
        wait_ready(&manager, id).await.unwrap();
        std::fs::write(&path, "[invalid").unwrap();
        assert!(reload(&manager, id, &path, "[invalid", &[]).await.is_err());
        std::fs::write(&path, &text).unwrap();
        assert_eq!(
            config
                .get_control_config()
                .secret_value()
                .unwrap()
                .as_deref(),
            Some("first phrase")
        );
        let first = references(&config);
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, "other phrase").unwrap();
        std::fs::rename(&replacement, &secret).unwrap();
        assert!(references(&config) != first);
        reload(&manager, id, &path, &text, &["control.secret_file".into()])
            .await
            .unwrap();
        assert_eq!(
            config
                .get_control_config()
                .secret_value()
                .unwrap()
                .as_deref(),
            Some("other phrase")
        );
        let restart_fields = manager.control_configs.lock().unwrap()[&id]
            .restart_fields
            .clone();
        assert!(restart_fields.is_empty(), "{restart_fields:?}");
        let foreign = text.replace(&id.to_string(), &uuid::Uuid::new_v4().to_string());
        std::fs::write(&path, foreign).unwrap();
        assert!(config::persist_change(&config, &file, Some(&config)).is_err());
        std::fs::write(&path, &text).unwrap();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut table: toml::Table = text.parse().unwrap();
        table["transport"]["listen"] = toml::Value::Array(vec![
            format!("tcp://{}", occupied.local_addr().unwrap()).into(),
        ]);
        let invalid_start = toml::to_string_pretty(&table).unwrap();
        std::fs::write(&path, &invalid_start).unwrap();
        reload(&manager, id, &path, &invalid_start, &[])
            .await
            .unwrap();
        assert!(activate(&manager, id).await.is_err());
        assert!(manager.get_instance_service(&id).is_some());
        assert!(config.get_listeners().unwrap_or_default().is_empty());
        assert!(manager.reload_errors.lock().unwrap()[&id].starts_with("Activation failed"));
        let recovered = TomlConfigLoader::new(&path).unwrap();
        assert!(recovered.get_listeners().unwrap_or_default().is_empty());
        let corrected = recovered
            .dump()
            .replace("[node]", "[node]\nhostname = 'corrected-node'");
        std::fs::write(&path, &corrected).unwrap();
        reload(&manager, id, &path, &corrected, &[]).await.unwrap();
        assert_eq!(config.get_hostname(), "corrected-node");
        assert!(!manager.reload_errors.lock().unwrap().contains_key(&id));
        let stopped = config.snapshot();
        let stopped_id = uuid::Uuid::new_v4();
        stopped.set_id(stopped_id);
        stopped.set_enabled(false);
        stopped.set_listeners(vec![
            format!("tcp://{}", occupied.local_addr().unwrap())
                .parse()
                .unwrap(),
        ]);
        let stopped_path = directory.path().join("stopped.toml");
        let stopped_file = ConfigFileControl::new(Some(stopped_path.clone()), 0u8.into());
        config::persist(&stopped, &stopped_file).unwrap();
        manager
            .create_network_instance(stopped.clone(), stopped_file)
            .unwrap();
        let service = ControlPlaneService::for_owned_instances(manager.clone());
        assert!(
            service
                .start_instance_inner(
                    crate::proto::rpc_types::controller::BaseController::default(),
                    crate::proto::api::control::v1::StartInstanceRequest {
                        meta: Some(RequestMeta {
                            instance_id: stopped_id.to_string(),
                            ..Default::default()
                        })
                    }
                )
                .await
                .is_err()
        );
        assert!(!stopped.get_enabled());
        assert!(!TomlConfigLoader::new(&stopped_path).unwrap().get_enabled());
        assert!(manager.get_instance_service(&stopped_id).is_none());
        manager.delete_network_instance(vec![stopped_id]).unwrap();
        let mut process_edit: toml::Table = corrected.parse().unwrap();
        process_edit.remove("identity");
        crate::common::config_schema::set(
            &mut process_edit,
            "control.portal",
            "127.0.0.1:15971".into(),
        );
        let process_edit = toml::to_string_pretty(&process_edit).unwrap();
        std::fs::write(&path, &process_edit).unwrap();
        reload(&manager, id, &path, &process_edit, &[])
            .await
            .unwrap();
        activate(&manager, id).await.unwrap();
        assert_eq!(
            TomlConfigLoader::new(&path)
                .unwrap()
                .get_secure_mode()
                .unwrap()
                .public_key()
                .unwrap(),
            config.get_secure_mode().unwrap().public_key().unwrap()
        );
        assert_eq!(RESTART_FILES.lock().unwrap().take().unwrap(), vec![path]);
        manager.stop_network_instance(id).await.unwrap();
    }
}
