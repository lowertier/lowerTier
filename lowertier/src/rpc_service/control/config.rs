use anyhow::Context;
use std::collections::BTreeSet;

use serde_json::Value;

use crate::{
    common::{
        acl_processor::AclRuleBuilder,
        config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
        config_schema::{self, Apply, Kind, OPTIONS},
    },
    proto::{api::control::v1::*, rpc_types::controller::BaseController},
};

use super::{ControlPlaneService, failure, read::now_ms};

#[derive(Clone)]
pub(crate) struct ConfigState {
    pub revision: u64,
    pub desired: Option<String>,
    pub restart_fields: Vec<String>,
}

impl Default for ConfigState {
    fn default() -> Self {
        Self {
            revision: 1,
            desired: None,
            restart_fields: Vec::new(),
        }
    }
}

const REDACTED: &str = "[REDACTED]";
const ACL_GROUPS: &str = "acl.acl_v1.group.declares";

fn secret_paths() -> impl Iterator<Item = &'static str> {
    OPTIONS
        .iter()
        .filter(|spec| spec.secret)
        .map(|spec| spec.path)
}

fn pointer(path: &str) -> String {
    format!("/{}", path.replace('.', "/"))
}

fn set_path(document: &mut Value, path: &str, value: Option<Value>) {
    let mut parts = path.split('.').peekable();
    let mut current = document;
    while let Some(part) = parts.next() {
        if !current.is_object() {
            *current = serde_json::json!({});
        }
        let object = current.as_object_mut().unwrap();
        if parts.peek().is_none() {
            if let Some(value) = value {
                object.insert(part.into(), value);
            } else {
                object.remove(part);
            }
            return;
        }
        current = object.entry(part).or_insert_with(|| serde_json::json!({}));
    }
}

/// The configuration as a JSON object in the public TOML layout.
pub(super) fn document(config: &TomlConfigLoader) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(config.dump().parse::<toml::Table>()?)?)
}

fn values_document(values: Option<&NodeConfig>) -> anyhow::Result<Value> {
    let text = values.map_or("", |values| values.toml.as_str());
    let table = text.parse::<toml::Table>().map_err(|error| {
        failure(
            "INVALID_ARGUMENT",
            &format!(
                "The configuration values are not valid TOML: {}",
                error.message()
            ),
            "values",
        )
    })?;
    Ok(serde_json::to_value(table)?)
}

pub(super) fn node_config(document: &Value) -> anyhow::Result<NodeConfig> {
    let table = toml::Table::try_from(document)?;
    Ok(NodeConfig {
        toml: toml::to_string_pretty(&table)?,
    })
}

fn parse(document: &Value) -> anyhow::Result<TomlConfigLoader> {
    TomlConfigLoader::new_from_table("control request", &toml::Table::try_from(document)?)
}

fn redact_urls(value: &mut Value) {
    match value {
        Value::Object(object) => object.values_mut().for_each(redact_urls),
        Value::Array(array) => array.iter_mut().for_each(redact_urls),
        Value::String(text) => {
            if let Ok(uri) = url::Url::parse(text) {
                if !uri.username().is_empty()
                    || uri.password().is_some()
                    || uri.query_pairs().any(|(key, _)| {
                        matches!(
                            key.as_ref(),
                            "key" | "token" | "secret" | "auth" | "passkey"
                        )
                    })
                {
                    *text = REDACTED.into();
                }
            }
        }
        _ => {}
    }
}

fn projection(config: &TomlConfigLoader) -> anyhow::Result<NodeConfig> {
    let mut value = document(config)?;
    for path in secret_paths() {
        if value.pointer(&pointer(path)).is_some() {
            set_path(&mut value, path, Some(REDACTED.into()));
        }
    }
    if let Some(declares) = value
        .pointer_mut(&pointer(ACL_GROUPS))
        .and_then(Value::as_array_mut)
    {
        for declaration in declares {
            declaration["group_secret"] = REDACTED.into();
        }
    }
    redact_urls(&mut value);
    node_config(&value)
}

/// The registry option that governs a path: the path itself or its closest ancestor.
fn governing(path: &str) -> Option<&'static config_schema::OptionSpec> {
    let mut candidate = path;
    loop {
        if let Some(spec) = config_schema::lookup(candidate) {
            return Some(spec);
        }
        candidate = candidate.rsplit_once('.')?.0;
    }
}

fn valid_path(path: &str) -> anyhow::Result<()> {
    if let Some(message) = config_schema::retired_message(path) {
        return Err(failure("INVALID_ARGUMENT", &format!("{message}."), path));
    }
    let section = OPTIONS
        .iter()
        .any(|spec| spec.path.starts_with(&format!("{path}.")));
    match governing(path) {
        _ if section => Ok(()),
        Some(spec) if spec.path == path || spec.kind == Kind::Table => Ok(()),
        Some(_) => Err(failure(
            "INVALID_ARGUMENT",
            "Arrays and values must be replaced completely.",
            path,
        )),
        None => Err(failure(
            "INVALID_ARGUMENT",
            "The configuration path is unknown.",
            path,
        )),
    }
}

pub(super) fn is_process_path(path: &str) -> bool {
    governing(path).is_some_and(|spec| spec.apply == Apply::Process)
}

fn contains_placeholder(value: &Value) -> bool {
    match value {
        Value::String(value) => matches!(value.as_str(), REDACTED | "<redacted>" | "***"),
        Value::Object(object) => object.values().any(contains_placeholder),
        Value::Array(array) => array.iter().any(contains_placeholder),
        _ => false,
    }
}

pub(super) fn changed_paths(before: &Value, after: &Value, path: &str, changed: &mut Vec<String>) {
    if before == after {
        return;
    }
    if config_schema::lookup(path).is_some_and(|spec| spec.kind == Kind::Table) {
        changed.push(path.to_owned());
        return;
    }
    if before.is_object() || after.is_object() {
        let keys = before
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
            .chain(
                after
                    .as_object()
                    .into_iter()
                    .flat_map(|object| object.keys()),
            )
            .collect::<BTreeSet<_>>();
        for key in keys {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            changed_paths(&before[key], &after[key], &child, changed);
        }
    } else {
        changed.push(path.into());
    }
}

fn classify(path: &str, quic: bool) -> &'static str {
    match governing(path).map_or(Apply::Restart, |spec| spec.apply) {
        Apply::Live => "live",
        Apply::NewConnections => "new_connection",
        Apply::QuicRestart if !quic => "new_connection",
        Apply::QuicRestart | Apply::Restart | Apply::Process => "restart",
    }
}

/// Keep stored secrets where a replacement repeats the redaction placeholder or omits them.
fn restore_secrets(value: &mut Value, path: &str, before: &Value) {
    for secret in secret_paths() {
        let child = if secret == path {
            ""
        } else if let Some(child) = secret.strip_prefix(&format!("{path}.")) {
            child
        } else {
            continue;
        };
        let previous = before.pointer(&pointer(secret)).cloned();
        if child.is_empty() {
            if value.as_str() == Some(REDACTED) {
                *value = previous.unwrap_or(Value::Null);
            }
        } else if value
            .pointer(&pointer(child))
            .is_none_or(|v| v.as_str() == Some(REDACTED))
        {
            set_path(value, child, previous);
        }
    }
    let groups = if path == ACL_GROUPS {
        value.as_array_mut()
    } else {
        ACL_GROUPS
            .strip_prefix(&format!("{path}."))
            .and_then(|child| value.pointer_mut(&pointer(child)))
            .and_then(Value::as_array_mut)
    };
    for declaration in groups.into_iter().flatten() {
        if declaration["group_secret"] == REDACTED {
            let name = declaration["group_name"].clone();
            if let Some(previous) = before
                .pointer(&pointer(ACL_GROUPS))
                .and_then(Value::as_array)
                .and_then(|groups| groups.iter().find(|group| group["group_name"] == name))
            {
                declaration["group_secret"] = previous["group_secret"].clone();
            }
        }
    }
}

fn prepare(
    current: &TomlConfigLoader,
    patch: &ConfigPatch,
    revision: u64,
) -> anyhow::Result<(TomlConfigLoader, ApplyResult)> {
    if patch.expected_revision != revision {
        return Err(failure(
            "CONFLICT",
            "The configuration revision changed.",
            "patch.expected_revision",
        ));
    }
    let paths = patch
        .field_mask
        .iter()
        .chain(&patch.clear_paths)
        .collect::<Vec<_>>();
    if paths.is_empty() || paths.len() > 256 {
        return Err(failure(
            "INVALID_ARGUMENT",
            "Specify between one and 256 configuration paths.",
            "patch.field_mask",
        ));
    }
    for (index, path) in paths.iter().enumerate() {
        valid_path(path)?;
        if paths[..index].iter().any(|other| {
            path == other
                || path.starts_with(&format!("{other}."))
                || other.starts_with(&format!("{path}."))
        }) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Configuration paths overlap.",
                path,
            ));
        }
    }
    let before = document(current)?;
    let values = values_document(patch.values.as_ref())?;
    let mut after = before.clone();
    for path in &patch.field_mask {
        let mut value = values
            .pointer(&pointer(path))
            .cloned()
            .ok_or_else(|| failure("INVALID_ARGUMENT", "The masked value is absent.", path))?;
        restore_secrets(&mut value, path, &before);
        if contains_placeholder(&value) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Redacted values cannot set configuration fields.",
                path,
            ));
        }
        set_path(&mut after, path, (!value.is_null()).then_some(value));
    }
    for path in &patch.clear_paths {
        set_path(&mut after, path, None);
    }
    if after.pointer("/node/instance_id") != before.pointer("/node/instance_id") {
        return Err(failure(
            "INVALID_ARGUMENT",
            "The instance ID cannot change.",
            "node.instance_id",
        ));
    }
    let candidate = parse(&after).map_err(|error| {
        failure(
            "INVALID_ARGUMENT",
            &format!("The configuration values are invalid: {error:#}"),
            "patch.values",
        )
    })?;
    validate_values(&candidate, &after)?;
    // Prepare ACL rules before persistence or runtime publication.
    AclRuleBuilder::build_config(&candidate).map_err(|_| {
        failure(
            "INVALID_ARGUMENT",
            "The ACL or port whitelist is invalid.",
            "acl",
        )
    })?;
    crate::tunnel::stealth_tls::rustls_server_config(&candidate.get_flags(), &[]).map_err(
        |_| {
            failure(
                "INVALID_ARGUMENT",
                "The TLS certificate or private key cannot be loaded.",
                "camouflage.tls_cert",
            )
        },
    )?;
    let after = document(&candidate)?;
    let mut changed = Vec::new();
    changed_paths(&before, &after, "", &mut changed);
    let quic = current
        .get_listeners()
        .into_iter()
        .flatten()
        .chain(candidate.get_listeners().into_iter().flatten())
        .any(|uri| uri.scheme() == "quic");
    let mut result = ApplyResult {
        revision,
        ..Default::default()
    };
    for path in changed {
        match classify(&path, quic) {
            "live" => result.live_fields.push(path),
            "new_connection" => result.new_connection_fields.push(path),
            _ => result.restart_fields.push(path),
        }
    }
    Ok((candidate, result))
}

fn desired_forwards(desired: Option<&NodeConfig>) -> anyhow::Result<Vec<Value>> {
    Ok(values_document(desired)?["forward"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

fn validate_values(config: &TomlConfigLoader, document: &Value) -> anyhow::Result<()> {
    if let Some(level) = config.get_log_config().console {
        if !matches!(
            level.as_str(),
            "off" | "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "The log level is invalid.",
                "log.console",
            ));
        }
    }
    for (path, kind) in [
        ("address.ipv4", 4),
        ("address.ipv6", 6),
        ("address.public_ipv6.prefix", 0),
    ] {
        if let Some(value) = document.pointer(&pointer(path)).and_then(Value::as_str) {
            let valid = match kind {
                4 => value.parse::<cidr::Ipv4Inet>().is_ok(),
                6 => value.parse::<cidr::Ipv6Inet>().is_ok(),
                _ => value.parse::<cidr::Ipv6Cidr>().is_ok(),
            };
            if !valid {
                return Err(failure(
                    "INVALID_ARGUMENT",
                    "The IP address or prefix is invalid.",
                    path,
                ));
            }
        }
    }
    for uri in config.get_mapped_listeners() {
        crate::common::config::validate_mapped_listener_url(&uri).map_err(|_| {
            failure(
                "INVALID_ARGUMENT",
                "The advertised listener is invalid.",
                "transport.advertise",
            )
        })?;
    }
    for forward in config.get_port_forwards() {
        if !matches!(forward.proto.as_str(), "tcp" | "udp")
            || forward.bind_addr.port() == 0
            || forward.dst_addr.port() == 0
        {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Port forwards require TCP or UDP and nonzero ports.",
                "forward",
            ));
        }
    }
    if let Some(acl) = config.get_acl().and_then(|acl| acl.acl_v1) {
        for chain in acl.chains {
            if crate::proto::acl::ChainType::try_from(chain.chain_type).is_err()
                || crate::proto::acl::Action::try_from(chain.default_action).is_err()
            {
                return Err(failure(
                    "INVALID_ARGUMENT",
                    "The ACL chain is invalid.",
                    "acl",
                ));
            }
            for rule in chain.rules {
                if crate::proto::acl::Protocol::try_from(rule.protocol).is_err()
                    || crate::proto::acl::Action::try_from(rule.action).is_err()
                {
                    return Err(failure(
                        "INVALID_ARGUMENT",
                        "The ACL rule is invalid.",
                        "acl",
                    ));
                }
                for address in rule.source_ips.iter().chain(&rule.destination_ips) {
                    if address.parse::<cidr::IpCidr>().is_err() {
                        return Err(failure(
                            "INVALID_ARGUMENT",
                            "The ACL IP address or range is invalid.",
                            "acl",
                        ));
                    }
                }
                for port in rule.ports.iter().chain(&rule.source_ports) {
                    let (start, end) = port.split_once('-').unwrap_or((port, port));
                    if start
                        .parse::<u16>()
                        .ok()
                        .zip(end.parse::<u16>().ok())
                        .is_none_or(|(a, b)| a > b)
                    {
                        return Err(failure(
                            "INVALID_ARGUMENT",
                            "The ACL port range is invalid.",
                            "acl",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn persist(
    config: &TomlConfigLoader,
    control: &ConfigFileControl,
) -> anyhow::Result<()> {
    persist_change(config, control, None)
}

pub(super) fn persist_change(
    config: &TomlConfigLoader,
    control: &ConfigFileControl,
    previous: Option<&TomlConfigLoader>,
) -> anyhow::Result<()> {
    use std::io::Write;
    if control.is_read_only() {
        return Err(failure(
            "PERMISSION_DENIED",
            "The configuration file is read-only.",
            "patch.persist",
        ));
    }
    let path = control.path.as_ref().ok_or_else(|| {
        failure(
            "INVALID_ARGUMENT",
            "The instance has no configuration file.",
            "patch.persist",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    #[cfg(not(windows))]
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| {
        failure(
            "UNAVAILABLE",
            "The configuration file cannot be prepared.",
            "patch.persist",
        )
    })?;
    #[cfg(windows)]
    let mut temporary = {
        use std::os::windows::fs::OpenOptionsExt;
        let temporary_path = parent.join(format!(".control-{}.tmp", uuid::Uuid::new_v4()));
        if !super::token::create_windows_token(&temporary_path)? {
            return Err(failure(
                "UNAVAILABLE",
                "The configuration file cannot be prepared.",
                "patch.persist",
            ));
        }
        let path = tempfile::TempPath::from_path(temporary_path);
        let file = std::fs::OpenOptions::new()
            .access_mode(0x40000000 | 0x00010000)
            .share_mode(0)
            .open(&path)?;
        super::token::secure_windows_token(&path)?;
        tempfile::NamedTempFile::from_parts(file, path)
    };
    let source = previous
        .map(|_| std::fs::read_to_string(path))
        .transpose()
        .map_err(|_| {
            failure(
                "CONFLICT",
                "The configuration file is unavailable. Correct the external edit before retrying.",
                "patch.persist",
            )
        })?;
    let rendered = match previous {
        Some(previous) => render_change(source.as_deref().unwrap(), previous, config)?,
        None => config.dump(),
    };
    #[cfg(unix)]
    if let Ok(metadata) = std::fs::metadata(path) {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        nix::unistd::fchown(
            temporary.as_file().as_raw_fd(),
            Some(metadata.uid().into()),
            Some(metadata.gid().into()),
        )?;
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
    }
    temporary
        .write_all(rendered.as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| {
            failure(
                "UNAVAILABLE",
                "The configuration file cannot be written.",
                "patch.persist",
            )
        })?;
    if let Some(source) = source {
        if std::fs::read_to_string(path).ok().as_ref() != Some(&source) {
            return Err(failure(
                "CONFLICT",
                "The configuration file changed during the update.",
                "patch.expected_revision",
            ));
        }
    }
    #[cfg(not(windows))]
    temporary.persist(path).map_err(|_| {
        failure(
            "UNAVAILABLE",
            "The configuration file cannot be replaced.",
            "patch.persist",
        )
    })?;
    #[cfg(windows)]
    persist_windows_handle(temporary, path).map_err(|_| {
        failure(
            "UNAVAILABLE",
            "The configuration file cannot be replaced.",
            "patch.persist",
        )
    })?;
    Ok(())
}

pub(super) fn retain_identity(raw: &mut toml::Table, active: &TomlConfigLoader) {
    let has_key = raw.get("identity").is_some_and(|identity| {
        identity.get("private_key").is_some() || identity.get("private_key_file").is_some()
    });
    let has_credential = raw
        .get("network")
        .is_some_and(|network| network.get("credential").is_some());
    if !has_key && !has_credential {
        if let Some(mode) = active.get_secure_mode() {
            for (field, value) in [
                ("identity.private_key", mode.local_private_key),
                ("identity.public_key", mode.local_public_key),
            ] {
                if let Some(value) = value {
                    config_schema::set(raw, field, toml::Value::String(value));
                }
            }
        }
    }
}

fn render_change(
    source: &str,
    before: &TomlConfigLoader,
    after: &TomlConfigLoader,
) -> anyhow::Result<String> {
    let conflict = || {
        failure(
            "CONFLICT",
            "The configuration file changed outside the control API. Wait for reload, then retry.",
            "patch.expected_revision",
        )
    };
    let mut raw = source.parse::<toml::Table>().map_err(|_| conflict())?;
    retain_identity(&mut raw, before);
    let stored =
        TomlConfigLoader::new_from_table("configuration file", &raw).map_err(|_| conflict())?;
    if raw
        .get("node")
        .and_then(|node| node.get("instance_id"))
        .is_none()
    {
        stored.set_id(before.get_id());
    }
    if document(&stored)? != document(before)? {
        return Err(conflict());
    }
    let mut original = source.parse::<toml_edit::DocumentMut>()?;
    let replacement = after.dump().parse::<toml_edit::DocumentMut>()?;
    let after_document = document(after)?;
    let mut paths = Vec::new();
    changed_paths(&document(before)?, &after_document, "", &mut paths);
    for path in [
        "node.instance_id",
        "identity.private_key",
        "identity.public_key",
    ] {
        let mut item = original.as_item();
        for part in path.split('.') {
            item = item.get(part).unwrap_or(&toml_edit::Item::None);
        }
        if item.is_none()
            && after_document.pointer(&pointer(path)).is_some()
            && !paths.iter().any(|existing| existing == path)
        {
            paths.push(path.to_owned());
        }
    }
    for path in paths {
        let parts = path.split('.').collect::<Vec<_>>();
        let mut source = replacement.as_item();
        for part in &parts {
            source = source.get(*part).unwrap_or(&toml_edit::Item::None);
        }
        let mut table = original.as_table_mut();
        for part in &parts[..parts.len() - 1] {
            if !table.contains_key(part) {
                table.insert(part, toml_edit::Item::Table(toml_edit::Table::new()));
            }
            table = table
                .get_mut(part)
                .and_then(toml_edit::Item::as_table_mut)
                .context("The configuration parent is not a table")?;
        }
        let name = parts.last().unwrap();
        if source.is_none() {
            table.remove(name);
        } else {
            let mut item = source.clone();
            if let Some(old) = table.get(name).and_then(toml_edit::Item::as_value) {
                if let Some(new) = item.as_value_mut() {
                    *new.decor_mut() = old.decor().clone();
                }
            }
            table.insert(name, item);
        }
    }
    Ok(original.to_string())
}

#[cfg(windows)]
fn persist_windows_handle(
    temporary: tempfile::NamedTempFile,
    destination: &std::path::Path,
) -> anyhow::Result<()> {
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle},
    };
    let filename = std::path::absolute(destination)?
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let length = offset
        .checked_add(
            filename
                .len()
                .checked_mul(2)
                .ok_or_else(|| anyhow::anyhow!("The configuration path is too long."))?,
        )
        .ok_or_else(|| anyhow::anyhow!("The configuration path is too long."))?;
    let mut buffer = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
    // Rename the locked file by handle. The pathname cannot select a replacement file.
    unsafe {
        let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*information).Anonymous.ReplaceIfExists = true;
        (*information).RootDirectory = HANDLE::default();
        (*information).FileNameLength = u32::try_from(filename.len() * 2)?;
        std::ptr::copy_nonoverlapping(
            filename.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            filename.len(),
        );
        SetFileInformationByHandle(
            HANDLE(temporary.as_file().as_raw_handle()),
            FileRenameInfo,
            information.cast(),
            u32::try_from(length)?,
        )?;
    }
    // The temporary path no longer exists. Drop the open handle after publication.
    drop(temporary);
    Ok(())
}

fn select_apply(
    active: &TomlConfigLoader,
    desired: &TomlConfigLoader,
    revision: u64,
    running: bool,
) -> anyhow::Result<(TomlConfigLoader, ApplyResult)> {
    let mut result = ApplyResult {
        revision,
        ..Default::default()
    };
    let before = document(active)?;
    let after = document(desired)?;
    let mut changed = Vec::new();
    changed_paths(&before, &after, "", &mut changed);
    let quic = crate::common::config::transport_protocol_enabled(&active.get_flags(), "quic")
        || crate::common::config::transport_protocol_enabled(&desired.get_flags(), "quic");
    let mut published = before;
    for path in changed {
        match if running || is_process_path(&path) {
            classify(&path, quic)
        } else {
            "live"
        } {
            "live" => {
                set_path(
                    &mut published,
                    &path,
                    after.pointer(&pointer(&path)).cloned(),
                );
                result.live_fields.push(path);
            }
            "new_connection" => {
                set_path(
                    &mut published,
                    &path,
                    after.pointer(&pointer(&path)).cloned(),
                );
                result.new_connection_fields.push(path);
            }
            _ => result.restart_fields.push(path),
        }
    }
    Ok((
        TomlConfigLoader::runtime_projection(&toml::Table::try_from(&published)?, active, desired)?,
        result,
    ))
}

impl ControlPlaneService {
    async fn persist_enabled(&self, id: uuid::Uuid, enabled: bool) -> anyhow::Result<()> {
        let mut transaction = self.clone();
        transaction.externally_locked = true;
        transaction
            .transact(
                Some(&RequestMeta {
                    instance_id: id.to_string(),
                    ..Default::default()
                }),
                ConfigPatch {
                    expected_revision: self.manager.config_revision(id),
                    field_mask: vec!["node.enabled".into()],
                    values: Some(node_config(
                        &serde_json::json!({"node": {"enabled": enabled}}),
                    )?),
                    persist: true,
                    stage: true,
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    pub(super) fn ensure_file(&self, id: uuid::Uuid) -> anyhow::Result<ConfigFileControl> {
        let control = self
            .manager
            .get_instance_config_control(&id)
            .ok_or_else(|| {
                failure(
                    "NOT_FOUND",
                    "The instance does not exist.",
                    "meta.instance_id",
                )
            })?;
        if control.path.is_some() {
            return Ok(control);
        }
        #[cfg(test)]
        let directory = self.manager.temporary_configs.path().to_path_buf();
        #[cfg(not(test))]
        let directory = self
            .manager
            .get_config_dir()
            .cloned()
            .or_else(|| {
                self.manager
                    .list_network_instance_ids()
                    .into_iter()
                    .filter_map(|id| self.manager.get_instance_config_control(&id)?.path)
                    .find_map(|path| path.parent().map(|path| path.to_path_buf()))
            })
            .unwrap_or(
                super::ControlToken::default_path(None)?
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .to_path_buf(),
            )
            .join("managed");
        let existed = directory.exists();
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.join(format!("{id}.toml"));
        anyhow::ensure!(
            !path.exists(),
            "A configuration already exists for this instance"
        );
        let control = ConfigFileControl::new(Some(path), 0u8.into());
        let config = self.manager.get_instance_config(&id).unwrap();
        persist(&config, &control)?;
        self.manager
            .set_instance_file_control(id, control.clone())?;
        Ok(control)
    }

    pub(super) async fn get_relay_inner(
        &self,
        _: BaseController,
        request: GetRelayRequest,
    ) -> anyhow::Result<GetRelayResponse> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        let context = instance.context()?;
        let flags = context.get_flags();
        let mut counters = context
            .stats_manager()
            .get_metrics_by_prefix("relay_")
            .into_iter()
            .map(|metric| crate::proto::api::instance::MetricSnapshot {
                name: metric.name_str(),
                value: metric.value,
                labels: metric
                    .labels
                    .labels()
                    .iter()
                    .map(|label| (label.key.clone(), label.value.clone()))
                    .collect(),
            })
            .collect::<Vec<_>>();
        counters.sort_unstable_by(|a, b| (&a.name, &a.labels).cmp(&(&b.name, &b.labels)));
        let acl = context.get_acl_filter().get_stats();
        counters.push(crate::proto::api::instance::MetricSnapshot {
            name: "relay_drops".into(),
            value: acl
                .global
                .get(&crate::common::acl_processor::AclStatKey::ForwardPacketsDropped.as_str())
                .copied()
                .unwrap_or(0),
            labels: [
                ("error_type".into(), "acl".into()),
                ("scope".into(), "instance".into()),
            ]
            .into_iter()
            .collect(),
        });
        let total_bytes = counters
            .iter()
            .filter(|counter| counter.name == "relay_bytes")
            .map(|counter| counter.value)
            .fold(0u64, u64::saturating_add);
        let state = self
            .manager
            .control_configs
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .unwrap_or_default();
        let desired = state
            .desired
            .as_deref()
            .map(TomlConfigLoader::new_from_str)
            .transpose()?
            .map_or_else(|| flags.clone(), |config| config.get_flags());
        let (generation, advertised, paths) = instance.peers()?.control_routes(&[]).await;
        let mut snapshot = self.snapshot(&instance).await?;
        snapshot.topology_generation = generation;
        Ok(GetRelayResponse {
            paths,
            snapshot: Some(snapshot),
            config: Some(flags.relay_config().clone()),
            total_bytes,
            counters,
            desired_permission: desired.relay_config().transit().as_str_name().into(),
            advertised_permission: advertised,
            drop_reasons: ["deny", "network", "budget", "acl", "unavailable_path"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        })
    }

    pub(super) async fn get_camouflage_inner(
        &self,
        _: BaseController,
        request: GetCamouflageRequest,
    ) -> anyhow::Result<GetCamouflageResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let flags = instance.context()?.get_flags();
        let mut config = flags.camouflage_config().clone();
        config.admission_secret.clear();
        Ok(GetCamouflageResponse {
            snapshot: Some(self.snapshot(&instance).await?),
            certificate_source: if config.tls_cert.is_empty() {
                "generated"
            } else {
                "configured_file"
            }
            .into(),
            quic_h2_verification: if config.has_server_names() && !config.has_decoy() {
                "pki"
            } else {
                "noise_authenticated_certificate"
            }
            .into(),
            direct_wss_verification: "noise_authenticated_certificate".into(),
            cdn_outer_verification: "pki".into(),
            cdn_inner_verification: "noise_exporter".into(),
            config: Some(config),
            ..Default::default()
        })
    }

    pub(super) async fn create_instance_inner(
        &self,
        _: BaseController,
        request: CreateInstanceRequest,
    ) -> anyhow::Result<CreateInstanceResponse> {
        let _guard = self.mutation_guard().await;
        let values = request.config.ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "An instance configuration is required.",
                "config",
            )
        })?;
        let value = values_document(Some(&values))?;
        if contains_placeholder(&value) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Redacted values cannot create an instance.",
                "config",
            ));
        }
        let config = parse(&value).map_err(|_| {
            failure(
                "INVALID_ARGUMENT",
                "The instance configuration is invalid.",
                "config",
            )
        })?;
        validate_values(&config, &value)?;
        crate::tunnel::stealth_tls::rustls_server_config(&config.get_flags(), &[]).map_err(
            |_| {
                failure(
                    "INVALID_ARGUMENT",
                    "The TLS certificate or private key cannot be loaded.",
                    "camouflage.tls_cert",
                )
            },
        )?;
        AclRuleBuilder::build_config(&config)
            .map_err(|_| failure("INVALID_ARGUMENT", "The ACL is invalid.", "config.acl"))?;
        if self.manager.get_instance_config(&config.get_id()).is_some() {
            return Err(failure(
                "CONFLICT",
                "The instance already exists.",
                "config.instance_id",
            ));
        }
        let id = self.manager.create_network_instance(
            {
                config.set_enabled(false);
                config
            },
            ConfigFileControl::new(
                None,
                crate::common::config::ConfigFilePermission::READ_ONLY.into(),
            ),
        )?;
        if let Err(error) = self.ensure_file(id) {
            self.manager.delete_network_instance(vec![id])?;
            return Err(error);
        }
        self.manager.hold_stopped(id);
        Ok(CreateInstanceResponse {
            instance_id: id.to_string(),
            result: Some(ApplyResult {
                revision: 1,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    pub(super) async fn start_instance_inner(
        &self,
        _: BaseController,
        request: StartInstanceRequest,
    ) -> anyhow::Result<StartInstanceResponse> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(request.meta.as_ref())?;
        if self
            .manager
            .iter()
            .any(|instance| *instance.key() == id && instance.is_lowertier_running())
        {
            return Err(failure(
                "CONFLICT",
                "The instance is already running.",
                "meta.instance_id",
            ));
        }
        let active = self.manager.get_instance_config(&id).unwrap();
        let previous = active.snapshot();
        self.persist_enabled(id, true).await?;
        let state = self
            .manager
            .control_configs
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .unwrap_or_default();
        if state
            .restart_fields
            .iter()
            .any(|path| is_process_path(path))
        {
            return Err(failure(
                "RESTART_REQUIRED",
                "Restart the process to apply staged process settings.",
                "restart_fields",
            ));
        }
        if let Some(desired) = &state.desired {
            active.replace_active(&TomlConfigLoader::new_from_str(desired)?);
        }
        let started = match self.manager.start_network_instance(id) {
            Ok(()) => super::maintenance::wait_ready(&self.manager, id).await,
            Err(error) => Err(error),
        };
        if let Err(error) = started {
            let _ = self.manager.stop_network_instance(id).await;
            let failed = active.snapshot();
            let restored = self
                .ensure_file(id)
                .and_then(|control| persist_change(&previous, &control, Some(&failed)))
                .is_ok();
            active.replace_active(&previous);
            self.manager.control_configs.lock().unwrap().insert(
                id,
                ConfigState {
                    revision: state.revision.saturating_add(1),
                    ..Default::default()
                },
            );
            self.manager.reload_errors.lock().unwrap().insert(
                id,
                if restored { "Activation failed. The instance remains stopped with its previous configuration." }
                else { "Activation failed. The instance remains stopped. The configuration file requires correction." }.into(),
            );
            return Err(error);
        }
        self.manager.release_stopped(&id);
        self.manager.control_configs.lock().unwrap().insert(
            id,
            ConfigState {
                revision: state.revision,
                ..Default::default()
            },
        );
        Ok(StartInstanceResponse {
            result: Some(ApplyResult {
                revision: state.revision,
                live_fields: state.restart_fields,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    pub(super) async fn stop_instance_inner(
        &self,
        _: BaseController,
        request: StopInstanceRequest,
    ) -> anyhow::Result<StopInstanceResponse> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(request.meta.as_ref())?;
        self.persist_enabled(id, false).await?;
        self.manager.hold_stopped(id);
        self.manager.stop_network_instance(id).await?;
        Ok(StopInstanceResponse::default())
    }

    pub(super) async fn delete_instance_inner(
        &self,
        _: BaseController,
        request: DeleteInstanceRequest,
    ) -> anyhow::Result<DeleteInstanceResponse> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(request.meta.as_ref())?;
        if self
            .manager
            .iter()
            .any(|instance| *instance.key() == id && instance.is_lowertier_running())
        {
            return Err(failure(
                "CONFLICT",
                "Stop the instance before deletion.",
                "meta.instance_id",
            ));
        }
        let control = self.manager.get_instance_config_control(&id).unwrap();
        if !control.is_deletable() {
            return Err(failure(
                "PERMISSION_DENIED",
                "The instance configuration cannot be deleted.",
                "meta.instance_id",
            ));
        }
        if let Some(path) = &control.path {
            std::fs::remove_file(path)?;
        }
        self.manager.delete_network_instance(vec![id])?;
        self.manager.release_stopped(&id);
        self.manager.control_configs.lock().unwrap().remove(&id);
        Ok(DeleteInstanceResponse::default())
    }

    pub(super) async fn set_acl_inner(
        &self,
        _: BaseController,
        request: SetAclRequest,
    ) -> anyhow::Result<SetAclResponse> {
        let mut values = serde_json::json!({ "acl": {
            "tcp_ports": request.tcp_whitelist,
            "udp_ports": request.udp_whitelist,
        }});
        let acl = serde_json::to_value(request.acl.unwrap_or_default())?;
        if let Value::Object(acl) = acl {
            for (key, value) in acl {
                values["acl"][key] = value;
            }
        }
        let patch = ConfigPatch {
            expected_revision: request.expected_revision,
            field_mask: vec!["acl".into()],
            values: Some(node_config(&values)?),
            persist: request.persist,
            ..Default::default()
        };
        Ok(SetAclResponse {
            result: Some(self.transact(request.meta.as_ref(), patch).await?),
            ..Default::default()
        })
    }

    pub(super) async fn put_port_forward_inner(
        &self,
        _: BaseController,
        request: PutPortForwardRequest,
    ) -> anyhow::Result<PutPortForwardResponse> {
        let row = request.port_forward.ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "A port forward is required.",
                "port_forward",
            )
        })?;
        let config = self
            .get_config_inner(
                BaseController::default(),
                GetConfigRequest {
                    meta: request.meta.clone(),
                },
            )
            .await?;
        let mut forwards = desired_forwards(config.desired.as_ref())?;
        forwards.retain(|entry| {
            entry["bind"] != row.bind.as_str() || entry["proto"] != row.proto.as_str()
        });
        forwards
            .push(serde_json::json!({ "proto": row.proto, "bind": row.bind, "dest": row.dest }));
        let values = node_config(&serde_json::json!({ "forward": forwards }))?;
        Ok(PutPortForwardResponse {
            result: Some(
                self.transact(
                    request.meta.as_ref(),
                    ConfigPatch {
                        expected_revision: request.expected_revision,
                        field_mask: vec!["forward".into()],
                        values: Some(values),
                        persist: request.persist,
                        stage: request.stage,
                        ..Default::default()
                    },
                )
                .await?,
            ),
            ..Default::default()
        })
    }

    pub(super) async fn delete_port_forward_inner(
        &self,
        _: BaseController,
        request: DeletePortForwardRequest,
    ) -> anyhow::Result<DeletePortForwardResponse> {
        let config = self
            .get_config_inner(
                BaseController::default(),
                GetConfigRequest {
                    meta: request.meta.clone(),
                },
            )
            .await?;
        let mut forwards = desired_forwards(config.desired.as_ref())?;
        let previous = forwards.len();
        forwards.retain(|entry| {
            entry["bind"] != request.bind.as_str() || entry["proto"] != request.proto.as_str()
        });
        if forwards.len() == previous {
            return Err(failure(
                "NOT_FOUND",
                "The port forward does not exist.",
                "bind",
            ));
        }
        let values = node_config(&serde_json::json!({ "forward": forwards }))?;
        Ok(DeletePortForwardResponse {
            result: Some(
                self.transact(
                    request.meta.as_ref(),
                    ConfigPatch {
                        expected_revision: request.expected_revision,
                        field_mask: vec!["forward".into()],
                        values: Some(values),
                        persist: request.persist,
                        stage: request.stage,
                        ..Default::default()
                    },
                )
                .await?,
            ),
            ..Default::default()
        })
    }

    pub(super) async fn get_config_inner(
        &self,
        _: BaseController,
        request: GetConfigRequest,
    ) -> anyhow::Result<GetConfigResponse> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(request.meta.as_ref())?;
        let active = self.manager.get_instance_config(&id).unwrap();
        let state = self
            .manager
            .control_configs
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .unwrap_or_default();
        let desired = state
            .desired
            .as_deref()
            .map(TomlConfigLoader::new_from_str)
            .transpose()?
            .unwrap_or_else(|| active.clone());
        Ok(GetConfigResponse {
            snapshot: Some(SnapshotMeta {
                revision: state.revision,
                topology_generation: self
                    .manager
                    .get_instance_service(&id)
                    .map_or(0, |instance| {
                        instance
                            .peers()
                            .map_or(0, |peers| peers.get_route().forwarding_generation())
                    }),
                sampled_at_unix_ms: now_ms(),
            }),
            desired: Some(projection(&desired)?),
            active: Some(projection(&active)?),
            restart_fields: state.restart_fields,
            reload_error: self
                .manager
                .reload_errors
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    pub(super) async fn validate_config_inner(
        &self,
        _: BaseController,
        request: ValidateConfigRequest,
    ) -> anyhow::Result<ValidateConfigResponse> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(request.meta.as_ref())?;
        let active = self.manager.get_instance_config(&id).unwrap();
        self.reject_starting(id)?;
        let state = self
            .manager
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
            .unwrap_or_else(|| active.clone());
        let patch = request.patch.ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "A configuration patch is required.",
                "patch",
            )
        })?;
        let (desired, _) = prepare(&current, &patch, state.revision)?;
        let (_, result) = select_apply(
            &active,
            &desired,
            state.revision,
            self.manager.get_instance_service(&id).is_some(),
        )?;
        Ok(ValidateConfigResponse {
            result: Some(result),
            ..Default::default()
        })
    }

    pub(super) async fn transact(
        &self,
        meta: Option<&RequestMeta>,
        patch: ConfigPatch,
    ) -> anyhow::Result<ApplyResult> {
        let _guard = self.mutation_guard().await;
        let id = self.select_instance(meta)?;
        let active = self.manager.get_instance_config(&id).unwrap();
        self.reject_starting(id)?;
        let state = self
            .manager
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
            .unwrap_or_else(|| active.clone());
        let (desired, _) = prepare(&current, &patch, state.revision)?;
        let after = document(&desired)?;
        let running = self.manager.get_instance_service(&id);
        let (candidate, mut result) =
            select_apply(&active, &desired, state.revision, running.is_some())?;
        let rules = AclRuleBuilder::build_config(&candidate)?;
        let runtime = running
            .as_ref()
            .map(|instance| Ok::<_, anyhow::Error>((instance.context()?, instance.peers()?)))
            .transpose()?;
        let changed_desired = document(&current)? != after;
        if changed_desired {
            result.revision = state.revision.checked_add(1).ok_or_else(|| {
                failure("INTERNAL", "The configuration revision is exhausted.", "")
            })?;
        }
        if !self.from_file {
            let control = self.ensure_file(id)?;
            if control.is_read_only() {
                return Err(failure(
                    "PERMISSION_DENIED",
                    "The configuration file is read-only.",
                    "patch.persist",
                ));
            }
            let path = control.path.as_ref().unwrap();
            if path.is_dir() {
                return Err(failure(
                    "UNAVAILABLE",
                    "The configuration path is not a regular file.",
                    "patch.persist",
                ));
            }
            if path.exists() || control.expected_exists {
                persist_change(&desired, &control, Some(&current))?;
            } else {
                persist(&desired, &control)?;
            }
            let mut adopted = control;
            adopted.expected_exists = true;
            self.manager.set_instance_file_control(id, adopted)?;
        }
        active.replace_active(&candidate);
        if let Some((context, _)) = runtime {
            context.set_hostname(candidate.get_hostname());
            context.set_flags(candidate.get_flags());
            context.get_acl_filter().reload_rules(rules.as_ref());
            if let Some(level) = candidate.get_log_config().console {
                super::read::apply_log_level(&level)?;
            }
        }
        self.manager.control_configs.lock().unwrap().insert(
            id,
            ConfigState {
                revision: result.revision,
                desired: (!result.restart_fields.is_empty()).then(|| desired.dump()),
                restart_fields: result.restart_fields.clone(),
            },
        );
        self.manager.reload_errors.lock().unwrap().remove(&id);
        if let Some(instance) = running {
            let route = instance.peers()?.get_route();
            tokio::spawn(async move {
                route.refresh_acl_groups().await;
            });
        }
        Ok(result)
    }

    pub(super) async fn patch_config_inner(
        &self,
        _: BaseController,
        request: PatchConfigRequest,
    ) -> anyhow::Result<PatchConfigResponse> {
        let patch = request.patch.ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "A configuration patch is required.",
                "patch",
            )
        })?;
        Ok(PatchConfigResponse {
            result: Some(self.transact(request.meta.as_ref(), patch).await?),
            ..Default::default()
        })
    }

    fn reject_starting(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        if self
            .manager
            .iter()
            .any(|instance| *instance.key() == id && instance.is_lowertier_running())
            && self.manager.get_instance_service(&id).is_none()
        {
            return Err(failure(
                "UNAVAILABLE",
                "The instance is starting. Retry after startup.",
                "meta.instance_id",
            ));
        }
        Ok(())
    }
}
