use std::{collections::BTreeSet, sync::LazyLock};

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, SerializeOptions};
use serde_json::Value;

use crate::{
    common::{
        acl_processor::AclRuleBuilder,
        config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
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

static POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(crate::proto::ALL_DESCRIPTOR_BYTES)
        .expect("The control schema is valid.")
});

const SECRET_PATHS: &[&str] = &[
    "network_identity.network_secret",
    "network_identity.network_secret_digest",
    "secure_mode.local_private_key",
    "secure_mode.credential_bundle",
    "secure_mode.credential_certificate",
    "camouflage.admission_secret",
];

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

fn prune_nulls(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            object.values_mut().for_each(prune_nulls);
        }
        Value::Array(array) => array.iter_mut().for_each(prune_nulls),
        _ => {}
    }
}

fn typed_value(config: &NodeConfig) -> anyhow::Result<Value> {
    let descriptor = POOL
        .get_message_by_name("api.control.v1.NodeConfig")
        .unwrap();
    let message = DynamicMessage::decode(descriptor, config.encode_to_vec().as_slice())?;
    // Include zero scalars so masks can set false, zero, and empty arrays.
    let options = SerializeOptions::new()
        .use_proto_field_name(true)
        .skip_default_fields(false);
    let mut value = message.serialize_with_options(serde_json::value::Serializer, &options)?;
    prune_nulls(&mut value);
    for path in [
        "flags.relay",
        "flags.camouflage",
        "flags.limits",
        "flags.port_mode",
        "flags.interface_adapter",
    ] {
        set_path(&mut value, path, None);
    }
    Ok(value)
}

fn document(config: &TomlConfigLoader) -> anyhow::Result<Value> {
    let mut document = serde_json::to_value(config.dump().parse::<toml::Value>()?)?;
    document.as_object_mut().unwrap().remove("source");
    document["flags"] = typed_value(&NodeConfig {
        flags: Some(config.get_flags()),
        ..Default::default()
    })?["flags"]
        .clone();
    for path in [
        "flags.relay",
        "flags.camouflage",
        "flags.limits",
        "flags.port_mode",
        "flags.interface_adapter",
    ] {
        set_path(&mut document, path, None);
    }
    Ok(document)
}

fn parse(document: &Value) -> anyhow::Result<TomlConfigLoader> {
    let value = toml::Value::try_from(document)?;
    TomlConfigLoader::new_from_str(&toml::to_string(&value)?)
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
                    *text = "[REDACTED]".into();
                }
            }
        }
        _ => {}
    }
}

fn projection(config: &TomlConfigLoader) -> anyhow::Result<NodeConfig> {
    let mut value = document(config)?;
    for path in SECRET_PATHS {
        set_path(&mut value, path, None);
    }
    if let Some(declares) = value
        .pointer_mut("/acl/acl_v1/group/declares")
        .and_then(Value::as_array_mut)
    {
        for declaration in declares {
            declaration["group_secret"] = "[REDACTED]".into();
        }
    }
    redact_urls(&mut value);
    serde_json::from_value(value).map_err(Into::into)
}

fn valid_path(path: &str) -> anyhow::Result<()> {
    for (old, replacement) in crate::common::control_config::LEGACY_KEYS {
        if path == *old || path == format!("flags.{old}") {
            return Err(failure(
                "INVALID_ARGUMENT",
                &format!("Use {replacement}."),
                path,
            ));
        }
    }
    let mut descriptor = POOL
        .get_message_by_name("api.control.v1.NodeConfig")
        .unwrap();
    let parts = path.split('.').collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let field = descriptor.get_field_by_name(part).ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "The configuration path is unknown.",
                path,
            )
        })?;
        if field
            .field_descriptor_proto()
            .options
            .as_ref()
            .is_some_and(|options| options.deprecated.unwrap_or(false))
            || path.starts_with("flags.relay")
            || path.starts_with("flags.camouflage")
            || path.starts_with("flags.limits")
        {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Use a canonical top-level configuration section.",
                path,
            ));
        }
        if index + 1 < parts.len() {
            descriptor = match field.kind() {
                Kind::Message(descriptor) if !field.is_list() && !field.is_map() => descriptor,
                _ => {
                    return Err(failure(
                        "INVALID_ARGUMENT",
                        "Arrays must be replaced completely.",
                        path,
                    ));
                }
            };
        }
    }
    Ok(())
}

fn contains_placeholder(value: &Value) -> bool {
    match value {
        Value::String(value) => matches!(value.as_str(), "[REDACTED]" | "<redacted>" | "***"),
        Value::Object(object) => object.values().any(contains_placeholder),
        Value::Array(array) => array.iter().any(contains_placeholder),
        _ => false,
    }
}

fn changed_paths(before: &Value, after: &Value, path: &str, changed: &mut Vec<String>) {
    if before == after {
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
    if path == "hostname"
        || path.starts_with("relay.")
        || path.starts_with("limits.")
        || matches!(
            path,
            "relay" | "limits" | "acl" | "tcp_whitelist" | "udp_whitelist"
        )
        || path.starts_with("acl.")
    {
        "live"
    } else if path.starts_with("camouflage.") || path == "camouflage" {
        if quic
            && matches!(
                path,
                "camouflage"
                    | "camouflage.tls_cert"
                    | "camouflage.tls_key"
                    | "camouflage.server_name"
                    | "camouflage.admission_secret"
                    | "camouflage.website_root"
                    | "camouflage.decoy_upstream"
                    | "camouflage.decoy_upstream.tcp"
                    | "camouflage.decoy_upstream.udp"
                    | "camouflage.sni_routing"
            )
        {
            "restart"
        } else {
            "new_connection"
        }
    } else {
        "restart"
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
    let values = typed_value(&patch.values.clone().unwrap_or_default())?;
    let mut after = before.clone();
    for path in &patch.field_mask {
        let mut value = values
            .pointer(&pointer(path))
            .cloned()
            .ok_or_else(|| failure("INVALID_ARGUMENT", "The masked value is absent.", path))?;
        for groups_path in [
            "acl.acl_v1.group.declares",
            "acl_v1.group.declares",
            "group.declares",
            "declares",
            "",
        ] {
            if format!("{path}.{groups_path}").trim_end_matches('.') != "acl.acl_v1.group.declares"
            {
                continue;
            }
            let declarations = if groups_path.is_empty() {
                value.as_array_mut()
            } else {
                value
                    .pointer_mut(&pointer(groups_path))
                    .and_then(Value::as_array_mut)
            };
            if let Some(declarations) = declarations {
                for declaration in declarations {
                    if declaration["group_secret"] == "[REDACTED]" {
                        let name = declaration["group_name"].clone();
                        if let Some(previous) = before
                            .pointer("/acl/acl_v1/group/declares")
                            .and_then(Value::as_array)
                            .and_then(|groups| {
                                groups.iter().find(|group| group["group_name"] == name)
                            })
                        {
                            declaration["group_secret"] = previous["group_secret"].clone();
                        }
                    }
                }
            }
        }
        if contains_placeholder(&value) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "Redacted values cannot set configuration fields.",
                path,
            ));
        }
        // A parent replacement preserves secrets unless their own paths are explicit.
        for secret in SECRET_PATHS {
            if let Some(child) = secret.strip_prefix(&format!("{path}.")) {
                set_path(&mut value, child, before.pointer(&pointer(secret)).cloned());
            }
        }
        set_path(&mut after, path, Some(value));
    }
    for path in &patch.clear_paths {
        set_path(&mut after, path, None);
    }
    if after["instance_id"] != before["instance_id"] {
        return Err(failure(
            "INVALID_ARGUMENT",
            "The instance ID cannot change.",
            "instance_id",
        ));
    }
    let candidate = parse(&after).map_err(|_| {
        failure(
            "INVALID_ARGUMENT",
            "The configuration values are invalid.",
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

fn validate_values(config: &TomlConfigLoader, document: &Value) -> anyhow::Result<()> {
    for (key, ipv6) in [
        ("ipv4", false),
        ("ipv6", true),
        ("ipv6_public_addr_prefix", true),
    ] {
        if let Some(value) = document[key].as_str() {
            let valid = if key == "ipv6_public_addr_prefix" {
                value.parse::<cidr::Ipv6Cidr>().is_ok()
            } else if ipv6 {
                value.parse::<cidr::Ipv6Inet>().is_ok()
            } else {
                value.parse::<cidr::Ipv4Inet>().is_ok()
            };
            if !valid {
                return Err(failure(
                    "INVALID_ARGUMENT",
                    "The IP address or prefix is invalid.",
                    key,
                ));
            }
        }
    }
    for uri in config.get_mapped_listeners() {
        crate::common::config::validate_mapped_listener_url(&uri).map_err(|_| {
            failure(
                "INVALID_ARGUMENT",
                "The mapped listener is invalid.",
                "mapped_listeners",
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
                "port_forward",
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

fn persist(config: &TomlConfigLoader, control: &ConfigFileControl) -> anyhow::Result<()> {
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
    temporary
        .write_all(config.dump().as_bytes())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| {
            failure(
                "UNAVAILABLE",
                "The configuration file cannot be written.",
                "patch.persist",
            )
        })?;
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
        match if running {
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
    Ok((parse(&published)?, result))
}

impl ControlPlaneService {
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
        let advertised = context.get_feature_flags();
        Ok(GetRelayResponse {
            snapshot: Some(self.snapshot(&instance).await?),
            config: Some(flags.relay_config().clone()),
            total_bytes,
            counters,
            desired_permission: desired.relay_config().transit().as_str_name().into(),
            advertised_permission: if advertised.deny_transit_data {
                "deny"
            } else if advertised.avoid_relay_data {
                "avoid"
            } else {
                "allow"
            }
            .into(),
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
            quic_h2_verification: if !config.server_name.is_empty() && !config.has_decoy() {
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
        let value = typed_value(&values)?;
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
            config,
            ConfigFileControl::new(
                None,
                crate::common::config::ConfigFilePermission::READ_ONLY.into(),
            ),
        )?;
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
        let previous = TomlConfigLoader::new_from_str(&active.dump())?;
        let state = self
            .manager
            .control_configs
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .unwrap_or_default();
        if let Some(desired) = &state.desired {
            active.replace_active(&TomlConfigLoader::new_from_str(desired)?);
        }
        if let Err(error) = self.manager.start_network_instance(id) {
            active.replace_active(&previous);
            return Err(error);
        }
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
        self.manager.delete_network_instance(vec![id])?;
        self.manager.control_configs.lock().unwrap().remove(&id);
        Ok(DeleteInstanceResponse::default())
    }

    pub(super) async fn set_acl_inner(
        &self,
        _: BaseController,
        request: SetAclRequest,
    ) -> anyhow::Result<SetAclResponse> {
        let patch = ConfigPatch {
            expected_revision: request.expected_revision,
            field_mask: vec!["acl".into(), "tcp_whitelist".into(), "udp_whitelist".into()],
            values: Some(NodeConfig {
                acl: Some(request.acl.unwrap_or_default()),
                tcp_whitelist: request.tcp_whitelist,
                udp_whitelist: request.udp_whitelist,
                ..Default::default()
            }),
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
        let mut values = config.desired.unwrap();
        values
            .port_forward
            .retain(|entry| entry.bind_addr != row.bind_addr || entry.proto != row.proto);
        values.port_forward.push(row);
        Ok(PutPortForwardResponse {
            result: Some(
                self.transact(
                    request.meta.as_ref(),
                    ConfigPatch {
                        expected_revision: request.expected_revision,
                        field_mask: vec!["port_forward".into()],
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
        let mut values = config.desired.unwrap();
        let previous = values.port_forward.len();
        values
            .port_forward
            .retain(|entry| entry.bind_addr != request.bind_addr || entry.proto != request.proto);
        if values.port_forward.len() == previous {
            return Err(failure(
                "NOT_FOUND",
                "The port forward does not exist.",
                "bind_addr",
            ));
        }
        Ok(DeletePortForwardResponse {
            result: Some(
                self.transact(
                    request.meta.as_ref(),
                    ConfigPatch {
                        expected_revision: request.expected_revision,
                        field_mask: vec!["port_forward".into()],
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
        if !patch.stage && !result.restart_fields.is_empty() {
            return Err(failure(
                "RESTART_REQUIRED",
                "Stage the configuration or stop the instance before this change.",
                &result.restart_fields[0],
            ));
        }
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
        if patch.persist {
            persist(
                &desired,
                &self.manager.get_instance_config_control(&id).unwrap(),
            )?;
        }
        active.replace_active(&candidate);
        if let Some((context, _)) = runtime {
            context.set_hostname(candidate.get_hostname());
            context.set_flags(candidate.get_flags());
            context.get_acl_filter().reload_rules(rules.as_ref());
        }
        self.manager.control_configs.lock().unwrap().insert(
            id,
            ConfigState {
                revision: result.revision,
                desired: (!result.restart_fields.is_empty()).then(|| desired.dump()),
                restart_fields: result.restart_fields.clone(),
            },
        );
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
