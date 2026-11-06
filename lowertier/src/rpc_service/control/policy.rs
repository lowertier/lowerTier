use std::collections::BTreeSet;

use anyhow::{Context, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use wildmatch::WildMatch;

use crate::common::{config::ControlConfig, control_config::peer_key};

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub from: Vec<String>,
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_users: Vec<String>,
    pub expires_unix: Option<i64>,
    pub max_session_seconds: Option<u64>,
}

fn key_text(value: &str) -> &str {
    value
        .strip_prefix("pubkey:")
        .or_else(|| value.strip_prefix("x25519:"))
        .unwrap_or(value)
}

impl ControlConfig {
    pub fn secret_value(&self) -> anyhow::Result<Option<String>> {
        if self.resolved_secret.is_some() {
            return Ok(self.resolved_secret.clone());
        }
        match &self.secret_file {
            Some(path) => {
                let value =
                    std::fs::read_to_string(path).context("Cannot read control.secret_file")?;
                let value = value.trim_end_matches(['\r', '\n']).to_owned();
                ensure!(!value.is_empty(), "control.secret_file must not be empty");
                Ok(Some(value))
            }
            None => Ok(self.secret.clone()),
        }
    }

    pub fn resolve_key(&self, selector: &str) -> anyhow::Result<[u8; 32]> {
        let selector = if selector == "default" {
            self.default
                .as_deref()
                .context("control.default is not configured")?
        } else {
            selector
        };
        if let Some(key) = self.keys.get(selector) {
            return peer_key(key_text(key));
        }
        let text = key_text(selector);
        if let Some(prefix) = text.strip_suffix("...") {
            ensure!(!prefix.is_empty(), "The key prefix is empty");
            let matches = self
                .keys
                .values()
                .filter(|key| key_text(key).starts_with(prefix))
                .map(|key| peer_key(key_text(key)))
                .collect::<anyhow::Result<BTreeSet<_>>>()?;
            ensure!(matches.len() == 1, "The key prefix is unknown or ambiguous");
            return Ok(*matches.first().unwrap());
        }
        peer_key(text).context("Use a complete public key or a configured control.keys alias")
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.keys.len() <= 4096
                && self.groups.len() <= 256
                && self.grant.len() <= 256
                && self.allow.len() <= 256,
            "The control policy exceeds its entry limit"
        );
        ensure!(
            self.groups.values().map(Vec::len).sum::<usize>() <= 4096
                && self
                    .grant
                    .iter()
                    .map(|grant| grant.from.len())
                    .sum::<usize>()
                    <= 4096,
            "The control policy exceeds its total selector limit"
        );
        ensure!(
            !(self.secret.is_some() && self.secret_file.is_some()),
            "Use control.secret or control.secret_file, not both"
        );
        if let Some(secret) = &self.secret {
            ensure!(!secret.is_empty(), "control.secret must not be empty");
        }
        for (alias, value) in &self.keys {
            ensure!(
                alias != "secret" && alias != "default",
                "control.keys cannot use the reserved names secret or default"
            );
            ensure!(
                !alias.is_empty()
                    && alias.len() <= 128
                    && alias
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
                "control.keys aliases must contain letters, digits, hyphens, underscores, or periods"
            );
            peer_key(key_text(value)).context("control.keys must contain complete public keys")?;
        }
        if let Some(default) = &self.default {
            self.resolve_key(default)?;
        }
        for members in self.groups.values() {
            ensure!(
                members.len() <= 4096,
                "The control group exceeds its entry limit"
            );
            for member in members {
                self.resolve_key(member)?;
            }
        }
        for selector in self
            .allow
            .iter()
            .chain(self.grant.iter().flat_map(|grant| &grant.from))
        {
            self.validate_selector(selector)?;
        }
        for grant in &self.grant {
            ensure!(
                !grant.from.is_empty() && !grant.permissions.is_empty(),
                "A control grant requires from and permissions"
            );
            ensure!(
                grant.from.len() <= 256
                    && grant.permissions.len() <= 64
                    && grant.config_paths.len() <= 256
                    && grant.ssh_users.len() <= 64,
                "The control grant exceeds its entry limit"
            );
            ensure!(
                grant
                    .max_session_seconds
                    .is_none_or(|seconds| (1..=86400).contains(&seconds)),
                "max_session_seconds must be between 1 and 86400"
            );
            for permission in &grant.permissions {
                ensure!(
                    CAPABILITIES
                        .iter()
                        .any(|known| WildMatch::new(permission).matches(known)),
                    "Unknown control permission"
                );
            }
            for path in &grant.config_paths {
                let prefix = path.trim_end_matches('*').trim_end_matches('.');
                ensure!(
                    path == "*"
                        || crate::common::config_schema::OPTIONS
                            .iter()
                            .any(|option| option.path == prefix
                                || option.path.starts_with(&format!("{prefix}."))),
                    "Unknown control configuration path"
                );
            }
            ensure!(
                grant.ssh_users.iter().all(|user| user == "*"
                    || (!user.is_empty()
                        && !user.starts_with('-')
                        && user
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)))),
                "Invalid SSH account selector"
            );
        }
        Ok(())
    }

    fn validate_selector(&self, selector: &str) -> anyhow::Result<()> {
        if selector == "*" || selector == "secret" {
            return Ok(());
        }
        if let Some(group) = selector.strip_prefix("group:") {
            ensure!(
                self.groups
                    .keys()
                    .any(|name| WildMatch::new(group).matches(name)),
                "Unknown control group"
            );
        } else if selector.contains('*') || selector.contains('?') {
            ensure!(
                self.keys
                    .keys()
                    .any(|name| WildMatch::new(selector).matches(name)),
                "Unknown control key alias pattern"
            );
        } else {
            self.resolve_key(selector)?;
        }
        Ok(())
    }

    fn matches(&self, selector: &str, key: &[u8; 32], network_member: bool, secret: bool) -> bool {
        match selector {
            "*" => network_member,
            "secret" => secret,
            _ => {
                if let Some(group) = selector.strip_prefix("group:") {
                    self.groups
                        .iter()
                        .filter(|(name, _)| WildMatch::new(group).matches(name))
                        .flat_map(|(_, members)| members)
                        .any(|member| self.resolve_key(member).ok().as_ref() == Some(key))
                } else if selector.contains('*') || selector.contains('?') {
                    self.keys
                        .keys()
                        .filter(|name| WildMatch::new(selector).matches(name))
                        .any(|name| self.resolve_key(name).ok().as_ref() == Some(key))
                } else {
                    self.resolve_key(selector).ok().as_ref() == Some(key)
                }
            }
        }
    }

    pub fn full_access(&self, key: &[u8; 32], network_member: bool, secret: bool) -> bool {
        // A configured shared secret retains the simple full-control form unless grants scope it.
        let scoped_secret = self
            .grant
            .iter()
            .any(|grant| grant.from.iter().any(|from| from == "secret"));
        (secret && !scoped_secret)
            || self
                .allow
                .iter()
                .any(|selector| self.matches(selector, key, network_member, secret))
    }

    pub fn permits(
        &self,
        key: &[u8; 32],
        network_member: bool,
        secret: bool,
        capability: &str,
        path: Option<&str>,
        user: Option<&str>,
        age_seconds: u64,
    ) -> bool {
        if self.full_access(key, network_member, secret) {
            return true;
        }
        let now = crate::peers::credential_manager::current_unix_timestamp();
        self.grant.iter().any(|grant| {
            let admin = grant
                .permissions
                .iter()
                .any(|permission| WildMatch::new(permission).matches("admin"));
            grant.expires_unix.is_none_or(|expiry| expiry > now)
                && grant
                    .max_session_seconds
                    .is_none_or(|maximum| age_seconds < maximum)
                && grant
                    .from
                    .iter()
                    .any(|selector| self.matches(selector, key, network_member, secret))
                && (admin
                    || grant
                        .permissions
                        .iter()
                        .any(|permission| WildMatch::new(permission).matches(capability)))
                && (admin
                    || path.is_none_or(|path| {
                        grant.config_paths.iter().any(|pattern| {
                            pattern == "*"
                                || pattern == path
                                || WildMatch::new(pattern).matches(path)
                                || pattern
                                    .strip_suffix(".*")
                                    .is_some_and(|prefix| prefix == path)
                        })
                    }))
                && (admin
                    || user.is_none_or(|user| {
                        grant
                            .ssh_users
                            .iter()
                            .any(|allowed| allowed == "*" || allowed == user)
                    }))
        })
    }
}

pub const CAPABILITIES: &[&str] = &[
    "admin",
    "status.read",
    "config.read",
    "config.write",
    "logs.read",
    "logs.write",
    "credentials.read",
    "credentials.write",
    "instances.read",
    "instances.start",
    "instances.stop",
    "instances.delete",
    "ssh",
];

pub fn public_key_text(key: &[u8; 32]) -> String {
    BASE64_STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_decode_errors_do_not_include_key_material() {
        let material = "private-key-test-value!?";
        let config = crate::proto::common::SecureModeConfig {
            local_private_key: Some(material.into()),
            ..Default::default()
        };
        let error = config
            .private_key()
            .err()
            .expect("invalid private key must fail");
        assert!(!format!("{error:#}").contains(material));
    }

    #[test]
    fn grants_pin_keys_and_bound_configuration_and_ssh_access() {
        let key = [17; 32];
        let other = [18; 32];
        let mut policy = ControlConfig::default();
        policy.keys.insert("operator".into(), public_key_text(&key));
        policy.grant.push(Grant {
            from: vec!["operator".into()],
            permissions: vec!["status.read".into(), "config.write".into(), "ssh".into()],
            config_paths: vec!["relay.*".into()],
            ssh_users: vec!["deploy".into()],
            ..Default::default()
        });
        policy.validate().unwrap();
        assert!(policy.permits(
            &key,
            true,
            false,
            "config.write",
            Some("relay.policy"),
            None,
            0
        ));
        assert!(!policy.permits(
            &key,
            true,
            false,
            "config.write",
            Some("control.allow"),
            None,
            0
        ));
        assert!(policy.permits(&key, true, false, "ssh", None, Some("deploy"), 0));
        assert!(!policy.permits(&key, true, false, "ssh", None, Some("root"), 0));
        assert!(!policy.permits(&other, true, false, "status.read", None, None, 0));
        let prefix = format!("{}...", &public_key_text(&key)[..6]);
        assert_eq!(policy.resolve_key(&prefix).unwrap(), key);
        let mut duplicate_prefix = key;
        duplicate_prefix[31] += 1;
        policy
            .keys
            .insert("second".into(), public_key_text(&duplicate_prefix));
        assert!(policy.resolve_key(&prefix).is_err());
        policy.allow = vec!["*".into()];
        assert!(policy.full_access(&other, true, false));
        assert!(!policy.full_access(&other, false, false));
    }
}
