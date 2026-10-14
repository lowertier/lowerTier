use std::sync::LazyLock;

use base64::{Engine as _, prelude::BASE64_STANDARD};

use crate::common::config::Flags;
pub use crate::proto::common::{
    CamouflageConfig, DecoyUpstream, LimitsConfig, RelayConfig, RelayLinkCost, RelayPolicy,
    RelayPrefer, TransitPolicy,
};

pub const LEGACY_KEYS: &[(&str, &str)] = &[
    ("port_mode", "automatic platform adapter selection"),
    ("interface_adapter", "automatic platform adapter selection"),
    ("source", "local configuration files"),
    ("instance_recv_bps_limit", "limits.receive_bps"),
    ("latency_first", "relay.policy"),
    ("speed_first", "relay.policy"),
    ("p2p_only", "relay.use_relays"),
    ("disable_relay_data", "relay.transit"),
    ("relay_network_whitelist", "relay.transit_networks"),
    ("foreign_relay_bps_limit", "relay.transit_bps_limit"),
    (
        "speed_probe_interval_seconds",
        "relay.probe_interval_seconds",
    ),
    ("speed_probe_budget_bps", "relay.probe_budget_bps"),
    ("quic_server_name", "camouflage.server_name"),
    ("quic_tls_cert", "camouflage.tls_cert"),
    ("quic_tls_key", "camouflage.tls_key"),
    ("quic_admission_secret", "camouflage.admission_secret"),
    ("quic_fallback_root", "camouflage.website_root"),
    ("quic_decoy_upstream", "camouflage.decoy_upstream"),
    ("quic_sni_passthrough", "camouflage.sni_routing"),
];

// WSS accepts one serialized overlay packet up to this existing receive bound.
pub(crate) const MAX_TRANSIT_PACKET_BYTES: u64 = crate::tunnel::tcp_lanes::MAX_PENDING_BYTES as u64;

impl Flags {
    pub(crate) fn memory_bytes(&self) -> Option<u64> {
        self.limits.as_ref().and_then(|limits| limits.memory_bytes)
    }

    pub fn receive_bps(&self) -> Option<u64> {
        self.limits.as_ref().and_then(|limits| limits.receive_bps)
    }
    pub fn relay_config(&self) -> &RelayConfig {
        static DEFAULT: LazyLock<RelayConfig> = LazyLock::new(RelayConfig::default);
        self.relay.as_ref().unwrap_or(&DEFAULT)
    }

    pub fn relay_config_mut(&mut self) -> &mut RelayConfig {
        self.relay.get_or_insert_with(RelayConfig::default)
    }

    pub fn camouflage_config(&self) -> &CamouflageConfig {
        static DEFAULT: LazyLock<CamouflageConfig> = LazyLock::new(CamouflageConfig::default);
        self.camouflage.as_ref().unwrap_or(&DEFAULT)
    }

    pub fn camouflage_config_mut(&mut self) -> &mut CamouflageConfig {
        self.camouflage
            .get_or_insert_with(CamouflageConfig::default)
    }
}

pub fn peer_key(value: &str) -> anyhow::Result<[u8; 32]> {
    BASE64_STANDARD
        .decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer public key must contain 32 bytes"))
}

impl RelayConfig {
    pub(crate) fn validate_local_key(&self, local_key: Option<&str>) -> anyhow::Result<()> {
        let Some(local_key) = local_key else {
            return Ok(());
        };
        let local_key = peer_key(local_key)?;
        for preference in &self.prefer {
            anyhow::ensure!(
                peer_key(&preference.peer)? != local_key && peer_key(&preference.via)? != local_key,
                "relay.prefer cannot reference the local peer key"
            );
        }
        for link in &self.link_cost {
            anyhow::ensure!(
                peer_key(&link.peer)? != local_key,
                "relay.link_cost cannot reference the local peer key"
            );
        }
        Ok(())
    }
    pub fn can_use_relays(&self) -> bool {
        self.use_relays.unwrap_or(true)
    }

    pub fn probe_interval(&self) -> u64 {
        self.probe_interval_seconds.unwrap_or(30)
    }

    pub fn permits_foreign_network(&self, name: &str) -> bool {
        self.transit_networks
            .iter()
            .any(|pattern| wildmatch::WildMatch::new(pattern).matches(name))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.prefer.len() <= 64 && self.link_cost.len() <= 256,
            "relay.prefer permits 64 entries; relay.link_cost permits 256 entries"
        );
        RelayPolicy::try_from(self.policy)?;
        TransitPolicy::try_from(self.transit)?;
        anyhow::ensure!(
            self.policy() != RelayPolicy::Goodput || self.probe_budget_bps > 0,
            "relay.policy=goodput requires a positive relay.probe_budget_bps"
        );
        if self.probe_budget_bps > 0 {
            anyhow::ensure!(
                (1..=300).contains(&self.probe_interval()),
                "relay.probe_interval_seconds must be between 1 and 300"
            );
        }
        if let Some(bits) = self.transit_bps_limit {
            anyhow::ensure!(bits > 0, "relay.transit_bps_limit must be positive");
        }
        if let Some(burst) = self.transit_burst_bytes {
            anyhow::ensure!(
                self.transit_bps_limit.is_some()
                    && burst >= MAX_TRANSIT_PACKET_BYTES
                    && burst <= u64::MAX / 8,
                "relay.transit_burst_bytes requires a limit and at least {MAX_TRANSIT_PACKET_BYTES} bytes for a maximum frame"
            );
        }
        for (index, prefer) in self.prefer.iter().enumerate() {
            peer_key(&prefer.peer)?;
            peer_key(&prefer.via)?;
            anyhow::ensure!(
                self.can_use_relays() || prefer.peer == prefer.via,
                "relay.prefer requires relay.use_relays for an intermediate first hop"
            );
            anyhow::ensure!(
                !self.prefer[..index]
                    .iter()
                    .any(|entry| entry.peer == prefer.peer),
                "duplicate relay.prefer destination"
            );
        }
        for (index, link) in self.link_cost.iter().enumerate() {
            peer_key(&link.peer)?;
            anyhow::ensure!(
                link.bias_ms <= i32::MAX as u32,
                "relay.link_cost.bias_ms exceeds the route cost range"
            );
            anyhow::ensure!(
                !self.link_cost[..index]
                    .iter()
                    .any(|entry| entry.peer == link.peer),
                "duplicate relay.link_cost peer"
            );
        }
        anyhow::ensure!(
            self.transit_networks
                .iter()
                .all(|name| !name.is_empty() && !name.contains(char::is_whitespace)),
            "relay.transit_networks must contain nonempty network name patterns"
        );
        Ok(())
    }
}

impl CamouflageConfig {
    pub fn set_decoy_upstream(&mut self, address: String) {
        self.decoy_upstream = Some(DecoyUpstream {
            tcp: address.clone(),
            udp: address,
        });
    }

    pub fn tcp_decoy(&self) -> &str {
        self.decoy_upstream
            .as_ref()
            .map_or("", |upstream| upstream.tcp.as_str())
    }

    pub fn udp_decoy(&self) -> &str {
        self.decoy_upstream
            .as_ref()
            .map_or("", |upstream| upstream.udp.as_str())
    }

    pub fn has_decoy(&self) -> bool {
        !self.tcp_decoy().is_empty() || !self.udp_decoy().is_empty()
    }

    pub fn websocket_path(&self) -> &str {
        if self.wss_path.is_empty() {
            "/ws"
        } else {
            &self.wss_path
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.tls_cert.is_empty() == self.tls_key.is_empty(),
            "camouflage.tls_cert and camouflage.tls_key must be configured together"
        );
        anyhow::ensure!(
            self.tls_cert.is_empty() || !self.server_name.is_empty(),
            "camouflage.server_name is required with a TLS certificate"
        );
        anyhow::ensure!(
            !self.sni_routing || self.has_decoy(),
            "camouflage.sni_routing requires camouflage.decoy_upstream"
        );
        anyhow::ensure!(
            self.server_name.is_empty() || !self.website_root.is_empty() || self.has_decoy(),
            "camouflage.website_root is required with camouflage.server_name"
        );
        anyhow::ensure!(
            self.server_name.is_empty()
                || (self.server_name.parse::<std::net::IpAddr>().is_err()
                    && !self.server_name.contains(['/', ':'])),
            "camouflage.server_name must be a DNS name"
        );
        anyhow::ensure!(
            self.admission_secret.is_empty() || self.admission_secret.len() >= 16,
            "camouflage.admission_secret must contain at least 16 bytes"
        );
        if self.has_decoy() {
            anyhow::ensure!(
                !self.server_name.is_empty(),
                "camouflage.server_name is required with camouflage.decoy_upstream"
            );
            anyhow::ensure!(
                self.admission_secret.len() >= 16,
                "camouflage.decoy_upstream requires camouflage.admission_secret"
            );
            for address in [self.tcp_decoy(), self.udp_decoy()]
                .into_iter()
                .filter(|address| !address.is_empty())
            {
                let endpoint = url::Url::parse(&format!("tcp://{address}"))?;
                anyhow::ensure!(
                    endpoint.port().is_some()
                        && endpoint.username().is_empty()
                        && endpoint.password().is_none()
                        && endpoint.query().is_none()
                        && endpoint.fragment().is_none()
                        && matches!(endpoint.path(), "" | "/"),
                    "camouflage.decoy_upstream must contain only a host and port"
                );
            }
        }
        anyhow::ensure!(
            self.website_root.is_empty() || std::path::Path::new(&self.website_root).is_dir(),
            "camouflage.website_root must be an existing directory"
        );
        let path = self.websocket_path();
        anyhow::ensure!(
            path.starts_with('/') && !path.contains(['?', '#']),
            "camouflage.wss_path must be an absolute HTTP path"
        );
        if !self.http_host.is_empty() {
            self.http_host.parse::<http::uri::Authority>()?;
        }
        for cidr in &self.trusted_proxy_cidrs {
            cidr.parse::<cidr::IpCidr>()?;
        }
        anyhow::ensure!(
            self.trusted_proxy_cidrs.len() <= 64,
            "camouflage.trusted_proxy_cidrs permits at most 64 entries"
        );
        Ok(())
    }
}

pub(crate) fn validate_camouflage_listeners(
    flags: &Flags,
    listeners: &[url::Url],
) -> anyhow::Result<()> {
    for listener in listeners {
        if listener.scheme() == "wss" {
            crate::tunnel::tcp_lanes::requested(listener)?;
        }
        let address = match listener.scheme() {
            "tcp" => flags.camouflage_config().tcp_decoy(),
            "quic" => flags.camouflage_config().udp_decoy(),
            _ => continue,
        };
        if address.is_empty() {
            continue;
        }
        let upstream = url::Url::parse(&format!("tcp://{address}"))?;
        let same_host = upstream.host_str() == listener.host_str()
            || (listener.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_unspecified())
            }) && upstream.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }));
        anyhow::ensure!(
            !(same_host && upstream.port() == listener.port()),
            "camouflage.decoy_upstream cannot forward to its own listener"
        );
    }
    Ok(())
}

impl std::fmt::Debug for CamouflageConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CamouflageConfig")
            .field("server_name", &self.server_name)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("admission_secret", &"[REDACTED]")
            .field("website_root", &self.website_root)
            .field("decoy_upstream", &self.decoy_upstream)
            .field("sni_routing", &self.sni_routing)
            .field("wss_path", &self.wss_path)
            .field("http_host", &self.http_host)
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn rejects_legacy_control_keys_with_replacement_names() {
        for (old, replacement) in super::LEGACY_KEYS {
            for section in ["[flags]\n", ""] {
                let text = format!("{section}{old} = false\n");
                let error =
                    crate::common::config::TomlConfigLoader::new_from_str(&text).unwrap_err();
                assert!(
                    format!("{error:#}").contains(replacement),
                    "{old}: {error:#}"
                );
            }
        }
        use crate::common::config::ConfigLoader;
        let config = crate::common::config::TomlConfigLoader::new_from_str(
            r#"
[relay]
policy = "latency"
use_relays = false
transit = "deny"
transit_networks = ["foreign-*"]
transit_bps_limit = 1
transit_burst_bytes = 262144
[limits]
receive_bps = 7
[camouflage]
wss_path = "/vpn"
http_host = "example.test"
trusted_proxy_cidrs = ["127.0.0.1/32"]
"#,
        )
        .unwrap();
        let flags = config.get_flags();
        assert_eq!(flags.relay_config().policy(), super::RelayPolicy::Latency);
        assert!(!flags.relay_config().can_use_relays());
        assert_eq!(flags.relay_config().transit(), super::TransitPolicy::Deny);
        assert_eq!(flags.relay_config().transit_bps_limit, Some(1));
        assert_eq!(flags.receive_bps(), Some(7));
        assert_eq!(flags.camouflage_config().websocket_path(), "/vpn");
        let reloaded =
            crate::common::config::TomlConfigLoader::new_from_str(&config.dump()).unwrap();
        assert_eq!(reloaded.get_flags(), flags);
    }
}
