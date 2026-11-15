use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::IpAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use dashmap::{DashMap, DashSet};
use quanta::Instant;
use tokio::{task::JoinSet, time::timeout};

use crate::{
    common::{dns::socket_addrs, join_joinset_background},
    proto::api::instance::{Connector, ConnectorStatus},
    tunnel::IpVersion,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    peers::peer_manager::PeerManager,
    use_global_var,
};

use super::create_connector_by_url;

/// Bootstrap ownership and retry state.
///
/// Registered targets and reconnecting targets are disjoint.
/// The seed mutex serializes every state transition.
/// A reconnect task can outlive its last owner. Completion discards an unowned target.
struct ConnectorManagerData {
    connectors: DashSet<url::Url>,
    reconnecting: DashSet<url::Url>,
    cold_until: DashMap<url::Url, tokio::time::Instant>,
    /// Consecutive failed reconnects per URL. The cold wait doubles from 15 s with each one.
    failures: DashMap<url::Url, u32>,
    /// Supplied seed URLs own effective transport URLs. Flag changes do not change ownership keys.
    seeds: std::sync::Mutex<BTreeMap<url::Url, BTreeSet<url::Url>>>,
    peer_manager: Weak<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

pub struct ManualConnectorManager {
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    /// Reconcile bootstrap URLs with one accepted configuration.
    ///
    /// Remove obsolete URLs before adding replacements. Shared transport alternatives remain
    /// registered while another seed owns them. An already absent URL needs no removal.
    /// New URLs use the candidate flags, including its WSS path and enabled transports.
    /// The control API holds its mutation lock until this method finishes.
    pub(crate) fn sync_configuration(
        &self,
        old_peers: &[crate::common::config::PeerConfig],
        candidate: &crate::common::config::TomlConfigLoader,
    ) {
        use crate::common::config::ConfigLoader;

        let flags = candidate.get_flags();
        let old_urls: BTreeSet<_> = old_peers.iter().map(|peer| &peer.uri).collect();
        let new_peers = candidate.get_peers();
        let new_urls: BTreeSet<_> = new_peers.iter().map(|peer| &peer.uri).collect();
        for url in old_urls.difference(&new_urls) {
            if let Err(error) = self.remove_connector((*url).clone()) {
                tracing::debug!(%url, ?error, "bootstrap connector was already absent");
            }
        }
        for url in new_urls.difference(&old_urls) {
            self.add_connector_by_url_with_flags((*url).clone(), &flags);
        }
    }

    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let tasks = JoinSet::new();

        let mut ret = Self {
            data: Arc::new(ConnectorManagerData {
                connectors: DashSet::new(),
                reconnecting: DashSet::new(),
                cold_until: DashMap::new(),
                failures: DashMap::new(),
                seeds: std::sync::Mutex::new(BTreeMap::new()),
                peer_manager: Arc::downgrade(&peer_manager),
                global_ctx,
            }),
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_reconn_routine(ret.data.clone()));

        ret
    }

    fn reconnect_timeout(_dead_url: &url::Url) -> Duration {
        // Transport setup and Noise admission span several RTTs on a satellite path.
        Duration::from_secs(20)
    }

    fn strict_reconnect_ip_versions(dead_url: &url::Url) -> Vec<IpVersion> {
        match dead_url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
        {
            Some(IpAddr::V4(_)) => vec![IpVersion::V4],
            Some(IpAddr::V6(_)) => vec![IpVersion::V6],
            None => vec![IpVersion::Both],
        }
    }

    fn remaining_budget(started_at: Instant, total_timeout: Duration) -> Option<Duration> {
        let remaining = total_timeout.checked_sub(started_at.elapsed())?;
        (!remaining.is_zero()).then_some(remaining)
    }

    fn emit_connect_error(
        data: &ConnectorManagerData,
        dead_url: &url::Url,
        ip_version: IpVersion,
        error: &Error,
    ) {
        data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
            dead_url.to_string(),
            format!("{:?}", ip_version),
            format!("{:#?}", error),
        ));
    }

    fn reconnect_timeout_error(stage: &str, duration: Duration) -> Error {
        Error::AnyhowError(anyhow::anyhow!("{} timeout after {:?}", stage, duration))
    }

    async fn with_reconnect_timeout<T, F>(
        stage: &'static str,
        started_at: Instant,
        total_timeout: Duration,
        fut: F,
    ) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        let remaining = Self::remaining_budget(started_at, total_timeout)
            .ok_or_else(|| Self::reconnect_timeout_error(stage, started_at.elapsed()))?;
        timeout(remaining, fut)
            .await
            .map_err(|_| Self::reconnect_timeout_error(stage, remaining))?
    }
}

impl ManualConnectorManager {
    /// Register one transport URL without creating alternatives.
    ///
    /// Existing alternatives for the same seed remain registered.
    /// Retries build connectors from current flags.
    pub fn add_single_connector_by_url(&self, seed: url::Url) {
        let member = crate::tunnel::websocket::effective_wss_url(
            seed.clone(),
            &self.data.global_ctx.get_flags(),
        );
        let mut seeds = self.data.seeds.lock().unwrap();
        seeds.entry(seed).or_default().insert(member.clone());
        if !self.data.reconnecting.contains(&member) {
            self.data.connectors.insert(member);
        }
    }

    /// Register a bootstrap URL and its enabled transport alternatives.
    ///
    /// Registration does not dial. The reconnect task reports dialing and authentication failures.
    pub fn add_connector_by_url(&self, url: url::Url) {
        self.add_connector_by_url_with_flags(url, &self.data.global_ctx.get_flags());
    }

    pub(crate) fn add_connector_by_url_with_flags(
        &self,
        url: url::Url,
        flags: &crate::common::config::Flags,
    ) {
        let seed = crate::tunnel::websocket::effective_wss_url(url.clone(), flags);
        let mut members = BTreeSet::new();
        members.insert(seed.clone());
        // A shared custom port can serve H3, H2, and WSS. Default ports retain their protocol mapping.
        if !seed.query_pairs().any(|(key, _)| key == "via") {
            let source_default = crate::tunnel::IpScheme::try_from(&seed)
                .ok()
                .map(|scheme| scheme.default_port());
            for protocol in crate::common::config::TRANSPORT_PROTOCOLS {
                if !crate::common::config::transport_protocol_enabled(flags, protocol)
                    || protocol == seed.scheme()
                {
                    continue;
                }
                let Ok(mut alternate) = url::Url::parse(&format!(
                    "{protocol}{}",
                    &seed.as_str()[seed.scheme().len()..]
                )) else {
                    continue;
                };
                let source_port = seed.port_or_known_default().or(source_default);
                let tcp_port = crate::tunnel::IpScheme::H2.default_port();
                let quic_port = crate::tunnel::IpScheme::Quic.default_port();
                let port = if source_port == Some(tcp_port) || source_port == Some(quic_port) {
                    Some(if protocol == "h2" {
                        tcp_port
                    } else {
                        quic_port
                    })
                } else {
                    source_port
                };
                if let Some(port) = port {
                    let _ = alternate.set_port(Some(port));
                }
                alternate.set_path("");
                if protocol == "quic" {
                    let query = alternate
                        .query_pairs()
                        .filter(|(key, _)| key != "lanes")
                        .map(|(key, value)| (key.into_owned(), value.into_owned()))
                        .collect::<Vec<_>>();
                    alternate.set_query(None);
                    if !query.is_empty() {
                        alternate.query_pairs_mut().extend_pairs(query);
                    }
                }
                members.insert(crate::tunnel::websocket::effective_wss_url(
                    alternate, flags,
                ));
            }
        }
        self.register_seed(url, members);
    }

    /// Publish ownership and registration under one lock.
    ///
    /// Replacing a seed removes its unshared old targets.
    /// A target already reconnecting keeps its current attempt and receives no duplicate registration.
    fn register_seed(&self, seed: url::Url, members: BTreeSet<url::Url>) {
        let mut seeds = self.data.seeds.lock().unwrap();
        let previous = seeds.insert(seed, members.clone()).unwrap_or_default();
        for member in previous.difference(&members) {
            if !seeds.values().any(|members| members.contains(member)) {
                Self::remove_target(&self.data, member);
            }
        }
        for member in members {
            if !self.data.reconnecting.contains(&member) {
                self.data.connectors.insert(member);
            }
        }
    }

    /// Remove a seed or one listed transport target from retry registration.
    ///
    /// A supplied seed releases its transport alternatives, even after flag changes.
    /// A seed URL takes precedence when it also names a listed target.
    /// An alternative remains registered while another seed owns it.
    /// A listed target is removed from every seed that contains it.
    /// An ongoing dial can finish. Its result cannot register an unowned target again.
    /// Established peer connections remain open. Unknown targets return [`Error::NotFound`].
    pub fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        let mut seeds = self.data.seeds.lock().unwrap();
        let removed = if let Some(members) = seeds.remove(&url) {
            members
        } else {
            let url =
                crate::tunnel::websocket::effective_wss_url(url, &self.data.global_ctx.get_flags());
            if !seeds.values().any(|members| members.contains(&url)) {
                return Err(Error::NotFound);
            }
            for members in seeds.values_mut() {
                members.remove(&url);
            }
            BTreeSet::from([url])
        };
        for member in removed {
            if !seeds.values().any(|members| members.contains(&member)) {
                Self::remove_target(&self.data, &member);
            }
        }
        Ok(())
    }

    /// List registered targets and owned reconnect attempts.
    ///
    /// Owned attempts report `Connecting`.
    /// Registered targets report `Connected`, `Disconnected`, or `ColdRetry` from peer state and retry deadlines.
    /// Removed targets stay hidden while existing attempts finish.
    pub async fn list_connectors(&self) -> Vec<Connector> {
        let seeds = self.data.seeds.lock().unwrap();
        let dead_urls = Self::collect_dead_conns(&self.data);

        let mut ret = Vec::new();

        for item in self.data.connectors.iter() {
            let conn_url = item.key().clone();
            let mut status = ConnectorStatus::Connected;
            let mut retry_after_seconds = 0;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
                if let Some(deadline) = self.data.cold_until.get(&conn_url)
                    && *deadline > tokio::time::Instant::now()
                {
                    status = ConnectorStatus::ColdRetry;
                    retry_after_seconds = deadline
                        .duration_since(tokio::time::Instant::now())
                        .as_secs()
                        .saturating_add(1);
                }
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: status.into(),
                    retry_after_seconds,
                },
            );
        }

        let reconnecting_urls: BTreeSet<url::Url> =
            self.data.reconnecting.iter().map(|x| x.clone()).collect();

        for conn_url in reconnecting_urls {
            if !seeds.values().any(|members| members.contains(&conn_url)) {
                continue;
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: ConnectorStatus::Connecting.into(),
                    retry_after_seconds: 0,
                },
            );
        }

        ret
    }

    /// Claim disconnected targets on each timer tick.
    ///
    /// Each target has one reconnect task. Completion updates registration directly.
    /// Removal and re-registration use the same ownership lock as these state transitions.
    async fn conn_mgr_reconn_routine(data: Arc<ConnectorManagerData>) {
        tracing::warn!("conn_mgr_routine started");
        let mut reconn_interval = tokio::time::interval(std::time::Duration::from_millis(
            use_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        ));
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "connector_reconnect_tasks".to_string());

        loop {
            reconn_interval.tick().await;
            for dead_url in Self::collect_dead_conns(&data) {
                if !Self::begin_reconnect(&data, &dead_url) {
                    continue;
                }
                let data = data.clone();
                tasks.lock().unwrap().spawn(async move {
                    let result = Self::conn_reconnect(data.clone(), dead_url.clone()).await;
                    Self::finish_reconnect(&data, dead_url, result.is_err());
                });
            }
        }
    }

    /// Claim a registered target unless its retry delay remains active.
    ///
    /// A stale candidate can disappear after collection. Only a successful removal starts a task.
    fn begin_reconnect(data: &ConnectorManagerData, url: &url::Url) -> bool {
        let _seeds = data.seeds.lock().unwrap();
        if data
            .cold_until
            .get(url)
            .is_some_and(|deadline| *deadline > tokio::time::Instant::now())
        {
            return false;
        }
        if data.connectors.remove(url).is_none() {
            return false;
        }
        data.reconnecting.insert(url.clone());
        true
    }

    /// Complete one attempt without restoring targets that lost every owner.
    ///
    /// A re-added target returns to registration. A failure sets its retry delay.
    /// A success clears retry history. An unowned target loses registration and retry history.
    fn finish_reconnect(data: &ConnectorManagerData, url: url::Url, failed: bool) {
        let seeds = data.seeds.lock().unwrap();
        data.reconnecting.remove(&url);
        if !seeds.values().any(|members| members.contains(&url)) {
            Self::remove_target(data, &url);
            return;
        }
        if failed {
            let failures = {
                let mut entry = data.failures.entry(url.clone()).or_insert(0);
                *entry = entry.saturating_add(1);
                *entry
            };
            data.cold_until.insert(
                url.clone(),
                tokio::time::Instant::now() + super::retry_backoff(failures),
            );
        } else {
            data.cold_until.remove(&url);
            data.failures.remove(&url);
        }
        data.connectors.insert(url);
    }

    /// Remove registration and retry history. An existing reconnect task finishes separately.
    fn remove_target(data: &ConnectorManagerData, url: &url::Url) {
        data.connectors.remove(url);
        data.cold_until.remove(url);
        data.failures.remove(url);
    }

    fn collect_dead_conns(data: &ConnectorManagerData) -> BTreeSet<url::Url> {
        let mut ret = BTreeSet::new();
        let Some(pm) = data.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, exit");
            return ret;
        };
        for url in data.connectors.iter().map(|x| x.key().clone()) {
            if !pm.get_peer_map().is_client_url_alive(&url)
                && !pm
                    .get_foreign_network_client()
                    .get_peer_map()
                    .is_client_url_alive(&url)
            {
                ret.insert(url.clone());
            }
        }
        ret
    }

    /// Resolve public key pins through supplied seed URLs.
    ///
    /// Transport alternatives share their seed's pin. Camouflage paths do not change the pin owner.
    /// Seeds without a pin permit normal network authentication.
    /// Conflicting pins from overlapping seeds return [`Error::SecretKeyError`] before dialing.
    fn seed_public_key(
        data: &ConnectorManagerData,
        member: &url::Url,
    ) -> Result<Option<String>, Error> {
        let configured = data.global_ctx.config.get_peers();
        let seeds = data.seeds.lock().unwrap();
        let mut selected = None;
        for (seed, _) in seeds.iter().filter(|(_, members)| members.contains(member)) {
            for peer in configured.iter().filter(|peer| peer.uri == *seed) {
                if let Some(key) = &peer.peer_public_key {
                    if selected.as_ref().is_some_and(|selected| selected != key) {
                        return Err(Error::SecretKeyError(
                            "overlapping seeds have different public-key pins".into(),
                        ));
                    }
                    selected = Some(key.clone());
                }
            }
        }
        Ok(selected)
    }

    async fn conn_reconnect_with_ip_version(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
        ip_version: IpVersion,
        started_at: Instant,
        total_timeout: Duration,
    ) -> Result<(), Error> {
        let mut connector = Self::with_reconnect_timeout(
            "resolve",
            started_at,
            total_timeout,
            create_connector_by_url(dead_url.as_str(), &data.global_ctx, ip_version),
        )
        .await?;
        connector.set_pinned_peer_key(Self::seed_public_key(&data, &dead_url)?);

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };

        let tunnel = Self::with_reconnect_timeout(
            "connect",
            started_at,
            total_timeout,
            pm.connect_tunnel(connector),
        )
        .await?;

        let (peer_id, conn_id) = Self::with_reconnect_timeout(
            "handshake",
            started_at,
            total_timeout,
            pm.add_client_tunnel_with_peer_id_hint(tunnel, true, None),
        )
        .await?;

        tracing::info!("reconnect succ: {} {} {}", peer_id, conn_id, dead_url);
        Ok(())
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
    ) -> Result<(), Error> {
        tracing::info!("reconnect: {}", dead_url);

        let mut ip_versions = if data.global_ctx.get_underlay_policy().is_active() {
            Self::strict_reconnect_ip_versions(&dead_url)
        } else {
            vec![]
        };
        if !ip_versions.is_empty() {
            tracing::debug!(
                ?dead_url,
                "strict reconnect skipped preflight DNS resolution"
            );
        } else {
            let converted_dead_url =
                match crate::common::idn::convert_idn_to_ascii(dead_url.clone()) {
                    Ok(url) => url,
                    Err(error) => {
                        let error: Error = error.into();
                        Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                        return Err(error);
                    }
                };
            let addrs = match Self::with_reconnect_timeout(
                "resolve",
                Instant::now(),
                Self::reconnect_timeout(&dead_url),
                socket_addrs(&converted_dead_url, || Some(1000)),
            )
            .await
            {
                Ok(addrs) => addrs,
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, IpVersion::Both, &error);
                    return Err(error);
                }
            };
            tracing::info!(?addrs, ?dead_url, "get ip from url done");
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;
            for addr in addrs {
                if addr.is_ipv4() {
                    if !has_ipv4 {
                        ip_versions.insert(0, IpVersion::V4);
                    }
                    has_ipv4 = true;
                } else if addr.is_ipv6() {
                    if !has_ipv6 {
                        ip_versions.push(IpVersion::V6);
                    }
                    has_ipv6 = true;
                }
            }
        }

        let mut reconn_ret = Err(Error::AnyhowError(anyhow::anyhow!(
            "cannot get ip from url"
        )));
        for ip_version in ip_versions {
            let started_at = Instant::now();
            let ret = Self::conn_reconnect_with_ip_version(
                data.clone(),
                dead_url.clone(),
                ip_version,
                started_at,
                Self::reconnect_timeout(&dead_url),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(result) => return Ok(result),
                Err(error) => {
                    Self::emit_connect_error(&data, &dead_url, ip_version, &error);
                    reconn_ret = Err(error);
                }
            }
        }

        reconn_ret
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::common::config::ConfigLoader as _;

    #[tokio::test]
    async fn shared_and_readded_seeds_keep_one_reconnect_attempt() {
        let peer = crate::peers::tests::create_mock_peer_manager_secure(
            "seed-readd".into(),
            "secret".into(),
        )
        .await;
        let manager = ManualConnectorManager::new(peer.get_global_ctx(), peer.clone());
        let seed: url::Url = "h2://127.0.0.1:9".parse().unwrap();
        let shared: url::Url = "wss://127.0.0.1:9".parse().unwrap();
        let target: url::Url = "quic://127.0.0.1:9".parse().unwrap();
        manager.add_connector_by_url(seed.clone());
        assert!(ManualConnectorManager::begin_reconnect(
            &manager.data,
            &target
        ));
        manager.remove_connector(seed.clone()).unwrap();
        manager.add_connector_by_url(seed);
        manager.add_connector_by_url(shared);
        assert!(!ManualConnectorManager::begin_reconnect(
            &manager.data,
            &target
        ));
        assert!(!manager.data.connectors.contains(&target));
        let listed = manager.list_connectors().await;
        let attempts = listed
            .iter()
            .filter(|connector| connector.url == Some(target.clone().into()))
            .collect::<Vec<_>>();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, ConnectorStatus::Connecting as i32);

        ManualConnectorManager::finish_reconnect(&manager.data, target.clone(), true);
        assert!(manager.data.connectors.contains(&target));
        assert!(!manager.data.reconnecting.contains(&target));
        assert_eq!(*manager.data.failures.get(&target).unwrap(), 1);
        assert!(*manager.data.cold_until.get(&target).unwrap() > tokio::time::Instant::now());
        manager
            .data
            .cold_until
            .insert(target.clone(), tokio::time::Instant::now());
        assert!(ManualConnectorManager::begin_reconnect(
            &manager.data,
            &target
        ));
        ManualConnectorManager::finish_reconnect(&manager.data, target.clone(), false);
        assert!(manager.data.connectors.contains(&target));
        assert!(!manager.data.failures.contains_key(&target));
        assert!(!manager.data.cold_until.contains_key(&target));
    }

    #[tokio::test]
    async fn listed_reconnecting_target_removal_drops_its_completion() {
        let peer = crate::peers::tests::create_mock_peer_manager_secure(
            "seed-remove".into(),
            "secret".into(),
        )
        .await;
        let manager = ManualConnectorManager::new(peer.get_global_ctx(), peer.clone());
        let seed: url::Url = "h2://127.0.0.1:9".parse().unwrap();
        let target: url::Url = "quic://127.0.0.1:9".parse().unwrap();
        manager.add_connector_by_url(seed.clone());
        assert!(ManualConnectorManager::begin_reconnect(
            &manager.data,
            &target
        ));
        manager.remove_connector(target.clone()).unwrap();
        assert!(matches!(
            manager.remove_connector(target.clone()),
            Err(Error::NotFound)
        ));
        assert!(
            manager
                .list_connectors()
                .await
                .iter()
                .all(|connector| connector.url != Some(target.clone().into()))
        );
        ManualConnectorManager::finish_reconnect(&manager.data, target.clone(), true);
        assert!(!manager.data.connectors.contains(&target));
        assert!(!manager.data.reconnecting.contains(&target));
        assert!(!manager.data.failures.contains_key(&target));
        assert!(!manager.data.cold_until.contains_key(&target));
        manager.remove_connector(seed).unwrap();
        assert!(manager.list_connectors().await.is_empty());
    }

    #[tokio::test]
    async fn seed_pins_and_removal_ignore_later_camouflage_paths() {
        use crate::common::config::PeerConfig;

        let peer = crate::peers::tests::create_mock_peer_manager_secure(
            "seed-path".into(),
            "secret".into(),
        )
        .await;
        let context = peer.get_global_ctx();
        let wss: url::Url = "wss://127.0.0.1:9".parse().unwrap();
        let h2: url::Url = "h2://127.0.0.1:9".parse().unwrap();
        let old_target: url::Url = "wss://127.0.0.1:9/old".parse().unwrap();
        let new_target: url::Url = "wss://127.0.0.1:9/new".parse().unwrap();
        let pin = context
            .config
            .get_secure_mode()
            .unwrap()
            .local_public_key
            .unwrap();
        context.config.set_peers(vec![
            PeerConfig {
                uri: wss.clone(),
                peer_public_key: Some(pin.clone()),
            },
            PeerConfig {
                uri: h2.clone(),
                peer_public_key: Some(pin.clone()),
            },
        ]);
        let mut flags = context.get_flags();
        let mut camouflage = flags.camouflage_config().clone();
        camouflage.wss_path = "/old".into();
        flags.camouflage = Some(camouflage.clone());
        context.set_flags(flags.clone());
        let manager = ManualConnectorManager::new(context.clone(), peer.clone());
        manager.add_connector_by_url(wss.clone());
        manager.add_connector_by_url(h2.clone());
        camouflage.wss_path = "/new".into();
        flags.camouflage = Some(camouflage);
        context.set_flags(flags);
        assert_eq!(
            ManualConnectorManager::seed_public_key(&manager.data, &old_target).unwrap(),
            Some(pin.clone()),
        );
        manager.remove_connector(wss).unwrap();
        assert!(manager.data.connectors.contains(&old_target));
        assert_eq!(
            ManualConnectorManager::seed_public_key(&manager.data, &old_target).unwrap(),
            Some(pin),
        );
        manager.remove_connector(h2).unwrap();
        assert!(!manager.data.connectors.contains(&old_target));
        assert!(!manager.data.connectors.contains(&new_target));
        assert!(manager.data.connectors.is_empty());
        assert!(manager.data.seeds.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_seed_reports_cold_retry_without_dialing() {
        let peer = crate::peers::tests::create_mock_peer_manager_secure(
            "seed-cold".into(),
            "secret".into(),
        )
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: url::Url = format!("h2://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let manager = ManualConnectorManager::new(peer.get_global_ctx(), peer.clone());
        manager.data.connectors.insert(url.clone());
        manager.data.cold_until.insert(
            url,
            tokio::time::Instant::now() + super::super::COLD_RETRY_INTERVAL,
        );
        let listed = manager.list_connectors().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, ConnectorStatus::ColdRetry as i32);
        assert!((599..=601).contains(&listed[0].retry_after_seconds));
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let seed: url::Url = "quic://127.0.0.1:11012".parse().unwrap();
        manager.add_connector_by_url(seed.clone());
        let members = manager.data.seeds.lock().unwrap()[&seed].clone();
        assert_eq!(members.len(), 3);
        for member in &members {
            assert_eq!(
                member.port_or_known_default(),
                Some(if member.scheme() == "h2" {
                    11010
                } else {
                    11012
                })
            );
            manager.data.cold_until.insert(
                member.clone(),
                tokio::time::Instant::now() + super::super::COLD_RETRY_INTERVAL,
            );
        }
        let wss: url::Url = "wss://127.0.0.1:11012".parse().unwrap();
        let wrong_pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
        let own_pin = peer
            .get_global_ctx()
            .config
            .get_secure_mode()
            .unwrap()
            .local_public_key
            .unwrap();
        peer.get_global_ctx().config.set_peers(vec![
            crate::common::config::PeerConfig {
                uri: seed.clone(),
                peer_public_key: Some(wrong_pin.clone()),
            },
            crate::common::config::PeerConfig {
                uri: wss.clone(),
                peer_public_key: Some(own_pin.clone()),
            },
        ]);
        manager.add_connector_by_url(wss.clone());
        let generated = members
            .iter()
            .find(|member| member.scheme() == "h2")
            .unwrap();
        assert!(ManualConnectorManager::seed_public_key(&manager.data, generated).is_err());
        manager.remove_connector(seed).unwrap();
        assert!(
            members
                .iter()
                .all(|member| manager.data.connectors.contains(member))
        );
        assert_eq!(
            ManualConnectorManager::seed_public_key(&manager.data, generated).unwrap(),
            Some(own_pin)
        );
        manager.remove_connector(wss).unwrap();
        assert!(
            members
                .iter()
                .all(|member| !manager.data.connectors.contains(member))
        );
        let server = crate::peers::tests::create_mock_peer_manager_secure(
            "seed-cold".into(),
            "secret".into(),
        )
        .await;
        let (left, right) = crate::tunnel::ring::create_ring_tunnel_pair();
        let left = super::super::retry::retain_with_pin(left, Vec::new(), Some(wrong_pin));
        let (client_result, _) = timeout(Duration::from_secs(10), async {
            tokio::join!(
                peer.add_client_tunnel(left, true),
                server.add_tunnel_as_server(right, true)
            )
        })
        .await
        .unwrap();
        assert!(
            client_result.is_err(),
            "a generated alternative must retain the seed public-key pin"
        );
    }

    #[tokio::test]
    async fn wss_effective_path_matches_the_retained_connector_and_live_connection() {
        use crate::{
            common::config::{PeerConfig, TomlConfigLoader},
            instance::instance::Instance,
            peers::tests::create_mock_peer_manager_secure,
            tunnel::{TunnelListener, websocket::WsTunnelListener},
        };

        timeout(Duration::from_secs(20), async {
            for (configured, explicit, expected) in [
                ("", "", "/ws"),
                ("/vpn", "", "/vpn"),
                ("/vpn", "/custom", "/custom"),
                ("/vpn", "/", "/vpn"),
            ] {
                let client =
                    create_mock_peer_manager_secure("wss-path".into(), "secret".into()).await;
                let server =
                    create_mock_peer_manager_secure("wss-path".into(), "secret".into()).await;
                let ctx = client.get_global_ctx();
                let mut flags = ctx.get_flags();
                flags.bind_device = false;
                flags.default_protocol = "wss".into();
                flags.enabled_protocols = vec!["wss".into()];
                flags.camouflage_config_mut().wss_path = configured.into();
                ctx.set_flags(flags.clone());
                let mut listener = WsTunnelListener::new(
                    format!("wss://127.0.0.1:0{explicit}?lanes=1")
                        .parse()
                        .unwrap(),
                );
                listener.set_flags(flags.clone());
                listener.listen().await.unwrap();
                let original: url::Url = format!(
                    "wss://127.0.0.1:{}{explicit}?lanes=1",
                    listener.local_url().port().unwrap(),
                )
                .parse()
                .unwrap();
                let connector = create_connector_by_url(original.as_str(), &ctx, IpVersion::V4)
                    .await
                    .unwrap();
                let effective = connector.remote_url();
                assert_eq!(effective.path(), expected);
                assert_eq!(effective, listener.local_url());
                let accepting_server = server.clone();
                let accepting = tokio::spawn(async move {
                    accepting_server
                        .add_tunnel_as_server(listener.accept().await.unwrap(), true)
                        .await
                        .unwrap();
                });
                let tunnel = client.connect_tunnel(connector).await.unwrap();
                assert_eq!(
                    url::Url::from(tunnel.info().unwrap().remote_addr.unwrap()),
                    effective
                );
                client.add_client_tunnel(tunnel, true).await.unwrap();
                accepting.await.unwrap();

                let manager = ManualConnectorManager::new(ctx, client.clone());
                manager.add_connector_by_url(original.clone());
                manager.add_single_connector_by_url(original.clone());
                assert!(ManualConnectorManager::collect_dead_conns(&manager.data).is_empty());
                let listed = manager.list_connectors().await;
                assert_eq!(listed.len(), 1);
                assert_eq!(listed[0].url, Some(effective.into()));
                assert_eq!(listed[0].status, ConnectorStatus::Connected as i32);
                manager.remove_connector(original).unwrap();
                assert!(manager.list_connectors().await.is_empty());
            }

            let mut instance = Instance::new(TomlConfigLoader::default());
            let mut camouflage = instance
                .get_global_ctx()
                .get_flags()
                .camouflage_config()
                .clone();
            camouflage.wss_path = "/vpn".into();
            let candidate = TomlConfigLoader::default();
            let mut flags = candidate.get_flags();
            flags.camouflage = Some(camouflage);
            candidate.set_flags(flags);
            candidate.set_peers(vec![PeerConfig {
                uri: "wss://127.0.0.1:9".parse().unwrap(),
                peer_public_key: None,
            }]);
            instance
                .get_conn_manager()
                .sync_configuration(&[], &candidate);
            let listed = instance.get_conn_manager().list_connectors().await;
            assert_eq!(listed.len(), 3);
            assert!(listed.iter().any(|connector| connector.url
                == Some("wss://127.0.0.1:9/vpn".parse::<url::Url>().unwrap().into())));
            instance.clear_resources().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn multi_lane_tcp_has_time_for_noise_after_tls_joins() {
        for (url, seconds) in [
            ("h2://localhost?lanes=4", 20),
            ("h2://localhost?lanes=2", 20),
            ("h2://localhost", 20),
            ("h2://localhost?lanes=1", 20),
            ("quic://localhost", 20),
            ("wss://localhost?lanes=4", 20),
        ] {
            assert_eq!(
                ManualConnectorManager::reconnect_timeout(&url.parse().unwrap()),
                Duration::from_secs(seconds),
                "{url}"
            );
        }
        assert!(
            ManualConnectorManager::remaining_budget(
                Instant::now() - Duration::from_millis(1800),
                Duration::from_secs(10)
            )
            .unwrap()
                > Duration::from_secs(8)
        );
    }
}
