use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};

use crate::{
    common::config::ConfigLoader,
    proto::{
        api::{control::v1::*, instance as legacy},
        rpc_types::controller::{BaseController, Controller},
    },
};

use super::{ControlInstance, ControlPlaneService, failure, logs};

pub(super) const METHODS: &[&str] = &[
    "GetCapabilities",
    "ListInstances",
    "GetNode",
    "ListPeers",
    "ListRoutes",
    "GetL2",
    "GetDiscovery",
    "ListListeners",
    "GetStats",
    "GetPrometheus",
    "ReadLogs",
    "GetLogConfig",
    "SetLogConfig",
    "GetAcl",
    "GetAclStats",
    "ListCredentials",
    "IssueCredential",
    "RevokeCredential",
    "ListPortForwards",
    "WatchChanges",
];

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            elapsed.as_millis().min(i64::MAX as u128) as i64
        })
}

fn page<T>(rows: Vec<T>, request: Option<Page>, stamp: &str) -> anyhow::Result<(Vec<T>, String)> {
    let request = request.unwrap_or_default();
    let limit = if request.limit == 0 {
        100
    } else {
        request.limit.min(256)
    } as usize;
    let offset = if request.page_token.is_empty() {
        0
    } else {
        let (token_stamp, offset) = request.page_token.rsplit_once(':').ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "The page token is invalid.",
                "page.page_token",
            )
        })?;
        if token_stamp != stamp {
            return Err(failure(
                "CONFLICT",
                "The snapshot changed. Start pagination again.",
                "page.page_token",
            ));
        }
        offset.parse::<usize>().map_err(|_| {
            failure(
                "INVALID_ARGUMENT",
                "The page offset is invalid.",
                "page.page_token",
            )
        })?
    };
    if offset > rows.len() {
        return Err(failure(
            "INVALID_ARGUMENT",
            "The page offset exceeds the snapshot.",
            "page.page_token",
        ));
    }
    let end = offset.saturating_add(limit).min(rows.len());
    let next = if end < rows.len() {
        format!("{stamp}:{end}")
    } else {
        String::new()
    };
    Ok((rows.into_iter().skip(offset).take(limit).collect(), next))
}

fn stamp(resource: &str, id: uuid::Uuid, generation: u64, keys: impl Hash) -> String {
    let mut digest = DefaultHasher::new();
    keys.hash(&mut digest);
    format!("{resource}:{id}:{generation}:{}", digest.finish())
}

impl ControlPlaneService {
    pub(super) fn resolve(
        &self,
        meta: Option<&RequestMeta>,
    ) -> anyhow::Result<(uuid::Uuid, ControlInstance)> {
        let id = self.select_instance(meta)?;
        let instance = self.manager.get_instance_service(&id).ok_or_else(|| {
            failure(
                "NOT_FOUND",
                "The instance is not running.",
                "meta.instance_id",
            )
        })?;
        Ok((id, (*instance).clone()))
    }

    pub(super) fn select_instance(&self, meta: Option<&RequestMeta>) -> anyhow::Result<uuid::Uuid> {
        if let Some(id) = meta
            .map(|meta| meta.instance_id.as_str())
            .filter(|id| !id.is_empty())
        {
            let id = id.parse().map_err(|_| {
                failure(
                    "INVALID_ARGUMENT",
                    "The instance ID is invalid.",
                    "meta.instance_id",
                )
            })?;
            if self.manager.get_instance_config(&id).is_none() {
                return Err(failure(
                    "NOT_FOUND",
                    "The instance does not exist.",
                    "meta.instance_id",
                ));
            }
            return Ok(id);
        }
        let ids = self.manager.list_network_instance_ids();
        match ids.as_slice() {
            [id] => Ok(*id),
            [] => Err(failure(
                "NOT_FOUND",
                "No instance exists.",
                "meta.instance_id",
            )),
            _ => Err(failure(
                "AMBIGUOUS",
                "Specify one instance ID.",
                "meta.instance_id",
            )),
        }
    }

    async fn snapshot(&self, instance: &ControlInstance) -> anyhow::Result<SnapshotMeta> {
        Ok(SnapshotMeta {
            revision: 1,
            topology_generation: instance
                .peers()?
                .get_peer_map()
                .forwarding_generation()
                .await,
            sampled_at_unix_ms: now_ms(),
        })
    }

    pub(super) async fn list_instances_inner(
        &self,
        _: BaseController,
        _: ListInstancesRequest,
    ) -> anyhow::Result<ListInstancesResponse> {
        let mut instances = self
            .manager
            .iter()
            .map(|entry| InstanceSnapshot {
                instance_id: entry.key().to_string(),
                name: entry.get_inst_name(),
                network_name: entry.get_network_name(),
                running: entry.is_lowertier_running(),
                last_error: entry.get_latest_error_msg().unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        instances.sort_unstable_by(|left, right| left.instance_id.cmp(&right.instance_id));
        Ok(ListInstancesResponse {
            instances,
            ..Default::default()
        })
    }

    pub(super) async fn get_node_inner(
        &self,
        _: BaseController,
        request: GetNodeRequest,
    ) -> anyhow::Result<GetNodeResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let mut node = instance.peers()?.get_my_info().await;
        // The legacy snapshot contains raw TOML with authentication secrets.
        node.config.clear();
        Ok(GetNodeResponse {
            node: Some(node),
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }

    pub(super) async fn list_peers_inner(
        &self,
        _: BaseController,
        request: ListPeersRequest,
    ) -> anyhow::Result<ListPeersResponse> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        let peers = instance.peers()?;
        let snapshot = self.snapshot(&instance).await?;
        let routes = peers
            .list_routes()
            .await
            .into_iter()
            .map(|route| (route.peer_id, route))
            .collect::<BTreeMap<_, _>>();
        let mut peer_infos = ControlInstance::list_peers(&peers)
            .await
            .into_iter()
            .map(|peer| (peer.peer_id, peer))
            .collect::<BTreeMap<_, _>>();
        for &peer_id in routes.keys() {
            if peer_id != peers.my_peer_id() {
                peer_infos
                    .entry(peer_id)
                    .or_insert_with(|| legacy::PeerInfo {
                        peer_id,
                        ..Default::default()
                    });
            }
        }
        let identities = peers.get_peer_map().origin_auth_snapshot();
        let mut rows = peer_infos
            .into_values()
            .map(|peer| {
                let selected = peer
                    .conns
                    .iter()
                    .find(|conn| {
                        peer.default_conn_id
                            .is_some_and(|id| id.to_string() == conn.conn_id)
                    })
                    .or_else(|| peer.conns.first());
                let route = routes.get(&peer.peer_id).cloned();
                let nat = route.as_ref().and_then(|route| route.stun_info.as_ref());
                PeerSnapshot {
                    peer_key: selected
                        .map(|conn| conn.noise_remote_static_pubkey.clone())
                        .or_else(|| {
                            identities
                                .lookup(peer.peer_id)
                                .map(|identity| identity.noise_static_pubkey.to_vec())
                        })
                        .unwrap_or_default(),
                    peer_id: peer.peer_id,
                    rtt_us: selected
                        .and_then(|conn| conn.stats.as_ref())
                        .map(|stats| stats.latency_us)
                        .filter(|rtt| *rtt > 0),
                    loss_ppm: selected.and_then(|conn| conn.tx_loss_ppm),
                    delivery_bps: selected.and_then(|conn| conn.tx_delivery_bps),
                    sample_age_ms: selected.and_then(|conn| conn.speed_sample_age_ms),
                    udp_nat: nat.map_or(0, |nat| nat.udp_nat_type),
                    tcp_nat: nat.map_or(0, |nat| nat.tcp_nat_type),
                    metric_scope: if selected.is_some() {
                        "direct_connection".into()
                    } else {
                        "unavailable".into()
                    },
                    conns: peer.conns,
                    route,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|peer| peer.peer_id);
        let stamp = stamp(
            "peers",
            id,
            snapshot.topology_generation,
            rows.iter().map(|peer| peer.peer_id).collect::<Vec<_>>(),
        );
        let (peers, next_page_token) = page(rows, request.page, &stamp)?;
        Ok(ListPeersResponse {
            peers,
            next_page_token,
            snapshot: Some(snapshot),
            ..Default::default()
        })
    }

    pub(super) async fn list_routes_inner(
        &self,
        _: BaseController,
        request: ListRoutesRequest,
    ) -> anyhow::Result<ListRoutesResponse> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        let snapshot = self.snapshot(&instance).await?;
        let flags = instance.context()?.get_flags();
        let policy = if flags.speed_first {
            "goodput"
        } else if flags.latency_first {
            "latency"
        } else {
            "hop"
        };
        let mut rows = instance
            .peers()?
            .list_routes()
            .await
            .into_iter()
            .map(|route| RouteSnapshot {
                destination: route.peer_id.to_string(),
                policy: policy.into(),
                effective_policy: if flags.speed_first
                    && route.path_delivery_bps_speed_first.is_none()
                {
                    "latency".into()
                } else {
                    policy.into()
                },
                source: "topology".into(),
                cost_ms: u64::try_from(route.path_latency).ok(),
                delivery_bps: if flags.speed_first {
                    route.path_delivery_bps_speed_first
                } else {
                    None
                },
                path_error: if request.include_paths {
                    "The route graph snapshot is not available.".into()
                } else {
                    String::new()
                },
                route: Some(route),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by_key(|route| route.route.as_ref().unwrap().peer_id);
        let stamp = stamp(
            "routes",
            id,
            snapshot.topology_generation,
            rows.iter()
                .map(|route| route.destination.as_str())
                .collect::<Vec<_>>(),
        );
        let (routes, next_page_token) = page(rows, request.page, &stamp)?;
        Ok(ListRoutesResponse {
            routes,
            next_page_token,
            snapshot: Some(snapshot),
            ..Default::default()
        })
    }

    pub(super) async fn get_l2_inner(
        &self,
        _: BaseController,
        request: GetL2Request,
    ) -> anyhow::Result<GetL2Response> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        let snapshot = self.snapshot(&instance).await?;
        let l2 = instance.peers()?.l2_snapshot();
        let mut rows = l2
            .entries
            .into_iter()
            .map(|entry| FdbEntry {
                vlans: entry.vlans.into_iter().map(u32::from).collect(),
                mac: entry.mac.to_vec(),
                owner_peer: entry.peer_id,
                age_ms: entry.idle.as_millis().min(u64::MAX as u128) as u64,
            })
            .collect::<Vec<_>>();
        rows.sort_unstable_by(|left, right| {
            (&left.vlans, &left.mac, left.owner_peer).cmp(&(
                &right.vlans,
                &right.mac,
                right.owner_peer,
            ))
        });
        let stamp = stamp(
            "fdb",
            id,
            0,
            rows.iter()
                .map(|entry| (&entry.vlans, &entry.mac, entry.owner_peer))
                .collect::<Vec<_>>(),
        );
        let (fdb, next_page_token) = page(rows, request.page, &stamp)?;
        Ok(GetL2Response {
            fdb,
            next_page_token,
            snapshot: Some(snapshot),
            counters: Some(L2Counters {
                flood_drops: l2.counters.flood_drops,
                ingress_flood_drops: l2.counters.ingress_flood_drops,
                loop_drops: l2.counters.loop_drops,
                policy_drops: l2.counters.policy_drops,
            }),
            ..Default::default()
        })
    }

    pub(super) async fn get_discovery_inner(
        &self,
        _: BaseController,
        request: GetDiscoveryRequest,
    ) -> anyhow::Result<GetDiscoveryResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let context = instance.context()?;
        Ok(GetDiscoveryResponse {
            snapshot: Some(self.snapshot(&instance).await?),
            trackers: context
                .config
                .get_tracker_discovery()
                .map(|config| {
                    config
                        .trackers
                        .into_iter()
                        .map(|uri| TrackerSnapshot {
                            uri: uri.to_string(),
                            ..Default::default()
                        })
                        .collect()
                })
                .unwrap_or_default(),
            active_paths: context
                .get_discovery_listeners()
                .into_iter()
                .map(|uri| uri.to_string())
                .collect(),
            ..Default::default()
        })
    }

    pub(super) async fn list_listeners_inner(
        &self,
        _: BaseController,
        request: ListListenersRequest,
    ) -> anyhow::Result<ListListenersResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let snapshot = self.snapshot(&instance).await?;
        let node = instance.peers()?.get_my_info().await;
        let listeners = node
            .listeners
            .into_iter()
            .enumerate()
            .map(|(index, uri)| {
                let parsed = url::Url::parse(&uri).ok();
                ListenerSnapshot {
                    id: format!("listener-{index}"),
                    transport: parsed
                        .as_ref()
                        .map(|uri| uri.scheme().to_owned())
                        .unwrap_or_default(),
                    lanes: parsed
                        .as_ref()
                        .and_then(|uri| uri.query_pairs().find(|(key, _)| key == "lanes"))
                        .and_then(|(_, value)| value.parse().ok())
                        .unwrap_or(1),
                    uri,
                    auth_state: "noise_exporter".into(),
                    binding_kind: "transport".into(),
                    config_revision: snapshot.revision,
                }
            })
            .collect();
        Ok(ListListenersResponse {
            listeners,
            snapshot: Some(snapshot),
            ..Default::default()
        })
    }

    pub(super) async fn get_stats_inner(
        &self,
        _: BaseController,
        request: GetStatsRequest,
    ) -> anyhow::Result<GetStatsResponse> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        let context = instance.context()?;
        let (sampled_at, metrics) = {
            let mut cache = self.stats.lock().unwrap();
            cache.retain(|id, _| self.manager.get_instance_name(id).is_some());
            let current = now_ms();
            let cached = cache.entry(id).or_insert_with(|| (0, Vec::new()));
            if current.saturating_sub(cached.0) >= 1000 {
                cached.0 = current;
                cached.1 = context
                    .stats_manager()
                    .get_all_metrics()
                    .into_iter()
                    .map(|metric| legacy::MetricSnapshot {
                        name: metric.name_str(),
                        value: metric.value,
                        labels: metric
                            .labels
                            .labels()
                            .iter()
                            .map(|label| (label.key.clone(), label.value.clone()))
                            .collect(),
                    })
                    .collect();
            }
            cached.clone()
        };
        let mut snapshot = self.snapshot(&instance).await?;
        snapshot.sampled_at_unix_ms = sampled_at;
        Ok(GetStatsResponse {
            metrics,
            snapshot: Some(snapshot),
            ..Default::default()
        })
    }

    pub(super) async fn get_prometheus_inner(
        &self,
        _: BaseController,
        request: GetPrometheusRequest,
    ) -> anyhow::Result<GetPrometheusResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let context = instance.context()?;
        let mut text = context.stats_manager().export_prometheus();
        text.push_str(&context.dataplane_telemetry().export_prometheus());
        Ok(GetPrometheusResponse {
            text,
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }

    pub(super) async fn read_logs_inner(
        &self,
        _: BaseController,
        request: ReadLogsRequest,
    ) -> anyhow::Result<ReadLogsResponse> {
        logs::read(request.page)
    }

    pub(super) async fn get_log_config_inner(
        &self,
        _: BaseController,
        _: GetLogConfigRequest,
    ) -> anyhow::Result<GetLogConfigResponse> {
        let level = crate::rpc_service::logger::CURRENT_LOG_LEVEL
            .get()
            .and_then(|level| level.lock().ok().map(|level| level.clone()))
            .unwrap_or_else(|| "info".into());
        Ok(GetLogConfigResponse {
            level,
            ..Default::default()
        })
    }

    pub(super) async fn set_log_config_inner(
        &self,
        _: BaseController,
        request: SetLogConfigRequest,
    ) -> anyhow::Result<SetLogConfigResponse> {
        if !matches!(
            request.level.as_str(),
            "off" | "error" | "warn" | "info" | "debug" | "trace"
        ) {
            return Err(failure(
                "INVALID_ARGUMENT",
                "The log level is invalid.",
                "level",
            ));
        }
        let sender = crate::rpc_service::logger::LOGGER_LEVEL_SENDER
            .get()
            .ok_or_else(|| failure("UNAVAILABLE", "The log reloader is not available.", "level"))?;
        sender
            .lock()
            .map_err(|_| failure("UNAVAILABLE", "The log reloader is not available.", "level"))?
            .send(request.level.clone())?;
        if let Some(level) = crate::rpc_service::logger::CURRENT_LOG_LEVEL.get() {
            *level.lock().map_err(|_| {
                failure(
                    "UNAVAILABLE",
                    "The log configuration is not available.",
                    "level",
                )
            })? = request.level;
        }
        Ok(SetLogConfigResponse::default())
    }

    pub(super) async fn get_acl_inner(
        &self,
        _: BaseController,
        request: GetAclRequest,
    ) -> anyhow::Result<GetAclResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let context = instance.context()?;
        Ok(GetAclResponse {
            acl: context.config.get_acl(),
            tcp_whitelist: context.config.get_tcp_whitelist(),
            udp_whitelist: context.config.get_udp_whitelist(),
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }

    pub(super) async fn get_acl_stats_inner(
        &self,
        _: BaseController,
        request: GetAclStatsRequest,
    ) -> anyhow::Result<GetAclStatsResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        Ok(GetAclStatsResponse {
            stats: Some(instance.context()?.get_acl_filter().get_stats()),
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }

    fn authorize_admin(
        &self,
        controller: &BaseController,
        instance: &ControlInstance,
        meta: Option<&RequestMeta>,
    ) -> anyhow::Result<()> {
        let context = instance.context()?;
        let remote_is_loopback = controller
            .get_tunnel_info()
            .and_then(|info| info.remote_addr.as_ref())
            .and_then(|address| url::Url::parse(&address.url).ok())
            .and_then(|address| match address.host()? {
                url::Host::Ipv4(address) => Some(std::net::IpAddr::V4(address)),
                url::Host::Ipv6(address) => Some(std::net::IpAddr::V6(address)),
                url::Host::Domain(address) => address.parse::<std::net::IpAddr>().ok(),
            })
            .is_some_and(|address| address.is_loopback());
        let expected = context
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        let valid = meta.is_some_and(|meta| {
            crate::common::verify_slices_are_equal(meta.admin_token.as_bytes(), expected.as_bytes())
                .is_ok()
        });
        if (!remote_is_loopback && self.token.is_some()) || expected.is_empty() || !valid {
            return Err(failure(
                "PERMISSION_DENIED",
                "Credential administration requires a loopback channel and a valid administrator token.",
                "meta.admin_token",
            ));
        }
        Ok(())
    }

    pub(super) async fn list_credentials_inner(
        &self,
        controller: BaseController,
        request: ListCredentialsRequest,
    ) -> anyhow::Result<ListCredentialsResponse> {
        let (id, instance) = self.resolve(request.meta.as_ref())?;
        self.authorize_admin(&controller, &instance, request.meta.as_ref())?;
        let mut rows = instance
            .context()?
            .get_credential_manager()
            .list_credentials();
        rows.sort_unstable_by(|left, right| left.credential_id.cmp(&right.credential_id));
        let stamp = stamp(
            "credentials",
            id,
            0,
            rows.iter()
                .map(|credential| {
                    (
                        &credential.credential_id,
                        credential.serial,
                        credential.expiry_unix,
                    )
                })
                .collect::<Vec<_>>(),
        );
        let (credentials, next_page_token) = page(rows, request.page, &stamp)?;
        Ok(ListCredentialsResponse {
            credentials,
            next_page_token,
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }

    pub(super) async fn issue_credential_inner(
        &self,
        controller: BaseController,
        request: IssueCredentialRequest,
    ) -> anyhow::Result<IssueCredentialResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        self.authorize_admin(&controller, &instance, request.meta.as_ref())?;
        if request.ttl_seconds <= 0 {
            return Err(failure(
                "INVALID_ARGUMENT",
                "The credential lifetime must be positive.",
                "ttl_seconds",
            ));
        }
        let context = instance.context()?;
        let (credential_id, credential_secret) = context
            .get_credential_manager()
            .generate_credential_bundle(
                request.groups,
                request.allow_relay,
                request.allowed_proxy_cidrs,
                std::time::Duration::from_secs(request.ttl_seconds as u64),
                request.credential_id,
                request.reusable.unwrap_or(true),
            )?;
        context.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);
        Ok(IssueCredentialResponse {
            credential_id,
            credential_secret,
            ..Default::default()
        })
    }

    pub(super) async fn revoke_credential_inner(
        &self,
        controller: BaseController,
        request: RevokeCredentialRequest,
    ) -> anyhow::Result<RevokeCredentialResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        self.authorize_admin(&controller, &instance, request.meta.as_ref())?;
        let context = instance.context()?;
        let revoked = context
            .get_credential_manager()
            .try_revoke_credential(&request.credential_id)?;
        if revoked {
            context.issue_event(crate::common::global_ctx::GlobalCtxEvent::CredentialChanged);
        }
        Ok(RevokeCredentialResponse {
            revoked,
            ..Default::default()
        })
    }

    pub(super) async fn list_port_forwards_inner(
        &self,
        _: BaseController,
        request: ListPortForwardsRequest,
    ) -> anyhow::Result<ListPortForwardsResponse> {
        let (_, instance) = self.resolve(request.meta.as_ref())?;
        let port_forwards = instance
            .context()?
            .config
            .get_port_forwards()
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(ListPortForwardsResponse {
            port_forwards,
            snapshot: Some(self.snapshot(&instance).await?),
            ..Default::default()
        })
    }
}
