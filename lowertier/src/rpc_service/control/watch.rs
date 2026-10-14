use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    sync::LazyLock,
    time::Duration,
};

use base64::Engine;

use crate::proto::{api::control::v1::*, rpc_types::controller::BaseController};

use super::{ControlPlaneService, failure, logs, read::now_ms};

pub(super) static PROCESS_EPOCH: LazyLock<uuid::Uuid> = LazyLock::new(uuid::Uuid::new_v4);

const RESOURCES: &[&str] = &[
    "node",
    "peers",
    "routes",
    "relay",
    "l2",
    "discovery",
    "listeners",
    "camouflage",
    "config",
    "stats",
    "logs",
    "acl",
    "credentials",
    "port_forwards",
    "instances",
];

#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    epoch: uuid::Uuid,
    instance_id: uuid::Uuid,
    sampled_at: i64,
    generations: BTreeMap<String, Vec<u64>>,
}

impl ControlPlaneService {
    async fn generations(&self, id: uuid::Uuid, resources: &[String]) -> anyhow::Result<Cursor> {
        let instance = self
            .manager
            .get_instance_service(&id)
            .map(|instance| (*instance).clone());
        let mut event = 0;
        let mut topology = 0;
        let mut l2 = vec![0; 5];
        let mut discovery = 0;
        if let Some(instance) = instance {
            event = instance.context()?.control_generation();
            let peers = instance.peers()?;
            topology = peers.get_peer_map().forwarding_generation().await;
            let counters = peers.l2_counters();
            l2 = vec![
                peers.l2_generation(),
                counters.flood_drops,
                counters.ingress_flood_drops,
                counters.loop_drops,
                counters.policy_drops,
            ];
            let mut sources = instance
                .context()?
                .discovery_sources()
                .into_iter()
                .map(|(socket, source)| {
                    (
                        socket,
                        source.candidate_count(),
                        source.has_live_connections(&peers),
                    )
                })
                .collect::<Vec<_>>();
            sources.sort_unstable();
            let mut hash = std::collections::hash_map::DefaultHasher::new();
            sources.hash(&mut hash);
            discovery = hash.finish();
        }
        let sampled_at = now_ms();
        let mut generations = BTreeMap::new();
        for resource in resources {
            let generation = match resource.as_str() {
                "stats" => vec![sampled_at.max(0) as u64 / 1000],
                "logs" => vec![logs::generation()],
                "l2" => l2.clone(),
                "discovery" => vec![event, discovery],
                "peers" | "routes" | "relay" => vec![event, topology],
                "instances" => {
                    let mut rows = self
                        .manager
                        .iter()
                        .map(|entry| {
                            (
                                *entry.key(),
                                entry.is_lowertier_running(),
                                entry.get_inst_name(),
                                entry.get_network_name(),
                                entry.get_latest_error_msg(),
                            )
                        })
                        .collect::<Vec<_>>();
                    rows.sort_unstable();
                    let mut hash = std::collections::hash_map::DefaultHasher::new();
                    rows.hash(&mut hash);
                    vec![hash.finish()]
                }
                _ => vec![event],
            };
            generations.insert(resource.clone(), generation);
        }
        Ok(Cursor {
            epoch: self.epoch,
            instance_id: id,
            sampled_at,
            generations,
        })
    }

    pub(super) async fn watch_changes_inner(
        &self,
        _: BaseController,
        mut request: WatchChangesRequest,
    ) -> anyhow::Result<WatchChangesResponse> {
        if request.resources.is_empty() {
            request.resources = RESOURCES.iter().map(|name| (*name).into()).collect();
        }
        if request.resources.len() > RESOURCES.len()
            || request
                .resources
                .iter()
                .any(|name| !RESOURCES.contains(&name.as_str()))
        {
            return Err(failure(
                "INVALID_ARGUMENT",
                "The watch resource list is invalid.",
                "resources",
            ));
        }
        request.resources.sort_unstable();
        request.resources.dedup();
        let id = if request
            .resources
            .iter()
            .all(|name| matches!(name.as_str(), "logs" | "instances"))
        {
            uuid::Uuid::nil()
        } else {
            self.select_instance(request.meta.as_ref())?
        };
        if request.cursor.len() > 8192 {
            return Err(failure(
                "INVALID_ARGUMENT",
                "The watch cursor is too large.",
                "cursor",
            ));
        }
        let previous = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&request.cursor)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok());
        let now = now_ms();
        let reset = previous.as_ref().is_none_or(|cursor| {
            cursor.epoch != self.epoch
                || cursor.instance_id != id
                || cursor.sampled_at > now
                || now.saturating_sub(cursor.sampled_at) > 300_000
                || cursor.generations.keys().ne(request.resources.iter())
        });
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(u64::from(request.max_wait_ms.min(20_000)));
        loop {
            let current = self.generations(id, &request.resources).await?;
            let changed = current
                .generations
                .iter()
                .filter_map(|(name, generation)| {
                    (reset
                        || previous
                            .as_ref()
                            .and_then(|cursor| cursor.generations.get(name))
                            != Some(generation))
                    .then(|| name.clone())
                })
                .collect::<Vec<_>>();
            if reset || !changed.is_empty() || tokio::time::Instant::now() >= deadline {
                let cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&current)?);
                return Ok(WatchChangesResponse {
                    cursor,
                    changed,
                    reset,
                    ..Default::default()
                });
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(250)),
            )
            .await;
        }
    }
}
