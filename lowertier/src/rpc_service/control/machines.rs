use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    common::config::{
        ConfigLoader, DEFAULT_OFFLINE_RETENTION, PeerNote, validate_offline_retention,
    },
    instance_manager::NetworkInstanceManager,
    peers::route_trait::NextHopPolicy,
    proto::{
        api::{control::v1::*, instance::Route},
        rpc_types::controller::BaseController,
    },
};

use super::{ControlPlaneService, failure, read::now_ms};

const MAX_MACHINES: usize = 1024;
const SAVE_INTERVAL_MS: i64 = 60_000;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PAGE_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct SavedHistory {
    instance: uuid::Uuid,
    network: String,
    owner_key: String,
    machines: Vec<OfflineMachine>,
}

pub(crate) struct MachineHistory {
    path: Option<PathBuf>,
    instance: uuid::Uuid,
    network: String,
    owner_key: String,
    machines: BTreeMap<String, OfflineMachine>,
    online: BTreeSet<String>,
    saved_at: i64,
    dirty: bool,
    generation: u64,
}

impl MachineHistory {
    fn load(
        path: Option<PathBuf>,
        instance: uuid::Uuid,
        network: String,
        owner_key: String,
    ) -> anyhow::Result<Self> {
        let mut history = Self {
            path,
            instance,
            network,
            owner_key,
            machines: BTreeMap::new(),
            online: BTreeSet::new(),
            saved_at: 0,
            dirty: false,
            generation: 1,
        };
        if let Some(path) = &history.path {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.len() <= MAX_FILE_BYTES,
                        "Machine history is too large."
                    );
                    let saved: SavedHistory = serde_json::from_slice(&std::fs::read(path)?)?;
                    if saved.instance == history.instance
                        && saved.network == history.network
                        && saved.owner_key == history.owner_key
                    {
                        anyhow::ensure!(
                            saved.machines.len() <= MAX_MACHINES,
                            "Too many saved machines."
                        );
                        for machine in saved.machines {
                            validate_offline_retention(machine.offline_retention)?;
                            anyhow::ensure!(
                                machine.peer_key.len() == 32
                                    && machine.route.as_ref().is_some_and(|route| {
                                        identity(route, &machine.peer_key) == machine.id
                                    }),
                                "A saved machine has an invalid identity."
                            );
                            history.machines.insert(machine.id.clone(), machine);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(history)
    }

    fn update(&mut self, live: Vec<(Vec<u8>, Route)>, notes: &[PeerNote], at: i64) -> bool {
        let previous = std::mem::take(&mut self.online);
        let mut changed = false;
        for (key, route) in live {
            let route = display_route(route);
            let id = identity(&route, &key);
            self.online.insert(id.clone());
            let retention = retention(&route, &key, notes);
            if retention == 0 {
                let removed = self.machines.remove(&id).is_some();
                self.dirty |= removed;
                changed |= removed;
                continue;
            }
            if !self.machines.contains_key(&id) && self.machines.len() >= MAX_MACHINES {
                // Keep permanent records. Prefer the oldest finite record when space is needed.
                let oldest = self
                    .machines
                    .iter()
                    .filter(|(_, machine)| machine.offline_retention >= 0)
                    .min_by_key(|(_, machine)| machine.last_seen_unix_ms)
                    .map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    self.machines.remove(&oldest);
                } else {
                    continue;
                }
            }
            changed |= self
                .machines
                .get(&id)
                .is_none_or(|machine| machine.offline_retention != retention);
            self.machines.insert(
                id.clone(),
                OfflineMachine {
                    id,
                    peer_key: key,
                    route: Some(route),
                    last_seen_unix_ms: at,
                    offline_retention: retention,
                },
            );
            self.dirty = true;
        }
        self.machines.retain(|id, machine| {
            if let Some(route) = &machine.route {
                let seconds = retention(route, &machine.peer_key, notes);
                self.dirty |= machine.offline_retention != seconds;
                changed |= machine.offline_retention != seconds;
                machine.offline_retention = seconds;
            }
            let keep = self.online.contains(id) || retained(machine, at);
            self.dirty |= !keep;
            changed |= !keep;
            keep
        });
        let changed = changed || previous != self.online;
        if changed {
            self.generation = self.generation.wrapping_add(1);
        }
        changed
    }

    fn save(&mut self, at: i64, force: bool) -> anyhow::Result<()> {
        if !self.dirty || (!force && at.saturating_sub(self.saved_at) < SAVE_INTERVAL_MS) {
            return Ok(());
        }
        if let Some(path) = &self.path {
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            let saved = SavedHistory {
                instance: self.instance,
                network: self.network.clone(),
                owner_key: self.owner_key.clone(),
                machines: self.machines.values().cloned().collect(),
            };
            let bytes = serde_json::to_vec(&saved)?;
            anyhow::ensure!(
                bytes.len() as u64 <= MAX_FILE_BYTES,
                "Machine history is too large."
            );
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            temporary.write_all(&bytes)?;
            temporary.flush()?;
            temporary.persist(path).map_err(|error| error.error)?;
        }
        self.saved_at = at;
        self.dirty = false;
        Ok(())
    }
}

fn identity(route: &Route, key: &[u8]) -> String {
    match uuid::Uuid::parse_str(&route.inst_id) {
        Ok(id) if !id.is_nil() => format!("instance:{id}:key:{}", BASE64_STANDARD.encode(key)),
        _ => format!("key:{}", BASE64_STANDARD.encode(key)),
    }
}

fn display_route(route: Route) -> Route {
    Route {
        peer_id: route.peer_id,
        inst_id: route.inst_id,
        hostname: route.hostname.chars().take(64).collect(),
        version: route.version.chars().take(128).collect(),
        ipv4_addr: route.ipv4_addr,
        offline_retention: route.offline_retention,
        ..Default::default()
    }
}

fn retention(route: &Route, key: &[u8], notes: &[PeerNote]) -> i64 {
    let key = BASE64_STANDARD.encode(key);
    let seconds = notes
        .iter()
        .find(|note| note.peer == key)
        .and_then(|note| note.offline_retention)
        .or(route.offline_retention)
        .unwrap_or(DEFAULT_OFFLINE_RETENTION);
    if validate_offline_retention(seconds).is_ok() {
        seconds
    } else {
        DEFAULT_OFFLINE_RETENTION
    }
}

fn retained(machine: &OfflineMachine, at: i64) -> bool {
    machine.offline_retention == -1
        || (machine.offline_retention > 0
            && at.saturating_sub(machine.last_seen_unix_ms)
                < machine.offline_retention.saturating_mul(1000))
}

/// Sample authenticated reachable routes even when no browser is open.
pub(crate) async fn refresh(manager: &Arc<NetworkInstanceManager>) {
    for id in manager.list_network_instance_ids() {
        let _guard = manager.remote_mutation_lock().lock_owned().await;
        let Some(service) = manager.get_instance_service(&id) else {
            continue;
        };
        let Ok(peers) = service.peers() else { continue };
        let Some(config) = manager.get_instance_config(&id) else {
            continue;
        };
        let network = config.get_network_identity().network_name;
        let owner_key = config
            .get_secure_mode()
            .and_then(|mode| mode.public_key().ok())
            .map(|key| BASE64_STANDARD.encode(key.as_bytes()))
            .unwrap_or_default();
        let path = manager
            .get_instance_config_control(&id)
            .and_then(|control| control.path)
            .map(|path| path.with_extension("machines.json"));
        let notes = config.get_peer_notes();
        let routes = peers.list_routes().await;
        let identities = peers.get_peer_map().origin_auth_snapshot();
        let descriptor = peers.get_peer_map().dataplane_descriptor();
        let live = routes
            .into_iter()
            .filter_map(|route| {
                if route.peer_id == peers.my_peer_id()
                    || route.inst_id == id.to_string()
                    || !descriptor
                        .forwarding_snapshot
                        .as_ref()
                        .is_some_and(|snapshot| {
                            snapshot
                                .next_hop(route.peer_id, NextHopPolicy::LeastHop)
                                .is_some()
                        })
                {
                    return None;
                }
                let key = identities
                    .lookup(route.peer_id)?
                    .noise_static_pubkey
                    .to_vec();
                (key.len() == 32).then_some((key, route))
            })
            .collect();
        let manager = manager.clone();
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut histories = manager.machine_history.lock().unwrap();
            let reload = histories.get(&id).is_none_or(|history| {
                history.path != path || history.network != network || history.owner_key != owner_key
            });
            if reload {
                histories.insert(id, MachineHistory::load(path, id, network, owner_key)?);
            }
            let history = histories.get_mut(&id).unwrap();
            let at = now_ms();
            let changed = history.update(live, &notes, at);
            history.save(at, changed)
        })
        .await;
        if !matches!(&result, Ok(Ok(()))) {
            tracing::warn!(instance = %id, error = ?result, "Cannot update machine history");
        }
    }
}

pub(crate) fn generation(manager: &NetworkInstanceManager, id: uuid::Uuid) -> u64 {
    let histories = manager.machine_history.lock().unwrap();
    histories.get(&id).map_or(0, |history| history.generation)
}

fn offline_page(
    history: &MachineHistory,
    page: Option<Page>,
    epoch: uuid::Uuid,
) -> anyhow::Result<ListOfflineMachinesResponse> {
    let page = page.unwrap_or_default();
    let stamp = format!("{epoch}:{}:{}", history.instance, history.generation);
    let offset = if page.page_token.is_empty() {
        0
    } else {
        let (prefix, offset) = page.page_token.rsplit_once(':').ok_or_else(|| {
            failure(
                "INVALID_ARGUMENT",
                "The page token is invalid.",
                "page.page_token",
            )
        })?;
        if prefix != stamp {
            return Err(failure(
                "CONFLICT",
                "Machine history changed. Start pagination again.",
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
    let rows: Vec<_> = history
        .machines
        .values()
        .filter(|machine| !history.online.contains(&machine.id))
        .collect();
    if offset > rows.len() {
        return Err(failure(
            "INVALID_ARGUMENT",
            "The page offset exceeds the history.",
            "page.page_token",
        ));
    }
    let limit = if page.limit == 0 {
        128
    } else {
        page.limit.min(128)
    } as usize;
    let mut machines = Vec::new();
    let mut bytes = 1024;
    for row in rows.iter().skip(offset).take(limit) {
        let size = serde_json::to_vec(row)?.len() + 1;
        if bytes + size > MAX_PAGE_BYTES {
            break;
        }
        bytes += size;
        machines.push((*row).clone());
    }
    let end = offset + machines.len();
    anyhow::ensure!(
        end > offset || end == rows.len(),
        "A machine record exceeds the response limit."
    );
    Ok(ListOfflineMachinesResponse {
        machines,
        next_page_token: if end < rows.len() {
            format!("{stamp}:{end}")
        } else {
            String::new()
        },
        ..Default::default()
    })
}

impl ControlPlaneService {
    pub(super) async fn list_offline_machines_inner(
        &self,
        _: BaseController,
        request: ListOfflineMachinesRequest,
    ) -> anyhow::Result<ListOfflineMachinesResponse> {
        let id = self.select_instance(request.meta.as_ref())?;
        let histories = self.manager.machine_history.lock().unwrap();
        match histories.get(&id) {
            Some(history) => offline_page(history, request.page, self.epoch),
            None => Ok(ListOfflineMachinesResponse::default()),
        }
    }

    pub(super) async fn forget_machine_inner(
        &self,
        _: BaseController,
        request: ForgetMachineRequest,
    ) -> anyhow::Result<ForgetMachineResponse> {
        let _guard = self.mutation_guard().await;
        let (id, _) = self.resolve(request.meta.as_ref())?;
        let mut histories = self.manager.machine_history.lock().unwrap();
        let history = histories
            .get_mut(&id)
            .context("Machine history is unavailable.")?;
        if history.online.contains(&request.id) {
            return Err(failure(
                "CONFLICT",
                "The machine is online. Change its offline retention instead.",
                "id",
            ));
        }
        if let Some(machine) = history.machines.remove(&request.id) {
            history.dirty = true;
            if let Err(error) = history.save(now_ms(), true) {
                history.machines.insert(request.id, machine);
                return Err(error);
            }
            history.generation = history.generation.wrapping_add(1);
        }
        Ok(ForgetMachineResponse::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(instance: uuid::Uuid, peer_id: u32, offline_retention: i64) -> (Vec<u8>, Route) {
        (
            vec![1; 32],
            Route {
                inst_id: instance.to_string(),
                peer_id,
                hostname: "test-vm".into(),
                offline_retention: Some(offline_retention),
                ..Default::default()
            },
        )
    }

    #[test]
    fn history_expires_temporary_nodes_and_merges_restarted_instances() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.machines.json");
        let local = uuid::Uuid::new_v4();
        let remote = uuid::Uuid::new_v4();
        let mut history =
            MachineHistory::load(Some(path.clone()), local, "test".into(), "owner".into()).unwrap();
        history.update(vec![route(remote, 10, 3600)], &[], 1000);
        history.update(vec![route(remote, 20, 3600)], &[], 2000);
        assert_eq!(history.machines.len(), 1);
        assert_eq!(
            history
                .machines
                .values()
                .next()
                .unwrap()
                .route
                .as_ref()
                .unwrap()
                .peer_id,
            20
        );
        history.update(Vec::new(), &[], 3000);
        history.save(3000, true).unwrap();
        let mut loaded =
            MachineHistory::load(Some(path.clone()), local, "test".into(), "owner".into()).unwrap();
        assert_eq!(loaded.machines.len(), 1);
        loaded.update(Vec::new(), &[], 3_602_000);
        assert!(loaded.machines.is_empty());
        history.update(vec![route(remote, 30, 0)], &[], 4000);
        assert!(history.machines.is_empty());
        history.update(vec![route(remote, 40, -1)], &[], 5000);
        history.update(Vec::new(), &[], i64::MAX);
        assert_eq!(history.machines.len(), 1);
        let note = PeerNote {
            peer: BASE64_STANDARD.encode([1; 32]),
            name: None,
            text: None,
            offline_retention: Some(0),
        };
        history.update(Vec::new(), &[note], i64::MAX);
        assert!(history.machines.is_empty());
        let other_network =
            MachineHistory::load(Some(path), local, "other".into(), "owner".into()).unwrap();
        assert!(other_network.machines.is_empty());
    }

    #[test]
    fn history_binds_keys_and_bounds_saved_metadata_and_pages() {
        let directory = tempfile::tempdir().unwrap();
        let local = uuid::Uuid::new_v4();
        let remote = uuid::Uuid::new_v4();
        let mut history = MachineHistory::load(
            Some(directory.path().join("node.machines.json")),
            local,
            "test".into(),
            "owner".into(),
        )
        .unwrap();
        let first = route(remote, 1, -1);
        let mut impersonator = route(remote, 2, 0);
        impersonator.0 = vec![2; 32];
        history.update(vec![first, impersonator], &[], 1000);
        assert_eq!(history.machines.len(), 1);
        assert_eq!(
            history.machines.values().next().unwrap().peer_key,
            vec![1; 32]
        );
        let live: Vec<_> = (1..=MAX_MACHINES)
            .map(|index| {
                let (key, mut route) =
                    route(uuid::Uuid::from_u128(index as u128), index as u32, -1);
                route.hostname = "界".repeat(1024);
                route.version = "界".repeat(1024);
                route.proxy_cidrs = vec!["2001:db8:abcd:1234::/64".into(); 256];
                route.multicast_groups = vec![vec![255; 16]; 256];
                (key, route)
            })
            .collect();
        history.update(live.clone(), &[], 2000);
        assert!(!history.update(live, &[], 2500));
        let before_offline = history.generation;
        history.update(Vec::new(), &[], 3000);
        assert_ne!(history.generation, before_offline);
        history.save(3000, true).unwrap();
        assert!(
            std::fs::metadata(history.path.as_ref().unwrap())
                .unwrap()
                .len()
                < MAX_FILE_BYTES
        );
        let mut loaded =
            MachineHistory::load(history.path.clone(), local, "test".into(), "owner".into())
                .unwrap();
        assert_eq!(loaded.machines.len(), MAX_MACHINES);
        assert!(
            loaded.machines.values().all(|machine| machine
                .route
                .as_ref()
                .unwrap()
                .proxy_cidrs
                .is_empty())
        );
        let epoch = uuid::Uuid::new_v4();
        let mut token = String::new();
        let mut count = 0;
        loop {
            let response = offline_page(
                &loaded,
                Some(Page {
                    limit: 128,
                    page_token: token,
                }),
                epoch,
            )
            .unwrap();
            assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_PAGE_BYTES);
            count += response.machines.len();
            if response.next_page_token.is_empty() {
                break;
            }
            token = response.next_page_token;
        }
        assert_eq!(count, MAX_MACHINES);
        let page = offline_page(
            &loaded,
            Some(Page {
                limit: 1,
                page_token: String::new(),
            }),
            epoch,
        )
        .unwrap();
        loaded.generation += 1;
        assert!(
            offline_page(
                &loaded,
                Some(Page {
                    limit: 1,
                    page_token: page.next_page_token
                }),
                epoch
            )
            .is_err()
        );
    }
}
