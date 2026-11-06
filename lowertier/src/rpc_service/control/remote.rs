use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snow::{HandshakeState, TransportState};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::sync::Mutex;

use crate::{
    common::{
        PeerId,
        config::{ConfigLoader, TomlConfigLoader},
    },
    instance_manager::NetworkInstanceManager,
    peers::peer_rpc::PeerRpcManager,
    proto::{
        api::control::v1::*,
        peer_rpc::*,
        rpc_types::{
            controller::{BaseController, Controller},
            error::Result,
        },
    },
};

use super::{ControlPlaneService, failure};

const MAX_SESSIONS: usize = 64;
const MAX_BODY: usize = 512 * 1024;
const FRAME_BYTES: usize = 48 * 1024;
const SESSION_IDLE: Duration = Duration::from_secs(120);
const PROLOGUE: &[u8] = b"lowertier end-to-end control v1";

#[derive(Default)]
pub(crate) struct Hub {
    servers: std::sync::Mutex<BTreeMap<uuid::Uuid, (PeerId, Arc<Endpoint>)>>,
    clients: Mutex<BTreeMap<uuid::Uuid, ClientSession>>,
}

pub(super) struct Endpoint {
    manager: Weak<NetworkInstanceManager>,
    instance_id: uuid::Uuid,
    sessions: Mutex<BTreeMap<uuid::Uuid, ServerSession>>,
    starts: std::sync::Mutex<VecDeque<Instant>>,
}

enum Cipher {
    Handshake(HandshakeState),
    Transport(TransportState),
}

pub(super) struct ServerSession {
    _memory: crate::common::global_ctx::ProcessMemoryPermit,
    cipher: Cipher,
    source: PeerId,
    pub(super) network_member: bool,
    secret: Option<String>,
    pub(super) key: Option<[u8; 32]>,
    pub(super) created: Instant,
    touched: Instant,
    #[cfg(unix)]
    pub(super) ssh: Option<super::ssh::SshStream>,
}

struct ClientSession {
    _memory: crate::common::global_ctx::ProcessMemoryPermit,
    rpc: Arc<PeerRpcManager>,
    source_instance: uuid::Uuid,
    destination: PeerId,
    wire_id: uuid::Uuid,
    cipher: TransportState,
    touched: Instant,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Operation {
    pub(super) method: String,
    pub(super) payload: Value,
    close: bool,
}

fn handshake(
    config: &TomlConfigLoader,
    secret: bool,
    initiator: bool,
) -> anyhow::Result<HandshakeState> {
    let mode = if secret {
        "Noise_XXpsk3_25519_ChaChaPoly_SHA256"
    } else {
        "Noise_XX_25519_ChaChaPoly_SHA256"
    };
    let secure = config
        .get_secure_mode()
        .context("The node has no identity")?;
    let key = secure.private_key()?;
    let builder = snow::Builder::new(mode.parse()?)
        .local_private_key(key.as_bytes())?
        .prologue(PROLOGUE)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

fn pake_context(network: &str) -> Vec<u8> {
    let mut identity = PROLOGUE.to_vec();
    identity.extend_from_slice(network.as_bytes());
    identity
}

fn seal(cipher: &mut TransportState, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        plain.len() <= MAX_BODY,
        "The remote control body exceeds its limit"
    );
    let mut result = Vec::with_capacity(plain.len() + 128);
    for chunk in plain.chunks(FRAME_BYTES) {
        let offset = result.len();
        result.resize(offset + 4 + chunk.len() + 16, 0);
        let size = cipher.write_message(chunk, &mut result[offset + 4..])?;
        result[offset..offset + 4].copy_from_slice(&(size as u32).to_be_bytes());
        result.truncate(offset + 4 + size);
    }
    Ok(result)
}

fn open(cipher: &mut TransportState, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        !wire.is_empty() && wire.len() <= MAX_BODY + 4096,
        "Invalid remote control frame size"
    );
    let mut wire = wire;
    let mut result = Vec::new();
    while !wire.is_empty() {
        ensure!(wire.len() >= 4, "Truncated remote control frame");
        let size = u32::from_be_bytes(wire[..4].try_into()?) as usize;
        wire = &wire[4..];
        ensure!(
            (16..=FRAME_BYTES + 16).contains(&size) && size <= wire.len(),
            "Invalid remote control record"
        );
        let mut plain = vec![0; size];
        let count = cipher.read_message(&wire[..size], &mut plain)?;
        ensure!(
            result.len() + count <= MAX_BODY,
            "Remote control body exceeds its limit"
        );
        result.extend_from_slice(&plain[..count]);
        wire = &wire[size..];
    }
    Ok(result)
}

pub(crate) fn register(manager: &Arc<NetworkInstanceManager>) {
    let mut servers = manager.remote_control.servers.lock().unwrap();
    let mut live = Vec::new();
    for instance in manager.iter() {
        let id = *instance.key();
        let Some(service) = manager.get_instance_service(&id) else {
            continue;
        };
        let Ok(peers) = service.peers() else { continue };
        let rpc = peers.get_peer_rpc_mgr();
        live.push(id);
        if servers
            .get(&id)
            .is_some_and(|(peer, _)| *peer == rpc.my_peer_id())
        {
            continue;
        }
        let endpoint = Arc::new(Endpoint {
            manager: Arc::downgrade(manager),
            instance_id: id,
            sessions: Default::default(),
            starts: Default::default(),
        });
        rpc.rpc_server()
            .registry()
            .register(MeshControlRpcServer::new(endpoint.clone()), "");
        servers.insert(id, (rpc.my_peer_id(), endpoint));
    }
    servers.retain(|id, _| live.contains(id));
}

pub(crate) async fn sweep(manager: &Arc<NetworkInstanceManager>) {
    use subtle::ConstantTimeEq;
    let endpoints = manager
        .remote_control
        .servers
        .lock()
        .unwrap()
        .values()
        .map(|(_, endpoint)| endpoint.clone())
        .collect::<Vec<_>>();
    let _guard = manager.remote_mutation_lock().lock_owned().await;
    for endpoint in endpoints {
        let Some(config) = manager.get_instance_config(&endpoint.instance_id) else {
            continue;
        };
        let peers = manager
            .get_instance_service(&endpoint.instance_id)
            .and_then(|instance| instance.peers().ok());
        let identities = peers
            .as_ref()
            .map(|peers| peers.get_peer_map().origin_auth_snapshot());
        let policy = config.get_control_config();
        let current_secret = policy.secret_value().ok().flatten();
        endpoint.sessions.lock().await.retain(|_, session| {
            if session.touched.elapsed() >= SESSION_IDLE
                || (matches!(session.cipher, Cipher::Handshake(_))
                    && session.created.elapsed() >= Duration::from_secs(10))
            {
                return false;
            }
            if let Some(key) = session.key {
                let local = peers
                    .as_ref()
                    .is_some_and(|peers| peers.my_peer_id() == session.source)
                    && config
                        .get_secure_mode()
                        .and_then(|mode| mode.public_key().ok())
                        .is_some_and(|public| public.to_bytes() == key);
                session.network_member &= local
                    || identities
                        .as_ref()
                        .and_then(|identities| identities.lookup(session.source))
                        .is_some_and(|identity| {
                            identity.noise_static_pubkey == key
                                && matches!(
                                    identity.identity_type,
                                    PeerIdentityType::Admin | PeerIdentityType::Credential
                                )
                                && identity.secure_auth_level >= SecureAuthLevel::PeerVerified
                        });
            }
            #[cfg(unix)]
            if let Some(ssh) = &session.ssh {
                let secret = session.secret.as_ref().is_some_and(|old| {
                    current_secret
                        .as_ref()
                        .is_some_and(|current| bool::from(current.as_bytes().ct_eq(old.as_bytes())))
                });
                let Some(key) = session.key else { return false };
                if (session.secret.is_some() && !secret)
                    || !policy.permits(
                        &key,
                        session.network_member,
                        secret,
                        "ssh",
                        None,
                        Some(&ssh.user),
                        session.created.elapsed().as_secs(),
                    )
                    || (ssh.full
                        && !policy.permits(
                            &key,
                            session.network_member,
                            secret,
                            "admin",
                            None,
                            None,
                            session.created.elapsed().as_secs(),
                        ))
                {
                    return false;
                }
            }
            true
        });
    }
    manager
        .remote_control
        .clients
        .lock()
        .await
        .retain(|_, session| session.touched.elapsed() < SESSION_IDLE);
}

#[async_trait::async_trait]
impl MeshControlRpc for Arc<Endpoint> {
    type Controller = BaseController;
    async fn exchange(
        &self,
        controller: BaseController,
        request: MeshControlExchangeRequest,
    ) -> Result<MeshControlExchangeResponse> {
        match self.handle(controller, request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                tracing::debug!(reason = %error, "Remote control exchange rejected");
                Ok(MeshControlExchangeResponse {
                    rejected: true,
                    ..Default::default()
                })
            }
        }
    }
}

impl Endpoint {
    async fn handle(
        &self,
        controller: BaseController,
        request: MeshControlExchangeRequest,
    ) -> anyhow::Result<MeshControlExchangeResponse> {
        // JSON values can expand beyond their wire size. Charge request processing separately from session state.
        let _request_memory = crate::common::global_ctx::global_process_memory_governor()
            .try_reserve_owned(4 * 1024 * 1024 + request.message.len().saturating_mul(20))
            .context("The process memory budget cannot admit this control request")?;
        let manager = self.manager.upgrade().context("The daemon stopped")?;
        let config = manager
            .get_instance_config(&self.instance_id)
            .context("The node was deleted")?;
        ensure!(
            request.message.len() <= MAX_BODY + 4096 && request.pake.len() <= 128,
            "Control frame is too large"
        );
        // The RPC server accepts missing transport identity only for its verified local loopback path.
        let local = manager
            .get_instance_service(&self.instance_id)
            .context("The node is not running")?
            .peers()?
            .my_peer_id();
        let source = controller.authenticated_peer_id().unwrap_or(local);
        let network_member = controller.authenticated_peer_id().is_none()
            || (matches!(
                controller.authenticated_peer_identity_type(),
                Some(PeerIdentityType::Admin | PeerIdentityType::Credential)
            ) && controller
                .authenticated_peer_secure_auth_level()
                .is_some_and(|level| level >= SecureAuthLevel::PeerVerified));
        if request.session_id.is_empty() {
            {
                let mut starts = self.starts.lock().unwrap();
                starts.retain(|time| time.elapsed() < Duration::from_secs(1));
                ensure!(starts.len() < 16, "Control authentication admission limit");
                starts.push_back(Instant::now());
            }
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|_, session| {
                session.touched.elapsed()
                    < if matches!(session.cipher, Cipher::Handshake(_)) {
                        Duration::from_secs(10)
                    } else {
                        SESSION_IDLE
                    }
            });
            ensure!(
                sessions.len() < MAX_SESSIONS
                    && sessions
                        .values()
                        .filter(|session| session.source == source
                            && matches!(session.cipher, Cipher::Handshake(_)))
                        .count()
                        < 8,
                "Control session admission limit"
            );
            let policy = config.get_control_config();
            let memory = crate::common::global_ctx::global_process_memory_governor()
                .try_reserve_owned(128 * 1024)
                .context("The process memory budget cannot admit another control session")?;
            let mut cipher = handshake(&config, !request.pake.is_empty(), false)?;
            let (pake, secret) = if request.pake.is_empty() {
                (Vec::new(), None)
            } else {
                let secret = policy
                    .secret_value()?
                    .context("Shared control authentication is disabled")?;
                let context = pake_context(&config.get_network_identity().network_name);
                let (state, message) = Spake2::<Ed25519Group>::start_symmetric(
                    &Password::new(secret.as_bytes()),
                    &Identity::new(&context),
                );
                let key = state
                    .finish(&request.pake)
                    .map_err(|_| anyhow::anyhow!("Control phrase exchange failed"))?;
                cipher.set_psk(3, &key)?;
                (message, Some(secret))
            };
            let mut scratch = vec![0; 65535];
            ensure!(
                cipher.read_message(&request.message, &mut scratch)? == 0,
                "Unexpected handshake payload"
            );
            let size = cipher.write_message(&[], &mut scratch)?;
            let id = uuid::Uuid::new_v4();
            sessions.insert(
                id,
                ServerSession {
                    _memory: memory,
                    cipher: Cipher::Handshake(cipher),
                    source,
                    network_member,
                    secret,
                    key: None,
                    created: Instant::now(),
                    touched: Instant::now(),
                    #[cfg(unix)]
                    ssh: None,
                },
            );
            return Ok(MeshControlExchangeResponse {
                session_id: id.as_bytes().to_vec(),
                message: scratch[..size].to_vec(),
                pake,
                ..Default::default()
            });
        }
        let id = uuid::Uuid::from_slice(&request.session_id)?;
        // Remove before processing. Invalid frames and concurrent requests cannot reuse nonce state.
        let mut session = self
            .sessions
            .lock()
            .await
            .remove(&id)
            .context("Unknown control session")?;
        ensure!(
            session.source == source && session.touched.elapsed() < SESSION_IDLE,
            "Control session expired"
        );
        session.network_member &= network_member;
        let plain = match session.cipher {
            Cipher::Handshake(mut cipher) => {
                let mut scratch = vec![0; 65535];
                ensure!(
                    cipher.read_message(&request.message, &mut scratch)? == 0
                        && cipher.is_handshake_finished(),
                    "Invalid control handshake"
                );
                session.key = Some(
                    cipher
                        .get_remote_static()
                        .context("Missing node identity")?
                        .try_into()?,
                );
                session.cipher = Cipher::Transport(cipher.into_transport_mode()?);
                let Cipher::Transport(cipher) = &mut session.cipher else {
                    unreachable!()
                };
                let welcome = seal(cipher, br#"{"ready":true}"#)?;
                session.touched = Instant::now();
                self.sessions.lock().await.insert(id, session);
                return Ok(MeshControlExchangeResponse {
                    session_id: id.as_bytes().to_vec(),
                    message: welcome,
                    ..Default::default()
                });
            }
            Cipher::Transport(mut cipher) => {
                let plain = open(&mut cipher, &request.message)?;
                session.cipher = Cipher::Transport(cipher);
                plain
            }
        };
        let operation: Operation = serde_json::from_slice(&plain)?;
        let response = match self.dispatch(&manager, &mut session, &operation).await {
            Ok(response) => response,
            Err(error) => json!({ "error": super::api_error(error) }),
        };
        let Cipher::Transport(cipher) = &mut session.cipher else {
            unreachable!()
        };
        let message = seal(cipher, &serde_json::to_vec(&response)?)?;
        session.touched = Instant::now();
        let failed = response.get("error").is_some_and(|error| !error.is_null());
        if !operation.close && !failed {
            self.sessions.lock().await.insert(id, session);
        }
        Ok(MeshControlExchangeResponse {
            session_id: id.as_bytes().to_vec(),
            message,
            ..Default::default()
        })
    }

    async fn dispatch(
        &self,
        manager: &Arc<NetworkInstanceManager>,
        session: &mut ServerSession,
        operation: &Operation,
    ) -> anyhow::Result<Value> {
        // Policy checks and mutations share the same lock. A queued request cannot retain a revoked grant.
        let _guard = manager.remote_mutation_lock().lock_owned().await;
        let key = session.key.context("The caller has no node identity")?;
        let anchor = manager
            .get_instance_config(&self.instance_id)
            .context("The node was deleted")?;
        let policy = anchor.get_control_config();
        let secret = if let Some(authenticated) = &session.secret {
            use subtle::ConstantTimeEq;
            let Some(current) = policy.secret_value()? else {
                #[cfg(unix)]
                {
                    session.ssh = None;
                }
                return Err(failure(
                    "PERMISSION_DENIED",
                    "The control secret was removed.",
                    "control.secret",
                ));
            };
            if !bool::from(current.as_bytes().ct_eq(authenticated.as_bytes())) {
                #[cfg(unix)]
                {
                    session.ssh = None;
                }
                return Err(failure(
                    "PERMISSION_DENIED",
                    "The control secret changed.",
                    "control.secret",
                ));
            }
            true
        } else {
            false
        };
        #[cfg(unix)]
        if operation.method.starts_with("Ssh") {
            return super::ssh::dispatch(
                manager,
                self.instance_id,
                session,
                &policy,
                secret,
                operation,
            )
            .await;
        }
        let mut payload = operation.payload.clone();
        let target = payload
            .pointer("/meta/instance_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::parse::<uuid::Uuid>)
            .transpose()?
            .unwrap_or(self.instance_id);
        let config = manager
            .get_instance_config(&target)
            .context("Unknown target instance")?;
        let network_member = session.network_member
            && config.get_network_identity().network_name
                == anchor.get_network_identity().network_name;
        let target_secret = secret && target == self.instance_id;
        let target_policy = config.get_control_config();
        authorize(
            &target_policy,
            &key,
            network_member,
            target_secret,
            &operation.method,
            &payload,
            session.created.elapsed().as_secs(),
        )?;
        if operation.method == "SetLogConfig" {
            for instance in manager.list_network_instance_ids() {
                let sibling = manager
                    .get_instance_config(&instance)
                    .context("The instance was deleted")?;
                let member = session.network_member
                    && sibling.get_network_identity().network_name
                        == anchor.get_network_identity().network_name;
                authorize(
                    &sibling.get_control_config(),
                    &key,
                    member,
                    secret && instance == self.instance_id,
                    &operation.method,
                    &payload,
                    session.created.elapsed().as_secs(),
                )?;
            }
        }
        if !payload.is_object() {
            payload = json!({});
        }
        payload["meta"] = json!({ "instance_id": target.to_string() });
        if matches!(
            operation.method.as_str(),
            "ListCredentials" | "IssueCredential" | "RevokeCredential"
        ) {
            payload["meta"]["admin_token"] = config
                .get_network_identity()
                .network_secret
                .unwrap_or_default()
                .into();
        }
        // Remote writers must persist. A caller cannot request a memory-only mutation.
        if operation.method == "PatchConfig" {
            payload["patch"]["persist"] = true.into();
            payload["patch"]["stage"] = true.into();
        }
        if matches!(
            operation.method.as_str(),
            "SetAcl" | "PutPortForward" | "DeletePortForward"
        ) {
            payload["persist"] = true.into();
            payload["stage"] = true.into();
        }
        if operation.method == "WatchChanges" {
            let wait = payload
                .get("max_wait_ms")
                .and_then(Value::as_u64)
                .unwrap_or(250)
                .min(250);
            payload["max_wait_ms"] = wait.into();
        }
        let mut service = ControlPlaneService::for_owned_instances(manager.clone());
        service.externally_locked = true;
        let mut response = service
            .json_call_method(BaseController::default(), &operation.method, payload)
            .await?;
        if operation.method == "ListInstances"
            && !target_policy.full_access(&key, network_member, target_secret)
            && !target_policy.permits(
                &key,
                network_member,
                target_secret,
                "instances.read",
                None,
                None,
                session.created.elapsed().as_secs(),
            )
        {
            if let Some(rows) = response.get_mut("instances").and_then(Value::as_array_mut) {
                rows.retain(|row| row["instance_id"] == target.to_string());
            }
        }
        Ok(response)
    }
}

fn authorize(
    policy: &crate::common::config::ControlConfig,
    key: &[u8; 32],
    member: bool,
    secret: bool,
    method: &str,
    payload: &Value,
    age: u64,
) -> anyhow::Result<()> {
    if matches!(method, "GetCapabilities" | "ListInstances")
        && super::policy::CAPABILITIES
            .iter()
            .any(|capability| policy.permits(key, member, secret, capability, None, None, age))
    {
        return Ok(());
    }
    let capability = match method {
        "GetConfig" => "config.read",
        "PatchConfig" | "ValidateConfig" | "SetAcl" | "PutPortForward" | "DeletePortForward" => {
            "config.write"
        }
        "ReadLogs" | "GetLogConfig" => "logs.read",
        "SetLogConfig" => "logs.write",
        "ListCredentials" => "credentials.read",
        "IssueCredential" | "RevokeCredential" => "credentials.write",
        "CreateInstance" => "admin",
        "StartInstance" => "instances.start",
        "StopInstance" => "instances.stop",
        "DeleteInstance" => "instances.delete",
        "ListInstances" => "instances.read",
        name if super::read::METHODS.contains(&name) => "status.read",
        _ => {
            return Err(failure(
                "PERMISSION_DENIED",
                "The remote operation is not permitted.",
                "method",
            ));
        }
    };
    let paths: Vec<&str> = match method {
        "PatchConfig" | "ValidateConfig" => ["field_mask", "clear_paths"]
            .into_iter()
            .flat_map(|field| {
                payload
                    .get("patch")
                    .and_then(|patch| patch.get(field))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
            })
            .collect(),
        "SetAcl" => vec!["acl"],
        "PutPortForward" | "DeletePortForward" => vec!["forward"],
        _ => Vec::new(),
    };
    let permitted = if capability == "config.write" {
        !paths.is_empty()
            && paths.iter().all(|path| {
                let privileged = path == &"control"
                    || path.starts_with("control.")
                    || path == &"gui"
                    || path.starts_with("gui.")
                    || path == &"network"
                    || path.starts_with("network.")
                    || path == &"identity"
                    || path.starts_with("identity.")
                    || crate::common::config_schema::OPTIONS.iter().any(|option| {
                        option.kind == crate::common::config_schema::Kind::Path
                            && (option.path == *path
                                || option.path.starts_with(&format!("{path}.")))
                    });
                (!privileged || policy.permits(key, member, secret, "admin", None, None, age))
                    && policy.permits(key, member, secret, capability, Some(path), None, age)
            })
    } else {
        policy.permits(key, member, secret, capability, None, None, age)
    };
    if !permitted {
        return Err(failure(
            "PERMISSION_DENIED",
            "The control policy denies this operation.",
            "control.grant",
        ));
    }
    Ok(())
}

async fn exchange(
    rpc: &PeerRpcManager,
    destination: PeerId,
    request: MeshControlExchangeRequest,
) -> anyhow::Result<MeshControlExchangeResponse> {
    let client = rpc
        .rpc_client()
        .scoped_client::<MeshControlRpcClientFactory<BaseController>>(
            rpc.my_peer_id(),
            destination,
            "".into(),
        );
    let response = client
        .exchange(
            BaseController {
                timeout_ms: 30_000,
                ..Default::default()
            },
            request,
        )
        .await?;
    if response.rejected {
        return Err(failure(
            "PERMISSION_DENIED",
            "The remote node rejected the control credentials or session. Reconnect before retrying.",
            "remote",
        ));
    }
    Ok(response)
}

impl ClientSession {
    async fn connect(
        manager: &Arc<NetworkInstanceManager>,
        instance_id: uuid::Uuid,
        selector: &str,
        secret: &str,
    ) -> anyhow::Result<Self> {
        let memory = crate::common::global_ctx::global_process_memory_governor()
            .try_reserve_owned(128 * 1024)
            .context("The process memory budget cannot admit another control client")?;
        let config = manager
            .get_instance_config(&instance_id)
            .context("Unknown source instance")?;
        let key = config.get_control_config().resolve_key(selector).map_err(|_| failure("INVALID_ARGUMENT", "The remote public key or alias is unknown or ambiguous. Configure control.keys.", "target"))?;
        let peers = manager
            .get_instance_service(&instance_id)
            .context("The source instance is not running")?
            .peers()?;
        let identities = peers.get_peer_map().origin_auth_snapshot();
        let routes = peers.list_routes().await;
        let local_key = config
            .get_secure_mode()
            .context("The source node has no identity")?
            .public_key()?
            .to_bytes();
        let destination = if local_key == key {
            Some(peers.my_peer_id())
        } else {
            routes
                .iter()
                .find(|route| {
                    identities
                        .lookup(route.peer_id)
                        .is_some_and(|identity| identity.noise_static_pubkey == key)
                        || peers
                            .get_peer_map()
                            .get_peer_public_key(route.peer_id)
                            .is_some_and(|candidate| candidate.as_slice() == key)
                })
                .map(|route| route.peer_id)
        }
        .ok_or_else(|| {
            failure(
                "UNAVAILABLE",
                "The pinned remote key has no route from this instance.",
                "target",
            )
        })?;
        let rpc = peers.get_peer_rpc_mgr();
        let mut cipher = handshake(&config, !secret.is_empty(), true)?;
        let mut scratch = vec![0; 65535];
        let size = cipher.write_message(&[], &mut scratch)?;
        let pake = if secret.is_empty() {
            None
        } else {
            let context = pake_context(&config.get_network_identity().network_name);
            Some(Spake2::<Ed25519Group>::start_symmetric(
                &Password::new(secret.as_bytes()),
                &Identity::new(&context),
            ))
        };
        let first = exchange(
            &rpc,
            destination,
            MeshControlExchangeRequest {
                message: scratch[..size].to_vec(),
                pake: pake
                    .as_ref()
                    .map(|(_, message)| message.clone())
                    .unwrap_or_default(),
                ..Default::default()
            },
        )
        .await?;
        cipher.read_message(&first.message, &mut scratch)?;
        ensure!(
            cipher.get_remote_static() == Some(key.as_slice()),
            "The remote node key does not match the pinned key"
        );
        if let Some((state, _)) = pake {
            let key = state
                .finish(&first.pake)
                .map_err(|_| anyhow::anyhow!("Control phrase exchange failed"))?;
            cipher.set_psk(3, &key)?;
        }
        let size = cipher.write_message(&[], &mut scratch)?;
        let welcome = exchange(
            &rpc,
            destination,
            MeshControlExchangeRequest {
                session_id: first.session_id.clone(),
                message: scratch[..size].to_vec(),
                ..Default::default()
            },
        )
        .await?;
        let mut cipher = cipher.into_transport_mode()?;
        let _: Value = serde_json::from_slice(&open(&mut cipher, &welcome.message)?)?;
        Ok(Self {
            _memory: memory,
            rpc,
            source_instance: instance_id,
            destination,
            wire_id: uuid::Uuid::from_slice(&first.session_id)?,
            cipher,
            touched: Instant::now(),
        })
    }

    async fn call(
        &mut self,
        method: String,
        payload: Value,
        close: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let plain = serde_json::to_vec(&Operation {
            method,
            payload,
            close,
        })?;
        let message = seal(&mut self.cipher, &plain)?;
        let response = exchange(
            &self.rpc,
            self.destination,
            MeshControlExchangeRequest {
                session_id: self.wire_id.as_bytes().to_vec(),
                message,
                ..Default::default()
            },
        )
        .await?;
        self.touched = Instant::now();
        open(&mut self.cipher, &response.message)
    }
}

impl ControlPlaneService {
    pub(super) async fn call_remote_inner(
        &self,
        _: BaseController,
        request: CallRemoteRequest,
    ) -> anyhow::Result<CallRemoteResponse> {
        let id = self.select_instance(request.meta.as_ref())?;
        let payload: Value = serde_json::from_slice(&request.payload).map_err(|_| {
            failure(
                "INVALID_ARGUMENT",
                "Invalid remote request body.",
                "payload",
            )
        })?;
        let mut session = if request.session_id.is_empty() {
            ClientSession::connect(&self.manager, id, &request.target, &request.secret).await?
        } else {
            let session_id = request.session_id.parse::<uuid::Uuid>()?;
            let session = self
                .manager
                .remote_control
                .clients
                .lock()
                .await
                .remove(&session_id)
                .context("Unknown local control session")?;
            ensure!(
                session.source_instance == id && session.touched.elapsed() < SESSION_IDLE,
                "The local control session expired"
            );
            session
        };
        let payload = session
            .call(request.method, payload, !request.keep_session)
            .await?;
        let mut session_id = String::new();
        let failed = serde_json::from_slice::<Value>(&payload)
            .ok()
            .is_some_and(|response| response.get("error").is_some_and(|error| !error.is_null()));
        if request.keep_session && !failed {
            let mut clients = self.manager.remote_control.clients.lock().await;
            clients.retain(|_, session| session.touched.elapsed() < SESSION_IDLE);
            ensure!(
                clients.len() < MAX_SESSIONS,
                "The local control session limit is reached"
            );
            let id = if request.session_id.is_empty() {
                uuid::Uuid::new_v4()
            } else {
                request.session_id.parse()?
            };
            session_id = id.to_string();
            clients.insert(id, session);
        }
        Ok(CallRemoteResponse {
            payload,
            session_id,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::config::ConfigFileControl,
        peers::tests::{connect_peer_manager, wait_route_appear},
    };
    use base64::{Engine, prelude::BASE64_STANDARD};

    fn node(seed: u8, control: &str) -> TomlConfigLoader {
        TomlConfigLoader::new_from_str(&format!(
            r#"
[node]
threads = 1
[identity]
private_key = "{}"
[network]
name = "mesh-control-test"
secret = "mesh-control-test-secret"
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
{}
"#,
            BASE64_STANDARD.encode([seed; 32]),
            control
        ))
        .unwrap()
    }

    #[test]
    fn limited_writers_cannot_replace_privileged_interfaces_or_create_instances() {
        let source = node(41, "");
        let key = source
            .get_secure_mode()
            .unwrap()
            .public_key()
            .unwrap()
            .to_bytes();
        let target = node(
            42,
            &format!(
                "[[control.grant]]\nfrom = ['pubkey:{}']\npermissions = ['config.write']\nconfig_paths = ['*']",
                BASE64_STANDARD.encode(key)
            ),
        );
        let policy = target.get_control_config();
        assert!(
            authorize(
                &policy,
                &key,
                true,
                false,
                "PatchConfig",
                &json!({"patch": {"field_mask": ["relay.policy"]}}),
                0
            )
            .is_ok()
        );
        for path in [
            "control",
            "control.allow",
            "gui",
            "gui.open",
            "network.secret_file",
            "network.secret",
            "network.name",
            "identity.private_key",
            "identity.private_key_file",
            "log.dir",
        ] {
            assert!(
                authorize(
                    &policy,
                    &key,
                    true,
                    false,
                    "PatchConfig",
                    &json!({"patch": {"field_mask": [path]}}),
                    0
                )
                .is_err(),
                "{path}"
            );
        }
        assert!(authorize(&policy, &key, true, false, "CreateInstance", &json!({}), 0).is_err());
    }

    #[tokio::test]
    async fn remote_control_proves_keys_enforces_grants_and_authenticates_phrases() {
        let manager = Arc::new(NetworkInstanceManager::new());
        let a = node(31, "");
        let key_a = a
            .get_secure_mode()
            .unwrap()
            .public_key()
            .unwrap()
            .to_bytes();
        let b = node(
            32,
            &format!(
                "[control]\nallow = [\"pubkey:{}\"]\n",
                BASE64_STANDARD.encode(key_a)
            ),
        );
        let key_b = b
            .get_secure_mode()
            .unwrap()
            .public_key()
            .unwrap()
            .to_bytes();
        let a_id = manager
            .run_network_instance(a.clone(), false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        let b_id = manager
            .run_network_instance(b.clone(), false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        super::super::maintenance::wait_ready(&manager, a_id)
            .await
            .unwrap();
        super::super::maintenance::wait_ready(&manager, b_id)
            .await
            .unwrap();
        let peers_a = manager
            .get_instance_service(&a_id)
            .unwrap()
            .peers()
            .unwrap();
        let peers_b = manager
            .get_instance_service(&b_id)
            .unwrap()
            .peers()
            .unwrap();
        connect_peer_manager(peers_a.clone(), peers_b.clone()).await;
        wait_route_appear(peers_a, peers_b).await.unwrap();
        register(&manager);
        let service = ControlPlaneService::for_owned_instances(manager.clone());
        let request = |method: &str, payload: Value, secret: &str| CallRemoteRequest {
            meta: Some(RequestMeta {
                instance_id: a_id.to_string(),
                ..Default::default()
            }),
            target: BASE64_STANDARD.encode(key_b),
            method: method.into(),
            payload: serde_json::to_vec(&payload).unwrap(),
            secret: secret.into(),
            ..Default::default()
        };
        let response = service
            .call_remote_inner(
                BaseController::default(),
                request("GetConfig", json!({}), ""),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&response.payload).unwrap();
        assert!(
            response.get("error").is_none_or(Value::is_null),
            "{response}"
        );
        let patch = json!({"patch": {"expected_revision": "1", "field_mask": ["relay.use_relays"], "values": {"toml": "[relay]\nuse_relays=false\n"}, "persist": false}});
        let changed = service
            .call_remote_inner(
                BaseController::default(),
                request("PatchConfig", patch.clone(), ""),
            )
            .await
            .unwrap();
        let changed: Value = serde_json::from_slice(&changed.payload).unwrap();
        assert!(changed.get("error").is_none_or(Value::is_null), "{changed}");
        let path = manager
            .get_instance_config_control(&b_id)
            .unwrap()
            .path
            .unwrap();
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(stored.contains("use_relays = false"));
        let stale = service
            .call_remote_inner(BaseController::default(), request("PatchConfig", patch, ""))
            .await
            .unwrap();
        let stale: Value = serde_json::from_slice(&stale.payload).unwrap();
        assert_eq!(stale["error"]["code"], "conflict");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), stored);

        #[cfg(unix)]
        {
            let mut invalid = request(
                "SshOpen",
                json!({"user": "lt_account_that_does_not_exist"}),
                "",
            );
            invalid.keep_session = true;
            let rejected = service
                .call_remote_inner(BaseController::default(), invalid)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&rejected.payload).unwrap();
            assert!(body.get("error").is_some_and(|error| !error.is_null()));
            assert!(rejected.session_id.is_empty());
            assert!(manager.remote_control.clients.lock().await.is_empty());
            let endpoint = manager.remote_control.servers.lock().unwrap()[&b_id]
                .1
                .clone();
            assert!(endpoint.sessions.lock().await.is_empty());
        }

        let restricted = node(
            32,
            &format!(
                "[[control.grant]]\nfrom = [\"pubkey:{}\"]\npermissions = [\"config.read\"]\n",
                BASE64_STANDARD.encode(key_a)
            ),
        );
        restricted.set_id(b_id);
        b.replace_active(&restricted);
        let validation = service.call_remote_inner(BaseController::default(), request("ValidateConfig", json!({"patch": {
            "expected_revision": "2", "field_mask": ["identity.private_key_file"], "values": {"toml": "[identity]\nprivate_key_file='/a/path/that/must/not/be/read'\n"}
        }}), "")).await.unwrap();
        let validation: Value = serde_json::from_slice(&validation.payload).unwrap();
        assert_eq!(validation["error"]["code"], "permission_denied");

        let phrase = node(32, "[control]\nsecret = 'test control phrase'\n");
        phrase.set_id(b_id);
        b.replace_active(&phrase);
        assert!(
            service
                .call_remote_inner(
                    BaseController::default(),
                    request("GetConfig", json!({}), "wrong phrase")
                )
                .await
                .is_err()
        );
        let good = service
            .call_remote_inner(
                BaseController::default(),
                request("GetConfig", json!({}), "test control phrase"),
            )
            .await
            .unwrap();
        let good: Value = serde_json::from_slice(&good.payload).unwrap();
        assert!(good.get("error").is_none_or(Value::is_null), "{good}");
        assert!(!good.to_string().contains("test control phrase"));
        manager.stop_network_instance(a_id).await.unwrap();
        manager.stop_network_instance(b_id).await.unwrap();
    }
}
