//! `lowertier gui`: a browser interface served on loopback by the CLI process.
//!
//! The page exchanges TOML documents with this server, the same format as the configuration
//! file, and the server forwards each call to the selected daemon with the control token. The
//! token never reaches the browser. Every API request must carry the per-run key from the URL
//! fragment, and requests with a foreign Host or Origin are refused, so other sites open in the
//! browser cannot reach the daemon through this port.

mod codec;
pub mod overlay;

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{
    cli::{
        args::{ApplyArgs, Arguments, GuiArgs},
        client::{self, Client, Response as CliResponse, Target},
        commands::{config, status},
        error::{CliError, Result},
    },
    common::{config_schema, runtime_registry},
    proto::{
        api::control::v1::{ControlPlaneV1Rpc as _, ListPathsRequest, ListRoutesRequest, Page},
        rpc_types::controller::BaseController,
    },
};

const INDEX: &[u8] = include_bytes!("../../gui/dist/index.html");
const SCRIPT: &[u8] = include_bytes!("../../gui/dist/app.js");
const STYLE: &[u8] = include_bytes!("../../gui/dist/app.css");

const KEY_HEADER: &str = "x-lowertier-key";
const MAX_BODY: usize = 1 << 20;
const TOML: &str = "application/toml; charset=utf-8";
/// Both ends close a portal connection after 60 s without traffic. Dial again before that.
const REUSE_IDLE: Duration = Duration::from_secs(20);
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(5);

/// Credentials and the daemon chosen on the command line.
struct Defaults {
    target: Option<Target>,
    target_error: Option<CliError>,
    token: Option<String>,
    admin_token: Option<String>,
    instance: Option<String>,
}

struct Server {
    key: String,
    hosts: Vec<String>,
    /// Serve only the configured daemon. Set for network-facing servers, whose clients must not
    /// reach the other daemons of the machine through their token files.
    pinned: bool,
    defaults: Defaults,
    /// Open connections by portal and instance, with their last use.
    clients: Mutex<HashMap<(String, String), (Arc<Client>, Instant)>>,
}

type Reply = Response<Full<Bytes>>;

fn reply(status: StatusCode, kind: &str, body: impl Into<Bytes>) -> Reply {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, kind.parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; \
         form-action 'none'"
            .parse()
            .unwrap(),
    );
    response
}

fn toml_reply(value: Value) -> Reply {
    match codec::document(value) {
        Ok(body) => reply(StatusCode::OK, TOML, body),
        Err(error) => error_reply(&error),
    }
}

fn error_reply(error: &CliError) -> Reply {
    let status = match error.0.code.as_str() {
        "invalid_argument" | "validation" => StatusCode::BAD_REQUEST,
        "permission_denied" | "unauthenticated" => StatusCode::FORBIDDEN,
        "not_found" => StatusCode::NOT_FOUND,
        "ambiguous" | "conflict" | "restart_required" => StatusCode::CONFLICT,
        "unavailable" | "deadline_exceeded" => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let error = json!({ "error": {
        "code": error.0.code,
        "message": error.0.message,
        "field_path": error.0.field_path,
        "retryable": error.0.retryable,
    }});
    reply(status, TOML, codec::document(error).unwrap_or_default())
}

fn query(request: &Request<Incoming>) -> HashMap<String, String> {
    request
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

/// `PATH=VALUE` assignments for every option in a `[set]` table in the public layout.
fn assignments(prefix: &str, table: &toml::Table, out: &mut Vec<String>) -> Result<()> {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if config_schema::lookup(&path).is_some() {
            let text = match value {
                toml::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            out.push(format!("{path}={text}"));
        } else if let toml::Value::Table(inner) = value {
            assignments(&path, inner, out)?;
        } else {
            let message = config_schema::retired_message(&path)
                .unwrap_or_else(|| format!("unknown option \"{path}\""));
            return Err(CliError::new("invalid_argument", message, &path));
        }
    }
    Ok(())
}

impl Server {
    /// Requests must name this server, so a rebinding DNS name cannot reach it.
    fn same_origin(&self, request: &Request<Incoming>) -> bool {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|host| host.to_str().ok());
        if !host.is_some_and(|host| self.hosts.iter().any(|allowed| allowed == host)) {
            return false;
        }
        match request.headers().get(header::ORIGIN) {
            None => true,
            Some(origin) => origin.to_str().ok().is_some_and(|origin| {
                self.hosts
                    .iter()
                    .any(|allowed| origin == format!("http://{allowed}"))
            }),
        }
    }

    fn authorized(&self, request: &Request<Incoming>, trusted: bool) -> bool {
        use subtle::ConstantTimeEq as _;
        trusted
            || request
                .headers()
                .get(KEY_HEADER)
                .is_some_and(|key| key.as_bytes().ct_eq(self.key.as_bytes()).into())
    }

    fn target(&self, node: Option<&str>) -> Result<Target> {
        let node = node.filter(|node| !node.is_empty() && !self.pinned);
        let Some(node) = node else {
            return match (&self.defaults.target, &self.defaults.target_error) {
                (Some(target), _) => Ok(Target {
                    portal: target.portal.clone(),
                    token_file: target.token_file.clone(),
                    name: target.name.clone(),
                }),
                (None, Some(error)) => Err(CliError(error.0.clone())),
                (None, None) => Err(CliError::new("not_found", "No daemon is selected.", "node")),
            };
        };
        runtime_registry::live_records()
            .into_iter()
            .find(|record| record.portal == node || record.name == node)
            .map(|record| Target {
                portal: record.portal,
                token_file: record.token_file,
                name: Some(record.name),
            })
            .ok_or_else(|| {
                CliError::new(
                    "not_found",
                    format!("No daemon {node:?} is running."),
                    "node",
                )
            })
    }

    async fn client(&self, params: &HashMap<String, String>) -> Result<Arc<Client>> {
        let target = self.target(params.get("node").map(String::as_str))?;
        let instance = params
            .get("instance")
            .filter(|instance| !instance.is_empty())
            .cloned()
            .or_else(|| self.defaults.instance.clone());
        let key = (target.portal.clone(), instance.clone().unwrap_or_default());
        if let Some((client, used)) = self.clients.lock().await.get_mut(&key)
            && used.elapsed() < REUSE_IDLE
        {
            *used = Instant::now();
            return Ok(client.clone());
        }
        // A token given on the command line belongs to the daemon chosen there.
        let token = self
            .defaults
            .target
            .as_ref()
            .is_some_and(|default| default.portal == target.portal)
            .then(|| self.defaults.token.clone())
            .flatten();
        let mut client = Client::open_with(
            token,
            self.defaults.admin_token.clone(),
            target,
            "gui".into(),
        )
        .await?;
        let (id, name) = client.select_instance(instance.as_deref()).await?;
        client.meta.instance_id = id;
        client.instance_name = Some(name);
        let client = Arc::new(client);
        self.clients
            .lock()
            .await
            .insert(key, (client.clone(), Instant::now()));
        Ok(client)
    }

    /// Drop a connection after a transport failure so the next request dials again.
    async fn forget(&self, client: &Arc<Client>, error: &CliError) {
        if matches!(error.0.code.as_str(), "unavailable" | "deadline_exceeded") {
            self.clients
                .lock()
                .await
                .retain(|_, (open, _)| !Arc::ptr_eq(open, client));
        }
    }

    fn nodes(&self) -> Value {
        let records = if self.pinned {
            Vec::new()
        } else {
            runtime_registry::live_records()
        };
        let selected = self.defaults.target.as_ref().map(|target| &target.portal);
        let mut nodes: Vec<Value> = records
            .iter()
            .map(|record| {
                json!({
                    "name": record.name,
                    "pid": record.pid,
                    "portal": record.portal,
                    "instances": record.instances,
                    "version": record.version,
                    "default": Some(&record.portal) == selected,
                })
            })
            .collect();
        if let Some(target) = &self.defaults.target
            && !records.iter().any(|record| record.portal == target.portal)
        {
            nodes.insert(
                0,
                json!({
                    "name": target.name.clone().unwrap_or_else(|| target.portal.clone()),
                    "portal": target.portal,
                    "instances": [],
                    "default": true,
                }),
            );
        }
        let error = self
            .defaults
            .target_error
            .as_ref()
            .map(|error| json!({ "code": error.0.code, "message": error.0.message }));
        json!({ "nodes": nodes, "version": crate::VERSION, "error": error })
    }

    async fn snapshot(&self, client: &Client) -> Result<Value> {
        let (view, routes, paths) = tokio::join!(
            status::fetch(client),
            client.rpc.list_routes(
                client.controller(),
                ListRoutesRequest {
                    meta: client.meta(),
                    page: Some(Page {
                        limit: 256,
                        page_token: String::new(),
                    }),
                    include_paths: true,
                },
            ),
            client.rpc.list_paths(
                client.controller(),
                ListPathsRequest {
                    meta: client.meta(),
                },
            )
        );
        let view = view?;
        let routes = routes?;
        if let Some(error) = routes.error {
            return Err(error.into());
        }
        let paths = paths?;
        if let Some(error) = paths.error {
            return Err(error.into());
        }
        let peers = &view.peers;
        Ok(json!({
            "daemon": view.daemon,
            "portal": view.portal,
            "instance": client.instance_name,
            "sampled_at_unix_ms": chrono::Utc::now().timestamp_millis(),
            "node": codec::message("GetNodeResponse", &view.node)?,
            "peers": codec::messages("PeerSnapshot", &peers.peers)?,
            "active_policy": peers.active_policy,
            "relay": codec::message("GetRelayResponse", &view.relay)?,
            "discovery": codec::message("GetDiscoveryResponse", &view.discovery)?,
            "listeners": codec::message("ListListenersResponse", &view.listeners)?,
            "routes": codec::messages("RouteSnapshot", &routes.routes)?,
            "paths": codec::messages("PathStatus", &paths.paths)?,
        }))
    }

    async fn config(&self, client: &Client) -> Result<Value> {
        let CliResponse::Config(view) = config::get(client, None).await? else {
            return Err(CliError::new(
                "internal",
                "Unexpected configuration reply.",
                "",
            ));
        };
        Ok(json!({
            "revision": view.revision,
            "restart_fields": view.restart_fields,
            "active": view.active,
            "desired": view.desired,
        }))
    }

    /// Apply a `[set]` table in the public layout and a `clear` list of option paths.
    async fn set(&self, client: &Client, mut body: toml::Table) -> Result<Value> {
        let mut values = toml::Table::new();
        let mut mask = Vec::new();
        if let Some(set) = body.remove("set") {
            let toml::Value::Table(set) = set else {
                return Err(CliError::new(
                    "invalid_argument",
                    "set must be a table.",
                    "set",
                ));
            };
            let mut found = Vec::new();
            assignments("", &set, &mut found)?;
            for assignment in found {
                let spec = config_schema::apply_set(&mut values, &assignment).map_err(|error| {
                    CliError::new("invalid_argument", format!("{error:#}"), "set")
                })?;
                mask.push(spec.path.to_owned());
            }
        }
        let clear: Vec<String> = match body.remove("clear") {
            Some(toml::Value::Array(paths)) => paths
                .iter()
                .filter_map(|path| path.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        if mask.is_empty() && clear.is_empty() {
            return Err(CliError::new(
                "invalid_argument",
                "Nothing to change.",
                "set",
            ));
        }
        let apply = ApplyArgs {
            stage: body
                .get("stage")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
            ..Default::default()
        };
        match config::patch_noting(client, values, mask, clear, &apply, None).await? {
            (CliResponse::PatchConfigResponse(response), unsaved) => {
                let mut reply = codec::message("PatchConfigResponse", &response)?;
                if let Some(reason) = unsaved {
                    reply["unsaved"] = Value::String(reason);
                }
                Ok(reply)
            }
            _ => Err(CliError::new("internal", "Unexpected patch reply.", "")),
        }
    }

    async fn call(&self, client: &Client, method: &str, body: toml::Table) -> Result<Value> {
        let (input, output) = codec::method(method).ok_or_else(|| {
            CliError::new(
                "not_found",
                format!("No control method {method}."),
                "method",
            )
        })?;
        let mut request = match codec::to_json(body)? {
            Value::Object(request) => request,
            _ => serde_json::Map::new(),
        };
        request.insert("meta".into(), serde_json::to_value(&client.meta)?);
        let request = Value::Object(request);
        codec::validate(input, &request)?;
        let response = client
            .rpc
            .json_call_method(
                BaseController {
                    timeout_ms: 30_000,
                    ..Default::default()
                },
                method,
                request,
            )
            .await?;
        if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
            return Err(CliError(serde_json::from_value(error.clone())?));
        }
        codec::normalize(output, response)
    }

    async fn api(&self, request: Request<Incoming>, path: &str) -> Result<Reply> {
        let method = request.method().clone();
        let params = query(&request);
        match (&method, path) {
            (&Method::GET, "nodes") => return Ok(toml_reply(self.nodes())),
            (&Method::GET, "schema") => return Ok(toml_reply(schema())),
            _ => {}
        }
        let body = if method == Method::POST {
            let bytes = Limited::new(request.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|_| {
                    CliError::new("invalid_argument", "The request body is too large.", "")
                })?
                .to_bytes();
            codec::parse(&bytes)?
        } else {
            toml::Table::new()
        };
        let client = self.client(&params).await?;
        let result = match (&method, path) {
            (&Method::GET, "snapshot") => {
                tokio::time::timeout(SNAPSHOT_DEADLINE, self.snapshot(&client))
                    .await
                    .unwrap_or_else(|_| {
                        Err(CliError::new(
                            "deadline_exceeded",
                            format!(
                                "No answer from {} for {}s.",
                                client.target.portal,
                                SNAPSHOT_DEADLINE.as_secs()
                            ),
                            "",
                        ))
                    })
            }
            (&Method::GET, "config") => self.config(&client).await,
            (&Method::POST, "config") => self.set(&client, body).await,
            (&Method::POST, rpc) if rpc.starts_with("rpc/") => {
                self.call(&client, &rpc["rpc/".len()..], body).await
            }
            _ => Err(CliError::new("not_found", format!("No API {path}."), "")),
        };
        if let Err(error) = &result {
            self.forget(&client, error).await;
        }
        result.map(toml_reply)
    }

    async fn handle(self: Arc<Self>, request: Request<Incoming>, trusted: bool) -> Reply {
        if !self.same_origin(&request) {
            return reply(
                StatusCode::FORBIDDEN,
                "text/plain",
                "Forbidden host or origin.",
            );
        }
        let path = request.uri().path().to_owned();
        if let Some(api) = path.strip_prefix("/api/") {
            if !self.authorized(&request, trusted) {
                return error_reply(&CliError::new(
                    "unauthenticated",
                    "The access key is missing or wrong.",
                    "key",
                ));
            }
            return self
                .api(request, api)
                .await
                .unwrap_or_else(|error| error_reply(&error));
        }
        if request.method() != Method::GET {
            return reply(StatusCode::METHOD_NOT_ALLOWED, "text/plain", "");
        }
        match path.as_str() {
            "/app.js" => reply(StatusCode::OK, "text/javascript; charset=utf-8", SCRIPT),
            "/app.css" => reply(StatusCode::OK, "text/css; charset=utf-8", STYLE),
            _ if trusted => reply(StatusCode::OK, "text/html; charset=utf-8", open_index()),
            _ => reply(StatusCode::OK, "text/html; charset=utf-8", INDEX),
        }
    }
}

/// The page for a keyless peer: a marker tells the script not to ask for the key.
fn open_index() -> Bytes {
    let page = String::from_utf8_lossy(INDEX);
    Bytes::from(page.replacen(
        "<head>",
        "<head><meta name=\"lowertier-open\" content=\"1\">",
        1,
    ))
}

/// Serve HTTP/1 on one accepted connection until it closes.
///
/// `trusted` connections come from a `gui.open` network and need no key.
async fn serve_stream<S>(server: Arc<Server>, stream: S, trusted: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |request| {
        let server = server.clone();
        async move { Ok::<_, Infallible>(server.handle(request, trusted).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// The option registry for the settings view.
fn schema() -> Value {
    use config_schema::Kind;
    let options: Vec<Value> = config_schema::OPTIONS
        .iter()
        .map(|spec| {
            let (kind, values) = match spec.kind {
                Kind::Enum(values) => ("enum", values.to_vec()),
                Kind::Bool => ("bool", vec![]),
                Kind::Int => ("int", vec![]),
                Kind::Str | Kind::Path | Kind::Proxy(_) => ("string", vec![]),
                Kind::StrList => ("list", vec![]),
                Kind::IntList => ("intlist", vec![]),
                Kind::Duration => ("duration", vec![]),
                Kind::BitRate => ("bitrate", vec![]),
                Kind::Bytes => ("bytes", vec![]),
                Kind::Table => ("table", vec![]),
                Kind::Tables => ("tables", vec![]),
            };
            json!({
                "path": spec.path,
                "kind": kind,
                "values": values,
                "type": spec.kind.describe(),
                "apply": spec.apply.as_str(),
                "default": spec.default,
                "secret": spec.secret,
                "doc": spec.doc,
                "fields": config_schema::table_fields(spec.path)
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "options": options })
}

fn open_browser(url: &str) {
    let mut command = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        let mut command = std::process::Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else {
        std::process::Command::new("xdg-open")
    };
    let _ = command
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

pub async fn serve(args: &Arguments, gui: &GuiArgs) -> Result<()> {
    let listen = gui
        .listen
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 15880)));
    if !listen.ip().is_loopback() {
        return Err(CliError::new(
            "invalid_argument",
            "The GUI serves plain HTTP and listens on loopback only. Use SSH port forwarding to \
             reach it from another machine.",
            "listen",
        ));
    }
    let bind = |address: SocketAddr| -> std::io::Result<_> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        let port = socket.local_addr()?.as_socket().unwrap().port();
        let guard = crate::rpc_service::protected_port::protect_gui_port(port)?;
        // Protect the selected port before the socket can accept proxy connections.
        socket.listen(128)?;
        let listener = tokio::net::TcpListener::from_std(socket.into())?;
        Ok((listener, guard))
    };
    let (listener, _port_guard) = match bind(listen) {
        Ok(bound) => bound,
        // The default port is taken, perhaps by another `lowertier gui`: use any free port.
        Err(_) if gui.listen.is_none() => bind(SocketAddr::new(listen.ip(), 0))
            .map_err(|error| CliError::new("unavailable", error.to_string(), "listen"))?,
        Err(error) => {
            return Err(CliError::new(
                "unavailable",
                format!("Cannot listen on {listen}: {error}"),
                "listen",
            ));
        }
    };
    let address = listener
        .local_addr()
        .map_err(|error| CliError::new("internal", error.to_string(), "listen"))?;
    let port = address.port();
    let mut hosts = vec![address.to_string(), format!("localhost:{port}")];
    if address.is_ipv4() {
        hosts.push(format!("127.0.0.1:{port}"));
    }
    let (target, target_error) = match client::target(args) {
        Ok(target) => (Some(target), None),
        Err(error) => (None, Some(error)),
    };
    let key = {
        use rand::RngCore as _;
        let mut bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let url = format!("http://{address}/#key={key}");
    let server = Arc::new(Server {
        key,
        hosts,
        pinned: false,
        defaults: Defaults {
            target,
            target_error,
            token: args.token.clone(),
            admin_token: args.admin_token.clone(),
            instance: args.instance.clone(),
        },
        clients: Mutex::new(HashMap::new()),
    });
    println!("LowTier GUI: {url}");
    println!("Press Ctrl-C to stop.");
    if !gui.no_open {
        open_browser(&url);
    }
    let accept = async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(serve_stream(server.clone(), stream, false));
        }
    };
    tokio::select! {
        _ = accept => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
