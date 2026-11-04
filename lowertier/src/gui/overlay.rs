//! The GUI on an instance's overlay address, enabled by default.
//!
//! The daemon serves the page itself, so it follows the instance and needs no second process.
//! In userspace mode the listener lives in the data-plane TCP stack. Otherwise it is an operating
//! system socket bound to the overlay address. Only peers inside `gui.allow` are served, and
//! every API request needs the stable key from `gui.key_file`.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use cidr::IpCidr;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};
use uuid::Uuid;

use super::{Defaults, Server, serve_stream};
use crate::{
    cli::client::Target,
    common::{
        config::{ConfigLoader as _, TomlConfigLoader},
        log,
    },
    instance_manager::NetworkInstanceManager,
    rpc_service::control::token::ControlToken,
};

const DEFAULT_PORT: u16 = 15880;
/// How often the bound address is compared with the instance's current overlay address.
const REBIND_CHECK: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 32;

struct Settings {
    id: Uuid,
    name: String,
    port: u16,
    allow: Vec<IpCidr>,
    open: Vec<IpCidr>,
    key: String,
    portal: SocketAddr,
    token_file: PathBuf,
}

/// Start the GUI unless `[gui] enabled = false`. Errors in the settings fail the
/// start; a missing overlay address only delays the listener.
pub fn spawn(
    manager: Arc<NetworkInstanceManager>,
    id: Uuid,
    config: &TomlConfigLoader,
    portal: SocketAddr,
    token_file: &Path,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    let gui = config.get_gui_config();
    if !gui.enabled.unwrap_or(true) {
        return Ok(None);
    }
    let cidrs = |list: &Option<Vec<String>>, option: &str| {
        list.iter()
            .flatten()
            .map(|cidr| cidr.parse().with_context(|| format!("{option}: {cidr}")))
            .collect::<anyhow::Result<Vec<IpCidr>>>()
    };
    let open = cidrs(&gui.open, "gui.open")?;
    let allow = cidrs(&gui.allow, "gui.allow")?;
    let key_file = match gui.key_file {
        Some(path) => path,
        None => token_file.with_file_name("gui.key"),
    };
    let key = ControlToken::load_or_create(&key_file, None)
        .with_context(|| format!("gui.key_file {}", key_file.display()))?;
    let name = config.get_inst_name();
    log::info!(
        instance = %name,
        key_file = %key_file.display(),
        allow = ?gui.allow.as_deref().unwrap_or_default(),
        open = ?gui.open.as_deref().unwrap_or_default(),
        "GUI enabled on the overlay address",
    );
    if allow.is_empty() {
        log::warn!(instance = %name, "gui.allow is empty: only this node may open the GUI");
    }
    let settings = Arc::new(Settings {
        id,
        name,
        port: gui.port.unwrap_or(DEFAULT_PORT),
        allow,
        open,
        key: key.expose().to_owned(),
        portal,
        token_file: token_file.to_owned(),
    });
    Ok(Some(tokio::spawn(supervise(manager, settings))))
}

/// The instance's overlay address and whether it runs without an operating system interface.
fn overlay_address(
    manager: &NetworkInstanceManager,
    id: &Uuid,
) -> Option<(Ipv4Addr, bool, String)> {
    let context = manager.get_instance_service(id)?.context().ok()?;
    let address = context.get_ipv4()?.address();
    let flags = context.get_flags();
    let hostname = context.get_hostname();
    let zone = flags.tld_dns_zone.trim_matches('.').to_owned();
    let qualified = if zone.is_empty() {
        hostname
    } else {
        format!("{hostname}.{zone}")
    };
    Some((address, flags.no_tun, qualified))
}

/// Keep one listener on the current overlay address, rebinding when it changes or the listener
/// stops.
async fn supervise(manager: Arc<NetworkInstanceManager>, settings: Arc<Settings>) {
    let mut bound: Option<(Ipv4Addr, JoinHandle<()>)> = None;
    loop {
        let current = overlay_address(&manager, &settings.id);
        let stale = match (&bound, &current) {
            (Some((address, handle)), Some((now, ..))) => address != now || handle.is_finished(),
            (Some(_), None) => true,
            (None, _) => false,
        };
        if stale && let Some((_, handle)) = bound.take() {
            handle.abort();
        }
        if bound.is_none()
            && let Some((address, userspace, qualified)) = current
        {
            let listener = tokio::spawn(listen(
                manager.clone(),
                settings.clone(),
                address,
                userspace,
                qualified,
            ));
            bound = Some((address, listener));
        }
        tokio::time::sleep(REBIND_CHECK).await;
    }
}

fn server(settings: &Settings, address: Ipv4Addr, qualified: &str) -> Arc<Server> {
    let port = settings.port;
    let mut hosts = vec![format!("{address}:{port}")];
    for name in [qualified, qualified.split('.').next().unwrap_or_default()] {
        if !name.is_empty() {
            hosts.push(format!("{name}:{port}"));
        }
    }
    if port == 80 {
        hosts.extend(
            hosts
                .clone()
                .into_iter()
                .map(|host| host.replace(":80", "")),
        );
    }
    Arc::new(Server {
        key: settings.key.clone(),
        hosts,
        pinned: true,
        defaults: Defaults {
            target: Some(Target {
                portal: settings.portal.to_string(),
                token_file: settings.token_file.clone(),
                name: Some(settings.name.clone()),
            }),
            target_error: None,
            token: None,
            admin_token: None,
            instance: Some(settings.name.clone()),
        },
        clients: Mutex::new(Default::default()),
    })
}

fn allowed(settings: &Settings, own: Ipv4Addr, peer: IpAddr) -> bool {
    let listed = settings
        .allow
        .iter()
        .chain(&settings.open)
        .any(|cidr| cidr.contains(&peer));
    listed || (settings.allow.is_empty() && peer == IpAddr::V4(own))
}

/// Peers in `gui.open` skip the access key.
fn keyless(settings: &Settings, peer: IpAddr) -> bool {
    settings.open.iter().any(|cidr| cidr.contains(&peer))
}

async fn listen(
    manager: Arc<NetworkInstanceManager>,
    settings: Arc<Settings>,
    address: Ipv4Addr,
    userspace: bool,
    qualified: String,
) {
    let server = server(&settings, address, &qualified);
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let port = settings.port;
    if userspace {
        let mut listener = match manager
            .data_plane_tcp_bind(&settings.id, port, Duration::from_secs(30))
            .await
        {
            Ok(listener) => listener,
            Err(error) => {
                log::warn!(%error, %address, port, "Cannot listen for the GUI in the userspace stack");
                return;
            }
        };
        log::info!(instance = %settings.name, %address, port, "GUI listening in the userspace stack");
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            };
            if !allowed(&settings, address, peer.ip()) {
                continue;
            }
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let server = server.clone();
            let trusted = keyless(&settings, peer.ip());
            tokio::spawn(async move {
                serve_stream(server, stream, trusted).await;
                drop(permit);
            });
        }
    } else {
        let listener = match tokio::net::TcpListener::bind((address, port)).await {
            Ok(listener) => listener,
            Err(error) => {
                log::warn!(%error, %address, port, "Cannot listen for the GUI");
                return;
            }
        };
        log::info!(instance = %settings.name, %address, port, "GUI listening on the overlay address");
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            };
            if !allowed(&settings, address, peer.ip()) {
                continue;
            }
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let server = server.clone();
            let trusted = keyless(&settings, peer.ip());
            tokio::spawn(async move {
                serve_stream(server, stream, trusted).await;
                drop(permit);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(allow: &[&str]) -> Settings {
        Settings {
            id: Uuid::nil(),
            name: "default".into(),
            port: DEFAULT_PORT,
            allow: allow.iter().map(|cidr| cidr.parse().unwrap()).collect(),
            open: vec![],
            key: "k".into(),
            portal: "127.0.0.1:1".parse().unwrap(),
            token_file: PathBuf::new(),
        }
    }

    #[tokio::test]
    async fn default_gui_waits_for_an_address_and_explicit_disable_creates_no_key() {
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("control.token");
        let manager = Arc::new(NetworkInstanceManager::new());
        let config = TomlConfigLoader::default();
        let task = spawn(
            manager.clone(),
            Uuid::nil(),
            &config,
            "127.0.0.1:1".parse().unwrap(),
            &token_file,
        )
        .unwrap()
        .expect("the GUI must start without an explicit enabled setting");
        assert!(directory.path().join("gui.key").is_file());
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "a missing overlay address must only delay listening"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let disabled = tempfile::tempdir().unwrap();
        let config = TomlConfigLoader::new_from_str("[gui]\nenabled = false\n").unwrap();
        assert!(
            spawn(
                manager,
                Uuid::nil(),
                &config,
                "127.0.0.1:1".parse().unwrap(),
                &disabled.path().join("control.token"),
            )
            .unwrap()
            .is_none()
        );
        assert!(!disabled.path().join("gui.key").exists());
    }

    #[test]
    fn allow_list_admits_listed_networks_only() {
        let own = Ipv4Addr::new(10, 77, 0, 2);
        let peer = |text: &str| text.parse::<IpAddr>().unwrap();
        let none = settings(&[]);
        assert!(allowed(&none, own, peer("10.77.0.2")));
        assert!(!allowed(&none, own, peer("10.77.0.1")));
        let net = settings(&["10.77.0.0/24", "10.88.0.9"]);
        assert!(allowed(&net, own, peer("10.77.0.1")));
        assert!(allowed(&net, own, peer("10.88.0.9")));
        assert!(!allowed(&net, own, peer("10.88.0.10")));
        assert!(!allowed(&net, own, peer("192.168.1.5")));
        let mut open = settings(&[]);
        open.open = vec!["192.168.51.0/24".parse().unwrap()];
        assert!(allowed(&open, own, peer("10.77.0.2")));
        assert!(allowed(&open, own, peer("192.168.51.9")));
        assert!(!allowed(&open, own, peer("10.77.0.1")));
        assert!(keyless(&open, peer("192.168.51.9")));
        assert!(!keyless(&open, peer("10.77.0.2")));
    }

    #[test]
    fn host_names_include_address_and_qualified_name() {
        let server = server(&settings(&[]), Ipv4Addr::new(10, 77, 0, 2), "node-b.lt");
        assert!(server.pinned);
        for host in ["10.77.0.2:15880", "node-b.lt:15880", "node-b:15880"] {
            assert!(server.hosts.iter().any(|allowed| allowed == host), "{host}");
        }
    }
}
