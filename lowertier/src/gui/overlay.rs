//! The GUI on loopback and an instance's overlay address, enabled by default.
//!
//! The daemon serves the page itself, so it follows the instance and needs no second process.
//! In userspace mode the listener lives in the data-plane TCP stack. Otherwise it is an operating
//! system socket bound to the overlay address. Only peers inside `gui.allow` are served, and
//! every API request needs the stable key from `gui.key_file`.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::Context as _;
use cidr::{IpCidr, Ipv4Inet};
use tokio::{
    sync::{Mutex, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_util::task::AbortOnDropHandle;
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
    loopback_port: u16,
    allow: Vec<IpCidr>,
    default_allow: bool,
    open: Vec<IpCidr>,
    key: String,
    portal: SocketAddr,
    token_file: PathBuf,
    connections: Arc<Semaphore>,
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
    anyhow::ensure!(
        gui.port.unwrap_or(DEFAULT_PORT) != 0 && gui.loopback_port.unwrap_or(DEFAULT_PORT) != 0,
        "GUI ports must be between 1 and 65535"
    );
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
    let settings = Arc::new(Settings {
        id,
        name,
        port: gui.port.unwrap_or(DEFAULT_PORT),
        loopback_port: gui.loopback_port.unwrap_or(DEFAULT_PORT),
        allow,
        default_allow: gui.allow.is_none(),
        open,
        key: key.expose().to_owned(),
        portal,
        token_file: token_file.to_owned(),
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
    });
    Ok(Some(tokio::spawn(supervise(
        Arc::downgrade(&manager),
        settings,
    ))))
}

/// The instance's overlay address and whether it runs without an operating system interface.
fn overlay_address(
    manager: &NetworkInstanceManager,
    id: &Uuid,
) -> Option<(Ipv4Inet, bool, String)> {
    let context = manager.get_instance_service(id)?.context().ok()?;
    let address = context.get_ipv4()?;
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
async fn supervise(manager: Weak<NetworkInstanceManager>, settings: Arc<Settings>) {
    // Listener tasks must stop with the instance, including during a configuration restart.
    let mut bound: Option<(Ipv4Inet, AbortOnDropHandle<()>)> = None;
    let mut loopback: Option<AbortOnDropHandle<()>> = None;
    loop {
        let Some(manager) = manager.upgrade() else {
            break;
        };
        if loopback.as_ref().is_none_or(|task| task.is_finished()) {
            loopback = Some(AbortOnDropHandle::new(tokio::spawn(listen(
                manager.clone(),
                settings.clone(),
                Ipv4Inet::new(Ipv4Addr::LOCALHOST, 32).expect("valid loopback prefix"),
                false,
                "localhost".to_owned(),
            ))));
        }
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
            bound = Some((address, AbortOnDropHandle::new(listener)));
        }
        drop(manager);
        tokio::time::sleep(REBIND_CHECK).await;
    }
}

fn server(settings: &Settings, address: Ipv4Addr, qualified: &str) -> Arc<Server> {
    let port = if address.is_loopback() {
        settings.loopback_port
    } else {
        settings.port
    };
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

fn allowed(settings: &Settings, own: Ipv4Inet, peer: IpAddr) -> bool {
    if own.address().is_loopback() {
        return peer.is_loopback();
    }
    let listed = settings
        .allow
        .iter()
        .chain(&settings.open)
        .any(|cidr| cidr.contains(&peer));
    listed
        || (settings.default_allow && IpCidr::V4(own.network()).contains(&peer))
        || (settings.allow.is_empty() && peer == IpAddr::V4(own.address()))
}

/// Peers in `gui.open` skip the access key.
fn keyless(settings: &Settings, peer: IpAddr) -> bool {
    settings.open.iter().any(|cidr| cidr.contains(&peer))
}

async fn listen(
    manager: Arc<NetworkInstanceManager>,
    settings: Arc<Settings>,
    network: Ipv4Inet,
    userspace: bool,
    qualified: String,
) {
    let address = network.address();
    let server = server(&settings, address, &qualified);
    let limit = settings.connections.clone();
    let mut connections = JoinSet::new();
    let port = if address.is_loopback() {
        settings.loopback_port
    } else {
        settings.port
    };
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
        drop(manager);
        log::info!(instance = %settings.name, %address, port, "GUI listening in the userspace stack");
        loop {
            while connections.try_join_next().is_some() {}
            let Ok((stream, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            };
            if !allowed(&settings, network, peer.ip()) {
                continue;
            }
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let server = server.clone();
            let trusted = keyless(&settings, peer.ip());
            connections.spawn(async move {
                serve_stream(server, stream, trusted).await;
                drop(permit);
            });
        }
    } else {
        drop(manager);
        let _port_guard = if address.is_loopback() {
            match crate::rpc_service::protected_port::protect_gui_port(port) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    log::warn!(%error, port, "Cannot protect the loopback GUI port");
                    return;
                }
            }
        } else {
            None
        };
        let listener = match tokio::net::TcpListener::bind((address, port)).await {
            Ok(listener) => listener,
            Err(error) => {
                log::warn!(%error, %address, port, "Cannot listen for the GUI");
                return;
            }
        };
        log::info!(instance = %settings.name, %address, port, "GUI listening on the overlay address");
        loop {
            while connections.try_join_next().is_some() {}
            let Ok((stream, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            };
            if !allowed(&settings, network, peer.ip()) {
                continue;
            }
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let server = server.clone();
            let trusted = keyless(&settings, peer.ip());
            connections.spawn(async move {
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
            loopback_port: DEFAULT_PORT,
            allow: allow.iter().map(|cidr| cidr.parse().unwrap()).collect(),
            default_allow: false,
            open: vec![],
            key: "k".into(),
            portal: "127.0.0.1:1".parse().unwrap(),
            token_file: PathBuf::new(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    async fn default_gui_waits_for_an_address_and_explicit_disable_creates_no_key() {
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("control.token");
        let manager = Arc::new(NetworkInstanceManager::new());
        let invalid = TomlConfigLoader::new_from_str("[gui]\nloopback_port = 0\n").unwrap();
        assert!(
            spawn(
                manager.clone(),
                Uuid::nil(),
                &invalid,
                "127.0.0.1:1".parse().unwrap(),
                &token_file
            )
            .is_err()
        );
        assert!(!directory.path().join("gui.key").exists());
        let reservation = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let config =
            TomlConfigLoader::new_from_str(&format!("[gui]\nloopback_port = {port}\n")).unwrap();
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
        let mut stream = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(stream) =
                    tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
                {
                    break stream;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("loopback GUI must start before the overlay address exists");
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        stream
            .write_all(format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0; 32];
        let length = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response[..length].starts_with(b"HTTP/1.1 200"));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut remaining))
            .await
            .expect("stopping the GUI must close existing HTTP connections")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stopping the GUI must release the loopback port");

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

    async fn instance_restart_applies_gui_settings() {
        use crate::common::config::ConfigFileControl;
        let directory = tempfile::tempdir().unwrap();
        let manager = Arc::new(NetworkInstanceManager::new());
        manager.configure_gui(
            "127.0.0.1:1".parse().unwrap(),
            directory.path().join("control.token"),
        );
        let mut reservations = Vec::new();
        for _ in 0..2 {
            reservations.push(
                tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap(),
            );
        }
        let ports: Vec<_> = reservations
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        drop(reservations);
        let id = Uuid::new_v4();
        let configuration = |enabled: bool, port: u16| {
            TomlConfigLoader::new_from_str(&format!(
                "[node]\ninstance_id = \"{id}\"\ninstance_name = \"gui-restart\"\n\
                 [network]\nname = \"gui-restart\"\nsecret = \"local-test-secret\"\n\
                 [address]\nipv4 = \"10.201.70.2/24\"\n\
                 [tun]\nmode = \"userspace\"\n\
                 [transport]\nlisten = []\n\
                 [nat]\np2p = \"off\"\nstun = []\nstun_v6 = []\nstun_tcp = []\n\
                 [gui]\nenabled = {enabled}\nloopback_port = {port}\n"
            ))
            .unwrap()
        };
        let config = configuration(true, ports[0]);
        manager
            .run_network_instance(config.clone(), true, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        async fn wait_for_listener(port: u16, manager: &NetworkInstanceManager, phase: &str) {
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                        .await
                        .is_ok()
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                result.is_ok(),
                "GUI listener must start during {phase}: {:?}",
                manager
                    .iter()
                    .map(|instance| instance.get_latest_error_msg())
                    .collect::<Vec<_>>()
            );
        }
        wait_for_listener(ports[0], &manager, "initial start").await;
        manager.stop_network_instance(id).await.unwrap();
        tokio::task::yield_now().await;
        config.replace_active(&configuration(false, ports[0]));
        manager.start_network_instance(id).unwrap();
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0]))
                .await
                .is_err()
        );
        manager.stop_network_instance(id).await.unwrap();
        config.replace_active(&configuration(true, ports[1]));
        manager.start_network_instance(id).unwrap();
        wait_for_listener(ports[1], &manager, "configuration restart").await;
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0]))
                .await
                .is_err()
        );
        manager.stop_network_instance(id).await.unwrap();
    }

    fn allow_list_admits_listed_networks_only() {
        let own: Ipv4Inet = "10.77.0.2/24".parse().unwrap();
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
        let mut default = settings(&[]);
        default.default_allow = true;
        assert!(allowed(&default, own, peer("10.77.0.1")));
        assert!(!allowed(&default, own, peer("10.78.0.1")));
        assert!(!keyless(&default, peer("10.77.0.1")));
    }

    fn host_names_include_address_and_qualified_name() {
        let server = server(&settings(&[]), Ipv4Addr::new(10, 77, 0, 2), "node-b.lt");
        assert!(server.pinned);
        for host in ["10.77.0.2:15880", "node-b.lt:15880", "node-b:15880"] {
            assert!(server.hosts.iter().any(|allowed| allowed == host), "{host}");
        }
    }

    #[tokio::test]
    async fn browser_interface_access_and_lifecycle() {
        allow_list_admits_listed_networks_only();
        host_names_include_address_and_qualified_name();
        default_gui_waits_for_an_address_and_explicit_disable_creates_no_key().await;
        instance_restart_applies_gui_settings().await;
    }
}
