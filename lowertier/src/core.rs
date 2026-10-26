//! Node entry points behind `lowertier run`, `lowertier check`, and `lowertier init`.

use crate::{
    common::{
        config::{ConfigFileControl, ConfigLoader, TomlConfigLoader, load_config_from_file},
        config_schema,
        constants::LOWTIER_VERSION,
        log, runtime_registry,
    },
    instance_manager::NetworkInstanceManager,
    rpc_service::{ApiRpcServer, api::TokenOptions},
    utils::panic::setup_panic_handler,
};
use anyhow::Context;
use guarden::defer;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

#[cfg(feature = "jemalloc-prof")]
use jemalloc_ctl::{Access as _, AsName as _, epoch, stats};

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, win_service_main);

#[cfg(target_os = "windows")]
static SERVICE_OPTIONS: std::sync::OnceLock<RunOptions> = std::sync::OnceLock::new();

fn set_prof_active(_active: bool) {
    #[cfg(feature = "jemalloc-prof")]
    {
        const PROF_ACTIVE: &[u8] = b"prof.active\0";
        let name = PROF_ACTIVE.name();
        name.write(_active).expect("Should succeed to set prof");
    }
}

#[cfg(feature = "jemalloc-prof")]
fn get_dump_profile_path(cur_allocated: usize, suffix: &str) -> String {
    format!(
        "profile-{}-{}.{}",
        cur_allocated,
        chrono::Local::now().format("%Y-%m-%d-%H-%M-%S"),
        suffix
    )
}

fn dump_profile(_cur_allocated: usize) {
    #[cfg(feature = "jemalloc-prof")]
    {
        const PROF_DUMP: &[u8] = b"prof.dump\0";
        static mut PROF_DUMP_FILE_NAME: [u8; 128] = [0; 128];
        let file_name_str = get_dump_profile_path(_cur_allocated, "out");
        // copy file name to PROF_DUMP
        let file_name = file_name_str.as_bytes();
        let len = file_name.len();
        if len > 127 {
            panic!("file name too long");
        }
        unsafe {
            PROF_DUMP_FILE_NAME[..len].copy_from_slice(file_name);
            // set the last byte to 0
            PROF_DUMP_FILE_NAME[len] = 0;

            let name = PROF_DUMP.name();
            name.write(&PROF_DUMP_FILE_NAME[..len + 1])
                .expect("Should succeed to dump profile");
            println!("dump profile to: {}", file_name_str);
        }
    }
}

/// Options for `lowertier run`.
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    pub config_files: Vec<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub sets: Vec<String>,
    pub daemon: bool,
    pub log_level: Option<String>,
}

/// `LOWTIER_CONFIG` holds comma-separated config paths used when no `-c` is given.
fn config_files(explicit: &[PathBuf]) -> Vec<PathBuf> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    std::env::var("LOWTIER_CONFIG")
        .map(|value| {
            value
                .split(',')
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn config_dir_files(config_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    anyhow::ensure!(
        config_dir.is_dir(),
        "config directory {} is not a directory",
        config_dir.display()
    );
    let mut files = Vec::new();
    for entry in std::fs::read_dir(config_dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Listeners used by a node built only from `--set` values.
fn default_listeners() -> toml::Value {
    toml::Value::Array(
        <crate::tunnel::IpScheme as strum::VariantArray>::VARIANTS
            .iter()
            .map(|scheme| {
                toml::Value::String(format!(
                    "{scheme}://0.0.0.0:{}",
                    11010 + scheme.port_offset()
                ))
            })
            .collect(),
    )
}

/// A node built only from `--set` values, for one-off runs without a file.
fn config_from_sets(sets: &[String]) -> anyhow::Result<TomlConfigLoader> {
    let mut public = toml::Table::new();
    for assignment in sets {
        config_schema::apply_set(&mut public, assignment)?;
    }
    if public
        .get("transport")
        .and_then(|transport| transport.get("listen"))
        .is_none()
    {
        config_schema::set(&mut public, "transport.listen", default_listeners());
    }
    if cfg!(not(feature = "tun")) {
        config_schema::set(&mut public, "tun.mode", toml::Value::String("none".into()));
    }
    TomlConfigLoader::new_from_table("--set", &public)
}

async fn load_configs(
    options: &RunOptions,
) -> anyhow::Result<Vec<(TomlConfigLoader, ConfigFileControl)>> {
    let mut files = config_files(&options.config_files);
    if let Some(config_dir) = &options.config_dir {
        files.extend(config_dir_files(config_dir)?);
    }
    let mut configs = Vec::with_capacity(files.len());
    for file in &files {
        configs.push(
            load_config_from_file(file, options.config_dir.as_ref(), &options.sets)
                .await
                .with_context(|| format!("cannot load {}", file.display()))?,
        );
    }
    if files.is_empty() && !options.sets.is_empty() {
        configs.push((
            config_from_sets(&options.sets)?,
            ConfigFileControl::STATIC_CONFIG,
        ));
    }
    anyhow::ensure!(
        !configs.is_empty() || options.daemon || options.config_dir.is_some(),
        "nothing to run: pass -c FILE, --config-dir DIR, or --set PATH=VALUE (see `lowertier init`)"
    );
    Ok(configs)
}

async fn run_main(options: RunOptions) -> anyhow::Result<()> {
    defer!(dump_profile(0););
    let configs = load_configs(&options).await?;
    // Process-wide settings come from the first configuration.
    let (control, mut log_config) = configs
        .first()
        .map(|(config, _)| (config.get_control_config(), config.get_log_config()))
        .unwrap_or_default();
    if let Some(level) = &options.log_level {
        log_config.console = Some(level.clone());
    }
    log::init(&log_config, true)?;

    let manager =
        Arc::new(NetworkInstanceManager::new().with_config_path(options.config_dir.clone()));
    let portal_allow = control
        .portal_allow
        .iter()
        .flatten()
        .map(|cidr| {
            cidr.parse()
                .with_context(|| format!("control.portal_allow: {cidr}"))
        })
        .collect::<anyhow::Result<Vec<cidr::IpCidr>>>()?;
    let rpc_server = ApiRpcServer::new(
        control.portal.clone(),
        (!portal_allow.is_empty()).then_some(portal_allow),
        TokenOptions {
            path: control.token_file.clone(),
            group: control.token_group.clone(),
        },
        manager.clone(),
    )?
    .serve()
    .await?;

    let _daemon_guard = options.daemon.then(|| manager.register_daemon());

    let mut instances = Vec::with_capacity(configs.len());
    for (config, control) in configs {
        instances.push(config.get_inst_name());
        log::info!(instance = %config.get_inst_name(), permission = ?control.permission, "Starting LowTier instance");
        manager.run_network_instance(config, true, control)?;
    }

    let _registration = rpc_server.addr.and_then(|portal| {
        let record = runtime_registry::Record {
            name: instances.first().cloned().unwrap_or_else(|| "lowertier".into()),
            pid: std::process::id(),
            portal: portal.to_string(),
            token_file: std::path::absolute(&rpc_server.token_path)
                .unwrap_or_else(|_| rpc_server.token_path.clone()),
            instances,
            version: LOWTIER_VERSION.into(),
        };
        runtime_registry::register(&record)
            .inspect_err(|error| log::warn!(%error, "Cannot write the runtime record; the CLI needs --portal"))
            .ok()
    });

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let sigterm = sigterm.recv();
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = manager.wait() => {
            let infos = manager.collect_network_infos().await?;
            if infos
                .into_values()
                .filter_map(|info| info.error_msg).next().is_some() {
                return Err(anyhow::anyhow!("some instances stopped with errors"));
            }
        }
        _ = tokio::signal::ctrl_c() => {
            log::info!("ctrl-c received, exiting...");
        }

        _ = sigterm, if cfg!(unix) => {
            log::warn!("terminate signal received, exiting...");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn win_service_set_work_dir(service_name: &std::ffi::OsString) -> anyhow::Result<()> {
    use crate::common::constants::WIN_SERVICE_WORK_DIR_REG_KEY;
    use winreg::{RegKey, enums::*};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(WIN_SERVICE_WORK_DIR_REG_KEY, KEY_READ)?;
    let dir_pat_str = key.get_value::<std::ffi::OsString, _>(service_name)?;
    let dir_path = std::fs::canonicalize(dir_pat_str)?;

    std::env::set_current_dir(dir_path)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn win_service_main(arg: Vec<std::ffi::OsString>) {
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use windows_service::{service::*, service_control_handler::*};

    _ = win_service_set_work_dir(&arg[0]);
    let options = SERVICE_OPTIONS.get().cloned().unwrap_or_default();

    let stop_notify_send = Arc::new(tokio::sync::Notify::new());
    let stop_notify_recv = Arc::clone(&stop_notify_send);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                stop_notify_send.notify_one();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = register(String::new(), event_handler).expect("register service fail");
    let status = |state, exit_code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)))
        .expect("set service status fail");

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            tokio::select! {
                res = run_main(options) => {
                    match res {
                        Ok(_) => {
                            status_handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0))).unwrap();
                            std::process::exit(0);
                        }
                        Err(error) => {
                            status_handle.set_service_status(status(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1))).unwrap();
                            log::error!(?error);
                        }
                    }
                },
                _ = stop_notify_recv.notified() => {
                    _ = status_handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)));
                    std::process::exit(0);
                }
            }
        });
    });
}

fn memory_monitor(_force_dump: Arc<AtomicBool>) {
    #[cfg(feature = "jemalloc-prof")]
    {
        let mut last_peak_size = 0;
        let e = epoch::mib().unwrap();
        let allocated_stats = stats::allocated::mib().unwrap();

        loop {
            e.advance().unwrap();
            let new_heap_size = allocated_stats.read().unwrap();

            log::debug!("heap size: {} bytes", new_heap_size);

            // dump every 75MB
            if (last_peak_size > 0
                && new_heap_size > last_peak_size
                && new_heap_size - last_peak_size > 10 * 1024 * 1024)
                || _force_dump.load(std::sync::atomic::Ordering::Relaxed)
            {
                log::debug!(
                    "heap size increased: {} bytes",
                    new_heap_size - last_peak_size,
                );
                dump_profile(new_heap_size);
                last_peak_size = new_heap_size;
                if _force_dump.load(std::sync::atomic::Ordering::Relaxed) {
                    // also dump whole jemalloc stats
                    use jemalloc_ctl::stats_print::stats_print;
                    let tmp_file = get_dump_profile_path(new_heap_size, "stats");
                    let mut file = std::fs::File::create(tmp_file).unwrap();
                    let _ = stats_print(&mut file, Default::default());
                    _force_dump.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }

            if last_peak_size == 0 {
                last_peak_size = new_heap_size;
            }

            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

/// Run nodes until a signal arrives or every instance stops.
pub async fn run(options: RunOptions) -> ExitCode {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    setup_panic_handler();

    #[cfg(target_os = "windows")]
    {
        _ = SERVICE_OPTIONS.set(options.clone());
        match windows_service::service_dispatcher::start(String::new(), ffi_service_main) {
            Ok(_) => std::thread::park(),
            Err(e) => {
                let should_panic = if let windows_service::Error::Winapi(ref io_error) = e {
                    io_error.raw_os_error() != Some(0x427) // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
                } else {
                    true
                };

                if should_panic {
                    panic!("SCM start an error: {}", e);
                }
            }
        };
    }

    set_prof_active(true);
    // register a signal handler to set force dump when signal usr1 is received
    let force_dump = Arc::new(AtomicBool::new(false));
    #[cfg(all(feature = "jemalloc-prof", not(target_os = "windows")))]
    {
        let force_dump_clone = force_dump.clone();
        let mut sigusr1 =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()).unwrap();
        tokio::task::spawn(async move {
            while sigusr1.recv().await.is_some() {
                force_dump_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }
    let _monitor = std::thread::spawn(move || memory_monitor(force_dump));

    let mut ret_code = 0;
    if let Err(error) = run_main(options).await {
        eprintln!("error: {error:#}");
        log::error!(%error);
        ret_code = 1;
    }

    log::info!("Stopping lowertier...");
    set_prof_active(false);

    ExitCode::from(ret_code)
}

/// Validate config files with overrides. Every problem is reported at once.
pub async fn check(files: &[PathBuf], sets: &[String]) -> anyhow::Result<Vec<String>> {
    let files = config_files(files);
    if files.is_empty() {
        config_from_sets(sets)?;
        return Ok(vec!["--set values".into()]);
    }
    let mut checked = Vec::with_capacity(files.len());
    let mut errors = Vec::new();
    for file in &files {
        match load_config_from_file(file, None, sets).await {
            Ok(_) => checked.push(file.display().to_string()),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(checked)
}

/// Options for `lowertier init`.
#[derive(Clone, Debug)]
pub struct InitOptions {
    pub output: PathBuf,
    pub network: String,
    pub listen_port: Option<u16>,
    pub peers: Vec<String>,
    pub tun_mode: Option<String>,
    pub ipv4: Option<String>,
    pub force: bool,
}

fn write_private(path: &Path, contents: &str, force: bool) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| {
        format!(
            "cannot create {} (use --force to replace it)",
            path.display()
        )
    })?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

/// Write a new sectioned configuration with a generated secret and identity key.
/// Returns the paths written.
pub fn init(options: &InitOptions) -> anyhow::Result<Vec<PathBuf>> {
    use base64::{Engine as _, prelude::BASE64_STANDARD};
    use rand::RngCore as _;

    let directory = options
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)?;
    let stem = options
        .output
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("lowertier");
    let secret_path = directory.join(format!("{stem}.secret"));
    let key_path = directory.join(format!("{stem}.key"));
    anyhow::ensure!(
        options.force || !options.output.exists(),
        "{} exists (use --force to replace it)",
        options.output.display()
    );

    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let key = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);

    let quote = |text: &str| toml::Value::String(text.into()).to_string();
    let list = |items: &[String]| {
        format!(
            "[{}]",
            items
                .iter()
                .map(|item| quote(item))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let base = options.listen_port.unwrap_or(11010);
    let listen = <crate::tunnel::IpScheme as strum::VariantArray>::VARIANTS
        .iter()
        .map(|scheme| format!("{scheme}://0.0.0.0:{}", base + scheme.port_offset()))
        .collect::<Vec<_>>();
    let absolute = |path: &Path| {
        std::path::absolute(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    };

    let mut text = String::new();
    text.push_str("# LowTier node. `lowertier config explain` documents every option.\n\n");
    text.push_str(&format!(
        "[network]\nname = {}\nsecret_file = {}\n\n",
        quote(&options.network),
        quote(&absolute(&secret_path))
    ));
    text.push_str(&format!(
        "[identity]\nprivate_key_file = {}\n\n",
        quote(&absolute(&key_path))
    ));
    match &options.ipv4 {
        Some(ipv4) => text.push_str(&format!("[address]\nipv4 = {}\n\n", quote(ipv4))),
        None => text.push_str("[address]\ndhcp = true\n\n"),
    }
    if let Some(mode) = &options.tun_mode {
        text.push_str(&format!("[tun]\nmode = {}\n\n", quote(mode)));
    }
    text.push_str(&format!("[transport]\nlisten = {}\n", list(&listen)));
    for peer in &options.peers {
        text.push_str(&format!("\n[[peer]]\nuri = {}\n", quote(peer)));
    }

    // Validate before writing anything, with the generated secrets in place.
    let mut check = text.parse::<toml::Table>()?;
    for path in ["network.secret_file", "identity.private_key_file"] {
        let (section, key) = path.split_once('.').unwrap();
        check
            .get_mut(section)
            .and_then(toml::Value::as_table_mut)
            .unwrap()
            .remove(key);
    }
    config_schema::set(
        &mut check,
        "network.secret",
        toml::Value::String(BASE64_STANDARD.encode(secret)),
    );
    TomlConfigLoader::new_from_table("init", &check)?;

    write_private(
        &secret_path,
        &format!("{}\n", BASE64_STANDARD.encode(secret)),
        options.force,
    )?;
    write_private(
        &key_path,
        &format!("{}\n", BASE64_STANDARD.encode(key.as_bytes())),
        options.force,
    )?;
    std::fs::write(&options.output, text)?;
    Ok(vec![options.output.clone(), secret_path, key_path])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init_output_passes_check_and_old_layout_fails() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("node.toml");
        let written = init(&InitOptions {
            output: output.clone(),
            network: "test-net".into(),
            listen_port: Some(21010),
            peers: vec!["quic://127.0.0.1:21012".into()],
            tun_mode: Some("none".into()),
            ipv4: None,
            force: false,
        })
        .unwrap();
        assert_eq!(written.len(), 3);
        check(&[output.clone()], &["relay.policy=latency".into()])
            .await
            .unwrap();
        let config = TomlConfigLoader::new(&output).unwrap();
        assert_eq!(config.get_network_identity().network_name, "test-net");
        assert!(config.get_network_identity().network_secret.is_some());
        assert!(!config.dump().contains("secret = "), "{}", config.dump());
        let again = InitOptions {
            output,
            network: "x".into(),
            listen_port: None,
            peers: vec![],
            tun_mode: None,
            ipv4: None,
            force: false,
        };
        assert!(
            init(&again).is_err(),
            "init must not overwrite without --force"
        );

        let old = directory.path().join("old.toml");
        std::fs::write(&old, "ipv4 = \"10.0.0.1/24\"\n[flags]\nmtu = 1200\n").unwrap();
        let error = check(&[old], &[]).await.unwrap_err().to_string();
        assert!(
            error.contains("address.ipv4") && error.contains("tun.mtu"),
            "{error}"
        );
    }
}
