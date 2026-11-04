use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

static PROTECTED_TCP_PORTS: Lazy<Mutex<HashMap<u16, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register_protected_tcp_port(port: u16) {
    let mut ports = PROTECTED_TCP_PORTS.lock().unwrap();
    *ports.entry(port).or_default() += 1;
}

pub fn unregister_protected_tcp_port(port: u16) {
    let mut ports = PROTECTED_TCP_PORTS.lock().unwrap();
    if let Some(ref_count) = ports.get_mut(&port) {
        *ref_count -= 1;
        if *ref_count == 0 {
            ports.remove(&port);
        }
    }
}

pub fn is_protected_tcp_port(port: u16) -> bool {
    if PROTECTED_TCP_PORTS.lock().unwrap().contains_key(&port) {
        return true;
    }
    match open_gui_port_file(port, false) {
        Ok(file) => file.try_lock_shared().is_err(),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// The file lock protects a loopback GUI across independent daemon processes.
pub struct GuiPortGuard {
    _file: std::fs::File,
}

fn open_gui_port_file(port: u16, create: bool) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    let directory = if cfg!(unix) {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let path = directory.join(format!("lowertier-gui-{port}.lock"));
    let options = || {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .mode(0o644);
        }
        options
    };
    let file = if create {
        match options().write(true).create_new(true).open(&path) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
                }
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options().open(path)?
            }
            Err(error) => return Err(error),
        }
    } else {
        options().open(path)?
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "The GUI port lock is not a regular file",
        ));
    }
    Ok(file)
}

pub fn protect_gui_port(port: u16) -> std::io::Result<GuiPortGuard> {
    let file = open_gui_port_file(port, true)?;
    file.try_lock()?;
    // Keep the empty file. Unlinking it would let another daemon bypass a live lock.
    Ok(GuiPortGuard { _file: file })
}

/// Hold this shared lock until the proxy finishes its operating system TCP connect.
pub fn allow_loopback_proxy(port: u16) -> std::io::Result<GuiPortGuard> {
    let file = open_gui_port_file(port, true)?;
    file.try_lock_shared()?;
    Ok(GuiPortGuard { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_port_protection_uses_distinct_handles_and_releases_on_drop() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(!is_protected_tcp_port(port));
        let guard = protect_gui_port(port).unwrap();
        assert!(is_protected_tcp_port(port));
        assert!(protect_gui_port(port).is_err());
        drop(guard);
        assert!(!is_protected_tcp_port(port));
        let connection = allow_loopback_proxy(port).unwrap();
        assert!(protect_gui_port(port).is_err());
        drop(connection);
        let _guard = protect_gui_port(port).unwrap();
    }
}
