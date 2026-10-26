//! Running daemons announce their management portal here so the CLI can find them.
//! Records never contain the control token, only the path of the token file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    pub pid: u32,
    pub portal: String,
    pub token_file: PathBuf,
    pub instances: Vec<String>,
    pub version: String,
}

/// Directories searched for records: the system directory, then the per-user directory.
pub fn directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if cfg!(target_os = "linux") {
        directories.push(PathBuf::from("/run/lowertier"));
    } else if cfg!(unix) {
        directories.push(PathBuf::from("/var/run/lowertier"));
    } else if let Some(data) = std::env::var_os("ProgramData") {
        directories.push(PathBuf::from(data).join("LowTier").join("run"));
    }
    if let Some(user) = user_directory() {
        directories.push(user);
    }
    directories
}

fn user_directory() -> Option<PathBuf> {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(runtime).join("lowertier"));
    }
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(|data| PathBuf::from(data).join("LowTier").join("run"));
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    Some(if cfg!(target_os = "macos") {
        home.join("Library/Caches/lowertier")
    } else {
        home.join(".cache/lowertier")
    })
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
        // EPERM means the process exists under another user.
        matches!(
            kill(Pid::from_raw(pid as i32), None),
            Ok(()) | Err(Errno::EPERM)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Removes the record when the daemon exits.
pub struct Registration(PathBuf);

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn register(record: &Record) -> anyhow::Result<Registration> {
    let directory = if is_root() {
        directories().into_iter().next()
    } else {
        user_directory()
    }
    .ok_or_else(|| anyhow::anyhow!("no runtime directory is available"))?;
    std::fs::create_dir_all(&directory)?;
    let mut path = directory.join(format!("{}.json", record.name));
    if read(&path).is_some_and(|other| other.pid != record.pid && process_alive(other.pid)) {
        path = directory.join(format!("{}-{}.json", record.name, record.pid));
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
    std::fs::rename(&temporary, &path)?;
    Ok(Registration(path))
}

fn read(path: &Path) -> Option<Record> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Records of running daemons, de-duplicated by process.
pub fn live_records() -> Vec<Record> {
    let mut records = Vec::<Record>::new();
    for directory in directories() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            if let Some(record) = read(&path)
                && process_alive(record.pid)
                && !records.iter().any(|other| other.pid == record.pid)
            {
                records.push(record);
            }
        }
    }
    records.sort_by(|a, b| a.name.cmp(&b.name));
    records
}

pub enum Selection {
    Found(Record),
    None,
    Ambiguous(Vec<Record>),
    Missing(String),
}

/// Pick the daemon named `name`, or the only one running.
pub fn select(records: Vec<Record>, name: Option<&str>) -> Selection {
    match name {
        Some(name) => records
            .into_iter()
            .find(|record| record.name == name || record.pid.to_string() == name)
            .map_or_else(|| Selection::Missing(name.to_owned()), Selection::Found),
        None => match records.len() {
            0 => Selection::None,
            1 => Selection::Found(records.into_iter().next().unwrap()),
            _ => Selection::Ambiguous(records),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, pid: u32) -> Record {
        Record {
            name: name.into(),
            pid,
            portal: "127.0.0.1:15888".into(),
            token_file: "/tmp/token".into(),
            instances: vec![],
            version: "test".into(),
        }
    }

    #[test]
    fn selection_prefers_name_then_sole_record() {
        let one = vec![record("a", 1)];
        assert!(matches!(select(one.clone(), None), Selection::Found(r) if r.name == "a"));
        assert!(matches!(select(one, Some("b")), Selection::Missing(_)));
        let two = vec![record("a", 1), record("b", 2)];
        assert!(matches!(select(two.clone(), None), Selection::Ambiguous(r) if r.len() == 2));
        assert!(matches!(select(two, Some("2")), Selection::Found(r) if r.name == "b"));
        assert!(matches!(select(vec![], None), Selection::None));
        assert!(process_alive(std::process::id()));
    }
}
