#![deny(warnings)]

use chrono::prelude::*;
use std::{
    convert::TryFrom,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

/// Determines when a file should be "rolled over".
pub trait RollingCondition {
    /// Determine and return whether or not the file should be rolled over.
    fn should_rollover(&mut self, now: &DateTime<Local>, current_filesize: u64) -> bool;
}

/// Determines how often a file should be rolled over
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RollingFrequency {
    EveryDay,
    EveryHour,
    EveryMinute,
}

impl RollingFrequency {
    /// Calculates a datetime that will be different if data should be in
    /// different files.
    pub fn equivalent_datetime(&self, dt: &DateTime<Local>) -> DateTime<Local> {
        let (year, month, day) = (dt.year(), dt.month(), dt.day());
        let (hour, min, sec) = match self {
            RollingFrequency::EveryDay => (0, 0, 0),
            RollingFrequency::EveryHour => (dt.hour(), 0, 0),
            RollingFrequency::EveryMinute => (dt.hour(), dt.minute(), 0),
        };
        Local
            .with_ymd_and_hms(year, month, day, hour, min, sec)
            .unwrap()
    }
}

/// Writes data to a file, and "rolls over" to preserve older data in
/// a separate set of files. Old files have a Debian-style naming scheme
/// where we have base_filename, base_filename.1, ..., base_filename.N
/// where N is the maximum number of rollover files to keep.
#[derive(Debug)]
pub struct RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    condition: RC,
    filename: String,
    max_filecount: usize,
    max_total_size: Option<u64>,
    current_filesize: u64,
    rotated_filesize: u64,
    writer_opt: Option<BufWriter<File>>,
}

impl<RC> RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    /// Creates a new rolling file appender with the given condition.
    /// The filename parent path must already exist.
    pub fn new(
        filename: impl AsRef<Path>,
        condition: RC,
        max_filecount: usize,
    ) -> io::Result<RollingFileAppender<RC>> {
        let filename = filename.as_ref().to_str().unwrap().to_string();
        let mut appender = RollingFileAppender {
            condition,
            filename,
            max_filecount,
            max_total_size: None,
            current_filesize: 0,
            rotated_filesize: 0,
            writer_opt: None,
        };
        // Fail if we can't open the file initially...
        appender.open_writer_if_needed()?;
        Ok(appender)
    }

    /// Determines the final filename, where n==0 indicates the current file
    fn filename_for(&self, n: usize) -> String {
        let f = self.filename.clone();
        if n > 0 { format!("{}.{}", f, n) } else { f }
    }

    fn scan_rotated_files(&self) -> Vec<(usize, u64)> {
        let base_path = Path::new(&self.filename);
        let parent = match base_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else {
            return Vec::new();
        };
        let prefix = format!("{base_name}.");
        let Ok(entries) = fs::read_dir(parent) else {
            return Vec::new();
        };
        let mut rotated = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name_str) = file_name.to_str() else {
                continue;
            };
            let Some(suffix) = name_str.strip_prefix(&prefix) else {
                continue;
            };
            if let Ok(index) = suffix.parse::<usize>()
                && index >= 1
            {
                let len = entry.metadata().map_or(0, |m| m.len());
                rotated.push((index, len));
            }
        }
        // Oldest rotated file (highest index) first.
        rotated.sort_by(|a, b| b.0.cmp(&a.0));
        rotated
    }

    fn trim_active_file_to(&mut self, target_bytes: u64) -> io::Result<()> {
        let _ = self.flush();
        self.writer_opt.take();
        let active_path = Path::new(&self.filename);
        if target_bytes == 0 {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(active_path)?;
            self.current_filesize = 0;
            return Ok(());
        }

        let current_len = active_path.metadata().map_or(0, |m| m.len());
        if current_len <= target_bytes {
            self.current_filesize = current_len;
            return Ok(());
        }

        let mut file = File::open(active_path)?;
        let seek_pos = current_len - target_bytes;
        file.seek(SeekFrom::Start(seek_pos))?;
        let mut buf = Vec::with_capacity(usize::try_from(target_bytes).unwrap_or(usize::MAX));
        file.read_to_end(&mut buf)?;
        drop(file);

        let tail = match buf.iter().position(|&b| b == b'\n') {
            Some(pos) if pos + 1 < buf.len() => &buf[pos + 1..],
            _ => &buf[..],
        };

        let mut out = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(active_path)?;
        out.write_all(tail)?;
        out.flush()?;
        self.current_filesize = u64::try_from(tail.len()).unwrap_or(u64::MAX);
        Ok(())
    }

    fn prune_to_cap(&mut self, incoming_bytes: u64) -> io::Result<()> {
        let mut rotated = self.scan_rotated_files();
        let mut total_rotated: u64 = 0;
        let mut kept = Vec::with_capacity(rotated.len());
        for (index, len) in rotated.drain(..) {
            if index > self.max_filecount {
                let _ = fs::remove_file(self.filename_for(index));
            } else {
                total_rotated = total_rotated.saturating_add(len);
                kept.push((index, len));
            }
        }
        self.rotated_filesize = total_rotated;

        let Some(cap) = self.max_total_size else {
            return Ok(());
        };

        let mut total = self
            .current_filesize
            .saturating_add(self.rotated_filesize)
            .saturating_add(incoming_bytes);
        for (index, len) in kept {
            if total <= cap {
                break;
            }
            let _ = fs::remove_file(self.filename_for(index));
            self.rotated_filesize = self.rotated_filesize.saturating_sub(len);
            total = total.saturating_sub(len);
        }

        if total > cap {
            let max_active = cap.saturating_sub(incoming_bytes);
            self.trim_active_file_to(max_active)?;
        }
        Ok(())
    }

    pub(crate) fn enforce_startup_cap(&mut self) -> io::Result<()> {
        let active_path = Path::new(&self.filename);
        if active_path.exists() {
            self.current_filesize = active_path.metadata().map_or(0, |m| m.len());
        } else {
            self.current_filesize = 0;
        }
        self.prune_to_cap(0)
    }

    /// Rotates old files to make room for a new one.
    /// This may result in the deletion of the oldest file
    fn rotate_files(&mut self) -> io::Result<()> {
        if self.max_filecount == 0 {
            let _ = fs::remove_file(self.filename_for(0));
            return self.prune_to_cap(0);
        }
        // ignore any failure removing the oldest file (may not exist)
        let _ = fs::remove_file(self.filename_for(self.max_filecount));
        let mut r = Ok(());
        for i in (0..self.max_filecount).rev() {
            let rotate_from = self.filename_for(i);
            let rotate_to = self.filename_for(i + 1);
            if let Err(e) = fs::rename(&rotate_from, &rotate_to).or_else(|e| match e.kind() {
                io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            }) {
                // capture the error, but continue the loop,
                // to maximize ability to rename everything
                r = Err(e);
            }
        }
        self.prune_to_cap(0)?;
        r
    }

    /// Forces a rollover to happen immediately.
    pub fn rollover(&mut self) -> io::Result<()> {
        // Before closing, make sure all data is flushed successfully.
        self.flush()?;
        // We must close the current file before rotating files
        self.writer_opt.take();
        self.current_filesize = 0;
        self.rotate_files()?;
        self.open_writer_if_needed()
    }

    /// Discards all rotated log files and truncates the active log file.
    pub fn clear(&mut self) -> io::Result<()> {
        let _ = self.flush();
        self.writer_opt.take();
        for (index, _) in self.scan_rotated_files() {
            let _ = fs::remove_file(self.filename_for(index));
        }
        self.rotated_filesize = 0;
        let active_path = Path::new(&self.filename);
        if active_path.exists() {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(active_path)?;
        }
        self.current_filesize = 0;
        Ok(())
    }

    /// Opens a writer for the current file.
    fn open_writer_if_needed(&mut self) -> io::Result<()> {
        if self.writer_opt.is_none() {
            let path = self.filename_for(0);
            let path = Path::new(&path);
            let mut open_options = OpenOptions::new();
            open_options.append(true).create(true);
            let new_file = match open_options.open(path) {
                Ok(new_file) => new_file,
                Err(err) => {
                    let Some(parent) = path.parent() else {
                        return Err(err);
                    };
                    fs::create_dir_all(parent)?;
                    open_options.open(path)?
                }
            };
            self.writer_opt = Some(BufWriter::new(new_file));
            self.current_filesize = path.metadata().map_or(0, |m| m.len());
            self.prune_to_cap(0)?;
            if self.writer_opt.is_none() {
                let reopened = open_options.open(path)?;
                self.writer_opt = Some(BufWriter::new(reopened));
                self.current_filesize = path.metadata().map_or(0, |m| m.len());
            }
        }
        Ok(())
    }

    /// Writes data using the given datetime to calculate the rolling condition
    pub fn write_with_datetime(&mut self, buf: &[u8], now: &DateTime<Local>) -> io::Result<usize> {
        if self.condition.should_rollover(now, self.current_filesize)
            && let Err(e) = self.rollover()
        {
            // If we can't rollover, just try to continue writing anyway
            // (better than missing data).
            // This will likely used to implement logging, so
            // avoid using log::warn and log to stderr directly
            eprintln!("WARNING: Failed to rotate logfile {}: {}", self.filename, e);
        }
        let incoming_bytes = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if let Some(cap) = self.max_total_size
            && self
                .current_filesize
                .saturating_add(self.rotated_filesize)
                .saturating_add(incoming_bytes)
                > cap
        {
            let _ = self.prune_to_cap(incoming_bytes);
        }
        self.open_writer_if_needed()?;
        if let Some(writer) = self.writer_opt.as_mut() {
            let buf_len = buf.len();
            writer.write_all(buf).map(|_| {
                self.current_filesize += u64::try_from(buf_len).unwrap_or(u64::MAX);
                buf_len
            })
        } else {
            Err(io::Error::other("unexpected condition: writer is missing"))
        }
    }
}

impl<RC> io::Write for RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let now = Local::now();
        self.write_with_datetime(buf, &now)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer_opt.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileAppenderWrapper {
    appender: std::sync::Arc<parking_lot::Mutex<RollingFileAppenderBase>>,
}

impl tracing_subscriber::fmt::MakeWriter<'_> for FileAppenderWrapper {
    type Writer = FileAppenderWriter;

    fn make_writer(&self) -> Self::Writer {
        FileAppenderWriter {
            appender: self.appender.clone(),
        }
    }
}

impl FileAppenderWrapper {
    pub fn new(appender: RollingFileAppenderBase) -> Self {
        Self {
            appender: std::sync::Arc::new(parking_lot::Mutex::new(appender)),
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        self.appender.lock().clear()
    }
}

#[derive(Debug, Clone)]
pub struct FileAppenderWriter {
    appender: std::sync::Arc<parking_lot::Mutex<RollingFileAppenderBase>>,
}

impl std::io::Write for FileAppenderWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.appender.lock().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.appender.lock().flush()
    }
}

pub mod base;
pub use base::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn total_log_bytes(dir: &Path) -> u64 {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| e.metadata().ok().map(|m| m.len()))
            .sum()
    }

    #[test]
    fn enforces_total_cap_and_discards_oldest_rotated_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lowertier.log");
        let mut appender = RollingFileAppenderBase::builder()
            .filename(path.to_string_lossy().into_owned())
            .condition_daily()
            .max_filecount(3)
            .condition_max_file_size(512)
            .max_total_size(1200)
            .build()
            .unwrap();

        for i in 0..80 {
            let line = format!("line-{i:03}-abcdefghijklmnopqrstuvwxyz\n");
            appender.write_all(line.as_bytes()).unwrap();
        }
        appender.flush().unwrap();

        assert!(
            total_log_bytes(dir.path()) <= 1200,
            "total bytes {} exceeded 1200",
            total_log_bytes(dir.path())
        );
        let active = fs::read_to_string(&path).unwrap();
        assert!(
            active.contains("line-079-"),
            "newest log line must be retained in active file: {active}"
        );
        let all_contents: String = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| fs::read_to_string(e.path()).ok())
            .collect();
        assert!(
            !all_contents.contains("line-000-"),
            "oldest log line should have been discarded"
        );
    }

    #[test]
    fn prunes_oversized_existing_logs_on_startup() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lowertier.log");
        fs::write(&path, "old-active-line\n".repeat(40)).unwrap();
        fs::write(dir.path().join("lowertier.log.1"), "r1\n".repeat(100)).unwrap();
        fs::write(dir.path().join("lowertier.log.2"), "r2\n".repeat(100)).unwrap();
        fs::write(dir.path().join("lowertier.log.4"), "stale\n".repeat(100)).unwrap();

        let _appender = RollingFileAppenderBase::builder()
            .filename(path.to_string_lossy().into_owned())
            .condition_daily()
            .max_filecount(3)
            .condition_max_file_size(512)
            .max_total_size(1024)
            .build()
            .unwrap();

        assert!(!dir.path().join("lowertier.log.4").exists());
        assert!(total_log_bytes(dir.path()) <= 1024);
    }

    #[test]
    fn clear_removes_rotated_and_truncates_active_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("lowertier.log");
        let mut appender = RollingFileAppenderBase::builder()
            .filename(path.to_string_lossy().into_owned())
            .condition_daily()
            .max_filecount(3)
            .condition_max_file_size(128)
            .max_total_size(1024)
            .build()
            .unwrap();

        for i in 0..20 {
            appender
                .write_all(format!("entry-{i:02}-0123456789\n").as_bytes())
                .unwrap();
        }
        appender.flush().unwrap();
        assert!(total_log_bytes(dir.path()) > 0);

        appender.clear().unwrap();
        assert_eq!(total_log_bytes(dir.path()), 0);
        assert!(!dir.path().join("lowertier.log.1").exists());
    }
}
