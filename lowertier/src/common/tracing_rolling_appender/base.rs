use super::*;
use anyhow::anyhow;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RollingConditionBase {
    last_write_opt: Option<DateTime<Local>>,
    frequency_opt: Option<RollingFrequency>,
    max_size_opt: Option<u64>,
}

impl RollingConditionBase {
    /// Constructs a new struct that does not yet have any condition set.
    pub fn new() -> RollingConditionBase {
        RollingConditionBase {
            last_write_opt: None,
            frequency_opt: None,
            max_size_opt: None,
        }
    }

    /// Sets a condition to rollover on the given frequency
    pub fn frequency(mut self, x: RollingFrequency) -> RollingConditionBase {
        self.frequency_opt = Some(x);
        self
    }

    /// Sets a condition to rollover when the date changes
    pub fn daily(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryDay);
        self
    }

    /// Sets a condition to rollover when the date or hour changes
    pub fn hourly(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryHour);
        self
    }

    /// Sets a condition to rollover when the date or minute changes
    pub fn minutely(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryMinute);
        self
    }

    /// Sets a condition to rollover when a certain size is reached
    pub fn max_size(mut self, x: u64) -> RollingConditionBase {
        self.max_size_opt = Some(x);
        self
    }
}

impl Default for RollingConditionBase {
    fn default() -> Self {
        RollingConditionBase::new().frequency(RollingFrequency::EveryDay)
    }
}

impl RollingCondition for RollingConditionBase {
    fn should_rollover(&mut self, now: &DateTime<Local>, current_filesize: u64) -> bool {
        let mut rollover = false;
        if let Some(frequency) = self.frequency_opt.as_ref()
            && let Some(last_write) = self.last_write_opt.as_ref()
            && frequency.equivalent_datetime(now) != frequency.equivalent_datetime(last_write)
        {
            rollover = true;
        }
        if let Some(max_size) = self.max_size_opt.as_ref()
            && current_filesize >= *max_size
        {
            rollover = true;
        }
        self.last_write_opt = Some(*now);
        rollover
    }
}

pub struct RollingFileAppenderBaseBuilder {
    condition: RollingConditionBase,
    filename: String,
    max_filecount: usize,
    current_filesize: u64,
    writer_opt: Option<BufWriter<File>>,
}

impl Default for RollingFileAppenderBaseBuilder {
    fn default() -> Self {
        RollingFileAppenderBaseBuilder {
            condition: RollingConditionBase::default(),
            filename: String::new(),
            max_filecount: 10,
            current_filesize: 0,
            writer_opt: None,
        }
    }
}

impl RollingFileAppenderBaseBuilder {
    /// Sets the log filename. Uses absolute path if provided, otherwise
    /// creates files in the current working directory.
    pub fn filename(mut self, filename: String) -> Self {
        self.filename = filename;
        self
    }

    /// Sets a condition for the maximum number of files to create before rolling
    /// over and deleting the oldest one.
    pub fn max_filecount(mut self, max_filecount: usize) -> Self {
        self.max_filecount = max_filecount;
        self
    }

    /// Sets a condition to rollover on a daily basis
    pub fn condition_daily(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryDay);
        self
    }

    /// Sets a condition to rollover when the date or hour changes
    pub fn condition_hourly(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryHour);
        self
    }

    /// Sets a condition to rollover when the date or minute changes
    pub fn condition_minutely(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryMinute);
        self
    }

    /// Sets a condition to rollover when a certain size is reached
    pub fn condition_max_file_size(mut self, x: u64) -> Self {
        self.condition.max_size_opt = Some(x);
        self
    }

    /// Builds a RollingFileAppenderBase instance from the current settings.
    ///
    /// Returns an error if the filename is empty.
    pub fn build(self) -> anyhow::Result<RollingFileAppenderBase> {
        if self.filename.is_empty() {
            return Err(anyhow!(
                "A filename is required to be set and can not be blank"
            ));
        }
        Ok(RollingFileAppenderBase {
            condition: self.condition,
            filename: self.filename,
            max_filecount: self.max_filecount,
            current_filesize: self.current_filesize,
            writer_opt: self.writer_opt,
        })
    }
}

impl RollingFileAppenderBase {
    /// Creates a new rolling file appender builder instance with the default
    /// settings without a filename set.
    pub fn builder() -> RollingFileAppenderBaseBuilder {
        RollingFileAppenderBaseBuilder::default()
    }
}

/// A rolling file appender with a rolling condition based on date/time or size.
pub type RollingFileAppenderBase = RollingFileAppender<RollingConditionBase>;

// LCOV_EXCL_START
#[cfg(test)]
mod test {
    use super::*;

    struct Context {
        _tempdir: tempfile::TempDir,
        rolling: RollingFileAppenderBase,
    }

    impl Context {
        fn verify_contains(&mut self, needle: &str, n: usize) {
            self.rolling.flush().unwrap();
            let p = self.rolling.filename_for(n);
            let haystack = fs::read_to_string(&p).unwrap();
            if !haystack.contains(needle) {
                panic!("file {:?} did not contain expected contents {}", p, needle);
            }
        }
    }

    fn build_context(condition: RollingConditionBase, max_files: usize) -> Context {
        let tempdir = tempfile::tempdir().unwrap();
        let filename = tempdir.path().join("test.log");
        let rolling = RollingFileAppenderBase::new(filename, condition, max_files).unwrap();
        Context {
            _tempdir: tempdir,
            rolling,
        }
    }

    fn build_builder_context(mut builder: RollingFileAppenderBaseBuilder) -> Context {
        if builder.filename.is_empty() {
            builder = builder.filename(String::from("test.log"));
        }
        let tempdir = tempfile::tempdir().unwrap();
        let filename = tempdir.path().join(&builder.filename);
        builder = builder.filename(String::from(filename.as_os_str().to_str().unwrap()));
        Context {
            _tempdir: tempdir,
            rolling: builder.build().unwrap(),
        }
    }
}
// LCOV_EXCL_STOP
