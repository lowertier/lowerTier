use std::{
    collections::VecDeque,
    fmt::Write,
    sync::{LazyLock, Mutex},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::Layer;

use crate::proto::api::control::v1::{LogEntry, Page, ReadLogsResponse};

const LOG_CAPACITY: usize = 512;
const LOG_MESSAGE_BYTES: usize = 2048;

#[derive(Default)]
struct LogRing {
    entries: VecDeque<LogEntry>,
    sequence: u64,
    truncated: u64,
    memory: Option<crate::common::global_ctx::ProcessMemoryPermit>,
}

static RING: LazyLock<Mutex<LogRing>> = LazyLock::new(|| Mutex::new(LogRing::default()));
static LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(3);

pub(crate) fn set_level(level: tracing::level_filters::LevelFilter) {
    use tracing::level_filters::LevelFilter;
    let value = match level {
        LevelFilter::OFF => 0,
        LevelFilter::ERROR => 1,
        LevelFilter::WARN => 2,
        LevelFilter::INFO => 3,
        LevelFilter::DEBUG => 4,
        _ => 5,
    };
    LEVEL.store(value, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) struct ControlLogFilter;

impl<S> tracing_subscriber::layer::Filter<S> for ControlLogFilter {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        let value = match *metadata.level() {
            tracing::Level::ERROR => 1,
            tracing::Level::WARN => 2,
            tracing::Level::INFO => 3,
            tracing::Level::DEBUG => 4,
            tracing::Level::TRACE => 5,
        };
        value <= LEVEL.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn callsite_enabled(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
}

#[derive(Default)]
struct LogMessage(String);

impl std::fmt::Write for LogMessage {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let mut remaining = LOG_MESSAGE_BYTES
            .saturating_sub(self.0.len())
            .min(text.len());
        while !text.is_char_boundary(remaining) {
            remaining -= 1;
        }
        self.0.push_str(&text[..remaining]);
        Ok(())
    }
}

impl Visit for LogMessage {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(
            field.name(),
            "control_token"
                | "admin_token"
                | "network_secret"
                | "credential_secret"
                | "admission_secret"
        ) {
            return;
        }
        let _ = write!(self, "{}={value:?} ", field.name());
    }
}

pub(crate) struct ControlLogLayer;

pub(super) fn generation() -> u64 {
    let ring = RING.lock().unwrap();
    ring.sequence.saturating_add(ring.truncated)
}

impl<S: Subscriber> Layer<S> for ControlLogLayer {
    fn on_event(&self, event: &Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut message = LogMessage::default();
        event.record(&mut message);
        let metadata = event.metadata();
        let mut ring = RING.lock().unwrap();
        if ring.memory.is_none() {
            // Charge the ring capacity and the bounded UTF-8 string allocations.
            ring.memory = crate::common::global_ctx::global_process_memory_governor()
                .try_reserve_owned(3 * 1024 * 1024);
        }
        if ring.memory.is_none() {
            ring.truncated = ring.truncated.saturating_add(1);
            return;
        }
        ring.sequence = ring.sequence.saturating_add(1);
        let sequence = ring.sequence;
        if ring.entries.len() == LOG_CAPACITY {
            ring.entries.pop_front();
            ring.truncated = ring.truncated.saturating_add(1);
        }
        ring.entries.push_back(LogEntry {
            sequence,
            sampled_at_unix_ms: super::read::now_ms(),
            level: metadata.level().as_str().into(),
            target: metadata.target().chars().take(256).collect(),
            message: message.0,
        });
    }
}

pub(super) fn read(request: Option<Page>) -> anyhow::Result<ReadLogsResponse> {
    let request = request.unwrap_or_default();
    let after = if request.page_token.is_empty() {
        0
    } else {
        let (epoch, sequence) = request.page_token.rsplit_once(':').ok_or_else(|| {
            super::failure(
                "INVALID_ARGUMENT",
                "The log cursor is invalid.",
                "page.page_token",
            )
        })?;
        if epoch != super::watch::PROCESS_EPOCH.to_string() {
            return Err(super::failure(
                "CONFLICT",
                "The log cursor belongs to an earlier process.",
                "page.page_token",
            ));
        }
        sequence.parse::<u64>().map_err(|_| {
            super::failure(
                "INVALID_ARGUMENT",
                "The log cursor is invalid.",
                "page.page_token",
            )
        })?
    };
    let limit = if request.limit == 0 {
        100
    } else {
        request.limit.min(256)
    } as usize;
    let ring = RING.lock().unwrap();
    if after > ring.sequence {
        return Err(super::failure(
            "CONFLICT",
            "The log cursor belongs to an earlier process.",
            "page.page_token",
        ));
    }
    let logs = ring
        .entries
        .iter()
        .filter(|entry| entry.sequence > after)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let next_page_token = format!(
        "{}:{}",
        *super::watch::PROCESS_EPOCH,
        logs.last().map_or(after, |entry| entry.sequence)
    );
    Ok(ReadLogsResponse {
        logs,
        next_page_token,
        truncated: ring.truncated,
        ..Default::default()
    })
}
