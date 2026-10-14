use atomic_shim::AtomicU64;
use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;

use crate::proto::common::LimiterConfig;

/// Token Bucket rate limiter using atomic operations
pub struct TokenBucket {
    available_tokens: AtomicU64, // Current token count (atomic)
    last_refill_time: AtomicU64, // Last refill time as micros since epoch
    config: BucketConfig,        // Immutable configuration
    refill_task: Mutex<Option<AbortOnDropHandle<()>>>, // Background refill task
    start_time: Instant,         // Bucket creation time

    refill_notifier: Arc<Notify>,
}

#[derive(Clone, Copy)]
pub struct BucketConfig {
    capacity: u64,             // Maximum token capacity
    fill_rate: u64,            // Tokens added per second
    refill_interval: Duration, // Time between refill operations
}

impl From<LimiterConfig> for BucketConfig {
    fn from(cfg: LimiterConfig) -> Self {
        let burst_rate = 1.max(cfg.burst_rate.unwrap_or(1));
        let fill_rate = 8196.max(cfg.bps.unwrap_or(u64::MAX / burst_rate));
        let refill_interval = cfg
            .fill_duration_ms
            .map(|x| Duration::from_millis(1.max(x)))
            .unwrap_or(Duration::from_millis(10));
        BucketConfig {
            capacity: burst_rate * fill_rate,
            fill_rate,
            refill_interval,
        }
    }
}

impl TokenBucket {
    pub fn new(capacity: u64, bps: u64, refill_interval: Duration) -> Arc<Self> {
        let config = BucketConfig {
            capacity,
            fill_rate: bps,
            refill_interval,
        };
        Self::new_from_cfg(config)
    }

    /// Creates a new Token Bucket rate limiter
    ///
    /// # Arguments
    /// * `capacity` - Bucket capacity in bytes
    /// * `bps` - Bandwidth limit in bytes per second
    /// * `refill_interval` - Refill interval (recommended 10-50ms)
    pub fn new_from_cfg(config: BucketConfig) -> Arc<Self> {
        // Create Arc instance with placeholder task
        let arc_self = Arc::new(Self {
            available_tokens: AtomicU64::new(config.capacity),
            last_refill_time: AtomicU64::new(0),
            config,
            refill_task: Mutex::new(None),
            start_time: std::time::Instant::now(),
            refill_notifier: Arc::new(Notify::new()),
        });

        // Start background refill task
        let weak_bucket = Arc::downgrade(&arc_self);
        let refill_interval = arc_self.config.refill_interval;
        let refill_notifer = arc_self.refill_notifier.clone();
        let refill_task = tokio::spawn(async move {
            let mut interval = time::interval(refill_interval);
            loop {
                interval.tick().await;
                let Some(bucket) = weak_bucket.upgrade() else {
                    break;
                };
                bucket.refill();
                refill_notifer.notify_waiters();
            }
        });

        // Replace placeholder task with actual one
        arc_self
            .refill_task
            .lock()
            .unwrap()
            .replace(AbortOnDropHandle::new(refill_task));
        arc_self
    }

    /// Internal refill method (called only by background task)
    fn refill(&self) {
        let now_micros = self.elapsed_micros();
        let prev_time = self.last_refill_time.swap(now_micros, Ordering::Acquire);

        // Calculate elapsed time in seconds
        let elapsed_secs = (now_micros.saturating_sub(prev_time)) as f64 / 1_000_000.0;

        // Calculate tokens to add
        let tokens_to_add = (self.config.fill_rate as f64 * elapsed_secs) as u64;
        if tokens_to_add == 0 {
            return;
        }

        // Add tokens without exceeding capacity
        let mut current = self.available_tokens.load(Ordering::Relaxed);
        loop {
            let new = current
                .saturating_add(tokens_to_add)
                .min(self.config.capacity);
            match self.available_tokens.compare_exchange_weak(
                current,
                new,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Calculate microseconds since bucket creation
    fn elapsed_micros(&self) -> u64 {
        self.start_time.elapsed().as_micros() as u64
    }

    /// Attempt to consume tokens without blocking
    ///
    /// # Returns
    /// `true` if tokens were consumed, `false` if insufficient tokens
    pub fn try_consume(&self, tokens: u64) -> bool {
        // Fast path for oversized packets
        if tokens > self.config.capacity {
            return false;
        }

        let mut current = self.available_tokens.load(Ordering::Relaxed);
        loop {
            if current < tokens {
                return false;
            }

            let new = current - tokens;
            match self.available_tokens.compare_exchange_weak(
                current,
                new,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Consume tokens, blocking if not available
    pub async fn consume(&self, tokens: u64) {
        while !self.try_consume(tokens) {
            self.refill_notifier.notified().await;
        }
    }
}

pub struct TokenBucketManager {
    buckets: Arc<DashMap<String, Arc<TokenBucket>>>,

    _retain_task: Option<AbortOnDropHandle<()>>,
}

impl Default for TokenBucketManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBucketManager {
    /// Creates a new TokenBucketManager
    pub fn new() -> Self {
        let buckets = Arc::new(DashMap::new());

        let retain_task = tokio::runtime::Handle::try_current().ok().map(|runtime| {
            let buckets_clone = buckets.clone();
            AbortOnDropHandle::new(runtime.spawn(async move {
                loop {
                    // Retain only buckets that are still in use.
                    let old_len = buckets_clone.len();
                    buckets_clone.retain(|_, bucket| Arc::<TokenBucket>::strong_count(bucket) > 1);
                    buckets_clone.shrink_to_fit();
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    tracing::info!(
                        "Retained buckets: {} ({} dropped)",
                        buckets_clone.len(),
                        old_len.saturating_sub(buckets_clone.len())
                    );
                }
            }))
        });

        Self {
            buckets,
            _retain_task: retain_task,
        }
    }

    /// Get or create a token bucket for the given key
    pub fn get_or_create(&self, key: &str, cfg: BucketConfig) -> Arc<TokenBucket> {
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new_from_cfg(cfg))
            .clone()
    }
}
