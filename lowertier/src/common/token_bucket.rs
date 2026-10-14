use atomic_shim::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;

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
