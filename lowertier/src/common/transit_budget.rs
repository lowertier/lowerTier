use std::time::Instant;

use super::control_config::RelayConfig;

// Store credit in bits. Integer division must not turn a small rate into zero.
#[derive(Debug)]
pub(crate) struct TransitBudget {
    rate: Option<u64>,
    capacity: u128,
    credit: u128,
    remainder: u128,
    updated: Instant,
}

impl TransitBudget {
    pub(crate) fn new(config: &RelayConfig) -> Self {
        let capacity = Self::capacity(config);
        Self {
            rate: config.transit_bps_limit,
            capacity,
            credit: capacity,
            remainder: 0,
            updated: Instant::now(),
        }
    }

    fn capacity(config: &RelayConfig) -> u128 {
        u128::from(config.transit_burst_bytes.unwrap_or_else(|| {
            config
                .transit_bps_limit
                .unwrap_or(0)
                .div_ceil(8)
                .max(super::control_config::MAX_TRANSIT_PACKET_BYTES)
        })) * 8
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.updated = now;
        if let Some(rate) = self.rate {
            let bits = elapsed
                .saturating_mul(u128::from(rate))
                .saturating_add(self.remainder);
            self.credit = self
                .capacity
                .min(self.credit.saturating_add(bits / 1_000_000_000));
            self.remainder = bits % 1_000_000_000;
        }
    }

    pub(crate) fn update(&mut self, config: &RelayConfig) {
        self.refill(Instant::now());
        self.rate = config.transit_bps_limit;
        self.capacity = Self::capacity(config);
        // A configuration update cannot grant a fresh burst.
        self.credit = self.credit.min(self.capacity);
    }

    pub(crate) fn consume(&mut self, bytes: usize) -> bool {
        self.refill(Instant::now());
        if self.rate.is_none() {
            return true;
        }
        let bits = bytes as u128 * 8;
        if bits > self.credit {
            return false;
        }
        self.credit -= bits;
        true
    }

    pub(crate) fn receive_chunk(&mut self, bytes: usize) -> (usize, std::time::Duration) {
        if self.rate.is_none() {
            return (bytes, std::time::Duration::ZERO);
        }
        let chunk = bytes.min((self.capacity / 8) as usize);
        if self.consume(chunk) {
            return (chunk, std::time::Duration::ZERO);
        }
        let nanos = (chunk as u128 * 8 - self.credit)
            .saturating_mul(1_000_000_000)
            .div_ceil(u128::from(self.rate.unwrap()));
        (
            0,
            std::time::Duration::from_nanos(nanos.min(u64::MAX as u128) as u64),
        )
    }
}

#[cfg(test)]
pub(crate) fn check_budget_units() {
    let config = RelayConfig {
        transit_bps_limit: Some(1),
        transit_burst_bytes: Some(super::control_config::MAX_TRANSIT_PACKET_BYTES),
        ..Default::default()
    };
    let mut budget = TransitBudget::new(&config);
    assert!(budget.consume(super::control_config::MAX_TRANSIT_PACKET_BYTES as usize));
    assert!(!budget.consume(1));
    let now = budget.updated + std::time::Duration::from_secs(8);
    budget.refill(now);
    assert_eq!(budget.credit, 8);
    assert!(budget.consume(1));
    budget.update(&config);
    assert!(!budget.consume(1));
}
