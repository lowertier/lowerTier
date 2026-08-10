use std::time::Duration;

/// Small, connection-stable profile catalog.
///
/// Values are selected once per connection. Per-packet randomisation is
/// intentionally absent because unconstrained variation creates a distinctive
/// high-entropy fingerprint and destabilises congestion control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireProfileKind {
    Bulk,
    Interactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireProfile {
    pub kind: WireProfileKind,
    /// Quinn's standard spin-bit behaviour is allowed. A strict deployment can
    /// choose the interactive profile and disable it in the integration layer.
    pub allow_spin: bool,
    /// QUIC-level fixed periodic keepalive remains disabled. LowTier's existing
    /// authenticated pinger may use this bounded, jittered interval only while
    /// the path is otherwise idle and NAT state must be preserved.
    pub application_keepalive_min: Duration,
    pub application_keepalive_max: Duration,
    /// Packet-timed rounds between adaptive capacity probes.
    pub probe_rounds_min: u8,
    pub probe_rounds_max: u8,
}

impl WireProfile {
    pub const BULK: Self = Self {
        kind: WireProfileKind::Bulk,
        allow_spin: true,
        application_keepalive_min: Duration::from_secs(23),
        application_keepalive_max: Duration::from_secs(37),
        probe_rounds_min: 8,
        probe_rounds_max: 12,
    };

    pub const INTERACTIVE: Self = Self {
        kind: WireProfileKind::Interactive,
        allow_spin: true,
        application_keepalive_min: Duration::from_secs(17),
        application_keepalive_max: Duration::from_secs(31),
        probe_rounds_min: 9,
        probe_rounds_max: 13,
    };

    /// Select from a finite catalog. This creates a small anonymity set and
    /// keeps one profile stable for the lifetime of the connection.
    pub fn select(seed: u64, bulk_hint: bool) -> Self {
        let random = XorShift64::new(seed).next();
        match (bulk_hint, random & 0b11) {
            (true, 0..=2) => Self::BULK,
            (false, 0) => Self::BULK,
            _ => Self::INTERACTIVE,
        }
    }

    pub fn keepalive_interval(self, seed: u64) -> Duration {
        duration_inclusive(
            self.application_keepalive_min,
            self.application_keepalive_max,
            seed,
        )
    }

    pub fn probe_rounds(self, seed: u64) -> u8 {
        let width = u64::from(
            self.probe_rounds_max
                .saturating_sub(self.probe_rounds_min)
                .saturating_add(1),
        );
        self.probe_rounds_min
            .saturating_add(u8::try_from(XorShift64::new(seed).next() % width).unwrap_or(0))
    }
}

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    fn next(mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

fn duration_inclusive(minimum: Duration, maximum: Duration, seed: u64) -> Duration {
    let minimum_ms = u64::try_from(minimum.as_millis()).unwrap_or(u64::MAX);
    let maximum_ms = u64::try_from(maximum.as_millis()).unwrap_or(u64::MAX);
    let width = maximum_ms.saturating_sub(minimum_ms).saturating_add(1);
    Duration::from_millis(minimum_ms.saturating_add(XorShift64::new(seed).next() % width.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_and_jitter_are_deterministic_for_one_seed() {
        let first = WireProfile::select(42, true);
        let second = WireProfile::select(42, true);
        assert_eq!(first, second);
        assert_eq!(first.keepalive_interval(99), second.keepalive_interval(99));
    }

    #[test]
    fn generated_values_remain_inside_profile_bounds() {
        for profile in [WireProfile::BULK, WireProfile::INTERACTIVE] {
            for seed in 0..1000 {
                let keepalive = profile.keepalive_interval(seed);
                assert!(keepalive >= profile.application_keepalive_min);
                assert!(keepalive <= profile.application_keepalive_max);
                let rounds = profile.probe_rounds(seed);
                assert!(rounds >= profile.probe_rounds_min);
                assert!(rounds <= profile.probe_rounds_max);
            }
        }
    }
}
