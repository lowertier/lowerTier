//! Offline fast-window model; sends no network traffic and has no dependencies.
//! Time is integer microseconds. UDP bytes include IPv4+UDP (28 bytes).
//! HTTP, DNS, mDNS, and final handshake timings are explicit modeling assumptions.
//! Run through run.py. This file is deliberately independent of the production crate.
use std::{cmp::Reverse, collections::BinaryHeap, env, error::Error};

const MS: u64 = 1000;
const SECOND: u64 = 1000 * MS;
const MAX_TRACKERS: usize = 8;
const UDP_HEADER: u64 = 28;
const TRACKER_RETRY: u64 = 15 * SECOND;
const COOKIE_LIFETIME: u64 = 60 * SECOND;
const ANNOUNCE_INTERVAL: u64 = 1800 * SECOND;
const PUNCH_FACTORS: [u64; 7] = [0, 1, 3, 7, 15, 31, 63];

#[derive(Clone, Copy)]
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / ((1u64 << 53) as f64)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    fn shuffle(&mut self, xs: &mut [usize]) {
        for i in (1..xs.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            xs.swap(i, j);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Transport {
    Udp,
    Http,
    Https,
}
#[derive(Clone, Copy)]
struct Policy {
    name: &'static str,
    count: usize,
    initial: usize,
    hedge: u64,
    mixed: bool,
    grace: u64,
    stun_second: u64,
    punch_unit: u64,
}
impl Policy {
    fn transport(self, t: usize) -> Transport {
        if self.mixed && t == self.count - 2 {
            Transport::Http
        } else if self.mixed && t == self.count - 1 {
            Transport::Https
        } else {
            Transport::Udp
        }
    }
}
fn policies() -> Vec<Policy> {
    let base = Policy {
        name: "udp1",
        count: 1,
        initial: 1,
        hedge: 0,
        mixed: false,
        grace: 0,
        stun_second: 100 * MS,
        punch_unit: 50 * MS,
    };
    vec![
        base,
        Policy {
            name: "udp2",
            count: 2,
            initial: 2,
            ..base
        },
        Policy {
            name: "udp4",
            count: 4,
            initial: 4,
            ..base
        },
        Policy {
            name: "udp8",
            count: 8,
            initial: 8,
            ..base
        },
        Policy {
            name: "hedge4",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            ..base
        },
        Policy {
            name: "mixed4",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            mixed: true,
            ..base
        },
        Policy {
            name: "mixed6",
            count: 6,
            initial: 2,
            hedge: 150 * MS,
            mixed: true,
            ..base
        },
        Policy {
            name: "lan150_mixed4",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            mixed: true,
            grace: 150 * MS,
            ..base
        },
        Policy {
            name: "lan250_mixed4",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            mixed: true,
            grace: 250 * MS,
            ..base
        },
        Policy {
            name: "udp4_p100",
            count: 4,
            initial: 4,
            punch_unit: 100 * MS,
            ..base
        },
        Policy {
            name: "hedge4_p100",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            punch_unit: 100 * MS,
            ..base
        },
        Policy {
            name: "mixed6_p100",
            count: 6,
            initial: 2,
            hedge: 150 * MS,
            mixed: true,
            punch_unit: 100 * MS,
            ..base
        },
        Policy {
            name: "lan250_hedge4_p100",
            count: 4,
            initial: 2,
            hedge: 150 * MS,
            grace: 250 * MS,
            punch_unit: 100 * MS,
            ..base
        },
    ]
}
#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    skew: u64,
    restricted: bool,
    dependent: bool,
    lan: bool,
    cached_peer: bool,
    warm: bool,
    tracker_udp_blocked: bool,
    all_udp_blocked: bool,
    outage: f64,
    loss: f64,
}
fn scenarios() -> Vec<Scenario> {
    let s = Scenario {
        name: "open_simultaneous",
        skew: 0,
        restricted: false,
        dependent: false,
        lan: false,
        cached_peer: false,
        warm: false,
        tracker_udp_blocked: false,
        all_udp_blocked: false,
        outage: 0.0,
        loss: 0.0,
    };
    vec![
        s,
        Scenario {
            name: "restricted_simultaneous",
            restricted: true,
            ..s
        },
        Scenario {
            name: "restricted_skew_2s",
            restricted: true,
            skew: 2 * SECOND,
            ..s
        },
        Scenario {
            name: "open_skew_2s",
            skew: 2 * SECOND,
            ..s
        },
        Scenario {
            name: "warm_restricted",
            restricted: true,
            warm: true,
            ..s
        },
        Scenario {
            name: "outage20_loss2",
            outage: 0.2,
            loss: 0.02,
            ..s
        },
        Scenario {
            name: "restricted_outage20_loss2",
            restricted: true,
            outage: 0.2,
            loss: 0.02,
            ..s
        },
        Scenario {
            name: "tracker_udp_blocked",
            tracker_udp_blocked: true,
            ..s
        },
        Scenario {
            name: "all_udp_blocked",
            all_udp_blocked: true,
            ..s
        },
        Scenario {
            name: "unpredictable_mapping",
            dependent: true,
            restricted: true,
            ..s
        },
        Scenario {
            name: "lan_registered",
            lan: true,
            skew: 100 * MS,
            ..s
        },
        Scenario {
            name: "cached_peer",
            cached_peer: true,
            ..s
        },
    ]
}

#[derive(Clone, Copy)]
struct Environment {
    starts: [u64; 2],
    rtt: [[u64; MAX_TRACKERS]; 2],
    dns: [[u64; MAX_TRACKERS]; 2],
    stun: [[u64; 2]; 2],
    alive: [bool; MAX_TRACKERS],
    peer_rtt: u64,
    lan_rtt: u64,
    query_delay: [u64; 2],
    answer_delay: [u64; 2],
}
impl Environment {
    fn generate(s: Scenario, seed: u64) -> Self {
        let mut r = Rng(seed);
        let mut e = Self {
            starts: [0, r.range(0, s.skew)],
            rtt: [[0; MAX_TRACKERS]; 2],
            dns: [[0; MAX_TRACKERS]; 2],
            stun: [[0; 2]; 2],
            alive: [true; MAX_TRACKERS],
            peer_rtt: r.range(20 * MS, 80 * MS),
            lan_rtt: 2 * MS,
            query_delay: [r.range(20 * MS, 120 * MS), r.range(20 * MS, 120 * MS)],
            answer_delay: [r.range(20 * MS, 120 * MS), r.range(20 * MS, 120 * MS)],
        };
        let access = [r.range(5 * MS, 35 * MS), r.range(5 * MS, 35 * MS)];
        for t in 0..MAX_TRACKERS {
            let shared = r.range(15 * MS, 100 * MS);
            e.alive[t] = r.unit() >= s.outage;
            for (n, a) in access.iter().enumerate() {
                e.rtt[n][t] = shared + a + r.range(0, 25 * MS);
                e.dns[n][t] = if s.warm { 0 } else { r.range(5 * MS, 30 * MS) };
            }
        }
        for (n, a) in access.iter().enumerate() {
            for j in 0..2 {
                e.stun[n][j] = a + r.range(10 * MS, 40 * MS);
            }
        }
        e
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Boot(usize),
    Wan(usize),
    Begin(usize, usize),
    StunSend(usize, usize, u8),
    StunServer(usize, usize),
    StunDone(usize),
    ConnectSend(usize, usize, u8),
    ConnectServer(usize, usize),
    Connected(usize, usize),
    AnnounceSend(usize, usize, u8),
    AnnounceServer(usize, usize),
    AnnounceDone(usize, usize, bool),
    LanQuery(usize),
    LanAnswer(usize),
    LanDone(usize),
    Hint(usize, bool),
    Punch(usize),
    PunchArrive(usize, bool),
    Ack(usize, bool),
}
#[derive(Default, Clone, Copy)]
struct Cost {
    wan_bytes: u64,
    lan_bytes: u64,
    wan_packets: u64,
    lan_packets: u64,
    punch_bytes: u64,
}
#[derive(Clone, Copy)]
struct ResultRow {
    first: Option<u64>,
    mutual: Option<u64>,
    check: Option<u64>,
    cost: Cost,
}
struct Model {
    s: Scenario,
    p: Policy,
    e: Environment,
    rng: Rng,
    queue: BinaryHeap<Reverse<(u64, u64, Event)>>,
    sequence: u64,
    mapped: [bool; 2],
    ready: [[bool; MAX_TRACKERS]; 2],
    issued: [[bool; MAX_TRACKERS]; 2],
    answered: [[bool; MAX_TRACKERS]; 2],
    cookie: [[u64; MAX_TRACKERS]; 2],
    registered: [[Option<u64>; 2]; MAX_TRACKERS],
    next_announce: [[u64; MAX_TRACKERS]; 2],
    known: [Option<u64>; 2],
    local: [bool; 2],
    opened_until: [u64; 2],
    train: [bool; 2],
    confirmed: [bool; 2],
    check: Option<u64>,
    cancel_at: Option<u64>,
    cost: Cost,
    horizon: u64,
}
impl Model {
    fn new(s: Scenario, p: Policy, e: Environment, seed: u64) -> Self {
        let mut m = Self {
            s,
            p,
            e,
            rng: Rng(seed ^ 0xd6e8feb86659fd93),
            queue: BinaryHeap::new(),
            sequence: 0,
            mapped: [false; 2],
            ready: [[false; MAX_TRACKERS]; 2],
            issued: [[false; MAX_TRACKERS]; 2],
            answered: [[false; MAX_TRACKERS]; 2],
            cookie: [[0; MAX_TRACKERS]; 2],
            registered: [[None; 2]; MAX_TRACKERS],
            next_announce: [[0; MAX_TRACKERS]; 2],
            known: [None; 2],
            local: [false; 2],
            opened_until: [0; 2],
            train: [false; 2],
            confirmed: [false; 2],
            check: None,
            cancel_at: None,
            cost: Cost::default(),
            horizon: e.starts[1] + 5 * SECOND,
        };
        m.push(e.starts[0], Event::Boot(0));
        m.push(e.starts[1], Event::Boot(1));
        m
    }
    fn push(&mut self, t: u64, event: Event) {
        if t <= self.horizon {
            self.sequence += 1;
            self.queue.push(Reverse((t, self.sequence, event)));
        }
    }
    fn active(&self, now: u64) -> bool {
        self.cancel_at.is_none_or(|t| now < t)
    }
    fn survives(&mut self) -> bool {
        self.rng.unit() >= self.s.loss
    }
    fn udp_cost(&mut self, payload: u64, lan: bool, punch: bool) {
        let size = payload + UDP_HEADER;
        if lan {
            self.cost.lan_bytes += size;
            self.cost.lan_packets += 1;
        } else {
            self.cost.wan_bytes += size;
            self.cost.wan_packets += 1;
        }
        if punch {
            self.cost.punch_bytes += size;
        }
    }
    fn dns_cost(&mut self) {
        self.cost.wan_bytes += 200;
        self.cost.wan_packets += 2;
    }
    fn tracker_live(&self, t: usize) -> bool {
        self.e.alive[t]
            && !(self.p.transport(t) == Transport::Udp
                && (self.s.tracker_udp_blocked || self.s.all_udp_blocked))
    }
    fn maybe_announce(&mut self, now: u64, n: usize, t: usize) {
        if self.active(now) && self.mapped[n] && self.ready[n][t] && !self.issued[n][t] {
            self.issued[n][t] = true;
            self.push(now, Event::AnnounceSend(n, t, 0));
        }
    }
    fn learn(&mut self, now: u64, n: usize, lan: bool) {
        if self.known[n].is_none() {
            self.known[n] = Some(now);
        }
        self.local[n] |= lan;
        if !self.train[n] && self.active(now) {
            self.train[n] = true;
            for factor in PUNCH_FACTORS {
                self.push(now + factor * self.p.punch_unit, Event::Punch(n));
            }
        }
    }
    fn handle(&mut self, now: u64, event: Event) {
        match event {
            Event::Boot(n) => {
                if self.s.cached_peer {
                    self.push(now, Event::Hint(n, false));
                }
                self.push(now + self.e.query_delay[n], Event::LanQuery(n));
                self.push(now + self.p.grace, Event::Wan(n));
            }
            Event::Wan(n) => {
                if !self.active(now) {
                    return;
                }
                self.push(now, Event::StunSend(n, 0, 0));
                self.push(now + self.p.stun_second, Event::StunSend(n, 1, 0));
                // Both peers use the same small pool. Only order/jitter is private.
                let mut ids: Vec<usize> = (0..self.p.count).collect();
                self.rng.shuffle(&mut ids);
                // Prefer UDP slots first in mixed policies; maintain independent UDP order.
                ids.sort_by_key(|&t| usize::from(self.p.transport(t) != Transport::Udp));
                for (rank, t) in ids.into_iter().enumerate() {
                    let delay = if rank < self.p.initial {
                        0
                    } else {
                        (rank - self.p.initial + 1) as u64 * self.p.hedge
                    };
                    self.push(now + delay, Event::Begin(n, t));
                }
            }
            Event::StunSend(n, j, attempt) => {
                if !self.active(now) || self.mapped[n] {
                    return;
                }
                if attempt == 0 && !self.s.warm {
                    self.dns_cost();
                }
                self.udp_cost(20, false, false);
                let dns = if attempt == 0 && !self.s.warm {
                    10 * MS
                } else {
                    0
                };
                if !self.s.all_udp_blocked && self.survives() {
                    self.push(now + dns + self.e.stun[n][j] / 2, Event::StunServer(n, j));
                }
                if attempt < 3 {
                    self.push(
                        now + (500 * MS << attempt),
                        Event::StunSend(n, j, attempt + 1),
                    );
                }
            }
            Event::StunServer(n, j) => {
                self.udp_cost(32, false, false);
                if self.survives() {
                    self.push(now + self.e.stun[n][j] / 2, Event::StunDone(n));
                }
            }
            Event::StunDone(n) => {
                self.mapped[n] = true;
                for t in 0..self.p.count {
                    self.maybe_announce(now, n, t);
                }
            }
            Event::Begin(n, t) => {
                if !self.active(now) {
                    return;
                }
                if !self.s.warm {
                    self.dns_cost();
                }
                let dns = self.e.dns[n][t];
                if self.s.warm {
                    self.cookie[n][t] = now + COOKIE_LIFETIME;
                    self.push(now + dns, Event::Connected(n, t));
                } else if self.p.transport(t) == Transport::Udp {
                    self.push(now + dns, Event::ConnectSend(n, t, 0));
                } else {
                    // Abstract TCP/TLS: reliable once reachable, no TCP loss model.
                    let tls = self.p.transport(t) == Transport::Https;
                    self.cost.wan_bytes += if tls { 4800 } else { 120 };
                    self.cost.wan_packets += if tls { 12 } else { 3 };
                    if self.tracker_live(t) {
                        self.push(
                            now + dns + self.e.rtt[n][t] * (if tls { 2 } else { 1 }),
                            Event::Connected(n, t),
                        );
                    }
                }
            }
            Event::ConnectSend(n, t, attempt) => {
                if !self.active(now) || self.ready[n][t] {
                    return;
                }
                self.udp_cost(16, false, false);
                if self.tracker_live(t) && self.survives() {
                    self.push(now + self.e.rtt[n][t] / 2, Event::ConnectServer(n, t));
                }
                if attempt < 2 {
                    self.push(
                        now + (TRACKER_RETRY << attempt),
                        Event::ConnectSend(n, t, attempt + 1),
                    );
                }
            }
            Event::ConnectServer(n, t) => {
                self.udp_cost(16, false, false);
                if self.survives() {
                    self.push(now + self.e.rtt[n][t] / 2, Event::Connected(n, t));
                }
            }
            Event::Connected(n, t) => {
                self.ready[n][t] = true;
                self.cookie[n][t] = now + COOKIE_LIFETIME;
                self.maybe_announce(now, n, t);
            }
            Event::AnnounceSend(n, t, attempt) => {
                if !self.active(now) || self.answered[n][t] {
                    return;
                }
                // No periodic announce occurs during this five-second fast window.
                assert!(now >= self.next_announce[n][t]);
                let udp = self.p.transport(t) == Transport::Udp;
                if udp && now >= self.cookie[n][t] {
                    return;
                }
                if udp {
                    self.udp_cost(98, false, false);
                } else {
                    self.cost.wan_bytes += 400;
                    self.cost.wan_packets += 2;
                }
                if self.tracker_live(t) && (!udp || self.survives()) {
                    self.push(now + self.e.rtt[n][t] / 2, Event::AnnounceServer(n, t));
                }
                if udp && attempt < 2 {
                    self.push(
                        now + (TRACKER_RETRY << attempt),
                        Event::AnnounceSend(n, t, attempt + 1),
                    );
                }
            }
            Event::AnnounceServer(n, t) => {
                self.registered[t][n] = Some(now);
                let has =
                    self.registered[t][1 - n].is_some_and(|at| now - at < ANNOUNCE_INTERVAL * 2);
                let udp = self.p.transport(t) == Transport::Udp;
                if udp {
                    self.udp_cost(20 + 6 * u64::from(has), false, false);
                } else {
                    self.cost.wan_bytes += 250 + 6 * u64::from(has);
                    self.cost.wan_packets += 2;
                }
                if !udp || self.survives() {
                    self.push(now + self.e.rtt[n][t] / 2, Event::AnnounceDone(n, t, has));
                }
            }
            Event::AnnounceDone(n, t, has) => {
                self.answered[n][t] = true;
                self.next_announce[n][t] = now + ANNOUNCE_INTERVAL;
                if has {
                    self.learn(now, n, false);
                }
            }
            Event::LanQuery(n) => {
                if !self.active(now) {
                    return;
                }
                self.udp_cost(96, true, false);
                // Registered mDNS responder only. Cold service probing is outside this model.
                if self.s.lan && now + self.e.lan_rtt / 2 >= self.e.starts[1 - n] && self.survives()
                {
                    self.push(
                        now + self.e.lan_rtt / 2 + self.e.answer_delay[1 - n],
                        Event::LanAnswer(n),
                    );
                }
            }
            Event::LanAnswer(n) => {
                self.udp_cost(200, true, false);
                if self.survives() {
                    self.push(now + self.e.lan_rtt / 2, Event::LanDone(n));
                }
            }
            Event::LanDone(n) => {
                self.learn(now, n, true);
            }
            Event::Hint(n, lan) => {
                self.learn(now, n, lan);
            }
            Event::Punch(n) => {
                if !self.active(now) || self.confirmed[n] {
                    return;
                }
                self.udp_cost(64, self.local[n], true);
                self.opened_until[n] = now + 30 * SECOND;
                if (self.local[n] || !self.s.all_udp_blocked) && self.survives() {
                    let rtt = if self.local[n] {
                        self.e.lan_rtt
                    } else {
                        self.e.peer_rtt
                    };
                    self.push(now + rtt / 2, Event::PunchArrive(n, self.local[n]));
                }
            }
            Event::PunchArrive(n, lan) => {
                let other = 1 - n;
                if now < self.e.starts[other] {
                    return;
                }
                if !lan
                    && (self.s.dependent || (self.s.restricted && self.opened_until[other] < now))
                {
                    return;
                }
                // One triggered ACK is enough; avoid a second redundant probe train.
                if self.known[other].is_none() {
                    self.known[other] = Some(now);
                }
                self.local[other] |= lan;
                self.udp_cost(64, lan, true);
                if self.survives() {
                    let rtt = if lan { self.e.lan_rtt } else { self.e.peer_rtt };
                    self.push(now + rtt / 2, Event::Ack(n, lan));
                }
            }
            Event::Ack(n, lan) => {
                self.confirmed[n] = true;
                if self.check.is_none() {
                    self.check = Some(now);
                    let rtt = if lan { self.e.lan_rtt } else { self.e.peer_rtt };
                    // Cancellation waits one extra modeled handshake RTT. Its bytes are excluded.
                    self.cancel_at = Some(now + rtt);
                }
            }
        }
    }
    fn run(mut self) -> ResultRow {
        while let Some(Reverse((now, _, event))) = self.queue.pop() {
            self.handle(now, event);
        }
        ResultRow {
            first: self.known.iter().flatten().copied().min(),
            mutual: self.known[0].zip(self.known[1]).map(|(a, b)| a.max(b)),
            check: self.check,
            cost: self.cost,
        }
    }
}

fn quantile(v: &mut [u64], p: f64) -> String {
    if v.is_empty() {
        return String::from("NA");
    }
    v.sort_unstable();
    let index = ((p * v.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(v.len() - 1);
    format!("{:.3}", v[index] as f64 / MS as f64)
}
fn csv_row(s: Scenario, p: Policy, trials: usize, seed: u64) {
    let mut first = Vec::with_capacity(trials);
    let mut mutual = Vec::with_capacity(trials);
    let mut checks = Vec::with_capacity(trials);
    let mut under1 = 0;
    let mut total = Cost::default();
    let mut success_bytes = 0u64;
    let mut failures_bytes = 0u64;
    for i in 0..trials {
        let trial_seed = seed.wrapping_add((i as u64).wrapping_mul(0x9e3779b97f4a7c15));
        let e = Environment::generate(s, trial_seed);
        let r = Model::new(s, p, e, trial_seed).run();
        let start = e.starts[1];
        if let Some(t) = r.first {
            first.push(t.saturating_sub(start));
        }
        if let Some(t) = r.mutual {
            mutual.push(t.saturating_sub(start));
        }
        if let Some(t) = r.check {
            let d = t.saturating_sub(start);
            checks.push(d);
            under1 += usize::from(d <= SECOND);
            success_bytes += r.cost.wan_bytes;
        } else {
            failures_bytes += r.cost.wan_bytes;
        }
        total.wan_bytes += r.cost.wan_bytes;
        total.lan_bytes += r.cost.lan_bytes;
        total.wan_packets += r.cost.wan_packets;
        total.punch_bytes += r.cost.punch_bytes;
    }
    let successes = checks.len();
    let first50 = quantile(&mut first, 0.5);
    let mutual50 = quantile(&mut mutual, 0.5);
    let check50 = quantile(&mut checks, 0.5);
    let check95 = quantile(&mut checks, 0.95);
    let avg = |x: u64, n: usize| {
        if n == 0 {
            String::from("NA")
        } else {
            format!("{:.2}", x as f64 / n as f64)
        }
    };
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        s.name,
        p.name,
        trials,
        successes,
        under1,
        first50,
        mutual50,
        check50,
        check95,
        avg(total.wan_bytes, trials),
        avg(total.lan_bytes, trials),
        avg(total.wan_packets, trials),
        avg(total.punch_bytes, trials),
        avg(success_bytes, successes),
        avg(failures_bytes, trials - successes),
        seed
    );
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let trials: usize = args
        .get(1)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(10_000);
    let seed: u64 = args
        .get(2)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(20260911);
    if trials == 0 || trials > 1_000_000 {
        return Err("trial count must be in 1..=1000000".into());
    }
    println!(
        "scenario,policy,trials,success_5s,success_1s,first_hint_p50_ms,mutual_hint_p50_ms,check_p50_ms_success_only,check_p95_ms_success_only,mean_wan_ip_bytes_all,mean_lan_ip_bytes_all,mean_wan_packets_all,mean_punch_ip_bytes_all,mean_wan_ip_bytes_success,mean_wan_ip_bytes_failure,seed"
    );
    for s in scenarios() {
        for p in policies() {
            csv_row(s, p, trials, seed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixed(s: Scenario) -> Environment {
        let mut e = Environment::generate(s, 7);
        e.starts = [0, 0];
        e.rtt = [[100 * MS; MAX_TRACKERS]; 2];
        e.dns = [[0; MAX_TRACKERS]; 2];
        e.stun = [[40 * MS; 2]; 2];
        e.alive = [true; MAX_TRACKERS];
        e.peer_rtt = 40 * MS;
        e
    }
    #[test]
    fn wire_costs() {
        assert_eq!(16 + 16 + 98 + 20 + 6 + 4 * 28, 268);
        assert_eq!(20 + 32 + 2 * 28, 108);
    }
    #[test]
    fn cold_parallel_critical_path() {
        let s = scenarios()[0];
        let r = Model::new(s, policies()[0], fixed(s), 1).run();
        assert_eq!(r.first, Some(200 * MS));
        assert_eq!(r.check, Some(240 * MS));
    }
    #[test]
    fn warm_cookie_saves_rtt_when_mapping_is_ready() {
        let s = Scenario {
            warm: true,
            ..scenarios()[0]
        };
        let r = Model::new(s, policies()[0], fixed(s), 1).run();
        assert_eq!(r.first, Some(140 * MS));
        assert_eq!(r.check, Some(180 * MS));
    }
    #[test]
    fn one_pull_does_not_open_two_restricted_nats() {
        let s = Scenario {
            restricted: true,
            ..scenarios()[0]
        };
        let r = Model::new(s, policies()[0], fixed(s), 1).run();
        assert!(r.first.is_some());
        assert!(r.check.is_none());
    }
    #[test]
    fn symmetric_arrival_order_can_defeat_eight_trackers() {
        let s = Scenario {
            restricted: true,
            ..scenarios()[0]
        };
        let r = Model::new(s, policies()[3], fixed(s), 1).run();
        assert!(r.check.is_none());
    }
    #[test]
    fn late_restricted_join_is_not_solved_by_a_startup_race() {
        let s = Scenario {
            restricted: true,
            ..scenarios()[0]
        };
        let mut e = fixed(s);
        e.starts[1] = 60 * SECOND;
        let r = Model::new(s, policies()[3], e, 1).run();
        assert!(r.first.is_some());
        assert!(r.check.is_none());
    }
    #[test]
    fn incompatible_mapping_remains_unreachable() {
        let s = Scenario {
            dependent: true,
            restricted: true,
            ..scenarios()[0]
        };
        assert!(
            Model::new(s, policies()[3], fixed(s), 1)
                .run()
                .check
                .is_none()
        );
    }
    #[test]
    fn https_signaling_cannot_repair_blocked_udp() {
        let s = Scenario {
            all_udp_blocked: true,
            cached_peer: true,
            ..scenarios()[0]
        };
        let result = Model::new(s, policies()[6], fixed(s), 1).run();
        assert!(result.first.is_some());
        assert!(result.check.is_none());
    }
    #[test]
    fn incoming_request_keeps_unacknowledged_checks_alive() {
        let s = scenarios()[0];
        let mut m = Model::new(s, policies()[0], fixed(s), 1);
        m.train[1] = true;
        m.handle(100 * MS, Event::PunchArrive(0, false));
        assert!(!m.confirmed[1]);
    }
    #[test]
    fn authenticated_reply_avoids_redundant_probe_train() {
        let s = scenarios()[0];
        let r = Model::new(s, policies()[0], fixed(s), 1).run();
        assert_eq!(r.cost.punch_bytes, 2 * (64 + UDP_HEADER));
    }
    #[test]
    fn inflight_wan_packet_keeps_its_original_path() {
        let s = Scenario {
            dependent: true,
            ..scenarios()[0]
        };
        let mut m = Model::new(s, policies()[0], fixed(s), 1);
        m.local[0] = true;
        m.handle(100 * MS, Event::PunchArrive(0, false));
        assert!(m.known[1].is_none());
    }
    #[test]
    fn slower_retry_does_not_delay_the_first_probe() {
        let s = scenarios()[0];
        let a = Model::new(s, policies()[2], fixed(s), 1).run();
        let b = Model::new(s, policies()[9], fixed(s), 1).run();
        assert_eq!(a.check, b.check);
        assert!(b.cost.punch_bytes <= a.cost.punch_bytes);
    }
    #[test]
    fn http_survives_tracker_only_udp_filtering() {
        let s = Scenario {
            tracker_udp_blocked: true,
            ..scenarios()[0]
        };
        assert!(
            Model::new(s, policies()[0], fixed(s), 1)
                .run()
                .check
                .is_none()
        );
        assert!(
            Model::new(s, policies()[5], fixed(s), 1)
                .run()
                .check
                .is_some()
        );
    }
    #[test]
    fn cached_endpoint_can_cancel_all_wan_discovery() {
        let s = Scenario {
            cached_peer: true,
            ..scenarios()[0]
        };
        let r = Model::new(s, policies()[7], fixed(s), 1).run();
        assert_eq!(r.cost.wan_bytes, r.cost.punch_bytes);
        assert_eq!(r.check, Some(40 * MS));
    }
    #[test]
    fn rng_and_outputs_are_reproducible() {
        let s = scenarios()[5];
        let p = policies()[6];
        let e = Environment::generate(s, 42);
        let a = Model::new(s, p, e, 42).run();
        let b = Model::new(s, p, e, 42).run();
        assert_eq!(a.check, b.check);
        assert_eq!(a.cost.wan_bytes, b.cost.wan_bytes);
    }
    #[test]
    fn tracker_retry_respects_fifteen_seconds() {
        assert_eq!(TRACKER_RETRY, 15_000 * MS);
    }
    #[test]
    fn nearest_rank_quantile_keeps_tail() {
        assert_eq!(quantile(&mut [MS, 2 * MS, 3 * MS], 0.95), "3.000");
        assert_eq!(quantile(&mut [], 0.5), "NA");
    }
}
