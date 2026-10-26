//! Dashboard state. `reduce` is pure so key handling and history bounds are testable.

use std::collections::{HashMap, VecDeque};

use crate::{
    cli::commands::status::StatusView,
    proto::api::control::v1::{LogEntry, PeerSnapshot, RouteSnapshot},
};

/// Samples kept per peer for sparklines.
pub const HISTORY: usize = 120;
/// Log lines kept in memory.
pub const LOG_LINES: usize = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Overview,
    Peers,
    Routes,
    Relay,
    Logs,
}

impl Pane {
    pub const ALL: [Pane; 5] = [
        Pane::Overview,
        Pane::Peers,
        Pane::Routes,
        Pane::Relay,
        Pane::Logs,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Pane::Overview => "Overview",
            Pane::Peers => "Peers",
            Pane::Routes => "Routes",
            Pane::Relay => "Relay",
            Pane::Logs => "Logs",
        }
    }

    fn index(self) -> usize {
        Pane::ALL.iter().position(|pane| *pane == self).unwrap()
    }
}

pub struct Snapshot {
    pub status: StatusView,
    pub routes: Vec<RouteSnapshot>,
}

#[derive(Default)]
pub struct History {
    pub rtt_us: VecDeque<u64>,
    pub rate_bps: VecDeque<u64>,
}

fn push(ring: &mut VecDeque<u64>, value: u64) {
    if ring.len() == HISTORY {
        ring.pop_front();
    }
    ring.push_back(value);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Up,
    Down,
    Home,
    End,
    Tab,
    BackTab,
    Enter,
    Esc,
    Backspace,
    Interrupt,
}

pub enum Event {
    Snapshot(Box<Snapshot>),
    Logs(Vec<LogEntry>),
    Failed(String),
    Key(Key),
}

#[derive(Default)]
pub struct App {
    pub pane: Option<Pane>,
    pub selected: usize,
    pub filter: String,
    pub editing_filter: bool,
    pub detail: bool,
    pub snapshot: Option<Snapshot>,
    pub history: HashMap<u32, History>,
    pub logs: VecDeque<LogEntry>,
    /// Lines scrolled back from the newest log line.
    pub log_scroll: usize,
    pub error: Option<String>,
    pub updated: Option<std::time::Instant>,
    pub quit: bool,
}

fn contains(text: &str, filter: &str) -> bool {
    text.to_lowercase().contains(filter)
}

pub fn peer_name(peer: &PeerSnapshot) -> &str {
    peer.route
        .as_ref()
        .map(|route| route.hostname.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("-")
}

impl App {
    pub fn pane(&self) -> Pane {
        self.pane.unwrap_or(Pane::Overview)
    }

    pub fn visible_peers(&self) -> Vec<&PeerSnapshot> {
        let filter = self.filter.to_lowercase();
        let mut peers = self
            .snapshot
            .iter()
            .flat_map(|snapshot| &snapshot.status.peers.peers)
            .filter(|peer| {
                filter.is_empty()
                    || contains(peer_name(peer), &filter)
                    || contains(&peer.peer_id.to_string(), &filter)
                    || peer
                        .route
                        .as_ref()
                        .and_then(|route| route.ipv4_addr.as_ref())
                        .is_some_and(|address| contains(&address.to_string(), &filter))
            })
            .collect::<Vec<_>>();
        peers.sort_by(|a, b| {
            peer_name(a)
                .cmp(peer_name(b))
                .then(a.peer_id.cmp(&b.peer_id))
        });
        peers
    }

    pub fn visible_routes(&self) -> Vec<&RouteSnapshot> {
        let filter = self.filter.to_lowercase();
        self.snapshot
            .iter()
            .flat_map(|snapshot| &snapshot.routes)
            .filter(|route| {
                filter.is_empty()
                    || contains(&route.destination, &filter)
                    || route
                        .route
                        .as_ref()
                        .is_some_and(|info| contains(&info.hostname, &filter))
            })
            .collect()
    }

    pub fn visible_logs(&self) -> Vec<&LogEntry> {
        let filter = self.filter.to_lowercase();
        self.logs
            .iter()
            .filter(|entry| {
                filter.is_empty()
                    || contains(&entry.message, &filter)
                    || contains(&entry.target, &filter)
                    || contains(&entry.level, &filter)
            })
            .collect()
    }

    fn rows(&self) -> usize {
        match self.pane() {
            Pane::Peers | Pane::Overview => self.visible_peers().len(),
            Pane::Routes => self.visible_routes().len(),
            Pane::Relay => self
                .snapshot
                .as_ref()
                .map_or(0, |snapshot| snapshot.status.relay.paths.len()),
            Pane::Logs => self.visible_logs().len(),
        }
    }

    fn clamp(&mut self) {
        let rows = self.rows();
        self.selected = self.selected.min(rows.saturating_sub(1));
        self.log_scroll = self
            .log_scroll
            .min(self.visible_logs().len().saturating_sub(1));
    }

    fn set_pane(&mut self, pane: Pane) {
        if self.pane() != pane {
            self.pane = Some(pane);
            self.selected = 0;
            self.detail = false;
        }
    }

    fn move_by(&mut self, delta: isize) {
        if self.pane() == Pane::Logs {
            // Up scrolls back in time.
            self.log_scroll = self.log_scroll.saturating_add_signed(-delta);
        } else {
            self.selected = self.selected.saturating_add_signed(delta);
        }
        self.clamp();
    }

    fn key(&mut self, key: Key) {
        if key == Key::Interrupt {
            self.quit = true;
            return;
        }
        if self.editing_filter {
            match key {
                Key::Char(character) => self.filter.push(character),
                Key::Backspace => {
                    self.filter.pop();
                }
                Key::Enter => self.editing_filter = false,
                Key::Esc => {
                    self.filter.clear();
                    self.editing_filter = false;
                }
                _ => {}
            }
            self.selected = 0;
            self.clamp();
            return;
        }
        match key {
            Key::Char('q') => self.quit = true,
            Key::Char(digit @ '1'..='5') => {
                self.set_pane(Pane::ALL[digit as usize - '1' as usize]);
            }
            Key::Tab => self.set_pane(Pane::ALL[(self.pane().index() + 1) % Pane::ALL.len()]),
            Key::BackTab => self
                .set_pane(Pane::ALL[(self.pane().index() + Pane::ALL.len() - 1) % Pane::ALL.len()]),
            Key::Char('j') | Key::Down => self.move_by(1),
            Key::Char('k') | Key::Up => self.move_by(-1),
            Key::Char('g') | Key::Home => self.move_by(isize::MIN / 2),
            Key::Char('G') | Key::End => self.move_by(isize::MAX / 2),
            Key::Enter => self.detail = !self.detail,
            Key::Esc => {
                if self.detail {
                    self.detail = false;
                } else {
                    self.filter.clear();
                }
            }
            Key::Char('/') => self.editing_filter = true,
            _ => {}
        }
    }

    fn snapshot(&mut self, snapshot: Snapshot) {
        for peer in &snapshot.status.peers.peers {
            let history = self.history.entry(peer.peer_id).or_default();
            push(&mut history.rtt_us, peer.rtt_us.unwrap_or(0));
            push(&mut history.rate_bps, peer.delivery_bps.unwrap_or(0));
        }
        self.history.retain(|id, _| {
            snapshot
                .status
                .peers
                .peers
                .iter()
                .any(|peer| peer.peer_id == *id)
        });
        self.snapshot = Some(snapshot);
        self.error = None;
        self.updated = Some(std::time::Instant::now());
    }
}

pub fn reduce(app: &mut App, event: Event) {
    match event {
        Event::Snapshot(snapshot) => app.snapshot(*snapshot),
        Event::Logs(entries) => {
            for entry in entries {
                if app.logs.len() == LOG_LINES {
                    app.logs.pop_front();
                }
                app.logs.push_back(entry);
            }
        }
        Event::Failed(error) => app.error = Some(error),
        Event::Key(key) => app.key(key),
    }
    app.clamp();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::client::PeerView,
        proto::api::{control::v1::*, instance::Route},
    };

    fn peer(id: u32, name: &str) -> PeerSnapshot {
        PeerSnapshot {
            peer_id: id,
            rtt_us: Some(u64::from(id) * 1000),
            route: Some(Route {
                hostname: name.into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn snapshot(peers: Vec<PeerSnapshot>) -> Event {
        Event::Snapshot(Box::new(Snapshot {
            status: StatusView {
                daemon: None,
                portal: String::new(),
                node: GetNodeResponse::default(),
                peers: PeerView {
                    snapshot: None,
                    peers,
                    route_summaries: Vec::new(),
                    active_policy: String::new(),
                    next_page_token: String::new(),
                    detail: false,
                },
                relay: GetRelayResponse::default(),
                discovery: GetDiscoveryResponse::default(),
                listeners: ListListenersResponse::default(),
            },
            routes: Vec::new(),
        }))
    }

    #[test]
    fn panes_selection_and_filter() {
        let mut app = App::default();
        reduce(
            &mut app,
            snapshot(vec![peer(1, "a"), peer(2, "b"), peer(3, "c")]),
        );
        reduce(&mut app, Event::Key(Key::Char('2')));
        assert_eq!(app.pane(), Pane::Peers);
        reduce(&mut app, Event::Key(Key::End));
        assert_eq!(app.selected, 2);
        // The selection stays inside the list when peers disappear.
        reduce(&mut app, snapshot(vec![peer(1, "a")]));
        assert_eq!(app.selected, 0);
        assert_eq!(app.history.len(), 1, "history of gone peers is dropped");
        reduce(&mut app, snapshot(vec![peer(1, "alpha"), peer(2, "beta")]));
        for key in [Key::Char('/'), Key::Char('b'), Key::Char('e'), Key::Enter] {
            reduce(&mut app, Event::Key(key));
        }
        assert!(!app.editing_filter);
        assert_eq!(app.visible_peers().len(), 1);
        reduce(&mut app, Event::Key(Key::Esc));
        assert_eq!(app.visible_peers().len(), 2);
        reduce(&mut app, Event::Key(Key::BackTab));
        assert_eq!(app.pane(), Pane::Overview);
        reduce(&mut app, Event::Key(Key::Char('q')));
        assert!(app.quit);
    }

    #[test]
    fn history_and_logs_are_bounded() {
        let mut app = App::default();
        for _ in 0..HISTORY + 10 {
            reduce(&mut app, snapshot(vec![peer(1, "a")]));
        }
        assert_eq!(app.history[&1].rtt_us.len(), HISTORY);
        reduce(
            &mut app,
            Event::Logs(vec![LogEntry::default(); LOG_LINES + 5]),
        );
        assert_eq!(app.logs.len(), LOG_LINES);
        reduce(&mut app, Event::Failed("gone".into()));
        assert_eq!(app.error.as_deref(), Some("gone"));
        reduce(&mut app, snapshot(vec![]));
        assert!(app.error.is_none());
    }
}
