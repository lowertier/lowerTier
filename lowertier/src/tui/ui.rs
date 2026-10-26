//! Drawing. Every color is paired with text, so the dashboard reads in monochrome.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap},
};

use super::state::{App, Pane, peer_name};
use crate::{
    cli::render::{bytes, clean, loss, nat, rate, rtt},
    proto::api::control::v1::{PeerSnapshot, RouteSnapshot},
};

const ACCENT: Color = Color::Cyan;
/// Below this width the dashboard drops secondary columns and side panels.
const NARROW: u16 = 100;

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

fn panel(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(dim())
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
}

fn selected() -> Style {
    Style::new().fg(Color::Black).bg(ACCENT)
}

fn session_span(peer: &PeerSnapshot) -> Span<'static> {
    match peer.end_to_end_session_ready {
        Some(true) => Span::styled("key-bound", Style::new().fg(Color::Green)),
        Some(false) => Span::styled("unverified", Style::new().fg(Color::Yellow)),
        None => Span::styled("none", dim()),
    }
}

fn via(app: &App, peer: &PeerSnapshot) -> String {
    if !peer.conns.is_empty() {
        return "direct".into();
    }
    let Some(snapshot) = &app.snapshot else {
        return "-".into();
    };
    snapshot
        .status
        .peers
        .route_summaries
        .iter()
        .find(|route| route.route.as_ref().map(|route| route.peer_id) == Some(peer.peer_id))
        .map(|route| name_of(app, route.first_hop_peer_id))
        .unwrap_or_else(|| "unreachable".into())
}

fn name_of(app: &App, id: u32) -> String {
    let Some(snapshot) = &app.snapshot else {
        return id.to_string();
    };
    if snapshot.status.node.node.as_ref().map(|node| node.peer_id) == Some(id) {
        return "this node".into();
    }
    snapshot
        .status
        .peers
        .peers
        .iter()
        .find(|peer| peer.peer_id == id)
        .map(|peer| clean(peer_name(peer)))
        .filter(|name| name != "-")
        .unwrap_or_else(|| id.to_string())
}

fn transport(peer: &PeerSnapshot) -> String {
    let mut kinds = peer
        .conns
        .iter()
        .filter_map(|conn| conn.tunnel.as_ref())
        .map(|tunnel| clean(&tunnel.tunnel_type))
        .collect::<Vec<_>>();
    kinds.sort();
    kinds.dedup();
    if kinds.is_empty() {
        "-".into()
    } else {
        kinds.join("+")
    }
}

fn right(text: String) -> Cell<'static> {
    Cell::from(Line::from(text).alignment(Alignment::Right))
}

fn header(frame: &mut Frame, app: &App, area: Rect) {
    let mut left = vec![Span::styled("lowertier", Style::new().fg(ACCENT).bold())];
    if let Some(snapshot) = &app.snapshot {
        let node = snapshot.status.node.node.clone().unwrap_or_default();
        let peers = &snapshot.status.peers.peers;
        let direct = peers.iter().filter(|peer| !peer.conns.is_empty()).count();
        left.push(Span::raw(format!(
            "  {} · {} · peer {} · {} {}, {direct} direct",
            clean(&node.hostname),
            if node.ipv4_addr.is_empty() {
                "no address".into()
            } else {
                clean(&node.ipv4_addr)
            },
            node.peer_id,
            peers.len(),
            if peers.len() == 1 { "peer" } else { "peers" },
        )));
    }
    let status = match (&app.error, app.updated) {
        (Some(_), _) => Span::styled("disconnected · retrying", Style::new().fg(Color::Red)),
        (None, Some(updated)) => Span::styled(
            format!("updated {:.1}s ago", updated.elapsed().as_secs_f32()),
            dim(),
        ),
        (None, None) => Span::styled("connecting…", dim()),
    };
    // The status keeps its own column so long host names never overlap it.
    let width = (status.width() as u16).min(area.width / 2);
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(width + 1)]).areas(area);
    frame.render_widget(Paragraph::new(Line::from(left)), left_area);
    frame.render_widget(
        Paragraph::new(Line::from(status)).alignment(Alignment::Right),
        right_area,
    );
}

fn tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles = Pane::ALL
        .iter()
        .enumerate()
        .map(|(index, pane)| format!("{} {}", index + 1, pane.title()));
    frame.render_widget(
        Tabs::new(titles)
            .select(Pane::ALL.iter().position(|pane| *pane == app.pane()))
            .style(dim())
            .highlight_style(
                Style::new()
                    .fg(ACCENT)
                    .bold()
                    .add_modifier(Modifier::UNDERLINED),
            )
            .divider(" ")
            .padding("", "  "),
        area,
    );
}

fn footer(frame: &mut Frame, app: &App, area: Rect) {
    let line = if app.editing_filter {
        Line::from(vec![
            Span::styled("filter ", Style::new().fg(ACCENT)),
            Span::raw(format!("{}▏", app.filter)),
            Span::styled("   enter keep · esc clear", dim()),
        ])
    } else if let Some(error) = &app.error {
        Line::from(Span::styled(clean(error), Style::new().fg(Color::Red)))
    } else {
        let mut spans = vec![Span::styled(
            "tab/1-5 pane · j/k move · enter detail · / filter · q quit",
            dim(),
        )];
        if !app.filter.is_empty() {
            spans.push(Span::styled(
                format!("   filter: {}", app.filter),
                Style::new().fg(ACCENT),
            ));
        }
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn key_values(rows: Vec<(&str, Line<'static>)>) -> Vec<Line<'static>> {
    let width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    rows.into_iter()
        .map(|(key, value)| {
            let mut spans = vec![Span::styled(format!("{key:width$}  "), dim())];
            spans.extend(value.spans);
            Line::from(spans)
        })
        .collect()
}

fn overview(frame: &mut Frame, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        frame.render_widget(Paragraph::new("Waiting for the daemon…").style(dim()), area);
        return;
    };
    let status = &snapshot.status;
    let node = status.node.node.clone().unwrap_or_default();
    let stun = node.stun_info.clone().unwrap_or_default();
    let mut rows = vec![
        ("host", Line::from(clean(&node.hostname))),
        (
            "address",
            Line::from(if node.ipv4_addr.is_empty() {
                "none".into()
            } else {
                clean(&node.ipv4_addr)
            }),
        ),
        ("peer id", Line::from(node.peer_id.to_string())),
        ("version", Line::from(clean(&node.version))),
        ("portal", Line::from(clean(&status.portal))),
        ("udp nat", Line::from(nat(stun.udp_nat_type))),
        ("tcp nat", Line::from(nat(stun.tcp_nat_type))),
        (
            "public ip",
            Line::from(if stun.public_ip.is_empty() {
                "unknown".into()
            } else {
                clean(&stun.public_ip.join(", "))
            }),
        ),
    ];
    for listener in &status.listeners.listeners {
        rows.push(("listen", Line::from(clean(&listener.uri))));
    }
    if status.listeners.listeners.is_empty() {
        rows.push((
            "listen",
            Line::styled("none: peers cannot dial in", Style::new().fg(Color::Yellow)),
        ));
    }
    for tracker in &status.discovery.trackers {
        rows.push((
            "tracker",
            if tracker.last_error.is_empty() {
                Line::from(vec![
                    Span::styled("ok   ", Style::new().fg(Color::Green)),
                    Span::raw(clean(&tracker.uri)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("fail ", Style::new().fg(Color::Red)),
                    Span::raw(format!(
                        "{} ({})",
                        clean(&tracker.uri),
                        clean(&tracker.last_error)
                    )),
                ])
            },
        ));
    }
    let node_panel = Paragraph::new(key_values(rows))
        .block(panel("Node"))
        .wrap(Wrap { trim: false });

    let relay = status.relay.config.clone().unwrap_or_default();
    let drops: u64 = status
        .relay
        .counters
        .iter()
        .filter(|counter| counter.name == "relay_drops")
        .map(|counter| counter.value)
        .sum();
    let relay_panel = Paragraph::new(key_values(vec![
        ("policy", Line::from(relay.policy().as_str_name())),
        ("transit", Line::from(relay.transit().as_str_name())),
        ("relayed", Line::from(bytes(status.relay.total_bytes))),
        (
            "drops",
            if drops == 0 {
                Line::from("0")
            } else {
                Line::styled(drops.to_string(), Style::new().fg(Color::Yellow))
            },
        ),
    ]))
    .block(panel("Relay"));

    if area.width < NARROW {
        let [top, bottom] =
            Layout::vertical([Constraint::Min(6), Constraint::Length(6)]).areas(area);
        frame.render_widget(node_panel, top);
        frame.render_widget(relay_panel, bottom);
        return;
    }
    let [left, right_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    frame.render_widget(node_panel, left);
    let [peers_area, relay_area] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(6)]).areas(right_area);
    let mut peers = app.visible_peers();
    peers.sort_by_key(|peer| std::cmp::Reverse(peer.delivery_bps.unwrap_or(0)));
    let rows = peers
        .iter()
        .map(|peer| {
            Row::new(vec![
                Cell::from(clean(peer_name(peer))),
                Cell::from(via(app, peer)),
                right(rtt(peer.rtt_us)),
                right(rate(peer.delivery_bps)),
            ])
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Length(12),
        ],
    )
    .header(Row::new(["PEER", "VIA", "     RTT", "        RATE"]).style(dim()))
    .block(panel("Busiest peers"));
    frame.render_widget(table, peers_area);
    frame.render_widget(relay_panel, relay_area);
}

fn spark<'a>(title: String, data: &'a [u64]) -> Sparkline<'a> {
    // Headroom above the peak keeps a steady value from reading as saturated.
    let peak = data.iter().copied().max().unwrap_or(0);
    Sparkline::default()
        .block(panel_owned(title))
        .data(data)
        .max(peak.saturating_add(peak / 3).max(1))
        .style(Style::new().fg(ACCENT))
}

fn panel_owned(title: String) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(dim())
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
}

fn peers(frame: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible_peers();
    let narrow = area.width < NARROW;
    let [list, bottom] = Layout::vertical([Constraint::Min(4), Constraint::Length(8)]).areas(area);
    let rows = visible
        .iter()
        .map(|peer| {
            let mut cells = vec![
                Cell::from(clean(peer_name(peer))),
                Cell::from(
                    peer.route
                        .as_ref()
                        .and_then(|route| route.ipv4_addr.as_ref())
                        .map_or_else(|| "-".into(), |address| address.to_string()),
                ),
                Cell::from(via(app, peer)),
            ];
            if !narrow {
                cells.push(Cell::from(transport(peer)));
            }
            cells.extend([
                right(rtt(peer.rtt_us)),
                right(loss(peer.loss_ppm)),
                right(rate(peer.delivery_bps)),
            ]);
            if !narrow {
                cells.push(Cell::from(session_span(peer)));
            }
            Row::new(cells)
        })
        .collect::<Vec<_>>();
    let (headers, widths): (Vec<&str>, Vec<Constraint>) = if narrow {
        (
            vec![
                "PEER",
                "ADDRESS",
                "VIA",
                "     RTT",
                "   LOSS",
                "        RATE",
            ],
            vec![
                Constraint::Fill(2),
                Constraint::Length(16),
                Constraint::Fill(1),
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(12),
            ],
        )
    } else {
        (
            vec![
                "PEER",
                "ADDRESS",
                "VIA",
                "TRANSPORT",
                "     RTT",
                "   LOSS",
                "        RATE",
                "SESSION",
            ],
            vec![
                Constraint::Fill(2),
                Constraint::Length(16),
                Constraint::Fill(1),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(12),
                Constraint::Length(10),
            ],
        )
    };
    let title = format!("Peers ({})", visible.len());
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(dim()))
        .block(panel_owned(title))
        .row_highlight_style(selected());
    let mut state =
        TableState::default().with_selected((!visible.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, list, &mut state);

    let Some(peer) = visible.get(app.selected) else {
        frame.render_widget(
            Paragraph::new("No peers.")
                .style(dim())
                .block(panel("Detail")),
            bottom,
        );
        return;
    };
    if app.detail {
        use base64::Engine as _;
        let lines = key_values(vec![
            (
                "public key",
                Line::from(base64::engine::general_purpose::STANDARD.encode(&peer.peer_key)),
            ),
            ("peer id", Line::from(peer.peer_id.to_string())),
            (
                "nat",
                Line::from(format!(
                    "udp {}, tcp {}",
                    nat(peer.udp_nat),
                    nat(peer.tcp_nat)
                )),
            ),
            ("session", Line::from(session_span(peer))),
            (
                "connections",
                Line::from(
                    peer.conns
                        .iter()
                        .filter_map(|conn| conn.tunnel.as_ref())
                        .map(|tunnel| {
                            format!(
                                "{} {}",
                                clean(&tunnel.tunnel_type),
                                tunnel
                                    .remote_addr
                                    .as_ref()
                                    .map_or_else(String::new, |url| clean(&url.to_string()))
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ),
            (
                "sample age",
                Line::from(
                    peer.sample_age_ms
                        .map_or("-".into(), |age| format!("{age} ms")),
                ),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_owned(format!(
                    "{} · detail (esc closes)",
                    clean(peer_name(peer))
                )))
                .wrap(Wrap { trim: true }),
            bottom,
        );
        return;
    }
    let history = app.history.get(&peer.peer_id);
    let rtt_data = history
        .map(|history| history.rtt_us.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    let rate_data = history
        .map(|history| history.rate_bps.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    let [left, right_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(bottom);
    let range = |data: &[u64], format: fn(Option<u64>) -> String| match (
        data.iter().filter(|value| **value > 0).min(),
        data.iter().max(),
    ) {
        (Some(min), Some(max)) => format!("{} – {}", format(Some(*min)), format(Some(*max))),
        _ => "no samples".into(),
    };
    let name = clean(peer_name(peer));
    // Show the most recent samples that fit the panel.
    let fit = |data: &[u64], area: Rect| {
        let width = area.width.saturating_sub(2) as usize;
        data[data.len().saturating_sub(width)..].to_vec()
    };
    let rtt_fit = fit(&rtt_data, left);
    let rate_fit = fit(&rate_data, right_area);
    frame.render_widget(
        spark(
            format!(
                "{name} RTT {} ({})",
                rtt(peer.rtt_us),
                range(&rtt_data, rtt)
            ),
            &rtt_fit,
        ),
        left,
    );
    frame.render_widget(
        spark(
            format!(
                "rate {} ({})",
                rate(peer.delivery_bps),
                range(&rate_data, rate)
            ),
            &rate_fit,
        ),
        right_area,
    );
}

fn route_rows(app: &App, routes: &[&RouteSnapshot]) -> Vec<Row<'static>> {
    routes
        .iter()
        .map(|route| {
            let via = match route.first_hop_peer_id {
                0 => "-".into(),
                hop if hop == route.final_gateway_peer_id => "direct".into(),
                hop => name_of(app, hop),
            };
            let fallback = if route.fallback_reason.is_empty() {
                Span::raw("")
            } else {
                Span::styled(
                    clean(&route.fallback_reason),
                    Style::new().fg(Color::Yellow),
                )
            };
            // Peer routes use the peer ID as destination; show who it is instead.
            let destination = match &route.route {
                Some(info) if route.destination == info.peer_id.to_string() => {
                    let address = info
                        .ipv4_addr
                        .as_ref()
                        .map_or_else(String::new, |address| format!(" {address}"));
                    format!("{}{address}", name_of(app, info.peer_id))
                }
                _ => clean(&route.destination),
            };
            Row::new(vec![
                Cell::from(destination),
                Cell::from(via),
                Cell::from(clean(&route.effective_policy)),
                right(
                    route
                        .cost_ms
                        .map_or("-".into(), |cost| format!("{cost} ms")),
                ),
                right(rtt(route.measured_rtt_us)),
                right(rate(route.delivery_bps)),
                Cell::from(fallback),
            ])
        })
        .collect()
}

fn route_table<'a>(rows: Vec<Row<'a>>, title: String) -> Table<'a> {
    Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new([
            "DESTINATION",
            "VIA",
            "POLICY",
            "    COST",
            "     RTT",
            "        RATE",
            "FALLBACK",
        ])
        .style(dim()),
    )
    .block(panel_owned(title))
    .row_highlight_style(selected())
}

fn routes(frame: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible_routes();
    let [list, bottom] = Layout::vertical([Constraint::Min(4), Constraint::Length(4)]).areas(area);
    let table = route_table(
        route_rows(app, &visible),
        format!("Routes ({})", visible.len()),
    );
    let mut state =
        TableState::default().with_selected((!visible.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, list, &mut state);
    let path = visible.get(app.selected).map_or_else(String::new, |route| {
        let hops = route
            .path_peer_ids
            .iter()
            .map(|id| name_of(app, *id))
            .collect::<Vec<_>>()
            .join(" › ");
        if route.path_error.is_empty() {
            hops
        } else {
            format!("{hops}  ({})", clean(&route.path_error))
        }
    });
    frame.render_widget(
        Paragraph::new(path)
            .block(panel("Path"))
            .wrap(Wrap { trim: true }),
        bottom,
    );
}

fn relay(frame: &mut Frame, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        return;
    };
    let relay = &snapshot.status.relay;
    let config = relay.config.clone().unwrap_or_default();
    let mut drops = std::collections::BTreeMap::<String, u64>::new();
    for counter in &relay.counters {
        if counter.name == "relay_drops" {
            let reason = counter
                .labels
                .get("error_type")
                .cloned()
                .unwrap_or_default();
            *drops.entry(reason).or_default() += counter.value;
        }
    }
    let lines = key_values(vec![
        ("policy", Line::from(config.policy().as_str_name())),
        (
            "transit",
            Line::from(format!(
                "{} (advertised {})",
                config.transit().as_str_name(),
                clean(&relay.advertised_permission)
            )),
        ),
        (
            "networks",
            Line::from(if config.transit_networks.is_empty() {
                "none (foreign transit denied)".into()
            } else {
                clean(&config.transit_networks.join(", "))
            }),
        ),
        (
            "limit",
            Line::from(
                config
                    .transit_bps_limit
                    .map_or("unlimited".into(), |limit| rate(Some(limit))),
            ),
        ),
        ("relayed", Line::from(bytes(relay.total_bytes))),
        (
            "drops",
            Line::from(
                drops
                    .iter()
                    .map(|(reason, count)| format!("{reason} {count}"))
                    .collect::<Vec<_>>()
                    .join(" · "),
            ),
        ),
    ]);
    let [top, list] = Layout::vertical([Constraint::Length(8), Constraint::Min(4)]).areas(area);
    frame.render_widget(Paragraph::new(lines).block(panel("Relay")), top);
    let paths = relay.paths.iter().collect::<Vec<_>>();
    let table = route_table(
        route_rows(app, &paths),
        format!("Peer paths ({})", paths.len()),
    );
    let mut state =
        TableState::default().with_selected((!paths.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, list, &mut state);
}

fn logs(frame: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible_logs();
    let height = area.height.saturating_sub(2) as usize;
    let end = visible.len().saturating_sub(app.log_scroll);
    let start = end.saturating_sub(height);
    let lines = visible[start..end]
        .iter()
        .map(|entry| {
            let level = entry.level.to_uppercase();
            let style = match level.as_str() {
                "ERROR" => Style::new().fg(Color::Red),
                "WARN" => Style::new().fg(Color::Yellow),
                "DEBUG" | "TRACE" => dim(),
                _ => Style::new(),
            };
            let time = chrono::DateTime::from_timestamp_millis(entry.sampled_at_unix_ms)
                .map(|time| {
                    time.with_timezone(&chrono::Local)
                        .format("%H:%M:%S")
                        .to_string()
                })
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(format!("{time} "), dim()),
                Span::styled(format!("{level:5} "), style),
                Span::styled(format!("{} ", clean(&entry.target)), dim()),
                Span::styled(
                    clean(
                        entry
                            .message
                            .strip_prefix("message=")
                            .unwrap_or(&entry.message),
                    ),
                    style,
                ),
            ])
        })
        .collect::<Vec<_>>();
    let title = if app.log_scroll == 0 {
        format!("Logs ({}) · following", visible.len())
    } else {
        format!(
            "Logs ({}) · {} lines back, G follows",
            visible.len(),
            app.log_scroll
        )
    };
    frame.render_widget(Paragraph::new(lines).block(panel_owned(title)), area);
}

pub fn draw(frame: &mut Frame, app: &App) {
    let [header_area, tabs_area, body, footer_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    header(frame, app, header_area);
    tabs(frame, app, tabs_area);
    match app.pane() {
        Pane::Overview => overview(frame, app, body),
        Pane::Peers => peers(frame, app, body),
        Pane::Routes => routes(frame, app, body),
        Pane::Relay => relay(frame, app, body),
        Pane::Logs => logs(frame, app, body),
    }
    footer(frame, app, footer_area);
}
