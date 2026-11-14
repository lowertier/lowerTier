use super::{
    args::{Arguments, Output},
    client::{PeerView, Response},
    commands::{config::ConfigView, doctor, route::Trace, status::StatusView},
    error::CliError,
};
use crate::proto::{api::control::v1::*, common::NatType};
use clap::CommandFactory;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fmt::Write as _,
    io::{self, Write},
};
use tabled::{
    builder::Builder,
    settings::{Alignment, Modify, Padding, Style, object::Columns},
};

#[derive(Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    pub request_id: String,
    pub instance_id: Option<String>,
    pub revision: Option<String>,
    pub data: Option<Value>,
    pub error: Option<ApiError>,
}

impl Envelope {
    pub fn success(
        request_id: &str,
        instance_id: &str,
        response: &Response,
    ) -> serde_json::Result<Self> {
        let mut data = serde_json::to_value(response)?;
        if let Some(object) = data.as_object_mut() {
            object.remove("error");
        }
        let revision = data
            .pointer("/snapshot/revision")
            .or_else(|| data.pointer("/result/revision"))
            .or_else(|| data.pointer("/revision"))
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            });
        let instance_id = data
            .get("instance_id")
            .and_then(Value::as_str)
            .unwrap_or(instance_id);
        Ok(Self {
            schema_version: 1,
            request_id: request_id.into(),
            instance_id: (!instance_id.is_empty()).then(|| instance_id.into()),
            revision,
            data: Some(data),
            error: None,
        })
    }
    pub fn failure(request_id: &str, instance_id: &str, error: &CliError) -> Self {
        Self {
            schema_version: 1,
            request_id: request_id.into(),
            instance_id: (!instance_id.is_empty()).then(|| instance_id.into()),
            revision: None,
            data: None,
            error: Some(error.0.clone()),
        }
    }
}

/// Escape control characters in remote text to protect terminal state.
pub fn clean(text: &str) -> String {
    text.chars()
        .flat_map(|character| character.escape_debug())
        .collect::<String>()
        .replace("\\'", "'")
        .replace("\\\"", "\"")
}

fn cell(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(value) => clean(value),
        _ => clean(&value.to_string()),
    }
}

fn field(value: &Value, key: &str) -> String {
    cell(value.get(key).unwrap_or(&Value::Null))
}

pub fn rtt(us: Option<u64>) -> String {
    match us {
        Some(us) if us < 10_000 => format!("{:.1} ms", us as f64 / 1000.0),
        Some(us) => format!("{} ms", us / 1000),
        None => "-".into(),
    }
}

pub fn loss(ppm: Option<u32>) -> String {
    ppm.map_or_else(
        || "-".into(),
        |ppm| format!("{:.1} %", f64::from(ppm) / 10_000.0),
    )
}

pub fn rate(bps: Option<u64>) -> String {
    let Some(bps) = bps else {
        return "-".into();
    };
    let bps = bps as f64;
    for (scale, unit) in [(1e9, "Gbit/s"), (1e6, "Mbit/s"), (1e3, "kbit/s")] {
        if bps >= scale {
            return format!("{:.1} {unit}", bps / scale);
        }
    }
    format!("{bps:.0} bit/s")
}

pub fn bytes(value: u64) -> String {
    let value = value as f64;
    for (scale, unit) in [
        (1u64 << 40, "TiB"),
        (1 << 30, "GiB"),
        (1 << 20, "MiB"),
        (1 << 10, "KiB"),
    ] {
        if value >= scale as f64 {
            return format!("{:.1} {unit}", value / scale as f64);
        }
    }
    format!("{value:.0} B")
}

pub fn nat(value: i32) -> &'static str {
    match NatType::try_from(value).unwrap_or(NatType::Unknown) {
        NatType::Unknown => "unknown",
        NatType::OpenInternet => "open",
        NatType::NoPat => "no PAT",
        NatType::FullCone => "full cone",
        NatType::Restricted => "restricted",
        NatType::PortRestricted => "port restricted",
        NatType::Symmetric => "symmetric",
        NatType::SymUdpFirewall => "symmetric firewall",
        NatType::SymmetricEasyInc => "symmetric (incrementing)",
        NatType::SymmetricEasyDec => "symmetric (decrementing)",
    }
}

/// A borderless table with right-aligned numeric columns.
fn table(headers: &[&str], rows: Vec<Vec<String>>, numeric: &[usize]) -> String {
    let mut builder = Builder::default();
    builder.push_record(headers.iter().map(|header| header.to_uppercase()));
    for row in rows {
        builder.push_record(row);
    }
    let mut table = builder.build();
    table
        .with(Style::blank())
        .with(Modify::new(Columns::first()).with(Padding::new(0, 1, 0, 0)));
    for column in numeric {
        table.with(Modify::new(Columns::single(*column)).with(Alignment::right()));
    }
    format!("{table}\n")
}

fn flatten(value: &Value, prefix: &str, rows: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                flatten(
                    value,
                    &if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    },
                    rows,
                );
            }
        }
        Value::Array(array) if !array.is_empty() => {
            for (index, value) in array.iter().enumerate() {
                flatten(value, &format!("{prefix}[{index}]"), rows);
            }
        }
        _ => rows.push(vec![prefix.into(), cell(value)]),
    }
}

fn fields(value: &Value) -> String {
    let mut rows = Vec::new();
    flatten(value, "", &mut rows);
    if rows.is_empty() {
        return "ok\n".into();
    }
    let width = rows.iter().map(|row| row[0].len()).max().unwrap_or(0);
    rows.iter()
        .map(|row| format!("{:width$}  {}\n", row[0], row[1]))
        .collect()
}

fn rows(data: &Value, key: &str) -> Vec<Value> {
    data.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn metrics(data: &Value, key: &str) -> String {
    let entries = rows(data, key)
        .iter()
        .map(|metric| {
            let name = metric.get("name").and_then(Value::as_str).unwrap_or("");
            let value = metric.get("value").and_then(|value| {
                value
                    .as_str()
                    .and_then(|text| text.parse::<u64>().ok())
                    .or(value.as_u64())
            });
            let shown = match value {
                Some(value) if name.contains("bytes") => bytes(value),
                Some(value) if name.ends_with("bps") => rate(Some(value)),
                Some(value) if name.ends_with("_us") => rtt(Some(value)),
                Some(value) => value.to_string(),
                None => "-".into(),
            };
            let labels = metric
                .get("labels")
                .and_then(Value::as_object)
                .map(|labels| {
                    labels
                        .iter()
                        .map(|(key, value)| format!("{key}={}", cell(value)))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            vec![clean(name), shown, labels]
        })
        .collect();
    table(&["Metric", "Value", "Labels"], entries, &[1])
}

fn peer_name(peer: &PeerSnapshot) -> String {
    peer.route
        .as_ref()
        .map(|route| clean(&route.hostname))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "-".into())
}

fn peer_address(peer: &PeerSnapshot) -> String {
    peer.route
        .as_ref()
        .and_then(|route| route.ipv4_addr.as_ref())
        .map_or_else(|| "-".into(), |address| address.to_string())
}

fn peer_via(peer: &PeerSnapshot, view: &PeerView) -> String {
    if !peer.conns.is_empty() {
        return "direct".into();
    }
    view.route_summaries
        .iter()
        .find(|route| route.route.as_ref().map(|route| route.peer_id) == Some(peer.peer_id))
        .map(|route| {
            let hop = route.first_hop_peer_id;
            view.peers
                .iter()
                .find(|other| other.peer_id == hop)
                .map(peer_name)
                .filter(|name| name != "-")
                .unwrap_or_else(|| hop.to_string())
        })
        .unwrap_or_else(|| "unreachable".into())
}

fn peer_transport(peer: &PeerSnapshot) -> String {
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

fn session(peer: &PeerSnapshot) -> &'static str {
    match peer.end_to_end_session_ready {
        Some(true) => "key-bound",
        Some(false) => "unverified",
        None => "none",
    }
}

fn peers_table(view: &PeerView) -> String {
    let rows = view
        .peers
        .iter()
        .map(|peer| {
            vec![
                peer_name(peer),
                peer_address(peer),
                peer_via(peer, view),
                peer_transport(peer),
                rtt(peer.rtt_us),
                loss(peer.loss_ppm),
                rate(peer.delivery_bps),
                session(peer).into(),
                peer.peer_id.to_string(),
            ]
        })
        .collect();
    table(
        &[
            "Peer",
            "Address",
            "Via",
            "Transport",
            "RTT",
            "Loss",
            "Rate",
            "Session",
            "ID",
        ],
        rows,
        &[4, 5, 6, 8],
    )
}

fn peer_detail(peer: &PeerSnapshot, view: &PeerView) -> String {
    use base64::Engine as _;
    let auth = |level: Option<i32>| {
        level
            .and_then(|level| crate::proto::peer_rpc::SecureAuthLevel::try_from(level).ok())
            .map_or("none".into(), |level| match level {
                crate::proto::peer_rpc::SecureAuthLevel::EncryptedUnauthenticated => {
                    "not locally attested".to_owned()
                }
                level => level.as_str_name().to_owned(),
            })
    };
    let lines = [
        ("peer", format!("{} (id {})", peer_name(peer), peer.peer_id)),
        (
            "public key",
            base64::engine::general_purpose::STANDARD.encode(&peer.peer_key),
        ),
        ("address", peer_address(peer)),
        ("via", peer_via(peer, view)),
        ("transport", peer_transport(peer)),
        ("rtt", rtt(peer.rtt_us)),
        ("loss", loss(peer.loss_ppm)),
        ("rate", rate(peer.delivery_bps)),
        (
            "nat",
            format!("udp {}, tcp {}", nat(peer.udp_nat), nat(peer.tcp_nat)),
        ),
        ("session", session(peer).into()),
        ("direct auth", auth(peer.direct_link_auth)),
        ("routing trust", auth(peer.routing_authority_auth)),
        (
            "sample age",
            peer.sample_age_ms
                .map_or("-".into(), |age| format!("{age} ms")),
        ),
    ];
    lines
        .iter()
        .map(|(key, value)| format!("{key:13}  {value}\n"))
        .collect()
}

fn routes(routes: &[RouteSnapshot], with_path: bool) -> String {
    let rows = routes
        .iter()
        .map(|route| {
            let info = route.route.as_ref();
            let mut via = match route.first_hop_peer_id {
                0 => "-".into(),
                hop if hop == route.final_gateway_peer_id => "direct".into(),
                hop => hop.to_string(),
            };
            if let Some(index) = route.path_index {
                via = format!("path {}", index + 1);
            }
            let mut row = vec![
                clean(&route.destination),
                info.map(|info| clean(&info.hostname))
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| "-".into()),
                info.and_then(|info| info.ipv4_addr.as_ref())
                    .map_or_else(|| "-".into(), |address| address.to_string()),
                via,
                clean(&route.effective_policy),
                route
                    .cost_ms
                    .map_or("-".into(), |cost| format!("{cost} ms")),
                rtt(route.measured_rtt_us),
                rate(route.delivery_bps),
                if route.fallback_reason.is_empty() {
                    "-".into()
                } else {
                    clean(&route.fallback_reason)
                },
            ];
            if with_path {
                row.push(
                    route
                        .path_peer_ids
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(" > "),
                );
            }
            row
        })
        .collect();
    let mut headers = vec![
        "Destination",
        "Peer",
        "Address",
        "Via",
        "Policy",
        "Cost",
        "RTT",
        "Rate",
        "Fallback",
    ];
    if with_path {
        headers.push("Path");
    }
    table(&headers, rows, &[5, 6, 7])
}

fn status(view: &StatusView) -> String {
    let node = view.node.node.clone().unwrap_or_default();
    let stun = node.stun_info.clone().unwrap_or_default();
    let mut text = String::new();
    let mut line = |label: &str, value: String| {
        let _ = writeln!(text, "{label:10}{value}");
    };
    line(
        "node",
        format!(
            "{} · peer {} · {} · {}",
            clean(&node.hostname),
            node.peer_id,
            view.daemon.as_deref().map_or_else(
                || view.portal.clone(),
                |name| format!("{name} @ {}", view.portal)
            ),
            clean(&node.version)
        ),
    );
    line(
        "address",
        if node.ipv4_addr.is_empty() {
            "none assigned".into()
        } else {
            clean(&node.ipv4_addr)
        },
    );
    line(
        "nat",
        format!(
            "udp {} · tcp {} · public {}",
            nat(stun.udp_nat_type),
            nat(stun.tcp_nat_type),
            if stun.public_ip.is_empty() {
                "unknown".into()
            } else {
                clean(&stun.public_ip.join(", "))
            }
        ),
    );
    let failing = view
        .discovery
        .trackers
        .iter()
        .filter(|tracker| !tracker.last_error.is_empty())
        .count();
    line(
        "discovery",
        if view.discovery.trackers.is_empty() {
            "no trackers configured".into()
        } else {
            format!(
                "{} tracker(s), {} failing · {} candidate(s)",
                view.discovery.trackers.len(),
                failing,
                view.discovery.candidate_count.unwrap_or(0)
            )
        },
    );
    line(
        "listen",
        if view.listeners.listeners.is_empty() {
            "none".into()
        } else {
            view.listeners
                .listeners
                .iter()
                .map(|listener| clean(&listener.uri))
                .collect::<Vec<_>>()
                .join("  ")
        },
    );
    let mut drops = std::collections::BTreeMap::<String, u64>::new();
    for counter in &view.relay.counters {
        if counter.name == "relay_drops" && counter.value > 0 {
            let reason = counter
                .labels
                .get("error_type")
                .cloned()
                .unwrap_or_default();
            *drops.entry(reason).or_default() += counter.value;
        }
    }
    let config = view.relay.config.clone().unwrap_or_default();
    line(
        "relay",
        format!(
            "policy {} · transit {} · relayed {} · drops {}",
            config.policy().as_str_name(),
            config.transit().as_str_name(),
            bytes(view.relay.total_bytes),
            if drops.is_empty() {
                "0".into()
            } else {
                drops
                    .iter()
                    .map(|(reason, count)| format!("{reason} {count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
    );
    text.push('\n');
    if view.peers.peers.is_empty() {
        text.push_str("No peers. Add one with `lowertier peers add URI`.\n");
    } else {
        text.push_str(&peers_table(&view.peers));
    }
    text
}

fn doctor(report: &doctor::Report) -> String {
    let mut text = String::new();
    for check in &report.checks {
        let marker = match check.level {
            doctor::Level::Ok => "ok  ",
            doctor::Level::Warn => "warn",
            doctor::Level::Fail => "FAIL",
        };
        let _ = writeln!(text, "{marker}  {:10} {}", check.name, clean(&check.detail));
        if let Some(fix) = &check.fix {
            let _ = writeln!(text, "      {:10} fix: {}", "", clean(fix));
        }
    }
    text
}

fn toml_at(path: Option<&str>, value: &toml::Value) -> String {
    match (path, value) {
        (None, toml::Value::Table(table)) => toml::to_string_pretty(table).unwrap_or_default(),
        (Some(path), toml::Value::Table(_)) | (Some(path), toml::Value::Array(_)) => {
            let mut root = toml::Table::new();
            crate::common::config_schema::set(&mut root, path, value.clone());
            toml::to_string_pretty(&root).unwrap_or_default()
        }
        (Some(path), value) => format!("{path} = {value}\n"),
        (None, value) => format!("{value}\n"),
    }
}

fn config_view(view: &ConfigView) -> String {
    let path = view.path.as_deref();
    let mut text = match &view.active {
        Some(value) => toml_at(path, value),
        None => {
            let default = path
                .and_then(crate::common::config_schema::lookup)
                .map(|spec| spec.default)
                .filter(|default| !default.is_empty());
            match default {
                Some(default) => format!("# {} is not set; default {default}\n", path.unwrap()),
                None => format!("# {} is not set\n", path.unwrap_or("configuration")),
            }
        }
    };
    if let Some(desired) = &view.desired {
        let _ = write!(
            text,
            "\n# Staged, applies after `lowertier instance stop` and `start`:\n{}",
            toml_at(path, desired)
        );
    }
    if path.is_none() && !view.restart_fields.is_empty() {
        let _ = writeln!(
            text,
            "\n# Pending restart: {}",
            view.restart_fields.join(", ")
        );
    }
    text
}

fn apply_result(result: &ApplyResult) -> String {
    let mut text = String::new();
    let mut group = |label: &str, fields: &[String]| {
        if !fields.is_empty() {
            let _ = writeln!(text, "{label:22}{}", fields.join(", "));
        }
    };
    group("applied now", &result.live_fields);
    group("new connections", &result.new_connection_fields);
    group("after restart", &result.restart_fields);
    if text.is_empty() {
        text.push_str("No change.\n");
    }
    if !result.restart_fields.is_empty() {
        text.push_str(
            "Restart the instance to apply: lowertier instance stop && lowertier instance start\n",
        );
    }
    let _ = writeln!(text, "{:22}{}", "revision", result.revision);
    text
}

fn paths(value: &ListPathsResponse) -> String {
    if value.paths.is_empty() {
        return "No paths. Add [[path]] entries; see `lowertier config explain path`.\n".into();
    }
    let mut text = String::new();
    for path in &value.paths {
        let mode_str = if path.mode.is_empty() {
            "parallel".to_owned()
        } else {
            clean(&path.mode)
        };
        let _ = writeln!(
            text,
            "path {} · to {} · {}{} ({}) · {} relayed · {} reordered · {} fallback · {} dropped",
            path.index + 1,
            clean(&path.to),
            clean(&path.state),
            if path.strict { " (strict)" } else { "" },
            mode_str,
            path.relayed_packets,
            path.reordered_packets,
            path.fallback_packets,
            path.dropped_packets,
        );
        if !path.reason.is_empty() {
            let _ = writeln!(text, "  {}", clean(&path.reason));
        }
        let segments = path
            .layers
            .iter()
            .enumerate()
            .map(|(index, segment)| (format!("layer {}", index + 1), segment))
            .chain(
                path.gateway
                    .iter()
                    .map(|segment| ("gateway".to_owned(), segment)),
            );
        let rows = segments
            .flat_map(|(role, segment)| {
                segment
                    .members
                    .iter()
                    .enumerate()
                    .map(move |(index, member)| {
                        vec![
                            if index == 0 {
                                role.clone()
                            } else {
                                String::new()
                            },
                            if index == 0 {
                                format!("{} ({})", clean(&segment.name), clean(&segment.mode))
                            } else {
                                String::new()
                            },
                            if member.hostname.is_empty() {
                                clean(&member.r#ref)
                            } else {
                                clean(&member.hostname)
                            },
                            member.weight.to_string(),
                            if member.usable {
                                "usable".into()
                            } else {
                                clean(&member.reason)
                            },
                            member.picks.to_string(),
                        ]
                    })
            })
            .collect();
        text += &table(
            &["Role", "Segment", "Member", "Weight", "State", "Picks"],
            rows,
            &[3, 5],
        );
        if !path.chains.is_empty() {
            let chain_rows = path
                .chains
                .iter()
                .map(|chain| {
                    let hops = chain
                        .hop_peer_ids
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    let rtt = if chain.rtt_us > 0 {
                        format!("{:.1}ms", chain.rtt_us as f64 / 1000.0)
                    } else {
                        "-".into()
                    };
                    let state = if chain.healthy { "healthy" } else { "down" };
                    vec![
                        chain.path_id.to_string(),
                        hops,
                        rtt,
                        chain.packets.to_string(),
                        state.into(),
                    ]
                })
                .collect();
            text += &table(
                &["Chain", "Hops", "RTT", "Packets", "State"],
                chain_rows,
                &[0, 3],
            );
        }
        text.push('\n');
    }
    text
}

fn trace(trace: &Trace) -> String {
    let mut text = format!(
        "{} · policy {}{} · cost {} · rtt {} · rate {}\n",
        clean(&trace.destination),
        clean(&trace.effective_policy),
        if trace.fallback_reason.is_empty() {
            String::new()
        } else {
            format!(" (fallback: {})", clean(&trace.fallback_reason))
        },
        trace
            .cost_ms
            .map_or("-".into(), |cost| format!("{cost} ms")),
        rtt(trace.measured_rtt_us),
        rate(trace.delivery_bps),
    );
    if let Some(path) = &trace.path {
        let _ = writeln!(
            text,
            "{}. Waypoints are chosen per flow; the hops below are the automatic route.",
            clean(path)
        );
    }
    if !trace.path_error.is_empty() {
        let _ = writeln!(text, "path unavailable: {}", clean(&trace.path_error));
    }
    let rows = trace
        .hops
        .iter()
        .enumerate()
        .map(|(index, hop)| {
            vec![
                index.to_string(),
                clean(&hop.name),
                if hop.address.is_empty() {
                    "-".into()
                } else {
                    clean(&hop.address)
                },
                if hop.transport.is_empty() {
                    "-".into()
                } else {
                    clean(&hop.transport)
                },
                rtt(hop.rtt_us),
                loss(hop.loss_ppm),
                hop.peer_id.to_string(),
            ]
        })
        .collect();
    text + &table(
        &["Hop", "Peer", "Address", "Transport", "RTT", "Loss", "ID"],
        rows,
        &[0, 4, 5, 6],
    )
}

fn key_values(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(key, value)| format!("{key:width$}  {value}\n"))
        .collect()
}

fn discovery(value: &GetDiscoveryResponse) -> String {
    let mut text = key_values(&[
        ("candidates", value.candidate_count.unwrap_or(0).to_string()),
        (
            "active paths",
            if value.active_paths.is_empty() {
                "-".into()
            } else {
                clean(&value.active_paths.join(", "))
            },
        ),
        (
            "last error",
            if value.last_error.is_empty() {
                "-".into()
            } else {
                clean(&value.last_error)
            },
        ),
    ]);
    if value.trackers.is_empty() {
        text.push_str("\nNo trackers. Set discovery.trackers or discovery.private_trackers.\n");
    } else {
        text.push('\n');
        text.push_str(&table(
            &["Tracker", "Status", "Candidates"],
            value
                .trackers
                .iter()
                .map(|tracker| {
                    vec![
                        clean(&tracker.uri),
                        if tracker.last_error.is_empty() {
                            "ok".into()
                        } else {
                            format!("error: {}", clean(&tracker.last_error))
                        },
                        tracker
                            .candidate_count
                            .map_or("-".into(), |count| count.to_string()),
                    ]
                })
                .collect(),
            &[2],
        ));
    }
    if !value.observations.is_empty() {
        text.push('\n');
        text.push_str(&table(
            &["Protocol", "Socket", "Observer", "Public endpoint", "Age"],
            value
                .observations
                .iter()
                .map(|observation| {
                    vec![
                        clean(&observation.protocol),
                        clean(&observation.socket),
                        clean(&observation.observer),
                        clean(&observation.endpoint)
                            + if observation.provisional {
                                " (provisional)"
                            } else {
                                ""
                            },
                        format!("{} s", observation.age_ms / 1000),
                    ]
                })
                .collect(),
            &[4],
        ));
    }
    text
}

fn camouflage(value: &GetCamouflageResponse) -> String {
    let config = value.config.clone().unwrap_or_default();
    let or_dash = |text: &str| {
        if text.is_empty() {
            "-".into()
        } else {
            clean(text)
        }
    };
    key_values(&[
        ("server names", or_dash(&config.server_names.join(", "))),
        ("http host", or_dash(&config.http_host)),
        ("wss path", clean(config.websocket_path())),
        ("sni routing", config.sni_routing.to_string()),
        ("decoy tcp", or_dash(config.tcp_decoy())),
        ("decoy udp", or_dash(config.udp_decoy())),
        ("website root", or_dash(&config.website_root)),
        (
            "trusted proxies",
            if config.trusted_proxy_cidrs.is_empty() {
                "none".into()
            } else {
                clean(&config.trusted_proxy_cidrs.join(", "))
            },
        ),
        ("certificate", clean(&value.certificate_source)),
        ("quic/h2 verify", clean(&value.quic_h2_verification)),
        ("wss verify", clean(&value.direct_wss_verification)),
        (
            "cdn verify",
            format!(
                "outer {}, inner {}",
                clean(&value.cdn_outer_verification),
                clean(&value.cdn_inner_verification)
            ),
        ),
    ])
}

fn logs(response: &ReadLogsResponse) -> String {
    let mut text = String::new();
    for entry in &response.logs {
        let time = chrono::DateTime::from_timestamp_millis(entry.sampled_at_unix_ms)
            .map(|time| {
                time.with_timezone(&chrono::Local)
                    .format("%H:%M:%S%.3f")
                    .to_string()
            })
            .unwrap_or_default();
        let message = entry
            .message
            .strip_prefix("message=")
            .unwrap_or(&entry.message);
        let _ = writeln!(
            text,
            "{time} {:5} {}: {}",
            clean(&entry.level),
            clean(&entry.target),
            clean(message)
        );
    }
    if response.truncated > 0 {
        let _ = writeln!(text, "({} older lines were dropped)", response.truncated);
    }
    text
}

fn table_output(response: &Response, data: &Value) -> String {
    match response {
        Response::Status(view) => status(view),
        Response::Doctor(report) => doctor(report),
        Response::Config(view) => config_view(view),
        Response::Trace(value) => trace(value),
        Response::Text { text } => text.clone(),
        Response::Nodes { nodes } => {
            if nodes.is_empty() {
                return "No LowTier daemon is running. Start one with `lowertier run -c FILE`.\n"
                    .into();
            }
            table(
                &["Name", "PID", "Portal", "Instances", "Token file"],
                nodes
                    .iter()
                    .map(|node| {
                        vec![
                            clean(&node.name),
                            node.pid.to_string(),
                            clean(&node.portal),
                            clean(&node.instances.join(", ")),
                            clean(&node.token_file.display().to_string()),
                        ]
                    })
                    .collect(),
                &[1],
            )
        }
        Response::Peers(view) => {
            if view.detail {
                view.peers
                    .iter()
                    .map(|peer| peer_detail(peer, view))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else if view.peers.is_empty() {
                "No peers.\n".into()
            } else {
                peers_table(view)
            }
        }
        Response::PatchConfigResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::ValidateConfigResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::SetAclResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::PutPortForwardResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::DeletePortForwardResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::StartInstanceResponse(value) => {
            value.result.as_ref().map_or_else(String::new, apply_result)
        }
        Response::ListPathsResponse(value) => paths(value),
        Response::ListRoutesResponse(value) => routes(
            &value.routes,
            value
                .routes
                .iter()
                .any(|route| !route.path_peer_ids.is_empty()),
        ),
        Response::ListInstancesResponse(_) => table(
            &["Name", "Network", "State", "Instance ID", "Last error"],
            rows(data, "instances")
                .iter()
                .map(|instance| {
                    vec![
                        field(instance, "name"),
                        field(instance, "network_name"),
                        if instance.get("running").and_then(Value::as_bool) == Some(true) {
                            "running".into()
                        } else {
                            "stopped".into()
                        },
                        field(instance, "instance_id"),
                        field(instance, "last_error"),
                    ]
                })
                .collect(),
            &[],
        ),
        Response::ListListenersResponse(_) => table(
            &["URI", "Transport", "Lanes", "Auth", "Binding", "Path", "ID"],
            rows(data, "listeners")
                .iter()
                .map(|listener| {
                    vec![
                        field(listener, "uri"),
                        field(listener, "transport"),
                        field(listener, "lanes"),
                        field(listener, "auth_state"),
                        field(listener, "binding_kind"),
                        field(listener, "configured_path"),
                        field(listener, "id"),
                    ]
                })
                .collect(),
            &[2],
        ),
        Response::ListPortForwardsResponse(value) => table(
            &["Proto", "Bind", "Destination"],
            value
                .port_forwards
                .iter()
                .map(|forward| {
                    let forward = crate::common::config::PortForwardConfig::from(*forward);
                    vec![
                        forward.proto,
                        forward.bind_addr.to_string(),
                        forward.dst_addr.to_string(),
                    ]
                })
                .collect(),
            &[],
        ),
        Response::GetStatsResponse(_) => metrics(data, "metrics"),
        Response::GetPrometheusResponse(value) => value.text.clone(),
        Response::ReadLogsResponse(value) => logs(value),
        Response::ClearLogsResponse(_) => "logs cleared\n".into(),
        Response::GetRelayResponse(value) => {
            let config = value.config.clone().unwrap_or_default();
            let mut drops = std::collections::BTreeMap::<String, u64>::new();
            for counter in &value.counters {
                if counter.name == "relay_drops" {
                    let reason = counter
                        .labels
                        .get("error_type")
                        .cloned()
                        .unwrap_or_default();
                    *drops.entry(reason).or_default() += counter.value;
                }
            }
            let mut summary = format!(
                "policy        {}\ntransit       {} (advertised {}, desired {})\nnetworks      {}\nlimit         {}\nspeed tests   {}\nrelayed       {}\ndrops         {}\n\n",
                config.policy().as_str_name(),
                config.transit().as_str_name(),
                clean(&value.advertised_permission),
                clean(&value.desired_permission),
                if config.transit_networks.is_empty() {
                    "none (foreign transit denied)".into()
                } else {
                    clean(&config.transit_networks.join(", "))
                },
                config
                    .transit_bps_limit
                    .map_or("unlimited".into(), |limit| rate(Some(limit))),
                if config.probe_budget_bps == 0 {
                    "off".into()
                } else {
                    format!("up to {}", rate(Some(config.probe_budget_bps)))
                },
                bytes(value.total_bytes),
                drops
                    .iter()
                    .map(|(reason, count)| format!("{reason} {count}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            summary.push_str(&routes(&value.paths, false));
            summary
        }
        Response::GetDiscoveryResponse(value) => discovery(value),
        Response::GetCamouflageResponse(value) => camouflage(value),
        Response::GetL2Response(_) => {
            let fdb = rows(data, "fdb");
            let mut text = fields(&json!({"counters": data.get("counters")}));
            if !fdb.is_empty() {
                text.push('\n');
                text.push_str(&table(
                    &["VLANs", "MAC (base64)", "Owner", "Age (ms)"],
                    fdb.iter()
                        .map(|entry| {
                            vec![
                                field(entry, "vlans"),
                                field(entry, "mac"),
                                field(entry, "owner_peer"),
                                field(entry, "age_ms"),
                            ]
                        })
                        .collect(),
                    &[3],
                ));
            }
            text
        }
        _ => fields(data),
    }
}

pub fn write_response(
    output: Output,
    request_id: &str,
    instance_id: &str,
    response: &Response,
) -> io::Result<()> {
    let envelope =
        Envelope::success(request_id, instance_id, response).map_err(io::Error::other)?;
    let mut stdout = io::stdout().lock();
    if output == Output::Json {
        serde_json::to_writer(&mut stdout, &envelope)?;
        writeln!(stdout)?;
    } else {
        stdout.write_all(table_output(response, envelope.data.as_ref().unwrap()).as_bytes())?;
        let paged = !matches!(response, Response::ReadLogsResponse(_));
        if let Some(cursor) = envelope
            .data
            .as_ref()
            .filter(|_| paged)
            .and_then(|data| data.get("next_page_token"))
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty())
        {
            writeln!(stdout, "more: --page-token {}", clean(cursor))?;
        }
    }
    stdout.flush()
}

pub fn write_error(
    output: Output,
    request_id: &str,
    instance_id: &str,
    error: &CliError,
) -> io::Result<()> {
    if output == Output::Json {
        let mut stdout = io::stdout().lock();
        serde_json::to_writer(
            &mut stdout,
            &Envelope::failure(request_id, instance_id, error),
        )?;
        writeln!(stdout)?;
        stdout.flush()
    } else {
        // Messages may span lines, for example parser reports; keep the line breaks.
        let message = error
            .0
            .message
            .lines()
            .map(clean)
            .collect::<Vec<_>>()
            .join("\n");
        writeln!(io::stderr(), "error: {message}")
    }
}

pub fn diagnostic(message: &str) {
    let _ = writeln!(io::stderr(), "{message}");
}

pub fn clap_message(error: &clap::Error) {
    let _ = error.print();
}

pub fn help(error: &clap::Error, output: Output, request_id: &str) -> io::Result<()> {
    if output == Output::Table {
        clap_message(error);
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    let envelope = Envelope {
        schema_version: 1,
        request_id: request_id.into(),
        instance_id: None,
        revision: None,
        data: Some(json!({"text": error.to_string()})),
        error: None,
    };
    serde_json::to_writer(&mut stdout, &envelope)?;
    writeln!(stdout)?;
    stdout.flush()
}

pub fn completion(shell: &crate::ShellType, output: Output, request_id: &str) -> io::Result<()> {
    let mut script = Vec::new();
    let mut command = Arguments::command();
    if let Some(shell) = shell.to_shell() {
        clap_complete::generate(shell, &mut command, "lowertier", &mut script);
    } else {
        clap_complete::generate(
            clap_complete_nushell::Nushell,
            &mut command,
            "lowertier",
            &mut script,
        );
    }
    let mut stdout = io::stdout().lock();
    if output == Output::Json {
        let envelope = Envelope {
            schema_version: 1,
            request_id: request_id.into(),
            instance_id: None,
            revision: None,
            data: Some(json!({"script": String::from_utf8_lossy(&script)})),
            error: None,
        };
        serde_json::to_writer(&mut stdout, &envelope)?;
        writeln!(stdout)?;
    } else {
        stdout.write_all(&script)?;
    }
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_and_exit_codes() {
        Arguments::command().debug_assert();
        let response = Response::GetNodeResponse(GetNodeResponse {
            snapshot: Some(SnapshotMeta {
                revision: u64::MAX,
                ..Default::default()
            }),
            ..Default::default()
        });
        let value =
            serde_json::to_value(Envelope::success("request", "instance", &response).unwrap())
                .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 6);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["revision"], u64::MAX.to_string());
        assert!(value["error"].is_null());
        for (code, exit) in [
            ("internal", 1),
            ("invalid_argument", 2),
            ("permission_denied", 3),
            ("not_found", 4),
            ("ambiguous", 4),
            ("conflict", 5),
            ("restart_required", 5),
            ("unavailable", 6),
            ("deadline_exceeded", 6),
            ("partial_failure", 7),
        ] {
            let error = CliError::new(code, "Failure.", "field");
            assert_eq!(error.exit_code(), exit);
            let value =
                serde_json::to_value(Envelope::failure("request", "instance", &error)).unwrap();
            assert!(value["data"].is_null());
            assert_eq!(value["error"]["code"], code);
        }
    }

    #[test]
    fn units_and_status_render() {
        assert_eq!(rtt(Some(1_234)), "1.2 ms");
        assert_eq!(rtt(Some(42_000)), "42 ms");
        assert_eq!(loss(Some(1_500)), "0.1 %");
        assert_eq!(rate(Some(812_000_000)), "812.0 Mbit/s");
        assert_eq!(bytes(3 << 20), "3.0 MiB");
        let peer = PeerSnapshot {
            peer_id: 7,
            rtt_us: Some(42_000),
            end_to_end_session_ready: Some(true),
            route: Some(crate::proto::api::instance::Route {
                hostname: "edge\u{1b}[2J".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let view = StatusView {
            daemon: Some("default".into()),
            portal: "127.0.0.1:15888".into(),
            node: GetNodeResponse::default(),
            peers: PeerView {
                snapshot: None,
                peers: vec![peer],
                route_summaries: Vec::new(),
                active_policy: "hop".into(),
                next_page_token: String::new(),
                detail: false,
            },
            relay: GetRelayResponse::default(),
            discovery: GetDiscoveryResponse::default(),
            listeners: ListListenersResponse::default(),
        };
        let text = status(&view);
        assert!(
            text.contains("key-bound") && text.contains("42 ms"),
            "{text}"
        );
        assert!(
            !text.contains('\u{1b}'),
            "control characters must be escaped"
        );
        assert!(text.contains("unreachable"));
    }
}
