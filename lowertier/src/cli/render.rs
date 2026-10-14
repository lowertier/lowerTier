use super::{
    args::{Arguments, Output},
    client::Response,
    error::CliError,
};
use clap::CommandFactory;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{self, Write};
use tabled::{builder::Builder, settings::Style};

#[derive(Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    pub request_id: String,
    pub instance_id: Option<String>,
    pub revision: Option<String>,
    pub data: Option<Value>,
    pub error: Option<crate::proto::api::control::v1::ApiError>,
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

fn cell(value: &Value) -> String {
    let text = match value {
        Value::Null => "unknown".into(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    };
    // Escape control characters in tables to protect terminal state.
    text.chars()
        .flat_map(|character| character.escape_debug())
        .collect()
}
fn field(value: &Value, key: &str) -> String {
    cell(value.get(key).unwrap_or(&Value::Null))
}
fn path(value: &Value) -> String {
    value
        .get("path_peer_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().map(cell).collect::<Vec<_>>().join(" -> "))
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
fn via(value: &Value) -> String {
    if let Some(first) = value
        .get("first_hop_peer_id")
        .filter(|first| first.as_u64().unwrap_or(0) != 0)
    {
        if value.get("final_gateway_peer_id") == Some(first) {
            return "direct".into();
        }
        return format!("via {}", cell(first));
    }
    match value.get("path_peer_ids").and_then(Value::as_array) {
        Some(ids) if ids.len() > 2 => format!("via {}", cell(&ids[1])),
        _ => "unknown".into(),
    }
}
fn table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut builder = Builder::default();
    builder.push_record(headers.iter().copied());
    for row in rows {
        builder.push_record(row);
    }
    format!("{}\n", builder.build().with(Style::rounded()))
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
        rows.push(vec!["status".into(), "ok".into()]);
    }
    table(&["Field", "Value"], rows)
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
            let unit = if name.contains("bytes") {
                "bytes"
            } else if name.ends_with("bps") {
                "bit/s"
            } else if name.ends_with("_us") {
                "us"
            } else if name.ends_with("_ms") {
                "ms"
            } else {
                "count"
            };
            vec![
                name.into(),
                metric.get("value").map(cell).unwrap_or_else(|| "0".into()),
                unit.into(),
                metric.get("labels").map(cell).unwrap_or_default(),
            ]
        })
        .collect();
    table(&["Metric", "Value", "Unit", "Labels"], entries)
}
fn routes(data: &Value, key: &str) -> String {
    table(
        &[
            "Destination",
            "Policy",
            "Effective policy",
            "First hop",
            "Path",
            "Cost (ms)",
            "RTT (us)",
            "Delivery (bit/s)",
            "Override",
            "Fallback",
            "Path error",
        ],
        rows(data, key)
            .iter()
            .map(|route| {
                vec![
                    field(route, "destination"),
                    field(route, "policy"),
                    field(route, "effective_policy"),
                    via(route),
                    path(route),
                    field(route, "cost_ms"),
                    field(route, "measured_rtt_us"),
                    field(route, "delivery_bps"),
                    field(route, "override_status"),
                    field(route, "fallback_reason"),
                    field(route, "path_error"),
                ]
            })
            .collect(),
    )
}

fn table_output(response: &Response, data: &Value) -> String {
    match response {
        Response::Peers(value) => {
            let summaries = rows(data, "route_summaries");
            let entries = rows(data, "peers")
                .iter()
                .map(|peer| {
                    let route = summaries
                        .iter()
                        .find(|route| route.pointer("/route/peer_id") == peer.get("peer_id"));
                    let connection = route.map(via).unwrap_or_else(|| {
                        if peer
                            .get("conns")
                            .and_then(Value::as_array)
                            .is_some_and(|conns| !conns.is_empty())
                        {
                            "direct".into()
                        } else {
                            "unavailable".into()
                        }
                    });
                    vec![
                        field(peer, "peer_id"),
                        field(peer, "peer_key"),
                        connection,
                        field(peer, "rtt_us"),
                        field(peer, "loss_ppm"),
                        field(peer, "delivery_bps"),
                        field(peer, "sample_age_ms"),
                        field(peer, "metric_scope"),
                    ]
                })
                .collect();
            table(&["Active policy"], vec![vec![value.active_policy.clone()]])
                + &table(
                    &[
                        "Peer ID",
                        "Public key",
                        "Connection",
                        "RTT (us)",
                        "Loss (ppm)",
                        "Delivery (bit/s)",
                        "Sample age (ms)",
                        "Scope",
                    ],
                    entries,
                )
        }
        Response::ListRoutesResponse(_) => routes(data, "routes"),
        Response::ListInstancesResponse(_) => table(
            &["Instance ID", "Name", "Network", "Running", "Last error"],
            rows(data, "instances")
                .iter()
                .map(|instance| {
                    vec![
                        field(instance, "instance_id"),
                        field(instance, "name"),
                        field(instance, "network_name"),
                        instance
                            .get("running")
                            .map(cell)
                            .unwrap_or_else(|| "false".into()),
                        field(instance, "last_error"),
                    ]
                })
                .collect(),
        ),
        Response::ListListenersResponse(_) => table(
            &[
                "ID",
                "URI",
                "Transport",
                "Lanes",
                "Authentication",
                "Binding",
                "Path",
                "Revision",
            ],
            rows(data, "listeners")
                .iter()
                .map(|listener| {
                    vec![
                        field(listener, "id"),
                        field(listener, "uri"),
                        field(listener, "transport"),
                        field(listener, "lanes"),
                        field(listener, "auth_state"),
                        field(listener, "binding_kind"),
                        field(listener, "configured_path"),
                        field(listener, "config_revision"),
                    ]
                })
                .collect(),
        ),
        Response::GetStatsResponse(_) => metrics(data, "metrics"),
        Response::GetPrometheusResponse(value) => value.text.clone(),
        Response::ReadLogsResponse(_) => {
            table(
                &[
                    "Sequence",
                    "UTC time (Unix ms)",
                    "Level",
                    "Target",
                    "Message",
                ],
                rows(data, "logs")
                    .iter()
                    .map(|log| {
                        vec![
                            field(log, "sequence"),
                            field(log, "sampled_at_unix_ms"),
                            field(log, "level"),
                            field(log, "target"),
                            field(log, "message"),
                        ]
                    })
                    .collect(),
            ) + &fields(&json!({"truncated": data.get("truncated").cloned().unwrap_or(json!("0"))}))
        }
        Response::GetRelayResponse(value) => {
            let mut summary = data.clone();
            summary.as_object_mut().unwrap().remove("paths");
            if let Some(config) = &value.config {
                summary["active_policy"] = json!(
                    crate::proto::common::RelayPolicy::try_from(config.policy)
                        .map(|policy| policy.as_str_name())
                        .unwrap_or("unknown")
                );
                summary["transit_permission"] = json!(
                    crate::proto::common::TransitPolicy::try_from(config.transit)
                        .map(|policy| policy.as_str_name())
                        .unwrap_or("unknown")
                );
                summary["transit_limit_bit_per_second"] = config
                    .transit_bps_limit
                    .map_or(json!("unlimited"), |limit| json!(limit.to_string()));
                summary["transit_burst_bytes"] = config
                    .transit_burst_bytes
                    .map_or(json!("default"), |burst| json!(burst.to_string()));
                summary["probe_budget_bit_per_second"] = json!(config.probe_budget_bps.to_string());
            }
            fields(&summary) + &routes(data, "paths")
        }
        Response::GetL2Response(_) => {
            let fdb = table(
                &["VLANs", "MAC (base64)", "Owner peer", "Age (ms)"],
                rows(data, "fdb")
                    .iter()
                    .map(|entry| {
                        vec![
                            field(entry, "vlans"),
                            field(entry, "mac"),
                            field(entry, "owner_peer"),
                            field(entry, "age_ms"),
                        ]
                    })
                    .collect(),
            );
            fdb + &fields(&json!({"counters": data.get("counters")}))
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
        if let Some(cursor) = envelope
            .data
            .as_ref()
            .and_then(|data| data.get("next_page_token"))
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty())
        {
            writeln!(stdout, "next_page_token: {}", cell(&json!(cursor)))?;
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
        writeln!(
            io::stderr(),
            "{}: {}",
            error.0.code,
            cell(&json!(error.0.message))
        )
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
        clap_complete::generate(shell, &mut command, "lowertier-cli", &mut script);
    } else {
        clap_complete::generate(
            clap_complete_nushell::Nushell,
            &mut command,
            "lowertier-cli",
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
    use crate::proto::api::control::v1::{GetNodeResponse, SnapshotMeta};

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
        assert_eq!(value["request_id"], "request");
        assert_eq!(value["instance_id"], "instance");
        assert_eq!(value["revision"], u64::MAX.to_string());
        assert!(value["error"].is_null());
        assert!(value["data"].is_object());
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
        let route =
            json!({"destination":"2001:db8::/64","path_peer_ids":[1,2,3,4],"first_hop_peer_id":2});
        assert_eq!(path(&route), "1 -> 2 -> 3 -> 4");
        assert_eq!(via(&route), "via 2");
    }
}
