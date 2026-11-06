use super::super::{
    args::ApplyArgs,
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::{common::config_schema, proto::api::control::v1::*};
use serde::Serialize;
use std::io::Write as _;
use toml::{Table, Value};

/// `lowertier get` output: values in the public TOML layout.
#[derive(Serialize)]
pub struct ConfigView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reload_error: Option<String>,
    pub path: Option<String>,
    pub revision: u64,
    pub active: Option<Value>,
    /// Present when staged changes differ from the active configuration.
    pub desired: Option<Value>,
    pub restart_fields: Vec<String>,
}

fn table(config: Option<&NodeConfig>) -> Result<Table> {
    config
        .map_or("", |config| config.toml.as_str())
        .parse::<Table>()
        .map_err(|error| {
            CliError::new(
                "internal",
                format!("The daemon returned invalid TOML: {error}"),
                "",
            )
        })
}

pub fn lookup<'a>(table: &'a Table, path: &str) -> Option<&'a Value> {
    let (parent, key) = match path.rsplit_once('.') {
        Some((parent, key)) => (lookup(table, parent)?.as_table()?, key),
        None => (table, path),
    };
    parent.get(key)
}

/// The desired configuration and its revision.
pub async fn desired(client: &Client, apply: &ApplyArgs) -> Result<(Table, u64)> {
    let config = client.config().await?;
    let revision = config.snapshot.map_or(0, |snapshot| snapshot.revision);
    if apply
        .expected_revision
        .is_some_and(|expected| expected != revision)
    {
        return Err(CliError::new(
            "conflict",
            format!("The configuration is at revision {revision}, not the expected revision."),
            "expected_revision",
        ));
    }
    Ok((table(config.desired.as_ref())?, revision))
}

/// Apply values for `mask` and remove `clear`. The change is saved to the configuration file
/// unless --no-persist is given or the file cannot be written.
pub async fn patch(
    client: &Client,
    values: Table,
    mask: Vec<String>,
    clear: Vec<String>,
    apply: &ApplyArgs,
    revision: Option<u64>,
) -> Result<Response> {
    let (response, unsaved) = patch_noting(client, values, mask, clear, apply, revision).await?;
    if let Some(reason) = unsaved {
        eprintln!("note: the change is not saved to a file: {reason}");
    }
    Ok(response)
}

/// `patch`, returning why the change was not saved to a file instead of printing it.
pub async fn patch_noting(
    client: &Client,
    values: Table,
    mask: Vec<String>,
    clear: Vec<String>,
    apply: &ApplyArgs,
    revision: Option<u64>,
) -> Result<(Response, Option<String>)> {
    if apply.no_persist {
        return Err(CliError::new(
            "invalid_argument",
            "Configuration changes must be saved. Remove --no-persist.",
            "no_persist",
        ));
    }
    let revision = match revision {
        Some(revision) => revision,
        None => client.revision(apply.expected_revision).await?,
    };
    let patch = ConfigPatch {
        expected_revision: revision,
        field_mask: mask,
        values: Some(NodeConfig {
            toml: toml::to_string(&values)
                .map_err(|error| CliError::new("invalid_argument", error.to_string(), "values"))?,
        }),
        clear_paths: clear,
        persist: !apply.no_persist,
        stage: apply.stage,
    };
    let send = |patch: ConfigPatch| async move {
        client
            .rpc
            .patch_config(
                client.controller(),
                PatchConfigRequest {
                    meta: client.meta(),
                    patch: Some(patch),
                },
            )
            .await
    };
    let response = send(patch).await?;
    Ok((checked(response)?, None))
}

pub async fn get(client: &Client, path: Option<&str>) -> Result<Response> {
    if let Some(path) = path
        && let Some(message) = config_schema::retired_message(path)
    {
        return Err(CliError::new(
            "invalid_argument",
            format!("{message}."),
            "path",
        ));
    }
    let config = client.config().await?;
    let active = table(config.active.as_ref())?;
    let desired = table(config.desired.as_ref())?;
    let select = |table: &Table| match path {
        Some(path) => lookup(table, path).cloned(),
        None => Some(Value::Table(table.clone())),
    };
    let active_value = select(&active);
    let desired_value = select(&desired);
    if let Some(path) = path
        && active_value.is_none()
        && desired_value.is_none()
        && config_schema::lookup(path).is_none()
        && !config_schema::OPTIONS
            .iter()
            .any(|spec| spec.path.starts_with(&format!("{path}.")))
    {
        return Err(CliError::new(
            "invalid_argument",
            format!("Unknown option {path:?}. See `lowertier config explain`."),
            "path",
        ));
    }
    Ok(Response::Config(ConfigView {
        reload_error: (!config.reload_error.is_empty()).then_some(config.reload_error),
        path: path.map(str::to_owned),
        revision: config.snapshot.map_or(0, |snapshot| snapshot.revision),
        desired: (desired_value != active_value)
            .then_some(desired_value)
            .flatten(),
        active: active_value,
        restart_fields: config.restart_fields,
    }))
}

pub async fn set(client: &Client, assignments: &[String], apply: &ApplyArgs) -> Result<Response> {
    let mut values = Table::new();
    let mut mask = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        let spec = config_schema::apply_set(&mut values, assignment).map_err(|error| {
            CliError::new("invalid_argument", format!("{error:#}"), "assignments")
        })?;
        if !mask.contains(&spec.path.to_owned()) {
            mask.push(spec.path.to_owned());
        }
    }
    patch(client, values, mask, Vec::new(), apply, None).await
}

pub async fn unset(client: &Client, paths: &[String], apply: &ApplyArgs) -> Result<Response> {
    for path in paths {
        if let Some(message) = config_schema::retired_message(path) {
            return Err(CliError::new(
                "invalid_argument",
                format!("{message}."),
                "paths",
            ));
        }
    }
    patch(
        client,
        Table::new(),
        Vec::new(),
        paths.to_vec(),
        apply,
        None,
    )
    .await
}

/// Leaves that `edit` compares: every registry option, with opaque tables compared whole.
fn option_values(table: &Table) -> Vec<(&'static str, Option<Value>)> {
    config_schema::OPTIONS
        .iter()
        .map(|spec| {
            let mut value = lookup(table, spec.path).cloned();
            if let Some(Value::Table(inner)) = &mut value
                && spec.kind == config_schema::Kind::Table
            {
                inner.retain(|key, _| {
                    config_schema::lookup(&format!("{}.{key}", spec.path)).is_none()
                });
            }
            (spec.path, value)
        })
        .collect()
}

/// Paths to set and to clear when the configuration changes from `before` to `after`.
pub fn diff(before: &Table, after: &Table) -> (Vec<String>, Vec<String>) {
    let mut mask = Vec::new();
    let mut clear = Vec::new();
    for ((path, old), (_, new)) in option_values(before).into_iter().zip(option_values(after)) {
        match (old, new) {
            (old, Some(new)) if old.as_ref() != Some(&new) => mask.push(path.to_owned()),
            (Some(_), None) => clear.push(path.to_owned()),
            _ => {}
        }
    }
    (mask, clear)
}

fn editor() -> String {
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        })
}

fn ask(question: &str) -> bool {
    eprint!("{question} [Y/n] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).is_ok()
        && !matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

const EDIT_HEADER: &str = "# Edit and save to apply. [REDACTED] values stay unchanged.\n\
                           # `lowertier config explain PATH` documents each option.\n";

pub async fn edit(client: &Client, apply: &ApplyArgs) -> Result<Response> {
    let (before, revision) = desired(client, apply).await?;
    let original = toml::to_string_pretty(&before).unwrap_or_default();
    let file = tempfile::Builder::new()
        .prefix("lowertier-")
        .suffix(".toml")
        .tempfile()
        .map_err(|error| CliError::new("internal", error.to_string(), "edit"))?;
    let mut text = format!("{EDIT_HEADER}\n{original}");
    loop {
        std::fs::write(file.path(), &text)
            .map_err(|error| CliError::new("internal", error.to_string(), "edit"))?;
        let editor = editor();
        let mut parts = editor.split_whitespace();
        let status = std::process::Command::new(parts.next().unwrap_or("vi"))
            .args(parts)
            .arg(file.path())
            .status()
            .map_err(|error| {
                CliError::new("internal", format!("Cannot run {editor}: {error}"), "edit")
            })?;
        if !status.success() {
            return Err(CliError::new(
                "internal",
                format!("{editor} exited with {status}."),
                "edit",
            ));
        }
        text = std::fs::read_to_string(file.path())
            .map_err(|error| CliError::new("internal", error.to_string(), "edit"))?;
        let failure = match text.parse::<Table>() {
            Err(error) => format!("The file is not valid TOML: {error}"),
            Ok(after) => {
                let (mask, clear) = diff(&before, &after);
                if mask.is_empty() && clear.is_empty() {
                    return Ok(Response::Text {
                        text: "No changes.\n".into(),
                    });
                }
                match patch(client, after, mask, clear, apply, Some(revision)).await {
                    Ok(response) => return Ok(response),
                    Err(error) if error.0.code == "conflict" => return Err(error),
                    Err(error) => error.0.message,
                }
            }
        };
        eprintln!("error: {failure}");
        if !ask("Edit again?") {
            return Err(CliError::new("invalid_argument", failure, "edit"));
        }
        let body = text
            .lines()
            .filter(|line| !line.starts_with("# error:"))
            .collect::<Vec<_>>()
            .join("\n");
        text = format!(
            "{}{body}\n",
            failure
                .lines()
                .map(|line| format!("# error: {line}\n"))
                .collect::<String>()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_diff_finds_set_and_cleared_options() {
        let before: Table =
            "[relay]\npolicy = \"hop\"\n[tun]\nmtu = 1380\n[acl]\ntcp_ports = [\"22\"]\n"
                .parse()
                .unwrap();
        let after: Table = "[relay]\npolicy = \"latency\"\n[acl]\ntcp_ports = [\"22\"]\n[acl.acl_v1]\nchains = []\n"
            .parse()
            .unwrap();
        let (mask, clear) = diff(&before, &after);
        assert_eq!(mask, vec!["relay.policy".to_owned(), "acl".to_owned()]);
        assert_eq!(clear, vec!["tun.mtu".to_owned()]);
    }
}
