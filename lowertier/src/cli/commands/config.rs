use super::super::{
    args::{ApplyArgs, ConfigCommand, PatchArgs},
    client::{Client, Response, checked},
    error::{CliError, Result},
};
use crate::proto::api::control::v1::*;
use serde_json::{Value, json};
use std::path::Path;

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| CliError::new("invalid_argument", "Cannot read the JSON file.", "file"))?;
    Ok(serde_json::from_str(&text)?)
}

fn qualify(path: &str, prefix: &str) -> String {
    if prefix.is_empty() || path.starts_with(&format!("{prefix}.")) || path == prefix {
        path.to_owned()
    } else {
        format!("{prefix}.{path}")
    }
}

fn set_value(document: &mut Value, path: &str, value: Value) -> Result<()> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(CliError::new(
            "invalid_argument",
            "The field path is invalid.",
            path,
        ));
    }
    let mut object = document.as_object_mut().ok_or_else(|| {
        CliError::new(
            "invalid_argument",
            "Configuration values must be a JSON object.",
            "values",
        )
    })?;
    for part in &parts[..parts.len() - 1] {
        object = object
            .entry((*part).to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| {
                CliError::new("invalid_argument", "A parent field is not an object.", path)
            })?;
    }
    object.insert(parts.last().unwrap().to_string(), value);
    Ok(())
}

pub async fn patch(
    client: &Client,
    args: &PatchArgs,
    prefix: &str,
    validate: bool,
) -> Result<Response> {
    let mut values = match &args.values {
        Some(path) => read_json(path)?,
        None => json!({}),
    };
    let mut mask = args
        .field
        .iter()
        .map(|path| qualify(path, prefix))
        .collect::<Vec<_>>();
    for assignment in &args.assignments {
        let (path, text) = assignment.split_once('=').ok_or_else(|| {
            CliError::new(
                "invalid_argument",
                "Use PATH=JSON for each assignment.",
                "assignments",
            )
        })?;
        let path = qualify(path, prefix);
        let value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(_) if !text.is_empty() && !matches!(text.as_bytes()[0], b'[' | b'{' | b'"') => {
                Value::String(text.into())
            }
            Err(error) => return Err(error.into()),
        };
        set_value(&mut values, &path, value)?;
        mask.push(path);
    }
    let clear_paths = args
        .clear
        .iter()
        .map(|path| qualify(path, prefix))
        .collect::<Vec<_>>();
    if mask.is_empty() && clear_paths.is_empty() {
        return Err(CliError::new(
            "invalid_argument",
            "Specify assignments, --field, or --clear.",
            "field_mask",
        ));
    }
    // Deserialize before reading state. Unknown fields must fail before a mutation.
    let values: NodeConfig = serde_json::from_value(values)?;
    let patch = ConfigPatch {
        expected_revision: client.revision(args.apply.expected_revision).await?,
        field_mask: mask,
        values: Some(values),
        clear_paths,
        persist: args.apply.persist,
        stage: args.apply.stage,
    };
    if validate {
        checked(
            client
                .rpc
                .validate_config(
                    client.controller(),
                    ValidateConfigRequest {
                        meta: client.meta(),
                        patch: Some(patch),
                    },
                )
                .await?,
        )
    } else {
        apply_patch(client, patch).await
    }
}

pub async fn apply_patch(client: &Client, patch: ConfigPatch) -> Result<Response> {
    checked(
        client
            .rpc
            .patch_config(
                client.controller(),
                PatchConfigRequest {
                    meta: client.meta(),
                    patch: Some(patch),
                },
            )
            .await?,
    )
}

pub async fn desired(client: &Client, apply: &ApplyArgs) -> Result<(NodeConfig, u64)> {
    let config = client.config().await?;
    let revision = config
        .snapshot
        .map(|snapshot| snapshot.revision)
        .ok_or_else(|| {
            CliError::new(
                "internal",
                "The configuration revision is absent.",
                "snapshot",
            )
        })?;
    require_revision(apply.expected_revision, revision)?;
    Ok((
        config.desired.ok_or_else(|| {
            CliError::new(
                "internal",
                "The desired configuration is absent.",
                "desired",
            )
        })?,
        revision,
    ))
}

fn require_revision(expected: Option<u64>, actual: u64) -> Result<()> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(CliError::new(
            "conflict",
            "The expected revision does not match the configuration snapshot.",
            "expected_revision",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_uses_the_read_revision() {
        assert!(require_revision(None, 3).is_ok());
        assert!(require_revision(Some(3), 3).is_ok());
        assert_eq!(require_revision(Some(2), 3).unwrap_err().exit_code(), 5);
        assert_eq!(require_revision(Some(4), 3).unwrap_err().exit_code(), 5);
    }
}

pub async fn replace(
    client: &Client,
    apply: &ApplyArgs,
    revision: u64,
    field: &str,
    values: NodeConfig,
) -> Result<Response> {
    apply_patch(
        client,
        ConfigPatch {
            expected_revision: revision,
            field_mask: vec![field.into()],
            values: Some(values),
            persist: apply.persist,
            stage: apply.stage,
            ..Default::default()
        },
    )
    .await
}

pub async fn execute(client: &Client, command: &ConfigCommand) -> Result<Response> {
    match command {
        ConfigCommand::Get => checked(client.config().await?),
        ConfigCommand::Set(args) => patch(client, args, "", false).await,
        ConfigCommand::Validate(args) => patch(client, args, "", true).await,
    }
}
