//! TOML documents for the GUI.
//!
//! Generated protobuf serializers write 64-bit integers as strings. Messages are re-encoded
//! through their descriptors so counters and rates stay integers in TOML. TOML has no null, so
//! absent values are omitted.

use std::sync::LazyLock;

use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, SerializeOptions};
use serde_json::Value as Json;
use toml::{Table, Value};

use crate::cli::error::{CliError, Result};

const SERVICE: &str = "api.control.v1.ControlPlaneV1Rpc";
const PACKAGE: &str = "api.control.v1";

static POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(crate::proto::ALL_DESCRIPTOR_BYTES)
        .expect("the compiled protobuf descriptors are valid")
});

fn internal(error: impl std::fmt::Display) -> CliError {
    CliError::new("internal", error.to_string(), "")
}

fn descriptor(name: &str) -> Result<MessageDescriptor> {
    POOL.get_message_by_name(name)
        .ok_or_else(|| internal(format!("no descriptor for {name}")))
}

fn plain(message: &DynamicMessage) -> Result<Json> {
    let options = SerializeOptions::new()
        .use_proto_field_name(true)
        .stringify_64_bit_integers(false)
        .skip_default_fields(false);
    message
        .serialize_with_options(serde_json::value::Serializer, &options)
        .map_err(internal)
}

/// A control API message as plain JSON, for a message named in the control package.
pub fn message<M: prost::Message>(name: &str, value: &M) -> Result<Json> {
    let message = DynamicMessage::decode(
        descriptor(&format!("{PACKAGE}.{name}"))?,
        value.encode_to_vec().as_slice(),
    )
    .map_err(internal)?;
    plain(&message)
}

pub fn messages<M: prost::Message>(name: &str, values: &[M]) -> Result<Json> {
    values
        .iter()
        .map(|value| message(name, value))
        .collect::<Result<Vec<_>>>()
        .map(Json::Array)
}

/// Input and output message names of a control method, by its protobuf name.
pub fn method(name: &str) -> Option<(MessageDescriptor, MessageDescriptor)> {
    POOL.get_service_by_name(SERVICE)?
        .methods()
        .find(|method| method.name() == name)
        .map(|method| (method.input(), method.output()))
}

/// Re-encode the JSON of a generated message so 64-bit integers are numbers.
pub fn normalize(descriptor: MessageDescriptor, value: Json) -> Result<Json> {
    let message = DynamicMessage::deserialize(descriptor, value).map_err(internal)?;
    plain(&message)
}

/// Check a request against its message type so mistakes name the field.
pub fn validate(descriptor: MessageDescriptor, value: &Json) -> Result<()> {
    DynamicMessage::deserialize(descriptor, value.clone())
        .map(drop)
        .map_err(|error| CliError::new("invalid_argument", error.to_string(), "body"))
}

pub fn to_toml(value: Json) -> Option<Value> {
    Some(match value {
        Json::Null => return None,
        Json::Bool(value) => Value::Boolean(value),
        Json::Number(number) => match (number.as_i64(), number.as_u64()) {
            (Some(value), _) => Value::Integer(value),
            // Beyond the TOML integer range.
            (None, Some(value)) => Value::String(value.to_string()),
            _ => Value::Float(number.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(value) => Value::String(value),
        Json::Array(items) => Value::Array(items.into_iter().filter_map(to_toml).collect()),
        Json::Object(map) => Value::Table(
            map.into_iter()
                .filter_map(|(key, value)| Some((key, to_toml(value)?)))
                .collect(),
        ),
    })
}

pub fn document(value: Json) -> Result<String> {
    let table = match to_toml(value) {
        Some(Value::Table(table)) => table,
        Some(other) => Table::from_iter([("value".to_owned(), other)]),
        None => Table::new(),
    };
    toml::to_string(&table).map_err(internal)
}

pub fn parse(body: &[u8]) -> Result<Table> {
    let text = std::str::from_utf8(body)
        .map_err(|_| CliError::new("invalid_argument", "The request is not UTF-8.", "body"))?;
    text.parse().map_err(|error: toml::de::Error| {
        CliError::new(
            "invalid_argument",
            format!("The request is not valid TOML: {}", error.message()),
            "body",
        )
    })
}

pub fn to_json(table: Table) -> Result<Json> {
    serde_json::to_value(table).map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::api::control::v1::{PeerSnapshot, SnapshotMeta};

    #[test]
    fn messages_keep_integers_and_drop_absent_values() {
        let peer = PeerSnapshot {
            peer_id: 7,
            rtt_us: Some(812),
            delivery_bps: Some(u64::from(u32::MAX) * 4),
            peer_key: vec![1, 2, 3],
            ..Default::default()
        };
        let json = message("PeerSnapshot", &peer).unwrap();
        let text = document(serde_json::json!({ "peers": [json] })).unwrap();
        let parsed: Table = text.parse().unwrap();
        let peer = parsed["peers"].as_array().unwrap()[0].as_table().unwrap();
        assert_eq!(peer["rtt_us"].as_integer(), Some(812));
        assert_eq!(
            peer["delivery_bps"].as_integer(),
            Some(i64::from(u32::MAX) * 4)
        );
        assert_eq!(peer["peer_key"].as_str(), Some("AQID"));
        assert!(!peer.contains_key("loss_ppm"));

        // The generated serializer writes strings; normalizing restores numbers.
        let meta = SnapshotMeta {
            revision: 42,
            ..Default::default()
        };
        let pbjson = serde_json::to_value(&meta).unwrap();
        assert_eq!(pbjson["revision"], "42");
        let plain = normalize(descriptor("api.control.v1.SnapshotMeta").unwrap(), pbjson).unwrap();
        assert_eq!(plain["revision"], 42);
        assert!(method("GetNode").is_some() && method("Nope").is_none());
    }
}
