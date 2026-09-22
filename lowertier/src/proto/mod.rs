pub mod rpc_impl;
pub mod rpc_types;

pub mod acl;
pub mod api;
pub mod common;
pub mod error;
#[cfg(feature = "magic-dns")]
pub mod magic_dns;
pub mod peer_rpc;
pub mod web;

#[cfg(test)]
pub mod tests;
pub mod utils;

pub const DESCRIPTOR_POOL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/runtime_descriptor_set.bin"));

pub const ALL_DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));

#[cfg(test)]
mod descriptor_tests {
    use prost_reflect::{DescriptorPool, DynamicMessage, Value};

    #[test]
    fn runtime_descriptor_preserves_schema_without_source_metadata() {
        let schema = DescriptorPool::global()
            .get_message_by_name("google.protobuf.FileDescriptorSet")
            .unwrap();
        let original = include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
        let mut expected = DynamicMessage::decode(schema.clone(), original.as_slice()).unwrap();
        let runtime = DynamicMessage::decode(schema, super::DESCRIPTOR_POOL_BYTES).unwrap();
        let Value::List(files) = expected.get_field_by_name_mut("file").unwrap() else {
            panic!("descriptor files must be a list");
        };
        assert!(!files.is_empty());
        for file in files {
            let Value::Message(file) = file else {
                panic!("descriptor file must be a message");
            };
            assert!(file.has_field_by_name("source_code_info"));
            file.clear_field_by_name("source_code_info");
        }
        assert_eq!(runtime, expected);
        assert!(super::DESCRIPTOR_POOL_BYTES.len() < original.len());
    }
}
