//! Generate typed config differences from the protobuf schema at build time.
//! Runtime config dumping must not initialize the full reflection descriptor pool.
use proc_macro2::{Ident, Span, TokenStream};
use prost_reflect::{DescriptorPool, Kind};
use quote::quote;
use std::{error::Error, path::Path};

fn value_expression(kind: Kind) -> Result<TokenStream, Box<dyn Error>> {
    Ok(match kind {
        Kind::Bool | Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 | Kind::Uint32 | Kind::Fixed32 => {
            quote!(serde_json::Value::from(*value))
        }
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 | Kind::Uint64 | Kind::Fixed64 => {
            quote!(serde_json::Value::String(value.to_string()))
        }
        Kind::String => quote!(serde_json::Value::String(value.clone())),
        Kind::Enum(descriptor) => {
            let mut names = std::collections::BTreeMap::new();
            for variant in descriptor.values() {
                names
                    .entry(variant.number())
                    .or_insert_with(|| variant.name().to_owned());
            }
            let arms = names.iter().map(
                |(number, name)| quote!(#number => serde_json::Value::String(#name.to_owned()),),
            );
            quote!(match *value { #(#arms)* other => serde_json::Value::from(other) })
        }
        other => {
            return Err(format!(
                "unsupported config flag kind {other:?}; extend typed diff generation"
            )
            .into());
        }
    })
}

pub fn generate(pool: &DescriptorPool, out: &Path) -> Result<(), Box<dyn Error>> {
    let descriptor = pool
        .get_message_by_name("common.FlagsInConfig")
        .ok_or("FlagsInConfig schema is missing")?;
    let mut comparisons = Vec::new();
    for field in descriptor.fields() {
        if matches!(field.name(), "relay" | "camouflage") {
            continue;
        }
        if field.is_map()
            || field
                .containing_oneof()
                .is_some_and(|oneof| !oneof.is_synthetic())
        {
            return Err(format!(
                "unsupported flag shape {}; extend typed diff generation",
                field.full_name()
            )
            .into());
        }
        let name = field.name();
        let ident = Ident::new_raw(name, Span::call_site());
        let expression = value_expression(field.kind())?;
        let insert = if field.is_list() {
            quote! {
                let values = flags.#ident.iter().map(|value| #expression).collect();
                result.insert(#name.to_owned(), serde_json::Value::Array(values));
            }
        } else if field.supports_presence() {
            quote! {
                if let Some(value) = flags.#ident.as_ref() {
                    result.insert(#name.to_owned(), #expression);
                }
            }
        } else {
            quote! {
                let value = &flags.#ident;
                result.insert(#name.to_owned(), #expression);
            }
        };
        comparisons.push(quote! { if flags.#ident != defaults.#ident { #insert } });
    }
    let generated = quote! {
        fn flags_diff_from_default(flags: &Flags) -> serde_json::Map<String, serde_json::Value> {
            let defaults = gen_default_flags();
            let mut result = serde_json::Map::new();
            #(#comparisons)*
            result
        }
    };
    std::fs::write(out.join("flags_diff.rs"), generated.to_string())?;
    Ok(())
}
