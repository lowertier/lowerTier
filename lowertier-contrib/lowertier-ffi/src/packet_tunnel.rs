use std::ffi::{CString, c_char, c_int};

use lowertier::common::config::{ConfigLoader, TomlConfigLoader, process_secure_mode_cfg};
use serde_json::{Value, json};

use crate::{error::set_error_msg, strings::c_str_to_string};

fn reject_file_references(value: &toml::Value) -> Result<(), String> {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if key.ends_with("_file")
                    || key == "file"
                    || key == "dir"
                    || (matches!(key.as_str(), "tls_cert" | "tls_key")
                        && value.as_str().is_some_and(|path| !path.is_empty()))
                {
                    return Err("Import a standalone configuration without file references.".into());
                }
                reject_file_references(value)?;
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                reject_file_references(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn prepare_config(text: &str) -> Result<Value, String> {
    let mut public: toml::Value = toml::from_str(text).map_err(|error| error.to_string())?;
    reject_file_references(&public)?;
    let table = public
        .as_table_mut()
        .ok_or("The configuration must be a TOML table.")?;
    // The extension owns the interface and exposes control through provider messages.
    for (section, key, value) in [
        ("gui", "enabled", toml::Value::Boolean(false)),
        ("tun", "mode", toml::Value::String("kernel".into())),
    ] {
        let section = table
            .entry(section)
            .or_insert_with(|| toml::Value::Table(Default::default()));
        section
            .as_table_mut()
            .ok_or("The configuration section must be a table.")?
            .insert(key.into(), value);
    }
    let config = TomlConfigLoader::new_from_str(
        &toml::to_string(&public).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if config.get_dhcp() {
        return Err("Use a static overlay address for the iOS VPN profile.".into());
    }
    let ipv4 = config
        .get_ipv4()
        .ok_or("Set address.ipv4 before connecting.")?;
    let mut secure = config.get_secure_mode().unwrap_or_default();
    secure.enabled = true;
    let secure = process_secure_mode_cfg(secure).map_err(|error| error.to_string())?;
    config.set_secure_mode(Some(secure));
    let id = config.get_id();
    config.set_id(id);
    let mut flags = config.get_flags();
    // Use the fleet MTU. The operating system and the core must agree.
    flags.mtu = 1280;
    config.set_flags(flags);
    let prefix = ipv4.network_length();
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let address = u32::from(ipv4.address());
    let mut routes = vec![json!({
        "address": std::net::Ipv4Addr::from(address & mask).to_string(),
        "mask": std::net::Ipv4Addr::from(mask).to_string(),
    })];
    for route in config.get_routes().unwrap_or_default() {
        let length = route.network_length();
        let mask = if length == 0 {
            0
        } else {
            u32::MAX << (32 - length)
        };
        routes.push(json!({
            "address": route.first_address().to_string(),
            "mask": std::net::Ipv4Addr::from(mask).to_string(),
        }));
    }
    let ipv6 = config.get_ipv6().map(|ip| {
        let prefix = ip.network_length();
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        json!({
            "address": ip.address().to_string(), "prefix": prefix,
            "network": std::net::Ipv6Addr::from(u128::from(ip.address()) & mask).to_string(),
        })
    });
    Ok(json!({
        "config": config.dump(),
        "instance_name": config.get_inst_name(),
        "instance_id": id.to_string(),
        "network_name": config.get_network_identity().network_name,
        "ipv4": ipv4.address().to_string(),
        "mask": std::net::Ipv4Addr::from(mask).to_string(),
        "routes": routes,
        "ipv6": ipv6,
        "mtu": 1280,
    }))
}

pub(crate) unsafe fn prepare(config: *const c_char, output: *mut *const c_char) -> c_int {
    if output.is_null() {
        set_error_msg("output is null");
        return -1;
    }
    unsafe { *output = std::ptr::null() };
    let result = (|| {
        let text = unsafe { c_str_to_string(config, "config") }?;
        let value = prepare_config(&text)?;
        CString::new(value.to_string()).map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => {
            unsafe { *output = value.into_raw() };
            0
        }
        Err(error) => {
            set_error_msg(&error);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_profile_preserves_identity_and_matches_interface_settings() {
        let text = r#"
[node]
instance_name = "ios-test"
[network]
name = "ios-test"
secret = "local-fixture"
[address]
ipv4 = "10.44.0.9/24"
ipv6 = "fd44::9/64"
[tun]
mode = "none"
mtu = 1400
"#;
        let prepared = prepare_config(text).unwrap();
        let restored = prepare_config(prepared["config"].as_str().unwrap()).unwrap();
        assert_eq!(prepared["ipv4"], "10.44.0.9");
        assert_eq!(prepared["mask"], "255.255.255.0");
        assert_eq!(prepared["mtu"], 1280);
        assert_eq!(prepared["ipv6"]["address"], "fd44::9");
        assert_eq!(prepared["ipv6"]["network"], "fd44::");
        assert_eq!(prepared["ipv6"]["prefix"], 64);
        assert_eq!(prepared["instance_id"], restored["instance_id"]);
        let first = TomlConfigLoader::new_from_str(prepared["config"].as_str().unwrap()).unwrap();
        let second = TomlConfigLoader::new_from_str(restored["config"].as_str().unwrap()).unwrap();
        assert_eq!(
            first.get_secure_mode().unwrap().local_private_key,
            second.get_secure_mode().unwrap().local_private_key
        );
        assert_eq!(first.get_gui_config().enabled, Some(false));
        assert_eq!(first.get_flags().mtu, 1280);
        assert!(
            prepare_config("[network]\nsecret_file = '/missing'")
                .unwrap_err()
                .contains("standalone")
        );
        for field in ["tls_cert", "tls_key"] {
            assert!(
                prepare_config(&format!("[camouflage]\n{field} = '/missing'"))
                    .unwrap_err()
                    .contains("standalone")
            );
        }
        assert!(prepare_config("[address]\ndhcp = true").is_err());
        assert!(prepare_config("[network]\nname = 'missing-address'\nsecret = 'fixture'").is_err());
    }
}
