use std::ffi::{CString, c_char, c_int};

use crate::{
    error::set_error_msg,
    state::{ASYNC_RUNTIME, INSTANCE_MANAGER},
    strings::{c_str_to_string, optional_c_str_to_string},
};

/// # Safety
/// See `crate::call_json_rpc`.
pub(crate) unsafe fn call_json_rpc(
    service_name: *const c_char,
    method_name: *const c_char,
    domain_name: *const c_char,
    payload_json: *const c_char,
    out_response_json: *mut *const c_char,
) -> c_int {
    if out_response_json.is_null() {
        set_error_msg("out_response_json is null");
        return -1;
    }
    unsafe {
        *out_response_json = std::ptr::null();
    }

    let service_name = match unsafe { c_str_to_string(service_name, "service_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let method_name = match unsafe { c_str_to_string(method_name, "method_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let domain_name = match unsafe { optional_c_str_to_string(domain_name, "domain_name") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let payload_json = match unsafe { c_str_to_string(payload_json, "payload_json") } {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };
    let before = INSTANCE_MANAGER.list_network_instance_ids();
    let (response, _remote_guard) = match serde_json::from_str::<serde_json::Value>(&payload_json) {
        Ok(payload) => {
            match ASYNC_RUNTIME.block_on(lowertier::rpc_service::control::call_owned_json_locked(
                &INSTANCE_MANAGER,
                &service_name,
                &method_name,
                domain_name.as_deref(),
                payload,
            )) {
                Ok(value) => value,
                Err(err) => {
                    set_error_msg(&format!("RPC Error: {}", err));
                    return -1;
                }
            }
        }
        Err(_) => (
            serde_json::json!({"error": lowertier::proto::api::control::v1::ApiError {
                code: "invalid_argument".into(), message: "The control request JSON is invalid.".into(), field_path: "payload_json".into(), retryable: false,
            }}),
            None,
        ),
    };
    if matches!(
        method_name.as_str(),
        "CreateInstance" | "StartInstance" | "StopInstance" | "DeleteInstance"
    ) && response.get("error").is_none()
    {
        let _guard = crate::state::INSTANCE_MUTATION_LOCK.lock().unwrap();
        let after = INSTANCE_MANAGER.list_network_instance_ids();
        let mut removed = before
            .into_iter()
            .filter(|id| !after.contains(id))
            .collect::<Vec<_>>();
        if method_name == "StopInstance" {
            if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_json) {
                if let Ok(request) = serde_json::from_value::<
                    lowertier::proto::api::control::v1::StopInstanceRequest,
                >(payload)
                {
                    let selected = request
                        .meta
                        .and_then(|meta| meta.instance_id.parse().ok())
                        .or_else(|| (after.len() == 1).then(|| after[0]));
                    if let Some(id) = selected {
                        removed.push(id);
                    }
                }
            }
        }
        crate::data_plane::remove_data_plane_handles_by_instance_ids(&removed);
        crate::state::INSTANCE_NAME_ID_MAP.clear();
        for id in after {
            if let Some(name) = INSTANCE_MANAGER.get_instance_name(&id) {
                crate::state::INSTANCE_NAME_ID_MAP.insert(name, id);
            }
        }
    }
    let response_json = match serde_json::to_string(&response) {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&format!("failed to serialize RPC response: {}", err));
            return -1;
        }
    };
    let response_json = match CString::new(response_json) {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&format!("failed to allocate RPC response: {}", err));
            return -1;
        }
    };

    unsafe {
        *out_response_json = response_json.into_raw();
    }
    0
}
