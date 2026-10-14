use crate::{
    state::{
        INSTANCE_MANAGER, INSTANCE_NAME_ID_MAP, find_instance_id_by_name,
        lock_remote_instance_mutation, remove_instance_name_ids,
    },
    *,
};
use lowertier::common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader};
use serde_json::Value;
use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char, c_void},
    sync::{Mutex, mpsc},
    time::Duration,
};
use uuid::Uuid;

#[test]
fn test_parse_config() {
    let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
    let cstr = std::ffi::CString::new(cfg_str).unwrap();
    unsafe {
        assert_eq!(parse_config(cstr.as_ptr()), 0);
    }
}

#[test]
fn test_run_network_instance() {
    let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
    let cstr = std::ffi::CString::new(cfg_str).unwrap();
    unsafe {
        assert_eq!(run_network_instance(cstr.as_ptr()), 0);
    }
}

fn take_last_error() -> Option<String> {
    unsafe {
        let mut error_ptr: *const c_char = std::ptr::null();
        get_error_msg(&mut error_ptr);
        if error_ptr.is_null() {
            None
        } else {
            let error = CStr::from_ptr(error_ptr).to_string_lossy().into_owned();
            free_string(error_ptr);
            Some(error)
        }
    }
}

fn free_key_value_pairs(infos: &[KeyValuePair]) {
    for info in infos {
        free_string(info.key);
        free_string(info.value);
    }
}

#[test]
fn list_instance_returns_instance_names_and_ids() {
    let instance_id = Uuid::new_v4();
    let instance_name = format!("list-instance-{}", instance_id);
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    cfg.set_inst_name(instance_name.clone());
    INSTANCE_MANAGER
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();
    INSTANCE_NAME_ID_MAP.insert(instance_name.clone(), instance_id);

    let mut infos = vec![
        KeyValuePair {
            key: std::ptr::null(),
            value: std::ptr::null(),
        };
        16
    ];
    let count = unsafe { list_instance(infos.as_mut_ptr(), infos.len()) };
    assert!(count > 0);

    let mut found = false;
    for info in infos.iter().take(count as usize) {
        let key = unsafe { CStr::from_ptr(info.key) }.to_string_lossy();
        let value = unsafe { CStr::from_ptr(info.value) }.to_string_lossy();
        if key == instance_name {
            assert_eq!(value, instance_id.to_string());
            found = true;
        }
    }

    free_key_value_pairs(&infos[..count as usize]);
    INSTANCE_MANAGER
        .delete_network_instance(vec![instance_id])
        .unwrap();
    remove_instance_name_ids(&[instance_id]);
    assert!(found);
}

#[test]
fn list_instance_allows_zero_length() {
    assert_eq!(unsafe { list_instance(std::ptr::null_mut(), 0) }, 0);
}

#[test]
fn list_instance_rejects_null_output_pointer() {
    assert_eq!(unsafe { list_instance(std::ptr::null_mut(), 1) }, -1);
    assert!(take_last_error().unwrap().contains("infos is null"));
}

#[test]
fn call_json_rpc_returns_logger_response() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{}").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        0
    );
    assert!(!response_ptr.is_null());
    let response = unsafe { CStr::from_ptr(response_ptr) }
        .to_string_lossy()
        .into_owned();
    free_string(response_ptr);
    let response: Value = serde_json::from_str(&response).unwrap();
    assert!(response.get("level").is_some());
}

#[test]
fn call_json_rpc_rejects_instance_management_service() {
    let service = CString::new("api.manage.WebClientService").unwrap();
    let method = CString::new("list_network_instance").unwrap();
    let payload = CString::new("{}").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        -1
    );
    assert!(response_ptr.is_null());
    assert!(take_last_error().unwrap().contains("not exposed"));
}

#[test]
fn call_json_rpc_rejects_malformed_payload_json() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        -1
    );
    assert!(response_ptr.is_null());
    assert!(
        take_last_error()
            .unwrap()
            .contains("failed to parse payload_json")
    );
}

#[test]
fn call_json_rpc_rejects_null_output_pointer() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{}").unwrap();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                std::ptr::null_mut(),
            )
        },
        -1
    );
    assert!(
        take_last_error()
            .unwrap()
            .contains("out_response_json is null")
    );
}

#[test]
fn find_instance_id_by_name_resolves_uncommitted_manager_instance_name() {
    let instance_id = Uuid::new_v4();
    let inst_name = format!("test-{}", instance_id);
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    cfg.set_inst_name(inst_name.clone());
    INSTANCE_MANAGER
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();

    assert_eq!(find_instance_id_by_name(&inst_name), Some(instance_id));
    INSTANCE_MANAGER
        .delete_network_instance(vec![instance_id])
        .unwrap();
    remove_instance_name_ids(&[instance_id]);
}

#[test]
fn delete_network_instance_removes_only_named_instances() {
    let keep_id = Uuid::new_v4();
    let delete_id = Uuid::new_v4();
    let keep_name = format!("keep-{}", keep_id);
    let delete_name = format!("delete-{}", delete_id);

    for (id, name) in [
        (keep_id, keep_name.clone()),
        (delete_id, delete_name.clone()),
    ] {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(id);
        cfg.set_inst_name(name.clone());
        INSTANCE_MANAGER
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        INSTANCE_NAME_ID_MAP.insert(name, id);
    }

    let delete_name = CString::new(delete_name.clone()).unwrap();
    let inst_names = [delete_name.as_ptr()];
    assert_eq!(
        unsafe { delete_network_instance(inst_names.as_ptr(), inst_names.len()) },
        0
    );

    assert_eq!(find_instance_id_by_name(&keep_name), Some(keep_id));
    assert!(find_instance_id_by_name(delete_name.to_str().unwrap()).is_none());

    INSTANCE_MANAGER
        .delete_network_instance(vec![keep_id])
        .unwrap();
    remove_instance_name_ids(&[keep_id]);
}

#[test]
fn retain_and_delete_network_instance_reject_invalid_name_pointers() {
    assert_eq!(unsafe { retain_network_instance(std::ptr::null(), 1) }, -1);
    assert_eq!(unsafe { delete_network_instance(std::ptr::null(), 1) }, -1);

    let inst_names = [std::ptr::null()];
    assert_eq!(
        unsafe { retain_network_instance(inst_names.as_ptr(), inst_names.len()) },
        -1
    );
    assert_eq!(
        unsafe { delete_network_instance(inst_names.as_ptr(), inst_names.len()) },
        -1
    );
}

#[test]
fn ffi_remote_mutation_lock_uses_manager_lock() {
    let manager_guard = INSTANCE_MANAGER
        .remote_mutation_lock()
        .blocking_lock_owned();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ffi_guard = lock_remote_instance_mutation();
        done_tx.send(()).unwrap();
    });

    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(manager_guard);
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    waiter.join().unwrap();
}

#[cfg(feature = "ffi-dataplane")]
#[test]
fn async_op_invalid_handle_helpers_are_stable() {
    assert_eq!(data_plane_async_op_status(u64::MAX), -2);
    assert_eq!(data_plane_async_op_wait(u64::MAX, 1), -2);
    assert_eq!(data_plane_async_op_cancel(u64::MAX), -2);
    assert_eq!(data_plane_async_op_free(u64::MAX), -2);
    data_plane_free_bytes(std::ptr::null(), 0);
}
