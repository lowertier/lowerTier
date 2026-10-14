//! C ABI facade for LowTier.
//!
//! This file exposes the C API. Internal modules implement the operations.
//!
//! Network management APIs:
//! - `parse_config`: validate a TOML network config string.
//! - `run_network_instance`: start one local network instance from TOML.
//! - `retain_network_instance`: keep named instances and stop all others.
//! - `delete_network_instance`: stop named local network instances.
//! - `list_instance`: list running instance names and IDs.
//! - `collect_network_infos`: collect running instance info as key/value pairs.
//! - `set_tun_fd`: attach a TUN file descriptor to a named instance.
//! - `call_json_rpc`: call an exposed LowTier RPC service with JSON payload.
//!
//! Data plane APIs, enabled by the `ffi-dataplane` feature:
//! - `data_plane_tcp_connect`: open an outbound TCP data-plane stream.
//! - `data_plane_tcp_bind`: bind a TCP data-plane listener.
//! - `data_plane_tcp_accept`: accept a TCP data-plane connection.
//! - `data_plane_tcp_read`: read from a TCP data-plane stream.
//! - `data_plane_tcp_write`: write to a TCP data-plane stream.
//! - `data_plane_tcp_close`: close a TCP data-plane stream.
//! - `data_plane_tcp_listener_close`: close a TCP data-plane listener.
//! - `data_plane_udp_bind`: bind a UDP data-plane socket.
//! - `data_plane_udp_send_to`: send one UDP data-plane datagram.
//! - `data_plane_udp_recv_from`: receive one UDP data-plane datagram.
//! - `data_plane_udp_close`: close a UDP data-plane socket.
//! - `data_plane_*_start` / `data_plane_*_finish`: asynchronous data-plane operations.
//! - `data_plane_async_op_*`: poll, wait, cancel, and free asynchronous operations.
//!
//! Shared FFI helper APIs:
//! - `get_error_msg`: copy the last FFI error message.
//! - `free_string`: release strings allocated by this library.

mod data_plane;
#[cfg(feature = "ffi-dataplane")]
mod data_plane_async;
mod error;
mod instance_api;
mod json_rpc;
mod state;
mod strings;
mod types;

#[cfg(test)]
mod tests;

pub use types::KeyValuePair;

use std::ffi::{c_char, c_int};
#[cfg(feature = "ffi-dataplane")]
use std::ffi::{c_uchar, c_ushort};

// ===== Network Management API =====

/// Validate a TOML network config string.
///
/// This only parses and validates the config. It does not start an instance and
/// does not change global FFI state.
///
/// # Safety
/// `cfg_str` must be a non-null pointer to a null-terminated UTF-8 string.
///
/// # Return
/// Returns `0` if the config parses successfully, or `-1` on failure. On
/// failure, call `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn parse_config(cfg_str: *const c_char) -> c_int {
    unsafe { instance_api::parse_config(cfg_str) }
}

/// Start one local LowTier network instance from a TOML config string.
///
/// The config's `inst_name` must be unique among instances started through this FFI layer.
///
/// # Safety
/// `cfg_str` must be a non-null pointer to a null-terminated UTF-8 string.
///
/// # Return
/// Returns `0` after the instance is started and registered in the FFI name
/// cache, or `-1` on failure. On failure, call `get_error_msg` on the same
/// thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn run_network_instance(cfg_str: *const c_char) -> c_int {
    unsafe { instance_api::run_network_instance(cfg_str) }
}

/// Keep the named network instances and stop all other instances.
///
/// Passing `length == 0` stops all instances. When `length > 0`, `inst_names`
/// must point to an array of `length` non-null C strings. Instances that are not
/// retained are removed from the FFI name cache and any related data-plane
/// handles are closed.
///
///
/// # Safety
/// If `length > 0`, `inst_names` must be a non-null pointer to an array of
/// `length` non-null pointers to null-terminated UTF-8 strings.
///
/// # Return
/// Returns `0` on success, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn retain_network_instance(
    inst_names: *const *const c_char,
    length: usize,
) -> c_int {
    unsafe { instance_api::retain_network_instance(inst_names, length) }
}

/// Stop the named network instances.
///
/// Passing `length == 0` is a no-op. When `length > 0`, `inst_names` must point
/// to an array of `length` non-null C strings. Unknown names are ignored.
/// Removed instances are also removed from the FFI name cache and any related
/// data-plane handles are closed.
///
///
/// # Safety
/// If `length > 0`, `inst_names` must be a non-null pointer to an array of
/// `length` non-null pointers to null-terminated UTF-8 strings.
///
/// # Return
/// Returns `0` on success, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn delete_network_instance(
    inst_names: *const *const c_char,
    length: usize,
) -> c_int {
    unsafe { instance_api::delete_network_instance(inst_names, length) }
}

/// List running network instance names and IDs.
///
/// Writes up to `max_length` entries into `infos`. Each returned key is the
/// instance name and each returned value is the instance ID string. Returned
/// key/value strings are allocated by this library and must be released with
/// `free_string`.
///
///
/// # Safety
/// If `max_length > 0`, `infos` must be a non-null pointer to writable storage
/// for at least `max_length` `KeyValuePair` values.
///
/// # Return
/// Returns the number of entries written, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn list_instance(infos: *mut KeyValuePair, max_length: usize) -> c_int {
    unsafe { instance_api::list_instance(infos, max_length) }
}

/// Collect running network instance information.
///
/// Writes up to `max_length` entries into `infos`. Each returned key is the
/// instance name and each returned value is a JSON string containing that
/// instance's running information. Returned key/value strings are allocated by
/// this library and must be released with `free_string`.
///
///
/// # Safety
/// If `max_length > 0`, `infos` must be a non-null pointer to writable storage
/// for at least `max_length` `KeyValuePair` values.
///
/// # Return
/// Returns the number of entries written, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> c_int {
    unsafe { instance_api::collect_network_infos(infos, max_length) }
}

/// Attach a TUN file descriptor to a named network instance.
///
/// The instance must already have been registered in the FFI name cache by
/// `run_network_instance`.
///
/// # Safety
/// `inst_name` must be a non-null pointer to a null-terminated UTF-8 string.
/// `fd` must be a valid TUN file descriptor owned by the caller.
///
/// # Return
/// Returns `0` if the descriptor is accepted by the instance, or `-1` on
/// failure.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn set_tun_fd(inst_name: *const c_char, fd: c_int) -> c_int {
    unsafe { instance_api::set_tun_fd(inst_name, fd) }
}

/// Call an exposed LowTier RPC method using protobuf JSON.
///
/// Use `api.control.v1.ControlPlaneV1Rpc` and a PascalCase method name.
/// The request uses pbjson field names, such as `meta.instance_id`.
/// Instance requests can access only instances owned by this FFI manager.
/// Credential methods also require `meta.admin_token`.
/// `domain_name` must be null or empty.
/// API failures return the shared `error` envelope with an `ApiError` value.
///
/// On success, writes a newly allocated JSON response string to
/// `out_response_json`. The caller must release it with `free_string`.
///
///
/// # Safety
/// `service_name`, `method_name`, `payload_json`, and `out_response_json` must
/// be non-null. String pointers must point to null-terminated UTF-8 strings.
/// `domain_name` may be null.
///
/// # Return
/// Returns `0` on success, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn call_json_rpc(
    service_name: *const c_char,
    method_name: *const c_char,
    domain_name: *const c_char,
    payload_json: *const c_char,
    out_response_json: *mut *const c_char,
) -> c_int {
    unsafe {
        json_rpc::call_json_rpc(
            service_name,
            method_name,
            domain_name,
            payload_json,
            out_response_json,
        )
    }
}

// ===== Data Plane API =====

/// Open an outbound TCP stream through an LowTier instance data plane.
///
/// On success, writes the local address selected for the connection into
/// `out_local_ip` and `out_local_port`. The returned IP string is allocated by
/// this library and must be released with `free_string`.
///
/// # Safety
/// `inst_name`, `dst_ip`, `out_local_ip`, and `out_local_port` must be non-null.
/// String pointers must point to null-terminated UTF-8 strings.
///
/// # Return
/// Returns a non-zero TCP stream handle on success, or `0` on failure. On
/// failure, call `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_connect(
    inst_name: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane::data_plane_tcp_connect(
            inst_name,
            dst_ip,
            dst_port,
            timeout_ms,
            out_local_ip,
            out_local_port,
        )
    }
}

/// Bind a TCP listener through an LowTier instance data plane.
///
/// On success, writes the bound local address into `out_local_ip` and
/// `out_local_port`. The returned IP string is allocated by this library and
/// must be released with `free_string`.
///
/// # Safety
/// `inst_name`, `out_local_ip`, and `out_local_port` must be non-null.
/// `inst_name` must point to a null-terminated UTF-8 string.
///
/// # Return
/// Returns a non-zero TCP listener handle on success, or `0` on failure. On
/// failure, call `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_bind(
    inst_name: *const c_char,
    local_port: c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane::data_plane_tcp_bind(
            inst_name,
            local_port,
            timeout_ms,
            out_local_ip,
            out_local_port,
        )
    }
}

/// Accept one connection from a TCP data-plane listener.
///
/// On success, writes both local and peer socket addresses to the output
/// pointers. Returned IP strings are allocated by this library and must be
/// released with `free_string`.
///
/// # Safety
/// All output pointers must be non-null and writable. `handle` must be a valid
/// TCP listener handle returned by `data_plane_tcp_bind`.
///
/// # Return
/// Returns a non-zero TCP stream handle on success, or `0` on failure. On
/// failure, call `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_accept(
    handle: u64,
    timeout_ms: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
    out_peer_ip: *mut *const c_char,
    out_peer_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane::data_plane_tcp_accept(
            handle,
            timeout_ms,
            out_local_ip,
            out_local_port,
            out_peer_ip,
            out_peer_port,
        )
    }
}

/// Read bytes from a TCP data-plane stream.
///
/// # Safety
/// `handle` must be a valid TCP stream handle returned by
/// `data_plane_tcp_connect` or `data_plane_tcp_accept`. `buf` must be non-null
/// and writable for `len` bytes.
///
/// # Return
/// Returns the number of bytes read, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_read(
    handle: u64,
    buf: *mut c_uchar,
    len: u32,
    timeout_ms: u64,
) -> c_int {
    unsafe { data_plane::data_plane_tcp_read(handle, buf, len, timeout_ms) }
}

/// Write bytes to a TCP data-plane stream.
///
/// This function attempts to write exactly `len` bytes before returning
/// success.
///
/// # Safety
/// `handle` must be a valid TCP stream handle returned by
/// `data_plane_tcp_connect` or `data_plane_tcp_accept`. `buf` must be non-null
/// and readable for `len` bytes.
///
/// # Return
/// Returns `len` on success, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_write(
    handle: u64,
    buf: *const c_uchar,
    len: u32,
    timeout_ms: u64,
) -> c_int {
    unsafe { data_plane::data_plane_tcp_write(handle, buf, len, timeout_ms) }
}

/// Close a TCP data-plane stream handle.
///
/// # Return
/// Returns `0` on success, or `-1` if the handle is missing, is not a TCP stream
/// handle, or data-plane calls are currently rejected.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_tcp_close(handle: u64) -> c_int {
    data_plane::data_plane_tcp_close(handle)
}

/// Close a TCP data-plane listener handle.
///
/// # Return
/// Returns `0` on success, or `-1` if the handle is missing, is not a TCP
/// listener handle, or data-plane calls are currently rejected.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_tcp_listener_close(handle: u64) -> c_int {
    data_plane::data_plane_tcp_listener_close(handle)
}

/// Bind a UDP socket through an LowTier instance data plane.
///
/// On success, writes the bound local address into `out_local_ip` and
/// `out_local_port`. The returned IP string is allocated by this library and
/// must be released with `free_string`.
///
/// # Safety
/// `inst_name`, `out_local_ip`, and `out_local_port` must be non-null.
/// `inst_name` must point to a null-terminated UTF-8 string.
///
/// # Return
/// Returns a non-zero UDP socket handle on success, or `0` on failure. On
/// failure, call `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_bind(
    inst_name: *const c_char,
    local_port: c_ushort,
    timeout_ms: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane::data_plane_udp_bind(
            inst_name,
            local_port,
            timeout_ms,
            out_local_ip,
            out_local_port,
        )
    }
}

/// Send one UDP datagram through a data-plane socket.
///
/// # Safety
/// `handle` must be a valid UDP socket handle returned by
/// `data_plane_udp_bind`. `dst_ip` must be non-null and point to a
/// null-terminated UTF-8 string. `buf` must be non-null and readable for `len`
/// bytes.
///
/// # Return
/// Returns the number of bytes sent, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_send_to(
    handle: u64,
    dst_ip: *const c_char,
    dst_port: c_ushort,
    buf: *const c_uchar,
    len: u32,
    timeout_ms: u64,
) -> c_int {
    unsafe { data_plane::data_plane_udp_send_to(handle, dst_ip, dst_port, buf, len, timeout_ms) }
}

/// Receive one UDP datagram from a data-plane socket.
///
/// On success, writes the peer address into `out_ip` and `out_port`. The
/// returned IP string is allocated by this library and must be released with
/// `free_string`.
///
/// # Safety
/// `handle` must be a valid UDP socket handle returned by
/// `data_plane_udp_bind`. `buf`, `out_ip`, and `out_port` must be non-null.
/// `buf` must be writable for `len` bytes.
///
/// # Return
/// Returns the number of bytes received, or `-1` on failure. On failure, call
/// `get_error_msg` on the same thread to retrieve details.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_recv_from(
    handle: u64,
    buf: *mut c_uchar,
    len: u32,
    out_ip: *mut *const c_char,
    out_port: *mut c_ushort,
    timeout_ms: u64,
) -> c_int {
    unsafe { data_plane::data_plane_udp_recv_from(handle, buf, len, out_ip, out_port, timeout_ms) }
}

/// Close a UDP data-plane socket handle.
///
/// # Return
/// Returns `0` on success, or `-1` if the handle is missing, is not a UDP
/// socket handle, or data-plane calls are currently rejected.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_udp_close(handle: u64) -> c_int {
    data_plane::data_plane_udp_close(handle)
}

// ===== Async Data Plane API =====

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_async_op_status(handle: u64) -> c_int {
    data_plane_async::data_plane_async_op_status(handle)
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_async_op_wait(handle: u64, timeout_ms: u64) -> c_int {
    data_plane_async::data_plane_async_op_wait(handle, timeout_ms)
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_async_op_cancel(handle: u64) -> c_int {
    data_plane_async::data_plane_async_op_cancel(handle)
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_async_op_free(handle: u64) -> c_int {
    data_plane_async::data_plane_async_op_free(handle)
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_free_bytes(ptr: *const c_uchar, len: u32) {
    data_plane_async::data_plane_free_bytes(ptr, len)
}

/// Start an asynchronous TCP data-plane connection.
///
/// # Safety
/// `inst_name` and `dst_ip` must be non-null pointers to null-terminated UTF-8
/// strings. The strings only need to remain valid for the duration of this
/// call.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_connect_start(
    inst_name: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_ushort,
    timeout_ms: u64,
) -> u64 {
    unsafe {
        data_plane_async::data_plane_tcp_connect_start(inst_name, dst_ip, dst_port, timeout_ms)
    }
}

/// Finish an asynchronous TCP data-plane connection.
///
/// On success, writes the stream local address into `out_local_ip` and
/// `out_local_port`. The returned IP string is allocated by this library and
/// must be released with `free_string`.
///
/// # Safety
/// `out_local_ip` and `out_local_port` must be non-null pointers to writable
/// storage.
///
/// # Return
/// Returns a non-zero TCP stream handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_connect_finish(
    op_handle: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane_async::data_plane_tcp_connect_finish(op_handle, out_local_ip, out_local_port)
    }
}

/// Start an asynchronous TCP data-plane bind.
///
/// # Safety
/// `inst_name` must be a non-null pointer to a null-terminated UTF-8 string.
/// The string only needs to remain valid for the duration of this call.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_bind_start(
    inst_name: *const c_char,
    local_port: c_ushort,
    timeout_ms: u64,
) -> u64 {
    unsafe { data_plane_async::data_plane_tcp_bind_start(inst_name, local_port, timeout_ms) }
}

/// Finish an asynchronous TCP data-plane bind.
///
/// On success, writes the listener local address into `out_local_ip` and
/// `out_local_port`. The returned IP string is allocated by this library and
/// must be released with `free_string`.
///
/// # Safety
/// `out_local_ip` and `out_local_port` must be non-null pointers to writable
/// storage.
///
/// # Return
/// Returns a non-zero TCP listener handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_bind_finish(
    op_handle: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe { data_plane_async::data_plane_tcp_bind_finish(op_handle, out_local_ip, out_local_port) }
}

/// Start an asynchronous TCP data-plane accept on a listener handle.
///
/// # Safety
/// `handle` must be a valid TCP listener handle returned by
/// `data_plane_tcp_bind` or `data_plane_tcp_bind_finish`.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_accept_start(handle: u64, timeout_ms: u64) -> u64 {
    unsafe { data_plane_async::data_plane_tcp_accept_start(handle, timeout_ms) }
}

/// Finish an asynchronous TCP data-plane accept.
///
/// On success, writes the accepted stream local address into `out_local_ip` and
/// `out_local_port`, and the peer address into `out_peer_ip` and
/// `out_peer_port`. Returned IP strings are allocated by this library and must
/// be released with `free_string`.
///
/// # Safety
/// `out_local_ip`, `out_local_port`, `out_peer_ip`, and `out_peer_port` must be
/// non-null pointers to writable storage.
///
/// # Return
/// Returns a non-zero TCP stream handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_accept_finish(
    op_handle: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
    out_peer_ip: *mut *const c_char,
    out_peer_port: *mut c_ushort,
) -> u64 {
    unsafe {
        data_plane_async::data_plane_tcp_accept_finish(
            op_handle,
            out_local_ip,
            out_local_port,
            out_peer_ip,
            out_peer_port,
        )
    }
}

/// Start an asynchronous TCP data-plane read.
///
/// # Safety
/// `handle` must be a valid TCP stream handle returned by
/// `data_plane_tcp_connect_finish` or `data_plane_tcp_accept_finish`.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_read_start(
    handle: u64,
    max_len: u32,
    timeout_ms: u64,
) -> u64 {
    unsafe { data_plane_async::data_plane_tcp_read_start(handle, max_len, timeout_ms) }
}

/// Finish an asynchronous TCP data-plane read.
///
/// On success, writes the received buffer pointer and length into `out_buf` and
/// `out_len`. The returned buffer is allocated by this library and must be
/// released with `data_plane_free_bytes`.
///
/// # Safety
/// `out_buf` and `out_len` must be non-null pointers to writable storage.
///
/// # Return
/// Returns the number of bytes read, or `-1` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_read_finish(
    op_handle: u64,
    out_buf: *mut *const c_uchar,
    out_len: *mut u32,
) -> c_int {
    unsafe { data_plane_async::data_plane_tcp_read_finish(op_handle, out_buf, out_len) }
}

/// Start an asynchronous TCP data-plane write.
///
/// The input bytes are copied before this function returns.
///
/// # Safety
/// `handle` must be a valid TCP stream handle returned by
/// `data_plane_tcp_connect_finish` or `data_plane_tcp_accept_finish`. If `len`
/// is non-zero, `buf` must be non-null and readable for `len` bytes.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_write_start(
    handle: u64,
    buf: *const c_uchar,
    len: u32,
    timeout_ms: u64,
) -> u64 {
    unsafe { data_plane_async::data_plane_tcp_write_start(handle, buf, len, timeout_ms) }
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_tcp_write_finish(op_handle: u64) -> c_int {
    data_plane_async::data_plane_tcp_write_finish(op_handle)
}

/// Start an asynchronous UDP data-plane bind.
///
/// # Safety
/// `inst_name` must be a non-null pointer to a null-terminated UTF-8 string.
/// The string only needs to remain valid for the duration of this call.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_bind_start(
    inst_name: *const c_char,
    local_port: c_ushort,
    timeout_ms: u64,
) -> u64 {
    unsafe { data_plane_async::data_plane_udp_bind_start(inst_name, local_port, timeout_ms) }
}

/// Finish an asynchronous UDP data-plane bind.
///
/// On success, writes the socket local address into `out_local_ip` and
/// `out_local_port`. The returned IP string is allocated by this library and
/// must be released with `free_string`.
///
/// # Safety
/// `out_local_ip` and `out_local_port` must be non-null pointers to writable
/// storage.
///
/// # Return
/// Returns a non-zero UDP socket handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_bind_finish(
    op_handle: u64,
    out_local_ip: *mut *const c_char,
    out_local_port: *mut c_ushort,
) -> u64 {
    unsafe { data_plane_async::data_plane_udp_bind_finish(op_handle, out_local_ip, out_local_port) }
}

/// Start an asynchronous UDP data-plane send.
///
/// The input bytes are copied before this function returns.
///
/// # Safety
/// `handle` must be a valid UDP socket handle returned by
/// `data_plane_udp_bind_finish`. `dst_ip` must be a non-null pointer to a
/// null-terminated UTF-8 string. If `len` is non-zero, `buf` must be non-null
/// and readable for `len` bytes.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_send_to_start(
    handle: u64,
    dst_ip: *const c_char,
    dst_port: c_ushort,
    buf: *const c_uchar,
    len: u32,
    timeout_ms: u64,
) -> u64 {
    unsafe {
        data_plane_async::data_plane_udp_send_to_start(
            handle, dst_ip, dst_port, buf, len, timeout_ms,
        )
    }
}

#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_udp_send_to_finish(op_handle: u64) -> c_int {
    data_plane_async::data_plane_udp_send_to_finish(op_handle)
}

/// Start an asynchronous UDP data-plane receive.
///
/// # Safety
/// `handle` must be a valid UDP socket handle returned by
/// `data_plane_udp_bind_finish`.
///
/// # Return
/// Returns a non-zero async operation handle on success, or `0` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_recv_from_start(
    handle: u64,
    max_len: u32,
    timeout_ms: u64,
) -> u64 {
    unsafe { data_plane_async::data_plane_udp_recv_from_start(handle, max_len, timeout_ms) }
}

/// Finish an asynchronous UDP data-plane receive.
///
/// On success, writes the received buffer into `out_buf` and `out_len`, and
/// the peer address into `out_ip` and `out_port`. The returned buffer is
/// allocated by this library and must be released with `data_plane_free_bytes`;
/// the returned IP string must be released with `free_string`.
///
/// # Safety
/// `out_buf`, `out_len`, `out_ip`, and `out_port` must be non-null pointers to
/// writable storage.
///
/// # Return
/// Returns the number of bytes received, or `-1` on failure.
#[cfg(feature = "ffi-dataplane")]
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_recv_from_finish(
    op_handle: u64,
    out_buf: *mut *const c_uchar,
    out_len: *mut u32,
    out_ip: *mut *const c_char,
    out_port: *mut c_ushort,
) -> c_int {
    unsafe {
        data_plane_async::data_plane_udp_recv_from_finish(
            op_handle, out_buf, out_len, out_ip, out_port,
        )
    }
}

// ===== Shared FFI Helper API =====

/// Return the last FFI error message.
///
/// Synchronous API failures are stored in a thread-local buffer, so call this
/// on the same thread that received `-1` or `0` from another API. Config-server
/// callback delivery failures may happen on a runtime thread; those are stored
/// globally and are included here so direct FFI callers can still retrieve the
/// last callback error. If there is no error message, this writes a null pointer
/// to `out`.
///
/// The returned string is allocated by this library and must be released with
/// `free_string`.
///
/// # Safety
/// `out` must be a non-null pointer to writable storage for one C string
/// pointer.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn get_error_msg(out: *mut *const c_char) {
    unsafe { error::get_error_msg(out) }
}

/// Release a C string allocated by this library.
///
/// Use this for strings returned through `get_error_msg`,
/// `collect_network_infos`, and data-plane address output parameters. Passing a
/// null pointer is allowed and has no effect.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn free_string(s: *const c_char) {
    error::free_string(s)
}
