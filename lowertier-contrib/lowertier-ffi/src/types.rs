use std::ffi::{c_char};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValuePair {
    pub key: *const c_char,
    pub value: *const c_char,
}
