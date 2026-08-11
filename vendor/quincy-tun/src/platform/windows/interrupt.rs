use crate::platform::windows::ffi;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};

pub(crate) struct InterruptEvent {
    pub(crate) handle: OwnedHandle,
}

impl InterruptEvent {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            handle: ffi::create_event()?,
        })
    }

    pub(crate) fn trigger(&self) -> io::Result<()> {
        ffi::set_event(self.handle.as_raw_handle())
    }
}
