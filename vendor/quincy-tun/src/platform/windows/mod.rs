mod device;
mod dns;
pub(crate) mod ffi;
mod interrupt;
mod netsh;
mod tun;

pub use device::DeviceImpl;
pub(crate) use interrupt::InterruptEvent;
