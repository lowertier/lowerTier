#[cfg(unix)]
pub(crate) mod unix;

#[cfg(unix)]
pub use unix::AsyncDevice;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::AsyncDevice;
