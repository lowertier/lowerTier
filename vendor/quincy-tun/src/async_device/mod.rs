#[cfg(unix)]
pub(crate) mod unix;

#[cfg(unix)]
pub use unix::AsyncDevice;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub use unix::{GsoReadContinuation, RecvMultipleResult};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::AsyncDevice;
