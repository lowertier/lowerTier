use std::sync::{Mutex, OnceLock, mpsc::Sender};

pub static LOGGER_LEVEL_SENDER: OnceLock<Mutex<Sender<String>>> = OnceLock::new();
pub static CURRENT_LOG_LEVEL: OnceLock<Mutex<String>> = OnceLock::new();
