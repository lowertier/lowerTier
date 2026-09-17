use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;

static PROTECTED_TCP_PORTS: Lazy<Mutex<HashMap<u16, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register_protected_tcp_port(port: u16) {
    let mut ports = PROTECTED_TCP_PORTS.lock().unwrap();
    *ports.entry(port).or_default() += 1;
}

pub fn unregister_protected_tcp_port(port: u16) {
    let mut ports = PROTECTED_TCP_PORTS.lock().unwrap();
    if let Some(ref_count) = ports.get_mut(&port) {
        *ref_count -= 1;
        if *ref_count == 0 {
            ports.remove(&port);
        }
    }
}

pub fn is_protected_tcp_port(port: u16) -> bool {
    PROTECTED_TCP_PORTS.lock().unwrap().contains_key(&port)
}

#[cfg(test)]
pub fn clear_protected_tcp_ports_for_test() {
    PROTECTED_TCP_PORTS.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::{
        clear_protected_tcp_ports_for_test, is_protected_tcp_port, register_protected_tcp_port,
        unregister_protected_tcp_port,
    };
}
