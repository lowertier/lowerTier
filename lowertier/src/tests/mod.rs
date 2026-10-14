#[cfg(target_os = "linux")]
mod credential_tests;

pub fn set_env_var<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
    unsafe { std::env::set_var(key, value) }
}

pub fn remove_env_var<K: AsRef<std::ffi::OsStr>>(key: K) {
    unsafe { std::env::remove_var(key) }
}

#[cfg(target_os = "linux")]
pub fn get_guest_veth_name(net_ns: &str) -> &str {
    Box::leak(format!("veth_{}_g", net_ns).into_boxed_str())
}

#[cfg(target_os = "linux")]
pub fn get_host_veth_name(net_ns: &str) -> &str {
    Box::leak(format!("veth_{}_h", net_ns).into_boxed_str())
}

#[cfg(target_os = "linux")]
pub fn del_netns(name: &str) {
    // del veth host
    let _ = std::process::Command::new("ip")
        .args(["link", "del", get_host_veth_name(name)])
        .output();

    let _ = std::process::Command::new("ip")
        .args(["netns", "del", name])
        .output();
}

#[cfg(target_os = "linux")]
pub fn create_netns(name: &str, ipv4: &str, ipv6: &str) {
    // create netns
    let _ = std::process::Command::new("ip")
        .args(["netns", "add", name])
        .output()
        .unwrap();

    // set lo up
    let _ = std::process::Command::new("ip")
        .args(["netns", "exec", name, "ip", "link", "set", "lo", "up"])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args([
            "link",
            "add",
            get_host_veth_name(name),
            "type",
            "veth",
            "peer",
            "name",
            get_guest_veth_name(name),
        ])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args(["link", "set", get_guest_veth_name(name), "netns", name])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            name,
            "ip",
            "link",
            "set",
            get_guest_veth_name(name),
            "up",
        ])
        .output()
        .unwrap();

    let _ = std::process::Command::new("ip")
        .args(["link", "set", get_host_veth_name(name), "up"])
        .output()
        .unwrap();

    for ip in [ipv4, ipv6] {
        let _ = std::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                name,
                "ip",
                "addr",
                "add",
                ip,
                "dev",
                get_guest_veth_name(name),
            ])
            .output()
            .unwrap();
    }
}

#[cfg(target_os = "linux")]
pub fn add_ns_to_bridge(br_name: &str, ns_name: &str) {
    // use brctl to add ns to bridge
    let _ = std::process::Command::new("brctl")
        .args(["addif", br_name, get_host_veth_name(ns_name)])
        .output()
        .unwrap();

    // set bridge up
    let _ = std::process::Command::new("ip")
        .args(["link", "set", br_name, "up"])
        .output()
        .unwrap();
}

#[cfg(target_os = "linux")]
pub async fn drop_insts(insts: Vec<crate::instance::instance::Instance>) {
    let mut set = tokio::task::JoinSet::new();
    for mut inst in insts {
        set.spawn(async move {
            inst.clear_resources().await;
            let pm = std::sync::Arc::downgrade(&inst.get_peer_manager());
            drop(inst);
            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 5 && pm.strong_count() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert_eq!(pm.strong_count(), 0, "PeerManager should be dropped");
        });
    }
    while set.join_next().await.is_some() {}
}

#[cfg(target_os = "linux")]
pub async fn ping_test(from_netns: &str, target_ip: &str, payload_size: Option<usize>) -> bool {
    use crate::common::netns::{NetNS, ROOT_NETNS_NAME};
    let _g = NetNS::new(Some(ROOT_NETNS_NAME.to_owned())).guard();
    let code = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            from_netns,
            "ping",
            "-c",
            "1",
            "-s",
            payload_size.unwrap_or(56).to_string().as_str(),
            "-W",
            "1",
            target_ip.to_string().as_str(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    code.code().unwrap() == 0
}
