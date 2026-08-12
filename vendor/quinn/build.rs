fn main() {
    // Avoid cfg_aliases! here. Nightly treats trailing semicolons from that
    // macro expansion as hard errors in expression position.
    println!("cargo:rustc-check-cfg=cfg(wasm_browser)");
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_family == "wasm" && target_os == "unknown" {
        println!("cargo:rustc-cfg=wasm_browser");
    }
}
