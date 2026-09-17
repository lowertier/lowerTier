use lowertier::core;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
use mimalloc::MiMalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
#[global_allocator]
static GLOBAL_MIMALLOC: MiMalloc = MiMalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
fn configure_mimalloc_rss() {
    // Matches mimalloc.h `mi_option_e` (v2.2). Must run before the first
    // heap alloc or the default 1 GiB arena is already reserved.
    const MI_OPTION_EAGER_COMMIT: i32 = 3;
    const MI_OPTION_ARENA_EAGER_COMMIT: i32 = 4;
    const MI_OPTION_PURGE_DELAY: i32 = 15;
    const MI_OPTION_ARENA_RESERVE: i32 = 23;
    unsafe extern "C" {
        fn mi_option_set(option: i32, value: std::ffi::c_long);
        fn mi_collect(force: bool);
    }
    unsafe {
        mi_option_set(MI_OPTION_EAGER_COMMIT, 0);
        mi_option_set(MI_OPTION_ARENA_EAGER_COMMIT, 0);
        mi_option_set(MI_OPTION_PURGE_DELAY, 0);
        // Internally KiB. 4 MiB arenas instead of the 1 GiB default.
        mi_option_set(MI_OPTION_ARENA_RESERVE, 4096);
        mi_collect(true);
    }
}

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc"), target_os = "linux"))]
extern "C" fn preinit_mimalloc_rss() {
    configure_mimalloc_rss();
}

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc"), target_os = "linux"))]
#[used]
#[unsafe(link_section = ".preinit_array")]
static PREINIT_MIMALLOC_RSS: [extern "C" fn(); 1] = [preinit_mimalloc_rss];

#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", feature = "jemalloc-prof", unix))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19,retain:false\0";

#[cfg(all(feature = "jemalloc", not(feature = "jemalloc-prof"), unix))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"retain:false\0";

rust_i18n::i18n!("locales", fallback = "en");

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc"), unix))]
fn ensure_mimalloc_env() {
    use std::os::unix::process::CommandExt as _;
    if std::env::var_os("MIMALLOC_PURGE_DELAY").is_some() {
        configure_mimalloc_rss();
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => {
            configure_mimalloc_rss();
            return;
        }
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let error = std::process::Command::new(exe)
        .args(args)
        .env("MIMALLOC_EAGER_COMMIT", "0")
        .env("MIMALLOC_ARENA_EAGER_COMMIT", "0")
        .env("MIMALLOC_PURGE_DELAY", "0")
        .env("MIMALLOC_ARENA_RESERVE", "4M")
        .exec();
    panic!("re-exec with mimalloc RSS options failed: {error}");
}

fn main() -> std::process::ExitCode {
    #[cfg(all(feature = "mimalloc", not(feature = "jemalloc"), unix))]
    ensure_mimalloc_env();
    #[cfg(all(feature = "mimalloc", not(feature = "jemalloc"), not(unix)))]
    configure_mimalloc_rss();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(core::main())
}
