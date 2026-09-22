//! Process-wide descriptor bounds for expanded NAT traversal.

use anyhow::{Result, ensure};

// TCP workers retain this permit until cancellation destroys their sockets.
pub(super) static PERMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[cfg(unix)]
pub(super) fn open_descriptors() -> Result<usize> {
    #[cfg(target_os = "linux")]
    let directory = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let directory = "/dev/fd";
    let mut count = 0;
    for entry in std::fs::read_dir(directory)? {
        if entry?
            .file_name()
            .to_str()
            .is_some_and(|name| name.parse::<u64>().is_ok())
        {
            count += 1;
        }
    }
    // Counting the directory descriptor leaves conservative headroom.
    Ok(count)
}

pub(super) fn capacity(
    descriptors_per_candidate: usize,
    stream_reserve: usize,
    max_candidates: usize,
) -> Result<usize> {
    #[cfg(unix)]
    let descriptors = {
        use nix::sys::resource::{Resource, getrlimit};
        let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE)?;
        let soft = usize::try_from(soft).unwrap_or(usize::MAX);
        // Keep half the available descriptors for peers and control traffic.
        // Unrelated work can consume that headroom after this snapshot.
        soft.saturating_sub(open_descriptors()?) / 2
    };
    #[cfg(not(unix))]
    let descriptors = descriptors_per_candidate * max_candidates + stream_reserve;
    let count = (descriptors.saturating_sub(stream_reserve) / descriptors_per_candidate)
        .min(max_candidates);
    ensure!(
        count > 0,
        "process file limit leaves no expanded traversal capacity"
    );
    Ok(count)
}
