# Fleet kernel endpoint audit, November 14, 2026

Ten of the twelve retained instances use the native kernel interface.
The s6916 speed repair remains active.
The other nine native instances already used kernel mode.
Their configuration and MTUs remain unchanged.
Two instances cannot use kernel mode with their current privileges.

The repair changes the TCP endpoint configuration.
It does not change the userspace TCP implementation.
The validated application build remains version `0.03`, commit `d91b334a`.

## Fleet state

| Host | Overlay address | Mode | Configured MTU | Application | Result |
| --- | --- | --- | --- | --- | --- |
| Local Mac | `10.126.126.2` | Kernel | 1300 | 0.03 | Verified |
| 862jp | `10.126.126.82` | Kernel | 1160 | 0.03 | Verified |
| jpali | `10.126.126.62` | Kernel | 1160 | 0.03 | Verified |
| s6916 | `10.126.126.60` | Kernel | 1280 | 0.03 | Verified repair |
| JPaws | `10.126.126.100` | Kernel | Default | 0.03 | Verified |
| 861jp | `10.126.126.81` | Kernel | 1360 | 0.03 | Verified |
| AliBJ | `10.126.126.110` | Kernel | 1360 | 0.03 | Verified |
| Hattori | `10.126.126.1` | Kernel | 1360 | 0.03 | Verified |
| BTROUTER | `10.126.126.40` | Kernel | 1360 | 0.03 | Verified |
| LA | `10.126.126.87` | Kernel | Default | 0.03 | Verified |
| Remote Mac | `10.126.126.3` | Userspace | 1360 | 0.03 | Administrator access required |
| Taiwan | `10.126.126.80` | Userspace | 1300 | 0.02 observed | Container privileges required; binary update pending |

The table reports configured MTUs.
The s6916 Linux TAP interface has a measured MTU of 1260.
Configured and effective MTUs can differ.
The fleet audit did not normalize MTUs.
The two exit instances retain their configured MTU of 1160.

The remote Mac runs as UID 504.
Noninteractive sudo requires a password.
Root SSH authentication failed.
Both checked LowTier system launch service labels were absent.
The userspace instance remains active.

Taiwan runs inside a Podman container.
Its effective and bounding capability masks are `00000000800405fb`.
The container lacks `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, and `CAP_NET_RAW`.
It has no `/dev/net/tun` or registered TUN device.
The existing service therefore remains in userspace mode.
The audit did not change container security policy.

The historical `btower` and `UTMOWRT` hosts remain pending.
Tailscale reported both hosts offline.
Their last recorded contact dates were October 17 and October 27, 2026, respectively.
The audit did not start retired instances.

## Verification

The eleven current-build instances passed these checks at 13:06 UTC:

- Each host exposes one retained LowTier instance.
- Instance IDs, public keys, addresses, routes, transport settings, and GUI settings match the initial snapshots.
- Each host has authenticated receiving peer connections over H2, QUIC, and WSS.
- All eleven Web UI pages accept `10.126.126.2` without a key.
- All eleven node API reads accept the same source without a key.
- All eleven node APIs reject a foreign Origin with HTTP 403.
- All three required source networks remain in `gui.allow` and `gui.open`.
- The ten remote hosts returned all 30 ICMP probes.

The required source networks are `10.126.126.0/24`, `192.168.51.0/24`, and `192.168.40.0/24`.
The GUI remains enabled on overlay TCP port 15880.
The earlier LAN and outside-source access tests remain historical evidence.
This audit did not repeat those source-network tests.
Taiwan has no successful overlay verification in this audit.

The repair report for s6916 contains the performance acceptance evidence:
[s6916 TCP speed repair](s6916-userspace-tcp-20261114.md).
The final two downloads measured 451.0 and 451.3 Mbit/s.
The final two uploads measured 393.6 and 413.5 Mbit/s.
Those trials used one TCP stream between the local native Mac and s6916.
They included two warmup seconds and ten measurement seconds.
The report also records delivery, latency, retransmission, CPU, and memory evidence.
These rates do not establish performance for other host pairs.
No new kernel migration completed during this audit.
The existing scenario baseline remains selected.

## Access failures and recovery

BTROUTER did not accept SSH on its Tailscale address.
Access through JPaws and the existing Tailscale subnet route succeeded.
The first router inspection used unsupported BusyBox `ps` options.
The OpenWrt process inspection recovered the correct configuration path.
The subsequent node and overlay checks passed.

Taiwan accepted initial inspection and a protected configuration read.
Later SSH sessions repeatedly timed out.
Direct IPv4, direct Tailscale IPv6, and the JPaws SSH forwarding path failed.
The Tailscale stream path through JPaws also failed.
The Hattori forwarding path transferred part of the candidate.
A subsequent read confirmed an incomplete file of 412,160 bytes.
The file remains at `/opt/lowertier/.fleet-kernel-20261114/lowertier.new` for the unfinished deployment.
The complete candidate and protected configuration reference remain in the local audit directory.
No replacement binary has been installed on Taiwan.
The final runtime check at 13:41 UTC confirmed version `0.02`, PID 189214, and an active service.

Two alternate download attempts used a temporary source on JPaws.
The source bound only to Tailscale address `100.123.70.87`, port 18564.
Its application artifact matched the validated transfer artifact.
Both attempts lost their SSH control connections.
The source received no download request.
Final cleanup checks found no remaining download helpers or Tailscale download clients.
The temporary source process and compressed transfer file were removed.
The source log remains available.

## Records and limits

The audit records are in `benchmark-results/.work/fleet-kernel-20261114/`.
`result.json` records the final fleet state and pending work.
`verification.json` contains the eleven passing node results.
`audit.jsonl` records fleet commands, directories, process IDs, output, exit codes, and recovery attempts.
Protected configuration files and the deployment archive remain outside version control.
The audit preserves configuration, keys, logs, raw measurements, and the existing application baseline.

Some early local file-discovery failures lack JSONL process metadata.
Their errors remain in the tool transcript.
The fleet command records and final verification have complete process records.
An independent review found no discrepancies in node counts, modes, MTUs, blockers, or performance scope.
The primary agent checked the final transfer and cleanup outcomes after that review.
This audit did not change Rust source or a deployed configuration.
It did not repeat library, Caddy, or throughput tests.
The existing source tests and s6916 performance evidence remain the relevant baseline.
The checks establish current delivery and access.
They do not establish long-term availability or a fleet-wide throughput improvement.
