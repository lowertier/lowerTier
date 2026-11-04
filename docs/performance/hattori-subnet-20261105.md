# Hattori subnet routing and GUI repair, 2026-11-05

The investigation reproduced unnecessary QUIC socket replacement, incorrect return routing, and nested VPN transport.
The repair preserves QUIC NAT mappings, subnet return routes, and an independent Tailscale transport path.
The GUI now starts on loopback and the instance overlay address by default.

## Confirmed causes

The recurring QUIC delay came from the client route watcher.
Every route generation could replace an established UDP socket, even when its source address did not change.
This also changed the local UDP port and its NAT mapping.
The trace showed Hattori RTT at 8.9 ms immediately after authentication.
One second later, RTT reset to Quinn's 333 ms initial value.
Repeated path validation failures followed, with congestion resets and queued datagrams.
Application pings then took one to three seconds.

A regression with a port-restricted NAT model reproduced the unexpected socket replacement.
An unrelated route check changed the UDP source port from 24717 to 29732.
The corrected check preserves that port and delivers packets in both directions.
Actual source changes still use authenticated path validation and rollback.

Alibj received traffic from the Hattori LAN, but Tailscale policy table 52 selected the reply path.
The main table already contained `192.168.51.0/24 dev lowertier`.
Before a source policy rule, the LAN test host received no replies from five pings.
Its connection to `10.126.126.110:22` also timed out.
A temporary source rule restored eight replies and the SSH banner.
The deployed rule now supplies this behavior automatically.
The temporary rule was removed before final delivery checks.

The Mac also needs LowTier return routes for forwarded LAN SSH.
An early isolation experiment removed these routes and interrupted the connection.
Capture showed a SYN entering `utun1` and its SYN-ACK leaving through Tailscale on `utun0`.
The repair restores LAN routes while excluding the router address `192.168.51.1`.
Tailscale retains the route to that router address.
The temporary router host route was removed after the persistent CIDR exclusions took effect.

Capture on Hattori's LowTier interface showed Tailscale UDP transport on port 41641.
The endpoints included LowTier addresses, so existing Tailscale sessions depended on LowTier delivery.
An owned firewall table now rejects this transport on the LowTier interface.
The rule counters confirmed matches while Tailscale retained its independent relay path.
The old Hattori UCI rule `network.lowertier_osku_prefer` is disabled.
That rule forced `172.25.0.0/16` into the main routing table.

The old GUI configuration restricted several nodes to one overlay client.
Some userspace instances had no usable operating system listener.
The new default starts loopback before the overlay address becomes available.
Each co-resident instance has a separate loopback port.

## Source changes

QUIC clients capture their initial routing source and source interface.
An unrelated route event now rechecks source selection without replacing the socket.
A source change, interface change, or local policy denial can still require replacement.
This preserves explicit discovery source bindings and avoids resetting healthy NAT paths.
Migration authentication, validation budgets, cooldown, and rollback remain active.

For `P` client paths and `R` unrelated route updates, the old watcher could replace `P × R` sockets.
Each replacement starts validation and resets congestion state.
The 333 ms initial RTT and 166.5 ms variance give a base probe timeout near one second.
The local validation deadline uses three probe timeouts, which explains pauses lasting several seconds.
Unchanged routes now create no replacement sockets or validation traffic.

Linux native interfaces install one source policy rule for their overlay IPv4 address.
The rule uses priority 5150 and the main table, with its default route suppressed.
It matches unmarked packets and preserves explicitly marked traffic.
Strict rule matching prevents cleanup from deleting unrelated policy rules.
Repeated installation and removal are idempotent.

GUI listener tasks and accepted HTTP connections follow instance lifetime.
Restart applies GUI settings and releases old listener ports.
Without an explicit allow list, the GUI permits authenticated clients from its overlay subnet.
Explicit allow lists and existing keyless access settings remain authoritative.
The shared connection limit remains 32.

Userspace GUI traffic must retain its source address and instance selection.
The optimized proxy declines the enabled overlay GUI port and uses packet delivery.
The generic TCP proxy also declines initial GUI SYN packets before listener registration.

Loopback GUI ports are protected across independent Unix processes with file locks.
GUI listeners hold an exclusive lock before accepting connections.
Local proxy connections hold a shared lock through the operating system TCP connect.
This prevents a proxy from entering another daemon's loopback GUI.
The standalone GUI also protects its selected port before listening.
Empty lock files remain in `/tmp` to prevent unlink races.
The locks release when their file descriptors close.
The implementation uses the standard library's [file lock API](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock).

## Measurements

These are delivery checks on the running test network.
They are not a matched transport throughput benchmark.

| Check | Delivery | RTT or result |
| --- | --- | --- |
| Initial Mac to Hattori LowTier ping | 20% loss | Approximately 1.9 seconds average |
| Initial Mac to Hattori Tailscale ping | 12.5% loss | Approximately 1.26 seconds average |
| First isolation check, LowTier | 300/300 | 5.85 ms average; 21.24 ms maximum |
| First isolation check, Tailscale | 300/300 | 22.06 ms average; 27.38 ms maximum |
| Deployed routing repair, LowTier | 200/200 | 5.61 ms average; 33.19 ms maximum |
| Deployed routing repair, Tailscale | 200/200 | 22.30 ms average; 41.48 ms maximum |
| Later LowTier check, 160 seconds | 160/160 | 5.95 ms average; 40.65 ms maximum |
| QUIC repair `91e67194`, ten route notifications | 80/80 | 5.89 ms average; 7.15 ms maximum; both UDP sockets unchanged |
| Final `fdc33ef5`, ten route notifications | 80/80 | 9.99 ms average; 91.44 ms maximum; both UDP sockets unchanged |
| Authenticated SSH through the LAN host | 120/120 messages | 44.13 ms median; 136.83 ms p95; 199.88 ms maximum |
| LAN to alibj, after temporary rule removal | 30/30 | 134.22 ms average; 502.70 ms maximum |
| LAN to alibj SSH | Banner received | `SSH-2.0-OpenSSH_9.9` |
| Final fleet, LowTier | 200/200 | 7.76 ms average; 92.37 ms maximum |
| Final fleet, Tailscale | 200/200 | 22.73 ms average; 28.22 ms maximum |
| Final fleet, authenticated subnet SSH | 120/120 messages | 47.84 ms median; 154.11 ms p95; 223.74 ms maximum |
| Final fleet, LAN to alibj | 30/30 | 88.62 ms average; 122.05 ms maximum; SSH banner received |

The SSH check uses a Tailscale ProxyCommand to reach the LAN host `192.168.51.170`.
The forwarded leg connects through Hattori to `boyu@10.126.126.2`.
The control connection contributes to the measured echo latency.
The test alternates short messages and 4096-byte messages.

An earlier dense alibj ping check received 17 of 20 replies, with 442 ms average RTT.
The later one-second check received all 30 replies.
Both results remain in the evidence.
The final alibj check measured 79–122 ms.
The LAN host also received HTTP 200 from the Hattori and alibj GUI pages.

Fresh Hattori QUIC sessions initially measured approximately 5 ms after isolation and restart.
A later Mac restart reproduced the delay and exposed the route-watcher defect described above.
The earlier temporary recovery therefore did not establish a complete fix.

The diagnostic throughput checks measured 20.94 Mbit/s upstream and 25.52 Mbit/s downstream.
The reverse sender reported 2656 retransmissions.
These single checks do not support a throughput improvement claim.
No MTU change was made.

## Verification and deployment

The native core suite covers QUIC migration, GUI defaults, access boundaries, restart, and listener cleanup.
The Caddy tests were also run explicitly and passed.
The working tree's core suite passed 482 tests, with two Caddy tests run separately.
The focused migration suite passed all four cases after the final namespace correction.
Privileged Linux kernel tests verified policy rule identity and repeated add/remove operations on 862jp.

The GUI proxy regression uses three independent local userspace daemons.
It checks correct instance selection, access keys, Host checks, and blocked loopback proxy access.
The old candidate reproduced the loopback access defect.
The test waits for both loopback and overlay listener readiness.

The fleet contains 15 instances on ten hosts, including this Mac.
Every instance receives a loopback listener and an overlay listener.
Loopback ports are 15880 and 15881 on hosts with two instances.
Overlay GUI ports remain 15880.
The listener checks reject wildcard bindings.
Overlay API checks verify the expected instance and an authenticated response.

The deployment preserves network identities, keys, network ACLs, and configuration ownership.
The fleet GUI allow lists admit the LowTier subnet and Hattori LAN with existing authentication settings.
Recovery copies remain available for each replaced binary and configuration.
Tw2's older recovery binary was archived locally with its SHA256 before reclaiming disk space.
The previous binaries and configurations remain available for recovery.

The first local deployment failed because a root-created configuration replaced a user-owned file.
The deployment restored the previous binary and configurations.
The corrected procedure preserves configuration owner and mode before writing changes.
One Mac rollout also rolled back after hard links made executable path verification ambiguous.
Separate Mac binary copies resolved that verification failure.
A diagnostic restart command timed out and caused one failed launch.
The service recovered, and the final deployment removed the temporary diagnostic environment.

Private audit logs and raw measurements remain in `benchmark-results/.work/hattori-connection-20261105/`.
The audit records commands, process IDs, exit codes, recovery actions, and binary hashes.
The public deployment summary contains no credentials.
It records all 15 instances running production source commit `fdc33ef5`.
See the [deployment summary and binary hashes](hattori-subnet-20261105.json).
