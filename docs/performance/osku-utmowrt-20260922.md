# Automatic interface selection and TCP rendezvous

Date: 2026-09-22, Japan time.
All three protocols established authenticated direct connections between osku and UTMOWRT.
All 30 LowTier transfer trials passed the before, during, and after path checks.
No physical interface name was fixed in the traversal code or fixture configuration.
The implementation preserves TLS exporter binding and peer authentication.

## Delivered TCP throughput

Each cell gives the median and full range from two 20-second runs, in Mb/s.

| Underlay | Streams | osku → UTM | UTM → osku |
| --- | ---: | ---: | ---: |
| QUIC | 1 | 82.7 (79.6–85.8) | 262.4 (262.2–262.5) |
| QUIC | 4 | 236.7 (219.7–253.8) | 419.1 (408.8–429.4) |
| H2 | 1 | 585.8 (584.6–586.9) | 470.5 (464.2–476.7) |
| H2 | 4 | 592.7 (581.1–604.4) | 490.4 (488.5–492.3) |
| WSS | 1 | 593.2 (591.1–595.2) | 437.0 (407.5–466.5) |
| WSS | 4 | 518.7 (398.4–639.0) | 498.8 (498.4–499.1) |

## Observed Tailscale relay baseline

These trials use changing peer-relay paths. They are not a matched direct-underlay comparison.

| Streams | osku → UTM, median (range), Mb/s | UTM → osku, median (range), Mb/s |
| ---: | ---: | ---: |
| 1 | 398.9 (388.9–408.8) | 296.0 (204.1–387.8) |
| 4 | 207.8 (9.1–406.5) | 216.8 (14.3–419.3) |

| Direction | Streams | Repeat | Delivered Mb/s | Relay observations |
| --- | ---: | ---: | ---: | --- |
| down | 1 | 1 | 204.1 | s6916 → jpali → jpali |
| down | 1 | 2 | 387.8 | s6916 → s6916 → s6916 |
| down | 4 | 1 | 14.3 | jpali → jpali → s6916 |
| down | 4 | 2 | 419.3 | s6916 → s6916 → s6916 |
| up | 1 | 1 | 388.9 | s6916 → s6916 → s6916 |
| up | 1 | 2 | 408.8 | s6916 → s6916 → s6916 |
| up | 4 | 1 | 9.1 | jpali → jpali → jpali |
| up | 4 | 2 | 406.5 | s6916 → s6916 → s6916 |

## UDP delivery

Each case sends 1,000-byte payloads at 10 Mb/s for 20 seconds. Each case runs once.

| Underlay | Direction | Delivered Mb/s | Lost / packets | iperf-reported sequence delivery | Byte delivery | Jitter, ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | osku → UTM | 9.992 | 0 / 25154 | 100.0000% | 100.0000% | 0.071 |
| QUIC | UTM → osku | 9.953 | 120 / 25164 | 99.5235% | 99.4559% | 0.167 |
| H2 | osku → UTM | 9.990 | 0 / 25032 | 100.0000% | 99.9720% | 0.149 |
| H2 | UTM → osku | 9.997 | 7 / 25141 | 99.9722% | 99.9046% | 0.164 |
| WSS | osku → UTM | 9.992 | 0 / 25024 | 100.0000% | 100.0000% | 0.122 |
| WSS | UTM → osku | 9.993 | 16 / 25023 | 99.9361% | 99.8682% | 0.209 |
| Tailscale relay | osku → UTM | 9.985 | 0 / 25128 | 100.0000% | 99.9881% | 0.055 |
| Tailscale relay | UTM → osku | 10.000 | 0 / 25002 | 100.0000% | 99.8841% | 0.188 |

## CPU and memory

These values aggregate all eight TCP trials per transport. CPU units are CPU-seconds per delivered Gbit.

| Transport | Host | Process CPU/Gbit | Whole-host CPU/Gbit | RSS range, MiB |
| --- | --- | ---: | ---: | ---: |
| QUIC | osku | 1.327 | 10.812 | 30.0–71.8 |
| QUIC | utm | 2.690 | 3.875 | 28.1–48.5 |
| H2 | osku | 0.373 | 3.708 | 29.2–85.2 |
| H2 | utm | 1.637 | 2.619 | 23.4–45.5 |
| WSS | osku | 0.405 | 4.227 | 29.4–94.8 |
| WSS | utm | 1.768 | 2.800 | 30.7–39.0 |
| Tailscale relay | osku | 3.702 | 12.535 | 257.3–258.0 |
| Tailscale relay | utm | 3.129 | 4.027 | 133.6–168.2 |
| Tailscale relay | relay | 2.459 | 2.350 | 442.6–445.9 |
| Tailscale relay | relay-jpali | 0.099 | 0.107 | 56.1–127.0 |

## Latency and transfer evidence

| Direct underlay | RTT during TCP trials, median (range), ms | Delivered TCP GiB | Tunnel TX bytes / delivered byte | Application TCP retransmissions, up / down range |
| --- | ---: | ---: | ---: | --- |
| QUIC | 14.19 (13.64–17.20) | 4.675 | 1.073 | 0–0 / 227–3257 |
| H2 | 17.70 (15.51–19.06) | 9.990 | 1.065 | 0–0 / 0–1 |
| WSS | 23.18 (20.83–26.53) | 9.572 | 1.065 | 0–13 / 0–0 |

## Result limits

QUIC single-stream upload remains slower than H2 and WSS on this fixture.
These measurements do not establish the cause of that throughput difference.
WSS four-stream upload varied from 398.4 to 639.0 Mb/s. Both repetitions remain included.

Reverse UDP sequence loss was 0.4765% for QUIC, 0.0278% for H2, and 0.0639% for WSS.
QUIC reported zero declared underlay packet loss during its UDP trials.
The WSS reverse trial reported zero macOS UDP socket-buffer drops.
The location of the application packet loss remains unresolved.
UDP sequence delivery and byte delivery use different counters and can differ at the timed-test boundary.
Sequence delivery uses iperf's reported loss percentage. It can differ slightly from the displayed lost-packet quotient.

QUIC declared sender packet-loss estimates during TCP trials ranged from 0.0432% to 0.0917% upstream.
The corresponding reverse range was 0.0327% to 0.1447%.
QUIC path samples bracketed each transfer over approximately 22–24 seconds.
Observed UDP payload MTUs ranged from 1,200 to 1,420 bytes.
Tunnel byte ratios include LowTier headers and reverse traffic. They exclude some transport and IP overhead.

Tailscale used s6916 and jpali peer relays. It did not report a direct endpoint in the final snapshots.
Eight of ten final trials retained the same reported relay at all three checks.
The two preliminary path-transition trials delivered 379.8 and 109.4 Mb/s upstream.
Their receipts remain available, but those trials are outside the planned final matrix.
Both peer relays run Tailscale 1.102.2. The endpoint versions also differ.
Both endpoint tunnel MTUs were 1,280 bytes.

Actual CPU sampling windows were 23.90–26.41 seconds on osku and 23–24 seconds on the Linux hosts.
The relay label in the CPU table means s6916. The relay-jpali label means jpali.
Both relay process and host counters include other Tailscale traffic.
The s6916 host recorded 5.02 seconds of steal time across all ten final trials. This time is excluded from CPU consumption.
Its host busy counter was slightly lower than its process CPU counter.
This counter inconsistency remains unresolved. Do not subtract these values to estimate isolated kernel overhead.

The fixture processes stopped after measurement. Temporary fixture credentials and raw remote logs were removed after audit capture.
Production VPN services and firewall rules were not changed.

## Interface selection

Production traversal does not select `eth0`, `en0`, or a MAP-E interface by name.
Explicit test restrictions remain configuration values.

The local Tailscale reference separates candidate discovery from socket routing:

- `ref/tailscale/net/netmon/state.go`, `LocalAddresses`, collects addresses from usable interfaces.
- `ref/tailscale/net/netns/netns_linux.go` normally applies a routing mark. Its fallback discovers the default interface.
- `ref/tailscale/net/netns/netns_darwin.go` discovers an interface index from current route information.
- `ref/tailscale/wgengine/magicsock/endpoint.go` coordinates UDP probes through `CallMeMaybe` messages.

LowTier now admits Linux point-to-point WAN links without a hardware-type whitelist.
It applies configured interface and address restrictions after discovery.
Socket binding resolves the selected source address to its current interface.
The macOS binding code now supplies a terminated interface name and rejects an invalid interface index.
The hardware-type change applies to Linux.
macOS retains its existing physical-interface discovery.
FreeBSD and Windows retain their existing MAC-address and point-to-point filters.
LowTier does not reproduce every Tailscale interface-selection rule.
Configured underlay exclusions remain necessary when the selected OS route uses another overlay.

## H2 and WSS rendezvous

Both protocols use TCP simultaneous open through authenticated peer RPC.
TCP and TLS roles remain independent.
The initiator selects one TLS stream with a random rendezvous token.
The peers then verify their identities with the existing TLS exporter binding.

TCP STUN retains its connections during traversal.
STUN, listening, and simultaneous-open sockets share the reserved source port.
Socket creation and local policy checks use the configured network namespace.
The `tcp_stun_servers` configuration field permits an explicit TCP STUN fixture.

## Observed NAT behavior

Osku has local IPv4 addresses under `172.25.0.0/16` and public address `133.1.22.2`.
UTM owns `14.10.162.66` on its current MAP-E interface.
Its inspected NAT rule assigns 240 external ports sequentially to new flows.

The first H2 traversal test discovered different TCP mappings at each STUN destination.
The peer connections did not complete.
A separate TCP listener on one assigned UTM port accepted an osku connection without a firewall change.
The traversal code now tries an additional mapped-port binding when the mapped address equals the selected local address.
The binding is exclusive. It cannot share an existing service port.
TCP retains its original listener, source port, candidates, and STUN connections.
QUIC retries both the mapped-port socket and the original STUN socket across available source addresses.
An actual authenticated connection must succeed before either path becomes active.
This behavior uses no MAP-E name, port range, or hardware-type constant.

Tailscale did not establish a direct path in five probes from each endpoint.
Osku runs Tailscale 1.102.3. UTM runs Tailscale 1.94.1.
Every probe used the s6916 peer relay.
Reported RTT was 24–25 ms.
These results are relay measurements.

## Verification and evidence

The focused tests cover rendezvous authentication, TLS binding, stream nomination, source-port retention, and interface-name independence.
The Caddy tests cover both backends, shared website traffic, and unauthorized probes.
Caddy 2.11.4 with caddy-l4 0.1.2 passed both integration tests.
Windows port-sharing behavior has not been tested on a Windows host.

The final traversal suite passed 28 tests.
The transport regression suite passed 25 tests.
Its two initially ignored Caddy tests passed when run with the required Caddy build.
The native and Linux release manifests contain the same 162 source-file hashes.

Initial compile and test failures exposed a portable-interface flag issue and test-fixture lifetime errors.
These errors were corrected before the final test run.
Missing OpenWrt utilities required BusyBox and Node alternatives.
The NAT inspection used nftables after the iptables query failed.
The audit retains the failed calls and recovery results.
Tailscale ping returned status 1 because it did not establish a direct connection.
The first Tailscale throughput trial changed its reported path from DERP to an IPv6 peer relay at UTM.
That trial failed the path-stability check.
A second trial switched from s6916 to the jpali peer relay at `47.91.14.86:14000`.
Both trials remain separate from the final observed-path baseline.
The final Tailscale baseline records every path snapshot and samples both relay daemons.
It does not require a fixed relay path and does not enter the direct-path table.

Complete command records are in `benchmark-results/all-protocol-punch-20260922/`.
The JSONL audit is `benchmark-results/.work/all-protocol-punch-20260922.jsonl`.
Release manifests record source hashes and binary hashes.

- [Per-trial measurement summary](../../benchmark-results/all-protocol-punch-20260922/measurement-summary.json)
- [Native release manifest](../../benchmark-results/all-protocol-punch-20260922/traversal-v3-native-manifest.json)
- [Linux release manifest](../../benchmark-results/all-protocol-punch-20260922/traversal-v3-linux-manifest.json)
- [Command audit](../../benchmark-results/.work/all-protocol-punch-20260922.jsonl)

## Measurement conditions

The fixture uses automatic interface discovery and excludes Tailscale address ranges.
It uses isolated overlay addresses, an MTU of 1280 bytes, and two worker threads per endpoint.
Osku uses the userspace network stack and a loopback port forward.
UTM uses a separate TAP interface.
The production VPN and firewall remain unchanged.

| Endpoint | Platform | CPUs | Memory | iperf3 |
| --- | --- | ---: | ---: | --- |
| osku | macOS, Darwin 27.0.0, arm64 | 16 | 128 GiB | 3.21 |
| UTMOWRT | OpenWrt, Linux 6.6.110, aarch64 | 6 | 8 GiB | 3.17.1 |

The iperf3 versions differ between endpoints. The same versions serve all transport cases.
Tailscale uses its existing tunnel and peer relay. This is not a matched direct-underlay comparison.

Each LowTier throughput result requires a direct authenticated connection before, during, and after the run.
The connection identifier must remain unchanged.
Relay throughput cannot satisfy this condition.

TCP payload tests use one and four concurrent streams in each direction.
Each case runs twice for 20 seconds.
Each protocol retains its established connection across these trials.
Two repetitions show the observed range. They do not establish a long-term performance distribution.
UDP delivery tests send 1,000-byte datagrams at 10 Mb/s for 20 seconds in each direction.
The final release uses information-level console logging.
Short feasibility tests ran during compilation. They are excluded from the final results.

CPU and RSS samples run approximately once per second for 23 seconds around each transfer.
Actual sampling windows include command overhead and are reported with the results.
Process CPU seconds are divided by delivered Gbit.
Whole-host busy CPU counters include kernel work, measurement tools, and unrelated background work.
They do not isolate the VPN's kernel cost.
Linux idle, I/O-wait, and steal time are excluded from CPU consumption.
Steal time is recorded separately.
Linux clock frequency is 100 ticks/s, verified from UTM process auxiliary data and relay `getconf` output.
The Tailscale comparison also samples both observed peer-relay daemons and hosts.

At rate R bit/s and payload size P bytes, the payload packet rate is approximately R/(8P).
At 500 Mb/s and 1,200 bytes, this is approximately 52,000 packets/s.
The path performs routing, encryption, and userspace forwarding for these packets.
Four streams can increase the available TCP window while retaining the same tunnel.
The measurements record delivered bytes, tunnel byte counters, CPU time, and RSS to distinguish these costs.
No performance-specific constants were changed for this fixture.

The reported application TCP retransmissions do not measure every underlay retransmission.
The loopback forward terminates the osku application TCP connection.
UTM host TCP counters include other connections and cannot isolate H2 or WSS retransmissions.
QUIC path logs provide separate packet-loss estimates.
Latency values are peer RTT snapshots. They are not latency percentiles.
Direct-path checks are also snapshots, taken before, during, and after each transfer.
TCP received/sent byte ratios include queued bytes at timed-test termination. They do not measure TCP reliability.
RSS ranges describe the persistent daemon during these samples. They are not isolated allocation peaks.
