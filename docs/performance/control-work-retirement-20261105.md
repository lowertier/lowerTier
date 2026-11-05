# Control work retirement, 2026-11-05

Source commit: `e7bd53b0`.

This change removes duplicate setup and control work.
It preserves transport authentication, migration validation, packet fallback, and protected GUI connections.
The deployment manifest is [control-work-retirement-20261105.json](control-work-retirement-20261105.json).

## Removed work

| Path | Previous work | Current work |
| --- | --- | --- |
| QUIC source probe | Configure UDP transport buffers and register a Tokio socket before converting it back | Create a standard socket without transport buffer configuration |
| QUIC endpoint setup | Apply plain UDP and QUIC buffer policies | Apply the QUIC policy once for sockets created by the endpoint manager |
| Migration endpoint grouping | Query both socket addresses for each comparison | Query each endpoint address once and compare saved addresses |
| Migration interface checks | Enumerate interfaces repeatedly for individual sources and groups | Share one lazy interface snapshot per scan |
| CIDR mapping updates | Run separate one-second updaters for TCP, UDP, ICMP, and optional overlay streams | Share one updater and atomic snapshot per instance |
| H2 admission with a decoy hostname | Resolve the hostname during marker selection and admission | Resolve asynchronously only for passthrough traffic |
| Local proxy admission | Bind a UDP socket even for a known local virtual address | Skip that ownership probe for known virtual addresses |
| GUI snapshots | Serialize unused route summaries | Keep the route data that the frontend reads |

With `P` distinct endpoints, grouping previously performed `P(P-1)` address queries.
It now performs `P` queries.
For 32 endpoints, this removes 960 address queries from each scan.

With interface rules and `G` concrete endpoint groups, a steady scan previously performed approximately `P+2G` interface enumerations.
An eligible scan now shares at most one snapshot.
Unrestricted wildcard groups need no snapshot.
Actual socket replacement and validation still perform fresh policy checks.

Source probes still query the operating system for the selected source address.
They preserve address families, socket marks, network namespaces, and local policy checks.
The two-second recovery timer remains active.
Pending validation and cooldown checks precede source probes and replacement setup.

The callback policy check now enters the socket's network namespace.
It releases the validation mutex before interface lookup.
The unused local-address argument was removed from remote validation admission.

These operation counts come from source analysis.
They do not establish CPU, throughput, or resident-memory improvements.
Socket buffer limits do not establish resident-memory allocation.

## Verification

- The full local core suite passed 484 tests before the final H2 and lazy-snapshot corrections.
- All 181 transport tests passed after those corrections.
- Both Caddy integration tests passed.
- Linux namespace policy validation passed in an isolated namespace on alibj.
- All four Linux migration tests passed.
- Linux source-probe and CIDR snapshot checks passed.
- Formatting and whitespace checks passed for the changed source files.
- All 15 GUI instances passed access and instance-selection checks.
- GUI checks covered authorized access, unauthorized requests, rejected foreign hosts, and listener addresses.
- Running binary identities and authenticated delivery were checked after deployment.

The existing CI test-count gate remains over its limit.
The previous committed tree contained 525 test annotations against a limit of 500.
The existing user changes add four annotations.
This change adds three focused tests, giving 532 annotations in the working tree.
The source review preserved existing tests and user changes.
No full CI success is claimed.

## Delivery and transfer evidence

The final Mac-to-Hattori check delivered 100 of 100 probes.
Mean RTT was 6.479 ms.
Maximum RTT was 26.419 ms.
The LAN SSH test delivered all 120 echo messages.
Median echo RTT was 49.726 ms, and the 95th percentile was 140.714 ms.
The SSH test ran during fleet GUI checks and used a Tailscale SSH jump host.
The final Tailscale check delivered 100 of 100 probes with mean RTT 22.596 ms.
The Hattori LAN host reached alibj with 30 of 30 probes and received its SSH banner.
LAN-to-alibj mean RTT was 195.421 ms, and maximum RTT was 533.247 ms.
These checks establish reachability rather than a latency improvement.

The transfer comparison used one TCP stream and ten-second iperf intervals in each direction.
The Mac used iperf 3.17.1, and Hattori used iperf 3.20.
Both states used the same host pair, test addresses, binaries for iperf, and configuration.
The observed Mac TUN MTU was 1280, and the Hattori TAP MTU was 1340.

| Trial | Receiver Mbit/s | Core CPU seconds per delivered Gbit | TCP retransmissions |
| --- | ---: | ---: | ---: |
| Previous version, upload A1 | 20.333 | 41.439 | Unavailable from the Mac sender |
| Previous version, download A1 | 25.935 | 37.228 | 2009 |
| Candidate, upload B1 | 24.584 | 43.239 | Unavailable from the Mac sender |
| Candidate, download B1 | 23.588 | 43.295 | 3044 |
| Candidate, upload B2 | 24.060 | 51.137 | Unavailable from the Mac sender |
| Candidate, download B2 | 26.257 | 47.381 | 2660 |

Each successful trial delivered all 60 concurrent LowTier probes and all 60 concurrent Tailscale probes.
CPU sampling covered both LowTier core processes.
It excluded kernel work, Tailscale, SSH, and iperf CPU work.
Each trial collected 14 RSS and CPU samples at nominal one-second intervals.
The CPU interval includes transfer setup and completion.
Raw samples retain the measured process counters.

Previous-version RSS ranged from 50.547 to 52.719 MiB on the Mac and 69.551 to 72.926 MiB on Hattori.
Candidate RSS ranged from 37.844 to 39.922 MiB on the Mac and 48.957 to 53.789 MiB on Hattori.
Process age and mesh convergence differed between states.
These RSS values do not establish a memory reduction.

The planned A1-B1-B2-A2 comparison did not finish.
The A2 upload timed out, and all 60 LowTier probes failed during that trial.
All 60 concurrent Tailscale probes succeeded.
Immediate delivery also failed after restoring the candidate.
Later captures showed requests and replies at both virtual interfaces.
Delivery returned without a source change.
The cause of this reconnect delay remains unconfirmed.

Failed trials and recovery checks remain in the audit directory.
No throughput, CPU, or memory improvement is claimed.
The final deployment retains the candidate with restored delivery.

## Deployment recovery

tw2-ingress had insufficient persistent space for another binary copy.
The failed test upload was removed.
The deployment used memory staging and a verified local recovery binary.
It preserved the installed path and configuration.

The initial backup command selected the wrong SSH account.
The corrected command used the recorded root account and passed checksum verification.

Direct alibj uploads timed out or lost their connection.
Recovery verified each existing file prefix before resuming a compressed suffix.
The release upload used an SSH jump through Hattori, with Tailscale addresses on both hops.
The complete test and release artifacts passed SHA256 checks before execution or replacement.

Raw records and scripts remain under `benchmark-results/.work/control-cleanup-20261105/`.
The JSONL audit records commands, process IDs, output paths, exit codes, and recovery actions.
Initial source reads lack complete process audit records.
