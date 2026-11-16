# Runtime decision cleanup and fleet verification

All four changes are implemented. Eleven reachable test instances run application commit `00b50c6b`.
Their final delivery, authentication, GUI, identity, configuration, and MTU checks passed on November 16, 2026.
The source commits are `9f1b5c83`, `1321101b`, and `00b50c6b`.
The comparison baseline is `57d2151b`.

The changes remove work and state from these paths:

- Registered packet consumers control proxy filtering. An enabled listener does not activate packet filtering.
- The source smoltcp stack is allocated when a packet consumer needs it.
- Configuration setters and route publication update forwarding state before packet dispatch.
- The experimental OverlayStream implementation is removed. TCP retains Kernel, HTTP/3 transport, and Smoltcp backends.

The final idle gate uses one atomic count load.
Insertion reserves the count before publishing an entry.
Removal releases the count after removing the entry.
This replaces an empty-map scan that acquired every DashMap shard lock.
The local 16-core host uses 64 shards.
An idle batch therefore avoids 64 shard lock acquisitions on that former path.

Validation also found false HTTP/3 admission failures during concurrent opens.
The repaired receiver waits for bounded queue capacity after reserving the existing stream and memory permits.
The stream limit, memory limit, authentication checks, and packet fallback rules remain enforced.

The source stack remains allocated after its first use until an address change or shutdown.
GUI and FFI listeners can require this stack.
Lazy allocation therefore does not establish a memory reduction for every fleet workload.

**Verification**

The permitted sequential core suite passed 556 tests.
Two public-domain probes were excluded under the local-test policy.
Two optional Caddy tests passed separately.
Full-feature, minimal-feature, and FFI checks passed.
Release builds passed for macOS arm64, Linux x86_64 musl, and Linux aarch64 musl.

The new admission and idle-gate tests failed before their respective repairs.
The admission test verifies pending concurrent opens, payload delivery, and permit release.
The idle-gate test verifies that an unrelated held shard cannot block the idle decision.
Existing tests cover lazy allocation, address changes, proxy shutdown, service-route snapshots, and asymmetric packet proxy paths.
Independent source review found no remaining actionable issues after the repairs.

An unchanged logging assertion failed in earlier parallel runs.
It passed in isolation and in sequential runs.
The default parallel suite is not claimed as passing.

**Binary footprint**

| Target | Baseline bytes | Final bytes | Reduction |
| --- | ---: | ---: | ---: |
| macOS arm64 | 22,801,664 | 22,669,088 | 132,576 bytes; 0.58% |
| Linux x86_64 musl | 29,677,000 | 29,493,192 | 183,808 bytes; 0.62% |
| Linux aarch64 musl | 25,318,352 | 25,168,976 | 149,376 bytes; 0.59% |

These measurements establish a smaller executable.
They do not establish an equal reduction in resident memory.

**Local userspace measurements**

The final matrix used an Apple M4 Max with 16 cores and 128 GiB of memory.
The underlay used loopback addresses.
GUI was disabled in these isolated processes.
Each group transferred 256 MiB three times in each direction.
Every payload byte was checked against a fixed pattern.
Connections were established before timing.
Concurrent admission was checked separately.

CPU is the sum of participating LowTier process CPU time per delivered Gbit.
Direct cases include two processes.
Relay cases include three processes.
Other processes and kernel work charged outside LowTier are excluded.
RSS was sampled every 100 milliseconds.
Each group also collected 21 application echo RTT samples.

The table shows median throughput and changes in CPU seconds per delivered Gbit.
A negative CPU change means less CPU time.

| Case | Download Mb/s, baseline → final | Upload Mb/s, baseline → final | Download CPU change | Upload CPU change |
| --- | ---: | ---: | ---: | ---: |
| Direct QUIC, 1 flow | 3,121 → 2,986 | 2,418 → 2,392 | +4.3% | +1.7% |
| Direct QUIC, 4 flows | 2,549 → 2,601 | 2,018 → 1,988 | −1.7% | +1.7% |
| Direct H2, 1 flow | 8,445 → 7,797 | 8,162 → 8,110 | +6.4% | +1.2% |
| Direct H2, 4 flows | 7,572 → 7,733 | 7,669 → 7,439 | −5.4% | +3.2% |
| Direct WSS, 1 flow | 9,517 → 8,965 | 6,895 → 7,547 | +3.9% | −4.2% |
| Direct WSS, 4 flows | 7,932 → 7,224 | 7,354 → 6,725 | +8.0% | +4.0% |
| Relay QUIC, 1 flow | 1,460 → 1,376 | 1,305 → 1,273 | +3.0% | +3.5% |
| Relay H2, 1 flow | 5,232 → 4,858 | 4,485 → 3,984 | +6.4% | +22.6% |
| Relay WSS, 1 flow | 4,714 → 4,731 | 3,969 → 3,708 | −0.9% | +5.8% |
| ACL-controlled QUIC, 1 flow | 1,889 → 2,373 | 1,537 → 1,587 | −16.6% | −3.7% |

All 120 transfers in the final baseline/candidate matrix delivered their complete payloads.
QUIC reported zero lost packets in these groups.
H2 and WSS captures recorded zero repeated TCP sequence packets and zero capture drops.
QUIC path statistics reported MTU 1452.
These loopback results do not establish WAN throughput.

The final direct cases had sampled aggregate RSS from 60.5 to 159.4 MiB.
The final relay cases had sampled aggregate RSS from 91.3 to 150.5 MiB.
Per-case sampled peak RSS changes ranged from about −6% to +19%.
Final median application RTTs ranged from 0.252 to 0.311 ms for direct cases.
Relay medians ranged from 0.401 to 0.419 ms.
The summary contains each case's RSS range and latency measurements.

These results are mixed.
Several final medians are below the default baseline.
Repeated baseline process starts also showed substantial variation in some cases.
The measurements do not establish a universal throughput or RSS improvement.
The work removal and executable reductions are separate, established results.
No workload-specific thresholds or resource-limit increases were introduced.

The retained experimental reference covers the same ten configurations with the former OverlayStream option enabled.
Those binaries and all raw measurements remain available locally.
The retired stream used different ACL processing granularity.
Its ACL rate is not a substitute for validating the retained packet ACL semantics.

**Native fleet measurements**

The native fixture used `861jp` as client and `862jp` as server.
Both endpoints used effective overlay MTU 1280.
Each direction transferred and validated 128 MiB three times.
The fixture measured exact receiver completion.

| Direction | Baseline Mb/s | Final Mb/s | Baseline CPU seconds/Gbit | Final CPU seconds/Gbit |
| --- | ---: | ---: | ---: | ---: |
| 862jp → 861jp | 216.6 | 221.1 | 2.552 | 2.356 |
| 861jp → 862jp | 223.3 | 206.4 | 2.645 | 2.533 |

Sampled aggregate RSS ranged from 80,832 to 98,540 KiB for the baseline.
It ranged from 81,472 to 94,176 KiB for the final candidate.
Median unloaded application RTT changed from 1.38 to 1.26 ms.
The complete runs recorded 68 baseline and 138 final application TCP retransmissions.
Both versions delivered every expected byte.

These native runs used the automatic fleet transport policy.
They did not isolate one underlying transport.
The baseline was already running, while candidates were restarted.
An intermediate candidate produced a higher upload rate in another automatic-route run.
These observations do not establish a universal version ranking or a transport-specific speed improvement.

**Fleet delivery and recovery**

All eleven reachable instances passed running-image transfer integrity checks.
The final fleet check received 55 of 55 full-size ICMP replies and 165 of 165 UDP replies.
Each instance delivered exactly 8 MiB in each TCP direction from another host.
Each instance retained authenticated H2, QUIC, and WSS connections.
Identities, keys, configuration, and effective MTU 1280 were preserved.

Each Web UI retained port 15880 and the three required open source subnets.
Keyless page, API, and RPC reads passed from the overlay.
Each instance rejected a foreign Origin.
The access-key requirement outside `gui.open` remains configured.

The router transfer timed out after a partial upload.
The saved 8,879,849-byte prefix matched the local transfer file.
The remaining bytes were appended and the complete compressed file and executable were verified.
The router's asynchronous restart required a later PID check before running-image verification.

The old local node had authenticated connections without routes to the restarted canaries.
Its planned update restored the routes and delivery.
Protected configuration references were recovered before comparison.
A viewer restart loaded the added source page.
The cleanup audit was corrected to exclude offline historical hosts.
All temporary fixtures are stopped.
Completed transfer files are removed.
Configuration references, logs, baseline artifacts, and raw measurements are retained.

`tw2-ingress`, `btower`, and `UTMOWRT` remain offline and pending.
Their migrations are not marked complete.

The local Flywheel graph has 37 active nodes, 30 dependency edges, and 21 source pages.
Both private viewer interfaces passed verification after deployment.

The [machine-readable summary](../../benchmark-results/decision-runtime-20261116/summary.json) contains complete aggregate results and deployment records.
Raw measurements and command records remain in `benchmark-results/.work/decision-runtime-20261116/`.
