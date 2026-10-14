# TCP lanes: verified throughput and browser TLS milestone

Validated on 2026-09-08. H2 and WSS each pass the 5 Gbit/s receiver-goodput gate in both directions. All twelve four-lane measurements exceed the threshold. The comparison also includes twelve same-binary single-lane measurements and six matched Linux kernel WireGuard measurements. This is a throughput result; the TCP-based paths retain a material loaded-latency disadvantage.

## Measurement conditions

The endpoints ran in separate Docker network namespaces in one aarch64 Colima VM: three vCPUs, 8 GiB RAM, Ubuntu 24.04.3 and Linux 6.8.0-117-generic. Each direction used four inner BBR TCP flows, 10 seconds of warm-up followed by 30 measured seconds, repeated three times. Forward and reverse were measured separately. The underlay MTU was 1500; the effective overlay interface MTU was 1340 for LowTier CLI `--mtu 1360`, and WireGuard used MTU 1340 explicitly.

Both endpoints applied egress netem on the underlay veth: 40 ms delay per direction, configured 0.1% random loss and queue limit 250000. Offloads remained enabled. Consequently the configured loss process acts on the qdisc-visible packet/GSO units and does not establish an independent MTU-packet loss model for every protocol. These measurements describe this topology, rather than a general Internet ceiling. Raw four-flow TCP controls measured 10.800 Gbit/s with the WireGuard run and 11.233 Gbit/s with the final LowTier control.

All LowTier variants used the same release binary, built with Rust 1.95, fat LTO and features `tun,quic,websocket`. SHA256: `28c9b67edcf790e16e6ab3e6df5fb04426a69ce57722245518a02f9cb1597a84`. The independent source candidate was reconstructed from base `c866fb8090e7ff83397915de827c663bd478d38a` plus the scoped changes, retaining the original tests. Throughput workloads and compilation were kept separate.

The common TCP receive/send autotuning ceilings were 64 MiB. LowTier used the existing opt-in `LOWTIER_ENABLE_TCP_LARGE_BUFFERS=1`, giving 64 MiB reported outer TCP accounting limits per socket direction. H2 used ordinary TLS with `--quic-sni-passthrough true`. The measured baseline had no per-socket `TCP_NOTSENT_LOWAT` limit. The number of inner TCP flows was unchanged when the outer lane count changed.

The 2026-10-14 candidate introduces a [separate unsent data budget](tcp-unsent-budget.md).
That candidate requires a new matched comparison; the measurements below apply to the earlier binary.

## Receiver goodput

| Path | Forward median [range], Gbit/s | Reverse median [range], Gbit/s |
| --- | ---: | ---: |
| Kernel WireGuard | 4.795 [4.786, 4.810] | 4.852 [4.804, 4.866] |
| H2, one lane | 2.405 [2.311, 2.475] | 2.373 [2.250, 2.386] |
| H2, four lanes | 7.124 [6.579, 7.308] | 7.105 [6.984, 7.415] |
| WSS, one lane | 2.846 [2.390, 2.974] | 2.826 [2.121, 2.959] |
| WSS, four lanes | 7.634 [7.324, 7.790] | 7.288 [7.012, 7.482] |

Each cell summarizes three valid trials. Nonzero workload exits, reported iperf errors, zero receiver delivery and shortened measurements fail validation; none of the final comparison trials was excluded.

| Four-lane path | Direction | Change from same-binary one lane | Change from kernel WireGuard |
| --- | --- | ---: | ---: |
| H2 | forward | +4.719 Gbit/s (+196.2%) | +2.329 Gbit/s (+48.6%) |
| H2 | reverse | +4.732 Gbit/s (+199.4%) | +2.253 Gbit/s (+46.4%) |
| WSS | forward | +4.788 Gbit/s (+168.3%) | +2.839 Gbit/s (+59.2%) |
| WSS | reverse | +4.462 Gbit/s (+157.9%) | +2.436 Gbit/s (+50.2%) |

### Complete throughput samples

| Path | Forward trials, Gbit/s | Reverse trials, Gbit/s |
| --- | --- | --- |
| Kernel WireGuard | 4.810, 4.786, 4.795 | 4.866, 4.852, 4.804 |
| H2, one lane | 2.475, 2.405, 2.311 | 2.250, 2.373, 2.386 |
| H2, four lanes | 6.579, 7.124, 7.308 | 7.105, 7.415, 6.984 |
| WSS, one lane | 2.390, 2.846, 2.974 | 2.121, 2.826, 2.959 |
| WSS, four lanes | 7.634, 7.324, 7.790 | 7.288, 7.482, 7.012 |

## Loaded latency and resources

CPU is estimated from differences in `/proc/stat` during each measured window, with `CLK_TCK=100`, using one node for the shared VM counters. It includes both endpoints, kernel networking, iperf and background VM work. Process CPU uses `/proc/<pid>/stat` deltas. Samples are approximately three seconds apart. The original analysis selected windows using the JSON control-connection timestamp plus the configured warm-up. Source verification against iperf 3.12 on 2026-09-08 shows that `iperf_on_connect` records this timestamp before stream creation and `TEST_START`; connection/setup delay can therefore add substantially more than one second of alignment error. The tabulated latency and CPU statistics use these nominal windows. Exact load-phase attribution requires separately timestamped interval evidence, particularly for delayed or interrupted trials. Values below are the median per-trial busy-core-seconds per delivered Gbit. Lifetime `ps %cpu` is not used for these comparisons.

Latency is from timestamped ICMP probes every 200 ms. Probes are assigned to measured windows by estimated send time (reply timestamp minus reported RTT); quantiles pool the received probes in those windows. This does not count unreturned probes as finite RTTs. RSS uses 4096-byte pages from process stat samples. The two endpoint peaks are reported separately and need not occur simultaneously.

| Path | Direction | VM core-s / delivered Gbit | Combined LowTier process core-s / Gbit | Loaded RTT p50 / p95 / p99, ms |
| --- | --- | ---: | ---: | ---: |
| Kernel WireGuard | forward | 0.408 | n/a | 80.6 / 82.0 / 84.1 |
| Kernel WireGuard | reverse | 0.408 | n/a | 80.7 / 82.2 / 83.2 |
| H2, four lanes | forward | 0.274 | 0.250 | 143.0 / 335.6 / 737.7 |
| H2, four lanes | reverse | 0.278 | 0.256 | 133.0 / 253.0 / 343.6 |
| WSS, four lanes | forward | 0.287 | 0.264 | 164.0 / 2027.2 / 5529.0 |
| WSS, four lanes | reverse | 0.308 | 0.286 | 142.0 / 263.2 / 389.9 |

| Four-lane path | Peak process RSS, endpoint A / B, MiB | Peak outer-socket skmem r+w, A / B, MiB |
| --- | ---: | ---: |
| H2, four lanes | 87.7 / 85.0 | 169.3 / 163.7 |
| WSS, four lanes | 28.2 / 33.2 | 182.3 / 166.3 |

Kernel socket memory is outside process RSS. The socket column sums the observed `ss -m` receive and queued-write memory fields for the outer TCP sockets; it is distinct from configured buffer limits and total VM memory. Kernel WireGuard has no directly comparable userspace process RSS. Its resource comparison therefore uses VM-wide CPU, with raw socket/kernel evidence retained separately.

H2 has the lower loaded tail latency of the retained TCP paths in this experiment. WSS forward p95 is about two seconds and p99 about 5.5 seconds, despite high goodput. These data do not establish WireGuard-equivalent responsiveness. Multi-lane transports remain explicit opt-ins; the throughput milestone does not justify replacing the latency-sensitive default solely from these results.

## Effective architecture

One logical PeerConn, one Noise authentication exchange and one peer receive pipeline own two or four independent TCP/TLS connections. Each connection carries one H2 CONNECT or WebSocket stream. An authenticated LTL2 setup binds a random group identifier, exact lane count, lane indices and each TLS exporter. The ordered exporters form the composite binding in the Noise prologue. Incomplete groups expire, duplicate or mismatched joins are rejected, and one established-lane failure terminates the entire logical connection.

The send path partitions owned packet batches by the full flow hash. A bounded 256-entry map assigns first-seen flows across lanes and never moves an installed mapping. At capacity, new flows use a deterministic hash fallback. Parsing uses the current cleartext packet encoding, so Ethernet compaction cannot turn a cached L2 hash into a different L3 path. Compression records that normalized hash before mutating bytes; compressed frames retain the same lane.

Only immediate direct TLS-protected data is eligible for striping. Session ciphertext, relayed data and control packets remain on the primary lane, preserving their existing replay domain. No replay bitmap was widened or disabled. Pending ownership is bounded to 64 packets and 256 KiB retained buffer capacity. Read and write polling visit siblings when one lane is pending; explicit flush is still a barrier. Shared admission, a full slow-lane queue and the final NIC remain real coupling points.

The WSS server now preserves concrete TCP/TLS I/O types instead of passing them through an Either implementation that hid vectored writes. A regression observes actual multi-buffer writes. H2/WSS clients use the same rustls connection as the servers.

## Chrome-family TLS verification

The H2/WSS client uses the same rustls+ring provider as QUIC, with Chrome/Safari cipher order (AES-128, AES-256, ChaCha). Public-certificate paths retain native trust validation; direct peer paths retain Noise-authenticated policy and exporter binding. This is not a Chrome ClientHello clone (no GREASE, extension permutation, or ML-KEM).

H2 and WSS clients use the same rustls+ring provider as QUIC. Cipher suite order follows Chrome/Safari (AES-128, AES-256, ChaCha). Tests lock a TLS handshake record and exporter binding, not a full Chrome ClientHello.

| Captured property | Result |
| --- | --- |
| Cipher preference order, supported groups, TLS versions, non-GREASE signature preferences | Matched the captured reference |
| Hybrid/classical key-share groups and lengths, ALPN, Brotli advertisement | Matched |
| WSS extension set excluding GREASE values | Matched |
| H2 extension set | ALPS 17613 omitted because the H2 stack does not consume TLS-delivered settings |
| Signature-algorithm GREASE | The captured Chrome includes an additional GREASE entry; this client does not |
| Native trust-anchor hints | Present, with values dependent on installed roots; captured payload lengths were 115 versus Chrome 206 bytes |
| ECH | GREASE advertisement only; no claim that SNI is encrypted |

This is a measured browser-family ClientHello profile, not a claim of complete browser traffic indistinguishability. HTTP/2 settings, connection reuse, server certificates, packet timing and application payload behavior are separate properties. The legacy H2 pre-TLS routing marker is intentionally outside this profile; use `--quic-sni-passthrough true` for ordinary TLS. A multi-lane L4 proxy needs backend affinity.

## Rejected experiments and verification

Using the low FNV bit concentrated even-port flows on one lane. Static six-bit shard mixing still produced sparse-flow collisions, and a permanent six-bit mapping accumulated uneven assignments across repeated trials. The bounded full-flow mapping fixes those observed causes without moving existing flows. Increasing TCP windows and adding TCP_NOTSENT_LOWAT did not yield a stable gain; the latter was removed. Raising WSS flush thresholds alone left the server/client asymmetry until the vectored-I/O path was repaired. Multiple independent PeerConns were not retained.

The candidate passed 20 lane tests with zstd enabled, three browser TLS tests, twelve WebSocket tests, sixteen TCP tests, nine replay-window-selected tests and two compressor tests. Filters overlap and these counts should not be summed as a unique-test total. The scoped Caddy integration test also passed, exercising ordinary website port sharing, two H2 and WSS backends, single-lane round-robin distribution and four-lane IP affinity.

Restored tests exposed an echo helper looping on terminal H2 errors and a fixed-port IPv6 race; both were repaired while preserving tests. A compression/lane-order regression was first observed failing and then passed after the metadata fix. The Linux build includes the existing RouteIdentity prerequisite while keeping its original tests. CMake/libclang prerequisites are documented in the benchmark Dockerfile and README. Minimal, WebSocket-only and lean compile configurations also pass.

## Reproduction and evidence

Use `script/colima-throughput/build-core.sh` with a prepared builder containing CMake and libclang and `LOWTIER_BUILD_FEATURES=tun,quic,websocket`. Select `UNDERLAY_PROTOCOL=tcp` or `wss` and `LOWTIER_TCP_LANES=1` or `4`; use the same binary for controls. `script/colima-throughput/README.md` describes the exact opt-ins and proxy requirements.

The retained local evidence is under `benchmark-results/tcp-lanes-20260907/`: `h2-commit-single-final`, `h2-commit-four-final`, `wss-commit-single-final`, `wss-commit-four-final` and `kernel-wg-final`. The directory name is historical; the final trials were executed on 2026-09-08. Each directory contains invocation metadata, raw iperf JSON, socket/proc samples and timestamped loaded pings. `benchmark-results/.work/finish-20260908/final-statistics.json` and `analyze.py` preserve the calculations. Earlier failed experiments remain separate from the accepted dataset.

Primary protocol and measurement references: RFC 8446 (TLS 1.3/exporters), RFC 8701 (GREASE), the BoringSSL ssl.h API documentation, the Chrome for Testing release manifest, Linux `/proc` documentation and the iputils ping manual.
