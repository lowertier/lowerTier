# Lean-core A/B transfer comparison — 2026-10-14

Candidate snapshot `9b0af7eb` reduced clean-link median QUIC throughput by 26.1–31.6%.
Clean-link H2 medians fell by 18.0–20.7%. Each complete cell has three matched repetitions per binary.
The owner stopped the campaign to give Colima to the regression bisection worker.
The final dataset contains 55 accepted clean transfers. WAN matrix trials did not run.
Corrected WSS results remain partial. These results do not measure later main commits.

## Scope and conditions

Baseline source: `10e33193c3075e06ac26081547a22f6ed492e902`.
Candidate source: `9b0af7eb55335f008a830514fe0e412867349b1d`.
Harness changes were committed on main as `5995b848`. No production repair was part of this benchmark.
Both Linux binaries used Rust 1.95.0, the release profile, fat LTO, one codegen unit, no default features, and feature `tun`.
QUIC, H2, and WSS are unconditional transport modules in these revisions.
Baseline SHA256: `c8c708fb47cce00d9ca5cb9e8405ed96d22d9f6d3722bee21c48bb5aad2092e0`.
Candidate SHA256: `62d50d1d0b0cadc042fea54c5f4ef4633472673d23cc291d24a4d60a3f20e127`.

Two Docker containers ran in the default aarch64 Colima VM: VZ, VirtioFS, three vCPUs, and 8 GiB RAM.
The guest used Ubuntu 24.04.4 and Linux 6.8.0-117-generic. Runtime iperf3 was 3.12.
The Docker bridge MTU was 1500. Both native TAP interfaces used MTU 1340 from configured MTU 1360.
Inner TCP used BBR, with one or four streams. The outer transport used one connection and one lane.
Forward means endpoint A to B. Reverse means endpoint B to A.
Each transfer excluded ten warmup seconds and measured twenty seconds.
Each repetition ran baseline before candidate, with the same direction and stream order.
Private network admission, secure mode, ChaCha20-Poly1305 configuration, and TLS exporter binding remained enabled.
All traffic targeted explicit local Docker test addresses. No resident instance was restarted or reconfigured.

## Complete clean comparisons

Each throughput and CPU cell is median [minimum–maximum]. CPU sums the two LowTier processes.
CPU cost is sampled process CPU rate divided by receiver throughput, in seconds per delivered Gbit.

| Transport | Direction | Streams | Baseline Gbit/s | Candidate Gbit/s | Delta | Baseline CPU s/Gbit | Candidate CPU s/Gbit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| QUIC | forward | 1 | 6.582 [6.484–6.656] | 4.596 [4.487–4.616] | -30.2% | 0.315 [0.314–0.325] | 0.445 [0.442–0.455] |
| QUIC | forward | 4 | 6.732 [6.645–6.854] | 4.976 [4.933–4.982] | -26.1% | 0.321 [0.318–0.322] | 0.437 [0.433–0.442] |
| QUIC | reverse | 1 | 6.432 [6.325–6.706] | 4.399 [4.379–4.688] | -31.6% | 0.329 [0.309–0.332] | 0.466 [0.448–0.471] |
| QUIC | reverse | 4 | 6.780 [6.330–6.836] | 4.841 [4.775–4.930] | -28.6% | 0.323 [0.316–0.329] | 0.450 [0.441–0.452] |
| H2 | forward | 1 | 8.164 [8.029–8.408] | 6.569 [6.559–6.781] | -19.5% | 0.270 [0.258–0.274] | 0.337 [0.329–0.339] |
| H2 | forward | 4 | 8.140 [8.099–8.368] | 6.474 [6.447–6.738] | -20.5% | 0.278 [0.270–0.280] | 0.348 [0.336–0.350] |
| H2 | reverse | 1 | 8.107 [8.103–8.381] | 6.648 [6.436–6.741] | -18.0% | 0.271 [0.262–0.274] | 0.331 [0.329–0.342] |
| H2 | reverse | 4 | 8.233 [8.113–8.490] | 6.526 [6.155–6.635] | -20.7% | 0.279 [0.270–0.280] | 0.346 [0.339–0.365] |

RSS ranges cover observed samples across the three repetitions. Each cell lists endpoint A / endpoint B, in MiB.

| Transport | Direction | Streams | Baseline RSS A / B | Candidate RSS A / B |
| --- | --- | ---: | ---: | ---: |
| QUIC | forward | 1 | 24.7–25.9 / 27.0–28.2 | 23.2–25.4 / 26.5–27.8 |
| QUIC | forward | 4 | 28.4–30.9 / 26.9–29.9 | 27.0–29.6 / 27.2–29.5 |
| QUIC | reverse | 1 | 28.8–29.3 / 28.2–30.0 | 27.2–28.8 / 28.8–29.7 |
| QUIC | reverse | 4 | 28.9–29.6 / 31.0–34.4 | 27.3–28.8 / 30.2–33.7 |
| H2 | forward | 1 | 21.1–27.3 / 24.7–27.7 | 23.1–25.7 / 24.3–26.6 |
| H2 | forward | 4 | 24.2–29.3 / 26.0–28.1 | 26.1–29.4 / 25.8–27.8 |
| H2 | reverse | 1 | 26.9–27.4 / 26.5–29.4 | 26.4–28.4 / 26.9–29.3 |
| H2 | reverse | 4 | 26.8–27.4 / 27.9–33.1 | 26.4–27.5 / 29.6–33.2 |

Loaded RTT cells give the median per-trial p50 / p95, in milliseconds.
Inner retransmissions cover measured iperf TCP. H2 outer counts cover the full observed transfer, including warmup.
QUIC outer cells estimate measured-window lost/sent packet percentages from one-second path-statistic samples.
H2 outer cells report socket retransmission counts from matched before/after socket tuples.

| Transport | Direction | Streams | RTT baseline p50 / p95 | RTT candidate p50 / p95 | Inner retrans baseline [range] | Inner retrans candidate [range] | Outer baseline [range] | Outer candidate [range] |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| QUIC | forward | 1 | 0.375 / 0.860 | 0.385 / 0.948 | 0 [0–0] | 0 [0–0] | 0.0000 [0.0000–0.0000]% | 0.0000 [0.0000–0.0000]% |
| QUIC | forward | 4 | 0.750 / 1.536 | 0.876 / 1.716 | 154 [0–2416] | 108 [0–501] | 0.0000 [0.0000–0.0000]% | 0.0000 [0.0000–0.0000]% |
| QUIC | reverse | 1 | 0.394 / 0.855 | 0.390 / 0.835 | 0 [0–0] | 0 [0–0] | 0.0000 [0.0000–0.0000]% | 0.0000 [0.0000–0.0000]% |
| QUIC | reverse | 4 | 0.821 / 1.713 | 0.879 / 1.782 | 136 [0–1712] | 0 [0–0] | 0.0000 [0.0000–0.0000]% | 0.0000 [0.0000–0.0000]% |
| H2 | forward | 1 | 0.941 / 1.983 | 0.872 / 1.718 | 557 [82–1559] | 0 [0–0] | 773 [708–898] | 237 [158–401] |
| H2 | forward | 4 | 1.515 / 2.913 | 1.265 / 2.531 | 200575 [174183–214192] | 53952 [45496–54889] | 833 [602–1153] | 430 [165–601] |
| H2 | reverse | 1 | 0.877 / 1.916 | 0.813 / 1.746 | 87 [0–375] | 20 [14–62] | 989 [893–1083] | 235 [223–288] |
| H2 | reverse | 4 | 1.515 / 2.927 | 1.410 / 3.039 | 124128 [117711–152345] | 34535 [26599–45552] | 670 [651–856] | 308 [268–370] |

## Partial WSS and omitted WAN trials

WSS uses explicit `/ws` URLs at both endpoints in the accepted partial dataset.
Each completed WSS cell has one sample. These samples cannot establish a repeated WSS comparison.
The owner stopped after the active transfer. The final candidate reverse four-stream transfer did not run.

| WSS direction | Streams | Baseline samples | Baseline Gbit/s | Candidate samples | Candidate Gbit/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| forward | 1 | 1 | 7.367 | 1 | 7.269 |
| forward | 4 | 1 | 7.431 | 1 | 7.223 |
| reverse | 1 | 1 | 6.994 | 1 | 6.752 |
| reverse | 4 | 1 | 7.359 | 0 | not run |

Partial WSS resources and reliability retain each single sample. RSS cells list endpoint A / B, in MiB.

| Direction | Streams | Binary | CPU s/Gbit A+B | RSS A / B | RTT p50 / p95 ms | Inner retrans | Outer retrans |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| forward | 1 | baseline | 0.297 | 23.0–24.8 / 22.5–22.8 | 1.020 / 2.659 | 3237 | 1216 |
| forward | 4 | baseline | 0.302 | 24.9–28.4 / 24.5–25.1 | 2.040 / 5.135 | 208794 | 1228 |
| reverse | 1 | baseline | 0.315 | 26.0–26.0 / 24.7–28.1 | 1.290 / 2.526 | 2037 | 631 |
| reverse | 4 | baseline | 0.314 | 26.0–26.0 / 25.1–31.4 | 2.420 / 5.104 | 239084 | 384 |
| forward | 1 | main | 0.301 | 22.3–25.1 / 23.0–23.2 | 1.395 / 2.643 | 2801 | 797 |
| forward | 4 | main | 0.314 | 24.2–30.3 / 25.9–25.9 | 2.620 / 5.565 | 213172 | 1612 |
| reverse | 1 | main | 0.322 | 25.6–25.6 / 26.0–28.5 | 1.040 / 2.725 | 3736 | 896 |

The revised matrix planned 120 transfers. `65` transfers are marked not run in `not-run.json`.
All 48 WAN matrix transfers were omitted. The remaining 17 clean transfers were also omitted.
The requested WAN profile was 40 ms egress delay and 0.1% random loss at each endpoint, with queue limit 250000.
Offloads remained enabled. Configured loss applies to qdisc-visible packet/GSO units.
Single substrate controls completed before the matrix: clean 108.071/121.730 Gbit/s and WAN 0.271/1.121 Gbit/s, for one/four streams.
These controls are context only. They do not establish a physical network ceiling or a repeated transport ranking.
Phase 2 was skipped at the PM request. No temporary real-path instance or binary was installed.

## Failures, recovery, and interpretation

The original pathless WSS configuration produced different connection behavior across revisions.
Baseline opened one connection. Candidate attempted 128 connections in each of its first two groups.
Source inspection shows that candidate WSS rewrites the connected URL to `/ws`; the configured manual-connector URL retained `/`.
The third candidate group panicked at `lowertier/src/tunnel/direct.rs:458` in snapshot `9b0af7eb`.
The panic message was `all branches are disabled and there is no else branch`.
Its four-stream forward transfer timed out; both subsequent reverse transfers received connection-refused errors.
The frozen source checks channel closure before a guarded `tokio::select!` without an `else` branch.
Channel closure between those checks can disable both branches. This is a source-derived cause for the panic.
The original failed group remains under `failed/`. Original WSS controls and successful groups remain under `contaminated/`.
Explicit `/ws` URLs removed reconnect churn from the seven accepted WSS transfers. No production code was changed.

The best throughput hypothesis is additional work in the packet pipeline, with a further QUIC-specific cost.
Candidate CPU cost per delivered Gbit increased in the complete QUIC and H2 comparisons.
Candidate adds source-MAC learning to ordinary TAP IP traffic and adds transit checks at the direct sink.
Source-MAC learning performs a mutable forwarding-table lookup for each packet.
QUIC migration handling also changed. This campaign does not isolate the responsible commit or function.
The first clean QUIC pair had similar wire bytes per delivered byte, about 1.077. Neither variant recorded QUIC packet loss in that pair.
At 1300 payload bytes, 1 Gbit represents approximately 96000 packets. An added microsecond per packet costs about 0.096 CPU seconds per Gbit.
This work model explains why per-packet costs warrant bisection. It is not a profile measurement.

The first Colima profile lacked a builder image and cache. The default profile had the runtime image and Rust image.
Its disk was full, causing verified apt operations to fail. Enlarging the disk to 140 GiB restored the verified builder build.
Main had removed `assets`. Cargo also required newly added workspace members in the staged source.
The baseline build initially reused a newer Quinn path artifact because older source timestamps did not invalidate the shared cache.
The harness now stages optional directories and refreshes staged timestamps. Both final release builds and all transport smoke tests passed.
One interrupted campaign group has no collected process exit code. Its complete logs remain in the contaminated dataset.

## Measurement limits and handoff

All accepted transfers have positive receiver delivery, full measured duration, expected MTUs, and one established connection per endpoint.
All 55 accepted ping summaries recorded replies to every transmitted probe before collection stopped.
Ping reply fraction covers warmup, measured traffic, and cleanup. It is not a measured-window packet-loss estimate.
Immediate ping termination can count an in-flight reply as missing. No such missing reply occurred in the accepted clean data.
Receiver/sender byte ratios are end-of-test accounting ratios. They are not packet-loss measurements.
Raw ratios, netem counters, namespace TCP counters, per-endpoint CPU costs, and latency ranges remain in `validated-trials.json`.
CPU and RSS samples use `/proc/<pid>/stat` at nominal 250 ms intervals, with 100 Hz ticks and 4096-byte pages.
CPU includes daemon user and system time. It excludes iperf, monitoring, and kernel networking work outside daemon accounting.
RSS includes shared resident pages and excludes kernel socket memory. Observed ranges are not guaranteed memory peaks.
Resource and loaded-RTT boundaries use wrapper completion minus receiver duration. These are approximate boundaries.
The reviewed clean trials had 34–306 ms combined startup and teardown overhead. Exact measured-window alignment cannot be recovered from retained text intervals.
QUIC loss counters use nearby one-second samples. Outer TCP and netem differences cover the full observed transfer.
The shared VM and sequential A/B order do not eliminate all host-load effects. Results apply to these source snapshots and this topology.

The temporary baseline worktree was removed. Benchmark containers, observer processes, and their Docker network stopped.
Colima remains running and available for exclusive regression bisection. Resident LowTier instances were not modified.
The resident authenticated Mac peer returned both verification pings. The real server used a different resident overlay address; no route was changed.
Raw artifacts: `benchmark-results/lean-core-ab-20261014/`.
Audit: `benchmark-results/.work/lean-core-ab-20261014.jsonl`.
Reproduction scripts, invocation environments, binary hashes, complete logs, failed trials, and omitted-cell records remain in those artifacts.

## Regression and fix

The source review compares baseline `10e33193` with main `502c81c4`.
The performance branch includes the new direct-sink drain, WSS connector, and patcher-order fixes.
The owner replaced bisection and profiling with code review and one confirming campaign.

The first valid campaign tested `66f45369`, before the log filter fix.
Each cell contains two interleaved repetitions with one stream.
Repetition one used baseline then candidate. Repetition two reversed that order.
Both directions used the same clean topology, TLS exporter binding, MTUs, build profile, and timing described above.
All 16 transfers passed binary hash, duration, one-connection, MTU, and CPU-sample checks.

| Transport | Direction | Baseline Gbit/s [range] | Candidate Gbit/s [range] | Delta | Baseline CPU s/Gbit [range] | Candidate CPU s/Gbit [range] |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | forward | 6.641 [6.441–6.840] | 4.767 [4.645–4.889] | -28.2% | 0.320 [0.310–0.331] | 0.434 [0.424–0.445] |
| QUIC | reverse | 6.665 [6.598–6.731] | 4.775 [4.752–4.799] | -28.3% | 0.321 [0.317–0.324] | 0.437 [0.434–0.441] |
| H2 | forward | 8.382 [8.327–8.437] | 6.616 [6.529–6.702] | -21.1% | 0.264 [0.264–0.264] | 0.335 [0.331–0.338] |
| H2 | reverse | 8.455 [8.435–8.475] | 6.607 [6.586–6.628] | -21.9% | 0.263 [0.261–0.264] | 0.335 [0.334–0.336] |

These measurements do not pass the performance gate.

RSS ranges cover endpoint A / B, in MiB. RTT gives median loaded p50 / p95, in milliseconds.
Retransmission cells show the two individual trials. QUIC outer loss was zero in every sampled window.
H2 outer retransmission counts include warmup and both endpoint sockets.

| Transport | Direction | Binary | RSS A / B | RTT p50 / p95 | Inner retransmissions | Outer H2 retransmissions |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| QUIC | forward | baseline | 25.2–25.4 / 27.5–28.1 | 0.408 / 0.836 | 0, 0 | not applicable |
| QUIC | forward | candidate | 22.7–25.5 / 26.8–27.4 | 0.393 / 0.842 | 0, 0 | not applicable |
| QUIC | reverse | baseline | 25.2–26.1 / 28.3–29.2 | 0.402 / 0.924 | 0, 0 | not applicable |
| QUIC | reverse | candidate | 25.1–26.0 / 27.5–27.8 | 0.394 / 0.780 | 0, 0 | not applicable |
| H2 | forward | baseline | 23.1–25.6 / 26.5–27.1 | 0.921 / 1.881 | 81, 271 | 1582, 1193 |
| H2 | forward | candidate | 22.2–24.3 / 25.0–26.3 | 0.904 / 1.896 | 28, 0 | 245, 188 |
| H2 | reverse | baseline | 24.0–25.6 / 27.1–29.1 | 0.875 / 1.830 | 254, 179 | 1397, 1122 |
| H2 | reverse | candidate | 22.8–24.5 / 25.9–28.1 | 0.868 / 1.694 | 0, 12 | 403, 335 |

All ping summaries recorded complete delivery. The same sampling limits apply as in the original report.
Source review then found a missing maximum-level hint in the control log filter.
Commit `0386ae55` restores global DEBUG/TRACE rejection at default INFO settings.
The focused log-level test, host check, Linux check, and format check pass.
The owner approved one final confirmation for that binary. The final results follow below.

The first attempted campaign used mismatched TAP MTUs, 1340 baseline and 1320 candidate.
Validation rejected those results. They remain under `invalid-mtu/`.
Recovery set configured MTU 1360 for both binaries and checked actual MTUs before each load.
No bisection or workload profile ran. WAN, WSS, and four-stream trials were excluded by the owner scope.
Raw repair artifacts are in `benchmark-results/lean-perf-20261014/`.

### Final confirmation

The final comparison tests `0386ae55` against baseline `10e33193`.
H2 meets the 3% throughput gate. QUIC misses the gate in both directions.
No further measurements ran after this campaign.
The same clean topology, one-stream matrix, timings, authentication, and MTUs were used.
Each cell contains two interleaved repetitions. All 16 transfers passed the validation checks.

| Transport | Direction | Baseline Gbit/s [range] | Fixed Gbit/s [range] | Delta | Baseline CPU s/Gbit [range] | Fixed CPU s/Gbit [range] |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | forward | 6.636 [6.549–6.723] | 6.417 [6.415–6.418] | -3.3% | 0.320 [0.316–0.324] | 0.332 [0.332–0.333] |
| QUIC | reverse | 6.679 [6.557–6.801] | 6.425 [6.396–6.454] | -3.8% | 0.321 [0.318–0.324] | 0.333 [0.333–0.333] |
| H2 | forward | 8.363 [8.325–8.401] | 8.253 [8.233–8.272] | -1.3% | 0.265 [0.265–0.266] | 0.270 [0.269–0.270] |
| H2 | reverse | 8.424 [8.405–8.444] | 8.200 [8.144–8.257] | -2.7% | 0.264 [0.263–0.265] | 0.271 [0.271–0.272] |

RSS ranges cover endpoint A / B, in MiB. RTT gives median loaded p50 / p95, in milliseconds.
Retransmission and loss cells list repetition one, then repetition two.
QUIC loss uses sampled measured-window counters. H2 outer retransmissions include warmup and both endpoint sockets.

| Transport | Direction | Binary | RSS A / B | RTT p50 / p95 | Inner retransmissions | Outer retransmissions or QUIC loss |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| QUIC | forward | baseline | 24.3–25.7 / 26.6–28.1 | 0.412 / 0.786 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | forward | fixed | 24.3–25.0 / 27.0–27.5 | 0.437 / 0.822 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | reverse | baseline | 24.6–26.1 / 27.3–29.1 | 0.421 / 0.849 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | reverse | fixed | 24.8–25.5 / 27.5–27.9 | 0.421 / 0.808 | 0, 0 | 0.0000%, 0.0000% |
| H2 | forward | baseline | 22.9–25.2 / 25.6–27.0 | 0.856 / 1.727 | 0, 0 | 902, 1221 |
| H2 | forward | fixed | 22.3–25.9 / 26.1–28.0 | 0.969 / 1.897 | 1063, 537 | 1025, 1284 |
| H2 | reverse | baseline | 23.6–25.3 / 26.2–29.2 | 0.862 / 1.782 | 316, 0 | 652, 953 |
| H2 | reverse | fixed | 23.7–25.6 / 27.3–29.8 | 0.923 / 2.102 | 381, 364 | 1515, 1056 |

Every ping summary recorded complete delivery. Receiver/sender byte accounting ratios ranged from 0.999916 to 1.000096.
Those ratios reflect end-of-transfer accounting. They do not measure packet loss.
Each endpoint supplied 79 or 80 CPU samples per measured window.
The sampling and shared-VM limits from the original report still apply. Two repetitions give limited statistical evidence.

The final binary SHA256 is `7a24e08ecfcdd668e81403e20a36b93e49d0b674ff9036fc106222252d99c6ba`.
The baseline binary hash matches the original report.
Manifest, invocation records, raw logs, validated trials, and summary are in `benchmark-results/lean-perf-20261014/final-confirmation/`.
Benchmark containers and the benchmark network have stopped. Colima remains available.
WAN, WSS, and four-stream performance remain unmeasured for the repaired binary.

### Remaining source suspects

The remaining QUIC CPU difference is about 0.012 CPU second per delivered Gbit.
At 1300 delivered payload bytes, that is about 0.12 microsecond per delivered data packet across both processes.
The H2 difference is about 0.004 through 0.007 CPU second per Gbit.
These measurements support investigation of small remaining packet costs. They do not identify a specific function.
The following ranking uses source evidence. No profile share or individual measured cost is available.

| Priority | Source | Remaining work and theoretical cost |
| --- | --- | --- |
| 1 | `vendor/quinn-proto/src/packet.rs:35`, `connection/datagrams.rs:123` | Every UDP packet now converts BytesMut to Vec, Bytes, and BytesMut to recover allocation capacity. The bytes conversion calls `ptr::copy`; equal-pointer execution cost is uncertain. Shared tails copy. DATAGRAM admission also tracks retained bytes and checks another queue bound. Cost scales with packet count. Extra branches, pointer conversion, metadata, or allocation can matter at a residual 0.12 microsecond per delivered packet. |
| 2 | `lowertier/src/peers/peer_manager.rs:872`, `peers/direct_nic.rs:566` | Compact TAP admission still parses each IP packet, classifies multicast/broadcast, applies type/VLAN policy, builds keep flags, and walks retained slots. Baseline skipped this admission without L2 policy. Cost remains O(N), even after address caching and removal of redundant moves. |
| 3 | `lowertier/src/peers/l2_fabric.rs:318`, `peers/peer_manager.rs:5153` | Default source learning still parses Ethernet policy metadata for each packet and reads the ownership generation. Cache membership scans up to U source tuples per packet. Parsing costs O(N). Membership costs O(N U). Mutable FDB work is O(U) while the generation stays unchanged. Small batches reduce the benefit. |
| 4 | `lowertier/src/tunnel/stats.rs:117`, `stats.rs:130` | TX and RX counters use adjacent atomic fields. Accounting uses two or three atomic additions per batch. Concurrent writers can share cache lines. Cost scales with N/B and contention. Preserve the counter race fix. No padding or counter tuning was attempted. |
| 5 | `lowertier/src/common/global_ctx.rs:1408`, `tunnel/direct.rs:48`, `peers/peer_conn.rs:4503` | Unlimited receive pacing still reads live flags. Local egress still scans transit flags and performs packet preparation. Transit/authentication fields add stores and metadata traffic. The live relay restriction also retains a packet-time ArcSwap read. These costs preserve runtime policy and authentication contracts. |

Camouflage access and TLS exporter checks remain setup costs, so they do not explain this residual packet cost.
The migration watcher remains periodic. This clean topology supplies no evidence of repeated rebinding.
The supplied benchmark does not configure a UDP decoy, so the decoy GRO fix does not explain its remaining gap.
Further work must preserve memory bounds, flood policy, FDB ownership, runtime limits, and authentication.

### Packet path review

The comparison uses baseline `10e33193` and main `502c81c4`.
The fixes are `226b495d`, `00b28f16`, `66f45369`, and `0386ae55`.
The owner replaced profiling and bisection with source analysis and one confirming campaign.

### Work model

Let N be the packet count, L the delivered TCP payload bytes per packet, and B the packet count per batch.
Let S be the segment count per GRO buffer, and U the distinct source tuples per batch.
Let K be the disabled trace events and spans reached per packet, including transport polls.
At L = 1300 bytes, one delivered Gbit contains about 96154 data packets.
An added 0.1 microsecond per packet costs about 0.0096 CPU second per Gbit.
A batch operation has about 1/B of that cost when batches contain B packets.
These estimates exclude ACK packets, retransmissions, and kernel work outside daemon CPU accounting.

The following latency ranges are assumptions for cost estimates.
They are not measured instruction costs on this VM.
An uncontended atomic or lock can cost tens through hundreds of nanoseconds.
Contention can increase that cost to microseconds.
An allocation, copy, and release can cost 0.1 through 1 microsecond for a small packet.
A time read can cost tens through hundreds of nanoseconds.
Assume a dynamic trace check costs 0.05 through 0.5 microsecond.
Its total cost is K times that cost per packet. K depends on transport framing and batching.
For K = 5, the estimate is 0.024 through 0.240 CPU second per delivered Gbit.

#### Send and receive paths

The send path is TAP read, NIC ingress workers, peer-manager fabric admission and routing,
peer connection preparation, session filtering, direct sink, and the transport writer.
QUIC submits DATAGRAM frames. H2 writes CONNECT-IP capsules in DATA frames.
WSS uses its WebSocket writer after the same peer and session stages.

The receive path is transport decoding, peer-connection session filtering, receive pacing,
peer-manager or direct-NIC admission, ACL processing, a NIC write batch, and TAP write.
The transport library trace calls execute inside these transport stages.

### Source inventory

| Path and function | Work added after baseline | Cost model | Fix or retained contract |
| --- | --- | --- | --- |
| TAP read and NIC ingress workers | No added per-packet production work in these modules. | Existing bounded reads and worker batching remain. | Keep the existing queues and batch limits. |
| TAP MTU selection | Main changes native TAP MTU calculation. Bridge mode can require DATAGRAM fragments on a 1500-byte underlay. | Up to two outer packets and allocations per large Ethernet frame. | Confirmation disables bridge mode and matches actual TAP MTU 1340. |
| `send_msg_by_hybrid_ethernet_batch` source admission | Source learning now runs by default. MAC quota changed from 0 to 256. Move hold changed from 0 to 5 seconds. | N mutable FDB lookups, hashes, shard locks, and timestamp stores. | Cache admitted sources within a batch. Recheck the ownership generation for each packet. Typical repeated sources need one lookup after insertion, or two during insertion. |
| `send_msg_by_hybrid_ethernet_batch` destination lookup | FDB resolution moved before the compact unicast path. Known owners also require route and origin checks. Invalid owners trigger a bounded FDB sweep. | A distinct destination needs a hash lookup. Known destinations can incur checks for each packet. | Skip FDB work for known overlay IP destinations and local virtual IP addresses. Keep FDB priority for real bridged destinations. |
| `sync_topology_service_routes` | Main adds another AcqRel generation swap and static-route publication. | Two shared atomic writes per packet, plus route rebuilding after a generation change. | Synchronize once per TAP batch. Use read checks before unchanged generation swaps. |
| `local_snapshot_next_hop` | Main adds a current relay-use check before snapshot lookup. | One borrowed ArcSwap load per routed packet. | Keep the live relay restriction. No configuration clone occurs here. |
| `PeerConn::prepare_outbound_transit` | New source/type classification and transit metadata preparation. | N header checks. Actual transit also clones an Arc for network metadata. | Return for local packets before type classification. Remove the separate full-batch source scan. |
| `TransitSink::start_send` | New sink layer upgrades two weak references and filters every batch. Actual transit also cloned network metadata and eagerly cloned the default identity. | O(N) filtering plus weak-reference atomics per batch. Transit identity and labels can allocate. | Local batches return directly after the transit flag scan. Transit packets borrow their network name. Resolve the default name only when required. |
| `GlobalCtx::admit_transit` | Permission, network, budget, and labeled metrics at actual transit egress. | A limited packet can require a mutex, time read, counter lookup, label allocation, and atomic accounting. | Preserve permission and budget checks after sink readiness. Local data bypasses this function. Remaining transit costs are explicit. |
| Session filter authentication clearing | Main clears receiving-connection authentication metadata before sending. | Fixed field stores per packet. | Keep the authentication boundary. |
| `ZCPacket` ownership | Main adds transit fields. NIC headroom grows from 8 to 18 bytes. | About 32 additional metadata bytes per packet move. Ten additional reserved bytes per NIC packet. | Keep transit classification and CONNECT-IP headroom. |
| Session filter and TLS exporter | The exporter mode still skips inner session AEAD for immediate direct QUIC, H2, and WSS hops. | Existing per-batch session loads and packet classification. | No new exporter derivation or binding check runs per packet. |
| QUIC DATAGRAM admission | Quinn copies every incoming DATAGRAM while holding connection ownership. The earlier application copy was removed. | An allocation and full payload copy occur on the serial receive driver. | Charge normalized backing allocation capacity. Keep ordinary packet storage. Copy only when the backing allocation exceeds the receive window. |
| QUIC packet ownership normalization | The fix recovers Vec allocation capacity before packet splitting. | No second allocation for independent offset-zero input. Shared coalesced tails copy. The bytes implementation calls `ptr::copy`, even for equal pointers. | Exact capacity supports a strict retained-memory bound. Self-copy execution cost remains uncertain from source alone. |
| `QuicDecoySocket::route_received` | Main routes every GRO segment separately. Cached segments read time, hash the tuple, lock a shard, and update an atomic timestamp. | N route lookups instead of about N/S. | Route an established tuple once per GRO buffer. Keep segment inspection for an unknown tuple that can mix Initial and short-header packets. |
| Quinn socket and path processing | Main tags receive batches with socket identity. It tracks current-socket delivery and credits the actual source path. | Pointer comparison per event batch. Boolean stores and address checks per received UDP packet. | Preserve migration validation and anti-amplification accounting. Same-path traffic skips migration policy calls. |
| QUIC migration watcher | Main scans client paths every two seconds and listens for route changes. Rebinding can reset path state. | Episodic socket probes and route checks. This is not per-packet work. | Unchanged source and route generation avoid rebinding. No speculative watcher change was made. |
| QUIC I/O statistics | Main checks the migration-rejection count when recording I/O statistics. | One atomic read and branch per statistics call. | Keep the counter. Packet labels are not formatted on the unchanged path. |
| QUIC keepalive | Main adds a three-second keepalive and ten-second idle timeout. | O(connections/time), rather than O(data packets). | Keep liveness and dead-path retirement. |
| H2 CONNECT-IP reader and writer | The packet reader, decoder, DATA credit release, coalescing size, flow-control windows, and flush code match baseline. | No new per-packet cost was found in `http2.rs`. | Keep those implementations. |
| H2 and QUIC camouflage settings | Methods return borrowed settings. SNI, host, admission token, certificate, and decoy changes occur at setup or accept. | Connection setup cost. No packet-time configuration clone was found in H2. | No camouflage rewrite was needed. |
| `DirectNicIngress` compact admission | Main applies compact-IP policy and flood admission on each received TAP packet. | N IP parses, address loads, flag decisions, and retained packet moves. The IPv4 AtomicCell uses a fallback sequence lock. Reads usually use its optimistic path. | Preserve flood and type policy. Read the IPv4 broadcast address once per batch. The shared retention fix removes moves before the first rejected packet. |
| `PacketBatch::retain_flags` | New compact admission calls this helper even when every packet is kept. The helper reads and writes each packet slot. | About 2 times packet-metadata size times N of memory traffic. | Move only when read and write slots differ. |
| `GlobalCtx::pace_receive` | A shared receive-budget mutex replaces an absent optional limiter on unlimited receive batches. | About N/B mutex acquisitions and weak-reference operations. | Read the current effective limit first. Unlimited reception skips the mutex. |
| Throughput counters at current main | Unsafe counters become atomic. | Two or three atomic additions per existing batch accounting call. Possible TX/RX cache-line sharing remains. | Keep the race fix. No fixture-specific padding or instruction tuning was added. |
| Direct NIC writer and tunnel owner | Their queues and write ownership already exist in baseline. Main separates the NIC module and fixes sink shutdown draining. | No additional queue hop, GSO/GRO disablement, or ordinary flush change was found. | Keep the new shutdown drain logic. |
| `ControlLogFilter` in `rpc_service/control/logs.rs` | Commit `de798b9f` adds control log capture. Commit `40908f8e` adds its level filter with no maximum-level hint. It returns dynamic callsite interest. Default INFO therefore loses global DEBUG/TRACE rejection. Existing QUIC and H2 trace events and spans enter the subscriber on packet processing and transport polls. | K dynamic subscriber calls per packet. Enabled checks include layer traversal, context access, and filter state. Transport field formatting remains disabled when all filters reject. | Publish the current maximum level. Rebuild the global cache after level changes. Serialize control updates and file-filter reloads. Keep dynamic callsite interest to avoid a first-registration race. |
| Crypto, compression, FEC, and stage sampling | Removal deletes inactive filters and compression/FEC work. Secure datagrams already used Ring. Stage sampling already existed. | No added enabled cipher was found. | Keep the removals. |

### Predicted change

The fixes remove common FDB writes, unchanged route-generation writes, unused budget locking, and redundant packet moves.
The log filter fix restores rejection before subscriber access at default INFO settings.
It removes work at existing QUIC and H2 trace calls. WSS has fewer such transport calls.
QUIC also removes the mandatory received-payload allocation and copy from connection processing.
The memory bound uses actual retained allocation capacity, rather than payload length alone.
Default MAC quotas, move holds, bridge checks, transit denial, and rate limits remain enforced.
No new queue or resource limit was added.

The original WSS sample difference is consistent with the trace-filter hypothesis.
Only one corrected WSS sample existed for each completed cell.
Transport batch sizes and other bottlenecks can change the cost of shared work per delivered byte.
The first valid confirmation measures the first three commits. It still shows the regression.
The final approved confirmation measures `0386ae55`. H2 meets the gate, while QUIC remains 3.3% through 3.8% below baseline.
No measured percentage can be assigned to an individual function from the current evidence.

### Remaining packet overhead repair

The `perf2` confirmation does not meet the complete performance gate.
QUIC forward is 2.34% below baseline. QUIC reverse is 0.71% above baseline and uses less daemon CPU per delivered Gbit.
H2 is 2.41% below baseline forward and 2.40% below baseline reverse.
Daemon CPU cost remains above baseline in the three slower cells.
All 16 transfers pass validation. No further measurements ran.

Worker `perf2` reviewed the remaining paths from `bca6da2d` before changing the source.
The repair uses `enable_bridge` at fabric creation to select TAP admission.
Without bridging or explicit VLAN/EtherType filters, local TAP traffic skips source learning.
Received compact IP also skips flood classification, keep flags, and retention traversal in that mode.
Explicit filters still apply without bridging.
Enabled bridges retain source ownership, move holds, MAC quotas, ingress flood limits, and complete Ethernet authorization.
Bridge policy changes require an instance restart, as before.
The control API classifies flag changes as restart changes and rejects direct application to a running instance.

Quinn now passes an owned UDP allocation to `Endpoint::handle_owned`.
The allocation capacity is read before conversion to `BytesMut`.
Partial decoding retains that capacity through every coalesced packet.
This removes the `BytesMut` to `Vec` capacity-recovery conversion from normal socket reception.
Coalesced tails also avoid normalization and payload copies.
The existing `Endpoint::handle` and public decoder still normalize external `BytesMut` slices.
DATAGRAM admission still bounds payload bytes, retained allocation bytes, and entry metadata.
Each queued DATAGRAM conservatively charges the full original allocation.
An allocation larger than the receive window still requires a compact payload copy.

Throughput counters use separate `CachePadded` TX and RX groups.
All counters remain atomic.
On aarch64, the counter object occupies 256 bytes instead of 40 bytes, from its declared layout.
This adds 216 bytes per counter object and prevents concurrent direction writers from sharing a cache line.
Receive pacing uses an atomic limit flag instead of loading the flags through ArcSwap.
Runtime updates publish this flag after updating the budget.
Foreign contexts still use their parent's receive budget.

The local transit scan and outbound source check remain.
These checks distinguish forwarded traffic from local traffic without changing authentication or queued transit admission.
Local packets already return before transit network allocation and destination writes.
Outbound session filters still clear incoming authentication metadata.
That boundary must remain when a received packet is forwarded.

For N data packets and B packets per batch, the default non-bridge path removes N source-policy parses.
It also removes N receive-policy parses and classification operations, plus the keep-flag and retention passes.
QUIC removes one ownership-conversion sequence per UDP packet and copies of shared coalesced tails.
The retained-memory charge remains O(1) per DATAGRAM.
Counter accounting still performs the same atomic additions per batch, with separate direction storage.
No queue, resource limit, fixture threshold, or transport parameter was added.

### Perf2 confirming comparison

The candidate is `da6ba2aa`, with the preceding changes in `fe652ea2` and `93f5f09f`.
The baseline remains `10e33193`, with the original retained Linux binary.
Both use Rust 1.95.0, release fat LTO, no default features, and `tun`.
Colima uses aarch64 VZ, three vCPUs, 8 GiB RAM, and a 1500-byte underlay MTU.
The clean matrix uses QUIC and H2, one inner TCP stream, forward and reverse, and two interleaved repetitions.
Repetition one runs baseline then candidate. Repetition two runs candidate then baseline.
Warmup lasts ten seconds. The measurement window lasts twenty seconds.
Configured TAP MTU is 1360. Both binaries use an actual TAP MTU of 1340.
Secure mode, private admission, encryption configuration, and TLS exporter binding remain enabled.

Each cell reports the arithmetic mean and the range of its two repetitions.
CPU cost sums daemon CPU at both endpoints and divides by delivered Gbit.
The gate requires throughput within 2% of baseline and CPU cost no greater than baseline.

| Transport | Direction | Baseline Gbit/s [range] | Candidate Gbit/s [range] | Delta | Baseline CPU s/Gbit [range] | Candidate CPU s/Gbit [range] |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | forward | 6.692 [6.503, 6.880] | 6.535 [6.292, 6.778] | -2.34% | 0.318 [0.307, 0.328] | 0.327 [0.313, 0.341] |
| QUIC | reverse | 6.644 [6.494, 6.794] | 6.691 [6.659, 6.722] | +0.71% | 0.323 [0.316, 0.331] | 0.318 [0.317, 0.319] |
| H2 | forward | 8.617 [8.530, 8.703] | 8.409 [8.319, 8.500] | -2.41% | 0.257 [0.255, 0.260] | 0.265 [0.262, 0.268] |
| H2 | reverse | 8.579 [8.524, 8.635] | 8.374 [8.257, 8.490] | -2.40% | 0.259 [0.258, 0.260] | 0.266 [0.262, 0.270] |

Only QUIC reverse meets both gates.
The source changes remove identified work, but the complete gate remains unmet.
Two repetitions do not establish a narrow confidence interval or an individual function's measured contribution.

RSS gives the sampled minimum and maximum at endpoint A and endpoint B, in MiB.
RTT is the mean of each repetition's loaded p50 / p95, in milliseconds.
Retransmission cells give repetition one, then repetition two.
H2 outer retransmissions include warmup and both endpoint sockets.

| Transport | Direction | Binary | RSS A / B | RTT p50 / p95 | Inner retransmissions | Outer retransmissions or QUIC loss |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| QUIC | forward | baseline | 25.3, 25.7 / 26.6, 27.6 | 0.419 / 0.778 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | forward | candidate | 24.9, 25.8 / 27.1, 27.7 | 0.400 / 0.791 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | reverse | baseline | 25.6, 25.9 / 27.4, 28.3 | 0.387 / 0.760 | 0, 0 | 0.0000%, 0.0000% |
| QUIC | reverse | candidate | 25.0, 26.1 / 28.0, 28.4 | 0.393 / 0.761 | 0, 0 | 0.0000%, 0.0000% |
| H2 | forward | baseline | 22.1, 25.0 / 24.8, 27.1 | 0.912 / 1.964 | 177, 51 | 740, 1087 |
| H2 | forward | candidate | 22.1, 25.8 / 25.5, 26.8 | 0.896 / 2.019 | 723, 28 | 1220, 910 |
| H2 | reverse | baseline | 23.2, 24.5 / 25.4, 28.6 | 0.887 / 1.850 | 78, 375 | 866, 980 |
| H2 | reverse | candidate | 24.8, 26.0 / 26.7, 29.5 | 0.934 / 1.950 | 1048, 850 | 1414, 1530 |

Each transfer passed binary SHA256, connection count, duration, MTU, and CPU-sample checks.
Each endpoint supplied 79 or 80 CPU samples per measured window.
Every ping summary recorded complete delivery. Every sampled QUIC window recorded zero outer loss.
Receiver/sender byte accounting ratios ranged from 0.999956 to 1.000134.
These ratios do not measure packet loss.
CPU excludes iperf and kernel work outside daemon accounting. RSS excludes kernel socket memory.
The requested retained-memory limits remain unchanged; no process peak-memory bound is inferred from these RSS samples.

The baseline SHA256 is `c8c708fb47cce00d9ca5cb9e8405ed96d22d9f6d3722bee21c48bb5aad2092e0`.
The candidate SHA256 is `b9f5d85252aca3e1546473214e5844354125bff2a0457cc9a24eabcef9e4a5f8`.
Raw logs, configurations, invocation records, binaries, source patch, scripts, and summaries are in
`/Users/boyu/code/lowertier-wt/perf2/benchmark-results/lean-perf2-20261014/`.
The campaign command was `python3 /private/tmp/perf2-run.py confirm 1200 python3 /private/tmp/perf2-confirm.py`.
The validation command was `python3 /private/tmp/perf2-run.py analyze 120 python3 /private/tmp/perf2-summary.py`.
Both commands completed successfully. `summary.json` records the failed performance gate separately.

Host and aarch64 Linux checks, locked metadata, and formatting of all changed Rust files pass.
The focused tests pass: 38 L2 cases, seven direct-sink cases, 12 Quinn DATAGRAM cases, and one coalesced-header case.
The existing tests now also check non-bridge filter behavior, shared allocation charges, and local/foreign runtime receive-limit changes.
No new test marker was added.
WAN, WSS, four-stream, full bridge performance, and a broad Caddy matrix remain unmeasured for this candidate.
The benchmark containers and network have stopped. No resident LowTier node was changed.

## WSS repeated

This campaign compares baseline `10e33193` with snapshot `f3c62ece`.
Each cell has three interleaved repetitions, in baseline/candidate order.
Explicit `/ws` listener and peer URLs prevent the earlier connector mismatch.
The clean Colima profile uses the topology, build profile, authentication, and MTUs described above.
Each trial excludes ten warmup seconds and measures twenty seconds.
The matrix has 24 transfers: both directions, one/four streams, two binaries, and three repetitions.

Throughput and CPU cells give median [minimum–maximum]. CPU sums both LowTier daemons.

| Direction | Streams | Baseline Gbit/s | Candidate Gbit/s | Delta | Baseline CPU s/Gbit | Candidate CPU s/Gbit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| forward | 1 | 7.931 [7.473–7.948] | 7.640 [7.498–7.762] | -3.7% | 0.281 [0.278–0.300] | 0.292 [0.287–0.292] |
| forward | 4 | 8.132 [7.868–8.347] | 7.935 [7.838–8.085] | -2.4% | 0.282 [0.272–0.293] | 0.288 [0.282–0.295] |
| reverse | 1 | 7.406 [7.179–7.533] | 7.400 [7.392–7.460] | -0.1% | 0.303 [0.297–0.313] | 0.301 [0.299–0.301] |
| reverse | 4 | 7.750 [7.507–7.920] | 7.653 [7.443–7.681] | -1.2% | 0.302 [0.295–0.308] | 0.302 [0.301–0.312] |

RSS covers endpoint A / B in MiB. Loaded RTT gives median [range] for p50 / p95 in milliseconds.
Retransmission lists retain all three repetitions. Outer counts include warmup and both endpoint sockets.

| Direction | Streams | Binary | RSS A / B | Loaded RTT p50 / p95 | Inner retransmissions | Outer retransmissions |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| forward | 1 | baseline | 21.2–24.7 / 22.5–22.8 | 1.240 [1.055–1.310] / 2.485 [2.417–2.903] | 1565, 2347, 1937 | 965, 539, 876 |
| forward | 1 | main | 22.2–25.6 / 22.8–22.9 | 1.210 [1.130–1.300] / 2.840 [2.554–2.882] | 556, 1887, 872 | 711, 695, 919 |
| forward | 4 | baseline | 25.7–28.9 / 24.9–25.9 | 2.470 [2.420–2.640] / 4.552 [4.446–5.022] | 103400, 271513, 171177 | 1112, 1197, 1484 |
| forward | 4 | main | 24.0–30.5 / 24.7–25.6 | 2.520 [2.470–2.990] / 4.986 [4.778–5.546] | 200382, 136350, 201615 | 2011, 1086, 1719 |
| reverse | 1 | baseline | 26.4–26.8 / 24.7–28.2 | 1.210 [0.994–1.280] / 2.451 [2.388–2.587] | 914, 749, 1468 | 595, 954, 571 |
| reverse | 1 | main | 26.0–29.0 / 24.9–28.5 | 1.180 [1.065–1.330] / 2.480 [2.446–2.554] | 2204, 2634, 2650 | 735, 522, 742 |
| reverse | 4 | baseline | 26.4–26.8 / 25.4–31.9 | 2.400 [2.210–2.680] / 4.865 [4.822–5.428] | 182483, 203645, 203340 | 956, 642, 491 |
| reverse | 4 | main | 26.0–29.1 / 25.9–33.6 | 2.720 [2.600–2.955] / 5.264 [5.061–5.694] | 204257, 148933, 141545 | 668, 656, 1180 |

Ping delivery was 3594/3594 across the observation windows.
The existing measured-window CPU, RTT, byte-accounting, and RSS limits apply.
Host release compilation ran during this campaign. This background load limits comparisons near the measurement spread.
These measurements do not establish the full default-on performance gate.

Colima baseline SHA256: `c8c708fb47cce00d9ca5cb9e8405ed96d22d9f6d3722bee21c48bb5aad2092e0`.
Colima candidate SHA256: `bf19b3b658bca9caf3d0b9f25fb938cb960cd1c6875d7b2d016a634e2a5e3f6b`.

## Real internet A/B

The Mac Studio and s6916 used isolated temporary instances over the public address `193.32.149.82`.
Management used SSH through the established Tailscale address. Benchmark peer traffic did not use the Tailscale overlay.
The Mac used native TUN. Linux used native TAP with compact IP. Actual interface MTUs were 1280.
The Mac has 16 logical CPUs. s6916 has two logical CPUs and runs Debian 11 with Linux 5.10.0-35-cloud-amd64.
Both release builds used Rust 1.95.0, no default features, and feature `tun`.
The Mac target was aarch64-apple-darwin. The Linux target was x86_64-unknown-linux-musl, built with cargo-zigbuild.
Iperf versions were 3.21 locally and 3.9 remotely.
Each trial requested one inner TCP stream for 12 sender seconds, without excluded warmup.
Each protocol ran two interleaved baseline/candidate repetitions in upload and download directions.
Upload means Mac to s6916. Download means s6916 to Mac.
The temporary network used separate secrets, work directories, overlay addresses, listener port 19924, and RPC port 19923.
Private admission, secure mode, ChaCha20-Poly1305, and TLS exporter authentication remained enabled.

| Transport | Direction | Baseline Mbit/s | Candidate Mbit/s | Delta | Baseline Mac / Linux CPU s/Gbit | Candidate Mac / Linux CPU s/Gbit |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | upload | 447.4 [443.1–451.8] | 438.6 [437.1–440.1] | -2.0% | 0.720 [0.714–0.726] / 3.133 [3.113–3.154] | 0.832 [0.778–0.885] / 3.158 [3.141–3.175] |
| QUIC | download | 416.0 [406.8–425.3] | 419.5 [409.4–429.6] | +0.8% | 1.231 [1.220–1.242] / 2.647 [2.588–2.707] | 1.224 [1.217–1.230] / 2.542 [2.366–2.717] |
| H2 | upload | 393.8 [336.1–451.6] | 449.7 [448.9–450.5] | +14.2% | 0.773 [0.331–1.214] / 2.869 [2.792–2.945] | 0.336 [0.324–0.348] / 2.791 [2.773–2.809] |
| H2 | download | 415.7 [385.2–446.2] | 445.6 [443.4–447.9] | +7.2% | 1.330 [1.133–1.527] / 1.331 [1.291–1.370] | 1.218 [1.190–1.247] / 1.376 [1.358–1.393] |
| WSS | upload | 340.2 [249.7–430.7] | 452.4 [451.7–453.2] | +33.0% | 0.569 [0.376–0.761] / 2.904 [2.900–2.908] | 0.568 [0.370–0.766] / 2.893 [2.846–2.940] |
| WSS | download | 433.6 [416.4–450.7] | 432.7 [417.7–447.6] | -0.2% | 0.982 [0.909–1.054] / 1.331 [1.248–1.414] | 0.950 [0.875–1.025] / 1.410 [1.294–1.525] |

RSS gives observed Mac / Linux ranges in MiB. Loaded RTT gives median [range] for each trial p50.
Each trial sent 12 ping probes at 0.5-second intervals during the transfer.

| Transport | Direction | Binary | RSS Mac / Linux | Loaded RTT p50, ms | Loaded RTT p95, ms | Inner TCP retransmissions |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| QUIC | upload | baseline | 25.0–28.7 / 19.8–30.3 | 14.53 [14.31–14.76] | 24.55 [23.98–25.13] | 1649, 798 |
| QUIC | upload | main | 25.4–31.8 / 19.5–30.4 | 18.76 [16.16–21.35] | 31.75 [31.16–32.34] | 1099, 942 |
| QUIC | download | baseline | 28.6–29.1 / 30.0–31.4 | 12.24 [12.01–12.47] | 14.56 [13.28–15.83] | 28989, 102 |
| QUIC | download | main | 29.8–32.5 / 29.8–31.9 | 13.00 [12.62–13.37] | 18.19 [15.38–21.01] | 4070, 18573 |
| H2 | upload | baseline | 24.3–30.1 / 17.8–35.7 | 35.15 [31.38–38.92] | 42.38 [35.95–48.80] | 146, 83 |
| H2 | upload | main | 24.6–31.3 / 18.0–37.4 | 29.63 [28.95–30.30] | 35.81 [33.71–37.90] | 156, 113 |
| H2 | download | baseline | 29.2–31.0 / 30.7–38.6 | 28.97 [26.23–31.70] | 44.48 [37.95–51.02] | 3, 11 |
| H2 | download | main | 31.4–32.4 / 32.8–44.2 | 27.71 [26.15–29.26] | 48.69 [34.78–62.60] | 0, 0 |
| WSS | upload | baseline | 24.2–30.5 / 17.8–51.4 | 58.56 [47.42–69.70] | 76.80 [75.12–78.47] | 37, 2 |
| WSS | upload | main | 24.5–30.5 / 16.7–58.5 | 69.04 [67.53–70.56] | 75.05 [74.78–75.32] | 78, 0 |
| WSS | download | baseline | 28.9–31.3 / 40.4–51.6 | 27.21 [24.91–29.51] | 54.07 [51.85–56.30] | 0, 0 |
| WSS | download | main | 29.9–31.8 / 46.6–58.7 | 25.84 [22.27–29.40] | 57.93 [41.78–74.09] | 0, 0 |

All 288 of 288 ping probes returned.
All transfers had positive receiver delivery, the requested sender duration, and stable authenticated connection IDs.
Baseline WSS upload repetition two sent for 12.140 seconds but recorded 22.219 receiver seconds.
Its final server interval spans 10.217 seconds and contains 12.157 MB. The raw record does not establish the delay cause.
That result remains in the table at 249.7 Mbit/s. The WSS upload delta therefore includes unequal receiver observation durations.
The result cannot establish a matched 12-second WSS upload speed improvement. No slow trial was discarded or replaced.
CPU includes daemon user and system time. Nominal sampling was 250 ms on both hosts.
CPU cost divides sampled CPU seconds by receiver-delivered Gbit. The observation windows include transfer setup and teardown.
CPU excludes iperf, monitoring, and kernel networking work outside daemon accounting.
RSS includes shared pages and excludes kernel socket memory. Observed ranges do not establish peak memory.
Inner TCP retransmissions do not measure outer QUIC loss or outer H2/WSS TCP retransmissions.
Remote socket and network snapshots remain in the raw records. Outer loss was not measured symmetrically.
Receiver/sender byte ratios remain end-of-transfer accounting ratios, not packet-loss measurements.
Two short repetitions cannot separate transport effects from changing internet conditions and host load.
Four-stream QUIC trials did not run. Caddy routing and unauthorized-probe tests were outside this measurement brief.

The temporary processes, binaries, configurations, and baseline worktree were removed.
Resident process IDs and binary hashes remained unchanged. Resident authenticated peers and ping delivery passed after cleanup.
No resident configuration, keys, ACLs, routes, or binary was replaced.

The first host build failed because Rust 1.95.0 was incomplete. Toolchain recovery restored the requested version.
The first cross build passed an incompatible Zig target. Removing the explicit compiler setting restored cargo-zigbuild.
The `s6916` SSH alias failed host-key verification. The established verified Tailscale IP identity succeeded.

The first candidate startup check assumed the old CLI JSON shape. The updated parser reads the main CLI data envelope.
The two completed baseline QUIC trials were retained. Cleanup and resident identity checks passed before the campaign resumed.
A root-owned output directory prevented one failure-log move. Ownership recovery preserved the traceback and campaign log.
The failed local startup log was overwritten. The audit retains the corresponding remote log and CLI response.

That ownership change also changed the control-token owner. Candidate startup correctly rejected the token.
Cleanup removed the token. The resumed campaign retained six completed trials and preserved token ownership.

Artifacts: `benchmark-results/lean-core-real-20261014/`.
Audit: `benchmark-results/.work/lean-core-20261014-bench2.jsonl`.
Raw JSON, complete logs, resource samples, path records, invocation records, and build manifests remain available.

Observed average sampling intervals were 317.6–374.3 ms on the Mac and 250.6–251.0 ms on Linux.
Receiver/sender byte-accounting ratios ranged from 0.970303–1.000142.
Both daemons used two worker threads and one authenticated transport connection.
The Mac public route used en0 with underlay MTU 1500. The server public interface used eth0 with MTU 1500.
The harness retained operating-system TCP congestion defaults for both binaries. Linux used BBR; the Mac algorithm was not recorded.

| Binary | SHA256 |
| --- | --- |
| baseline-mac | `19433e6980a8a3c77fbfd4d89c1f3ca05179ec2453e414ecd632baf422fbcafe` |
| main-mac | `6dd8d74fdf5e47b876e52c24073541226edbf18d623038fbde3ea801abe6109a` |
| baseline-remote-linux | `4a28137cffcda19cc23c709b521e5435f485bc69c141aa10e2bbf2484c51a963` |
| main-remote-linux | `ff1ac4ede2d2ee29290be39dbb39e8e6d3e857ff2090356ea71750facd9a2a6c` |

## Loaded-latency changes

This confirmation compares A `f3c62ece` with B `1b2452cd`.
The clean H2 guard fails: median throughput falls 6.43%, beyond the allowed 3% loss.
Clean QUIC and WSS pass this throughput guard. Their changes are -1.41% and -0.23%.
Public upload p50 decreases for all transports. H2 download p95 increases.
Public QUIC throughput falls, and repetition-one measurement contamination limits that comparison.
The campaign does not establish acceptance of the loaded-latency changes.
The campaign ran once, without performance iteration or replacement of slow trials.
B adds NIC CoDel, ECN marking, bounded unsent queues, and complete QUIC packet expiry.
The source model predicts less local backlog while preserving network flight capacity.
At 450 Mbit/s, the 384 KiB NIC handoff limit represents 6.99 ms of payload service.
The QUIC admission floor represents 5.12 ms at a 1500-byte path MTU.
These estimates describe individual stages, not an RTT guarantee.

### Public-path confirmation

The campaign reused the isolated Mac Studio to s6916 method from the preceding section.
Each transport used one stream, 12 sender seconds, and two interleaved A/B repetitions in both directions.
Each transfer included 12 ping probes at 0.5-second intervals, as in bench2.
Actual overlay MTU was 1280. Underlay MTU was 1500.
Each process used two worker threads and one authenticated transport connection.
Management used Tailscale SSH. Peer traffic used the public address and separate temporary credentials.

A duplicate Colima compilation overlapped both A QUIC repetition-one transfers and B QUIC repetition-one upload.
The duplicate build was stopped. All affected trials remain in the tables and raw records.
The benchmark supervisor was also paused during B QUIC repetition-one upload. Iperf, ping, and both daemons continued.
That pause left only three Mac resource samples. Its CPU endpoints remain recorded, but RSS and sampling coverage are incomplete.
The largest Mac sampling gap in that record was 13.085 seconds.
These records cannot establish a repeated matched QUIC comparison without measurement contamination.

Loaded RTT is the primary metric. Cells give median [minimum–maximum] across two trials.

| Transport | Direction | A RTT p50 ms | B RTT p50 ms | A RTT p95 ms | B RTT p95 ms |
| --- | --- | ---: | ---: | ---: | ---: |
| QUIC | upload | 18.49 [17.23–19.75] | 12.10 [11.55–12.66] | 56.72 [22.60–90.84] | 15.54 [11.81–19.27] |
| QUIC | download | 13.32 [12.33–14.30] | 13.02 [12.98–13.07] | 15.92 [13.90–17.94] | 15.50 [15.39–15.61] |
| H2 | upload | 32.00 [31.83–32.16] | 16.07 [12.14–19.99] | 37.71 [37.08–38.34] | 20.15 [12.41–27.89] |
| H2 | download | 26.55 [25.66–27.43] | 23.64 [23.48–23.79] | 35.15 [32.01–38.29] | 40.68 [33.44–47.92] |
| WSS | upload | 63.54 [57.03–70.05] | 40.66 [40.16–41.15] | 68.98 [62.96–75.00] | 59.49 [51.39–67.60] |
| WSS | download | 23.54 [21.82–25.26] | 22.56 [17.24–27.88] | 55.64 [26.73–84.55] | 45.78 [41.72–49.85] |

| Transport | Direction | A Mbit/s | B Mbit/s | Change | A Mac / Linux CPU s/Gbit | B Mac / Linux CPU s/Gbit |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | upload | 434.5 [434.0–434.9] | 290.3 [283.7–296.9] | -33.2% | 0.829 [0.637–1.021] / 3.179 [3.174–3.184] | 1.170 [0.842–1.497] / 3.993 [3.860–4.126] |
| QUIC | download | 422.5 [406.1–438.9] | 388.3 [364.0–412.5] | -8.1% | 0.862 [0.505–1.219] / 2.537 [2.326–2.748] | 1.319 [1.293–1.345] / 2.880 [2.821–2.938] |
| H2 | upload | 440.4 [428.4–452.4] | 381.7 [314.5–449.0] | -13.3% | 0.640 [0.337–0.944] / 2.821 [2.790–2.853] | 0.578 [0.390–0.766] / 2.944 [2.859–3.030] |
| H2 | download | 437.5 [430.4–444.5] | 445.1 [441.9–448.2] | +1.7% | 1.283 [1.211–1.354] / 1.443 [1.393–1.493] | 1.211 [1.208–1.215] / 1.365 [1.359–1.371] |
| WSS | upload | 451.5 [449.0–454.1] | 446.2 [443.9–448.4] | -1.2% | 0.620 [0.350–0.891] / 2.878 [2.855–2.900] | 0.584 [0.536–0.632] / 2.940 [2.918–2.962] |
| WSS | download | 427.0 [410.1–443.9] | 449.5 [446.3–452.7] | +5.3% | 1.008 [0.981–1.035] / 1.535 [1.530–1.540] | 0.941 [0.859–1.023] / 1.431 [1.264–1.599] |

RSS gives observed Mac / Linux ranges in MiB. Retransmission lists retain both repetitions.

| Transport | Direction | Binary | RSS Mac / Linux MiB | Inner TCP retransmissions |
| --- | --- | --- | ---: | ---: |
| QUIC | upload | A | 25.3–30.9 / 19.4–30.3 | 506, 857 |
| QUIC | upload | B | 25.4–30.6 / 24.4–34.8 | 1006, 2055 |
| QUIC | download | A | 30.1–31.3 / 29.2–31.8 | 3, 12264 |
| QUIC | download | B | 28.1–30.9 / 33.2–36.4 | 918, 35887 |
| H2 | upload | A | 24.4–31.3 / 18.2–39.5 | 189, 181 |
| H2 | upload | B | 24.5–30.6 / 21.0–46.6 | 114, 112 |
| H2 | download | A | 29.6–32.4 / 33.7–46.4 | 0, 0 |
| H2 | download | B | 30.1–31.4 / 38.1–52.1 | 8, 34 |
| WSS | upload | A | 24.4–30.0 / 17.4–34.4 | 0, 94 |
| WSS | upload | B | 24.5–30.0 / 20.9–44.2 | 0, 0 |
| WSS | download | A | 29.7–31.2 / 30.7–34.5 | 0, 0 |
| WSS | download | B | 29.9–31.1 / 38.3–44.5 | 1119, 0 |

B counters are before/after differences on each host. Queue residence is the sojourn sum divided by dequeued packets.
Counter windows include transfer setup and teardown. Each cell retains both repetitions.

| Transport | Direction | Host | NIC drops | NIC marks | Mean NIC residence us | NIC dequeued | Expired QUIC packets |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| QUIC | upload | Mac | 0, 0 | 0, 1 | 4.79, 1084.14 | 350406, 365945 | 881, 1271 |
| QUIC | upload | Linux | 0, 0 | 0, 0 | 1.67, 4.05 | 71729, 66742 | 5, 2 |
| QUIC | download | Mac | 0, 0 | 0, 0 | 2.06, 3.32 | 58104, 216129 | 0, 0 |
| QUIC | download | Linux | 5, 0 | 1016, 2 | 12259.75, 1849.96 | 453039, 548774 | 476, 516 |
| H2 | upload | Mac | 114, 100 | 1, 2 | 383.17, 705.28 | 386244, 551147 | not applicable |
| H2 | upload | Linux | 0, 0 | 0, 0 | 1.46, 1.84 | 31762, 45902 | not applicable |
| H2 | download | Mac | 0, 0 | 0, 0 | 2.82, 2.11 | 50002, 50227 | not applicable |
| H2 | download | Linux | 0, 34 | 60, 39 | 9376.08, 9800.24 | 555918, 549507 | not applicable |
| WSS | upload | Mac | 0, 0 | 1, 1 | 1129.31, 1008.92 | 551357, 554518 | not applicable |
| WSS | upload | Linux | 0, 0 | 0, 0 | 5.15, 2.58 | 66816, 63484 | not applicable |
| WSS | download | Mac | 0, 0 | 0, 0 | 2.01, 0.25 | 45191, 39589 | not applicable |
| WSS | download | Linux | 1119, 0 | 58, 0 | 9096.49, 348.51 | 562652, 549719 | not applicable |

Public-path ping delivery was 288/288.
All transfers retained authenticated connection IDs and positive receiver delivery.
CPU includes daemon user and system time divided by receiver-delivered Gbit.
CPU excludes iperf, monitoring, and kernel networking work outside daemon accounting.
RSS includes shared pages and excludes kernel socket memory. Sampled ranges do not establish peak memory.
Inner retransmissions do not measure outer transport loss. Remote network and socket snapshots remain in the raw records.
Two short repetitions and 12 probes per trial limit confidence, especially for p95.
QUIC resource rows include the marked sampling gap. This gap limits comparison of Mac CPU cost and memory ranges.
Ping probes cover the first half of each transfer, as in the reused bench2 method.
End-of-transfer byte ratios are accounting measurements, not packet-loss measurements.

Observed Mac mean sampling intervals were 309.5–376.9 ms, excluding the flagged pause.
Linux mean sampling intervals were 250.6–251.0 ms.
Receiver/sender byte ratios ranged from 0.970810–1.000000.

### Clean Colima throughput guard

The clean guard reused the bench2 topology, authentication, release profile, and native TAP method.
Each transport used forward traffic, one stream, and two interleaved A/B repetitions.
Each transfer excluded ten warmup seconds and measured twenty seconds.
Overlay MTU was 1340. Docker bridge MTU was 1500. Inner TCP used BBR.
No Rust compilation ran during the clean guard.
Clean CPU cost divides sampled CPU seconds by sampled duration, then divides that rate by receiver Gbit/s.
The clean guard configured private secure admission. It retained connection logs, but did not save peer authentication snapshots.
The requested guard permits no more than 3% median throughput loss.

| Transport | A Gbit/s | B Gbit/s | Change | 3% guard | A CPU s/Gbit | B CPU s/Gbit |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| QUIC | 6.317 [6.290–6.344] | 6.228 [6.176–6.280] | -1.41% | pass | 0.335 [0.332–0.338] | 0.336 [0.334–0.337] |
| H2 | 8.418 [8.361–8.474] | 7.876 [7.874–7.879] | -6.43% | fail | 0.264 [0.263–0.264] | 0.282 [0.282–0.283] |
| WSS | 7.688 [7.649–7.727] | 7.670 [7.608–7.733] | -0.23% | pass | 0.289 [0.289–0.290] | 0.293 [0.292–0.295] |

Guard resource and reliability records retain both repetitions. RSS gives endpoint A / B ranges in MiB.

| Transport | Binary | RSS A / B MiB | Loaded p50 / p95 ms | Inner retransmissions | Outer retransmissions or QUIC loss |
| --- | --- | ---: | ---: | ---: | ---: |
| QUIC | A | 25.8–26.3 / 26.4–27.4 | 0.37 [0.35–0.39] / 0.83 [0.82–0.83] | 0, 0 | 0.0000%, 0.0000% |
| QUIC | B | 25.5–27.1 / 27.0–28.6 | 0.56 [0.51–0.60] / 1.08 [0.99–1.18] | 2589, 2282 | 0.0000%, 0.0000% |
| H2 | A | 23.4–26.6 / 25.5–27.2 | 0.97 [0.90–1.05] / 1.84 [1.82–1.87] | 955, 159 | 715, 1055 |
| H2 | B | 23.2–25.8 / 25.0–26.4 | 0.80 [0.80–0.81] / 1.51 [1.45–1.58] | 86, 0 | 0, 6 |
| WSS | A | 23.6–26.5 / 22.7–22.9 | 1.14 [1.10–1.18] / 2.74 [2.68–2.80] | 3790, 1404 | 713, 648 |
| WSS | B | 23.2–26.2 / 22.8–23.2 | 1.24 [1.21–1.27] / 2.39 [2.37–2.40] | 3149, 1882 | 14, 35 |

Colima ping delivery was 1774/1774.
H2/WSS outer counts cover both endpoint sockets, including warmup.
QUIC outer loss estimates use measured-window path-counter differences from both hosts.
Expired unsent packets and inner retransmissions measure separate events.
This two-repetition guard does not establish the broader default-on performance gate.

### Build identity and evidence

The retained A Colima binary matched the bench2 SHA256.
The missing A Mac and remote Linux binaries were rebuilt from a detached `f3c62ece` worktree.
The rebuilt hashes differ from the removed bench2 binaries. This comparison uses verified source revisions and the hashes below.
All builds used Rust 1.95.0, release, fat LTO, one codegen unit, no default features, and feature `tun`.
Mac used aarch64-apple-darwin. Remote Linux used x86_64-unknown-linux-musl with cargo-zigbuild.
Colima used aarch64-unknown-linux-gnu in the existing builder image.

| Binary | SHA256 |
| --- | --- |
| baseline-mac | `46ce5db2e8a6402d98c1bacaf805a4574f5bc5449ae7a244e71cd22cccf199c0` |
| baseline-mac-cli | `862aa208a53441fca9b35227f5e9b1a27c9f553e647eee3e77b033e00e1209b0` |
| baseline-remote-linux | `5cccb3956e3ccc078f2d88fbb1789adac0ff2bcb2b4bf02a6fa48d917cf0cabf` |
| baseline-remote-linux-cli | `4325cc7d6251a51f89c74064d4b6dab6be78382bcd5c5d6d4f7806de9409eb46` |
| main-mac | `e69e1438840ed6908b16d28958c70bf8d62c87979f4da5750114d5372e02fc1d` |
| main-mac-cli | `edba66e74a61913d79f02ac1c51718283735bdfcc2abf06908fa63e948a9cb6e` |
| main-remote-linux | `2402c2a45e642b6ffc2e9633344089cb2b5ec463aab0f22f68de69906c4d5330` |
| main-remote-linux-cli | `3635ce1f84a00d9f08f3a9e7a370eddf551c408fe0b8e2e7e93bdbe0b375fdf5` |
| baseline-linux | `bf19b3b658bca9caf3d0b9f25fb938cb960cd1c6875d7b2d016a634e2a5e3f6b` |
| main-linux | `b6a28d7c6ac827af51c5f50c20dbc73904ef4cb5b47a36c3e453ff8ffbef6a4d` |

### Verification, recovery, and cleanup

The macOS and aarch64 Linux all-target compilation checks passed. Locked Cargo metadata also passed.
The Darwin CPU meter matched an independent process CPU measurement.
All 12 clean transfers passed delivery, topology, sampling, and connection-count validation.
All 24 public transfers passed delivery, sender-duration, authentication, and MTU checks.
The flagged QUIC Mac resource record retains its explicit sampling exception.
No Rust source changed. Rust format checks and module tests were not applicable.
Caddy routing, unauthorized probes, multi-stream traffic, and symmetric public outer-loss measurements were outside this brief.

The first B Mac build failed because its private release cache retained stale A quinn-proto artifacts.
Cleaning quinn-proto, quinn, and lowertier artifacts restored the B release build.
A duplicate Colima build was cancelled with exit 137 after the completed artifact was preserved.
Its output had overwritten the successful build log. The complete successful output was recovered from the command audit.
The paused sudo supervisor was resumed after its benchmark child completed. The campaign then returned exit zero.
An intermediate progress parser read an incomplete JSON file. Completed-group parsing replaced that progress check.
Discovery errors and the unsupported compiler-version query remain recorded with their recovery actions.

Temporary real-path processes, remote binaries, configurations, tokens, interfaces, and routes were removed.
Colima benchmark containers and their network were removed.
The detached worktree and task-owned cloned build caches were removed. Only the main worktree remains.
Resident PIDs and binary hashes matched before and after. Resident authentication and ping delivery passed after cleanup.
Mac hashes cover the installed executable file. Linux hashes cover each running `/proc/PID/exe` executable.
No resident binary, configuration, keys, ACLs, or routes were replaced.
Benchmark binaries and original measurement evidence remain available.

Raw logs, scripts, samples, counters, and validation records: `benchmark-results/lean-core-latency-20261014/`.
Command audit: `benchmark-results/.work/lean-core-20261014-bench3.jsonl`.
