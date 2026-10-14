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
