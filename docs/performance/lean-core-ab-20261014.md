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
