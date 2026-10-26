# Userspace TCP stream measurements, 2026-10-26

Authenticated HTTP/3 CONNECT streams reduce the per-byte work of direct userspace TCP proxy transfers. Eligible SOCKS5 and HTTP connections now carry bytes over the existing authenticated QUIC connection, bypassing smoltcp packet construction, parsing, NAT, checksums, and per-packet fabric dispatch. The retained TCP packet path also drains ready packets into bounded batches and updates NAT checksums incrementally.

## Scope and validation

The initial stream scope is a locally initiated direct QUIC connection to a userspace peer's own IPv4 service address, with ACLs disabled. Both endpoints check admission. The source address must belong to the authenticated peer; destination and protected-port checks run before opening the local service socket. The feature capability is included in the Noise-bound admission context. Older peers, unsupported destinations, ACL-controlled traffic, relay paths, H2, and WSS retain the packet path.

Each endpoint permits 32 streams and reserves 64 KiB per stream for the adapter/copy buffers; QUIC has its existing connection/flow-control limits. Existing TLS exporter binding, ordinary HTTP/3 website handling, and CONNECT-IP remain in place. Application byte counters are exposed as `tcp_stream_proxy_{open,tx_bytes,rx_bytes}`; existing packet-path peer byte counters do not include stream payloads.

All 455 library tests passed, with zero ignored tests, including both Caddy integration tests. Five Python probe tests passed. The package format check passed; the workspace-wide format check reports pre-existing differences in clean vendored Quinn and tokio-websockets sources, which were retained. A final unprivileged local smoke passed SOCKS5 TCP/UDP, HTTP CONNECT, HTTP forwarding, and overlay name resolution with no interface changes. Mixed-version QUIC fallback and H2/WSS passed WAN upload/download byte-count and SHA-256 checks.

## Matched comparison before the TCP_NODELAY follow-up

Both isolated endpoints used the same candidate revision, compiler/settings, protocol, path, and configurations. Stream selection alone was disabled/enabled. The order was packet, stream, stream, packet, packet, stream, with alternating direction order. Each direction/mode has three 256 MiB repetitions. Values below include every completed repetition, including the slow controls.

| Direction | Packet Mbps median (range) | Stream Mbps median (range) | Packet CPU s/Gbit, Mac + JP | Stream CPU s/Gbit, Mac + JP | Combined daemon CPU reduction |
|---|---:|---:|---:|---:|---:|
| Upload | 119.5 (48.1–265.1) | 296.0 (257.9–304.6) | 2.61 + 2.31 | 1.80 + 1.46 | 33.7% |
| Download | 202.4 (66.6–299.3) | 392.0 (389.1–400.8) | 2.21 + 1.40 | 2.04 + 0.60 | 27.1% |

CPU is sampled process user + system time, interpolated over the application transfer interval and normalized by receiver-verified payload Gbit. The table averages CPU work across equal-sized repetitions. It excludes the fixture, curl, verifier, other processes, interrupt work, and kernel memory; those processes/host observations are saved separately. These are not whole-host or WireGuard efficiency measurements. Different historical native-Mac results are not a matched control.

Peak sampled core RSS across the short repetitions was Mac/JP 46.9/41.4 MiB versus 36.2/30.8 MiB for upload, and 51.7/39.7 MiB versus 36.1/32.7 MiB for download. Sampling was approximately 100 ms on Linux and 106 ms on macOS; exact gaps, Linux VmHWM, swap, faults, and Mac physical footprint are retained per trial.

The same build completed verified 5,000,000,000-byte transfers in each direction and mode:

| Mode | Upload Mbps / seconds | Download Mbps / seconds | Peak RSS Mac/JP, upload | Peak RSS Mac/JP, download |
|---|---:|---:|---:|---:|
| Packet | 58.6 / 682.0 | 203.9 / 196.1 | 46.9 / 40.8 MiB | 56.3 / 32.8 MiB |
| Stream | 307.8 / 129.9 | 388.2 / 103.0 | 36.6 / 28.2 MiB | 37.0 / 23.5 MiB |

The 682-second upload finished before the user requested the new time caps. It is retained as observed evidence; it would exceed the new budget. The single long transfers are integrity/resource observations, not repeated performance medians.

## Final build under the 200 Mbps time budget

The follow-up enables TCP_NODELAY on the accepted local proxy socket. Both modes use that same final binary pair. Every new bulk transfer is capped at `bytes * 8 / 200,000,000` seconds: 10.737 seconds for 256 MiB, 40 seconds for 1 GB, and 200 seconds for 5 GB. Curl has the transfer deadline and a five-second connection timeout; its SSH wrapper has an eight-second collection allowance. Setup, control calls, and cleanup have separate short limits. A capped transfer is a failure, retains its partial output and resource evidence, and does not prevent independent trials from running. A 30-second recovery observation follows successful long transfers only.

| Direction | Final packet 256 MiB outcomes | Final stream 256 MiB outcomes | Final stream Mbps median (range) |
|---|---|---|---:|
| Upload | 1/3 completed, 2 capped; completed run 247.1 Mbps | 3/3 verified | 302.4 (285.4–340.4) |
| Download | 1/3 completed, 2 capped; completed run 220.4 Mbps | 3/3 verified | 359.2 (348.4–383.9) |

Five packet trials hit their budgets: four short transfers and the 1 GB upload. These are not excluded successful repetitions. A three-run packet throughput/CPU median cannot be inferred for this capped follow-up. Final stream CPU averaged Mac/JP 1.60/1.41 s/Gbit for upload and 1.84/0.61 for download. Final short stream RSS peaks were 36.5/31.9 MiB and 36.4/32.4 MiB.

The final build verified 1 GB at 298.2 Mbps upload (26.83 s) and 384.7 Mbps download (20.80 s). Core RSS peaks were 36.3/28.2 MiB and 36.7/33.8 MiB. The packet 1 GB download completed at 235.2 Mbps; its upload was capped at 40 seconds. Thirty-second recovery samples show warm retained memory; they do not establish that all RSS returns to its cold value or prove an unlimited-duration leak bound.

## Latency and loss

Concurrent tiny HTTP response probes were collected throughout the transfers. In the first matched comparison, upload median/p95 latency was packet 16.0/68.6 ms and stream 41.9/62.0 ms; download was packet 28.3/49.8 ms and stream 32.3/37.8 ms. Final short stream median/p95 was 47.3/57.5 ms for upload and 26.1/38.0 ms for download. TCP_NODELAY did not establish an upload latency improvement. Higher upload median latency remains a tradeoff; throughput gains are not a claim of lower latency for every request.

One-second QUIC path samples enclose every completed and capped performance trial. The underlay MTU was 1452 bytes in these windows. Initial bulk-sender reported lost/sent packet fractions ranged from 0.032–0.731% for packet upload, 0.005–0.115% for packet download, 0–0.034% for stream upload, and 0.076–0.606% for stream download. Final stream download windows reported 0.684–4.777% lost QUIC packets while every requested payload still passed full byte-count/SHA verification. These are QUIC loss inferences over sampled connection windows, including possible reordering, not final application loss or a controlled equal-loss experiment. Exact retransmitted byte counts and inner TCP retransmission counts were not exposed. All completed transfers delivered the full requested payload; capped transfers remain failures.

## Artifacts and baseline handling

Complete commands, PIDs, timestamps, stdout/stderr, failures, recovery, manifests, per-process samples, peer authentication/route snapshots, network observations, and loss windows are retained locally under `benchmark-results/.work/userspace-stream-20261026/`. Entry points are `comparison.json`, `quic-loss-summary.json`, `audit.jsonl`, `candidate/{mac,linux}/manifest.json`, `followup-driver.log`, and `final-smoke-results.json`. The pre-NODELAY binaries are preserved in `candidate-before-nodelay/` for the first comparison. Later source changes are benchmark helpers/documentation; the compiled Rust patch is retained and verified against both manifests.

The fastest verified choice for this isolated userspace QUIC scenario is the enabled stream path. Candidate artifacts were staged and exercised on yutoms and JP AWS. Existing resident service binaries, configurations, identities, ACLs, routes, and keys remain preserved; their mixed/native scenarios were not benchmarked as equivalent replacements. Temporary benchmark daemons and samplers are stopped after collection. No performance claim is made for H2/WSS, relays, ACL-enabled stream traffic, or other service-address scopes.
