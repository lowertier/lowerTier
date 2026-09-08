# H2 / WebSocket TCP lanes implementation tracklist

Updated: 2026-09-08. Scope: one logical peer connection over two or four independent TCP transports. Status: the exact Linux candidate passed the bidirectional 5 Gbit/s throughput gate for H2 and WSS; the complete matched matrix, browser TLS comparison, integration tests and scoped commit review are complete.

## Acceptance criterion

A successful milestone requires receiver goodput of at least 5.0 Gbit/s, reported separately for H2 and WSS and for forward/reverse. Use matched single-lane and kernel WireGuard controls, the same source revision/build flags, 80 ms nominal RTT, 0.1% configured loss, underlay MTU 1500, overlay MTU 1360, four inner BBR TCP flows. Final trials: at least three valid runs per direction, 30 seconds measured after 10 seconds warm-up; report median and range, actual RTT, retransmissions, loaded latency, process RSS and available kernel/VM CPU or memory metrics. A fastest sample alone does not pass. Report observed topology/offload/netem placement and raw substrate capacity. Invalid or interrupted iperf results fail the trial even when the runner exits zero.

The current environment is an uncommitted development tree. Preserve all unrelated changes. Starting hashes and git state: `benchmark-results/.work/tcp-lanes-start-20260907.json`.

## Corrections to previous analysis

* `tcp://` with the `quic` feature calls `http2::connect/accept`; earlier tables labeled "plain TCP" and "H2" do not establish a separate raw-TCP control.
* The previous 2/4-PeerConn trials stalled and lost liveness. Recv-Q accumulation proves the application stopped draining; the three-batch admission capacity alone does not establish the cause. Investigate wakeups, write/read dependencies, session replay handling and admission ownership.
* Increasing a system autotuning ceiling does not establish that an explicitly sized socket adopted the new limit. Record effective socket settings.
* Removing a copy can retain large shared allocations. Account retained capacity and downstream compaction, in addition to payload bytes.

## Proposed invariants and risks

1. One peer/session/pinger and one logical batch interface. Two or four independent TCP/TLS connections, one H2 CONNECT or WebSocket per connection. Existing single-lane behavior remains the default and preserves its wire format.
2. Negotiate the exact lane count/version before sending striped payloads. Pairing identifiers alone provide no authentication. Bind both physical TLS exporters, lane identities and the pairing transcript into the peer authentication context; reject duplicate, mismatched, expired and cross-session joins. Bound pending joins and handshake time. Plain WS needs an equivalent authenticated joining design before enabling it.
3. Both connections must reach the same backend. Load balancers require backend affinity; connections routed to different servers must fail closed within a bounded deadline. No transparent cross-backend session merge.
4. Select lanes using the existing cleartext flow classification before it is lost to encryption/framing. Preserve packet order within each flow, including fragmented IP and Ethernet traffic. Control traffic has a documented lane; no global reorder buffer that recreates cross-flow HOL.
5. Audit all encryption sequence and replay windows. Current `REPLAY_WINDOW_BITS` is 1024. A fast lane can advance more than this while another lane retransmits. Preserve anti-replay guarantees using authenticated lane-specific sequence domains or another proved bounded design; blindly widening the bitmap or disabling replay checks is forbidden.
6. A ready fast lane must be polled even when its sibling is pending. `Sink::poll_ready` has no item argument, so readiness, pending ownership and flush semantics must be explicit. Bound packet count AND retained bytes, preserve partial writes, register wakers, and avoid an unconditional wait for both lane flushes on each batch.
7. Fair receive polling, bounded work per poll, exact ownership on cancellation and no per-lane mpsc/PeerConn duplication. Shared NIC backpressure remains real; multiplexing alone cannot remove a downstream bottleneck. Liveness must distinguish local backpressure from a dead peer without accepting unauthenticated keepalives.
8. Initial implementation fails the logical connection when an established lane fails. Do not silently move live flows across lanes: old data can remain in flight. Reconnect/re-authenticate the whole pair; dynamic lane replacement is deferred.
9. Two lanes may still hash all four test flows onto one lane. Record actual lane byte distribution, exercise balanced and skewed flows, and report single-flow limits separately. Two lanes share link capacity and may consume more congestion-control share; no guaranteed doubling.
10. Maintain authentication, TLS exporter binding, admission/ACL checks, socket mark, address-family and underlay policies. No crypto weakening or protocol impersonation claims.

## Tracklist

- [x] T0 Record existing changes and isolate a commit candidate from HEAD.
  Comment: The candidate retains original tests and excludes unrelated test removals and QUIC development changes. Main-tree changes remain preserved.
- [x] T1 Audit ownership, authentication, replay domains and flow metadata.
  Comment: Direct TLS-protected frames may use multiple lanes; session ciphertext, relay and control traffic remain on the primary lane.
- [x] T2 Implement authenticated two/four-lane admission and composite binding.
  Comment: Exact LTL2 count/index/role binding, bounded joins, no silent downgrade or live-lane replacement.
- [x] T3 Implement bounded, flow-stable send partitioning and fair receive polling.
  Comment: A bounded full-flow map replaces the collision-prone six-bit map. Existing assignments never migrate. Explicit flush remains a barrier.
- [x] T4 Integrate H2 with one logical PeerConn and independent physical TLS connections.
- [x] T5 Integrate WSS and preserve vectored server writes.
  Comment: Plain WS and CDN/proxy-terminated WSS reject multiple lanes. The server no longer loses vectored writes through Either.
- [x] T6 Verify ordering, partial readiness, shutdown, malformed joins and replay preservation.
  Comment: The isolated candidate passes 20 lane tests with zstd, including the reproduced compression-order regression, 16 TCP tests and two compressor tests. The old echo helper now stops on terminal errors; the DNS/IPv6 test uses ephemeral ports.
- [x] T7 Repair benchmark validity checks and record effective topology/resources.
  Comment: Error, timeout, zero-delivery and truncated workloads cannot pass. Effective overlay MTU is 1340 for CLI --mtu 1360; underlay MTU is 1500.
- [x] T8 Complete the exact commit candidate's matched single/four-lane H2/WSS matrix.
  Comment: Completed 24 valid same-binary LowTier trials. H2 one/four-lane medians 2.405/7.124 forward and 2.373/7.105 reverse; WSS 2.846/7.634 forward and 2.826/7.288 reverse. Full samples and resource statistics are in tcp-lanes-milestone.md.
- [x] T9 Verify at least 5 Gbit/s median in both directions for each retained protocol.
  Comment: All twelve four-lane samples passed. H2 medians 7.124/7.105 Gbit/s; WSS 7.634/7.288. Three valid 30-second measurements after 10-second warm-up, four inner BBR flows, 80 ms nominal RTT and configured 0.1% loss. WSS forward loaded tail latency remains a documented limitation; throughput equivalence does not imply latency equivalence.
- [x] T10 Publish the measured approach and tradeoffs after final candidate verification.
  Comment: docs/performance/tcp-lanes-milestone.md contains all thirty comparison trials, source/build identity, CPU/RSS, loaded latency, TLS capture differences and rejected experiments.
- [x] T11 Implement and capture-test the Chromium-family TLS client.
  Comment: BoringSSL 5.2, comparison against official Chrome 152.0.7977.82, fresh randomness, GREASE, extension permutation, hybrid key shares, signature preferences and Brotli. Native trust-anchor hints depend on installed roots; H2 omits unsupported ALPS and signature-algorithm GREASE differs from the Chrome capture. This applies to H2/WSS client TLS and carries no indistinguishability claim for other layers or QUIC.
- [x] T12 Complete the matched kernel WireGuard control.
  Comment: Six valid trials, forward median 4.795 and reverse median 4.852 Gbit/s; raw four-flow control 10.800 Gbit/s. Same VM, actual MTU, BBR, socket ceilings and netem configuration. Compare final candidate resource/latency measurements as well as throughput.
- [x] T13 Review and commit only the independently verified task changes.
  Comment: The independently constructed candidate retains original tests, includes the Linux RouteIdentity prerequisite, and passes Linux release, minimal/WebSocket-only/lean checks and Caddy two-backend tests. This scoped commit includes the report; unrelated pre-existing test removals and QUIC work remain outside it.

## Experiment / decision log

2026-09-08 final verification: all 24 LowTier trials and six kernel WireGuard trials are valid. The release build took 166.63 seconds; SHA256 `28c9b67edcf790e16e6ab3e6df5fb04426a69ce57722245518a02f9cb1597a84`. Both protocols exceed WireGuard median throughput in both directions. Loaded RTT remains higher, especially WSS forward (p95 about 2 seconds). The standalone candidate also passes minimal, WebSocket-only and lean compile checks. Caddy ordinary website sharing, two backends and multi-lane affinity pass. No failed sample was reclassified as a success.

2026-09-08 isolated candidate H2 acceptance: binary SHA256 28c9b67edcf790e16e6ab3e6df5fb04426a69ce57722245518a02f9cb1597a84 completed six valid 30+10-second trials. forward 6.579/7.124/7.308 Gbit/s, median 7.124. reverse 7.105/7.415/6.984 Gbit/s, median 7.105. WSS and same-binary single-lane controls remain in progress. Loaded tail latency is reported separately from throughput and remains above the kernel WireGuard control.

2026-09-08 final candidate review: restored tests exposed a fixed-port race and an echo helper that continued on a terminal H2 stream error; both are corrected without removing tests. The optional zstd regression reproduced a flow moving from lane 1 to lane 0 after compression. The compressor now records the current cleartext full-flow hash before mutating the payload, and the mux uses it for compressed frames. Twenty lane tests, sixteen TCP tests and two compressor tests pass. The zstd C-header build issue was resolved for verification by using the existing system libzstd 1.5.7 through its supported pkg-config path; dependencies and global toolchain settings were unchanged.

2026-09-08 Linux setup regression: the first browser-TLS/full-flow run had no valid workload. Four TLS joins completed, but the manual connector's inherited two-second TCP budget left 400 ms for Noise; the initiator timed out after the responder committed. Multi-lane TCP now receives a bounded ten-second total budget; ordinary TCP remains two seconds and WSS keeps twenty. The regression test checks the URL-specific budget and remaining time. This failed run is retained and excluded from throughput results.


2026-09-08 repeat diagnosis: slow trials had only two or three bulk lanes despite four sockets. WSS reverse lane fractions were 0/47/23/30%, 0/20/62/18%, 0/55/17/28%; H2 reverse trial 2 used only two lanes (62/38%). Replace six-bit shard keys with the existing full cleartext tuple hash, reparsed consistently across cached metadata loss. Pin at most 256 full-flow hashes; never evict a live mapping. After saturation, unseen flows use a deterministic hash mapping without allocations. A regression uses four distinct tuples with the SAME wire shard, verifies four lanes and stable mapping after saturation. No replay or packet wire format changes.


2026-09-08 browser TLS: native BoringSSL client builds and two initial TLS tests pass (exporters match rustls servers; strict native-root verification rejects the unknown test identity). Official Chrome 152.0.7977.82 HTTPS and WSS ClientHello captures are saved locally. Current client matches ordered ciphers, supported groups, key-share types/sizes, ALPN, TLS versions and GREASE presence; ALPS, new signature algorithms, server-padding and trust-anchor extensions are under comparison. First compiler errors were duplicate visibility from an exact-text patch and the method name SslMethod::tls; both corrected. WSS capture initially timed out; a localhost page with explicit content type and dump-dom produced the capture without changing TLS security.


2026-09-07 WSS root cause reproduced: the exact pinned tokio-util Either wrapper reports `is_write_vectored() == false` around a real TCP stream whose own result is true. Diagnostic log: `benchmark-results/.work/tcp-lanes-either-tcp-probe.log`. The first probe used Tokio Sink, which itself lacks vectored support; it was corrected to a real TCP socket before drawing this conclusion. The WSS server used Either while the client used MaybeTlsStream, accounting for an implementation asymmetry. Server handshake handling now retains the concrete TCP/TLS I/O type through a shared generic `accept_stream` function; no dependency upgrade or new wrapper was added. A frame-level regression counts actual multi-buffer writes through this server function. Eighteen lane tests plus five WebSocket tests pass. Linux benchmark verification is pending.

2026-09-07 WSS 64 KiB threshold-only repeats: binary `b35492c1565e8daba4dec91973c378e450458d6978f565f74ff475164dc462eb` produced forward 2.930/2.849 Gbit/s and reverse 6.132/7.086 in valid 30+10-second trials. Loaded forward ping frequently measured 200–360 ms. Increasing the threshold alone did not resolve the direction asymmetry. Keep the threshold fixed while testing the concrete-I/O fix.

2026-09-07 first 5 Gbit/s crossing: the four-lane binary `1b2dee42cc8439a38e7150f2050210d46403e0584010721b5ee9ff9a43bdc4c3` measured H2 7.527/6.939 Gbit/s in a valid 30+10-second trial, with 318872/86778 inner TCP retransmits. WSS measured 2.155/6.890 Gbit/s with 0/1 retransmits, all four physical sockets carrying bytes. These are one trial per direction, so repeated acceptance remains open. Seventeen transport tests passed with every lane carrying payload, including real H2/WSS and full Noise/PeerConn paths.

2026-09-07 WSS experiment: use a 64 KiB flush threshold only for multi-lane WSS, retaining individual WebSocket messages and explicit batch flushes. Bound paired message payloads to 256 KiB before join/authentication; the default single-lane behavior remains unchanged. Eighteen tests pass including rejection of oversized unauthenticated joins followed by successful valid grouping. The unsuccessful TCP_NOTSENT_LOWAT option has been removed; `common.rs` matches its task-start SHA exactly. Resource sampling now records wall-clock timestamps, process stat and VM CPU counters plus continuous loaded ping during the actual throughput workload. It adds no extra pressure-test phase.

2026-09-07 lane-count decision: first-seen shard mapping passed 15 tests and its Linux build succeeded (SHA256 `ff1f6a18b2313940db2bcd6ad01c2b4aaca592131ce2e66b0b1ae7f5da1717f1`). With 30+10-second trials, two-lane H2 measured 4.378/3.761 Gbit/s and WSS 2.621/2.926. Both physical sockets carried bulk traffic. H2 with a 256 KiB unsent threshold fell to 3.420/2.902. The threshold is not selected as a default. Add a four-lane comparison using the SAME logical PeerConn/session/receiver and bounded state; do not increase the number of PeerConns or inner iperf flows. Count/index binding and incomplete four-lane admission regressions are being added before benchmarking. The 5 Gbit/s milestone remains unpassed.

2026-09-07 sparse-flow refinement: static shard mixing still concentrated all four forward flows onto one lane in the 256 KiB unsent-backlog trial (13.54 GB versus 13.8 MB, with the latter including reverse ACK traffic). The writer now keeps a fixed 64-byte shard-to-lane map, alternates first-seen shard assignments and never moves an assigned shard. Control/encrypted traffic does not consume assignments. Fifteen focused tests pass, including sparse shards that collide under the old mapping, unchanged assignment after all shards are seen, and the prior full-pipeline delay test. This balances newly encountered distinct shards; unequal flow sizes and shard collisions remain possible. Linux rebuild is in progress.

2026-09-07 outer-backlog diagnostics: the optional TCP_NOTSENT_LOWAT build passed (SHA256 `0ddc6b1d75fbcdd22e68d42571aa2735fcb12ae36eb1a19a09fdabca7a9b6086`). With static shard mixing and 30+10-second trials, H2 at 256 KiB measured 2.517/3.592 Gbit/s and at 1 MiB measured 2.658/3.005. WSS at 256 KiB measured 1.450/2.647 Gbit/s. All four trial invocations completed successfully; these diagnostics do not meet the milestone and are confounded by sparse-flow distribution. No low-water default is accepted. The next comparisons keep the new fixed-assignment binary identical and vary only the optional unsent threshold.

2026-09-07 longer-window experiment: 128 MiB effective TCP ceilings did not give a stable gain. H2 30+10-second forward trials 2.132/3.491 Gbit/s; reverse 2.724/1.648. The final reverse CPU probe timed out (exit 124); the overall run fails acceptance and the planned WSS trial did not start. A live diagnostic captured 24118 TUN TX drops, TCP out-of-order queue drops and extensive retransmission. These observations do not isolate a single cause. Next experiment adds optional outer-socket-only TCP_NOTSENT_LOWAT; inner iperf settings stay unchanged. No default low-water setting has been selected.

Measurement correction: `--mtu 1360` currently results in `et0` MTU 1340 in this tree. Existing LowTier A/B samples share that actual MTU. The final WireGuard control must use the same observed interface MTU, and reports must distinguish the CLI setting from the effective MTU.

2026-09-07 shard fix: the first two-lane trial put all payload on one socket (7.06 GB versus 20 KB). Actual inner source ports 45348/45360/45366/45370 shared FNV low-bit parity. Lane selection now multiplicatively mixes the existing six-bit shard; it remains stable when the optional full hash is absent. Regression covers even ports and shard fallback. No wire metadata change. The first trial's reverse iperf daemon was absent; it is excluded. Each subsequent workload now starts from a confirmed listening iperf server and captures its log.

2026-09-07 matched smoke: both H2 lanes carried bulk bytes after the shard fix. H2 improved by 1.528 Gbit/s (+60.4%) forward and 0.991 Gbit/s (+42.6%) reverse in this one adjacent pair. Forward inner retransmits were 132778 and inner peak RTT approximately 298–397 ms. Further validation is required; 5 Gbit/s is still unverified.

2026-09-07 validation: 12 focused tests passed (0 failed), including both real transports and a full authenticated PeerConn pipeline. Linux candidate build passed in 184.65 seconds. The documented `easytier-throughput:wan-builder` image was absent; the verified existing `lowertier-linux-builder:local` was used without installing or pulling anything. A benchmark edit initially missed the script's final echo; re-reading the unchanged file and using the exact text fixed the patch.

2026-09-07 implementation: added `tunnel/tcp_lanes.rs`, local tests, connector/listener integration and composite Noise binding. First compile found `PacketBatch::pop_singleton` returns Result; corrected to map_err. Exact command, exit status and logs are in `benchmark-results/.work/tcp-lanes-build.jsonl`. No new throughput claim yet.

2026-09-07: Previous flush-threshold, multi-PeerConn and receive ownership experiments were reverted. Their mixed smoke results are hypotheses/evidence, not an accepted speedup. Begin with transport and replay correctness; do not inherit the previous unproved stall attribution.

## Primary technical references

* HTTP/2 send capacity: https://docs.rs/h2/latest/h2/struct.SendStream.html
* TLS 1.3 exporters: https://www.rfc-editor.org/rfc/rfc8446#section-7.5
* TLS channel binding: https://www.rfc-editor.org/rfc/rfc9266
* Tokio fair semaphore and multi-permit admission: https://docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html
