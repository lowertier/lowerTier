# Passthrough rate limits and anti-amplification validation — 2026-10-13

## Scope

Implemented process-wide plus per-source-IP decoy limits, shared by TCP/UDP and
both directions. Defaults and threat-model limits are documented in
[decoy passthrough](../decoy-passthrough.md). This does not add wildcard upstream
resolution, change authenticated transport bindings, or claim browser-traffic
indistinguishability.

Working tree started at `60753501` with unrelated README, QUIC liveness, tracker,
and userspace changes already present. Those were preserved and remain outside
this scoped change. Tests ran against the working tree, including those
pre-existing changes; exact source and test-binary hashes are recorded in
`benchmark-results/.work/passthrough-final-review.log`.

## Functional verification

- **177 transport tests passed**, zero failures, zero ignored in the final run.
  This includes the two explicitly enabled real Caddy-L4 integration tests:
  shared website port, dual backends, H2/H3/WSS bindings, and ordinary probes.
- The two existing public-domain live tests were deliberately excluded. Every
  network destination used by this validation was explicit loopback; the example
  name `challenges.cloudflare.com` was SNI only.
- New coverage includes shared global/IP bursts; reconnect/parallel-flow behavior;
  packet and flow admission caps; cancellation; TCP byte preservation, half-close
  and bidirectional idle tracking; bounded QUIC Initial parsing; QUIC-bit
  greasing; wrong/short/client-chosen CIDs; fresh Initials on reused tuples;
  byte/packet anti-amplification; and queued probes not consuming or deleting
  local VPN routes.
- A real HTTP/3 origin with a certificate larger than 3,000 bytes and a 512 KiB
  response completed three consecutive downloads in the final suite. Every
  byte matched. The rate-ceiling assertions and delivery assertions were kept.
- `cargo check --locked --offline -p lowertier --bins` passed.
- `git diff --check` and scoped rustfmt checks passed.
- The separate **CI source-test-annotation budget remains failing**: 576 / 500.
  Investigation found 559 pre-existing annotations plus 17 new invariant tests.
  No assertions/tests were removed and the budget was not raised to manufacture
  a passing gate. Reconciling that existing suite-wide overage is outside this
  scoped transport change. Evidence: `passthrough-test-budget.log` and
  `passthrough-test-budget-diagnosis.log` under `benchmark-results/.work/`.

Final suite: 45.25 seconds after compilation. Command, PID, timestamps, exit
status, and complete output:

- `benchmark-results/.work/passthrough-implementation-audit.jsonl`
- `benchmark-results/.work/passthrough-final-transport.log`
- `benchmark-results/.work/passthrough-binary-check.log`

## Local resource/delivery sample

This is a **debug-build correctness and shaping sample**, not a matched VPN
throughput benchmark or a baseline-promotion claim. Platform: local macOS
27.0.1, arm64; Rust `1.100.0-nightly (f7575a9da 2026-09-24)`. The test process
contains the client, origin, and decoy relay together. No separate Caddy process
was involved in this resource sample.

One invocation, three consecutive 512 KiB downloads, 12.37 seconds process wall
time. Each trial starts a new connection; the per-IP bucket deliberately
survives between trials. Rates include handshake time and protocol effects.

| Trial | Application delivery | Elapsed ms | Handshake ms | Effective Mbit/s | Final client RTT µs | Server QUIC lost/sent packets | Client/server UDP MTU |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 0 | 524,288 / 524,288 | 3,789 | 4 | 1.107 | 151,186 | 4 / 389 | 1452 / 1452 |
| 1 | 524,288 / 524,288 | 4,301 | 31 | 0.975 | 104,164 | 3 / 398 | 1200 / 1452 |
| 2 | 524,288 / 524,288 | 4,242 | 53 | 0.989 | 65,954 | 3 / 390 | 1326 / 1452 |

The initial burst explains why the first effective rate can exceed the steady
128 KiB/s ceiling. Application delivery was 100%; UDP loss was **not zero**.
QUIC recovered losses under shaping. Lost/sent counts are Quinn path statistics,
not a packet-capture retransmission count. RTT is a final connection estimate,
not a latency percentile. Adaptive MTUs differ, so these numbers must not be
presented as matched-MTU performance comparisons.

`/usr/bin/time -l` reported 0.49 user + 0.18 system CPU seconds. Delivered payload
was 1,572,864 bytes = 0.012582912 Gbit, giving approximately **53.25 CPU-seconds
per delivered Gbit** for the combined debug test process. This excludes unrelated
host/kernel work outside the process and is not comparable to a standalone
release VPN or WireGuard measurement.

Maximum RSS was **39,682,048 bytes (37.84 MiB)** over the complete invocation.
Sampling was the OS high-water statistic from `time -l`, not periodic RSS
sampling; no RSS min/max time series was collected. Its separately reported
10,043,992-byte peak memory footprint is not substituted for RSS.

Complete raw output: `benchmark-results/.work/passthrough-resource-sample.log`.
Test binary SHA256:
`ad7e9202866429e7e9f726382c90c55f83db19adbbd0e8055e85324be21bed2d`.

## Failures and recovery

All failed runs were retained, not counted as successful samples:

1. Initial Rust 1.95 build encountered an unrelated macOS C header-search error:
   `cannot open file '/usr/local/include/stddef.h': Permission denied`.
   Recovered using explicit existing clang/SDK include directories and the
   repository's selected nightly toolchain. No permissions or security policies
   were changed. See `passthrough-unit.log`, `passthrough-compiler-diagnosis.log`,
   `passthrough-compiler-recovery.log`, and `passthrough-unit-recovery.log` under
   `benchmark-results/.work/`.
2. The first large-certificate fixture was below the asserted 3,000-byte minimum.
   Increased the fixture's SAN list; did not lower the assertion. The original
   failure remains in `passthrough-udp-integration.log`.
3. Repeated large-certificate handshakes exposed intermittent missing return-path
   evidence. Traces identified a parser that incorrectly required QUIC's optional
   fixed bit to be set. Updated it to accept RFC 9287 greasing and added a
   deterministic regression. The one-for-one anti-amplification limit was not
   relaxed. Failed runs are `passthrough-udp-integration-recovery.log` and
   `passthrough-udp-trace.log`; the recovered scoped run is
   `passthrough-fixed-bit-recovery.log`.
4. Repository discovery encountered obsolete/nonexistent paths; scoped searches
   recovered. One exact-text edit was rejected because formatting no longer
   matched; rereading the file and applying the correct text recovered without
   partial edits. These inspection/edit errors did not change test outcomes.

## Baselines and deployment

The implementation was initially held in the working tree because the
repository-wide CI annotation gate was failing. The user subsequently authorized
merging this scoped change into `main` and running a local demo despite that
known overage. The CI budget and all assertions remain unchanged.

No resident instance or remote host was replaced, restarted, or reconfigured.
Existing resident baselines remain untouched. No release/WAN performance gate
or matched baseline comparison was performed, so the debug validation binary is
not promoted to a resident baseline. This report makes no claim of validated
remote deployment or faster authenticated VPN throughput.
