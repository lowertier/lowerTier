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

## Main integration and local demo follow-up

The scoped implementation was committed on local `main` as
`85dec0102424de8c6a57f086894e33f6ed8f6a24`. Only the passthrough hunks of
`README.md` and `quic.rs` were staged; unrelated tracker, userspace, and QUIC
liveness work remained in the original working tree. No remote push was made.

A clean detached worktree at that commit reused the existing toolchain/build
cache. **176 transport tests passed**, including both explicitly enabled Caddy
integrations, in 22.90 seconds after compilation. The count is one below the
original working-tree run because the unrelated, uncommitted QUIC liveness test
was deliberately not merged. No assertion was removed or weakened.

A runnable demo was added at `lowertier/examples/passthrough_demo.rs`. It was
built against that clean committed library, with source SHA256
`4b32daa2d3571b97ca63710ac9e793ec09c1cf3c1cd1dbc2f04c30fad44abd8a`.
It uses a real LowTier TCP listener, a loopback H2/TLS origin, an in-memory test
certificate with client verification enabled, and three consecutive 512 KiB
responses. The H3 demo was the committed loopback integration fixture, including
the oversized-certificate and UDP guard cases. No external destination, TUN,
privileged networking, or system trust-store changes were used.

### H2/TLS demo

| Trial | Delivered bytes | TLS ms | First 32 KiB ms | Total ms | Effective Mbit/s | Average KiB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 524,288 / 524,288 | 3 | 6 | 3,536 | 1.186 | 144.79 |
| 1 | 524,288 / 524,288 | 8 | 383 | 4,031 | 1.040 | 127.00 |
| 2 | 524,288 / 524,288 | 7 | 382 | 4,027 | 1.041 | 127.11 |

All responses were HTTP 200 and every payload byte matched. The first transfer
consumed the initial burst; new TCP connections did not reset the IP bucket.
Whole-transfer averages, including TLS setup, are reported. A pilot run printed
a short last-half interval as `steady_KiB_s`; that label was misleading because
a token bucket also permits bursts within an interval. The final demo reports
whole-transfer `average_KiB_s` instead. The pilot log was retained, and its payload
and rate-bound assertions passed; it is not used as a steady-rate measurement.
TCP kernel retransmission counts and TCP RTT were not sampled. TLS setup time
must not be presented as TCP RTT. No custom TCP/loopback MTU was configured.

### H3 and UDP protection demo

| Trial | Delivered bytes | Handshake ms | Total ms | Effective Mbit/s | Final RTT µs | QUIC lost/sent packets | Client/server UDP MTU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 0 | 524,288 / 524,288 | 3 | 3,790 | 1.106 | 154,533 | 4 / 389 | 1452 / 1452 |
| 1 | 524,288 / 524,288 | 25 | 4,277 | 0.981 | 56,902 | 3 / 396 | 1200 / 1452 |
| 2 | 524,288 / 524,288 | 32 | 4,256 | 0.985 | 78,855 | 3 / 394 | 1200 / 1452 |

All payloads matched. These are application-delivery results, not a zero-UDP-loss
claim. RTT is the final Quinn estimate, and adaptive MTUs differ between trials.
The additional UDP cases passed: non-QUIC input did not reach the origin; a
1,200-byte Initial did not permit a 2,400-byte response or duplicate reflected
responses before CID return; a wrong CID did not unlock amplification; and a
new source port did not borrow validation. Pending decoy traffic could neither
exhaust the local-route cache nor erase an existing local route on rejection.

### Resource scope and evidence

Each invocation delivered 1,572,864 application bytes (0.012582912 Gbit) in three
transfers. `/usr/bin/time -l` excluded compilation and covered the combined local
client, origin, and relay process:

| Invocation | Wall seconds | User + system CPU seconds | CPU-seconds / delivered Gbit | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| H2 demo | 12.10 | 0.14 + 0.07 | 16.69 | 16,908,288 bytes (16.125 MiB) |
| H3 + two UDP guard cases | 13.05 | 1.03 + 0.56 | 126.36 | 40,812,544 bytes (38.922 MiB) |

RSS is the OS process high-water statistic, not a periodically sampled range.
The H3 invocation also includes the synthetic 5,000-tuple route-pressure test;
its CPU figure is **not** a pure H3 forwarding measurement and must not be compared
with the H2 figure to rank transports. Both are debug builds, not release/WAN
baselines. No resident binary was replaced.

All logs below are in `benchmark-results/.work/`:

- `passthrough-main-audit.jsonl`: commands, working directories, PIDs, timestamps,
  exit codes, and log references.
- `passthrough-main-clean-transport.log`: complete committed-tree transport run,
  including Caddy and a separate set of three H3 trials.
- `passthrough-main-demo-h2-final.log`: complete final H2 demo and resource output.
- `passthrough-main-demo-h3-udp.log`: complete H3/UDP demo and resource output.
- `passthrough-main-demo-h2.log`: retained H2 pilot, including the superseded
  interval-rate label.
- `passthrough-main-demo-hashes.log`: committed-library, demo-source, and binary
  SHA256 identities.

H2 demo binary SHA256:
`04b7083dbb79daab78557dc49365a676fb699fe80e261ed5eea170731ad983fd`.
Committed-tree test binary SHA256:
`2d3a231338aed9fd0c55a9cc6c7359801eeca68ec1982f1f051a1565c6e21025`.

The initial chained background launch created the worktree but did not start
Cargo. Process state and saved logs were inspected, the existing worktree was
verified rather than recreated, and the test job was relaunched with redirected
output. A formatting-sensitive edit was rejected atomically; rereading the
source and applying the exact text recovered. Both are recorded separately from
the successful demo runs. A subsequent preservation check detected an additional
concurrent QUIC CONNECT-IP admission-timeout hunk. The earlier unrelated hunks
were verified intact; the new concurrent hunk was retained and excluded from
these commits. The pre-existing CI annotation overage remains; the merge did not
raise its threshold or remove tests.
