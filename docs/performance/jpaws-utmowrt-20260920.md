# JP AWS and UTM OpenWrt comparison

Measured on 2026-09-20 JST (2026-09-19 UTC).

Later measurements after workload reduction are in the [JP AWS retest](jpaws-retest-20260920.md).
The separate [s6916 comparison](s6916-utmowrt-20260920.md) includes the matched iperf receiver investigation and TAP MAC correction.
The results below preserve the original experiment and its conditions.

The current-source LowTier candidate exceeded Tailscale median throughput with one TCP stream.
With four streams, LowTier upload remained 9.9% lower. General parity and 10 Gbit/s capability are not established.
No production dataplane change was retained from this investigation.

## TCP results

Upload means UTM OpenWrt to JP AWS. Download means JP AWS to UTM OpenWrt.
Rates use receiver bytes and receiver duration. Each range includes every completed trial in the stated series.

| Workload | Direction | Tailscale median, Mbit/s | LowTier median, Mbit/s | Tailscale range | LowTier range |
|---|---|---:|---:|---:|---:|
| One stream, 3 trials, 60 seconds requested | Upload | 2.628 | 4.108 | 2.625–4.869 | 3.346–6.143 |
| One stream, 3 trials, 60 seconds requested | Download | 10.608 | 16.253 | 9.161–12.041 | 15.606–17.371 |
| Four streams, 2 trials, 30 seconds requested | Upload | 4.242 | 3.820 | 3.606–4.877 | 3.407–4.233 |
| Four streams, 2 trials, 30 seconds requested | Download | 13.159 | 13.421 | 12.267–14.050 | 12.687–14.155 |

The one-stream LowTier medians were 56.3% higher on upload and 53.2% higher on download.
The four-stream download median was 2.0% higher. The small sample does not establish a stable difference.

One-stream endpoint duration differences stayed below 1%.
Four-stream upload timing differed materially: one Tailscale trial reported 30.003 sender seconds and 43.036 receiver seconds.
The table retains the actual receiver rate. The four-stream series is not an exact matched-duration comparison.

TCP retransmission totals across each series were:

| Workload | Direction | Tailscale | LowTier |
|---|---|---:|---:|
| One stream | Upload | 13 | 2 |
| One stream | Download | 1613 | 34 |
| Four streams | Upload | 12 | 4 |
| Four streams | Download | 729 | 1068 |

These are sender TCP retransmissions. They are not outer QUIC retransmission counts or direct packet-loss measurements.

## UDP delivery and latency

UDP used two 15-second trials per path and direction, with 1200-byte datagrams.
The offered rates were 3 Mbit/s upload and 10 Mbit/s download.

| Direction | Tailscale receiver range, Mbit/s | LowTier receiver range, Mbit/s | Tailscale reported loss, trial 1 / 2 | LowTier reported loss, trial 1 / 2 |
|---|---:|---:|---:|---:|
| Upload | 2.912–2.957 | 2.924–2.966 | 0.856% / 2.313% | 0% / 1.413% |
| Download | 8.409–10.027 | 9.860–9.934 | 14.851% / 0% | 0% / 0.619% |

Rates come from iperf `end.sum_received`. Loss uses receiver lost/expected packet counts.
Upload receiver counts come from `server_output_text`; download receiver counts come from `end.sum_received`.
Combined JSON incorrectly reports zero upload loss and uses different denominators for download loss percentages.
Per-stream loss percentages also remain zero in some records with lost packets.
For example, LowTier upload trial 2 reports 66 lost packets out of 4672 in the server text, despite zero loss in JSON.
The resulting 4606 delivered datagrams exactly match 5527200 receiver bytes.
All eight corrected receiver counts reconcile with receiver bytes and the 1200-byte datagram size.
Original conflicting JSON fields remain in the evidence. Different endpoint report windows still limit whole-transfer delivery claims.
TCP sender/receiver byte ratios were not treated as delivery rates.

Each one-stream benchmark window included 14 ICMP probes at five-second intervals.
All 84 probes per path returned. This sample cannot establish negligible loss.

| Direction | Tailscale median of trial mean RTT, ms | LowTier median of trial mean RTT, ms | Tailscale maximum RTT, ms | LowTier maximum RTT, ms |
|---|---:|---:|---:|---:|
| Upload | 234.612 | 159.285 | 3781.142 | 804.924 |
| Download | 1036.898 | 287.538 | 12891.601 | 1117.474 |

## Conditions and resource limits

JP AWS metadata identifies the instance as `t3.nano`. The guest exposes two Xeon 8259CL vCPUs and 421788 KiB of RAM.
UTM OpenWrt exposes six aarch64 CPUs. The user reports 10 Gbit/s links at both endpoints.
These tests do not independently validate that physical capacity.

JP AWS reported 92.82–93.86% CPU steal during the one-stream series.
The four-stream range was 92.91–94.28%.
This leaves roughly 0.11–0.14 CPU equivalents across two vCPUs before other guest work.
The cause of CPU deprivation was not established. Instance type alone does not prove credit exhaustion.

A later check identified the attached IAM role as `AmazonLightsailInstanceRole`.
This indicates a Lightsail-managed instance. Fresh one-second samples showed 92–96% steal.
AWS documents increased steal time when Lightsail exhausts its CPU burst capacity.
The 512 MiB, two-vCPU Lightsail plan has a 5% baseline.
These facts support burst-capacity exhaustion as a likely cause, but do not prove the current balance.
The instance role denied read access to EC2 credit settings and CloudWatch credit metrics.
No IAM policy, instance plan, or credit mode was changed.
The relevant Lightsail console metrics are `BurstCapacityPercentage` and `BurstCapacityTime`.
See [AWS steal-time guidance](https://repost.aws/knowledge-center/lightsail-high-cpu-steal-time),
[baseline capacity](https://docs.aws.amazon.com/lightsail/latest/userguide/baseline-cpu-performance.html),
and [burst metrics](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-instance-health-metrics-in-amazon-lightsail.html).

At 10 Gbit/s and 1200 payload bytes per packet, the forwarding path must handle about 1.04 million packets per second.
The observed CPU availability would provide approximately 110–140 ns per logical packet for all guest work.
Batching can reduce per-packet overhead, but these conditions do not support a useful 10 Gbit/s validation.

CPU and memory were sampled every five seconds. One-stream monitor windows lasted approximately 65 seconds.
The following JP AWS CPU values include setup and idle time around the 60-second transfers.
Host CPU includes kernel work, both overlay services, iperf, monitoring, and other processes.

| Direction | Tailscale process CPU seconds / delivered Gbit | LowTier process CPU seconds / delivered Gbit | Host CPU with Tailscale, seconds / delivered Gbit | Host CPU with LowTier, seconds / delivered Gbit |
|---|---:|---:|---:|---:|
| Upload | 6.44 | 4.10 | 50.15 | 32.00 |
| Download | 3.41 | 2.33 | 13.04 | 9.10 |

Values are medians of per-trial ratios. Delivered Gbit means receiver bytes multiplied by eight and divided by 1e9.
Process CPU includes user and system time. Host CPU excludes idle, I/O wait, and steal.
Both hosts report `AT_CLKTCK=100` in saved auxiliary-vector evidence.

UTM OpenWrt counters do not reconcile in some trials: monitored process CPU exceeds total active host CPU.
The parser indices and PID sets were independently checked. No duplicate process samples were found.
Read timing cannot explain or exclude the discrepancy from the available evidence.
Therefore, this report makes no combined-endpoint CPU-efficiency claim.
One four-stream receiver interval also exceeded its CPU monitor window.

During the one-stream series, JP AWS candidate RSS ranged from 9104 to 16604 KiB; process swap ranged from 6112 to 8908 KiB.
Tailscale RSS ranged from 37128 to 71376 KiB; process swap ranged from 13592 to 47652 KiB.
These are sampled process ranges, not total allocation, peak live data, or kernel memory.
Process ages differed. Restarts prevent attributing these memory differences to a code change.

## Source analysis and profiling

The inspected path uses QUIC DATAGRAM payloads, bounded packet batches, vector UDP I/O, and reusable sealed-packet buffers.
Negotiated QUIC exporter protection avoids redundant inner payload encryption.
The receive path gives each logical UDP datagram independent storage to avoid retaining large GRO allocations.
Changing that ownership requires preserving mutable packet access and bounded retained memory.

The current allocator forces immediate purge. High minor-fault counts suggested a possible allocation cost.
A separate Linux perf counter probe measured all five candidate threads without changing allocator settings.
The 45.045-second profile contained one four-stream upload and reported 470 `madvise` calls, 4701 minor faults, and 38 major faults.
The transfer delivered 4.143 Mbit/s over 30.881 receiver seconds.
A 10.082-second idle profile reported one `madvise` call, 21 minor faults, and no major faults.
These counts do not measure syscall duration or establish a dominant allocator cost.
Minor faults were not converted into claimed memory traffic.
No allocator cache increase, threshold adjustment, or speculative dataplane patch was applied.

## Reproduction and comparison scope

The candidate uses source commit `1547eb18f340a7067ef24b85daf9b40a321abbad`, default release features, and two runtime worker threads.
Both target binaries were built locally with `cargo zigbuild --locked --release -p lowertier --bin lowertier-core` and the appropriate target.

| Target | SHA-256 |
|---|---|
| `x86_64-unknown-linux-musl` | `26cb122718629c15ec7af6ab5c8411de1b86e2a001e9549eb3551c700a125b8a` |
| `aarch64-unknown-linux-musl` | `ed5ff36c18307612597fe545c465dee63cf1646bb485db7babfa4c82c1bc3de6` |

The ARM version string includes a dirty-worktree marker from a test-only fixture correction.
The production source is identical across builds.

JP AWS ran kernel 5.14.0-687.36.1, iperf 3.9, and Tailscale 1.102.2.
UTM OpenWrt ran kernel 6.6.110, iperf 3.17.1, and Tailscale 1.94.1.
Endpoint software versions therefore differ. Each path used the same endpoints and iperf versions.

Candidate instances used isolated addresses `10.127.126.50` and `10.127.126.100`, interface `lt-speed`, and QUIC IPv6 port 14292.
The configured MTU was 1280; the resulting LowTier interface MTU was 1260 after encryption allowance.
Tailscale MTU was 1280. Both TCP paths used MSS 1200.
Secure mode and private mode remained enabled. Test credentials were separate from production credentials.

Tailscale initially selected an address routed through the production LowTier interface.
Temporary firewall rules prevented this nesting and forced the tested Tailscale peer onto its public IPv6 endpoint.
Candidate-series path snapshots before and after each TCP trial showed direct public IPv6.
Snapshots cannot exclude a path change within a trial. Tests ran sequentially, always Tailscale before LowTier within each trial.

The UTM client command was:

```text
iperf3 -c DESTINATION -B SOURCE -p 5209 -M 1200 -P STREAMS \
  -t SECONDS -O 0 --connect-timeout 10000 -J --get-server-output
```

Download adds `-R`. Tailscale uses `100.87.183.91` and `100.123.70.87`.
The candidate uses the isolated addresses above. Destination servers bind only their respective test addresses.

Earlier series remain in the artifact directory for audit:

- `baseline`: Tailscale nested through LowTier; excluded from independent comparisons.
- `independent`: mixed outer address families and delayed omit timers; excluded from the final table.
- `long-baseline`: old deployed LowTier, mixed outer address families, and different process state; not a matched source baseline.

No old-versus-new causal speedup is claimed.

## Validation and final state

The launcher round-trip test used an invalid cipher name. Its fixture now uses the valid, nondefault `aes-256-gcm` value.
The production cipher validator remains unchanged.
The library suite passed with **385 passed, 0 failed, and 2 ignored** when run serially.
The default parallel run exposed interference from a test that consumes all global handshake receipt slots.
The two ignored Caddy integration tests require an unavailable Caddy L4 executable.
They were not run, so this work does not validate live Caddy backend routing or unauthorized-probe behavior.
Both Linux target builds and candidate configuration checks passed.

The initial production upgrade attempt rejected retired configuration flags.
The original JP AWS executable was restored, and its configuration remained unchanged.
Tailscale also restarted during setup; its exit cause remains unresolved.
An initial candidate launch under `/tmp` failed SELinux execution checks.
The isolated candidate then ran from the normal application directory with restored file labels; SELinux stayed enforcing.
Candidate setup logs contain authentication and connection errors before the measured series.
The last such client error preceded the first candidate-series trial.

Both production LowTier services remain on their original executables.
Temporary candidate processes, three iperf servers, test firewall tables, staged executables, and private test configurations were removed.
The original `overlay_isolation` firewall tables remain.
JP AWS executable and configuration hashes match their pre-upgrade values.
The original LowTier path answered all three final health probes.
The original JP AWS backup remains at `/opt/lowertier/lowertier-core.before-20260920`.

Further acceptance work needs available endpoint CPU capacity, a representative workload matrix, and consistent CPU accounting.
The four-stream upload gap remains open.

Raw measurements, exact commands, redacted configurations, build logs, and cleanup evidence are in
[`benchmark-results/jpaws-utmowrt-opt-20260920`](../../benchmark-results/jpaws-utmowrt-opt-20260920/).
[`analysis.json`](../../benchmark-results/jpaws-utmowrt-opt-20260920/analysis.json) contains endpoint durations, CPU counters, and UDP receiver fields.
Failure and recovery records are in
[`benchmark-results/.work/jpaws-utmowrt-opt-20260920-audit.jsonl`](../../benchmark-results/.work/jpaws-utmowrt-opt-20260920-audit.jsonl).
