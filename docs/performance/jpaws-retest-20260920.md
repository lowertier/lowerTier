# JP AWS retest after workload reduction

Measured on 2026-09-20 UTC and JST.

JP AWS recovered idle CPU capacity after the user reduced its workload.
Five one-second `vmstat` samples showed 0% steal and 97–98% idle CPU before testing.
Steal returned under sustained transfer load.
The initial Tailscale upload reached approximately 740–860 Mbit/s for much of its first 17 seconds, then fell sharply.
Its full receiver average was 469.372 Mbit/s over 30.816 seconds.
Five-second steal samples rose from approximately 0% to 54–59% during that transfer.
The following Tailscale download averaged 29.604 Mbit/s, with 55–76% steal across its sampling intervals.

These observations show that idle CPU availability did not provide sustained benchmark capacity.
Burst-capacity exhaustion remains a plausible explanation, but this retest did not obtain the account-level capacity metrics.
The earlier API permission limits and official references remain in the [initial JP AWS report](jpaws-utmowrt-20260920.md).

## Recovered TCP results

Each path and direction used two sequential trials. Path order alternated between trials.

| Streams | Direction | Tailscale median, Mbit/s | LowTier median, Mbit/s | Tailscale range | LowTier range |
|---|---|---:|---:|---:|---:|
| One | Upload | 19.519 | 41.567 | 18.938–20.101 | 28.844–54.290 |
| One | Download | 24.500 | 39.547 | 8.912–40.087 | 37.958–41.137 |
| Four | Upload | 66.807 | 28.883 | 6.261–127.352 | 22.111–35.655 |
| Four | Download | 24.710 | 30.006 | 23.557–25.864 | 26.877–33.134 |

The one-stream receiver durations ranged from 30.001 to 33.461 seconds.
The slow second Tailscale upload retains its actual receiver duration.
This series is not an exact matched-duration comparison.
JP AWS steal averaged 52.40–69.08% across the individual transfer monitoring windows.
These small samples under changing CPU availability do not establish a causal implementation speedup.
Four-stream receiver durations ranged from 30.001 to 30.479 seconds.
Their JP AWS steal averages ranged from 54.87% to 74.79%.
The four-stream upload median remains lower for LowTier. JP AWS parity is not established.

The first four-stream Tailscale upload also had a short initial burst.
Its first three receiver intervals reported 875 Mbit/s, 1.49 Gbit/s, and 641 Mbit/s.
Later intervals mostly reported tens of Mbit/s, with one zero-delivery interval.
Its full 127.352 Mbit/s average does not represent a stable sustained rate.
All intervals remain in the reported full-transfer results.

One-stream TCP retransmission totals were 133/2358 for Tailscale upload/download and 2924/281 for LowTier.
All 64 ICMP probes returned in this series.
Mean upload RTT per trial ranged from 97.548–3480.280 ms for Tailscale and 63.096–84.502 ms for LowTier.
Mean download RTT ranged from 367.205–734.341 ms and 106.715–168.012 ms, respectively.
The maximum observed Tailscale upload probe RTT was 13765.045 ms.
These are sparse five-second probes, not a complete latency distribution.

Four-stream TCP retransmission totals were 7264/992 for Tailscale upload/download and 10231/1279 for LowTier.
All 64 four-stream ICMP probes also returned.
Mean upload RTT per trial ranged from 232.837–360.518 ms for Tailscale and 67.852–145.331 ms for LowTier.
Mean download RTT ranged from 326.482–348.949 ms and 149.295–227.843 ms, respectively.

## UDP delivery

Each path and direction used two 15-second trials with 1200-byte UDP payloads at an offered rate of 10 Mbit/s.
That rate represents approximately 1042 datagrams per second.
This rate is 35 times lower than the offered rate in the s6916 UDP comparison.
It still exceeds some JP AWS TCP results and does not imply sufficient sustained endpoint capacity.
This is a delivery check at a lower offered rate, not a maximum-throughput test.
Server restarts and alternating path order matched the recovered TCP procedure.

| Direction | Path | Receiver rate range, Mbit/s | Receiver loss range |
|---|---|---:|---:|
| Upload | Tailscale | 5.506–9.736 | 2.254–30.369% |
| Upload | LowTier | 9.316–9.558 | 4.218–5.600% |
| Download | Tailscale | 7.000–9.181 | 6.161–27.580% |
| Download | LowTier | 9.012–9.893 | 0–5.844% |

This table preserves all attempts, including a Tailscale path change.
Tailscale upload trial 2 began with a direct IPv6 snapshot but ended with an empty `CurAddr` and a populated `PeerRelay`.
Its 5.506 Mbit/s rate and 30.369% receiver loss are not a verified direct-path comparison.
That trial reported an 18.938-second receiver window and a 15.000-second sender window.
The timing of the path change within the transfer is unknown.

All eight receiver byte counts reconcile with received datagram counts.
The parser uses receiver lost/expected counts and preserves conflicting aggregate iperf fields.
Endpoint measurement windows differ. Offered rate alone does not determine receiver throughput or the reported loss percentage.
These UDP runs did not include separate host CPU sampling.
Neither path provided consistently loss-free delivery under these conditions.

## CPU and memory evidence

Values below are medians of CPU seconds divided by receiver-delivered Gbit in the one-stream recovery series.
They include setup and idle intervals around each transfer.

| Host | Direction | Tailscale process | LowTier candidate | Host CPU with Tailscale | Host CPU with LowTier |
|---|---|---:|---:|---:|---:|
| JP AWS | Upload | 2.628 | 2.318 | 9.385 | 4.770 |
| JP AWS | Download | 5.060 | 2.473 | 12.395 | 5.304 |
| UTM OpenWrt | Upload | 15.697 | 6.728 | 17.256 | 8.852 |
| UTM OpenWrt | Download | 10.076 | 2.800 | 17.276 | 7.639 |

Some UTM process CPU counters exceed the corresponding host active CPU counters.
The parser preserves and flags that discrepancy. These values do not support a precise CPU-efficiency claim.

| Host | Process | Sampled RSS range, KiB | Sampled swap range, KiB |
|---|---|---:|---:|
| JP AWS | Tailscale | 9584–41660 | 92368–162604 |
| JP AWS | LowTier candidate | 5388–16580 | 5284–13372 |
| UTM OpenWrt | Tailscale | 125252–167580 | 0 |
| UTM OpenWrt | LowTier candidate | 48912–54696 | 0 |

These are process samples from the one-stream series, not peak allocation or total kernel memory.
Process ages and prior workloads differ. The ranges do not establish a causal memory improvement.
JP AWS monitoring windows were 35.000–35.060 seconds; UTM windows were 35.110–35.130 seconds.

## Conditions

The test pair was JP AWS `100.123.70.87` and UTM OpenWrt `100.87.183.91`.
Upload means UTM OpenWrt to JP AWS. Download means JP AWS to UTM OpenWrt.
Both outer paths used public IPv6. Tailscale path snapshots bracketed each transfer.
Temporary firewall rules prevented Tailscale from using the candidate overlay.

Both paths used iperf 3.17.1, TCP MSS 1200, 30-second requests, and no omitted interval.
The temporary server was the same static executable used in the [s6916 comparison](s6916-utmowrt-20260920.md).
Rates use receiver bytes and the receiver's actual duration.
CPU and memory samples came from `/proc` every five seconds over approximately 35 seconds per transfer.
Host CPU includes kernel work, tunnel services, iperf, monitoring, and other processes.

The candidate contains commit `1547eb18f340a7067ef24b85daf9b40a321abbad` plus the TAP MAC correction.
The candidate source and binary hashes match the s6916 comparison.
Two runtime workers, default offload, encryption, secure mode, and private mode remained enabled.
The configured MTU was 1280. LowTier's interface MTU was 1260; Tailscale used 1280.
Candidate addresses were `10.127.126.50` and `10.127.126.100` on isolated interface `lt-speed`.
Production executables and configurations were not replaced.

## Initial failure and recovery

The first LowTier upload failed before it produced a transfer interval.
The client reported `control socket has closed unexpectedly`.
The server reported `idle timeout for receiving data`.
The server and candidate processes remained active, and all three subsequent overlay health pings returned.
The kernel log query returned no entries for that interval.
Candidate logs also contain peer-center RPC rejections for missing authenticated-peer context.
The server source rejects those requests before processing peer reports or map reads.
The direct overlay transfers succeeded. This experiment does not validate peer-center map operation or resolve those RPC errors.

The iperf 3.17.1 server initializes `last_receive_time` before accepting a test.
It can test that timestamp after leaving the initial state, before it records the first received data block.
Long server idle time and delayed test startup can therefore affect this timeout.
The default timeout is 120 seconds. The failed client started approximately 121.6 seconds after server startup.
The recovery series starts a fresh server before every transfer on both paths.
All eight recovered one-stream transfers completed successfully.
It preserves the original failure and uses separate result directories.
This changes the measurement harness, not LowTier's data path or the delivery criteria.

## Scope and remaining limits

The retest preserves the TAP MAC correction and does not add a throughput-specific code change.
The correction passed nine virtual-NIC tests, two Linux parser tests, and live MAC-change checks in the s6916 investigation.
Both Linux release builds passed there, and the same executables passed configuration checks in this retest.
The four-stream JP AWS upload gap remains unresolved under variable CPU availability.
The s6916 matched TCP medians were within 1.85%; neither host pair establishes 10 Gbit/s capacity.
Live Caddy backend routing and unauthorized-probe checks were not repeated for this TAP-only change.
The earlier library run ignored two Caddy tests because the required Caddy L4 executable was unavailable.

All 32 recovered TCP snapshots showed active direct IPv6 to JP AWS.
Thirteen of sixteen UDP snapshots also showed direct IPv6.
Two other empty snapshots occurred during LowTier trials; the third contained the Tailscale relay evidence described above.
Snapshots cannot exclude a path change during a transfer.
All temporary candidates, iperf servers, firewall tables, staged executables, and private test configurations were removed.
JP AWS and UTM production executable and configuration hashes match their pre-test values.
Both production services remained active, and the original LowTier path returned all three final health pings.
The original production firewall tables and retained JP AWS executable backup remain unchanged.

## Evidence

Raw commands, measurements, redacted configurations, and cleanup records are in
[`benchmark-results/jpaws-retest-20260920`](../../benchmark-results/jpaws-retest-20260920/).
The initial idle check is in
[`reduced-workload-preflight.json`](../../benchmark-results/jpaws-utmowrt-opt-20260920/reduced-workload-preflight.json).
Failure records are in
[`benchmark-results/.work/jpaws-retest-20260920-audit.jsonl`](../../benchmark-results/.work/jpaws-retest-20260920-audit.jsonl).
