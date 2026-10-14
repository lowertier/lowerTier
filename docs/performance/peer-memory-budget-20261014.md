# Process memory budget and QUIC peer capacity, 2026-10-14

The process memory governor now scales its default budget with physical RAM.
The rule is `clamp(physical RAM / 16, 64 MiB, 1 GiB)`.
`[limits] memory_bytes` provides an explicit positive override.
iOS and `macos-ne` builds cap the result at 16 MiB.
The governor covers retained-memory reservations, not all process RSS or kernel socket allocations.

## Connection model

The previous QUIC charge was 4 MiB per connection against a fixed 64 MiB budget.
The process could reserve at most 16 connections before other consumers used credit.
The old payload windows totaled 9 MiB: 3 MiB of DATAGRAM queues and 6 MiB of stream windows.
Quinn allocates these queues from demand, so the limits do not describe idle RSS.
Its public interface does not expose complete allocation ownership for incremental accounting.

The revised fixed charge is 1.25 MiB per connection.
DATAGRAM send and receive limits are 128 KiB and 256 KiB.
Stream send and aggregate receive windows are 128 KiB and 256 KiB.
These payload limits total 768 KiB.
Receive queue metadata and connection state each receive a 256 KiB allowance.
The receive queue bounds tiny and empty frames by count.
Received payloads use exact copies so small slices cannot retain padded UDP packets.
The incoming bidirectional stream limit is 16.
Fragment storage follows the 256 KiB receive ceiling and retains its separate governor permits.
Endpoint scratch, allocator overhead, duplicate stream storage, and runtime state prevent an exact RSS guarantee.

QUIC admission leaves one quarter of the budget available for control packets and shared buffer growth.
Existing connections retain their permits when a smaller override takes effect.
An exhausted admission budget produces a counted warning and refuses the connection.
The theoretical admission counts are 38 at 64 MiB and 614 at 1 GiB, before other reservations.
The 16 MiB Network Extension ceiling permits nine under the same condition.

The first explicit override can replace the machine default.
Later configurations keep the smallest explicit override until process restart.
This rule prevents one instance from increasing another instance's process limit.
Removing an override or increasing the effective limit requires process restart.
Tracker handshake slots initially follow one quarter of the governor limit divided by the connection charge.
The slot count does not decrease after a later budget reduction; current connection reservations still enforce the total budget.
Userspace TCP growth follows one eighth of the current limit per direction, with the existing 8 MiB upper bound.

## Short idle measurement

The fixture ran on macOS ARM64 with 128 GiB of physical RAM.
It used one listener and separate loopback clients in one debug test process with the system allocator.
Both endpoints completed the Noise handshake, including TLS exporter binding and network-secret confirmation.
Each client had a separate identity context.
The fixture retained both endpoints of every connection.
It sampled `ps -o rss= -p PID` after a 300 ms settling interval at each listed peer count.
Admission used 80 ms between connections to respect the existing source rate limit.
Each row is one point sample from one short run.
The results do not measure private heap memory, peak memory, production mimalloc, or loaded throughput.

| Build | Peer pairs | QUIC endpoints | RSS KiB | RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| Previous | 0 | 0 | 26,160 | 25.55 |
| Previous | 1 | 2 | 35,856 | 35.02 |
| Previous | 7 | 14 | 39,664 | 38.73 |
| Revised | 0 | 0 | 26,320 | 25.70 |
| Revised | 1 | 2 | 35,456 | 34.62 |
| Revised | 7 | 14 | 39,456 | 38.53 |
| Revised | 8 | 16 | 39,952 | 39.02 |
| Revised | 32 | 64 | 51,712 | 50.50 |
| Revised | 128 | 256 | 101,616 | 99.23 |

The revised increase from 32 to 128 pairs was 49,904 KiB across 192 endpoints, or 259.9 KiB per endpoint.
The previous increase from 1 to 7 pairs was 3,808 KiB across 12 endpoints, or 317.3 KiB per endpoint.
These measurements support a small idle connection allowance.
The 1.25 MiB charge additionally accounts for bounded payload windows and receive queue metadata.
The initial connection also loads shared TLS, protocol, and runtime state.
Its RSS increase must not be assigned to every subsequent connection.

The original configuration cannot admit 32 or 128 pairs because both endpoints consume the same 64 MiB budget.
An initial attempt reached eight pairs and then stalled during Noise when connection charges used all credit.
Earlier attempts also exposed fixture timing sensitivity when client identity and connector contexts differed.
The final baseline used seven pairs, matching identity contexts, and paced admissions.
The revised fixture authenticated all 128 pairs in 13.44 seconds.
The final baseline fixture completed in 1.60 seconds.
These durations include fixture work and settling. They are not transport performance comparisons.

The temporary fixture used this command before its removal:

```sh
LIMITS_IDLE_PROBE=1 LIMITS_PROBE_COUNT=7 cargo test -p lowertier --lib tunnel::quic::tests::quic_admission_deadline_releases_source_for_another_peer -- --exact --nocapture
LIMITS_IDLE_PROBE=1 cargo test -p lowertier --lib tunnel::quic::tests::quic_admission_deadline_releases_source_for_another_peer -- --exact --nocapture
```

Raw logs are `/private/tmp/limits-baseline-rss-final.log` and `/private/tmp/limits-after-rss-final.log`.
The fixture source remains in `/private/tmp/limits-idle-probe.rs`.
Failure and recovery records are in `benchmark-results/.work/lean-core-20261014-limits.jsonl`.

## Limits

Smaller stream windows can constrain reliable traffic at large RTT.
Smaller DATAGRAM queues can increase packet loss during receive stalls.
Owned DATAGRAM payloads add one allocation and copy per accepted nonempty frame.
The effect on loaded CPU use and throughput remains unmeasured.
There is no matched WAN throughput measurement for these window changes.
The previous WAN resource audits remain historical evidence for their original window sizes.
The current measurement establishes idle admission capacity and approximate RSS growth only.
