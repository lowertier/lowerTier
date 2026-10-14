# QUIC delivery evidence and MTU detection, 2026-09-22

A focused regression reproduced an incorrect MTU reduction in Quinn's black-hole detector.
The detector ignored a newer successful packet when an older successful packet was larger.
The native osku–UTMOWRT measurements also showed repeated MTU reductions.
The unit failure establishes the code defect. It does not establish the cause of every measured reduction.

## Evidence and acceptance criteria

QUIC processes newly acknowledged packets before detecting packet loss for the same ACK frame.
The previous detector retained one packet number and one maximum acknowledged size.
An early 1420-byte delivery therefore hid later 1326-byte deliveries.
Four separate 1326-byte losses could then trigger a reduction to 1200 bytes.
The regression gives every loss a later successful packet of the same size.
It failed before the production change.

The detector must preserve both size and transmission order from an actual delivered packet.
A newer packet of sufficient size disproves an older suspicious loss burst.
A delayed ACK for an older packet must not hide a later MTU reduction.
A smaller successful packet must not disprove a larger-packet black hole.
Probe delivery uses the same ordering rule.
The loss threshold, MTU limits, congestion controller, and recovery interval stay unchanged.

## Implementation and cost model

The detector stores a contiguous list of non-dominated acknowledged packets.
Packet numbers increase through the list; packet sizes decrease.
A later packet replaces older packets of equal or smaller size.
The first retained packet sent after a loss burst has the largest qualifying size.
Binary search locates that packet.

Let `k` be the number of retained size levels.
Search costs `O(log k)` comparisons.
An insertion can move `O(k)` entries and requires no per-entry allocation.
Repeated delivery of one size retains one entry.
Each entry contains a packet number and a size.
The memory model uses 16 bytes per entry, including 64-bit alignment.
For payload sizes from 1200 through 1500, at most 301 live entries require 4816 bytes, excluding vector capacity.
The current 1452-byte discovery ceiling reduces that bound to 253 entries, or 4048 bytes.
Larger configured UDP payload limits permit more entries; this bound is not a fixed connection memory allowance.
Vector capacity can exceed the live entry count and remain allocated until the detector resets.

At 300 Mbit/s with 1250-byte inner TCP payloads, the sender handles approximately 30,000 frames per second.
A 1200-byte outer MTU requires two QUIC datagrams for a full inner frame at the fixture's 1280-byte interface MTU.
A sufficiently large outer MTU requires one.
The predicted avoidable work is therefore approximately 30,000 additional datagrams per second in this example.
This model predicts packet-processing cost, not a guaranteed throughput increase.

The v8 reverse TCP trials reported outer MTUs from 1200 through 1420 bytes.
Their sender telemetry showed approximately 1.8–5.0 datagrams per send call.
Forward trials retained 1420 bytes and showed approximately 8.7–12.3 datagrams per call.
The telemetry brackets exceed the 20-second payload windows.
These observations motivate the regression; they do not isolate its network performance effect.

## Verification state

The original failure is saved in
`benchmark-results/zerotier-goal-20260922/mtu-smaller-ack-regression-standalone.json`.
The workspace-level test command first failed because `quinn-proto` is excluded from workspace membership.
The standalone manifest command compiled and ran the regression.

All 41 focused MTU unit and integration tests passed after the change.
Coverage includes the new regression, reordered ACKs, delayed probe ACKs, real MTU reduction, migration, and packet splitting.
The passing receipt is `mtu-frontier-focused-tests.json` in the same result directory.
A v9 release matrix completed eight TCP trials and two UDP trials with the same inner MTU and test tools.
Every TCP sender telemetry bracket retained MTU 1420.
Median reverse throughput increased from 228.5 to 538.9 Mbit/s for one stream and from 321.1 to 527.3 for four streams.
Both UDP trials reported zero loss.
These observations agree with the predicted reduction in fragmentation work.
The original v8 trials varied substantially.
A v8 control matrix run after v9 again reduced the MTU in every reverse trial.
Its median reverse throughput was 313.9 Mbit/s for one stream and 271.9 Mbit/s for four streams.
Both campaigns passed direct-path checks and used the same hosts, tools, and inner MTU.
This control strengthens the performance evidence while retaining uncertainty from network timing variation.
Complete throughput, CPU, memory, and path limits appear in [native transport measurements](zerotier-native-20260922.md).
The saved v8 benchmark binaries do not contain this change.

## Queued datagram boundary

A separate regression reproduced loss of a valid queued datagram after an MTU reduction.
`Datagrams::max_size()` returns an inclusive payload limit, but queue pruning previously retained only smaller payloads.
The correction retains payloads equal to that limit and removes only larger payloads.
The regression checks the retained order and total queued bytes.

The regression failed before the correction.
All 42 MTU tests and 12 datagram tests passed in an isolated source copy.
After application, all 12 production datagram tests passed.
The production file matches the tested copy's SHA-256.
Receipts use the `datagram-limit-` prefix in the same result directory.

This correction affects Quinn's queued unreliable datagrams.
It does not affect payloads held by the separate fast-send path.
No performance gain is established for this correction.
The v9 measurement binaries contain the MTU detector change but exclude this later boundary correction.

## Reference

[RFC 8899, section 4.3](https://www.rfc-editor.org/rfc/rfc8899.html#section-4.3)
permits packet-size-specific loss evidence for black-hole detection.
The change preserves size reduction when that evidence remains valid.
