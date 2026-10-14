# Transfer optimization investigation

The investigation found IPv4 and IPv6 TCP segmentation offload faults on Hattori's eth0 path.
It also found a fixed userspace TCP window and a QUIC MTU detection defect.
The new implementation remains under performance validation.
This report does not yet establish faster transfer than Tailscale.

## Conditions

The isolated network uses S6916 as the relay.
Hattori uses eth0, Osku uses a native utun interface, and Yutoms uses the unprivileged userspace stack.
Tests use iperf3 3.17.1 and receiver throughput.
Diagnostic transfers last 20 seconds.
The initial LowTier interface MTU is 1260 bytes.
The installed Tailscale interface MTU is 1280 bytes.
These diagnostic values are not a matched Tailscale comparison.

Remote control uses SSH through Tailscale.
The fixture keeps production VPN processes running.
Raw results and executable test scripts are in `benchmark-results/speed-goal-20260920/`.
The audit log is `benchmark-results/.work/speed-goal-20260920.jsonl`.

## Hattori IPv4 offload fault

A controlled H2 reverse test changed only `tx-tcp-segmentation` on eth0.
The test used one TCP stream.

| Feature state | Receiver Mbit/s |
| --- | ---: |
| Original on | 0.366 |
| Off | 410.918 |
| Restored on | 0.209 |

Endpoint captures show missing TCP sequence ranges after large offloaded sends.
Smaller retransmitted segments advance the receiver's acknowledgements.
Both endpoint captures report zero kernel capture drops.
The evidence identifies the offload path, but does not identify the faulty driver, hypervisor, or downstream component.
The interface uses `virtio_net`.

With that feature disabled, four-stream results were:

| Client | Transport | To Hattori Mbit/s | From Hattori Mbit/s |
| --- | --- | ---: | ---: |
| Osku | H2 | 352.4 | 400.6 |
| Osku | WSS | 416.0 | 414.2 |
| Yutoms | H2 | 99.0 | 115.5 |
| Yutoms | WSS | 93.4 | 122.1 |

These are single diagnostic runs.
The fixture restores the original feature state after each group.
Final cleanup compares all 62 feature values with the original snapshot.

The IPv6 control changed only `tx-tcp6-segmentation`.
Yutoms H2 reverse throughput reached 373.3 Mbit/s with this feature off.
Restoring the feature reduced throughput to 0.210 Mbit/s.
The IPv4 feature remained on during that control.

## QUIC aggregate congestion and MTU detection

The previous controller advertised a 4 GiB congestion window and disabled pacing.
An Osku four-stream test delivered 58.0 Mbit/s toward Hattori and 370.1 Mbit/s in reverse.
The Osku sending leg lost approximately 1.8% of QUIC packets.
The Hattori sending leg lost approximately 5.5% in reverse.
Kernel UDP receive-buffer error counters did not increase.

The candidate uses BBR to estimate each underlay path's delivery rate and RTT.
Local DATAGRAM queue bounds remain separate from congestion control.
The candidate also restores Quinn's default loss thresholds and minimum MTU.

The first paced test delivered 99.5/207.6 Mbit/s.
The reverse regression remains part of the evidence.
Relay MTU fallback to 1200 bytes doubled the number of frame fragments.

The MTU detector ignored equal-size successful packets when updating the latest acknowledged packet number.
Later loss processing could then treat older losses as evidence of a black hole.
The correction accepts newer equal-size delivery as evidence against those older losses.
Successful smaller packets still permit black-hole detection and MTU reduction.
The regression test covers both conditions and reordered acknowledgements.

Corrected MTU detection keeps the observed MTU at 1452 bytes.
BBR still shows variable throughput and remains under investigation.
The next IPv4 diagnostic delivered 72.5/12.6 Mbit/s.
The source-bound IPv6 diagnostic delivered 128.0/273.0 Mbit/s.
These regressions prevent acceptance of BBR as the final throughput solution.

Two additional regression tests reproduced QUIC state defects.
The DATAGRAM wakeup cleared the blocked flag before the external sender consumed its backlog.
An empty control poll could then report an application-limited connection despite queued payloads.
A separate pending flag now preserves the backlog state through that wakeup.

BBR also treated reduced-rate RTT probe traffic as an unrestricted bandwidth sample.
The regression reduced a 100 MB/s estimate to 56.25 MB/s without a path change.
Send snapshots now retain the RTT probe limitation through delayed acknowledgements.
Equal-timestamp snapshots combine their limitation flags.
The tests cover probe exit and an acknowledgement received after that exit.
These fixes passed focused tests.
The next S6916 diagnostic delivered 97.7/161.8 Mbit/s on Osku.
Yutoms upload then stalled and exceeded the 75-second client timeout.
The failed transfer remains in the raw evidence.

The Yutoms log identifies `ENOBUFS` in the macOS connected UDP send path.
That path returned the error to Quinn, which stopped its connection driver.
The ordinary quinn-udp path treats this error as packet loss and continues recovery.
The connected path now uses the same error contract.
It preserves `WouldBlock` and rejects a partial datagram send.
An injected error test verifies these classifications.
It does not inject an operating-system error into a live driver.

BBR now retains an application-limited flight marker until delivery passes its final packet number.
Bandwidth samples use the state recorded when packets were sent.
The estimator also retains actual ACK delay instead of clipping long intervals to the minimum RTT.
The old clipping heuristic could misclassify queueing as scheduler delay and inflate the estimated rate.
Thirteen BBR tests and three fast DATAGRAM tests passed after these corrections.
Network validation remains in progress.

The shared Quinn driver then delivered 264.3/420.2 Mbit/s on Yutoms through JP AWS.
The external sender delivered 244.0/241.5 Mbit/s under the same fixture configuration.
Each diagnostic used four streams for 20 seconds.
On Osku, the shared driver delivered 102.3/514.6 Mbit/s with one stream.
The external sender delivered 27.8/363.1 Mbit/s in that control.
These are single diagnostic comparisons; repeated acceptance tests remain required.

The external sender could retain a sealed batch while the driver sent newer control packets.
Later ACKs could then mark packets lost before the external sender submitted them.
Its immediate ENOBUFS retry also competed with connection timer work.
Source review confirms these possible sequences, but the diagnostic does not isolate their individual performance effects.
The candidate now submits data and control packets through the same Quinn driver.
This removes the external sealed-packet queue, duplicate UDP socket handles, and endpoint send-socket map.
It also removes inconsistent initial-send and retry error handling from LowTier's sender.

## Adaptive userspace TCP storage

The previous userspace stack allocated 128 KiB in each direction for every TCP socket.
At 30 ms RTT, a 128 KiB window permits approximately 35 Mbit/s per flow before other limits.

The candidate starts with the existing 8 KiB default in each direction.
It estimates demand from application bytes accepted or consumed during a measured RTT interval.
The target is two bandwidth-delay products.
Growth occurs geometrically, with at most one doubling per sample interval.
Small and idle connections do not cause growth.
Each buffer has an 8 MiB limit.
One full-duplex socket can therefore retain at most one quarter of the existing 64 MiB process budget.
The process budget also covers its existing governed consumers.

The allocator reserves the complete replacement buffer before allocation.
The old allocation and its permit remain live through copying.
This accounts for replacement peak storage.
Admission failure returns an error instead of allocating outside the budget.
Growth failure retains the existing buffer and its permit.
Buffer storage remains allocated until socket destruction; idle shrink is not implemented.
The memory budget is not an RSS limit.

Ring growth preserves the complete old storage relative to its read position.
This includes out-of-order receive bytes and unacknowledged transmit bytes.
Sequence numbers and reassembly offsets remain unchanged.
Window scaling uses the maximum receive capacity before the SYN exchange.
Peers without window scaling retain the unscaled receive limit.

For final capacity C, geometric growth copies less than 2C old bytes per direction.
Initial payload storage falls from 256 KiB to 16 KiB per TCP socket.
Active sockets can use more memory when throughput requires a larger window.

Adaptive receive storage raised Yutoms H2 reverse throughput from 115.5 to 385.3 Mbit/s in the IPv4 diagnostic.
Upload remained near 100 Mbit/s with four streams.

## Userspace TCP emission batches

The reactor previously called one smoltcp egress pass before waiting again.
Each pass emits at most one TCP segment per socket.
Larger send buffers therefore did not remove the scheduling limit.

The reactor now repeats egress passes until no progress occurs or the existing batch bound is reached.
The device queue retains its existing 100-packet limit.
The queue also retains its allocation while the asynchronous sender drains it.
Interface and socket locks do not cross an asynchronous wait.

For S sockets and batch bound B, one reactor turn performs at most B socket scans, or O(BS) socket visits.
The bound remains independent of the TCP buffer size.
The regression test checks the batch limit and complete payload emission.
The first IPv6 H2 diagnostic delivered 222.2 Mbit/s toward Hattori with one stream.
Reverse throughput reached 366.7 Mbit/s.

With four streams, H2 delivered 285.6/387.8 Mbit/s and WSS delivered 270.5/422.9 Mbit/s.
With a 1280-byte Hattori inner MTU, H2 delivered 323.8/392.1 Mbit/s.
The userspace stack advertises its existing 1284-byte device MTU; the peer's MSS bounds emitted TCP segments.

Further source review found a receive-batch boundary defect.
The tuple condition polled the input stream even when the receive batch was full.
It discarded the next packet if that packet was immediately available.
With a continuous ready stream, the 100-packet batch could discard one packet per 101 arrivals.
The loop now checks capacity before polling.
The regression failed with the old loop and passed after the correction.
All four focused userspace stack tests passed.
The fix adds no packet copy or retained allocation.

## Current Tailscale reference

The first new four-stream reference delivered 270.2/437.0 Mbit/s on Osku and 220.3/358.0 Mbit/s on Yutoms.
Each run lasted 20 seconds and used the same iperf3 binaries.
Both Hattori TCP segmentation features were off for this comparison group.

Tailscale selected JP AWS toward Hattori.
Yutoms reverse traffic also used JP AWS.
Hattori reported S6916 for Osku reverse traffic after each reverse run.
Relay selection is directional and can change during a test.
The first reference lacks JP AWS CPU samples.
Later references sample both candidate relays and record both endpoint states during transfer.
LowTier's S6916 results therefore do not establish a controlled implementation advantage over every Tailscale result.

The second Yutoms Tailscale reference delivered 220.7/369.2 Mbit/s with four streams through JP AWS.
LowTier through JP AWS delivered 227.7/241.4 Mbit/s with H2 and 274.8/212.8 Mbit/s with WSS.
These LowTier results are single 20-second, four-stream transfers with the matched inner MTU.
JP AWS CPU steal stayed near 0.04% during these transfers.
The isolated relay process used approximately 30–33% of one CPU core.
Its sampled RSS ranged from 22.0 to 28.6 MiB across the four transfers.
CPU exhaustion does not explain the reverse throughput gap in this group.

Osku WSS through JP AWS later delivered 306.9/483.6 Mbit/s with four streams.
The one-stream result was 306.0/433.9 Mbit/s.
These results exceed the earlier operational Tailscale reference, but need repeated comparison.
The routes remain directional: the earlier Osku Tailscale reverse reference reported S6916.

A five-second Yutoms sample during WSS reverse transfer showed substantial waits in `kevent` and condition variables.
JP AWS socket samples showed Cubic congestion-window reductions with retransmissions and approximately 1 MiB of unsent data.
Receive-window limitation did not dominate those samples.
This supports an underlay TCP congestion limit in that run, rather than a continuously busy userspace worker.

The result summaries retain all completed transfers, TCP retransmissions, latency, CPU seconds per delivered Gbit, and RSS ranges.
They are `transfer-summary.json` and `transfer-summary.csv` in the raw result directory.
CPU samples run once per second for 24 seconds around each 20-second transfer.
Tailscale samples include the userspace forward helper.
Host CPU counters include unrelated activity and kernel work.
Tailscale production daemons have longer lifetimes and more peers than the isolated LowTier processes.
Their RSS values do not establish equal-lifetime memory savings.

## Verification

- 174 smoltcp TCP tests passed.
- 11 LowTier gateway tests passed.
- 35 LowTier QUIC tests passed.
- 28 Quinn MTU tests passed.
- Three buffer-growth tests passed.
- Three focused userspace gateway tests passed after the batching change.
- Ten BBR tests and five pacing tests passed before the MTU correction.
- Twelve BBR tests and three fast DATAGRAM tests passed after the state corrections.
- Native macOS and both Linux release targets built successfully.

The tests cover ring wrap, out-of-order storage, sequence preservation, negotiated window scaling, admission accounting, and MTU fallback.
Independent review found a listener unwrap that became unsafe under memory admission failure.
The listener now reports that error through its accept-result channel.

## Other diagnostic findings

Yutoms initially rejected a short-lived Admin certificate near a clock-second boundary.
The source checks issuance against integer wall-clock seconds without future tolerance.
The clocks differed by a fraction of a second.
Admission recovered after the retry phase changed.
Certificate validation was not relaxed.

Hattori has an IPv6 default route restricted to its source prefix.
A lookup without that source returns `Network unreachable`.
A lookup with its global eth0 source succeeds through eth0.
The fixture uses source-bound IPv6 because Tailscale reported the same relay over IPv6.

Caddy integration has not been rerun in this investigation.
The previous task recorded that a local Caddy test binary was unavailable.
