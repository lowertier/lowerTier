# Local queue delay

NIC admission uses a separate CoDel controller for each flow.
The target is 5 ms.
The interval is 100 ms.
Packets from one NIC input batch share one enqueue timestamp.
Dequeue reads the clock once per output batch.
Persistent delay triggers head drops with the inverse square root control law.
The existing packet, flow, and retained-memory limits remain hard limits.
Active NIC deliveries share a three-batch handoff limit of 384 KiB in retained buffer capacity.
Excess packets remain in the fair flow queues with their original enqueue timestamps.
All 16 flow slots remain available for small independent deliveries.
One legal packet can exceed the handoff limit when the active budget is empty.
The 2 MiB active-memory hard limit still applies.
At 450 Mbit/s, 384 KiB corresponds to at most 6.99 ms of payload service.
The previous full active window allowed 23.3 ms for 1,024 packets with 1,280-byte payloads.
The handoff limit is a byte bound. It does not guarantee a fixed delay at lower rates.

The controller follows [RFC 8289](https://www.rfc-editor.org/rfc/rfc8289).
The statistics names are `nic_aqm_drops`, `nic_queue_sojourn_us`, and `nic_queue_dequeued`.
Divide the sojourn sum by the dequeue count to obtain mean NIC queue residence in microseconds.
The drop count includes hard-limit drops.

At 450 Mbit/s, the service rate is 56,250 bytes/ms.
The previous 2,048-packet NIC queue could contain 46.6 ms of 1,280-byte payloads.
CoDel targets 5 ms of persistent delay after an initial observation interval.
The target is not a maximum packet age.
Transient bursts and unresponsive senders can exceed the target.
Network flight windows, transport authentication, and MTU rules do not change.
The [matched confirmation](lean-core-ab-20261014.md#rate-based-admission-confirmation) passes the clean throughput guards.
Public upload and latency targets remain unmet.

Direct data admission uses the measured sink drain rate times 4 ms.
Its scheduling floor is three 128 KiB charged batches.
One legal batch always fits an empty budget.
The 1 MiB retained-memory ceiling still applies.
Credits remain held until sink flush completes.

QUIC DATAGRAM admission uses the recent peak controller pacing rate times 4 ms.
Controllers without a pacing rate use congestion window divided by RTT.
Ten 100 ms buckets retain peaks for approximately 0.9 to 1 second.
ACK processing records samples. Batch admission also ages the filter after idle periods.
This prevents BBR drain and ProbeRTT from immediately reducing the scheduling budget.
Three 64-datagram batches at the path MTU form the scheduling floor.
The 1 MiB DATAGRAM memory ceiling still applies.
Quinn reports this capacity through `datagram_send_buffer_space()`.
Each admitted DATAGRAM carries its Quinn enqueue timestamp.
The connection observes FIFO head residence on transmission, admission, and its next timeout.
Head residence above 5 ms for a 100 ms interval pauses new packet-group admission.
Admission resumes when the FIFO head falls below 5 ms or the FIFO becomes empty.
The controller preserves all admitted DATAGRAMs and keeps the peak-rate byte cap.
It does not add expiry or change congestion-control pacing.

Each NIC flow holds a weak binding to its current DATAGRAM connection.
One metadata tag per delivery batch establishes that binding before serialization.
Reliable QUIC, H2, and WSS clear the binding when the flow changes transport.
The binding does not retain the connection or payload buffers.
Persistent FIFO delay primes that flow's existing NIC CoDel interval.
NIC CoDel then marks ECN-capable packets or drops unmarked head packets under its existing control law.
The one-maximum-packet exemption remains in effect.
A monotonic congestion count preserves an episode while direct-send credits block the NIC delivery.
Each flow consumes that retained signal independently after delivery resumes.
The dequeue consumes feedback only after packet capacity becomes available.
This prevents FIFO drain from erasing the signal before NIC dequeue.
Queue statistics record summed FIFO residence, dequeued fragments, and persistent episodes.

The writer waits for FIFO drain before flush completes.
Batch admission can fill the rate budget before flush waits for drain.
Congestion windows and reliable stream windows remain unchanged.

At 450 Mbit/s, 4 ms corresponds to 225,000 bytes.
At a 1,500-byte path MTU, the QUIC floor is 288,000 bytes, or 5.12 ms.
The previous QUIC FIFO ceiling was 18.64 ms.
The direct floor is 393,216 charged bytes, or 6.99 ms if all charges represented wire bytes.
Actual payload queue time is lower because charges include allocation capacity and packet metadata.

The tunnel does not configure DATAGRAM packet expiry.
The former 10 ms deadline could discard valid traffic during BBR's approximately 200 ms ProbeRTT period.
This BBR implementation uses a ProbeRTT window of 0.75 times estimated BDP, with a four-MTU minimum.
It sets the ProbeRTT pacing gain to 1.0. It does not always reduce flight to four packets.
The 200 ms minimum duration starts after flight reaches the probe target and requires a subsequent round start before exit.
The earlier B upload records combined local expiry with increased inner TCP retransmissions and low mean NIC residence.
Removing expiry removes that loss source. The confirmation still records inner retransmissions and unmet public performance targets.
NIC CoDel still controls persistent waiting time. Hard memory limits still bound staging and Quinn admission.
Quinn retains its optional complete-group expiry API for other callers.
The `quic_datagrams_expired` statistic remains available and should stay zero without another expiry caller.

At 8 Gbit/s, a 4 ms budget would require 4,000,000 bytes.
The existing 1 MiB QUIC ceiling instead permits approximately 1.05 ms of payload service.
At 450 Mbit/s, the 288,000-byte floor still represents 5.12 ms at a 1,500-byte MTU.
At the normal 1.25 ProbeBw pacing gain, rate times 4 ms is 281,250 bytes at this speed.
The 288,000-byte floor therefore dominates that budget. The confirmation does not isolate the peak filter's performance effect.
The recent peak can increase that budget during controller probe gains, within the same memory ceiling.
Removing expiry preserves queued packets through temporary congestion-controller pauses.
It does not change the congestion window, pacing algorithm, wire format, or network flight capacity.

The feedback adds one timestamp per queued DATAGRAM and two atomic values per connection.
NIC binding adds one weak reference and one observed generation per flow.
One packet metadata field carries the flow reference, with one reference clone per NIC delivery batch.
The controller reads the existing clock once per transmit or admission operation, rather than once per fragment.
It adds no payload queue or payload copy.
Darwin removes one readiness syscall per write and adds at most one kernel sample per 50 ms of active writing.
For `W` writes per second, this removes `W` readiness queries and retains approximately 20 kernel samples per socket.

At a CoDel congestion signal, ECT inner IPv4 and IPv6 packets receive CE before encryption.
IPv4 marking recomputes the header checksum, including options.
IPv6 marking preserves the DSCP bits and flow label.
Native Ethernet marking uses the IP payload after the Ethernet and VLAN headers.
Marking preserves the flow hash.
Non-ECT, malformed, and non-IP packets retain the drop fallback.
Hard-limit overflow always drops.
The `nic_aqm_marks` statistic counts successful congestion marks.
ECN signaling follows [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168).
