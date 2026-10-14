# Local queue delay

NIC admission uses a separate CoDel controller for each flow.
The target is 5 ms.
The interval is 100 ms.
Packets from one NIC input batch share one enqueue timestamp.
Dequeue reads the clock once per output batch.
Persistent delay triggers head drops with the inverse square root control law.
The existing packet, flow, and retained-memory limits remain hard limits.

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
Throughput and loaded latency require a matched measurement after integration.

Direct data admission uses the measured sink drain rate times 4 ms.
Its scheduling floor is three 128 KiB charged batches.
One legal batch always fits an empty budget.
The 1 MiB retained-memory ceiling still applies.
Credits remain held until sink flush completes.

QUIC DATAGRAM admission uses the controller pacing rate times 4 ms.
Controllers without a pacing rate use congestion window divided by RTT.
Three 64-datagram batches at the path MTU form the scheduling floor.
The 1 MiB DATAGRAM memory ceiling still applies.
Quinn reports this capacity through `datagram_send_buffer_space()`.
The writer waits for FIFO drain before flush completes.
Congestion windows and reliable stream windows remain unchanged.

At 450 Mbit/s, 4 ms corresponds to 225,000 bytes.
At a 1,500-byte path MTU, the QUIC floor is 288,000 bytes, or 5.12 ms.
The previous QUIC FIFO ceiling was 18.64 ms.
The direct floor is 393,216 charged bytes, or 6.99 ms if all charges represented wire bytes.
Actual payload queue time is lower because charges include allocation capacity and packet metadata.
