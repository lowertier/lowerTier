# Asymmetric Speed-First Routing Design

Date: 2026-08-12

## Goal

LowTier must select data paths independently for each direction between two nodes.

The speed-first policy must prefer delivered goodput over latency and hop count.

The policy must keep packets from one flow on one path while that path remains usable.

The implementation must preserve existing hop-first and latency-first behavior by default.

## Current behavior

Each node already builds its own directed topology graph.

Each source already marks packets with its selected route policy.

The existing flow cache pins a destination and flow to one next hop.

These properties already permit different forward and reverse paths.

The current route metric contains round-trip latency only.

The current implementation does not measure directional delivery capacity.

The least-hop policy always prefers a direct link over a faster relay path.

The latency-first policy cannot identify a higher-capacity path with greater latency.

Connection selection also prefers the configured protocol before measured path quality.

## Non-goals

This change does not change TCP congestion control.

This change does not set a fixed QUIC Brutal rate.

This change does not infer capacity from passive byte counters at low utilization.

This change does not split one flow across multiple paths.

This change does not require symmetric forward and reverse routes.

## Configuration

Add these `FlagsInConfig` fields with new protobuf field numbers:

```toml
[flags]
speed_first = true
speed_probe_interval_seconds = 30
speed_probe_budget_bps = 1000000
```

`speed_first` is false by default.

`speed_first` has priority when `latency_first` is also true.

`speed_probe_interval_seconds` controls the normal refresh interval.

The default interval is 30 seconds.

`speed_probe_budget_bps` limits average probe traffic across the complete node.

The default global budget is zero.

A positive probe budget enables measurement and reporting independently from `speed_first`.

`speed_first` controls local route selection and data-packet policy marking.

A relay can therefore report directional measurements without using speed-first routes for its own traffic.

Configuration validation rejects `speed_first = true` when the probe budget is zero.

Speed-first routing falls back to latency-first routing when no fresh speed sample exists.

Configuration validation rejects a zero interval when the probe budget is positive.

The CLI, launcher, environment parser, FFI, and configuration round trip must expose the new fields.

## Wire compatibility

Add `speed_routing` to `PeerFeatureFlag`.

The new binary advertises `speed_routing` regardless of local route-policy and probe settings.

The feature flag indicates wire-protocol capability only.

Add `SPEED_FIRST` with value `0b0010_0000` to `PeerManagerHeaderFlags`.

The selected bit was previously deprecated and is available for reuse.

`set_speed_first(true)` also sets `LATENCY_FIRST`.

An older relay will therefore use latency-first routing as a safe fallback.

A modern relay checks `SPEED_FIRST` before `LATENCY_FIRST`.

Add `SpeedProbe` and `SpeedProbeAck` packet types after the current assigned packet types.

A node sends speed probes only to a peer that advertises `speed_routing`.

The existing peer header carries the route flag without additional data-packet bytes.

## Directional measurement

Each direct `PeerConn` owns one local egress measurement.

The measurement contains delivered bits per second, loss in parts per million, sample age, and probe generation.

The measurement describes traffic sent by the local node to the connected peer.

The reverse connection stores a separate measurement at the reverse sender.

The sender runs a bounded packet train through the authenticated direct tunnel.

The packet train uses the current effective tunnel payload size.

The node-wide token bucket refills at `speed_probe_budget_bps`.

The bucket capacity equals one configured probe interval of traffic.

The scheduler takes one bucket snapshot at the start of each probe cycle.

The scheduler divides those bytes equally across supported direct connections.

The scheduler skips a connection when its share cannot carry two probe packets.

The sender reserves one complete share before it starts a probe.

The sender does not borrow tokens from a later probe cycle.

The sender transmits the reserved packet train as quickly as the direct tunnel accepts it.

The sender stops after one second even when reserved bytes remain.

Unused reserved bytes return to the global bucket.

The final marker contains the expected packet count and expected byte count.

The receiver does not finish early when reordered probe packets follow the final marker.

The receiver ends the sample when all expected packets arrive.

The receiver also ends the sample one second after it receives the final marker.

The receiver discards an incomplete generation two seconds after its first packet when no final marker arrives.

The goodput duration uses the first and last data-packet arrival times.

The receiver counts unique probe bytes for each generation.

The receiver returns received bytes, received packets, first arrival time, and last arrival time.

The sender calculates delivered goodput from receiver bytes and receiver duration.

The sender calculates loss from sent and received packet counts.

The sender retains the completed probe with the newest generation.

The scheduler gives every supported direct connection a turn.

Connections with recent data traffic receive the earliest available turns.

The scheduler does not start a second probe on the same connection.

The probe records no capacity when fewer than two packets arrive.

A sample expires after three configured probe intervals.

Transport statistics can support diagnostics.

Transport statistics do not replace the receiver-confirmed speed sample.

## Peer-center reporting

Extend `DirectConnectedPeerInfo` with these protobuf fields:

- `tx_delivery_bps`
- `tx_loss_ppm`
- `speed_sample_age_ms`
- `speed_sample_ttl_ms`
- `speed_probe_generation`

The reporting node selects the best fresh egress measurement across its direct connections to one peer.

The selected measurement must identify the connection used by speed-first traffic.

The reporting node sets `speed_sample_ttl_ms` to three times its configured probe interval.

The peer center adds server residence time to the reported sample age.

This rule avoids a dependency on synchronized wall clocks.

Each receiving node records the monotonic time when it receives the global map.

Each route calculation adds local residence time to `speed_sample_age_ms`.

A sample is fresh only when total age is less than `speed_sample_ttl_ms`.

The source node's reported TTL controls freshness for that directed edge.

The global peer map preserves independent `A -> B` and `B -> A` edge measurements.

An absent, zero, or expired delivery rate represents an unknown speed.

## Route selection

Add `NextHopPolicy::MaxGoodput`.

Build a third route table for the new policy.

The speed table uses only directed edges with fresh delivery measurements.

The speed table uses a widest-path algorithm.

The primary path value is the minimum delivered bit rate across all path edges.

The algorithm maximizes that minimum value.

Total directed latency is the first tie-breaker.

Hop count is the second tie-breaker.

Peer identifier order provides the final deterministic tie-breaker.

The selected route stores path delivery rate, total latency, hop count, and next hop.

If no complete speed path exists, the source uses the latency-first table.

If no latency path exists, the source uses the least-hop table.

Relays apply the policy encoded in each packet.

Only these packet types can use speed-first routing:

- `Data`
- `ForeignNetworkPacket`
- `KcpSrc`
- `KcpDst`
- `QuicSrc`
- `QuicDst`
- `DataWithKcpSrcModified`
- `DataWithQuicSrcModified`
- `Ethernet`
- `AlternateFecSource`
- `AlternateFecParity`

An Ethernet packet marked as critical L2 control uses latency-first routing.

Every packet type outside this allowlist uses latency-first routing.

This rule covers handshake, RPC, route, ping, relay-handshake, noise-handshake, and speed-probe traffic.

Direct speed probes bypass topology routing and use their measured direct connection.

## Flow and connection pinning

Use the existing stable flow shard and `FlowPathCache` for next-hop pinning.

Add a distinct cache namespace for `MaxGoodput`.

The cache remains local to each sender and relay.

Forward and reverse directions can therefore select different next hops.

The reverse five-tuple can have the same flow shard without sharing cache state across nodes.

An active flow keeps its selected next hop while packets continue and the next hop remains live.

New flows use the newest speed route.

A failed next hop invalidates all pins that use that next hop.

Generalize the flow cache for connection identifiers.

Each `Peer` uses a connection-flow cache when more than one direct connection is available.

Speed-first traffic selects the connection with the highest fresh delivered rate.

Latency-first traffic selects the sampled connection with the lowest latency.

Least-hop traffic preserves the configured protocol preference.

A speed-first flow without a fresh connection sample uses latency-first connection selection.

The connection selector then uses the configured protocol when no latency sample exists.

The connection selector keeps the current live connection when both measurements are unavailable.

The connection selector uses a deterministic connection identifier order when no current connection exists.

A connection failure invalidates its connection-flow pins immediately.

These rules prevent packet reordering during route or connection metric changes.

## API and diagnostics

Extend the route API with these optional fields:

- `next_hop_peer_id_speed_first`
- `path_delivery_bps_speed_first`
- `path_latency_speed_first`
- `path_len_speed_first`

Extend peer connection diagnostics with the local directional speed sample.

The CLI route table shows the speed-first next hop and path delivery rate.

The CLI peer table shows the selected connection delivery rate and sample age.

Metrics report probe bytes, probe packets, probe failures, sample age, and selected path delivery rate.

Logs must not print credentials or probe payload data.

## Failure handling

Malformed probe packets are dropped without changing the current sample.

Duplicate probe packets do not increase delivered bytes.

Late acknowledgements from an old generation do not replace a newer sample.

A probe timeout keeps the previous sample until that sample expires.

An expired sample removes its edge from the speed graph.

Route computation then performs the defined latency and hop fallbacks.

The route update uses hysteresis through flow pinning instead of a fixed speed threshold.

Existing flows stay on a live path.

New flows can use a better measured path immediately.

## Test plan

Unit tests cover configuration defaults, validation, serialization, and compatibility.

Packet tests cover the new flag and the combined latency fallback bit.

Probe tests use a deterministic clock and a bounded mock tunnel.

Probe tests verify delivery calculation, loss calculation, duplicate handling, budget enforcement, timeout behavior, and sample expiry.

Peer-center tests verify independent forward and reverse measurements.

Route tests use a directed three-node graph.

The forward graph makes the relay path wider than the direct path.

The reverse graph makes the direct path wider than the relay path.

The forward route must use the relay.

The reverse route must use the direct edge.

Route tests also verify tie-breakers and fallback behavior.

Flow tests verify that route changes do not move an active flow.

Flow tests verify immediate movement after a pinned next-hop failure.

Connection tests verify independent policy selection and connection-flow pinning.

Mixed-version tests verify latency fallback when a peer lacks `speed_routing`.

Integration tests use controlled directional rate and loss limits.

Integration tests verify asymmetric route selection without packet reordering.

The final local verification runs formatting, targeted tests, the LowTier crate tests, Clippy, and configuration round-trip tests.

## Live validation

Restore stable route synchronization before the performance comparison.

Record the original route table and connector state.

Run the baseline with current QUIC and least-hop settings.

Run speed-first with the same transport settings.

Test one and four TCP streams in both directions.

Record sender and receiver throughput separately.

Record unloaded RTT, loaded RTT, retransmissions, packet loss, CPU, memory, probe traffic, and selected routes.

Repeat each measurement at least three times.

Keep the feature only when the representative matrix improves delivered throughput without unacceptable probe traffic or instability.

Do not change the probe budget to make only the `.40` fixture pass.

## Deployment

Deploy the new binary to the hub, the Mac node, and `.40` before enabling `speed_first`.

Leave `speed_first` disabled on other nodes until their binaries support the feature.

Set a positive probe budget on the hub and both endpoints before speed-first route selection begins.

The hub can keep `speed_first` disabled while it measures and reports its directed edges.

Enable the feature on one sender first.

Verify the forward route and control-plane stability.

Enable the feature on the reverse sender next.

Verify that each direction can retain a different path.

Rollback requires only disabling `speed_first` and restarting the affected instance.
