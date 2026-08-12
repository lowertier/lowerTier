# Asymmetric Speed-First Routing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add measured directional goodput routing so each traffic direction can choose its fastest path without reordering active flows.

**Architecture:** Each direct connection measures local egress delivery with bounded authenticated probe trains. The peer center distributes fresh directed measurements. A widest-path route table selects the best bottleneck goodput, while existing flow caches pin routes and connections.

**Tech Stack:** Rust, Tokio, Prost protobuf, Petgraph, DashMap, Clap, Criterion-free deterministic tests, iperf3 live validation.

---

## File structure

- Create `lowertier/src/peers/speed_probe.rs`. Own probe payloads, samples, budgets, receiver state, and deterministic calculations.
- Modify `lowertier/src/proto/common.proto`. Add route and probe configuration plus capability advertisement.
- Modify `lowertier/src/proto/peer_rpc.proto`. Add directed speed fields to peer-center reports.
- Modify `lowertier/src/proto/api_instance.proto`. Add speed route and connection diagnostics.
- Modify `lowertier/src/tunnel/packet_def.rs`. Add packet types and the speed-first wire flag.
- Modify `lowertier/src/common/config.rs`. Add defaults and validation.
- Modify `lowertier/src/common/global_ctx.rs`. Add route-policy helpers and derived feature support.
- Modify `lowertier/src/core.rs` and `lowertier/src/launcher.rs`. Expose CLI and launcher configuration.
- Modify `lowertier/src/peers/peer_conn.rs`. Run and receive direct speed probes.
- Modify `lowertier/src/peers/peer.rs`. Expose probe candidates and select direct connections by policy.
- Modify `lowertier/src/peers/peer_manager.rs`. Own one node-wide probe scheduler and budget.
- Modify `lowertier/src/peers/flow.rs`. Generalize bounded path pins for connection identifiers.
- Modify `lowertier/src/peers/peer_map.rs`. Add the speed policy cache namespace and route fallback.
- Modify `lowertier/src/peers/route_trait.rs`. Add `MaxGoodput` and directed route-quality types.
- Modify `lowertier/src/peers/peer_ospf_route.rs`. Build and expose the widest-path route table.
- Modify `lowertier/src/peers/peer_manager.rs`. Mark eligible data and select the new policy.
- Modify `lowertier/src/peer_center/mod.rs`, `instance.rs`, and `server.rs`. Report and age directed samples.
- Modify `lowertier/src/lowertier-cli.rs`. Show speed route and sample diagnostics.
- Modify `README.md`. Document configuration and fallback behavior.
- Create `docs/performance/asymmetric-speed-first-results.md`. Record the representative live matrix.

### Task 1: Configuration and wire schema

**Files:**
- Modify: `lowertier/src/proto/common.proto`
- Modify: `lowertier/src/proto/peer_rpc.proto`
- Modify: `lowertier/src/proto/api_instance.proto`
- Modify: `lowertier/src/common/config.rs`
- Modify: `lowertier/src/common/global_ctx.rs`
- Modify: `lowertier/src/core.rs`
- Modify: `lowertier/src/launcher.rs`

- [ ] **Step 1: Write failing default and validation tests**

Add tests that require these values:

```rust
assert!(!flags.speed_first);
assert_eq!(flags.speed_probe_interval_seconds, 30);
assert_eq!(flags.speed_probe_budget_bps, 0);
```

Add validation tests for `speed_first` with a zero budget and a positive budget with a zero interval.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `cargo test -p lowertier common::config::tests --lib`

Expected: Compilation fails because the new fields do not exist.

- [ ] **Step 3: Add protobuf fields and configuration plumbing**

Add unused protobuf field numbers for:

```text
FlagsInConfig.speed_first
FlagsInConfig.speed_probe_interval_seconds
FlagsInConfig.speed_probe_budget_bps
PeerFeatureFlag.speed_routing
DirectConnectedPeerInfo.tx_delivery_bps
DirectConnectedPeerInfo.tx_loss_ppm
DirectConnectedPeerInfo.speed_sample_age_ms
DirectConnectedPeerInfo.speed_sample_ttl_ms
DirectConnectedPeerInfo.speed_probe_generation
```

Add optional speed fields to route and peer-connection API messages.

Add this validation logic:

```rust
if flags.speed_first && flags.speed_probe_budget_bps == 0 {
    anyhow::bail!("speed_first requires a positive speed_probe_budget_bps");
}
if flags.speed_probe_budget_bps > 0 && flags.speed_probe_interval_seconds == 0 {
    anyhow::bail!("speed probes require a positive speed_probe_interval_seconds");
}
```

Expose all three settings through Clap, launcher conversion, environment parsing, and config round trips.

- [ ] **Step 4: Run focused tests and verify success**

Run: `cargo test -p lowertier common::config::tests launcher::tests --lib`

Expected: All selected tests pass.

- [ ] **Step 5: Commit the schema slice**

```bash
git add lowertier/src/proto lowertier/src/common/config.rs lowertier/src/common/global_ctx.rs lowertier/src/core.rs lowertier/src/launcher.rs
git commit -m "Add speed-first routing configuration"
```

### Task 2: Packet policy and compatibility

**Files:**
- Modify: `lowertier/src/tunnel/packet_def.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`
- Test: unit tests in both files

- [ ] **Step 1: Write failing packet-policy tests**

Require `set_speed_first(true)` to set both `SPEED_FIRST` and `LATENCY_FIRST`.

Require `set_speed_first(false)` to clear only `SPEED_FIRST`.

Test the exact speed-eligible packet allowlist from the specification.

Test that critical Ethernet and all control packets use latency-first routing.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier tunnel::packet_def::tests peers::peer_manager::tests --lib`

Expected: Compilation fails because the speed flag and policy do not exist.

- [ ] **Step 3: Implement the wire flag and policy helpers**

Add `SPEED_FIRST = 0b0010_0000`.

Add `SpeedProbe` and `SpeedProbeAck` after packet type 24.

Implement:

```rust
pub fn is_speed_first(&self) -> bool;
pub fn set_speed_first(&mut self, enabled: bool) -> &mut Self;
pub fn packet_supports_speed_first(packet: &ZCPacket) -> bool;
```

Only mark eligible packets when the local speed policy is enabled.

At every route-policy decode point, check `SPEED_FIRST` before `LATENCY_FIRST`.

Map `SPEED_FIRST` to `NextHopPolicy::MaxGoodput`.

Map packets with only `LATENCY_FIRST` to `NextHopPolicy::LeastCost`.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier tunnel::packet_def::tests peers::peer_manager::tests --lib`

Expected: All selected tests pass.

- [ ] **Step 5: Commit the packet slice**

```bash
git add lowertier/src/tunnel/packet_def.rs lowertier/src/peers/peer_manager.rs
git commit -m "Add speed-first packet policy"
```

### Task 3: Directional probe engine

**Files:**
- Create: `lowertier/src/peers/speed_probe.rs`
- Modify: `lowertier/src/peers/mod.rs`
- Test: `lowertier/src/peers/speed_probe.rs`

- [ ] **Step 1: Write failing deterministic tests**

Test sample goodput, loss, freshness, generation replacement, duplicate suppression, reordered final markers, incomplete expiry, and node budget division.

Test bucket capacity, interval refill, reservation return, and the two-packet minimum.

Test a one-second send deadline and unused-byte return.

Test one-second post-marker completion and two-second incomplete-generation expiry.

Use these core types:

```rust
pub(crate) struct SpeedSample {
    pub delivery_bps: u64,
    pub loss_ppm: u32,
    pub generation: u64,
    pub measured_at: Instant,
    pub ttl: Duration,
}

pub(crate) struct ProbeBudget;
pub(crate) struct ProbeReceiver;
pub(crate) struct ProbeData;
pub(crate) struct ProbeAck;
```

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier peers::speed_probe::tests --lib`

Expected: Compilation fails because the module does not exist.

- [ ] **Step 3: Implement bounded probe state**

Encode probe payloads with fixed-width little-endian fields.

Reject malformed sizes and arithmetic overflow.

Track unique sequence numbers with a bounded bit set.

Calculate delivery rate from first and last data arrival.

Calculate `loss_ppm = missing * 1_000_000 / expected`.

Return unused reserved bytes to the budget.

Build packet trains from the current effective tunnel payload size.

Include the generation, sequence, expected packet count, expected byte count, and final-marker flag in each probe payload.

Send reserved packets until all bytes are sent or the one-second sender deadline expires.

After the final marker arrives, wait for all expected packets or one more second.

Discard a generation two seconds after its first packet when no final marker arrives.

Measure goodput from the first and last unique data-packet arrival times.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier peers::speed_probe::tests --lib`

Expected: All selected tests pass.

- [ ] **Step 5: Commit the probe engine**

```bash
git add lowertier/src/peers/speed_probe.rs lowertier/src/peers/mod.rs
git commit -m "Add bounded directional speed probes"
```

### Task 4: Direct-connection probe integration

**Files:**
- Modify: `lowertier/src/peers/peer_conn.rs`
- Modify: `lowertier/src/peers/peer.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`
- Modify: `lowertier/src/proto/api.rs`
- Test: unit tests in `peer_conn.rs` and `peer.rs`

- [ ] **Step 1: Write failing connection tests**

Test handshake feature advertisement with `speed-routing-v1`.

Test that older peers never receive probes.

Test one probe generation over a ring tunnel.

Test timeout retention and later sample expiry.

Test several peers and connections sharing one deterministic global budget.

Test that recent-data peers receive turns before idle peers without starving idle peers.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier peers::peer_conn::tests peers::peer::tests --lib`

Expected: New tests fail because connection probes are absent.

- [ ] **Step 3: Integrate probing into authenticated direct connections**

Advertise `speed-routing-v1` through `HandshakeRequest.features` and `PeerFeatureFlag.speed_routing`.

Intercept `SpeedProbe` and `SpeedProbeAck` before normal packet forwarding.

Store one atomic or lock-protected `SpeedSample` on each `PeerConn`.

Create one `ProbeBudget` and scheduler in `PeerManager`.

At each configured interval, snapshot the global budget once.

Collect every supported live connection from `PeerMap`.

Sort peers with recent data traffic before idle peers.

Rotate the starting peer after every cycle so idle peers cannot starve.

Divide the snapshot equally across all collected connections.

Skip a share that cannot carry two effective-payload packets.

Reserve each complete share before starting its probe.

Allow only one active probe for each connection.

Send probes through the selected `DirectTunnelSender` only.

Expose fresh sample data in connection diagnostics.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier peers::peer_conn::tests peers::peer::tests proto::api::tests --lib`

Expected: All selected tests pass.

- [ ] **Step 5: Commit connection integration**

```bash
git add lowertier/src/peers/peer_conn.rs lowertier/src/peers/peer.rs lowertier/src/proto/api.rs
git commit -m "Measure direct connection delivery rate"
```

### Task 5: Directed peer-center measurements

**Files:**
- Modify: `lowertier/src/peer_center/mod.rs`
- Modify: `lowertier/src/peer_center/instance.rs`
- Modify: `lowertier/src/peer_center/server.rs`
- Test: unit tests in these files

- [ ] **Step 1: Write failing directed-age tests**

Create different `A -> B` and `B -> A` samples.

Require both values to survive report and retrieval.

Advance deterministic local residence time and require sample expiry at three source intervals.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier peer_center:: --lib`

Expected: New assertions fail because reports contain latency only.

- [ ] **Step 3: Add directed report fields and monotonic age**

Select the live connection that the speed policy would use.

Report its delivery, loss, generation, age, and TTL.

Store server receipt time with each edge entry.

Add server residence time during global-map output.

Record map receipt time at each client and add local residence time during cost lookup.

Never substitute the reverse measurement for an expired forward measurement.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier peer_center:: --lib`

Expected: All peer-center tests pass.

- [ ] **Step 5: Commit peer-center propagation**

```bash
git add lowertier/src/peer_center
git commit -m "Report directed delivery measurements"
```

### Task 6: Widest-path route table

**Files:**
- Modify: `lowertier/src/peers/route_trait.rs`
- Modify: `lowertier/src/peers/peer_ospf_route.rs`
- Test: route tests in `peer_ospf_route.rs`

- [ ] **Step 1: Write failing asymmetric graph tests**

Build a three-node directed graph.

Set `A -> C` direct to 5 Mbit/s and `A -> B -> C` to 20 Mbit/s.

Set `C -> A` direct to 30 Mbit/s and `C -> B -> A` to 10 Mbit/s.

Require `A -> C` through B and `C -> A` directly.

Test latency, hop, and peer identifier tie-breakers.

Test speed-to-latency-to-hop fallback.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier peers::peer_ospf_route::tests --lib`

Expected: Compilation fails because `MaxGoodput` does not exist.

- [ ] **Step 3: Implement widest-path routing**

Add a route quality value:

```rust
pub struct RouteQuality {
    pub delivery_bps: u64,
    pub latency_ms: u64,
    pub hops: usize,
}
```

Order candidates by highest delivery, lowest latency, lowest hops, then lowest next-hop peer identifier.

Build and publish the third table with fresh directed edges only.

Expose fallback through one route lookup method so callers cannot omit it.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier peers::peer_ospf_route::tests --lib`

Expected: All route tests pass.

- [ ] **Step 5: Commit route computation**

```bash
git add lowertier/src/peers/route_trait.rs lowertier/src/peers/peer_ospf_route.rs
git commit -m "Route data by directed bottleneck speed"
```

### Task 7: Flow-pinned route and connection selection

**Files:**
- Modify: `lowertier/src/peers/flow.rs`
- Modify: `lowertier/src/peers/peer_map.rs`
- Modify: `lowertier/src/peers/peer.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`
- Modify: `lowertier/src/peers/relay_peer_map.rs`
- Test: unit tests in all changed peer files

- [ ] **Step 1: Write failing pinning tests**

Test a distinct speed-policy cache namespace.

Test that an active flow retains a live old route after metrics change.

Test immediate invalidation after route failure.

Test the same rules across multiple direct connections.

Test speed-to-latency-to-protocol fallback for unsampled connections.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier peers::flow::tests peers::peer_map::tests peers::peer::tests peers::peer_manager::tests --lib`

Expected: New speed-policy tests fail.

- [ ] **Step 3: Implement policy-aware flow selection**

Add `MaxGoodput` to every exhaustive policy match.

Use a third route-cache namespace bit pattern.

Generalize the bounded cache key so direct connection identifiers can use the same expiry and invalidation rules.

Pass flow identity into direct send selection.

Do not move an active flow while its pinned next hop and connection remain live.

- [ ] **Step 4: Run tests and verify success**

Run the same focused command from Step 2.

Expected: All selected tests pass.

- [ ] **Step 5: Commit policy-aware pinning**

```bash
git add lowertier/src/peers
git commit -m "Pin speed-first flows to live paths"
```

### Task 8: Diagnostics and documentation

**Files:**
- Modify: `lowertier/src/lowertier-cli.rs`
- Modify: `lowertier/src/peers/traffic_metrics.rs`
- Modify: `README.md`
- Test: CLI serialization and row-construction tests

- [ ] **Step 1: Write failing CLI tests**

Require route rows to show speed next hop, delivery rate, latency, and path length.

Require peer rows to show selected delivery rate and sample age.

Require metrics to expose probe bytes, probe packets, failures, sample age, and selected path delivery rate.

- [ ] **Step 2: Run tests and verify failure**

Run: `cargo test -p lowertier --bin lowertier-cli && cargo test -p lowertier peers::traffic_metrics::tests --lib`

Expected: New fields are absent.

- [ ] **Step 3: Implement diagnostic output and documentation**

Add stable table columns and JSON fields.

Add counters for transmitted and received probe bytes and packets.

Add counters for timeout, malformed, unsupported-peer, and budget failures.

Add gauges for selected sample age and selected path delivery rate.

Label metrics with network name and local destination peer identifier.

Document measurement enablement separately from route selection.

Document mixed-version fallback and asymmetric direction behavior.

- [ ] **Step 4: Run tests and verify success**

Run: `cargo test -p lowertier --bin lowertier-cli && cargo test -p lowertier peers::traffic_metrics::tests --lib`

Expected: All CLI tests pass.

- [ ] **Step 5: Commit diagnostics**

```bash
git add lowertier/src/lowertier-cli.rs lowertier/src/peers/traffic_metrics.rs README.md
git commit -m "Document speed-first route diagnostics"
```

### Task 9: Mixed-version and connected-node integration tests

**Files:**
- Modify: `lowertier/src/tests/three_node.rs`
- Modify: `lowertier/src/tests/mod.rs` when test registration requires it

- [ ] **Step 1: Write the failing asymmetric integration test**

Create three ring-connected nodes with directed mock speed samples.

Require the forward flow to use the relay.

Require the reverse flow to use the direct connection.

Change the forward measurements and require an active flow to keep its live pinned path.

Start a new flow and require the new route.

Close the pinned next hop and require immediate failover.

- [ ] **Step 2: Write the failing mixed-version test**

Create one peer without `speed-routing-v1`.

Require no probe traffic to that peer.

Require speed-marked packets to keep `LATENCY_FIRST` set.

Require an old-policy relay model to choose the latency route.

- [ ] **Step 3: Run tests and verify failure**

Run: `cargo test -p lowertier tests::three_node::speed_first --lib`

Expected: New tests fail before the complete feature integration.

- [ ] **Step 4: Complete integration wiring**

Connect policy marking, directed reports, widest-path lookup, flow pins, connection pins, and fallbacks through the real three-node harness.

- [ ] **Step 5: Run tests and verify success**

Run: `cargo test -p lowertier tests::three_node::speed_first --lib`

Expected: All new integration tests pass.

- [ ] **Step 6: Commit integration coverage**

```bash
git add lowertier/src/tests
git commit -m "Test asymmetric speed-first routing"
```

### Task 10: Full local verification

**Files:**
- Modify only files required by failures in this feature.

- [ ] **Step 1: Format the changed Rust code**

Run: `cargo +nightly fmt --all -- --check`

Expected: Exit status 0.

- [ ] **Step 2: Run the LowTier library suite**

Run: `cargo test -p lowertier --lib`

Expected: All tests pass.

- [ ] **Step 3: Run changed binary tests**

Run: `cargo test -p lowertier --bins`

Expected: All tests pass.

- [ ] **Step 4: Run Clippy**

Run: `cargo clippy -p lowertier --all-targets -- -D warnings`

Expected: Exit status 0.

- [ ] **Step 5: Build release binaries**

Run: `cargo build -p lowertier --release --bin lowertier-core --bin lowertier-cli`

Expected: Exit status 0 and both binaries exist.

- [ ] **Step 6: Verify repository state**

Run: `git status --short && git diff --check`

Expected: Only the intended result-document work remains uncommitted.

### Task 11: Controlled deployment and live matrix

**Files:**
- Create: `docs/performance/asymmetric-speed-first-results.md`

- [ ] **Step 1: Recover and verify control-plane stability**

Require ten uninterrupted minutes without repeated peer removal or route-sync timeout events.

Do not run performance tests while the connector reports connected with no peer route.

- [ ] **Step 2: Record baseline state**

Record binary hashes, versions, configurations, peer tables, route tables, CPU, memory, and probe settings.

- [ ] **Step 3: Deploy compatible binaries with measurement only**

Deploy the same tested revision to the hub, Mac, and `.40`.

Set a positive shared probe budget on these three nodes.

Keep `speed_first = false` on all three nodes.

Verify fresh directed measurements without route changes.

- [ ] **Step 4: Enable one direction**

Enable `speed_first` on the Mac only.

Verify that Mac-to-`.40` uses the widest measured path.

Verify that `.40`-to-Mac still uses its previous policy.

- [ ] **Step 5: Enable the reverse direction**

Enable `speed_first` on `.40`.

Verify independent route selection in both directions.

- [ ] **Step 6: Run the representative matrix**

Run at least three samples for each case:

```text
baseline, one TCP stream, forward
baseline, one TCP stream, reverse
baseline, four TCP streams, forward
baseline, four TCP streams, reverse
speed-first, one TCP stream, forward
speed-first, one TCP stream, reverse
speed-first, four TCP streams, forward
speed-first, four TCP streams, reverse
```

Record sender and receiver throughput, unloaded and loaded RTT, retransmissions, loss, CPU, memory, probe traffic, and routes.

- [ ] **Step 7: Apply the retention gate**

Retain the feature configuration only when median delivered throughput improves without route flapping or material control-plane instability.

Restore the original configuration when the gate fails.

- [ ] **Step 8: Commit the evidence**

```bash
git add docs/performance/asymmetric-speed-first-results.md
git commit -m "Record asymmetric speed-first results"
```
