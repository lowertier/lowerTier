# Security and Data Plane Efficiency Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development or superpowers:executing-plans. Use checkbox steps for tracking.

**Goal:** Bind authorization to authenticated identity and remove structural packet-path work.

**Architecture:** Trusted transport metadata carries the immediate peer identity. Forwarding uses immutable data-plane snapshots and owned batches.

**Tech Stack:** Rust, Tokio, Quinn, Criterion, protobuf RPC, and EasyTier packet batches.

---

### Task 1: Authenticated RPC identity

**Files:**

- Modify: `lowertier/src/proto/rpc_impl/server.rs`
- Modify: `lowertier/src/proto/rpc_types/controller.rs`
- Modify: `lowertier/src/peers/peer_ospf_route.rs`

- [ ] Write a failing test for a mismatched route synchronization peer ID.
- [ ] Run the focused test and verify the expected failure.
- [ ] Add authenticated peer metadata to the RPC controller.
- [ ] Reject mismatched and unknown peer identities.
- [ ] Run focused and route tests.

### Task 2: Authenticated packet origin

**Files:**

- Modify: `lowertier/src/peers/peer_conn.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`
- Modify: `lowertier/src/peers/link_envelope.rs`

- [ ] Write failing tests for direct source spoofing and verified relay traffic.
- [ ] Run the focused tests and verify the expected failures.
- [ ] Carry authenticated next-hop identity with received packets.
- [ ] Enforce logical-origin rules before authorization and local delivery.
- [ ] Run peer security tests.

### Task 3: QUIC recovery and listener safety

**Files:**

- Modify: `lowertier/src/tunnel/quic.rs`

- [ ] Write failing tests for clean EOF recovery and activation timeout.
- [ ] Write a failing test for reliable replay deduplication.
- [ ] Treat unexpected EOF as a recoverable lane error.
- [ ] bound activation time and accept connections concurrently.
- [ ] Add reliable sequence identifiers and receive deduplication.
- [ ] Include socket ownership in endpoint keys.
- [ ] Run all QUIC tests.

### Task 4: Reusable slab ownership

**Files:**

- Modify: `lowertier/src/tunnel/packet_def.rs`
- Modify: `lowertier/src/instance/linux_tun.rs`

- [ ] Write a failing test that detects slab replacement after conversion.
- [ ] Run the focused test and verify the expected failure.
- [ ] Keep the complete slab owner and store an active range.
- [ ] Return the original allocation after transport bytes drop.
- [ ] Run packet and Linux TUN tests.

### Task 5: Hybrid batch preservation

**Files:**

- Modify: `lowertier/src/peers/peer_ospf_route.rs`
- Modify: `lowertier/src/peers/peer_map.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`

- [ ] Write failing mixed-capability batch tests.
- [ ] Add a lightweight immutable forwarding snapshot.
- [ ] Classify each packet once per batch.
- [ ] Preserve compact and Ethernet peer batches.
- [ ] Run hybrid and route tests.

### Task 6: Neighbor validation

**Files:**

- Modify: `lowertier/src/instance/l2_tun.rs`
- Modify: `lowertier/src/instance/virtual_nic.rs`

- [ ] Write failing tests for invalid ARP and normal IPv6 traffic.
- [ ] Parse and validate neighbor requests before route lookup.
- [ ] Reuse parsed targets when building replies.
- [ ] Run L2 and virtual NIC tests.

### Task 7: Measurement and integration

**Files:**

- Modify: `lowertier/benches/tx_throughput.rs`
- Modify: `docs/performance/hybrid-routing-results.md`

- [ ] Add counters for route snapshots, copies, allocations, queue sends, and socket calls.
- [ ] Run the representative correctness matrix.
- [ ] Run the throughput and memory matrix.
- [ ] Compare results with the current baseline.
- [ ] Retain only changes with general evidence.
- [ ] Run formatting, lint, and workspace tests.
