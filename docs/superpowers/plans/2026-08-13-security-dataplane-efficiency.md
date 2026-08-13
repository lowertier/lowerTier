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
- [x] Add authenticated peer metadata to the RPC controller.
- [x] Bind all RPC fragments to one authenticated session.
- [x] Reject missing, mismatched, and unknown peer identities.
- [x] Bound RPC body, merger, decompression, timeout, and task admission work.
- [ ] Run focused and route tests.

### Task 2: Authenticated packet origin

**Files:**

- Modify: `lowertier/src/peers/peer_conn.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`
- Modify: `lowertier/src/peers/link_envelope.rs`

- [ ] Write failing tests for direct source spoofing and verified relay traffic.
- [ ] Run the focused tests and verify the expected failures.
- [ ] Carry authenticated next-hop identity with received packets.
- [ ] Remove local identity metadata at the final peer egress boundary.
- [ ] Enforce logical-origin rules before authorization and local delivery.
- [ ] Require and verify the relay origin proof envelope.
- [ ] Reject replay, field changes, missing proof, and old protocol versions.
- [ ] Remove the plaintext handshake and legacy packet filter.
- [ ] Test direct, relay, and version-rejection traffic.
- [ ] Run peer security tests.

### Task 3: QUIC recovery and listener safety

**Files:**

- Modify: `lowertier/src/tunnel/quic.rs`

- [x] Test clean FIN half-close, terminal lane reset, and activation timeout.
- [x] Preserve one reliable direction after a clean FIN on the other direction.
- [x] Close the QUIC connection on a non-clean reliable read or write error.
- [x] Keep current framing without stream replacement or frame replay.
- [ ] Write a failing test for future reliable replay deduplication.
- [ ] bound activation time and accept connections concurrently.
- [ ] Assign future reliable recovery framing to a mandatory protocol version.
- [ ] Add epochs, sequence identifiers, acknowledgements, and bounded replay state.
- [ ] Add global and per-peer activation bounds.
- [ ] Include all underlay policy and owner fields in endpoint keys.
- [ ] Run all QUIC tests.

### Task 4: Reusable slab ownership

**Files:**

- Modify: `lowertier/src/tunnel/packet_def.rs`
- Modify: `lowertier/src/instance/linux_tun.rs`

- [ ] Write a failing test that detects slab replacement after conversion.
- [ ] Run the focused test and verify the expected failure.
- [ ] Keep the complete slab owner and store an active range.
- [ ] Return the original allocation after transport bytes drop.
- [ ] Reset initialized bounds before reuse and prevent reuse through aliases.
- [ ] Test stale bytes, headroom, tailroom, capacity classes, and alias lifetime.
- [ ] Run packet and Linux TUN tests.

### Task 5: Hybrid batch preservation

**Files:**

- Modify: `lowertier/src/peers/peer_ospf_route.rs`
- Modify: `lowertier/src/peers/peer_map.rs`
- Modify: `lowertier/src/peers/peer_manager.rs`

- [ ] Write failing mixed-capability batch tests.
- [x] Add a lightweight immutable forwarding snapshot.
- [x] Classify each packet once per batch.
- [x] Preserve compact and Ethernet peer batches.
- [x] Preserve exact recipient, order, and multiplicity semantics.
- [x] Keep bridge authorization separate from capability.
- [x] Run the outbound NIC and ACL pipeline once per TUN IP packet.
- [x] Reserve aggregate fanout bytes before packet cloning.
- [x] Bound route synchronization nodes, edges, and repeated records before graph work.
- [x] Run focused hybrid and L2 fanout tests.
- [ ] Run focused route snapshot tests.

### Task 6: Neighbor validation

**Files:**

- Modify: `lowertier/src/instance/l2_tun.rs`
- Modify: `lowertier/src/instance/virtual_nic.rs`

- [ ] Write failing tests for invalid ARP and normal IPv6 traffic.
- [ ] Parse and validate neighbor requests before route lookup.
- [ ] Reuse parsed targets when building replies.
- [ ] Test ARP, NDP, VLAN, checksum, option, and duplicate-address rules.
- [ ] Run L2 and virtual NIC tests.

### Task 7: Measurement and integration

**Files:**

- Modify: `lowertier/benches/tx_throughput.rs`
- Modify: `docs/performance/hybrid-routing-results.md`

- [ ] Add counters for route snapshots, copies, allocations, queue sends, and socket calls.
- [x] Bind directed link-quality reports to authenticated sources and bound their values.
- [ ] Run the representative correctness matrix.
- [ ] Run the throughput and memory matrix.
- [ ] Compare results with the current baseline.
- [ ] Retain only changes with general evidence.
- [ ] Run formatting, lint, and workspace tests.
