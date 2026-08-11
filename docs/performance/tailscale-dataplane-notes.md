# Established dataplane designs: Tailscale, WireGuard, and ZeroTier

This review uses these pinned local source snapshots:

- Tailscale `cc0b3ddbbe7804f84cf95bd087df9e921bada30e`
- Tailscale's wireguard-go `2e01ba5b00f0`
- ZeroTierOne `5951981622a8d1216a64a8df065d87b9a0dbd21e`

The purpose is implementation reuse, not an assumption that the projects have identical routing
or security models. No Tailscale, WireGuard, or ZeroTier code is copied into LowTier by this
document. Tailscale and wireguard-go provide the throughput model. ZeroTier provides useful L2
forwarding and flow-sharding patterns. Its current scalar UDP transmit path is not a 10GbE model.

## Current wire cost

For an encrypted LowTier raw-UDP data packet, the fixed inner overhead is:

| Field | Bytes |
| --- | ---: |
| LowTier peer-manager header | 16 |
| LowTier UDP tunnel header | 8 |
| AEAD tag | 16 |
| Transmitted AEAD nonce | 12 |
| Total before outer IP/UDP | 52 |

WireGuard transport data uses a 16-byte transport header and a 16-byte tag, or
32 bytes before outer IP/UDP. LowTier therefore pays 20 more fixed bytes for
normal L3 packets. Compatible Ethernet adds a 14-byte Ethernet header, making its fixed
inner overhead 66 bytes. Outer IPv4 plus UDP adds 28 bytes in both cases; IPv6
plus UDP adds 48 bytes.

The peer-manager header carries real LowTier functionality: source and
destination peer IDs, packet type, relay counter, flags, and payload length.
Removing it globally would trade away routing features. The transmitted random
nonce is a better future target: a per-session monotonic counter with a replay
window can avoid 12 wire bytes and random-number generation per packet.

## What actually produced Tailscale's 10Gb/s result

Tailscale's published result is not a faster congestion-control algorithm. It is an end-to-end
packet-vector and kernel-offload pipeline:

1. wireguard-go reads a packet vector from TUN.
2. `device/send.go` groups the vector by peer and uses pooled queue containers.
3. Encryption workers process packet elements in parallel.
4. A sequential per-peer sender preserves order and passes the vector to the UDP binding.
5. `net/batching/conn_linux.go` uses scatter/gather `sendmmsg`/`recvmmsg`, UDP GSO/GRO, bounded
   64-datagram GSO groups, and capability fallback.
6. `tun/tun_linux.go` negotiates `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6`, consumes virtio network
   headers, performs GSO splitting when required, and applies TCP/UDP GRO on writes back to TUN.

`conn.IdealBatchSize` is 128. Crucially, the vector exists before peer selection and encryption.
The final UDP layer does not try to reconstruct useful batches from a scalar pipeline.

Tailscale reports 13.0 Gbit/s on bare-metal Linux after this full sequence. That figure cannot be
attributed to UDP GSO alone.

## What ZeroTier contributes

ZeroTier is L2-native. `Switch::onLocalEthernet` classifies an Ethernet frame by destination MAC.
Known ZeroTier MAC addresses map directly to a peer. Unknown bridged destinations use the learned
bridge table or bounded flooding. `_trySend` selects the peer path, then `_sendViaSpecificPath`
encrypts and transmits it.

The reusable performance ideas are:

- `PacketMultiplexer` hashes `flowId % concurrency` into bounded 2,048-entry queues. Packets in
  one flow remain on one worker, while independent flows can run in parallel.
- Linux receive uses a 128-entry `recvmmsg` window.
- Packet records and receive buffers are pooled instead of recreated for every frame.
- L2 forwarding maps a known MAC directly to its peer and chosen path.

The limits matter as much as the useful ideas:

- `Phy::udpSend` still uses scalar `sendto`.
- `PacketMultiplexer` is disabled on Apple, BSD, and Windows builds.
- The macOS TAP implementation uses a helper process and `writev`; it is not a modern utun fast
  path.
- ZeroTier's protocol and crypto are not substitutes for LowTier's established
  ChaCha20-Poly1305 implementation.

LowTier should therefore adopt flow-stable bounded workers and direct L2 peer selection only
after packet vectors exist. It should not copy ZeroTier's scalar UDP transmit or old macOS TAP
backend.

## Current LowTier hot-path difference

LowTier now carries a bounded packet vector from TUN/TAP ingress through L2 classification,
next-hop grouping, direct/relay selection, peer queues, and platform UDP I/O. Linux uses
`sendmmsg`/`recvmmsg` plus coupled UDP GSO/GRO. Darwin keeps its utun `recvmsg_x`/`sendmsg_x`
backend, uses socket `recvmsg_x`, and defaults socket transmit to scalar `send_to` because native
A/B testing rejected Darwin UDP `sendmsg_x` for this workload.

LowTier now assigns symmetric flows to 64 stable FIFO send lanes and pins their chosen path in a
bounded TTL cache. The six-bit shard is carried in the existing reserved peer-header byte, so it
survives encryption and relay hops without increasing the header. This adopts ZeroTier's ordering
model without copying its scalar UDP backend.
The remaining structural difference is crypto worker ownership: Tailscale and wireguard-go
amortize crypto across persistent workers, while LowTier's available parallel implementation is
still batch-scoped Rayon. Experiments reject that fork/join path as a default, so parallel crypto
remains opt-in and the singleton/vector inline path is the measured default.

Eagerly turning every mixed vector into one queue job per shard is also opt-in through
`LOWTIER_ENABLE_FLOW_SHARD_SPLIT=1`. On four-vCPU QEMU it reduced TCP p4 from
3.913/3.942 Gbit/s to 2.706/2.608 Gbit/s and roughly doubled CPU/Gbit. The retained default stamps
the flow identity and preserves the intact vector; future persistent flow workers can consume the
same metadata without repeating classification.

Other recurring LowTier work includes route and DashMap lookups, asynchronous
traffic-metric updates, compression dispatch even when compression is disabled,
and deep packet clones during fanout. These are secondary to batching for bulk
traffic, but they can matter for small-packet p99 latency.

## Experimental correction to the implementation order

Two clean VZ experiments disproved the old recommendation to add socket batching first:

| Candidate | Forward TCP p1 | Reverse TCP p1 | CPU/Gbit result | Unloaded RTT | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Clean encrypted baseline | 3.834 Gbit/s | 3.849 Gbit/s | 0.883 / 0.994 total cores/Gbit | 0.544 ms | reference |
| Late no-copy `sendmmsg` | 3.598 Gbit/s | 3.659 Gbit/s | 0.879 / 0.985 | 0.806 ms | remove |
| Late `quinn-udp` GSO | 3.426 Gbit/s | 3.416 Gbit/s | 0.923 / 1.017 | 0.785 ms | remove |

The first GSO prototype also exposed an integration hazard. `quinn-udp::UdpSocketState::new`
enables UDP GRO opportunistically. LowTier's scalar `recv_from` then received several logical
datagrams as one buffer and rejected it. A Linux regression test reproduced the behavior. After
GRO was disabled and packet boundaries were restored, the candidate still regressed and was
removed.

The result is unambiguous: syscall batching is useful only after the upstream dataplane produces
a real vector.

The completed upstream batch implementation validates that conclusion. Exact encrypted L2-TUN
tests improved QEMU TCP p4 from 2.607/2.678 to 3.754/3.878 Gbit/s and VZ TCP p4 from
3.458/3.429 to 5.707/5.701 Gbit/s. QEMU unloaded RTT improved from 1.152 to 1.119 ms; VZ unloaded
RTT improved from 0.682 to 0.632 ms. Per-endpoint CPU/Gbit fell by at least 24% on QEMU and 48%
on VZ. These gains appeared only when the vector survived the peer queue before reaching UDP.

Two established mechanisms remain implemented with measured gates:

- `quincy-tun` ports WireGuard-go's Linux checksum, TSO/GRO, and virtio-header logic. x86_64 uses
  its AVX2/SSE4.1 checksum acceleration by default. aarch64 defaults off because forced scalar
  checksum handling fell to about 86 Mbit/s in QEMU; it can be enabled with
  `LOWTIER_ENABLE_LINUX_TUN_OFFLOAD=1` for capable ARM implementations.
- Rayon packet encryption preserves per-peer order after the parallel phase, but direct Rayon
  reached 1.88-1.93 Gbit/s in earlier QEMU trials and a final adjacent A/B reached only
  3.271/2.902 Gbit/s versus 4.029/3.845 Gbit/s inline. It requires
  `LOWTIER_ENABLE_PARALLEL_CRYPTO=1`.

## Correct implementation order

1. Introduce one bounded `PacketBatch` ownership type at TUN/TAP ingress. A lone packet leaves
   immediately; only already-ready packets join it.
2. Classify L2 frames once, group known unicast by next hop, and carry one batch through the peer
   queue. L2-TUN is an edge adapter into the same classifier.
3. Follow wireguard-go's split: parallel per-packet encryption, then ordered per-peer batch send.
   Reuse packet and batch containers.
4. Collapse the duplicate UDP ring and peer MPSC stages or make them carry one batch item, not 64
   scalar notifications.
5. Add Linux `sendmmsg`/`recvmmsg`, then UDP GSO/GRO with explicit segment metadata and fallback.
6. Add Linux TUN TSO/GRO and checksum metadata. Without this step, a 10GbE claim is not credible.
7. Shard independent flows across bounded workers only after the single-worker batch path is
   correct. Preserve per-flow ordering as ZeroTier does.
8. Cache selected next hops by route-table generation and flush worker-local metrics in groups.
9. Replace transmitted random AEAD nonces with a session ID plus monotonic
   packet counter and replay window. This requires a protocol version break and
   careful nonce uniqueness across reconnects.
10. Make fanout packet storage immutable and reference-counted so only the small
   per-destination header is copied.
11. Consider a compact direct-data header only after profiling proves the
   16-byte peer header is material. Keep the full header for relay and control
   traffic.

The socket and kernel offload steps must remain disabled until their matching batch metadata is
consumed on receive. No stage may add a batch-fill timer.

## Measurements from the L2-TUN milestone

The Colima QEMU UDP suite measured 2.74 Gbit/s for three-node native TAP and
2.59 Gbit/s for three-node compatible Ethernet in one run. This is about a 5.5% difference,
but it includes VM scheduling, TCP behavior inside `iperf3`, and run-to-run
variance, so it does not isolate the 14-byte shim.

The native macOS `utun` to Linux TAP test used UDP through Colima's gRPC port
forwarder. Five pings in each direction had zero loss and average RTTs of
1.437 ms and 1.471 ms. Colima's default SSH forwarder is TCP-only and cannot be
used for this UDP test.
