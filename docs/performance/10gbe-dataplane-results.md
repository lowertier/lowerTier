# 10GbE-class dataplane results

Measured on 2026-07-18 on an Apple Silicon macOS host. The VZ run used the default Colima
profile with 16 virtual CPUs and 128 GiB RAM. The native macOS run used an LowTier process on
the host and an aarch64 QEMU Colima peer reached through UDP port forwarding.

These are software dataplane measurements, not simulated NIC line-rate claims. The raw VZ
Docker bridge carried 121.95 Gbit/s with eight TCP streams, so it did not constrain the LowTier
result. The QEMU macOS-to-VM path does constrain the native test; CPU per delivered Gbit is the
primary macOS metric.

## Retained changes

- Darwin utun reads and writes packet vectors instead of issuing one syscall per packet.
- TUN/TAP ingress creates bounded, zero-copy `PacketBatch` values. L2-TUN caches each unique
  destination route once per batch, Ethernet classification runs once per frame, and known
  unicast packets are grouped in stable order by next hop.
- Direct and relay peer selection, traffic accounting, and MPSC queues carry packet batches.
  A batch is one queue flush round. Both batch jobs and scalar compatibility jobs consume bounded
  packet-count credits, so a vector cannot silently multiply queue memory by its width.
- Receive slots and payload storage are persistent on Darwin utun, Darwin UDP, and Linux UDP.
  Counter handles share immutable metric keys, and cached peer counters update without cloning
  label strings on every packet.
- A symmetric five-tuple classifier assigns packets to 64 stable flow shards. Reverse traffic uses
  the same shard, each shard retains FIFO order, and a bounded TTL path cache pins the selected
  next hop until route invalidation, path failure, or strict underlay denial. The shard is stamped
  into the existing reserved peer-header byte before encryption, so relays retain flow identity
  with no additional wire bytes. Eagerly splitting a mixed vector is experimental through
  `LOWTIER_ENABLE_FLOW_SHARD_SPLIT=1` because the default keeps the faster intact vector.
- Linux UDP uses `sendmmsg`/`recvmmsg` and coupled UDP GSO/GRO. Darwin UDP receive uses
  `recvmsg_x`; Darwin socket `sendmsg_x` remains opt-in with
  `LOWTIER_ENABLE_UDP_SEND_VECTOR=1` because native A/B testing found a forward-throughput
  regression. The separate utun `sendmsg_x` backend remains enabled.
- Established Rayon parallel encryption is implemented for batches of at least 32 packets but is
  opt-in (`LOWTIER_ENABLE_PARALLEL_CRYPTO=1`). Per-batch Rayon reduced throughput on both the
  four-vCPU QEMU and 16-vCPU VZ profiles, so the measured default preserves in-order sequential
  ChaCha20-Poly1305 encryption.
- Linux virtio TUN checksum/TSO/GRO support is implemented with `quincy-tun`, which ports the
  WireGuard-go offload model. It defaults on for x86_64, where quincy has AVX2/SSE4.1 checksum
  acceleration. It defaults off on aarch64, where forced scalar checksum handling reduced this
  QEMU workload to about 86 Mbit/s. ARM users can opt in with
  `LOWTIER_ENABLE_LINUX_TUN_OFFLOAD=1`; every architecture falls back to portable TUN if the
  kernel rejects negotiation.
- Fresh STUN observations are gathered for every punch attempt through the persistent data socket.
  Strict deny filtering is applied before STUN handling, candidate advertisement, triggered checks,
  or path-cache reuse, so a denied interface, address, or subnet cannot carry discovery traffic.
- QUIC uses the established Quinn BBR controller. Normal data uses raw QUIC DATAGRAM records when
  it fits. Critical control and oversized records use the reliable stream. The direct data path has
  no private reliability envelope, packet identifier, acknowledgment, retransmission, or FEC.
- L3, L2-TUN, and TAP use the same measured forwarding and UDP transport path.
- Lean builds always include audited ChaCha20-Poly1305 authenticated encryption. XOR is no longer
  an encryption option.

Several smaller peer-manager fast paths were evaluated after the vector-I/O change. They were
removed because exact native A/B runs did not show a consistent improvement.

## Shared packet-batch result

The final encrypted L2-TUN defaults were compared with exact commit `5e635e5d`. QEMU used four
virtual CPUs; VZ used sixteen. Both raw substrates exceeded 100 Gbit/s.

| Platform | Measurement | Baseline | Packet-batch default | Change |
| --- | --- | ---: | ---: | ---: |
| QEMU | TCP p1 forward | 2.463 Gbit/s | 3.486 Gbit/s | +41.5% |
| QEMU | TCP p4 forward | 2.607 Gbit/s | 3.754 Gbit/s | +44.0% |
| QEMU | TCP p4 reverse | 2.678 Gbit/s | 3.878 Gbit/s | +44.8% |
| QEMU | forward endpoint cores/Gbit | 0.362 + 0.327 | 0.170 + 0.247 | -53.0% / -24.5% |
| QEMU | unloaded RTT | 1.152 ms | 1.119 ms | -0.033 ms |
| VZ | TCP p4 forward | 3.458 Gbit/s | 5.707 Gbit/s | +65.0% |
| VZ | TCP p4 reverse | 3.429 Gbit/s | 5.701 Gbit/s | +66.3% |
| VZ | endpoint cores/Gbit | 0.46-0.52 | 0.183-0.237 | at least 48% lower |
| VZ | unloaded RTT | 0.682 ms | 0.632 ms | -0.050 ms |

The QEMU CPU probe delivered 3.95 Gbit/s forward and 3.90 Gbit/s reverse. Loaded RTT averaged
0.623 ms forward and 0.591 ms reverse. The VZ CPU probe delivered 5.67/5.69 Gbit/s; loaded RTT
averaged 1.000/0.985 ms. VZ UDP delivered the full offered 2.5 Gbit/s in both directions.

The decisive sequencing result is that socket batching only became useful after packet vectors
survived route selection, encryption, and the peer queue. Linux vector UDP alone reached about
3.00 Gbit/s on QEMU; coupled UDP GSO/GRO raised TCP to about 3.9 Gbit/s. GSO without GRO fell to
1.55 Gbit/s and was rejected.

Native macOS remains constrained by the QEMU port-forwarding path. With Darwin socket send vectors
disabled, two adjacent five-second runs delivered 494-509 Mbit/s forward and 423-429 Mbit/s
reverse. Host CPU measured 0.917 cores/Gbit forward and 2.186 reverse. Enabling Darwin UDP
`sendmsg_x` reduced the three-run forward median to 418 Mbit/s, so it is opt-in; Darwin UDP
`recvmsg_x` and the existing vector utun backend remain default.

An exact-final-source smoke run, with no performance environment overrides, delivered 520 Mbit/s
forward and 435 Mbit/s reverse with zero packet loss. Its five-second CPU probes measured 0.962
and 2.269 cores/Gbit. The short run is confirmation of the retained default, not a replacement for
the adjacent multi-run A/B result above.

Flow sharding and path pinning now follow ZeroTier's ordering rule without introducing a
per-batch fork/join. The classifier hashes both directions of a flow to the same one of 64 FIFO
lanes, while the path cache survives route jitter and is explicitly invalidated on failure or
denial. Ordered Rayon crypto remains available for vectors of at least 32 packets, but it is
opt-in because a final adjacent QEMU A/B measured 4.029/3.845 Gbit/s with the inline path versus
3.271/2.902 Gbit/s with per-batch Rayon.

## Flow-sharded hybrid-transport result

The final source was rebuilt in the four-vCPU aarch64 QEMU profile after packet-credit queue
accounting, flow pinning, fresh STUN, QUIC DATAGRAM, and Linux offload integration. The raw Docker
bridge carried 129.09 Gbit/s with four streams.

| Final QEMU L2-TUN measurement | Forward | Reverse |
| --- | ---: | ---: |
| TCP p1 | 3.485 Gbit/s | 3.506 Gbit/s |
| TCP p4 | 3.913 Gbit/s | 3.942 Gbit/s |
| UDP received at 5 Gbit/s offered | 2.547 Gbit/s | 2.408 Gbit/s |
| endpoint CPU cores/Gbit | 0.200 + 0.281 | 0.267 + 0.273 |
| loaded RTT average | 0.621 ms | 0.649 ms |

Unloaded RTT was 0.175/0.754/1.268 ms minimum/average/maximum with no loss. This short final run
is consistent with the retained packet-batch result above and shows that bounded packet credits do
not erase the vector gain.

The final native macOS smoke run used the same source on both the host and QEMU peer. It delivered
486 Mbit/s forward and 408 Mbit/s reverse. Separate CPU probes measured 0.821 and 2.164 native
cores/Gbit, sampled RSS was about 24.5 MiB, and the process used six threads. Unloaded RTT was
2.137/4.997/7.533 ms in this jittery short run. The QEMU UDP port-forwarding boundary still constrains this topology, so the
native numbers validate regressions and resource use rather than a physical 10GbE ceiling.

Eager mixed-vector shard splitting was measured separately and rejected as a default. It reduced
TCP p4 to 2.706/2.608 Gbit/s and raised per-endpoint CPU to about 0.36-0.45 cores/Gbit. Keeping the
wire-stamped shard and intact vector restored 3.913/3.942 Gbit/s. The split implementation remains
available for experiments that have enough persistent per-flow work to amortize the extra jobs.

## VZ result

Quick L3 runs used eight TCP streams, one repetition, and five-second workloads. The baseline and
candidate substrate results were 122.71 and 121.95 Gbit/s, respectively.

| Direction | Baseline TCP | Candidate fast paths | Change |
| --- | ---: | ---: | ---: |
| Forward | 3.840 Gbit/s | 3.900 Gbit/s | +1.6% |
| Reverse | 3.869 Gbit/s | 3.865 Gbit/s | -0.1% |
| Mean | 3.855 Gbit/s | 3.882 Gbit/s | +0.7% |

The candidate run received 5.40 Gbit/s forward and 5.42 Gbit/s reverse when offered 10 Gbit/s
UDP. Unloaded RTT averaged 0.643 ms; loaded RTT averaged 1.272 ms. The 0.7% mean TCP change was
too small to justify retention after the native A/B result disagreed.

The full baseline matrix found the same ceiling in every port mode:

| Mode | Forward TCP | Reverse TCP |
| --- | ---: | ---: |
| L3 | 3.778 Gbit/s | 3.807 Gbit/s |
| L2-TUN | 3.814 Gbit/s | 3.812 Gbit/s |
| TAP | 3.984 Gbit/s | 3.991 Gbit/s |

This rules out the L2 shim and TUN mode as the main throughput limit. The common peer-manager,
queue, and UDP socket path is the remaining ceiling.

## Authenticated-encryption result

The earlier minimal `tun` benchmark build did not include an AEAD feature and therefore selected
the old XOR fallback. That was an insecure configuration bug, so those numbers are retained only
as a performance baseline. Commit `b64d3e7a` makes `ring` ChaCha20-Poly1305 available and default
in every feature set, removes XOR from the accepted algorithms, and makes both benchmark harnesses
select `chacha20-poly1305` explicitly.

The encrypted VZ matrix used three five-second samples per direction. The raw bridge carried
118.74 Gbit/s, so the substrate remained valid.

| Mode | Forward TCP median | Reverse TCP median | Forward change vs XOR | Reverse change vs XOR |
| --- | ---: | ---: | ---: | ---: |
| L3 | 3.553 Gbit/s | 3.398 Gbit/s | -6.0% | -10.8% |
| L2-TUN | 3.458 Gbit/s | 3.429 Gbit/s | -9.3% | -10.1% |
| TAP | 3.710 Gbit/s | 3.661 Gbit/s | -6.9% | -8.3% |

Encrypted UDP medians were 4.84-5.24 Gbit/s when offered 10 Gbit/s. Unloaded RTT averaged
0.646 ms for L3, 0.682 ms for L2-TUN, and 0.793 ms for TAP. CPU use was 0.46-0.52 cores per
delivered Gbit at each LowTier endpoint. The similar cost in every mode confirms that encryption
belongs in the shared peer/UDP optimization work rather than separate L2 and L3 implementations.

## Native macOS result

The native test used L2-TUN, eight TCP streams, three ten-second runs in each direction, a
ten-second CPU probe, and a QEMU Colima peer. The exact pre-change commit and each candidate were
built separately and run through the same harness.

| Build | Forward median | Reverse median | Forward cores/Gbit | Reverse cores/Gbit |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 506.4 Mbit/s | 430.8 Mbit/s | 1.029 | 2.113 |
| Full candidate, run 1 | 510.1 Mbit/s | 427.8 Mbit/s | 1.014 | 2.163 |
| Full candidate, run 2 | 502.2 Mbit/s | 426.6 Mbit/s | 1.004 | 2.183 |
| TX-only candidate | 499.8 Mbit/s | 424.8 Mbit/s | 1.023 | 2.207 |

Two authenticated-encryption repeats produced combined six-sample medians of approximately
506 Mbit/s forward and 430 Mbit/s reverse, effectively unchanged from the XOR throughput baseline.
The exact ten-second CPU-window repeat measured 1.003 cores/Gbit forward and 2.173 reverse. The
QEMU path remains the throughput limit; ChaCha's cost appears mainly as small CPU variation here.

The candidate saved some host TX CPU but consistently lost reverse throughput and reverse CPU
efficiency. The TX-only result also lost forward throughput. All peer-manager candidates were
therefore removed. QEMU RTT varied from 4.5 to 5.9 ms between adjacent runs, which quantifies why
single-run macOS results must not be used for retention decisions.

## Rejected experiments

The following changes were measured and removed:

- A 64-datagram `sendmmsg`/Darwin `sendmsg_x` batch at the UDP socket edge reduced VZ TCP
  throughput by 5-6%. Packets reached that boundary too sparsely to form useful batches.
- An `ArcSwap` cache of the selected peer connection left serial injection flat and reduced the
  saturated microbenchmark by about 1.1% on Apple Silicon.
- A Tokio `try_send`-first queue path and a combined direct-peer lookup produced mixed or
  negative microbenchmark results.
- Empty NIC-filter and no-compression fast paths improved some TX CPU samples but regressed the
  repeated native A/B throughput and RX efficiency, so they were removed.

### Fresh VZ offload isolation

A second clean encrypted L2-TUN baseline used the same VZ host, five-second workloads, one run,
and a raw substrate of 102.13 Gbit/s for one stream and 115.39 Gbit/s for eight streams.

| Measurement | Forward | Reverse |
| --- | ---: | ---: |
| Baseline TCP p1 | 3.834 Gbit/s | 3.849 Gbit/s |
| Baseline TCP p8 | 3.601 Gbit/s | 3.512 Gbit/s |
| Baseline total CPU cores/Gbit | 0.883 | 0.994 |
| Baseline loaded RTT | 1.386 ms | 1.368 ms |

Two established Linux mechanisms were then isolated and removed:

| Candidate | Forward TCP p1 | Reverse TCP p1 | Forward total cores/Gbit | Reverse total cores/Gbit | Unloaded RTT |
| --- | ---: | ---: | ---: | ---: | ---: |
| `quinn-udp` GSO after boundary fix | 3.426 Gbit/s | 3.416 Gbit/s | 0.923 | 1.017 | 0.785 ms |
| no-copy `nix::sendmmsg` | 3.598 Gbit/s | 3.659 Gbit/s | 0.879 | 0.985 | 0.806 ms |

The baseline unloaded RTT was 0.544 ms. Both candidates exceeded the 0.2 ms latency-regression
limit. Neither delivered the required 15% throughput or CPU/Gbit improvement. The GSO candidate
lost 10.7% forward and 11.2% reverse p1 TCP throughput. The no-copy `sendmmsg` candidate lost
6.2% forward and 5.0% reverse.

This is not evidence against `sendmmsg` or GSO. It is evidence against applying them after
LowTier has already serialized routing, encryption, queueing, and scheduling. Tailscale keeps
vectors through those stages before reaching UDP. LowTier must do the same.

These results point to batching before the final UDP queue, not adding delay or another cache at
the socket. Linux UDP GSO/GRO and multi-packet queue items are the next credible route to 10
Gbit/s. Darwin should use `sendmsg_x`/`recvmsg_x` from the same upstream batch abstraction.

## Noisy L2 QUIC DATAGRAM result

The QEMU Colima profile used four vCPUs and 8 GiB RAM. Both container egress
interfaces applied `delay 140ms 40ms loss random 3%`, producing a randomized
100-180 ms one-way path with independent loss in each direction. The raw bridge
carried 12.14 Mbit/s with one TCP flow and 16.93 Mbit/s with four flows in this
deliberately impaired environment.

The legacy LowTier QUIC checksum implementation was not resilient. Under the
same matrix it produced checksum mismatches, false stateless resets,
`KEY_UPDATE_ERROR`, and `unsent packet acked`, with three peer reconnects in one
run. Upgrading Quinn alone did not correct the defect.

After replacing the checksum shim with Quinn's rustls/ring TLS 1.3 packet
protection, the complete matrix recorded zero peer removals, protocol
violations, key-update failures, checksum failures, receive-loop errors, or
send timeouts. Results from the five-second workloads were:

| Workload | Forward | Reverse |
| --- | ---: | ---: |
| TCP, one flow | 0.918 Mbit/s | 0.356 Mbit/s |
| TCP, four flows | 1.657 Mbit/s | 1.440 Mbit/s |
| UDP receiver, 100 Mbit/s offered | inner iperf control reset | 2.509 Mbit/s |
| CPU probe, four TCP flows | 1.826 Mbit/s | 1.490 Mbit/s |
| Endpoint CPU during probe | 3.25% / 3.23% | 3.78% / 4.40% |

Unloaded overlay RTT averaged 305.8 ms. Loaded RTT averaged 374.9 ms forward
and 314.8 ms reverse, with maxima of 967.2 and 808.6 ms. The 100 Mbit/s forward
UDP offer overloaded an approximately 2 Mbit/s overlay enough to reset iperf's
inner TCP control flow, but the LowTier peer and QUIC connection stayed up.
The harness now records such application-level failures in
`workload-errors.tsv` rather than writing an incomplete throughput row.

A second run offered 5 Mbit/s UDP, near the usable noisy-path capacity. It
delivered 4.980 Mbit/s forward and 5.000 Mbit/s reverse, with iperf loss of
1.09% and 0.16%. There were no workload errors or LowTier peer removals.
Loaded RTT averaged 318.9 ms forward and 299.8 ms reverse. This separates the
transport result from the intentional 100 Mbit/s overload: normal offered load
is carried nearly in full, while gross overload drops application traffic
without tearing down the encrypted QUIC peer.

The exact final image was also rerun at a conservative 1 Mbit/s UDP offer. It
delivered 0.990 Mbit/s forward and 1.004 Mbit/s reverse, with 0.70% and 0.32%
inner iperf loss. All loaded pings completed and the logs again contained no
peer removal, QUIC protocol violation, key-update failure, receive-loop error,
or send timeout. One short reverse four-flow TCP workload lost its inner iperf
control connection; the LowTier QUIC peer remained connected and the following
reverse UDP and latency workloads completed.

## Comparison boundary

Tailscale's published 10GbE work used two bare-metal Linux systems with Mellanox 25GbE adapters,
then added packet vectors, UDP GSO/GRO, and checksum work. LowTier's VZ result is therefore not
an apples-to-apples product comparison. It is an actionable bottleneck test: the substrate is
fast enough, all LowTier port modes converge near 4 Gbit/s TCP, and the remaining work belongs
in the shared queue/socket backend.

References:

- [Tailscale: Surpassing 10Gb/s](https://tailscale.com/blog/more-throughput)
- [Tailscale performance best practices](https://tailscale.com/docs/reference/best-practices/performance)
- [ZeroTierOne source](https://github.com/zerotier/ZeroTierOne)

## Reproduce

```bash
QUICK=1 RESULT_DIR=/tmp/lowertier-10gbe script/colima-throughput/e2e.sh

cargo build --locked --release -p lowertier --bin lowertier-core \
  --no-default-features --features tun
RUNS=1 DURATION=5 CPU_DURATION=5 RESULT_DIR=/tmp/lowertier-macos \
  script/macos-tun-bench/e2e.sh target/release/lowertier-core
```

Both harnesses default `ENCRYPTION_ALGORITHM=chacha20-poly1305` and record it in
`environment.txt`.

The raw JSON, latency samples, CPU samples, normalized throughput, and environment metadata are
kept in the selected result directory.

The native macOS resource comparison against pinned Tailscale `wireguard-go`, including two full
measurement passes and the rejected coherent-ring experiment, is documented in
[`wireguard-resource-comparison.md`](wireguard-resource-comparison.md).
