# Protected L2 Wire Results

Date: 2026-08-10

## Result

The native TAP path provides complete Ethernet frame transport within its configured MTU.

Secure UDP traffic now hides the peer header, packet type, length field, peer identifiers, payload, and sequence number.

The L2 correctness gate passed.

The steady-state signature gate passed after the eight-byte UDP transport header.

The latency and throughput targets did not pass in the QEMU environment.

## Test Environment

The tests used the `easytier-l2` Colima QEMU profile.

The virtual machine used four ARM64 virtual CPUs.

EasyTier used UDP underlay transport and secure mode.

The two-node benchmark used 1000 ping samples and three 10-second throughput runs.

The WireGuard comparison used Linux kernel WireGuard in the same QEMU profile.

WireGuard carried L3 traffic.

EasyTier carried native TAP Ethernet traffic.

This comparison is not feature equivalent.

## Full L2 Verification

The exact frame harness passed these cases through a relay:

- Unknown EtherType.
- IEEE 802.1Q VLAN.
- IEEE 802.1ad QinQ.
- LLDP multicast.
- Broadcast.
- Known unicast.
- Unknown unicast.
- MAC movement.
- Configured MTU boundary.
- Oversized frame rejection.

The harness also passed L2-TUN, mixed TAP and L2-TUN, and L3 compatibility modes.

Linux can remove a VLAN tag before AF_PACKET delivery.

The receiver restores that tag from authenticated PACKET_AUXDATA metadata before comparison.

## Encryption

Secure mode uses Noise XX with X25519, ChaCha20-Poly1305, and SHA-256.

Noise derives separate link keys for each direction.

The link envelope encrypts the complete peer header and payload.

The envelope authenticates the protocol domain and packet sequence.

HMAC-SHA256 header protection hides the sequence number.

A 256-packet replay window rejects duplicate and stale packets.

Direct packets use one link encryption layer.

Relayed packets keep end-to-end encryption inside each protected physical link.

The negative tests reject ciphertext changes, visible header changes, replay, wrong direction, and plaintext downgrade.

Protected link activation occurs only after the Noise handshake installs the link keys.

The protected envelope does not have explicit mixed-version negotiation yet.

Mixed secure versions can fail after the Noise handshake.

The new envelope has not received an external security audit.

## Passive Signature Result

The scanner captured 128 steady-state UDP packets.

The scanner removed the eight-byte UDP transport header before the strict envelope test.

| Measurement | Result |
| --- | ---: |
| Packet count | 128 |
| Unique packet ratio | 1.000 |
| Common envelope prefix | 0 bytes |
| Common envelope suffix | 0 bytes |
| Fixed envelope positions | 0 |
| Mean position entropy | 6.549 bits |
| Minimum position entropy | 6.411 bits |
| `easytier` hits | 0 |
| Network name hits | 0 |
| Network secret hits | 0 |
| `ETL1` hits | 0 |

The complete UDP payload has a four-byte connection identifier prefix.

The identifier is random for each connection.

The outer packet type, padding, and length bytes vary with protected packet bytes.

Packet size, timing, direction, endpoints, and the connection identifier remain visible.

The UDP SYN and SACK setup packets remain recognizable.

Noise message one still exposes its clear payload under the Noise XX pattern.

QUIC no longer sends the fixed `easytier-quic/4` ALPN value.

QUIC no longer sends the fixed `localhost` server name.

QUIC traffic remains recognizable as QUIC.

The tests do not claim active probing resistance.

## RTT

The table reports the median result from three independent EasyTier runs.

WireGuard used one 1000-sample latency run.

| QEMU RTT overhead | Protected EasyTier TAP | Basic EasyTier TAP | Kernel WireGuard |
| --- | ---: | ---: | ---: |
| Median | 0.699 ms | 0.607 ms | 0.602 ms |
| p99 | 1.309 ms | 1.311 ms | 1.379 ms |

The protected envelope adds about 0.093 ms median RTT over the basic EasyTier path.

Its p99 result is equal within QEMU variation.

One quiet protected run reached 0.190 ms median overhead and 0.291 ms p99 overhead.

The representative result does not meet the 0.25 ms median target.

The representative result does not meet the 0.75 ms p99 target.

A native host-to-host test is still required.

## Throughput

| QEMU throughput | Median |
| --- | ---: |
| Protected EasyTier TAP | 3.21 Gbit/s |
| Basic EasyTier TAP | 3.84 Gbit/s |
| Kernel WireGuard | 5.76 Gbit/s |

Protected EasyTier is 16.3 percent slower than the basic EasyTier path.

The result does not meet the five percent regression target.

Protected EasyTier is 44.2 percent slower than kernel WireGuard in this QEMU test.

The earlier native macOS L2-TUN test used userspace `wireguard-go`.

That test measured EasyTier as 31.8 percent faster forward and 1.4 percent faster reverse.

The protected TAP build has not repeated that native comparison.

## Implementation Cost

The first envelope copied and allocated full packets.

It reached 2.36 Gbit/s in the first two-node test.

The retained path encrypts and decrypts the existing packet buffer in place.

It also preserves internal queue policy without exposing the peer packet type.

The retained path reaches 3.21 Gbit/s median.

Further work must reduce structural packet work.

Micro-tuning is not justified by the current evidence.

## Verification Commands

```text
cargo test --locked -p easytier --no-default-features --features tun l2 -- --nocapture
cargo test --locked -p easytier --no-default-features --features tun peer_conn_secure_mode -- --nocapture
cargo test --locked -p easytier --no-default-features --features tun link_envelope::tests -- --nocapture
cargo test --locked -p easytier --no-default-features --features tun,quic quic_transport_uses_tls13_and_survives_a_key_update -- --nocapture
bash script/tests/colima-l2-static-test.sh
bash script/tests/colima-l2-benchmark-static-test.sh
COLIMA_DOCKER_CONTEXT=colima-easytier-l2 SKIP_IMAGE_BUILD=1 bash script/colima-l2/e2e.sh
```

Clippy completed with 13 existing warnings.

Clippy reported no warning in the new envelope, UDP signature, benchmark, or frame probe code.
