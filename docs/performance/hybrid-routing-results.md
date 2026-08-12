# Automatic hybrid routing results

The test ran on 2026-08-13 in the default aarch64 Colima virtual machine.
The release build used ChaCha20-Poly1305 and the UDP underlay.
The raw Docker bridge delivered 127.02 Gbit/s with eight TCP streams.
The substrate did not limit the LowTier results.

The quick matrix used one three-second run for each workload.
It compared routed, automatic, and legacy Ethernet modes.
It tested both directions with one and eight TCP streams.
It also offered 10 Gbit/s UDP traffic in both directions.

## Data path work

Automatic mode removes the 14-byte Ethernet header from normal IP packets.
The sender advances the packet view and does not copy the IP payload.
The receiver moves the IP payload once only when a TAP edge needs an Ethernet header.
The existing packet batch stays intact when all peers support hybrid L3.
Legacy peers and authorized bridges use the complete Ethernet compatibility path.

This change reduces the overlay payload by 0.92 percent for a 1,500-byte IP packet.
It removes 14 bytes from every normal IP packet at all packet sizes.
It also removes FDB lookup and Ethernet flooding from normal IP unicast.
Multicast delivery uses advertised membership for new peers.
Each peer can advertise at most 256 valid multicast groups.

## Throughput and CPU

The following values come from the repeated matrix that also sampled memory.

| Measurement | Routed | Automatic | Legacy Ethernet |
| --- | ---: | ---: | ---: |
| TCP p8 forward | 4.990 Gbit/s | 4.855 Gbit/s | 4.911 Gbit/s |
| TCP p8 reverse | 4.650 Gbit/s | 4.649 Gbit/s | 4.650 Gbit/s |
| UDP forward received | 2.550 Gbit/s | 2.551 Gbit/s | 2.563 Gbit/s |
| UDP reverse received | 2.640 Gbit/s | 2.653 Gbit/s | 2.718 Gbit/s |
| Forward endpoint cores/Gbit | 0.142 + 0.124 | 0.144 + 0.125 | 0.145 + 0.125 |
| Reverse endpoint cores/Gbit | 0.162 + 0.157 | 0.166 + 0.162 | 0.164 + 0.158 |

Automatic mode stayed close to routed mode in this short matrix.
The largest TCP p8 difference was 2.7 percent.
The reverse TCP p8 results were equal within 0.01 percent.
The common peer manager, encryption, queue, and UDP paths remain the main throughput limit.

## Memory and latency

Peak RSS stayed between 30.0 MiB and 32.5 MiB for automatic mode.
The largest automatic peak was 0.34 MiB above the matching routed peak.
Other automatic peaks were lower than their routed values.

Automatic unloaded RTT averaged 0.239 ms in the repeated run.
It averaged 0.597 ms in the first run.
Routed unloaded RTT averaged 0.574 ms and 0.577 ms.
The short runs do not show a stable latency difference.

## Correctness evidence

The full LowTier library test ran 1,068 tests.
It passed 1,058 tests and ignored 10 tests.
No test failed.

Focused integration tests verified these properties:

- Modern TAP peers carry compact IP packets in the original batch order.
- Legacy Ethernet peers receive the original complete Ethernet frame.
- Multicast traffic targets only peers that advertise membership.
- Hybrid nonbridge peers reject complete Ethernet from modern hybrid senders.
- Local ARP and NDP replies use the known overlay peer address.
- Reliable QUIC streams recover without reconnecting the QUIC connection.

The Linux release binary built and completed the complete performance matrix.
The direct macOS cross-check could not run because the host lacks `x86_64-linux-gnu-gcc`.
The Docker Linux build provides the target-platform build evidence.

Clippy found existing warnings in generated code, vendor code, and unrelated modules.
The project does not currently pass `cargo clippy -- -D warnings` on this toolchain.
