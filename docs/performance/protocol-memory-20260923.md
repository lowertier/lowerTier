# LowTier protocol-specific memory optimization

Source changes are committed. This report separates implementation correctness, cold footprint, loaded footprint, and deployment selection.

## Engineering changes

An explicit enabled_protocols startup allowlist prevents disabled transport factories, hole-punch state and NAT workers from being constructed. Listeners and bootstrap peers must use an enabled protocol. Optional inner-IP proxy state and flow-cache storage are demand-driven.

QUIC GRO receive scratch starts with one complete coalesced slot and doubles under observed batch pressure up to the unchanged maximum. For a 1500-byte, 64-segment, 32-slot configuration this changes initial scratch from 3,072,000 to 96,000 bytes per endpoint. Active traffic retains the existing maximum batching capability. Spare scratch is released after the endpoint connections drain.

Configuration differences are generated from the protobuf schema at build time. Normal dumping avoids loading runtime reflection descriptors or constructing complete default/current dynamic-message maps. Tests compare every supported field against the original reflected output, including explicit false, optional zero, list values, known and unknown enum numbers.

## Cold-process results

Each value below is the median of two observed run peaks. These tests have one loopback listener, no peer and no assigned IP/TUN, with two seconds settling followed by three seconds of 250 ms sampling.

| Host | Protocol | Q8 RSS MiB | M11 RSS MiB | Q8 physical footprint MiB | M11 physical footprint MiB |
|---|---|---:|---:|---:|---:|
| osku | quic | 22.445 | 20.023 | 10.657 | 8.626 |
| osku | tcp | 21.773 | 19.141 | 10.337 | 8.204 |
| osku | wss | 21.820 | 19.242 | 10.313 | 8.235 |
| UTM | quic | 23.186 | 14.717 | unavailable | unavailable |
| UTM | tcp | 16.475 | 13.598 | unavailable | unavailable |
| UTM | wss | 16.449 | 13.619 | unavailable | unavailable |

## Matched public-WAN throughput and memory

Upload is osku to UTM; download is UTM to osku. One inner TCP flow, MTU 1280, three seconds warmup and fifteen seconds measurement, two repetitions. Bootstrap uses the same selected transport as the measured data. Throughput and CPU/Gbit are medians; RSS is the maximum observed across the two runs.

| Protocol | Direction | Q8 to M11 Mbit/s | osku RSS Q8 to M11 MiB | UTM RSS Q8 to M11 MiB | osku CPU s/Gbit Q8 to M11 | UTM CPU s/Gbit Q8 to M11 |
|---|---|---:|---:|---:|---:|---:|
| quic | up | 725.11 to 797.79 | 35.97 to 35.75 | 36.40 to 32.08 | 0.884 to 1.078 | 1.887 to 1.809 |
| quic | down | 529.76 to 529.27 | 35.11 to 35.20 | 35.92 to 31.25 | 0.757 to 0.851 | 1.549 to 1.559 |
| tcp | up | 634.30 to 467.19 | 36.28 to 35.55 | 28.30 to 27.39 | 0.431 to 0.427 | 1.980 to 1.564 |
| tcp | down | 476.09 to 421.02 | 36.11 to 34.88 | 28.98 to 28.60 | 0.568 to 0.583 | 1.176 to 1.330 |
| wss | up | 493.74 to 649.43 | 34.70 to 32.95 | 39.12 to 36.49 | 0.435 to 0.549 | 1.543 to 2.141 |
| wss | down | 393.58 to 422.60 | 33.50 to 32.31 | 28.98 to 35.75 | 0.564 to 0.620 | 1.719 to 1.611 |

## Reused-connection QUIC validation

Four consecutive 60-second transfers share one established connection. Full steady-window CPU accounting is used.

| Direction | Receiver Mbit/s | osku RSS peak MiB | UTM RSS peak MiB |
|---|---:|---:|---:|
| down | 457.24 | 34.98 | 31.36 |
| down | 458.93 | 35.31 | 43.57 |
| up | 519.72 | 34.94 | 27.11 |
| up | 623.02 | 35.30 | 44.88 |

## Configuration-only control

M10 and M11 differ here only in generated configuration differences. Both use the same QUIC-only localhost configuration; logging is deliberately off or info. Each cell contains two reversed-order repetitions.

| Build | Logging | RSS peak median MiB | Physical footprint peak median MiB |
|---|---|---:|---:|
| memory10 | off | 21.898 | 10.071 |
| memory10 | info | 22.211 | 10.110 |
| memory11 | off | 20.008 | 8.618 |
| memory11 | info | 20.328 | 8.618 |

## Using a single protocol

```toml
[flags]
default_protocol = "quic"
enabled_protocols = ["quic"]
```

Use matching QUIC listeners, mapped listeners and bootstrap peers. For H2 use tcp; for WSS use wss. Restart after changing the allowlist. Omitting the list retains the earlier all-protocol compatibility behavior.

## Selection and remaining work

M11 is installed on both test machines with QUIC as the sole enabled data transport. Q8 backups remain available. Matched QUIC upload increased from 725.11 to 797.79 Mbit/s, download stayed approximately 529 Mbit/s, and all four 60-second sequential transfers passed 400 Mbit/s. H2 throughput regressed, so the Q8 archive remains the reference for H2. CPU/Gbit did not improve uniformly.

Resident UTM bootstrap connectivity remains incomplete. A bounded rollback to Q8 with its original configuration also returned no authenticated peers; M11 was restored. osku has authenticated QUIC peers. These checks do not establish resident-pair delivery or identify the bootstrap failure cause.

Shared routing, authentication, TLS primitives, management and runtime state still consume memory. The universal executable still includes supported transport code. Compile-time transport-specific builds and a matched WireGuard measurement are separate remaining work. No WireGuard-equivalent footprint is claimed.

## Verification and evidence

248 distinct LowTier tests passed, with the Caddy shared-port integration and both optimized target builds. Raw receiver bytes, authenticated direct paths, stable connection IDs and binary/source hashes were independently checked.

benchmark-results/protocol-memory-20260923/final11

Runtime/fixture verification:

Both installed core/CLI hashes and the loaded process identities were checked. The final UTM process after the rollback control is PID 5577. Benchmark core PID files, the test TUN and local test listeners were absent. Two hash-verified cold-test executable copies were removed from UTM scratch storage; this cleanup is separate from application footprint savings. Raw measurements, scripts and archived baseline binaries remain. The pre-existing shared STUN fixture was left untouched.

## Commit identities

Runtime transport isolation: `ab9936b598789846f71df6356e43193b96a5f393`. Demand-sized QUIC scratch: `c82c2c091a414e4d397f40a39e5b3e1ae3f72274`. Typed config differences: `35fbd1f5ff069092be5d22a3bd1bb39c57e7f503`.
