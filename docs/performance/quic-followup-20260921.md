# LowTier QUIC/TCP recovery follow-up — 2026-09-21

Report generated: 2026-09-21T21:00:36+09:00. Source base: `1547eb18f340a7067ef24b85daf9b40a321abbad`.

## Acceptance status

The complete goal has not been met in the measured matrix. The table below is the full final matrix, including slower cases. Lower measured daemon CPU/RSS against the operational Tailscale reference does not establish an equal-peer-count minimum-footprint result. Each row is one 20-second transfer; small differences do not establish statistical superiority.

## Retained changes

`vendor/smoltcp/src/socket/tcp.rs`: bound total unacknowledged data by both the peer window and congestion window in readiness and packet construction. ACK-only dispatch cannot smuggle new payload past the congestion limit. Sequence-wrap, partial-window, and full-window retransmission regressions cover the repaired behavior.

`vendor/smoltcp/src/socket/tcp/congestion/reno.rs`: ignore zero-byte ACKs for growth, cap slow-start growth at one MSS per ACK, accumulate newly ACKed bytes for one MSS of congestion-avoidance growth per window, retain the loss threshold, and reset ACK credit on retransmission. The added state is one usize; no heap allocation or floating point.

The TCP RTT estimator now cancels ambiguous samples for both retransmission paths; only a real retransmission timeout doubles RTO. The original minimum/maximum RTO, timeout backoff, and congestion response remain in place. The regression first reproduced 2000 ms after fast retransmission where 1000 ms was expected.

The TCP sender also accepts a conservative SACK loss hint despite an advertised-window update: a negotiated, valid in-flight contiguous block must cover more than two MSS above the cumulative ACK. This reuses the existing duplicate-ACK state and scans at most three blocks. It is a limited loss detector, not a complete RFC 6675 scoreboard. Invalid, unnegotiated, insufficient, and sequence-wrapped cases are tested. All ranges use unsigned offsets anchored at the cumulative ACK; this rejects cyclic serial-order counterexamples from spans larger than half the sequence space. The initial hint implementation failed that new socket regression and was hardened before this candidate. SACKed bytes remain buffered until cumulatively acknowledged.

`vendor/quinn-proto/src/connection/pacing.rs`: credit and clamp elapsed idle time before spending existing tokens, preventing two full bursts at one timestamp. Packets sharing a batch timestamp retain a short comparison path. Explicit-rate and window-derived pacing are both covered. The measured isolated pacing change did not materially improve upload; its retained value is the repaired token-bucket invariant.

`lowertier/src/gateway/tokio_smoltcp/reactor.rs`: test-only fixture correction. The batching test now models cumulative peer ACKs and negotiates an MSS that permits four segments in the initial window. It still checks four-packet batches and all 16384 payload bytes. Runtime batching behavior was not weakened for the test.

## Rejected experiment and unchanged constraints

The BBR alias experiment is preserved as the `paced` binaries and raw results. It did not solve upload and regressed four-flow performance; the source uses CUBIC. No plaintext mode, congestion-control bypass, fixed unlimited window, reliable-stream substitution for QUIC DATAGRAM, production service replacement, or alternate test NIC was used.

## Test path and accounting

LowTier payload: yutoms `en1` / `172.25.23.12` → direct IPv4 public endpoint `58.147.228.119` → Hattori `pppoe-bbd` (MTU 1396). The NAT witness is `133.1.22.2`; UDP 15392 is QUIC, TCP 15390 is H2, and TCP 15393 is WSS. Both endpoints are checked before/during/after each transfer; peer cost, next hop, single-connection addresses, route, and payload packet witnesses are retained. SSH management uses Tailscale; LowTier payload uses the direct public transport.

Daemon user+system CPU over the full sample window, including 4-second padding and management/RPC activity. Tailscale includes its loopback adapter. iperf and kernel work charged outside these processes are excluded.

Operational baseline: existing Tailscale daemons serve additional peers; LowTier is an isolated two-peer instance. This does not establish equal-peer-count minimum RSS. Management SSH uses Tailscale; LowTier benchmark payload uses only the direct public endpoint.

CPU is reported as process CPU seconds per delivered Gbit. RSS is the median of process samples, in MiB. Peer/background overhead and the sampling padding are included as documented. No system-wide energy or IRQ-inclusive CPU superiority is claimed. No final p99 end-to-end latency benchmark was collected.

The fresh Tailscale reference uses the same physical path. Its audited temporary peer-UDP return-route lease was verified restored. Existing Tailscale services were retained. Intermediate QUIC diagnostics with warning logs and header capture are kept separately and excluded from the final performance table.

## Final complete matrix

| Version / transport | Streams | Direction | Receiver Mbit/s | CPU s/Gbit yutoms | CPU s/Gbit Hattori | RSS MiB yutoms | RSS MiB Hattori |
|---|---:|---|---:|---:|---:|---:|---:|
| guarded / quic | 1 | up | 22.953 | 7.51 | 17.31 | 35.12 | 28.77 |
| guarded / quic | 1 | down | 24.378 | 6.07 | 18.25 | 36.03 | 28.94 |
| guarded / quic | 4 | up | 22.355 | 6.77 | 18.49 | 36.98 | 29.05 |
| guarded / quic | 4 | down | 24.378 | 6.58 | 18.13 | 37.22 | 29.06 |
| guarded / h2 | 1 | up | 25.468 | 2.35 | 6.05 | 34.83 | 25.15 |
| guarded / h2 | 1 | down | 26.468 | 4.10 | 9.91 | 35.56 | 35.34 |
| guarded / h2 | 4 | up | 25.968 | 2.36 | 7.94 | 58.47 | 35.72 |
| guarded / h2 | 4 | down | 26.469 | 4.76 | 11.05 | 58.80 | 35.32 |
| guarded / wss | 1 | up | 25.819 | 1.93 | 6.61 | 36.09 | 22.59 |
| guarded / wss | 1 | down | 26.306 | 4.10 | 9.99 | 44.48 | 22.13 |
| guarded / wss | 4 | up | 26.462 | 2.07 | 8.61 | 56.73 | 22.46 |
| guarded / wss | 4 | down | 26.257 | 4.68 | 10.68 | 56.78 | 22.33 |
| tailscale / tailscale | 1 | up | 26.244 | 14.49 | 20.94 | 236.81 | 130.87 |
| tailscale / tailscale | 1 | down | 26.734 | 16.40 | 24.25 | 236.97 | 130.87 |
| tailscale / tailscale | 4 | up | 26.243 | 16.62 | 24.17 | 237.14 | 130.87 |
| tailscale / tailscale | 4 | down | 26.680 | 20.24 | 29.15 | 237.17 | 130.87 |

## UDP underlay diagnostic

A separate source-bound 1200-byte UDP test on the same public QUIC port delivered 24.981 Mbit/s with zero loss at an offered 25 Mbit/s. At an offered 30 Mbit/s it delivered 29.064 Mbit/s with 3.037% loss. These are raw underlay diagnostics, not encrypted LowTier throughput or CPU results.

## Validation and reproducibility

`tcp-final-after-tests.log`: 189 passed, zero failed.
`quinn-final-tests.log`: 285 passed, zero failed.
`userspace-verified-tests.log`: 5 passed, zero failed.
`quic-verified-tests.log`: 31 passed, zero failed.
`h2-verified-tests.log`: 5 passed, zero failed.
`wss-verified-tests.log`: 4 passed, zero failed.

The nine direct-path gate tests also passed. The optional external Caddy-L4 test was not run in this follow-up: CADDY_BIN is unset and caddy is absent from PATH. The ordinary QUIC/H2/WSS security and routing tests above did run. Compiler warnings already present in the workspace remain.

Exact compiler commands, environment setup, logs, process IDs and exit status are retained in `benchmark-results/.work/quic-followup-20260921.jsonl`, `build.py`, and the per-build receipts. Initial SDK selection and the first count-bounded inner capture failed; both were recovered with explicit SDK paths and a timed capture that preserves partial output. Demonstrated failing regressions are preserved in the `*-before-tests.log` files.

`followup-only.patch` is relative to the source snapshots at this task’s start, so preexisting user changes are excluded. `final-source/` preserves the measured source; `manifest.json` preserves both endpoint binary SHA256s. The reproducible entry points are `build.py`, `run.py`, and this `report.py` under `benchmark-results/quic-followup-20260921/`.

### Measured binary SHA256

yutoms: `f2eefb5b3fd1df1e4418832ab6968c67065d21b3fe16f5392f9d154e75772cc5` (`/tmp/lt-direct-repair-20260921/core-guarded`).
hattori: `7907082c5f0ba4c142bcaac0cbde94a5f6e197fd7a08d56a6be8902c27ada470` (`/tmp/lt-direct-repair-20260921/core-guarded`).

### Measured source SHA256

`vendor/smoltcp/src/socket/tcp.rs`: `518fed085d371b8b0b9ff56dfda00537be71f9b8c6b1cf2adde79fe57c22e676`.
`vendor/smoltcp/src/socket/tcp/congestion/reno.rs`: `23577ab60f1ef45252f70b54a49af21d1c221e38eb2eeebf2cd21d37bc9bfb11`.
`vendor/quinn-proto/src/connection/pacing.rs`: `97e0aa919361029dbee858df35abfd31ca25e108faa0b89c30ef45a89899caa2`.
`lowertier/src/tunnel/quic/tunnel_cc.rs`: `76e0a811b56e238fdf66ea8b429f0a3220e989d1a55452786c4d8418d3428b71`.
`lowertier/src/gateway/tokio_smoltcp/reactor.rs`: `db109679dd7d4ea949e897c3507ca2fd71ce13322d0d1081a5a2a50e73ad986a`.

### Protocol references

RFC 5681 §3.1 (congestion-window accounting and growth); RFC 6298 §§3,5 (Karn sampling and timeout backoff); RFC 6675 §§2,4 (SACK loss evidence). The SACK change is the conservative single-block detection subset described above; full SACK-based retransmission scheduling remains a separate task.
