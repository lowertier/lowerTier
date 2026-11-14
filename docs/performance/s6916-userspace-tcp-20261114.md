# s6916 TCP speed repair, November 14, 2026

The userspace TCP endpoint on `10.126.126.60` caused slow and variable downloads.
The node now uses the Linux kernel interface.
The final two download trials delivered 451.0 and 451.3 Mbit/s.
The final two upload trials delivered 393.6 and 413.5 Mbit/s.
These results apply to the local Mac at `10.126.126.2` and s6916.

The running application binary did not change.
The node retains its instance ID, network identity, keys, ACLs, routes, and Web UI policy.
Only `tun.mode` and `tun.mtu` changed semantically.
The retained configuration selects kernel mode and a configured MTU of 1280.
The resulting Linux TAP interface has an observed MTU of 1260.
QUIC, H2, and WSS remain available.

## Evidence

Each TCP trial used one stream, two warmup seconds, and ten measurement seconds.
Rates use receiver bytes and receiver duration.
The client used iperf 3.22.
The server used the installed iperf 3.9.
Both endpoint versions remained constant across the comparisons.

| Configuration | Direction | Trials | Receiver Mbit/s |
| --- | --- | ---: | --- |
| Public address `193.32.149.82` | Upload | 1 | 489.5 |
| Public address `193.32.149.82` | Download | 1 | 495.2 |
| Original userspace node, automatic transport selection | Upload | 2 | 439.9, 432.6 |
| Original userspace node, automatic transport selection | Download | 2 | 131.2, 27.8 |
| Kernel node, QUIC enforced by startup arguments | Download | 2 | 457.2, 459.0 |
| Userspace node, QUIC enforced by startup arguments | Download | 2 | 244.1, 144.6 |
| Final kernel node, all transports available | Download | 2 | 451.0, 451.3 |
| Final kernel node, all transports available | Upload | 2 | 393.6, 413.5 |

The original slow trials carried their bulk traffic over direct QUIC.
They did not use a relay.
The final download trials used WSS and QUIC, respectively.
The final upload trials used QUIC.
Connection byte counters establish these transport observations.
The final upload trials were slower than the original userspace upload trials.
Kernel mode resolves the reported download collapse while retaining approximately 400 Mbit/s upload.
The repair does not establish a throughput improvement in both directions.

The enforced QUIC comparison used the same configured MTU of 1280.
The userspace TCP device uses an effective MTU of 1280.
The final Linux TAP interface uses 1260.
The public interface uses 1500.
These measurements do not establish exact MTU parity.
They compare the complete endpoint paths.

## Cause and cost

The userspace node terminates overlay TCP in smoltcp.
It bridges each application connection through a separate kernel loopback connection.
The userspace path adds TCP packet construction, acknowledgement processing, buffer management, and copies.
The native path lets Linux TCP serve the overlay address through TAP.

At 500 Mbit/s and a 12 ms RTT, the payload flight requirement is approximately 750,000 bytes.
With a 1220-byte payload, the sender processes approximately 51,200 data packets each second.
The userspace sockets start with 16 KiB buffers.
The buffers grow from measured demand and RTT under the process memory governor.
The current userspace build selects CUBIC.
The Linux host selects BBR.

CPU samples do not show saturation as the cause of the original 27.8 Mbit/s result.
Changing the complete TCP endpoint path consistently improved download speed.
The measurements do not isolate one congestion controller, buffer rule, or loss recovery defect.
No repair to the underlying userspace TCP implementation is claimed.

Relevant source:

- `lowertier/src/gateway/tcp_proxy.rs`: userspace TCP device, initial buffers, and loopback service connection.
- `lowertier/src/gateway/tokio_smoltcp/tcp_buffers.rs`: buffer growth and memory accounting.
- `vendor/smoltcp/src/socket/tcp/congestion.rs`: default congestion controller selection.
- `lowertier/src/tunnel/quic.rs`: QUIC congestion control, pacing, and datagram queue bounds.

## Delivery, latency, and resources

The final node passed exact byte-pattern checks for 64 MiB uploads and downloads.
Each final loaded trial returned all 14 ICMP probes.
The final idle check returned all ten probes.
Idle RTT averaged 12.337 ms.

| Final trial | Mean / maximum loaded RTT, ms | Kernel TCP retransmissions | s6916 sampled RSS, MiB |
| --- | --- | ---: | --- |
| Download 1, WSS | 33.292 / 82.701 | 272 | 40.6–45.4 |
| Download 2, QUIC | 12.352 / 17.812 | 10430 | 43.4–47.3 |
| Upload 1, QUIC | 11.853 / 13.962 | 1 | 43.5–44.6 |
| Upload 2, QUIC | 14.053 / 26.987 | 0 | 43.7–45.6 |

Retransmissions are sender TCP counters.
The userspace trial counters describe the separate loopback leg.
They do not count userspace overlay TCP retransmissions.
Outer QUIC loss and retransmission totals were not instrumented.
ICMP delivery does not establish zero bulk packet loss.

Resource sampling covered approximately 15 seconds, including warmup and collection time.
CPU values include LowTier process user and system time.
One logical core corresponds to 100 percent.
The following CPU costs divide the full observation window by measured receiver payload Gbit.
They exceed transfer-only CPU costs.

| Final trial | Local CPU seconds / Gbit | s6916 CPU seconds / Gbit |
| --- | ---: | ---: |
| Download 1 | 1.07 | 1.55 |
| Download 2 | 1.51 | 3.07 |
| Upload 1 | 1.37 | 4.27 |
| Upload 2 | 1.31 | 4.04 |

Remote RSS includes shared pages and excludes kernel memory.
The local sampler used macOS `top MEM`; those samples are not reported as RSS.
A separate final local RSS snapshot measured 83,904 KiB.
No WireGuard efficiency comparison is claimed.

## Deployment and recovery

The retained service remains enabled and active.
The running executable matches the installed binary.
The final peer snapshot contains authenticated QUIC, H2, and WSS connections.
The Web UI page and API accept the approved overlay source without a key.
The API rejects a foreign Origin with HTTP 403.
The three approved source subnets remain configured.

Temporary protocol settings encountered argument and configuration validation errors.
Some staged settings were absent after restart.
The control portal also needed time to become available after restart.
Initial readiness probes encountered stale routes.
Startup overrides and full-delivery readiness checks enabled the enforced QUIC comparison.
The staged-setting behavior remains unresolved.

A textual preservation check detected formatting and field-order differences.
A field comparison confirmed that only `tun.mode` and `tun.mtu` changed semantically.
The temporary service override and task-owned servers were removed.
The original iperf server on port 5201 remains untouched.
The original configuration remains in a protected reference file on s6916.
No replacement or backup executable was created.

Complete local evidence is in `benchmark-results/.work/s6916-speed-20261114/`.
The entry points are `summary.json`, `result.json`, and `audit.jsonl`.
Raw trial records include commands, working directories, timestamps, process IDs, output, and exit codes.
Rejected settings and failed readiness checks remain in the audit.
Trial names beginning with `strict-` identify the enforced QUIC comparison.
Earlier names containing `quic` do not establish transport enforcement.
Their connection counters retain the actual observations.
The initial broad filename search had truncated output without a complete local record.

The implementation source did not change.
Library and Caddy tests were not repeated because this repair changed node configuration and documentation.
Validation covered the affected service, authenticated transports, byte delivery, Web UI access, and measured TCP paths.
The trials do not establish long-term availability or performance for other fleet pairs.
