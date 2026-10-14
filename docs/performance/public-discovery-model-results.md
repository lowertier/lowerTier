# Public discovery model results

Date: 2026-09-11 (Asia/Tokyo).

**Simulation results. No Internet traffic or production networking code was executed.**

Source SHA-256: `5b8dc2b03fd2e7154fe1ab5926bd64971f8991d05cc4c1c9db55ba6cd80da4f3`. Compiler: `rustc 1.100.0-nightly (908501772 2026-08-30)`.

Cases per seed: 156. Retained runs: 3. Total modeled sessions: 4,680,000.

The successful-check time is the first authenticated-probe/ACK round trip in the model. It excludes transport establishment. Traffic includes both nodes and service responses, DNS assumptions, and peer probes; WAN and LAN are separate. IP-layer bytes exclude Ethernet/Wi-Fi and final transport handshakes. HTTP/TLS byte counts are assumed budgets. These historical results came from an offline model that is no longer maintained in this repository.

## Primary seed results

Percentiles below use successful sessions only. Every row separately reports the success fraction within five seconds. An unconditional 95th percentile is outside the decision window whenever more than 5% of sessions fail.

### open_simultaneous

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 100.00% | 209.653 | 260.103 | 351.505 | 1822.99 | 248.00 |
| udp2 | 100.00% | 175.717 | 226.611 | 314.517 | 2822.16 | 248.00 |
| udp4 | 100.00% | 154.550 | 205.082 | 273.889 | 4740.15 | 248.00 |
| udp8 | 100.00% | 140.028 | 190.507 | 242.696 | 8508.62 | 248.00 |
| hedge4 | 100.00% | 217.955 | 268.265 | 392.883 | 4062.01 | 248.00 |
| mixed4 | 100.00% | 175.717 | 226.611 | 314.517 | 10618.83 | 248.00 |
| mixed6 | 100.00% | 218.153 | 268.280 | 394.251 | 4344.10 | 248.00 |
| lan150_mixed4 | 100.00% | 325.717 | 376.611 | 464.517 | 10618.83 | 248.00 |
| lan250_mixed4 | 100.00% | 425.717 | 476.611 | 564.517 | 10618.83 | 248.00 |
| udp4_p100 | 100.00% | 154.550 | 205.082 | 273.889 | 4607.46 | 248.00 |
| hedge4_p100 | 100.00% | 217.955 | 268.265 | 392.883 | 3946.31 | 248.00 |
| mixed6_p100 | 100.00% | 218.153 | 268.280 | 394.251 | 4227.61 | 248.00 |
| lan250_hedge4_p100 | 100.00% | 467.955 | 518.265 | 642.883 | 3946.31 | 248.00 |

### restricted_simultaneous

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | 209.653 | NA | NA | 2190.00 | 248.00 |
| udp2 | 32.85% | 175.717 | 285.336 | 354.003 | 3099.39 | 248.00 |
| udp4 | 58.98% | 154.550 | 252.513 | 336.455 | 4942.06 | 248.00 |
| udp8 | 77.10% | 140.028 | 223.968 | 318.000 | 8646.76 | 248.00 |
| hedge4 | 97.08% | 217.955 | 440.858 | 601.191 | 4871.61 | 248.00 |
| mixed4 | 79.51% | 175.717 | 462.615 | 696.178 | 15228.73 | 248.00 |
| mixed6 | 98.98% | 218.153 | 441.285 | 617.010 | 9623.28 | 248.00 |
| lan150_mixed4 | 79.51% | 325.717 | 612.615 | 846.178 | 15228.73 | 248.00 |
| lan250_mixed4 | 79.51% | 425.717 | 712.615 | 946.178 | 15228.73 | 248.00 |
| udp4_p100 | 58.98% | 154.550 | 255.329 | 335.555 | 4805.48 | 248.00 |
| hedge4_p100 | 97.08% | 217.955 | 441.496 | 601.633 | 4705.87 | 248.00 |
| mixed6_p100 | 98.98% | 218.153 | 442.826 | 617.448 | 9487.87 | 248.00 |
| lan250_hedge4_p100 | 97.08% | 467.955 | 691.496 | 851.633 | 4705.87 | 248.00 |

### restricted_skew_2s

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | 196.495 | NA | NA | 2190.00 | 248.00 |
| udp2 | 0.54% | 162.436 | 281.168 | 332.163 | 3119.62 | 248.00 |
| udp4 | 0.99% | 140.361 | 250.525 | 323.097 | 4979.45 | 248.00 |
| udp8 | 1.34% | 125.845 | 224.556 | 317.729 | 8699.14 | 248.00 |
| hedge4 | 10.65% | 165.556 | 370.550 | 541.446 | 4962.20 | 248.00 |
| mixed4 | 4.49% | 162.436 | 484.612 | 671.735 | 16350.52 | 248.00 |
| mixed6 | 10.80% | 164.618 | 374.478 | 575.581 | 17308.18 | 248.00 |
| lan150_mixed4 | 4.49% | 312.436 | 634.612 | 821.735 | 16350.52 | 248.00 |
| lan250_mixed4 | 4.49% | 412.436 | 734.612 | 921.735 | 16350.52 | 248.00 |
| udp4_p100 | 0.99% | 140.361 | 250.525 | 323.097 | 4886.68 | 248.00 |
| hedge4_p100 | 10.65% | 165.556 | 372.269 | 537.487 | 4862.33 | 248.00 |
| mixed6_p100 | 10.80% | 164.618 | 376.464 | 578.377 | 17215.99 | 248.00 |
| lan250_hedge4_p100 | 10.65% | 415.556 | 622.269 | 787.487 | 4862.33 | 248.00 |

### open_skew_2s

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 100.00% | 196.495 | 246.973 | 340.394 | 1822.99 | 248.00 |
| udp2 | 100.00% | 162.436 | 213.578 | 301.668 | 2754.21 | 248.00 |
| udp4 | 100.00% | 140.361 | 191.054 | 263.264 | 4614.54 | 248.00 |
| udp8 | 100.00% | 125.845 | 176.328 | 232.870 | 8332.93 | 247.99 |
| hedge4 | 100.00% | 165.556 | 216.742 | 308.212 | 4145.05 | 248.00 |
| mixed4 | 100.00% | 162.436 | 213.578 | 301.629 | 12893.26 | 248.00 |
| mixed6 | 100.00% | 164.618 | 215.731 | 308.324 | 9875.06 | 248.00 |
| lan150_mixed4 | 100.00% | 312.436 | 363.578 | 451.629 | 12893.26 | 248.00 |
| lan250_mixed4 | 100.00% | 412.436 | 463.578 | 551.629 | 12893.26 | 248.00 |
| udp4_p100 | 100.00% | 140.361 | 191.054 | 263.264 | 4520.77 | 248.00 |
| hedge4_p100 | 100.00% | 165.556 | 216.742 | 308.212 | 4048.65 | 248.00 |
| mixed6_p100 | 100.00% | 164.618 | 215.731 | 308.324 | 9778.72 | 248.00 |
| lan250_hedge4_p100 | 100.00% | 415.556 | 466.742 | 558.212 | 4048.65 | 248.00 |

### warm_restricted

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | 146.242 | NA | NA | 1214.00 | 248.00 |
| udp2 | 9.03% | 130.592 | 197.218 | 243.348 | 1560.64 | 248.00 |
| udp4 | 17.28% | 119.676 | 183.250 | 233.784 | 2262.14 | 248.00 |
| udp8 | 23.68% | 112.112 | 170.820 | 226.438 | 3673.22 | 247.99 |
| hedge4 | 95.83% | 151.028 | 316.322 | 473.738 | 2194.74 | 248.00 |
| mixed4 | 73.16% | 130.592 | 417.232 | 484.624 | 4036.25 | 248.00 |
| mixed6 | 98.64% | 150.786 | 319.864 | 487.378 | 2674.50 | 248.00 |
| lan150_mixed4 | 73.16% | 280.592 | 567.232 | 634.624 | 4036.25 | 248.00 |
| lan250_mixed4 | 73.16% | 380.592 | 667.232 | 734.624 | 4036.25 | 248.00 |
| udp4_p100 | 17.28% | 119.676 | 184.094 | 238.780 | 2156.13 | 248.00 |
| hedge4_p100 | 95.83% | 151.028 | 316.864 | 472.396 | 2046.78 | 248.00 |
| mixed6_p100 | 98.64% | 150.786 | 319.672 | 485.838 | 2527.89 | 248.00 |
| lan250_hedge4_p100 | 95.83% | 401.028 | 566.864 | 722.396 | 2046.78 | 248.00 |

### outage20_loss2

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 68.61% | 215.086 | 266.268 | 356.709 | 1652.62 | 248.00 |
| udp2 | 90.38% | 195.056 | 247.424 | 344.357 | 2570.19 | 248.00 |
| udp4 | 99.10% | 170.094 | 223.586 | 314.318 | 4296.70 | 248.00 |
| udp8 | 99.99% | 150.073 | 203.123 | 283.274 | 7650.24 | 248.00 |
| hedge4 | 99.07% | 257.043 | 308.908 | 516.738 | 3895.27 | 248.00 |
| mixed4 | 99.58% | 203.051 | 255.236 | 518.213 | 11498.11 | 248.00 |
| mixed6 | 99.96% | 257.642 | 309.875 | 529.884 | 5418.24 | 248.00 |
| lan150_mixed4 | 99.58% | 353.051 | 405.236 | 668.213 | 11498.11 | 248.00 |
| lan250_mixed4 | 99.58% | 453.051 | 505.236 | 768.213 | 11498.11 | 248.00 |
| udp4_p100 | 99.10% | 170.094 | 223.886 | 318.886 | 4182.78 | 248.00 |
| hedge4_p100 | 99.07% | 257.043 | 309.993 | 520.746 | 3794.36 | 248.00 |
| mixed6_p100 | 99.96% | 257.642 | 311.582 | 532.714 | 5356.32 | 248.00 |
| lan250_hedge4_p100 | 99.07% | 507.043 | 559.993 | 770.746 | 3794.36 | 248.00 |

### restricted_outage20_loss2

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | 215.086 | NA | NA | 1904.05 | 248.00 |
| udp2 | 14.65% | 195.056 | 289.146 | 357.080 | 2861.21 | 248.00 |
| udp4 | 39.85% | 170.094 | 270.012 | 348.029 | 4550.10 | 248.00 |
| udp8 | 63.48% | 150.073 | 242.807 | 335.418 | 7836.17 | 248.00 |
| hedge4 | 71.21% | 257.043 | 479.497 | 622.792 | 4524.32 | 248.00 |
| mixed4 | 62.95% | 203.051 | 524.098 | 726.881 | 15171.03 | 248.00 |
| mixed6 | 88.94% | 257.642 | 513.331 | 926.785 | 12233.02 | 248.00 |
| lan150_mixed4 | 62.95% | 353.051 | 674.098 | 876.881 | 15171.03 | 248.00 |
| lan250_mixed4 | 62.95% | 453.051 | 774.098 | 976.881 | 15171.03 | 248.00 |
| udp4_p100 | 39.84% | 170.094 | 272.699 | 351.486 | 4431.27 | 248.00 |
| hedge4_p100 | 71.30% | 257.043 | 481.785 | 626.540 | 4382.19 | 248.00 |
| mixed6_p100 | 88.93% | 257.642 | 514.617 | 930.870 | 12131.47 | 248.00 |
| lan250_hedge4_p100 | 71.30% | 507.043 | 731.785 | 876.540 | 4382.19 | 248.00 |

### tracker_udp_blocked

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | NA | NA | NA | 1104.00 | 248.00 |
| udp2 | 0.00% | NA | NA | NA | 1592.00 | 248.00 |
| udp4 | 0.00% | NA | NA | NA | 2568.00 | 248.00 |
| udp8 | 0.00% | NA | NA | NA | 4520.00 | 248.00 |
| hedge4 | 0.00% | NA | NA | NA | 2568.00 | 248.00 |
| mixed4 | 100.00% | 448.375 | 498.068 | 614.128 | 14926.98 | 248.00 |
| mixed6 | 100.00% | 750.467 | 800.348 | 913.129 | 15910.25 | 248.00 |
| lan150_mixed4 | 100.00% | 598.375 | 648.068 | 764.128 | 14926.98 | 248.00 |
| lan250_mixed4 | 100.00% | 698.375 | 748.068 | 864.128 | 14926.98 | 248.00 |
| udp4_p100 | 0.00% | NA | NA | NA | 2568.00 | 248.00 |
| hedge4_p100 | 0.00% | NA | NA | NA | 2568.00 | 248.00 |
| mixed6_p100 | 100.00% | 750.467 | 800.348 | 913.129 | 15793.32 | 248.00 |
| lan250_hedge4_p100 | 0.00% | NA | NA | NA | 2568.00 | 248.00 |

### all_udp_blocked

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | NA | NA | NA | 2056.00 | 248.00 |
| udp2 | 0.00% | NA | NA | NA | 2544.00 | 248.00 |
| udp4 | 0.00% | NA | NA | NA | 3520.00 | 248.00 |
| udp8 | 0.00% | NA | NA | NA | 5472.00 | 248.00 |
| hedge4 | 0.00% | NA | NA | NA | 3520.00 | 248.00 |
| mixed4 | 0.00% | NA | NA | NA | 13184.00 | 248.00 |
| mixed6 | 0.00% | NA | NA | NA | 14160.00 | 248.00 |
| lan150_mixed4 | 0.00% | NA | NA | NA | 13184.00 | 248.00 |
| lan250_mixed4 | 0.00% | NA | NA | NA | 13184.00 | 248.00 |
| udp4_p100 | 0.00% | NA | NA | NA | 3520.00 | 248.00 |
| hedge4_p100 | 0.00% | NA | NA | NA | 3520.00 | 248.00 |
| mixed6_p100 | 0.00% | NA | NA | NA | 14160.00 | 248.00 |
| lan250_hedge4_p100 | 0.00% | NA | NA | NA | 3520.00 | 248.00 |

### unpredictable_mapping

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 0.00% | 209.653 | NA | NA | 2190.00 | 248.00 |
| udp2 | 0.00% | 175.717 | NA | NA | 3331.55 | 248.00 |
| udp4 | 0.00% | 154.550 | NA | NA | 5359.83 | 248.00 |
| udp8 | 0.00% | 140.028 | NA | NA | 9196.52 | 248.00 |
| hedge4 | 0.00% | 217.955 | NA | NA | 5605.20 | 248.00 |
| mixed4 | 0.00% | 175.717 | NA | NA | 16884.04 | 248.00 |
| mixed6 | 0.00% | 218.153 | NA | NA | 18869.43 | 248.00 |
| lan150_mixed4 | 0.00% | 325.717 | NA | NA | 16884.04 | 248.00 |
| lan250_mixed4 | 0.00% | 425.717 | NA | NA | 16884.04 | 248.00 |
| udp4_p100 | 0.00% | 154.550 | NA | NA | 5213.57 | 248.00 |
| hedge4_p100 | 0.00% | 217.955 | NA | NA | 5423.88 | 248.00 |
| mixed6_p100 | 0.00% | 218.153 | NA | NA | 18686.37 | 248.00 |
| lan250_hedge4_p100 | 0.00% | 467.955 | NA | NA | 5423.88 | 248.00 |

### lan_registered

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 100.00% | 109.590 | 113.608 | 190.690 | 1463.37 | 768.17 |
| udp2 | 100.00% | 107.889 | 113.707 | 190.059 | 2305.45 | 762.82 |
| udp4 | 100.00% | 105.132 | 113.769 | 187.418 | 3983.02 | 755.95 |
| udp8 | 100.00% | 102.548 | 114.234 | 185.262 | 7327.43 | 748.25 |
| hedge4 | 100.00% | 109.235 | 113.557 | 190.282 | 2529.64 | 768.65 |
| mixed4 | 100.00% | 107.889 | 113.707 | 190.059 | 4679.96 | 762.82 |
| mixed6 | 100.00% | 109.709 | 113.613 | 189.715 | 2525.35 | 768.98 |
| lan150_mixed4 | 100.00% | 111.528 | 113.528 | 188.470 | 726.67 | 776.12 |
| lan250_mixed4 | 100.00% | 111.528 | 113.528 | 188.470 | 63.59 | 776.14 |
| udp4_p100 | 100.00% | 105.132 | 113.769 | 192.469 | 3976.87 | 745.37 |
| hedge4_p100 | 100.00% | 109.235 | 113.557 | 192.133 | 2537.96 | 764.25 |
| mixed6_p100 | 100.00% | 109.709 | 113.613 | 191.750 | 2534.14 | 764.70 |
| lan250_hedge4_p100 | 100.00% | 111.528 | 113.528 | 188.470 | 63.65 | 776.14 |

### cached_peer

| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |
|---|---:|---:|---:|---:|---:|---:|
| udp1 | 100.00% | 0.000 | 50.366 | 76.944 | 1902.08 | 182.78 |
| udp2 | 100.00% | 0.000 | 50.366 | 76.944 | 2634.58 | 182.78 |
| udp4 | 100.00% | 0.000 | 50.366 | 76.944 | 4101.63 | 182.78 |
| udp8 | 100.00% | 0.000 | 50.366 | 76.944 | 7033.30 | 182.78 |
| hedge4 | 100.00% | 0.000 | 50.366 | 76.944 | 2666.82 | 182.78 |
| mixed4 | 100.00% | 0.000 | 50.366 | 76.944 | 3087.61 | 182.78 |
| mixed6 | 100.00% | 0.000 | 50.366 | 76.944 | 2668.26 | 182.78 |
| lan150_mixed4 | 100.00% | 0.000 | 50.366 | 76.944 | 674.52 | 182.78 |
| lan250_mixed4 | 100.00% | 0.000 | 50.366 | 76.944 | 553.99 | 182.78 |
| udp4_p100 | 100.00% | 0.000 | 50.366 | 76.944 | 3915.65 | 182.78 |
| hedge4_p100 | 100.00% | 0.000 | 50.366 | 76.944 | 2480.83 | 182.78 |
| mixed6_p100 | 100.00% | 0.000 | 50.366 | 76.944 | 2482.27 | 182.78 |
| lan250_hedge4_p100 | 100.00% | 0.000 | 50.366 | 76.944 | 368.00 | 182.78 |

## Replication: success across retained seeds

Wilson 95% intervals quantify Monte Carlo sampling uncertainty under this model. They do not bound Internet deployment uncertainty.

| Scenario | Policy | Success / sessions | Pooled success | Wilson 95% interval |
|---|---|---:|---:|---:|
| open_simultaneous | udp2 | 30000/30000 | 100.00% | 99.99–100.00% |
| open_simultaneous | udp4 | 30000/30000 | 100.00% | 99.99–100.00% |
| open_simultaneous | udp8 | 30000/30000 | 100.00% | 99.99–100.00% |
| open_simultaneous | hedge4 | 30000/30000 | 100.00% | 99.99–100.00% |
| open_simultaneous | mixed6 | 30000/30000 | 100.00% | 99.99–100.00% |
| open_simultaneous | hedge4_p100 | 30000/30000 | 100.00% | 99.99–100.00% |
| restricted_simultaneous | udp2 | 9720/30000 | 32.40% | 31.87–32.93% |
| restricted_simultaneous | udp4 | 17644/30000 | 58.81% | 58.26–59.37% |
| restricted_simultaneous | udp8 | 22923/30000 | 76.41% | 75.93–76.89% |
| restricted_simultaneous | hedge4 | 29003/30000 | 96.68% | 96.47–96.87% |
| restricted_simultaneous | mixed6 | 29648/30000 | 98.83% | 98.70–98.94% |
| restricted_simultaneous | hedge4_p100 | 29003/30000 | 96.68% | 96.47–96.87% |
| restricted_skew_2s | udp2 | 152/30000 | 0.51% | 0.43–0.59% |
| restricted_skew_2s | udp4 | 278/30000 | 0.93% | 0.82–1.04% |
| restricted_skew_2s | udp8 | 377/30000 | 1.26% | 1.14–1.39% |
| restricted_skew_2s | hedge4 | 3226/30000 | 10.75% | 10.41–11.11% |
| restricted_skew_2s | mixed6 | 3293/30000 | 10.98% | 10.63–11.34% |
| restricted_skew_2s | hedge4_p100 | 3226/30000 | 10.75% | 10.41–11.11% |
| outage20_loss2 | udp2 | 27211/30000 | 90.70% | 90.37–91.03% |
| outage20_loss2 | udp4 | 29757/30000 | 99.19% | 99.08–99.29% |
| outage20_loss2 | udp8 | 29994/30000 | 99.98% | 99.96–99.99% |
| outage20_loss2 | hedge4 | 29744/30000 | 99.15% | 99.04–99.24% |
| outage20_loss2 | mixed6 | 29990/30000 | 99.97% | 99.94–99.98% |
| outage20_loss2 | hedge4_p100 | 29744/30000 | 99.15% | 99.04–99.24% |

## Reverse-discovery polling bound

For an incumbent with k equally phased, healthy pull directories and an illustrative common interval I=1800 s, a uniformly arriving new node waits an average I/(2k), with maximum I/k, for the incumbent's next poll. This is an ideal lower-latency polling arrangement; it excludes network delay, record propagation, mapping lifetime, and the subsequent punching window. Increasing the initial race width cannot remove this steady-state wait.

| Trackers k | Ideal mean reverse wait (s) | Ideal maximum gap (s) | Minimum IPv4 tracker traffic per node per day (bytes) |
|---:|---:|---:|---:|
| 2 | 450.000 | 900.000 | 25152 |
| 4 | 225.000 | 450.000 | 50304 |
| 8 | 112.500 | 225.000 | 100608 |
| 16 | 56.250 | 112.500 | 201216 |
| 32 | 28.125 | 56.250 | 402432 |

The traffic column assumes an empty compact response and a fresh BEP-15 connect/announce exchange at every 30-minute poll. It excludes DNS, STUN upkeep, peer probes, nonempty responses, loss, and transport handshakes. Normal announce intervals are service-specific. A 30-minute interval is an input, rather than an assertion about all public trackers.

## Verification output

```text
running 17 tests
test tests::cached_endpoint_can_cancel_all_wan_discovery ... ok
test tests::authenticated_reply_avoids_redundant_probe_train ... ok
test tests::http_survives_tracker_only_udp_filtering ... ok
test tests::incoming_request_keeps_unacknowledged_checks_alive ... ok
test tests::cold_parallel_critical_path ... ok
test tests::inflight_wan_packet_keeps_its_original_path ... ok
test tests::nearest_rank_quantile_keeps_tail ... ok
test tests::one_pull_does_not_open_two_restricted_nats ... ok
test tests::incompatible_mapping_remains_unreachable ... ok
test tests::https_signaling_cannot_repair_blocked_udp ... ok
test tests::symmetric_arrival_order_can_defeat_eight_trackers ... ok
test tests::slower_retry_does_not_delay_the_first_probe ... ok
test tests::rng_and_outputs_are_reproducible ... ok
test tests::late_restricted_join_is_not_solved_by_a_startup_race ... ok
test tests::tracker_retry_respects_fifteen_seconds ... ok
test tests::wire_costs ... ok
test tests::warm_cookie_saves_rtt_when_mapping_is_ready ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The original implementation specification is no longer maintained in this repository.
