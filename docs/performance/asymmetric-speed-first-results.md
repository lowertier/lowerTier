# Asymmetric speed-first routing results

Test date: 2026-08-12 and 2026-08-13.

## Objective

Speed-first routing selects the directed path with the highest measured bottleneck delivery rate.
Each endpoint makes an independent decision.

## Route calculation matrix

The synthetic matrix covered sparse and dense topologies.

| Topology | Nodes | Directed edges |
| --- | ---: | ---: |
| Sparse | 8 | 14 |
| Sparse | 32 | 62 |
| Sparse | 128 | 254 |
| Dense | 8 | 56 |
| Dense | 24 | 552 |
| Dense | 48 | 2,256 |

The focused route test completed in 0.02 seconds.
The process used 14.3 MB of resident memory.
The matrix did not identify an algorithmic or memory regression.

## Live topology

The live topology used a Mac endpoint, a public relay, and the `.40` router endpoint.
All three nodes used the same feature build.
The relay measured directed links but did not select speed-first routes for its own traffic.
Both endpoints enabled speed-first selection.
The total probe budget was 1 Mbit/s on each node.

## Baseline

The normal hop route used the direct link.
The latency route used the relay.

| Test | Result |
| --- | ---: |
| Mac to `.40`, TCP, four streams | 1.65 to 5.78 Mbit/s |
| `.40` to Mac, TCP, four streams | 28.95 to 35.08 Mbit/s |
| Mac to `.40`, ping loss | 30% |
| Mac to `.40`, ping average | 242.7 ms |

## Speed-first results

The Mac selected the relay path to `.40`.
The `.40` router selected the direct path to the Mac.
The live route was asymmetric after fresh directed samples arrived.

| Test | Result |
| --- | ---: |
| Mac to `.40`, TCP | 13.06 to 20.71 Mbit/s |
| `.40` to Mac, TCP | 24.35 to 52.61 Mbit/s |
| Mac to `.40`, ping loss | 15% |
| Mac to `.40`, ping average | 114.0 ms |

One Mac route sample selected a 34.85 Mbit/s relay path with 85 ms path latency.
One `.40` route sample selected a 45.08 Mbit/s direct path with 211 ms path latency.
These decisions show that each direction can select a different path.

The final four samples used 30-second intervals.
The Mac route changed from direct to relay and then back to direct.
The selected relay sample measured 22.03 Mbit/s.
The router independently used latency fallback through `btower` after its speed sample expired.
Existing flows remained on their pinned path during route updates.

The final four-stream test received 20.08 Mbit/s from the Mac to `.40`.
The reverse test received 30.24 Mbit/s.

## Stability

The final build completed a 15-minute live soak.
The relay kept one process and reported zero restarts.
The relay recorded no panic for the final build.
The soak exceeded the previous failure interval.

The Mac file descriptor count varied between 73 and 261 during the soak.
The count decreased several times without a process restart.
Existing UDP hole-punch socket churn needs separate investigation.
No resource limit changed during this work.

## Verification

The library test suite passed 1,039 tests.
The binary test suite passed four tests.
Release builds passed for macOS arm64, Linux x86_64 glibc, and Linux x86_64 musl.
The route matrix covered different node counts and graph densities.
