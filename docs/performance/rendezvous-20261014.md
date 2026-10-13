# Rendezvous verification: 2026-10-14

The minimal tracker-compatible service passed six complete VPN feature cases.
The verified service now runs on `s6916` and `jpaws`.
The resident VPN cores retain the fastest previously verified baseline.

## Source and build

The tested source snapshot is `72dc3847dfd8407b90fa2d3c77093864e9e815ff`.
Its base is `be976262012d7c3ccf107d6caf5f446ea4a50e6d`.
The Linux musl and native macOS release builds passed.
The focused discovery suite passed all ten tests in 15.56 seconds.
The exclusive mapped TCP listener test passed in 0.22 seconds.
No new unit tests were added for this work.

The source changes provide:

- One discovery session across all permitted interface addresses.
- Separate endpoint leases for concurrent IPv4 and IPv6 addresses.
- Interface refresh, mapping updates, and retries after connection-slot release.
- Mapped TCP connection attempts with coordinated TLS roles.
- Existing Noise authentication and TLS exporter binding.
- Configurable ports, with `16969` as the new service default.
- The exact HTTP user agent `aria2/1.37.0`.

Public UDP, HTTP, and HTTPS tracker client paths remain present.
This run did not send test announcements to public tracker operators.

## Complete VPN cases

The fixture ran on `s6916` in five isolated Linux network namespaces.
Test traffic had no route to the public Internet.
The nodes used native TUN, MTU 1300, secure mode, and no static peer URLs.
Peer-assisted traversal was disabled to isolate initial discovery.
The private tracker returned a two-second interval.

IPv4 used fixed address translation with stateful inbound filtering.
The gateways dropped unsolicited inbound packets.
The UDP tracker cases changed the running node's local and translated IPv4 addresses.
The HTTP tracker cases supplied two interfaces and both address families, then disabled the first interface.

| Transport | Tracker and case | Initial authentication, seconds | Recovery validation completion, seconds |
| --- | --- | ---: | ---: |
| QUIC | UDP, IPv4 address change | 2.199 | 35.648 |
| QUIC | HTTP, dual stack, interface removal | 2.173 | 36.576 |
| H2 | UDP, IPv4 address change | 2.195 | 5.224 |
| H2 | HTTP, dual stack, interface removal | 1.976 | 5.215 |
| WSS | UDP, IPv4 address change | 2.190 | 5.248 |
| WSS | HTTP, dual stack, interface removal | 2.191 | 2.166 |

Each case verified a 1 MiB payload by SHA256 before and after the change.
Each delivery check also required three successful pings with zero loss.
The running nodes retained their authenticated peer identities.
Recovery times include failed request deadlines, the successful transfer, and three pings.
These times are not exact outage durations.
Each row represents one functional run, not a throughput benchmark or a repeated performance comparison.

Every dual-stack capture contained announcements from all eight source addresses.
Each node used one session identifier across its four addresses.
Every captured HTTP announce used `aria2/1.37.0`.

The H2 snapshots show a surviving second-interface IPv6 connection before and after interface removal.
They do not prove an active-path switch for H2.
The WSS snapshots show authenticated IPv4 delivery and IPv6 discovery attempts.
They do not prove authenticated WSS delivery over IPv6 in this namespace fixture.
The focused discovery suite separately covers all three transports with IPv4 and IPv6 loopback endpoints.

## Retained failures and limits

The first SNAT-only fixture failed to establish QUIC.
Packet captures showed a destination-dependent mapping mismatch.
One node announced UDP port `43527`, but its peer-directed packet used port `16180`.
The other node announced `41455`, while some peer-directed packets used `1473`.
Initial endpoint discovery cannot guarantee traversal when the peer mapping differs from the advertised mapping.
The passing fixed-translation cases do not establish success for this NAT behavior.

An earlier interface-removal run failed to recover within its 65-second budget.
Published connections outlived their discovery paths and retained connection slots.
The fix records ownership before an asynchronous wait and closes owned connections when the path stops.
Retry scheduling now observes actual slot release and preserves active attempts.
The final QUIC interface-removal case passed after these changes.

One final build failed on an extra reference in a retry-map lookup.
The corrected source passed both release builds and the focused tests.

## Deployment and recovery

Both services retain UDP port `16970` and loopback HTTP port `16973`.
Both now listen on IPv4 and IPv6 with a two-second interval.
The running executable SHA256 on both hosts is:

```text
467625d7ec201d45488a4b4ee6e0a9ab8bd70af9022c1f7c637a553d6f853133
```

Local IPv4 and IPv6 UDP and HTTP checks passed on both hosts.
Both resident peers remained authenticated.
Three overlay pings to each host passed without loss.
All fixture namespaces were removed; the existing `wgcf` namespace remains.

The first deployment hash check ran before the service executable was ready.
Its rollback copy failed with `Text file busy`; direct inspection confirmed the new service was healthy.
The deployment helper now waits for the executable and uses atomic replacement for rollback.
The second host initially rejected a copied temporary-file security label.
Rollback restored its old service.
Replacement then preserved the installed file metadata and passed verification with SELinux still enforcing.

Previous service binaries and units remain under `/opt/lowertier-baselines/rendezvous-20261014` on both hosts.
Verified clients are archived under `/Users/boyu/et/baselines/rendezvous-20261014` and the server backup's `client` directory.
The new clients ran in the namespace fixtures but did not replace resident VPN cores.
Their inherited data-plane changes lack a faster matched result than the retained baseline.

## Evidence

Complete local records are under `benchmark-results/.work/rendezvous-20261014/`:

- `audit.jsonl`: commands, process IDs, output, exit codes, and recovery actions.
- `feature-180414/`: final six-case results, packet records, node logs, and binary hashes.
- `feature-174008/`: retained SNAT mapping failure and connection-tracking records.
- `feature-174232/`: retained interface-removal failure before the ownership fix.
- `source.json`, `build-linux-verified.log`, and `build-native-verified.log`: source and build evidence.
- `runtime-tests-verified.log`: the final focused discovery results.

These local records are not included in the source commit.
