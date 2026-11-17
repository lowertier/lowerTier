# Transport condition and compiler warning audit

This audit removes four experimental selectors and repairs a release-only multicast defect.
It preserves the selected transport behavior and resource limits.

## Removed runtime paths

| Removed selector | Retained behavior |
| --- | --- |
| `LOWTIER_QUIC_CONGESTION` | BBR with a 12,000-byte initial window. |
| `LOWTIER_QUIC_PACING_BURST_PACKETS` | The existing 64-packet pacing bound. |
| `LOWTIER_QUIC_DISABLE_PRECISE_TIMER` | The precise macOS QUIC timer. |
| `LOWTIER_DARWIN_UDP_BATCH_SEGMENTS` | One UDP segment per submission on connected macOS sockets. |

The Darwin cleanup removes the experimental `sendmsg_x` implementation.
The retained partial-send path preserves datagram boundaries and the unsent suffix.
The audit also removes unused imports, redundant manifest fields, an unused build dependency, and obsolete test helpers.

Read-only checks found none of the four removed selectors in the eleven reachable node processes.
These removals therefore preserve their observed runtime choices.
The checks also found no TCP large-buffer override or QUIC statistics interval override.

The changes remove setup parsing and selector state.
They do not change payload framing or add a new multiplexer.
No throughput, CPU, or RSS improvement follows from this source audit alone.

## Conditions that remain

Authentication, TLS exporter binding, ACL checks, destination scope, resource admission, and cancellation remain.
These checks enforce current protocol and ownership rules.
The native sender still requires the HTTP client side of its carrier.
The automatic policy can select packets when that capability is unavailable.
Strict `on` mode reports the unsupported operation.

QUIC reliable-stream and DATAGRAM paths remain separate.
WSS retains its packet path and its explicit carrier-lane options.
Platform and build-feature guards remain where the corresponding facility is unavailable.

`LOWTIER_ENABLE_TCP_LARGE_BUFFERS` remains a separate Linux resource experiment.
It changes socket storage and H2 flow-control windows.
This audit does not select new transport memory limits.
`LOWTIER_QUIC_STATS_INTERVAL_MS` remains an observation control.

The shared-carrier QUIC slow-reader stall remains unresolved.
The cleanup does not remove the packet writer's reliable-write dependency.
See [the QUIC admission report](quic-auto-20261117.md).

## Release-only multicast repair

Repeated multicast reports must refresh the reporter's expiration deadline.
The previous call appeared inside `debug_assert!`.
Release builds omitted that call and retained the old deadline.

The repair executes the mutation before the assertion.
The regression checks both the extended deadline and the final expiration.
With debug assertions disabled, the regression failed before the repair and passed after it.

The deadline index remains a bounded `BTreeSet`.
Each refresh removes and inserts one index entry.
The work remains `O(log M)` for at most 4,096 memberships.
The repair restores that required work in release builds.

## Feature ownership

Builds without TUN omit unavailable direct NIC storage and writer helpers.
The packet classifier, authentication, admission checks, fallback queue, and packet ownership remain.
NIC injection still consumes its packet and returns `TunnelError::Shutdown` when no TUN writer exists.

Builds without SOCKS5 omit unused native client admission state.
Native receive support remains available to authenticated peers.
The H3 guard retains the original request handle until its carrier closes.
The endpoint drops only its unused clone.
The TCP proxy no longer allocates an unused smoltcp channel when smoltcp is absent.

The smoltcp changes align internal fields and helpers with their medium and protocol features.
They retain Ethernet, IP, IEEE 802.15.4, and multicast configurations.
The test matrix checks the feature boundaries without blanket warning suppression.

## Verified local results

| Check | Result |
| --- | --- |
| Full feature and FFI compiler baseline | 23 Rust warnings. |
| Minimal compiler baseline | 58 Rust warnings. |
| Eight selected production feature checks | Passed without Rust warnings. |
| Library suite | 569 passed; two Caddy tests run separately; two public-domain probes excluded. |
| Separate Caddy integration tests | Two passed. |
| Quinn runtime tests | Three passed. |
| Multicast regression with debug assertions disabled | Passed after the repair. |
| Release tracker bootstrap without configured peers | Exact 4 MiB delivered. |
| macOS release build | Passed without warnings. |
| Linux x86-64 release build | Passed with one linker warning. |
| Linux arm64 release build | Passed with one linker warning. |

The feature checks cover minimal, default, full with FFI, TUN-only, SOCKS5-only, userspace FFI, packet-tunnel FFI, and additional smoltcp media.
The standalone smoltcp media tests also passed without warnings.
The eight feature checks ran on macOS arm64.
The standalone smoltcp IP-only tests passed with 17 unused test-fixture warnings.
Those fixture warnings remain outside the production feature checks.
Each Linux cross build reports `ignoring deprecated linker optimization setting "1"`.
The linker warning remains visible.
Windows, iOS, and FreeBSD builds were not run.

Five external runtime cases use non-test executables without TUN.
Each case checks authenticated peers and an exact 4 MiB transfer in each direction.

| Carrier | Admission | Server build | Result |
| --- | --- | --- | --- |
| QUIC | `on` | Minimal | Native upload and download passed. |
| H2 | `on` | Minimal | Native upload and download passed. |
| QUIC | `off` | SOCKS5-only | Packet upload and download passed. |
| H2 | `off` | SOCKS5-only | Packet upload and download passed. |
| WSS | Packet path | SOCKS5-only | Upload and download passed. |

The native cases record the selected native path.
The packet cases record packet selection where the transport has an admission endpoint.
The runtime checks cover forwarding without TUN.
They do not exercise every unavailable-NIC error branch.

Initial runtime fixtures omitted required discovery configuration.
Another fixture allowed tracker discovery to replace the intended carrier.
That replacement could give the SOCKS5 client the HTTP server role.
Separate local tracker peer lists keep the configured carrier direction deterministic.
The corrected fixture retained the same transfer assertions.
All failed runs and their logs remain in the private audit directory.

## Fleet deployment

Application commit `94cca88a` is deployed to all eleven reachable test instances.
Running-image transfer integrity passed on every instance.
Configuration, identities, routes, MTUs, and GUI policy remain unchanged.
H2 retains saved `auto`.
QUIC retains its compiled `auto` default.

| Check | Result |
| --- | --- |
| Full-size ICMP | 55 sent; 55 received. |
| UDP at 64, 1,160, and 1,252 payload bytes | 165 sent; 165 exact replies received. |
| TCP per instance | Exact 8 MiB upload and 8 MiB download. |
| Authenticated transport observations | H2, QUIC, and WSS on every instance. |
| Keyless GUI page, API, and RPC reads | Eleven passed for each check. |
| Foreign-Origin rejection | Eleven passed. |
| Running-image integrity | Eleven passed. |
| Temporary fixture and transfer cleanup | Eleven passed. |

The LA application check runs from jpaws.
The checks use normal transport selection.
They verify delivery and do not establish throughput changes or artificial-loss recovery.

The router upload exceeded its first 300-second deadline.
The resume verified the retained 8,355,561-byte compressed prefix before append.
The complete candidate then passed binary transfer integrity and configuration checks.

`tw2-ingress`, `btower`, and `UTMOWRT` remain offline and pending.
Their migration is unverified.
No legacy binary backups were created.
Logs, configuration, keys, and raw measurements remain.

## Evidence

Complete commands, compiler diagnostics, process records, and recovery logs are under:

`benchmark-results/.work/transport-conditions-20261117/`

The accepted feature runtime run is `feature-interop/run-5`.
The release bootstrap records are in `release-bootstrap`.
Public summaries are under `benchmark-results/transport-conditions-20261117/`.
