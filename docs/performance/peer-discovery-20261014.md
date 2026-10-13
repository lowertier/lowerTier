# Peer discovery and idle rendezvous

## Scope

This change reuses the authenticated overlay for peer information and endpoint requests.
It does not add a second peer list or gossip protocol.
The existing versioned route synchronization supplies membership changes.
The endpoint RPC includes active discovery listeners and their mapped addresses.

The private tracker returns at least 30 seconds after the client authenticates a mesh connection.
Bootstrap retains the configured interval, which defaults to two seconds.
Each interface continues to advertise and receive candidate endpoints.
This preserves discovery between disconnected groups and across different NAT paths.
Public tracker intervals remain authoritative.

The client uses nonzero `left` values for both states.
This avoids the seeder filtering used by some public trackers.
The private convention does not change BEP 15 or compact HTTP packet formats.

## Removed work

- Live connections suppress duplicate endpoint RPCs, direct dials, and hole-punch attempts.
- Authenticated endpoint hints suppress repeated candidate work for a peer with a live connection.
- Duplicate tracker URLs and listener URLs are removed before scheduling.
- Peer and route events trigger task checks without waiting for the five-second fallback scan.
- A local hash table replaces a concurrent task map owned by one loop.
- Hash-set membership replaces repeated linear membership searches.
- Task removal no longer shrinks the hash table after each removed entry.

For `P` eligible peers and `T` tasks, task membership work changes from approximately `P × T` comparisons to `P + T` operations.
The periodic fallback and traversal resource limits remain unchanged.
The tracker interval change predicts 15 times fewer steady announcements when its configured interval is two seconds.
Mapping refresh, connection recovery, cookie renewal, and protocol overhead remain additional work.

## Recovery contracts

Mapping changes and connection loss cancel pending tracker requests.
Mapping changes discard UDP tracker cookies that can depend on the old public IP.
New connectors collect current local bind addresses instead of using the 60-second address cache.
The existing interface and route-source eligibility rules remain unchanged.
STUN observations are not local bind addresses.
Listener publication and withdrawal use the same ownership lock.
Foreign-route publication also wakes connection tasks.

Relay session reuse now checks the current authenticated origin revision.
Route withdrawal can invalidate that revision even when the peer keeps the same key.
Stale authority stops session reuse and returns queued traffic to the authenticated handshake path.
The session retains cryptographic recovery state while the new handshake updates its authority binding.
Batch receive also rejects stale generic authority and marks an existing send queue for recovery.
An unverified Ethernet flag cannot reset an otherwise valid generic session.
Ordinary received data still cannot create sessions.
Relay initiation retries the same Noise message and handshake identifier after a lost reply.
One five-second deadline bounds the first send, reply wait, and retries.
Retries use the existing exponential retry delays.

Discovery retains authenticated identity before Noise session commit.
A canceled handshake can then recover an unacknowledged receipt on its next attempt.
Cached identity is advisory; an authenticated new identity can replace it after endpoint reuse.
Fresh authenticated punch expectations retain their strict identity check.
Tracker refresh does not refresh the identity timestamp used for duplicate suppression.
Hints are bounded to 64 cached endpoints per discovery path.

The ping task now closes the connection when liveness checks stop.
Previously, a silent TCP stream could remain open after the ping task reported excessive loss.
Duplicate suppression then treated the failed path as live and prevented repair.
Tracker state also requires an actual live connection, rather than cached peer authentication alone.
The existing eight-second ping deadline now includes queue admission.
A blocked send could previously stop ping results before their response deadline started.
The RTT sample still starts after admission.
Received traffic and the existing receive-backpressure signal still clear the failure counter.
Local send attempts no longer clear it.
The send counter advances before the transport accepts a packet and does not prove remote delivery.
The old condition could keep a failed connection available for route selection during application retries.

Mapped TCP attempts must overlap the remote discovery poll.
The old three-second TCP deadline could cancel a SYN before the remote peer learned a changed endpoint.
The NAT retained state for that canceled socket.
Captures showed a later SYN reaching a new listener, followed by an untranslated SYN-ACK.
The connection did not reach TLS or Noise authentication.

The complete mapped TCP attempt now lasts one default private interval plus the existing 15-second handshake allowance.
The resulting deadline is 45 seconds, with at most eight concurrent candidate attempts per path.
The same socket retains its TCP sequence state during that window.
The conventional fresh-port connection still races the mapped attempt.
QUIC retains its 15-second deadline.
Longer public tracker intervals can still exceed the bounded TCP window.

## Measurement method

The Linux feature fixture runs in isolated network namespaces on `s6916`.
All test traffic uses explicit test addresses.
The underlay uses `198.18.14.0/24`, private IPv4 subnets, and IPv6 ULA subnets.
The overlay uses `10.216.14.0/24` with MTU 1300.
Each VPN process uses two runtime worker threads.
The comparison baseline is the client from commit `9cd80f53`.

Idle windows last 60 seconds after initial authenticated delivery and a five-second settling period.
UDP tests use one IPv4 interface per node.
HTTP tests use two IPv4 and two IPv6 addresses per node.
Each comparison uses two complete idle windows per version.
The capture counts Ethernet frame bytes on the gateway-facing interfaces.
Each tracker frame is counted once.
TCP ACKs, connection setup, and UDP cookie requests are included.
Preambles, inter-frame gaps, and Ethernet FCS are excluded.

Core CPU time and RSS are sampled from `/proc` every five seconds.
CPU scope covers the two VPN processes, not the tracker, kernel, capture process, or test HTTP server.
RSS includes each VPN process's resident pages.
Idle windows have no application delivery, so CPU per delivered Gbit is undefined.
These measurements establish control-traffic cost, not VPN throughput capacity.

## Idle results

Each paired value below gives the first and second 60-second windows.
RSS gives the minimum and maximum individual-process sample across both windows.

| Discovery and version | Announcements | Tracker frames | Tracker bytes | Core CPU seconds | RSS per process |
| --- | ---: | ---: | ---: | ---: | ---: |
| UDP baseline | 60 / 60 | 124 / 124 | 12,712 / 12,712 | 0.36 / 0.38 | 22.05–28.13 MiB |
| UDP candidate | 4 / 4 | 12 / 12 | 1,064 / 1,064 | 0.31 / 0.34 | 21.73–27.71 MiB |
| HTTP baseline | 240 / 240 | 2,377 / 2,385 | 317,282 / 318,010 | 0.84 / 0.73 | 26.32–33.77 MiB |
| HTTP candidate | 16 / 16 | 160 / 159 | 21,296 / 21,222 | 0.43 / 0.41 | 25.47–29.47 MiB |

Announcements decreased by 93.3% in both modes.
Mean captured tracker bytes decreased by 91.6% for UDP and 93.3% for HTTP.
Two windows are insufficient to establish a general CPU or memory improvement.

All four candidate windows passed subsequent recovery, payload integrity, and three-ping delivery checks with no ping loss.
IPv4 address recovery took 33.83–38.53 seconds after idle.
Dual-stack interface removal took 2.20–39.68 seconds after idle.
These ranges include connection failure detection and repair.
Transport retransmission counts were not collected for these windows.
The measurements do not establish an application throughput or transport-loss improvement.

Baseline runs: `feature-183510`, `feature-183937`, `feature-185529`, and `feature-185645`.
Candidate runs: `feature-205804` and `feature-210115`.

## Functional results

The final source snapshot is `feaa289eea0811a982db0857943da5f964c4f294`.
The Linux and native macOS release builds passed.
Each row below is one complete functional run, not a repeated throughput comparison.

| Test | QUIC | H2 | WSS |
| --- | ---: | ---: | ---: |
| Two NAT layers per peer: initial connection | 2.19 s | 2.19 s | 2.19 s |
| Two NAT layers per peer: address recovery | 16.42 s | 16.37 s | 16.37 s |
| Forced relay: initial connection | 1.12 s | 1.12 s | 1.38 s |
| Forced relay: address recovery | 32.21 s | 32.24 s | 31.97 s |
| Tracker stopped: third peer joins through one seed | 1.31 s | 4.18 s | 1.31 s |
| Tracker stopped: departed peer leaves the peer list | 27.65 s | 0.02 s | 0.02 s |
| Tracker stopped: new identity reuses a listener address | 33.45 s | 3.26 s | 0.30 s |

The direct fixture preserves translated ports and rejects unsolicited inbound traffic.
The relay fixture uses SNAT without DNAT and blocks forwarding between the endpoint networks.
It permits outbound connections to the reachable relay.
Both endpoints change neither peer identity nor network credentials during address recovery.

Each recovery includes a verified 1 MiB transfer and three successful pings.
The direct fixture also delivered 1,327, 2,424, and 2,190 verified MiB transfers during separate 45-second traffic periods.
The existing connection identifiers survived those periods.
These transfers check connection stability and payload integrity; they do not establish a throughput improvement.
WSS also passed dual-stack interface removal, with delivery recovery in 2.18 seconds.

The third node had one configured seed and no tracker configuration.
It discovered the other node, authenticated a direct connection, and received a verified 1 MiB payload.
The fixture then checked peer removal and a restarted peer with a new identity at the same listener address.
Each restarted connection passed the same payload and ping checks.
QUIC peer removal and endpoint reuse still depend on connection failure detection.

Raw runs: `feature-204029`, `feature-204225`, `feature-204236`, and `feature-205622`.

## Validation and failures

The final source passed 44 connector tests, six peer-connection tests, and 36 session tests.
Four network tests and three underlay-policy tests also passed.
Five relay recovery tests and 33 secure-datagram tests passed.
The suite covers QUIC, H2, WSS, authentication, TLS exporter binding, and retained session recovery.
The Caddy integration test passed with both VPN backends, shared website traffic, and unauthorized probes.
These checks total 132 passing tests.
Fourteen final network cases also passed on the same source snapshot.

Initial build failures identified an exhaustive event match and a channel type inference error.
Both errors were fixed before functional validation.
A later relay edit removed a session-key variable still used by the activity update.
The compiler rejected the edit; the variable was restored before verification.
One parallel session-test run exhausted a shared global test quota and caused four additional lock-poison failures.
All 36 session tests passed with one test thread.
Three test filters initially selected no tests; corrected filters ran the intended suites.
The unprivileged macOS process-map check failed; the same read-only check passed with existing sudo access.

The baseline and the first candidate each failed one interface-recovery check after a 60-second idle period.
The failure was not treated as an idle-traffic success or a passing reliability result.
Diagnostic logs identified duplicate attempts and unacknowledged initiator receipts.
An unhinted retry could not select the retained receipt.
The final implementation retains authenticated identity before a handshake can leave that receipt.
All failed logs remain available beside subsequent verification results.

Later WSS runs exposed another recovery limit.
An old connection remained available while a new connection authenticated.
Source review found an unbounded ping queue wait and a loss counter reset by local send attempts.
The fixes bound admission and require received traffic for remote progress.
The original INFO logs do not establish which condition caused each failed run.

A forced-relay address-change run retained a removed source address for approximately 60 seconds.
The logs showed repeated bind failures until the address cache refreshed.
Fresh bind-address collection removes that delay without changing interface eligibility.
Another relay check read its route snapshot before route synchronization completed.
The fixture now waits for the required two-hop routes in both directions before accepting bootstrap.
The delivery and route assertions remain unchanged.

After the bind-address fix, forced-relay delivery still failed while hop authentication and route synchronization recovered.
Batch receive rejected stale origin revisions without changing the send state.
Outbound session reuse also omitted revision validation.
The repair preserves revocation checks and requires a new authenticated transition.
Session publication can precede authority-binding publication during that transition.
The repair retains cryptographic state to avoid invalidating a session during that publication window.

The next forced-relay run exposed a lost-reply recovery gap.
The relay retained its old connection for approximately one second after the new connection authenticated.
The responder received the first handshake request, but the initiator received no reply.
The logs do not establish the exact reply-loss location.
Later attempts used new identifiers while the responder retained the first request and returned a busy error.
Retries now retain the original identifier, which lets the responder return its stored reply.

The tracker-free join fixture exposed a separate underlay problem.
Adding its third bridge port could change the gateway's automatically selected MAC address.
Such a change can leave existing IPv6 neighbor entries with the previous address.
A controlled namespace probe confirmed that adding a lower-address port changed the bridge MAC.
The fixture now assigns a fixed gateway MAC and checks that joining preserves it.
The original packet logs do not establish the cached neighbor value in each failed run.
No additional QUIC or relay change was made for this fixture problem.
The first probe used an ambiguous interface-name argument; the explicit argument passed.

## Limits

NAT layer count alone does not determine direct reachability.
Destination-dependent mapping and filtering can prevent direct traversal at any layer.
The tracker cannot relay VPN traffic.
An authenticated reachable LowTier peer supplies the relay fallback when direct traversal fails.

The longer private interval trades initial group discovery latency for lower idle traffic.
It can add one returned interval before an established group learns a new endpoint.
Handshake retries and public tracker policy can add further delay.

## Deployment

Both test trackers run the final Linux tracker binary, SHA256 `b21a425eaf086c22d2e0756783aed03eef3d7d5de3a31fec23b5844dbbee85c8`.
UDP and HTTP checks passed over IPv4 and IPv6 on both hosts.
Bootstrap returned two seconds; the connected state returned 30 seconds.
The service units, ports, network identities, ACLs, routes, and keys remain unchanged.

Resident VPN cores retain the established fastest throughput baselines under the test-baseline policy.
The discovery measurements do not qualify a new data path for throughput promotion.
The final core and CLI candidates are archived on both Linux hosts and the Mac.

Complete measurements, build logs, failure logs, binary manifests, and the command audit remain in `benchmark-results/.work/peer-discovery-20261014/`.
The machine-readable result is `summary.json` in that directory.
The source manifest records the changed file list and the isolated verification commit.

| Host | Resident core SHA256 prefix | Final candidate SHA256 prefix |
| --- | --- | --- |
| Mac | `4ba1b2794b45` | `6d6fbc04de38` |
| s6916 | `4c7b732b74a5` | `36f7ba07e0e7` |
| jpaws | `83af59bcfecf` | `36f7ba07e0e7` |

The final resident checks confirmed authenticated paths and three successful pings to each Linux VPN address.
The earlier jpaws resident connection did not deliver traffic.
Restarting its existing service restored authentication and delivery without changing its binary or configuration.
The available evidence does not connect that resident failure to the tracker change.

Raw commands, process identifiers, output, exit codes, source metadata, and fixture captures are in
`benchmark-results/.work/peer-discovery-20261014/`.
Private fixture configurations are removed after each run.
