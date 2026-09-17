# Public discovery latency and traffic model

This is an offline, dependency-free Rust discrete-event model. It sends no packets, opens no sockets, and changes no LowTier runtime defaults. It evaluates the proposed multicast + UDP STUN + UDP/HTTP/HTTPS tracker race before a live implementation is enabled. A model result is a prediction under its stated assumptions, never a measured Internet success rate.

## Reproduction

From the repository root, run `python3 script/discovery-model/run.py --trials 10000 --seed 20260911`, then `python3 script/discovery-model/analyze.py`. The runner invokes rustfmt, rustc tests, and an optimized rustc binary through structured subprocess argument arrays. No Cargo dependency resolution or production rebuild is needed. Outputs are under `target/discovery-model/`; the analysis writes `docs/performance/public-discovery-model-results.md`. Repeat the executable with other seeds and retain outputs as `results-SEED.csv` for a sensitivity analysis. The checked experiment used seeds 20260911, 20260912, and 20260913.

The source requires Rust supporting the 2024 edition. Current run metadata records the exact compiler version and source SHA-256. Seventeen unit tests cover byte accounting, critical-path timing, tracker retry timing, one-sided discovery, deterministic ordering across trackers, startup skew, unavailable UDP, incompatible mappings, cache cancellation, lost-ACK handling, and immutable in-flight path identity.

## Model and metrics

There are two nodes and up to eight shared tracker services. Each service stores registrations and returns a snapshot at announce arrival. The model never supplies a peer with knowledge of a future registration. Independent node ordering selects different first arrivals; a common access delay creates correlated ordering across providers. An endpoint is a hint. Restrictive NATs additionally require each side to have sent toward the other endpoint before incoming probes are admitted. An incompatible-mapping scenario explicitly has no valid direct candidate; it represents a worst case and does not characterize every endpoint-dependent NAT.

The first-hint, mutual-hint, and successful probe/ACK times are separate outputs. Latencies are relative to the second node's boot. The decision window is five seconds after that boot. Late-join failure also has a deterministic test. Completion requires a returning probe ACK; a received request alone does not cancel an unacknowledged outbound check. The receiver emits a triggered ACK without launching a redundant probe train. Probe retries cease after an ACK. The model delays cancellation of other discovery tasks by one further peer RTT, representing an assumed handshake delay; transport-handshake bytes and cryptographic processing are excluded.

All reported latency percentiles are conditional on success or on receipt of the relevant hint. Failure counts remain explicit. In particular, a fast median among the few successful attempts cannot establish a fast general connection policy. Means for traffic include failed attempts and both nodes. Each transmitted datagram, including tracker/STUN responses, is counted once across the network. Already-started UDP transactions can finish after cancellation; new proactive work is suppressed.

## Explicit synthetic assumptions

Tracker RTT is the sum of a provider-specific uniform 15–100 ms delay, a node-specific uniform 5–35 ms access delay, and a uniform 0–25 ms path term. The access term is shared by all providers for one node. STUN RTT is that access term plus a uniform 10–40 ms term. Peer RTT is uniform 20–80 ms. LAN RTT is 2 ms. Cold tracker DNS delay is uniform 5–30 ms; STUN DNS delay is 10 ms. DNS traffic is modeled as 200 IP-layer bytes and two packets per cold name lookup. Provider outage probability and UDP packet loss are either zero or, in stress scenarios, 20% and 2%, respectively. Outages are common to both nodes using the same provider. Region-wide blocking is modeled separately. These distributions are sensitivity inputs; they have not been fitted to measurements.

IPv4 UDP accounting includes 20-byte IP and 8-byte UDP headers and excludes link-layer framing. STUN uses the minimal 20-byte Binding request and a 32-byte success response carrying an IPv4 XOR-MAPPED-ADDRESS; optional attributes increase the real size. UDP tracker payloads follow BEP 15: connect 16/16 bytes, announce request 98 bytes, response 20+6n bytes. No assumption that a tracker overwrites the advertised port with its observed UDP source port is made. Candidate correctness is a separate scenario assumption.

HTTP/HTTPS use aggregate setup costs and reliable delivery after reachability is established. HTTP cold setup is modeled as one RTT, 120 IP-layer bytes, and three packets. HTTPS cold setup is two RTTs, 4800 bytes, and twelve packets. A request costs 400 bytes/two packets and a response 250+6n bytes/two packets. These TCP/TLS figures are assumptions, not wire-format constants; TCP retransmission, certificate variation, resumption, redirects, proxying, HTTP/2, and idle teardown are outside the model. Failed TCP setup is conservatively charged the attempted setup budget. The UDP loss variable does not simulate TCP recovery.

The multicast model assumes an already registered mDNS service. It models a 96-byte query, a 200-byte response, and independent uniform 20–120 ms query and responder delays. It sends one initial query per node. Cold mDNS name probing, repeat-query backoff, multicast loss recovery, large-LAN response suppression, AP isolation, multiple interfaces, and IPv6 packet costs are outside this simulation. It is a LAN fast-path model, not a complete mDNS implementation.

The second STUN provider is a 100 ms hedge and is suppressed once a mapping is available. Two matching STUN observations would still be insufficient to prove all mapping/filtering behavior. A warm scenario represents a still-valid UDP tracker connection ID or an already-open HTTP(S) connection; STUN is gathered afresh. Cookie warming maintenance is not free and is excluded. Tracker cookies expire after 60 seconds; UDP requests retry at 15 seconds with exponential backoff. The initial-race production scenarios finish before a UDP tracker retry is due. Trackers advertise an illustrative 1800-second regular announce interval; no early ordinary announce is used. Public tracker population, record expiry/churn, seed-only suppression, and arbitrary inter-operator policies require live compatibility tests.

## Policy names

`udp1`, `udp2`, `udp4`, and `udp8` send all initial UDP requests at once. `hedge4` sends two UDP requests initially and one more at 150 and 300 ms, shuffling node-local order within the same shared pool. `mixed4` uses two initial UDP trackers, HTTP at 150 ms, and HTTPS at 300 ms. `mixed6` uses four UDP trackers (two initial, two hedged), HTTP at 450 ms, and HTTPS at 600 ms. The `lan150_` and `lan250_` prefixes defer WAN startup by 150 or 250 ms. `_p100` uses probe times 0,100,300,700,1500,3100 ms within the decision window; other policies use 0,50,150,350,750,1550,3150 ms. Those are modeled peer-check schedules, never public tracker or STUN retransmission intervals.

## References

BEP 15: https://www.bittorrent.org/beps/bep_0015.html
BEP 3: https://www.bittorrent.org/beps/bep_0003.html
BEP 23: https://www.bittorrent.org/beps/bep_0023.html
STUN: https://www.rfc-editor.org/rfc/rfc8489.html
UDP NAT mapping and filtering: https://www.rfc-editor.org/rfc/rfc4787.html
ICE: https://www.rfc-editor.org/rfc/rfc8445.html
Multicast DNS: https://www.rfc-editor.org/rfc/rfc6762.html
ICE-TCP: https://www.rfc-editor.org/rfc/rfc6544.html
QUIC: https://www.rfc-editor.org/rfc/rfc9000.html
