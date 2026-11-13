# Decoy passthrough limits

`camouflage.decoy_upstream.tcp` and `.udp` select fixed upstream endpoints.
TCP forwards unmarked streams. QUIC forwards unmarked datagrams.
The endpoints can differ. Visitors cannot select a destination.
See [camouflage](../camouflage.md) for admission and SNI settings.

## Shared probe sessions

Each source can open two probe sessions within a rolling 60-second window.
QUIC, H2, and WSS share this counter across all process listeners and instances.
Closing a session, changing source ports, or changing protocols does not restore a slot.
Rejected attempts do not extend the window.
The third session receives no upstream connection.

Each forwarded session has these limits:

| Resource | Limit |
| --- | ---: |
| Combined bytes in both directions | 64 KiB |
| Inactivity | 5 seconds |
| Total lifetime | 10 seconds |

The byte limit includes forwarded TLS and HTTP framing.
TLS hides individual page requests within a connection.
These limits count sessions and bytes, not page loads.
A client can request several small resources within one bounded session.

IPv4 addresses have separate counters.
IPv4-mapped IPv6 addresses share the corresponding IPv4 counter.
IPv6 addresses within one `/64` share a counter.
Clients behind NAT share the visible source counter.
The limiter keeps at most 4,096 source entries.
It retains probe timestamps for 60 seconds and then reclaims inactive entries.
Restarting the process clears this in-memory history.

A valid admission token exempts the VPN connection from probe limits.
H2 and WSS use `network.secret` when no explicit admission secret is configured.
Credential-only peers can configure the same `camouflage.admission_secret` on both endpoints.
Tokenless H2 and WSS setup stays bounded until Noise authentication succeeds.
Successful authentication removes its provisional probe reservation.
A verified TCP lane group shares one reservation and one setup byte budget.
Each lane reserves a probe slot before the exporter-bound join.
A verified follower releases its slot and joins the primary session.
It cannot forward website traffic during setup.
Internal control and DNS services use dedicated loopback listeners without probe limits.
These listeners cannot configure decoy forwarding.
Control RPC requests still require the control token.

A configured local HTTP/3 website root uses separate website resource limits.
This website serves local files and does not forward requests to another host.
Its limits permit eight concurrent connections per source, 30 seconds of inactivity, and five minutes of total lifetime.
The default HTTP/3 page has the probe session, response byte, and lifetime limits.

## Shared bandwidth and bursts

Unauthenticated decoy forwarding uses a single process-wide limiter, shared by
all instances, listeners, TCP and UDP, and both forwarding directions. There is
also a per-source-IP limiter. Opening more connections, changing source ports,
reconnecting, or switching protocols does not create a fresh IP burst.

The initial built-in limits are:

| Resource | Process-wide | Per source IP |
| --- | ---: | ---: |
| Forwarded payload bytes per second | 1 MiB/s | 128 KiB/s |
| Payload burst capacity | 256 KiB | 64 KiB |
| Concurrent probe sessions | 128 | 2 |
| Probe admissions per rolling 60 seconds | - | 2 |
| New decoy flows per second | 16 | 4 |
| New-flow burst | 32 | 8 |
| Forwarded UDP datagrams per second | 4,096 | 512 |
| Datagram burst | 512 | 128 |

These are ceilings, not bandwidth guarantees. Byte accounting counts each
forwarded payload once, in either direction, not twice for its two network legs.
IP/TCP/UDP framing overhead is not part of this bandwidth budget. Both global and
source budgets must allow a transfer before either budget is consumed.

The values currently live in `lowertier/src/tunnel/decoy.rs`; there are no new CLI
or configuration flags. They are deliberately enabled whenever decoy forwarding
is used. Admitted LowTier tunnels do not consume these budgets; their existing
admission checks, authentication, and TLS-exporter bindings remain intact.

TCP copying waits for tokens and uses TCP backpressure. It preserves bytes and
half-close behavior. UDP ingress exceeding its budget is dropped, since UDP has
no transport-level backpressure. Responses are paced as whole, unchanged
UDP datagrams, with one pending response per flow and bounded ingress channels
(64 shared, four per flow). Sustained overload may cause QUIC loss/retransmission;
it cannot create an unlimited delay queue. No HTTP status or synthetic TLS/QUIC
response is injected, and passthrough TLS is not terminated.

An L4 proxy that replaces source addresses makes clients share the proxy address counter.
LowTier does not trust HTTP forwarding headers for probe accounting.

TCP upstream connection setup and routing-prefix reads have five-second timeouts.
Resource/admission exhaustion drops UDP or closes new TCP flows without an HTTP
response. It does not convert an over-limit visitor into an authenticated peer.

## UDP reflection and amplification

A bandwidth cap alone does not prevent a spoofed-source UDP reflection attack.
The decoy path additionally:

1. Creates new UDP forwarding state only for structurally bounded QUIC v1/v2
   Initial datagrams of at least 1,200 bytes. Arbitrary UDP, unsupported versions,
   and short-header packets cannot open an upstream flow. This is a header check,
   not cryptographic client authentication. Parsing permits QUIC-bit greasing
   ([RFC 9287](https://www.rfc-editor.org/rfc/rfc9287.html)); the optional cleared
   bit must not hide a legitimate server CID from the return-path check.
2. Before return-path evidence, sends no more response **bytes or packets** than
   were forwarded from that client tuple. Byte credit includes 28 bytes of
   IPv4/UDP overhead per datagram and is capped at 64 KiB; packet credit is capped
   at 32. Rate-limit bursts never override this one-for-one bound.
3. Remembers an upstream-selected CID only from an Initial or Retry actually
   forwarded to the client, with the matching version and client CID. A later
   client Initial/Handshake must echo it to lift the one-for-one response bound.
   This evidence belongs only to that connection/tuple, not to all traffic from
   its IP. A fresh Initial for a different connection on the same tuple resets
   both the proof and the accumulated response credit.
4. Never treats an empty, shorter-than-eight-byte, or client-supplied CID as this
   evidence. Rate, packet, and resource caps still apply after the check succeeds.

**The fixed upstream is trusted and must generate CIDs with at least 64 bits of
unpredictable entropy.** Length alone cannot prove entropy. CID-based return-path
validation follows the option described in [RFC 9000 section 8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1),
but it is not a substitute for the endpoint's QUIC/TLS authentication.
An upstream using predictable CIDs is unsuitable for this protection. The
connected UDP socket filters by upstream address, but this is not cryptographic
origin authentication: an attacker able to inject forged upstream responses or
observe the return path is outside this off-path protection model. Short/empty
CIDs retain the one-for-one cap and may prevent ordinary large downloads.

The pre-validation limit is deliberately stricter than QUIC's standard 3x
anti-amplification allowance. Large certificate flights can take extra probe
round trips. A new source tuple cannot borrow prior validation; transparent
migration of upstream website traffic using only short headers is not supported by this decoy admission path.
Authenticated VPN path migration uses Quinn's separate connection policy and path validation.

This prevents **amplification before return-path evidence**, subject to the CID
entropy requirement; it is not a claim of zero reflection. A transparent UDP
service can still return up to the bounded amount of traffic to a spoofed address.
Preventing every such response would require disabling UDP passthrough or a
separate client address-validation protocol. Network-level anti-spoofing and
host ingress limits remain useful, particularly against floods that saturate the
link before the application can act.

## Run a local demo

From the repository root:

```sh
cargo run --locked --offline -p lowertier --example passthrough_demo
cargo test --locked --offline -p lowertier --lib tunnel::quic::decoy_tests -- --nocapture --test-threads=1
```

The first command starts a loopback H2/TLS origin and a LowTier H2 listener.
It verifies the origin certificate and downloads two 8 KiB payloads.
It checks every payload byte and rejects a third connection before the origin receives it.
It reports TLS latency, delivery time, and effective throughput.
All demo services use loopback sockets and stop on exit.
No root access, TUN, or system trust change is required.

The second command demonstrates real H3 downloads with a large certificate,
checks byte-for-byte delivery, reports QUIC loss/RTT/MTU, and exercises UDP
anti-amplification, wrong-CID probes, and source-port isolation. These are local
debug demos, not release/WAN performance comparisons. TLS timing is not a TCP
RTT measurement, and the H2 demo does not sample kernel retransmission counters.

If macOS Clang cannot access `/usr/local/include`, configure the installed SDK header paths:

```sh
export CFLAGS="-nostdinc -isystem $(xcrun clang -print-resource-dir)/include -isystem $(xcrun --show-sdk-path)/usr/include"
```

## Verification

Local tests cover shared global/IP budgets, burst refill and reconnect behavior,
packet and concurrent-flow caps, cancellation, TCP lossless bidirectional copying
and half-close, malformed QUIC headers, byte/packet anti-amplification, wrong-CID
probes, and isolation between source ports. A real loopback HTTP/3 origin exercises
a large certificate flight and two 8 KiB downloads, then rejects a third session.
It records delivery, loss, RTT, MTU, and effective throughput.
Caddy shared-port tests cover two backends, ordinary
websites, and the existing H2/H3/WSS transport bindings.

Tests use `challenges.cloudflare.com` only as the SNI/example name and connect to
explicit loopback addresses. Test certificates do not establish ownership of that
public domain. Probe forwarding and speed regulation do not guarantee that
LowTier traffic is indistinguishable from ordinary browser traffic; notably,
legacy H2 decoy routing still uses its pre-ClientHello routing record.

## Certificate verification and endpoint URLs

Certificate and key paths must be configured together.
Decoy forwarding requires an admission secret of at least 16 bytes and a server name.
`sni_routing=true` replaces marker classification with SNI classification. Noise still authenticates VPN peers.
Named QUIC/H2 connections validate certificates when no decoy is configured.
Otherwise QUIC/H2 uses the existing Noise-authenticated certificate verifier.
Direct WSS retains its existing Noise verifier. CDN outer TLS always validates the public CDN certificate.
CDN inner TLS retains the end-to-end exporter binding. Missing subprotocol negotiation fails the connection.

H2 and WSS listeners read camouflage changes for new connections.
Existing connections keep their authenticated transport binding.
QUIC listeners cache certificates and decoy settings until listener recreation.
The control API stages cached QUIC settings as restart fields while QUIC is enabled.
Stop and start the instance to recreate those endpoints.

Endpoint URLs retain `via=cdn`, `lanes=1,2,4`, and WSS paths.
An explicit WSS URL path overrides `camouflage.wss_path`. The listener rejects a different request path.
WSS peer URLs with an empty or root path use `camouflage.wss_path`, which defaults to `/ws`.
Manual connectors retain this effective path so an active connection prevents repeated dialing.
Multiple lanes are unavailable in CDN mode. Trusted proxy CIDRs default to none.
CIDR and interface restrictions remain enforced. Strict underlay policy continues to reject peer hostnames.
VPN/SNI examples use `challenges.cloudflare.com`. This name does not establish certificate ownership.
Use explicit loopback endpoints for local tests.
