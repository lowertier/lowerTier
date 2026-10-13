# Decoy passthrough limits

`quic_decoy_upstream` forwards unmarked TCP and QUIC traffic to one
operator-configured upstream. It does not resolve destinations supplied by
visitors. Rate limiting does not make arbitrary visitor-selected upstreams safe:
that would still be an open proxy, only slower.

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
| Concurrent decoy flows | 128 | 8 |
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

There are at most 4,096 retained IP accounting entries. Inactive entries are
reclaimed after at least 60 seconds, longer than any bucket's refill time.
IPv4-mapped IPv6 addresses share their IPv4 budget. Actual IPv6 addresses are
accounted individually, so address rotation can evade a per-IP cap but not the
process-wide cap. Clients behind NAT share their visible source-IP budget. An
L4 proxy that replaces source addresses also makes its clients share that proxy
IP's budget; LowTier does not trust an HTTP forwarding header for this purpose.

Decoy flows have a 30-second I/O idle timeout and a five-minute maximum lifetime.
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
migration using only short headers is not supported by this decoy admission path.

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

The first command starts an ephemeral loopback H2/TLS origin and a real LowTier
TCP listener, verifies the origin's in-memory test certificate, and downloads
512 KiB three times. It prints TLS latency, time to receive the first 32 KiB,
full-download time, effective throughput, and exact byte delivery. The initial
burst is fast; reconnecting does not create another full IP burst. It checks
that each entire transfer obeys the sustained-rate-plus-burst bound. All sockets
are loopback-bound and all demo services stop on exit. No root/TUN access or
system trust-store modification is required.

The second command demonstrates real H3 downloads with a large certificate,
checks byte-for-byte delivery, reports QUIC loss/RTT/MTU, and exercises UDP
anti-amplification, wrong-CID probes, and source-port isolation. These are local
debug demos, not release/WAN performance comparisons. TLS timing is not a TCP
RTT measurement, and the H2 demo does not sample kernel retransmission counters.

If macOS clang selects an inaccessible custom `/usr/local/include`, the local
validation used the installed SDK headers without changing directory permissions:

```sh
export CFLAGS="-nostdinc -isystem $(xcrun clang -print-resource-dir)/include -isystem $(xcrun --show-sdk-path)/usr/include"
```

## Verification

Local tests cover shared global/IP budgets, burst refill and reconnect behavior,
packet and concurrent-flow caps, cancellation, TCP lossless bidirectional copying
and half-close, malformed QUIC headers, byte/packet anti-amplification, wrong-CID
probes, and isolation between source ports. A real loopback HTTP/3 origin exercises
a large certificate flight and a 512 KiB download three times, checking complete
payload delivery and the sustained-rate ceiling while recording loss, RTT, MTU,
and effective throughput. Caddy shared-port tests cover two backends, ordinary
websites, and the existing H2/H3/WSS transport bindings.

Tests use `challenges.cloudflare.com` only as the SNI/example name and connect to
explicit loopback addresses. Test certificates do not establish ownership of that
public domain. Probe forwarding and speed regulation do not guarantee that
LowTier traffic is indistinguishable from ordinary browser traffic; notably,
legacy H2 decoy routing still uses its pre-ClientHello routing record.
