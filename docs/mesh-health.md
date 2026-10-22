# Peer authentication and UDP reply health

`lowertier-cli peer list` exposes three separate authentication scopes. The
JSON peer fields are additive to the existing route and connection records:

- `direct_link_auth` describes a live direct transport connection. It is absent
  when the peer is reached only through a relay.
- `end_to_end_session_ready` describes a valid, committed data-plane session
  bound to a Noise static peer key. It is absent when no such session is
  established, and false when a retained session lacks a bound peer key.
- `routing_authority_auth` describes the local routing attestation. A relayed
  route without a local attestation remains `EncryptedUnauthenticated` in this
  field; the CLI calls it `not locally attested`.

A ready data-plane session does not grant routing authority. These status
fields do not change authentication, TLS exporter binding, ACLs, or relay
origin-proof checks.

UDP proxy replies reserve bounded queue capacity for every IPv4 fragment before
emitting any fragment. When capacity is unavailable, the reply waits instead of
being silently discarded. `udp_proxy_reply_queue_waits` counts replies that
encountered a full queue. `udp_proxy_reply_drops` counts replies that could not
be queued because the receiver closed. A quiet metric may be omitted from a
stats snapshot until it is first used; consumers should treat an absent counter
as zero.

QUIC still depends on the host's UDP receive buffers. Socket-buffer warnings and
kernel receive-buffer errors are distinct from these proxy metrics. Raise
limits in the owning host or network namespace when permitted, then recreate
sockets and verify actual sizes and packet delivery. A container with read-only
kernel controls should retain its isolation; an authenticated H2/TLS transport
can be validated as a fallback when that host setting is unavailable.
