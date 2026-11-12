# Dataplane cryptography

LowTier peer traffic defaults to `chacha20-poly1305` through the `ring` AEAD implementation.
The primitive uses a 256-bit key, a 96-bit nonce, and a 128-bit authentication tag.
The `ring` backend also provides AES-128-GCM and AES-256-GCM.
All algorithms keep the existing ciphertext, tag, and nonce layout.
The optional `aes-gcm` and `openssl-crypto` backends are removed.

This choice follows the established WireGuard dataplane primitive used by Tailscale. Tailscale
delegates peer packet encryption to `wireguard-go`; its batched `magicsock` path carries already
encrypted WireGuard packets. LowTier does not claim wire-format compatibility with WireGuard and
does not introduce a new cipher.

## Configuration

- `chacha20-poly1305` is the canonical spelling and the default in every feature set.
- `chacha20` remains accepted as a legacy spelling and normalizes to
  `chacha20-poly1305`.
- `aes-gcm` and `aes-256-gcm` remain authenticated alternatives.
- XOR has been removed from the encryption choices. There is no option to disable encryption.

Unknown algorithm names currently fall back to the secure default with a warning. CLI values are
validated before startup, while this fallback protects protocol input from selecting an insecure
cipher.

## Protocol boundary

The AEAD authenticates the encrypted payload and tag. The existing peer-manager header remains
outside the AEAD because relay nodes must update routing fields. Changing that boundary requires a
versioned packet protocol, not an ad-hoc AAD change.

Every peer connection also uses Noise handshakes and session protections:

- Noise XX with X25519, ChaChaPoly, and SHA-256 for direct peer authentication;
- Noise IK with the same standard primitives on the relay path;
- per-direction traffic keys, epoch rotation, sequence nonces, and replay windows.

This is still LowTier's protocol construction, not the complete WireGuard protocol. A future
full WireGuard-compatible peer session would need a separately versioned handshake and packet
format rather than reusing the LowTier framing under a WireGuard name.

## Direct and relayed packets

Direct QUIC, HTTP/2, and WSS links bind the Noise handshake to the TLS exporter. Packets between
directly connected peers then rely on that TLS 1.3 protection and skip the inner session AEAD
(`PeerConn::encrypt_packet_if_needed`). Packets that cross a relay or a waypoint carry the inner
session AEAD, sealed by the source for the final destination, with the stable peer-header fields
as associated data.

## Verification

Minimal `tun` builds run the same authenticated cipher tests as full builds. Regression coverage
asserts the secure default, canonical and legacy parsing, XOR rejection, ciphertext round-trip,
tamper rejection, asymmetric peer algorithms, replay windows, epoch changes, and secure peer data
round-trips.

References:

- [Tailscale's userspace WireGuard engine](https://github.com/tailscale/tailscale/tree/main/wgengine)
- [WireGuard protocol and cryptography](https://www.wireguard.com/protocol/)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
