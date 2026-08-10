# Dataplane cryptography

EasyTier peer traffic defaults to `chacha20-poly1305`, implemented by the audited `ring` AEAD
implementation in lean builds and by OpenSSL when the `openssl-crypto` feature is selected. The
primitive uses a 256-bit key, a 96-bit nonce, and a 128-bit authentication tag.

This choice follows the established WireGuard dataplane primitive used by Tailscale. Tailscale
delegates peer packet encryption to `wireguard-go`; its batched `magicsock` path carries already
encrypted WireGuard packets. EasyTier does not claim wire-format compatibility with WireGuard and
does not introduce a new cipher.

## Configuration

- `chacha20-poly1305` is the canonical spelling and the default in every feature set.
- `chacha20` remains accepted as a legacy spelling and normalizes to
  `chacha20-poly1305`.
- `aes-gcm` and `aes-256-gcm` remain authenticated alternatives.
- XOR has been removed from the encryption choices. Use the explicit disable-encryption option
  only when plaintext operation is deliberately required.

Unknown algorithm names currently fall back to the secure default with a warning. CLI values are
validated before startup, while this fallback protects protocol input from selecting an insecure
cipher.

## Protocol boundary

The AEAD authenticates the encrypted payload and tag. The existing peer-manager header remains
outside the AEAD because relay nodes must update routing fields. Changing that boundary requires a
versioned packet protocol, not an ad-hoc AAD change.

EasyTier secure mode adds existing Noise handshakes and session protections:

- Noise XX with X25519, ChaChaPoly, and SHA-256 for direct peer authentication;
- Noise IK with the same standard primitives on the relay path;
- per-direction traffic keys, epoch rotation, sequence nonces, and replay windows.

This is still EasyTier's protocol construction, not the complete WireGuard protocol. Deployments
requiring peer identity authentication and replay protection should enable secure mode. A future
full WireGuard-compatible peer session would need a separately versioned handshake and packet
format rather than reusing the EasyTier framing under a WireGuard name.

## Verification

Minimal `tun` builds run the same authenticated cipher tests as full builds. Regression coverage
asserts the secure default, canonical and legacy parsing, XOR rejection, ciphertext round-trip,
tamper rejection, asymmetric peer algorithms, replay windows, epoch changes, and secure peer data
round-trips.

References:

- [Tailscale's userspace WireGuard engine](https://github.com/tailscale/tailscale/tree/main/wgengine)
- [WireGuard protocol and cryptography](https://www.wireguard.com/protocol/)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
