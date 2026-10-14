# Lean core

LowTier keeps QUIC with HTTP/3 CONNECT-IP and DATAGRAM, TCP with TLS and HTTP/2, and WSS.
TCP lanes remain available. QUIC and TCP NAT traversal remain available.
Windows, macOS, iOS, and the `macos-ne` feature remain supported in the source.
The FFI crate belongs to the workspace. Its `ffi-dataplane` feature remains available.

## Removed components

The core no longer includes the web console client or the managed FFI config-server client.
The `--config-server` option and `ET_CONFIG_SERVER` are removed.
JSON RPC and the instance-management RPC interface remain available.

Unused UDP vector I/O, insecure TLS helpers, UPnP/NAT-PMP mapping, legacy UDP RPCs, and link envelopes are removed.
The `disable_upnp` option is removed. Android and OHOS paths are removed.
Ring tunnels used by tests now use session AEAD after authentication.
The production TLS exporter bindings remain unchanged.

Magic DNS retains active listeners, packet handling, and Windows and macOS system configuration.
The unused Linux DNS configurator stub and orphan test helpers are removed.
Linux system DNS configuration remains unavailable, as before.

## Cryptography and compression

Ring provides ChaCha20-Poly1305, AES-128-GCM, and AES-256-GCM.
Algorithm names and ciphertext, tag, and nonce layouts remain unchanged.
The optional `aes-gcm` and `openssl-crypto` backends are removed.
The `full` feature now enables magic DNS.

Payload compression and the `zstd` feature are removed.
RPC peers advertise no compression. A remote compression advertisement still permits uncompressed replies.
Compressed RPC bodies produce an unsupported-compression error.
Compressed overlay packets are discarded. The peer connection remains active.

## QUIC FEC

QUIC FEC encoding, recovery, alternate-path parity, and resource budgets are removed.
Peers advertise zero FEC capabilities. Receivers discard retired FEC packet types 23 and 24.
These packet type values must not be reused.

TOML configuration loading rejects these removed keys with an error that names the key:

- `quic_datagram_fec_parity`
- `quic_datagram_alternate_path_parity`
- `data_compress_algo`

Removed protobuf fields reserve their numbers and names.
The retired direct-connector RPC method index 2 is documented in the schema.
Protobuf service declarations do not support `reserved` statements.

Historical performance records describe earlier binaries. Their FEC and compression settings no longer apply to the current core.
