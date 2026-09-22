# Local changes

Source: `https://github.com/smoltcp-rs/smoltcp.git`.
Revision: `0a926767a68bc88d5512afefa7529c5ecdade4ea`.

The local changes add TCP buffer growth and a read-only RTT measurement.
Growth preserves sequence numbers, unacknowledged bytes, and out-of-order receive data.
The receive limit determines window scaling before connection establishment.
LowTier controls allocation and memory admission outside this library.
