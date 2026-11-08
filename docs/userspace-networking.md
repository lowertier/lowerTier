# Userspace networking

LowTier can run without a kernel TUN or TAP interface.

This mode follows the Tailscale userspace networking model.
Applications use a local SOCKS5 proxy or HTTP proxy.
LowTier sends each proxy connection through its existing encrypted overlay route.

## Start the proxy

The following configuration starts both proxy protocols on one local TCP port.

```toml
[network]
name = "example"
secret_file = "example.secret"

[tun]
mode = "userspace"

[proxy]
socks5 = "127.0.0.1:1055"
http = "127.0.0.1:1055"

[[peer]]
uri = "quic://192.0.2.10:11012"
```

Start it without administrator privileges with `lowertier run -c example.toml`.

Replace the example network values before use.
Use an unprivileged local port above 1023.
The retained underlays are QUIC/H3, H2 over TLS, and WSS.
Use `quic://`, `tcp://`, and `wss://` URLs, respectively.
The `tcp://` scheme selects H2 over TLS.
Plain `ws://` and raw `udp://` underlays are rejected.

LowTier detects SOCKS5 and HTTP from the first client byte.
One shared listener avoids a second socket and a second userspace network stack.
Different listener addresses create separate sockets but still share one network stack.

Use these variables for applications that accept standard proxy variables.

```bash
export ALL_PROXY=socks5h://127.0.0.1:1055
export HTTP_PROXY=http://127.0.0.1:1055
export HTTPS_PROXY=http://127.0.0.1:1055
export all_proxy="$ALL_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
```

Use `socks5h` so LowTier resolves peer names inside the overlay.

The userspace mode selects all required internal settings.
The removed low-level CLI flags cannot select a partial userspace mode.
The mode also disables local DNS acceptance and UDP broadcast relay.
It rejects a socket mark because that option can require operating system privileges.

## Protocol behavior

The SOCKS5 listener supports TCP connections and the existing SOCKS5 UDP association path.
The HTTP listener supports `CONNECT` tunnels and normal HTTP proxy requests.
Both proxy protocols pass unresolved names to one central dial path.
The dial path resolves peer hostnames and qualified names from the current route table.
For other names, it uses the selected internet exit's system resolver when an exit route exists.
The DNS request and response use the authenticated overlay RPC channel.
DNS and data retain the same connection key for exit-group selection.
The dial path checks the resolved IP address against the normal route policy and ACLs.
An exit lookup failure does not fall back to local DNS.
A strict internet path also rejects DNS when its gateway is unavailable.
Without an internet exit, the dial path uses the local system resolver.
It uses the same peer, subnet, exit, service, and blackhole routes as packet forwarding.
The userspace overlay target path currently supports IPv4 destinations.
One SOCKS5 UDP association can use at most 256 active targets.

Only nodes with `routes.serve_exit = true` answer exit DNS requests.
The server accepts requests only from authenticated network peers.
Each instance permits at most 16 resolver workers and 16 IPv4 answers per request.
Requests have a five-second resolver deadline and an eight-second RPC deadline.
A resolver worker retains its capacity reservation until the operating system lookup returns, including after a request timeout.
The resolver enters the exit instance's network namespace on its own worker thread.
Application TLS still terminates at the application and origin server.

For an eligible direct QUIC connection, TCP proxy traffic uses an HTTP/3 CONNECT
stream on the existing authenticated connection. Both peers must advertise the
stream capability in the authenticated Noise admission transcript. The receiver
checks the source peer, destination address, and protected local ports before
opening the destination socket. Each connection retains bounded send/receive
storage and uses QUIC flow control and reliable delivery; it does not create a
second TCP stack for that stream.

This path currently applies when the local peer initiated QUIC, the destination
is the remote userspace peer's own IPv4 address, and neither endpoint has ACL
rules enabled. ACL-controlled destinations, relayed or mapped routes, peers
without the capability, and H2/WSS retain the packet path. Enabling ACL rules
stops an active direct stream so reconnecting uses the policy-aware packet path.

Each packet-path userspace TCP socket starts with an 8 KiB receive buffer and an 8 KiB transmit buffer.
Active buffers grow with measured application demand and TCP round-trip time.
Each buffer can grow to 8 MiB, subject to the shared process memory budget.
Growth reserves replacement storage before it copies the existing buffer.
If that reservation fails, the socket retains its current buffer.
Socket creation returns an error if the initial storage cannot fit within the budget.
Buffers remain allocated until the socket closes.
The memory budget does not limit total process RSS.

This mode does not add host routes.
It does not create a TUN or TAP interface.
It does not provide transparent `ping`, ARP, raw Ethernet, or complete L2 access to local applications.
Use TAP mode when applications require a complete Ethernet interface.

## Security

LowTier applies its configured overlay encryption after the local proxy accepts a connection.
The local proxy connection itself is plain TCP.
The proxy listener has no local authentication.
Bind the listener to `127.0.0.1` or `::1` unless a trusted firewall protects it.

HTTP destinations remain visible to an HTTP proxy by protocol design.
HTTPS applications normally use `CONNECT`, so application TLS protects the content end to end.
LowTier does not log proxy request payloads or complete request targets.

## Compatibility

Tailscale documents the same application proxy model for `--tun=userspace-networking`.
Tailscale also permits SOCKS5 and HTTP on one address.
See the [Tailscale userspace networking guide](https://tailscale.com/docs/concepts/userspace-networking).
See the [Tailscale daemon reference](https://tailscale.com/docs/reference/tailscaled).
See the [Tailscale router comparison](https://tailscale.com/kb/1177/kernel-vs-userspace-routers).

See the [measured LowTier results](performance/userspace-networking-results.md)
and the [matched HTTP/3 stream comparison](performance/userspace-stream-results-20261026.md).
The throughput probe caps each payload transfer at the time needed for 200 Mbps;
for example, its default 64 MiB payload has a 2.684-second transfer budget.
Proxy readiness has a separate 15-second deadline.
