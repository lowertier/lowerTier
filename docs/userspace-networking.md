# Userspace networking

LowTier can run without a kernel TUN or TAP interface.

This mode follows the Tailscale userspace networking model.
Applications use a local SOCKS5 proxy or HTTP proxy.
LowTier sends each proxy connection through its existing encrypted overlay route.

## Start the proxy

The following command starts both proxy protocols on one local TCP port.

```bash
lowertier-core \
  --tun=userspace-networking \
  --socks5-server=127.0.0.1:1055 \
  --outbound-http-proxy-listen=127.0.0.1:1055 \
  --network-name=example \
  --network-secret='replace-this-secret' \
  --peers=udp://192.0.2.10:11010
```

Replace the example network values before use.
Use an unprivileged local port above 1023.
Published binaries support UDP, TCP, and QUIC underlay connections.
Full source builds can also support WebSocket connections.
Some other underlay modes can require extra operating system privileges.

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
It uses system DNS only when the route table has no matching peer name.
It uses the same peer, subnet, exit, service, and blackhole routes as packet forwarding.
The userspace overlay target path currently supports IPv4 destinations.
One SOCKS5 UDP association can use at most 256 active targets.

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

See the [measured LowTier results](performance/userspace-networking-results.md).
