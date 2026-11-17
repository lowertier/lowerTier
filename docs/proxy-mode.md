# Proxy mode

Proxy mode joins a machine to the network without root and without a TUN or TAP device.
Applications reach the network through a local SOCKS5 or HTTP proxy. It works like Tailscale's userspace networking.

## Start it

```toml
[network]
name = "office"
secret_file = "office.secret"

[tun]
mode = "userspace"

[proxy]
socks5 = "127.0.0.1:1055"
http = "127.0.0.1:1055"

[[peer]]
uri = "quic://192.0.2.10:11012"
```

```bash
lowertier run -c office.toml
```

Both proxies can share one port: the listener tells SOCKS5 from HTTP by the first byte.
Use a port above 1023 so no privileges are needed.

## Point applications at it

```bash
export ALL_PROXY=socks5h://127.0.0.1:1055
export HTTP_PROXY=http://127.0.0.1:1055
export HTTPS_PROXY=http://127.0.0.1:1055
```

Some programs read only the lowercase names (`all_proxy`, `http_proxy`, `https_proxy`); set those too.
Use `socks5h` so peer names resolve inside the network, for example `curl http://node-a/`.

## What works

UDP NAT entries include both overlay peer IDs and the source and destination sockets.
A restarted peer can reuse a UDP socket tuple without sending replies to the previous peer ID.
Fragment reassembly also separates peers, including fragments with identical IPv4 addresses and packet IDs.

- SOCKS5 TCP connections and UDP association, up to 256 targets per association.
- HTTP `CONNECT` tunnels and ordinary HTTP proxy requests.
- Peer names, peer addresses, exported subnets, and the internet through an exit node.
  With an exit, names outside the network resolve on the exit.
- Routes, ACLs, and paths apply as they do for kernel-mode traffic.
- TCP to a directly connected proxy-mode peer can use native H2 or QUIC streams.
  The destination must be the remote peer's own IPv4 address.
  This node must have initiated the transport connection.
  Both endpoints must have ACL rules disabled.

Targets inside the network must be IPv4 for now.

## Native TCP streams

Set the transport mode on both peers:

```toml
[transport.h2]
tcp_proxy = "auto"

[transport.quic]
tcp_proxy = "auto"
```

| Mode | New TCP flows |
| --- | --- |
| `off` | Use the packet path. |
| `on` | Require native streams for eligible direct flows. Report native capability, capacity, and open errors. |
| `auto` | Use native streams when scope, capacity, and health permit. Permit safe packet fallback before destination admission. |

QUIC defaults to `auto`.
H2 defaults to `off`.
The retained test fleet explicitly selects H2 `auto`.
Mode changes apply to new flows.
Admitted streams continue after a mode change.
Authentication loss or an ACL change can stop an admitted stream.

The remote userspace peer checks the source identity and destination before opening a local socket.
Protected GUI ports, kernel peers, and other destinations outside the native scope retain the packet path.
Mapped routes, relays, and WSS also retain the packet path.
H2 and H3 servers cannot initiate native HTTP request streams.
In `auto`, that direction uses packets.
In `on`, an eligible native open from the server side returns an error.

An ambiguous error or timeout fails the current flow.
The proxy does not replay application data.
In `auto`, an endpoint refusal or native open failure starts a cooldown for later flows.
The cooldown grows from two seconds to thirty seconds.
One real flow can attempt recovery after the cooldown.
No synthetic probe runs in the background.
Destination and policy failures do not reduce native transport health.

H2 streams share one TCP carrier.
A lost outer TCP segment can delay all streams.
The automatic policy does not repair that carrier by selecting packets on the same connection.
QUIC uses its native stream and datagram facilities.
Its automatic policy has the same admission and no-replay boundaries.
Packet fallback still needs packet-stack resources.
It does not repair a failed QUIC connection.
WSS retains packet forwarding and has no native TCP proxy mode.

## What does not

Proxy mode adds no host routes and creates no interface. There is no `ping`, ARP, raw Ethernet, or transparent access for applications that ignore proxy settings.
Use the kernel interface (`tun.mode = "kernel"`) when you need those.

## Security

The proxy has no authentication. Bind it to `127.0.0.1` or `::1` unless a firewall you trust protects it.
SOCKS5 clients must offer the no-authentication method (`0x00`).
The proxy returns `0xff` if the client does not offer that method.
Traffic between the application and the proxy is plain TCP on the local machine. Everything after the proxy is encrypted like any other lowertier traffic.

HTTP proxy requests reveal their destination to the proxy, as HTTP proxies always do. HTTPS uses `CONNECT`, so the application's TLS runs end to end.
lowertier does not log request payloads or full request targets.

## More

- [Userspace proxy internals](design/userspace-proxy.md): name resolution, dialing, buffers, and native stream admission.
- [H2 stream cost model](design/h2-native-proxy.md): overhead, flow control, and automatic policy.
- [QUIC admission policy](design/quic-proxy-policy.md): safe fallback, cooldown, and WSS limits.
