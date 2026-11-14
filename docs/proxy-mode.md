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
- TCP to the own address of a directly connected proxy-mode peer can run over a QUIC stream instead of packets, when this node dialed the QUIC connection and neither side has ACL rules.

Targets inside the network must be IPv4 for now.

## What does not

Proxy mode adds no host routes and creates no interface. There is no `ping`, ARP, raw Ethernet, or transparent access for applications that ignore proxy settings.
Use the kernel interface (`tun.mode = "kernel"`) when you need those.

## Security

The proxy has no authentication. Bind it to `127.0.0.1` or `::1` unless a firewall you trust protects it.
Traffic between the application and the proxy is plain TCP on the local machine. Everything after the proxy is encrypted like any other lowertier traffic.

HTTP proxy requests reveal their destination to the proxy, as HTTP proxies always do. HTTPS uses `CONNECT`, so the application's TLS runs end to end.
lowertier does not log request payloads or full request targets.

## More

- [Userspace proxy internals](design/userspace-proxy.md): name resolution, dialing, buffers, and the QUIC stream path.
