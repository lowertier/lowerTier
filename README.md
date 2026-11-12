# lowertier

lowertier puts your machines on one private network, wherever they are and however many NATs sit in front of them.
Machines find each other through public BitTorrent trackers: no coordination server, no fixed address, no port forwarding.

- **Finds its own peers.** Give each machine the network name, its secret, and a few public trackers. Members discover each other's current addresses, punch direct paths through NAT, and relay for each other when a direct path fails.
- **Real Ethernet.** Linux and FreeBSD nodes share a Layer 2 segment: ARP, VLANs, multicast, and any EtherType cross unchanged. macOS and Windows join the same network over IP.
- **No root needed.** Any machine can join through a local SOCKS5 or HTTP proxy instead of a network device.
- **Standard transports.** Traffic runs over QUIC (HTTP/3), HTTP/2, or WebSocket, all on TLS 1.3, and can share port 443 with a real website.
- **One binary.** `lowertier` runs the node, manages it from the command line, and serves a web interface.

Documentation: **[lowertier.github.io](https://lowertier.github.io)**, or [docs/](docs/README.md) in this repository.

## Install

Download a build for Linux, macOS, or Windows from [Releases](https://github.com/lowertier/lowerTier/releases).
On Linux, this installs the latest release as a service:

```bash
curl -fsSL https://raw.githubusercontent.com/lowertier/lowerTier/main/script/install.sh | sudo bash -s -- install
```

To build from source, see [getting started](docs/getting-started.md#install).

## Connect two machines

On the first machine, write a configuration and add the trackers:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.1/24
cat >> office.toml <<'EOF'

[discovery]
trackers = [
  "udp://tracker.opentrackr.org:1337/announce",
  "http://tracker.opentrackr.org:1337/announce",
  "https://tracker.nekomi.cn:443/announce",
]
EOF
sudo lowertier run -c office.toml
```

On the second machine, do the same with `--ipv4 10.44.0.2/24`, then replace its `office.secret` with the first machine's copy before starting it.
The secret is the network password: move it over a channel you trust.

Neither machine needs to know the other's address. Once they find each other, `sudo lowertier status` lists the other machine and `ping 10.44.0.1` works.
In our tests, machines behind different NATs connected directly 2 to 45 seconds after the second one started.
Two NATs that both refuse direct paths need a third member that both can reach; it relays.

A tracker learns the network's rendezvous hash and the members' public addresses, never the secret or the traffic. See [discovery and NAT traversal](docs/nat-traversal.md).
If you know an address, `--peer quic://192.0.2.10:11012` on `init` dials it directly, with or without trackers.

[Getting started](docs/getting-started.md) continues with services, checks, and join codes.

## Documentation

| Guide | Covers |
| --- | --- |
| [Configuration](docs/configuration.md) | The config file, changing a running node, peers, listeners, access control |
| [Commands](docs/commands.md) | Every command, JSON output, exit codes |
| [Ethernet](docs/ethernet.md) | Layer 2 between nodes, bridging a LAN |
| [Proxy mode](docs/proxy-mode.md) | Joining without root |
| [Discovery and NAT traversal](docs/nat-traversal.md) | Trackers, hole punching, your own tracker, measured results |
| [Routing](docs/routing.md) and [paths](docs/paths.md) | Relays, exit nodes, subnets, chosen routes |
| [Camouflage](docs/camouflage.md) | Port 443 with a website, CDNs |
| [Web interface](docs/web-interface.md) | The management page and join codes |
| [Remote control](docs/remote-control.md) | Managing and SSH into other nodes |
| [Security](docs/security.md) | Admission, encryption, what observers see |
| [Option reference](docs/options.md) | Every option |

## Status

Release 0.01 is the first release. Peers must run the same major version: release 0.01 uses peer version 0.
Configuration and protocol may still change between releases without a migration path.
The protocol has not had an external security audit.

lowertier began as a fork of [EasyTier](https://github.com/EasyTier/EasyTier).

## License

[LGPL-3.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) to work on the code.
