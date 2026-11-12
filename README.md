# lowertier

lowertier puts your machines on one private network, wherever they are and however many NATs sit in front of them.

- **Real Ethernet.** Linux and FreeBSD nodes share a Layer 2 segment: ARP, VLANs, multicast, and any EtherType cross unchanged. macOS and Windows join the same network over IP.
- **No root needed.** Any machine can join through a local SOCKS5 or HTTP proxy instead of a network device.
- **Gets through.** Peers punch through NAT over UDP and TCP, find each other through BitTorrent trackers if you like, and relay for each other when a direct path fails.
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

On machine A:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.1/24
sudo lowertier run -c office.toml
```

Copy `office.secret` from A to B over a channel you trust. Then on machine B, with A's address:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.2/24 --peer quic://192.0.2.10:11012
cp /path/to/copied/office.secret office.secret
sudo lowertier run -c office.toml
```

A must accept TCP port 11010 and TCP and UDP port 11012. Then, from B:

```bash
ping 10.44.0.1
sudo lowertier status
```

[Getting started](docs/getting-started.md) continues with join codes, services, and checks.

## Documentation

| Guide | Covers |
| --- | --- |
| [Configuration](docs/configuration.md) | The config file, changing a running node, peers, listeners, access control |
| [Commands](docs/commands.md) | Every command, JSON output, exit codes |
| [Ethernet](docs/ethernet.md) | Layer 2 between nodes, bridging a LAN |
| [Proxy mode](docs/proxy-mode.md) | Joining without root |
| [NAT traversal](docs/nat-traversal.md) | Hole punching, trackers, your own tracker |
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
