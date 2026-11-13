# Getting started

This page installs lowertier, connects two machines, and keeps the node running as a service.

## Install

Pick one.

**Release archive.** Download the archive for your system from [Releases](https://github.com/lowertier/lowerTier/releases) and check it against `SHA256SUMS`.
Each archive holds `lowertier` (the node, the command-line tool, and the dashboard) and `lowertier-tracker`.
Windows archives also hold the driver files.

**Linux install script.** Installs into `/opt/lowertier`, writes `/opt/lowertier/config/default.toml`, and starts it with systemd (`lowertier@default`) or OpenRC.

```bash
curl -fsSL https://raw.githubusercontent.com/lowertier/lowerTier/main/script/install.sh | sudo bash -s -- install
```

The script also accepts `update` and `uninstall`.

**Build from source.** Install rustup and your platform's C build tools. Cargo picks the nightly toolchain pinned in `rust-toolchain.toml`.

```bash
git clone https://github.com/lowertier/lowerTier.git
cd lowerTier
cargo build --release --locked -p lowertier --bins
sudo install -m 0755 target/release/lowertier /usr/local/bin/lowertier
lowertier --version
```

The default build includes TAP/TUN, all three transports, the proxy, the `top` dashboard, and the web interface.
Add `--features full` for Magic DNS.

## Connect two machines

Machines find each other through BitTorrent trackers, so neither needs a fixed address or an open port.
Each machine announces a hash of the network name and secret to the trackers, gets back the addresses of other members, and connects to them.
Connected members then share what they know, punch direct paths through NAT, and relay for each other when a direct path fails.

`lowertier init` writes a configuration file, a random network secret, and an identity key, with mode 0600.

On Node A:

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

On Node B, run the same commands with `--ipv4 10.44.0.2/24`.
Before starting Node B, replace its `office.secret` with Node A's copy.
The secret is the network password. Copy the secret over a trusted channel.

Add a third machine, or a tenth, the same way. Each one needs only the network name, the secret, and the trackers.

## Check it

On Node B:

```bash
sudo lowertier peers
ping 10.44.0.1
```

The peer list shows connected nodes and their available transports.
A `direct` connection carries traffic between Node A and Node B without a relay.
`sudo lowertier discovery` shows each tracker's status and the addresses it returned.
If Node A started before Node B, discovery can depend on Node A's next announce.
See [discovery and NAT traversal](nat-traversal.md#how-long-discovery-takes).

## Connect to a known address

If one machine has a reachable address, the other can dial it directly, with or without trackers:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.2/24 --peer quic://192.0.2.10:11012
```

The dialed machine must accept TCP port `11010` (HTTP/2) and TCP and UDP port `11012` (WSS and QUIC).

## More checks

`sudo lowertier status` shows the node, its addresses, NAT type, trackers, listeners, and peers on one screen.
If something is wrong, `sudo lowertier doctor` checks each layer and prints a fix.
`sudo lowertier top` is a live dashboard, and `sudo lowertier gui` opens the [web interface](web-interface.md).

The commands find the running node by themselves.
A node run as root keeps its control token readable only by root, so the commands need `sudo`.
Set `control.token_group` to let a Unix group manage the node without `sudo`.

## Join codes

Builds newer than 0.01 can skip copying the secret.
Create a join code in the web interface under **Add machine**, then on the new machine:

```bash
lowertier init office.toml --join lt1.xxxx
```

On Linux, the install script takes the same code and starts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/lowertier/lowerTier/main/script/install.sh | sudo bash -s -- install --join lt1.xxxx
```

A code carries the network name, the network secret or a signed credential, and the peers to dial first.
See [join codes](web-interface.md#join-codes).

## Run as a service

```bash
sudo lowertier service install -- -c /etc/lowertier/office.toml
sudo lowertier service status
```

`service install` registers `lowertier run` with the given arguments with the system service manager.
`service start`, `stop`, and `uninstall` do what they say.

## Next

- No root on this machine? Use [proxy mode](proxy-mode.md).
- Bridge a physical LAN into the network: [Ethernet](ethernet.md).
- Peers behind NAT with no public address: [NAT traversal](nat-traversal.md).
- Every option: [configuration](configuration.md) and the [option reference](options.md).
