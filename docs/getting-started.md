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

`lowertier init` writes a configuration file, a random network secret, and an identity key.
The secret and key files get mode 0600 and sit next to the configuration.

On machine A:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.1/24
sudo lowertier run -c office.toml
```

Copy `office.secret` from A to B over a channel you trust. The secret is the network password.
On machine B, replacing `192.0.2.10` with A's address:

```bash
lowertier init office.toml --network office --ipv4 10.44.0.2/24 --peer quic://192.0.2.10:11012
cp /path/to/copied/office.secret office.secret
sudo lowertier run -c office.toml
```

Machine A must accept TCP port `11010` (HTTP/2) and TCP and UDP port `11012` (WSS and QUIC).
B only dials out, so it needs no open ports.

## Check it

On machine B:

```bash
sudo lowertier status
ping 10.44.0.1
```

`status` shows the node and its peers on one screen:

```text
node      node-b · peer 2006876804 · default @ 127.0.0.1:15888 · 0.01
address   10.44.0.2/24
nat       udp symmetric · tcp symmetric · public 203.0.113.7
discovery no trackers configured
listen    h2://0.0.0.0:11010  quic://0.0.0.0:11012  wss://0.0.0.0:11012/ws
relay     policy hop · transit allow · relayed 0 B · drops 0

PEER     ADDRESS        VIA      TRANSPORT       RTT   LOSS   RATE   SESSION     ID
node-a   10.44.0.1/24   direct   h2+quic+wss   31 ms      -      -   key-bound   2114138755
```

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
