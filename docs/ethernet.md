# Ethernet

On Linux and FreeBSD, lowertier gives each node a TAP device, and IP traffic works with no further setup.
Nodes with `l2.bridge = true` also exchange complete Ethernet frames, like ports on one switch:
ARP, VLAN and QinQ tags, LLDP, broadcast, multicast, and any EtherType pass between them unchanged.
macOS and Windows join the same network through a TUN device, which carries IP only.

lowertier picks TAP or TUN from the operating system. There is nothing to choose.

## Turn on full Ethernet

```toml
[l2]
bridge = true
```

Set it on every node that should send or receive complete frames, including any node whose TAP device you bridge to a physical LAN.
Without it, a node accepts no arbitrary Ethernet input, and peers do not send it broadcast or unknown-unicast frames.
Bridge the TAP device to a LAN with your system's tools; lowertier does not create the bridge.

Use one bridging node per physical LAN segment. lowertier does not run STP, so two bridges into one LAN make a loop.
While a MAC address belongs to one port, frames that claim it from another port are dropped, which stops reflected frames.
Still, turn on loop protection on the physical switch before you add redundant bridges.

## Limit what crosses

```toml
[l2]
bridge = true
flood_bytes_per_second = "64MiB"   # broadcast, multicast, and unknown unicast; 0 disables the limit
max_macs_per_peer = 256            # 0 disables the limit
mac_move_hold = "5s"               # a MAC must stay quiet this long before it may move to another peer
vlans = [0, 100, 200]              # empty allows all; 0 means untagged
ether_types = [2048, 2054, 34525, 35020]   # IPv4, ARP, IPv6, LLDP; empty allows all
```

Keep a finite flood limit on any real network.
Every VLAN tag must be allowed, including inner QinQ tags. Restart the instance after changing these.

## How frames travel

The node learns source MAC addresses into a forwarding table, 16,384 entries by default, each kept 5 minutes (`l2.fdb_capacity`, `l2.fdb_age`).
A frame for a known address goes to one peer. Broadcast, multicast, and unknown unicast go to every peer that accepts Ethernet input, within the flood limit.

Ordinary IP traffic travels as compact IP packets without the Ethernet header, on TAP and TUN alike.
Frames that need their Ethernet header keep it: non-IP protocols, VLAN-tagged frames, and unicast from bridged hosts.

With `bridge = true`, the TAP MTU is at least 1516 bytes, enough for a 1500-byte payload with four VLAN tags.
Over QUIC, large frames are split across datagrams; losing one piece loses the frame. HTTP/2 and WSS carry whole frames.

`lowertier l2 fdb` lists learned addresses and `lowertier l2 stats` shows the counters.

The [forwarding rules](design/l2-forwarding.md) describe learning, flooding, MAC ownership, and the test harness in detail.

## TUN limits

TUN on macOS and Windows carries IPv4 and IPv6 only: no ARP, no VLAN bridging, no non-IP protocols.
A Linux or FreeBSD node can bridge those devices instead.
