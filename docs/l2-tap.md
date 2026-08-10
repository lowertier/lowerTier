# Ethernet fabric

LowTier can carry complete Ethernet frames through its existing peer routing,
relay, compression, encryption, and underlay transport stack. This is useful
when nodes need L2 behavior such as ARP, IPv6 neighbour discovery, broadcast,
or a simple bridged network.

Native TAP is available on Linux and FreeBSD. macOS `utun`, iOS Network
Extension, Android VPN APIs, and Windows Wintun are IP-only interfaces. Use
`port_mode = "compatible-ethernet"` on those edges to carry local IPv4 and IPv6 packets
through the Ethernet overlay without pretending the operating-system device is
a TAP interface.

LowTier provides three network profile names through `port_mode`:

- `routed` selects the IP-only TUN path.
- `ethernet` requires native TAP and provides complete Ethernet behavior.
- `compatible-ethernet` selects an IP-only TUN edge with an Ethernet overlay.

The existing `l3`, `tap`, and `l2-tun` names remain valid aliases.

Linux and FreeBSD use native Ethernet by default.
Other systems use compatible Ethernet by default.
Select `routed` to use the L3 path.

The `ethernet` profile fails when native TAP is unavailable.

LowTier does not silently replace complete Ethernet behavior with L2-TUN.

```toml
[flags]
port_mode = "ethernet"
dev_name = "et0"

# Bounded source-MAC forwarding database.
l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300

# Bytes per second for unknown-unicast, multicast, and broadcast replication.
# Zero removes this limit. Keep a finite limit in production.
l2_flood_bps = 67108864
```

For an IP-only edge, change only the mode:

```toml
[flags]
port_mode = "compatible-ethernet"
```

`compatible-ethernet` reserves the Ethernet header in the receive buffer and resolves normal
unicast with the existing LowTier IP route table. It still targets only one
peer, but uses an Ethernet broadcast destination so a native TAP kernel accepts
the routed packet. A locally administered source MAC is derived from the peer
ID. The TUN edge answers ARP for its own overlay IPv4 address, which allows TAP
and TUN edges to communicate without flooding normal data. Broadcast and
multicast retain the bounded fabric fanout. On delivery, only IPv4 (`0x0800`)
and IPv6 (`0x86dd`) frames are written to the TUN device. LLDP, VLAN-tagged
frames, and other non-IP Ethernet protocols require native `tap`.

The equivalent CLI options are `--port-mode`, `--l2-fdb-capacity`,
`--l2-fdb-age-seconds`, and `--l2-flood-bps`. They also accept the matching
`ET_` environment variables.

Use `--port-mode ethernet` for complete L2 behavior.

Known unicast frames use the learned destination MAC and send once to that
peer. The normal LowTier route table can still deliver that logical peer over
multiple hops. Unknown unicast, broadcast, and multicast frames replicate only
to routes whose peer advertises Ethernet input. The FDB never learns zero,
broadcast, or multicast source MAC addresses. Entries age out and are removed
when their peer disconnects.

Ethernet frames do not enter IP ACL parsing. Underlay deny-interface and deny
CIDR policy remains separate and still protects handshake, discovery, relay,
and data sockets. Restart the instance after any port-mode or underlay-policy
change.

The default direct transport is UDP. If raw UDP cannot establish an eligible
path, LowTier next tries QUIC and then TCP. An explicit `default_protocol`
still takes first priority. All three transports use the same strict underlay
interface and CIDR checks.

Run `script/colima-l2/e2e.sh` for QEMU-backed TAP, L3, L2-TUN, and mixed-edge
checks. A native macOS-to-Colima UDP test requires an UDP-capable Colima port
forwarder, for example `colima -p lowertier-l2 start --port-forwarder grpc`.
The default SSH forwarder carries TCP only.

Avoid using unlimited flood traffic on a large mesh. L2 broadcast is necessary
for discovery, but its replication cost grows with the number of eligible peers.
