# Automatic Ethernet interface

LowTier carries IP packets and complete Ethernet frames through one fabric protocol.

LowTier uses TAP when the operating system supports the required implementation.

Native TAP is available on Linux and FreeBSD.

LowTier uses TUN on other operating systems.

```toml
[flags]
dev_name = "et0"
enable_bridge = true

l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300
l2_flood_bps = 67108864

# Optional source ownership and frame policy.
l2_max_macs_per_peer = 256
l2_mac_move_hold_seconds = 30
l2_allowed_vlans = [0, 100, 200]
l2_allowed_ether_types = [2048, 2054, 34525, 35020]
```

Users do not select TAP or TUN.

Set `enable_bridge = true` on each native Ethernet bridge.
The command-line equivalent is `--enable-bridge`.
The default is false and does not authorize arbitrary Ethernet input.
Both endpoints must also pass the existing peer and bridge authorization checks.

Known unicast frames use the learned destination MAC.

Unknown unicast, broadcast, and multicast frames use bounded replication.

The forwarding database does not learn zero, broadcast, or multicast source addresses.

Entries expire after the configured age.

When capacity is exhausted, learning reclaims expired entries without requiring destination traffic.
Reclamation scans at most the configured table capacity once per second under pressure.

Entries are also removed when their peer disconnects.

IPv4 and IPv6 frames enter IP ACL parsing, including VLAN-tagged frames.
The optional bridge policy runs before local Ethernet transmission and before received Ethernet delivery.
Transit relays retain the existing encrypted forwarding and authorization rules.

The source limit counts MAC/VLAN entries per peer, including the local bridge.
Zero disables the source limit and the MAC movement hold time.
An active source retains ownership while the hold time applies.
Frames claiming that source from another peer or the local interface are dropped.
This also rejects reflected frames from an external bridge loop.
The hold time delays legitimate MAC movement and failover by the same interval.

Empty VLAN and EtherType lists permit all values.
VLAN zero includes untagged frames.
Every VLAN tag must be allowed, including inner QinQ tags.
EtherType policy checks the final type after the tags.
Compact IP received by TAP must also pass the untagged VLAN and IPv4/IPv6 EtherType policy.
The example permits IPv4, ARP, IPv6, and LLDP.
Use an empty EtherType list to permit arbitrary Ethernet protocols.
Restart the instance after changing bridge policy.

## Platform and topology limits

Linux and FreeBSD provide native Ethernet through TAP.
macOS and Windows use an IP-only TUN interface.
TUN does not provide raw Ethernet, VLAN bridging, or transparent non-IP protocols.
Use a Linux or FreeBSD bridge for those devices.

Use one active LowTier bridge per physical LAN segment.
LowTier does not implement STP or select a standby bridge.
MAC movement hold time limits reflected traffic, but does not replace physical loop prevention.
Configure physical switch loop protection before connecting redundant bridge paths.

The exact-frame harness covers QUIC, H2 (`tcp`), and WSS.
It checks VLAN, QinQ, arbitrary EtherTypes, multicast, MAC movement, reflected frames, and MTU boundaries.
Run `script/colima-l2/e2e.sh` with the documented Colima test environment.
Set `LOWTIER_L2_PROTOCOLS` to select one transport when investigating a failure.

The underlay policy still applies to all transport sockets.

LowTier ignores the removed `port_mode` and `interface_adapter` fields during migration.

Protocol version 4 does not use the old L2-TUN send path.
