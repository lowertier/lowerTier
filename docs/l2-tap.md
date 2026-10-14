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
l2_flood_bytes_per_second = 67108864

# Default source ownership limits and optional frame policy.
l2_max_macs_per_peer = 256
l2_mac_move_hold_seconds = 5
l2_allowed_vlans = [0, 100, 200]
l2_allowed_ether_types = [2048, 2054, 34525, 35020]
```

Users do not select TAP or TUN.

Set `enable_bridge = true` on each native Ethernet bridge.
The command-line equivalent is `--enable-bridge`.
The default is false and does not authorize arbitrary Ethernet input.
Both endpoints must also pass the existing peer and bridge authorization checks.

Known unicast frames use the learned destination MAC.
Bridged IPv4 and IPv6 unicast retain both original Ethernet MAC addresses.
A learned LAN destination takes priority over automatic proxy and exit routes.
IP ACL rules, explicit packet destinations, and blackhole service routes still apply.
LowTier creates synthetic MAC addresses only when it constructs Ethernet for compact IP packets.

Unknown unicast, broadcast, and multicast frames use bounded replication.
The outgoing limit counts all replicated packet bytes, including the peer header.
A monotonic token bucket refills continuously and permits at most one second of initial burst credit.
Each authenticated origin peer also has an ingress bucket before TAP delivery.
The ingress bucket counts complete Ethernet frame bytes.
Compact IP broadcast and multicast share that bucket and include the reconstructed Ethernet header.
Ingress unknown unicast uses the receiving node's FDB state.
Zero disables both byte limits.
The retired TOML key `l2_flood_bps` produces an error naming `l2_flood_bytes_per_second`.
The new CLI option is `--l2-flood-bytes-per-second`.
The new environment variable is `ET_L2_FLOOD_BYTES_PER_SECOND`.

The forwarding database does not learn zero, broadcast, or multicast source addresses.

Entries expire after the configured age.

When capacity is exhausted, learning reclaims expired entries without requiring destination traffic.
Reclamation scans at most the configured table capacity once per second under pressure.

Route publication removes entries whose peer loses reachability or bridge authorization.
Entries are also removed when their peer disconnects.
A stale known destination uses bounded unknown-unicast forwarding.

IPv4 and IPv6 frames enter IP ACL parsing, including VLAN-tagged frames.
The optional bridge policy runs before local Ethernet transmission and before received Ethernet delivery.
Transit relays retain the existing encrypted forwarding and authorization rules.

The source limit counts MAC/VLAN entries per peer, including the local bridge.
The defaults permit 256 entries per peer and hold source ownership for five seconds.
Set either ownership limit to zero to disable that limit.
An active source retains ownership while the hold time applies.
Frames claiming that source from another peer or the local interface are dropped.
This also rejects reflected frames from an external bridge loop.
An incoming flood with a source learned on the local TAP is dropped during the ownership hold time.
The hold time delays legitimate MAC movement and failover by the same interval.

Empty VLAN and EtherType lists permit all values.
VLAN zero includes untagged frames.
Every VLAN tag must be allowed, including inner QinQ tags.
EtherType policy checks the final type after the tags.
Compact IP received by TAP must also pass the untagged VLAN and IPv4/IPv6 EtherType policy.
With `enable_bridge = false`, ordinary TAP IP traffic skips source learning and bridge flood admission.
Explicit VLAN and EtherType lists still apply in this mode.
The example permits IPv4, ARP, IPv6, and LLDP.
Use an empty EtherType list to permit arbitrary Ethernet protocols.
Restart the instance after changing bridge policy.

## Platform and topology limits

Linux and FreeBSD provide native Ethernet through TAP.
macOS and Windows use an IP-only TUN interface.
TUN does not provide raw Ethernet, VLAN bridging, or transparent non-IP protocols.
Use a Linux or FreeBSD bridge for those devices.

With `enable_bridge = true`, TAP MTU is at least 1516 bytes.
This permits a 1500-byte LAN payload with all four supported VLAN tags.
The configured MTU can raise this minimum for a larger LAN.
Encryption overhead does not reduce bridge TAP MTU.
QUIC fragments oversized packets across DATAGRAM frames at the current path limit.
H2 and WSS carry complete packets through stream framing.
Loss of a QUIC fragment can discard the complete packet.

Use one active LowTier bridge per physical LAN segment.
LowTier does not implement STP or select a standby bridge.
MAC movement hold time limits reflected traffic, but does not replace physical loop prevention.
Configure physical switch loop protection before connecting redundant bridge paths.

The exact-frame harness covers QUIC, H2 (`tcp`), and WSS.
It checks VLAN, QinQ, arbitrary EtherTypes, multicast, MAC movement, reflected frames, and MTU boundaries.
Run `script/colima-l2/e2e.sh` with the documented Colima test environment.
Set `LOWTIER_L2_PROTOCOLS` to select one transport when investigating a failure.

The internal `PeerManager::l2_snapshot()` API returns live FDB entries and drop counters.
The `PeerManager::l2_counters()` API reads counters without scanning the FDB.
The counters cover outgoing flood limits, ingress flood limits, local reflections, and ingress source policy.
Snapshots can change during collection because packet processing continues.

The underlay policy still applies to all transport sockets.

LowTier rejects the removed `port_mode` and `interface_adapter` fields when it loads TOML configuration.
Remove these keys to use automatic platform adapter selection.

Protocol version 4 does not use the old L2-TUN send path.
