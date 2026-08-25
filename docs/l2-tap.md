# Automatic Ethernet interface

LowTier carries IP packets and complete Ethernet frames through one fabric protocol.

LowTier uses TAP when the operating system supports the required implementation.

Native TAP is available on Linux and FreeBSD.

LowTier uses TUN on other operating systems.

```toml
[flags]
dev_name = "et0"

l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300
l2_flood_bps = 67108864
```

Users do not select TAP or TUN.

Known unicast frames use the learned destination MAC.

Unknown unicast, broadcast, and multicast frames use bounded replication.

The forwarding database does not learn zero, broadcast, or multicast source addresses.

Entries expire after the configured age.

Entries are also removed when their peer disconnects.

Ethernet frames do not enter IP ACL parsing.

The underlay policy still applies to all transport sockets.

LowTier ignores the removed `port_mode` and `interface_adapter` fields during migration.

Protocol version 4 does not use the old L2-TUN send path.
