# Ethernet interface adapter

LowTier carries IP packets and complete Ethernet frames through one fabric protocol.

Use the TAP adapter when an application requires ARP, VLAN, LLDP, broadcast, or other Ethernet data.

Native TAP is available on Linux and FreeBSD.

Use the TUN adapter on systems that provide only an IP interface.

```toml
[flags]
interface_adapter = "tap"
dev_name = "et0"

l2_fdb_capacity = 16384
l2_fdb_age_seconds = 300
l2_flood_bps = 67108864
```

Use this configuration for an IP interface:

```toml
[flags]
interface_adapter = "tun"
```

Use `interface_adapter = "auto"` for the platform default.

The equivalent CLI option is `--interface-adapter`.

Known unicast frames use the learned destination MAC.

Unknown unicast, broadcast, and multicast frames use bounded replication.

The forwarding database does not learn zero, broadcast, or multicast source addresses.

Entries expire after the configured age.

Entries are also removed when their peer disconnects.

Ethernet frames do not enter IP ACL parsing.

The underlay policy still applies to all transport sockets.

The old `port_mode` field remains a migration alias.

The old `routed` and `compatible-ethernet` values map to `tun`.

The old `ethernet` value maps to `tap`.

Protocol version 4 does not use the old L2-TUN send path.
