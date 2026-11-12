//! Public configuration schema.
//!
//! Every option has one dotted path. The TOML file, `run --set`, `lowertier set`, and the
//! Control API field masks all use these paths. `to_internal` and `to_public` translate between
//! this layout and the internal `Config` representation, so runtime getters stay unchanged.

use anyhow::{Context as _, bail};
use toml::{Table, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Int,
    Str,
    Path,
    Enum(&'static [&'static str]),
    StrList,
    IntList,
    /// Seconds. Accepts `30`, `30s`, `5m`, `1h`.
    Duration,
    /// Bit/s. Accepts `8000000`, `8Mbit`, `1.5Gbit`.
    BitRate,
    /// Bytes. Accepts `1048576`, `1MiB`, `64KB`.
    Bytes,
    /// A proxy listener. Accepts `host:port` or a URL with the given scheme.
    Proxy(&'static str),
    /// An opaque table copied as is, except for children that have their own paths.
    Table,
    /// An array of tables. Field names are translated by `TABLE_FIELDS`.
    Tables,
}

impl Kind {
    pub fn unit(self) -> Option<&'static str> {
        match self {
            Kind::Duration => Some("s"),
            Kind::BitRate => Some("bit/s"),
            Kind::Bytes => Some("bytes"),
            _ => None,
        }
    }

    pub fn describe(self) -> String {
        match self {
            Kind::Bool => "bool".into(),
            Kind::Int => "integer".into(),
            Kind::Str => "string".into(),
            Kind::Path => "path".into(),
            Kind::Enum(values) => values.join(" | "),
            Kind::StrList => "list of strings".into(),
            Kind::IntList => "list of integers".into(),
            Kind::Duration => "duration (30, 30s, 5m, 1h)".into(),
            Kind::BitRate => "bit rate (8000000, 8Mbit, 1Gbit)".into(),
            Kind::Bytes => "size (1048576, 256KiB, 1GiB)".into(),
            Kind::Proxy(scheme) => format!("host:port or {scheme}://host:port"),
            Kind::Table => "table".into(),
            Kind::Tables => "array of tables".into(),
        }
    }
}

/// When a changed value takes effect on a running node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Apply {
    Live,
    NewConnections,
    /// New connections, but QUIC listeners cache it until the instance restarts.
    QuicRestart,
    Restart,
    /// Process-wide settings that need a process restart.
    Process,
}

impl Apply {
    pub fn as_str(self) -> &'static str {
        match self {
            Apply::Live => "live",
            Apply::NewConnections => "new connections",
            Apply::QuicRestart => "new connections (QUIC: instance restart)",
            Apply::Restart => "instance restart",
            Apply::Process => "process restart",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Map {
    /// The internal path equals the public path.
    Same,
    To(&'static str),
    /// A positive public bool stored as an internal `disable_*` bool.
    Not(&'static str),
    Custom,
}

#[derive(Debug)]
pub struct OptionSpec {
    pub path: &'static str,
    pub kind: Kind,
    pub map: Map,
    pub apply: Apply,
    pub default: &'static str,
    pub secret: bool,
    pub doc: &'static str,
}

const fn opt(
    path: &'static str,
    kind: Kind,
    map: Map,
    apply: Apply,
    default: &'static str,
    doc: &'static str,
) -> OptionSpec {
    OptionSpec {
        path,
        kind,
        map,
        apply,
        default,
        secret: false,
        doc,
    }
}

const fn secret(path: &'static str, map: Map, apply: Apply, doc: &'static str) -> OptionSpec {
    OptionSpec {
        path,
        kind: Kind::Str,
        map,
        apply,
        default: "",
        secret: true,
        doc,
    }
}

use Apply::*;
use Kind::*;
use Map::*;

const TRANSPORTS: &[&str] = &["quic", "h2", "wss"];

pub static OPTIONS: &[OptionSpec] = &[
    opt(
        "node.enabled",
        Bool,
        To("enabled"),
        Live,
        "true",
        "Run this instance. A false value keeps its persistent configuration available for management.",
    ),
    opt(
        "node.hostname",
        Str,
        To("hostname"),
        Live,
        "",
        "Name shown to peers. Defaults to the system host name.",
    ),
    opt(
        "node.instance_name",
        Str,
        To("instance_name"),
        Restart,
        "default",
        "Local instance name. Distinguishes instances in one process.",
    ),
    opt(
        "node.instance_id",
        Str,
        To("instance_id"),
        Restart,
        "",
        "Stable instance UUID. Generated when absent.",
    ),
    opt(
        "node.netns",
        Str,
        To("netns"),
        Restart,
        "",
        "Linux network namespace to run in.",
    ),
    opt(
        "node.threads",
        Int,
        Custom,
        Restart,
        "2",
        "Runtime worker threads. 1 runs single-threaded.",
    ),
    opt(
        "control.portal",
        Str,
        Same,
        Process,
        "127.0.0.1:15888",
        "Loopback management portal. Default 127.0.0.1:15888, or a free port up to 15899.",
    ),
    opt(
        "control.portal_allow",
        StrList,
        Same,
        Process,
        "",
        "Extra CIDRs admitted to the portal in addition to loopback.",
    ),
    opt(
        "control.token_file",
        Path,
        Same,
        Process,
        "",
        "Control token file. Created with mode 0600 when absent.",
    ),
    opt(
        "control.token_group",
        Str,
        Same,
        Process,
        "",
        "Unix group that may read the token file (mode 0640).",
    ),
    opt(
        "control.default",
        Str,
        Same,
        Live,
        "",
        "Pinned alias of the default controller.",
    ),
    opt(
        "control.allow",
        StrList,
        Same,
        Live,
        "",
        "Callers with full control. Use pinned keys, aliases, local groups, or * for authenticated network members.",
    ),
    opt(
        "control.keys",
        Table,
        Same,
        Live,
        "",
        "Local aliases bound to complete X25519 public keys.",
    ),
    opt(
        "control.groups",
        Table,
        Same,
        Live,
        "",
        "Local groups of pinned key aliases.",
    ),
    secret(
        "control.secret",
        Same,
        Live,
        "Optional shared phrase or generated key for remote control authentication.",
    ),
    opt(
        "control.secret_file",
        Path,
        Same,
        Live,
        "",
        "Protected file containing control.secret.",
    ),
    opt(
        "control.grant",
        Tables,
        Same,
        Live,
        "",
        "Granular remote control and SSH grants.",
    ),
    opt(
        "gui.enabled",
        Bool,
        Same,
        Restart,
        "true",
        "Serve the browser interface on loopback and this instance's overlay address.",
    ),
    opt(
        "gui.port",
        Int,
        Same,
        Restart,
        "15880",
        "TCP port of the interface on the overlay address.",
    ),
    opt(
        "gui.loopback_port",
        Int,
        Same,
        Restart,
        "15880",
        "TCP port on 127.0.0.1. Use separate ports for instances on the same host.",
    ),
    opt(
        "gui.key_file",
        Path,
        Same,
        Restart,
        "",
        "File holding the access key. Created with mode 0600 when absent. Default: gui.key beside the control token.",
    ),
    opt(
        "gui.allow",
        StrList,
        Same,
        Restart,
        "",
        "Source CIDRs that may open the overlay interface. Default: this instance's overlay subnet. API requests require the access key.",
    ),
    opt(
        "gui.open",
        StrList,
        Same,
        Restart,
        "",
        "Overlay CIDRs served without the access key, and allowed. Trust is by source address only: use it for a network you control.",
    ),
    secret(
        "identity.private_key",
        To("secure_mode.local_private_key"),
        Restart,
        "Base64 X25519 private key. Generated when absent.",
    ),
    opt(
        "identity.private_key_file",
        Path,
        To("private_key_file"),
        Restart,
        "",
        "File that holds identity.private_key.",
    ),
    opt(
        "identity.public_key",
        Str,
        To("secure_mode.local_public_key"),
        Restart,
        "",
        "Base64 X25519 public key. Must match the private key.",
    ),
    opt(
        "identity.credential_root",
        Str,
        To("secure_mode.credential_root_fingerprint"),
        Restart,
        "",
        "Pinned credential root fingerprint (base64).",
    ),
    opt(
        "network.name",
        Str,
        To("network_identity.network_name"),
        Restart,
        "default",
        "Network name. Peers must use the same name.",
    ),
    secret(
        "network.secret",
        To("network_identity.network_secret"),
        Restart,
        "Shared network secret.",
    ),
    opt(
        "network.secret_file",
        Path,
        To("network_secret_file"),
        Restart,
        "",
        "File that holds network.secret.",
    ),
    secret(
        "network.credential",
        To("secure_mode.credential_bundle"),
        Restart,
        "Signed credential bundle. Replaces network.secret.",
    ),
    opt(
        "network.credential_file",
        Path,
        To("credential_file"),
        Restart,
        "",
        "Store for credentials issued by this node.",
    ),
    opt(
        "network.cipher",
        Enum(&["chacha20-poly1305", "aes-gcm", "aes-256-gcm"]),
        To("flags.encryption_algorithm"),
        Restart,
        "chacha20-poly1305",
        "Data cipher. Peers must agree.",
    ),
    opt(
        "address.ipv4",
        Str,
        To("ipv4"),
        Restart,
        "",
        "Virtual IPv4 address with prefix, for example 10.126.126.1/24.",
    ),
    opt(
        "address.ipv6",
        Str,
        To("ipv6"),
        Restart,
        "",
        "Virtual IPv6 address with prefix.",
    ),
    opt(
        "address.dhcp",
        Bool,
        To("dhcp"),
        Restart,
        "false",
        "Choose a free virtual IPv4 address automatically.",
    ),
    opt(
        "address.public_ipv6.provide",
        Bool,
        To("ipv6_public_addr_provider"),
        Restart,
        "false",
        "Lease this node's public IPv6 prefix to peers (Linux).",
    ),
    opt(
        "address.public_ipv6.auto",
        Bool,
        To("ipv6_public_addr_auto"),
        Restart,
        "false",
        "Obtain a public IPv6 address from a providing peer.",
    ),
    opt(
        "address.public_ipv6.prefix",
        Str,
        To("ipv6_public_addr_prefix"),
        Restart,
        "",
        "Public IPv6 prefix to lease instead of auto-detection.",
    ),
    opt(
        "tun.mode",
        Enum(&["kernel", "userspace", "none"]),
        Custom,
        Restart,
        "kernel",
        "kernel: TUN/TAP device. userspace: in-process stack for proxies and forwards. none: no local interface.",
    ),
    opt(
        "tun.name",
        Str,
        To("flags.dev_name"),
        Restart,
        "",
        "Device name. Chosen automatically when empty.",
    ),
    opt(
        "tun.mtu",
        Int,
        To("flags.mtu"),
        Restart,
        "1380",
        "Overlay MTU in bytes.",
    ),
    opt(
        "tun.ipv6",
        Bool,
        To("flags.enable_ipv6"),
        Restart,
        "true",
        "Carry IPv6 on the virtual interface.",
    ),
    opt(
        "tun.udp_broadcast_relay",
        Bool,
        To("flags.enable_udp_broadcast_relay"),
        Restart,
        "false",
        "Relay UDP broadcasts from the virtual interface (Windows).",
    ),
    opt(
        "transport.protocols",
        StrList,
        To("flags.enabled_protocols"),
        Restart,
        "",
        "Allowed transports: quic, h2, wss. Empty allows all.",
    ),
    opt(
        "transport.prefer",
        Enum(TRANSPORTS),
        To("flags.default_protocol"),
        Restart,
        "quic",
        "Initial transport priority. Measured connection quality takes precedence after setup.",
    ),
    opt(
        "transport.listen",
        StrList,
        To("listeners"),
        Restart,
        "",
        "Listener URLs, for example quic://0.0.0.0:11012.",
    ),
    opt(
        "transport.advertise",
        StrList,
        To("mapped_listeners"),
        Restart,
        "",
        "Public listener URLs announced to peers, for port mappings.",
    ),
    opt(
        "transport.quic.initial_receive_window",
        Bytes,
        To("flags.quic_initial_receive_window"),
        Restart,
        "2MiB",
        "Initial QUIC stream receive window.",
    ),
    opt(
        "transport.quic.receive_window",
        Bytes,
        To("flags.quic_receive_window"),
        Restart,
        "4MiB",
        "Maximum QUIC connection receive window.",
    ),
    opt(
        "peer",
        Tables,
        To("peer"),
        Restart,
        "",
        "Peers to connect to: uri and optional pinned public_key.",
    ),
    opt(
        "nat.p2p",
        Enum(&["on", "lazy", "required", "off"]),
        Custom,
        Restart,
        "on",
        "Direct connections: on, lazy (only when traffic needs it), required (never relay), off.",
    ),
    opt(
        "nat.udp_punch",
        Bool,
        Not("flags.disable_udp_hole_punching"),
        Restart,
        "true",
        "UDP hole punching.",
    ),
    opt(
        "nat.tcp_punch",
        Bool,
        Not("flags.disable_tcp_hole_punching"),
        Restart,
        "true",
        "TCP hole punching.",
    ),
    opt(
        "nat.symmetric_punch",
        Bool,
        Not("flags.disable_sym_hole_punching"),
        Restart,
        "true",
        "Hole punching toward symmetric NATs.",
    ),
    opt(
        "nat.stun",
        StrList,
        To("stun_servers"),
        Restart,
        "",
        "IPv4 STUN servers. Built-in list when absent.",
    ),
    opt(
        "nat.stun_v6",
        StrList,
        To("stun_servers_v6"),
        Restart,
        "",
        "IPv6 STUN servers. Built-in list when absent.",
    ),
    opt(
        "nat.stun_tcp",
        StrList,
        To("tcp_stun_servers"),
        Restart,
        "",
        "TCP STUN servers.",
    ),
    opt(
        "underlay.deny_interfaces",
        StrList,
        To("flags.underlay_deny_interfaces"),
        Restart,
        "",
        "Local interfaces the underlay must not use.",
    ),
    opt(
        "underlay.deny_cidrs",
        StrList,
        To("flags.underlay_deny_cidrs"),
        Restart,
        "",
        "Local and remote CIDRs the underlay must not use.",
    ),
    opt(
        "underlay.bind_device",
        Bool,
        To("flags.bind_device"),
        Restart,
        "true",
        "Bind underlay sockets to the physical device.",
    ),
    opt(
        "underlay.socket_mark",
        Int,
        To("flags.socket_mark"),
        Restart,
        "",
        "SO_MARK for underlay sockets (Linux).",
    ),
    opt(
        "discovery.trackers",
        StrList,
        Same,
        Restart,
        "",
        "Tracker URLs: udp, http, https, or tcp for a LowTier hosted tracker.",
    ),
    opt(
        "discovery.private_trackers",
        StrList,
        Same,
        Restart,
        "",
        "Private tracker URLs. Supports udp, tcp, http, and https.",
    ),
    opt(
        "discovery.bind",
        Str,
        Same,
        Restart,
        "",
        "Local socket address for discovery traffic.",
    ),
    opt(
        "discovery.advertise",
        Str,
        Same,
        Restart,
        "",
        "Socket address announced to trackers.",
    ),
    opt(
        "relay.policy",
        Enum(&["hop", "latency", "goodput"]),
        Same,
        Live,
        "hop",
        "How to pick a relay route when no direct link exists: hop (fewest hops), latency (lowest round trip), or goodput (highest measured delivery rate; needs relay.probe_budget_bps).",
    ),
    opt(
        "relay.use_relays",
        Bool,
        Same,
        Live,
        "true",
        "Send local data through relay peers.",
    ),
    opt(
        "relay.transit",
        Enum(&["allow", "avoid", "deny"]),
        Same,
        Live,
        "allow",
        "Carry data for other peers.",
    ),
    opt(
        "relay.transit_networks",
        StrList,
        Same,
        Live,
        "",
        "Foreign network name patterns this node relays. [\"*\"] permits all.",
    ),
    opt(
        "relay.transit_bps_limit",
        BitRate,
        Same,
        Live,
        "",
        "Shared transit budget. Unlimited when absent.",
    ),
    opt(
        "relay.transit_burst_bytes",
        Bytes,
        Same,
        Live,
        "",
        "Transit burst capacity.",
    ),
    opt(
        "relay.probe_interval_seconds",
        Duration,
        Same,
        Live,
        "30",
        "Seconds between speed test rounds, 1 to 300.",
    ),
    opt(
        "relay.probe_budget_bps",
        BitRate,
        Same,
        Live,
        "0",
        "Bandwidth limit for speed tests, for the whole machine. The tests measure how fast each direct connection delivers; the results show as RATE, start new flows on each peer's fastest connection (except under relay.policy=latency), and are required by relay.policy=goodput. 0 turns the tests off.",
    ),
    opt(
        "relay.link_cost",
        Tables,
        Same,
        Live,
        "",
        "Adjacent link cost bias: peer public key and bias_ms.",
    ),
    opt(
        "relay.foreign_rpc",
        Bool,
        To("flags.relay_all_peer_rpc"),
        Restart,
        "false",
        "Relay control RPC for foreign networks outside relay.transit_networks.",
    ),
    opt(
        "relay.private_mode",
        Bool,
        To("flags.private_mode"),
        Restart,
        "false",
        "Reject foreign networks without authorized admission.",
    ),
    opt(
        "camouflage.server_names",
        StrList,
        Same,
        QuicRestart,
        "",
        "TLS server names (SNI). Clients use one name per destination; servers accept all. Configure a decoy upstream or a website with matching certificates.",
    ),
    opt(
        "camouflage.tls_cert",
        Path,
        Same,
        QuicRestart,
        "",
        "TLS certificate file. Set together with tls_key.",
    ),
    opt(
        "camouflage.tls_key",
        Path,
        Same,
        QuicRestart,
        "",
        "TLS private key file.",
    ),
    secret(
        "camouflage.admission_secret",
        Same,
        QuicRestart,
        "Secret that separates VPN clients from website visitors (16+ bytes).",
    ),
    opt(
        "camouflage.website_root",
        Path,
        Same,
        QuicRestart,
        "",
        "Static website served to unauthenticated visitors.",
    ),
    opt(
        "camouflage.sni_routing",
        Bool,
        Same,
        QuicRestart,
        "false",
        "Classify connections by SNI instead of the admission marker.",
    ),
    opt(
        "camouflage.decoy_upstream.tcp",
        Str,
        Same,
        QuicRestart,
        "",
        "TCP decoy upstream for unauthenticated connections.",
    ),
    opt(
        "camouflage.decoy_upstream.udp",
        Str,
        Same,
        QuicRestart,
        "",
        "UDP decoy upstream for unauthenticated connections.",
    ),
    opt(
        "camouflage.wss_path",
        Str,
        Same,
        NewConnections,
        "/ws",
        "WebSocket path.",
    ),
    opt(
        "camouflage.http_host",
        Str,
        Same,
        NewConnections,
        "",
        "HTTP authority for H2 and WSS.",
    ),
    opt(
        "camouflage.trusted_proxy_cidrs",
        StrList,
        Same,
        NewConnections,
        "",
        "Reverse proxies trusted for client addresses.",
    ),
    opt(
        "limits.memory_bytes",
        Bytes,
        Same,
        Process,
        "",
        "Process memory budget. Default: RAM/16, 64MiB to 1GiB.",
    ),
    opt(
        "limits.receive_bps",
        BitRate,
        Same,
        Live,
        "",
        "Instance receive limit. Unlimited when absent.",
    ),
    opt(
        "l2.fdb_capacity",
        Int,
        To("flags.l2_fdb_capacity"),
        Restart,
        "16384",
        "Forwarding database entries.",
    ),
    opt(
        "l2.fdb_age",
        Duration,
        To("flags.l2_fdb_age_seconds"),
        Restart,
        "300",
        "Forwarding database entry lifetime.",
    ),
    opt(
        "l2.flood_bytes_per_second",
        Bytes,
        To("flags.l2_flood_bytes_per_second"),
        Restart,
        "64MiB",
        "Unknown-unicast, broadcast, and multicast budget per second. 0 disables.",
    ),
    opt(
        "l2.bridge",
        Bool,
        To("flags.enable_bridge"),
        Restart,
        "false",
        "Accept complete Ethernet frames from this admin node.",
    ),
    opt(
        "l2.max_macs_per_peer",
        Int,
        To("flags.l2_max_macs_per_peer"),
        Restart,
        "256",
        "MAC addresses each peer may own. 0 disables the limit.",
    ),
    opt(
        "l2.mac_move_hold",
        Duration,
        To("flags.l2_mac_move_hold_seconds"),
        Restart,
        "5",
        "Hold time before a MAC may move to another peer.",
    ),
    opt(
        "l2.vlans",
        IntList,
        To("flags.l2_allowed_vlans"),
        Restart,
        "",
        "Allowed VLAN IDs. Empty allows all; 0 means untagged.",
    ),
    opt(
        "l2.ether_types",
        IntList,
        To("flags.l2_allowed_ether_types"),
        Restart,
        "",
        "Allowed EtherTypes. Empty allows all.",
    ),
    opt(
        "routes.manual",
        StrList,
        To("routes"),
        Restart,
        "",
        "Routes installed instead of the automatic routes.",
    ),
    opt(
        "routes.serve_exit",
        Bool,
        To("flags.enable_exit_node"),
        Restart,
        "false",
        "Act as an exit node for peers.",
    ),
    opt(
        "group",
        Tables,
        Same,
        Live,
        "",
        "Load-balance groups: name, members (peer keys or virtual IPs), balance (flow or failover), weights.",
    ),
    opt(
        "path",
        Tables,
        Same,
        Live,
        "",
        "Paths: to (peer, CIDR, or internet), via (peers or groups in order), gateway (peer or group), strict.",
    ),
    opt(
        "note",
        Tables,
        Same,
        Live,
        "",
        "Local peer names and notes for the management interface: peer (public key), name, text.",
    ),
    opt(
        "export",
        Tables,
        To("proxy_network"),
        Restart,
        "",
        "Local subnets exported to peers: cidr, optional mapped_cidr and allow.",
    ),
    opt(
        "proxy.socks5",
        Proxy("socks5"),
        To("socks5_proxy"),
        Restart,
        "",
        "SOCKS5 listener into the network.",
    ),
    opt(
        "proxy.http",
        Proxy("http"),
        To("outbound_http_proxy"),
        Restart,
        "",
        "HTTP proxy listener into the network.",
    ),
    opt(
        "proxy.system_forward",
        Bool,
        To("flags.proxy_forward_by_system"),
        Restart,
        "false",
        "Forward exported subnets with the system stack.",
    ),
    opt(
        "forward",
        Tables,
        To("port_forward"),
        Restart,
        "",
        "Port forwards: proto, bind, dest.",
    ),
    opt(
        "dns.accept",
        Bool,
        To("flags.accept_dns"),
        Restart,
        "false",
        "Serve magic DNS for peer host names.",
    ),
    opt(
        "dns.zone",
        Str,
        To("flags.tld_dns_zone"),
        Restart,
        "lt.net.",
        "Magic DNS zone.",
    ),
    opt("acl", Table, Same, Live, "", "ACL chains and groups."),
    opt(
        "acl.tcp_ports",
        StrList,
        To("tcp_whitelist"),
        Live,
        "",
        "Local TCP ports peers may reach. Empty allows all.",
    ),
    opt(
        "acl.udp_ports",
        StrList,
        To("udp_whitelist"),
        Live,
        "",
        "Local UDP ports peers may reach. Empty allows all.",
    ),
    opt(
        "log.console",
        Str,
        Same,
        Live,
        "",
        "Console log level: off, error, warn, info, debug, trace.",
    ),
    opt("log.file", Str, Same, Process, "", "File log level."),
    opt("log.dir", Path, Same, Process, "", "File log directory."),
    opt(
        "log.max_size_mb",
        Int,
        Same,
        Process,
        "",
        "File size before rotation, in MiB.",
    ),
    opt(
        "log.max_files",
        Int,
        Same,
        Process,
        "",
        "Rotated files to keep.",
    ),
];

/// Field names inside arrays of tables, as (public, internal).
const TABLE_FIELDS: &[(&str, &[(&str, &str)])] = &[
    ("peer", &[("uri", "uri"), ("public_key", "peer_public_key")]),
    (
        "export",
        &[
            ("cidr", "cidr"),
            ("mapped_cidr", "mapped_cidr"),
            ("allow", "allow"),
        ],
    ),
    (
        "forward",
        &[
            ("proto", "proto"),
            ("bind", "bind_addr"),
            ("dest", "dst_addr"),
        ],
    ),
    (
        "group",
        &[
            ("name", "name"),
            ("members", "members"),
            ("balance", "balance"),
            ("weights", "weights"),
        ],
    ),
    (
        "path",
        &[
            ("to", "to"),
            ("via", "via"),
            ("gateway", "gateway"),
            ("strict", "strict"),
        ],
    ),
    (
        "control.grant",
        &[
            ("from", "from"),
            ("permissions", "permissions"),
            ("config_paths", "config_paths"),
            ("ssh_users", "ssh_users"),
            ("expires_unix", "expires_unix"),
            ("max_session_seconds", "max_session_seconds"),
        ],
    ),
    (
        "relay.link_cost",
        &[("peer", "peer"), ("bias_ms", "bias_ms")],
    ),
    (
        "note",
        &[("peer", "peer"), ("name", "name"), ("text", "text")],
    ),
];

/// Old names. `None` means the option was removed.
const RETIRED: &[(&str, Option<&str>)] = &[
    ("hostname", Some("node.hostname")),
    ("instance_name", Some("node.instance_name")),
    ("instance_id", Some("node.instance_id")),
    ("netns", Some("node.netns")),
    ("ipv4", Some("address.ipv4")),
    ("ipv6", Some("address.ipv6")),
    ("dhcp", Some("address.dhcp")),
    (
        "ipv6_public_addr_provider",
        Some("address.public_ipv6.provide"),
    ),
    ("ipv6_public_addr_auto", Some("address.public_ipv6.auto")),
    (
        "ipv6_public_addr_prefix",
        Some("address.public_ipv6.prefix"),
    ),
    ("listeners", Some("transport.listen")),
    ("mapped_listeners", Some("transport.advertise")),
    ("exit_nodes", Some("path")),
    ("routes.exit_nodes", Some("path")),
    ("relay.prefer", Some("path")),
    ("routes", Some("routes.manual")),
    ("proxy_network", Some("export")),
    ("socks5_proxy", Some("proxy.socks5")),
    ("outbound_http_proxy", Some("proxy.http")),
    ("port_forward", Some("forward")),
    ("tcp_whitelist", Some("acl.tcp_ports")),
    ("udp_whitelist", Some("acl.udp_ports")),
    ("stun_servers", Some("nat.stun")),
    ("stun_servers_v6", Some("nat.stun_v6")),
    ("tcp_stun_servers", Some("nat.stun_tcp")),
    ("credential_file", Some("network.credential_file")),
    ("network_identity", Some("network")),
    ("network_identity.network_name", Some("network.name")),
    ("network_identity.network_secret", Some("network.secret")),
    ("secure_mode", Some("identity")),
    ("secure_mode.enabled", None),
    (
        "secure_mode.local_private_key",
        Some("identity.private_key"),
    ),
    ("secure_mode.local_public_key", Some("identity.public_key")),
    ("secure_mode.credential_bundle", Some("network.credential")),
    (
        "secure_mode.credential_root_fingerprint",
        Some("identity.credential_root"),
    ),
    ("secure_mode.credential_certificate", None),
    ("peer.peer_public_key", Some("peer.public_key")),
    ("export.mapped", Some("export.mapped_cidr")),
    ("forward.bind_addr", Some("forward.bind")),
    ("forward.dst_addr", Some("forward.dest")),
    ("flags.default_protocol", Some("transport.prefer")),
    ("flags.enabled_protocols", Some("transport.protocols")),
    ("flags.dev_name", Some("tun.name")),
    ("flags.enable_encryption", None),
    ("flags.enable_ipv6", Some("tun.ipv6")),
    ("flags.mtu", Some("tun.mtu")),
    ("flags.enable_exit_node", Some("routes.serve_exit")),
    ("flags.no_tun", Some("tun.mode")),
    ("flags.use_smoltcp", Some("tun.mode")),
    ("flags.disable_p2p", Some("nat.p2p")),
    ("flags.lazy_p2p", Some("nat.p2p")),
    ("flags.need_p2p", Some("nat.p2p")),
    ("flags.relay_all_peer_rpc", Some("relay.foreign_rpc")),
    ("flags.disable_udp_hole_punching", Some("nat.udp_punch")),
    ("flags.disable_tcp_hole_punching", Some("nat.tcp_punch")),
    (
        "flags.disable_sym_hole_punching",
        Some("nat.symmetric_punch"),
    ),
    ("flags.multi_thread", Some("node.threads")),
    ("flags.multi_thread_count", Some("node.threads")),
    ("flags.bind_device", Some("underlay.bind_device")),
    (
        "flags.proxy_forward_by_system",
        Some("proxy.system_forward"),
    ),
    ("flags.accept_dns", Some("dns.accept")),
    ("flags.private_mode", Some("relay.private_mode")),
    ("flags.encryption_algorithm", Some("network.cipher")),
    ("flags.tld_dns_zone", Some("dns.zone")),
    (
        "flags.enable_udp_broadcast_relay",
        Some("tun.udp_broadcast_relay"),
    ),
    ("flags.socket_mark", Some("underlay.socket_mark")),
    (
        "flags.underlay_deny_interfaces",
        Some("underlay.deny_interfaces"),
    ),
    ("flags.underlay_deny_cidrs", Some("underlay.deny_cidrs")),
    (
        "flags.quic_initial_receive_window",
        Some("transport.quic.initial_receive_window"),
    ),
    (
        "flags.quic_receive_window",
        Some("transport.quic.receive_window"),
    ),
    ("flags.l2_fdb_capacity", Some("l2.fdb_capacity")),
    ("flags.l2_fdb_age_seconds", Some("l2.fdb_age")),
    (
        "flags.l2_flood_bytes_per_second",
        Some("l2.flood_bytes_per_second"),
    ),
    ("flags.l2_flood_bps", Some("l2.flood_bytes_per_second")),
    ("flags.enable_bridge", Some("l2.bridge")),
    ("flags.l2_max_macs_per_peer", Some("l2.max_macs_per_peer")),
    ("flags.l2_mac_move_hold_seconds", Some("l2.mac_move_hold")),
    ("flags.l2_allowed_vlans", Some("l2.vlans")),
    ("flags.l2_allowed_ether_types", Some("l2.ether_types")),
    ("flags.quic_datagram_fec_parity", None),
    ("flags.quic_datagram_alternate_path_parity", None),
    ("flags.data_compress_algo", None),
    ("flags.port_mode", None),
    ("flags.interface_adapter", None),
    ("flags.instance_recv_bps_limit", Some("limits.receive_bps")),
    ("flags.latency_first", Some("relay.policy")),
    ("flags.speed_first", Some("relay.policy")),
    ("flags.p2p_only", Some("relay.use_relays")),
    ("flags.disable_relay_data", Some("relay.transit")),
    (
        "flags.relay_network_whitelist",
        Some("relay.transit_networks"),
    ),
    (
        "flags.foreign_relay_bps_limit",
        Some("relay.transit_bps_limit"),
    ),
    (
        "flags.speed_probe_interval_seconds",
        Some("relay.probe_interval_seconds"),
    ),
    (
        "flags.speed_probe_budget_bps",
        Some("relay.probe_budget_bps"),
    ),
    ("flags.quic_server_name", Some("camouflage.server_names")),
    ("camouflage.server_name", Some("camouflage.server_names")),
    ("flags.quic_tls_cert", Some("camouflage.tls_cert")),
    ("flags.quic_tls_key", Some("camouflage.tls_key")),
    (
        "flags.quic_admission_secret",
        Some("camouflage.admission_secret"),
    ),
    ("flags.quic_fallback_root", Some("camouflage.website_root")),
    (
        "flags.quic_decoy_upstream",
        Some("camouflage.decoy_upstream"),
    ),
    ("flags.quic_sni_passthrough", Some("camouflage.sni_routing")),
    ("flags.relay", Some("relay")),
    ("flags.camouflage", Some("camouflage")),
    ("flags.limits", Some("limits")),
    ("source", None),
    ("config_server", None),
    ("external_node", Some("peer")),
];

pub fn lookup(path: &str) -> Option<&'static OptionSpec> {
    OPTIONS.iter().find(|spec| spec.path == path)
}

/// Explain why a path is not accepted, naming its replacement when one exists.
pub fn retired_message(path: &str) -> Option<String> {
    let current = lookup(path).is_some()
        || OPTIONS
            .iter()
            .any(|spec| spec.path.starts_with(&format!("{path}.")));
    if current { None } else { retired_entry(path) }
}

/// The retired-name message without checking current names. An old value can share a name
/// with a current section, such as the old `routes = [...]` list.
fn retired_entry(path: &str) -> Option<String> {
    let entry = |name: &str| RETIRED.iter().find(|(old, _)| *old == name);
    let found = entry(path).or_else(|| {
        // Old flags were accepted both inside [flags] and at the top level.
        path.strip_prefix("flags.")
            .map_or_else(|| entry(&format!("flags.{path}")), |_| None)
    })?;
    Some(match found.1 {
        // First-hop preferences and exit lists became [[path]] entries.
        Some("path") => {
            format!("\"{path}\" was replaced by [[path]]; see `lowertier config explain path`")
        }
        Some(new) => format!("\"{path}\" was renamed to \"{new}\""),
        None => format!("\"{path}\" was removed"),
    })
}

pub fn table_fields(path: &str) -> &'static [(&'static str, &'static str)] {
    TABLE_FIELDS
        .iter()
        .find(|(name, _)| *name == path)
        .map_or(&[], |(_, fields)| fields)
}

fn unknown(path: &str) -> String {
    retired_entry(path).unwrap_or_else(|| format!("unknown option \"{path}\""))
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

/// Collect every option leaf in a public table.
fn walk(
    table: &Table,
    prefix: &str,
    leaves: &mut Vec<(&'static OptionSpec, Value)>,
    errors: &mut Vec<String>,
) {
    for (key, value) in table {
        let path = join(prefix, key);
        match (lookup(&path), value) {
            (Some(spec), Value::Table(children)) if spec.kind == Kind::Table => {
                // Children with their own paths leave the opaque table.
                let mut rest = Table::new();
                for (child, child_value) in children {
                    let child_path = join(&path, child);
                    match lookup(&child_path) {
                        Some(child_spec) => leaves.push((child_spec, child_value.clone())),
                        None => {
                            rest.insert(child.clone(), child_value.clone());
                        }
                    }
                }
                if !rest.is_empty() {
                    leaves.push((spec, Value::Table(rest)));
                }
            }
            (Some(spec), value) => leaves.push((spec, value.clone())),
            (None, Value::Table(children))
                if OPTIONS
                    .iter()
                    .any(|spec| spec.path.starts_with(&format!("{path}."))) =>
            {
                walk(children, &path, leaves, errors)
            }
            (None, Value::Table(children)) if retired_entry(&path).is_none() => {
                walk(children, &path, leaves, errors)
            }
            (None, _) => errors.push(unknown(&path)),
        }
    }
}

fn parse_number(text: &str) -> Option<f64> {
    let value = text.trim().parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn split_unit(text: &str) -> (&str, &str) {
    let text = text.trim();
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    (&text[..end], text[end..].trim())
}

fn scaled(text: &str, scale: f64, path: &str) -> anyhow::Result<i64> {
    let (number, _) = split_unit(text);
    let value = parse_number(number)
        .with_context(|| format!("{path}: \"{text}\" is not a number"))?
        * scale;
    anyhow::ensure!(
        value.fract() == 0.0 && value <= i64::MAX as f64,
        "{path}: \"{text}\" does not resolve to a whole value"
    );
    Ok(value as i64)
}

pub fn parse_duration(text: &str, path: &str) -> anyhow::Result<i64> {
    let scale = match split_unit(text).1 {
        "" | "s" | "sec" | "secs" => 1.0,
        "m" | "min" => 60.0,
        "h" => 3600.0,
        "d" => 86400.0,
        unit => bail!("{path}: unknown duration unit \"{unit}\"; use s, m, h, or d"),
    };
    scaled(text, scale, path)
}

pub fn parse_bit_rate(text: &str, path: &str) -> anyhow::Result<i64> {
    let unit = split_unit(text).1.to_ascii_lowercase();
    let unit = unit
        .trim_end_matches("/s")
        .trim_end_matches("ps")
        .trim_end_matches("bit")
        .trim_end_matches('b');
    let scale = match unit {
        "" => 1.0,
        "k" => 1e3,
        "m" => 1e6,
        "g" => 1e9,
        "t" => 1e12,
        _ => bail!("{path}: unknown rate unit in \"{text}\"; use bit, Kbit, Mbit, Gbit"),
    };
    scaled(text, scale, path)
}

pub fn parse_bytes(text: &str, path: &str) -> anyhow::Result<i64> {
    let scale = match split_unit(text).1.to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kb" | "k" => 1e3,
        "mb" | "m" => 1e6,
        "gb" | "g" => 1e9,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        unit => bail!("{path}: unknown size unit \"{unit}\"; use B, KiB, MiB, GiB"),
    };
    scaled(text, scale, path)
}

fn type_error(spec: &OptionSpec, value: &Value) -> anyhow::Error {
    anyhow::anyhow!(
        "{}: expected {}, found {}",
        spec.path,
        spec.kind.describe(),
        value.type_str()
    )
}

/// Check a value's type and resolve units, enums, and proxy shorthand.
fn normalize(spec: &OptionSpec, value: Value) -> anyhow::Result<Value> {
    let path = spec.path;
    let units = |parse: fn(&str, &str) -> anyhow::Result<i64>| match &value {
        Value::Integer(number) if *number >= 0 => Ok(value.clone()),
        Value::String(text) => parse(text, path).map(Value::Integer),
        _ => Err(type_error(spec, &value)),
    };
    match spec.kind {
        Kind::Bool if value.is_bool() => Ok(value),
        Kind::Int if value.is_integer() => Ok(value),
        Kind::Str | Kind::Path if value.is_str() => Ok(value),
        Kind::Enum(values) => match value.as_str() {
            Some(text) if values.contains(&text) => Ok(value),
            Some(text) => bail!("{path}: \"{text}\" is not one of {}", values.join(", ")),
            None => Err(type_error(spec, &value)),
        },
        Kind::StrList
            if value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_str)) =>
        {
            Ok(value)
        }
        Kind::IntList
            if value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_integer)) =>
        {
            Ok(value)
        }
        Kind::Duration => units(parse_duration),
        Kind::BitRate => units(parse_bit_rate),
        Kind::Bytes => units(parse_bytes),
        Kind::Proxy(scheme) => {
            let text = value.as_str().ok_or_else(|| type_error(spec, &value))?;
            let text = text
                .strip_prefix(&format!("{scheme}://"))
                .unwrap_or(text)
                .trim_end_matches('/');
            Ok(Value::String(
                crate::common::config::parse_proxy_listener_url(text, scheme)
                    .with_context(|| path.to_owned())?
                    .to_string(),
            ))
        }
        Kind::Table if value.is_table() => Ok(value),
        Kind::Tables => {
            let fields = table_fields(path);
            let items = value.as_array().ok_or_else(|| type_error(spec, &value))?;
            for item in items {
                let item = item.as_table().ok_or_else(|| type_error(spec, &value))?;
                for key in item.keys() {
                    if !fields.iter().any(|(public, _)| public == key) {
                        bail!(unknown(&join(path, key)));
                    }
                }
            }
            Ok(value)
        }
        _ => Err(type_error(spec, &value)),
    }
}

fn get<'a>(table: &'a Table, path: &str) -> Option<&'a Value> {
    let (parent, key) = match path.rsplit_once('.') {
        Some((parent, key)) => (get(table, parent)?.as_table()?, key),
        None => (table, path),
    };
    parent.get(key)
}

pub(crate) fn set(table: &mut Table, path: &str, value: Value) {
    let mut current = table;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            current.insert(part.to_owned(), value);
            return;
        }
        let entry = current
            .entry(part.to_owned())
            .or_insert_with(|| Value::Table(Table::new()));
        if !entry.is_table() {
            *entry = Value::Table(Table::new());
        }
        current = entry.as_table_mut().unwrap();
    }
}

fn rename_fields(value: Value, path: &str, to_internal: bool) -> Value {
    let fields = table_fields(path);
    let Value::Array(items) = value else {
        return value;
    };
    Value::Array(
        items
            .into_iter()
            .map(|item| match item {
                Value::Table(item) => Value::Table(
                    item.into_iter()
                        .map(|(key, value)| {
                            let renamed = fields
                                .iter()
                                .find(|(public, internal)| {
                                    key == if to_internal { *public } else { *internal }
                                })
                                .map(
                                    |(public, internal)| {
                                        if to_internal { *internal } else { *public }
                                    },
                                );
                            (renamed.unwrap_or(&key).to_owned(), value)
                        })
                        .collect(),
                ),
                other => other,
            })
            .collect(),
    )
}

/// Translate a public sectioned table into the internal configuration table.
pub fn to_internal(public: &Table) -> anyhow::Result<Table> {
    let mut leaves = Vec::new();
    let mut errors = Vec::new();
    walk(public, "", &mut leaves, &mut errors);
    for (spec, value) in &mut leaves {
        match normalize(spec, value.clone()) {
            Ok(normalized) => *value = normalized,
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    if !errors.is_empty() {
        bail!("invalid configuration:\n  {}", errors.join("\n  "));
    }

    let mut internal = Table::new();
    for (spec, value) in &leaves {
        match spec.map {
            Map::Same => set(
                &mut internal,
                spec.path,
                rename_fields(value.clone(), spec.path, true),
            ),
            Map::To(target) => set(
                &mut internal,
                target,
                rename_fields(value.clone(), spec.path, true),
            ),
            Map::Not(target) => set(
                &mut internal,
                target,
                Value::Boolean(!value.as_bool().unwrap()),
            ),
            Map::Custom => {}
        }
    }

    let given = |path: &str| {
        leaves
            .iter()
            .find(|(spec, _)| spec.path == path)
            .map(|(_, value)| value)
    };
    if let Some(threads) = given("node.threads").and_then(Value::as_integer) {
        anyhow::ensure!(threads >= 1, "node.threads must be at least 1");
        set(
            &mut internal,
            "flags.multi_thread",
            Value::Boolean(threads > 1),
        );
        if threads > 1 {
            set(
                &mut internal,
                "flags.multi_thread_count",
                Value::Integer(threads),
            );
        }
    }
    if let Some(mode) = given("tun.mode").and_then(Value::as_str) {
        let (no_tun, smoltcp) = match mode {
            "kernel" => (false, false),
            "userspace" => (true, true),
            _ => (true, false),
        };
        set(&mut internal, "flags.no_tun", Value::Boolean(no_tun));
        set(&mut internal, "flags.use_smoltcp", Value::Boolean(smoltcp));
        if mode == "userspace" {
            anyhow::ensure!(
                given("tun.name").is_none(),
                "tun.name cannot be used with tun.mode = \"userspace\""
            );
            anyhow::ensure!(
                given("underlay.socket_mark").is_none(),
                "underlay.socket_mark cannot be used with tun.mode = \"userspace\""
            );
            // The userspace stack has no device to bind its own traffic to.
            if given("underlay.bind_device").is_none() {
                set(&mut internal, "flags.bind_device", Value::Boolean(false));
            }
        }
    }
    if let Some(p2p) = given("nat.p2p").and_then(Value::as_str) {
        for (flag, active) in [
            ("disable_p2p", p2p == "off"),
            ("lazy_p2p", p2p == "lazy"),
            ("need_p2p", p2p == "required"),
        ] {
            set(
                &mut internal,
                &format!("flags.{flag}"),
                Value::Boolean(active),
            );
        }
    }
    if let Some(identity) = internal
        .get_mut("network_identity")
        .and_then(Value::as_table_mut)
    {
        identity
            .entry("network_name")
            .or_insert_with(|| Value::String("default".into()));
    }
    if let Some(secure) = internal
        .get_mut("secure_mode")
        .and_then(Value::as_table_mut)
    {
        secure.insert("enabled".into(), Value::Boolean(true));
    }
    Ok(internal)
}

/// Translate the internal configuration table into the public sectioned table.
/// Internal values without a public path are dropped.
pub fn to_public(internal: &Table) -> Table {
    let mut public = Table::new();
    let flag = |name: &str| get(internal, &format!("flags.{name}"));
    let flag_bool =
        |name: &str, default: bool| flag(name).and_then(Value::as_bool).unwrap_or(default);
    for spec in OPTIONS {
        let value = match spec.map {
            Map::Same => get(internal, spec.path).cloned(),
            Map::To(source) => get(internal, source).cloned(),
            Map::Not(source) => get(internal, source)
                .and_then(Value::as_bool)
                .map(|value| Value::Boolean(!value)),
            Map::Custom => match spec.path {
                "node.threads"
                    if flag("multi_thread").is_some() || flag("multi_thread_count").is_some() =>
                {
                    Some(Value::Integer(if flag_bool("multi_thread", true) {
                        flag("multi_thread_count")
                            .and_then(Value::as_integer)
                            .unwrap_or(2)
                    } else {
                        1
                    }))
                }
                "tun.mode" if flag("no_tun").is_some() || flag("use_smoltcp").is_some() => {
                    Some(Value::String(
                        match (flag_bool("no_tun", false), flag_bool("use_smoltcp", false)) {
                            (false, _) => "kernel",
                            (true, true) => "userspace",
                            (true, false) => "none",
                        }
                        .into(),
                    ))
                }
                "nat.p2p"
                    if ["disable_p2p", "lazy_p2p", "need_p2p"]
                        .iter()
                        .any(|name| flag_bool(name, false)) =>
                {
                    Some(Value::String(
                        if flag_bool("disable_p2p", false) {
                            "off"
                        } else if flag_bool("need_p2p", false) {
                            "required"
                        } else {
                            "lazy"
                        }
                        .into(),
                    ))
                }
                _ => None,
            },
        };
        let Some(value) = value else {
            continue;
        };
        // An opaque table must not repeat children that have their own paths.
        let value = match value {
            Value::Table(mut table) if spec.kind == Kind::Table => {
                table.retain(|key, _| lookup(&join(spec.path, key)).is_none());
                if table.is_empty() {
                    continue;
                }
                Value::Table(table)
            }
            Value::Table(table) if table.is_empty() => continue,
            // Protobuf JSON encodes 64-bit integers as strings.
            Value::String(text)
                if matches!(
                    spec.kind,
                    Kind::Int | Kind::Duration | Kind::BitRate | Kind::Bytes
                ) && text.parse::<i64>().is_ok() =>
            {
                Value::Integer(text.parse().unwrap())
            }
            value => rename_fields(value, spec.path, false),
        };
        set(&mut public, spec.path, value);
    }
    // The userspace stack disables device binding implicitly.
    if get(&public, "tun.mode").and_then(Value::as_str) == Some("userspace")
        && get(&public, "underlay.bind_device").and_then(Value::as_bool) == Some(false)
        && let Some(underlay) = public.get_mut("underlay").and_then(Value::as_table_mut)
    {
        underlay.remove("bind_device");
        if underlay.is_empty() {
            public.remove("underlay");
        }
    }
    public
}

/// Parse a `--set PATH=VALUE` argument into the public table.
pub fn apply_set(public: &mut Table, assignment: &str) -> anyhow::Result<&'static OptionSpec> {
    let (path, text) = assignment
        .split_once('=')
        .with_context(|| format!("\"{assignment}\" must use PATH=VALUE"))?;
    let path = path.trim();
    let spec = lookup(path).ok_or_else(|| anyhow::anyhow!(unknown(path)))?;
    let value = parse_value(spec, text.trim())?;
    set(public, path, value);
    Ok(spec)
}

/// Parse command-line text for one option.
pub fn parse_value(spec: &OptionSpec, text: &str) -> anyhow::Result<Value> {
    let path = spec.path;
    let list = |text: &str| -> Vec<String> {
        text.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let value = match spec.kind {
        Kind::Bool => Value::Boolean(match text.to_ascii_lowercase().as_str() {
            "true" | "on" | "yes" | "1" => true,
            "false" | "off" | "no" | "0" => false,
            _ => bail!("{path}: \"{text}\" is not true or false"),
        }),
        Kind::Int => Value::Integer(
            text.parse()
                .with_context(|| format!("{path}: \"{text}\" is not an integer"))?,
        ),
        Kind::StrList | Kind::IntList | Kind::Tables | Kind::Table
            if text.starts_with(['[', '{']) =>
        {
            let wrapped = format!("value = {text}");
            wrapped
                .parse::<Table>()
                .with_context(|| format!("{path}: \"{text}\" is not a TOML value"))?
                .remove("value")
                .unwrap()
        }
        Kind::StrList => Value::Array(list(text).into_iter().map(Value::String).collect()),
        Kind::IntList => Value::Array(
            list(text)
                .iter()
                .map(|item| {
                    let parsed = match item.strip_prefix("0x") {
                        Some(hex) => i64::from_str_radix(hex, 16),
                        None => item.parse(),
                    };
                    parsed
                        .map(Value::Integer)
                        .with_context(|| format!("{path}: \"{item}\" is not an integer"))
                })
                .collect::<anyhow::Result<_>>()?,
        ),
        Kind::Tables => {
            // Shorthand: comma-separated values for the first field, for example peer URIs.
            let (field, _) = table_fields(path)
                .first()
                .with_context(|| format!("{path} needs a TOML array of tables"))?;
            Value::Array(
                list(text)
                    .into_iter()
                    .map(|item| {
                        let mut table = Table::new();
                        table.insert((*field).to_owned(), Value::String(item));
                        Value::Table(table)
                    })
                    .collect(),
            )
        }
        Kind::Table => bail!("{path} needs a TOML table"),
        _ => Value::String(text.to_owned()),
    };
    normalize(spec, value)
}

/// Human-readable documentation for one option, or a list of all options under a prefix.
pub fn explain(prefix: Option<&str>) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let prefix = prefix.unwrap_or("").trim_end_matches('.');
    if let Some(spec) = lookup(prefix) {
        let mut text = format!(
            "{}\n  {}\n\n  type     {}\n",
            spec.path,
            spec.doc,
            spec.kind.describe()
        );
        if let Some(unit) = spec.kind.unit() {
            writeln!(text, "  unit     {unit}").unwrap();
        }
        if !spec.default.is_empty() {
            writeln!(text, "  default  {}", spec.default).unwrap();
        }
        writeln!(text, "  applies  {}", spec.apply.as_str()).unwrap();
        if spec.secret {
            writeln!(text, "  secret   redacted in output").unwrap();
        }
        let fields = table_fields(spec.path);
        if !fields.is_empty() {
            let names = fields.iter().map(|(name, _)| *name).collect::<Vec<_>>();
            writeln!(text, "  fields   {}", names.join(", ")).unwrap();
        }
        return Ok(text);
    }
    if let Some(message) = retired_message(prefix) {
        bail!(message);
    }
    let matches = OPTIONS
        .iter()
        .filter(|spec| prefix.is_empty() || spec.path.starts_with(&format!("{prefix}.")))
        .collect::<Vec<_>>();
    anyhow::ensure!(!matches.is_empty(), "unknown option \"{prefix}\"");
    let width = matches
        .iter()
        .map(|spec| spec.path.len())
        .max()
        .unwrap_or(0);
    let mut text = String::new();
    for spec in matches {
        writeln!(text, "{:width$}  {}", spec.path, spec.doc).unwrap();
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> Table {
        text.parse().unwrap()
    }

    #[test]
    fn registry_paths_are_unique_and_renames_resolve() {
        for (index, spec) in OPTIONS.iter().enumerate() {
            assert!(
                OPTIONS[..index].iter().all(|other| other.path != spec.path),
                "{}",
                spec.path
            );
            assert!(!spec.doc.is_empty(), "{}", spec.path);
        }
        for (old, new) in RETIRED {
            if let Some(new) = new {
                let base = new.split('.').next().unwrap();
                assert!(
                    lookup(new).is_some() || OPTIONS.iter().any(|spec| spec.path.starts_with(base)),
                    "{old} -> {new}"
                );
            }
        }
    }

    #[test]
    fn units_resolve() {
        assert_eq!(parse_bit_rate("8Mbit", "x").unwrap(), 8_000_000);
        assert_eq!(parse_bit_rate("1.5Gbit", "x").unwrap(), 1_500_000_000);
        assert_eq!(parse_bit_rate("8000", "x").unwrap(), 8000);
        assert_eq!(parse_bytes("256KiB", "x").unwrap(), 262_144);
        assert_eq!(parse_bytes("1GiB", "x").unwrap(), 1 << 30);
        assert_eq!(parse_duration("5m", "x").unwrap(), 300);
        assert!(parse_bytes("1.5B", "x").is_err());
        assert!(parse_duration("5 parsecs", "x").is_err());
    }

    #[test]
    fn set_parses_by_kind() {
        let mut public = Table::new();
        apply_set(&mut public, "relay.transit_bps_limit=8Mbit").unwrap();
        apply_set(&mut public, "tun.mode=userspace").unwrap();
        apply_set(&mut public, "peer=quic://a.example:1,h2://b.example:2").unwrap();
        apply_set(
            &mut public,
            "camouflage.server_names=user-selected.example.test,cdn.example.test",
        )
        .unwrap();
        assert_eq!(
            get(&public, "camouflage.server_names"),
            Some(&Value::Array(vec![
                Value::String("user-selected.example.test".into()),
                Value::String("cdn.example.test".into()),
            ]))
        );
        apply_set(&mut public, "l2.vlans=0,10,0x14").unwrap();
        assert_eq!(
            get(&public, "relay.transit_bps_limit"),
            Some(&Value::Integer(8_000_000))
        );
        assert_eq!(
            get(&public, "l2.vlans").unwrap().as_array().unwrap().len(),
            3
        );
        assert_eq!(get(&public, "peer").unwrap().as_array().unwrap().len(), 2);
        let error = apply_set(&mut public, "tun.mode=bogus")
            .unwrap_err()
            .to_string();
        assert!(error.contains("kernel, userspace, none"), "{error}");
        let error = apply_set(&mut public, "flags.mtu=1200")
            .unwrap_err()
            .to_string();
        assert!(error.contains("tun.mtu"), "{error}");
        assert!(lookup("network.secret").unwrap().secret);
    }

    #[test]
    fn old_layout_reports_every_replacement() {
        let error = to_internal(&table(
            "listeners = [\"quic://0.0.0.0:1\"]\nroutes = [\"10.0.0.0/8\"]\nprivate_mode = true\n[flags]\nmtu = 1200\nenable_encryption = false\n[[peer]]\nuri = \"quic://a:1\"\npeer_public_key = \"x\"\n",
        ))
        .unwrap_err()
        .to_string();
        for expected in [
            "\"listeners\" was renamed to \"transport.listen\"",
            "\"routes\" was renamed to \"routes.manual\"",
            "\"private_mode\" was renamed to \"relay.private_mode\"",
            "\"flags.mtu\" was renamed to \"tun.mtu\"",
            "\"flags.enable_encryption\" was removed",
            "\"peer.peer_public_key\" was renamed to \"peer.public_key\"",
        ] {
            assert!(error.contains(expected), "{expected}\n{error}");
        }
    }

    #[test]
    fn custom_options_round_trip() {
        let public = table(
            "[node]\nthreads = 4\n[tun]\nmode = \"userspace\"\nmtu = 1200\n[nat]\np2p = \"lazy\"\nudp_punch = false\n[relay]\npolicy = \"latency\"\nforeign_rpc = true\n[[path]]\nto = \"internet\"\nvia = [\"relays\"]\ngateway = \"10.0.0.9\"\n[[group]]\nname = \"relays\"\nmembers = [\"10.0.0.2\", \"10.0.0.3\"]\nweights = [2, 1]\n[[forward]]\nproto = \"tcp\"\nbind = \"0.0.0.0:80\"\ndest = \"10.0.0.1:80\"\n[acl]\ntcp_ports = [\"22\"]\n[acl.acl_v1]\nchains = []\n",
        );
        let internal = to_internal(&public).unwrap();
        assert_eq!(
            get(&internal, "flags.multi_thread_count"),
            Some(&Value::Integer(4))
        );
        assert_eq!(
            get(&internal, "flags.bind_device"),
            Some(&Value::Boolean(false))
        );
        assert_eq!(
            get(&internal, "flags.disable_udp_hole_punching"),
            Some(&Value::Boolean(true))
        );
        assert_eq!(
            get(&internal, "flags.relay_all_peer_rpc"),
            Some(&Value::Boolean(true))
        );
        assert_eq!(
            get(&internal, "tcp_whitelist")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            get(&internal, "port_forward").unwrap().as_array().unwrap()[0]
                .get("bind_addr")
                .is_some()
        );
        assert_eq!(to_public(&internal), public);
    }
}
