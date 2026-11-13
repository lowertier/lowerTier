# Web interface

Every node serves a management page. It lists machines, edits routes and settings, shows logs, creates join codes, and can manage other nodes across the network.

## Open it

There are two ways to open the page:

1. **Built into every running node.** By default, each instance serves the page on loopback (`gui.loopback_port`, default `15880`) and on its overlay IPv4 address at TCP port `15880` (`gui.port`).
   Other members of the network can open `http://<overlay address>:15880/` with the node's access key (see [access](#access)).
   `[gui] enabled = false` turns both listeners off.
2. **From the command line (`lowertier gui`).** Starts a local loopback proxy using your control token:

```bash
sudo lowertier gui              # open the page with a temporary access key
lowertier gui --no-open         # print the address only
lowertier gui --listen 127.0.0.1:18080
```

To reach a node's loopback page from another machine without the overlay, forward a port over SSH:

```bash
ssh -L 18080:127.0.0.1:18080 host 'sudo lowertier gui --listen 127.0.0.1:18080 --no-open'
```

## What it shows

- **Machines.** This machine and every peer: address, connection, round trip, traffic, version.
  Filter for direct peers, relayed peers, or peers that need attention: no direct connection, an older version, or 1% loss or more.
  Each row can be renamed and annotated, and opens a detail sheet with live figures, the route, the path editor, and connections.
- **Routes.** Paths, groups, relay policy, transit, probe budget, and exit service.
- **Logs.** Recent log lines.
- **Settings.** General, Keys, Access, Connectivity, and All options, which lists every option with search and a TOML view.

Options that need a restart are staged, and the page offers to restart the instance.
The header switch picks Auto, Light, or Night.

Names and notes for peers stay on the machine that serves the page, as `[[note]]` tables. Other machines keep their own.
Renaming this machine changes `node.hostname`, which peers see.

```toml
[[note]]
peer = "N2BdrcGbQFyGOmutpWhewjc0ufbs1E80Xlk5BFIFLhg="
name = "builder"
text = "Build box in rack 2."
```

## Manage other nodes

You can switch the page to manage any other reachable node across the network, using the local node as a bridge over an end-to-end Noise control session:

- Click **Manage node** in a peer's action menu (`...`) or detail sheet, or click **Remote…** in the top bar.
- You can pick a connected peer, a pinned alias from `control.keys` (or `default` when `control.default` is set), or enter any peer's `pubkey:<base64>` and an optional control phrase (`control.secret`).
- While managing a remote node, **Machines**, **Routes**, **Logs**, and **Settings** read and edit that remote node. Click **Return to this machine** in the banner to switch back.

Authorization on the remote node is governed by its `[control]` policy (`control.allow`, `control.grant`, or `control.secret`), not by `[gui]` settings. See [remote control](remote-control.md).

## Join codes

**Add machine**, or **Create join code** under Settings, Keys, makes a code and install commands for Linux, macOS, and Windows.
Any member can make one; there is no coordination server.
A code names the network, carries its admission material, and defaults to tracker discovery (using this node's `discovery.trackers` or the built-in public trackers) so machines can join and maintain the mesh even when no node has a public IP.
You can also select optional bootstrap peers for the new machine to dial first.

- **Network secret code.** Embeds the shared secret and never expires. Share it like a password.
- **Signed credential code.** Embeds a credential issued on the spot, with a lifetime, a reuse limit, and optional groups.
  It needs `network.credential_file` on this machine and `camouflage.admission_secret` on every member,
  because credential machines hold no network secret. Settings, Keys lists issued credentials and revokes them.

When `camouflage.admission_secret` is set, every code carries it.
The new machine uses a code with `lowertier init FILE --join CODE` or `install.sh install --join CODE`.
Join codes need a build newer than release 0.01.

## Access

```toml
[gui]
port = 15880
loopback_port = 15880             # give each instance on one host its own port
allow = ["10.44.0.0/24"]          # sources that may connect; they need the key
open = ["10.44.0.10/32"]          # sources that may connect and control without the key
# key_file = "/etc/lowertier/gui.key"
```

- Without `allow`, peers in the node's overlay subnet may connect with the access key. An empty list allows only the node itself and `open` sources.
- The key lives in `gui.key` beside the control token (mode 0600), or at `gui.key_file`.
- `open` trusts the source address alone. Use it only for networks you control; a router that masquerades a LAN makes the whole LAN one address.
- Changes need an instance restart. Settings, Access edits the same options.

The page is plain HTTP inside the encrypted overlay. Sources outside `allow` and `open` get no response, and at most 32 connections are served at once.
The daemon-served `[gui]` listener is pinned to the local daemon and instance that serve it (it cannot switch to other local daemons on the same host), whereas `lowertier gui` can switch between local daemons and instances. Both can manage remote nodes across the network via [remote control](remote-control.md).
With a userspace interface, the overlay listener runs inside the userspace stack.

## Security

The `lowertier gui` process holds the control token; the browser never sees it.
Each run creates a random key and passes it in the URL fragment, which browsers do not send to servers.
Every API request carries the key in an `x-lowertier-key` header, and the browser keeps it in `sessionStorage` for the tab.
Requests whose `Host` or `Origin` names another site are refused, which blocks DNS rebinding.
Responses forbid framing and load scripts and styles only from the server.
The overlay's SOCKS5 and HTTP proxies cannot connect to loopback listeners, so peers reach the page only through its overlay listener and its source checks.

## API

Requests and responses are TOML in the same layout as the configuration file.

| Request | Returns or does |
| --- | --- |
| `GET /api/nodes` | Running nodes on this machine. |
| `GET /api/schema` | The option registry: path, type, values, default, and when a change applies. |
| `GET /api/snapshot` | Node, peers, routes, relay, discovery, and listeners in one sample. |
| `GET /api/config` | Active and staged configuration and options waiting for a restart. |
| `POST /api/config` | Apply `[set]` values keyed by option path and a `clear` list. `stage = true` stores restart-class options. |
| `POST /api/rpc/<Method>` | Any Control API method by protobuf name, for example `ReadLogs`. |

Add `?node=<portal or name>` and `?instance=<name>` when using `lowertier gui` to address another daemon or instance on the same machine.
Add `?remote=<alias, key, or default>` (and optionally `?via_instance=<local instance>`) to forward the request to another node over an end-to-end Noise control session. Pass the remote control phrase in the `x-lowertier-remote-secret` header when the remote node uses `control.secret`.

```bash
curl -s -H "x-lowertier-key: $KEY" -X POST --data-binary @- \
  http://127.0.0.1:15880/api/config <<'TOML'
stage = true
[set]
"relay.policy" = "latency"
TOML
```

Quote dotted keys in `[set]` to keep the exact path. `"acl.tcp_ports" = ["22"]` changes only that list; setting `acl` replaces the whole table.

`CreateJoinCode` needs a loopback or in-process control channel, or the `admin` grant for remote callers.
A loopback caller with the control token may also list, issue, and revoke credentials without `--admin-token`.

## Development

The page is a SolidJS app in `lowertier/gui`. The built files in `lowertier/gui/dist` are committed and embedded in the binary, so Rust builds need no Node.

```bash
cd lowertier/gui
pnpm install
pnpm build          # type-check and write dist/
pnpm dev            # dev server; proxies /api to a running `lowertier gui`
```

Build without the page by leaving out the `gui` feature.
After building, `python3 script/tests/gui-proxy-test.py --binary target/release/lowertier` checks instance selection, access keys, and Host checks with two local nodes.
