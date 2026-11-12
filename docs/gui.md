# Browser interface

The daemon starts the browser interface on loopback and each instance's overlay address by default.
Loopback starts before the overlay address is available.
Set `[gui] enabled = false` to disable both listeners.

`lowertier gui` also serves a management page on loopback and opens it in the default browser.
The CLI selects a free port when the daemon already uses the default port.

```bash
sudo lowertier gui              # open a page with a temporary access key
lowertier gui --no-open         # print the address only
lowertier gui --listen 127.0.0.1:18080
```

The page has four sections: Machines, Routes, Logs, and Settings.
Machines lists this machine and every peer with its address, connection, round trip, traffic, and version.
A filter shows direct peers, relayed peers, or peers that need attention: no direct connection, an older LowTier version, or loss of 1% or more.
Each row has a menu to rename the peer, edit its note, copy its address or public key, and open its details.
The details sheet shows live figures, the automatic route, the path editor, the link cost bias, and connections.
Options that need a restart are staged; the page then offers an instance restart.
The header switch selects Auto, Light, or Night. Auto follows the system setting; the choice persists in the browser.

Names and notes for peers are stored on the machine that serves the page, as `[[note]]` tables keyed by public key.
They apply live and stay local: other machines keep their own names.
Renaming this machine changes `node.hostname`, which peers see.

```toml
[[note]]
peer = "N2BdrcGbQFyGOmutpWhewjc0ufbs1E80Xlk5BFIFLhg="
name = "builder"
text = "Build box in rack 2."
```

Settings has five pages: General, Keys, Access, Connectivity, and All options.
The first four show the common options with plain labels. All options lists the full registry with search and a TOML view.

## Join codes

Add machine, or Create join code under Settings, Keys, produces a join code and install commands for Linux, macOS, and Windows.
Any member can create one; there is no coordination server.
The code names the network, carries its admission material, and lists bootstrap peers for the new machine to dial first.
The page proposes this machine's public listeners, its advertised addresses, and its own bootstrap peers. Add any other reachable member.

- A network secret code embeds the shared secret. It never expires. Share it the way you would share a password.
- A signed credential code embeds a credential issued on the spot, with a lifetime, a reuse limit, and optional groups.
  It needs `network.credential_file` on this machine and `camouflage.admission_secret` on every member,
  because credential machines hold no network secret for transport admission.
  Settings, Keys lists issued credentials and revokes them.
- When `camouflage.admission_secret` is set, every code carries it.

The new machine applies a code with `lowertier init FILE --join CODE` or `install.sh install --join CODE`.
The `CreateJoinCode` control method produces codes. It requires a loopback or in-process control channel, or the `admin` grant for remote callers.
A loopback caller with the control token may also list, issue, and revoke credentials without `--admin-token`, since that token can already replace the network secret.

Settings groups each secret with its value or file source.
Network authentication selects a shared secret or a signed credential.
A signed credential supplies the identity key. The public key is read-only.
The optional root trust pin remains available under Identity.
The issued credential store holds credentials issued by this node.
It is not an input file for the node's own signed credential.

Source networks use one table with a key requirement for each rule.
The table writes `gui.allow` and `gui.open` together.
The three fleet source networks retain access without a key.
The ACL has one editor for rules and port lists.
The Routing page edits paths, groups, relay policy, relay use, transit, probe budget, and exit service.
Settings links to that page.

The admission secret is an optional override for network-secret admission.
Decoy forwarding still requires an explicit admission secret of at least 16 bytes.

## On the lt network

A daemon serves the page on its own overlay address, so allowed peers can open it without SSH forwarding.
Every joined `lt-` node must expose the Web UI to `10.126.126.0/24` by default.
The listener uses TCP port `15880` on the node's overlay address.
Sources in `10.126.126.0/24`, `192.168.51.0/24`, and `192.168.40.0/24` may control the Web UI without a key.
Keep this setting in the configuration when a node joins the fleet.
The [fleet inventory](lt-fleet.json) lists verified instances and pending migrations.

```toml
[gui]
enabled = true                    # default; false disables the listener
port = 15880                      # default
loopback_port = 15880             # use separate ports for instances on one host
allow = ["10.126.126.0/24", "192.168.51.0/24", "192.168.40.0/24"]
open = ["10.126.126.0/24", "192.168.51.0/24", "192.168.40.0/24"]
# key_file = "/etc/lowertier/gui.key"
```

Open `http://<overlay address>:15880/` from one of these three subnets. The page opens directly.
`allow` permits a source to connect. `open` also permits the source to control the interface without a key.
The server uses the connection's source address. It does not trust client-supplied forwarding headers.
A router that masquerades a LAN into the overlay makes the whole LAN appear as one address.
Allowed sources outside `open` must provide the key from `gui.key`.
The daemon creates this file with mode 0600 beside the control token, or at `gui.key_file`.
Without `allow`, peers in the instance's overlay subnet may connect with the access key.
An empty `allow` permits the node itself and sources listed in `open`.
Loopback clients may connect with the same key.
Changes need an instance restart; the Settings page edits the same options.
The restart closes existing listeners and HTTP connections before applying the new settings.
Overlay proxies cannot connect to loopback GUI listeners, including listeners in another daemon process.
GUI requests use the instance's overlay listener and retain its source access checks.

- With `tun.mode = "userspace"` the listener lives in the userspace stack, so it needs no operating system interface. With a kernel interface it is a normal socket bound to the overlay address.
- It manages the instance that serves it. `?node=` cannot select another daemon on the machine, so the page never reaches other control tokens.
- Browsers keep the key in `sessionStorage` for the tab. A key the server refuses is dropped and the key prompt returns.
- The page is plain HTTP inside the encrypted overlay. Peers outside `allow` and `open` get no response. At most 32 connections are served at once.
- Sources in `open` can change this node's configuration and restart it. Other allowed sources need the access key.

## Security

The `lowertier gui` process holds the control token. (The `[gui]` section above applies the same checks in the daemon.) The browser never receives it.
The daemon skips the key check for `gui.open` sources. Host and Origin checks still apply.
The standalone `lowertier gui` server listens on loopback only. Use SSH port forwarding to reach it from another machine:

```bash
ssh -L 18080:127.0.0.1:18080 host 'sudo lowertier gui --listen 127.0.0.1:18080 --no-open'
```

Each run creates a random key and passes it in the URL fragment, which browsers do not send to servers.
Every API request must carry the key in the `x-lowertier-key` header.
Requests whose `Host` or `Origin` names another site are refused, which blocks DNS rebinding.
Responses forbid framing and load scripts and styles only from the server.

## API

Requests and responses are TOML documents in the same layout as the configuration file.
Absent values are omitted. 64-bit counters stay integers.

| Request | Purpose |
| --- | --- |
| `GET /api/nodes` | Running daemons from the runtime records. |
| `GET /api/schema` | The option registry: path, type, values, default, and when a change applies. |
| `GET /api/snapshot` | Node, peers, routes, relay, discovery, and listeners in one sample. |
| `GET /api/config` | Active and staged configuration and restart-pending options. |
| `POST /api/config` | Apply `[set]` values keyed by exact option paths and a `clear` list. `stage = true` stores restart-class options. |
| `POST /api/rpc/<Method>` | Any Control API method by protobuf name, for example `ReadLogs`. |

Add `?node=<portal or name>` and `?instance=<name>` to address another daemon or instance.

```bash
curl -s -H "x-lowertier-key: $KEY" -X POST --data-binary @- \
  http://127.0.0.1:15880/api/config <<'TOML'
stage = true
[set]
"relay.policy" = "latency"
TOML
```

Quote dotted keys in `[set]` to preserve the exact update path.
For example, `"acl.tcp_ports" = ["22"]` changes only that port list.
Setting `acl` replaces the complete ACL table.

## Development

The page is a SolidJS app in `lowertier/gui`. The built files in `lowertier/gui/dist` are committed and embedded in the binary, so Rust builds do not need Node.

```bash
cd lowertier/gui
pnpm install
pnpm build          # type-check and write dist/
pnpm dev            # dev server; proxies /api to a running `lowertier gui`
```

Build without the page with `--no-default-features` and the features you need, leaving out `gui`.

Run the userspace proxy regression check after building the binary.
The check uses two local nodes and verifies instance selection, access keys, and Host checks.

```bash
python3 script/tests/gui-proxy-test.py --binary target/release/lowertier
```
