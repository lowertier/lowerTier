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

The page shows peers placed by round-trip time, traffic rates, loss, and routes.
It sets every option in the registry, edits paths and load-balance groups with live per-member traffic shares, follows logs, and switches between daemons on the machine.
Options that need a restart are staged; the page then offers an instance restart.
Light and dark themes follow the system setting.

## On the lt network

A daemon serves the page on its own overlay address, so allowed peers can open it without SSH forwarding.

```toml
[gui]
enabled = true                    # default; false disables the listener
port = 15880                      # default
loopback_port = 15880             # use separate ports for instances on one host
allow = ["10.144.0.0/24"]         # overlay CIDRs that may connect (with the key)
open = ["192.168.51.0/24"]        # CIDRs served without the key
# key_file = "/etc/lowertier/gui.key"
```

Open `http://<overlay address>:15880/` from an allowed peer and enter the key. The key is the content of `gui.key`, which the daemon creates with mode 0600 beside the control token (or at `gui.key_file`).
`open = ["192.168.51.0/24"]` lists networks served without the key: their peers open the page directly and are allowed even when `allow` omits them. Trust is by source address only, so list a network you control. A router that masquerades a LAN into the overlay makes the whole LAN appear as one address.
Without `allow`, peers in the instance's overlay subnet may connect with the access key.
An explicit empty list permits only the node itself.
Loopback clients may connect with the same key.
Changes need an instance restart; the Settings page edits the same options.
The restart closes existing listeners and HTTP connections before applying the new settings.
Overlay proxies cannot connect to loopback GUI listeners, including listeners in another daemon process.
GUI requests use the instance's overlay listener and retain its source access checks.

- With `tun.mode = "userspace"` the listener lives in the userspace stack, so it needs no operating system interface. With a kernel interface it is a normal socket bound to the overlay address.
- It manages the instance that serves it. `?node=` cannot select another daemon on the machine, so the page never reaches other control tokens.
- Browsers keep the key in `sessionStorage` for the tab. A key the server refuses is dropped and the key prompt returns.
- The page is plain HTTP inside the encrypted overlay. Peers outside `allow` get no response, and at most 32 connections are served at once.
- Keep `allow` and `open` narrow: anyone holding the key can change this node's configuration and restart it.

## Security

The `lowertier gui` process holds the control token. (The `[gui]` section above applies the same checks in the daemon.) The browser never receives it.
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
| `POST /api/config` | Apply `[set]` values in the public layout and a `clear` list. `stage = true` stores restart-class options. |
| `POST /api/rpc/<Method>` | Any Control API method by protobuf name, for example `ReadLogs`. |

Add `?node=<portal or name>` and `?instance=<name>` to address another daemon or instance.

```bash
curl -s -H "x-lowertier-key: $KEY" -X POST --data-binary @- \
  http://127.0.0.1:15880/api/config <<'TOML'
stage = true
[set.relay]
policy = "latency"
TOML
```

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
