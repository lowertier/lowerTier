# Browser interface

`lowertier gui` serves a management page on loopback and opens it in the default browser.

```bash
sudo lowertier gui              # http://127.0.0.1:15880/#key=...
lowertier gui --no-open         # print the address only
lowertier gui --listen 127.0.0.1:18080
```

The page shows peers placed by round-trip time, traffic rates, loss, and routes.
It sets every option in the registry, edits paths and load-balance groups with live per-member traffic shares, follows logs, and switches between daemons on the machine.
Options that need a restart are staged; the page then offers an instance restart.
Light and dark themes follow the system setting.

## Security

The `lowertier gui` process holds the control token. The browser never receives it.
The server listens on loopback only. Use SSH port forwarding to reach it from another machine:

```bash
ssh -L 15880:127.0.0.1:15880 host 'sudo lowertier gui --no-open'
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
