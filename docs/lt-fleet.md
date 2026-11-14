# lt fleet: web interface access

Operational policy for the `lt-` test fleet. The [web interface guide](web-interface.md) documents the options in general.

A daemon serves the page on its own overlay address, so allowed peers can open it without SSH forwarding.
Every joined `lt-` node must expose the Web UI to `10.126.126.0/24` by default.
The listener uses TCP port `15880` on the node's overlay address.
Sources in `10.126.126.0/24`, `192.168.51.0/24`, and `192.168.40.0/24` may control the Web UI without a key.
Keep this setting in the configuration when a node joins the fleet.
The [fleet inventory](lt-fleet.json) lists verified instances and pending migrations.

Run one joined instance per physical host.
Keep retired services and watchdogs disabled.
Consult the active inventory before restarting or deploying instances.
Preserve retired configuration, identity keys, and logs.

The November 14, 2026 cleanup stopped five duplicate instances:

| Host | Retired address | Retained address |
| --- | --- | --- |
| Local Mac Studio | `10.126.126.202` | `10.126.126.2` |
| 862jp | `10.126.126.182` | `10.126.126.82` |
| JPali | `10.126.126.162` | `10.126.126.62` |
| s6916 | `10.126.126.61` | `10.126.126.60` |
| yutoms-mcp | `10.126.126.70` | `10.126.126.3` |

The retained 862jp and JPali kernel instances provide exit-node service.
The active inventory keeps their existing `862jp-secondary` and `jpali-secondary` aliases.
These aliases refer to the only joined instance on each host.
Twelve hosts retain one running instance each.
Eleven instances passed identity, peer removal, authenticated traffic, GUI policy, and Web UI checks.
Packet tests delivered all 30 packets to ten remote nodes.
Taiwan at `10.126.126.80` still runs version `0.02`.
Its SSH access works, but local overlay delivery and Web UI checks failed.
The cause remains unconfirmed.
The cleanup did not change its configuration or software.
The inventory records this pending connectivity check separately from the historical offline hosts.

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
