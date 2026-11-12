# Commands

One binary does everything: `lowertier run` runs a node, and the other commands manage a running node through its local control port.
`lowertier COMMAND --help` shows the options compiled into your binary.

## Run

| Command | Does |
| --- | --- |
| `init FILE` | Write a configuration with a new network secret and identity key. `--network`, `--ipv4`, `--peer`, `--tun`, `--listen`, `--join`. |
| `run -c FILE` | Run a node in the foreground. `--config-dir DIR` runs every `.toml` in a directory; `--set PATH=VALUE` overrides one value. |
| `check -c FILE` | Validate files without starting, reporting every problem at once. |
| `service install -- ARGS` | Register `lowertier run ARGS` with the system service manager. Also `uninstall`, `status`, `start`, `stop`. |

## Look

| Command | Shows |
| --- | --- |
| `status` | Node, addresses, NAT, discovery, listeners, relay, and peers on one screen. |
| `doctor` | Checks token, control port, instances, listeners, NAT, trackers, peers, and loss, with a fix for each problem. |
| `top` | Live dashboard. Tab or 1-5 switch panes, j/k move, Enter opens detail, `/` filters, q quits. |
| `gui` | Opens the [web interface](web-interface.md). |
| `peers [show PEER]` | Peers with round trip, loss, rate, and session state. |
| `routes [trace DEST]` | Routes, or the path to one destination hop by hop. |
| `paths` | Each path and group member: usable or why not, and traffic carried. |
| `relay`, `camouflage`, `discovery` | Relay policy and drops; camouflage settings; trackers and NAT observations. |
| `listeners`, `l2 fdb`, `l2 stats`, `acl stats` | Listeners, learned MAC addresses, Ethernet counters, ACL counters. |
| `stats [--prometheus] [-w]` | Metrics, once or each time they change. |
| `logs [-f]` | Recent log lines, optionally followed. |
| `nodes` | Nodes running on this machine. |

## Change

| Command | Does |
| --- | --- |
| `set PATH=VALUE...` | Change options in one transaction and save them to the file. |
| `unset PATH...` | Remove options so their defaults apply. |
| `edit` | Edit the configuration in `$EDITOR`, then apply the difference. |
| `get [PATH]` | Show the active configuration, and staged values when they differ. |
| `config explain [PATH]` | Describe options. Works without a running node. |
| `peers add URI`, `peers rm` | Add or remove a configured peer. |
| `listeners add URI`, `listeners rm` | Add or remove a listener. |
| `forward add`, `forward rm` | Port forwards. |
| `acl set FILE` | Replace the ACL rules. |
| `creds list`, `issue`, `revoke` | Network credentials. Needs `--admin-token` or `LOWTIER_ADMIN_TOKEN`, except locally with the control token. |
| `instance list`, `create FILE`, `start`, `stop`, `delete` | Instances inside one node process. |
| `log-level [LEVEL]` | Show or change the log level. |
| `ssh USER@NODE` | Open an SSH session through the network. See [remote control](remote-control.md). |
| `completion SHELL` | Shell completion for bash, elvish, fish, PowerShell, zsh, or Nushell. |

Changes that need a restart require `--stage`. `--expected-revision N` refuses a change if the configuration changed since revision N.

## Picking a node

The commands find the node on their own. A running node records its control port and token file, and the commands read that record.

- `-n NAME` picks one node when several run. `lowertier nodes` lists them.
- `-i NAME` picks an instance when one node runs several.
- `-p ADDR` and `--token-file PATH` name the control port and token directly.
- `--remote NODE` manages another machine; see [remote control](remote-control.md).

A node run as root keeps its token readable only by root, so use `sudo`, or set `control.token_group`.
The control port listens on `127.0.0.1:15888` (or the next free port up to 15899). Do not expose it to an untrusted network.

## Scripting

`-o json` prints one envelope per result. `lowertier -o json config explain relay.policy` prints:

```json
{"schema_version":1,"request_id":"78bed153-b5d5-48f8-aa05-82c0264e6317","instance_id":null,"revision":null,
 "data":{"text":"relay.policy\n  Automatic routes use direct links first. ..."},"error":null}
```

Exactly one of `data` and `error` holds a value. Followed output prints one envelope per line.

| Exit code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | Internal error |
| 2 | Invalid arguments or configuration |
| 3 | Permission |
| 4 | Missing or ambiguous node, instance, or resource |
| 5 | Revision conflict, or a restart is required |
| 6 | Connection or deadline |
| 7 | Partial failure, or a failed `doctor` check |
