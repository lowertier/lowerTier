# Remote control and SSH

Any node can manage another node across the network, and open an SSH session to it, without a public SSH port.
Each node decides which public keys may control it. The caller proves its identity key through an end-to-end Noise session; host names are only labels.

## Allow a controller

On the node to be managed, pin the controller's public key under a local alias and allow it:

```toml
[control]
allow = ["laptop"]

[control.keys]
laptop = "<laptop's base64 X25519 public key>"
```

On the controller, pin the managed nodes' keys the same way, and optionally set a default target:

```toml
[control]
default = "node-a"

[control.keys]
node-a = "<node-a's public key>"
```

Then:

```bash
lowertier --remote node-a status
lowertier --remote node-a set relay.policy=latency
lowertier ssh root@node-a -- uname -n
lowertier ssh -t root@node-a
```

`--remote default` targets `control.default`. `--via-instance NAME` picks the local instance to send from, and `--instance NAME` the instance on the remote node.
Remote control needs a route to the destination key.
SSH runs inside lowertier: the remote daemon starts the session as the requested account, if it has permission to. It does not create accounts.
Sessions support terminals, resizing, commands, and exit status on Unix.

## Who may connect

| Selector | Matches |
| --- | --- |
| `node-a` | The alias `node-a` in `control.keys`. |
| `pubkey:BASE64` | A complete public key. `x25519:` also works. |
| `PREFIX...` | A unique prefix of a key already in `control.keys`. |
| `office-*` | Aliases matching the wildcard. |
| `group:ops` | Members of `control.groups.ops`. |
| `*` | Any authenticated member of this network. |
| `secret` | Callers that prove the control phrase. |

Unknown or ambiguous prefixes fail. Wildcards never match advertised host names.

## Limit what they may do

`allow` grants full control. A grant gives less:

```toml
[control.keys]
operator = "<public key>"

[control.groups]
ops = ["operator"]

[[control.grant]]
from = ["group:ops"]
permissions = ["status.read", "config.read", "config.write", "ssh"]
config_paths = ["relay.*"]
ssh_users = ["deploy"]
max_session_seconds = 3600
# expires_unix = 1798761600
```

Permissions: `admin`, `status.read`, `config.read`, `config.write`, `logs.read`, `logs.write`, `credentials.read`, `credentials.write`,
`instances.read`, `instances.start`, `instances.stop`, `instances.delete`, and `ssh`. Patterns accept `*` and `?`.

`admin` equals full control, within the grant's expiry and session limit.
Creating instances, changing control policy, network trust, identity, web interface settings, or file paths always needs full control, as does SSH port forwarding.
The node rechecks permissions on every operation, so revoking a grant ends its sessions.

## Control phrase

Instead of pinning keys, callers can prove a shared phrase:

```toml
[control]
secret_file = "/etc/lowertier/control.secret"
```

```bash
lowertier --remote node-a --remote-secret-file ./control.secret status
lowertier --remote-secret-file ./control.secret ssh deploy@node-a -- id
```

The phrase is checked with SPAKE2 and Noise PSK, so it never crosses the network in a reusable form. The client still pins the node's public key.
A phrase grants full control unless a grant with `from = ["secret"]` narrows it.
`control.secret` works inline too; use one or the other.

## Saving changes

Remote changes are saved to the node's file before they take effect, keeping file ownership, modes, and comments.
Changes that need a restart are staged automatically.
`--expected-revision N` refuses a change if the configuration moved on since revision N.
