# Remote control and SSH

Each node decides which public keys can control that node.
The node proves its X25519 private key through an end-to-end Noise session.
Hostnames identify displays only.

Use one `control` section for the controller, permissions, and SSH.

```toml
[control]
default = "hattori-wrt"
allow = ["hattori-wrt"]

[control.keys]
hattori-wrt = "jjyGmLpFPYpV2djEFYmFVYV+bfY5VPnmkZyj1Ckv8XI="
```

This example pins the public key of the fleet controller.
Replace that key when you configure a different controller.
Put the destination keys in the controller's `control.keys` table.
Use local aliases to keep commands and permission lists short.

```sh
lowertier --remote node-a status
lowertier --remote node-a set relay.policy=latency
lowertier ssh root@node-a -- uname -n
lowertier ssh -t root@node-a
```

`--remote default` uses `control.default` from the local source instance.
Use `--via-instance NAME` when a process has several source instances.
Use `--instance NAME` to select an instance inside the destination process.
Remote control needs an active mesh route to the pinned destination key.
SSH uses an internal SSH client and requires no public SSH listener.
The daemon must have permission to use the selected operating-system account.
The daemon does not create accounts.

## Key selectors

| Selector | Meaning |
| --- | --- |
| `node-a` | Exact alias in the local `control.keys` table. |
| `pubkey:BASE64` | Complete X25519 public key. The `x25519:` prefix also works. |
| `PREFIX...` | Unique prefix of an already pinned key in `control.keys`. |
| `office-*` | Wildcard over local key aliases. |
| `group:ops` | Members of the local `control.groups.ops` list. |
| `*` | Authenticated members of this network. |
| `secret` | Callers that prove the configured control phrase. |

Unknown and ambiguous key prefixes fail.
Wildcards never match advertised hostnames.
Every alias stores the complete key.

## Granular permissions

```toml
[control.keys]
operator = "COMPLETE_BASE64_PUBLIC_KEY"

[control.groups]
ops = ["operator"]

[[control.grant]]
from = ["group:ops"]
permissions = ["status.read", "config.read", "config.write", "ssh"]
config_paths = ["relay.*"]
ssh_users = ["deploy"]
max_session_seconds = 3600
```

Grant selectors use the key selectors listed above.
`config_paths` limits configuration writes.
`ssh_users` limits operating-system accounts.
`expires_unix` sets an optional Unix expiry time in seconds.
`max_session_seconds` limits the lifetime of an authenticated session.
Permission patterns accept `*` and `?`.

Available permissions are `admin`, `status.read`, `config.read`, `config.write`, `logs.read`, `logs.write`,
`credentials.read`, `credentials.write`, `instances.read`, `instances.start`, `instances.stop`, `instances.delete`, and `ssh`.

`allow` entries have full control.
The `admin` permission also grants full control, subject to the grant's expiry and session limit.
Instance creation and changes to control policy, GUI settings, or file paths require full control.
Process log changes require permission on every affected instance.
SSH TCP forwarding requires full control.
The node checks current permissions on each operation and during periodic session cleanup.

## Control phrase

```toml
[control]
secret_file = "/etc/lowertier/control.secret"
```

Use a protected file that contains a phrase or a random key.
The inline `control.secret` option also works.
Use only one of these options.
The phrase grants full control unless a grant selects `from = ["secret"]` and limits its permissions.

```sh
lowertier --remote node-a --remote-secret-file ./control.secret status
lowertier --remote-secret-file ./control.secret ssh deploy@node-a -- id
```

The phrase authenticates through SPAKE2 and Noise PSK3.
The protocol does not send the phrase as a reusable plaintext credential.
The client still pins the destination public key.

## Files and reloads

Changes through local or remote management commands persist before runtime activation.
`--no-persist` is rejected.
Atomic replacement preserves file ownership, access modes, and unrelated TOML comments.
Revisions reject stale API updates.
External file edits reject conflicting API writes.
Credential issuance and revocation require `network.credential_file` for durable storage.

The daemon checks configuration files and referenced keys, secrets, tokens, and TLS files each second.
Valid changes apply automatically.
Instance settings restart the affected instance.
Process settings restart the process with its original process settings owner first.
Invalid changes keep the previous runtime configuration active.
`lowertier get` reports the reload error.
Failed instance startup restores the previous runtime and attempts to restore the previous source file.

Files with startup `--set` overrides do not reload automatically.
Restart those processes externally to retain override precedence.
Environment variables still expand during reload.
Files that use environment variables remain read-only through the API.
Use explicit configuration files in service definitions for persistence across external service restarts.
An instance created through the API receives a persistent file and starts disabled.

SSH terminal sessions support PTYs, resize events, commands, stdout, stderr, and exit status on Unix systems.
The client restores terminal settings when the session ends.
Session closure or permission revocation terminates the associated process groups.
