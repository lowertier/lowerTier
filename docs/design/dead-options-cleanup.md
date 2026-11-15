# Unused option and API cleanup

The November 15, 2026 cleanup removes fixed internal SOCKS5 settings and unused APIs.
The public configuration fields checked in this audit have runtime consumers.

## SOCKS5 settings

The local listener had one constructor.
That constructor selected the same values for every connection.
No configuration, CLI, GUI, FFI, or test caller selected another value.

| Removed setting | Retained behavior |
| --- | --- |
| `request_timeout` | The connector receives a 10-second connection timeout. |
| `skip_auth` | Every connection negotiates a SOCKS5 method. |
| `allow_no_auth` | The local proxy uses the no-authentication method. |
| `dns_resolve` | The connector receives domain targets and controls name resolution. |
| `execute_command` | Every accepted request executes CONNECT or UDP ASSOCIATE. |
| `allow_udp` | UDP ASSOCIATE remains available. |

The private `auth` field was always `None`.
The password parser, authentication trait, example authenticators, credential storage, and associated error variants had no reachable caller.
The socket wrapper also had unused stream trait implementations.
These paths and the generic configuration object were removed.

The old negotiation code selected method `0x00` even when the client did not offer it.
The server now returns `0xff` for unsupported offers, including an empty method list.
Clients that offer method `0x00` retain CONNECT and UDP ASSOCIATE support.
The local proxy still requires loopback binding or a trusted firewall.
Peer authentication and destination admission remain separate controls.

## Other removed code

- The unused `PeerCenterInstanceService` wrapper and `get_rpc_service` constructor.
  The authenticated `PeerCenterServer` and local job client remain active.
- The unused TCP-status getter, serializer, protobuf message, and protobuf state enum.
  TCP connection state remains a local Rust enum.
  The monotonic connection age remains available.
  The unused wall-clock timestamp was removed.
- The HTTP/2 routing-prefix helper and its scalar test.
  Production code never called that helper.
  Existing loopback integration tests exercise static, punched, decoy, and SNI routing paths.
- An unused FFI dataplane test fixture with no tests.
  The FFI dataplane remains available.

The QUIC and TCP punch initiation helpers are compiled only for their test callers.
The runtime schedulers still acquire permits before starting attempts.
The scalar L2 source-admission helper is also compiled only for tests.
Production code retains batch source admission.

## Retained controls

The audit found runtime consumers for the inspected public configuration fields.
The environment controls also select active behavior.
This cleanup retains transport selection, receive pacing, Linux TUN controls, QUIC controls, and both stream-proxy switches.
An experimental default does not establish that an option is unused.

## Acceptance

The new SOCKS5 tests exercise TCP transfer, UDP delivery and control closure, connector-managed domain targets, and unsupported-method rejection.
The core suite excludes public-domain probes under the local-test policy.
Release, integration, feature, FFI, and fleet results are recorded with the cleanup report.
These checks do not establish a performance improvement.
