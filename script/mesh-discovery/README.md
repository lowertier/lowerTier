# Supervised discovery for the test mesh

The mesh uses two independently running UDP trackers and STUN Binding servers.
A tracker process and a STUN process run on each discovery host. The deployment
installs executables under `/opt/lowertier-discovery`, outside temporary test
folders. Both units are enabled at boot and restarted after process failure.

`lowertier-stun.service` runs `script/mesh-stun.py` with IPv4 UDP and TCP listeners
on ports 16780 and 16781. The service has no automatic lifetime expiry. It answers
STUN Binding requests with XOR-MAPPED-ADDRESS. UDP CHANGE-PORT is supported;
CHANGE-IP, TURN allocations, authentication, and relay allocation are outside
its scope. It is a bounded Binding service for the owned mesh, rather than a
complete TURN or RFC 5780 deployment.

The parser rejects malformed lengths, oversized bodies, unsupported methods,
invalid CHANGE-REQUEST bits, and unknown comprehension-required attributes.
Limits are 512 request-body bytes, 128 requests per source per second, 2048
requests per second overall, 256 rate-limit source entries per second, and 64
active TCP clients. TCP headers have a 60-second idle deadline; body and write
operations have five-second deadlines. Parser and limiter coverage lives in
`script/tests/test_mesh_stun.py`.

`lowertier-tracker.service` runs the existing release tracker binary with UDP
16970, loopback-only HTTP 16973, and a 10-second announce interval. This bounded
cadence is for the small private mesh and shortens restart-incarnation discovery. Clients continue to respect the
interval returned by each tracker. Public tracker operators retain control of
their own announce cadence.

Both units use a dynamic unprivileged user, read-only system paths, no new
privileges, a private temporary directory, a 64 MiB memory ceiling, 16 tasks,
and 256 file descriptors. Network identities and VPN keys are absent from these
service files and the Binding implementation.

Clients should configure both tracker URLs and interleave STUN endpoints from
the two hosts. A public seed should query the other host first. Exclude overlay,
container, and unrelated VPN interfaces from transport candidate collection;
keep the physical WAN and any intentionally usable physical LAN paths.

After copying a binary onto an SELinux-enforcing host, restore its standard
file context before starting the service. A copied temporary-file label can
produce systemd status 203/EXEC. Keep SELinux enforcement enabled.

Acceptance must include a failure-injection test: stop only one host's discovery
services, cold-start a client with no static peers, and verify actual overlay
packets and application payload hashes through the surviving discovery host.
Always restore the stopped services in a finally path. A visible topology entry
alone does not establish data-plane reachability. Enabled units and process
restarts also do not constitute a completed machine-reboot or multi-hour soak
test.

The September 24 repair records are retained in
`benchmark-results/.work/mesh-repair-20260924/`. Root cause: the previous temporary
STUN fixture exited after `asyncio.sleep(7200)`, while its tracker used a manually
started process and an 1800-second default interval. The Rust client now withdraws
failed mapped-address observations, retries missing mappings after five seconds,
and notifies watchers when the same address becomes usable again.
