# Control API v1 contract

This contract defines stages 4–6. Stages 1–3 provide the configuration and routing behavior.
Use the existing protobuf RPC framework. Register `api.control.v1.ControlPlaneV1Rpc` on the management portal.
The service replaces all `api_*` management services. Keep inter-node peer RPC schemas wire compatible.
Do not retain old method slots or compatibility services. CLI and core ship together.

## Common contract and authentication

Every request carries `RequestMeta { instance_id, control_token, admin_token, request_id }`.
Instance identifiers are required for instance resources. Process resources omit the instance identifier.
Every snapshot carries `SnapshotMeta { revision, topology_generation, sampled_at }`.
Use UTC timestamps, optional unknown measurements, string JSON uint64 values, and base64 JSON bytes.
Use protobuf field names in snake_case. Public keys identify peers; numeric peer IDs describe the current topology.

Keep loopback portal binding and CIDR admission. Require the process control token for every portal method.
Store the token in `[control].token_file`. Generate the file once with Unix mode 0600 or a Windows owner ACL.
Credential administration also requires the existing administrator token and loopback restriction.
Compare tokens in constant time. Never expose tokens in snapshots, logs, or errors.
In-process adapters use an owned instance handle. Reject caller-supplied provenance and unowned instance identifiers.
Do not register management services on foreign peer RPC domains.

Return `ApiError { code, message, field_path, retryable }` consistently.
Codes include invalid_argument, permission_denied, not_found, conflict, restart_required, deadline_exceeded,
unavailable, internal, and partial_failure. `GetCapabilities` reports protocol version, supported resources, and apply classes.
Paginate lists with `Page { limit, page_token }`. Bind page tokens to the resource and snapshot generation.

## Instances, node, peers, and routes

Methods: `ListInstances`, `CreateInstance`, `StartInstance`, `StopInstance`, `DeleteInstance`, `GetNode`, `ListPeers`, `ListRoutes`.
Retain `NetworkInstanceManager` and `--daemon`. Instance deletion requires a stopped instance.

Peer snapshots contain peer key, peer ID, connections, transport, lanes, NAT types, RTT in microseconds,
loss in ppm, directed delivery rate in bit/s, sample age, sample expiry, and measurement scope.
Route snapshots contain destination, final gateway, first hop, selected path, policy, effective policy,
fallback reason, source, cost in milliseconds, measured RTT, bottleneck rate, override status, and topology generation.
Return `control_policy=hop`. Data policies are hop, latency, and goodput.
Requested paths describe the captured graph. They are not packet traces.
Reconstruct paths from one snapshot within the route work budget. Preserve destination-specific goodput thresholds.
Avoid one predecessor tree for every goodput destination. Keep stored route summaries at O(V) for V peers.
Unavailable preferences use automatic routing and report an inactive reason.

## Relay, L2, discovery, listeners, and camouflage

Methods: `GetRelay`, `GetL2`, `GetDiscovery`, `ListListeners`, `GetCamouflage`.
Relay snapshots contain the canonical config, total bytes, per-destination/network bytes, and drop reasons.
Report deny, network permission, budget, ACL, and unavailable-path drops. Retain bounded metric labels.
Count each data egress copy before transport framing. Control and transport retransmissions consume no transit credit.
Expose desired permission and advertised permission separately during topology convergence.

L2 snapshots use the L2 worker's snapshot interface. Include paged FDB entries, VLAN, MAC, owner, age, and BUM counters.
Discovery snapshots use tracker runtime snapshots. Include tracker status, candidate counts, active path, and errors.
Mapping observations include protocol, socket, observer, endpoint, age, expiry, and provisional status.
Listener snapshots contain URI, transport, lanes, configured path, authentication state, binding kind, and config revision.
Camouflage snapshots expose effective SNI, HTTP authority, WSS path, certificate source, decoy endpoints,
SNI routing, and trusted proxy CIDRs. Redact the admission secret.
Report the current certificate verification inference. CDN outer TLS uses PKI; its inner TLS supplies the peer exporter.

## Configuration and runtime apply

Methods: `GetConfig`, `ValidateConfig`, `PatchConfig`.
`NodeConfig` projects TOML, including relay, camouflage, limits, discovery, identity, endpoints, L2, underlay,
ACL, port forwards, and retained core settings. Optional scalars preserve presence. Arrays replace completely.
Reject unknown keys and retired options. Return the replacement path for retired options.

`ConfigPatch { expected_revision, field_mask, values, clear_paths, persist, stage }` uses optimistic concurrency.
Reject stale revisions and conflicting mask/clear paths. Preserve untouched secrets. Redacted placeholders cannot set secrets.
Validate and prepare resources before publication. A persistence failure preserves the previous active configuration.
Return `ApplyResult { revision, live_fields, new_connection_fields, restart_fields, errors }`.
Default patches reject fields that require restart. Explicit staging changes desired configuration and reports active fields.
Relay changes apply live and rebuild forwarding snapshots. Permission narrowing applies to queued data at egress.
Camouflage changes affect new connections. Existing authenticated connections keep their exporter binding.

After FFI uses this service through pbjson, delete `NetworkConfig` conversions and `json_rpc`.
Web client code is already removed. Do not add a replacement GUI-specific configuration model.

The implemented protobuf schema uses repeated strings for `field_mask`.
Paths use TOML names, such as `relay.use_relays`, `camouflage.http_host`, and `port_forward`.
Mask paths cannot overlap clear paths or other mask paths. Arrays replace completely.
Revision values start at one. Successful changes increment the revision once.
`GetConfig` returns separate `desired` and `active` projections and pending `restart_fields`.
`ValidateConfig` uses the same active baseline and apply classes as `PatchConfig`.
Secrets are absent or use `[REDACTED]`. Untouched secrets remain in the stored configuration.
ACL group arrays preserve redacted secrets for existing group names.
Each transaction prepares ACL rules and TLS identity before persistence and publication.
Failed persistence leaves the previous configuration and revision active.

Relay, limits, hostname, and ACL fields apply live.
`limits.memory_bytes` requires a process restart because instances share the strictest explicit memory limit.
Instance stop/start does not activate a staged process memory limit.
Camouflage HTTP authority, WSS path, and trusted proxy CIDRs affect new connections.
TLS identity, SNI classification, admission secret, website root, and decoy endpoints require restart when QUIC is enabled.
This includes QUIC endpoints created by discovery. Existing authenticated connections keep their transport binding.
Other core settings and port forwards currently require restart while the instance runs.
Use `stage=true` to store those desired changes. Stop and start the instance to activate staged fields.
Stopped instances apply configuration fields immediately. Startup rejects patches until the instance service becomes ready.
Instances created through the API use memory configuration and permit deletion after stop.
Persistence requires an instance configuration file with write permission.

`ListRoutes` reconstructs only the requested page from a captured immutable graph.
Each request shares the existing route work limit. A path error reports unavailable or exhausted reconstruction.
Goodput reconstruction retains each destination's positive delivery threshold.
Route summaries remain O(V). The captured graphs require O(V + E) storage.
`sample_expiry_ms` reports the remaining lifetime of a peer measurement.
Relay ACL drops use the instance forwarding-chain counter. These drops have instance scope.
Unavailable-path drops count transit sends without a usable destination or gateway.
These drops use one aggregate counter in the owning instance, including foreign transit.
Discovery HTTP observations describe the HTTP control socket. They do not identify the VPN transport socket.
An omitted observation expiry means that the observer did not supply a lifetime.

The FFI JSON bridge accepts the exact service name and PascalCase method names.
Its manager supplies trusted ownership. The request selects only instances owned by that manager.
The bridge uses generated pbjson requests and responses, including shared lowercase `ApiError` codes.
API failures return an error envelope. Invalid C pointers still return the C ABI failure code.
The FFI manager lock covers lifecycle changes and data-plane handle cleanup.

## Statistics, logs, watch, and administration

Methods: `GetStats`, `GetPrometheus`, `WatchChanges`, `ReadLogs`, `GetLogConfig`, `SetLogConfig`,
`GetAcl`, `SetAcl`, `GetAclStats`, `ListCredentials`, `IssueCredential`, `RevokeCredential`,
`ListPortForwards`, `PutPortForward`, `DeletePortForward`.
Prometheus remains protected by portal authentication. Use paced statistics snapshots and a bounded shared log ring.
Return log truncation counters and cursors. Paginate logs and credentials.

Use unary long polling: `WatchRequest { resources, cursor, max_wait_ms }`.
Return `WatchResponse { cursor, changed, reset }`. Limit each wait to 20 seconds.
Client deadlines must exceed the server wait. Coalesce resource generations; do not allocate per-client event queues.
Expired cursors and process restarts return reset. Watch does not promise every intermediate event.
ACL and credential methods retain existing authorization checks. Port forward changes use the same configuration transaction.

## CLI contract

Keep `lowertier-cli.rs` small. Use `cli/{args,client,render,error,commands}`.
Command modules construct typed requests. Only render writes results or applies table width limits.
Commands cover node, peer, route, relay, L2, discovery, listener, camouflage, config, stats, log,
ACL, credential, port-forward, and instance resources. Service installation and completion remain local operations.
Select the sole instance automatically. Otherwise require `--instance`. Never fan out mutations implicitly.

Default output is a table. `--output json` emits one envelope:
`{ schema_version, request_id, instance_id, revision, data, error }`.
Exactly one of data or error is populated. Watch/follow emits one envelope per line.
JSON preserves identifiers and complete requested paths. Tables show units, active policy, and the first hop as `via`.
Diagnostics use stderr. `-v` changes diagnostics only. Mutations return apply results.

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Internal error |
| 2 | Arguments or validation |
| 3 | Authentication or permission |
| 4 | Missing or ambiguous resource |
| 5 | Revision conflict or restart required |
| 6 | Connection or deadline |
| 7 | Partial failure |
