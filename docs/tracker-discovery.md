# Tracker discovery

LowTier can discover initial peers through UDP, HTTP, or HTTPS torrent trackers.
Hosted LowTier trackers also accept length-prefixed tracker messages over TCP.
The tracker returns transport endpoints. It does not authenticate nodes or relay VPN traffic.
Peers still complete the transport handshake and the existing Noise authentication.
TLS exporter binding remains enabled for QUIC, H2, and WSS.

Tracker discovery is opt-in. A configuration without `[discovery]` uses its configured peers for bootstrap and does not announce to public trackers. After peers connect, encrypted peer RPCs coordinate hole punching while STUN discovers NAT mappings. A tracker supplies bootstrap addresses; a connected peer can coordinate punching and provide relay fallback.

QUIC/UDP, H2/TCP, and WSS/TCP are all allowed by default, and both UDP and TCP punching are enabled.
Omit `transport.protocols` to retain those transport defaults.
Tracker discovery maintains an independent rendezvous namespace and path for every enabled protocol.
`transport.prefer` selects the preferred connection without stopping the other protocols.

## Client configuration

```toml
[network]
name = "example-network"
secret_file = "/etc/lowertier/example.secret"

[transport]
listen = []
prefer = "quic"

[discovery]
trackers = [
  "udp://open.stealth.si:80/announce",
  "udp://tracker.torrent.eu.org:451/announce",
  "https://tracker.example.net/announce",
]
```

Set `transport.prefer` to `tcp` for H2 or `wss` for WSS.
Nodes with different preferences can discover each other through every protocol they both enable.
Tracker contact and peer transport are independent.
H2 and WSS bootstrap with QUIC disabled through TCP, HTTP, or HTTPS trackers.
Configure at least one TCP or HTTP(S) tracker when UDP traffic is blocked.
The `tcp://` scheme requires a LowTier hosted tracker and an explicit port.
The public tracker fragment in `script/mesh-discovery/public-trackers.toml` supplies UDP, HTTP, and HTTPS alternatives.
Public HTTP and HTTPS trackers already use TCP; native `tcp://` framing is a separate hosted-service extension.
Remove `[[peer]]` entries when the tracker must supply the entire bootstrap peer set.
Existing configured peers remain available when both mechanisms are configured.
Tracker discovery requires a nonempty shared network secret. Credential-only bootstrap is not supported by this initial version.
Tracker URLs can contain an existing query string, such as a private tracker passkey.
Do not publish configuration files that contain secrets or passkeys.

LowTier selects permitted local addresses from its interface collector.
It does not require an interface named `eth0`, `en0`, or `map-m4`.
Existing underlay allow and deny rules apply to tracker connections and discovered peers.
Public tracker candidates exclude local and private address scopes.
List private service URLs in `discovery.private_trackers` to permit those scopes.
The effective tracker set is the deduplicated union of `trackers` and `private_trackers`, with at most eight distinct URLs.
A URL in `private_trackers` is private even when it also appears in `trackers`.
Either list can be omitted. At least one tracker URL is required across the two lists.
The automatic address selection currently uses IPv4. Explicit IPv6 binding supports tracker codecs and QUIC endpoints; automatic dual-stack discovery is pending.

For a reachable seed or a fixed port mapping, set explicit socket endpoints:

```toml
[discovery]
private_trackers = ["http://127.0.0.1:6970/announce"]
bind = "127.0.0.1:16969"
advertise = "127.0.0.1:16969"
```

This example addresses a local test server. For deployment, use the seed's actual local address and mapped public endpoint.
The tracker uses the request's observed IP and the advertised port.
The `advertise` IP must therefore match the public source IP that the tracker observes.
The seed needs the same network secret as its peers.
The protocol preferred at instance start retains the configured `bind` and `advertise` endpoints.
Other protocols use temporary ports on the same permitted local address and discover their own mappings.
Changing the preference preserves existing socket mappings.

## Bootstrap sequence

1. Start STUN and independent tracker requests concurrently.
2. Send BEP 15 CONNECT before STUN completes.
3. Announce the bound transport port provisionally while STUN collects a mapping.
4. Attempt returned candidates immediately.
5. Complete VPN authentication before accepting membership.
6. Use existing encrypted routing and rendezvous RPCs to discover and connect additional peers.

QUIC shares one UDP socket for STUN, BEP 15, authenticated punch packets, and punched VPN connections.
Punch packets encrypt the peer ID, timestamp, and challenge with XChaCha20-Poly1305.
Each packet uses a fresh random 24-byte cipher nonce and randomized padding.
Packets range from 96 to 192 bytes and contain no clear LowTier marker.
Replies must match a recent probe. The peer ID must pass the subsequent VPN handshake.
The lower peer ID initiates QUIC after the authenticated exchange.
Duplicate tracker results retain the same active probe challenge.
Probe bursts and connection handshakes have separate concurrency limits.
Speculative QUIC handshakes share a process-wide limit across interfaces and instances.
Their fixed memory reservations cannot exceed one quarter of the process memory budget.
Queued attempts check membership again before they allocate a connection.
Silent candidates can delay bootstrap while these bounded handshake slots remain occupied.
If bootstrap still has no peer after the probe burst, the client also attempts a standard QUIC handshake.
This fallback uses a fresh source port on the same permitted local address.
It permits a reachable seed to work when the discovery UDP flow cannot carry QUIC.
The fallback retains transport authentication, Noise authentication, and same-network admission.
While that fallback remains pending, a valid PUNCH message can switch the attempt to the original mapped socket.
The attempt retains its handshake permit and deadline.

H2 and WSS announce their TCP STUN port when available, or the bound TCP port provisionally.
A separate UDP socket queries UDP trackers. Its observed UDP port never replaces a TCP port.
Their first bootstrap TCP attempt reuses the reserved source port.
A conventional fresh-port connection starts after 750 milliseconds on the same permitted local address.
The complete attempt has a 45-second deadline and retains all authentication checks.
The advertised listener and retained STUN connections survive this retry.
After bootstrap, authenticated rendezvous RPCs coordinate simultaneous TCP opens between known peers.
Pending punch connections remain alive until the existing 20-second traversal deadline.
Failed candidates retry independently; a pending candidate does not delay another candidate's retry.
New peers can also negotiate bounded TCP port search when only one side reports varying STUN mappings.
The variable side opens a pool of source ports toward the stable candidate.
The stable side searches ports at the other peer's public address from its reserved source port.
Each successful stream still needs TLS authentication, the rendezvous token, and VPN authentication.
This uses native TCP for both H2 and WSS.
Peers with symmetric traversal disabled use candidate-only traversal.
When both sides report varying mappings, the expanded method is not used.

Authenticated peers advertise their enabled punching protocols.
Each common protocol schedules and repairs its own direct path.
A healthy path on another protocol does not cancel the attempt or consume its retry delay.
An established peer retains this behavior in lazy P2P mode.
Disabling a protocol prevents new attempts and withdraws its tracker path without closing the other tracker paths.
The existing process memory budget, handshake limits, traversal permits, and tracker traffic limits remain shared.
Each peer map retains its limit of 64 live connections.
Each peer can hold two connections per protocol, which permits a replacement without closing the current path.
Internal tunnel names share one quota and cannot create additional protocol quotas.

One process-wide permit covers expanded TCP traversal and QUIC socket pools across all networks.
QUIC port search retains one existing socket and does not need this pool permit.
Each QUIC pool contains at most 128 sockets and uses the same available-descriptor calculation.
QUIC destroys its inline receive futures and unused sockets before releasing the permit.
The TCP pool has at most 128 listeners and 128 pending outgoing connections.
TCP port search has at most 128 pending connections and a shuffled list of at most 4096 ports.
On Unix, traversal uses at most half the currently available file-descriptor capacity.
The budget accounts for listeners, outgoing connections, stream handoff, and transport handshakes.
It preserves the process file limit. Unavailable descriptor enumeration disables expanded traversal.
Concurrent daemon work can consume the remaining capacity after the snapshot.
New attempts are paced at eight milliseconds. Search connections expire after eight seconds.
Expanded traversal stops after 28 seconds, within the existing 40-second overall attempt deadline.
With silent drops and the full 128-connection capacity, approximately 512 ports can be searched.
Lower descriptor capacity reduces that number.
Cancellation retains the process permit until outstanding connection workers release their sockets.
Pool accepts run within the traversal task and do not create one task per listener.
The method remains probabilistic and depends on NAT TCP behavior.
An observed UDP mapping does not establish a TCP mapping.
Automatic TCP mappings refresh every 30 seconds through the retained STUN connections.
Failed connections close before the client reacquires mappings from the same reserved source port.
The client uses its bound port provisionally when it has no valid mapping.
The provisional port can be unreachable behind NAT. Outbound bootstrap remains available.
Locally assigned public ports retain their listeners while valid and acquire replacement listeners when needed.
The advertised local public endpoint matches the bound listener.
Established VPN sessions remain independent of this mapping maintenance.
An explicit `advertise` setting remains static.

Normal announcements respect each tracker's interval.
A changed mapping starts a new announce event with a minimum event delay.
Failed trackers retry independently. A slow tracker does not delay a successful tracker.
The client retains a connection ID for at most 60 seconds.
While disconnected, the client retries cached peer candidates without querying the tracker again.
Each attempt uses one permitted DNS address of the socket's address family.
Failed attempts advance through a sorted, deduplicated address list for both UDP and HTTP/HTTPS trackers.
DNS resolution enters and leaves the network namespace on the same blocking worker thread.
Tracker tasks copy valid mappings under the watch read lock, so concurrent withdrawal cannot invalidate that read.
Independent tracker URLs remain useful because one slow address can delay an individual attempt.

Tracker discovery cannot guarantee a direct path between arbitrary NATs.
A tracker does not notify an old peer when a new peer announces.
At least one reachable seed is necessary when all other returned endpoints reject initial traffic.
The seed can coordinate punching and provide the existing relay fallback.
The tracker alone cannot replace that function.

## Rendezvous namespace

The key is the existing 32-byte network secret digest, which includes the network name and shared secret.
QUIC uses:

```text
H = HMAC-SHA256(key, "vpn-rendezvous-v1")[0..20]
```

H2 appends `\0transport=tcp` to the HMAC message.
WSS appends `\0transport=wss`.
This prevents compact tracker entries from mixing transport types.
Each tracker, protocol, and local path has an independent random 20-byte tracker peer ID.
The announce key is random and does not repeat bytes from the peer ID.
Public trackers can observe the rendezvous hash, public IP, and advertised port.
Knowledge of the hash does not authorize VPN access.

## Tracker privacy limits

Public announcements use standard tracker fields.
HTTP requests do not claim another application's user agent.
Transfer counters remain zero because these requests do not report torrent payload transfers.
The `left` value stays constant and does not reveal whether a peer connection is active.
Private services receive `left=2` to retain their 30-second polling floor.
Public services receive `left=1` and control their own announce intervals.

Independent peer IDs reduce exact identity reuse across trackers and transports.
The rendezvous hash remains stable for a network and protocol.
A tracker can still group endpoints by that hash and correlate their source addresses and timing.
An active tracker can return an endpoint that it controls and inspect the resulting traffic.
Encrypted probes remove the clear marker but do not reproduce the BitTorrent peer protocol.
Private endpoint-observation extensions remain LowTier-specific.
HTTPS protects tracker requests from intermediate observers; the tracker operator can read them.

## Self-hosted tracker

```sh
cargo build --release -p lowertier-tracker --features server --bin lowertier-tracker
lowertier-tracker --udp-listen 0.0.0.0:6969 --http-listen 127.0.0.1:6970
```

The service implements BEP 15 CONNECT and ANNOUNCE, plus compact HTTP announcements at `/announce`.
Use `--tcp-listen 127.0.0.1:16970` to enable native TCP tracker contact.
Each TCP frame has a four-byte big-endian length followed by a BEP 15 message.
One connection serves CONNECT and ANNOUNCE, with a 15-second overall deadline.
Request frames are limited to 2048 bytes; response frames are limited to 16 KiB.
TCP tracker connections share the existing 64-connection budget and permit at most 16 connections per source IP.
IPv6 source limits apply to a /64, including rotating interface identifiers.
It also supports bounded UDP Binding and optional TCP Binding in the same process.
See [rendezvous options](rendezvous.md) for private echoes, passkeys, and the optional alternate Binding port.
It keeps bounded, expiring state in memory. Restarting the service clears that state.
It has no torrent data transfer, DHT, scrape API, or VPN credentials.

For HTTP behind Caddy, use an actual hostname that you control:

```caddyfile
tracker.example.net {
    @announce path /announce
    reverse_proxy @announce 127.0.0.1:6970 {
        header_up X-Real-IP {remote_host}
    }
}
```

Start the tracker with `--trusted-proxy 127.0.0.1/32` for this local proxy.
Without that option, the tracker ignores forwarded client addresses.
A trusted proxy must supply one valid IP address in `X-Real-IP`.
The `--client-ip-header` option selects another header.

A CDN must forward every announce request to the origin and preserve its complete query string.
Disable caching for `/announce`. The server also sends `Cache-Control: no-store, private`.
Configure the reverse proxy to trust only the CDN's actual proxy networks before extracting the client IP.
Do not pass an arbitrary client-supplied address header through to the tracker.
HTTPS clients validate the server certificate against system roots.
The HTTP client does not follow redirects.

UDP trackers require direct UDP reachability. An ordinary HTTP CDN does not forward BEP 15 packets.
DHT fallback is not part of this implementation.

## References

- [BEP 15 UDP tracker protocol](https://www.bittorrent.org/beps/bep_0015.html)
- [BEP 3 HTTP tracker announcements](https://www.bittorrent.org/beps/bep_0003.html)
- [BEP 55 peer-assisted hole punching](https://www.bittorrent.org/beps/bep_0055.html)

LowTier uses the peer-assisted rendezvous principle from BEP 55.
Its encrypted RPCs and punch packets are not BEP 55 wire messages.
