# WSS through a terminating CDN

Use `via=cdn` when a proxy terminates the public TLS or WebSocket connection.
Configure the option on both the client URL and the origin listener URL.

```toml
# Origin configuration
listeners = ["wss://0.0.0.0:11012?via=cdn"]

# Client configuration, in a separate file
[[peer]]
uri = "wss://YOUR-TUNNEL-HOST.example:443?via=cdn"
```

Replace the example host with a hostname that you control.
Configure the CDN to forward WebSocket connections to the origin listener.
Preserve the `Sec-WebSocket-Protocol: lowertier-tls-v1` request and response headers.
The CDN must permit long-lived binary WebSocket messages.

The client validates the public CDN certificate.
An inner TLS connection runs inside WebSocket and supplies the TLS exporter for Noise authentication.
The CDN cannot replace that authenticated peer connection with its own TLS exporter.
The inner TLS handshake uses `challenges.cloudflare.com` as its compatibility SNI.
This SNI does not imply certificate ownership or make the connection unidentifiable.

The origin uses its existing ephemeral TLS certificate.
Configure origin certificate verification for that deployment explicitly.
The normal configuration interface requires a `wss` origin listener.
Peer authentication requires the inner TLS connection in CDN mode.

Direct WSS keeps its existing outer TLS exporter binding.
CDN mode requires both endpoints to support the inner TLS subprotocol.
It does not fall back to unbound authentication when the subprotocol is absent.
Multiple TCP lanes are not available in CDN mode.

WebSocket messages have a 256 KiB payload limit, including fragmented messages.
Inner TLS writes use chunks of at most 32 KiB.
The additional TLS layer has a CPU and framing cost.
Compare throughput and CPU per delivered Gbit on the intended CDN path.

Underlay restrictions still apply.
A policy that rejects DNS tunnel targets can reject the CDN hostname before connection setup.
Use a policy suitable for the intended public CDN addresses.
