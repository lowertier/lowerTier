# Fabric protocol version 4

Protocol version 4 uses one fabric dataplane for IP packets and Ethernet frames.

## Packet model

`FabricPacket` contains one payload kind and one zero-copy packet buffer.

`FabricBatch` contains packets of one payload kind.

The sender uses one `send_fabric_batch` function for all platform interfaces.

The IP payload kind uses the compact routed representation.

The Ethernet payload kind retains the complete Ethernet frame when L2 data is necessary.

The receiver continues to use authenticated peer headers for both payload kinds.

## Platform interface

LowTier selects TAP on Linux and FreeBSD.

LowTier selects TUN on other operating systems.

The removed adapter settings do not change this selection.

TAP IP traffic uses the compact routed representation.

## Route planes

Node topology computes reachability and the next hop for each gateway node.

The service RIB stores IPv4 and IPv6 prefix routes separately.

A service route contains a prefix, gateway peer ID, preference, metric, path ID, and action.

Longest-prefix matching occurs before preference and metric selection.

Equal routes use rendezvous selection across live gateways.

A bounded cache pins each flow to its selected gateway for 300 seconds.

Route withdrawal moves only flows whose gateway is no longer eligible.

The supported actions are `FORWARD`, `EXIT_SNAT`, and `BLACKHOLE`.

## Local BGP API

The `PeerManageRpc` service provides `ReplaceLocalBgpRoutes` and `ListLocalBgpRoutes`.

The replace operation is atomic for the local BGP source.

The API accepts IPv4 and IPv6 prefixes.

The API requires a loopback RPC connection and a valid administrator token.

The gateway peer ID can identify any reachable node.

## Migration rule

Protocol version 4 requires an exact peer protocol version match during the authenticated handshake.

A version 3 node cannot join a version 4 network.

Upgrade all nodes during one controlled network maintenance operation.

Do not operate a mixed version 3 and version 4 network.
