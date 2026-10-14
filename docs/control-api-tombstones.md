# Retired management services

`api.control.v1.ControlPlaneV1Rpc` replaces these service identities.
The portal does not register the retired services.
Peer RPC service identities and methods remain unchanged.

| Package | Retired service |
| --- | --- |
| api.instance | PeerManageRpc |
| api.instance | ConnectorManageRpc |
| api.instance | MappedListenerManageRpc |
| api.instance | TcpProxyRpc |
| api.instance | AclManageRpc |
| api.instance | PortForwardManageRpc |
| api.instance | StatsRpc |
| api.instance | CredentialManageRpc |
| api.config | ConfigRpc |
| api.logger | LoggerRpc |
| api.manage | WebClientService |

The retired `NetworkConfig` message reserves its field numbers and names.
Internal snapshot messages remain available for core data structures.
