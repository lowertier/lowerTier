# Native iOS control

`VpnPlugin.swift` manages `NETunnelProviderManager`.
`Shared.swift` stores the active configuration in the shared Keychain.
The containing app and the packet extension use the same Keychain group.

The provider accepts only the listed read commands.
Configuration changes require a disconnected VPN and an explicit profile replacement.
