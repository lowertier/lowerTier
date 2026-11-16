# LowTier VPN bridge

This local plugin connects the shared Solid frontend to the iOS VPN manager.
Its commands store profiles, connect, disconnect, and read provider state.
The packet tunnel runs in a separate extension.
The plugin never sends packet data through the WebView.

See [the iOS guide](../../../../../docs/ios-app.md) for build and signing instructions.
