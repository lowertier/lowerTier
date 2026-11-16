import Foundation
import NetworkExtension
import Tauri
import WebKit

private struct CommandArgs: Decodable {
    let action: String
    let payload: String
}

class VpnPlugin: Plugin {
    private var vpnManager: NETunnelProviderManager?
    private var changing = false
    private var managerWaiters: [(Invoke, (NETunnelProviderManager) -> Void)] = []

    @objc public func execute(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CommandArgs.self)
        let payload = try JSONSerialization.jsonObject(with: Data(args.payload.utf8)) as? [String: Any] ?? [:]
        DispatchQueue.main.async {
            self.withManager(invoke) { manager in
                do {
                    switch args.action {
                    case "status":
                        invoke.resolve(try self.status(manager))
                    case "saveProfile":
                        guard !self.active(manager) && !self.changing else {
                            throw TunnelError.message("Disconnect before replacing the network profile.")
                        }
                        guard let name = payload["name"] as? String, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                              let config = payload["config"] as? String, !config.isEmpty,
                              config.utf8.count <= 256 * 1024 else {
                            throw TunnelError.message("Enter a profile name and a configuration smaller than 256 KiB.")
                        }
                        let id = try ProfileStore.load()?.id ?? UUID().uuidString
                        try ProfileStore.save(TunnelProfile(id: id, name: name, config: config))
                        ProfileStore.diagnostics?.removeObject(forKey: "lastError")
                        invoke.resolve(try self.status(manager))
                    case "connect":
                        guard !self.changing else { throw TunnelError.message("A VPN change is already in progress.") }
                        if self.active(manager) { invoke.resolve(try self.status(manager)); return }
                        guard let profile = try ProfileStore.load() else {
                            throw TunnelError.message("Add a network before connecting.")
                        }
                        self.changing = true
                        let protocolConfig = NETunnelProviderProtocol()
                        protocolConfig.providerBundleIdentifier = Bundle.main.bundleIdentifier! + ".PacketTunnel"
                        protocolConfig.serverAddress = profile.name
                        protocolConfig.providerConfiguration = ["profileID": profile.id]
                        manager.protocolConfiguration = protocolConfig
                        manager.localizedDescription = "LowTier"
                        manager.isEnabled = true
                        manager.saveToPreferences { error in
                            DispatchQueue.main.async {
                                if let error { self.changing = false; invoke.reject(error.localizedDescription); return }
                                manager.loadFromPreferences { error in
                                    DispatchQueue.main.async {
                                        self.changing = false
                                        do {
                                            if let error { throw error }
                                            try manager.connection.startVPNTunnel()
                                            invoke.resolve(try self.status(manager))
                                        } catch { invoke.reject(error.localizedDescription) }
                                    }
                                }
                            }
                        }
                    case "disconnect":
                        guard !self.changing else { throw TunnelError.message("A VPN change is already in progress.") }
                        manager.connection.stopVPNTunnel()
                        invoke.resolve(try self.status(manager))
                    case "deleteProfile":
                        guard !self.active(manager) && !self.changing else {
                            throw TunnelError.message("Disconnect before removing the network profile.")
                        }
                        try ProfileStore.delete()
                        invoke.resolve(try self.status(manager))
                    case "request":
                        guard manager.connection.status == .connected,
                              let session = manager.connection as? NETunnelProviderSession else {
                            throw TunnelError.message("Connect the VPN to read network information.")
                        }
                        let data = try JSONSerialization.data(withJSONObject: payload)
                        guard data.count <= 256 * 1024 else { throw TunnelError.message("The request is too large.") }
                        try session.sendProviderMessage(data) { response in
                            guard let response, let object = try? JSONSerialization.jsonObject(with: response) as? [String: Any] else {
                                invoke.reject("The VPN extension did not answer."); return
                            }
                            invoke.resolve(object)
                        }
                    default:
                        throw TunnelError.message("Unknown VPN command.")
                    }
                } catch { invoke.reject(error.localizedDescription) }
            }
        }
    }

    private func withManager(_ invoke: Invoke, _ body: @escaping (NETunnelProviderManager) -> Void) {
        if let manager = vpnManager { body(manager); return }
        managerWaiters.append((invoke, body))
        guard managerWaiters.count == 1 else { return }
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async {
                let waiting = self.managerWaiters
                self.managerWaiters.removeAll()
                if let error {
                    for (invoke, _) in waiting { invoke.reject(error.localizedDescription) }
                    return
                }
                let identifier = Bundle.main.bundleIdentifier! + ".PacketTunnel"
                let found = managers?.first {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier
                } ?? NETunnelProviderManager()
                self.vpnManager = found
                for (_, body) in waiting { body(found) }
            }
        }
    }

    private func active(_ manager: NETunnelProviderManager) -> Bool {
        [.connected, .connecting, .reasserting, .disconnecting].contains(manager.connection.status)
    }

    private func status(_ manager: NETunnelProviderManager) throws -> [String: Any] {
        let states: [NEVPNStatus: String] = [
            .invalid: "disconnected", .disconnected: "disconnected", .connecting: "connecting",
            .connected: "connected", .reasserting: "reconnecting", .disconnecting: "disconnecting"
        ]
        var result: [String: Any] = [
            "state": states[manager.connection.status] ?? "disconnected",
            "platform": "ios", "mtu": 1280,
            "lastError": ProfileStore.diagnostics?.string(forKey: "lastError") ?? ""
        ]
        if let profile = try ProfileStore.load() {
            result["profile"] = ["id": profile.id, "name": profile.name]
        }
        if let date = manager.connection.connectedDate {
            result["connectedAt"] = date.timeIntervalSince1970 * 1000
        }
        return result
    }
}

@_cdecl("init_plugin_lowertier_vpn")
public func initPlugin() -> Plugin { VpnPlugin() }
