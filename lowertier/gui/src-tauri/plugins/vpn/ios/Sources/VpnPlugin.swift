import Foundation
import NetworkExtension
import Tauri
import WebKit

private struct ProfileSummary {
    let id: String
    let name: String
}

class VpnPlugin: Plugin {
    private var vpnManager: NETunnelProviderManager?
    private var changing = false
    private var managerWaiters: [(Invoke, (NETunnelProviderManager) -> Void)] = []
    private var profileSummary: ProfileSummary?
    private var profileLoaded = false
    private var connectionGeneration: UInt64 = 0
    private var observedStatus: NEVPNStatus?
    private var observedDate: Date?
    private var statusObserver: NSObjectProtocol?
    private let statusLock = NSLock()
    private var statusRevision: UInt64 = 0
    private var disconnectRevision: UInt64 = 0
    private var observedRevision: UInt64 = 0
    private var requestSerial: UInt64 = 0
    private var pendingRequest: (id: UInt64, statusRevision: UInt64)?

    deinit {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
    }

    @objc public func execute(_ invoke: Invoke) throws {
        guard let args = try JSONSerialization.jsonObject(with: Data(invoke.getRawArgs().utf8)) as? [String: Any],
              let action = args["action"] as? String, let payload = args["payload"] as? [String: Any] else {
            throw TunnelError.message("The VPN command is invalid.")
        }
        DispatchQueue.main.async {
            self.withManager(invoke) { manager in
                do {
                    switch action {
                    case "poll":
                        let status = try self.status(manager)
                        guard manager.connection.status == .connected,
                              let session = manager.connection as? NETunnelProviderSession else {
                            invoke.resolve(["status": status]); return
                        }
                        self.request(manager, session: session, payload: ["path": "snapshot"]) { response, generation in
                            do {
                                var result: [String: Any] = ["status": try self.status(manager)]
                                if self.observedStatus == .connected {
                                    result["snapshot"] = generation == self.connectionGeneration ? response : self.changedConnection()
                                }
                                invoke.resolve(result)
                            } catch { invoke.reject(error.localizedDescription) }
                        }
                    case "saveProfile":
                        guard !self.active(manager) && !self.changing else {
                            throw TunnelError.message("Disconnect before replacing the network profile.")
                        }
                        guard let name = payload["name"] as? String, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                              let config = payload["config"] as? String, !config.isEmpty,
                              config.utf8.count <= 256 * 1024 else {
                            throw TunnelError.message("Enter a profile name and a configuration smaller than 256 KiB.")
                        }
                        let id = try self.profile()?.id ?? UUID().uuidString
                        try ProfileStore.save(TunnelProfile(id: id, name: name, config: config))
                        self.profileSummary = ProfileSummary(id: id, name: name)
                        self.profileLoaded = true
                        ProfileStore.diagnostics?.removeObject(forKey: "lastError")
                        invoke.resolve(try self.status(manager))
                    case "connect":
                        guard !self.changing else { throw TunnelError.message("A VPN change is already in progress.") }
                        if self.active(manager) { invoke.resolve(try self.status(manager)); return }
                        guard let profile = try self.profile() else {
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
                        // Both preference completion handlers run on the main thread under the NetworkExtension contract.
                        manager.saveToPreferences { error in
                            if let error { self.changing = false; invoke.reject(error.localizedDescription); return }
                            manager.loadFromPreferences { error in
                                self.changing = false
                                do {
                                    if let error { throw error }
                                    try manager.connection.startVPNTunnel()
                                    invoke.resolve(try self.status(manager))
                                } catch { invoke.reject(error.localizedDescription) }
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
                        self.profileSummary = nil
                        self.profileLoaded = true
                        invoke.resolve(try self.status(manager))
                    case "request":
                        guard manager.connection.status == .connected,
                              let session = manager.connection as? NETunnelProviderSession else {
                            throw TunnelError.message("Connect the VPN to read network information.")
                        }
                        self.request(manager, session: session, payload: payload) { response, _ in invoke.resolve(response) }
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
            DispatchQueue.main.async { [self] in
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
                self.updateConnection(found)
                let connection = found.connection
                self.statusObserver = NotificationCenter.default.addObserver(
                    forName: .NEVPNStatusDidChange, object: connection, queue: nil
                ) { [weak self, weak connection] _ in
                    guard let self, let connection else { return }
                    // Capture a brief disconnection before another state replaces it on the main queue.
                    self.statusLock.lock()
                    self.statusRevision += 1
                    if connection.status == .disconnected || connection.status == .invalid {
                        self.disconnectRevision = self.statusRevision
                    }
                    self.statusLock.unlock()
                }
                for (_, body) in waiting { body(found) }
            }
        }
    }

    private func active(_ manager: NETunnelProviderManager) -> Bool {
        [.connected, .connecting, .reasserting, .disconnecting].contains(manager.connection.status)
    }

    private func providerResponse(_ data: Data?) -> [String: Any] {
        guard let data, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ["error": ["code": "unavailable", "message": "The VPN extension did not answer."]]
        }
        return object
    }

    private func changedConnection() -> [String: Any] {
        ["error": ["code": "unavailable", "message": "The VPN connection changed. Refresh the network information."]]
    }

    private func request(
        _ manager: NETunnelProviderManager, session: NETunnelProviderSession, payload: [String: Any],
        completion: @escaping ([String: Any], UInt64) -> Void
    ) {
        updateConnection(manager)
        guard pendingRequest == nil else {
            completion(["error": ["code": "unavailable", "message": "The VPN extension request is still pending."]], connectionGeneration)
            return
        }
        requestSerial += 1
        let request = requestSerial
        let generation = connectionGeneration
        pendingRequest = (request, observedRevision)
        var answered = false
        var timeout: DispatchWorkItem?
        let finish: (Data?) -> Void = { data in
            guard !answered else { return }
            answered = true
            timeout?.cancel()
            timeout = nil
            let response = self.providerResponse(data)
            self.updateConnection(manager)
            completion(generation == self.connectionGeneration ? response : self.changedConnection(), generation)
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: payload)
            guard data.count <= 256 * 1024 else { throw TunnelError.message("The request is too large.") }
            try session.sendProviderMessage(data) { response in
                DispatchQueue.main.async {
                    self.updateConnection(manager)
                    if self.pendingRequest?.id == request { self.pendingRequest = nil }
                    finish(response)
                }
            }
            // The deadline releases the invocation. Admission remains closed until the provider replies or the connection ends.
            timeout = DispatchWorkItem { finish(nil) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: timeout!)
        } catch {
            if pendingRequest?.id == request { pendingRequest = nil }
            answered = true
            completion(["error": ["code": "unavailable", "message": error.localizedDescription]], generation)
        }
    }

    private func updateConnection(_ manager: NETunnelProviderManager) {
        statusLock.lock()
        let revision = statusRevision
        let disconnected = disconnectRevision
        statusLock.unlock()
        let state = manager.connection.status
        let date = manager.connection.connectedDate
        if state == .disconnected || state == .invalid ||
            pendingRequest.map({ $0.statusRevision < disconnected }) == true {
            pendingRequest = nil
        }
        guard revision != observedRevision || state != observedStatus || date != observedDate else { return }
        observedStatus = state
        observedDate = date
        observedRevision = revision
        connectionGeneration += 1
    }

    private func profile() throws -> ProfileSummary? {
        if !profileLoaded {
            // The extension updates credentials and identity. Only the app changes the profile name or ID.
            profileSummary = try ProfileStore.load().map { ProfileSummary(id: $0.id, name: $0.name) }
            profileLoaded = true
        }
        return profileSummary
    }

    private func status(_ manager: NETunnelProviderManager) throws -> [String: Any] {
        updateConnection(manager)
        let states: [NEVPNStatus: String] = [
            .invalid: "disconnected", .disconnected: "disconnected", .connecting: "connecting",
            .connected: "connected", .reasserting: "reconnecting", .disconnecting: "disconnecting"
        ]
        var result: [String: Any] = [
            "state": states[observedStatus ?? .invalid] ?? "disconnected",
            "platform": "ios", "mtu": 1280, "connectionGeneration": connectionGeneration,
            "lastError": ProfileStore.diagnostics?.string(forKey: "lastError") ?? ""
        ]
        if let profile = try profile() {
            result["profile"] = ["id": profile.id, "name": profile.name]
        }
        if let date = observedDate {
            result["connectedAt"] = date.timeIntervalSince1970 * 1000
        }
        return result
    }
}

@_cdecl("init_plugin_lowertier_vpn")
public func initPlugin() -> Plugin { VpnPlugin() }
