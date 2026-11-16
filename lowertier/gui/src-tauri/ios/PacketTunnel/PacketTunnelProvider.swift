import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let work = DispatchQueue(label: "com.lowertier.vpn-control")
    private var bridge: PacketBridge?
    private var instanceName: String?
    private var instanceID: String?
    private var generation = 0
    private var starting: ((Error?) -> Void)?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        work.async {
            self.generation += 1
            let generation = self.generation
            self.starting = completionHandler
            do {
                guard var profile = try ProfileStore.load(),
                      let configuration = self.protocolConfiguration as? NETunnelProviderProtocol,
                      configuration.providerConfiguration?["profileID"] as? String == profile.id else {
                    throw TunnelError.message("The saved VPN profile is missing or has changed.")
                }
                var output: UnsafePointer<CChar>?
                guard profile.config.withCString({ prepare_packet_tunnel_config($0, &output) }) == 0,
                      let output else { throw self.coreError() }
                let preparedData = Data(String(cString: output).utf8)
                free_string(output)
                guard let prepared = try JSONSerialization.jsonObject(with: preparedData) as? [String: Any],
                      let config = prepared["config"] as? String,
                      let name = prepared["instance_name"] as? String,
                      let id = prepared["instance_id"] as? String,
                      let address = prepared["ipv4"] as? String,
                      let mask = prepared["mask"] as? String,
                      let routes = prepared["routes"] as? [[String: String]] else {
                    throw TunnelError.message("The core returned invalid network settings.")
                }
                // Save generated identity before any network operation can publish it.
                profile.config = config
                try ProfileStore.save(profile)
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                let ipv4 = NEIPv4Settings(addresses: [address], subnetMasks: [mask])
                ipv4.includedRoutes = try routes.map {
                    guard let address = $0["address"], let mask = $0["mask"] else {
                        throw TunnelError.message("The core returned an invalid IPv4 route.")
                    }
                    return NEIPv4Route(destinationAddress: address, subnetMask: mask)
                }
                settings.ipv4Settings = ipv4
                if let value = prepared["ipv6"] as? [String: Any],
                   let address = value["address"] as? String, let network = value["network"] as? String,
                   let prefix = value["prefix"] as? Int {
                    let ipv6 = NEIPv6Settings(addresses: [address], networkPrefixLengths: [NSNumber(value: prefix)])
                    ipv6.includedRoutes = [NEIPv6Route(destinationAddress: network, networkPrefixLength: NSNumber(value: prefix))]
                    settings.ipv6Settings = ipv6
                }
                settings.mtu = 1280
                self.setTunnelNetworkSettings(settings) { error in
                    self.work.async {
                        guard generation == self.generation else { return }
                        do {
                            if let error { throw error }
                            let bridge = PacketBridge(
                                deliver: { [weak provider = self] packets, protocols in
                                    provider?.packetFlow.writePackets(packets, withProtocols: protocols) ?? false
                                },
                                fail: { [weak provider = self] error in provider?.fail(error, generation: generation) }
                            )
                            self.bridge = bridge
                            guard config.withCString({ run_network_instance($0) }) == 0 else { throw self.coreError() }
                            self.instanceName = name
                            self.instanceID = id
                            self.waitUntilReady(bridge, generation: generation, deadline: Date().addingTimeInterval(20))
                        } catch { self.fail(error, generation: generation) }
                    }
                }
            } catch { self.fail(error, generation: generation) }
        }
    }

    private func waitUntilReady(_ current: PacketBridge, generation: Int, deadline: Date) {
        guard generation == self.generation, bridge === current, let instanceName else { return }
        do {
            if try current.start(instance: instanceName) {
                ProfileStore.diagnostics?.removeObject(forKey: "lastError")
                readPackets(current, generation: generation)
                let complete = starting
                starting = nil
                complete?(nil)
            } else if Date() < deadline {
                work.asyncAfter(deadline: .now() + 0.1) {
                    self.waitUntilReady(current, generation: generation, deadline: deadline)
                }
            } else {
                throw TunnelError.message("The VPN core did not become ready.")
            }
        } catch { fail(error, generation: generation) }
    }

    private func readPackets(_ current: PacketBridge, generation: Int) {
        packetFlow.readPackets { [weak self, weak current] packets, protocols in
            guard let self, let current else { return }
            current.send(packets, protocols: protocols) { [weak self, weak current] in
                guard let self, let current else { return }
                self.work.async {
                    guard generation == self.generation, self.bridge === current else { return }
                    self.readPackets(current, generation: generation)
                }
            }
        }
    }

    private func coreError() -> Error {
        // Parser diagnostics can contain configuration secrets.
        return TunnelError.message("The VPN core rejected the configuration or packet interface.")
    }

    private func fail(_ error: Error, generation expected: Int) {
        work.async {
            guard expected == self.generation else { return }
            ProfileStore.diagnostics?.set(error.localizedDescription, forKey: "lastError")
            let complete = self.starting
            self.starting = nil
            self.cleanup {
                if let complete { complete(error) } else { self.cancelTunnelWithError(error) }
            }
        }
    }

    private func cleanup(_ completion: @escaping () -> Void) {
        generation += 1
        bridge?.stop {}
        bridge = nil
        if let name = instanceName {
            name.withCString { name in
                var names: [UnsafePointer<CChar>?] = [name]
                _ = delete_network_instance(&names, 1)
            }
        }
        instanceName = nil
        instanceID = nil
        completion()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        work.async {
            let starting = self.starting
            self.starting = nil
            self.cleanup {
                starting?(TunnelError.message("The VPN connection was stopped."))
                completionHandler()
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        work.async {
            let response: [String: Any]
            do {
                guard messageData.count <= 256 * 1024,
                      let request = try JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                      let path = request["path"] as? String else {
                    throw TunnelError.message("The provider request is invalid.")
                }
                if path == "snapshot" {
                    let node = try self.rpc("GetNode")
                    let peers = try self.rpc("ListPeers", ["page": ["limit": 256]])
                    let routes = try self.rpc("ListRoutes", ["include_paths": true, "page": ["limit": 256]])
                    response = [
                        "instance": self.instanceName ?? "", "sampled_at_unix_ms": Date().timeIntervalSince1970 * 1000,
                        "node": node, "peers": peers["peers"] ?? [], "routes": routes["routes"] ?? []
                    ]
                } else if path.hasPrefix("rpc/") {
                    let method = String(path.dropFirst(4))
                    let allowed: Set<String> = [
                        "GetNode", "ListPeers", "ListRoutes", "ListPaths", "GetStats", "ReadLogs",
                        "GetDiscovery", "GetRelay", "ListListeners"
                    ]
                    guard allowed.contains(method) else { throw TunnelError.message("This provider command is not permitted.") }
                    response = try self.rpc(method, request["body"] as? [String: Any] ?? [:])
                } else {
                    throw TunnelError.message("Unknown provider request.")
                }
            } catch {
                response = ["error": ["code": "unavailable", "message": error.localizedDescription]]
            }
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        }
    }

    private func rpc(_ method: String, _ payload: [String: Any] = [:]) throws -> [String: Any] {
        guard let id = instanceID else { throw TunnelError.message("The VPN core is stopped.") }
        var body = payload
        body["meta"] = ["instance_id": id]
        let text = String(decoding: try JSONSerialization.data(withJSONObject: body), as: UTF8.self)
        var output: UnsafePointer<CChar>?
        let result = "api.control.v1.ControlPlaneV1Rpc".withCString { service in
            method.withCString { method in text.withCString { call_json_rpc(service, method, nil, $0, &output) } }
        }
        guard result == 0, let output else { throw coreError() }
        defer { free_string(output) }
        guard let doc = try JSONSerialization.jsonObject(with: Data(String(cString: output).utf8)) as? [String: Any] else {
            throw TunnelError.message("The core returned an invalid control response.")
        }
        if let error = doc["error"] as? [String: Any] {
            throw TunnelError.message(error["message"] as? String ?? "The control request failed.")
        }
        return doc
    }
}
