import Foundation
import NetworkExtension
import Tauri

// These fakes run the production control plugin without a signed VPN or a device.
enum TunnelError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let text): return text }
    }
}

struct TunnelProfile {
    let id: String
    let name: String
    var config: String
}

enum ProfileStore {
    static var value: TunnelProfile? = TunnelProfile(id: "fixture-profile", name: "Fixture network", config: "fixture")
    static var reads = 0
    static var diagnostics: UserDefaults? { nil }
    static func load() throws -> TunnelProfile? { reads += 1; return value }
    static func save(_ profile: TunnelProfile) throws { value = profile }
    static func delete() throws { value = nil }
}

class NEVPNConnection: NSObject {
    var status = NEVPNStatus.connected
    var connectedDate: Date? = Date(timeIntervalSince1970: 1000)
    var starts = 0
    func startVPNTunnel() throws {
        starts += 1
        status = .connecting
        connectedDate = nil
    }
    func stopVPNTunnel() {}
}

final class NETunnelProviderSession: NEVPNConnection {
    var sent = 0
    var replies: [Int: (Data?) -> Void] = [:]
    var onSend: (() -> Void)?

    func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?) -> Void) throws {
        sent += 1
        replies[sent] = responseHandler
        onSend?()
    }

    func respond(_ request: Int, _ object: [String: Any]) throws {
        guard let reply = replies.removeValue(forKey: request) else {
            throw TunnelError.message("The fixture request does not exist.")
        }
        reply(try JSONSerialization.data(withJSONObject: object))
    }

    func transition(_ next: NEVPNStatus, date: Date?) {
        status = next
        connectedDate = date
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: self)
    }
}

final class NETunnelProviderProtocol: NSObject {
    var providerBundleIdentifier: String?
    var serverAddress: String?
    var providerConfiguration: [String: Any]?
}

final class NETunnelProviderManager: NSObject {
    static let current = NETunnelProviderManager()
    let connection: NEVPNConnection = NETunnelProviderSession()
    var protocolConfiguration: NSObject?
    var localizedDescription: String?
    var isEnabled = false
    var saves = 0
    var loads = 0

    override init() {
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = Bundle.main.bundleIdentifier! + ".PacketTunnel"
        protocolConfiguration = configuration
        super.init()
    }

    static func loadAllFromPreferences(completionHandler: ([NETunnelProviderManager]?, Error?) -> Void) {
        completionHandler([current], nil)
    }

    func saveToPreferences(completionHandler: (Error?) -> Void) { saves += 1; completionHandler(nil) }
    func loadFromPreferences(completionHandler: (Error?) -> Void) { loads += 1; completionHandler(nil) }
}

@main
struct VpnControlTest {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) {
        if !value() {
            fputs("FAIL: \(message)\n", stderr)
            exit(1)
        }
    }

    @MainActor
    static func call(_ plugin: VpnPlugin, _ action: String, _ payload: [String: Any] = [:]) async throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: ["action": action, "payload": payload])
        return try await withCheckedThrowingContinuation { continuation in
            let invoke = Invoke(args: String(decoding: data, as: UTF8.self), reply: {
                continuation.resume(returning: $0)
            }, failure: {
                continuation.resume(throwing: TunnelError.message($0))
            })
            do { try plugin.execute(invoke) }
            catch { continuation.resume(throwing: error) }
        }
    }

    @MainActor
    static func begin(
        _ plugin: VpnPlugin, _ session: NETunnelProviderSession, expected: Int,
        action: String = "poll", payload: [String: Any] = [:]
    ) async -> Task<[String: Any], Error> {
        var task: Task<[String: Any], Error>!
        await withCheckedContinuation { continuation in
            session.onSend = {
                require(session.sent == expected, "The provider received an unexpected request.")
                session.onSend = nil
                continuation.resume()
            }
            task = Task { @MainActor in try await call(plugin, action, payload) }
        }
        return task
    }

    @MainActor
    static func run() async throws {
        let plugin = VpnPlugin()
        let session = NETunnelProviderManager.current.connection as! NETunnelProviderSession
        let timedOut = await begin(plugin, session, expected: 1)
        let timeout = try await timedOut.value
        require((timeout["snapshot"] as? [String: Any])?["error"] != nil, "The missing provider reply did not time out.")
        for _ in 0..<4 {
            let result = try await call(plugin, "poll")
            require((result["status"] as? [String: Any])?["state"] as? String == "connected", "A timeout hid the system connection state.")
        }
        require(session.sent == 1, "Repeated polls bypassed provider admission after a timeout.")

        session.transition(.reasserting, date: nil)
        _ = try await call(plugin, "poll")
        session.transition(.connected, date: Date(timeIntervalSince1970: 1100))
        _ = try await call(plugin, "poll")
        require(session.sent == 1, "Reassertion reopened admission before the pending provider request finished.")
        try session.respond(1, ["node": ["name": "timed-out reply"]])

        let old = await begin(plugin, session, expected: 2)
        session.transition(.disconnected, date: nil)
        session.transition(.connected, date: Date(timeIntervalSince1970: 1200))
        let current = await begin(plugin, session, expected: 3)
        try session.respond(2, ["node": ["name": "old connection"]])
        let stale = try await old.value
        require((stale["snapshot"] as? [String: Any])?["error"] != nil, "A previous connection supplied the current snapshot.")
        _ = try await call(plugin, "poll")
        require(session.sent == 3, "An old reply released admission for the replacement request.")
        try session.respond(3, ["node": ["name": "current connection"]])
        let fresh = try await current.value
        require(((fresh["snapshot"] as? [String: Any])?["node"] as? [String: Any])?["name"] as? String == "current connection",
                "The current connection snapshot was rejected.")

        let logs = await begin(plugin, session, expected: 4, action: "request", payload: ["path": "rpc/ReadLogs"])
        session.transition(.disconnected, date: nil)
        session.transition(.connected, date: Date(timeIntervalSince1970: 1300))
        try session.respond(4, ["logs": [["message": "old connection"]]])
        let staleLogs = try await logs.value
        require(staleLogs["error"] != nil && staleLogs["logs"] == nil, "Previous-connection logs reached the app.")
        require(ProfileStore.reads == 1, "Steady polling repeatedly read the Keychain fixture.")

        session.transition(.disconnected, date: nil)
        let saved = try await call(plugin, "saveProfile", ["name": "Replacement network", "config": "fixture"])
        require(((saved["profile"] as? [String: Any])?["name"] as? String) == "Replacement network",
                "Saving the profile did not update cached metadata.")
        let connecting = try await call(plugin, "connect")
        let manager = NETunnelProviderManager.current
        require(session.starts == 1 && manager.saves == 1 && manager.loads == 1,
                "Connecting did not save, reload, and start the selected VPN manager.")
        require(connecting["state"] as? String == "connecting", "The start result did not use the system connection state.")
        require((manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profileID"] as? String == "fixture-profile",
                "The VPN preferences did not select the saved profile.")
        session.transition(.disconnected, date: nil)
        let deleted = try await call(plugin, "deleteProfile")
        require(deleted["profile"] == nil, "Deleting the profile left cached metadata.")
        require(ProfileStore.reads == 1, "Profile mutations unnecessarily reloaded the cached profile.")
        print("PASS: provider deadline, bounded admission, reassertion, connection generations, late replies, and profile metadata.")
    }

    static func main() async {
        do { try await run() }
        catch {
            fputs("FAIL: \(error)\n", stderr)
            exit(1)
        }
    }
}
