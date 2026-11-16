import Foundation
import Security

enum TunnelError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

struct TunnelProfile: Codable {
    let id: String
    let name: String
    var config: String
}

enum ProfileStore {
    static let service = "com.lowertier.app.vpn"
    static let account = "active-profile"

    static func query() throws -> [String: Any] {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "LowTierKeychainGroup") as? String,
              !group.contains("$("), !group.isEmpty else {
            throw TunnelError.message("Configure the shared Keychain group before using the VPN.")
        }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group
        ]
    }

    static func load() throws -> TunnelProfile? {
        var request = try query()
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw TunnelError.message("The VPN profile is unavailable in the Keychain (\(status)).")
        }
        return try JSONDecoder().decode(TunnelProfile.self, from: data)
    }

    static func save(_ profile: TunnelProfile) throws {
        let request = try query()
        let attributes: [String: Any] = [
            kSecValueData as String: try JSONEncoder().encode(profile),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(request as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(request.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw TunnelError.message("The VPN profile could not be saved (\(status)).")
        }
    }

    static func delete() throws {
        let status = SecItemDelete(try query() as CFDictionary)
        guard status == errSecItemNotFound || status == errSecSuccess else {
            throw TunnelError.message("The VPN profile could not be removed (\(status)).")
        }
    }

    static var diagnostics: UserDefaults? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "LowTierAppGroup") as? String else { return nil }
        return UserDefaults(suiteName: group)
    }
}
