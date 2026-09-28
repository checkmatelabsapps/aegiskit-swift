import Foundation
#if canImport(Security)
import Security
#endif

/// Where AegisKit keeps the App Attest key id and the current principal
/// credential. Keychain by default: both survive app restarts, and neither
/// is backed up to other devices (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
/// — an App Attest key only works on the device that generated it.
public protocol CredentialStore: Sendable {
    func get(_ key: String) -> String?
    func set(_ key: String, _ value: String?)
}

public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private var values: [String: String] = [:]
    private let lock = NSLock()
    public init() {}
    public func get(_ key: String) -> String? { lock.withLock { values[key] } }
    public func set(_ key: String, _ value: String?) { lock.withLock { values[key] = value } }
}

#if canImport(Security)
public struct KeychainCredentialStore: CredentialStore {
    let service: String
    public init(service: String = "dev.aegis.kit") { self.service = service }

    private func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
    }

    public func get(_ key: String) -> String? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func set(_ key: String, _ value: String?) {
        SecItemDelete(query(key) as CFDictionary)
        guard let value else { return }
        var q = query(key)
        q[kSecValueData as String] = Data(value.utf8)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }
}
#endif
