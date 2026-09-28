import Foundation
#if canImport(Security)
@preconcurrency import Security
#endif

/// A long-lived P-256 keypair, generated once per device and used only to
/// sign a server challenge on enrollment/assertion — never to encrypt or
/// carry data of its own.
///
/// This exists for exactly one problem App Attest can't solve on its own:
/// a reinstalled app has a brand-new Secure Enclave key (the old one was
/// deleted with the app) AND no cached principal credential worth presenting
/// (they expire in hours, App Attest keys don't survive reinstall regardless).
/// With nothing connecting the two enrollments, the server has no choice but
/// to treat "reinstalled" the same as "a new device" — see
/// packages/aegis-core/src/principal-credential.ts's `joinKey` doc for the
/// server side of this.
///
/// A Keychain item, unlike an App Attest key, is NOT deleted when the app is
/// uninstalled — only a full device erase, an explicit Keychain wipe, or
/// restoring from a backup that excludes it removes it. Persisting this
/// keypair there (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, same
/// class CredentialStore already uses) is what lets a reinstalled app prove
/// "I'm the same device that enrolled before" — its public half plus a
/// signature over each request's challenge, verified server-side with the
/// exact same primitive (verifyP256) already used for Android's Keystore
/// key. The private key never leaves this type.
///
/// Honest limits: a full device erase/restore-as-new, or an app that clears
/// its own Keychain items on every launch, defeats this exactly as it
/// defeats every other Keychain-based continuity trick. It is a real
/// mitigation, not an unbreakable one.
public protocol DeviceJoinKeyProvider: Sendable {
    /// DER SubjectPublicKeyInfo of the public key. Safe to send on every
    /// request — it identifies the device, it doesn't authenticate anything
    /// by itself.
    var publicKeySPKI: Data { get }
    /// ECDSA-SHA256 signature (DER, X9.62/ANSI encoding) over `challenge`.
    func sign(challenge: Data) throws -> Data
}

/// The fixed ASN.1 prefix for a P-256 SubjectPublicKeyInfo wrapping an
/// uncompressed EC point — identical for every P-256 key; only the 65-byte
/// point (0x04 || X || Y) that follows differs. Both Security.framework's
/// SecKeyCopyExternalRepresentation and CryptoKit's x963Representation
/// return exactly that 65-byte point for a P-256 key, so this same prefix
/// wraps either.
private let p256SPKIHeader = Data([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
])

func p256SPKI(fromUncompressedPoint point: Data) -> Data {
    p256SPKIHeader + point
}

#if canImport(Security)
/// Production implementation: a Keychain-persisted P-256 keypair.
public struct KeychainDeviceJoinKey: DeviceJoinKeyProvider {
    public let publicKeySPKI: Data
    private let privateKeyRef: SecKey

    /// Loads the existing join key for `tag`, or generates and persists a
    /// new one if none exists yet (first launch, or first launch after a
    /// reinstall that lost everything — see the type doc for what that
    /// means for continuity).
    public init(tag: String = "dev.aegis.kit.joinkey") throws {
        let tagData = Data(tag.utf8)
        let key = try Self.loadPrivateKey(tag: tagData) ?? Self.createAndStorePrivateKey(tag: tagData)
        self.privateKeyRef = key
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw AegisError.crypto("device join key: couldn't derive public key")
        }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw AegisError.crypto("device join key: couldn't export public key (\(String(describing: error)))")
        }
        self.publicKeySPKI = p256SPKI(fromUncompressedPoint: point)
    }

    public func sign(challenge: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKeyRef, .ecdsaSignatureMessageX962SHA256, challenge as CFData, &error) as Data? else {
            throw AegisError.crypto("device join key: sign failed (\(String(describing: error)))")
        }
        return signature
    }

    private static func loadPrivateKey(tag: Data) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            // swiftlint:disable:next force_cast
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw AegisError.crypto("device join key: keychain query failed (\(status))")
        }
    }

    private static func createAndStorePrivateKey(tag: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw AegisError.crypto("device join key: generation failed (\(String(describing: error)))")
        }
        return key
    }
}
#endif
