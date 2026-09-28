import Foundation
import CryptoKit

/// A pure-Swift stand-in for KeychainDeviceJoinKey, generated fresh (never
/// persisted) — same public shape, same signature format, so tests exercise
/// the real signing/encoding path without touching the OS keychain, which
/// behaves inconsistently across CI, Simulator, and sandboxed test runs.
///
/// Production code should use KeychainDeviceJoinKey; this type provides no
/// continuity across app restarts and exists for tests only.
public struct InMemoryDeviceJoinKey: DeviceJoinKeyProvider {
    private let privateKey: P256.Signing.PrivateKey
    public let publicKeySPKI: Data

    public init() {
        self.privateKey = P256.Signing.PrivateKey()
        // x963Representation is the same 65-byte uncompressed point
        // (0x04 || X || Y) Security.framework exports for a P-256 key.
        self.publicKeySPKI = p256SPKI(fromUncompressedPoint: privateKey.publicKey.x963Representation)
    }

    public func sign(challenge: Data) throws -> Data {
        try privateKey.signature(for: challenge).derRepresentation
    }
}
