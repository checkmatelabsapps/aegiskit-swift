import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// The three App Attest calls AegisKit needs. `DCAppAttestProvider` is the
/// real one; tests (and the Simulator, where App Attest is unavailable)
/// substitute their own.
public protocol AppAttestProvider: Sendable {
    var isSupported: Bool { get }
    /// Returns the key id as DeviceCheck does: standard base64 of 32 bytes.
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// The device no longer has the App Attest key a stored key id names. This
/// happens after a delete-and-reinstall or a restore to a new device: the key
/// id lives in the Keychain, which survives both, but the Secure Enclave key
/// does not. `AegisClient` handles it by enrolling a fresh key (and the device
/// join key, if present, resolves that to the same principal). A provider
/// throws this from `generateAssertion` for a key it no longer has.
public struct AppAttestKeyInvalid: Error, Equatable {
    public init() {}
}

#if canImport(DeviceCheck)
@available(iOS 14.0, macOS 11.0, *)
public struct DCAppAttestProvider: AppAttestProvider {
    public init() {}
    public var isSupported: Bool { DCAppAttestService.shared.isSupported }
    public func generateKey() async throws -> String {
        try await Self.mapped { try await DCAppAttestService.shared.generateKey() }
    }
    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await Self.mapped { try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) }
    }
    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await Self.mapped(assertion: true) { try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) }
    }

    private static func mapped<T>(assertion: Bool = false, _ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch {
            throw mapError(error, assertion: assertion)
        }
    }

    /// DeviceCheck's errors, as the rest of AegisKit understands them:
    /// `invalidKey` means the key is gone (see AppAttestKeyInvalid), and
    /// `serverUnavailable` is Apple asking for a retry later, so it surfaces
    /// as `.busy` (ERR_AEGIS_BUSY in JS, retried once by default). Anything
    /// else propagates unchanged.
    ///
    /// On an assertion, `invalidInput` also means the key is gone: after the
    /// app is deleted and reinstalled the key id survives in the Keychain but
    /// the Secure Enclave key doesn't, and a real iPhone (iOS 26.6.2, Fade,
    /// 2026-09-25) answered that with code 2 (invalidInput), not 3
    /// (invalidKey), leaving the device unable to get a pass. The only inputs
    /// are that key id and a 32-byte SHA-256, so nothing else can be invalid.
    static func mapError(_ error: Error, assertion: Bool) -> Error {
        guard let dc = error as? DCError else { return error }
        switch dc.code {
        case .invalidKey: return AppAttestKeyInvalid()
        case .invalidInput where assertion: return AppAttestKeyInvalid()
        case .serverUnavailable: return AegisError.busy(retryAfterSeconds: 5)
        default: return error
        }
    }
}
#endif
