import Foundation

public enum AegisError: Error, Equatable, CustomStringConvertible {
    /// The server refused, with Aegis's stable reason codes (e.g. "cap.exhausted", "ticket.replay").
    case refused(status: Int, reasons: [String], message: String?)
    /// Retry after a short wait: the server shed load ("heat.high") or rate-limited ceremonies.
    case busy(retryAfterSeconds: Int)
    case attestationUnsupported
    case proofVerificationFailed
    case invalidResponse(String)
    case crypto(String)

    public var description: String {
        switch self {
        case let .refused(status, reasons, message): return "Aegis refused (\(status)): \(reasons.joined(separator: ", "))\(message.map { " — \($0)" } ?? "")"
        case let .busy(s): return "Aegis is busy; retry in \(s)s"
        case .attestationUnsupported: return "App Attest isn't supported on this device (e.g. the Simulator)"
        case .proofVerificationFailed: return "The issuer's proof didn't verify — refusing the ticket"
        case let .invalidResponse(why): return "Invalid response: \(why)"
        case let .crypto(why): return "Crypto error: \(why)"
        }
    }

    /// True when the same request may succeed if retried later today.
    public var isRetryable: Bool {
        if case .busy = self { return true }
        return false
    }

    /// True when the per-principal daily cap is spent (for the route or for issuance).
    public var isCapExhausted: Bool {
        if case let .refused(_, reasons, _) = self { return reasons.contains("cap.exhausted") }
        return false
    }
}
