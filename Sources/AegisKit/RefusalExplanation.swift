// GENERATED from packages/aegis-sdk/src/explain.ts by scripts/gen-refusal-explanations.mjs. Do not edit.
import Foundation

/// What to tell a person whose request Aegis refused.
///
/// Every refusal carries stable reason codes ("cap.exhausted", "heat.high",
/// ...). Those are for code and support staff; an end user needs a sentence
/// and to know whether trying again helps. The same table ships in the web
/// SDK, the Expo module and the Android SDK; all of them are tested against
/// Tests/AegisKitTests/Resources/refusal-explanations.json.
public struct RefusalExplanation: Equatable, Sendable {
    public enum Kind: String, Sendable {
        /// A limit for this action is used up.
        case limit
        /// Nothing is wrong with the user; the same action may work shortly.
        case retry
        /// The device or account couldn't be verified.
        case verification
        /// The site doesn't allow this action for anyone right now.
        case unavailable
        /// Held for a person to look at.
        case review
    }

    public let kind: Kind
    /// A few words, e.g. for an alert title.
    public let title: String
    /// One or two sentences for the end user.
    public let message: String
    /// Whether trying the same thing again (after `retryAfterSeconds`, if set) can succeed without the user changing anything.
    public let retryable: Bool
    public let retryAfterSeconds: Int?
    /// The raw reason codes, for logs and support tickets.
    public let reasons: [String]
    /// A support reference to show under the message when the server gave one:
    /// support can undo a wrong refusal with it (POST /api/admin/appeals).
    public let reference: String?

    struct Entry {
        let kind: Kind
        let title: String
        let message: String
        let retryable: Bool
    }

    static let table: [String: Entry] = [
        "cap.exhausted": Entry(kind: .limit, title: "Limit reached", message: "You've reached the limit for this on this device.", retryable: false),
        "device.reused": Entry(kind: .limit, title: "This phone can't set up a new account", message: "This phone has already been used to set up this app, by you or a previous owner, so it can't start a new account here right now.", retryable: false),
        "heat.high": Entry(kind: .retry, title: "Busy right now", message: "We're getting a lot of requests right now. Please try again in a moment.", retryable: true),
        "epoch.stale": Entry(kind: .retry, title: "Please try again", message: "Your security check expired before it was used. Trying again will get a fresh one.", retryable: true),
        "ticket.replay": Entry(kind: .retry, title: "Please try again", message: "That security check was already used. Trying again will get a fresh one.", retryable: true),
        "ticket.missing": Entry(kind: .retry, title: "Please try again", message: "The security check didn't come through with your request. Please try again.", retryable: true),
        "sig.invalid": Entry(kind: .retry, title: "Please try again", message: "Your security check couldn't be read. Please try again.", retryable: true),
        "pop.required": Entry(kind: .verification, title: "Verification needed", message: "This needs a verified device: the app on a supported phone, or a passkey on this browser.", retryable: false),
        "pop.failed": Entry(kind: .verification, title: "Couldn't verify this request", message: "This device or request couldn't be verified. If you're using the app, make sure it's up to date.", retryable: false),
        "presence.injected": Entry(kind: .verification, title: "Couldn't confirm this was you", message: "This action has to come from you directly, not from an automation tool.", retryable: false),
        "sig.unknown_agent": Entry(kind: .unavailable, title: "Not available to automated clients", message: "Automated clients can't do this here.", retryable: false),
        "directory.mismatch": Entry(kind: .unavailable, title: "Not available to automated clients", message: "Automated clients can't do this here.", retryable: false),
        "scope.denied": Entry(kind: .unavailable, title: "Not available", message: "This isn't available right now.", retryable: false),
        "hitl.required": Entry(kind: .review, title: "Needs a person to review", message: "This needs to be reviewed by a person before it can go through.", retryable: false),
        "quarantine": Entry(kind: .review, title: "Held for review", message: "Your request was received and is being held for review.", retryable: false),
    ]

    /// Which reason explains a refusal when several are present: the one the
    /// user can do least about goes first.
    static let priority: [String] = ["quarantine","hitl.required","device.reused","cap.exhausted","presence.injected","pop.required","pop.failed","sig.unknown_agent","directory.mismatch","scope.denied","heat.high","epoch.stale","ticket.replay","ticket.missing","sig.invalid"]

    static let fallback = Entry(kind: .retry, title: "Something went wrong", message: "Something went wrong checking your request. Please try again.", retryable: true)
    /// Any 5xx: the deployment itself was down, so never "not available".
    static let outage = Entry(kind: .retry, title: "Temporarily unavailable", message: "We couldn't check your request just now. Please try again in a moment.", retryable: true)
    static let attestationUnsupported = Entry(kind: .verification, title: "This device can't be verified", message: "This device doesn't support the security check this app uses (for example a simulator or a modified device).", retryable: false)

    init(_ entry: Entry, reasons: [String], retryAfterSeconds: Int? = nil, reference: String? = nil) {
        kind = entry.kind
        title = entry.title
        message = entry.message
        retryable = entry.retryable
        self.retryAfterSeconds = entry.retryable ? retryAfterSeconds : nil
        self.reasons = reasons
        self.reference = reference
    }

    /// The support reference inside a refusal message ("... Reference: K7Q2M-9XF4B").
    static func reference(in text: String?) -> String? {
        guard let text, let range = text.range(of: #"Reference: [0-9A-Z]{5}(-[0-9A-Z]{5}){1,3}"#, options: .regularExpression) else { return nil }
        return String(text[range].dropFirst("Reference: ".count))
    }

    /// The explanation for a refusal's reason codes. Unknown or missing codes
    /// get a generic "try again", never a blocking message; a 5xx status is an
    /// outage whatever the reasons say.
    public static func explain(reasons: [String], status: Int? = nil, retryAfterSeconds: Int? = nil, reference: String? = nil) -> RefusalExplanation {
        if let status, status >= 500 { return RefusalExplanation(outage, reasons: reasons, retryAfterSeconds: retryAfterSeconds, reference: reference) }
        let lead = priority.first { reasons.contains($0) }
        let entry = lead.flatMap { table[$0] } ?? fallback
        return RefusalExplanation(entry, reasons: reasons, retryAfterSeconds: retryAfterSeconds, reference: reference)
    }
}

extension AegisError {
    /// What to show the user for this error (see RefusalExplanation).
    public var explanation: RefusalExplanation {
        switch self {
        case let .refused(status, reasons, message):
            return RefusalExplanation.explain(reasons: reasons, status: status, reference: RefusalExplanation.reference(in: message))
        case let .busy(seconds):
            return RefusalExplanation.explain(reasons: ["heat.high"], retryAfterSeconds: seconds)
        case .attestationUnsupported:
            return RefusalExplanation(RefusalExplanation.attestationUnsupported, reasons: [])
        case .proofVerificationFailed, .invalidResponse, .crypto:
            return RefusalExplanation(RefusalExplanation.fallback, reasons: [])
        }
    }
}
