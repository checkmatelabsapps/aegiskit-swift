import XCTest
@testable import AegisKit

/// The table must match the canonical JSON the web SDK, the Expo module and
/// the Android SDK are tested against, so a refusal reads the same everywhere.
final class RefusalExplanationTests: XCTestCase {
    private struct Canonical: Decodable {
        struct Entry: Decodable, Equatable {
            let kind: String
            let title: String
            let message: String
            let retryable: Bool
        }
        let priority: [String]
        let explanations: [String: Entry]
        let fallback: Entry
        let outage: Entry
        let attestationUnsupported: Entry
    }

    private func canonical() throws -> Canonical {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "refusal-explanations", withExtension: "json"))
        return try JSONDecoder().decode(Canonical.self, from: Data(contentsOf: url))
    }

    private func entry(_ e: RefusalExplanation.Entry) -> Canonical.Entry {
        Canonical.Entry(kind: e.kind.rawValue, title: e.title, message: e.message, retryable: e.retryable)
    }

    func testTableMatchesTheCanonicalJSON() throws {
        let c = try canonical()
        XCTAssertEqual(RefusalExplanation.priority, c.priority)
        XCTAssertEqual(RefusalExplanation.table.mapValues(entry), c.explanations)
        XCTAssertEqual(entry(RefusalExplanation.fallback), c.fallback)
        XCTAssertEqual(entry(RefusalExplanation.outage), c.outage)
        XCTAssertEqual(entry(RefusalExplanation.attestationUnsupported), c.attestationUnsupported)
    }

    func testTheReasonTheUserCanDoLeastAboutSpeaksFirst() {
        let e = RefusalExplanation.explain(reasons: ["heat.high", "cap.exhausted"])
        XCTAssertEqual(e.kind, .limit)
        XCTAssertFalse(e.retryable)
        XCTAssertEqual(e.reasons, ["heat.high", "cap.exhausted"])
    }

    func testASupportReferenceInTheMessageReachesTheExplanation() {
        let e = AegisError.refused(status: 409, reasons: ["cap.exhausted"], message: "Reference: K7Q2M-9XF4B")
        XCTAssertEqual(e.explanation.reference, "K7Q2M-9XF4B")
        XCTAssertNil(AegisError.refused(status: 409, reasons: ["cap.exhausted"], message: "issuance_denied").explanation.reference)
    }

    func testUnknownCodesNeverStrandTheUser() {
        XCTAssertEqual(RefusalExplanation.explain(reasons: ["some.future.code"]).kind, .retry)
        XCTAssertTrue(RefusalExplanation.explain(reasons: []).retryable)
    }

    func testEveryAegisErrorHasAnExplanation() {
        XCTAssertEqual(AegisError.refused(status: 409, reasons: ["cap.exhausted"], message: nil).explanation.kind, .limit)
        let busy = AegisError.busy(retryAfterSeconds: 5).explanation
        XCTAssertEqual(busy.kind, .retry)
        XCTAssertEqual(busy.retryAfterSeconds, 5)
        XCTAssertEqual(AegisError.attestationUnsupported.explanation.kind, .verification)
        let outage = AegisError.refused(status: 503, reasons: ["scope.denied"], message: nil).explanation
        XCTAssertEqual(outage.kind, .retry)
        XCTAssertTrue(outage.retryable)
        XCTAssertFalse(AegisError.attestationUnsupported.explanation.retryable)
        XCTAssertTrue(AegisError.invalidResponse("x").explanation.retryable)
        XCTAssertNil(AegisError.refused(status: 409, reasons: ["cap.exhausted"], message: nil).explanation.retryAfterSeconds)
    }
}
