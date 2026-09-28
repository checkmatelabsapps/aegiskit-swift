import XCTest
@testable import AegisKit

/// A device that can't be verified, as the Simulator is.
private struct NoAttestation: AppAttestProvider {
    var isSupported: Bool { false }
    func generateKey() async throws -> String { throw AegisError.attestationUnsupported }
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { throw AegisError.attestationUnsupported }
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data { throw AegisError.attestationUnsupported }
}

/// The app's own server, answering what each test sets.
private final class AppServer: URLProtocol {
    nonisolated(unsafe) static var answer: (status: Int, headers: [String: String], body: String) = (200, [:], "{}")
    nonisolated(unsafe) static var seen: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.seen.append(request)
        let a = Self.answer
        let response = HTTPURLResponse(url: request.url!, statusCode: a.status, httpVersion: "HTTP/1.1", headerFields: a.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(a.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

/// `send(ifNoPass: .send)`: an app keeps working where no pass can be had.
final class SendWithoutPassTests: XCTestCase {
    private func client() -> AegisClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [AppServer.self]
        return AegisClient(baseURL: URL(string: "https://pwnbot.invalid")!, attestation: NoAttestation(), store: InMemoryCredentialStore(), appSession: URLSession(configuration: config))
    }

    private var write: URLRequest {
        var r = URLRequest(url: URL(string: "https://api.example/api/signup")!)
        r.httpMethod = "POST"
        r.setValue("forged", forHTTPHeaderField: AegisClient.leaseHeader)
        return r
    }

    override func setUp() {
        AppServer.seen = []
        AppServer.answer = (200, [:], "{\"id\":1}")
    }

    func testTheDefaultStillThrowsWithoutSending() async {
        do {
            _ = try await client().send(write, route: "POST /api/signup")
            XCTFail("should have thrown")
        } catch {
            XCTAssertEqual(error as? AegisError, .attestationUnsupported)
        }
        XCTAssertTrue(AppServer.seen.isEmpty)
    }

    func testWithNoPassTheRequestIsSentSayingWhyAndACanaryServerAnswersAsUsual() async throws {
        let (_, response) = try await client().send(write, route: "POST /api/signup", ifNoPass: .send)
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(AppServer.seen.count, 1)
        XCTAssertEqual(AppServer.seen[0].value(forHTTPHeaderField: AegisClient.noPassHeader), "unsupported")
        XCTAssertNil(AppServer.seen[0].value(forHTTPHeaderField: AegisClient.leaseHeader))
    }

    func testAnEnforcingServersRefusalIsThrownAsWhyThereWasNoPass() async {
        AppServer.answer = (403, [AegisClient.refusedHeader: "1"], "{\"reasons\":[\"ticket.missing\"]}")
        do {
            _ = try await client().send(write, route: "POST /api/signup", ifNoPass: .send)
            XCTFail("should have thrown")
        } catch {
            XCTAssertEqual(error as? AegisError, .attestationUnsupported)
        }
    }

    func testTheAppsOwn403IsReturned() async throws {
        AppServer.answer = (403, [:], "{\"error\":\"email already registered\"}")
        let (_, response) = try await client().send(write, route: "POST /api/signup", ifNoPass: .send)
        XCTAssertEqual(response.statusCode, 403)
    }

    func testTheReasonSentIsOneTheServerKnows() {
        XCTAssertEqual(AegisClient.noPassReason(AegisError.refused(status: 409, reasons: ["cap.exhausted"], message: nil)), "limit")
        XCTAssertEqual(AegisClient.noPassReason(AegisError.refused(status: 403, reasons: ["pop.required"], message: nil)), "refused")
        XCTAssertEqual(AegisClient.noPassReason(AegisError.busy(retryAfterSeconds: 3)), "busy")
        XCTAssertEqual(AegisClient.noPassReason(URLError(.notConnectedToInternet)), "unreachable")
    }
}
