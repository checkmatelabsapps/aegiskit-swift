import XCTest
import CryptoKit
@testable import AegisKit

/// End to end against a running Aegis server — the real HTTP protocol, the
/// real VOPRF issuer, the real App Attest verifier — with a synthetic device
/// standing in for DCAppAttestService (unavailable on Mac and Simulator).
///
///   npx tsx scripts/device-attest-e2e.mjs --setup > .aegis-attest-env
///   (set -a; . ./.aegis-attest-env; set +a; AEGIS_ENFORCE=true npm run start -w apps/origin)
///   npx tsx scripts/synthetic-device-server.mjs
///   AEGIS_LIVE_BASE_URL=http://127.0.0.1:3001 AEGIS_SYNTHETIC_DEVICE_URL=http://127.0.0.1:3999 swift test
final class LiveServerTests: XCTestCase {
    struct SyntheticDevice: AppAttestProvider {
        let url: URL
        var isSupported: Bool { true }
        func call(_ path: String, _ body: [String: String]) async throws -> [String: String] {
            var req = URLRequest(url: url.appendingPathComponent(path))
            req.httpMethod = "POST"
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            let (data, _) = try await URLSession.shared.data(for: req)
            return try JSONSerialization.jsonObject(with: data) as? [String: String] ?? [:]
        }
        func generateKey() async throws -> String { try await call("apple/generateKey", [:])["keyId"]! }
        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            Data(base64Encoded: try await call("apple/attestKey", ["keyId": keyId, "clientDataHash": clientDataHash.base64EncodedString()])["attestation"]!)!
        }
        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            Data(base64Encoded: try await call("apple/assert", ["keyId": keyId, "clientDataHash": clientDataHash.base64EncodedString()])["assertion"]!)!
        }
    }

    func live() throws -> (URL, SyntheticDevice) {
        let env = ProcessInfo.processInfo.environment
        guard let base = env["AEGIS_LIVE_BASE_URL"].flatMap(URL.init(string:)), let device = env["AEGIS_SYNTHETIC_DEVICE_URL"].flatMap(URL.init(string:)) else {
            throw XCTSkip("set AEGIS_LIVE_BASE_URL and AEGIS_SYNTHETIC_DEVICE_URL to run against a live server")
        }
        return (base, SyntheticDevice(url: device))
    }

    func testDelegatesToTheUsersOwnAgentAndRevokes() async throws {
        let (base, device) = try live()
        let aegis = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore())
        let d = try await aegis.delegate(routes: ["POST /v1/keys"], perDay: 2, ttlSeconds: 3600)
        XCTAssertGreaterThan(d.expiresAt, Date())
        func allowanceAsAgent() async throws -> (Int, [String: Any]) {
            var req = URLRequest(url: base.appendingPathComponent("api/aegis/allowance"))
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = try JSONSerialization.data(withJSONObject: ["principal": d.delegation])
            let (data, response) = try await URLSession.shared.data(for: req)
            return ((response as! HTTPURLResponse).statusCode, (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:])
        }
        let (status, view) = try await allowanceAsAgent()
        XCTAssertEqual(status, 200)
        XCTAssertEqual((view["delegation"] as? [String: Any])?["perDay"] as? Int, 2)
        XCTAssertEqual((view["routes"] as? [[String: Any]])?.count, 1)
        try await aegis.revokeDelegation(id: d.id)
        let (after, _) = try await allowanceAsAgent()
        XCTAssertEqual(after, 401)
    }

    func testEnrollMintSpendWriteThenCapAndReturningSession() async throws {
        let (base, device) = try live()
        let store = InMemoryCredentialStore()
        let aegis = AegisClient(baseURL: base, attestation: device, store: store)

        // First run: App Attest enrollment → principal with app_attest evidence.
        let p1 = try await aegis.principal()
        XCTAssertEqual(p1.evidence, ["app_attest"])
        let fresh = try await aegis.allowance()
        XCTAssertEqual(fresh.routes.first { $0.route == "POST /v1/keys" }?.remaining, 3)
        XCTAssertGreaterThan(fresh.resetsAt, Date())

        // Three API keys (the demo route's 3/day cap), each a separately minted unlinkable ticket.
        var request = URLRequest(url: base.appendingPathComponent("v1/keys"))
        request.httpMethod = "POST"
        for _ in 0..<3 {
            let (data, response) = try await aegis.send(request, route: "POST /v1/keys")
            XCTAssertEqual(response.statusCode, 200, String(decoding: data, as: UTF8.self))
        }
        // The fourth is refused: today's share for this device is spent.
        let credentialBeforeRefusal = store.get("aegis.principal")
        do {
            _ = try await aegis.send(request, route: "POST /v1/keys")
            XCTFail("expected cap.exhausted")
        } catch let error as AegisError {
            XCTAssertTrue(error.isCapExhausted, "\(error)")
            // A limit is an answer, not a revoked credential: keep it (only
            // epoch.stale makes the client prove the device again).
            XCTAssertEqual(store.get("aegis.principal"), credentialBeforeRefusal)
            // The refusal carries a support reference, and says what to tell the user.
            XCTAssertNotNil(error.explanation.reference, "\(error)")
            XCTAssertEqual(error.explanation.kind, .limit)
        }
        let spent = try await aegis.allowance()
        XCTAssertEqual(spent.routes.first { $0.route == "POST /v1/keys" }.map { [$0.used, $0.remaining] }, [3, 0])

        // A later session (credential expired/cleared, key kept): an assertion returns the SAME principal.
        store.set("aegis.principal", nil)
        let p2 = try await aegis.principal()
        XCTAssertEqual(p2.principalSite, p1.principalSite)

        // A lease is single-use.
        let lease = try await aegis.authorize(route: "POST /waitlist")
        var waitlist = URLRequest(url: base.appendingPathComponent("waitlist"))
        waitlist.httpMethod = "POST"
        waitlist.httpBody = Data(#"{"email":"ios@example.com"}"#.utf8)
        waitlist.setValue("application/json", forHTTPHeaderField: "content-type")
        waitlist.setValue(lease.headerValue, forHTTPHeaderField: AegisClient.leaseHeader)
        let (_, first) = try await URLSession.shared.data(for: waitlist)
        let (_, second) = try await URLSession.shared.data(for: waitlist)
        XCTAssertEqual(first.statusCode(), 200)
        XCTAssertEqual(second.statusCode(), 403)
    }

    /// The scenario this whole feature exists for: the app is deleted and
    /// reinstalled (new App Attest key, no cached credential — a fresh
    /// InMemoryCredentialStore stands in for that), but the join key
    /// survived (a real device would keep it in Keychain). The reinstalled
    /// "app" must resolve to the SAME principal as before, not a new one.
    /// A private route (specs/PRIVATE_ROUTES.md): tickets minted ahead with
    /// the credential, spent without it; the pass names no one, and the
    /// route's limit of 3 holds at mint.
    func testPrivateRouteMintsAheadAndSpendsWithTheTicketAlone() async throws {
        let (base, device) = try live()
        let aegis = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore())
        let minted = try await aegis.prefetchPrivate(route: "POST /v1/vote", count: 5)
        XCTAssertEqual(minted, 3)
        for _ in 0..<3 {
            let lease = try await aegis.authorizePrivate(route: "POST /v1/vote")
            let json = try JSONSerialization.jsonObject(with: Data(base64URL: lease.headerValue)!) as? [String: Any]
            XCTAssertNil(json?["principal_site"], "a private pass must name no one")
        }
        do {
            _ = try await aegis.authorizePrivate(route: "POST /v1/vote")
            XCTFail("a fourth vote today should be refused at mint")
        } catch let AegisError.refused(_, reasons, _) {
            XCTAssertTrue(reasons.contains("cap.exhausted"))
        }
    }

    /// Key transparency: a client pinned to the server's signing key accepts
    /// its tickets; one pinned to another key refuses them.
    func testKeyPinsAcceptTheSignedKeysAndRefuseAnUnpinnedSigner() async throws {
        let (base, device) = try live()
        let (data, _) = try await URLSession.shared.data(from: base.appendingPathComponent("api/aegis/voprf/keys"))
        let signed = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let pin = try XCTUnwrap(signed["publicKey"] as? String)
        let pinned = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore(), keyPins: [pin])
        let lease = try await pinned.authorizePrivate(route: "POST /v1/vote")
        XCTAssertFalse(lease.headerValue.isEmpty)
        let wrongPin = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64URL
        let wrong = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore(), keyPins: [wrongPin])
        do {
            _ = try await wrong.authorize(route: "POST /v1/keys")
            XCTFail("a statement signed by an unpinned key must be refused")
        } catch let AegisError.refused(_, reasons, _) {
            XCTAssertEqual(reasons, ["sig.invalid"])
        }
    }

    /// With `keySite`, the statement must also name this app's site.
    func testKeySiteRefusesAnotherSitesStatement() async throws {
        let (base, device) = try live()
        let (data, _) = try await URLSession.shared.data(from: base.appendingPathComponent("api/aegis/voprf/keys"))
        let signed = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let pin = try XCTUnwrap(signed["publicKey"] as? String)
        let statement = try XCTUnwrap(signed["statement"] as? String)
        let site = try XCTUnwrap((try JSONSerialization.jsonObject(with: Data(statement.utf8)) as? [String: Any])?["site"] as? String)
        let mine = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore(), keyPins: [pin], keySite: site)
        let lease = try await mine.authorize(route: "POST /v1/keys")
        XCTAssertFalse(lease.headerValue.isEmpty)
        let other = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore(), keyPins: [pin], keySite: site + "-other")
        do {
            _ = try await other.authorize(route: "POST /v1/keys")
            XCTFail("another site's statement must be refused")
        } catch let AegisError.refused(_, reasons, _) {
            XCTAssertEqual(reasons, ["sig.invalid"])
        }
    }

    func testReinstallWithSameJoinKeyKeepsTheSamePrincipal() async throws {
        let (base, device1) = try live()
        let joinKey = InMemoryDeviceJoinKey()

        let before = AegisClient(baseURL: base, attestation: device1, store: InMemoryCredentialStore(), joinKey: joinKey)
        let p1 = try await before.principal()
        XCTAssertEqual(p1.evidence, ["app_attest"])

        // Reinstall: brand-new App Attest device (the Secure Enclave key is
        // gone with the old app) and a brand-new, empty credential store —
        // everything about the old session is gone except the join key.
        let (_, device2) = try live()
        let after = AegisClient(baseURL: base, attestation: device2, store: InMemoryCredentialStore(), joinKey: joinKey)
        let p2 = try await after.principal()
        XCTAssertEqual(p2.principalSite, p1.principalSite, "reinstall with the same join key must resolve to the same principal")

        // And the cap carried over too: spend what's left of today's 3/day
        // share from the FIRST session, then confirm the SECOND ("reinstalled")
        // session sees the same exhausted cap, not a fresh one.
        var request = URLRequest(url: base.appendingPathComponent("v1/keys"))
        request.httpMethod = "POST"
        for _ in 0..<3 {
            _ = try await before.send(request, route: "POST /v1/keys")
        }
        do {
            _ = try await after.send(request, route: "POST /v1/keys")
            XCTFail("expected the reinstalled session to inherit the exhausted cap")
        } catch let error as AegisError {
            XCTAssertTrue(error.isCapExhausted, "\(error)")
        }
    }

    /// What a real reinstall actually looks like: the Keychain (credential
    /// store AND join key) survives, so the old key id is still there, but
    /// the Secure Enclave key it names is gone. DeviceCheck answers
    /// generateAssertion with invalidKey, which DCAppAttestProvider turns
    /// into AppAttestKeyInvalid. The client must enroll a new key and, via
    /// the join key, land on the same principal, not fail forever.
    func testReinstallKeepsKeychainButLosesTheKeyAndRecovers() async throws {
        let (base, device1) = try live()
        let store = InMemoryCredentialStore()
        let joinKey = InMemoryDeviceJoinKey()
        let p1 = try await AegisClient(baseURL: base, attestation: device1, store: store, joinKey: joinKey).principal()

        let (_, fresh) = try live()
        let reinstalled = ReinstalledDevice(fresh: fresh)
        store.set("aegis.principal", nil) // long since expired on a real reinstall
        let p2 = try await AegisClient(baseURL: base, attestation: reinstalled, store: store, joinKey: joinKey).principal()
        XCTAssertEqual(p2.principalSite, p1.principalSite)
        XCTAssertTrue(reinstalled.refusedAnOldKey, "the stale key id should have been tried and refused first")
    }

    /// The user deleted their account and the app server erased their
    /// principal (POST /api/aegis/forget), which revokes the credential the
    /// client still has cached, hours before it expires. The client must
    /// drop it and prove the device again, not get `epoch.stale` until the
    /// TTL runs out (seen on a real iPhone on Fade, 2026-09-25).
    /// Needs AEGIS_LIVE_ADMIN_TOKEN, the server's AEGIS_ADMIN_TOKEN.
    func testRecoversAfterItsPrincipalIsErased() async throws {
        let (base, device) = try live()
        guard let admin = ProcessInfo.processInfo.environment["AEGIS_LIVE_ADMIN_TOKEN"] else {
            throw XCTSkip("set AEGIS_LIVE_ADMIN_TOKEN to the server's AEGIS_ADMIN_TOKEN")
        }
        let store = InMemoryCredentialStore()
        let aegis = AegisClient(baseURL: base, attestation: device, store: store)
        let before = try await aegis.principal()
        _ = try await aegis.allowance()

        var req = URLRequest(url: base.appendingPathComponent("api/admin/forget"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.setValue("Bearer \(admin)", forHTTPHeaderField: "authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["principal_site": before.principalSite])
        let (data, response) = try await URLSession.shared.data(for: req)
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200, String(decoding: data, as: UTF8.self))

        // Same client, same cache: the credential still looks valid locally.
        XCTAssertGreaterThan(before.expiresAt.timeIntervalSinceNow, 60)
        _ = try await aegis.allowance()
        let lease = try await aegis.authorize(route: "POST /v1/keys")
        XCTAssertGreaterThan(lease.expiresAt, Date())
        XCTAssertNotEqual(store.get("aegis.principal"), before.token, "the revoked credential should have been replaced")
    }

    /// Counts new App Attest keys, which is what Apple's risk metric counts.
    final class CountingDevice: AppAttestProvider, @unchecked Sendable {
        let inner: SyntheticDevice
        private let lock = NSLock()
        private var generated = 0
        init(_ inner: SyntheticDevice) { self.inner = inner }
        var keysGenerated: Int { lock.withLock { generated } }
        var isSupported: Bool { true }
        func generateKey() async throws -> String {
            lock.withLock { generated += 1 }
            return try await inner.generateKey()
        }
        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { try await inner.attestKey(keyId, clientDataHash: clientDataHash) }
        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data { try await inner.generateAssertion(keyId, clientDataHash: clientDataHash) }
    }

    /// Two protected calls that both find their credential erased must
    /// recover with ONE new key between them, not one each: every extra key
    /// moves an honest device toward the risk-metric limit.
    func testConcurrentRecoveryAfterAnErasureEnrollsOneKey() async throws {
        let (base, synthetic) = try live()
        guard let admin = ProcessInfo.processInfo.environment["AEGIS_LIVE_ADMIN_TOKEN"] else {
            throw XCTSkip("set AEGIS_LIVE_ADMIN_TOKEN to the server's AEGIS_ADMIN_TOKEN")
        }
        let device = CountingDevice(synthetic)
        let aegis = AegisClient(baseURL: base, attestation: device, store: InMemoryCredentialStore())
        let before = try await aegis.principal()
        XCTAssertEqual(device.keysGenerated, 1)

        var req = URLRequest(url: base.appendingPathComponent("api/admin/forget"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.setValue("Bearer \(admin)", forHTTPHeaderField: "authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["principal_site": before.principalSite])
        _ = try await URLSession.shared.data(for: req)

        async let a = aegis.allowance()
        async let b = aegis.allowance()
        _ = try await (a, b)
        XCTAssertEqual(device.keysGenerated, 2, "one new key for both recoveries")
    }

    /// Apple's serverUnavailable on attestKey: the client must retry with the
    /// SAME key (a new key per retry inflates Apple's risk metric), and
    /// succeed once Apple is back.
    func testAttestServerUnavailableRetriesWithTheSameKey() async throws {
        let (base, fresh) = try live()
        let flaky = FlakyAttestDevice(fresh: fresh)
        let aegis = AegisClient(baseURL: base, attestation: flaky, store: InMemoryCredentialStore())
        do {
            _ = try await aegis.principal()
            XCTFail("expected busy on the first attempt")
        } catch let error as AegisError {
            XCTAssertTrue(error.isRetryable, "\(error)")
        }
        let p = try await aegis.principal()
        XCTAssertEqual(p.evidence, ["app_attest"])
        XCTAssertEqual(flaky.generated, 1, "the retry must reuse the pending key, not mint a new one")
    }

    final class FlakyAttestDevice: AppAttestProvider, @unchecked Sendable {
        let fresh: SyntheticDevice
        private let lock = NSLock()
        private(set) var generated = 0
        private var failedOnce = false
        init(fresh: SyntheticDevice) { self.fresh = fresh }
        var isSupported: Bool { true }
        func generateKey() async throws -> String {
            lock.withLock { generated += 1 }
            return try await fresh.generateKey()
        }
        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            let fail = lock.withLock { () -> Bool in defer { failedOnce = true }; return !failedOnce }
            if fail { throw AegisError.busy(retryAfterSeconds: 5) } // what DCAppAttestProvider maps serverUnavailable to
            return try await fresh.attestKey(keyId, clientDataHash: clientDataHash)
        }
        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            try await fresh.generateAssertion(keyId, clientDataHash: clientDataHash)
        }
    }

    /// A device after reinstall: keys it generated work, any other key id is invalidKey.
    final class ReinstalledDevice: AppAttestProvider, @unchecked Sendable {
        let fresh: SyntheticDevice
        private var mine = Set<String>()
        private(set) var refusedAnOldKey = false
        private let lock = NSLock()
        init(fresh: SyntheticDevice) { self.fresh = fresh }
        var isSupported: Bool { true }
        func generateKey() async throws -> String {
            let id = try await fresh.generateKey()
            lock.withLock { _ = mine.insert(id) }
            return id
        }
        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            try await fresh.attestKey(keyId, clientDataHash: clientDataHash)
        }
        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            let known = lock.withLock { mine.contains(keyId) }
            guard known else {
                lock.withLock { refusedAnOldKey = true }
                throw AppAttestKeyInvalid()
            }
            return try await fresh.generateAssertion(keyId, clientDataHash: clientDataHash)
        }
    }

    func testWithoutAJoinKeyReinstallGetsAFreshPrincipal() async throws {
        let (base, device1) = try live()
        let before = AegisClient(baseURL: base, attestation: device1, store: InMemoryCredentialStore()) // no joinKey
        let p1 = try await before.principal()

        let (_, device2) = try live()
        let after = AegisClient(baseURL: base, attestation: device2, store: InMemoryCredentialStore()) // no joinKey
        let p2 = try await after.principal()
        XCTAssertNotEqual(p2.principalSite, p1.principalSite, "without a join key, today's default behavior (fresh principal) is unchanged")
    }

    func testAnUnsupportedDeviceFailsClearly() async throws {
        let (base, _) = try live()
        struct Unsupported: AppAttestProvider {
            var isSupported: Bool { false }
            func generateKey() async throws -> String { "" }
            func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { Data() }
            func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data { Data() }
        }
        let aegis = AegisClient(baseURL: base, attestation: Unsupported(), store: InMemoryCredentialStore())
        do {
            _ = try await aegis.principal()
            XCTFail("expected attestationUnsupported")
        } catch {
            XCTAssertEqual(error as? AegisError, .attestationUnsupported)
        }
    }
}

extension URLResponse {
    func statusCode() -> Int { (self as? HTTPURLResponse)?.statusCode ?? -1 }
}
