import Foundation
import CryptoKit

/// A principal credential: the server-signed identity every Aegis cap counts.
public struct PrincipalCredential: Sendable, Equatable {
    /// Opaque token to send as `principal` (don't parse it for decisions — the server does).
    public let token: String
    /// Pairwise id for this site; stable for this device key.
    public let principalSite: String
    /// Evidence proven this session, e.g. ["app_attest"] or ["app_attest", "passkey"].
    public let evidence: [String]
    public let expiresAt: Date
}

public struct Ticket: Sendable, Equatable {
    public let serial: String
    public let proof: String
}

/// A user's grant to their own agent (`AegisClient.delegate`).
public struct Delegation: Sendable {
    /// Hand this to the agent; it spends the user's allowance, so treat it like a password.
    public let delegation: String
    /// Keep this to revoke it.
    public let id: String
    public let expiresAt: Date
}

/// What this user has left today on each capped route (AegisClient.allowance).
public struct Allowance: Sendable, Equatable {
    public struct Route: Sendable, Equatable {
        public let route: String
        public let limit: Int
        public let used: Int
        public let remaining: Int
        /// False when the route needs evidence this device hasn't presented.
        public let evidenceOk: Bool
        /// On a route with trust tiers: the next limit and the evidence kinds
        /// this user lacks for it ("Add a passkey to raise this to 10 a day").
        public let nextTier: NextTier?
        /// On a route whose limit counts over more than a day (capWindowDays):
        /// the window, and when this user's resets. Nil on a daily route.
        public var windowDays: Int? = nil
        public var resetsAt: Date? = nil
    }
    public struct NextTier: Sendable, Equatable {
        public let cap: Int
        public let missing: [String]
    }
    /// When daily limits reset (midnight in the site's reset time zone, UTC by default); a longer window has its own `Route.resetsAt`.
    public let resetsAt: Date
    public let routes: [Route]
}

/// A single-use pass for one write. Send `headerValue` as `x-aegis-lease`.
public struct Lease: Sendable {
    public let headerValue: String
    public let expiresAt: Date
}

/// The native Aegis client for iOS.
///
///     let aegis = try AegisClient(baseURL: URL(string: "https://api.example.com")!)
///     var request = URLRequest(url: URL(string: "https://api.example.com/v1/keys")!)
///     request.httpMethod = "POST"
///     let (data, response) = try await aegis.send(request, route: "POST /v1/keys")
///
/// What happens underneath, and what leaves the device:
///  1. **Identity** — on first use, App Attest generates a Secure Enclave key
///     and Apple attests it; the server verifies Apple's chain and returns a
///     principal credential. Later sessions sign a challenge with the same
///     key (an assertion). The key never leaves the Secure Enclave.
///  2. **Ticket** — a random input is blinded on-device; the server signs
///     the blinded value without seeing it (VOPRF). The finished ticket
///     can't be linked back to this issuance.
///  3. **Spend** — the ticket buys a single-use, ~30s pass for one write,
///     counted against this principal's daily cap for the route.
public actor AegisClient {
    public static let leaseHeader = "x-aegis-lease"

    private let baseURL: URL
    private let apiPath: String
    private let attestation: AppAttestProvider
    private let store: CredentialStore
    private let session: URLSession
    /// nil disables reinstall continuity entirely (matches AegisClient's
    /// behavior before this existed): every reinstall anchors a fresh
    /// principal, same as a genuinely new device. See DeviceJoinKey.swift.
    private let joinKey: DeviceJoinKeyProvider?
    private var refreshing: Task<PrincipalCredential, Error>?
    /// Private routes' tickets, minted ahead (in memory), per route: see `prefetchPrivate`.
    private var privateTickets: [String: [Ticket]] = [:]

    private static let keyIdKey = "aegis.appattest.keyId"
    private static let principalKey = "aegis.principal"
    private static let pendingKeyIdKey = "aegis.appattest.pendingKeyId"

    /// Key transparency (specs/PRIVATE_ROUTES.md): the deployment's
    /// lease-signing public keys (raw Ed25519, base64url; `publicKey` on
    /// GET /api/aegis/voprf/keys), baked into the app. When set, every ticket
    /// key must appear in the day's statement signed by one of them.
    private let keyPins: [String]
    /// With `keyPins`: the site id the statement must name. Every site on a
    /// deployment signs with the same key, so without this a server could
    /// show this app another site's validly signed statement.
    private let keySite: String?
    private var statements: [String: [String: String]] = [:]

    /// The default session: no cookies, no cache, nothing on disk. Nothing
    /// ambient identifies the person beyond what each call sends, and a key
    /// statement is always fresh.
    public static let ephemeralSession: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpShouldSetCookies = false
        c.httpCookieAcceptPolicy = .never
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.urlCache = nil
        return URLSession(configuration: c)
    }()

    /// The app's own protected request (to its backend) goes out on this
    /// session, with the app's cookies, as it would without PwnBot. Only
    /// PwnBot's own calls use `session` (ephemeral by default).
    private let appSession: URLSession

    public init(baseURL: URL, attestation: AppAttestProvider, store: CredentialStore, joinKey: DeviceJoinKeyProvider? = nil, apiPath: String = "/api/aegis", session: URLSession = AegisClient.ephemeralSession, appSession: URLSession = .shared, keyPins: [String] = [], keySite: String? = nil) {
        self.appSession = appSession
        self.keyPins = keyPins
        self.keySite = keySite
        self.baseURL = baseURL
        self.apiPath = apiPath
        self.attestation = attestation
        self.store = store
        self.joinKey = joinKey
        self.session = session
    }

    #if canImport(DeviceCheck) && canImport(Security)
    /// Production defaults: DeviceCheck App Attest + Keychain, including a
    /// Keychain-persisted join key so a reinstalled app keeps its principal
    /// (and spend history) instead of starting over — pass `joinKey: nil`
    /// to opt out.
    @available(iOS 14.0, macOS 11.0, *)
    public init(baseURL: URL, apiPath: String = "/api/aegis", keyPins: [String] = [], keySite: String? = nil) throws {
        self.init(baseURL: baseURL, attestation: DCAppAttestProvider(), store: KeychainCredentialStore(), joinKey: try KeychainDeviceJoinKey(), apiPath: apiPath, keyPins: keyPins, keySite: keySite)
    }
    #endif

    // MARK: - The one call most apps need

    /// Authorize and send one protected write: obtains a principal, a ticket
    /// and a pass for `route` (e.g. "POST /v1/keys"), then sends `request`
    /// with the pass attached. Throws `AegisError.refused` with
    /// `isCapExhausted` when today's share is used up. On a route limited
    /// per thing (so many bookings per person per venue), `resource` names
    /// the thing; the app's server names it again when it checks the pass.
    ///
    /// `ifNoPass: .send` is for an app that must keep working where no pass
    /// can be had (the Simulator, PwnBot unreachable, today's limit): the
    /// request is sent without one, with the reason in `x-pwnbot-no-pass`,
    /// and the app's server decides. In canary it lets the write through;
    /// in enforce it refuses, and that refusal is thrown here as the error
    /// that says why there was no pass. The default, `.fail`, throws
    /// without sending.
    public func send(_ request: URLRequest, route: String, family: String = "T_unique", resource: String? = nil, ifNoPass: NoPass = .fail) async throws -> (Data, HTTPURLResponse) {
        var req = request
        var why: Error?
        req.setValue(nil, forHTTPHeaderField: Self.noPassHeader)
        do {
            let lease = try await authorize(route: route, family: family, resource: resource)
            req.setValue(lease.headerValue, forHTTPHeaderField: Self.leaseHeader)
        } catch {
            if ifNoPass == .fail { throw error }
            why = error
            req.setValue(nil, forHTTPHeaderField: Self.leaseHeader)
            req.setValue(Self.noPassReason(error), forHTTPHeaderField: Self.noPassHeader)
        }
        let (data, response) = try await appSession.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw AegisError.invalidResponse("not HTTP") }
        // Only on the path that sends without a pass: a refusal by the server's PwnBot guard (it marks its own).
        if ifNoPass == .send, http.statusCode == 403 || http.statusCode == 503, http.value(forHTTPHeaderField: Self.refusedHeader) != nil {
            if let why { throw why }
            if http.statusCode == 503 { throw AegisError.busy(retryAfterSeconds: 5) }
            let reasons = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["reasons"] as? [String] ?? []
            throw AegisError.refused(status: http.statusCode, reasons: reasons, message: nil)
        }
        return (data, http)
    }

    /// What to do when no pass can be had; see `send`.
    public enum NoPass: Sendable { case send, fail }
    /// Why a request carries no pass; the app server's guard logs it.
    public static let noPassHeader = "x-pwnbot-no-pass"
    /// Set by pwnbotdetect's guards on the refusals that are theirs.
    public static let refusedHeader = "x-pwnbot-refused"

    static func noPassReason(_ error: Error) -> String {
        guard let aegis = error as? AegisError else { return "unreachable" }
        switch aegis {
        case .refused: return aegis.isCapExhausted ? "limit" : "refused"
        case .busy: return "busy"
        case .attestationUnsupported: return "unsupported"
        default: return "unreachable"
        }
    }

    /// Principal → ticket → single-use pass for `route`.
    public func authorize(route: String, family: String = "T_unique", resource: String? = nil) async throws -> Lease {
        try await withPrincipal { principal in
            let ticket = try await mintTicket(family: family, principal: principal)
            return try await spend(route: route, family: family, ticket: ticket, principal: principal, resource: resource)
        }
    }

    // MARK: - Private routes (specs/PRIVATE_ROUTES.md)

    /// Mint up to `count` tickets for a private route now (at app start, or
    /// when the screen with the votes opens) to spend later with
    /// `authorizePrivate`. Minting is identified and charges the route's
    /// limit; spending isn't. Minting ahead keeps the server from pairing a
    /// write with the mint just before it by timing. Stops quietly at the
    /// limit and returns how many it minted. Tickets are good on that route,
    /// the day (UTC) they're minted.
    @discardableResult
    public func prefetchPrivate(route: String, count: Int, family: String = "T_unique") async throws -> Int {
        guard count > 0 else { return 0 }
        var minted = 0
        for _ in 0..<count {
            do {
                let ticket = try await withPrincipal { try await mintTicket(family: family, principal: $0, route: route) }
                privateTickets[route, default: []].append(ticket)
                minted += 1
            } catch let AegisError.refused(_, reasons, _) where reasons.contains("cap.exhausted") {
                break
            }
        }
        return minted
    }

    /// A pass for a private route: spends a prefetched ticket if there is one
    /// and sends no credential, so the pass names no one. A ticket from a
    /// past day, or already spent, is dropped for the next; a spend that
    /// fails for any other reason (busy, offline) keeps its ticket for the
    /// retry. With nothing held it mints one now, which lets the server pair
    /// the mint and the write by timing: call `prefetchPrivate` ahead.
    public func authorizePrivate(route: String, family: String = "T_unique") async throws -> Lease {
        func dead(_ error: Error) -> Bool {
            if case let AegisError.refused(_, reasons, _) = error { return reasons.contains("pop.failed") || reasons.contains("ticket.replay") }
            return false
        }
        while let ticket = privateTickets[route]?.first {
            privateTickets[route]?.removeFirst()
            do {
                return try await spendPrivate(route: route, family: family, ticket: ticket)
            } catch {
                if dead(error) { continue }
                privateTickets[route, default: []].insert(ticket, at: 0)
                throw error
            }
        }
        let ticket = try await withPrincipal { try await mintTicket(family: family, principal: $0, route: route) }
        do {
            return try await spendPrivate(route: route, family: family, ticket: ticket)
        } catch {
            if !dead(error) { privateTickets[route, default: []].insert(ticket, at: 0) }
            throw error
        }
    }

    /// `send` for a private route: the pass from `authorizePrivate`.
    public func sendPrivate(_ request: URLRequest, route: String, family: String = "T_unique") async throws -> (Data, HTTPURLResponse) {
        let lease = try await authorizePrivate(route: route, family: family)
        var req = request
        req.setValue(lease.headerValue, forHTTPHeaderField: Self.leaseHeader)
        let (data, response) = try await appSession.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw AegisError.invalidResponse("not HTTP") }
        return (data, http)
    }

    /// Runs `body` with the principal credential, once more with a fresh one
    /// if the server says the cached one was revoked before it expired
    /// (`epoch.stale`: an epoch bump, or the user's records were erased when
    /// they deleted their account). Without this the device got no passes
    /// until the credential's TTL ran out (Fade, 2026-09-25).
    private func withPrincipal<T>(_ body: (PrincipalCredential) async throws -> T) async throws -> T {
        let principal = try await principal()
        do {
            return try await body(principal)
        } catch let AegisError.refused(_, reasons, _) where reasons.contains("epoch.stale") {
            // Only if it's still the refused one: a concurrent call may
            // already have stored its replacement.
            if store.get(Self.principalKey) == principal.token { store.set(Self.principalKey, nil) }
            return try await body(try await self.principal())
        }
    }

    // MARK: - Identity (App Attest)

    /// A principal credential with at least a minute left: the cached one, or
    /// a fresh App Attest assertion, or (first run) an App Attest enrollment.
    public func principal() async throws -> PrincipalCredential {
        if let cached = cachedPrincipal(), cached.expiresAt.timeIntervalSinceNow > 60 { return cached }
        // One refresh at a time. The actor is reentrant at every await, so
        // two callers would otherwise each assert or, worse, each enroll a
        // new key, and Apple's risk metric counts every key a device makes.
        if let refreshing { return try await refreshing.value }
        let task = Task { try await self.refreshPrincipal() }
        refreshing = task
        defer { refreshing = nil }
        return try await task.value
    }

    private func refreshPrincipal() async throws -> PrincipalCredential {
        if let keyId = store.get(Self.keyIdKey) {
            do {
                return try await assertKey(keyId)
            } catch let AegisError.refused(status, _, _) where status == 404 {
                // The server no longer knows this key (e.g. its store was reset): enroll a fresh one.
                store.set(Self.keyIdKey, nil)
            } catch is AppAttestKeyInvalid {
                // The device no longer has this key: the app was deleted and
                // reinstalled, or restored to another device. The key id
                // survived in the Keychain; the Secure Enclave key didn't.
                store.set(Self.keyIdKey, nil)
            }
        }
        return try await enroll()
    }

    /// Forget the device key and credential (e.g. on sign-out). The next call enrolls again.
    public func reset() {
        store.set(Self.keyIdKey, nil)
        store.set(Self.pendingKeyIdKey, nil)
        store.set(Self.principalKey, nil)
    }

    private func enroll() async throws -> PrincipalCredential {
        guard attestation.isSupported else { throw AegisError.attestationUnsupported }
        // Apple: if attestKey fails with serverUnavailable, retry later with
        // the SAME key; for any other error, discard it. A fresh key per
        // retry would inflate Apple's per-device risk metric, which a
        // deployment can use to cap principals per device. So a key waiting
        // on a retryable failure is kept as pending and reused.
        let keyId: String
        if let pending = store.get(Self.pendingKeyIdKey) {
            keyId = pending
        } else {
            keyId = try await attestation.generateKey()
            store.set(Self.pendingKeyIdKey, keyId)
        }
        guard let rawKeyId = Data(base64Encoded: keyId), rawKeyId.count == 32 else {
            store.set(Self.pendingKeyIdKey, nil)
            throw AegisError.invalidResponse("unexpected App Attest key id")
        }
        let challenge = try await newChallenge()
        let object: Data
        do {
            object = try await attestation.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: challenge.bytes)))
        } catch AegisError.busy(let seconds) {
            throw AegisError.busy(retryAfterSeconds: seconds) // keep the pending key for the retry
        } catch {
            store.set(Self.pendingKeyIdKey, nil)
            throw error
        }
        // Attested (a key can only be attested once): never reuse it as pending.
        store.set(Self.pendingKeyIdKey, nil)
        var body: [String: String] = [
            "challengeKey": challenge.key,
            "keyId": rawKeyId.base64URL,
            "attestation": object.base64URL
        ]
        // A still-cached (not yet expired) credential from before this
        // enrollment — e.g. the server lost its record of our old key but
        // our short-lived credential is still good — lets attach() add this
        // new key to that SAME principal instead of anchoring a fresh one.
        // Only while unexpired: the server treats a lapsed one as absent anyway.
        if let cached = cachedPrincipal(), cached.expiresAt > Date() { body["current"] = cached.token }
        // The join key covers the gap that leaves: a real reinstall, where
        // the credential above is long expired (or never existed on this
        // launch) but the Keychain-persisted join key survived anyway. See
        // DeviceJoinKey.swift.
        if let joinKey {
            body["joinPublicKey"] = joinKey.publicKeySPKI.base64URL
            body["joinSignature"] = try joinKey.sign(challenge: challenge.bytes).base64URL
        }
        let json = try await post("/attest/apple/register", body)
        store.set(Self.keyIdKey, keyId)
        return try remember(json)
    }

    private func assertKey(_ keyId: String) async throws -> PrincipalCredential {
        guard let rawKeyId = Data(base64Encoded: keyId) else { throw AegisError.invalidResponse("stored key id") }
        let challenge = try await newChallenge()
        // The server requires exactly this JSON, byte for byte, to carry its challenge.
        let clientData = Data(#"{"challenge":"\#(challenge.string)"}"#.utf8)
        let assertion = try await attestation.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
        var body: [String: String] = [
            "challengeKey": challenge.key,
            "keyId": rawKeyId.base64URL,
            "assertion": assertion.base64URL,
            "clientData": clientData.base64URL
        ]
        // Not needed to resolve identity here (the assertion already does
        // that) — presenting it anyway keeps the join key's server-side
        // binding fresh across ordinary, frequent use, so it doesn't expire
        // on a device that's actually active. See device-attest.ts's
        // appleAssertInner.
        if let joinKey {
            body["joinPublicKey"] = joinKey.publicKeySPKI.base64URL
            body["joinSignature"] = try joinKey.sign(challenge: challenge.bytes).base64URL
        }
        let json = try await post("/attest/apple/assert", body)
        return try remember(json)
    }

    private func newChallenge() async throws -> (key: String, string: String, bytes: Data) {
        let json = try await post("/attest/challenge", [:])
        guard let key = json["challengeKey"] as? String, let c = json["challenge"] as? String, let bytes = Data(base64URL: c) else {
            throw AegisError.invalidResponse("challenge")
        }
        return (key, c, bytes)
    }

    private func remember(_ json: [String: Any]) throws -> PrincipalCredential {
        guard let token = json["principal"] as? String, let cred = Self.parse(token) else { throw AegisError.invalidResponse("principal credential") }
        store.set(Self.principalKey, token)
        return cred
    }

    private func cachedPrincipal() -> PrincipalCredential? {
        store.get(Self.principalKey).flatMap(Self.parse)
    }

    /// Reads the credential's (server-signed) fields for local bookkeeping only.
    static func parse(_ token: String) -> PrincipalCredential? {
        guard let data = Data(base64URL: token),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ps = obj["ps"] as? String, let ev = obj["ev"] as? [String], let exp = obj["exp"] as? Double
        else { return nil }
        return PrincipalCredential(token: token, principalSite: ps, evidence: ev, expiresAt: Date(timeIntervalSince1970: exp))
    }

    // MARK: - Tickets (VOPRF) and spending

    /// Mint one unlinkable ticket. The input and blind never leave this device.
    /// Spend it soon: issuer keys rotate at UTC midnight and a ticket minted
    /// the day before is accepted only until 00:15 UTC (then `pop.failed`).
    /// `send`/`authorize` mint and spend together and never hit this.
    public func mintTicket(family: String = "T_unique", principal: PrincipalCredential, route: String? = nil) async throws -> Ticket {
        // route: a private route's ticket, under that route's own key.
        var keyBody: [String: Any] = ["family": family]
        if let route { keyBody["route"] = route }
        let pk = try await post("/voprf/pubkey", keyBody)
        guard pk["mode"] as? String == "voprf", let pkString = pk["publicKey"] as? String, let pkBytes = Data(base64URL: pkString) else {
            throw AegisError.invalidResponse("server isn't running the VOPRF issuer")
        }
        var input = Data(count: 32)
        let status = input.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw AegisError.crypto("no randomness") }
        let client = try VOPRFClient(publicKey: pkBytes)
        let (request, state) = try client.blind(input: input)
        var evalBody: [String: Any] = ["family": family, "evalRequest": request.base64URL, "principal": principal.token]
        if let route { evalBody["route"] = route }
        let ev = try await post("/voprf/evaluate", evalBody)
        guard let evalString = ev["evaluation"] as? String, let evaluation = Data(base64URL: evalString) else {
            throw AegisError.invalidResponse("evaluation")
        }
        // Across UTC midnight the issuer key rotates between pubkey and
        // evaluate; the server says which key evaluated, and the proof
        // check below still binds the result to that key.
        // Only a key anyone gets: evaluate is an identified request, so a key
        // of this identity's own would let the server tell whose ticket it
        // was at spend. A changed key must match a second, credential-less fetch.
        var finalizer = client
        var usedKey = pkString
        if let k = ev["publicKey"] as? String, !k.isEmpty, k != pkString {
            // A key that won't decode is refused, never skipped: skipping would
            // finalize under pkString while checking `k` against the statement.
            guard let kb = Data(base64URL: k) else { throw AegisError.invalidResponse("publicKey") }
            let again = try await post("/voprf/pubkey", keyBody)
            guard again["publicKey"] as? String == k else {
                throw AegisError.refused(status: 0, reasons: ["sig.invalid"], message: "the issuer evaluated under a key it doesn't publish")
            }
            finalizer = try VOPRFClient(publicKey: kb)
            usedKey = k
        }
        // Key transparency: the key that finalizes must be one the server signed for the day.
        try await requireStatedKey(route.map { "private:\($0)" } ?? family, usedKey)
        let output = try finalizer.finalize(state: state, evaluation: evaluation)
        return Ticket(serial: input.base64URL, proof: output.base64URL)
    }

    /// With `keyPins` set: `key` must be `keyName`'s key in today's or
    /// yesterday's statement signed by a pinned key (fetched without a credential).
    private func requireStatedKey(_ keyName: String, _ key: String) async throws {
        guard !keyPins.isEmpty else { return }
        // A statement can change within a UTC day (a private route's day turns
        // at the site's local midnight; a route added mid-day): on a miss,
        // read it again once before refusing.
        if try await statedKeyMatches(keyName, key, fresh: false) { return }
        if try await statedKeyMatches(keyName, key, fresh: true) { return }
        throw AegisError.refused(status: 0, reasons: ["sig.invalid"], message: "the issuer's key isn't in its signed key statement")
    }

    private func statedKeyMatches(_ keyName: String, _ key: String, fresh: Bool) async throws -> Bool {
        let today = ISO8601DateFormatter().string(from: Date()).prefix(10)
        for day in ["today", "yesterday"] {
            let cacheKey = "\(today):\(day)"
            var keys = fresh ? nil : statements[cacheKey]
            if keys == nil {
                var components = URLComponents(url: baseURL.appendingPathComponent(apiPath + "/voprf/keys"), resolvingAgainstBaseURL: false)!
                components.queryItems = [URLQueryItem(name: "day", value: day)]
                let (data, _) = try await session.data(from: components.url!)
                let body = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
                guard let statement = body["statement"] as? String, let sig = (body["sig"] as? String).flatMap({ Data(base64URL: $0) }),
                      keyPins.contains(where: { pin in
                          guard let raw = Data(base64URL: pin), let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { return false }
                          return pub.isValidSignature(sig, for: Data(statement.utf8))
                      }),
                      let parsed = try? JSONSerialization.jsonObject(with: Data(statement.utf8)) as? [String: Any],
                      let stated = parsed["keys"] as? [String: String] else {
                    throw AegisError.refused(status: 0, reasons: ["sig.invalid"], message: "the issuer's key statement isn't signed by a pinned key")
                }
                // Today's or yesterday's, give or take a drifting clock: an old
                // statement, however validly signed then, isn't today's.
                let dayFormat = ISO8601DateFormatter()
                dayFormat.formatOptions = [.withFullDate]
                guard let statedDay = (parsed["day"] as? String).flatMap({ dayFormat.date(from: $0) }),
                      let todayDate = dayFormat.date(from: String(today)),
                      abs(statedDay.timeIntervalSince(todayDate)) <= 2 * 86_400 else {
                    throw AegisError.refused(status: 0, reasons: ["sig.invalid"], message: "the issuer's key statement is for another day")
                }
                if let keySite, parsed["site"] as? String != keySite {
                    throw AegisError.refused(status: 0, reasons: ["sig.invalid"], message: "the issuer's key statement is for another site")
                }
                statements[cacheKey] = stated
                keys = stated
            }
            if keys?[keyName] == key { return true }
        }
        return false
    }

    /// What this user has left today on each capped route, so the app can say
    /// "2 invites left today" before anyone hits a refusal. Only this
    /// principal's own numbers.
    public func allowance() async throws -> Allowance {
        let json = try await withPrincipal { try await post("/allowance", ["principal": $0.token]) }
        guard let resetsAt = json["resetsAt"] as? Double, let routes = json["routes"] as? [[String: Any]] else {
            throw AegisError.invalidResponse("allowance")
        }
        return Allowance(
            resetsAt: Date(timeIntervalSince1970: resetsAt / 1000),
            routes: try routes.map { r in
                guard let route = r["route"] as? String, let limit = r["limit"] as? Int, let used = r["used"] as? Int,
                      let remaining = r["remaining"] as? Int, let evidenceOk = r["evidenceOk"] as? Bool else {
                    throw AegisError.invalidResponse("allowance route")
                }
                let next = (r["nextTier"] as? [String: Any]).flatMap { t -> Allowance.NextTier? in
                    guard let cap = t["cap"] as? Int, let missing = t["missing"] as? [String] else { return nil }
                    return Allowance.NextTier(cap: cap, missing: missing)
                }
                return Allowance.Route(route: route, limit: limit, used: used, remaining: remaining, evidenceOk: evidenceOk, nextTier: next,
                                       windowDays: r["windowDays"] as? Int,
                                       resetsAt: (r["resetsAt"] as? Double).map { Date(timeIntervalSince1970: $0 / 1000) })
            }
        )
    }

    /// Lets this user's own agent (an assistant, a script) act for them: up to
    /// `perDay` writes a day on `routes`, charged to the user's own limits
    /// too, so the agent never adds capacity. Hand `Delegation.delegation` to
    /// the agent (it sends it as `principal`); keep `id` to revoke it. Lasts
    /// `ttlSeconds` (default a day, at most a week).
    public func delegate(routes: [String], perDay: Int, ttlSeconds: Int? = nil) async throws -> Delegation {
        let json = try await withPrincipal { principal in
            var body: [String: Any] = ["principal": principal.token, "routes": routes, "per_day": perDay]
            if let ttlSeconds { body["ttl_seconds"] = ttlSeconds }
            return try await post("/delegate", body)
        }
        guard let delegation = json["delegation"] as? String, let id = json["id"] as? String, let expiresAt = json["expires_at"] as? Double else {
            throw AegisError.invalidResponse("delegation")
        }
        return Delegation(delegation: delegation, id: id, expiresAt: Date(timeIntervalSince1970: expiresAt / 1000))
    }

    /// Ends one of this user's delegations now.
    public func revokeDelegation(id: String) async throws {
        let json = try await withPrincipal { try await post("/delegate/revoke", ["principal": $0.token, "id": id]) }
        guard json["revoked"] as? Bool == true else { throw AegisError.invalidResponse("revoke") }
    }

    /// Spend a ticket on `route` for a single-use pass.
    public func spend(route: String, family: String = "T_unique", ticket: Ticket, principal: PrincipalCredential, resource: String? = nil) async throws -> Lease {
        var body: [String: Any] = [
            "route": route,
            "family": family,
            "ticket": ["serial": ticket.serial, "proof": ticket.proof],
            "principal": principal.token
        ]
        if let resource { body["resource"] = resource }
        let json = try await post("/spend", body)
        guard let lease = json["lease"] as? [String: Any], let exp = lease["exp"] as? Double else { throw AegisError.invalidResponse("lease") }
        let data = try JSONSerialization.data(withJSONObject: lease)
        return Lease(headerValue: data.base64URL, expiresAt: Date(timeIntervalSince1970: exp))
    }

    /// Spend a private route's ticket: no credential, so the pass names no one.
    public func spendPrivate(route: String, family: String = "T_unique", ticket: Ticket) async throws -> Lease {
        let json = try await post("/spend", [
            "route": route,
            "family": family,
            "ticket": ["serial": ticket.serial, "proof": ticket.proof]
        ])
        guard let lease = json["lease"] as? [String: Any], let exp = lease["exp"] as? Double else { throw AegisError.invalidResponse("lease") }
        let data = try JSONSerialization.data(withJSONObject: lease)
        return Lease(headerValue: data.base64URL, expiresAt: Date(timeIntervalSince1970: exp))
    }

    /// "This was me": sends the support reference from a refusal
    /// (`AegisError.refused`'s message carries "Reference: …") and an optional
    /// note to the deployment's appeal inbox, where the operator gives today's
    /// allowance back with one click. Needs no credential; returns once it is
    /// in the inbox. The restore happens when the operator acts.
    public func appeal(reference: String, route: String, note: String? = nil) async throws {
        var body: [String: Any] = ["reference": reference, "route": route]
        if let note, !note.isEmpty { body["note"] = note }
        _ = try await post("/appeal", body)
    }

    // MARK: - HTTP

    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        var req = URLRequest(url: baseURL.appendingPathComponent(apiPath + path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw AegisError.invalidResponse("not HTTP") }
        let json = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        let reasons = json["reasons"] as? [String] ?? []
        // A support reference ("ref", see RefusalExplanation.reference) rides in
        // the message, so it reaches the Expo bridge and explanation unchanged.
        let refusal = [json["error"] as? String, (json["ref"] as? String).map { "Reference: \($0)" }]
            .compactMap { $0 }.joined(separator: " ")
        let message = refusal.isEmpty ? nil : refusal
        if http.statusCode == 429 || (http.statusCode == 503 && reasons.contains("heat.high")) {
            if reasons.contains("cap.exhausted") { throw AegisError.refused(status: http.statusCode, reasons: reasons, message: message) }
            throw AegisError.busy(retryAfterSeconds: Int(http.value(forHTTPHeaderField: "retry-after") ?? "") ?? 1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw AegisError.refused(status: http.statusCode, reasons: reasons, message: message)
        }
        return json
    }
}
