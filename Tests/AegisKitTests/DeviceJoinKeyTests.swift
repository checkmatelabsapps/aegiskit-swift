import XCTest
import CryptoKit
@testable import AegisKit

/// Verifies InMemoryDeviceJoinKey's SPKI encoding and signature format
/// server-side verification actually depends on — not that Security.framework
/// works (that's Apple's job), but that our encoding matches what
/// verifyP256() on the server expects: DER P-256 SubjectPublicKeyInfo,
/// ECDSA-SHA256 signature in DER (X9.62/ANSI) form.
final class DeviceJoinKeyTests: XCTestCase {
    func testPublicKeySPKIIsAWellFormedP256SubjectPublicKeyInfo() {
        let key = InMemoryDeviceJoinKey()
        // 26-byte fixed header + 65-byte uncompressed point (0x04 || X || Y).
        XCTAssertEqual(key.publicKeySPKI.count, 91)
        XCTAssertEqual(key.publicKeySPKI.first, 0x30) // DER SEQUENCE tag
        XCTAssertEqual(key.publicKeySPKI[key.publicKeySPKI.startIndex + 26], 0x04) // uncompressed point marker
    }

    func testSignatureVerifiesAgainstThePublicKeyUsingCryptoKitIndependently() throws {
        // Independent of our own signing code: re-derive a CryptoKit public
        // key from the SPKI bytes we produced, and verify with CryptoKit's
        // own verifier — if our SPKI encoding were wrong, this round trip
        // would fail even though our own sign() "succeeded".
        let key = InMemoryDeviceJoinKey()
        let challenge = Data("test-challenge-\(UUID().uuidString)".utf8)
        let signature = try key.sign(challenge: challenge)

        let rawPoint = key.publicKeySPKI.suffix(65) // strip the fixed 26-byte header back off
        let publicKey = try P256.Signing.PublicKey(x963Representation: rawPoint)
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(ecdsaSignature, for: challenge))
    }

    func testDifferentChallengesProduceDifferentSignatures() throws {
        let key = InMemoryDeviceJoinKey()
        let a = try key.sign(challenge: Data("challenge-a".utf8))
        let b = try key.sign(challenge: Data("challenge-b".utf8))
        XCTAssertNotEqual(a, b)
    }

    func testTwoInstancesHaveDifferentKeys() {
        XCTAssertNotEqual(InMemoryDeviceJoinKey().publicKeySPKI, InMemoryDeviceJoinKey().publicKeySPKI)
    }

    func testASignatureFromOneKeyDoesNotVerifyAgainstAnothersPublicKey() throws {
        let key = InMemoryDeviceJoinKey()
        let impostor = InMemoryDeviceJoinKey()
        let challenge = Data("test-challenge".utf8)
        let signature = try impostor.sign(challenge: challenge)

        let rawPoint = key.publicKeySPKI.suffix(65)
        let publicKey = try P256.Signing.PublicKey(x963Representation: rawPoint)
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertFalse(publicKey.isValidSignature(ecdsaSignature, for: challenge))
    }
}
