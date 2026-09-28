import Foundation
import CryptoKit

/// RFC 9497 VOPRF client, suite ristretto255-SHA512 — byte-compatible with
/// the Aegis server's issuer (@cloudflare/voprf-ts), checked against vectors
/// that library generated (Tests/AegisKitTests/Resources/voprf-vectors.json).
///
/// The input and blind never leave the device: the server only sees
/// `request` (a blinded element) and can't link the finalized ticket back to
/// this issuance. `finalize` verifies the server's DLEQ proof, so a server
/// using a different key per user (to tag them) is detected, not trusted.
public struct VOPRFClient {
    static let contextString: [UInt8] = Array("OPRFV1-".utf8) + [0x01] + Array("-ristretto255-SHA512".utf8)
    static let hashToGroupDST = Array("HashToGroup-".utf8) + contextString
    static let hashToScalarDST = Array("HashToScalar-".utf8) + contextString
    static let seedDST = Array("Seed-".utf8) + contextString

    let publicKey: Element

    public init(publicKey: Data) throws {
        self.publicKey = try Element.decode(Array(publicKey))
    }

    public struct FinalizeState {
        let input: [UInt8]
        let blind: Scalar
        let blinded: Element
    }

    /// Blind `input`. Returns the serialized EvaluationRequest (u16 count = 1 ‖ element).
    public func blind(input: Data) throws -> (request: Data, state: FinalizeState) {
        try blind(input: Array(input), blind: .random())
    }

    func blind(input: [UInt8], blind r: Scalar) throws -> (request: Data, state: FinalizeState) {
        let p = Element.fromHash(expandMessageXMD(input, dst: Self.hashToGroupDST, length: 64))
        let blinded = try p.times(r)
        return (Data([0x00, 0x01] + blinded.bytes), FinalizeState(input: input, blind: r, blinded: blinded))
    }

    /// Verify the proof in a serialized Evaluation (u16 count ‖ elements ‖ mode ‖ c ‖ s) and unblind.
    public func finalize(state: FinalizeState, evaluation: Data) throws -> Data {
        let e = Array(evaluation)
        guard e.count == 2 + 32 + 1 + 64, e[0] == 0x00, e[1] == 0x01, e[34] == 0x01 else {
            throw AegisError.invalidResponse("evaluation must carry exactly one element and a VOPRF proof")
        }
        let evaluated = try Element.decode(Array(e[2..<34]))
        let c = try Scalar.decode(Array(e[35..<67]))
        let s = try Scalar.decode(Array(e[67..<99]))
        guard try verifyProof(blinded: state.blinded, evaluated: evaluated, c: c, s: s) else {
            throw AegisError.proofVerificationFailed
        }
        let unblinded = try evaluated.times(try state.blind.inverted())
        var h = SHA512()
        h.update(data: lp(state.input) + lp(unblinded.bytes) + Array("Finalize".utf8))
        return Data(h.finalize())
    }

    /// RFC 9497 §2.2.2 VerifyProof for one (C, D) pair: A = G, B = pkS, C = blinded, D = evaluated.
    func verifyProof(blinded: Element, evaluated: Element, c: Scalar, s: Scalar) throws -> Bool {
        let seed = sha512(lp(publicKey.bytes) + lp(Self.seedDST))
        let di = hashToScalar(lp(seed) + [0x00, 0x00] + lp(blinded.bytes) + lp(evaluated.bytes) + Array("Composite".utf8))
        let m = try blinded.times(di)
        let z = try evaluated.times(di)
        let t2 = try Element.base(times: s).plus(try publicKey.times(c))
        let t3 = try m.times(s).plus(try z.times(c))
        let challenge = hashToScalar(
            lp(publicKey.bytes) + lp(m.bytes) + lp(z.bytes) + lp(t2.bytes) + lp(t3.bytes) + Array("Challenge".utf8)
        )
        return constantTimeEqual(challenge.bytes, c.bytes)
    }

    func hashToScalar(_ msg: [UInt8]) -> Scalar {
        Scalar.reduce(expandMessageXMD(msg, dst: Self.hashToScalarDST, length: 64))
    }
}

/// u16 big-endian length prefix, as RFC 9497 frames every hashed field.
func lp(_ b: [UInt8]) -> [UInt8] {
    [UInt8(b.count >> 8), UInt8(b.count & 0xff)] + b
}

func sha512(_ b: [UInt8]) -> [UInt8] {
    Array(SHA512.hash(data: b))
}

/// RFC 9380 §5.3.1 expand_message_xmd with SHA-512.
func expandMessageXMD(_ msg: [UInt8], dst: [UInt8], length: Int) -> [UInt8] {
    let bInBytes = 64, sInBytes = 128
    let ell = (length + bInBytes - 1) / bInBytes
    precondition(ell <= 255 && dst.count <= 255 && length <= 65535)
    let dstPrime = dst + [UInt8(dst.count)]
    let msgPrime = [UInt8](repeating: 0, count: sInBytes) + msg + [UInt8(length >> 8), UInt8(length & 0xff), 0] + dstPrime
    let b0 = sha512(msgPrime)
    var bi = sha512(b0 + [1] + dstPrime)
    var uniform = bi
    if ell > 1 {
        for i in 2...ell {
            bi = sha512(zip(b0, bi).map { $0 ^ $1 } + [UInt8(i)] + dstPrime)
            uniform += bi
        }
    }
    return Array(uniform.prefix(length))
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}
