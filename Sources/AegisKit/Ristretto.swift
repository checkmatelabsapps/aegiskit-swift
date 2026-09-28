import Foundation
import Clibsodium

/// Thin, checked wrappers over libsodium's ristretto255 primitives — the
/// group the Aegis VOPRF runs in (RFC 9497 suite ristretto255-SHA512).
enum Sodium {
    static let ready: Bool = sodium_init() >= 0
}

struct Scalar: Equatable {
    let bytes: [UInt8]  // 32 bytes, little-endian, canonical (< L)

    static func random() -> Scalar {
        _ = Sodium.ready
        var out = [UInt8](repeating: 0, count: 32)
        crypto_core_ristretto255_scalar_random(&out)
        return Scalar(bytes: out)
    }

    /// Reduce a 64-byte uniform string mod L (hash-to-scalar).
    static func reduce(_ wide: [UInt8]) -> Scalar {
        precondition(wide.count == 64)
        _ = Sodium.ready
        var out = [UInt8](repeating: 0, count: 32)
        crypto_core_ristretto255_scalar_reduce(&out, wide)
        return Scalar(bytes: out)
    }

    /// Accepts only canonical encodings, as the server's decoder does.
    static func decode(_ b: [UInt8]) throws -> Scalar {
        guard b.count == 32 else { throw AegisError.invalidResponse("scalar length") }
        let s = reduce(b + [UInt8](repeating: 0, count: 32))
        guard s.bytes == b else { throw AegisError.invalidResponse("non-canonical scalar") }
        return Scalar(bytes: b)
    }

    func inverted() throws -> Scalar {
        var out = [UInt8](repeating: 0, count: 32)
        guard crypto_core_ristretto255_scalar_invert(&out, bytes) == 0 else { throw AegisError.crypto("scalar not invertible") }
        return Scalar(bytes: out)
    }
}

struct Element: Equatable {
    let bytes: [UInt8]  // 32-byte canonical ristretto255 encoding

    /// Map a 64-byte uniform string to the group (hash-to-group).
    static func fromHash(_ uniform: [UInt8]) -> Element {
        precondition(uniform.count == 64)
        _ = Sodium.ready
        var out = [UInt8](repeating: 0, count: 32)
        crypto_core_ristretto255_from_hash(&out, uniform)
        return Element(bytes: out)
    }

    static func decode(_ b: [UInt8]) throws -> Element {
        _ = Sodium.ready
        guard b.count == 32, crypto_core_ristretto255_is_valid_point(b) == 1 else {
            throw AegisError.invalidResponse("invalid group element")
        }
        return Element(bytes: b)
    }

    static func base(times s: Scalar) throws -> Element {
        var out = [UInt8](repeating: 0, count: 32)
        guard crypto_scalarmult_ristretto255_base(&out, s.bytes) == 0 else { throw AegisError.crypto("identity result") }
        return Element(bytes: out)
    }

    func times(_ s: Scalar) throws -> Element {
        var out = [UInt8](repeating: 0, count: 32)
        guard crypto_scalarmult_ristretto255(&out, s.bytes, bytes) == 0 else { throw AegisError.crypto("identity result") }
        return Element(bytes: out)
    }

    func plus(_ other: Element) throws -> Element {
        var out = [UInt8](repeating: 0, count: 32)
        guard crypto_core_ristretto255_add(&out, bytes, other.bytes) == 0 else { throw AegisError.crypto("invalid addition") }
        return Element(bytes: out)
    }
}
