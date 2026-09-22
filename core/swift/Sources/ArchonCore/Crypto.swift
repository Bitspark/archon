import CArchonCrypto

/// Ed25519 key derivation, signing and verification, raw and domain-separated.
///
/// Domain separation is Ed25519ph with the domain as the RFC 8032 §5.1 context string. The
/// prefix enters BOTH the nonce hash and the challenge hash, so it cannot be layered over a pure
/// `sign(message)` — which is why this core binds OpenSSL rather than CryptoKit or swift-crypto,
/// both of which ship pure Ed25519 only. (CryptoKit also randomises its signatures, so it could
/// not produce archon's vectors even if it took a context.)
///
/// Verification enforces ADR 0008 before the equation runs: the public key and R must each be
/// canonical encodings of points of order exactly L, and S must be below L. That is why
/// libsodium is linked too — OpenSSL validates no points for Ed25519.
///
/// Every function takes and returns plain byte arrays and reports refusal with `nil` or
/// `false`, never by throwing: the oracle's protocol has two outcomes, and so does this API.
public enum Crypto {
    public static let seedSize = Int(ARCHON_SEED_SIZE)
    public static let publicKeySize = Int(ARCHON_PUBLIC_KEY_SIZE)
    public static let signatureSize = Int(ARCHON_SIGNATURE_SIZE)
    /// A domain is 1...255 BYTES of UTF-8. Counted in bytes, as every core counts it: a
    /// character-counting core would accept 255-character domains the others refuse.
    public static let maxDomainSize = Int(ARCHON_MAX_DOMAIN_SIZE)

    public static func publicKeyFromSeed(_ seed: [UInt8]) -> [UInt8]? {
        guard seed.count == seedSize else { return nil }
        var out = [UInt8](repeating: 0, count: publicKeySize)
        let ok = seed.withUnsafeBufferPointer { s in
            out.withUnsafeMutableBufferPointer { o in
                archon_public_key_from_seed(s.baseAddress, o.baseAddress)
            }
        }
        return ok == 1 ? out : nil
    }

    public static func sign(seed: [UInt8], message: [UInt8]) -> [UInt8]? {
        guard seed.count == seedSize else { return nil }
        var out = [UInt8](repeating: 0, count: signatureSize)
        let ok = seed.withUnsafeBufferPointer { s in
            message.withUnsafeBufferPointer { m in
                out.withUnsafeMutableBufferPointer { o in
                    archon_sign(s.baseAddress, m.baseAddress, m.count, o.baseAddress)
                }
            }
        }
        return ok == 1 ? out : nil
    }

    public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == publicKeySize, signature.count == signatureSize else { return false }
        return publicKey.withUnsafeBufferPointer { p in
            message.withUnsafeBufferPointer { m in
                signature.withUnsafeBufferPointer { g in
                    archon_verify(p.baseAddress, m.baseAddress, m.count, g.baseAddress) == 1
                }
            }
        }
    }

    public static func signInDomain(seed: [UInt8], domain: String, message: [UInt8]) -> [UInt8]? {
        let context = Array(domain.utf8)
        guard seed.count == seedSize, domainOK(context) else { return nil }
        var out = [UInt8](repeating: 0, count: signatureSize)
        let ok = seed.withUnsafeBufferPointer { s in
            context.withUnsafeBufferPointer { d in
                message.withUnsafeBufferPointer { m in
                    out.withUnsafeMutableBufferPointer { o in
                        archon_sign_in_domain(s.baseAddress, d.baseAddress, d.count,
                                              m.baseAddress, m.count, o.baseAddress)
                    }
                }
            }
        }
        return ok == 1 ? out : nil
    }

    public static func verifyInDomain(
        publicKey: [UInt8], domain: String, message: [UInt8], signature: [UInt8]
    ) -> Bool {
        let context = Array(domain.utf8)
        guard publicKey.count == publicKeySize, signature.count == signatureSize,
              domainOK(context) else { return false }
        return publicKey.withUnsafeBufferPointer { p in
            context.withUnsafeBufferPointer { d in
                message.withUnsafeBufferPointer { m in
                    signature.withUnsafeBufferPointer { g in
                        archon_verify_in_domain(p.baseAddress, d.baseAddress, d.count,
                                                m.baseAddress, m.count, g.baseAddress) == 1
                    }
                }
            }
        }
    }

    /// Whether the OpenSSL and libsodium this process LOADED meet archon's floors. When they do
    /// not, every function above refuses: signing nothing and accepting nothing is the only
    /// safe behaviour for a core that cannot enforce its own profile.
    public static var librariesMeetFloors: Bool { archon_libraries_ok() == 1 }

    private static func domainOK(_ context: [UInt8]) -> Bool {
        !context.isEmpty && context.count <= maxDomainSize
    }
}
