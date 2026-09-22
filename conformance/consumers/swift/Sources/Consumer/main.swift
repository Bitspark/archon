// What an outside consumer of archon's Swift package must be able to do.
//
// This builds against archon as a DEPENDENCY, not as source. Passing the oracle proves the code;
// it says nothing about whether the package is right — a manifest that only builds from its own
// directory, a system library the consumer is not told to link, or a shim header that is not
// exported all pass conformance and fail here.
//
// Two claims, the same two every archon consumer asserts in every language:
//   1. domain separation holds, in every direction;
//   2. the ADR 0008 profile is enforced, on the pair that is load-bearing in EVERY language —
//      profile-mixed-order-A-k-divisible and profile-identity-R, oracle bytes verbatim. Every
//      implementation measured before 0008 accepted both, so nothing but archon's own check can
//      refuse them. For Swift that check is libsodium's; OpenSSL alone would accept both.
import ArchonCore

/// fatalError, not print-then-exit: print buffers stdout and a trap would discard the buffer,
/// losing the one line that says which claim failed. fatalError writes its message to stderr
/// before it traps.
func check(_ condition: Bool, _ what: String) {
    if !condition { fatalError(what) }
}

func bytes(_ hex: String) -> [UInt8] {
    let chars = Array(hex.utf8)
    return stride(from: 0, to: chars.count, by: 2).map {
        UInt8(String(decoding: chars[$0...$0 + 1], as: UTF8.self), radix: 16)!
    }
}

check(Crypto.librariesMeetFloors, "the loaded OpenSSL and libsodium must meet archon's floors")

let seed = [UInt8](0..<32)
let domain = "archon/test/v1"
let message = Array("hello".utf8)
let pub = Crypto.publicKeyFromSeed(seed)!

let signature = Crypto.signInDomain(seed: seed, domain: domain, message: message)!
check(Crypto.verifyInDomain(publicKey: pub, domain: domain, message: message, signature: signature),
      "a domain signature must verify in its own domain")
check(!Crypto.verifyInDomain(publicKey: pub, domain: "archon/test/v2", message: message, signature: signature),
      "a domain signature must not verify in another domain")
check(!Crypto.verify(publicKey: pub, message: message, signature: signature),
      "a domain signature must never verify as a raw signature")

let raw = Crypto.sign(seed: seed, message: message)!
check(Crypto.verify(publicKey: pub, message: message, signature: raw), "a raw signature must verify raw")
check(!Crypto.verifyInDomain(publicKey: pub, domain: domain, message: message, signature: raw),
      "a raw signature must not verify in any domain")

// ADR 0008 class 4: A = A_good + T8, order 8L, with k divisible by 8 so BOTH equations hold.
let mixedOrderA = bytes("05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4")
let mixedOrderMessage = bytes("6d697865642d6f72646572233133")
let mixedOrderSig = bytes("b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
                        + "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b")
check(!Crypto.verify(publicKey: mixedOrderA, message: mixedOrderMessage, signature: mixedOrderSig),
      "a mixed-order public key must be refused, though both equations hold")
check(!Crypto.verifyInDomain(publicKey: mixedOrderA, domain: domain, message: mixedOrderMessage,
                             signature: mixedOrderSig),
      "a mixed-order public key must be refused in a domain too")

// ADR 0008 class 5: R is the identity point and S = k·a, so the equation holds under every
// formulation. RFC 8032 pure verification accepts it; no honest signer produces it.
let honestA = bytes("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
let identityRSig = bytes("0100000000000000000000000000000000000000000000000000000000000000"
                       + "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07")
check(!Crypto.verify(publicKey: honestA, message: message, signature: identityRSig),
      "an identity R must be refused, though RFC 8032 pure verification accepts it")

let text = KeyText.encodeKey(pub)
check(KeyText.decodeKey(text) == pub, "the canonical key text must round trip")
check(KeyCodec.spkiPEMToPubkey(KeyCodec.pubkeyToSPKIPEM(pub)!) == pub, "SPKI PEM must round trip")

print("consumer ok: \(text)")
