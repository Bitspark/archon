// Unit tests for what the oracle cannot express. Its protocol has two outcomes per case — ok or
// error — so argument SHAPE failures (a 31-byte seed, a 256-byte domain) and the byte-versus-
// character count of a domain have nowhere to go there. Correctness of the signatures
// themselves is the oracle's job, through conformance/harness.mjs.
import ArchonCore
import Testing

private let seed = [UInt8](0..<32)

@Test func theLoadedLibrariesMeetArchonsFloors() {
    // If this fails, every other test fails too — by design, since a core that cannot enforce
    // the profile refuses everything. This one says why.
    #expect(Crypto.librariesMeetFloors)
}

@Test func wrongSizedInputsAreRefusedNotTruncated() {
    #expect(Crypto.publicKeyFromSeed([UInt8](repeating: 1, count: 31)) == nil)
    #expect(Crypto.publicKeyFromSeed([UInt8](repeating: 1, count: 33)) == nil)
    #expect(Crypto.sign(seed: [], message: [1]) == nil)
    let pub = Crypto.publicKeyFromSeed(seed)!
    let sig = Crypto.sign(seed: seed, message: [1])!
    #expect(!Crypto.verify(publicKey: Array(pub.dropLast()), message: [1], signature: sig))
    #expect(!Crypto.verify(publicKey: pub, message: [1], signature: Array(sig.dropLast())))
}

@Test func anEmptyMessageSignsAndVerifies() {
    // Both host bindings may hand the shim a NULL pointer for an empty array.
    let pub = Crypto.publicKeyFromSeed(seed)!
    let sig = Crypto.sign(seed: seed, message: [])!
    #expect(Crypto.verify(publicKey: pub, message: [], signature: sig))
    let dsig = Crypto.signInDomain(seed: seed, domain: "archon/test/v1", message: [])!
    #expect(Crypto.verifyInDomain(publicKey: pub, domain: "archon/test/v1", message: [], signature: dsig))
}

@Test func theDomainIsBoundedInBytesNotCharacters() {
    #expect(Crypto.signInDomain(seed: seed, domain: "", message: [1]) == nil)
    #expect(Crypto.signInDomain(seed: seed, domain: String(repeating: "a", count: 255), message: [1]) != nil)
    #expect(Crypto.signInDomain(seed: seed, domain: String(repeating: "a", count: 256), message: [1]) == nil)
    // "é" is two bytes of UTF-8: 128 of them are 128 characters but 256 bytes — over the bound.
    #expect(Crypto.signInDomain(seed: seed, domain: String(repeating: "é", count: 128), message: [1]) == nil)
    #expect(Crypto.signInDomain(seed: seed, domain: String(repeating: "é", count: 127), message: [1]) != nil)
}

@Test func domainSeparationHoldsInEveryDirection() {
    let pub = Crypto.publicKeyFromSeed(seed)!
    let message: [UInt8] = Array("hello".utf8)
    let domainSig = Crypto.signInDomain(seed: seed, domain: "archon/test/v1", message: message)!
    #expect(Crypto.verifyInDomain(publicKey: pub, domain: "archon/test/v1", message: message, signature: domainSig))
    #expect(!Crypto.verifyInDomain(publicKey: pub, domain: "archon/test/v2", message: message, signature: domainSig))
    #expect(!Crypto.verify(publicKey: pub, message: message, signature: domainSig))
    let rawSig = Crypto.sign(seed: seed, message: message)!
    #expect(!Crypto.verifyInDomain(publicKey: pub, domain: "archon/test/v1", message: message, signature: rawSig))
}

@Test func keyTextRoundTripsAndIsStrictAboutItsPrefix() {
    let pub = Crypto.publicKeyFromSeed(seed)!
    let text = KeyText.encodeKey(pub)
    #expect(text.hasPrefix("ed25519:"))
    #expect(KeyText.decodeKey(text) == pub)
    #expect(KeyText.decodeKey(text.uppercased()) == nil)  // ED25519: is not archon's spelling
    #expect(KeyText.decodeKey("ed25519:" + HexBytes.toHex(pub).uppercased()) == pub)
}

@Test func base64PaddingOnlyAtTheEnd() {
    // The Go reference's rules, which the oracle's keycodec cases do not reach.
    let pem = KeyCodec.pubkeyToSPKIPEM(Crypto.publicKeyFromSeed(seed)!)!
    #expect(KeyCodec.spkiPEMToPubkey(pem) != nil)
    // Padding in the FIRST quad rather than the last. Replacing the body's final character would
    // prove nothing: a 44-byte SPKI already ends in "=", so the "corrupted" PEM would be the
    // original and the test would pass without exercising anything.
    let body = Array(pem.split(separator: "\n")[1])
    var corrupted = body
    corrupted[2] = "="
    let broken = pem.replacing(String(body), with: String(corrupted))
    #expect(broken != pem)
    #expect(KeyCodec.spkiPEMToPubkey(broken) == nil)
}
