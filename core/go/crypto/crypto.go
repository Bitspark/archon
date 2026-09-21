// Package crypto is archon's Ed25519 sign/verify over canonical bytes (RFC 8032).
//
// It wraps the standard library's crypto/ed25519. Verify collapses every shape failure
// (wrong-sized key or signature, malformed point) into a single false, so callers can
// treat all "bad signature" cases uniformly — and, crucially, so the length guard is
// written ONCE. The standard library's ed25519.Verify PANICS on a wrong-sized public
// key, which makes every unguarded call site a latent crash; thesmos repeats that guard
// by hand at each authority site. One guarded verify per language, byte-identical across
// the three cores and pinned by the `signature_verify` conformance family, is precisely
// the kind of thing archon exists to own.
//
// These are the generic primitives callers sign and check over — no authority vocabulary
// of any kind. What a signature MEANS is thesmos's; that one is well-formed is archon's.
//
// Two ways to sign, deliberately:
//
//   - Sign / Verify — RAW: pure Ed25519 over exactly the bytes given. The caller owns
//     separation; two protocols signing overlapping byte layouts with one key can replay
//     each other's signatures. This is what every consumer's on-disk signatures are
//     today, and it stays.
//   - SignInDomain / VerifyInDomain — DOMAIN-SEPARATED: Ed25519ph with a context string
//     (RFC 8032 §5.1), the domain, mixed into the hash. A signature made in one domain
//     verifies in no other and never as a raw signature, and a raw signature verifies in
//     no domain — for every key the profile admits (ADR 0008), by the construction and
//     not by any encoding convention. One key, many protocols, no cross-talk: the default
//     for any protocol that has no bytes on disk yet. The domain is the caller's
//     (<repo>/<purpose>/v<n> by convention); archon neither knows nor registers domains.
//
// Both verifies apply the verification profile of ADR 0008 before the equation (see
// profile.go): the public key and the signature's R must be canonical encodings of
// points of order exactly L, and S must be in range. That is what makes the accepted set
// the same in every core regardless of which equation its library uses. A domain is a
// UTF-8 string of 1..=255 bytes; a Go string that is not valid UTF-8 is refused, not
// signed as its bytes, so that the same domain means the same context in every language.
//
// NOTE: this package has no thesmos ancestor. rs and ts carried a guarded verify; go did
// not. It is written here to make the three cores symmetric.
package crypto

import (
	stdcrypto "crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"unicode/utf8"
)

// PublicKeySize is the length of an Ed25519 public key, in bytes.
const PublicKeySize = ed25519.PublicKeySize

// SignatureSize is the length of an Ed25519 signature, in bytes.
const SignatureSize = ed25519.SignatureSize

// SeedSize is the length of an Ed25519 seed (private key), in bytes.
const SeedSize = ed25519.SeedSize

// MaxDomainSize is the longest domain (RFC 8032 context) a signature can be made in.
const MaxDomainSize = 255

// PublicKeyFromSeed derives the Ed25519 public key for a 32-byte seed. It panics if
// len(seed) != 32 (a seed of the wrong size is a programming error, not a runtime
// condition to handle) — the guard is archon's own, not the standard library's.
func PublicKeyFromSeed(seed []byte) []byte {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("crypto: seed must be %d bytes, got %d", SeedSize, len(seed)))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return append([]byte(nil), pub...)
}

// Sign signs message with the key derived from seed, returning the 64-byte signature
// (the message is whatever canonical byte sequence the caller defines). It panics if
// len(seed) != 32.
func Sign(seed, message []byte) []byte {
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)
}

// Verify reports whether signature is a valid Ed25519 signature over message under the
// public key pubkey, within the verification profile (ADR 0008). It returns false on any
// shape failure — including a key or an R outside the profile — rather than panicking.
func Verify(pubkey, message, signature []byte) bool {
	if !signatureInProfile(pubkey, signature) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubkey), message, signature)
}

// SignInDomain signs message with the key derived from seed IN domain (Ed25519ph with
// the domain as the RFC 8032 context). It errors — never silently signs raw — when the
// domain is empty or longer than MaxDomainSize bytes: an empty domain is "sign in no
// domain", which is exactly what this function exists to make impossible. It panics if
// len(seed) != 32, like Sign.
func SignInDomain(seed []byte, domain string, message []byte) ([]byte, error) {
	if err := checkDomain(domain); err != nil {
		return nil, err
	}
	h := sha512.Sum512(message)
	return ed25519.NewKeyFromSeed(seed).Sign(nil, h[:], &ed25519.Options{Hash: stdcrypto.SHA512, Context: domain})
}

// VerifyInDomain reports whether signature is a valid signature over message IN domain
// under pubkey. Total, like Verify: every shape failure — including an empty or
// over-long domain — is false. A raw signature over the same message is false here; a
// signature from any other domain is false here.
func VerifyInDomain(pubkey []byte, domain string, message, signature []byte) bool {
	if checkDomain(domain) != nil || !signatureInProfile(pubkey, signature) {
		return false
	}
	h := sha512.Sum512(message)
	opts := &ed25519.Options{Hash: stdcrypto.SHA512, Context: domain}
	return ed25519.VerifyWithOptions(ed25519.PublicKey(pubkey), h[:], signature, opts) == nil
}

// checkDomain: a domain is 1..=255 bytes of valid UTF-8 — the RFC 8032 context bound,
// with the empty context excluded on purpose (see SignInDomain), and with invalid UTF-8
// refused: a Go string can carry arbitrary bytes, but a domain is text, and the other
// cores cannot even represent the bytes this one would otherwise sign under.
func checkDomain(domain string) error {
	switch n := len(domain); {
	case n == 0:
		return errors.New("crypto: domain is empty")
	case n > MaxDomainSize:
		return fmt.Errorf("crypto: domain is %d bytes, max %d", n, MaxDomainSize)
	case !utf8.ValidString(domain):
		return errors.New("crypto: domain is not valid UTF-8")
	}
	return nil
}
