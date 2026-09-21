package crypto

import (
	"bytes"

	"filippo.io/edwards25519"
)

// The verification profile (ADR 0008): before any equation is checked, the public key A
// and the signature's R must each be a CANONICAL encoding of a point of order exactly L —
// a non-identity element of the prime-order subgroup. Under that condition the cofactored
// and the uncofactored verification equations accept the same signatures, which is what
// lets four libraries with three different equations be one floor.
//
// The standard library's ed25519.Verify decodes non-canonical encodings, admits the
// identity and every small-order point as a key, and — because its equation is
// uncofactored — accepts a mixed-order key for one message in eight. None of that is a bug
// in Go; RFC 8032 leaves it open. archon closes it here, and this file is the one place
// core/go needs point arithmetic: filippo.io/edwards25519, the library the standard
// library's own implementation is maintained from, used for validation only. Nothing here
// touches a secret.

// lMinusOne is L − 1, the largest canonical scalar. [L]P is computed as [L − 1]P + P
// because a Scalar holds values mod L and cannot spell L itself.
var lMinusOne = func() *edwards25519.Scalar {
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian, minus one.
	b := []byte{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		panic("crypto: L-1 is not a canonical scalar: " + err.Error())
	}
	return s
}()

// isPrimeOrderPoint reports whether b is a canonical 32-byte encoding of a point of order
// exactly L. False for: not on the curve; a non-canonical spelling (y ≥ p, or x = 0 with
// the sign bit set — the point re-encodes to different bytes); the identity; any
// small-order point; any mixed-order point.
func isPrimeOrderPoint(b []byte) bool {
	if len(b) != PublicKeySize {
		return false
	}
	var P edwards25519.Point
	if _, err := P.SetBytes(b); err != nil {
		return false
	}
	if !bytes.Equal(P.Bytes(), b) {
		return false
	}
	identity := edwards25519.NewIdentityPoint()
	if P.Equal(identity) == 1 {
		return false
	}
	var Q edwards25519.Point
	Q.ScalarMult(lMinusOne, &P)
	Q.Add(&Q, &P)
	return Q.Equal(identity) == 1
}

// signatureInProfile reports whether pubkey and signature satisfy the profile's shape
// conditions: both are the right size, A and R are prime-order points. S's range
// (0 ≤ S < L) is enforced by the standard library's verify, which refuses a non-canonical
// scalar, so it is not repeated here.
func signatureInProfile(pubkey, signature []byte) bool {
	return len(pubkey) == PublicKeySize && len(signature) == SignatureSize &&
		isPrimeOrderPoint(pubkey) && isPrimeOrderPoint(signature[:32])
}
