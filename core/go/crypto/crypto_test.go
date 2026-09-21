package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestDomainSeparatesAndRawNeverCrosses(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, SeedSize)
	pk := PublicKeyFromSeed(seed)
	msg := []byte("the law laid down")
	sigA, err := SignInDomain(seed, "archon/test/a", msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInDomain(pk, "archon/test/a", msg, sigA) {
		t.Error("in-domain verify failed")
	}
	if VerifyInDomain(pk, "archon/test/b", msg, sigA) {
		t.Error("verified in another domain")
	}
	if Verify(pk, msg, sigA) {
		t.Error("domain signature verified raw")
	}
	if VerifyInDomain(pk, "archon/test/a", msg, Sign(seed, msg)) {
		t.Error("raw signature verified in-domain")
	}
	if VerifyInDomain(pk, "archon/test/a", []byte("other"), sigA) {
		t.Error("verified over another message")
	}
	if VerifyInDomain(make([]byte, PublicKeySize), "archon/test/a", msg, sigA) {
		t.Error("verified under the zero key")
	}
}

func TestDomainBounds(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, SeedSize)
	pk := PublicKeyFromSeed(seed)
	if _, err := SignInDomain(seed, "", []byte("m")); err == nil {
		t.Error("signed in the empty domain")
	}
	if VerifyInDomain(pk, "", []byte("m"), make([]byte, SignatureSize)) {
		t.Error("verified in the empty domain")
	}
	max := strings.Repeat("d", MaxDomainSize)
	sig, err := SignInDomain(seed, max, []byte("m"))
	if err != nil || !VerifyInDomain(pk, max, []byte("m"), sig) {
		t.Errorf("max-length domain: %v", err)
	}
	over := max + "d"
	if _, err := SignInDomain(seed, over, []byte("m")); err == nil {
		t.Error("signed in an over-long domain")
	}
	if VerifyInDomain(pk, over, []byte("m"), sig) {
		t.Error("verified in an over-long domain")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, SeedSize)
	pk := PublicKeyFromSeed(seed)
	msg := []byte("the law laid down")
	sig := Sign(seed, msg)

	if !Verify(pk, msg, sig) {
		t.Fatal("a freshly produced signature does not verify")
	}
	if Verify(pk, []byte("other"), sig) {
		t.Fatal("signature verified over the wrong message")
	}

	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if Verify(pk, msg, bad) {
		t.Fatal("a bit-flipped signature verified")
	}
	if Verify(make([]byte, PublicKeySize), msg, sig) {
		t.Fatal("signature verified under the wrong key")
	}
}

// The whole point of the wrapper: the standard library panics on a wrong-sized public
// key, and archon's contract is that every shape failure is just `false`.
func TestVerifyRejectsWrongSizesWithoutPanicking(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, SeedSize)
	pk := PublicKeyFromSeed(seed)
	msg := []byte("m")
	sig := Sign(seed, msg)

	for _, tc := range []struct {
		name string
		pub  []byte
		sig  []byte
	}{
		{"short pubkey", pk[:31], sig},
		{"long pubkey", append(append([]byte(nil), pk...), 0x00), sig},
		{"empty pubkey", []byte{}, sig},
		{"short sig", pk, sig[:63]},
		{"long sig", pk, append(append([]byte(nil), sig...), 0x00)},
		{"empty sig", pk, []byte{}},
	} {
		if Verify(tc.pub, msg, tc.sig) {
			t.Fatalf("%s: verified when it must not", tc.name)
		}
	}
}

// Derivation lives here, not in keytext: rs and ts both put public_key_from_seed /
// getPublicKey in crypto, and go used to export it from BOTH crypto and the package
// now called keytext — two implementations of one function, only one of which
// carried its own length guard. These tests came across with it.
func TestPublicKeyFromSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, SeedSize)
	a := PublicKeyFromSeed(seed)
	b := PublicKeyFromSeed(seed)
	if !bytes.Equal(a, b) {
		t.Fatalf("derivation not deterministic: %x vs %x", a, b)
	}
	if len(a) != PublicKeySize {
		t.Fatalf("public key is %d bytes, expected %d", len(a), PublicKeySize)
	}
}

func TestPublicKeyFromSeedPanicsOnBadLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for a 31-byte seed")
		}
	}()
	PublicKeyFromSeed(bytes.Repeat([]byte{0x00}, SeedSize-1))
}
