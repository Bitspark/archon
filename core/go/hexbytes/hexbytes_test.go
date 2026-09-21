package hexbytes

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoundTripsAndLowercases(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	text := ToHex(seed)
	if text != strings.Repeat("ab", 32) {
		t.Fatalf("ToHex = %q", text)
	}
	for _, in := range []string{text, strings.ToUpper(text)} {
		got, err := SeedFromHex(in)
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("SeedFromHex(%q) = %x, %v", in, got, err)
		}
	}
	sig := bytes.Repeat([]byte{0x5a}, 64)
	if got, err := SignatureFromHex(ToHex(sig)); err != nil || !bytes.Equal(got, sig) {
		t.Fatalf("SignatureFromHex round trip: %x, %v", got, err)
	}
}

func TestFailsClosedOnSizeAndAlphabet(t *testing.T) {
	ab31 := strings.Repeat("ab", 31)
	bad := []string{
		ab31,                     // short
		strings.Repeat("ab", 33), // long
		ab31 + "a",               // odd
		ab31 + "zz",              // non-hex
		"0x" + ab31,              // 0x prefix
		"",                       // empty
	}
	for _, in := range bad {
		if _, err := SeedFromHex(in); err == nil {
			t.Errorf("SeedFromHex(%q) accepted", in)
		}
	}
	if _, err := PubkeyFromHex(""); err == nil {
		t.Error("PubkeyFromHex(\"\") accepted")
	}
	// a key is not a signature.
	if _, err := SignatureFromHex(strings.Repeat("ab", 32)); err == nil {
		t.Error("SignatureFromHex accepted 32 bytes")
	}
}
