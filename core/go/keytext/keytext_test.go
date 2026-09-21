package keytext

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeFixedForm(t *testing.T) {
	got := EncodeKey(bytes.Repeat([]byte{0x11}, 32))
	want := "ed25519:" + strings.Repeat("11", 32)
	if got != want {
		t.Fatalf("encode mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	text := EncodeKey(key)
	back, err := DecodeKey(text)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(back, key) {
		t.Fatalf("round-trip mismatch:\n got %x\nwant %x", back, key)
	}
}

func TestDecodeAcceptsUppercaseHex(t *testing.T) {
	lower, errL := DecodeKey("ed25519:" + strings.Repeat("ab", 32))
	upper, errU := DecodeKey("ed25519:" + strings.Repeat("AB", 32))
	if errL != nil || errU != nil {
		t.Fatalf("decode errors: lower=%v upper=%v", errL, errU)
	}
	if !bytes.Equal(lower, upper) {
		t.Fatalf("uppercase/lowercase mismatch")
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing prefix": strings.Repeat("11", 32),
		"odd length":     "ed25519:111",
		"non-hex":        "ed25519:" + strings.Repeat("zz", 32),
		"too short":      "ed25519:" + strings.Repeat("11", 31),
		"too long":       "ed25519:" + strings.Repeat("11", 33),
	}
	for name, in := range cases {
		if _, err := DecodeKey(in); err == nil {
			t.Errorf("%s: expected an error for %q", name, in)
		}
	}
}
