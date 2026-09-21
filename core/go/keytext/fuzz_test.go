package keytext

// Native-fuzz battery for the key-text decode surface (issue #90). `go test ./...`
// runs each FuzzXxx against its seed corpus. DecodeKey is documented to NEVER panic on
// arbitrary text — these funcs assert exactly that, plus encode→decode round-trip on
// the valid 32-byte domain. Seeds cover adversarial inputs (no prefix, odd-length hex,
// non-hex chars, wrong decoded length).

import (
	"bytes"
	"testing"
)

// FuzzDecodeKeyTotal: DecodeKey on an ARBITRARY string returns (bytes, err) and never
// panics — odd length, non-hex, missing prefix, and wrong length are all clean errors.
func FuzzDecodeKeyTotal(f *testing.F) {
	f.Add("")
	f.Add("ed25519:")
	f.Add("ed25519:11")                           // valid hex, wrong decoded length
	f.Add("ed25519:zz")                           // non-hex body
	f.Add("ed25519:111")                          // odd-length body
	f.Add("nope:" + "11")                         // missing prefix
	f.Add("ed25519:" + string(make([]byte, 200))) // long NUL body
	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic; the result is whatever DecodeKey returns.
		_, _ = DecodeKey(s)
	})
}

// FuzzEncodeDecodeRoundTrip: a 32-byte key round-trips through EncodeKey / DecodeKey.
// (The fuzzer supplies arbitrary bytes; we use exactly the first 32, padding if short,
// so every input drives a valid round-trip.)
func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x11}, 32))
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		key := make([]byte, 32)
		copy(key, b) // first 32 bytes (or zero-padded) — always a valid 32-byte key
		text := EncodeKey(key)
		got, err := DecodeKey(text)
		if err != nil {
			t.Fatalf("EncodeKey/DecodeKey round-trip failed: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatalf("round-trip mismatch: %x -> %x", key, got)
		}
	})
}
