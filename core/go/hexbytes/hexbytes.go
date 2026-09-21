// Package hexbytes is archon's typed, fail-closed hex spelling for the three fixed-size
// values the floor deals in: a 32-byte seed, a 32-byte public key, a 64-byte signature.
//
// Every consumer hand-wrote these — hexToBytes, seed32, seedFromHex — around its archon
// calls, ~30 definitions per lane, each one a place for a length bug. The value here is
// not hex (every language has hex) but the FIXED SIZE: a decoder that returns exactly
// 32 or 64 bytes or an error, never a slice the caller must re-check. Encoding is
// always lowercase; decoding accepts either case. No 0x prefix, no whitespace — a
// spelling is a spelling.
package hexbytes

import (
	"encoding/hex"
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
)

// ToHex renders bytes as lowercase hex, two digits per byte.
func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// SeedFromHex decodes the hex spelling of a 32-byte Ed25519 seed. It errors on odd
// length, any non-hex character, or a decoded length other than 32.
func SeedFromHex(text string) ([]byte, error) {
	return fixed(text, crypto.SeedSize, "seed")
}

// PubkeyFromHex decodes the hex spelling of a 32-byte Ed25519 public key. Same failure
// rules as SeedFromHex.
func PubkeyFromHex(text string) ([]byte, error) {
	return fixed(text, crypto.PublicKeySize, "public key")
}

// SignatureFromHex decodes the hex spelling of a 64-byte Ed25519 signature. Same
// failure rules as SeedFromHex.
func SignatureFromHex(text string) ([]byte, error) {
	return fixed(text, crypto.SignatureSize, "signature")
}

// fixed decodes hex into exactly n bytes or fails. The length is checked on the text
// before any byte is decoded, so a wrong-sized input never allocates.
func fixed(text string, n int, what string) ([]byte, error) {
	if len(text) != n*2 {
		return nil, fmt.Errorf("hexbytes: %s hex is %d characters, expected %d", what, len(text), n*2)
	}
	out, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("hexbytes: %s: %w", what, err)
	}
	return out, nil
}
