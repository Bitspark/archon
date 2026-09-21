// Package keytext is archon's canonical key spelling: the text form
// ed25519:<lowercase-hex> that the three cores agree on byte-for-byte, and nothing
// else. It adds no authority vocabulary — no root, no admission, no grants. Those
// are thesmos's.
//
// Key DERIVATION lives in the sibling crypto package, not here, so that each concern
// has exactly one home per lane and all three lanes agree on which home that is.
//
// This package was inherited from thesmos as core/go/keys, where derivation and key
// text shared a package because thesmos's go lane had no crypto package to put
// derivation in. archon has one, so the two were separated and the package renamed to
// keytext — which is what the rs and ts lanes have called it all along.
package keytext

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// ed25519Prefix is the v1 key-text scheme prefix; exactly one scheme exists today.
const ed25519Prefix = "ed25519:"

// publicKeyLen is the fixed length, in bytes, of an Ed25519 public key.
const publicKeyLen = ed25519.PublicKeySize

// EncodeKey renders public-key bytes as the canonical key text ed25519:<lowercase-hex>.
// The bytes are emitted verbatim as lowercase hex with the scheme prefix.
func EncodeKey(pubkey []byte) string {
	return ed25519Prefix + hex.EncodeToString(pubkey)
}

// DecodeKey parses canonical key text back to its raw public-key bytes. It strips the
// ed25519: prefix and hex-decodes the body, returning an error (never panicking) when
// the prefix is missing, the body is not even-length hex, or the decoded length is not
// 32 bytes.
func DecodeKey(text string) ([]byte, error) {
	body, ok := strings.CutPrefix(text, ed25519Prefix)
	if !ok {
		return nil, fmt.Errorf("keytext: missing %q prefix", ed25519Prefix)
	}
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("keytext: key body has an odd number of hex digits")
	}
	out, err := hex.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("keytext: non-hex character in key body: %w", err)
	}
	if len(out) != publicKeyLen {
		return nil, fmt.Errorf("keytext: decoded key is %d bytes, expected %d", len(out), publicKeyLen)
	}
	return out, nil
}
