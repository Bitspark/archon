package login

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Bitspark/archon/sdk/go/possession"
)

// FingerprintDomain is the label the transaction fingerprint's digest is computed under
// (docs/login.md §5.3). It is not an RFC 8032 context: nothing is signed with it, and no login
// proof's bytes are ever a fingerprint's input or the other way round.
const FingerprintDomain = "archon-login-fingerprint/1"

// Fingerprint is the login's transaction fingerprint (docs/login.md §5.3), what a person
// compares before approving: the page that began the login computes it from its own K and the
// begin response, the CLI from the exact request it is about to sign, and the two agree only
// if every field the login proof binds — audience, K, id, scope, validity — and the nonce are
// the same on both sides. It is the first 16 bytes (128 bits) of
//
//	SHA-256( u16be(len domain) ‖ domain ‖ u16be(len nonce) ‖ nonce ‖ Binding(RoleLogin, audience, req) )
//
// with domain FingerprintDomain — an encoding of its own beside the proof's, pinned by
// vectors/login.json's login_fingerprint family. It errors on everything
// Binding(RoleLogin, …) errors on, and on a nonce shorter than possession.MinNonceSize or
// longer than the u16 prefix allows. Total: it never panics.
func Fingerprint(audience string, req *Request) ([16]byte, error) {
	var fp [16]byte
	binding, err := Binding(RoleLogin, audience, req)
	if err != nil {
		return fp, err
	}
	if len(req.Nonce) < possession.MinNonceSize || len(req.Nonce) > MaxFieldSize {
		return fp, fmt.Errorf("login: nonce is %d bytes, want %d..=%d", len(req.Nonce), possession.MinNonceSize, MaxFieldSize)
	}
	var b bytes.Buffer
	putField(&b, []byte(FingerprintDomain))
	putField(&b, req.Nonce)
	b.Write(binding)
	digest := sha256.Sum256(b.Bytes())
	copy(fp[:], digest[:16])
	return fp, nil
}

// FormatFingerprint is fp as a person reads and compares it (docs/login.md §5.3): its 32
// lowercase hex digits in eight groups of four, separated by single ASCII spaces —
// "7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f". The three lanes spell it identically, so the
// page's rendering and the CLI's can be compared character by character.
func FormatFingerprint(fp [16]byte) string {
	h := hex.EncodeToString(fp[:])
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}
