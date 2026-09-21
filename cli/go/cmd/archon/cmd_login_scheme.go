package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/login"
)

// THE SCHEME SEAM. This is the ONE place cmd_login.go reaches the login scheme, which is
// why wiring it was a single-file change when sdk/go/login landed (archon#16, PR #19).
//
// The scheme owns the binding layout, the role tags, the domain and the proof
// (docs/login.md §3.2). This lane owns none of them and must never recompute them: a
// binding written twice is a binding that drifts, and the drift would surface only as a
// proof that verifies in one lane and not another.
//
// What stays on THIS side of the seam is the wire-to-scheme conversion — hex and key text
// in, bytes out — plus the principal, which is a property of the seed rather than of the
// scheme.

// proveLogin returns the person's login proof over this request and their principal as
// canonical key text.
//
// The decodes below have all been validated already by validateLoginRequest, which runs
// BEFORE the person is shown anything. They are re-checked here rather than assumed
// because this function is reachable from any future caller, and a silent mis-decode would
// produce a proof bound to bytes nobody displayed.
func proveLogin(seed []byte, audience string, r *loginRequest) (proof []byte, principal string, err error) {
	principal = keytext.EncodeKey(crypto.PublicKeyFromSeed(seed))

	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil {
		return nil, principal, fmt.Errorf("login: nonce is not hex: %w", err)
	}
	browser, err := keytext.DecodeKey(r.Browser)
	if err != nil {
		return nil, principal, fmt.Errorf("login: browser key is not canonical key text: %w", err)
	}

	// THE ID IS HEX-DECODED, NOT HANDED OVER AS TEXT. docs/login.md §3.1 makes the id BYTES
	// carried as "hex in URLs and JSON"; the scheme binds the bytes. Passing []byte(r.ID)
	// would bind the ASCII of the hex string — 0x38 0x66 0x33 0x63 for "8f3c" instead of
	// 0x8f 0x3c — and the resulting proof verifies NOWHERE.
	//
	// It is worth being blunt about why that was wrong here for a while: a stub test that
	// builds its expected Request the same wrong way still passes, because both sides agree
	// with each other and neither agrees with the server. The test below therefore checks
	// against an INDEPENDENTLY hex-decoded id, and asserts the ASCII form does NOT verify.
	idBytes, err := hex.DecodeString(r.ID)
	if err != nil {
		return nil, principal, fmt.Errorf("login: id is not hex: %w", err)
	}
	proof, err = login.Prove(seed, audience, &login.Request{
		ID:       idBytes,
		Nonce:    nonce,
		Browser:  browser,
		Scope:    r.Scope,
		ValidFor: r.ValidFor,
	})
	if err != nil {
		return nil, principal, err
	}
	return proof, principal, nil
}
