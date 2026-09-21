// Package possession is proof of possession — CAN THEY SIGN, RIGHT NOW, FOR THIS CHANNEL?
//
// The challenger picks a nonce (fresh entropy, ≥ 16 bytes — its own, never this
// package's) and a binding (something only this channel has: a session key, a TLS
// exporter, the server's identity — the transport's, never this package's). The prover
// signs a fixed layout of both in the protocol's domain; the challenger verifies with
// the prover's public key.
//
// THE BINDING IS WHAT MAKES THIS A PROOF. A signed nonce alone is relayable: an attacker
// facing the server as the victim forwards the server's nonce to the victim under some
// pretext, gets it signed, and presents the signature. Bound to the channel, the
// signature is worthless anywhere else. So an empty binding is refused outright — the
// thing it would produce looks like a proof and is not one.
//
// The signed bytes are SchemeTag ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖
// binding, signed with crypto.SignInDomain in the caller's domain. The tag keeps a
// possession message and an envelope payload in the same domain from ever being the
// same bytes.
package possession

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
)

// SchemeTag is the first byte of every possession message. Distinct from
// envelope.SchemeTag.
const SchemeTag byte = 0x01

// MinNonceSize is the shortest nonce accepted, in bytes. Below this a proof is
// guessable, so it is refused rather than weakened.
const MinNonceSize = 16

// MaxFieldSize is the longest nonce or binding, in bytes — the u16 length prefix's bound.
const MaxFieldSize = 0xffff

// Prove proves possession of the key behind seed to a challenger who supplied nonce and
// binding, in domain. It errors on an invalid domain (see crypto.SignInDomain), a nonce
// shorter than MinNonceSize, an empty binding, either field over MaxFieldSize, or a seed
// of the wrong size — an error rather than the floor's panic, because in the sdk a seed
// comes from custody (a file, a store), not from code (ADR 0004, dated note 2026-09-10).
func Prove(seed []byte, domain string, nonce, binding []byte) ([]byte, error) {
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("possession: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	message, err := MessageBytes(nonce, binding)
	if err != nil {
		return nil, err
	}
	return crypto.SignInDomain(seed, domain, message)
}

// Verify reports whether signature was made by the key behind pubkey over this nonce and
// binding in domain. Total: every shape failure — bad domain, short nonce, empty binding,
// wrong-sized key or signature — is false.
func Verify(pubkey []byte, domain string, nonce, binding, signature []byte) bool {
	message, err := MessageBytes(nonce, binding)
	if err != nil {
		return false
	}
	return crypto.VerifyInDomain(pubkey, domain, message, signature)
}

// MessageBytes is the pinned layout of what gets signed. Exported so a consumer can pin
// it too.
func MessageBytes(nonce, binding []byte) ([]byte, error) {
	switch {
	case len(nonce) < MinNonceSize:
		return nil, fmt.Errorf("possession: nonce is %d bytes, min %d", len(nonce), MinNonceSize)
	case len(nonce) > MaxFieldSize:
		return nil, fmt.Errorf("possession: nonce is %d bytes, max %d", len(nonce), MaxFieldSize)
	case len(binding) == 0:
		return nil, errors.New("possession: binding is empty — an unbound proof is not a proof")
	case len(binding) > MaxFieldSize:
		return nil, fmt.Errorf("possession: binding is %d bytes, max %d", len(binding), MaxFieldSize)
	}
	out := make([]byte, 0, 1+2+len(nonce)+2+len(binding))
	out = append(out, SchemeTag)
	out = binary.BigEndian.AppendUint16(out, uint16(len(nonce)))
	out = append(out, nonce...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(binding)))
	out = append(out, binding...)
	return out, nil
}
