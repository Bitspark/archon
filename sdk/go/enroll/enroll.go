// Package enroll is key enrollment — THIS NEW KEY BELONGS TO THIS ACCOUNT (ADR 0010 §7;
// docs/request.md §6, PROVISIONAL until ADR 0010 §8's gate is met).
//
// Login has a person approve a browser key. Enrollment is a different statement: a NEW key
// proves its own possession, while a separate authority — a session, or a bootstrap credential
// — says whose key it becomes. That authority lives in the service's pending transaction
// record, never in this proof: the service creates the record only after validating the
// authority, and the verifier rebuilds the binding from that record and its configured
// audience. A completion request names the transaction and carries the proof, nothing more.
//
// The proof is the possession scheme with the server's fresh nonce, in Domain, over
//
//	version ‖ u16be(len purpose) ‖ purpose ‖ u16be(len audience) ‖ audience
//	        ‖ u16be(len transaction) ‖ transaction ‖ new_key[32] ‖ intent_digest[32]
//
// The intent digest is the service's SHA-256 of its immutable enrollment intent (the account
// reference, the purpose, product-defined restrictions); archon binds the 32 bytes and never
// reads what they digest.
//
// What enrollment shows: an account and a key are associated. Not that the key is
// non-exportable, lives on one device, or is used by one process.
package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/possession"
	"github.com/Bitspark/archon/sdk/go/signer"
)

// Domain is the RFC 8032 context every enrollment proof is made in.
const Domain = "archon-enroll/1"

// Version is the first byte of every enrollment binding.
const Version byte = 0x01

// MaxPurposeSize and MaxTransactionSize bound the two short fields.
const (
	MaxPurposeSize     = 255
	MaxTransactionSize = 255
)

// DigestSize is the intent digest's length: a SHA-256.
const DigestSize = 32

// Request is a pending enrollment as the service recorded it.
type Request struct {
	Nonce        []byte // the server's fresh entropy, at least possession.MinNonceSize bytes
	Transaction  []byte // the pending transaction's id, 1..=MaxTransactionSize bytes, opaque
	Purpose      string // "add-key", "rotate", "recover", …: 1..=MaxPurposeSize bytes of UTF-8, no control characters
	NewKey       []byte // the public key being enrolled, exactly crypto.PublicKeySize bytes
	IntentDigest []byte // SHA-256 of the service's immutable intent bytes, exactly DigestSize bytes
}

// Binding is the bytes an enrollment proof is bound to, for req at audience. It errors on a
// purpose that is empty, over MaxPurposeSize, not UTF-8 or carrying a control character
// (U+0000–U+001F, U+007F); an audience that is empty, not UTF-8 or carrying a control
// character; a transaction id that is empty or over MaxTransactionSize; a new key or intent
// digest of the wrong size; or a binding that would not fit the possession scheme's u16 field.
func Binding(audience string, req *Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("enroll: nil request")
	}
	if len(req.Purpose) > MaxPurposeSize {
		return nil, fmt.Errorf("enroll: purpose is %d bytes, want 1..=%d", len(req.Purpose), MaxPurposeSize)
	}
	if err := checkText("purpose", req.Purpose); err != nil {
		return nil, err
	}
	if err := checkText("audience", audience); err != nil {
		return nil, err
	}
	if len(req.Transaction) == 0 || len(req.Transaction) > MaxTransactionSize {
		return nil, fmt.Errorf("enroll: transaction is %d bytes, want 1..=%d", len(req.Transaction), MaxTransactionSize)
	}
	if len(req.NewKey) != crypto.PublicKeySize {
		return nil, fmt.Errorf("enroll: new key is %d bytes, want %d", len(req.NewKey), crypto.PublicKeySize)
	}
	if len(req.IntentDigest) != DigestSize {
		return nil, fmt.Errorf("enroll: intent digest is %d bytes, want %d", len(req.IntentDigest), DigestSize)
	}
	var b bytes.Buffer
	b.WriteByte(Version)
	putField(&b, []byte(req.Purpose))
	putField(&b, []byte(audience))
	putField(&b, req.Transaction)
	b.Write(req.NewKey)
	b.Write(req.IntentDigest)
	if b.Len() > possession.MaxFieldSize {
		return nil, fmt.Errorf("enroll: binding is %d bytes, over the possession scheme's %d", b.Len(), possession.MaxFieldSize)
	}
	return b.Bytes(), nil
}

// Prove makes the enrollment proof: possession by the key behind seed — which must be the
// request's NewKey — in Domain, over req.Nonce and Binding(audience, req). A seed whose public
// key is not NewKey is an error: only the key being enrolled can prove it holds itself.
func Prove(seed []byte, audience string, req *Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("enroll: nil request")
	}
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("enroll: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	if !bytes.Equal(crypto.PublicKeyFromSeed(seed), req.NewKey) {
		return nil, errors.New("enroll: seed is not the new key the request names")
	}
	binding, err := Binding(audience, req)
	if err != nil {
		return nil, err
	}
	return possession.Prove(seed, Domain, req.Nonce, binding)
}

// Verify reports whether signature is the enrollment proof by req.NewKey for req at audience.
// Total: every shape failure is false.
func Verify(audience string, req *Request, signature []byte) bool {
	if req == nil {
		return false
	}
	binding, err := Binding(audience, req)
	if err != nil {
		return false
	}
	return possession.Verify(req.NewKey, Domain, req.Nonce, binding, signature)
}

// Prepare is the signing request the enrollment proof needs (ADR 0009 §4). Pure. The expected
// key is the request's NewKey, so only that key's signer can complete it — Prove's refusal of
// any other seed, carried into the request itself. Complete it with possession.Complete.
func Prepare(audience string, req *Request) (signer.Request, error) {
	if req == nil {
		return signer.Request{}, errors.New("enroll: nil request")
	}
	binding, err := Binding(audience, req)
	if err != nil {
		return signer.Request{}, err
	}
	return possession.Prepare(req.NewKey, Domain, req.Nonce, binding)
}

// ProveWith is Prove through a signer instead of a seed. A signer for any other key is refused.
func ProveWith(ctx context.Context, s signer.Signer, audience string, req *Request) ([]byte, error) {
	r, err := Prepare(audience, req)
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignWith(ctx, s, r)
	if err != nil {
		return nil, err
	}
	return possession.Complete(r, signature)
}

func checkText(what, s string) error {
	if len(s) == 0 || len(s) > possession.MaxFieldSize {
		return fmt.Errorf("enroll: %s is %d bytes, want 1..=%d", what, len(s), possession.MaxFieldSize)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("enroll: %s is not valid UTF-8", what)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("enroll: %s carries a control character U+%04X", what, r)
		}
	}
	return nil
}

// putField writes u16be(len field) ‖ field. Callers have bounded len(field).
func putField(b *bytes.Buffer, field []byte) {
	b.WriteByte(byte(len(field) >> 8))
	b.WriteByte(byte(len(field)))
	b.Write(field)
}
