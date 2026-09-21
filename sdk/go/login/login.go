// Package login is the archon login scheme — MAY THIS EPHEMERAL KEY ACT AS ME, HERE, FOR
// THIS, UNTIL THEN?
//
// A browser (any key-less client) holds an ephemeral key K and opens a request at a service;
// the person's CLI, holding P, proves to that service that P agrees to let K act there for a
// stated scope and validity. The proof is the possession scheme (sdk/go/possession) in the
// domain "archon-login/1", over the server's nonce and a binding that names everything the
// person approved: the audience the CLI talks to, K, the request, the scope entries and the
// validity — see docs/login.md §3.
//
// The AUDIENCE IS DERIVED, NEVER TRANSPORTED: the CLI takes it from the URL it was invoked
// with and the server from its own configuration (docs/login.md §2). This package takes it as
// an argument and binds it; it never reads it off a message. Everything this package refuses
// to source — the nonce, the id, K, clocks, the delegation's contents, custody, sockets — is
// an argument or another layer's (ADR 0004, ADR 0007).
//
// Two proofs share the layout and differ in a role byte: the login proof (0x01) is made by P;
// the collect proof (0x02) is made by K when the browser collects the answer, so a bystander
// who saw the request id cannot consume the login.
package login

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/possession"
)

// Domain is the RFC 8032 context every login-scheme proof is made in.
const Domain = "archon-login/1"

// RoleLogin is the binding's first byte for the person's proof (made by P).
const RoleLogin byte = 0x01

// RoleCollect is the binding's first byte for the browser's collect proof (made by K).
const RoleCollect byte = 0x02

// MaxFieldSize is the longest audience, id or scope entry, in bytes — the u16 length
// prefix's bound. It also bounds the scope entry count and the whole binding (which must fit
// the possession scheme's own u16 field).
const MaxFieldSize = 0xffff

// Request is a pending login as the server issued it and the CLI reads it back
// (docs/login.md §3.1). Nonce is validated by the possession scheme (≥ 16 bytes) at proof
// time; the other fields by Binding.
type Request struct {
	ID       []byte   // the server's, opaque, 1..=MaxFieldSize bytes
	Nonce    []byte   // the server's fresh entropy, one per request
	Browser  []byte   // K's public key, exactly crypto.PublicKeySize bytes
	Scope    []string // ordered; each 1..=MaxFieldSize bytes of UTF-8 with no control characters
	ValidFor uint32   // the delegation's requested lifetime in seconds, > 0
}

// Binding is the bytes both proofs are bound to, for role over audience and req
// (docs/login.md §3.2):
//
//	role ‖ u16be(len audience) ‖ audience ‖ browser[32] ‖ u16be(len id) ‖ id
//	     ‖ u16be(count scope) ‖ ( u16be(len entry) ‖ entry )* ‖ u32be(valid_for)
//
// It errors on an unknown role, an empty or oversized audience, an audience or scope entry
// carrying a control character (U+0000–U+001F, U+007F), a scope entry that is empty or not
// UTF-8, a browser key of the wrong size, an empty or oversized id, a zero validity, or a
// binding that would not fit the possession scheme's u16 field.
func Binding(role byte, audience string, req *Request) ([]byte, error) {
	if role != RoleLogin && role != RoleCollect {
		return nil, fmt.Errorf("login: unknown role 0x%02x", role)
	}
	if req == nil {
		return nil, errors.New("login: nil request")
	}
	if err := checkText("audience", audience); err != nil {
		return nil, err
	}
	if len(req.Browser) != crypto.PublicKeySize {
		return nil, fmt.Errorf("login: browser key is %d bytes, want %d", len(req.Browser), crypto.PublicKeySize)
	}
	if len(req.ID) == 0 || len(req.ID) > MaxFieldSize {
		return nil, fmt.Errorf("login: id is %d bytes, want 1..=%d", len(req.ID), MaxFieldSize)
	}
	if len(req.Scope) > MaxFieldSize {
		return nil, fmt.Errorf("login: %d scope entries, want at most %d", len(req.Scope), MaxFieldSize)
	}
	for i, entry := range req.Scope {
		if err := checkText(fmt.Sprintf("scope[%d]", i), entry); err != nil {
			return nil, err
		}
	}
	if req.ValidFor == 0 {
		return nil, errors.New("login: valid_for is 0")
	}

	var b bytes.Buffer
	b.WriteByte(role)
	putField(&b, []byte(audience))
	b.Write(req.Browser)
	putField(&b, req.ID)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(req.Scope)))
	b.Write(n[:])
	for _, entry := range req.Scope {
		putField(&b, []byte(entry))
	}
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], req.ValidFor)
	b.Write(v[:])
	if b.Len() > possession.MaxFieldSize {
		return nil, fmt.Errorf("login: binding is %d bytes, over the possession scheme's %d", b.Len(), possession.MaxFieldSize)
	}
	return b.Bytes(), nil
}

// Prove makes the person's login proof: possession by the key behind seed, in Domain, over
// req.Nonce and Binding(RoleLogin, audience, req). Errors are Binding's, the possession
// scheme's (short nonce), and a seed of the wrong size — an error here rather than the
// floor's panic, because the seed comes from custody (a file, a store), not from code.
func Prove(seed []byte, audience string, req *Request) ([]byte, error) {
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("login: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	binding, err := Binding(RoleLogin, audience, req)
	if err != nil {
		return nil, err
	}
	return possession.Prove(seed, Domain, req.Nonce, binding)
}

// Verify reports whether signature is the login proof by the key behind pubkey for req at
// audience. Total: every shape failure is false.
func Verify(pubkey []byte, audience string, req *Request, signature []byte) bool {
	if req == nil {
		return false
	}
	binding, err := Binding(RoleLogin, audience, req)
	if err != nil {
		return false
	}
	return possession.Verify(pubkey, Domain, req.Nonce, binding, signature)
}

// ProveCollect makes the browser's collect proof: possession by the key behind seed — which
// must be the key req names as Browser — in Domain, over req.Nonce and
// Binding(RoleCollect, audience, req). A seed whose public key is not req.Browser is an
// error: the proof is only meaningful from the key the request names.
func ProveCollect(seed []byte, audience string, req *Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("login: nil request")
	}
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("login: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	if !bytes.Equal(crypto.PublicKeyFromSeed(seed), req.Browser) {
		return nil, errors.New("login: seed is not the browser key the request names")
	}
	binding, err := Binding(RoleCollect, audience, req)
	if err != nil {
		return nil, err
	}
	return possession.Prove(seed, Domain, req.Nonce, binding)
}

// VerifyCollect reports whether signature is the collect proof by req.Browser for req at
// audience. Total.
func VerifyCollect(audience string, req *Request, signature []byte) bool {
	if req == nil {
		return false
	}
	binding, err := Binding(RoleCollect, audience, req)
	if err != nil {
		return false
	}
	return possession.Verify(req.Browser, Domain, req.Nonce, binding, signature)
}

// checkText enforces the rule shared by the audience and every scope entry: 1..=MaxFieldSize
// bytes of valid UTF-8 with no control character (U+0000–U+001F, U+007F). These bytes are
// displayed verbatim by the CLI before signing; a control character could make the display
// lie about what is bound.
func checkText(what, s string) error {
	if len(s) == 0 || len(s) > MaxFieldSize {
		return fmt.Errorf("login: %s is %d bytes, want 1..=%d", what, len(s), MaxFieldSize)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("login: %s is not valid UTF-8", what)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("login: %s carries a control character U+%04X", what, r)
		}
	}
	return nil
}

// putField writes u16be(len field) ‖ field. Callers have bounded len(field) to MaxFieldSize.
func putField(b *bytes.Buffer, field []byte) {
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(field)))
	b.Write(n[:])
	b.Write(field)
}
