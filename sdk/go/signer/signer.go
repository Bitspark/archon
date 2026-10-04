// Package signer is the signer contract — SIGNING CAPABILITY, NOT SEEDS (ADR 0009 §2–4).
//
// Every helper in this module can take a seed, which is right for a key held in software and
// wrong for one that is not: a stored key behind `archon sign --key`, or any backend a caller
// wires in. So each signing helper also comes in three parts — a PURE Prepare (the exact
// request it needs signed), the signer's own work, and a PURE Complete (the checked signature,
// then packaging) — with a ...With convenience that runs the signer between them. The seed
// functions are unchanged.
//
// A Request is three things, and the scheme is a discriminated value, never a scheme name
// plus an optional domain: the public key the caller expects, raw Ed25519 (Raw) or Ed25519ph
// with the domain as the RFC 8032 context (PhContext), and the ORIGINAL message bytes — never
// a digest. crypto.SignInDomain hashes inside; a backend that wants the prehash computes it in
// its own adapter, and the contract never shows the difference.
//
// Three rules, all enforced here rather than trusted to a signer:
//
//   - A request is validated BEFORE the signer is invoked: a wrong-length key or a domain the
//     floor refuses never reaches it.
//   - A signer REPORTS what it can do (Capabilities), and a request outside that is refused
//     before it is invoked. A signer that cannot carry a context declares raw only; it must
//     never sign a PhContext request with an empty context instead, and if it does anyway,
//     the check below catches it.
//   - Every returned signature is VERIFIED against the requested key, scheme, domain and
//     bytes — never against values the signer echoes back. That catches a wrong key, a
//     dropped context, raw substituted for ph, and a wrong prehash adaptation. It does not
//     prove that a signer signs deterministically (ADR 0008 §1.7 requires it); that is a
//     property of the backend, tested against the domain_sign vectors.
//
// Domain separation is not authorization: whoever may ask for signatures in a domain gets
// any signature in that domain. Consent belongs to the caller that knows what the bytes mean.
package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/Bitspark/archon/core/go/crypto"
)

// Kind names a scheme in Capabilities.
type Kind string

// The two schemes.
const (
	KindRaw       Kind = "ed25519-raw"
	KindPhContext Kind = "ed25519ph-context"
)

// Scheme is Raw or PhContext.
type Scheme interface {
	Kind() Kind
}

// Raw is pure Ed25519 over the message. It carries no domain.
type Raw struct{}

// PhContext is Ed25519ph with Domain as the RFC 8032 context.
type PhContext struct{ Domain string }

// Kind reports KindRaw.
func (Raw) Kind() Kind { return KindRaw }

// Kind reports KindPhContext.
func (PhContext) Kind() Kind { return KindPhContext }

// Request is what a signer is asked to sign. Message is always the original bytes.
type Request struct {
	ExpectedPublicKey []byte
	Scheme            Scheme
	Message           []byte
}

// Capabilities is what a signer can do. A nil Domains means any domain the floor accepts.
type Capabilities struct {
	Schemes []Kind
	Domains []string
}

// Signer is a source of signatures. Sign may prompt, call a subprocess or wait on a device;
// it is given the context, and a signature it returns after the context is done is
// discarded, never packaged.
type Signer interface {
	PublicKey() []byte
	Capabilities() Capabilities
	Sign(ctx context.Context, r Request) ([]byte, error)
}

// Validate errors unless r is in range: a 32-byte expected key, a known scheme, and — for
// PhContext — a domain the floor accepts. The domain is checked by the floor's own rule (it
// signs nothing with a throwaway key), so no copy of ADR 0008 §2 lives here to drift.
func Validate(r Request) error {
	if len(r.ExpectedPublicKey) != crypto.PublicKeySize {
		return fmt.Errorf("signer: the expected public key must be %d bytes", crypto.PublicKeySize)
	}
	switch s := r.Scheme.(type) {
	case Raw:
		return nil
	case PhContext:
		_, err := crypto.SignInDomain(make([]byte, crypto.SeedSize), s.Domain, nil)
		return err
	default:
		return fmt.Errorf("signer: unknown scheme %T", r.Scheme)
	}
}

// Check errors unless signature verifies for exactly what was REQUESTED: its key, scheme,
// domain and original bytes.
func Check(r Request, signature []byte) error {
	if err := Validate(r); err != nil {
		return err
	}
	var ok bool
	switch s := r.Scheme.(type) {
	case Raw:
		ok = crypto.Verify(r.ExpectedPublicKey, r.Message, signature)
	case PhContext:
		ok = crypto.VerifyInDomain(r.ExpectedPublicKey, s.Domain, r.Message, signature)
	}
	if !ok {
		return errors.New("signer: the signature does not verify for the requested key, scheme and message")
	}
	return nil
}

// CheckCapability errors unless s claims to be able to sign r: its key is the expected one,
// and the scheme and domain are among its capabilities. Called before it is invoked.
func CheckCapability(s Signer, r Request) error {
	if !bytes.Equal(s.PublicKey(), r.ExpectedPublicKey) {
		return errors.New("signer: this signer's key is not the expected key")
	}
	caps := s.Capabilities()
	if !slices.Contains(caps.Schemes, r.Scheme.Kind()) {
		return fmt.Errorf("signer: this signer cannot produce %s", r.Scheme.Kind())
	}
	if ph, ok := r.Scheme.(PhContext); ok && caps.Domains != nil && !slices.Contains(caps.Domains, ph.Domain) {
		return fmt.Errorf("signer: this signer does not sign in domain %q", ph.Domain)
	}
	return nil
}

// SignWith validates r, checks s's capabilities, invokes it, and returns the signature only
// if ctx was not done by then and the signature verifies for what was requested.
func SignWith(ctx context.Context, s Signer, r Request) ([]byte, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	if err := CheckCapability(s, r); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := s.Sign(ctx, r)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := Check(r, signature); err != nil {
		return nil, err
	}
	return bytes.Clone(signature), nil
}

// seedSigner is the software signer.
type seedSigner struct {
	seed, pub []byte
}

// Seed returns the software signer: a seed held in this process, both schemes, any domain
// the floor accepts, deterministic by the floor's construction. The seed is copied.
func Seed(seed []byte) (Signer, error) {
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("signer: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	held := bytes.Clone(seed)
	return &seedSigner{seed: held, pub: crypto.PublicKeyFromSeed(held)}, nil
}

func (s *seedSigner) PublicKey() []byte { return bytes.Clone(s.pub) }

func (s *seedSigner) Capabilities() Capabilities {
	return Capabilities{Schemes: []Kind{KindRaw, KindPhContext}}
}

func (s *seedSigner) Sign(_ context.Context, r Request) ([]byte, error) {
	switch sc := r.Scheme.(type) {
	case Raw:
		return crypto.Sign(s.seed, r.Message), nil
	case PhContext:
		return crypto.SignInDomain(s.seed, sc.Domain, r.Message)
	default:
		return nil, fmt.Errorf("signer: unknown scheme %T", r.Scheme)
	}
}
