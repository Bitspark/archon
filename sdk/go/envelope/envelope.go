// Package envelope is the signed envelope — THESE BYTES, SIGNED BY THIS KEY, IN THIS DOMAIN.
//
// A fixed binary container, JWS-shaped and deliberately not JWT-shaped:
//
//	"arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ signature[64] ‖ payload
//
// where signature = SignInDomain(seed, domain, SchemeTag ‖ payload). The domain is bound
// cryptographically (it is the RFC 8032 context), the public key is bound by
// verification, and the payload is opaque: the envelope says nothing about what it
// means. WHAT IS NOT HERE, ON PURPOSE: expiry, issuer, audience, key-id, nonce. Each is
// either policy — whose clock, whose trust? — or a second spelling of the key, and both
// belong to the consumer.
//
// Open takes the domain the VERIFIER expects and refuses an envelope that claims
// another. The verifier chooses the domain; an envelope never gets to choose it for
// them. Whether to trust the key it names is, again, the verifier's.
package envelope

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/signer"
)

// Magic is the first four bytes of every envelope.
var Magic = []byte("arcn")

// Version is the envelope format version.
const Version byte = 0x01

// SchemeTag is the first byte of every signed envelope message. Distinct from
// possession.SchemeTag.
const SchemeTag byte = 0x02

// Opened is what Open returns: the sealing key and the payload, both verified.
type Opened struct {
	// Pubkey is the public key that sealed the envelope. Trusting it is the caller's
	// decision.
	Pubkey []byte
	// Payload is the payload, verbatim.
	Payload []byte
}

// Seal seals payload in domain with the key behind seed. It errors on an invalid domain
// (see crypto.SignInDomain) and on a seed of the wrong size — an error rather than the
// floor's panic, because in the sdk a seed comes from custody, not from code (ADR 0004,
// dated note 2026-09-10). An empty payload is allowed — the signed message is never empty
// because of the scheme tag.
func Seal(seed []byte, domain string, payload []byte) ([]byte, error) {
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("envelope: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	signature, err := crypto.SignInDomain(seed, domain, MessageBytes(payload))
	if err != nil {
		return nil, err
	}
	return pack(domain, crypto.PublicKeyFromSeed(seed), signature, payload), nil
}

// PrepareSeal is the signing request sealing payload in domain needs, for a signer whose key
// is pubkey (ADR 0009 §4). Pure; it errors on an invalid domain. The message is
// MessageBytes(payload), so an envelope made through it is the same bytes.
func PrepareSeal(pubkey []byte, domain string, payload []byte) (signer.Request, error) {
	r := signer.Request{ExpectedPublicKey: pubkey, Scheme: signer.PhContext{Domain: domain}, Message: MessageBytes(payload)}
	if err := signer.Validate(r); err != nil {
		return signer.Request{}, err
	}
	return r, nil
}

// CompleteSeal is the envelope, from a signature over a prepared seal request: the signature
// is checked against the request, then the envelope is assembled from the request's own key,
// domain and payload. Pure.
func CompleteSeal(r signer.Request, signature []byte) ([]byte, error) {
	ph, ok := r.Scheme.(signer.PhContext)
	if !ok || len(r.Message) == 0 || r.Message[0] != SchemeTag {
		return nil, errors.New("envelope: not a seal request")
	}
	if err := signer.Check(r, signature); err != nil {
		return nil, err
	}
	return pack(ph.Domain, r.ExpectedPublicKey, signature, r.Message[1:]), nil
}

// SealWith is Seal through a signer instead of a seed.
func SealWith(ctx context.Context, s signer.Signer, domain string, payload []byte) ([]byte, error) {
	r, err := PrepareSeal(s.PublicKey(), domain, payload)
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignWith(ctx, s, r)
	if err != nil {
		return nil, err
	}
	return CompleteSeal(r, signature)
}

// pack is the container layout, from parts already checked: the domain fits a u8.
func pack(domain string, pubkey, signature, payload []byte) []byte {
	out := make([]byte, 0, 4+1+1+len(domain)+crypto.PublicKeySize+crypto.SignatureSize+len(payload))
	out = append(out, Magic...)
	out = append(out, Version)
	out = append(out, byte(len(domain))) // ≤ 255: SignInDomain has already checked it
	out = append(out, domain...)
	out = append(out, pubkey...)
	out = append(out, signature...)
	out = append(out, payload...)
	return out
}

// Open opens envelope, which the caller expects to be sealed in domain. It errors — never
// returns a payload — when the bytes are not an envelope (magic, version, length), the
// envelope claims a different domain, or the signature does not verify.
func Open(envelope []byte, domain string) (Opened, error) {
	at := 0
	take := func(n int) ([]byte, error) {
		if at+n > len(envelope) {
			return nil, fmt.Errorf("envelope: truncated at byte %d", len(envelope))
		}
		s := envelope[at : at+n]
		at += n
		return s, nil
	}
	magic, err := take(4)
	if err != nil {
		return Opened{}, err
	}
	if !bytes.Equal(magic, Magic) {
		return Opened{}, errors.New("envelope: not an envelope: bad magic")
	}
	version, err := take(1)
	if err != nil {
		return Opened{}, err
	}
	if version[0] != Version {
		return Opened{}, fmt.Errorf("envelope: unsupported version %d", version[0])
	}
	dl, err := take(1)
	if err != nil {
		return Opened{}, err
	}
	dlen := int(dl[0])
	if dlen == 0 || dlen > crypto.MaxDomainSize {
		return Opened{}, fmt.Errorf("envelope: domain length %d out of range", dlen)
	}
	claimed, err := take(dlen)
	if err != nil {
		return Opened{}, err
	}
	if string(claimed) != domain {
		return Opened{}, errors.New("envelope: claims a different domain")
	}
	pubkey, err := take(crypto.PublicKeySize)
	if err != nil {
		return Opened{}, err
	}
	signature, err := take(crypto.SignatureSize)
	if err != nil {
		return Opened{}, err
	}
	payload := envelope[at:]
	if !crypto.VerifyInDomain(pubkey, domain, MessageBytes(payload), signature) {
		return Opened{}, errors.New("envelope: signature does not verify")
	}
	return Opened{
		Pubkey:  append([]byte(nil), pubkey...),
		Payload: append([]byte(nil), payload...),
	}, nil
}

// MessageBytes is the pinned layout of what gets signed: the scheme tag, then the
// payload verbatim.
func MessageBytes(payload []byte) []byte {
	return append([]byte{SchemeTag}, payload...)
}
