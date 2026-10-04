// Package request is the server's half of request authentication (ADR 0010 §5–§6;
// docs/request.md §7 steps 8–9, version 1, fixed by ADR 0010's status note of 4 October 2026).
//
// The sdk's request.Verify checks a proof: one spelling, the coverage, the audience echo, the
// digest, freshness and the signature. It does not remember. This package adds what only a
// server can: the HTTP extraction (from net/http, through the request line as received), the
// clock, and the REPLAY STORE — the one operation that makes a proof usable at most once:
//
//	InsertIfAbsent((profile, audience, principal, nonce), from, until) → inserted | alreadyPresent | unavailable
//
// A request reaches the application only as an Authenticated, and only after a proof verified
// AND its identifier was inserted. `alreadyPresent` is a replay; `unavailable` FAILS CLOSED —
// a store that cannot answer is never permission to skip the check.
//
// What this does not do: authorize. Authenticated is the principal together with the verified
// request descriptor, so the application's authorization evaluates the request authentication
// verified — not a re-parse of it (ADR 0010 §6).
package request

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	sdk "github.com/Bitspark/archon/sdk/go/request"
)

// MaxBodyBytes caps the content a verifier reads to recompute the digest. A larger body is
// refused rather than truncated: a digest over part of a body verifies nothing.
const MaxBodyBytes = 1 << 20

// Outcome is what a replay store answers.
type Outcome int

const (
	Inserted       Outcome = iota // the identifier was new and is now remembered
	AlreadyPresent                // the identifier was seen: a replay
	Unavailable                   // the store cannot answer: the request fails closed
)

// ReplayKey is what a replay store remembers. It is never the signature bytes: a signature is
// one spelling of a proof, the identifier is the proof's.
type ReplayKey struct {
	Profile   string // sdk.Tag
	Audience  string
	Principal string // the canonical key text
	Nonce     string // hex
}

// ReplayEntry is one insertion: the key, and the window in which any verifier could accept the
// proof — From is created − δ, Until is expires + δ. A store retains the key at least until
// Until; From is what lets a store that lost its memory refuse proofs it might have seen.
type ReplayEntry struct {
	Key         ReplayKey
	From, Until time.Time
}

// ReplayStore makes a proof usable at most once. Requirements (ADR 0010 §5): one winner across
// every verifier in the acceptance scope — concurrent inserts of one key return Inserted at
// most once; a key is retained at least until its Until, when no verifier can still accept the
// proof; and a store that cannot guarantee both answers Unavailable rather than Inserted.
type ReplayStore interface {
	InsertIfAbsent(ctx context.Context, e ReplayEntry) Outcome
}

// Authenticated is a request that verified and was admitted by the replay store: the
// principal, and the request descriptor authentication verified.
type Authenticated struct {
	sdk.Verified
}

// Refusal says why a request was not authenticated. Status is the HTTP status a middleware
// answers with: 400 for a request that does not parse as the profile, 401 for one that parses
// but does not authenticate, 413 for an oversized body, 503 when the replay store is
// unavailable.
type Refusal struct {
	Status int
	Err    error
}

func (r *Refusal) Error() string { return r.Err.Error() }

// Verifier authenticates requests under one policy against one replay store.
type Verifier struct {
	Policy sdk.Policy
	Store  ReplayStore
	// Clock is the verifier's time; nil means time.Now.
	Clock func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Clock == nil {
		return time.Now()
	}
	return v.Clock()
}

// Authenticate reads r's body (restoring it for whoever reads it next), verifies the proof and
// inserts its identifier. The request-target is r.RequestURI — the request line as received,
// never a URL net/http rebuilt — so what is verified is what arrived.
func (v *Verifier) Authenticate(r *http.Request) (Authenticated, error) {
	if v.Store == nil {
		return Authenticated{}, &Refusal{http.StatusServiceUnavailable, errors.New("request: no replay store")}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return Authenticated{}, &Refusal{http.StatusBadRequest, fmt.Errorf("request: reading the body: %w", err)}
	}
	if len(body) > MaxBodyBytes {
		return Authenticated{}, &Refusal{http.StatusRequestEntityTooLarge, errors.New("request: the body is over the verifier's limit")}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// v1 accepts no content coding and no trailers (ADR 0010 §4): the digest is over the
	// content as received, and a coded body would make "as received" ambiguous.
	if len(r.Header.Values("Content-Encoding")) > 0 || len(r.Trailer) > 0 {
		return Authenticated{}, &Refusal{http.StatusBadRequest, errors.New("request: content codings and trailers are not accepted in v1")}
	}
	headers := make([][2]string, 0, len(r.Header))
	for name, values := range r.Header {
		for _, value := range values {
			headers = append(headers, [2]string{name, value})
		}
	}
	now := v.now().Unix()
	verified, err := sdk.Verify(v.Policy, now, sdk.Received{
		Method: r.Method, RequestTarget: r.RequestURI, Headers: headers, Body: body,
	})
	if err != nil {
		return Authenticated{}, &Refusal{http.StatusUnauthorized, err}
	}

	// Only now, after the proof and its freshness verified (ADR 0010 §5: verify before
	// inserting), is the identifier remembered — until no verifier can still accept it.
	entry := ReplayEntry{
		Key:   ReplayKey{Profile: sdk.Tag, Audience: v.Policy.Audience, Principal: verified.KeyText, Nonce: fmt.Sprintf("%x", verified.Nonce)},
		From:  time.Unix(verified.Created-v.Policy.Skew, 0),
		Until: time.Unix(verified.Expires+v.Policy.Skew, 0),
	}
	switch v.Store.InsertIfAbsent(r.Context(), entry) {
	case Inserted:
		return Authenticated{verified}, nil
	case AlreadyPresent:
		return Authenticated{}, &Refusal{http.StatusUnauthorized, errors.New("request: replayed")}
	default:
		return Authenticated{}, &Refusal{http.StatusServiceUnavailable, errors.New("request: the replay store is unavailable")}
	}
}

type contextKey struct{}

// Middleware authenticates every request before next sees it. A refused request never reaches
// next: it is answered with the refusal's status and a one-line reason.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := v.Authenticate(r)
		if err != nil {
			status := http.StatusUnauthorized
			var refusal *Refusal
			if errors.As(err, &refusal) {
				status = refusal.Status
			}
			http.Error(w, err.Error(), status)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, a)))
	})
}

// FromContext is the Authenticated the middleware attached, if any.
func FromContext(ctx context.Context) (Authenticated, bool) {
	a, ok := ctx.Value(contextKey{}).(Authenticated)
	return a, ok
}
