// Package enroll is the server's half of key enrollment (ADR 0010 §7; docs/request.md §6,
// version 1, fixed by ADR 0010's status note of 4 October 2026).
//
// An enrollment has a new key prove its own possession while a separate authority — the
// service's session, or a bootstrap credential — says whose key it is. The sdk's enroll package
// holds the binding and the proof. This package holds what only a server can, in two halves:
//
//   - Prepare builds the PENDING RECORD, the immutable association of authorizing context,
//     intended account, purpose, new key, a fresh nonce, the intent's digest and an expiry. The
//     service calls it only after validating the session or bootstrap credential, persists the
//     record in its own transaction (reserving a bootstrap credential to it atomically, when
//     there is one), and sends the client the Challenge.
//   - Complete takes what a completion request carries — the transaction id and the proof —
//     and the authorization the service extracted from that request. It checks, in order: the
//     record exists and has not expired; the same authorization began it; the proof verifies
//     under the record's new key, over the binding rebuilt from the record and the configured
//     audience. Only then does it call the Integration's Complete, the service's ATOMIC business
//     operation: the key-account association recorded and the record consumed, in one
//     persistence transaction. archon cannot promise that atomicity across a callback and a
//     separate database (ADR 0010 §7), so it does not pretend to: the operation is the
//     service's.
//
// There is NO "possession alone suffices" mode: New refuses a missing Integration. Possession
// identifies a key; only the service's authority ties it to an account. And a completion cannot
// substitute anything: it names a record, and the account, key, purpose, nonce and intent all
// come from that record.
//
// archon defines no enrollment route. The service mounts completion wherever it serves its
// accounts, behind its own session and CSRF protection.
package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	sdk "github.com/Bitspark/archon/sdk/go/enroll"
	"github.com/Bitspark/archon/sdk/go/possession"
)

// DefaultTTL is how long a pending enrollment lives when Config.TTL is zero.
const DefaultTTL = 5 * time.Minute

// idSize is the size of the generated transaction id and nonce: the possession scheme's floor,
// and enough that an id is not guessable.
const idSize = possession.MinNonceSize

// Record is a pending enrollment: written once by Prepare, persisted by the service, and never
// changed — completion consumes it, it does not edit it.
type Record struct {
	Transaction []byte // the pending transaction's id
	// Authorization identifies what authorized the enrollment: the session, or the bootstrap
	// credential reserved to this record. An identifier, never a secret: a session's id, not
	// its cookie, since the record is stored.
	Authorization []byte
	Account       []byte // the intended account, opaque to archon
	Purpose       string // "add-key", "rotate", "recover", …
	NewKey        []byte // the public key being enrolled
	Nonce         []byte // the server's fresh challenge
	IntentDigest  []byte // SHA-256 of the service's immutable intent bytes
	Expires       time.Time
}

// Challenge is what the client needs to prove: the record's public half and the audience.
type Challenge struct {
	Transaction  []byte
	Nonce        []byte
	Purpose      string
	Audience     string
	IntentDigest []byte
	Expires      time.Time
}

// Begin is what the service supplies to Prepare, after validating the authorizing credential.
type Begin struct {
	Authorization []byte
	Account       []byte
	Purpose       string
	NewKey        []byte
	// Intent is the immutable intent bytes — what the service will record. Prepare and Complete
	// bind their digest and never interpret them. A digest is not confidentiality, so no intent
	// may have a guessable preimage: build it with Intent (format 1, a fresh blind) for
	// `archon enroll`, or keep guessable account data out (ADR 0013, docs/enroll.md §2).
	Intent []byte
}

// ErrNotFound is what Integration.Load returns for a transaction it holds no record of.
var ErrNotFound = errors.New("enroll: no such pending transaction")

// Outcome is what Integration.Complete answers.
type Outcome int

const (
	Completed   Outcome = iota // the association is recorded and the record consumed
	NotPending                 // already completed or consumed, or no longer acceptable
	Unavailable                // the integration cannot answer: the completion fails closed
)

// Integration is the service's authorizing integration: its persistence of pending records and
// its atomic completion.
type Integration interface {
	// Load returns the record for transaction; ErrNotFound when there is none; any other error
	// when it cannot answer, and the completion fails closed.
	Load(ctx context.Context, transaction []byte) (Record, error)

	// Complete is the service's atomic business operation. In one persistence transaction it
	// checks that r is still pending and that its authorizing context is still acceptable under
	// the service's policy, records r.NewKey as r.Account's for r.Purpose, and consumes r (and
	// any bootstrap credential reserved to it). Concurrent calls for one record answer Completed
	// at most once.
	Complete(ctx context.Context, r Record) Outcome
}

// Config is what a service supplies. Audience and Integration are required.
type Config struct {
	// Audience is the configured audience every binding is rebuilt from (docs/request.md §2).
	Audience string
	// Integration is required: without it, possession alone would suffice.
	Integration Integration
	// TTL is how long a pending enrollment lives. Zero means DefaultTTL.
	TTL time.Duration
	// Clock and Entropy default to time.Now and crypto/rand when nil.
	Clock   func() time.Time
	Entropy func(b []byte) error
}

// Enroller prepares and completes enrollments under one configuration.
type Enroller struct {
	audience    string
	integration Integration
	ttl         time.Duration
	clock       func() time.Time
	entropy     func(b []byte) error
}

// New builds an Enroller, refusing a configuration with no Integration or an audience the
// binding does not accept.
func New(cfg Config) (*Enroller, error) {
	if cfg.Integration == nil {
		return nil, errors.New("enroll: Config.Integration is required — possession identifies a key; only the service's authority ties it to an account")
	}
	probe := &sdk.Request{
		Transaction: []byte{0}, Purpose: "add-key", NewKey: make([]byte, crypto.PublicKeySize), IntentDigest: make([]byte, sdk.DigestSize),
	}
	if _, err := sdk.Binding(cfg.Audience, probe); err != nil {
		return nil, fmt.Errorf("enroll: Config.Audience %q: %w", cfg.Audience, err)
	}
	e := &Enroller{audience: cfg.Audience, integration: cfg.Integration, ttl: cfg.TTL, clock: cfg.Clock, entropy: cfg.Entropy}
	if e.ttl <= 0 {
		e.ttl = DefaultTTL
	}
	if e.clock == nil {
		e.clock = time.Now
	}
	if e.entropy == nil {
		e.entropy = func(b []byte) error { _, err := rand.Read(b); return err }
	}
	return e, nil
}

// Prepare builds the pending record for b and the challenge to send the client. The service
// persists the record; nothing here stores it.
func (e *Enroller) Prepare(b Begin) (Record, Challenge, error) {
	if len(b.Authorization) == 0 {
		return Record{}, Challenge{}, errors.New("enroll: an enrollment needs the authorization that began it")
	}
	if len(b.Account) == 0 {
		return Record{}, Challenge{}, errors.New("enroll: an enrollment needs the account it is for")
	}
	digest := sha256.Sum256(b.Intent)
	r := Record{
		Transaction:   make([]byte, idSize),
		Authorization: bytes.Clone(b.Authorization),
		Account:       bytes.Clone(b.Account),
		Purpose:       b.Purpose,
		NewKey:        bytes.Clone(b.NewKey),
		Nonce:         make([]byte, idSize),
		IntentDigest:  digest[:],
		Expires:       e.clock().Add(e.ttl),
	}
	if err := e.entropy(r.Transaction); err != nil {
		return Record{}, Challenge{}, fmt.Errorf("enroll: entropy: %w", err)
	}
	if err := e.entropy(r.Nonce); err != nil {
		return Record{}, Challenge{}, fmt.Errorf("enroll: entropy: %w", err)
	}
	// The sdk's binding rules, refused here rather than at completion.
	if _, err := sdk.Binding(e.audience, request(r)); err != nil {
		return Record{}, Challenge{}, err
	}
	return r, Challenge{
		Transaction: r.Transaction, Nonce: r.Nonce, Purpose: r.Purpose,
		Audience: e.audience, IntentDigest: r.IntentDigest, Expires: r.Expires,
	}, nil
}

// Refusal says why a completion failed. Status is the HTTP status a service's route answers
// with: 400 for a malformed completion, 401 for a proof that does not verify, 403 for a
// completion under another authorization, 404 for an unknown or expired transaction, 409 for
// one already completed or no longer eligible, 503 when the integration cannot answer.
type Refusal struct {
	Status int
	Err    error
}

func (r *Refusal) Error() string { return r.Err.Error() }

// Complete completes the enrollment transaction names, under authorization, with proof. It
// returns the completed record, or a *Refusal.
func (e *Enroller) Complete(ctx context.Context, transaction, proof, authorization []byte) (Record, error) {
	if len(transaction) == 0 || len(transaction) > sdk.MaxTransactionSize {
		return Record{}, &Refusal{http.StatusBadRequest, errors.New("enroll: malformed transaction id")}
	}
	r, err := e.integration.Load(ctx, transaction)
	if errors.Is(err, ErrNotFound) {
		return Record{}, &Refusal{http.StatusNotFound, errors.New("enroll: unknown or expired transaction")}
	}
	if err != nil {
		return Record{}, &Refusal{http.StatusServiceUnavailable, fmt.Errorf("enroll: the integration cannot load: %w", err)}
	}
	// A record for another transaction is an integration fault, and is never verified against.
	if !bytes.Equal(r.Transaction, transaction) {
		return Record{}, &Refusal{http.StatusServiceUnavailable, errors.New("enroll: the integration returned another transaction's record")}
	}
	if !e.clock().Before(r.Expires) {
		return Record{}, &Refusal{http.StatusNotFound, errors.New("enroll: unknown or expired transaction")}
	}
	// The same authorization that began it — checked before the proof, so a stranger's
	// completion learns nothing about it.
	if len(authorization) == 0 || subtle.ConstantTimeCompare(r.Authorization, authorization) != 1 {
		return Record{}, &Refusal{http.StatusForbidden, errors.New("enroll: not the authorization that began this enrollment")}
	}
	if !sdk.Verify(e.audience, request(r), proof) {
		return Record{}, &Refusal{http.StatusUnauthorized, errors.New("enroll: the proof does not verify")}
	}
	switch e.integration.Complete(ctx, r) {
	case Completed:
		return r, nil
	case NotPending:
		return Record{}, &Refusal{http.StatusConflict, errors.New("enroll: already completed or no longer eligible")}
	default:
		return Record{}, &Refusal{http.StatusServiceUnavailable, errors.New("enroll: the integration cannot complete")}
	}
}

// request is the sdk's view of a record: everything a binding covers, from the record alone.
func request(r Record) *sdk.Request {
	return &sdk.Request{Nonce: r.Nonce, Transaction: r.Transaction, Purpose: r.Purpose, NewKey: r.NewKey, IntentDigest: r.IntentDigest}
}
