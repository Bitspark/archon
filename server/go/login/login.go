// Package login is the service side of the archon login protocol (docs/login.md §4): a
// mounted handler implementing the four routes a browser and a CLI need to rendezvous, so
// a service adopts proof-of-possession sign-in by mounting a handler rather than by
// building a session system.
//
// THREE THINGS THIS PACKAGE DELIBERATELY IS NOT (ADR 0007 §B):
//
//   - It is not a server. It opens no socket and starts no goroutine; the service's own
//     server owns the listener and mounts this at a path.
//   - It is not a law. The authority payload is opaque bytes here, interpreted only inside
//     the AdmitAuthority callback the service supplies. archon ships no implementation of
//     one, and nothing in this package reads a grant.
//   - It is not a store. One in-memory record per pending login, dropped at expiry or on
//     collection; nothing persisted, nothing surviving the process.
//
// THE AUDIENCE IS CONFIGURED, NEVER READ FROM THE WIRE. Every binding is recomputed from
// the string the service configured, in both directions. That is the WebAuthn rule and
// review Finding 1: a relying party's identity comes from its own configuration, not from
// a value an attacker can put in a message. There is no code path here that reads an
// audience from a request, which is why there is no way to get it wrong.
//
// The scheme itself — the binding layout, the domain, the proofs — is sdk/go/login's and is
// consumed, never reimplemented: a binding written twice is a binding that drifts.
package login

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/login"
)

// The RFC 8628 / RFC 6749 error codes §4 adopts verbatim. Their bearer-token result is not
// ours, but their vocabulary is, so a client that already speaks device flow behaves well.
const (
	errInvalidRequest = "invalid_request"
	errInvalidGrant   = "invalid_grant"
	errExpiredToken   = "expired_token"
	errPendingCode    = "authorization_pending"
	errSlowDown       = "slow_down"
)

// errExpired is the internal signal that a record is gone or was never there. It becomes
// `404 expired_token` — the two cases are deliberately indistinguishable to a client, so a
// stranger cannot probe which ids exist.
var errExpired = errors.New("login: no such pending request")

// Defaults from §4. expires_in is five minutes and interval is five seconds, both
// advertised to the browser in the begin response so a client need not guess.
const (
	DefaultTTL      = 5 * time.Minute
	DefaultInterval = 5 * time.Second

	// minEntropy is the floor on both the id and the nonce. §3.1 requires ≥ 16 bytes of
	// nonce and recommends ≥ 16 for the id; this package uses 16 for both, since an id a
	// stranger can guess is as bad as a nonce they can guess — it is the address of a
	// pending login.
	minEntropy = 16

	// minCodeHex is the floor on an offer's code (§4.1): at least 16 bytes of the PROVER's
	// entropy, spelled as lowercase hex — so 32 characters. The code is the address of an
	// open offer and is confidential until the offer is taken; a short one is guessable.
	minCodeHex = 2 * minEntropy
)

// AdmitAuthority is the ONLY place an authority payload is interpreted, and archon ships no
// implementation of it. It is handed the browser key the delegation is for, the principal
// that signed the proof, and the opaque payload; returning a non-nil error refuses the
// answer with `403 invalid_grant` and stores nothing.
//
// A nil AdmitAuthority means the proof alone suffices — correct for a service whose law
// needs nothing beyond "this key holder was here and approved this scope".
type AdmitAuthority func(browser, principal []byte, authority json.RawMessage) error

// Clock and Entropy are CONSTRUCTOR ARGUMENTS rather than package-level calls, which is the
// sdk's rule and the reason this package is testable without sleeping or flaking: a test
// injects a clock it steps by hand and entropy it can predict, and the same code runs in
// production with time.Now and crypto/rand.
type (
	Clock   func() time.Time
	Entropy func(b []byte) error
)

// Config is what a service supplies. Only Audience is required.
//
// Two limits are fixed rather than configurable, and are named here so a service reading
// this type learns them without reading the source:
//
//   - maxBodyBytes (64 KiB) caps every request body. Each message in this protocol is a
//     key, a hex proof and a short scope list; the authority payload is the only field with
//     no natural size, and a law needing more than this should say so rather than have the
//     handler guess high.
//   - minEntropy (16 bytes) is the floor on both the generated id and the generated nonce.
//     §3.1 requires it of the nonce and recommends it for the id; this package applies it
//     to both, since an id a stranger can guess is the address of a pending login.
type Config struct {
	// Audience is the service's base URL as it knows itself — scheme and host lowercased,
	// default port omitted, no trailing slash (docs/login.md §2). Every binding is
	// recomputed from THIS string.
	//
	// The handler must be mounted at <Audience path>/login, because the CLI derives the
	// audience by removing `/login/<id>` from the URL it was given (§2.1) and its grammar
	// requires that penultimate segment to be exactly `login`. A service that mounts it
	// elsewhere is reachable but unusable: the CLI would derive an audience this handler
	// never binds, and every proof would fail for no visible reason.
	Audience string

	// Admit interprets the authority payload. Nil means the proof alone suffices.
	Admit AdmitAuthority

	// Page is the address a person opens to finish a login the CLI started (docs/login.md
	// §4.1 — the offers form). Optional. When set, an offer's response carries
	// `<Page>#<code>`: the code travels in the FRAGMENT, which a browser never sends to any
	// server, so it reaches the page's script and no log. A Page that already carries a
	// fragment is refused by New, because the code would have nowhere to go. The CLI prints
	// the address and never opens it (§4.1 rule 1).
	Page string

	// TTL is how long a pending login lives — and how long an open offer lives. Zero means
	// DefaultTTL.
	TTL time.Duration

	// Interval is the poll interval advertised to the browser and enforced as slow_down.
	// Zero means DefaultInterval.
	Interval time.Duration

	// Clock and Entropy default to time.Now and crypto/rand when nil.
	Clock   Clock
	Entropy Entropy
}

// Handler implements the four routes. It is an http.Handler and nothing more: mount it,
// and the service's own server does the listening.
type Handler struct {
	audience string
	admit    AdmitAuthority
	page     string
	ttl      time.Duration
	interval time.Duration
	clock    Clock
	entropy  Entropy
	store    *store
}

// New builds a handler. It errors rather than panicking on a bad audience, because the
// audience comes from a service's configuration — a file, a flag, an environment variable —
// and a configuration mistake should be a startup error the operator can read.
func New(cfg Config) (*Handler, error) {
	if cfg.Audience == "" {
		return nil, errors.New("login: Config.Audience is required — the handler binds to it and never reads one from the wire")
	}
	// THE AUDIENCE MUST BE A FIXED POINT OF THE GRAMMAR, checked with the grammar itself
	// rather than with a list of rules restated here.
	//
	// caa's finding: New accepted `https://Dawn.example/api`, `…:443` and `wss://…`, each of
	// which §2.1 DERIVES to something else — so the CLI would bind `https://dawn.example/api`
	// while this handler bound the spelling in the config file, and every proof would fail
	// with nothing on either side saying why. A comment could not prevent that; a startup
	// error can. Feeding the audience back through DeriveAudience is the exact test, because
	// it asks the one question that matters: is this the string the CLI will produce?
	//
	// The `/login/00` is the shortest invocation URL the grammar admits — a minimum-length
	// id — and exists only to make the audience parseable as one.
	derived, _, err := login.DeriveAudience(cfg.Audience + "/login/00")
	if err != nil {
		return nil, fmt.Errorf("login: Config.Audience %q is not a valid audience: %w (docs/login.md §2.1)", cfg.Audience, err)
	}
	if derived != cfg.Audience {
		return nil, fmt.Errorf(
			"login: Config.Audience %q is not canonical — the CLI will derive %q and bind THAT, "+
				"so every proof would fail. Configure %q (docs/login.md §2.1)",
			cfg.Audience, derived, derived)
	}
	// The code goes in the page's fragment (§4.1), so a page that already has one is a
	// configuration mistake — refused here, where the operator can read it, rather than
	// producing an address with two fragments that no browser parses the way anyone meant.
	if strings.Contains(cfg.Page, "#") {
		return nil, fmt.Errorf("login: Config.Page %q carries a fragment — the offer's code goes there (docs/login.md §4.1)", cfg.Page)
	}
	h := &Handler{
		audience: cfg.Audience,
		admit:    cfg.Admit,
		page:     cfg.Page,
		ttl:      cfg.TTL,
		interval: cfg.Interval,
		clock:    cfg.Clock,
		entropy:  cfg.Entropy,
		store:    newStore(),
	}
	if h.ttl == 0 {
		h.ttl = DefaultTTL
	}
	if h.interval == 0 {
		h.interval = DefaultInterval
	}
	if h.clock == nil {
		h.clock = time.Now
	}
	if h.entropy == nil {
		h.entropy = func(b []byte) error { _, err := rand.Read(b); return err }
	}
	return h, nil
}

// Sweep drops expired records and dead offers and reports how many went. Optional: both also
// expire on read, so a handler that is never swept is correct, just less tidy. A long-lived
// service can call this from its own maintenance loop; this package starts no goroutine of
// its own.
func (h *Handler) Sweep() int { return h.store.sweep(h.clock()) }

// ServeHTTP routes the four requests of §4 and the two of §4.1. The path is taken RELATIVE to
// wherever the service mounted this handler, so it works under any prefix:
//
//	POST   ""               begin      the browser opens a request (with "offer", on an offer)
//	POST   "/offers"        offer      the CLI registers what it will delegate, under its code
//	GET    "/offers/<code>" read offer the page reads it once; the CLI polls it until taken
//	GET    "/<id>"          read       the CLI reads what it is being asked to sign
//	POST   "/<id>/answer"   answer     the CLI delivers the proof
//	GET    "/<id>/answer"   collect    the browser takes the answer, once
//
// The `offers` segment is matched before the id routes. There is no ambiguity to resolve —
// an id is hex and `offers` is not — but the order says which family owns the segment.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(r.URL.Path, "/")
	switch {
	case rest == "":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errInvalidRequest)
			return
		}
		h.begin(w, r)
	default:
		parts := strings.Split(rest, "/")
		switch {
		case parts[0] == "offers" && len(parts) == 1:
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, errInvalidRequest)
				return
			}
			h.offer(w, r)
		case parts[0] == "offers" && len(parts) == 2:
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, errInvalidRequest)
				return
			}
			h.readOffer(w, parts[1])
		case len(parts) == 1:
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, errInvalidRequest)
				return
			}
			h.read(w, parts[0])
		case len(parts) == 2 && parts[1] == "answer":
			switch r.Method {
			case http.MethodPost:
				h.answer(w, r, parts[0])
			case http.MethodGet:
				h.collect(w, r, parts[0])
			default:
				writeError(w, http.StatusMethodNotAllowed, errInvalidRequest)
			}
		default:
			writeError(w, http.StatusNotFound, errExpiredToken)
		}
	}
}

// beginRequest is what the browser posts to open a login.
type beginRequest struct {
	Browser  string   `json:"browser"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
	// Offer names the offer this request is made on (§4.1), or is nil when the member is
	// ABSENT — the page-started form. Raw rather than *string so that a member that is
	// present but `null` is told apart from an absent one: a present member must be a code
	// string, and null is a malformed body (400), not "no offer". A *string read null as nil
	// and began a login on a body ts refused (caa's review of #40).
	Offer json.RawMessage `json:"offer"`
}

// offerMember reads begin's `offer`: absent (nil raw) is no offer; anything present must be
// a JSON string, else the body is malformed. The code's SHAPE is checked by the caller with
// checkCode, because that refusal is a different one (404: unknown by construction).
func offerMember(raw json.RawMessage) (code string, present bool, err error) {
	if raw == nil {
		return "", false, nil
	}
	// A JSON null reaches a RawMessage as the literal `null` (it implements Unmarshaler, and
	// Unmarshal calls it for null too); unmarshalling null into a string leaves the string
	// untouched and reports nothing, so it is refused here by its bytes.
	if string(raw) == "null" {
		return "", true, errors.New("login: the offer member is null")
	}
	if err := json.Unmarshal(raw, &code); err != nil {
		return "", true, fmt.Errorf("login: the offer member is not a string: %w", err)
	}
	return code, true, nil
}

// begin creates a pending record: the server's id and nonce, the browser's key, the scope
// and validity it asked for. The nonce is the SERVER's, never the browser's — a nonce a
// caller chooses is a nonce a caller can replay (§3.1).
//
// On an offer, the request must be what the prover offered — scope entry for entry, in
// order, and validity equal — and the offer must be open. That is checked FIRST, before the
// browser key is decoded and before any entropy is drawn (§4.1: refused before anything is
// stored, before any key is involved), and then again under the lock when the request is
// stored and the offer taken in one critical section (store.takeOffer).
func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	var body beginRequest
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	offerCode, onOffer, err := offerMember(body.Offer)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if onOffer {
		// A malformed code is an UNKNOWN one (§4.1): a registered code is always well-formed,
		// so this names nothing, and the answer is the poll route's 404, not a 400 that would
		// tell a prober which of its guesses were at least the right shape.
		if err := checkCode(offerCode); err != nil {
			writeError(w, http.StatusNotFound, errExpiredToken)
			return
		}
		if !h.writeOfferRefusal(w, h.store.checkOffer(offerCode, h.clock(), body.Scope, body.ValidFor)) {
			return
		}
	}
	browser, err := keytext.DecodeKey(body.Browser)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if body.ValidFor == 0 {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	// The scope is checked HERE, at the door, rather than at proof time: the CLI prints
	// these entries verbatim to a terminal, so an entry carrying a control character could
	// repaint the statement the person is approving. Refusing at begin means such a request
	// never exists to be shown. The scheme refuses them again at Binding; that is the floor,
	// not the gate.
	for _, entry := range body.Scope {
		if err := checkScopeEntry(entry); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}
	}

	id := make([]byte, minEntropy)
	if err := h.entropy(id); err != nil {
		writeError(w, http.StatusInternalServerError, errInvalidRequest)
		return
	}
	nonce := make([]byte, minEntropy)
	if err := h.entropy(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, errInvalidRequest)
		return
	}

	now := h.clock()
	rec := &record{
		id:       id,
		nonce:    nonce,
		browser:  browser,
		scope:    body.Scope,
		validFor: body.ValidFor,
		expires:  now.Add(h.ttl),
	}
	// A request that cannot produce a binding must not be handed out: the CLI would fetch
	// it, show it, and fail at signing time with nothing to explain. Constructing the
	// binding now turns that into a clean refusal at the door.
	if _, err := login.Binding(login.RoleLogin, h.audience, h.request(rec)); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if onOffer {
		// Store the request and take the offer together, re-checking under the lock: the
		// offer may have been taken, or died, while this request was built outside it.
		if !h.writeOfferRefusal(w, h.store.takeOffer(offerCode, h.clock(), rec)) {
			return
		}
	} else {
		h.store.put(rec)
	}

	// The same body whether or not an offer was named: the offer is not echoed, so a browser
	// client needs one shape for begin (pinned as begin_on_offer in login-wire.json).
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        key(id),
		"nonce":     hex.EncodeToString(nonce),
		"browser":   body.Browser,
		"scope":     scopeOrEmpty(body.Scope),
		"valid_for": body.ValidFor,
		// expires_in and interval are seconds, as RFC 8628 spells them, so a device-flow
		// client needs no translation.
		"expires_in":       int(h.ttl / time.Second),
		"interval":         int(h.interval / time.Second),
		"verification_uri": h.audience + "/login/" + key(id),
	})
}

// read is what the CLI fetches. It answers with the request and NOT with the audience:
// there is no audience field in this response by design, because a CLI that would read one
// is a CLI that can be told to sign for someone else (Finding 1).
func (h *Handler) read(w http.ResponseWriter, idHex string) {
	rec, ok := h.store.get(idHex, h.clock())
	if !ok {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":        key(rec.id),
		"nonce":     hex.EncodeToString(rec.nonce),
		"browser":   keytext.EncodeKey(rec.browser),
		"scope":     scopeOrEmpty(rec.scope),
		"valid_for": rec.validFor,
		"expires":   rec.expires.UTC().Format(time.RFC3339),
	})
}

// writeOfferRefusal maps a store verdict on an offer to §4.1's refusals and reports whether
// the caller may go on: errExpired → `404 expired_token` (unknown, expired or orphaned —
// indistinguishable), errTaken → `409 invalid_request` (one offer, one request), errMismatch →
// `400 invalid_request` (the request differs from the offer). Stated once because begin
// asks twice — before building the request and again when storing it.
func (h *Handler) writeOfferRefusal(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errExpired):
		writeError(w, http.StatusNotFound, errExpiredToken)
	case errors.Is(err, errTaken):
		writeError(w, http.StatusConflict, errInvalidRequest)
	case errors.Is(err, errMismatch):
		writeError(w, http.StatusBadRequest, errInvalidRequest)
	default:
		writeError(w, http.StatusInternalServerError, errInvalidRequest)
	}
	return false
}

// offerRequest is what the prover posts to register an offer (§4.1).
type offerRequest struct {
	Code     string   `json:"code"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
}

// offer registers what a prover is willing to delegate, under a code the PROVER minted. The
// server draws no entropy here: the code is the prover's own, which is what lets the prover
// know it before anyone else does and print it on its own terminal (§4.1 "The code").
//
// Everything that would make the offer impossible to begin on is refused now, at the door,
// rather than at the page's begin — where the refusal would reach the page and not the
// person who typed the offer: a malformed code, a validity of zero, a scope entry the CLI
// could not display, and a scope that cannot bind at all.
func (h *Handler) offer(w http.ResponseWriter, r *http.Request) {
	var body offerRequest
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if err := checkCode(body.Code); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if body.ValidFor == 0 {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	for _, entry := range body.Scope {
		if err := checkScopeEntry(entry); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}
	}
	// THE SCOPE MUST BIND. A binding needs a key and an id the offer does not have yet, so
	// the probe uses placeholders of the right size: what is being asked is only whether
	// THESE scope entries and THIS validity fit the binding's fields (§3.2), which no key
	// changes. An offer that passes here can always be begun on; one that fails would have
	// sat open until it expired, every begin on it refused for a reason the page cannot see.
	probe := &login.Request{
		ID:       make([]byte, minEntropy),
		Nonce:    make([]byte, minEntropy),
		Browser:  make([]byte, 32),
		Scope:    body.Scope,
		ValidFor: body.ValidFor,
	}
	if _, err := login.Binding(login.RoleLogin, h.audience, probe); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}

	now := h.clock()
	o := &offer{code: body.Code, scope: body.Scope, validFor: body.ValidFor, expires: now.Add(h.ttl)}
	if !h.store.putOffer(o, now) {
		// A live offer under this code already: one code, one offer. The prover minted the
		// code from 16 bytes of its own entropy, so this is a broken prover or a replay,
		// never a collision worth retrying silently.
		writeError(w, http.StatusConflict, errInvalidRequest)
		return
	}

	response := map[string]any{
		"code":       body.Code,
		"scope":      scopeOrEmpty(body.Scope),
		"valid_for":  body.ValidFor,
		"expires_in": int(h.ttl / time.Second),
		"interval":   int(h.interval / time.Second),
	}
	if h.page != "" {
		// The code rides in the fragment, which a browser keeps to itself: the page's script
		// reads it, no server and no log ever sees it (§4.1 "The code").
		response["page"] = h.page + "#" + body.Code
	}
	writeJSON(w, http.StatusCreated, response)
}

// readOffer is read once by the page — to learn what it is being offered — and polled by the
// prover until `request` names the request that took the offer (§4.1).
//
// There is deliberately NO pacing on this route (ADR 0007 §C.7, amendment #39). Two parties
// poll it, and one reference time would let the prover's period lock the page out on every
// retry; and there is nothing here to protect — no proof to verify, no answer to hand over. A
// stranger who holds the code already has everything this route returns. The prover paces
// itself by the `interval` the offer response advertised.
//
// A malformed code is `404`, the same as an unknown one: a registered code is always
// well-formed, so a malformed one is unknown by construction, and a stranger probing learns
// nothing from the difference.
func (h *Handler) readOffer(w http.ResponseWriter, code string) {
	if err := checkCode(code); err != nil {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	o, ok := h.store.getOffer(code, h.clock())
	if !ok {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	var request any // null until taken, then the id — the shape a poller switches on
	if o.request != "" {
		request = o.request
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":      o.code,
		"scope":     scopeOrEmpty(o.scope),
		"valid_for": o.validFor,
		"request":   request,
		"expires":   o.expires.UTC().Format(time.RFC3339),
	})
}

// answerBody is what the CLI posts.
type answerBody struct {
	Principal  string          `json:"principal"`
	Possession string          `json:"possession"`
	Authority  json.RawMessage `json:"authority,omitempty"`
}

// answer verifies BEFORE storing, which is the whole point of the route (§4): the proof is
// checked against the binding recomputed from the STORED request and the CONFIGURED
// audience, and the authority is admitted by the service's law. Anything else is refused
// and nothing is written, so junk cannot be deposited against a pending request.
//
// A request is consumed by its first verified answer: a second one is `409`, not a
// silent overwrite. Two CLIs racing to answer one login is a real situation (a person with
// two terminals), and the winner must be the one whose proof was stored.
func (h *Handler) answer(w http.ResponseWriter, r *http.Request, idHex string) {
	var body answerBody
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	principal, err := keytext.DecodeKey(body.Principal)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}
	possession, err := hex.DecodeString(body.Possession)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}

	// SNAPSHOT, VERIFY OUTSIDE THE LOCK, RE-LOCK TO STORE.
	//
	// AdmitAuthority is the SERVICE's code: it may read a database, call thesmos, or block
	// on a network. Running it while holding the store's mutex would let one service's law
	// stall every other login in the process — a handler whose throughput is decided by
	// somebody else's callback. Signature verification is cheaper but is moved out for the
	// same reason: neither needs the lock, because the binding's inputs are immutable after
	// begin (see store.snapshot).
	//
	// What CAN change while unlocked is whether the request is still unanswered, so both
	// checks are REPEATED on re-lock. The window is real: two CLIs answering one login is an
	// ordinary situation — a person with two terminals — and the second must get 409, not
	// overwrite the first.
	now := h.clock()
	rec, answered, err := h.store.snapshot(idHex, now)
	if errors.Is(err, errExpired) {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	if answered {
		writeError(w, http.StatusConflict, errInvalidRequest)
		return
	}

	// The binding is recomputed by the scheme from the stored request and h.audience;
	// nothing here reconstructs it, and nothing takes an audience from the message.
	if !login.Verify(principal, h.audience, h.request(&rec), possession) {
		writeError(w, http.StatusForbidden, errInvalidGrant)
		return
	}
	if h.admit != nil {
		if err := h.admit(rec.browser, principal, body.Authority); err != nil {
			writeError(w, http.StatusForbidden, errInvalidGrant)
			return
		}
	}

	conflict := false
	err = h.store.update(idHex, h.clock(), func(live *record) error {
		if live.answered != nil {
			// Another answer won while this one was being verified. Storing here would
			// discard a proof the browser may already have collected.
			conflict = true
			return nil
		}
		live.answered = &answer{
			Principal:  body.Principal,
			Possession: body.Possession,
			Authority:  body.Authority,
		}
		return nil
	})
	if errors.Is(err, errExpired) {
		// It expired during verification. Refusing is right: the person's approval was for
		// a request that no longer exists, and the browser has stopped waiting.
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	if conflict {
		writeError(w, http.StatusConflict, errInvalidRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CollectHeader carries the browser's collect proof. Exported because a browser client has
// to spell it, and one spelling in one place is how the two halves stay agreed.
const CollectHeader = "Archon-Collect"

// collect hands the answer to the browser ONCE and drops the record.
//
// The proof is what makes this safe to expose on a guessable-looking URL: the collect proof
// is made by the request's own browser key (role 0x02), so a stranger who saw the id cannot
// take the answer. The service also gets a liveness signal from it — ADR 0007 §B's reason
// for the poll proving K at all.
func (h *Handler) collect(w http.ResponseWriter, r *http.Request, idHex string) {
	proof, err := hex.DecodeString(r.Header.Get(CollectHeader))
	if err != nil || len(proof) == 0 {
		writeError(w, http.StatusForbidden, errInvalidGrant)
		return
	}

	// THE ORDER HERE IS THE FIX caa FOUND. The interval is checked WITHOUT writing the
	// timer; the proof is verified; only then does the timer advance, inside the same
	// critical section that takes the answer. Advancing it before verification let a
	// stranger polling junk every four seconds hold the real browser at 429 indefinitely —
	// slow_down turned into a denial of service handed to anyone who saw the id.
	//
	// A stranger is therefore not rate-limited at all here. That is correct: they get 403
	// every time, and ADR 0007 §B says to add no rate limiting beyond slow_down, which
	// exists for the legitimate client's benefit rather than as a guard.
	now := h.clock()
	allowed, err := h.store.pollAllowed(idHex, now, h.interval)
	if errors.Is(err, errExpired) {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	if !allowed {
		writeError(w, http.StatusTooManyRequests, errSlowDown)
		return
	}

	// Verification is outside the lock, for the same reason as in answer: it needs no
	// shared state, and a poll per pending login should not serialise against every other
	// request in the process.
	rec, _, err := h.store.snapshot(idHex, now)
	if errors.Is(err, errExpired) {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	if !login.VerifyCollect(h.audience, h.request(&rec), proof) {
		writeError(w, http.StatusForbidden, errInvalidGrant)
		return
	}

	// One critical section: advance the timer, and take-and-drop if an answer is waiting.
	payload, err := h.store.collectAnswer(idHex, h.clock())
	if errors.Is(err, errExpired) {
		writeError(w, http.StatusNotFound, errExpiredToken)
		return
	}
	if payload == nil {
		writeError(w, http.StatusAccepted, errPendingCode)
		return
	}
	// NOT writeJSON: the authority payload is opaque bytes and an encoder would compact and
	// HTML-escape it. See writeCollected.
	writeCollected(w, payload)
}

// request turns a stored record into the scheme's Request. It is the only place the two
// shapes meet, so the field mapping is stated once.
func (h *Handler) request(rec *record) *login.Request {
	return &login.Request{
		ID:       rec.id,
		Nonce:    rec.nonce,
		Browser:  rec.browser,
		Scope:    rec.scope,
		ValidFor: rec.validFor,
	}
}
