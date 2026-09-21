package login

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// The store is one in-memory record per pending login and nothing else (ADR 0007 §B:
// store-minimal). Nothing is persisted, nothing survives the process, and a record leaves
// in exactly two ways: it expires, or it is collected. That is the whole lifetime.
//
// This is not a cache with a short TTL — it is a rendezvous. A login that outlives the
// person's attention is a login nobody is waiting for, so forgetting it is correct
// behaviour rather than a limitation.

// record is one pending login. It is written once at begin, gains an answer at most once,
// and is read until it is collected or expires.
type record struct {
	id       []byte
	nonce    []byte
	browser  []byte // K, 32 bytes
	scope    []string
	validFor uint32
	expires  time.Time

	// answered holds the CLI's answer once one has VERIFIED. A record with a nil answer
	// has never been successfully answered — an answer that failed verification is not
	// stored at all, so junk cannot be deposited against a pending request (§4).
	answered *answer

	// lastPoll is when the browser last asked to collect. It exists only to implement
	// RFC 8628's slow_down: a client polling faster than the interval is told to slow
	// down rather than served. It is not rate limiting in any wider sense, and ADR 0007
	// §B says not to add any.
	lastPoll time.Time
}

// answer is what the CLI posted and the browser collects, held verbatim between the two.
type answer struct {
	Principal  string          `json:"principal"`
	Possession string          `json:"possession"`
	Authority  json.RawMessage `json:"authority,omitempty"`
}

// offer is one registered offer (docs/login.md §4.1): what a prover is willing to delegate, to
// a key it does not know yet. It carries no key and no proof — what it carries is the code's
// confidentiality until it is taken. Written once at registration; only `request` changes,
// once, when the first matching request takes it.
type offer struct {
	code     string // lowercase hex — the map key and the URL segment; ≥ 16 bytes of the prover's entropy
	scope    []string
	validFor uint32
	expires  time.Time

	// request is the hex id of the request that took this offer, or "" while it is open. An
	// offer dies with its request (§4.1 "State"): once that record is gone — collected or
	// expired — the offer is gone too, which the store enforces on read like every expiry.
	request string
}

// The two refusals a request naming an offer can meet beyond errExpired. They become
// `409 invalid_request` (one offer, one request — §4.1 rule 5) and `400 invalid_request`
// (the request differs from the offer, in any way).
var (
	errTaken    = errors.New("login: the offer is already taken")
	errMismatch = errors.New("login: the request differs from the offer")
)

// store is two maps guarded by ONE mutex. A handler is used from many goroutines — one per
// request — so every path through it takes the lock, including the reads: an expiry check
// followed by an unguarded read is a race that returns a record another goroutine has just
// collected. One lock rather than one per map, because "begin on the offer" must check the
// offer, store the request and take the offer in a single critical section, and two locks
// would make that an ordering discipline instead of a fact.
type store struct {
	mu      sync.Mutex
	records map[string]*record
	offers  map[string]*offer
}

func newStore() *store {
	return &store{records: make(map[string]*record), offers: make(map[string]*offer)}
}

// key is the map key for an id: its lowercase hex, which is also how the id travels in
// URLs and JSON (§4). Keying by the hex rather than the bytes keeps one spelling of an id
// in one place; the bytes are what the binding uses and they live in the record.
func key(id []byte) string { return hex.EncodeToString(id) }

// put stores a fresh pending record.
func (s *store) put(r *record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key(r.id)] = r
}

// get returns the record for id if it exists AND has not expired, dropping it if it has.
//
// Expiry is enforced on READ rather than by a sweeper goroutine. A sweeper would be a
// second thing to own, to stop, and to get wrong in tests; expiring on read gives every
// route the same answer — an expired login is indistinguishable from one that never
// existed, which is also what §4 asks for (both are `404 expired_token`).
func (s *store) get(idHex string, now time.Time) (*record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[idHex]
	if !ok {
		return nil, false
	}
	if !now.Before(r.expires) {
		delete(s.records, idHex)
		return nil, false
	}
	return r, true
}

// update runs fn against a live record under the lock, so a check and the write it
// justifies cannot be separated by another request. Every mutation goes through here.
func (s *store) update(idHex string, now time.Time, fn func(*record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[idHex]
	if !ok {
		return errExpired
	}
	if !now.Before(r.expires) {
		delete(s.records, idHex)
		return errExpired
	}
	return fn(r)
}

// snapshot copies out what a verification needs, under the lock, and reports whether the
// record has already been answered.
//
// IT IS SAFE TO VERIFY AGAINST THIS COPY OUTSIDE THE LOCK, and the reason is a property of
// the record rather than of the caller: every field a binding is computed from — id, nonce,
// browser, scope, valid_for — is written ONCE at begin and never mutated. Only `answered`
// and `lastPoll` change, and neither enters a binding. So a snapshot cannot go stale in a
// way that matters to a proof; what CAN change is whether the request is still unanswered,
// which is why the caller re-checks that when it re-locks to store.
func (s *store) snapshot(idHex string, now time.Time) (rec record, answered bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[idHex]
	if !ok {
		return record{}, false, errExpired
	}
	if !now.Before(r.expires) {
		delete(s.records, idHex)
		return record{}, false, errExpired
	}
	return *r, r.answered != nil, nil
}

// pollAllowed reports whether a collect may proceed under the interval. It only READS
// lastPoll — writing it here is what caa found: a stranger polling junk every four seconds
// would advance the timer and keep the REAL browser at 429 forever, turning slow_down into a
// denial of service handed to anyone who saw the id. The timer advances in collectAnswer,
// after the proof has verified, so only a proven poll counts as a poll.
func (s *store) pollAllowed(idHex string, now time.Time, interval time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[idHex]
	if !ok {
		return false, errExpired
	}
	if !now.Before(r.expires) {
		delete(s.records, idHex)
		return false, errExpired
	}
	if !r.lastPoll.IsZero() && now.Sub(r.lastPoll) < interval {
		return false, nil
	}
	return true, nil
}

// collectAnswer advances the poll timer and, if an answer is waiting, TAKES IT AND DROPS THE
// RECORD IN THE SAME CRITICAL SECTION.
//
// One section, not two: taking the payload and deleting separately leaves a window in which
// a second proven collector reads the same answer, and §4 says the record is handed over
// ONCE. The timer is advanced here rather than before verification so that only a poll whose
// collect proof verified counts against the interval.
func (s *store) collectAnswer(idHex string, now time.Time) (*answer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[idHex]
	if !ok {
		return nil, errExpired
	}
	if !now.Before(r.expires) {
		delete(s.records, idHex)
		return nil, errExpired
	}
	r.lastPoll = now
	if r.answered == nil {
		return nil, nil // still pending
	}
	payload := r.answered
	delete(s.records, idHex)
	return payload, nil
}

// drop removes a record. Called when an answer has been collected: the login is over and
// nothing about it outlives that moment (§4).
func (s *store) drop(idHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, idHex)
}

// sweep drops every expired record and every dead offer. Nothing calls it on a timer — it
// exists so a service that keeps a handler alive for a long time can bound the maps from its
// own maintenance loop if it wants to. Without it, an abandoned login occupies its record
// until something asks for that id again, which may be never.
func (s *store) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, r := range s.records {
		if !now.Before(r.expires) {
			delete(s.records, k)
			n++
		}
	}
	// Offers after records, so an offer whose request just went is seen as orphaned.
	for k, o := range s.offers {
		if !s.offerLiveLocked(o, now) {
			delete(s.offers, k)
			n++
		}
	}
	return n
}

// offerLiveLocked is the one definition of a live offer, under the lock: unexpired, and — if
// a request has taken it — that request still present and unexpired. "Dies with its request"
// (§4.1) is enforced here, on every read, rather than by anything that runs when a request
// is collected: a record leaving is already one line in three places, and an offer that
// consults the record it points at can never disagree with it.
func (s *store) offerLiveLocked(o *offer, now time.Time) bool {
	if !now.Before(o.expires) {
		return false
	}
	if o.request == "" {
		return true
	}
	r, ok := s.records[o.request]
	return ok && now.Before(r.expires)
}

// putOffer registers an offer. It reports false — and stores nothing — when a LIVE offer is
// already registered under the code (§4.1: `409` for a code already registered and
// unexpired); a dead one under the same code is simply replaced, since the code is free again.
func (s *store) putOffer(o *offer, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live, ok := s.offers[o.code]; ok && s.offerLiveLocked(live, now) {
		return false
	}
	s.offers[o.code] = o
	return true
}

// getOffer returns a COPY of the live offer under code, dropping a dead one. A copy rather than
// the pointer, because `request` is written by takeOffer while a poll may be rendering it —
// the one field of an offer that changes after registration is the one field the poll reads.
func (s *store) getOffer(code string, now time.Time) (offer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.offers[code]
	if !ok {
		return offer{}, false
	}
	if !s.offerLiveLocked(o, now) {
		delete(s.offers, code)
		return offer{}, false
	}
	return *o, true
}

// matchesOffer is §4.1's "differs in any way", stated once: the same number of entries, each
// equal to its counterpart IN ORDER, and the same validity. A set comparison would let a page
// reorder what the person typed; a length comparison would let it swap an entry.
func matchesOffer(o *offer, scope []string, validFor uint32) bool {
	if validFor != o.validFor || len(scope) != len(o.scope) {
		return false
	}
	for i := range scope {
		if scope[i] != o.scope[i] {
			return false
		}
	}
	return true
}

// checkOffer answers, under the lock, whether a request with this scope and validity may take
// the offer: errExpired (unknown, expired or orphaned), errTaken, errMismatch, or nil. begin
// calls it BEFORE decoding the browser key or drawing entropy, so a page that alters what it
// was offered is refused before anything is stored and before any key is involved (§4.1).
func (s *store) checkOffer(code string, now time.Time, scope []string, validFor uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkOfferLocked(code, now, scope, validFor)
}

func (s *store) checkOfferLocked(code string, now time.Time, scope []string, validFor uint32) error {
	o, ok := s.offers[code]
	if !ok {
		return errExpired
	}
	if !s.offerLiveLocked(o, now) {
		delete(s.offers, code)
		return errExpired
	}
	if o.request != "" {
		return errTaken
	}
	if !matchesOffer(o, scope, validFor) {
		return errMismatch
	}
	return nil
}

// takeOffer stores the request AND marks the offer taken IN ONE CRITICAL SECTION, repeating
// every check of checkOffer first: the offer may have expired, been taken by another request,
// or — its request gone — died while this request was being built outside the lock. Two pages
// beginning on one code is ordinary (a person with two tabs), and exactly one must win.
func (s *store) takeOffer(code string, now time.Time, rec *record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOfferLocked(code, now, rec.scope, rec.validFor); err != nil {
		return err
	}
	id := key(rec.id)
	s.records[id] = rec
	s.offers[code].request = id
	return nil
}
