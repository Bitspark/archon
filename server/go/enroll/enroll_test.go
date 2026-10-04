package enroll

// ADR 0010 §8's enrollment failure tests for the Go lane — substitution and replay — through
// net/http itself. archon defines no enrollment route, so the test plays the service: a route
// that takes its session from a cookie, reads {"transaction","proof"} and calls Complete, in
// front of an integration that keeps records and associations in memory under one lock. Every
// refusal is checked twice: the status, and that no association was recorded.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	sdk "github.com/Bitspark/archon/sdk/go/enroll"
)

const audience = "https://dawn.example/api"

var (
	keySeed   = bytes.Repeat([]byte{0x61}, 32)
	otherSeed = bytes.Repeat([]byte{0x62}, 32)
	newKey    = crypto.PublicKeyFromSeed(keySeed)
	t0        = time.Unix(1_789_034_640, 0)
)

type association struct {
	account, key []byte
	purpose      string
}

// service is the integration: pending records, consumed marks and recorded associations, all
// under one lock, which is what makes its Complete atomic.
type service struct {
	mu           sync.Mutex
	records      map[string]Record
	consumed     map[string]bool
	associations []association

	loadDown, completeDown, wrongRecord bool
}

func (s *service) persist(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[string(r.Transaction)] = r
}

func (s *service) Load(_ context.Context, transaction []byte) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadDown {
		return Record{}, errors.New("the database is down")
	}
	r, ok := s.records[string(transaction)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if s.wrongRecord {
		for _, other := range s.records {
			if !bytes.Equal(other.Transaction, transaction) {
				return other, nil
			}
		}
	}
	return r, nil
}

func (s *service) Complete(_ context.Context, r Record) Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeDown {
		return Unavailable
	}
	if s.consumed[string(r.Transaction)] {
		return NotPending
	}
	s.consumed[string(r.Transaction)] = true
	s.associations = append(s.associations, association{r.Account, r.NewKey, r.Purpose})
	return Completed
}

func (s *service) recorded() []association {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]association(nil), s.associations...)
}

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.at = t; c.mu.Unlock() }

type harness struct {
	srv      *httptest.Server
	enroller *Enroller
	svc      *service
	clock    *clock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	svc := &service{records: map[string]Record{}, consumed: map[string]bool{}}
	c := &clock{at: t0}
	var n byte
	e, err := New(Config{
		Audience: audience, Integration: svc, Clock: c.now,
		Entropy: func(b []byte) error {
			n++
			for i := range b {
				b[i] = n
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{enroller: e, svc: svc, clock: c}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll/complete", func(w http.ResponseWriter, r *http.Request) {
		var authorization []byte
		if c, err := r.Cookie("session"); err == nil {
			authorization = []byte(c.Value)
		}
		var body struct{ Transaction, Proof string }
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		transaction, err1 := hex.DecodeString(body.Transaction)
		proof, err2 := hex.DecodeString(body.Proof)
		if err1 != nil || err2 != nil {
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		if _, err := e.Complete(r.Context(), transaction, proof, authorization); err != nil {
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Error(w, err.Error(), refusal.Status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// begin is the service's begin route, after it validated the session: prepare, persist, and
// hand the client its challenge.
func (h *harness) begin(t *testing.T, session string, key []byte) Challenge {
	t.Helper()
	r, ch, err := h.enroller.Prepare(Begin{
		Authorization: []byte(session), Account: []byte("acct-1"), Purpose: "add-key", NewKey: key,
		Intent: []byte("acct-1 add-key restrictions=none"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.persist(r)
	return ch
}

// prove is the client: the proof by seed over the challenge, with edit applied to what it
// signs.
func prove(t *testing.T, seed []byte, ch Challenge, edit ...func(*sdk.Request, *string)) []byte {
	t.Helper()
	req := &sdk.Request{Nonce: ch.Nonce, Transaction: ch.Transaction, Purpose: ch.Purpose,
		NewKey: crypto.PublicKeyFromSeed(seed), IntentDigest: ch.IntentDigest}
	aud := ch.Audience
	for _, f := range edit {
		f(req, &aud)
	}
	proof, err := sdk.Prove(seed, aud, req)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (h *harness) complete(t *testing.T, session string, transaction, proof []byte) int {
	t.Helper()
	body := fmt.Sprintf(`{"transaction":%q,"proof":%q}`, hex.EncodeToString(transaction), hex.EncodeToString(proof))
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/enroll/complete", strings.NewReader(body))
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAnEnrollmentCompletesOnceWithTheRecordsAssociation(t *testing.T) {
	h := newHarness(t)
	ch := h.begin(t, "s1", newKey)
	if got := h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch)); got != http.StatusNoContent {
		t.Fatalf("status %d", got)
	}
	got := h.svc.recorded()
	if len(got) != 1 || string(got[0].account) != "acct-1" || !bytes.Equal(got[0].key, newKey) || got[0].purpose != "add-key" {
		t.Fatalf("recorded %+v", got)
	}
	digest := sha256.Sum256([]byte("acct-1 add-key restrictions=none"))
	if ch.Audience != audience || !bytes.Equal(ch.IntentDigest, digest[:]) || len(ch.Nonce) < 16 || !ch.Expires.Equal(t0.Add(DefaultTTL)) {
		t.Fatalf("challenge %+v", ch)
	}
}

func TestThereIsNoPossessionAloneMode(t *testing.T) {
	if _, err := New(Config{Audience: audience}); err == nil {
		t.Fatal("New built an enroller with no authorizing integration")
	}
	if _, err := New(Config{Audience: "", Integration: &service{}}); err == nil {
		t.Fatal("New accepted an empty audience")
	}
}

func TestNothingCanBeSubstituted(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, h *harness) int
		want int
	}{
		{"another key proves for the record's key", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			// otherSeed signs a binding naming its own key: the record names newKey.
			return h.complete(t, "s1", ch.Transaction, prove(t, otherSeed, ch))
		}, http.StatusUnauthorized},
		{"another transaction's proof", func(t *testing.T, h *harness) int {
			first, second := h.begin(t, "s1", newKey), h.begin(t, "s1", newKey)
			return h.complete(t, "s1", first.Transaction, prove(t, keySeed, second))
		}, http.StatusUnauthorized},
		{"a proof over another purpose", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch, func(r *sdk.Request, _ *string) { r.Purpose = "recover" }))
		}, http.StatusUnauthorized},
		{"a proof for another audience", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch, func(_ *sdk.Request, a *string) { *a = "https://evil.example/api" }))
		}, http.StatusUnauthorized},
		{"a proof over another intent", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			other := sha256.Sum256([]byte("acct-2 add-key"))
			return h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch, func(r *sdk.Request, _ *string) { r.IntentDigest = other[:] }))
		}, http.StatusUnauthorized},
		{"a proof over another nonce", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch, func(r *sdk.Request, _ *string) { r.Nonce = bytes.Repeat([]byte{0xee}, 16) }))
		}, http.StatusUnauthorized},
		{"another session completes", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "s2", ch.Transaction, prove(t, keySeed, ch))
		}, http.StatusForbidden},
		{"no session completes", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "", ch.Transaction, prove(t, keySeed, ch))
		}, http.StatusForbidden},
		{"an unknown transaction", func(t *testing.T, h *harness) int {
			ch := h.begin(t, "s1", newKey)
			return h.complete(t, "s1", bytes.Repeat([]byte{0x77}, 16), prove(t, keySeed, ch))
		}, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			if got := c.run(t, h); got != c.want {
				t.Fatalf("status %d, want %d", got, c.want)
			}
			if n := len(h.svc.recorded()); n != 0 {
				t.Fatalf("%d associations recorded", n)
			}
		})
	}
}

func TestARecordWithNoAuthorizationCompletesForNoOne(t *testing.T) {
	// Prepare refuses to build one; a record the integration holds without one is still never
	// completed, least of all by a request that carries no session either.
	h := newHarness(t)
	ch := h.begin(t, "s1", newKey)
	h.svc.mu.Lock()
	r := h.svc.records[string(ch.Transaction)]
	r.Authorization = nil
	h.svc.records[string(ch.Transaction)] = r
	h.svc.mu.Unlock()
	if got := h.complete(t, "", ch.Transaction, prove(t, keySeed, ch)); got != http.StatusForbidden {
		t.Fatalf("status %d, want 403", got)
	}
	if n := len(h.svc.recorded()); n != 0 {
		t.Fatalf("%d associations recorded", n)
	}
}

func TestACompletedEnrollmentCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	ch := h.begin(t, "s1", newKey)
	proof := prove(t, keySeed, ch)
	if got := h.complete(t, "s1", ch.Transaction, proof); got != http.StatusNoContent {
		t.Fatalf("first: %d", got)
	}
	if got := h.complete(t, "s1", ch.Transaction, proof); got != http.StatusConflict {
		t.Fatalf("replay: %d, want 409", got)
	}
	// The same proof against a fresh transaction for the same key and session: its nonce and
	// transaction are not the ones the proof covers.
	fresh := h.begin(t, "s1", newKey)
	if got := h.complete(t, "s1", fresh.Transaction, proof); got != http.StatusUnauthorized {
		t.Fatalf("the proof replayed into a new transaction: %d, want 401", got)
	}
	if n := len(h.svc.recorded()); n != 1 {
		t.Fatalf("%d associations recorded, want 1", n)
	}
}

func TestConcurrentCompletionsRecordOne(t *testing.T) {
	h := newHarness(t)
	ch := h.begin(t, "s1", newKey)
	proof := prove(t, keySeed, ch)
	const n = 24
	statuses := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- h.complete(t, "s1", ch.Transaction, proof) }()
	}
	wg.Wait()
	close(statuses)
	ok := 0
	for st := range statuses {
		if st == http.StatusNoContent {
			ok++
		} else if st != http.StatusConflict {
			t.Fatalf("unexpected status %d", st)
		}
	}
	if ok != 1 || len(h.svc.recorded()) != 1 {
		t.Fatalf("%d completed, %d recorded; want 1 and 1", ok, len(h.svc.recorded()))
	}
}

func TestAnExpiredEnrollmentIsGone(t *testing.T) {
	for _, c := range []struct {
		at   time.Time
		want int
	}{
		{t0.Add(DefaultTTL - time.Second), http.StatusNoContent},
		{t0.Add(DefaultTTL), http.StatusNotFound},
	} {
		h := newHarness(t)
		ch := h.begin(t, "s1", newKey)
		h.clock.set(c.at)
		if got := h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch)); got != c.want {
			t.Fatalf("at t0+%s: %d, want %d", c.at.Sub(t0), got, c.want)
		}
	}
}

func TestAnIntegrationThatCannotAnswerFailsClosed(t *testing.T) {
	for _, c := range []struct {
		name  string
		fault func(s *service)
	}{
		{"load down", func(s *service) { s.loadDown = true }},
		{"complete down", func(s *service) { s.completeDown = true }},
		{"another transaction's record", func(s *service) { s.wrongRecord = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			ch := h.begin(t, "s1", newKey)
			_ = h.begin(t, "s1", newKey) // a second record, for wrongRecord to return
			c.fault(h.svc)
			if got := h.complete(t, "s1", ch.Transaction, prove(t, keySeed, ch)); got != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503", got)
			}
			if n := len(h.svc.recorded()); n != 0 {
				t.Fatalf("%d associations recorded", n)
			}
		})
	}
}

func TestPrepareRefusesWhatCouldNotComplete(t *testing.T) {
	h := newHarness(t)
	good := Begin{Authorization: []byte("s1"), Account: []byte("acct-1"), Purpose: "add-key", NewKey: newKey, Intent: []byte("i")}
	for name, edit := range map[string]func(b *Begin){
		"no authorization": func(b *Begin) { b.Authorization = nil },
		"no account":       func(b *Begin) { b.Account = nil },
		"a short key":      func(b *Begin) { b.NewKey = newKey[:31] },
		"no purpose":       func(b *Begin) { b.Purpose = "" },
		"a control char":   func(b *Begin) { b.Purpose = "add\nkey" },
	} {
		b := good
		edit(&b)
		if _, _, err := h.enroller.Prepare(b); err == nil {
			t.Errorf("%s: Prepare accepted it", name)
		}
	}
	if _, _, err := h.enroller.Prepare(good); err != nil {
		t.Fatalf("the good begin: %v", err)
	}
}
