package login

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	sdk "github.com/Bitspark/archon/sdk/go/login"
)

const audience = "https://dawn.example/api"

// A deterministic clock and a deterministic entropy source, which is why this suite never
// sleeps and never flakes. Both are constructor arguments precisely so a test can own them
// (ADR 0007 §B); production passes time.Now and crypto/rand.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// countingEntropy fills each request with a distinct, predictable pattern, so an id and a
// nonce are never accidentally equal and a failure names which one was wrong.
type countingEntropy struct{ n byte }

func (e *countingEntropy) fill(b []byte) error {
	e.n++
	for i := range b {
		b[i] = e.n
	}
	return nil
}

func newTestHandler(t *testing.T, admit AdmitAuthority) (*Handler, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	entropy := &countingEntropy{}
	h, err := New(Config{
		Audience: audience,
		Admit:    admit,
		Clock:    clock.Now,
		Entropy:  entropy.fill,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, clock
}

func do(h *Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func seedFor(b byte) []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return seed
}

// decode reads a JSON response body, failing the test rather than the caller.
func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", w.Code, w.Body.String())
	}
	return out
}

// THE WHOLE PROTOCOL, browser and CLI played against the handler with the real sdk. This is
// the test ADR 0007 §B asks each lane to carry, and it is the one that would notice if any
// part of this package quietly stopped meaning what §4 says.
func TestEndToEnd(t *testing.T) {
	var admitted struct {
		called             bool
		browser, principal []byte
		authority          json.RawMessage
	}
	h, _ := newTestHandler(t, func(browser, principal []byte, authority json.RawMessage) error {
		admitted.called = true
		admitted.browser, admitted.principal, admitted.authority = browser, principal, authority
		return nil
	})

	browserSeed, personSeed := seedFor(1), seedFor(100)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)

	// BEGIN — the browser opens a request.
	w := do(h, http.MethodPost, "/", map[string]any{
		"browser":   keytext.EncodeKey(browserKey),
		"scope":     []string{"read:projects", "read:campaigns"},
		"valid_for": 28800,
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("begin = %d, want 201: %s", w.Code, w.Body.String())
	}
	begun := decode(t, w)
	id, _ := begun["id"].(string)
	if id == "" {
		t.Fatal("begin returned no id")
	}
	// The verification_uri is what the browser shows the person to type, and the CLI's
	// grammar (§2.1) requires exactly this shape — audience, then /login/, then the hex id.
	if got, want := begun["verification_uri"], audience+"/login/"+id; got != want {
		t.Fatalf("verification_uri = %v, want %v", got, want)
	}
	if begun["expires_in"] != float64(300) || begun["interval"] != float64(5) {
		t.Fatalf("expires_in/interval = %v/%v, want 300/5", begun["expires_in"], begun["interval"])
	}
	// The nonce is the SERVER's and must clear the scheme's floor.
	nonce, err := hex.DecodeString(begun["nonce"].(string))
	if err != nil || len(nonce) < 16 {
		t.Fatalf("nonce = %v (%d bytes), want ≥16 bytes of hex", begun["nonce"], len(nonce))
	}

	// READ — the CLI fetches what it is being asked to sign.
	w = do(h, http.MethodGet, "/"+id, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("read = %d, want 200: %s", w.Code, w.Body.String())
	}
	read := decode(t, w)
	// THE RESPONSE MUST NOT CARRY AN AUDIENCE. A CLI that would read one is a CLI that can
	// be told to sign for someone else (Finding 1), so its absence is a property worth a
	// test rather than a convention worth a comment.
	if _, present := read["audience"]; present {
		t.Fatal("the read response carries an audience; it must never be on the wire")
	}
	if read["id"] != id || read["nonce"] != begun["nonce"] {
		t.Fatalf("read disagrees with begin: %v", read)
	}

	// ANSWER — the CLI proves possession over the request, with the scheme.
	idBytes, _ := hex.DecodeString(id)
	req := &sdk.Request{
		ID: idBytes, Nonce: nonce, Browser: browserKey,
		Scope: []string{"read:projects", "read:campaigns"}, ValidFor: 28800,
	}
	proof, err := sdk.Prove(personSeed, audience, req)
	if err != nil {
		t.Fatalf("sdk.Prove: %v", err)
	}
	principal := keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed))
	w = do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
		"principal":  principal,
		"possession": hex.EncodeToString(proof),
		"authority":  json.RawMessage(`{"grants":["read:projects"]}`),
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("answer = %d, want 204: %s", w.Code, w.Body.String())
	}
	if !admitted.called {
		t.Fatal("AdmitAuthority was not consulted")
	}
	if !bytes.Equal(admitted.browser, browserKey) {
		t.Fatal("AdmitAuthority got the wrong browser key")
	}
	if string(admitted.authority) != `{"grants":["read:projects"]}` {
		t.Fatalf("the authority reached the law altered: %s", admitted.authority)
	}

	// COLLECT — the browser proves K and takes the answer.
	collect, err := sdk.ProveCollect(browserSeed, audience, req)
	if err != nil {
		t.Fatalf("sdk.ProveCollect: %v", err)
	}
	w = do(h, http.MethodGet, "/"+id+"/answer", nil,
		map[string]string{CollectHeader: hex.EncodeToString(collect)})
	if w.Code != http.StatusOK {
		t.Fatalf("collect = %d, want 200: %s", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if got["principal"] != principal || got["possession"] != hex.EncodeToString(proof) {
		t.Fatalf("collected answer differs from the one posted: %v", got)
	}

	// ONCE, and then the record is gone (§4). The second collect is indistinguishable from
	// an id that never existed.
	w = do(h, http.MethodGet, "/"+id+"/answer", nil,
		map[string]string{CollectHeader: hex.EncodeToString(collect)})
	if w.Code != http.StatusNotFound {
		t.Fatalf("second collect = %d, want 404 — the answer is handed over once", w.Code)
	}
}

// A proof-only service: no AdmitAuthority, no authority payload. §3.4 allows the field to be
// absent, and ADR 0007 §B says a nil admitter means the proof alone suffices.
func TestProofOnlyServiceNeedsNoAuthority(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	browserSeed, personSeed := seedFor(2), seedFor(200)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)

	w := do(h, http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(browserKey), "scope": []string{}, "valid_for": 60,
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("begin = %d: %s", w.Code, w.Body.String())
	}
	begun := decode(t, w)
	id := begun["id"].(string)
	// An empty scope is a LIST, never null — a client should not need a special case.
	if s, ok := begun["scope"].([]any); !ok || len(s) != 0 {
		t.Fatalf("empty scope encoded as %#v, want []", begun["scope"])
	}

	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey, Scope: []string{}, ValidFor: 60}
	proof, _ := sdk.Prove(personSeed, audience, req)
	w = do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
		"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
		"possession": hex.EncodeToString(proof),
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("answer without authority = %d, want 204: %s", w.Code, w.Body.String())
	}
}

// Everything §4 says to refuse. Each of these would otherwise be a way to deposit or take
// something that was never proved.
func TestRefusals(t *testing.T) {
	browserSeed, personSeed := seedFor(3), seedFor(30)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)

	// A pending request to attack, rebuilt per subtest so the cases cannot interfere.
	setup := func(t *testing.T, admit AdmitAuthority) (*Handler, *testClock, string, *sdk.Request) {
		t.Helper()
		h, clock := newTestHandler(t, admit)
		w := do(h, http.MethodPost, "/", map[string]any{
			"browser": keytext.EncodeKey(browserKey), "scope": []string{"read:projects"}, "valid_for": 3600,
		}, nil)
		if w.Code != http.StatusCreated {
			t.Fatalf("begin = %d", w.Code)
		}
		begun := decode(t, w)
		id := begun["id"].(string)
		idBytes, _ := hex.DecodeString(id)
		nonce, _ := hex.DecodeString(begun["nonce"].(string))
		return h, clock, id, &sdk.Request{
			ID: idBytes, Nonce: nonce, Browser: browserKey,
			Scope: []string{"read:projects"}, ValidFor: 3600,
		}
	}

	t.Run("a proof by the wrong key is refused and NOTHING is stored", func(t *testing.T) {
		h, _, id, req := setup(t, nil)
		imposter := seedFor(77)
		proof, _ := sdk.Prove(imposter, audience, req)
		// Claiming to be the person while signing with another key.
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403", w.Code)
		}
		// And the request must still be answerable by the real holder: a refused answer
		// that consumed the request would be a denial of service by anyone who saw the id.
		good, _ := sdk.Prove(personSeed, audience, req)
		w = do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(good),
		}, nil)
		if w.Code != http.StatusNoContent {
			t.Fatalf("the real answer after a refused one = %d, want 204", w.Code)
		}
	})

	t.Run("a proof for another audience is refused", func(t *testing.T) {
		h, _, id, req := setup(t, nil)
		// The same request, proved against a different service. This is the phishing case
		// the whole derived-audience rule exists for, seen from the server's side.
		proof, _ := sdk.Prove(personSeed, "https://evil.example", req)
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403 — the binding names the audience", w.Code)
		}
	})

	t.Run("a proof over a wider scope than was asked is refused", func(t *testing.T) {
		h, _, id, req := setup(t, nil)
		wider := *req
		wider.Scope = []string{"read:projects", "publish:everything"}
		proof, _ := sdk.Prove(personSeed, audience, &wider)
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403 — the scope is bound, so a wider delegation cannot verify", w.Code)
		}
	})

	t.Run("the law can refuse, and then nothing is stored", func(t *testing.T) {
		h, _, id, req := setup(t, func(browser, principal []byte, authority json.RawMessage) error {
			return errors.New("the law says no")
		})
		proof, _ := sdk.Prove(personSeed, audience, req)
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
			"authority":  json.RawMessage(`{"nope":true}`),
		}, nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403", w.Code)
		}
		// The browser must still be told "pending", not handed a refused answer.
		collect, _ := sdk.ProveCollect(browserSeed, audience, req)
		w = do(h, http.MethodGet, "/"+id+"/answer", nil,
			map[string]string{CollectHeader: hex.EncodeToString(collect)})
		if w.Code != http.StatusAccepted {
			t.Fatalf("collect after a refused answer = %d, want 202 authorization_pending", w.Code)
		}
	})

	t.Run("a request is consumed by its first verified answer", func(t *testing.T) {
		h, _, id, req := setup(t, nil)
		proof, _ := sdk.Prove(personSeed, audience, req)
		body := map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}
		if w := do(h, http.MethodPost, "/"+id+"/answer", body, nil); w.Code != http.StatusNoContent {
			t.Fatalf("first answer = %d", w.Code)
		}
		if w := do(h, http.MethodPost, "/"+id+"/answer", body, nil); w.Code != http.StatusConflict {
			t.Fatalf("second answer = %d, want 409", w.Code)
		}
	})

	t.Run("a stranger cannot collect", func(t *testing.T) {
		h, _, id, req := setup(t, nil)
		proof, _ := sdk.Prove(personSeed, audience, req)
		do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		// Someone who saw the URL, holding a key that is not the request's browser key.
		stranger, _ := sdk.ProveCollect(seedFor(9), audience, req)
		w := do(h, http.MethodGet, "/"+id+"/answer", nil,
			map[string]string{CollectHeader: hex.EncodeToString(stranger)})
		if w.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403 — collect proves K", w.Code)
		}
		// A login proof is not a collect proof: the roles are distinct (§3.3).
		w = do(h, http.MethodGet, "/"+id+"/answer", nil,
			map[string]string{CollectHeader: hex.EncodeToString(proof)})
		if w.Code != http.StatusForbidden {
			t.Fatalf("a role-0x01 proof collected = %d, want 403", w.Code)
		}
		// And no header at all.
		if w := do(h, http.MethodGet, "/"+id+"/answer", nil, nil); w.Code != http.StatusForbidden {
			t.Fatalf("collect with no proof = %d, want 403", w.Code)
		}
	})

	t.Run("polling faster than the interval is slowed down", func(t *testing.T) {
		h, clock, id, req := setup(t, nil)
		collect, _ := sdk.ProveCollect(browserSeed, audience, req)
		hdr := map[string]string{CollectHeader: hex.EncodeToString(collect)}
		if w := do(h, http.MethodGet, "/"+id+"/answer", nil, hdr); w.Code != http.StatusAccepted {
			t.Fatalf("first poll = %d, want 202", w.Code)
		}
		if w := do(h, http.MethodGet, "/"+id+"/answer", nil, hdr); w.Code != http.StatusTooManyRequests {
			t.Fatalf("immediate second poll = %d, want 429 slow_down", w.Code)
		}
		clock.advance(DefaultInterval)
		if w := do(h, http.MethodGet, "/"+id+"/answer", nil, hdr); w.Code != http.StatusAccepted {
			t.Fatalf("poll after the interval = %d, want 202", w.Code)
		}
	})

	t.Run("an unverified poll does not hold the browser in slow_down", func(t *testing.T) {
		// caa's finding. The timer must advance only for a poll whose collect proof
		// VERIFIED — otherwise a stranger polling junk faster than the interval keeps the
		// real browser at 429 forever, and slow_down becomes a denial of service handed to
		// anyone who saw the id.
		h, _, id, req := setup(t, nil)
		junk := map[string]string{CollectHeader: hex.EncodeToString(make([]byte, 64))}
		for i := 0; i < 5; i++ {
			if w := do(h, http.MethodGet, "/"+id+"/answer", nil, junk); w.Code != http.StatusForbidden {
				t.Fatalf("junk poll %d = %d, want 403", i, w.Code)
			}
		}
		// The real browser, polling immediately after all that, must NOT be slowed down:
		// none of those polls was a poll.
		collect, _ := sdk.ProveCollect(browserSeed, audience, req)
		w := do(h, http.MethodGet, "/"+id+"/answer", nil,
			map[string]string{CollectHeader: hex.EncodeToString(collect)})
		if w.Code != http.StatusAccepted {
			t.Fatalf("the real browser after five junk polls = %d, want 202", w.Code)
		}
	})

	t.Run("everything about an expired request is 404", func(t *testing.T) {
		h, clock, id, req := setup(t, nil)
		clock.advance(DefaultTTL + time.Second)
		if w := do(h, http.MethodGet, "/"+id, nil, nil); w.Code != http.StatusNotFound {
			t.Fatalf("read = %d, want 404", w.Code)
		}
		proof, _ := sdk.Prove(personSeed, audience, req)
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("answer = %d, want 404", w.Code)
		}
		if got := decode(t, w)["error"]; got != errExpiredToken {
			t.Fatalf("error = %v, want %q", got, errExpiredToken)
		}
	})

	t.Run("an unknown id is indistinguishable from an expired one", func(t *testing.T) {
		h, _, _, _ := setup(t, nil)
		w := do(h, http.MethodGet, "/"+strings.Repeat("ab", 16), nil, nil)
		if w.Code != http.StatusNotFound || decode(t, w)["error"] != errExpiredToken {
			t.Fatalf("= %d %s; a stranger must not learn which ids exist", w.Code, w.Body.String())
		}
	})
}

// The door: what begin refuses before a request exists at all.
func TestBeginRefusals(t *testing.T) {
	browserKey := crypto.PublicKeyFromSeed(seedFor(4))
	ok := keytext.EncodeKey(browserKey)
	for _, c := range []struct {
		name string
		body map[string]any
	}{
		{"browser is not key text", map[string]any{"browser": "7a91", "scope": []string{"a"}, "valid_for": 60}},
		{"valid_for is zero", map[string]any{"browser": ok, "scope": []string{"a"}, "valid_for": 0}},
		{"a scope entry is empty", map[string]any{"browser": ok, "scope": []string{""}, "valid_for": 60}},
		{"a scope entry has a control character", map[string]any{"browser": ok, "scope": []string{"read:\x1b[2Jx"}, "valid_for": 60}},
		{"an unknown field", map[string]any{"browser": ok, "scope": []string{"a"}, "valid_for": 60, "audience": "https://evil.example"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newTestHandler(t, nil)
			w := do(h, http.MethodPost, "/", c.body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("= %d, want 400: %s", w.Code, w.Body.String())
			}
		})
	}
}

// The audience is configuration, and a misconfiguration is a startup error an operator can
// read — not a panic, and not a handler that half-works.
func TestNewRefusesABadAudience(t *testing.T) {
	// Each of these DERIVES (by §2.1) to something other than itself, so a handler
	// configured with one would bind a string the CLI never produces and every proof would
	// fail with nothing on either side saying why. A misconfiguration must be a startup
	// error an operator can read, not a comment nobody reaches.
	for _, bad := range []string{
		"",
		"https://dawn.example/api/",    // trailing slash
		"https://Dawn.Example/api",     // uppercase host
		"https://dawn.example:443/api", // explicit default port
		"wss://dawn.example/api",       // a scheme that folds
		"HTTPS://dawn.example/api",     // uppercase scheme
		"https://dawn.example/api?x=1", // a query
		"dawn.example/api",             // no scheme
	} {
		_, err := New(Config{Audience: bad})
		if err == nil {
			t.Fatalf("New accepted audience %q", bad)
		}
	}
	// And the error must NAME the spelling the CLI will derive, so the fix is in the
	// message rather than in a document the operator has to find.
	_, err := New(Config{Audience: "https://Dawn.Example/api"})
	if err == nil || !strings.Contains(err.Error(), "https://dawn.example/api") {
		t.Fatalf("error = %v; it must name the derived spelling", err)
	}
	// The canonical one is accepted.
	if _, err := New(Config{Audience: "https://dawn.example/api"}); err != nil {
		t.Fatalf("New rejected a canonical audience: %v", err)
	}
}

// Mounting under a prefix is the normal case (ADR 0007 §B: it is a mounted handler), so the
// routes must be relative to wherever the service put it.
func TestMountedUnderAPrefix(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	mux := http.NewServeMux()
	mux.Handle("/api/login", http.StripPrefix("/api/login", h))
	mux.Handle("/api/login/", http.StripPrefix("/api/login", h))

	body, _ := json.Marshal(map[string]any{
		"browser":   keytext.EncodeKey(crypto.PublicKeyFromSeed(seedFor(5))),
		"scope":     []string{"read:projects"},
		"valid_for": 60,
	})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("begin under a prefix = %d, want 201: %s", w.Code, w.Body.String())
	}
	id := decode(t, w)["id"].(string)

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/login/"+id, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read under a prefix = %d, want 200", w.Code)
	}
}

// Sweep is optional tidiness, not correctness — records expire on read regardless. The test
// says which, so nobody later "fixes" the absence of a sweeper goroutine.
func TestSweepIsOptional(t *testing.T) {
	h, clock := newTestHandler(t, nil)
	do(h, http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(crypto.PublicKeyFromSeed(seedFor(6))), "scope": []string{"a"}, "valid_for": 60,
	}, nil)
	if n := h.Sweep(); n != 0 {
		t.Fatalf("swept %d live records", n)
	}
	clock.advance(DefaultTTL + time.Second)
	if n := h.Sweep(); n != 1 {
		t.Fatalf("swept %d expired records, want 1", n)
	}
}

// ---- THE OFFERS FORM (docs/login.md §4.1) ------------------------------------------------
//
// The prover starts, the page finishes. Two routes and one member; the binding and the
// proofs are the same, so every case below ends in the same sdk calls the page-started form
// ends in. Names and cases mirror the rs and ts suites.

// page is the address a service configures for the offers form. Only the tests that need the
// optional `page` key set it; the rest run without one, so both shapes are on the wire.
const page = "https://dawn.example/login"

func newPagedHandler(t *testing.T) (*Handler, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	entropy := &countingEntropy{}
	h, err := New(Config{Audience: audience, Page: page, Clock: clock.Now, Entropy: entropy.fill})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, clock
}

// codeFor is a well-formed code — 16 bytes as 32 lowercase hex characters — distinct per
// byte, so two tests never share one by accident.
func codeFor(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 16)) }

func offerBody(code string, scope []string, validFor uint32) map[string]any {
	return map[string]any{"code": code, "scope": scope, "valid_for": validFor}
}

// beginOn is §4's begin body with the one member §4.1 adds.
func beginOn(code string, browserKey []byte, scope []string, validFor uint32) map[string]any {
	return map[string]any{
		"browser": keytext.EncodeKey(browserKey), "scope": scope, "valid_for": validFor, "offer": code,
	}
}

func TestOffersEndToEnd(t *testing.T) {
	h, _ := newPagedHandler(t)
	browserSeed, personSeed := seedFor(60), seedFor(160)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	scope := []string{"read:projects", "read:campaigns"}
	code := codeFor(0xa1)

	// The prover offers what it is willing to delegate, to a key it does not know yet.
	w := do(h, http.MethodPost, "/offers", offerBody(code, scope, 28800), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("offer = %d: %s", w.Code, w.Body.String())
	}
	offered := decode(t, w)
	if offered["code"] != code {
		t.Fatalf("the offer echoed code %v, want %s", offered["code"], code)
	}
	// The code rides in the page's FRAGMENT — the part of an address a browser never sends
	// to any server — so the page's script reads it and no log does (§4.1 "The code").
	if offered["page"] != page+"#"+code {
		t.Fatalf("page = %v, want %s", offered["page"], page+"#"+code)
	}
	if offered["expires_in"] != float64(DefaultTTL/time.Second) || offered["interval"] != float64(DefaultInterval/time.Second) {
		t.Fatalf("expires_in/interval = %v/%v", offered["expires_in"], offered["interval"])
	}
	if _, present := offered["audience"]; present {
		t.Fatal("an audience on the wire — Finding 1 applies to this route too")
	}

	// The page reads the offer: open, nothing taken yet.
	w = do(h, http.MethodGet, "/offers/"+code, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("read offer = %d: %s", w.Code, w.Body.String())
	}
	read := decode(t, w)
	if read["request"] != nil {
		t.Fatalf("an open offer must say request: null, got %v", read["request"])
	}
	if got := read["scope"].([]any); len(got) != 2 || got[0] != "read:projects" || got[1] != "read:campaigns" {
		t.Fatalf("the page read scope %v", got)
	}

	// The page begins on the offer with EXACTLY what was offered.
	w = do(h, http.MethodPost, "/", beginOn(code, browserKey, scope, 28800), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("begin on the offer = %d: %s", w.Code, w.Body.String())
	}
	begun := decode(t, w)
	if _, present := begun["offer"]; present {
		t.Fatal("begin's response must not echo the offer — one shape for begin")
	}
	id := begun["id"].(string)

	// The prover polls: taken, and by that request.
	w = do(h, http.MethodGet, "/offers/"+code, nil, nil)
	if got := decode(t, w)["request"]; got != id {
		t.Fatalf("after begin the offer names request %v, want %s", got, id)
	}

	// The prover reads the request the offer names. The CLI re-checks scope and validity
	// itself (§4.1 rule 2); here the server's word is checked to be the offer's.
	w = do(h, http.MethodGet, "/"+id, nil, nil)
	request := decode(t, w)
	if request["browser"] != keytext.EncodeKey(browserKey) || request["valid_for"] != float64(28800) {
		t.Fatalf("the request is not the offer's: %v", request)
	}
	if got := request["scope"].([]any); len(got) != 2 || got[0] != "read:projects" || got[1] != "read:campaigns" {
		t.Fatalf("the request's scope %v is not the offer's", got)
	}

	// ...it answers with the sdk, the page collects, and the proof verifies — §4 unchanged.
	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(request["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey, Scope: scope, ValidFor: 28800}
	proof, err := sdk.Prove(personSeed, audience, req)
	if err != nil {
		t.Fatalf("sdk.Prove: %v", err)
	}
	principal := keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed))
	w = do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
		"principal": principal, "possession": hex.EncodeToString(proof),
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("answer = %d: %s", w.Code, w.Body.String())
	}
	collect, _ := sdk.ProveCollect(browserSeed, audience, req)
	w = do(h, http.MethodGet, "/"+id+"/answer", nil, map[string]string{CollectHeader: hex.EncodeToString(collect)})
	if w.Code != http.StatusOK {
		t.Fatalf("collect = %d: %s", w.Code, w.Body.String())
	}
	answer := decode(t, w)
	possession, _ := hex.DecodeString(answer["possession"].(string))
	if answer["principal"] != principal || !sdk.Verify(crypto.PublicKeyFromSeed(personSeed), audience, req, possession) {
		t.Fatal("the collected answer is not the person's verified proof")
	}

	// ...and the offer died with its request (§4.1 "State").
	w = do(h, http.MethodGet, "/offers/"+code, nil, nil)
	if w.Code != http.StatusNotFound || decode(t, w)["error"] != errExpiredToken {
		t.Fatalf("after collection the offer must be gone: %d %s", w.Code, w.Body.String())
	}
}

// THE offer_mismatch FAMILY from the shared fixture: a request naming an offer whose scope or
// validity differ IN ANY WAY is refused before anything is stored and before any key is
// involved. "Nothing stored" and "no key involved" are asserted, not assumed: a refused begin
// draws no entropy (the id and nonce would be the first thing built), and the offer is still
// open afterwards. Then the FRAMING: the exact offer is accepted, and accepted once.
func TestAMismatchedRequestIsRefusedBeforeAnythingIsStored(t *testing.T) {
	family := readWireFixture(t).OfferMismatch
	if len(family.Cases) == 0 {
		t.Fatal("the fixture states no offer_mismatch cases — a pin nobody can fail is not a pin")
	}
	clock := &testClock{now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	entropy := &countingEntropy{}
	h, err := New(Config{Audience: audience, Clock: clock.Now, Entropy: entropy.fill})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	browserKey := crypto.PublicKeyFromSeed(seedFor(61))
	code := codeFor(0xa2)
	if w := do(h, http.MethodPost, "/offers", offerBody(code, family.Offer.Scope, family.Offer.ValidFor), nil); w.Code != http.StatusCreated {
		t.Fatalf("offer = %d: %s", w.Code, w.Body.String())
	}
	drawn := entropy.n

	for _, c := range family.Cases {
		t.Run(c.Name, func(t *testing.T) {
			w := do(h, http.MethodPost, "/", beginOn(code, browserKey, c.Scope, c.ValidFor), nil)
			if w.Code != c.Status {
				t.Fatalf("= %d, fixture says %d: %s", w.Code, c.Status, w.Body.String())
			}
			if got := decode(t, w)["error"]; got != c.Error {
				t.Fatalf("error = %v, fixture says %v", got, c.Error)
			}
			if entropy.n != drawn {
				t.Fatal("a refused begin drew entropy — a request was built before the offer was checked")
			}
			if got := decode(t, do(h, http.MethodGet, "/offers/"+code, nil, nil))["request"]; got != nil {
				t.Fatalf("a refused begin took the offer: request = %v", got)
			}
		})
	}

	// A begin that passes the offer check but fails LATER must not take the offer either: the
	// take happens with the store, in one critical section, and a body refused after the check
	// never reaches it.
	w := do(h, http.MethodPost, "/", map[string]any{
		"browser": "not a key", "scope": family.Offer.Scope, "valid_for": family.Offer.ValidFor, "offer": code,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a malformed browser key on an exact offer = %d, want 400", w.Code)
	}
	if got := decode(t, do(h, http.MethodGet, "/offers/"+code, nil, nil))["request"]; got != nil {
		t.Fatalf("a begin refused after the offer check took the offer: request = %v", got)
	}

	// THE FRAMING: the exact offer is accepted — else the cases above proved nothing — and
	// the same request a second time is refused as taken (one offer, one request).
	w = do(h, http.MethodPost, "/", beginOn(code, browserKey, family.Offer.Scope, family.Offer.ValidFor), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("the exact offer must be accepted (201), else the family proves nothing: %d %s", w.Code, w.Body.String())
	}
	w = do(h, http.MethodPost, "/", beginOn(code, browserKey, family.Offer.Scope, family.Offer.ValidFor), nil)
	if w.Code != http.StatusConflict || decode(t, w)["error"] != errInvalidRequest {
		t.Fatalf("a second request on a taken offer = %d %s, want 409 invalid_request", w.Code, w.Body.String())
	}
}

func TestOneOfferOneRequest(t *testing.T) {
	h, clock := newTestHandler(t, nil)
	browserKey := crypto.PublicKeyFromSeed(seedFor(62))
	scope := []string{"read:projects"}
	code := codeFor(0xa3)

	if w := do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil); w.Code != http.StatusCreated {
		t.Fatalf("offer = %d", w.Code)
	}
	// One code, one offer: a second registration under a LIVE code is a conflict.
	if w := do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil); w.Code != http.StatusConflict {
		t.Fatalf("a second offer under a live code = %d, want 409", w.Code)
	}
	// One offer, one request: the first matching request takes it, the next is refused,
	// and the poll keeps naming the first.
	w := do(h, http.MethodPost, "/", beginOn(code, browserKey, scope, 3600), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("begin on the offer = %d: %s", w.Code, w.Body.String())
	}
	first := decode(t, w)["id"]
	if w := do(h, http.MethodPost, "/", beginOn(code, crypto.PublicKeyFromSeed(seedFor(63)), scope, 3600), nil); w.Code != http.StatusConflict {
		t.Fatalf("a second request on a taken offer = %d, want 409", w.Code)
	}
	if got := decode(t, do(h, http.MethodGet, "/offers/"+code, nil, nil))["request"]; got != first {
		t.Fatalf("the offer names %v after the refused second request, want %v", got, first)
	}

	// Past its TTL the offer is dead — and so is its request — and the code is FREE again: a
	// new registration replaces the dead one rather than colliding with it.
	clock.advance(DefaultTTL + time.Second)
	if w := do(h, http.MethodGet, "/offers/"+code, nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("an expired offer = %d, want 404", w.Code)
	}
	if w := do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil); w.Code != http.StatusCreated {
		t.Fatalf("re-registering a dead code = %d, want 201: %s", w.Code, w.Body.String())
	}
}

// Unknown, expired and MALFORMED codes are one answer, on both routes a code can name an
// offer by: a registered code is always well-formed, so a malformed one is unknown by
// construction, and a stranger probing learns nothing from the difference. Only the offer
// route itself says 400 to a malformed code — that one is the prover's own mistake, and the
// prover is who is told.
func TestAnUnknownExpiredOrMalformedCodeIs404Alike(t *testing.T) {
	h, clock := newTestHandler(t, nil)
	browserKey := crypto.PublicKeyFromSeed(seedFor(64))
	good := codeFor(0xab)
	malformed := map[string]string{
		"unknown":        codeFor(0xee),
		"not hex":        "zz" + good[2:],
		"odd length":     good[:31],
		"too short":      good[:30],
		"uppercase":      strings.ToUpper(good),
		"a stray slash?": good[:16] + "%2f" + good[19:],
	}
	for name, code := range malformed {
		t.Run(name, func(t *testing.T) {
			w := do(h, http.MethodGet, "/offers/"+code, nil, nil)
			if w.Code != http.StatusNotFound || decode(t, w)["error"] != errExpiredToken {
				t.Fatalf("read = %d %s, want 404 expired_token", w.Code, w.Body.String())
			}
			w = do(h, http.MethodPost, "/", beginOn(code, browserKey, []string{"read:projects"}, 3600), nil)
			if w.Code != http.StatusNotFound || decode(t, w)["error"] != errExpiredToken {
				t.Fatalf("begin = %d %s, want 404 expired_token", w.Code, w.Body.String())
			}
		})
	}

	// An expired one, from both sides.
	if w := do(h, http.MethodPost, "/offers", offerBody(good, []string{"read:projects"}, 3600), nil); w.Code != http.StatusCreated {
		t.Fatalf("offer = %d", w.Code)
	}
	clock.advance(DefaultTTL + time.Second)
	if w := do(h, http.MethodGet, "/offers/"+good, nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("an expired offer read = %d, want 404", w.Code)
	}
	if w := do(h, http.MethodPost, "/", beginOn(good, browserKey, []string{"read:projects"}, 3600), nil); w.Code != http.StatusNotFound {
		t.Fatalf("a begin on an expired offer = %d, want 404", w.Code)
	}

	// Whereas the prover registering a malformed code is told so: 400, nothing registered.
	for _, code := range []string{"zz" + good[2:], good[:31], good[:30], strings.ToUpper(good)} {
		w := do(h, http.MethodPost, "/offers", offerBody(code, []string{"read:projects"}, 3600), nil)
		if w.Code != http.StatusBadRequest || decode(t, w)["error"] != errInvalidRequest {
			t.Fatalf("offer with code %q = %d %s, want 400 invalid_request", code, w.Code, w.Body.String())
		}
	}
}

// An offer dies with its request (§4.1 "State"), and the store knows it without anything
// running at collection time: liveness consults the record the offer points at.
func TestAnOfferDiesWithItsRequest(t *testing.T) {
	h, clock := newTestHandler(t, nil)
	browserSeed, personSeed := seedFor(65), seedFor(165)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	scope := []string{"read:projects"}

	// Collected: the request is handed over once and dropped, and the offer goes with it.
	code := codeFor(0xa5)
	do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil)
	begun := decode(t, do(h, http.MethodPost, "/", beginOn(code, browserKey, scope, 3600), nil))
	id := begun["id"].(string)
	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey, Scope: scope, ValidFor: 3600}
	proof, _ := sdk.Prove(personSeed, audience, req)
	if w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
		"principal": keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)), "possession": hex.EncodeToString(proof),
	}, nil); w.Code != http.StatusNoContent {
		t.Fatalf("answer = %d", w.Code)
	}
	collect, _ := sdk.ProveCollect(browserSeed, audience, req)
	if w := do(h, http.MethodGet, "/"+id+"/answer", nil, map[string]string{CollectHeader: hex.EncodeToString(collect)}); w.Code != http.StatusOK {
		t.Fatalf("collect = %d", w.Code)
	}
	// Not read first: Sweep must see the orphan on its own, not because a read dropped it.
	if n := h.Sweep(); n != 1 {
		t.Fatalf("Sweep after collection = %d, want 1 (the orphaned offer)", n)
	}
	if w := do(h, http.MethodGet, "/offers/"+code, nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("the collected login's offer = %d, want 404", w.Code)
	}

	// Never taken and past its TTL: swept as well, counted once.
	do(h, http.MethodPost, "/offers", offerBody(codeFor(0xa6), scope, 3600), nil)
	if n := h.Sweep(); n != 0 {
		t.Fatalf("swept %d live offers", n)
	}
	clock.advance(DefaultTTL + time.Second)
	if n := h.Sweep(); n != 1 {
		t.Fatalf("Sweep past the TTL = %d, want 1", n)
	}
}

// Everything that would make an offer impossible to begin on is refused at the offer route,
// where the prover hears it — not at the page's begin, where only the page would.
func TestOfferRefusalsAtTheDoor(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	scope := []string{"read:projects"}
	refused := func(t *testing.T, what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusBadRequest || decode(t, w)["error"] != errInvalidRequest {
			t.Fatalf("%s = %d %s, want 400 invalid_request", what, w.Code, w.Body.String())
		}
	}
	refused(t, "an unparseable body", doRaw(h, http.MethodPost, "/offers", "{"))
	refused(t, "an unknown member", doRaw(h, http.MethodPost, "/offers",
		`{"code":"`+codeFor(0xb1)+`","scope":["read:projects"],"valid_for":3600,"audience":"https://evil.example"}`))
	refused(t, "a validity of zero", do(h, http.MethodPost, "/offers", offerBody(codeFor(0xb2), scope, 0), nil))
	refused(t, "a scope entry that could lie on screen", do(h, http.MethodPost, "/offers",
		offerBody(codeFor(0xb3), []string{"read:\x1b[2Jx"}, 3600), nil))
	refused(t, "an empty scope entry", do(h, http.MethodPost, "/offers", offerBody(codeFor(0xb4), []string{""}, 3600), nil))
	// A scope that cannot BIND (an entry over the binding's u16 field) is refused now, not at
	// the page's begin, where an offer nobody could ever begin on would sit until it expired.
	refused(t, "a scope that cannot bind", do(h, http.MethodPost, "/offers",
		offerBody(codeFor(0xb5), []string{strings.Repeat("a", sdk.MaxFieldSize+1)}, 3600), nil))
	// None of the refused codes exists afterwards.
	for _, b := range []byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5} {
		if w := do(h, http.MethodGet, "/offers/"+codeFor(b), nil, nil); w.Code != http.StatusNotFound {
			t.Fatalf("a refused offer %x exists: %d", b, w.Code)
		}
	}
	// Methods: the offer route is POST, the read route is GET, and nothing else.
	if w := do(h, http.MethodGet, "/offers", nil, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /offers = %d, want 405", w.Code)
	}
	if w := do(h, http.MethodPost, "/offers/"+codeFor(0xb6), nil, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /offers/<code> = %d, want 405", w.Code)
	}

	// The page's fragment is where the code goes, so a configured page with one is refused
	// where the operator can read it.
	if _, err := New(Config{Audience: audience, Page: page + "#already"}); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("New accepted a page carrying a fragment: %v", err)
	}
	// And a handler WITHOUT a page emits no page key — the fixture calls it optional, and
	// optional means absent when unconfigured, never null or empty.
	got := decode(t, do(h, http.MethodPost, "/offers", offerBody(codeFor(0xb7), scope, 3600), nil))
	if _, present := got["page"]; present {
		t.Fatalf("a handler with no page configured emitted page = %v", got["page"])
	}
}

// THE OFFER ROUTE IS NOT PACED (ADR 0007 §C.7, amendment #39). §4's collect is polled by one
// party with a proof; this route is read by the page AND polled by the prover, and one
// reference time would let the prover's period lock the page out on every retry. There is
// also nothing here to protect — no proof to verify, no answer to hand over; a stranger with
// the code already has everything the route returns. The prover paces itself by the
// advertised interval. This test is the regression guard for that ruling: ten reads at one
// instant all answer 200, and the offer stays open.
func TestTheOfferRouteIsNotPaced(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	code := codeFor(0xa7)
	do(h, http.MethodPost, "/offers", offerBody(code, []string{"read:projects"}, 3600), nil)
	for i := 0; i < 10; i++ {
		w := do(h, http.MethodGet, "/offers/"+code, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("poll %d = %d %s — the offer route must not be paced", i, w.Code, w.Body.String())
		}
		if decode(t, w)["request"] != nil {
			t.Fatalf("poll %d: the offer was taken by nobody", i)
		}
	}
}

// EVERY ERROR CODE THE FIXTURE PINS, each driven by the situation that produces it — never by
// building a response by hand. A code listed in a file three lanes read, that no lane actually
// emits, is a lie in the one place they all trust; the count assertion at the end is what keeps
// this from drifting into a subset. rs and ts carried this test from the start; this lane did
// not, and the §4.1 codes would have been pinned in two lanes of three without it.
func TestEveryPinnedErrorCodeIsEmitted(t *testing.T) {
	fixture := readWireFixture(t).Errors
	if len(fixture.Codes) == 0 {
		t.Fatal("the fixture pins no error codes — a pin nobody can fail is not a pin")
	}
	got := map[string]*httptest.ResponseRecorder{}
	h, _ := newTestHandler(t, nil)
	browserSeed, personSeed := seedFor(20), seedFor(210)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	principal := keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed))

	got["begin_malformed"] = doRaw(h, http.MethodPost, "/", "{")
	got["read_unknown_or_expired"] = do(h, http.MethodGet, "/"+strings.Repeat("ab", 16), nil, nil)

	id, req := openLogin(t, h, browserSeed)
	good, _ := sdk.Prove(personSeed, audience, req)
	answer := func(proof []byte) map[string]any {
		return map[string]any{"principal": principal, "possession": hex.EncodeToString(proof)}
	}
	got["answer_malformed"] = doRaw(h, http.MethodPost, "/"+id+"/answer", "{")
	wrong, _ := sdk.Prove(seedFor(211), audience, req)
	got["answer_proof_refused"] = do(h, http.MethodPost, "/"+id+"/answer", answer(wrong), nil)

	// Two polls back to back: the first is pending, the second is too fast.
	collect, _ := sdk.ProveCollect(browserSeed, audience, req)
	hdr := map[string]string{CollectHeader: hex.EncodeToString(collect)}
	got["collect_pending"] = do(h, http.MethodGet, "/"+id+"/answer", nil, hdr)
	got["collect_too_fast"] = do(h, http.MethodGet, "/"+id+"/answer", nil, hdr)
	got["collect_proof_refused"] = do(h, http.MethodGet, "/"+id+"/answer", nil, nil)

	if w := do(h, http.MethodPost, "/"+id+"/answer", answer(good), nil); w.Code != http.StatusNoContent {
		t.Fatalf("the good answer = %d", w.Code)
	}
	got["answer_already_answered"] = do(h, http.MethodPost, "/"+id+"/answer", answer(good), nil)

	// A service whose law refuses.
	refusing, _ := newTestHandler(t, func(_, _ []byte, _ json.RawMessage) error { return errors.New("no") })
	id2, req2 := openLogin(t, refusing, seedFor(21))
	proof2, _ := sdk.Prove(personSeed, audience, req2)
	got["answer_authority_refused"] = do(refusing, http.MethodPost, "/"+id2+"/answer", answer(proof2), nil)

	// A request that ran out of time, approached from both sides.
	timed, clock3 := newTestHandler(t, nil)
	browser3 := seedFor(22)
	id3, req3 := openLogin(t, timed, browser3)
	proof3, _ := sdk.Prove(personSeed, audience, req3)
	collect3, _ := sdk.ProveCollect(browser3, audience, req3)
	clock3.advance(DefaultTTL + time.Second)
	got["answer_expired"] = do(timed, http.MethodPost, "/"+id3+"/answer", answer(proof3), nil)
	got["collect_expired"] = do(timed, http.MethodGet, "/"+id3+"/answer", nil,
		map[string]string{CollectHeader: hex.EncodeToString(collect3)})

	// The offers form (§4.1). One fixture entry, several drives where the spec says the
	// answers are indistinguishable: every drive must match the pinned entry.
	scope := []string{"read:projects"}
	got["offer_malformed"] = do(h, http.MethodPost, "/offers", offerBody(codeFor(0xc1)[:30], scope, 3600), nil)
	code := codeFor(0xc2)
	if w := do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil); w.Code != http.StatusCreated {
		t.Fatalf("offer = %d", w.Code)
	}
	got["offer_code_taken"] = do(h, http.MethodPost, "/offers", offerBody(code, scope, 3600), nil)
	got["begin_offer_mismatch"] = do(h, http.MethodPost, "/", beginOn(code, browserKey, []string{"read:campaigns"}, 3600), nil)
	if w := do(h, http.MethodPost, "/", beginOn(code, browserKey, scope, 3600), nil); w.Code != http.StatusCreated {
		t.Fatalf("begin on the offer = %d", w.Code)
	}
	got["begin_offer_taken"] = do(h, http.MethodPost, "/", beginOn(code, browserKey, scope, 3600), nil)

	expired, clock4 := newTestHandler(t, nil)
	stale := codeFor(0xc3)
	do(expired, http.MethodPost, "/offers", offerBody(stale, scope, 3600), nil)
	clock4.advance(DefaultTTL + time.Second)
	alike := func(name string, drives ...*httptest.ResponseRecorder) {
		t.Helper()
		got[name] = drives[0]
		for i, w := range drives[1:] {
			if w.Code != drives[0].Code || w.Body.String() != drives[0].Body.String() {
				t.Errorf("%s: drive %d answered %d %s, drive 0 answered %d %s — the spec says indistinguishable",
					name, i+1, w.Code, w.Body.String(), drives[0].Code, drives[0].Body.String())
			}
		}
	}
	alike("offer_unknown_or_expired",
		do(h, http.MethodGet, "/offers/"+codeFor(0xc4), nil, nil),
		do(expired, http.MethodGet, "/offers/"+stale, nil, nil),
		do(h, http.MethodGet, "/offers/"+strings.ToUpper(code), nil, nil))
	alike("begin_offer_unknown_or_expired",
		do(h, http.MethodPost, "/", beginOn(codeFor(0xc4), browserKey, scope, 3600), nil),
		do(expired, http.MethodPost, "/", beginOn(stale, browserKey, scope, 3600), nil),
		do(h, http.MethodPost, "/", beginOn(code[:30], browserKey, scope, 3600), nil))

	for name, want := range fixture.Codes {
		w, ok := got[name]
		if !ok {
			t.Fatalf("the fixture pins error %q, which no case here drives", name)
		}
		t.Run(name, func(t *testing.T) {
			if w.Code != want.Status {
				t.Fatalf("status = %d, fixture says %d: %s", w.Code, want.Status, w.Body.String())
			}
			body := decode(t, w)
			if body["error"] != want.Error {
				t.Fatalf("code = %v, fixture says %v", body["error"], want.Error)
			}
			// The body carries the code and NOTHING else: no description, no echoed id, so a
			// stranger probing ids learns nothing from the difference between them.
			for k := range body {
				allowed := false
				for _, key := range fixture.Keys {
					allowed = allowed || key == k
				}
				if !allowed {
					t.Errorf("an error body carries %q", k)
				}
			}
		})
	}
	if len(got) != len(fixture.Codes) {
		t.Fatalf("%d cases driven here, %d pinned — a case the fixture does not pin", len(got), len(fixture.Codes))
	}
}

// THE CROSS-LANE WIRE FIXTURE. A cross-lane smoke run is impractical for a server (each
// lane needs its own socket and runtime), so server/testdata/login-wire.json is where go,
// rs and ts are held to one wire format instead. Each lane's suite reads the SAME file and
// asserts the exact key set it emits per route.
//
// It pins KEYS and their absence, not values: an id and a nonce are random by construction,
// and pinning them would pin the entropy rather than the format. Where lanes drift is the
// key set — a field added on one side, a null where a list belongs, an `audience` creeping
// into a response.
func TestWireShapesMatchTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "login-wire.json"))
	if err != nil {
		t.Fatalf("could not read the shared wire fixture: %v", err)
	}
	var fixture struct {
		Responses map[string]struct {
			Status        int      `json:"status"`
			Keys          []string `json:"keys"`
			OptionalKeys  []string `json:"optional_keys"`
			ForbiddenKeys []string `json:"forbidden_keys"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("the shared wire fixture is not the expected JSON: %v", err)
	}
	if len(fixture.Responses) == 0 {
		t.Fatal("the fixture pins no responses — a fixture nobody can fail is not a pin")
	}

	// Drive one whole login, capturing what each route actually emitted. A handler WITH a
	// page configured, so the offer response's optional `page` key is on the wire and the
	// fixture's optional_keys is exercised rather than trivially satisfied by absence.
	h, _ := newPagedHandler(t)
	browserSeed, personSeed := seedFor(8), seedFor(80)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)

	emitted := map[string]*httptest.ResponseRecorder{}
	emitted["begin"] = do(h, http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(browserKey), "scope": []string{"read:projects"}, "valid_for": 3600,
	}, nil)
	begun := decode(t, emitted["begin"])
	id := begun["id"].(string)
	emitted["read"] = do(h, http.MethodGet, "/"+id, nil, nil)

	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey,
		Scope: []string{"read:projects"}, ValidFor: 3600}
	proof, _ := sdk.Prove(personSeed, audience, req)
	emitted["answer"] = do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
		"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
		"possession": hex.EncodeToString(proof),
	}, nil)
	collect, _ := sdk.ProveCollect(browserSeed, audience, req)
	emitted["collect"] = do(h, http.MethodGet, "/"+id+"/answer", nil,
		map[string]string{CollectHeader: hex.EncodeToString(collect)})

	// And the offers form (§4.1): the prover offers, the page begins on the offer, the
	// prover reads the offer back — the two routes and the one member the fixture pins.
	code := codeFor(0x08)
	emitted["offer"] = do(h, http.MethodPost, "/offers", offerBody(code, []string{"read:projects"}, 3600), nil)
	emitted["begin_on_offer"] = do(h, http.MethodPost, "/",
		beginOn(code, crypto.PublicKeyFromSeed(seedFor(9)), []string{"read:projects"}, 3600), nil)
	emitted["offer_read"] = do(h, http.MethodGet, "/offers/"+code, nil, nil)

	for route, want := range fixture.Responses {
		w, ok := emitted[route]
		if !ok {
			t.Fatalf("the fixture pins route %q, which this test does not exercise", route)
		}
		t.Run(route, func(t *testing.T) {
			if w.Code != want.Status {
				t.Fatalf("status = %d, fixture says %d", w.Code, want.Status)
			}
			if len(want.Keys) == 0 {
				if body := strings.TrimSpace(w.Body.String()); body != "" {
					t.Fatalf("fixture says no body, got %q", body)
				}
				return
			}
			got := decode(t, w)
			for _, k := range want.Keys {
				if _, present := got[k]; !present {
					t.Errorf("missing key %q", k)
				}
			}
			for _, k := range want.ForbiddenKeys {
				if _, present := got[k]; present {
					t.Errorf("key %q must NOT be on the wire", k)
				}
			}
			// No key beyond what the fixture allows: a lane that adds a field is a lane
			// the other two do not match, which is exactly what this file exists to catch.
			allowed := map[string]bool{}
			for _, k := range append(append([]string{}, want.Keys...), want.OptionalKeys...) {
				allowed[k] = true
			}
			for k := range got {
				if !allowed[k] {
					t.Errorf("unexpected key %q — the fixture does not allow it", k)
				}
			}
		})
	}
}

// A SERVICE'S LAW MUST NOT BE ABLE TO STALL THE HANDLER.
//
// AdmitAuthority is the service's own code and may read a database, call thesmos, or block
// on a network. If it ran while the store's mutex was held, one slow law would decide the
// throughput of every login in the process — including reads and polls that have nothing to
// do with it. This test holds an admitter open and requires an unrelated route to answer
// meanwhile; it fails by TIMING OUT rather than by asserting, because a lock held across a
// callback does not produce a wrong value, it produces a wait.
func TestABlockingAdmitterDoesNotBlockTheHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h, _ := newTestHandler(t, func(browser, principal []byte, authority json.RawMessage) error {
		close(entered)
		<-release // hold the law open
		return nil
	})

	browserSeed, personSeed := seedFor(11), seedFor(110)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	w := do(h, http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(browserKey), "scope": []string{"read:projects"}, "valid_for": 3600,
	}, nil)
	begun := decode(t, w)
	id := begun["id"].(string)
	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey,
		Scope: []string{"read:projects"}, ValidFor: 3600}
	proof, _ := sdk.Prove(personSeed, audience, req)

	answered := make(chan int, 1)
	go func() {
		w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
			"authority":  json.RawMessage(`{"slow":true}`),
		}, nil)
		answered <- w.Code
	}()

	<-entered // the law is now inside, and would be holding the lock if we had it wrong

	done := make(chan int, 1)
	go func() { done <- do(h, http.MethodGet, "/"+id, nil, nil).Code }()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("concurrent read = %d, want 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a read blocked behind AdmitAuthority — the law is holding the store's lock")
	}

	close(release)
	if code := <-answered; code != http.StatusNoContent {
		t.Fatalf("answer = %d, want 204", code)
	}
}

// The re-check on re-lock, which is what makes verifying outside the lock safe: if a second
// answer lands while the first is still being verified, exactly one wins and the other is a
// 409 — never a silent overwrite of a proof the browser may already hold.
func TestASecondAnswerDuringVerificationLosesCleanly(t *testing.T) {
	// Only the FIRST admitter waits. An earlier version of this gated on a buffered channel,
	// which deadlocked: once the test drained it, the second admitter could send into it and
	// block as well. sync.Once says "first" without depending on who has drained what.
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h, _ := newTestHandler(t, func(browser, principal []byte, authority json.RawMessage) error {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
		return nil
	})

	browserSeed, personSeed := seedFor(12), seedFor(120)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	w := do(h, http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(browserKey), "scope": []string{"read:projects"}, "valid_for": 3600,
	}, nil)
	begun := decode(t, w)
	id := begun["id"].(string)
	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey,
		Scope: []string{"read:projects"}, ValidFor: 3600}
	proof, _ := sdk.Prove(personSeed, audience, req)
	body := map[string]any{
		"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
		"possession": hex.EncodeToString(proof),
	}

	first := make(chan int, 1)
	go func() { first <- do(h, http.MethodPost, "/"+id+"/answer", body, nil).Code }()
	<-entered // the first is inside the law, having passed its snapshot check

	// The second runs the whole path while the first is suspended, and wins the store.
	if code := do(h, http.MethodPost, "/"+id+"/answer", body, nil).Code; code != http.StatusNoContent {
		t.Fatalf("second answer = %d, want 204 — it should reach the store first", code)
	}
	close(release)
	if code := <-first; code != http.StatusConflict {
		t.Fatalf("first answer = %d, want 409 — it must not overwrite the stored proof", code)
	}
}
