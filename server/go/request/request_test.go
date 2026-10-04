package request

// ADR 0010 §8's failure tests for the Go lane, through net/http itself: a real httptest.Server,
// requests on the wire (raw TCP where the exact request line matters), and the middleware in
// front of a handler that records whether it ran. Every refusal is checked twice: the status,
// and that the application never saw the request.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	sdk "github.com/Bitspark/archon/sdk/go/request"
)

const audience = "https://dawn.example/api"

var (
	seed      = bytes.Repeat([]byte{0x44}, 32)
	otherSeed = bytes.Repeat([]byte{0x55}, 32)
	t0        = time.Unix(1_789_034_640, 0)
)

// fixedClock is a clock a test moves by hand.
type fixedClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fixedClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fixedClock) set(t time.Time) { c.mu.Lock(); c.at = t; c.mu.Unlock() }

// app records what reached it.
type app struct {
	hits  atomic.Int32
	mu    sync.Mutex
	last  Authenticated
	reads []byte
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth, ok := FromContext(r.Context())
	if !ok {
		http.Error(w, "no authentication in context", http.StatusInternalServerError)
		return
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(r.Body)
	a.mu.Lock()
	a.last, a.reads = auth, body.Bytes()
	a.mu.Unlock()
	a.hits.Add(1)
	w.WriteHeader(http.StatusNoContent)
}

type harness struct {
	srv   *httptest.Server
	app   *app
	clock *fixedClock
	store *Memory
}

func newHarness(t *testing.T, store ReplayStore) *harness {
	t.Helper()
	clock := &fixedClock{at: t0.Add(5 * time.Second)}
	mem, _ := store.(*Memory)
	h := &harness{app: &app{}, clock: clock, store: mem}
	v := &Verifier{
		Policy: sdk.Policy{Audience: audience, Declared: []string{"idempotency-key"}, MaxLifetime: 300, Skew: 30},
		Store:  store,
		Clock:  clock.now,
	}
	h.srv = httptest.NewServer(v.Middleware(h.app))
	t.Cleanup(h.srv.Close)
	return h
}

// signed is a request signed by seed (or, with signer, a different key than keyid claims via a
// raw seed swap) for the given target and body, plus its header set.
type signed struct {
	method, target string
	body           []byte
	headers        [][2]string
}

func newNonce() []byte {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	return n
}

func sign(t *testing.T, method, target string, body []byte, opts ...func(*sdk.ToSign)) signed {
	t.Helper()
	ct := "application/json"
	in := sdk.ToSign{
		Method: method, Audience: audience, RequestTarget: target, Body: body, ContentType: &ct,
		Declared: [][2]string{{"idempotency-key", "k-1"}},
		Created:  t0.Unix(), Expires: t0.Unix() + 60, Nonce: newNonce(),
	}
	for _, o := range opts {
		o(&in)
	}
	_, h, err := sdk.Sign(seed, in)
	if err != nil {
		t.Fatal(err)
	}
	headers := [][2]string{
		{"Archon-Audience", h.ArchonAudience}, {"Content-Digest", h.ContentDigest},
		{"Signature-Input", h.SignatureInput}, {"Signature", h.Signature},
	}
	if in.ContentType != nil {
		headers = append(headers, [2]string{"Content-Type", *in.ContentType})
	}
	for _, d := range in.Declared {
		headers = append(headers, d)
	}
	return signed{method: method, target: target, body: body, headers: headers}
}

// send writes the request on a raw TCP connection, byte for byte — the request line exactly as
// given, which no client library would guarantee — and returns the status.
func (h *harness) send(t *testing.T, s signed) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: dawn.example\r\nContent-Length: %d\r\nConnection: close\r\n", s.method, s.target, len(s.body))
	for _, kv := range s.headers {
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	b.WriteString("\r\n")
	b.Write(s.body)
	if _, err := conn.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func without(headers [][2]string, name string) [][2]string {
	out := [][2]string{}
	for _, kv := range headers {
		if !strings.EqualFold(kv[0], name) {
			out = append(out, kv)
		}
	}
	return out
}

func replace(headers [][2]string, name, value string) [][2]string {
	out := without(headers, name)
	return append(out, [2]string{name, value})
}

var body = []byte(`{"name":"thing"}`)

func TestAnAuthenticatedRequestReachesTheApplicationWithWhatWasVerified(t *testing.T) {
	h := newHarness(t, NewMemory(t0.Add(-time.Hour)))
	if got := h.send(t, sign(t, "POST", "/api/v1/things?x=1", body)); got != http.StatusNoContent {
		t.Fatalf("status %d", got)
	}
	if h.app.hits.Load() != 1 || !bytes.Equal(h.app.last.Principal, crypto.PublicKeyFromSeed(seed)) {
		t.Fatalf("the application saw %+v", h.app.last)
	}
	if h.app.last.TargetURI != "https://dawn.example/api/v1/things?x=1" || !bytes.Equal(h.app.reads, body) {
		t.Fatalf("target %q, body %q", h.app.last.TargetURI, h.app.reads)
	}
}

func TestEveryRefusalKeepsTheRequestFromTheApplication(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T) signed
		want int
	}{
		{"wrong-key signer: keyid names one key, another signed", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			_, oh, _ := sdk.Sign(otherSeed, sdk.ToSign{Method: "POST", Audience: audience, RequestTarget: "/api/v1/things",
				Body: body, Created: t0.Unix(), Expires: t0.Unix() + 60, Nonce: newNonce()})
			s.headers = replace(s.headers, "Signature", oh.Signature)
			return s
		}, http.StatusUnauthorized},
		{"dropped-context signer: a raw signature over the base", func(t *testing.T) signed {
			ct := "application/json"
			p, err := sdk.Prepare(crypto.PublicKeyFromSeed(seed), sdk.ToSign{Method: "POST", Audience: audience, RequestTarget: "/api/v1/things",
				Body: body, ContentType: &ct, Declared: [][2]string{{"idempotency-key", "k-1"}}, Created: t0.Unix(), Expires: t0.Unix() + 60, Nonce: newNonce()})
			if err != nil {
				t.Fatal(err)
			}
			raw := crypto.Sign(seed, p.Signing.Message)
			s := sign(t, "POST", "/api/v1/things", body)
			s.headers = replace(replace(s.headers, "Signature-Input", p.Headers.SignatureInput), "Signature",
				"archon=:"+b64(raw)+":")
			return s
		}, http.StatusUnauthorized},
		{"path ambiguity: signed with an escape, sent decoded", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/a%2Fb", body)
			s.target = "/api/a/b"
			return s
		}, http.StatusUnauthorized},
		{"query ambiguity: parameters reordered", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things?a=1&b=2", body)
			s.target = "/api/v1/things?b=2&a=1"
			return s
		}, http.StatusUnauthorized},
		{"modified body", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.body = []byte(`{"name":"other"}`)
			return s
		}, http.StatusUnauthorized},
		{"emptied body", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.body = nil
			return s
		}, http.StatusUnauthorized},
		{"missing covered header", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.headers = without(s.headers, "Idempotency-Key")
			return s
		}, http.StatusUnauthorized},
		{"duplicated covered header", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.headers = append(s.headers, [2]string{"Idempotency-Key", "k-1"})
			return s
		}, http.StatusUnauthorized},
		{"a content coding", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.headers = append(s.headers, [2]string{"Content-Encoding", "identity"})
			return s
		}, http.StatusBadRequest},
		{"absolute-form request-target", func(t *testing.T) signed {
			s := sign(t, "POST", "/api/v1/things", body)
			s.target = "http://dawn.example/api/v1/things"
			return s
		}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, NewMemory(t0.Add(-time.Hour)))
			if got := h.send(t, c.make(t)); got != c.want {
				t.Fatalf("status %d, want %d", got, c.want)
			}
			if n := h.app.hits.Load(); n != 0 {
				t.Fatalf("the application ran %d times", n)
			}
		})
	}
}

func TestExpiryBounds(t *testing.T) {
	// created t0, expires t0+60, skew 30: acceptable on [t0−30, t0+90).
	for _, c := range []struct {
		at   time.Time
		want int
	}{
		{t0.Add(-30 * time.Second), http.StatusNoContent},
		{t0.Add(-31 * time.Second), http.StatusUnauthorized},
		{t0.Add(89 * time.Second), http.StatusNoContent},
		{t0.Add(90 * time.Second), http.StatusUnauthorized},
	} {
		h := newHarness(t, NewMemory(t0.Add(-time.Hour)))
		h.clock.set(c.at)
		if got := h.send(t, sign(t, "POST", "/api/v1/things", body)); got != c.want {
			t.Fatalf("at t0%+ds: status %d, want %d", c.at.Unix()-t0.Unix(), got, c.want)
		}
	}
}

func TestConcurrentCopiesOfOneProofAdmitOne(t *testing.T) {
	h := newHarness(t, NewMemory(t0.Add(-time.Hour)))
	s := sign(t, "POST", "/api/v1/things", body)
	const n = 24
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	for range n {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- h.send(t, s) }()
	}
	wg.Wait()
	close(statuses)
	ok := 0
	for st := range statuses {
		if st == http.StatusNoContent {
			ok++
		} else if st != http.StatusUnauthorized {
			t.Fatalf("unexpected status %d", st)
		}
	}
	if ok != 1 || h.app.hits.Load() != 1 {
		t.Fatalf("%d admitted, the application ran %d times; want 1 and 1", ok, h.app.hits.Load())
	}
}

// outage is a store that cannot answer.
type outage struct{}

func (outage) InsertIfAbsent(context.Context, ReplayEntry) Outcome { return Unavailable }

func TestAnUnavailableReplayStoreFailsClosed(t *testing.T) {
	h := newHarness(t, outage{})
	if got := h.send(t, sign(t, "POST", "/api/v1/things", body)); got != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", got)
	}
	if h.app.hits.Load() != 0 {
		t.Fatal("the application ran while the replay store was down")
	}
}

func TestFailoverToAnotherVerifierSharingTheStoreStillAdmitsOnce(t *testing.T) {
	shared := NewMemory(t0.Add(-time.Hour))
	first, second := newHarness(t, shared), newHarness(t, shared)
	s := sign(t, "POST", "/api/v1/things", body)
	if got := first.send(t, s); got != http.StatusNoContent {
		t.Fatalf("first verifier: %d", got)
	}
	if got := second.send(t, s); got != http.StatusUnauthorized {
		t.Fatalf("the second verifier admitted the same proof: %d", got)
	}
}

func TestARestartedProcessRefusesProofsItCannotKnowAbout(t *testing.T) {
	// The process restarts at t0+10: a proof created at t0 (open from t0−30) may have been
	// accepted before the restart, so the new incarnation refuses it; a proof opened after the
	// restart is admitted.
	h := newHarness(t, NewMemory(t0.Add(10*time.Second)))
	h.clock.set(t0.Add(20 * time.Second))
	if got := h.send(t, sign(t, "POST", "/api/v1/things", body)); got != http.StatusServiceUnavailable {
		t.Fatalf("an old proof after a restart: %d, want 503", got)
	}
	fresh := sign(t, "POST", "/api/v1/things", body, func(in *sdk.ToSign) {
		in.Created, in.Expires = t0.Unix()+40, t0.Unix()+100
	})
	h.clock.set(t0.Add(45 * time.Second))
	if got := h.send(t, fresh); got != http.StatusNoContent {
		t.Fatalf("a proof opened after the restart: %d, want 204", got)
	}
}

func TestAnOversizedBodyIsRefusedNotTruncated(t *testing.T) {
	h := newHarness(t, NewMemory(t0.Add(-time.Hour)))
	big := bytes.Repeat([]byte("a"), MaxBodyBytes+1)
	if got := h.send(t, sign(t, "POST", "/api/v1/things", big)); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", got)
	}
}

func b64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		n := uint(b[i]) << 16
		chars := 2
		if i+1 < len(b) {
			n |= uint(b[i+1]) << 8
			chars = 3
		}
		if i+2 < len(b) {
			n |= uint(b[i+2])
			chars = 4
		}
		for j := 0; j < chars; j++ {
			out.WriteByte(alphabet[(n>>(18-6*uint(j)))&63])
		}
		out.WriteString(strings.Repeat("=", 4-chars))
	}
	return out.String()
}
