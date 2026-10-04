package signer_test

// The signer seam (ADR 0009 §2–4): every helper through a Signer produces the SAME bytes the
// seed functions produce — checked against the vectors, whose signatures OpenSSL derived — and
// every rule the seam enforces is exercised against a signer that breaks it.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/envelope"
	"github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/sdk/go/possession"
	"github.com/Bitspark/archon/sdk/go/signer"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile("../../../vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

type result struct {
	OK    string `json:"ok"`
	Error bool   `json:"error"`
}

type vecRequest struct {
	ID       string   `json:"id"`
	Nonce    string   `json:"nonce"`
	Browser  string   `json:"browser"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
}

func (v vecRequest) request(t *testing.T) *login.Request {
	scope := make([]string, len(v.Scope))
	for i, s := range v.Scope {
		scope[i] = string(unhex(t, s))
	}
	return &login.Request{ID: unhex(t, v.ID), Nonce: unhex(t, v.Nonce), Browser: unhex(t, v.Browser), Scope: scope, ValidFor: v.ValidFor}
}

// countOK counts a family's ok cases through a second, generic decode of the file, so a
// struct-mapping slip in the test above cannot shrink both counts together.
func countOK(t *testing.T, file, family string) int {
	t.Helper()
	var all map[string]json.RawMessage
	load(t, file, &all)
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(all[family], &cases); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cases {
		var r map[string]any
		if err := json.Unmarshal(c["result"], &r); err != nil {
			t.Fatal(err)
		}
		if _, ok := r["ok"]; ok {
			n++
		}
	}
	return n
}

func seedSigner(t *testing.T, seed []byte) signer.Signer {
	t.Helper()
	s, err := signer.Seed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestThroughASeedSignerEveryHelperReproducesTheVectors(t *testing.T) {
	ctx := context.Background()
	var sdk struct {
		PossessionProve []struct {
			Name, Seed, Domain, Nonce, Binding string
			Result                             result
		} `json:"possession_prove"`
		EnvelopeSeal []struct {
			Name, Seed, Domain, Payload string
			Result                      result
		} `json:"envelope_seal"`
	}
	load(t, "sdk.json", &sdk)
	checked := 0
	for _, c := range sdk.PossessionProve {
		if c.Result.OK == "" {
			continue
		}
		checked++
		sig, err := possession.ProveWith(ctx, seedSigner(t, unhex(t, c.Seed)), c.Domain, unhex(t, c.Nonce), unhex(t, c.Binding))
		if err != nil || hex.EncodeToString(sig) != c.Result.OK {
			t.Errorf("possession %s: %x, %v", c.Name, sig, err)
		}
	}
	for _, c := range sdk.EnvelopeSeal {
		if c.Result.OK == "" {
			continue
		}
		checked++
		env, err := envelope.SealWith(ctx, seedSigner(t, unhex(t, c.Seed)), c.Domain, unhex(t, c.Payload))
		if err != nil || hex.EncodeToString(env) != c.Result.OK {
			t.Errorf("envelope %s: %x, %v", c.Name, env, err)
		}
	}
	var lv struct {
		LoginProve []struct {
			Name, Seed, Audience string
			Request              vecRequest
			Result               result
		} `json:"login_prove"`
		CollectProve []struct {
			Name, Seed, Audience string
			Request              vecRequest
			Result               result
		} `json:"login_collect_prove"`
	}
	load(t, "login.json", &lv)
	for _, c := range lv.LoginProve {
		if c.Result.OK == "" {
			continue
		}
		checked++
		sig, err := login.ProveWith(ctx, seedSigner(t, unhex(t, c.Seed)), c.Audience, c.Request.request(t))
		if err != nil || hex.EncodeToString(sig) != c.Result.OK {
			t.Errorf("login %s: %x, %v", c.Name, sig, err)
		}
	}
	for _, c := range lv.CollectProve {
		if c.Result.OK == "" {
			continue
		}
		checked++
		sig, err := login.ProveCollectWith(ctx, seedSigner(t, unhex(t, c.Seed)), c.Audience, c.Request.request(t))
		if err != nil || hex.EncodeToString(sig) != c.Result.OK {
			t.Errorf("collect %s: %x, %v", c.Name, sig, err)
		}
	}
	// Every OpenSSL-derived ok case across the four families: a decoding slip that skipped them
	// all would otherwise pass in silence.
	want := countOK(t, "sdk.json", "possession_prove") + countOK(t, "sdk.json", "envelope_seal") +
		countOK(t, "login.json", "login_prove") + countOK(t, "login.json", "login_collect_prove")
	if checked != want || checked < 8 {
		t.Fatalf("checked %d vector cases, want %d (and at least 8)", checked, want)
	}
}

// fake is a signer that counts its calls and signs however `how` says.
type fake struct {
	pub   []byte
	caps  signer.Capabilities
	how   func(signer.Request) []byte
	calls int
}

func (f *fake) PublicKey() []byte                 { return f.pub }
func (f *fake) Capabilities() signer.Capabilities { return f.caps }
func (f *fake) Sign(_ context.Context, r signer.Request) ([]byte, error) {
	f.calls++
	return f.how(r), nil
}

var both = signer.Capabilities{Schemes: []signer.Kind{signer.KindRaw, signer.KindPhContext}}

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, crypto.SeedSize) }

func mustSignIn(seed []byte, domain string, msg []byte) []byte {
	sig, err := crypto.SignInDomain(seed, domain, msg)
	if err != nil {
		panic(err)
	}
	return sig
}

func TestAnOutOfRangeRequestIsRefusedBeforeTheSignerIsInvoked(t *testing.T) {
	ctx := context.Background()
	seed := seedOf(7)
	f := &fake{pub: crypto.PublicKeyFromSeed(seed), caps: both, how: func(r signer.Request) []byte { return crypto.Sign(seed, r.Message) }}
	nonce := bytes.Repeat([]byte{1}, 16)
	if _, err := possession.ProveWith(ctx, f, "", nonce, []byte{1}); err == nil {
		t.Error("an empty domain must be refused")
	}
	if _, err := possession.ProveWith(ctx, f, "d", nonce[:15], []byte{1}); err == nil {
		t.Error("a short nonce must be refused")
	}
	if _, err := envelope.SealWith(ctx, f, strings.Repeat("d", 256), nil); err == nil {
		t.Error("a 256-byte domain must be refused")
	}
	if _, err := signer.SignWith(ctx, f, signer.Request{ExpectedPublicKey: make([]byte, 31), Scheme: signer.Raw{}, Message: []byte{1}}); err == nil {
		t.Error("a 31-byte key must be refused")
	}
	if f.calls != 0 {
		t.Fatalf("the signer was asked %d times, want 0", f.calls)
	}
}

func TestASignerIsAskedOnlyForWhatItSaysItCanDo(t *testing.T) {
	ctx := context.Background()
	seed := seedOf(7)
	pub := crypto.PublicKeyFromSeed(seed)
	r, err := possession.Prepare(pub, "archon/test/pop", bytes.Repeat([]byte{1}, 16), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	// A raw-only signer — every agent and device ADR 0007 §A measured — is refused for ph.
	rawOnly := &fake{pub: pub, caps: signer.Capabilities{Schemes: []signer.Kind{signer.KindRaw}}, how: func(r signer.Request) []byte { return crypto.Sign(seed, r.Message) }}
	elsewhere := &fake{pub: pub, caps: signer.Capabilities{Schemes: []signer.Kind{signer.KindPhContext}, Domains: []string{"archon/test/other"}}, how: func(r signer.Request) []byte { return mustSignIn(seed, "archon/test/pop", r.Message) }}
	otherKey := &fake{pub: crypto.PublicKeyFromSeed(seedOf(8)), caps: both, how: func(r signer.Request) []byte { return crypto.Sign(seed, r.Message) }}
	for _, c := range []struct {
		name string
		f    *fake
		want string
	}{{"raw only", rawOnly, "cannot produce"}, {"other domains", elsewhere, "does not sign in domain"}, {"other key", otherKey, "not the expected key"}} {
		if _, err := signer.SignWith(ctx, c.f, r); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if c.f.calls != 0 {
			t.Errorf("%s: the signer was asked", c.name)
		}
	}
}

func TestASignatureIsCheckedAgainstTheRequestNeverTheSignersWord(t *testing.T) {
	ctx := context.Background()
	seed := seedOf(7)
	pub := crypto.PublicKeyFromSeed(seed)
	const domain = "archon/test/pop"
	r, err := possession.Prepare(pub, domain, bytes.Repeat([]byte{1}, 16), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		how  func(signer.Request) []byte
	}{
		{"signs with another key", func(r signer.Request) []byte { return mustSignIn(seedOf(8), domain, r.Message) }},
		{"drops the context and signs raw", func(r signer.Request) []byte { return crypto.Sign(seed, r.Message) }},
		{"signs in another domain", func(r signer.Request) []byte { return mustSignIn(seed, "archon/test/other", r.Message) }},
		{"signs other bytes", func(signer.Request) []byte { return mustSignIn(seed, domain, []byte{0}) }},
		{"returns 63 bytes", func(r signer.Request) []byte { return mustSignIn(seed, domain, r.Message)[1:] }},
	} {
		if _, err := signer.SignWith(ctx, &fake{pub: pub, caps: both, how: c.how}, r); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := possession.Complete(r, c.how(r)); err == nil {
			t.Errorf("complete: %s accepted", c.name)
		}
	}
}

// cancelling cancels the context from inside Sign and returns a good signature anyway.
type cancelling struct {
	fake
	cancel context.CancelFunc
}

func (c *cancelling) Sign(ctx context.Context, r signer.Request) ([]byte, error) {
	c.cancel()
	return c.fake.Sign(ctx, r)
}

func TestASignatureThatArrivesAfterCancellationIsNeverPackaged(t *testing.T) {
	seed := seedOf(7)
	ctx, cancel := context.WithCancel(context.Background())
	late := &cancelling{fake: fake{pub: crypto.PublicKeyFromSeed(seed), caps: both, how: func(r signer.Request) []byte {
		return mustSignIn(seed, r.Scheme.(signer.PhContext).Domain, r.Message)
	}}, cancel: cancel}
	if _, err := envelope.SealWith(ctx, late, "archon/test/env", []byte{1}); err == nil {
		t.Error("a signature returned after cancellation was packaged")
	}
	if _, err := envelope.SealWith(ctx, late, "archon/test/env", []byte{1}); err == nil || late.calls != 1 {
		t.Errorf("an already-cancelled context must not reach the signer: %v, calls %d", err, late.calls)
	}
}

func TestCompleteAssemblesFromTheRequestAndTheSeedSignerIsDeterministic(t *testing.T) {
	ctx := context.Background()
	s := seedSigner(t, seedOf(7))
	r, err := envelope.PrepareSeal(s.PublicKey(), "archon/test/env", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.Sign(ctx, r)
	second, _ := s.Sign(ctx, r)
	if !bytes.Equal(first, second) {
		t.Fatal("signing twice gave different bytes")
	}
	env, err := envelope.CompleteSeal(r, first)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := envelope.Open(env, "archon/test/env")
	if err != nil || string(opened.Payload) != "payload" {
		t.Fatalf("open: %v %q", err, opened.Payload)
	}
	pr, _ := possession.Prepare(s.PublicKey(), "d", make([]byte, 16), []byte{1})
	if _, err := envelope.CompleteSeal(pr, first); err == nil {
		t.Error("a possession request completed as a seal")
	}
}
