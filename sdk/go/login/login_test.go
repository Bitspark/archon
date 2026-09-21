package login

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/possession"
)

var (
	seedP = bytes.Repeat([]byte{0x11}, 32)
	seedK = bytes.Repeat([]byte{0x22}, 32)
)

func request() *Request {
	return &Request{
		ID:       []byte("req-1"),
		Nonce:    bytes.Repeat([]byte{0xaa}, 16),
		Browser:  crypto.PublicKeyFromSeed(seedK),
		Scope:    []string{"read:projects", "read:campaigns"},
		ValidFor: 28800,
	}
}

const audience = "https://dawn.example/api"

func TestBindingLayout(t *testing.T) {
	req := request()
	b, err := Binding(RoleLogin, audience, req)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01}
	want = append(want, 0x00, byte(len(audience)))
	want = append(want, audience...)
	want = append(want, req.Browser...)
	want = append(want, 0x00, 0x05)
	want = append(want, "req-1"...)
	want = append(want, 0x00, 0x02)
	want = append(want, 0x00, 0x0d)
	want = append(want, "read:projects"...)
	want = append(want, 0x00, 0x0e)
	want = append(want, "read:campaigns"...)
	want = append(want, 0x00, 0x00, 0x70, 0x80)
	if !bytes.Equal(b, want) {
		t.Fatalf("binding\n got %x\nwant %x", b, want)
	}
	c, _ := Binding(RoleCollect, audience, req)
	if c[0] != RoleCollect || !bytes.Equal(c[1:], b[1:]) {
		t.Fatal("collect binding differs from login binding beyond the role byte")
	}
}

func TestProveVerifyRoundTrip(t *testing.T) {
	req := request()
	sig, err := Prove(seedP, audience, req)
	if err != nil {
		t.Fatal(err)
	}
	pubP := crypto.PublicKeyFromSeed(seedP)
	if !Verify(pubP, audience, req, sig) {
		t.Fatal("login proof did not verify")
	}
	// The proof IS the possession scheme in Domain over the login binding.
	binding, _ := Binding(RoleLogin, audience, req)
	if !possession.Verify(pubP, Domain, req.Nonce, binding, sig) {
		t.Fatal("login proof is not a possession proof over the binding")
	}
	// Every bound field binds.
	tamper := []struct {
		name string
		aud  string
		mod  func(*Request)
	}{
		{"audience", "https://evil.example/api", func(*Request) {}},
		{"browser", audience, func(r *Request) { r.Browser = crypto.PublicKeyFromSeed(seedP) }},
		{"id", audience, func(r *Request) { r.ID = []byte("req-2") }},
		{"nonce", audience, func(r *Request) { r.Nonce = bytes.Repeat([]byte{0xab}, 16) }},
		{"scope order", audience, func(r *Request) { r.Scope = []string{"read:campaigns", "read:projects"} }},
		{"scope entry", audience, func(r *Request) { r.Scope = []string{"read:projects", "write:campaigns"} }},
		{"scope extra", audience, func(r *Request) { r.Scope = append(r.Scope, "admin") }},
		{"valid_for", audience, func(r *Request) { r.ValidFor = 28801 }},
	}
	for _, tc := range tamper {
		r := request()
		tc.mod(r)
		if Verify(pubP, tc.aud, r, sig) {
			t.Errorf("%s did not bind", tc.name)
		}
	}
	// Not a proof: the other key, a raw signature, another domain, the other role.
	if Verify(crypto.PublicKeyFromSeed(seedK), audience, req, sig) {
		t.Error("verified under the wrong key")
	}
	msg, _ := possession.MessageBytes(req.Nonce, binding)
	if Verify(pubP, audience, req, crypto.Sign(seedP, msg)) {
		t.Error("a raw signature verified as a login proof")
	}
	other, _ := possession.Prove(seedP, "archon-login/2", req.Nonce, binding)
	if Verify(pubP, audience, req, other) {
		t.Error("a proof from another domain verified")
	}
	collect, _ := ProveCollect(seedK, audience, req)
	if Verify(crypto.PublicKeyFromSeed(seedK), audience, req, collect) {
		t.Error("a collect proof verified as a login proof")
	}
}

func TestCollect(t *testing.T) {
	req := request()
	sig, err := ProveCollect(seedK, audience, req)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCollect(audience, req, sig) {
		t.Fatal("collect proof did not verify")
	}
	if VerifyCollect("https://evil.example/api", req, sig) {
		t.Error("collect proof verified at another audience")
	}
	login, _ := Prove(seedK, audience, req)
	if VerifyCollect(audience, req, login) {
		t.Error("a login proof verified as a collect proof")
	}
	if _, err := ProveCollect(seedP, audience, req); err == nil {
		t.Error("collect proof from a key the request does not name was not refused")
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name string
		aud  string
		mod  func(*Request)
	}{
		{"empty audience", "", func(*Request) {}},
		{"control char in audience", "https://dawn.example/api\n", func(*Request) {}},
		{"browser wrong size", audience, func(r *Request) { r.Browser = r.Browser[:31] }},
		{"empty id", audience, func(r *Request) { r.ID = nil }},
		{"empty scope entry", audience, func(r *Request) { r.Scope = []string{""} }},
		{"control char in scope", audience, func(r *Request) { r.Scope = []string{"read:\x07projects"} }},
		{"DEL in scope", audience, func(r *Request) { r.Scope = []string{"read:\x7fprojects"} }},
		{"invalid utf-8 in scope", audience, func(r *Request) { r.Scope = []string{"read:\xffprojects"} }},
		{"zero validity", audience, func(r *Request) { r.ValidFor = 0 }},
		{"oversized id", audience, func(r *Request) { r.ID = bytes.Repeat([]byte{1}, MaxFieldSize+1) }},
		{"binding over the possession bound", audience, func(r *Request) {
			r.Scope = []string{strings.Repeat("a", MaxFieldSize), strings.Repeat("b", MaxFieldSize)}
		}},
	}
	for _, tc := range cases {
		r := request()
		tc.mod(r)
		if _, err := Binding(RoleLogin, tc.aud, r); err == nil {
			t.Errorf("%s: not refused", tc.name)
		}
		if _, err := Prove(seedP, tc.aud, r); err == nil {
			t.Errorf("%s: Prove did not refuse", tc.name)
		}
		if Verify(crypto.PublicKeyFromSeed(seedP), tc.aud, r, make([]byte, 64)) {
			t.Errorf("%s: Verify returned true", tc.name)
		}
	}
	if _, err := Binding(0x03, audience, request()); err == nil {
		t.Error("unknown role not refused")
	}
	r := request()
	r.Nonce = r.Nonce[:15]
	if _, err := Prove(seedP, audience, r); err == nil {
		t.Error("short nonce not refused by Prove")
	}
	r = request()
	r.Scope = nil
	if _, err := Binding(RoleLogin, audience, r); err != nil {
		t.Errorf("empty scope list should be allowed (the law may refuse it): %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := Prove(seedP, audience, request())
	b, _ := Prove(seedP, audience, request())
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatal("login proof is not deterministic")
	}
}
