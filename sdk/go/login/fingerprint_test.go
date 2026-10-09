package login

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
)

// TestFingerprintLayout recomputes the digest from docs/login.md §5.3 with the domain spelled
// out here, not taken from the constant, so a change to either is caught.
func TestFingerprintLayout(t *testing.T) {
	req := request()
	fp, err := Fingerprint(audience, req)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := Binding(RoleLogin, audience, req)
	domain := []byte("archon-login-fingerprint/1")
	var in []byte
	in = binary.BigEndian.AppendUint16(in, uint16(len(domain)))
	in = append(in, domain...)
	in = binary.BigEndian.AppendUint16(in, uint16(len(req.Nonce)))
	in = append(in, req.Nonce...)
	in = append(in, binding...)
	digest := sha256.Sum256(in)
	if !bytes.Equal(fp[:], digest[:16]) {
		t.Fatalf("fingerprint\n got %x\nwant %x", fp, digest[:16])
	}
	if FingerprintDomain != string(domain) {
		t.Fatalf("FingerprintDomain is %q", FingerprintDomain)
	}
	// The login role, never the collect role.
	collect, _ := Binding(RoleCollect, audience, req)
	in = append(in[:len(in)-len(binding)], collect...)
	other := sha256.Sum256(in)
	if bytes.Equal(fp[:], other[:16]) {
		t.Fatal("fingerprint is over the collect binding")
	}
}

// TestFingerprintBindsEveryField: the comparison is only worth making if a substitution of any
// field the proof binds, or of the nonce, changes what the person reads.
func TestFingerprintBindsEveryField(t *testing.T) {
	base, err := Fingerprint(audience, request())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Fingerprint(audience, request())
	if base != again {
		t.Fatal("fingerprint is not deterministic")
	}
	tamper := []struct {
		name string
		aud  string
		mod  func(*Request)
	}{
		{"audience", "https://evil.example/api", func(*Request) {}},
		{"browser", audience, func(r *Request) { r.Browser = crypto.PublicKeyFromSeed(seedP) }},
		{"id", audience, func(r *Request) { r.ID = []byte("req-2") }},
		{"nonce", audience, func(r *Request) { r.Nonce = bytes.Repeat([]byte{0xab}, 16) }},
		{"nonce length", audience, func(r *Request) { r.Nonce = bytes.Repeat([]byte{0xaa}, 17) }},
		{"scope order", audience, func(r *Request) { r.Scope = []string{"read:campaigns", "read:projects"} }},
		{"scope entry", audience, func(r *Request) { r.Scope = []string{"read:projects", "write:campaigns"} }},
		{"scope extra", audience, func(r *Request) { r.Scope = append(r.Scope, "admin") }},
		{"valid_for", audience, func(r *Request) { r.ValidFor = 28801 }},
	}
	for _, tc := range tamper {
		r := request()
		tc.mod(r)
		got, err := Fingerprint(tc.aud, r)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got == base {
			t.Errorf("%s did not change the fingerprint", tc.name)
		}
	}
}

// TestFingerprintRefusals covers what the vectors do not carry: the nil request and the nonce
// over the u16 field (a 130 KB vector), beside the shorter refusals they do.
func TestFingerprintRefusals(t *testing.T) {
	if _, err := Fingerprint(audience, nil); err == nil {
		t.Error("nil request not refused")
	}
	cases := []struct {
		name string
		aud  string
		mod  func(*Request)
	}{
		{"short nonce", audience, func(r *Request) { r.Nonce = r.Nonce[:15] }},
		{"empty nonce", audience, func(r *Request) { r.Nonce = nil }},
		{"nonce over the u16 field", audience, func(r *Request) { r.Nonce = make([]byte, MaxFieldSize+1) }},
		{"empty audience", "", func(*Request) {}},
		{"browser wrong size", audience, func(r *Request) { r.Browser = r.Browser[:31] }},
		{"empty id", audience, func(r *Request) { r.ID = nil }},
		{"zero validity", audience, func(r *Request) { r.ValidFor = 0 }},
		{"invalid utf-8 in scope", audience, func(r *Request) { r.Scope = []string{"read:\xffprojects"} }},
	}
	for _, tc := range cases {
		r := request()
		tc.mod(r)
		if _, err := Fingerprint(tc.aud, r); err == nil {
			t.Errorf("%s: not refused", tc.name)
		}
	}
	r := request()
	r.Nonce = make([]byte, MaxFieldSize)
	if _, err := Fingerprint(audience, r); err != nil {
		t.Errorf("a nonce of exactly the u16 field was refused: %v", err)
	}
}

func TestFormatFingerprint(t *testing.T) {
	var seq, ones [16]byte
	for i := range seq {
		seq[i] = byte(i)
		ones[i] = 0xff
	}
	example := [16]byte{0x7a, 0x91, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f}
	for _, tc := range []struct {
		fp   [16]byte
		want string
	}{
		{seq, "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f"},
		{ones, "ffff ffff ffff ffff ffff ffff ffff ffff"},
		{example, "7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f"},
	} {
		if got := FormatFingerprint(tc.fp); got != tc.want {
			t.Errorf("FormatFingerprint(%x) = %q, want %q", tc.fp, got, tc.want)
		}
	}
}
