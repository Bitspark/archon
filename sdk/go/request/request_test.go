package request

import (
	"bytes"
	"context"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/signer"
)

var seed = bytes.Repeat([]byte{0x44}, 32)

func input() ToSign {
	ct := "application/json"
	return ToSign{
		Method: "POST", Audience: "https://dawn.example/api", RequestTarget: "/api/v1/things?x=1",
		Body: []byte(`{"a":1}`), ContentType: &ct, Declared: [][2]string{{"idempotency-key", "k-1"}},
		Created: 1789034640, Expires: 1789034700, Nonce: bytes.Repeat([]byte{7}, 16),
	}
}

// What the vectors leave to the lanes: a signed request verifying end to end, and the verifier
// reporting what it verified.
func TestASignedRequestVerifies(t *testing.T) {
	in := input()
	_, h, err := Sign(seed, in)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(Policy{Audience: in.Audience, Declared: []string{"idempotency-key"}, MaxLifetime: 300, Skew: 30},
		in.Created+5, Received{
			Method: in.Method, RequestTarget: in.RequestTarget, Body: in.Body,
			Headers: [][2]string{
				{"Content-Type", "application/json"}, {"Idempotency-Key", "k-1"},
				{"Archon-Audience", h.ArchonAudience}, {"Content-Digest", h.ContentDigest},
				{"Signature-Input", h.SignatureInput}, {"Signature", h.Signature},
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.Principal, crypto.PublicKeyFromSeed(seed)) || v.TargetURI != "https://dawn.example/api/v1/things?x=1" || len(v.Covered) != 4 {
		t.Fatalf("verified %+v", v)
	}
}

// Through a signer the headers are the seed's.
func TestSignWithMatchesSign(t *testing.T) {
	_, want, err := Sign(seed, input())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := signer.Seed(seed)
	got, err := SignWith(context.Background(), s, input())
	if err != nil || got != want {
		t.Fatalf("SignWith = %+v, %v; want %+v", got, err, want)
	}
}
