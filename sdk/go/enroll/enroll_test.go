package enroll

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/possession"
	"github.com/Bitspark/archon/sdk/go/signer"
)

const audience = "https://dawn.example/api"

var seedN = bytes.Repeat([]byte{0x44}, 32)

func request() *Request {
	return &Request{
		Nonce:        bytes.Repeat([]byte{0xcc}, 16),
		Transaction:  []byte("txn-1"),
		Purpose:      "add-key",
		NewKey:       crypto.PublicKeyFromSeed(seedN),
		IntentDigest: bytes.Repeat([]byte{0x5f}, 32),
	}
}

// The oversize refusal the vectors leave to the lanes: an audience that makes the binding
// exceed the possession scheme's u16 field.
func TestABindingOverThePossessionFieldIsRefused(t *testing.T) {
	room := possession.MaxFieldSize - (1 + 2 + 7 + 2 + 2 + 5 + 32 + 32)
	if _, err := Binding(strings.Repeat("a", room), request()); err != nil {
		t.Fatalf("a binding of exactly %d bytes: %v", possession.MaxFieldSize, err)
	}
	if _, err := Binding(strings.Repeat("a", room+1), request()); err == nil {
		t.Fatal("a binding one byte over the possession field was accepted")
	}
}

// Through a signer the proof is the same bytes as through the seed, and only the new key's
// signer is asked: the request expects req.NewKey.
func TestProveWithMatchesProveAndOnlyTheNewKeySigns(t *testing.T) {
	want, err := Prove(seedN, audience, request())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := signer.Seed(seedN)
	got, err := ProveWith(context.Background(), s, audience, request())
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ProveWith = %x, %v; want %x", got, err, want)
	}
	if !Verify(audience, request(), got) {
		t.Fatal("the proof made through a signer does not verify")
	}
	other, _ := signer.Seed(bytes.Repeat([]byte{0x11}, 32))
	if _, err := ProveWith(context.Background(), other, audience, request()); err == nil {
		t.Fatal("a signer for another key proved an enrollment of the new key")
	}
}
