package enroll

// The by-hand flow of docs/enroll.md §1 end to end, short of the command's terminal: the service
// builds an intent and a challenge token, the command decodes the token and proves over the
// request it yields, and the page reads the proof token back and completes through the route.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	sdk "github.com/Bitspark/archon/sdk/go/enroll"
)

func TestAStoredKeyEnrollsThroughTheTokens(t *testing.T) {
	h := newHarness(t)
	h.clock.set(t0.Add(700 * time.Millisecond)) // the token's deadline rounds the expiry down
	intent, err := h.enroller.Intent("u_1", "julia (acme)", "add-key", []string{"read:projects"})
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := h.enroller.Prepare(Begin{
		Authorization: []byte("s1"), Account: []byte("acct-1"), Purpose: "add-key", NewKey: newKey, Intent: intent,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.persist(r)
	token, err := h.enroller.ChallengeToken(r, intent)
	if err != nil {
		t.Fatal(err)
	}

	// The command: decode once, show the intent, prove over the request the token yields.
	ch, err := sdk.DecodeChallenge("\n" + token + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Audience != audience || !ch.Deadline.Equal(t0.Add(DefaultTTL)) {
		t.Fatalf("token audience %q deadline %v", ch.Audience, ch.Deadline)
	}
	req, shown, err := ch.Request()
	if err != nil {
		t.Fatal(err)
	}
	if shown.AccountName != "julia (acme)" || shown.AccountID != "u_1" || shown.Restrictions[0] != "read:projects" {
		t.Fatalf("shown %+v", shown)
	}
	proof, err := sdk.Prove(keySeed, ch.Audience, req)
	if err != nil {
		t.Fatal(err)
	}
	proofToken, err := sdk.EncodeProof(&sdk.Proof{Transaction: req.Transaction, NewKey: req.NewKey, Proof: proof})
	if err != nil {
		t.Fatal(err)
	}

	// The page: only its own pending enrollment, then the route.
	p, err := sdk.DecodeProof(proofToken)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Transaction, r.Transaction) || !bytes.Equal(p.NewKey, r.NewKey) {
		t.Fatal("the proof token is not the page's own enrollment")
	}
	if got := h.complete(t, "s1", p.Transaction, p.Proof); got != http.StatusNoContent {
		t.Fatalf("status %d", got)
	}
	if got := h.svc.recorded(); len(got) != 1 || !bytes.Equal(got[0].key, newKey) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestChallengeTokenRefusesWhatCouldNeverVerify(t *testing.T) {
	h := newHarness(t)
	intent, err := h.enroller.Intent("u_1", "julia", "add-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.enroller.Intent("u_1", "julia", "add-key", nil) // another blind
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(purpose string, intent []byte) Record {
		r, _, err := h.enroller.Prepare(Begin{
			Authorization: []byte("s1"), Account: []byte("acct-1"), Purpose: purpose, NewKey: newKey, Intent: intent,
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, tc := range []struct {
		name   string
		record Record
		intent []byte
		want   string
	}{
		{"other intent bytes", prepare("add-key", intent), other, "not the record's"},
		{"purpose differs", prepare("rotate", intent), intent, "purpose"},
		{"not format 1", prepare("add-key", []byte("acct-1 add-key")), []byte("acct-1 add-key"), "format"},
	} {
		if _, err := h.enroller.ChallengeToken(tc.record, tc.intent); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one naming %q", tc.name, err, tc.want)
		}
	}
}

func TestIntentDrawsAFreshBlindAndRefusesWhatCannotBeShown(t *testing.T) {
	h := newHarness(t)
	a, err := h.enroller.Intent("u_1", "julia", "add-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.enroller.Intent("u_1", "julia", "add-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	ia, _ := sdk.DecodeIntent(a)
	ib, _ := sdk.DecodeIntent(b)
	if len(ia.Blind) != sdk.MinBlindSize || bytes.Equal(ia.Blind, ib.Blind) {
		t.Fatalf("blinds %x %x: want two different %d-byte blinds", ia.Blind, ib.Blind, sdk.MinBlindSize)
	}
	if _, err := h.enroller.Intent("u_1", "julia"+string(rune(0x202e)), "add-key", nil); err == nil {
		t.Fatal("a right-to-left override in the account name was accepted")
	}
}
