package login

// archon#93: the delegation is [acceptedAt, acceptedAt + valid_for), and acceptedAt is the
// server's clock when it ACCEPTED the answer — taken once, handed to the law, and returned
// with the collected answer. These tests go red if the time is stamped at collection, if the
// law and the collecting client are told different instants, or if a refused answer before the
// accepted one moves it.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	sdk "github.com/Bitspark/archon/sdk/go/login"
)

// acceptLater begins a request, waits, answers it, waits again and collects it, returning the
// collected body. The law is h's own.
func acceptLater(t *testing.T, h *Handler, clock *testClock, beforeAnswer, beforeCollect time.Duration, answers int) map[string]any {
	t.Helper()
	browserSeed, personSeed := seedFor(3), seedFor(150)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
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
	req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey, Scope: []string{"read:projects"}, ValidFor: 3600}
	proof, err := sdk.Prove(personSeed, audience, req)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(beforeAnswer)
	for i := 0; i < answers; i++ {
		do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
			"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
			"possession": hex.EncodeToString(proof),
		}, nil)
		clock.advance(4 * time.Second)
	}
	clock.advance(beforeCollect)
	collect, _ := sdk.ProveCollect(browserSeed, audience, req)
	w = do(h, http.MethodGet, "/"+id+"/answer", nil, map[string]string{CollectHeader: hex.EncodeToString(collect)})
	if w.Code != http.StatusOK {
		t.Fatalf("collect = %d: %s", w.Code, w.Body.String())
	}
	return decode(t, w)
}

func TestTheDelegationStartsWhenTheAnswerIsAccepted(t *testing.T) {
	var seen []time.Time
	h, clock := newTestHandler(t, func(_, _ []byte, _ json.RawMessage, req Admitted) error {
		seen = append(seen, req.AcceptedAt)
		return nil
	})
	start := clock.now
	got := acceptLater(t, h, clock, 7*time.Second, 40*time.Second, 1)

	want := start.Add(7 * time.Second)
	if len(seen) != 1 || !seen[0].Equal(want) {
		t.Fatalf("the law was handed %v, want [%v]: the answer was accepted 7 s after begin", seen, want)
	}
	// Collected 44 s later than that, and still the acceptance instant: collection cannot move it.
	if got["accepted_at"] != want.Format(time.RFC3339) {
		t.Fatalf("accepted_at = %v, want %s — the instant the answer was accepted, not collected", got["accepted_at"], want.Format(time.RFC3339))
	}
}

func TestARefusedAnswerDoesNotStartTheDelegation(t *testing.T) {
	calls := 0
	var accepted time.Time
	h, clock := newTestHandler(t, func(_, _ []byte, _ json.RawMessage, req Admitted) error {
		calls++
		if calls == 1 {
			return errors.New("not yet")
		}
		accepted = req.AcceptedAt
		return nil
	})
	start := clock.now
	// Two answers 4 s apart: the law refuses the first and accepts the second.
	got := acceptLater(t, h, clock, 5*time.Second, 10*time.Second, 2)
	want := start.Add(9 * time.Second)
	if !accepted.Equal(want) || got["accepted_at"] != want.Format(time.RFC3339) {
		t.Fatalf("law %v, collected %v; want both %v — the answer that was STORED starts it", accepted, got["accepted_at"], want)
	}
}

func TestAProofOnlyServiceIsToldTheStartToo(t *testing.T) {
	// No law, so nothing is handed Admitted: the collected answer is how such a service learns it.
	h, clock := newTestHandler(t, nil)
	start := clock.now
	got := acceptLater(t, h, clock, 3*time.Second, 20*time.Second, 1)
	if want := start.Add(3 * time.Second).Format(time.RFC3339); got["accepted_at"] != want {
		t.Fatalf("accepted_at = %v, want %s", got["accepted_at"], want)
	}
}

func TestAcceptedAtIsWholeSecondsUTC(t *testing.T) {
	var seen time.Time
	h, clock := newTestHandler(t, func(_, _ []byte, _ json.RawMessage, req Admitted) error {
		seen = req.AcceptedAt
		return nil
	})
	clock.now = clock.now.In(time.FixedZone("x", 2*3600)).Add(700 * time.Millisecond)
	got := acceptLater(t, h, clock, 0, 10*time.Second, 1)
	if seen.Nanosecond() != 0 || seen.Location() != time.UTC {
		t.Fatalf("AcceptedAt = %v, want whole seconds in UTC — what the collected RFC 3339 can carry", seen)
	}
	if got["accepted_at"] != seen.Format(time.RFC3339) {
		t.Fatalf("the law (%v) and the collected answer (%v) disagree", seen, got["accepted_at"])
	}
}
