package login

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	sdk "github.com/Bitspark/archon/sdk/go/login"
)

// A FIXTURE LAW that uses everything AdmitAuthority is handed, the way a real one would
// (archon-internal #49): it refuses a delegation longer than it allows — a check only the
// verified request (Admitted, #61) makes possible — and an authority addressed to any key but
// the browser key the delegation is for. The authority shape is this test's own; archon reads
// none of it.
const fixtureMaxValidFor = 8 * 60 * 60

func fixtureLaw(browser, _ []byte, authority json.RawMessage, req Admitted) error {
	if req.ValidFor > fixtureMaxValidFor {
		return errors.New("the law allows at most eight hours")
	}
	var a struct {
		Recipient string `json:"recipient"`
	}
	if err := json.Unmarshal(authority, &a); err != nil {
		return err
	}
	if a.Recipient != keytext.EncodeKey(browser) {
		return errors.New("the authority names another recipient")
	}
	return nil
}

func TestAFixtureLawRefusesAnExcessiveValidityAndAWrongRecipient(t *testing.T) {
	browserSeed, personSeed := seedFor(60), seedFor(160)
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	other := keytext.EncodeKey(crypto.PublicKeyFromSeed(seedFor(61)))

	for _, c := range []struct {
		name      string
		validFor  uint32
		recipient string
		want      int
	}{
		{"within the limit, addressed to the browser key", 3600, keytext.EncodeKey(browserKey), http.StatusNoContent},
		{"longer than the law allows", fixtureMaxValidFor + 1, keytext.EncodeKey(browserKey), http.StatusForbidden},
		{"addressed to another key", 3600, other, http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newTestHandler(t, fixtureLaw)
			begun := decode(t, do(h, http.MethodPost, "/", map[string]any{
				"browser": keytext.EncodeKey(browserKey), "scope": []string{"read:projects"}, "valid_for": c.validFor,
			}, nil))
			id := begun["id"].(string)
			idBytes, _ := hex.DecodeString(id)
			nonce, _ := hex.DecodeString(begun["nonce"].(string))
			req := &sdk.Request{ID: idBytes, Nonce: nonce, Browser: browserKey, Scope: []string{"read:projects"}, ValidFor: c.validFor}
			proof, err := sdk.Prove(personSeed, audience, req)
			if err != nil {
				t.Fatal(err)
			}
			w := do(h, http.MethodPost, "/"+id+"/answer", map[string]any{
				"principal":  keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)),
				"possession": hex.EncodeToString(proof),
				"authority":  map[string]string{"recipient": c.recipient},
			}, nil)
			if w.Code != c.want {
				t.Fatalf("answer = %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
			// A refusal stores nothing: the browser still finds the login pending.
			collect, _ := sdk.ProveCollect(browserSeed, audience, req)
			got := do(h, http.MethodGet, "/"+id+"/answer", nil, map[string]string{CollectHeader: hex.EncodeToString(collect)}).Code
			if want := map[bool]int{true: http.StatusOK, false: http.StatusAccepted}[c.want == http.StatusNoContent]; got != want {
				t.Fatalf("collect = %d, want %d", got, want)
			}
		})
	}
}
