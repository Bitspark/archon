// The authority payload is OPAQUE BYTES (ADR 0007 §B), pinned here by VALUE from the fixture
// all three server lanes read, and the malformed-body cases they must answer alike.
//
// This lane was the reference the other two were measured against when caa found they rebuilt
// the payload — and then a second probe found that the reference violated the pin too, in a
// way the first payload could not see. That is the argument for carrying these cases here as
// well as in the lanes that were visibly broken.
package login

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	sdk "github.com/Bitspark/archon/sdk/go/login"
)

// wireFixture is the shared cross-lane file, read by all three server suites.
type wireFixture struct {
	Errors struct {
		Keys  []string `json:"keys"`
		Codes map[string]struct {
			Status int    `json:"status"`
			Error  string `json:"error"`
		} `json:"codes"`
	} `json:"errors"`
	AuthorityRoundtrip struct {
		Payload string `json:"payload"`
	} `json:"authority_roundtrip"`
	OfferMismatch struct {
		Offer struct {
			Scope    []string `json:"scope"`
			ValidFor uint32   `json:"valid_for"`
		} `json:"offer"`
		Cases []struct {
			Name     string   `json:"name"`
			Scope    []string `json:"scope"`
			ValidFor uint32   `json:"valid_for"`
			Status   int      `json:"status"`
			Error    string   `json:"error"`
		} `json:"cases"`
	} `json:"offer_mismatch"`
	MalformedBodies struct {
		Cases []struct {
			Name       string `json:"name"`
			Route      string `json:"route"`
			Append     string `json:"append_to_a_valid_body"`
			Status     int    `json:"status"`
			Error      string `json:"error"`
			BaseStatus int    `json:"base_status"`
		} `json:"cases"`
	} `json:"malformed_bodies"`
}

func readWireFixture(t *testing.T) wireFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "login-wire.json"))
	if err != nil {
		t.Fatalf("could not read the shared wire fixture: %v", err)
	}
	var fixture wireFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("the shared wire fixture is not the expected JSON: %v", err)
	}
	return fixture
}

// doRaw sends a body EXACTLY as given. The shared `do` helper marshals its argument, which
// would re-encode the very bytes these cases are about.
func doRaw(h *Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// openLogin begins a login and returns its id and the scheme request the CLI would prove over.
func openLogin(t *testing.T, h *Handler, browserSeed []byte) (string, *sdk.Request) {
	t.Helper()
	browserKey := crypto.PublicKeyFromSeed(browserSeed)
	w := do(h, http.MethodPost, "/", map[string]any{
		"browser":   keytext.EncodeKey(browserKey),
		"scope":     []string{"read:projects"},
		"valid_for": 3600,
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("begin = %d, want 201: %s", w.Code, w.Body.String())
	}
	begun := decode(t, w)
	id, _ := begun["id"].(string)
	idBytes, _ := hex.DecodeString(id)
	nonce, _ := hex.DecodeString(begun["nonce"].(string))
	return id, &sdk.Request{
		ID: idBytes, Nonce: nonce, Browser: browserKey,
		Scope: []string{"read:projects"}, ValidFor: 3600,
	}
}

func TestTheAuthorityCrossesThisLaneAsBytes(t *testing.T) {
	payload := readWireFixture(t).AuthorityRoundtrip.Payload
	if payload == "" {
		t.Fatal("the fixture states no authority_roundtrip payload — a pin nobody can fail is not a pin")
	}

	var seen string
	h, _ := newTestHandler(t, func(browser, principal []byte, authority json.RawMessage) error {
		seen = string(authority)
		return nil
	})

	browserSeed, personSeed := seedFor(41), seedFor(210)
	id, req := openLogin(t, h, browserSeed)
	proof, err := sdk.Prove(personSeed, audience, req)
	if err != nil {
		t.Fatalf("sdk.Prove: %v", err)
	}

	// Built as TEXT so the fixture's exact bytes reach the handler. Marshalling a map here
	// would compact the payload before the handler ever saw it, and the test would then be
	// measuring encoding/json rather than this package.
	body := `{"principal":"` + keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)) +
		`","possession":"` + hex.EncodeToString(proof) + `","authority":` + payload + `}`
	w := doRaw(h, http.MethodPost, "/"+id+"/answer", body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("answer = %d, want 204: %s", w.Code, w.Body.String())
	}
	if seen != payload {
		t.Fatalf("the law was handed a rebuilt payload:\n got %s\nwant %s", seen, payload)
	}

	collect, err := sdk.ProveCollect(browserSeed, audience, req)
	if err != nil {
		t.Fatalf("sdk.ProveCollect: %v", err)
	}
	w = do(h, http.MethodGet, "/"+id+"/answer", nil, map[string]string{CollectHeader: hex.EncodeToString(collect)})
	if w.Code != http.StatusOK {
		t.Fatalf("collect = %d, want 200: %s", w.Code, w.Body.String())
	}
	// The headers, asserted because THIS route now has a hand-rolled writer and headers are
	// what a hand-rolled writer forgets. `no-store` is not decoration here: the body carries a
	// possession proof, and a cache holding it is exactly what must not happen.
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// TrimRight because the other routes still go through json.NewEncoder, which appends a
	// newline; this one does not, since it splices the authority itself.
	got := strings.TrimRight(w.Body.String(), "\n")
	if !strings.HasSuffix(got, `,"authority":`+payload+`}`) {
		t.Fatalf("the browser received a rebuilt authority:\n got  %s\nwant suffix %s", got, `,"authority":`+payload+`}`)
	}

	// Every kind of damage a round trip does, named separately, so a regression says WHICH one
	// came back rather than only that something differs. The last two are caa's second probe:
	// json.Encoder compacts a RawMessage AND HTML-escapes it, and the first version of this
	// payload — no whitespace, no & or < — could see neither.
	for _, c := range []struct{ what, want string }{
		{"the 64-bit integer changed", "9007199254740993"},
		{"the trailing zero was normalised away", "1.10"},
		{"the escape was decoded", `\u00e9`},
		{"the insignificant whitespace was compacted away", `{"z":1, "a"`},
		{"the ampersand did not survive", "?a=1&b=2"},
		{"the angle brackets did not survive", "<b>"},
	} {
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q not in %s", c.what, c.want, got)
		}
	}
	// And the escaped forms must NOT appear: this is the half of the check that catches an
	// encoder being reintroduced, since the raw characters would then be gone.
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(got, escaped) {
			t.Errorf("the payload was HTML-escaped (%s): %s", escaped, got)
		}
	}
	if strings.Index(got, `"z"`) > strings.Index(got, `"a"`) {
		t.Errorf("the keys were reordered: %s", got)
	}
}

// The malformed-body cases the three lanes must answer ALIKE, from the shared fixture.
//
// Each case is members APPENDED to an otherwise-valid body, and the test proves that framing
// by sending the SAME body without them afterwards and requiring `base_status`. So a case here
// cannot pass because the request was refused for some unrelated reason — which is exactly how
// the door-check tests fooled themselves before.
func TestMalformedBodiesAreRefusedAlike(t *testing.T) {
	cases := readWireFixture(t).MalformedBodies.Cases
	if len(cases) == 0 {
		t.Fatal("the fixture states no malformed_bodies cases — a pin nobody can fail is not a pin")
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Append == "" {
				t.Fatalf("case %q appends nothing, so it cannot distinguish anything", c.Name)
			}
			h, _ := newTestHandler(t, nil)
			browserSeed, personSeed := seedFor(51), seedFor(220)

			var path, open string
			switch c.Route {
			case "begin":
				path = "/"
				open = `{"browser":"` + keytext.EncodeKey(crypto.PublicKeyFromSeed(browserSeed)) +
					`","scope":["read:projects"],"valid_for":3600`
			case "answer":
				id, req := openLogin(t, h, browserSeed)
				proof, err := sdk.Prove(personSeed, audience, req)
				if err != nil {
					t.Fatalf("sdk.Prove: %v", err)
				}
				path = "/" + id + "/answer"
				open = `{"principal":"` + keytext.EncodeKey(crypto.PublicKeyFromSeed(personSeed)) +
					`","possession":"` + hex.EncodeToString(proof) + `"`
			case "offer":
				// The third route a body enters by (§4.1). The base body's 201 is what proves
				// the refusal above was for the repeated member and not for the code.
				path = "/offers"
				open = `{"code":"` + codeFor(0x77) + `","scope":["read:projects"],"valid_for":3600`
			default:
				t.Fatalf("the fixture names a route this suite does not drive: %q", c.Route)
			}

			w := doRaw(h, http.MethodPost, path, open+c.Append+"}")
			if w.Code != c.Status {
				t.Fatalf("= %d, want %d: %s", w.Code, c.Status, w.Body.String())
			}
			if got := decode(t, w)["error"]; got != c.Error {
				t.Fatalf("error = %v, want %v", got, c.Error)
			}

			// The framing: the same body without the appended members is accepted. If this
			// fails, the case above proved nothing about what it names.
			w = doRaw(h, http.MethodPost, path, open+"}")
			if w.Code != c.BaseStatus {
				t.Fatalf("the base body must be accepted (%d), else the case proves nothing: %d %s",
					c.BaseStatus, w.Code, w.Body.String())
			}
		})
	}
}
