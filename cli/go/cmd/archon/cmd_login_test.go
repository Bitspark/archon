package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/login"
)

// A well-formed browser key, used wherever a request needs one.
const testBrowserKey = "ed25519:7a91b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f"

// The audience rule is the security boundary of this command, and since archon#22 it lives
// in the SCHEME (docs/login.md §2.1, sdk/go/login). These cases are kept as a CROSS-CHECK
// rather than deleted: they are this lane's own statement of what it believes it is calling,
// and they are what would catch the sdk and the CLI drifting apart. They agree with the
// login_audience oracle — verified by running the real DeriveAudience over every case here
// BEFORE the swap, not after.
func TestDeriveAudience(t *testing.T) {
	for _, c := range []struct {
		name, url, audience, id string
	}{
		{"plain", "https://prover.core.example.dev/login/8f3c", "https://prover.core.example.dev", "8f3c"},
		{"mount prefix", "https://prover.core.example.dev/api/login/8f3c", "https://prover.core.example.dev/api", "8f3c"},
		{"deep prefix", "https://h.example/a/b/c/login/ab12", "https://h.example/a/b/c", "ab12"},
		{"ws folds to http", "ws://h.example/login/1a", "http://h.example", "1a"},
		{"wss folds to https", "wss://h.example/api/login/1a", "https://h.example/api", "1a"},
		{"scheme lowercased", "HTTPS://h.example/login/1a", "https://h.example", "1a"},
		{"host lowercased", "https://Prover.Core.Example.DEV/login/1a", "https://prover.core.example.dev", "1a"},
		{"port kept", "http://localhost:8080/api/login/1a", "http://localhost:8080/api", "1a"},
		{"path case kept", "https://h.example/API/login/1a", "https://h.example/API", "1a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			audience, idBytes, err := login.DeriveAudience(c.url)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if audience != c.audience {
				t.Errorf("audience = %q, want %q", audience, c.audience)
			}
			// The scheme returns the id DECODED; this lane carries it as hex on the wire.
			if got := hex.EncodeToString(idBytes); got != c.id {
				t.Errorf("id = %q, want %q", got, c.id)
			}
		})
	}
}

// Every refusal here is a URL that must NOT yield an audience. A guess would be worse
// than a refusal: it would silently sign for something the person did not read.
func TestDeriveAudienceRefuses(t *testing.T) {
	for _, c := range []struct{ name, url string }{
		{"no login segment", "https://h.example/api/8f3c"},
		{"wrong mount", "https://h.example/signin/8f3c"},
		{"too few segments", "https://h.example/login"},
		{"empty path", "https://h.example/"},
		{"no host", "https:///login/1a"},
		{"foreign scheme", "ftp://h.example/login/1a"},
		{"file scheme", "file:///login/1a"},
		{"query present", "https://h.example/login/1?next=evil"},
		{"fragment present", "https://h.example/login/1#x"},
		{"not a url", "::::"},
		// A TRAILING SLASH IS NOW A REFUSAL, and this lane used to ACCEPT it and trim it.
		// docs/login.md §2.1 makes it an empty segment; the oracle case is
		// `trailing-slash-rejected`. My test was encoding a normalisation — the kind the
		// whole point of moving this into the scheme was to stop — so it flipped rather
		// than the scheme bending to it.
		{"trailing slash", "https://prover.core.example.dev/api/login/8f3c/"},
		// Userinfo is refused, not normalised: the three parsers disagree about it, and the
		// disagreement is the phished-invocation shape the audience rule exists to stop.
		{"userinfo with password", "https://user:pass@h.example/api/login/8f3c"},
		{"userinfo without password", "https://user@h.example/login/8f3c"},
		// The id is BYTES carried as lowercase hex (docs/login.md §3.1, §4). Anything else
		// is refused rather than normalised: the CLI binds the decoded bytes and the server
		// binds its stored ones, so a difference here is a real disagreement.
		{"id is percent-encoded", "https://h.example/login/a%20b"},
		{"id has a space", "https://h.example/login/a b"},
		{"id is uppercase hex", "https://h.example/login/8F3C"},
		{"id is odd-length hex", "https://h.example/login/8f3"},
		{"id is not hex", "https://h.example/login/zzzz"},
		{"id is a single hex digit", "https://h.example/login/a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if audience, id, err := login.DeriveAudience(c.url); err == nil {
				t.Fatalf("accepted %q -> audience %q id %x; want refusal", c.url, audience, id)
			}
		})
	}
}

func validRequest() *loginRequest {
	return &loginRequest{
		ID:       "8f3c",
		Nonce:    strings.Repeat("ab", 16), // 16 bytes, the floor
		Browser:  testBrowserKey,
		Scope:    []string{"read:projects", "read:campaigns"},
		ValidFor: 28800,
		Expires:  "2026-09-10T18:04:00Z",
	}
}

func TestValidateLoginRequestAccepts(t *testing.T) {
	if err := validateLoginRequest(validRequest(), "8f3c"); err != nil {
		t.Fatalf("rejected a valid request: %v", err)
	}
}

func TestValidateLoginRequestRefuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(*loginRequest)
	}{
		{"id mismatch", func(r *loginRequest) { r.ID = "other" }},
		{"nonce not hex", func(r *loginRequest) { r.Nonce = "zzzz" }},
		{"nonce too short", func(r *loginRequest) { r.Nonce = strings.Repeat("ab", 15) }},
		{"browser not key text", func(r *loginRequest) { r.Browser = "7a91" }},
		{"browser wrong algorithm", func(r *loginRequest) { r.Browser = "rsa:7a91" }},
		{"empty scope entry", func(r *loginRequest) { r.Scope = []string{"read:projects", ""} }},
		{"valid_for zero", func(r *loginRequest) { r.ValidFor = 0 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := validRequest()
			c.break_(r)
			if err := validateLoginRequest(r, "8f3c"); err == nil {
				t.Fatalf("accepted %s; want refusal", c.name)
			}
		})
	}
}

// A scope entry is printed verbatim to a terminal. An escape sequence there can erase or
// repaint the statement the person is about to approve, so control characters are a
// security refusal and not a formatting nicety.
func TestValidateRefusesUndisplayableScope(t *testing.T) {
	// Control characters AND invalid UTF-8: both can make the display lie about what is
	// being bound, and the scheme refuses both at Binding, which is AFTER the person has
	// already been shown the statement and agreed to it.
	for _, bad := range []string{
		"read:\x1b[2Jprojects", "read:\nprojects", "read:\rprojects",
		"read:\x00projects", "read:\x7fprojects",
		"read:\xff\xfeprojects", // not valid UTF-8
	} {
		r := validRequest()
		r.Scope = []string{bad}
		if err := validateLoginRequest(r, "8f3c"); err == nil {
			t.Fatalf("accepted scope entry %q; want refusal", bad)
		}
	}
}

// The statement is the contract with the person AND the cross-lane pin: all three
// binaries must produce these bytes exactly.
func TestRenderStatement(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 4, 0, 0, time.UTC)
	got := renderStatement("https://prover.core.example.dev/api", validRequest(), now, "the seed file /keys/julia")
	want := "https://prover.core.example.dev/api asks you to let browser key " + testBrowserKey + " act as you:\n" +
		"  read:projects\n" +
		"  read:campaigns\n" +
		"for 8h0m0s, until 2026-09-10T18:04:00Z\n" +
		"signing with the seed file /keys/julia\n"
	if got != want {
		t.Fatalf("statement mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderStatementKeepsScopeOrderAndVerbatim(t *testing.T) {
	r := validRequest()
	r.Scope = []string{"publish:projects/bun/workers/w1", "read:projects"}
	got := renderStatement("https://h.example", r, time.Unix(0, 0).UTC(), "the seed given on the command line")
	first := strings.Index(got, "publish:projects/bun/workers/w1")
	second := strings.Index(got, "read:projects")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("scope order not preserved verbatim: %q", got)
	}
}

// An empty scope is VALID (docs/login.md §3.1) and must still say so on screen.
func TestRenderStatementStatesAnEmptyScope(t *testing.T) {
	r := validRequest()
	r.Scope = nil
	got := renderStatement("https://h.example", r, time.Unix(0, 0).UTC(), "the seed given on the command line")
	if !strings.Contains(got, noScopeLine) {
		t.Fatalf("an empty scope must be stated, not shown as a blank: %q", got)
	}
}

// Default ports are omitted (docs/login.md §2): the server binds its configured audience,
// which has no :443 in it, so keeping the port binds a different string.
func TestDeriveAudienceOmitsDefaultPorts(t *testing.T) {
	for _, c := range []struct{ url, audience string }{
		{"https://h.example:443/api/login/8f3c", "https://h.example/api"},
		{"http://h.example:80/api/login/8f3c", "http://h.example/api"},
		{"https://h.example:8443/login/8f3c", "https://h.example:8443"},
		{"http://localhost:8080/api/login/8f3c", "http://localhost:8080/api"},
		{"http://[::1]:8080/login/8f3c", "http://[::1]:8080"},
		{"https://[::1]:443/login/8f3c", "https://[::1]"},
		{"wss://h.example:443/login/8f3c", "https://h.example"},
	} {
		got, _, err := login.DeriveAudience(c.url)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if got != c.audience {
			t.Errorf("audience for %s = %q, want %q", c.url, got, c.audience)
		}
	}
}

// A percent-escape in the BASE path must survive as written: url.Parse's decoded Path would
// turn %2F into a segment separator here and leave it escaped in the other two lanes.
func TestDeriveAudienceKeepsTheEscapedPath(t *testing.T) {
	got, idBytes, err := login.DeriveAudience("https://h.example/a%2Fb/login/8f3c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id := hex.EncodeToString(idBytes); got != "https://h.example/a%2Fb" || id != "8f3c" {
		t.Fatalf("audience = %q id = %q; the escaped path must be preserved", got, id)
	}
}

func TestFormatDuration(t *testing.T) {
	for _, c := range []struct {
		seconds uint32
		want    string
	}{
		{28800, "8h0m0s"}, {3600, "1h0m0s"}, {3661, "1h1m1s"},
		{300, "5m0s"}, {90, "1m30s"}, {45, "45s"}, {1, "1s"},
	} {
		if got := formatDuration(c.seconds); got != c.want {
			t.Errorf("formatDuration(%d) = %q, want %q", c.seconds, got, c.want)
		}
	}
}

// Default-no is the whole point of a confirmation prompt: a login must never complete
// because stdin happened to be closed or held something unexpected.
func TestConfirmDefaultsToNo(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"y\n", true}, {"Y\n", true}, {"yes\n", true}, {"YES\n", true}, {" y \n", true},
		{"n\n", false}, {"\n", false}, {"", false}, {"maybe\n", false}, {"yolo\n", false},
	} {
		got, err := confirm(strings.NewReader(c.in))
		if err != nil {
			t.Fatalf("confirm(%q) errored: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("confirm(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSeedFromHexFile(t *testing.T) {
	seed32 := strings.Repeat("11", 32)
	if got, err := seedFromHexFile(seed32 + "\n"); err != nil || len(got) != 32 {
		t.Fatalf("32-byte seed: got %d bytes, err %v", len(got), err)
	}
	// the first consumer's key files are 128 hex characters: the seed followed by the public key.
	if got, err := seedFromHexFile(seed32 + strings.Repeat("22", 32)); err != nil || len(got) != 32 {
		t.Fatalf("64-byte private key: got %d bytes, err %v", len(got), err)
	} else if got[0] != 0x11 {
		t.Fatalf("took the wrong half of the private key")
	}
	for _, bad := range []string{"", "zz", strings.Repeat("11", 31)} {
		if _, err := seedFromHexFile(bad); err == nil {
			t.Fatalf("accepted bad seed file %q", bad)
		}
	}
}

// The transport, against a stub service — the shape archon#16 asks for.
func TestFetchLoginRequestAgainstStub(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login/8f3c" {
			t.Errorf("GET path = %q, want /api/login/8f3c", r.URL.Path)
		}
		json.NewEncoder(w).Encode(validRequest())
	}))
	defer server.Close()

	audience, idBytes, err := login.DeriveAudience(server.URL + "/api/login/8f3c")
	id := hex.EncodeToString(idBytes)
	if err != nil {
		t.Fatalf("deriveAudience: %v", err)
	}
	got, err := fetchLoginRequest(audience, id)
	if err != nil {
		t.Fatalf("fetchLoginRequest: %v", err)
	}
	if err := validateLoginRequest(got, id); err != nil {
		t.Fatalf("validateLoginRequest: %v", err)
	}
	if got.Browser != testBrowserKey {
		t.Errorf("browser = %q", got.Browser)
	}
}

// An unknown field is a service speaking a different version of the protocol. Refuse it
// rather than silently ignoring the part we do not understand — and in particular, refuse
// an `audience` field, which is exactly the wire value Finding 1 forbids trusting.
func TestFetchRefusesUnknownFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"8f3c","nonce":"` + strings.Repeat("ab", 16) + `","browser":"` + testBrowserKey +
			`","scope":["read:projects"],"valid_for":60,"expires":"","audience":"https://evil.example"}`))
	}))
	defer server.Close()
	audienceB, idBytesB, _ := login.DeriveAudience(server.URL + "/login/8f3c")
	audience, id := audienceB, hex.EncodeToString(idBytesB)
	if _, err := fetchLoginRequest(audience, id); err == nil {
		t.Fatal("accepted a request carrying an audience field; want refusal")
	}
}

func TestFetchSurfacesRFC8628Errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"expired_token"}`))
	}))
	defer server.Close()
	audienceB, idBytesB, _ := login.DeriveAudience(server.URL + "/login/8f3c")
	audience, id := audienceB, hex.EncodeToString(idBytesB)
	_, err := fetchLoginRequest(audience, id)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want an expiry diagnosis", err)
	}
}

func TestPostLoginAnswerAgainstStub(t *testing.T) {
	var seen loginAnswer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/8f3c/answer" {
			t.Errorf("POST path = %q", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&seen)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	audienceB, idBytesB, _ := login.DeriveAudience(server.URL + "/login/8f3c")
	audience, id := audienceB, hex.EncodeToString(idBytesB)
	answer := loginAnswer{Principal: testBrowserKey, Possession: "aabb", Authority: ""}
	if err := postLoginAnswer(audience, id, answer); err != nil {
		t.Fatalf("postLoginAnswer: %v", err)
	}
	if seen.Possession != "aabb" || seen.Principal != testBrowserKey {
		t.Fatalf("service saw %+v", seen)
	}
}

// The seam is wired (sdk/go/login, archon#19). The proof it returns must VERIFY under the
// scheme's own verifier — this lane converts wire values to scheme values, and a
// conversion bug is exactly what would otherwise sail through as a plausible-looking
// signature.
func TestProveLoginProducesAProofTheSchemeVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	r := validRequest()
	const audience = "https://prover.core.example.dev/api"

	proof, principal, err := proveLogin(seed, audience, r)
	if err != nil {
		t.Fatalf("proveLogin: %v", err)
	}
	if !strings.HasPrefix(principal, "ed25519:") {
		t.Fatalf("principal = %q, want canonical key text", principal)
	}

	nonce, _ := hex.DecodeString(r.Nonce)
	browser, _ := keytext.DecodeKey(r.Browser)
	idBytes, _ := hex.DecodeString(r.ID)
	req := &login.Request{ID: idBytes, Nonce: nonce, Browser: browser, Scope: r.Scope, ValidFor: r.ValidFor}
	if !login.Verify(crypto.PublicKeyFromSeed(seed), audience, req, proof) {
		t.Fatal("the scheme does not verify the proof this lane produced")
	}

	// And it must be bound to THIS audience: a proof that verifies elsewhere is the whole
	// hazard the derived-audience rule exists to prevent.
	if login.Verify(crypto.PublicKeyFromSeed(seed), "https://evil.example", req, proof) {
		t.Fatal("the proof verified against a different audience — the binding is not doing its job")
	}

	// THE ID IS BOUND AS DECODED BYTES, NOT AS THE ASCII OF ITS HEX TEXT.
	//
	// This assertion exists because the lane got it wrong and the earlier stub test did not
	// notice: it built its expected Request the same wrong way, so both sides agreed with
	// each other and neither agreed with the server. A proof over the ASCII form must FAIL
	// here — if it ever passes, the two encodings have been conflated again.
	asciiReq := &login.Request{ID: []byte(r.ID), Nonce: nonce, Browser: browser, Scope: r.Scope, ValidFor: r.ValidFor}
	if login.Verify(crypto.PublicKeyFromSeed(seed), audience, asciiReq, proof) {
		t.Fatal("the proof verified against an id bound as ASCII hex text; it must be the DECODED bytes")
	}
}

// The whole flow against a stub service, which is the case seat:cca asked each lane to
// carry in its unit tests. (The smoke run was pre-network until the store's consumer
// needed a server; it now hosts one itself — see cli/smoke.mjs — and verifies against the
// oracle's key, never a lane's.) The tests above each cover one half; this covers the join
// — what the service sends, through validation and conversion, into a proof the SCHEME
// accepts.
func TestEndToEndAgainstAStubService(t *testing.T) {
	var gotPath, postPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotPath = r.URL.Path
			json.NewEncoder(w).Encode(validRequest())
			return
		}
		postPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	audience, idBytes, err := login.DeriveAudience(server.URL + "/api/login/8f3c")
	id := hex.EncodeToString(idBytes)
	if err != nil {
		t.Fatalf("deriveAudience: %v", err)
	}
	if audience != server.URL+"/api" {
		t.Fatalf("audience = %q; it must come from the URL, not the wire", audience)
	}

	request, err := fetchLoginRequest(audience, id)
	if err != nil {
		t.Fatalf("fetchLoginRequest: %v", err)
	}
	if err := validateLoginRequest(request, id); err != nil {
		t.Fatalf("validateLoginRequest: %v", err)
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	proof, principal, err := proveLogin(seed, audience, request)
	if err != nil {
		t.Fatalf("proveLogin: %v", err)
	}
	if err := postLoginAnswer(audience, id, loginAnswer{Principal: principal, Possession: hex.EncodeToString(proof)}); err != nil {
		t.Fatalf("postLoginAnswer: %v", err)
	}
	if gotPath != "/api/login/8f3c" || postPath != "/api/login/8f3c/answer" {
		t.Fatalf("paths: GET %q POST %q", gotPath, postPath)
	}

	// The proof must verify for THIS audience and no other.
	nonce, _ := hex.DecodeString(request.Nonce)
	browser, _ := keytext.DecodeKey(request.Browser)
	boundID, _ := hex.DecodeString(request.ID)
	req := &login.Request{ID: boundID, Nonce: nonce, Browser: browser, Scope: request.Scope, ValidFor: request.ValidFor}
	pubkey := crypto.PublicKeyFromSeed(seed)
	if !login.Verify(pubkey, audience, req, proof) {
		t.Fatal("the scheme rejected the proof from the full flow")
	}
	if login.Verify(pubkey, "https://evil.example", req, proof) {
		t.Fatal("the proof was not bound to its audience")
	}
}

// THE CROSS-LANE STATEMENT FIXTURE. This is where the three lanes are held together: all
// three suites read the SAME file and assert their renderer reproduces it byte for byte.
// (cli/smoke.mjs pins one rendered statement too, from the store-key login it runs against
// the server it hosts; this fixture is what pins every OTHER source line, with no network.)
//
// CAVEAT, measured: the fixture lives outside this module, so Go's test cache does not treat
// it as an input. After editing ONLY the fixture, `go test ./...` can report `ok (cached)`
// and miss the change — run `go test -count=1 ./...`. CI is unaffected (fresh checkout, no
// cache), and the Rust and TypeScript lanes re-read it every run.
func TestStatementMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "login-statement.json"))
	if err != nil {
		t.Fatalf("could not read the shared fixture: %v", err)
	}
	var fixture struct {
		Cases []struct {
			Name      string       `json:"name"`
			Audience  string       `json:"audience"`
			KeySource string       `json:"keySource"`
			NowUnix   int64        `json:"nowUnix"`
			Request   loginRequest `json:"request"`
			Statement string       `json:"statement"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("the shared fixture is not the expected JSON: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("the shared fixture holds no cases — a fixture nobody can fail is not a pin")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := renderStatement(c.Audience, &c.Request, time.Unix(c.NowUnix, 0).UTC(), c.KeySource)
			if got != c.Statement {
				t.Fatalf("statement differs from the shared fixture\n got: %q\nwant: %q", got, c.Statement)
			}
		})
	}
}

// The fixture pins describeKeySource's OUTPUT for whichever source a case names; this pins
// the branch selection itself — and that a store key is named by its NAME, never a
// principal, whether --key chose it or the default pointer did.
func TestDescribeKeySource(t *testing.T) {
	for _, c := range []struct {
		name string
		src  loginSource
		want string
	}{
		{"store key", loginSource{storeKey: "julia"}, "the store key julia"},
		{"seed file", loginSource{seedFile: "/keys/julia"}, "the seed file /keys/julia"},
		{"key file", loginSource{keyFile: "k.pem"}, "the key file k.pem"},
		{"seed on the command line", loginSource{seedHex: "ab"}, "the seed given on the command line"},
		{"nothing decided", loginSource{}, "an unspecified key"},
	} {
		if got := describeKeySource(c.src); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// captureStdout swaps os.Stdout for a pipe around fn. The command prints the statement and
// the outcome with fmt, and pinning what a person would have SEEN is the point of the test
// below. fn's error is returned rather than asserted inside, so stdout is always restored.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	out, _, err := captureBoth(t, fn)
	return out, err
}

// captureBoth swaps os.Stdout AND os.Stderr for pipes around fn, because the offers form
// writes to both on purpose (§4.1 rule 1: the code to stderr, the ledger to stdout) and the
// test's point is that each went where it belongs. Safe in Go: the testing package holds the
// original *os.File, so nothing of the runner's own reporting travels through the swap.
func captureBoth(t *testing.T, fn func() error) (stdout, stderr string, runErr error) {
	t.Helper()
	pipe := func(target **os.File) func() string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := *target
		*target = w
		done := make(chan string)
		go func() {
			b, _ := io.ReadAll(r)
			done <- string(b)
		}()
		return func() string {
			*target = saved
			w.Close()
			return <-done
		}
	}
	outDone := pipe(&os.Stdout)
	errDone := pipe(&os.Stderr)
	runErr = fn()
	return outDone(), errDone(), runErr
}

// ---- THE OFFERS FORM (docs/login.md §4.1) ------------------------------------------------

// THE LEDGER FIXTURE (§4.1 rule 4): the offers form prints, AFTER answering, the same fields
// the confirmed form shows before signing, and all three lanes must print the ledger
// byte-identically too. Same shared file, second section.
func TestLedgerMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "login-statement.json"))
	if err != nil {
		t.Fatalf("could not read the shared fixture: %v", err)
	}
	var fixture struct {
		OfferCases []struct {
			Name      string       `json:"name"`
			Audience  string       `json:"audience"`
			KeySource string       `json:"keySource"`
			NowUnix   int64        `json:"nowUnix"`
			Request   loginRequest `json:"request"`
			Verdict   string       `json:"verdict"`
			Ledger    string       `json:"ledger"`
		} `json:"offer_cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("the shared fixture is not the expected JSON: %v", err)
	}
	if len(fixture.OfferCases) == 0 {
		t.Fatal("the shared fixture holds no offer_cases — a fixture nobody can fail is not a pin")
	}
	for _, c := range fixture.OfferCases {
		t.Run(c.Name, func(t *testing.T) {
			accepted := c.Verdict == "accepted"
			code := ""
			if !accepted {
				code = strings.TrimPrefix(c.Verdict, "refused:")
			}
			got := renderLedger(c.Audience, &c.Request, time.Unix(c.NowUnix, 0).UTC(), c.KeySource, accepted, code)
			if got != c.Ledger {
				t.Fatalf("ledger differs from the shared fixture\n got: %q\nwant: %q", got, c.Ledger)
			}
		})
	}
}

// The page address is PRINTED AND MARKED, never opened (§4.1 rule 1; ADR 0007 §C.7 (6)):
// "on the service's own origin" is a byte-exact comparison of scheme and host with the
// audience's, so a differently spelled origin fails closed.
func TestDescribePage(t *testing.T) {
	const audience = "https://dawn.example/api"
	const on = " (on the service's own origin)"
	const off = " (NOT on the service's origin — do not open it)"
	for _, c := range []struct{ page, want string }{
		{"https://dawn.example/login", "page: https://dawn.example/login" + on},
		{"https://dawn.example/login#abc", "page: https://dawn.example/login#abc" + on},
		{"https://dawn.example", "page: https://dawn.example" + on},
		{"https://dawn.example.evil/login", "page: https://dawn.example.evil/login" + off},
		{"https://evil.example/login", "page: https://evil.example/login" + off},
		{"HTTPS://dawn.example/login", "page: HTTPS://dawn.example/login" + off},
		{"http://dawn.example/login", "page: http://dawn.example/login" + off},
		{"/login", "page: /login" + off},
	} {
		if got := describePage(audience, c.page); got != c.want {
			t.Errorf("describePage(%q) = %q, want %q", c.page, got, c.want)
		}
	}
	// The port is part of the origin.
	if got := describePage("http://127.0.0.1:8080/api", "http://127.0.0.1:8080/login"); !strings.HasSuffix(got, on) {
		t.Errorf("same host and port must be on origin: %q", got)
	}
	if got := describePage("http://127.0.0.1:8080/api", "http://127.0.0.1:8081/login"); !strings.HasSuffix(got, off) {
		t.Errorf("another port is another origin: %q", got)
	}
}

// §4.1 rule 1: the audience is --audience, or ARCHON_AUDIENCE as the configured default,
// checked exactly the same way — a fixed point of §2.1's grammar — and refused otherwise,
// naming the spelling the service would bind.
func TestConfiguredAudience(t *testing.T) {
	t.Setenv("ARCHON_AUDIENCE", "")
	if _, err := configuredAudience(""); err == nil || !strings.Contains(err.Error(), "ARCHON_AUDIENCE") {
		t.Fatalf("no audience anywhere: err = %v, want a refusal naming the two sources", err)
	}
	if got, err := configuredAudience("http://localhost:8080"); err != nil || got != "http://localhost:8080" {
		t.Fatalf("a canonical flag: %q, %v", got, err)
	}
	t.Setenv("ARCHON_AUDIENCE", "https://dawn.example/api")
	if got, err := configuredAudience(""); err != nil || got != "https://dawn.example/api" {
		t.Fatalf("the environment default: %q, %v", got, err)
	}
	if got, err := configuredAudience("https://other.example"); err != nil || got != "https://other.example" {
		t.Fatalf("the flag wins over the environment: %q, %v", got, err)
	}
	for _, bad := range []string{
		"https://Dawn.example/api",     // host case
		"https://dawn.example/api/",    // trailing slash — an empty segment
		"https://dawn.example:443/api", // a default port
		"wss://dawn.example/api",       // a scheme the grammar folds
		"not an audience",
	} {
		if _, err := configuredAudience(bad); err == nil {
			t.Errorf("accepted %q; want a refusal", bad)
		}
	}
	// The refusal names what the service binds, so the fix is in the message.
	_, err := configuredAudience("https://Dawn.example/api")
	if err == nil || !strings.Contains(err.Error(), `"https://dawn.example/api"`) {
		t.Fatalf("a non-canonical audience must be refused naming the derived spelling: %v", err)
	}
}

// offerStub plays the SERVICE for the offers form: the four routes the form touches,
// scripted per scenario, and the answer verified with the scheme against the sealed key's
// own public key. Every request is logged BEFORE it is answered, because WHERE a refusal
// lands is the point of most scenarios.
type offerStub struct {
	mu        sync.Mutex
	offers    map[string]offerBody
	requests  []string
	polls     int
	pollPlan  []int // a scripted status per successive poll; 0 means "answer normally"
	takenAt   int   // the poll (1-based) from which `request` names the id; 0 means never
	interval  int
	expiresIn int
	page      string
	echo      func(*offerResponse)
	alter     func(*loginRequest)
	refuse    string
	browser   string
	id        string
	pubkey    []byte
	principal string
	posted    *loginAnswer
	verified  bool
}

func (s *offerStub) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offers = map[string]offerBody{}
	s.requests = nil
	s.polls = 0
	s.pollPlan = nil
	s.takenAt = 2
	s.interval = 2
	s.expiresIn = 300
	s.page = ""
	s.echo = nil
	s.alter = nil
	s.refuse = ""
	s.posted = nil
	s.verified = false
}

// requestFor is the request the page "began" on the (single) offer: the offer's scope and
// validity, the stub's own browser key K, a fixed nonce.
func (s *offerStub) requestFor() *loginRequest {
	r := &loginRequest{ID: s.id, Nonce: strings.Repeat("ab", 16), Browser: s.browser}
	for _, offer := range s.offers {
		r.Scope, r.ValidFor = offer.Scope, offer.ValidFor
	}
	return r
}

func (s *offerStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	fail := func(status int, code string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/login/offers":
		var body offerBody
		json.NewDecoder(r.Body).Decode(&body)
		s.offers[body.Code] = body
		resp := offerResponse{Code: body.Code, Scope: body.Scope, ValidFor: body.ValidFor, ExpiresIn: s.expiresIn, Interval: s.interval}
		if s.page != "" {
			resp.Page = s.page + "#" + body.Code
		}
		if s.echo != nil {
			s.echo(&resp)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/login/offers/"):
		code := strings.TrimPrefix(r.URL.Path, "/api/login/offers/")
		s.polls++
		if s.polls <= len(s.pollPlan) && s.pollPlan[s.polls-1] != 0 {
			status := s.pollPlan[s.polls-1]
			if status == http.StatusTooManyRequests {
				fail(status, "slow_down")
			} else {
				fail(status, "expired_token")
			}
			return
		}
		offer, ok := s.offers[code]
		if !ok {
			fail(http.StatusNotFound, "expired_token")
			return
		}
		var request *string
		if s.takenAt > 0 && s.polls >= s.takenAt {
			request = &s.id
		}
		json.NewEncoder(w).Encode(offerRead{Code: code, Scope: offer.Scope, ValidFor: offer.ValidFor, Request: request, Expires: "2026-09-10T10:09:00Z"})
	case r.Method == http.MethodGet && r.URL.Path == "/api/login/"+s.id:
		req := s.requestFor()
		if s.alter != nil {
			s.alter(req)
		}
		json.NewEncoder(w).Encode(req)
	case r.Method == http.MethodPost && r.URL.Path == "/api/login/"+s.id+"/answer":
		var answer loginAnswer
		json.NewDecoder(r.Body).Decode(&answer)
		s.posted = &answer
		vr := s.requestFor()
		nonce, _ := hex.DecodeString(vr.Nonce)
		browser, _ := keytext.DecodeKey(vr.Browser)
		idBytes, _ := hex.DecodeString(vr.ID)
		proof, _ := hex.DecodeString(answer.Possession)
		req := &login.Request{ID: idBytes, Nonce: nonce, Browser: browser, Scope: vr.Scope, ValidFor: vr.ValidFor}
		s.verified = answer.Principal == s.principal && login.Verify(s.pubkey, "http://"+r.Host+"/api", req, proof)
		if s.refuse != "" {
			fail(http.StatusForbidden, s.refuse)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(http.StatusNotFound, "expired_token")
	}
}

func (s *offerStub) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

func (s *offerStub) theCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.offers) != 1 {
		t.Fatalf("%d offers registered, want exactly one", len(s.offers))
	}
	for code := range s.offers {
		return code
	}
	return ""
}

// THE OFFERS FORM, end to end, from a sealed store key: the real runLogin with no URL against
// the stub above. The clock is pinned so the ledger is byte-exact, and the sleeps are
// RECORDED rather than slept, because the pacing is the prover's own (ADR 0007 §C.7, #39) and
// therefore this lane's to pin: one interval before the first poll, one between polls.
//
// The scenarios say where each refusal lands: the flag refusals before any request; a
// divergent request after the poll but before any answer; a service refusal in the ledger.
// And they say where each byte goes: the code on stderr and never on stdout (§4.1 rule 1).
func TestOffersFromASealedStoreKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ARCHON_HOME", home)
	const password = "a password with a space"
	t.Setenv("ARCHON_KEY_PASSWORD", password)
	t.Setenv("ARCHON_AUDIENCE", "")

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 9)
	}
	pubkey := crypto.PublicKeyFromSeed(seed)
	principal := keytext.EncodeKey(pubkey)
	if _, err := sealAndWrite(filepath.Join(home, "keys", "julia"), seed, []byte(password)); err != nil {
		t.Fatalf("sealAndWrite: %v", err)
	}
	browserSeed := make([]byte, 32)
	for i := range browserSeed {
		browserSeed[i] = byte(0x40 + i)
	}
	K := keytext.EncodeKey(crypto.PublicKeyFromSeed(browserSeed))

	stub := &offerStub{browser: K, id: "8f3c", pubkey: pubkey, principal: principal}
	server := httptest.NewServer(stub)
	defer server.Close()
	audience := server.URL + "/api"

	fixedNow := time.Date(2026, 9, 10, 10, 4, 0, 0, time.UTC)
	savedClock, savedSleep := clockNow, sleepFor
	t.Cleanup(func() { clockNow = savedClock; sleepFor = savedSleep })
	clockNow = func() time.Time { return fixedNow }
	var sleeps []time.Duration
	sleepFor = func(d time.Duration) { sleeps = append(sleeps, d) }
	reset := func() {
		stub.reset()
		sleeps = nil
	}
	scope := []string{"--scope", "read:projects", "--scope", "read:campaigns"}
	base := append([]string{"--audience", audience}, append(scope, "--valid-for", "28800", "--key", "julia")...)
	ledger := func(verdict string) string {
		return "you offered " + audience + " to let browser key " + K + " act as you:\n" +
			"  read:projects\n  read:campaigns\n" +
			"for 8h0m0s, until 2026-09-10T18:04:00Z\n" +
			"signed with the store key julia\n" + verdict
	}
	run := func(args ...string) (string, string, error) {
		return captureBoth(t, func() error { return runLogin(args) })
	}

	t.Run("offers, waits for the page, answers only the request that took the offer", func(t *testing.T) {
		reset()
		stub.page = server.URL + "/login"
		out, errOut, err := run(base...)
		if err != nil {
			t.Fatalf("runLogin: %v\nstderr:\n%s", err, errOut)
		}
		code := stub.theCode(t)
		if len(code) != 2*codeBytes {
			t.Fatalf("the code has %d hex characters, want %d", len(code), 2*codeBytes)
		}
		// stdout is the ledger and nothing else — never the code.
		if out != ledger("the service accepted the login. the browser is in.\n") {
			t.Fatalf("stdout is not the ledger:\n%s", out)
		}
		if strings.Contains(out, code) {
			t.Fatal("the code was printed on stdout — stdout may be a log")
		}
		// stderr carries the code, the page marked on-origin, and the wait.
		for _, want := range []string{
			"offer registered at " + audience + "\n",
			"code: " + code + "\n",
			"page: " + server.URL + "/login#" + code + " (on the service's own origin)\n",
			"waiting for the page to take the offer, up to 300s\n",
		} {
			if !strings.Contains(errOut, want) {
				t.Errorf("stderr lacks %q:\n%s", want, errOut)
			}
		}
		// The pacing is the prover's own: one interval BEFORE the first poll, one between.
		if len(sleeps) != 2 || sleeps[0] != 2*time.Second || sleeps[1] != 2*time.Second {
			t.Fatalf("sleeps = %v, want [2s 2s] — one before each of the two polls", sleeps)
		}
		want := []string{"POST /api/login/offers", "GET /api/login/offers/" + code, "GET /api/login/offers/" + code,
			"GET /api/login/8f3c", "POST /api/login/8f3c/answer"}
		if got := stub.seen(); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("requests = %v, want %v", got, want)
		}
		if !stub.verified || stub.posted == nil || stub.posted.Principal != principal {
			t.Fatal("the service did not verify a proof for the sealed key's principal")
		}
	})

	t.Run("a request that differs from the offer is refused, and nothing is signed", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			alter func(*loginRequest)
		}{
			{"a changed entry", func(r *loginRequest) { r.Scope = []string{"read:projects", "read:campaign"} }},
			{"a reordered entry", func(r *loginRequest) { r.Scope = []string{"read:campaigns", "read:projects"} }},
			{"an extra entry", func(r *loginRequest) { r.Scope = append(r.Scope, "write:projects") }},
			{"a dropped entry", func(r *loginRequest) { r.Scope = r.Scope[:1] }},
			{"a changed validity", func(r *loginRequest) { r.ValidFor = 28801 }},
		} {
			t.Run(c.name, func(t *testing.T) {
				reset()
				stub.alter = c.alter
				out, _, err := run(base...)
				if err == nil || !strings.Contains(err.Error(), "differs from the offer") {
					t.Fatalf("err = %v, want the rule-2 refusal", err)
				}
				if out != "" {
					t.Fatalf("a refused login printed a ledger:\n%s", out)
				}
				if stub.posted != nil {
					t.Fatal("an answer was posted for a request that differs from the offer")
				}
			})
		}
	})

	t.Run("--yes is refused before any request", func(t *testing.T) {
		reset()
		_, _, err := run(append(append([]string{}, base...), "--yes")...)
		if err == nil || !strings.Contains(err.Error(), "drop --yes") {
			t.Fatalf("err = %v", err)
		}
		if n := len(stub.seen()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
	})

	t.Run("no audience is refused before any request", func(t *testing.T) {
		reset()
		_, _, err := run(append(scope, "--valid-for", "28800", "--key", "julia")...)
		if err == nil || !strings.Contains(err.Error(), "ARCHON_AUDIENCE") {
			t.Fatalf("err = %v", err)
		}
		if n := len(stub.seen()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
	})

	t.Run("a non-canonical --audience is refused naming the derived spelling", func(t *testing.T) {
		reset()
		shouted := strings.ToUpper(audience) // the scheme folds, the path is kept: derived differs
		_, _, err := run(append([]string{"--audience", shouted}, base[2:]...)...)
		if err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("err = %v", err)
		}
		if n := len(stub.seen()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
		_, _, err = run(append([]string{"--audience", audience + "/"}, base[2:]...)...)
		if err == nil || !strings.Contains(err.Error(), "not valid") {
			t.Fatalf("a trailing slash: err = %v", err)
		}
	})

	t.Run("ARCHON_AUDIENCE is the configured default", func(t *testing.T) {
		reset()
		t.Setenv("ARCHON_AUDIENCE", audience)
		out, _, err := run(base[2:]...)
		if err != nil {
			t.Fatalf("runLogin: %v", err)
		}
		if !strings.HasPrefix(out, "you offered "+audience+" ") || !stub.verified {
			t.Fatalf("the environment's audience was not used:\n%s", out)
		}
	})

	t.Run("a page not on the service's origin is marked, and nothing is opened", func(t *testing.T) {
		reset()
		stub.page = "https://evil.example/login"
		_, errOut, err := run(base...)
		if err != nil {
			t.Fatalf("runLogin: %v", err)
		}
		if !strings.Contains(errOut, "page: https://evil.example/login#"+stub.theCode(t)+" (NOT on the service's origin — do not open it)\n") {
			t.Fatalf("the page was not marked off-origin:\n%s", errOut)
		}
	})

	t.Run("a refusal by the service is recorded in the ledger", func(t *testing.T) {
		reset()
		stub.refuse = "invalid_grant"
		out, _, err := run(base...)
		if err == nil || !strings.Contains(err.Error(), "refused the login (invalid_grant)") {
			t.Fatalf("err = %v", err)
		}
		if out != ledger("the service refused the login (invalid_grant). the browser is not in.\n") {
			t.Fatalf("the ledger must record the refusal:\n%s", out)
		}
	})

	t.Run("an offer the page never took", func(t *testing.T) {
		reset()
		stub.pollPlan = []int{http.StatusNotFound}
		out, _, err := run(base...)
		if err == nil || !strings.Contains(err.Error(), "expired before the page took it") {
			t.Fatalf("err = %v", err)
		}
		if out != "" || stub.posted != nil {
			t.Fatal("nothing must be signed or printed for an offer nobody took")
		}
	})

	t.Run("a 429 is sleep-and-retry, never an error", func(t *testing.T) {
		reset()
		stub.pollPlan = []int{http.StatusTooManyRequests}
		stub.takenAt = 3
		_, _, err := run(base...)
		if err != nil {
			t.Fatalf("runLogin: %v", err)
		}
		if len(sleeps) != 3 || stub.polls != 3 {
			t.Fatalf("sleeps = %v, polls = %d; want one sleep before each of three polls", sleeps, stub.polls)
		}
	})

	t.Run("an echo that differs from the offer is refused before any poll", func(t *testing.T) {
		reset()
		stub.echo = func(r *offerResponse) { r.ValidFor++ }
		_, _, err := run(base...)
		if err == nil || !strings.Contains(err.Error(), "altered the offer") {
			t.Fatalf("err = %v", err)
		}
		if stub.polls != 0 {
			t.Fatalf("%d polls after an altered echo", stub.polls)
		}
	})

	t.Run("--valid-for is required, and is a whole positive number of seconds", func(t *testing.T) {
		reset()
		_, _, err := run(append([]string{"--audience", audience}, append(scope, "--key", "julia")...)...)
		if err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("err = %v", err)
		}
		for _, bad := range []string{"0", "-5", "8h", "1.5"} {
			_, _, err := run(append([]string{"--audience", audience}, append(scope, "--valid-for", bad, "--key", "julia")...)...)
			if err == nil {
				t.Errorf("accepted --valid-for %q", bad)
			}
		}
		if n := len(stub.seen()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
	})

	t.Run("a scope entry that could lie on screen is refused before any request", func(t *testing.T) {
		reset()
		_, _, err := run("--audience", audience, "--scope", "read:\x1b[2Jx", "--valid-for", "60", "--key", "julia")
		if err == nil || !strings.Contains(err.Error(), "control character") {
			t.Fatalf("err = %v", err)
		}
		_, _, err = run("--audience", audience, "--scope", "", "--valid-for", "60", "--key", "julia")
		if err == nil {
			t.Fatal("an empty --scope value was accepted")
		}
		if n := len(stub.seen()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
	})
}

// THE STORE'S CONSUMER, end to end: a key SEALED into a temp store, the real runLogin
// driven with --key and --yes against a stub service that verifies the proof with the
// scheme against the sealed seed's own public key. This is the row of ADR 0007 §A's table
// that was "not yet true" until this test could pass.
//
// The stub counts requests atomically (cli/go runs under -race in CI), and every scenario
// says how many it expects, because WHERE a refusal lands is the point: a bad name and a
// missing default are refused before any request is made; a wrong password is refused
// after the GET but before any POST — the unlock comes after show-and-confirm, and a
// failed unlock never posts.
func TestLoginFromASealedStoreKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ARCHON_HOME", home)
	const password = "a password with a space"
	t.Setenv("ARCHON_KEY_PASSWORD", password)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 9)
	}
	pubkey := crypto.PublicKeyFromSeed(seed)
	principal := keytext.EncodeKey(pubkey)
	if _, err := sealAndWrite(filepath.Join(home, "keys", "julia"), seed, []byte(password)); err != nil {
		t.Fatalf("sealAndWrite: %v", err)
	}

	var gets, posts atomic.Int32
	var verified atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
			json.NewEncoder(w).Encode(validRequest())
			return
		}
		posts.Add(1)
		var answer loginAnswer
		json.NewDecoder(r.Body).Decode(&answer)
		vr := validRequest()
		nonce, _ := hex.DecodeString(vr.Nonce)
		browser, _ := keytext.DecodeKey(vr.Browser)
		idBytes, _ := hex.DecodeString(vr.ID)
		proof, _ := hex.DecodeString(answer.Possession)
		req := &login.Request{ID: idBytes, Nonce: nonce, Browser: browser, Scope: vr.Scope, ValidFor: vr.ValidFor}
		// The audience is this server's own address, read from the request rather than
		// captured from the test goroutine, so the handler shares nothing unsynchronised.
		audience := "http://" + r.Host + "/api"
		if answer.Principal == principal && login.Verify(pubkey, audience, req, proof) {
			verified.Store(true)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	url := server.URL + "/api/login/8f3c"
	reset := func() {
		gets.Store(0)
		posts.Store(0)
		verified.Store(false)
	}
	expectRequests := func(t *testing.T, wantGets, wantPosts int32) {
		t.Helper()
		if gets.Load() != wantGets || posts.Load() != wantPosts {
			t.Fatalf("requests: %d GET %d POST, want %d GET %d POST", gets.Load(), posts.Load(), wantGets, wantPosts)
		}
	}

	t.Run("--key unlocks the sealed key and the proof verifies", func(t *testing.T) {
		reset()
		out, err := captureStdout(t, func() error { return runLogin([]string{url, "--key", "julia", "--yes"}) })
		if err != nil {
			t.Fatalf("runLogin: %v", err)
		}
		if !verified.Load() {
			t.Fatal("the service did not verify a proof for the sealed key's principal")
		}
		if !strings.Contains(out, "signing with the store key julia\n") {
			t.Fatalf("the statement did not name the store key:\n%s", out)
		}
		if !strings.HasSuffix(out, "signed as "+principal+". the browser is in.\n") {
			t.Fatalf("the outcome line is wrong:\n%s", out)
		}
		expectRequests(t, 1, 1)
	})

	t.Run("no source flag falls back to the store's default", func(t *testing.T) {
		reset()
		pointer := filepath.Join(home, "default")
		if err := os.WriteFile(pointer, []byte("julia\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(pointer)
		out, err := captureStdout(t, func() error { return runLogin([]string{url, "--yes"}) })
		if err != nil {
			t.Fatalf("runLogin: %v", err)
		}
		if !verified.Load() {
			t.Fatal("the default key did not produce a verified proof")
		}
		// The statement names the NAME the pointer resolved to, exactly as --key would.
		if !strings.Contains(out, "signing with the store key julia\n") {
			t.Fatalf("the statement did not name the default key:\n%s", out)
		}
		expectRequests(t, 1, 1)
	})

	t.Run("no source flag and no default is refused before any request", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error { return runLogin([]string{url, "--yes"}) })
		if err == nil || !strings.Contains(err.Error(), "no default key is set") {
			t.Fatalf("err = %v, want the store's own wording", err)
		}
		expectRequests(t, 0, 0)
	})

	t.Run("a name not in the store is refused before any request", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error { return runLogin([]string{url, "--key", "nobody", "--yes"}) })
		if err == nil || !strings.Contains(err.Error(), `no key named "nobody" in archon's store`) {
			t.Fatalf("err = %v, want the store's own wording", err)
		}
		expectRequests(t, 0, 0)
	})

	t.Run("a wrong password is refused after the statement and before any answer", func(t *testing.T) {
		reset()
		t.Setenv("ARCHON_KEY_PASSWORD", "not the password")
		out, err := captureStdout(t, func() error { return runLogin([]string{url, "--key", "julia", "--yes"}) })
		if err == nil || !strings.Contains(err.Error(), "wrong password") {
			t.Fatalf("err = %v, want the store's own wording", err)
		}
		// The person SAW the statement — the unlock is after it — and nothing was posted.
		if !strings.Contains(out, "signing with the store key julia\n") {
			t.Fatalf("the statement was not shown before the unlock:\n%s", out)
		}
		expectRequests(t, 1, 0)
		if verified.Load() {
			t.Fatal("a proof verified without the password")
		}
	})

	t.Run("two sources are refused before any request", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error {
			return runLogin([]string{url, "--key", "julia", "--seed", strings.Repeat("11", 32), "--yes"})
		})
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v, want the exclusivity refusal", err)
		}
		expectRequests(t, 0, 0)
	})

	t.Run("--password-fd beside a seed file is refused", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error {
			return runLogin([]string{url, "--seed", strings.Repeat("11", 32), "--password-fd", "3", "--yes"})
		})
		if err == nil || !strings.Contains(err.Error(), "applies only to a store key") {
			t.Fatalf("err = %v", err)
		}
		expectRequests(t, 0, 0)
	})

	t.Run("--password-fd 0 without --yes is refused", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error { return runLogin([]string{url, "--key", "julia", "--password-fd", "0"}) })
		if err == nil || !strings.Contains(err.Error(), "pass --yes") {
			t.Fatalf("err = %v", err)
		}
		expectRequests(t, 0, 0)
	})

	t.Run("a missing authority file is refused before any request", func(t *testing.T) {
		reset()
		_, err := captureStdout(t, func() error {
			return runLogin([]string{url, "--key", "julia", "--authority-file", filepath.Join(home, "no-such-file"), "--yes"})
		})
		if err == nil || !strings.Contains(err.Error(), "could not read") {
			t.Fatalf("err = %v", err)
		}
		// It used to be refused AFTER the person had read the statement and said yes: the
		// read sat on the far side of the prompt. A refusal belongs before the question.
		expectRequests(t, 0, 0)
	})
}
