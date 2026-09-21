package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/sdk/go/possession"
)

// The login command: prove possession of the person's key to a service, so a browser key
// it names may act for them within a scope the person is shown BEFORE signing.
//
// This file owns the TRANSPORT (HTTP/JSON), the DISPLAY (the statement the person
// confirms), and the FLOW. It deliberately owns NO scheme: the binding layout and the
// proof are sdk/*/login's (archon#16, seat:cca authorship comment 2026-09-10T13:01Z),
// reached through the single seam proveLogin below. Nothing here computes signed bytes —
// a second implementation of a binding is how two lanes drift apart.
//
// TWO FORMS, one command. With a URL (docs/login.md §4) the page started and the person
// finishes here: the audience is DERIVED FROM THE INVOCATION URL, never read from the wire
// (archon#16 Finding 1: a server that may name its own audience can name someone else's),
// the statement is shown, and nothing is signed until the person says yes. With no URL
// (§4.1, the offers form) the CLI starts and the page finishes: the audience is the CLI's
// OWN configuration, the CLI offers exactly what was typed, answers only the request that
// took its offer, asks no confirmation, and prints the ledger of that decision afterwards.

const loginUsage = "usage: archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] " +
	"[--authority-file <file>] [--yes]\n" +
	"       archon login --audience <base> [--scope <entry>]... --valid-for <seconds> " +
	"[--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] [--authority-file <file>]\n  " +
	"proves possession of your key to the service at <url> so the browser key it names may act for you. " +
	"<url> is the invocation URL <audience>/login/<id>; the audience is derived from it, never taken from the server. " +
	"--key names a key in the store and is the default (archon key default); --key-file is a PKCS#8 file. " +
	"Store password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv.\n  " +
	"with no URL, the CLI OFFERS what you typed and the page finishes: the audience is --audience or ARCHON_AUDIENCE, " +
	"never a page's word; the code and the page address go to stderr, the ledger to stdout after the service answers; " +
	"no confirmation is asked — what you typed is what you sign."

// clockNow and sleepFor are the two places this command meets wall-clock time. Package
// variables rather than calls, so a test can pin the ledger's wall-clock end and record the
// offers form's pacing without sleeping through it; production leaves them alone.
var (
	clockNow = time.Now
	sleepFor = time.Sleep
)

// The signing domain (archon-login/1) is deliberately NOT declared here. It is the
// scheme's, applied inside sdk/go/login, and a copy in the CLI would be a second place it
// could drift from.

// maxRequestBytes caps the body a service may hand us. A login request is a few hundred
// bytes; larger is a malformed or hostile peer, refused before parsing.
const maxRequestBytes = 64 << 10

// minNonceSize is the SCHEME's floor, cited rather than restated: possession.MinNonceSize
// is where it is decided, and a local 16 would be a second place it could move from. It is
// checked HERE, and not only at signing time, because a short nonce must be refused before
// the person is asked to confirm — the check's POSITION is this lane's, its VALUE is not.
const minNonceSize = possession.MinNonceSize

// noScopeLine stands in the scope position when the request delegates nothing.
const noScopeLine = "(no scope entries — the service asks only for proof of your key)"

// loginRequest is what the service answers on GET <audience>/login/<id>. Field names
// follow the authorship comment and are pinned by docs/login.md when it lands; they are
// named in exactly one place so a spec rename is one edit.
//
// NOTE the absent field: there is no audience here, by design. See Finding 1 above.
type loginRequest struct {
	ID       string   `json:"id"`
	Nonce    string   `json:"nonce"`     // hex
	Browser  string   `json:"browser"`   // canonical key text, ed25519:<hex>
	Scope    []string `json:"scope"`     // ordered, verbatim, displayed to the person
	ValidFor uint32   `json:"valid_for"` // seconds
	Expires  string   `json:"expires"`   // RFC 3339; when the REQUEST dies, not the delegation
}

// loginAnswer is what we POST to <audience>/login/<id>/answer.
type loginAnswer struct {
	Principal  string `json:"principal"`  // canonical key text of the person's key
	Possession string `json:"possession"` // hex
	Authority  string `json:"authority"`  // hex; empty when no authority payload was given
}

// loginSource is WHICH custody will sign. It is decided at flag-parse time — before the
// audience is derived — so the statement can name it and a bad choice is refused before
// anything is fetched or shown.
type loginSource struct {
	seedHex, keyFile, seedFile string
	// storeKey is a NAME in the store, never a principal (ADR 0007 §A). Set by --key, or by
	// the store's default pointer when no source flag was given.
	storeKey string
}

// decide settles the source: exactly one flag, or none and the store's default. It never
// guesses a seed file — the only fallback is the pointer the person set with
// `archon key default`. A named store key is checked to EXIST here (a stat, opening
// nothing), so a typo is refused before a pointless fetch; the password and the unlock
// still wait for consent.
func (s *loginSource) decide() error {
	n := 0
	for _, v := range []string{s.seedHex, s.keyFile, s.seedFile, s.storeKey} {
		if v != "" {
			n++
		}
	}
	if n > 1 {
		return fmt.Errorf("--key, --seed, --key-file and --seed-file are mutually exclusive\n%s", loginUsage)
	}
	if n == 0 {
		name, err := readDefaultKeyName()
		if err != nil {
			return err
		}
		if name == "" {
			return errors.New("no default key is set\n  pass --key <name>, --seed <hex>, --key-file <file> or --seed-file <file>, " +
				"or choose one with: archon key default <name>")
		}
		s.storeKey = name
	}
	if s.storeKey != "" {
		return requireNamedKey(s.storeKey)
	}
	return nil
}

// runLogin is the command. The order is the security order and is not an accident:
// derive the audience, fetch, validate, SHOW, confirm, only then unlock and sign.
//
// Everything decidable WITHOUT the network — which custody signs, whether the flags agree,
// whether a named store key exists, whether the authority file is readable — is decided
// first, so those refusals land before a request is made and before the person reads a
// statement they could not have signed.
func runLogin(args []string) error {
	if wantsHelp(args) {
		fmt.Println(loginUsage)
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("%s", loginUsage)
	}
	rawURL := args[0]
	if strings.HasPrefix(rawURL, "--") {
		// No URL: the offers form (docs/login.md §4.1). The CLI starts, the page finishes.
		return runOffer(args)
	}
	// The password descriptor is the STORE's flag, taken out first exactly as `key add`
	// does, so login sources a password the one way the store does.
	rest, pwFD, err := takePasswordFD(args[1:])
	if err != nil {
		return err
	}
	var src loginSource
	var authorityFile string
	var assumeYes bool
	for i := 0; i < len(rest); i++ {
		flag := rest[i]
		if flag == "--yes" {
			assumeYes = true
			continue
		}
		if i+1 >= len(rest) || rest[i+1] == "" {
			return fmt.Errorf("flag %q needs a value\n%s", flag, loginUsage)
		}
		value := rest[i+1]
		i++
		switch flag {
		case "--key":
			src.storeKey = value
		case "--seed":
			src.seedHex = value
		case "--key-file":
			src.keyFile = value
		case "--seed-file":
			src.seedFile = value
		case "--authority-file":
			authorityFile = value
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, loginUsage)
		}
	}
	if err := src.decide(); err != nil {
		return err
	}
	// --password-fd belongs to the store. Beside a seed file it would be silently ignored,
	// and a flag that does nothing is a flag someone will come to rely on.
	if pwFD >= 0 && src.storeKey == "" {
		return fmt.Errorf("--password-fd applies only to a store key (--key, or the default)\n%s", loginUsage)
	}
	// `confirm` reads stdin, so a password on fd 0 would be read by the prompt first. The
	// store's own commands never confirm; this is the one place the two meet.
	if pwFD == 0 && !assumeYes {
		return errors.New("--password-fd 0 puts the password on stdin, which the sign? prompt reads first; pass --yes with it")
	}
	// Read here, not after consent: a missing authority file is refused before the person
	// has read a statement and said yes to it. The payload stays opaque (see readAuthority).
	authority, err := readAuthority(authorityFile)
	if err != nil {
		return err
	}

	// THE DERIVATION IS THE SCHEME'S (docs/login.md §2.1, sdk/go/login). It used to live in
	// this file, in three lanes, and the three disagreed: net/url decoded the path and kept a
	// default port, the WHATWG URL dropped the port, a hand-rolled split kept userinfo. The
	// audience is the FIRST FIELD OF THE BINDING, so one URL must yield one audience
	// everywhere — which makes this the scheme's job and not a CLI's.
	audience, idBytes, err := login.DeriveAudience(rawURL)
	if err != nil {
		return err
	}
	// The id crosses the wire as hex (§4) and is bound as bytes. Re-encoding the bytes the
	// scheme handed back is exact rather than convenient: the grammar admits only lowercase
	// hex, so this round-trips the URL's own segment and is the value the service will echo.
	id := hex.EncodeToString(idBytes)

	request, err := fetchLoginRequest(audience, id)
	if err != nil {
		return err
	}
	if err := validateLoginRequest(request, id); err != nil {
		return err
	}

	// SHOW BEFORE SIGN. The person confirms the statement, not the URL.
	fmt.Print(renderStatement(audience, request, clockNow().UTC(), describeKeySource(src)))
	if !assumeYes {
		ok, err := confirm(os.Stdin)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("refused. nothing was signed.")
			return nil
		}
	}

	// ONLY NOW is the key touched. For a store key this is where the password is asked for.
	seed, err := resolveLoginSeed(src, pwFD)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(seed)

	possession, principal, err := proveLogin(seed, audience, request)
	if err != nil {
		return err
	}
	if err := postLoginAnswer(audience, id, loginAnswer{
		Principal:  principal,
		Possession: hex.EncodeToString(possession),
		Authority:  hex.EncodeToString(authority),
	}); err != nil {
		return err
	}
	fmt.Printf("signed as %s. the browser is in.\n", principal)
	return nil
}

// validateLoginRequest refuses a malformed request BEFORE anything is displayed, so the
// person is never shown a statement built from junk. Every refusal names the field.
func validateLoginRequest(r *loginRequest, wantID string) error {
	// EXACT, not case-folded: the server's stored id bytes are what its binding recomputes,
	// and the URL segment is what this CLI binds. If the two disagree in any way, the two
	// bindings disagree, so the disagreement is the answer — normalising it away would turn
	// a real mismatch into a proof that fails at the server for no visible reason.
	if r.ID != wantID {
		return fmt.Errorf("login: the service answered for request %q, not %q", r.ID, wantID)
	}
	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil {
		return fmt.Errorf("login: nonce is not hex: %w", err)
	}
	if len(nonce) < minNonceSize {
		return fmt.Errorf("login: nonce is %d bytes, min %d — refusing a guessable challenge", len(nonce), minNonceSize)
	}
	if _, err := keytext.DecodeKey(r.Browser); err != nil {
		return fmt.Errorf("login: browser key %q is not canonical key text: %w", r.Browser, err)
	}
	for i, entry := range r.Scope {
		if entry == "" {
			return fmt.Errorf("login: scope entry %d is empty", i)
		}
		if err := refuseUndisplayable(fmt.Sprintf("scope entry %d", i), entry); err != nil {
			return err
		}
	}
	if r.ValidFor == 0 {
		return errors.New("login: valid_for is 0 — a delegation dead on arrival")
	}
	return nil
}

// refuseUndisplayable rejects anything that cannot be shown to the person faithfully:
// invalid UTF-8, and C0/DEL control characters. A scope entry carrying an escape sequence
// can repaint the terminal and hide what is really being signed, so display safety is a
// validation concern rather than a cosmetic one.
//
// This MIRRORS the scheme's own checkText (docs/login.md §3.2), deliberately and with the
// duplication acknowledged: the scheme refuses these at Binding, which is AFTER the person
// has been shown the statement and said yes. Refusing here means a request that could lie
// on screen never reaches the confirm prompt at all.
func refuseUndisplayable(field, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("login: %s is not valid UTF-8 — refusing", field)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("login: %s contains a control character (%#U) — refusing", field, r)
		}
	}
	return nil
}

// renderStatement is EXACTLY what the person is asked to approve, and is the text all
// three lanes must print byte-identically. now is a parameter so the wall-clock end is
// testable rather than dependent on when the suite runs.
func renderStatement(audience string, r *loginRequest, now time.Time, keySource string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s asks you to let browser key %s act as you:\n", audience, r.Browser)
	writeScopeAndValidity(&b, r, now)
	fmt.Fprintf(&b, "signing with %s\n", keySource)
	return b.String()
}

// renderLedger is the offers form's counterpart (docs/login.md §4.1 rule 4): the same
// fields as the statement, printed AFTER answering rather than before signing, because in
// that form nobody confirmed — the person typed the scope and the audience is the CLI's
// own. It names K as the request delivered it, the source that signed, and the service's
// verdict. Never the code: the ledger goes to stdout, and stdout may be a log.
func renderLedger(audience string, r *loginRequest, now time.Time, keySource string, accepted bool, code string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "you offered %s to let browser key %s act as you:\n", audience, r.Browser)
	writeScopeAndValidity(&b, r, now)
	fmt.Fprintf(&b, "signed with %s\n", keySource)
	if accepted {
		b.WriteString("the service accepted the login. the browser is in.\n")
	} else {
		fmt.Fprintf(&b, "the service refused the login (%s). the browser is not in.\n", code)
	}
	return b.String()
}

// writeScopeAndValidity is the middle of both renderings — every scope entry verbatim, in
// order, then the validity as a duration and as a wall-clock end — written once so the two
// forms cannot drift from each other in the lines they share.
func writeScopeAndValidity(b *strings.Builder, r *loginRequest, now time.Time) {
	// An EMPTY scope is valid (docs/login.md §3.1: 0..=65535 entries) — a proof-only service
	// asks for possession and delegates nothing. It still gets a line, because a statement
	// that silently showed nothing where the scope goes would read as a rendering bug at
	// exactly the moment the person is deciding what to sign.
	if len(r.Scope) == 0 {
		fmt.Fprintf(b, "  %s\n", noScopeLine)
	}
	for _, entry := range r.Scope {
		fmt.Fprintf(b, "  %s\n", entry)
	}
	end := now.Add(time.Duration(r.ValidFor) * time.Second)
	fmt.Fprintf(b, "for %s, until %s\n", formatDuration(r.ValidFor), end.Format("2006-01-02T15:04:05Z"))
}

// describeKeySource names the custody the signature will come from, for the last line of
// the statement (seat:cca ruling, 2026-09-10).
//
// It is the SOURCE and not the principal, on purpose: naming the principal would mean
// unlocking the key before the person has agreed to sign — which, for a
// password-protected store, means demanding a password in order to show someone what they
// are being asked to approve. The source is known without touching the key at all.
//
// A store key is named by its NAME, whether --key chose it or the default pointer did: the
// statement says what will sign, and how the name was chosen is not part of what is being
// approved. The pinned wording is cca's (2026-09-10 20:47Z).
func describeKeySource(src loginSource) string {
	switch {
	case src.storeKey != "":
		return "the store key " + src.storeKey
	case src.seedFile != "":
		return "the seed file " + src.seedFile
	case src.keyFile != "":
		return "the key file " + src.keyFile
	case src.seedHex != "":
		return "the seed given on the command line"
	default:
		return "an unspecified key"
	}
}

// formatDuration renders seconds the same way in every lane. Written out rather than
// taken from time.Duration.String() precisely so Rust and TypeScript reproduce it
// exactly — a shared format nobody has to reverse-engineer from Go formatting.
func formatDuration(seconds uint32) string {
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// confirm reads a y/N answer. Default is NO: anything that is not an explicit yes refuses,
// including EOF, so a login cannot be completed by a closed stdin.
func confirm(in io.Reader) (bool, error) {
	fmt.Print("sign? [y/N] ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// resolveLoginSeed obtains the seed for the source decided at flag-parse time. It runs
// ONLY after the person has confirmed the statement: for a store key that is the moment
// the password is asked for, and never before. Seed files stay beside the store
// permanently, so an agent's non-interactive run and a person's login are the same code
// with two custody sources (ADR 0007 §A; archon#16, answer 2). The caller owns the seed.
func resolveLoginSeed(src loginSource, pwFD int) ([]byte, error) {
	switch {
	case src.storeKey != "":
		return unlockNamedKey(src.storeKey, pwFD)
	case src.seedFile != "":
		raw, err := os.ReadFile(src.seedFile)
		if err != nil {
			return nil, fmt.Errorf("could not read %q: %w", src.seedFile, err)
		}
		return seedFromHexFile(string(raw))
	default:
		return resolveSeed(src.seedHex, src.keyFile, src.seedHex != "", src.keyFile != "", loginUsage)
	}
}

// seedFromHexFile accepts the two hex seed-file shapes in use: 64 hex characters (a raw
// 32-byte seed) and 128 (Go ed25519.PrivateKey — seed followed by public key), the shape
// the first consumer's key files carry (archon#16, answer 4).
func seedFromHexFile(text string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("seed file is not hex: %w", err)
	}
	switch len(raw) {
	case 32:
		return raw, nil
	case 64:
		return raw[:32], nil
	default:
		return nil, fmt.Errorf("seed file holds %d bytes; want 32 (seed) or 64 (seed and public key)", len(raw))
	}
}

// readAuthority reads the authority payload. It is OPAQUE to archon — the delegation
// meaning is the law (thesmos), and this command must never parse it. Absent is empty,
// a valid answer for a service whose law needs none.
func readAuthority(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %w", path, err)
	}
	return raw, nil
}

// fetchLoginRequest GETs the request. The CLI owns HTTP; the SDK never opens a socket
// (archon#16: no network code in the sdk).
func fetchLoginRequest(audience, id string) (*loginRequest, error) {
	endpoint := audience + "/login/" + url.PathEscape(id)
	response, err := httpClient().Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("login: could not reach %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes))
	if err != nil {
		return nil, fmt.Errorf("login: could not read the response from %s: %w", endpoint, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, loginHTTPError(response.StatusCode, body)
	}
	var request loginRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("login: the service request is not the expected JSON: %w", err)
	}
	return &request, nil
}

// postLoginAnswer delivers the answer and reports the service verdict as an error, which is
// what the confirmed form wants: a refusal ends the command.
func postLoginAnswer(audience, id string, answer loginAnswer) error {
	status, body, err := postAnswer(audience, id, answer)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return loginHTTPError(status, body)
	}
	return nil
}

// postAnswer is the POST itself, returning the service's status and body so the offers
// form can record a refusal in its ledger rather than stop on it (§4.1 rule 4: the ledger
// is printed whether the service accepted or refused). Only a failure to reach the service
// is an error here — then nothing was answered, and there is nothing to record.
func postAnswer(audience, id string, answer loginAnswer) (int, []byte, error) {
	endpoint := audience + "/login/" + url.PathEscape(id) + "/answer"
	payload, err := json.Marshal(answer)
	if err != nil {
		return 0, nil, fmt.Errorf("login: could not encode the answer: %w", err)
	}
	response, err := httpClient().Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("login: could not reach %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes))
	return response.StatusCode, body, nil
}

// loginHTTPError turns a non-success response into a diagnosis. RFC 8628 error vocabulary
// is used where the service speaks it, since this protocol adopts that shape.
func loginHTTPError(status int, body []byte) error {
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		switch payload.Error {
		case "expired_token":
			return errors.New("login: this request has expired — reload the page and run the new command")
		case "access_denied":
			return errors.New("login: the service refused the login")
		}
		if payload.Description != "" {
			return fmt.Errorf("login: %s (%s)", payload.Description, payload.Error)
		}
		return fmt.Errorf("login: the service answered %q", payload.Error)
	}
	return fmt.Errorf("login: the service answered HTTP %d", status)
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// ---------------------------------------------------------------------------
// THE OFFERS FORM (docs/login.md §4.1)
// ---------------------------------------------------------------------------
//
// `archon login` with no URL. The prover starts: it mints a code from its own entropy,
// registers what it is willing to delegate, prints the code where only the person can see
// it, waits for the page to take the offer, and answers ONLY the request that took it —
// after checking for itself that the request is what was offered. No confirmation is
// asked: the person typed the scope, the audience is the CLI's own, and the only request it
// will answer carries the code it minted a moment ago. Afterwards it prints the ledger of
// that decision, whether the service accepted or refused.

// codeBytes is how much of the CLI's own entropy a code carries: 16 bytes, spelled as 32
// lowercase hex characters, the floor §4.1 sets. The code is confidential until the offer is
// taken — whoever holds it can begin with exactly the offered scope and their own key.
const codeBytes = 16

// offerBody is what the prover posts to `<audience>/login/offers`.
type offerBody struct {
	Code     string   `json:"code"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
}

// offerResponse is the service's answer to an offer. `page`, when the service has one, is
// the address the person opens, carrying the code in its fragment. There is no audience
// here either: the audience in this form is the prover's own configuration, and a response
// carrying one is a service speaking a protocol this command does not.
type offerResponse struct {
	Code      string   `json:"code"`
	Scope     []string `json:"scope"`
	ValidFor  uint32   `json:"valid_for"`
	ExpiresIn int      `json:"expires_in"`
	Interval  int      `json:"interval"`
	Page      string   `json:"page"`
}

// offerRead is `GET <audience>/login/offers/<code>`: `request` is null until the page has
// taken the offer, then the id of the request that did.
type offerRead struct {
	Code     string   `json:"code"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
	Request  *string  `json:"request"`
	Expires  string   `json:"expires"`
}

// runOffer is the offers form. The order is §4.1's, rule by rule, and the same
// before-any-network discipline as the confirmed form: everything decidable without the
// service — the custody, the authority file, the scope, the validity, the audience — is
// decided first, so those refusals land before an offer exists.
func runOffer(args []string) error {
	// The password descriptor is the STORE's flag, taken out first exactly as `key add`
	// does. `--password-fd 0` needs no `--yes` here: nothing in this form reads stdin.
	rest, pwFD, err := takePasswordFD(args)
	if err != nil {
		return err
	}
	var src loginSource
	var authorityFile, audienceFlag, validForText string
	scope := []string{}
	for i := 0; i < len(rest); i++ {
		flag := rest[i]
		if flag == "--yes" {
			// A flag that does nothing is a flag someone will come to rely on — and this one
			// would suggest a confirmation exists to skip.
			return fmt.Errorf("no confirmation is asked in this form — what you typed is what you sign; drop --yes\n%s", loginUsage)
		}
		if i+1 >= len(rest) || rest[i+1] == "" {
			return fmt.Errorf("flag %q needs a value\n%s", flag, loginUsage)
		}
		value := rest[i+1]
		i++
		switch flag {
		case "--audience":
			audienceFlag = value
		case "--scope":
			scope = append(scope, value)
		case "--valid-for":
			validForText = value
		case "--key":
			src.storeKey = value
		case "--seed":
			src.seedHex = value
		case "--key-file":
			src.keyFile = value
		case "--seed-file":
			src.seedFile = value
		case "--authority-file":
			authorityFile = value
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, loginUsage)
		}
	}
	if err := src.decide(); err != nil {
		return err
	}
	if pwFD >= 0 && src.storeKey == "" {
		return fmt.Errorf("--password-fd applies only to a store key (--key, or the default)\n%s", loginUsage)
	}
	authority, err := readAuthority(authorityFile)
	if err != nil {
		return err
	}
	// WHAT YOU TYPED IS WHAT YOU SIGN — so what was typed is checked the way the service
	// will check it, here, before an offer nobody could begin on is registered.
	for i, entry := range scope {
		if entry == "" {
			return fmt.Errorf("login: --scope entry %d is empty", i)
		}
		if err := refuseUndisplayable(fmt.Sprintf("--scope entry %d", i), entry); err != nil {
			return err
		}
	}
	validFor, err := parseValidFor(validForText)
	if err != nil {
		return err
	}
	// RULE 1: the audience is the CLI's own configuration, a fixed point of §2.1's grammar,
	// refused before anything is fetched.
	audience, err := configuredAudience(audienceFlag)
	if err != nil {
		return err
	}

	// The code is the CLI's own entropy, registered under it. The service echoes the offer
	// back; an echo that differs is a service that altered what was offered, and nothing of
	// it is trusted from here on.
	code, err := mintCode()
	if err != nil {
		return err
	}
	offered, err := postOffer(audience, offerBody{Code: code, Scope: scope, ValidFor: validFor})
	if err != nil {
		return err
	}
	if err := checkOfferEcho(offered, code, scope, validFor); err != nil {
		return err
	}
	// STDERR, deliberately: the interactive channel, where the password prompt already
	// lives. `archon login … > file` must never write the code into a log (§4.1 rule 1).
	fmt.Fprintf(os.Stderr, "offer registered at %s\n", audience)
	fmt.Fprintf(os.Stderr, "code: %s\n", code)
	if offered.Page != "" {
		fmt.Fprintln(os.Stderr, describePage(audience, offered.Page))
	}
	fmt.Fprintf(os.Stderr, "waiting for the page to take the offer, up to %ds\n", offered.ExpiresIn)

	// The prover paces ITSELF (ADR 0007 §C.7, #39): the route is unpaced because two parties
	// poll it, so the discipline is here — one interval before the first poll, so the page
	// always has the first window, and one between polls.
	id, err := pollOffer(audience, code, offered)
	if err != nil {
		return err
	}

	// RULE 2: answer only the request the offer names, and only after re-checking it
	// against what was offered — never trusting that the service's refusal happened. K is
	// RECORDED from the request; it was never offered, so it is not checked, and it is what
	// the ledger names.
	request, err := fetchLoginRequest(audience, id)
	if err != nil {
		return err
	}
	if err := validateLoginRequest(request, id); err != nil {
		return err
	}
	if err := checkAgainstOffer(request, scope, validFor); err != nil {
		return err
	}

	// RULE 3: no confirmation. The key is unlocked now — for a store key this is where the
	// password is asked for — and the proof made and posted.
	seed, err := resolveLoginSeed(src, pwFD)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(seed)
	possession, principal, err := proveLogin(seed, audience, request)
	if err != nil {
		return err
	}
	status, body, err := postAnswer(audience, id, loginAnswer{
		Principal:  principal,
		Possession: hex.EncodeToString(possession),
		Authority:  hex.EncodeToString(authority),
	})
	if err != nil {
		return err
	}

	// RULE 4: the ledger, accepted or refused, on stdout — field by field, never the code.
	accepted := status == http.StatusNoContent || status == http.StatusOK
	verdict := errorCodeOf(status, body)
	fmt.Print(renderLedger(audience, request, clockNow().UTC(), describeKeySource(src), accepted, verdict))
	if !accepted {
		return fmt.Errorf("login: the service refused the login (%s)", verdict)
	}
	return nil
}

// parseValidFor reads --valid-for. Required: a delegation's lifetime is typed, never
// assumed — a default here would be a number nobody chose, signed anyway.
func parseValidFor(text string) (uint32, error) {
	if text == "" {
		return 0, fmt.Errorf("--valid-for <seconds> is required — a delegation's lifetime is typed, never assumed\n%s", loginUsage)
	}
	n, err := strconv.ParseUint(text, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("--valid-for must be a whole number of seconds, 1 or more; got %q", text)
	}
	return uint32(n), nil
}

// configuredAudience is §4.1 rule 1. The audience is --audience, or ARCHON_AUDIENCE as the
// configured default, checked exactly the same way: it must be a fixed point of §2.1's
// grammar — the very check the server applies to its own configuration — and the CLI
// refuses to start otherwise. The `/login/00` is the shortest invocation URL the grammar
// admits, there only to make the audience parseable as one; feeding the audience through
// the scheme's derivation asks the one question that matters: is this the string the
// service binds?
func configuredAudience(flag string) (string, error) {
	audience := flag
	if audience == "" {
		audience = os.Getenv("ARCHON_AUDIENCE")
	}
	if audience == "" {
		return "", errors.New("login: no audience — pass --audience <base> or set ARCHON_AUDIENCE; " +
			"in this form the audience is your configuration, never a page's word (docs/login.md §4.1)")
	}
	derived, _, err := login.DeriveAudience(audience + "/login/00")
	if err != nil {
		return "", fmt.Errorf("login: audience %q is not valid: %w (docs/login.md §2.1)", audience, err)
	}
	if derived != audience {
		return "", fmt.Errorf("login: audience %q is not canonical — the service binds %q; pass that (docs/login.md §2.1)", audience, derived)
	}
	return audience, nil
}

// mintCode draws the code from the OS CSPRNG. The randomness lives HERE, in the command,
// as every other randomness of the pinned tiers does (ADR 0006).
func mintCode() (string, error) {
	raw := make([]byte, codeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("login: could not draw a code: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// postOffer registers the offer. Unknown fields in the response are refused, as everywhere
// in this command: a service adding fields is speaking a protocol this lane does not.
func postOffer(audience string, offer offerBody) (*offerResponse, error) {
	endpoint := audience + "/login/offers"
	payload, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("login: could not encode the offer: %w", err)
	}
	response, err := httpClient().Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("login: could not reach %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes))
	if err != nil {
		return nil, fmt.Errorf("login: could not read the response from %s: %w", endpoint, err)
	}
	if response.StatusCode != http.StatusCreated {
		return nil, loginHTTPError(response.StatusCode, body)
	}
	var offered offerResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&offered); err != nil {
		return nil, fmt.Errorf("login: the service's offer is not the expected JSON: %w", err)
	}
	return &offered, nil
}

// checkOfferEcho requires the service to have registered EXACTLY what was offered. The
// offer is what the person typed; a service that echoes something else has altered it, and
// a prover that went on would be waiting to sign a delegation nobody typed.
func checkOfferEcho(offered *offerResponse, code string, scope []string, validFor uint32) error {
	if offered.Code != code {
		return errors.New("login: the service altered the offer: the code it registered is not the one sent")
	}
	if err := sameScopeAndValidity(offered.Scope, offered.ValidFor, scope, validFor); err != nil {
		return fmt.Errorf("login: the service altered the offer: %w", err)
	}
	if offered.ExpiresIn <= 0 {
		return errors.New("login: the service's offer has no lifetime (expires_in)")
	}
	return nil
}

// describePage is the one line about the page address, printed and MARKED, never opened
// (§4.1 rule 1; ADR 0007 §C.7 (6)). "On the service's own origin" is a byte-exact comparison
// of scheme and host with the audience's — a differently spelled origin fails closed, which
// is the right direction for an address a person is about to click — and launching a browser
// is the person's action, never this command's: spawning a platform opener by name is the
// PATH surface §C.5 refuses.
func describePage(audience, page string) string {
	origin := originOf(audience)
	onOrigin := page == origin ||
		strings.HasPrefix(page, origin+"/") ||
		strings.HasPrefix(page, origin+"#") ||
		strings.HasPrefix(page, origin+"?")
	if onOrigin {
		return "page: " + page + " (on the service's own origin)"
	}
	return "page: " + page + " (NOT on the service's origin — do not open it)"
}

// originOf is the audience up to its path: scheme, host and port, as the audience spells them
// (canonical by construction — configuredAudience made sure).
func originOf(audience string) string {
	rest := audience
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		return audience[:len(audience)-len(rest)+i]
	}
	return audience
}

// pollOffer waits for the page to take the offer and returns the id of the request that did.
//
// The pacing is the prover's own (ADR 0007 §C.7, #39): one advertised interval BEFORE the
// first poll — the page always gets the first window — and one between polls; a 429 from a
// server that paces anyway is sleep-and-retry, never an error. The wait is bounded by the
// offer's own lifetime, and a 404 before then is the offer gone — expired, or taken and
// already finished — which for a prover still waiting means the page never took it.
func pollOffer(audience, code string, offered *offerResponse) (string, error) {
	interval := time.Duration(max(offered.Interval, 1)) * time.Second
	deadline := clockNow().Add(time.Duration(offered.ExpiresIn) * time.Second)
	endpoint := audience + "/login/offers/" + url.PathEscape(code)
	for {
		sleepFor(interval)
		if clockNow().After(deadline) {
			return "", errors.New("login: the offer expired before the page took it")
		}
		response, err := httpClient().Get(endpoint)
		if err != nil {
			return "", fmt.Errorf("login: could not reach %s: %w", endpoint, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxRequestBytes))
		response.Body.Close()
		if readErr != nil {
			return "", fmt.Errorf("login: could not read the response from %s: %w", endpoint, readErr)
		}
		switch response.StatusCode {
		case http.StatusTooManyRequests:
			continue
		case http.StatusNotFound:
			return "", errors.New("login: the offer expired before the page took it")
		case http.StatusOK:
		default:
			return "", loginHTTPError(response.StatusCode, body)
		}
		var read offerRead
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&read); err != nil {
			return "", fmt.Errorf("login: the service's offer is not the expected JSON: %w", err)
		}
		if read.Request != nil && *read.Request != "" {
			return *read.Request, nil
		}
	}
}

// checkAgainstOffer is §4.1 rule 2, done by the prover for itself: the request's scope must
// be what was offered, entry for entry, in order, and its validity equal. The service
// refuses a mismatched begin before storing anything — but a prover that relied on that
// would be trusting the service about the one thing it is about to sign.
func checkAgainstOffer(r *loginRequest, scope []string, validFor uint32) error {
	if err := sameScopeAndValidity(r.Scope, r.ValidFor, scope, validFor); err != nil {
		return fmt.Errorf("login: the service's request differs from the offer — %w — refusing to sign", err)
	}
	return nil
}

// sameScopeAndValidity is "differs in any way", stated once for the echo and for the request:
// the same number of entries, each equal to its counterpart IN ORDER, the same validity.
func sameScopeAndValidity(gotScope []string, gotValidFor uint32, scope []string, validFor uint32) error {
	if gotValidFor != validFor {
		return fmt.Errorf("valid_for is %d, offered %d", gotValidFor, validFor)
	}
	if len(gotScope) != len(scope) {
		return fmt.Errorf("%d scope entries, offered %d", len(gotScope), len(scope))
	}
	for i := range scope {
		if gotScope[i] != scope[i] {
			return fmt.Errorf("scope entry %d is %q, offered %q", i, gotScope[i], scope[i])
		}
	}
	return nil
}

// errorCodeOf names the service's verdict for the ledger: the RFC 8628 code from an error
// body, or the bare status when the body carries none. An accepted answer has no code.
func errorCodeOf(status int, body []byte) string {
	if status == http.StatusNoContent || status == http.StatusOK {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		return payload.Error
	}
	return fmt.Sprintf("HTTP %d", status)
}
