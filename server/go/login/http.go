package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
)

// maxBodyBytes caps what a caller may post. Every body in this protocol is a few hundred
// bytes — a key, a hex proof, a short scope list — so a larger one is a malformed or
// hostile peer and is refused before parsing rather than buffered.
//
// The authority payload is the only field with no natural size, and it is still opaque:
// a law that needs more than this should say so, rather than this package guessing high.
const maxBodyBytes = 64 << 10

// readJSON decodes a request body strictly: capped, and with unknown fields REFUSED.
//
// The refusal is deliberate and is the same rule the CLI applies in the other direction. A
// caller sending a field this package does not know is speaking a different version of the
// protocol, and half-reading their message is how two peers come to disagree about what was
// agreed. Refusing says so at the door.
func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	// Buffered rather than streamed, because the body is walked twice: once for duplicate
	// member names, once to decode. The cap makes that safe, and reading one byte past it
	// turns "too large" into a refusal rather than a truncated body that fails to parse for
	// a reason nobody can read.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxBodyBytes {
		return fmt.Errorf("login: body is over the %d byte cap", maxBodyBytes)
	}
	if err := refuseDuplicateKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	// Exactly one JSON value, and nothing after it: a body carrying a second document is
	// ambiguous about which one was meant.
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("login: trailing content after the JSON body")
	}
	return nil
}

// writeCollected emits the collect response with the authority payload spliced in VERBATIM.
//
// It cannot go through json.Marshal or json.Encoder, and that is not a style preference: both
// COMPACT a json.RawMessage, dropping insignificant whitespace, and both HTML-ESCAPE it,
// turning `&` into \u0026 and `<` into \u003c. The law is handed the CLI's bytes, so the
// browser must receive the same ones (ADR 0007 §B) — and `SetEscapeHTML(false)` does not fix
// it, because compaction runs regardless.
//
// Found by caa on #31 with a payload the round-trip pin could not see: the pin's payload had
// no whitespace and no `&<>`, so this lane passed a pin it violated.
//
// `principal` and `possession` are this package's own key text and hex, so marshalling those
// is both safe and correct.
func writeCollected(w http.ResponseWriter, a *answer) {
	principal, _ := json.Marshal(a.Principal)
	possession, _ := json.Marshal(a.Possession)
	var body bytes.Buffer
	body.WriteString(`{"principal":`)
	body.Write(principal)
	body.WriteString(`,"possession":`)
	body.Write(possession)
	if len(a.Authority) > 0 {
		body.WriteString(`,"authority":`)
		body.Write(a.Authority)
	}
	body.WriteString(`}`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
}

// refuseDuplicateKeys refuses a body that names the same top-level member twice.
//
// encoding/json will not: it keeps the LAST occurrence, and DisallowUnknownFields does not
// help, because both members are known ones. That is tolerable for a field this package
// parses — but not for `authority`, which is OPAQUE BYTES carried verbatim (ADR 0007 §B).
// Two `authority` members are two candidate payloads with no reason to prefer either, and
// choosing silently is how a law admits one payload while the browser receives another.
//
// The Rust lane refuses duplicates already (serde does it for a struct), and the TypeScript
// lane must, because its span scanner would otherwise have to choose. This is the third lane
// answering alike: a malformed body handled three ways is the same class of defect as the
// authority round trip caa found.
func refuseDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := opening.(json.Delim); !ok || delim != '{' {
		return errors.New("login: the body is not a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return errors.New("login: a member name is not a string")
		}
		if _, repeated := seen[name]; repeated {
			return fmt.Errorf("login: the body repeats the top-level key %q", name)
		}
		seen[name] = struct{}{}
		// Step over the value, whatever shape it is. Only the top level is checked: a
		// duplicate inside the authority is the law's business, not this package's — the
		// bytes are carried either way.
		if err := decoder.Decode(new(json.RawMessage)); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError emits the RFC 8628 / RFC 6749 shape §4 adopts: `{"error": "<code>"}`, and
// nothing else. No description, no detail, no id echoed back — a client that guessed an id
// learns only that it is not pending, which is the same thing it learns for an id that
// never existed.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// scopeOrEmpty renders a scope list as JSON. A nil slice would encode as `null`, and the
// spec's field is a LIST — an empty one for a proof-only service (§3.1 allows 0 entries),
// never a null. One line here saves every client a special case.
func scopeOrEmpty(scope []string) []string {
	if scope == nil {
		return []string{}
	}
	return scope
}

// checkCode refuses a code that is not what §4.1 says a code is: lowercase hex of even length,
// at least 32 characters (≥ 16 bytes of the prover's own entropy). Registration answers `400`
// to a refusal; the read route answers `404`, because a registered code is always well-formed
// and so a malformed one is unknown by construction — a stranger learns nothing from the
// difference (the same rule as an unknown versus an expired id).
func checkCode(code string) error {
	if len(code) < minCodeHex || len(code)%2 != 0 {
		return fmt.Errorf("login: a code is lowercase hex of even length, at least %d characters", minCodeHex)
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("login: a code is lowercase hex")
		}
	}
	return nil
}

// checkScopeEntry refuses what the CLI could not display faithfully: an empty entry,
// invalid UTF-8, or a control character (§3.1).
//
// The scheme refuses these too, at Binding. Refusing HERE as well is not redundancy for its
// own sake: the scheme's refusal happens when a proof is made, which is after the person has
// read the statement — so a request that could lie on screen would already have been shown.
// Checking at the door means it never exists to be shown.
func checkScopeEntry(entry string) error {
	if entry == "" {
		return errors.New("login: a scope entry is empty")
	}
	if !utf8.ValidString(entry) {
		return errors.New("login: a scope entry is not valid UTF-8")
	}
	for _, r := range entry {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("login: a scope entry carries a control character (%#U)", r)
		}
	}
	return nil
}
