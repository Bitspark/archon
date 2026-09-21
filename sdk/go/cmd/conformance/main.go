// Conformance CLI (go, sdk) — a dev/CI artifact, not part of the library surface. Same
// `conformance v1` protocol as the floor's CLI: `conformance <family>` reads the whole
// vectors/sdk.json on stdin, selects its family, recomputes each result from the case
// INPUTS, and writes one NDJSON line per case to stdout in input order.
//
//	possession_prove  : in {name, seed, domain, nonce, binding}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//	possession_verify : in {name, pubkey, domain, nonce, binding, sig} out {"name","valid":<bool>}
//	envelope_seal     : in {name, seed, domain, payload}               out {"name","result":{"ok":"<hex>"}|{"error":true}}
//	envelope_open     : in {name, envelope, domain}                    out {"name","result":{"ok":{"pubkey","payload"}}|{"error":true}}
//
// vectors/login.json (same protocol; `request` is {id, nonce, browser, scope[hex], valid_for}):
//
//	login_audience       : in {name, url}                            out {"name","result":{"ok":{"audience","id"}}|{"error":true}}
//	login_binding        : in {name, role, audience, request}        out {"name","result":{"ok":"<hex>"}|{"error":true}}
//	login_prove          : in {name, seed, audience, request}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//	login_verify         : in {name, pubkey, audience, request, sig} out {"name","valid":<bool>}
//	login_collect_prove  : in {name, seed, audience, request}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//	login_collect_verify : in {name, audience, request, sig}         out {"name","valid":<bool>}
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Bitspark/archon/sdk/go/envelope"
	"github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/sdk/go/possession"
)

type kase struct {
	Name     string `json:"name"`
	Seed     string `json:"seed"`
	Pubkey   string `json:"pubkey"`
	Domain   string `json:"domain"`
	Nonce    string `json:"nonce"`
	Binding  string `json:"binding"`
	Sig      string `json:"sig"`
	Payload  string `json:"payload"`
	Envelope string `json:"envelope"`
	// vectors/login.json
	Role     *int          `json:"role"`
	URL      string        `json:"url"`
	Audience string        `json:"audience"`
	Request  *loginRequest `json:"request"`
}

// loginRequest is the oracle's spelling of login.Request: bytes as hex, scope entries as hex
// (so a non-UTF-8 entry can be a case).
type loginRequest struct {
	ID       string   `json:"id"`
	Nonce    string   `json:"nonce"`
	Browser  string   `json:"browser"`
	Scope    []string `json:"scope"`
	ValidFor uint32   `json:"valid_for"`
}

func (r *loginRequest) request() *login.Request {
	scope := make([]string, len(r.Scope))
	for i, entry := range r.Scope {
		scope[i] = string(mustHex(entry))
	}
	return &login.Request{ID: mustHex(r.ID), Nonce: mustHex(r.Nonce), Browser: mustHex(r.Browser), Scope: scope, ValidFor: r.ValidFor}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("case input is not valid hex: %v", err))
	}
	return b
}

// The oracle distinguishes success-with-a-value from failure, never the message.
func resultOf(v any, err error) map[string]any {
	if err != nil {
		return map[string]any{"error": true}
	}
	return map[string]any{"ok": v}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: conformance <family>")
		os.Exit(2)
	}
	family := os.Args[1]
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(fmt.Sprintf("stdin is not valid JSON: %v", err))
	}
	blob, ok := doc[family]
	if !ok {
		panic("unknown family: " + family)
	}
	var cases []kase
	if err := json.Unmarshal(blob, &cases); err != nil {
		panic(err)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, c := range cases {
		out := map[string]any{"name": c.Name}
		switch family {
		case "possession_prove":
			sig, err := possession.Prove(mustHex(c.Seed), c.Domain, mustHex(c.Nonce), mustHex(c.Binding))
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "possession_verify":
			out["valid"] = possession.Verify(mustHex(c.Pubkey), c.Domain, mustHex(c.Nonce), mustHex(c.Binding), mustHex(c.Sig))
		case "envelope_seal":
			env, err := envelope.Seal(mustHex(c.Seed), c.Domain, mustHex(c.Payload))
			out["result"] = resultOf(hex.EncodeToString(env), err)
		case "envelope_open":
			o, err := envelope.Open(mustHex(c.Envelope), c.Domain)
			out["result"] = resultOf(map[string]any{
				"pubkey":  hex.EncodeToString(o.Pubkey),
				"payload": hex.EncodeToString(o.Payload),
			}, err)
		case "login_audience":
			aud, id, err := login.DeriveAudience(c.URL)
			out["result"] = resultOf(map[string]any{"audience": aud, "id": hex.EncodeToString(id)}, err)
		case "login_binding":
			b, err := login.Binding(byte(*c.Role), c.Audience, c.Request.request())
			out["result"] = resultOf(hex.EncodeToString(b), err)
		case "login_prove":
			sig, err := login.Prove(mustHex(c.Seed), c.Audience, c.Request.request())
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "login_verify":
			out["valid"] = login.Verify(mustHex(c.Pubkey), c.Audience, c.Request.request(), mustHex(c.Sig))
		case "login_collect_prove":
			sig, err := login.ProveCollect(mustHex(c.Seed), c.Audience, c.Request.request())
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "login_collect_verify":
			out["valid"] = login.VerifyCollect(c.Audience, c.Request.request(), mustHex(c.Sig))
		default:
			panic("unknown family: " + family)
		}
		if err := enc.Encode(out); err != nil {
			panic(err)
		}
	}
}
