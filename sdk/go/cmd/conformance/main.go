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
//
// vectors/request.json (same protocol; `request` is {nonce, transaction, purpose[hex], new_key, intent_digest}):
//
//	enroll_binding : in {name, audience, request}       out {"name","result":{"ok":"<hex>"}|{"error":true}}
//	enroll_prove   : in {name, seed, audience, request} out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//	enroll_verify  : in {name, audience, request, sig}  out {"name","valid":<bool>}
//	request_sign   : in {name, seed, method, audience, request_target, body, content_type, declared, created, expires, nonce}
//	                 out {"name","result":{"ok":{"base","headers"}}|{"error":true}}
//	request_verify : in {name, policy, now, request{method, request_target, headers, body}}
//	                 out {"name","result":{"ok":{"principal","created","expires","nonce","target_uri"}}|{"error":true}}
//
// vectors/enroll.json (same protocol; text fields of an intent as hex):
//
//	enroll_intent_encode     : in {name, intent}      out {"name","result":{"ok":"<hex>"}|{"error":true}}
//	enroll_intent_decode     : in {name, bytes}       out {"name","result":{"ok":{intent}}|{"error":true}}
//	enroll_challenge_encode  : in {name, challenge}   out {"name","result":{"ok":"<token>"}|{"error":true}}
//	enroll_challenge_decode  : in {name, text}        out {"name","result":{"ok":{challenge}}|{"error":true}}
//	enroll_challenge_request : in {name, text}        out {"name","result":{"ok":{"audience","request"}}|{"error":true}}
//	enroll_proof_encode      : in {name, proof_token} out {"name","result":{"ok":"<token>"}|{"error":true}}
//	enroll_proof_decode      : in {name, text}        out {"name","result":{"ok":{proof_token}}|{"error":true}}
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Bitspark/archon/sdk/go/enroll"
	"github.com/Bitspark/archon/sdk/go/envelope"
	"github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/sdk/go/possession"
	"github.com/Bitspark/archon/sdk/go/request"
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
	Role     *int            `json:"role"`
	URL      string          `json:"url"`
	Audience string          `json:"audience"`
	Request  json.RawMessage `json:"request"` // a login, enrollment or received HTTP request, by family
	// vectors/request.json, the request profile
	Method        string      `json:"method"`
	RequestTarget string      `json:"request_target"`
	Body          string      `json:"body"`
	ContentType   *string     `json:"content_type"`
	Declared      [][2]string `json:"declared"`
	Created       int64       `json:"created"`
	Expires       int64       `json:"expires"`
	Now           int64       `json:"now"`
	Policy        *struct {
		Audience    string   `json:"audience"`
		Declared    []string `json:"declared"`
		MaxLifetime int64    `json:"max_lifetime"`
		Skew        int64    `json:"skew"`
	} `json:"policy"`
	// vectors/enroll.json
	Intent    *intentJSON `json:"intent"`
	Bytes     string      `json:"bytes"`
	Challenge *struct {
		Audience    string `json:"audience"`
		Transaction string `json:"transaction"`
		Nonce       string `json:"nonce"`
		NewKey      string `json:"new_key"`
		Intent      string `json:"intent"`
		Deadline    int64  `json:"deadline"`
	} `json:"challenge"`
	Text       string `json:"text"`
	ProofToken *struct {
		Transaction string `json:"transaction"`
		NewKey      string `json:"new_key"`
		Proof       string `json:"proof"`
	} `json:"proof_token"`
}

// intentJSON is the oracle's spelling of enroll.Intent: every text field as hex, so non-UTF-8
// text can be a case.
type intentJSON struct {
	Blind        string   `json:"blind"`
	AccountID    string   `json:"account_id"`
	AccountName  string   `json:"account_name"`
	Purpose      string   `json:"purpose"`
	Restrictions []string `json:"restrictions"`
}

func (j *intentJSON) intent() *enroll.Intent {
	restrictions := make([]string, len(j.Restrictions))
	for i, r := range j.Restrictions {
		restrictions[i] = string(mustHex(r))
	}
	return &enroll.Intent{
		Blind: mustHex(j.Blind), AccountID: string(mustHex(j.AccountID)), AccountName: string(mustHex(j.AccountName)),
		Purpose: string(mustHex(j.Purpose)), Restrictions: restrictions,
	}
}

func spellIntent(i *enroll.Intent) intentJSON {
	restrictions := make([]string, len(i.Restrictions))
	for n, r := range i.Restrictions {
		restrictions[n] = hex.EncodeToString([]byte(r))
	}
	return intentJSON{
		Blind: hex.EncodeToString(i.Blind), AccountID: hex.EncodeToString([]byte(i.AccountID)),
		AccountName: hex.EncodeToString([]byte(i.AccountName)), Purpose: hex.EncodeToString([]byte(i.Purpose)),
		Restrictions: restrictions,
	}
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

func (c kase) login() *login.Request {
	var r loginRequest
	if err := json.Unmarshal(c.Request, &r); err != nil {
		panic(err)
	}
	return r.request()
}

// enrollRequest is the oracle's spelling of enroll.Request: bytes as hex, the purpose as hex
// (so a non-UTF-8 purpose can be a case).
type enrollRequest struct {
	Nonce        string `json:"nonce"`
	Transaction  string `json:"transaction"`
	Purpose      string `json:"purpose"`
	NewKey       string `json:"new_key"`
	IntentDigest string `json:"intent_digest"`
}

func (c kase) enroll() *enroll.Request {
	var r enrollRequest
	if err := json.Unmarshal(c.Request, &r); err != nil {
		panic(err)
	}
	return &enroll.Request{
		Nonce: mustHex(r.Nonce), Transaction: mustHex(r.Transaction), Purpose: string(mustHex(r.Purpose)),
		NewKey: mustHex(r.NewKey), IntentDigest: mustHex(r.IntentDigest),
	}
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
			b, err := login.Binding(byte(*c.Role), c.Audience, c.login())
			out["result"] = resultOf(hex.EncodeToString(b), err)
		case "login_prove":
			sig, err := login.Prove(mustHex(c.Seed), c.Audience, c.login())
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "login_verify":
			out["valid"] = login.Verify(mustHex(c.Pubkey), c.Audience, c.login(), mustHex(c.Sig))
		case "login_collect_prove":
			sig, err := login.ProveCollect(mustHex(c.Seed), c.Audience, c.login())
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "login_collect_verify":
			out["valid"] = login.VerifyCollect(c.Audience, c.login(), mustHex(c.Sig))
		case "enroll_binding":
			b, err := enroll.Binding(c.Audience, c.enroll())
			out["result"] = resultOf(hex.EncodeToString(b), err)
		case "enroll_prove":
			sig, err := enroll.Prove(mustHex(c.Seed), c.Audience, c.enroll())
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "enroll_verify":
			out["valid"] = enroll.Verify(c.Audience, c.enroll(), mustHex(c.Sig))
		case "request_sign":
			base, h, err := request.Sign(mustHex(c.Seed), request.ToSign{
				Method: c.Method, Audience: c.Audience, RequestTarget: c.RequestTarget, Body: mustHex(c.Body),
				ContentType: c.ContentType, Declared: c.Declared, Created: c.Created, Expires: c.Expires, Nonce: mustHex(c.Nonce),
			})
			out["result"] = resultOf(map[string]any{"base": base, "headers": map[string]string{
				"archon-audience": h.ArchonAudience, "content-digest": h.ContentDigest,
				"signature-input": h.SignatureInput, "signature": h.Signature,
			}}, err)
		case "request_verify":
			var r struct {
				Method        string      `json:"method"`
				RequestTarget string      `json:"request_target"`
				Headers       [][2]string `json:"headers"`
				Body          string      `json:"body"`
			}
			if err := json.Unmarshal(c.Request, &r); err != nil {
				panic(err)
			}
			v, err := request.Verify(request.Policy{
				Audience: c.Policy.Audience, Declared: c.Policy.Declared, MaxLifetime: c.Policy.MaxLifetime, Skew: c.Policy.Skew,
			}, c.Now, request.Received{Method: r.Method, RequestTarget: r.RequestTarget, Headers: r.Headers, Body: mustHex(r.Body)})
			out["result"] = resultOf(map[string]any{
				"principal": v.KeyText, "created": v.Created, "expires": v.Expires,
				"nonce": hex.EncodeToString(v.Nonce), "target_uri": v.TargetURI,
			}, err)
		case "enroll_intent_encode":
			b, err := enroll.EncodeIntent(c.Intent.intent())
			out["result"] = resultOf(hex.EncodeToString(b), err)
		case "enroll_intent_decode":
			i, err := enroll.DecodeIntent(mustHex(c.Bytes))
			if err != nil {
				out["result"] = resultOf(nil, err)
			} else {
				out["result"] = resultOf(spellIntent(i), nil)
			}
		case "enroll_challenge_encode":
			ch := c.Challenge
			text, err := enroll.EncodeChallenge(&enroll.Challenge{
				Audience: ch.Audience, Transaction: mustHex(ch.Transaction), Nonce: mustHex(ch.Nonce),
				NewKey: mustHex(ch.NewKey), Intent: mustHex(ch.Intent), Deadline: time.Unix(ch.Deadline, 0),
			})
			out["result"] = resultOf(text, err)
		case "enroll_challenge_decode":
			ch, err := enroll.DecodeChallenge(c.Text)
			if err != nil {
				out["result"] = resultOf(nil, err)
			} else {
				out["result"] = resultOf(map[string]any{
					"audience": ch.Audience, "transaction": hex.EncodeToString(ch.Transaction),
					"nonce": hex.EncodeToString(ch.Nonce), "new_key": hex.EncodeToString(ch.NewKey),
					"intent": hex.EncodeToString(ch.Intent), "deadline": ch.Deadline.Unix(),
				}, nil)
			}
		case "enroll_challenge_request":
			ch, err := enroll.DecodeChallenge(c.Text)
			var r *enroll.Request
			if err == nil {
				r, _, err = ch.Request()
			}
			if err != nil {
				out["result"] = resultOf(nil, err)
			} else {
				out["result"] = resultOf(map[string]any{"audience": ch.Audience, "request": map[string]string{
					"nonce": hex.EncodeToString(r.Nonce), "transaction": hex.EncodeToString(r.Transaction),
					"purpose": hex.EncodeToString([]byte(r.Purpose)), "new_key": hex.EncodeToString(r.NewKey),
					"intent_digest": hex.EncodeToString(r.IntentDigest),
				}}, nil)
			}
		case "enroll_proof_encode":
			p := c.ProofToken
			text, err := enroll.EncodeProof(&enroll.Proof{
				Transaction: mustHex(p.Transaction), NewKey: mustHex(p.NewKey), Proof: mustHex(p.Proof),
			})
			out["result"] = resultOf(text, err)
		case "enroll_proof_decode":
			p, err := enroll.DecodeProof(c.Text)
			if err != nil {
				out["result"] = resultOf(nil, err)
			} else {
				out["result"] = resultOf(map[string]any{
					"transaction": hex.EncodeToString(p.Transaction), "new_key": hex.EncodeToString(p.NewKey),
					"proof": hex.EncodeToString(p.Proof),
				}, nil)
			}
		default:
			panic("unknown family: " + family)
		}
		if err := enc.Encode(out); err != nil {
			panic(err)
		}
	}
}
