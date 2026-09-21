// Conformance CLI (go) — a dev/CI artifact, not part of the library surface.
//
// Implements the `conformance v1` protocol archon inherits from thesmos ADR 0006:
// `conformance <family>` reads the whole vectors/identity.json on stdin, selects its
// family's cases, recomputes each result from the case INPUTS (ignoring the expected
// value the oracle carries), and writes one NDJSON line per case to stdout in input
// order. The harness (conformance/harness.mjs) drives this and the rs/ts CLIs as black
// boxes and asserts each line against the oracle.
//
//	pubkey_from_seed : in {name, seed}                 out {"name","pubkey":"<64-hex>"}
//	key_encode       : in {name, pubkey}               out {"name","text":"<key text>"}
//	keycodec         : in {name, kind, key?|pem?}      out {"name","result":{"ok":"<PEM|hex>"}|{"error":true}}
//	signature_verify : in {name, pubkey, message, sig} out {"name","valid":<bool>}
//	hex_decode       : in {name, kind, hex}            out {"name","result":{"ok":"<hex>"}|{"error":true}}
//	domain_sign      : in {name, seed, domain, message} out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//	domain_verify    : in {name, pubkey, domain, message, sig} out {"name","valid":<bool>}
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
	"github.com/Bitspark/archon/core/go/keytext"
)

type kase struct {
	Name    string `json:"name"`
	Seed    string `json:"seed"`
	Pubkey  string `json:"pubkey"`
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	PEM     string `json:"pem"`
	Message string `json:"message"`
	Sig     string `json:"sig"`
	Hex     string `json:"hex"`
	Domain  string `json:"domain"`
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("case input is not valid hex: %v", err))
	}
	return b
}

// The oracle distinguishes success-with-a-value from failure, never the message: the
// reject *reason* is a core's own diagnostic, the reject *decision* is what must agree
// across three languages.
func resultOf(v string, err error) map[string]any {
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
		case "pubkey_from_seed":
			out["pubkey"] = hex.EncodeToString(crypto.PublicKeyFromSeed(mustHex(c.Seed)))
		case "key_encode":
			out["text"] = keytext.EncodeKey(mustHex(c.Pubkey))
		case "keycodec":
			switch c.Kind {
			case "encode_pkcs8":
				pem, err := keycodec.SeedToPKCS8PEM(mustHex(c.Key))
				out["result"] = resultOf(string(pem), err)
			case "encode_spki":
				pem, err := keycodec.PubkeyToSPKIPEM(mustHex(c.Key))
				out["result"] = resultOf(string(pem), err)
			case "decode_pkcs8":
				k, err := keycodec.PKCS8PEMToSeed([]byte(c.PEM))
				out["result"] = resultOf(hex.EncodeToString(k), err)
			case "decode_spki":
				k, err := keycodec.SPKIPEMToPubkey([]byte(c.PEM))
				out["result"] = resultOf(hex.EncodeToString(k), err)
			default:
				panic("unknown keycodec kind: " + c.Kind)
			}
		case "signature_verify":
			out["valid"] = crypto.Verify(mustHex(c.Pubkey), mustHex(c.Message), mustHex(c.Sig))
		case "hex_decode":
			var b []byte
			var err error
			switch c.Kind {
			case "seed":
				b, err = hexbytes.SeedFromHex(c.Hex)
			case "pubkey":
				b, err = hexbytes.PubkeyFromHex(c.Hex)
			case "signature":
				b, err = hexbytes.SignatureFromHex(c.Hex)
			default:
				panic("unknown hex_decode kind: " + c.Kind)
			}
			out["result"] = resultOf(hexbytes.ToHex(b), err)
		case "domain_sign":
			sig, err := crypto.SignInDomain(mustHex(c.Seed), c.Domain, mustHex(c.Message))
			out["result"] = resultOf(hex.EncodeToString(sig), err)
		case "domain_verify":
			out["valid"] = crypto.VerifyInDomain(mustHex(c.Pubkey), c.Domain, mustHex(c.Message), mustHex(c.Sig))
		default:
			panic("unknown family: " + family)
		}
		if err := enc.Encode(out); err != nil {
			panic(err)
		}
	}
}
