// Conformance CLI (go, cli) — a dev/CI artifact, not part of the command's surface. Same
// `conformance v1` protocol as the floor's and the sdk's: `conformance <family>` reads the
// whole vectors/keystore.json on stdin, selects its family, recomputes each result from the
// case INPUTS, and writes one NDJSON line per case to stdout in input order.
//
//	keystore_seal : in {name, seed, password, salt, nonce, m_kib, t, p}
//	                out {"name","result":{"ok":{"file","public_key"}}|{"error":true}}
//	keystore_open : in {name, file, password}
//	                out {"name","result":{"ok":{"seed"}}|{"error":true}}
//	keystore_name : in {name, input}
//	                out {"name","result":{"ok":<bool>}}
//
// It lives in cli/ because the store does (ADR 0007 §A): the format is the command's, so
// its oracle is driven by the command's lane, not by core/ or sdk/.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
)

type kase struct {
	Name     string `json:"name"`
	Seed     string `json:"seed"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
	Nonce    string `json:"nonce"`
	MemKiB   uint32 `json:"m_kib"`
	Time     uint32 `json:"t"`
	Parallel uint8  `json:"p"`
	File     string `json:"file"`
	Input    string `json:"input"`
	// Policy is a keystore_seal input (docs/keystore.md §8.1), passed as given, unsorted
	// included, so that a vector can pin what the writer refuses.
	Policy *casePolicy `json:"policy"`
}

type casePolicy struct {
	Mode     string   `json:"mode"`
	Contexts []string `json:"contexts"`
}

// policyJSON is a parsed header's policy as the vectors spell it: null for version 1.
func policyJSON(p *keystore.Policy) any {
	switch {
	case p == nil:
		return nil
	case p.Unrestricted:
		return map[string]any{"mode": "unrestricted"}
	default:
		return map[string]any{"mode": "allowlist", "contexts": p.Contexts}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("case input is not valid hex: %v", err))
	}
	return b
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
		case "keystore_seal":
			p := keystore.Params{MemoryKiB: c.MemKiB, Time: c.Time, Parallelism: c.Parallel}
			var pol keystore.Policy
			if c.Policy == nil {
				panic("keystore_seal case without a policy: " + c.Name)
			}
			switch c.Policy.Mode {
			case "unrestricted":
				pol = keystore.Policy{Unrestricted: true, Contexts: c.Policy.Contexts}
			case "allowlist":
				pol = keystore.Policy{Contexts: append([]string{}, c.Policy.Contexts...)}
			default:
				panic("unknown policy mode in a case: " + c.Policy.Mode)
			}
			blob, err := keystore.Seal(mustHex(c.Seed), []byte(c.Password), mustHex(c.Salt), mustHex(c.Nonce), p, pol)
			if err != nil {
				out["result"] = map[string]any{"error": true}
			} else {
				out["result"] = map[string]any{"ok": map[string]any{
					"file":       hex.EncodeToString(blob),
					"public_key": hex.EncodeToString(blob[30:62]),
				}}
			}
		case "keystore_open":
			// A refusal carries the category the command would report (§8.2): the header's own
			// kind, or unlock-failed for anything the seal refused.
			file := mustHex(c.File)
			h, err := keystore.ParseHeader(file)
			var seed []byte
			if err == nil {
				seed, err = keystore.Open(file, []byte(c.Password))
			}
			var fe *keystore.FormatError
			switch {
			case errors.As(err, &fe):
				out["result"] = map[string]any{"error": fe.Kind}
			case err != nil:
				out["result"] = map[string]any{"error": "unlock-failed"}
			default:
				out["result"] = map[string]any{"ok": map[string]any{
					"seed":    hex.EncodeToString(seed),
					"version": h.Version,
					"policy":  policyJSON(h.Policy),
				}}
			}
		case "keystore_name":
			out["result"] = map[string]any{"ok": keystore.ValidateName(c.Input) == nil}
		default:
			panic("unknown family: " + family)
		}
		if err := enc.Encode(out); err != nil {
			panic(err)
		}
	}
}
