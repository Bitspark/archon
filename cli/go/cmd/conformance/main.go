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
			blob, err := keystore.Seal(mustHex(c.Seed), []byte(c.Password), mustHex(c.Salt), mustHex(c.Nonce), p)
			if err != nil {
				out["result"] = map[string]any{"error": true}
			} else {
				out["result"] = map[string]any{"ok": map[string]any{
					"file":       hex.EncodeToString(blob),
					"public_key": hex.EncodeToString(blob[30:62]),
				}}
			}
		case "keystore_open":
			seed, err := keystore.Open(mustHex(c.File), []byte(c.Password))
			if err != nil {
				out["result"] = map[string]any{"error": true}
			} else {
				out["result"] = map[string]any{"ok": map[string]any{"seed": hex.EncodeToString(seed)}}
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
