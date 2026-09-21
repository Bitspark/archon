package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
)

// readInput resolves a command's input as raw bytes: the file when inPath != "", else
// stdin. `--in <file>` exists because PowerShell has no `<` input redirection; when
// absent, behaviour is byte-identical to the stdin default.
func readInput(inPath string) ([]byte, error) {
	if inPath != "" {
		b, err := os.ReadFile(inPath)
		if err != nil {
			return nil, fmt.Errorf("could not read %q: %w", inPath, err)
		}
		return b, nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("could not read stdin: %w", err)
	}
	return b, nil
}

// takeInFlag scans args for an optional `--in <file>` pair, returning args with that pair
// removed and the path ("" when absent). A trailing or empty `--in` is a clean error, so
// all three lanes reject `--in ""` identically.
func takeInFlag(args []string) (rest []string, inPath string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--in" {
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, "", fmt.Errorf("flag %q needs a value", "--in")
			}
			inPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest, inPath, nil
}

// resolveSeed resolves a private key from the two ways every signing command accepts
// one: --seed <hex> (a raw 32-byte seed) or a PKCS#8 PEM from --key-file <file> / stdin.
// The two are mutually exclusive.
func resolveSeed(seedHex, keyFile string, haveSeed, haveKeyFile bool, usage string) ([]byte, error) {
	switch {
	case haveSeed && haveKeyFile:
		return nil, fmt.Errorf("--seed and --key-file are mutually exclusive\n%s", usage)
	case haveSeed:
		s, err := hexbytes.SeedFromHex(seedHex)
		if err != nil {
			return nil, fmt.Errorf("--seed: %w", err)
		}
		return s, nil
	default:
		pem, err := readInput(keyFile)
		if err != nil {
			return nil, err
		}
		return keycodec.PKCS8PEMToSeed(pem)
	}
}

// parsePubkey accepts a public key as canonical key text (ed25519:<hex>) or bare hex.
func parsePubkey(value string) ([]byte, error) {
	if strings.HasPrefix(value, "ed25519:") {
		k, err := keytextDecode(value)
		if err != nil {
			return nil, fmt.Errorf("--pubkey: %w", err)
		}
		return k, nil
	}
	k, err := hexbytes.PubkeyFromHex(value)
	if err != nil {
		return nil, fmt.Errorf("--pubkey: %w", err)
	}
	if len(k) != crypto.PublicKeySize {
		return nil, fmt.Errorf("--pubkey: %d bytes", len(k))
	}
	return k, nil
}

// verdict is the error type `verify` returns for `invalid`: a result already printed on
// stdout, exit 1, and nothing on stderr. main recognises it and skips the diagnostic line.
type verdict struct{}

func (verdict) Error() string { return "invalid" }

func asVerdict(err error, v *verdict) bool {
	_, ok := err.(verdict)
	return ok
}
