package main

import (
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
)

const verifyUsage = "usage: archon verify --pubkey <ed25519:...|hex> --sig <hex> [--domain <d>] [--in <file>]\n  " +
	"verifies the signature over the input bytes (stdin, or --in <file>); prints valid (exit 0) " +
	"or invalid (exit 1). --domain checks a domain-separated signature."

// runVerify verifies a signature over raw bytes, raw or in a domain. Prints `valid`
// (exit 0) or `invalid` (exit 1) on stdout: a verdict, not a usage error, so a bad
// signature is silent on stderr. Not thesmos's `verify` — that one verifies facts, proofs
// and freshness. This one verifies bytes.
func runVerify(args []string) error {
	if wantsHelp(args) {
		fmt.Println(verifyUsage)
		return nil
	}
	var pubkey, sig []byte
	var domain, inPath string
	var haveDomain bool
	for i := 0; i < len(args); i += 2 {
		flag := args[i]
		if i+1 >= len(args) || (args[i+1] == "" && flag != "--domain") {
			return fmt.Errorf("flag %q needs a value\n%s", flag, verifyUsage)
		}
		value := args[i+1]
		var err error
		switch flag {
		case "--pubkey":
			if pubkey, err = parsePubkey(value); err != nil {
				return err
			}
		case "--sig":
			if sig, err = hexbytes.SignatureFromHex(value); err != nil {
				return fmt.Errorf("--sig: %w", err)
			}
		case "--domain":
			domain, haveDomain = value, true
		case "--in":
			inPath = value
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, verifyUsage)
		}
	}
	if pubkey == nil || sig == nil {
		return fmt.Errorf("--pubkey and --sig are required\n%s", verifyUsage)
	}
	message, err := readInput(inPath)
	if err != nil {
		return err
	}
	var ok bool
	if haveDomain {
		ok = crypto.VerifyInDomain(pubkey, domain, message, sig)
	} else {
		ok = crypto.Verify(pubkey, message, sig)
	}
	if ok {
		fmt.Println("valid")
		return nil
	}
	fmt.Println("invalid")
	return verdict{}
}
