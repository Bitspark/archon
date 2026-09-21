package main

import (
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
)

const signUsage = "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex>) [--domain <d>] [--in <file>]\n  " +
	"signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain " +
	"makes the signature domain-separated: it verifies in that domain and nowhere else."

// runSign signs raw bytes, raw or in a domain. The message is the input, verbatim. With
// --domain the signature is domain-separated (Ed25519ph with the domain as RFC 8032
// context) and verifies only there; without it, the signature is raw Ed25519 and
// separation is the caller's problem. This is NOT thesmos's `sign` — that one signs a
// fact and knows what a fact is. This one knows nothing.
func runSign(args []string) error {
	if wantsHelp(args) {
		fmt.Println(signUsage)
		return nil
	}
	var keyFile, seedHex, domain, inPath string
	var haveKeyFile, haveSeed, haveDomain bool
	for i := 0; i < len(args); i += 2 {
		flag := args[i]
		if i+1 >= len(args) || (args[i+1] == "" && flag != "--domain") {
			return fmt.Errorf("flag %q needs a value\n%s", flag, signUsage)
		}
		value := args[i+1]
		switch flag {
		case "--key-file":
			keyFile, haveKeyFile = value, true
		case "--seed":
			seedHex, haveSeed = value, true
		case "--domain":
			domain, haveDomain = value, true
		case "--in":
			inPath = value
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, signUsage)
		}
	}
	if !haveKeyFile && !haveSeed {
		return fmt.Errorf("one of --key-file or --seed is required\n%s", signUsage)
	}
	seed, err := resolveSeed(seedHex, keyFile, haveSeed, haveKeyFile, signUsage)
	if err != nil {
		return err
	}
	message, err := readInput(inPath)
	if err != nil {
		return err
	}
	var sig []byte
	if haveDomain {
		sig, err = crypto.SignInDomain(seed, domain, message)
		if err != nil {
			return err
		}
	} else {
		sig = crypto.Sign(seed, message)
	}
	fmt.Println(hexbytes.ToHex(sig))
	return nil
}
