package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keytext"
)

const signUsage = "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex> | --key <name> --domain <d>) " +
	"[--domain <d>] [--expect <principal>] [--in <file>] [--password-fd <n>] [--json]\n  " +
	"signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain " +
	"makes the signature domain-separated: it verifies in that domain and nowhere else. --key " +
	"signs with a key in archon's store, in a domain only, and needs --expect: the principal " +
	"`archon key list --json` shows for it. --json prints one versioned record instead."

// signFailure is a refusal with the machine mode's category: what a caller branches on,
// where the human sentence on stderr is free to change.
type signFailure struct {
	category string
	err      error
}

func (f *signFailure) Error() string { return f.err.Error() }

// as gives err the category, unless it already carries one.
func as(category string, err error) error {
	if err == nil {
		return nil
	}
	var f *signFailure
	if errors.As(err, &f) {
		return err
	}
	return &signFailure{category, err}
}

func refuse(category, format string, args ...any) error {
	return &signFailure{category, fmt.Errorf(format, args...)}
}

// runSign signs raw bytes, raw or in a domain. The message is the input, verbatim. With
// --domain the signature is domain-separated (Ed25519ph with the domain as RFC 8032
// context) and verifies only there; without it, the signature is raw Ed25519 and
// separation is the caller's problem. This is NOT thesmos's `sign` — that one signs a
// fact and knows what a fact is. This one knows nothing.
//
// --key signs with a key in archon's store, and is the boundary ADR 0009 §5 draws for a tool
// that is not archon: the seed never leaves this process. With --key the domain is REQUIRED —
// the store does not sign raw — and so is --expect, the principal the caller read from
// `archon key list --json` and built its bytes around. A header that names another key is
// refused before the password is asked for, and the opened seed is checked again before
// signing, so a mismatched key never produces a signature. Every signature, whatever the key
// source, is verified against the requested key, scheme and bytes before it is printed.
func runSign(args []string) error {
	if wantsHelp(args) {
		fmt.Println(signUsage)
		return nil
	}
	json := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--json" {
			json = true
			continue
		}
		rest = append(rest, a)
	}
	err := signWith(rest, json)
	if err != nil && json {
		category := "internal"
		var f *signFailure
		if errors.As(err, &f) {
			category = f.category
		}
		fmt.Printf("{\"version\":1,\"error\":%s}\n", jsonString(category))
	}
	return err
}

func signWith(argv []string, json bool) error {
	args, pwFD, err := takePasswordFD(argv)
	if err != nil {
		return as("usage", err)
	}
	var keyFile, seedHex, keyName, domain, expectText, inPath string
	var haveKeyFile, haveSeed, haveKey, haveDomain, haveExpect bool
	for i := 0; i < len(args); i += 2 {
		flag := args[i]
		if i+1 >= len(args) || (args[i+1] == "" && flag != "--domain") {
			return refuse("usage", "flag %q needs a value\n%s", flag, signUsage)
		}
		value := args[i+1]
		switch flag {
		case "--key-file":
			keyFile, haveKeyFile = value, true
		case "--seed":
			seedHex, haveSeed = value, true
		case "--key":
			keyName, haveKey = value, true
		case "--domain":
			domain, haveDomain = value, true
		case "--expect":
			expectText, haveExpect = value, true
		case "--in":
			inPath = value
		default:
			return refuse("usage", "unknown flag %q\n%s", flag, signUsage)
		}
	}
	sources := 0
	for _, have := range []bool{haveKeyFile, haveSeed, haveKey} {
		if have {
			sources++
		}
	}
	switch {
	case sources == 0:
		return refuse("usage", "one of --key-file, --seed or --key is required\n%s", signUsage)
	case sources > 1:
		return refuse("usage", "--key-file, --seed and --key are mutually exclusive\n%s", signUsage)
	case haveKey && !haveDomain:
		return refuse("usage", "--key needs --domain: archon's store does not sign raw\n%s", signUsage)
	case haveKey && !haveExpect:
		return refuse("usage", "--key needs --expect <principal>: `archon key list --json` shows it\n%s", signUsage)
	case !haveKey && pwFD >= 0:
		return refuse("usage", "--password-fd applies only to --key\n%s", signUsage)
	}

	// The domain is checked by the core's own rule before anything is read or asked for:
	// signing nothing with a throwaway key refuses exactly what ADR 0008 §2 refuses, and no
	// copy of that rule lives here to drift from it.
	if haveDomain {
		if _, err := crypto.SignInDomain(make([]byte, crypto.SeedSize), domain, nil); err != nil {
			return as("domain", err)
		}
	}
	var expected []byte
	if haveExpect {
		if expected, err = keytext.DecodeKey(expectText); err != nil {
			return as("usage", err)
		}
	}

	if haveKey {
		file, claimed, err := readNamedKey(keyName)
		if err != nil {
			return as("no-key", err)
		}
		if !bytes.Equal(claimed, expected) {
			return refuse("key-mismatch", "key %s is %s, not the expected %s; refusing to sign",
				keyName, keytext.EncodeKey(claimed), keytext.EncodeKey(expected))
		}
		message, err := readInput(inPath)
		if err != nil {
			return as("input", err)
		}
		digest := sha256.Sum256(message)
		preamble := fmt.Sprintf("signing %d bytes (sha256 %s) in domain %s with %s (%s)\n",
			len(message), hexbytes.ToHex(digest[:]), jsonString(domain), keyName, keytext.EncodeKey(expected))
		password, err := readPassword(pwFD, false, preamble)
		if err != nil {
			return as("password", err)
		}
		seed, err := keystore.Open(file, password)
		keystore.Zeroise(password)
		if err != nil {
			return as("unlock-failed", err)
		}
		defer keystore.Zeroise(seed)
		principal := crypto.PublicKeyFromSeed(seed)
		if !bytes.Equal(principal, expected) {
			return refuse("key-mismatch", "key %s did not open to the expected key; refusing to sign", keyName)
		}
		return emitSignature(seed, principal, domain, haveDomain, message, json)
	}

	seed, err := resolveSeed(seedHex, keyFile, haveSeed, haveKeyFile, signUsage)
	if err != nil {
		return as("input", err)
	}
	principal := crypto.PublicKeyFromSeed(seed)
	if haveExpect && !bytes.Equal(principal, expected) {
		return refuse("key-mismatch", "the key is %s, not the expected %s; refusing to sign",
			keytext.EncodeKey(principal), keytext.EncodeKey(expected))
	}
	message, err := readInput(inPath)
	if err != nil {
		return as("input", err)
	}
	return emitSignature(seed, principal, domain, haveDomain, message, json)
}

// emitSignature signs, checks the signature against what was REQUESTED, and prints it.
func emitSignature(seed, principal []byte, domain string, haveDomain bool, message []byte, json bool) error {
	var sig []byte
	var ok bool
	if haveDomain {
		var err error
		if sig, err = crypto.SignInDomain(seed, domain, message); err != nil {
			return as("domain", err)
		}
		ok = crypto.VerifyInDomain(principal, domain, message, sig)
	} else {
		sig = crypto.Sign(seed, message)
		ok = crypto.Verify(principal, message, sig)
	}
	if !ok {
		return refuse("internal", "the signature did not verify; nothing was printed")
	}
	if !json {
		fmt.Println(hexbytes.ToHex(sig))
		return nil
	}
	scheme, domainMember := "ed25519-raw", ""
	if haveDomain {
		scheme, domainMember = "ed25519ph-context", ",\"domain\":"+jsonString(domain)
	}
	fmt.Fprintf(os.Stdout, "{\"version\":1,\"principal\":%s,\"scheme\":%s%s,\"signature\":%s}\n",
		jsonString(keytext.EncodeKey(principal)), jsonString(scheme), domainMember, jsonString(hexbytes.ToHex(sig)))
	return nil
}
