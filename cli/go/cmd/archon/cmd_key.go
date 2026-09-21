package main

import (
	"fmt"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
	"github.com/Bitspark/archon/core/go/keytext"
)

const keyUsage = "usage: archon key <encode <pubkey-hex>|decode <ed25519:...>|" +
	"pkcs8 <encode <seed-hex>|decode>|spki <encode <pubkey-hex>|decode>|" +
	"pub [--in <file>|--seed <hex>] [--format spki|text|hex]|" +
	"add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>]|list [--json]|" +
	"rm <name> [--force]|default [<name>]|export <name> --reveal --out <file>>\n  " +
	"pkcs8/spki decode read a PEM block on stdin (or --in <file>); " +
	"pub derives the public key from a private key, default --format text.\n  " +
	"add/list/rm/default/export are the password-protected seed store (ADR 0007 §A); " +
	"keys live in $ARCHON_HOME/keys, default ~/.archon."

// runKey converts between raw key bytes and the canonical key text, or between raw
// key/seed bytes and the standard PEM containers (PKCS#8 v1 / SPKI):
//
//	archon key encode <pubkey-hex>        -> prints keytext.EncodeKey(bytes) to stdout
//	archon key decode <ed25519:...>       -> prints the decoded bytes as hex to stdout
//	archon key pkcs8 encode <seed-hex>    -> prints the PKCS#8 v1 PEM to stdout
//	archon key pkcs8 decode               -> reads a PEM on stdin, prints the seed hex
//	archon key spki encode <pubkey-hex>   -> prints the SPKI PEM to stdout
//	archon key spki decode                -> reads a PEM on stdin, prints the pubkey hex
//	archon key pub [...]                  -> the public key of a private key
//
// Every hex input goes through the floor's typed decoders (hexbytes), so a 31-byte
// "public key" is refused here exactly as the library refuses it. PEM decode is total: a
// malformed block is a clean error (exit non-zero), never a panic.
func runKey(args []string) error {
	if wantsHelp(args) {
		fmt.Println(keyUsage)
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("%s", keyUsage)
	}
	switch args[0] {
	case "encode":
		if len(args) != 2 {
			return fmt.Errorf("%s", keyUsage)
		}
		pub, err := hexbytes.PubkeyFromHex(args[1])
		if err != nil {
			return err
		}
		fmt.Println(keytext.EncodeKey(pub))
		return nil
	case "decode":
		if len(args) != 2 {
			return fmt.Errorf("%s", keyUsage)
		}
		bytes, err := keytext.DecodeKey(args[1])
		if err != nil {
			return err
		}
		fmt.Println(hexbytes.ToHex(bytes))
		return nil
	case "pkcs8":
		return runKeyPEM(args[1:], "pkcs8")
	case "spki":
		return runKeyPEM(args[1:], "spki")
	case "pub":
		return runKeyPub(args[1:])
	// The store (ADR 0007 §A). Siblings of the codec subcommands above: `key encode`
	// converts bytes it is handed, `key add` keeps a seed. They share the noun, nothing else.
	case "add":
		return runKeyAdd(args[1:])
	case "list":
		return runKeyList(args[1:])
	case "rm":
		return runKeyRm(args[1:])
	case "default":
		return runKeyDefault(args[1:])
	case "export":
		return runKeyExport(args[1:])
	default:
		return fmt.Errorf("%s", keyUsage)
	}
}

// runKeyPEM handles `key pkcs8|spki <encode <hex>|decode>`: a 32-byte seed or public key
// <-> its PEM container.
func runKeyPEM(args []string, container string) error {
	switch {
	case len(args) == 2 && args[0] == "encode":
		var pem []byte
		if container == "pkcs8" {
			seed, err := hexbytes.SeedFromHex(args[1])
			if err != nil {
				return err
			}
			pem, err = keycodec.SeedToPKCS8PEM(seed)
			if err != nil {
				return err
			}
		} else {
			pub, err := hexbytes.PubkeyFromHex(args[1])
			if err != nil {
				return err
			}
			pem, err = keycodec.PubkeyToSPKIPEM(pub)
			if err != nil {
				return err
			}
		}
		// keycodec emits the PEM with its own single trailing newline; print verbatim.
		fmt.Print(string(pem))
		return nil
	case len(args) >= 1 && args[0] == "decode":
		rest, inPath, err := takeInFlag(args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return fmt.Errorf("%s", keyUsage)
		}
		input, err := readInput(inPath)
		if err != nil {
			return err
		}
		var raw []byte
		if container == "pkcs8" {
			raw, err = keycodec.PKCS8PEMToSeed(input)
		} else {
			raw, err = keycodec.SPKIPEMToPubkey(input)
		}
		if err != nil {
			return err
		}
		fmt.Println(hexbytes.ToHex(raw))
		return nil
	default:
		return fmt.Errorf("%s", keyUsage)
	}
}

// runKeyPub derives the public key from a private key and renders it. The private key
// comes from a PKCS#8 PEM on stdin (default) or --in <file>, or from --seed <hex>; --in
// and --seed are mutually exclusive. --format spki|text|hex, default text.
func runKeyPub(args []string) error {
	inPath, seedHex, format := "", "", "text"
	haveIn, haveSeed := false, false
	for i := 0; i < len(args); i += 2 {
		flag := args[i]
		if i+1 >= len(args) {
			return fmt.Errorf("flag %q needs a value\n%s", flag, keyUsage)
		}
		value := args[i+1]
		switch flag {
		case "--in":
			if value == "" {
				return fmt.Errorf("flag %q needs a value\n%s", flag, keyUsage)
			}
			inPath, haveIn = value, true
		case "--seed":
			seedHex, haveSeed = value, true
		case "--format":
			f, err := parsePubFormat(value)
			if err != nil {
				return err
			}
			format = f
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, keyUsage)
		}
	}
	if haveIn && haveSeed {
		return fmt.Errorf("--in and --seed are mutually exclusive\n%s", keyUsage)
	}
	var seed []byte
	if haveSeed {
		s, err := hexbytes.SeedFromHex(seedHex)
		if err != nil {
			return fmt.Errorf("--seed: %w", err)
		}
		seed = s
	} else {
		input, err := readInput(inPath)
		if err != nil {
			return err
		}
		s, err := keycodec.PKCS8PEMToSeed(input)
		if err != nil {
			return err
		}
		seed = s
	}
	rendered, err := renderPubkey(crypto.PublicKeyFromSeed(seed), format)
	if err != nil {
		return err
	}
	fmt.Print(string(rendered))
	return nil
}
