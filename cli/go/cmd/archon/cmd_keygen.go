package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
	"github.com/Bitspark/archon/core/go/keytext"
)

const keygenUsage = "usage: archon keygen [--seed <hex>] [--store <name>] [--out <file>] [--pub-out <file>] [--pub-format spki|text|hex]\n  " +
	"prints the public key (canonical text) on stdout; writes the PKCS#8 PEM private key " +
	"to <file> (--out) or, by default, to stderr behind a SECRET warning; --pub-out writes " +
	"the public key (--pub-format spki|text|hex, default spki) to a file. --seed derives " +
	"the key deterministically. --store <name> keeps the new seed in the password-protected " +
	"store (ADR 0007 §A) instead of writing a PEM; it is mutually exclusive with --out."

// runKeygen generates (or deterministically derives) an Ed25519 key pair: the canonical
// public key to stdout — the shareable part — and the private key as a PKCS#8 v1 PEM,
// never the raw seed hex, either to --out <file> (the recommended path) or to stderr
// behind a clear warning.
//
// The RNG is the one deliberately-unpinned edge, and it lives here, in the CLI: the
// library takes a seed it is given and never invents one (ADR 0002). This is not custody
// in stele's sense — nothing is named, stored or managed; a file you name is written and
// forgotten.
func runKeygen(args []string) error {
	if wantsHelp(args) {
		fmt.Println(keygenUsage)
		return nil
	}
	args, storeName, err := takeStoreFlag(args)
	if err != nil {
		return err
	}
	args, pwFD, err := takePasswordFD(args)
	if err != nil {
		return err
	}
	// Validated before anything is generated or printed: a bad name should cost nothing.
	if storeName != "" {
		if err := keystore.ValidateName(storeName); err != nil {
			return err
		}
	}
	seed, out, pubOut, pubFormat, err := parseKeygen(args)
	if err != nil {
		return err
	}
	if storeName != "" && out != "" {
		return fmt.Errorf("--store and --out are mutually exclusive: one keeps the seed, the other writes it out")
	}
	pub := crypto.PublicKeyFromSeed(seed)
	fmt.Println(keytext.EncodeKey(pub))

	// --store: the seed stays in the store and no PEM is produced at all. Same seal path
	// `key add` uses (sealAndWrite), reached from the command that owns the CSPRNG.
	if storeName != "" {
		if err := storeGenerated(storeName, seed, pwFD); err != nil {
			return err
		}
		if pubOut != "" {
			rendered, err := renderPubkey(pub, pubFormat)
			if err != nil {
				return err
			}
			if err := os.WriteFile(pubOut, rendered, 0o644); err != nil {
				return fmt.Errorf("could not write public key to %q: %w", pubOut, err)
			}
			fmt.Fprintf(os.Stderr, "wrote public key (%s) to %s\n", pubFormat, pubOut)
		}
		return nil
	}

	pem, err := keycodec.SeedToPKCS8PEM(seed)
	if err != nil {
		return err
	}
	if out != "" {
		if err := os.WriteFile(out, pem, 0o600); err != nil {
			return fmt.Errorf("could not write key to %q: %w", out, err)
		}
		fmt.Fprintf(os.Stderr, "wrote PKCS#8 private key PEM to %s\n", out)
	} else {
		fmt.Fprintln(os.Stderr, "SECRET — do not share. Anyone with this private key controls the identity:")
		fmt.Fprint(os.Stderr, string(pem))
	}
	if pubOut != "" {
		rendered, err := renderPubkey(pub, pubFormat)
		if err != nil {
			return err
		}
		if err := os.WriteFile(pubOut, rendered, 0o644); err != nil {
			return fmt.Errorf("could not write public key to %q: %w", pubOut, err)
		}
		fmt.Fprintf(os.Stderr, "wrote public key (%s) to %s\n", pubFormat, pubOut)
	}
	return nil
}

func parseKeygen(args []string) (seed []byte, out, pubOut, pubFormat string, err error) {
	pubFormat = "spki"
	haveSeed := false
	for i := 0; i < len(args); i += 2 {
		flag := args[i]
		if i+1 >= len(args) {
			return nil, "", "", "", fmt.Errorf("flag %q needs a value\n%s", flag, keygenUsage)
		}
		value := args[i+1]
		switch flag {
		case "--seed":
			s, e := hexbytes.SeedFromHex(value)
			if e != nil {
				return nil, "", "", "", fmt.Errorf("--seed: %w", e)
			}
			seed, haveSeed = s, true
		case "--out":
			out = value
		case "--pub-out":
			pubOut = value
		case "--pub-format":
			// Validated at parse time so a bad format never leaves a private key behind.
			f, e := parsePubFormat(value)
			if e != nil {
				return nil, "", "", "", e
			}
			pubFormat = f
		default:
			return nil, "", "", "", fmt.Errorf("unknown flag %q\n%s", flag, keygenUsage)
		}
	}
	if !haveSeed {
		seed = make([]byte, crypto.SeedSize)
		if _, e := rand.Read(seed); e != nil {
			return nil, "", "", "", fmt.Errorf("could not read OS randomness: %w", e)
		}
	}
	return seed, out, pubOut, pubFormat, nil
}
