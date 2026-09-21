package main

import (
	"fmt"

	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
	"github.com/Bitspark/archon/core/go/keytext"
)

// keytextDecode is the canonical key text parser, named here so io.go can reach it
// without a second import block.
var keytextDecode = keytext.DecodeKey

// parsePubFormat validates a --format / --pub-format value at flag-parse time, so a bad
// format errors before any input is read or any key is written. The message is
// byte-identical across the three lanes.
func parsePubFormat(s string) (string, error) {
	switch s {
	case "spki", "text", "hex":
		return s, nil
	default:
		return "", fmt.Errorf("unknown --format %q (want spki|text|hex)", s)
	}
}

// renderPubkey renders a 32-byte public key in one of the shared formats, returning the
// exact bytes to print:
//   - spki: the keycodec SPKI PEM, verbatim (it carries its own single trailing newline)
//   - text: the canonical key text ed25519:<hex> + exactly one newline
//   - hex:  the raw 32-byte pubkey as lowercase hex + exactly one newline
func renderPubkey(pub []byte, format string) ([]byte, error) {
	switch format {
	case "spki":
		return keycodec.PubkeyToSPKIPEM(pub)
	case "text":
		return []byte(keytext.EncodeKey(pub) + "\n"), nil
	case "hex":
		return []byte(hexbytes.ToHex(pub) + "\n"), nil
	default:
		return nil, fmt.Errorf("unknown --format %q (want spki|text|hex)", format)
	}
}
