module github.com/Bitspark/archon/cli/go

go 1.25

// The dependencies, and why each is here.
//
// core/go is the floor: keys, hex, PEM, domain-separated signing.
// sdk/go is the layer above it, and `login` is the only part of it this CLI touches —
// the login scheme's binding and proof, which the CLI consumes and never reimplements.
// Local builds resolve both through the repository's go.work; `go install` resolves them
// from GitHub at these versions.
//
// The x/ modules arrived with custody (ADR 0007 §A) and are the first dependencies
// this command has outside the repository: the key store's Argon2id and
// XChaCha20-Poly1305, the NFC normaliser its password rule names, and a terminal prompt
// that does not echo. keygen's CSPRNG is still the standard library's.
require (
	github.com/Bitspark/archon/core/go v0.6.0
	github.com/Bitspark/archon/sdk/go v0.6.0
	golang.org/x/crypto v0.31.0
	golang.org/x/term v0.27.0
	golang.org/x/text v0.21.0
)

require golang.org/x/sys v0.28.0 // indirect
