package keystore

// The archon key store's file format — docs/keystore.md, ADR 0007 §A.
//
// Identical across cli/{rs,go,ts} and pinned by vectors/keystore.json. Version 2 (§8), the
// only one written:
//
//	"arck" ‖ 0x02 ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]
//	  ‖ u8(mode) ‖ u8(n) ‖ n × (u8(len) ‖ context)                               header, H
//	nonce[24]
//	XChaCha20Poly1305(seed[32], aad = header)                                     48 with the tag
//
// Version 1 (§2) is the same without the policy, a fixed 134 bytes; it is still read.
//
// This file is the format and nothing else: no paths, no prompts, no policy. Custody is
// the command's (ADR 0007 §A) and nothing in core/ or sdk/ learns a password — but that
// cuts both ways, so the format does not learn a directory either.

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/login"
)

const (
	// Magic follows the envelope's "arcn" ‖ version (sdk/{go,rs,ts}). It is what stops a
	// 134-byte non-key file being LISTED as a key: `key list` reads the header without a
	// password, so it is the one place a wrong file would be believed.
	Magic = "arck"

	// Version1 is the fixed 134-byte file of docs/keystore.md §2. It is still PARSED, so that
	// `key list`, `key rm` and `key policy` can name and convert it, and nothing signs with it.
	// Version2 adds the context policy of §8; it is the only version written.
	Version1 = 0x01
	Version2 = 0x02

	SaltSize  = 16
	NonceSize = chacha20poly1305.NonceSizeX // 24
	// The fields every version shares, up to and including the public key.
	commonSize = 4 + 1 + 4 + 4 + 1 + SaltSize + crypto.PublicKeySize // 62
	sealSize   = crypto.SeedSize + 16                                // ciphertext ‖ tag
	// Version 1 is exactly this long.
	V1FileSize = commonSize + NonceSize + sealSize // 134

	// Version 2's policy: a mode, a count, then length-prefixed contexts (§8.1).
	PolicyUnrestricted = 0x00
	PolicyAllowlist    = 0x01
	MaxContexts        = 16
	MaxContextSize     = 255
	MinV2FileSize      = commonSize + 2 + NonceSize + sealSize                                  // 136
	MaxV2FileSize      = commonSize + 2 + MaxContexts*(1+MaxContextSize) + NonceSize + sealSize // 4232

	// The shipping default, measured rather than assumed (docs/keystore.md §3): p=4 buys
	// nothing in any lane we ship and costs two of three external oracles.
	DefaultMemoryKiB   = 65536
	DefaultTime        = 3
	DefaultParallelism = 1
)

// Params are the Argon2id cost parameters. They live in the header and are READ, never
// assumed, which is what lets the defaults change without a format version.
type Params struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

func DefaultParams() Params {
	return Params{MemoryKiB: DefaultMemoryKiB, Time: DefaultTime, Parallelism: DefaultParallelism}
}

// The ceilings a header's parameters must stay under (docs/keystore.md §2). They exist only so
// that a header someone else wrote cannot make an unlock unbounded, and they are generous on
// purpose: RFC 9106's first recommended setting (2 GiB, t=1, p=4) still opens.
const (
	MaxMemoryKiB = 2 * 1024 * 1024
	MaxTime      = 10
)

// check refuses parameters no lane may derive with. The lower bounds are RFC 9106's validity
// rules and nothing more (t ≥ 1, p ≥ 1, m ≥ 8p), so a weak but valid file keeps opening: its
// weakness is its writer's. x/crypto/argon2 would silently raise m < 8p to 8p and derive a key
// the other lanes' libraries refuse to compute, so the rule is stated here, once, before any
// derivation.
func (p Params) check() error {
	switch {
	case p.Time == 0 || p.Parallelism == 0:
		return errors.New("argon2id parameters are not usable: t and p must be at least 1")
	case p.MemoryKiB < 8*uint32(p.Parallelism):
		return fmt.Errorf("argon2id parameters are not usable: m=%d KiB is below 8*p=%d", p.MemoryKiB, 8*uint32(p.Parallelism))
	case p.MemoryKiB > MaxMemoryKiB:
		return fmt.Errorf("argon2id parameters are not usable: m=%d KiB is above %d", p.MemoryKiB, MaxMemoryKiB)
	case p.Time > MaxTime:
		return fmt.Errorf("argon2id parameters are not usable: t=%d is above %d", p.Time, MaxTime)
	}
	return nil
}

// Header is the authenticated prefix of a key file. PublicKey and Policy are readable without
// a password — that is what `key list` prints — but they are only a CLAIM until an unlock
// verifies the tag over this header and re-derives the key from the seed.
type Header struct {
	Version   byte
	Params    Params
	Salt      []byte
	PublicKey []byte
	// Policy is nil for a version-1 file, which has none.
	Policy *Policy
	// Size is the header's length: the AEAD's associated data is file[:Size].
	Size int
}

// FormatError is a refusal of the file itself, before any derivation. Kind is the machine-mode
// category the command reports (docs/keystore.md §8.2): "unsupported" for a version byte this
// binary does not know, "malformed" for everything else.
type FormatError struct {
	Kind string
	Err  error
}

func (e *FormatError) Error() string { return e.Err.Error() }

func malformed(format string, args ...any) error {
	return &FormatError{Kind: "malformed", Err: fmt.Errorf(format, args...)}
}

// Policy is a version-2 entry's context policy (§8.1). Unrestricted, or an allowlist of
// contexts in strictly ascending byte order; an empty allowlist denies every context.
type Policy struct {
	Unrestricted bool
	Contexts     []string
}

// NewAllowlist builds an allowlist from the contexts a person named: each a domain by ADR 0008
// §2 (1..255 bytes of well-formed UTF-8), no duplicates, at most MaxContexts. It sorts them,
// so one policy has one encoding.
func NewAllowlist(contexts []string) (Policy, error) {
	if len(contexts) > MaxContexts {
		return Policy{}, fmt.Errorf("at most %d contexts (got %d)", MaxContexts, len(contexts))
	}
	sorted := append([]string(nil), contexts...)
	sort.Strings(sorted)
	for i, c := range sorted {
		if err := checkContext([]byte(c)); err != nil {
			return Policy{}, err
		}
		if i > 0 && sorted[i-1] == c {
			return Policy{}, fmt.Errorf("context %q is named twice", c)
		}
	}
	return Policy{Contexts: sorted}, nil
}

func checkContext(c []byte) error {
	if len(c) < 1 || len(c) > MaxContextSize {
		return fmt.Errorf("a context is 1 to %d bytes (got %d)", MaxContextSize, len(c))
	}
	if !utf8.Valid(c) {
		return errors.New("a context is well-formed UTF-8")
	}
	// A policy is shown to the person (`key policy`, `key list`, the refusals), so a context
	// holds nothing a terminal would not show as itself (docs/login.md §5's set). Refused on
	// write and on read, so nothing is written that cannot be read, and nothing read that cannot
	// be shown.
	for _, r := range string(c) {
		if login.DisplayUnsafe(r) {
			return fmt.Errorf("a context may not contain U+%04X: it would not be shown as itself", r)
		}
	}
	return nil
}

// Permits says whether the policy lets this entry sign in domain: byte-exact membership,
// no prefix, no wildcard, no normalisation.
func (p Policy) Permits(domain string) bool {
	if p.Unrestricted {
		return true
	}
	for _, c := range p.Contexts {
		if c == domain {
			return true
		}
	}
	return false
}

// String is the policy as the command prints it.
func (p Policy) String() string {
	switch {
	case p.Unrestricted:
		return "unrestricted"
	case len(p.Contexts) == 0:
		return "allow nothing"
	default:
		quoted := make([]string, len(p.Contexts))
		for i, c := range p.Contexts {
			quoted[i] = quote(c)
		}
		return "allow " + strings.Join(quoted, ", ")
	}
}

// quote spells a context by the JSON string rule, so a context holding ", " cannot read as two.
// The same rule in the three lanes: `"` and `\` escaped, C0 controls as \u00xx.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (p Policy) encode() []byte {
	if p.Unrestricted {
		return []byte{PolicyUnrestricted, 0}
	}
	out := []byte{PolicyAllowlist, byte(len(p.Contexts))}
	for _, c := range p.Contexts {
		out = append(out, byte(len(c)))
		out = append(out, c...)
	}
	return out
}

// ErrEmptyPassword is its own error because both ends refuse it: a store sealed under an
// empty password is a plaintext store that looks encrypted, and refusing at OPEN too keeps
// a file made by a lenient writer from ever being trusted.
var ErrEmptyPassword = errors.New("an empty password is refused: it would look encrypted and not be")

// deriveKey derives the file key. The password is UTF-8, normalised NFC so the same
// characters typed on different platforms derive the same key.
func deriveKey(password []byte, salt []byte, p Params) []byte {
	normalised := norm.NFC.Bytes(password)
	return argon2.IDKey(normalised, salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
}

// encodeHeader writes a version-2 header: the only version written (§8).
func encodeHeader(p Params, salt, publicKey []byte, pol Policy) []byte {
	out := make([]byte, 0, commonSize+2)
	out = append(out, Magic...)
	out = append(out, Version2)
	out = binary.BigEndian.AppendUint32(out, p.MemoryKiB)
	out = binary.BigEndian.AppendUint32(out, p.Time)
	out = append(out, p.Parallelism)
	out = append(out, salt...)
	out = append(out, publicKey...)
	return append(out, pol.encode()...)
}

// ParseHeader reads the header of a key file WITHOUT a password, version 1 or 2. Every
// refusal here is cheap, happens before any crypto runs, and is a *FormatError.
func ParseHeader(file []byte) (Header, error) {
	if len(file) < 5 || !bytes.Equal(file[:4], []byte(Magic)) {
		return Header{}, malformed("bad magic: not an archon key file")
	}
	var h Header
	switch file[4] {
	case Version1:
		if len(file) != V1FileSize {
			return Header{}, malformed("not %d bytes (got %d)", V1FileSize, len(file))
		}
		h.Size = commonSize
	case Version2:
		if len(file) < MinV2FileSize || len(file) > MaxV2FileSize {
			return Header{}, malformed("a version-2 key file is %d to %d bytes (got %d)", MinV2FileSize, MaxV2FileSize, len(file))
		}
		pol, size, err := parsePolicy(file)
		if err != nil {
			return Header{}, err
		}
		h.Policy, h.Size = &pol, size
	default:
		return Header{}, &FormatError{Kind: "unsupported", Err: fmt.Errorf("unknown key file version %d", file[4])}
	}
	h.Version = file[4]
	h.Params = Params{
		MemoryKiB:   binary.BigEndian.Uint32(file[5:9]),
		Time:        binary.BigEndian.Uint32(file[9:13]),
		Parallelism: file[13],
	}
	h.Salt = append([]byte(nil), file[14:30]...)
	h.PublicKey = append([]byte(nil), file[30:commonSize]...)
	if err := h.Params.check(); err != nil {
		return Header{}, &FormatError{Kind: "malformed", Err: err}
	}
	return h, nil
}

// parsePolicy reads §8.1's policy and returns it with the header's length. The file must be
// exactly that header, the nonce and the seal: nothing missing, nothing trailing.
func parsePolicy(file []byte) (Policy, int, error) {
	mode, n := file[commonSize], int(file[commonSize+1])
	var pol Policy
	switch {
	case mode == PolicyUnrestricted && n == 0:
		pol.Unrestricted = true
	case mode == PolicyUnrestricted:
		return Policy{}, 0, malformed("an unrestricted policy lists no contexts (got %d)", n)
	case mode == PolicyAllowlist && n > MaxContexts:
		return Policy{}, 0, malformed("at most %d contexts (got %d)", MaxContexts, n)
	case mode != PolicyAllowlist:
		return Policy{}, 0, malformed("unknown policy mode %d", mode)
	}
	end := len(file) - NonceSize - sealSize
	off := commonSize + 2
	pol.Contexts = []string{}
	for i := 0; i < n; i++ {
		if off >= end {
			return Policy{}, 0, malformed("the policy runs past the header")
		}
		size := int(file[off])
		if off+1+size > end {
			return Policy{}, 0, malformed("the policy runs past the header")
		}
		c := file[off+1 : off+1+size]
		if err := checkContext(c); err != nil {
			return Policy{}, 0, malformed("policy: %v", err)
		}
		if i > 0 && pol.Contexts[i-1] >= string(c) {
			return Policy{}, 0, malformed("policy contexts are not in strictly ascending order")
		}
		pol.Contexts = append(pol.Contexts, string(c))
		off += 1 + size
	}
	if off != end {
		return Policy{}, 0, malformed("the file is not exactly the header it declares, a nonce and a seal")
	}
	return pol, off, nil
}

// Seal produces a version-2 file. salt and nonce are ARGUMENTS: the randomness is the
// command's, never this function's, which is what makes the format pinnable.
func Seal(seed, password, salt, nonce []byte, p Params, pol Policy) ([]byte, error) {
	if len(seed) != crypto.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes", crypto.SeedSize)
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes", SaltSize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes", NonceSize)
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	if !pol.Unrestricted {
		// The writer's half of §8.1: the same rules the reader enforces, so nothing is written
		// that would not be read back.
		if _, err := NewAllowlist(pol.Contexts); err != nil {
			return nil, err
		}
		if !sort.StringsAreSorted(pol.Contexts) {
			return nil, errors.New("policy contexts must be sorted: build them with NewAllowlist")
		}
	} else if len(pol.Contexts) != 0 {
		return nil, errors.New("an unrestricted policy lists no contexts")
	}
	header := encodeHeader(p, salt, crypto.PublicKeyFromSeed(seed), pol)
	key := deriveKey(password, salt, p)
	defer Zeroise(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(header)+NonceSize+sealSize)
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, seed, header)
	return out, nil
}

// Reseal is `key policy`'s step 4 (§8.3): it opens file — version 1 or 2 — and seals the same
// seed under the same salt and parameters, the new policy and a fresh nonce. The result is
// always version 2.
func Reseal(file, password, nonce []byte, pol Policy) ([]byte, error) {
	h, err := ParseHeader(file)
	if err != nil {
		return nil, err
	}
	seed, err := Open(file, password)
	if err != nil {
		return nil, err
	}
	defer Zeroise(seed)
	return Seal(seed, password, h.Salt, nonce, h.Params, pol)
}

// Open reverses Seal, for version 1 or 2, and then checks the decrypted seed against the
// header's public key. The tag proves the bytes are ours, policy included; that check proves
// they are CONSISTENT — a file can verify and still be refused. Whether a version-1 seed may be
// USED is the command's decision (§8.2), not this function's.
func Open(file, password []byte) ([]byte, error) {
	header, err := ParseHeader(file)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	key := deriveKey(password, header.Salt, header.Params)
	defer Zeroise(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := file[header.Size : header.Size+NonceSize]
	seed, err := aead.Open(nil, nonce, file[header.Size+NonceSize:], file[:header.Size])
	if err != nil {
		// One message for a wrong password and a tampered file alike: which of the two it
		// was is not something the holder of a bad password should learn.
		return nil, errors.New("could not open: wrong password, or the file has been altered")
	}
	if subtle.ConstantTimeCompare(crypto.PublicKeyFromSeed(seed), header.PublicKey) != 1 {
		Zeroise(seed)
		return nil, errors.New("the sealed seed does not derive the public key in the header")
	}
	return seed, nil
}

// Zeroise is best-effort and is not a security claim: Go can move a slice before this
// runs. It is still worth doing (docs/keystore.md §4).
func Zeroise(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
