package enroll

// `archon enroll`'s formats (docs/enroll.md §2–§3, ADR 0013): the intent in format 1, which a
// service builds and the command renders, and the two tokens a person carries by hand between
// the signed-in page and the command. The proof above never reads an intent; these are for the
// command, which must show the person which account a key joins before it signs.
//
// Pinned by vectors/enroll.json.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/sdk/go/possession"
)

// IntentFormat is the first byte of an intent in format 1.
const IntentFormat byte = 0x01

// The intent's bounds.
const (
	MinBlindSize    = 16 // at least 128 bits, so the digest cannot confirm a guess
	MaxBlindSize    = 64
	MaxTextSize     = 255 // each of the account reference, the account name, the purpose, a restriction
	MaxRestrictions = 32
)

// The tokens' prefixes and bounds.
const (
	ChallengePrefix = "archon-enroll-challenge-1:"
	ProofPrefix     = "archon-enroll-proof-1:"
	MaxTokenSize    = 65536 // bytes of token text, surrounding whitespace excluded
	MaxNonceSize    = 255   // a challenge token's nonce: possession.MinNonceSize..=MaxNonceSize
	MaxIntentSize   = 0xffff
	ProofSize       = 64
	// MaxDeadline is 9999-12-31T23:59:59Z in Unix seconds: every lane renders it, and no lane
	// needs more than 53 bits to hold it.
	MaxDeadline = 253402300799
)

// Intent is an enrollment intent in format 1. The service builds it from its own validated
// records; the command decodes it and shows it. Every text field is 1..=MaxTextSize bytes of
// UTF-8 with no display-unsafe code point (login.DisplayUnsafe).
type Intent struct {
	Blind        []byte   // MinBlindSize..=MaxBlindSize bytes from a CSPRNG, fresh for every intent
	AccountID    string   // the service's identifier for the account
	AccountName  string   // the account's unique name, such as its sign-in handle: never a free display name
	Purpose      string   // the binding's purpose
	Restrictions []string // 0..=MaxRestrictions lines, in order
}

// EncodeIntent writes i in format 1, refusing any field outside its bounds.
func EncodeIntent(i *Intent) ([]byte, error) {
	if i == nil {
		return nil, errors.New("enroll: nil intent")
	}
	if len(i.Blind) < MinBlindSize || len(i.Blind) > MaxBlindSize {
		return nil, fmt.Errorf("enroll: blind is %d bytes, want %d..=%d", len(i.Blind), MinBlindSize, MaxBlindSize)
	}
	for _, f := range [...]struct{ what, s string }{
		{"account id", i.AccountID}, {"account name", i.AccountName}, {"purpose", i.Purpose},
	} {
		if err := checkShown(f.what, f.s); err != nil {
			return nil, err
		}
	}
	if len(i.Restrictions) > MaxRestrictions {
		return nil, fmt.Errorf("enroll: %d restrictions, want at most %d", len(i.Restrictions), MaxRestrictions)
	}
	for n, r := range i.Restrictions {
		if err := checkShown(fmt.Sprintf("restriction %d", n), r); err != nil {
			return nil, err
		}
	}
	var b bytes.Buffer
	b.WriteByte(IntentFormat)
	putField(&b, i.Blind)
	putField(&b, []byte(i.AccountID))
	putField(&b, []byte(i.AccountName))
	putField(&b, []byte(i.Purpose))
	b.WriteByte(byte(len(i.Restrictions)))
	for _, r := range i.Restrictions {
		putField(&b, []byte(r))
	}
	return b.Bytes(), nil
}

// DecodeIntent reads an intent in format 1. It refuses an unknown format, any field outside
// its bounds, display-unsafe text, and any byte left over.
func DecodeIntent(b []byte) (*Intent, error) {
	r := reader{b: b}
	format, err := r.take(1)
	if err != nil {
		return nil, err
	}
	if format[0] != IntentFormat {
		return nil, fmt.Errorf("enroll: intent format 0x%02x, want 0x%02x", format[0], IntentFormat)
	}
	i := &Intent{}
	if i.Blind, err = r.field(); err != nil {
		return nil, err
	}
	if len(i.Blind) < MinBlindSize || len(i.Blind) > MaxBlindSize {
		return nil, fmt.Errorf("enroll: blind is %d bytes, want %d..=%d", len(i.Blind), MinBlindSize, MaxBlindSize)
	}
	for _, f := range [...]struct {
		what string
		to   *string
	}{{"account id", &i.AccountID}, {"account name", &i.AccountName}, {"purpose", &i.Purpose}} {
		raw, err := r.field()
		if err != nil {
			return nil, err
		}
		if err := checkShown(f.what, string(raw)); err != nil {
			return nil, err
		}
		*f.to = string(raw)
	}
	count, err := r.take(1)
	if err != nil {
		return nil, err
	}
	if int(count[0]) > MaxRestrictions {
		return nil, fmt.Errorf("enroll: %d restrictions, want at most %d", count[0], MaxRestrictions)
	}
	i.Restrictions = make([]string, 0, count[0])
	for n := 0; n < int(count[0]); n++ {
		raw, err := r.field()
		if err != nil {
			return nil, err
		}
		if err := checkShown(fmt.Sprintf("restriction %d", n), string(raw)); err != nil {
			return nil, err
		}
		i.Restrictions = append(i.Restrictions, string(raw))
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return i, nil
}

// Challenge is the challenge token's content: what the service hands the person, for the
// command. Intent is the exact intent bytes; the token's codec checks only its own fields, and
// Request decodes the intent.
type Challenge struct {
	Audience    string
	Transaction []byte    // 1..=MaxTransactionSize bytes
	Nonce       []byte    // possession.MinNonceSize..=MaxNonceSize bytes
	NewKey      []byte    // the key the record enrolls
	Intent      []byte    // 1..=MaxIntentSize bytes
	Deadline    time.Time // the record's expiry, whole seconds, 1970 to MaxDeadline
}

// EncodeChallenge writes c as a challenge token.
func EncodeChallenge(c *Challenge) (string, error) {
	if c == nil {
		return "", errors.New("enroll: nil challenge")
	}
	if err := c.check(); err != nil {
		return "", err
	}
	var b bytes.Buffer
	putField(&b, []byte(c.Audience))
	putField(&b, c.Transaction)
	putField(&b, c.Nonce)
	b.Write(c.NewKey)
	putField(&b, c.Intent)
	_ = binary.Write(&b, binary.BigEndian, uint64(c.Deadline.Unix()))
	text := ChallengePrefix + hex.EncodeToString(b.Bytes())
	if len(text) > MaxTokenSize {
		return "", fmt.Errorf("enroll: challenge token is %d bytes, over %d", len(text), MaxTokenSize)
	}
	return text, nil
}

// DecodeChallenge reads a challenge token. Surrounding tabs, line feeds, carriage returns and
// spaces are ignored; anything else that is not exactly the prefix and lowercase hex of the
// fields, with no byte left over, is refused.
func DecodeChallenge(text string) (*Challenge, error) {
	b, err := unwrap(text, ChallengePrefix)
	if err != nil {
		return nil, err
	}
	r := reader{b: b}
	c := &Challenge{}
	audience, err := r.field()
	if err != nil {
		return nil, err
	}
	c.Audience = string(audience)
	if c.Transaction, err = r.field(); err != nil {
		return nil, err
	}
	if c.Nonce, err = r.field(); err != nil {
		return nil, err
	}
	if c.NewKey, err = r.take(crypto.PublicKeySize); err != nil {
		return nil, err
	}
	if c.Intent, err = r.field(); err != nil {
		return nil, err
	}
	deadline, err := r.take(8)
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	seconds := binary.BigEndian.Uint64(deadline)
	if seconds > MaxDeadline {
		return nil, fmt.Errorf("enroll: deadline %d is after 9999-12-31T23:59:59Z", seconds)
	}
	c.Deadline = time.Unix(int64(seconds), 0).UTC()
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

// Request is the enrollment request this token yields (docs/enroll.md §3): the token's nonce,
// transaction and new key, the intent's purpose, and SHA-256 of the token's intent bytes. It
// decodes the intent, and refuses one that is not format 1. It is the one derivation of what an
// `archon enroll` proof binds, so that what the command shows is what it binds.
func (c *Challenge) Request() (*Request, *Intent, error) {
	if err := c.check(); err != nil {
		return nil, nil, err
	}
	intent, err := DecodeIntent(c.Intent)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(c.Intent)
	return &Request{
		Nonce: bytes.Clone(c.Nonce), Transaction: bytes.Clone(c.Transaction), Purpose: intent.Purpose,
		NewKey: bytes.Clone(c.NewKey), IntentDigest: digest[:],
	}, intent, nil
}

func (c *Challenge) check() error {
	// Stricter than the binding's audience rule (C0 and DEL only): a command that refuses a token
	// prints its audience, so nothing display-unsafe may get that far (docs/enroll.md §3).
	if err := checkText("audience", c.Audience); err != nil {
		return err
	}
	for _, r := range c.Audience {
		if login.DisplayUnsafe(r) {
			return fmt.Errorf("enroll: audience carries a code point that cannot be shown, U+%04X", r)
		}
	}
	if len(c.Transaction) == 0 || len(c.Transaction) > MaxTransactionSize {
		return fmt.Errorf("enroll: transaction is %d bytes, want 1..=%d", len(c.Transaction), MaxTransactionSize)
	}
	if len(c.Nonce) < possession.MinNonceSize || len(c.Nonce) > MaxNonceSize {
		return fmt.Errorf("enroll: nonce is %d bytes, want %d..=%d", len(c.Nonce), possession.MinNonceSize, MaxNonceSize)
	}
	if len(c.NewKey) != crypto.PublicKeySize {
		return fmt.Errorf("enroll: new key is %d bytes, want %d", len(c.NewKey), crypto.PublicKeySize)
	}
	if len(c.Intent) == 0 || len(c.Intent) > MaxIntentSize {
		return fmt.Errorf("enroll: intent is %d bytes, want 1..=%d", len(c.Intent), MaxIntentSize)
	}
	if s := c.Deadline.Unix(); s < 0 || s > MaxDeadline || c.Deadline.Nanosecond() != 0 {
		return errors.New("enroll: deadline must be whole seconds from 1970 to 9999-12-31T23:59:59Z")
	}
	return nil
}

// Proof is the proof token's content: what the command prints and the service reads back.
type Proof struct {
	Transaction []byte // 1..=MaxTransactionSize bytes
	NewKey      []byte // the key that proved
	Proof       []byte // the possession signature, ProofSize bytes
}

// EncodeProof writes p as a proof token.
func EncodeProof(p *Proof) (string, error) {
	if p == nil {
		return "", errors.New("enroll: nil proof")
	}
	if err := p.check(); err != nil {
		return "", err
	}
	var b bytes.Buffer
	putField(&b, p.Transaction)
	b.Write(p.NewKey)
	b.Write(p.Proof)
	return ProofPrefix + hex.EncodeToString(b.Bytes()), nil
}

// DecodeProof reads a proof token, under DecodeChallenge's rules.
func DecodeProof(text string) (*Proof, error) {
	b, err := unwrap(text, ProofPrefix)
	if err != nil {
		return nil, err
	}
	r := reader{b: b}
	p := &Proof{}
	if p.Transaction, err = r.field(); err != nil {
		return nil, err
	}
	if p.NewKey, err = r.take(crypto.PublicKeySize); err != nil {
		return nil, err
	}
	if p.Proof, err = r.take(ProofSize); err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Proof) check() error {
	if len(p.Transaction) == 0 || len(p.Transaction) > MaxTransactionSize {
		return fmt.Errorf("enroll: transaction is %d bytes, want 1..=%d", len(p.Transaction), MaxTransactionSize)
	}
	if len(p.NewKey) != crypto.PublicKeySize {
		return fmt.Errorf("enroll: new key is %d bytes, want %d", len(p.NewKey), crypto.PublicKeySize)
	}
	if len(p.Proof) != ProofSize {
		return fmt.Errorf("enroll: proof is %d bytes, want %d", len(p.Proof), ProofSize)
	}
	return nil
}

// checkShown is the rule for text the command shows: 1..=MaxTextSize bytes of well-formed
// UTF-8 with no display-unsafe code point. The code point is named, never echoed.
func checkShown(what, s string) error {
	if len(s) == 0 || len(s) > MaxTextSize {
		return fmt.Errorf("enroll: %s is %d bytes, want 1..=%d", what, len(s), MaxTextSize)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("enroll: %s is not valid UTF-8", what)
	}
	for _, r := range s {
		if login.DisplayUnsafe(r) {
			return fmt.Errorf("enroll: %s carries a code point that cannot be shown, U+%04X", what, r)
		}
	}
	return nil
}

// unwrap strips the surrounding whitespace the token rules allow and decodes the hex after
// prefix: lowercase only, even length, nothing else.
func unwrap(text, prefix string) ([]byte, error) {
	t := strings.Trim(text, "\t\n\r ")
	if len(t) > MaxTokenSize {
		return nil, fmt.Errorf("enroll: token is %d bytes, over %d", len(t), MaxTokenSize)
	}
	h, ok := strings.CutPrefix(t, prefix)
	if !ok {
		return nil, fmt.Errorf("enroll: not a token beginning %q", prefix)
	}
	if len(h)%2 != 0 {
		return nil, errors.New("enroll: token hex has an odd length")
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return nil, errors.New("enroll: token is not lowercase hex")
		}
	}
	return hex.DecodeString(h)
}

// reader takes length-prefixed fields off a byte slice, refusing anything that runs past it.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) take(n int) ([]byte, error) {
	if n > len(r.b)-r.pos {
		return nil, errors.New("enroll: truncated")
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) field() ([]byte, error) {
	n, err := r.take(2)
	if err != nil {
		return nil, err
	}
	return r.take(int(binary.BigEndian.Uint16(n)))
}

func (r *reader) end() error {
	if r.pos != len(r.b) {
		return fmt.Errorf("enroll: %d bytes left over", len(r.b)-r.pos)
	}
	return nil
}
