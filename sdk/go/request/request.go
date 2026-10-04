// Package request is request authentication — THIS KEY MADE THIS HTTP REQUEST (ADR 0010 §2–§6;
// docs/request.md §3–§5 and §7, version 1, fixed by ADR 0010's status note of 4 October 2026).
//
// archon's RFC 9421 application profile: the client signs the RFC 9421 signature base directly,
// in Domain, with archon's construction (Ed25519ph with the domain as the RFC 8032 context), and
// `alg` is never sent — the registered `ed25519` is pure Ed25519. The coverage is fixed: the
// method, the full target URI, the configured audience as a CHECKED ECHO, a SHA-256
// Content-Digest, Content-Type if present, and every product-declared header the request
// carries.
//
// This package is the sdk's part (ADR 0010 §1): the transcript, the strict parsing, the coverage
// rule and pure verification. Time is an argument. What it does NOT do is remember: one-use
// enforcement (the replay store) and the HTTP extraction belong to the server adapters, so a
// Verified is a proof that checked out, not yet a request that may reach an application.
package request

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/signer"
)

// The profile's constants (docs/request.md §1, §3.1).
const (
	Domain        = "archon-request/1" // the RFC 8032 context every request signature is made in
	Tag           = "archon-request/1" // the `tag` signature parameter; a verifier accepts only this
	Label         = "archon"           // the one dictionary member in Signature-Input and Signature
	MinNonceSize  = 16
	MaxNonceSize  = 64
	MaxTargetSize = 8192
	MaxValueSize  = 8192
	MaxInt        = 999_999_999_999_999
)

// ToSign is what a client signs. Declared holds the product-declared headers the request
// carries, in the product's declared order, names in lowercase. A nil ContentType means the
// request carries none.
type ToSign struct {
	Method        string
	Audience      string
	RequestTarget string
	Body          []byte
	ContentType   *string
	Declared      [][2]string
	Created       int64
	Expires       int64
	Nonce         []byte
}

// Headers are the four headers archon adds to a request.
type Headers struct {
	ArchonAudience string // Archon-Audience
	ContentDigest  string // Content-Digest
	SignatureInput string // Signature-Input
	Signature      string // Signature
}

// Prepared is a request prepared for a signer: the base it will sign, the signing request, and
// every header but Signature.
type Prepared struct {
	Base    string
	Signing signer.Request
	Headers Headers
}

// Policy is what a verifier is configured with. MaxLifetime is W, Skew is δ, both in seconds.
type Policy struct {
	Audience    string
	Declared    []string
	MaxLifetime int64
	Skew        int64
}

// Received is a request as the server received it: the method, the raw request-target, every
// header field in the order received (names in any case), and the body after transfer framing.
type Received struct {
	Method        string
	RequestTarget string
	Headers       [][2]string
	Body          []byte
}

// Verified is a proof that checked out under the policy at now. Not yet replay-checked.
type Verified struct {
	Principal     []byte
	KeyText       string
	Created       int64
	Expires       int64
	Nonce         []byte
	Method        string
	TargetURI     string
	Covered       [][2]string // every covered field, in coverage order, with the verified value
	ContentDigest []byte
}

var (
	tchar         = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	visible       = regexp.MustCompile(`^[\x21-\x7e]+$`)
	audienceShape = regexp.MustCompile(`^(https?://)([^/]*)(/.*)?$`)
	valueChars    = regexp.MustCompile(`^[\t\x20-\x7e]+$`)
	declaredName  = regexp.MustCompile(`^[a-z0-9-]+$`)
	reserved      = map[string]bool{"archon-audience": true, "content-digest": true, "content-type": true, "signature-input": true, "signature": true}

	signatureInput = regexp.MustCompile(`^archon=\(("[^"]*"(?: "[^"]*")*)\);created=(0|[1-9][0-9]{0,14});expires=(0|[1-9][0-9]{0,14});nonce="([A-Za-z0-9_-]+)";keyid="([^"\\]*)";tag="archon-request/1"$`)
	signatureField = regexp.MustCompile(`^archon=:([A-Za-z0-9+/=]+):$`)
	contentDigest  = regexp.MustCompile(`^sha-256=:([A-Za-z0-9+/=]+):$`)
)

// Origin is the origin of an audience — the audience up to its authority's end — or an error
// for an audience outside docs/request.md §3.1.
func Origin(audience string) (string, error) {
	if !visible.MatchString(audience) {
		return "", errors.New("request: the audience is not visible ASCII")
	}
	m := audienceShape.FindStringSubmatch(audience)
	if m == nil {
		return "", errors.New("request: the audience is not an http or https URL")
	}
	if m[2] == "" || strings.Contains(m[2], "@") {
		return "", errors.New("request: the audience's authority is empty or carries userinfo")
	}
	if strings.ContainsAny(audience, "?#") {
		return "", errors.New("request: the audience carries a query or a fragment")
	}
	if strings.HasSuffix(audience, "/") {
		return "", errors.New("request: the audience ends in /")
	}
	return m[1] + m[2], nil
}

func checkMethod(method string) error {
	if !tchar.MatchString(method) {
		return errors.New("request: the method is not a token")
	}
	return nil
}

func checkTarget(target string) error {
	if len(target) == 0 || len(target) > MaxTargetSize {
		return errors.New("request: the request-target's length")
	}
	if !strings.HasPrefix(target, "/") || !visible.MatchString(target) || strings.Contains(target, "#") {
		return errors.New("request: the request-target is not origin form")
	}
	return nil
}

// coveredValue trims leading and trailing SP and HTAB and checks what remains.
func coveredValue(value string) (string, error) {
	v := strings.Trim(value, " \t")
	if len(v) == 0 || len(v) > MaxValueSize || !valueChars.MatchString(v) {
		return "", errors.New("request: a covered value is empty, too long, or not visible ASCII, SP and HTAB")
	}
	return v, nil
}

func checkDeclaredName(name string) error {
	if !declaredName.MatchString(name) || reserved[name] {
		return fmt.Errorf("request: %q cannot be a declared header", name)
	}
	return nil
}

func checkInt(n int64, what string) error {
	if n < 0 || n > MaxInt {
		return fmt.Errorf("request: %s is not an integer in 0..=%d", what, int64(MaxInt))
	}
	return nil
}

func checkNonce(nonce []byte) error {
	if len(nonce) < MinNonceSize || len(nonce) > MaxNonceSize {
		return fmt.Errorf("request: the nonce is %d bytes, want %d..=%d", len(nonce), MinNonceSize, MaxNonceSize)
	}
	return nil
}

// SignatureBase is the RFC 9421 signature base: one `"<name>": <value>` line per covered
// component, then `"@signature-params": <inner list>` with no trailing line feed.
func SignatureBase(components [][2]string, innerList string) string {
	var b strings.Builder
	for _, c := range components {
		fmt.Fprintf(&b, "\"%s\": %s\n", c[0], c[1])
	}
	b.WriteString("\"@signature-params\": ")
	b.WriteString(innerList)
	return b.String()
}

func digestHeader(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// Prepare is the base and headers for in, for a signer whose key is publicKey. Pure; it errors
// on any value outside docs/request.md §3.1.
func Prepare(publicKey []byte, in ToSign) (Prepared, error) {
	if len(publicKey) != crypto.PublicKeySize {
		return Prepared{}, errors.New("request: the public key is not 32 bytes")
	}
	if err := checkMethod(in.Method); err != nil {
		return Prepared{}, err
	}
	origin, err := Origin(in.Audience)
	if err != nil {
		return Prepared{}, err
	}
	if err := checkTarget(in.RequestTarget); err != nil {
		return Prepared{}, err
	}
	if err := checkInt(in.Created, "created"); err != nil {
		return Prepared{}, err
	}
	if err := checkInt(in.Expires, "expires"); err != nil {
		return Prepared{}, err
	}
	if in.Created >= in.Expires {
		return Prepared{}, errors.New("request: created must be before expires")
	}
	if err := checkNonce(in.Nonce); err != nil {
		return Prepared{}, err
	}
	digest := digestHeader(in.Body)
	components := [][2]string{
		{"@method", in.Method},
		{"@target-uri", origin + in.RequestTarget},
		{"archon-audience", in.Audience},
		{"content-digest", digest},
	}
	if in.ContentType != nil {
		v, err := coveredValue(*in.ContentType)
		if err != nil {
			return Prepared{}, err
		}
		components = append(components, [2]string{"content-type", v})
	}
	seen := map[string]bool{}
	for _, d := range in.Declared {
		if err := checkDeclaredName(d[0]); err != nil {
			return Prepared{}, err
		}
		if seen[d[0]] {
			return Prepared{}, fmt.Errorf("request: %s is declared twice", d[0])
		}
		seen[d[0]] = true
		v, err := coveredValue(d[1])
		if err != nil {
			return Prepared{}, err
		}
		components = append(components, [2]string{d[0], v})
	}
	keyText := keytext.EncodeKey(publicKey)
	names := make([]string, len(components))
	for i, c := range components {
		names[i] = `"` + c[0] + `"`
	}
	inner := fmt.Sprintf("(%s);created=%d;expires=%d;nonce=\"%s\";keyid=\"%s\";tag=\"%s\"",
		strings.Join(names, " "), in.Created, in.Expires, base64.RawURLEncoding.EncodeToString(in.Nonce), keyText, Tag)
	base := SignatureBase(components, inner)
	return Prepared{
		Base:    base,
		Signing: signer.Request{ExpectedPublicKey: bytes.Clone(publicKey), Scheme: signer.PhContext{Domain: Domain}, Message: []byte(base)},
		Headers: Headers{ArchonAudience: in.Audience, ContentDigest: digest, SignatureInput: Label + "=" + inner},
	}, nil
}

// Complete is the headers, from a signature over a prepared request: checked against it first.
// Pure.
func Complete(p Prepared, signature []byte) (Headers, error) {
	if err := signer.Check(p.Signing, signature); err != nil {
		return Headers{}, err
	}
	h := p.Headers
	h.Signature = Label + "=:" + base64.StdEncoding.EncodeToString(signature) + ":"
	return h, nil
}

// Sign signs in with the key behind seed: the base, and the four headers to send.
func Sign(seed []byte, in ToSign) (string, Headers, error) {
	if len(seed) != crypto.SeedSize {
		return "", Headers{}, fmt.Errorf("request: seed is %d bytes, want %d", len(seed), crypto.SeedSize)
	}
	p, err := Prepare(crypto.PublicKeyFromSeed(seed), in)
	if err != nil {
		return "", Headers{}, err
	}
	sig, err := crypto.SignInDomain(seed, Domain, p.Signing.Message)
	if err != nil {
		return "", Headers{}, err
	}
	h, err := Complete(p, sig)
	return p.Base, h, err
}

// SignWith is Sign through a signer instead of a seed.
func SignWith(ctx context.Context, s signer.Signer, in ToSign) (Headers, error) {
	p, err := Prepare(s.PublicKey(), in)
	if err != nil {
		return Headers{}, err
	}
	sig, err := signer.SignWith(ctx, s, p.Signing)
	if err != nil {
		return Headers{}, err
	}
	return Complete(p, sig)
}

// Verify verifies r under p at now (seconds since the epoch): docs/request.md §7 steps 1–7. It
// does not check replay: a server adapter must insert (Tag, audience, principal, nonce) into its
// replay store before the request reaches an application.
func Verify(p Policy, now int64, r Received) (Verified, error) {
	origin, err := Origin(p.Audience)
	if err != nil {
		return Verified{}, err
	}
	declared := map[string]bool{}
	for _, d := range p.Declared {
		if err := checkDeclaredName(d); err != nil {
			return Verified{}, err
		}
		if declared[d] {
			return Verified{}, fmt.Errorf("request: %s is declared twice", d)
		}
		declared[d] = true
	}
	if err := checkInt(p.MaxLifetime, "max_lifetime"); err != nil {
		return Verified{}, err
	}
	if p.MaxLifetime < 1 {
		return Verified{}, errors.New("request: max_lifetime must be at least 1")
	}
	if err := checkInt(p.Skew, "skew"); err != nil {
		return Verified{}, err
	}
	if err := checkInt(now, "now"); err != nil {
		return Verified{}, err
	}

	fields := map[string][]string{}
	for _, h := range r.Headers {
		// ASCII case folding only: HTTP field names are tokens, and Unicode folding would turn
		// U+212A KELVIN SIGN into `k` — a different header in a lane that folds ASCII only.
		key := strings.Map(func(r rune) rune {
			if 'A' <= r && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, h[0])
		fields[key] = append(fields[key], strings.Trim(h[1], " \t"))
	}
	once := func(name string) (string, error) {
		if len(fields[name]) != 1 {
			return "", fmt.Errorf("request: %s must appear exactly once", name)
		}
		return fields[name][0], nil
	}

	// 1. The two proof fields parse, in their one spelling.
	siText, err := once("signature-input")
	if err != nil {
		return Verified{}, err
	}
	si := signatureInput.FindStringSubmatch(siText)
	if si == nil {
		return Verified{}, errors.New("request: Signature-Input is not the profile's spelling")
	}
	sigText, err := once("signature")
	if err != nil {
		return Verified{}, err
	}
	sm := signatureField.FindStringSubmatch(sigText)
	if sm == nil {
		return Verified{}, errors.New("request: Signature is not the profile's spelling")
	}
	signature, err := decodeCanonical(base64.StdEncoding, sm[1])
	if err != nil || len(signature) != crypto.SignatureSize {
		return Verified{}, errors.New("request: the signature is not 64 bytes of canonical base64")
	}
	quoted := strings.Split(si[1], " ")
	names := make([]string, len(quoted))
	for i, q := range quoted {
		names[i] = q[1 : len(q)-1]
	}
	created, _ := strconv.ParseInt(si[2], 10, 64)
	expires, _ := strconv.ParseInt(si[3], 10, 64)
	nonce, err := decodeCanonical(base64.RawURLEncoding, si[4])
	if err != nil {
		return Verified{}, err
	}
	if err := checkNonce(nonce); err != nil {
		return Verified{}, err
	}

	// 2. keyid is a canonical principal (the tag was matched by the grammar).
	keyText := si[5]
	principal, err := keytext.DecodeKey(keyText)
	if err != nil {
		return Verified{}, errors.New("request: keyid is not a principal")
	}
	if keytext.EncodeKey(principal) != keyText {
		return Verified{}, errors.New("request: keyid is not the canonical key text")
	}

	// 3. The coverage is exactly §3.1's, for what this request carries.
	expected := []string{"@method", "@target-uri", "archon-audience", "content-digest"}
	if _, ok := fields["content-type"]; ok {
		expected = append(expected, "content-type")
	}
	for _, d := range p.Declared {
		if _, ok := fields[d]; ok {
			expected = append(expected, d)
		}
	}
	if strings.Join(names, "\x00") != strings.Join(expected, "\x00") {
		return Verified{}, errors.New("request: the coverage is not the profile's for this request")
	}
	if err := checkMethod(r.Method); err != nil {
		return Verified{}, err
	}
	if err := checkTarget(r.RequestTarget); err != nil {
		return Verified{}, err
	}
	components := make([][2]string, 0, len(names))
	for _, n := range names {
		switch n {
		case "@method":
			components = append(components, [2]string{n, r.Method})
		case "@target-uri":
			components = append(components, [2]string{n, origin + r.RequestTarget})
		default:
			raw, err := once(n)
			if err != nil {
				return Verified{}, err
			}
			v, err := coveredValue(raw)
			if err != nil {
				return Verified{}, err
			}
			components = append(components, [2]string{n, v})
		}
	}

	// 4. The audience echo is the configured audience, byte for byte.
	if echo, _ := once("archon-audience"); echo != p.Audience {
		return Verified{}, errors.New("request: Archon-Audience is not the configured audience")
	}

	// 5. The digest is the received content's.
	cdText, _ := once("content-digest")
	cd := contentDigest.FindStringSubmatch(cdText)
	if cd == nil {
		return Verified{}, errors.New("request: Content-Digest is not the profile's spelling")
	}
	digest, err := decodeCanonical(base64.StdEncoding, cd[1])
	if err != nil {
		return Verified{}, err
	}
	actual := sha256.Sum256(r.Body)
	if !bytes.Equal(digest, actual[:]) {
		return Verified{}, errors.New("request: Content-Digest does not match the content")
	}

	// 6. Freshness: 0 < e − c ≤ W and c − δ ≤ now < e + δ.
	if !(created < expires && expires-created <= p.MaxLifetime) {
		return Verified{}, errors.New("request: the lifetime is out of bounds")
	}
	if !(created-p.Skew <= now && now < expires+p.Skew) {
		return Verified{}, errors.New("request: not fresh at now")
	}

	// 7. The signature, over the base built from what was received and configured.
	base := SignatureBase(components, si[0][len(Label)+1:])
	if !crypto.VerifyInDomain(principal, Domain, []byte(base), signature) {
		return Verified{}, errors.New("request: the signature does not verify")
	}

	covered := make([][2]string, 0, len(components))
	for _, c := range components {
		if !strings.HasPrefix(c[0], "@") {
			covered = append(covered, c)
		}
	}
	return Verified{
		Principal: principal, KeyText: keyText, Created: created, Expires: expires, Nonce: nonce,
		Method: r.Method, TargetURI: origin + r.RequestTarget, Covered: covered, ContentDigest: digest,
	}, nil
}

// decodeCanonical decodes text and refuses it unless re-encoding gives the same text: base64
// has one spelling here (docs/request.md §3.1).
func decodeCanonical(enc *base64.Encoding, text string) ([]byte, error) {
	b, err := enc.Strict().DecodeString(text)
	if err != nil || enc.EncodeToString(b) != text {
		return nil, errors.New("request: not the canonical base64 spelling")
	}
	return b, nil
}
