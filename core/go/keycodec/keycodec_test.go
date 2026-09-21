package keycodec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
)

// seed32 is a deterministic 32-byte seed (0x00..0x1f) used across the tests.
func seed32() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// pemWrap frames arbitrary DER as a single-line PEM block of the given type — used to
// craft both canonical and malformed decode inputs.
func pemWrap(pemType string, der []byte) []byte {
	body := base64.StdEncoding.EncodeToString(der)
	return []byte("-----BEGIN " + pemType + "-----\n" + body + "\n-----END " + pemType + "-----\n")
}

func mustEncode(t *testing.T, fn func([]byte) ([]byte, error), key []byte) []byte {
	t.Helper()
	out, err := fn(key)
	if err != nil {
		t.Fatalf("encode: unexpected error: %v", err)
	}
	return out
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	seed := seed32()
	pub := crypto.PublicKeyFromSeed(seed)

	privPEM := mustEncode(t, SeedToPKCS8PEM, seed)
	gotSeed, err := PKCS8PEMToSeed(privPEM)
	if err != nil {
		t.Fatalf("PKCS8PEMToSeed: %v", err)
	}
	if !bytes.Equal(gotSeed, seed) {
		t.Fatalf("seed round-trip mismatch:\n got %x\nwant %x", gotSeed, seed)
	}

	pubPEM := mustEncode(t, PubkeyToSPKIPEM, pub)
	gotPub, err := SPKIPEMToPubkey(pubPEM)
	if err != nil {
		t.Fatalf("SPKIPEMToPubkey: %v", err)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("pubkey round-trip mismatch:\n got %x\nwant %x", gotPub, pub)
	}
}

// TestMatchesStdlibX509 pins our hand-rolled template against Go's audited crypto/x509
// (an independent RFC 8410 implementation): for several seeds, our encode output must
// equal x509+pem byte-for-byte, and we must decode x509+pem output to the same key.
func TestMatchesStdlibX509(t *testing.T) {
	seeds := [][]byte{
		make([]byte, 32),               // all-zero
		seed32(),                       // 0x00..0x1f
		bytes.Repeat([]byte{0xff}, 32), // all-ones
	}
	for _, seed := range seeds {
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)

		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
		}
		wantPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})
		if got := mustEncode(t, SeedToPKCS8PEM, seed); !bytes.Equal(got, wantPriv) {
			t.Fatalf("SeedToPKCS8PEM != x509/pem for seed %x:\n got %q\nwant %q", seed, got, wantPriv)
		}

		spkiDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
		}
		wantPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
		if got := mustEncode(t, PubkeyToSPKIPEM, []byte(pub)); !bytes.Equal(got, wantPub) {
			t.Fatalf("PubkeyToSPKIPEM != x509/pem for seed %x:\n got %q\nwant %q", seed, got, wantPub)
		}

		// And our decoders read x509's PEM back to the right raw bytes.
		if gotSeed, err := PKCS8PEMToSeed(wantPriv); err != nil || !bytes.Equal(gotSeed, seed) {
			t.Fatalf("PKCS8PEMToSeed(x509) = %x, %v; want %x", gotSeed, err, seed)
		}
		if gotPub, err := SPKIPEMToPubkey(wantPub); err != nil || !bytes.Equal(gotPub, pub) {
			t.Fatalf("SPKIPEMToPubkey(x509) = %x, %v; want %x", gotPub, err, []byte(pub))
		}
	}
}

func TestEncodeRejectsNon32(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		key := make([]byte, n)
		if _, err := SeedToPKCS8PEM(key); err == nil {
			t.Errorf("SeedToPKCS8PEM(%d bytes): expected error", n)
		}
		if _, err := PubkeyToSPKIPEM(key); err == nil {
			t.Errorf("PubkeyToSPKIPEM(%d bytes): expected error", n)
		}
	}
}

// TestDecodeAcceptsFramingVariants checks the tolerated framing: CRLF line endings, and
// zero / extra trailing newlines.
func TestDecodeAcceptsFramingVariants(t *testing.T) {
	canon := mustEncode(t, SeedToPKCS8PEM, seed32())
	variants := map[string][]byte{
		"canonical":            canon,
		"crlf":                 bytes.ReplaceAll(canon, []byte("\n"), []byte("\r\n")),
		"no-trailing-newline":  bytes.TrimRight(canon, "\n"),
		"extra-trailing-lines": append(append([]byte{}, canon...), '\n', '\n'),
	}
	for name, in := range variants {
		got, err := PKCS8PEMToSeed(in)
		if err != nil || !bytes.Equal(got, seed32()) {
			t.Errorf("%s: PKCS8PEMToSeed = %x, %v; want the seed", name, got, err)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	seed := seed32()
	pub := crypto.PublicKeyFromSeed(seed)
	validSPKI := mustEncode(t, PubkeyToSPKIPEM, pub)
	validPKCS8 := mustEncode(t, SeedToPKCS8PEM, seed)

	// X25519 OID 1.3.101.110 (...2b656e...) in an otherwise SPKI-shaped header.
	wrongOIDSPKI := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00}
	// SPKI with a non-zero BIT STRING unused-bits octet (0xff instead of 0x00).
	badUnusedBits := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0xff}
	// A faithful PKCS#8 v2 (version 1 + embedded [1] public key) — we reject it.
	v2 := func() []byte {
		out := []byte{0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
		out = append(out, seed...)
		out = append(out, 0x81, 0x21, 0x00)
		return append(out, pub...)
	}()

	rejects := map[string]struct {
		fn func([]byte) ([]byte, error)
		in []byte
	}{
		"spki: wrong OID (x25519)":       {SPKIPEMToPubkey, pemWrap("PUBLIC KEY", wrongOIDSPKI[:])},
		"spki: non-00 unused bits":       {SPKIPEMToPubkey, pemWrap("PUBLIC KEY", append(badUnusedBits[:], pub...))},
		"spki: key too short (31)":       {SPKIPEMToPubkey, pemWrap("PUBLIC KEY", append(append([]byte{}, spkiPrefix...), pub[:31]...))},
		"spki: trailing garbage byte":    {SPKIPEMToPubkey, pemWrap("PUBLIC KEY", append(append(append([]byte{}, spkiPrefix...), pub...), 0x00))},
		"spki: truncated (prefix only)":  {SPKIPEMToPubkey, pemWrap("PUBLIC KEY", spkiPrefix)},
		"spki: bare DER, no armor":       {SPKIPEMToPubkey, []byte(base64.StdEncoding.EncodeToString(append(append([]byte{}, spkiPrefix...), pub...)))},
		"spki: bad base64 body":          {SPKIPEMToPubkey, []byte("-----BEGIN PUBLIC KEY-----\n!!!not base64!!!\n-----END PUBLIC KEY-----\n")},
		"spki: empty":                    {SPKIPEMToPubkey, []byte("")},
		"cross: pkcs8 PEM to pubkey":     {SPKIPEMToPubkey, validPKCS8},
		"pkcs8: v2 with embedded pubkey": {PKCS8PEMToSeed, pemWrap("PRIVATE KEY", v2)},
		"pkcs8: key too long (33)":       {PKCS8PEMToSeed, pemWrap("PRIVATE KEY", append(append([]byte{}, pkcs8Prefix...), append(append([]byte{}, seed...), 0x00)...))},
		"cross: spki PEM to seed":        {PKCS8PEMToSeed, validSPKI},
		"pkcs8: wrong header label":      {PKCS8PEMToSeed, bytes.ReplaceAll(validPKCS8, []byte("PRIVATE KEY"), []byte("EC PRIVATE KEY"))},
	}
	for name, c := range rejects {
		if out, err := c.fn(c.in); err == nil {
			t.Errorf("%s: expected error, got %x", name, out)
		}
	}
}

// TestCrossSurfaceTie ties the codec to the existing key surfaces: the SPKI of a seed's
// public key decodes to exactly crypto.PublicKeyFromSeed(seed), and a PKCS#8 round-trip
// preserves the seed that derives it.
func TestCrossSurfaceTie(t *testing.T) {
	seed := seed32()
	pub := crypto.PublicKeyFromSeed(seed)

	decodedPub, err := SPKIPEMToPubkey(mustEncode(t, PubkeyToSPKIPEM, pub))
	if err != nil || !bytes.Equal(decodedPub, pub) {
		t.Fatalf("SPKI tie: got %x, %v; want %x", decodedPub, err, pub)
	}
	decodedSeed, err := PKCS8PEMToSeed(mustEncode(t, SeedToPKCS8PEM, seed))
	if err != nil {
		t.Fatalf("PKCS8PEMToSeed: %v", err)
	}
	if !bytes.Equal(crypto.PublicKeyFromSeed(decodedSeed), pub) {
		t.Fatal("PKCS8 tie: decoded seed does not derive the same public key")
	}
}

// TestOpenSSLInterop validates against the external standard: openssl parses our output,
// and openssl's own genpkey output decodes (and re-encodes byte-for-byte) through us. It
// skips when openssl is not on PATH (e.g. dev machines without it) — or when the openssl
// on PATH cannot generate ed25519 keys AT ALL (macOS ships LibreSSL as `openssl`, whose
// genpkey lacks the algorithm), since the oracle itself is unusable there. The capability
// probe runs NO archon code, so skipping on it can never mask a real interop failure;
// CI runners carry a capable OpenSSL and run the interop for real.
func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found on PATH; skipping interop")
	}
	if out, err := exec.Command(openssl, "genpkey", "-algorithm", "ed25519").CombinedOutput(); err != nil {
		t.Skipf("openssl on PATH cannot generate ed25519 keys (LibreSSL?); skipping interop: %v\n%s", err, out)
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(openssl, args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	// openssl emits CRLF on Windows, LF on Unix; our canonical form is LF (spec A.8) and
	// our decode tolerates both. Compare content modulo the platform's line-ending choice.
	normNL := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

	// 1. openssl generates a key; we decode its PKCS#8, then re-encode byte-for-byte.
	osslPriv := filepath.Join(dir, "priv.pem")
	run("genpkey", "-algorithm", "ed25519", "-out", osslPriv)
	privPEM, err := os.ReadFile(osslPriv)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := PKCS8PEMToSeed(privPEM)
	if err != nil {
		t.Fatalf("decode openssl PKCS#8: %v", err)
	}
	if reenc := mustEncode(t, SeedToPKCS8PEM, seed); !bytes.Equal(reenc, normNL(privPEM)) {
		t.Fatalf("re-encode != openssl PKCS#8:\n got %q\nwant %q", reenc, normNL(privPEM))
	}

	// 2. openssl extracts the public key; we decode its SPKI and re-encode byte-for-byte.
	osslPub := filepath.Join(dir, "pub.pem")
	run("pkey", "-in", osslPriv, "-pubout", "-out", osslPub)
	pubPEM, err := os.ReadFile(osslPub)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := SPKIPEMToPubkey(pubPEM)
	if err != nil {
		t.Fatalf("decode openssl SPKI: %v", err)
	}
	if !bytes.Equal(pub, crypto.PublicKeyFromSeed(seed)) {
		t.Fatal("openssl SPKI pubkey != derived pubkey")
	}
	if reenc := mustEncode(t, PubkeyToSPKIPEM, pub); !bytes.Equal(reenc, normNL(pubPEM)) {
		t.Fatalf("re-encode != openssl SPKI:\n got %q\nwant %q", reenc, normNL(pubPEM))
	}

	// 3. openssl accepts our own encode (both directions).
	oursPriv := filepath.Join(dir, "ours_priv.pem")
	if err := os.WriteFile(oursPriv, mustEncode(t, SeedToPKCS8PEM, seed), 0o600); err != nil {
		t.Fatal(err)
	}
	run("pkey", "-in", oursPriv, "-noout")
	oursPub := filepath.Join(dir, "ours_pub.pem")
	if err := os.WriteFile(oursPub, mustEncode(t, PubkeyToSPKIPEM, pub), 0o600); err != nil {
		t.Fatal(err)
	}
	run("pkey", "-pubin", "-in", oursPub, "-noout")
}
