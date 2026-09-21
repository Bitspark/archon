// Package keycodec is archon's Ed25519 key codec: the pure, IO-free conversions
// between raw 32-byte keys/seeds and the two standard PEM containers — PKCS#8 v1
// (private) and SPKI (public). It is a byte codec, NOT key custody: it holds no key,
// reads no file, and draws no randomness (archon ADR 0002). The byte templates and the
// accept/reject contract are RFC 5958 / RFC 5280 (`ed25519-key-codec-v1`), byte-pinned
// across the three cores by the `keycodec` conformance family.
//
// It wraps no ASN.1 library: the Ed25519 DER is fixed-size, so encode is a constant
// prefix followed by the 32 key bytes, and decode is a bounded template match. Decode
// is PEM-only and total — any shape it does not recognize is a clean error, never a
// panic. PKCS#8 is v1-only (no embedded public key); v2 is rejected (spec A.8).
package keycodec

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// keyLen is the fixed length, in bytes, of an Ed25519 public key — and of a seed.
const keyLen = ed25519.PublicKeySize // 32; == ed25519.SeedSize

// The fixed DER prefixes (RFC 8410); each is followed verbatim by the 32 key bytes.
var (
	// spkiPrefix is the SubjectPublicKeyInfo header for an Ed25519 public key — the
	// first 12 bytes of the 44-byte DER: SEQUENCE { SEQUENCE { OID 1.3.101.112 },
	// BIT STRING(0 unused bits) { pubkey } }. The trailing 0x00 is the unused-bits octet.
	spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	// pkcs8Prefix is the PKCS#8 v1 PrivateKeyInfo header for an Ed25519 seed — the first
	// 16 bytes of the 48-byte DER: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
	// OCTET STRING { OCTET STRING { seed } } }. Version 0 = v1 (no embedded public key).
	pkcs8Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
)

const (
	pemTypePublic  = "PUBLIC KEY"
	pemTypePrivate = "PRIVATE KEY"
)

// PubkeyToSPKIPEM encodes a 32-byte Ed25519 public key as SPKI PEM
// (`-----BEGIN PUBLIC KEY-----`). It errors if pubkey is not exactly 32 bytes.
func PubkeyToSPKIPEM(pubkey []byte) ([]byte, error) {
	return encode(pubkey, spkiPrefix, pemTypePublic)
}

// SeedToPKCS8PEM encodes a 32-byte Ed25519 seed as PKCS#8 v1 PEM
// (`-----BEGIN PRIVATE KEY-----`). It errors if seed is not exactly 32 bytes.
func SeedToPKCS8PEM(seed []byte) ([]byte, error) {
	return encode(seed, pkcs8Prefix, pemTypePrivate)
}

// SPKIPEMToPubkey decodes SPKI PEM back to the raw 32-byte Ed25519 public key.
func SPKIPEMToPubkey(pemBytes []byte) ([]byte, error) {
	return decode(pemBytes, spkiPrefix, pemTypePublic)
}

// PKCS8PEMToSeed decodes PKCS#8 v1 PEM back to the raw 32-byte Ed25519 seed.
func PKCS8PEMToSeed(pemBytes []byte) ([]byte, error) {
	return decode(pemBytes, pkcs8Prefix, pemTypePrivate)
}

// encode renders key (which must be exactly 32 bytes) as prefix||key, base64'd into a
// single PEM line. The body is 44/48 bytes -> 60/64 base64 chars, so it is always one
// line of at most 64 columns; the framing is LF-terminated with exactly one trailing
// newline (spec A.8).
func encode(key, prefix []byte, pemType string) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("keycodec: key must be %d bytes, got %d", keyLen, len(key))
	}
	der := make([]byte, 0, len(prefix)+keyLen)
	der = append(der, prefix...)
	der = append(der, key...)
	body := base64.StdEncoding.EncodeToString(der)
	pem := "-----BEGIN " + pemType + "-----\n" + body + "\n-----END " + pemType + "-----\n"
	return []byte(pem), nil
}

// decode is PEM-only and total: it accepts exactly the canonical fixed template for
// pemType (prefix||32 bytes), tolerating \r\n line endings and trailing newlines, and
// returns the 32 key bytes. Anything else — bare DER, wrong header, wrong OID, wrong
// length (incl. PKCS#8 v2), truncation, trailing content, bad base64 — is a clean error.
func decode(pemBytes, prefix []byte, pemType string) ([]byte, error) {
	s := strings.ReplaceAll(string(pemBytes), "\r\n", "\n")
	s = strings.TrimRight(s, "\n")
	begin := "-----BEGIN " + pemType + "-----"
	end := "-----END " + pemType + "-----"
	lines := strings.Split(s, "\n")
	if len(lines) < 3 || lines[0] != begin || lines[len(lines)-1] != end {
		return nil, fmt.Errorf("keycodec: not a %q PEM block", pemType)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(lines[1:len(lines)-1], ""))
	if err != nil {
		return nil, fmt.Errorf("keycodec: invalid base64 in PEM body: %w", err)
	}
	if len(der) != len(prefix)+keyLen || !bytes.Equal(der[:len(prefix)], prefix) {
		return nil, fmt.Errorf("keycodec: DER does not match the %s ed25519-key-codec-v1 template", pemType)
	}
	out := make([]byte, keyLen)
	copy(out, der[len(prefix):])
	return out, nil
}
