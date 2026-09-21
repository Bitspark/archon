package keystore

// The archon key store's file format — docs/keystore.md, ADR 0007 §A.
//
// A fixed 134-byte layout, identical across cli/{rs,go,ts} and pinned by
// vectors/keystore.json:
//
//	"arck" ‖ version ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]   header, 62
//	nonce[24]
//	XChaCha20Poly1305(seed[32], aad = header)                                     48 with the tag
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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"

	"github.com/Bitspark/archon/core/go/crypto"
)

const (
	// Magic follows the envelope's "arcn" ‖ version (sdk/{go,rs,ts}). It is what stops a
	// 134-byte non-key file being LISTED as a key: `key list` reads the header without a
	// password, so it is the one place a wrong file would be believed.
	Magic   = "arck"
	Version = 0x01

	SaltSize   = 16
	NonceSize  = chacha20poly1305.NonceSizeX // 24
	HeaderSize = 4 + 1 + 4 + 4 + 1 + SaltSize + crypto.PublicKeySize
	FileSize   = HeaderSize + NonceSize + crypto.SeedSize + 16

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

// Header is the authenticated prefix of a key file. PublicKey is readable without a
// password — that is what `key list` prints — but it is only a CLAIM until an unlock
// verifies the tag over this header and re-derives it from the seed.
type Header struct {
	Params    Params
	Salt      []byte
	PublicKey []byte
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

func EncodeHeader(h Header) []byte {
	out := make([]byte, 0, HeaderSize)
	out = append(out, Magic...)
	out = append(out, Version)
	out = binary.BigEndian.AppendUint32(out, h.Params.MemoryKiB)
	out = binary.BigEndian.AppendUint32(out, h.Params.Time)
	out = append(out, h.Params.Parallelism)
	out = append(out, h.Salt...)
	out = append(out, h.PublicKey...)
	return out
}

// ParseHeader reads the header of a key file WITHOUT a password. Every refusal here is
// cheap and happens before any crypto runs.
func ParseHeader(file []byte) (Header, error) {
	if len(file) != FileSize {
		return Header{}, fmt.Errorf("not %d bytes (got %d)", FileSize, len(file))
	}
	if !bytes.Equal(file[:4], []byte(Magic)) {
		return Header{}, fmt.Errorf("bad magic: not an archon key file")
	}
	if file[4] != Version {
		return Header{}, fmt.Errorf("unknown key file version %d", file[4])
	}
	h := Header{
		Params: Params{
			MemoryKiB:   binary.BigEndian.Uint32(file[5:9]),
			Time:        binary.BigEndian.Uint32(file[9:13]),
			Parallelism: file[13],
		},
		Salt:      append([]byte(nil), file[14:30]...),
		PublicKey: append([]byte(nil), file[30:HeaderSize]...),
	}
	if h.Params.MemoryKiB == 0 || h.Params.Time == 0 || h.Params.Parallelism == 0 {
		return Header{}, fmt.Errorf("argon2id parameters in the header are not usable")
	}
	return h, nil
}

// Seal produces the 134 bytes. salt and nonce are ARGUMENTS: the randomness is the
// command's, never this function's, which is what makes the format pinnable.
func Seal(seed, password, salt, nonce []byte, p Params) ([]byte, error) {
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
	header := EncodeHeader(Header{Params: p, Salt: salt, PublicKey: crypto.PublicKeyFromSeed(seed)})
	key := deriveKey(password, salt, p)
	defer Zeroise(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, FileSize)
	out = append(out, header...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, seed, header)
	return out, nil
}

// Open reverses Seal and then checks the decrypted seed against the header's public
// key. The tag proves the bytes are ours; that check proves they are CONSISTENT — a file
// can verify and still be refused.
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
	nonce := file[HeaderSize : HeaderSize+NonceSize]
	seed, err := aead.Open(nil, nonce, file[HeaderSize+NonceSize:], file[:HeaderSize])
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
