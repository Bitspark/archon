package envelope

import (
	"bytes"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
)

const d = "archon/test/env"

func TestSealsAndOpens(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, 32)
	env, err := Seal(seed, d, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(env, d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.Pubkey, crypto.PublicKeyFromSeed(seed)) || string(o.Payload) != "payload" {
		t.Errorf("opened = %x / %q", o.Pubkey, o.Payload)
	}
	empty, _ := Seal(seed, d, nil)
	if o, err := Open(empty, d); err != nil || len(o.Payload) != 0 {
		t.Errorf("empty payload: %v, %q", err, o.Payload)
	}
}

func TestRefusesEveryTamper(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, 32)
	env, _ := Seal(seed, d, []byte("payload"))
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), env...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"payload tampered":     mut(func(b []byte) { b[len(b)-1] ^= 0x01 }),
		"bad magic":            mut(func(b []byte) { b[0] = 'x' }),
		"unknown version":      mut(func(b []byte) { b[4] = 0x02 }),
		"domain bytes altered": mut(func(b []byte) { b[6] ^= 0x01 }),
		"truncated":            env[:len(env)-8],
		"far too short":        env[:10],
	}
	for name, b := range cases {
		if _, err := Open(b, d); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := Open(env, "archon/test/other"); err == nil {
		t.Error("verifier expecting another domain: opened")
	}
	// A different key's signature over the same payload does not open under the original
	// key's envelope header.
	other, _ := Seal(bytes.Repeat([]byte{0x0a}, 32), d, []byte("payload"))
	sigAt := 4 + 1 + 1 + len(d) + crypto.PublicKeySize
	swapped := mut(func(b []byte) { copy(b[sigAt:sigAt+crypto.SignatureSize], other[sigAt:sigAt+crypto.SignatureSize]) })
	if _, err := Open(swapped, d); err == nil {
		t.Error("signature from another key: opened")
	}
}

func TestSealRefusesWrongSizeSeed(t *testing.T) {
	if _, err := Seal(make([]byte, 31), "archon/test/env", []byte("hello")); err == nil {
		t.Fatal("a 31-byte seed was not refused")
	}
}
