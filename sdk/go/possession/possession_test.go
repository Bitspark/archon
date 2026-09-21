package possession

import (
	"bytes"
	"testing"

	"github.com/Bitspark/archon/core/go/crypto"
)

const d = "archon/test/pop"

func TestProvesAndRefusesEverySubstitution(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, 32)
	pk := crypto.PublicKeyFromSeed(seed)
	nonce := bytes.Repeat([]byte{0xaa}, 16)
	binding := []byte("session:1")
	sig, err := Prove(seed, d, nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, d, nonce, binding, sig) {
		t.Error("proof did not verify")
	}
	if Verify(pk, d, bytes.Repeat([]byte{0xab}, 16), binding, sig) {
		t.Error("other nonce accepted")
	}
	if Verify(pk, d, nonce, []byte("session:2"), sig) {
		t.Error("other binding accepted")
	}
	if Verify(pk, "archon/test/other", nonce, binding, sig) {
		t.Error("other domain accepted")
	}
	if Verify(make([]byte, 32), d, nonce, binding, sig) {
		t.Error("other key accepted")
	}
	m, _ := MessageBytes(nonce, binding)
	if Verify(pk, d, nonce, binding, crypto.Sign(seed, m)) {
		t.Error("raw signature accepted as a proof")
	}
	bare, _ := crypto.SignInDomain(seed, d, nonce)
	if Verify(pk, d, nonce, binding, bare) {
		t.Error("domain signature over the bare nonce accepted as a proof")
	}
}

func TestRefusesShortNonceAndEmptyBinding(t *testing.T) {
	seed := bytes.Repeat([]byte{0x09}, 32)
	pk := crypto.PublicKeyFromSeed(seed)
	if _, err := Prove(seed, d, bytes.Repeat([]byte{0xaa}, 15), []byte("b")); err == nil {
		t.Error("15-byte nonce accepted")
	}
	if _, err := Prove(seed, d, bytes.Repeat([]byte{0xaa}, 16), nil); err == nil {
		t.Error("empty binding accepted")
	}
	if _, err := Prove(seed, "", bytes.Repeat([]byte{0xaa}, 16), []byte("b")); err == nil {
		t.Error("empty domain accepted")
	}
	if Verify(pk, d, bytes.Repeat([]byte{0xaa}, 15), []byte("b"), make([]byte, 64)) {
		t.Error("verify accepted a short nonce")
	}
	if Verify(pk, d, bytes.Repeat([]byte{0xaa}, 16), nil, make([]byte, 64)) {
		t.Error("verify accepted an empty binding")
	}
}

func TestLayoutIsThePinnedOne(t *testing.T) {
	m, err := MessageBytes(bytes.Repeat([]byte{0x11}, 16), []byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{SchemeTag, 0x00, 0x10}, bytes.Repeat([]byte{0x11}, 16)...)
	want = append(want, 0x00, 0x02, 'a', 'b')
	if !bytes.Equal(m, want) {
		t.Errorf("layout = %x, want %x", m, want)
	}
}

func TestProveRefusesWrongSizeSeed(t *testing.T) {
	if _, err := Prove(make([]byte, 31), "archon/test/pop", make([]byte, 16), []byte("session:1")); err == nil {
		t.Fatal("a 31-byte seed was not refused")
	}
}
