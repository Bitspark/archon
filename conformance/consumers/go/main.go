// An OUTSIDE consumer of archon from the public Go proxy: the floor and the sdk, resolved
// through proxy.golang.org and sum.golang.org into an empty module cache, with no checkout,
// replace directive or workspace in sight. Run by release.yml after the tags are public,
// and by hand as
//
//	d=$(mktemp -d) && cp conformance/consumers/go/main.go "$d" && cd "$d" && go mod init consumer \
//	  && GOFLAGS= GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOMODCACHE=$(mktemp -d) \
//	     go get github.com/Bitspark/archon/sdk/go@vX github.com/Bitspark/archon/core/go@vX && go run .
//
// "Meaningful execution" means the behaviour the release claims: a genuine domain signature
// verifies in its domain and nowhere else, the sdk's possession proof goes through the same
// floor, and the identity key's universal signature is refused (ADR 0008) — which is what a
// consumer of 0.6.x would have got wrong.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/possession"
)

func main() {
	seed := bytes.Repeat([]byte{0x11}, 32)
	pub := crypto.PublicKeyFromSeed(seed)
	fmt.Println("key:", keytext.EncodeKey(pub))

	sig, err := crypto.SignInDomain(seed, "archon/test/v1", []byte("hello"))
	if err != nil {
		panic(err)
	}
	inDomain := crypto.VerifyInDomain(pub, "archon/test/v1", []byte("hello"), sig)
	otherDomain := crypto.VerifyInDomain(pub, "archon/test/v2", []byte("hello"), sig)
	asRaw := crypto.Verify(pub, []byte("hello"), sig)
	fmt.Printf("genuine: in v1=%v in v2=%v raw=%v\n", inDomain, otherDomain, asRaw)

	// The profile assertions use inputs EVERY library accepted before ADR 0008 — the identity
	// as R, and a mixed-order key with a challenge divisible by 8 (oracle cases
	// profile-identity-R and profile-mixed-order-A-k-divisible) — so that only archon's own
	// check can be what refuses them. An input a language's library already refuses on its
	// own (the identity as a KEY, for noble and Bouncy Castle) would pass whether or not
	// the published package enforces anything; the peer lane found its first Java consumer
	// green against a deliberately broken core for exactly that reason.
	identityR := refused(pub, "68656c6c6f",
		"0100000000000000000000000000000000000000000000000000000000000000"+
			"04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07")
	mixedKey, _ := hex.DecodeString("05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4")
	mixedA := refused(mixedKey, "6d697865642d6f72646572233133",
		"b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"+
			"20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b")
	fmt.Printf("profile: identity R refused=%v, mixed-order key refused=%v\n", identityR, mixedA)

	nonce := bytes.Repeat([]byte{0x42}, 32)
	proof, err := possession.Prove(seed, "example/pop/v1", nonce, []byte("binding"))
	if err != nil {
		panic(err)
	}
	pop := possession.Verify(pub, "example/pop/v1", nonce, []byte("binding"), proof)
	fmt.Printf("possession: %v\n", pop)

	if !(inDomain && !otherDomain && !asRaw && identityR && mixedA && pop) {
		fmt.Println("FAIL: the published Go modules do not behave as the release claims")
		os.Exit(1)
	}
	fmt.Println("OK: archon core/go + sdk/go from the public proxy")
}

// refused reports whether the published floor refuses (pubkey, message, sig) — a case an
// unprofiled verifier accepts.
func refused(pubkey []byte, messageHex, sigHex string) bool {
	message, _ := hex.DecodeString(messageHex)
	sig, _ := hex.DecodeString(sigHex)
	return !crypto.Verify(pubkey, message, sig)
}
