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

	identity, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	universal, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666" +
		"0100000000000000000000000000000000000000000000000000000000000000")
	uRaw := crypto.Verify(identity, []byte("hello"), universal)
	uDomain := crypto.VerifyInDomain(identity, "archon/test/v1", []byte("hello"), universal)
	fmt.Printf("identity key: raw=%v in v1=%v\n", uRaw, uDomain)

	nonce := bytes.Repeat([]byte{0x42}, 32)
	proof, err := possession.Prove(seed, "example/pop/v1", nonce, []byte("binding"))
	if err != nil {
		panic(err)
	}
	pop := possession.Verify(pub, "example/pop/v1", nonce, []byte("binding"), proof)
	fmt.Printf("possession: %v\n", pop)

	if !(inDomain && !otherDomain && !asRaw && !uRaw && !uDomain && pop) {
		fmt.Println("FAIL: the published Go modules do not behave as the release claims")
		os.Exit(1)
	}
	fmt.Println("OK: archon core/go + sdk/go from the public proxy")
}
