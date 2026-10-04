// An OUTSIDE consumer of archon's SERVER tier from the public Go proxy: the login handler
// (server/go), driven through a whole login in-process — begin, read, answer with the sdk's
// proof, collect — with a law that checks the Admitted it is handed. Run by release.yml for
// every tag whose server/go has Admitted (0.9.0 on, #69), and by hand as
//
//	d=$(mktemp -d) && cp conformance/consumers/go-server/main.go "$d" && cd "$d" && go mod init consumer \
//	  && GOFLAGS= GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOMODCACHE=$(mktemp -d) \
//	     go get github.com/Bitspark/archon/server/go@vX && go mod tidy && go run .
//
// Every @bitspark/archon-server on npm through 0.8.1 was a package.json and nothing else
// (archon#55), and no step noticed because nothing imported it. The Go server tier had the
// same blind spot: no release step depended on github.com/Bitspark/archon/server/go.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	sdklogin "github.com/Bitspark/archon/sdk/go/login"
	"github.com/Bitspark/archon/server/go/login"
)

const (
	audience = "https://service.example/api"
	validFor = 60
)

var scope = []string{"read:projects"}

func main() {
	seed := bytes.Repeat([]byte{0x11}, 32) // P: the person's key
	pub := crypto.PublicKeyFromSeed(seed)
	kSeed := bytes.Repeat([]byte{0x22}, 32) // K: the key-less client's key
	browser := crypto.PublicKeyFromSeed(kSeed)

	// The law sees exactly what the proof covered, or the login is refused.
	lawSaw := false
	h, err := login.New(login.Config{
		Audience: audience,
		Admit: func(b, principal []byte, _ json.RawMessage, req login.Admitted) error {
			lawSaw = bytes.Equal(b, browser) && bytes.Equal(principal, pub) &&
				len(req.ID) > 0 && len(req.Scope) == 1 && req.Scope[0] == scope[0] && req.ValidFor == validFor
			if !lawSaw {
				return errors.New("the law was handed something other than what the proof covered")
			}
			return nil
		},
	})
	if err != nil {
		fail("login.New: %v", err)
	}

	// The handler is mounted at <audience>/login; these paths are relative to that mount.
	call := func(method, path string, body any, header map[string]string) (int, []byte) {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		r := httptest.NewRequest(method, path, rdr)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}

	beginStatus, beginBody := call(http.MethodPost, "/", map[string]any{
		"browser": keytext.EncodeKey(browser), "scope": scope, "valid_for": validFor,
	}, nil)
	var begun struct{ ID, Nonce string }
	_ = json.Unmarshal(beginBody, &begun)

	readStatus, readBody := call(http.MethodGet, "/"+begun.ID, nil, nil)
	var shown struct {
		Scope    []string `json:"scope"`
		ValidFor uint32   `json:"valid_for"`
	}
	_ = json.Unmarshal(readBody, &shown)

	req := &sdklogin.Request{ID: unhex(begun.ID), Nonce: unhex(begun.Nonce), Browser: browser, Scope: shown.Scope, ValidFor: shown.ValidFor}
	proof, err := sdklogin.Prove(seed, audience, req)
	if err != nil {
		fail("sdk login.Prove: %v", err)
	}
	answerStatus, _ := call(http.MethodPost, "/"+begun.ID+"/answer", map[string]any{
		"principal": keytext.EncodeKey(pub), "possession": hex.EncodeToString(proof),
	}, nil)

	collectProof, err := sdklogin.ProveCollect(kSeed, audience, req)
	if err != nil {
		fail("sdk login.ProveCollect: %v", err)
	}
	collectStatus, collectBody := call(http.MethodGet, "/"+begun.ID+"/answer", nil,
		map[string]string{login.CollectHeader: hex.EncodeToString(collectProof)})
	var answer struct{ Principal, Possession string }
	_ = json.Unmarshal(collectBody, &answer)

	verified := answer.Principal == keytext.EncodeKey(pub) && sdklogin.Verify(pub, audience, req, unhex(answer.Possession))
	fmt.Printf("server: begin %d, read %d, answer %d, collect %d; law saw the request=%v; login verified=%v\n",
		beginStatus, readStatus, answerStatus, collectStatus, lawSaw, verified)

	if !(beginStatus == 201 && readStatus == 200 && answerStatus == 204 && collectStatus == 200 && lawSaw && verified) {
		fail("the published server/go does not behave as the release claims")
	}
	fmt.Println("OK: github.com/Bitspark/archon/server/go from proxy.golang.org")
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}
