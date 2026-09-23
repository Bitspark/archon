module github.com/Bitspark/archon/server/go

go 1.25

// Two dependencies, both this repository's own, and nothing outside the module graph: the
// handler is stdlib net/http, and it consumes the login scheme rather than reimplementing
// any of it (ADR 0007 §B: "It depends on the sdk and the floor and on nothing else").
//
// Local builds resolve both through the repository's go.work; `go get` resolves them from
// GitHub at these versions.
require (
	github.com/Bitspark/archon/core/go v0.8.1
	github.com/Bitspark/archon/sdk/go v0.8.1
)
