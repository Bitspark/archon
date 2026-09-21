module github.com/Bitspark/archon/sdk/go

go 1.25

// The floor. The ONLY dependency. Pinned to the commit that landed ADR-0003 (domain-
// separated signing), which this layer is built on. Local builds resolve it through the
// repository's go.work instead; consumers resolve it from GitHub.
require github.com/Bitspark/archon/core/go v0.5.0
