# Contributing

archon is small on purpose, and most of what a contributor needs to know is a consequence
of that. Read this page before opening a pull request.

## The one rule that declines the most changes

**archon owns what can be said without the law.** A module belongs here only if it can be
stated entirely in RFC 8032, RFC 5280 and RFC 5958 vocabulary — a seed, a public key, a
signature, an opaque message, a key text, a PEM. If explaining a change needs the words
*admission*, *grant*, *fact*, *receipt*, *epoch* or *root*, it belongs above this layer,
not in it. [ADR 0001](docs/architecture/decisions/0001-archon-scope.md) states the
criterion and works an example where archon argued for taking something and was correctly
refused.

archon also declares **no dependency on any other Bitspark repository**, and a change that
would add one should be suspected of belonging somewhere else. Its runtime dependencies
are `ed25519-dalek` in Rust, nothing at all in Go (the standard library's
`crypto/ed25519`), and `@noble/curves` with `@noble/hashes` in TypeScript. Adding to that
list needs a reason in the pull request.

## Three cores, one meaning

A behavior change exists in **all three languages** — `core/{rs,go,ts}`, and the `sdk`,
`cli` and `server` tiers above them — or it does not land. The cores are held to one
hand-authored oracle in `vectors/`, and the harness recomputes every case rather than
trusting the recorded answer:

```
node conformance/check.mjs
```

That must print agreement across three cores before a change lands, and CI runs it on
every push. A change that makes the cores disagree is not a failing test, it is the bug
the repository exists to prevent.

**Changing a vector is a bigger act than changing code.** `vectors/` is a published
oracle: consumers and other implementations check themselves against it. A new case is
welcome; changing what an existing case *means* needs to be argued in the pull request.

## Writing the encodings, not the curve

Each core binds its language's audited Ed25519 implementation. archon writes only its own
encodings on top — the key text, the codecs, the domain separation. Do not hand-roll curve
arithmetic here; a pull request that does will be declined on that ground alone.

## Landing a change

- `main` takes no direct push. A change is a branch, a pull request, and green checks.
- Go: `go test ./...` in each of `core/go`, `sdk/go`, `cli/go`, `server/go`.
- Rust: `cargo test` in each of `core/rs`, `sdk/rs`, `cli/rs`, `server/rs`.
- TypeScript: `npm test` in each `*/ts`.
- Then `node conformance/check.mjs`, which is the one that decides.
- A vulnerability is reported the way [SECURITY.md](SECURITY.md) says, never in an issue.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the license this repository carries.
