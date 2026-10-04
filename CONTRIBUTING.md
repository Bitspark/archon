# Contributing

archon is small on purpose, and most of what a contributor needs to know is a consequence
of that. Read this page before opening a pull request.

## The one rule that declines the most changes

**archon owns a security contract only if it can state the whole of it.** A contract belongs
to the lowest layer that can state its complete success claim and validity conditions without
interpreting higher-layer concepts, and that layer owns its conformance tests
([ADR 0011](docs/architecture/decisions/0011-transport-integrations-stay-above-archon.md) §1).

- **The core** holds what RFC 8032, RFC 5280 and RFC 5958 vocabulary states: a seed, a public
  key, a signature, an opaque message, a key text, a PEM.
- **Above it**, archon owns a few named protocols whose whole claim it can state: the login
  scheme (ADR 0007), the signing boundary (ADR 0009), and the request and enrollment profiles
  (ADR 0010).
- **Everything else is above this layer.** If explaining a change needs the words *admission*,
  *grant*, *fact*, *receipt*, *epoch* or *root*, it belongs higher. The same goes for a
  transport's own semantics (repositories, refs, SSH sessions, a service's credentials).

Using archon's proofs does not make the protocol around them archon's. That is why ADR 0011
places Git transport authentication with the product that hosts Git.
[ADR 0001](docs/architecture/decisions/0001-archon-scope.md) works an example where archon
argued for taking something and was correctly refused.

archon also declares **no dependency on any other Bitspark repository**, and a change that
would add one should be suspected of belonging somewhere else. Its runtime dependencies,
per language, are listed in full in the [README](README.md#install); adding to that list
needs a reason in the pull request.

## Every core, one meaning

A behavior change exists in **every language that carries the tier it touches** — the
`core` in all eight, and the `sdk`, `cli` and `server` tiers wherever
[docs/languages.md](docs/languages.md) says they exist — or it does not land. The cores are
held to one hand-authored oracle in `vectors/`, and the harness recomputes every case
rather than trusting the recorded answer:

```
node conformance/check.mjs
```

checks Go, Rust and TypeScript with nothing more than their toolchains; each further
language has its own check, listed in [conformance/README.md](conformance/README.md). All
of them must agree before a change lands, and CI runs every one on every push. A change
that makes the cores disagree is not a failing test, it is the bug the repository exists to
prevent.

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
- Then `node conformance/check.mjs`, and the check of every other language your change
  touches ([conformance/README.md](conformance/README.md)) — those decide.
- `node cli/smoke.mjs` if the change touches the command; it also runs the README's
  quickstart as written.
- A vulnerability is reported the way [SECURITY.md](SECURITY.md) says, never in an issue.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the license this repository carries.
