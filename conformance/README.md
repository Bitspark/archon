# conformance

Eight implementations of the same encodings are eight chances to disagree. This directory
is what stops that.

```
node conformance/check.mjs
```

builds the Go, Rust and TypeScript cores' conformance CLIs, drives each as a black box over
[`../vectors/identity.json`](../vectors/identity.json), and asserts every emitted result
against the oracle carried in the vector itself. Every core is checked against the
standard — and therefore against every other core.

That is the whole setup. A fresh clone needs a Rust toolchain, Go 1.26 and Node 22 on
PATH; `npm ci` for the TypeScript core runs itself if `node_modules` is missing, and the
command works from any directory (paths derive from the script's own location, not from
cwd). The same command is what [CI](../.github/workflows/conformance.yml) runs on every
push and pull request — there is no second, blessed invocation that only the robot knows.

## Every other language

`check.mjs` needs only those three toolchains on purpose, so a contributor without the
others can still run the one command. Every further core is driven through the same
`harness.mjs` over the same vectors by a check of its own, and CI runs each as its own job:

| language | check | needs |
|---|---|---|
| Python | `check-py.mjs` (core), `check-py-sdk.mjs` (sdk); then `check-py-package.mjs` and `check-py-sdk-package.mjs` consume the built wheel from a clean venv | Python 3 |
| Java | `check-java.mjs`, `check-java-sdk.mjs`; then `check-java-package.mjs` and `check-java-sdk-package.mjs` build a consumer against the installed jar | a JDK and Maven |
| C++, Swift, Haskell | built by CI's `cpp`, `swift` and `haskell` jobs, then `node conformance/harness.mjs vectors <the built CLI>` | OpenSSL ≥ 3.2 and libsodium ≥ 1.0.21 — [why both](../docs/languages.md) |

Agreement is transitive through the oracle, not pairwise: every core is asserted against the
same fixed vectors, so two cores that each agree with the oracle agree with each other.

Two checks have no oracle at all, because the finding is the disagreement itself:

- `check-differential.mjs` — [ADR 0008](../docs/architecture/decisions/0008-the-ed25519-verification-profile.md)'s
  differential: fresh members of every verification-profile class through Go, Rust and
  TypeScript (or the CLIs you name), failing on any case two cores answer differently. Run
  it after `check.mjs`; it reuses the binaries.
- `profile-cases.mjs` — generates those classes: `emit` is the source of the `profile-*`
  cases in the oracle, `measure` prints what each core accepts, `differential` drives the
  run above.

One checks a release rather than a commit: `verify-source.mjs` consumes a public tag the
way a stranger would, for the three languages that have no registry (C++, Swift, Haskell).

## The protocol

`conformance v1`, inherited from thesmos ADR 0006. A CLI is invoked as
`<cli> <family>`, receives the **whole** oracle document on stdin, selects its family's
cases, recomputes each result from the case **inputs** (ignoring the expected value), and
writes one NDJSON line per case to stdout **in input order**.

| family | in | out |
|---|---|---|
| `pubkey_from_seed` | `{name, seed}` | `{"name","pubkey":"<64-hex>"}` |
| `key_encode` | `{name, pubkey}` | `{"name","text":"<key text>"}` |
| `keycodec` | `{name, kind, key or pem}` | `{"name","result":{"ok":"…"} or {"error":true}}` |
| `signature_verify` | `{name, pubkey, message, sig}` | `{"name","valid":<bool>}` |

The harness compares as **canonical JSON** (keys sorted recursively), so a core's key
order can never be the thing that passes or fails. It also asserts each case's `name`
positionally, so a drop-plus-duplicate — which preserves the count — cannot slip past.

## Files

| | |
|---|---|
| `check.mjs` | build Go, Rust and TypeScript, then run the harness. The one command. |
| `check-py*.mjs`, `check-java*.mjs` | the Python and Java cores and sdks, then their packages ([above](#every-other-language)) |
| `check-differential.mjs`, `profile-cases.mjs` | the oracle-free verification-profile checks |
| `verify-source.mjs` | a public tag, consumed from outside |
| `consumers/` | the outside-consumer programs the release workflow, the Java package checks and `verify-source.mjs` run |
| `harness.mjs` | the driver. Knows nothing about any core's language or internals. |
| `spawn.mjs` | shell-free, cross-platform process invocation. Copied verbatim from thesmos — pure plumbing. |

The CLIs themselves live with their cores: `core/rs/src/bin/conformance.rs` (behind the
`conformance-cli` feature, so the published library keeps exactly one dependency),
`core/go/cmd/conformance`, `core/ts/conformance/cli.ts`.

## Adding a case

Add it to `vectors/identity.json` with the expected value **hand-authored from the RFC**,
not pasted from a core's output. A vector copied out of an implementation pins whatever
that implementation does, including its bugs; a vector derived from the standard pins the
standard. Then run `check.mjs` and the other languages' checks, and watch every core agree —
or find out which one does not.
