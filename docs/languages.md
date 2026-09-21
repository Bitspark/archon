# Languages

archon is one floor with several native presentations. A language binding gives consumers the
same seam — the same key bytes, the same canonical text, the same PEM codecs, the same
signatures — in a form that is idiomatic where they already are.

**Three claims are kept separate throughout this page**, because conflating them is how a
packaging scaffold gets described as a working implementation:

| claim | what it means |
|---|---|
| **implemented** | the code exists and does the thing |
| **conforming** | it recomputes all 60 oracle cases and agrees with [`vectors/identity.json`](../vectors/identity.json) |
| **published** | a consumer outside this repository can install it, unauthenticated, and run it |

A binding can be implemented and not conforming, or conforming and not published. None of the
three implies another.

## Components

archon has four tiers. Not every tier needs a package in every language: `core` is the floor
and is portable everywhere, while `server` presumes an HTTP story and `cli` ships a binary.

| tier | what it adds |
|---|---|
| `core` | key bytes, the canonical key text, SPKI/PKCS-8, raw and domain-separated signing |
| `sdk` | signed envelopes, proof of possession, audience binding |
| `cli` | the `archon` command |
| `server` | the login endpoint |

## Current state — 0.6.2

| Language | core | sdk | cli | server | Coordinates | Conforming | Published |
|---|---|---|---|---|---|---|---|
| **Go** | ✅ | ✅ | ✅ | ✅ | `github.com/Bitspark/archon/{core,sdk,cli,server}/go` | 60/60 | ✅ public proxy + checksum db |
| **Rust** | ✅ | ✅ | ✅ | ✅ | `bitspark-archon-{core,sdk,cli,server}` | 60/60 | ✅ crates.io |
| **TypeScript** | ✅ | ✅ | ✅ | ✅ | `@bitspark/archon{,-sdk,-cli,-server}` | 60/60 | ✅ npmjs, with provenance |
| **Python** | ✅ | — | — | — | `bitspark-archon-core` (import `archon_core`) | **60/60** | ⏳ not yet uploaded |
| **Java** | — | — | — | — | `dev.bitspark:archon-core` (planned) | — | — |
| **C++** | — | — | — | — | CMake package (planned) | — | — |
| **Swift** | — | — | — | — | SwiftPM product (planned) | — | **blocked, see below** |
| **Haskell** | — | — | — | — | Cabal via Git (planned) | — | **blocked, see below** |

The registry prefixes differ by ecosystem because the namespaces do. crates.io and PyPI are
flat, so those carry `bitspark-`; npm has scopes, so it carries `@bitspark/`. **The prefix is
a registry name only** — what a consumer *writes* is unprefixed: `use archon_core::`,
`import archon_core`, `import "…/core/go"`.

## Evidence

Every language is checked the same three ways, and the three are not interchangeable.

1. **Unit tests**, in-language, covering the argument-shape failures the oracle cannot express
   — its protocol carries only `ok` / `error`, so a raised exception or a wrong-sized seed has
   nowhere to go.
2. **The oracle**, through the shared harness: the binding recomputes each case from its
   inputs and is asserted against the same fixed vectors as every other. Agreement is
   **transitive through the oracle** — a binding that agrees with the vectors agrees with
   every other binding that does, which is what lets this scale past three implementations
   without pairwise comparison.
3. **An outside consumer**: the built artifact installed into a clean environment with no
   source directory reachable, then run. Passing the oracle proves the *code*; it says nothing
   about whether the *package* is right.

For Python those are `core/py/test` (22 tests), `conformance/check-py.mjs`, and
`conformance/check-py-package.mjs` — the last builds the sdist and wheel, installs the **wheel**
into a fresh venv with `PYTHONPATH` stripped, and runs the conformance protocol again against
the installed package.

## What adding a language actually costs

Not the signing. Two other things, both learned from Python:

**The domain-separation primitive.** `sign_in_domain` is Ed25519ph with the domain as the
RFC 8032 §5.1 context string. Support is thin, because [RFC 8032 itself says the prehashed
variants "SHOULD NOT be used"](https://datatracker.ietf.org/doc/html/rfc8032) and library
authors follow it. Go's stdlib, `ed25519-dalek` and `@noble/curves` expose it;
`cryptography` does not, which is why the Python core binds **PyCryptodome**.

⛔ **Swift and Haskell are blocked on exactly this.** CryptoKit and swift-crypto ship pure
Ed25519 only, as stated policy; crypton/cryptonite hardcode SHA-512 with no context
selection. The prefix goes *inside* both the nonce and challenge hashes, so a stock
`sign(M)` API cannot be wrapped — reaching it means re-entering EdDSA at the curve level,
which [CONTRIBUTING](../CONTRIBUTING.md) forbids. This is an open question, not a to-do.

**The acceptance profile.** Less obvious and more dangerous. RFC 8032 permits more than one
verification equation, so implementations genuinely disagree about which signatures are
*valid* — and that disagreement is silent until two of them meet.

Python's first full run was **58/60**. The misses were `small-order-pubkey-order4` and
`small-order-pubkey-order8`: PyCryptodome accepts small-order public keys; Go and
`ed25519-dalek` reject them. archon had met this before — the TypeScript core settles it with
`@noble`'s `{ zip215: false }`. PyCryptodome has no such flag, so the Python core checks
`[8]A` against the identity explicitly.

⚠ **archon's acceptance profile exists only in the oracle, never in prose.** That was
tolerable at three cores. Each further language arrives with its own library's opinion on
cofactored verification, and the only thing that catches the difference is running the
vectors. See [`research-docs/0002`](https://github.com/Bitspark/archon-internal) (internal)
for the open question.

## Adding one

1. Implement `core` — `crypto`, `hexbytes`, `keytext`, `keycodec`. Bind an existing Ed25519;
   write only archon's own encodings on top.
2. Implement the `conformance v1` CLI: `conformance <family>` reads `vectors/identity.json` on
   stdin, **recomputes** each case from its inputs, writes one NDJSON line per case. A CLI that
   echoes the oracle's `result` agrees by construction and proves nothing.
3. Drive it through `conformance/harness.mjs` against `vectors/identity.json`.
4. Add a CI job of its own. Do **not** add the toolchain to `conformance/check.mjs`: that is
   the tri-core check, and every prerequisite added there is a contributor who can no longer
   run the one command the README advertises.
5. Package it, and prove the package separately from the code.
