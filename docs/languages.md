# Languages

archon is one floor with several native presentations. A language binding gives consumers the
same seam — the same key bytes, the same canonical text, the same PEM codecs, the same
signatures — in a form that is idiomatic where they already are.

**Three claims are kept separate throughout this page**, because conflating them is how a
packaging scaffold gets described as a working implementation:

| claim | what it means |
|---|---|
| **implemented** | the code exists and does the thing |
| **conforming** | it recomputes all 105 oracle cases and agrees with [`vectors/identity.json`](../vectors/identity.json) — including the 36 [verification-profile](architecture/decisions/0008-the-ed25519-verification-profile.md) classes, which is where library defaults disagree |
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

## Current state — 0.7.0

| Language | core | sdk | cli | server | Coordinates | Conforming | Published |
|---|---|---|---|---|---|---|---|
| **Go** | ✅ | ✅ | ✅ | ✅ | `github.com/Bitspark/archon/{core,sdk,cli,server}/go` | 105/105 | ✅ public proxy + checksum db (0.6.2) |
| **Rust** | ✅ | ✅ | ✅ | ✅ | `bitspark-archon-{core,sdk,cli,server}` | 105/105 | ✅ crates.io (0.6.2) |
| **TypeScript** | ✅ | ✅ | ✅ | ✅ | `@bitspark/archon{,-sdk,-cli,-server}` | 105/105 | ✅ npmjs, with provenance (0.6.2) |
| **Python** | ✅ | — | — | — | `bitspark-archon-core` (import `archon_core`) | 105/105 | ⏳ PyPI, once the pending publisher is registered (see `release.yml`) |
| **Java** | ✅ | — | — | — | `dev.bitspark:archon-core` | 105/105 | ⏳ Maven Central; publishes with 0.7.0 |
| **C++** | 🔧 in review | — | — | — | CMake package | 60/60 on the pre-0008 oracle; the profile classes pending | — |
| **Swift** | — | — | — | — | SwiftPM product (planned) | — | needs a binding to a complete Ed25519ph-with-context implementation (0008 §8) |
| **Haskell** | — | — | — | — | Cabal via Git (planned) | — | needs the same binding (0008 §8) |

A published version is a version that was published: 0.6.2 is on the three registries;
0.7.0, the profile, is the next release, and it is the one that carries Java. The C++ row
says "pre-0008" because a core that agrees with the 60 cases and has not yet been run on the
36 profile classes has not been asked the question that ADR 0008 exists to ask.

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

For Java they are `core/java/src/test`, `conformance/check-java.mjs`, and
`conformance/check-java-package.mjs`. The third resolves `dev.bitspark:archon-core` into a
local repository of its own and builds [`conformance/consumers/java`](../conformance/consumers/java)
against it; the release workflow runs **that same program** against Maven Central, so the
local check and the published check cannot drift. Its assertions were chosen by measurement
rather than by plausibility: with the core's profile predicate disabled, the mixed-order case
fails. The obvious candidate — the identity public key — does **not** fail, because Bouncy
Castle refuses that one itself, so asserting it alone would have proved nothing about archon.

## What adding a language actually costs

Not the signing. Two other things, both learned from Python:

**The domain-separation primitive.** `sign_in_domain` is Ed25519ph with the domain as the
RFC 8032 §5.1 context string. Support is thin, because [RFC 8032 itself says the prehashed
variants "SHOULD NOT be used"](https://datatracker.ietf.org/doc/html/rfc8032) and library
authors follow it. Go's stdlib, `ed25519-dalek` and `@noble/curves` expose it;
`cryptography` does not, which is why the Python core binds **PyCryptodome**.

**Swift and Haskell need a binding for exactly this.** CryptoKit and swift-crypto ship pure
Ed25519 only, as stated policy; crypton/cryptonite hardcode SHA-512 with no context
selection. The prefix goes *inside* both the nonce and challenge hashes, so a stock
`sign(M)` API cannot be wrapped — reaching it means re-entering EdDSA at the curve level,
which [CONTRIBUTING](../CONTRIBUTING.md) forbids. The question of whether to change the
construction instead was put to outside advice and ruled: it stays (ADR 0008 §6 — a framing
cannot separate from raw signing on the same key, and Ed25519ctx is no better supported).
Those two languages bind a **complete Ed25519ph-with-context implementation** — OpenSSL ≥ 3.2
through its signature-operation parameters; BoringSSL's public API is raw Ed25519 only and
does not qualify — and are released when they pass the whole oracle, not a subset of it.
Note also that CryptoKit *randomises* signatures, so it could not be a core's signer even if
it had the context.

**The acceptance profile.** Less obvious and more dangerous. RFC 8032 permits more than one
verification equation, so implementations genuinely disagree about which signatures are
*valid* — and that disagreement is silent until two of them meet.

Python found it first: its first full run was 58/60, PyCryptodome accepting the two
small-order keys the oracle happened to pin. The fix at the time — an explicit `[8]A` check —
was written in the belief that Go and `ed25519-dalek` reject such keys. **They do not.**
Measured through the harness with the identity point as a public key, `R = B`, `S = 1`: Go
and Rust accept that one signature over *every* message and in *every* domain; TypeScript
and Python reject it; Java (Bouncy Castle) rejects it natively; C++ (OpenSSL) accepts it.
Three of six. Widened to the classes that matter — small-order and *mixed-order* keys,
non-canonical spellings, the identity and a small-order point as `R` — the four cores had
three different accepted sets, and four inputs that all of them accepted.

That is now written down. [**ADR 0008**](architecture/decisions/0008-the-ed25519-verification-profile.md)
states the accepted set in prose — `A` and `R` are canonical encodings of points of order
exactly L, `0 ≤ S < L`, the equation decides only inside that, and the domain is UTF-8 text
counted in bytes — and every core checks it *itself*, ahead of its library, so the set is
archon's rather than the binding's. The oracle carries the classes as 36 generated cases
([`conformance/profile-cases.mjs`](../conformance/profile-cases.mjs)), admitted on their
adversarial value rather than on agreement, which is the rule that had kept the oracle blind.
`node conformance/profile-cases.mjs measure "<cli>"` prints what any core accepts across the
classes with no expected value applied — run it on a new binding before anything else.

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
