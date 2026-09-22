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
| `sdk` | signed envelopes, proof of possession ([`vectors/sdk.json`](../vectors/sdk.json)), and the login scheme's proofs and audience binding ([`vectors/login.json`](../vectors/login.json)) |

An sdk tick below names what that sdk carries when it is not all of it. Go, Rust and
TypeScript carry both oracles; an sdk marked *possession + envelope* conforms to `sdk.json`
and does not implement the login scheme at all — which is a different claim from
implementing it badly.
| `cli` | the `archon` command |
| `server` | the login endpoint |

## Current state — 0.7.0

| Language | core | sdk | cli | server | Coordinates | Conforming | Published |
|---|---|---|---|---|---|---|---|
| **Go** | ✅ | ✅ | ✅ | ✅ | `github.com/Bitspark/archon/{core,sdk,cli,server}/go` | 105/105 | ✅ proxy + checksum db — **0.7.0**, and automatically (see below) |
| **Rust** | ✅ | ✅ | ✅ | ✅ | `bitspark-archon-{core,sdk,cli,server}` | 105/105 | ✅ crates.io — **0.7.0** |
| **TypeScript** | ✅ | ✅ | ✅ | ✅ | `@bitspark/archon{,-sdk,-cli,-server}` | 105/105 | ✅ npmjs, with provenance — **0.7.0** |
| **Python** | ✅ | ✅ possession + envelope | — | — | `bitspark-archon-{core,sdk}` (import `archon_{core,sdk}`) | 105/105; sdk 38/38 | ✅ PyPI — core **0.7.0**, wheel + sdist · sdk ⏳ from the next release, once its own pending publisher is registered |
| **Java** | ✅ | — | — | — | `dev.bitspark:archon-core` | 105/105 | ✅ Maven Central — **0.7.0**, signed |
| **C++** | ✅ | — | — | — | CMake package (`archon::core`) | 105/105 | ⏳ consumed from the tag — awaits a `verify-source` run (see below) |
| **Swift** | ✅ | — | — | — | SwiftPM product `ArchonCore` (git URL + tag) | 105/105 | ⏳ consumed from the tag — awaits a `verify-source` run |
| **Haskell** | ✅ | — | — | — | `bitspark-archon-core` (module `Archon.Core`), Cabal via Git | 105/105 | ⏳ consumed from the tag — awaits a `verify-source` run |

A published version is a version that was published — which is not the same as a version that
was tagged. **Snapshot taken 2026-09-22 11:20Z**, and dated because an earlier version of
this table went stale within the hour: it is a fact about the world, not about this
repository, so re-measure rather than trust it.

**0.7.0 is on every armed registry**, each verified by an outside consumer that installed it
from the public registry with no source tree reachable:

| registry | has | proof |
|---|---|---|
| Go proxy + `sum.golang.org` | **v0.7.0** (`@latest`) | the Go consumer, run 35682432520 |
| npm | **0.7.0** (`latest`), all four packages | the npm consumer, same run |
| crates.io | **0.7.0**, all four crates | the crates.io consumer, same run |
| Maven Central | **0.7.0**, signed | the Central consumer, same run — resolved jar byte-identical to what Central serves |
| PyPI | **0.7.0**, wheel + sdist | the Python round trip, same run |

To re-measure, ask each registry rather than reading the tag list:

```sh
curl -s https://registry.npmjs.org/@bitspark/archon | jq '.["dist-tags"], (.versions|keys)'
curl -s https://crates.io/api/v1/crates/bitspark-archon-core/versions | jq '[.versions[].num]'
curl -s https://proxy.golang.org/github.com/!bitspark/archon/core/go/@latest
curl -so /dev/null -w '%{http_code}\n' https://repo.maven.apache.org/maven2/dev/bitspark/archon-core/0.7.0/archon-core-0.7.0.pom
```

**Go is the asymmetry to keep in mind:** nobody publishes it, and nothing gates it. Pushing a
tag to a public repo is enough for the proxy to serve that version and for `sum.golang.org`
to pin its hash forever, which is why a tag can never be re-cut once it exists.

**C++ has no registry, so its proof is a different shape.** The CMake package is consumed
from the immutable public tag, which means there is no "install it and run it" to perform
against a registry. The equivalent is
[`verify-source`](../.github/workflows/verify-source.yml): dispatch it with a tag and it
clones the **public** repository at that tag, asserts the clone's HEAD against the SHA the
remote serves, builds `core/cpp`, runs the tag's own oracle over the tag's own vectors,
installs the exported package, and builds the tag's consumer against that installation.
Nothing from the workspace participates — a build that succeeded because a checkout happened
to be lying in the working directory would prove something about the runner, not the tag.

C++ counts as published when that run is green. It cannot run yet: the C++ core landed
**after** `v0.7.0` was cut, so no existing tag contains it, and the workflow says so rather
than failing obscurely. The next tag is the one that can answer.

**Maven Central is the other one.** It accepts and validates in seconds and serves much
later — **44 minutes** for archon-core 0.7.0, validated 15:15:38Z and served 15:59:40Z, past
the ~37 minutes a publish job could ever wait — so a green publish run proves the upload,
not the availability. Java counts as published when a consumer resolves it from the public
repository — which happens in a **later** run, not the one that published it. Either a
`verify_only` dispatch, or a re-dispatch: the publish step skips a version Central already
serves and records that it did, and the consumer runs on that signal, because an artifact
already being served has no propagation left to wait for. 0.7.0 was verified the second way.

0.7.0 is the next release for the other registries, and it carries Java — but only because
the release workflow checks out **two trees**, which is worth understanding before changing
anything there.

A release checks out its own tag, so anything read from that tree is whatever existed when
the tag was cut. `v0.7.0` is `9ce7589`: it contains `core/java` at 0.7.0 with the profile, so
the Java artifact can be *built and published* from it — but it contains no
`conformance/consumers/` at all, because those were added afterwards. A consumer step reading
its program from the tag's tree would therefore fail on `v0.7.0` *after* the registries had
been written to.

So the workflow takes a second, sparse checkout of the ref the **workflow file itself** came
from, into `tooling/`, and the consumer steps read their programs from there. The split is
the point: **the product is the tag's, the tooling is the workflow's.** What gets published
is the exact tagged source; what checks it is the current program.

Re-cutting the tag was never an option. `core/go/v0.7.0` is already pinned in
`sum.golang.org` — and on that note, see the Go row above. C++ is the row
to read carefully: its signing is correct — OpenSSL ≥ 3.2 reproduces every `domain_sign`
vector byte for byte — and it fails only on acceptance. `EVP_PKEY_public_check` validates
nothing for Ed25519, and OpenSSL exposes no scalar multiplication for the curve, so the
profile predicate cannot be written against its public API at all. That is a packaging
question, not a coding one, and [ADR 0008 §8](architecture/decisions/0008-the-ed25519-verification-profile.md)
is where it is owed an answer.

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

The Python sdk has the same three, one layer up: `sdk/py/test` (16 tests),
`conformance/check-py-sdk.mjs` against `vectors/sdk.json`, and
`conformance/check-py-sdk-package.mjs`, which installs the sdk wheel on the floor's wheel from
the same tree and asserts two things only an install can show — that the sdk names its floor
by a registry range equal to its own version, and that an envelope genuinely sealed in
another domain is refused. The unit tests carry two refusals the oracle cannot: `sdk.json`'s
`nonce-15-rejected` and `binding-empty-rejected` **verify** cases hold signatures that are
not genuine over their own layout, so they come out `false` whether or not an sdk checks the
shape at all. Measured: with both refusals deleted, all 12 `possession_verify` cases still
pass, and only the unit tests go red.

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

**One library is not enough, and C++ is the proof.** OpenSSL ≥ 3.2 signs correctly — the C++
core reproduces every `domain_sign` vector byte for byte — and on its own failed 22 acceptance
cases, because `EVP_PKEY_public_check` validates nothing for Ed25519 and OpenSSL exposes no
scalar multiplication for the curve, so the profile predicate cannot be written against its
public API at all. Swift and Haskell reach the same wall for the same reason: signing and
accepting are separate problems, and binding a signer solves only the first.

C++, Swift and Haskell now bind both, and each passes 105/105 plus a clean three-seed differential against Go and TypeScript. Swift and Haskell share one C shim — only the calls into the two libraries, since OpenSSL's `OSSL_PARAM_construct_*` return structs by value, which Haskell's FFI cannot express — and CI asserts the two copies are byte-identical. The second library is where the profile lives:

libsodium's `crypto_core_ed25519_is_valid_point` is the profile predicate almost exactly —
on the curve, canonical, on the main subgroup, not small order. Measured against the oracle's
own vectors, it accepts an honest key and refuses the identity, the mixed-order key and a
small-order `R`. **Require libsodium ≥ 1.0.21.** In 1.0.20 and earlier that function
*accepted some points in mixed-order subgroups*. Measured against the oracle's four
mixed-order public keys, 1.0.20 refuses the 8L and 4L ones and **accepts
`profile-mixed-order-A-torsion-2-k-divisible`**, a point of order 2L. A core built against
1.0.20 compiles, signs correctly, passes 104 of 105 cases, and ships the defect the profile
exists to forbid.

Note what does *not* catch it. The outside consumers all assert the same pair
(`profile-mixed-order-A-k-divisible` and `profile-identity-R`), chosen because every
implementation measured before ADR 0008 accepted both — but that mixed-order key has order 8L,
and 1.0.20 refuses it. So a consumer would pass against a 1.0.20 build. The oracle's torsion-2
case catches it, and so do the floors below; the consumers do not, and are not meant to.

The floor has to be asserted **twice**, and the second time is the one that is easy to miss:

- **when building** — CMake's `pkg_check_modules`, Cabal's `pkgconfig-depends`, and for Swift
  (whose system-library targets cannot express a version) an `#error` in the shim. Measured
  from the release tarballs: 1.0.20 is library version 26.2, 1.0.21 is 26.3.
- **when running** — 1.0.20 and 1.0.22 share the soname `libsodium.so.26`, so a binary built
  against 1.0.22 will load 1.0.20 without complaint if that is what the library path offers.
  Demonstrated, not supposed: the same binary reports the floor met with 1.0.22 loaded, and
  refuses to derive a key or sign with 1.0.20 on `LD_LIBRARY_PATH`. So the shim checks
  `sodium_library_version_minor()` against what was actually loaded, and a process below the
  floor signs nothing and accepts nothing.

Distribution packages do not help: **Ubuntu 26.04's own `libsodium-dev` is 1.0.18.** Every CI
job here builds libsodium from its release tarball.

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
