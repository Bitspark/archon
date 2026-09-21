# 0008 — the Ed25519 verification profile

**Status:** **ACCEPTED** (2026-09-21) · **Type:** contract
**Amends [0003](0003-the-floor-grows-typed-spellings-and-domain-signing.md)** — the wording
of the separation property, and the rationale 0003 owed RFC 8032 §8.5. Ruled by the operator
on 2026-09-21 on external advice taken in the form of
[0001](0001-archon-scope.md)'s consultation (`research-docs/0002-*`, internal), after the
advice's central claim was reproduced through this repository's own harness.

## Context

archon's entire claim is that its cores agree: *are these bytes that key* and *is this
signature that key's* answer the same in every language, because a consumer's two ends may
be in different languages, and a disagreement between cores **is** the defect. That claim
was held by an oracle of 60 cases, and 0001's advice had asked for one more thing that was
never written — an explicit **verification profile**: exactly which public keys, which `R`
values, which scalars and which equation a core accepts, on the grounds that RFC 8032
"permits more than one verification equation" and the accepted set is "not completely
pinned by merely saying RFC 8032."

It is not. RFC 8032 §5.1.7 allows the cofactored check `[8][S]B = [8]R + [8][k]A` or the
uncofactored `[S]B = R + [k]A`; it says nothing about admitting the identity or a
small-order point as a public key, nothing about a mixed-order key, and its canonical-
encoding rule (§5.1.3) is one that ZIP-215 decoders — most of the ecosystem — relax on
purpose. Every library resolves these differently, and every core inherits its library's
resolution.

### What was measured

Take `A` = the identity point (`01 00×31`), `R` = the base point `B` (`58 66×31`), `S` = 1.
Under the uncofactored equation `[S]B = R + [k]A` this is `B = B + [k]O = B`, true for
**every** challenge `k`, hence for every message and every context. Through the real
conformance harness at `957bfb9`:

| core | library | raw `verify` | in `archon/test/v1` | in `archon/test/v2` |
|---|---|---|---|---|
| Go | `crypto/ed25519` (stdlib) | **true** | **true** | **true** |
| Rust | `ed25519-dalek` 3, `verify` | **true** | **true** | **true** |
| TypeScript | `@noble/curves` 2.4, `zip215: false` | false | false | false |
| Python | PyCryptodome + an explicit `[8]A` check | false | false | false |

Two cores admit a key whose every signature is valid everywhere. For that key, 0003's
"a signature made in one domain verifies in no other … cryptographically, whatever the
bytes" is simply false in Go and Rust: the same 64 bytes verify raw, in `v1` and in `v2`.

Widened to the classes the profile below names — 36 generated cases,
[`conformance/profile-cases.mjs`](../../../conformance/profile-cases.mjs), each carrying a
signature that some conforming verifier accepts — the four cores turned out to have
**three different accepted sets**:

| class | Go, Rust (uncofactored) | TS (cofactored, small-order `A` refused) | Python (`[8]A` refused) |
|---|---|---|---|
| identity or small-order `A`, `8 \| k` | accept | reject | reject |
| non-canonical spelling of a small-order `A` | accept | reject | reject |
| mixed-order `A` = `A_good + T8`, `8 \| k` | **accept** | **accept** | **accept** |
| mixed-order `A`, `8 ∤ k` | reject | accept | accept |
| `R` = identity, `S = k·a` | **accept** | **accept** | **accept** |
| `R` = a small-order point, `S = k·a` | reject | accept | accept |
| non-canonical `R`; `S = L`; `S = L − 1` | reject | reject | reject |

Eighteen of the 36 split the cores. Six were accepted by **all four** — a mixed-order key
with a divisible challenge, for each order of torsion component, and the identity as `R` —
and are the cases this decision turns into rejections: a policy change, not a bug fix, and
recorded as one.

Three further facts fix the framing:

- **Across the ecosystem the identity key is an even split, and the split is a choice.**
  The peer lane measured Java (Bouncy Castle 1.80) rejecting it natively and C++ (OpenSSL
  3.2.4) accepting it natively. By library *default*, four of six accept — Go, dalek,
  OpenSSL, PyCryptodome, and @noble too unless `zip215: false` is passed; Bouncy Castle
  alone refuses unasked. "Reject" is not the norm archon is restoring. It is the profile
  archon is choosing, and it must be argued as one.
- **The oracle could not have found any of this.** Its `signature_verify` family took only
  cases "all three demonstrably accept/reject identically" — an oracle admitted on
  agreement is an oracle that cannot contain a disagreement. Its two small-order cases pass
  everywhere because those particular equations fail, not because any core refuses the
  class. And issue #106, which set `zip215: false` in the TS core to "restore tri-core
  parity" on the stated ground that Go and dalek reject small-order keys, rested on a false
  premise: they do not. #106 flipped the split; it did not close it.
- **The oracle's independent authority is one of the accepting implementations.** The
  domain families' signatures were derived with OpenSSL 3.2.4, chosen deliberately as an
  implementation outside every core so that a vector would pin the standard rather than a
  core's bugs. That was independence on the *signing* side. No vector ever asked OpenSSL an
  acceptance question, and it holds no opinion on one — it admits the identity key.

## Decision

### 1. The accepted set

A core's `verify(pubkey, message, signature)` and `verify_in_domain(pubkey, domain,
message, signature)` return `true` exactly when all of the following hold. Nothing else is
consulted; a failure of any line is `false`, never an error.

1. **Shape.** `pubkey` is exactly 32 bytes; `signature` is exactly 64, split as
   `R ‖ S` (32 ‖ 32); each 32-byte field is little-endian.
2. **The public key `A` is a canonical encoding of a point of order exactly L.** That is:
   the 32 bytes decode to a point on the curve; the decoded point **re-encodes to the same
   32 bytes** (so `y ≥ p` and `x = 0` with the sign bit set are refused, per RFC 8032
   §5.1.3, however leniently the library decodes); the point is **not the identity**; and
   `[L]A = O` — the point lies in the prime-order subgroup. A small-order point fails the
   last line; so does a **mixed-order** point, which no small-order check catches.
3. **`R` satisfies the same condition as `A`**, verbatim. The identity as `R` is refused,
   not left to the equation: refusing is implementable in every language, forcing a
   library to accept is not, and the same asymmetry rules every line above.
4. **`0 ≤ S < L`**, read from the encoding as-is. An out-of-range `S` is refused; it is
   never reduced.
5. **The equation** `[S]B = R + [k]A`, with `k = SHA-512(dom2 ‖ R ‖ A ‖ PH(M)) mod L`,
   where for raw signing `dom2` is empty and `PH(M) = M`, and for domain signing `dom2 =
   "SigEd25519 no Ed25519 collisions" ‖ 0x01 ‖ len(domain) ‖ domain` and `PH(M) =
   SHA-512(M)` (Ed25519ph, RFC 8032 §5.1 with the domain as context). **Inside lines 2–4
   the cofactored and the uncofactored forms of this equation accept the same signatures**
   — that is the reason for lines 2–4 — so a core uses whichever its library implements and
   need not know which that is.
6. **Batch verification changes nothing.** A signature accepted in a batch is one accepted
   alone by lines 1–5, and vice versa.
7. **Signing output is the deterministic RFC 8032 §5.1.6 bytes**, pinned by `domain_sign`
   and by every sdk and login vector. A binding whose signer randomises `R` (CryptoKit
   documents that it does) cannot be a core's signer, whatever its verifier does.

### 2. The domain is text

The domain of `sign_in_domain` / `verify_in_domain` is a **string of Unicode scalar
values**; its **UTF-8 encoding** is the RFC 8032 context. The bound **1 ≤ bytes ≤ 255 counts
bytes, not characters** (128 × `ф` is refused). No normalisation of any kind is applied. An
embedded `U+0000` is an ordinary byte of the context, not a terminator. A host-language
string that is not a sequence of scalar values — a Go `string` holding invalid UTF-8, a
JavaScript string holding a lone surrogate — is **refused**, never substituted or truncated:
Go checks `utf8.ValidString`, TS checks well-formedness before `TextEncoder` can replace
anything with U+FFFD, Rust's `&str` and Python's `str.encode` cannot produce the wrong
bytes. The multibyte, NUL and 255/256-byte cases in `domain_sign` / `domain_verify` pin
this; the signatures were derived with OpenSSL 3.2.4 via `hexcontext-string`.

### 3. Checked in the core, explicitly, before the equation

Each core applies lines 1–4 **itself**, ahead of calling its library, whether or not the
library would have applied some of them. The accepted set is archon's, stated here; the
library's defaults are an implementation detail that may change under it. Concretely:

| core | canonicality and subgroup, how | dependency |
|---|---|---|
| Go | `filippo.io/edwards25519`: `SetBytes`, re-encode and compare, `[L−1]P + P = O` | **new** — see §5 |
| Rust | `VerifyingKey::to_edwards()`: `compress()` and compare, `is_torsion_free()` | none new |
| TypeScript | `Point.fromBytes(bytes, false)`, `!is0()`, `isTorsionFree()` | none new |
| Python | `ECC.import_key`, `export_key(format="raw")` and compare, `[L]P` is `(0, 1)` — both coordinates, because the library's own infinity test is `x == 0` (see Consequences) | none new |
| Java | Bouncy Castle's `Ed25519.validatePublicKeyFull`, measured to be exactly lines 2–3, called on `A` and on `R` — `Ed25519Signer` alone applies only the *partial* validator to `A` and nothing to `R` | none new |

Point arithmetic remains the library's in every lane. archon writes a **check**, never a
curve operation, and never anything on the secret path — 0001 Finding 5 holds.

### 4. The oracle admits rejections on adversarial value, not on agreement

A case enters `signature_verify` or `domain_verify` because some RFC 8032 verifier would
accept it and the profile does not, or the reverse. Where the standard leaves acceptance
open, the expected value is **this profile's, by definition**, and the cores are brought to
it. The `profile-*` cases are generated from the classes of §1 by
`conformance/profile-cases.mjs` so that they can be re-derived, and every class carries at
least one instance that was accepted by some core before this decision — a rejection that
nothing ever accepted pins nothing. The oracle grew from 60 to 105 cases; 420 case-checks
across four cores agree; stubbing out one core's profile check fails exactly that core's
former acceptances and nothing else.

### 5. Go takes one dependency, for validation only

`core/go` had no dependencies, and said so. Lines 2–3 need `[L]P`, and the standard
library exposes no point. The choices were a blocklist of the small-order encodings —
no dependency, and **incomplete**, because a blocklist cannot see a mixed-order point,
which is precisely the class on which the cofactored and uncofactored cores disagreed — or
`filippo.io/edwards25519`, the published form of the very implementation `crypto/ed25519`
is maintained from, by the standard library's own maintainer. The dependency is taken. It
is used in one file, `crypto/profile.go`, on public inputs only, and README's "none" becomes
"one, for point validation". The cost is real and is stated rather than hidden.

### 6. 0003 is amended, not superseded

- The property reads: *a signature made in one domain verifies in no other and never as a
  raw signature, and a raw signature verifies in no domain — **for every key this profile
  admits, by the construction and not by any encoding convention**.* The old clause,
  "cryptographically, whatever the bytes", promised something no verifier can promise about
  an arbitrary 32-byte value; the guarantee is computational, under lines 1–4.
- The construction stays **Ed25519ph with the domain as context.** The alternative of
  moving separation into a framing that plain Ed25519 signs was examined and refused: with
  raw `sign` on the same key, an attacker who can obtain a raw signature on chosen bytes
  asks for a raw signature over the frame and holds a domain signature — no prefix,
  version byte or length field changes that. Framing separates framed protocols from each
  other; it cannot separate them from raw signing, which is the one property 0003 exists
  to provide. Ed25519ctx would keep the property but is no better supported where support
  is the problem, and dalek's context API is ph-only.
- **RFC 8032 §8.5's SHOULD NOT is acknowledged and answered.** The prehashed variants are
  discouraged, and prehashing gives up pure EdDSA's collision resilience. archon uses ph
  for its *context*, not its prehash: same-key separation from unrestricted raw signing
  requires a context-bearing variant, the selected implementations provide this one, and
  archon accepts the prehash dependency rather than weaken the separation or write EdDSA
  itself. RFC 2119 permits the exception when its implications are understood; they are
  recorded here.

### 7. "Audited" becomes a backend-admission policy

Of the shipping dependencies only `@noble/curves` has a published third-party audit. The
bar a binding must meet is therefore stated, not implied: the implementation and its
**version and features** are named; it is **not written in this repository**; it is
**credibly maintained** with security-update ownership; its **secret-path provenance** is
stated (the standard library, a 215M-download crate, a published audit — whichever it is);
and it **satisfies this profile through the oracle**, including the `profile-*` classes.
Download counts and an audit of a different release are not substitutes.

### 8. Version and rollout

This ships as **0.7.0**, under [0005](0005-the-layers-version-with-the-floor.md)'s
lockstep, as a **verification-policy correction**: four inputs that every core accepted are
refused from this version, and the accepted set of every `verify` in every layer above —
the sdk's possession and envelope, the login proofs — narrows with it. No honest signer
produces any refused input (RFC 8032 §5.1.6 signing yields a prime-order `R`; a generated
key is prime-order), so no legitimate consumer is affected; the change is nevertheless
observable and is not a patch. A rollback must not restore the former acceptance through a
"legacy" path.

Language reach is staged on it: six complete implementations — Go, Rust, TypeScript,
Python, Java, C++ — each held to the 105 cases, before eight. C++, Swift and Haskell share
one binding problem and therefore one decision: OpenSSL ≥ 3.2 is the **complete
ph-with-context implementation** (via its signature-operation parameters; BoringSSL's public
API is raw Ed25519 only and does not qualify) and it validates nothing, so each of the three
also binds **libsodium ≥ 1.0.21** for lines 2–3 — see Consequences for why the floor is that
version and not "libsodium". They are released when they pass the same oracle and a clean
differential run, never as "the 43 non-domain cases".

## Consequences

- **Verification costs more.** Two subgroup checks per verify, each a scalar
  multiplication, on top of the library's own — the order of the verification itself. The
  floor is not a high-volume verifier; the cost is accepted and should be measured before
  anyone optimises it away.
- **Java and C++ must apply §1 before they are conforming.** Measured on the classes:
  Bouncy Castle's `Ed25519Signer` validates the key with its *partial* validator, which
  refuses the identity, small-order and non-canonical points but admits a mixed-order
  point, and it never examines `R` at all — eight of the 36 cases accepted, all of them
  mixed-order `A` or a small-order `R`. Its `Ed25519.validatePublicKeyFull` is exactly
  lines 2–3 (mixed-order refused), and the Java core calls it on both `A` and `R`. OpenSSL
  does **no** point validation — `EVP_PKEY_public_check` accepts all eight torsion points,
  the identity and the non-canonical spellings — and exposes no public Ed25519 point API,
  so the C++ core needs a second component for lines 2–3 (libsodium's
  `crypto_core_ed25519_is_valid_point`; libsodium cannot do the ph-with-context signing,
  OpenSSL cannot do the validation) — a blocklist does not meet line 2. The C++ core on
  OpenSSL alone measures 83/105: every miss a profile case, both universal cases included.
  Whether a given library's *equation* is cofactored is a separate question from its
  accepted set and is not claimed here for any library that was not measured on it.
- **libsodium is the predicate only from 1.0.21, and the floor is written down because
  nothing but the oracle would notice.** libsodium's own documentation records that in
  versions ≤ 1.0.20 `crypto_core_ed25519_is_valid_point` accepted points of order 2L, 4L
  and 8L — mixed-order points, i.e. `profile-mixed-order-A-k-divisible`, one half of the
  pair every outside consumer asserts *because* every unprofiled implementation accepted
  it. A core built against 1.0.20 would ship the defect this decision exists to forbid
  with a green build and a passing unit suite; only the oracle and the differential run
  would catch it. 1.0.21 (2026-01-06) and 1.0.22 (2026-04-09) satisfy it; msys2 packages
  1.0.22. Every OpenSSL-bound core states `libsodium >= 1.0.21` in its build files and
  asserts it at configure time. This is the backend-admission policy of §7 doing its job:
  "identified version and features", not a library name.
- **The differential run exists, and it found something on its first pass.**
  `profile-cases.mjs differential --seed N --per-class N <cli>…` draws fresh members of
  every class — random torsion component, nonce, message and domain — plus genuine
  signatures, drives them through every core given, and fails on any case two cores
  answer differently or any non-genuine case all of them accept. No oracle; the finding is
  the disagreement. Its first run split Python from the other three on a mixed-order key
  whose torsion component has **order 2**: PyCryptodome's `is_point_at_infinity()` on an
  Edwards curve is `x == 0`, which the order-2 point `(0, −1)` satisfies as well as the
  identity, so `[L]A`, correctly computed as `(0, −1)`, was reported as the identity and the
  key passed the subgroup check. The fixed vectors had drawn only an order-8 component and
  were green in all four cores. The Python core now tests for `(0, 1)`, the oracle pins a
  mixed-order case per torsion order, and `measure` is not the last word on a new binding —
  `differential` is: Java was run against Go and against Go + TypeScript together, eight
  runs and 4,352 cases, zero splits, before being called conforming. What a clean run says
  is bounded, and should be read as bounded: **no split in the classes the generator
  samples.** PyCryptodome's exception was found because a class existed whose members land
  `[L]A` on `(0, −1)`; a library exceptional on a shape no class produces is not found by
  more seeds of the same classes, only by a new class.
- **Not a wire change.** `archon-login/1`, the sdk layouts and every published signature
  are unchanged; only what is *accepted* narrowed, to inputs no signer emits.
- **The key codecs stay byte codecs.** `keytext` and `keycodec` still spell arbitrary 32
  bytes; whether those bytes are a key is this profile's question, answered at `verify`.
