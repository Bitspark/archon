# 0001 — archon: the identity and crypto layer beneath the law

**Status:** **ACCEPTED, scope narrowed** (2026-08-22) · **Proposed:** 2026-08-21 · **Type:** scope / architecture

> **Status note, 2026-09-09 (the archon maintainers).** The one row this ADR left open — *"the
> Merkle inclusion primitive · UNRESOLVED — decide it separately"* — is **resolved in the
> negative by the operator**: *"the root designation and Merkle format have not been accepted
> into archon"* (`docs/growth-plan.md` §6.3, §10, verbatim). `PLACEHOLDER_ROOT` stays a
> thesmos designation. The refusal this ADR's own criterion already predicted for `merkle`
> is now also the operator's word. Recorded in [0006](0006-the-archon-command-three-binaries-one-command.md);
> the row below is left as written.

> ## ✂ THE SPLIT STANDS — this ADR claimed too much
>
> **The decision holds: thesmos is the law, archon is identity and crypto.** It follows
> from **one-change-authority** — Ed25519, the canonical key spelling and the PEM codec
> need **zero** Bitspark vocabulary (RFC 8032 / 5280 / 5958), so thesmos is not their
> rightful owner by thesmos's own rule. thesmos's repo inventory diagnosed this from the
> inside: the charter names a *domain* (authority), but the repo attracts things for a
> *capability* (tri-core byte-pinning). Identity is the clearest drift.
>
> What this ADR got wrong was **reach**. Four of its claims were measured against the
> constellation and do not hold. Full record:
> `research-docs/0001-identity-floor-seam.md`.
>
> | claim as written | disposition |
> |---|---|
> | Ed25519 primitives, canonical key spellings, PEM key codec | **HOLDS** — 368 vocabulary-free lines (`keytext` 117 + `keycodec` 251), true leaf modules with zero internal imports |
> | — and newly, **proof of possession** | **DROP** — it exists in **kosmos**, as a custody-mode discriminator in the `ClientHello` handshake. Protocol vocabulary, not a primitive. |
> | — and **the principal** | **DROP** — the key *is* the principal by construction. There is rotation; there is no rotation-preserving identity. Nothing distinct to own. |
> | — and **succession** | **DROP** — thesmos **ADR 0023** owns it (epoch-wipe + deny-by-default positive reconstitution), re-ruled independently as **Q17 shape (b)**: *dies-with-the-key, no re-key path, re-genesis on loss.* |
> | the **Merkle inclusion primitive** | **UNRESOLVED** — not settled this round. It is not identity; decide it separately. |
> | `PLACEHOLDER_ROOT` travels with the primitives | **NO** — it is a thesmos tri-core conformance fixture and belongs in thesmos's vectors. |
>
> **Cost, stated honestly:** archon needs its own tri-core conformance harness from zero,
> plus ADR-0005 per-language pins and a skew window while the move lands. That is the real
> work — and it is the debt thesmos's inventory named, paid down rather than deepened.

## Decision

archon is a fresh, standalone, tri-core (`{go,rs,ts}`) library holding the
constellation's **identity floor**: Ed25519 primitives, the canonical key spellings,
the PEM key codec, the Merkle inclusion primitive, and — newly — **proof of
possession**, the **principal**, and **succession**.

It owns *who you provably are*. It owns **nothing** about what you may do: `is_root`,
`signed_fact`, `grant`, `authorized`, `covers_*` remain thesmos's reserved vocabulary,
untouched.

**thesmos depends on archon.** The four primitive modules move out of thesmos and
thesmos re-exports or re-points to them; the `signed_fact` leaf verifier keeps its
meaning and its bytes, and calls archon for the signature check.

## Context — the problem, as thesmos itself states it

Two facts, both already recorded in thesmos, and neither of them an aesthetic judgement.

**1. thesmos knows it is chartered around the wrong axis.** Its `docs/repo-inventory.md`
(#471, 2026-08-20) measures four distinct jobs in a repo chartered for one, and names the
cause: *"thesmos is where the constellation puts anything that must be tri-core byte-pinned
and independently checkable. That is a **capability**. The charter names a **domain**."*
It concludes that the cheapest correction is **not a split but a charter restatement** —
because anything needing the capability will drift in regardless of domain.

That conclusion is right about the *general* case and this ADR does not contest it. But it
proves too much if applied to identity, because identity has a property the other three
jobs lack: **it has consumers who want it and do not want the law.** A charter restatement
leaves those consumers linking the authority contract to call `sign()`.

**2. The consumers are already there, and the coupling is measured.** `stele` imports
thesmos in **24 sites purely for keys and crypto**:

| site | what it takes |
|---|---|
| `stele/app/node/rs/src/main.rs` | `thesmos::crypto::{sign, verify, public_key_from_seed, PUBLIC_KEY_SIZE}`, `thesmos::keycodec::{spki_pem_to_pubkey, pkcs8_pem_to_seed}` — the node's **request path** |
| `stele/app/cli/{go,rs}` | `keycodec` for the local keypair store, `crypto` for derivation |
| `stele/app/node/go/{identity,rootkey}.go` | `keycodec` for the node's own identity + root key |

None of these call sites mentions `is_root`, `grant`, or `authorized`. A node daemon
verifying a read request links the authority contract to do it.

This is not accidental, and it is not stele's error — it is what
thesmos ADR 0013
**decided on purpose**, jointly with stele as the consumer, because there was no better
venue: *"stele asked thesmos to own the `raw-32 ↔ PEM` codec so the three cores agree
byte-for-byte."* ADR 0013 was the right call **given the venues that existed**. archon
changes the set of venues.

**3. Identity's own concepts are homeless.** PoP is named by bitagent-runtime (*"a run-edge
auth plane, PoP-gated admission"*), by kosmos (*"stores only the pubkey +
proof-of-possession"*), and by the accounts posture note (*"aud + subject/actor live at the
mediator/PoP-envelope layer, not the grant"*) — and implemented by none of them. thesmos's
inventory §5 assigns *"principals & identity"* to an **"accounts bridge"** that does not
exist. Three repos each hold half a concept whose other half is nobody's.

**4. stele's own charter already contains the sharpest version of this argument.**
stele ADR 0011 (*"Authorization is engine-reasoned: stele holds no authority logic"*) states
that *"stele has **no authority logic of its own** … substrate services carry **zero
authority code**."* Its node nonetheless links `thesmos::crypto::{sign, verify}` on the
request path. ⚠ **Stated fairly, this is not a breach** — ADR 0011 governs *decision logic*,
not link graphs, and a strict reading does not condemn the import. The argument is weaker
than "stele is violating its own ADR" and stronger than archon's own preference: **the link
graph should not have to be explained away against the posture.** It is also the least
self-serving evidence available, because stele wrote it first and it holds whether or not
archon is founded.

⚠ **Counterweight, recorded because it cuts against this ADR.** stele ADR 0012 shows the
current boundary *working*: it draws the custody line cleanly (*"encryption-at-rest needs
exactly what thesmos refuses to hold … so it lives entirely in stele"*) and concludes **"no
thesmos change is implied."** A venue that produces clean boundary reasoning under pressure
is not obviously broken. This ADR's claim is narrower than "the arrangement has failed" — it
is that the arrangement costs stele a dependency it does not want and leaves identity's own
concepts homeless.

## Why the cut is clean

The four moving modules have **no coupling to the value model or the checker** — verified,
not assumed:

| module | imports |
|---|---|
| `crypto.rs` | `ed25519_dalek` only |
| `keytext.rs` | **nothing** |
| `keycodec.rs` | **nothing** (hand-rolled fixed DER templates, no new deps — ADR 0013) |

Contrast `fact.rs`, which imports `logos_contract` **and** `ontos_core` — that is the
authority preimage and it **stays in thesmos**. The seam falls exactly where the import
graph already put it.

## The extraction criterion [normative]

> ⛔ **SUPERSEDED BY A BETTER-FOUNDED INVARIANT, 2026-08-21** —
> `research-docs/0001` §Applied. The
> two-clause criterion below was derived from a **single refutation** and is *"both too strong
> and too weak"*: too strong because one format can have many independent verifiers (Ed25519
> has no owner), too weak because holding verifier code grants no semantic ownership of the
> protocols that call it.
>
> **The replacement:** *a security-sensitive format and its normative validity relation must
> have ONE CHANGE AUTHORITY — the lowest layer that can define the canonical bytes, validity
> conditions, success claim, and versioning without vocabulary from a higher layer.*
>
> It subsumes this criterion's verdicts (including `merkle`'s refusal, for a deeper reason)
> and answers both cases this ADR flagged as uncertain. **Not yet promoted to normative here** — this
> waited on the operator's Q5, which ⛔ **closed 2026-08-22 (answered in thesmos ADR 0023, `No`);
> archon's scope is the KEY layer.** The block on promotion is now the switch decision, a
> different and still-open question.

A module may be extracted into archon's primitives tier **only if both clauses hold**:

1. **Its format is a published standard or a pure display form** — an RFC, or a spelling that
   never enters signed or hashed bytes. **Not** a format a consumer defined for its own
   verification.
2. **It exports no type that appears in another repo's data shape** — functions over bytes and
   strings only; never a struct or enum that lands in someone else's witness, record, or wire
   type.

| module | format | exported types | verdict |
|---|---|---|---|
| `crypto` | Ed25519 — RFC 8032 | none | ✅ take |
| `keycodec` | PKCS#8 / SPKI — RFC 8410 + 7468 | none | ✅ take |
| `keytext` | `ed25519:<hex>` — coined, pure display, never in signed bytes | none | ✅ take |
| `merkle` | `merkle-inclusion-v1` — **thesmos-defined** verification format | `Side`, `Step` — struct fields of four ACCEPT(D) witness types | ⛔ **refuse** |

Both clauses are load-bearing: clause 2 alone admits a coined-but-typeless format; clause 1
alone admits a standard whose types sit in another repo's records.

⭐ **This criterion is normative here because a dependency measurement is not.** archon
proposed taking `merkle` on the strength of a leaf-set/import-graph measurement and was
refuted by thesmos's maintainers on structure. The criterion is what *predicts* that refusal instead
of arriving after it — **a dependency graph says what a module touches; it does not say what
a module is.** Recorded at thesmos's maintainers's suggestion, whose reason was that a rule left in a
withdrawal message *"is where good arguments go to be forgotten."*

## Consequences

- **Layout `core/{go,rs,ts}`**, two tiers: `primitives` (depends on nothing) and
  `identity` (depends on `ontos` alone, for canonical signing bytes). **archon does not
  depend on logos** — it states no clauses and consumes no checker. That absence is
  load-bearing: it is what lets a node daemon and a custodial lens link archon without
  pulling in the reasoning engine.

  ⛔ **Tier 2 no longer exists.** The narrowing above dropped PoP (kosmos's) and the
  principal (the key *is* the principal), which were tier 2's entire content — so the
  `ontos` edge it would have justified has no bearer. As built, archon is **one tier and
  a pure leaf: zero constellation dependencies**, and `atlas.json` now declares
  `dependsOn: []` rather than an ontos `build` edge the manifests cannot support (the
  schema defines `build` as *verifiable from package.json/go.mod/Cargo.toml*, and nothing
  in archon's three manifests names a Bitspark package). The "does not depend on logos"
  point survives and is strengthened: archon depends on nothing here at all.
- **archon inherits the byte-pinning venue machinery** — a hand-authored oracle, a
  differential CLI conformance harness, ADRs, a freeze gate. The inventory argues this
  overhead is *"rational for a byte-pinning venue and disproportionate for an
  authorisation program of a few thousand lines."* archon is squarely the former, and
  the extraction arrives with **five conformance families already written** — 34 of 429
  cases — so parity is proven on day one rather than rebuilt.
  ⛔ **Four families, 30 cases.** Applying the one-change-authority rule case by case at
  execution moved the line twice against this estimate: `admission_context_signing_bytes`
  (4) is thesmos's, the root-placeholder case (1) pins a designation, and
  `signature_verify` (9) — uncounted here — is archon's. See
  [`vectors/README.md`](../../../vectors/README.md). The claim itself held: parity was
  proven on day one, and [CI](../../../.github/workflows/conformance.yml) re-proves it on
  every push.
- ⛔ **thesmos does NOT shrink toward its charter — this ADR claimed it does and the claim is
  false.** Recomputed: `keycodec` is *inside* the inventory's charter set, so the lift removes
  163 source lines from the **numerator** and 315 from the **denominator**. The charter share
  moves **39.3% → 38.7% — the wrong way.**

  ```
  before  2767/7042 = 39.3%       after  2604/6727 = 38.7%
  ```

  ⇒ **Delete this as an argument.** archon must be justified by *where identity belongs*, not
  by a ratio it makes marginally worse. (Caught by applying thesmos's maintainers's recompute-on-
  resolution rule to this repo's own claims after `merkle` was withdrawn.)
- **ADR 0013 is superseded in venue, not in content.** The four conversions, the fixed
  byte templates (RFC 8410), the PEM framing (RFC 7468), the v1-only decode, and the
  accept/reject contract all move **verbatim**. The bytes do not change, so the existing
  `keycodec` vectors pin the moved code unmodified — which is the migration's proof.
- **Consumers re-point, and most of them get lighter.** stele's 24 sites swap
  `thesmos::crypto` → `archon::crypto`; its node stops linking the authority contract for
  key work entirely.
- **A dependency inversion in thesmos's Job 4 is *not* resolved by this ADR**, and archon
  must not claim otherwise. The signing-byte registry for stele-produced artifacts
  (`freshness-v1`, `admission-receipt-v1`, `active-set-head-v2`, `epoch-fence-v1`) is a
  different tension, tracked in the inventory's §6 row 1.
  ⛔ **archon argued that taking `merkle` would resolve it and was refuted** — the
  producer/verifier dependency there is *deliberate* (stele ADR 0012 / spec A.4.1), and
  relocating the format would make a two-way split three-way. See the extraction plan §9.

## The name

ἄρχων — the **officeholder**. In Athens the archons held the offices and the θεσμοί were
the laws laid down that bound them. **archon is who bears the office; thesmos is the law
that binds it.** The word is authority-adjacent, which is a real collision risk with
thesmos and worth stating plainly — the split that resolves it is *bearer* vs *law*, and
every doc should say which side of that line a concept falls on.

The retired **arche-core** shares the root (ἀρχή) but is not an ancestor: archon is
greenfield, and arche-core's authority half already became thesmos.

## Open questions

1. ~~**Does the principal want to be an ontos value?**~~ **MOOT.** There is no principal
   to encode and no PoP envelope to sign — the narrowing dropped both, and tier 2 with
   them. The question can only return if a tier 2 does.
2. ~~**Does `merkle` belong here or in stele?**~~ **WITHDRAWN**, and the withdrawal is
   recorded above: `merkle` was proposed on a leaf-set/import-graph measurement and refuted
   by thesmos's maintainers on structure. It is not in archon.
3. **Does `keytext` stay v1-only?** archon is the natural venue for a second scheme
   (a non-Ed25519 key). Deferred; the move is verbatim.
