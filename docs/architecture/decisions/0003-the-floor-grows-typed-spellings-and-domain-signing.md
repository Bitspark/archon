# 0003 — the floor grows: typed byte spellings and domain-separated signing

**Status:** **ACCEPTED** (2026-09-09) · **Type:** scope
**Supersedes nothing.** The first *addition* to a charter [0001](0001-archon-scope.md) cut by
subtraction. Ruled by the operator on 2026-09-09; the measurement and the reasoning are
`docs/growth-plan.md` §2–§5.

> **Amended 2026-09-21 by [0008](0008-the-ed25519-verification-profile.md).** Decision 2's
> property was stated as holding "cryptographically, whatever the bytes". It does not hold for
> a public key outside 0008's verification profile — for the identity point, one signature
> verifies raw and in every domain, and two cores accepted it — and no verifier can promise
> anything about an arbitrary 32-byte value. The property now reads as struck and replaced
> below: it holds **for every key the profile admits, by the construction**. The construction
> itself — Ed25519ph with the domain as context — is unchanged, the framing alternative was
> examined and refused (0008 §6), and the rationale this decision owed RFC 8032 §8.5's
> SHOULD NOT is recorded there.

## Context

archon was nine functions in three cores, pinned by 30 vectors, and both consumers used
every one of them. What they hand-wrote *around* the calls showed the two gaps:

- **Fixed-size hex decoding** — `hex_to_bytes`, `seed32`, `seed_from_hex`: 46 definitions
  in rs, 25 in go, 57 in ts, across thesmos and stele. Every one a place for a length bug.
- **No domain separation at the signature layer.** Every consumer signs
  `sign(seed, canonical_bytes(value))`. A signature over a thesmos head fails to verify as
  a stele read request only because the two ontos encodings happen to differ — an
  invariant spanning three repos, owned by nobody. The moment one key is used from several
  repositories (the stated plan) it is load-bearing.

## Decision

The floor gains two families, in all three cores, pinned by the oracle:

**1. `hexbytes` — typed, fail-closed spellings.** `to_hex`, `seed_from_hex → [32]`,
`pubkey_from_hex → [32]`, `signature_from_hex → [64]`. Either case in, lowercase out; no
`0x`, no whitespace; the length is checked on the text before any byte is decoded. Not a
hex helper — every language has hex — but the *fixed size*: exactly N bytes or a failure.

**2. `sign_in_domain` / `verify_in_domain` — domain-separated signing.** Ed25519ph with the
domain as the RFC 8032 §5.1 context string. A signature made in one domain verifies in no
other and never as a raw signature; a raw signature verifies in no domain —
~~cryptographically, whatever the bytes~~ *for every key the verification profile
([0008](0008-the-ed25519-verification-profile.md)) admits, by the construction and not by
any encoding convention* (amended 2026-09-21). Bounds: a domain is 1..=255 bytes — of
UTF-8, counted in bytes (0008 §2). **The empty domain is rejected** (legal in the RFC;
"sign in no domain" is exactly what this exists to make impossible).

The domain is the caller's — `<repo>/<purpose>/v<n>` by convention — and **archon neither
knows nor registers domains.** The moment it did, "no thesmos term in the API" would be gone.

**Raw `sign` / `verify` stay.** thesmos heads, receipts, admission contexts and stele's
signed state are raw signatures on disk; changing them is theirs. Domain signing is
*offered*, documented as the default for any protocol with no bytes on disk yet. Whether
the constellation *requires* it for new protocols is an atlas ruling, not an archon API.

**The mechanism was chosen for a property, not a preference.** A framing scheme (prefix the
domain, sign plainly) separates framed contexts from each other only; its separation from
raw contexts depends on ontos encodings never starting with the frame — an invariant archon
does not own. The RFC context makes separation *unilateral*: a consumer that adopts it is
protected from every raw signature that exists or ever will, whatever anyone else does.
That is the only version in which an optional primitive protects whoever calls it.

## Consequences

- **The ts lane moved from `@noble/ed25519` to `@noble/curves`** — the former has no
  context API. Same author, same RFC 8032 semantics, `{ zip215: false }` retained (#106).
  The 30 pre-existing vectors passed unchanged across the swap.
- **The rs lane enables dalek's `digest` feature.** dalek re-exports its own `Sha512`, so
  the manifest's rule — exactly one dependency — holds.
- **The oracle is 60 cases in 7 families** (was 30 in 4): `hex_decode` (12), `domain_sign`
  (5), `domain_verify` (12), and `signature_verify` gains `domain-sig-never-raw`. Expected
  signatures were derived with **OpenSSL 3.2.4**, an implementation outside all three
  cores, per `vectors/README.md`'s rule: a vector captured from a core pins that core's
  bugs. 180 case-checks; all three cores agree.
- **The entry test is now written down** (growth-plan §3) so the next addition is measured
  the same way: at least two consumers hand-write it today; it is about the bytes of keys
  and signatures, not custody, policy or schema; it can be delivered identically in three
  lanes and pinned by tri-core vectors.
