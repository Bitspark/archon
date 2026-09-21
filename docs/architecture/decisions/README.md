# Architecture decisions

One file per decision, numbered, never renumbered. A decision that reverses an earlier one
supersedes it by number rather than editing it.

| # | decision | status |
|---|---|---|
| [0001](0001-archon-scope.md) | archon: the identity and crypto layer beneath the law | **Accepted, scope narrowed** (2026-08-22); its open Merkle row resolved in the negative by the operator (2026-09-09, note at top) |
| [0002](0002-keycodec-is-a-byte-codec-not-key-custody.md) | the key codec is a byte codec, not key custody | **Accepted** (2026-08-22) |
| [0003](0003-the-floor-grows-typed-spellings-and-domain-signing.md) | the floor grows: typed byte spellings and domain-separated signing | **Accepted** (2026-09-09) |
| [0004](0004-the-sdk-layer-above-the-floor.md) | the sdk layer: possession and the envelope, one layer above the floor — re-rules 0001's PoP subtraction | **Accepted** (2026-09-09) |
| [0005](0005-the-layers-version-with-the-floor.md) | the layers above version with the floor: one commit, one version, one tag line per Go module — extends 0004 §Consequences | **Accepted** (2026-09-09); §Consequences amended 2026-09-10 to the fleet's template-first ledger order after v0.2.2's tag commit declared v0.2.1 (archon#14); capture is a dispatch on the tag ref, since a four-tag push fires no push event; first cut under the corrected order v0.2.3 @ e1d9483, verified; v0.3.0 @ e4bef63 verified — the Go `require` lines are version sites (go install does not see go.work); `go.work`'s pinned `replace` lines too (#20); v0.4.0 @ 4c92507 verified — five tags, four templates, the server tier's first cut; v0.4.1 published but never tagged (no gitHead from a worktree publish; four orphan packages); v0.4.2 @ 7f1fea7 verified — the same shape, published only by the workflow; v0.5.0 @ e6f95ea verified — the offers form on both sides, nothing new on the checklist |
| [0006](0006-the-archon-command-three-binaries-one-command.md) | the `archon` command: three binaries, one command, owned here — key/keygen stay archon's; Merkle and the root designation do not enter | **Accepted** (2026-09-09); decision 1's "does not depend on the sdk" superseded for the login scheme as of archon#18 (note at top, 2026-09-10); corrected the same evening: external deps are those ADR 0007 §A names + the Rust login transport |
| [0007](0007-custody-in-the-command-and-the-login-server-tier.md) | custody enters the command (`archon key`, a named password-protected seed store) and a login server tier enters the repository — re-rules 0002's custody line for the CLI store and 0004's third line for a mounted handler; archon#16 | **Accepted** (2026-09-10); §A amended from the keystore contract (#20); all four parts built and shipped — the scheme (#19, #22) and `archon login` (#18) in v0.3.0; the keystore (#20) and the server tier in three lanes (#25, #28, #29, #31: the authority payload is opaque BYTES, pinned) in v0.4.0 @ 4c92507; `login --key` landed 2026-09-11 (#36) — every ruled part in the tree (landings notes) |
| [0008](0008-the-ed25519-verification-profile.md) | the Ed25519 verification profile: what `verify` accepts, in prose — `A` and `R` canonical encodings of points of order exactly L, `0 ≤ S < L`, the domain as UTF-8 text — checked in every core ahead of its library; amends 0003's "whatever the bytes" and records the RFC 8032 §8.5 rationale | **Accepted** (2026-09-21); ruled on the 0002 consultation's advice after its counterexample (the identity key's universal signature, accepted by Go and Rust) was reproduced through the harness; 43 oracle cases added (60 → 103); ships as 0.7.0, a verification-policy correction |

**On 0001's narrowing.** As proposed it claimed identity *plus* succession *plus* proof of
possession *plus* "the principal." Measurement cut it to Ed25519 primitives, the canonical
key spelling, and the PEM key codec — succession was already thesmos's (ADR 0023, and again
independently as Q17 shape (b)), PoP is kosmos's, and the key simply *is* the principal.
The record is `research-docs/0001-identity-floor-seam.md`.

**On the venue.** thesmos ADR 0013 was decided *jointly with stele*, so it is a three-repo
instrument and not archon's to supersede alone. ADR 0002 does not try to: it restates 0013's
substance for archon's own copy of the codec. **Resolved 2026-08-23 in the right venue:**
thesmos **ADR-0027** superseded 0013's *venue* — its content untouched — with stele
co-signing, since 0013 was joint. The switch then landed 2026-08-27 (thesmos), and
thesmos's copy of the codec is gone; §A.8 became a pointer here (thesmos).
