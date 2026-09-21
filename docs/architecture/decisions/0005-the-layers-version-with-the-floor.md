# 0005 — the layers above version with the floor: one commit, one version, one tag line per Go module

**Status:** **ACCEPTED** (2026-09-09) · **Type:** release / versioning
**Extends [0004](0004-the-sdk-layer-above-the-floor.md) §Consequences**, which said only that
the publish path rewrites the sdk's `file:` dependency at publish time and that consumers of
`sdk/go` resolve a pseudo-version. Ruled by the archon maintainers on the coordinator's routing
(2026-09-09, seat:cca: *"decide it once, in an ADR"*).

## Context

On 2026-09-09 the sdk (`@bitspark/archon-sdk`, `archon-sdk`, `sdk/go`) and the command
(`@bitspark/archon-cli`, `archon-cli`, `cli/go`) were published for the first time — both at
**0.1.0**, from commit `2a2db88`, by the `sdk` and `cli` jobs of `publish-npm.yml`. The floor
was at **v0.2.1**, cut from `4d2b4bd`, with `substrate/release-facts.json` anchoring all three
of its lanes to that one commit. Measured, the state this left:

| tier | rs | go | ts | ledger line |
|---|---|---|---|---|
| floor | crate 0.2.1 at tag `v0.2.1` | `core/go/v0.2.1` | 0.2.1, gitHead `4d2b4bd` | `release-facts.json` |
| sdk | crate **0.1.0**, resolved by consumers at tag **`v0.2.1`** | **no tag**; pseudo-version `v0.0.0-2026…` | 0.1.0, gitHead `2a2db88` | none |
| cli | crate **0.1.0**, `cargo install --tag v0.2.1` | **no tag**; pseudo-version | 0.1.0, gitHead `2a2db88` | none |

Three things are wrong with that, and they are one thing:

1. **A tag names a version it does not carry.** A consumer writing
   `archon-sdk = { git = …, tag = "v0.2.1" }` gets a crate whose declared version is 0.1.0.
   The substrate gate that protects consumers — ADR 0027 Gate B, *"the source tag, per-lane
   declared versions, embedded source commits … all AGREE"* (`substrate-release.yml:31-36`)
   — would red exactly this, if the sdk had a line for it to check.
2. **The three lanes of one tier do not co-resolve from one commit.** The sdk's Rust lane
   resolves at `4d2b4bd`, its npm lane was published from `2a2db88`. The sources are
   identical between those commits; the gate cannot know that, and should not have to.
3. **Nothing declares the sdk or the command to the substrate at all**, so nothing verifies
   they are published, and no consumer can pin them through the ledger.

The tooling supports two shapes. `substrate-release.yml` fans out over every
`substrate/release-facts*.json` (`:39-46`), so a repo can declare several components; and a
component can declare a `tagPrefix` and be skipped by tags that do not name it (`:313`), so
components *could* version independently.

## Decision

**The layers above version with the floor.** One release of archon is one commit, one
version number, and a set of tags that all name it:

| what | tag / version at release `X.Y.Z` |
|---|---|
| source tag, release id, every Rust crate | `vX.Y.Z` |
| `core/go` | `core/go/vX.Y.Z` |
| `sdk/go` | `sdk/go/vX.Y.Z` |
| `cli/go` | `cli/go/vX.Y.Z` |
| `@bitspark/archon`, `@bitspark/archon-sdk`, `@bitspark/archon-cli` | `X.Y.Z` |
| `archon-core`, `archon-sdk`, `archon-cli` (`Cargo.toml` `version`) | `X.Y.Z` |
| `sdk/*` and `cli/*` path dependencies on the floor (`version = "…"`) | `X.Y.Z` |

Three ledger lines, one per published component, all carrying the same `source.tag` and
`source.commit`:

| file | component | `typeIdentityCritical` | why |
|---|---|---|---|
| `substrate/release-facts.json` | `archon` (the floor) | true | unchanged |
| `substrate/release-facts.sdk.json` | `archon-sdk` | **true** | its bytes are pinned tri-lane by `vectors/sdk.json`; a consumer's possession proof must verify byte-for-byte across lanes |
| `substrate/release-facts.cli.json` | `archon-cli` | **false** | an executable nobody links; smoke-pinned, published, verifiable — but not a type identity (the shape logos uses for `logos-kernel`) |

**`sdk/go` and `cli/go` get their tag lines** — the question ADR 0004 §Consequences and the
caa charter left open — and get them *because* Go's nested-module rule forces a per-module
tag, not because the sdk has its own version. It does not.

## Why lockstep and not independent

- **It is the constellation's convention, measured, not asserted.** Every multi-component
  member in the constellation versions all its components under one source tag: ontos five
  components at `v0.7.0` (`ontos/substrate/release-facts{,.codec,.data,.data-json,.deixis-projection}.json`),
  logos `logos-contract` + `logos-kernel` at `v0.15.0` with tags `contract/go/v0.15.0` and
  `kernel/go/v0.15.0`, thesmos `v0.19.0` + `core/go/v0.19.0` + `db-binding/go/v0.19.0`.
  Independent versioning exists in the tooling and **no member uses it**. A consumer of the
  constellation reads one version per repo; archon should not be the exception that makes
  them read three.
- **It is what the one-commit gate already means.** The floor's v0.2.0 was published from
  two commits and v0.2.1 was cut to repair that (`4d2b4bd`, *"cut in order"*). A tier whose
  lanes may drift apart from the floor's commit is the same defect with a different name.
- **The sdk is one dependency away from the floor and nothing else** (ADR 0004). A change to
  the floor's bytes is a change to what the sdk signs; there is no sdk release that is not
  also a statement about a floor version. Lockstep makes that statement the version number.
- **The cost is patch bumps of unchanged packages**, and it is paid nowhere it hurts: every
  npm publish is idempotent per version (`publish-npm.yml`), a Go tag on unchanged source is
  free, and a Rust crate is resolved by git tag. A consumer who pins `^0.3.0` on the sdk
  sees no churn from a floor-only patch.

## Consequences

- **At the next cut**, whoever cuts it (release is the archon maintainers's) bumps `sdk/rs`,
  `cli/rs`, `sdk/ts`, `cli/ts` to the floor's version, updates the `version = "…"` on the
  path dependencies, pushes `vX.Y.Z` + the three `<dir>/go/vX.Y.Z` tags at one commit, and
  adds `release-facts.sdk.json` and `release-facts.cli.json` in the shape of
  `release-facts.json`. **Not before:** a ledger line written today would declare a
  tag/version pair that Gate B rejects. The 0.1.0 packages stay on the registries as
  pre-ledger artifacts; nothing depends on them through the ledger.
- **The `file:` / `path` rewrite of ADR 0004 §Consequences is unchanged.** It is about
  *where* the dependency resolves at publish time, not *which version*; the range it writes
  (`^<floor>`) becomes `^X.Y.Z` of the same release, which is the honest range.
- **The publish job order is already right:** `sdk` and `cli` `needs: archon`, so the floor
  a dependent names is on the registry before the dependent is.
- **`go install github.com/Bitspark/archon/cli/go/cmd/archon@vX.Y.Z`** becomes the
  command's stable install line once `cli/go/vX.Y.Z` exists; until then `@main`, as the
  README says.
- **What this does not decide:** whether the sdk's *surface* changes are semver-major for the
  floor's number (a floor at 0.x is pre-1.0; the question arrives with 1.0 and is deferred to
  it); the fleet-wide domain-tag rule (atlas's, still not ruled — growth-plan §10); anything
  about thesmos's own tiers.
