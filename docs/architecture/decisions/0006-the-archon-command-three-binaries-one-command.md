# 0006 — the `archon` command: three binaries, one command, owned here

**Status:** **ACCEPTED** (2026-09-09) · **Type:** scope / tier

> **Status note, 2026-09-10 (the archon maintainers) — decision 1's "it does not depend on the sdk"
> is superseded, for the login scheme only, as of archon#18.** `archon login` (ADR 0007 §C.5)
> proves a login binding, and the binding and proof are the sdk's login scheme (`sdk/*/login`,
> #19, #22). The command **consumes** that scheme and never re-implements it — the alternative,
> a fourth copy of a pinned scheme in three binaries, is the drift the oracle exists to prevent.
> So the manifests now state, with #18: `cli/rs` `archon-sdk = { path = "../../sdk/rs" }`,
> `cli/go` `require github.com/Bitspark/archon/sdk/go`, `cli/ts` `"@bitspark/archon-sdk":
> "file:../../sdk/ts"`. The rule becomes: **the command depends on the floor and on the
> sdk's login scheme; nothing else, and nothing outside this repository** (the Rust lane's
> `ureq`/`serde` are transport, per decision 1's "presentation and I/O layer"). The publish
> path learned the edge in #23 (`cli` `needs: [archon, sdk]`, both `file:` ranges rewritten
> at publish time, ADR 0004 §Consequences); the poster's tier figure is redrawn as a stack
> when #18 is in the tree. Decided in caa's review of #18 (2026-09-10T16:00Z); it takes
> effect in the tree when #18 merges. *Merged the same day as `5c8c54e`; the poster's stack
> and `poster/SEAM.md` §1/§2c/§4 follow at `443c758`.*
>
> **Correction to the note above, same day, evening (the archon maintainers).** "Nothing outside
> this repository" was too strong as written: ADR 0007 §A had already named the custody
> dependencies (`golang.org/x/crypto`, RustCrypto `argon2` + `chacha20poly1305`,
> `@noble/ciphers`), and the tree since archon#20 (`a3d9abf`) carries them, plus `x/term`
> (a prompt that does not echo), `x/text` and `unicode-normalization` (the NFC rule),
> `rpassword`. The rule that is actually ruled, and that the manifests now state: **no
> archon-internal edge beyond the floor and the sdk's login scheme; external runtime
> dependencies only those ADR 0007 §A names for custody, and the Rust lane's login
> transport** (`minreq` + `serde` + `serde_json`, chosen by measurement). Decision 1's "the
> library stays dependency-minimal" is untouched — none of these reach `core/` or `sdk/`.
> Also from #20: this ADR's "the repository's only randomness lives in the command" now
> covers salt and nonce as ADR 0007 §Consequences predicted, and is qualified by the server
> tier, which is unpinned and sources its own (ADR 0007 landings note).
Records a tier that landed without an ADR (`docs/growth-plan.md` §8.2, ad0b8aa) and two
operator rulings about it, so a successor reads the decision by number rather than
reconstructing it from a plan, a commit and two messages. Ruled by the archon maintainers.

## Context

The floor shipped no command. A consumer using archon without thesmos could not spell a
key from the command line; thesmos's CLI tier carried `key` and `keygen` that, measured,
contained no thesmos term (growth-plan §8.2). On 2026-09-09 they were carved out into this
repository as `cli/rs`, `cli/go`, `cli/ts`, with `sign` and `verify` added new — raw bytes,
domain-aware, sharing the names of thesmos's fact-signing commands and nothing else
(`cli/README.md:25-32`).

The operator ruled twice the same day, verbatim (growth-plan §10 `:441-445`):

> *"Finish the agreed version, tag and publication alignment for its CLI and SDK. Maintain
> ownership of the extracted key commands; the root designation and Merkle format have not
> been accepted into archon."*

## Decision

1. **Three native binaries build one command.** `archon <keygen|key|sign|verify|version>
   [args]`, identical stdout and exit codes across `cli/rs`, `cli/go`, `cli/ts`, pinned by
   `cli/smoke.mjs` — 28 invocations × 3 binaries on every push, expected values from the
   oracle or OpenSSL, never from a lane; on Linux and Windows (`conformance.yml` `cli-smoke`,
   `cli-smoke-windows`). The command is a presentation and I/O layer **over** the floor,
   never part of it (`cli/rs/Cargo.toml:3`), and it does not depend on the sdk
   (`cli/rs/Cargo.toml:24-26`, `cli/go/go.mod:8`, `cli/ts/package.json:25`).
2. **`archon key` and `archon keygen` are archon's, and stay archon's.** The operator's
   *"maintain ownership of the extracted key commands"* closes the question growth-plan §8.2
   had left as *asked, not ruled*. Nothing moves back to thesmos or elsewhere; thesmos
   retiring its own copies remains thesmos's act.
3. **The only randomness in the repository lives in the command.** `keygen` without
   `--seed` draws from the OS CSPRNG in the binary — `getrandom` (rs), `crypto/rand` (go),
   `node:crypto` (ts) — never in the floor or the sdk (ADR 0002; ADR 0004 line 1;
   `cli/README.md:34-41`). It is not custody: nothing is named, stored or managed.
4. **A Go main package lives under `cmd/<name>/`.** `go install …/cli/go@main` named the
   binary `go` — the module root's directory — and a binary that shadows the toolchain on
   PATH is a hazard, not a quirk (seat:cca ruling, 2365bbd). The main package is
   `cli/go/cmd/archon`; `go install github.com/Bitspark/archon/cli/go/cmd/archon@vX.Y.Z`
   yields `archon`. `go build ./...` from `cli/go` still drops `archon(.exe)` there;
   `.gitignore` covers it, and a compiled binary is never committed.
5. **The command versions with the floor** (ADR 0005): `cli/go/vX.Y.Z` tags,
   `@bitspark/archon-cli` and `archon-cli` at `X.Y.Z`, ledger line
   `substrate/release-facts.cli.json` with `typeIdentityCritical: false`. First cut under
   that rule: v0.2.2 at 8fd74e0.
6. **`archon version` prints `archon <semver> (<commit>)`; the commit slot is
   environment-stamped and pinned by shape only.** `vcs.revision` (go, from a repository
   build), `ARCHON_GIT_COMMIT` (rs, ts, when a build stamps it), else `unknown` — in all
   three, and the smoke requires only exit-code agreement on that case
   (`cli/smoke.mjs:112-138`). **Considered and declined** (2026-09-09): having the Go binary
   fall back to `debug.ReadBuildInfo().Main.Version` so a `go install …@v0.2.2` prints
   `(v0.2.2)` instead of `(unknown)`. It would put a *version* in the *commit* slot, in one
   lane only — the rust and ts binaries installed from the same tag have no equivalent and
   would keep printing `(unknown)` — so the three would print the same line with two
   meanings. The version already has its own slot and is correct there in all three
   (`archon 0.2.2 (unknown)` from a `go install …@v0.2.2`, measured).

## What archon does NOT take with the command (operator, 2026-09-09)

- **The Merkle inclusion format** (`merkle-inclusion-v1`, thesmos ADR series). ADR 0001's
  *"UNRESOLVED — decide it separately"* row is resolved in the negative; the refusal the
  criterion in 0001 already predicted (a thesmos-defined format whose types sit in thesmos's
  records) is now the operator's word as well (growth-plan §6.3 `:212-218`).
- **The root trust-anchor designation** (`PLACEHOLDER_ROOT` and its seed). A thesmos
  designation, removed from archon's cores; thesmos pins it *through* archon's derivation
  (`README.md`, "archon does NOT own"). Nothing in the floor, the sdk or the command carries
  either.

## Consequences

- thesmos's CLI split (its `sign`/`verify` on facts stay; its `key`/`keygen` copies retire)
  is thesmos's to execute and thesmos's maintainers's to rule; this seat watches that it lands
  as §8.2 describes and owns none of it.
- Any future subcommand enters the command the way a function enters the floor: measured
  against what consumers hand-write, deliverable identically in three binaries, and pinned
  in `cli/smoke.mjs` before it is called done. A subcommand only one binary can implement
  is not a subcommand of *this* command.
- Nothing here changes the floor's entry test (ADR 0003, growth-plan §3); the command is
  not a route into the floor.
