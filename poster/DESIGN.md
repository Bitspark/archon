# archon poster — editorial and visual contract

Companion to [`SEAM.md`](SEAM.md) (facts) and [`index.html`](index.html) (the artifact).

> **Refinement record, 2026-09-09 — a REFRAME, not a redesign.** The identity (a
> calibration certificate: three lanes, the oracle above them, agreement as alignment) is
> preserved whole. What changed: the repository grew two tiers above the floor (ADR 0004's
> sdk; the `archon` command) and the floor itself grew (ADR 0003), so the page had drifted
> on truth — a 30/90 seal against a 60/180 oracle, `v0.1.0` attach tags against a `v0.2.1`
> floor, and a non-goals list stating that proof of possession and an envelope were *not*
> archon's after ADR 0004 had made them so. Repaired all of that; added one section ("The
> floor, and what stands on it") with three figures that reuse the existing vocabulary; and
> extended the attach doors by one line each. Nothing was removed from the narrative.
> Details in the sections marked *(2026-09-09)* below.
>
> **2026-09-10, repair:** the login scheme landed (#19) — a third sdk scheme with its own
> oracle. The seal's counts move (154 vectors, 462 case-checks), the sdk tier card names the
> third scheme and its oracle, and the scheme figure gains a third byte plate in the same cell
> language, because its distinctive fact — scope and validity are *inside* the signed bytes —
> is a layout fact and reads best as one. No structure changed. The keystore, `archon login`
> and the server tier are ruled (ADR 0007) and not yet built; the poster shows them when they
> exist.
>
> **2026-09-10, later, counts only:** #21 pinned the wrong-size-seed error in every sdk lane
> (36 → 38 sdk cases, 108 → 114) and #22 moved audience derivation into the scheme with its
> own oracle family (58 → 105 login cases, 174 → 315). Seal: **203 vectors, 609 case-checks**;
> the sdk card and the closing derivation line follow. The binding plate's audience cell now
> says the derivation is pinned, since that is the fact #22 added. Nothing else moved.
>
> **2026-09-10, `archon login` (#18, `5c8c54e`) — the tier figure becomes a stack.** The
> 09-09 figure drew the sdk and the command side by side on the floor, and said why: *a stack
> is a claim*, and the manifests then named the floor only. The manifests now name the sdk
> from all three command lanes (`cli/rs/Cargo.toml:27`, `cli/go/go.mod:16`,
> `cli/ts/package.json:26`) — `login` consumes the sdk's scheme rather than carrying a fourth
> copy (ADR 0006 status note) — so the same rule that forbade the stack now requires it. The
> grid is one column; the two connector lines name the two edges exactly ("the command
> consumes the sdk's login scheme — and the floor directly, for everything else"; "the sdk
> depends on the floor, and on nothing else"), because a bare stack would read as cli → sdk →
> floor and hide the direct edge. The command card gains `login`, the smoke count moves 28 →
> 38, and the command figcaption names a second deliberately unpinned edge: the network
> round-trip. Measured overflow 0 at 1440 / 768 / 390.
>
> **2026-09-10, evening — the key store (#20) and the server tier (#25).** Seal: **240
> vectors, 720 case-checks**, smoke 74; the command card names its own oracle
> (`vectors/keystore.json`, 37 · 3 · 111) and the cross-binary custody the smoke pins; the
> usage paragraph gains the store's verbs and their four refusals in one clause each. The
> randomness sentence is qualified to "any pinned tier", because the server tier now sources
> its own. **The server tier is not on the poster yet**: it has no published surface until
> the cut that tags `server/go`, and the poster shows only what a reader can attach to (the
> 09-10 rule). `poster/SEAM.md` §2d records it in full. No structure changed.
>
> **2026-09-10, night — v0.4.0 (4c92507): the server tier is on the poster.** Its three lanes
> shipped (#25 go, #28 rs, #29 ts, #31 the byte pin) and the cut tagged them, so there is a
> surface to attach to and the 09-10 rule is satisfied. Placement: the top of the stack is now
> a **pair** — the command and the server side by side on the sdk — because that is what the
> manifests say: each names the floor and the sdk, neither names the other. A fourth card in
> the same cell language; its "pin" line is honest about the tier being unpinnable by an
> oracle and held instead by three suites reading one fixture, with the byte-for-byte
> authority payload named because it is the fact the evening's reviews established. Each
> door gains a server line; the closing line reads four tiers. The seal's numbers do not move:
> the server tier adds no oracle vectors. The lede's "nothing outside this repository"
> (wrong since #20's custody dependencies) becomes "every edge between them is a line in a
> manifest", which is the claim the figure actually makes. Measured overflow 0 at 1440 /
> 768 / 390.

---

## Primary reader

**A consumer engineer who needs Ed25519 identity in more than one language** and is
deciding whether to attach.

Not the contributor, and deliberately not the constellation architect. The README already
serves those two — it opens on ownership rulings, one-change-authority and ADR
archaeology. A reader who has not cloned the repo needs to know what crosses the boundary,
what guarantee comes with it, and whether it applies to them. The ownership argument
survives on the poster only where it changes *use*: the rules in §5 of SEAM and the honest
adoption test in §6.

Operators and contributors are served at the end (the one command, the source links), never
in the opening narrative.

## Plain-language proposition

> **archon is Ed25519 identity — keys, one canonical way to write them, and the standard
> PEM containers — implemented separately in Rust, Go and TypeScript, and proven to produce
> the same bytes in all three.**

**Differentiator:**

> The three implementations are not bindings over a shared core. They are three real
> implementations, and a hand-authored oracle proves they agree on every byte — including
> the cases where Ed25519 libraries genuinely disagree with each other.

## Reading passes

**Five seconds** — archon is the identity floor: Ed25519 keys and their canonical
spelling, written three times in three languages and proven byte-identical. The hero strip
shows one seed producing the same public key, the same `ed25519:…` text and the same PEM in
Rust, Go and TypeScript.

**Thirty seconds** *(2026-09-09)* — the seam is fifteen functions in four modules; the
guarantee is enforced by 288 case-checks on every push (180 floor + 108 sdk) against oracles
authored from the RFCs and OpenSSL; it catches real divergence — `@noble/ed25519`'s default
verification accepts a small-order key that `ed25519-dalek` and Go's stdlib reject; and two
things stand on the floor to the same discipline — an sdk (possession + envelope) and the
`archon` command — each written three times and pinned by its own oracle. The masthead's
one-line layers note plus the seal carry this; the reader does not need to reach the new
section to know the tiers exist.

**Five minutes** *(2026-09-09)* — the verified round-trip, the tier figure (what stands on
the floor and what each tier depends on), the two scheme plates (what a possession proof and
an envelope actually sign, with JWS-never-JWT stated as an in/out list), the masthead's seed
through the three command binaries, the three attachment coordinates with the sdk and
command one line under each, the rules that change how the seam is used, the honest test
for when *not* to adopt it, and a next action.

## Content budget

| slot | committed |
|---|---|
| central claim | one identity, three languages, same bytes — proven, not asserted *(unchanged 2026-09-09: the tiers inherit the claim, they do not replace it)* |
| supporting proof | ZIP-215 divergence caught · oracle hand-authored from standards not captured from a core · 11 of 15 codec cases are rejections · one guarded `verify` where Go's stdlib panics · openssl reads archon's PEM |
| attachment | three peer coordinates (crate+tag · go module · npm scope); **one** primary action: `node conformance/check.mjs`; Rust named canonical only for semantics disputes |
| interaction | the seed `11…11` round-trip — pubkey, key text, SPKI PEM — run live across all three cores by the author |
| rules | fails closed · no custody/RNG/IO · no authority vocabulary · no rotation · rejection pinned, reason not · *(2026-09-09, in the tier section rather than the rules grid)* the sdk sources no entropy, time or binding · JWS never JWT · the only RNG is the command's `keygen` |
| next actions | attach · run the check · read ADR 0001/0002 |

**Deliberately subordinated or omitted**

- The full 30-case inventory by name → `SEAM.md` §3.1 only. The poster shows the four
  families and their counts, never the roster.
- ADR archaeology, the extraction plan, the Merkle withdrawal, the retired tier 2 → linked,
  not narrated. Contributor material.
- The CI job matrix and the Windows-leg promotion story → one clause in the appendix. It is
  an excellent story about measurement discipline and it is not why a consumer attaches.
- Commit count, line counts, repository age → present only as a small status line at the
  end. These must not outrank the thesis, and on this page they do not appear above it.
- The constellation layer diagram (`dependsOn: []`, thesmos above) → compressed to one
  sentence of type. There is nothing to draw: an empty dependency list is best stated, not
  illustrated.
- *(2026-09-09)* The sdk's per-door symbol tables and the command's full flag matrix →
  `SEAM.md` §2b/§2c. The poster shows two byte plates and one usage line: the *shape* of
  each scheme and the *shape* of the command, not their inventories.
- *(2026-09-09)* A fourth "door" row for the sdk and the command → refused. The floor's three
  doors stay primary; the tiers attach "the same way, one line under each", which keeps one
  attachment path visibly primary.
- *(2026-09-09)* `go install …/cli/go@main` → was kept off the poster because, verified, it
  named the binary `go`. Resolved the same day by moving the main package to
  `cli/go/cmd/archon` (seat:cca ruling); the Go door now cites `go install …/cmd/archon`.

## Storyboard

| # | Beat | Reader question | One-sentence answer | Evidence | Representation | Priority |
|---|---|---|---|---|---|---|
| 1 | Standard & specimen | What is this? | Ed25519 identity implemented three times and proven byte-identical. | `atlas.json:6`, `harness.mjs:10-12` | Title + proposition + hero agreement strip (one seed → three identical columns) | P0 |
| 2 | Why three | Why not one library with bindings? | Because a key spelled by one core must be readable by another, or the floor isn't a floor — and the curve math is never rewritten, only the encodings. | `harness.mjs:10-12`, `Cargo.toml:8-12` | Short prose + written-3× vs bound-1× contrast | P0 |
| 3 | The catch | Is the guarantee real? | It caught a live divergence: `@noble` default says `true`, dalek and Go say `false`. | `crypto.ts:32-37`, verified live | **Divergence figure** — broken alignment, the only use of the alert colour | P0 |
| 4 | The instrument | How is agreement proven? | A hand-authored oracle, 30 cases in 4 families, driven against three black boxes; 90 case-checks per push. | `harness.mjs:7-8,38-47`, `vectors/README.md:36-40` | Bench diagram: oracle above, three lanes below, verdicts compared | P0 |
| 5 | The surface | What can I call? | Nine functions in three modules — and the doors are *not* signature-compatible. | SEAM §2 | Grouped index, three signature columns that deliberately do not align | P1 |
| 6 | The template | How can three languages agree on DER without three ASN.1 libraries? | The Ed25519 DER is fixed-size: a constant prefix with the 32 key bytes spliced in. | `keycodec.rs:5-7,17-25` | Byte plate — constant region + variable window | P1 |
| 6b *(2026-09-09)* | The tiers | What else is here, and does it dilute the floor? | Two things stand on the floor — an sdk and the command — each three times, each pinned, each depending on the floor and nothing else. | SEAM §1, §2b, §2c | **Tier figure**: sdk and cli side by side above a full-width floor row, three lanes in each, the pin named under each. Then two **scheme plates** (possession, envelope — the same cell language as beat 6, with an in/out list for JWS-never-JWT). Then the masthead's seed through the three binaries, in the hero's own lane component. | P1 |
| 7 | Attach | How do I connect? | Three coordinates, one command. | `release-facts.json`, `check.mjs` | Code blocks | P0 |
| 8 | Rules | What changes how I use it? | Fails closed; holds no key; has no opinion about authority; no rotation. | SEAM §5 | Rule list + boundary note (custody→stele, authority→thesmos) | P0 |
| 9 | Counter-case | Should *I* adopt it? | Only if you have zero canonical spellings — in a repo with one, archon adds a second. | extraction-plan §4 | Callout, quoted refusal | P1 |
| 10 | Status & next | What now? | Founded, not switched. Attach, run the check, read the ADRs. | `README.md:15,154-157` | Status line + actions | P1 |

Beat 4 was nearly merged into beat 1 — both are "the agreement". Kept separate because
beat 1 answers *what the output is* and beat 4 answers *what makes it trustworthy*; a
reader who accepts the first without the second has taken the claim on faith, which is the
exact posture the repo refuses.

---

## Thesis

> **archon is Ed25519 identity written three times on purpose, whose product is not the
> code but the proof that the three agree on every byte.**

## Candidate directions

Three candidates, each derived from a fact in `SEAM.md`.

### A — Interlaboratory comparison / calibration certificate ✅ CHOSEN

*Derived from:* `conformance/harness.mjs:7-12` — three implementations driven as **black
boxes**, explicitly "not one library with two bindings" — plus `vectors/README.md:36-40`,
where the expected values are hand-authored from the standard so that "all three cores be
wrong together and be caught."

That is exactly the structure of a metrology round-robin: a **reference standard**, *N*
**independent instruments**, each measured against the standard rather than against each
other, and a **certificate of agreement** as the deliverable.

*Commits to:* three parallel measurement lanes as the page's spine; every byte value in
monospace because the bytes *are* the measurements; agreement rendered as literal vertical
alignment and divergence as a break in it; the oracle drawn above the lanes as a separate
authority, never as a fourth lane; ruled hairlines and letterspaced label caps; verdict
marks alongside every coloured state.

*Interchangeability test:* fails hard when transplanted. A calibration certificate is
meaningless for a repo that does not produce independent measurements of the same quantity.

### B — Fixed-template byte plate ❌ REJECTED as primary

*Derived from:* `core/rs/src/keycodec.rs:5-7,17-25` — the DER is fixed-size, so encode is a
constant prefix with 32 key bytes spliced in and decode is a template match.

*Rejected because* it is true of **one module of three**. A poster built on it would be a
poster about PEM encoding, and archon is not a PEM library — it would push the strongest
fact in the repository (the verify divergence) off the page.

*Retained as a secondary figure* (beat 6), where it does the one job prose does worse:
showing why three languages can agree on DER without three ASN.1 dependencies.

### C — Orthography / one-spelling lexicon ❌ REJECTED

*Derived from:* `README.md:35-41` and extraction-plan §4 — archon's value is "one canonical
spelling instead of three", and the logos refusal turns precisely on that.

*Rejected because* it captures `keytext` and the adoption test but **cannot carry
verification semantics**. The ZIP-215 divergence is not a spelling question; it is a
*verdict* question, and it is where the sharpest proof lives. A dictionary plate has no
grammar for "these two libraries return different booleans."

*Retained as copy* in beat 9, where the one-spelling framing is exactly right.

## Derivation

- because `harness.mjs:10-12` states the three cores exist so a key spelled by one is
  readable by another **byte for byte**, therefore agreement is shown as **literal vertical
  alignment of identical values**, never asserted in prose;
- because `vectors/README.md:36-40` authors the oracle from the standard so all three cores
  can be wrong together and be caught, therefore the oracle sits **above** the three lanes
  as a distinct authority, and is never drawn as a fourth core;
- because `core/ts/src/crypto.ts:32-37` records a case where `@noble` returned `true` while
  dalek and Go returned `false`, therefore one figure exists **solely to break the
  alignment**, and the alert colour appears nowhere else on the page;
- because `docs/…/0002-….md:47-52` says a codec that differs on what it *refuses* is a
  codec that differs, therefore **refusal has its own semantic colour** — deliberate, not
  alarming — distinct from both agreement and divergence;
- because `core/rs/src/keycodec.rs:5-7` says the DER is a constant template with the key
  spliced in, therefore beat 6 is a **byte plate** with a shaded constant region and a
  marked 32-byte window, not a box-and-arrow diagram;
- because the three doors differ in argument order and error style (SEAM §5), therefore the
  API figure sets three columns that **deliberately do not align** — the one place on the
  page where misalignment means "correct, and watch out";
- because `atlas.json:8` declares `dependsOn: []` and CI needs no credential, therefore
  dependencies are **one line of type**: an empty list is stated, not illustrated.
- *(2026-09-09)* because `cli/rs/Cargo.toml:24-26`, `cli/go/go.mod:8` and
  `cli/ts/package.json:25` name the floor and never the sdk, therefore the tier figure draws
  the sdk and the command **side by side on one floor row**, not as a three-high stack — a
  stack would assert a dependency the manifests refute;
- *(2026-09-09)* because ADR 0004 `:49-53` says the sdk's bytes are pinnable *only because*
  entropy, time and binding are arguments, therefore the deterministic-given-inputs rule is
  set **inside the sdk's tier card**, under its pin, rather than in the general rules grid —
  it is the reason the pin exists, and it belongs beside it;
- *(2026-09-09)* because ADR 0004 `:54-56` lists what is in the envelope and what is out
  permanently, therefore JWS-never-JWT is an **in/out list with the page's verdict glyphs**
  (`=` in, `×` out) rather than a sentence — a refusal is part of the contract and reads as
  one;
- *(2026-09-09)* because the possession message and the envelope are fixed layouts with a
  constant tag and variable windows (`possession.ts:15`, `envelope.ts:7`), therefore they are
  **byte plates in beat 6's cell language** — the scheme tag set in weight, never in a
  semantic colour, since it is a template byte and not a verdict;
- *(2026-09-09)* because `cli/smoke.mjs:93` pins `key pub --seed` on the masthead's own seed,
  therefore the command is shown **re-deriving the hero's key text through three binaries**
  in the hero's own lane component — the tier is tied to the certificate's spine rather than
  given a new idiom.

## Design system

### Type roles

| role | stack | job |
|---|---|---|
| **measure** | `ui-monospace, "Cascadia Code", "SF Mono", Consolas, "DejaVu Sans Mono", monospace` | every byte value, signature, PEM, verdict, coordinate. The dominant voice — the measurements themselves. |
| **body** | `ui-sans-serif, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` | sustained reading. ≥16px, line-height 1.65, measure ≤68ch. |
| **label** | body face, uppercase, `letter-spacing: .14em`, small size, `--ink-3` | form-field labels on a certificate: section eyebrows, lane headers, figure captions' lead-in. |
| **display** | body face at large size, `font-weight: 600`, tight tracking | the repository name and section heads only. |

No embedded font files. All stacks resolve offline from system faces.

### Palette — semantic roles, fixed across the page

| token | light | dark | means — and *only* this |
|---|---|---|---|
| `--paper` | `#faf9f6` | `#14161a` | page ground (warm archival white / near-black) |
| `--panel` | `#ffffff` | `#1b1e24` | raised measurement surfaces |
| `--panel-2` | `#f4f2ec` | `#20242b` | plate headers, inset cells |
| `--ink` | `#16181d` | `#e8eaee` | primary text — **and measured values that are not verdicts** |
| `--ink-2` | `#4a5058` | `#a8b0bb` | secondary text |
| `--ink-3` | `#656c76` | `#8b939d` | labels, captions |
| `--rule` | `#d9d5cc` | `#2c3038` | hairlines, grid, plate borders |
| `--agree` | `#1f5fa8` | `#6fa8e8` | **concurrence** — the cores agree; also the one call-to-action surface. Archival blue. |
| `--refuse` | `#925514` | `#d9954a` | **a verdict of rejected.** Ochre — deliberate, not alarming. 11 of 15 codec cases live here. |
| `--diverge` | `#b3261e` | `#f2827a` | **implementations disagree.** Used in exactly one figure. |

An accent never changes meaning between sections. **No state is carried by colour alone** —
every agree/refuse/diverge mark also carries a glyph and a word (`=` concur, `×` refused,
`≠` divergent).

**Contrast is a gate, not a preference.** Every text/background pair was measured against
WCAG AA (4.5:1) in *both* themes. Four pairs failed the first palette and were corrected
rather than waived:

| pair | was | now |
|---|---|---|
| light `--ink-3` on `--panel-2` | `#767d87` — 3.71:1 | `#656c76` — 4.74:1 |
| light `--ink-3` on `--paper` | 3.95:1 | 5.04:1 |
| light `--refuse` on `--panel-2` / `--refuse-bg` | `#a8641a` — 4.17:1 | `#925514` — 5.31:1 |
| dark `--ink-3` on `--panel-2` | `#7d858f` — 4.17:1 | `#8b939d` — 5.01:1 |

A refinement run that changes any palette value must re-run that whole matrix, not
spot-check the pair it touched.

⚠ **`--refuse` is for verdicts, never for measurements.** The counter-case tally (`0` vectors,
`0` PEM, `0` spellings) was first set in ochre and corrected to `--ink` at weight 600: those
are *absences being counted*, not *things being rejected*, and borrowing a semantic colour
for emphasis is exactly how an accent starts meaning two things. Emphasis there is weight.

### Grid, rhythm, density

- Content column `min(1180px, 100% - 2*gutter)`; prose blocks capped at 68ch.
- The three-lane grid (`rs · go · ts`) is the recurring spatial motif: `repeat(3, 1fr)`
  above 900px, stacked below.
- Vertical rhythm on an 8px base; section separation 64–88px desktop, 44–56px phone.
- **Density rule:** monospace measurement blocks may be tight (line-height 1.5, compact
  padding) — they are scanned, not read. Prose stays spacious and never drops below 16px
  (body is 16.5px).
- **Type floor, as built and enforced:** body 16.5px · figcaption 14px · measured values
  12.5px · letterspaced uppercase mono labels **11.5px**, and nothing on the page goes below
  it. (An earlier draft put the `ARCHON` chip at 10.5px and the appendix table head at 11px;
  both were raised. The core-name lane label sits at 12px because it is an *essential* figure
  label rather than a caption.)

### Line, shape, mark

- Hairline rules (1px `--rule`) and square corners for measurement surfaces; a certificate
  does not have rounded cards. Radius is limited to 3px on inline chips.
- The **lane rule** — a vertical hairline between the three columns — is the page's
  signature mark; it is what makes alignment and its breaking visible.
- Verdict marks are typographic (`=`, `×`, `≠`), not icons.
- One decorative element only: the Greek `ἄρχων` set as a specimen line under the title.

### Motion

**None.** A certificate does not animate, and nothing on this page is explained better by
movement than by a static drawing. No transitions, no scroll effects, no reduced-motion
special case needed.

### Responsive transformation — every dense region

| region | wide | narrow | crossover |
|---|---|---|---|
| hero agreement strip | 3 lanes side by side, identical values aligned | **collapses to one value per stage** with the three core names beneath as concurring marks — the identity of the values *is* the argument, so showing it once with three witnesses reads better small, not worse | 760px |
| divergence figure | 3 columns: library, verdict, agreement | stacked; verdict + mark move under the library name. The two column headings are **dropped, not stacked** — every data row already reads `false × refused` on its own, and a lone right-hand stub is an orphan | 640px |
| bench diagram (SVG) | oracle above, three black boxes, comparator below | dedicated narrow variant: vertical flow, oracle → boxes stacked → comparator | **1080px** |
| four vector families | 4 across | 2 across, then 1 | 900 / 560px |
| API index | 3 signature columns per module | per-function block, three labelled signature lines each | 900px |
| rules | 3 across (6 items = 2 clean rows) | 2, then 1 | 1000 / 660px |
| DER byte plate | 44/48 cells in one wrapped grid | same grid, wraps naturally; constant/variable regions keep fill + label | — |
| attach coordinates | 3 blocks in a row | stacked | 820px |
| *(2026-09-09)* tier figure | sdk + cli side by side, floor row full width; 3 lanes per card | cards stack (820px); lanes stack inside each card (640px) — its own `.tier-lanes` grid, never `.lanes` | 820 / 640px |
| *(2026-09-09)* scheme plates | one wrapped byte row per scheme; in/out list two columns | rows wrap naturally (the variable cells are `flex:1 1 auto`); in/out stacks | 640px |
| *(2026-09-09)* seed through the command | 3 lanes (the hero's `.lanes`) | the hero's `.lanes-narrow` — one value, three witnesses | 760px |

No page-level horizontal scrolling at any width — verified at 390, 720, 768 and 1440 by
measuring `documentElement.scrollWidth` against `clientWidth` and counting elements whose
right edge exceeds the viewport (zero at every width). Nothing relies on a scroll affordance.

*(2026-09-09)* Re-measured the same way after the refinement: 1440 → 1424/1424, 768 →
752/752, 390 → 390/390, and 720 at device-scale 2 (≈200 % zoom) → 704/704, all with zero
overflowing elements. Headless Chrome clamps windows to 500 px, so the 390 reading was taken
inside a 390 px iframe, where media queries follow the frame. The first pass at 390 measured
413/390 with 22 overflowing elements — the new attach notes carried unbreakable coordinates
(`github.com/Bitspark/archon/sdk/go/possession@main`) in a class without `overflow-wrap`.
Fixed on the class, not the content; the pre-refinement page measured clean at 390 the same
way, so the defect was introduced and removed in the same pass.

**Two traps this layout fell into once. Do not re-introduce them.**

1. **The narrow bench SVG must stay capped** (`max-width:430px`, centred). Its viewBox is 360
   units wide; left to fill a 750px container it renders every label at roughly twice the
   surrounding type. The crossover is **1080px, not 820px**, for the mirror-image reason:
   below ~1080 the 1000-unit wide variant shrinks its 10.5-unit labels under the legibility
   floor. Each variant has a band where it is wrong; 1080 plus the cap is where neither is.
2. **`.lanes` is the three-core component and is `display:none` below 760px.** It is only
   ever valid paired with a `.lanes-narrow` sibling. The four-families block was briefly
   built by overriding `.lanes` to four columns, and rendered **completely blank on every
   phone**. It now has its own `.families` grid. Before reusing `.lanes` for anything that is
   not the three cores: don't.

### Identity invariants — preserve in any future refinement

0. **The masthead carries the stamp block** — now `96 vectors · 3 implementations · 288
   case-checks` *(2026-09-09; was `30 · 3 · 90`, then briefly stale against a 60/180 oracle)*.
   It is the certificate's seal, it completes the five-second read, and it is the only place
   those three figures appear above the fold. Not decoration, and not a metrics badge. The
   numbers are derived: 60 + 36 vectors, 180 + 108 case-checks; the command's 28 × 3 is named
   in the caption rather than added, because a smoke invocation is not a case-check.
1. **Three lanes are the spine.** `rs · go · ts` in that order wherever cores are compared.
2. **Agreement is shown, not claimed** — identical values in visible alignment.
3. **The oracle is above the lanes**, never a fourth lane.
4. **`--diverge` appears in exactly one figure.** Its scarcity is the point.
5. **`--refuse` is not an error colour.** Rejection is a feature and reads as deliberate.
6. **Monospace carries every byte.** No byte value is ever set in the body face.
7. **No state by colour alone** — glyph + word always accompany.
8. **No motion.**
9. **The honest counter-case stays on the page.** The logos refusal is not marketing damage
   to be trimmed; it is the most trust-generating fact available.
10. **Square corners, hairline rules, letterspaced caps labels.**
11. *(2026-09-09)* **The floor stays the thesis.** Tiers above it are drawn *on* it — a
    full-width floor row under side-by-side cards — never as a stack that puts something
    above the floor's own certificate, and never with a fourth lane. The command re-derives
    the masthead's own key text so the tiers point back at the seal instead of away from it.

### Implementation choices that may change freely

Exact hex values, the specific system-font stacks, section order below beat 4, the byte
plate's cell size, the appendix's disclosure mechanism, and whether the bench diagram is
one SVG or two.
