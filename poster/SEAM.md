# archon — the public seam

Exhaustive record of what crosses archon's boundary, with `path:line` evidence for every
technical claim. This file is the accuracy contract for [`index.html`](index.html) and the
input to every future refinement run.

Compiled 2026-08-26 against `main` @ `2f9a767`. **Re-derived 2026-09-09 against `main` @
`78f69b4`** for the layers above the floor (ADR 0004 sdk, the `archon` command) and the
floor's own growth (ADR 0003: typed spellings, domain-separated signing — nine functions
became fifteen). Sections marked *(2026-09-09)* are new or re-verified; unmarked lines were
re-checked against the tree and still hold.

---

## 1. What the repository ships

*(2026-09-09)* archon ships **three tiers, each through three doors**: the identity
**floor** (`core/`), an **sdk** layer above it (`sdk/`, ADR 0004), and the **`archon`
command** (`cli/`). The sdk depends on the floor and on nothing else. The command depended
on the floor alone until 2026-09-10; **since `archon login` (#18, `5c8c54e`) it also names
the sdk**, whose login scheme it consumes and never re-implements (`cli/rs/Cargo.toml:24,27`
`archon-core` + `archon-sdk`; `cli/go/go.mod:14-17` `core/go` + `sdk/go`;
`cli/ts/package.json:25-26` `@bitspark/archon` + `@bitspark/archon-sdk`) — ADR 0006's
2026-09-10 status note; the rule is now *the floor and the sdk's login scheme, nothing else,
nothing outside this repository*. Every tier is written three times and pinned by its own
oracle — §2b, §2c, §3.

| tier | rust | go | typescript | pinned by |
|---|---|---|---|---|
| floor | `archon-core` 0.5.0 (`core/rs/Cargo.toml`), git tag `v0.5.0` | `github.com/Bitspark/archon/core/go`, tag `core/go/v0.5.0` | `@bitspark/archon` 0.5.0 (`core/ts/package.json:2-3`) | `vectors/identity.json` — 60 cases, 7 families, 180 case-checks |
| sdk | `archon-sdk` 0.5.0 (`sdk/rs/Cargo.toml:10-11`), same git, same tag | `github.com/Bitspark/archon/sdk/go` (`sdk/go/go.mod:1`), tag `sdk/go/v0.5.0` | `@bitspark/archon-sdk` 0.5.0 (`sdk/ts/package.json:2-3`) | `vectors/sdk.json` — 38 cases, 4 families, 114 case-checks *(36/108 until #21)*; *(2026-09-10, #19, #22)* `vectors/login.json` — 105 cases, 6 families, 315 case-checks (on `main` since `c8a772e` / `0515aa9`; published from v0.3.0) |
| cli | `archon-cli` 0.5.0, bin `archon` (`cli/rs/Cargo.toml:12-13,20`) | `github.com/Bitspark/archon/cli/go`, main at `cmd/archon`, tag `cli/go/v0.5.0` | `@bitspark/archon-cli` 0.5.0, bin `archon` (`cli/ts/package.json:2-3,13-15`) | `cli/smoke.mjs` — 107 invocations × 3 binaries on Linux, 95 on Windows (twelve POSIX-only password-file rows) *(28 until #18, 38 until #20, 74 until #36)*; `vectors/keystore.json` — 37 cases, 3 families, 111 case-checks |
| server *(2026-09-10, v0.4.0; now v0.5.0, with the offers form)* | `archon-server` 0.5.0 (`server/rs/Cargo.toml`), same git, same tag | `github.com/Bitspark/archon/server/go` (`server/go/go.mod:1`), tag `server/go/v0.5.0` | `@bitspark/archon-server` 0.5.0 (`server/ts/package.json:2-3`) | `server/testdata/login-wire.json` — key sets per route, the byte-for-byte authority payload (six damages), the malformed bodies; three suites (go 13 · rs 31 · ts 26) read it |

*(2026-09-10)* **ADR 0007 (archon#16) — all four parts in the tree by the evening.** The
`sdk/*/login` scheme (#19 `c8a772e`, #22 `0515aa9`) — §2b; `archon login` (#18 `5c8c54e`) —
§2c; both published from v0.3.0. The key store (#20 `a3d9abf`: `archon key
add|list|rm|default|export --reveal`, `keygen --store`, `$ARCHON_HOME/keys/<name>`, Argon2id +
XChaCha20-Poly1305, one 134-byte format across the three binaries pinned by
`vectors/keystore.json`) — §2c. The **fourth tier**, `server/go/login` (#25 `6c4c461`: a
mounted handler, law-free, in-memory TTL) — §2d, Go lane only so far. The last two are on
`main` and unreleased: the next lockstep cut carries them, with `server/go`'s tag line and a
non-critical ledger line. *(2026-09-11, #36 `9d830e5`)* `login --key <name>` with the store's
default as the fallback — the store's consumer, §A's last row — is in the tree; every part of
ADR 0007 is now true in it.

**Versioning of the tiers is ruled — ADR 0005 (2026-09-09): the sdk and the command version
with the floor** (one commit, one version, `vX.Y.Z` + `core/go/` + `sdk/go/` + `cli/go/` tag
lines, one `release-facts.<component>.json` each). **Current: v0.5.0 at `e6f95ea`** (2026-09-11)
— a minor: the prover-initiated form ships (`docs/login.md` §4.1, ADR 0007 §C.7) — the offer
routes in all three server lanes (#40) and `archon login` with no URL in all three command
lanes (#42 `7ba9926`); the wire fixture grew, the scheme's vectors did not. The v0.4.0 shape, checked in
the tag commit: five tags (`v0.5.0` + `core/go/` + `sdk/go/` + `cli/go/` + `server/go/v0.5.0`),
four templates declaring `v0.5.0` with placeholder digests, every version site at 0.5.0 across
the 23 the four tiers carry, the eight lockfiles, and `go.work`'s two version-pinned `replace`
lines; npm 0.5.0 ×4 with `gitHead e6f95ea` published before the tags by the workflow, the command
and the server carrying `^0.5.0` on both the floor and the sdk; the substrate capture dispatched
on the tag ref (run 34625499445, four cells green, `head_sha == e6f95ea`). Verified from outside the
checkout: `archon-sdk` and `archon-server` at tag `v0.5.0` build; `go get
server/go/login@v0.5.0` resolves `sdk/go v0.5.0` and `core/go v0.5.0` and `login.New` refuses a
non-canonical audience; `go install …/cli/go/cmd/archon@v0.5.0` into an empty `GOBIN` prints
`archon 0.5.0 (unknown)` and its usage names `--audience`; `npm i @bitspark/archon-server@0.5.0`
and `@bitspark/archon-cli@0.5.0` into empty directories pull the sdk and the floor at 0.5.0.
History: v0.4.2 (`7f1fea7`, 2026-09-11) shipped `archon login --key`; **v0.4.1 was published
and never tagged** (2026-09-11): its release commit `5c84030` passed every pre-tag check, but
the publish workflow's `cli` job failed at the smoke gate (the smoke mounts `server/ts` since
#36 and the job did not build it), the command package was then published by hand from a
worktree — where npm records no `gitHead` — and a package without `gitHead` cannot satisfy
the one-commit axis; npm is immutable, so the four 0.4.1 packages are pre-ledger orphans
like 0.2.0's, the workflow was fixed on `main`, and v0.4.2 was cut from that; v0.4.0 (`4c92507`,
2026-09-10) added the fourth tier — the server in three lanes — and the key store, the first
cut with five tags and four templates (`release-facts.server.json`: `archon-server`,
`typeIdentityCritical: false`, `substrateDeps` `archon` + `archon-sdk`); v0.3.0 (`e4bef63`)
shipped the login scheme and `archon login`, the first cut in
which the command named the sdk; v0.2.3 (`e1d9483`) was the first cut under the
template-first order; v0.2.2 (`8fd74e0`) the first lockstep cut, whose tag commit still
declared v0.2.1 (archon#14). The 0.1.0 sdk/cli packages published
2026-09-09 remain on the registries as pre-ledger artifacts. The command tier's own decision
record is ADR 0006; the `login` dependency is its 2026-09-10 status note.

**The floor** ships **one seam through three doors**. It is a **multi-language surface**, but of
an unusual kind: the three doors are not bindings over a shared core. They are three
independent implementations of the same encodings in three languages, held byte-identical
by a conformance oracle.

> "This is the whole reason archon is three implementations rather than one library with
> two bindings: a key spelled by the Rust core must be readable by the Go core, byte for
> byte, or the identity floor is not a floor."
> — `conformance/harness.mjs:10-12`

Curve arithmetic is **not** written three times. Each core binds its language's mature,
audited Ed25519; what archon writes three times is its **encodings**.
(`core/rs/Cargo.toml:8-12`, `README.md:57-61`)

| door | coordinate | evidence |
|---|---|---|
| rust | crate `archon-core`, git `https://github.com/Bitspark/archon`, tag `v0.5.0` | `substrate/release-facts.json`, `.github/workflows/publish-npm.yml` header |
| go | module `github.com/Bitspark/archon/core/go` | `core/go/go.mod:1`, `substrate/release-facts.json:11-13` |
| typescript | package `@bitspark/archon` on `https://npm.pkg.github.com` | `core/ts/package.json:2`, `core/ts/package.json:18-20` |

Rust is named **canonical** in-source when semantics are disputed
(`core/ts/src/crypto.ts:36` — "the canonical Rust core and the TS core admit exactly the
same signed-fact / Head evidence"). In practice the three cannot disagree: CI fails on the
first divergence.

The rust and go lanes publish by **git tag alone** — no workflow, no registry. Only the
npm lanes need a job, and its only credential is the automatic `GITHUB_TOKEN`.
*(2026-09-09)* `publish-npm.yml` now carries three jobs — `archon`, `sdk`, `cli` — the
latter two `needs: archon`. Each dependent keeps its committed
`"@bitspark/archon": "file:../../core/ts"` (`sdk/ts/package.json:24`,
`cli/ts/package.json:25`) and rewrites it to `^<floor version>` on the runner only, right
before `npm publish`, then installs its own package into an empty directory and probes it.
(`.github/workflows/publish-npm.yml:103-176` sdk, `:177-` cli; run 34394095124 on
2026-09-09 published both and passed both probes.)

---

## 2. The public surface — fifteen functions, four modules, three times

*(2026-09-09)* The floor grew under ADR 0003: every core now exports **fifteen functions
across four modules** — `crypto` 5 (`getPublicKey · sign · verify · signInDomain ·
verifyInDomain`), `hexbytes` 4 (`toHex · seedFromHex · pubkeyFromHex · signatureFromHex`),
`keytext` 2, `keycodec` 4. Verified by count on the TypeScript door:
`grep -c "^export function" core/ts/src/{crypto,hexbytes,keytext,keycodec}.ts` → 5, 4, 2, 4
(`core/ts/src/index.ts:6-9` re-exports exactly those four modules). Domain signing is
Ed25519ph with the caller's domain as the RFC 8032 context (`core/ts/src/crypto.ts:73,83`;
`README.md:125`). The three module tables below predate ADR 0003 and describe the original
nine; they are still true of those nine.

*(2026-08-26)* Every core exported **nine functions** across three modules. Verified by count:
`grep -c "^pub fn" core/rs/src/*.rs` → crypto 3, keycodec 4, keytext 2;
`grep -c "^export function" core/ts/src/*.ts` → 3, 4, 2;
`grep -n "^func [A-Z]" core/go/*/*.go` → 9 exported functions.

### 2.1 crypto — Ed25519 over canonical bytes (RFC 8032)

| | rust | go | typescript |
|---|---|---|---|
| derive | `public_key_from_seed(&[u8;32]) -> [u8;32]` | `PublicKeyFromSeed([]byte) []byte` | `getPublicKey(Uint8Array): Uint8Array` |
| sign | `sign(seed, message) -> [u8;64]` | `Sign(seed, message) []byte` | `sign(message, seed): Uint8Array` |
| verify | `verify(pubkey, message, signature) -> bool` | `Verify(pubkey, message, signature) bool` | `verify(signature, message, pub): boolean` |

`core/rs/src/crypto.rs:21,27,33` · `core/go/crypto/crypto.go:36,48,54` ·
`core/ts/src/crypto.ts:12,18,39`

Constants (rs, go only): `PUBLIC_KEY_SIZE`/`PublicKeySize` = 32, `SIGNATURE_SIZE`/
`SignatureSize` = 64, `SEED_SIZE`/`SeedSize` = 32.
(`core/rs/src/crypto.rs:14,16,18` · `core/go/crypto/crypto.go:25,28,31`)

Underlying library per core: `ed25519-dalek` v2 (`core/rs/Cargo.toml:26`), stdlib
`crypto/ed25519` (`core/go/crypto/crypto.go:20`), `@noble/ed25519` v3 +
`@noble/hashes` (`core/ts/package.json:24-27`).

### 2.2 keytext — the canonical key spelling

| | rust | go | typescript |
|---|---|---|---|
| encode | `encode_key(&[u8]) -> String` | `EncodeKey([]byte) string` | `encodeKey(Uint8Array): string` |
| decode | `decode_key(&str) -> Result<Vec<u8>,String>` | `DecodeKey(string) ([]byte, error)` | `decodeKey(string): Uint8Array` |

`core/rs/src/keytext.rs:18,34` · `core/go/keytext/keytext.go:30,38` ·
`core/ts/src/keytext.ts:15,29`

Form: `"ed25519:" + lowercaseHex(pubkeyBytes)`. (`core/rs/src/keytext.rs:9`,
`core/ts/src/keytext.ts:9`) Exactly one scheme exists today.
(`core/rs/src/keytext.rs:8`)

Decode accepts **either case** of hex but encode always emits lowercase
(`core/rs/src/keytext.rs:60-66` maps `a-f` and `A-F`; test at
`core/rs/src/keytext.rs:89-93` asserts uppercase decodes equal). Decode rejects: missing
prefix, odd-length body, non-hex character, decoded length ≠ 32.
(`core/rs/src/keytext.rs:36-55`)

### 2.3 keycodec — SPKI + PKCS#8 v1 PEM

| | rust | go | typescript |
|---|---|---|---|
| public → PEM | `pubkey_to_spki_pem` | `PubkeyToSPKIPEM` | `pubkeyToSpkiPem` |
| seed → PEM | `seed_to_pkcs8_pem` | `SeedToPKCS8PEM` | `seedToPkcs8Pem` |
| PEM → public | `spki_pem_to_pubkey` | `SPKIPEMToPubkey` | `spkiPemToPubkey` |
| PEM → seed | `pkcs8_pem_to_seed` | `PKCS8PEMToSeed` | `pkcs8PemToSeed` |

`core/rs/src/keycodec.rs:31,36,41,46` · `core/go/keycodec/keycodec.go:44,50,55,60` ·
`core/ts/src/keycodec.ts:29,34,39,44`

**The DER is a fixed-size template.** Encode is a constant prefix followed by the 32 key
bytes; decode is a bounded template match. No ASN.1 library in any core.
(`core/rs/src/keycodec.rs:5-7`, ADR 0002 at
`docs/architecture/decisions/0002-keycodec-is-a-byte-codec-not-key-custody.md:41-45`)

- SPKI prefix, 12 bytes → 44-byte DER:
  `30 2a 30 05 06 03 2b 65 70 03 21 00` (`core/rs/src/keycodec.rs:17-19`)
- PKCS#8 v1 prefix, 16 bytes → 48-byte DER:
  `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20` (`core/rs/src/keycodec.rs:23-25`)
- OID `1.3.101.112` = Ed25519, encoded `2b 65 70` (`core/rs/src/keycodec.rs:15-16`)
- Output framing: header line, exactly one base64 line (60/64 chars), footer, one trailing
  LF. (`core/rs/src/keycodec.rs:50-52`, test at `:193-198`)

base64 is **hand-rolled** in every core, deliberately: Node's `Buffer.from(_,"base64")`
silently strips invalid characters, so the strict accept/reject set would differ from
Go/Rust. (`core/ts/src/keycodec.ts:10-12`, `core/rs/src/keycodec.rs:92`)


---

## 2b. The layer above — `sdk/`: possession and the envelope *(2026-09-09)*

**Status:** ADR 0004, ACCEPTED 2026-09-09, re-ruling one subtraction of ADR 0001 — proof
of possession was cut as "kosmos's — protocol vocabulary, not a free-standing primitive";
measured, kosmos had **zero code files** and the pointer pointed at a spec.
(`docs/architecture/decisions/0004-the-sdk-layer-above-the-floor.md:3-16`)

**Why not in the floor:** the floor's identity is that vectors cover every function;
sockets, sessions and clocks cannot be pinned by byte vectors; and a proof of possession is
only correct with an input — the channel binding — that the floor cannot have.
(ADR 0004 `:18-21`)

**One dependency, the floor:** `sdk/rs/Cargo.toml:4,22` ("depends on archon-core and
nothing else"), `sdk/go/go.mod:8`, `sdk/ts/package.json:24`. `go.work` at the repo root
resolves `core/go` for `sdk/go` locally; consumers resolve the pseudo-versioned require
from GitHub (`go.work:1-4`, ADR 0004 `:69-70`).

### Two schemes, both signing in the caller's domain through `sign_in_domain`

| scheme | question it answers | signed bytes | refusals | evidence |
|---|---|---|---|---|
| **possession** | can they sign, *right now*, for *this channel*? | `0x01 ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖ binding` | nonce < 16 bytes; **empty binding** ("an unbound proof is not a proof"); either field > 0xffff | `sdk/ts/src/possession.ts:15,22-26,65-71`; ADR 0004 `:31-35` |
| **envelope** | these bytes, signed by this key, in this domain | `"arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ sig[64] ‖ payload`, `sig = sign_in_domain(seed, domain, 0x02 ‖ payload)` | bad magic; unsupported version; domain length 0 or > 255; **envelope claims a different domain**; signature does not verify; truncation | `sdk/ts/src/envelope.ts:7,27-31,52-54,74-94,102`; ADR 0004 `:37-41` |

`open` takes the domain the **verifier** expects and refuses an envelope claiming another —
the verifier chooses the domain, never the envelope; whether to trust the key it names is
the verifier's. (ADR 0004 `:39-41`) The one-byte scheme tags keep the two schemes from ever
being the same signed bytes in the same domain; pinned by `envelope_open /
possession-sig-rejected` (`vectors/sdk.json:350`, ADR 0004 `:43-45`).

### The surface per door

| | rust `archon_sdk::` | go `sdk/go/` | typescript `@bitspark/archon-sdk` |
|---|---|---|---|
| possession | `possession::{prove, verify, message_bytes, SCHEME_TAG, MIN_NONCE_SIZE, MAX_FIELD_SIZE}` (`sdk/rs/src/possession.rs:24-58`) | `possession.{Prove, Verify, MessageBytes, SchemeTag, MinNonceSize, MaxFieldSize}` (`sdk/go/possession/possession.go:31-64`) | `provePossession, verifyPossession, possessionMessageBytes, POSSESSION_SCHEME_TAG, MIN_NONCE_SIZE, MAX_FIELD_SIZE` (`sdk/ts/src/possession.ts:22-64`) |
| envelope | `envelope::{seal, open, message_bytes, MAGIC, VERSION, SCHEME_TAG}` (`sdk/rs/src/envelope.rs:25-103`) | `envelope.{Seal, Open, MessageBytes, Version, SchemeTag}` (`sdk/go/envelope/envelope.go:31-128`) | `seal, open, envelopeMessageBytes, ENVELOPE_MAGIC, ENVELOPE_VERSION, ENVELOPE_SCHEME_TAG` (`sdk/ts/src/envelope.ts:27-100`) |

Measured from the published package: `@bitspark/archon-sdk@0.1.0` installed into an empty
directory imports **12 exports** (the six functions and six constants above) — publish run
34394095124, and reproduced locally on 2026-09-09.

### Three lines, drawn at founding (ADR 0004 `:47-58`)

1. **Entropy, time and channel binding are arguments. The sdk never sources them.** No RNG,
   no clock, no socket — which is what makes every byte it emits a deterministic function of
   its inputs and therefore pinnable. Verified by grep on 2026-09-09: zero occurrences of
   `getrandom | crypto/rand | randomBytes | OsRng` in non-test source under `core/` and
   `sdk/`; three in `cli/`, all in `keygen` (§2c).
2. **JWS, never JWT.** In the envelope: version, domain, key, signature, payload. Out,
   permanently: expiry, issuer, audience, key-id, nonce — each either policy (whose clock,
   whose trust?) or a second spelling of the key, and both the consumer's.
3. **Connection setup stays out.** It *is* the transport. The sdk hands a server the bytes to
   move; it never opens a socket. (`README.md:137`)

### The login scheme — `sdk/*/login` *(2026-09-10, archon#19, `c8a772e`)*

*May this ephemeral key act as me, here, for this, for this long?* The third scheme, built
on possession: the person's key P proves to a service, unrelayably, that it agrees to let
one ephemeral browser key K act at one **audience** for one stated **scope** and **validity**;
the delegation payload itself is opaque here and belongs to the authority layer. Spec:
[`docs/login.md`](../docs/login.md) — the only document the scheme is defined in; ADR 0007 §C
names the constraints and cites §3.2 for the binding layout rather than restating it.

| rule | where |
|---|---|
| **the audience is derived, never transported** — the CLI takes it from the invocation URL (`<audience>/login/<id>`, the last two segments removed); the server recomputes every binding from its own configured audience; it appears in no message | `docs/login.md` §2 |
| **the derivation is part of the scheme, not of any CLI** *(2026-09-10, #22)* — `derive_audience(url) → (audience, id bytes)` in `sdk/*/login` accepts exactly one hand-written grammar (scheme `http`/`https`/`ws`/`wss` folded to `http(s)`, ASCII lowercased host, a port dropped only when it is the folded scheme's default, path segments kept as written and never decoded, a lowercase even-length hex id) and **refuses everything else rather than normalising it** — userinfo, query, fragment, empty or dot segments, non-ASCII, a penultimate segment other than `login`. Found at #18's review: three lanes with three URL parsers derived two different audiences from one URL, and the audience is the binding's first field | `docs/login.md` §2.1; `sdk/rs/src/login/audience.rs:22`, `sdk/go/login/audience.go:29`, `sdk/ts/src/login-audience.ts:22` |
| **the binding** `role ‖ u16 len ‖ audience ‖ K[32] ‖ u16 len ‖ id ‖ u16 count ‖ (u16 len ‖ entry)* ‖ u32 valid_for` — role `0x01` login proof by P, `0x02` collect proof by K; **scope and validity are inside the signed bytes**, so what the person approved is what the proof covers | §3.2 |
| **the proofs** are the possession scheme in domain `archon-login/1` over the server's nonce and that binding; a raw signature, another domain, the bare nonce, or the other role never verifies; `collect` is constructible only by the key the request names | §3.3 |
| scope entries: ordered UTF-8, 1..=65535 bytes each, no control characters (DEL included); `valid_for` a `u32 > 0`; the whole binding ≤ 65535 bytes | §3.1, §3.2 |
| a wrong-size seed is an **error**, not the floor's panic — the sdk-layer rule, ADR 0004's 2026-09-10 status note | `sdk/go/login/login.go:119-122` |
| *(2026-09-10, night, #35; server side built 2026-09-11, #40 `1048daa`)* **the prover-initiated form** — `docs/login.md` §4.1: the CLI starts by registering an *offer* (a code confidential until taken, the scope and validity it typed), the page begins a request naming it, the prover re-checks and answers without a confirmation; two routes and one member of **transport only** — the binding, the proofs and `vectors/login.json` are untouched. ADR 0007 §C.7. Built on both sides — the server in three lanes (#40, §2d) and the prover in three lanes (#42 `7ba9926`, §2c) — shipped in v0.5.0 | `docs/login.md` §4.1; `server/{go,rs,ts}`; `cli/{rs,go,ts}` |

| | rust `archon_sdk::login::` | go `sdk/go/login` | typescript `@bitspark/archon-sdk` |
|---|---|---|---|
| surface | `Request`, `binding`, `prove`, `verify`, `prove_collect`, `verify_collect`, `derive_audience`, `DOMAIN`, `ROLE_LOGIN`, `ROLE_COLLECT`, `MAX_FIELD_SIZE` (`sdk/rs/src/login.rs:23-161`, `login/audience.rs:22`) | `Request`, `Binding`, `Prove`, `Verify`, `ProveCollect`, `VerifyCollect`, `DeriveAudience` (`sdk/go/login/login.go:50-167`, `audience.go:29`) | `LoginRequest`, `loginBinding`, `proveLogin`, `verifyLogin`, `proveCollect`, `verifyCollect`, `deriveAudience`, `LOGIN_DOMAIN`, `LOGIN_ROLE_LOGIN`, `LOGIN_ROLE_COLLECT`, `LOGIN_MAX_FIELD_SIZE` (`sdk/ts/src/login.ts:24-151`, `login-audience.ts:22`, re-exported by `index.ts:17-18`) |

**Its oracle:** `vectors/login.json` — **105 cases in 6 families**: `login_audience` 47
*(#22)* · `login_binding` 18 · `login_prove` 7 · `login_verify` 23 · `login_collect_prove` 4 ·
`login_collect_verify` 6 (counted from the file, 2026-09-10; 58 in 5 families at #19). Derived by `vectors/tools/login-vectors.py` — a fourth, deliberately
naive implementation of the layouts outside the three lanes, every signature from OpenSSL
3.2.4 (`vectors/README.md`, the doctrine made reproducible; accepted by number in caa's
review). `conformance/check.mjs` runs the same three sdk CLIs over it — **315 case-checks**
(`conformance/check.mjs:111-113`; 174 before #22). The 47 `login_audience` cases were
independently re-derived at #22's review from §2.1's grammar alone, 47/47. **Independently re-derived at review:** all 7 positive
`login_binding` results recomputed by hand from §3.2 with a separate encoder (7/7), and all 4
positive proof signatures verified with the floor's `verifyInDomain` over a hand-assembled
possession message (4/4).

### Its own conformance

`vectors/sdk.json` — **38 cases in 4 families**: `possession_prove` 7 · `possession_verify`
12 · `envelope_seal` 6 · `envelope_open` 13 (counted from the file, 2026-09-10; 36 until #21
added `seed-short-rejected` to `possession_prove` and `envelope_seal`, so that a wrong-size
seed is a pinned **error** in every lane — Go `Prove`/`Seal` had inherited the floor's panic;
`sdk/go/possession/possession.go:46-47`, `sdk/go/envelope/envelope.go:52`; ADR 0004's
2026-09-10 status note). Proofs and envelopes are signatures, so expected values are
derived with OpenSSL 3.2.4 outside all three lanes (`vectors/README.md:40-46`). Three
conformance CLIs speak the same `conformance v1` protocol as the floor's
(`sdk/ts/conformance/cli.ts:2-9`); `conformance/check.mjs` builds them after the floor and
runs the harness over `sdk.json` — **114 case-checks** (`conformance/check.mjs:81-109`; 108
until #21). Measured 2026-09-10 (#22's CI, run on `0515aa9`): `all cores agree: 180
case-checks, 3 core(s)` then `all cores agree: 114 case-checks, 3 core(s)` then `all cores
agree: 315 case-checks, 3 core(s)` — 609 in all.

---

## 2c. The command — `cli/`: three binaries, one `archon` *(2026-09-09; `login` 2026-09-10)*

`archon <keygen|key|login|sign|verify|version> [args]` (`cli/ts/src/main.ts:19`; `cli/README.md:9`).
Three native binaries — `cli/rs`, `cli/go`, `cli/ts` — build the **same** command with
identical stdout and exit codes. A thin presentation + I/O layer over the floor and, for
`login`, over the sdk's scheme — never part of either library: they stay dependency-minimal,
the CLI's I/O lives here. (`cli/README.md:3-7`, `cli/rs/Cargo.toml:3`)

| subcommand | does | evidence |
|---|---|---|
| `key encode <pubkey-hex>` / `key decode <ed25519:…>` | raw bytes ⇄ the canonical key text | `cli/README.md:14` |
| `key pkcs8 encode <seed-hex>` / `decode` · `key spki encode <pubkey-hex>` / `decode` | a seed or public key ⇄ its PEM; `decode` reads stdin or `--in` | `cli/README.md:15-16` |
| `key pub [--in <pem>\|--seed <hex>] [--format spki\|text\|hex]` | the public key of a private key | `cli/README.md:17` |
| `keygen [--seed <hex>] [--out <pem>] …` | a key pair: public text on stdout, private PEM to `--out` or to stderr behind a SECRET warning | `cli/README.md:18` |
| *(2026-09-10, #20)* `keygen --store <name>` | generates and stores in one step; `--store` and `--out` are mutually exclusive (one keeps the seed, the other writes it out) | `cli/rs/src/cmd/keygen.rs:26-49` |
| *(2026-09-10, #20)* `key add <name> (--seed-file <f>\|--seed <hex>\|--pkcs8 <pem>)` · `key list [--json]` · `key rm <name> [--force]` · `key default [<name>]` · `key export <name> --reveal --out <file>` | the password-protected seed store, ADR 0007 §A: **refuses an existing name before asking for a password**; `list --json` prints `{name, principal}` from the header alone, no password; `export` **refuses without `--reveal`** and refuses stdout unless `--out -`; `rm` prints *"removed `<name>` (`<principal>`) from archon's store at `<path>`; any copy of this key outside it is untouched"*, and refuses a file that is not a key unless `--force`. Password: `--password-fd <n>`, then `ARCHON_KEY_PASSWORD`, then a prompt that refuses a non-terminal — **never argv**; *(#33)* a password **file** readable by group or others is refused on POSIX (`fstat` on the descriptor; pipes and Windows have no mode to check and say so). Files `$ARCHON_HOME/keys/<name>`, dir `0700`, file `0600`, temp-then-rename. Format (`docs/keystore.md` §2): `arck ‖ 01 ‖ u32 m ‖ u32 t ‖ u8 p ‖ salt16 ‖ pubkey32` (62) ‖ nonce24 ‖ XChaCha20-Poly1305(seed, aad = header) (48) = 134 bytes; Argon2id `m = 65536 KiB, t = 3, p = 1` shipping, read from the header never assumed. Its consumer, `login --key`, landed with #36 (the login row below). | `cli/README.md` (the store's rows and section, #33); `cli/rs/src/cmd/key_store.rs`, `cli/rs/src/keystore.rs:25-36`; `cli/go/cmd/archon/cmd_key_store.go`, `cli/go/internal/keystore/format.go`; `cli/ts/src/cmd/key_store.ts`, `cli/ts/src/keystore.ts:24-37`; `docs/keystore.md` |
| `sign (--key-file\|--seed) [--domain <d>] [--in <file>]` | sign the input bytes; `--domain` makes it domain-separated | `cli/README.md:19` |
| `verify --pubkey <ed25519:…\|hex> --sig <hex> [--domain <d>] [--in <file>]` | `valid` (exit 0) / `invalid` (exit 1) | `cli/README.md:20` |
| *(2026-09-10, #18; `--key` 2026-09-11, #36)* `login <url> [--key <name>\|--seed <hex>\|--key-file <pem>\|--seed-file <file>] [--authority-file <f>] [--yes]` | prove possession of your key to the service at `<url>` so the browser key it names may act for you, within a scope you are **shown before you sign** (ADR 0007 §C.5). **The store is the default custody** (#36): with no key flag, the store's default (`archon key default`) is used, and its absence is a refusal naming the four ways out; the source is decided at flag-parse time, a named key's existence is checked before the statement **without unlocking it**, the statement's last line reads *"signing with the store key `<name>`"* (pinned by `cli/testdata/login-statement.json`), and the seed is obtained — the password asked for — only after the person has said yes (`cmd_login.go:221-234`, `login.rs:227-239`, `login.ts:198-205`); the store's own password sourcing is reused, not copied, `--password-fd 0` refused without `--yes` because the confirm prompt reads stdin first. *(2026-09-11, #42 `7ba9926`)* **With no URL — `archon login --audience <base> --scope <entry>… --valid-for <seconds>` — the prover-initiated form** (`docs/login.md` §4.1, ADR 0007 §C.7), selected by the absence of a URL positional; the same order in all three lanes: the audience is the CLI's own (`--audience`, else `ARCHON_AUDIENCE`), checked as a fixed point of §2.1 by feeding `<audience>/login/00` through the scheme's derivation and refused at start otherwise; the code minted from the OS CSPRNG; the offer registered; **the code and the page address on stderr** (the page printed and marked *on the service's own origin* or *NOT — do not open it*, never opened); the offer polled with **one interval's sleep before the first poll**, `429` as sleep-and-retry; the paired request fetched, validated and **re-checked against what was typed** (scope entry for entry, in order; validity equal; K recorded, never checked); **only then the store unlocked** — the password asked for here and nowhere earlier (#41); the proof made and posted **with no confirmation**; and **the ledger on stdout** — audience, scope, validity as duration and wall-clock end, K's principal, the service's verdict — **never the code**, accepted or refused (`cmd_login.go:685-761`, `login.rs:747-812`, `login.ts:569-609`). The ledger is pinned across the three lanes by `login-statement.json`'s two `offer_cases`; the cross-binary smoke offers a login from every lane against the run's own server/ts handler and **plays the page from the code it reads off stderr**. The command owns transport (HTTP/JSON), display and flow; the audience is `derive_audience`'s (§2b) and the proof is the scheme's single `prove` call, reached through one seam per lane (`cli/rs/src/cmd/login.rs:521`, `cli/go/cmd/archon/cmd_login_scheme.go:31`, `cli/ts/src/cmd/login.ts:370`), with the id crossing it as bytes. A malformed request is refused before anything is displayed (id must echo the URL's, nonce ≥ 16 bytes, browser key canonical text, scope entries non-empty with no control characters and valid UTF-8, `valid_for > 0`); the statement names the key *source*, not the principal, so nothing is unlocked before consent (`login.rs:141-149`, `cmd_login.go:139-140`, `login.ts:127`); the authority payload is a file argument and opaque (no executable discovery); the statement text is pinned across the three lanes by `cli/testdata/login-statement.json`. Rust's transport is `minreq` + `serde_json` (chosen by measurement: +21 crates against ureq's +52/+69; `cli/rs/Cargo.toml:30-38`); Go and TypeScript use their standard libraries. | `cli/README.md:21` |

Every hex input goes through the floor's typed decoders: a 31-byte "public key" is refused
here exactly as the library refuses it (`cli/README.md:22-23`).

**The RNG lives here and in no pinned tier.** `keygen` without `--seed` draws from the OS
CSPRNG — `getrandom::fill` (`cli/rs/src/cmd/keygen.rs:136`), `crypto/rand`
(`cli/go/cmd/archon/cmd_keygen.go:138`), `node:crypto` `randomBytes`
(`cli/ts/src/cmd/keygen.ts:107`) — and since #20 the key store draws its salt and nonce (and
`keygen --store`'s seed) the same way (`key_store.rs:215-216,331`, `cmd_key_store.go:112,433-436`,
`key_store.ts:186-187,276`), exactly as ADR 0007 §Consequences predicted. The library takes a
seed it is given and never invents one (`cli/README.md:34-41`, ADR 0002). Grep-verified
2026-09-10: zero RNG sites in non-test source under `core/` and `sdk/`; the only others are
the server tier's ids and nonces (`server/go/login/login.go`, §2d), which is unpinned by
construction.

**Provenance:** `key` and `keygen` were carved out of thesmos's CLI tier on 2026-09-09
(`docs/growth-plan.md` §8.2); `sign` / `verify` are new and work on bytes.
(`cli/ts/src/main.ts:9-10`, `cli/README.md:25-32`). **Ownership ruled by the operator
2026-09-09** — *"maintain ownership of the extracted key commands"* — recorded as ADR 0006.

### The pin — `cli/smoke.mjs`

Builds all three binaries, runs **38 deterministic invocations** against each (28 until
#18), and asserts per case that the lanes agree with each other byte-for-byte on stdout and
exit code AND with the expected value — taken from `vectors/identity.json` or derived with
OpenSSL, never from a lane. Two edges are unpinned by design: `keygen` without `--seed`,
checked for shape only; and `login`'s network round-trip, which the smoke never makes — its
ten `login` cases are all pre-network (the usage text and nine refusals of the invocation
URL: no mount, wrong mount, too few segments, a foreign scheme, a query, a fragment, a flag
where the URL goes, an unknown flag), so they pin what the scheme's grammar refuses without a
server, and the proof itself is pinned in the sdk. (`cli/smoke.mjs:1-9,49-57,82-130`)
Measured 2026-09-10 on both CI legs at #18's head: `all lanes agree: 38 cases × 3 binaries`
(2026-09-09: 28). **Since #36 (`9d830e5`): `107 cases × 3 binaries` on Linux, `95 × 3` on
Windows** — the difference is the twelve POSIX-only password-file rows (owner-only accepted,
world-readable refused, per lane, on fd 0 and fd 3), read from the Linux smoke job's log by
`seat:cca` before the merge. #36 also made the smoke's login a **real cli↔server round trip**:
server/ts's `Handler` mounted over `node:http` (the `examples/serve.ts` bridge), every lane
logging in with `--key shared` from a key another binary sealed, the collected answer's
principal and proof checked against the oracle's key with the sdk's `verifyLogin`, never a
lane's output. **Since #20 (`a3d9abf`): `74 cases × 3 binaries`** — the key store's
cross-binary custody, which no same-lane round trip could show: one lane writes the key,
every lane lists it from the header without a password, the other two open it and the
recovered seed is checked through `key pub` against the oracle's public key; then the
refusals every lane owes (no `--reveal`, wrong password, duplicate name, the name rules), a
stray non-key file never listed and refused by `rm`, and the removal line itself, scrubbed of
the temp path so the pin is about wording (`cli/smoke.mjs:165-262`).

### The command's own oracle — `vectors/keystore.json` *(2026-09-10, #20)*

The store's file format is a byte contract across three binaries, so it is pinned the way the
sdk is: **37 cases in 3 families** — `keystore_seal` 6 · `keystore_open` 17 · `keystore_name`
14 (counted from the file). Salt, nonce and password are case **inputs** (the command sources
them; the format never does), which is what makes a sealed file a deterministic function of its
inputs and therefore pinnable. `conformance/check.mjs` runs a conformance driver of each
**command** lane over it — `all cores agree: 111 case-checks, 3 core(s)` (run 34508951807) —
the first oracle the command tier owns, beside the floor's 180, the sdk's 114 and the login
scheme's 315: **720 case-checks per push**. Independently re-derived at the post-merge review:
all 5 positive `keystore_seal` files, byte-for-byte, with the reference C Argon2id and
libsodium's XChaCha20-Poly1305 — neither a lane.

**The masthead's seed through the command:** `archon key pub --seed 11…11` (32 × `0x11`)
prints `ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` from all
three binaries — the same text the hero strip derives through the libraries. Verified
2026-09-09 (smoke case `key pub --seed (text)`, `cli/smoke.mjs:93`; and against the
published `@bitspark/archon-cli` in the publish run's clean-directory probe).

### Attach, verified from outside the checkout (2026-09-09)

*(the §2d server tier follows the attach table; it has no door until the cut that tags it)*

| door | command | verified |
|---|---|---|
| rust, sdk | `archon-sdk = { git = "https://github.com/Bitspark/archon", tag = "v0.5.0" }` | at `v0.5.0` and `v0.3.0` a fresh crate builds and reaches `archon_sdk::login::derive_audience`, lockfile declares the tag's version; at `v0.2.1` it declared 0.1.0 (the skew ADR 0005 closed) |
| rust, cli | `cargo install --git https://github.com/Bitspark/archon --tag v0.5.0 archon-cli` | at `v0.2.1`: installed `bin/archon`, `archon --help` prints the usage line |
| rust, server *(v0.5.0)* | `archon-server = { git = "https://github.com/Bitspark/archon", tag = "v0.5.0" }` | a fresh crate builds and reaches `archon_server::Handler::new` (2026-09-10) |
| go, sdk | `go get github.com/Bitspark/archon/sdk/go/login@v0.5.0` | resolved `sdk/go v0.5.0` + `core/go v0.5.0`; `login.DeriveAudience` runs (2026-09-10; the same at v0.3.0) |
| go, server *(v0.5.0)* | `go get github.com/Bitspark/archon/server/go/login@v0.5.0` | resolved `server/go v0.5.0` + `sdk/go v0.5.0` + `core/go v0.5.0`; `login.New` refuses a non-canonical audience naming the canonical spelling (2026-09-10) |
| go, cli | `go install github.com/Bitspark/archon/cli/go/cmd/archon@v0.5.0` (`cli/README.md:48`); from a clone, `go build -o archon ./cli/go/cmd/archon` (`cli/README.md:47`) | into an empty `GOBIN` → `archon.exe`, `archon 0.5.0 (unknown)`, `key list` on an empty store (2026-09-10; 0.3.0, 0.2.3 and 0.2.2 likewise) |
| *(superseded row)* | | | *(lane 4, seat:cca ruling 2026-09-09)* the main package moved from the module root to `cli/go/cmd/archon` **because** `go install …/cli/go@main` named the binary `go` — a toolchain-shadowing hazard, fixed by layout rather than docs (`cli/README.md:54-58`). Verification of the install into an empty `GOBIN` is recorded in the lane-4 commit message. |
| ts, sdk | `npm i @bitspark/archon-sdk` | empty dir → 0.1.0, floor 0.2.1 from the registry, 12 exports |
| ts, cli | `npm i @bitspark/archon-cli` | empty dir → `node_modules/.bin/archon`; `npx --no -- archon key pub --seed <seed-11>` = oracle text |
| ts, server *(v0.5.0)* | `npm i @bitspark/archon-server` | empty dir → 0.5.0, pulls `@bitspark/archon-sdk` 0.4.0 and `@bitspark/archon` 0.4.0; `new Handler({audience})` refuses a non-canonical audience (2026-09-10) |

All three dependents at 0.4.2 carry `"@bitspark/archon": "^0.4.2"` on the registry, and the
command and the server also carry `"@bitspark/archon-sdk": "^0.4.2"` (`npm view`, 2026-09-11)
— the publish-time rewrite of the committed `file:` links (§1; #23 and #30 for the sdk
ranges).

---

## 2d. The server tier — `server/{go,rs,ts}` *(2026-09-10; go #25 `6c4c461`, rs #28 `9af1853`, ts #29 `8214689`, the byte pin #31 `284a04a`; shipped in v0.4.0)*

The service side of the login protocol (`docs/login.md` §4), ADR 0007 §B: a **mounted
handler**, not a server — `go get github.com/Bitspark/archon/server/go/login@v0.4.2`,
`archon-server` at tag `v0.4.2`, `npm i @bitspark/archon-server`. Unpinnable by an oracle by
construction (a clock, a store, the service's socket), so its pin is three suites reading one
fixture, `server/testdata/login-wire.json`: the JSON **key sets** per route with `audience` a
forbidden key on every response; an **authority payload the three lanes must carry
byte-for-byte** — stored as a string so no lane parses it, six damages a re-encoding does
(integer at 2⁵³, a trailing zero, an escape, key order, compacted whitespace, HTML escaping)
asserted separately; and the **malformed bodies** every lane refuses the same way (a repeated
top-level key, on `begin` and on `answer`).

*(2026-09-11, #40 `1048daa`)* **The prover-initiated form, server side — built in three lanes
at once** (`docs/login.md` §4.1, ADR 0007 §C.7): `POST /login/offers` and `GET
/login/offers/<code>`, the `offer` member on `begin`; **one code predicate behind three routes**
with the ruled split (a malformed code is `400` on the offer route, `404` on read and begin so
a stranger learns nothing); `page` shipped as `<page>#<code>`, a configured page already
carrying a fragment refused at construction (`server/go/login/login.go:184`,
`server/rs/src/lib.rs:343`, `server/ts/src/login.ts:222`); **one offer, one request** — the take
in one critical section per lane, `409` for the second; an offer dying with its request or at
its own expiry; the offer route **unpaced** (no timer touched on read); an `offer` member that
is present but not a string — `null` included — a malformed body, `400` in all three (go had
read `null` as absent, ts as an unknown code: the last divergence the fixture could not see,
pinned as two `malformed_bodies` cases). `login-wire.json` carries the two routes' key sets and
forbidden keys, six error codes, the five-case `offer_mismatch` family (extra, reordered,
changed, dropped entry; changed validity) and the malformed offer body; the seven offer tests
carry the same names in go, rs and ts, and the fixture was committed first so every lane was
written to it. The prover's side — `archon login` with no URL, all three command lanes — landed
the same day (#42 `7ba9926`, §2c's `login` row). Both sides shipped in v0.5.0.

| rule (ADR 0007 §B) | in the tree |
|---|---|
| **opens no socket, starts no goroutine** — an `http.Handler` mounted under any prefix, routes relative to the mount: `POST ""` begin · `GET /<id>` read · `POST /<id>/answer` answer · `GET /<id>/answer` collect; `Sweep()` is optional and caller-driven | `server/go/login/login.go:193-234` |
| **the audience is configured and never read from the wire, in either direction** — every binding is recomputed by the scheme from the stored request and `Config.Audience`; no response carries an audience (the fixture forbids the key); and `New` **requires the configured audience to be a fixed point of `DeriveAudience`** — `https://Dawn.example/api`, `…:443`, `wss://…` are startup errors naming the canonical spelling, since each would make the CLI bind a different string and every proof fail silently | `login.go:140-165`; `server/testdata/login-wire.json` |
| **law-free** — `AdmitAuthority(browser, principal, authority json.RawMessage) error` is the only reader of the payload; nil means the proof suffices; archon ships no implementation | `login.go:75` |
| **store-minimal** — one in-memory record, expiry enforced on read, unknown and expired both `404 expired_token` and indistinguishable, dropped on collection, nothing persisted | `store.go` |
| **verify before store; consumed by the first verified answer** (`409`); a failed proof or a refused authority writes nothing; the law's callback runs outside the store mutex, with the consumed-check repeated under the lock | `login.go:349-430` |
| **the poll proves K**, and an unverified poll leaves no trace: the interval is read, the collect proof verified, and only then the timer advanced — in the same critical section that takes the answer and drops the record, so it is handed over once under concurrency | `login.go:441-492`, `store.go:136-180` |
| RFC 8628 vocabulary verbatim; bodies bounded at 64 KiB, unknown fields and trailing content refused; `Clock` and `Entropy` injected (`time.Now`, `crypto/rand` by default); *(#32)* the collect response's `Content-Type: application/json` and `Cache-Control: no-store` asserted in all three lanes | `http.go`, `login.go:81-96` |

Surface: `New(Config) (*Handler, error)`, `Config{Audience, Admit, TTL, Interval, Clock,
Entropy}`, `AdmitAuthority`, `Handler.ServeHTTP`, `Handler.Sweep`, `CollectHeader`
(`"Archon-Collect"`), `DefaultTTL`, `DefaultInterval` (`login.go:57-193,433`). Depends on the
floor and the sdk and nothing else (`server/go/go.mod`). CI: `server fmt + vet + test` in the
`go` job since #25. The tier's ledger line (`release-facts.server.json`, non-critical) and tag
line arrive with the next cut (ADR 0005, ADR 0007 §Consequences).

*(2026-09-10, #28, `9af1853`)* **Rust lane — `archon-server` (`server/rs`)**: the same rules,
framework-free by construction — `Handler::handle(&Request) -> Response` over bytes
(`server/rs/src/routes.rs`), a plain `http` adapter (head parser, mount stripped exactly, body
cap enforced before the body is read; `src/http.rs`), `examples/serve.rs` a mount on a bare
`TcpListener` that CI compiles (`--all-targets`). Surface: `Handler::new(Config) ->
Result<Handler, String>`, `Config::new(audience).admit(..).clock(..).entropy(..)`,
`Handler::handle`, `Handler::sweep`, `COLLECT_HEADER` (`"archon-collect"` — header names are
case-insensitive on the wire), `DEFAULT_TTL_SECS`, `DEFAULT_INTERVAL_SECS`
(`src/lib.rs:37-242`). 27 tests read the same `login-wire.json`. Dependencies, by number:
the floor and the sdk, `serde` + `serde_json` (+ `serde_path_to_error`) as the JSON transport
codec, `getrandom` as the entropy default (`server/rs/Cargo.toml`) — the Rust spellings of
Go's standard library, none reaching `core/` or `sdk/` (ADR 0007 landings note).

*(2026-09-10, found at #29's review, closed by #31)* **One property the fixture could not
hold, now ruled and pinned: the authority payload is opaque bytes.** All three lanes rewrote
it somewhere — rs through `serde_json::Value` (keys sorted, floats normalised), ts through
`JSON.parse`/`stringify` (the same plus 2⁵³ integer loss), and go, the reference, at collect
through `json.Encoder` (whitespace compacted, `&<>` HTML-escaped). One answer, three
payloads. Same bytes in, same bytes out, in every lane: rs `serde_json::value::RawValue`,
ts the exact source span of the member (`server/ts/src/json.ts` `authoritySpan`), go a
hand-built collect body that splices the bytes (`server/go/login/http.go` `writeCollected`);
`login-wire.json`'s `authority_roundtrip` holds it in all three, and restoring any of the
three encoders turns that lane's case red.

*(2026-09-10, #29 `8214689`)* **TypeScript lane — `@bitspark/archon-server` (`server/ts`)**: a
fetch-style `Handler` over the platform's `Request`/`Response` (`server/ts/src/login.ts:136`),
`examples/serve.ts` the `node:http` bridge that CI builds; deps the floor and the sdk as
`file:` links and nothing else — the cleanest manifest of the three. Surface: `new
Handler(Config)`, `Handler.handle(Request): Promise<Response>`, `Handler.sweep`,
`COLLECT_HEADER`, `DEFAULT_TTL_SECONDS`, `DEFAULT_INTERVAL_SECONDS`, `AdmitAuthority`,
`Clock`, `Entropy` (`login.ts:42-136`). The `await` on the law's callback is the only
interleaving and the re-fetch with the checks repeated after it is the whole rule; `collect`
is synchronous, so interval → verify → timer → take is one step by construction. 26 tests
read the fixture.

## 3. What is proven, and how

### 3.1 The oracle

`vectors/identity.json` — **30 cases in 4 families**, version 1.
Counts verified by reading the file: `pubkey_from_seed` 3, `key_encode` 3, `keycodec` 15,
`signature_verify` 9. (`vectors/README.md:6-11`)

Provenance: copied from thesmos `vectors/authority.json` @ `d878832` on 2026-08-22.
(`vectors/identity.json` → `provenance`)

**Expected values are hand-authored from the standards, never captured from a core.**
"A vector copied out of an implementation pins whatever that implementation does, bugs
included; a vector derived from the standard pins the standard, and lets all three cores be
wrong together and be caught." (`vectors/README.md:36-40`)

### 3.2 The harness

`conformance v1`, inherited from thesmos ADR 0006. A CLI is invoked as `<cli> <family>`,
receives the whole oracle on stdin, recomputes each result **ignoring the expected value**,
and writes one NDJSON line per case to stdout in input order.
(`conformance/README.md:19-23`, `conformance/harness.mjs:14-17`)

- Comparison is **canonical JSON**, keys sorted recursively, so a core's key order can
  never be what passes or fails. (`conformance/harness.mjs:38-42`)
- Each case's `name` is asserted **positionally**, so a drop-plus-duplicate — which
  preserves the count — cannot slip past. (`conformance/harness.mjs:45-47,95-99`)
- The harness knows nothing of any core's language or internals; it spawns black boxes and
  reads NDJSON. (`conformance/harness.mjs:7-8`)

One command: `node conformance/check.mjs` builds all three cores and runs the harness.
Paths derive from the script's own location, not cwd. (`conformance/check.mjs:14-17`)
It bootstraps `npm ci` for the TS core if `node_modules` is absent, because a fresh clone
running the advertised command previously died on a raw `MODULE_NOT_FOUND` stack.
(`conformance/check.mjs:37-41`)

### 3.3 Verified live, 2026-08-26

Run by the poster author, not quoted from the README:

```
$ node conformance/check.mjs
build go … ok
build rs … ok
build ts … ok

ok   …/bin/conformance-go.exe pubkey_from_seed (3)
…
all cores agree: 90 case-checks, 3 core(s)
[exited with code 0]
```

30 cases × 3 cores = **90 case-checks**. (`.github/workflows/conformance.yml:112-114`)

**Round-trip probe, all three cores, seed `11…11` (32 bytes):**

| stage | go | rs | ts |
|---|---|---|---|
| `pubkey_from_seed` | `d04ab232…778737` | identical | identical |
| `key_encode` | `ed25519:d04ab232…778737` | identical | identical |
| `keycodec/encode_spki` | `-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=\n-----END PUBLIC KEY-----\n` | identical | identical |

**Independent standards check:** `openssl pkey -pubin -text -noout` on archon's SPKI PEM
output reports `ED25519 Public-Key: d0:4a:b2:32:…:87:37` — the PEM is a genuine standard
container, readable by a tool that has never heard of archon.

### 3.4 The divergence the harness catches — verified live

`signature_verify/small-order-pubkey-order8` and `…-order4` pin a small-order (torsion)
public key with signature `R=A, S=0` as **rejected**.

Demonstrated by the poster author against the installed `@noble/ed25519`:

```
small-order-pubkey-order8
   @noble default (zip215:true) -> true
   archon crypto.verify          -> false   | oracle expects false
small-order-pubkey-order4
   @noble default (zip215:true) -> true
   archon crypto.verify          -> false   | oracle expects false
```

`@noble/ed25519` defaults to ZIP-215 (cofactored) verification, which **accepts** such
keys; Go's `crypto/ed25519` and `ed25519-dalek` v2 **reject** them. The TS core passes
`{ zip215: false }` to restore RFC 8032 semantics and tri-core parity.
(`core/ts/src/crypto.ts:32-37,42`)

Without that flag the same signature would be **valid in TypeScript and invalid in Rust**.
The vector note records the mechanism: "S=0 makes the verification equation [8](S·B) =
[8](R + h·A) collapse since R=A is order-8 and h·A is also torsion."
(`vectors/identity.json` → `signature_verify` → `small-order-pubkey-order8.note`)

`non-canonical-s` (S replaced by S+L) is also pinned false; all three libraries already
agreed there. (`vectors/identity.json` → `signature_verify` → `non-canonical-s.note`)

### 3.5 Rejection is pinned; the reason is not

Of 15 `keycodec` cases, **11 are rejections**: wrong length on encode, PKCS#8 v2, wrong OID
(X25519), short key, non-zero BIT STRING unused-bits octet, trailing garbage, bare DER
without armor, bad base64, and both cross-template directions. "A codec that differs on what
it *refuses* is a codec that differs."
(`docs/architecture/decisions/0002-keycodec-is-a-byte-codec-not-key-custody.md:47-52`)

The reject **reason** is deliberately not pinned — the harness compares `{"error":true}`.
"A core's error message is its own diagnostic; the reject *decision* is what must agree."
(`…/0002-…md:54-56`, `conformance/harness.mjs:57`)

### 3.6 CI

`.github/workflows/conformance.yml` runs on every push to main and every pull request.
*(2026-09-09)* Seven jobs: `rust` (fmt, clippy `-D warnings`, `cargo test --locked`), `go`
(gofmt, vet, test), `ts` (npm ci, build, test — now also builds and tests `sdk/ts` and builds
`cli/ts` through their `file:` links), `conformance` (three oracles, 180 + 114 + 315),
`cli-smoke` (38 × 3 since #18; 107 × 3 since #36; 141 × 3 on Linux since #42), and the two required Windows legs `conformance-windows` and
`cli-smoke-windows`.

*(2026-09-11, #45 `e6415f1`)* **Where the jobs run:** the nine Linux jobs of `conformance.yml` and
`publish-npm.yml` run on the org's shared self-hosted fleet (`runs-on: ubuntu-latest
the same pool the substrate and atlas legs have used since founding; the two Windows legs stay on
GitHub-hosted runners because the fleet is Linux. The indirection is the org kill switch: deleting
`CI_RUNNER` reverts every Linux job to hosted at once. Verified at merge from the jobs API (each
Linux job on a `shunter-pool-r*` runner, the Windows legs on GitHub's). Before #45 archon's own
CI was hosted, which is why the 2026-09-11 Actions billing wall stopped it while the substrate
cells kept seating (`.github/workflows/conformance.yml`, `publish-npm.yml`; `README.md` "CI runners"). (`.github/workflows/conformance.yml:123-136,138,166,202,228`) The
`cli smoke (windows)` leg first ran red because `ad0b8aa` had committed a 3.2 MB
`cli/go/go.exe` (a bare `go build` in a directory named `go`) that shadowed the toolchain on
the runner; `78f69b4` untracked and ignored it, and the leg is green on `main`
(run 34394719692).

The Windows leg was **promoted to blocking on measurement, not elapsed time**: 17 of 17
runs passed it, confirmed by reading per-job status rather than the badge — "with
continue-on-error the JOB's failure never reaches the WORKFLOW's conclusion, so a green
badge on this file was never evidence about this leg."
(`.github/workflows/conformance.yml:126-137`)

**CI needs no credential to build archon**, because archon depends on nothing private.
(`.github/workflows/conformance.yml:11-14`) Publishing is isolated in a separate file so
that claim cannot be quietly weakened by a later edit.
(`.github/workflows/publish-npm.yml:19-22`)

---

## 4. Dependencies

**Runtime, in full (floor):** `ed25519-dalek` (rust) · **none**, stdlib only (go) ·
`@noble/ed25519` + `@noble/hashes` (typescript).
(`core/rs/Cargo.toml:26`, `core/go/go.mod`, `core/ts/package.json:24-27`)

*(2026-09-09)* **sdk:** the floor and nothing else (`sdk/rs/Cargo.toml:22`,
`sdk/go/go.mod:8`, `sdk/ts/package.json:24`). **cli** *(amended 2026-09-10, #18)*: the floor
**and the sdk** (`cli/rs/Cargo.toml:24,27`, `cli/go/go.mod:14-17`, `cli/ts/package.json:25-26`)
— `login` consumes the sdk's scheme and never re-implements it — plus, in the Rust binary
only, `getrandom` for `keygen` and `minreq` + `serde` + `serde_json` as `login`'s HTTP/JSON
transport (`cli/rs/Cargo.toml:29-38`; the scheme is bytes, so nothing security-bearing
depends on the JSON codec); `cli/go` and `cli/ts` use their standard libraries for all of it.
Until #18 the command did not depend on the sdk; ADR 0006's status note records the change
by number. *(2026-09-10, #20)* **Custody's dependencies, the command's first outside the
repository, named by ADR 0007 §A:** rust `argon2`, `chacha20poly1305`,
`unicode-normalization` (the NFC rule), `rpassword` (a prompt that does not echo); go
`golang.org/x/crypto` (`argon2`, `chacha20poly1305.NewX`), `x/text` (NFC), `x/term`; ts
`@noble/ciphers` + `@noble/hashes` (`cli/rs/Cargo.toml`, `cli/go/go.mod`,
`cli/ts/package.json:25-28`). None reach `core/` or `sdk/`. Rule as now stated in ADR 0006's
corrected note: no archon-internal edge beyond the floor and the sdk's login scheme; external
runtime dependencies only those §A names for custody and the Rust lane's login transport.
**server** *(#25, #28, #29)*: go — the floor and the sdk, stdlib `net/http` (`server/go/go.mod`);
rs — the floor and the sdk, `serde` + `serde_json` (`raw_value`) + `serde_path_to_error` as
the transport codec, `getrandom` as the entropy default (`server/rs/Cargo.toml`); ts — the
floor and the sdk as `file:` links and nothing else (`server/ts/package.json`).

`serde_json` is present in the Rust manifest but **optional and off by default**, gated
behind the `conformance-cli` feature so the published library keeps exactly one dependency.
(`core/rs/Cargo.toml:28-34`)

**Constellation dependencies: none.** `atlas.json` declares `"dependsOn": []`.
(`atlas.json:8`) Verified: no core source file imports thesmos, ontos or logos — the only
occurrences of those names in `core/*/src` are prose comments explaining the absence.

---

## 5. Rules, boundaries, negative space

| rule | statement | evidence |
|---|---|---|
| **no authority** | archon has no opinion about what any identity may *do*. `is_root`, admission, grants are thesmos's. Verified: zero occurrences in code — only in comments saying so. | `core/rs/src/lib.rs:5-7`, grep audit |
| **verify fails closed** | Every shape failure — wrong-sized key or signature, malformed point — collapses to `false`. Never panics, never throws. | `core/rs/src/crypto.rs:32-33`, `core/go/crypto/crypto.go:52-53`, `core/ts/src/crypto.ts:25-27` |
| **…and that is the point** | Go's stdlib `ed25519.Verify` **panics** on a wrong-sized public key, making every unguarded call site a latent crash. thesmos repeats that guard by hand at each authority site. Writing it once, pinned, is what archon exists to own. | `core/go/crypto/crypto.go:5-10` |
| **derive panics on a bad seed** | `PublicKeyFromSeed` panics if `len(seed) != 32` — "a programming error, not a runtime condition to handle". Asymmetric with `Verify` on purpose. | `core/go/crypto/crypto.go:33-39` |
| **no custody** | keycodec holds no key, reads no file, writes no file, draws no randomness. No RNG: `seedToPkcs8Pem` takes a seed it is *given*; it never invents one. | ADR 0002 `:33-40` |
| **custody lives elsewhere** | Key *generation* is custody, and custody lives in `stele`. | ADR 0002 `:39-40` |
| **PKCS#8 v1 only** | v2 (with embedded public key) is rejected. | `core/rs/src/keycodec.rs:8`, vector `decode-pkcs8-v2-rejected` |
| **decode is PEM-only and total** | Bare DER is rejected; any unrecognised shape is a clean error. | `core/rs/src/keycodec.rs:7-8`, vector `decode-spki-bare-der` |
| **no rotation** | The key **is** the principal by construction. There is rotation; there is no rotation-preserving identity. Loss or compromise means re-genesis. | ADR 0001 `:22-24` |
| **the doors are not signature-compatible** | Argument order and error style differ per language *by design*: rs `verify(pubkey,msg,sig)` vs ts `verify(sig,msg,pub)`; rs `sign(seed,msg)` vs ts `sign(msg,seed)`; rs returns `Result`, go returns `error`, ts **throws**. The cores agree on **bytes**, not on call shapes. | §2 tables above |

### Explicitly does NOT own

| | why | evidence |
|---|---|---|
| succession / rotation / epoch | thesmos ADR 0023 owns it; re-ruled independently as Q17 shape (b) | `README.md:110`, ADR 0001 `:25` |
| "the principal" | the key is the principal by construction — nothing distinct to own | ADR 0001 `:23-24` |
| proof of possession — the **protocol** | the `ClientHello` handshake, the custody-mode discriminator, the connection itself: kosmos's. *(2026-09-09)* The **scheme** — what is signed, with what binding — was **re-ruled into archon's sdk** by ADR 0004, because kosmos had the vocabulary and no code. §2b. | `README.md:152`, ADR 0004 `:4-16` |
| connection setup | it *is* the transport; the sdk hands a server the bytes to move and never opens a socket | ADR 0004 `:57-58`, `README.md:137` |
| expiry, issuer, audience, key-id | policy, or a second spelling of the key — out of the envelope permanently (JWS, never JWT) | ADR 0004 `:54-56` |
| `PLACEHOLDER_ROOT` | a root trust-anchor *designation* — authority vocabulary. Removed from all three cores; thesmos keeps it and pins it *through* archon's derivation | `README.md:113`, ADR 0001 `:27` |
| authority predicates | `is_root`, admission, grants | `README.md:114` |
| ~~a principal type / PoP envelope~~ | *(2026-09-09)* **superseded** — the signed envelope now ships in the sdk (§2b). ADR 0002's "no tier would" was written before ADR 0004 re-ruled it. | ADR 0002 `:73-78` → ADR 0004 |
| the Merkle inclusion primitive | argued for, then **withdrawn** after refutation | `docs/extraction-plan.md` §4b, ADR 0001 `:28` |

---

## 6. When NOT to adopt archon — the repo's own counter-case

The sharpest honest fact in the repository, and it argues *against* the product.

`logos/helpers/leaf-signature` needs Ed25519 and cannot import thesmos (cycle). archon
asked whether it should be the backend and **sent its own answer — no — as the question**.
logos's maintainers confirmed it with measurements:

| at the logos seam | count |
|---|---|
| key / signature types | raw `&[u8]` — 32-byte key, 64-byte sig |
| hand-authored vectors carrying a signer | 0 |
| SPKI / PKCS-8 / PEM anywhere in logos | 0 |
| `ed25519:<hex>` spellings | 0 |

> "logos already has a canonical byte→text spelling (`wire.rs`, `to_hex`). Adding
> `ed25519:<hex>` beside it would **create** the second spelling archon exists to prevent.
> *One canonical spelling instead of three* argues for archon in a repo with zero, and
> against it in a repo with one."
> — `docs/extraction-plan.md` §4, `README.md:35-41`

**The general rule:** archon's value is not universal. It replaces *N* spellings with one.
In a repo that already has exactly one, it adds a second. The case must be made per
consumer against what that consumer already has.

---

## 7. Status — founded, switched, grown

*(2026-09-11, later)* **v0.5.0 across four tiers** at `e6f95ea` — the prover-initiated form
published on both sides, a minor with the v0.4.0 shape (§1). v0.4.2 at `7f1fea7` shipped
`archon login --key`; v0.4.0 at `4c92507` (2026-09-10)
shipped the server tier in three lanes and the key store, five tags, four ledger lines; v0.3.0 at `e4bef63`
shipped the login scheme and `archon login`; v0.2.3 at `e1d9483` was the first cut under ADR
0005's template-first order, v0.2.2 at `8fd74e0` the first lockstep cut (§1). **The switch is done:** stele and thesmos link these bytes; stele merged
1726bb9 and every consumer is on the floor at v0.2.1 or later. The sdk and the command were
first published at 0.1.0 earlier that day (run 34394095124) and re-published at 0.2.2 from
the tag. The command tier is recorded as ADR 0006; the operator's rulings of 2026-09-09 —
key commands stay archon's; Merkle and the root designation do not enter — are in §5 and
in growth-plan §6.3/§10 verbatim. *(2026-09-10, night)* **ADR 0007 is four parts built of
four, all released:** the login scheme (#19, #22) and `archon login` (#18) shipped in v0.3.0;
the key store (#20) and the server tier in three lanes (#25 go, #28 rs, #29 ts, #31 the byte
pin) shipped in v0.4.0 at `4c92507`, with the `server/go` tag line and the non-critical
`release-facts.server.json`; `login --key` (#36, `9d830e5`) ships in v0.4.1. Nothing ruled
under ADR 0007 is unbuilt; §4.1's prover-initiated form (ruled #35) shipped in v0.5.0 (#40 the server side, #42 `7ba9926` the prover's).

Source excluding tests, 2026-09-09: floor rs 654 · go 327 · ts 368; sdk rs 331 · go 212 ·
ts 201; cli rs 597 · go 676 · ts 502 lines.

*(2026-08-26)* **Status: founded.** (`README.md:15`) Three cores, a published dependency list, a
conformance harness run on every push.

What remains unpaid is **the switch**: ADR-0005 per-language pins and a skew window while
thesmos moves onto these bytes. The copy is **non-destructive** — thesmos keeps its own
copy, and nothing breaks until someone deletes it. "Copying was never the risk; switching
is." (`README.md:154-157`, `vectors/README.md:42-44`)

Measured consumer coupling that motivated the repo: **stele imports thesmos in 24 sites
purely for keys and crypto** — none of which mentions `is_root`, `grant` or `authorized`.
A node daemon verifying a read request links the authority contract to do it.
(ADR 0001 `:57-66`)

Repository scale: 48 commits; source excluding tests is rust 454 lines, go 216, typescript
241.

---

## 8. Editorial tiers

### Thesis-critical (consumer)
- One seam, three independent implementations, not bindings. (§1)
- Fifteen functions per language across crypto / hexbytes / keytext / keycodec. (§2)
- *(2026-09-09)* Two things stand on the floor — the sdk (possession + envelope + login) and
  the `archon` command — each written three times, each pinned by its own oracle; the sdk
  depends on the floor and nothing else, the command on the floor and the sdk's login scheme
  *(since 2026-09-10)*, and nothing on anything outside the repository. (§1, §2b, §2c)
- The guarantee: same bytes in all three languages, proven not asserted. (§3)
- Curve arithmetic is never rewritten; encodings are. (§1)

### Differentiating proof (consumer)
- **The ZIP-215 divergence**, demonstrated live: `@noble` default says `true`, archon says
  `false`, Rust and Go say `false`. (§3.4) ← strongest single fact in the repo
- The oracle is hand-authored from RFCs, not captured from an implementation. (§3.1)
- 11 of 15 keycodec cases are **rejections**. (§3.5)
- One guarded `verify` written once, where Go's stdlib would panic. (§5)
- openssl reads archon's PEM. (§3.3)
- *(2026-09-09)* The sdk is deterministic given its inputs — it never sources entropy, time
  or binding — which is the only reason a possession proof can be byte-pinned at all. (§2b)
- *(2026-09-10)* The login scheme binds the audience, the ephemeral key, the request id, the
  scope entries and the validity into the signed bytes, and derives the audience from the URL
  rather than the wire — so a phished request binds to the origin the CLI actually talks to,
  and a delegation can never be wider than what the person read. (§2b)
- *(2026-09-09)* The masthead's seed produces the same key text through the three command
  binaries as through the three libraries. (§2c)

### Attachment-critical (consumer)
- Three coordinates: crate/git-tag, go module path, npm scope + registry. (§1)
- The verified round-trip: seed → pubkey → key text → SPKI PEM. (§3.3)
- `node conformance/check.mjs` — the one command. (§3.2)
- **The doors are not signature-compatible.** Argument order and error style differ. (§5)
- *(2026-09-09)* sdk and command coordinates per door, each verified from outside the
  checkout. (§2c attach table)

### Trust-critical (consumer + operator)
- verify fails closed; derive panics on a bad seed. (§5)
- No custody: no key held, no file read, no RNG. (§5)
- No authority vocabulary, verified by grep. (§5)
- No rotation; the key is the principal. (§5)
- Rejection pinned, reason not. (§3.5)
- Zero constellation dependencies; CI needs no credential. (§4, §3.6)
- *(2026-09-09)* Possession: an empty binding is refused; a short nonce is refused, not
  weakened. Envelope: the verifier chooses the domain; JWS, never JWT. Connection setup is
  out. The only RNG in the repository is `keygen`'s, in the command. (§2b, §2c)

### Reference-only (contributor)
- The exact DER prefix bytes. (§2.3) — *keep, but as figure content, not prose*
- Full 60-case and 36-case inventories by name. (§3.1, §2b) — *do not list on the poster*
- *(2026-09-09)* Per-door sdk symbol tables; the subcommand flag matrix. (§2b, §2c) —
  *poster shows the usage line and one invocation only*. The `go install` binary-name
  footgun that stood here for an hour is resolved by layout (§2c attach table).
- CI job matrix and the Windows-leg promotion story. (§3.6) — *appendix at most*
- Provenance commit `d878832`, extraction plan, ADR history. (§3.1, §7)
- Line counts, commit count. (§7) — *must not outrank the thesis*

### Audience note
The README is written for **contributors and constellation architects** — it opens on
ownership rulings and one-change-authority. The poster's primary reader is a **consumer**.
The ownership argument is compressed to the rules that change how the seam is used (§5) and
the honest adoption test (§6); the ADR archaeology stays in `docs/`.
