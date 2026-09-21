# 0007 — custody enters the command, and a login server tier enters the repository

**Status:** **ACCEPTED** (2026-09-10) · **Type:** scope / tier
**Re-rules two subtractions**, both by the operator on archon#16, first-hand, verbatim:
custody (*"a - Yes"*, 12:15Z) and the server package (*"a - Yes!"*, 12:21Z). Both are also in `docs/growth-plan.md` §10. Written by
the archon maintainers from the proposers' requirements (the first consumer
and the archon maintainers's review, which found the three design defects
this ADR carries as constraints.

## Context

archon#16 proposes `archon login`: a browser-initiated rendezvous in which the person's
CLI proves possession of a key to a web service and hands the browser a short-lived,
key-bound delegation. The proposal is the first consumer with a running service (the first consumer,
in production since 2026-09-10) and the operator's own requirement — *"where do I find the
key?"* — and it needs exactly the two pieces this repository had subtracted:

| piece | where ADR 0001–0004 put it | measured on 2026-09-10 |
|---|---|---|
| custody of the person's seed | stele (ADR 0002 `:29,44`: *"custody lives in stele … a consumer that needs custody needs stele"*), kosmos (ADR 0004 `:63`) | the only custody that can produce archon's possession proof is one that holds the seed in software — `possession.Prove` signs through `crypto.SignInDomain`, Ed25519**ph with context** (`sdk/go/possession/possession.go:48`, `core/go/crypto/crypto.go:81-91`); an ssh-agent, a FIDO key or 1Password signs pure Ed25519 over the bytes it is handed and cannot compute it. No stele store is in use on the operator's machine. |
| the server side of the exchange | the transport's — kosmos's attach/serve (ADR 0001), *"connection setup stays out; it is the transport"* (ADR 0004 line 3 `:57-58`) | kosmos has zero code files (ADR 0004 `:12-13`); every archon-authenticated web app would write the handler again |

The measurement that brought possession into the sdk (ADR 0004) applies again, and the
operator ruled both in.

## Decision

### A. Custody: `archon key`, a named, password-protected seed store in the command

A fifth family of subcommands in the `cli/` tier — three binaries, one command (ADR 0006)
— and **not** a library surface: nothing in `core/` or `sdk/` learns a file path, a
password or a directory.

| command | does |
|---|---|
| `archon key add <name> (--seed-file <path> \| --seed <hex> \| --pkcs8 <pem>)` | stores a seed under `<name>`, password-encrypted. **Refuses an existing name** — a key is never silently replaced. Accepts a 32-byte seed as 64 hex, the first consumer's `ed25519.PrivateKey` shape (128 hex = seed ‖ public key, the public half **checked against the seed**), and PKCS#8 v1 PEM through the floor's codec. |
| `archon keygen --store <name>` | generates and stores in one step (the RNG stays the command's, ADR 0002/0006); `keygen` without `--store` keeps today's behaviour. |
| `archon key list [--json]` | names and principals; `--json` prints `[{name, principal}]` so an issuer can join grants by principal text without the store learning what a grant is. |
| `archon key rm <name>` | removes. |
| `archon key default [<name>]` | sets or shows the default; `login` and any unlocking command take `--key <name>` and fall back to it. Selection is by name, never by principal text. |
| `archon key export <name> --reveal --out <file>` | **refuses without `--reveal`**, and refuses to write to a pipe or stdout unless `--out -` is given explicitly. |
| `archon login <url> [--key <name>] [--authority-file <path>]` | the consumer of the store (§C). |

**Where and how:**

- `~/.archon/keys/<name>`, directory `0700`, files `0600`, written atomically (temp file in
  the same directory, then rename). `ARCHON_HOME` overrides the directory.
- **One encrypted-file format, identical across the three binaries, versioned by its first
  byte:** header (version, KDF parameters, 16-byte salt), 24-byte nonce, AEAD ciphertext of
  the 32-byte seed with the header as associated data. KDF **Argon2id** (RFC 9106); AEAD
  **XChaCha20-Poly1305**. Chosen because both exist as maintained implementations in every
  ecosystem the repository already draws from — `@noble/hashes` 2.4 (`argon2`, in the tree)
  + `@noble/ciphers`, `golang.org/x/crypto` (`argon2`, `chacha20poly1305.NewX`), RustCrypto
  `argon2` + `chacha20poly1305` — and because a 24-byte nonce makes a random nonce safe
  without a counter the three binaries would have to share. The Argon2id parameters live in
  the header and are read, never assumed; the initial values are the implementing PR's,
  starting from RFC 9106 §4's second recommended option (64 MiB, t=3, p=4) and measured on
  the operator's machines before landing.
- **The format is pinnable and is pinned.** Given salt, nonce, password and seed, the file
  bytes are a deterministic function of their inputs, so `vectors/keystore.json` pins them
  across three lanes exactly as `vectors/sdk.json` pins the sdk (ADR 0004 line 1): the
  command sources salt, nonce and password; the *format* is a tri-core byte contract. The
  cross-binary property — a key added by one binary opens in the other two — is also pinned
  in `cli/smoke.mjs`, add-with-one, list-and-login-with-another.
- **Password entry.** Interactive prompt by default. Non-interactive: `ARCHON_KEY_PASSWORD`
  or `--password-fd <n>`, **never argv**; a password file is refused if world- or
  group-readable. No lock timeout and no daemon — an unlocked seed held by a process is an
  agent again, which is what cannot sign here; prompting per invocation is the design and
  `login` is rare.
- **The store is for people. Agents and CI stay on seed files.** `--seed` / `--seed-file`
  keep working beside the store on every command that takes a key, so a worker's
  read-only-mounted `key` file and a person's `archon login` are the same code with two
  custody sources. A container has no password to give, and a worker's key is disposable by
  design.
- **Seeds only.** Grants stay the law's, joined by principal (`key list --json`); the store
  never interprets them. Rotation is the law's (issue to the new key, let the old grants
  expire). A generic per-key attachment slot was offered by the proposers as "would use, do
  not need" and is **not** in v1.
- **Agents and hardware keys are out** — not disfavoured, *incapable*: none computes
  Ed25519ph with a context string. Stated so the next proposal does not re-derive it.

### B. The server tier: `server/{go,rs,ts}/login`

A **fourth tier**, beside `cli/`, with `cli/`'s status: three lanes of one handler,
unpinnable by construction (a clock, a store, a socket the *service* owns), smoke-tested
across the three, a non-critical ledger line (`substrate/release-facts.server.json`,
`typeIdentityCritical: false`), lockstep-versioned (ADR 0005). It depends on the sdk and the
floor and on nothing else.

| what | rule |
|---|---|
| shape | a **mounted handler** — `http.Handler` (go), a tower service (rs), a fetch-style handler (ts) — implementing the four routes: open a request, read a request, answer it, collect the answer. **It opens no socket; the service's server does.** |
| audience | **configured** into the handler by the service; recomputed from configuration on every verification; **never read from the wire** in either direction (review Finding 1 — the WebAuthn rule: the relying party's identity comes from the origin, not the challenge). |
| authority | **law-free.** `AdmitAuthority(browserPrincipal, answer) error` is the only place an authority payload is interpreted, and archon ships no implementation of it. The payload is opaque bytes to archon. |
| state | **store-minimal.** One in-memory record per pending request, TTL five minutes, dropped on collection; nothing persisted, nothing survives the process. A request is **consumed by the first verified answer**; anything unverifiable is refused before it is stored. |
| the poll | the browser's collection **proves K** (a possession over the request id in the same domain) so a stranger who saw the URL cannot deny the browser its login — and the service gets a liveness signal to expire abandoned requests early. |
| vocabulary | RFC 8628's `authorization_pending` / `slow_down` / `expired_token` and `interval`, adopted verbatim; its bearer-token result is not ours. |

**Supersessions, by number and by scope:** ADR 0004 line 3 (*"connection setup stays out;
it is the transport; never opens a socket"*) is superseded **for a mounted handler that
opens no socket**, and stands for the sdk and for anything that would open one; ADR 0001's
attach/serve → kosmos is superseded **for this handler only** — kosmos keeps attach,
invoke and serve as a transport.

### C. The scheme: `sdk/{rs,go,ts}/login` — welcomed, not ruled, and constrained

The pinnable part lands in the sdk beside possession and envelope, lockstep-versioned,
with `vectors/login.json` and `docs/login.md`. It is a PR, not a ruling (the review said
*welcome*), and this ADR fixes the constraints that PR carries:

1. **The audience is derived, not transmitted.** The CLI derives it from the invocation URL
   with `/login/<id>` removed — origin plus mount prefix, trailing slash trimmed, `ws(s)`
   folded to `http(s)` (the first consumer's convention, so one string means one service everywhere) —
   displays *that*, and binds to it. A service that knows itself by a name that is not its
   URL is misconfigured for this scheme.
2. **The binding names everything the person approved, and its layout lives in the spec,
   not here.** The proof is the existing possession scheme, with the server's nonce, in
   domain **`archon-login/1`**, over a binding that carries — length-prefixed, in the SDK's
   style — a role byte (a login proof by the person's key P, or a collect proof by the
   browser's key K), the derived audience, K, the request id, **the scope entries and
   `valid_for`**. Binding scope and validity makes *"what you see is what you sign"* a byte
   fact rather than a display promise: an answer cannot carry a delegation wider than the
   lines the CLI printed. The exact layout is **`docs/login.md` §3.2**, the document
   `vectors/login.json` is generated from; this ADR deliberately does not restate the bytes,
   so it cannot drift from the oracle. *(Corrected the same day: the first text of this item
   restated the review's earlier sketch, `audience ‖ 0 ‖ K ‖ 0 ‖ id`, which bound neither scope
   nor validity and used separators where the SDK uses length prefixes — #16 comment
   5619088916.)*
3. **Scope is structured and shown verbatim.** `wants` is a list of `kind:path` strings
   plus `valid_for`; the CLI prints it and the issued authority is one entry per line and
   no more. There is no free-text description (Finding 3).
4. **Byte records, not canonical JSON.** The request and answer are length-prefixed byte
   layouts like possession and envelope; JSON is transport only. That is what keeps
   `vectors/login.json` byte-level and a fourth-lane server writable from `docs/login.md`.
5. **The issuer is a function argument, not a plugin.** `archon login` takes the authority
   payload from `--authority-file` (or none, for a law that needs nothing); executable
   discovery by name is a PATH-hijack surface and is refused. thesmos already depends on
   archon, so `thesmos login` = the same exported functions + grant issuance, in-process.
6. **Three lanes at once.** `conformance/check.mjs` runs every vector family across all
   three cores, so a Go-only `vectors/login.json` reds rs and ts. The scheme PR lands all
   three lanes, or the rs/ts lanes land in the same PR as the vectors.

## Who lands what

Lanes are named, not handles — a lane outlives the session that takes it (ADR-0007 of the
board: seats remember, agents act).

| lane | owner | evidence |
|---|---|---|
| **the scheme**, three lanes at once: `docs/login.md`, `sdk/{rs,go,ts}/login`, `vectors/login.json`, conformance | **archon** — the archon maintainers writes it, PR within a day; the record shapes from the proposers' answers 6–9 adopted verbatim. the first consumer's Go-lane scheme PR is withdrawn on the issue — a seeded Go-only vectors file would red rs and ts (C.6). | operator, in cca's tab, 2026-09-10 (*"go"*); #16 |
| **the keystore** (§A) in `cli/{rs,go,ts}`, `vectors/keystore.json`, the cross-binary smoke | **archon** implementer lane, routed by the archon maintainers; waits on this ADR | this ADR |
| **`archon login`** (§C.5) in `cli/{rs,go,ts}` — HTTP/JSON transport and display can start from the spec; signing waits on the scheme | **archon** implementer lane, routed by cca | this ADR |
| **`server/{go,rs,ts}`** (§B) | **archon** lane; the first consumer's `internal/login`, written in the ruled shape, is the reference and lifts onto `server/go` | #16 §9 |
| the TypeScript browser client (`sdk/ts/login/browser`: non-extractable WebCrypto key, `@noble/ed25519` in-memory fallback never persisted, polling with `slow_down`) and the cross-check against the first consumer in production | **the first consumer** | same, §8 |
| `thesmos login` | thesmos — thesmos's maintainers | growth-plan §8.2; the review's Q3 |
| RFC 9421 / 9530 helpers | a separate ADR, not ruled; it carries the same pure-Ed25519 tension as Finding 2 | review, landing order 4 |

## Consequences

- ADR 0002 stands for the **codec**: it is still a byte codec and not custody. What moved is
  narrower than "custody": one store, in the command, for people. Its title is not
  superseded; its `:29,44` lines are, for the CLI store only. stele's maintainers was told
  first-hand before this landed (2026-09-10T12:19Z); ceremony and `~/.stele` are untouched.
- growth-plan §8.5's *"`keygen` writes a file you name and forgets it existed"* stays true
  of `keygen` without `--store`, and stops being the only shape.
- ADR 0006's list of what the command holds gains the store; its rule that the repository's
  only randomness lives in the command now covers salt and nonce as well as seeds.
- ADR 0005's lockstep gains a fourth component and a fourth Go tag line (`server/go/vX.Y.Z`)
  when `server/` first ships; the ledger line is non-critical, like `cli`'s.
- `poster/SEAM.md` §1 records both tiers as **ruled, not yet built** until the code lands;
  the poster itself changes only when there is a surface to show.
- **What this does not decide:** the Argon2id parameter values (the PR's, measured, in the
  header); RFC 9421 helpers; `thesmos login`; a per-key attachment slot (declined for v1);
  whether a second consumer's server will be written in a lane the first consumer does not supply.
