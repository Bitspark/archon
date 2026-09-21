# cli — the `archon` command

Three native binaries — `cli/rs`, `cli/go`, `cli/ts` — each build the **same** `archon`
command with **identical** stdout and exit codes, pinned by [`smoke.mjs`](smoke.mjs)
(the case table, the store's cross-binary checks, one store-key login and one offered login
per lane against a server the run hosts itself — × 3 binaries, on every push). They are thin presentation + I/O layers over the
floor, never part of it: the library stays dependency-minimal; the CLI's I/O lives here.

```
archon <keygen|key|login|sign|verify|version> [args]
```

| subcommand | what it does |
|---|---|
| `key encode <pubkey-hex>` / `decode <ed25519:…>` | raw bytes ⇄ the canonical key text |
| `key pkcs8 encode <seed-hex>` / `decode` | a seed ⇄ its PKCS#8 v1 PEM (`decode` reads stdin or `--in <file>`) |
| `key spki encode <pubkey-hex>` / `decode` | a public key ⇄ its SPKI PEM |
| `key pub [--in <pem>\|--seed <hex>] [--format spki\|text\|hex]` | the public key of a private key |
| `keygen [--seed <hex>] [--out <pem>] [--pub-out <file>] [--pub-format …]` | a key pair: public key text on stdout, private PEM to `--out` or to stderr behind a SECRET warning |
| `sign (--key-file <pem>\|--seed <hex>) [--domain <d>] [--in <file>]` | sign the input bytes; `--domain` makes it domain-separated |
| `verify --pubkey <ed25519:…\|hex> --sig <hex> [--domain <d>] [--in <file>]` | `valid` (exit 0) / `invalid` (exit 1) |
| `login <url> [--key <name>\|--seed <hex>\|--key-file <pem>\|--seed-file <file>] [--authority-file <f>] [--yes]` | prove possession to a service so a browser key may act for you, within a scope you are shown first; with no key flag, the store's default key signs |
| `login --audience <base> [--scope <entry>]... --valid-for <seconds> [--key <name>\|--seed <hex>\|--key-file <pem>\|--seed-file <file>] [--authority-file <f>]` | the offers form ([§4.1](../docs/login.md)): with no URL, *you* start and the page finishes — the code and the page address on stderr, no confirmation, the ledger on stdout after the service answers |
| `key add <name> [--seed <hex>\|--seed-file <file>\|--pkcs8 <file>]` | keep a seed under a name in the password-protected store; generates one when no source is given, and refuses an existing name |
| `key list [--json]` | every stored key as `{name, principal}` — read from each file's header, so it never asks for a password |
| `key rm <name> [--force]` | remove a key and say what was removed and from where; a file that is not an archon key is refused unless `--force` |
| `key default [<name>]` | set or show the default key, by name |
| `key export <name> --reveal --out <file>` | write the seed out as a PKCS#8 PEM; refuses without `--reveal`, and refuses stdout unless `--out -` says so |
| `keygen --store <name>` | generate straight into the store instead of writing a PEM |

Every hex input goes through the floor's typed decoders: a 31-byte "public key" is refused
here exactly as the library refuses it.

## The key store

`key add|list|rm|default|export` and `keygen --store` are the password-protected seed
store of [ADR 0007](../docs/architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A. Keys live in `$ARCHON_HOME/keys` (default `~/.archon`), one
fixed 134-byte file each; [`docs/keystore.md`](../docs/keystore.md) is the byte contract and
`vectors/keystore.json` pins it across the three binaries.

Passwords come from an interactive prompt, or from `ARCHON_KEY_PASSWORD` or
`--password-fd <n>` — never from argv, which is world-readable in the process table.

Every operation that destroys, reveals or creates key material says what it did **in
scope**: archon speaks for its own store and never for anyone else's, so an empty result
means *nothing visible here*, never *nothing exists*. Those lines are pinned in
`cli/smoke.mjs` so the wording cannot drift.

## `login` and the audience

`login` is the one subcommand that talks to a network, and the one whose safety rests on a
rule rather than on a type: **the audience is derived from the invocation URL you typed, and
is never read from the wire.** `<url>` is `<audience>/login/<id>`; the audience is that URL
with the last two segments removed, the trailing slash trimmed, `ws(s)` folded to `http(s)`,
and scheme and host lowercased. A service that could name its own audience could name
someone else's, and the proof would then verify against a service you never saw
(archon#16, Finding 1) — so the request struct has no audience field at all, and a response
carrying one is refused rather than half-read.

The order is the security order: derive, fetch, validate, **show**, confirm, only then
unlock and sign. You are shown the audience, the browser key, every scope entry verbatim,
the validity and which key will sign, and nothing is signed until you answer `y` — the
default, including on a closed stdin, is no.

Which key signs is decided before anything is fetched, and the statement names it by its
source: `--key <name>` picks a key in the store, and with no key flag at all the store's
default (`archon key default`) signs — never a guessed seed file. A name that is not in the
store, or no default when none was given, is refused before a request is made. The password
is asked for only **after** you answer `y`, and it is sourced exactly as the store's own
commands source it: a prompt, `ARCHON_KEY_PASSWORD`, or `--password-fd <n>` — never argv.
`--seed`, `--key-file` and `--seed-file` stay beside the store for agents and CI, which have
no password to give.

### The offers form — `archon login` with no URL

The page-started form above needs you to carry a URL from the page to the terminal. With
**no URL** — `archon login` followed by flags only; a literal `--` is not an idiom here, just
an unknown flag — *you* start and the page finishes ([`docs/login.md` §4.1](../docs/login.md)).
The rules the command keeps, in this order:

1. **The audience is your own configuration**: `--audience <base>`, or `ARCHON_AUDIENCE` as
   the default, checked the way the server checks its own — a fixed point of §2.1's grammar —
   and refused before anything is sent otherwise, naming the spelling the service binds.
   Never a page's word.
2. **The code is yours and confidential until the page takes it.** It comes from the
   command's own entropy (16 bytes) and is printed on **stderr** — the interactive channel,
   where the password prompt lives — together with the page address, which is printed and
   **marked** (*on the service's own origin*, or *NOT on the service's origin — do not open
   it*) and never opened for you. So `archon login … > file` never writes the code into a log.
3. **You typed the scope; nobody confirms it.** `--scope <entry>` repeated, in order, and
   `--valid-for <seconds>` (required) are what is offered and what is signed. `--yes` is
   refused: there is no confirmation to skip.
4. **Only the request that took your offer is answered**, and only after the command has
   re-checked it against what you typed — entry for entry, in order; validity equal — never
   trusting that the server refused a mismatch. Your key is unlocked (the password asked
   for) only after that check passes: a mismatched request, or a page that never comes, never
   asks you for a password.
5. **The ledger comes after**, on **stdout**, accepted or refused: the audience, every scope
   entry verbatim, the validity as a duration and a wall-clock end, the browser key that now
   acts as you, which key signed, and the service's verdict — never the code. A refusal is
   recorded there and the command exits 1.

The command paces itself while it waits — one advertised interval before its first poll, so
the page always has the first window — and gives up when the offer's own lifetime ends.

The **scheme** — the binding layout and the proof — is not here: it lives in `sdk/*/login`,
and each lane reaches it through a single seam, so a binding is written once and cannot
drift between binaries.

## What `login` costs the Rust lane

`login` is the only subcommand that opens a socket, and in Rust that is not free. Measured
2026-09-10 against a 47-crate baseline (`archon-core`, `archon-sdk`, `getrandom`, `serde`,
`serde_json`), by resolving one lockfile per candidate:

| HTTP client | lockfile | added |
|---|---|---|
| **`minreq` + `https-rustls`** (what this lane uses) | 68 | **+21** |
| `ureq` 2 | 99 | +52 |
| `ureq` 3.x | 116 | +69 |

`ureq` 3.x is the natural guess and the worst of the three — which is why this was measured
rather than reasoned about. `native-tls` was ruled out: it would make the Windows CI leg
depend on a build environment.

The irreducible part is TLS (`rustls`, `ring`, `webpki`); the rest is what a general HTTP
client drags along. **Go and TypeScript pay none of this** — `net/http` and the platform's
`fetch` are already there — so the Rust lane is the only one where the cost is visible, and
this table is the honest price of it.

## Where it came from

`key` and `keygen` were carved out of thesmos's CLI tier (thesmos ADR 0007) on
2026-09-09 — `docs/growth-plan.md` §8.2. Measured, they contained
no thesmos term, and archon shipped no CLI at all, so a consumer using archon without
thesmos could not spell a key from the command line. thesmos retires its copies in favour
of this command; its `sign` and `verify` stay, because they sign and verify **facts** — this
command's `sign` and `verify` share the names and nothing else. They work on bytes.

## The RNG

`keygen` without `--seed` draws from the OS CSPRNG. That RNG lives **here**, in the CLI,
and not in the library — the library takes a seed it is given and never invents one
([ADR 0002](../docs/architecture/decisions/0002-keycodec-is-a-byte-codec-not-key-custody.md)).
It is not custody in stele's sense: nothing is named, stored or managed; a file you name is
written and forgotten. Anyone who wants no keygen at all can use
`openssl genpkey -algorithm ed25519` — it emits the PKCS#8 PEM this command reads.

## Building

```
cargo build --release --manifest-path cli/rs/Cargo.toml       # → cli/rs/target/release/archon
go build -o archon ./cli/go/cmd/archon                         # from the repo root (go.work)
go install github.com/Bitspark/archon/cli/go/cmd/archon@v0.5.0   # from anywhere -> $GOBIN/archon
(cd cli/ts && npm ci && npm run build) && node cli/ts/dist/src/main.js
```

`cli/ts` consumes `core/ts` through a `file:` dependency, so build the floor first.

The Go main package lives at `cli/go/cmd/archon`, not at the module root, on purpose: `go
install` and a bare `go build` name a binary after its package directory, and the module
root's directory is called `go`. A binary called `go` on PATH shadows the toolchain — it
did, on a Windows CI runner, when a stray `cli/go/go.exe` got committed. `cmd/archon` makes
the name `archon` by construction (seat:cca ruling, 2026-09-09).
