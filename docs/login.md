# archon login — the scheme

**Status:** draft for review on [archon#16](https://github.com/Bitspark/archon/issues/16) ·
**Layer:** `sdk/{rs,go,ts}/login` (ADR 0004; pinnable, tri-lane) · **Oracle:** `vectors/login.json`

A person holds a key on their machine. A browser — or any client that wants to act but holds no
long-lived key — needs to act *as* that person at a service. `archon login` is the exchange in
which the person's key proves, unrelayably, that it agrees to let one ephemeral key act at one
service for one stated scope and time, and hands that client a delegation whose meaning the
service's law decides.

This document defines **only what nothing else defines**: the binding rule, the two proofs, the
records they are made over, and the transport that carries them. The rendezvous shape is RFC
8628's (device authorization) with the roles swapped; the proof is archon's possession scheme;
the delegation payload is opaque here and belongs to the authority layer (thesmos, for the
constellation). What this scheme deliberately leaves to its callers: entropy (the server's
nonce, the server's id, the browser's key), time (expiry, validity), the delegation's contents,
key custody, and every socket.

## 1. Parties and names

| party | holds | called |
|---|---|---|
| the **browser** | an ephemeral Ed25519 key **K**, generated for this login, held in memory for exactly the delegation's lifetime | the client |
| the **service** | its own **audience** string (§2) and a law that admits delegations | the server |
| the **CLI** | the person's key **P**, in custody it controls | the prover |

Roles generalise: the "browser" is any key-less client (a CI job, a container, a phone); the
"CLI" is any holder of a key (a person's laptop, an agent with a workspace key).

## 2. The audience is derived, never transported

The audience is the service's **base URL** as the service is configured to know itself:
scheme and host lowercased, `ws`/`wss` folded to `http`/`https`, default ports omitted, no
query, no fragment, **trailing slash trimmed**. Examples: `https://prover.core.example.dev/api`,
`http://localhost:8080`.

The login mount is `<audience>/login`; a pending request is `<audience>/login/<id>`. The CLI is
invoked with that URL and **derives the audience from it** by removing the last two path
segments (`login`, `<id>`) and normalising as above. The server recomputes every binding from
**its own configured audience**. The audience appears in no message. A request relayed from
another origin therefore binds to the origin the CLI actually talks to — and the CLI displays
that origin before anything is signed.

### 2.1 Deriving it — one function, one grammar, pinned

Three URL parsers normalise three ways (a WHATWG `URL` drops a default port, `net/url`
keeps it and decodes the path, a hand-rolled one keeps userinfo), and the audience is the
first field of the binding — so the derivation is part of the **scheme**, not of any CLI:
`derive_audience(url) → (audience, id bytes)` in `sdk/*/login`, pinned by the `login_audience`
oracle family. It accepts exactly this grammar and **refuses everything else rather than
normalising it**:

```
invocation = scheme "://" host [ ":" port ] *( "/" segment ) "/login/" id
scheme     = "http" / "https" / "ws" / "wss"        ASCII, case-insensitive; ws → http, wss → https
host       = reg-name / "[" ipv6 "]"                ASCII only, lowercased
reg-name   = label *( "." label )                   label = 1*( ALPHA / DIGIT / "-" )
ipv6       = 2*( HEXDIG / ":" / "." ) containing ":"  no zone id
port       = 1*DIGIT, no leading zero, 1..=65535     omitted from the audience when it is the
                                                     scheme's default after the fold (80, 443)
segment    = 1*( unreserved / sub-delims / ":" / "@" / pct-encoded )   kept as written, case
                                                     preserved, never decoded; "." and ".." refused
id         = 2*HEXDIG, lowercase, even length        the id bytes are the hex decoded
```

Refused: any non-ASCII, whitespace or control byte; userinfo (`@` in the authority); a query
(`?`) or fragment (`#`); an empty segment (which includes a trailing slash and `//`); a
malformed `%` escape; a penultimate segment other than `login`; an id that is not lowercase
hex of even length; a scheme, host or port outside the grammar.

```
audience = scheme "://" host [ ":" port ] *( "/" segment )      with "/login/" id removed
```

The server's configured audience must be spelled the same way (§2); a service that knows
itself by another spelling has misconfigured itself, and every proof made for it fails closed.

## 3. Records

Byte lengths are big-endian. `u16(x)` is a two-byte length prefix; `u32(x)` a four-byte
integer. Hex in JSON is lowercase.

### 3.1 The request

Created by the browser, completed by the server, read by the CLI.

| field | bytes | rule |
|---|---|---|
| `id` | 1..=65535 | the server's; opaque; ≥ 16 random bytes recommended; hex in URLs and JSON |
| `nonce` | 16..=65535 | the server's fresh entropy, one per request, never reused |
| `browser` | 32 | K's public key |
| `scope` | 0..=65535 entries | an **ordered list** of UTF-8 strings, each 1..=65535 bytes, **no control characters** (U+0000–U+001F, U+007F); the law's vocabulary (`read:projects`); the CLI prints each entry verbatim |
| `valid_for` | u32 | the delegation's requested lifetime in seconds, `> 0` |

### 3.2 The binding

```
binding = role
        ‖ u16(len audience) ‖ audience
        ‖ browser[32]
        ‖ u16(len id) ‖ id
        ‖ u16(count scope) ‖ ( u16(len entry) ‖ entry )*
        ‖ u32(valid_for)
```

`role` is `0x01` for the **login proof** (made by P) and `0x02` for the **collect proof** (made
by K). The audience is 1..=65535 bytes, no control characters. The whole binding must fit the
possession scheme's `u16` field (≤ 65535 bytes). Every rule violation is an error at
construction; verification treats it as false.

The scope and validity are bound so that what the person approved is what the proof covers,
byte for byte — the rendering the CLI shows is derived from the same bytes.

### 3.3 The proofs

Both proofs are the SDK's possession scheme in the domain **`archon-login/1`**, over the
request's nonce and the binding of §3.2:

```
login   = possession.prove(seed_P, "archon-login/1", nonce, binding(0x01, audience, request))
collect = possession.prove(seed_K, "archon-login/1", nonce, binding(0x02, audience, request))
```

i.e. Ed25519ph with the domain as RFC 8032 context over
`0x01 ‖ u16(len nonce) ‖ nonce ‖ u16(len binding) ‖ binding`. A raw Ed25519 signature, a
signature in another domain, a signature over the bare nonce, or a proof of the other role never
verifies. `collect` is made only by the key the request names: constructing it with a seed whose
public key is not `browser` is an error.

### 3.4 The answer

Posted by the CLI, collected by the browser.

| field | rule |
|---|---|
| `principal` | P's public key, as archon key text (`ed25519:<64 hex>`) |
| `possession` | the login proof, 64 bytes |
| `authority` | **opaque**: the delegation from P to K for the request's scope and validity, in the service's law (for thesmos, the grant facts P issued). The scheme neither reads nor signs it; the law does both. May be absent for a service whose law needs nothing beyond the proof. |

## 4. Transport

JSON over HTTPS; bytes as lowercase hex; keys as archon key text. Error bodies are
`{"error": "<code>"}` with RFC 8628 / RFC 6749 codes: `invalid_request`, `invalid_grant`,
`expired_token`, `authorization_pending`, `slow_down`, `access_denied`.

| step | request | response |
|---|---|---|
| **begin** (browser) | `POST <audience>/login` `{"browser": "ed25519:…", "scope": [...], "valid_for": 28800}` | `201` `{"id", "nonce", "browser", "scope", "valid_for", "expires_in": 300, "interval": 5, "verification_uri": "<audience>/login/<id>"}` |
| **read** (CLI) | `GET <audience>/login/<id>` | `200` `{"id", "nonce", "browser", "scope", "valid_for", "expires": "<RFC 3339>"}` · `404 expired_token` |
| **answer** (CLI) | `POST <audience>/login/<id>/answer` `{"principal", "possession", "authority"}` | `204` · `400 invalid_request` · `403 invalid_grant` (proof or authority refused) · `404 expired_token` · `409 invalid_request` (already answered) |
| **collect** (browser) | `GET <audience>/login/<id>/answer` with header `Archon-Collect: <hex collect proof>` | `200` `{"principal", "possession", "authority"}` **once**, then the record is dropped · `202 authorization_pending` · `429 slow_down` · `403 invalid_grant` (collect proof refused) · `404 expired_token` |

The server verifies **before storing** an answer: the id is pending and unexpired; the nonce is
the request's; the binding recomputed from the stored request and the server's own audience
verifies under `principal`; the authority is admissible for `browser` under the law
(`AdmitAuthority(browser, principal, authority)`). Anything else is refused and nothing is
stored, so junk cannot be deposited against a pending request. A request is consumed by its
first verified answer.

State is one in-memory record per pending request, dropped at `expires_in` (five minutes) or on
collection. Nothing outlives the login.

A collect poll that arrives sooner than `interval` after the last **verified** poll is answered
`429 slow_down` **without advancing the reference time**: the timer moves only when a collect
proof has verified and the poll was allowed, so an eager client is delayed, never locked out,
and a stranger's polls (which never verify) cannot delay the browser at all.

### 4.1 The prover-initiated form — offers

*Status: proposed by the first consumer from use (archon#16, 2026-09-10); ruled in by ADR 0007 §C.7; lands in
v0.5.0.* The page-started form above needs the person to carry a URL from the page to the
CLI. Nothing in the scheme requires the page to start: the holder of the key can start, and
the person finishes in the page — RFC 8628's original direction. **The binding and the proofs
are unchanged**; only the transport grows two routes and one member.

**The code.** The prover mints a *code* — at least 16 random bytes from its own entropy,
spelled as lowercase hex of even length like an id, used once — and registers an **offer**:
what it is willing to delegate, to a key it does not know yet. **The code is confidential
until the offer is taken.** Until then `GET <audience>/login/offers/<code>` hands the offered
scope and validity to whoever holds it, and a stranger who overhears it can begin with
*exactly* the offered scope and their own K — which rule 2 accepts and no one confirms. So
the code travels only in a fragment or on the prover's own terminal, never in logs, query
strings or messages; the page is expected to take it within seconds (`expires_in` is the
ceiling, not the plan); and the residual is named: an attacker reading that terminal or
clipboard in that window — the same local exposure the page-started form has to a swapped
URL, and the reason both forms print K's principal. Once taken, the code is spent.

| step | request | response |
|---|---|---|
| **offer** (prover) | `POST <audience>/login/offers` `{"code": "<hex>", "scope": [...], "valid_for": 28800}` | `201` `{"code", "scope", "valid_for", "expires_in", "interval", "page"?}` — `page`, if the service is configured with one, is `<configured page>#<code>` (a configured page that already carries a fragment is refused at construction); the prover **prints** it, marked *on the service's own origin* or *NOT on the service's origin — do not open it* by comparing scheme and host with the audience's, and **never launches a browser** — spawning a platform opener by name is the PATH surface ADR 0007 §C.5 refuses, and a service response is never an open redirect · `409 invalid_request` (code taken) · `400 invalid_request` (malformed body) |
| **read the offer** (page) | `GET <audience>/login/offers/<code>` | `200` `{"code", "scope", "valid_for", "request": null \| "<id>", "expires"}` · `404 expired_token` |
| **begin on the offer** (page) | `POST <audience>/login` as §4, with `"offer": "<code>"` added | `201` as §4 begin · `400 invalid_request` if the request's `scope` or `valid_for` differs from the offer's **in any way** · `409 invalid_request` if the offer is already taken · `404 expired_token` (unknown or expired offer, or a code that is not lowercase hex of even length ≥ 32 — a registered code is always well-formed, so a malformed one is unknown by construction and a stranger learns nothing from the difference) |
| **poll the offer** (prover) | `GET <audience>/login/offers/<code>` until `request` is set. **The prover paces itself** by the advertised `interval` — it sleeps one `interval` *before* its first poll, so the page always has the first window to read the offer — and treats a `429` as sleep-and-retry should a server ever send one. The server does **not** pace this route: it hands over no proof and no answer, so pacing protects nothing, and with two pollers (the page's one read, the prover's loop) one reference time would let a page read that lands just after a prover poll be refused at every retry. | as above |
| **read, re-check, answer** (prover) | `GET <audience>/login/<id>` (§4 read); then `POST <audience>/login/<id>/answer` (§4 answer) | as §4 |
| **collect** (page) | unchanged (§4) | unchanged |

**Rules the prover keeps, in this order, without exception:**

1. **Its audience is its own configuration** — `--audience <base>`, or the environment
   variable `ARCHON_AUDIENCE` as the configured default, checked exactly the same way — never
   inferred from a URL and never a page's word; it must be a fixed point of §2.1's grammar,
   the same rule the server enforces at construction, and the prover refuses to start
   otherwise. The code and the page address are printed on **stderr** (the interactive
   channel, where the password prompt lives) and the ledger of rule 4 on **stdout**, so a
   redirected `archon login … > file` never writes the code into a log.
2. **It answers only the request the offer names**, and only after **re-checking itself**
   that the request's `scope` and `valid_for` are what it offered — scope entry for entry, in
   order; validity equal — never trusting that the server's refusal happened. It never
   offered a key, so it does not check `browser`: it **records** K from the request, and K is
   what the ledger (rule 4) names.
3. **No confirmation is asked.** The person typed the command and chose the scope; the
   audience is the prover's own; the only request it will answer carries the code it minted a
   moment ago. What you *typed* is what you sign.
4. **After answering — whether the service accepted or refused — it prints the ledger of
   the decision no one confirmed**, field by field: the audience, every scope entry verbatim
   in order, the validity as a duration and as a wall-clock end, K's principal (`ed25519:…`),
   and the service's verdict — never the code — the same shape the confirmed form shows *before* signing,
   printed *after*, so `login-statement.json` pins both forms across the three CLI lanes.
5. **One offer, one request.** A second request naming a taken offer is refused; an offer is
   consumed by the first request that matches it, and dies with that request or at its own
   expiry, whichever comes first.

**Refusals**, as the server makes them:

| condition | status | code |
|---|---|---|
| a code already registered and unexpired | `409` | `invalid_request` |
| a code that is not lowercase hex of even length ≥ 32 characters, or a malformed offer body | `400` | `invalid_request` |
| a request naming an offer whose `scope` or `valid_for` differ, in any way | `400` | `invalid_request` — refused **before** anything is stored, before any key is involved |
| a request naming an offer already taken | `409` | `invalid_request` |
| an unknown or expired offer, on any route — a malformed code included | `404` | `expired_token` — indistinguishable, as with requests |

**State**: one in-memory record per offer beside the request records, dropped at
`expires_in` (the same five minutes) or when its request is dropped; the paired request is
an ordinary request with its own lifetime. The offer carries no key and no proof; what it
carries is the code's confidentiality until it is taken (above).

**Properties**, in addition to §6: the audience is not even derived from a URL in this form —
it is the prover's configuration, so the relay of §2 has no message to ride; a page that
alters what it was offered gets `400` before a key is touched, and a prover never signs a
scope it did not type. What rule 2 does **not** buy is protection against a code overheard
before it is taken — that is the confidentiality window above, bounded by seconds and named
in the ledger by K's principal.

**Pinned by** the server tier's fixtures: `server/testdata/login-wire.json` gains the two
routes' key sets, forbidden keys (no `audience` anywhere, still) and status codes, a
`malformed_bodies` case for the offer body, no `offer_poll_too_fast` case (the offer route is unpaced — only collect's `slow_down` is pinned), and an `offer_mismatch` family stating the
divergences (an extra entry, a reordered entry, a changed entry, a changed validity) each of
which must be `400`; `cli/testdata/login-statement.json` gains the prover-initiated
statement. The CLI form is `archon login` with no URL: `--audience <base>` (or `ARCHON_AUDIENCE`),
`--scope <entry>` repeated, `--valid-for <seconds>`, custody as the confirmed form — except that
the store is unlocked only after the paired request has been read and **re-checked (rule 2)
and found to match**: the key is needed at signing and nowhere earlier, so a mismatched
request is refused without a password ever being asked for — as the server refuses a
mismatched offer before any key is involved — a person who never finishes never types a
password, and the offer is registered before any custody is touched; the code from the
CLI's own entropy.

## 5. What the CLI shows before it signs

The audience it derived (§2), the browser principal, every scope entry verbatim in order, the
validity as a duration and as a wall-clock end, and which of its keys will sign. It signs only
after an explicit confirmation. A request that fails any rule in §3 is refused before display.

## 6. Properties

- **Unrelayable.** The binding names the audience the CLI talks to, the key that will act, the
  request, the scope and the validity; the possession scheme refuses an empty binding and a
  short nonce. A proof made for one origin verifies nowhere else; a proof captured in transit
  binds a key the attacker does not hold.
- **What you see is what you sign.** Scope and validity are inside the binding.
- **No long-lived secrets in the browser, no sessions on the server.** K is a key the page
  can read — necessarily: the collect proof is Ed25519ph with a context (§3.3), which
  WebCrypto's Ed25519 cannot compute, so a non-extractable K is not a property this scheme
  can have and it does not claim one *(corrected 2026-09-10 from the first consumer's finding on
  archon#16; the first text said "generated non-extractable where the platform allows")*.
  What K has instead: it never signs anything but its own collect proofs, the delegation
  the law issues is bound to it, and both live exactly as long as the delegation — in
  memory, `sessionStorage` at most, never `localStorage`, gone with the tab. P never leaves
  its custody; the service holds nothing after the login. Revocation is expiry, as elsewhere
  in the constellation's development profile.
- **Pinnable.** The binding is a deterministic function of its inputs and the proofs are
  deterministic Ed25519ph signatures, so `vectors/login.json` pins the bytes across the three
  lanes; nonce generation and clocks are the callers'.

## 7. Not in this document

Custody of P (ADR 0007: the CLI's key store), the server package and the browser client
(ADR 0007; `server/`, `sdk/ts/login/browser`), the delegation's contents (the law's), request
signing after login (RFC 9421 — a separate proposal), and any fleet rule about domains. The
prover-initiated form is §4.1 as of v0.5.0.
