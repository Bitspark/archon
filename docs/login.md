# archon login — the scheme

**Status:** shipped — in every release since 0.3.0 (designed on
[archon#16](https://github.com/Bitspark/archon/issues/16); the offers form since 0.5.0,
`acceptedAt` since 0.11.0, the display rule since 0.12.0; the transaction fingerprint, the
consequence statement and the offers page's trusted origin from the release after 0.14.0,
[ADR 0015](architecture/decisions/0015-approving-the-right-client.md)), in all three lanes ·
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
| the **browser** | an ephemeral Ed25519 key **K**, generated for this login and kept only while it has a role (§6) | the client |
| the **service** | its own **audience** string (§2) and a law that admits delegations | the server |
| the **CLI** | the person's key **P**, in custody it controls | the prover |

Roles generalise: the "browser" is any key-less client (a CI job, a container, a phone); the
"CLI" is any holder of a key (a person's laptop, an agent with a workspace key).

### 1.1 What a login claims

A login claims what its prover can stand behind, at three levels
([ADR 0015](architecture/decisions/0015-approving-the-right-client.md) §3):
- **Cryptographic.** A valid login proof under P commits to this request's audience, K, id, scope and
  validity, in the login domain and over the request's nonce.
- **A conforming prover** (§5.1). The prover obtained approval of a presentation generated from the
  frozen operation before signing it.
- **A custodial deployment** (§5.2). A custodian signed with P after an account service authenticated
  approval of the custodian's operation. The claim is subject to the recorded evidence and the trust
  placed in that service, its presentation and the custodian. For an unattended renewal under a
  mandate: the custodian signed under that mandate after evaluating its current conditions, and no
  fresh human approval is asserted.

None of these claims sole control of P or a qualified signature. None says that the person started
the request: see §6's approval relay.

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
| **collect** (browser) | `GET <audience>/login/<id>/answer` with header `Archon-Collect: <hex collect proof>` | `200` `{"principal", "possession", "accepted_at": "<RFC 3339>", "authority"}` **once**, then the record is dropped · `202 authorization_pending` · `429 slow_down` · `403 invalid_grant` (collect proof refused) · `404 expired_token` |

The server verifies **before storing** an answer: the id is pending and unexpired; the nonce is
the request's; the binding recomputed from the stored request and the server's own audience
verifies under `principal`; the authority is admissible for `browser` under the law
(`AdmitAuthority(browser, principal, authority, request)`). Anything else is refused and nothing
is stored, so junk cannot be deposited against a pending request. A request is consumed by its
first verified answer.

**The law is handed the request the proof covers**: its id, and the scope and `valid_for` the
person was shown and approved, exactly as the binding carried them (§3.2). A law therefore
decides against what was signed, not against a scope it would have to look up or assume. Each
lane hands it a copy, so nothing the law does to it reaches the stored request.

**When the delegation starts** *(archon#93)*. The server records `acceptedAt`, its own clock in
whole seconds, once: when the answer holds the admission turn (below) and has passed its
re-check, just before the law runs. That one instant is:

- handed to the law as `Admitted`'s `acceptedAt`;
- stored with the answer;
- returned to the collecting client as `accepted_at` (RFC 3339), which is how a service with no
  law learns it.

The delegation is the interval **`[acceptedAt, acceptedAt + valid_for)`**. Nothing moves it:
a refused answer stores nothing, so only the answer that is stored starts it; the browser
collects once, and collecting reads the stored instant rather than taking a new one; and a
retry is a new request with a new proof and its own `acceptedAt`. The binding is unchanged: the
duration is signed, the start is the accepting server's record.

**The law runs at most once at a time per request, and never for a late answer.** A verified
answer takes the request's *admission turn* before the law runs and re-checks the request while
holding it. An answer that arrives while another is being admitted waits. If the other is stored,
the waiting answer gets `409` and the law never runs for it. If the other is refused, the turn
passes on, so a stranger's refused answer delays the person by the law's running time but never
denies them. The turn belongs to one request, so a slow law holds up no other login. This is
**not** an exactly-once boundary: a refused answer's law did run, and a process can stop after
the law returns but before the answer is stored. So a law must do one of three things:

- only validate;
- make its effects idempotent, keyed by the request id it is handed;
- leave its effects until the browser has collected.

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

**Two rules hold without exception** (ADR 0015 §5):
- **The code's binding.** The code is confidential, short-lived and single-use. Taking an offer binds
  it atomically to one request and K, and nothing replaces that binding (rule 5).
- **No fallback.** The prover signs automatically only for its outstanding offer and its frozen
  parameters. Expiry, cancellation, a conflict or changed parameters never fall back to the
  page-started form.

**The page address is printed only on a trusted origin.** It carries the code, so the CLI prints it
only when both hold:
- it is `https`, or `http` on a loopback host;
- its origin is the audience's, or the one the person names with `--page-origin <origin>`.

Otherwise the CLI says why it did not print the address, and prints the code alone. A label saying
"do not open it" is not a trust relationship.

**A page that receives a code** keeps the address out of logs and telemetry, runs as little script as
it can, and removes the code from the browser's history once it has taken it.

The ledger of rule 4 is an audit record, not the defence. The defence is exclusive possession of the
code, and the first use binding it to K.

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
validity as a duration and as an approximate wall-clock end ("for 8h0m0s, until about <T>"),
which of its keys will sign, and the request's transaction fingerprint (§5.3). `<T>` is the CLI's
clock plus `valid_for` when it shows the statement. The delegation starts when the server accepts the answer (§4), a little later, so
the real end is later than `<T>` by the time the person takes to confirm, and at most by the
request's remaining lifetime.

Then it states the consequence, "This gives the browser key above authority to act as you. Approve
only a client you started yourself.", and signs only after an explicit confirmation. The confirmation
defaults to no. A request that fails any rule in §3 is refused before display.

**What may be shown.** A scope entry is text a service chose, and the person reads it on a
terminal. Some code points make what they read differ from the bytes they sign: a terminal may
render them as nothing, or let them rearrange or hide the text around them. The CLI refuses,
before it shows anything, a scope entry carrying one of them, the **display-unsafe** code points:

    Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point

That is the control characters (C0, DEL, C1), the format characters (bidirectional controls,
zero-width characters, invisible operators, interlinear annotations, tags), the line and
paragraph separators, and every code point Unicode says should render invisibly (soft hyphen,
combining grapheme joiner, Hangul fillers, variation selectors, …). The list is frozen as
explicit ranges in `vectors/display-unsafe.json` (from Unicode 15.1), identical in the three
lanes (`login.DisplayUnsafe`, `login::display_unsafe`, `displayUnsafe`), and each lane's sdk
test sweeps every code point against that file.

- **The CLI's refusal is the guarantee.** The binding's grammar (§3.1) is unchanged and still
  refuses only C0 and DEL, so such an entry is valid on the wire and a server may send one.
  The person's CLI will neither show it nor sign it.
- **The server's refusal is a courtesy.** The login handler refuses the same code points at
  begin and offer (`400`), so an honest service learns at once rather than from a person whose
  CLI refused. A third-party server that skips this check still cannot get past the CLI.
- **The offers form's page address is refused too** when it carries one. It is the address a
  person would open, printed only on a trusted origin (§4.1), so it is never shown escaped.
- **Elsewhere, such a code point is escaped, never shown.** The CLIs write one as `\uxxxx`, a
  UTF-16 surrogate pair above U+FFFF, in everything else a service or a caller chose that they
  print:
  - `sign`'s pre-prompt display and `--json` output, and `key list --json`;
  - a refused response's `error` and `error_description`;
  - the offers ledger's verdict.

  The value is unchanged; the raw code point never reaches the terminal.
- **Look-alikes are not caught.** A Cyrillic "а" in place of a Latin "a" is an ordinary letter,
  and no list of code points can tell it from the one it imitates. A service that wants its
  scope entries to be unmistakable keeps them to ASCII.

### 5.1 Every prover's contract

The CLI is one prover. Any holder of P that makes a login proof is another, such as a custodian
signing for a person ([ADR 0015](architecture/decisions/0015-approving-the-right-client.md) §2,
extending [ADR 0009](architecture/decisions/0009-the-signing-boundary-and-the-signer-contract.md)
§6). Every prover keeps this contract:
1. It **selects the signing principal**, **obtains and validates the pending request** (§3), and
   **establishes the audience itself** (§2.1, or its own configuration in §4.1). It never takes the
   audience from the party that asked it to sign.
2. It **freezes the complete message** to be signed before asking for approval.
3. It **generates the presentation from that frozen message.** Caller-supplied explanatory text is
   never an authoritative description of what will be signed.
4. It **obtains approval of that exact operation,** or relies on an explicit policy authorized
   earlier that covers it. Authentication of an account alone is not approval.
5. It **signs only the approved bytes, verifies the signature, and records the operation's single
   use.** A material change needs a new approval.
6. It **never presents a valid audience, a displayed key identifier or a matching fingerprint as
   evidence that the person started the request.** None of them is.

### 5.2 A prover that is not the person's CLI

A prover that signs for a person from elsewhere keeps §5.1, and four things more (ADR 0015 §6).
- **It fetches the request itself.**
  - It builds `<audience>/login/<id>` from its own registration of the service's audience and the
    request id. It never uses an address the requesting party supplied.
  - It derives the audience by §2.1.
  - The fetch uses authenticated transport, controlled egress, bounded responses, and a redirect
    policy that cannot change the audience.

  This keeps what it shows and what it signs from diverging. It does not make the requesting party's
  choices (its K, its coverage) reflect the person's intent.
- **Its operation is larger than the binding.** A custodian's frozen operation includes:
  - the proof's domain, nonce and binding;
  - P;
  - the exact grants it will sign;
  - the product and account bindings;
  - the pending session;
  - the deadlines;
  - the custody mode;
  - any renewal mandate.

  §5.1 covers the whole operation. Approving a login proof is never permission to sign an arbitrary
  accompanying grant: the authority payload is opaque here, so the party issuing it understands and
  limits it, and `AdmitAuthority` checks the correspondence (§6).
- **Its presentation shows, at minimum:**
  - who acts: the account, P, the service, the audience, and which party holds K;
  - what authority is issued: the exact scope strings, beside any interpretation of them;
  - for how long;
  - what further authority it creates, such as renewal;
  - which initiation it belongs to, with verified facts kept distinct from estimates.

  A key fingerprint the person has never seen may be shown, but recognising it is not their task.
- **Its claim is the custodial level of §1.1,** never "the person signed".

### 5.3 The transaction fingerprint

A short value the person can compare between the page that began a login and the prover about to
sign it (ADR 0015 §4):

    fingerprint = SHA-256( u16be(len d) ‖ d ‖ u16be(len nonce) ‖ nonce ‖ binding )[0..16]
    d           = "archon-login-fingerprint/1"
    binding     = the login proof's binding, role 0x01 (§3.2)

It is shown as eight groups of four lowercase hex digits: `7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f`.
- **Inputs.** The page computes it from the K it generated and its own begin response (`id`,
  `nonce`, `scope`, `valid_for`) at its configured audience. The prover computes it from the request
  it will sign (`login.Fingerprint`, `login::fingerprint`, `fingerprint`).
- **Coverage.** It covers the whole transcript, not K alone, so it tells apart requests that reuse a
  key, and changes with any difference in scope or validity. At 128 bits a match cannot be searched
  for offline.
- **Pinning.** `vectors/login.json`'s `login_fingerprint` family pins it in the three lanes. It is not
  a signature and changes no signed bytes.
- **A page shows it only for the request its own K began,** never for whichever request an address
  or a message names.
- **It is conditional protection.** It detects substitution only when the person compares it with a
  page they started and trust. An attacker's page can show the matching value for the attacker's own
  request beside its instruction. The CLI cannot see what a page showed. It prints the fingerprint
  and asks the person to approve only a client they started. A flow that requires comparison fails
  when the comparison cannot be made, and the person enforces that by answering no.

## 6. Properties

- **Unrelayable.** The binding names the audience the CLI talks to, the key that will act, the
  request, the scope and the validity; the possession scheme refuses an empty binding and a
  short nonce. A proof made for one origin verifies nowhere else; a proof captured in transit
  binds a key the attacker does not hold. That is about relaying a *proof*. Relaying the *request
  for approval* is the next property.
- **Approval relay: the residual risk, by form**
  ([ADR 0015](architecture/decisions/0015-approving-the-right-client.md)). Begin is
  unauthenticated, so anyone can begin a request with their own K and send the person its address.
  RFC 8628 calls this remote phishing, and RFC 10027 (BCP 247) treats cross-device flows at length.
  - **The page-started form** is open to it when the person accepts an attacker's request. The
    fingerprint (§5.3) detects substitution only when the person compares it with a page they started
    and trust; an attacker's page can show the matching value. An approval without that comparison
    is lower assurance.
  - **The offers form** resists an unsolicited address while the code stays confidential and reaches
    the intended page. An attacker who reads the code before it is taken can race to authorize their
    own K. The form does not authenticate the page after the code is disclosed, nor stop a person who
    hands the code over. It is the recommended form for a person who can start at their own terminal.
  - **A custodial prover** (§5.2), approved on a phone through an account service. Account matching
    refuses a relay across accounts. A matching code helps against unrelated or mistaken requests.
    Neither defeats a live attacker who controls a session on the person's own account and relays its
    presentation. That needs a fresh phishing-resistant sign-in in the initiating browser, bound to
    the pending delegation ("Authenticate then Initiate", RFC 10027 §6.1.15), which is the
    deployment's to provide. Account matching and a code never close the same-account relay.
  - **What services do.** No prior account authentication is required of every login: a client
    with no prior session is legitimate. A service SHOULD:
    - offer the offers form;
    - protect the page that begins a login;
    - bound pending requests and their lifetimes;
    - provide a way to find and end issued authority;
    - where it has accounts, bind a pending request to the account that began it, and admit only that
      account's P.
  - **Rollout.** An old and a new prover make the same v1 proofs, so a service cannot read the
    stronger ceremony from the signature. A service that requires it enforces its own initiation
    state and refuses the paths that bypass it. A CLI version string is not proof.
- **What you see is what you sign.** Scope and validity are inside the binding. The validity is
  signed as a duration; its start is the server's `acceptedAt` (§4), so the wall-clock end the
  CLI shows is an estimate, which is why it says "about". A signed absolute end would need a new
  binding version (archon#93 records that as a later decision, for a consumer that must check
  the end from the proof alone).
- **P never enters the browser; K is a key the page can read.** P stays in the prover's custody.
  K is generated for this login and is readable by page script — necessarily: the collect proof
  is Ed25519ph with a context (§3.3), which WebCrypto's Ed25519 cannot compute, so a
  non-extractable K is not a property this scheme can have and it does not claim one
  *(corrected 2026-09-10 from the first consumer's finding on archon#16; the first text said
  "generated non-extractable where the platform allows")*. Nor does it claim that someone holding
  K is confined to archon's sdk.
- **After the collect, K is used only through a protocol the service specifies**
  ([ADR 0014](architecture/decisions/0014-a-login-keys-use-after-the-collect.md), superseding
  the earlier sentence that K "never signs anything but its own collect proofs"). The login uses K
  for its collect proof. Afterwards a service may accept K through archon's request profile
  (§7), through a session it binds to K at the collect, or through a protocol of its own with a
  complete acceptance contract. A successful login does not by itself authenticate any later
  operation.
- **Authority stays bounded, and is checked where it is accepted.** Every use of authority derived
  from a login stays within the approved audience, the admitted interpretation of the approved
  scope, and the earliest applicable end: `acceptedAt + valid_for`, every applicable grant's
  expiry, and any limit the service sets. It is checked at each execution boundary: a command, a
  subscription's delivery, a stream's output, queued work, a reconnect. The principal is K,
  established by the service's authentication or by a credential bound to K, never inferred from a
  submitted chain. Attributing K's actions to P's account does not remove the limits of the
  delegation to K.
- **What a service's `AdmitAuthority` must establish.**
  - The admitted authority corresponds to the approval: the right P and K, the approved scope as
    the service interprets it, the service's audience and the login's interval. A payload that
    holds *some valid grant* is not enough. The handler hands the law everything this needs (§4).
  - The audience is carried by the authority itself. Whoever holds K can sign a fresh proof naming
    another audience, so the grant, the admission context or a trust namespace exclusive to one
    deployment (with thesmos, a root or a space subtree per deployment; thesmos#895) must restrict
    the authority to this audience, and every accepting route must
    enforce that. The audience is compared byte for byte, never by prefix: a login mounted at
    `https://x.dev/login` has the audience `https://x.dev`, not the API's `https://x.dev/api`. Mount
    the login at `<api base>/login` so the two are one string, or have the admitted authority name
    the API's audience explicitly. For downstream services, use one of two constructions (ADR 0015
    §6):
    - they implement operations within the login's audience, as one logical boundary;
    - or each destination gets separately restricted authority.

    Until a deployment specifies one, it refuses the login's authority at any other audience.
  - If the grants carry no start time, the admission context enforces the login's start.
    Collecting, reconnecting and renewing never restart `valid_for`.
  - A grant signed before `acceptedAt` matches the login when the login's interval is its upper
    bound: the admitted authority ends no later than `acceptedAt + valid_for`. Exact equality with a
    clock reading taken later is not required (ADR 0015 §6).
  - Onward delegation, enrollment, credential exchange, recovery and renewal acquire no broader or
    longer-lived authority because of this login; what they derive keeps its source's limits. A
    service does not claim a restriction its law cannot enforce: thesmos's default law allows
    onward delegation. A thesmos grant to K can withhold it (ADR 0014's status note), enforced
    only by relying parties that require every link of a chain to be resident.
- **A session started at the collect is the service's, and is sound under six conditions.** It is
  created only as a consequence of a successful collect and admission; it is bound immutably to K,
  the admitted authority, the audience and the deadlines; collection and session creation are
  single-use across concurrent requests, replicas and retries (archon's handler makes collection
  single-use within one process); nothing renews it past the authority's end; each operation is
  still authorized; and the service states how a session ends. An HttpOnly cookie keeps page
  script from *reading* the session, not from *using* it; a credential returned to JavaScript has
  no such protection. A client that has no further use for K discards it at the handoff.
  - **How to build it with this handler.** The handler has no collect callback, and the collect
    response carries no K, so never build the session from that response. Record K, P, the
    admitted authority and the deadlines in `AdmitAuthority`, keyed by `Admitted.ID` and
    idempotently; wrap the collect route; and where the handler answers 200 for that id (it has
    verified K's collect proof), create the session from that record, once.
  - **Replicas.** The handler's state lives in one process's memory. Route every request of one
    login to the same replica; that also keeps collection single-use across replicas.
  - **Renewal** (ADR 0015 §6).
    - A replacement is a new immutable admission, switched in atomically. The old admission's
      deadline is never mutated.
    - A switched session pointer does not invalidate a published grant. Superseded grants are
      retracted, or every accepting route enforces the current generation.
    - Replacements that keep going to the same K keep going to a stolen copy of it too. A short
      grant is then not a short compromise window.
- **No bearer credential, and no sessions in the login handler.** The login protocol issues no
  bearer credential; a service that completes the exchange with a bearer session or another
  credential specifies that construction and its binding to the admitted authority. The login
  handler holds nothing after the login (§4). The service may keep admitted authority, principal
  bindings, sessions, replay records and connection state its protocols need. Plaintext logs and
  proxies that see a bearer credential are inside that credential's trust boundary.
- **Keeping K is client behaviour, never revocation.** A client keeps K only while it has a role,
  in memory or `sessionStorage` at most, never `localStorage`, and discards it when the exchange is
  abandoned, its role ends or the deadline passes. That is not erasure: `sessionStorage` can be
  copied into windows the page opens, a copy of K survives the tab, and closing a tab revokes
  nothing. Expired authority is refused whatever copies of K remain. The login protocol has no early
  revocation; revocation is expiry, and a service that supports more says what it invalidates.
- **Residual risk.** A service that accepts K directly exposes all the authority it accepts
  through K, for as long as that authority lasts, to page compromise or a copied K. Request
  verification does not show that the sender holds K now, since requests can be signed in advance
  (ADR 0010 §5); the hard bound is the authority check at the time of use. A session reduces
  extraction but not misuse by page script. A copy of K can race the page to collect, and is not
  inert afterwards while any route accepts K or authority derived from it, such as an onward grant.
  Expiry stops further use; it does not undo what was done.
- **Pinnable.** The binding is a deterministic function of its inputs and the proofs are
  deterministic Ed25519ph signatures, so `vectors/login.json` pins the bytes across the three
  lanes; nonce generation and clocks are the callers'.

## 7. Protocols composed with login, and what this document leaves out

- **HTTP requests.** archon's request profile ([`request.md`](request.md), ADR 0010) is the
  standard composition. A service may accept requests signed by the K this login approved,
  combining request verification with §6's audience, principal and authority conditions. It
  authenticates the signed request under that profile; it does not show that the sender holds K
  now, or holds it alone.
- **Sessions and connections.** Login defines no session credential and no WebSocket, stream or
  connection authentication. A browser cannot add headers to a WebSocket upgrade, so a service
  authenticates a connection by its session cookie (with an Origin check, as a supplement), by a
  challenge and K's proof in the first messages, or by a single-use ticket from an authenticated
  request. The integrating protocol specifies its signature domain, version and purpose; a fresh,
  single-use challenge tied to the actual pending connection; its binding to the audience and
  endpoint; which key becomes the principal and how its authority is obtained; and its timeout,
  reconnect and expiry behaviour. It owns that contract's tests.
- **Other signatures and derived authority.** A service may define other uses of K, onward grants
  included where its law allows them. Each accepting protocol defines what its signatures mean and
  when K's authority is accepted for them. A distinct signature domain alone establishes neither;
  and a proof of possession never raises a key's standing, so enrollment and issuance are governed
  by their endpoints' policy. Using archon's signature or possession primitives does not make the
  enclosing protocol an archon protocol (ADR 0011).

**Not in this document:** custody of P (ADR 0007: the CLI's key store; a custodian's custody is
its own, and what it must do as a prover is §5.1 and §5.2), the server package
(`server/`), the delegation's contents (the law's), and any fleet rule about signature domains. The
prover-initiated form is §4.1 as of v0.5.0.
