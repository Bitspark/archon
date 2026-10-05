# vectors

`sdk.json` — 38 cases in 4 families (`possession_prove` · `possession_verify` · `envelope_seal` ·
`envelope_open`), the same contract one layer up, for `sdk/{rs,go,ts,py,java}` ([ADR 0004](../docs/architecture/decisions/0004-the-sdk-layer-above-the-floor.md)).

`login.json` — 105 cases in 6 families (`login_audience` · `login_binding` · `login_prove` ·
`login_verify` · `login_collect_prove` · `login_collect_verify`), the login scheme ([docs/login.md](../docs/login.md)),
for the same `sdk/{rs,go,ts}` CLIs. Derived by [`tools/login-vectors.py`](tools/login-vectors.py):
the layouts assembled by hand from the spec, every signature from OpenSSL 3.2.4 — regenerate with
`python vectors/tools/login-vectors.py > vectors/login.json` from the repo root. Scope entries are
hex so a non-UTF-8 entry can be a case; a lane decodes them before calling the scheme.

`request.json` — 139 cases in 5 families, request authentication and key enrollment
([docs/request.md](../docs/request.md)), for the same `sdk/{rs,go,ts}` CLIs: `request_sign` (35, the
client's signature base, headers and signature, and every value §3.1 refuses), `request_verify` (61,
every acceptance and refusal of §5 and §7 steps 1–7; replay is the server's), `enroll_binding` ·
`enroll_prove` · `enroll_verify` (43, §6). **Version 1, fixed** by
[ADR 0010](../docs/architecture/decisions/0010-request-authentication-and-key-enrollment-profiles.md)'s
status note of 4 October 2026: a change to any byte here is a new wire version, never an edit.
Derived by [`tools/request-vectors.py`](tools/request-vectors.py), a naive fourth
client and every signature from OpenSSL 3.2.4 — regenerate with
`python vectors/tools/request-vectors.py > vectors/request.json`. Each verify refusal breaks exactly one
rule and is otherwise signed correctly, so it can only be refused for that rule.

`enroll.json` — 106 cases in 7 families, `archon enroll`'s formats ([docs/enroll.md](../docs/enroll.md)
§2–§3, [ADR 0013](../docs/architecture/decisions/0013-enrolling-a-stored-key.md)), for the same
`sdk/{rs,go,ts}` CLIs: `enroll_intent_encode` · `enroll_intent_decode` (24 + 18, intent format 1 and
every refusal: lengths, counts, display-unsafe text, a leading byte-order mark, trailing bytes),
`enroll_challenge_encode` · `enroll_challenge_decode` (18 + 25, the challenge token: its prefix,
lowercase hex, the whitespace it ignores and the whitespace it does not, the 65536-byte bound, the
deadline's bound, a display-unsafe audience), `enroll_challenge_request` (7, the request a token
yields: the intent's purpose and SHA-256 of its bytes), and `enroll_proof_encode` ·
`enroll_proof_decode` (6 + 8, the proof token). Text fields are hex in the cases, so non-UTF-8 text
can be a case. The file is ASCII, so no invisible code point sits raw in it. Derived by
[`tools/enroll-vectors.py`](tools/enroll-vectors.py), a naive fourth implementation of the layouts
that takes the display-unsafe set from `display-unsafe.json`; regenerate with
`python vectors/tools/enroll-vectors.py > vectors/enroll.json`.

`display-unsafe.json` — not cases but one frozen list: the display-unsafe code points
(`Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point`, from Unicode 15.1) that the CLIs refuse in a
scope entry and escape in what they print ([docs/login.md](../docs/login.md) §5). Each sdk lane's
unit test sweeps every code point against it, so the three lanes' tables are this file exactly.
Derived by [`tools/display-unsafe.py`](tools/display-unsafe.py); regenerate with
`python vectors/tools/display-unsafe.py > vectors/display-unsafe.json`, with a Python whose
Unicode data is 15.1.0 (the generator refuses any other).

`identity.json` — 105 cases in 7 families, the byte-level contract every archon core must
satisfy. Driven by [`../conformance/`](../conformance/).

| family | cases | what it pins |
|---|---|---|
| `pubkey_from_seed` | 3 | Ed25519 public-key derivation (RFC 8032 §5.1.5) |
| `key_encode` | 3 | the canonical key text `ed25519:<lowercase-hex>` |
| `keycodec` | 15 | the PKCS#8 v1 / SPKI PEM codec (RFC 5958 / RFC 5280) — accepts **and** rejects |
| `signature_verify` | 40 | verify semantics: non-canonical S, wrong-length inputs, a domain signature never raw — and the **verification profile** of ADR 0008, by class: the identity and every small-order point as a key, their non-canonical spellings, a mixed-order key, the identity and a small-order point as `R`, `S` at the bound |
| `hex_decode` | 12 | the typed fixed-size hex decoders — what is accepted **and** what is refused (31 bytes, odd digits, `0x`, a key where a signature was asked for) |
| `domain_sign` | 9 | domain-separated signing (Ed25519ph, RFC 8032 §5.1 context) — the signature itself, the 255-byte bound, the empty-domain refusal; and the domain as **text**: multibyte UTF-8, an embedded NUL, the bound reached and exceeded in bytes rather than characters |
| `domain_verify` | 23 | the crossings: domain A in domain B, raw in any domain, both `false`; the shape failures; the profile's classes in a domain; the text cases |

The 30 `profile-*` cases in `signature_verify` and the 6 in `domain_verify` are **generated**, by
[`../conformance/profile-cases.mjs`](../conformance/profile-cases.mjs), from the classes ADR
0008 names — each with a signature some RFC 8032 verifier accepts, because a rejection nobody
would accept pins nothing. Their expected values are the profile's, by definition; the note on
the first case of each class says which equation accepted it before the profile and why.

## Why the first four and not others

Copied from thesmos `vectors/authority.json` @ `d878832`, selected by the
**one-change-authority** rule: a case belongs to archon only if it can be stated entirely
in RFC 8032 / 5280 / 5958 vocabulary — a seed, a public key, a signature, an opaque
message, a key text, a PEM. If saying what a case *means* requires the words *root*,
*admission*, *grant*, *fact*, *receipt* or *epoch*, it is thesmos's, however much crypto
it happens to involve.

That rule excluded two things a file-level reading would have taken:

- **`admission_context_signing_bytes`** — signs with a key, so it looks like crypto. It
  cannot be described without "admission", "authority cut" and "receipt". thesmos's.
- **`pubkey_from_seed/root-placeholder`** — pure derivation, pure bytes. It exists to pin
  a root trust-anchor *designation*. thesmos pins that one *through* archon's function.

And it included one thing a cost-based reading would have skipped: **`signature_verify`**.
Nobody was being hurt by it living in thesmos. But it is stated in nothing but RFC 8032,
and it covers precisely where independent implementations diverge in practice. A core
answering `true` where another answers `false` splits the constellation in half.

## Authoring

Expected values are **hand-authored from the standards**, not captured from a core. Where a
value cannot be written by hand — a deterministic Ed25519ph signature — it is derived with an
implementation **outside all of the cores** (OpenSSL 3.2.4, `pkeyutl -rawin -pkeyopt
instance:Ed25519ph -pkeyopt context-string:<domain>`, or `hexcontext-string:<utf-8 hex>` for
a domain the shell cannot spell), and the case's note says so. A vector copied out of an
implementation pins whatever that implementation does, bugs included; a vector derived from
the standard pins the standard, and lets every core be wrong together and be caught.

**A rejection is admitted on its adversarial value, never on agreement.** Until ADR 0008 the
`signature_verify` family took only cases every core already answered identically — which is
an oracle that cannot contain a disagreement, and it did not: the identity point as a public
key verified a universal signature in two cores and not in the other two, with no case
saying so. Where the standard leaves acceptance open (RFC 8032 permits more than one
verification equation), the expected value is the **profile's** — ADR 0008 decides it, the
case's note cites the class, and the cores are brought to it, not the other way round. The
independent authority above is an authority on *signing*; it was never asked an acceptance
question and holds no opinion on one — OpenSSL itself accepts the identity key.

thesmos keeps its copy of these cases until the switch. The copy is non-destructive —
nothing breaks until someone deletes the original.

## `keystore.json`

81 cases in 3 families (`keystore_seal` · `keystore_open` · `keystore_name`) — the
password-protected seed store of [ADR 0007](../docs/architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A,
with the context policy of [ADR 0012](../docs/architecture/decisions/0012-a-stored-keys-signing-contexts.md),
for `cli/{rs,go,ts}`. The layout is [`docs/keystore.md`](../docs/keystore.md): version 2 (§8) is
the only one written, version 1 (§2) is still read.

| family | cases | what it pins |
|---|---|---|
| `keystore_seal` | 19 | the version-2 file as a deterministic function of (seed, password, salt, nonce, m, t, p, policy) — unrestricted, one context, two, a multibyte context, sixteen, a 255-byte context, an empty list (deny all), the shipping parameters, the Argon2id floor `m = 8p` at p=1 and p=4; and the writer's refusals: an empty password, `m < 8p`, seventeen contexts, unsorted, duplicate, an empty context, a 256-byte context, an unrestricted policy that lists one, a context holding a display-unsafe code point (U+202E) |
| `keystore_open` | 48 | every seal opens, with its version and policy; **the version-1 files still open** (renamed `v1-…`), so `key policy` can convert them; and every refusal **with its category** (`malformed`, `unsupported`, `unlock-failed`, as `sign --key` reports it): the version-1 tampers, truncations and parameter bounds; an unknown version (3); a version-2 file the length of a version-1 one; and for version 2 a tampered context (tag), an unrestricted policy listing a context, an unknown mode, seventeen contexts, an empty context, a context that is not UTF-8, a policy running past the header, a trailing byte, a missing one, unsorted and duplicate contexts, a file too short to be version 2, and a genuine seal (tag valid) whose context holds U+202E, refused at parse |
| `keystore_name` | 14 | the name rules as pure string cases — 3 accepted, 11 refused (empty, leading and trailing dot, both separators, colon, a control character, reserved device names bare and with an extension, over-length) |

**Oracles**, both outside all three cores, both validated before use — the same discipline as
`sdk.json`'s OpenSSL-derived signatures:

- **Argon2id** — the reference C implementation (`phc-winner-argon2` via `argon2-cffi`),
  checked byte-for-byte against **OpenSSL 3.2.4** `ARGON2ID` on this parameter shape.
- **XChaCha20-Poly1305** — **libsodium** (via PyNaCl), checked byte-for-byte against
  **draft-irtf-cfrg-xchacha-03** Appendix A.3, verbatim.
- The container around them is assembled by hand from the layout, as this file describes for
  the possession vectors — and all 23 crypto cases were then **reproduced independently by
  `@noble/hashes` + `@noble/ciphers` + `@noble/curves`**, a stack sharing no code with either
  oracle, refusals included, before any lane was written.
- The parameter-bound cases (2026-10-05): the two `m = 8p` files were computed with the same two
  oracles and are byte-identical to what `golang.org/x/crypto/argon2` writes. The `m < 8p` files
  can only come from x/crypto, which raises `m` to `8p` silently; the reference implementation
  refuses to compute them, and that refusal is checked before the cases are written.
- The version-2 cases (2026-10-05) were computed with the same two oracles, the policy bytes laid
  out by hand from `docs/keystore.md` §8.1, and the writer's refusals decided by an independent
  statement of §8.1's rules. Go, Rust and TypeScript each passed all of them as written,
  before any lane saw another's output.

Most cases run at cheap Argon2id parameters **on purpose**: the header carries `m`/`t`/`p` and a
reader must *read* them, so a 1 MiB case pins the format exactly as a 64 MiB one does while
keeping conformance fast in three lanes. One case runs at the shipping parameters so those are
pinned too.
