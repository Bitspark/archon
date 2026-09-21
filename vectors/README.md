# vectors

`sdk.json` — 38 cases in 4 families (`possession_prove` · `possession_verify` · `envelope_seal` ·
`envelope_open`), the same contract one layer up, for `sdk/{rs,go,ts}` ([ADR 0004](../docs/architecture/decisions/0004-the-sdk-layer-above-the-floor.md)).

`login.json` — 105 cases in 6 families (`login_audience` · `login_binding` · `login_prove` ·
`login_verify` · `login_collect_prove` · `login_collect_verify`), the login scheme ([docs/login.md](../docs/login.md)),
for the same `sdk/{rs,go,ts}` CLIs. Derived by [`tools/login-vectors.py`](tools/login-vectors.py):
the layouts assembled by hand from the spec, every signature from OpenSSL 3.2.4 — regenerate with
`python vectors/tools/login-vectors.py > vectors/login.json` from the repo root. Scope entries are
hex so a non-UTF-8 entry can be a case; a lane decodes them before calling the scheme.

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

37 cases in 3 families (`keystore_seal` · `keystore_open` · `keystore_name`) — the
password-protected seed store of [ADR 0007](../docs/architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A,
for `cli/{rs,go,ts}`. The layout is [`docs/keystore.md`](../docs/keystore.md).

| family | cases | what it pins |
|---|---|---|
| `keystore_seal` | 6 | the 134-byte file as a deterministic function of (seed, password, salt, nonce, m, t, p) — including a non-ASCII password, a case at the shipping parameters, and the empty-password refusal |
| `keystore_open` | 17 | 5 round-trips and **12 refusals**: wrong password, bad magic, unknown version, tampered salt / memory-cost / public-key / nonce / ciphertext, short file, long file, an empty-password file, and a file whose tag verifies but whose header names a public key the sealed seed does not derive |
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

Most cases run at cheap Argon2id parameters **on purpose**: the header carries `m`/`t`/`p` and a
reader must *read* them, so a 1 MiB case pins the format exactly as a 64 MiB one does while
keeping conformance fast in three lanes. One case runs at the shipping parameters so those are
pinned too.
