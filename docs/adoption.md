# Adopting archon

Which part of archon does which job, what it deliberately leaves to you, and what it will not
interoperate with. Language coverage and the exact published versions are in
[languages.md](languages.md) and are not repeated here; this page names the tier, and that
page says which languages carry it. The current release is **0.13.0**.

## Which part does which job

| You need to… | Use | Tier | Notes |
|---|---|---|---|
| spell a public key as text, or read and write PEM | `encode_key` / `decode_key`, the SPKI and PKCS#8 codecs | `core` | one spelling, `ed25519:<64 hex>`; byte codecs, not key storage |
| sign bytes any Ed25519 verifier can check | raw `sign` / `verify` | `core` | pure Ed25519 (RFC 8032); see [the two schemes](#the-two-signature-schemes) |
| sign bytes so the signature counts in one context only | `sign_in_domain` / `verify_in_domain` | `core` | Ed25519ph with the domain as the RFC 8032 context; refused in every other domain and as a raw signature |
| prove you hold a key, over a challenge and something it is bound to | possession `prove` / `verify` | `sdk` | the binding must not be empty; what goes into it is your protocol's to define |
| send a payload that only opens under its expected domain and key | envelope `seal` / `open` | `sdk` | |
| let a person's key authorize a key-less client (a browser, a CI job) for a stated scope and time | the login scheme ([login.md](login.md)), `archon login`, and the mounted login handler | `sdk`, `cli`, `server` | Go, Rust and TypeScript; Python and Java have possession and envelope but not login |
| authenticate an ordinary API request: which key sent it, to this service, not replayed | the request profile ([request.md](request.md)): the sdk signs and verifies, the server's verifier keeps the replay store | `sdk`, `server` | Go, Rust and TypeScript, from 0.10.0; a narrow RFC 9421 application profile, wire version 1 ([ADR 0010](architecture/decisions/0010-request-authentication-and-key-enrollment-profiles.md)); whether the key may do the thing is still yours |
| enroll a new key under an account the service already authenticated | key enrollment: `prove_enroll` / `verify_enroll`, and the server's enroller | `sdk`, `server` | Go, Rust and TypeScript, from 0.10.0; the enrollment statement in ADR 0010 |
| keep a person's key on their machine under a name and a password | `archon key`, `keygen --store`, `login --key` | `cli` | [ADR 0007](architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A; for people — agents and CI use seed files. From 0.13.0 each key names the contexts it may sign in (`--allow`, `archon key policy`; [ADR 0012](architecture/decisions/0012-a-stored-keys-signing-contexts.md)) |
| decide what a key is allowed to do | **not archon** — a grant layer such as thesmos | — | the login handler passes the authority payload, as opaque bytes, to an `AdmitAuthority` callback you supply, and never reads it |

## What each tier owns

- **`core`** — key bytes, the key text, the PEM codecs, raw and domain-separated signing, and
  [the verification profile](architecture/decisions/0008-the-ed25519-verification-profile.md):
  what every implementation accepts, written down once and checked ahead of the library.
- **`sdk`** — possession, the envelope and the login scheme's binding and proofs: deterministic
  byte layouts with vectors. No clock, no entropy, no I/O; time and randomness are arguments.
- **`server`** — the login handler a service mounts: the routes, a configured audience,
  injected clock and entropy, one in-memory record per pending login. From 0.10.0 also the
  request verifier with its replay store, and the key enroller. It opens no socket and
  interprets no authority.
- **`cli`** — the `archon` command, and the one place keys are kept (the store above).

## The two signature schemes

archon signs in two ways, and they are not interchangeable.

- **Raw** — pure Ed25519 over exactly the bytes given. Any standard Ed25519 implementation
  produces and checks these.
- **Domain-separated** — Ed25519ph with the domain as the RFC 8032 context string. Possession
  proofs, envelopes and login proofs are all built on it. A signature made in one domain
  verifies in no other domain and never as a raw signature.

WebCrypto's Ed25519, SSH agents and CryptoKit sign pure Ed25519 only. They can at most
produce raw signatures; **none of them can produce an archon domain signature, so none can
make a possession, envelope or login proof**. HSMs and hardware tokens vary: only one that
computes Ed25519ph with a caller-supplied context could, and archon has tested none as a
signer. A raw signature never stands in for a domain signature — the domain-separated verify
refuses it, by design.

## What the login scheme is, and is not

archon login is its own proof-of-possession protocol, specified in [login.md](login.md): a
person approves a scope and a duration with a key they hold, and a key-less client receives a
delegation bound to the service's configured audience. It borrows device-flow vocabulary for
its error codes. **It is not an OAuth or OpenID Connect provider, not SAML, and not a browser
single sign-on integration**, and it issues no bearer token. Whether the person behind the key
may do anything is the authority layer's question, answered in your `AdmitAuthority`.

## Signing with a stored key (from 0.9.0)

Decided in [ADR 0009](architecture/decisions/0009-the-signing-boundary-and-the-signer-contract.md)
([#47](https://github.com/Bitspark/archon/issues/47)) and released in 0.9.0:

- `archon sign --key <name> --domain <d> --expect <principal> [--json]`: a tool that is not
  archon gets a person's stored key to sign its bytes without receiving the seed. It signs in a
  domain only, and the tool runs it from a path its integrator pinned
  ([`cli/README.md`](../cli/README.md#sign---key-signing-for-another-tool)). In every command,
  the password is read from the controlling terminal, never from stdin;
- a signer interface in the sdk, so the protocol helpers can sign through something other than
  a seed (ADR 0009 §4): prepare, sign with a signer, complete. It is additive, in TypeScript, Go
  and Rust, and in Python and Java for possession and the envelope.

**Changed in 0.9.0 for Go and Rust servers:** `AdmitAuthority` takes a fourth argument,
`Admitted{id, scope, validFor}`, the request the proof covers. Every Go and Rust law gains the
parameter. A TypeScript law written for three arguments keeps working.

**Changed in 0.11.0:** `Admitted` also carries when the server accepted the answer (Go
`AcceptedAt`, Rust `accepted_at`, TypeScript `acceptedAt`), and the delegation runs from that
instant for `valid_for` seconds ([login.md](login.md) §4). Go and Rust code that constructs
`Admitted` itself must set it; a law that only reads it needs no change.

**Changed in 0.13.0:** a stored key names the contexts it may sign in, sealed with the seed
(ADR 0012), and `sign --key` refuses any other context before asking for the password. A key
stored before 0.13.0 is `migration-required` until `archon key policy <name> --allow <context>`
(or `--unrestricted`) converts it, once, at a terminal. Upgrade every archon binary that uses
the store first: older binaries can't read the new key-file version.

## Request authentication and key enrollment (from 0.10.0)

Request-authentication and key-enrollment profiles for authenticating ordinary API requests
([#48](https://github.com/Bitspark/archon/issues/48)), released in 0.10.0. The design is in
[ADR 0010](architecture/decisions/0010-request-authentication-and-key-enrollment-profiles.md):
a narrow RFC 9421 application profile, and a separate enrollment statement. **The wire is fixed
as version 1** ([docs/request.md](request.md)). The sdk halves (sign, strict parse, pure verify,
enrollment) and the server halves (replay store, verifier, enroller) ship in the TypeScript, Go
and Rust `sdk` and `server` packages; the Python and Java sdks do not carry them.

## Not in archon

- Git transport authentication: a Git credential helper, the credentials a Git service issues,
  SSH-key association and a Git command gate. These belong to the product that hosts Git
  ([ADR 0011](architecture/decisions/0011-transport-integrations-stay-above-archon.md),
  [#64](https://github.com/Bitspark/archon/issues/64), [#65](https://github.com/Bitspark/archon/issues/65)).
  archon's request profile authenticates the exchange that issues such credentials.

## Getting started

The README's [quickstart](../README.md) is executed as written, in all three command
implementations, on every push. `node cli/quickstart.mjs -- archon` runs it against the
`archon` you have installed.

[`examples/login`](../examples/login/) is a whole login on the published TypeScript packages
at exact versions: a service mounting the handler with an `admit` callback, a key-less
client, and a person with `archon login`. CI runs it on every push, installing from the
registry rather than from this repository. Its README also says what `admit` receives as
the authority payload.
