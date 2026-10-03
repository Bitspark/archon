# 0009 — the signing boundary and the signer contract

**Status:** **ACCEPTED** (2026-10-04) · **Type:** contract / tier
**Amends [0007](0007-custody-in-the-command-and-the-login-server-tier.md)** — §A's stated reason
for refusing a key agent, and §C.5, to admit an executable path the integrator pins. Ruled by the
operator on 2026-10-04 on external advice taken in the form of
[0001](0001-archon-scope.md)'s consultation (`research-docs/0003-*`, internal), for
[archon#47](https://github.com/Bitspark/archon/issues/47). The companion request and enrollment
profiles ([archon#48](https://github.com/Bitspark/archon/issues/48)) are separate decisions.

## Context

Two needs met here.

**A tool that is not archon needs exact bytes signed by a key in archon's store.** The first is
thesmos's grant issuance: thesmos builds the grant, shows it to the person, and needs it signed by
their key. Today its command takes keys only as a PKCS#8 PEM path, so a person whose key lives in
the store must `archon key export --reveal` it to plaintext first — the one thing the store exists
to avoid — or each downstream tool re-implements archon's custody, which is the drift ADR 0007
put custody in one place to prevent.

**Protocol helpers need signing capability, not seeds.** Every sdk signing function in every
lane — `provePossession`, `seal`, `proveLogin`, `proveCollect` — takes the 32-byte seed. A helper
that must work for a seed file, a stored key and, later, other backends cannot ask for a seed.

The measured constraint is the same one ADR 0007 recorded: archon's domain scheme is Ed25519ph
with the domain as the RFC 8032 context, and no surveyed signing device or cloud key service
produces it with a non-empty context (WebCrypto, `ssh-agent`, FIDO and the password managers' agents
sign pure Ed25519; the best hardware and cloud signers offer Ed25519ph with an *empty* context only),
while several silently drop a context they do not support. And the first consumer signs **raw**:
thesmos facts are pure Ed25519 over their canonical bytes. A boundary that signs raw Ed25519 over
caller-supplied bytes with a person's long-lived key is a cross-protocol signing oracle.

## Decision

### 1. Two pieces, because they solve different problems

- **The signer contract** lives in the **sdk** (option S3 in the consultation): protocol helpers
  accept a signer instead of a seed, additively.
- **The stored-key boundary** lives in the **command** (option S1): `archon sign --key` run as a
  subprocess by an integrator who pins its path. The seed never leaves an archon process.

**Not chosen:** a custody library that downstream programs import (S2) — custody stays "**not**
a library surface" (ADR 0007 §A stands); it would put unlocked-key lifetime into other programs'
processes and meet no need the subprocess cannot. **Deferred:** an archon key agent (S4) — see 5.

### 2. The signing request

A request is three things, and the scheme is a discriminated value, never a scheme name plus an
optional domain:

```
SigningRequest = { expectedPublicKey: 32 bytes,
                   scheme:  ed25519-raw                       (no domain)
                          | ed25519ph-context { domain },     (domain per ADR 0008 §2)
                   message: the ORIGINAL message bytes }
```

- `message` is **always the original bytes**, never a digest. A backend whose API wants a
  prehash (Go's `crypto/ed25519` does for Ed25519ph) computes it inside its adapter; the contract
  never exposes that difference.
- Validation happens **before signing, and before prompting where it can**: an expected key of the
  wrong length, a domain on a raw request, or a domain that ADR 0008 §2 refuses (empty, over 255
  bytes, not well-formed text) is refused. No normalisation.
- A signer **reports the schemes it supports and any domain restriction** (capability discovery),
  and refuses — never approximates — a request outside them. In particular a signer that cannot
  carry a context **refuses `ed25519ph-context`**; it does not sign with an empty context.

### 3. Checked completion

Every signature a signer returns is **verified before use** with the profile verifier (ADR 0008)
against the *requested* public key, scheme, domain and original bytes — never against values the
signer echoes back. This catches a wrong key, a dropped context, raw substituted for ph, and a
wrong prehash adaptation.

**Verification does not prove deterministic signing** (ADR 0008 §1.7 requires the RFC 8032 §5.1.6
output). Determinism is a **backend-conformance requirement**, tested per backend against the
`domain_sign` vectors (derived outside the cores with OpenSSL) and by signing twice.

Domain separation is **not** authorization to sign: a caller allowed to request signatures in a
domain can obtain any signature in that domain. Consent is §6.

### 4. The sdk seam: additive, and the synchronous seed functions stay

Every existing seed function keeps its signature and stays synchronous. Each signing helper gains a
**pure prepare** (the exact message, scheme and expected key it needs signed) and a **pure complete**
(checked completion, then packaging), with a convenience that runs the signer between them. The
portable contract is *exact inputs, completion, failure and cancellation* — not one promise-shaped
API in every lane; each lane uses its idiom (a Promise in TypeScript, a `context.Context` in Go, a
future in Rust). prepare and complete stay inside the vectors' reach; invoking a signer is an
injected effect, and deterministic Ed25519 does not make a password prompt or a subprocess pure.

The seed-backed signer ships in the sdk. Store-backed signing ships only as the command (5).

### 5. The stored-key boundary: `archon sign --key`

- **`archon sign --key <name> --domain <d>`.** With `--key`, `--domain` is **required**: the
  store does **not** sign raw. Raw signing stays in `core` and on `--seed` / `--key-file` exactly as
  today. A raw stored-key mode would need a consumer that justifies it; the first one, thesmos, is
  moving its facts to a domain instead (operator ruling, 2026-10-04: a clean cut, no legacy path).
- **Two-stage key selection.** A caller learns the key's principal **without a password** — the
  store header carries the public key in the clear (`archon key list --json`) — builds its bytes,
  then asks for a signature naming the principal it expects (`--expect <ed25519:…>`). A header that
  already names another key is refused **before the password is asked for**; archon still treats
  the header as provisional until the seal opens and the seed derives the header key, and refuses
  if that key is not the expected one — **always before signing**, so a mismatched key never
  produces a signature at all and a store entry replaced between the two stages is never signed for
  silently. thesmos needs this order — the signer's key is inside the bytes it signs.
- **A machine mode.** A versioned machine output (one JSON record on stdout: version, principal,
  scheme, domain, signature; one JSON error record with a semantic category on failure) is
  selected explicitly. Without it the output stays the signature alone, 128 hex digits — with
  `--key` as with `--seed` — so a caller attaches exactly 64 bytes without parsing anything.
- **Secret channels.** The message arrives by `--in <file>` or stdin; the password by
  `--password-fd` or `ARCHON_KEY_PASSWORD` as today, or **from the controlling terminal**
  (`/dev/tty`, the Windows console) — **never from the stdin that carries the message.** Today every
  lane reads the prompt's password from stdin and refuses a non-terminal stdin; this changes in all
  three lanes. A caller passes no secrets or extra descriptors it does not mean to pass.
- **Cancellation and failure** produce no signature on stdout and a non-zero exit; a signature
  already computed when a caller cancels is not "undone", and the caller must not package it.
- **What archon shows** on the terminal, before asking for the password: the key's name and
  principal, the domain, the message length and its SHA-256. That proves byte identity, not meaning.
- All of this is one command delivered identically in three binaries and pinned in
  `cli/smoke.mjs`, including its terminal and failure paths on Windows (ADR 0006).

**Executable trust (amends ADR 0007 §C.5).** A downstream tool may run `archon` only from an
**absolute path its integrator configures**, executed directly — no shell, no `PATH` search, no
fallback. §C.5's refusal of executable discovery *by name* stands; a pinned path is not discovery.
A pinned path is still not a pinned binary: packaging, update and permissions remain the
integrator's to get right.

**The key agent (amends ADR 0007 §A's rationale).** §A refused a daemon because "an unlocked seed
held by a process is an agent again, which is what cannot sign here". That reason is about
*third-party* agents, which cannot compute archon's scheme; an archon agent could run the same
code. The decision stands — no agent — for the reasons that do apply: unlocked-key lifetime,
session access control, revocation, and no demonstrated need (high-volume signers, the software
agents of the planned orchestrator, use seed files, not the store).

### 6. Consent belongs to the caller

archon signs bytes; it cannot say what they mean. The caller that understands them owns the
consent flow: **discover the principal → construct and freeze the canonical bytes → render their
meaning from those same bytes → obtain approval → sign exactly those bytes → verify (§3) → emit.**
For grants that caller is thesmos, which therefore must be trusted to render honestly; defending
against a dishonest caller would need a trusted renderer, which an opaque byte signer cannot be.
Nothing in archon recognises grant or fact formats (ADR 0001).

## Consequences

- The sdk gains additive "with signer" entry points in the lanes that carry each helper; existing
  callers and every vector are unchanged.
- `archon sign` gains `--key`, `--expect` and a machine mode, and the three password readers gain a
  controlling-terminal path. The default output and today's flags are unchanged.
- thesmos moves its signed facts to a domain (its own decision and constant: `thesmos/fact/v1`,
  thesmos#727, a clean cut), which is what makes issuance from a stored key possible under 5.
- Hardware and browser signers remain out (ADR 0007 §A): the contract lets them *declare* raw-only
  support, and the checked completion refuses them for archon's domain scheme rather than letting
  a context go missing.

## Not decided here

The request-authentication and enrollment profiles (archon#48); a raw stored-key mode; a key agent;
any change to the domain construction (ADR 0008 §6).
