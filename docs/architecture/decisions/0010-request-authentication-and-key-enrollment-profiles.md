# 0010 — request authentication and key enrollment profiles

**Status:** **ACCEPTED** (2026-10-04) · **Type:** contract / tier. The design is decided, and
since §8's gate was met the **wire is fixed as version 1** (the status note below).
**Rules the row [0007](0007-custody-in-the-command-and-the-login-server-tier.md) left open**
("RFC 9421 / 9530 helpers — a separate ADR, not ruled"), and narrows 0007 §B's "in-memory, single
process" to the login handler. The operator ruled this on 2026-10-04, on the external advice taken
in the 0003 consultation (`research-docs/0003-*`, internal): "a narrow RFC 9421 request profile"
and "E2 enrollment". It answers [archon#48](https://github.com/Bitspark/archon/issues/48), and
builds on [0009](0009-the-signing-boundary-and-the-signer-contract.md)'s signer contract.

> **Status note, 2026-10-04 — the wire is fixed: §8's gate is met.** The vectors and every §8
> failure test now exist in all three lanes, through each lane's own HTTP stack, so §8's four
> provisional values are fixed as **version 1**:
>
> - the request domain and profile tag: both `archon-request/1`;
> - the echo header: `Archon-Audience`;
> - the covered components, in this order: `@method`, `@target-uri`, `archon-audience`,
>   `content-digest`, then `content-type` if the request carries one, then each product-declared
>   header it carries, in the product's declared order. The signature parameters are `created`,
>   `expires`, `nonce` (16..=64 bytes), `keyid` and `tag`, in that order, under the label
>   `archon` (`docs/request.md` §3–§5);
> - the enrollment binding, in `archon-enroll/1`: `0x01 ‖ u16 purpose ‖ u16 audience ‖ u16
>   transaction ‖ new key[32] ‖ intent digest[32]` (`docs/request.md` §6).
>
> **The evidence:**
>
> - `vectors/request.json`: 139 cases, with every signature derived with OpenSSL outside the
>   cores;
> - the request profile's failure tests in `server/{go,ts,rs}` ([#81](https://github.com/Bitspark/archon/pull/81),
>   [#82](https://github.com/Bitspark/archon/pull/82), [#84](https://github.com/Bitspark/archon/pull/84));
> - enrollment's substitution and replay tests ([#85](https://github.com/Bitspark/archon/pull/85)).
>
> Each failure test was proven to fire by perturbing the source it guards. A change to any value
> above is a new wire version, never an edit (`docs/request.md` §8). One lane-specific reading is
> recorded where it applies: TypeScript's fetch entry point verifies the request a fetch
> application routes on, because a fetch `Request` no longer carries the raw request line
> (`docs/request.md` §7), as this ADR's §4 requires: "The verifier authenticates the request the
> application processes."

## Context

Login (0007) proves that a person approved a browser key. Two further statements are wanted.

**"This key made this HTTP request."** An agent or service calling an archon-authenticated API
signs each ordinary request. Today every service would have to define destination binding, body
integrity and replay handling for itself, and each of those definitions is security-sensitive.

**"This new key belongs to this account."** A service adds a key to an account that a session or
a bootstrap credential already authorizes. The new key proves possession, and the existing
authority says whose key it becomes.

Both need archon's signature construction: Ed25519ph with the domain as the RFC 8032 context
(0008). No registered HTTP-signature algorithm names that construction, so no off-the-shelf
verifier checks it as it stands.

## Decision

### 1. archon owns both profiles, narrowly

- The **sdk** holds transcripts, parsing rules, coverage requirements and pure verification.
- The **server adapters** hold HTTP extraction, the clock and the replay store.
- **Products** hold authorization and their deployment infrastructure.

The envelope (0004) is unchanged: freshness belongs to the request profile, not to a generic
signed container. archon learns no authority vocabulary (0001).

### 2. The request profile is an RFC 9421 application profile

It is called **"archon's RFC 9421 application profile"** and requires archon's signature
construction and verification profile (0008).

- The signature-base bytes RFC 9421 defines are signed **directly**, in a fixed request domain.
  There is no possession framing around them.
- **`alg` is omitted.** The registered `ed25519` means pure Ed25519, and archon's construction is
  never labelled with it.
- Interoperability is claimed only after an independent RFC 9421 implementation, given the
  construction as an adapter, produces matching signature bases and verifies.
- Not chosen: a DPoP-shaped proof. DPoP binds access tokens and leaves the payload outside the
  proof, so it is the wrong abstraction here. A bespoke canonicalization wrapped in the possession
  layout was also rejected: it would still have to settle every HTTP question RFC 9421 already
  models.

### 3. The v1 profile is deliberately narrow

| dimension | rule |
|---|---|
| selection | one construction, one versioned request domain, a required signed profile tag; no algorithm fallback |
| principal | `keyid` is archon's canonical principal text; no other key names, no network key discovery |
| destination | cover `@method`, the complete `@target-uri`, and the configured audience as a **checked echo** header (provisionally `Archon-Audience`). The client derives it from trusted configuration, and the verifier requires exact equality with its own. |
| body | a covered SHA-256 `Content-Digest` (RFC 9530) is required, including for empty content, and is **recomputed** over the received content |
| interpretation | cover `Content-Type` whenever present, plus every header the product declares security-relevant (tenant selection, conditional headers, which authority evidence applies, an idempotency key). archon understands only header names and coverage. |
| freshness | signed creation time `c`, expiry `e`, and a fresh client identifier of at least 128 random bits |
| acceptance | the configured coverage set is required; missing coverage, ambiguous authentication fields and unsupported features are refused |

**The audience echo is a deliberate difference from login.** Login never transports its audience
(0007 §C.1), and that rule stands. Here the audience travels only to be compared with
configuration; it is never a source of configuration.

### 4. Canonicalization and the proxy boundary are release gates

- The verifier authenticates **the request the application processes**.
- Queries are not sorted, duplicates not collapsed, escaped separators not decoded, and no target
  is rebuilt from a framework object that has lost distinctions. Supported target forms are
  defined, and anything ambiguous is refused.
- The body digest is recomputed after transfer framing is removed, before content decoding
  changes the bytes, and before any application side effect.
- v1 accepts no compressed request bodies and no trailers.
- `Forwarded` and `X-Forwarded-*` are never authoritative. A deployment either verifies before the
  proxy transforms the request, or carries the external request over a trusted, authenticated hop.

### 5. Freshness and the replay store

A request is accepted when `0 < e − c ≤ W` and `c − δ ≤ t < e + δ`, where `t` is the verifier's
time, `W` is the longest proof lifetime and `δ` the clock tolerance. The implementing spec fixes
integer units, inclusivity and overflow behaviour. **Deployments choose finite `W` and `δ`**;
archon ships no universal default.

What this proves, and what it does not: **the key authorized this exact request**, accepted within
a bounded window and at most once. A key holder can pre-sign future requests, so it does **not**
prove the submitter holds the key right now. A deployment that needs that uses a separately
specified server-challenge profile; the two are never silently swapped.

The replay store is part of the contract. Its one operation is
`insertIfAbsent((profile, audience, principal, proofId), retainUntil) → inserted | alreadyPresent | unavailable`:

- there is one winner across every verifier in the acceptance scope;
- the proof and its freshness are verified **before** inserting;
- `unavailable` **fails closed**;
- an entry is retained until no verifier can still accept the proof;
- the key is never the signature bytes alone;
- in-memory state needs a restart policy, because losing accepted identifiers reopens old proofs.

archon specifies the interface and its consistency and failure rules; a deployment supplies the
implementation. **This lifts 0007 §B's "in-memory, single process" for new profiles only.** The
login handler is unchanged.

### 6. Retries, redirects, and what reaches the application

- A retry carries a **new proof identifier** and keeps the application's idempotency key. Replay
  protection is not exactly-once execution.
- Client adapters do not follow redirects for signed requests. A permitted redirect is signed
  anew for its new destination.
- Only a request that passed freshness and replay checks reaches application code, as an
  **`AuthenticatedRequest`**: the principal **together with the verified request descriptor**.
  Authorization then evaluates the request that authentication verified, not a re-parse of it.

### 7. Enrollment is its own statement (E2)

Login has a person approve a browser key. Enrollment has a new key prove its own possession while
a separate authority says whose key it is. Reusing login's binding would carry fields that mean
nothing here and hide that difference.

- **The construction.** The possession scheme (0004), with the server's fresh nonce, in domain
  **`archon-enroll/1`**. The binding is length-prefixed and covers: version, purpose, the
  configured audience, the pending transaction's id, the new public key, and a digest of the
  immutable enrollment intent. The intent is opaque bytes to archon. A digest is not
  confidentiality, so guessable account data stays out of it.
- **The authority lives in the transaction record.** The service creates the pending record only
  after it has validated the session or bootstrap credential. The record holds an immutable
  association of authorizing context, intended account, purpose, new key, nonce, intent digest and
  expiry. Completion names the record; it cannot substitute an account or a key.
  - A session-based enrollment requires the same authorized session at completion. A session
    cookie never enters the signed transcript, and cookie flows need CSRF protection at both ends.
  - A bootstrap credential is reserved atomically to one transaction and key.
- **Completion is the service's atomic business operation.** archon's adapter cannot promise
  atomicity across a callback and a separate database.
- **There is no "possession alone suffices" mode.** An enrollment adapter cannot be constructed
  without its authorizing integration. Possession identifies a key; it does not tie that key to an
  account. This is the opposite of login, where omitting the law is allowed.
- Retries of a completed transaction, rotation and recovery are distinct purposes with distinct
  policy. They do not inherit "add a key".
- Enrollment shows that an account and a key are associated. It does not show that the key is
  non-exportable, lives on one device, or is used by only one process.

### 8. The gate before the wire is frozen

The following are **provisional**, chosen by the implementing PR:

- the request domain and profile tag;
- the echo header's name;
- the exact covered-component list;
- the enrollment binding's byte layout.

They become fixed when vectors **and** these failure tests exist, run through each lane's real
HTTP framework:

- wrong-key and dropped-context signers;
- query and path ambiguity;
- empty and modified bodies;
- missing covered headers;
- expiry bounds;
- concurrent duplicates;
- replay-store outage and failover;
- restart;
- enrollment's substitution and replay paths.

A status note on this ADR then records the fixed values.

Wire versions are independent of package versions: lockstep releases are not atomic deployments.
Each profile specifies the versions it supports, how it rejects others, and how it migrates.

## Consequences

- `sdk/` gains the request transcript and verification and the enrollment binding. `server/` gains
  extraction adapters, a replay-store interface with an in-memory reference implementation
  carrying its restart caveat, and an enrollment adapter. All of it follows lockstep (0005).
- 0007's open row "RFC 9421 / 9530 helpers" is closed by this ADR.
- **Downstream adapters build on these profiles and are not decided here.** That includes the Git
  HTTPS credential helper (#64) and SSH key binding (#65). Their scope is a separate decision, and
  they cannot freeze anything before §8's gate is met.

## Not decided here

- the numeric `W` and `δ` (each deployment's);
- a server-challenge request profile;
- rotation and recovery protocols;
- #64 and #65;
- any change to the signature construction (0008 §6).
