# 0011 — transport integrations stay above archon; one change authority is the scope rule

**Status:** **ACCEPTED** (2026-10-04) · **Type:** scope.
**Answers** [archon#64](https://github.com/Bitspark/archon/issues/64) (a Git HTTPS credential
helper and a proof-to-bearer exchange) and [archon#65](https://github.com/Bitspark/archon/issues/65)
(SSH key association and a Git-over-SSH command boundary), which
[0010](0010-request-authentication-and-key-enrollment-profiles.md) left undecided.
**Promotes** [0001](0001-archon-scope.md)'s one-change-authority invariant to the normative scope
rule. The operator ruled both on 2026-10-04, on the external advice taken in the 0004 consultation
(`research-docs/0004-*`, internal): *accept the placement* and *promote the invariant*.

> **Status note, 2026-10-09: when a fact is signed.** [ADR 0015](0015-approving-the-right-client.md)
> §1 adds a test beside the scope rule. The rule decides which layer owns a contract. The test
> decides whether a fact is signed: *must a relying party verify it without trusting mutable state
> or an authenticated assertion from the layer that owns it?* If so, the fact, or a commitment to
> it, goes in a signed artifact of that layer, which is not necessarily archon's.

## Context

#64 and #65 ask archon for Git transport integrations. Their proposed pieces:

- a credential helper Git runs to get a username and password;
- an exchange that turns a key proof into a short-lived bearer credential;
- that credential's storage and revocation;
- an association between an SSH key and a principal;
- a gate for `git-upload-pack` and `git-receive-pack`;
- the handoff of the authenticated actor to Git's hooks;
- an authorization interface the transports call, which thesmos would implement.

Every piece passes 0001's negative test, because none needs authorization vocabulary. Every piece
fails its positive test, because none is RFC 8032/5280/5958 vocabulary. The login tier (0007) and
the request and enrollment profiles (0010) sit in the same position, so the rule as written to
contributors could not decide the case. It had been decided twice by exception.

The only planned Git host, bithost, had already designed both features for itself.

## Decision

### 1. The scope rule

> **A security contract belongs to the lowest layer that can state its complete success claim and
> validity conditions without interpreting higher-layer concepts. That layer owns the contract's
> conformance tests. Using a lower layer's proof does not move the enclosing protocol into the
> lower layer.**

This promotes 0001's invariant ("one change authority"), with the clarification above. "Lowest"
means the lowest layer that is semantically sufficient. It does not mean the lowest place that
could accept opaque bytes and invoke a callback.

The rule applies separately to each contract in a composition. A proof profile, the credential or
association built on it, and the execution boundary that enforces it may have three different
owners.

What archon owns under it:

- **core:** what RFC 8032, RFC 5280 and RFC 5958 vocabulary states (keys, the key text, the PEM
  codecs, raw and domain-separated signatures, the verification profile).
- **Named protocols whose whole success claim archon can state:**
  - the login scheme (0007), "this person's key approved this client key for this scope and
    duration, at this audience";
  - the signing boundary (0009);
  - the request and enrollment profiles (0010).

### 2. Git transport authentication is not archon's

archon can state "this principal authenticated this exchange request". It cannot state "this
credential stays confined to the authority admitted for these repositories". That needs
repositories, operations, supporting evidence, revocation and execution boundaries. So:

| piece | owner |
|---|---|
| credential helper (Git's helper protocol, repository scoping, caching, renewal, unattended behaviour) | the product (bithost) |
| exchange request | **split**: archon authenticates it with the 0010 request profile; the product owns the exchange's meaning, schema, restrictions and errors |
| exchange endpoint, and the credential's mint, store, validate and revoke | the product |
| SSH-key association statement, its SSHSIG verification, and the association store | the product (no SSH codec or SSHSIG verifier enters archon) |
| SSH command gate, and the actor's handoff to hooks | the product's Git transport and executor |
| Git permission mapping, ref-transaction authorization | thesmos (its Git adapter) |

The prohibition on bearer credentials stays where it was: a statement about the login scheme.
These credentials are kept out of archon because of their security contract and their owner, not
because they are bearer credentials.

### 3. The authorization interface belongs to the enforcement point

An authorization interface is defined by the code that enforces its decisions, initially the
product's Git integration. thesmos implements it. archon's authorizing integrations stay
profile-specific (0007's `AdmitAuthority`, 0010's enrollment integration) and do not grow into a
transport-wide interface.

### 4. What archon provides to these integrations, unchanged

- The **request profile** (0010) authenticates the exchange request, and a principal's approval of
  an SSH-key association can be an authenticated request whose body covers the association's
  intent.
- The **signing boundary** (0009) lets a helper outside archon sign with a person's stored key,
  in a domain only, without receiving the seed. The domain is the integrator's, set by
  `--domain`; it is never chosen by a server's challenge.

### 5. Moving a piece later

- **To a separate adapter package**, on evidence:
  - another independently deployed consumer with the same semantics;
  - an independent release requirement;
  - duplicated security fixes;
  - a conformance suite both consumers need unchanged.

  Such a package may live in the same repository as its first consumer.
- **Into archon**, only when the piece's complete success claim no longer depends on Git, SSH,
  credential or session semantics, repository routing or the interpretation of authority. A
  widely reused Git gate is still a Git gate.

## Consequences

- #64 and #65 are answered as not placed in archon. archon's part of both is 0010, already in
  delivery. #48's request for an archon-owned, transport-wide authorization interface is declined
  (§3).
- 0001's invariant is normative. The contributor rule (`CONTRIBUTING.md`) and the README's Scope
  section now state §1 rather than the RFC-vocabulary test alone.
- No code changes. 0010's design, its wire constants and its gate are untouched.
- The advice's guidance for the product is recorded in the consultation and routed to bithost:
  - a bounded, repository-bound credential with an authority-preservation contract;
  - three enforcement boundaries, with `pre-receive` not atomic with the ref update;
  - the SSH association's claim: *"S is a bounded credential for P under association A"*, never
    *"S is P"*.

## Not decided here

- bithost's credential, association and executor designs (bithost's);
- the thesmos Git adapter (thesmos#731);
- whether and when an adapter package is extracted (§5, on evidence);
- whether an archon module may exist in fewer languages than Go, Rust and TypeScript (moot for
  these features).
