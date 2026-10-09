# 0015 — approving the right client: a prover contract, residual risk by form, and no new login version

**Status:** **ACCEPTED** (2026-10-09) · **Type:** protocol property / integration contract.

**Answers** two questions:
- [archon#123](https://github.com/Bitspark/archon/issues/123): how a person ties a login approval
  to the client they meant to approve, when anyone can begin a pending request and send them its
  address;
- the open parts of [archon#125](https://github.com/Bitspark/archon/issues/125): what a prover other
  than archon's CLI must do, such as a custodian holding P, and what login contributes when one
  backend is both the login's client and the service that admits it.

**Scope.** It does not change the login's signed bytes, its vectors or its transport. It adds a
separate encoding, the transaction fingerprint, with its own vectors.

**Who decided it.** Decided by archon-0b on 2026-10-09, under the operator's ruling of 2026-10-04
that such decisions are the agents'. It rests on the external advice taken in the 0008 consultation
(`research-docs/0008-*`, internal). Reviewed by archon-2a on its pull request; its three points (the account binding with the shipped
handler, renewal beside ADR 0014, and the fingerprint's audience) are folded in.

## Context

**The approval relay.** Begin is unauthenticated (`docs/login.md` §4). An attacker begins a login at
the genuine service with their own K and sends the person the address. The person's CLI then shows a
true statement: the genuine audience, a plausible scope, and a key they cannot recognise. If the
person approves, the attacker's page collects a delegation from them.

The binding is "unrelayable" in §6's sense: a proof made for one audience verifies nowhere else. That
property concerns relaying a *proof*. It says nothing about relaying the *request for approval*.
RFC 8628 names the same attack remote phishing, and keeps it as a residual risk. RFC 10027 (BCP 247,
August 2026, "Best Current Practice for Security of Cross-Device Flows") treats it at length.

**The platform deployment.** Bitspark's platform keeps each ordinary member's P in a custodian that
signs after the person approves on their phone through accounts. Each product backend is then both
the login's client, holding K, and the service that admits the login. The prover is no longer the
person's own terminal. accounts' proposed decision holds every custodial login until archon decides
(bitspark-accounts PR #21, H10).

**The advice's central rule:** "Approval must be bound both to the exact authorization being issued
and to an independently established initiating context. A binding to the authorization does not, by
itself, establish that context."
- A matching value helps only when one side comes from the actual initiating client, through a
  display the person already trusts. An attacker who supplies the initiating display can show
  matching values for their own request.
- Account matching refuses a relay across accounts, but not one within the person's own account.

## Decision

### 1. No new login version

Nothing below changes `archon-login/1`'s bytes. They are specification, CLI, service and platform
changes, and one auxiliary encoding with its own vectors (§4).

**Where a fact belongs.** ADR 0011's scope rule decides the layer. One more test decides whether the
fact is signed: *must a relying party verify this fact without trusting mutable state, or an
authenticated assertion from the layer that owns it?*
- If so, put it, or an unambiguous commitment to it, in a signed artifact of the layer that owns it.
- That artifact is not necessarily the login proof.

Applied here:

| fact | its home |
|---|---|
| P's approval of audience, K, request, scope and duration | the login proof, as today |
| exact grants, absolute ends, renewal powers, other destinations | the signed authority and mandate artifacts (the law's) |
| the initiating account, epoch and browser session | the deployment's transaction state; authenticated or signed evidence where another party must verify it |
| how the approval was obtained | an approval-evidence profile (accounts and the custodian) |
| who held P | custody records or attestations, never a self-description inside the proof |

Signing an account identifier does not refuse a same-account relay. Signing a session identifier does
not help when the session is the attacker's. A new login version is warranted only when archon itself
promises a new portable claim and defines how verifiers enforce it. Such commitments never go into
ad hoc scope strings to avoid versioning.

**Rollout.** An old and a new prover make indistinguishable v1 proofs. A service cannot read the
stronger ceremony from the signature. A service that needs it enforces its own initiation state and
evidence, and refuses the paths that bypass them. A CLI version string is not proof of a compliant
approval.

### 2. The prover contract

[ADR 0009 §6](0009-the-signing-boundary-and-the-signer-contract.md) puts consent in the caller
that understands the bytes. This decision extends that to **every prover of a login**: the CLI, and any other holder of P, such as a
custodian. `docs/login.md` §5.1 carries the normative text:
1. Select the signing principal.
2. Obtain and validate the pending request.
3. Establish the audience itself (§2).
4. Freeze the complete message to be signed **before** asking for approval.
5. Generate the presentation from that frozen message. Caller-supplied explanatory text is never an
   authoritative description of what will be signed.
6. Obtain approval of that exact operation, or rely on an explicit policy authorized earlier that
   covers it. Authentication of an account alone is not approval.
7. Sign only the approved bytes and verify the signature.
8. Record the operation's single use. A material change needs a new approval.

A prover never presents a valid audience, a displayed key identifier or a matching value as
evidence that the person initiated the request.

### 3. What a login claims, at three levels

- **Cryptographic:** a valid signature under P commits to this request's audience, K, id, scope and
  validity, in the login domain and over the request's nonce.
- **A conforming prover:** the prover obtained approval of a presentation generated from the frozen
  operation before signing it.
- **A custodial deployment:** the custodian signed with P after an account service authenticated
  approval of the custodian's operation. The claim is subject to the recorded evidence and the trust
  placed in that service, its presentation and the custodian. For unattended renewal: the custodian
  signed under an existing mandate after evaluating its current conditions, and no fresh human
  approval is asserted.

None of these claims sole control of P or a qualified signature. ADR 0011's sentence, "this person's
key approved this client key for this scope and duration, at this audience", is the cryptographic and
conforming levels together.

### 4. The page-started form

- **The transaction fingerprint.** It is the first 16 bytes of
  `SHA-256(u16be(len d) ‖ d ‖ u16be(len nonce) ‖ nonce ‖ Binding(0x01, audience, request))`, with
  `d = "archon-login-fingerprint/1"`. It is shown as eight groups of four lowercase hex digits.
  - The page computes it from the K it generated and its own begin response. It takes the
    audience from that response's `verification_uri` with derive-audience (§2.1), never from its
    own configured spelling, so a spelling difference cannot make every fingerprint mismatch.
  - The CLI computes it from the exact request it will sign.
  - It covers the whole transcript, not K alone, so it distinguishes requests that reuse a key and
    shows any difference in scope or validity.
  - At 128 bits there is no offline search for a match.
  - It is pinned by `vectors/login.json`'s `login_fingerprint` family in the three lanes. It is not a
    signature and changes no signed bytes.
- **It is conditional protection.** It detects substitution only when the person compares against a
  page they started and trust. The attacker's own page can show the matching value beside its
  instruction. So:
  - a page shows it only for the request its own K began, never for whichever request an address
    names;
  - the CLI tells the person to compare it with the page they started.

  The CLI cannot observe what a page showed. A flow that requires comparison fails when the
  comparison cannot be made, which the person enforces by answering no, the default.
- **The confirmation states its consequence.** Before `sign? [y/N]`, the CLI prints "This gives the
  browser key above authority to act as you. Approve only a client you started yourself." Decline
  stays the default (RFC 10027 §6.1.14).
- **No universal prior authentication.** Clients with no prior session (a CI job, a container, a
  fresh browser) are legitimate login clients. Stronger initiation is a service profile, and an
  approval without a comparison is lower assurance, which `docs/login.md` says.
- **Services SHOULD:**
  - offer the offers form;
  - protect the page that begins a login;
  - bound pending requests and their lifetimes;
  - provide a way to find and end issued authority;
  - where accounts exist, bind a pending request to the account that began it, and admit only that
    account's P.

  With the shipped handler, the service binds the account by wrapping begin:
  - it authenticates the session on its own begin route;
  - it takes `id` from the handler's `201`;
  - it records `id` → the account;
  - `AdmitAuthority` refuses any P that is not that account's bound key.

  It never puts the account into a scope entry (§1).

### 5. The offers form

It is the recommended form for a person who can start at their own terminal. The attacker must then
obtain a confidential capability minted by the person's prover, instead of persuading the person to
approve a request the attacker made. Two things already hold, and are now MUST text:
- The code is confidential, short-lived and single-use. Taking an offer binds it atomically to one
  request and K, and nothing replaces that binding (§4.1, rule 5).
- The prover signs automatically only for its outstanding offer and its frozen parameters. Expiry,
  cancellation, a conflict or changed parameters never fall back to page-started approval.

One thing changes:
- **The CLI prints the page address only on a trusted origin.** The address carries the code. It is
  printed only when it is HTTPS (or HTTP on a loopback host), and either on the audience's own
  origin or on an origin the person names with `--page-origin`. A label saying "do not open it" is
  not a trust relationship.

Guidance for a service's page:
- keep the address out of logs and telemetry;
- minimise script on the receiving page;
- remove the code from the browser's history once taken.

The ledger the CLI prints afterwards is an audit record, not the defence. The defence is exclusive
possession of the code, and the first use binding it to K.

### 6. A prover that is not the person's CLI, and a backend that is both client and service

**A remote prover's request.** The prover builds the retrieval address from its own registration of
the service's audience and the request id. It fetches the pending request itself and derives the
audience by §2.1. It takes no audience, binding field or statement from the party that asked it to
sign. The fetch uses:
- authenticated transport;
- controlled egress;
- bounded responses;
- a redirect policy that cannot change the audience.

Fetching it independently keeps what the prover shows and what it signs from diverging. It does
**not** make the requesting backend's choices (its K, its coverage) reflect the person's intent.

**A custodian's operation is larger than the login binding.** It includes:
- the proof's domain, nonce and binding;
- P;
- the exact grants to be signed;
- the product and account bindings;
- the pending session;
- the deadlines;
- the custody mode;
- any renewal mandate.

The prover contract covers the whole operation. Approving a login proof is never permission to sign
an arbitrary accompanying grant: the payload is opaque to archon, so the party issuing it must
understand and limit it, and admission checks the correspondence.

**What a login presentation shows, at minimum:**
- who acts: the account, P, the service, the audience, and which party holds K;
- what authority is issued: the exact scope strings, beside any interpretation of them;
- for how long;
- what further authority it creates, such as renewal;
- which initiation it belongs to, with verified facts kept distinct from estimates.

A previously unseen key fingerprint is available, but recognising it is not the person's main task.

**When one backend is both client and service.**
- **What login contributes:** across the boundary between custodian and backend, a standard
  P-signed approval statement, domain separation, request freshness and an admission lifecycle.
- **What it does not:** separation inside the backend.
- **Single use comes from atomic state, not the collect proof.** ADR 0014's condition 3 already
  says this.
- **A grant alone could carry K, coverage, audience and deadlines,** so a login proof is not
  logically indispensable. Its value is a common contract independent of the law's grant language,
  not a second source of the person's intent.
- **archon's login (unchanged) is the first construction.** Issuing the grant directly is legitimate
  only with a complete named-operation profile covering approval, audience, freshness, admission and
  lifecycle.
- **Downstream services:** either they implement operations within the login's audience (one logical
  boundary), or each destination gets separately restricted authority. Until a deployment specifies
  one, it refuses the login's authority at any other audience. ADR 0014 already says so.

**Interval matching.** A grant signed before `acceptedAt` matches the login when the login's interval
is its upper bound: the admitted authority ends no later than `acceptedAt + valid_for`. Exact
equality with a clock reading taken later is not required.

**Renewal.**
- A replacement is a new immutable admission, switched in atomically. The old admission's deadline
  is never mutated.
- A replacement's authority is bounded by what authorized it, a fresh approval or a mandate's end,
  never by extending the login it replaces. So ADR 0014's "renewing never restarts `valid_for`"
  holds.
- A switched session pointer does not invalidate a published grant. So superseded grants are
  retracted, or every accepting route enforces the current generation.
- If replacement grants keep going to the same K, a stolen K keeps receiving them, so a short grant
  is not a short compromise window.

**The platform's launch.** The relay within one account is not closed by account matching plus a
code. archon's condition for a custodial login is the platform's end-to-end test: an attacker's
same-account pending session cannot obtain authority by relaying its code and presentation through
any permitted sign-in path.

### 7. Who owns what

- **archon:** proof construction and verification, audience derivation, the request lifecycle, the
  prover contract, the fingerprint's encoding, and honest statements of what login does not
  establish.
- **thesmos and stele:** authority interpretation, narrowing, audience restriction, activation,
  residence, retraction, and authorization of replacements.
- **accounts and the custodian:** account and epoch continuity, authenticated approval, evidence
  verification, trusted presentation, signing activation, and mandate execution.
- **products:** the genuine initiating display, browser-session binding, custody of K, admission
  and session association, and the declared downstream boundary.

**Routed, not archon's** (on archon#125, and to thesmos for activation):
- a fresh phishing-resistant sign-in in the initiating browser, bound to the pending delegation
  (RFC 10027 §6.1.15, "Authenticate then Initiate");
- a correlation code the custodian mints, shown only in the initiating session and typed into the
  approval;
- account continuity checked before presenting, before signing and at admission;
- the receipt and the passkey evidence (accounts PR #20);
- the renewal mandate's rules, and one K per episode;
- whether publication activates authority before admission;
- durable issuance identifiers and recovery;
- a backend asking for more coverage than intended;
- a revocation consistency contract.

## Consequences

- `docs/login.md` gains:
  - the claim's levels (§1.1);
  - the offers form's delivery rules (§4.1);
  - the prover contract, a remote prover and the fingerprint (§5.1–§5.3);
  - the residual risk for each form, interval matching and renewal (§6).
- The sdk gains `Fingerprint` in three lanes, with vectors.
- The CLI shows the fingerprint and the consequence, and refuses an untrusted offers page. That last
  change narrows behaviour: an off-origin or plain-HTTP page is no longer printed.
- ADR 0011 gains a status note pointing to §1's signing test.
- **Deferred:** a configurable cap on pending requests in archon's handler. Trigger: an open issue on
  Bitspark/archon reports pending-request exhaustion.

## Not adopted

- **A new login version,** or signing the account, session, custody or approval method into the
  proof (§1).
- **Prior account authentication as a universal login requirement.**
- **Account matching and a matching code as the close of the relay within one account.**
- **A short fingerprint.** It would need a guessing and retry model, and a short hash of a key the
  attacker chooses can be searched for offline.
