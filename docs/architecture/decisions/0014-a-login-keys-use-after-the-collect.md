# 0014 — a login's key after the collect: bounded authority, accepted through specified protocols

**Status:** **ACCEPTED** (2026-10-07) · **Type:** protocol property / integration contract.
**Answers** [archon#121](https://github.com/Bitspark/archon/issues/121): may the browser key K,
which `archon login` delegates to, sign anything after its collect proof? **Supersedes** the
sentence in [`docs/login.md`](../../login.md) §6 that K "never signs anything but its own collect
proofs". It does not change the login's signed bytes, its vectors or its transport. Decided by
archon-57 on 2026-10-07, under the operator's ruling of 2026-10-04 that such decisions are the
agents', on the external advice taken in the 0007 consultation (`research-docs/0007-*`, internal).
Reviewed by archon-74 on its pull request.

## Context

In a login, a person's key P approves a key K that a page generated, for a scope and a duration at
one audience. The service's law admits a delegation from P to K, and the page collects it with a
proof by K (`docs/login.md` §3–§4).

On 2026-09-10 the specification conceded that K cannot be non-extractable: the collect proof is
Ed25519ph with a context, which WebCrypto cannot compute, so K is a seed that page script can
read. In the same change it stated what K has instead: "it never signs anything but its own
collect proofs". At that time nothing after the collect was defined. §7 left "request signing after
login (RFC 9421 — a separate proposal)" to a later decision, and the request profile (ADR 0010)
was then decided without mentioning login's K.

That left a gap. thesmos's gate takes the caller's key from the service's own authentication, and
accepts a chain ending P → K only when the caller is K; a copied chain is public evidence, not
proof of possession. So the delegation was bound to a key that may not authenticate. The consumers
diverged:
- aiscape planned for K to sign requests, prove itself on its WebSocket, and sign grants;
- bithost told its readers not to build on K signing requests;
- accounts and the platform leaned towards sessions held by a backend.

**The sentence also bounded nothing.** A key that page script can read can be made to sign
anything, by that script or by whoever copies it. A rule about which signatures K produces cannot
hold against the attacker it would matter for. What a system can enforce is which authority it
accepts.

## Decision

### 1. §6's sentence is superseded

K is used for the login's collect proof. After a successful collect, **a service may accept K
through a protocol it specifies**:
- **archon's request profile** (ADR 0010), the standard composition for HTTP;
- **a session the service establishes at the collect** and binds to K, under the conditions in §4;
- **a protocol of its own** (a connection proof, signed records, onward grants), with a complete
  acceptance contract: what each signature means, and when K's authority is accepted for it.

A successful login does not by itself authenticate any later operation.

### 2. The property is bounded authority, enforced where it is accepted

Every exercise of authority derived from the login stays within:
- **the approved audience;**
- **the admitted interpretation of the approved scope;**
- **the earliest applicable end:** `acceptedAt + valid_for`, every applicable grant's expiry, and
  any limit the service sets. A session or a connection may end sooner.

It is checked at each execution boundary (a command, a subscription's delivery, a stream's output,
queued work, a reconnect), as thesmos ADR 0037 already requires for reusing a decision.

**The principal is K.** The service establishes it through its authentication, or through a
credential bound to K, never from a submitted chain. Attributing K's actions to P's account must not
remove the restrictions of the delegation to K: for a chain ending P → K, the gate receives K.

This is a statement about authority derived from *this login*. K may separately hold other
authority, and no public key is marked as a "login key".

### 3. What archon requires of a service that admits a login

- **The admission contract.** `AdmitAuthority` must establish that the admitted authority
  corresponds to the approval: the right P and K, the approved scope as the service interprets it,
  the service's audience, and the login's interval. Checking that the payload holds *some valid
  grant* is not enough. archon's handler already hands the law everything this needs: the browser
  key, P, the payload, the request the proof covers, and `acceptedAt`.
- **The audience is carried by the authority, not only by a proof.** Whoever holds K can sign a
  *fresh* proof naming another audience. Domain separation and the request profile's audience check
  stop a proof from being replayed elsewhere, but not that. So the grant, the admission context, or a
  trust namespace exclusive to one deployment must restrict the authority to the approved audience,
  and every accepting route must enforce it.
- **The start.** `acceptedAt` is taken once and never moves (archon#93). Collecting, reconnecting
  and renewing must not restart `valid_for`. If the grants carry no start time, the admission
  context enforces the login's start.
- **No broader or longer authority by virtue of the login.** Onward delegation, enrollment,
  credential exchange, recovery and renewal must not acquire broader or longer-lived authority
  solely because of this login. Authority derived from it keeps its source's restrictions. A
  service must not claim a restriction its law cannot enforce: thesmos's default law allows onward
  delegation (thesmos ADR 0036), so "no onward grants" holds only where a service's law says so.

### 4. A session started at the collect is a sound completion

It is the service's construction, not login's, and it meets six conditions:
1. it is created only as a consequence of a successful collect and admission, never from a client's
   report, a request id or a public chain;
2. it is bound immutably to K, the admitted authority, the audience and the deadlines;
3. collection and session creation are single-use across concurrent requests, replicas and retries;
4. nothing renews it past the authority's end;
5. each operation is still authorized under the law;
6. the service states how a session ends, since immediate revocation needs a server-side check.

archon's handler already makes collection single-use within one process. A deployment with replicas
makes it single-use across them.

**A page-readable K still matters under a session.** A copy of K can race the page to collect, and
it is not inert afterwards if any route accepts K or authority derived from it, for example an onward
grant K → L. A client that has no further use for K discards it at the handoff.

**Bearer credentials.** The login protocol issues no bearer credential. A service that completes the
exchange with a bearer session, or another credential, specifies that construction and its binding
to the admitted authority. An HttpOnly cookie keeps page script from reading the session, not from
using it. A credential returned to JavaScript has no such protection.

### 5. Connections are the integrating protocol's

Login defines no session, WebSocket, stream or connection authentication. A browser cannot add
headers to a WebSocket upgrade, so a service authenticates a connection by its session cookie (with
an Origin check, as a supplement and never alone), by a challenge and K's proof in the first
messages, or by a single-use ticket from an authenticated request. Whichever it chooses, it
specifies:
- the signature domain, version, purpose and role;
- a fresh, short-lived, single-use challenge, associated with the actual pending connection;
- the binding to the audience and the endpoint;
- which key becomes the principal and how its authority is obtained;
- timeout, failure, reconnect and expiry behaviour.

Using archon's possession proof does not make such a protocol archon's (ADR 0011). A reusable archon
connection profile would be a new archon protocol version, taken up when a product needs one.

### 6. What is not adopted

- **"Any signature domain except archon's" as a rule.** Signature domains tell protocols apart; they
  do not make K eligible in any of them. Each accepting protocol states its own conditions.
- **Excluding `archon-enroll/1` as a defence.** A proof of possession never raises a key's standing;
  elevation is the enrollment endpoint's and the law's policy. K could otherwise ask an issuer to
  grant to another key through an ordinary request.
- **An sdk that confines K, for now.** Interfaces that bind K to its collect, its audience and its
  deadline would help callers avoid mistakes, but they bind only archon's code, never a copy of the
  seed (ADR 0012 records the same limit). Deferred until the first consumer builds the browser half
  of login, or asks for them. Restrictions are enforced where authority is accepted.

## Residual risk

- **Page compromise.** A service that accepts K directly exposes all the authority it accepts
  through K, for as long as that authority lasts. A copy of K stays usable until the authority ends
  or the service blocks it. Short proof windows, sdk restrictions and deleting K locally do not
  change that.
- **Signing in advance.** Request verification does not show that the sender holds K now: someone
  who could sign for a while can prepare requests for later windows (ADR 0010 §5). The hard bound is
  the authority check at the time of use.
- **A session.** An HttpOnly session reduces extraction by page script, but malicious page script can
  still act through it, and any operation that creates credentials can undo that advantage.
- **Consequences outlive permission.** Expiry stops further use of the delegation. It does not undo
  writes, copied data or configuration changes already made.
- **Approving the wrong client.** A person can approve, at the genuine service, a pending request an
  attacker created for the attacker's K. That needs its own analysis, tracked separately.

## Consequences

- **`docs/login.md` §1, §6 and §7 are rewritten** to this decision. The stale reference to a browser
  client package (`sdk/ts/login/browser`), which archon never shipped, is removed. ADR 0007's
  historical table keeps it as it was.
- **thesmos** is asked whether a grant can restrict onward delegation and the audience; services must
  not claim either until their law enforces it.
- **aiscape's** planned login route is a reasonable composition under §1–§3, with its connection
  proof, its write envelopes and grants signed in the page each needing the acceptance contracts
  above.
- **bithost's** review answers on login keys are revised: the warning against K signing requests is
  replaced by the conditions here. bithost may still refuse P → K chains as its own policy.
- **No signed bytes change**, so no vectors change and no login version moves.
