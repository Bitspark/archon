# 0013 — enrolling a stored key: a renderable intent, `archon enroll`, and tokens carried by hand

**Status:** **ACCEPTED** (2026-10-05) · **Type:** command / format contract.
**Answers** [archon#113](https://github.com/Bitspark/archon/issues/113): a key in archon's store
cannot make the `archon-enroll/1` proof, because `archon sign` refuses archon's own domains and no
command makes it. **Refines** [0010](0010-request-authentication-and-key-enrollment-profiles.md)
§7's intent rule (its status note of today). Decided by archon-1e on 2026-10-05, under the
operator's ruling of 2026-10-04 that such decisions are the agents', on the external advice taken
in the 0006 consultation (`research-docs/0006-*`, internal). archon-92 reviewed the design on #113
with no objection. bithost, whose service builds the intent, is asked on
[bithost#69](https://github.com/Bitspark/bithost/issues/69). The specification is
[`docs/enroll.md`](../../enroll.md).

## Context

Enrollment ([0010](0010-request-authentication-and-key-enrollment-profiles.md) §7;
[`docs/request.md`](../../request.md) §6, version 1) has a new key prove its own possession over a
binding of the purpose, the audience, the pending transaction, the key, and **the SHA-256 of the
service's intent**. The authority (a session, or a bootstrap credential) lives in the service's
record, and completion needs the same authorization that began it. 0010 §7 kept the intent opaque
to archon and said that "guessable account data stays out of it".

A person whose key is in archon's store has no way to make that proof. 0009's status note reserves
`archon-*` domains from `sign`, so that archon's own protocol signatures are made only by commands
that show what they mean, and no such command exists for enrollment. The interim is to enroll a key
*before* storing it, with the sdk and a plaintext seed.

A command that showed what the binding holds would show the service, a purpose, the person's own
key, and a digest. **That is not enough for consent.** An attacker signed in to the real service as
*themselves* can begin an enrollment naming the victim's public key, which is public, and get the
victim to make the proof. The attacker's own session then completes it, and the victim's key joins
the attacker's account. Every check passes: the proof is valid, and the authorization at
completion is the one that began the record. Same-session completion stops one session from
finishing another's enrollment. It does not show that the person signing meant that session's
account. Nothing the person could read would tell the two accounts apart.

## Decision

### 1. The proof and the authority stay where they are

The binding stays version 1, and its wire is unchanged. Authority stays in the service's validated,
immutable pending record, and completion stays the service's atomic operation. The proof still
binds only the intent's digest, and verification and completion never read the intent. Format 1
(§2) is read only by the command, and by the server's helper that writes a challenge token, to
check the purpose given to `Prepare`. What is added is the **third**
thing an enrollment needs, beside the possession proof and the service's authorization: that the
key holder can see what they are agreeing to.

### 2. A renderable intent, format 1, opt-in for services

archon defines an intent format a service may choose to build
([`docs/enroll.md`](../../enroll.md) §2): a format byte; a **blind** of 16 to 64 random bytes; the
service's **account id**; the account's **unique name**, such as its sign-in handle, with its
namespace where the handle is scoped to one; the **purpose**; and up to 32 **restrictions**. Every
text field must be free of display-unsafe code points (0.12.0's set), and the sdk refuses anything
else at encoding and at decoding.

- **The id is for precision and the name is for people.** An opaque id alone repeats today's
  problem. **The name must be unique to the account, never a display name its holder chooses
  freely.** Otherwise an attacker names their own account after the victim, and the statement
  shows the victim's name beside an id nobody checks. A unique name can still be imitated by a
  look-alike, which is the residual risk below.
- **The service builds it from its own records**, never from a label the browser sent, and keeps
  the exact bytes beside the record.
- **Privacy, refined, not abandoned.** 0010 §7's rule exists because the digest travels to the
  client, and SHA-256 does not hide a low-entropy input: anyone holding the digest of an email
  address could confirm a guess. The blind inside the intent closes that. Seeing the digest
  reveals nothing, and seeing the intent reveals the account to the person the command shows it
  to. The rule becomes "**no intent has a guessable preimage**" (0010's status note). The
  same idea is SD-JWT's (RFC 9901): random salts in the digested material, with no SD-JWT
  machinery adopted.
- **A label outside the digest proves nothing.** The command shows only what it decoded from the
  bytes whose digest it binds. It takes the purpose and the digest from the intent itself, never
  from a second field beside it.

### 3. `archon enroll`: interactive, a store key, no blind mode

The command ([`docs/enroll.md`](../../enroll.md) §4):

- **Its inputs.** It takes a store entry (`--key`, or the default). Its audience is selected
  independently (`--audience` or `ARCHON_AUDIENCE`, canonical, as `login`'s offers form). It reads
  a challenge token from a file or one line of stdin, never from the command line.
- **Its checks before display.** It refuses a token for another audience or another key, a passed
  deadline, an intent it cannot decode, and every purpose but `add-key`.
- **Show, then sign.** It shows the account association on the controlling terminal and asks
  there, defaulting to no. Only then does it unlock the same snapshot of the entry. It checks that
  the authenticated header key and the seed-derived key both equal the key it showed. It binds
  SHA-256 of the intent bytes it showed, so **what it shows is what it binds**.
- **Its output.** It prints a proof token. Its success means "proof produced"; the key is
  enrolled when the signed-in page completes.

**There is no blind mode.** An intent the command cannot render is refused, never approved by
digest. A service that keeps its intent opaque proves with the sdk, or waits for the presentation
in §7.

**It is interactive only.** An unattended approval is not consent, and a password supplied through
`ARCHON_KEY_PASSWORD` or `--password-fd` must not quietly stand in for one. So the confirmation is
always asked on the controlling terminal. There is no `--yes`, and without a terminal the command
refuses. Unattended enrollment needs a stated policy instead, which is §7's automation mode.

**A store key only.** The command exists for keys in the store, the gap in #113. A store entry's
header names its public key, so a token for another key is refused before anything is shown,
without touching key material before consent. Seeds and key files already prove with the sdk.

**The store's policy (0012 §4) applies.** An *unrestricted* entry permits `archon-enroll/1`. An
*allowlist* entry must list it. Because `key policy` replaces a list rather than adding to it, the
refusal prints the command that adds `archon-enroll/1` to the entry's current list: for a key made
for thesmos delegation, `--allow thesmos/fact/v2 --allow archon-enroll/1`. **Listing the domain
admits only this command.** `archon sign` still refuses `archon-enroll/1` (0009's status note),
whatever the policy lists, so an entry that may enroll still cannot be made to sign arbitrary
enrollment bytes.

### 4. The tokens: one line, carried by hand

The challenge and the proof each travel as one line: a fixed prefix (`archon-enroll-challenge-1:`,
`archon-enroll-proof-1:`), then lowercase hexadecimal of length-prefixed binary, in the binding's
own style ([`docs/enroll.md`](../../enroll.md) §3). JSON was the alternative, and it was rejected:
duplicate members parse differently across Go, Rust and TypeScript, and the advice asks that
duplicates be refused. A length-prefixed record cannot hold a duplicate, and it decodes identically
in every language.

**The manual transport ships first.** It needs no route in archon, no credential beside the
session, and no listener. The page shows the challenge token, the person carries it to the command
by a file or a paste, and carries the proof token back. The page checks that the proof is for its
own pending enrollment and completes under the session it validates then.

**Delivering a proof is not completing.** Any later transport (§7) delivers the proof to the page,
which completes. No transport acquires the browser's authority to enroll.

### 5. What services must do

These are in [`docs/enroll.md`](../../enroll.md) §6. In brief:
- **The intent's promise.** Build the intent from validated records, with the account's unique
  name, and keep its bytes with the record. Pass `Prepare` the intent's purpose. Make completion do
  what the intent says, so the account, purpose and restrictions shown describe the change made.
- **Time for the transfer.** The token's deadline is the record's expiry, rounded down to the
  second. A by-hand flow needs a longer `TTL` than the adapter's five-minute default.
- **Completion.** Take back only the page's own pending enrollment, and authorize completion from
  a credential validated then, never from a stored or client-supplied identifier.
- **The key on the page.** Show the full key on the page. Name a policy for a key already enrolled
  elsewhere, and reserve nothing on an unproven enrollment.

### 6. What is not promised

- **The sender is not authenticated.** Recomputing the digest proves that a proof the service
  accepts matches what was shown. It does not prove who sent the token.
- **Audience selection is consistency, not intent.** It stops a token from changing the service.
  It cannot know which service the person meant, and a hostile program that can set the
  environment can set `ARCHON_AUDIENCE`. That is why the statement leads with the audience.
- **No evidence of review.** The libraries can still sign in `archon-enroll/1`, so a valid proof
  does not show that anyone saw a statement. The command protects the person; it attests nothing
  to the service.
- **The local trust base** is the `archon` binary, its configuration, the controlling terminal and
  the process holding the unlocked seed. Reading the terminal or the clipboard while the exchange
  runs is the exposure `login` already accepts ([`docs/login.md`](../../login.md) §4.1). Controlling
  the prompt is more than that, and no prompt survives it.

### 7. Deferred, each with its trigger

| what | trigger |
|---|---|
| **A command-started rendezvous.** The command registers an offer, the signed-in page claims it once, the command fetches only that offer's challenge, reviews it, and stages its proof, and the page completes. It is the smoother flow, and it ties the page's enrollment to this invocation, which also closes the opposite error (an attacker's key pasted into a victim's page). It mirrors `login`'s offers form and needs its own capability rules: one claim, separate capabilities for claiming and staging, and confidentiality | a consumer for whom copying the tokens is the obstacle |
| **An authenticated presentation** of an opaque intent, fetched from the configured audience and bound to the transaction, key, purpose and digest | the first service that cannot disclose its intent to the command |
| **An automation mode** approved by a stated policy (the expected audience, account id, purpose and restrictions), with an automatic refusal on mismatch | the first unattended consumer with a stored key |
| **Rendering `rotate` and `recover`.** Each needs a defined effect on existing keys: kept or disabled, and when | the first consumer that rotates or recovers through the command |
| **A loopback transport**, which needs origin checks, capabilities and listener rules (RFC 8252's interception risks) | none yet |
| **Seeds, key files and seed files** as the signing key | a consumer that needs them |

The advice also weighed **pairing codes** and found them useful only between this invocation and
the genuine service page, never as an account check (RFC 8628 describes a device linked to an
attacker's account through a phished code). They belong with the rendezvous, if anywhere.

## Residual risk

A person can still approve an account that is visibly wrong, or that only looks like theirs: the
display-unsafe set does not catch look-alike characters. A person can also paste into their own
page a proof an attacker made for the attacker's key, which the page's display of the key, and
later the rendezvous, address. These are real, and they are named. **They are not the same as
signing blind.** A statement with no account in it would have withheld the very information the
approval is about.

## Consequences

- #113 is answered. Its implementation lands in three steps:
  1. this record and [`docs/enroll.md`](../../enroll.md);
  2. the sdk's codecs for the intent and both tokens, pinned by vectors in Go, Rust and
     TypeScript, with the server helpers that build an intent with a fresh blind and a challenge
     token from `Prepare`'s output;
  3. `archon enroll` in the three command implementations, with a byte-identical statement fixture
     and a smoke case.
- **No server API breaks.** `Record` gains no field, because services build records in their
  integration's `load`, so a new field would break every Rust and TypeScript integration. The
  specification says to persist the intent beside the record instead.
- **bithost's interim continues until the command ships.** After that, a stored key enrolls with a
  policy that lists `archon-enroll/1`.
- **0010 §7's intent rule is refined**, by its status note, to "no guessable preimage". Nothing else
  in 0010 changes.
