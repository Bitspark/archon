# 0012 — a stored key's signing contexts: what archon can promise, and the design it builds

**Status:** **ACCEPTED** (2026-10-05) · **Type:** scope / custody contract.
**Answers** [archon#91](https://github.com/Bitspark/archon/issues/91): bound the contexts a key in
archon's store may sign in by policy, not by the caller. **Amends** the reading of
[0003](0003-the-floor-grows-typed-spellings-and-domain-signing.md)'s *"archon neither knows nor registers domains"* for one
case, a local custody restriction on a store entry (§3). Decided by archon-92 on 2026-10-05, under
the operator's ruling of 2026-10-04 that such decisions are the agents', on the external advice
taken in the 0005 consultation (`research-docs/0005-*`, internal). thesmos answered on #91
(comment 5988080523): it needs D1's trusted-production rule, keeps every root operation in an
attended ceremony, and names the first entry that needs a list (§5), so §4 is built.

## Context

thesmos is adding control objects, each signed under its own context (`thesmos/root-lease/v1`,
`thesmos/tenure-record/v1`, `thesmos/wipe-act/v1`, `thesmos/adopt-transition/v1`). It asked that a
tool allowed some signatures from a stored key not be able to obtain one in a control context just
by asking. Five facts shape the answer:

- **The password and the file are the seed.** The key-file format is public
  ([`docs/keystore.md`](../../keystore.md)), so whoever has the password and can read the file can
  decrypt the seed without archon. A policy kept in the file binds archon's binary, and through it
  only callers that cannot supply the password themselves.
- **`sign --key` shows what it signs only before an interactive prompt.** With
  `ARCHON_KEY_PASSWORD` or `--password-fd`, no person sees anything.
- **thesmos's most sensitive key signs routine and control contexts alike.** Its root key signs
  facts (`thesmos/fact/v1`) as well as leases, tenure records and wipe acts. A list of permitted
  contexts on that key does not separate a routine request from a ceremony one.
- **Office keys cannot live only in archon's store.** They also sign raw Ed25519, which the store
  refuses (0009 §5), so another copy must exist.
- **No key that signs a control object is in archon's store today.**

## Decision

### 1. Three properties, kept apart

| property | the question it answers | whose |
|---|---|---|
| **context ceiling** | is this context permitted for this store entry? | archon (§2) |
| **request authorization** | may this requester obtain this particular signature? | above archon; archon has no identity for its caller |
| **trusted production and consent** | is this the intended, valid protocol object, built and approved through the required workflow? | the protocol's tooling (0009 §6) |

An allowlist answers only the first. Even a single-context entry signs arbitrary caller-supplied
bytes in that context. So archon's allowlist does **not** discharge thesmos ADR 0041
D1 (*"a key that signs a control context must never sign caller-chosen bytes in any context"*).

### 2. What archon promises, and what it does not

> When the command signs through a restricted store entry, it has authenticated that entry's
> policy together with its encrypted seed, checked the expected principal, and established that the
> requested context is an exact member of the authenticated allowlist; it then signs and verifies
> as 0009 §5 already requires.

It promises this of **the entry being used**, not of the principal. It does **not** promise:
- caller authorization;
- approval of what the bytes mean;
- that the seed cannot be exported;
- that the entry is the newest policy for that principal (no rollback resistance);
- any restriction on other copies of the seed;
- anything a verifier can see: a signature carries no evidence of the policy it was made under.

`--expect` pins an identity, not a policy: a restored older file of the same key passes it.

### 3. Scope: a local custody restriction is archon's

A per-entry allowlist of opaque, byte-compared context strings is a **local custody restriction**.
It is within the store that 0007 §A gave the command, because §2's claim is stated entirely in
archon's own vocabulary (entry, principal, scheme, context, bytes), which is ADR 0011's test. It
is authorization in the broad sense, and this ADR says so rather than calling it otherwise. archon
still knows no domain's meaning and keeps no registry. The rule is enforced in the command. The sdk
may report it for a preflight check (0009 §2), and that check is not the boundary.

### 4. The design

It is built this way:

- **The policy is authenticated with the seed.** It lives in the header, inside the AEAD's
  associated data, in a new format version, with its encoding, lengths and mode. There is no
  sidecar file.
- **An explicit mode.**
  - An entry is either explicitly *unrestricted* or carries a finite allowlist.
  - An empty list denies everything.
  - Missing, malformed or unknown policy never means unrestricted.
  - Counts and lengths are bounded. Strings are strict UTF-8, compared byte for byte, and
    duplicates are refused.
  - There is no normalisation, no prefix match and no wildcard.
- **One snapshot.**
  - The command reads the entry once and may refuse from the unauthenticated header before
    asking for the password. A pre-unlock check may refuse; it never releases a signature or a
    seed.
  - After the password, it authenticates that same snapshot, re-checks the principal, and
    enforces the authenticated policy before signing.
  - One derivation per signature.
- **Policy changes only through a dedicated management command.** It authenticates the old entry,
  shows the old and new policies apart from any signing request, asks for explicit approval, and
  re-seals atomically under a fresh nonce. A password change or a cost-parameter upgrade keeps the
  policy unless the command says it changes it. The password holder is the policy's
  administrator, and the documentation says so.
- **The other paths, consistently:**
  - `key export --reveal` is refused for a restricted entry. A backup is the encrypted entry.
  - Every store-backed signer of one of archon's own protocols needs that protocol's domain in
    the list: today `login`, with an explicit or default key, needs `archon-login/1`, and is refused
    before contacting the server.
  - Importing an existing seed is allowed, and the policy starts with that entry.
  - Seed-file paths are unchanged and outside the policy.
  - A refusal never falls back to another entry, store or seed file.
  - `sign` itself never signs in `archon-*` domains (0009's 2026-10-05 note), whatever a list
    holds.
- **A clean cut.**
  - Once the new version exists, store-backed signing accepts only it.
  - Conversion of a version-1 entry is an explicit management command with an explicit policy
    choice. It replaces the entry atomically and leaves no unrestricted copy behind.
  - Readers of the new version tell *unsupported*, *migration required*, *malformed* and
    *absent* apart, and `key list` shows the entries it cannot use instead of skipping them, under
    a versioned `--json` schema. Any policy it prints unauthenticated is labelled as a claim. Until
    then, `key list` names each entry it skips on stderr, one line each (#104).
- **Rollback is disclaimed.** An older authentic file with a wider policy cannot be told from the
  newest without trusted state outside `$ARCHON_HOME`. archon does not claim it can.

### 5. When it is built: on the first entry that needs a proper subset, which exists

§4 is built for the first entry whose legitimate contexts are a proper subset of what its callers
can reach, and not before: §4 changes the format and adds a management command and a migration in
three lanes. A root key kept to ceremonies would list all its contexts, and office keys cannot be
stored only here, so neither is that entry.

**The entry exists.** thesmos keeps delegators' keys in archon's store for
`thesmos delegate sign --key` (thesmos#768, thesmos v0.26.0), and they should sign only
`thesmos/fact/v1` (#91, comment 5988080523). §4 is the specification, and the work follows this ADR
without another consultation, as one minor release across the three lanes, after 0.11.0.

### 6. What is not adopted

- **Per-context conditions on how the password arrives, as authorization.** "This context needs a
  password typed at the terminal" describes an input path, not an approval: a program that starts
  archon in a pseudo-terminal it controls can type a password it knows. It may be offered later as
  a safeguard against an inherited password, named as that.
- **Per-caller authorization in archon.** archon cannot identify the program that started it.
- **Separate store entries for one seed, called key separation.** Two names for the same seed are
  one signing secret. Separation needs distinct keys.

## For thesmos

These are the advice's recommendations for thesmos, recorded on #91, not archon's to deliver:
- keep D1's trusted-production rule independent of any allowlist;
- run every root operation, root-signed facts included, inside the ceremony, with delegated keys
  for routine work;
- audit whether a root-signed fact can confer authority equivalent to a control object;
- give a producer rules for what it may construct, since building a structure locally from
  attacker-chosen fields is not by itself authorization.

## Consequences

- #91 is answered: the property archon can state is §2's, and its design is §4's, built for
  thesmos's delegator keys (§5). thesmos's D1 does not wait on it.
- **The clean cut has a cost, named here:** every existing entry must be converted, explicitly and
  with a policy choice, before it signs again, and a binary older than the new version cannot use a
  converted entry. With one person's handful of keys and the configured absolute-path installs
  0009 §5 requires, that cost is a command per key and an upgrade, paid once.
- Delivered alongside this record: `sign` refuses archon's own domains (#99, 0009's note).
- 0003's sentence stands for everything except §3's custody restriction.
- 0007 §A's refusal of a per-key attachment slot stands. §4's policy is a typed, authenticated
  field with one meaning, not a slot.
