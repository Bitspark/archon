# `archon enroll`: enrolling a stored key

**Status:** specified by [ADR 0013](architecture/decisions/0013-enrolling-a-stored-key.md)
([archon#113](https://github.com/Bitspark/archon/issues/113)).
- **The formats (§2–§3) are implemented** in all three lanes and pinned by `vectors/enroll.json`.
  - **The sdk** encodes and decodes the intent and both tokens, and derives the request a token
    yields. It is Go's `enroll.EncodeIntent` and `enroll.DecodeChallenge` with
    `(*Challenge).Request`, Rust's `enroll::encode_intent` and `enroll::decode_challenge` with
    `Challenge::request`, and TypeScript's `encodeEnrollIntent` and `decodeEnrollChallenge` with
    `enrollChallengeRequest`, each with its proof-token pair.
  - **The server** builds an intent with a fresh blind and writes a record's challenge token:
    `Enroller.Intent` and `Enroller.ChallengeToken` in Go, `intent` and `challenge_token` in Rust,
    `intent` and `challengeToken` in TypeScript.
- **The command (§4) is implemented** in all three command implementations, which print the
  statement and the policy refusal byte-identically (`cli/testdata/enroll-statement.json`).
  `cli/smoke.mjs` pins every lane's refusals and, on Linux through a pseudo-terminal, the
  statement, the question, and a proof token the sdk verifies, identical across the lanes. It
  ships in the release after 0.13.0.

Enrollment ([`request.md`](request.md) §6) has a new key prove its own possession while a signed-in
session, or a bootstrap credential, says whose key it becomes. The proof binds the account only
through the service's **intent digest**. That is enough for the service, which holds the record. It
is not enough for the person making the proof: a digest shows them nothing, and an attacker signed
in as *themselves* can start an enrollment naming the victim's public key. If the victim then makes
the proof, the victim's key joins the attacker's account. Completing in the same session does not
stop this, because the attacker's own session begins and completes it.

So `archon enroll` makes an enrollment proof with a key in archon's store only when it can show the
person **which account** the key joins, decoded from the very bytes whose digest it binds. A
service opts in by building its intent in **format 1** (§2). The proof's binding stays version 1:
the proof binds only the intent's digest. Verification and completion never read the intent. The
sdk's format-1 codec reads it for the command, and for the server's token helper, which checks
that the purpose given to `Prepare` is the intent's (§6).

## 1. The flow

```
signed-in page            person                  archon enroll                 service
  │ Prepare(...) ──────────────────────────────────────────────────────────────▶ record (persisted,
  │ ◀─────────────────── challenge token ─────────────────────────────────────── with the intent bytes)
  │ shows the token ─▶ copies it to a file
  │                    or pastes it ──────────▶ checks, shows the account,
  │                                             asks on the terminal, unlocks,
  │                                             signs, prints the proof token
  │ ◀── pastes the proof token ◀── copies it
  │ checks it is its own pending enrollment,
  │ completes under the session ─────────────────────────────────────────────────▶ Complete
```

The proof travels **by hand**. archon defines no route and the command contacts no server, so the
command's success means "a proof was produced", never "the key is enrolled". The key is enrolled
when the signed-in page completes.

## 2. The intent, format 1

The service builds these bytes, persists them beside its pending record, passes them to `Prepare`
as the intent, and puts them in the challenge token. `Prepare` binds their SHA-256.

```
format          u8                        0x01
blind           u16be length ‖ bytes      16..=64 bytes from a CSPRNG, fresh for every intent
account id      u16be length ‖ UTF-8      1..=255 bytes: the service's identifier for the account
account name    u16be length ‖ UTF-8      1..=255 bytes: the account's unique name at the service,
                                          such as its sign-in handle, with its namespace where
                                          the handle is scoped to one
purpose         u16be length ‖ UTF-8      1..=255 bytes: the binding's purpose
restrictions    u8 count                  0..=32
                count × (u16be length ‖ UTF-8)   each 1..=255 bytes
```

Nothing follows the last restriction. **The rules, refused at encoding and at decoding:**

- every text field is well-formed UTF-8 with no **display-unsafe** code point (`Cc ∪ Cf ∪ Zl ∪ Zp
  ∪ Default_Ignorable_Code_Point`, [`login.md`](login.md) §5, pinned by
  `vectors/display-unsafe.json`), which also covers the binding's own C0 and DEL rule;
- the lengths are exact, the counts are within bounds, and no byte is left over;
- an unknown format byte is refused, never skipped.

**Why the blind.** The digest travels to the client and may sit in a pasted file, terminal
scrollback or a log. Without a secret random part, anyone holding the digest could confirm a
guessed account name by hashing it. The blind is inside the intent, so only someone who sees the
intent itself learns the account, and that is the person the command shows it to. This refines
[ADR 0010](architecture/decisions/0010-request-authentication-and-key-enrollment-profiles.md)
§7's rule from "guessable account data stays out of the intent" to "no intent has a guessable
preimage".

**The account name is unique to the account.** It is a name no other account at the service can
hold, such as the handle the person signs in with. It is never a display name an account holder
chooses freely. Otherwise an attacker names their own account after the victim, and the statement
shows the victim's name beside an id nobody checks. The account id is for precision. The name is
what the person reads, so the name is what must not be shared.

**What the fields mean is the service's promise.** SHA-256 binds bytes, not meaning. The service
builds the account id and name from its own validated records, never from a label the browser
sent, and completion does exactly what the intent says (§6).

**Purposes.** Version 1 of the command renders `add-key`: *add this key to this account*. It
refuses every other purpose by name, because `rotate` and `recover` change existing keys, and a
command that printed only the word would not show what happens to them (ADR 0013 §7).

## 3. The tokens

Both tokens are one line of text: a fixed prefix, then lowercase hexadecimal of length-prefixed
binary. A token has no fields to duplicate, nothing nested, and one parse in every language.

**The challenge token**, `archon-enroll-challenge-1:` followed by the hex of:

```
audience        u16be length ‖ UTF-8      the service's audience: non-empty, with no display-unsafe
                                          code point
transaction     u16be length ‖ bytes      1..=255 bytes: the pending transaction's id
nonce           u16be length ‖ bytes      16..=255 bytes: the record's nonce
new key         32 bytes                  the key the record enrolls
intent          u16be length ‖ bytes      1..=65535 bytes: the exact intent bytes
deadline        u64be                     the record's expiry in Unix seconds, at most
                                          253402300799 (9999-12-31T23:59:59Z)
```

The token's codec checks the token's own fields. The intent inside it is checked by the intent
codec (§2) when the command decodes it. The audience rule is stricter than the binding's, which
refuses only C0 and DEL. The command may print a token's audience when it refuses it (§4 step 4),
so a C1 control or a bidirectional override is refused at decoding, before anything is printed.
A canonical audience ([`login.md`](login.md) §2.1) never carries one.

It carries no purpose and no digest: the command takes both from the intent it shows, so there is
no second copy to disagree with the first. **The request a token yields** is the binding's request
([`request.md`](request.md) §6) with the token's nonce, transaction and new key, the **intent's**
purpose, and **SHA-256 of the token's intent bytes** as the intent digest. The sdk derives it in one
function, so no implementation assembles it differently.

**The proof token**, `archon-enroll-proof-1:` followed by the hex of:

```
transaction     u16be length ‖ bytes      1..=255 bytes
new key         32 bytes
proof           64 bytes                  the possession signature (request.md §6)
```

**Reading a token:** leading and trailing tabs, line feeds, carriage returns and spaces are
ignored. What remains must be at most 65536 bytes, and exactly the prefix followed by an even
number of lowercase hex digits, decoding to exactly the fields above with no byte left over.
Uppercase hex, a missing or different prefix, whitespace inside the token, and trailing bytes are
refused. Writing a token produces the prefix and the hex, and nothing else.

## 4. The command

```
archon enroll [--challenge-file <file>] [--audience <base>] [--key <name>] [--password-fd <n>]
```

- **The key** is a store entry: `--key <name>`, or the store's default key. Version 1 takes no
  seed, key file or seed file. Those are plaintext seeds, which the sdk already proves with.
- **The audience** is `--audience`, or `ARCHON_AUDIENCE`, checked exactly as `login`'s offers form
  checks it ([`login.md`](login.md) §4.1 rule 1): it must be canonical. A token never supplies it.
- **The token** is read from `--challenge-file`, or one line from stdin. It is never a
  command-line argument, which would put the intent into shell history and process listings.
  - **A long token belongs in a file.** A terminal cuts a pasted line at its own limit: 1024 bytes
    on macOS and 4095 on Linux. A token with restrictions can be longer, so the page offers the
    token as a download as well as for copying. A token read from a terminal that fails to decode
    is refused with a pointer to `--challenge-file`.
  - **`--password-fd 0` is refused when the token comes from stdin.** Both would read the same
    stream.
- **The password** comes from the store's sources ([`keystore.md`](keystore.md) §4), but **the
  confirmation is always asked on the controlling terminal**: a password from
  `ARCHON_KEY_PASSWORD` or `--password-fd` does not answer it, and there is no `--yes`. Without a
  controlling terminal, the command refuses.

**The order is the security order:**

1. The flags, and **the entry**. It must exist, be key-store version 2, and permit
   `archon-enroll/1`. An *unrestricted* entry permits it. An *allowlist* entry must list it.
   - **The refusal prints the command that adds it.** That is `archon key policy <name>`, then one
     `--allow` for each context the entry already lists, in its order, then
     `--allow archon-enroll/1`. Every context is listed because `key policy` replaces a list
     rather than adding to it. A key made for thesmos delegation, for example, enrolls after
     `archon key policy <name> --allow thesmos/fact/v2 --allow archon-enroll/1`.
   - **Quoting: none, in any shell.** The command is printed only when every context is a bare
     word that sh, cmd.exe and PowerShell all receive as itself: `A–Z a–z 0–9 . _ / : + = -`,
     beginning with a letter or digit (a leading `@` is PowerShell's splatting, a leading `-` a
     flag). Otherwise the refusal prints no command: it lists the contexts JSON-quoted and says to
     run `archon key policy <name>` with `--allow` for each of them and for `archon-enroll/1`. No
     one quoting rule is right in every shell, so the command never relies on one.
   - **A full list.** An entry that already lists 16 contexts, the most a policy holds, cannot gain
     another. The refusal says so and prints no command: drop a context, or keep a separate key
     for enrollment.
2. **The audience**, configured and canonical, and **a controlling terminal**.
3. **The token**, read and decoded once (§3). From here on the command holds immutable values and
   never reads the file again.
4. **The token's audience** must equal the configured audience, byte for byte. The refusal names
   both, each JSON-quoted. The token's audience is already display-safe (§3), and the quotes show
   where it begins and ends.
5. **The token's new key** must equal the entry's public key, as its header states it. Nothing is
   unlocked yet; a token for another key is refused before anything is shown.
6. **The deadline** must be in the future: the command refuses when its clock's whole seconds are
   at or past the deadline.
7. **The intent** must decode as format 1 (§2), and its purpose must be `add-key`.
8. **The statement** is written to the terminal, and the person is asked there. Any answer but `y`
   or `yes` refuses, and nothing is signed.
9. **Only now is the key unlocked.** It is the same snapshot of the entry that was read in step 1,
   and its authenticated policy is checked again. The authenticated header key and the key derived
   from the decrypted seed must both equal the key shown in step 8. A mismatch aborts.
10. **The proof** is made over the binding with the configured audience, the token's transaction
    and nonce, the intent's purpose, the new key, and **SHA-256 of the intent bytes that were
    shown**. The command verifies its own proof before printing it.
11. **The proof token** goes to stdout, one line. The terminal is told that the proof is produced
    and the key is enrolled only when the page completes.

**The statement**, byte-identical in every implementation:

```text
https://bitshelf.dev/api asks you to add a key to an account:
  account:      julia (bitspark)
  account id:   u_8f3c2a
  key:          ed25519:7a91b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f
  restrictions: none
the service may give this key the account's authority.
the request's deadline is about 2026-10-05T10:45:00Z, the service's word; it is not the key's expiry.
signing with the store key personal
add this key to the account "julia (bitspark)"? [y/N]
```

With restrictions, each is shown on its own line, in order, in full:

```text
  restrictions:
    read:projects
    expires 2027-01-01
```

The transaction id and the digest are not shown: no person can check them unaided. The deadline is
the record's expiry, as the token states it. It is not signed, and it is not the key's lifetime.

## 5. What the command does not do

- **It does not authenticate the service.** Checking the digest proves that a proof the service
  accepts will match what was shown. It does not prove who sent the token.
- **The audience check is consistency, not intent.** It refuses a token for a service other than
  the one configured. It cannot tell whether the configured audience is the one the person meant,
  which is why the statement leads with it.
- **It is not evidence of review.** archon's libraries can still sign in `archon-enroll/1`, so a
  service cannot infer from a valid proof that a person saw a statement. The command is a
  safeguard on the person's side, not an attestation.
- **It trusts its own machine:** the `archon` binary, its configuration, the terminal it asks on
  and the process holding the unlocked seed. A program that can rewrite the terminal or answer for
  the person defeats any prompt.
- **`archon sign` still refuses `archon-enroll/1`**
  ([ADR 0009](architecture/decisions/0009-the-signing-boundary-and-the-signer-contract.md)'s
  status note), whatever the entry's policy lists. Listing the domain lets `archon enroll` use the
  entry, and nothing else.

## 6. What a service must do

- **Build the intent from its records.** Take the account id and the account's unique name from
  the account the validated session or credential authorizes (§2). Never take a label from the
  browser and place it beside a separately chosen account. Use a fresh blind every time.
- **Pass `Prepare` the intent's purpose.** The binding's purpose and the intent's must be the same
  string, because the command binds the intent's. A record with any other purpose produces a proof
  that never verifies. The server's helper that writes the challenge token refuses the mismatch.
- **Write the record's expiry as the token's deadline, rounded down to the second.** Give the
  record time for a by-hand transfer. The adapter's default of five minutes is tight for copying a
  token to a terminal and back; fifteen minutes is a reasonable `TTL` for this flow.
- **Keep the intent with the record.** Persist the exact intent bytes beside the pending record, so
  the token can be rebuilt, and never regenerate them from account data that may have changed. If
  the account changes in a way that makes the intent untrue, expire the record and begin again.
- **Make the intent true.** Completion does what the intent says: it adds this key to this account,
  with these restrictions, and nothing else.
- **Take back only the page's own enrollment.** When a proof token is pasted, check that its
  transaction and key are the page's own pending enrollment, and never adopt another. Complete with
  `Complete` under the authorization validated at that moment. `Complete` already refuses another
  session's transaction (403) and a proof by another key (401).
- **Authorize from a credential, never from an identifier.** The `authorization` passed to
  `Complete` comes from a credential the service validates at completion: the session, or a
  bootstrap credential presented again. It is never the stored identifier itself, nor a session id
  the client supplied.
- **Show the person the key on the page.** The page shows the full key it is enrolling. An
  attacker who controls a key can get a victim to paste that key's proof into the victim's own
  page. Showing the key is the page's half of that defence; the command's half is that it signs
  only for the selected entry's key.
- **Decide what a key already enrolled elsewhere means.** Silent reassignment from one account to
  another is not a policy. Do not reserve a key for an enrollment that has not been proved, or
  anyone can block a public key.
- **For rotation and recovery,** the authority comes from the session, the old credential or a
  recovery procedure before `Prepare`, never from the new key's proof. The intent says whether the
  old key stays, and no old key is disabled before the replacement completes. The command does not
  render these purposes yet (§2).
- **Keep disclosed intents out of logs and telemetry**, and keep bootstrap credentials out of URLs
  and command lines.

## 7. Not in version 1

Each of these is deferred with the trigger that brings it ([ADR 0013](architecture/decisions/0013-enrolling-a-stored-key.md) §7):

| what | trigger |
|---|---|
| A command-started **rendezvous**: the command registers an offer, the signed-in page claims it once, the command fetches only that offer's challenge and stages its proof, and the page completes. It is the smoother flow, and it ties the page's enrollment to this invocation | a consumer for whom copying the tokens is the obstacle |
| An **authenticated presentation** of an opaque intent, fetched from the configured audience and bound to the transaction | the first service that cannot disclose its intent to the command |
| An **automation mode** for unattended enrollment, approved by a stated policy (expected audience, account id, purpose and restrictions) rather than by a person | the first unattended consumer with a stored key |
| Rendering **`rotate` and `recover`**, with their effect on existing keys | the first consumer that rotates or recovers through the command |
| A **loopback** transport | none yet; it needs its own origin, capability and listener rules |
| Seeds, key files and seed files as the signing key | a consumer that needs them; the sdk proves with a seed today |
