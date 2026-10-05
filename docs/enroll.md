# `archon enroll`: enrolling a stored key

**Status:** specified by [ADR 0013](architecture/decisions/0013-enrolling-a-stored-key.md); the
implementation follows in its own pull requests
([archon#113](https://github.com/Bitspark/archon/issues/113)).

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
archon's sdk and server still bind the digest and never read the intent.

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
account ref     u16be length ‖ UTF-8      1..=255 bytes: the service's identifier for the account
account name    u16be length ‖ UTF-8      1..=255 bytes: what the person recognizes, with its
                                          organisation or namespace where that disambiguates
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

**What the fields mean is the service's promise.** SHA-256 binds bytes, not meaning. The service
builds the account reference and name from its own validated records, never from a label the
browser sent, and completion does exactly what the intent says (§6).

**Purposes.** Version 1 of the command renders `add-key`: *add this key to this account*. It
refuses every other purpose by name, because `rotate` and `recover` change existing keys, and a
command that printed only the word would not show what happens to them (ADR 0013 §7).

## 3. The tokens

Both tokens are one line of text: a fixed prefix, then lowercase hexadecimal of length-prefixed
binary. A token has no fields to duplicate, nothing nested, and one parse in every language.

**The challenge token**, `archon-enroll-challenge-1:` followed by the hex of:

```
audience        u16be length ‖ UTF-8      the service's audience, as the binding spells it
transaction     u16be length ‖ bytes      1..=255 bytes: the pending transaction's id
nonce           u16be length ‖ bytes      16..=255 bytes: the record's nonce
new key         32 bytes                  the key the record enrolls
intent          u16be length ‖ bytes      the exact intent bytes, in format 1
deadline        u64be                     the record's expiry, in Unix seconds
```

It carries no purpose and no digest: the command takes both from the intent it shows, so there is
no second copy to disagree with the first.

**The proof token**, `archon-enroll-proof-1:` followed by the hex of:

```
transaction     u16be length ‖ bytes      1..=255 bytes
new key         32 bytes
proof           64 bytes                  the possession signature (request.md §6)
```

**Reading a token:** surrounding ASCII whitespace is ignored. Otherwise the text must be exactly
the prefix followed by an even number of lowercase hex digits, decoding to exactly the fields
above with no byte left over, and the whole token is at most 65536 bytes. Uppercase hex, a missing
or different prefix, and trailing bytes are refused.

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
- **The password** comes from the store's sources ([`keystore.md`](keystore.md) §4), but **the
  confirmation is always asked on the controlling terminal**: a password from
  `ARCHON_KEY_PASSWORD` or `--password-fd` does not answer it, and there is no `--yes`. Without a
  controlling terminal, the command refuses.

**The order is the security order:**

1. The flags, and **the entry**. It must exist, be key-store version 2, and permit
   `archon-enroll/1`. An *unrestricted* entry permits it. An *allowlist* entry must list it, and
   the refusal prints the `archon key policy` command that adds it to the entry's current list,
   because `key policy` replaces a list rather than adding to it. A key made for thesmos
   delegation, for example, enrolls after
   `archon key policy <name> --allow thesmos/fact/v2 --allow archon-enroll/1`.
2. **The audience**, configured and canonical, and **a controlling terminal**.
3. **The token**, read and decoded once (§3). From here on the command holds immutable values and
   never reads the file again.
4. **The token's audience** must equal the configured audience, byte for byte. The refusal names
   both.
5. **The token's new key** must equal the entry's public key, as its header states it. Nothing is
   unlocked yet; a token for another key is refused before anything is shown.
6. **The deadline** must not have passed.
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

- **Build the intent from its records.** Take the account reference and name from the account the
  validated session or credential authorizes. Never take a label from the browser and place it
  beside a separately chosen account. Use a fresh blind every time.
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
| An **automation mode** for unattended enrollment, approved by a stated policy (expected audience, account reference, purpose and restrictions) rather than by a person | the first unattended consumer with a stored key |
| Rendering **`rotate` and `recover`**, with their effect on existing keys | the first consumer that rotates or recovers through the command |
| A **loopback** transport | none yet; it needs its own origin, capability and listener rules |
| Seeds, key files and seed files as the signing key | a consumer that needs them; the sdk proves with a seed today |
