# The archon key store — file format

**Status:** shipped — in every release since 0.4.0, in all three command implementations · implements [ADR 0007](architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A

`archon key` stores a 32-byte Ed25519 seed under a name, encrypted with a password-derived
key. This document is the byte contract: the three binaries (`cli/{rs,go,ts}`) write and read
the *same* file, and `vectors/keystore.json` pins it the way `vectors/sdk.json` pins the sdk.

Nothing in `core/` or `sdk/` learns a file path, a password or a directory (ADR 0007 §A). The
store is the command's.

## 1. Where

    $ARCHON_HOME/keys/<name>          ARCHON_HOME defaults to ~/.archon
    directory  0700
    file       0600
    write      temp file in the SAME directory, fsync, rename  (atomic; never a partial key)

The mode bits are POSIX. **Windows has none**, and the lanes do not pretend otherwise: the
file inherits the ACL of `$ARCHON_HOME`, which is inside the user's own profile. Saying so
is better than a comment claiming an 0600 that never happened — the protection there is the
password, not the filesystem.

`<name>` is the person's handle for the key and is used as a path segment, so it is
constrained (§5). Selection everywhere is by name, never by principal text.

The default key is a pointer at `$ARCHON_HOME/default` — one line, the name. It lives
BESIDE `keys/` rather than inside it, so it can never collide with a key name, and it is
a name rather than a copy, so `key rm` cannot leave a default pointing at nothing that
also happens to still hold a seed.

## 2. The file

A fixed 134-byte layout. All integers big-endian. There is no framing, no base64 and no
text: the file is exactly these bytes.

    offset  size  field
    ------  ----  --------------------------------------------------------------
         0     4  magic = "arck"            ─┐
         4     1  version = 0x01             │
         5     4  argon2id memory, KiB       │
         9     4  argon2id iterations        │  HEADER, 62 bytes
        13     1  argon2id parallelism       │  authenticated as the AEAD's
        14    16  salt                       │  associated data
        30    32  public key                ─┘
        62    24  nonce
        86    48  ciphertext(32-byte seed) ‖ Poly1305 tag(16)
    ------  ----
       134        total

- **The magic is `"arck"`**, following the envelope's `"arcn" ‖ version` (`sdk/{go,rs,ts}`).
  A file that does not begin with it is refused before anything else — which is what stops a
  134-byte non-key file being *listed* as a key, since `key list` reads the header without a
  password and is therefore the one place a wrong file would be believed.
- **version** selects the whole suite. `0x01` is Argon2id (RFC 9106) + XChaCha20-Poly1305. A
  reader that does not know a version refuses the file; it does not guess.
- **The Argon2id parameters are read, never assumed** (ADR 0007 §A). A file written with
  other parameters opens on any binary, which is what lets the values change without a
  format version — **within bounds every reader checks when it parses the header, before any
  derivation:**

      t:  1 ≤ t ≤ 10
      p:  1 ≤ p          (one byte, so ≤ 255)
      m:  8·p ≤ m ≤ 2097152 KiB (2 GiB)

  The lower bounds are RFC 9106's validity rules and nothing more, so a weak but valid file keeps
  opening: its weakness is its writer's. They are stated here because not every Argon2
  implementation enforces them — `golang.org/x/crypto/argon2` silently raises `m < 8p` to `8p`
  where the reference implementation refuses — and three lanes must refuse the same headers.
  The upper bounds exist only so that a header someone else wrote cannot make an unlock
  unbounded; they are generous on purpose, and RFC 9106 §4's first recommended setting (2 GiB,
  `t=1`, `p=4`) still opens. **Their cost is named:** a file above them, which no archon binary
  has ever written, no longer opens. A file outside the bounds is refused at parse, so `key
  list` does not show it either. Writers refuse to seal outside them.
- **The public key is in the clear, and this is load-bearing**: `archon key list [--json]`
  prints `{name, principal}` for every key, and it must not ask for a password to do it.
  Because the public key is inside the authenticated header, it also binds the ciphertext to
  the principal it claims — one key's ciphertext cannot be moved under another's name
  without failing the tag.
- **`list` prints what the header *claims*.** The claim is only *proven* at unlock, by the
  AEAD tag over the header and by the seed-derives-its-own-public-key check below. Never
  build an access decision on `list` output.
- **The nonce is not in the associated data** and does not need to be: XChaCha20-Poly1305
  derives its subkey from the nonce, so altering it fails the tag.

### Deriving and opening

    key    = Argon2id(password = UTF-8 NFC bytes, salt = header.salt,
                      m = header.memory, t = header.iterations, p = header.parallelism,
                      tag length = 32)
    file   = header ‖ nonce ‖ XChaCha20Poly1305_Encrypt(key, nonce, plaintext = seed,
                                                        aad = header)

Opening reverses it and then **checks the decrypted seed against the header's public key**.
A file whose seed does not derive its own public key is refused as corrupt, even though the
tag verified — the tag proves the bytes are ours, this proves they are consistent.

## 3. Parameters — measured, not assumed

ADR 0007 §A named RFC 9106 §4's second option (64 MiB, `t=3`, `p=4`) as the starting point and
required the values be measured before landing. Measured here, min-of-5 with the two worst runs
dropped (the host was running ~67 sessions, so early runs were contention, not cost):

| m (KiB) | t | p | reference C | pure JS (`@noble/hashes`) |
|---|---|---|---|---|
| 19456 | 2 | 1 | 61 ms | 382 ms |
| 32768 | 3 | 4 | 117 ms | 944 ms |
| 65536 | 3 | 4 | 271 ms | 2072 ms |
| **65536** | **3** | **1** | **210 ms** | **2040 ms** |
| 131072 | 3 | 4 | 570 ms | — |

Two things the table says that the ADR could not have known:

1. **The TypeScript lane is the binding constraint**, at ~7.6× the native cost — ~2.0 s per
   unlock in `cli/ts` against ~210 ms in `cli/go`/`cli/rs`. That is per invocation by design:
   there is no daemon and no cache (§4). `key list` never pays it, because the public key is
   in the clear (§2).
2. **`p=4` buys nothing measurable in any lane we ship.** Pure JS does not thread at all
   (2072 ms at `p=4` vs 2040 ms at `p=1`), and the reference C implementation was *slower* at
   `p=4` than at `p=1`. `p` also costs two independent oracles: OpenSSL's Argon2id refuses
   `p>1` without a thread pool, and libsodium's is hard-wired to `p=1`, so at `p=4` only one
   external implementation can check our vectors instead of three.

**Shipping default: `m=65536, t=3, p=1`** — same memory hardness, same wall clock within noise,
three oracles back. Accepted by the archon maintainers on the LANE A PR and recorded against ADR 0007
§A by number. The values are in the header and are read, never assumed, so this is a default and
not a format change: files written at any parameters within §2's bounds keep opening, which is
what `keystore_seal/params-in-header` and `keystore_seal/parallelism-4` exist to pin.

## 4. Passwords

Interactive prompt by default, **on the controlling terminal** — `/dev/tty`, or the Windows
console — and never on stdin, which may be carrying the message being signed (ADR 0009 §5): a
tool can pipe bytes to `archon sign --key` and the person still types the password into their own
terminal. With no terminal to prompt on (a daemon, a detached session, CI), the command refuses
and names the two non-interactive sources: `ARCHON_KEY_PASSWORD` or `--password-fd <n>`.
**Never argv** — argv is world-readable in the process table.

On POSIX, a password file handed to `--password-fd` is **refused if it is group- or
world-readable**. Only a *regular file* is checked: a pipe, a terminal or a process
substitution has no meaningful mode, and `--password-fd 0` fed by a heredoc is a pipe, so
checking those would refuse the ordinary non-interactive case for nothing. Windows has no
mode bits, so nothing is checked there and nothing is claimed — the same honesty this
document keeps about `0600` in §1.

**An empty password is refused**, both when sealing and when opening: a store sealed under `""`
is a plaintext store that looks encrypted, and refusing at open too keeps a file made by a
lenient writer from ever being trusted.

The password is encoded UTF-8 and **normalised NFC** before use, so the same characters typed on
different platforms derive the same key. The normaliser is a per-lane dependency and is named
here so the lanes cannot drift to "as typed":

| lane | NFC |
|---|---|
| go | `golang.org/x/text/unicode/norm` (pinned; `--locked` in CI) |
| rs | `unicode-normalization` |
| ts | `String.prototype.normalize("NFC")` — no dependency |

There is no pepper and no stretching beyond Argon2id. No lock timeout and no daemon: an unlocked
seed held by a process is an agent again, and an agent cannot compute archon's Ed25519ph-with-
context possession proof (ADR 0007 §A), so there would be nothing to gain.

**Zeroise the decrypted seed after use** where the language allows. Best-effort is worth doing
and is not a security claim. `cli/go` (`keystore.Zeroise`) and `cli/rs` (`zeroize::Zeroizing`,
since [#53](https://github.com/Bitspark/archon/issues/53)) do it, on the seed, the password and
the derived key. It is not possible in TypeScript.

## 5. Names

A name is a path segment on three operating systems, so it is restricted rather than
escaped:

    1..64 bytes, UTF-8
    allowed:   a-z A-Z 0-9 . _ -
    refused:   empty
               a LEADING '.'          (hides the key from an ordinary listing)
               a TRAILING '.'         (Windows strips it, so `alice.` and `alice` are one
                                       file on one OS and two on another)
               '/' or '\'             (escapes the store directory)
               ':'                    (an NTFS alternate data stream)
               any control character
               any byte outside the allowed set
               the Windows reserved device names — CON, PRN, AUX, NUL, COM1-9, LPT1-9 —
                 case-insensitively, AND with any extension: Windows treats `CON.key` as
                 the device.

`key add` **refuses an existing name** (ADR 0007 §A): a key is never silently replaced.

## 6. Saying what was done

Every operation that destroys, reveals or creates key material states what it did — **in
scope**. The scoping is the point: an empty result means *nothing visible here*, never
*nothing exists*, and archon speaks only for its own store. No path to any other store, no
coupling, no flag. The lines are pinned in `cli/smoke.mjs` so the wording cannot drift.

| command | line |
|---|---|
| `key rm <name>` | `removed <name> (ed25519:<hex>) from archon's store at <path>; any copy of this key outside it is untouched.` |
| `key rm` on an unparsable file | refuses: `not an archon key file: <path>: <reason>` |
| `key rm --force` on one | `removed <name> (unreadable header: <reason>) from archon's store at <path>; any copy of this key outside it is untouched.` |
| `key export <name> --reveal --out <file>` | `wrote the seed of <name> to <file>; the store's copy remains.` |
| `key add <name>` with a source | `stored <name> (<principal>) from <file>; the source file is untouched.` |
| `key add <name>` generating | `generated and stored <name> (<principal>).` |

`key rm` refusing an unparsable file is deliberate: deleting an unrecognised file inside the
store silently is exactly what this rule exists to prevent, and `--force` still says what it
could not read rather than pretending it knew.

## 7. What the store does not hold

Seeds, and from version 2 a context policy (§8). Grants stay the law's and are joined by
principal text through `key list --json`; the store never interprets them, and there is no
per-key attachment slot (ADR 0007 §A): §8's policy is one typed, authenticated field with one
meaning. Agents and CI stay on `--seed` / `--seed-file`, which keep working beside the store on
every command that takes a key.

## 8. Version 2: a context policy

**Status:** specified and implemented in all three command implementations, pinned by `vectors/keystore.json`; ships in the release after 0.11.0 ([ADR 0012](architecture/decisions/0012-a-stored-keys-signing-contexts.md)).
From the release that ships it, the store **writes only version 2** and **signs only with version
2**; a version-1 entry must be converted, once, with `key policy` (§8.3).

What version 2 adds is a **context policy**: the set of domains (RFC 8032 contexts, ADR 0008 §2)
the entry may sign in, authenticated together with the seed. What it promises is ADR 0012 §2's
and nothing more: *the command refuses, through this entry, every context outside the entry's
authenticated policy.* It is not caller authorization, not consent, not non-exportability, not
rollback resistance, and it says nothing about another copy of the seed.

### 8.1 The file

    offset  size  field
    ------  ----  --------------------------------------------------------------
         0     4  magic = "arck"                       ─┐
         4     1  version = 0x02                        │
         5     4  argon2id memory, KiB                  │
         9     4  argon2id iterations                   │
        13     1  argon2id parallelism                  │  HEADER, H bytes,
        14    16  salt                                  │  authenticated as the
        30    32  public key                            │  AEAD's associated data
        62     1  policy mode                           │
        63     1  n, the number of contexts             │
        64     …  n × ( u8 length ‖ that many bytes )  ─┘
         H    24  nonce
       H+24   48  ciphertext(32-byte seed) ‖ Poly1305 tag(16)
    ------  ----
       H+72       total, where H = 64 + Σ (1 + lengthᵢ): 136 to 4232 bytes

Everything in §2 holds for version 2, with the header now `[0, H)`. And:

- **The policy mode** is `0x00` *unrestricted* (then `n` must be 0) or `0x01` *allowlist*
  (then `0 ≤ n ≤ 16`, and **`n = 0` denies every context**). Any other mode is refused. There
  is no default: a missing, malformed or unknown policy never means unrestricted.
- **Each context** is a domain by ADR 0008 §2: 1 to 255 bytes of well-formed UTF-8, compared byte
  for byte, never normalised. There is no wildcard and no prefix match.
- **The contexts are in strictly ascending byte order.** That refuses duplicates and makes the
  encoding canonical: one policy has one header.
- **The length is exact.** A file that is not `H + 72` bytes, for the `H` its own header implies,
  is refused before any derivation, like every other header refusal.
- **Version `0x01` files are still parsed** (§2), so that `key list`, `key rm` and `key policy`
  can name and convert them. Nothing signs with them, logs in with them or exports them.

Deriving and opening are §2's, with `aad = header[0, H)`. A changed policy byte fails the tag.

### 8.2 What each command does with an entry

| command | version 2, allowlist | version 2, unrestricted | version 1 | unknown version / malformed |
|---|---|---|---|---|
| `sign --key <n> --domain <d>` | signs only if `d` is in the list; otherwise refused as `policy`, **before the message or the password is read** | as before | refused: `migration-required`, naming the conversion command | refused: `unsupported` / `malformed` |
| `login --key <n>` or the default key | needs `archon-login/1` in the list; otherwise refused **before contacting the server** | as before | refused before contacting the server | refused before contacting the server |
| `key export <n> --reveal` | **refused**: an allowlisted entry's seed is not written out (a backup is the encrypted file) | as before | refused (convert first) | refused |
| `key default <n>` | accepted | accepted | refused (convert first) | refused |
| `key list` | listed, with its policy | listed | listed as `migration-required` | named on stderr, not listed |
| `key rm <n>` | as before | as before | as before | needs `--force` |

`sign` never signs in `archon-*` domains whatever the list holds (ADR 0009's note); `archon-login/1`
in a list is for `login`.

The machine-mode categories of `sign --key` (cli/README) gain four, and **every header refusal has
exactly one**:

| category | when |
|---|---|
| `no-key` | no file has that name |
| `unsupported` | the version byte is neither `0x01` nor `0x02` |
| `malformed` | anything else wrong with the header or the file: magic, length, Argon2id parameters outside §2's bounds (before this version, `no-key`), a policy that breaks §8.1 |
| `migration-required` | a version-1 entry. The message names the command that converts it: `archon key policy <name> --allow <context>…` (or `--unrestricted`) |
| `policy` | the domain is not in the entry's list |

The pre-unlock check reads the header **once**; the same bytes are then unlocked, so the policy
that was checked is the policy the tag authenticates (ADR 0012 §4, one snapshot). A refusal
before unlock never releases anything.

### 8.3 Choosing and changing a policy

- **Every new entry states its policy.** `key add <name> <source>` and `keygen --store <name>`
  require exactly one of `--allow <context>` (repeatable) or `--unrestricted`. The writer sorts
  the contexts and refuses a duplicate, an invalid domain, a context the command would display
  unfaithfully (the display-unsafe code points of `docs/login.md`), more than 16, and `--allow`
  mixed with `--unrestricted`. Creating a key stays non-interactive-capable, as today.
- **`key policy <name>`** prints the header's policy, labelled as a claim: it is read without the
  password and is only proven at unlock (§2).
- **`key policy <name> (--allow <context>… | --unrestricted)`** converts a version-1 entry or
  changes a version-2 one. It is the only way a policy changes, and it is **always interactive**:
  1. It reads the entry once and prints it, the policy the header claims (*version 1, no policy*
     for a version-1 entry) and the policy it will have, **before asking for anything**.
  2. It asks `change it? [y/N]` at the controlling terminal.
  3. It asks for the password **at the controlling terminal only**: `ARCHON_KEY_PASSWORD` and
     `--password-fd` are refused here, and there is no `--yes`. It unlocks the same bytes it read,
     and re-checks the principal.
  4. It re-seals the seed under the same salt and parameters and a **fresh nonce**, and writes the
     file atomically (§1).
  5. It says: `changed the policy of <name> (<principal>) to <policy>; any copy of this key
     outside archon's store is untouched.`

  The password holder is the policy's administrator. Insisting on a person at the terminal is a
  safeguard against a password a program inherited, not an authorization claim: whoever can
  type the password can also decrypt the file (§8.5, ADR 0012 §6). Nothing else changes a
  policy, and a password or parameter change, should one exist, keeps it.
- **For thesmos's delegator keys** (thesmos#768) the policy is the fact domain of the thesmos
  version that uses the key: `--allow thesmos/fact/v1` for thesmos 0.27 and earlier,
  `--allow thesmos/fact/v2` from thesmos 0.28.0. Moving from one to the other is a `key policy`
  change. archon names no default.

### 8.4 `key list`

- **`--json` keeps its shape**, an array of rows a caller finds a principal in by name, with a row
  for **every entry whose principal it can read**, so an entry awaiting conversion is reported as
  that and not as absent. Each row gains a `status` and the header's policy, labelled as a claim:

      {"name":"alice","principal":"ed25519:…","status":"usable","claimed_policy":{"mode":"allowlist","contexts":["thesmos/fact/v2"]}}
      {"name":"bob","principal":"ed25519:…","status":"usable","claimed_policy":{"mode":"unrestricted"}}
      {"name":"carol","principal":"ed25519:…","status":"usable","claimed_policy":{"mode":"allowlist","contexts":[]}}
      {"name":"dave","principal":"ed25519:…","status":"migration-required","claimed_policy":null}

- **An entry whose principal it cannot read** (`unsupported`, `malformed`) is named, with the
  reason, on stderr (one line each, as since 0.11.0) and in the text listing, so a key never
  disappears without a word.

### 8.5 What is not claimed

- **Rollback.** An older authentic file with a wider policy, put back in place, opens. Telling it
  from the newest needs trusted state outside `$ARCHON_HOME`, and archon has none.
- **Other copies.** The policy starts with this entry. A seed imported from elsewhere, or a
  version-1 backup, is not bound by it. `--expect` pins the principal, not the policy.
- **Anyone with the password and the file.** The format is public; they can decrypt the seed
  without archon. The policy binds archon's binary, and through it callers that cannot supply the
  password themselves.
