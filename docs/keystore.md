# The archon key store — file format

**Status:** for review on the LANE A PR · implements [ADR 0007](architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md) §A

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
  format version.
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
not a format change: files written at any parameters keep opening, which is what
`keystore_seal/params-in-header` and `keystore_seal/parallelism-4` exist to pin.

## 4. Passwords

Interactive prompt by default. Non-interactive: `ARCHON_KEY_PASSWORD` or `--password-fd <n>`.
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

**Zeroise the decrypted seed after use** where the language allows — best-effort in Go and Rust,
not possible in TypeScript. Best-effort is worth doing and is not a security claim.

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

Seeds only. Grants stay the law's and are joined by principal text through
`key list --json`; the store never interprets them, and there is no per-key attachment slot
in v1 (ADR 0007 §A). Agents and CI stay on `--seed` / `--seed-file`, which keep working
beside the store on every command that takes a key.
