# archon

<p align="center"><em>ἄρχων — the officeholder; the one who bears the office.</em></p>
<p align="center"><em>Who you provably are — as bytes anyone can re-check.</em></p>

[![conformance](https://github.com/Bitspark/archon/actions/workflows/conformance.yml/badge.svg)](https://github.com/Bitspark/archon/actions/workflows/conformance.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Bitspark/archon/core/go.svg)](https://pkg.go.dev/github.com/Bitspark/archon/core/go)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Ed25519 identity with **one** spelling. A key is `ed25519:<64 hex>` — the same 32 bytes, the
same text, in Rust, Go and TypeScript, checked against one oracle on every push. The PEM
codecs are RFC 5280 SPKI and RFC 5958 PKCS-8, nothing invented. Signing is
domain-separated, so a signature made for one context cannot count in another.

It answers exactly two questions — *are these bytes that key?* and *is this signature that
key's?* — and deliberately answers nothing else. What a key is allowed to do, and where a
key is kept, are somebody else's questions. See [Scope](#scope).

```console
$ archon keygen --out seed.hex --pub-out key.txt --pub-format text
$ cat key.txt
ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

$ echo -n "hello" | archon sign --seed "$(cat seed.hex)" --domain example.v1 > sig.hex

$ echo -n "hello" | archon verify --pubkey "$(cat key.txt)" --sig "$(cat sig.hex)" --domain example.v1
valid
```

`verify` prints `valid` or `invalid` and exits 0 or 1 — a verdict on stdout, not a usage
error, so a failed check is scriptable.

The same three operations, as a library:

```go
import (
    "github.com/Bitspark/archon/core/go/crypto"
    "github.com/Bitspark/archon/core/go/keytext"
)

pub  := crypto.PublicKeyFromSeed(seed)         // 32 bytes -> 32 bytes
text := keytext.EncodeKey(pub)                 // -> "ed25519:d75a98…"
sig  := crypto.SignInDomain("example.v1", seed, msg)
```

```rust
let public = archon_core::public_key_from_seed(&seed);
let text   = archon_core::encode_key(&public);
let sig    = archon_core::sign_in_domain("example.v1", &seed, msg);
```

```ts
import { getPublicKey, encodeKey, signInDomain } from "@bitspark/archon";

const pub  = getPublicKey(seed);
const text = encodeKey(pub);
const sig  = signInDomain("example.v1", seed, msg);
```

## Three cores, one meaning

Rust, Go and TypeScript are not three ports that drifted. They are held to one hand-authored
oracle in [`vectors/`](vectors/), and the harness **recomputes** every case rather than
trusting the recorded answer:

```console
$ node conformance/check.mjs
all cores agree: 180 case-checks, 3 core(s)
```

That runs on every push. If the cores ever disagree about whether something is a valid key,
a valid signature or a valid key text, that disagreement *is* the bug — a consumer's two
ends may not be written in the same language.

`vectors/` is a published oracle: an independent implementation can check itself against it
without using any of this code.

## The tiers

| | what it adds |
|---|---|
| **core** | key bytes, the canonical key text, SPKI/PKCS-8, domain-separated sign and verify |
| **sdk** | signed envelopes, proof of possession, and the login scheme's audience binding |
| **cli** | the `archon` command — `keygen`, `key`, `sign`, `verify`, `login`, `version` |
| **server** | the login endpoint: proof-of-possession sign-in and key-to-key delegation |

## Install

```console
# Go — resolves straight from this repository
go get github.com/Bitspark/archon/core/go        # also /sdk/go, /cli/go, /server/go

# Rust — the package name carries the vendor prefix; what you `use` does not
cargo add bitspark-archon-core                   # use archon_core::…
                                                 # also -sdk, -cli, -server

# TypeScript
npm install @bitspark/archon                     # also -sdk, -cli, -server

# Python — the floor; import archon_core
pip install bitspark-archon-core

# Java — Maven Central
#   <dependency><groupId>dev.bitspark</groupId><artifactId>archon-core</artifactId>
#     <version>0.7.0</version></dependency>
```

The Go modules resolve directly from this repository and need nothing else; the others are
on their public registries. Python and Java have the floor published; each also has an sdk
(possession and envelope, not the login scheme) in this tree, which ships with the next
release as `bitspark-archon-sdk` and `dev.bitspark:archon-sdk`. Which language carries which
tier, and how each claim is proven, is in [docs/languages.md](docs/languages.md).

The command is the same in all three languages — install it from whichever you already have:

```console
go install github.com/Bitspark/archon/cli/go/cmd/archon@latest
npm install -g @bitspark/archon-cli
cargo install bitspark-archon-cli                # installs the binary `archon`
```

On crates.io the packages carry a `bitspark-` prefix, because crates.io has a single flat
namespace with no scopes and the short `archon-*` names are not all available. It is a
registry name only: the library target keeps its own name, so you write
`use archon_core::…`, and the installed binary is `archon`.

Runtime dependencies, in full: `ed25519-dalek` (Rust) · the standard library's
`crypto/ed25519` plus `filippo.io/edwards25519` for point validation only (Go — the
published form of the implementation the standard library is maintained from; see ADR 0008
§5 for why a blocklist was not enough) · `@noble/curves` and `@noble/hashes` (TypeScript,
because noble v3 unbundles SHA-512 and makes you supply it) · PyCryptodome (Python, the one
mainstream route to Ed25519ph with a context). Nothing else, in any language, at any
version. Each core binds its language's Ed25519 and archon writes only the encodings and
the checks on top; the curve arithmetic is not reimplemented here. What every core
*accepts* is written down once, in [ADR 0008](docs/architecture/decisions/0008-the-ed25519-verification-profile.md),
and checked ahead of the library rather than inherited from it.

## Scope

archon owns what can be stated **without a law** — in RFC 8032, RFC 5280 and RFC 5958
vocabulary alone: a seed, a public key, a signature, an opaque message, a key text, a PEM.

It deliberately does **not** own:

- **Authority.** Whether a key may do a thing is not archon's question. The login server
  hands the authority payload to the consumer through `AdmitAuthority` and never reads it.
- **Custody.** Storing a key, encrypting it at rest, rotating it, running a root ceremony,
  retiring an epoch — none of it. `archon key` writes a file you name and reads a file you
  name; it manages nothing and is not a keychain.
- **Succession.** There is no re-key path. A key dies with itself; loss or compromise means
  generating a new one.

[ADR 0001](docs/architecture/decisions/0001-archon-scope.md) states the criterion, and works
an example in which archon argued to take something and was — correctly — refused. That
example is the useful part: the value of one canonical spelling is real but it is **not
universal**, and a project that already has a canonical byte-to-text spelling would be
*adding* a second by adopting this one.

## Documentation

- [Architecture decisions](docs/architecture/decisions/) — why the boundaries are where they are
- [The login scheme](docs/login.md) — proof of possession, audience binding, delegation
- [The key store](docs/keystore.md) — what `archon key` does and does not do
- [Conformance](conformance/) and [the oracle](vectors/) — how agreement is established
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
