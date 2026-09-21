# archon core — Python

The identity floor in Python: Ed25519 key bytes, one canonical text spelling, the SPKI and
PKCS-8 codecs, and domain-separated signing.

```console
pip install bitspark-archon-core
```

The distribution is `bitspark-archon-core`; the import is `archon_core`. The prefix is a
registry name only — PyPI, like crates.io, has a single flat namespace.

```python
from archon_core import (
    public_key_from_seed, encode_key, sign_in_domain, verify_in_domain,
)

seed = bytes(range(32))
pub  = public_key_from_seed(seed)

encode_key(pub)
# 'ed25519:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8'

sig = sign_in_domain(seed, "example.v1", b"hello")
verify_in_domain(pub, "example.v1", b"hello", sig)   # True
verify_in_domain(pub, "other.v1",   b"hello", sig)   # False — domains do not cross
```

## What it is

Two questions and no others: *are these bytes that key*, and *is this signature that key's*.
Authority and custody belong to their own layers — see the
[repository README](https://github.com/Bitspark/archon).

| | |
|---|---|
| `crypto` | `public_key_from_seed`, `sign`/`verify`, `sign_in_domain`/`verify_in_domain` |
| `hexbytes` | `to_hex`, and fixed-size decoders that accept exactly N bytes or fail |
| `keytext` | `encode_key`/`decode_key` — `ed25519:<64 hex>` |
| `keycodec` | RFC 5280 SPKI and RFC 5958 PKCS-8 v1 PEM, as a byte codec |

## Agreement is the claim

This core is held to the same hand-authored oracle as the Go, Rust and TypeScript cores —
60 cases in [`vectors/identity.json`](https://github.com/Bitspark/archon/blob/main/vectors/identity.json),
recomputed rather than echoed. If it disagrees with the others about whether something is a
valid key, signature or key text, that disagreement is the defect.

Two places where Python needed care to agree, both recorded in the source:

- **`sign_in_domain` is Ed25519ph with the domain as the RFC 8032 §5.1 context.**
  `cryptography` cannot express it — it offers only pure `sign(data)`. This package binds
  **PyCryptodome**, which can.
- **Small-order public keys are rejected.** PyCryptodome's verifier accepts them; Go's
  `crypto/ed25519` and `ed25519-dalek` do not. archon's profile is to reject, so `verify`
  checks `[8]A` against the identity using the library's own point arithmetic. Without it,
  two oracle cases pass in Python and fail everywhere else.

## Verification

Signing raises rather than silently signing raw: an empty domain, or one over 255 bytes, is
an error. Verification is total — every shape failure returns `False`, so a caller cannot
mistake *malformed* for *valid*.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
