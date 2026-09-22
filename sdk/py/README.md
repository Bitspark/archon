# archon sdk — Python

One layer above the identity floor: proof of possession and the signed envelope.

```console
pip install bitspark-archon-sdk
```

The distribution is `bitspark-archon-sdk`; the import is `archon_sdk`. It depends on
[`bitspark-archon-core`](https://pypi.org/project/bitspark-archon-core/) and nothing else, and
pip installs the floor with it.

```python
from archon_core import public_key_from_seed
from archon_sdk import envelope, possession

seed = bytes(range(32))
pub  = public_key_from_seed(seed)

# Proof of possession: the challenger picks the nonce and the channel binding.
nonce, binding = bytes(range(16)), b"tls-exporter-bytes"
proof = possession.prove(seed, "example/pop/v1", nonce, binding)
possession.verify(pub, "example/pop/v1", nonce, binding, proof)        # True
possession.verify(pub, "example/pop/v1", nonce, b"another channel", proof)  # False

# The signed envelope: the verifier chooses the domain, never the envelope.
sealed = envelope.seal(seed, "example/env/v1", b"payload")
opened = envelope.open(sealed, "example/env/v1")   # Opened(pubkey=…, payload=b'payload')
envelope.open(sealed, "example/env/other")         # ValueError: claims a different domain
```

## What it is

| | |
|---|---|
| `possession` | `prove`, `verify`, `message_bytes` — *can they sign, right now, for this channel?* |
| `envelope` | `seal`, `open`, `message_bytes`, `Opened` — *these bytes, signed by this key, in this domain* |

Both sign in the **caller's** domain through `archon_core.sign_in_domain`, and each prefixes
its layout with a one-byte scheme tag so a possession proof and an envelope payload in the
same domain can never be the same bytes.

**Entropy, time and channel binding are arguments.** This package never sources them, which
is what makes every byte it emits a deterministic function of its inputs. Verification is
total: `possession.verify` returns `False` on any shape failure and never raises;
`envelope.open` raises `ValueError` and never returns an unverified payload.

**Not here yet: the login scheme.** The Go, Rust and TypeScript sdks also carry
`archon-login/1` ([docs/login.md](https://github.com/Bitspark/archon/blob/main/docs/login.md));
this one does not.

## Agreement is the claim

This sdk is held to the same hand-authored oracle as the Go, Rust and TypeScript sdks — 38
cases in [`vectors/sdk.json`](https://github.com/Bitspark/archon/blob/main/vectors/sdk.json),
recomputed rather than echoed. If it disagrees with them about a proof or an envelope, that
disagreement is the defect.

## Verification

```console
node conformance/check-py-sdk.mjs          # the oracle, against this tree
node conformance/check-py-sdk-package.mjs  # the built wheel, installed from nothing
```

## License

Apache-2.0.
