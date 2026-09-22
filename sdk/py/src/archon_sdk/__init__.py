"""archon sdk — one layer above the identity floor, in Python.

`archon_core` answers *"is this really them?"* over bytes. This package answers the two
questions every protocol asks next, without knowing the protocol:

- `possession` — *can they sign, right now, for this channel?* The challenger supplies a
  nonce and a channel binding, the prover signs a fixed layout of both in the protocol's
  domain, the challenger verifies. The binding is what makes the proof unrelayable; without
  one there is no proof, so an empty binding is refused.
- `envelope` — *these bytes, signed by this key, in this domain.* A fixed container:
  version, domain, public key, signature, opaque payload. No expiry, issuer, audience or
  key-id — each is either policy or a second spelling of the key, and both are the
  consumer's.

**The rule that keeps this layer honest:** entropy, time and channel binding are arguments.
This package never sources them, so every byte it emits is a deterministic function of its
inputs and is pinned by `vectors/sdk.json` — the same oracle the Go, Rust and TypeScript sdks
are held to. The login scheme, which the other three also carry, is not here yet.
"""

from . import envelope, possession
from .envelope import Opened

__version__ = "0.8.0"

__all__ = ["envelope", "possession", "Opened", "__version__"]
